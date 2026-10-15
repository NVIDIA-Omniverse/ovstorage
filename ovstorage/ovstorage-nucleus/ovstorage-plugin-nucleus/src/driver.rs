// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for Nucleus sessions (RFC-0066).
//!
//! Nucleus is the SESSION-FULL shape the driver trait's `on_authenticated`
//! hook was designed for: proving a credential and *serving the data path*
//! are two different things. The credential bundle (api_token, or
//! username+password, or the `interactive_auth` marker) is exchanged through
//! a SOWS discovery + OmniAuth handshake for a live session (`RuntimeOps`
//! ConnLib socket + optional `LftClient` + `NucleusSession` tokens) installed
//! on the connection's [`NucleusShared`] cell. The verbs map onto that split:
//!
//! - `obtain` runs the credential-appropriate handshake on driver-private
//!   staging. A persisted OAuth bundle drives warm continuation; api-token /
//!   username+password drive replayable grants; the `interactive_auth` marker
//!   and an empty bundle are `AwaitingInteractive` (Nucleus has no anonymous
//!   data path). The effective bundle carries the rotated refresh token to the
//!   generic lifecycle for persistence.
//! - `verify` confirms the staged handshake completed Nucleus's ConnLib
//!   `authorize_token` proof without touching the live cell.
//! - `activate` promotes the staged session through the set-captured identity
//!   generation fence. `on_authenticated` only verifies that the session-full
//!   invariant now holds.
//! - `refresh` drives the single-flight `refresh_under_epoch` engine
//!   (refresh-token grant when the session carries one, else api-token
//!   re-auth), with its live install fenced on the same generation.
//! - `interactive` drives the real handshake per credential shape, with the
//!   URL+nonce-poll SSO flow gated on the host's interactive capability. It
//!   installs before terminal success and returns the effective bundle so the
//!   set owns persistence.
//!
//! Refresh-token grants rotate one-time tokens and warm continuation consumes a
//! single-use persisted secret. The `ConnectionSet` serializes and persists
//! these grants under the stable request identity.

use std::sync::Arc;

use crate::address::NUCLEUS_KIND;
use crate::auth::{
    CredentialShape, classify_credentials, has_secret_field, synthesize_auth_events,
};
use crate::backend::session::{
    InstallKind, NucleusShared, RefreshToken, clear_session_state_if_identity_unchanged,
    credentials_with_session, install_handshake_output, refresh_token, refresh_under_epoch,
    spawn_interactive_auth_stream,
};
use crate::config::NucleusConfig;
use crate::handshake::{
    HandshakeOutput, establish_api_token, establish_username_password, try_warm_continue,
};
use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionAuthDriver, GrantPolicy, Obtained, Refreshed};
use ovstorage_plugin::{
    AuthEvent, AuthEventStream, AuthReason, CancellationToken, Connection, ConnectionId, Error,
    ErrorCode, InteractiveAuthCapability, Result, SecretBundle, oauth_secret_store, race_cancel,
};

/// The credential fields the handshake consumes (plus the `interactive_auth`
/// marker the host uses to request the SSO flow). Anything else in a bundle
/// is a caller mistake `obtain` refuses — sibling parity with s3/azure/gcs/
/// opendal, so a typo'd field cannot be silently dropped into a handshake
/// that then fails opaquely (or worse, succeeds as the wrong shape).
const ALLOWED_CREDENTIAL_FIELDS: &[&str] = &[
    "username",
    "password",
    "api_token",
    "interactive_auth",
    "oauth",
];

const KEYRING_BACKEND_KIND: &str = NUCLEUS_KIND;

pub(crate) struct NucleusDriver {
    config: NucleusConfig,
    /// The live session cell shared with the connection's `NucleusBackend`.
    shared: Arc<NucleusShared>,
    /// `obtain`'s proven handshake output, promoted onto the live cell by the
    /// fenced `activate` commit — driver-private staging, so a probe (which
    /// never commits) cannot leak a session onto the live cell.
    staged: tokio::sync::Mutex<Option<HandshakeOutput>>,
    /// This connection's claim on its durable key.
    ///
    /// Taken lazily, on first use — where "use" means touching the durable
    /// store. Laziness alone does NOT keep a probe out: a probe drives
    /// `obtain`, so any guard there that reached through this accessor would
    /// acquire and contend. What keeps it out is that every path a probe takes
    /// inspects the claim without taking one (see `ensure_claim_usable`), and
    /// only load/persist — which a probe does not do — acquire.
    ///
    /// It matters because contention is remembered for a claim's whole life: a
    /// probe that acquired would leave the LIVE connection non-exclusive
    /// forever, refusing its grants and stranding the secret store on a token the
    /// provider has already rotated past.
    ///
    /// A second live connection claiming the same key makes the stored lineage
    /// ambiguous, and persistence is refused for both until the operator sets
    /// distinct `persistence_id`s.
    claim: std::sync::OnceLock<oauth_secret_store::SharedPersistenceClaim>,
}

impl NucleusDriver {
    pub(crate) fn new(shared: Arc<NucleusShared>) -> Self {
        Self {
            config: shared.config.clone(),
            shared,
            staged: tokio::sync::Mutex::new(None),
            claim: std::sync::OnceLock::new(),
        }
    }

    /// Refuse if this connection's adoption has been retracted.
    ///
    /// Deliberately inspects the claim WITHOUT taking one. `probe` drives
    /// `obtain` on a throwaway driver built from the same request, so it
    /// derives the same durable key — and acquiring here would contend with the
    /// live connection's claim. Contention is remembered for a claim's whole
    /// life, so a single "Test connection" would permanently refuse the live
    /// connection's grants and writes.
    ///
    /// A driver that has never touched the durable store has taken no claim and
    /// has no adoption to retract, which is exactly the probe's case.
    fn ensure_claim_usable(&self) -> Result<()> {
        match self.claim.get() {
            Some(claim) => claim.ensure_usable(),
            None => Ok(()),
        }
    }

    /// This connection's claim on its durable key, taken on first use.
    fn claim(&self) -> &oauth_secret_store::SharedPersistenceClaim {
        self.claim.get_or_init(|| {
            Arc::new(oauth_secret_store::PersistenceClaim::acquire(
                KEYRING_BACKEND_KIND,
                &self.config.stable_id,
            ))
        })
    }

    /// Run the credential-appropriate handshake. `Missing` / `InteractiveAuth`
    /// shapes never reach this (obtain reports `AwaitingInteractive`), but the
    /// arm stays honest for a direct call.
    async fn handshake_for_bundle(&self, bundle: &SecretBundle) -> Result<HandshakeOutput> {
        #[cfg(test)]
        if let Some(callback) = self
            .shared
            .handshake_override
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
        {
            return callback();
        }
        match classify_credentials(bundle) {
            CredentialShape::ApiToken => establish_api_token(&self.config, bundle).await,
            CredentialShape::UsernameAndPassword => {
                establish_username_password(&self.config, bundle).await
            }
            CredentialShape::InteractiveAuth
            | CredentialShape::Partial
            | CredentialShape::Missing => Err(Error::new(
                ErrorCode::AuthRequired,
                "Nucleus authentication requires `api_token` or `username`+`password`, \
                 or an interactive sign-in",
            )),
        }
    }

    /// Stage a verified handshake, first confirming its principal is the one
    /// this connection's persisted lineage is bound to.
    ///
    /// `Err(AuthRequired)` means the handshake authenticated as somebody else,
    /// so the session is refused rather than adopted on a stored credential
    /// whose owner it contradicts.
    async fn stage_output(
        &self,
        base: &SecretBundle,
        output: HandshakeOutput,
    ) -> Result<SecretBundle> {
        self.shared.binding.observe(self.identity_of(&output))?;
        let effective = credentials_with_session(base, &output.session);
        *self.staged.lock().await = Some(output);
        Ok(effective)
    }

    /// The identity a completed handshake attests to. Nucleus reports the
    /// authenticated principal directly, so the binding names the server and
    /// that principal rather than reading claims out of a bearer.
    fn identity_of(&self, output: &HandshakeOutput) -> oauth_secret_store::IdentityBinding {
        crate::backend::session::identity_binding(&self.shared, &output.session.principal)
    }

    async fn activate_staged(
        &self,
        credentials: &SecretBundle,
        expected_gen: u64,
        kind: InstallKind,
    ) -> Result<bool> {
        let Some(HandshakeOutput { ops, lft, session }) = self.staged.lock().await.take() else {
            return Err(Error::new(
                ErrorCode::Internal,
                "Nucleus activation has no staged, verified session",
            ));
        };
        Ok(install_handshake_output(
            &self.shared,
            ops,
            lft,
            session,
            credentials.clone(),
            kind,
            Some(expected_gen),
        ))
    }
}

#[async_trait]
impl ConnectionAuthDriver for NucleusDriver {
    fn backend_kind(&self) -> &str {
        NUCLEUS_KIND
    }

    fn stable_id(&self) -> Option<ConnectionId> {
        Some(self.config.stable_id.clone())
    }

    async fn obtain(
        &self,
        creds: &SecretBundle,
        policy: GrantPolicy,
        cancel: Option<CancellationToken>,
    ) -> Result<Obtained> {
        // A sibling that claimed this key after the adoption retracts it: the
        // connection is serving on a lineage nothing can show is its own, so it
        // re-authenticates rather than continuing.
        self.ensure_claim_usable()?;
        if let Some(unknown) = creds
            .fields
            .keys()
            .find(|key| !ALLOWED_CREDENTIAL_FIELDS.contains(&key.as_str()))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unknown credential field '{unknown}' for Nucleus \
                     (expected: {})",
                    ALLOWED_CREDENTIAL_FIELDS.join(", ")
                ),
            ));
        }
        // Shape checks use the SAME presence semantics as
        // `classify_credentials` (an empty value is absent), so a broken
        // pair cannot slip past `contains_key` and reclassify as `Missing`.
        let has_token = has_secret_field(creds, "api_token");
        let has_user = has_secret_field(creds, "username");
        let has_pass = has_secret_field(creds, "password");
        let refresh = match refresh_token(creds)? {
            RefreshToken::Present(token) => Some(token.to_string()),
            RefreshToken::Absent | RefreshToken::Clear => None,
        };
        // A bundle carrying BOTH an api_token and username/password material
        // is ambiguous: precedence would silently drop the pair — the
        // "succeeds as the wrong shape" hazard the field allowlist exists
        // to prevent.
        if has_token && (has_user || has_pass) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "ambiguous Nucleus credential bundle: supply either `api_token` or \
                 `username`+`password`, not both",
            ));
        }
        // Half a username/password pair can never drive the OmniAuth
        // handshake; refuse it up front rather than let verify fail opaquely.
        if has_user != has_pass {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "Nucleus username/password authentication requires both `username` and `password`",
            ));
        }
        // A persisted one-time refresh token is authoritative for warm
        // continuation. A probe must not consume it; a real grant rotates it
        // on private staging and hands the successor to `ConnectionSet` for
        // persistence before activation.
        if let Some(refresh) = refresh {
            if policy == GrantPolicy::NonConsumingOnly && !(has_token || (has_user && has_pass)) {
                return Ok(Obtained::WouldConsume);
            }
            if policy == GrantPolicy::AllowConsuming {
                if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
                    return Err(Error::new(
                        ErrorCode::Cancelled,
                        "Nucleus warm continuation cancelled",
                    ));
                }
                // Once the warm grant starts it may consume a one-time refresh
                // token. Let it finish so the successor always reaches the
                // ConnectionSet persistence transaction.
                let output = try_warm_continue(&self.config, refresh).await?;
                let effective = self.stage_output(creds, output).await?;
                return Ok(Obtained::Bearer {
                    credentials: effective,
                    expires_at: None,
                });
            }
        }

        Ok(match classify_credentials(creds) {
            CredentialShape::ApiToken | CredentialShape::UsernameAndPassword => {
                let output = race_cancel(cancel.as_ref(), self.handshake_for_bundle(creds)).await?;
                let effective = self.stage_output(creds, output).await?;
                Obtained::Bearer {
                    credentials: effective,
                    expires_at: None,
                }
            }
            // No anonymous arm: every nucleus op needs a session, so a bare /
            // interactive-marker bundle parks awaiting sign-in rather than
            // reporting a healthy `Anonymous` connection that cannot serve.
            CredentialShape::InteractiveAuth | CredentialShape::Missing => {
                Obtained::AwaitingInteractive {
                    reason: AuthReason::NeverAuthenticated,
                }
            }
            // A malformed bundle (empty-valued field the half-pair guards
            // above didn't already catch) must not park as interactive and
            // silently change the caller's explicit authentication intent.
            CredentialShape::Partial => {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    "incomplete Nucleus credential bundle: supply a non-empty `api_token` or \
                     both `username`+`password`, or omit credentials for interactive sign-in",
                ));
            }
        })
    }

    async fn verify(
        &self,
        _credentials: &SecretBundle,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // `obtain` completed the Nucleus handshake on private staging. That
        // handshake's ConnLib `authorize_token` is the backend acceptance
        // proof; keep the staged output intact for the fenced activation.
        if self.staged.lock().await.is_some() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                "Nucleus verification has no staged handshake",
            ))
        }
    }

    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        self.activate_staged(credentials, expected_gen, InstallKind::Refresh)
            .await
    }

    async fn activate_replacing(
        &self,
        credentials: &SecretBundle,
        expected_gen: u64,
    ) -> Result<bool> {
        self.activate_staged(credentials, expected_gen, InstallKind::Identity)
            .await
    }

    fn identity_gen(&self) -> u64 {
        self.shared
            .identity_gen
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Answered from the credential the live identity published: a bundle
    /// carrying a different refresh token belongs to a flow the live cell has
    /// moved past, and committing it would regress the connection onto a token
    /// the provider's rotation has already consumed.
    fn credentials_are_current(&self, credentials: &SecretBundle) -> bool {
        oauth_secret_store::bundle_carries_published_credential(self.shared.as_ref(), credentials)
    }

    async fn on_authenticated(
        &self,
        _connection: &Connection,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // Grant commits install their staged session in `activate`; the
        // interactive pump installs before emitting terminal success. This hook
        // therefore verifies the session-full invariant without another grant.
        if self.shared.has_session() {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::Internal,
            "Nucleus authenticated transition has no installed session",
        ))
    }

    async fn refresh(
        &self,
        current: &SecretBundle,
        cancel: Option<CancellationToken>,
        expected_gen: u64,
    ) -> Result<Refreshed> {
        // A sibling that claimed this key after the adoption retracts it: the
        // connection is serving on a lineage nothing can show is its own, so it
        // re-authenticates rather than continuing.
        self.ensure_claim_usable()?;
        // Single-flight under the shared cell's epoch: concurrent retriers
        // that observed the same stale session collapse onto one round-trip.
        // `refresh_session` prefers the (rotating, one-time) refresh-token
        // grant and falls back to api-token re-auth; the fresh session +
        // rotated refresh token land on the live cell only when the identity
        // generation captured by the set still matches. The returned effective
        // bundle carries that rotated token to the set-owned persistence hook.
        let observed = self
            .shared
            .cred_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        let refreshed = race_cancel(
            cancel.as_ref(),
            refresh_under_epoch(&self.shared, current, observed, expected_gen),
        )
        .await?;
        let credentials = match refreshed {
            Some(credentials) => credentials,
            None => self
                .shared
                .credentials
                .lock()
                .map_err(|_| Error::new(ErrorCode::Internal, "Nucleus credential state poisoned"))?
                .clone(),
        };
        Ok(Refreshed {
            credentials,
            expires_at: None,
        })
    }

    async fn interactive(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let expected_gen = self.identity_gen();
        // Preserve the credential-shape dispatch with one identity-safety
        // narrowing.
        let bundle = self
            .shared
            .credentials
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        let shape = classify_credentials(&bundle);
        match shape {
            // Both headless-safe: the api-token exchange and the synchronous
            // `Credentials.auth` need no browser, so they run under every
            // capability mode (including `None`).
            CredentialShape::ApiToken | CredentialShape::UsernameAndPassword => {
                let mut events = vec![Ok(AuthEvent::Progress {
                    message: match shape {
                        CredentialShape::ApiToken => {
                            "Authenticating with Nucleus via SOWS discovery + ConnLib".into()
                        }
                        _ => "Authenticating with Nucleus via SOWS Credentials.auth".into(),
                    },
                })];
                match race_cancel(cancel.as_ref(), self.handshake_for_bundle(&bundle)).await {
                    Ok(HandshakeOutput { ops, lft, session }) => {
                        let effective = credentials_with_session(&bundle, &session);
                        if !install_handshake_output(
                            &self.shared,
                            ops,
                            lft,
                            session,
                            effective.clone(),
                            InstallKind::Identity,
                            Some(expected_gen),
                        ) {
                            events.push(Ok(AuthEvent::Failed {
                                error: Error::new(
                                    ErrorCode::AuthCancelled,
                                    "Nucleus interactive authentication was superseded",
                                ),
                            }));
                        } else {
                            events.push(Ok(AuthEvent::Succeeded {
                                connection: Box::new(connection),
                                credentials: Some(effective),
                            }));
                        }
                    }
                    Err(error) => {
                        // A failed re-authentication tears the
                        // live session down before the terminal `Failed`, so
                        // an already-installed session cannot keep serving
                        // as the stale identity while the connection reports
                        // parked (data dispatch gates on session presence,
                        // not `ConnectionAuthState`).
                        clear_session_state_if_identity_unchanged(&self.shared, expected_gen);
                        events.push(Ok(AuthEvent::Failed { error }));
                    }
                }
                Ok(Box::new(events.into_iter()))
            }
            CredentialShape::InteractiveAuth => {
                if matches!(capability, InteractiveAuthCapability::None) {
                    return Err(Error::new(
                        ErrorCode::AuthRequired,
                        "Interactive sign-in is disabled in this session, so the \
                         URL-based Nucleus sign-in flow is unavailable. Enable browser \
                         or headless interactive auth, or set credentials in TOML.",
                    ));
                }
                Ok(spawn_interactive_auth_stream(
                    self.shared.clone(),
                    connection,
                    cancel,
                    expected_gen,
                ))
            }
            CredentialShape::Missing if !matches!(capability, InteractiveAuthCapability::None) => {
                Ok(spawn_interactive_auth_stream(
                    self.shared.clone(),
                    connection,
                    cancel,
                    expected_gen,
                ))
            }
            // A malformed bundle never launches SSO (that would sign in as an
            // identity it can't validate); surface the honest `AuthRequired`.
            // Reached only if `obtain` was bypassed — belt-and-suspenders with
            // its own `Partial` refusal.
            CredentialShape::Partial => Ok(Box::new(
                synthesize_auth_events(connection, Some(&bundle)).into_iter(),
            )),
            CredentialShape::Missing => {
                // No credentials and no interactive capability: nothing can
                // drive a handshake — surface the honest `AuthRequired`
                // failure event (never a synthesized `Succeeded`).
                Ok(Box::new(
                    synthesize_auth_events(connection, Some(&bundle)).into_iter(),
                ))
            }
        }
    }

    async fn persist_credentials(&self, credentials: &SecretBundle) -> Result<()> {
        match refresh_token(credentials)? {
            RefreshToken::Present(token) => {
                // The binding is read inside the publication lock that guards
                // the write, so an identity install cannot land between them and
                // leave this principal's secret under another's record.
                oauth_secret_store::persist_current_lineage(
                    NUCLEUS_KIND,
                    KEYRING_BACKEND_KIND,
                    self.claim(),
                    self.shared.as_ref(),
                    &self.shared.publication,
                    token,
                )?;
            }
            RefreshToken::Clear => oauth_secret_store::delete_current_lineage(
                NUCLEUS_KIND,
                KEYRING_BACKEND_KIND,
                self.claim(),
                &self.shared.publication,
            )?,
            RefreshToken::Absent => return Ok(()),
        }
        // The old server-hostname entry is deliberately never read because it
        // may represent any of several formerly-colliding identities. Once the
        // identity-scoped entry is touched, retire that orphan best-effort.
        let _ = oauth_secret_store::delete_bound_refresh_token(
            NUCLEUS_KIND,
            KEYRING_BACKEND_KIND,
            &ConnectionId(self.config.server.clone()),
        );
        Ok(())
    }

    async fn load_credentials(&self) -> Result<Option<SecretBundle>> {
        // Warm continuation adopts the stored lineage only once the handshake
        // it drives proves the principal matches the binding recorded here.
        let read_gen = self
            .shared
            .identity_gen
            .load(std::sync::atomic::Ordering::Acquire);
        match oauth_secret_store::read_claimed_refresh_token(
            NUCLEUS_KIND,
            KEYRING_BACKEND_KIND,
            self.claim(),
        )? {
            Some(stored) if !stored.refresh_token.is_empty() => {
                // Fenced on the generation read BEFORE the secret-store round trip,
                // exactly as the OAuth plugins fence theirs: a sign-in that won
                // while this was in flight owns the identity, and restoring what
                // was read would revert it.
                if !self
                    .shared
                    .adopt_binding_if_identity_unchanged(stored.binding, read_gen)
                {
                    // The read latched the adoption; this connection is
                    // declining the record, so it serves on nothing it read and
                    // a later sibling must not find it retro-actively refused.
                    self.claim().retract_adoption();
                    return Ok(None);
                }
                Ok(Some(oauth_secret_store::oauth_bundle(
                    "",
                    Some(&stored.refresh_token),
                    None,
                )))
            }
            _ => Ok(None),
        }
    }

    async fn delete_credentials(&self) -> Result<()> {
        // Token and binding live under this connection's key alone, so a
        // sibling identity — which occupies a different key — is untouched.
        oauth_secret_store::delete_bound_refresh_token(
            NUCLEUS_KIND,
            KEYRING_BACKEND_KIND,
            &self.config.stable_id,
        )?;
        self.shared.binding.clear();
        let _ = oauth_secret_store::delete_bound_refresh_token(
            NUCLEUS_KIND,
            KEYRING_BACKEND_KIND,
            &ConnectionId(self.config.server.clone()),
        );
        Ok(())
    }

    async fn purge_credentials(&self) -> Result<()> {
        self.delete_credentials().await?;
        if let Ok(mut credentials) = self.shared.credentials.lock() {
            credentials.fields.remove("oauth");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use ovstorage_plugin::connection::ConnectionAuthDriver as _;
    use ovstorage_plugin::ffi;
    use ovstorage_plugin::{
        ConfigValue, ConnectionId, ConnectionRequest, SecretBundle, SecretBytes,
    };

    use super::{KEYRING_BACKEND_KIND, NUCLEUS_KIND, NucleusDriver};
    use crate::backend::session::{NucleusShared, RefreshToken, refresh_token};
    use crate::config::NucleusConfig;

    type Key = (String, String, String);

    struct StubHost {
        secrets: Mutex<HashMap<Key, SecretBytes>>,
        /// Runs inside `secret_get`, so a test can land a concurrent sign-in
        /// *during* the round trip a warm continuation fences on rather than
        /// simulating one before or after it.
        during_get: Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
    }

    static HOST: OnceLock<&'static StubHost> = OnceLock::new();

    fn registered_host() -> &'static StubHost {
        HOST.get_or_init(|| {
            let host = Box::leak(Box::new(StubHost {
                secrets: Mutex::new(HashMap::new()),
                during_get: Mutex::new(None),
            }));
            let callbacks = Box::leak(Box::new(ffi::HostCallbacks {
                struct_size: std::mem::size_of::<ffi::HostCallbacks>(),
                host_state: std::ptr::from_ref(host) as *mut core::ffi::c_void,
                secret_get,
                secret_put,
                secret_delete,
                auth_refresh_lock_with_refresh,
                host_kind: ffi::HostKindV1::Library as u32,
                log,
            }));
            // SAFETY: both the callback table and its state are leaked for the
            // lifetime of this test process.
            unsafe { ovstorage_plugin::marshal::register_host(callbacks) };
            host
        })
    }

    unsafe fn key_from_ffi(key: *const ffi::SecretKey) -> Key {
        unsafe {
            let key = &*key;
            let read = |value: &ffi::Str| {
                std::str::from_utf8(std::slice::from_raw_parts(
                    value.ptr as *const u8,
                    value.len,
                ))
                .unwrap()
                .to_owned()
            };
            (
                read(&key.backend_kind),
                read(&key.connection_id.id),
                read(&key.field),
            )
        }
    }

    unsafe extern "C" fn secret_get(
        state: *mut core::ffi::c_void,
        key: *const ffi::SecretKey,
        out_value: *mut ffi::Optional<ffi::SecretBytes>,
    ) -> *mut ffi::Error {
        unsafe {
            let host = &*(state as *const StubHost);
            let key = key_from_ffi(key);
            let during = host.during_get.lock().unwrap().clone();
            if let Some(during) = during {
                during();
            }
            let value = host.secrets.lock().unwrap().get(&key).cloned();
            std::ptr::write(
                out_value,
                value.map_or_else(ffi::Optional::none, |secret| {
                    ffi::Optional::some(ovstorage_plugin::marshal::descriptor::secret_bytes_to_ffi(
                        secret,
                    ))
                }),
            );
            std::ptr::null_mut()
        }
    }

    unsafe extern "C" fn secret_put(
        state: *mut core::ffi::c_void,
        key: *const ffi::SecretKey,
        value: *const ffi::SecretBytes,
    ) -> *mut ffi::Error {
        unsafe {
            let host = &*(state as *const StubHost);
            let bytes = std::slice::from_raw_parts((*value).bytes.ptr, (*value).bytes.len).to_vec();
            host.secrets
                .lock()
                .unwrap()
                .insert(key_from_ffi(key), SecretBytes(bytes));
            std::ptr::null_mut()
        }
    }

    unsafe extern "C" fn secret_delete(
        state: *mut core::ffi::c_void,
        key: *const ffi::SecretKey,
    ) -> *mut ffi::Error {
        unsafe {
            let host = &*(state as *const StubHost);
            host.secrets.lock().unwrap().remove(&key_from_ffi(key));
            std::ptr::null_mut()
        }
    }

    unsafe extern "C" fn auth_refresh_lock_with_refresh(
        _state: *mut core::ffi::c_void,
        _backend_kind: *const ffi::Str,
        _connection_id: *const ffi::ConnectionId,
        _freshness_window_ms: u64,
        refresh_state: *mut core::ffi::c_void,
        refresh_fn: ffi::HostRefreshFn,
    ) -> *mut ffi::Error {
        unsafe { refresh_fn(refresh_state) }
    }

    unsafe extern "C" fn log(
        _state: *mut core::ffi::c_void,
        _level: u8,
        _target: *const ffi::Str,
        _message: *const ffi::Str,
    ) {
    }

    fn driver(display_name: &str) -> NucleusDriver {
        let request = ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config: HashMap::from([("server".into(), ConfigValue::String("same.example".into()))]),
            credentials: SecretBundle::default(),
            persist: true,
            display_name: Some(display_name.into()),
        };
        let config = NucleusConfig::from_request(&request).unwrap();
        NucleusDriver::new(NucleusShared::new(config, request.credentials))
    }

    /// A driver whose connection also carries a durable account discriminator,
    /// the setting that keeps two same-server connections apart.
    fn driver_with_persistence_id(display_name: &str, persistence_id: &str) -> NucleusDriver {
        let request = ConnectionRequest {
            backend_kind: NUCLEUS_KIND.into(),
            config: HashMap::from([
                ("server".into(), ConfigValue::String("same.example".into())),
                (
                    "persistence_id".into(),
                    ConfigValue::String(persistence_id.into()),
                ),
            ]),
            credentials: SecretBundle::default(),
            persist: true,
            display_name: Some(display_name.into()),
        };
        let config = NucleusConfig::from_request(&request).unwrap();
        NucleusDriver::new(NucleusShared::new(config, request.credentials))
    }

    fn key(connection_id: &ConnectionId) -> Key {
        (
            KEYRING_BACKEND_KIND.into(),
            connection_id.0.clone(),
            "refresh_token".into(),
        )
    }

    /// A live session carrying `refresh`, as a handshake produces.
    fn live_session(principal: &str, refresh: Option<&str>) -> crate::handshake::NucleusSession {
        crate::handshake::NucleusSession {
            access_token: format!("{principal}-access"),
            refresh_token: refresh.map(str::to_owned),
            tokens_url: "https://same.example/tokens".into(),
            principal: principal.into(),
        }
    }

    /// Publish an identity and the credential it was published with, the way an
    /// IDENTITY install does — session, binding, and generation bump all under
    /// the session lock (mirrors `install_handshake_output`'s Identity arm).
    fn publish_identity(driver: &NucleusDriver, principal: &str, refresh: Option<&str>) {
        let mut fence = driver.shared.session.lock().unwrap();
        *fence = Some(live_session(principal, refresh));
        driver
            .shared
            .binding
            .expect(crate::backend::session::identity_binding(
                &driver.shared,
                principal,
            ));
        driver
            .shared
            .identity_gen
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Rotate the live session's refresh token the way a REFRESH install does:
    /// the session is replaced, and the binding and identity generation are
    /// deliberately left alone (mirrors `install_handshake_output`'s Refresh
    /// path, which is the same code with `kind == InstallKind::Refresh`).
    fn rotate_session(driver: &NucleusDriver, principal: &str, refresh: &str) {
        let mut fence = driver.shared.session.lock().unwrap();
        *fence = Some(live_session(principal, Some(refresh)));
    }

    fn binding_key(connection_id: &ConnectionId) -> Key {
        (
            KEYRING_BACKEND_KIND.into(),
            connection_id.0.clone(),
            "identity_binding".into(),
        )
    }

    #[tokio::test]
    async fn a_durable_account_discriminator_separates_connections_sharing_a_display_name() {
        // Two connections to one server intended for different accounts, given
        // the same presentation label: the discriminator keeps their stored
        // credentials apart where the label cannot.
        let alice = driver_with_persistence_id("Storage", "alice-work");
        let bob = driver_with_persistence_id("Storage", "bob-work");
        assert_ne!(alice.config.stable_id, bob.config.stable_id);
    }

    #[tokio::test]
    async fn a_probe_does_not_poison_a_live_connections_claim() {
        // Drives the probe's REAL entry point. `ConnectionSet::probe_connection`
        // builds a throwaway driver from the same request — same durable key —
        // and calls `obtain`. Asserting only that the keys match would pass
        // while `obtain` acquired and permanently refused the live connection.
        registered_host();
        let live = driver_with_persistence_id("probe-victim", "probe-victim");
        // The live connection has adopted: it holds a claim and is serving.
        let _ = live.load_credentials().await;
        assert!(live.claim().is_exclusive());
        assert!(live.claim().ensure_usable().is_ok());

        {
            let probe = driver_with_persistence_id("probe-victim", "probe-victim");
            assert_eq!(probe.config.stable_id, live.config.stable_id);
            let outcome = probe
                .obtain(
                    &SecretBundle::default(),
                    ovstorage_plugin::connection::GrantPolicy::NonConsumingOnly,
                    None,
                )
                .await;
            assert!(outcome.is_ok(), "the probe itself succeeds: {outcome:?}");
        }

        assert!(
            live.claim().is_exclusive(),
            "a probe that never touched the durable store left the live \
             connection able to grant and to persist",
        );
        assert!(live.claim().ensure_usable().is_ok());
    }

    /// A warm load must not publish a stored binding over an identity a
    /// concurrent sign-in established while the secret store read was in flight.
    ///
    /// Broker and services fence this; Nucleus restored the record
    /// unconditionally, so a bob sign-in landing mid-read was silently reverted
    /// to alice — and without advancing the generation, so nothing downstream
    /// could notice.
    ///
    /// The generation is sampled where `load_credentials` samples it: before
    /// the secret-store round trip. The sign-in then lands, and what the load read
    /// is offered afterwards.
    #[tokio::test]
    async fn a_warm_load_does_not_publish_over_a_concurrent_sign_in() {
        registered_host();
        let driver = driver_with_persistence_id("warm-vs-signin", "warm-vs-signin");
        publish_identity(&driver, "alice", None);

        // The load begins: generation sampled, keyring read in flight.
        let read_gen = driver
            .shared
            .identity_gen
            .load(std::sync::atomic::Ordering::Acquire);

        // A bob sign-in wins meanwhile. This is the state an IDENTITY install
        // leaves: the binding published and the generation advanced, both under
        // the session lock.
        {
            let _fence = driver.shared.session.lock().unwrap();
            driver
                .shared
                .binding
                .expect(crate::backend::session::identity_binding(
                    &driver.shared,
                    "bob",
                ));
            driver
                .shared
                .identity_gen
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        assert_eq!(driver.shared.binding.current().unwrap().subject, "bob");

        // The load resumes and offers alice's stored record.
        let adopted = driver.shared.adopt_binding_if_identity_unchanged(
            crate::backend::session::identity_binding(&driver.shared, "alice"),
            read_gen,
        );

        assert!(!adopted, "a record read before the sign-in is refused");
        assert_eq!(
            driver.shared.binding.current().unwrap().subject,
            "bob",
            "the sign-in that won still owns the identity",
        );
    }

    /// A rotation must advance the STORED token, not merely report success.
    ///
    /// The durable half of the rotation property, asserted here because the
    /// Nucleus driver tests register a stub keyring host. A persist that
    /// refused, no-opped, or wrote under the wrong key would pass a
    /// binding-only assertion.
    ///
    /// Driven from a real IDENTITY install, so the supersession proof is armed:
    /// a sign-in publishes both the binding AND the credential it was minted
    /// with, and the rotation that follows is a same-identity REFRESH install
    /// which advances the live session without touching either. A proof that
    /// tracked only identity-changing writes would still name the consumed
    /// predecessor here and refuse the rotation.
    #[tokio::test]
    async fn a_rotation_advances_the_stored_token() {
        let host = registered_host();
        let driver = driver_with_persistence_id("rotation", "rotation-scope");
        publish_identity(&driver, "alice", Some("rt-0"));

        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("rt-0"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            host.secrets
                .lock()
                .unwrap()
                .get(&key(&driver.config.stable_id))
                .unwrap()
                .0,
            b"rt-0",
        );

        // A background refresh consumes rt-0 and installs rt-1: the live
        // session advances, the identity does not change.
        rotate_session(&driver, "alice", "rt-1");
        // The token rotates; the connection persists its successor.
        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("rt-1"),
                None,
            ))
            .await
            .expect("the rotation is persistable");

        assert_eq!(
            host.secrets
                .lock()
                .unwrap()
                .get(&key(&driver.config.stable_id))
                .unwrap()
                .0,
            b"rt-1",
            "the stored entry advanced to the rotated token",
        );
    }

    /// A same-key sibling's FRESH login must not destroy an existing valid
    /// credential.
    ///
    /// The retirement predicate was "the stored token differs from the one
    /// being written", which proves difference, not supersession. A fresh
    /// interactive login consumed nothing — it has no predecessor — so its
    /// refused persist must leave the other connection's credential alone.
    ///
    /// Driven as the real sequence: A signs in and persists, B signs in as
    /// somebody else on the same key and persists. No manufactured claim that
    /// one token came from consuming the other.
    #[tokio::test]
    async fn a_siblings_fresh_login_does_not_destroy_a_valid_credential() {
        let host = registered_host();
        let alice = driver_with_persistence_id("fresh-login", "fresh-login");
        publish_identity(&alice, "alice", Some("alice-token"));
        alice
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("alice-token"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            host.secrets
                .lock()
                .unwrap()
                .get(&key(&alice.config.stable_id))
                .unwrap()
                .0,
            b"alice-token",
        );

        // Bob's connection derives the same key and signs in fresh. Nothing it
        // holds is a successor to alice's token.
        let bob = driver_with_persistence_id("fresh-login", "fresh-login");
        assert_eq!(bob.config.stable_id, alice.config.stable_id);
        publish_identity(&bob, "bob", Some("bob-token"));
        let refused = bob
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("bob-token"),
                None,
            ))
            .await;
        assert_eq!(
            refused.unwrap_err().code(),
            ovstorage_plugin::ErrorCode::CredentialUnavailable,
            "the ambiguous key refuses bob's write",
        );

        assert_eq!(
            host.secrets
                .lock()
                .unwrap()
                .get(&key(&alice.config.stable_id))
                .map(|bytes| bytes.0.clone()),
            Some(b"alice-token".to_vec()),
            "alice's valid credential survives a sibling's refused fresh login",
        );
    }

    /// A flow whose terminal event queued before a newer sign-in committed must
    /// not persist its credential afterwards.
    ///
    /// The inline lease ends at the queue boundary; the lifecycle's persist
    /// runs after the queue drains, and that is the LAST point at which a stale
    /// flow can still write. Flow A commits and queues `Succeeded(A)`; flow B
    /// commits and persists; B's event drains first; A's then drains and the
    /// `Some(credentials)` branch persists A's token.
    ///
    /// The binding cannot catch this on its own: with opaque tokens both
    /// identities collapse onto the same client-only record, so the mismatch
    /// passes and the account reverts. The credential the live identity
    /// published is what discriminates.
    #[tokio::test]
    async fn a_queued_flow_cannot_persist_after_a_newer_sign_in_won() {
        let host = registered_host();
        let driver = driver_with_persistence_id("queued-flow", "queued-flow");

        // Flow A commits alice with alice-rt and queues its terminal event.
        publish_identity(&driver, "alice", Some("alice-rt"));

        // Flow B commits bob with bob-rt and persists.
        publish_identity(&driver, "bob", Some("bob-rt"));
        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("bob-rt"),
                None,
            ))
            .await
            .unwrap();

        // A's queued event now drains and the lifecycle persists ITS bundle.
        let refused = driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("alice-rt"),
                None,
            ))
            .await;

        assert_eq!(
            refused.unwrap_err().code(),
            ovstorage_plugin::ErrorCode::AuthCancelled,
            "the superseded flow cannot reach the durable write",
        );
        assert_eq!(
            host.secrets
                .lock()
                .unwrap()
                .get(&key(&driver.config.stable_id))
                .unwrap()
                .0,
            b"bob-rt",
            "the winner's credential is what is stored",
        );
    }

    /// A load the driver's generation fence discarded must leave the claim
    /// saying it adopted NOTHING.
    ///
    /// The read latches adoption as soon as the secret store returns a record, but
    /// the driver applies a second gate afterwards and hands back no bundle
    /// when a sign-in landed during the round trip. A latch left standing there
    /// makes a later sibling's arrival retro-actively fatal for a connection
    /// that never served on the stored lineage: `ensure_usable` refuses, and
    /// the operator sees an unnecessary re-authentication.
    #[tokio::test]
    async fn a_load_the_fence_discarded_leaves_the_claim_unadopted() {
        let host = registered_host();
        let driver = driver_with_persistence_id("fence-discard", "fence-discard-scope");

        // A stored, bound lineage this connection could adopt.
        publish_identity(&driver, "alice", Some("stored-rt"));
        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("stored-rt"),
                None,
            ))
            .await
            .unwrap();

        // A sign-in wins WHILE the warm continuation's keyring read is in
        // flight, so what the read returns is already stale when it lands.
        let racing = std::sync::Arc::clone(&driver.shared);
        *host.during_get.lock().unwrap() = Some(std::sync::Arc::new(move || {
            racing
                .identity_gen
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }));
        let loaded = driver.load_credentials().await.unwrap();
        *host.during_get.lock().unwrap() = None;
        assert!(
            loaded.is_none(),
            "the fence discards a record read before the sign-in",
        );

        // A sibling connection now claims the same key. This one adopted
        // nothing, so nothing about it became unattributable.
        let sibling = driver_with_persistence_id("fence-discard", "fence-discard-scope");
        assert_eq!(sibling.config.stable_id, driver.config.stable_id);
        let _sibling_claim = sibling.claim();
        assert!(
            driver.claim().ensure_usable().is_ok(),
            "a connection that adopted nothing is not retro-actively refused",
        );
    }

    #[tokio::test]
    async fn retiring_the_legacy_entry_leaves_no_orphaned_binding() {
        // The legacy hostname key is retired best-effort on the first
        // identity-scoped write. Removing only the token field would leave its
        // identity record behind — an orphan a later reader meets with no
        // secret attached. Both fields go together.
        let host = registered_host();
        let driver = driver_with_persistence_id("orphan", "orphan-scope");
        let legacy = ConnectionId(driver.config.server.clone());
        {
            let mut entries = host.secrets.lock().unwrap();
            entries.insert(key(&legacy), SecretBytes(b"legacy-rt".to_vec()));
            entries.insert(
                binding_key(&legacy),
                SecretBytes(b"legacy-binding".to_vec()),
            );
        }

        publish_identity(&driver, "alice", Some("rt"));
        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("rt"),
                None,
            ))
            .await
            .unwrap();

        let entries = host.secrets.lock().unwrap();
        assert!(!entries.contains_key(&key(&legacy)));
        assert!(
            !entries.contains_key(&binding_key(&legacy)),
            "the legacy record went with its token",
        );
    }

    #[tokio::test]
    async fn an_unbound_legacy_entry_is_refused_until_a_sign_in_binds_it() {
        let host = registered_host();
        let driver = driver_with_persistence_id("legacy", "legacy-migration");
        let entry = key(&driver.config.stable_id);
        host.secrets
            .lock()
            .unwrap()
            .insert(entry.clone(), SecretBytes(b"legacy-rt".to_vec()));

        // An entry a prior build wrote carries no identity binding, so it
        // cannot be attributed to this connection's account: warm continuation
        // declines it and the connection signs in instead.
        assert!(driver.load_credentials().await.unwrap().is_none());
        // The secret survives the refusal — the migration loses no credential
        // it cannot also re-mint.
        assert_eq!(
            host.secrets.lock().unwrap().get(&entry).unwrap().0,
            b"legacy-rt",
        );

        // A sign-in records who authenticated, and the rebind carries that
        // principal — not merely *a* record. A record naming nobody would
        // verify against every identity, leaving the entry adoptable by exactly
        // the sibling this binding exists to keep out.
        publish_identity(&driver, "alice", Some("bound-rt"));
        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("bound-rt"),
                None,
            ))
            .await
            .unwrap();
        let record = host
            .secrets
            .lock()
            .unwrap()
            .get(&binding_key(&driver.config.stable_id))
            .map(|bytes| bytes.0.clone())
            .expect("a bound entry carries its identity record");
        let record =
            ovstorage_plugin::oauth_secret_store::IdentityBinding::decode(&record).unwrap();
        assert_eq!(record.subject, "alice");
        assert_eq!(record.issuer, driver.config.server);
        assert!(record.is_specific());

        // The next warm continuation adopts the now-bound entry.
        let loaded = driver.load_credentials().await.unwrap().unwrap();
        assert!(matches!(
            refresh_token(&loaded).unwrap(),
            RefreshToken::Present("bound-rt")
        ));
    }

    #[tokio::test]
    async fn a_session_that_names_nobody_persists_no_credential() {
        // Reached only if a sign-in failed to record its principal. Writing the
        // token under a record matching every identity would be strictly worse
        // than not persisting: any connection deriving the same key would adopt
        // it. The cost of refusing is one interactive sign-in.
        let host = registered_host();
        let driver = driver_with_persistence_id("unbindable", "unbindable-scope");
        let refused = driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("rt"),
                None,
            ))
            .await;
        // Reported, not passed off as a persist: the lifecycle must not retire
        // this connection's persistence debt on a write that did not happen.
        assert_eq!(
            refused.unwrap_err().code(),
            ovstorage_plugin::ErrorCode::CredentialUnavailable,
        );

        let entries = host.secrets.lock().unwrap();
        assert!(!entries.contains_key(&key(&driver.config.stable_id)));
        assert!(!entries.contains_key(&binding_key(&driver.config.stable_id)));
    }

    #[tokio::test]
    async fn removal_clears_the_binding_with_the_secret() {
        let host = registered_host();
        let driver = driver_with_persistence_id("removal", "removal-scope");
        publish_identity(&driver, "alice", Some("rt"));
        driver
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("rt"),
                None,
            ))
            .await
            .unwrap();

        driver.purge_credentials().await.unwrap();

        // An orphaned binding would outlive the secret it describes.
        let entries = host.secrets.lock().unwrap();
        assert!(!entries.contains_key(&key(&driver.config.stable_id)));
        assert!(!entries.contains_key(&binding_key(&driver.config.stable_id)));
    }

    #[tokio::test]
    async fn identity_scoped_keyring_lifecycle_preserves_sibling() {
        // The stub keyring is shared by every test in this process, so each
        // works on connection keys of its own.
        let host = registered_host();
        let alice = driver("alice");
        let bob = driver("bob");
        assert_ne!(alice.config.stable_id, bob.config.stable_id);
        publish_identity(&alice, "alice", Some("alice-0"));
        publish_identity(&bob, "bob", Some("bob-0"));

        let legacy = key(&ConnectionId(alice.config.server.clone()));
        host.secrets
            .lock()
            .unwrap()
            .insert(legacy.clone(), SecretBytes(b"legacy".to_vec()));

        alice
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("alice-0"),
                None,
            ))
            .await
            .unwrap();
        bob.persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
            "",
            Some("bob-0"),
            None,
        ))
        .await
        .unwrap();

        let alice_key = key(&alice.config.stable_id);
        let bob_key = key(&bob.config.stable_id);
        {
            let entries = host.secrets.lock().unwrap();
            assert_eq!(entries.get(&alice_key).unwrap().0, b"alice-0");
            assert_eq!(entries.get(&bob_key).unwrap().0, b"bob-0");
            assert!(!entries.contains_key(&legacy));
        }

        let loaded = alice.load_credentials().await.unwrap().unwrap();
        assert!(matches!(
            refresh_token(&loaded).unwrap(),
            RefreshToken::Present("alice-0")
        ));

        // A rotation advances the live session, so the successor is the
        // credential the connection is serving on when it persists.
        rotate_session(&alice, "alice", "alice-1");
        alice
            .persist_credentials(&ovstorage_plugin::oauth_secret_store::oauth_bundle(
                "",
                Some("alice-1"),
                None,
            ))
            .await
            .unwrap();
        alice.purge_credentials().await.unwrap();

        let entries = host.secrets.lock().unwrap();
        assert!(!entries.contains_key(&alice_key));
        assert_eq!(entries.get(&bob_key).unwrap().0, b"bob-0");
    }
}
