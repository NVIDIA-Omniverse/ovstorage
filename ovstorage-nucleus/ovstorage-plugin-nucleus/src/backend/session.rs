// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-connection Nucleus session state (RFC-0066).
//!
//! The connection lifecycle belongs to
//! the generic `ConnectionSet<NucleusDriver>` and one v2 connection
//! owns exactly one [`NucleusShared`]. This module provides the live session cell and the
//! handshake install/teardown/refresh machinery the driver verbs call.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nucleus_client::LftClient;
use ovstorage_plugin::{
    AuthEventStream, CancellationToken, Error, ErrorCode, Result, SecretBundle, SecretBytes,
    SecretValue,
};

use crate::config::NucleusConfig;
use crate::handshake::{HandshakeOutput, NucleusSession, refresh_session};
use crate::ops::NucleusOps;
use tracing::debug;

use super::convert::poisoned_state;

/// Live per-connection session cell shared (via `Arc`) between the
/// [`super::spi::NucleusBackend`] serving the data path and the
/// `NucleusDriver` that establishes / refreshes the session.
pub(crate) struct NucleusShared {
    pub config: NucleusConfig,
    pub credentials: Mutex<SecretBundle>,
    /// The identity this connection's persisted refresh-token lineage belongs
    /// to: seeded from the durable store on warm continuation, checked against
    /// every handshake the driver stages, and written back on rotation.
    ///
    /// It lives on the shared cell rather than the driver because the
    /// interactive sign-in flows run against the cell alone, and a sign-in that
    /// did not record its principal would persist a record naming nobody.
    pub binding: ovstorage_plugin::oauth_secret_store::BindingCell,
    /// Serializes a durable credential write against an identity-changing
    /// install. See the crate's credential lock order.
    pub publication: std::sync::Mutex<()>,
    pub ops: Mutex<Option<Arc<dyn NucleusOps>>>,
    pub lft_client: Mutex<Option<Arc<LftClient>>>,
    /// Bumped on every successful refresh; lets concurrent retriers observe
    /// that another task already re-established the session.
    pub cred_epoch: AtomicU64,
    /// Bumped on IDENTITY installs — an explicit credential replacement or
    /// interactive success — and on session teardown. A teardown bump prevents
    /// an in-flight grant for the removed identity from resurrecting it.
    /// A same-identity background refresh ([`InstallKind::Refresh`]) swaps the
    /// transport state but deliberately does NOT advance it. A failed
    /// rotation's teardown fences on this counter: a same-identity refresh
    /// landing between the observation and the clear must NOT make the clear
    /// decline (the old identity still has to be torn down), whereas a genuine
    /// credential winner installed since must be preserved.
    pub identity_gen: AtomicU64,
    pub session: Mutex<Option<NucleusSession>>,
    /// Single-flight gate guarding load-check + refresh + epoch-bump.
    /// `tokio::sync::Mutex` because the inner network call awaits.
    pub refresh_lock: tokio::sync::Mutex<()>,
    #[cfg(test)]
    pub refresh_override: Mutex<Option<RefreshOverride>>,
    /// Test seam marking the generation-compare point inside
    /// [`install_refreshed_session`], invoked while the session lock is held.
    ///
    /// It must stay immediately before that compare: the test asserts the lock
    /// is held when it runs, which is how "the compare and the identity check
    /// share the install's lock" is checked.
    #[cfg(test)]
    pub observation_gate: Mutex<Option<ObservationGate>>,
    /// Test seam replacing the SOWS+ConnLib handshake in the driver's
    /// `verify`/`interactive` paths, so connection-lifecycle tests can drive
    /// the real `ConnectionSet` admission gate against a `MockTransport`.
    #[cfg(test)]
    pub handshake_override: Mutex<Option<HandshakeOverride>>,
}

/// The identity fence is the session lock, which an IDENTITY install holds
/// across its binding write and its generation bump. See the crate's credential
/// lock order for what may run inside it.
impl ovstorage_plugin::oauth_secret_store::IdentityEpoch for NucleusShared {
    fn with_identity_fence(
        &self,
        f: &mut dyn FnMut(
            ovstorage_plugin::oauth_secret_store::EpochView<'_>,
        ) -> ovstorage_plugin::oauth_secret_store::LeaseVerdict,
    ) -> ovstorage_plugin::oauth_secret_store::LeaseVerdict {
        let Ok(fence) = self.session.lock() else {
            return ovstorage_plugin::oauth_secret_store::LeaseVerdict::Superseded;
        };
        let live = self.binding.current();
        // Read off the live session rather than from a field installs have to
        // remember to update. The session IS the credential this connection is
        // serving on, so a rotation advances the proof by construction — a
        // mirrored field would still name the token live at the last identity
        // change, and every persist after a background refresh would be refused
        // as superseded.
        let published = fence
            .as_ref()
            .and_then(|session| session.refresh_token.as_deref())
            .map(ovstorage_plugin::oauth_secret_store::fingerprint);
        f(ovstorage_plugin::oauth_secret_store::EpochView {
            generation: self.identity_gen.load(Ordering::Acquire),
            binding: live.as_ref(),
            published_credential: published.as_deref(),
        })
    }
}

impl NucleusShared {
    pub(crate) fn new(config: NucleusConfig, credentials: SecretBundle) -> Arc<Self> {
        Arc::new(Self {
            config,
            credentials: Mutex::new(credentials),
            binding: ovstorage_plugin::oauth_secret_store::BindingCell::new(),
            publication: std::sync::Mutex::new(()),
            ops: Mutex::new(None),
            lft_client: Mutex::new(None),
            cred_epoch: AtomicU64::new(0),
            identity_gen: AtomicU64::new(0),
            session: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            observation_gate: Mutex::new(None),
            #[cfg(test)]
            refresh_override: Mutex::new(TEST_REFRESH_OVERRIDE.with(|slot| slot.borrow().clone())),
            #[cfg(test)]
            handshake_override: Mutex::new(
                TEST_HANDSHAKE_OVERRIDE.with(|slot| slot.borrow().clone()),
            ),
        })
    }

    /// Whether a session is currently installed (the data path is live).
    pub(crate) fn has_session(&self) -> bool {
        self.ops.lock().is_ok_and(|slot| slot.is_some())
    }
}

#[cfg(test)]
pub(crate) type RefreshOverride = std::sync::Arc<
    dyn Fn() -> Result<(Arc<dyn NucleusOps>, Option<Arc<LftClient>>, NucleusSession)> + Send + Sync,
>;

#[cfg(test)]
pub(crate) type ObservationGate = std::sync::Arc<dyn Fn(&NucleusShared) + Send + Sync>;

#[cfg(test)]
pub(crate) type HandshakeOverride =
    std::sync::Arc<dyn Fn() -> Result<HandshakeOutput> + Send + Sync>;

#[cfg(test)]
thread_local! {
    /// Ambient handshake seam for tests that cannot reach the per-cell
    /// override because the cell is constructed INSIDE the code under test
    /// (the layer's `instantiate_connection`/`probe`). Copied into each new
    /// [`NucleusShared`] at construction; thread-local so parallel tests
    /// cannot bleed overrides into each other (a `#[tokio::test]` body and
    /// the layer construction it drives run on one thread).
    pub(crate) static TEST_HANDSHAKE_OVERRIDE: std::cell::RefCell<Option<HandshakeOverride>> =
        const { std::cell::RefCell::new(None) };

    /// Ambient refresh seam, same pattern as [`TEST_HANDSHAKE_OVERRIDE`]:
    /// copied into each new [`NucleusShared`] so layer-level tests (which
    /// never see the cell) can drive the `with_recovery` →
    /// `NucleusDriver::refresh` → [`refresh_under_epoch`] loop without a
    /// live server.
    pub(crate) static TEST_REFRESH_OVERRIDE: std::cell::RefCell<Option<RefreshOverride>> =
        const { std::cell::RefCell::new(None) };
}

/// Whether an install replaces the identity (and so must be respected by a
/// failed rotation's teardown) or merely refreshes the same identity's
/// transport state. See [`NucleusShared::identity_gen`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum InstallKind {
    /// Explicit credential replacement or interactive success advances
    /// `identity_gen`.
    Identity,
    /// Same-identity background token refresh — swaps transport state, does
    /// NOT advance `identity_gen`.
    Refresh,
}

/// Carry the current session tokens alongside the replayable credential shape.
/// The generic connection lifecycle persists only the OAuth refresh slot; the
/// original api-token or username/password fields remain available as a
/// refresh fallback when a deployment does not issue refresh tokens.
pub(crate) fn credentials_with_session(
    base: &SecretBundle,
    session: &NucleusSession,
) -> SecretBundle {
    let mut effective = base.clone();
    effective.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(session.access_token.as_bytes().to_vec()),
            refresh: session
                .refresh_token
                .as_ref()
                .map(|token| SecretBytes(token.as_bytes().to_vec())),
            expires_at: None,
        },
    );
    effective
}

pub(crate) enum RefreshToken<'a> {
    Absent,
    Clear,
    Present(&'a str),
}

pub(crate) fn refresh_token(bundle: &SecretBundle) -> Result<RefreshToken<'_>> {
    let Some(SecretValue::OAuthToken { refresh, .. }) = bundle.fields.get("oauth") else {
        return Ok(RefreshToken::Absent);
    };
    let Some(refresh) = refresh else {
        return Ok(RefreshToken::Clear);
    };
    let token = std::str::from_utf8(&refresh.0).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "Nucleus refresh token must be valid UTF-8",
        )
    })?;
    Ok(if token.is_empty() {
        RefreshToken::Clear
    } else {
        RefreshToken::Present(token)
    })
}

impl NucleusShared {
    /// Seed the binding from a durable record, unless an identity-changing
    /// install landed since `expected_gen` was read.
    ///
    /// The compare and the write happen under the session lock — the lock an
    /// IDENTITY install holds across its own binding write and generation bump
    /// — so a sign-in that won while the secret store read was in flight is either
    /// wholly visible here or not at all. Without this a warm load silently
    /// reverted a completed sign-in to the previously stored account, and
    /// advanced nothing, so nothing downstream could tell.
    pub(crate) fn adopt_binding_if_identity_unchanged(
        &self,
        binding: ovstorage_plugin::oauth_secret_store::IdentityBinding,
        expected_gen: u64,
    ) -> bool {
        let Ok(_fence) = self.session.lock() else {
            return false;
        };
        if self.identity_gen.load(Ordering::Acquire) != expected_gen {
            return false;
        }
        self.binding.expect(binding);
        true
    }
}

/// The identity record for a Nucleus principal on this connection's server.
///
/// Nucleus reports the authenticated principal directly, so the binding names
/// the server and that principal rather than reading claims out of a bearer.
/// Both fields are non-empty for any real session, which is what keeps the
/// persisted record specific enough to refuse somebody else.
pub(crate) fn identity_binding(
    shared: &NucleusShared,
    principal: &str,
) -> ovstorage_plugin::oauth_secret_store::IdentityBinding {
    ovstorage_plugin::oauth_secret_store::IdentityBinding {
        issuer: shared.config.server.clone(),
        client_id: String::new(),
        subject: principal.to_string(),
    }
}

/// Atomically publish a complete live session, optionally fenced on the
/// identity generation captured by `ConnectionSet` at grant start.
///
/// Returns `false` when the expected generation is stale. In that case none of
/// the live transport, session, credential, epoch, or generation cells change.
#[must_use]
pub(crate) fn install_handshake_output(
    shared: &NucleusShared,
    ops: Arc<dyn NucleusOps>,
    lft: Option<Arc<LftClient>>,
    session: NucleusSession,
    credentials: SecretBundle,
    kind: InstallKind,
    expected_gen: Option<u64>,
) -> bool {
    debug!(plugin = "nucleus", server = %shared.config.server, lft_configured = lft.is_some(), install_kind = ?kind, "installing nucleus handshake output");
    // Install the transport state (ops/lft), session, effective credentials,
    // and generation bump as ONE critical section under the session lock — the same lock the
    // gen-gated clear ([`clear_session_state_if_identity_unchanged`]) holds for
    // its compare-and-clear. That mutual exclusion is what makes the clear see
    // either the whole install or none of it: it cannot slip between an
    // ops/lft store and the session store+bump and leave `session=Some` with
    // `ops=None`. Lock order session→ops→lft matches the clear, so the nested
    // acquisition cannot deadlock (no path takes ops/lft/credentials before
    // session while holding one of those locks).
    // Publication lock before the identity fence, per the crate's credential
    // lock order: a durable write and an identity-changing install must not
    // interleave.
    let _publishing = shared
        .publication
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Ok(mut session_slot) = shared.session.lock() {
        if expected_gen
            .is_some_and(|expected| shared.identity_gen.load(Ordering::Acquire) != expected)
        {
            return false;
        }
        if let Ok(mut slot) = shared.ops.lock() {
            *slot = Some(ops);
        }
        if let Ok(mut slot) = shared.lft_client.lock() {
            *slot = lft;
        }
        let principal = session.principal.clone();
        // Installing the session is what publishes the credential this
        // connection now serves on: the identity fence reads the refresh token
        // straight off the live session, so a REFRESH install advances the
        // supersession proof without a separate field to keep in step.
        *session_slot = Some(session);
        if let Ok(mut slot) = shared.credentials.lock() {
            *slot = credentials;
        }
        if kind == InstallKind::Identity {
            // An IDENTITY install is this connection's authoritative statement
            // of who it is: an interactive sign-in, or a handshake the driver
            // already checked against the stored record. Either way the
            // principal the server just authenticated defines the binding any
            // subsequent persist writes, so the record can never name nobody.
            //
            // A REFRESH install leaves the record alone because it was already
            // checked against it — [`install_refreshed_session`] verifies the
            // grant's principal before calling here, and refuses rather than
            // installing when it disagrees. Nothing reaches the live cell
            // without its identity having been confirmed or established.
            shared.binding.expect(identity_binding(shared, &principal));
            shared
                .identity_gen
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        return true;
    }
    false
}

/// Clear the session only if no newer IDENTITY landed since `observed_gen` was
/// read — the failure-path clear, for callers
/// running outside the credential lifecycle's serialization (a failed
/// rotation's clear must not erase a concurrently installed credential winner).
/// Returns whether the clear ran. A successful clear advances `identity_gen`:
/// teardown is itself an identity-changing live-cell write, and the bump fences
/// an already-running refresh of the removed identity out of a later install.
///
/// Fences on `identity_gen`, NOT a bump-on-every-install counter: a
/// same-identity background refresh that lands between the observation and this
/// call leaves `identity_gen` untouched, so the clear still PROCEEDS and tears
/// the old identity's (freshly refreshed) session down — the invariant Finding
/// K5-r3 flagged. Only an identity-changing install or teardown advances the
/// counter and makes a stale clear decline.
///
/// The whole compare-and-clear holds the `session` lock — the same lock
/// [`install_handshake_output`] performs its atomic store+bump under — so an
/// install and this guard are mutually exclusive: the clear observes either a
/// completed install (and, for an identity install, the bumped generation) or a
/// not-yet-started one, never a torn middle. `ops`/`lft_client` are nested
/// inside deliberately: no other path holds those locks while acquiring
/// `session`, so the nesting cannot deadlock, and clearing them under the same
/// guard means a concurrent install cannot slip fresh transport state in
/// between.
/// Teardown bumps `identity_gen`, so it is an identity-changing write and takes
/// the publication lock like every other one — see the crate's credential lock
/// order.
pub(crate) fn clear_session_state_if_identity_unchanged(
    shared: &NucleusShared,
    observed_gen: u64,
) -> bool {
    let _publishing = shared
        .publication
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Ok(mut session_slot) = shared.session.lock() else {
        return false;
    };
    if shared
        .identity_gen
        .load(std::sync::atomic::Ordering::Acquire)
        != observed_gen
    {
        return false;
    }
    *session_slot = None;
    if let Ok(mut slot) = shared.ops.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = shared.lft_client.lock() {
        *slot = None;
    }
    shared.identity_gen.fetch_add(1, Ordering::AcqRel);
    true
}

/// Single-flight session refresh: re-check the epoch under `refresh_lock` so
/// concurrent retriers that observed the same stale epoch collapse onto one
/// network round-trip, then bump `cred_epoch` only on success. This is the
/// engine behind `NucleusDriver::refresh` (the data-path recovery loop
/// and the `ConnectionSet` background scheduler both land here).
pub(crate) async fn refresh_under_epoch(
    shared: &Arc<NucleusShared>,
    current_credentials: &SecretBundle,
    observed_epoch: u64,
    expected_gen: u64,
) -> Result<Option<SecretBundle>> {
    let _guard = shared.refresh_lock.lock().await;
    if shared.identity_gen.load(Ordering::Acquire) != expected_gen {
        return Ok(None);
    }
    let current = shared.cred_epoch.load(Ordering::Acquire);
    if current > observed_epoch {
        debug!(plugin = "nucleus", server = %shared.config.server, "nucleus token refresh: another task already refreshed");
        return Ok(shared.credentials.lock().ok().map(|guard| guard.clone()));
    }
    debug!(plugin = "nucleus", server = %shared.config.server, "nucleus token refresh: refreshing session");

    #[cfg(test)]
    if let Some(callback) = shared
        .refresh_override
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
    {
        let (ops, lft, new_session) = callback()?;
        let base = merge_current_oauth(shared, current_credentials)?;
        return install_refreshed_session(shared, &base, ops, lft, new_session, expected_gen);
    }

    let mut prior = shared
        .session
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "Nucleus refresh: no cached session (initial handshake never ran)",
            )
        })?;
    let bundle = merge_current_oauth(shared, current_credentials)?;
    if let RefreshToken::Present(refresh) = refresh_token(current_credentials)? {
        prior.refresh_token = Some(refresh.to_string());
    }
    let HandshakeOutput { ops, lft, session } =
        refresh_session(&shared.config, &bundle, &prior).await?;

    install_refreshed_session(shared, &bundle, ops, lft, session, expected_gen)
}

/// Install a session a refresh grant returned, after confirming it
/// authenticated as the principal this connection's lineage is bound to.
///
/// A refresh grant is not trusted to be same-identity just because it was
/// driven from a same-identity token: that is a statement about the provider,
/// not something this process observes. A grant that comes back as somebody
/// else is refused before the session reaches the live cell, so the data path
/// never serves under an identity the connection is not bound to, and the
/// rotated token is never persisted beside a record it contradicts.
///
/// `Err(AuthRequired)` propagates to the `ConnectionSet`, which purges the
/// lineage and re-authenticates.
fn install_refreshed_session(
    shared: &Arc<NucleusShared>,
    base: &SecretBundle,
    ops: Arc<dyn NucleusOps>,
    lft: Option<Arc<LftClient>>,
    session: NucleusSession,
    expected_gen: u64,
) -> Result<Option<SecretBundle>> {
    // Supersession outranks the identity check: a refresh whose generation has
    // already moved on is discarded whatever it returned, and reporting its
    // principal as a mismatch would make the `ConnectionSet` purge the lineage
    // of the credential winner that superseded it.
    //
    // The two are read under the SESSION lock, which is the lock an IDENTITY
    // install holds while it writes the binding and bumps the generation. A
    // pair of independent reads would not do: an install that had written its
    // binding but not yet bumped is visible as "somebody else's principal, same
    // generation", and this would report an identity failure against the very
    // connection about to win.
    let verdict = {
        let _fence = shared.session.lock().map_err(poisoned_state)?;
        #[cfg(test)]
        {
            let gate = shared
                .observation_gate
                .lock()
                .ok()
                .and_then(|guard| guard.clone());
            if let Some(gate) = gate {
                gate(shared);
            }
        }
        if shared.identity_gen.load(Ordering::Acquire) != expected_gen {
            None
        } else {
            Some(
                shared
                    .binding
                    .observe(identity_binding(shared, &session.principal)),
            )
        }
    };
    match verdict {
        None => return Ok(None),
        Some(Err(err)) => return Err(err),
        Some(Ok(())) => {}
    }
    let effective = credentials_with_session(base, &session);
    if !install_handshake_output(
        shared,
        ops,
        lft,
        session,
        effective.clone(),
        InstallKind::Refresh,
        Some(expected_gen),
    ) {
        return Ok(None);
    }
    shared.cred_epoch.fetch_add(1, Ordering::AcqRel);
    Ok(Some(effective))
}

/// Keep replayable explicit credentials from the live cell while replacing
/// its OAuth slot with the secret store head `ConnectionSet` loaded under the
/// cross-process lock. This prevents replaying an in-memory predecessor after
/// a sibling process rotated the token.
fn merge_current_oauth(shared: &NucleusShared, current: &SecretBundle) -> Result<SecretBundle> {
    let mut base = shared.credentials.lock().map_err(poisoned_state)?.clone();
    if let Some(oauth) = current.fields.get("oauth") {
        base.fields.insert("oauth".into(), oauth.clone());
    }
    Ok(base)
}

/// Spawn a worker thread that runs the URL+nonce-poll handshake and pushes
/// `AuthEvent`s into a sync channel as they're produced. The returned
/// iterator drains the receiver — `Iterator::next()` blocks until the next
/// event arrives, so the host sees the `OpenBrowser { url, ... }` event the
/// moment `start_interactive` resolves, instead of after the minutes-long
/// sign-in poll.
///
/// One OS thread per concurrent interactive sign-in is acceptable: bounded
/// by user traffic, not code paths. The thread owns its own current-thread
/// tokio runtime so blocking on `Iterator::next` cannot deadlock the host's
/// runtime.
pub(crate) fn spawn_interactive_auth_stream(
    shared: Arc<NucleusShared>,
    connection: ovstorage_plugin::Connection,
    cancel: Option<CancellationToken>,
    expected_gen: u64,
) -> AuthEventStream {
    let (tx, rx) = std::sync::mpsc::channel::<Result<ovstorage_plugin::AuthEvent>>();
    // Kept outside the closure so a FAILED spawn (thread exhaustion) can
    // still surface an error event instead of panicking into the FFI
    // unwind wall.
    let tx_for_spawn_failure = tx.clone();
    let pump = std::thread::Builder::new()
        .name("ovs-nuc-auth".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = tx.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!("nucleus auth pump: failed to build runtime: {err}"),
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                // The test handshake seam applies here too so lifecycle tests
                // can drive an interactive success without a live server.
                #[cfg(test)]
                if let Some(callback) = shared
                    .handshake_override
                    .lock()
                    .ok()
                    .and_then(|guard| guard.clone())
                {
                    match callback() {
                        Ok(HandshakeOutput { ops, lft, session }) => {
                            install_and_emit_interactive_success(
                                &shared,
                                &tx,
                                connection,
                                ops,
                                lft,
                                session,
                                expected_gen,
                            );
                        }
                        Err(error) => {
                            clear_session_state_if_identity_unchanged(&shared, expected_gen);
                            let _ = tx.send(Ok(ovstorage_plugin::AuthEvent::Failed { error }));
                        }
                    }
                    return;
                }
                let output = crate::handshake::establish_interactive_auth(
                    &shared.config,
                    connection,
                    cancel,
                    tx.clone(),
                )
                .await;
                // Install BEFORE forwarding the terminal `Succeeded` (the
                // helper withholds it): a host that reacts to `Succeeded` —
                // the `ConnectionSet` adapter's `on_authenticated` — must
                // find the session already live, or a completed sign-in
                // would re-handshake an interactive-marker bundle, fail,
                // and park an already-successful connection.
                if let Some((HandshakeOutput { ops, lft, session }, connection)) = output {
                    install_and_emit_interactive_success(
                        &shared,
                        &tx,
                        connection,
                        ops,
                        lft,
                        session,
                        expected_gen,
                    );
                } else {
                    clear_session_state_if_identity_unchanged(&shared, expected_gen);
                }
            });
        })
        .map_err(|err| {
            let _ = tx_for_spawn_failure.send(Err(Error::new(
                ErrorCode::Internal,
                format!("nucleus auth pump: failed to spawn thread: {err}"),
            )));
        })
        .ok();
    Box::new(InteractiveAuthIter { rx, _pump: pump })
}

fn install_and_emit_interactive_success(
    shared: &NucleusShared,
    tx: &std::sync::mpsc::Sender<Result<ovstorage_plugin::AuthEvent>>,
    connection: ovstorage_plugin::Connection,
    ops: Arc<dyn NucleusOps>,
    lft: Option<Arc<LftClient>>,
    session: NucleusSession,
    expected_gen: u64,
) {
    let base = shared
        .credentials
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let effective = credentials_with_session(&base, &session);
    let event = if install_handshake_output(
        shared,
        ops,
        lft,
        session,
        effective.clone(),
        InstallKind::Identity,
        Some(expected_gen),
    ) {
        ovstorage_plugin::AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: Some(effective),
        }
    } else {
        ovstorage_plugin::AuthEvent::Failed {
            error: Error::new(
                ErrorCode::AuthCancelled,
                "Nucleus interactive authentication was superseded",
            ),
        }
    };
    let _ = tx.send(Ok(event));
}

struct InteractiveAuthIter {
    rx: std::sync::mpsc::Receiver<Result<ovstorage_plugin::AuthEvent>>,
    /// Joined on drop so the worker thread is reaped if the host stops
    /// pulling early (e.g. host cancels sign-in mid-poll). `None` when the
    /// spawn itself failed (the stream then carries only the failure event).
    _pump: Option<std::thread::JoinHandle<()>>,
}

impl Iterator for InteractiveAuthIter {
    type Item = Result<ovstorage_plugin::AuthEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}
