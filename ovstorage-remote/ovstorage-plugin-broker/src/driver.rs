// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ConnectionAuthDriver` for the broker **client** backend.
//!
//! The generic `ConnectionSet<BrokerDriver>` embedded on the crate's
//! `BrokerClientLayer` owns the `ConnectionAuthState` machine, single-flight
//! bring-up, cooldown, background-refresh scheduling, cross-process coalescing,
//! and the data-path recovery loop; this driver supplies only the broker's
//! **tier-1** (client → broker-listener) auth verbs — obtain / verify / activate
//! / refresh / interactive / classify — plus secret persistence, wrapping the
//! existing `auth` flows. `obtain` grants against a driver-PRIVATE staging
//! `DiscoveryState` and `verify` probes over an EPHEMERAL transport, so neither
//! ever touches the live token cell; only `activate` installs a proven bearer.
//!
//! Broker credential model (a deviation from the services-client template):
//! - **Direct-endpoint** addresses (`unix:` / `npipe:` / `grpc[+tls/+tcp]://`)
//!   have no OAuth surface — a configured `token_file` bearer, else anonymous.
//! - **Discovery** addresses (`http(s)://`) drive OIDC: a config-driven
//!   `client_secret_file` `client_credentials` grant, a supplied OAuth bundle,
//!   a supplied `(client_id, client_secret)` pair, or an interactive flow.
//!
//! Tier-3 brokered *upstream* auth is selected by the
//! `BrokerClientLayer::authenticate_connection` branch in `layer.rs` when the
//! request carries `ext::UPSTREAM_AUTH_ADDRESS`; that branch drives the broker's
//! upstream auth stream through `auth::drive_upstream_auth`.

use std::sync::Weak;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ovstorage_plugin::connection::{
    AuthErrorClass, ConnectionAuthDriver, GrantPolicy, Obtained, Refreshed,
};
use ovstorage_plugin::{
    AuthEventStream, AuthReason, CancellationToken, Connection, ConnectionId, Error, ErrorCode,
    InteractiveAuthCapability, Result, SecretBundle, SecretBytes, SecretValue, oauth_secret_store,
    race_cancel,
};

use crate::auth::{
    self, DiscoveryState, drive_client_credentials_grant,
    drive_client_credentials_grant_with_secret, drive_interactive_login, drive_refresh_token_grant,
};
use crate::layer::BrokerClientLayer;
use crate::{KEYRING_BACKEND_KIND, KIND, PLUGIN_NAME, read_token_file, transport_for_with_auth};

/// Per-connection broker-client auth driver. Holds the connection's broker
/// address (discovery URL or direct endpoint), the config-derived credential
/// mode, the shared [`DiscoveryState`] the transport interceptor reads, a shared
/// HTTP client for OIDC grants, and the stable keyring id.
pub struct BrokerDriver {
    discovery_url: String,
    /// Direct-endpoint scheme (`unix:` / `npipe:` / `grpc*://`) — no OAuth.
    is_direct: bool,
    /// `[connection.auth] token_file` bearer path (direct mode only).
    token_file: Option<String>,
    /// `[connection.auth] client_secret_file` M2M secret path (discovery mode).
    client_secret_file: Option<String>,
    state: DiscoveryState,
    http: reqwest::Client,
    /// Stable cross-process/cross-restart id (broker address + OIDC client
    /// identity + durable account discriminator) for the secret store + refresh lock
    /// — the host `ConnectionId` is `pid+nanos`. This stable key lets persisted
    /// refresh tokens warm-continue across upgrades.
    stable: ConnectionId,
    /// This connection's claim on `stable`. A second live connection claiming
    /// the same key makes the stored lineage ambiguous, and persistence is
    /// refused for both until the operator sets distinct `persistence_id`s.
    ///
    /// Taken lazily, on first use. Acquiring it in the constructor would claim
    /// the UNSCOPED key for as long as it took the builder to apply
    /// `persistence_id` — long enough to contend with a sibling connection
    /// sitting on that key, which then stays ambiguous permanently over a key
    /// this connection never ends up using.
    claim: std::sync::OnceLock<oauth_secret_store::SharedPersistenceClaim>,
    /// Back-reference to the owning layer so [`Self::on_authenticated`] can
    /// republish routes after a deferred sign-in. `Weak` because the layer owns
    /// (via its `ConnectionSet`) this driver — an `Arc` would leak the cycle.
    layer: Weak<BrokerClientLayer>,
}

impl BrokerDriver {
    pub fn new(
        discovery_url: String,
        is_direct: bool,
        token_file: Option<String>,
        client_secret_file: Option<String>,
        state: DiscoveryState,
        http: reqwest::Client,
        layer: Weak<BrokerClientLayer>,
    ) -> Self {
        let stable =
            oauth_secret_store::conn_id_from_url_and_client(&discovery_url, state.client_name());
        Self {
            discovery_url,
            is_direct,
            token_file,
            client_secret_file,
            state,
            http,
            stable,
            claim: std::sync::OnceLock::new(),
            layer,
        }
    }

    /// Scope this connection's durable key by its account discriminator.
    ///
    /// `persistence_id` is immutable operator-chosen config: two connections to
    /// one broker address under one OIDC client, intended for different
    /// accounts, otherwise derive one key and share one refresh-token lineage.
    /// An empty value leaves the key on the client-scoped form.
    pub fn with_persistence_id(mut self, persistence_id: &str) -> Self {
        self.stable = oauth_secret_store::conn_id_from_url_and_account(
            &self.discovery_url,
            self.state.client_name(),
            persistence_id,
        );
        // No claim can have been taken yet on the production path, and
        // dropping any that was releases the unscoped key rather than holding
        // it against the connection sitting there.
        self.claim.take();
        self
    }

    /// This connection's identity epoch, for minting a flow's lease.
    pub fn identity_epoch(&self) -> std::sync::Arc<dyn oauth_secret_store::IdentityEpoch> {
        std::sync::Arc::new(self.state.clone())
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

    /// This connection's claim on its final durable key, taken on first use.
    fn claim(&self) -> &oauth_secret_store::SharedPersistenceClaim {
        self.claim.get_or_init(|| {
            std::sync::Arc::new(oauth_secret_store::PersistenceClaim::acquire(
                KEYRING_BACKEND_KIND,
                &self.stable,
            ))
        })
    }

    /// Check a freshly granted bearer against the identity the persisted
    /// lineage is bound to, latching the sharpened record for the next persist.
    ///
    /// `Err(AuthRequired)` means the session authenticated as someone other
    /// than the account this connection's stored credential belongs to. Raised
    /// from a grant on the secret store lineage, it takes the `ConnectionSet`'s
    /// purge-and-reauthenticate path, so the unusable entry is dropped rather
    /// than replayed.
    fn check_identity(&self, access: &str) -> Result<()> {
        let observed =
            oauth_secret_store::identity_from_access_token(access, self.state.client_name());
        // No fence: `obtain`'s adoption decision is not racing a commit of its
        // own, and an unfenced check there is the strict one.
        self.state
            .observe_binding_unless_superseded(observed, self.state.identity_generation())?;
        Ok(())
    }

    /// [`Self::check_identity`], with supersession outranking an identity
    /// failure.
    ///
    /// A grant whose identity generation has already moved past `expected_gen`
    /// is being discarded anyway: its commit is fenced out downstream.
    /// Reporting *its* bearer as an identity mismatch would name the connection
    /// that just won the sign-in, and the lifecycle parks a credential-class
    /// failure — leaving the winner holding valid tokens it cannot use.
    ///
    /// The generation compare and the identity check happen under the binding
    /// lock, which every identity-changing write holds across its bump, so a
    /// winner cannot be observed half-applied.
    fn check_identity_unless_superseded(&self, access: &str, expected_gen: u64) -> Result<bool> {
        let observed =
            oauth_secret_store::identity_from_access_token(access, self.state.client_name());
        self.state
            .observe_binding_unless_superseded(observed, expected_gen)
    }

    /// Fetch + install auth-config and OIDC discovery onto `state` if absent
    /// (idempotent). `obtain` runs discovery on PRIVATE staging, so the live
    /// cell may still lack these when a later `refresh` / `interactive` runs.
    async fn ensure_oidc_loaded(&self, state: &DiscoveryState) -> Result<()> {
        if state.oidc_config().await.is_none() {
            let auth_config = auth::fetch_auth_config(&self.http, &self.discovery_url).await?;
            state.install_auth_config(auth_config.clone()).await;
            let oidc = auth::fetch_oidc_config(&self.http, &auth_config).await?;
            state.install_oidc_config(oidc).await;
        }
        Ok(())
    }
}

/// Whether the ONLY path from `creds` to a working bearer is a *consuming*
/// refresh-token grant — the condition a [`GrantPolicy::NonConsumingOnly`]
/// `obtain` (a probe) must refuse with [`Obtained::WouldConsume`] rather than
/// burn a one-time refresh token. A `client_credentials` pair is replayable, so
/// it never consumes; a supplied access token still valid beyond
/// [`auth::REFRESH_SKEW`] is usable as-is; only an empty / expired / near-expiry
/// access token backed by a refresh token would-consume.
fn would_consume_only(creds: &SecretBundle) -> bool {
    if creds.fields.contains_key("client_id") && creds.fields.contains_key("client_secret") {
        return false;
    }
    let Some(SecretValue::OAuthToken {
        token,
        refresh,
        expires_at,
    }) = creds.fields.get("oauth")
    else {
        return false;
    };
    let has_refresh = matches!(refresh, Some(rt) if !rt.0.is_empty());
    let access_usable = !token.0.is_empty()
        && match expires_at {
            None => true,
            Some(at) => SystemTime::now() + auth::REFRESH_SKEW < *at,
        };
    if access_usable {
        return false;
    }
    has_refresh
}

/// Read a UTF-8 string from a `SecretValue::Bytes` field. `Ok(None)` when
/// absent; `InvalidArgument` when present but the wrong variant / non-UTF-8.
fn extract_secret_string(value: Option<&SecretValue>, field: &str) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(SecretValue::Bytes(b)) => String::from_utf8(b.0.clone()).map(Some).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker: {field} must be valid UTF-8"),
            )
        }),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("broker: {field} must be a Bytes secret value"),
        )),
    }
}

impl BrokerDriver {
    /// Build the effective `Obtained::Bearer` for an OAuth-bundle credential,
    /// honoring `policy` (a `NonConsumingOnly` probe that would need a consuming
    /// refresh grant reports `WouldConsume`). Grants run on `staging`.
    async fn obtain_from_oauth(
        &self,
        staging: &DiscoveryState,
        token: &[u8],
        refresh: Option<&[u8]>,
        expires_at: Option<SystemTime>,
        policy: GrantPolicy,
    ) -> Result<Obtained> {
        let access = String::from_utf8(token.to_vec()).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "broker: oauth access token must be valid UTF-8",
            )
        })?;
        let refresh_str = match refresh {
            Some(rt) => Some(String::from_utf8(rt.to_vec()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "broker: oauth refresh token must be valid UTF-8",
                )
            })?),
            None => None,
        };
        let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
        staging
            .install_tokens(access, refresh_str, expires_in)
            .await;
        if staging.token_needs_refresh().await && staging.refresh_token().await.is_some() {
            if policy == GrantPolicy::NonConsumingOnly {
                return Ok(Obtained::WouldConsume);
            }
            if let Err(err) = drive_refresh_token_grant(&self.http, staging).await {
                tracing::warn!(
                    target: "ovstorage.broker.auth",
                    error = %err.message(),
                    "broker: initial refresh failed; connection awaits auth"
                );
                return Ok(Obtained::AwaitingInteractive {
                    reason: AuthReason::RefreshTokenExpired,
                });
            }
        }
        let access = staging.access_token().await.unwrap_or_default();
        // Adopt the session only once the bearer proves it belongs to the
        // account the persisted lineage is bound to.
        self.check_identity(&access)?;
        let refresh = staging.refresh_token().await;
        let expires_at = staging.access_token_expires_at().await;
        Ok(Obtained::Bearer {
            credentials: oauth_secret_store::oauth_bundle(&access, refresh.as_deref(), expires_at),
            expires_at,
        })
    }

    /// Parse a PROVEN `activate` bundle into the pieces the live-cell install
    /// primitives need: `(access, refresh, expires_in, client_credentials)`.
    /// `Ok(None)` when the bundle carries no OAuth bearer (anonymous / direct —
    /// nothing to install). A non-empty `client_credentials` pair is the M2M
    /// grant's `(client_id, client_secret)` that `obtain` stamped onto the
    /// effective bundle (the grant ran on private staging).
    #[allow(clippy::type_complexity)]
    fn parse_activation_bundle(
        credentials: &SecretBundle,
    ) -> Result<
        Option<(
            String,
            Option<String>,
            Option<Duration>,
            Option<(String, String)>,
        )>,
    > {
        let Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) = credentials.fields.get("oauth")
        else {
            return Ok(None);
        };
        let access = String::from_utf8(token.0.clone()).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "broker: oauth access token must be valid UTF-8",
            )
        })?;
        let refresh = match refresh {
            Some(rt) => Some(String::from_utf8(rt.0.clone()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "broker: oauth refresh token must be valid UTF-8",
                )
            })?),
            None => None,
        };
        let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
        // M2M pair, if the effective bundle carries one: `obtain` stamped it
        // because the client_credentials grant ran on private staging.
        let client_credentials = match (
            credentials.fields.get("client_id"),
            credentials.fields.get("client_secret"),
        ) {
            (Some(SecretValue::Bytes(id)), Some(SecretValue::Bytes(secret))) => {
                match (
                    String::from_utf8(id.0.clone()),
                    String::from_utf8(secret.0.clone()),
                ) {
                    (Ok(id), Ok(secret)) if !id.is_empty() && !secret.is_empty() => {
                        Some((id, secret))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        Ok(Some((access, refresh, expires_in, client_credentials)))
    }
}

#[async_trait]
impl ConnectionAuthDriver for BrokerDriver {
    fn backend_kind(&self) -> &str {
        KIND
    }

    fn stable_id(&self) -> Option<ConnectionId> {
        Some(self.stable.clone())
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
        if policy == GrantPolicy::NonConsumingOnly && would_consume_only(creds) {
            return Ok(Obtained::WouldConsume);
        }
        // Direct-endpoint schemes have no OAuth surface.
        if self.is_direct {
            if let Some(token_file) = &self.token_file {
                let token = read_token_file(std::path::Path::new(token_file))?;
                return Ok(Obtained::Bearer {
                    credentials: oauth_secret_store::oauth_bundle(&token, None, None),
                    expires_at: None,
                });
            }
            return Ok(Obtained::Anonymous);
        }
        race_cancel(cancel.as_ref(), async {
            // Grant against a PRIVATE staging `DiscoveryState` — never the live
            // `self.state` the interceptor reads and never the secret store (the
            // `ConnectionSet` owns keyring reload/persist under its lock).
            let staging = DiscoveryState::new(self.state.client_name().to_string());
            // No auth-config published → broker is anonymous-friendly.
            let auth_config = match auth::fetch_auth_config(&self.http, &self.discovery_url).await {
                Ok(cfg) => cfg,
                Err(err) if err.code() == ErrorCode::NotConfigured => {
                    return Ok(Obtained::Anonymous);
                }
                Err(err) => return Err(err),
            };
            staging.install_auth_config(auth_config.clone()).await;
            let oidc = auth::fetch_oidc_config(&self.http, &auth_config).await?;
            staging.install_oidc_config(oidc).await;

            // (1) config-driven `client_secret_file` M2M grant — replayable, so
            // allowed even under `NonConsumingOnly`. `refresh` re-reads the file.
            if let Some(secret_file) = &self.client_secret_file {
                return Ok(
                    match drive_client_credentials_grant(
                        &self.http,
                        &staging,
                        std::path::Path::new(secret_file),
                    )
                    .await
                    {
                        Ok(_) => {
                            let access = staging.access_token().await.unwrap_or_default();
                            let expires_at = staging.access_token_expires_at().await;
                            Obtained::Bearer {
                                credentials: oauth_secret_store::oauth_bundle(
                                    &access, None, expires_at,
                                ),
                                expires_at,
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                target: "ovstorage.broker.auth",
                                error = %err.message(),
                                "broker: initial client_secret_file grant failed; awaits auth"
                            );
                            Obtained::AwaitingInteractive {
                                reason: AuthReason::RefreshTokenExpired,
                            }
                        }
                    },
                );
            }

            // (2) supplied OAuth bundle.
            if let Some(SecretValue::OAuthToken {
                token,
                refresh,
                expires_at,
            }) = creds.fields.get("oauth")
            {
                return self
                    .obtain_from_oauth(
                        &staging,
                        &token.0,
                        refresh.as_ref().map(|r| r.0.as_slice()),
                        *expires_at,
                        policy,
                    )
                    .await;
            }

            // (3) supplied `(client_id, client_secret)` pair (SecretBundle M2M).
            let client_id = extract_secret_string(creds.fields.get("client_id"), "client_id")?;
            let client_secret =
                extract_secret_string(creds.fields.get("client_secret"), "client_secret")?;
            if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
                staging
                    .set_client_credentials(client_id.clone(), client_secret.clone())
                    .await;
                return Ok(
                    match drive_client_credentials_grant_with_secret(
                        &self.http,
                        &staging,
                        &client_id,
                        &client_secret,
                    )
                    .await
                    {
                        Ok(_) => {
                            let access = staging.access_token().await.unwrap_or_default();
                            let refresh = staging.refresh_token().await;
                            let expires_at = staging.access_token_expires_at().await;
                            let mut effective = oauth_secret_store::oauth_bundle(
                                &access,
                                refresh.as_deref(),
                                expires_at,
                            );
                            // The pair ran on PRIVATE staging, so carry it through
                            // in the effective bundle for `activate` to cache on
                            // the live cell (a client_credentials connection has no
                            // refresh token to fall back on).
                            effective.fields.insert(
                                "client_id".into(),
                                SecretValue::Bytes(SecretBytes(client_id.into_bytes())),
                            );
                            effective.fields.insert(
                                "client_secret".into(),
                                SecretValue::Bytes(SecretBytes(client_secret.into_bytes())),
                            );
                            Obtained::Bearer {
                                credentials: effective,
                                expires_at,
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                target: "ovstorage.broker.auth",
                                error = %err.message(),
                                "broker: initial client_credentials grant failed; awaits auth"
                            );
                            Obtained::AwaitingInteractive {
                                reason: AuthReason::RefreshTokenExpired,
                            }
                        }
                    },
                );
            }

            // (4) auth-config present but no credential — interactive required.
            Ok(Obtained::AwaitingInteractive {
                reason: AuthReason::NeverAuthenticated,
            })
        })
        .await
    }

    async fn verify(
        &self,
        credentials: &SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // Prove the backend accepts the bearer with ONE read-only RPC over an
        // EPHEMERAL transport whose interceptor reads a fresh private state
        // seeded with only `credentials`' bearer — never the live cell. An empty
        // (anonymous) bundle probes anonymously.
        let vstate = DiscoveryState::new(self.state.client_name().to_string());
        if let Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) = credentials.fields.get("oauth")
        {
            let access = String::from_utf8(token.0.clone()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "broker: oauth access token must be valid UTF-8",
                )
            })?;
            let refresh = match refresh {
                Some(rt) => Some(String::from_utf8(rt.0.clone()).map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "broker: oauth refresh token must be valid UTF-8",
                    )
                })?),
                None => None,
            };
            let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
            vstate.install_tokens(access, refresh, expires_in).await;
        }
        let transport = transport_for_with_auth(&self.discovery_url, Some(vstate)).await?;
        race_cancel(cancel.as_ref(), async {
            transport.list_address_roots().await.map(|_| ())
        })
        .await
    }

    async fn activate(&self, credentials: &SecretBundle, expected_gen: u64) -> Result<bool> {
        // Install a PROVEN bundle onto the LIVE cell with same-identity MERGE
        // semantics, fenced on `expected_gen`: a concurrent interactive success
        // or credential update that bumped `identity_gen` wins, and the merge is
        // skipped (not an error). A `None` refresh PRESERVES the existing slot
        // (RFC 6749 §6), and `identity_gen` is NOT bumped — this is the bring-up /
        // warm-continue path (`Lineage::Stored`). Returns whether the fenced
        // install committed (the primitive's own flag); an empty bundle installs
        // nothing and reports committed so the set-side commit proceeds.
        let Some((access, refresh, expires_in, client_credentials)) =
            Self::parse_activation_bundle(credentials)?
        else {
            return Ok(true);
        };
        let committed = match client_credentials {
            // M2M: cache the `(client_id, client_secret)` pair on the live cell
            // atomically under the same fence so `has_silent_grant` is true the
            // instant bring-up commits.
            Some((client_id, client_secret)) => {
                self.state
                    .install_tokens_and_client_credentials_if_identity_unchanged(
                        access,
                        refresh,
                        expires_in,
                        client_id,
                        client_secret,
                        expected_gen,
                    )
                    .await
            }
            None => {
                self.state
                    .install_tokens_if_identity_unchanged(access, refresh, expires_in, expected_gen)
                    .await
            }
        };
        Ok(committed)
    }

    async fn activate_replacing(
        &self,
        credentials: &SecretBundle,
        expected_gen: u64,
    ) -> Result<bool> {
        // Explicit caller-supplied credential change (`Lineage::Fresh`): the
        // bundle is a NEW identity, so REPLACE the live cell — overwrite the
        // refresh slot (clearing it when the bundle carries none) and replace the
        // cached M2M pair (setting the supplied pair or clearing it) — and BUMP
        // `identity_gen`, fencing any in-flight interactive sign-in / refresh of
        // the PRIOR identity out of its own commit. Still fenced on `expected_gen`
        // like `activate`: a concurrent identity change that already won is not
        // regressed. Returns the primitive's committed-flag — the
        // `ConnectionSet` gates its set-side commit on THIS (an `identity_gen`
        // re-read cannot tell this method's own successful-commit bump from a
        // racing winner's).
        let Some((access, refresh, expires_in, client_credentials)) =
            Self::parse_activation_bundle(credentials)?
        else {
            return Ok(true);
        };
        let committed = self
            .state
            .replace_tokens_and_client_credentials_if_identity_unchanged(
                access,
                refresh,
                expires_in,
                client_credentials,
                expected_gen,
            )
            .await;
        Ok(committed)
    }

    async fn on_authenticated(
        &self,
        connection: &Connection,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // The `ConnectionSet` fires this on every authenticated transition,
        // including a DEFERRED interactive sign-in on a connection that parked
        // `AwaitingAuth` at bring-up. Such a connection advertised no address
        // roots (initial discovery is gated on an authenticated bring-up) and
        // its root watcher's stream-open failed on the empty bearer and
        // terminated, so its route table is empty — every object op returns
        // `NoRoute` until this repopulation runs. Re-list the broker's roots,
        // republish the routing view, and restart the watcher. `Weak::upgrade`
        // failing means the layer is dropping — nothing to repopulate. Errors
        // are swallowed inside `repopulate_roots` so a transient listing blip
        // never parks a freshly-authenticated connection.
        if let Some(layer) = self.layer.upgrade() {
            layer.repopulate_roots(&connection.id).await;
        }
        Ok(())
    }

    fn identity_gen(&self) -> u64 {
        self.state.identity_generation()
    }

    /// Answered from the credential the live identity published: a bundle
    /// carrying a different refresh token belongs to a flow the live cell has
    /// moved past, and committing it would regress the connection onto a token
    /// the provider's rotation has already consumed.
    fn credentials_are_current(&self, credentials: &SecretBundle) -> bool {
        oauth_secret_store::bundle_carries_published_credential(&self.state, credentials)
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
        // `expected_gen` is the identity generation the `ConnectionSet` captured
        // at the START of this grant (the identity it intended to refresh) — the
        // supersession fence for the whole refresh, threaded in rather than
        // re-captured at this method's entry. Re-capturing here would miss an
        // interactive sign-in that bumped `identity_gen` in the window between the
        // set's capture and this call (widened by the set's cross-process lock +
        // keyring-head reload — milliseconds), letting the fenced commit below
        // install this OLD identity's freshly-minted token onto a live cell the
        // interactive winner already owns. Symmetric with `obtain`: the grant runs
        // on driver-PRIVATE staging and only this fenced commit ever touches the
        // live cell.
        race_cancel(cancel.as_ref(), async {
            // OIDC/auth config is identity-neutral: cache it on the live cell
            // (idempotent; also warms the interactive path), then seed a PRIVATE
            // staging cell from it so the grant never mutates the live token cell.
            self.ensure_oidc_loaded(&self.state).await?;
            let staging = DiscoveryState::new(self.state.client_name().to_string());
            if let Some(cfg) = self.state.auth_config().await {
                staging.install_auth_config(cfg).await;
            }
            if let Some(oidc) = self.state.oidc_config().await {
                staging.install_oidc_config(oidc).await;
            }

            // The M2M `(client_id, client_secret)` pair for the grant: prefer
            // `current`, else the live cell's cached pair (stamped at `activate`).
            let m2m = match (
                current.fields.get("client_id"),
                current.fields.get("client_secret"),
            ) {
                (Some(SecretValue::Bytes(id)), Some(SecretValue::Bytes(secret))) => {
                    match (
                        String::from_utf8(id.0.clone()),
                        String::from_utf8(secret.0.clone()),
                    ) {
                        (Ok(id), Ok(secret)) if !id.is_empty() && !secret.is_empty() => {
                            Some((id, secret))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            let m2m = match m2m {
                Some(pair) => Some(pair),
                None => self.state.client_credentials().await,
            };

            // Credential-lineage gate: after an interactive sign-in,
            // `replace_tokens` clears the cached M2M pair but cannot clear the
            // immutable `client_secret_file` config field — without this gate
            // the next proactive/recovery refresh would re-drive the
            // service-principal grant with a fresh post-sign-in
            // `expected_gen` and its fenced install would commit, silently
            // reverting the user's bearer (the exact revert `replace_tokens`'
            // doc rules out). While the live identity is interactive, route
            // the refresh through the refresh-token grant only; with no
            // refresh token the grant fails and the connection parks for
            // re-auth instead of reverting.
            // Null every client-credentials SOURCE once while the identity
            // is interactive — everything downstream (`is_client_credentials`,
            // the branch selection) derives from these gated bindings, so a
            // credential source added later cannot miss the gate.
            let (secret_file, m2m) = if self.state.interactive_identity() {
                (None, None)
            } else {
                (self.client_secret_file.as_ref(), m2m)
            };

            // A `client_credentials` grant (config `client_secret_file` or an M2M
            // pair) mints an access-only, re-mintable bearer with NO refresh token
            // of its own; only an OAuth refresh-token grant rotates a paired
            // refresh successor. This gates BOTH the staging seed (below) and the
            // committed/returned refresh (a `client_credentials` bearer must be
            // access-only, never carrying a foreign — possibly interactive-user —
            // refresh into a mixed-identity bundle).
            let is_client_credentials = secret_file.is_some() || m2m.is_some();

            // Priority: config `client_secret_file` (re-read for rotation) >
            // cached M2M pair > OAuth refresh-token grant. All install onto the
            // PRIVATE `staging` cell, never the live one.
            if let Some(secret_file) = secret_file {
                drive_client_credentials_grant(
                    &self.http,
                    &staging,
                    std::path::Path::new(secret_file),
                )
                .await?;
            } else if let Some((client_id, client_secret)) = &m2m {
                drive_client_credentials_grant_with_secret(
                    &self.http,
                    &staging,
                    client_id,
                    client_secret,
                )
                .await?;
            } else {
                // Seed the refresh token onto STAGING for the refresh-token grant:
                // prefer the reloaded (possibly rotated) token from `current` (the
                // sibling-persisted successor), else fall back to the live cell's
                // current refresh. Only this branch consumes a refresh token, so
                // seeding is scoped to it — a `client_credentials` grant would
                // MERGE-preserve a seeded token into a mixed-identity bundle.
                let seed_refresh = match current.fields.get("oauth") {
                    Some(SecretValue::OAuthToken {
                        refresh: Some(rt), ..
                    }) => String::from_utf8(rt.0.clone())
                        .ok()
                        .filter(|s| !s.is_empty()),
                    _ => None,
                };
                match seed_refresh {
                    Some(rt) => staging.install_refresh_token(rt).await,
                    None => {
                        if let Some(rt) = self.state.refresh_token().await {
                            staging.install_refresh_token(rt).await;
                        }
                    }
                }
                drive_refresh_token_grant(&self.http, &staging).await?;
            }

            // Commit the freshly-minted bearer to the LIVE cell with same-identity
            // MERGE semantics (a `None` refresh preserves the slot per RFC 6749
            // §6; the cached M2M pair is untouched), fenced on the set-captured
            // identity generation. If a concurrent interactive success bumped
            // `identity_gen` since that capture, the merge is SKIPPED and the live
            // cell keeps
            // the winning identity; the minted bundle is still returned so the
            // set-side `record_refreshed` applies its own cred_gen/identity_gen
            // fence.
            let access = staging.access_token().await.unwrap_or_default();
            // Supersession outranks the identity check here: the commit below
            // is already fenced on `expected_gen`, so a superseded grant is
            // discarded either way — but failing it would park the winner.
            self.check_identity_unless_superseded(&access, expected_gen)?;
            // A `client_credentials` bearer is access-only and re-mintable — carry
            // NO refresh token onto the committed / returned bundle. Only the
            // refresh-token grant yields a legitimately paired successor.
            let refresh = if is_client_credentials {
                None
            } else {
                staging.refresh_token().await
            };
            let expires_at = staging.access_token_expires_at().await;
            let expires_in = expires_at.and_then(|at| at.duration_since(SystemTime::now()).ok());
            let _committed = self
                .state
                .install_tokens_if_identity_unchanged(
                    access.clone(),
                    refresh.clone(),
                    expires_in,
                    expected_gen,
                )
                .await;
            let mut credentials =
                oauth_secret_store::oauth_bundle(&access, refresh.as_deref(), expires_at);
            // Stamp the supplied/cached M2M pair back onto the returned bundle
            // (mirroring `obtain`'s supplied-pair path) so the set-side
            // `persist_credentials` recognizes this as a keyring-inert
            // `client_credentials` credential rather than an access-only rotation
            // that would delete a colliding sibling's refresh-token slot. A
            // `client_secret_file` grant carries no in-bundle pair; its
            // `persist_credentials` `client_secret_file` check keeps it inert.
            if let Some((client_id, client_secret)) = &m2m {
                credentials.fields.insert(
                    "client_id".into(),
                    SecretValue::Bytes(SecretBytes(client_id.clone().into_bytes())),
                );
                credentials.fields.insert(
                    "client_secret".into(),
                    SecretValue::Bytes(SecretBytes(client_secret.clone().into_bytes())),
                );
            }
            Ok(Refreshed {
                credentials,
                expires_at,
            })
        })
        .await
    }

    async fn interactive(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // A direct endpoint — anything that is not `http(s)://`, so
        // `grpc://`, `grpc+tcp://`, `grpc+tls://`, `unix:/…` and `npipe:/…`
        // alike — has no
        // OAuth surface: its credential is whatever `obtain` resolves at
        // bring-up (a `token_file` bearer, or none). There is no flow to drive.
        //
        // Answered BEFORE the capability check: whether a backend has a flow at
        // all is a property of the backend, not of what the host could drive.
        // `Unsupported` is the code a host reads as "no flow was offered", and
        // it keeps the registration; `AuthRequired` claims a flow exists that
        // could not be run, and is an ordinary failure.
        //
        // A terminal `Succeeded` here would be a claim that a sign-in happened:
        // `ConnectionSet` promotes on it, yet nothing in this arm re-reads the
        // token file, verifies it, or installs a bearer in the live cell — so a
        // connection its broker refused would report `Authenticated` on no
        // grant and no probe, with an empty route table underneath it.
        //
        // What does recover such a connection is
        // `update_connection_credentials`: it re-reads the token file through
        // `obtain`, verifies it, installs the bearer, and only then repopulates
        // the routing view — through the `on_authenticated` hook when the
        // outcome is `Authenticated`, or through the layer's explicit call on
        // the `Anonymous` branch when the endpoint carries no `token_file`.
        if self.is_direct {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "broker: direct-endpoint connections have no interactive \
                 authentication flow; credentials are supplied at bring-up",
            ));
        }
        if matches!(capability, InteractiveAuthCapability::None) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "broker: host declared no interactive auth capability",
            ));
        }
        // Persist the interactively-minted refresh token BEFORE the flow thread
        // forwards `Succeeded`, on this connection's stable keyring id.
        let claim = std::sync::Arc::clone(self.claim());
        // A sign-in superseded before its callback runs cannot express the
        // write at all. Anchored on the identity being published, not on the
        // generation at flow start: this flow's OWN commit advances the
        // generation, so a start anchor would refuse every sign-in.
        let epoch = self.identity_epoch();
        let publication = self.state.clone();
        let state = self.state.clone();
        let persist: auth::PersistRefresh = std::sync::Arc::new(
            move |_access: &str, refresh: Option<String>, generation: u64| {
                // Anchored on the generation this flow's own commit produced,
                // so a flow superseded before its callback ran cannot write.
                let lease = oauth_secret_store::IdentityLease::at_generation(&epoch, generation);
                // The binding is NOT published here. The token install that
                // preceded this callback published it, fenced and under one
                // lock; republishing would reopen the window where a superseded
                // flow overwrites the winner's identity. What this callback
                // reads is therefore whatever the winning install recorded.
                // Through the claim, like every other write: a sign-in that
                // stamped its token onto a key a sibling connection also
                // derives would hand that sibling this account's lineage on the
                // next warm continuation.
                match refresh {
                    Some(rt) if !rt.is_empty() => oauth_secret_store::write_leased_refresh_token(
                        PLUGIN_NAME,
                        KEYRING_BACKEND_KIND,
                        &claim,
                        &lease,
                        publication.publication_lock(),
                        &rt,
                        &state.current_binding().unwrap_or_default(),
                    ),
                    _ => oauth_secret_store::delete_leased_refresh_token(
                        PLUGIN_NAME,
                        KEYRING_BACKEND_KIND,
                        &claim,
                        &lease,
                        publication.publication_lock(),
                    ),
                }
            },
        );
        self.state.set_capability(capability);
        race_cancel(cancel.as_ref(), async {
            self.ensure_oidc_loaded(&self.state).await?;
            drive_interactive_login(&self.state, connection, capability, persist, cancel.clone())
                .await
        })
        .await
    }

    fn classify(&self, error: &Error) -> AuthErrorClass {
        match error.code() {
            ErrorCode::AuthExpired | ErrorCode::CredentialExpired => {
                AuthErrorClass::RecoverableCredential
            }
            // gRPC UNAUTHENTICATED maps to `AuthRequired`. If we hold a silent
            // grant (refresh token / cached M2M pair / a config secret file) the
            // access token has almost certainly just expired — route to a silent
            // refresh + retry-once rather than a dead-end prompt.
            ErrorCode::AuthRequired
                if self.state.has_silent_grant() || self.client_secret_file.is_some() =>
            {
                AuthErrorClass::RecoverableCredential
            }
            ErrorCode::AuthRequired | ErrorCode::AuthCancelled => AuthErrorClass::NeedsInteractive,
            ErrorCode::PermissionDenied => AuthErrorClass::PermissionDenied,
            _ => AuthErrorClass::NotAuth,
        }
    }

    async fn persist_credentials(&self, creds: &SecretBundle) -> Result<()> {
        // An M2M `client_credentials` connection re-mints its bearer from the
        // client secret (a config `client_secret_file`, re-read each grant, or a
        // supplied/cached `(client_id, client_secret)` pair carried on the
        // effective bundle) and never owns a refresh token worth persisting, so it
        // must be keyring-INERT: it must neither delete nor overwrite the slot,
        // which a colliding interactive sibling (same stable id — the id ignores
        // the runtime M2M client identity) may own. An access-only M2M result
        // hitting the delete-on-`None` branch below would erase that sibling's
        // refresh token.
        if self.client_secret_file.is_some()
            || (creds.fields.contains_key("client_id")
                && creds.fields.contains_key("client_secret"))
        {
            return Ok(());
        }
        if let Some(SecretValue::OAuthToken { refresh, .. }) = creds.fields.get("oauth") {
            match refresh {
                Some(rt) => {
                    let rt = String::from_utf8(rt.0.clone()).map_err(|_| {
                        Error::new(
                            ErrorCode::InvalidArgument,
                            "broker: refresh token must be valid UTF-8",
                        )
                    })?;
                    if rt.is_empty() {
                        oauth_secret_store::delete_current_lineage(
                            PLUGIN_NAME,
                            KEYRING_BACKEND_KIND,
                            self.claim(),
                            self.state.publication_lock(),
                        )?;
                    } else {
                        oauth_secret_store::persist_current_lineage(
                            PLUGIN_NAME,
                            KEYRING_BACKEND_KIND,
                            self.claim(),
                            &self.state,
                            self.state.publication_lock(),
                            &rt,
                        )?;
                    }
                }
                None => oauth_secret_store::delete_current_lineage(
                    PLUGIN_NAME,
                    KEYRING_BACKEND_KIND,
                    self.claim(),
                    self.state.publication_lock(),
                )?,
            }
        }
        Ok(())
    }

    async fn load_credentials(&self) -> Result<Option<SecretBundle>> {
        // Warm-continue: a persisted refresh token seeds a refresh-token-only
        // bundle; `obtain` then drives the grant to mint a fresh access token,
        // and the identity that grant authenticates as must match the binding
        // recorded here — a stored lineage is adopted only once its owner is
        // confirmed. A keyring READ error propagates so callers fail closed.
        let read_gen = self.state.identity_generation();
        match oauth_secret_store::read_claimed_refresh_token(
            PLUGIN_NAME,
            KEYRING_BACKEND_KIND,
            self.claim(),
        )? {
            Some(stored) if !stored.refresh_token.is_empty() => {
                // Fenced on the generation read BEFORE the secret-store round trip:
                // an identity-changing write that landed while this was in
                // flight owns the live identity, and restoring what was read
                // would overwrite it — durably, once the winner's token is
                // persisted under this record.
                if !self
                    .state
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
        // Both fields live under this connection's key alone, so a sibling
        // identity — which occupies a different key — is untouched.
        oauth_secret_store::delete_bound_refresh_token(
            PLUGIN_NAME,
            KEYRING_BACKEND_KIND,
            &self.stable,
        )?;
        self.state.clear_binding();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::connection::credential_conformance::{
        CredentialSnapshot, CredentialTransactionSubject, assert_credential_transaction_conformance,
    };
    use ovstorage_plugin::oauth_secret_store::{IdentityEpoch, LeaseVerdict};
    use ovstorage_plugin::{Capabilities, ConnectionAuthState, ConnectionSource, UserMetadata};

    /// The real driver's reading of its own credential transaction, for the
    /// shared conformance harness. The identity generation, the binding and the
    /// published credential are read inside ONE identity fence, so they are a
    /// coherent observation rather than three independent loads.
    #[async_trait]
    impl CredentialTransactionSubject for BrokerDriver {
        async fn credential_snapshot(&self) -> CredentialSnapshot {
            let mut epoch = None;
            self.state.with_identity_fence(&mut |view| {
                epoch = Some((
                    view.generation,
                    view.binding.cloned(),
                    view.published_credential.map(str::to_string),
                ));
                LeaseVerdict::Current
            });
            let (identity_generation, binding, published_credential) =
                epoch.expect("the identity-fence body always runs");
            CredentialSnapshot {
                access_token: self.state.access_token().await,
                refresh_token: self.state.refresh_token().await,
                expires_at: self.state.access_token_expires_at().await,
                client_credentials: self.state.client_credentials().await,
                interactive_lineage: self.state.interactive_identity(),
                generation: self.state.generation(),
                identity_generation,
                published_credential,
                binding,
            }
        }
    }

    /// The real driver stands the shared credential-transaction expectation —
    /// the same harness `ovstorage-plugin`'s `MockDriver` stands in
    /// `mock_driver_conforms_to_the_credential_transaction`.
    ///
    /// Holding both to one description is the point: the mock is a stand-in for
    /// THIS transaction, so a dimension added here that the mock does not mirror
    /// fails on the mock's side rather than quietly making every test that uses
    /// the mock vacuous.
    #[tokio::test]
    async fn broker_driver_conforms_to_the_credential_transaction() {
        assert_credential_transaction_conformance(&detached_driver()).await;
    }

    /// Driver with no reachable network; exercises only the server-free surface
    /// (backend_kind / stable_id / classify / would_consume / interactive guard).
    fn detached_driver() -> BrokerDriver {
        BrokerDriver::new(
            "https://broker.example".into(),
            false,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        )
    }

    /// A driver on a durable key of its own. The claim registry is process
    /// wide, so tests that take a claim must not share one.
    fn detached_driver_keyed(persistence_id: &str) -> BrokerDriver {
        BrokerDriver::new(
            "https://broker.example".into(),
            false,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        )
        .with_persistence_id(persistence_id)
    }

    fn dummy_connection() -> Connection {
        Connection {
            id: ConnectionId("c1".into()),
            backend_kind: KIND.into(),
            display_name: "broker".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
    }

    #[tokio::test]
    async fn a_probe_does_not_poison_a_live_connections_claim() {
        // Drives the guard `obtain` runs first. A probe builds a throwaway
        // driver from the same request — same durable key — so a guard that
        // reached through the claim accessor would acquire and leave the live
        // connection permanently refused. Asserting only that the keys match
        // would pass in exactly that case.
        let live = detached_driver_keyed("probe-victim");
        let _ = live.claim();
        assert!(live.claim().is_exclusive());

        {
            let probe = detached_driver_keyed("probe-victim");
            assert_eq!(probe.stable, live.stable, "the probe derives the same key");
            // `obtain`, not the helper it happens to call. Calling the helper
            // would still pass if `obtain` were changed back to reach through
            // the claim accessor — which is exactly the regression. The grant
            // itself has no server to reach and is expected to fail; what is
            // under test is whether getting there took a claim.
            let _ = probe
                .obtain(
                    &SecretBundle::default(),
                    ovstorage_plugin::connection::GrantPolicy::NonConsumingOnly,
                    None,
                )
                .await;
        }

        assert!(
            live.claim().is_exclusive(),
            "a probe that never touched the durable store left the live \
             connection able to grant and to persist",
        );
        assert!(live.claim().ensure_usable().is_ok());
    }

    /// Building a discriminated connection must not touch the undiscriminated
    /// key on the way.
    ///
    /// Claiming in the constructor claimed the unscoped key until the builder
    /// applied `persistence_id`. A sibling connection already sitting on that
    /// key was contended by the visit — and contention is permanent for the
    /// claims it touches, so the existing connection would have stopped
    /// persisting over a key the new one never ends up using.
    #[tokio::test]
    async fn building_a_discriminated_connection_does_not_disturb_the_default_key() {
        let neighbour = detached_driver_keyed("neighbour");
        let unscoped = neighbour.stable.clone();
        assert!(
            neighbour.claim().is_exclusive(),
            "the existing connection owns the unscoped key",
        );

        let scoped = BrokerDriver::new(
            "https://broker.example".into(),
            false,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        )
        .with_persistence_id("neighbour-alice-work");
        assert_ne!(scoped.stable, unscoped, "it lands on its own key");
        assert!(scoped.claim().is_exclusive());

        // The neighbour is untouched by a connection that was never its
        // sibling.
        assert!(neighbour.claim().is_exclusive());
    }

    /// An interactive commit publishes its binding inside the same fenced
    /// transaction that installs its tokens.
    ///
    /// Scope, stated exactly: these two commits run in sequence, so this
    /// asserts the property — each commit publishes the identity it installed,
    /// leaving nothing for a later unfenced publish to get wrong — and NOT the
    /// interleaving itself. The interleaved sequence, where a descheduled flow
    /// resumes after another has committed, is
    /// `a_superseded_flow_cannot_persist`.
    #[tokio::test]
    async fn an_interactive_commit_publishes_its_binding_atomically() {
        let driver = detached_driver();

        // Flow A commits alice's tokens.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("alice-rt".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );
        assert_eq!(
            driver.state.current_binding().unwrap().subject,
            alice_subject(),
            "the commit publishes the identity it installed",
        );

        // Flow B commits bob's tokens at the next generation.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    BOB_BEARER.into(),
                    Some("bob-rt".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );

        // The live identity is bob's, established by the write that installed
        // bob's tokens — not left for an unfenced publish that flow A could
        // still win.
        assert_eq!(driver.state.current_binding().unwrap().subject, "bob");
    }

    /// A credential ROTATION must leave the connection with an identity to
    /// persist under.
    ///
    /// `obtain` establishes the candidate identity, then the activation
    /// replaces the tokens — an identity-changing write. If that write cleared
    /// the binding and only interactive sign-in ever republished it, the
    /// immediately following persist would find no identity and write nothing.
    ///
    /// Scope, stated exactly: this asserts the PRECONDITION, because these
    /// crates register no keyring host and a durable assertion here would test
    /// nothing. That the write then actually lands is asserted where a stub
    /// host exists — `ovstorage-plugin`'s `oauth_identity_binding` suite for
    /// the storage layer, and the Nucleus driver's
    /// `a_rotation_advances_the_stored_token` for a driver's `persist_credentials`
    /// end to end.
    #[tokio::test]
    async fn a_rotation_leaves_the_connection_able_to_persist() {
        let driver = detached_driver();

        // Alice is live and bound, as after a sign-in.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("rt-0".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );

        // Her token rotates: an identity-changing replacement carrying rt-1.
        assert!(
            driver
                .state
                .replace_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("rt-1".into()),
                    None,
                    driver.state.identity_generation(),
                )
                .await
                .is_some()
        );

        assert!(
            driver.state.current_binding().is_some(),
            "the rotation left an identity to persist under",
        );
        assert_eq!(
            driver.state.current_binding().unwrap().subject,
            alice_subject(),
        );
    }

    /// A same-identity ROTATION must still be persistable after a sign-in
    /// published the credential it superseded.
    ///
    /// The supersession proof compares the offered token against the one the
    /// live identity published. A refresh commits through the MERGE primitive,
    /// which rotates the refresh slot without changing the identity, so a proof
    /// that only tracked identity-CHANGING writes would still name the consumed
    /// predecessor and refuse every rotation that followed a sign-in — leaving
    /// the secret store holding a token the provider has already retired.
    #[tokio::test]
    async fn a_rotation_after_a_sign_in_is_still_persistable() {
        let driver = detached_driver_keyed("rotation-after-sign-in");

        // An interactive sign-in commits rt-0 and publishes it.
        driver
            .state
            .replace_tokens_if_identity_unchanged(
                ALICE_BEARER.into(),
                Some("rt-0".into()),
                None,
                driver.state.identity_generation(),
            )
            .await
            .expect("the sign-in commits");
        oauth_secret_store::persist_current_lineage(
            PLUGIN_NAME,
            KEYRING_BACKEND_KIND,
            driver.claim(),
            &driver.state,
            driver.state.publication_lock(),
            "rt-0",
        )
        .expect("the credential the sign-in published is persistable");

        // A background refresh consumes rt-0 and merges rt-1 onto the live
        // cell. Same identity, so the generation does not move.
        let generation = driver.state.identity_generation();
        assert!(
            driver
                .state
                .install_tokens_if_identity_unchanged(
                    ALICE_BEARER.into(),
                    Some("rt-1".into()),
                    None,
                    generation,
                )
                .await,
            "the rotation commits onto the live cell",
        );
        assert_eq!(
            driver.state.identity_generation(),
            generation,
            "a rotation is not an identity change",
        );

        // The lifecycle now persists the successor the live cell holds.
        oauth_secret_store::persist_current_lineage(
            PLUGIN_NAME,
            KEYRING_BACKEND_KIND,
            driver.claim(),
            &driver.state,
            driver.state.publication_lock(),
            "rt-1",
        )
        .expect("the rotated token the live cell holds is persistable");
    }

    /// A superseded flow must not be able to persist at all.
    ///
    /// Flow A installs alice and publishes alice's binding atomically, then is
    /// descheduled before its persistence callback runs. Flow B installs and
    /// persists bob at the new generation. A resumes still carrying ALICE's
    /// refresh token, reads the now-current binding — bob's — and writes
    /// alice's token under bob's record. The live transport is bob while the
    /// keyring describes a mix.
    ///
    /// The lease is what makes that unwritable: A captured the generation when
    /// its flow began, and the write refuses when the generation has moved.
    #[tokio::test]
    async fn a_superseded_flow_cannot_persist() {
        let driver = detached_driver_keyed("superseded-flow");
        let epoch = driver.identity_epoch();

        // Flow A commits alice and takes a lease on the generation ITS OWN
        // commit produced — the anchor the interactive callback uses.
        let gen_a = driver
            .state
            .replace_tokens_if_identity_unchanged(
                ALICE_BEARER.into(),
                Some("alice-rt".into()),
                None,
                driver.state.identity_generation(),
            )
            .await
            .expect("flow A commits");
        let lease_a = oauth_secret_store::IdentityLease::at_generation(&epoch, gen_a);
        assert!(
            lease_a.is_current(),
            "A owns the identity it just established"
        );

        // Flow B commits bob at the next generation.
        let gen_b = driver
            .state
            .replace_tokens_if_identity_unchanged(
                BOB_BEARER.into(),
                Some("bob-rt".into()),
                None,
                driver.state.identity_generation(),
            )
            .await
            .expect("flow B commits");
        assert_ne!(gen_a, gen_b);

        // Flow A's callback finally runs. It must not be able to write.
        assert!(!lease_a.is_current());
        let refused = oauth_secret_store::write_leased_refresh_token(
            "test",
            "test-kind",
            driver.claim(),
            &lease_a,
            driver.state.publication_lock(),
            "alice-rt",
            &oauth_secret_store::identity_from_access_token(ALICE_BEARER, "default"),
        );
        assert_eq!(
            refused.unwrap_err().code(),
            ErrorCode::AuthCancelled,
            "a superseded flow cannot persist",
        );

        // B, which does own the identity, can.
        let lease_b = oauth_secret_store::IdentityLease::at_generation(&epoch, gen_b);
        assert!(lease_b.is_current());
    }

    /// A stale durable binding load must not overwrite the identity a
    /// concurrent sign-in just established.
    ///
    /// The stale commit being generation-fenced does not cover this: that
    /// fences the TOKEN, and this corrupts the BINDING. Left unfenced, the
    /// interactive persist then writes the winner's token under the previous
    /// account's record, and the winner is refused on its next grant.
    #[tokio::test]
    async fn a_stale_binding_load_does_not_overwrite_a_concurrent_sign_in() {
        let driver = detached_driver();
        // The generation a warm continuation reads before its keyring round
        // trip.
        let read_gen = driver.state.identity_generation();

        // Bob signs in: identity-changing token write, then his binding.
        driver
            .state
            .replace_tokens("bob-access".into(), Some("bob-rt".into()), None)
            .await;
        driver
            .state
            .set_binding(oauth_secret_store::identity_from_access_token(
                BOB_BEARER, "default",
            ));
        assert_ne!(driver.state.identity_generation(), read_gen);

        // The warm continuation resumes and offers what it read.
        let adopted = driver.state.adopt_binding_if_identity_unchanged(
            oauth_secret_store::IdentityBinding {
                issuer: "https://idp.example".into(),
                client_id: "default".into(),
                subject: "alice".into(),
            },
            read_gen,
        );

        assert!(!adopted, "a load from before the sign-in is refused");
        assert_eq!(
            driver.state.current_binding().unwrap().subject,
            "bob",
            "the winner's identity survives a stale load",
        );
    }

    /// The generation compare must be guarded by the same lock the identity
    /// check runs under.
    ///
    /// Two independent loads leave a window: a winner that has recorded its
    /// identity but not yet bumped the generation is visible as "another
    /// principal, same generation", so the in-flight grant reports a false
    /// `AuthRequired` against the connection about to win. The seam runs INSIDE
    /// the checked section, so a version that samples the generation outside
    /// the lock fails here.
    #[tokio::test]
    async fn the_identity_check_and_the_generation_compare_share_one_lock() {
        let driver = detached_driver();
        let observed_under_lock = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = std::sync::Arc::clone(&observed_under_lock);
        driver
            .state
            .set_binding_observation_gate(Some(std::sync::Arc::new(
                move |state: &DiscoveryState| {
                    seen.store(
                        state.binding_lock_is_held(),
                        std::sync::atomic::Ordering::SeqCst,
                    );
                },
            )));

        let expected_gen = driver.state.identity_generation();
        driver
            .state
            .set_binding(oauth_secret_store::IdentityBinding {
                issuer: "https://idp.example".into(),
                client_id: "default".into(),
                subject: "alice".into(),
            });
        let _ = driver.check_identity_unless_superseded(BOB_BEARER, expected_gen);
        driver.state.set_binding_observation_gate(None);

        assert!(
            observed_under_lock.load(std::sync::atomic::Ordering::SeqCst),
            "the binding lock is held across the generation compare and the check, \
             so a half-applied identity install is not observable",
        );
    }

    /// A refresh whose grant is superseded by a concurrent sign-in must not be
    /// reported as an identity failure.
    ///
    /// The winning connection holds valid tokens; parking it on a
    /// credential-class error leaves it unusable. The commit is already fenced
    /// on the generation, so supersession outranks the identity check.
    #[tokio::test]
    async fn a_superseded_refresh_is_skipped_rather_than_failed_as_an_impostor() {
        let driver = detached_driver();
        let expected_gen = driver.state.identity_generation();
        driver
            .state
            .set_binding(oauth_secret_store::IdentityBinding {
                issuer: "https://idp.example".into(),
                client_id: "default".into(),
                subject: "alice".into(),
            });
        let bob = BOB_BEARER;

        // Without supersession, this bearer disagrees with the binding.
        assert_eq!(
            driver.check_identity(bob).unwrap_err().code(),
            ErrorCode::AuthRequired,
        );

        // A concurrent sign-in advances the identity generation.
        driver
            .state
            .set_client_credentials("id".into(), "secret".into())
            .await;
        assert_ne!(driver.state.identity_generation(), expected_gen);

        // Now the same bearer is a superseded grant, not an impostor.
        assert!(
            !driver
                .check_identity_unless_superseded(bob, expected_gen)
                .unwrap(),
            "reported as superseded, so the caller skips instead of failing",
        );
        // And the superseded grant wrote nothing: the identity-changing write
        // unbound the connection, and the winner records its own identity. A
        // stale grant must not re-establish the account it was carrying.
        assert!(driver.state.current_binding().is_none());
    }

    /// A signed-shaped bearer whose claims name alice at the test issuer and
    /// client. Written out rather than encoded so this test needs no base64
    /// dependency; the payload is
    /// `{"iss":"https://idp.example","sub":"alice","azp":"default"}`.
    const ALICE_BEARER: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiYWxpY2UiLCJhenAiOiJkZWZhdWx0In0.c2ln";

    fn alice_subject() -> String {
        "alice".to_string()
    }

    /// The same shape naming bob; payload
    /// `{"iss":"https://idp.example","sub":"bob","azp":"default"}`.
    const BOB_BEARER: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiYm9iIiwiYXpwIjoiZGVmYXVsdCJ9.c2ln";

    #[tokio::test]
    async fn backend_kind_and_stable_id() {
        let driver = detached_driver();
        assert_eq!(driver.backend_kind(), KIND);
        assert!(driver.stable_id().is_some());
    }

    #[tokio::test]
    async fn classify_maps_the_auth_taxonomy() {
        let driver = detached_driver();
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::AuthRequired, "")),
            AuthErrorClass::NeedsInteractive
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::AuthExpired, "")),
            AuthErrorClass::RecoverableCredential
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::PermissionDenied, "")),
            AuthErrorClass::PermissionDenied
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::Transient, "")),
            AuthErrorClass::NotAuth
        );
    }

    /// A stored silent grant flips a gRPC UNAUTHENTICATED to a recoverable
    /// credential (silent refresh + retry-once) instead of a dead-end prompt.
    #[tokio::test]
    async fn classify_authrequired_with_silent_grant_is_recoverable() {
        let driver = detached_driver();
        driver.state.install_refresh_token("rt".into()).await;
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::AuthRequired, "")),
            AuthErrorClass::RecoverableCredential
        );
    }

    /// A config `client_secret_file` is a silent grant even before any token
    /// lands, so an UNAUTHENTICATED reclassifies as recoverable.
    #[tokio::test]
    async fn classify_authrequired_with_client_secret_file_is_recoverable() {
        let driver = BrokerDriver::new(
            "https://broker.example".into(),
            false,
            None,
            Some("/run/secrets/broker".into()),
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        );
        assert_eq!(
            driver.classify(&Error::new(ErrorCode::AuthRequired, "")),
            AuthErrorClass::RecoverableCredential
        );
    }

    /// Regression: after an interactive sign-in, a background/recovery
    /// refresh on a `client_secret_file` connection must NOT re-drive the
    /// service-principal grant — `replace_tokens` clears the cached M2M pair
    /// but cannot clear the config field, and the refresh runs with a fresh
    /// post-sign-in `expected_gen`, so without the lineage gate its fenced
    /// install would commit the revert. With no interactive refresh token
    /// stored, the gated refresh fails typed (`AuthRequired`, parking the
    /// connection for re-auth) with NO token-endpoint attempt, and the live
    /// cell keeps the user's bearer.
    #[tokio::test]
    async fn refresh_after_interactive_does_not_revert_to_client_secret_file() {
        let state = DiscoveryState::new("default");
        // Pre-load config so the grant paths need no discovery fetch; the
        // secret file deliberately does not exist — the gated refresh must
        // never even try to read it.
        state
            .install_auth_config(auth::AuthConfig {
                openid_configuration: "http://127.0.0.1:1/oidc".into(),
                clients: [(
                    "default".to_string(),
                    auth::AuthClientConfig {
                        client_id: "cid".into(),
                        scope: None,
                    },
                )]
                .into_iter()
                .collect(),
            })
            .await;
        state
            .install_oidc_config(auth::OidcConfig {
                issuer: "http://127.0.0.1:1".into(),
                token_endpoint: "http://127.0.0.1:1/token".into(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let driver = BrokerDriver::new(
            "https://broker.example".into(),
            false,
            None,
            Some("/nonexistent/broker-secret".into()),
            state.clone(),
            reqwest::Client::new(),
            Weak::new(),
        );

        // Interactive sign-in (the IdP response carried no refresh token)
        // wins the live cell.
        state.replace_tokens("user-access".into(), None, None).await;
        assert!(state.interactive_identity());
        let fence_gen = state.identity_generation();

        let err = driver
            .refresh(&SecretBundle::default(), None, fence_gen)
            .await
            .expect_err("an interactive identity with no refresh token must park, not revert");
        assert_eq!(err.code(), ErrorCode::AuthRequired, "{err}");
        assert_eq!(
            state.access_token().await.as_deref(),
            Some("user-access"),
            "the interactive bearer survives the refresh attempt"
        );
        assert!(
            state.client_credentials().await.is_none(),
            "no service pair may be resurrected onto the live cell"
        );
    }

    /// The lineage gate is scoped to the interactive identity: a plain
    /// service connection (no interactive sign-in) still routes its refresh
    /// through the `client_secret_file` grant — proven by the grant
    /// genuinely reaching the secret-file READ (the config carries a valid
    /// client entry, so nothing fails earlier) and surfacing the read
    /// failure with the configured path named.
    #[tokio::test]
    async fn refresh_without_interactive_identity_still_reads_the_secret_file() {
        let state = DiscoveryState::new("default");
        state
            .install_auth_config(auth::AuthConfig {
                openid_configuration: "http://127.0.0.1:1/oidc".into(),
                clients: [(
                    "default".to_string(),
                    auth::AuthClientConfig {
                        client_id: "cid".into(),
                        scope: None,
                    },
                )]
                .into_iter()
                .collect(),
            })
            .await;
        state
            .install_oidc_config(auth::OidcConfig {
                issuer: "http://127.0.0.1:1".into(),
                token_endpoint: "http://127.0.0.1:1/token".into(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let driver = BrokerDriver::new(
            "https://broker.example".into(),
            false,
            None,
            Some("/nonexistent/broker-secret".into()),
            state.clone(),
            reqwest::Client::new(),
            Weak::new(),
        );
        let err = driver
            .refresh(&SecretBundle::default(), None, state.identity_generation())
            .await
            .expect_err("the missing secret file fails the client_credentials grant");
        assert_eq!(
            err.code(),
            ErrorCode::CredentialUnavailable,
            "the failure must be the secret-file read itself: {err}"
        );
        assert!(
            err.message().contains("/nonexistent/broker-secret"),
            "the error names the configured path: {err}"
        );
    }

    #[tokio::test]
    async fn interactive_rejects_no_capability() {
        let driver = detached_driver();
        match driver
            .interactive(dummy_connection(), InteractiveAuthCapability::None, None)
            .await
        {
            Err(err) => assert_eq!(err.code(), ErrorCode::AuthRequired),
            Ok(_) => panic!("None capability must fail fast"),
        }
    }

    /// Direct-endpoint connections expose no OAuth surface, so there is no flow
    /// to open and `interactive` says so rather than emitting a `Succeeded` that
    /// would promote a connection the broker refused.
    ///
    /// Every capability, and `None` in particular: the answer must be
    /// `Unsupported` there too, because "this backend has no flow" is not a
    /// statement about what the host can drive — and a host reads `Unsupported`
    /// as "no flow was offered" while `AuthRequired` is an ordinary failure.
    #[tokio::test]
    async fn interactive_direct_endpoint_reports_no_flow() {
        let driver = BrokerDriver::new(
            "unix:/run/ovstorage/broker.sock".into(),
            true,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        );
        for capability in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
            InteractiveAuthCapability::Browser,
        ] {
            let err = driver
                .interactive(dummy_connection(), capability, None)
                .await
                .err()
                .expect("a direct endpoint offers no interactive flow to open");
            assert_eq!(
                err.code(),
                ErrorCode::Unsupported,
                "capability {capability:?} must not change the answer"
            );
        }
    }

    /// A direct-endpoint connection with no token_file obtains anonymously; one
    /// with a token_file yields a bearer read from the file.
    #[tokio::test]
    async fn obtain_direct_endpoint_anonymous_and_token_file() {
        let anon = BrokerDriver::new(
            "unix:/run/ovstorage/broker.sock".into(),
            true,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        );
        assert!(matches!(
            anon.obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
                .await
                .unwrap(),
            Obtained::Anonymous
        ));

        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let token_path = std::env::temp_dir().join(format!("ovbroker-token-{nanos}"));
        std::fs::write(&token_path, "sekret-bearer\n").unwrap();
        let with_token = BrokerDriver::new(
            "unix:/run/ovstorage/broker.sock".into(),
            true,
            Some(token_path.to_string_lossy().into_owned()),
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        );
        let obtained = with_token
            .obtain(&SecretBundle::default(), GrantPolicy::AllowConsuming, None)
            .await
            .unwrap();
        let _ = std::fs::remove_file(&token_path);
        match obtained {
            Obtained::Bearer { credentials, .. } => {
                assert!(matches!(
                    credentials.fields.get("oauth"),
                    Some(SecretValue::OAuthToken { .. })
                ));
            }
            other => panic!("expected Bearer, got {other:?}"),
        }
    }

    /// An access-only EXPLICIT credential update
    /// (`update_credentials` → `activate_replacing`) is an identity change — the
    /// prior identity's refresh token must NOT survive the rotation, and
    /// `identity_gen` must bump. This pins access-only rotation clearing stale
    /// refresh state on the driver surface.
    #[tokio::test]
    async fn activate_replacing_clears_stale_refresh_on_access_only_rotation() {
        let driver = detached_driver();
        // Seed a refresh-bearing identity on the live cell.
        driver
            .state
            .install_tokens("old-access".into(), Some("old-refresh".into()), None)
            .await;
        assert_eq!(
            driver.state.refresh_token().await.as_deref(),
            Some("old-refresh")
        );
        let gen0 = driver.identity_gen();

        // Rotate to an access-only credential (no refresh) via the explicit-update
        // replacement path.
        let bundle = oauth_secret_store::oauth_bundle("new-access", None, None);
        let committed = driver
            .activate_replacing(&bundle, gen0)
            .await
            .expect("access-only explicit update activates");
        assert!(
            committed,
            "an uncontended explicit update reports committed"
        );

        assert_eq!(
            driver.state.access_token().await.as_deref(),
            Some("new-access")
        );
        // The prior identity's refresh must NOT survive the rotation.
        assert_eq!(
            driver.state.refresh_token().await,
            None,
            "stale refresh from the prior identity must be cleared"
        );
        // The identity change bumps `identity_gen`.
        assert_eq!(driver.identity_gen(), gen0 + 1);
    }

    /// The `identity_gen` bump from an explicit access-only update fences out
    /// an in-flight interactive sign-in that captured the pre-update generation —
    /// its supersession guard fails, so it cannot clobber the update.
    #[tokio::test]
    async fn activate_replacing_bump_fences_stale_interactive_flow() {
        let driver = detached_driver();
        // An interactive flow starts and captures the current identity generation.
        let interactive_gen_at_start = driver.identity_gen();

        // An explicit access-only update lands first and bumps `identity_gen`.
        let update = oauth_secret_store::oauth_bundle("update-access", None, None);
        driver
            .activate_replacing(&update, interactive_gen_at_start)
            .await
            .expect("explicit update activates");
        assert_eq!(driver.identity_gen(), interactive_gen_at_start + 1);

        // The now-stale interactive flow tries to commit against its captured
        // generation — the fence rejects it, and the live cell keeps the update.
        let committed = driver
            .state
            .replace_tokens_if_identity_unchanged(
                "interactive-access".into(),
                Some("interactive-refresh".into()),
                None,
                interactive_gen_at_start,
            )
            .await;
        assert!(
            committed.is_none(),
            "a superseded interactive commit must not land"
        );
        assert_eq!(
            driver.state.access_token().await.as_deref(),
            Some("update-access")
        );
        assert_eq!(driver.state.refresh_token().await, None);
    }

    /// An explicit M2M update caches the supplied `(client_id, client_secret)`
    /// pair on the live cell (so `has_silent_grant` is immediately true) while
    /// still bumping `identity_gen`.
    #[tokio::test]
    async fn activate_replacing_caches_m2m_pair_and_bumps_identity() {
        let driver = detached_driver();
        let gen0 = driver.identity_gen();
        let mut bundle = oauth_secret_store::oauth_bundle("m2m-access", None, None);
        bundle.fields.insert(
            "client_id".into(),
            SecretValue::Bytes(SecretBytes(b"svc-id".to_vec())),
        );
        bundle.fields.insert(
            "client_secret".into(),
            SecretValue::Bytes(SecretBytes(b"svc-secret".to_vec())),
        );
        driver
            .activate_replacing(&bundle, gen0)
            .await
            .expect("m2m explicit update activates");
        assert_eq!(
            driver.state.client_credentials().await,
            Some(("svc-id".into(), "svc-secret".into()))
        );
        assert!(driver.state.has_silent_grant());
        assert_eq!(driver.identity_gen(), gen0 + 1);
    }

    /// A stale-fenced `activate_replacing` (a concurrent identity change already
    /// won) must DISCARD rather than regress the live cell.
    #[tokio::test]
    async fn activate_replacing_respects_the_fence() {
        let driver = detached_driver();
        let stale_gen = driver.identity_gen();
        // A concurrent identity change lands first (bumps identity_gen).
        driver
            .state
            .replace_tokens("winner-access".into(), Some("winner-refresh".into()), None)
            .await;
        // The stale-fenced explicit update is discarded; the live cell keeps the
        // winner and does NOT bump again.
        let gen_after_winner = driver.identity_gen();
        let committed = driver
            .activate_replacing(
                &oauth_secret_store::oauth_bundle("stale-access", None, None),
                stale_gen,
            )
            .await
            .expect("stale activate_replacing is a no-op, not an error");
        assert!(
            !committed,
            "a stale-fenced explicit update reports NOT committed so the set discards it"
        );
        assert_eq!(
            driver.state.access_token().await.as_deref(),
            Some("winner-access")
        );
        assert_eq!(driver.identity_gen(), gen_after_winner);
    }

    /// A `NonConsumingOnly` probe of an expired-access + refresh bundle must
    /// refuse (WouldConsume) rather than burn the one-time refresh token — and
    /// the check is pre-network (no transport needed).
    #[tokio::test]
    async fn probe_would_consume_refuses_before_network() {
        let driver = detached_driver();
        let expired = SystemTime::now() - std::time::Duration::from_secs(3600);
        let bundle =
            oauth_secret_store::oauth_bundle("stale-access", Some("refresh"), Some(expired));
        assert!(matches!(
            driver
                .obtain(&bundle, GrantPolicy::NonConsumingOnly, None)
                .await
                .unwrap(),
            Obtained::WouldConsume
        ));
    }
}
