// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Factory` impl: descriptor, probe, instantiate, update_credentials, authenticate.

use ovstorage_plugin::connection::GrantPolicy;
use ovstorage_plugin::{
    AuthAttempt, AuthReason, Capabilities, ConnectionAuthState, ConnectionRequest, Error,
    ErrorCode, Result, SecretBundle, SecretValue, StorageBackendKindDescriptor, Url, race_cancel,
};
use tokio_util::sync::CancellationToken;

use crate::auth::{
    self, DiscoveryState, drive_client_credentials_grant, drive_refresh_token_grant,
};
use crate::config;
use crate::transport::OmniverseStorageTransport;

pub(crate) const PLUGIN_NAME: &str = "omniverse-storage-service";

/// Translate a stored bundle's `expires_at` into the `expires_in`
/// the auth-state's [`DiscoveryState::install_tokens`] expects.
///
/// Past-`expires_at` returns `Some(Duration::ZERO)` (not `None`),
/// so `install_tokens` records a defined-but-already-elapsed TTL
/// and [`DiscoveryState::token_needs_refresh`] correctly reports
/// the token as needing refresh. Using
/// `.and_then(|at| at.duration_since(now).ok())` would instead collapse
/// expired stored tokens to `None` — the auth state would then treat
/// them as "no expiry, valid indefinitely" and never refresh.
fn bundle_expires_in(expires_at: Option<std::time::SystemTime>) -> Option<std::time::Duration> {
    match expires_at {
        None => None,
        Some(at) => match at.duration_since(std::time::SystemTime::now()) {
            Ok(remaining) => Some(remaining),
            Err(_) => Some(std::time::Duration::ZERO),
        },
    }
}

/// Read a UTF-8 string from a `SecretValue::Bytes` field. Returns
/// `Ok(None)` when the field is absent so the caller can fall through to
/// alternative credential methods; returns an `InvalidArgument` error
/// when the field is present but holds the wrong variant or non-UTF-8
/// bytes. `client_credentials` callers stamp `client_id`/`client_secret`
/// as `Bytes` since the SPI's `SecretValue` enum has no dedicated string
/// variant.
fn extract_secret_string(value: Option<&SecretValue>, field_name: &str) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(SecretValue::Bytes(b)) => String::from_utf8(b.0.clone()).map(Some).map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service: {field_name} must be valid UTF-8"),
            )
        }),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "omniverse-storage-service: {field_name} must be a Bytes secret value (got a \
                 different variant)"
            ),
        )),
    }
}

/// Descriptor provider for the Omniverse Storage Service backend kind. The
/// connection lifecycle (validate / refresh / interactive / classify) lives in
/// the generic `ConnectionSet<OmniverseStorageDriver>` embedded on
/// `crate::layer::OmniverseStorageLayer` (RFC-0066); this type only
/// supplies the static kind descriptor.
pub struct OmniverseStorageFactory;

impl OmniverseStorageFactory {
    pub(crate) fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: config::KIND.into(),
            display_name: "Omniverse Storage".into(),
            description: Some("Routes storage operations to a Omniverse Storage Service".into()),
            config_schema: config::config_schema(),
            credential_schema: config::credential_schema(),
            credential_methods: config::credential_methods(),
            icon: None,
            supports_runtime_add: true,
            // The service stores user metadata, through the metadata service
            // after the write. Whether a given deployment runs that service is a
            // per-root fact this static, per-kind declaration does not resolve.
            // This backend's own answer when it cannot reach the service is to
            // log and discard when every key that failed is one of the host's
            // reserved ones, and to fail the write when a caller's own key
            // failed — so a stamp can be lost where the caller asked for no
            // metadata of their own. That deviation is recorded on
            // `stash_user_metadata` in `backend.rs`; it is this plugin's
            // behaviour, not something the declaration promises.
            supports_user_metadata: true,
        }
    }
}

/// Capability set the plugin advertises for every connection root, before the
/// per-root `GetFolderMode` / `GetOptimisticLockingSupport` downgrades applied
/// by `OmniverseStorageBackend::capabilities_for_root`. Public so the external
/// conformance suite (`tests/conformance_scenarios.rs`) gates registry
/// scenarios on the real advertised bits instead of a drifting copy.
pub fn descriptor_capabilities() -> Capabilities {
    Capabilities {
        supports_if_match_write: true,
        supports_no_overwrite_write: false,
        supports_native_metadata_patch: true,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: true,
        // Availability, not mechanism: `Copy`/`Move` exist in the fileobject
        // v1alpha surface, and a stack carrying the copy/rename fallback
        // serves both even against a deployment that answers `UNIMPLEMENTED`.
        // The `supports_server_side_*` bits below describe the protocol, which
        // is not the same claim as the connected deployment implementing them.
        supports_copy: true,
        supports_rename: true,
        supports_write: true,
        supports_write_stream: true,
        supports_write_redirect: true,
        supports_delete: true,
        supports_server_side_copy: true,
        supports_server_side_rename: true,
        supports_atomic_rename: true,
        has_real_directories: true,
        supports_list: true,
        wants_list_backed_stat: false,
        supports_recursive_list: false,
        supports_create_directory: true,
        supports_delete_directory: true,
        populates_subdirectory_metadata: false,
        supports_version_listing: true,
        version_list_order: None,
        populates_effective_permissions_on_stat: false,
        supports_access_check: true,
        supports_watch_directory: true,
        watch_directory_kinds: ovstorage_plugin::ChangeKindSet {
            created: true,
            deleted: true,
            // The Omniverse Storage Service today emits no Modified or MetadataChanged events
            // for non-durable subscriptions; flag them off so the host
            // doesn't expect dispatch.
            modified: false,
            metadata_changed: false,
        },
        watch_directory_resumable: true,
        watch_directory_max_lag: None,
        // Always offer write_redirect first; the server's FetchWriteTypeInfo
        // tells us per-write whether to actually surface a redirect.
        redirect_size_threshold: None,
    }
}

/// The capability set a *connection* advertises, as opposed to the kind-wide
/// set in [`descriptor_capabilities`].
///
/// They differ only in directory watching. `watch_directory` runs over the
/// `notification-consumer` service, and only `/api/v1/services` can name that
/// endpoint — a connection configured with a direct gRPC endpoint has no way to
/// reach it, so it does not advertise it. This is the same rule the auth
/// surface follows, one layer down: a capability whose only transport is
/// unreachable is not a capability, and saying so up front beats failing at the
/// first `watch_directory` call.
///
/// The descriptive fields are cleared with it, because a `kinds` set or a
/// resumable flag on a watch that is not offered describes nothing. Azure does
/// the same for `watch_directory_kinds`, emptying it in the arm where watch is
/// unavailable. It is not evidence for `watch_directory_resumable`, and neither
/// is S3: both hold that field `false` unconditionally, so this is the only
/// backend where clearing it is a live question. It is cleared on its own
/// merits.
pub fn connection_capabilities(has_discovery: bool) -> Capabilities {
    let mut capabilities = descriptor_capabilities();
    if !has_discovery {
        capabilities.supports_watch_directory = false;
        capabilities.watch_directory_kinds = ovstorage_plugin::ChangeKindSet {
            created: false,
            deleted: false,
            modified: false,
            metadata_changed: false,
        };
        capabilities.watch_directory_resumable = false;
    }
    capabilities
}

pub(crate) async fn list_top_level_addresses(
    transport: &OmniverseStorageTransport,
) -> Result<Vec<Url>> {
    use ovstorage_services_protos::nvidia::omniverse::storage::capabilities::v1alpha as cap;
    let mut client = transport.capabilities_client().await?;
    let response = client
        .list_top_level_addresses(cap::ListTopLevelAddressesRequest {})
        .await
        .map_err(crate::convert::map_status)?;
    Ok(response
        .into_inner()
        .items
        .into_iter()
        // Validated by the SAME function the backend's copy of this RPC uses.
        // Two validators over one wire format is two answers to "is this root
        // admissible", and the two are not consulted at the same time: this
        // copy runs at bring-up and on credential rotation, the backend's runs
        // for `watch_address_roots`, whose `Snapshot` replaces the route table
        // outright. A root only this copy admits is therefore installed at
        // bring-up and disappears on the first watcher snapshot, never to
        // return — a route that flickers rather than one that is refused.
        //
        // The rule it applies: an address the URL parser or ovstorage's
        // canonicalization would move names a different node than it spells,
        // and an authority-less one can never match a request at all, because
        // every request address is parsed through `address::parse`, which
        // refuses that class.
        //
        // Skipping is right here where the other returned-address boundaries
        // refuse: a listing has a remainder the caller still sees, and one
        // unusable root must not cost every usable sibling. It warns because a
        // silently shorter route table is indistinguishable from a server that
        // published fewer roots.
        //
        // Per rejected root, where the backend's copy of this RPC emits one
        // aggregated `warn!` with counts. The shapes differ on purpose: this
        // copy runs once at bring-up, where naming each rejected root is what
        // an operator needs and the cardinality is the configuration's; the
        // backend's runs on every watcher snapshot, where per-entry logging
        // would repeat forever.
        .filter_map(|entry| {
            match crate::backend::parse_server_address(
                &entry.top_level_address,
                "top-level address",
            ) {
                Ok(address) => Some(address),
                Err(error) => {
                    tracing::warn!(
                        target: "ovstorage.omniverse_storage_service.factory",
                        plugin = "omniverse-storage-service",
                        address = %crate::backend::redacted_address(&entry.top_level_address),
                        reason = %error.message(),
                        "omniverse-storage-service: top-level address is not addressable; \
                         omitted from the route table",
                    );
                    None
                }
            }
        })
        .collect())
}

/// Build a `DiscoveryState` from a `ConnectionRequest`, optionally seeding it
/// with credentials. Mirrors the broker plugin's pattern but hits the Omniverse Storage Service's
/// `/api/v1/auth-config` for OIDC bootstrap.
///
/// Visible to integration tests so they can stand up a mock OIDC and
/// exercise the client_credentials grant in isolation from
/// `instantiate`'s services-discovery RPC.
pub async fn build_auth_state(
    discovery_url: Option<&str>,
    request: &ConnectionRequest,
) -> Result<(DiscoveryState, ConnectionAuthState)> {
    let client_name = config::oidc_client_name(&request.config);
    // Share one `reqwest::Client` between discovery and the initial grant.
    // `reqwest::Client` is internally Arc'd, so the clone into the state is
    // cheap and reuses the connection pool / TLS config.
    let http = reqwest::Client::new();
    let state = DiscoveryState::new(client_name);
    // Connection bring-up is a registered path → `AllowConsuming` (never a probe), so a
    // warm-continue refresh-token grant is driven rather than reported
    // `WouldConsume`.
    let auth_state = match seed_connection_auth(
        &state,
        discovery_url,
        &http,
        &request.credentials,
        GrantPolicy::AllowConsuming,
        None,
    )
    .await?
    {
        SeedOutcome::State(state) => state,
        // Unreachable under `AllowConsuming` (only a `NonConsumingOnly` probe
        // yields `WouldConsume`); park defensively rather than panic.
        SeedOutcome::WouldConsume => ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::NeverAuthenticated,
            last_attempt: None,
        },
    };
    Ok((state, auth_state))
}

/// Say plainly that part of a credential bundle attached to a direct-endpoint
/// connection could not be acted on, rather than absorbing it silently. A
/// connection that quietly discards a client secret looks identical to one that
/// used it.
///
/// A direct endpoint can serve from an access token the host supplies, and from
/// nothing else: a refresh token and a `client_credentials` pair both need the
/// OIDC token endpoint that only `/api/v1/auth-config` publishes, and there is
/// no auth-config to publish it.
///
/// Takes no argument and names no field value. The unusable fields are secrets
/// by construction, so there is nothing here that could be interpolated safely
/// and no reason to try; the message says which shapes cannot be used and the
/// caller has the bundle.
///
/// The live caller is the driver's `obtain`, which decides direct mode before
/// this function's own caller can be reached. The call site in
/// [`seed_connection_auth`] is defensive: its `discovery_url == None` arm is
/// unreachable from `obtain` by construction, and its other caller
/// [`build_auth_state`] has no non-test callers. Kept so the warning survives a
/// future path into that arm rather than silently not existing.
pub(crate) fn warn_direct_credentials_unusable() {
    tracing::warn!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: part of the credential bundle supplied for a direct gRPC \
         endpoint cannot be used; such a connection publishes no auth-config, so it can act on \
         a supplied access token but on no refresh token and no client-credentials pair",
    );
}

/// Result of [`seed_connection_auth`]: the resolved [`ConnectionAuthState`], or a
/// signal that the ONLY path to a bearer would consume a one-time refresh token —
/// which a [`GrantPolicy::NonConsumingOnly`] probe must refuse rather than burn
/// the token to test it. The driver's `obtain` maps `WouldConsume` to
/// [`ovstorage_plugin::connection::Obtained::WouldConsume`].
pub(crate) enum SeedOutcome {
    State(ConnectionAuthState),
    WouldConsume,
}

/// Seed `state` from `creds` — fetch auth-config/OIDC (a `NotConfigured`
/// auth-config means the server is anonymous-friendly), install tokens or drive
/// the initial `client_credentials` grant — and report the resulting
/// [`ConnectionAuthState`]. Extracted from [`build_auth_state`] so the ABI-v2
/// `OmniverseStorageDriver`'s `obtain` slot reuses the same
/// bring-up logic against a connection's already-constructed [`DiscoveryState`]
/// (the generic `ConnectionSet` owns everything around it).
pub(crate) async fn seed_connection_auth(
    state: &DiscoveryState,
    discovery_url: Option<&str>,
    http: &reqwest::Client,
    creds: &SecretBundle,
    policy: GrantPolicy,
    cancel: Option<CancellationToken>,
) -> Result<SeedOutcome> {
    // A direct gRPC endpoint publishes no auth-config, so there is no server to
    // ask and nothing to grant against. Answer `Anonymous` without a network
    // call — the same verdict the 404 arm below reaches for a deployment that
    // has a discovery service and no auth on it.
    //
    // A host-supplied bearer is NOT resolved here. The one production decision
    // about a direct endpoint's credential lives in the driver's `obtain`, in
    // one place, and this arm is unreachable from it; answering the question a
    // second time here is how the two would drift apart.
    let Some(discovery_url) = discovery_url else {
        if !creds.fields.is_empty() {
            warn_direct_credentials_unusable();
        }
        return Ok(SeedOutcome::State(ConnectionAuthState::Anonymous));
    };
    race_cancel(cancel.as_ref(), async move {
        // No auth-config published → server is anonymous-friendly.
        let auth_config = match auth::fetch_auth_config(http, discovery_url).await {
            Ok(cfg) => cfg,
            Err(err) if err.code() == ErrorCode::NotConfigured => {
                return Ok(SeedOutcome::State(ConnectionAuthState::Anonymous));
            }
            Err(err) => return Err(err),
        };
        state.install_auth_config(auth_config.clone()).await;
        let oidc_config = auth::fetch_oidc_config(http, &auth_config).await?;
        state.install_oidc_config(oidc_config).await;
        if let Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) = creds.fields.get("oauth")
        {
            let access = String::from_utf8(token.0.clone()).map_err(|_| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "omniverse-storage-service: oauth access token must be valid UTF-8",
                )
            })?;
            let refresh_str = match refresh {
                Some(rt) => Some(String::from_utf8(rt.0.clone()).map_err(|_| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: oauth refresh token must be valid UTF-8",
                    )
                })?),
                None => None,
            };
            let expires_in = bundle_expires_in(*expires_at);
            state.install_tokens(access, refresh_str, expires_in).await;
            if state.token_needs_refresh().await && state.refresh_token().await.is_some() {
                // The installed access token is empty / expired / within
                // REFRESH_SKEW, and a refresh token is present: the ONLY path to a
                // fresh bearer is a CONSUMING refresh-token grant. A probe
                // (`NonConsumingOnly`) must NOT drive it — report `WouldConsume` so
                // the one-time refresh token is not burned just to test it (the
                // driver's up-front `would_consume_only` gate normally catches this
                // pre-network; this is the defense-in-depth stop right before the
                // grant would run).
                if policy == GrantPolicy::NonConsumingOnly {
                    return Ok(SeedOutcome::WouldConsume);
                }
                if let Err(err) = drive_refresh_token_grant(http, state).await {
                    tracing::warn!(
                        target: "ovstorage.omniverse_storage_service.auth",
                        error = %err.message(),
                        "omniverse-storage-service: initial refresh failed; connection awaits auth"
                    );
                    return Ok(SeedOutcome::State(ConnectionAuthState::AwaitingAuth {
                        reason: AuthReason::RefreshTokenExpired,
                        last_attempt: Some(AuthAttempt {
                            at: std::time::SystemTime::now(),
                            error: Some(err),
                        }),
                    }));
                }
            }
            // Read `expires_at` back from the state — after a refresh it carries
            // the new TTL, NOT the stored bundle's stale value.
            let post_refresh_expires_at = state.access_token_expires_at().await;
            return Ok(SeedOutcome::State(ConnectionAuthState::Authenticated {
                last_authenticated_at: std::time::SystemTime::now(),
                expires_at: post_refresh_expires_at,
            }));
        }
        // No `oauth` bundle — fall through to the `client_credentials` grant if
        // both `client_id` and `client_secret` are supplied (the M2M path). The
        // pair is cached on the state so `ConnectionSet`'s background refresh can
        // re-drive the grant via `driver.refresh`.
        let client_id = extract_secret_string(creds.fields.get("client_id"), "client_id")?;
        let client_secret =
            extract_secret_string(creds.fields.get("client_secret"), "client_secret")?;
        if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
            state
                .set_client_credentials(client_id.clone(), client_secret.clone())
                .await;
            match drive_client_credentials_grant(http, state, &client_id, &client_secret).await {
                Ok(_) => {
                    let expires_at = state.access_token_expires_at().await;
                    return Ok(SeedOutcome::State(ConnectionAuthState::Authenticated {
                        last_authenticated_at: std::time::SystemTime::now(),
                        expires_at,
                    }));
                }
                Err(err) => {
                    tracing::warn!(
                        target: "ovstorage.omniverse_storage_service.auth",
                        error = %err.message(),
                        "omniverse-storage-service: initial client_credentials grant failed; connection awaits auth"
                    );
                    let reason = match err.code() {
                        ErrorCode::AuthRequired
                        | ErrorCode::AuthExpired
                        | ErrorCode::PermissionDenied => AuthReason::RefreshTokenExpired,
                        _ => AuthReason::NeverAuthenticated,
                    };
                    return Ok(SeedOutcome::State(ConnectionAuthState::AwaitingAuth {
                        reason,
                        last_attempt: Some(AuthAttempt {
                            at: std::time::SystemTime::now(),
                            error: Some(err),
                        }),
                    }));
                }
            }
        }
        Ok(SeedOutcome::State(ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::NeverAuthenticated,
            last_attempt: None,
        }))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `expires_at = None` (no stored expiry) → `expires_in = None`.
    /// install_tokens then treats the token as no-expiry, matching
    /// IDPs that don't issue `expires_in`.
    #[test]
    fn bundle_expires_in_none_passes_through() {
        assert_eq!(bundle_expires_in(None), None);
    }

    /// Future expiry → positive remaining TTL.
    #[test]
    fn bundle_expires_in_future_returns_remaining() {
        let in_an_hour = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let got = bundle_expires_in(Some(in_an_hour)).expect("future yields Some");
        // Allow a small fuzz window for the elapsed time between the
        // test's `now` and the helper's internal `now`.
        assert!(
            got >= std::time::Duration::from_secs(3590)
                && got <= std::time::Duration::from_secs(3600),
            "expected ~3600s remaining, got {got:?}",
        );
    }

    /// PAST expiry → `Some(Duration::ZERO)`, not `None`. This is the
    /// blocking-bug regression: `.duration_since(now).ok()` would
    /// collapse past times to `None`, causing install_tokens to install
    /// with `expires_at: None`, which `token_needs_refresh` reads as
    /// "valid forever".
    /// Returning `Some(ZERO)` makes install_tokens record a defined
    /// TTL of 0, so `token_needs_refresh` correctly fires.
    #[test]
    fn bundle_expires_in_past_returns_zero_not_none() {
        let an_hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        assert_eq!(
            bundle_expires_in(Some(an_hour_ago)),
            Some(std::time::Duration::ZERO),
            "an expired stored token must NOT collapse to no-expiry",
        );
    }

    /// End-to-end check on DiscoveryState: an expired stored token
    /// installed via `bundle_expires_in` is recognized as needing
    /// refresh. A `(Some(access_token), None)` shape must not be treated
    /// as no-refresh-needed — otherwise an expired access_token + valid
    /// refresh_token bundle would be accepted as authenticated.
    #[tokio::test]
    async fn expired_stored_token_is_recognized_as_needing_refresh() {
        let state = DiscoveryState::new("default");
        let an_hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let expires_in = bundle_expires_in(Some(an_hour_ago));
        state
            .install_tokens("expired-access".into(), Some("refresh".into()), expires_in)
            .await;
        assert!(
            state.token_needs_refresh().await,
            "expired stored token must be flagged for refresh, not silently accepted",
        );
    }
}

#[cfg(test)]
mod user_metadata_declaration_tests {
    use super::*;

    /// This kind's `supports_user_metadata` declaration is what a host reads to
    /// decide whether to compose its attribution layer over this backend's
    /// branch. Asserted here, in the crate that owns the answer, because a host
    /// crate cannot reach it: a plugin crate may not depend on a host-side
    /// crate, and two plugin rlibs in one test binary are a duplicate-symbol
    /// link error under `rust-lld`.
    ///
    /// Flipping it is a behaviour change for every host that loads this plugin —
    /// this backend records user metadata through the metadata service after the write.
    #[test]
    fn omniverse_storage_service_declares_its_user_metadata_support() {
        let descriptor = OmniverseStorageFactory.descriptor();
        assert_eq!(descriptor.kind, config::KIND);
        assert!(
            descriptor.supports_user_metadata,
            "this backend's user-metadata declaration changed; a host composes \
             its attribution layer from it"
        );
    }
}
