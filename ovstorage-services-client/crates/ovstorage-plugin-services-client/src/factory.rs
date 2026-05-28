// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Factory` impl: descriptor, probe, instantiate, update_credentials, authenticate.

use std::sync::{Arc, Mutex};

use ovstorage_plugin::{
    AddressRoot, AddressVisibility, AuthAttempt, AuthEvent, AuthEventStream, AuthReason, BackendId,
    Capabilities, ConfigLayer, Connection, ConnectionAuthState, ConnectionId, ConnectionRequest,
    Error, ErrorCode, InteractiveAuthCapability, Result, RouteSource, SecretBundle, SecretValue,
    StorageBackendKindDescriptor, Url, UserMetadata, race_cancel,
};
use ovstorage_plugin::{oauth_keyring, shim};
use tokio_util::sync::CancellationToken;

use crate::auth::{
    self, DiscoveryState, drive_client_credentials_grant, drive_refresh_token_grant,
};
use crate::backend::OmniverseStorageBackend;
use crate::config;
use crate::transport::OmniverseStorageTransport;

const PLUGIN_NAME: &str = "omniverse-storage-service";

async fn build_oauth_bundle_from_state(state: &DiscoveryState) -> SecretBundle {
    let access = state.access_token().await.unwrap_or_default();
    let refresh = state.refresh_token().await;
    let expires_at = state.access_token_expires_at().await;
    oauth_keyring::oauth_bundle(&access, refresh.as_deref(), expires_at)
}

/// Translate a stored bundle's `expires_at` into the `expires_in`
/// the auth-state's [`DiscoveryState::install_tokens`] expects.
///
/// Past-`expires_at` returns `Some(Duration::ZERO)` (not `None`),
/// so `install_tokens` records a defined-but-already-elapsed TTL
/// and [`DiscoveryState::token_needs_refresh`] correctly reports
/// the token as needing refresh. The previous code used
/// `.and_then(|at| at.duration_since(now).ok())` which collapsed
/// expired stored tokens to `None` — the auth state then treated
/// them as "no expiry, valid indefinitely" and never refreshed.
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

/// Per-connection auth context retained for later `authenticate` calls. The
/// HTTP discovery URL is the only thing we need to refetch auth-config /
/// OIDC discovery from scratch when a cold-start interactive flow runs.
#[derive(Clone, Debug)]
struct AuthContext {
    discovery_url: String,
    client_name: String,
}

/// Live mapping from a `Connection` to the `Backend` that's serving it. The
/// Connection arrives at `update_credentials` / `authenticate` after the
/// host has handed the BackendInstance off; this slot lets us reach back
/// to the same `Arc<OmniverseStorageBackend>` and install fresh tokens on its
/// shared `DiscoveryState`.
struct BackendSlot {
    display_name: String,
    connection_id: Option<ConnectionId>,
    context: AuthContext,
    backend: Arc<OmniverseStorageBackend>,
}

pub struct OmniverseStorageFactory {
    slots: Mutex<Vec<BackendSlot>>,
}

impl Default for OmniverseStorageFactory {
    fn default() -> Self {
        tracing::info!(
            plugin = "omniverse-storage-service",
            "omniverse-storage-service: plugin factory initialized",
        );
        Self {
            slots: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl shim::Factory for OmniverseStorageFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: config::KIND.into(),
            display_name: "Omniverse Storage".into(),
            description: Some("Routes storage operations to a Omniverse Storage Service".into()),
            config_schema: config::config_schema(),
            credential_schema: config::credential_schema(),
            credential_methods: config::credential_methods(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        race_cancel(cancel.as_ref(), async move {
            let discovery_url = config::discovery_url(&request.config)?;
            tracing::info!(
                target: "ovstorage.omniverse_storage_service.factory",
                plugin = "omniverse-storage-service",
                "omniverse-storage-service: instantiating backend",
            );
            let display_name = request
                .display_name
                .clone()
                .unwrap_or_else(|| format!("omniverse-storage-service:{discovery_url}"));
            let client_name = config::oidc_client_name(&request.config);
            let context = AuthContext {
                discovery_url: discovery_url.clone(),
                client_name,
            };
            let (state, conn_auth_state) = build_auth_state(&discovery_url, request).await?;
            let awaiting_auth = matches!(conn_auth_state, ConnectionAuthState::AwaitingAuth { .. });
            let transport = OmniverseStorageTransport::new(discovery_url.clone(), state.clone());
            // Defer services discovery until tokens land. The host's
            // address-roots watcher repopulates routes once
            // `update_credentials` installs the OAuth bearer.
            let capabilities = descriptor_capabilities();
            let backend_id = BackendId(format!("omniverse-storage-service:{discovery_url}"));
            let backend = Arc::new(OmniverseStorageBackend::new(
                discovery_url,
                capabilities.clone(),
                transport,
            ));
            let address_roots = if awaiting_auth {
                Vec::new()
            } else {
                let urls = list_top_level_addresses(backend.transport()).await?;
                if urls.is_empty() {
                    return Err(Error::new(
                        ErrorCode::NotConfigured,
                        "omniverse-storage-service: server published no top-level addresses",
                    ));
                }
                let mut roots = Vec::with_capacity(urls.len());
                for address in urls {
                    let capabilities = backend.capabilities_for_root(&address).await;
                    roots.push(AddressRoot {
                        address,
                        display_name: None,
                        backend_kind: "omniverse-storage-service".into(),
                        connection_id: None,
                        capabilities,
                        source: RouteSource::Static {
                            layer: ConfigLayer::Programmatic,
                        },
                        visibility: AddressVisibility::Visible,
                        user_metadata: UserMetadata::new(),
                    });
                }
                roots
            };
            // Park a slot so update_credentials / authenticate can reach back
            // to this backend's auth state by Connection later.
            if let Ok(mut slots) = self.slots.lock() {
                slots.push(BackendSlot {
                    display_name: display_name.clone(),
                    connection_id: None,
                    context,
                    backend: backend.clone(),
                });
            }
            tracing::info!(
                target: "ovstorage.omniverse_storage_service.factory",
                plugin = "omniverse-storage-service",
                display_name = %display_name,
                awaiting_auth,
                "omniverse-storage-service: backend instantiated",
            );
            Ok(shim::BackendInstance {
                backend_id,
                backend,
                address_roots,
                display_name: Some(display_name),
                auth_state: conn_auth_state,
            })
        })
        .await
    }

    async fn update_credentials(
        &self,
        connection: &Connection,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        race_cancel(cancel.as_ref(), async move {
            let Some(backend) = self.resolve_backend(connection)? else {
                // Unknown connection — broker plugin treats this the same way:
                // a benign no-op, since the host may be replaying credentials
                // for a connection owned by a different factory instance.
                return Ok(());
            };
            // Prefer the interactive `oauth` bundle when both methods are
            // present (compat with current callers). Falls through to
            // `client_credentials` below when the host replays just the
            // service-identity pair.
            if let Some(SecretValue::OAuthToken {
                token,
                refresh,
                expires_at,
            }) = credentials.fields.get("oauth")
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
                let discovery_url = backend.discovery_url().to_string();
                // Mirror the (possibly rotated) refresh_token into the OS keyring
                // so the next process can warm-continue without an interactive
                // sign-in. No refresh => delete any stale entry from a prior
                // identity so we don't loop on a token that no longer matches.
                let conn = oauth_keyring::conn_id_from_url(&discovery_url);
                match refresh_str.as_deref() {
                    Some(rt) if !rt.is_empty() => {
                        oauth_keyring::write_refresh_token(PLUGIN_NAME, config::KIND, &conn, rt)
                    }
                    _ => oauth_keyring::delete_refresh_token(PLUGIN_NAME, config::KIND, &conn),
                }
                backend
                    .transport()
                    .auth_state()
                    .install_tokens(access, refresh_str, expires_in)
                    .await;
                return Ok(());
            }
            // No `oauth` bundle present — accept a `client_credentials`
            // rotation. The host calls update_credentials whenever a
            // backend's stored credentials change; for service identities
            // that means a fresh `(client_id, client_secret)` pair. Cache
            // the pair on the state (so the background refresh loop picks
            // up the rotation) and drive a fresh grant immediately so the
            // bearer interceptor has a token to install.
            let client_id =
                extract_secret_string(credentials.fields.get("client_id"), "client_id")?;
            let client_secret =
                extract_secret_string(credentials.fields.get("client_secret"), "client_secret")?;
            if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
                let state = backend.transport().auth_state().clone();
                state
                    .set_client_credentials(client_id.clone(), client_secret.clone())
                    .await;
                let http = reqwest::Client::new();
                drive_client_credentials_grant(&http, &state, &client_id, &client_secret).await?;
                return Ok(());
            }
            Ok(())
        })
        .await
    }

    async fn authenticate(
        &self,
        connection: Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        race_cancel(cancel.as_ref(), async move {
            if matches!(capability, InteractiveAuthCapability::None) {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    "omniverse-storage-service::authenticate: host declared no interactive auth capability",
                ));
            }
            let ctx = self.resolve_context(&connection)?.ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "omniverse-storage-service::authenticate: no auth context for connection — \
                     the connection must be instantiated by this factory first",
                )
            })?;
            if !ctx.discovery_url.starts_with("http://")
                && !ctx.discovery_url.starts_with("https://")
            {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service::authenticate: interactive OAuth requires an http(s) discovery URL",
                ));
            }
            // Fresh DiscoveryState seeded with auth-config + OIDC discovery.
            // Reuse over an instance's existing state would race the
            // interceptor's per-RPC token reads.
            tracing::info!(
                target: "ovstorage.omniverse_storage_service.auth",
                plugin = "omniverse-storage-service",
                "omniverse-storage-service: authenticate called, fetching auth-config and OIDC discovery",
            );
            let http = reqwest::Client::new();
            let state = DiscoveryState::with_http_client(ctx.client_name.clone(), http.clone());
            let auth_config = auth::fetch_auth_config(&http, &ctx.discovery_url).await?;
            state.install_auth_config(auth_config.clone()).await;
            let oidc_config = auth::fetch_oidc_config(&http, &auth_config).await?;
            state.install_oidc_config(oidc_config).await;

            // Warm continuation: if a prior process persisted a refresh_token
            // for this discovery host, swap it for a fresh access token and
            // skip the browser. Falls through to interactive on any failure;
            // AuthExpired/AuthRequired also clear the stale entry.
            let keyring_conn = oauth_keyring::conn_id_from_url(&ctx.discovery_url);
            if let Some(refresh_token) =
                oauth_keyring::read_refresh_token(PLUGIN_NAME, config::KIND, &keyring_conn)
            {
                state.install_refresh_token(refresh_token).await;
                match drive_refresh_token_grant(&http, &state).await {
                    Ok(_) => {
                        // Replay the install through update_credentials so
                        // the backend's state, keyring mirror, and Succeeded
                        // event all stay in sync with the interactive path.
                        let bundle = build_oauth_bundle_from_state(&state).await;
                        self.update_credentials(&connection, bundle.clone(), None)
                            .await?;
                        tracing::info!(
                            target: "ovstorage.omniverse_storage_service.auth",
                            plugin = "omniverse-storage-service",
                            "omniverse-storage-service: warm-continue succeeded; skipping interactive flow",
                        );
                        let stream: AuthEventStream =
                            Box::new(std::iter::once(Ok(AuthEvent::Succeeded {
                                connection: Box::new(connection),
                                credentials: Some(bundle),
                            })));
                        return Ok(stream);
                    }
                    Err(err) => {
                        tracing::debug!(
                            target: "ovstorage.omniverse_storage_service.auth",
                            plugin = "omniverse-storage-service",
                            code = ?err.code(),
                            "warm-continue failed; falling through to interactive",
                        );
                        if matches!(
                            err.code(),
                            ErrorCode::AuthRequired
                                | ErrorCode::AuthExpired
                                | ErrorCode::PermissionDenied
                        ) {
                            oauth_keyring::delete_refresh_token(
                                PLUGIN_NAME,
                                config::KIND,
                                &keyring_conn,
                            );
                        }
                    }
                }
            }

            auth::drive_interactive_login(&state, connection, capability).await
        })
        .await
    }
}

impl OmniverseStorageFactory {
    /// Resolve a `Connection` to its live backend. Prefer matching by
    /// `connection.id`; fall back to a unique-display-name match (and
    /// backfill the id) so a freshly issued connection gets pinned to its
    /// slot on first contact.
    fn resolve_backend(
        &self,
        connection: &Connection,
    ) -> Result<Option<Arc<OmniverseStorageBackend>>> {
        let mut slots = self.slots.lock().map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: backend slot registry lock poisoned",
            )
        })?;
        if let Some(slot) = slots
            .iter()
            .find(|s| s.connection_id.as_ref() == Some(&connection.id))
        {
            return Ok(Some(slot.backend.clone()));
        }
        let matches: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.display_name == connection.display_name && s.connection_id.is_none())
            .map(|(i, _)| i)
            .collect();
        match matches.as_slice() {
            [] => Ok(None),
            [idx] => {
                let slot = &mut slots[*idx];
                slot.connection_id = Some(connection.id.clone());
                Ok(Some(slot.backend.clone()))
            }
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "omniverse-storage-service: multiple connections share display_name '{}' — \
                     cannot disambiguate without connection_id",
                    connection.display_name
                ),
            )),
        }
    }

    fn resolve_context(&self, connection: &Connection) -> Result<Option<AuthContext>> {
        let mut slots = self.slots.lock().map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: backend slot registry lock poisoned",
            )
        })?;
        if let Some(slot) = slots
            .iter()
            .find(|s| s.connection_id.as_ref() == Some(&connection.id))
        {
            return Ok(Some(slot.context.clone()));
        }
        let matches: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.display_name == connection.display_name && s.connection_id.is_none())
            .map(|(i, _)| i)
            .collect();
        match matches.as_slice() {
            [] => Ok(None),
            [idx] => {
                let slot = &mut slots[*idx];
                slot.connection_id = Some(connection.id.clone());
                Ok(Some(slot.context.clone()))
            }
            _ => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "omniverse-storage-service: multiple connections share display_name '{}' — \
                     cannot disambiguate without connection_id",
                    connection.display_name
                ),
            )),
        }
    }
}

fn descriptor_capabilities() -> Capabilities {
    Capabilities {
        supports_if_match_write: true,
        supports_no_overwrite_write: false,
        supports_native_metadata_patch: true,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: true,
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

async fn list_top_level_addresses(transport: &OmniverseStorageTransport) -> Result<Vec<Url>> {
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
        .filter_map(|entry| Url::parse(&entry.top_level_address).ok())
        .collect())
}

#[cfg(test)]
impl OmniverseStorageFactory {
    /// Test-only helper: stash a fully-built backend in a slot with the given
    /// display_name. Lets `update_credentials` / `authenticate` be exercised
    /// without spinning up a live discovery service.
    pub(crate) fn push_test_slot(
        &self,
        display_name: String,
        discovery_url: String,
        client_name: String,
        backend: Arc<OmniverseStorageBackend>,
    ) {
        self.slots.lock().unwrap().push(BackendSlot {
            display_name,
            connection_id: None,
            context: AuthContext {
                discovery_url,
                client_name,
            },
            backend,
        });
    }
}

/// Build a `DiscoveryState` from a `ConnectionRequest`, optionally seeding it
/// with credentials. Mirrors the broker plugin's pattern but hits the Omniverse Storage Service's
/// `/api/v1/auth-config` for OIDC bootstrap.
///
/// Visible to integration tests so they can stand up a mock OIDC and
/// exercise the client_credentials grant in isolation from
/// `instantiate`'s services-discovery RPC.
pub async fn build_auth_state(
    discovery_url: &str,
    request: &ConnectionRequest,
) -> Result<(DiscoveryState, ConnectionAuthState)> {
    let client_name = config::oidc_client_name(&request.config);
    // Share one `reqwest::Client` between discovery, the initial grant,
    // and the background refresh loop spawned by `install_tokens`.
    // `reqwest::Client` is internally Arc'd, so the clone into the state
    // is cheap and reuses the connection pool / TLS config.
    let http = reqwest::Client::new();
    let state = DiscoveryState::with_http_client(client_name, http.clone());
    // No auth-config published → server is anonymous-friendly.
    let auth_config = match auth::fetch_auth_config(&http, discovery_url).await {
        Ok(cfg) => cfg,
        Err(err) if err.code() == ErrorCode::NotConfigured => {
            return Ok((state, ConnectionAuthState::Anonymous));
        }
        Err(err) => return Err(err),
    };
    state.install_auth_config(auth_config.clone()).await;
    let oidc_config = auth::fetch_oidc_config(&http, &auth_config).await?;
    state.install_oidc_config(oidc_config).await;
    if let Some(SecretValue::OAuthToken {
        token,
        refresh,
        expires_at,
    }) = request.credentials.fields.get("oauth")
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
        if state.token_needs_refresh().await
            && state.refresh_token().await.is_some()
            && let Err(err) = drive_refresh_token_grant(&http, &state).await
        {
            tracing::warn!(
                target: "ovstorage.omniverse_storage_service.auth",
                error = %err.message(),
                "omniverse-storage-service: initial refresh failed; connection awaits auth"
            );
            return Ok((
                state,
                ConnectionAuthState::AwaitingAuth {
                    reason: AuthReason::RefreshTokenExpired,
                    last_attempt: Some(AuthAttempt {
                        at: std::time::SystemTime::now(),
                        error: Some(err),
                    }),
                },
            ));
        }
        // Read `expires_at` back from the state — after a refresh
        // it carries the new TTL, NOT the stored bundle's stale
        // value. Returning `*expires_at` here would lie to the host
        // and trigger another refresh on the next op.
        let post_refresh_expires_at = state.access_token_expires_at().await;
        return Ok((
            state,
            ConnectionAuthState::Authenticated {
                last_authenticated_at: std::time::SystemTime::now(),
                expires_at: post_refresh_expires_at,
            },
        ));
    }
    // No `oauth` bundle present — fall through to the `client_credentials`
    // grant if both `client_id` and `client_secret` are supplied. This is
    // the machine-to-machine auth path advertised by the
    // `client_credentials` credential method in the descriptor; the
    // factory caches the pair on the state so the background refresh
    // loop can re-drive the grant without re-fetching credentials.
    let client_id =
        extract_secret_string(request.credentials.fields.get("client_id"), "client_id")?;
    let client_secret = extract_secret_string(
        request.credentials.fields.get("client_secret"),
        "client_secret",
    )?;
    if let (Some(client_id), Some(client_secret)) = (client_id, client_secret) {
        state
            .set_client_credentials(client_id.clone(), client_secret.clone())
            .await;
        match drive_client_credentials_grant(&http, &state, &client_id, &client_secret).await {
            Ok(_) => {
                let expires_at = state.access_token_expires_at().await;
                return Ok((
                    state,
                    ConnectionAuthState::Authenticated {
                        last_authenticated_at: std::time::SystemTime::now(),
                        expires_at,
                    },
                ));
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
                return Ok((
                    state,
                    ConnectionAuthState::AwaitingAuth {
                        reason,
                        last_attempt: Some(AuthAttempt {
                            at: std::time::SystemTime::now(),
                            error: Some(err),
                        }),
                    },
                ));
            }
        }
    }
    Ok((
        state,
        ConnectionAuthState::AwaitingAuth {
            reason: AuthReason::NeverAuthenticated,
            last_attempt: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_plugin::shim::Factory;
    use ovstorage_plugin::{ConnectionSource, SecretBytes, UserMetadata};
    use tonic::transport::Channel;

    fn dummy_connection(id: &str, display_name: &str) -> Connection {
        Connection {
            id: ConnectionId(id.into()),
            backend_kind: config::KIND.into(),
            display_name: display_name.into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
    }

    fn detached_backend() -> Arc<OmniverseStorageBackend> {
        // Channel is never connected; tests only exercise auth-state mutation,
        // not RPC dispatch.
        let endpoint = tonic::transport::Endpoint::try_from("http://[::1]:1").unwrap();
        let channel = Channel::balance_list(std::iter::once(endpoint));
        let auth_state = DiscoveryState::new("default");
        let transport = OmniverseStorageTransport::with_channel(channel, auth_state);
        Arc::new(OmniverseStorageBackend::new(
            "http://test".into(),
            Capabilities::empty(),
            transport,
        ))
    }

    #[tokio::test]
    async fn update_credentials_installs_oauth_tokens_on_resolved_backend() {
        let factory = OmniverseStorageFactory::default();
        let backend = detached_backend();
        factory.push_test_slot(
            "omniverse-storage-service:test".into(),
            "https://test.example".into(),
            "default".into(),
            backend.clone(),
        );
        let connection = dummy_connection("c1", "omniverse-storage-service:test");
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "oauth".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(b"new-access".to_vec()),
                refresh: Some(SecretBytes(b"new-refresh".to_vec())),
                expires_at: Some(
                    std::time::SystemTime::now() + std::time::Duration::from_secs(300),
                ),
            },
        );
        // Pre-state: no token installed.
        assert_eq!(backend.transport().auth_state().access_token().await, None);
        factory
            .update_credentials(&connection, bundle, None)
            .await
            .expect("update_credentials ok");
        assert_eq!(
            backend
                .transport()
                .auth_state()
                .access_token()
                .await
                .as_deref(),
            Some("new-access")
        );
        assert_eq!(
            backend
                .transport()
                .auth_state()
                .refresh_token()
                .await
                .as_deref(),
            Some("new-refresh")
        );
    }

    #[tokio::test]
    async fn update_credentials_no_op_for_unknown_connection() {
        let factory = OmniverseStorageFactory::default();
        let connection = dummy_connection("nope", "missing");
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "oauth".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(b"x".to_vec()),
                refresh: None,
                expires_at: None,
            },
        );
        // Should silently succeed; no slot exists.
        factory
            .update_credentials(&connection, bundle, None)
            .await
            .expect("no-op ok");
    }

    #[tokio::test]
    async fn authenticate_rejects_no_capability() {
        let factory = OmniverseStorageFactory::default();
        let backend = detached_backend();
        factory.push_test_slot(
            "omniverse-storage-service:test".into(),
            "https://test.example".into(),
            "default".into(),
            backend,
        );
        let connection = dummy_connection("c1", "omniverse-storage-service:test");
        match factory
            .authenticate(connection, InteractiveAuthCapability::None, None)
            .await
        {
            Err(err) => assert_eq!(err.code(), ErrorCode::AuthRequired),
            Ok(_) => panic!("None capability must fail-fast"),
        }
    }

    #[tokio::test]
    async fn authenticate_unknown_connection_returns_not_configured() {
        let factory = OmniverseStorageFactory::default();
        let connection = dummy_connection("nope", "missing");
        match factory
            .authenticate(connection, InteractiveAuthCapability::Browser, None)
            .await
        {
            Err(err) => assert_eq!(err.code(), ErrorCode::NotConfigured),
            Ok(_) => panic!("missing slot must fail"),
        }
    }

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
    /// blocking-bug regression: the old code used
    /// `.duration_since(now).ok()` which collapsed past times to
    /// `None`, causing install_tokens to install with `expires_at:
    /// None`, which `token_needs_refresh` reads as "valid forever".
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
    /// refresh. Previously `(Some(access_token), None)` was treated
    /// as no-refresh-needed, so an expired access_token + valid
    /// refresh_token bundle was happily accepted as authenticated.
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
