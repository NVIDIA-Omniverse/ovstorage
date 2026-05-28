// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `NucleusBackendFactory` and the per-root shared state it owns.
//!
//! The `instantiate` -> `update_credentials` -> `authenticate` lifecycle
//! drives the same backend instance across multiple `Connection` handles
//! by keying `NucleusShared` on the address root.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nucleus_client::LftClient;
use ovstorage_plugin::{
    AddressRoot, AddressVisibility, AuthEventStream, BackendId, CancellationToken, ConfigLayer,
    ConnectionAuthState, ConnectionId, ConnectionRequest, Error, ErrorCode,
    InteractiveAuthCapability, Result, RouteSource, SecretBundle, StorageBackendKindDescriptor,
    Url, UserMetadata,
};
use ovstorage_plugin::{oauth_keyring, shim};

use crate::address::NUCLEUS_KIND;
use crate::auth::{CredentialShape, classify_credentials, synthesize_auth_events};
use crate::config::{
    NucleusConfig, nucleus_config_schema, nucleus_credential_methods, nucleus_credential_schema,
};
use crate::handshake::{
    HandshakeOutput, NucleusSession, establish_api_token, establish_interactive_auth,
    establish_username_password, refresh_session, try_warm_continue,
};
use crate::ops::NucleusOps;
use tracing::{debug, info};

const KEYRING_BACKEND_KIND: &str = NUCLEUS_KIND;

fn keyring_conn(server: &str) -> ConnectionId {
    ConnectionId(server.to_string())
}

use super::convert::poisoned_state;
use super::spi::{NucleusBackend, native_capabilities};

/// Native Nucleus storage backend factory.
pub struct NucleusBackendFactory {
    state: Arc<Mutex<HashMap<String, Arc<NucleusShared>>>>,
}

impl NucleusBackendFactory {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn get_or_create_shared(
        &self,
        config: &NucleusConfig,
        credentials: SecretBundle,
    ) -> Result<Arc<NucleusShared>> {
        let mut map = self.state.lock().map_err(poisoned_state)?;
        let key = config.root.as_str().to_string();
        if let Some(existing) = map.get(&key) {
            let prior = &existing.config;
            if prior.prefix != config.prefix
                || prior.endpoint != config.endpoint
                || prior.use_lft != config.use_lft
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "Nucleus connection already instantiated for this root with a \
                     different prefix/endpoint/use_lft; tear down the prior connection \
                     before re-instantiating with new config",
                ));
            }
            *existing.credentials.lock().map_err(poisoned_state)? = credentials;
            clear_session_state(existing);
            return Ok(Arc::clone(existing));
        }
        let shared = Arc::new(NucleusShared {
            config: config.clone(),
            credentials: Mutex::new(credentials),
            ops: Mutex::new(None),
            lft_client: Mutex::new(None),
            cred_epoch: AtomicU64::new(0),
            session: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            refresh_override: Mutex::new(None),
        });
        map.insert(key, Arc::clone(&shared));
        Ok(shared)
    }

    fn lookup_shared(&self, root: &Url) -> Option<Arc<NucleusShared>> {
        self.state
            .lock()
            .ok()
            .and_then(|map| map.get(root.as_str()).cloned())
    }

    /// Bypass the OmniAuth/ConnLib handshake; returns `false` if `root` has no instantiated backend.
    #[cfg(test)]
    pub(crate) fn install_ops_for_testing(&self, root: &Url, ops: Arc<dyn NucleusOps>) -> bool {
        let Some(shared) = self.lookup_shared(root) else {
            return false;
        };
        let Ok(mut slot) = shared.ops.lock() else {
            return false;
        };
        *slot = Some(ops);
        true
    }

    /// Bypasses omni1 lft() discovery + auth-token pickup for the LFT redirect path tests.
    #[cfg(test)]
    pub(crate) fn install_lft_client_for_testing(
        &self,
        root: &Url,
        client: Arc<LftClient>,
    ) -> bool {
        let Some(shared) = self.lookup_shared(root) else {
            return false;
        };
        let Ok(mut slot) = shared.lft_client.lock() else {
            return false;
        };
        *slot = Some(client);
        true
    }

    /// Replaces `refresh_under_epoch`'s SOWS+ConnLib path with a test callback;
    /// the helper bumps `cred_epoch` after the callback succeeds.
    #[cfg(test)]
    pub(crate) fn install_refresh_override_for_testing(
        &self,
        root: &Url,
        callback: RefreshOverride,
    ) -> bool {
        let Some(shared) = self.lookup_shared(root) else {
            return false;
        };
        let Ok(mut slot) = shared.refresh_override.lock() else {
            return false;
        };
        *slot = Some(callback);
        true
    }

    #[cfg(test)]
    pub(crate) fn cred_epoch_for_testing(&self, root: &Url) -> Option<u64> {
        self.lookup_shared(root)
            .map(|shared| shared.cred_epoch.load(Ordering::Acquire))
    }

    /// Snapshot the currently-installed `ops` so tests can keep the same backing transport across refresh.
    #[cfg(test)]
    pub(crate) fn snapshot_ops_for_testing(&self, root: &Url) -> Option<Arc<dyn NucleusOps>> {
        self.lookup_shared(root)
            .and_then(|shared| shared.ops.lock().ok().and_then(|guard| guard.clone()))
    }

    #[cfg(test)]
    pub(crate) fn install_session_for_testing(&self, root: &Url, session: NucleusSession) -> bool {
        let Some(shared) = self.lookup_shared(root) else {
            return false;
        };
        let Ok(mut slot) = shared.session.lock() else {
            return false;
        };
        *slot = Some(session);
        true
    }

    #[cfg(test)]
    pub(crate) fn lft_client_for_testing(&self, root: &Url) -> Option<Arc<LftClient>> {
        self.lookup_shared(root)
            .and_then(|shared| shared.lft_client.lock().ok().and_then(|g| g.clone()))
    }
}

impl Default for NucleusBackendFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl shim::Factory for NucleusBackendFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: NUCLEUS_KIND.into(),
            display_name: "Nucleus".into(),
            description: Some(
                "Native Omniverse Nucleus backend (SOWS discovery + ConnLib + LFT)".into(),
            ),
            config_schema: nucleus_config_schema(),
            credential_schema: nucleus_credential_schema(),
            credential_methods: nucleus_credential_methods(),
            icon: None,
            supports_runtime_add: true,
        }
    }

    async fn instantiate(
        &self,
        request: &ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<shim::BackendInstance> {
        let _ = &cancel; // no async work in this method body; nothing to interrupt.
        let config = NucleusConfig::from_request(request)?;
        info!(plugin = "nucleus", server = %config.server, "nucleus backend instantiated");
        let shared = self.get_or_create_shared(&config, request.credentials.clone())?;
        let backend = Arc::new(NucleusBackend::from_shared(Arc::clone(&shared)));
        let auth_state = if shared.ops.lock().map_err(poisoned_state)?.is_some() {
            ConnectionAuthState::Authenticated {
                last_authenticated_at: SystemTime::now(),
                expires_at: None,
            }
        } else {
            ConnectionAuthState::Anonymous
        };
        Ok(shim::BackendInstance {
            backend_id: BackendId(format!("{}:{}", NUCLEUS_KIND, config.root)),
            backend,
            address_roots: vec![AddressRoot {
                address: config.root.clone(),
                display_name: None,
                backend_kind: NUCLEUS_KIND.into(),
                connection_id: None,
                capabilities: native_capabilities(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }],
            display_name: request
                .display_name
                .clone()
                .or_else(|| Some(format!("Nucleus {}", config.server))),
            auth_state,
        })
    }

    async fn update_credentials(
        &self,
        connection: &ovstorage_plugin::Connection,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _ = &cancel; // no async work in this method body; nothing to interrupt.
        let Some(root) = connection.current_addresses.first() else {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Nucleus connection has no address root to key credentials by",
            ));
        };
        let Some(shared) = self.lookup_shared(root) else {
            return Err(Error::new(
                ErrorCode::NotFound,
                "Nucleus backend has not been instantiated for this connection",
            ));
        };
        *shared.credentials.lock().map_err(poisoned_state)? = credentials;
        clear_session_state(&shared);
        // Stored refresh_token may belong to a different identity; the next
        // handshake will write a fresh one if applicable.
        oauth_keyring::delete_refresh_token(
            NUCLEUS_KIND,
            KEYRING_BACKEND_KIND,
            &keyring_conn(&shared.config.server),
        );
        Ok(())
    }

    async fn authenticate(
        &self,
        connection: ovstorage_plugin::Connection,
        capability: InteractiveAuthCapability,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        // Capability gating only blocks the URL+nonce-poll path under `None`;
        // api-token and U/P are headless-safe. Nucleus's URL+nonce-poll works
        // in both `Headless` and `Browser` since the user can open the URL on any device.
        let root = connection.current_addresses.first().cloned();
        let shared = root.as_ref().and_then(|r| self.lookup_shared(r));
        let bundle = shared
            .as_ref()
            .and_then(|s| s.credentials.lock().ok().map(|guard| guard.clone()));

        // Warm continuation: if a prior process persisted a refresh_token,
        // try to swap it for a fresh access token without going interactive.
        // Falls through on any failure; AuthExpired/AuthRequired/PermissionDenied
        // also clear the stale entry so we don't loop on it.
        if let Some(shared) = shared.as_ref()
            && let Some(rt) = oauth_keyring::read_refresh_token(
                NUCLEUS_KIND,
                KEYRING_BACKEND_KIND,
                &keyring_conn(&shared.config.server),
            )
        {
            match try_warm_continue(&shared.config, rt).await {
                Ok(HandshakeOutput { ops, lft, session }) => {
                    install_handshake_output(shared.as_ref(), ops, lft, session);
                    use ovstorage_plugin::AuthEvent;
                    let events = vec![Ok(AuthEvent::Succeeded {
                        connection: Box::new(connection),
                        credentials: None,
                    })];
                    return Ok(Box::new(events.into_iter()));
                }
                Err(err) => {
                    debug!(plugin = %NUCLEUS_KIND, server = %shared.config.server, code = ?err.code(), "warm continuation failed; falling through");
                    if matches!(
                        err.code(),
                        ErrorCode::AuthRequired
                            | ErrorCode::AuthExpired
                            | ErrorCode::PermissionDenied
                    ) {
                        oauth_keyring::delete_refresh_token(
                            NUCLEUS_KIND,
                            KEYRING_BACKEND_KIND,
                            &keyring_conn(&shared.config.server),
                        );
                    }
                    // Transient/network errors: keep the keyring entry; a
                    // future authenticate call may succeed.
                }
            }
        }

        // Only `Missing`-without-interactive-capability falls through to the synthesize path;
        // `Missing`-with-capability drives the URL+nonce-poll handshake (the host signaled
        // it can carry an interactive sign-in by advertising a capability != `None`).
        if let (Some(shared), Some(bundle)) = (shared.as_ref(), bundle.as_ref()) {
            match classify_credentials(bundle) {
                CredentialShape::ApiToken => {
                    let events = run_api_token_handshake(shared.as_ref(), bundle, connection).await;
                    return Ok(Box::new(events.into_iter()));
                }
                CredentialShape::UsernameAndPassword => {
                    // Synchronous Credentials.auth needs no browser; valid under all capability modes.
                    let events =
                        run_username_password_handshake(shared.as_ref(), bundle, connection).await;
                    return Ok(Box::new(events.into_iter()));
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
                    return Ok(spawn_interactive_auth_stream(
                        shared.clone(),
                        connection,
                        cancel,
                    ));
                }
                CredentialShape::Missing
                    if !matches!(capability, InteractiveAuthCapability::None) =>
                {
                    return Ok(spawn_interactive_auth_stream(
                        shared.clone(),
                        connection,
                        cancel,
                    ));
                }
                _ => {}
            }
        }

        let events = synthesize_auth_events(connection, bundle.as_ref());
        Ok(Box::new(events.into_iter()))
    }
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
fn spawn_interactive_auth_stream(
    shared: Arc<NucleusShared>,
    connection: ovstorage_plugin::Connection,
    cancel: Option<CancellationToken>,
) -> AuthEventStream {
    let (tx, rx) = std::sync::mpsc::channel::<Result<ovstorage_plugin::AuthEvent>>();
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
                let output =
                    establish_interactive_auth(&shared.config, connection, cancel, tx).await;
                if let Some(HandshakeOutput { ops, lft, session }) = output {
                    install_handshake_output(&shared, ops, lft, session);
                } else {
                    clear_session_state(&shared);
                }
            });
        })
        .expect("failed to spawn thread");
    Box::new(InteractiveAuthIter { rx, _pump: pump })
}

struct InteractiveAuthIter {
    rx: std::sync::mpsc::Receiver<Result<ovstorage_plugin::AuthEvent>>,
    /// Joined on drop so the worker thread is reaped if the host stops
    /// pulling early (e.g. host cancels sign-in mid-poll).
    _pump: std::thread::JoinHandle<()>,
}

impl Iterator for InteractiveAuthIter {
    type Item = Result<ovstorage_plugin::AuthEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rx.recv().ok()
    }
}

async fn run_username_password_handshake(
    shared: &NucleusShared,
    bundle: &SecretBundle,
    connection: ovstorage_plugin::Connection,
) -> Vec<Result<ovstorage_plugin::AuthEvent>> {
    use ovstorage_plugin::AuthEvent;
    let mut events = vec![Ok(AuthEvent::Progress {
        message: "Authenticating with Nucleus via SOWS Credentials.auth".into(),
    })];
    match establish_username_password(&shared.config, bundle).await {
        Ok(HandshakeOutput { ops, lft, session }) => {
            install_handshake_output(shared, ops, lft, session);
            events.push(Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }));
        }
        Err(error) => {
            clear_session_state(shared);
            events.push(Ok(AuthEvent::Failed { error }));
        }
    }
    events
}

async fn run_api_token_handshake(
    shared: &NucleusShared,
    bundle: &SecretBundle,
    connection: ovstorage_plugin::Connection,
) -> Vec<Result<ovstorage_plugin::AuthEvent>> {
    use ovstorage_plugin::AuthEvent;
    let mut events = vec![Ok(AuthEvent::Progress {
        message: "Authenticating with Nucleus via SOWS discovery + ConnLib".into(),
    })];
    match establish_api_token(&shared.config, bundle).await {
        Ok(HandshakeOutput { ops, lft, session }) => {
            install_handshake_output(shared, ops, lft, session);
            events.push(Ok(AuthEvent::Succeeded {
                connection: Box::new(connection),
                credentials: None,
            }));
        }
        Err(error) => {
            clear_session_state(shared);
            events.push(Ok(AuthEvent::Failed { error }));
        }
    }
    events
}

fn install_handshake_output(
    shared: &NucleusShared,
    ops: Arc<dyn NucleusOps>,
    lft: Option<Arc<LftClient>>,
    session: NucleusSession,
) {
    debug!(plugin = "nucleus", server = %shared.config.server, lft_configured = lft.is_some(), "installing nucleus handshake output");
    // Mirror the (possibly-rotated) refresh_token to the OS keyring so the
    // next process can warm-continue without an interactive sign-in. The
    // api-token branch returns `refresh_token: None`; clear any stale entry
    // in that case so we don't try to warm-continue with a token from a
    // different identity.
    let conn = keyring_conn(&shared.config.server);
    match session.refresh_token.as_deref() {
        Some(rt) if !rt.is_empty() => {
            oauth_keyring::write_refresh_token(NUCLEUS_KIND, KEYRING_BACKEND_KIND, &conn, rt)
        }
        _ => oauth_keyring::delete_refresh_token(NUCLEUS_KIND, KEYRING_BACKEND_KIND, &conn),
    }
    if let Ok(mut slot) = shared.ops.lock() {
        *slot = Some(ops);
    }
    if let Ok(mut slot) = shared.lft_client.lock() {
        *slot = lft;
    }
    if let Ok(mut slot) = shared.session.lock() {
        *slot = Some(session);
    }
}

fn clear_session_state(shared: &NucleusShared) {
    if let Ok(mut slot) = shared.ops.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = shared.lft_client.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = shared.session.lock() {
        *slot = None;
    }
}

/// Shared per-root state cloned via `Arc` so multiple `NucleusBackend` handles
/// for the same root share credentials and session.
pub(crate) struct NucleusShared {
    pub config: NucleusConfig,
    pub credentials: Mutex<SecretBundle>,
    pub ops: Mutex<Option<Arc<dyn NucleusOps>>>,
    pub lft_client: Mutex<Option<Arc<LftClient>>>,
    /// Bumped on every successful `refresh_under_epoch`; lets `with_refresh` collapse
    /// retriers that observed the same stale value onto a single network round-trip.
    pub cred_epoch: AtomicU64,
    pub session: Mutex<Option<NucleusSession>>,
    /// Single-flight gate guarding load-check + refresh + epoch-bump.
    /// `tokio::sync::Mutex` because the inner network call awaits.
    pub refresh_lock: tokio::sync::Mutex<()>,
    #[cfg(test)]
    pub refresh_override: Mutex<Option<RefreshOverride>>,
}

#[cfg(test)]
pub(crate) type RefreshOverride = std::sync::Arc<
    dyn Fn() -> Result<(Arc<dyn NucleusOps>, Option<Arc<LftClient>>, NucleusSession)> + Send + Sync,
>;

/// One-shot refresh-on-`AuthExpired` retry. A second `AuthExpired` (or any
/// other error on the retry) propagates so the dispatcher's `with_route_retry`
/// can invalidate the resolved-credential cache.
pub(crate) async fn with_refresh<F, Fut, T>(shared: &Arc<NucleusShared>, op: F) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let observed = shared.cred_epoch.load(Ordering::Acquire);
    match op().await {
        Ok(value) => Ok(value),
        Err(err) if err.code() == ErrorCode::AuthExpired => {
            refresh_under_epoch(shared, observed).await?;
            op().await
        }
        Err(err) => Err(err),
    }
}

/// Single-flight refresh: re-check epoch under `refresh_lock` to collapse waiters,
/// then bump `cred_epoch` only on success.
async fn refresh_under_epoch(shared: &Arc<NucleusShared>, observed_epoch: u64) -> Result<u64> {
    let _guard = shared.refresh_lock.lock().await;
    let current = shared.cred_epoch.load(Ordering::Acquire);
    if current > observed_epoch {
        debug!(plugin = "nucleus", server = %shared.config.server, "nucleus token refresh: another task already refreshed");
        return Ok(current);
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
        if let Ok(mut slot) = shared.ops.lock() {
            *slot = Some(ops);
        }
        if let Ok(mut slot) = shared.lft_client.lock() {
            *slot = lft;
        }
        if let Ok(mut slot) = shared.session.lock() {
            *slot = Some(new_session);
        }
        return Ok(shared.cred_epoch.fetch_add(1, Ordering::AcqRel) + 1);
    }

    let prior = shared
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
    let bundle = shared
        .credentials
        .lock()
        .map_err(super::convert::poisoned_state)?
        .clone();
    let HandshakeOutput { ops, lft, session } =
        refresh_session(&shared.config, &bundle, &prior).await?;

    if let Ok(mut slot) = shared.ops.lock() {
        *slot = Some(ops);
    }
    if let Ok(mut slot) = shared.lft_client.lock() {
        *slot = lft;
    }
    if let Ok(mut slot) = shared.session.lock() {
        *slot = Some(session);
    }
    let new_epoch = shared.cred_epoch.fetch_add(1, Ordering::AcqRel) + 1;
    Ok(new_epoch)
}
