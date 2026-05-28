// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC discovery state + bearer interceptor for the Omniverse Storage Service gRPC client.
//!
//! Adapted from `ovstorage-plugin-broker/src/auth.rs`. The Omniverse Storage Service
//! discovery surface is the HTTP root that serves `/api/v1/services` and
//! `/api/v1/auth-config`; the rest of the OIDC dance is identical to the
//! broker pattern.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::{Duration, SystemTime};

use ovstorage_plugin::{
    AuthEventStream, BackendId, Connection, ConnectionId, Error, ErrorCode,
    InteractiveAuthCapability, Result,
};
use serde::Deserialize;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};
use tracing::Instrument;

/// Refresh proactively when less than this much lifetime remains; absorbs
/// client/IDP clock skew.
pub const REFRESH_SKEW: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    pub openid_configuration: String,
    #[serde(default)]
    pub clients: std::collections::BTreeMap<String, AuthClientConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

#[derive(Clone)]
pub struct DiscoveryState {
    inner: Arc<DiscoveryStateInner>,
}

struct DiscoveryStateInner {
    generation: AtomicU64,
    access_token: RwLock<Option<String>>,
    refresh_token: RwLock<Option<String>>,
    expires_at: RwLock<Option<SystemTime>>,
    auth_config: RwLock<Option<AuthConfig>>,
    oidc_config: RwLock<Option<OidcConfig>>,
    client_name: String,
    /// Cached `(client_id, client_secret)` for the `client_credentials`
    /// grant. Populated by the factory when a connection is instantiated
    /// with `client_id`/`client_secret` credentials so the background
    /// refresh loop can re-drive the grant without prompting the user.
    /// `None` when the connection is using the interactive refresh-token
    /// grant or is anonymous.
    client_credentials: RwLock<Option<(String, String)>>,
    /// Woken when `install_tokens` lands a fresh access token. Lets
    /// `wait_for_token` block cold-start paths (services discovery, the
    /// dynamic-roots watcher) until the OIDC flow completes — without
    /// busy-polling.
    token_arrived: Notify,
    /// Handle to the background refresh-loop task spawned by
    /// `install_tokens`. Aborted and replaced on every fresh token
    /// install (so the loop re-bases on the latest TTL) and aborted in
    /// `Drop` so the task can't outlive the state it borrows via `Weak`.
    /// `std::sync::Mutex` (not `tokio::sync::Mutex`) because `Drop` is
    /// sync and must be able to reach the handle without awaiting.
    refresh_task: StdMutex<Option<JoinHandle<()>>>,
    /// HTTP client used by the background refresh loop (and shared with
    /// the factory's discovery fetches). `reqwest::Client` is internally
    /// `Arc`'d, so cloning into the spawned task is cheap.
    http_client: reqwest::Client,
}

impl Drop for DiscoveryStateInner {
    fn drop(&mut self) {
        // Abort the background refresh-loop so it can't keep running with
        // a dangling `Weak`. `try_lock` because Drop is sync; if the lock
        // happens to be contended (very unlikely — only `install_tokens`
        // takes it, and only briefly) the task will be aborted by the
        // tokio runtime on process shutdown anyway.
        if let Ok(mut guard) = self.refresh_task.try_lock()
            && let Some(handle) = guard.take()
        {
            handle.abort();
        }
    }
}

impl DiscoveryState {
    /// Build a state with a fresh `reqwest::Client`. Convenience for tests
    /// and code paths that don't already have an HTTP client to thread
    /// through; production callers (the factory) should prefer
    /// [`DiscoveryState::with_http_client`] so the background refresh
    /// loop reuses the same client used for discovery.
    pub fn new(client_name: impl Into<String>) -> Self {
        Self::with_http_client(client_name, reqwest::Client::new())
    }

    /// Build a state that shares the caller's `reqwest::Client`. Used by
    /// the factory so the background refresh task and the initial
    /// auth-config / OIDC discovery fetches share a single client (and
    /// its connection pool / TLS config).
    pub fn with_http_client(client_name: impl Into<String>, http_client: reqwest::Client) -> Self {
        Self {
            inner: Arc::new(DiscoveryStateInner {
                generation: AtomicU64::new(0),
                access_token: RwLock::new(None),
                refresh_token: RwLock::new(None),
                expires_at: RwLock::new(None),
                auth_config: RwLock::new(None),
                oidc_config: RwLock::new(None),
                client_name: client_name.into(),
                client_credentials: RwLock::new(None),
                token_arrived: Notify::new(),
                refresh_task: StdMutex::new(None),
                http_client,
            }),
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.generation.load(Ordering::SeqCst)
    }

    pub async fn access_token(&self) -> Option<String> {
        self.inner.access_token.read().await.clone()
    }

    pub async fn refresh_token(&self) -> Option<String> {
        self.inner.refresh_token.read().await.clone()
    }

    pub async fn access_token_expires_at(&self) -> Option<SystemTime> {
        *self.inner.expires_at.read().await
    }

    pub async fn auth_config(&self) -> Option<AuthConfig> {
        self.inner.auth_config.read().await.clone()
    }

    pub async fn oidc_config(&self) -> Option<OidcConfig> {
        self.inner.oidc_config.read().await.clone()
    }

    pub fn client_name(&self) -> &str {
        &self.inner.client_name
    }

    /// Cache the `(client_id, client_secret)` pair so the background
    /// refresh loop can re-drive the `client_credentials` grant without
    /// re-fetching credentials from the host. Called by the factory when
    /// a connection is instantiated (or has its credentials updated) with
    /// `client_id`/`client_secret` fields.
    pub async fn set_client_credentials(&self, client_id: String, client_secret: String) {
        *self.inner.client_credentials.write().await = Some((client_id, client_secret));
    }

    /// Read the cached `(client_id, client_secret)` pair, if any. Returns
    /// `None` for connections using the interactive / refresh-token grant
    /// or for anonymous connections.
    pub async fn client_credentials(&self) -> Option<(String, String)> {
        self.inner.client_credentials.read().await.clone()
    }

    /// Seed only the refresh token slot — used by the warm-continue path
    /// where the caller has a stored refresh_token but no access_token yet
    /// and is about to drive a refresh-token grant.
    pub async fn install_refresh_token(&self, refresh_token: String) {
        *self.inner.refresh_token.write().await = Some(refresh_token);
    }

    pub async fn install_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
    ) {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        *self.inner.access_token.write().await = Some(access_token);
        if let Some(rt) = refresh_token {
            *self.inner.refresh_token.write().await = Some(rt);
        }
        *self.inner.expires_at.write().await = expires_at;
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
        self.inner.token_arrived.notify_waiters();
        // Spawn (or replace) the background refresh task. We only know
        // when to refresh if the server told us how long the token lives;
        // tokens without an `expires_in` are treated as "valid forever
        // from our POV" — the bearer interceptor will surface the
        // server's eventual UNAUTHENTICATED and warm-continue / the host
        // will re-authenticate.
        if let Some(ttl) = expires_in {
            self.replace_refresh_task(ttl);
        }
    }

    /// Abort any prior refresh task and spawn a new one re-based on `ttl`.
    /// Used internally by `install_tokens`; factored out so the spawn
    /// site is easy to follow.
    fn replace_refresh_task(&self, ttl: Duration) {
        // tokio::spawn requires we be on a runtime; this is only ever
        // called from async paths so `Handle::try_current` succeeds.
        let runtime_present = tokio::runtime::Handle::try_current().is_ok();
        if !runtime_present {
            // Some tests construct a `DiscoveryState` and call
            // `install_tokens` synchronously from a non-tokio context
            // (or after the runtime has been torn down). Skip the spawn
            // in that case — there's no loop to maintain.
            return;
        }
        let mut guard = match self.inner.refresh_task.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(prev) = guard.take() {
            prev.abort();
        }
        let state_weak = Arc::downgrade(&self.inner);
        let http = self.inner.http_client.clone();
        *guard = Some(tokio::spawn(refresh_loop(state_weak, http, ttl)));
    }

    /// Block until an access token is present. Used by cold-start paths
    /// (services discovery, dynamic-roots watcher) that must defer their
    /// first auth-required call until interactive sign-in completes.
    /// Uses the register-then-check pattern — `notify_waiters` doesn't
    /// store permits, so a naive `notified().await` after a None check
    /// would race with `install_tokens`.
    pub async fn wait_for_token(&self) {
        loop {
            let notified = self.inner.token_arrived.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.access_token().await.is_some() {
                return;
            }
            notified.await;
        }
    }

    pub async fn install_auth_config(&self, config: AuthConfig) {
        *self.inner.auth_config.write().await = Some(config);
    }

    pub async fn install_oidc_config(&self, config: OidcConfig) {
        *self.inner.oidc_config.write().await = Some(config);
    }

    pub async fn token_needs_refresh(&self) -> bool {
        let token = self.inner.access_token.read().await;
        let expires_at = self.inner.expires_at.read().await;
        let needs = match (token.as_ref(), *expires_at) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(_), Some(at)) => SystemTime::now() + REFRESH_SKEW >= at,
        };
        if needs {
            tracing::debug!(
                target: "ovstorage.omniverse_storage_service.auth",
                plugin = "omniverse-storage-service",
                cache.hit = false,
                cache.kind = "oauth_token",
                "omniverse-storage-service: token cache miss — refresh required",
            );
        } else {
            tracing::debug!(
                target: "ovstorage.omniverse_storage_service.auth",
                plugin = "omniverse-storage-service",
                cache.hit = true,
                cache.kind = "oauth_token",
                "omniverse-storage-service: token cache hit",
            );
        }
        needs
    }
}

#[derive(Clone)]
pub struct AuthorizationInterceptor {
    state: DiscoveryState,
}

impl AuthorizationInterceptor {
    pub fn new(state: DiscoveryState) -> Self {
        Self { state }
    }
}

impl Interceptor for AuthorizationInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        // Sync interceptor: try_read avoids blocking under refresh contention.
        // No token → emit nothing and let the server return UNAUTHENTICATED.
        let token = match self.state.inner.access_token.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        };
        if let Some(token) = token {
            let header = format!("Bearer {token}");
            match MetadataValue::try_from(header.as_str()) {
                Ok(value) => {
                    request.metadata_mut().insert("authorization", value);
                }
                Err(_) => {
                    return Err(Status::internal(
                        "omniverse-storage-service: access token contains characters \
                         invalid in an HTTP header",
                    ));
                }
            }
        }
        Ok(request)
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

pub async fn fetch_auth_config(
    client: &reqwest::Client,
    discovery_url: &str,
) -> Result<AuthConfig> {
    let trimmed = discovery_url.trim_end_matches('/');
    let url = format!("{trimmed}/api/v1/auth-config");
    tracing::debug!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: fetching auth-config",
    );
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: auth-config fetch failed for {url}: {err}"),
        )
    })?;
    if response.status().as_u16() == 404 {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "omniverse-storage-service: {url} returned 404 (server publishes no auth-config)"
            ),
        ));
    }
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::Transient,
            format!(
                "omniverse-storage-service: auth-config returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: auth-config body read failed: {err}"),
        )
    })?;
    let parsed = serde_json::from_slice::<AuthConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("omniverse-storage-service: auth-config JSON parse failed: {err}"),
        )
    })?;
    tracing::trace!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        url = %url,
        auth_config = ?parsed,
        "omniverse-storage-service: /api/v1/auth-config response body",
    );
    Ok(parsed)
}

pub async fn fetch_oidc_config(
    client: &reqwest::Client,
    auth_config: &AuthConfig,
) -> Result<OidcConfig> {
    let url = auth_config
        .openid_configuration
        .trim_end_matches('/')
        .to_string();
    tracing::debug!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: fetching OIDC discovery",
    );
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: OIDC discovery fetch failed for {url}: {err}"),
        )
    })?;
    let response = if response.status().is_success() {
        response
    } else {
        let alt = format!("{url}/.well-known/openid-configuration");
        client.get(&alt).send().await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: OIDC discovery fetch failed for {alt}: {err}"),
            )
        })?
    };
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "omniverse-storage-service: OIDC discovery returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: OIDC discovery body read failed: {err}"),
        )
    })?;
    serde_json::from_slice::<OidcConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("omniverse-storage-service: OIDC discovery JSON parse failed: {err}"),
        )
    })
}

/// Compute the next sleep before a proactive token refresh.
///
/// Refresh at 90% of the token's TTL — far enough ahead of expiry to
/// absorb network latency and IDP clock skew, but late enough that
/// short-lived tokens don't trigger a thundering herd of refreshes
/// immediately after install. Clamped to a 30-second floor so a
/// pathologically tiny TTL (or a clock that jumped forward) doesn't
/// busy-loop the refresh endpoint.
fn refresh_sleep_for(ttl: Duration) -> Duration {
    (ttl * 9 / 10).max(Duration::from_secs(30))
}

/// Background refresh loop spawned by `install_tokens`. Owns only a
/// `Weak<DiscoveryStateInner>` so it doesn't keep the state alive past
/// its natural drop — `Drop for DiscoveryStateInner` aborts the
/// `JoinHandle`, and any in-flight upgrade attempt returns `None` after
/// the strong-count hits zero.
///
/// Each iteration:
/// 1. Sleep until the next refresh deadline — `refresh_sleep_for(ttl)`
///    on the first iteration, [`REFRESH_RETRY_INTERVAL`] on retries
///    after a failure.
/// 2. Try to upgrade the `Weak`; on failure (state dropped), exit.
/// 3. Pick the grant: cached `client_credentials` if set, else the
///    refresh-token grant. (Anonymous connections never install a
///    token with `expires_in`, so this branch is unreachable for them.)
/// 4. On grant success, return — `install_tokens` (called inside the
///    grant) has already spawned a replacement loop re-based on the
///    new TTL. On failure, switch the next sleep to the short retry
///    interval so a single failure doesn't strand the token expired
///    for most of its remaining lifetime.
async fn refresh_loop(state_weak: Weak<DiscoveryStateInner>, http: reqwest::Client, ttl: Duration) {
    let mut next_sleep = refresh_sleep_for(ttl);
    loop {
        tokio::time::sleep(next_sleep).await;
        let Some(inner) = state_weak.upgrade() else {
            return;
        };
        let live = DiscoveryState { inner };
        let grant_result = match live.client_credentials().await {
            Some((id, secret)) => drive_client_credentials_grant(&http, &live, &id, &secret).await,
            None => drive_refresh_token_grant(&http, &live).await,
        };
        // Release the strong ref before the next sleep so the state
        // can be dropped during the retry window if the host tears the
        // connection down.
        drop(live);
        match grant_result {
            Ok(_) => {
                // install_tokens (called inside the grant) just spawned a
                // fresh refresh task re-based on the new TTL. Exit this
                // iteration so we don't have two loops racing each other.
                return;
            }
            Err(err) => {
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    error.code = ?err.code(),
                    "omniverse-storage-service: background refresh failed; will retry in 30s",
                );
                // Don't drift back to refresh_sleep_for(ttl): the
                // token is past its 90%-of-TTL refresh point and
                // another long sleep would leave it expired for most
                // of the remaining lifetime.
                next_sleep = REFRESH_RETRY_INTERVAL;
            }
        }
    }
}

/// Cadence used by [`refresh_loop`] for retry sleeps after a failed
/// grant. Short enough that one IDP blip doesn't leave the token
/// expired for the rest of its lifetime, long enough not to hammer
/// the IDP under sustained failures.
const REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub async fn drive_refresh_token_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
) -> Result<u64> {
    let span = tracing::debug_span!(
        "omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        outcome = tracing::field::Empty,
    );
    async move {
        tracing::debug!(
            target: "ovstorage.omniverse_storage_service.auth",
            plugin = "omniverse-storage-service",
            "omniverse-storage-service: refresh token grant triggered",
        );
        let result = drive_refresh_token_grant_inner(client, state).await;
        match &result {
            Ok(_) => {
                tracing::span::Span::current().record("outcome", "ok");
                tracing::info!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    "omniverse-storage-service: token refreshed",
                );
            }
            Err(err) => {
                tracing::span::Span::current().record("outcome", "err");
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    error.code = ?err.code(),
                    "omniverse-storage-service: refresh token grant failed",
                );
            }
        }
        result
    }
    .instrument(span)
    .await
}

async fn drive_refresh_token_grant_inner(
    client: &reqwest::Client,
    state: &DiscoveryState,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: refresh requested but OIDC config not loaded",
        )
    })?;
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: refresh requested but auth-config not loaded",
        )
    })?;
    let refresh_token = state.refresh_token().await.ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "omniverse-storage-service: refresh requested but no refresh_token is stored",
        )
    })?;
    let client_id = auth_config
        .clients
        .get(state.client_name())
        .map(|c| c.client_id.clone())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "omniverse-storage-service: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(scope) = auth_config
        .clients
        .get(state.client_name())
        .and_then(|c| c.scope.clone())
    {
        form.push(("scope", scope));
    }
    let response = client
        .post(&oidc.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body);
        let code = if status.as_u16() == 401
            || (status.as_u16() == 400 && body_str.contains("invalid_grant"))
        {
            ErrorCode::AuthExpired
        } else {
            ErrorCode::Transient
        };
        return Err(Error::new(
            code,
            format!(
                "omniverse-storage-service: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                body_str
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: token endpoint response JSON parse failed: {err}"),
        )
    })?;
    state
        .install_tokens(
            token_response.access_token,
            token_response.refresh_token,
            token_response.expires_in.map(Duration::from_secs),
        )
        .await;
    Ok(state.generation())
}

/// Drive an OAuth2 `client_credentials` grant against the IDP's token
/// endpoint. Used for machine-to-machine identities that authenticate
/// with a `(client_id, client_secret)` pair instead of an interactive
/// user sign-in. On success the response's access token is installed on
/// `state` via `install_tokens`; a refresh token is rarely issued for
/// this grant type (and is not required since the grant can be
/// re-driven from the cached credentials).
pub async fn drive_client_credentials_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
    client_id: &str,
    client_secret: &str,
) -> Result<u64> {
    let span = tracing::debug_span!(
        "omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        grant = "client_credentials",
        outcome = tracing::field::Empty,
    );
    async move {
        tracing::debug!(
            target: "ovstorage.omniverse_storage_service.auth",
            plugin = "omniverse-storage-service",
            "omniverse-storage-service: client_credentials grant triggered",
        );
        let result =
            drive_client_credentials_grant_inner(client, state, client_id, client_secret).await;
        match &result {
            Ok(_) => {
                tracing::span::Span::current().record("outcome", "ok");
                tracing::info!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    "omniverse-storage-service: client_credentials grant succeeded",
                );
            }
            Err(err) => {
                tracing::span::Span::current().record("outcome", "err");
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.auth",
                    plugin = "omniverse-storage-service",
                    error.code = ?err.code(),
                    "omniverse-storage-service: client_credentials grant failed",
                );
            }
        }
        result
    }
    .instrument(span)
    .await
}

async fn drive_client_credentials_grant_inner(
    client: &reqwest::Client,
    state: &DiscoveryState,
    client_id: &str,
    client_secret: &str,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: client_credentials grant requested but OIDC config not loaded",
        )
    })?;
    // auth-config is optional for this grant — the caller supplies the
    // client_id/client_secret directly — but if it's loaded and has a
    // scope for the configured client, honour it. This mirrors the
    // refresh-token grant's scope handling so server-side enforcement
    // sees the same scope on both grants.
    let scope = state
        .auth_config()
        .await
        .and_then(|cfg| cfg.clients.get(state.client_name()).cloned())
        .and_then(|client| client.scope);
    let mut form = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id.to_string()),
        ("client_secret", client_secret.to_string()),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    let response = client
        .post(&oidc.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body);
        let code = if status.as_u16() == 401
            || (status.as_u16() == 400 && body_str.contains("invalid_client"))
        {
            ErrorCode::AuthExpired
        } else {
            ErrorCode::Transient
        };
        return Err(Error::new(
            code,
            format!(
                "omniverse-storage-service: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                body_str
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("omniverse-storage-service: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: token endpoint response JSON parse failed: {err}"),
        )
    })?;
    state
        .install_tokens(
            token_response.access_token,
            token_response.refresh_token,
            token_response.expires_in.map(Duration::from_secs),
        )
        .await;
    Ok(state.generation())
}

/// Drive an interactive OIDC login (PKCE on `Browser`, RFC 8628 device flow
/// Pick the OIDC URL that maps to `OAuthEndpoints.authorization_endpoint`
/// for the given capability. PKCE wants the IDP's
/// `authorization_endpoint`; the device-code flow wants
/// `device_authorization_endpoint` — the host's field is overloaded
/// (see `ovstorage::auth::flow::run_device_flow`). Wiring PKCE's URL
/// to the device flow makes the client POST the device-code request
/// to `/authorize`, which the IDP rejects.
fn endpoint_for_capability(
    oidc: &OidcConfig,
    capability: InteractiveAuthCapability,
) -> Result<&str> {
    match capability {
        InteractiveAuthCapability::Browser => {
            oidc.authorization_endpoint.as_deref().ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "omniverse-storage-service: IDP discovery missing authorization_endpoint \
                 (required for PKCE / browser flow)",
                )
            })
        }
        InteractiveAuthCapability::Headless => oidc
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::NotConfigured,
                    "omniverse-storage-service: IDP discovery missing \
                     device_authorization_endpoint (required for headless / device-code flow)",
                )
            }),
        InteractiveAuthCapability::None => Err(Error::new(
            ErrorCode::AuthRequired,
            "omniverse-storage-service: host declared no interactive auth capability",
        )),
    }
}

/// on `Headless`) using the shared `ovstorage::OAuthFlow` infra. The
/// `AuthEvent` stream is bridged from async (BoxStream) to the sync iterator
/// the SPI expects via a dedicated thread + per-bridge tokio runtime — both
/// flows park waiting on a user action, so collecting first would deadlock
/// the prompt.
pub async fn drive_interactive_login(
    state: &DiscoveryState,
    connection: Connection,
    capability: InteractiveAuthCapability,
) -> Result<AuthEventStream> {
    let span = tracing::info_span!(
        "omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        outcome = tracing::field::Empty,
    );
    let _guard = span.enter();

    if matches!(capability, InteractiveAuthCapability::None) {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "omniverse-storage-service: host declared no interactive auth capability",
        ));
    }
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: interactive login requested but auth-config not loaded",
        )
    })?;
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "omniverse-storage-service: interactive login requested but OIDC discovery not loaded",
        )
    })?;
    let client = auth_config
        .clients
        .get(state.client_name())
        .cloned()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "omniverse-storage-service: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    // The host's `OAuthEndpoints.authorization_endpoint` is overloaded:
    // for PKCE flow it is the OIDC `authorization_endpoint`; for the
    // device-code flow it is the OIDC `device_authorization_endpoint`.
    // Choose by capability so headless auth POSTs the device-code
    // request to the right URL (was using `/authorize` for both).
    let endpoint_str = endpoint_for_capability(&oidc, capability)?;
    let endpoints = ovstorage::OAuthEndpoints {
        authorization_endpoint: url::Url::parse(endpoint_str).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service: malformed authorization_endpoint: {err}"),
            )
        })?,
        token_endpoint: url::Url::parse(&oidc.token_endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service: malformed token_endpoint: {err}"),
            )
        })?,
        client_id: client.client_id,
        scope: client.scope,
    };
    tracing::info!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: interactive OAuth flow started",
    );
    let connection_id: ConnectionId = connection.id.clone();
    let backend_id = BackendId(format!("omniverse-storage-service:{}", state.client_name()));
    let flow = match capability {
        InteractiveAuthCapability::Headless => {
            ovstorage::OAuthFlow::device(backend_id).with_connection(connection_id)
        }
        InteractiveAuthCapability::Browser => {
            // Path matches the omniverse-storage-service AAD app's registered redirect URI.
            let redirect_base = url::Url::parse("http://127.0.0.1/openid").map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("omniverse-storage-service: redirect base parse: {err}"),
                )
            })?;
            ovstorage::OAuthFlow::pkce(backend_id, redirect_base).with_connection(connection_id)
        }
        InteractiveAuthCapability::None => unreachable!("checked above"),
    };
    let flow = flow.with_endpoints(endpoints);
    tracing::info!(
        target: "ovstorage.omniverse_storage_service.auth",
        plugin = "omniverse-storage-service",
        "omniverse-storage-service: interactive OAuth flow dispatched to bridge thread",
    );
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("ovs-oms-auth".into())
        .spawn(move || {
            use futures::StreamExt;
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = sender.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!(
                            "omniverse-storage-service: failed to create OAuth flow runtime: {err}"
                        ),
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                match flow.run().await {
                    Ok(mut stream) => {
                        while let Some(event) = stream.next().await {
                            if sender.send(event).is_err() {
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        let _ = sender.send(Err(err.into_error()));
                    }
                }
            });
        })
        .expect("failed to spawn thread");
    Ok(Box::new(receiver.into_iter()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn install_tokens_bumps_generation() {
        let state = DiscoveryState::new("default");
        assert_eq!(state.generation(), 0);
        state
            .install_tokens(
                "at1".into(),
                Some("rt1".into()),
                Some(Duration::from_secs(3600)),
            )
            .await;
        assert_eq!(state.generation(), 1);
        assert_eq!(state.access_token().await.as_deref(), Some("at1"));
        assert_eq!(state.refresh_token().await.as_deref(), Some("rt1"));
        // Refresh preserved when install_tokens doesn't supply one.
        state
            .install_tokens("at2".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert_eq!(state.generation(), 2);
        assert_eq!(state.refresh_token().await.as_deref(), Some("rt1"));
    }

    #[tokio::test]
    async fn token_needs_refresh_handles_unset_and_skew() {
        let state = DiscoveryState::new("default");
        assert!(state.token_needs_refresh().await);
        state
            .install_tokens("at".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert!(!state.token_needs_refresh().await);
        state
            .install_tokens("at".into(), None, Some(Duration::from_secs(30)))
            .await;
        assert!(state.token_needs_refresh().await);
    }

    #[tokio::test]
    async fn interceptor_injects_bearer_when_token_present() {
        let state = DiscoveryState::new("default");
        state.install_tokens("token123".into(), None, None).await;
        let mut interceptor = AuthorizationInterceptor::new(state);
        let request: Request<()> = Request::new(());
        let intercepted = interceptor.call(request).unwrap();
        let auth = intercepted.metadata().get("authorization").unwrap();
        assert_eq!(auth.to_str().unwrap(), "Bearer token123");
    }

    #[tokio::test]
    async fn interceptor_passes_through_when_no_token() {
        let state = DiscoveryState::new("default");
        let mut interceptor = AuthorizationInterceptor::new(state);
        let request: Request<()> = Request::new(());
        let intercepted = interceptor.call(request).unwrap();
        assert!(intercepted.metadata().get("authorization").is_none());
    }

    #[tokio::test]
    async fn set_and_read_client_credentials_round_trips() {
        let state = DiscoveryState::new("default");
        assert!(state.client_credentials().await.is_none());
        state
            .set_client_credentials("svc-id".into(), "svc-secret".into())
            .await;
        assert_eq!(
            state.client_credentials().await,
            Some(("svc-id".into(), "svc-secret".into()))
        );
    }

    /// Stand up a single-shot token endpoint that captures the form body
    /// and replies with a canned `TokenResponse`. Asserts the body shape
    /// produced by `drive_client_credentials_grant` matches RFC 6749 §4.4
    /// (`grant_type=client_credentials&client_id=…&client_secret=…`) and
    /// that the access token lands in the state.
    #[tokio::test]
    async fn client_credentials_grant_form_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            // Read headers, then continue reading until we have a full
            // body matching Content-Length.
            let mut content_length: Option<usize> = None;
            let mut header_end: Option<usize> = None;
            while total < buf.len() {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none()
                    && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    header_end = Some(idx + 4);
                    let header_str = String::from_utf8_lossy(&buf[..idx]).to_string();
                    for line in header_str.lines() {
                        if let Some(value) = line
                            .strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                        {
                            content_length = value.trim().parse().ok();
                        }
                    }
                }
                if let (Some(hend), Some(cl)) = (header_end, content_length)
                    && total >= hend + cl
                {
                    break;
                }
            }
            let header_end = header_end.unwrap_or(total);
            let body = String::from_utf8_lossy(&buf[header_end..total]).to_string();
            let _ = body_tx.send(body);
            let response_body =
                r#"{"access_token":"cc-access","token_type":"Bearer","expires_in":300}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let state = DiscoveryState::new("default");
        state
            .install_oidc_config(OidcConfig {
                issuer: "http://test".into(),
                token_endpoint: token_endpoint.clone(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let http = reqwest::Client::new();
        let generation =
            drive_client_credentials_grant(&http, &state, "svc-client", "svc-secret-shhh")
                .await
                .expect("grant succeeds");
        assert_eq!(generation, 1, "install_tokens must bump generation to 1");
        assert_eq!(
            state.access_token().await.as_deref(),
            Some("cc-access"),
            "access token must be installed",
        );

        let body = body_rx.await.expect("server captured form body");
        // Parse the URL-encoded form body so we don't depend on field order.
        let pairs: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            pairs.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            pairs.get("client_id").map(String::as_str),
            Some("svc-client")
        );
        assert_eq!(
            pairs.get("client_secret").map(String::as_str),
            Some("svc-secret-shhh"),
        );
        // No auth-config installed → no scope field on the wire.
        assert!(
            !pairs.contains_key("scope"),
            "scope absent when no auth-config"
        );
    }

    /// When auth-config carries a `scope` for the configured client, the
    /// grant must include it on the wire so server-side enforcement matches
    /// the refresh-token grant path.
    #[tokio::test]
    async fn client_credentials_grant_includes_scope_when_configured() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            let mut content_length: Option<usize> = None;
            let mut header_end: Option<usize> = None;
            while total < buf.len() {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none()
                    && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    header_end = Some(idx + 4);
                    let header_str = String::from_utf8_lossy(&buf[..idx]).to_string();
                    for line in header_str.lines() {
                        if let Some(value) = line
                            .strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                        {
                            content_length = value.trim().parse().ok();
                        }
                    }
                }
                if let (Some(hend), Some(cl)) = (header_end, content_length)
                    && total >= hend + cl
                {
                    break;
                }
            }
            let header_end = header_end.unwrap_or(total);
            let body = String::from_utf8_lossy(&buf[header_end..total]).to_string();
            let _ = body_tx.send(body);
            let response_body = r#"{"access_token":"cc-2","expires_in":300}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let state = DiscoveryState::new("default");
        let mut clients = std::collections::BTreeMap::new();
        clients.insert(
            "default".to_string(),
            AuthClientConfig {
                client_id: "ignored-default-client".into(),
                scope: Some("storage.read storage.write".into()),
            },
        );
        state
            .install_auth_config(AuthConfig {
                openid_configuration: "http://test".into(),
                clients,
            })
            .await;
        state
            .install_oidc_config(OidcConfig {
                issuer: "http://test".into(),
                token_endpoint: token_endpoint.clone(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        let http = reqwest::Client::new();
        drive_client_credentials_grant(&http, &state, "svc-id", "svc-secret")
            .await
            .expect("grant succeeds");
        let body = body_rx.await.expect("captured");
        let pairs: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            pairs.get("scope").map(String::as_str),
            Some("storage.read storage.write"),
        );
    }

    /// The first sleep must land at exactly `ttl * 9 / 10`. We verify
    /// this deterministically by spawning `refresh_loop` directly with a
    /// `Weak` whose target we drop up-front: that turns the loop into a
    /// pure "sleep, then upgrade-and-bail" stub, so the moment the loop
    /// returns we know the sleep completed.
    ///
    /// `tokio::time::pause()` freezes the clock; `advance` moves it
    /// without yielding to wall-clock time. We advance to `9/10 * ttl - 1ms`
    /// and check the task hasn't finished, then advance the final 1ms
    /// and confirm it has — proving the sleep was exactly `9/10 * ttl`.
    #[tokio::test(start_paused = true)]
    async fn refresh_loop_sleeps_until_90pct_ttl() {
        // Set up a Weak that's already dead so the loop short-circuits
        // on its first upgrade. No HTTP or grant logic runs.
        let weak: Weak<DiscoveryStateInner> = {
            let state = DiscoveryState::new("default");
            Arc::downgrade(&state.inner)
        };
        assert!(weak.upgrade().is_none(), "state must be dropped");

        let ttl = Duration::from_secs(1_000);
        let expected_sleep = ttl * 9 / 10;
        let http = reqwest::Client::new();
        let handle = tokio::spawn(refresh_loop(weak, http, ttl));

        // Yield so the spawned task is polled and registers its sleep
        // BEFORE we advance the clock. Otherwise `advance` happens
        // before the sleep is installed and the task still parks for
        // the full `expected_sleep` after we resume.
        tokio::task::yield_now().await;

        // Just-before the sleep deadline: task must still be parked.
        tokio::time::advance(expected_sleep - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !handle.is_finished(),
            "loop returned before the 90%-TTL sleep deadline",
        );

        // Cross the deadline: the sleep resolves, the upgrade returns
        // None (state was dropped), and the loop exits.
        tokio::time::advance(Duration::from_millis(2)).await;
        // Give the task a chance to run to completion. With paused
        // time we can't `tokio::time::timeout` — that would never
        // resolve. Yield repeatedly and check `is_finished` instead.
        for _ in 0..100 {
            if handle.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            handle.is_finished(),
            "loop did not exit after the 90%-TTL sleep deadline",
        );
        // Drain the JoinHandle so we surface any panic.
        let _ = handle.await;
    }

    /// When the state has a cached `(client_id, client_secret)` pair,
    /// the refresh loop must dispatch via the `client_credentials` grant
    /// path — not the refresh-token grant. We verify this on the wire by
    /// pointing the state at a mock token endpoint and asserting the
    /// captured form body has `grant_type=client_credentials`.
    #[tokio::test]
    async fn refresh_loop_picks_client_credentials_when_cached() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let (body_tx, body_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            let mut content_length: Option<usize> = None;
            let mut header_end: Option<usize> = None;
            while total < buf.len() {
                let n = sock.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if header_end.is_none()
                    && let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n")
                {
                    header_end = Some(idx + 4);
                    let header_str = String::from_utf8_lossy(&buf[..idx]).to_string();
                    for line in header_str.lines() {
                        if let Some(value) = line
                            .strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                        {
                            content_length = value.trim().parse().ok();
                        }
                    }
                }
                if let (Some(hend), Some(cl)) = (header_end, content_length)
                    && total >= hend + cl
                {
                    break;
                }
            }
            let header_end = header_end.unwrap_or(total);
            let body = String::from_utf8_lossy(&buf[header_end..total]).to_string();
            let _ = body_tx.send(body);
            // Reply with a short-lived token — keeps the test fast and
            // proves install_tokens accepts the response on the
            // client_credentials path.
            let response_body =
                r#"{"access_token":"refreshed-cc","token_type":"Bearer","expires_in":120}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });

        let state = DiscoveryState::new("default");
        state
            .install_oidc_config(OidcConfig {
                issuer: "http://test".into(),
                token_endpoint: token_endpoint.clone(),
                authorization_endpoint: None,
                device_authorization_endpoint: None,
                end_session_endpoint: None,
            })
            .await;
        state
            .set_client_credentials("loop-id".into(), "loop-secret".into())
            .await;

        // Pause tokio time so the loop's first sleep (the 30s floor in
        // `refresh_sleep_for`) doesn't actually wall-clock-block the
        // test. We spawn first, yield to let the loop register its
        // sleep, then advance past the deadline. Resuming lets the
        // mock server's real-I/O accept loop make progress.
        tokio::time::pause();
        let http = reqwest::Client::new();
        let weak = Arc::downgrade(&state.inner);
        let handle = tokio::spawn(refresh_loop(weak, http, Duration::from_secs(1)));
        // Yield so the task gets polled and registers its sleep before
        // we advance time. Without this `advance` would happen before
        // the sleep was installed and the task would still park 30s.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::time::resume();
        let body = tokio::time::timeout(Duration::from_secs(5), body_rx)
            .await
            .expect("token endpoint received a request within 5s")
            .expect("body captured");
        // The loop may keep going past the first grant (it spawned a
        // replacement task on install_tokens). Abort to keep the test
        // bounded.
        handle.abort();

        let pairs: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
        assert_eq!(
            pairs.get("grant_type").map(String::as_str),
            Some("client_credentials"),
            "background loop must dispatch via client_credentials when cached",
        );
        assert_eq!(pairs.get("client_id").map(String::as_str), Some("loop-id"),);
        assert_eq!(
            pairs.get("client_secret").map(String::as_str),
            Some("loop-secret"),
        );
        // The form body is the primary signal — it proves the loop
        // dispatched via `drive_client_credentials_grant` rather than
        // `drive_refresh_token_grant`. We don't assert on the
        // post-grant `state.access_token()` here because the test
        // aborts the loop right after capturing the body (the grant
        // response read can race with abort), and because
        // `install_tokens` spawns a replacement refresh task that we'd
        // need to chase down separately for cleanup.
    }

    /// Dropping the `DiscoveryState` must abort the spawned refresh
    /// task — even if its `tokio::time::sleep` is parked far in the
    /// future. We prove this by observing a Drop guard the spawned task
    /// holds: when the JoinHandle is aborted, the future is cancelled
    /// at its next await point, the guard's `Drop` runs, and our
    /// `Arc<AtomicBool>` flips. If we relied on natural runtime
    /// shutdown the flag wouldn't flip within the test window.
    #[tokio::test(start_paused = true)]
    async fn refresh_loop_aborts_on_drop() {
        use std::sync::atomic::AtomicBool;

        // The task's local state hooks into Drop to signal completion
        // from outside. The atomic is shared with the test thread.
        struct CompletionSignal(Arc<AtomicBool>);
        impl Drop for CompletionSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let done = Arc::new(AtomicBool::new(false));
        let done_for_task = done.clone();

        let state = DiscoveryState::new("default");
        // Spawn a task that mirrors `refresh_loop`'s structure (parks on
        // a long sleep) and is registered in the state's `refresh_task`
        // slot so `Drop for DiscoveryStateInner` aborts it.
        let weak = Arc::downgrade(&state.inner);
        let task = tokio::spawn(async move {
            let _signal = CompletionSignal(done_for_task);
            // Mirror the real loop's structure: sleep, then bail if
            // the state is gone. With time paused the sleep parks
            // forever — only abort can wake this task.
            tokio::time::sleep(Duration::from_secs(3_600)).await;
            // Unreachable in this test (abort fires first).
            let _ = weak.upgrade();
        });
        // Park the task in `state.inner.refresh_task` so Drop sees it.
        // (We bypass install_tokens to avoid stamping a real grant URL.)
        *state.inner.refresh_task.lock().unwrap() = Some(task);

        // Yield so the spawned task gets to its `.await` and the sleep
        // is actually registered. With paused time, the sleep won't
        // resolve naturally — only abort can complete this task.
        tokio::task::yield_now().await;
        assert!(
            !done.load(Ordering::SeqCst),
            "completion signal must not fire before drop",
        );

        // Drop the state. This drops the last Arc → DiscoveryStateInner
        // is dropped → Drop's `handle.abort()` fires → the spawned
        // task's sleep .await yields a CancelledError → the future
        // unwinds, dropping `_signal` → `done` flips.
        drop(state);

        // Give the runtime a chance to deliver the abort to the task.
        // We loop on yield rather than sleep because time is paused.
        for _ in 0..100 {
            if done.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            done.load(Ordering::SeqCst),
            "refresh task did not abort after state drop",
        );
    }

    /// After a failed refresh, the loop's NEXT sleep must be the short
    /// retry cadence — not the long `refresh_sleep_for(ttl)` again.
    /// Otherwise one failure leaves the token expired for most of its
    /// remaining lifetime.
    ///
    /// To exercise this without HTTP, we cache `client_credentials` but
    /// never install an OIDC config — so `drive_client_credentials_grant`
    /// fails synchronously at the "OIDC config not loaded" check. After
    /// the first failure we drop the strong ref; the loop's next
    /// `upgrade()` will return `None` and the task exits — but only
    /// after its next sleep elapses. We assert the task finishes within
    /// the retry window (~30s), which only holds if the loop didn't go
    /// back to `refresh_sleep_for(ttl)` after the failure.
    #[tokio::test(start_paused = true)]
    async fn refresh_loop_retries_on_short_cadence_after_failure() {
        let state = DiscoveryState::new("default");
        state
            .set_client_credentials("id".into(), "secret".into())
            .await;

        let ttl = Duration::from_secs(1_000);
        let first_sleep = refresh_sleep_for(ttl);
        let http = reqwest::Client::new();
        let weak = Arc::downgrade(&state.inner);
        let handle = tokio::spawn(refresh_loop(weak, http, ttl));

        // Let the task park on the first sleep.
        tokio::task::yield_now().await;

        // Cross the first sleep deadline. The loop wakes, attempts the
        // grant, and it fails synchronously (no OIDC config). The loop
        // then arms its retry sleep.
        tokio::time::advance(first_sleep + Duration::from_millis(1)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }

        // Drop the only strong ref. The next `upgrade()` inside the
        // loop will return `None`, so the loop exits — but only after
        // its current sleep elapses.
        drop(state);

        // Advance just past 30s. With the fix in place, the retry
        // sleep is 30s and the task should now finish. Without the
        // fix, the retry path sleeps 30s and then immediately parks
        // on another `refresh_sleep_for(ttl)` (~900s) at the top of
        // the loop, so the task stays alive.
        tokio::time::advance(Duration::from_secs(31)).await;
        for _ in 0..200 {
            if handle.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            handle.is_finished(),
            "loop did not retry on the short cadence after a failed refresh",
        );
        let _ = handle.await;
    }

    fn oidc_with(auth: Option<&str>, device: Option<&str>) -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example".into(),
            token_endpoint: "https://idp.example/token".into(),
            authorization_endpoint: auth.map(str::to_string),
            device_authorization_endpoint: device.map(str::to_string),
            end_session_endpoint: None,
        }
    }

    /// Browser/PKCE flow uses the OIDC `authorization_endpoint`.
    #[test]
    fn endpoint_for_capability_browser_picks_authorization_endpoint() {
        let oidc = oidc_with(
            Some("https://idp.example/authorize"),
            Some("https://idp.example/device"),
        );
        let url = endpoint_for_capability(&oidc, InteractiveAuthCapability::Browser).unwrap();
        assert_eq!(url, "https://idp.example/authorize");
    }

    /// Headless/device flow uses the OIDC `device_authorization_endpoint`
    /// — NOT `authorization_endpoint`. The host's OAuthEndpoints field
    /// is overloaded for device flow.
    #[test]
    fn endpoint_for_capability_headless_picks_device_endpoint() {
        let oidc = oidc_with(
            Some("https://idp.example/authorize"),
            Some("https://idp.example/device"),
        );
        let url = endpoint_for_capability(&oidc, InteractiveAuthCapability::Headless).unwrap();
        assert_eq!(
            url, "https://idp.example/device",
            "device flow must POST to the device_authorization_endpoint, \
             not the authorization_endpoint",
        );
    }

    #[test]
    fn endpoint_for_capability_browser_missing_endpoint_errors() {
        let oidc = oidc_with(None, Some("https://idp.example/device"));
        let err = endpoint_for_capability(&oidc, InteractiveAuthCapability::Browser).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("authorization_endpoint"));
    }

    #[test]
    fn endpoint_for_capability_headless_missing_endpoint_errors() {
        let oidc = oidc_with(Some("https://idp.example/authorize"), None);
        let err = endpoint_for_capability(&oidc, InteractiveAuthCapability::Headless).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("device_authorization_endpoint"));
    }
}
