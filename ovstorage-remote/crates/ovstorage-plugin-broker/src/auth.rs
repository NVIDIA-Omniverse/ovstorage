// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-client OIDC authentication: discovery state + bearer interceptor.
//!
//! The interceptor reads the access token from `DiscoveryState` per RPC,
//! so a fresh token from refresh / `update_credentials` is visible on
//! the next call without channel rebuild.
//!
//! No internal retry on transient HTTP failures: callers propagate the
//! error and the library's retry layer handles it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ovstorage_broker_protocol::{
    X_OV_IAUTH, capability_from_metadata as protocol_capability_from_metadata,
    capability_metadata_value as protocol_capability_metadata_value,
};
use ovstorage_plugin::{
    ConnectionId, Error, ErrorCode, ErrorContext, InteractiveAuthCapability, Result,
};
use serde::Deserialize;
use tokio::sync::RwLock;
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Proactive-refresh window: refresh when the access token has less than
/// this remaining lifetime, to absorb client/IDP clock skew.
pub const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// Broker-published auth-config document, fetched at `/api/v1/auth-config`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthConfig {
    /// URL of the IDP's OpenID discovery doc.
    pub openid_configuration: String,
    /// Per-client config keyed by client name; selected via the
    /// `oidc_client_name` config knob (defaults to `"default"`).
    #[serde(default)]
    pub clients: std::collections::BTreeMap<String, AuthClientConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AuthClientConfig {
    pub client_id: String,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Selected fields from the OIDC discovery doc.
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

/// Per-backend auth state. Cheaply cloneable (`Arc` inside).
#[derive(Clone)]
pub struct DiscoveryState {
    inner: Arc<DiscoveryStateInner>,
}

struct DiscoveryStateInner {
    /// Bumps on every refresh or install; useful for downstream invalidation.
    generation: AtomicU64,
    access_token: RwLock<Option<String>>,
    refresh_token: RwLock<Option<String>>,
    expires_at: RwLock<Option<SystemTime>>,
    auth_config: RwLock<Option<AuthConfig>>,
    oidc_config: RwLock<Option<OidcConfig>>,
    client_name: String,
    /// Host's declared interactive-auth capability; read per-RPC by the
    /// interceptor to compose the `x-ov-iauth` metadata header.
    capability: std::sync::atomic::AtomicU8,
}

impl DiscoveryState {
    pub fn new(client_name: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(DiscoveryStateInner {
                generation: AtomicU64::new(0),
                access_token: RwLock::new(None),
                refresh_token: RwLock::new(None),
                expires_at: RwLock::new(None),
                auth_config: RwLock::new(None),
                oidc_config: RwLock::new(None),
                client_name: client_name.into(),
                capability: std::sync::atomic::AtomicU8::new(
                    InteractiveAuthCapability::Browser as u8,
                ),
            }),
        }
    }

    /// Set the host's declared interactive-auth capability. Default `Browser`.
    pub fn set_capability(&self, capability: InteractiveAuthCapability) {
        self.inner
            .capability
            .store(capability as u8, std::sync::atomic::Ordering::Relaxed);
    }

    /// Read back the currently-installed capability.
    pub fn capability(&self) -> InteractiveAuthCapability {
        match self
            .inner
            .capability
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            x if x == InteractiveAuthCapability::None as u8 => InteractiveAuthCapability::None,
            x if x == InteractiveAuthCapability::Headless as u8 => {
                InteractiveAuthCapability::Headless
            }
            _ => InteractiveAuthCapability::Browser,
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

    /// Seed only the refresh token slot — used by the warm-continue path
    /// where the caller has a stored refresh_token but no access_token yet
    /// and is about to drive a refresh-token grant.
    pub async fn install_refresh_token(&self, refresh_token: String) {
        *self.inner.refresh_token.write().await = Some(refresh_token);
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

    /// Install a fresh access + refresh token pair. Bumps generation.
    ///
    /// `refresh_token == None` PRESERVES the existing in-memory refresh
    /// slot. The refresh-token grant flow legitimately omits the
    /// refresh on response (RFC 6749 §6 — issuing a new refresh is
    /// optional), and we want to keep using the prior one. For the
    /// access-only credential-rotation path that must clear the slot,
    /// see [`Self::install_tokens_replacing_refresh`].
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
    }

    /// Like [`Self::install_tokens`] but always writes the refresh slot,
    /// clearing it when `refresh_token` is `None`. Use when rotating
    /// the credential identity (e.g., from a refresh-bearing OAuth
    /// bundle to an access-only one) so a stale refresh from the
    /// previous identity doesn't survive in memory.
    pub async fn install_tokens_replacing_refresh(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<Duration>,
    ) {
        let expires_at = expires_in.map(|d| SystemTime::now() + d);
        *self.inner.access_token.write().await = Some(access_token);
        *self.inner.refresh_token.write().await = refresh_token;
        *self.inner.expires_at.write().await = expires_at;
        self.inner.generation.fetch_add(1, Ordering::SeqCst);
    }

    pub async fn install_auth_config(&self, config: AuthConfig) {
        *self.inner.auth_config.write().await = Some(config);
    }

    pub async fn install_oidc_config(&self, config: OidcConfig) {
        *self.inner.oidc_config.write().await = Some(config);
    }

    /// True when the access token is unset OR within `REFRESH_SKEW` of expiring.
    pub async fn token_needs_refresh(&self) -> bool {
        let token = self.inner.access_token.read().await;
        let expires_at = self.inner.expires_at.read().await;
        match (token.as_ref(), *expires_at) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(_), Some(at)) => SystemTime::now() + REFRESH_SKEW >= at,
        }
    }
}

/// Tonic interceptor that injects `Authorization: Bearer <token>` per RPC,
/// reading the token from `DiscoveryState`. With no token, the request
/// passes through unchanged so the broker surfaces `AuthRequired`.
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
        // Synchronous interceptor: `try_read()` rather than `.await`.
        // Contended write window during refresh is microseconds; on miss
        // we emit no Authorization header and let the broker enforce.
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
                    // Refuse rather than emit a malformed header.
                    return Err(Status::internal(
                        "broker: access token contains characters \
                         invalid in an HTTP header",
                    ));
                }
            }
        }
        let capability_value = protocol_capability_metadata_value(self.state.capability());
        request.metadata_mut().insert(X_OV_IAUTH, capability_value);
        Ok(request)
    }
}

/// Re-export of the protocol-level metadata parser; lets broker-only
/// callers read the capability off a `MetadataMap` without depending on
/// `ovstorage-broker-protocol` directly.
pub fn capability_from_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> InteractiveAuthCapability {
    protocol_capability_from_metadata(metadata)
}

/// OIDC token-endpoint response (subset used by the refresh path).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Fetch the broker's `/api/v1/auth-config` and parse into [`AuthConfig`].
pub async fn fetch_auth_config(
    client: &reqwest::Client,
    discovery_url: &str,
) -> Result<AuthConfig> {
    let trimmed = discovery_url.trim_end_matches('/');
    let url = format!("{trimmed}/api/v1/auth-config");
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: auth-config fetch failed for {url}: {err}"),
        )
    })?;
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "broker: auth-config returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: auth-config body read failed: {err}"),
        )
    })?;
    let parsed = serde_json::from_slice::<AuthConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker: auth-config JSON parse failed: {err}"),
        )
    })?;
    tracing::trace!(
        target: "ovstorage.broker.auth",
        url = %url,
        auth_config = ?parsed,
        "broker: /api/v1/auth-config response body",
    );
    Ok(parsed)
}

/// Fetch the IDP's OIDC discovery document and parse into [`OidcConfig`].
pub async fn fetch_oidc_config(
    client: &reqwest::Client,
    auth_config: &AuthConfig,
) -> Result<OidcConfig> {
    let url = auth_config
        .openid_configuration
        .trim_end_matches('/')
        .to_string();
    // OIDC discovery may be served at the configured URL OR at issuer-root
    // + `.well-known/openid-configuration`; try configured first, fall back.
    let response = client.get(&url).send().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: OIDC discovery fetch failed for {url}: {err}"),
        )
    })?;
    let response = if response.status().is_success() {
        response
    } else {
        let alt = format!("{url}/.well-known/openid-configuration");
        client.get(&alt).send().await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("broker: OIDC discovery fetch failed for {alt}: {err}"),
            )
        })?
    };
    if !response.status().is_success() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!(
                "broker: OIDC discovery returned HTTP {} from {url}",
                response.status().as_u16()
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: OIDC discovery body read failed: {err}"),
        )
    })?;
    serde_json::from_slice::<OidcConfig>(&body).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker: OIDC discovery JSON parse failed: {err}"),
        )
    })
}

/// Drive an interactive OAuth login against the broker's IDP, returning
/// an `AuthEventStream` the host surfaces to the caller. Cold-start /
/// re-login case where no usable refresh token is available.
pub async fn drive_interactive_login(
    state: &DiscoveryState,
    connection: ovstorage_plugin::Connection,
    capability: InteractiveAuthCapability,
) -> ovstorage_plugin::Result<ovstorage_plugin::AuthEventStream> {
    if matches!(capability, InteractiveAuthCapability::None) {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "broker: host declared no interactive auth capability",
        ));
    }
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: interactive login requested but auth-config not loaded",
        )
    })?;
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: interactive login requested but OIDC discovery not loaded",
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
                    "broker: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    let authorization_endpoint = oidc.authorization_endpoint.as_ref().ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: IDP discovery missing authorization_endpoint",
        )
    })?;
    let endpoints = ovstorage::OAuthEndpoints {
        authorization_endpoint: url::Url::parse(authorization_endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker: malformed authorization_endpoint: {err}"),
            )
        })?,
        token_endpoint: url::Url::parse(&oidc.token_endpoint).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker: malformed token_endpoint: {err}"),
            )
        })?,
        client_id: client.client_id,
        scope: client.scope,
    };
    let connection_id = connection.id.clone();
    let backend_id = ovstorage_plugin::BackendId(format!("broker:{}", state.client_name()));
    let flow = match capability {
        InteractiveAuthCapability::Headless => {
            ovstorage::OAuthFlow::device(backend_id).with_connection(connection_id)
        }
        InteractiveAuthCapability::Browser => {
            // Path matches the broker's IDP app registration.
            let redirect_base = url::Url::parse("http://127.0.0.1/openid").map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("broker: redirect base parse: {err}"),
                )
            })?;
            ovstorage::OAuthFlow::pkce(backend_id, redirect_base).with_connection(connection_id)
        }
        InteractiveAuthCapability::None => unreachable!("handled above"),
    };
    let flow = flow.with_endpoints(endpoints);
    // Bridge async stream to sync iterator without buffering: browser/device
    // flows emit a prompt then wait for user action, so collecting first
    // would hide the prompt until the flow terminates. Dedicated thread +
    // per-bridge Runtime mirrors `watch_directory`.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("ovs-bc-auth".into())
        .spawn(move || {
            use futures::StreamExt;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                let _ = sender.send(Err(Error::new(
                    ErrorCode::Internal,
                    "broker: failed to create OAuth flow runtime",
                )));
                return;
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

/// Drive a refresh-token grant against the IDP's token endpoint, updating
/// the discovery state on success and returning the new generation counter.
pub async fn drive_refresh_token_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: refresh requested but OIDC config not loaded",
        )
    })?;
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: refresh requested but auth-config not loaded",
        )
    })?;
    let refresh_token = state.refresh_token().await.ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "broker: refresh requested but no refresh_token is stored",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("no_refresh_token_stored".into()),
            expired_at: None,
        })
    })?;
    let client_id = auth_config
        .clients
        .get(state.client_name())
        .map(|c| c.client_id.clone())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "broker: auth-config has no client named '{}'",
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
                format!("broker: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        // 401 / 400 with `invalid_grant` => refresh revoked/expired;
        // surface as AuthExpired so the host drives a fresh interactive flow.
        let body_str = String::from_utf8_lossy(&body);
        let is_auth_expired = status.as_u16() == 401
            || (status.as_u16() == 400 && body_str.contains("invalid_grant"));
        let code = if is_auth_expired {
            ErrorCode::AuthExpired
        } else {
            ErrorCode::Transient
        };
        let err = Error::new(
            code,
            format!(
                "broker: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                body_str
            ),
        );
        let err = if is_auth_expired {
            err.with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some(format!("refresh_token_grant_{}", status.as_u16())),
                expired_at: None,
            })
        } else {
            err
        };
        return Err(err);
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("broker: token endpoint response JSON parse failed: {err}"),
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

/// OAuth2 `client_credentials` grant. Used by `[connection.auth] client_secret_file`
/// to skip the interactive flow for non-interactive workloads (CI, batch jobs,
/// service accounts that have an OAuth client at the IDP).
///
/// Reads the secret at call time so kubelet- or vault-managed secret files
/// rotate transparently. The grant uses the discovered `client_id` + `scope`
/// for `state.client_name()`.
pub async fn drive_client_credentials_grant(
    client: &reqwest::Client,
    state: &DiscoveryState,
    secret_file: &std::path::Path,
) -> Result<u64> {
    let oidc = state.oidc_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: client_credentials grant requested but OIDC config not loaded",
        )
    })?;
    let auth_config = state.auth_config().await.ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            "broker: client_credentials grant requested but auth-config not loaded",
        )
    })?;
    let client_entry = auth_config
        .clients
        .get(state.client_name())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "broker: auth-config has no client named '{}'",
                    state.client_name()
                ),
            )
        })?;
    let client_id = client_entry.client_id.clone();
    let scope = client_entry.scope.clone();
    let client_secret = std::fs::read_to_string(secret_file)
        .map_err(|err| {
            Error::new(
                ErrorCode::CredentialUnavailable,
                format!(
                    "broker: client_secret_file '{}' read failed: {err}",
                    secret_file.display()
                ),
            )
        })?
        .trim()
        .to_string();
    if client_secret.is_empty() {
        return Err(Error::new(
            ErrorCode::CredentialUnavailable,
            format!(
                "broker: client_secret_file '{}' is empty",
                secret_file.display()
            ),
        ));
    }
    let mut form = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id),
        ("client_secret", client_secret),
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
                format!("broker: token endpoint POST failed: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        return Err(Error::new(
            if status.as_u16() == 401 || status.as_u16() == 400 {
                ErrorCode::AuthExpired
            } else {
                ErrorCode::Transient
            },
            format!(
                "broker: client_credentials grant returned HTTP {}: {}",
                status.as_u16(),
                String::from_utf8_lossy(&body)
            ),
        ));
    }
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker: token endpoint body read failed: {err}"),
        )
    })?;
    let token_response: TokenResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("broker: token endpoint response JSON parse failed: {err}"),
        )
    })?;
    state
        .install_tokens(
            token_response.access_token,
            None,
            token_response.expires_in.map(Duration::from_secs),
        )
        .await;
    Ok(state.generation())
}

/// Drive the broker's per-user upstream OAuth flow over the streaming `Auth`
/// RPC, rebuilding each `AuthEventPartial` into the SPI `AuthEvent` shape.
/// Workers without an interactive UI drop the stream; the broker's gate
/// times out and the next SPI call surfaces `AuthRequired`.
pub async fn drive_upstream_auth(
    transport: &dyn ovstorage_broker_protocol::BrokerClientTransport,
    address: ovstorage_plugin::Url,
    connection: ovstorage_plugin::Connection,
) -> ovstorage_plugin::Result<ovstorage_plugin::AuthEventStream> {
    let stream = transport.auth_stream(address).await?;
    // Bridge async-to-sync without buffering: the broker's gate blocks until
    // the host calls `RegisterCredential` after the interactive step, so
    // collecting first would deadlock the gate.
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("ovs-bc-upstream".into())
        .spawn(move || {
            use futures::StreamExt;
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                let _ = sender.send(Err(Error::new(
                    ErrorCode::Internal,
                    "broker: failed to create upstream-auth runtime",
                )));
                return;
            };
            runtime.block_on(async move {
                let mut stream = stream;
                while let Some(frame) = stream.next().await {
                    let partial = match frame {
                        Ok(p) => p,
                        Err(err) => {
                            let _ = sender.send(Err(err));
                            return;
                        }
                    };
                    let event = match partial {
                        ovstorage_broker_protocol::AuthEventPartial::OpenBrowser {
                            url,
                            expires_at,
                        } => Ok(ovstorage_plugin::AuthEvent::OpenBrowser { url, expires_at }),
                        ovstorage_broker_protocol::AuthEventPartial::DeviceCode {
                            user_code,
                            verification_url,
                            expires_at,
                            interval,
                        } => Ok(ovstorage_plugin::AuthEvent::DeviceCode {
                            user_code,
                            verification_url,
                            expires_at,
                            interval,
                        }),
                        ovstorage_broker_protocol::AuthEventPartial::Progress { message } => {
                            Ok(ovstorage_plugin::AuthEvent::Progress { message })
                        }
                        ovstorage_broker_protocol::AuthEventPartial::Succeeded {
                            connection_id: _,
                        } => Ok(ovstorage_plugin::AuthEvent::Succeeded {
                            connection: Box::new(connection.clone()),
                            credentials: None,
                        }),
                        ovstorage_broker_protocol::AuthEventPartial::Failed { error } => {
                            Ok(ovstorage_plugin::AuthEvent::Failed { error })
                        }
                        ovstorage_broker_protocol::AuthEventPartial::Cancelled => {
                            Ok(ovstorage_plugin::AuthEvent::Cancelled)
                        }
                    };
                    let terminal = matches!(
                        event,
                        Ok(ovstorage_plugin::AuthEvent::Succeeded { .. })
                            | Ok(ovstorage_plugin::AuthEvent::Failed { .. })
                            | Ok(ovstorage_plugin::AuthEvent::Cancelled)
                    );
                    if sender.send(event).is_err() {
                        return;
                    }
                    if terminal {
                        return;
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
        assert_eq!(state.access_token().await, Some("at1".into()));
        assert_eq!(state.refresh_token().await, Some("rt1".into()));
        state
            .install_tokens("at2".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert_eq!(state.generation(), 2);
        assert_eq!(state.access_token().await, Some("at2".into()));
        // Refresh preserved when install_tokens doesn't supply one.
        assert_eq!(state.refresh_token().await, Some("rt1".into()));
    }

    // Joe's review finding #3: rotating to an access-only identity
    // must clear the in-memory refresh slot — install_tokens(..., None,
    // ...) preserves on purpose (RFC 6749 §6 refresh-grant path), so
    // identity rotation needs the dedicated method.
    #[tokio::test]
    async fn install_tokens_replacing_refresh_clears_in_memory_slot() {
        let state = DiscoveryState::new("default");
        state
            .install_tokens(
                "at1".into(),
                Some("rt1".into()),
                Some(Duration::from_secs(3600)),
            )
            .await;
        assert_eq!(state.refresh_token().await, Some("rt1".into()));

        // Rotate to an access-only credential — the prior refresh
        // must not survive in memory.
        state
            .install_tokens_replacing_refresh("at2".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert_eq!(state.access_token().await, Some("at2".into()));
        assert_eq!(state.refresh_token().await, None);

        // Rotating to a different refresh-bearing identity also works.
        state
            .install_tokens_replacing_refresh(
                "at3".into(),
                Some("rt3".into()),
                Some(Duration::from_secs(3600)),
            )
            .await;
        assert_eq!(state.refresh_token().await, Some("rt3".into()));
    }

    #[tokio::test]
    async fn token_needs_refresh_handles_unset_and_skew() {
        let state = DiscoveryState::new("default");
        assert!(state.token_needs_refresh().await);
        state
            .install_tokens("at".into(), None, Some(Duration::from_secs(3600)))
            .await;
        assert!(!state.token_needs_refresh().await);
        // Token already inside the skew window.
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
}
