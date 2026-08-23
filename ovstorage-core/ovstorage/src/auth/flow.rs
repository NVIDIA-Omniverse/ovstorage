// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-driven OAuth state machine: PKCE auth-code with loopback
//! redirect listener ([`OAuthFlow::pkce`]) and RFC 8628 device-code
//! ([`OAuthFlow::device`]). Both return a `BoxStream<Result<AuthEvent>>`
//! from [`OAuthFlow::run`] terminating in `Succeeded` / `Failed` /
//! `Cancelled`. See `ovstorage.md` § "OAuth flow library API".

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use futures::stream::{BoxStream, StreamExt};
use ovstorage_plugin::{
    AuthEvent, BackendId, Connection, ConnectionAuthState, ConnectionId, Error, ErrorCode,
};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use super::pkce;

/// Maximum JSON or error body accepted from an OAuth endpoint. OAuth token and
/// device responses are small; bounding them prevents a misbehaving IdP from
/// making one flow retain an arbitrarily large response in memory.
pub(super) const MAX_OAUTH_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// Collect one OAuth endpoint response body without exceeding
/// [`MAX_OAUTH_RESPONSE_BODY_BYTES`]. The streamed-size check remains
/// authoritative because `Content-Length` may be absent or incorrect.
pub(super) async fn read_oauth_response_body(
    response: reqwest::Response,
    operation: &str,
) -> Result<Bytes, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OAUTH_RESPONSE_BODY_BYTES as u64)
    {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!(
                "{operation} body exceeds the {MAX_OAUTH_RESPONSE_BODY_BYTES}-byte OAuth response limit"
            ),
        ));
    }

    let mut body = BytesMut::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_OAUTH_RESPONSE_BODY_BYTES as u64) as usize,
    );
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| {
            Error::new(
                ErrorCode::Transient,
                format!("{operation} body read failed: {error}"),
            )
        })?;
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > MAX_OAUTH_RESPONSE_BODY_BYTES)
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                format!(
                    "{operation} body exceeds the {MAX_OAUTH_RESPONSE_BODY_BYTES}-byte OAuth response limit"
                ),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

/// Setup-time errors surfaced before any `AuthEvent` can be emitted.
/// Terminal flow failures (token exchange refused, device-code
/// expired) come through `AuthEvent::Failed` inside the stream.
#[derive(Debug)]
pub enum AuthError {
    Setup(Error),
}

impl AuthError {
    pub fn into_error(self) -> Error {
        match self {
            AuthError::Setup(err) => err,
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Setup(err) => write!(f, "{}", err.message()),
        }
    }
}

impl std::error::Error for AuthError {}

/// Per-flow IDP coordinates. The flow does not bake in any specific
/// IDP discovery step — callers compose this from their own
/// `OidcConfig` source.
#[derive(Clone, Debug)]
pub struct OAuthEndpoints {
    /// PKCE authorise endpoint OR device-authorisation endpoint —
    /// overloaded so callers build one struct from `OidcConfig`.
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub client_id: String,
    /// Space-separated; defaults to `"openid"`.
    pub scope: Option<String>,
}

/// One-shot OAuth flow attempt; `run` consumes `self`.
pub struct OAuthFlow {
    backend: BackendId,
    connection_id: Option<ConnectionId>,
    kind: FlowKind,
    endpoints: Option<OAuthEndpoints>,
    http: Option<reqwest::Client>,
}

enum FlowKind {
    Pkce { redirect_base: Url },
    Device,
}

impl OAuthFlow {
    /// `redirect_base` is typically `http://127.0.0.1`; the listener
    /// picks a free port and appends it before emitting `OpenBrowser`.
    pub fn pkce(backend: BackendId, redirect_base: Url) -> Self {
        Self {
            backend,
            connection_id: None,
            kind: FlowKind::Pkce { redirect_base },
            endpoints: None,
            http: None,
        }
    }

    pub fn device(backend: BackendId) -> Self {
        Self {
            backend,
            connection_id: None,
            kind: FlowKind::Device,
            endpoints: None,
            http: None,
        }
    }

    /// Threaded into the terminal `AuthEvent::Succeeded { connection }`.
    pub fn with_connection(mut self, id: ConnectionId) -> Self {
        self.connection_id = Some(id);
        self
    }

    pub fn is_device(&self) -> bool {
        matches!(self.kind, FlowKind::Device)
    }

    pub fn is_pkce(&self) -> bool {
        matches!(self.kind, FlowKind::Pkce { .. })
    }

    /// Required before `run`; otherwise `run` returns `Setup`.
    pub fn with_endpoints(mut self, endpoints: OAuthEndpoints) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// Defaults to a fresh [`reqwest::Client`].
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = Some(client);
        self
    }

    /// Stream emits progress events and one terminal event
    /// (`Succeeded` / `Failed` / `Cancelled`).
    ///
    /// # Errors
    ///
    /// [`AuthError::Setup`], before any event is emitted:
    /// [`ErrorCode::NotConfigured`] when [`OAuthFlow::with_endpoints`]
    /// was never called, or [`ErrorCode::Internal`] when the PKCE
    /// loopback listener cannot bind or `redirect_base` cannot carry a
    /// port. Terminal flow failures (token exchange refused,
    /// device-code expired) surface as `AuthEvent::Failed` inside the
    /// stream instead.
    pub async fn run(self) -> Result<BoxStream<'static, Result<AuthEvent, Error>>, AuthError> {
        let endpoints = self.endpoints.ok_or_else(|| {
            AuthError::Setup(Error::new(
                ErrorCode::NotConfigured,
                "OAuthFlow: endpoints not supplied (call OAuthFlow::with_endpoints)",
            ))
        })?;
        let http = self.http.unwrap_or_default();
        let backend = self.backend;
        let connection_id = self.connection_id;
        match self.kind {
            FlowKind::Pkce { redirect_base } => {
                run_pkce(backend, connection_id, endpoints, http, redirect_base).await
            }
            FlowKind::Device => run_device(backend, connection_id, endpoints, http).await,
        }
    }
}

/// Token-endpoint response common to both flows. `access_token` and
/// `refresh_token` are deserialised for structural validation; only
/// `expires_in` is read directly by this module.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// RFC 8628 §3.2.
#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_device_interval")]
    interval: u64,
}

fn default_device_interval() -> u64 {
    5
}

/// RFC 6749 §5.2 / RFC 8628 §3.5; only `error` drives the polling
/// decision.
#[derive(Debug, Deserialize)]
struct TokenError {
    error: String,
}

async fn run_pkce(
    backend: BackendId,
    connection_id: Option<ConnectionId>,
    endpoints: OAuthEndpoints,
    http: reqwest::Client,
    redirect_base: Url,
) -> Result<BoxStream<'static, Result<AuthEvent, Error>>, AuthError> {
    // Bind first so the redirect URI carries the chosen port.
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|err| {
            AuthError::Setup(Error::new(
                ErrorCode::Internal,
                format!("OAuthFlow::pkce: bind failed: {err}"),
            ))
        })?;
    let local_addr = listener.local_addr().map_err(|err| {
        AuthError::Setup(Error::new(
            ErrorCode::Internal,
            format!("OAuthFlow::pkce: local_addr failed: {err}"),
        ))
    })?;
    // `redirect_base` carries the path the IDP app is registered with;
    // bare hosts (path = `/`) fall back to `/callback` for back-compat.
    let mut redirect_url = redirect_base.clone();
    redirect_url
        .set_port(Some(local_addr.port()))
        .map_err(|()| {
            AuthError::Setup(Error::new(
                ErrorCode::Internal,
                format!("OAuthFlow::pkce: redirect_base does not accept a port: {redirect_base}"),
            ))
        })?;
    if redirect_url.path() == "/" {
        redirect_url.set_path("/callback");
    }
    let redirect_uri = redirect_url.to_string();
    let pkce_material = pkce::generate();
    let state_token = random_state();
    let mut authorize_url = endpoints.authorization_endpoint.clone();
    {
        let mut q = authorize_url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &endpoints.client_id);
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("code_challenge", &pkce_material.challenge);
        q.append_pair("code_challenge_method", pkce_material.challenge_method);
        q.append_pair("state", &state_token);
        q.append_pair("scope", endpoints.scope.as_deref().unwrap_or("openid"));
    }
    let expires_at = SystemTime::now() + Duration::from_secs(300);
    let stream = async_stream::try_stream! {
        yield AuthEvent::OpenBrowser {
            url: authorize_url.to_string(),
            expires_at,
        };
        yield AuthEvent::Progress {
            message: "waiting for authorisation-code redirect".into(),
        };
        let captured = match accept_redirect(
            listener,
            &state_token,
            endpoints.authorization_endpoint.host_str(),
        ).await {
            Ok(code) => code,
            Err(err) => {
                yield AuthEvent::Failed { error: err.clone() };
                return;
            }
        };
        yield AuthEvent::Progress {
            message: "exchanging code for tokens".into(),
        };
        let token = match exchange_code(
            &http,
            &endpoints,
            &captured,
            &pkce_material.verifier,
            &redirect_uri,
        )
        .await
        {
            Ok(t) => t,
            Err(err) => {
                yield AuthEvent::Failed { error: err };
                return;
            }
        };
        let token_expires_at = match checked_token_expiry(token.expires_in) {
            Ok(expires_at) => expires_at,
            Err(error) => {
                yield AuthEvent::Failed { error };
                return;
            }
        };
        let connection = build_succeeded_connection(
            &backend,
            connection_id.as_ref(),
            token_expires_at,
        );
        let credentials = credentials_from_token(&token, token_expires_at);
        yield AuthEvent::Succeeded {
            connection: Box::new(connection),
            credentials: Some(credentials),
        };
    };
    Ok(stream.boxed())
}

async fn run_device(
    backend: BackendId,
    connection_id: Option<ConnectionId>,
    endpoints: OAuthEndpoints,
    http: reqwest::Client,
) -> Result<BoxStream<'static, Result<AuthEvent, Error>>, AuthError> {
    let stream = async_stream::try_stream! {
        // `authorization_endpoint` is overloaded — for device flow it
        // points at the IDP's `device_authorization_endpoint`.
        let device = match request_device_code(&http, &endpoints).await {
            Ok(d) => d,
            Err(err) => {
                yield AuthEvent::Failed { error: err };
                return;
            }
        };
        let expires_at = match checked_token_expiry(Some(device.expires_in)) {
            Ok(Some(expires_at)) => expires_at,
            Ok(None) => unreachable!("device expires_in is always present"),
            Err(error) => {
                yield AuthEvent::Failed { error };
                return;
            }
        };
        yield AuthEvent::DeviceCode {
            user_code: device.user_code.clone(),
            verification_url: device
                .verification_uri_complete
                .clone()
                .unwrap_or_else(|| device.verification_uri.clone()),
            expires_at,
            interval: Duration::from_secs(device.interval),
        };
        let mut interval = Duration::from_secs(device.interval.max(1));
        loop {
            tokio::time::sleep(interval).await;
            if SystemTime::now() >= expires_at {
                yield AuthEvent::Failed {
                    error: Error::new(
                        ErrorCode::AuthExpired,
                        "OAuthFlow::device: device code expired",
                    ),
                };
                return;
            }
            yield AuthEvent::Progress {
                message: "polling token endpoint".into(),
            };
            match poll_device_token(&http, &endpoints, &device.device_code).await {
                Ok(token) => {
                    let token_expires_at = match checked_token_expiry(token.expires_in) {
                        Ok(expires_at) => expires_at,
                        Err(error) => {
                            yield AuthEvent::Failed { error };
                            return;
                        }
                    };
                    let connection = build_succeeded_connection(
                        &backend,
                        connection_id.as_ref(),
                        token_expires_at,
                    );
                    let credentials = credentials_from_token(&token, token_expires_at);
                    yield AuthEvent::Succeeded {
                        connection: Box::new(connection),
                        credentials: Some(credentials),
                    };
                    return;
                }
                Err(DevicePollError::Pending) => continue,
                Err(DevicePollError::SlowDown) => {
                    interval = interval.saturating_add(Duration::from_secs(5));
                    continue;
                }
                Err(DevicePollError::Terminal(err)) => {
                    yield AuthEvent::Failed { error: err };
                    return;
                }
            }
        }
    };
    Ok(stream.boxed())
}

async fn accept_redirect(
    listener: TcpListener,
    expected_state: &str,
    idp_host: Option<&str>,
) -> Result<String, Error> {
    let (mut socket, _peer) = listener.accept().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("OAuthFlow::pkce: accept failed: {err}"),
        )
    })?;
    let mut buf = vec![0u8; 8192];
    let mut total = 0usize;
    // Read until \r\n\r\n header terminator or the cap.
    loop {
        if total >= buf.len() {
            break;
        }
        let n = socket.read(&mut buf[total..]).await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("OAuthFlow::pkce: read failed: {err}"),
            )
        })?;
        if n == 0 {
            break;
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&buf[..total]);
    let request_line = request.lines().next().unwrap_or("");
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let cb = parse_callback_query(path);
    let response_body = if cb.code.is_some() && cb.state.as_deref() == Some(expected_state) {
        render_success_page(idp_host)
    } else {
        render_error_page(cb.error.as_deref(), cb.error_description.as_deref())
    };
    let _ = socket.write_all(&response_body).await;
    let _ = socket.shutdown().await;
    let code = match cb.code {
        Some(code) => code,
        None => {
            let msg = match (cb.error.as_deref(), cb.error_description.as_deref()) {
                (Some(e), Some(d)) if !d.is_empty() => {
                    format!("OAuthFlow::pkce: redirect returned IDP error '{e}': {d}")
                }
                (Some(e), _) => format!("OAuthFlow::pkce: redirect returned IDP error '{e}'"),
                _ => "OAuthFlow::pkce: redirect missing 'code' parameter".to_string(),
            };
            return Err(Error::new(ErrorCode::AuthRequired, msg));
        }
    };
    if cb.state.as_deref() != Some(expected_state) {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "OAuthFlow::pkce: redirect 'state' mismatch (CSRF guard)",
        ));
    }
    Ok(code)
}

#[derive(Default)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_callback_query(path: &str) -> CallbackQuery {
    let query = path.split_once('?').map(|x| x.1).unwrap_or("");
    let mut out = CallbackQuery::default();
    for pair in query.split('&') {
        let mut it = pair.splitn(2, '=');
        let key = it.next().unwrap_or("");
        let value = it.next().unwrap_or("");
        let decoded = url::form_urlencoded::parse(format!("k={value}").as_bytes())
            .next()
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| value.to_string());
        match key {
            "code" => out.code = Some(decoded),
            "state" => out.state = Some(decoded),
            "error" => out.error = Some(decoded),
            "error_description" => out.error_description = Some(decoded),
            _ => {}
        }
    }
    out
}

const SUCCESS_HTML_TEMPLATE: &str = include_str!("flow/callback_success.html");
const ERROR_HTML_TEMPLATE: &str = include_str!("flow/callback_error.html");

fn render_success_page(idp_host: Option<&str>) -> Vec<u8> {
    let host_line = match idp_host {
        Some(host) if !host.is_empty() => format!(
            "<p>Signed in via <span class=\"host\">{}</span>.</p>",
            html_escape(host)
        ),
        _ => String::new(),
    };
    let body = SUCCESS_HTML_TEMPLATE.replace("{{idp_host_line}}", &host_line);
    http_response(200, "OK", &body)
}

fn render_error_page(error: Option<&str>, description: Option<&str>) -> Vec<u8> {
    let detail = match (error, description) {
        (Some(e), Some(d)) if !e.is_empty() && !d.is_empty() => {
            format!("{}: {}", html_escape(e), html_escape(d))
        }
        (Some(e), _) if !e.is_empty() => html_escape(e),
        (_, Some(d)) if !d.is_empty() => html_escape(d),
        _ => "The authorization response didn't include a valid code or state.".to_string(),
    };
    let body = ERROR_HTML_TEMPLATE.replace("{{error_detail}}", &detail);
    http_response(400, "Bad Request", &body)
}

fn http_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    )
    .into_bytes()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

async fn exchange_code(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<TokenResponse, Error> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", endpoints.client_id.as_str()),
        ("code_verifier", verifier),
        ("redirect_uri", redirect_uri),
    ];
    let response = http
        .post(endpoints.token_endpoint.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("OAuthFlow::pkce: token POST failed: {err}"),
            )
        })?;
    let status = response.status();
    let body = read_oauth_response_body(response, "OAuthFlow::pkce: token").await?;
    if !status.is_success() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            format!(
                "OAuthFlow::pkce: token endpoint returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        ));
    }
    serde_json::from_slice::<TokenResponse>(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("OAuthFlow::pkce: token JSON parse failed: {err}"),
        )
    })
}

async fn request_device_code(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
) -> Result<DeviceAuthorizationResponse, Error> {
    let form = [
        ("client_id", endpoints.client_id.as_str()),
        ("scope", endpoints.scope.as_deref().unwrap_or("openid")),
    ];
    let response = http
        .post(endpoints.authorization_endpoint.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("OAuthFlow::device: device-auth POST failed: {err}"),
            )
        })?;
    let status = response.status();
    let body = read_oauth_response_body(response, "OAuthFlow::device: device-auth").await?;
    if !status.is_success() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            format!(
                "OAuthFlow::device: device-auth returned HTTP {}: {}",
                status.as_u16(),
                ovstorage_plugin::provider_error::oauth_error_detail(&body)
            ),
        ));
    }
    serde_json::from_slice::<DeviceAuthorizationResponse>(&body).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("OAuthFlow::device: device-auth JSON parse failed: {err}"),
        )
    })
}

enum DevicePollError {
    /// `authorization_pending` — keep polling at the same interval.
    Pending,
    /// `slow_down` — bump the interval per RFC 8628 §3.5.
    SlowDown,
    /// Do not retry.
    Terminal(Error),
}

/// What a terminal RFC 8628 device-poll rejection reports.
///
/// `TokenError::error` is a free string on the wire, so it goes through the
/// same grammar check as every other reported provider code rather than being
/// interpolated because it happened to deserialize. This arm is the one a
/// conforming rejection takes — `serde_json` parses `{"error":…}` before the
/// status-keyed arm below it is reached — so it is the device flow's ordinary
/// failure message, not an edge case.
fn device_poll_error_message(error: &str) -> String {
    match ovstorage_plugin::provider_error::validate_code_token(error.as_bytes()) {
        Some(code) => format!("OAuthFlow::device: token endpoint returned '{code}'"),
        None => format!(
            "OAuthFlow::device: token endpoint returned a {} byte error field \
             that is not a code token",
            error.len()
        ),
    }
}

async fn poll_device_token(
    http: &reqwest::Client,
    endpoints: &OAuthEndpoints,
    device_code: &str,
) -> Result<TokenResponse, DevicePollError> {
    let form = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device_code),
        ("client_id", endpoints.client_id.as_str()),
    ];
    let response = http
        .post(endpoints.token_endpoint.as_str())
        .form(&form)
        .send()
        .await
        .map_err(|err| {
            DevicePollError::Terminal(Error::new(
                ErrorCode::Transient,
                format!("OAuthFlow::device: poll POST failed: {err}"),
            ))
        })?;
    let status = response.status();
    let body = read_oauth_response_body(response, "OAuthFlow::device: poll")
        .await
        .map_err(DevicePollError::Terminal)?;
    if status.is_success() {
        return serde_json::from_slice::<TokenResponse>(&body).map_err(|err| {
            DevicePollError::Terminal(Error::new(
                ErrorCode::Internal,
                format!("OAuthFlow::device: poll JSON parse failed: {err}"),
            ))
        });
    }
    // RFC 8628 §3.5: `authorization_pending` and `slow_down` are soft;
    // everything else terminal.
    if let Ok(parsed) = serde_json::from_slice::<TokenError>(&body) {
        return match parsed.error.as_str() {
            "authorization_pending" => Err(DevicePollError::Pending),
            "slow_down" => Err(DevicePollError::SlowDown),
            "expired_token" => Err(DevicePollError::Terminal(Error::new(
                ErrorCode::AuthExpired,
                "OAuthFlow::device: device code expired (IDP)",
            ))),
            other => Err(DevicePollError::Terminal(Error::new(
                ErrorCode::AuthRequired,
                device_poll_error_message(other),
            ))),
        };
    }
    Err(DevicePollError::Terminal(Error::new(
        ErrorCode::AuthRequired,
        format!(
            "OAuthFlow::device: token endpoint returned HTTP {}: {}",
            status.as_u16(),
            ovstorage_plugin::provider_error::oauth_error_detail(&body)
        ),
    )))
}

fn checked_token_expiry(expires_in: Option<u64>) -> Result<Option<SystemTime>, Error> {
    expires_in
        .map(|seconds| {
            SystemTime::now()
                .checked_add(Duration::from_secs(seconds))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::CredentialUnavailable,
                        "OAuth token expires_in is out of range",
                    )
                })
        })
        .transpose()
}

fn credentials_from_token(
    token: &TokenResponse,
    expires_at: Option<SystemTime>,
) -> ovstorage_plugin::SecretBundle {
    use ovstorage_plugin::{SecretBundle, SecretBytes, SecretValue};
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(token.access_token.clone().into_bytes()),
            refresh: token
                .refresh_token
                .as_ref()
                .map(|r| SecretBytes(r.clone().into_bytes())),
            expires_at,
        },
    );
    bundle
}

fn build_succeeded_connection(
    backend: &BackendId,
    connection_id: Option<&ConnectionId>,
    expires_at: Option<SystemTime>,
) -> Connection {
    let now = SystemTime::now();
    Connection {
        id: connection_id
            .cloned()
            .unwrap_or_else(|| ConnectionId(format!("oauth-{}", backend.0))),
        backend_kind: backend.0.clone(),
        display_name: format!("oauth({})", backend.0),
        source: ovstorage_plugin::ConnectionSource::Runtime { persisted: false },
        capabilities: ovstorage_plugin::Capabilities::empty(),
        current_addresses: Vec::new(),
        auth_state: ConnectionAuthState::Authenticated {
            last_authenticated_at: now,
            expires_at,
        },
        last_probed: None,
        user_metadata: std::collections::HashMap::new(),
    }
}

fn random_state() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Convenience bundle of HTTP client + endpoints.
#[derive(Clone)]
pub struct FlowContext {
    pub endpoints: OAuthEndpoints,
    pub http: Arc<reqwest::Client>,
}

/// Test fixtures gated behind `test-support` so production builds
/// don't carry the fake-IdP HTTP server.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::oneshot;

    /// In-process fake IDP serving `/.well-known/openid-configuration`,
    /// `/authorize`, `/token`, `/device_authorization` on a random
    /// loopback port.
    pub struct FakeIdp {
        pub base_url: String,
        pub client_id: String,
        pub poll_attempts_before_grant: Arc<AtomicU32>,
        /// Number of refresh-token grants received by the fake token endpoint.
        pub refresh_grant_attempts: Arc<AtomicU32>,
        /// Override before driving the flow for non-default tokens.
        pub access_token: Arc<std::sync::Mutex<String>>,
        _shutdown: oneshot::Sender<()>,
    }

    impl FakeIdp {
        pub async fn start() -> Self {
            Self::start_with_token("test-access").await
        }

        pub async fn start_with_token(token: impl Into<String>) -> Self {
            Self::start_with_device_grant(token, Some(1), 60, false).await
        }

        /// Start an IdP whose refresh token can be redeemed only once.
        pub async fn start_with_single_use_refresh_token(token: impl Into<String>) -> Self {
            Self::start_with_device_grant(token, Some(1), 60, true).await
        }

        /// Start an IdP whose device-token endpoint remains
        /// `authorization_pending` for the lifetime of a one-hour device code.
        /// A shorter cancellation-test deadline can therefore observe permit
        /// release only from teardown, never from a natural grant.
        pub async fn start_with_pending_device_flow(token: impl Into<String>) -> Self {
            Self::start_with_device_grant(token, None, 3_600, false).await
        }

        async fn start_with_device_grant(
            token: impl Into<String>,
            polls_before_grant: Option<u32>,
            device_expires_in: u64,
            single_use_refresh: bool,
        ) -> Self {
            let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let (tx, mut rx) = oneshot::channel::<()>();
            let attempts = Arc::new(AtomicU32::new(0));
            let attempts_for_task = Arc::clone(&attempts);
            let refresh_attempts = Arc::new(AtomicU32::new(0));
            let refresh_attempts_for_task = Arc::clone(&refresh_attempts);
            let access_token = Arc::new(std::sync::Mutex::new(token.into()));
            let access_for_task = Arc::clone(&access_token);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut rx => break,
                        accept = listener.accept() => {
                            if let Ok((sock, _)) = accept {
                                let attempts = Arc::clone(&attempts_for_task);
                                let refresh_attempts = Arc::clone(&refresh_attempts_for_task);
                                let token = access_for_task.lock().unwrap().clone();
                                tokio::spawn(handle_idp_request(
                                    sock,
                                    attempts,
                                    refresh_attempts,
                                    token,
                                    polls_before_grant,
                                    device_expires_in,
                                    single_use_refresh,
                                ));
                            }
                        }
                    }
                }
            });
            Self {
                base_url: base,
                client_id: "test-client".into(),
                poll_attempts_before_grant: attempts,
                refresh_grant_attempts: refresh_attempts,
                access_token,
                _shutdown: tx,
            }
        }

        pub fn endpoints(&self, device: bool) -> OAuthEndpoints {
            let auth_endpoint = if device {
                format!("{}/device_authorization", self.base_url)
            } else {
                format!("{}/authorize", self.base_url)
            };
            OAuthEndpoints {
                authorization_endpoint: Url::parse(&auth_endpoint).unwrap(),
                token_endpoint: Url::parse(&format!("{}/token", self.base_url)).unwrap(),
                client_id: self.client_id.clone(),
                scope: Some("openid".into()),
            }
        }
    }

    async fn handle_idp_request(
        mut sock: tokio::net::TcpStream,
        attempts: Arc<AtomicU32>,
        refresh_attempts: Arc<AtomicU32>,
        access_token: String,
        polls_before_grant: Option<u32>,
        device_expires_in: u64,
        single_use_refresh: bool,
    ) {
        let mut buf = vec![0u8; 8192];
        let mut total = 0usize;
        loop {
            if total >= buf.len() {
                break;
            }
            let n = match sock.read(&mut buf[total..]).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => return,
            };
            total += n;
            if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buf[..total]).into_owned();
        let line = request.lines().next().unwrap_or("");
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");
        let (status, body): (u16, String) = if path.starts_with("/.well-known/openid-configuration")
        {
            (200, "{\"issuer\":\"http://fake\"}".into())
        } else if path.starts_with("/authorize") {
            // PKCE test drives the redirect directly; stub here.
            (200, "stub".into())
        } else if path.starts_with("/device_authorization") && method == "POST" {
            (
                200,
                serde_json::json!({
                    "device_code": "fake-device-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "http://example.com/device",
                    "expires_in": device_expires_in,
                    "interval": 1,
                })
                .to_string(),
            )
        } else if path.starts_with("/token") && method == "POST" {
            // Body is the form payload after \r\n\r\n.
            let body_start = request
                .find("\r\n\r\n")
                .map(|i| i + 4)
                .unwrap_or(request.len());
            let form_body = &request[body_start..];
            if form_body
                .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
                || form_body.contains("device_code=")
            {
                let prior = attempts.fetch_add(1, Ordering::SeqCst);
                if polls_before_grant.is_none_or(|required| prior < required) {
                    (
                        400,
                        serde_json::json!({"error":"authorization_pending"}).to_string(),
                    )
                } else {
                    (
                        200,
                        serde_json::json!({
                            "access_token": access_token,
                            "refresh_token":"device-refresh",
                            "expires_in":3600,
                        })
                        .to_string(),
                    )
                }
            } else if form_body.contains("grant_type=refresh_token") {
                let prior = refresh_attempts.fetch_add(1, Ordering::SeqCst);
                if single_use_refresh && prior > 0 {
                    (
                        400,
                        serde_json::json!({"error":"invalid_grant"}).to_string(),
                    )
                } else {
                    (
                        200,
                        serde_json::json!({
                            "access_token": access_token,
                            "refresh_token":"rotated-device-refresh",
                            "expires_in":3600,
                        })
                        .to_string(),
                    )
                }
            } else {
                (
                    200,
                    serde_json::json!({
                        "access_token": access_token,
                        "refresh_token":"pkce-refresh",
                        "expires_in":3600,
                    })
                    .to_string(),
                )
            }
        } else {
            (404, "{}".into())
        };
        let response = format!(
            "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            status,
            body.len(),
            body
        );
        let _ = sock.write_all(response.as_bytes()).await;
        let _ = sock.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeIdp;
    use super::*;
    use futures::StreamExt;

    async fn oversized_chunked_endpoint() -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            Url::parse(&format!("http://{}/oauth", listener.local_addr().unwrap())).unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            let oversized = vec![b'x'; MAX_OAUTH_RESPONSE_BODY_BYTES + 1];
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
                oversized.len()
            );
            let _ = socket.write_all(headers.as_bytes()).await;
            let _ = socket.write_all(&oversized).await;
            let _ = socket.write_all(b"\r\n0\r\n\r\n").await;
            let _ = socket.shutdown().await;
        });
        endpoint
    }

    #[test]
    fn token_expiry_rejects_unrepresentable_idp_values() {
        let error = checked_token_expiry(Some(u64::MAX)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
    }

    #[tokio::test]
    async fn device_authorization_rejects_an_oversized_streamed_response() {
        let authorization_endpoint = oversized_chunked_endpoint().await;
        let endpoints = OAuthEndpoints {
            authorization_endpoint,
            token_endpoint: Url::parse("https://idp.example/token").unwrap(),
            client_id: "test-client".into(),
            scope: Some("openid".into()),
        };
        let http = reqwest::Client::builder().no_proxy().build().unwrap();

        let error = request_device_code(&http, &endpoints)
            .await
            .expect_err("an OAuth response beyond the body cap must be rejected");

        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert!(
            error
                .message()
                .contains(&MAX_OAUTH_RESPONSE_BODY_BYTES.to_string())
        );
    }

    /// A conforming rejection still names its code, so an operator keeps the
    /// only usable diagnostic.
    #[test]
    fn a_device_poll_rejection_reports_a_clean_code_verbatim() {
        assert_eq!(
            device_poll_error_message("invalid_grant"),
            "OAuthFlow::device: token endpoint returned 'invalid_grant'"
        );
    }

    /// `TokenError::error` is a free string on the wire, and this arm is the
    /// device flow's ordinary failure path — a conforming `{"error":…}` body
    /// parses here rather than falling through to the status-keyed arm. So an
    /// IDP or an intermediary putting a credential in that field must not have
    /// it interpolated.
    ///
    /// The load-bearing assertion is the absence of `eyJleaked`: replacing
    /// `device_poll_error_message`'s body with
    /// `format!("OAuthFlow::device: token endpoint returned '{error}'")`
    /// reddens it. The length assertion pins that the operator is told
    /// something rather than nothing.
    #[test]
    fn a_device_poll_error_field_that_is_not_a_code_token_is_suppressed() {
        let message = device_poll_error_message("Bearer eyJleaked; rejected for tenant");
        assert!(!message.contains("eyJleaked"), "{message}");
        assert!(message.contains("37 byte error field"), "{message}");
    }

    #[tokio::test]
    async fn device_flow_polls_until_token() {
        let idp = FakeIdp::start().await;
        let flow = OAuthFlow::device(BackendId("test".into())).with_endpoints(idp.endpoints(true));
        let mut stream = flow.run().await.unwrap();
        let mut saw_device_code = false;
        let mut saw_progress = false;
        let mut saw_succeeded = false;
        while let Some(event) = stream.next().await {
            match event.unwrap() {
                AuthEvent::DeviceCode { user_code, .. } => {
                    saw_device_code = true;
                    assert_eq!(user_code, "ABCD-EFGH");
                }
                AuthEvent::Progress { .. } => saw_progress = true,
                AuthEvent::Succeeded { .. } => {
                    saw_succeeded = true;
                    break;
                }
                AuthEvent::Failed { error } => panic!("unexpected fail: {}", error.message()),
                _ => {}
            }
        }
        assert!(saw_device_code, "device flow must emit DeviceCode");
        assert!(saw_progress, "device flow must emit Progress");
        assert!(saw_succeeded, "device flow must reach Succeeded");
    }

    #[tokio::test]
    async fn pkce_flow_round_trips_with_loopback_listener() {
        let idp = FakeIdp::start().await;
        let flow = OAuthFlow::pkce(
            BackendId("test".into()),
            Url::parse("http://127.0.0.1").unwrap(),
        )
        .with_endpoints(idp.endpoints(false));
        let mut stream = flow.run().await.unwrap();
        let first = stream.next().await.unwrap().unwrap();
        let (browser_url, _expires) = match first {
            AuthEvent::OpenBrowser { url, expires_at } => (url, expires_at),
            other => panic!("expected OpenBrowser, got {other:?}"),
        };
        let parsed = Url::parse(&browser_url).unwrap();
        let mut redirect_uri = String::new();
        let mut state = String::new();
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "redirect_uri" => redirect_uri = value.into_owned(),
                "state" => state = value.into_owned(),
                _ => {}
            }
        }
        let redirect_url = format!("{redirect_uri}?code=fake-code&state={state}");
        tokio::spawn(async move {
            let _ = reqwest::get(&redirect_url).await;
        });
        let mut saw_succeeded = false;
        while let Some(event) = stream.next().await {
            match event.unwrap() {
                AuthEvent::Succeeded { .. } => {
                    saw_succeeded = true;
                    break;
                }
                AuthEvent::Failed { error } => panic!("unexpected fail: {}", error.message()),
                _ => {}
            }
        }
        assert!(saw_succeeded, "pkce flow must reach Succeeded");
    }

    #[tokio::test]
    async fn run_without_endpoints_returns_setup_error() {
        let flow = OAuthFlow::pkce(
            BackendId("x".into()),
            Url::parse("http://127.0.0.1").unwrap(),
        );
        let err = flow.run().await.err().expect("missing endpoints must fail");
        assert!(matches!(err, AuthError::Setup(_)));
    }
}
