// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nucleus auth handshake.
//!
//! Multi-leg flow:
//! 1. SOWS-connect to discovery (`{ws,wss}://{server}/omni/discovery`).
//! 2. `DiscoverySearch::find` for the `Tokens` and `Connection` interfaces.
//! 3. SOWS-connect to `Tokens`; exchange credentials for a session `Auth` envelope.
//! 4. ConnLib-connect to `Connection`; `authorize_token` with the access_token to land
//!    `connection_id`, `lft_address`, `lft_threshold`, and session tokens.
//! 5. Build `LftClient` from that `Auth` and wrap the ConnLib transport in `RuntimeOps`.
//!
//! Three entry points: `establish_api_token`, `establish_username_password`,
//! `establish_interactive_auth`. All converge on `complete_session`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Context;

use nucleus_auth::flow::{DEFAULT_POLL_INTERVAL, start_interactive};
use nucleus_auth::generated::{Credentials, Tokens};
use nucleus_auth::types::{Auth as TokensAuth, AuthStatus};
use nucleus_client::LftClient;
use nucleus_client::types::{Auth as ConnectionAuth, StatusType};
use nucleus_discovery::types::{SearchResult, TransportSettings};
use nucleus_discovery::{
    discovery_url, generated::DiscoverySearch, make_query, supported_transports, url_from_transport,
};
use nucleus_transport::{ConnLibTransport, SowsTransport, Subscription};
use ovstorage_plugin::{
    AuthEvent, CancellationToken, ConnectionId, Error, ErrorCode, ErrorContext, Result,
    SecretBundle, SecretValue,
};

use crate::address::NUCLEUS_KIND;
use crate::config::NucleusConfig;
use crate::ops::{NucleusOps, RuntimeOps};

use nucleus_client::generated::Connection;

/// State installed into `NucleusShared` after a successful handshake.
pub(crate) struct HandshakeOutput {
    pub ops: Arc<dyn NucleusOps>,
    pub lft: Option<Arc<LftClient>>,
    pub session: NucleusSession,
}

/// Refresh-relevant state cached so refresh can avoid re-running discovery.
/// The ConnLib transport is short-lived: every refresh tears down the previous
/// `RuntimeOps`/ConnLib socket and authorizes a fresh one against the new access token.
#[derive(Clone)]
pub(crate) struct NucleusSession {
    #[allow(dead_code)]
    pub access_token: String,
    /// `None` on the api-token branch when the server returns no refresh_token;
    /// in that case refresh falls back to re-`auth_with_api_token`.
    pub refresh_token: Option<String>,
    /// SOWS URL for `Tokens`, cached from discovery (stable per deployment).
    pub tokens_url: String,
    pub principal: String,
}

/// Terminal outcome of `poll_interactive_outcome`.
pub(crate) enum InteractiveOutcome {
    /// Server published `Auth { status: OK, ... }`.
    Authenticated(TokensAuth),
    /// Server explicitly denied (Denied / Disabled / InvalidUsername / InvalidToken / etc.).
    Denied {
        status: AuthStatus,
        reason: &'static str,
    },
    /// `expires_at` reached before a terminal frame.
    Expired,
    /// Host dropped the stream or cancellation token fired.
    Cancelled,
    /// Transport-level error during polling (websocket close, JSON decode, etc.).
    TransportError(anyhow::Error),
}

/// Drive the Nucleus URL+nonce-poll handshake.
///
/// Discovers `Credentials` + `Tokens`, calls `start_interactive` for
/// `(login_url, nonce, subscription)`, emits `OpenBrowser` + `Progress`,
/// then polls until terminal `Auth { status: OK, ... }`, denial, timeout,
/// or cancellation.
///
/// Events are pushed through `tx` as they are produced (so the host can
/// surface the URL the moment it's known instead of waiting for the
/// minutes-long sign-in poll to terminate). The returned
/// `Option<HandshakeOutput>` is the session state to install in
/// `NucleusShared` on success.
pub(crate) async fn establish_interactive_auth(
    config: &NucleusConfig,
    connection: ovstorage_plugin::Connection,
    cancel: Option<CancellationToken>,
    tx: std::sync::mpsc::Sender<Result<AuthEvent>>,
) -> Option<HandshakeOutput> {
    let span =
        tracing::info_span!("nucleus.handshake", plugin = "nucleus", server = %config.server);
    let _guard = span.enter();
    tracing::debug!("starting interactive auth handshake");

    let push = |evt: Result<AuthEvent>| {
        let _ = tx.send(evt);
    };

    push(Ok(AuthEvent::Progress {
        message: "Discovering Nucleus auth endpoints".into(),
    }));

    let endpoints = match discover_auth_endpoints(config).await {
        Ok(endpoints) => endpoints,
        Err(error) => {
            push(Ok(AuthEvent::Failed {
                error: error.with_context(ErrorContext::Auth {
                    connection_id: connection.id.clone(),
                    reason: Some("interactive_discovery_failed".into()),
                    expired_at: None,
                }),
            }));
            return None;
        }
    };

    let login_url = match endpoints.login_url.clone() {
        Some(url) => url,
        None => {
            push(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::Unsupported,
                    "Nucleus discovery did not advertise an SSO login URL (meta.login_url missing)",
                )
                .with_context(ErrorContext::Auth {
                    connection_id: connection.id.clone(),
                    reason: Some("no_login_url".into()),
                    expired_at: None,
                }),
            }));
            return None;
        }
    };
    let tokens_transport = match SowsTransport::connect(&endpoints.tokens_url).await {
        Ok(transport) => transport,
        Err(err) => {
            push(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::Transient,
                    format!(
                        "Nucleus Tokens connect failed ({}): {err:#}",
                        endpoints.tokens_url
                    ),
                )
                .with_context(ErrorContext::Auth {
                    connection_id: connection.id.clone(),
                    reason: Some("tokens_connect_failed".into()),
                    expired_at: None,
                }),
            }));
            return None;
        }
    };

    let started = match start_interactive(&tokens_transport, &login_url, &config.server).await {
        Ok(s) => s,
        Err(err) => {
            push(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::Transient,
                    format!("Nucleus interactive auth handshake start failed: {err:#}"),
                )
                .with_context(ErrorContext::Auth {
                    connection_id: connection.id.clone(),
                    reason: Some("interactive_start_failed".into()),
                    expired_at: None,
                }),
            }));
            return None;
        }
    };

    push(Ok(AuthEvent::OpenBrowser {
        url: started.auth_url,
        expires_at: started.expires_at,
    }));
    push(Ok(AuthEvent::Progress {
        message: "Waiting for Nucleus sign-in".into(),
    }));

    tracing::debug!("browser auth URL issued, polling for sign-in");
    let outcome = poll_interactive_outcome(
        started.subscription,
        started.expires_at,
        DEFAULT_POLL_INTERVAL,
        cancel,
    )
    .await;

    match outcome {
        InteractiveOutcome::Authenticated(tokens_auth) => {
            tracing::debug!("interactive sign-in completed, establishing session");
            match complete_session(
                config,
                endpoints.tokens_url,
                &endpoints.connection_url,
                tokens_auth,
            )
            .await
            {
                Ok(output) => {
                    tracing::info!("nucleus interactive auth succeeded");
                    push(Ok(AuthEvent::Succeeded {
                        connection: Box::new(connection),
                        credentials: None,
                    }));
                    Some(output)
                }
                Err(error) => {
                    tracing::warn!(error.code = ?error.code(), "nucleus interactive auth session setup failed");
                    push(Ok(AuthEvent::Failed { error }));
                    None
                }
            }
        }
        InteractiveOutcome::Denied { status, reason } => {
            tracing::warn!(%reason, status = ?status, "nucleus interactive auth denied");
            push(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::AuthRequired,
                    format!("Nucleus sign-in denied (status={status:?})"),
                )
                .with_context(ErrorContext::Auth {
                    connection_id: connection.id,
                    reason: Some(reason.into()),
                    expired_at: None,
                }),
            }));
            None
        }
        InteractiveOutcome::Expired => {
            tracing::warn!("nucleus interactive auth URL expired before sign-in completed");
            push(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::AuthExpired,
                    "Nucleus sign-in URL expired before user completed sign-in",
                )
                .with_context(ErrorContext::Auth {
                    connection_id: connection.id,
                    reason: Some("interactive_url_expired".into()),
                    expired_at: Some(started.expires_at),
                }),
            }));
            None
        }
        InteractiveOutcome::Cancelled => {
            tracing::debug!("nucleus interactive auth cancelled by host");
            push(Ok(AuthEvent::Cancelled));
            None
        }
        InteractiveOutcome::TransportError(err) => {
            tracing::warn!(err = %err, "nucleus interactive auth transport error during polling");
            push(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::Transient,
                    format!("Nucleus subscription error during polling: {err:#}"),
                )
                .with_context(ErrorContext::Auth {
                    connection_id: connection.id,
                    reason: Some("interactive_poll_failed".into()),
                    expired_at: None,
                }),
            }));
            None
        }
    }
}

/// Drive the polling state machine over an open `Tokens.subscribe` subscription.
///
/// Three-way `tokio::select!`: cancel, deadline, recv. `Pending`/`Subscribed`
/// are transitional; `OK`/`Denied`/`Disabled`/`InvalidUsername`/`InvalidToken`/
/// `Expired`/`NotFound` are terminal.
pub(crate) async fn poll_interactive_outcome(
    mut subscription: Subscription,
    expires_at: SystemTime,
    poll_interval: Duration,
    cancel: Option<CancellationToken>,
) -> InteractiveOutcome {
    // tokio's sleep_until is monotonic; convert SystemTime once.
    let now_sys = SystemTime::now();
    let until_expiry = expires_at.duration_since(now_sys).unwrap_or(Duration::ZERO);
    let deadline = tokio::time::Instant::now() + until_expiry;

    // poll_interval is informational; the SOWS subscription pushes frames, so the
    // select races recv vs. deadline vs. cancel without per-tick polling.
    let _ = poll_interval;

    loop {
        let cancel_fut = async {
            match cancel.as_ref() {
                Some(token) => token.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            biased;
            _ = cancel_fut => return InteractiveOutcome::Cancelled,
            _ = tokio::time::sleep_until(deadline) => return InteractiveOutcome::Expired,
            recv = subscription.recv::<TokensAuth>() => match recv {
                Ok((auth, _blob)) => match auth.status {
                    AuthStatus::OK => return InteractiveOutcome::Authenticated(auth),
                    AuthStatus::Pending | AuthStatus::Subscribed => continue,
                    AuthStatus::Denied => return InteractiveOutcome::Denied {
                        status: auth.status,
                        reason: "denied",
                    },
                    AuthStatus::Disabled => return InteractiveOutcome::Denied {
                        status: auth.status,
                        reason: "disabled",
                    },
                    AuthStatus::InvalidUsername => return InteractiveOutcome::Denied {
                        status: auth.status,
                        reason: "invalid_username",
                    },
                    AuthStatus::InvalidToken => return InteractiveOutcome::Denied {
                        status: auth.status,
                        reason: "invalid_token",
                    },
                    AuthStatus::NotFound => return InteractiveOutcome::Denied {
                        status: auth.status,
                        reason: "not_found",
                    },
                    AuthStatus::Expired => return InteractiveOutcome::Denied {
                        status: auth.status,
                        reason: "auth_expired",
                    },
                    other => return InteractiveOutcome::Denied {
                        status: other,
                        reason: "unexpected_status",
                    },
                },
                Err(err) => return InteractiveOutcome::TransportError(err.into()),
            }
        }
    }
}

/// SOWS-discovered URLs for the three interfaces the interactive flow uses.
struct InteractiveAuthEndpoints {
    credentials_url: String,
    tokens_url: String,
    connection_url: String,
    /// Browser sign-in URL pulled from the Credentials interface's discovery
    /// `meta.login_url`, with any `*` substituted to the connecting hostname.
    /// `None` if the server doesn't advertise it (older Nucleus deployments).
    login_url: Option<String>,
}

/// SOWS-discover `Credentials`, `Tokens`, `Connection` over a single short-lived discovery socket.
async fn discover_auth_endpoints(config: &NucleusConfig) -> Result<InteractiveAuthEndpoints> {
    let discovery_endpoint = config
        .endpoint
        .clone()
        .unwrap_or_else(|| discovery_url(&config.server));
    tracing::debug!(plugin = "nucleus", endpoint = %discovery_endpoint, "connecting to nucleus discovery");
    let discovery = SowsTransport::connect(&discovery_endpoint)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("Nucleus discovery connect failed ({discovery_endpoint}): {err:#}"),
            )
        })?;

    let sows_transports = supported_transports::<SowsTransport>();

    let (credentials_settings, credentials_meta) =
        find_interface(&discovery, credentials_spec(), &sows_transports).await?;
    let credentials_url = url_from_transport(&credentials_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Credentials transport settings missing host/port",
        )
    })?;
    let login_url = credentials_meta
        .as_ref()
        .and_then(|m| m.get("login_url"))
        .map(|raw| substitute_login_url_host(raw, &config.server));

    let (tokens_settings, _) = find_interface(&discovery, tokens_spec(), &sows_transports).await?;
    let tokens_url = url_from_transport(&tokens_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Tokens transport settings missing host/port",
        )
    })?;

    let connlib_transports = supported_transports::<ConnLibTransport>();
    let (connection_settings, _) =
        find_interface(&discovery, connection_spec(), &connlib_transports).await?;
    let connection_url = url_from_transport(&connection_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Connection transport settings missing host/port",
        )
    })?;

    drop(discovery);
    Ok(InteractiveAuthEndpoints {
        credentials_url,
        tokens_url,
        connection_url,
        login_url,
    })
}

/// Replace `*` in a discovery-supplied login URL with the connecting hostname
/// (port stripped). Mirrors Nucleus reference CLI behaviour.
fn substitute_login_url_host(login_url: &str, server: &str) -> String {
    let hostname = server.split(':').next().unwrap_or(server);
    login_url.replace('*', hostname)
}

/// Drive the full API-token auth handshake.
///
/// Error mapping: transport failures -> `Transient`; server auth failures
/// or missing/empty token -> `AuthRequired`; missing required `Auth` fields -> `Internal`.
pub(crate) async fn establish_api_token(
    config: &NucleusConfig,
    bundle: &SecretBundle,
) -> Result<HandshakeOutput> {
    let span =
        tracing::info_span!("nucleus.handshake", plugin = "nucleus", server = %config.server);
    let _guard = span.enter();
    tracing::debug!("starting API token handshake");

    let api_token = api_token_from_bundle(bundle)?;

    let discovery_endpoint = config
        .endpoint
        .clone()
        .unwrap_or_else(|| discovery_url(&config.server));
    let discovery = SowsTransport::connect(&discovery_endpoint)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("Nucleus discovery connect failed ({discovery_endpoint}): {err:#}"),
            )
        })?;

    let sows_transports = supported_transports::<SowsTransport>();
    let (tokens_settings, _) = find_interface(&discovery, tokens_spec(), &sows_transports).await?;
    let tokens_url = url_from_transport(&tokens_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Tokens transport settings missing host/port",
        )
    })?;

    // Discover Connection up-front so the discovery socket can drop before `auth_with_api_token`.
    let connlib_transports = supported_transports::<ConnLibTransport>();
    let (connection_settings, _) =
        find_interface(&discovery, connection_spec(), &connlib_transports).await?;
    let connection_url = url_from_transport(&connection_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Connection transport settings missing host/port",
        )
    })?;

    tracing::debug!("exchanging API token");
    let tokens_auth = exchange_api_token(&tokens_url, &api_token).await?;
    tracing::debug!("API token exchanged, establishing session");
    complete_session(config, tokens_url, &connection_url, tokens_auth).await
}

/// Drive the full username+password auth handshake.
///
/// Discover `Credentials`/`Tokens`/`Connection`, call `Credentials::auth`,
/// then bring up ConnLib + LFT via `complete_session`.
///
/// Error mapping: transport failures -> `Transient`; `Denied`/`Disabled`/
/// `InvalidUsername`/`InvalidToken`/`NotFound` -> `AuthRequired`; `Expired` ->
/// `AuthExpired`; missing/empty fields -> `AuthRequired`; wrong SecretValue ->
/// `InvalidArgument`; transitional or undocumented status on a sync reply -> `Internal`.
pub(crate) async fn establish_username_password(
    config: &NucleusConfig,
    bundle: &SecretBundle,
) -> Result<HandshakeOutput> {
    let span =
        tracing::info_span!("nucleus.handshake", plugin = "nucleus", server = %config.server);
    let _guard = span.enter();
    tracing::debug!("starting username/password handshake");

    let (username, password) = username_password_from_bundle(bundle)?;

    let endpoints = discover_auth_endpoints(config).await?;

    let credentials_transport = SowsTransport::connect(&endpoints.credentials_url)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!(
                    "Nucleus Credentials connect failed ({}): {err:#}",
                    endpoints.credentials_url
                ),
            )
        })?;

    let client_id = format!("ovstorage-plugin-nucleus/{}", env!("CARGO_PKG_VERSION"));
    let auth = Credentials::auth(
        &credentials_transport,
        username,
        password,
        None,
        Some(client_id),
    )
    .await
    .map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("Nucleus Credentials.auth call failed: {err:#}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("credentials_auth_call_failed".into()),
            expired_at: None,
        })
    })?;

    match auth.status {
        AuthStatus::OK => {
            tracing::debug!("Credentials.auth succeeded, establishing session");
            complete_session(
                config,
                endpoints.tokens_url,
                &endpoints.connection_url,
                auth,
            )
            .await
        }
        AuthStatus::Denied
        | AuthStatus::Disabled
        | AuthStatus::InvalidUsername
        | AuthStatus::InvalidToken
        | AuthStatus::NotFound => {
            tracing::warn!(status = ?auth.status, "Credentials.auth denied");
            let reason = match auth.status {
                AuthStatus::Denied => "credentials_auth_denied",
                AuthStatus::Disabled => "credentials_auth_disabled",
                AuthStatus::InvalidUsername => "credentials_auth_invalid_username",
                AuthStatus::InvalidToken => "credentials_auth_invalid_token",
                AuthStatus::NotFound => "credentials_auth_not_found",
                _ => unreachable!(),
            };
            Err(Error::new(
                ErrorCode::AuthRequired,
                format!(
                    "Nucleus Credentials.auth rejected (status={:?})",
                    auth.status
                ),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some(reason.into()),
                expired_at: None,
            }))
        }
        AuthStatus::Expired => {
            tracing::warn!("Credentials.auth returned Expired");
            Err(Error::new(
                ErrorCode::AuthExpired,
                "Nucleus Credentials.auth returned Expired",
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("credentials_auth_expired".into()),
                expired_at: None,
            }))
        }
        other => Err(Error::new(
            ErrorCode::Internal,
            format!(
                "Nucleus Credentials.auth returned unexpected status={other:?} \
                 (synchronous reply should carry a terminal Auth)"
            ),
        )),
    }
}

/// missing -> `AuthRequired`, wrong kind -> `InvalidArgument`, empty -> `AuthRequired`.
fn username_password_from_bundle(bundle: &SecretBundle) -> Result<(String, String)> {
    let username = secret_string_field(bundle, "username")?;
    let password = secret_string_field(bundle, "password")?;
    Ok((username, password))
}

fn secret_string_field(bundle: &SecretBundle, key: &str) -> Result<String> {
    let value = bundle.fields.get(key).ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            format!(
                "Nucleus username/password credential missing (`{key}` not present in SecretBundle)"
            ),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some(format!("{key}_missing")),
            expired_at: None,
        })
    })?;
    let bytes = match value {
        SecretValue::Bytes(b) => &b.0,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("Nucleus `{key}` credential must be SecretBytes"),
            ));
        }
    };
    if bytes.is_empty() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            format!("Nucleus `{key}` credential is empty"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some(format!("{key}_empty")),
            expired_at: None,
        }));
    }
    std::str::from_utf8(bytes)
        .with_context(|| format!("Nucleus {key} bytes are not UTF-8"))
        .map(|s| s.to_string())
        .map_err(|err| Error::new(ErrorCode::InvalidArgument, format!("{err:#}")))
}

/// Cold-start warm continuation: rediscover `tokens_url`, then drive a
/// refresh-token grant + ConnLib re-auth via `refresh_session`. Used by the
/// factory when a prior process persisted a refresh_token in the OS keyring.
/// On any error, the caller should fall through to interactive sign-in
/// (and clear the keyring entry on `AuthRequired`/`AuthExpired`/`PermissionDenied`).
pub(crate) async fn try_warm_continue(
    config: &NucleusConfig,
    refresh_token: String,
) -> Result<HandshakeOutput> {
    tracing::debug!(plugin = "nucleus", server = %config.server, "nucleus warm continuation: rediscovering tokens_url");
    let discovery_endpoint = config
        .endpoint
        .clone()
        .unwrap_or_else(|| discovery_url(&config.server));
    let discovery = SowsTransport::connect(&discovery_endpoint)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("Nucleus discovery connect failed ({discovery_endpoint}): {err:#}"),
            )
        })?;
    let sows_transports = supported_transports::<SowsTransport>();
    let (tokens_settings, _) = find_interface(&discovery, tokens_spec(), &sows_transports).await?;
    let tokens_url = url_from_transport(&tokens_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Tokens transport settings missing host/port",
        )
    })?;
    drop(discovery);

    // refresh_session takes the refresh_token branch when prior_session.refresh_token is Some,
    // so the bundle is unused here (no api-token fallback).
    let prior = NucleusSession {
        access_token: String::new(),
        refresh_token: Some(refresh_token),
        tokens_url,
        principal: String::new(),
    };
    refresh_session(config, &SecretBundle::default(), &prior).await
}

/// Refresh round-trip: prefers `refresh_token` if present, falls back to
/// re-running `auth_with_api_token`. Returns a fresh `HandshakeOutput`
/// bound to a new ConnLib socket.
pub(crate) async fn refresh_session(
    config: &NucleusConfig,
    bundle: &SecretBundle,
    prior_session: &NucleusSession,
) -> Result<HandshakeOutput> {
    tracing::debug!(plugin = "nucleus", server = %config.server, "refreshing nucleus session");
    // Re-discover Connection on every refresh; rediscovery is cheap and avoids stashing two URLs on `NucleusSession`.
    let discovery_endpoint = config
        .endpoint
        .clone()
        .unwrap_or_else(|| discovery_url(&config.server));
    let discovery = SowsTransport::connect(&discovery_endpoint)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("Nucleus discovery connect failed ({discovery_endpoint}): {err:#}"),
            )
        })?;
    let connlib_transports = supported_transports::<ConnLibTransport>();
    let (connection_settings, _) =
        find_interface(&discovery, connection_spec(), &connlib_transports).await?;
    let connection_url = url_from_transport(&connection_settings).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Nucleus Connection transport settings missing host/port",
        )
    })?;
    drop(discovery);

    // OAuth-backed deployments mint refresh_tokens; raw api-token deployments do not.
    let tokens_auth = if let Some(refresh_token) = prior_session.refresh_token.clone() {
        let tokens_transport = SowsTransport::connect(&prior_session.tokens_url)
            .await
            .map_err(|err| {
                Error::new(
                    ErrorCode::Transient,
                    format!(
                        "Nucleus Tokens connect (refresh) failed ({}): {err:#}",
                        prior_session.tokens_url
                    ),
                )
            })?;
        tokens_transport
            .refresh(refresh_token, None)
            .await
            .map_err(|err| {
                Error::new(
                    ErrorCode::AuthExpired,
                    format!("Nucleus Tokens.refresh failed: {err:#}"),
                )
                .with_context(ErrorContext::Auth {
                    connection_id: ConnectionId(String::new()),
                    reason: Some("tokens_refresh_failed".into()),
                    expired_at: None,
                })
            })?
    } else {
        let api_token = api_token_from_bundle(bundle)?;
        exchange_api_token(&prior_session.tokens_url, &api_token).await?
    };
    complete_session(
        config,
        prior_session.tokens_url.clone(),
        &connection_url,
        tokens_auth,
    )
    .await
}

/// Shared by the initial handshake and the refresh fallback when no refresh_token is available.
async fn exchange_api_token(tokens_url: &str, api_token: &str) -> Result<TokensAuth> {
    let tokens_transport = SowsTransport::connect(tokens_url).await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("Nucleus Tokens connect failed ({tokens_url}): {err:#}"),
        )
    })?;
    tokens_transport
        .auth_with_api_token(api_token.to_string(), None)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("Nucleus Tokens.auth_with_api_token failed: {err:#}"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("auth_with_api_token_failed".into()),
                expired_at: None,
            })
        })
}

/// Bring up ConnLib + LFT from an already-issued `TokensAuth`. Shared by
/// the initial-handshake and refresh paths.
async fn complete_session(
    config: &NucleusConfig,
    tokens_url: String,
    connection_url: &str,
    tokens_auth: TokensAuth,
) -> Result<HandshakeOutput> {
    tracing::debug!(plugin = "nucleus", server = %config.server, "completing nucleus session via ConnLib authorize_token");
    let user_agent = Some(format!(
        "ovstorage-plugin-nucleus/{}",
        env!("CARGO_PKG_VERSION")
    ));
    let access_token = tokens_auth.access_token.clone().ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "Nucleus Tokens auth returned no access_token",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("no_access_token".into()),
            expired_at: None,
        })
    })?;

    // Some Nucleus deployments gate the websocket upgrade on the URL-query
    // access_token. Reference CLI appends it before connecting, then also calls
    // authorize_token. Belt + suspenders.
    let connect_url = {
        let sep = if connection_url.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{connection_url}{sep}access_token={access_token}")
    };
    let connlib = ConnLibTransport::connect(&connect_url)
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("Nucleus Connection connect failed ({connection_url}): {err:#}"),
            )
        })?;

    let session: ConnectionAuth = connlib
        .authorize_token(
            access_token.clone(),
            nucleus_client::types::VERSION.into(),
            HashMap::new(),
            user_agent,
            None,
        )
        .await
        .map_err(|err| {
            Error::new(
                ErrorCode::AuthRequired,
                format!("Nucleus Connection.authorize_token failed: {err:#}"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("authorize_token_failed".into()),
                expired_at: None,
            })
        })?;
    // Server can return non-empty connection_id with a non-OK status (e.g. Denied,
    // TokenExpired). Without this check we'd silently install a denied session and
    // surface an opaque error on the first RPC.
    match session.status {
        StatusType::OK => {}
        denied @ (StatusType::Denied | StatusType::Unauthenticated) => {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                format!("Nucleus authorize_token denied (status={denied:?})"),
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("authorize_token_denied".into()),
                expired_at: None,
            }));
        }
        StatusType::TokenExpired => {
            return Err(Error::new(
                ErrorCode::AuthExpired,
                "Nucleus authorize_token reported token expired",
            )
            .with_context(ErrorContext::Auth {
                connection_id: ConnectionId(String::new()),
                reason: Some("authorize_token_expired".into()),
                expired_at: None,
            }));
        }
        other => {
            return Err(Error::new(
                ErrorCode::Internal,
                format!("Nucleus authorize_token returned unexpected status {other:?}"),
            ));
        }
    }
    if session.connection_id.is_empty() {
        return Err(Error::new(
            ErrorCode::Internal,
            "Nucleus authorize_token returned empty connection_id",
        ));
    }

    // LFT requires a server-advertised address; threshold defaults to 0 (use LFT
    // for everything). Token/username/signature must be filtered for empties so
    // an empty server response doesn't masquerade as real auth at the LFT layer.
    let lft = if config.use_lft {
        match session.lft_address.clone() {
            Some(address) if !address.is_empty() => {
                let threshold = session.lft_threshold.unwrap_or(0);
                let signature = session
                    .connection_id_signature
                    .clone()
                    .filter(|s| !s.is_empty());
                let session_token = Some(session.token.clone()).filter(|s| !s.is_empty());
                let username = Some(session.username.clone()).filter(|s| !s.is_empty());
                // 5 MiB matches the Nucleus LFT server's
                // `DEFAULT_MULTIPART_CHUNK_SIZE`, well below its 24 MiB
                // per-PUT cap. Single-PUT fallback would defer 413s to
                // the upload itself, so always chunk on missing.
                let multipart_chunk_size = session.multipart_chunk_size.unwrap_or(5 * 1024 * 1024);
                Some(Arc::new(
                    LftClient::new(
                        address,
                        threshold,
                        session.connection_id.clone(),
                        signature,
                        session_token,
                        Some(access_token.clone()),
                        username,
                        multipart_chunk_size,
                    )
                    .map_err(|err| {
                        Error::new(ErrorCode::Transient, format!("LFT client init: {err}"))
                    })?,
                ))
            }
            _ => None,
        }
    } else {
        None
    };

    // Discovery + Tokens transports drop here; only the ConnLib socket survives.
    let _ = NUCLEUS_KIND;
    let ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(connlib));

    tracing::info!(
        plugin = "nucleus",
        server = %config.server,
        "nucleus session established",
    );
    Ok(HandshakeOutput {
        ops,
        lft,
        session: NucleusSession {
            access_token,
            refresh_token: tokens_auth.refresh_token.clone(),
            tokens_url,
            principal: session.username,
        },
    })
}

fn api_token_from_bundle(bundle: &SecretBundle) -> Result<String> {
    let value = bundle.fields.get("api_token").ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "Nucleus API token credential missing (`api_token` not present in SecretBundle)",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("api_token_missing".into()),
            expired_at: None,
        })
    })?;
    let bytes = match value {
        SecretValue::Bytes(b) => &b.0,
        _ => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Nucleus `api_token` credential must be SecretBytes",
            ));
        }
    };
    if bytes.is_empty() {
        return Err(Error::new(
            ErrorCode::AuthRequired,
            "Nucleus `api_token` credential is empty",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("api_token_empty".into()),
            expired_at: None,
        }));
    }
    let token = std::str::from_utf8(bytes)
        .context("Nucleus api_token bytes are not UTF-8")
        .map_err(|err| Error::new(ErrorCode::InvalidArgument, format!("{err:#}")))?
        .to_string();
    Ok(token)
}

/// SOWS interface coordinates. `origin` is the IDL file the interface is
/// declared in; `capabilities` is the per-method version map the client
/// supports. The Nucleus discovery registry is keyed on `(origin, name)`.
struct InterfaceSpec {
    origin: &'static str,
    name: &'static str,
    capabilities: std::collections::HashMap<String, u64>,
}

fn credentials_spec() -> InterfaceSpec {
    InterfaceSpec {
        origin: nucleus_auth::generated::credentials::ORIGIN,
        name: nucleus_auth::generated::credentials::INTERFACE,
        capabilities: nucleus_auth::generated::credentials::capabilities(),
    }
}

fn tokens_spec() -> InterfaceSpec {
    InterfaceSpec {
        origin: nucleus_auth::generated::tokens::ORIGIN,
        name: nucleus_auth::generated::tokens::INTERFACE,
        capabilities: nucleus_auth::generated::tokens::capabilities(),
    }
}

fn connection_spec() -> InterfaceSpec {
    InterfaceSpec {
        origin: nucleus_client::generated::connection::ORIGIN,
        name: nucleus_client::generated::connection::INTERFACE,
        capabilities: nucleus_client::generated::connection::capabilities(),
    }
}

async fn find_interface<T>(
    discovery: &T,
    spec: InterfaceSpec,
    supported: &[nucleus_discovery::types::SupportedTransport],
) -> Result<(TransportSettings, Option<HashMap<String, String>>)>
where
    T: nucleus_transport::Transport + Sync,
{
    let InterfaceSpec {
        origin,
        name,
        capabilities,
    } = spec;
    let query = make_query(
        origin,
        name,
        Some(capabilities),
        Some("external"),
        supported,
    );
    let result = discovery.find(query).await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("Nucleus discovery {name} failed: {err:#}"),
        )
    })?;
    let SearchResult {
        found,
        transport,
        service_interface,
        meta,
        ..
    } = result;
    if !found {
        return Err(Error::new(
            ErrorCode::NotFound,
            format!("Nucleus discovery: no {name} interface registered (origin={origin})"),
        ));
    }
    let _ = service_interface;
    let transport = transport.ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("Nucleus discovery {name}: result missing transport settings"),
        )
    })?;
    Ok((transport, meta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use nucleus_transport::{RawResponse, Subscription};
    use ovstorage_plugin::CancellationToken;
    use tokio::sync::mpsc;

    fn fake_subscription() -> (Subscription, mpsc::Sender<anyhow::Result<RawResponse>>) {
        let (tx, rx) = mpsc::channel(8);
        let (stop_tx, _stop_rx) = mpsc::channel(1);
        let finished = StdArc::new(AtomicBool::new(false));
        (Subscription::new(rx, 1, stop_tx, finished), tx)
    }

    #[tokio::test]
    async fn poll_outcome_returns_authenticated_on_ok() {
        let (subscription, tx) = fake_subscription();
        let expires_at = SystemTime::now() + Duration::from_secs(60);
        let task = tokio::spawn(async move {
            poll_interactive_outcome(subscription, expires_at, Duration::from_millis(50), None)
                .await
        });
        tokio::task::yield_now().await;
        let auth = TokensAuth {
            status: AuthStatus::OK,
            access_token: Some("at".into()),
            refresh_token: Some("rt".into()),
            ..Default::default()
        };
        tx.send(Ok(RawResponse {
            json: serde_json::to_vec(&auth).unwrap(),
            blob: None,
        }))
        .await
        .unwrap();
        let outcome = task.await.unwrap();
        match outcome {
            InteractiveOutcome::Authenticated(a) => {
                assert_eq!(a.access_token.as_deref(), Some("at"));
                assert_eq!(a.refresh_token.as_deref(), Some("rt"));
            }
            _ => panic!("expected Authenticated"),
        }
    }

    #[tokio::test]
    async fn poll_outcome_skips_pending_frames() {
        let (subscription, tx) = fake_subscription();
        let expires_at = SystemTime::now() + Duration::from_secs(60);
        let task = tokio::spawn(async move {
            poll_interactive_outcome(subscription, expires_at, Duration::from_millis(50), None)
                .await
        });
        for status in [AuthStatus::Pending, AuthStatus::OK] {
            let auth = TokensAuth {
                status,
                access_token: if status == AuthStatus::OK {
                    Some("final".into())
                } else {
                    None
                },
                ..Default::default()
            };
            tx.send(Ok(RawResponse {
                json: serde_json::to_vec(&auth).unwrap(),
                blob: None,
            }))
            .await
            .unwrap();
        }
        let outcome = task.await.unwrap();
        assert!(
            matches!(outcome, InteractiveOutcome::Authenticated(a) if a.access_token.as_deref() == Some("final"))
        );
    }

    #[tokio::test]
    async fn poll_outcome_returns_denied_on_denied_status() {
        let (subscription, tx) = fake_subscription();
        let expires_at = SystemTime::now() + Duration::from_secs(60);
        let task = tokio::spawn(async move {
            poll_interactive_outcome(subscription, expires_at, Duration::from_millis(50), None)
                .await
        });
        let denied = TokensAuth {
            status: AuthStatus::Denied,
            ..Default::default()
        };
        tx.send(Ok(RawResponse {
            json: serde_json::to_vec(&denied).unwrap(),
            blob: None,
        }))
        .await
        .unwrap();
        let outcome = task.await.unwrap();
        match outcome {
            InteractiveOutcome::Denied { status, reason } => {
                assert_eq!(status, AuthStatus::Denied);
                assert_eq!(reason, "denied");
            }
            _ => panic!("expected Denied"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn poll_outcome_returns_expired_when_deadline_elapses() {
        let (subscription, _tx) = fake_subscription();
        // Hold `_tx` so the channel stays open; otherwise recv races the deadline arm.
        let expires_at = SystemTime::now() + Duration::from_secs(30);
        let handle = tokio::spawn(async move {
            poll_interactive_outcome(subscription, expires_at, Duration::from_secs(1), None).await
        });
        tokio::time::advance(Duration::from_secs(31)).await;
        let outcome = handle.await.unwrap();
        assert!(matches!(outcome, InteractiveOutcome::Expired));
    }

    /// Subscription's Drop must fire the SOWS stop signal; observed via the stop channel id.
    #[tokio::test]
    async fn poll_outcome_returns_cancelled_when_token_fires() {
        let (tx, rx) = mpsc::channel(4);
        let (stop_tx, mut stop_rx) = mpsc::channel(4);
        let finished = StdArc::new(AtomicBool::new(false));
        let subscription = Subscription::new(rx, 7, stop_tx, finished);
        // Hold `_frame_tx` so the recv arm parks forever and only cancel can complete.
        let _frame_tx = tx;
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        let expires_at = SystemTime::now() + Duration::from_secs(60);
        let handle = tokio::spawn(async move {
            poll_interactive_outcome(
                subscription,
                expires_at,
                Duration::from_millis(50),
                Some(cancel_for_task),
            )
            .await
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        let outcome = handle.await.unwrap();
        assert!(matches!(outcome, InteractiveOutcome::Cancelled));
        let stopped_id = stop_rx.recv().await.expect("stop signal must fire on Drop");
        assert_eq!(stopped_id, 7);
    }

    #[tokio::test]
    async fn poll_outcome_returns_transport_error_on_recv_failure() {
        let (subscription, tx) = fake_subscription();
        let expires_at = SystemTime::now() + Duration::from_secs(60);
        let task = tokio::spawn(async move {
            poll_interactive_outcome(subscription, expires_at, Duration::from_millis(50), None)
                .await
        });
        tx.send(Err(anyhow::anyhow!("websocket dropped")))
            .await
            .unwrap();
        let outcome = task.await.unwrap();
        assert!(matches!(outcome, InteractiveOutcome::TransportError(_)));
    }

    fn make_user_pass_bundle(username: SecretValue, password: SecretValue) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert("username".into(), username);
        bundle.fields.insert("password".into(), password);
        bundle
    }

    #[test]
    fn username_password_from_bundle_happy_path() {
        use ovstorage_plugin::SecretBytes;
        let bundle = make_user_pass_bundle(
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
            SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
        );
        let (user, pass) = username_password_from_bundle(&bundle).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "hunter2");
    }

    #[test]
    fn username_password_from_bundle_rejects_missing_password() {
        use ovstorage_plugin::SecretBytes;
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "username".into(),
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
        );
        let err = username_password_from_bundle(&bundle).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("password_missing"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// `password_empty` is distinct from `password_missing` so the host can render a different message.
    #[test]
    fn username_password_from_bundle_rejects_empty_password() {
        use ovstorage_plugin::SecretBytes;
        let bundle = make_user_pass_bundle(
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
            SecretValue::Bytes(SecretBytes(Vec::new())),
        );
        let err = username_password_from_bundle(&bundle).unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth { reason, .. }) => {
                assert_eq!(reason.as_deref(), Some("password_empty"));
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn username_password_from_bundle_rejects_wrong_kind() {
        use ovstorage_plugin::SecretBytes;
        let bundle = make_user_pass_bundle(
            SecretValue::File(SecretBytes(b"alice".to_vec())),
            SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
        );
        let err = username_password_from_bundle(&bundle).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn username_password_from_bundle_rejects_non_utf8() {
        use ovstorage_plugin::SecretBytes;
        let bundle = make_user_pass_bundle(
            SecretValue::Bytes(SecretBytes(b"alice".to_vec())),
            SecretValue::Bytes(SecretBytes(vec![0xFF, 0xFE, 0xFD])),
        );
        let err = username_password_from_bundle(&bundle).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}
