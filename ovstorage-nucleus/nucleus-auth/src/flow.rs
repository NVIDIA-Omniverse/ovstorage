// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for the Nucleus URL+nonce-poll interactive auth flow.
//!
//! Nucleus does NOT speak OAuth: a client subscribes to `Tokens.subscribe`
//! to obtain a server-issued `nonce`, opens
//! `<login_url>?server=<host>&nonce=<n>` in a browser, and waits for the
//! *second* `recv()` on the same SOWS subscription — the server publishes
//! `Auth { access_token, refresh_token, ... }` once the user signs in.
//!
//! `login_url` is sourced from the SOWS discovery `meta` of the Credentials
//! interface (with `*` substituted for the connecting hostname), NOT from
//! `Credentials.get_settings()`. Reference Nucleus CLIs do the same; not
//! every server populates `CredentialSettings.login_url`.
//!
//! [`start_interactive`] runs only the URL+nonce leg and returns the
//! still-open `Subscription` so the caller owns the polling loop and its
//! cancel/timeout policy.

use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use nucleus_transport::{Subscription, Transport};
use url::Url;

use crate::generated::Tokens;
use crate::types::{Auth, AuthStatus};

/// Output of the URL+nonce leg of the Nucleus interactive auth flow.
pub struct InteractiveHandshakeStart {
    /// Browser URL to open; already carries `?server=...&nonce=...`.
    pub auth_url: String,
    /// Server-issued nonce embedded in `auth_url`.
    pub nonce: String,
    /// Wall-clock instant when the URL stops being valid; SOWS does not
    /// return an explicit TTL, so [`DEFAULT_EXPIRES_IN`] is applied.
    pub expires_at: SystemTime,
    /// Open SOWS subscription; next `recv::<Auth>()` returns the terminal
    /// envelope (or a transitional `Pending`).
    pub subscription: Subscription,
}

/// Default URL TTL; SOWS does not advertise one. 15 min covers slow IdP flows
/// (MFA, password reset, manual approval) without holding the SOWS subscription
/// indefinitely when the user wanders off.
pub const DEFAULT_EXPIRES_IN: Duration = Duration::from_secs(900);

/// Recommended polling cadence; the caller's loop enforces it.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Per-await upper bound applied by [`start_interactive`] to each pre-browser leg.
pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(30);

/// Drive the URL+nonce leg of the Nucleus interactive auth flow.
///
/// `login_url` is the discovery `meta.login_url` value (with any `*` placeholder
/// already substituted to the connecting hostname). `server` is the hostname
/// (optionally with port) that will be embedded as `?server=<host>` so the
/// IDP can redirect back to the right Nucleus deployment.
/// Each pre-browser await is bounded by [`DEFAULT_START_TIMEOUT`].
pub async fn start_interactive<T: Transport>(
    tokens: &T,
    login_url: &str,
    server: &str,
) -> Result<InteractiveHandshakeStart> {
    start_interactive_with_timeout(tokens, login_url, server, Some(DEFAULT_START_TIMEOUT)).await
}

/// Like [`start_interactive`] but with a configurable per-await timeout; `None` disables it.
pub async fn start_interactive_with_timeout<T: Transport>(
    tokens: &T,
    login_url: &str,
    server: &str,
    timeout: Option<Duration>,
) -> Result<InteractiveHandshakeStart> {
    let span = tracing::info_span!("nucleus.auth", plugin = "nucleus");
    let _guard = span.enter();

    tracing::debug!("subscribing to Tokens");
    let mut subscription = bounded(timeout, "Tokens::subscribe", tokens.subscribe())
        .await
        .context("Tokens::subscribe failed")?;
    let (first, _): (Auth, _) = bounded(
        timeout,
        "Tokens::subscribe first frame",
        subscription.recv(),
    )
    .await
    .context("Tokens::subscribe first frame")?;
    if first.status != AuthStatus::Subscribed {
        tracing::warn!(status = ?first.status, "Tokens::subscribe returned unexpected initial status");
        return Err(anyhow::anyhow!(
            "Tokens::subscribe expected status=Subscribed, got status={:?}",
            first.status
        ));
    }
    let nonce = first.nonce.filter(|n| !n.is_empty()).ok_or_else(|| {
        tracing::warn!("Tokens::subscribe returned no nonce");
        anyhow::anyhow!("Tokens::subscribe returned no nonce")
    })?;

    tracing::debug!("auth URL built, nonce obtained");
    let auth_url = build_auth_url(login_url, &nonce, server)?;
    Ok(InteractiveHandshakeStart {
        auth_url,
        nonce,
        expires_at: SystemTime::now() + DEFAULT_EXPIRES_IN,
        subscription,
    })
}

async fn bounded<F, R, E>(timeout: Option<Duration>, label: &'static str, fut: F) -> Result<R>
where
    F: std::future::Future<Output = Result<R, E>>,
    E: Into<anyhow::Error>,
{
    match timeout {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(inner) => inner.map_err(Into::into),
            Err(_) => Err(anyhow::anyhow!("{label} timed out after {:?}", d)),
        },
        None => fut.await.map_err(Into::into),
    }
}

/// Append `?server=<host>&nonce=<n>` to `login_url`. Rejects non-http(s) schemes
/// to block javascript:/data:/file: injection if a server returns a tainted URL.
fn build_auth_url(login_url: &str, nonce: &str, server: &str) -> Result<String> {
    let mut parsed = Url::parse(login_url)
        .map_err(|e| anyhow::anyhow!("invalid login_url {login_url:?}: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow::anyhow!(
            "login_url has unsupported scheme {scheme:?}; expected http or https"
        ));
    }
    parsed
        .query_pairs_mut()
        .append_pair("server", server)
        .append_pair("nonce", nonce);
    Ok(parsed.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_auth_url_appends_server_and_nonce() {
        let url =
            build_auth_url("https://nucleus.example/login", "abc123", "host.example").unwrap();
        assert_eq!(
            url,
            "https://nucleus.example/login?server=host.example&nonce=abc123"
        );
    }

    #[test]
    fn build_auth_url_preserves_existing_query() {
        let url = build_auth_url(
            "https://nucleus.example/login?form=basic",
            "abc123",
            "host.example",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://nucleus.example/login?form=basic&server=host.example&nonce=abc123"
        );
    }

    #[test]
    fn build_auth_url_preserves_fragment() {
        let url = build_auth_url(
            "https://nucleus.example/login#/signin",
            "abc123",
            "host.example",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://nucleus.example/login?server=host.example&nonce=abc123#/signin"
        );
    }

    #[test]
    fn build_auth_url_percent_encodes_special_chars() {
        let url = build_auth_url("https://nucleus.example/login", "n+ce/=", "host:8080").unwrap();
        assert!(url.contains("nonce=n%2Bce%2F%3D"));
        assert!(url.contains("server=host%3A8080"));
    }

    #[test]
    fn build_auth_url_rejects_javascript_scheme() {
        let err = build_auth_url("javascript:alert(1)", "n", "host").unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn build_auth_url_rejects_file_scheme() {
        let err = build_auth_url("file:///etc/passwd", "n", "host").unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn build_auth_url_rejects_data_scheme() {
        let err = build_auth_url("data:text/html,<script>alert(1)</script>", "n", "h").unwrap_err();
        assert!(err.to_string().contains("unsupported scheme"));
    }

    #[test]
    fn build_auth_url_rejects_malformed_input() {
        let err = build_auth_url("not a url", "n", "h").unwrap_err();
        assert!(err.to_string().contains("invalid login_url"));
    }
}
