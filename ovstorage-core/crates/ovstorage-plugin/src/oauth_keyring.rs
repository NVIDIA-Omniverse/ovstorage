// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OAuth refresh-token persistence helpers shared by plugins that
//! warm-continue a long-lived OIDC session across process restarts.
//!
//! The host's keyring API takes a `(backend_kind, connection_id, field)`
//! triple. Callers pass a stable hostname-shaped key so the entry
//! survives across restarts (the host-issued `ConnectionId` is
//! `pid + nanos`, non-stable).

use std::time::SystemTime;

use crate::ErrorCode;
use crate::shim;
use crate::types::{ConnectionId, SecretBundle, SecretBytes, SecretValue};

const REFRESH_TOKEN_FIELD: &str = "refresh_token";

/// Map a discovery URL to a stable `ConnectionId` keyed on its host.
/// Plugins keyed on a bare hostname can construct `ConnectionId(host)`
/// directly without this helper.
pub fn conn_id_from_url(discovery_url: &str) -> ConnectionId {
    let host = url::Url::parse(discovery_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| discovery_url.to_string());
    ConnectionId(host)
}

pub fn read_refresh_token(plugin: &str, backend_kind: &str, conn: &ConnectionId) -> Option<String> {
    let host_cb = shim::host()?;
    match host_cb.keyring_get(backend_kind, conn, REFRESH_TOKEN_FIELD) {
        Ok(Some(bytes)) => match std::str::from_utf8(&bytes.0) {
            Ok(s) if !s.is_empty() => Some(s.to_string()),
            Ok(_) => None,
            Err(_) => {
                tracing::warn!(
                    plugin,
                    key = %conn.0,
                    "stored refresh_token is not UTF-8; ignoring",
                );
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            tracing::warn!(plugin, key = %conn.0, error = %err, "keyring_get failed");
            None
        }
    }
}

pub fn write_refresh_token(plugin: &str, backend_kind: &str, conn: &ConnectionId, token: &str) {
    let Some(host_cb) = shim::host() else {
        return;
    };
    let value = SecretBytes(token.as_bytes().to_vec());
    if let Err(err) = host_cb.keyring_put(backend_kind, conn, REFRESH_TOKEN_FIELD, &value) {
        tracing::warn!(
            plugin,
            key = %conn.0,
            error = %err,
            "keyring_put failed; refresh_token will not survive process exit",
        );
    }
}

pub fn delete_refresh_token(plugin: &str, backend_kind: &str, conn: &ConnectionId) {
    let Some(host_cb) = shim::host() else {
        return;
    };
    if let Err(err) = host_cb.keyring_delete(backend_kind, conn, REFRESH_TOKEN_FIELD)
        && err.code() != ErrorCode::NotFound
    {
        tracing::warn!(plugin, key = %conn.0, error = %err, "keyring_delete failed");
    }
}

/// Build the SecretBundle shape `update_credentials` expects from a
/// resolved access/refresh/expiry triple.
pub fn oauth_bundle(
    access: &str,
    refresh: Option<&str>,
    expires_at: Option<SystemTime>,
) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "oauth".into(),
        SecretValue::OAuthToken {
            token: SecretBytes(access.as_bytes().to_vec()),
            refresh: refresh.map(|r| SecretBytes(r.as_bytes().to_vec())),
            expires_at,
        },
    );
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_id_from_url_uses_host() {
        let id = conn_id_from_url("https://storage.example.com/discovery");
        assert_eq!(id.0, "storage.example.com");
    }

    #[test]
    fn conn_id_from_url_falls_back_to_raw_when_unparseable() {
        let id = conn_id_from_url("not a url");
        assert_eq!(id.0, "not a url");
    }

    #[test]
    fn oauth_bundle_round_trips_optional_fields() {
        let now = SystemTime::now();
        let bundle = oauth_bundle("AT", Some("RT"), Some(now));
        match bundle.fields.get("oauth").unwrap() {
            SecretValue::OAuthToken {
                token,
                refresh,
                expires_at,
            } => {
                assert_eq!(token.0, b"AT");
                assert_eq!(refresh.as_ref().unwrap().0, b"RT");
                assert_eq!(*expires_at, Some(now));
            }
            _ => panic!("expected OAuthToken"),
        }
    }

    #[test]
    fn oauth_bundle_omits_refresh_when_none() {
        let bundle = oauth_bundle("AT", None, None);
        match bundle.fields.get("oauth").unwrap() {
            SecretValue::OAuthToken {
                refresh,
                expires_at,
                ..
            } => {
                assert!(refresh.is_none());
                assert!(expires_at.is_none());
            }
            _ => panic!("expected OAuthToken"),
        }
    }
}
