// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only fixture helpers; the build script populates a per-`OUT_DIR`
//! plugin fixture and exports its path as `OVSTORAGE_REST_TEST_PLUGIN_DIR`.

#![cfg(test)]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use ovstorage::auth::{AuthRefreshLock, SecretStore};
use ovstorage::{Library, LibraryBuilder};

/// Path to the build-script-populated plugin fixture directory.
pub(crate) fn workspace_plugin_dir() -> PathBuf {
    PathBuf::from(env!("OVSTORAGE_REST_TEST_PLUGIN_DIR"))
}

pub(crate) trait BuilderTestExt {
    fn open_with_test_plugins(self) -> Arc<Library>;
}

impl BuilderTestExt for LibraryBuilder {
    fn open_with_test_plugins(self) -> Arc<Library> {
        let (secret_store, refresh_lock) = shared_test_substrate();
        let library = self
            .with_credential_persistence(secret_store.clone(), refresh_lock.clone())
            // `allow_test_plugins(true)` is required by core's `test_only`
            // plugin manifest gate.
            .allow_test_plugins(true)
            .open()
            .expect("library open");
        // SAFETY: dlopen of the build-script fixture only.
        unsafe {
            library
                .load_plugins_from_dir(Some(&workspace_plugin_dir()))
                .expect("dlopen test plugins");
        }
        library
    }
}

fn shared_test_substrate() -> &'static (Arc<SecretStore>, Arc<AuthRefreshLock>) {
    static SHARED: OnceLock<(Arc<SecretStore>, Arc<AuthRefreshLock>)> = OnceLock::new();
    SHARED.get_or_init(|| {
        let auth_root =
            std::env::temp_dir().join(format!("ovstorage-rest-test-auth-{}", std::process::id()));
        std::fs::create_dir_all(&auth_root).unwrap();
        (
            Arc::new(SecretStore::new()),
            Arc::new(AuthRefreshLock::open(&auth_root).unwrap()),
        )
    })
}

/// Mint an HS256-signed JWT for tests; pair with `spawn_test_jwks_server`.
pub(crate) fn signed_test_jwt(
    subject: &str,
    issuer: &str,
    audience: &str,
    kid: &str,
    secret: &[u8],
    expiry_offset_seconds: i64,
) -> String {
    signed_test_jwt_with_nbf(
        subject,
        issuer,
        audience,
        kid,
        secret,
        expiry_offset_seconds,
        -60,
    )
}

pub(crate) fn signed_test_jwt_with_nbf(
    subject: &str,
    issuer: &str,
    audience: &str,
    kid: &str,
    secret: &[u8],
    expiry_offset_seconds: i64,
    nbf_offset_seconds: i64,
) -> String {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Claims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        nbf: u64,
    }

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(
        &header,
        &Claims {
            sub: subject,
            iss: issuer,
            aud: audience,
            exp: jwt_timestamp(expiry_offset_seconds),
            nbf: jwt_timestamp(nbf_offset_seconds),
        },
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap()
}

pub(crate) fn jwt_timestamp(offset_seconds: i64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    now.saturating_add(offset_seconds).max(0) as u64
}

/// Build a single-key JWKS JSON document for `(kid, HS256 secret)`.
pub(crate) fn jwks_value(kid: &str, secret: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    json!({
        "keys": [
            {
                "kty": "oct",
                "kid": kid,
                "alg": "HS256",
                "k": URL_SAFE_NO_PAD.encode(secret),
            }
        ]
    })
}

/// Mutable JWKS state used by `spawn_rotatable_test_jwks_server` to
/// simulate key rotation.
pub(crate) type RotatableJwks = Arc<std::sync::Mutex<serde_json::Value>>;

/// Like `spawn_test_jwks_server` but with a swappable JWKS document.
pub(crate) fn spawn_rotatable_test_jwks_server(
    kid: &str,
    secret: &[u8],
) -> (String, tokio::sync::oneshot::Sender<()>, RotatableJwks) {
    use axum::routing::get;
    use axum::{Json, Router};

    let jwks: RotatableJwks = Arc::new(std::sync::Mutex::new(jwks_value(kid, secret)));
    let app = Router::new().route(
        "/jwks",
        get({
            let jwks = jwks.clone();
            move || {
                let jwks = jwks.clone();
                async move {
                    let value = jwks.lock().unwrap().clone();
                    Json(value)
                }
            }
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ovs-test-jwks".into())
        .spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });
        })
        .expect("failed to spawn thread");
    (format!("http://{addr}/jwks"), shutdown, jwks)
}

/// Spawn an axum HTTP server exposing a static JWKS document at `/jwks`.
pub(crate) fn spawn_test_jwks_server(
    kid: &str,
    secret: &[u8],
) -> (String, tokio::sync::oneshot::Sender<()>) {
    use axum::routing::get;
    use axum::{Json, Router};

    let jwks = jwks_value(kid, secret);
    let app = Router::new().route(
        "/jwks",
        get(move || {
            let jwks = jwks.clone();
            async move { Json(jwks) }
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ovs-test-jwks".into())
        .spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .unwrap();
            });
        })
        .expect("failed to spawn thread");
    (format!("http://{addr}/jwks"), shutdown)
}
