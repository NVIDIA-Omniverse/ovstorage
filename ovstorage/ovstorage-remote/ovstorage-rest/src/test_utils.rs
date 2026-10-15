// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only fixture helpers; the build script populates a per-`OUT_DIR`
//! plugin fixture and exports its path as `OVSTORAGE_REST_TEST_PLUGIN_DIR`.

#![cfg(test)]

use std::path::PathBuf;

use ovstorage::{ConfigValue, ConnectionConfig, ConnectionRequest, LayerConfig};
use ovstorage_authz_layer::{ANONYMOUS_ALLOW_ALL_POLICY, POLICY_CONFIG_KEY};

use ovstorage_authz::UserMetadataKinds;

use crate::stack::rest_stack_config;
use crate::{GatewayStack, GatewayStackBuilder, RestJwtParams};

/// Assemble the built-in auth layer's [`LayerConfig`] for tests: an unset policy
/// is the explicit anonymous allow-all (the single allow-all home in the auth
/// crate), a set policy gates, and JWT params configure `Tcp` bearer authn.
fn test_auth_config(policy_toml: Option<&str>, jwt: Option<&RestJwtParams>) -> LayerConfig {
    let mut config = LayerConfig::new();
    let policy = policy_toml
        .map(str::to_string)
        .unwrap_or_else(|| ANONYMOUS_ALLOW_ALL_POLICY.to_string());
    config.insert(POLICY_CONFIG_KEY.to_string(), ConfigValue::Toml(policy));
    if let Some(jwt) = jwt {
        jwt.apply_to(&mut config);
    }
    config
}

/// Path to the build-script-populated plugin fixture directory.
pub(crate) fn workspace_plugin_dir() -> PathBuf {
    PathBuf::from(env!("OVSTORAGE_REST_TEST_PLUGIN_DIR"))
}

/// Compose the gateway's per-listener auth Stack over the build-script fixture
/// plugins, applying `connections`. The auth layer carries the builder's
/// allow-all default policy. Shared setup for the REST unit tests.
pub(crate) async fn test_gateway(connections: Vec<ConnectionRequest>) -> GatewayStack {
    test_gateway_inner(connections, None, None, false).await
}

/// [`test_gateway`] with the operator's `redirect_credential_disclosure` set.
/// `true` is `allow`; the default is the shipped `refuse`.
pub(crate) async fn test_gateway_disclosing_redirects(
    connections: Vec<ConnectionRequest>,
) -> GatewayStack {
    test_gateway_inner(connections, None, None, true).await
}

/// [`test_gateway`] with the built-in auth layer's policy set from `policy_toml`.
pub(crate) async fn test_gateway_with_authz(
    connections: Vec<ConnectionRequest>,
    policy_toml: &str,
) -> GatewayStack {
    test_gateway_inner(connections, Some(policy_toml), None, false).await
}

/// [`test_gateway`] with the built-in auth layer configured for OIDC bearer-JWT
/// authn. `policy_toml` scopes authorization; `None` uses the
/// allow-all default.
pub(crate) async fn test_gateway_with_jwt(
    connections: Vec<ConnectionRequest>,
    jwt: RestJwtParams,
    policy_toml: Option<&str>,
) -> GatewayStack {
    test_gateway_inner(connections, policy_toml, Some(jwt), false).await
}

/// A gateway whose declared graph contains **no** `redirect_follower` at all —
/// the layer graph is operator config and may omit it, and this is the shape
/// that leaves the handler as the only thing between a backend's redirect and
/// the client. Its `copy_rename_fallback` points straight at the router.
pub(crate) async fn test_gateway_without_a_follower(
    connections: Vec<ConnectionRequest>,
) -> GatewayStack {
    let mut stack_config = rest_stack_config(
        connections
            .into_iter()
            .map(ConnectionConfig::from_request)
            .collect(),
        &UserMetadataKinds::from_factories(&[]),
    );
    stack_config.layers.remove("redirect_follower");
    stack_config
        .layers
        .get_mut("copy_rename_fallback")
        .expect("the REST twin declares copy_rename_fallback")
        .inner = Some("router".into());
    build_test_gateway(stack_config, None, None, false).await
}

async fn test_gateway_inner(
    connections: Vec<ConnectionRequest>,
    policy_toml: Option<&str>,
    jwt: Option<RestJwtParams>,
    disclose_redirect_credentials: bool,
) -> GatewayStack {
    // Emit the REST default forward graph over the fixture's connections; the
    // builder hands it verbatim to `build_stack`.
    let stack_config = rest_stack_config(
        connections
            .into_iter()
            .map(ConnectionConfig::from_request)
            .collect(),
        &UserMetadataKinds::from_factories(&[]),
    );
    build_test_gateway(
        stack_config,
        policy_toml,
        jwt,
        disclose_redirect_credentials,
    )
    .await
}

/// Build a gateway over an arbitrary declared graph.
async fn build_test_gateway(
    stack_config: ovstorage::StackConfig,
    policy_toml: Option<&str>,
    jwt: Option<RestJwtParams>,
    disclose_redirect_credentials: bool,
) -> GatewayStack {
    // Deliberately ONE directory per process, with no uniquifying suffix.
    // `ovstorage::init_auth_substrate` keeps a process-global substrate and
    // rejects a second call naming a different `auth_dir`, so a per-fixture
    // auth root makes every gateway after the first fail to build. The pid
    // is all the isolation this name needs, and all it may have.
    let auth_root =
        std::env::temp_dir().join(format!("ovstorage-rest-test-auth-{}", std::process::id()));
    std::fs::create_dir_all(&auth_root).unwrap();
    let auth_config = test_auth_config(policy_toml, jwt.as_ref());
    let builder = GatewayStackBuilder::new()
        .plugin_dir(workspace_plugin_dir())
        .auth_dir(auth_root)
        // `allow_test_plugins(true)` is required by core's `test_only`
        // plugin manifest gate.
        .allow_test_plugins(true)
        .stack_config(stack_config)
        .redirect_disclosure(disclose_redirect_credentials)
        .auth_config(auth_config);
    // SAFETY: dlopen of the build-script fixture only.
    unsafe { builder.build().await.expect("gateway build") }
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
