// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use axum::body::Body as AxumBody;
use axum::http::{Method, Request};
use http_body_util::BodyExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

#[tokio::test]
async fn object_routes_use_documented_paths_and_headers() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let object = address::join_relative(&prefix, "object.txt").unwrap();

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .header("If-None-Match", "*")
                .body(AxumBody::from("abcdef"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .header("If-None-Match", "*")
                .body(AxumBody::from("replacement"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);

    let range = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects?address={object}"))
                .header("Range", "bytes=1-3")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(range.status(), StatusCode::OK);
    let bytes = range.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..], b"bcd");

    let stat = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:stat?address={object}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stat.status(), StatusCode::OK);
    let body = stat.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["size"], 6);
    let etag = json["etag"]
        .as_str()
        .expect("file plugin synthesizes an etag")
        .to_string();

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:list?prefix={prefix}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);

    let delete = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v1/objects?address={object}"))
                .header("If-Match", format!("\"{etag}\""))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn copy_rename_metadata_round_trip_through_router() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let src = address::join_relative(&prefix, "src.txt").unwrap();
    let copied = address::join_relative(&prefix, "copied.txt").unwrap();
    let renamed = address::join_relative(&prefix, "renamed.txt").unwrap();

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={src}"))
                .body(AxumBody::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);

    let copy = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .body(AxumBody::from(format!(
                    r#"{{"src":"{src}","dest":"{copied}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(copy.status(), StatusCode::OK);

    let rename = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:rename")
                .header("content-type", "application/json")
                .body(AxumBody::from(format!(
                    r#"{{"src":"{copied}","dest":"{renamed}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rename.status(), StatusCode::NO_CONTENT);

    let metadata = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/v1/objects:metadata?address={renamed}"))
                .header("content-type", "application/json")
                .body(AxumBody::from(r#"{"set":{"author":"brian"}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    let body = metadata.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["user_metadata"]["author"], "brian");

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn directory_create_delete_round_trip() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let dir = address::join_relative(&prefix, "nested/").unwrap();

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/directories?address={dir}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    assert!(root.join("nested").is_dir());

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v1/directories?address={dir}&recursive=true"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert!(!root.join("nested").exists());

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn discovery_endpoints_return_json() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);

    let caps = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/capabilities?prefix={prefix}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(caps.status(), StatusCode::OK);
    let body = caps.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["writes_are_atomic"], true);

    let roots = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/address-roots")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(roots.status(), StatusCode::OK);
    let body = roots.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["items"].as_array().unwrap().iter().any(|item| {
        item["address"]
            .as_str()
            .unwrap()
            .starts_with(prefix.as_str())
    }));

    let kinds = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(kinds.status(), StatusCode::OK);
    let body = kinds.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let kinds_list = json["items"].as_array().unwrap();
    assert!(kinds_list.iter().any(|k| k["kind"] == "file"));

    std::fs::remove_dir_all(root).unwrap();
}

/// Policy TOML: allow everything, then deny `Write` everywhere — the auth-layer
/// policy equivalent of the retired write-denying test plugin.
const DENY_WRITE_POLICY: &str = "\
plugin = \"ovstorage-authz-toml\"

[[policy]]
id = \"allow-all\"
effect = \"allow\"
principal = \"*\"
operations = [\"*\"]
prefix = \"*\"

[[policy]]
id = \"deny-write\"
effect = \"deny\"
principal = \"*\"
operations = [\"write\"]
prefix = \"*\"
";

#[tokio::test]
async fn authz_denial_returns_403_with_reason() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let mut config = HashMap::new();
    config.insert(
        "root".to_string(),
        ovstorage::ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    let gateway = crate::test_utils::test_gateway_with_authz(
        vec![ovstorage::ConnectionRequest {
            backend_kind: "file".into(),
            config,
            credentials: ovstorage::SecretBundle::default(),
            persist: false,
            display_name: None,
        }],
        DENY_WRITE_POLICY,
    )
    .await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let object = address::join_relative(&prefix, "denied.txt").unwrap();

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .body(AxumBody::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::FORBIDDEN);
    let body = put.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "PermissionDenied");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("denied by policy"),
        "expected the Layer's policy-deny reason: {json}"
    );

    let list = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:list?prefix={prefix}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn openapi_endpoint_renders_a_document_listing_object_paths() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let app = router(gateway);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/openapi.json")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(doc["paths"]["/v1/objects"]["get"].is_object());
    assert!(doc["paths"]["/v1/objects:copy"]["post"].is_object());
    assert!(doc["paths"]["/v1/openapi.yaml"]["get"].is_object());
    assert_eq!(doc["info"]["title"], "ovstorage REST");

    let yaml_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/openapi.yaml")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(yaml_response.status(), StatusCode::OK);
    let yaml_body = yaml_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let yaml = std::str::from_utf8(&yaml_body).unwrap();
    assert!(yaml.contains("/v1/objects"));
    std::fs::remove_dir_all(root).unwrap();
}

/// Drift test: rewrites `spec/openapi.yaml` and fails if the
/// committed contents differed. Re-run after handler/schema edits
/// and `git add` the updated file.
#[test]
fn openapi_yaml_is_regenerated_and_fails_on_drift() {
    let runtime = serde_yaml::to_string(&openapi_spec()).unwrap();
    let committed_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/openapi.yaml");
    std::fs::create_dir_all(committed_path.parent().unwrap()).unwrap();
    let drifted = match std::fs::read_to_string(&committed_path) {
        Ok(committed) => committed != runtime,
        Err(_) => true,
    };
    std::fs::write(&committed_path, &runtime).unwrap();
    assert!(
        !drifted,
        "spec/openapi.yaml was out of date; rewrote it. Re-run tests; commit the updated file.",
    );
}

static TEMP_DIR_SERIAL: AtomicU64 = AtomicU64::new(0);

fn next_temp_dir_serial() -> u64 {
    TEMP_DIR_SERIAL.fetch_add(1, Ordering::Relaxed)
}

/// The naming rule, with both varying inputs supplied by the caller.
///
/// Split out so a test can freeze the clock reading; see the broker's
/// `temp_dir_named` for why a test that calls `unique_temp_dir()` twice does
/// not guard the serial.
fn temp_dir_named(stamp: u128, serial: u64) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ovstorage-rest-test-{}-{stamp}-{serial}",
        std::process::id()
    ))
}

/// A temporary root no other call in this process can name.
///
/// The serial, not the clock, is what guarantees uniqueness within a process:
/// two calls close enough together share a `SystemTime::now()` reading, and a
/// collision silently merges two roots a test meant to keep apart. Same
/// helper, same reasoning, as the broker's `unique_temp_dir`, which carries
/// the note on why three copies exist.
fn unique_temp_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    temp_dir_named(stamp, next_temp_dir_serial())
}

#[test]
fn same_tick_temp_dirs_differ() {
    const FROZEN_TICK: u128 = 1_700_000_000_000_000_000;

    let first = temp_dir_named(FROZEN_TICK, next_temp_dir_serial());
    let second = temp_dir_named(FROZEN_TICK, next_temp_dir_serial());
    assert_ne!(
        first, second,
        "two temp roots minted in the same clock tick must not collide"
    );
}

#[test]
fn concurrent_temp_dirs_are_all_distinct() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 64;

    let paths: Vec<PathBuf> = std::thread::scope(|scope| {
        // Every thread is spawned before any is joined, so the calls really do
        // overlap.
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                (0..PER_THREAD)
                    .map(|_| unique_temp_dir())
                    .collect::<Vec<_>>()
            }));
        }
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    });

    let distinct: std::collections::HashSet<_> = paths.iter().collect();
    assert_eq!(
        distinct.len(),
        THREADS * PER_THREAD,
        "{} of {} concurrently minted temp roots collided",
        THREADS * PER_THREAD - distinct.len(),
        THREADS * PER_THREAD
    );
}

async fn build_test_gateway_with_file_root(root: &Path) -> GatewayStack {
    let mut config = HashMap::new();
    config.insert(
        "root".to_string(),
        ovstorage::ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    let request = ovstorage::ConnectionRequest {
        backend_kind: "file".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    crate::test_utils::test_gateway(vec![request]).await
}

async fn build_plugin_auth_gateway_with_file_root(root: &Path) -> GatewayStack {
    let connection = ovstorage::ConnectionConfig::from_request(ovstorage::ConnectionRequest {
        backend_kind: "file".into(),
        config: HashMap::from([(
            "root".to_string(),
            ovstorage::ConfigValue::String(root.to_string_lossy().into_owned()),
        )]),
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: Some("rest-plugin-auth".into()),
    });
    let auth = toml::Value::Table(toml::Table::from_iter([(
        "kind".to_string(),
        toml::Value::String("mini-auth".to_string()),
    )]));
    // SAFETY: the REST build script stages only this workspace's test plugins
    // in the fixture directory.
    unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(crate::test_utils::workspace_plugin_dir())
            .allow_test_plugins(true)
            .stack_config(rest_stack_config(
                vec![connection],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .listener_auth(Some(auth), "rest-plugin-auth")
            .build()
            .await
            .expect("compose REST with the loaded mini-auth wrapper")
    }
}

#[tokio::test]
async fn loaded_plugin_auth_gates_rest_data_and_backend_kind_routes() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "authorized.txt").unwrap();
    let app = router(build_plugin_auth_gateway_with_file_root(&root).await);

    let allowed_write = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .header("Authorization", "Bearer alice")
                .body(AxumBody::from("allowed"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed_write.status(), StatusCode::OK);

    let allowed_stat = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:stat?address={object}"))
                .header("Authorization", "Bearer alice")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed_stat.status(), StatusCode::OK);

    let denied_stat = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:stat?address={object}"))
                .header("Authorization", "Bearer deny")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_stat.status(), StatusCode::FORBIDDEN);

    let allowed_kinds = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", "Bearer alice")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed_kinds.status(), StatusCode::OK);
    let body = allowed_kinds
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| { kind["kind"] == "file" })
    );

    let denied_kinds = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", "Bearer deny")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_kinds.status(), StatusCode::FORBIDDEN);
    std::fs::remove_dir_all(root).unwrap();
}

// OIDC bearer-JWT authn lives in the gateway's built-in auth layer: the gateway
// is composed with `.jwt(...)`, and the credential-gathering seam hands the
// UNDECODED bearer to the auth layer, which validates it and resolves the
// principal. There is no host-side JWT middleware.
const JWT_ISSUER: &str = "https://issuer.test";
const JWT_AUDIENCE: &str = "ovstorage-rest";
const JWT_SECRET: &[u8] = b"test-secret-bytes-bytes-bytes-bytes!";
const JWT_KID: &str = "test-key";

/// Build a JWT-authn gateway (test backend at `test://demo/`) whose auth layer
/// validates bearers against `jwks_url`. `policy` scopes authorization; `None`
/// uses the allow-all default.
async fn jwt_gateway(jwks_url: String, policy: Option<&str>) -> GatewayStack {
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String("test://demo/".into()),
    );
    let request = ovstorage::ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    crate::test_utils::test_gateway_with_jwt(
        vec![request],
        crate::RestJwtParams {
            issuer: JWT_ISSUER.into(),
            audience: JWT_AUDIENCE.into(),
            jwks_url,
        },
        policy,
    )
    .await
}

/// GET `/v1/objects:list?prefix=test://demo/` with an optional `Authorization`
/// header; returns the HTTP status.
async fn list_status(app: &Router, authorization: Option<&str>) -> StatusCode {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri("/v1/objects:list?prefix=test://demo/");
    if let Some(value) = authorization {
        builder = builder.header("Authorization", value);
    }
    app.clone()
        .oneshot(builder.body(AxumBody::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn jwt_valid_token_admits_request() {
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        JWT_ISSUER,
        JWT_AUDIENCE,
        JWT_KID,
        JWT_SECRET,
        3600,
    );
    // Allow-all default policy admits the resolved principal ⇒ exactly 200.
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {token}"))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn jwt_missing_token_is_unauthorized() {
    // A JWT-configured listener fails closed: a missing bearer on a `Tcp`
    // transport is `AuthRequired` → 401, NOT silently anonymous. An explicitly
    // anonymous listener would use `auth =
    // "anonymous"` instead of a JWT config.
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    assert_eq!(list_status(&app, None).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_basic_auth_returns_401() {
    // A non-`Bearer` scheme value passes through to the auth layer UNDECODED and
    // fails JWT validation → AuthRequired → 401.
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    assert_eq!(
        list_status(&app, Some("Basic dXNlcjpwYXNz")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jwt_expired_token_returns_401() {
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        JWT_ISSUER,
        JWT_AUDIENCE,
        JWT_KID,
        JWT_SECRET,
        -3600,
    );
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {token}"))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jwt_wrong_issuer_returns_401() {
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        "https://wrong-issuer.test",
        JWT_AUDIENCE,
        JWT_KID,
        JWT_SECRET,
        3600,
    );
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {token}"))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jwt_wrong_audience_returns_401() {
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        JWT_ISSUER,
        "other-audience",
        JWT_KID,
        JWT_SECRET,
        3600,
    );
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {token}"))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn jwt_future_nbf_returns_401() {
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, None).await);
    let token = crate::test_utils::signed_test_jwt_with_nbf(
        "alice",
        JWT_ISSUER,
        JWT_AUDIENCE,
        JWT_KID,
        JWT_SECRET,
        3600,
        3600,
    );
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {token}"))).await,
        StatusCode::UNAUTHORIZED
    );
}

/// The auth layer resolves the JWT `sub` to a principal and authorizes against
/// it: a policy scoped to `alice` admits alice's token and denies bob's — proof
/// the request is principal-scoped end-to-end.
#[tokio::test]
async fn jwt_principal_scoped_authz() {
    const ALICE_ONLY_POLICY: &str = "\
plugin = \"ovstorage-authz-toml\"

[[policy]]
id = \"alice-all\"
effect = \"allow\"
principal = \"alice\"
operations = [\"*\"]
prefix = \"*\"
";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server(JWT_KID, JWT_SECRET);
    let app = router(jwt_gateway(jwks_url, Some(ALICE_ONLY_POLICY)).await);

    let alice = crate::test_utils::signed_test_jwt(
        "alice",
        JWT_ISSUER,
        JWT_AUDIENCE,
        JWT_KID,
        JWT_SECRET,
        3600,
    );
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {alice}"))).await,
        StatusCode::OK,
        "alice is allowed by the policy"
    );

    let bob = crate::test_utils::signed_test_jwt(
        "bob",
        JWT_ISSUER,
        JWT_AUDIENCE,
        JWT_KID,
        JWT_SECRET,
        3600,
    );
    assert_eq!(
        list_status(&app, Some(&format!("Bearer {bob}"))).await,
        StatusCode::FORBIDDEN,
        "bob is denied by the alice-only policy"
    );
}

#[tokio::test]
async fn read_with_redirect_url_returns_307_with_location() {
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String("test://b3-rest-redirect/".into()),
    );
    config.insert(
        "test_redirect_url".into(),
        ovstorage::ConfigValue::String("https://upstream.example".into()),
    );
    let gateway = crate::test_utils::test_gateway(vec![ovstorage::ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    }])
    .await;

    let app = router(gateway);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects?address=test://b3-rest-redirect/foo.txt")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("redirect must include Location header");
    assert!(
        location
            .to_str()
            .unwrap()
            .starts_with("https://upstream.example")
    );
}

/// A `test`-backend connection minting redirects that declare `credential`.
fn redirecting_connection(root: &str, credential: &str) -> ovstorage::ConnectionRequest {
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String(root.into()),
    );
    config.insert(
        "test_redirect_url".into(),
        ovstorage::ConfigValue::String("https://upstream.example".into()),
    );
    config.insert(
        "test_redirect_credential".into(),
        ovstorage::ConfigValue::String(credential.into()),
    );
    ovstorage::ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    }
}

async fn read_object_response(gateway: GatewayStack, address: &str) -> axum::response::Response {
    router(gateway)
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects?address={address}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// The gateway's `307` carries the redirect URL and no request headers, so what
/// the disclosure policy withholds here is a credential riding in the URL's
/// query — an operator-supplied Azure `sas_token` is the live shape. The
/// backend declares that; the gateway cannot tell such a URL from a presigned
/// one by looking at it.
///
/// Under the shipped default the redirect is not surfaced. The follower in the
/// graph runs `follow_reads = false`, so it fetches the object itself and the
/// handler streams the bytes: a `200`, not a failure.
#[tokio::test]
async fn a_connection_scoped_read_redirect_is_not_surfaced_as_a_307() {
    let (responder, redirect_kv) = ovstorage_plugin_test::start_responder_with_redirect(vec![
        ovstorage_plugin_test::Route::new(
            "GET",
            "/",
            ovstorage_plugin_test::ScriptedResponse::ok(b"redirected bytes"),
        ),
    ])
    .expect("loopback responder binds");
    let mut connection = redirecting_connection("test://rest-wide-redirect/", "connection");
    connection
        .config
        .insert(redirect_kv.0.into(), redirect_kv.1);

    let gateway = crate::test_utils::test_gateway(vec![connection]).await;
    let response = read_object_response(gateway, "test://rest-wide-redirect/foo.txt").await;

    assert!(
        response
            .headers()
            .get(axum::http::header::LOCATION)
            .is_none(),
        "no Location header may carry the redirect URL when the policy refuses"
    );
    // `assert_eq!(OK)`, not `assert_ne!(307)`. Both halves of the claim matter
    // and only one of them is about disclosure: the redirect must not be
    // surfaced, AND the read must still succeed, because the follower holds an
    // open connection and fetching the bytes here discloses nothing. A weaker
    // `assert_ne!` is satisfied by a 5xx — which is exactly what a fixture
    // pointing at a hostname that does not resolve would produce, passing the
    // test while demonstrating the opposite of the availability half. Hence the
    // live loopback responder.
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a refused redirect must degrade to the gateway serving the bytes, not fail"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"redirected bytes");
    assert!(
        !responder.captures().is_empty(),
        "the gateway must have fetched the object itself; an empty capture list          means the fixture never redirected and this test proved nothing"
    );
}

/// The same backend and the same redirect, one operator key different. Without
/// this arm the assertion above would be satisfied by a gateway that never
/// redirects at all.
#[tokio::test]
async fn the_operator_can_opt_in_to_the_same_read_redirect() {
    let gateway =
        crate::test_utils::test_gateway_disclosing_redirects(vec![redirecting_connection(
            "test://rest-wide-allowed/",
            "connection",
        )])
        .await;

    let response = read_object_response(gateway, "test://rest-wide-allowed/foo.txt").await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(
        response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("`allow` surfaces the redirect the default withholds")
            .to_str()
            .unwrap()
            .starts_with("https://upstream.example")
    );
}

/// The out-edge guard on its own, with nothing upstream that could also catch
/// the redirect.
///
/// The test above passes as soon as *something* withholds the redirect, and in
/// a stock graph the follower gets there first — so on its own it would prove
/// the handler's check nothing. The layer graph is operator config and can omit
/// the follower entirely; this builds exactly that graph, which leaves the
/// handler as the only thing between the backend and the client.
///
/// There are no bytes in reach at this point — the follower that would have
/// fetched them is not in the graph — so the only available answer is a
/// refusal, and it is a `403` rather than a degraded read.
#[tokio::test]
async fn the_handler_refuses_when_no_follower_is_in_the_graph_to_refuse_first() {
    let gateway = crate::test_utils::test_gateway_without_a_follower(vec![redirecting_connection(
        "test://rest-no-follower/",
        "connection",
    )])
    .await;

    let response = read_object_response(gateway, "test://rest-no-follower/foo.txt").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .headers()
            .get(axum::http::header::LOCATION)
            .is_none(),
        "the refusal must not carry the redirect URL it refused"
    );
}

/// The same follower-less graph, request-scoped: the handler forwards it.
/// Without this arm the refusal above would be satisfied by a graph that simply
/// cannot serve redirects.
#[tokio::test]
async fn the_handler_forwards_a_request_scoped_redirect_with_no_follower_present() {
    let gateway = crate::test_utils::test_gateway_without_a_follower(vec![redirecting_connection(
        "test://rest-no-follower-narrow/",
        "request",
    )])
    .await;

    let response = read_object_response(gateway, "test://rest-no-follower-narrow/foo.txt").await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
}

/// A redirect scoped to the redirected request is surfaced under **both**
/// settings — a presigned URL discloses nothing beyond the object being
/// transferred, and withholding it would cost every deployment the redirect
/// path in exchange for nothing.
#[tokio::test]
async fn a_request_scoped_read_redirect_is_surfaced_under_the_default() {
    let gateway = crate::test_utils::test_gateway(vec![redirecting_connection(
        "test://rest-narrow-redirect/",
        "request",
    )])
    .await;

    let response = read_object_response(gateway, "test://rest-narrow-redirect/foo.txt").await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
}

#[tokio::test]
async fn read_without_redirect_returns_200_bytes() {
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String("test://b3-rest-bytes/".into()),
    );
    let gateway = crate::test_utils::test_gateway(vec![ovstorage::ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    }])
    .await;

    let app = router(gateway);
    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/objects?dest=test://b3-rest-bytes/hello.txt")
                .body(AxumBody::from("hello"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);
    let get = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects?address=test://b3-rest-bytes/hello.txt")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let body = get.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello");
}

fn address_for_path(path: &Path) -> Url {
    let mut path = path.to_string_lossy().replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    address::parse(&format!("file:{path}")).unwrap()
}

#[tokio::test]
async fn list_recursive_with_garbage_returns_400() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:list?prefix={prefix}&recursive=maybe"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "InvalidArgument");
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn list_versions_max_results_garbage_returns_400() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let object = address::join_relative(&prefix, "obj.txt").unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/v1/objects:versions?address={object}&max_results=abc"
                ))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "InvalidArgument");
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn watch_poll_interval_zero_returns_400() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/v1/objects:watch-directory?prefix={prefix}&poll_interval_ms=0"
                ))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "InvalidArgument");
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn backend_kinds_discovery_reflects_routed_kinds() {
    // The discovery endpoint gates `supports_runtime_add` on the kinds the graph
    // routes (a Router child), not the raw startup connection list: `file`
    // (routed) is true, `test` (loaded but unrouted) is false. In this fixture
    // the routed set equals the connected set; the graph-vs-connections
    // distinction is covered by the `stack` unit test.
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let app = router(gateway);

    let kinds = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(kinds.status(), StatusCode::OK);
    let body = kinds.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let items = json["items"].as_array().unwrap();
    let runtime_add = |kind: &str| -> Option<bool> {
        items
            .iter()
            .find(|k| k["kind"] == kind)
            .map(|k| k["supports_runtime_add"].as_bool().unwrap())
    };
    assert_eq!(runtime_add("file"), Some(true));
    assert_eq!(runtime_add("test"), Some(false));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn runtime_management_routes_are_removed() {
    // Connections/aliases/visibility are operator config only.
    // There are no runtime management endpoints; the router returns 404 for them.
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let app = router(gateway);

    let cases = [
        (
            Method::POST,
            "/v1/connections",
            r#"{"backend_kind":"test"}"#,
        ),
        (
            Method::POST,
            "/v1/aliases",
            r#"{"from":"file:///a/","to":"file:///b/"}"#,
        ),
        (
            Method::PUT,
            "/v1/address-visibility",
            r#"{"address":"file:///a/","visibility":"hidden"}"#,
        ),
    ];
    for (method, uri, body) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(AxumBody::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{method} {uri} should be removed"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn metadata_set_and_remove_same_key_returns_400() {
    // The handler must reject setting and removing the same key; the Stack does
    // not re-validate, so an overlap would otherwise
    // silently resolve to a set (file backend applies remove-then-set).
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let object = address::join_relative(&prefix, "obj.txt").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri(format!("/v1/objects:metadata?address={object}"))
                .header("content-type", "application/json")
                .body(AxumBody::from(r#"{"set":{"k":"v"},"remove":["k"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "InvalidArgument");
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn watch_poll_interval_garbage_returns_400() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let gateway = build_test_gateway_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(gateway);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/v1/objects:watch-directory?prefix={prefix}&poll_interval_ms=bad"
                ))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    std::fs::remove_dir_all(root).unwrap();
}
