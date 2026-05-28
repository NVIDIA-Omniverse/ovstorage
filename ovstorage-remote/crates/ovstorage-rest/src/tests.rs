// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use axum::body::Body as AxumBody;
use axum::http::{Method, Request};
use http_body_util::BodyExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

#[tokio::test]
async fn object_routes_use_documented_paths_and_headers() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);

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

/// Test authz plugin that denies a configured set of operations.
struct DenyingAuthz {
    denied: Vec<Operation>,
}

#[async_trait::async_trait]
impl ovstorage_authz::AuthzPlugin for DenyingAuthz {
    fn plugin_name(&self) -> &str {
        "test-denying"
    }
    async fn authorize(
        &self,
        request: &AuthzRequest,
    ) -> ovstorage::Result<ovstorage_authz::AuthzDecision> {
        if self.denied.contains(&request.operation) {
            Ok(ovstorage_authz::AuthzDecision::deny(
                "denied by test plugin",
            ))
        } else {
            Ok(ovstorage_authz::AuthzDecision::allow())
        }
    }
}

#[tokio::test]
async fn authz_denial_returns_403_with_reason() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let authz: Arc<dyn ovstorage_authz::AuthzPlugin> = Arc::new(DenyingAuthz {
        denied: vec![Operation::Write],
    });
    let app = router(library, None, Some(authz));
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
            .contains("denied by test plugin")
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
    let library = build_test_library_with_file_root(&root).await;
    let app = router(library, None, None);

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

fn unique_temp_dir() -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ovstorage-rest-test-{}-{stamp}",
        std::process::id()
    ))
}

async fn build_test_library_with_file_root(root: &Path) -> Arc<Library> {
    let library = {
        use crate::test_utils::BuilderTestExt;
        Library::builder().open_with_test_plugins()
    };
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
    library.add_connection(request, None).await.unwrap();
    library
}

#[tokio::test]
async fn jwt_valid_token_admits_request() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "test-key",
        secret,
        3600,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .header("Authorization", format!("Bearer {token}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_missing_token_returns_401() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_basic_auth_returns_401() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .header("Authorization", "Basic dXNlcjpwYXNz")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_expired_token_returns_401() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "test-key",
        secret,
        -3600,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .header("Authorization", format!("Bearer {token}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_wrong_issuer_returns_401() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        "https://wrong-issuer.test",
        "ovstorage-rest",
        "test-key",
        secret,
        3600,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .header("Authorization", format!("Bearer {token}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_wrong_audience_returns_401() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "other-audience",
        "test-key",
        secret,
        3600,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .header("Authorization", format!("Bearer {token}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_future_nbf_returns_401() {
    let secret = b"test-secret-bytes-bytes-bytes-bytes!";
    let (jwks_url, _shutdown) = crate::test_utils::spawn_test_jwks_server("test-key", secret);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token = crate::test_utils::signed_test_jwt_with_nbf(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "test-key",
        secret,
        3600,
        3600,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/")
                .header("Authorization", format!("Bearer {token}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_with_redirect_url_returns_307_with_location() {
    use crate::test_utils::BuilderTestExt;
    let library = Library::builder().open_with_test_plugins();
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String("test://b3-rest-redirect/".into()),
    );
    config.insert(
        "test_redirect_url".into(),
        ovstorage::ConfigValue::String("https://upstream.example".into()),
    );
    library
        .add_connection(
            ovstorage::ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: ovstorage::SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap();

    let app = router(library, None, None);
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

#[tokio::test]
async fn read_without_redirect_returns_200_bytes() {
    use crate::test_utils::BuilderTestExt;
    let library = Library::builder().open_with_test_plugins();
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String("test://b3-rest-bytes/".into()),
    );
    library
        .add_connection(
            ovstorage::ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: ovstorage::SecretBundle::default(),
                persist: false,
                display_name: None,
            },
            None,
        )
        .await
        .unwrap();

    let app = router(library, None, None);
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

async fn build_test_library_for_authn() -> Arc<Library> {
    use crate::test_utils::BuilderTestExt;
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ovstorage::ConfigValue::String("test://demo/".into()),
    );
    let library = Library::builder().open_with_test_plugins();
    let request = ovstorage::ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: ovstorage::SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    library.add_connection(request, None).await.unwrap();
    library
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
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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
async fn watch_poll_interval_garbage_returns_400() {
    let root = unique_temp_dir();
    std::fs::create_dir_all(&root).unwrap();
    let library = build_test_library_with_file_root(&root).await;
    let prefix = address_for_path(&root);
    let app = router(library, None, None);
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

#[tokio::test]
async fn jwks_unknown_kid_triggers_refresh_and_accepts_rotated_key() {
    let secret_a = b"jwks-rotation-secret-a-bytes-32!!!";
    let secret_b = b"jwks-rotation-secret-b-bytes-32!!!";
    let (jwks_url, _shutdown, jwks_state) =
        crate::test_utils::spawn_rotatable_test_jwks_server("kid-a", secret_a);
    let authenticator = Arc::new(crate::JwtAuthenticator::new(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token_a = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "kid-a",
        secret_a,
        3600,
    );
    let primed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {token_a}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(primed.status(), StatusCode::UNAUTHORIZED);
    *jwks_state.lock().unwrap() = crate::test_utils::jwks_value("kid-b", secret_b);
    let token_b = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "kid-b",
        secret_b,
        3600,
    );
    let rotated = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {token_b}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        rotated.status(),
        StatusCode::UNAUTHORIZED,
        "rotated kid should be accepted after refresh-on-miss"
    );
}

#[tokio::test]
async fn jwks_cache_ttl_expiry_refetches_keys() {
    use std::time::Duration;
    let secret_a = b"jwks-ttl-secret-a-bytes-bytes-32!";
    let secret_b = b"jwks-ttl-secret-b-bytes-bytes-32!";
    let (jwks_url, _shutdown, jwks_state) =
        crate::test_utils::spawn_rotatable_test_jwks_server("kid-a", secret_a);
    let authenticator = Arc::new(crate::JwtAuthenticator::with_ttl(
        "https://issuer.test".into(),
        "ovstorage-rest".into(),
        jwks_url,
        Duration::from_millis(50),
    ));
    let library = build_test_library_for_authn().await;
    let app = router(library, Some(authenticator), None);
    let token_a = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "kid-a",
        secret_a,
        3600,
    );
    let primed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {token_a}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(primed.status(), StatusCode::UNAUTHORIZED);
    *jwks_state.lock().unwrap() = crate::test_utils::jwks_value("kid-a", secret_b);
    tokio::time::sleep(Duration::from_millis(120)).await;
    let token_b = crate::test_utils::signed_test_jwt(
        "alice",
        "https://issuer.test",
        "ovstorage-rest",
        "kid-a",
        secret_b,
        3600,
    );
    let after = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {token_b}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "post-TTL refetch should pick up the rotated secret under the same kid"
    );
}
