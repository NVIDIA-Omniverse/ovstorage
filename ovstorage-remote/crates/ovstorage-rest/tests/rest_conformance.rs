// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST conformance test kit. Each test maps to one assertion in the
//! public REST contract; a compliant implementation MUST pass them all.

use std::collections::HashMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body as AxumBody;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use ovstorage::auth::{AuthRefreshLock, SecretStore};
use ovstorage::{
    ConfigValue, ConnectionRequest, Library, ListVersionsOptions, SecretBundle, Storage as _, Url,
    WriteOptions, address,
};
use ovstorage_rest::{JwtAuthenticator, router};
use tower::ServiceExt;

/// Fixture dir holding the plugin cdylibs built by `build.rs`.
fn plugin_dir() -> PathBuf {
    PathBuf::from(env!("OVSTORAGE_REST_TEST_PLUGIN_DIR"))
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "ovstorage-rest-conformance-{prefix}-{}-{stamp}",
        std::process::id()
    ))
}

/// Process-shared test substrate; the SPI registers the host substrate
/// set-once-per-process, so every Library in this binary reuses these Arcs.
fn shared_substrate() -> &'static (Arc<SecretStore>, Arc<AuthRefreshLock>) {
    static SHARED: OnceLock<(Arc<SecretStore>, Arc<AuthRefreshLock>)> = OnceLock::new();
    SHARED.get_or_init(|| {
        let auth_root = unique_temp_dir("conformance-auth");
        std::fs::create_dir_all(&auth_root).unwrap();
        (
            Arc::new(SecretStore::new()),
            Arc::new(AuthRefreshLock::open(&auth_root).unwrap()),
        )
    })
}

async fn build_library_with_file_root(root: &Path) -> Arc<Library> {
    let (secret_store, refresh_lock) = shared_substrate();
    let library = Library::builder()
        .with_credential_persistence(secret_store.clone(), refresh_lock.clone())
        .open()
        .unwrap();
    // SAFETY: dlopen of the build-script-populated fixture.
    unsafe {
        library.load_plugins_from_dir(Some(&plugin_dir())).unwrap();
    }
    let mut config = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    library
        .add_connection(
            ConnectionRequest {
                backend_kind: "file".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("conformance-file".into()),
            },
            None,
        )
        .await
        .unwrap();
    library
}

/// Build a library with the test plugin mounted at `test://demo/`.
async fn build_library_with_test_plugin(
    extra_config: HashMap<String, ConfigValue>,
) -> Arc<Library> {
    let (secret_store, refresh_lock) = shared_substrate();
    let library = Library::builder()
        .with_credential_persistence(secret_store.clone(), refresh_lock.clone())
        .allow_test_plugins(true)
        .open()
        .unwrap();
    // SAFETY: dlopen of build-script-populated fixture only.
    unsafe {
        library.load_plugins_from_dir(Some(&plugin_dir())).unwrap();
    }
    let mut config = extra_config;
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    library
        .add_connection(
            ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("conformance-test".into()),
            },
            None,
        )
        .await
        .unwrap();
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
    // file plugin uses `file:<abs-path>/` (no authority component).
    address::parse(&format!("file:{path}")).unwrap()
}

#[tokio::test]
async fn assertion_1_redirect_emitting_route_returns_307_with_location() {
    let mut config = HashMap::new();
    config.insert(
        "test_redirect_url".into(),
        ConfigValue::String("https://upstream.example.com/blob".into()),
    );
    let library = build_library_with_test_plugin(config).await;
    let app = router(library, None, None);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects?address=test://demo/redirect.bin")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .expect("Location header")
        .to_str()
        .unwrap();
    assert!(
        location.starts_with("https://upstream.example.com/blob"),
        "Location should be the configured upstream URL, got {location}"
    );
    assert!(response.headers().get("x-ov-audit-id").is_some());
}

#[tokio::test]
async fn assertion_2_local_delegate_reads_stream_through_axum_body() {
    // `tower::oneshot` doesn't run hyper's wire-level encoder, so we
    // assert intact stream delivery rather than `Transfer-Encoding: chunked`.
    let root = unique_temp_dir("ass2");
    std::fs::create_dir_all(&root).unwrap();
    let library = build_library_with_file_root(&root).await;
    let app = router(library.clone(), None, None);

    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "streamed.bin").unwrap();
    let payload = vec![0xab; 1024 * 64];

    library
        .write(
            object.clone(),
            ovstorage::Body::Bytes(payload.clone()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects?address={object}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.len(), payload.len());
    assert_eq!(&bytes[..], &payload[..]);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn assertion_3_if_match_header_quoted_and_bare_etag_round_trip() {
    let library = build_library_with_test_plugin(HashMap::new()).await;
    let app = router(library.clone(), None, None);

    let object = address::parse("test://demo/identity.txt").unwrap();
    let written = library
        .write(
            object.clone(),
            ovstorage::Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let etag = written.info.etag.clone().expect("etag");

    // 412 Precondition Failed (409 is reserved for Conflict / DirectoryNotEmpty).
    let stale = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v1/objects?address={object}"))
                .header("If-Match", "\"definitely-not-the-real-etag\"")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        stale.status(),
        StatusCode::PRECONDITION_FAILED,
        "stale If-Match should return 412 Precondition Failed"
    );

    let ok = app
        .clone()
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
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);

    let info = library
        .write(
            object.clone(),
            ovstorage::Body::Bytes(b"hi".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap()
        .info;

    let bare_form = app
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/v1/objects?address={object}"))
                .header("If-Match", info.etag.as_deref().unwrap())
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        bare_form.status(),
        StatusCode::NO_CONTENT,
        "If-Match accepts the bare opaque etag (no surrounding quotes)"
    );
}

#[tokio::test]
async fn if_match_wildcard_is_rejected_instead_of_silently_dropped() {
    let library = build_library_with_test_plugin(HashMap::new()).await;
    let app = router(library.clone(), None, None);

    let object = address::parse("test://demo/wildcard.txt").unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .header("If-Match", "*")
                .body(AxumBody::from("payload"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "If-Match: * is RFC-defined wildcard existence matching, not an etag; REST must reject it rather than drop the precondition"
    );

    let missing = library.stat(object, Default::default(), None).await;
    assert!(
        missing.is_err(),
        "rejected If-Match: * write must not create the object"
    );
}

#[tokio::test]
async fn assertion_4_objects_versions_returns_same_addresses_as_list_versions() {
    // `full` preset enables `supports_version_listing` (default `minimal` doesn't).
    let mut config = HashMap::new();
    config.insert("test_caps".into(), ConfigValue::String("full".into()));
    let library = build_library_with_test_plugin(config).await;
    let app = router(library.clone(), None, None);

    let object = address::parse("test://demo/versioned.txt").unwrap();
    library
        .write(
            object.clone(),
            ovstorage::Body::Bytes(b"v1".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    library
        .write(
            object.clone(),
            ovstorage::Body::Bytes(b"v2".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let rust_addresses: Vec<String> = library
        .list_versions(object.clone(), ListVersionsOptions::default(), None)
        .await
        .unwrap()
        .iter()
        .map(|v| v.address.to_string())
        .collect();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/objects:versions?address={object}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rest_addresses: Vec<String> = json["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["address"].as_str().unwrap().to_string())
        .collect();

    assert_eq!(rust_addresses, rest_addresses);
}

#[tokio::test]
async fn assertion_5_if_none_match_star_enforces_no_overwrite() {
    let root = unique_temp_dir("ass5");
    std::fs::create_dir_all(&root).unwrap();
    let library = build_library_with_file_root(&root).await;
    let app = router(library, None, None);

    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "once.txt").unwrap();

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .header("If-None-Match", "*")
                .body(AxumBody::from("first"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let conflict = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .header("If-None-Match", "*")
                .body(AxumBody::from("second"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    std::fs::remove_dir_all(root).unwrap();
}

// Public-facing memory-DoS regression guard: the request body must
// stream chunk-by-chunk, never drain to a single Vec<u8> at the gateway.
#[tokio::test]
async fn streaming_write_does_not_drain_body() {
    use axum::body::Body as AxumBody;
    use bytes::Bytes;
    use futures::stream;

    let root = unique_temp_dir("stream-write");
    std::fs::create_dir_all(&root).unwrap();
    let library = build_library_with_file_root(&root).await;
    let app = router(library.clone(), None, None);

    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "stream.bin").unwrap();

    // 16 MiB in 64 KiB chunks; the 16-slot bounded mpsc keeps peak host
    // buffering at 16 * 64 KiB = 1 MiB regardless of total size.
    const CHUNK: usize = 64 * 1024;
    const TOTAL: usize = 16 * 1024 * 1024;
    const CHUNK_COUNT: usize = TOTAL / CHUNK;

    let make_chunk = |i: usize| -> Bytes {
        let mut buf = Vec::with_capacity(CHUNK);
        for j in 0..CHUNK {
            buf.push(((i * 31 + j) & 0xFF) as u8);
        }
        Bytes::from(buf)
    };

    let chunk_stream =
        stream::iter((0..CHUNK_COUNT).map(move |i| Ok::<_, std::io::Error>(make_chunk(i))));
    let body = AxumBody::from_stream(chunk_stream);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/v1/objects?dest={object}"))
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "streaming PUT failed: {:?}",
        response
            .into_body()
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
    );

    use ovstorage::ReadOptions;
    let (readback, _info) = library
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(readback.len(), TOTAL, "wrong total length");
    for i in 0..CHUNK_COUNT {
        let expected = (0..CHUNK)
            .map(|j| ((i * 31 + j) & 0xFF) as u8)
            .collect::<Vec<u8>>();
        let actual = &readback[i * CHUNK..(i + 1) * CHUNK];
        assert_eq!(actual, expected.as_slice(), "chunk {i} mismatch");
    }

    std::fs::remove_dir_all(root).unwrap();
}

// Security invariant: directional ops decompose into primitives —
// copy/rename require Read(src)+Write(dst); add_alias also Read-checks `to`.

mod directional_authz {

    use ovstorage_authz::{AuthzDecision, AuthzPlugin, AuthzRequest, Operation, Principal};

    /// Test plugin denying configured (operation, address-substring) pairs.
    pub(super) struct DenyMatching {
        pub(super) deny: Vec<(Operation, &'static str)>,
    }

    #[async_trait::async_trait]
    impl AuthzPlugin for DenyMatching {
        fn plugin_name(&self) -> &str {
            "deny-matching"
        }
        async fn authorize(&self, request: &AuthzRequest) -> ovstorage::Result<AuthzDecision> {
            let address_str = request
                .address
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_default();
            for (op, needle) in &self.deny {
                if request.operation == *op && address_str.contains(needle) {
                    return Ok(AuthzDecision::deny(format!(
                        "deny {:?} on address containing '{}'",
                        op, needle
                    )));
                }
            }
            Ok(AuthzDecision::allow())
        }
    }

    pub(super) fn _silence_unused(_: &Principal) {}
}

#[tokio::test]
async fn copy_authz_uses_read_on_source_and_write_on_destination() {
    use ovstorage_authz::{AuthzPlugin, Operation};

    let library = build_library_with_test_plugin(HashMap::new()).await;
    let src = address::parse("test://demo/source.txt").unwrap();
    let dst = address::parse("test://demo/destination.txt").unwrap();
    library
        .write(
            src.clone(),
            ovstorage::Body::Bytes(b"src bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    // Deny Read(src): copy must fail even if Write(dst) would succeed.
    let authz_no_read: Arc<dyn AuthzPlugin> = Arc::new(directional_authz::DenyMatching {
        deny: vec![(Operation::Read, "source.txt")],
    });
    let app_no_read = router(library.clone(), None, Some(authz_no_read));
    let r = app_no_read
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .body(AxumBody::from(format!(
                    r#"{{"src":"{src}","dest":"{dst}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Deny Write(dst): copy must fail.
    let authz_no_write: Arc<dyn AuthzPlugin> = Arc::new(directional_authz::DenyMatching {
        deny: vec![(Operation::Write, "destination.txt")],
    });
    let app_no_write = router(library.clone(), None, Some(authz_no_write));
    let r = app_no_write
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .body(AxumBody::from(format!(
                    r#"{{"src":"{src}","dest":"{dst}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn add_alias_authz_also_checks_read_on_target() {
    use ovstorage_authz::{AuthzPlugin, Operation};

    let library = build_library_with_test_plugin(HashMap::new()).await;
    library
        .write(
            address::parse("test://demo/secret.txt").unwrap(),
            ovstorage::Body::Bytes(b"secret".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    // Deny Read(to): the implicit Read check on the alias target must
    // fail even when AddAlias(from) is allowed.
    let authz: Arc<dyn AuthzPlugin> = Arc::new(directional_authz::DenyMatching {
        deny: vec![(Operation::Read, "secret.txt")],
    });
    let app = router(library, None, Some(authz));
    let r = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/aliases")
                .header("content-type", "application/json")
                .body(AxumBody::from(
                    r#"{"from":"test://demo/shortcut","to":"test://demo/secret.txt"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "alias creation must fail when caller can't Read the target"
    );
}

// Copy / rename carry two precondition operands (source + destination);
// RFC 7232's `If-Match` has no operand binding, so accepting a bare
// `If-Match` would silently pick one side and footgun callers who
// reach for it intending the other. The gateway rejects bare
// `If-Match` on these routes with 400 and points the caller at the
// explicit `X-OV-If-Source-Match` / `X-OV-If-Dest-Match` headers.
#[tokio::test]
async fn copy_rename_reject_bare_if_match_with_400_pointing_at_explicit_headers() {
    let library = build_library_with_test_plugin(HashMap::new()).await;
    let src = address::parse("test://demo/src-rejected.txt").unwrap();
    let dst = address::parse("test://demo/dst-rejected.txt").unwrap();
    library
        .write(
            src.clone(),
            ovstorage::Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let app = router(library, None, None);

    let copy = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .header("If-Match", "\"some-etag\"")
                .body(AxumBody::from(format!(
                    r#"{{"src":"{src}","dest":"{dst}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(copy.status(), StatusCode::BAD_REQUEST);
    let body = copy.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["code"], "InvalidArgument");
    let message = parsed["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("X-OV-If-Source-Match") && message.contains("X-OV-If-Dest-Match"),
        "rejection message must point the caller at the explicit headers: {message}"
    );

    let rename = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:rename")
                .header("content-type", "application/json")
                .header("If-Match", "\"some-etag\"")
                .body(AxumBody::from(format!(
                    r#"{{"src":"{src}","dest":"{dst}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rename.status(), StatusCode::BAD_REQUEST);
    let body = rename.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"]["code"], "InvalidArgument");
    let message = parsed["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("X-OV-If-Source-Match") && message.contains("X-OV-If-Dest-Match"),
        "rejection message must point the caller at the explicit headers: {message}"
    );
}

// Two-sided preconditions on copy: source side rides on
// `X-OV-If-Source-Match`, destination side on `X-OV-If-Dest-Match`.
// Sending both together is the supported way to express
// "copy-this-exact-source onto this-exact-destination" atomically.
#[tokio::test]
async fn copy_accepts_both_explicit_source_and_dest_match_headers() {
    let library = build_library_with_test_plugin(HashMap::new()).await;
    let src = address::parse("test://demo/two-sided-src.txt").unwrap();
    let dst = address::parse("test://demo/two-sided-dst.txt").unwrap();
    let src_info = library
        .write(
            src.clone(),
            ovstorage::Body::Bytes(b"src bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap()
        .info;
    let dst_info = library
        .write(
            dst.clone(),
            ovstorage::Body::Bytes(b"old dst".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap()
        .info;
    let src_etag = src_info.etag.clone().expect("source etag");
    let dst_etag = dst_info.etag.clone().expect("dest etag");

    let app = router(library, None, None);
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .header("X-OV-If-Source-Match", format!("\"{src_etag}\""))
                .header("X-OV-If-Dest-Match", format!("\"{dst_etag}\""))
                .body(AxumBody::from(format!(
                    r#"{{"src":"{src}","dest":"{dst}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "two-sided precondition copy with matching etags must succeed"
    );
}

// Joe's review finding #6: REST `check_access` must intersect the
// backend's per-op decision with authz. Mirrors the broker's
// `apply_authz_access_decision` so gRPC and REST cannot drift. Uses
// the file plugin because it advertises `supports_access_check` —
// the test plugin does not.
#[tokio::test]
async fn check_access_intersects_with_authz_decision() {
    use ovstorage_authz::{AuthzPlugin, Operation};

    let root = unique_temp_dir("check-access");
    std::fs::create_dir_all(&root).unwrap();
    let library = build_library_with_file_root(&root).await;
    let probe = address_for_path(&root).join("probe.txt").unwrap();
    library
        .write(
            probe.clone(),
            ovstorage::Body::Bytes(b"probe".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    // File backend allows everything; authz denies Write. Without the
    // intersection, REST returns `allowed: true` and empty `denied_ops`
    // — letting the caller think Write is permitted when policy says
    // no.
    let authz: Arc<dyn AuthzPlugin> = Arc::new(directional_authz::DenyMatching {
        deny: vec![(Operation::Write, "probe.txt")],
    });
    let app = router(library, None, Some(authz));
    let r = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:check-access")
                .header("content-type", "application/json")
                .body(AxumBody::from(format!(
                    r#"{{"address":"{probe}","read":true,"write":true,"delete":false,"update_metadata":false}}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed["allowed"].as_bool(),
        Some(false),
        "authz Write deny must force allowed=false: {parsed}"
    );
    assert_eq!(
        parsed["denied_ops"]["write"].as_bool(),
        Some(true),
        "authz Write deny must surface in denied_ops.write: {parsed}"
    );
    assert_eq!(
        parsed["denied_ops"]["read"].as_bool(),
        Some(false),
        "Read was allowed by authz; denied_ops.read must stay false: {parsed}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

// Joe's review finding #7: REST `list_address_roots` must filter
// per-root by Read/List authz, mirroring the broker's
// `filter_address_roots`. Otherwise REST leaks routes the same policy
// hides from gRPC clients.
#[tokio::test]
async fn list_address_roots_filters_per_root_by_authz() {
    use ovstorage::ConnectionRequest;
    use ovstorage_authz::{AuthzPlugin, Operation};

    let library = build_library_with_test_plugin(HashMap::new()).await;
    // Add a second test root the policy will hide.
    let mut secret_config = HashMap::new();
    secret_config.insert(
        "test_root".into(),
        ConfigValue::String("test://secret/".into()),
    );
    library
        .add_connection(
            ConnectionRequest {
                backend_kind: "test".into(),
                config: secret_config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("conformance-secret".into()),
            },
            None,
        )
        .await
        .unwrap();

    // Deny both Read and List on the secret root; demo stays visible.
    let authz: Arc<dyn AuthzPlugin> = Arc::new(directional_authz::DenyMatching {
        deny: vec![
            (Operation::Read, "test://secret"),
            (Operation::List, "test://secret"),
        ],
    });
    let app = router(library, None, Some(authz));
    let r = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/address-roots")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let items = parsed["items"].as_array().expect("items array");
    let addresses: Vec<&str> = items
        .iter()
        .filter_map(|item| item["address"].as_str())
        .collect();
    assert!(
        addresses.iter().any(|a| a.contains("test://demo")),
        "demo root must remain visible: {addresses:?}"
    );
    assert!(
        !addresses.iter().any(|a| a.contains("test://secret")),
        "secret root must be filtered out by per-root authz: {addresses:?}"
    );
}

mod oidc {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::Serialize;
    use serde_json::json;

    pub(super) fn signed_jwt(
        subject: &str,
        issuer: &str,
        audience: &str,
        kid: &str,
        secret: &[u8],
        expiry_offset_seconds: i64,
    ) -> String {
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            iss: &'a str,
            aud: &'a str,
            exp: u64,
            nbf: u64,
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + expiry_offset_seconds).max(0) as u64;
        let nbf = (now - 60).max(0) as u64;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(
            &header,
            &Claims {
                sub: subject,
                iss: issuer,
                aud: audience,
                exp,
                nbf,
            },
            &jsonwebtoken::EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    pub(super) fn spawn_jwks_server(
        kid: &str,
        secret: &[u8],
    ) -> (String, tokio::sync::oneshot::Sender<()>) {
        use axum::routing::get;
        use axum::{Json, Router};
        let jwks = json!({
            "keys": [
                {
                    "kty": "oct",
                    "kid": kid,
                    "alg": "HS256",
                    "k": URL_SAFE_NO_PAD.encode(secret),
                }
            ]
        });
        let app = Router::new().route(
            "/jwks",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
}

#[tokio::test]
async fn assertion_7_oidc_matrix_admits_valid_rejects_expired_wrong_missing() {
    let secret = b"conformance-test-secret-bytes-32!";
    let (jwks_url, _shutdown) = oidc::spawn_jwks_server("conformance-key", secret);
    let authenticator = Arc::new(JwtAuthenticator::new(
        "https://issuer.example/".into(),
        "rest-conformance-audience".into(),
        jwks_url,
    ));

    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    let library = build_library_with_test_plugin(config).await;
    let app = router(library, Some(authenticator), None);

    // Endpoint without address routing isolates the OIDC layer as the only gate.
    let valid = oidc::signed_jwt(
        "alice",
        "https://issuer.example/",
        "rest-conformance-audience",
        "conformance-key",
        secret,
        3600,
    );
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {valid}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK, "valid token should admit");

    let expired = oidc::signed_jwt(
        "alice",
        "https://issuer.example/",
        "rest-conformance-audience",
        "conformance-key",
        secret,
        -3600,
    );
    let exp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {expired}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exp.status(), StatusCode::UNAUTHORIZED);

    let wrong_issuer = oidc::signed_jwt(
        "alice",
        "https://other-issuer.example/",
        "rest-conformance-audience",
        "conformance-key",
        secret,
        3600,
    );
    let wrong = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .header("Authorization", format!("Bearer {wrong_issuer}"))
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let missing = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/backend-kinds")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
}

// Security invariant: an authz plugin denying Read on an address
// must keep that address out of both `list` and `watch-directory` output.

#[tokio::test]
async fn list_filters_per_item_via_filter_list_batch() {
    use ovstorage_authz::AuthzPlugin;

    let library = build_library_with_test_plugin(HashMap::new()).await;
    for name in ["allowed-1.txt", "denied.txt", "allowed-2.txt"] {
        library
            .write(
                address::parse(&format!("test://demo/{name}")).unwrap(),
                ovstorage::Body::Bytes(b"content".to_vec()),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
    }
    let authz: Arc<dyn AuthzPlugin> = Arc::new(directional_authz::DenyMatching {
        // Per-item Read-deny on a single entry; prefix-level List stays allowed.
        deny: vec![(ovstorage_authz::Operation::Read, "denied.txt")],
    });
    let app = router(library, None, Some(authz));
    let r = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test%3A%2F%2Fdemo%2F&recursive=true")
                .body(AxumBody::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = r.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("allowed-1.txt") && body.contains("allowed-2.txt"),
        "expected allowed entries to survive the filter: {body}"
    );
    assert!(
        !body.contains("denied.txt"),
        "denied entry must not appear in the list response: {body}"
    );
}
