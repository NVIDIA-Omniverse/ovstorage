// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST conformance test kit. Each test maps to one assertion in the
//! public REST contract; a compliant implementation MUST pass them all.

use std::collections::HashMap;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body as AxumBody;
use axum::http::{Method, Request, StatusCode};
use futures::StreamExt as _;
use http_body_util::BodyExt;
use ovstorage::{
    Body, CancellationToken, ConfigValue, ConnectionRequest, Layer, ListVersionsOptions,
    ListVersionsRequest, ObjectInfo, ReadOptions, ReadRequest, ReadResult, Request as SpiRequest,
    SecretBundle, Stack, StatOptions, StatRequest, Url, WriteOptions, WriteRequest, WriteResult,
    address,
};
use ovstorage_rest::{GatewayStack, GatewayStackBuilder, RestJwtParams, rest_stack_config, router};
use tower::ServiceExt;

/// Fixture dir holding the plugin cdylibs built by `build.rs`.
fn plugin_dir() -> PathBuf {
    PathBuf::from(env!("OVSTORAGE_REST_TEST_PLUGIN_DIR"))
}

/// Assemble the gateway's built-in auth [`LayerConfig`]: an
/// unset policy is the explicit anonymous allow-all, a set policy gates, and
/// JWT params configure `Tcp` bearer authn.
fn conformance_auth_config(
    policy_toml: Option<&str>,
    jwt: Option<RestJwtParams>,
) -> ovstorage::LayerConfig {
    let mut config = ovstorage::LayerConfig::new();
    let policy = policy_toml
        .map(str::to_string)
        .unwrap_or_else(|| ovstorage_authz_layer::ANONYMOUS_ALLOW_ALL_POLICY.to_string());
    config.insert(
        ovstorage_authz_layer::POLICY_CONFIG_KEY.to_string(),
        ConfigValue::Toml(policy),
    );
    if let Some(jwt) = jwt {
        jwt.apply_to(&mut config);
    }
    config
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
fn temp_dir_named(prefix: &str, stamp: u128, serial: u64) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ovstorage-rest-conformance-{prefix}-{}-{stamp}-{serial}",
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
fn unique_temp_dir(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    temp_dir_named(prefix, stamp, next_temp_dir_serial())
}

#[test]
fn same_tick_temp_dirs_differ() {
    const FROZEN_TICK: u128 = 1_700_000_000_000_000_000;

    let first = temp_dir_named("collision", FROZEN_TICK, next_temp_dir_serial());
    let second = temp_dir_named("collision", FROZEN_TICK, next_temp_dir_serial());
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
                    .map(|_| unique_temp_dir("concurrent"))
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

/// Convenience seed operations on the gateway Stack. Distinct names
/// (vs. `Layer`'s `write`/`stat`/…) keep the call sites unambiguous.
#[async_trait::async_trait]
trait TestStackExt {
    async fn seed_write(
        &self,
        dest: Url,
        body: Body,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<WriteResult>;
    async fn seed_stat(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<ObjectInfo>;
    async fn seed_list_versions(
        &self,
        addr: Url,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<Vec<ObjectInfo>>;
    async fn seed_read_bytes(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<(Vec<u8>, ObjectInfo)>;
}

#[async_trait::async_trait]
impl TestStackExt for Stack {
    async fn seed_write(
        &self,
        dest: Url,
        body: Body,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<WriteResult> {
        Layer::write(
            self,
            SpiRequest::new(WriteRequest {
                address: dest,
                body,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn seed_stat(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<ObjectInfo> {
        Layer::stat(
            self,
            SpiRequest::new(StatRequest {
                address: addr,
                options: opts,
            }),
            cancel,
        )
        .await
    }

    async fn seed_list_versions(
        &self,
        addr: Url,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<Vec<ObjectInfo>> {
        let page = Layer::list_versions(
            self,
            SpiRequest::new(ListVersionsRequest {
                address: addr,
                options: opts,
            }),
            cancel,
        )
        .await?;
        Ok(page.items)
    }

    async fn seed_read_bytes(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> ovstorage::Result<(Vec<u8>, ObjectInfo)> {
        let result = Layer::read(
            self,
            SpiRequest::new(ReadRequest {
                address: addr,
                options: opts,
            }),
            cancel,
        )
        .await?;
        match result {
            ReadResult::Bytes { bytes, info } => Ok((bytes, info)),
            ReadResult::Stream { mut stream, info } => {
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk?);
                }
                Ok((bytes, info))
            }
            ReadResult::LocalDelegate(local) => {
                let bytes = tokio::fs::read(&local.path).await.map_err(|error| {
                    ovstorage::Error::new(ovstorage::ErrorCode::Internal, error.to_string())
                })?;
                Ok((bytes, local.info))
            }
            ReadResult::Redirect(_) => Err(ovstorage::Error::new(
                ovstorage::ErrorCode::Internal,
                "seed_read_bytes received an unfollowed redirect",
            )),
        }
    }
}

async fn build_gateway_with_file_root(root: &Path) -> GatewayStack {
    let mut config = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    // SAFETY: dlopen of the build-script-populated fixture.
    unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(plugin_dir())
            .auth_config(conformance_auth_config(None, None))
            .stack_config(rest_stack_config(
                vec![ovstorage::ConnectionConfig::from_request(
                    ConnectionRequest {
                        backend_kind: "file".into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-file".into()),
                    },
                )],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .unwrap()
    }
}

/// Build a gateway with the test plugin mounted at `test://demo/`.
async fn build_gateway_with_test_plugin(
    extra_config: HashMap<String, ConfigValue>,
) -> GatewayStack {
    let mut config = extra_config;
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    // SAFETY: dlopen of build-script-populated fixture only.
    unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(plugin_dir())
            .allow_test_plugins(true)
            .auth_config(conformance_auth_config(None, None))
            .stack_config(rest_stack_config(
                vec![ovstorage::ConnectionConfig::from_request(
                    ConnectionRequest {
                        backend_kind: "test".into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-test".into()),
                    },
                )],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .unwrap()
    }
}

/// Build a policy TOML that allows everything, then denies the given
/// `(operation, address-prefix)` pairs — the auth-layer policy equivalent
/// of the retired `DenyMatching` plugin (a specific deny over a blanket allow;
/// the policy's longest-prefix precedence makes the narrow deny win). Because
/// the policy matches on address PREFIX (not substring), each deny names the
/// full target address/prefix.
fn deny_policy_toml(denies: &[(&str, &str)]) -> String {
    let mut toml = String::from(
        "plugin = \"ovstorage-authz-toml\"\n\n\
         [[policy]]\n\
         id = \"allow-all\"\n\
         effect = \"allow\"\n\
         principal = \"*\"\n\
         operations = [\"*\"]\n\
         prefix = \"*\"\n",
    );
    for (i, (op, prefix)) in denies.iter().enumerate() {
        toml.push_str(&format!(
            "\n[[policy]]\nid = \"deny-{i}\"\neffect = \"deny\"\nprincipal = \"*\"\noperations = [\"{op}\"]\nprefix = \"{prefix}\"\n"
        ));
    }
    toml
}

/// [`build_gateway_with_file_root`] with the built-in auth layer
/// composed at the top of the Stack from `policy_toml`.
async fn build_gateway_with_file_root_authz(root: &Path, policy_toml: &str) -> GatewayStack {
    let mut config = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.to_string_lossy().into_owned()),
    );
    // SAFETY: dlopen of the build-script-populated fixture.
    unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(plugin_dir())
            .auth_config(conformance_auth_config(Some(policy_toml), None))
            .stack_config(rest_stack_config(
                vec![ovstorage::ConnectionConfig::from_request(
                    ConnectionRequest {
                        backend_kind: "file".into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-file".into()),
                    },
                )],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .unwrap()
    }
}

/// [`build_gateway_with_test_plugin`] with the built-in auth layer
/// composed at the top of the Stack from `policy_toml`.
async fn build_gateway_with_test_plugin_authz(
    extra_config: HashMap<String, ConfigValue>,
    policy_toml: &str,
) -> GatewayStack {
    let mut config = extra_config;
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    // SAFETY: dlopen of build-script-populated fixture only.
    unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(plugin_dir())
            .allow_test_plugins(true)
            .auth_config(conformance_auth_config(Some(policy_toml), None))
            .stack_config(rest_stack_config(
                vec![ovstorage::ConnectionConfig::from_request(
                    ConnectionRequest {
                        backend_kind: "test".into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-test".into()),
                    },
                )],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .unwrap()
    }
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
    let gateway = build_gateway_with_test_plugin(config).await;
    let app = router(gateway);

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
    let gateway = build_gateway_with_file_root(&root).await;
    let app = router(gateway.clone());

    let prefix = address_for_path(&root);
    let object = address::join_relative(&prefix, "streamed.bin").unwrap();
    let payload = vec![0xab; 1024 * 64];

    gateway
        .stack
        .seed_write(
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
    let gateway = build_gateway_with_test_plugin(HashMap::new()).await;
    let app = router(gateway.clone());

    let object = address::parse("test://demo/identity.txt").unwrap();
    let written = gateway
        .stack
        .seed_write(
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

    let info = gateway
        .stack
        .seed_write(
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
    let gateway = build_gateway_with_test_plugin(HashMap::new()).await;
    let app = router(gateway.clone());

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

    let missing = gateway
        .stack
        .seed_stat(object, Default::default(), None)
        .await;
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
    let gateway = build_gateway_with_test_plugin(config).await;
    let app = router(gateway.clone());

    let object = address::parse("test://demo/versioned.txt").unwrap();
    gateway
        .stack
        .seed_write(
            object.clone(),
            ovstorage::Body::Bytes(b"v1".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    gateway
        .stack
        .seed_write(
            object.clone(),
            ovstorage::Body::Bytes(b"v2".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let rust_addresses: Vec<String> = gateway
        .stack
        .seed_list_versions(object.clone(), ListVersionsOptions::default(), None)
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
    let gateway = build_gateway_with_file_root(&root).await;
    let app = router(gateway);

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
    let gateway = build_gateway_with_file_root(&root).await;
    let app = router(gateway.clone());

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
    let (readback, _info) = gateway
        .stack
        .seed_read_bytes(object.clone(), ReadOptions::default(), None)
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
// The built-in auth Layer derives these outcomes from the configured policy.

#[tokio::test]
async fn copy_authz_uses_read_on_source_and_write_on_destination() {
    let src = address::parse("test://demo/source.txt").unwrap();
    let dst = address::parse("test://demo/destination.txt").unwrap();
    let copy_body = format!(r#"{{"src":"{src}","dest":"{dst}"}}"#);

    // Deny Read(src): copy must fail even if Write(dst) would succeed.
    let lib_no_read = build_gateway_with_test_plugin_authz(
        HashMap::new(),
        &deny_policy_toml(&[("read", "test://demo/source.txt")]),
    )
    .await;
    lib_no_read
        .stack
        .seed_write(
            src.clone(),
            ovstorage::Body::Bytes(b"src bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let app_no_read = router(lib_no_read);
    let r = app_no_read
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .body(AxumBody::from(copy_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Deny Write(dst): copy must fail.
    let lib_no_write = build_gateway_with_test_plugin_authz(
        HashMap::new(),
        &deny_policy_toml(&[("write", "test://demo/destination.txt")]),
    )
    .await;
    lib_no_write
        .stack
        .seed_write(
            src.clone(),
            ovstorage::Body::Bytes(b"src bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let app_no_write = router(lib_no_write);
    let r = app_no_write
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/objects:copy")
                .header("content-type", "application/json")
                .body(AxumBody::from(copy_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

// Copy / rename carry two precondition operands (source + destination);
// RFC 7232's `If-Match` has no operand binding, so accepting a bare
// `If-Match` would silently pick one side and footgun callers who
// reach for it intending the other. The gateway rejects bare
// `If-Match` on these routes with 400 and points the caller at the
// explicit `X-OV-If-Source-Match` / `X-OV-If-Dest-Match` headers.
#[tokio::test]
async fn copy_rename_reject_bare_if_match_with_400_pointing_at_explicit_headers() {
    let gateway = build_gateway_with_test_plugin(HashMap::new()).await;
    let src = address::parse("test://demo/src-rejected.txt").unwrap();
    let dst = address::parse("test://demo/dst-rejected.txt").unwrap();
    gateway
        .stack
        .seed_write(
            src.clone(),
            ovstorage::Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let app = router(gateway);

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
    let gateway = build_gateway_with_test_plugin(HashMap::new()).await;
    let src = address::parse("test://demo/two-sided-src.txt").unwrap();
    let dst = address::parse("test://demo/two-sided-dst.txt").unwrap();
    let src_info = gateway
        .stack
        .seed_write(
            src.clone(),
            ovstorage::Body::Bytes(b"src bytes".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap()
        .info;
    let dst_info = gateway
        .stack
        .seed_write(
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

    let app = router(gateway);
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

// REST `check_access` must intersect the
// backend's per-op decision with authz. Mirrors the broker's
// `apply_authz_access_decision` so gRPC and REST cannot drift. Uses
// the file plugin because it advertises `supports_access_check` —
// the test plugin does not.
#[tokio::test]
async fn check_access_intersects_with_authz_decision() {
    let root = unique_temp_dir("check-access");
    std::fs::create_dir_all(&root).unwrap();
    let probe = address_for_path(&root).join("probe.txt").unwrap();
    // File backend allows everything; the in-stack authz Layer denies Write on
    // the probe. Without the Layer's intersection, REST would return
    // `allowed: true` and empty `denied_ops`, letting the caller think Write is
    // permitted when policy says no.
    // Seed the object directly on disk: writing through the Stack would be
    // rejected by the very Write deny this test relies on.
    std::fs::write(root.join("probe.txt"), b"probe").unwrap();
    let gateway =
        build_gateway_with_file_root_authz(&root, &deny_policy_toml(&[("write", probe.as_str())]))
            .await;

    let app = router(gateway);
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

// REST `list_address_roots` must filter
// per-root by Read/List authz, mirroring the broker's
// `filter_address_roots`. Otherwise REST leaks routes the same policy
// hides from gRPC clients.
#[tokio::test]
async fn list_address_roots_filters_per_root_by_authz() {
    // Two test roots on the immutable gateway Stack — `demo` stays visible,
    // `secret` is what the policy hides. The in-stack authz Layer denies both
    // Read and List on the secret root, so its `is_root_visible` (Read OR List)
    // predicate drops it from `list_address_roots`.
    let mut demo_config = HashMap::new();
    demo_config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    let mut secret_config = HashMap::new();
    secret_config.insert(
        "test_root".into(),
        ConfigValue::String("test://secret/".into()),
    );
    let policy_toml = deny_policy_toml(&[("read", "test://secret/"), ("list", "test://secret/")]);
    // SAFETY: dlopen of build-script-populated fixture only.
    let gateway = unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(plugin_dir())
            .allow_test_plugins(true)
            .auth_config(conformance_auth_config(Some(&policy_toml), None))
            .stack_config(rest_stack_config(
                vec![
                    ovstorage::ConnectionConfig::from_request(ConnectionRequest {
                        backend_kind: "test".into(),
                        config: demo_config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-test".into()),
                    }),
                    ovstorage::ConnectionConfig::from_request(ConnectionRequest {
                        backend_kind: "test".into(),
                        config: secret_config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-secret".into()),
                    }),
                ],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .unwrap()
    };

    let app = router(gateway);
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
async fn assertion_7_oidc_matrix_admits_valid_rejects_expired_wrong() {
    // OIDC bearer-JWT authn lives in the gateway's built-in auth
    // layer (composed via `.jwt(...)`), not a host-side middleware. The
    // credential-gathering seam hands the UNDECODED bearer to the auth layer,
    // which validates it on a request that dispatches through the Stack.
    let secret = b"conformance-test-secret-bytes-32!";
    let (jwks_url, _shutdown) = oidc::spawn_jwks_server("conformance-key", secret);

    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    // SAFETY: dlopen of build-script-populated fixture only.
    let gateway = unsafe {
        GatewayStackBuilder::new()
            .plugin_dir(plugin_dir())
            .allow_test_plugins(true)
            .auth_config(conformance_auth_config(
                None,
                Some(RestJwtParams {
                    issuer: "https://issuer.example/".into(),
                    audience: "rest-conformance-audience".into(),
                    jwks_url,
                }),
            ))
            .stack_config(rest_stack_config(
                vec![ovstorage::ConnectionConfig::from_request(
                    ConnectionRequest {
                        backend_kind: "test".into(),
                        config,
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: Some("conformance-test".into()),
                    },
                )],
                &ovstorage_authz::UserMetadataKinds::from_factories(&[]),
            ))
            .build()
            .await
            .unwrap()
    };
    let app = router(gateway);

    // `objects:list` dispatches through the auth layer, isolating the OIDC gate.
    let list = |authorization: Option<String>| {
        let app = app.clone();
        async move {
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri("/v1/objects:list?prefix=test://demo/");
            if let Some(value) = authorization {
                builder = builder.header("Authorization", value);
            }
            app.oneshot(builder.body(AxumBody::empty()).unwrap())
                .await
                .unwrap()
                .status()
        }
    };

    let valid = oidc::signed_jwt(
        "alice",
        "https://issuer.example/",
        "rest-conformance-audience",
        "conformance-key",
        secret,
        3600,
    );
    assert_eq!(
        list(Some(format!("Bearer {valid}"))).await,
        StatusCode::OK,
        "valid token should admit (allow-all default policy ⇒ 200)"
    );

    let expired = oidc::signed_jwt(
        "alice",
        "https://issuer.example/",
        "rest-conformance-audience",
        "conformance-key",
        secret,
        -3600,
    );
    assert_eq!(
        list(Some(format!("Bearer {expired}"))).await,
        StatusCode::UNAUTHORIZED
    );

    let wrong_issuer = oidc::signed_jwt(
        "alice",
        "https://other-issuer.example/",
        "rest-conformance-audience",
        "conformance-key",
        secret,
        3600,
    );
    assert_eq!(
        list(Some(format!("Bearer {wrong_issuer}"))).await,
        StatusCode::UNAUTHORIZED
    );

    // A JWT-configured listener fails closed: a missing bearer on a `Tcp`
    // transport is `AuthRequired` → 401, not silently anonymous.
    assert_eq!(list(None).await, StatusCode::UNAUTHORIZED);
}

// Security invariant: a policy denying Read on an address must keep that
// address out of both `list` and `watch-directory` output.

#[tokio::test]
async fn list_filters_per_item_via_filter_list_batch() {
    // The in-stack authz Layer post-filters `list` per item with `Stat` (list
    // entries are metadata; the broker filters with `Stat`, not `Read`), so a
    // single-entry `Stat`-deny drops `denied.txt` while the prefix-level `List`
    // stays allowed and the other entries survive.
    let gateway = build_gateway_with_test_plugin_authz(
        HashMap::new(),
        &deny_policy_toml(&[("stat", "test://demo/denied.txt")]),
    )
    .await;
    for name in ["allowed-1.txt", "denied.txt", "allowed-2.txt"] {
        gateway
            .stack
            .seed_write(
                address::parse(&format!("test://demo/{name}")).unwrap(),
                ovstorage::Body::Bytes(b"content".to_vec()),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
    }
    let app = router(gateway);
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
