// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

//! Host-of-plugin behaviors pinned via `ovstorage-plugin-test`.
//!
//! These tests register `TestFactory` directly via `register_backend_factory`
//! (rlib link, no FFI) so dispatch goes through `dyn shim::Factory` /
//! `dyn shim::Backend` exactly as it would for a dlopen'd plugin. The
//! intent is to pin host contracts the existing in-memory mocks in
//! `crates/ovstorage/src/lib.rs` cannot reach: `continue_write` redirect
//! loop, watch streams, error code round-trip, auth event variants,
//! retry policy, multi-route isolation, and `__test_meta/` introspection.
//!
//! Per the plan: failures are real. Either fix the test or fix ovstorage —
//! never `#[ignore]`.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage::{Library, Storage as _};
use ovstorage_plugin::{
    AuthEvent, Body, ChangeEvent, ConfigValue, Connection, ConnectionId, ConnectionRequest,
    CopyOptions, ErrorCode, ListVersionsOptions, ReadOptions, SecretBundle, SecretBytes,
    SecretValue, StatOptions, Url, WatchDirectoryOptions, WriteOptions, address,
};
use ovstorage_plugin_test::TestFactory;

// ---------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------
//
// The plugin SPI is set-once-per-process: `init_auth_substrate(...)`
// registers a process-global host substrate, and a second call with a
// different `auth_dir` is a contract violation. So all tests in this
// binary share *one* `Library` and *one* substrate; per-test isolation
// is provided by unique `test_root`s and auto-generated `ConnectionId`s
// rather than by per-test `Library`/substrate construction.

use std::sync::OnceLock;

use ovstorage::retry::RetryConfig;

/// Spec-shaped retry config but with 0ms delays so the retry path
/// runs at full speed in tests. The number of attempts (5) matches
/// production; tests that assert "host retried N times" use this
/// expectation.
const TEST_MAX_ATTEMPTS: u32 = 5;
const FAST_RETRY: RetryConfig = RetryConfig {
    initial_delay_ms: 0,
    max_delay_ms: 0,
    max_attempts: TEST_MAX_ATTEMPTS,
};

static SHARED: OnceLock<SharedFixture> = OnceLock::new();

struct SharedFixture {
    library: Arc<Library>,
    _auth_root: tempfile::TempDir,
}

fn shared() -> &'static SharedFixture {
    SHARED.get_or_init(|| {
        // Route SecretStore through the keyring crate's in-process mock backend.
        // Workspace stress runs flake the real secret-service backend (~1.7%
        // round-trip failures from dbus contention); the mock has identical
        // put/get/delete semantics with no IPC. Must be installed before any
        // `keyring::Entry` is constructed.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let auth_root = tempfile::tempdir().expect("auth tempdir");
        ovstorage::init_auth_substrate(Some(auth_root.path())).expect("init auth substrate");
        let library = Library::builder()
            .register_backend_factory(Arc::new(TestFactory::new()))
            .with_retry(FAST_RETRY)
            .expect("retry config valid")
            .open()
            .expect("library open");
        SharedFixture {
            library,
            _auth_root: auth_root,
        }
    })
}

struct Fixture {
    library: Arc<Library>,
}

impl Fixture {
    fn open() -> Self {
        Self {
            library: shared().library.clone(),
        }
    }

    async fn add_route(&self, root: &str, extra: &[(&str, ConfigValue)]) -> Url {
        self.add_connection(root, extra)
            .await
            .current_addresses
            .first()
            .cloned()
            .expect("connection should expose at least one root")
    }

    /// Variant of `add_route` that returns the full `Connection` so
    /// tests can grab the `ConnectionId` for auth-flow exercises.
    async fn add_connection(&self, root: &str, extra: &[(&str, ConfigValue)]) -> Connection {
        let mut config = HashMap::new();
        config.insert("test_root".into(), ConfigValue::String(root.into()));
        for (k, v) in extra {
            config.insert((*k).into(), v.clone());
        }
        self.library
            .add_connection(
                ConnectionRequest {
                    backend_kind: "test".into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: Some(format!("test-route:{root}")),
                },
                None,
            )
            .await
            .expect("add_connection")
    }

    /// Read `__test_meta/method_calls.json` for a route and return the
    /// parsed JSON. The introspection read itself bumps the `read`
    /// counter, so callers should account for an off-by-one when
    /// asserting exact counts.
    async fn method_calls(&self, root: &Url) -> serde_json::Value {
        let meta =
            address::join_relative(root, "__test_meta/method_calls.json").expect("meta path");
        let (bytes, _info) = self
            .library
            .read_bytes(meta, ReadOptions::default(), None)
            .await
            .expect("introspection read");
        serde_json::from_slice(&bytes).expect("counters parse as JSON")
    }
}

// ---------------------------------------------------------------------
// Batch 1 — continue_write & redirect coordination
// ---------------------------------------------------------------------

#[tokio::test]
async fn write_simple_returns_done_through_spi() {
    let fx = Fixture::open();
    let root = fx.add_route("test://b1-simple/", &[]).await;
    let object = address::join_relative(&root, "hello.txt").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write");
    let info = fx
        .library
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat");
    assert_eq!(info.size, Some(5));
    let (bytes, _info) = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("read_bytes");
    assert_eq!(bytes, b"hello");
}

#[tokio::test]
async fn read_redirect_followed_returns_bytes() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let payload = b"redirected bytes".to_vec();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/test-key.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(payload.clone())
                .insert_header("etag", "\"redirected\"")
                .insert_header("content-length", payload.len().to_string()),
        )
        .mount(&server)
        .await;

    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b1-readredirect/",
            &[("test_redirect_url", ConfigValue::String(server.uri()))],
        )
        .await;
    let object = address::join_relative(&root, "test-key.txt").unwrap();
    let (bytes, _info) = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("read_bytes via redirect follower");
    assert_eq!(bytes, payload);
}

#[tokio::test]
async fn multipart_write_single_stage_calls_continue_write_once() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"part-ok\""))
        .mount(&server)
        .await;

    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b1-multipart-1/",
            &[
                ("test_redirect_url", ConfigValue::String(server.uri())),
                ("test_multipart_parts", ConfigValue::Int(3)),
                ("test_continue_write_loops", ConfigValue::Int(1)),
            ],
        )
        .await;
    let object = address::join_relative(&root, "multipart.bin").unwrap();
    fx.library
        .write(
            object,
            Body::Bytes(b"DATA".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("multipart write");

    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["write_redirect"], 1,
        "write_redirect should be called exactly once (multipart emission)"
    );
    assert_eq!(
        counts["continue_write"], 1,
        "continue_write should be called once for a single-stage multipart"
    );
}

#[tokio::test]
async fn multipart_write_multistage_loops_continue_write_twice() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"part\""))
        .mount(&server)
        .await;

    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b1-multipart-multi/",
            &[
                ("test_redirect_url", ConfigValue::String(server.uri())),
                ("test_multipart_parts", ConfigValue::Int(2)),
                ("test_continue_write_loops", ConfigValue::Int(2)),
            ],
        )
        .await;
    let object = address::join_relative(&root, "multistage.bin").unwrap();
    fx.library
        .write(
            object,
            Body::Bytes(b"X".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("multistage multipart write");

    let counts = fx.method_calls(&root).await;
    assert_eq!(counts["write_redirect"], 1);
    assert_eq!(
        counts["continue_write"], 2,
        "continue_write should be called twice for a 2-loop multistage write"
    );
}

#[tokio::test]
async fn streaming_write_drains_into_test_plugin_store() {
    use ovstorage_plugin::BodyStream;

    let fx = Fixture::open();
    let root = fx.add_route("test://b1-stream/", &[]).await;
    let object = address::join_relative(&root, "streamed.bin").unwrap();
    let chunks: Vec<Result<Vec<u8>, _>> = vec![
        Ok(b"hello ".to_vec()),
        Ok(b"streaming ".to_vec()),
        Ok(b"world".to_vec()),
    ];
    let body = Body::Stream(BodyStream::from_iter(chunks.into_iter()));
    let result = fx
        .library
        .write(object.clone(), body, WriteOptions::default(), None)
        .await
        .expect("streaming write completes via write_stream");

    assert_eq!(
        result.info.address.as_str(),
        object.as_str(),
        "address normalization preserves the caller-facing URL"
    );
    let info = fx
        .library
        .stat(object, StatOptions::default(), None)
        .await
        .expect("stat after streaming write");
    assert_eq!(info.size, Some(21));

    let counts = fx.method_calls(&root).await;
    assert_eq!(counts["write_stream"], 1);
    // The test plugin's `write_redirect` returns Unsupported (no
    // `test_redirect_url`), so the host falls back to `write_stream`.
    assert_eq!(counts["write_redirect"], 1);
    assert_eq!(counts["write"], 0);
}

#[tokio::test]
async fn continue_write_cardinality_mismatch_surfaces_error() {
    // The plugin's `continue_write` calls `validate_redirect_results`
    // which surfaces `InvalidArgument` when batch lengths mismatch.
    // The host produces results from its own follower, so this can't
    // happen in normal operation — but the plugin's check runs on the
    // host side via the SPI, and we exercise it directly through the
    // `shim::Backend` trait to pin the contract.
    use ovstorage_plugin::{
        BackendId, RedirectResult, RedirectResultBatch, ResolvedTarget, WriteRedirectBatch,
    };

    let factory = TestFactory::new();
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://b1-card/".into()),
    );
    config.insert(
        "test_redirect_url".into(),
        ConfigValue::String("https://test.example".into()),
    );
    config.insert("test_multipart_parts".into(), ConfigValue::Int(2));
    let request = ConnectionRequest {
        backend_kind: "test".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    use ovstorage_plugin::shim::Factory as _;
    let instance = factory.instantiate(&request, None).await.unwrap();
    let target = ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: address::parse("test://b1-card/x").unwrap(),
    };
    let bogus = WriteRedirectBatch {
        continuation: vec![],
        redirects: vec![],
    };
    let mismatched_results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 200,
            captured_headers: vec![],
            captured_body: vec![],
        }],
    };
    let err = instance
        .backend
        .continue_write(target, bogus, mismatched_results, None)
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        ErrorCode::InvalidArgument,
        "validate_redirect_results should reject mismatched cardinality"
    );
}

// ---------------------------------------------------------------------
// Batch 2 — watch_directory dispatch
// ---------------------------------------------------------------------

#[tokio::test]
async fn watch_stream_forwards_n_events_in_order() {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b2-events/",
            &[
                ("test_caps_watch", ConfigValue::Bool(true)),
                ("test_watch_event_count", ConfigValue::Int(5)),
            ],
        )
        .await;
    let stream = fx
        .library
        .watch_directory(root, WatchDirectoryOptions::default(), None)
        .await
        .expect("watch_directory");
    let events: Vec<_> = stream.collect();
    assert_eq!(events.len(), 5);
    for (i, event) in events.iter().enumerate() {
        match event.as_ref().unwrap() {
            ChangeEvent::Object { cursor, .. } => {
                assert_eq!(cursor.0, vec![i as u8], "events should arrive in order");
            }
            other => panic!("expected Object at index {i}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn watch_stream_forwards_lapsed_event() {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b2-lapsed/",
            &[
                ("test_caps_watch", ConfigValue::Bool(true)),
                ("test_watch_event_count", ConfigValue::Int(3)),
                ("test_watch_lapsed_at", ConfigValue::Int(2)),
            ],
        )
        .await;
    let stream = fx
        .library
        .watch_directory(root, WatchDirectoryOptions::default(), None)
        .await
        .expect("watch_directory");
    let events: Vec<_> = stream.collect();
    // 3 Object events + 1 Lapsed inserted at index 2 = 4 total.
    assert_eq!(events.len(), 4);
    match events[2].as_ref().unwrap() {
        ChangeEvent::Lapsed { .. } => {}
        other => panic!("expected Lapsed at index 2, got {other:?}"),
    }
}

#[tokio::test]
async fn watch_stream_zero_events_terminates_cleanly() {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b2-empty/",
            &[
                ("test_caps_watch", ConfigValue::Bool(true)),
                ("test_watch_event_count", ConfigValue::Int(0)),
            ],
        )
        .await;
    let stream = fx
        .library
        .watch_directory(root, WatchDirectoryOptions::default(), None)
        .await
        .expect("watch_directory");
    let events: Vec<_> = stream.collect();
    assert!(events.is_empty());
}

// ---------------------------------------------------------------------
// Batch 6 — multi-route isolation, introspection, multi-instance reuse
// ---------------------------------------------------------------------

#[tokio::test]
async fn multi_route_isolation_keeps_state_separate() {
    let fx = Fixture::open();
    let alpha = fx.add_route("test://b6-alpha/", &[]).await;
    let beta = fx.add_route("test://b6-beta/", &[]).await;
    fx.library
        .write(
            address::join_relative(&alpha, "a.txt").unwrap(),
            Body::Bytes(b"alpha".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let listing = fx
        .library
        .list(beta, Default::default(), None)
        .await
        .expect("list on beta route");
    assert!(
        listing.is_empty(),
        "beta route should not see alpha's bytes"
    );
}

#[tokio::test]
async fn introspection_path_via_host_shows_method_calls() {
    let fx = Fixture::open();
    let root = fx.add_route("test://b6-intro/", &[]).await;
    fx.library
        .write(
            address::join_relative(&root, "a").unwrap(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    fx.library
        .stat(
            address::join_relative(&root, "a").unwrap(),
            StatOptions::default(),
            None,
        )
        .await
        .unwrap();
    let counts = fx.method_calls(&root).await;
    assert_eq!(counts["write"], 1);
    assert_eq!(counts["stat"], 1);
    // The meta read itself bumps `read` to 1.
    assert_eq!(counts["read"], 1);
}

#[tokio::test]
async fn duplicate_route_prefix_via_add_connection_rejected() {
    let fx = Fixture::open();
    fx.add_connection("test://b6-dup/", &[]).await;
    // Second add with same root must be rejected — the host pins the
    // "no duplicate route prefix" contract per its existing
    // `duplicate_route_prefix_is_rejected` test, but only at builder
    // time. Here we verify it through `add_connection`'s lifetime.
    let mut config = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://b6-dup/".into()),
    );
    let result = fx
        .library
        .add_connection(
            ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("dup".into()),
            },
            None,
        )
        .await;
    let err = match result {
        Ok(_) => panic!("duplicate add_connection should be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::RouteConflict);
}

#[tokio::test]
async fn remove_then_readd_connection_preserves_factory_store() {
    let fx = Fixture::open();
    // Stage bytes, then remove the connection, then re-add at the same
    // root. The TestFactory keys its per-root instance state by root
    // string — so the re-added connection should see the original bytes.
    let conn1 = fx.add_connection("test://b6-readd/", &[]).await;
    let root = conn1.current_addresses[0].clone();
    fx.library
        .write(
            address::join_relative(&root, "preserved.txt").unwrap(),
            Body::Bytes(b"survives".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    fx.library
        .remove_connection(&conn1.id)
        .expect("remove_connection");

    let conn2 = fx.add_connection("test://b6-readd/", &[]).await;
    let root2 = conn2.current_addresses[0].clone();
    let (bytes, _info) = fx
        .library
        .read_bytes(
            address::join_relative(&root2, "preserved.txt").unwrap(),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("re-added connection should see old bytes via factory store");
    assert_eq!(bytes, b"survives");
    assert_ne!(conn1.id, conn2.id, "new connection has a fresh ID");
}

// ---------------------------------------------------------------------
// Batch 5 — update_credentials, versioning, copy emulation distinction
// ---------------------------------------------------------------------

#[tokio::test]
async fn update_credentials_dispatches_to_factory() {
    let fx = Fixture::open();
    let conn = fx.add_connection("test://b5-creds/", &[]).await;
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "token".into(),
        SecretValue::Bytes(SecretBytes(b"new".to_vec())),
    );
    fx.library
        .update_connection_credentials(&conn.id, bundle, None)
        .await
        .expect("update_connection_credentials");
    // The TestFactory's update_credentials returns Ok(()) by default —
    // the host's plumbing should reach it without error. We can't peek
    // at the factory's internal state without introspection on the
    // factory side, but a successful call pins the dispatch path.
}

#[tokio::test]
async fn list_versions_returns_chain_with_current_last() {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b5-versions/",
            &[("test_caps_versioning", ConfigValue::Bool(true))],
        )
        .await;
    let object = address::join_relative(&root, "doc.txt").unwrap();
    for v in 0..3 {
        fx.library
            .write(
                object.clone(),
                Body::Bytes(format!("v{v}").into_bytes()),
                WriteOptions::default(),
                None,
            )
            .await
            .unwrap();
    }
    let object_str = object.as_str().to_owned();
    let versions = fx
        .library
        .list_versions(object, ListVersionsOptions::default(), None)
        .await
        .expect("list_versions");
    assert_eq!(versions.len(), 3);
    for (i, v) in versions.iter().enumerate() {
        let expected_version = format!("v{i}");
        assert_eq!(
            v.address.as_str(),
            format!("{object_str}?version={expected_version}")
        );
        assert_eq!(v.version.as_deref(), Some(expected_version.as_str()));
    }
}

#[tokio::test]
async fn server_side_copy_when_capability_advertised_calls_backend() {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b5-copy-cap/",
            &[("test_caps_server_copy", ConfigValue::Bool(true))],
        )
        .await;
    let src = address::join_relative(&root, "src.txt").unwrap();
    let dst = address::join_relative(&root, "dst.txt").unwrap();
    fx.library
        .write(
            src.clone(),
            Body::Bytes(b"data".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    fx.library
        .copy(src, dst, CopyOptions::default(), None)
        .await
        .expect("server-side copy");
    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["copy"], 1,
        "host should call backend.copy when capability is advertised"
    );
    // The setup write counts; copy should not have triggered another.
    assert_eq!(counts["write"], 1);
}

#[tokio::test]
async fn server_side_copy_when_capability_unset_emulates_via_read_write() {
    let fx = Fixture::open();
    // Default `test_caps=minimal` does NOT set supports_server_side_copy.
    let root = fx.add_route("test://b5-copy-emul/", &[]).await;
    let src = address::join_relative(&root, "src.txt").unwrap();
    let dst = address::join_relative(&root, "dst.txt").unwrap();
    fx.library
        .write(
            src.clone(),
            Body::Bytes(b"data".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    fx.library
        .copy(src, dst, CopyOptions::default(), None)
        .await
        .expect("emulated copy");
    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["copy"], 0,
        "host should not invoke backend.copy when capability unset"
    );
    // Setup write + emulation write = 2 total writes; emulation also reads.
    assert_eq!(counts["write"], 2);
    assert!(
        counts["read"].as_u64().unwrap() >= 1,
        "emulation should read the source at least once"
    );
}

// ---------------------------------------------------------------------
// Batch 4 — error code round-trip + retry policy pin
// ---------------------------------------------------------------------

async fn assert_inject_round_trips(error_code: &str) {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            &format!("test://b4-{}/", error_code.to_lowercase()),
            &[
                ("test_inject_error_on", ConfigValue::String("read".into())),
                (
                    "test_inject_error_code",
                    ConfigValue::String(error_code.into()),
                ),
            ],
        )
        .await;
    // Pre-stage an object so a non-injected read would have bytes to
    // return — that way we know the failure is from injection, not
    // from a missing key.
    let object = address::join_relative(&root, "k.txt").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("pre-stage write");

    let err = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("inject should fail the read");
    let actual = format!("{:?}", err.code());
    assert_eq!(
        actual, error_code,
        "host should preserve {error_code} unchanged"
    );
}

#[tokio::test]
async fn plugin_NotFound_round_trips_unchanged() {
    assert_inject_round_trips("NotFound").await;
}

#[tokio::test]
async fn plugin_PermissionDenied_round_trips_unchanged() {
    assert_inject_round_trips("PermissionDenied").await;
}

#[tokio::test]
async fn plugin_PreconditionFailed_round_trips_unchanged() {
    assert_inject_round_trips("PreconditionFailed").await;
}

#[tokio::test]
async fn plugin_Conflict_round_trips_unchanged() {
    assert_inject_round_trips("Conflict").await;
}

#[tokio::test]
async fn plugin_Transient_retries_until_budget_then_surfaces() {
    // The library wraps idempotent SPI calls in a retry loop and
    // hits the plugin TEST_MAX_ATTEMPTS times before surfacing the
    // last `Transient` to the caller. The test plugin's
    // `test_inject_error_count` defaults to -1 (inject forever) so
    // every attempt fails; the retry budget exhausts and the
    // caller sees `Transient`.
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b4-transient/",
            &[
                ("test_inject_error_on", ConfigValue::String("read".into())),
                (
                    "test_inject_error_code",
                    ConfigValue::String("Transient".into()),
                ),
            ],
        )
        .await;
    let object = address::join_relative(&root, "k.txt").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let err = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("Transient should still surface after retry budget");
    assert_eq!(err.code(), ErrorCode::Transient);

    // Counter = TEST_MAX_ATTEMPTS user reads (each attempt hits the
    // plugin) + 1 meta read. The fixture's `method_calls` triggers
    // one introspection read after the user op completes.
    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["read"],
        u64::from(TEST_MAX_ATTEMPTS) + 1,
        "host should retry Transient up to max_attempts ({TEST_MAX_ATTEMPTS}) + 1 introspection meta read"
    );
}

#[tokio::test]
async fn plugin_BrokerUnavailable_retries_until_budget_then_surfaces() {
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b4-broker-unavail/",
            &[
                ("test_inject_error_on", ConfigValue::String("read".into())),
                (
                    "test_inject_error_code",
                    ConfigValue::String("BrokerUnavailable".into()),
                ),
            ],
        )
        .await;
    let object = address::join_relative(&root, "k.txt").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let err = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("BrokerUnavailable should still surface after retry budget");
    assert_eq!(err.code(), ErrorCode::BrokerUnavailable);

    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["read"],
        u64::from(TEST_MAX_ATTEMPTS) + 1,
        "host should retry BrokerUnavailable up to max_attempts ({TEST_MAX_ATTEMPTS}) + 1 introspection meta read"
    );
}

#[tokio::test]
async fn plugin_Transient_recovers_within_budget() {
    // Inject 2 Transients, then succeed. The retry loop consumes
    // the 2 injected errors and a single user-visible `read_bytes`
    // call returns successfully.
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b4-transient-recovers/",
            &[
                ("test_inject_error_on", ConfigValue::String("read".into())),
                (
                    "test_inject_error_code",
                    ConfigValue::String("Transient".into()),
                ),
                ("test_inject_error_count", ConfigValue::Int(2)),
            ],
        )
        .await;
    let object = address::join_relative(&root, "k.txt").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"survives".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    let (bytes, _info) = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("retry consumes 2 injected errors and returns bytes");
    assert_eq!(bytes, b"survives");

    let counts = fx.method_calls(&root).await;
    // 2 failed attempts + 1 successful attempt + 1 introspection.
    assert_eq!(
        counts["read"], 4,
        "host should hit the plugin 3 times (2 injected fails + 1 success) + 1 meta read"
    );
}

#[tokio::test]
#[allow(non_snake_case)]
async fn plugin_NotFound_skips_retry_loop() {
    // `NotFound` is not retryable; surface immediately with the
    // counter at 1 user read + 1 meta read, regardless of retry
    // budget.
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b4-not-found-noretry/",
            &[
                ("test_inject_error_on", ConfigValue::String("read".into())),
                (
                    "test_inject_error_code",
                    ConfigValue::String("NotFound".into()),
                ),
            ],
        )
        .await;
    let object = address::join_relative(&root, "k.txt").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"x".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    let err = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("NotFound surfaces immediately");
    assert_eq!(err.code(), ErrorCode::NotFound);

    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["read"], 2,
        "non-retryable error: 1 user read + 1 meta read"
    );
}

// ---------------------------------------------------------------------
// Batch 3 — auth event flow variants
// ---------------------------------------------------------------------

async fn collect_auth_events(fx: &Fixture, id: &ConnectionId) -> Vec<AuthEvent> {
    let stream = fx
        .library
        .authenticate_connection(id, None)
        .await
        .expect("authenticate_connection");
    stream.map(|r| r.expect("auth event")).collect()
}

#[tokio::test]
async fn authenticate_emits_failed_event() {
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-fail/",
            &[("test_auth_flow", ConfigValue::String("fail".into()))],
        )
        .await;
    let events = collect_auth_events(&fx, &conn.id).await;
    assert_eq!(events.len(), 1);
    match &events[0] {
        AuthEvent::Failed { error } => assert_eq!(error.code(), ErrorCode::AuthRequired),
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[tokio::test]
async fn authenticate_emits_cancelled_event() {
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-cancel/",
            &[("test_auth_flow", ConfigValue::String("cancel".into()))],
        )
        .await;
    let events = collect_auth_events(&fx, &conn.id).await;
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], AuthEvent::Cancelled));
}

#[tokio::test]
async fn authenticate_progress_then_succeeded_emits_two_events() {
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-progress/",
            &[(
                "test_auth_flow",
                ConfigValue::String("progress-then-succeed".into()),
            )],
        )
        .await;
    let events = collect_auth_events(&fx, &conn.id).await;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], AuthEvent::Progress { .. }));
    assert!(matches!(events[1], AuthEvent::Succeeded { .. }));
}

#[tokio::test]
async fn authenticate_open_browser_then_succeeded_emits_two_events() {
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-browser/",
            &[(
                "test_auth_flow",
                ConfigValue::String("open-browser-then-succeed".into()),
            )],
        )
        .await;
    let events = collect_auth_events(&fx, &conn.id).await;
    assert_eq!(events.len(), 2);
    match &events[0] {
        AuthEvent::OpenBrowser { url, .. } => {
            assert!(url.starts_with("https://"))
        }
        other => panic!("expected OpenBrowser, got {other:?}"),
    }
    assert!(matches!(events[1], AuthEvent::Succeeded { .. }));
}

#[tokio::test]
async fn authenticate_device_code_then_succeeded_emits_two_events() {
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-device/",
            &[(
                "test_auth_flow",
                ConfigValue::String("device-code-then-succeed".into()),
            )],
        )
        .await;
    let events = collect_auth_events(&fx, &conn.id).await;
    assert_eq!(events.len(), 2);
    match &events[0] {
        AuthEvent::DeviceCode {
            user_code,
            verification_url,
            ..
        } => {
            assert!(!user_code.is_empty());
            assert!(verification_url.starts_with("https://"));
        }
        other => panic!("expected DeviceCode, got {other:?}"),
    }
    assert!(matches!(events[1], AuthEvent::Succeeded { .. }));
}

#[tokio::test]
async fn authenticate_drives_host_keyring_round_trip() {
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-keyring/",
            &[("test_auth_drives_host_callbacks", ConfigValue::Bool(true))],
        )
        .await;
    // The plugin's `authenticate` should put/get/delete on the host's
    // keyring while emitting events. If the SecretStore plumbing is
    // broken, the plugin returns Failed.
    let events = collect_auth_events(&fx, &conn.id).await;
    let succeeded = events
        .iter()
        .any(|e| matches!(e, AuthEvent::Succeeded { .. }));
    assert!(
        succeeded,
        "host keyring round-trip should succeed; got events {events:?}"
    );
}

#[tokio::test]
async fn authenticate_drives_host_refresh_lock() {
    // Same shape as the keyring test — we don't peek inside the lock,
    // we just verify the call doesn't fail. The lock files appear in
    // the auth substrate's tempdir but the lock itself has no
    // observable read-after-write surface in the public Library API.
    let fx = Fixture::open();
    let conn = fx
        .add_connection(
            "test://b3-refresh/",
            &[("test_auth_drives_host_callbacks", ConfigValue::Bool(true))],
        )
        .await;
    let events = collect_auth_events(&fx, &conn.id).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AuthEvent::Succeeded { .. }))
    );
}

// ---------------------------------------------------------------------
// Cancellation + panic plumbing
// ---------------------------------------------------------------------

#[tokio::test]
async fn cancel_token_aborts_in_flight_read() {
    use tokio_util::sync::CancellationToken;
    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b7-cancel-aborts/",
            &[("test_read_delay_ms", ConfigValue::Int(2_000))],
        )
        .await;
    let object = address::join_relative(&root, "hello.txt").unwrap();
    // Pre-populate with a real value so the read would otherwise
    // succeed (after the 2s delay). The cancel must beat the delay.
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"unused-payload".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("seed write");

    let token = CancellationToken::new();
    let read_handle = {
        let library = fx.library.clone();
        let object = object.clone();
        let token = token.clone();
        tokio::spawn(async move {
            library
                .read_bytes(object, ReadOptions::default(), Some(token))
                .await
        })
    };
    // Let the plugin enter the delay, then cancel.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    token.cancel();

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), read_handle)
        .await
        .expect("read should resolve well before the 2s delay")
        .expect("task join");
    let err = result.expect_err("read should surface a cancellation error");
    assert_eq!(err.code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn cancel_token_after_completion_is_noop() {
    use tokio_util::sync::CancellationToken;
    let fx = Fixture::open();
    let root = fx.add_route("test://b7-cancel-noop/", &[]).await;
    let object = address::join_relative(&root, "data.bin").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"payload".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write");

    let token = CancellationToken::new();
    let (bytes, _info) = fx
        .library
        .read_bytes(object.clone(), ReadOptions::default(), Some(token.clone()))
        .await
        .expect("read succeeds");
    assert_eq!(bytes, b"payload");

    // Late cancel — token is dropped naturally below; the second
    // call must still work.
    token.cancel();
    let (bytes2, _info) = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("second read still works after late cancel");
    assert_eq!(bytes2, b"payload");
}

#[tokio::test]
async fn null_cancel_token_path_works() {
    let fx = Fixture::open();
    let root = fx.add_route("test://b7-null-cancel/", &[]).await;
    let object = address::join_relative(&root, "obj").unwrap();
    fx.library
        .write(
            object.clone(),
            Body::Bytes(b"ok".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write with None cancel");
    let info = fx
        .library
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat with None cancel");
    assert_eq!(info.size, Some(2));
    let (bytes, _info) = fx
        .library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("read with None cancel");
    assert_eq!(bytes, b"ok");
}

// Note: `panic_in_plugin_method_surfaces_internal` lives in
// `ovstorage-plugin-test/tests/loaded.rs` rather than this file. The
// catch_unwind that converts a plugin panic into ErrorCode::Internal
// runs inside the FFI thunks, which the rlib-style registration here
// bypasses. The dlopen test exercises the FFI path and verifies the
// panic surfaces correctly.

#[tokio::test]
async fn watch_directory_blocked_when_capability_unset() {
    let fx = Fixture::open();
    // Default `test_caps=minimal` does NOT set supports_watch_directory.
    let root = fx.add_route("test://b2-nocap/", &[]).await;
    let result = fx
        .library
        .watch_directory(root.clone(), WatchDirectoryOptions::default(), None)
        .await;
    let err = match result {
        Ok(_) => panic!("watch should be capability-gated"),
        Err(err) => err,
    };
    assert_eq!(
        err.code(),
        ErrorCode::Unsupported,
        "host should refuse watch_directory when capability unset"
    );

    // Counter should be zero — gating must happen *before* the host
    // dispatches into the backend.
    let counts = fx.method_calls(&root).await;
    assert_eq!(
        counts["watch_directory"], 0,
        "watch_directory should not have been called on the backend"
    );
}

// ---------------------------------------------------------------------
// LocalFile redirect failure-mode tests (code-review Finding: missing
// Body::LocalFile becomes an empty redirected upload). The host must
// propagate the I/O error rather than synthesize an empty Vec.
// ---------------------------------------------------------------------

#[tokio::test]
async fn local_file_missing_path_fails_redirect_path_with_io_error() {
    use std::path::PathBuf;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Wiremock server: instrument PUT so we can prove no upload was
    // sent. The redirect path-of-fewest-resistance previously buffered
    // an empty Vec and PUT it; the fix makes the missing-file IO error
    // surface before any HTTP call.
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"empty-bad\""))
        .mount(&server)
        .await;

    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b1-localfile-missing/",
            &[
                ("test_redirect_url", ConfigValue::String(server.uri())),
                ("test_multipart_parts", ConfigValue::Int(1)),
                ("test_continue_write_loops", ConfigValue::Int(1)),
            ],
        )
        .await;
    let object = address::join_relative(&root, "missing.bin").unwrap();
    let missing_path = PathBuf::from("/definitely/not/a/real/path/missing-file.bin");
    let result = fx
        .library
        .write(
            object,
            Body::LocalFile(missing_path),
            WriteOptions::default(),
            None,
        )
        .await;
    let err = match result {
        Ok(_) => panic!("missing local file must surface an error"),
        Err(err) => err,
    };
    // io_error maps NotFound → ErrorCode::NotFound.
    assert_eq!(
        err.code(),
        ErrorCode::NotFound,
        "missing file must surface NotFound, not synthesize an empty PUT body"
    );
    // Wiremock should not have seen any PUT — host bailed before HTTP.
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "no PUT should have been issued for a missing source file (got {} requests)",
        received.len()
    );
}

#[tokio::test]
async fn buffered_write_redirect_retries_transient_http_status() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Wiremock returns 503 then 200 — the buffered write redirect path
    // must retry the idempotent PUT (per the fix to follow_write_redirects).
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .respond_with(ResponseTemplate::new(200).insert_header("etag", "\"part-ok\""))
        .mount(&server)
        .await;

    let fx = Fixture::open();
    let root = fx
        .add_route(
            "test://b1-buffered-retry/",
            &[
                ("test_redirect_url", ConfigValue::String(server.uri())),
                ("test_multipart_parts", ConfigValue::Int(1)),
                ("test_continue_write_loops", ConfigValue::Int(1)),
            ],
        )
        .await;
    let object = address::join_relative(&root, "retry.bin").unwrap();
    fx.library
        .write(
            object,
            Body::Bytes(b"DATA".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("buffered write should succeed after one retry");

    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.len() >= 2,
        "buffered write should issue PUT at least twice (got {})",
        received.len()
    );
}
