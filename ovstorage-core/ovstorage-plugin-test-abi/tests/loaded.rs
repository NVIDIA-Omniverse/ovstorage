// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loads the crate's cdylib via `dlopen` and exercises an end-to-end
//! vtable-slot slice across the ABI-v2 plugin FFI. The cdylib path is
//! set by `build.rs` as `OVSTORAGE_PLUGIN_TEST_SO`.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use ovstorage::ext::LayerExt as _;
use ovstorage::{LayerConnectionRequest, LayerTable, Request, Stack, StackConfig};
use ovstorage_plugin::{
    Body, ConfigValue, ConnectionRequest, ErrorCode, ListOptions, ReadOptions, SecretBundle,
    StatOptions, Url, WriteOptions, address,
};
use ovstorage_plugin_test::{Route, ScriptedResponse, start_responder_with_redirect};

const PLUGIN_PATH: &str = env!("OVSTORAGE_PLUGIN_TEST_SO");

/// Host substrate is set-once-per-process; tests share one auth_dir
/// and isolate via unique connection IDs.
fn shared_substrate_auth_dir() -> &'static tempfile::TempDir {
    static SHARED: OnceLock<tempfile::TempDir> = OnceLock::new();
    SHARED.get_or_init(|| {
        let temp = tempfile::tempdir().expect("auth tempdir");
        ovstorage::init_auth_substrate(Some(temp.path())).expect("init auth substrate");
        temp
    })
}

async fn open_stack() -> Arc<Stack> {
    let _ = shared_substrate_auth_dir();
    // SAFETY: the test harness intentionally opts into this test-only plugin.
    let mut factories =
        unsafe { ovstorage::load_layer_plugin(PLUGIN_PATH, true) }.expect("load test layer plugin");
    let plugin_dir = std::path::Path::new(PLUGIN_PATH)
        .parent()
        .expect("test plugin path has a parent");
    for stem in ["ovstorage_plugin_core", "ovstorage_plugin_http"] {
        let path = plugin_dir.join(format!(
            "{}{stem}{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
        // SAFETY: `make test` stages these first-party plugin cdylibs beside
        // the test backend before this ABI integration test runs.
        factories.extend(
            unsafe { ovstorage::load_layer_plugin(&path, false) }
                .unwrap_or_else(|error| panic!("load {}: {error}", path.display())),
        );
    }
    ovstorage::host::build_stack(
        &StackConfig {
            root: Some("redirect_follower".into()),
            layers: HashMap::from([
                (
                    "redirect_follower".into(),
                    LayerTable {
                        kind: Some("redirect_follower".into()),
                        inner: Some("retry".into()),
                        ..LayerTable::default()
                    },
                ),
                (
                    "retry".into(),
                    LayerTable {
                        kind: Some("retry".into()),
                        inner: Some("test".into()),
                        ..LayerTable::default()
                    },
                ),
                (
                    "test".into(),
                    LayerTable {
                        kind: Some("test".into()),
                        ..LayerTable::default()
                    },
                ),
            ]),
            connections: Vec::new(),
        },
        factories,
    )
    .await
    .expect("build test plugin Stack")
}

async fn add_connection(stack: &Stack, extra: &[(&str, ConfigValue)]) -> Url {
    let mut config: HashMap<String, ConfigValue> = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    for (k, v) in extra {
        config.insert((*k).into(), v.clone());
    }
    let connection = ovstorage::Layer::add_connection(
        stack,
        Request::new(LayerConnectionRequest {
            target: "test".into(),
            connection: ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("test-plugin-loaded".into()),
            },
        }),
        None,
    )
    .await
    .expect("add_connection");
    connection
        .current_addresses
        .first()
        .cloned()
        .expect("connection should expose a route prefix")
}

#[tokio::test]
async fn dlopen_round_trip_through_in_memory_store() {
    let stack = open_stack().await;
    let prefix = add_connection(&stack, &[]).await;

    let object = address::join_relative(&prefix, "hello.txt").unwrap();
    stack
        .write(
            object.clone(),
            Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write");

    let info = stack
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat");
    assert_eq!(info.size, Some(5));

    let (bytes, _info) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("read_bytes");
    assert_eq!(bytes, b"hello");

    let listing = stack
        .list_page(prefix.clone(), ListOptions::default(), None)
        .await
        .expect("list");
    assert!(listing.items.iter().any(|item| item.address == object));
}

#[tokio::test]
async fn dlopen_read_emits_redirect_when_url_configured() {
    let stack = open_stack().await;
    let (responder, redirect_kv) = start_responder_with_redirect(vec![Route::new(
        "GET",
        "/",
        ScriptedResponse::ok(b"hello-from-responder"),
    )])
    .expect("loopback responder binds");
    let prefix = add_connection(&stack, &[(redirect_kv.0, redirect_kv.1.clone())]).await;
    let object = address::join_relative(&prefix, "redirected.bin").unwrap();
    let (bytes, _info) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("redirect follower fetches scripted bytes");
    assert_eq!(bytes, b"hello-from-responder");
    let captures = responder.captures();
    assert!(
        !captures.is_empty(),
        "responder must observe the host's GET"
    );
    assert_eq!(captures[0].method, "GET");
    assert!(captures[0].path.ends_with("/redirected.bin"));
}

#[tokio::test]
async fn dlopen_multipart_write_runs_continue_write_loop() {
    let stack = open_stack().await;
    let (responder, redirect_kv) = start_responder_with_redirect(vec![Route::new(
        "PUT",
        "/",
        ScriptedResponse {
            status: 200,
            headers: vec![("etag".into(), "part-ok".into())],
            body: Vec::new(),
        },
    )])
    .expect("loopback responder binds");
    let prefix = add_connection(
        &stack,
        &[
            (redirect_kv.0, redirect_kv.1.clone()),
            ("test_multipart_parts", ConfigValue::Int(2)),
            ("test_continue_write_loops", ConfigValue::Int(2)),
        ],
    )
    .await;
    let object = address::join_relative(&prefix, "multipart.bin").unwrap();
    let _ = stack
        .write(
            object,
            Body::Bytes(b"DATA".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("multi-stage write completes against the loopback responder");
    let captures = responder.captures();
    assert!(
        captures.len() >= 4,
        "expected at least four PUT captures (2 parts * 2 loops), got {}",
        captures.len()
    );
    assert!(captures.iter().all(|c| c.method == "PUT"));
}

#[tokio::test]
async fn dlopen_introspection_returns_method_call_counter_after_injected_retries() {
    let stack = open_stack().await;
    let prefix = add_connection(
        &stack,
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

    let object = address::join_relative(&prefix, "with-retries.txt").unwrap();
    stack
        .write(
            object.clone(),
            Body::Bytes(b"survives".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write before injected reads");

    // Retry loop consumes 2 injected Transients; 3rd plugin call
    // returns bytes from one caller-side `read_bytes`.
    let (bytes, _info) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("retry budget consumes 2 injected errors and surfaces bytes");
    assert_eq!(bytes, b"survives");

    let meta = address::join_relative(&prefix, "__test_meta/method_calls.json").unwrap();
    let (meta_bytes, _info) = stack
        .read_bytes(meta, ReadOptions::default(), None)
        .await
        .expect("introspection read");
    let counts: serde_json::Value =
        serde_json::from_slice(&meta_bytes).expect("counters parse as JSON");
    // 3 retry-loop calls (2 injected + 1 success) + 1 meta read = 4.
    assert_eq!(counts["read"], 4);
    assert_eq!(counts["write"], 1);
}

/// Plugin Err must surface as Err without abandoning the oneshot;
/// library remains usable. The `panic_on_read_key` knob returns
/// Err(Internal) (rather than a live panic) to pin the Err-return
/// path; a genuine in-method panic on the dlopen path would also
/// surface as Internal via the thunk's `catch_unwind` wall.
#[tokio::test]
async fn dlopen_internal_error_in_plugin_method_surfaces_to_host() {
    let stack = open_stack().await;
    let prefix = add_connection(
        &stack,
        &[("test_panic_on_read_key", ConfigValue::String("boom".into()))],
    )
    .await;
    let object = address::join_relative(&prefix, "boom").unwrap();
    let err = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("plugin returned Err; should surface as Err");
    assert_eq!(err.code(), ErrorCode::Internal);

    let healthy = address::join_relative(&prefix, "post-panic.txt").unwrap();
    stack
        .write(
            healthy,
            Body::Bytes(b"alive".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("Stack survives plugin Err; subsequent calls work");
}

/// The host's route construction calls `list_address_roots` across the
/// FFI vtable. The plugin's snapshot round-trips into the route table,
/// proving the FFI thunk + host bridge wire up a `RootInfo`'s address +
/// capabilities end to end.
#[tokio::test]
async fn dlopen_list_address_roots_round_trip_through_ffi() {
    let stack = open_stack().await;
    let mut config: HashMap<String, ConfigValue> = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://dyn-roots/".into()),
    );
    config.insert("test_caps".into(), ConfigValue::String("full".into()));
    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "test".into(),
            connection: ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("dyn-roots".into()),
            },
        }),
        None,
    )
    .await
    .expect("add_connection");

    let prefix = connection
        .current_addresses
        .first()
        .cloned()
        .expect("connection emits at least one route");
    ovstorage::Layer::list_address_roots(&*stack, &ovstorage::Extensions::new(), None)
        .await
        .expect("list roots through the Stack");
    let meta = address::join_relative(&prefix, "__test_meta/method_calls.json").unwrap();
    // Poll the introspection counter until the host's route construction
    // drives one list_address_roots call across FFI.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut counters = serde_json::json!({});
    while std::time::Instant::now() < deadline {
        let (bytes, _info) = stack
            .read_bytes(meta.clone(), ReadOptions::default(), None)
            .await
            .expect("introspection read");
        counters = serde_json::from_slice(&bytes).expect("counters parse as JSON");
        if counters["list_address_roots"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        counters["list_address_roots"].as_u64().unwrap_or(0) >= 1,
        "list_address_roots should fire across the FFI; counters={counters}",
    );

    // The snapshot feeds the host's route table. Verify the connection's
    // current_addresses still expose the same prefix the test plugin
    // reports — the address round-tripped intact across FFI.
    let connections = stack
        .list_connections(None)
        .await
        .expect("list_connections after watcher fires");
    let snapshotted = connections
        .iter()
        .find(|c| c.id == connection.id)
        .expect("connection survives Snapshot apply");
    assert_eq!(
        snapshotted.current_addresses.first().map(|u| u.as_str()),
        Some(prefix.as_str()),
        "AddressRoot.address survives FFI round-trip; current_addresses={:?}",
        snapshotted.current_addresses,
    );
}

/// Companion to the `list_address_roots` round-trip: the per-URL
/// `root_info_for` query is a v8 async completion-callback slot too. Drive it
/// across the FFI vtable and prove the resolved `RootInfo` — address and layer
/// kind — round-trips intact from the loaded plugin back through the host.
#[tokio::test]
async fn dlopen_root_info_for_round_trip_through_ffi() {
    let stack = open_stack().await;
    let prefix = add_connection(&stack, &[]).await;
    let query = address::join_relative(&prefix, "some/object.txt").unwrap();
    let info =
        ovstorage::Layer::root_info_for(&*stack, &query, &ovstorage::Extensions::new(), None)
            .await
            .expect("root_info_for across the async v8 FFI slot");
    assert_eq!(
        info.root.as_str(),
        prefix.as_str(),
        "root address round-trips through the async v8 root_info_for slot",
    );
    assert_eq!(
        info.layer_kind, "test",
        "layer kind round-trips through the async v8 root_info_for slot",
    );
}

/// Companion to the two round-trips above: `list_connections` is the third v8
/// async completion-callback dynamic-query slot. Add a connection, then prove
/// it surfaces through the slot's snapshot back across the FFI.
#[tokio::test]
async fn dlopen_list_connections_round_trip_through_ffi() {
    let stack = open_stack().await;
    let prefix = add_connection(&stack, &[]).await;
    let connections = stack
        .list_connections(None)
        .await
        .expect("list_connections across the async v8 FFI slot");
    assert_eq!(
        connections.len(),
        1,
        "exactly the one added connection lists"
    );
    assert!(
        connections[0]
            .current_addresses
            .iter()
            .any(|u| u.as_str() == prefix.as_str()),
        "the added connection's address round-trips through the async v8 \
         list_connections slot",
    );
}

// host loader rejects test_only=true plugins unless allow_test_plugins=true;
// rejection surfaces as PluginRejected (policy refusal, not malformed binary).
#[test]
fn dlopen_test_plugin_is_rejected_without_allow_flag() {
    let _ = shared_substrate_auth_dir();
    let result = unsafe { ovstorage::load_layer_plugin(PLUGIN_PATH, false) };
    let error = result.err().expect("loader must reject test_only plugin");
    assert_eq!(
        error.code(),
        ErrorCode::PluginRejected,
        "expected PluginRejected, got {:?}: {}",
        error.code(),
        error.message()
    );
}

// Companion to the test above: `load_plugins_from_dir` (the bulk
// discovery path the broker and the REST gateway use at startup)
// must SKIP the test plugin when `allow_test_plugins=false` rather
// than fail the whole scan. Without this, the release archive's
// `plugins/` directory — which ships the test plugin so consumers
// can opt in to it — would crash every default-posture host that
// pointed at it.
#[test]
fn bulk_load_skips_test_plugin_without_allow_flag() {
    let _ = shared_substrate_auth_dir();
    let staging = tempfile::tempdir().expect("staging tempdir");
    let plugin_src = std::path::Path::new(PLUGIN_PATH);
    let plugin_name = plugin_src.file_name().expect("plugin filename");
    std::fs::copy(plugin_src, staging.path().join(plugin_name))
        .expect("copy test plugin into staging dir");
    let loaded = unsafe { ovstorage::load_layer_plugins_from_dir(staging.path(), false) }
        .expect("bulk load must succeed: test_only plugins are skipped, not fatal");
    assert!(loaded.is_empty(), "test-only factory must be skipped");
    // Direct load against the same path still surfaces the rejection
    // — discovery is lenient, but a host that explicitly asks for the
    // test plugin gets a clear error rather than silent inaction.
    let direct = unsafe { ovstorage::load_layer_plugin(plugin_src, false) };
    assert_eq!(
        direct.err().map(|e| e.code()),
        Some(ErrorCode::PluginRejected),
        "direct load_plugin must still surface PluginRejected",
    );
}

/// `next_action` must survive the plugin ABI.
///
/// The hint is set by `TestLayer::root_info_for` inside the dlopen'd cdylib
/// and read back here in the host binary, so the two are different images
/// with their own copy of `ovstorage-plugin`. That is the whole point: a
/// hint parked in a `static` side table on the plugin side is invisible to
/// the host's copy of that static, and a same-binary test cannot tell the
/// difference because there is only one map.
#[tokio::test(flavor = "multi_thread")]
async fn next_action_crosses_the_plugin_abi() {
    let stack = open_stack().await;
    let url = Url::parse("unroutable://nowhere/object").expect("probe url");

    let error =
        ovstorage::Layer::root_info_for(stack.as_ref(), &url, &ovstorage::Extensions::new(), None)
            .await
            .expect_err("an unroutable URL must fail");

    assert_eq!(error.code(), ErrorCode::NoRoute);
    assert_eq!(
        error.next_action(),
        Some(ovstorage_plugin_test::TEST_LAYER_NO_ROUTE_NEXT_ACTION),
        "the plugin's recovery hint must reach the host across the .so \
         boundary, not be dropped with the plugin's copy of the codec"
    );
}
