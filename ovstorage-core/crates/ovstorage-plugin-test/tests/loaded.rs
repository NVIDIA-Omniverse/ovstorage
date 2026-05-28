// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Loads the crate's cdylib via `dlopen` and exercises an end-to-end
//! SPI slice. The cdylib path is set by `build.rs` as
//! `OVSTORAGE_PLUGIN_TEST_SO`.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use ovstorage::Library;
use ovstorage::Storage as _;
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

fn open_library() -> Arc<Library> {
    let _ = shared_substrate_auth_dir();
    let library = Library::builder()
        // Cdylib manifest carries `test_only = true`; production
        // hosts reject it. Harness opts in here.
        .allow_test_plugins(true)
        .open()
        .expect("library open");
    unsafe {
        library.load_plugin(PLUGIN_PATH).expect("load_plugin");
    }
    library
}

async fn add_connection(library: &Arc<Library>, extra: &[(&str, ConfigValue)]) -> Url {
    let mut config: HashMap<String, ConfigValue> = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    for (k, v) in extra {
        config.insert((*k).into(), v.clone());
    }
    let connection = library
        .add_connection(
            ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("test-plugin-loaded".into()),
            },
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
    let library = open_library();
    let prefix = add_connection(&library, &[]).await;

    let object = address::join_relative(&prefix, "hello.txt").unwrap();
    library
        .write(
            object.clone(),
            Body::Bytes(b"hello".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write");

    let info = library
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat");
    assert_eq!(info.size, Some(5));

    let (bytes, _info) = library
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("read_bytes");
    assert_eq!(bytes, b"hello");

    let listing = library
        .list(prefix.clone(), ListOptions::default(), None)
        .await
        .expect("list");
    assert!(listing.iter().any(|item| item.address == object));
}

#[tokio::test]
async fn dlopen_read_emits_redirect_when_url_configured() {
    let library = open_library();
    let (responder, redirect_kv) = start_responder_with_redirect(vec![Route::new(
        "GET",
        "/",
        ScriptedResponse::ok(b"hello-from-responder"),
    )])
    .expect("loopback responder binds");
    let prefix = add_connection(&library, &[(redirect_kv.0, redirect_kv.1.clone())]).await;
    let object = address::join_relative(&prefix, "redirected.bin").unwrap();
    let (bytes, _info) = library
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
    let library = open_library();
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
        &library,
        &[
            (redirect_kv.0, redirect_kv.1.clone()),
            ("test_multipart_parts", ConfigValue::Int(2)),
            ("test_continue_write_loops", ConfigValue::Int(2)),
        ],
    )
    .await;
    let object = address::join_relative(&prefix, "multipart.bin").unwrap();
    let _ = library
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
    let library = open_library();
    let prefix = add_connection(
        &library,
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
    library
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
    let (bytes, _info) = library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("retry budget consumes 2 injected errors and surfaces bytes");
    assert_eq!(bytes, b"survives");

    let meta = address::join_relative(&prefix, "__test_meta/method_calls.json").unwrap();
    let (meta_bytes, _info) = library
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
/// library remains usable. Workspace `panic = "abort"` (FFI ABI
/// stability) means in-plugin panics abort the process, so the
/// `panic_on_read_key` knob returns Err(Internal) instead.
#[tokio::test]
async fn dlopen_internal_error_in_plugin_method_surfaces_to_host() {
    let library = open_library();
    let prefix = add_connection(
        &library,
        &[("test_panic_on_read_key", ConfigValue::String("boom".into()))],
    )
    .await;
    let object = address::join_relative(&prefix, "boom").unwrap();
    let err = library
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("plugin returned Err; should surface as Err");
    assert_eq!(err.code(), ErrorCode::Internal);

    let healthy = address::join_relative(&prefix, "post-panic.txt").unwrap();
    library
        .write(
            healthy,
            Body::Bytes(b"alive".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("library survives plugin Err; subsequent calls work");
}

/// The host always spawns a watcher that calls `watch_address_roots`
/// across the FFI vtable. The test plugin's one-shot `Snapshot`
/// round-trips into the route table, proving the FFI thunk + host
/// bridge wire up an `AddressRoot`'s address + capabilities end to end.
#[tokio::test]
async fn dlopen_watch_address_roots_round_trip_through_ffi() {
    let library = open_library();
    let mut config: HashMap<String, ConfigValue> = HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://dyn-roots/".into()),
    );
    config.insert("test_caps".into(), ConfigValue::String("full".into()));
    let connection = library
        .add_connection(
            ConnectionRequest {
                backend_kind: "test".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("dyn-roots".into()),
            },
            None,
        )
        .await
        .expect("add_connection");

    let prefix = connection
        .current_addresses
        .first()
        .cloned()
        .expect("connection emits at least one route");
    let meta = address::join_relative(&prefix, "__test_meta/method_calls.json").unwrap();
    // Poll the introspection counter until the host's spawn_address_roots_watcher
    // task drives one watch_address_roots call across FFI. The Snapshot the
    // plugin emits is one-shot (stream ends after a single frame), so the
    // method count saturates at 1.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut counters = serde_json::json!({});
    while std::time::Instant::now() < deadline {
        let (bytes, _info) = library
            .read_bytes(meta.clone(), ReadOptions::default(), None)
            .await
            .expect("introspection read");
        counters = serde_json::from_slice(&bytes).expect("counters parse as JSON");
        if counters["watch_address_roots"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        counters["watch_address_roots"].as_u64().unwrap_or(0) >= 1,
        "watch_address_roots should fire across the FFI; counters={counters}",
    );

    // The Snapshot replaces the connection's routes with the
    // plugin-emitted set. Verify the connection's current_addresses
    // still expose the same prefix the test plugin reports — the
    // address round-tripped intact across FFI.
    let connections = library
        .list_connections()
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

// host loader rejects test_only=true plugins unless allow_test_plugins=true;
// rejection surfaces as PluginRejected (policy refusal, not malformed binary).
#[test]
fn dlopen_test_plugin_is_rejected_without_allow_flag() {
    let _ = shared_substrate_auth_dir();
    let library = Library::builder()
        // No allow_test_plugins(true): production-host path.
        .open()
        .expect("library open");
    let result = unsafe { library.load_plugin(PLUGIN_PATH).map(|()| library) };
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
    let library = Library::builder()
        // No allow_test_plugins(true): production-host path.
        .open()
        .expect("library open");
    unsafe {
        library
            .load_plugins_from_dir(Some(staging.path()))
            .expect("bulk load must succeed: test_only plugins are skipped, not fatal");
    }
    // Direct load against the same path still surfaces the rejection
    // — discovery is lenient, but a host that explicitly asks for the
    // test plugin gets a clear error rather than silent inaction.
    let direct = unsafe { library.load_plugin(plugin_src) };
    assert_eq!(
        direct.err().map(|e| e.code()),
        Some(ErrorCode::PluginRejected),
        "direct load_plugin must still surface PluginRejected",
    );
}
