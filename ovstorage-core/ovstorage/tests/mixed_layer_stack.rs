// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A loaded ABI-v2 Layer cdylib (`ovstorage-plugin-test-layer`) and a native
//! Rust `FileBackend` compose in one `Stack` and round-trip operations.
//!
//! The two cdylibs are workspace members, so `cargo test --workspace`
//! (i.e. `make test` / `make test-ci`) builds them into the target
//! profile dir. When run via plain `cargo test -p ovstorage` they may be
//! absent, in which case the test skips.
//!

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;
use ovstorage::layers::FileBackendFactory;
use ovstorage_plugin_core::RouterFactoryImpl;

mod plugin_locator;

use ovstorage::{
    Body, CancellationToken, ConfigValue, ConnectionChange, ConnectionRequest, ErrorCode, Layer,
    LayerConfig, LayerConnectionRequest, LayerSpec, LoadedLayerFactory, ReadOptions, ReadRequest,
    ReadResult, Request, RootInfoChange, SecretBundle, Stack, StatOptions, StatRequest, Url,
    WriteOptions, WriteRequest,
};
use plugin_locator::plugin_so;

fn take_backend(factories: Vec<LoadedLayerFactory>) -> Arc<dyn ovstorage::BackendFactory> {
    for factory in factories {
        if let LoadedLayerFactory::Backend(backend) = factory {
            return backend;
        }
    }
    panic!("expected a backend-layer factory from the plugin");
}

#[tokio::test]
async fn loaded_plugin_and_native_layer_round_trip_in_one_stack() {
    let v2_so = match plugin_so("ovstorage_plugin_test_layer") {
        Some(v2) => v2,
        None => {
            eprintln!(
                "skipping mixed-layer Stack test: built plugin cdylibs not found next to the test binary \
                 (run via `cargo test --workspace` / `make test-ci`)"
            );
            return;
        }
    };

    ovstorage::init_auth_substrate(None).expect("init auth substrate");

    // v2 Layer cdylib -> create-by-layer_type (kind "mini-v2").
    let v2_backend = take_backend(
        unsafe { ovstorage::load_layer_plugin(&v2_so, true) }.expect("load v2 plugin"),
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let file_root = Url::from_directory_path(tmp.path()).expect("file root url");

    let mut v2_spec = LayerSpec::backend("v2", "mini-v2");
    v2_spec
        .config
        .insert("root".into(), ConfigValue::String("mini://dual/".into()));
    let mut file_spec = LayerSpec::backend("file", "file");
    file_spec
        .config
        .insert("root".into(), ConfigValue::String(file_root.to_string()));

    let stack = Stack::builder("router")
        .router_factory(Arc::new(RouterFactoryImpl))
        .backend_factory(v2_backend)
        .backend_factory(Arc::new(FileBackendFactory))
        .layer(LayerSpec::router(
            "router",
            "router",
            vec!["v2".into(), "file".into()],
        ))
        .layer(v2_spec)
        .layer(file_spec)
        .build()
        .await
        .expect("build mixed-layer stack");

    // Round-trip write -> read -> stat against each backend's root.
    let cases = [
        ("v2 (mini)", "mini://dual/obj.bin"),
        ("native file", &format!("{file_root}obj.bin")),
    ];
    for (label, addr) in cases {
        let url = Url::parse(addr).unwrap_or_else(|e| panic!("{label}: bad url {addr}: {e}"));
        let payload = format!("mixed-layer payload for {label}").into_bytes();

        stack
            .write(
                Request::new(WriteRequest {
                    address: url.clone(),
                    body: Body::Bytes(payload.clone()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));

        let read = stack
            .read(
                Request::new(ReadRequest {
                    address: url.clone(),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{label}: read failed: {e}"));
        match read {
            ReadResult::Bytes { bytes, .. } => {
                assert_eq!(bytes, payload, "{label}: read bytes mismatch");
            }
            // The native `FileBackend` hands off a whole-object `file://` read
            // as a `LocalDelegate` (a local path), not buffered bytes — the
            // intended behavior. Read the delegate path.
            ReadResult::LocalDelegate(local) => {
                let bytes = std::fs::read(&local.path)
                    .unwrap_or_else(|e| panic!("{label}: read delegate {:?}: {e}", local.path));
                assert_eq!(bytes, payload, "{label}: delegate bytes mismatch");
            }
            other => panic!("{label}: expected bytes or local delegate, got {other:?}"),
        }

        let info = stack
            .stat(
                Request::new(StatRequest {
                    address: url.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{label}: stat failed: {e}"));
        assert_eq!(info.size, Some(payload.len() as u64), "{label}: stat size");
    }

    // Cancel marshalling (CancelTokenFFI -> CancelTokenLocal -> the Layer's
    // token): a pre-canceled token surfaces ErrorCode::Cancelled through
    // the v2 backend.
    let cancel_addr = Url::parse("mini://dual/cancel-me").unwrap();
    stack
        .write(
            Request::new(WriteRequest {
                address: cancel_addr.clone(),
                body: Body::Bytes(b"x".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write cancel target");
    let canceled = CancellationToken::new();
    canceled.cancel();
    let err = stack
        .read(
            Request::new(ReadRequest {
                address: cancel_addr,
                options: ReadOptions::default(),
            }),
            Some(canceled),
        )
        .await
        .expect_err("a pre-canceled read must fail");
    assert_eq!(
        err.code(),
        ErrorCode::Cancelled,
        "expected Cancelled, got {err}"
    );

    // Stream-read marshalling (ReadResult::Stream across the FFI byte
    // stream): a `/stream` address returns a chunk stream the host drains.
    let stream_addr = Url::parse("mini://dual/blob/stream").unwrap();
    let stream_payload = b"streamed plugin bytes across the FFI boundary".to_vec();
    stack
        .write(
            Request::new(WriteRequest {
                address: stream_addr.clone(),
                body: Body::Bytes(stream_payload.clone()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("write stream target");
    let read = stack
        .read(
            Request::new(ReadRequest {
                address: stream_addr,
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("stream read");
    match read {
        ReadResult::Stream { mut stream, .. } => {
            let mut got = Vec::new();
            while let Some(chunk) = stream.next().await {
                got.extend_from_slice(&chunk.expect("stream chunk"));
            }
            assert_eq!(got, stream_payload, "streamed bytes mismatch");
        }
        other => panic!("expected ReadResult::Stream, got {other:?}"),
    }
}

/// The FFI update-stream bridge: a v2-FFI-loaded plugin
/// that emits root and connection changes *after* the initial snapshot must
/// reach the host across the ABI. The mini-v2 backend registers a subscriber
/// on each `list_address_roots` / `list_connections` call and pushes a
/// `*::Added` change from `add_connection`; the host bridges the plugin's
/// synchronous FFI pull streams back into async streams, so the host observes
/// both. Without the bridge the host drops these streams (snapshot-only), so
/// this regresses if the bridge is removed.
#[tokio::test]
async fn v2_plugin_root_and_connection_updates_bridge_across_ffi() {
    let v2_so = match plugin_so("ovstorage_plugin_test_layer") {
        Some(v2) => v2,
        None => {
            eprintln!(
                "skipping v2 update-stream bridge: built plugin cdylib not found \
                 (run via `cargo test --workspace` / `make test-ci`)"
            );
            return;
        }
    };

    ovstorage::init_auth_substrate(None).expect("init auth substrate");

    let v2_backend = take_backend(
        unsafe { ovstorage::load_layer_plugin(&v2_so, true) }.expect("load v2 plugin"),
    );

    // Instantiate the backend Layer directly so we drive the FFI
    // `list_address_roots` / `list_connections` / `add_connection` slots and
    // their bridged update streams in isolation (no Router in between). The
    // full Router-consumes-the-stream propagation is a separate end-to-end gate.
    let mut config = LayerConfig::new();
    config.insert("root".into(), ConfigValue::String("mini://bridge/".into()));
    let layer = v2_backend
        .create_backend("v2", &config, None)
        .await
        .expect("create mini-v2 backend");

    // Subscribe to both update streams BEFORE mutating, so the post-snapshot
    // change is observed on the stream rather than folded into a later snapshot.
    let (root_snapshot, root_stream) = layer
        .list_address_roots(&ovstorage::Extensions::new(), None)
        .await
        .expect("list_address_roots");
    let mut root_stream = root_stream.expect("v2 plugin advertises a root-update stream");
    assert!(
        root_snapshot
            .roots
            .iter()
            .all(|r| r.root.as_str() != "mini://runtime/"),
        "runtime root must not be present before add_connection"
    );

    let (conn_snapshot, conn_stream) = layer
        .list_connections(&ovstorage::Extensions::new(), None)
        .await
        .expect("list_connections");
    let mut conn_stream = conn_stream.expect("v2 plugin advertises a connection-update stream");
    assert!(conn_snapshot.connections.is_empty());

    // Add a connection (a new root) after both snapshots.
    let mut conn_config = HashMap::new();
    conn_config.insert(
        "root".to_string(),
        ConfigValue::String("mini://runtime/".into()),
    );
    let request = LayerConnectionRequest {
        target: "v2".into(),
        connection: ConnectionRequest {
            backend_kind: "mini-v2".into(),
            config: conn_config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        },
    };
    layer
        .add_connection(Request::new(request), None)
        .await
        .expect("add_connection");

    // The plugin pushed a `RootInfoChange::Added` — the host must observe it
    // through the bridged async stream.
    let root_change = tokio::time::timeout(Duration::from_secs(5), root_stream.next())
        .await
        .expect("root update did not arrive across the FFI bridge")
        .expect("root-update stream ended early")
        .expect("root-update stream error");
    match root_change {
        RootInfoChange::Added(roots) => assert!(
            roots.iter().any(|r| r.root.as_str() == "mini://runtime/"),
            "expected the added runtime root, got {roots:?}"
        ),
        other => panic!("expected RootInfoChange::Added, got {other:?}"),
    }

    // ...and the matching `ConnectionChange::Added`.
    let conn_change = tokio::time::timeout(Duration::from_secs(5), conn_stream.next())
        .await
        .expect("connection update did not arrive across the FFI bridge")
        .expect("connection-update stream ended early")
        .expect("connection-update stream error");
    match conn_change {
        ConnectionChange::Added(connection) => assert!(
            connection
                .current_addresses
                .iter()
                .any(|a| a.as_str() == "mini://runtime/"),
            "expected the added connection's runtime root, got {connection:?}"
        ),
        other => panic!("expected ConnectionChange::Added, got {other:?}"),
    }
}
