// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stack-native ABI-v2 connection lifecycle coverage.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use ovstorage::ext::LayerExt;
use ovstorage::{
    Body, ConfigValue, ConnectionAuthState, ConnectionConfig, ConnectionKey, ConnectionRequest,
    ErrorCode, Layer, LayerConnectionRequest, LayerSpec, ReadOptions, Request, SecretBundle, Stack,
    StackConfig, StatOptions, UpdateConnectionCredentialsRequest, Url, WriteOptions,
};
use ovstorage_plugin_test::TestLayerFactory;

mod support;

async fn empty_file_stack() -> Arc<Stack> {
    ovstorage::host::build_stack(
        &StackConfig {
            root: Some("file".into()),
            layers: support::linear_stack_config("file", &[]).layers,
            connections: Vec::new(),
        },
        Vec::new(),
    )
    .await
    .expect("build file Stack")
}

fn file_connection_request(root: &Url) -> ConnectionRequest {
    ConnectionRequest {
        backend_kind: "file".into(),
        config: HashMap::from([("root".into(), ConfigValue::String(root.to_string()))]),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: Some("workspace".into()),
    }
}

async fn add_file_connection(stack: &Stack, root: &Url) -> ovstorage::Connection {
    stack
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "file".into(),
                connection: file_connection_request(root),
            }),
            None,
        )
        .await
        .expect("add native file connection")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_add_connection_resolves_native_file_backend_without_cdylib() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let file = root.join("obj.txt").unwrap();
    let stack = empty_file_stack().await;

    let connection = add_file_connection(&stack, &root).await;
    assert_eq!(connection.backend_kind, "file");
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    assert!(
        connection
            .current_addresses
            .iter()
            .any(|address| address == &root)
    );

    let (connections, _) = Layer::list_connections(&*stack, &ovstorage::Extensions::new(), None)
        .await
        .expect("list connections");
    assert!(
        connections
            .connections
            .iter()
            .any(|item| item.id == connection.id)
    );
    let (roots, _) = Layer::list_address_roots(&*stack, &ovstorage::Extensions::new(), None)
        .await
        .expect("list roots");
    assert!(roots.roots.iter().any(|item| item.root == root));
    assert!(
        stack
            .root_info_for(&file, &ovstorage::Extensions::new(), None)
            .await
            .expect("root info")
            .capabilities
            .supports_write
    );

    LayerExt::write(
        &*stack,
        file.clone(),
        Body::Bytes(b"stack-file".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .expect("write through Stack");
    let (bytes, info) = stack
        .read_bytes(file.clone(), ReadOptions::default(), None)
        .await
        .expect("read through Stack");
    assert_eq!(bytes, b"stack-file");
    assert_eq!(info.address, file);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_config_loader_resolves_native_file_backend() {
    let data = tempfile::tempdir().unwrap();
    let cfg_dir = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(data.path()).unwrap();
    let file = root.join("cfg.txt").unwrap();
    let config_path = cfg_dir.path().join("ovstorage.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"[ovstorage]
root = "file"

[ovstorage.layers.file]

[[ovstorage.connections]]
backend_kind = "file"
config = {{ root = "{root}" }}
"#,
        ),
    )
    .unwrap();

    let config = StackConfig::from_toml_path(&config_path).expect("parse Stack config");
    let stack = ovstorage::host::build_stack(&config, Vec::new())
        .await
        .expect("build configured Stack");
    let (connections, _) = Layer::list_connections(&*stack, &ovstorage::Extensions::new(), None)
        .await
        .expect("list connections");
    assert_eq!(connections.connections.len(), 1);

    LayerExt::write(
        &*stack,
        file.clone(),
        Body::Bytes(b"from-config".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .expect("write via configured connection");
    let (bytes, _) = stack
        .read_bytes(file, ReadOptions::default(), None)
        .await
        .unwrap();
    assert_eq!(bytes, b"from-config");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_update_credentials_reports_file_backend_limitations() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Url::from_directory_path(tmp.path()).unwrap();
    let stack = empty_file_stack().await;
    let connection = add_file_connection(&stack, &root).await;

    let error = stack
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "file".into(),
                    id: connection.id.clone(),
                },
                credentials: SecretBundle::default(),
            }),
            None,
        )
        .await
        .expect_err("the file backend does not support credential updates");
    assert_eq!(error.code(), ErrorCode::Unsupported);
}

async fn empty_test_stack() -> Arc<Stack> {
    Arc::new(
        Stack::builder("test")
            .backend_factory(Arc::new(TestLayerFactory::default()))
            .layer(LayerSpec::backend("test", "test"))
            .build()
            .await
            .expect("build test Stack"),
    )
}

async fn add_test_connection(stack: &Stack, root: &str) -> ovstorage::Connection {
    stack
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "test".into(),
                connection: ConnectionRequest {
                    backend_kind: "test".into(),
                    config: HashMap::from([("test_root".into(), ConfigValue::String(root.into()))]),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("add test connection")
}

#[tokio::test]
async fn stack_test_connections_isolate_state_by_root() {
    let stack = empty_test_stack().await;
    add_test_connection(&stack, "test://isolation-a/").await;
    add_test_connection(&stack, "test://isolation-b/").await;
    let a_only = Url::parse("test://isolation-a/a-only.txt").unwrap();
    let b_view_of_a = Url::parse("test://isolation-b/a-only.txt").unwrap();
    let b_only = Url::parse("test://isolation-b/b-only.txt").unwrap();
    let a_view_of_b = Url::parse("test://isolation-a/b-only.txt").unwrap();

    LayerExt::write(
        &*stack,
        a_only,
        Body::Bytes(b"alpha".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    let error = stack
        .read_bytes(b_view_of_a, ReadOptions::default(), None)
        .await
        .expect_err("root B must not see root A state");
    assert_eq!(error.code(), ErrorCode::NotFound);

    LayerExt::write(
        &*stack,
        b_only,
        Body::Bytes(b"beta".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    let error = stack
        .read_bytes(a_view_of_b, ReadOptions::default(), None)
        .await
        .expect_err("root A must not see root B state");
    assert_eq!(error.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn stack_test_connection_remove_then_readd_preserves_factory_store() {
    let stack = empty_test_stack().await;
    let first = add_test_connection(&stack, "test://readd/").await;
    let object = Url::parse("test://readd/preserved.txt").unwrap();
    LayerExt::write(
        &*stack,
        object.clone(),
        Body::Bytes(b"survives".to_vec()),
        WriteOptions::default(),
        None,
    )
    .await
    .unwrap();
    stack
        .remove_connection(
            Request::new(ConnectionKey {
                target: "test".into(),
                id: first.id.clone(),
            }),
            None,
        )
        .await
        .expect("remove test connection");

    let second = add_test_connection(&stack, "test://readd/").await;
    assert_ne!(first.id, second.id);
    let (bytes, _) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("re-added root must retain factory-owned bytes");
    assert_eq!(bytes, b"survives");
}

fn spawn_http_object(body: &'static [u8]) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(2) {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 1024];
            let len = stream.read(&mut buf).unwrap();
            let payload = if buf[..len].starts_with(b"HEAD ") {
                &b""[..]
            } else {
                body
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v2http\"\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(payload).unwrap();
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_loads_real_http_cdylib_and_round_trips() {
    let Some(path) = std::env::var_os("OVSTORAGE_HTTP_PLUGIN_SO_OVERRIDE") else {
        assert!(std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"));
        eprintln!("skipping: OVSTORAGE_HTTP_PLUGIN_SO_OVERRIDE unset");
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let factories =
        unsafe { ovstorage::load_layer_plugin(path, true) }.expect("load ABI-v2 http cdylib");
    let port = spawn_http_object(b"hello-v2-http");
    let root = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let object = root.join("obj.txt").unwrap();
    let config = StackConfig {
        root: Some("redirect_follower".into()),
        layers: support::linear_stack_config("http", &["redirect_follower"]).layers,
        connections: vec![ConnectionConfig {
            backend_kind: "http".into(),
            target: Some("http".into()),
            display_name: Some("cdn".into()),
            config: HashMap::from([("root_url".into(), toml::Value::String(root.to_string()))]),
            credentials: HashMap::new(),
        }],
    };
    let stack = ovstorage::host::build_stack(&config, factories)
        .await
        .expect("build loaded HTTP Stack");

    let stat = LayerExt::stat(&*stack, object.clone(), StatOptions::default(), None)
        .await
        .expect("stat through loaded HTTP cdylib");
    assert_eq!(stat.etag.as_deref(), Some("v2http"));
    let (bytes, _) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("read through loaded HTTP cdylib");
    assert_eq!(bytes, b"hello-v2-http");
}
