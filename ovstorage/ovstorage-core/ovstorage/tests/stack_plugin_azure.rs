// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the ABI-v2 **azure cdylib** through a native Stack.
//!
//! Loads the staged `libovstorage_plugin_azure` via `load_layer_plugin`
//! (exercising its `ovstorage_layer_plugin!` manifest, thunks, and loader),
//! opens a `backend_kind = "azure"` connection with a
//! Shared Key through the Stack, and drives the real data path
//! against a local mock Azure endpoint (the loopback-only `__test_endpoint`
//! config key; Shared Key signing sends an HMAC signature, never the secret):
//! signed verify, stat (HEAD blob), read (SAS-presigned redirect FOLLOWED by
//! the Stack's redirect follower), small write (Put Blob), and teardown.
//! Gated on `OVSTORAGE_AZURE_PLUGIN_SO_OVERRIDE` (hard error under
//! `OVSTORAGE_REQUIRE_TEST_PLUGINS`, else skip — matching `mixed_layer_stack.rs`).

use std::collections::HashMap;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ovstorage::ext::LayerExt as _;
use ovstorage::{
    Body, ConfigValue, ConnectionAuthState, ConnectionKey, ConnectionRequest, ErrorCode,
    LayerConnectionRequest, ReadOptions, Request, SecretBundle, SecretBytes, SecretValue, Stack,
    StatOptions, Url, WriteOptions,
};

mod support;

const OBJECT_BODY: &[u8] = b"hello-v2-azure";

/// Read one HTTP request (headers + any Content-Length body) off `stream`.
fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let mut header_end = None;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                raw.extend_from_slice(&buf[..len]);
                if header_end.is_none() {
                    header_end = raw
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|pos| pos + 4);
                }
                if let Some(end) = header_end {
                    let headers = String::from_utf8_lossy(&raw[..end]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + content_length {
                        break;
                    }
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!raw.is_empty()).then(|| String::from_utf8_lossy(&raw).to_string())
}

/// Mock Azure Blob endpoint: answers List Blobs (the driver's verify), HEAD
/// blob (stat), GET blob (the followed SAS redirect), and Put Blob; records
/// every request line for wire assertions.
fn spawn_mock_azure() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    std::thread::Builder::new()
        .name("ovs-test-mock-azure".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                let request_line = raw.lines().next().unwrap_or_default().to_string();
                requests_for_thread
                    .lock()
                    .expect("requests poisoned")
                    .push(request_line.clone());
                let response: Vec<u8> = if request_line.contains("comp=list") {
                    let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
                        <EnumerationResults ServiceEndpoint=\"http://127.0.0.1/\" ContainerName=\"assets\">\
                        <Blobs></Blobs><NextMarker /></EnumerationResults>";
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .into_bytes()
                } else if request_line.starts_with("HEAD ") {
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"v2azure\"\r\nLast-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        OBJECT_BODY.len()
                    )
                    .into_bytes()
                } else if request_line.starts_with("PUT ") {
                    "HTTP/1.1 201 Created\r\nConnection: close\r\nETag: \"put-etag\"\r\nLast-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                        .into_bytes()
                } else {
                    // GetObject — the followed SAS (or bare) URL.
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"v2azure\"\r\nLast-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        OBJECT_BODY.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(OBJECT_BODY);
                    response
                };
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        })
        .expect("spawn mock azure");
    std::thread::sleep(Duration::from_millis(50));
    (endpoint, requests)
}

fn shared_key_bundle() -> SecretBundle {
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef0123456789abcdef");
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "account_key".into(),
        SecretValue::Bytes(SecretBytes(key.into_bytes())),
    );
    bundle
}

fn azure_connection_request(endpoint: &str, credentials: SecretBundle) -> ConnectionRequest {
    ConnectionRequest {
        backend_kind: "azure".into(),
        config: HashMap::from([
            ("account".into(), ConfigValue::String("acct123".into())),
            ("container".into(), ConfigValue::String("assets".into())),
            (
                "__test_endpoint".into(),
                ConfigValue::String(endpoint.into()),
            ),
        ]),
        credentials,
        persist: false,
        display_name: Some("mock-azure".into()),
    }
}

fn staged_azure_cdylib() -> Option<std::path::PathBuf> {
    match std::env::var_os("OVSTORAGE_AZURE_PLUGIN_SO_OVERRIDE") {
        Some(path) => Some(std::path::PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
                "OVSTORAGE_AZURE_PLUGIN_SO_OVERRIDE unset but OVSTORAGE_REQUIRE_TEST_PLUGINS \
                 demands the staged azure cdylib"
            );
            eprintln!("skipping: OVSTORAGE_AZURE_PLUGIN_SO_OVERRIDE unset");
            None
        }
    }
}

async fn azure_stack(so: &std::path::Path) -> Arc<Stack> {
    let core = support::sibling_plugin(so, "ovstorage_plugin_core");
    let http = support::sibling_plugin(so, "ovstorage_plugin_http");
    let factories = support::load_plugins(&[so, &core, &http]);
    ovstorage::host::build_stack(
        &support::linear_stack_config("azure", &["redirect_follower", "retry"]),
        factories,
    )
    .await
    .expect("build azure Stack")
}

/// The full credentialed round trip: load cdylib → bridge add_connection
/// (Authenticated through the plugin-loading policy) → stat → SAS-redirect-
/// followed read → small write → removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_loads_real_azure_cdylib_and_round_trips() {
    let Some(so) = staged_azure_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_azure();
    let object = Url::parse("azure://acct123/assets/obj.txt").unwrap();

    let stack = azure_stack(&so).await;

    // The plugin-loading policy admits the credentialed azure kind: this must
    // route through the Layer's own add_connection, verify against the mock,
    // and come back Authenticated.
    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "azure".into(),
            connection: azure_connection_request(&endpoint, shared_key_bundle()),
        }),
        None,
    )
    .await
    .expect("open an azure connection to the loaded v2 cdylib through the Stack");
    assert_eq!(connection.backend_kind, "azure");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "shared key verifies against the mock, got {:?}",
        connection.auth_state
    );
    assert!(
        connection
            .current_addresses
            .iter()
            .any(|a| a.as_str() == "azure://acct123/assets/"),
        "connection contributes the config-derived root"
    );

    // stat = signed HEAD blob through the composed Stack.
    let stat = stack
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat through the loaded azure cdylib");
    assert_eq!(stat.etag.as_deref(), Some("v2azure"));
    assert_eq!(stat.size, Some(OBJECT_BODY.len() as u64));

    // read = SAS-presigned Redirect emitted by the plugin, FOLLOWED by the
    // Stack's redirect follower against the mock endpoint.
    let (bytes, _) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("redirect-followed read through the loaded azure cdylib");
    assert_eq!(bytes, OBJECT_BODY);
    {
        let seen = requests.lock().unwrap();
        assert!(
            seen.iter()
                .any(|line| line.starts_with("GET ") && line.contains("sig=")),
            "the followed read must be the SAS-signed GET: {seen:?}"
        );
    }

    // Small write = direct signed Put Blob from the plugin.
    stack
        .write(
            object.clone(),
            Body::Bytes(b"updated".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("small write through the loaded azure cdylib");
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with("PUT ")),
        "the write must reach the mock as a PUT"
    );

    // Teardown: the root stops routing.
    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "azure".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .expect("remove azure connection");
    let err = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect_err("root not routable after removal");
    assert!(
        matches!(err.code(), ErrorCode::NoRoute | ErrorCode::NotConfigured),
        "expected NoRoute/NotConfigured, got {:?}",
        err.code()
    );
}

/// Anonymous azure connection through the Stack: read follows a bare unsigned URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_anonymous_azure_connection_reads_unsigned() {
    let Some(so) = staged_azure_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_azure();
    let object = Url::parse("azure://acct123/assets/obj.txt").unwrap();

    let stack = azure_stack(&so).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "azure".into(),
            connection: azure_connection_request(&endpoint, SecretBundle::default()),
        }),
        None,
    )
    .await
    .expect("anonymous azure connection through the Stack");
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));

    let (bytes, _) = stack
        .read_bytes(object, ReadOptions::default(), None)
        .await
        .expect("anonymous redirect-followed read");
    assert_eq!(bytes, OBJECT_BODY);
    let seen = requests.lock().unwrap();
    let get = seen
        .iter()
        .find(|line| line.starts_with("GET "))
        .expect("the anonymous read reached the mock");
    assert!(
        !get.contains("sig="),
        "anonymous read must be unsigned: {get}"
    );
}
