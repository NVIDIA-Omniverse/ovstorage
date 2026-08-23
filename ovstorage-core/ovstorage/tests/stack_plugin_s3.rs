// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the ABI-v2 **s3 cdylib** through a native Stack.
//!
//! Loads the staged `libovstorage_plugin_s3` via `load_layer_plugin`, composes
//! its factory with the standard redirect/retry wrappers, opens a
//! `backend_kind = "s3"` connection with static keys, and drives the real data path against a
//! local mock S3 endpoint: signed verify, stat (HeadObject), read (presigned
//! redirect followed by the Stack's redirect follower), small write (PUT),
//! credential rotation observed on the wire, and teardown. Gated on
//! `OVSTORAGE_S3_PLUGIN_SO_OVERRIDE` (hard error under
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
    StatOptions, UpdateConnectionCredentialsRequest, Url, WriteOptions,
};

mod support;

const OBJECT_BODY: &[u8] = b"hello-v2-s3";

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

/// Mock S3 endpoint: answers ListObjectsV2 (the driver's verify), HeadObject,
/// GetObject (the followed presigned redirect), and PutObject; records every
/// request line + query for wire assertions.
fn spawn_mock_s3() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    std::thread::Builder::new()
        .name("ovs-test-mock-s3".into())
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
                let response = if request_line.contains("list-type=2") {
                    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                        <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                        <Name>bkt</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
                        <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>";
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                } else if request_line.starts_with("HEAD ") {
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"v2s3\"\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        OBJECT_BODY.len()
                    )
                } else if request_line.starts_with("PUT ") {
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"put-etag\"\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                } else {
                    // GetObject — the followed presigned (or unsigned) URL.
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"v2s3\"\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        OBJECT_BODY.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(OBJECT_BODY);
                    let _ = stream.write_all(&response);
                    let _ = stream.flush();
                    continue;
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        })
        .expect("spawn mock s3");
    std::thread::sleep(Duration::from_millis(50));
    (endpoint, requests)
}

fn credentials_bundle(access: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "aws_access_key_id".into(),
        SecretValue::Bytes(SecretBytes(access.as_bytes().to_vec())),
    );
    bundle.fields.insert(
        "aws_secret_access_key".into(),
        SecretValue::Bytes(SecretBytes(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
        )),
    );
    bundle
}

fn s3_connection_request(endpoint: &str, credentials: SecretBundle) -> ConnectionRequest {
    ConnectionRequest {
        backend_kind: "s3".into(),
        config: HashMap::from([
            ("bucket".into(), ConfigValue::String("bkt".into())),
            ("region".into(), ConfigValue::String("us-east-1".into())),
            ("endpoint".into(), ConfigValue::String(endpoint.into())),
            (
                "compatibility_profile".into(),
                ConfigValue::String("custom".into()),
            ),
            ("force_path_style".into(), ConfigValue::Bool(true)),
        ]),
        credentials,
        persist: false,
        display_name: Some("mock-s3".into()),
    }
}

fn staged_s3_cdylib() -> Option<std::path::PathBuf> {
    match std::env::var_os("OVSTORAGE_S3_PLUGIN_SO_OVERRIDE") {
        Some(path) => Some(std::path::PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
                "OVSTORAGE_S3_PLUGIN_SO_OVERRIDE unset but OVSTORAGE_REQUIRE_TEST_PLUGINS \
                 demands the staged s3 cdylib"
            );
            eprintln!("skipping: OVSTORAGE_S3_PLUGIN_SO_OVERRIDE unset");
            None
        }
    }
}

async fn s3_stack(so: &std::path::Path) -> Arc<Stack> {
    let core = support::sibling_plugin(so, "ovstorage_plugin_core");
    let http = support::sibling_plugin(so, "ovstorage_plugin_http");
    let factories = support::load_plugins(&[so, &core, &http]);
    ovstorage::host::build_stack(
        &support::linear_stack_config("s3", &["redirect_follower", "retry"]),
        factories,
    )
    .await
    .expect("build s3 Stack")
}

/// The full credentialed round trip: load cdylib → bridge add_connection
/// (Authenticated) → stat → redirect-followed read → small write → credential
/// rotation observed on the presigned wire → removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_loads_real_s3_cdylib_and_round_trips() {
    let Some(so) = staged_s3_cdylib() else { return };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_s3();
    let object = Url::parse("s3://bkt/obj.txt").unwrap();

    let stack = s3_stack(&so).await;

    // The plugin-loading policy admits the credentialed s3 kind: this must
    // route through the Layer's own add_connection, verify against the mock,
    // and come back Authenticated.
    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "s3".into(),
            connection: s3_connection_request(&endpoint, credentials_bundle("AKIAORIGINAL")),
        }),
        None,
    )
    .await
    .expect("open an s3 connection to the loaded v2 cdylib through the Stack");
    assert_eq!(connection.backend_kind, "s3");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "static keys verify against the mock, got {:?}",
        connection.auth_state
    );
    assert!(
        connection
            .current_addresses
            .iter()
            .any(|a| a.as_str() == "s3://bkt/"),
        "connection contributes the config-derived root"
    );

    // stat = signed HeadObject through the composed Stack.
    let stat = stack
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat through the loaded s3 cdylib");
    assert_eq!(stat.etag.as_deref(), Some("v2s3"));
    assert_eq!(stat.size, Some(OBJECT_BODY.len() as u64));

    // read = presigned Redirect emitted by the plugin, FOLLOWED by the
    // Stack's redirect follower against the mock endpoint.
    let (bytes, _) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("redirect-followed read through the loaded s3 cdylib");
    assert_eq!(bytes, OBJECT_BODY);
    {
        let seen = requests.lock().unwrap();
        assert!(
            seen.iter()
                .any(|line| line.starts_with("GET ") && line.contains("X-Amz-Credential=")),
            "the followed read must be the presigned GET: {seen:?}"
        );
    }

    // Small write = direct signed PutObject from the plugin.
    stack
        .write(
            object.clone(),
            Body::Bytes(b"updated".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("small write through the loaded s3 cdylib");
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with("PUT ")),
        "the write must reach the mock as a PUT"
    );

    // Credential rotation crosses the loaded ABI-v2 lifecycle slot; the next
    // presigned read must be signed with the new key.
    ovstorage::Layer::update_connection_credentials(
        &*stack,
        Request::new(UpdateConnectionCredentialsRequest {
            key: ConnectionKey {
                target: "s3".into(),
                id: connection.id.clone(),
            },
            credentials: credentials_bundle("AKIAROTATED"),
        }),
        None,
    )
    .await
    .expect("update credentials on the s3 connection");
    let (bytes, _) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("read after rotation");
    assert_eq!(bytes, OBJECT_BODY);
    {
        let seen = requests.lock().unwrap();
        let last_get = seen
            .iter()
            .rev()
            .find(|line| line.starts_with("GET ") && line.contains("X-Amz-Credential="))
            .expect("a presigned GET after rotation");
        assert!(
            last_get.contains("AKIAROTATED"),
            "post-rotation presign must carry the new key id: {last_get}"
        );
    }

    // Teardown: the root stops routing.
    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "s3".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .expect("remove s3 connection");
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

/// Anonymous (no-credentials) s3 connection through the Stack: read-only,
/// the read follows a plain UNSIGNED object URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_anonymous_s3_connection_reads_unsigned() {
    let Some(so) = staged_s3_cdylib() else { return };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_s3();
    let object = Url::parse("s3://bkt/obj.txt").unwrap();

    let stack = s3_stack(&so).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "s3".into(),
            connection: s3_connection_request(&endpoint, SecretBundle::default()),
        }),
        None,
    )
    .await
    .expect("anonymous s3 connection through the Stack");
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
        !get.contains("X-Amz-Credential="),
        "anonymous read must be unsigned: {get}"
    );
}
