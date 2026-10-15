// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the ABI-v2 **opendal cdylib** through
//! a native Stack — the fourth credentialed kind admitted by the host's
//! plugin-loading policy, and the first multi-service kind (fs/s3/webdav
//! behind one `"opendal"` kind).
//!
//! Loads the staged `libovstorage_plugin_opendal` through the ABI-v2 loader
//! (exercising its `ovstorage_layer_plugin!` manifest, thunks, and loader) and
//! drives two shapes: an anonymous **fs** connection
//! with a full real-filesystem round trip (write → stat → read — opendal
//! reads never redirect, so the bytes flow straight through the Stack), and a
//! credentialed **s3-profile** connection against a loopback mock, admitted
//! by the allowlist with the verify-time `Operator::check()` observed on the
//! wire. Gated on `OVSTORAGE_OPENDAL_PLUGIN_SO_OVERRIDE` (hard error
//! under `OVSTORAGE_REQUIRE_TEST_PLUGINS`, else skip — matching
//! `mixed_layer_stack.rs`).

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

/// Read one HTTP request off `stream` (headers only — the mock never needs
/// bodies).
fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                raw.extend_from_slice(&buf[..len]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!raw.is_empty()).then(|| String::from_utf8_lossy(&raw).to_string())
}

/// Mock S3-compatible endpoint answering every request with an empty list
/// (enough for `Operator::check()`); records full request heads so the SigV4
/// Authorization header can be asserted on the wire.
fn spawn_mock_s3() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    std::thread::Builder::new()
        .name("ovs-test-mock-opendal-s3".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("requests poisoned")
                    .push(raw);
                let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                    <Name>bkt</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
                    <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        })
        .expect("spawn mock s3");
    std::thread::sleep(Duration::from_millis(50));
    (endpoint, requests)
}

fn staged_opendal_cdylib() -> Option<std::path::PathBuf> {
    match std::env::var_os("OVSTORAGE_OPENDAL_PLUGIN_SO_OVERRIDE") {
        Some(path) => Some(std::path::PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
                "OVSTORAGE_OPENDAL_PLUGIN_SO_OVERRIDE unset but OVSTORAGE_REQUIRE_TEST_PLUGINS \
                 demands the staged opendal cdylib"
            );
            eprintln!("skipping: OVSTORAGE_OPENDAL_PLUGIN_SO_OVERRIDE unset");
            None
        }
    }
}

async fn opendal_stack(so: &std::path::Path) -> Arc<Stack> {
    let core = support::sibling_plugin(so, "ovstorage_plugin_core");
    let factories = support::load_plugins(&[so, &core]);
    ovstorage::host::build_stack(
        &support::linear_stack_config("opendal", &["retry"]),
        factories,
    )
    .await
    .expect("build opendal Stack")
}

/// Anonymous fs connection: full real-filesystem round trip through the
/// composed Stack (write → stat → read), then teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_loads_real_opendal_cdylib_fs_round_trips() {
    let Some(so) = staged_opendal_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let tmp = tempfile::tempdir().unwrap();
    let object = Url::parse("opendal://fs/team/obj.txt").unwrap();

    let stack = opendal_stack(&so).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "opendal".into(),
            connection: ConnectionRequest {
                backend_kind: "opendal".into(),
                config: HashMap::from([
                    ("service".into(), ConfigValue::String("fs".into())),
                    (
                        "root".into(),
                        ConfigValue::String(tmp.path().display().to_string()),
                    ),
                ]),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("scratch".into()),
            },
        }),
        None,
    )
    .await
    .expect("open an fs opendal connection through the Stack");
    assert_eq!(connection.backend_kind, "opendal");
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));

    stack
        .write(
            object.clone(),
            Body::Bytes(b"hello-v2-opendal".to_vec()),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("write through the loaded opendal cdylib");
    let stat = stack
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat through the loaded opendal cdylib");
    assert_eq!(stat.size, Some(b"hello-v2-opendal".len() as u64));
    let (bytes, _) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("streamed (non-redirect) read through the loaded opendal cdylib");
    assert_eq!(bytes, b"hello-v2-opendal");

    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "opendal".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .unwrap();
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

/// Credentialed s3-profile connection: admitted by the plugin-loading policy,
/// with the verify-time `Operator::check()` observed against the mock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_credentialed_s3_profile_connection_is_bridged() {
    let Some(so) = staged_opendal_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_s3();

    let stack = opendal_stack(&so).await;

    let mut credentials = SecretBundle::default();
    credentials.fields.insert(
        "access_key_id".into(),
        SecretValue::Bytes(SecretBytes(b"AKIATESTFIXTURE".to_vec())),
    );
    credentials.fields.insert(
        "secret_access_key".into(),
        SecretValue::Bytes(SecretBytes(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
        )),
    );
    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "opendal".into(),
            connection: ConnectionRequest {
                backend_kind: "opendal".into(),
                config: HashMap::from([
                    ("service".into(), ConfigValue::String("s3".into())),
                    ("endpoint".into(), ConfigValue::String(endpoint.clone())),
                    ("bucket".into(), ConfigValue::String("bkt".into())),
                    ("region".into(), ConfigValue::String("us-east-1".into())),
                    (
                        "prefix".into(),
                        ConfigValue::String("opendal://s3-bkt/".into()),
                    ),
                ]),
                credentials,
                persist: false,
                display_name: Some("mock-s3-via-opendal".into()),
            },
        }),
        None,
    )
    .await
    .expect("open a credentialed opendal connection through the Stack");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "verify-time check() against the mock authenticates, got {:?}",
        connection.auth_state
    );
    assert!(
        connection
            .current_addresses
            .iter()
            .any(|a| a.as_str() == "opendal://s3-bkt/"),
        "connection contributes the caller-chosen prefix root"
    );
    {
        let heads = requests.lock().unwrap();
        assert!(
            !heads.is_empty(),
            "the verify-time Operator::check() reached the mock"
        );
        // The secret-bundle credential was APPLIED, not just carried: the
        // check() is SigV4-signed with the supplied access key id.
        assert!(
            heads.iter().all(|head| head.contains("AWS4-HMAC-SHA256")
                && head.contains("Credential=AKIATESTFIXTURE/")),
            "every request must carry a SigV4 Authorization header signed with \
             AKIATESTFIXTURE: {heads:?}"
        );
    }

    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "opendal".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .unwrap();
    assert!(stack.list_connections(None).await.unwrap().is_empty());
}
