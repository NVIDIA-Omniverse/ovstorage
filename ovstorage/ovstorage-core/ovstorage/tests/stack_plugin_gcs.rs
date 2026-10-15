// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end proof of the ABI-v2 **gcs cdylib** through a native Stack.
//!
//! Loads the staged `libovstorage_plugin_gcs` via `load_layer_plugin`
//! (exercising its `ovstorage_layer_plugin!` manifest, thunks, and loader),
//! opens a `backend_kind = "gcs"` connection with a
//! service-account key through the Stack, and drives the real data
//! path against ONE local mock serving both the token endpoint (the
//! credential JSON's `token_uri` points at it, so only synthetic tokens ever
//! travel) and storage (the public `endpoint` config override): token
//! exchange + bearer verify, stat (objects.get), read (V4-signed redirect
//! followed by the Stack's redirect follower), and teardown. Gated on
//! `OVSTORAGE_GCS_PLUGIN_SO_OVERRIDE` (hard error under
//! `OVSTORAGE_REQUIRE_TEST_PLUGINS`, else skip — matching `mixed_layer_stack.rs`).

use std::collections::HashMap;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use ovstorage::ext::LayerExt as _;
use ovstorage::{
    ConfigValue, ConnectionAuthState, ConnectionKey, ConnectionRequest, ErrorCode,
    LayerConnectionRequest, ReadOptions, Request, SecretBundle, SecretBytes, SecretValue, Stack,
    StatOptions, Url,
};

mod support;

const OBJECT_BODY: &[u8] = b"hello-v2-gcs";
const SYNTHETIC_PEM: &str =
    include_str!("../../../ovstorage-cloud/ovstorage-plugin-gcs/tests/synthetic_rsa_pkcs8.pem");

/// Read one HTTP request (headers + any Content-Length body) off `stream`.
fn read_request(stream: &mut TcpStream) -> Option<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
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

/// One mock serving the token endpoint (POST /token), objects.list (verify),
/// objects.get (stat), and the followed download URL; records request lines.
fn spawn_mock_gcs() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    std::thread::Builder::new()
        .name("ovs-test-mock-gcs".into())
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
                let json =
                    |body: String| -> Vec<u8> {
                        format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .into_bytes()
                    };
                let response: Vec<u8> = if request_line.starts_with("POST /token") {
                    json("{\"access_token\": \"synthetic-token\", \"expires_in\": 3600}".into())
                } else if request_line.contains("/storage/v1/b/bkt/o?")
                    || request_line.contains("maxResults=1")
                {
                    // objects.list — the driver's verify.
                    json("{\"items\": []}".into())
                } else if request_line.contains("/storage/v1/b/bkt/o/") {
                    // objects.get — stat metadata.
                    json(format!(
                        "{{\"bucket\": \"bkt\", \"name\": \"obj.txt\", \"etag\": \"v2gcs\", \
                         \"generation\": \"123\", \"size\": \"{}\"}}",
                        OBJECT_BODY.len()
                    ))
                } else {
                    // The followed download URL (V4-signed or public).
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"v2gcs\"\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
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
        .expect("spawn mock gcs");
    std::thread::sleep(Duration::from_millis(50));
    (endpoint, requests)
}

fn service_account_bundle(endpoint: &str) -> SecretBundle {
    let json = serde_json::json!({
        "type": "service_account",
        "client_email": "tester@example.iam.gserviceaccount.com",
        "private_key": SYNTHETIC_PEM,
        "token_uri": format!("{endpoint}/token"),
        "private_key_id": "kid-1",
    })
    .to_string();
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "service_account_key".into(),
        SecretValue::Bytes(SecretBytes(json.into_bytes())),
    );
    bundle
}

fn gcs_connection_request(endpoint: &str, credentials: SecretBundle) -> ConnectionRequest {
    ConnectionRequest {
        backend_kind: "gcs".into(),
        config: HashMap::from([
            ("bucket".into(), ConfigValue::String("bkt".into())),
            ("endpoint".into(), ConfigValue::String(endpoint.into())),
        ]),
        credentials,
        persist: false,
        display_name: Some("mock-gcs".into()),
    }
}

fn staged_gcs_cdylib() -> Option<std::path::PathBuf> {
    match std::env::var_os("OVSTORAGE_GCS_PLUGIN_SO_OVERRIDE") {
        Some(path) => Some(std::path::PathBuf::from(path)),
        None => {
            assert!(
                std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
                "OVSTORAGE_GCS_PLUGIN_SO_OVERRIDE unset but OVSTORAGE_REQUIRE_TEST_PLUGINS \
                 demands the staged gcs cdylib"
            );
            eprintln!("skipping: OVSTORAGE_GCS_PLUGIN_SO_OVERRIDE unset");
            None
        }
    }
}

async fn gcs_stack(so: &std::path::Path) -> Arc<Stack> {
    let core = support::sibling_plugin(so, "ovstorage_plugin_core");
    let http = support::sibling_plugin(so, "ovstorage_plugin_http");
    let factories = support::load_plugins(&[so, &core, &http]);
    ovstorage::host::build_stack(
        &support::linear_stack_config("gcs", &["redirect_follower", "retry"]),
        factories,
    )
    .await
    .expect("build gcs Stack")
}

/// The full credentialed round trip: load cdylib → bridge add_connection
/// (Authenticated through the plugin-loading policy, with the token exchange and
/// bearer verify observed on the wire) → stat → V4-signed-redirect-followed
/// read → removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_loads_real_gcs_cdylib_and_round_trips() {
    let Some(so) = staged_gcs_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_gcs();
    let object = Url::parse("gs://bkt/obj.txt").unwrap();

    let stack = gcs_stack(&so).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "gcs".into(),
            connection: gcs_connection_request(&endpoint, service_account_bundle(&endpoint)),
        }),
        None,
    )
    .await
    .expect("open a gcs connection to the loaded v2 cdylib through the Stack");
    assert_eq!(connection.backend_kind, "gcs");
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "service-account key verifies against the mock, got {:?}",
        connection.auth_state
    );
    assert!(
        connection
            .current_addresses
            .iter()
            .any(|a| a.as_str() == "gs://bkt/"),
        "connection contributes the config-derived root"
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with("POST /token")),
        "the verify drove a token exchange against the mock IdP"
    );

    // stat = bearer objects.get through the composed Stack.
    let stat = stack
        .stat(object.clone(), StatOptions::default(), None)
        .await
        .expect("stat through the loaded gcs cdylib");
    assert_eq!(stat.size, Some(OBJECT_BODY.len() as u64));

    // read = V4-signed Redirect emitted by the plugin, FOLLOWED by the
    // Stack's redirect follower against the mock endpoint.
    let (bytes, _) = stack
        .read_bytes(object.clone(), ReadOptions::default(), None)
        .await
        .expect("redirect-followed read through the loaded gcs cdylib");
    assert_eq!(bytes, OBJECT_BODY);
    {
        let seen = requests.lock().unwrap();
        assert!(
            seen.iter()
                .any(|line| line.starts_with("GET ") && line.contains("X-Goog-Signature=")),
            "the followed read must be the V4-signed GET: {seen:?}"
        );
    }

    // Teardown: the root stops routing.
    ovstorage::Layer::remove_connection(
        &*stack,
        Request::new(ConnectionKey {
            target: "gcs".into(),
            id: connection.id,
        }),
        None,
    )
    .await
    .expect("remove gcs connection");
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

/// Anonymous gcs connection through the Stack: read follows an unsigned public URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stack_anonymous_gcs_connection_reads_unsigned() {
    let Some(so) = staged_gcs_cdylib() else {
        return;
    };
    ovstorage::init_auth_substrate(None).expect("init auth substrate");
    let (endpoint, requests) = spawn_mock_gcs();
    let object = Url::parse("gs://bkt/obj.txt").unwrap();

    let stack = gcs_stack(&so).await;

    let connection = ovstorage::Layer::add_connection(
        &*stack,
        Request::new(LayerConnectionRequest {
            target: "gcs".into(),
            connection: gcs_connection_request(&endpoint, SecretBundle::default()),
        }),
        None,
    )
    .await
    .expect("anonymous gcs connection through the Stack");
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
        .find(|line| line.starts_with("GET ") && !line.contains("/storage/v1/"))
        .expect("the anonymous read reached the mock");
    assert!(
        !get.contains("X-Goog-Signature="),
        "anonymous read must be unsigned: {get}"
    );
}
