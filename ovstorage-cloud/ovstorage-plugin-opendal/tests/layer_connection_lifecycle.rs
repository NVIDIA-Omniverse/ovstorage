// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Connection-lifecycle coverage for the ABI-v2 `OpenDalLayer` (RFC-0066):
//! the `ConnectionSet<OpenDalDriver>` integration — add/probe/remove,
//! the two-stage admission gate (config-shape errors fail the add outright
//! and deterministically; the verify-time `Operator::check()` PARKS on failure
//! instead of erroring, so an unreachable endpoint remains recoverable),
//! the frozen-credentials update rejection, routing, decoded-key traversal
//! containment, and the `Layer::list` fold contract across the fs (real
//! directories) and s3 (flat, marker-folding) profiles. fs tests run against
//! a `TempDir`; the credentialed s3-profile and webdav tests run against
//! loopback scripted mocks (no real network).

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use futures::StreamExt as _;
use ovstorage_plugin::{
    AttributePatch, AuthenticateRequest, BackendFactory, Body, ConfigValue, ConnectionAuthState,
    ConnectionKey, ConnectionRequest, ErrorCode, InteractiveAuthCapability, LayerConfig,
    LayerConnectionRequest, LayerHandle, ListOptions, ListRequest, ObjectKind, ReadRequest,
    Request, SecretBundle, SecretBytes, SecretValue, StatOptions, StatRequest,
    UpdateConnectionAttributesRequest, UpdateConnectionCredentialsRequest, WriteOptions,
    WriteRequest, address,
};
use ovstorage_plugin_opendal::OpenDalLayerFactory;
use tempfile::TempDir;

// === Scripted loopback mock (for the credentialed s3 profile) ===

fn read_http_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut request = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                request.extend_from_slice(&buf[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!request.is_empty()).then_some(request)
}

const EMPTY_S3_LIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
    <Name>bkt</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
    <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>";

fn spawn_scripted_server(
    status_line: &'static str,
    body: &'static str,
) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_thread = counter.clone();
    // Full request heads, so tests can assert what flowed on the wire (the
    // SigV4 Authorization header, or its absence for anonymous connections)
    // rather than just that an RPC happened.
    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::Builder::new()
        .name("ovs-test-opendal-lifecycle".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(head) = read_http_head(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("requests poisoned")
                    .push(String::from_utf8_lossy(&head).to_string());
                counter_for_thread.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        })
        .expect("spawn scripted server");
    thread::sleep(Duration::from_millis(50));
    (endpoint, counter, requests)
}

/// Every captured request head carries a SigV4 Authorization header signed
/// with the expected access key id — proof the secret-bundle credential was
/// APPLIED, not just that a check() RPC occurred.
fn assert_sigv4_signed(requests: &Mutex<Vec<String>>, access_key_id: &str) {
    let heads = requests.lock().expect("requests poisoned");
    assert!(!heads.is_empty(), "the mock saw at least one request");
    let needle = format!("Credential={access_key_id}/");
    for head in heads.iter() {
        assert!(
            head.contains("AWS4-HMAC-SHA256") && head.contains(&needle),
            "expected a SigV4 Authorization header carrying {access_key_id}: {head}"
        );
    }
}

// === Minimal scripted WebDAV endpoint (for the webdav profile) ===

/// One full HTTP request: the head plus a `Content-Length`-delimited body.
fn read_http_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut raw = read_http_head(stream)?;
    let head_end = raw.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let content_length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);
    let mut body = raw.split_off(head_end);
    let mut buf = [0u8; 8192];
    while body.len() < content_length {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => body.extend_from_slice(&buf[..len]),
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    Some((head, body))
}

fn propfind_multistatus(href: &str, content_length: Option<usize>) -> String {
    let (length_prop, resource_type) = match content_length {
        Some(len) => (
            format!("<D:getcontentlength>{len}</D:getcontentlength>"),
            "<D:resourcetype/>".to_string(),
        ),
        None => (
            String::new(),
            "<D:resourcetype><D:collection/></D:resourcetype>".to_string(),
        ),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>{href}</D:href>\
         <D:propstat><D:prop>\
         <D:getlastmodified>Sun, 01 May 2022 06:39:47 GMT</D:getlastmodified>\
         {length_prop}{resource_type}\
         </D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>\
         </D:response></D:multistatus>"
    )
}

struct WebdavMock {
    endpoint: String,
    /// Request heads observed, in order (method + path + headers).
    requests: Arc<Mutex<Vec<String>>>,
}

/// Serves just enough RFC 4918 for one object round trip: PROPFIND (root
/// collection + stored files), MKCOL (always "already exists"), PUT, GET.
fn spawn_webdav_mock() -> WebdavMock {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let requests_for_thread = requests.clone();
    thread::Builder::new()
        .name("ovs-test-opendal-webdav".into())
        .spawn(move || {
            let files: Mutex<HashMap<String, Vec<u8>>> = Mutex::new(HashMap::new());
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some((head, body)) = read_http_request(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("requests poisoned")
                    .push(head.clone());
                let request_line = head.lines().next().unwrap_or_default();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default().to_string();
                let (status, payload): (&str, Vec<u8>) = match method {
                    "PROPFIND" => {
                        if path == "/" {
                            ("207 Multi-Status", propfind_multistatus("/", None).into_bytes())
                        } else if let Some(content) =
                            files.lock().expect("files poisoned").get(&path)
                        {
                            (
                                "207 Multi-Status",
                                propfind_multistatus(&path, Some(content.len())).into_bytes(),
                            )
                        } else {
                            ("404 Not Found", Vec::new())
                        }
                    }
                    "MKCOL" => ("405 Method Not Allowed", Vec::new()),
                    "PUT" => {
                        files.lock().expect("files poisoned").insert(path, body);
                        ("201 Created", Vec::new())
                    }
                    "GET" => match files.lock().expect("files poisoned").get(&path) {
                        Some(content) => ("200 OK", content.clone()),
                        None => ("404 Not Found", Vec::new()),
                    },
                    "DELETE" => {
                        files.lock().expect("files poisoned").remove(&path);
                        ("204 No Content", Vec::new())
                    }
                    _ => ("405 Method Not Allowed", Vec::new()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n",
                    payload.len(),
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&payload);
                let _ = stream.flush();
            }
        })
        .expect("spawn webdav mock");
    thread::sleep(Duration::from_millis(50));
    WebdavMock { endpoint, requests }
}

// === Helpers ===

fn fs_request(root: &TempDir) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("service".into(), ConfigValue::String("fs".into()));
    config.insert(
        "root".into(),
        ConfigValue::String(root.path().display().to_string()),
    );
    ConnectionRequest {
        backend_kind: "opendal".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    }
}

fn s3_profile_request(endpoint: &str, credentials: SecretBundle) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("service".into(), ConfigValue::String("s3".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert(
        "prefix".into(),
        ConfigValue::String("opendal://s3-bkt/".into()),
    );
    ConnectionRequest {
        backend_kind: "opendal".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

fn webdav_request(endpoint: &str) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("service".into(), ConfigValue::String("webdav".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    config.insert("username".into(), ConfigValue::String("dav-user".into()));
    let mut credentials = SecretBundle::default();
    credentials.fields.insert(
        "password".into(),
        SecretValue::Bytes(SecretBytes(b"hunter2".to_vec())),
    );
    ConnectionRequest {
        backend_kind: "opendal".into(),
        config,
        credentials,
        persist: false,
        display_name: None,
    }
}

fn key_bundle() -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "access_key_id".into(),
        SecretValue::Bytes(SecretBytes(b"AKIATESTFIXTURE".to_vec())),
    );
    bundle.fields.insert(
        "secret_access_key".into(),
        SecretValue::Bytes(SecretBytes(
            b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
        )),
    );
    bundle
}

async fn empty_layer() -> LayerHandle {
    OpenDalLayerFactory::default()
        .create_backend("opendal", &LayerConfig::new(), None)
        .await
        .unwrap()
}

async fn add(layer: &LayerHandle, request: ConnectionRequest) -> ovstorage_plugin::Connection {
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "opendal".into(),
                connection: request,
            }),
            None,
        )
        .await
        .unwrap()
}

/// Drain a layer read, returning the reassembled bytes and the number of
/// stream chunks they arrived in.
async fn read_all(layer: &LayerHandle, address: &str) -> (Vec<u8>, usize) {
    let read = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse(address).unwrap(),
                options: ovstorage_plugin::ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    match read {
        ovstorage_plugin::ReadResult::Stream { mut stream, .. } => {
            let mut bytes = Vec::new();
            let mut chunks = 0usize;
            while let Some(chunk) = stream.next().await {
                bytes.extend_from_slice(&chunk.unwrap());
                chunks += 1;
            }
            (bytes, chunks)
        }
        ovstorage_plugin::ReadResult::Bytes { bytes, .. } => (bytes, 1),
        other => panic!("opendal read never redirects, got {other:?}"),
    }
}

// === add_connection: the two-stage admission gate ===

/// An fs connection adds anonymously (no credentials exist for fs); operator
/// construction against a real directory succeeds and the connection routes.
#[tokio::test]
async fn add_fs_connection_is_anonymous_and_routable() {
    let root = TempDir::new().unwrap();
    let layer = empty_layer().await;
    let connection = add(&layer, fs_request(&root)).await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    assert_eq!(connection.current_addresses[0].as_str(), "opendal://fs/");
    let info = layer
        .root_info_for(
            &address::parse("opendal://fs/x").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(info.capabilities.has_real_directories);
}

/// A credentialed s3-profile connection reports `Authenticated` after the
/// driver's verify-time `Operator::check()` succeeds against the mock — the
/// reachability probe on the parking path.
#[tokio::test]
async fn add_s3_profile_connection_authenticates_via_verify_check() {
    let (endpoint, hits, requests) = spawn_scripted_server("200 OK", EMPTY_S3_LIST);
    let layer = empty_layer().await;
    let connection = add(&layer, s3_profile_request(&endpoint, key_bundle())).await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "the verify-time Operator::check() reached the mock"
    );
    assert_sigv4_signed(&requests, "AKIATESTFIXTURE");
    let root = layer
        .root_info_for(
            &address::parse("opendal://s3-bkt/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(!root.capabilities.has_real_directories);
}

/// The availability contract behind `BRIDGE_REPLAY_SAFE_KINDS`: a failing
/// verify-time `check()` PARKS the connection (`AwaitingAuth`) — the add
/// still succeeds, the connection registers, and its config-derived root
/// still routes while the endpoint is momentarily unreachable or denied.
#[tokio::test]
async fn failed_verify_check_parks_connection_instead_of_failing_add() {
    let (endpoint, hits, _requests) = spawn_scripted_server("403 Forbidden", "denied");
    let layer = empty_layer().await;
    let connection = add(&layer, s3_profile_request(&endpoint, key_bundle())).await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "a failed check parks, got {:?}",
        connection.auth_state
    );
    assert!(hits.load(Ordering::SeqCst) >= 1, "check reached the mock");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(
        snapshot.connections.len(),
        1,
        "the parked connection is registered"
    );
    // Roots derive from config, not auth-gated discovery: they publish even
    // for a parked connection so later recovery can use the same route.
    layer
        .root_info_for(
            &address::parse("opendal://s3-bkt/obj.txt").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .expect("parked connection still publishes its config-derived root");
}

/// A parked connection is what `authenticate_connection` is called on, and
/// OpenDAL has no interactive flow to run: credentials arrive with the
/// connection. The call is refused with `Unsupported`, and the connection is
/// left exactly as parked as it was, still registered.
///
/// The load-bearing line is the `Unsupported` error in
/// `OpenDalDriver::interactive`. Restoring the
/// `AuthEvent::Succeeded { credentials: None }` it used to emit makes this
/// test hand back a stream instead; draining that stream runs the promoting
/// adapter, and the parked-state check then reads `Authenticated` — a
/// connection promoted on no grant and no probe, which is the defect this pins.
#[tokio::test]
async fn authenticate_connection_leaves_a_parked_connection_parked() {
    let (endpoint, hits, _requests) = spawn_scripted_server("403 Forbidden", "denied");
    let layer = empty_layer().await;
    let connection = add(&layer, s3_profile_request(&endpoint, key_bundle())).await;
    // Everything below asserts something about a PARKED connection, so a
    // fixture that quietly authenticated would make the test vacuous.
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ),
        "fixture must park the connection, got {:?}",
        connection.auth_state
    );
    assert!(hits.load(Ordering::SeqCst) >= 1, "check reached the mock");

    let key = ConnectionKey {
        target: "opendal".into(),
        id: connection.id.clone(),
    };
    // Drive the call the way a host does. The promotion the defect produced
    // happens when the returned stream is DRAINED, not when the call returns,
    // so a test that only inspects the call cannot observe it: draining here is
    // what makes the parked-state check below load-bearing.
    let refusal = match layer
        .authenticate_connection(
            Request::new(AuthenticateRequest {
                key,
                capability: InteractiveAuthCapability::Browser,
                auto_open_browser: false,
            }),
            None,
        )
        .await
    {
        // Drain it. The promotion this test exists to catch happens when the
        // adapter consumes a terminal event, not when the call returns, so
        // leaving the stream undrained would make the state check below
        // unfalsifiable. The refusal is asserted after that check, so a
        // regression that promotes is reported as the promotion it is.
        Ok(mut stream) => {
            for event in std::iter::from_fn(|| stream.next()) {
                let _ = event;
            }
            None
        }
        Err(error) => Some(error),
    };

    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    let [still] = snapshot.connections.as_slice() else {
        panic!(
            "the refused call must not unregister the connection, got {} connections",
            snapshot.connections.len()
        );
    };
    // "Untouched" means the whole park, not just the variant: a re-park under a
    // different reason, or one that recorded this call as a failed attempt,
    // would also be a state change this call must not make.
    let (before_reason, before_attempt) = match &connection.auth_state {
        ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt,
        } => (reason.clone(), last_attempt.clone()),
        other => panic!("fixture must park the connection, got {other:?}"),
    };
    match &still.auth_state {
        ConnectionAuthState::AwaitingAuth {
            reason,
            last_attempt,
        } => {
            assert_eq!(*reason, before_reason, "the park reason must not change");
            assert_eq!(
                *last_attempt, before_attempt,
                "a refused authenticate is not a failed attempt"
            );
        }
        // Reached when a stream was offered AND draining it moved the state —
        // the original defect exactly. The call was not refused, so say that
        // rather than describing a refusal that did not happen.
        other => panic!(
            "authenticate must not move a parked connection; draining what it \
             returned left it {other:?}"
        ),
    }
    // Only now the call itself: a driver that returned an empty or
    // progress-only stream would also leave the park untouched, and that is
    // still a contract violation — the answer must be an immediate refusal.
    let refusal = refusal.expect("a backend with no interactive flow must not offer a stream");
    assert_eq!(
        refusal.code(),
        ErrorCode::Unsupported,
        "a backend with no interactive flow answers Unsupported, got {refusal:?}"
    );
}

/// Config-SHAPE errors are the arm that still fails outright: they are
/// deterministic under replay (a request that failed to build never built),
/// so nothing registers and nothing routes.
#[tokio::test]
async fn invalid_config_fails_add_outright_without_registration() {
    let layer = empty_layer().await;
    let mut config = HashMap::new();
    config.insert("service".into(), ConfigValue::String("fs".into()));
    // fs requires `root`.
    let err = layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "opendal".into(),
                connection: ConnectionRequest {
                    backend_kind: "opendal".into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        snapshot.connections.is_empty(),
        "nothing registers on a config-shape failure"
    );
    assert!(
        layer
            .root_info_for(
                &address::parse("opendal://fs/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .is_err(),
        "nothing routes on a config-shape failure"
    );
}

// === probe ===

/// Probe validates the full config shape and drives the same verify-time
/// `check()` an add performs — without registering anything.
#[tokio::test]
async fn probe_checks_reachability_without_registering() {
    let (endpoint, hits, requests) = spawn_scripted_server("200 OK", EMPTY_S3_LIST);
    let layer = empty_layer().await;
    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "opendal".into(),
                connection: s3_profile_request(&endpoint, key_bundle()),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(
        probed.auth_state,
        ConnectionAuthState::Authenticated { .. }
    ));
    assert!(probed.last_probed.is_some());
    assert_eq!(probed.current_addresses[0].as_str(), "opendal://s3-bkt/");
    assert!(hits.load(Ordering::SeqCst) >= 1, "probe hit the mock");
    assert_sigv4_signed(&requests, "AKIATESTFIXTURE");
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert!(
        snapshot.connections.is_empty(),
        "probe must not register a connection"
    );
}

/// A side-effect-free probe of the fs profile: `FsBuilder::build` would
/// `create_dir_all` a missing root, so the probe must validate the config
/// WITHOUT constructing an operator — and a pre-cancelled probe must return
/// `Cancelled` before any validation runs.
#[tokio::test]
async fn fs_probe_does_not_create_missing_root() {
    let parent = TempDir::new().unwrap();
    let missing = parent.path().join("never-created");
    let mut config = HashMap::new();
    config.insert("service".into(), ConfigValue::String("fs".into()));
    config.insert(
        "root".into(),
        ConfigValue::String(missing.display().to_string()),
    );
    let request = ConnectionRequest {
        backend_kind: "opendal".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let layer = empty_layer().await;

    let probed = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "opendal".into(),
                connection: request.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    assert!(matches!(probed.auth_state, ConnectionAuthState::Anonymous));
    assert!(
        !missing.exists(),
        "a probe must not durably create the configured root"
    );

    let cancelled = ovstorage_plugin::CancellationToken::new();
    cancelled.cancel();
    let err = layer
        .probe(
            Request::new(LayerConnectionRequest {
                target: "opendal".into(),
                connection: request,
            }),
            Some(cancelled),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
    assert!(
        !missing.exists(),
        "a cancelled probe must not create it either"
    );
}

/// The documented empty-bundle contract, on the wire: an anonymous
/// s3-profile connection runs UNSIGNED — no Authorization header, no ambient
/// environment/IMDS credential fallback.
#[tokio::test]
async fn anonymous_s3_profile_connection_runs_unsigned() {
    let (endpoint, _hits, requests) = spawn_scripted_server("200 OK", EMPTY_S3_LIST);
    let layer = empty_layer().await;
    let connection = add(
        &layer,
        s3_profile_request(&endpoint, SecretBundle::default()),
    )
    .await;
    assert!(matches!(
        connection.auth_state,
        ConnectionAuthState::Anonymous
    ));
    layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("opendal://s3-bkt/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let heads = requests.lock().unwrap();
    assert!(!heads.is_empty(), "the list reached the mock");
    for head in heads.iter() {
        assert!(
            !head.to_ascii_lowercase().contains("authorization:"),
            "an anonymous connection must not sign or bear ambient credentials: {head}"
        );
    }
}

// === frozen credentials ===

/// OpenDAL credentials are frozen at add time (static strings in an immutable
/// `Operator`): EVERY update
/// is rejected with remove-and-re-add guidance, state untouched.
#[tokio::test]
async fn update_credentials_is_rejected_with_guidance() {
    let root = TempDir::new().unwrap();
    let layer = empty_layer().await;
    let connection = add(&layer, fs_request(&root)).await;

    let err = layer
        .update_connection_credentials(
            Request::new(UpdateConnectionCredentialsRequest {
                key: ConnectionKey {
                    target: "opendal".into(),
                    id: connection.id.clone(),
                },
                credentials: key_bundle(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported);
    assert!(
        err.message().contains("re-add"),
        "rejection must carry guidance: {}",
        err.message()
    );
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 1);
    assert!(matches!(
        snapshot.connections[0].auth_state,
        ConnectionAuthState::Anonymous
    ));
}

/// Attribute patches fail CLOSED on restriction fields the layer cannot
/// store/enforce (`access_mode`, `visible`) — a mixed patch is rejected
/// whole, never half-applied — while a supported display-name patch still
/// lands.
#[tokio::test]
async fn attribute_patch_restriction_fields_fail_closed() {
    let root = TempDir::new().unwrap();
    let layer = empty_layer().await;
    let connection = add(&layer, fs_request(&root)).await;
    let key = || ConnectionKey {
        target: "opendal".into(),
        id: connection.id.clone(),
    };

    for patch in [
        AttributePatch {
            display_name: Some("renamed".into()),
            access_mode: Some("read-only".into()),
            ..AttributePatch::default()
        },
        AttributePatch {
            display_name: Some("renamed".into()),
            visible: Some(false),
            ..AttributePatch::default()
        },
    ] {
        let err = layer
            .update_connection_attributes(
                Request::new(UpdateConnectionAttributesRequest { key: key(), patch }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert_ne!(
            snapshot.connections[0].display_name, "renamed",
            "a rejected mixed patch must not be partially applied"
        );
    }

    let updated = layer
        .update_connection_attributes(
            Request::new(UpdateConnectionAttributesRequest {
                key: key(),
                patch: AttributePatch {
                    display_name: Some("renamed".into()),
                    ..AttributePatch::default()
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.display_name, "renamed");
}

// === data path through the layer (fs round trip) ===

/// Full object round trip through the Layer slots against a real fs root:
/// write → stat → read → list with fold → remove tears routes down.
#[tokio::test]
async fn fs_round_trip_through_layer_slots() {
    let root = TempDir::new().unwrap();
    let layer = empty_layer().await;
    let connection = add(&layer, fs_request(&root)).await;
    let object = address::parse("opendal://fs/team/file.txt").unwrap();

    layer
        .write(
            Request::new(WriteRequest {
                address: object.clone(),
                body: Body::Bytes(b"hello-opendal".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let stat = layer
        .stat(
            Request::new(StatRequest {
                address: object.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(stat.size, Some(b"hello-opendal".len() as u64));

    let (bytes, _) = read_all(&layer, object.as_str()).await;
    assert_eq!(bytes, b"hello-opendal");

    // fs has REAL directories: the fold must pass the concrete Directory
    // through, not downgrade it to DirectoryInferred.
    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse("opendal://fs/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let dir = page
        .items
        .iter()
        .find(|item| item.address.as_str() == "opendal://fs/team/")
        .expect("directory listed");
    assert_eq!(
        dir.kind,
        ObjectKind::Directory,
        "a real fs directory must stay concrete"
    );
    assert_eq!(dir.size, None, "directory sizes are None by contract");

    layer
        .remove_connection(
            Request::new(ConnectionKey {
                target: "opendal".into(),
                id: connection.id.clone(),
            }),
            None,
        )
        .await
        .unwrap();
    let err = layer
        .root_info_for(
            &address::parse("opendal://fs/x").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NoRoute);
}

/// `read` always returns `ReadResult::Stream`; prove a multi-megabyte object
/// arrives as MULTIPLE chunks (streamed, not buffered whole) and survives
/// reassembly byte-for-byte.
#[tokio::test]
async fn fs_large_read_streams_in_multiple_chunks() {
    let root = TempDir::new().unwrap();
    let layer = empty_layer().await;
    add(&layer, fs_request(&root)).await;
    let object = address::parse("opendal://fs/big.bin").unwrap();

    // Non-uniform payload so a reassembly/order bug cannot cancel out.
    let payload: Vec<u8> = (0..9 * 1024 * 1024u32)
        .map(|index| (index % 251) as u8)
        .collect();
    layer
        .write(
            Request::new(WriteRequest {
                address: object.clone(),
                body: Body::Bytes(payload.clone()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let (bytes, chunks) = read_all(&layer, object.as_str()).await;
    assert!(
        chunks > 1,
        "a {}-byte read must stream in multiple chunks, got {chunks}",
        payload.len(),
    );
    assert_eq!(bytes, payload, "reassembled bytes match");
}

// === decoded-key containment (fs profile) ===

/// The route-prefix check runs on the ENCODED URL, so `a%2F..%2F..%2Fx`
/// passes it as one opaque segment and only becomes a real `../..` after
/// decoding. The layer must reject the decoded escape; nothing outside the
/// configured root may be read or written.
/// The encoded traversal cannot reach outside the root. Canonicalization
/// decodes `%2F` to a real separator and then resolves the dot segments it
/// exposes, clamped at the root, so the address arrives naming an ordinary
/// in-root object — the escape is neutralized rather than refused, and the
/// untouched file outside the root is what carries the claim.
#[tokio::test]
async fn fs_percent_encoded_traversal_cannot_reach_outside_the_root() {
    let outside = TempDir::new().unwrap();
    let root = TempDir::new_in(outside.path()).unwrap();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, b"do-not-read").unwrap();

    let layer = empty_layer().await;
    add(&layer, fs_request(&root)).await;
    let escape = address::parse("opendal://fs/a%2F..%2F..%2Fsecret.txt").unwrap();
    assert_eq!(
        escape.as_str(),
        "opendal://fs/secret.txt",
        "the traversal must clamp to an in-root address"
    );

    let err = layer
        .read(
            Request::new(ReadRequest {
                address: escape.clone(),
                options: ovstorage_plugin::ReadOptions::default(),
            }),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::NotFound, "in-root, and absent");

    // The write lands inside the root, under the name the clamped address
    // spells — never on the file outside it.
    layer
        .write(
            Request::new(WriteRequest {
                address: escape,
                body: Body::Bytes(b"clobber".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("an in-root write must succeed");
    assert_eq!(
        std::fs::read(root.path().join("secret.txt")).unwrap(),
        b"clobber",
        "the write landed inside the root"
    );
    assert_eq!(
        std::fs::read(&secret).unwrap(),
        b"do-not-read",
        "nothing outside the root was touched"
    );
}

// === webdav live data path ===

/// Live webdav round trip against a scripted RFC 4918 mock: the basic-auth
/// credential flows on the wire, the verify-time `check()` (PROPFIND)
/// authenticates the add, and write → stat → read drive PUT / PROPFIND / GET
/// through the Layer slots.
#[tokio::test]
async fn webdav_round_trip_through_layer_slots() {
    let mock = spawn_webdav_mock();
    let layer = empty_layer().await;
    let connection = add(&layer, webdav_request(&mock.endpoint)).await;
    assert!(
        matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ),
        "verify-time check() (PROPFIND) authenticates, got {:?}",
        connection.auth_state
    );
    let root = layer
        .root_info_for(
            &address::parse("opendal://webdav/x").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(root.capabilities.has_real_directories);

    let object = address::parse("opendal://webdav/hello.txt").unwrap();
    layer
        .write(
            Request::new(WriteRequest {
                address: object.clone(),
                body: Body::Bytes(b"webdav-round-trip".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    let stat = layer
        .stat(
            Request::new(StatRequest {
                address: object.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(stat.size, Some(b"webdav-round-trip".len() as u64));

    let (bytes, _) = read_all(&layer, object.as_str()).await;
    assert_eq!(bytes, b"webdav-round-trip");

    // Directory stat: webdav's PROPFIND parser marks metadata
    // `Metakey::Complete` with `content_length` at its zero default — the
    // size must still be None for a collection, not Some(0).
    let dir_stat = layer
        .stat(
            Request::new(StatRequest {
                address: address::parse("opendal://webdav/").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(dir_stat.kind, ObjectKind::Directory);
    assert_eq!(dir_stat.size, None, "directory sizes are None by contract");

    let requests = mock.requests.lock().unwrap();
    // base64("dav-user:hunter2") — the configured username + secret-bundle
    // password arrived as HTTP basic auth.
    assert!(
        requests
            .iter()
            .any(|head| head.contains("ZGF2LXVzZXI6aHVudGVyMg==")),
        "basic-auth credential observed on the wire"
    );
    for verb in ["PROPFIND", "PUT /hello.txt", "GET /hello.txt"] {
        assert!(
            requests.iter().any(|head| head.starts_with(verb)),
            "expected a {verb} request, got: {:?}",
            requests
                .iter()
                .map(|head| head.lines().next().unwrap_or_default())
                .collect::<Vec<_>>()
        );
    }
}

// === routing across services ===

/// Two connections with different services and prefixes route independently
/// under one layer (the multi-service kind).
#[tokio::test]
async fn routes_across_two_services() {
    let root = TempDir::new().unwrap();
    let (endpoint, _hits, _requests) = spawn_scripted_server("200 OK", EMPTY_S3_LIST);
    let layer = empty_layer().await;
    add(&layer, fs_request(&root)).await;
    add(&layer, s3_profile_request(&endpoint, key_bundle())).await;

    let fs_root = layer
        .root_info_for(
            &address::parse("opendal://fs/x").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(fs_root.capabilities.has_real_directories);
    let s3_root = layer
        .root_info_for(
            &address::parse("opendal://s3-bkt/x").unwrap(),
            &ovstorage_plugin::Extensions::new(),
            None,
        )
        .await
        .unwrap();
    assert!(!s3_root.capabilities.has_real_directories);
    let (snapshot, _) = layer
        .list_connections(&ovstorage_plugin::Extensions::new(), None)
        .await
        .unwrap();
    assert_eq!(snapshot.connections.len(), 2);
}
