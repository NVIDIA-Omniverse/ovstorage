// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ovstorage_plugin::shim::{Backend, Factory};
use ovstorage_plugin::{
    BackendChangeEvent, BackendId, ChangeKind, ConfigValue, ConnectionRequest, ErrorCode,
    ResolvedTarget, SecretBundle, WatchDirectoryCursor, WatchDirectoryOptions, address,
};
use ovstorage_plugin_gcs::GcsBackendFactory;

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: String,
}

struct FixtureState {
    responses: Mutex<VecDeque<HttpResponse>>,
    requests: Mutex<Vec<HttpRequest>>,
}

enum HttpResponse {
    Json {
        status: u16,
        body: String,
    },
    ForPath {
        suffix: &'static str,
        response: Box<HttpResponse>,
    },
    Hold {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        client_closed: mpsc::Sender<bool>,
    },
}

struct PubsubFixture {
    endpoint: String,
    state: Arc<FixtureState>,
}

impl PubsubFixture {
    fn new(responses: Vec<HttpResponse>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(FixtureState {
            responses: Mutex::new(VecDeque::from(responses)),
            requests: Mutex::new(Vec::new()),
        });
        let state_for_thread = state.clone();
        thread::Builder::new()
            .name("ovs-gcs-test".into())
            .spawn(move || serve(listener, state_for_thread))
            .expect("failed to spawn thread");
        Self { endpoint, state }
    }

    fn requests(&self) -> Vec<(String, String, String)> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                (
                    request.method.clone(),
                    request.path.clone(),
                    request.body.clone(),
                )
            })
            .collect()
    }

    fn append_responses(&self, responses: Vec<HttpResponse>) {
        self.state.responses.lock().unwrap().extend(responses);
    }
}

fn serve(listener: TcpListener, state: Arc<FixtureState>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let state = state.clone();
        let _ = thread::Builder::new()
            .name("ovs-gcs-http".into())
            .spawn(move || handle_connection(stream, state));
    }
}

fn handle_connection(mut stream: TcpStream, state: Arc<FixtureState>) {
    let Ok(request) = read_request(&mut stream) else {
        return;
    };
    let path = request.path.clone();
    state.requests.lock().unwrap().push(request);
    let response = next_response(&state, &path);
    match response {
        Some(HttpResponse::Json { status, body }) => write_json(&mut stream, status, &body),
        Some(HttpResponse::ForPath { .. }) => write_json(
            &mut stream,
            500,
            r#"{"error":{"status":"UNMATCHED_ROUTE"}}"#,
        ),
        Some(HttpResponse::Hold {
            started,
            release,
            client_closed,
        }) => {
            let _ = started.send(());
            let _ = release.recv_timeout(Duration::from_secs(2));
            let closed = peer_closed(&mut stream);
            let _ = client_closed.send(closed);
            write_json(&mut stream, 200, "{}");
        }
        None => write_json(&mut stream, 500, r#"{"error":{"status":"UNEXPECTED"}}"#),
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn next_response(state: &FixtureState, path: &str) -> Option<HttpResponse> {
    let mut responses = state.responses.lock().unwrap();
    if !matches!(responses.front(), Some(HttpResponse::ForPath { .. })) {
        return responses.pop_front();
    }
    if let Some(index) = responses.iter().position(|response| {
        matches!(response, HttpResponse::ForPath { suffix, .. } if path.ends_with(suffix))
    }) {
        let Some(HttpResponse::ForPath { response, .. }) = responses.remove(index) else {
            unreachable!();
        };
        return Some(*response);
    }
    responses.pop_front()
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        bytes.extend_from_slice(&buf[..read]);
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let content_len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < header_end + 4 + content_len {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..read]);
    }
    let mut request_line = headers
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    let body_start = header_end + 4;
    let body_end = (body_start + content_len).min(bytes.len());
    let body = String::from_utf8_lossy(&bytes[body_start..body_end]).to_string();
    Ok(HttpRequest { method, path, body })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn peer_closed(stream: &mut TcpStream) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte), Ok(0))
}

fn subscription_get(ack_deadline_seconds: u32) -> HttpResponse {
    subscription_get_with_exactly_once(ack_deadline_seconds, false)
}

fn subscription_get_with_exactly_once(
    ack_deadline_seconds: u32,
    exactly_once_delivery: bool,
) -> HttpResponse {
    HttpResponse::Json {
        status: 200,
        body: serde_json::json!({
            "ackDeadlineSeconds": ack_deadline_seconds,
            "enableExactlyOnceDelivery": exactly_once_delivery
        })
        .to_string(),
    }
}

fn pull_response(messages: &[(&str, &str)]) -> HttpResponse {
    let received = messages
        .iter()
        .map(|(ack_id, object_id)| {
            serde_json::json!({
                "ackId": ack_id,
                "message": {
                    "messageId": ack_id,
                    "attributes": {
                        "bucketId": "assets",
                        "objectId": object_id,
                        "objectGeneration": "42",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    HttpResponse::Json {
        status: 200,
        body: serde_json::json!({ "receivedMessages": received }).to_string(),
    }
}

fn pull_response_with_payload(
    ack_id: &str,
    object_id: &str,
    size: u64,
    updated: &str,
) -> HttpResponse {
    use base64::Engine as _;
    let payload = serde_json::json!({
        "size": size.to_string(),
        "updated": updated,
    });
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload.to_string().as_bytes());
    HttpResponse::Json {
        status: 200,
        body: serde_json::json!({
            "receivedMessages": [{
                "ackId": ack_id,
                "message": {
                    "messageId": ack_id,
                    "attributes": {
                        "bucketId": "assets",
                        "objectId": object_id,
                        "objectGeneration": "42",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    },
                    "data": encoded,
                }
            }]
        })
        .to_string(),
    }
}

fn malformed_pull_response() -> HttpResponse {
    HttpResponse::Json {
        status: 200,
        body: serde_json::json!({
            "receivedMessages": [{
                "ackId": "ack-malformed",
                "message": {
                    "messageId": "malformed",
                    "attributes": {
                        "objectId": "dir/bad.txt"
                    }
                }
            }]
        })
        .to_string(),
    }
}

fn empty_pull_response() -> HttpResponse {
    HttpResponse::Json {
        status: 200,
        body: "{}".into(),
    }
}

fn ack_response() -> HttpResponse {
    HttpResponse::Json {
        status: 200,
        body: "{}".into(),
    }
}

fn ack_invalid_argument_response() -> HttpResponse {
    HttpResponse::Json {
        status: 400,
        body: serde_json::json!({
            "error": {
                "code": 400,
                "status": "INVALID_ARGUMENT",
                "message": "bad ack id"
            }
        })
        .to_string(),
    }
}

fn scope_403_response() -> HttpResponse {
    HttpResponse::Json {
        status: 403,
        body: serde_json::json!({
            "error": {
                "code": 403,
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT"
                }]
            }
        })
        .to_string(),
    }
}

fn permission_403_response() -> HttpResponse {
    HttpResponse::Json {
        status: 403,
        body: serde_json::json!({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "caller lacks pubsub.subscriptions.consume"
            }
        })
        .to_string(),
    }
}

async fn backend(endpoint: &str) -> Arc<dyn Backend> {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("assets".into()));
    config.insert(
        "pubsub_subscription".into(),
        ConfigValue::String("projects/p/subscriptions/s".into()),
    );
    config.insert(
        "pubsub_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    config.insert("pubsub_pull_max".into(), ConfigValue::Int(2));
    let request = ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    GcsBackendFactory::new()
        .instantiate(&request, None)
        .await
        .unwrap()
        .backend
}

fn target(prefix: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("gcs:test".into()),
        resolved_address: address::parse(&format!("gs://assets/{prefix}")).unwrap(),
    }
}

fn next_event(
    stream: &mut ovstorage_plugin::BackendChangeStream,
) -> Option<ovstorage_plugin::Result<BackendChangeEvent>> {
    stream.next()
}

async fn next_item(
    mut stream: ovstorage_plugin::BackendChangeStream,
) -> (
    ovstorage_plugin::BackendChangeStream,
    Option<ovstorage_plugin::Result<BackendChangeEvent>>,
) {
    tokio::task::spawn_blocking(move || {
        let item = stream.next();
        (stream, item)
    })
    .await
    .expect("stream iterator task should not panic")
}

#[tokio::test(flavor = "multi_thread")]
async fn subscription_get_ack_deadline_zero_normalizes_and_since_yields_lapsed() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(0),
        pull_response(&[("ack-1", "dir/a.txt")]),
    ]);
    let backend = backend(&fixture.endpoint).await;
    let mut stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                since: Some(WatchDirectoryCursor(b"resume".to_vec())),
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    match next_event(&mut stream).unwrap().unwrap() {
        BackendChangeEvent::Lapsed { .. } => {}
        other => panic!("expected initial Lapsed, got {other:?}"),
    }
    match next_event(&mut stream).unwrap().unwrap() {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected object event, got {other:?}"),
    }
    drop(stream);

    let requests = fixture.requests();
    assert_eq!(requests[0].0, "GET");
    assert_eq!(requests[0].1, "/v1/projects/p/subscriptions/s");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_trailing_slash_watch_matches_children_and_drops_siblings() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[
            ("ack-child", "dir/a.txt"),
            ("ack-sibling", "directory/a.txt"),
        ]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let mut stream = backend
        .watch_directory(
            target("dir"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    match next_event(&mut stream).unwrap().unwrap() {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected child object event, got {other:?}"),
    }
    wait_for_acks(&fixture, 1);
    let bodies = ack_bodies(&fixture);
    assert!(bodies[0].contains(r#""ack-sibling""#));
    assert!(!bodies[0].contains(r#""ack-child""#));
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_messages_ack_one_event_delayed() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-1", "dir/a.txt"), ("ack-2", "dir/b.txt")]),
        ack_response(),
        ack_response(),
    ]);
    let backend = backend(&fixture.endpoint).await;
    let mut stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    let first = next_event(&mut stream).unwrap().unwrap();
    match first {
        BackendChangeEvent::Object { address, kind, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42");
            assert_eq!(kind, ChangeKind::Created);
        }
        other => panic!("expected first object, got {other:?}"),
    }
    thread::sleep(Duration::from_millis(50));
    assert_eq!(ack_paths(&fixture).len(), 0);

    let second = next_event(&mut stream).unwrap().unwrap();
    match second {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/b.txt?generation=42")
        }
        other => panic!("expected second object, got {other:?}"),
    }
    wait_for_acks(&fixture, 1);
    assert_eq!(ack_paths(&fixture).len(), 1);
    let bodies = ack_bodies(&fixture);
    assert!(
        bodies[0].contains(r#""ack-1""#),
        "the first ack should be sent only after the second event is yielded: {bodies:?}"
    );
    assert!(!bodies[0].contains(r#""ack-2""#));

    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn filtered_message_is_acked_without_iterator_progress() {
    let (started_tx, _started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closed_tx, _closed_rx) = mpsc::channel();
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-filtered", "other/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(HttpResponse::Hold {
                started: started_tx,
                release: release_rx,
                client_closed: closed_tx,
            }),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let cancel = ovstorage_plugin::CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_secs(5),
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .unwrap();

    wait_for_acks(&fixture, 1);
    let bodies = ack_bodies(&fixture);
    assert!(
        bodies[0].contains(r#""ack-filtered""#),
        "filtered message should be acknowledged without yielding an event: {bodies:?}"
    );

    cancel.cancel();
    let _ = release_tx.send(());
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn filtered_message_ack_permission_denied_surfaces_fatal() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-denied", "other/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(permission_403_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    let (_stream, fatal) = next_item(stream).await;
    let err = fatal
        .expect("fatal stream item")
        .expect_err("filtered ack PermissionDenied should stop the stream");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    let bodies = ack_bodies(&fixture);
    assert!(bodies[0].contains(r#""ack-denied""#));
}

#[tokio::test(flavor = "multi_thread")]
async fn ack_runs_while_next_pull_is_held_open() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closed_tx, _closed_rx) = mpsc::channel();
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-split", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(HttpResponse::Hold {
                started: started_tx,
                release: release_rx,
                client_closed: closed_tx,
            }),
        },
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let cancel = ovstorage_plugin::CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_secs(5),
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .unwrap();

    let (stream, first) = next_item(stream).await;
    match first.expect("stream item").expect("object event") {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected object event, got {other:?}"),
    }
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("producer should enter held pull before iterator advances");

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    wait_for_acks(&fixture, 1);
    let bodies = ack_bodies(&fixture);
    assert!(
        bodies[0].contains(r#""ack-split""#),
        "ack pump should acknowledge while the producer pull is still held: {bodies:?}"
    );

    cancel.cancel();
    let _ = release_tx.send(());
    assert!(
        next.await
            .expect("iterator task should not panic")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_message_yields_lapsed_then_is_acked() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        malformed_pull_response(),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(empty_pull_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let cancel = ovstorage_plugin::CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_secs(5),
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .unwrap();

    let (stream, item) = next_item(stream).await;
    assert!(matches!(
        item.expect("stream item").expect("lapsed event"),
        BackendChangeEvent::Lapsed { .. }
    ));

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    wait_for_acks(&fixture, 1);
    let bodies = ack_bodies(&fixture);
    assert!(bodies[0].contains(r#""ack-malformed""#));
    cancel.cancel();
    assert!(
        next.await
            .expect("iterator task should not panic")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ack_invalid_argument_surfaces_as_fatal_error() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-bad", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_invalid_argument_response()),
        },
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(empty_pull_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_secs(5),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    let (stream, first) = next_item(stream).await;
    match first.expect("stream item").expect("object event") {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected object event, got {other:?}"),
    }
    let (_stream, fatal) = next_item(stream).await;
    let err = fatal
        .expect("fatal stream item")
        .expect_err("ack INVALID_ARGUMENT should be fatal before the deadline");
    assert_eq!(err.code(), ErrorCode::Internal);
}

#[tokio::test(flavor = "multi_thread")]
async fn exactly_once_stale_ack_invalid_argument_is_nonfatal_at_iterator_level() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closed_tx, _closed_rx) = mpsc::channel();
    let fixture = PubsubFixture::new(vec![
        subscription_get_with_exactly_once(1, true),
        pull_response(&[("ack-stale", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(HttpResponse::Hold {
                started: started_tx,
                release: release_rx,
                client_closed: closed_tx,
            }),
        },
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_invalid_argument_response()),
        },
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(pull_response(&[("ack-next", "dir/b.txt")])),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    let (stream, first) = next_item(stream).await;
    match first.expect("stream item").expect("object event") {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected object event, got {other:?}"),
    }
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("producer should hold the next pull while the ack deadline expires");
    tokio::time::sleep(Duration::from_millis(6500)).await;

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        let item = stream.next();
        (stream, item)
    });
    wait_for_acks(&fixture, 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = release_tx.send(());
    let (stream, second) = next.await.expect("iterator task should not panic");
    match second
        .expect("stream item")
        .expect("stale ack should not be fatal")
    {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/b.txt?generation=42")
        }
        other => panic!("expected object event after stale ack, got {other:?}"),
    }
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn last_delivered_event_is_not_acked_on_drop_and_can_redeliver() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-first", "dir/redeliver.txt")]),
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(HttpResponse::Hold {
                started: started_tx,
                release: release_rx,
                client_closed: closed_tx,
            }),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    let (stream, first) = next_item(stream).await;
    match first.expect("stream item").expect("object event") {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(
                address.as_str(),
                "gs://assets/dir/redeliver.txt?generation=42"
            )
        }
        other => panic!("expected object event, got {other:?}"),
    }
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("producer should enter held pull");
    drop(stream);
    let _ = release_tx.send(());
    let _ = closed_rx.recv_timeout(Duration::from_secs(2));
    thread::sleep(Duration::from_millis(100));
    assert!(ack_paths(&fixture).is_empty());

    fixture.append_responses(vec![
        subscription_get(10),
        pull_response(&[("ack-second", "dir/redeliver.txt")]),
    ]);
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();
    let (stream, second) = next_item(stream).await;
    match second.expect("stream item").expect("redelivery") {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(
                address.as_str(),
                "gs://assets/dir/redeliver.txt?generation=42"
            )
        }
        other => panic!("expected object event, got {other:?}"),
    }
    drop(stream);
    thread::sleep(Duration::from_millis(100));
    assert!(ack_paths(&fixture).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_pull_does_not_terminate_and_is_paced() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        empty_pull_response(),
        pull_response(&[("ack-1", "dir/a.txt")]),
    ]);
    let backend = backend(&fixture.endpoint).await;
    let started = std::time::Instant::now();
    let mut stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(150),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    match next_event(&mut stream).unwrap().unwrap() {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected object after empty pull, got {other:?}"),
    }
    assert!(started.elapsed() >= Duration::from_millis(100));
    let pull_count = fixture
        .requests()
        .iter()
        .filter(|(_, path, _)| path.ends_with(":pull"))
        .count();
    assert_eq!(pull_count, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_insufficient_403_maps_auth_required() {
    let fixture = PubsubFixture::new(vec![scope_403_response()]);
    let backend = backend(&fixture.endpoint).await;

    let result = backend
        .watch_directory(target("dir/"), WatchDirectoryOptions::default(), None)
        .await;
    let err = match result {
        Ok(_) => panic!("watch_directory should fail on Pub/Sub 403"),
        Err(err) => err,
    };

    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

#[tokio::test(flavor = "multi_thread")]
async fn generic_403_maps_permission_denied() {
    let fixture = PubsubFixture::new(vec![permission_403_response()]);
    let backend = backend(&fixture.endpoint).await;

    let result = backend
        .watch_directory(target("dir/"), WatchDirectoryOptions::default(), None)
        .await;
    let err = match result {
        Ok(_) => panic!("watch_directory should fail on generic Pub/Sub 403"),
        Err(err) => err,
    };

    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread")]
async fn json_api_v1_payload_propagates_size_and_mtime() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response_with_payload("ack-payload", "dir/a.txt", 5_678, "2026-05-12T13:45:01Z"),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let mut stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();

    match next_event(&mut stream).unwrap().unwrap() {
        BackendChangeEvent::Object {
            address,
            etag,
            version,
            size,
            mtime,
            ..
        } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42");
            assert_eq!(etag.as_deref(), Some("42"));
            assert_eq!(version.as_deref(), Some("42"));
            assert_eq!(size, Some(5_678));
            assert!(mtime.is_some());
        }
        other => panic!("expected object event, got {other:?}"),
    }
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_stream_closes_held_pull() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        HttpResponse::Hold {
            started: started_tx,
            release: release_rx,
            client_closed: closed_tx,
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let stream = backend
        .watch_directory(
            target("dir/"),
            WatchDirectoryOptions {
                recursive: true,
                poll_interval: Duration::from_millis(20),
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .unwrap();
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("pull should reach fixture");

    drop(stream);
    release_tx.send(()).unwrap();

    assert!(
        closed_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        "dropping the stream should cancel the held pull connection"
    );
}

fn ack_paths(fixture: &PubsubFixture) -> Vec<String> {
    fixture
        .requests()
        .into_iter()
        .filter(|(_, path, _)| path.ends_with(":acknowledge"))
        .map(|(_, path, _)| path)
        .collect()
}

fn ack_bodies(fixture: &PubsubFixture) -> Vec<String> {
    fixture
        .requests()
        .into_iter()
        .filter(|(_, path, _)| path.ends_with(":acknowledge"))
        .map(|(_, _, body)| body)
        .collect()
}

fn wait_for_acks(fixture: &PubsubFixture, expected: usize) {
    for _ in 0..20 {
        if ack_paths(fixture).len() >= expected {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("expected at least {expected} ack requests");
}
