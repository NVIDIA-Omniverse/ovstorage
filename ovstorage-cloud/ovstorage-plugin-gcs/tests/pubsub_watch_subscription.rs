// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pub/Sub watch adopter tests under the `WatchCoalescer` model: one Pub/Sub
//! pull consumer per connection, ack-after-fan-out (each message acked once
//! after every one of its events' ack handles fire), `Full`/`Closed` dispatch →
//! typed terminal `Err`, and an async provider ack failure surfaced as a
//! terminal `Err` on the stream (drained after any queued events). The
//! pre-coalescing one-event-delayed iterator semantics INTENTIONALLY no longer
//! hold; GCS-only exactly-once + stale-ack nuances are preserved.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendId, CancellationToken, ConfigValue, ErrorCode,
    ResolvedTarget, SecretBundle, WatchDirectoryCursor, WatchDirectoryOptions, address,
};
use ovstorage_plugin_gcs::GcsBackend;

mod support;
use support::{GatedPubsubFixture, PubsubMessageSpec};

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: String,
    received_at: Instant,
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
    /// Sleep `delay` before answering, so the caller's post-response
    /// `clock.now()` lands beyond a deadline (models a slow ack whose id has
    /// since expired under exactly-once delivery).
    Delayed {
        delay: Duration,
        status: u16,
        body: String,
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

    fn pull_times(&self) -> Vec<Instant> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.path.ends_with(":pull"))
            .map(|request| request.received_at)
            .collect()
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
        Some(HttpResponse::Delayed {
            delay,
            status,
            body,
        }) => {
            thread::sleep(delay);
            write_json(&mut stream, status, &body);
        }
        // Queue exhausted: behave like an idle Pub/Sub (empty pull / ack ok) so
        // a producer that keeps polling is paced, not flooded with transient
        // gaps.
        None => write_json(&mut stream, 200, "{}"),
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
    // Front is a path-routed `ForPath` that does NOT match this request (e.g. an
    // aggressive re-pull arriving while only an `:acknowledge` response is
    // queued). Do NOT consume the mismatched entry; serve a path-appropriate
    // idle default (the `None` branch), so the puller is paced, not flooded with
    // transient gaps.
    None
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
    Ok(HttpRequest {
        method,
        path,
        body,
        received_at: Instant::now(),
    })
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

async fn backend(endpoint: &str) -> Arc<GcsBackend> {
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
    let config = ovstorage_plugin_gcs::__test_only_parse_config(&config).expect("parse config");
    Arc::new(
        ovstorage_plugin_gcs::__test_only_backend(config, SecretBundle::default())
            .expect("build backend"),
    )
}

fn target(prefix: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("gcs:test".into()),
        resolved_address: address::parse(&format!("gs://assets/{prefix}")).unwrap(),
    }
}

/// Start a coalesced watch on `prefix`.
async fn watch(
    backend: &GcsBackend,
    prefix: &str,
    opts: WatchDirectoryOptions,
    cancel: Option<CancellationToken>,
) -> ovstorage_plugin::Result<BackendChangeStream> {
    backend.watch_directory(target(prefix), opts, cancel).await
}

fn recursive_opts() -> WatchDirectoryOptions {
    WatchDirectoryOptions {
        recursive: true,
        poll_interval: Duration::from_millis(20),
        ..WatchDirectoryOptions::default()
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

fn object_address(event: &BackendChangeEvent) -> String {
    match event {
        BackendChangeEvent::Object { address, .. } => address.as_str().to_string(),
        other => panic!("expected object event, got {other:?}"),
    }
}

/// Collected results of draining a watcher within a bounded window.
struct Collected {
    events: Vec<BackendChangeEvent>,
    terminal: Option<ovstorage_plugin::Error>,
}

/// Read the next stream item, bounded by `timeout`. On timeout, cancel the
/// watcher (unblocking the parked `next()`) and report end-of-stream.
async fn read_next(
    stream: BackendChangeStream,
    cancel: &CancellationToken,
    timeout: Duration,
) -> (
    Option<BackendChangeStream>,
    Option<ovstorage_plugin::Result<BackendChangeEvent>>,
) {
    let mut handle = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        let item = stream.next();
        (stream, item)
    });
    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(joined) => {
            let (stream, item) = joined.expect("blocking next() task panicked");
            match item {
                Some(event) => (Some(stream), Some(event)),
                None => (None, None),
            }
        }
        Err(_elapsed) => {
            cancel.cancel();
            match tokio::time::timeout(Duration::from_secs(2), &mut handle).await {
                Ok(joined) => {
                    let _ = joined.expect("blocking next() task panicked after cancel");
                }
                Err(_) => handle.abort(),
            }
            (None, None)
        }
    }
}

/// Drain up to `expected` object events (plus a short quiet window), cancelling
/// on idle. A terminal `Err` is captured in `Collected::terminal`.
async fn collect(
    stream: BackendChangeStream,
    cancel: &CancellationToken,
    expected: usize,
) -> Collected {
    const PER_EVENT: Duration = Duration::from_secs(5);
    const QUIET_WINDOW: Duration = Duration::from_millis(400);
    let mut events = Vec::new();
    let mut terminal = None;
    let mut stream = Some(stream);
    while let Some(current) = stream.take() {
        let wait = if events.len() < expected {
            PER_EVENT
        } else {
            QUIET_WINDOW
        };
        let (next_stream, item) = read_next(current, cancel, wait).await;
        match item {
            Some(Ok(event)) => {
                events.push(event);
                stream = next_stream;
            }
            Some(Err(err)) => {
                terminal = Some(err);
                break;
            }
            None => break,
        }
    }
    Collected { events, terminal }
}

// === Migrated single-consumer behavior (new ack-after-fan-out contract) ===

#[tokio::test(flavor = "multi_thread")]
async fn since_prepends_initial_lapsed_then_live_event() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(0),
        pull_response(&[("ack-1", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let mut stream = watch(
        &backend,
        "dir/",
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
async fn no_trailing_slash_watch_matches_children_and_acks_both() {
    // Under coalescing the producer opens at root, so BOTH the child and the
    // filtered sibling are real deliveries: the child fans out to the "dir/"
    // subscriber, the sibling fans out to zero matching subscribers — and BOTH
    // are acked after fan-out (an event outside a view is still acked, never
    // leaked). This is the ack-after-fan-out contract replacing the old
    // one-next-delayed behavior.
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
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "dir", recursive_opts(), Some(cancel.clone()))
        .await
        .unwrap();

    let (stream, first) = next_item(stream).await;
    match first.unwrap().unwrap() {
        BackendChangeEvent::Object { address, .. } => {
            assert_eq!(address.as_str(), "gs://assets/dir/a.txt?generation=42")
        }
        other => panic!("expected child object event, got {other:?}"),
    }
    wait_for_ack_ids(&fixture, &["ack-child", "ack-sibling"]);
    let acked: String = ack_bodies(&fixture).join(",");
    assert!(acked.contains("ack-child"), "child must be acked: {acked}");
    assert!(
        acked.contains("ack-sibling"),
        "filtered sibling must still be acked: {acked}"
    );
    cancel.cancel();
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn each_message_is_acked_after_fanout() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        pull_response(&[("ack-1", "dir/a.txt"), ("ack-2", "dir/b.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
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
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "dir/", recursive_opts(), Some(cancel.clone()))
        .await
        .unwrap();

    let collected = collect(stream, &cancel, 2).await;
    assert!(collected.terminal.is_none());
    let mut got: Vec<String> = collected.events.iter().map(object_address).collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            "gs://assets/dir/a.txt?generation=42".to_string(),
            "gs://assets/dir/b.txt?generation=42".to_string(),
        ]
    );
    // Both messages acked, each exactly once — whether the pump coalesced them
    // into one batched `:acknowledge` or issued two calls (the pump batches ready
    // receipts, so the request count is timing-dependent; the exactly-once ackId
    // guarantee is not).
    wait_for_ack_ids(&fixture, &["ack-1", "ack-2"]);
    let acked: String = ack_bodies(&fixture).join(",");
    assert_eq!(
        acked.matches("ack-1").count(),
        1,
        "ack-1 must be acknowledged exactly once"
    );
    assert_eq!(
        acked.matches("ack-2").count(),
        1,
        "ack-2 must be acknowledged exactly once"
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
    let cancel = CancellationToken::new();
    let stream = watch(
        &backend,
        "dir/",
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
        item.unwrap().unwrap(),
        BackendChangeEvent::Lapsed { .. }
    ));
    wait_for_acks(&fixture, 1);
    let acked: String = ack_bodies(&fixture).join(",");
    assert!(acked.contains("ack-malformed"));
    cancel.cancel();
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn ack_invalid_argument_surfaces_as_fatal_error() {
    // Case (c): a non-exactly-once INVALID_ARGUMENT ack is TERMINAL.
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
    let stream = watch(
        &backend,
        "dir/",
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
    match first.unwrap().unwrap() {
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
    let stream = watch(
        &backend,
        "dir/",
        WatchDirectoryOptions {
            recursive: true,
            poll_interval: Duration::from_millis(20),
            ..WatchDirectoryOptions::default()
        },
        None,
    )
    .await
    .unwrap();

    // The filtered event fans out to zero matching subscribers, but its ack
    // still fires; the PermissionDenied ack failure is a terminal broadcast.
    let (_stream, fatal) = next_item(stream).await;
    let err = fatal
        .expect("fatal stream item")
        .expect_err("filtered ack PermissionDenied should stop the stream");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    let acked: String = ack_bodies(&fixture).join(",");
    assert!(acked.contains("ack-denied"));
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
    let mut stream = watch(&backend, "dir/", recursive_opts(), None)
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
async fn empty_pull_does_not_terminate_and_is_paced() {
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        empty_pull_response(),
        pull_response(&[("ack-1", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let mut stream = watch(
        &backend,
        "dir/",
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
    // The coalescer-supplied cadence (the request's normalized 150ms poll
    // interval for a single subscriber) paces the empty-pull re-poll. The
    // producer may legitimately issue a third pull as soon as the non-empty
    // second response is consumed, so assert the interval between the two
    // requests whose timing carries the contract rather than the live
    // producer's eventual request count.
    let pull_times = fixture.pull_times();
    assert!(
        pull_times.len() >= 2,
        "the event requires an empty pull followed by a non-empty pull"
    );
    let pull_delay = pull_times[1].duration_since(pull_times[0]);
    assert!(
        pull_delay >= Duration::from_millis(100),
        "empty-pull re-poll was not paced: observed {pull_delay:?}"
    );
    drop(stream);
}

#[tokio::test(flavor = "multi_thread")]
async fn scope_insufficient_403_maps_auth_required() {
    let fixture = PubsubFixture::new(vec![scope_403_response()]);
    let backend = backend(&fixture.endpoint).await;

    let err = match watch(&backend, "dir/", WatchDirectoryOptions::default(), None).await {
        Ok(_) => panic!("watch_directory should fail on Pub/Sub 403"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::AuthRequired);
}

#[tokio::test(flavor = "multi_thread")]
async fn generic_403_maps_permission_denied() {
    let fixture = PubsubFixture::new(vec![permission_403_response()]);
    let backend = backend(&fixture.endpoint).await;

    let err = match watch(&backend, "dir/", WatchDirectoryOptions::default(), None).await {
        Ok(_) => panic!("watch_directory should fail on generic Pub/Sub 403"),
        Err(err) => err,
    };
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_last_stream_closes_held_pull() {
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
    let stream = watch(
        &backend,
        "dir/",
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
        "dropping the last stream should cancel the held pull connection"
    );
}

// === REQUIRED: exactly-once stale-ack replacement (pump-level) ===

/// The four exactly-once stale-ack cases under ack-after-fan-out:
///   (a) an exactly-once ack delayed beyond the stale threshold returning
///       INVALID_ARGUMENT is classified `ExpectedStale` and the stream
///       CONTINUES (asserted here);
///   (d) a subsequent message is actually acked after the stale result
///       (asserted here);
///   (b) a pre-deadline exactly-once INVALID_ARGUMENT is TERMINAL — asserted by
///       the `invalid_argument_before_deadline_is_fatal` unit test in
///       `subscription.rs`;
///   (c) a non-exactly-once INVALID_ARGUMENT is TERMINAL — asserted by
///       `ack_invalid_argument_surfaces_as_fatal_error` above and the
///       `non_exactly_once_invalid_argument_is_fatal_even_after_deadline` unit
///       test.
#[tokio::test(flavor = "multi_thread")]
async fn exactly_once_stale_ack_continues_and_next_message_is_acked() {
    // Under ack-after-fan-out the ack fires promptly, so the stale threshold is
    // crossed by DELAYING the ack response itself: `clock.now()` is captured
    // AFTER the POST returns, so a ~6.5s-delayed 400 lands beyond
    // ack_deadline (1s) + ACK_STALE_SKEW (5s) → ExpectedStale, non-fatal. The
    // producer meanwhile keeps pulling (independent task), so `dir/b.txt`
    // arrives promptly and is acked normally.
    let fixture = PubsubFixture::new(vec![
        subscription_get_with_exactly_once(1, true),
        pull_response(&[("ack-stale", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(HttpResponse::Delayed {
                delay: Duration::from_millis(6500),
                status: 400,
                body: serde_json::json!({
                    "error": { "code": 400, "status": "INVALID_ARGUMENT", "message": "expired" }
                })
                .to_string(),
            }),
        },
        HttpResponse::ForPath {
            suffix: ":pull",
            response: Box::new(pull_response(&[("ack-next", "dir/b.txt")])),
        },
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let stream = watch(
        &backend,
        "dir/",
        WatchDirectoryOptions {
            recursive: true,
            poll_interval: Duration::from_millis(20),
            ..WatchDirectoryOptions::default()
        },
        None,
    )
    .await
    .unwrap();

    // The producer delivers a then b promptly, while the ack pump is parked on
    // the delayed stale ack. Read both WITHOUT cancelling so the shared upstream
    // stays alive until the (slow) acks complete. A fatal stale classification
    // would surface as a terminal Err in place of the second object.
    let (stream, first) = next_item(stream).await;
    assert_eq!(
        object_address(&first.unwrap().unwrap()),
        "gs://assets/dir/a.txt?generation=42"
    );
    let (stream, second) = next_item(stream).await;
    match second.expect("stream item") {
        Ok(event) => assert_eq!(
            object_address(&event),
            "gs://assets/dir/b.txt?generation=42",
            "an ExpectedStale ack must NOT terminate the stream"
        ),
        Err(err) => panic!("stale ack must not be fatal, got terminal {:?}", err.code()),
    }

    // Case (d): the subsequent message is actually acked after the stale result.
    wait_for_ack_ids(&fixture, &["ack-stale", "ack-next"]);
    let acked: String = ack_bodies(&fixture).join(",");
    assert!(acked.contains("ack-stale"), "the stale ack was attempted");
    assert!(
        acked.contains("ack-next"),
        "the subsequent message must be acked after the stale result: {acked}"
    );
    drop(stream);
}

// === REQUIRED adopter tests: shared consumer, caps, cadence ===

/// A GCS backend (one connection) wired to the gated Pub/Sub mock.
fn gated_backend(endpoint: &str) -> GcsBackend {
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
    config.insert("pubsub_pull_max".into(), ConfigValue::Int(10));
    let parsed = ovstorage_plugin_gcs::__test_only_parse_config(&config).expect("parse config");
    ovstorage_plugin_gcs::__test_only_backend(parsed, SecretBundle::default())
        .expect("backend init")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_different_prefix_watches_share_one_puller() {
    let fixture = GatedPubsubFixture::new(vec![
        PubsubMessageSpec::new("ack-a", "a/x.txt"),
        PubsubMessageSpec::new("ack-b", "b/y.txt"),
    ]);
    let backend = gated_backend(fixture.endpoint());

    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();
    let w_a = watch(&backend, "a/", recursive_opts(), Some(cancel_a.clone()))
        .await
        .expect("a/ watch should start");
    let w_b = watch(&backend, "b/", recursive_opts(), Some(cancel_b.clone()))
        .await
        .expect("b/ watch should start");

    assert!(
        fixture.wait_for_pullers(1, Duration::from_secs(5)),
        "a coalesced connection must open exactly one physical Pub/Sub puller"
    );
    fixture.open_gate();

    let got_a = collect(w_a, &cancel_a, 1).await;
    let got_b = collect(w_b, &cancel_b, 1).await;
    assert!(got_a.terminal.is_none() && got_b.terminal.is_none());
    assert_eq!(
        got_a.events.iter().map(object_address).collect::<Vec<_>>(),
        vec!["gs://assets/a/x.txt?generation=42".to_string()]
    );
    assert_eq!(
        got_b.events.iter().map(object_address).collect::<Vec<_>>(),
        vec!["gs://assets/b/y.txt?generation=42".to_string()]
    );
    assert_eq!(
        fixture.max_concurrent_pulls(),
        1,
        "the two watches must not open competing consumers"
    );
    // Each message acked exactly once.
    assert!(fixture.wait_for_acks(2, Duration::from_secs(2)));
    let mut acks = fixture.acks();
    acks.sort();
    assert_eq!(acks, vec!["ack-a".to_string(), "ack-b".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn since_watch_coalesces_initial_lapsed_then_live_no_dedicated_puller() {
    let fixture = GatedPubsubFixture::new(vec![PubsubMessageSpec::new("ack-live", "dir/live.txt")]);
    let backend = gated_backend(fixture.endpoint());
    let cancel = CancellationToken::new();
    let stream = watch(
        &backend,
        "dir/",
        WatchDirectoryOptions {
            recursive: true,
            since: Some(WatchDirectoryCursor(vec![9, 9, 9])),
            poll_interval: Duration::from_millis(20),
            ..WatchDirectoryOptions::default()
        },
        Some(cancel.clone()),
    )
    .await
    .expect("since watch should start");

    // The prepended Lapsed arrives before the gate opens (no history to replay).
    let (stream, first) = next_item(stream).await;
    assert!(matches!(
        first.expect("stream item").expect("initial lapsed"),
        BackendChangeEvent::Lapsed { .. }
    ));

    assert!(fixture.wait_for_pullers(1, Duration::from_secs(5)));
    fixture.open_gate();

    let collected = collect(stream, &cancel, 1).await;
    assert!(collected.terminal.is_none());
    assert_eq!(
        collected
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["gs://assets/dir/live.txt?generation=42".to_string()]
    );
    assert_eq!(
        fixture.max_concurrent_pulls(),
        1,
        "a since watch must coalesce, not open a dedicated consumer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn coalesced_cadence_normalizes_zero_poll_interval() {
    // A zero `poll_interval` normalizes to EMPTY_PULL_IDLE_INTERVAL (1s) via
    // `empty_pull_idle_interval`, which the coalescer mins across the cohort and
    // hands the upstream. A non-normalized zero would busy re-pull immediately;
    // here the second pull must NOT have happened within a 300ms window.
    let fixture = PubsubFixture::new(vec![
        subscription_get(10),
        empty_pull_response(),
        pull_response(&[("ack-1", "dir/a.txt")]),
        HttpResponse::ForPath {
            suffix: ":acknowledge",
            response: Box::new(ack_response()),
        },
    ]);
    let backend = backend(&fixture.endpoint).await;
    let cancel = CancellationToken::new();
    let stream = watch(
        &backend,
        "dir/",
        WatchDirectoryOptions {
            recursive: true,
            poll_interval: Duration::ZERO,
            ..WatchDirectoryOptions::default()
        },
        Some(cancel.clone()),
    )
    .await
    .unwrap();

    // After the first (empty) pull, the 1s normalized idle has not elapsed, so
    // only one pull should have been issued.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let pull_count = fixture
        .requests()
        .iter()
        .filter(|(_, path, _)| path.ends_with(":pull"))
        .count();
    assert_eq!(
        pull_count, 1,
        "zero poll_interval must normalize to a 1s idle, not a tight re-pull loop"
    );
    cancel.cancel();
    drop(stream);
}

fn ack_bodies(fixture: &PubsubFixture) -> Vec<String> {
    fixture
        .requests()
        .into_iter()
        .filter(|(_, path, _)| path.ends_with(":acknowledge"))
        .map(|(_, _, body)| body)
        .collect()
}

/// Wait until every `ack_id` has appeared in some `:acknowledge` request body,
/// regardless of how the pump split them across batched calls.
fn wait_for_ack_ids(fixture: &PubsubFixture, ack_ids: &[&str]) {
    for _ in 0..400 {
        let acked: String = ack_bodies(fixture).join(",");
        if ack_ids.iter().all(|id| acked.contains(id)) {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("expected all ackIds {ack_ids:?} to be acknowledged");
}

fn wait_for_acks(fixture: &PubsubFixture, expected: usize) {
    // Budget generously: an exactly-once stale-ack test delays an ack response
    // ~6.5s, and the sequential ack pump only issues the following ack after it.
    for _ in 0..400 {
        if ack_bodies(fixture).len() >= expected {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("expected at least {expected} ack requests");
}
