// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared test fixtures/helpers are used unevenly across this binary's tests.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendId, CancellationToken, ChangeKind, ConfigValue,
    ErrorCode, ResolvedTarget, WatchDirectoryCursor, WatchDirectoryOptions, address,
};
use ovstorage_plugin_s3::{AwsCredentials, S3Backend};

mod support;
use support::GatedSqsFixture;

// S3 ignores `opts.poll_interval`; the coalescer negotiates over the
// connection's `sqs_wait_seconds`. These backends configure 1s, so drivers pass
// this normalized cadence.
const CADENCE: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct SqsMessageSpec {
    message_id: String,
    receipt_handle: String,
    body: String,
}

#[derive(Clone)]
enum ReceivePlan {
    Messages(Vec<SqsMessageSpec>),
    Hold,
}

#[derive(Clone)]
enum DeletePlan {
    Success,
    AccessDenied,
    ReceiptExpired,
    ReceiptHandleInvalid,
    /// Never answer the delete: park the connection until the client closes it
    /// (or the fixture shuts down). Models a `DeleteMessageBatch` in flight, for
    /// exercising cancellation mid-delete.
    Hold,
}

struct FixtureState {
    receive_plans: VecDeque<ReceivePlan>,
    delete_plans: VecDeque<DeletePlan>,
    /// Per-receipt-handle delete plan overrides. Consulted before the ordered
    /// `delete_plans` queue, so a test can pin an outcome to a specific message
    /// regardless of the (scheduling-dependent) order its delete arrives in.
    delete_overrides: HashMap<String, DeletePlan>,
    deletes: Vec<String>,
    receive_count: usize,
    held_receives_started: usize,
    held_receives_closed: usize,
    /// Number of held (`DeletePlan::Hold`) deletes whose client connection has
    /// closed — the pump dropped the in-flight `DeleteMessageBatch` future on
    /// cancellation. Proves the parked delete actually unwound, not just that the
    /// event stream EOF'd.
    held_deletes_closed: usize,
    /// Delay applied to a `ReceiptExpired` delete before its response is written,
    /// so the response lands past the ack deadline plus `STALE_HANDLE_SKEW` and
    /// classifies as `Transient` (a genuinely-lapsed receipt handle) rather than
    /// fatal — without any caller pacing.
    expired_delete_delay: Duration,
    shutdown: bool,
}

struct SqsFixture {
    queue_url: String,
    shared: Arc<(Mutex<FixtureState>, Condvar)>,
    listener: Option<thread::JoinHandle<()>>,
}

impl SqsFixture {
    fn new(receive_plans: Vec<ReceivePlan>, delete_plans: Vec<DeletePlan>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        listener.set_nonblocking(true).expect("set nonblocking");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new((
            Mutex::new(FixtureState {
                receive_plans: receive_plans.into(),
                delete_plans: delete_plans.into(),
                delete_overrides: HashMap::new(),
                deletes: Vec::new(),
                receive_count: 0,
                held_receives_started: 0,
                held_receives_closed: 0,
                held_deletes_closed: 0,
                expired_delete_delay: Duration::ZERO,
                shutdown: false,
            }),
            Condvar::new(),
        ));
        let shared_for_thread = shared.clone();
        let handle = thread::Builder::new()
            .name("ovs-test-sqs".into())
            .spawn(move || accept_loop(listener, shared_for_thread))
            .expect("failed to spawn thread");

        Self {
            queue_url: format!("http://{addr}/123456789012/watch"),
            shared,
            listener: Some(handle),
        }
    }

    fn queue_url(&self) -> &str {
        &self.queue_url
    }

    /// Hold every `ReceiptExpired` delete response for `delay` before writing it,
    /// so it lands past the ack deadline plus skew (→ `Transient`).
    fn set_expired_delete_delay(&self, delay: Duration) {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap().expired_delete_delay = delay;
    }

    /// Pin a delete outcome to a specific receipt handle, independent of the
    /// order its `DeleteMessageBatch` arrives in.
    fn set_delete_override(&self, receipt_handle: &str, plan: DeletePlan) {
        let (lock, _) = &*self.shared;
        lock.lock()
            .unwrap()
            .delete_overrides
            .insert(receipt_handle.to_string(), plan);
    }

    fn wait_until(&self, timeout: Duration, mut predicate: impl FnMut(&FixtureState) -> bool) {
        let deadline = std::time::Instant::now() + timeout;
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().unwrap();
        while !predicate(&state) {
            let now = std::time::Instant::now();
            assert!(now < deadline, "fixture condition timed out");
            let wait = deadline.saturating_duration_since(now);
            let (next, _) = cvar.wait_timeout(state, wait).unwrap();
            state = next;
        }
    }

    fn assert_no_deletes_beyond(&self, expected: &[&str], duration: Duration) {
        let (lock, cvar) = &*self.shared;
        let state = lock.lock().unwrap();
        let (state, _) = cvar.wait_timeout(state, duration).unwrap();
        assert_eq!(
            state.deletes, expected,
            "unexpected deletes beyond {expected:?}"
        );
    }

    fn deletes(&self) -> Vec<String> {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap().deletes.clone()
    }

    fn wait_for_deletes(&self, expected: &[&str]) {
        self.wait_until(Duration::from_secs(2), |state| {
            state.deletes.len() >= expected.len()
                && state
                    .deletes
                    .iter()
                    .zip(expected.iter())
                    .all(|(actual, expected)| actual == expected)
        });
    }

    fn wait_for_held_receive_started(&self) {
        self.wait_until(Duration::from_secs(2), |state| {
            state.held_receives_started > 0
        });
    }

    fn wait_for_held_receive_closed(&self) {
        self.wait_until(Duration::from_secs(2), |state| {
            state.held_receives_closed > 0
        });
    }

    fn wait_for_held_delete_closed(&self) {
        self.wait_until(Duration::from_secs(2), |state| {
            state.held_deletes_closed > 0
        });
    }
}

impl Drop for SqsFixture {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.shared;
        {
            let mut state = lock.lock().unwrap();
            state.shutdown = true;
            cvar.notify_all();
        }
        if let Some(handle) = self.listener.take() {
            handle.join().expect("SQS fixture listener should exit");
        }
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<(Mutex<FixtureState>, Condvar)>) {
    loop {
        {
            let (lock, _) = &*shared;
            if lock.lock().unwrap().shutdown {
                return;
            }
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let shared_for_thread = shared.clone();
                thread::Builder::new()
                    .name("ovs-sqs-conn".into())
                    .spawn(move || handle_connection(stream, shared_for_thread))
                    .expect("failed to spawn thread");
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return,
        }
    }
}

fn handle_connection(mut stream: TcpStream, shared: Arc<(Mutex<FixtureState>, Condvar)>) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    // aws-sdk-sqs speaks awsJson1.0: the operation lives in the `X-Amz-Target`
    // header (`AmazonSQS.ReceiveMessage` / `AmazonSQS.DeleteMessageBatch`).
    if request.target.ends_with("ReceiveMessage") {
        handle_receive(stream, shared);
    } else if request.target.ends_with("DeleteMessageBatch") {
        handle_delete(stream, shared, &request.body);
    } else {
        write_response(&mut stream, 400, "Bad Request", "{}");
    }
}

fn handle_receive(mut stream: TcpStream, shared: Arc<(Mutex<FixtureState>, Condvar)>) {
    let plan = {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        state.receive_count += 1;
        let plan = state.receive_plans.pop_front().unwrap_or(ReceivePlan::Hold);
        cvar.notify_all();
        plan
    };

    match plan {
        ReceivePlan::Messages(messages) => {
            write_response(&mut stream, 200, "OK", &receive_response(&messages));
        }
        ReceivePlan::Hold => {
            {
                let (lock, cvar) = &*shared;
                let mut state = lock.lock().unwrap();
                state.held_receives_started += 1;
                cvar.notify_all();
            }
            wait_for_client_close(&mut stream);
            let (lock, cvar) = &*shared;
            let mut state = lock.lock().unwrap();
            state.held_receives_closed += 1;
            cvar.notify_all();
        }
    }
}

fn handle_delete(mut stream: TcpStream, shared: Arc<(Mutex<FixtureState>, Condvar)>, body: &[u8]) {
    // A `DeleteMessageBatch` carries one OR MORE entries (the ack pump coalesces
    // ready receipts into a single call). Parse every entry's `(Id, ReceiptHandle)`
    // and resolve a per-entry plan — one plan per message, equivalent to the old
    // one-plan-per-request model back when each message got its own delete call.
    let entries: Vec<(String, String)> = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("Entries").and_then(|e| e.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            let id = entry.get("Id")?.as_str()?.to_string();
            let receipt = entry.get("ReceiptHandle")?.as_str()?.to_string();
            Some((id, receipt))
        })
        .collect();

    let (planned, expired_delay) = {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        let mut planned: Vec<(String, DeletePlan)> = Vec::new();
        let mut any_expired = false;
        for (id, receipt) in &entries {
            let plan = state
                .delete_overrides
                .get(receipt)
                .cloned()
                .unwrap_or_else(|| {
                    state
                        .delete_plans
                        .pop_front()
                        .unwrap_or(DeletePlan::Success)
                });
            if matches!(plan, DeletePlan::ReceiptExpired) {
                any_expired = true;
            }
            // Record every entry's receipt (in batch order) so multi-message
            // batched deletes account for each message, not just the first.
            state.deletes.push(receipt.clone());
            planned.push((id.clone(), plan));
        }
        let expired_delay = if any_expired {
            state.expired_delete_delay
        } else {
            Duration::ZERO
        };
        cvar.notify_all();
        (planned, expired_delay)
    };

    // A `Hold` entry never responds: the batched delete stays in flight until the
    // client (the pump, on cancellation) closes the connection. Record the close
    // so a test can prove the parked delete unwound at the delete site.
    if planned
        .iter()
        .any(|(_, plan)| matches!(plan, DeletePlan::Hold))
    {
        wait_for_client_close(&mut stream);
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        state.held_deletes_closed += 1;
        cvar.notify_all();
        return;
    }

    // Delay the whole response past the ack deadline plus skew so any lapsed
    // receipt handle in the batch classifies as Transient.
    if !expired_delay.is_zero() {
        thread::sleep(expired_delay);
    }
    write_response(&mut stream, 200, "OK", &delete_batch_response(&planned));
}

struct HttpRequest {
    /// `X-Amz-Target` header (awsJson1.0): `AmazonSQS.ReceiveMessage` etc.
    target: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<HttpRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        let len = stream.read(&mut buf).ok()?;
        if len == 0 {
            return None;
        }
        bytes.extend_from_slice(&buf[..len]);
        if let Some(found) = find_header_end(&bytes) {
            break found;
        }
    };
    let (content_length, target) = {
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let target = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-amz-target")
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default();
        (content_length, target)
    };
    let body_start = header_end + 4;
    while bytes.len() < body_start + content_length {
        let len = stream.read(&mut buf).ok()?;
        if len == 0 {
            return None;
        }
        bytes.extend_from_slice(&buf[..len]);
    }
    Some(HttpRequest {
        target,
        body: bytes[body_start..body_start + content_length].to_vec(),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn wait_for_client_close(stream: &mut TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_millis(25)))
        .expect("set read timeout");
    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return,
        }
    }
}

fn write_response(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/x-amz-json-1.0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn receive_response(messages: &[SqsMessageSpec]) -> String {
    let messages: Vec<serde_json::Value> = messages
        .iter()
        .map(|message| {
            serde_json::json!({
                "MessageId": message.message_id,
                "ReceiptHandle": message.receipt_handle,
                "Body": message.body,
            })
        })
        .collect();
    serde_json::json!({ "Messages": messages }).to_string()
}

/// Build a `DeleteMessageBatch` response covering every entry, echoing each
/// entry's own `Id` so the pump maps a `Failed` result back to its receipt (and
/// deadline). A `Success` entry lands in `Successful`; every other plan lands in
/// `Failed` with the matching AWS error code.
fn delete_batch_response(planned: &[(String, DeletePlan)]) -> String {
    let mut successful = Vec::new();
    let mut failed = Vec::new();
    for (id, plan) in planned {
        match plan {
            DeletePlan::Success => successful.push(serde_json::json!({ "Id": id })),
            DeletePlan::AccessDenied => failed.push(serde_json::json!({
                "Id": id,
                "SenderFault": true,
                "Code": "AccessDenied",
                "Message": "denied",
            })),
            DeletePlan::ReceiptExpired => failed.push(serde_json::json!({
                "Id": id,
                "SenderFault": true,
                "Code": "InvalidParameterValue",
                "Message": "The receipt handle has expired.",
            })),
            DeletePlan::ReceiptHandleInvalid => failed.push(serde_json::json!({
                "Id": id,
                "SenderFault": false,
                "Code": "ReceiptHandleIsInvalid",
                "Message": "bad handle",
            })),
            // Hold is handled before response construction (never reaches here).
            DeletePlan::Hold => {}
        }
    }
    serde_json::json!({ "Successful": successful, "Failed": failed }).to_string()
}

fn backend(queue_url: &str) -> S3Backend {
    backend_with_visibility(queue_url, 5)
}

fn backend_with_visibility(queue_url: &str, visibility_timeout: i64) -> S3Backend {
    backend_with_config(queue_url, visibility_timeout, |_| {})
}

fn backend_with_config(
    queue_url: &str,
    visibility_timeout: i64,
    tweak: impl FnOnce(&mut HashMap<String, ConfigValue>),
) -> S3Backend {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String("bkt".into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert(
        "sqs_queue_url".into(),
        ConfigValue::String(queue_url.into()),
    );
    config.insert("sqs_max_messages".into(), ConfigValue::Int(10));
    config.insert("sqs_wait_seconds".into(), ConfigValue::Int(1));
    config.insert(
        "sqs_visibility_timeout".into(),
        ConfigValue::Int(visibility_timeout),
    );
    tweak(&mut config);
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    let credentials = AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    };
    S3Backend::with_credentials(parsed, credentials).expect("backend init")
}

fn target(prefix: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("s3:s3://bkt/".into()),
        resolved_address: address::parse(&format!("s3://bkt/{prefix}")).unwrap(),
    }
}

fn recursive_opts() -> WatchDirectoryOptions {
    WatchDirectoryOptions {
        recursive: true,
        ..WatchDirectoryOptions::default()
    }
}

/// Open a coalesced watch on `backend` for `prefix`.
async fn watch(
    backend: &S3Backend,
    prefix: &str,
    opts: WatchDirectoryOptions,
    cancel: Option<CancellationToken>,
) -> ovstorage_plugin::Result<BackendChangeStream> {
    backend
        .watch_directory(target(prefix), opts, CADENCE, cancel)
        .await
}

fn notification_body(key: &str) -> String {
    notification_body_records(&[key])
}

/// A `Records` notification carrying one `ObjectCreated:Put` per key.
fn notification_body_records(keys: &[&str]) -> String {
    let records: Vec<serde_json::Value> = keys
        .iter()
        .map(|key| {
            serde_json::json!({
                "eventTime": "2026-05-12T10:11:12Z",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": "bkt"},
                    "object": {"key": key, "eTag": "etag-1", "size": 7}
                }
            })
        })
        .collect();
    serde_json::json!({ "Records": records }).to_string()
}

fn malformed_notification_body() -> String {
    "{not json".into()
}

fn notification_body_with_malformed_sibling() -> String {
    serde_json::json!({
        "Records": [
            {
                "eventTime": "2026-05-12T10:11:12Z",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": "bkt"},
                    "object": {"key": "photos/good.jpg", "eTag": "etag-1", "size": 7}
                }
            },
            {
                "eventTime": "2026-05-12T10:11:13Z",
                "s3": {
                    "bucket": {"name": "bkt"},
                    "object": {"key": "photos/bad.jpg", "eTag": "etag-2", "size": 8}
                }
            }
        ]
    })
    .to_string()
}

fn mismatched_notification_body() -> String {
    serde_json::json!({
        "Records": [{
            "eventTime": "2026-05-12T10:11:12Z",
            "eventName": "ObjectCreated:Put",
            "s3": {
                "bucket": {"name": "other-bucket"},
                "object": {"key": "photos/ignored.jpg"}
            }
        }]
    })
    .to_string()
}

fn message(message_id: &str, receipt_handle: &str, body: String) -> SqsMessageSpec {
    SqsMessageSpec {
        message_id: message_id.into(),
        receipt_handle: receipt_handle.into(),
        body,
    }
}

async fn next_item(
    mut stream: BackendChangeStream,
) -> (
    BackendChangeStream,
    Option<ovstorage_plugin::Result<BackendChangeEvent>>,
) {
    tokio::task::spawn_blocking(move || {
        let item = stream.next();
        (stream, item)
    })
    .await
    .expect("stream iterator task should not panic")
}

/// Drain the stream, bounding each blocking `next()` with a timeout + cancel so
/// a starved watcher yields end-of-stream instead of hanging. Returns the object
/// event addresses (sorted), the ordered event kinds, and any terminal error.
struct Collected {
    events: Vec<BackendChangeEvent>,
    terminal: Option<ovstorage_plugin::Error>,
}

async fn collect(
    stream: BackendChangeStream,
    cancel: &CancellationToken,
    expected: usize,
) -> Collected {
    let mut events = Vec::new();
    let mut stream = Some(stream);
    while let Some(current) = stream.take() {
        let wait = if events.len() < expected {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(300)
        };
        let handle = tokio::task::spawn_blocking(move || {
            let mut s = current;
            let item = s.next();
            (s, item)
        });
        match tokio::time::timeout(wait, handle).await {
            Ok(joined) => {
                let (s, item) = joined.expect("blocking next() task panicked");
                match item {
                    Some(Ok(event)) => {
                        events.push(event);
                        stream = Some(s);
                    }
                    Some(Err(err)) => {
                        return Collected {
                            events,
                            terminal: Some(err),
                        };
                    }
                    None => break,
                }
            }
            Err(_) => {
                cancel.cancel();
                break;
            }
        }
    }
    Collected {
        events,
        terminal: None,
    }
}

fn object_address(event: &BackendChangeEvent) -> String {
    match event {
        BackendChangeEvent::Object { address, .. } => address.as_str().to_string(),
        other => panic!("expected an object event, got {other:?}"),
    }
}

fn assert_object(event: BackendChangeEvent, key_suffix: &str) {
    match event {
        BackendChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            ..
        } => {
            assert_eq!(address.as_str(), format!("s3://bkt/photos/{key_suffix}"));
            assert_eq!(kind, ChangeKind::Created);
            assert_eq!(etag.as_deref(), Some("etag-1"));
            assert!(version.is_none());
            assert_eq!(size, Some(7));
            assert!(mtime.is_none());
            assert!(at <= SystemTime::now());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

fn assert_lapsed(event: &BackendChangeEvent) {
    match event {
        BackendChangeEvent::Lapsed { since, cursor } => {
            assert!(since.is_none());
            assert!(cursor.0.is_empty());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

// === `since` on a non-resumable backend: coalesced initial Lapsed, no
// dedicated reader ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn since_prepends_initial_lapsed_and_drop_tears_down_upstream() {
    let fixture = SqsFixture::new(vec![ReceivePlan::Hold], vec![]);
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(
        &backend,
        "photos/",
        WatchDirectoryOptions {
            recursive: true,
            since: Some(WatchDirectoryCursor(vec![1, 2, 3])),
            ..WatchDirectoryOptions::default()
        },
        Some(cancel.clone()),
    )
    .await
    .expect("watch_directory should start");

    // The coalescer prepends one Lapsed for a `since` watch on this
    // non-resumable backend (the best "resume" without history).
    let (stream, item) = next_item(stream).await;
    assert_lapsed(&item.expect("stream item").expect("initial event"));

    // One physical consumer opened and is long-polling.
    fixture.wait_for_held_receive_started();
    // Dropping the last (only) subscriber tears the shared upstream down.
    drop(stream);
    fixture.wait_for_held_receive_closed();
}

// === Ack-after-fan-out: each event's delete dispatches right after fan-out,
// and a multi-event message is deleted exactly once ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_event_message_is_deleted_once_after_every_event_acks() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-1",
                "rh-1",
                notification_body_records(&["photos/a.jpg", "photos/b.jpg"]),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Success],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    let collected = collect(stream, &cancel, 2).await;
    assert!(collected.terminal.is_none(), "no terminal error expected");
    let addresses: Vec<String> = collected.events.iter().map(object_address).collect();
    assert_eq!(
        addresses,
        vec![
            "s3://bkt/photos/a.jpg".to_string(),
            "s3://bkt/photos/b.jpg".to_string(),
        ]
    );
    // One SQS message → two events → deleted exactly once, after both acks.
    fixture.wait_for_deletes(&["rh-1"]);
    fixture.assert_no_deletes_beyond(&["rh-1"], Duration::from_millis(150));
}

// === Async provider ack failure: queued events DRAIN first, then the terminal
// Err (never the old "fatal beats the buffered tail" ordering) ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ack_fatal_drains_queued_events_then_surfaces_terminal_error() {
    // Determinism hinges on one SQS message carrying SEVERAL records: they share
    // a single refcounted delivery whose lone delete fires only after every one
    // of its events has been fanned out (its ack handle called). So all three
    // events are guaranteed delivered before the delete can fail — the terminal
    // provider `Err` is always the last stream item, never racing ahead of a
    // queued event. (With one event per message the ordering would be
    // scheduling-dependent.)
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-1",
                "rh-1",
                notification_body_records(&["photos/a.jpg", "photos/b.jpg", "photos/c.jpg"]),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::AccessDenied],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    // Every queued event drains before the trailing error.
    let collected = collect(stream, &cancel, 4).await;
    let addresses: Vec<String> = collected.events.iter().map(object_address).collect();
    assert_eq!(
        addresses,
        vec![
            "s3://bkt/photos/a.jpg".to_string(),
            "s3://bkt/photos/b.jpg".to_string(),
            "s3://bkt/photos/c.jpg".to_string(),
        ],
        "every queued event must drain before the terminal error"
    );
    let err = collected
        .terminal
        .expect("an async delete failure must surface as a terminal error");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
    fixture.wait_for_deletes(&["rh-1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_access_denied_surfaces_as_permission_denied() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-1",
                "rh-denied",
                notification_body("photos/denied.jpg"),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::AccessDenied],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    let collected = collect(stream, &cancel, 1).await;
    assert_eq!(
        collected
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["s3://bkt/photos/denied.jpg".to_string()]
    );
    let err = collected.terminal.expect("terminal error expected");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_handle_is_invalid_surfaces_as_fatal_even_without_sender_fault() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-invalid",
                "rh-invalid",
                notification_body("photos/invalid.jpg"),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::ReceiptHandleInvalid],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    let collected = collect(stream, &cancel, 1).await;
    assert_eq!(
        collected
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["s3://bkt/photos/invalid.jpg".to_string()]
    );
    let err = collected.terminal.expect("terminal error expected");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(err.message().contains("ReceiptHandleIsInvalid"));
    fixture.wait_for_deletes(&["rh-invalid"]);
}

// The STALE_HANDLE_SKEW classification (an expired receipt handle is transient
// only once it is past the visibility deadline plus skew) is exercised at the
// classifier level by the `expired_receipt_is_transient_only_after_deadline_skew`
// unit test in `src/subscription.rs`. Reader pacing can no longer delay a delete
// past the deadline (acks dispatch immediately after fan-out), but the pump-level
// `delayed_expired_delete_is_transient_and_pump_continues` test below drives it
// through the stream via a delayed `DeleteMessageBatch` response instead.

// === A DeleteMessageBatch response delayed past the visibility deadline + skew
// (no caller pacing) classifies Transient, and the pump keeps deleting later
// messages — a lapsed receipt handle is nonterminal ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_expired_delete_is_transient_and_pump_continues() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-1",
                "rh-1",
                notification_body("photos/a.jpg"),
            )]),
            ReceivePlan::Messages(vec![message(
                "m-2",
                "rh-2",
                notification_body("photos/b.jpg"),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::ReceiptExpired, DeletePlan::Success],
    );
    // visibility_timeout = 1s (the config floor) → ack deadline = receive + 1s; a
    // delete response held ~6.3s lands past deadline + STALE_HANDLE_SKEW (5s), so
    // the lapsed handle classifies Transient rather than fatal.
    fixture.set_expired_delete_delay(Duration::from_millis(6300));
    let backend = backend_with_visibility(fixture.queue_url(), 1);
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    // Both events fan out promptly (fan-out never waits on the delete).
    let (stream, first) = next_item(stream).await;
    assert_object(first.expect("stream item").expect("first event"), "a.jpg");
    let (stream, second) = next_item(stream).await;
    assert_object(second.expect("stream item").expect("second event"), "b.jpg");

    // rh-1's delete is Transient (nonterminal), so the pump recovers and deletes
    // rh-2. A fatal classification would instead stop the pump before rh-2. The
    // wait spans the ~5.3s hold on rh-1's response.
    fixture.wait_until(Duration::from_secs(15), |state| state.deletes.len() >= 2);
    assert_eq!(
        fixture.deletes(),
        vec!["rh-1".to_string(), "rh-2".to_string()]
    );

    // No terminal error ever surfaces: a transient delete is not a stream error.
    let collected = collect(stream, &cancel, 0).await;
    assert!(
        collected.terminal.is_none(),
        "a delayed expired-handle delete is transient, not a terminal error"
    );
}

// === Cancelling while a DeleteMessageBatch is in flight is a clean teardown, not
// a terminal error ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_during_in_flight_delete_tears_down_without_terminal_error() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-1",
                "rh-1",
                notification_body("photos/a.jpg"),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Hold],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    // The event fans out and its delete is dispatched; the fixture parks it, so
    // the pump is now blocked in `ack_with_cancel` awaiting the delete response.
    let (stream, item) = next_item(stream).await;
    assert_object(item.expect("stream item").expect("event"), "a.jpg");
    fixture.wait_for_deletes(&["rh-1"]);

    // Cancelling mid-delete selects the cancellation arm of `ack_with_cancel`:
    // the pump tears down cleanly and surfaces NO terminal error.
    cancel.cancel();
    let collected = collect(stream, &cancel, 0).await;
    assert!(
        collected.terminal.is_none(),
        "cancellation mid-delete is a clean teardown, not a terminal error"
    );

    // Prove the blocked in-flight delete actually unwound: dropping the ack
    // future on cancellation closed its `DeleteMessageBatch` client connection.
    // (A clean stream EOF alone would not prove the parked delete terminated.)
    fixture.wait_for_held_delete_closed();
}

// === Malformed notifications become a broadcast Lapsed, and the message is
// still deleted ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_message_yields_lapsed_then_is_deleted() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-malformed",
                "rh-malformed",
                malformed_notification_body(),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Success],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    let (stream, item) = next_item(stream).await;
    assert_lapsed(&item.expect("stream item").expect("lapsed event"));
    fixture.wait_for_deletes(&["rh-malformed"]);
    cancel.cancel();
    drop(stream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_record_sibling_yields_lapsed_without_dropping_valid_record() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-mixed",
                "rh-mixed",
                notification_body_with_malformed_sibling(),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Success],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    // The valid record and the synthesized Lapsed both arrive; the one SQS
    // message is deleted once, after both events ack.
    let collected = collect(stream, &cancel, 2).await;
    assert!(collected.terminal.is_none());
    assert_eq!(collected.events.len(), 2);
    assert_eq!(
        object_address(&collected.events[0]),
        "s3://bkt/photos/good.jpg"
    );
    assert_lapsed(&collected.events[1]);
    fixture.wait_for_deletes(&["rh-mixed"]);
    fixture.assert_no_deletes_beyond(&["rh-mixed"], Duration::from_millis(100));
}

// === A record outside the connection bucket carries no event; its
// acknowledgement (delete) routes through the ack pump (and a delete failure
// still surfaces terminally) ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_message_is_deleted_via_pump() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-filtered",
                "rh-filtered",
                mismatched_notification_body(),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Success],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    fixture.wait_for_deletes(&["rh-filtered"]);
    cancel.cancel();
    drop(stream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_message_delete_failure_surfaces_as_permission_denied() {
    let fixture = SqsFixture::new(
        vec![ReceivePlan::Messages(vec![message(
            "m-filtered",
            "rh-filtered",
            mismatched_notification_body(),
        )])],
        vec![DeletePlan::AccessDenied],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    let collected = collect(stream, &cancel, 0).await;
    let err = collected
        .terminal
        .expect("a filtered-delete failure must surface as a terminal error");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
    fixture.wait_for_deletes(&["rh-filtered"]);
}

// === A ZERO-EVENT message whose delete fails FATALLY, behind a queued eventful
// tail, surfaces the REAL provider error as the terminal — routed through the
// ack pump, so the queued event drains first and no masking generic error
// precedes it. Parity with the GCS `zero_event_*` pump tests. ===

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_event_fatal_delete_surfaces_after_queued_tail() {
    // Batch 1 fills a queued eventful tail; batch 2 is a bucket-mismatched
    // (zero-event) message whose delete is fatal. Receipt-keyed delete
    // overrides pin each outcome regardless of delete arrival order.
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-event",
                "rh-event",
                notification_body("photos/a.jpg"),
            )]),
            ReceivePlan::Messages(vec![message(
                "m-zero",
                "rh-zero",
                mismatched_notification_body(),
            )]),
            ReceivePlan::Hold,
        ],
        vec![],
    );
    fixture.set_delete_override("rh-event", DeletePlan::Success);
    fixture.set_delete_override("rh-zero", DeletePlan::AccessDenied);
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(&backend, "photos/", recursive_opts(), Some(cancel.clone()))
        .await
        .expect("watch_directory should start");

    // The queued eventful tail drains first, THEN the zero-event fatal delete
    // surfaces as the single terminal — never a masking generic error ahead of
    // the queued event. `collect` bounds each blocking `next()` with a timeout.
    let collected = collect(stream, &cancel, 1).await;
    assert_eq!(
        collected
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["s3://bkt/photos/a.jpg".to_string()],
        "the queued eventful tail must drain before the terminal"
    );
    let err = collected
        .terminal
        .expect("a zero-event fatal delete must surface as a terminal error");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
    // Deliberately NOT asserting which receipts were deleted: the queued
    // event's ack and the zero-event delivery both land on `ack_rx`, and their
    // relative order is scheduling-dependent. If the fatal zero-event delete is
    // processed first, the terminal helper legitimately drains and discards the
    // later event's queued ack (no delete), so requiring `rh-event`'s deletion
    // would flake. The masking intent is fully covered above: the real
    // `AccessDenied` terminal surfaces AFTER the queued event drains, never
    // masked by a generic error.
}

// === Adopter self-coalescing: two different-prefix watches share ONE consumer,
// each gets its events, and the message is deleted once ===

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_different_prefix_watches_share_one_consumer() {
    let fixture = GatedSqsFixture::new(vec![support::SqsMessageSpec::new(
        "m-shared",
        "rh-shared",
        support::notification_body(&["photos/a.jpg", "docs/b.jpg"]),
    )]);
    let backend = backend(fixture.queue_url());

    let cancel_photos = CancellationToken::new();
    let cancel_docs = CancellationToken::new();
    let w_photos = watch(
        &backend,
        "photos/",
        recursive_opts(),
        Some(cancel_photos.clone()),
    )
    .await
    .expect("photos watch should start");
    let w_docs = watch(
        &backend,
        "docs/",
        recursive_opts(),
        Some(cancel_docs.clone()),
    )
    .await
    .expect("docs watch should start");

    // Open BOTH watches, then release the one batch to the single consumer.
    assert!(
        fixture.wait_for_receivers(1, Duration::from_secs(5)),
        "a coalesced connection must open exactly one physical SQS receiver"
    );
    fixture.open_gate();

    let got_photos = collect(w_photos, &cancel_photos, 1).await;
    let got_docs = collect(w_docs, &cancel_docs, 1).await;
    assert!(got_photos.terminal.is_none() && got_docs.terminal.is_none());
    assert_eq!(
        got_photos
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["s3://bkt/photos/a.jpg".to_string()]
    );
    assert_eq!(
        got_docs
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["s3://bkt/docs/b.jpg".to_string()]
    );
    assert_eq!(
        fixture.max_concurrent_receives(),
        1,
        "the two watches must not open competing consumers"
    );
    // One SQS message (two records) → deleted exactly once.
    assert!(fixture.wait_for_deletes(1, Duration::from_secs(2)));
    assert_eq!(fixture.deletes(), vec!["rh-shared".to_string()]);
}

// === Adopter: a `since` watch coalesces (initial Lapsed then live), opening no
// dedicated consumer ===

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn since_watch_coalesces_initial_lapsed_then_live_no_dedicated_consumer() {
    let fixture = GatedSqsFixture::new(vec![support::SqsMessageSpec::new(
        "m-since",
        "rh-since",
        support::notification_body(&["photos/live.jpg"]),
    )]);
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = watch(
        &backend,
        "photos/",
        WatchDirectoryOptions {
            recursive: true,
            since: Some(WatchDirectoryCursor(vec![9, 9, 9])),
            ..WatchDirectoryOptions::default()
        },
        Some(cancel.clone()),
    )
    .await
    .expect("since watch should start");

    // The prepended Lapsed arrives before the gate opens (no history to replay).
    let (stream, first) = next_item(stream).await;
    assert_lapsed(&first.expect("stream item").expect("initial lapsed"));

    assert!(fixture.wait_for_receivers(1, Duration::from_secs(5)));
    fixture.open_gate();

    let collected = collect(stream, &cancel, 1).await;
    assert!(collected.terminal.is_none());
    assert_eq!(
        collected
            .events
            .iter()
            .map(object_address)
            .collect::<Vec<_>>(),
        vec!["s3://bkt/photos/live.jpg".to_string()]
    );
    assert_eq!(
        fixture.max_concurrent_receives(),
        1,
        "a since watch must coalesce, not open a dedicated consumer"
    );
}
