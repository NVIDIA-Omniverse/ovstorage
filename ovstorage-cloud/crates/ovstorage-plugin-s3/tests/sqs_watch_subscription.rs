// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::shim::Backend;
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendId, CancellationToken, ChangeKind, ConfigValue,
    ErrorCode, ResolvedTarget, WatchDirectoryCursor, WatchDirectoryOptions, address,
};
use ovstorage_plugin_s3::{AwsCredentials, S3Backend};

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
    Hold,
}

struct FixtureState {
    receive_plans: VecDeque<ReceivePlan>,
    delete_plans: VecDeque<DeletePlan>,
    deletes: Vec<String>,
    receive_count: usize,
    held_receives_started: usize,
    held_receives_closed: usize,
    held_deletes_started: usize,
    held_deletes_closed: usize,
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
                deletes: Vec::new(),
                receive_count: 0,
                held_receives_started: 0,
                held_receives_closed: 0,
                held_deletes_started: 0,
                held_deletes_closed: 0,
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

    fn assert_no_deletes_for(&self, duration: Duration) {
        let (lock, cvar) = &*self.shared;
        let state = lock.lock().unwrap();
        let (state, _) = cvar.wait_timeout(state, duration).unwrap();
        assert!(
            state.deletes.is_empty(),
            "unexpected deletes: {:?}",
            state.deletes
        );
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

    fn wait_for_held_delete_started(&self) {
        self.wait_until(Duration::from_secs(2), |state| {
            state.held_deletes_started > 0
        });
    }

    fn wait_for_held_delete_closed(&self) {
        self.wait_until(Duration::from_secs(2), |state| {
            state.held_deletes_closed > 0
        });
    }

    fn push_receive_plans(&self, plans: Vec<ReceivePlan>) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().unwrap();
        state.receive_plans.extend(plans);
        cvar.notify_all();
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
    let body = String::from_utf8_lossy(&request.body);
    let params: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    match params.get("Action").map(String::as_str) {
        Some("ReceiveMessage") => handle_receive(stream, shared),
        Some("DeleteMessageBatch") => handle_delete(stream, shared, &params),
        _ => write_response(&mut stream, 400, "Bad Request", ""),
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

fn handle_delete(
    mut stream: TcpStream,
    shared: Arc<(Mutex<FixtureState>, Condvar)>,
    params: &HashMap<String, String>,
) {
    let receipt = params
        .get("DeleteMessageBatchRequestEntry.1.ReceiptHandle")
        .cloned()
        .unwrap_or_default();
    let plan = {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        state.deletes.push(receipt);
        let plan = state
            .delete_plans
            .pop_front()
            .unwrap_or(DeletePlan::Success);
        cvar.notify_all();
        plan
    };
    match plan {
        DeletePlan::Success => write_response(&mut stream, 200, "OK", &delete_success_response()),
        DeletePlan::AccessDenied => {
            write_response(&mut stream, 200, "OK", &delete_access_denied_response())
        }
        DeletePlan::ReceiptExpired => {
            write_response(&mut stream, 200, "OK", &delete_receipt_expired_response())
        }
        DeletePlan::ReceiptHandleInvalid => write_response(
            &mut stream,
            200,
            "OK",
            &delete_receipt_handle_invalid_response(),
        ),
        DeletePlan::Hold => {
            {
                let (lock, cvar) = &*shared;
                let mut state = lock.lock().unwrap();
                state.held_deletes_started += 1;
                cvar.notify_all();
            }
            wait_for_client_close(&mut stream);
            let (lock, cvar) = &*shared;
            let mut state = lock.lock().unwrap();
            state.held_deletes_closed += 1;
            cvar.notify_all();
        }
    }
}

struct HttpRequest {
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
    let body_start = header_end + 4;
    while bytes.len() < body_start + content_length {
        let len = stream.read(&mut buf).ok()?;
        if len == 0 {
            return None;
        }
        bytes.extend_from_slice(&buf[..len]);
    }
    Some(HttpRequest {
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
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn receive_response(messages: &[SqsMessageSpec]) -> String {
    let messages = messages
        .iter()
        .map(|message| {
            format!(
                "<Message><MessageId>{}</MessageId><ReceiptHandle>{}</ReceiptHandle><Body>{}</Body></Message>",
                xml_escape(&message.message_id),
                xml_escape(&message.receipt_handle),
                xml_escape(&message.body),
            )
        })
        .collect::<String>();
    format!(
        "<ReceiveMessageResponse><ReceiveMessageResult>{messages}</ReceiveMessageResult></ReceiveMessageResponse>"
    )
}

fn delete_success_response() -> String {
    "<DeleteMessageBatchResponse><DeleteMessageBatchResult><DeleteMessageBatchResultEntry><Id>m1</Id></DeleteMessageBatchResultEntry></DeleteMessageBatchResult></DeleteMessageBatchResponse>".into()
}

fn delete_access_denied_response() -> String {
    "<DeleteMessageBatchResponse><DeleteMessageBatchResult><BatchResultErrorEntry><Id>m1</Id><SenderFault>true</SenderFault><Code>AccessDenied</Code><Message>denied</Message></BatchResultErrorEntry></DeleteMessageBatchResult></DeleteMessageBatchResponse>".into()
}

fn delete_receipt_expired_response() -> String {
    "<DeleteMessageBatchResponse><DeleteMessageBatchResult><BatchResultErrorEntry><Id>m1</Id><SenderFault>true</SenderFault><Code>InvalidParameterValue</Code><Message>The receipt handle has expired.</Message></BatchResultErrorEntry></DeleteMessageBatchResult></DeleteMessageBatchResponse>".into()
}

fn delete_receipt_handle_invalid_response() -> String {
    "<DeleteMessageBatchResponse><DeleteMessageBatchResult><BatchResultErrorEntry><Id>m1</Id><SenderFault>false</SenderFault><Code>ReceiptHandleIsInvalid</Code><Message>bad handle</Message></BatchResultErrorEntry></DeleteMessageBatchResult></DeleteMessageBatchResponse>".into()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn backend(queue_url: &str) -> S3Backend {
    backend_with_visibility(queue_url, 5)
}

fn backend_with_visibility(queue_url: &str, visibility_timeout: i64) -> S3Backend {
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

fn notification_body(key: &str) -> String {
    serde_json::json!({
        "Records": [{
            "eventTime": "2026-05-12T10:11:12Z",
            "eventName": "ObjectCreated:Put",
            "s3": {
                "bucket": {"name": "bkt"},
                "object": {"key": key, "eTag": "etag-1", "size": 7}
            }
        }]
    })
    .to_string()
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
            // `version` propagates from `s3.object.versionId`; the
            // shared fixture omits it, so the wire value is None.
            assert!(version.is_none());
            // `size` propagates from `s3.object.size`; the shared
            // fixture sets it to 7.
            assert_eq!(size, Some(7));
            // S3 notifications carry `eventTime` but no separate
            // object-level `lastModified`.
            assert!(mtime.is_none());
            assert!(at <= SystemTime::now());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

fn assert_lapsed(event: BackendChangeEvent) {
    match event {
        BackendChangeEvent::Lapsed { since, cursor } => {
            assert!(since.is_none());
            assert!(cursor.0.is_empty());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn since_emits_initial_lapsed_and_drop_closes_long_poll() {
    let fixture = SqsFixture::new(vec![ReceivePlan::Hold], vec![]);
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                since: Some(WatchDirectoryCursor(vec![1, 2, 3])),
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let (stream, item) = next_item(stream).await;
    match item.expect("stream item").expect("initial event") {
        BackendChangeEvent::Lapsed { since, cursor } => {
            assert!(since.is_none());
            assert!(cursor.0.is_empty());
        }
        other => panic!("unexpected event: {other:?}"),
    }

    fixture.wait_for_held_receive_started();
    drop(stream);

    fixture.wait_for_held_receive_closed();
    assert!(cancel.is_cancelled());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ack_is_one_event_delayed_for_two_source_messages() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![
                message("m-1", "rh-1", notification_body("photos/a.jpg")),
                message("m-2", "rh-2", notification_body("photos/b.jpg")),
            ]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Success, DeletePlan::Success],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(first.expect("first item").expect("first event"), "a.jpg");
    fixture.assert_no_deletes_for(Duration::from_millis(75));

    let (stream, second) = next_item(stream).await;
    assert_object(second.expect("second item").expect("second event"), "b.jpg");
    fixture.wait_for_deletes(&["rh-1"]);

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    fixture.wait_for_deletes(&["rh-1", "rh-2"]);
    cancel.cancel();

    assert!(
        next.await
            .expect("stream iterator task should not panic")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ack_fatal_wins_before_already_buffered_later_event() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![
                message("m-1", "rh-1", notification_body("photos/a.jpg")),
                message("m-2", "rh-2", notification_body("photos/b.jpg")),
            ]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::AccessDenied],
    );
    let backend = backend(fixture.queue_url());
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(first.expect("first item").expect("first event"), "a.jpg");

    let (_, item) = next_item(stream).await;
    let err = item
        .expect("fatal item should be emitted before buffered second event")
        .expect_err("AccessDenied delete must surface before b.jpg");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
    fixture.wait_for_deletes(&["rh-1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_unblocks_iterator_waiting_for_delete_ack() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![
                message("m-1", "rh-1", notification_body("photos/a.jpg")),
                message("m-2", "rh-2", notification_body("photos/b.jpg")),
            ]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Hold],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(first.expect("first item").expect("first event"), "a.jpg");

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    fixture.wait_for_held_delete_started();
    cancel.cancel();

    let item = tokio::time::timeout(Duration::from_secs(1), next)
        .await
        .expect("cancel should unblock iterator waiting on DeleteMessageBatch")
        .expect("stream iterator task should not panic");
    assert!(
        item.is_none(),
        "cancelled iterator must not yield already-buffered b.jpg"
    );
    fixture.wait_for_held_delete_closed();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_message_is_deleted_immediately() {
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
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    fixture.wait_for_deletes(&["rh-filtered"]);
    cancel.cancel();
    drop(stream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_unblocks_iterator_waiting_for_filtered_delete() {
    let fixture = SqsFixture::new(
        vec![ReceivePlan::Messages(vec![message(
            "m-filtered",
            "rh-filtered",
            mismatched_notification_body(),
        )])],
        vec![DeletePlan::Hold],
    );
    let backend = backend(fixture.queue_url());
    let cancel = CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    fixture.wait_for_held_delete_started();
    cancel.cancel();

    let item = tokio::time::timeout(Duration::from_secs(1), next)
        .await
        .expect("cancel should unblock iterator waiting on filtered DeleteMessageBatch")
        .expect("stream iterator task should not panic");
    assert!(item.is_none(), "cancelled filtered iterator must end");
    fixture.wait_for_held_delete_closed();
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
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .expect("watch_directory should start");

    let (_, item) = next_item(stream).await;
    let err = item
        .expect("fatal item should be emitted")
        .expect_err("filtered-message delete failure must surface as an error");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
    fixture.wait_for_deletes(&["rh-filtered"]);
}

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
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let (stream, item) = next_item(stream).await;
    assert!(matches!(
        item.expect("stream item").expect("lapsed event"),
        BackendChangeEvent::Lapsed { .. }
    ));

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    fixture.wait_for_deletes(&["rh-malformed"]);
    cancel.cancel();
    assert!(
        next.await
            .expect("stream iterator task should not panic")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_message_batch_access_denied_surfaces_as_permission_denied() {
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
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(
        first.expect("first item").expect("first event"),
        "denied.jpg",
    );

    let (_, item) = next_item(stream).await;
    let err = item
        .expect("fatal item should be emitted")
        .expect_err("AccessDenied delete must surface as an error");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    assert!(err.message().contains("AccessDenied"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn last_delivered_event_is_not_deleted_on_drop_and_can_redeliver() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-redeliver",
                "rh-first",
                notification_body("photos/redeliver.jpg"),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::Success],
    );
    let backend = backend(fixture.queue_url());
    let first = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .expect("first watch should start");

    let (first, item) = next_item(first).await;
    assert_object(
        item.expect("first stream item").expect("first delivery"),
        "redeliver.jpg",
    );
    fixture.wait_for_held_receive_started();
    drop(first);
    fixture.wait_for_held_receive_closed();
    fixture.assert_no_deletes_for(Duration::from_millis(100));

    fixture.push_receive_plans(vec![
        ReceivePlan::Messages(vec![message(
            "m-redeliver",
            "rh-second",
            notification_body("photos/redeliver.jpg"),
        )]),
        ReceivePlan::Hold,
    ]);
    let second = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .expect("second watch should start");
    let (second, item) = next_item(second).await;
    assert_object(
        item.expect("second stream item").expect("redelivery"),
        "redeliver.jpg",
    );
    drop(second);
    fixture.assert_no_deletes_for(Duration::from_millis(100));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_receipt_after_visibility_deadline_does_not_end_stream() {
    let fixture = SqsFixture::new(
        vec![
            ReceivePlan::Messages(vec![message(
                "m-stale",
                "rh-stale",
                notification_body("photos/stale.jpg"),
            )]),
            ReceivePlan::Messages(vec![message(
                "m-next",
                "rh-next",
                notification_body("photos/next.jpg"),
            )]),
            ReceivePlan::Hold,
        ],
        vec![DeletePlan::ReceiptExpired, DeletePlan::Success],
    );
    let backend = backend_with_visibility(fixture.queue_url(), 1);
    let cancel = CancellationToken::new();
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(
        first.expect("first item").expect("first event"),
        "stale.jpg",
    );
    tokio::time::sleep(Duration::from_secs(7)).await;

    let (stream, second) = next_item(stream).await;
    assert_object(
        second.expect("second item").expect("second event"),
        "next.jpg",
    );
    fixture.wait_for_deletes(&["rh-stale"]);

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    fixture.wait_for_deletes(&["rh-stale", "rh-next"]);
    cancel.cancel();
    assert!(
        next.await
            .expect("stream iterator task should not panic")
            .is_none()
    );
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
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            None,
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(
        first.expect("first item").expect("first event"),
        "invalid.jpg",
    );

    let (_, item) = next_item(stream).await;
    let err = item
        .expect("fatal item should be emitted")
        .expect_err("ReceiptHandleIsInvalid delete must surface as an error");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(err.message().contains("ReceiptHandleIsInvalid"));
    fixture.wait_for_deletes(&["rh-invalid"]);
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
    let stream = backend
        .watch_directory(
            target("photos/"),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
            Some(cancel.clone()),
        )
        .await
        .expect("watch_directory should start");

    let (stream, first) = next_item(stream).await;
    assert_object(first.expect("first item").expect("first event"), "good.jpg");
    fixture.assert_no_deletes_for(Duration::from_millis(75));

    let (stream, second) = next_item(stream).await;
    assert_lapsed(second.expect("second item").expect("lapsed event"));

    let next = tokio::task::spawn_blocking(move || {
        let mut stream = stream;
        stream.next()
    });
    fixture.wait_for_deletes(&["rh-mixed"]);
    cancel.cancel();
    assert!(
        next.await
            .expect("stream iterator task should not panic")
            .is_none()
    );
}
