// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process Azure Blob Change Feed traversal tests.

mod support;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendId, ChangeKind, ConfigValue, ConnectionRequest,
    ErrorCode, ResolvedTarget, SecretBundle, WatchDirectoryCursor, WatchDirectoryOptions, address,
};

const SEGMENT: &str = "idx/segments/2026/05/12/1000/meta.json";
const CHUNK_DIR: &str = "$blobchangefeed/log/00/2026/05/12/1000/";
const CHUNK_PREFIX: &str = "log/00/2026/05/12/1000/";
const CHUNK_FILE: &str = "log/00/2026/05/12/1000/00000.avro";
const SYNC: [u8; 16] = *b"0123456789abcdef";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segments_manifest_chunk_and_avro_yield_object_event() {
    let server = TestServer::spawn(change_feed_handler(change_feed_avro_chunk(), None));
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    let (stream, item) = next_item(stream).await;
    drop(stream);

    let event = item
        .expect("stream should yield")
        .expect("event should succeed");
    let BackendChangeEvent::Object {
        address,
        kind,
        etag,
        version,
        size,
        mtime,
        cursor,
        ..
    } = event
    else {
        panic!("expected object event");
    };
    assert_eq!(address.as_str(), "azure://acct123/assets/dir/blob.txt");
    assert_eq!(kind, ChangeKind::Created);
    assert_eq!(etag.as_deref(), Some("0x8DB"));
    // The Avro fixture has no `blobVersion` field, so `version` falls
    // back to the etag.
    assert_eq!(version.as_deref(), Some("0x8DB"));
    // The Avro fixture sets `contentLength` to 1024 (see
    // `put_change_feed_data`).
    assert_eq!(size, Some(1024));
    // `mtime` is the parsed `eventTime`.
    assert!(mtime.is_some());
    let cursor = String::from_utf8(cursor.0).expect("cursor is JSON");
    assert!(cursor.contains("\"chunk_file\":\"log/00/2026/05/12/1000/00000.avro\""));
    assert!(cursor.contains("\"offset\":0"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn since_cursor_emits_initial_lapsed() {
    let server = TestServer::spawn(change_feed_handler(change_feed_avro_chunk(), None));
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            since: Some(WatchDirectoryCursor(b"resume-from-host".to_vec())),
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    let (stream, item) = next_item(stream).await;
    drop(stream);

    assert!(matches!(
        item.expect("stream should yield")
            .expect("event should succeed"),
        BackendChangeEvent::Lapsed { .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_terminal_errors_surface_from_segments_read() {
    for (status, expected) in [
        (401, ErrorCode::AuthRequired),
        (403, ErrorCode::PermissionDenied),
    ] {
        let server = TestServer::spawn(move |_| {
            HttpResponse::new(
                status,
                "text/plain",
                format!("terminal {status}").into_bytes(),
            )
        });
        let stream = open_watch(
            server.endpoint(),
            WatchDirectoryOptions {
                recursive: true,
                ..WatchDirectoryOptions::default()
            },
        )
        .await;

        let (stream, item) = next_item(stream).await;
        drop(stream);

        let err = item
            .expect("stream should yield terminal error")
            .expect_err("terminal status should surface as error");
        assert_eq!(err.code(), expected);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_5xx_emits_lapsed_then_recovers() {
    let failed_once = Arc::new(AtomicBool::new(false));
    let server = TestServer::spawn(change_feed_handler(
        change_feed_avro_chunk(),
        Some(failed_once),
    ));
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    let (stream, first) = next_item(stream).await;
    assert!(matches!(
        first
            .expect("stream should yield")
            .expect("event should succeed"),
        BackendChangeEvent::Lapsed { .. }
    ));

    let (stream, second) = next_item(stream).await;
    drop(stream);
    assert!(matches!(
        second
            .expect("stream should yield after retry")
            .expect("retry should recover"),
        BackendChangeEvent::Object {
            kind: ChangeKind::Created,
            ..
        }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_stream_cancels_held_change_feed_request() {
    let server = HeldServer::spawn();
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    server.wait_until_request_is_held();
    drop(stream);

    assert!(
        server.wait_until_client_closed(),
        "dropping the watch stream should close the held request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_stream_cancels_held_chunk_listing_request() {
    let server = RouteHeldServer::spawn(
        |target| {
            target.starts_with("/$blobchangefeed?")
                && query_param(target, "prefix").as_deref() == Some(CHUNK_PREFIX)
        },
        change_feed_handler(change_feed_avro_chunk(), None),
    );
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    server.wait_until_request_is_held();
    drop(stream);

    assert!(
        server.wait_until_client_closed(),
        "dropping the watch stream should close the held chunk listing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_stream_cancels_held_chunk_get_request() {
    let server = RouteHeldServer::spawn(
        |target| target == format!("/$blobchangefeed/{CHUNK_FILE}"),
        change_feed_handler(change_feed_avro_chunk(), None),
    );
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    server.wait_until_request_is_held();
    drop(stream);

    assert!(
        server.wait_until_client_closed(),
        "dropping the watch stream should close the held chunk read"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_record_chunk_cursors_advance_by_record_offset() {
    let server = TestServer::spawn(change_feed_handler(
        change_feed_avro_chunk_with_keys(&["dir/first.txt", "dir/second.txt"]),
        None,
    ));
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    let (stream, first) = next_item(stream).await;
    let first = first.expect("first item").expect("first event");
    let BackendChangeEvent::Object {
        address, cursor, ..
    } = first
    else {
        panic!("expected first object event");
    };
    assert_eq!(address.as_str(), "azure://acct123/assets/dir/first.txt");
    assert!(
        String::from_utf8(cursor.0)
            .unwrap()
            .contains("\"offset\":0")
    );

    let (stream, second) = next_item(stream).await;
    drop(stream);
    let second = second.expect("second item").expect("second event");
    let BackendChangeEvent::Object {
        address, cursor, ..
    } = second
    else {
        panic!("expected second object event");
    };
    assert_eq!(address.as_str(), "azure://acct123/assets/dir/second.txt");
    assert!(
        String::from_utf8(cursor.0)
            .unwrap()
            .contains("\"offset\":1")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_nested_avro_field_emits_lapsed() {
    let server = TestServer::spawn(change_feed_handler(
        change_feed_avro_chunk_with_unknown_nested_record(),
        None,
    ));
    let stream = open_watch(
        server.endpoint(),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    let (stream, item) = next_item(stream).await;
    drop(stream);

    let event = item
        .expect("stream should yield")
        .expect("decode failure should become a lapsed event");
    assert!(matches!(event, BackendChangeEvent::Lapsed { .. }));
}

async fn open_watch(endpoint: &str, opts: WatchDirectoryOptions) -> BackendChangeStream {
    open_watch_from(connection_request(endpoint), opts).await
}

async fn open_watch_from(
    request: ConnectionRequest,
    opts: WatchDirectoryOptions,
) -> BackendChangeStream {
    let config = ovstorage_plugin_azure::__test_only_parse_config(&request.config)
        .expect("parse Azure config");
    let backend = ovstorage_plugin_azure::__test_only_with_credentials(config, request.credentials)
        .expect("build Azure backend");
    let target = ResolvedTarget {
        backend_id: BackendId("azure:test".into()),
        resolved_address: address::parse("azure://acct123/assets/dir/").unwrap(),
    };
    backend
        .watch_directory(target, opts, None)
        .await
        .expect("watch_directory should start")
}

async fn next_item(
    stream: BackendChangeStream,
) -> (
    BackendChangeStream,
    Option<ovstorage_plugin::Result<BackendChangeEvent>>,
) {
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let mut stream = stream;
            let item = stream.next();
            (stream, item)
        }),
    )
    .await
    .expect("change stream timed out")
    .expect("blocking task should complete")
}

fn connection_request(endpoint: &str) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String("acct123".into()));
    config.insert("container".into(), ConfigValue::String("assets".into()));
    config.insert("change_feed_enabled".into(), ConfigValue::Bool(true));
    config.insert(
        "change_feed_segment_lag_seconds".into(),
        ConfigValue::Int(0),
    );
    config.insert(
        "change_feed_poll_interval_seconds".into(),
        ConfigValue::Int(1),
    );
    config.insert(
        "__test_change_feed_endpoint".into(),
        ConfigValue::String(endpoint.to_string()),
    );
    ConnectionRequest {
        backend_kind: "azure".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    }
}

/// The change feed lives in the blob tier's `$blobchangefeed` container, so a
/// path-style `blob_endpoint` prefixes its requests AND the resource they are
/// signed against.
///
/// Nothing else covers that wire-through. The other tests here drive the
/// unprefixed `__test_change_feed_endpoint` hook with an ANONYMOUS bundle, so
/// they never sign at all, and the config tests stop at
/// `change_feed_canonical_prefix()` — reverting either interpolation in
/// `subscription.rs` would leave the whole suite green while producing Shared
/// Key 403s against a path-style endpoint.
const CHANGE_FEED_PREFIX: &str = "/devstoreaccount1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_feed_requests_carry_the_endpoint_prefix_and_sign_it() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server = TestServer::spawn(prefixed_change_feed_handler(
        change_feed_avro_chunk(),
        Arc::clone(&seen),
    ));
    // A `blob_endpoint`, NOT the change-feed hook: the change feed follows
    // the blob tier, so this pins that precedence as well as the prefix.
    let stream = open_watch_from(
        signed_prefixed_connection_request(server.endpoint()),
        WatchDirectoryOptions {
            recursive: true,
            ..WatchDirectoryOptions::default()
        },
    )
    .await;

    let (stream, item) = next_item(stream).await;
    drop(stream);
    // The fixture answers 403 on a signature that does not cover the URI it
    // saw, and the traversal surfaces that as an error — so reaching an event
    // at all means every request on the way was signed WITH the prefix.
    item.expect("stream should yield")
        .expect("a prefixed change-feed traversal must be signed correctly");

    let seen = seen.lock().expect("recorded targets").clone();
    assert!(
        !seen.is_empty(),
        "the traversal made no requests, so this asserts nothing"
    );
    assert!(
        seen.iter()
            .all(|target| target.starts_with(CHANGE_FEED_PREFIX)),
        "every change-feed request must carry the endpoint path prefix; saw {seen:#?}"
    );
    // The two call sites the prefix wiring touches, named individually so a
    // regression at either one is identifiable from the failure.
    assert!(
        seen.iter()
            .any(|t| t.starts_with(&format!("{CHANGE_FEED_PREFIX}/$blobchangefeed?"))),
        "the $blobchangefeed listing must be prefixed; saw {seen:#?}"
    );
    assert!(
        seen.iter()
            .any(|t| t == &format!("{CHANGE_FEED_PREFIX}/$blobchangefeed/{SEGMENT}")),
        "the segment blob read must be prefixed; saw {seen:#?}"
    );
}

/// `connection_request` with Shared Key credentials and a path-style
/// `blob_endpoint`, so the change feed both routes through the prefix and
/// signs it.
fn signed_prefixed_connection_request(endpoint: &str) -> ConnectionRequest {
    let mut request = connection_request(endpoint);
    // The hook would override the blob endpoint for the change feed, which is
    // the precedence this test does NOT want to exercise.
    request.config.remove("__test_change_feed_endpoint");
    request.config.insert(
        "blob_endpoint".into(),
        ConfigValue::String(format!("{endpoint}{CHANGE_FEED_PREFIX}")),
    );
    request.credentials = support::shared_key_bundle();
    request
}

/// [`change_feed_handler`] behind a path-style endpoint prefix, verifying the
/// Shared Key signature from the wire the way `azurite_endpoint.rs` does and
/// answering 403 on a mismatch.
fn prefixed_change_feed_handler(
    avro: Vec<u8>,
    seen: Arc<Mutex<Vec<String>>>,
) -> impl Fn(String) -> HttpResponse + Send + Sync + 'static {
    let inner = change_feed_handler(avro, None);
    // The account the connection is configured with, which is what the
    // canonicalized resource is keyed on — deliberately NOT the same string
    // as the endpoint prefix, so confusing the two fails.
    let signer = support::SharedKeySigner::new("acct123");
    move |request| {
        let target = request_target(&request).to_string();
        seen.lock().expect("recorded targets").push(target.clone());
        if let verdict @ (support::SharedKeyVerdict::Mismatch { .. }
        | support::SharedKeyVerdict::Absent) = support::verify_shared_key(&request, &signer)
        {
            return HttpResponse::new(403, "text/plain", format!("{verdict:?}").into_bytes());
        }
        // Delegate to the unprefixed handler with the prefix removed, so the
        // canned bodies stay in one place.
        let Some(stripped) = target.strip_prefix(CHANGE_FEED_PREFIX) else {
            return HttpResponse::new(404, "text/plain", b"missing endpoint prefix".to_vec());
        };
        inner(request.replacen(&format!(" {target} "), &format!(" {stripped} "), 1))
    }
}

fn change_feed_handler(
    avro: Vec<u8>,
    fail_segments_once: Option<Arc<AtomicBool>>,
) -> impl Fn(String) -> HttpResponse + Send + Sync + 'static {
    move |request| {
        let target = request_target(&request);
        if target == "/$blobchangefeed/meta/Segments.json" {
            if fail_segments_once
                .as_ref()
                .is_some_and(|failed| !failed.swap(true, Ordering::SeqCst))
            {
                return HttpResponse::new(500, "text/plain", b"server busy".to_vec());
            }
            return HttpResponse::new(
                200,
                "application/json",
                br#"{"lastConsumable":"2026-05-12T11:00:00Z"}"#.to_vec(),
            );
        }
        if target.starts_with("/$blobchangefeed?") {
            return match query_param(target, "prefix").as_deref() {
                Some("idx/segments/2026/05/12/10") => xml_response(&[SEGMENT]),
                Some("idx/segments/2026/05/12/11") => xml_response(&[]),
                Some(CHUNK_PREFIX) => xml_response(&[CHUNK_FILE]),
                _ => xml_response(&[]),
            };
        }
        if target == format!("/$blobchangefeed/{SEGMENT}") {
            return HttpResponse::new(
                200,
                "application/json",
                format!(r#"{{"chunkFilePaths":["{CHUNK_DIR}"]}}"#).into_bytes(),
            );
        }
        if target == format!("/$blobchangefeed/{CHUNK_FILE}") {
            return HttpResponse::new(200, "application/octet-stream", avro.clone());
        }
        HttpResponse::new(404, "text/plain", b"not found".to_vec())
    }
}

fn request_target(request: &str) -> &str {
    request.split_whitespace().nth(1).unwrap_or_default()
}

fn query_param(target: &str, name: &str) -> Option<String> {
    let (_, query) = target.split_once('?')?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        if key == name {
            return urlencoding::decode(value)
                .ok()
                .map(|value| value.into_owned());
        }
    }
    None
}

fn xml_response(names: &[&str]) -> HttpResponse {
    let blobs = names
        .iter()
        .map(|name| format!("<Blob><Name>{name}</Name></Blob>"))
        .collect::<String>();
    HttpResponse::new(
        200,
        "application/xml",
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <EnumerationResults><Blobs>{blobs}</Blobs><NextMarker /></EnumerationResults>"
        )
        .into_bytes(),
    )
}

struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }
}

struct TestServer {
    endpoint: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn spawn(handler: impl Fn(String) -> HttpResponse + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fixture listener");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        let handler = Arc::new(handler);
        let handle = thread::Builder::new()
            .name("ovs-aztest".into())
            .spawn(move || {
                while !stop_for_thread.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let request = read_request(&mut stream);
                            let response = handler(request);
                            write_response(&mut stream, response);
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("spawn fixture thread");
        Self {
            endpoint,
            stop,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct HeldServer {
    endpoint: String,
    request_rx: mpsc::Receiver<()>,
    closed_rx: mpsc::Receiver<bool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl HeldServer {
    fn spawn() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind held listener");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (request_tx, request_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let handle = thread::Builder::new()
            .name("ovs-azhold".into())
            .spawn(move || {
                let Ok((mut stream, _)) = listener.accept() else {
                    let _ = closed_tx.send(false);
                    return;
                };
                let _ = read_request(&mut stream);
                let _ = request_tx.send(());
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set held stream timeout");
                let mut one = [0_u8; 1];
                let closed = matches!(stream.read(&mut one), Ok(0));
                let _ = closed_tx.send(closed);
            })
            .expect("spawn held fixture thread");
        Self {
            endpoint,
            request_rx,
            closed_rx,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn wait_until_request_is_held(&self) {
        self.request_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("held request should reach fixture");
    }

    fn wait_until_client_closed(&self) -> bool {
        self.closed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("fixture should report client close")
    }
}

impl Drop for HeldServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct RouteHeldServer {
    endpoint: String,
    request_rx: mpsc::Receiver<()>,
    closed_rx: mpsc::Receiver<bool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl RouteHeldServer {
    fn spawn(
        hold: impl Fn(&str) -> bool + Send + Sync + 'static,
        handler: impl Fn(String) -> HttpResponse + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind route-held listener");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (request_tx, request_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let hold = Arc::new(hold);
        let handler = Arc::new(handler);
        let handle = thread::Builder::new()
            .name("ovs-azroute".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else {
                        break;
                    };
                    let request = read_request(&mut stream);
                    let target = request_target(&request);
                    if hold(target) {
                        let _ = request_tx.send(());
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .expect("set held stream timeout");
                        let mut one = [0_u8; 1];
                        let closed = matches!(stream.read(&mut one), Ok(0));
                        let _ = closed_tx.send(closed);
                        break;
                    }
                    let response = handler(request);
                    write_response(&mut stream, response);
                }
            })
            .expect("spawn route-held fixture thread");
        Self {
            endpoint,
            request_rx,
            closed_rx,
            handle: Some(handle),
        }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn wait_until_request_is_held(&self) {
        self.request_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("held request should reach fixture");
    }

    fn wait_until_client_closed(&self) -> bool {
        self.closed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("fixture should report client close")
    }
}

impl Drop for RouteHeldServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                request.extend_from_slice(&buf[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn write_response(stream: &mut std::net::TcpStream, response: HttpResponse) {
    let reason = match response.status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Fixture",
    };
    let header = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

fn change_feed_avro_chunk() -> Vec<u8> {
    change_feed_avro_chunk_with_keys(&["dir/blob.txt"])
}

fn change_feed_avro_chunk_with_keys(keys: &[&str]) -> Vec<u8> {
    let mut records = Vec::new();
    for key in keys {
        records.extend(change_feed_record(key));
    }

    avro_chunk(avro_schema(), records, keys.len())
}

fn change_feed_avro_chunk_with_unknown_nested_record() -> Vec<u8> {
    let mut record = Vec::new();
    put_string(&mut record, "BlobCreated");
    put_string(
        &mut record,
        "/blobServices/default/containers/assets/blobs/dir/blob.txt",
    );
    put_string(&mut record, "2026-05-12T10:30:00Z");
    put_string(&mut record, "future-label");
    put_long(&mut record, 42);
    put_change_feed_data(&mut record, "dir/blob.txt");

    let schema = r#"{
        "type":"record",
        "name":"ChangeFeedEvent",
        "fields":[
            {"name":"eventType","type":"string"},
            {"name":"subject","type":"string"},
            {"name":"eventTime","type":"string"},
            {"name":"future","type":{
                "type":"record",
                "name":"Future",
                "fields":[
                    {"name":"child","type":{
                        "type":"record",
                        "name":"Child",
                        "fields":[{"name":"label","type":"string"}]
                    }},
                    {"name":"count","type":"long"}
                ]
            }},
            {"name":"data","type":{
                "type":"record",
                "name":"Data",
                "fields":[
                    {"name":"url","type":["null","string"]},
                    {"name":"eTag","type":["null","string"]},
                    {"name":"metadata","type":["null",{"type":"map","values":"string"}]}
                ]
            }}
        ]
    }"#;

    avro_chunk(schema.into(), record, 1)
}

fn avro_chunk(schema: String, records: Vec<u8>, record_count: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"Obj\x01");
    put_long(&mut out, 2);
    put_string(&mut out, "avro.schema");
    put_bytes(&mut out, schema.as_bytes());
    put_string(&mut out, "avro.codec");
    put_bytes(&mut out, b"null");
    put_long(&mut out, 0);
    out.extend_from_slice(&SYNC);
    put_long(&mut out, record_count as i64);
    put_long(&mut out, records.len() as i64);
    out.extend_from_slice(&records);
    out.extend_from_slice(&SYNC);
    out
}

fn change_feed_record(key: &str) -> Vec<u8> {
    let mut record = Vec::new();
    put_string(&mut record, "BlobCreated");
    put_string(
        &mut record,
        &format!("/blobServices/default/containers/assets/blobs/{key}"),
    );
    put_string(&mut record, "2026-05-12T10:30:00Z");
    put_change_feed_data(&mut record, key);
    record
}

fn put_change_feed_data(record: &mut Vec<u8>, key: &str) {
    // url: union branch 1 (string)
    put_long(record, 1);
    put_string(
        record,
        &format!("https://acct123.blob.core.windows.net/assets/{key}"),
    );
    // eTag: union branch 1 (string)
    put_long(record, 1);
    put_string(record, "0x8DB");
    // contentLength: union branch 1 (long) 1024
    put_long(record, 1);
    put_long(record, 1024);
    // metadata: union branch 1 (map), one entry, end-of-blocks
    put_long(record, 1);
    put_long(record, 1);
    put_string(record, "tier");
    put_string(record, "hot");
    put_long(record, 0);
}

fn avro_schema() -> String {
    r#"{
        "type":"record",
        "name":"ChangeFeedEvent",
        "fields":[
            {"name":"eventType","type":"string"},
            {"name":"subject","type":"string"},
            {"name":"eventTime","type":"string"},
            {"name":"data","type":{
                "type":"record",
                "name":"Data",
                "fields":[
                    {"name":"url","type":["null","string"]},
                    {"name":"eTag","type":["null","string"]},
                    {"name":"contentLength","type":["null","long"]},
                    {"name":"metadata","type":["null",{"type":"map","values":"string"}]}
                ]
            }}
        ]
    }"#
    .into()
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_long(out, value.len() as i64);
    out.extend_from_slice(value);
}

fn put_long(out: &mut Vec<u8>, value: i64) {
    let mut encoded = ((value << 1) ^ (value >> 63)) as u64;
    loop {
        let mut byte = (encoded & 0x7f) as u8;
        encoded >>= 7;
        if encoded != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if encoded == 0 {
            break;
        }
    }
}
