// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared, gated SQS test fixture for cross-prefix watch conformance.
//!
//! Lives under `tests/support/` (a subdirectory `mod.rs`) so cargo does
//! NOT compile it as its own integration-test target; test files opt in
//! with `mod support;`.
//!
//! Unlike the private `SqsFixture` in `sqs_watch_subscription.rs` (whose
//! `Hold` only waits for the client to close), this fixture models the SQS
//! competing-consumer transport precisely: every `ReceiveMessage` blocks
//! until the driver **opens the gate**, then exactly ONE physical receiver
//! wins the single queued batch; every other receiver (and every re-poll)
//! long-holds until shutdown. That lets a driver open all watches first,
//! then release one batch to one consumer — reproducing cannibalization
//! when multiple watches share the queue.

// Each integration-test binary that opts in with `mod support;` uses a
// different subset of this shared fixture.
#![allow(dead_code)]

/// A loopback fake MinIO that really verifies presigned SigV4 signatures, for
/// the redirect-replay conformance suite.
pub mod minio_sigv4;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// One SQS message the gate can hand to the winning receiver.
#[derive(Clone)]
pub struct SqsMessageSpec {
    pub message_id: String,
    pub receipt_handle: String,
    pub body: String,
}

impl SqsMessageSpec {
    pub fn new(message_id: &str, receipt_handle: &str, body: String) -> Self {
        Self {
            message_id: message_id.into(),
            receipt_handle: receipt_handle.into(),
            body,
        }
    }
}

struct GateState {
    /// Number of `ReceiveMessage` handlers that have begun waiting on the
    /// gate — i.e. physical receivers currently parked in a long-poll.
    receives_started: usize,
    /// `ReceiveMessage` handlers currently in flight (a long-poll that has
    /// started but not yet returned).
    receives_in_flight: usize,
    /// High-water mark of `receives_in_flight`: the maximum number of
    /// concurrent physical SQS consumers. A correctly self-coalescing backend
    /// keeps exactly ONE consumer per connection, so this stays 1; competing
    /// per-`watch_directory` consumers push it above 1 (cannibalization).
    max_concurrent_receives: usize,
    /// Set by the driver once every watch is open; wakes all parked
    /// receivers so exactly one can claim `batch`.
    gate_open: bool,
    /// The single batch delivered to whichever receiver claims it first;
    /// `None` once claimed (or if never seeded).
    batch: Option<Vec<SqsMessageSpec>>,
    /// Receipt handles the backend asked to delete (ack).
    deletes: Vec<String>,
    shutdown: bool,
}

/// A gated, competing-consumer SQS mock.
pub struct GatedSqsFixture {
    queue_url: String,
    shared: Arc<(Mutex<GateState>, Condvar)>,
    listener: Option<thread::JoinHandle<()>>,
}

impl GatedSqsFixture {
    /// Spawn the mock with a single batch queued behind a closed gate.
    pub fn new(batch: Vec<SqsMessageSpec>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        listener.set_nonblocking(true).expect("set nonblocking");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new((
            Mutex::new(GateState {
                receives_started: 0,
                receives_in_flight: 0,
                max_concurrent_receives: 0,
                gate_open: false,
                batch: Some(batch),
                deletes: Vec::new(),
                shutdown: false,
            }),
            Condvar::new(),
        ));
        let shared_for_thread = shared.clone();
        let handle = thread::Builder::new()
            .name("ovs-test-gated-sqs".into())
            .spawn(move || accept_loop(listener, shared_for_thread))
            .expect("failed to spawn thread");
        Self {
            queue_url: format!("http://{addr}/123456789012/watch"),
            shared,
            listener: Some(handle),
        }
    }

    pub fn queue_url(&self) -> &str {
        &self.queue_url
    }

    /// Block until at least `n` physical receivers are parked on the gate,
    /// bounded by `timeout`. Returns `true` on success, `false` on timeout
    /// (so callers can fail rather than hang).
    pub fn wait_for_receivers(&self, n: usize, timeout: Duration) -> bool {
        self.wait_until(timeout, |state| state.receives_started >= n)
    }

    /// The high-water mark of concurrent physical `ReceiveMessage` long-polls.
    /// One for a correctly self-coalescing connection; higher when watches
    /// cannibalize by each opening their own consumer.
    pub fn max_concurrent_receives(&self) -> usize {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap().max_concurrent_receives
    }

    /// Open the gate, releasing the queued batch to exactly one receiver.
    pub fn open_gate(&self) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().unwrap();
        state.gate_open = true;
        cvar.notify_all();
    }

    /// The receipt handles the backend has asked to delete (ack), in order.
    pub fn deletes(&self) -> Vec<String> {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap().deletes.clone()
    }

    /// Block until at least `n` deletes have been recorded, bounded by
    /// `timeout`. Returns `true` on success, `false` on timeout.
    pub fn wait_for_deletes(&self, n: usize, timeout: Duration) -> bool {
        self.wait_until(timeout, |state| state.deletes.len() >= n)
    }

    fn wait_until(&self, timeout: Duration, mut predicate: impl FnMut(&GateState) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().unwrap();
        while !predicate(&state) {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (next, _) = cvar.wait_timeout(state, deadline - now).unwrap();
            state = next;
        }
        true
    }
}

impl Drop for GatedSqsFixture {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.shared;
        {
            let mut state = lock.lock().unwrap();
            state.shutdown = true;
            cvar.notify_all();
        }
        if let Some(handle) = self.listener.take() {
            handle
                .join()
                .expect("gated SQS fixture listener should exit");
        }
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<(Mutex<GateState>, Condvar)>) {
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
                    .name("ovs-gated-sqs-conn".into())
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

fn handle_connection(mut stream: TcpStream, shared: Arc<(Mutex<GateState>, Condvar)>) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    if request.target.ends_with("ReceiveMessage") {
        handle_receive(stream, shared);
    } else if request.target.ends_with("DeleteMessageBatch") {
        handle_delete(stream, shared, &request.body);
    } else {
        write_response(&mut stream, 400, "Bad Request", "{}");
    }
}

fn handle_receive(mut stream: TcpStream, shared: Arc<(Mutex<GateState>, Condvar)>) {
    let claimed = {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        state.receives_started += 1;
        state.receives_in_flight += 1;
        state.max_concurrent_receives = state.max_concurrent_receives.max(state.receives_in_flight);
        cvar.notify_all();
        // Park until the driver opens the gate (or we are torn down).
        while !state.gate_open && !state.shutdown {
            state = cvar.wait(state).unwrap();
        }
        if state.shutdown {
            None
        } else {
            // Exactly one receiver claims the batch; everyone else holds.
            state.batch.take()
        }
    };
    match claimed {
        Some(messages) => {
            // Decrement BEFORE writing the response. Otherwise the winning
            // consumer's client can receive it and start its next
            // `ReceiveMessage` (re-incrementing `receives_in_flight`) before this
            // decrement runs, transiently pushing the high-water mark to 2 for a
            // single sequential consumer — and falsely tripping a `== 1` gate.
            // Decrementing first keeps a sequential re-poll at 1→0→1, peak 1.
            // Held (parked) receivers, by contrast, decrement only after the hold
            // ends, so genuinely concurrent consumers (cannibalization) still
            // read ≥2.
            decrement_in_flight(&shared);
            write_response(&mut stream, 200, "OK", &receive_response(&messages));
        }
        None => {
            wait_for_client_close(&mut stream);
            decrement_in_flight(&shared);
        }
    }
}

fn decrement_in_flight(shared: &Arc<(Mutex<GateState>, Condvar)>) {
    let (lock, cvar) = &**shared;
    let mut state = lock.lock().unwrap();
    state.receives_in_flight = state.receives_in_flight.saturating_sub(1);
    cvar.notify_all();
}

fn handle_delete(mut stream: TcpStream, shared: Arc<(Mutex<GateState>, Condvar)>, body: &[u8]) {
    // A `DeleteMessageBatch` may carry more than one entry (the pump coalesces
    // ready receipts): record every entry's receipt, not just the first.
    let receipts: Vec<String> = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("Entries").and_then(|e| e.as_array()).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| {
            entry
                .get("ReceiptHandle")
                .and_then(|handle| handle.as_str())
                .map(str::to_string)
        })
        .collect();
    {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        for receipt in receipts {
            state.deletes.push(receipt);
        }
        cvar.notify_all();
    }
    write_response(&mut stream, 200, "OK", &delete_success_response());
}

struct HttpRequest {
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

fn delete_success_response() -> String {
    serde_json::json!({ "Successful": [{ "Id": "m1" }], "Failed": [] }).to_string()
}

/// An S3 event-notification message body carrying one `ObjectCreated:Put`
/// record per key (all under bucket `bkt`).
pub fn notification_body(keys: &[&str]) -> String {
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
