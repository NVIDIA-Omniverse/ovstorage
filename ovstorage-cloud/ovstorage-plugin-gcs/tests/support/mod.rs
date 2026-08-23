// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared, gated Pub/Sub test fixture for cross-prefix watch conformance.
//!
//! Lives under `tests/support/` (a subdirectory `mod.rs`) so cargo does
//! NOT compile it as its own integration-test target; test files opt in
//! with `mod support;`.
//!
//! Unlike the private `PubsubFixture` in `pubsub_watch_subscription.rs`
//! (whose `Hold` only waits for the client to close), this fixture models
//! the Pub/Sub competing-consumer pull transport precisely: `GET`
//! subscription config always answers immediately, but every `:pull`
//! blocks until the driver **opens the gate**, then exactly ONE physical
//! puller wins the single queued batch; every other puller (and every
//! re-poll) long-holds until shutdown. That lets a driver open all watches
//! first, then release one batch to one consumer — reproducing
//! cannibalization when multiple watches share the subscription.

// Each integration-test binary that opts in with `mod support;` uses a
// different subset of this shared fixture.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// One Pub/Sub message the gate can hand to the winning puller: an
/// `ackId` and the GCS `objectId` (bucket-relative key) the storage
/// notification carries.
#[derive(Clone)]
pub struct PubsubMessageSpec {
    pub ack_id: String,
    pub object_id: String,
}

impl PubsubMessageSpec {
    pub fn new(ack_id: &str, object_id: &str) -> Self {
        Self {
            ack_id: ack_id.into(),
            object_id: object_id.into(),
        }
    }
}

struct GateState {
    /// Number of `:pull` handlers that have begun waiting on the gate —
    /// i.e. physical pullers currently parked in a long-poll.
    pulls_started: usize,
    /// `:pull` handlers currently in flight (a long-poll that has started
    /// but not yet returned).
    pulls_in_flight: usize,
    /// High-water mark of `pulls_in_flight`: the maximum number of
    /// concurrent physical Pub/Sub pullers. A correctly self-coalescing
    /// backend keeps exactly ONE puller per connection, so this stays 1;
    /// competing per-`watch_directory` pullers push it above 1
    /// (cannibalization).
    max_concurrent_pulls: usize,
    /// Set by the driver once every watch is open; wakes all parked
    /// pullers so exactly one can claim `batch`.
    gate_open: bool,
    /// The single batch delivered to whichever puller claims it first;
    /// `None` once claimed (or if never seeded).
    batch: Option<Vec<PubsubMessageSpec>>,
    /// `ackId`s the backend asked to acknowledge (ack), in order.
    acks: Vec<String>,
    shutdown: bool,
}

/// A gated, competing-consumer Pub/Sub mock.
pub struct GatedPubsubFixture {
    endpoint: String,
    shared: Arc<(Mutex<GateState>, Condvar)>,
    listener: Option<thread::JoinHandle<()>>,
}

impl GatedPubsubFixture {
    /// Spawn the mock with a single batch queued behind a closed gate.
    pub fn new(batch: Vec<PubsubMessageSpec>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        listener.set_nonblocking(true).expect("set nonblocking");
        let addr = listener.local_addr().unwrap();
        let shared = Arc::new((
            Mutex::new(GateState {
                pulls_started: 0,
                pulls_in_flight: 0,
                max_concurrent_pulls: 0,
                gate_open: false,
                batch: Some(batch),
                acks: Vec::new(),
                shutdown: false,
            }),
            Condvar::new(),
        ));
        let shared_for_thread = shared.clone();
        let handle = thread::Builder::new()
            .name("ovs-test-gated-pubsub".into())
            .spawn(move || accept_loop(listener, shared_for_thread))
            .expect("failed to spawn thread");
        Self {
            endpoint: format!("http://{addr}"),
            shared,
            listener: Some(handle),
        }
    }

    /// The Pub/Sub endpoint base URL the backend's `pubsub_endpoint`
    /// should point at.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Block until at least `n` physical pullers are parked on the gate,
    /// bounded by `timeout`. Returns `true` on success, `false` on timeout
    /// (so callers can fail rather than hang).
    pub fn wait_for_pullers(&self, n: usize, timeout: Duration) -> bool {
        self.wait_until(timeout, |state| state.pulls_started >= n)
    }

    /// The high-water mark of concurrent physical `:pull` long-polls. One
    /// for a correctly self-coalescing connection; higher when watches
    /// cannibalize by each opening their own puller.
    pub fn max_concurrent_pulls(&self) -> usize {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap().max_concurrent_pulls
    }

    /// Open the gate, releasing the queued batch to exactly one puller.
    pub fn open_gate(&self) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().unwrap();
        state.gate_open = true;
        cvar.notify_all();
    }

    /// The `ackId`s the backend has asked to acknowledge, in order.
    pub fn acks(&self) -> Vec<String> {
        let (lock, _) = &*self.shared;
        lock.lock().unwrap().acks.clone()
    }

    /// Block until at least `n` acks have been recorded, bounded by
    /// `timeout`. Returns `true` on success, `false` on timeout.
    pub fn wait_for_acks(&self, n: usize, timeout: Duration) -> bool {
        self.wait_until(timeout, |state| state.acks.len() >= n)
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

impl Drop for GatedPubsubFixture {
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
                .expect("gated Pub/Sub fixture listener should exit");
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
                    .name("ovs-gated-pubsub-conn".into())
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
    if request.path.ends_with(":pull") {
        handle_pull(stream, shared);
    } else if request.path.ends_with(":acknowledge") {
        handle_ack(stream, shared, &request.body);
    } else {
        // Everything else is the pre-pull `GET` subscription config fetch;
        // it must answer immediately (it is not gated and does not count as
        // a physical puller).
        let mut stream = stream;
        write_json(&mut stream, 200, &subscription_config_body());
    }
}

fn handle_pull(mut stream: TcpStream, shared: Arc<(Mutex<GateState>, Condvar)>) {
    let claimed = {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        state.pulls_started += 1;
        state.pulls_in_flight += 1;
        state.max_concurrent_pulls = state.max_concurrent_pulls.max(state.pulls_in_flight);
        cvar.notify_all();
        // Park until the driver opens the gate (or we are torn down).
        while !state.gate_open && !state.shutdown {
            state = cvar.wait(state).unwrap();
        }
        if state.shutdown {
            None
        } else {
            // Exactly one puller claims the batch; everyone else holds.
            state.batch.take()
        }
    };
    match claimed {
        Some(messages) => {
            // Decrement BEFORE writing the response. Otherwise the winning
            // consumer's client can receive it and start its next `:pull`
            // (re-incrementing `pulls_in_flight`) before this decrement runs,
            // transiently pushing the high-water mark to 2 for a single
            // sequential consumer — and falsely tripping a `== 1` gate.
            // Decrementing first keeps a sequential re-poll at 1→0→1, peak 1.
            // Held (parked) pullers, by contrast, decrement only after the
            // hold ends, so genuinely concurrent consumers (cannibalization)
            // still read >=2.
            decrement_in_flight(&shared);
            write_json(&mut stream, 200, &pull_response_body(&messages));
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
    state.pulls_in_flight = state.pulls_in_flight.saturating_sub(1);
    cvar.notify_all();
}

fn handle_ack(mut stream: TcpStream, shared: Arc<(Mutex<GateState>, Condvar)>, body: &[u8]) {
    let ack_ids = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("ackIds")
                .and_then(|ids| ids.as_array())
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| id.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
        })
        .unwrap_or_default();
    {
        let (lock, cvar) = &*shared;
        let mut state = lock.lock().unwrap();
        state.acks.extend(ack_ids);
        cvar.notify_all();
    }
    write_json(&mut stream, 200, "{}");
}

struct HttpRequest {
    path: String,
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
    let (content_length, path) = {
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
        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_string();
        (content_length, path)
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
        path,
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

fn write_json(stream: &mut TcpStream, status: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn subscription_config_body() -> String {
    serde_json::json!({
        "ackDeadlineSeconds": 10,
        "enableExactlyOnceDelivery": false
    })
    .to_string()
}

fn pull_response_body(messages: &[PubsubMessageSpec]) -> String {
    let received: Vec<serde_json::Value> = messages
        .iter()
        .map(|message| {
            serde_json::json!({
                "ackId": message.ack_id,
                "message": {
                    "messageId": message.ack_id,
                    "attributes": {
                        "bucketId": "assets",
                        "objectId": message.object_id,
                        "objectGeneration": "42",
                        "eventType": "OBJECT_FINALIZE",
                        "eventTime": "2026-05-12T13:45:00Z"
                    }
                }
            })
        })
        .collect();
    serde_json::json!({ "receivedMessages": received }).to_string()
}
