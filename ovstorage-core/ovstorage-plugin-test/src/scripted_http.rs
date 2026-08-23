// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scripted single-response HTTP mock server for provider tests.
//!
//! Answers every request with ONE canned response, counts hits, and
//! records raw requests for wire-level assertions. Binds only
//! `127.0.0.1`. This is the shared "dumbest possible cloud endpoint"
//! used by the cloud provider crates' conformance and
//! connection-lifecycle suites — hoisted here so the six per-crate
//! copies cannot drift independently. For route-based scripting with
//! structured captures use [`crate::Responder`] instead.
//!
//! Request framing is Content-Length aware: the reader waits for the
//! full body (no chunked encoding), so captured requests include
//! uploaded bytes and the canned response never races a mid-body
//! client. Manual framing avoids dragging an HTTP server crate into
//! the test plugin.

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// One canned HTTP response replayed for every request the server
/// receives. `Connection: close` and `Content-Length` are always
/// emitted; extra headers (e.g. azure's `x-ms-error-code`) slot in
/// between.
#[derive(Clone, Debug)]
pub struct CannedHttpResponse {
    status_line: String,
    content_type: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl CannedHttpResponse {
    /// Canned response with the given status line (e.g. `"200 OK"`,
    /// `"409 Conflict"`) and body, typed `application/octet-stream`.
    pub fn new(status_line: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            status_line: status_line.into(),
            content_type: "application/octet-stream".into(),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// [`CannedHttpResponse::new`] typed `application/xml` (azure /
    /// s3 wire format).
    pub fn xml(status_line: impl Into<String>, body: impl Into<String>) -> Self {
        Self::new(status_line, body).with_content_type("application/xml")
    }

    /// [`CannedHttpResponse::new`] typed `application/json` (gcs wire
    /// format).
    pub fn json(status_line: impl Into<String>, body: impl Into<String>) -> Self {
        Self::new(status_line, body).with_content_type("application/json")
    }

    /// Override the `Content-Type` header value.
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }

    /// Append an extra response header (e.g. `x-ms-error-code`).
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn render(&self) -> String {
        let mut extra = String::new();
        for (name, value) in &self.headers {
            extra.push_str(&format!("{name}: {value}\r\n"));
        }
        format!(
            "HTTP/1.1 {}\r\nConnection: close\r\n{extra}Content-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
            self.status_line,
            self.content_type,
            self.body.len(),
            self.body,
        )
    }
}

/// Handle to a spawned scripted server: the loopback endpoint, a hit
/// counter, and the raw-request log.
///
/// The accept loop runs for the life of the test process (the six
/// hoisted copies all leaked their accept thread the same way; test
/// binaries are short-lived).
pub struct ScriptedHttpServer {
    endpoint: String,
    hits: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl ScriptedHttpServer {
    /// Bind a loopback ephemeral port and answer every request with
    /// `response`.
    pub fn spawn(response: CannedHttpResponse) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let rendered = response.render();
        let hits_for_thread = hits.clone();
        let requests_for_thread = requests.clone();
        thread::Builder::new()
            .name("ovs-test-scripted-http".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let Some(raw) = read_http_request(&mut stream) else {
                        continue;
                    };
                    hits_for_thread.fetch_add(1, Ordering::SeqCst);
                    requests_for_thread
                        .lock()
                        .expect("requests poisoned")
                        .push(raw);
                    let _ = stream.write_all(rendered.as_bytes());
                    let _ = stream.flush();
                }
            })
            .expect("spawn scripted server");
        Self {
            endpoint,
            hits,
            requests,
        }
    }

    /// Bind a loopback ephemeral port and answer each request with the next
    /// entry of `script`, in order.
    ///
    /// A `None` entry answers by **closing the connection without a
    /// response**, which surfaces to the client as a transport error rather
    /// than a status. That is the only way to exercise a code path whose
    /// failure mode is "the request never completed" — a rollback whose token
    /// refresh or socket dies, say — as distinct from one that returns a
    /// non-2xx.
    ///
    /// Requests beyond the end of `script` are answered with its last entry,
    /// so a script need only cover the prefix under test.
    pub fn spawn_sequence(script: Vec<Option<CannedHttpResponse>>) -> Self {
        assert!(!script.is_empty(), "a script needs at least one entry");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let endpoint = format!("http://{}", listener.local_addr().expect("local addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let rendered: Vec<Option<String>> = script
            .into_iter()
            .map(|entry| entry.map(|response| response.render()))
            .collect();
        let hits_for_thread = hits.clone();
        let requests_for_thread = requests.clone();
        thread::Builder::new()
            .name("ovs-test-scripted-http-seq".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let Some(raw) = read_http_request(&mut stream) else {
                        continue;
                    };
                    let index = hits_for_thread.fetch_add(1, Ordering::SeqCst);
                    requests_for_thread
                        .lock()
                        .expect("requests poisoned")
                        .push(raw);
                    let entry = rendered
                        .get(index)
                        .unwrap_or_else(|| rendered.last().expect("non-empty script"));
                    match entry {
                        Some(response) => {
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                        }
                        // Drop the stream unanswered.
                        None => drop(stream),
                    }
                }
            })
            .expect("spawn scripted server");
        Self {
            endpoint,
            hits,
            requests,
        }
    }

    /// `http://127.0.0.1:<port>` base URL for the connection config.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Number of requests answered so far.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// Snapshot of the raw requests received so far, in order.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests poisoned").clone()
    }
}

/// Whether a raw captured request carries the header `name: value`
/// (header name matched case-insensitively, value after trimming).
pub fn request_has_header(raw: &str, name: &str, value: &str) -> bool {
    let head = raw.split("\r\n\r\n").next().unwrap_or(raw);
    head.lines().skip(1).any(|line| {
        line.split_once(':')
            .is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case(name) && v.trim() == value)
    })
}

// Content-Length-aware request read: waits for the header block, then
// for the declared body (no chunked encoding). A read timeout bails
// out with whatever arrived so a misbehaving client can't hang the
// accept loop.
fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut request = Vec::new();
    let mut buf = [0u8; 8192];
    let mut header_end = None;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                request.extend_from_slice(&buf[..len]);
                if header_end.is_none() {
                    header_end = request
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n")
                        .map(|pos| pos + 4);
                }
                if let Some(end) = header_end {
                    let headers = String::from_utf8_lossy(&request[..end]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= end + content_length {
                        break;
                    }
                }
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
            Err(_) => return None,
        }
    }
    (!request.is_empty()).then(|| String::from_utf8_lossy(&request).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(endpoint: &str, path: &str, extra_headers: &str) -> String {
        let host = endpoint.strip_prefix("http://").unwrap();
        let mut stream = TcpStream::connect(host).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nhost: {host}\r\n{extra_headers}connection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        String::from_utf8_lossy(&raw).to_string()
    }

    #[test]
    fn serves_the_canned_response_with_extra_headers() {
        let server = ScriptedHttpServer::spawn(
            CannedHttpResponse::xml("409 Conflict", "<Error/>")
                .with_header("x-ms-error-code", "BlobAlreadyExists"),
        );
        let response = get(server.endpoint(), "/a", "");
        assert!(
            response.starts_with("HTTP/1.1 409 Conflict\r\n"),
            "{response}"
        );
        assert!(response.contains("x-ms-error-code: BlobAlreadyExists\r\n"));
        assert!(response.contains("Content-Type: application/xml\r\n"));
        assert!(response.ends_with("<Error/>"));
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn counts_hits_and_records_raw_requests_in_order() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::json("200 OK", "{}"));
        get(server.endpoint(), "/first?delimiter=%2F", "");
        get(server.endpoint(), "/second", "x-probe: yes\r\n");
        assert_eq!(server.hits(), 2);
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("delimiter="));
        assert!(request_has_header(&requests[1], "X-Probe", "yes"));
        assert!(!request_has_header(&requests[0], "X-Probe", "yes"));
    }

    #[test]
    fn waits_for_the_content_length_body() {
        let server = ScriptedHttpServer::spawn(CannedHttpResponse::new("200 OK", ""));
        let host = server
            .endpoint()
            .strip_prefix("http://")
            .unwrap()
            .to_string();
        let mut stream = TcpStream::connect(&host).unwrap();
        write!(
            stream,
            "PUT /obj HTTP/1.1\r\nhost: {host}\r\ncontent-length: 5\r\n\r\n"
        )
        .unwrap();
        stream.flush().unwrap();
        // Body arrives in a second write; the capture must include it.
        std::thread::sleep(Duration::from_millis(50));
        stream.write_all(b"hello").unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].ends_with("hello"), "{}", requests[0]);
    }
}
