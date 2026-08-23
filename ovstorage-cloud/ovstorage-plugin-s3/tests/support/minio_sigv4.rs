// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A loopback fake MinIO that performs **real** presigned SigV4 verification.
//!
//! The point is not to mock S3 — `ScriptedHttpServer` already does that. It is
//! to recompute the signature the way a strict origin does, so a redirect
//! replayed with a header set that diverges from the signed one is rejected
//! here exactly as MinIO rejects it in production. A fixture that merely
//! answered `200` would be blind to the entire defect class.
//!
//! Faithful to MinIO's `doesPresignedSignatureMatch` / `extractSignedHeaders`:
//!
//! - A request carrying `X-Amz-Signature` in the query takes the presigned
//!   path. A request carrying `Authorization: AWS4-HMAC-SHA256` is an ordinary
//!   SDK call (the `add_connection` verify, multipart init/complete) and gets a
//!   canned XML answer without signature checks — those are the SDK's own
//!   requests, not the thing under test.
//! - Every name in `X-Amz-SignedHeaders` is resolved off the wire, with `host`
//!   taken from the literal `Host:` header. A signed header that is absent is
//!   `ErrUnsignedHeaders` — a 403, not a silent pass.
//! - The canonical query is the raw wire pairs minus `X-Amz-Signature`, sorted;
//!   the canonical request uses the payload hash MinIO would pick
//!   (`X-Amz-Content-Sha256` from query, then header, else `UNSIGNED-PAYLOAD`).
//! - `X-Amz-Expires` is deliberately **not** enforced, so the suite is
//!   time-independent. Expiry is the host's contract, covered elsewhere.
//!
//! HMAC-SHA256 is hand-rolled over the crate's existing `sha2` dependency, so
//! the fixture adds no Cargo entries.

// Each integration-test binary that opts in with `mod support;` uses a
// different subset of this fixture.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Static credentials the fixture accepts. Tests hand the same pair to the S3
/// layer, so a signature mismatch can only come from the request, never from a
/// credential disagreement.
pub const ACCESS_KEY: &str = "minioadmin";
pub const SECRET_KEY: &str = "minioadminsecret";
pub const BUCKET: &str = "bkt";
pub const REGION: &str = "us-east-1";

/// The upload id the fake hands back from `CreateMultipartUpload`.
pub const UPLOAD_ID: &str = "fake-upload-id";

/// One request as the fake received it.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    /// Path portion of the request target, percent-encoded as it arrived.
    pub path: String,
    /// Raw query string (no leading `?`), empty when absent.
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Status the fake answered with.
    pub status: u16,
    /// Whether the request took the presigned-verification path.
    pub presigned: bool,
}

impl RecordedRequest {
    /// The value of `name` as it arrived, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(found, value)| found.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }
}

#[derive(Default)]
struct FakeState {
    requests: Vec<RecordedRequest>,
    /// Stored objects, keyed by S3 object key (the path after the bucket).
    objects: HashMap<String, Vec<u8>>,
    /// Why each 403 fired, in order — so a failing test names the divergent
    /// header instead of just reporting "403".
    rejections: Vec<String>,
}

/// A loopback fake MinIO. Dropping it stops the accept loop and joins the
/// listener thread, so a fixture leaves no thread or bound port behind. Already
/// established connections finish on their own; each is bounded by the read
/// timeout `serve_connection` installs.
pub struct FakeMinio {
    endpoint: String,
    addr: SocketAddr,
    state: Arc<Mutex<FakeState>>,
    shutdown: Arc<AtomicBool>,
    /// `Some` until `Drop` joins it.
    accept: Option<thread::JoinHandle<()>>,
}

impl FakeMinio {
    /// Bind an ephemeral loopback port and start serving.
    pub fn spawn() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let state = Arc::new(Mutex::new(FakeState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let state_for_thread = Arc::clone(&state);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let accept = thread::Builder::new()
            .name("ovs-fake-minio".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    // `Drop` sets the flag and then dials the port to wake this
                    // accept, so the wake-up connection is observed here and
                    // never served.
                    if shutdown_for_thread.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = stream else { return };
                    let state = Arc::clone(&state_for_thread);
                    let spawned = thread::Builder::new()
                        .name("ovs-fake-minio-conn".into())
                        .spawn(move || serve_connection(stream, state));
                    if spawned.is_err() {
                        return;
                    }
                }
            })
            .expect("failed to spawn thread");
        Self {
            endpoint: format!("http://{addr}"),
            addr,
            state,
            shutdown,
            accept: Some(accept),
        }
    }

    /// Base URL to hand the S3 layer as `endpoint` (path-style addressing).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Every request the fake has served, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.lock().unwrap().requests.clone()
    }

    /// Bytes stored under `key` by a successful PUT, if any.
    pub fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().objects.get(key).cloned()
    }

    /// The reason each 403 fired, in order. Empty on a clean run.
    pub fn rejections(&self) -> Vec<String> {
        self.state.lock().unwrap().rejections.clone()
    }
}

impl Drop for FakeMinio {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // The accept loop is parked in a blocking `accept()`; one throwaway
        // connection returns it to the top of the loop, where it sees the flag
        // and exits. If the dial fails the thread is already gone.
        let _ = TcpStream::connect(self.addr);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

struct WireRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    close: bool,
}

fn serve_connection(mut stream: TcpStream, state: Arc<Mutex<FakeState>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let mut pending: Vec<u8> = Vec::new();
    loop {
        let Some(request) = read_request(&mut stream, &mut pending) else {
            return;
        };
        let close = request.close;
        let response = handle_request(request, &state);
        if stream.write_all(&response).is_err() || stream.flush().is_err() {
            return;
        }
        // Honor `Connection: close`. A client that asks for it may block on
        // read-to-EOF rather than on the response framing, so holding the
        // socket open would hang it instead of answering it.
        if close {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
    }
}

/// Read one request off the wire, buffering any pipelined remainder in
/// `pending`. Only `Content-Length` framing is supported — every client that
/// reaches this fixture sends a length-framed body.
fn read_request(stream: &mut TcpStream, pending: &mut Vec<u8>) -> Option<WireRequest> {
    let mut buf = [0u8; 8192];
    let head_end = loop {
        if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&pending[..head_end]).into_owned();
    pending.drain(..head_end);

    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    let length = header_of(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while pending.len() < length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
        }
    }
    let body: Vec<u8> = pending.drain(..length).collect();
    let close = header_of(&headers, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
    Some(WireRequest {
        method,
        target,
        headers,
        body,
        close,
    })
}

fn header_of<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(found, value)| found.eq_ignore_ascii_case(name).then_some(value.as_str()))
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

fn handle_request(request: WireRequest, state: &Arc<Mutex<FakeState>>) -> Vec<u8> {
    let (path, query) = match request.target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (request.target.clone(), String::new()),
    };
    let pairs = query_pairs(&query);
    let presigned = pairs.iter().any(|(name, _)| name == "X-Amz-Signature");

    let (status, body, extra_headers) = if presigned {
        match verify_presigned(&request, &path, &pairs) {
            Ok(()) => dispatch(&request, &path, &pairs, state),
            Err(reason) => {
                state.lock().unwrap().rejections.push(reason.clone());
                (
                    403,
                    error_xml("SignatureDoesNotMatch", &reason).into_bytes(),
                    Vec::new(),
                )
            }
        }
    } else {
        // An ordinary SDK call (SigV4 in the `Authorization` header): the
        // verify probe and the multipart control-plane. Answered canned; the
        // redirect replay is what this fixture exists to check.
        dispatch(&request, &path, &pairs, state)
    };

    state.lock().unwrap().requests.push(RecordedRequest {
        method: request.method,
        path,
        query,
        headers: request.headers,
        body: request.body,
        status,
        presigned,
    });
    http_response(status, &body, &extra_headers)
}

/// Route a request that has already passed verification (or did not need it).
fn dispatch(
    request: &WireRequest,
    path: &str,
    pairs: &[(String, String)],
    state: &Arc<Mutex<FakeState>>,
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let key = object_key(path);
    let has = |name: &str| pairs.iter().any(|(found, _)| found == name);
    let etag = format!(
        "\"{}\"",
        &hex(&Sha256::digest(request.body.as_slice()))[..32]
    );

    match request.method.as_str() {
        "GET" if has("list-type") => (200, list_bucket_xml().into_bytes(), Vec::new()),
        "GET" => match state.lock().unwrap().objects.get(&key).cloned() {
            Some(bytes) => (200, bytes, vec![("ETag".into(), etag)]),
            None => (
                404,
                error_xml("NoSuchKey", "not stored by the fake").into_bytes(),
                Vec::new(),
            ),
        },
        "HEAD" => match state.lock().unwrap().objects.get(&key) {
            Some(bytes) => (
                200,
                Vec::new(),
                vec![
                    ("ETag".into(), etag),
                    ("x-amz-content-length".into(), bytes.len().to_string()),
                ],
            ),
            None => (404, Vec::new(), Vec::new()),
        },
        "POST" if has("uploads") => (200, initiate_multipart_xml(&key).into_bytes(), Vec::new()),
        "POST" if has("uploadId") => (
            200,
            complete_multipart_xml(&key).into_bytes(),
            vec![("ETag".into(), etag)],
        ),
        "DELETE" if has("uploadId") => (204, Vec::new(), Vec::new()),
        "PUT" => {
            // A part upload is not the whole object; only a single PUT stores.
            if !has("uploadId") {
                state
                    .lock()
                    .unwrap()
                    .objects
                    .insert(key, request.body.clone());
            }
            (200, Vec::new(), vec![("ETag".into(), etag)])
        }
        "DELETE" => {
            state.lock().unwrap().objects.remove(&key);
            (204, Vec::new(), Vec::new())
        }
        _ => (200, Vec::new(), Vec::new()),
    }
}

/// The S3 object key: the request path minus the leading `/bucket/`. The layer
/// is configured path-style, so the first segment is always the bucket.
fn object_key(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((_bucket, key)) => key.to_string(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Presigned SigV4 verification
// ---------------------------------------------------------------------------

/// Recompute the presigned signature and compare. `Err(reason)` is a 403; the
/// reason names what diverged, so a failing test is self-diagnosing.
fn verify_presigned(
    request: &WireRequest,
    path: &str,
    pairs: &[(String, String)],
) -> Result<(), String> {
    let query = |name: &str| {
        pairs
            .iter()
            .find_map(|(found, value)| (found == name).then_some(value.as_str()))
    };

    let algorithm = query("X-Amz-Algorithm").ok_or("X-Amz-Algorithm is missing")?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(format!("unsupported signature algorithm '{algorithm}'"));
    }
    let credential = decode(query("X-Amz-Credential").ok_or("X-Amz-Credential is missing")?);
    let amz_date = query("X-Amz-Date")
        .ok_or("X-Amz-Date is missing")?
        .to_string();
    let signed_headers =
        decode(query("X-Amz-SignedHeaders").ok_or("X-Amz-SignedHeaders is missing")?);
    let provided = query("X-Amz-Signature").ok_or("X-Amz-Signature is missing")?;

    // `<access-key>/<date>/<region>/<service>/aws4_request`. The access key may
    // itself contain slashes in principle, so split from the right.
    let segments: Vec<&str> = credential.split('/').collect();
    if segments.len() < 5 {
        return Err(format!("X-Amz-Credential is malformed: '{credential}'"));
    }
    let scope_parts = &segments[segments.len() - 4..];
    let access_key = segments[..segments.len() - 4].join("/");
    if access_key != ACCESS_KEY {
        return Err(format!("unknown access key '{access_key}'"));
    }
    let scope = scope_parts.join("/");
    let (date, region, service) = (scope_parts[0], scope_parts[1], scope_parts[2]);

    // Resolve every signed header off the wire. MinIO answers `ErrUnsignedHeaders`
    // when one is missing rather than signing around it — which is exactly how a
    // replay that drops or renames a signed header surfaces as a 403.
    let mut canonical_headers = String::new();
    let mut names: Vec<&str> = signed_headers
        .split(';')
        .filter(|s| !s.is_empty())
        .collect();
    names.sort_unstable();
    for name in &names {
        let value = if *name == "host" {
            // MinIO reads `r.Host`, i.e. the literal Host header, so the
            // canonical value is the authority including any non-default port.
            header_of(&request.headers, "host")
                .ok_or_else(|| "signed header 'host' is absent from the request".to_string())?
        } else {
            header_of(&request.headers, name).ok_or_else(|| {
                format!("signed header '{name}' is absent from the request (ErrUnsignedHeaders)")
            })?
        };
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(value.trim());
        canonical_headers.push('\n');
    }
    let signed_header_list = names.join(";");

    // Canonical query: the raw wire pairs minus the signature, sorted by
    // encoded name then encoded value. Sorting the pairs (not the joined
    // `k=v` strings) is what keeps prefix-related names in AWS's order.
    let mut canonical_pairs: Vec<(&str, &str)> = pairs
        .iter()
        .filter(|(name, _)| name != "X-Amz-Signature")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    canonical_pairs.sort_unstable();
    let canonical_query = canonical_pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");

    // MinIO's `getContentSha256Cksum` for a presigned request: the query value,
    // then the header, else UNSIGNED-PAYLOAD.
    let payload_hash = query("X-Amz-Content-Sha256")
        .map(decode)
        .or_else(|| header_of(&request.headers, "x-amz-content-sha256").map(str::to_string))
        .unwrap_or_else(|| "UNSIGNED-PAYLOAD".to_string());

    // The path arrives percent-encoded exactly as the signer encoded it, so it
    // is used verbatim as the canonical URI.
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method, path, canonical_query, canonical_headers, signed_header_list, payload_hash,
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex(&Sha256::digest(canonical_request.as_bytes())),
    );
    let expected = hex(&hmac_sha256(
        &signing_key(SECRET_KEY, date, region, service),
        string_to_sign.as_bytes(),
    ));
    if expected == provided {
        return Ok(());
    }
    Err(format!(
        "SignatureDoesNotMatch: signed headers [{signed_header_list}] resolved to \
         [{}]; canonical request was {:?}",
        canonical_headers.trim_end().replace('\n', ", "),
        canonical_request,
    ))
}

/// The SigV4 signing key: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let initial = format!("AWS4{secret}");
    let key = hmac_sha256(initial.as_bytes(), date.as_bytes());
    let key = hmac_sha256(&key, region.as_bytes());
    let key = hmac_sha256(&key, service.as_bytes());
    hmac_sha256(&key, b"aws4_request")
}

/// HMAC-SHA256 (RFC 2104) over the crate's existing `sha2` dependency, so the
/// fixture needs no new Cargo entry.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= padded[index];
        outer_pad[index] ^= padded[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Split a raw query string into its encoded `(name, value)` pairs, preserving
/// wire order and encoding. Names are compared as-is; the SDK emits the
/// canonical `X-Amz-*` spelling.
fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name.to_string(), value.to_string()),
            None => (pair.to_string(), String::new()),
        })
        .collect()
}

/// Percent-decode a query value. Only needed for values the verifier compares
/// as text (credential, signed-header list); the canonical query keeps the
/// encoded form.
fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

fn http_response(status: u16, body: &[u8], extra: &[(String, String)]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

fn error_xml(code: &str, message: &str) -> String {
    // The message is echoed for diagnosis only; MinIO's own text differs.
    let escaped = message.replace('&', "&amp;").replace('<', "&lt;");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{code}</Code><Message>{escaped}</Message>\
         <RequestId>fake-minio</RequestId></Error>"
    )
}

fn list_bucket_xml() -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Name>{BUCKET}</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
         <MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"
    )
}

fn initiate_multipart_xml(key: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Bucket>{BUCKET}</Bucket><Key>{key}</Key><UploadId>{UPLOAD_ID}</UploadId>\
         </InitiateMultipartUploadResult>"
    )
}

fn complete_multipart_xml(key: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Location>http://fake/{BUCKET}/{key}</Location><Bucket>{BUCKET}</Bucket>\
         <Key>{key}</Key><ETag>&quot;fake-complete-etag&quot;</ETag>\
         </CompleteMultipartUploadResult>"
    )
}

// ---------------------------------------------------------------------------
// Raw replay, for negative controls
// ---------------------------------------------------------------------------

/// Send a request to `endpoint` byte-for-byte as given and return
/// `(status, body)`. Used to replay a captured presigned request with one
/// header deliberately tampered, proving the verifier is not vacuous.
pub fn send_raw(
    endpoint: &str,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, String) {
    let authority = endpoint.trim_start_matches("http://");
    let mut stream = TcpStream::connect(authority).expect("connect to the fake");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes()).expect("write head");
    stream.write_all(body).expect("write body");
    stream.flush().expect("flush");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .expect("status line");
    (status, text)
}
