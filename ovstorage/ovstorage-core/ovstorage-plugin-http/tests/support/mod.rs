// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-side signing toolkit for the HTTP plugin's credential channels.
//!
//! A fixture that answers `200` to anything cannot tell a preserved signature
//! from a mangled one, so every token here is **minted with a real key and
//! checked with a real verifier**:
//!
//! - [`mint_container_sas`] emits an Azure-shaped container-scoped SAS
//!   (`sr=c`): one grant covers every object under the container, which is the
//!   scope family the plugin is allowed to hold on a connection.
//! - [`mint_sigv4_presign`] emits an AWS SigV4 presigned query whose canonical
//!   request includes the **exact object path**. That path binding is what
//!   makes the token per-object, and what the plugin's refusal of a per-object
//!   presign is about — a test can therefore show the token working at the path
//!   it was minted for and failing one path over.
//! - [`VerifyingOrigin`] is a loopback origin that runs a caller-supplied
//!   verifier over the request it actually received and answers `403` when the
//!   check fails, so a byte the plugin drops or re-encodes surfaces as a status
//!   code rather than passing silently.
//!
//! Keys, accounts, and the SigV4 host are fixed constants: the signatures stay
//! independent of the ephemeral port and of wall-clock time, so the only thing
//! a failure can point at is the request itself.

// Each integration-test binary that opts in with `mod support;` uses a
// different subset of this toolkit.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// === Primitives ===

/// HMAC-SHA256 over `message`. Any key length is accepted, as RFC 2104 allows.
pub fn hmac_sha256(key: &[u8], message: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Lowercase hex, the encoding SigV4 signatures use on the wire.
pub fn hex_lower(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
}

/// Length-then-fold comparison, so a mismatch leaks no position information.
fn signatures_match(expected: &str, provided: &str) -> bool {
    expected.len() == provided.len()
        && expected
            .bytes()
            .zip(provided.bytes())
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Split a raw query string into its `(name, value)` pairs, preserving wire
/// order and percent-encoding. Values are compared or decoded by the caller.
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

fn query_value(pairs: &[(String, String)], name: &str) -> Option<String> {
    pairs.iter().find_map(|(found, value)| {
        (found == name).then(|| {
            urlencoding::decode(value)
                .map(|decoded| decoded.into_owned())
                .unwrap_or_else(|_| value.clone())
        })
    })
}

// === Container-scoped SAS (Azure shape, `sr=c`) ===

/// Storage account the container SAS is canonicalized under.
pub const SAS_ACCOUNT: &str = "ovstorageaccount";
/// Signed-version stamp, matching the version the Azure plugin signs with.
pub const SAS_VERSION: &str = "2021-12-02";
/// Read-only grant; the HTTP plugin only ever issues reads.
pub const SAS_PERMISSIONS: &str = "r";

/// The Service SAS string-to-sign for a *container*-scoped grant.
///
/// Same field order as the Azure plugin's blob-scoped signer, with
/// `signedResource = c`: the grant covers the container, not one blob.
fn container_sas_string_to_sign(container: &str, expiry: &str) -> String {
    format!(
        "{permissions}\n\
         \n\
         {expiry}\n\
         /blob/{account}/{container}\n\
         \n\
         \n\
         \n\
         {version}\n\
         c\n\
         \n\
         \n\
         \n\
         \n\
         \n\
         \n\
         ",
        permissions = SAS_PERMISSIONS,
        expiry = expiry,
        account = SAS_ACCOUNT,
        container = container,
        version = SAS_VERSION,
    )
}

/// Mint a container-scoped SAS query string (no leading `?`).
///
/// `expiry` is an ISO-8601 instant such as `2030-01-01T00:00:00Z`; it is signed
/// but never enforced, so the suite stays time-independent.
pub fn mint_container_sas(key: &[u8], container: &str, expiry: &str) -> String {
    let signature = base64::engine::general_purpose::STANDARD.encode(hmac_sha256(
        key,
        &container_sas_string_to_sign(container, expiry),
    ));
    format!(
        "sv={version}&sr=c&sp={permissions}&se={expiry}&sig={signature}",
        version = urlencoding::encode(SAS_VERSION),
        permissions = urlencoding::encode(SAS_PERMISSIONS),
        expiry = urlencoding::encode(expiry),
        signature = urlencoding::encode(&signature),
    )
}

/// Recompute a container SAS and check it grants `path`.
///
/// Two independent conditions, both required: the signature recomputes, and
/// `path` falls under the container the signature was scoped to. A container
/// grant covers every object beneath it and nothing outside it.
pub fn verify_container_sas(key: &[u8], container: &str, path: &str, query: &str) -> bool {
    let pairs = query_pairs(query);
    let (Some(version), Some(resource), Some(permissions), Some(expiry), Some(provided)) = (
        query_value(&pairs, "sv"),
        query_value(&pairs, "sr"),
        query_value(&pairs, "sp"),
        query_value(&pairs, "se"),
        query_value(&pairs, "sig"),
    ) else {
        return false;
    };
    if version != SAS_VERSION || resource != "c" || permissions != SAS_PERMISSIONS {
        return false;
    }
    if !path
        .trim_start_matches('/')
        .starts_with(&format!("{container}/"))
    {
        return false;
    }
    let expected = base64::engine::general_purpose::STANDARD.encode(hmac_sha256(
        key,
        &container_sas_string_to_sign(container, &expiry),
    ));
    signatures_match(&expected, &provided)
}

// === Per-object SigV4 presign (AWS shape) ===

/// Access key id embedded in the credential scope.
pub const SIGV4_ACCESS_KEY: &str = "AKIAOVSTORAGETEST";
pub const SIGV4_REGION: &str = "us-east-1";
pub const SIGV4_SERVICE: &str = "s3";
/// Canonical `host` header value. Fixed rather than read off the wire so a
/// token minted in one test stays valid against any ephemeral loopback port —
/// the binding this toolkit exists to prove is the *path*, not the authority.
pub const SIGV4_HOST: &str = "origin.ovstorage.test";

/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
fn sigv4_signing_key(secret: &[u8], datestamp: &str) -> Vec<u8> {
    let mut initial = b"AWS4".to_vec();
    initial.extend_from_slice(secret);
    let key = hmac_sha256(&initial, datestamp);
    let key = hmac_sha256(&key, SIGV4_REGION);
    let key = hmac_sha256(&key, SIGV4_SERVICE);
    hmac_sha256(&key, "aws4_request")
}

/// The canonical query of a presign: every parameter except the signature, in
/// the wire encoding, sorted by name.
fn sigv4_canonical_query(pairs: &[(String, String)]) -> String {
    let mut canonical: Vec<(&str, &str)> = pairs
        .iter()
        .filter(|(name, _)| name != "X-Amz-Signature")
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    canonical.sort_unstable();
    canonical
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The string-to-sign for a `GET` presign over exactly `path`.
fn sigv4_string_to_sign(path: &str, amz_date: &str, scope: &str, canonical_query: &str) -> String {
    let canonical_request =
        format!("GET\n{path}\n{canonical_query}\nhost:{SIGV4_HOST}\n\nhost\nUNSIGNED-PAYLOAD");
    format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex_lower(&Sha256::digest(canonical_request.as_bytes())),
    )
}

/// Mint a presigned SigV4 query string (no leading `?`) bound to `path`.
///
/// `path` is signed material: the same token at a different path does not
/// verify. `date` is an `X-Amz-Date` stamp in `YYYYMMDDTHHMMSSZ` form; its
/// leading day stamp becomes the credential scope.
pub fn mint_sigv4_presign(key: &[u8], path: &str, date: &str) -> String {
    let datestamp = date.get(..8).expect("X-Amz-Date is YYYYMMDDTHHMMSSZ");
    let scope = format!("{datestamp}/{SIGV4_REGION}/{SIGV4_SERVICE}/aws4_request");
    let credential = format!("{SIGV4_ACCESS_KEY}/{scope}");
    let unsigned = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={credential}\
         &X-Amz-Date={date}&X-Amz-Expires=900&X-Amz-SignedHeaders=host",
        credential = urlencoding::encode(&credential),
    );
    let signature = hex_lower(&hmac_sha256(
        &sigv4_signing_key(key, datestamp),
        &sigv4_string_to_sign(path, date, &scope, &unsigned),
    ));
    format!("{unsigned}&X-Amz-Signature={signature}")
}

/// Recompute a presigned SigV4 signature over the path it actually arrived at.
pub fn verify_sigv4_presign(key: &[u8], path: &str, query: &str) -> bool {
    let pairs = query_pairs(query);
    let (Some(algorithm), Some(credential), Some(amz_date), Some(provided)) = (
        query_value(&pairs, "X-Amz-Algorithm"),
        query_value(&pairs, "X-Amz-Credential"),
        query_value(&pairs, "X-Amz-Date"),
        query_value(&pairs, "X-Amz-Signature"),
    ) else {
        return false;
    };
    if algorithm != "AWS4-HMAC-SHA256" {
        return false;
    }
    // `<access-key>/<date>/<region>/<service>/aws4_request`; an access key may
    // itself contain slashes, so the scope is taken from the right.
    let segments: Vec<&str> = credential.split('/').collect();
    if segments.len() < 5 || segments[..segments.len() - 4].join("/") != SIGV4_ACCESS_KEY {
        return false;
    }
    let scope_parts = &segments[segments.len() - 4..];
    let scope = scope_parts.join("/");
    let expected = hex_lower(&hmac_sha256(
        &sigv4_signing_key(key, scope_parts[0]),
        &sigv4_string_to_sign(path, &amz_date, &scope, &sigv4_canonical_query(&pairs)),
    ));
    signatures_match(&expected, &provided)
}

// === Verifying origin ===

/// One request as the origin received it.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    /// The request line byte-for-byte, e.g. `GET /c/a.txt?sig=x HTTP/1.1`.
    pub line: String,
    pub method: String,
    /// Request target up to the `?`, in the encoding it arrived in.
    pub path: String,
    /// Raw query string with no leading `?`, empty when absent.
    pub query: String,
    pub headers: Vec<(String, String)>,
}

impl RecordedRequest {
    /// The value of `name` as it arrived, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find_map(|(found, value)| found.eq_ignore_ascii_case(name).then_some(value.as_str()))
    }
}

type Verifier = Arc<dyn Fn(&RecordedRequest) -> bool + Send + Sync>;

/// A loopback origin that authorizes each request with a real check.
///
/// Answers `200` with the configured body when the verifier accepts and `403`
/// when it does not, and records every request it saw. Dropping it stops the
/// accept loop and joins the thread, so a fixture leaves no bound port behind.
pub struct VerifyingOrigin {
    addr: SocketAddr,
    body: Arc<Vec<u8>>,
    seen: Arc<Mutex<Vec<RecordedRequest>>>,
    shutdown: Arc<AtomicBool>,
    /// `Some` until `Drop` joins it.
    accept: Option<JoinHandle<()>>,
}

impl VerifyingOrigin {
    /// Bind an ephemeral loopback port and serve `body` to requests `verify`
    /// accepts.
    pub fn spawn<F>(body: impl Into<Vec<u8>>, verify: F) -> Self
    where
        F: Fn(&RecordedRequest) -> bool + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let body = Arc::new(body.into());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let verify: Verifier = Arc::new(verify);

        let (body_thread, seen_thread, shutdown_thread) =
            (Arc::clone(&body), Arc::clone(&seen), Arc::clone(&shutdown));
        let accept = thread::Builder::new()
            .name("ovs-verifying-origin".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    // `Drop` sets the flag and then dials the port to wake this
                    // accept, so the wake-up connection is observed here and
                    // never served.
                    if shutdown_thread.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(stream) = stream else { return };
                    let (body, seen, verify) = (
                        Arc::clone(&body_thread),
                        Arc::clone(&seen_thread),
                        Arc::clone(&verify),
                    );
                    let spawned = thread::Builder::new()
                        .name("ovs-verifying-origin-conn".into())
                        .spawn(move || serve_connection(stream, &body, &seen, &verify));
                    if spawned.is_err() {
                        return;
                    }
                }
            })
            .expect("failed to spawn thread");

        Self {
            addr,
            body,
            seen,
            shutdown,
            accept: Some(accept),
        }
    }

    /// Ephemeral port the origin listens on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Base URL of the origin, with no trailing slash.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The body a `200` answer carries.
    pub fn body(&self) -> Vec<u8> {
        self.body.as_ref().clone()
    }

    /// Every request the origin saw, in order.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// The raw request lines, in order — the byte-preservation record.
    pub fn request_lines(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .map(|request| request.line)
            .collect()
    }

    /// Forget requests already asserted so a later operation can be judged in
    /// isolation. This does not affect the origin or its verifier.
    pub fn clear_requests(&self) {
        self.seen.lock().unwrap().clear();
    }
}

impl Drop for VerifyingOrigin {
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

fn serve_connection(
    mut stream: TcpStream,
    body: &[u8],
    seen: &Mutex<Vec<RecordedRequest>>,
    verify: &Verifier,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let authorized = verify(&request);
    seen.lock().unwrap().push(request.clone());

    // `Connection: close` on every answer, and one answer per connection: the
    // crate's other fixtures do the same, because reqwest otherwise pools a
    // socket this origin has already dropped and turns the next assertion into
    // a spurious transport error.
    let response = if authorized {
        let etag = format!("\"{}\"", &hex_lower(&Sha256::digest(body))[..16]);
        let mut head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: {etag}\r\n\
             Accept-Ranges: bytes\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        if request.method != "HEAD" {
            head.extend_from_slice(body);
        }
        head
    } else {
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    };
    let _ = stream.write_all(&response);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Read one request off the wire. Only `Content-Length` framing is supported;
/// the body is drained and discarded, since this origin serves reads.
fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut buf = [0_u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
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
    let line = lines.next()?.to_string();
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target.to_string(), String::new()),
    };
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    let length = headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case("content-length").then_some(value))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while pending.len() < length {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
        }
    }

    Some(RecordedRequest {
        line,
        method,
        path,
        query,
        headers,
    })
}
