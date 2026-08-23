// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared fixture for the Azure integration tests, matching the `tests/support`
//! module the S3 and GCS plugins already carry.
//!
//! Lives under `tests/support/` (a subdirectory `mod.rs`) so cargo does NOT
//! compile it as its own integration-test target; test files opt in with
//! `mod support;`.
//!
//! Backend construction, the resolved-target helper and the loopback Azure
//! server live here rather than in each test target. They are the pieces that
//! encode how this plugin is wired for a test — the `__test_only_*` hooks, the
//! Shared-Key credential shape, the endpoint override — so a change to any of
//! them should be made once. Held separately, they drift silently: two targets
//! keep compiling and keep passing while testing different setups.
//!
//! Two server fixtures live here, and the difference between them is what
//! they are willing to assert. [`spawn_capture_server`] and
//! [`spawn_stat_probe_server`] record requests and answer from a canned
//! script — enough to assert "the right header / query parameter was
//! emitted". [`spawn_fake_azure`] additionally *verifies* the Shared Key
//! signature, by re-deriving it from the captured request exactly the way
//! Azure does and answering 403 on a mismatch. That is the only way a fake
//! server can observe whether the canonicalized resource the plugin signed
//! matches the URI it actually sent — the failure mode that path-style
//! (emulator) endpoints introduce.

// Each integration-test binary compiles this module on its own and uses a
// subset of it, so the unused remainder is expected rather than dead.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use ovstorage_plugin::{
    BackendId, ConfigValue, ResolvedTarget, SecretBundle, SecretBytes, SecretValue, address,
};
use ovstorage_plugin_azure::AzureBackend;
use sha2::Sha256;

// === Credentials ===

/// Deterministic Shared Key material. Every fixture uses the same bytes so a
/// server that verifies signatures can be handed the same key the backend
/// signs with.
pub fn shared_key_bytes() -> Vec<u8> {
    [0x11u8; 32].to_vec()
}

pub fn shared_key_bundle() -> SecretBundle {
    shared_key_bundle_for(&base64::engine::general_purpose::STANDARD.encode(shared_key_bytes()))
}

/// A credential bundle over an account key this crate does not choose.
///
/// The live-emulator suite signs with Azurite's published development key, so
/// its bytes are fixed by the emulator rather than by [`shared_key_bytes`].
pub fn shared_key_bundle_for(key_base64: &str) -> SecretBundle {
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "account_key".into(),
        SecretValue::Bytes(SecretBytes(key_base64.as_bytes().to_vec())),
    );
    bundle
}

// === Backend construction ===

pub fn config_map(
    account: &str,
    container: &str,
    pairs: &[(&str, ConfigValue)],
) -> HashMap<String, ConfigValue> {
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String(account.into()));
    config.insert("container".into(), ConfigValue::String(container.into()));
    for (key, value) in pairs {
        config.insert((*key).into(), value.clone());
    }
    config
}

/// Build a backend from a config map, through the public parse hook so the
/// test exercises the same validation a real connection would.
///
/// This is the primitive the named constructors below are expressed in; reach
/// for it directly when a test needs to set a config key they do not cover
/// (`blob_endpoint`, `dfs_endpoint`).
pub fn build_backend_from_config(config: HashMap<String, ConfigValue>) -> Arc<AzureBackend> {
    build_backend_from_config_with_key(
        config,
        &base64::engine::general_purpose::STANDARD.encode(shared_key_bytes()),
    )
}

/// [`build_backend_from_config`] signing with a caller-supplied account key.
pub fn build_backend_from_config_with_key(
    config: HashMap<String, ConfigValue>,
    key_base64: &str,
) -> Arc<AzureBackend> {
    let parsed =
        ovstorage_plugin_azure::__test_only_parse_config(&config).expect("parse azure config");
    Arc::new(
        ovstorage_plugin_azure::__test_only_with_credentials(
            parsed,
            shared_key_bundle_for(key_base64),
        )
        .expect("backend init"),
    )
}

/// A Shared-Key backend against the real `https://{account}.blob.…` base.
pub fn build_backend(account: &str, container: &str) -> Arc<AzureBackend> {
    build_backend_inner(account, container, None, false)
}

/// The same backend with its endpoint repointed at a loopback fixture.
///
/// Shared-Key signing covers the account, container and path but not the host,
/// so the request still signs correctly over plain HTTP.
///
/// Routed through the hidden `__test_only_with_endpoint_override` hook rather
/// than the public `blob_endpoint` key, because the hook repoints both tiers
/// at once and takes precedence over both endpoint keys. It does not itself
/// require a loopback address — that guard sits on the `__test_endpoint`
/// config key — so callers here pass a fixture's own `127.0.0.1` address.
pub fn build_backend_with_endpoint(
    account: &str,
    container: &str,
    endpoint: &str,
) -> Arc<AzureBackend> {
    build_backend_inner(account, container, Some(endpoint), false)
}

/// [`build_backend_with_endpoint`] with `hierarchical_namespace` on: the
/// backend advertises `has_real_directories` and takes the ADLS Gen2 (DFS)
/// routes.
pub fn build_hns_backend_with_endpoint(
    account: &str,
    container: &str,
    endpoint: &str,
) -> Arc<AzureBackend> {
    build_backend_inner(account, container, Some(endpoint), true)
}

fn build_backend_inner(
    account: &str,
    container: &str,
    endpoint: Option<&str>,
    hierarchical_namespace: bool,
) -> Arc<AzureBackend> {
    let pairs: Vec<(&str, ConfigValue)> = if hierarchical_namespace {
        vec![("hierarchical_namespace", ConfigValue::Bool(true))]
    } else {
        Vec::new()
    };
    let config = config_map(account, container, &pairs);
    let parsed =
        ovstorage_plugin_azure::__test_only_parse_config(&config).expect("parse azure config");
    let parsed = match endpoint {
        Some(endpoint) => {
            ovstorage_plugin_azure::__test_only_with_endpoint_override(parsed, endpoint.to_string())
                .expect("loopback endpoint override parses")
        }
        None => parsed,
    };
    Arc::new(
        ovstorage_plugin_azure::__test_only_with_credentials(parsed, shared_key_bundle())
            .expect("backend init"),
    )
}

pub fn target(account: &str, container: &str, key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("azure:{account}:{container}")),
        resolved_address: address::parse(&format!("azure://{account}/{container}/{key}")).unwrap(),
    }
}

// === Captured requests ===

/// What the fixture concluded about a request's `Authorization` header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SharedKeyVerdict {
    /// The server was not given an account key, so nothing was checked.
    #[default]
    NotChecked,
    /// No `Authorization` header was present.
    Absent,
    Valid,
    /// The header did not match the signature the fixture re-derived from
    /// the wire. `string_to_sign` is what the fixture expected to be signed;
    /// diffing it against the plugin's canonical string is how a
    /// canonical-path regression gets diagnosed.
    Mismatch {
        string_to_sign: String,
    },
}

#[derive(Clone, Default)]
pub struct CapturedRequest {
    pub raw: String,
    pub shared_key: SharedKeyVerdict,
}

impl CapturedRequest {
    pub fn request_line(&self) -> &str {
        self.raw.lines().next().unwrap_or("")
    }

    /// The request-target of the request line, query string included.
    pub fn target(&self) -> &str {
        self.request_line().split(' ').nth(1).unwrap_or("")
    }

    /// The request-target with any query string stripped.
    pub fn path(&self) -> &str {
        self.target().split('?').next().unwrap_or("")
    }

    /// The exact, decoded value of query parameter `name`, or `None` when it
    /// is absent.
    ///
    /// Parsed into key/value pairs rather than substring-searched: a
    /// malformed target such as `?xrestype=container` contains the text
    /// `restype=container` and would satisfy a `contains` check while
    /// carrying a parameter Azure does not recognize.
    ///
    /// Panics if `name` appears more than once — a duplicated query
    /// parameter is a bug in the request builder, not something a test
    /// should silently take the first of.
    pub fn query_param(&self, name: &str) -> Option<String> {
        let query = self.target().split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut found = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
            .filter(|(key, _)| decode(key) == name)
            .map(|(_, value)| decode(value));
        let first = found.next()?;
        assert!(
            found.next().is_none(),
            "query parameter {name:?} appears more than once in {:?}",
            self.target(),
        );
        Some(first)
    }

    pub fn has_header(&self, name: &str) -> bool {
        let needle = format!("\r\n{}: ", name.to_lowercase());
        self.raw.to_lowercase().contains(&needle)
    }

    pub fn header_value(&self, name: &str) -> Option<String> {
        let lower = self.raw.to_lowercase();
        let needle = format!("\r\n{}: ", name.to_lowercase());
        let start = lower.find(&needle)? + needle.len();
        let after = &self.raw[start..];
        let end = after.find("\r\n").unwrap_or(after.len());
        Some(after[..end].to_string())
    }
}

#[derive(Clone)]
pub struct Capture {
    pub requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl Capture {
    fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn snapshot(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("capture poisoned").clone()
    }

    /// The first captured request with the given method, with every captured
    /// request line in the panic message so a routing regression is
    /// diagnosable from the failure alone.
    pub fn expect_one(&self, method: &str) -> CapturedRequest {
        let requests = self.snapshot();
        requests
            .iter()
            .find(|r| r.request_line().starts_with(&format!("{method} ")))
            .cloned()
            .unwrap_or_else(|| panic!("expected a {method} request; saw:\n{}", render(&requests)))
    }
}

/// [`CapturedRequest::query_param`] for a raw request a fixture holds before
/// it has been captured — the response-dispatch side of the same parse.
pub fn request_query_param(raw: &str, name: &str) -> Option<String> {
    CapturedRequest {
        raw: raw.to_string(),
        shared_key: SharedKeyVerdict::NotChecked,
    }
    .query_param(name)
}

pub fn render(requests: &[CapturedRequest]) -> String {
    requests
        .iter()
        .map(|r| r.request_line().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

// === Capture-style fake Azure server ===
//
// A TCP listener that records every request line + headers and answers with
// minimal headers Azure returns. Enough to assert "the right header / query
// parameter was emitted" without an Azurite fixture. Each accepted connection
// serves exactly one request, then closes.

/// An empty `List Blobs` page, so the connection verify a `Layer` performs on
/// `add_connection` gets a well-formed answer instead of the bare 202 every
/// other route here returns.
const EMPTY_LIST_BODY: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<EnumerationResults><Blobs></Blobs><NextMarker /></EnumerationResults>",
);

/// [`spawn_capture_server`] that also answers the bounded `comp=list` probe, so
/// a test can drive the whole `Layer` — `add_connection` included — rather than
/// a bare backend, and still assert on the requests the commit emitted.
pub fn spawn_capture_server_serving_verify() -> (String, Capture, Arc<AtomicUsize>) {
    spawn_capture_server_inner(true)
}

pub fn spawn_capture_server() -> (String, Capture, Arc<AtomicUsize>) {
    spawn_capture_server_inner(false)
}

fn spawn_capture_server_inner(serve_verify: bool) -> (String, Capture, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let capture = Capture::new();
    let requests_for_thread = capture.requests.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_thread = counter.clone();

    thread::Builder::new()
        .name("ovs-test-azure-capture".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                let raw_for_response = raw.clone();
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest {
                        raw,
                        shared_key: SharedKeyVerdict::NotChecked,
                    });
                counter_for_thread.fetch_add(1, Ordering::SeqCst);
                // `Connection: close` for the same reason as the stat-probe
                // fixture below: one request per stream, so reqwest must not
                // pool and reuse the connection the server is about to drop.
                let list_probe = serve_verify && raw_for_response.to_lowercase().contains("comp=list");
                let response = if list_probe {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        EMPTY_LIST_BODY.len(),
                        EMPTY_LIST_BODY,
                    )
                } else {
                    "HTTP/1.1 202 Accepted\r\nETag: \"fake-etag\"\r\nLast-Modified: Wed, 01 Jan 2026 00:00:00 GMT\r\nx-ms-copy-status: success\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string()
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn capture server");

    thread::sleep(Duration::from_millis(50));
    (endpoint, capture, counter)
}

/// How the stat-probe fixture should answer the prefix-list `GET`.
pub struct ProbeResponse {
    pub status: u16,
    pub reason: &'static str,
    pub body: String,
    /// Extra response headers, each already `Name: value` (no CRLF).
    pub extra_headers: Vec<String>,
}

impl ProbeResponse {
    pub fn ok(body: &'static str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            body: body.to_string(),
            extra_headers: Vec::new(),
        }
    }

    pub fn failure(status: u16, reason: &'static str, body: String) -> Self {
        Self {
            status,
            reason,
            body,
            extra_headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        self.extra_headers.push(header.into());
        self
    }
}

/// A `stat`-shaped fixture: 404 on the `HEAD` that probes the directory
/// marker, then `response` on the bounded prefix-list `GET` that follows.
///
/// Every branch advertises `Connection: close` because the handler serves
/// exactly one request per accepted stream and then drops it. Without the
/// header, reqwest keeps the connection in its idle pool and may reuse it for
/// the follow-up request — a `stat` does HEAD then a prefix-list GET on the
/// same backend. Racing the server's close, that reuse surfaces as a connection
/// error mapped to `Transient` instead of the status the test set up.
pub fn spawn_stat_probe_server(response: ProbeResponse) -> (String, Capture) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let capture = Capture::new();
    let requests_for_thread = capture.requests.clone();

    thread::Builder::new()
        .name("ovs-test-azure-stat-probe".into())
        .spawn(move || {
            let extra = response
                .extra_headers
                .iter()
                .map(|header| format!("{header}\r\n"))
                .collect::<String>();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest {
                        raw: raw.clone(),
                        shared_key: SharedKeyVerdict::NotChecked,
                    });
                let reply = if raw.starts_with("HEAD ") {
                    "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                } else if raw.starts_with("GET ") {
                    format!(
                        "HTTP/1.1 {} {}\r\nContent-Type: application/xml\r\n{extra}\
                         Connection: close\r\nContent-Length: {}\r\n\r\n{}",
                        response.status,
                        response.reason,
                        response.body.len(),
                        response.body
                    )
                } else {
                    "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(reply.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn stat probe server");

    thread::sleep(Duration::from_millis(50));
    (endpoint, capture)
}

// === Signature-verifying fake Azure server ===

/// Account identity the server checks signatures against. `None` on the
/// server means signatures are recorded as [`SharedKeyVerdict::NotChecked`].
#[derive(Clone)]
pub struct SharedKeySigner {
    pub account: String,
    pub key_bytes: Vec<u8>,
}

impl SharedKeySigner {
    pub fn new(account: &str) -> Self {
        Self {
            account: account.to_string(),
            key_bytes: shared_key_bytes(),
        }
    }
}

pub struct FakeAzure {
    /// `http://127.0.0.1:{port}`, ready to hand to an endpoint config key.
    pub endpoint: String,
    pub port: u16,
    pub capture: Capture,
}

/// Bind an ephemeral loopback port and serve captures from it. One request
/// per accepted connection, then close — `responder` must advertise
/// `Connection: close` for the same reason, or reqwest keeps the socket in
/// its idle pool and races the server's close on the next call.
///
/// When `signer` is set, a request whose Shared Key signature does not
/// re-derive from the wire is answered 403 instead of being handed to
/// `responder`, so the operation under test fails the way real Azure would.
pub fn spawn_fake_azure(
    label: &str,
    signer: Option<SharedKeySigner>,
    responder: impl Fn(&str) -> String + Send + 'static,
) -> FakeAzure {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    let capture = Capture::new();
    let requests_for_thread = capture.requests.clone();

    thread::Builder::new()
        .name(format!("ovs-test-azure-{label}"))
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let Some(raw) = read_request(&mut stream) else {
                    continue;
                };
                let shared_key = match signer.as_ref() {
                    Some(signer) => verify_shared_key(&raw, signer),
                    None => SharedKeyVerdict::NotChecked,
                };
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest {
                        raw: raw.clone(),
                        shared_key: shared_key.clone(),
                    });
                let response = match shared_key {
                    SharedKeyVerdict::Mismatch { .. } | SharedKeyVerdict::Absent => {
                        "HTTP/1.1 403 Server failed to authenticate the request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string()
                    }
                    _ => responder(&raw),
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn fake azure server");

    thread::sleep(Duration::from_millis(50));
    FakeAzure {
        endpoint: format!("http://127.0.0.1:{port}"),
        port,
        capture,
    }
}

/// Read one whole HTTP request: headers, then exactly `Content-Length` bytes of
/// body. A single `read` is not enough — a client is free to write the headers
/// and the body as separate segments, which would truncate the capture and make
/// any assertion about the body intermittently wrong.
///
/// Length-delimited bodies only. Every request the plugin sends carries an
/// `Option<Vec<u8>>` body, so reqwest always sets `Content-Length` and never
/// chunks; a `Transfer-Encoding: chunked` request would fall back to headers
/// plus whatever happened to arrive, which is the nondeterminism this exists to
/// remove.
fn read_request(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut buf = [0u8; 65536];
    let header_end = loop {
        if let Some(at) = find_subslice(&raw, b"\r\n\r\n") {
            break at + 4;
        }
        let len = stream.read(&mut buf).ok()?;
        if len == 0 {
            return None;
        }
        raw.extend_from_slice(&buf[..len]);
    };
    let headers = String::from_utf8_lossy(&raw[..header_end]).to_ascii_lowercase();
    let content_length = headers
        .split("\r\n")
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < header_end + content_length {
        let len = stream.read(&mut buf).ok()?;
        if len == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..len]);
    }
    Some(String::from_utf8_lossy(&raw).to_string())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// === Shared Key verification ===
//
// Mirrors `src/signing.rs`, but derived from the bytes on the wire rather
// than from the plugin's own request struct — that independence is the whole
// point. Azure's string-to-sign is
// `VERB\n<6 blank-or-content headers>\n...\nCanonicalizedHeaders` followed
// by `/{account}` + the request URI path + the sorted query.

type HmacSha256 = Hmac<Sha256>;

/// Re-derive a raw request's Shared Key signature and report whether it
/// matches, for a fixture that owns its own listener rather than using
/// [`spawn_fake_azure`] (the change-feed suite).
pub fn verify_shared_key(raw: &str, signer: &SharedKeySigner) -> SharedKeyVerdict {
    let headers = parse_headers(raw);
    let Some(authorization) = header(&headers, "authorization") else {
        return SharedKeyVerdict::Absent;
    };
    let string_to_sign = string_to_sign(raw, &headers, &signer.account);
    let mut mac =
        HmacSha256::new_from_slice(&signer.key_bytes).expect("HMAC accepts any key length");
    mac.update(string_to_sign.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    if authorization == format!("SharedKey {}:{signature}", signer.account) {
        SharedKeyVerdict::Valid
    } else {
        SharedKeyVerdict::Mismatch { string_to_sign }
    }
}

fn string_to_sign(raw: &str, headers: &[(String, String)], account: &str) -> String {
    let request_line = raw.lines().next().unwrap_or("");
    let method = request_line.split(' ').next().unwrap_or("");
    let target = request_line.split(' ').nth(1).unwrap_or("");

    // An absent or zero Content-Length signs as empty, matching Azure.
    let content_length = match header(headers, "content-length").as_deref() {
        None | Some("0") => String::new(),
        Some(value) => value.to_string(),
    };
    // The plugin signs the caller's raw etag but sends the RFC 7232 quoted
    // form, so unquote before re-deriving. `*` is unaffected.
    let if_match = header(headers, "if-match")
        .map(|v| unquote(&v))
        .unwrap_or_default();
    let if_none_match = header(headers, "if-none-match")
        .map(|v| unquote(&v))
        .unwrap_or_default();

    format!(
        "{method}\n\
         \n\
         \n\
         {content_length}\n\
         {content_md5}\n\
         {content_type}\n\
         \n\
         \n\
         {if_match}\n\
         {if_none_match}\n\
         \n\
         {range}\n\
         {canonical_headers}{canonical_resource}",
        content_md5 = header(headers, "content-md5").unwrap_or_default(),
        content_type = header(headers, "content-type").unwrap_or_default(),
        range = header(headers, "range").unwrap_or_default(),
        canonical_headers = canonical_ms_headers(headers),
        canonical_resource = canonical_resource(account, target),
    )
}

fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
        .collect()
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

fn unquote(value: &str) -> String {
    value.trim_matches('"').to_string()
}

fn canonical_ms_headers(headers: &[(String, String)]) -> String {
    let mut sorted: BTreeMap<&str, String> = BTreeMap::new();
    for (name, value) in headers {
        if name.starts_with("x-ms-") {
            sorted.insert(name.as_str(), collapse_whitespace(value.trim()));
        }
    }
    sorted
        .into_iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect()
}

fn collapse_whitespace(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_space = false;
    for ch in value.chars() {
        if ch == ' ' || ch == '\t' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out
}

/// `/{account}` + the request path AS SENT + `\n{name}:{v1,v2}` per query
/// parameter, names lowercased and sorted.
///
/// The path is NOT decoded. Azure canonicalizes URI-derived parts of the
/// resource "encoded exactly as it is in the URI" — the .NET signer uses
/// `Uri.AbsolutePath` and the Go one `EscapedPath()` for exactly this. Query
/// parameters are the exception the spec calls out: their names and values
/// are decoded before sorting and joining.
///
/// Decoding the path here would make this fixture agree with a plugin that
/// signs a decoded path — a wrong oracle that passes its own tests and then
/// 403s against the real service. Taking the path from the wire verbatim is
/// what makes a plugin that signed anything other than what it addressed —
/// a dropped endpoint prefix, a raw key where the URL carries an encoded one
/// — fail here.
fn canonical_resource(account: &str, target: &str) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut resource = format!("/{account}{path}");
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        grouped
            .entry(decode(name).to_ascii_lowercase())
            .or_default()
            .push(decode(value));
    }
    for (name, mut values) in grouped {
        values.sort();
        resource.push('\n');
        resource.push_str(&name);
        resource.push(':');
        resource.push_str(&values.join(","));
    }
    resource
}

fn decode(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}
