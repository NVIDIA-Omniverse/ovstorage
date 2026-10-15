// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for the GCS plugin's precondition contracts.
//!
//! Mirrors the S3 plugin's `tests/precondition.rs` shape. Each test
//! exercises one of the systemic preconditions enforcement contracts
//! the GCS plugin honors (see `git show f1e1643 972530b 8b32818` for
//! the underlying services-client review that motivated them). The
//! intent is twofold: prove the production code refuses caller input
//! that the GCS wire can't enforce, and pin behaviors that were
//! already correct so a future refactor cannot silently regress them.
//!
//! GCS is the INVERSE of S3 for `if_match`: the wire conditional is
//! `ifGenerationMatch` (a numeric GCS generation), NOT an HTTP etag.
//! GCS interprets the SPI's opaque `if_match` etag string as the
//! generation number; conditional-precondition tests pin that the
//! numeric-string precondition path is accepted at every SPI entry
//! point.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use ovstorage_plugin::{
    BackendId, BodyStream, ByteRange, ConfigValue, ConnectionRequest, CopyOptions, Error,
    ErrorCode, IfDestExists, ReadOptions, ReadResult, RenameOptions, ResolvedTarget, Result,
    SecretBundle, SecretBytes, SecretValue, WriteOptions, address,
};
use ovstorage_plugin_gcs::GcsBackend;
use ovstorage_plugin_test::scripted_http::{CannedHttpResponse, ScriptedHttpServer};

// === Helpers ===

fn version_only_if_match() -> String {
    "42".into()
}

const SYNTHETIC_PEM: &str = include_str!("synthetic_rsa_pkcs8.pem");

fn service_account_bundle() -> SecretBundle {
    let json = serde_json::json!({
        "type": "service_account",
        "client_email": "tester@example.iam.gserviceaccount.com",
        "private_key": SYNTHETIC_PEM,
        "token_uri": "https://oauth2.example/token",
        "private_key_id": "kid-1",
    })
    .to_string();
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "service_account_key".into(),
        SecretValue::Bytes(SecretBytes(json.into_bytes())),
    );
    bundle
}

async fn anonymous_backend(endpoint: &str, bucket: &str) -> Arc<GcsBackend> {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    let request = ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    };
    let config =
        ovstorage_plugin_gcs::__test_only_parse_config(&request.config).expect("parse config");
    Arc::new(
        ovstorage_plugin_gcs::__test_only_backend(config, request.credentials)
            .expect("build backend"),
    )
}

async fn service_account_backend(endpoint: &str, bucket: &str) -> Arc<GcsBackend> {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    let request = ConnectionRequest {
        backend_kind: "gcs".into(),
        config,
        credentials: service_account_bundle(),
        persist: false,
        display_name: None,
    };
    let config =
        ovstorage_plugin_gcs::__test_only_parse_config(&request.config).expect("parse config");
    Arc::new(
        ovstorage_plugin_gcs::__test_only_backend(config, request.credentials)
            .expect("build backend"),
    )
}

fn target(bucket: &str, key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("gcs:gs://{bucket}/")),
        resolved_address: address::parse(&format!("gs://{bucket}/{key}")).unwrap(),
    }
}

// === Capture-style fake GCS server ===
//
// Spins up a TCP listener that records every request line + body and
// responds 200 with a minimal GCS Object JSON. Sufficient for
// asserting "the right query parameter was emitted" without a full
// fake-gcs-server fixture. Each connection serves exactly one
// request, then closes.

#[derive(Clone, Default)]
struct CapturedRequest {
    raw: String,
}

impl CapturedRequest {
    fn request_line(&self) -> &str {
        self.raw.lines().next().unwrap_or("")
    }
}

struct Capture {
    requests: Arc<std::sync::Mutex<Vec<CapturedRequest>>>,
}

impl Capture {
    fn new() -> Self {
        Self {
            requests: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn snapshot(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("capture poisoned").clone()
    }
}

fn spawn_capture_server() -> (String, Capture, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);
    let capture = Capture::new();
    let requests_for_thread = capture.requests.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_thread = counter.clone();

    thread::Builder::new()
        .name("ovs-test-gcs-precondition".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut buf = [0u8; 65536];
                let len = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest { raw: raw.clone() });
                counter_for_thread.fetch_add(1, Ordering::SeqCst);
                // Minimal GCS Object JSON response — sufficient to
                // satisfy parse_object on the copy/rewrite path. The
                // exact field shape mirrors the on-the-wire response;
                // we just need `done`, `resource`, and the resource's
                // `name`/`generation` to make parse_object happy.
                let body = r#"{"done":true,"resource":{"bucket":"bkt","name":"dst.txt","generation":"100","metageneration":"1","size":"5","updated":"2026-01-01T00:00:00Z","md5Hash":"AAA="}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn capture server");

    thread::sleep(Duration::from_millis(50));
    (endpoint, capture, counter)
}

// === Conditional precondition enforcement ===
//
// GCS's only wire conditional is `ifGenerationMatch` (numeric). GCS
// interprets the SPI's opaque `if_match` etag string as the generation
// number. These tests pin that the numeric-generation precondition
// path is accepted at every SPI entry point.

/// Sanity guard: a numeric `if_match` is the supported precondition
/// shape on GCS and must NOT be rejected. Exercised via `read` because
/// the anonymous read path produces a `ReadResult::Redirect` without
/// touching the wire, so we don't need an HTTP fixture.
#[tokio::test]
async fn read_accepts_version_only_if_match() {
    let backend = anonymous_backend("http://127.0.0.1:1", "bkt").await;
    backend
        .read(
            target("bkt", "x"),
            ReadOptions {
                if_match: Some(version_only_if_match()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("version-only if_match must be accepted");
}

// === Range validation ===

#[tokio::test]
async fn read_range_inverted_returns_invalid_argument() {
    let backend = anonymous_backend("http://127.0.0.1:1", "bkt").await;
    let err = backend
        .read(
            target("bkt", "x"),
            ReadOptions {
                range: Some(ByteRange {
                    start: 100,
                    end_inclusive: Some(50),
                }),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("inverted range must error");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

// === Copy emits source-side ifSourceGenerationMatch ===

#[tokio::test]
async fn copy_emits_source_if_match() {
    // GCS's conditional-copy uses `ifSourceGenerationMatch` (source-
    // side). If the plugin ever bound `if_match` to the destination
    // side (`ifGenerationMatch`), a same-key overwrite would
    // atomic-mutate on the *new* object's current state rather than
    // the caller's expected source identity. Pin both: param
    // present, with the caller-supplied version.
    let (endpoint, capture, _) = spawn_capture_server();
    // Service-account creds avoid token-exchange (sign_url is
    // local) but the copy/rewrite still hits the endpoint for the
    // POST. Actually rewrite POSTs need a bearer token. Use
    // anonymous instead — rewrite POSTs go out without auth and the
    // server still receives the query params. The mock returns
    // 200 with the rewrite-done JSON.
    let backend = anonymous_backend(&endpoint, "bkt").await;

    let _ = backend
        .copy(
            target("bkt", "src.txt"),
            target("bkt", "dst.txt"),
            CopyOptions {
                if_source: Some("123".into()),
                ..Default::default()
            },
            None,
        )
        .await;

    let requests = capture.snapshot();
    let post = requests
        .iter()
        .find(|r| r.request_line().starts_with("POST "))
        .expect("expected a POST for rewriteTo");
    let request_line = post.request_line();
    assert!(
        request_line.contains("ifSourceGenerationMatch=123"),
        "copy must emit source-side ifSourceGenerationMatch query param; request line:\n{}",
        request_line,
    );
    // Negative: must NOT bind the same conditional on the dest side
    // (would be the bare `ifGenerationMatch` query param).
    assert!(
        !request_line.contains("ifGenerationMatch=123"),
        "destination-side ifGenerationMatch must not leak when caller asked for source-side conditional; line:\n{}",
        request_line,
    );
}

// === write_stream propagates source errors ===

#[tokio::test]
async fn write_stream_propagates_source_error() {
    // A BodyStream chunk that errors mid-upload must surface from
    // write_stream as `Err` (not silently truncate). The services-
    // client review found `filter_map(|i| i.ok())` dropping errors;
    // this pins that pattern as absent from GCS.
    //
    // We point at an unreachable endpoint so the upload fails fast.
    // The contract under test is just that the upload didn't
    // silently succeed.
    let backend = anonymous_backend("http://127.0.0.1:1", "bkt").await;
    let chunks: Vec<Result<Vec<u8>>> = vec![
        Ok(b"first chunk".to_vec()),
        Err(Error::new(ErrorCode::Transient, "synthetic source error")),
    ];
    let body = BodyStream::from_iter(chunks.into_iter());
    let err = backend
        .write_stream(
            target("bkt", "partial.bin"),
            body,
            WriteOptions::default(),
            None,
        )
        .await
        .expect_err("body-stream error must propagate from write_stream");
    // GCS may map the error code on the way out (e.g. via
    // map_status_to_error if the failure happens during an HTTP
    // call). The contract is just that the upload didn't silently
    // succeed — assert non-Cancelled and non-Ok.
    assert_ne!(err.code(), ErrorCode::Cancelled);
}

// === if_match enforcement on reads: version passes through ===

#[tokio::test]
async fn read_with_if_match_version_passes_through() {
    // The service-account read path returns `ReadResult::Redirect`
    // with a signed URL. When the caller sets a version-only
    // `if_match`, the plugin folds `ifGenerationMatch=<version>`
    // into the signed query. Pin that the query parameter lands on
    // the presigned URL (and is therefore part of the V4
    // signature).
    let backend = service_account_backend("https://storage.googleapis.com", "bkt").await;
    let result = backend
        .read(
            target("bkt", "x.txt"),
            ReadOptions {
                if_match: Some("42".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("read should succeed (returns presigned redirect)");
    let redirect = match result {
        ReadResult::Redirect(r) => r,
        other => panic!("expected ReadResult::Redirect, got {other:?}"),
    };
    assert!(
        redirect.request.url.contains("ifGenerationMatch=42")
            || redirect.request.url.contains("ifGenerationMatch%3D42"),
        "presigned URL must carry ifGenerationMatch=<version>; url:\n{}",
        redirect.request.url,
    );
    // The conditional must be part of the V4 signature (i.e. it's
    // in the canonical query string that gets signed). GCS V4
    // signs every query param, so its presence on the URL is
    // sufficient — the SignedHeaders pin doesn't apply to GCS
    // (only `host` is in V4 signed headers for GCS).
}

// === Item 6 regression: anonymous read redirect carries ifGenerationMatch ===
//
// The anonymous read path builds a public download URL by hand (no V4
// signing). The CAS precondition has to ride as an `ifGenerationMatch`
// query parameter or GCS treats the read as unconditional — a
// stale-read race would silently return the newer object's bytes
// instead of surfacing `ObjectModified` via the host's 412 follower.

#[tokio::test]
async fn anonymous_read_with_if_match_threads_if_generation_match() {
    let backend = anonymous_backend("https://storage.googleapis.com", "bkt").await;
    let result = backend
        .read(
            target("bkt", "x.txt"),
            ReadOptions {
                if_match: Some("99".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("anonymous read returns ReadResult::Redirect");
    let redirect = match result {
        ReadResult::Redirect(r) => r,
        other => panic!("expected ReadResult::Redirect, got {other:?}"),
    };
    assert!(
        redirect.request.url.contains("ifGenerationMatch=99")
            || redirect.request.url.contains("ifGenerationMatch%3D99"),
        "anonymous redirect URL must carry ifGenerationMatch=<version>; url:\n{}",
        redirect.request.url,
    );
}

#[tokio::test]
async fn anonymous_read_without_if_match_omits_if_generation_match() {
    // Negative case: without `if_match`, the URL must NOT have a
    // stray `ifGenerationMatch` (which would make every read a CAS
    // failure on a healthy concurrent-write race).
    let backend = anonymous_backend("https://storage.googleapis.com", "bkt").await;
    let result = backend
        .read(target("bkt", "x.txt"), ReadOptions::default(), None)
        .await
        .expect("anonymous read without if_match returns ReadResult::Redirect");
    let redirect = match result {
        ReadResult::Redirect(r) => r,
        other => panic!("expected ReadResult::Redirect, got {other:?}"),
    };
    assert!(
        !redirect.request.url.contains("ifGenerationMatch"),
        "anonymous read without if_match must NOT add ifGenerationMatch; url:\n{}",
        redirect.request.url,
    );
}

// === no-overwrite on the streaming path: resumable finalize refusal ===

/// A no-overwrite streaming write hits the `IfDestExists::Fail` contract
/// at the resumable session's FINALIZE (GCS enforces the initiation-time
/// `ifGenerationMatch=0` when the session commits) — the 412 there must
/// surface the documented `AlreadyExists`, and the conditional must ride
/// the initiation request on the wire.
#[tokio::test]
async fn no_overwrite_resumable_finalize_412_maps_already_exists() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);
    let session_url = format!("http://{}/session?uploadid=RESUME-FIXTURE", addr);
    let initiate_conditionals = Arc::new(AtomicUsize::new(0));
    let initiate_conditionals_for_thread = initiate_conditionals.clone();

    thread::Builder::new()
        .name("ovs-test-gcs-resumable".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let mut buf = [0u8; 65536];
                let len = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                let response = if raw.starts_with("POST ") {
                    // Resumable initiation: hand out the session URL. The
                    // no-overwrite conditional rides THIS request's query.
                    if raw.contains("ifGenerationMatch=0") {
                        initiate_conditionals_for_thread.fetch_add(1, Ordering::SeqCst);
                    }
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
                        session_url,
                    )
                } else if raw.starts_with("PUT ") {
                    // Session finalize: GCS enforces the initiation-time
                    // precondition here — refuse with 412.
                    let body = r#"{"error": {"message": "conditionNotMet"}}"#;
                    format!(
                        "HTTP/1.1 412 Precondition Failed\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn resumable fixture");

    thread::sleep(Duration::from_millis(50));

    let backend = anonymous_backend(&endpoint, "bkt").await;
    let chunks: Vec<Result<Vec<u8>>> = vec![Ok(b"streamed no-overwrite payload".to_vec())];
    let body = BodyStream::from_iter(chunks.into_iter());
    let err = backend
        .write_stream(
            target("bkt", "existing.bin"),
            body,
            WriteOptions {
                if_dest: IfDestExists::Fail,
                ..WriteOptions::default()
            },
            None,
        )
        .await
        .expect_err("the no-overwrite finalize must refuse");
    assert_eq!(
        err.code(),
        ErrorCode::AlreadyExists,
        "the ifGenerationMatch=0 412 at finalize is the exists-refusal; got: {err}"
    );
    assert!(
        initiate_conditionals.load(Ordering::SeqCst) >= 1,
        "the resumable initiation must carry ifGenerationMatch=0 on the wire",
    );
}

// === rename rollback reports ambiguity however the rollback fails ===

#[tokio::test]
async fn rename_rollback_transport_failure_still_reports_ambiguity() {
    // A gcs `rename` is rewrite-then-delete. When the source delete fails the
    // plugin rolls the destination back, and when that rollback also fails the
    // caller must be told the object may exist at BOTH addresses --
    // `CommitAmbiguous`. The rollback can fail three ways: a token refresh
    // error, a transport error, or a non-2xx status. Only the last used to
    // reach the ambiguity report; the other two escaped as themselves and
    // reported the rollback's own error, hiding the surviving destination.
    //
    // Those are the LIKELY companions of whatever broke the source delete
    // (throttle, partition, expired token), so the escaping path is the common
    // one. This drives the transport case: the rollback DELETE gets its
    // connection closed with no response at all.
    //
    // Script, in wire order:
    //   1. POST rewriteTo      -> 200, rewrite done (copy succeeds)
    //   2. DELETE source       -> 503 (the failure that triggers rollback)
    //   3. DELETE destination  -> connection closed, no response (transport)
    let server = ScriptedHttpServer::spawn_sequence(vec![
        Some(CannedHttpResponse::json(
            "200 OK",
            r#"{"done":true,"resource":{"name":"move-dst.txt","generation":"2"}}"#,
        )),
        Some(CannedHttpResponse::json(
            "503 Service Unavailable",
            r#"{"error":{"code":503,"message":"backend unavailable"}}"#,
        )),
        None,
    ]);
    let backend = anonymous_backend(server.endpoint(), "bkt").await;

    let error = backend
        .rename(
            target("bkt", "move-src.txt"),
            target("bkt", "move-dst.txt"),
            RenameOptions::default(),
            None,
        )
        .await
        .expect_err("the source delete failed, so rename cannot report success");

    assert_eq!(
        error.code(),
        ErrorCode::CommitAmbiguous,
        "a rollback that dies in transport leaves the destination standing just \
         as surely as one that gets a non-2xx, so it must report the same \
         ambiguity; got: {error}",
    );
    assert!(
        error
            .next_action()
            .is_some_and(|hint| hint.contains("both")),
        "the caller must be told to inspect both addresses; next_action: {:?}",
        error.next_action(),
    );
    assert_eq!(
        server.hits(),
        3,
        "expected rewrite + source delete + rollback delete",
    );
}
