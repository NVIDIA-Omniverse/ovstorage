// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for the S3 plugin's precondition contracts.
//!
//! Each test exercises one of the systemic enforcement patterns the
//! plugin is expected to honor (see `git show f1e1643 79ae38a 49bd04f
//! 088b129` for the underlying services-client review that motivated
//! them). The intent is twofold: prove the production code refuses
//! caller input that the S3 wire can't enforce, and pin the behaviors
//! that were already correct so a future refactor cannot silently
//! regress them.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use ovstorage_plugin::{
    BackendId, BodyStream, ByteRange, ConfigValue, CopyOptions, Error, ErrorCode, ReadOptions,
    ReadResult, RedirectResult, RedirectResultBatch, RenameOptions, ResolvedTarget, Result,
    WriteOptions, address,
};
use ovstorage_plugin_s3::{AwsCredentials, S3Backend};

// === Helpers ===

fn aws_credentials() -> AwsCredentials {
    AwsCredentials {
        access_key_id: "AKIATESTFIXTURE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
        session_token: None,
    }
}

fn build_backend(endpoint: &str, bucket: &str) -> Arc<S3Backend> {
    let mut config = HashMap::new();
    config.insert("bucket".into(), ConfigValue::String(bucket.into()));
    config.insert("region".into(), ConfigValue::String("us-east-1".into()));
    config.insert("endpoint".into(), ConfigValue::String(endpoint.into()));
    config.insert(
        "compatibility_profile".into(),
        ConfigValue::String("custom".into()),
    );
    config.insert("force_path_style".into(), ConfigValue::Bool(true));
    let parsed = ovstorage_plugin_s3::__test_only_parse_config(&config).expect("parse config");
    Arc::new(S3Backend::with_credentials(parsed, aws_credentials()).expect("backend init"))
}

fn target(bucket: &str, key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("s3:s3://{bucket}/")),
        resolved_address: address::parse(&format!("s3://{bucket}/{key}")).unwrap(),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => {
                request.extend_from_slice(&buf[..len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(
                    request.len() <= 65536,
                    "fake S3 request exceeded capture limit"
                );
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(_) => return None,
        }
    }
    (!request.is_empty()).then(|| String::from_utf8_lossy(&request).to_string())
}

// === Capture-style fake S3 server ===
//
// Spins up a TCP listener that records every request line and
// responds 200 to anything (no body for HEAD/DELETE, minimal XML for
// list/multipart). Sufficient for asserting "the right header /
// query parameter was emitted" without bringing in a full
// minio/localstack fixture.

#[derive(Clone, Default)]
struct CapturedRequest {
    raw: String,
}

impl CapturedRequest {
    fn has_header(&self, name: &str) -> bool {
        let needle = format!("\r\n{}: ", name.to_lowercase());
        self.raw.to_lowercase().contains(&needle)
    }

    fn header_value(&self, name: &str) -> Option<String> {
        let lower = self.raw.to_lowercase();
        let needle = format!("\r\n{}: ", name.to_lowercase());
        let start = lower.find(&needle)? + needle.len();
        let after = &self.raw[start..];
        let end = after.find("\r\n").unwrap_or(after.len());
        Some(after[..end].to_string())
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
        .name("ovs-test-s3-precondition".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let Some(raw) = read_http_request(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest { raw: raw.clone() });
                counter_for_thread.fetch_add(1, Ordering::SeqCst);
                let response = if raw.contains("?uploads") && raw.starts_with("POST ") {
                    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                                <InitiateMultipartUploadResult>\
                                <Bucket>bkt</Bucket><Key>big.bin</Key>\
                                <UploadId>UPLOAD-PRECONDITION</UploadId>\
                                </InitiateMultipartUploadResult>";
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    )
                } else if raw.contains("uploadId=UPLOAD-PRECONDITION") && raw.starts_with("POST ") {
                    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                                <CompleteMultipartUploadResult>\
                                <Bucket>bkt</Bucket><Key>big.bin</Key>\
                                <ETag>\"final-etag\"</ETag>\
                                </CompleteMultipartUploadResult>";
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    )
                } else {
                    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                                <CopyObjectResult><ETag>\"copied-etag\"</ETag>\
                                <LastModified>2026-01-01T00:00:00Z</LastModified></CopyObjectResult>";
                    format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nETag: \"fake-etag\"\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body,
                    )
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

fn spawn_stat_probe_server(list_status: u16, list_body: &'static str) -> (String, Capture) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);
    let capture = Capture::new();
    let requests_for_thread = capture.requests.clone();

    thread::Builder::new()
        .name("ovs-test-s3-stat-probe".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                let Some(raw) = read_http_request(&mut stream) else {
                    continue;
                };
                requests_for_thread
                    .lock()
                    .expect("capture poisoned")
                    .push(CapturedRequest { raw: raw.clone() });
                let response = if raw.starts_with("HEAD ") {
                    "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                } else if raw.starts_with("GET ") && raw.contains("list-type=2") {
                    format!(
                        "HTTP/1.1 {list_status} {}\r\nConnection: close\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        if list_status == 200 { "OK" } else { "Forbidden" },
                        list_body.len(),
                        list_body
                    )
                } else {
                    "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                };
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                drop(stream);
            }
        })
        .expect("spawn stat probe server");

    thread::sleep(Duration::from_millis(50));
    (endpoint, capture)
}

const EMPTY_LIST_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bkt</Name>
  <Prefix>missing/</Prefix>
  <Delimiter>/</Delimiter>
  <KeyCount>0</KeyCount>
  <MaxKeys>2</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;

const DESCENDANT_LIST_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bkt</Name>
  <Prefix>dir/</Prefix>
  <Delimiter>/</Delimiter>
  <KeyCount>1</KeyCount>
  <MaxKeys>2</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>dir/file.txt</Key>
    <LastModified>2024-01-02T03:04:05.000Z</LastModified>
    <ETag>"child"</ETag>
    <Size>1</Size>
  </Contents>
</ListBucketResult>"#;

const MARKER_LIST_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bkt</Name>
  <Prefix>dir/</Prefix>
  <Delimiter>/</Delimiter>
  <KeyCount>1</KeyCount>
  <MaxKeys>2</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>dir/</Key>
    <LastModified>2024-01-02T03:04:05.000Z</LastModified>
    <ETag>"marker"</ETag>
    <Size>0</Size>
  </Contents>
</ListBucketResult>"#;

const MARKER_AND_PREFIX_LIST_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bkt</Name>
  <Prefix></Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>foo/</Key>
    <LastModified>2024-01-02T03:04:05.000Z</LastModified>
    <ETag>"marker"</ETag>
    <Size>0</Size>
  </Contents>
  <CommonPrefixes>
    <Prefix>foo/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;

// === Conditional precondition enforcement ===
//
// The SPI's `if_match` is a single opaque etag string. These tests pin
// that the etag-only precondition path is accepted (not rejected) at
// the SPI entry points.

/// Sanity guard: etag-only `if_match` is the supported precondition
/// shape and must NOT be rejected. Exercised via `read` because the
/// read path produces a `ReadResult::Redirect` without touching the
/// wire, so we don't need an HTTP fixture.
#[tokio::test]
async fn read_accepts_etag_only_if_match() {
    let backend = build_backend("http://127.0.0.1:1", "bkt");
    backend
        .read(
            target("bkt", "x"),
            ReadOptions {
                if_match: Some("v1".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("etag-only if_match must be accepted");
}

// === write_redirect size-hint requirement ===

#[tokio::test]
async fn write_redirect_unknown_size_returns_unsupported() {
    // Without `size_hint`, the plugin can't supply a finite
    // `Content-Length` for the presigned PUT (or a part count for
    // multipart), so it refuses — rather than assuming
    // `S3_PUTOBJECT_MAX_BYTES`, which would produce mismatches at the
    // follower — and the host routes through write_stream instead.
    let backend = build_backend("http://127.0.0.1:1", "bkt");
    let err = backend
        .write_redirect(
            target("bkt", "x"),
            WriteOptions {
                size_hint: None,
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("missing size_hint must be refused");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

// === Range validation ===

#[tokio::test]
async fn read_range_inverted_returns_invalid_argument() {
    let backend = build_backend("http://127.0.0.1:1", "bkt");
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

// === Copy emits source-side x-amz-copy-source-if-match ===

#[tokio::test]
async fn copy_emits_source_if_match() {
    // S3's conditional-copy uses the source-side header. If the
    // plugin ever bound `if_match` to the destination's `If-Match`
    // instead, a same-key overwrite would atomic-mutate on the *new*
    // object's current state rather than the caller's expected
    // source identity. Pin both: header present, and with the
    // ETag-quoted value the caller supplied.
    let (endpoint, capture, _) = spawn_capture_server();
    let backend = build_backend(&endpoint, "bkt");

    backend
        .copy(
            target("bkt", "src.txt"),
            target("bkt", "dst.txt"),
            CopyOptions {
                if_source: Some("abc123".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("copy should succeed against the fake");

    let requests = capture.snapshot();
    let put = requests
        .iter()
        .find(|r| r.raw.starts_with("PUT "))
        .expect("expected a PUT for CopyObject");
    assert!(
        put.has_header("x-amz-copy-source-if-match"),
        "copy must emit source-side x-amz-copy-source-if-match; raw:\n{}",
        put.raw,
    );
    let value = put
        .header_value("x-amz-copy-source-if-match")
        .expect("conditional header should be readable");
    assert_eq!(
        value, "\"abc123\"",
        "conditional value must quote the ETag the caller supplied",
    );
    // Negative: must NOT bind the same conditional on the destination
    // side (would be `If-Match`).
    assert!(
        !put.has_header("if-match"),
        "destination-side If-Match must not leak when caller asked for source-side conditional; raw:\n{}",
        put.raw,
    );
}

// === write_stream propagates source errors ===

#[tokio::test]
async fn write_stream_propagates_source_error() {
    // A BodyStream chunk that errors mid-upload must surface from
    // write_stream as `Err` (not silently truncate). The
    // services-client review found `filter_map(|i| i.ok())` dropping
    // errors; this pins that pattern as absent from S3.
    let backend = build_backend("http://127.0.0.1:1", "bkt");
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
    // S3 may map the error code on the way out (e.g. via
    // map_error_status if the stream failure happens during an HTTP
    // call). The contract is just that the upload didn't silently
    // succeed.
    assert_ne!(err.code(), ErrorCode::Cancelled);
}

// === if_match enforcement on reads: read with if_match etag passes through to redirect URL ===

#[tokio::test]
async fn read_with_if_match_etag_passes_through_to_redirect_url() {
    // The read path returns `ReadResult::Redirect`. When the caller
    // sets an etag-only `if_match`, the plugin signs an `If-Match`
    // header into the presigned URL so the upstream S3 honors the
    // precondition. Pin that the header is on the request (and
    // therefore folded into the SigV4 signature).
    let backend = build_backend("http://127.0.0.1:9", "bkt");
    let result = backend
        .read(
            target("bkt", "x.txt"),
            ReadOptions {
                if_match: Some("abc".into()),
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
    let if_match = redirect
        .request
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("if-match"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        if_match.as_deref(),
        Some("\"abc\""),
        "read redirect must carry the quoted If-Match conditional",
    );
    // The presigned URL must also fold the conditional into the
    // signed-headers set (SigV4 requirement). Match on the
    // `SignedHeaders=` query parameter.
    assert!(
        redirect.request.url.to_lowercase().contains("if-match"),
        "presigned URL should sign the if-match header; url:\n{}",
        redirect.request.url,
    );
}

// === Multipart sizing (32 MiB target, balanced split,
//                       10 000-part cap) ===
//
// The math is unit-tested in `multipart::tests`; this integration
// test confirms the new sizing reaches `build_part_batch` end-to-end
// and the resulting redirect offsets/lengths form a valid prefix
// sum.

#[tokio::test]
async fn write_redirect_multipart_offsets_form_prefix_sum() {
    let (endpoint, _capture, _counter) = spawn_capture_server();
    let backend = build_backend(&endpoint, "bkt");

    // 100 MiB exactly = MULTIPART_REDIRECT_THRESHOLD_BYTES. At
    // 32 MiB target → 4 parts (32+32+32+4). Balanced split makes
    // each: base=25 MiB, rem=0… wait, 100/4=25 MiB exactly. Let's
    // use 200 MiB which is unambiguously multipart: 200/32 ceil = 7
    // parts of ~28.5 MiB each.
    let known_size: u64 = 200 * 1024 * 1024;
    let batch = backend
        .write_redirect(
            target("bkt", "big.bin"),
            WriteOptions {
                size_hint: Some(known_size),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("multipart write_redirect should succeed");

    assert!(
        batch.redirects.len() >= 2,
        "must be a multipart batch (got {} redirects)",
        batch.redirects.len(),
    );

    // Walk redirects and verify offsets are a strictly-increasing
    // prefix sum and lengths sum to `known_size`. Also confirm no
    // part exceeds the 5 GiB single-part cap.
    let max_part = 5u64 * 1024 * 1024 * 1024;
    let mut expected_offset: u64 = 0;
    let mut total: u64 = 0;
    for r in &batch.redirects {
        match &r.body_source {
            ovstorage_plugin::RedirectBodySource::UserBytes { offset, len } => {
                assert_eq!(
                    *offset, expected_offset,
                    "offset must equal prefix sum (got {offset}, expected {expected_offset})",
                );
                assert!(*len <= max_part, "no part may exceed 5 GiB");
                expected_offset += len;
                total += len;
            }
            other => panic!("expected UserBytes body_source, got {other:?}"),
        }
    }
    assert_eq!(
        total, known_size,
        "sum of part lengths must equal advertised total",
    );

    // Drain the upload so the multipart abort doesn't fire (cleanup
    // helps the capture-server thread quit promptly).
    let results: Vec<RedirectResult> = batch
        .redirects
        .iter()
        .enumerate()
        .map(|(i, _)| RedirectResult {
            status_code: 200,
            captured_headers: vec![("etag".into(), format!("\"part-etag-{}\"", i + 1))],
            captured_body: Vec::new(),
        })
        .collect();
    let _ = backend
        .continue_write(
            target("bkt", "big.bin"),
            batch,
            RedirectResultBatch { results },
            None,
        )
        .await;
}

// === Rename carries source if_match through delete ===
//
// S3 rename is conditional-copy + unconditional-delete. Pre-fix, a
// concurrent source mutation between the copy and the delete could
// be deleted, weakening the caller's source `if_match` precondition.
// The fix passes the same `if_match` through to the delete so both
// the PUT (copy) and the DELETE carry their respective conditional
// header.

#[tokio::test]
async fn rename_carries_source_precondition_through_delete() {
    let (endpoint, capture, _) = spawn_capture_server();
    let backend = build_backend(&endpoint, "bkt");

    let _ = backend
        .rename(
            target("bkt", "src.txt"),
            target("bkt", "dst.txt"),
            RenameOptions {
                if_source: Some("abc123".into()),
                ..Default::default()
            },
            None,
        )
        .await;

    let requests = capture.snapshot();
    // Copy phase: PUT carries the source-side conditional.
    let put = requests
        .iter()
        .find(|r| r.raw.starts_with("PUT "))
        .expect("expected a CopyObject PUT");
    assert!(
        put.has_header("x-amz-copy-source-if-match"),
        "copy must emit source-side x-amz-copy-source-if-match; raw:\n{}",
        put.raw,
    );
    let copy_value = put
        .header_value("x-amz-copy-source-if-match")
        .expect("copy conditional should be readable");
    assert_eq!(copy_value, "\"abc123\"");

    // Delete phase: DELETE carries `If-Match` so a concurrent source
    // mutation cannot bypass the caller's precondition.
    let delete = requests
        .iter()
        .find(|r| r.raw.starts_with("DELETE "))
        .expect("expected a DELETE for the source after copy");
    assert!(
        delete.has_header("if-match"),
        "delete must carry If-Match so a concurrent source mutation cannot bypass the caller's precondition; raw:\n{}",
        delete.raw,
    );
    let delete_value = delete
        .header_value("if-match")
        .expect("delete's If-Match header should be readable");
    assert_eq!(
        delete_value, "\"abc123\"",
        "delete's If-Match must quote the same ETag the caller supplied",
    );
}

// === Item 5 regression: stat tags directory shape correctly ===
//
// S3 is a flat namespace; the host dispatcher folds directory markers
// on `list`, not on `stat`. So a direct `stat` against a trailing-slash
// key must classify the result here. Hit → `DirectoryMarker` (a real
// zero-byte marker existed). Marker miss → bounded prefix-list probe;
// a marker returned by the probe still wins, otherwise only a proven
// descendant can become `DirectoryInferred`.

#[tokio::test]
async fn stat_with_trailing_slash_tags_marker_when_present() {
    use ovstorage_plugin::{ObjectKind, StatOptions};

    let (endpoint, _capture, _) = spawn_capture_server();
    let backend = build_backend(&endpoint, "bkt");

    let info = backend
        .stat(target("bkt", "dir/"), StatOptions::default(), None)
        .await
        .expect("HEAD against a trailing-slash key must succeed when the marker exists");
    assert_eq!(
        info.kind,
        ObjectKind::DirectoryMarker,
        "trailing-slash stat must surface DirectoryMarker, not File — the dispatcher's marker-fold only runs on `list`",
    );
}

#[tokio::test]
async fn stat_missing_trailing_slash_without_descendants_returns_not_found() {
    use ovstorage_plugin::StatOptions;

    let (endpoint, capture) = spawn_stat_probe_server(200, EMPTY_LIST_BODY);
    let backend = build_backend(&endpoint, "bkt");
    let err = backend
        .stat(target("bkt", "missing/"), StatOptions::default(), None)
        .await
        .expect_err("missing marker and empty prefix probe must be NotFound");
    assert_eq!(err.code(), ErrorCode::NotFound);
    let requests = capture.snapshot();
    assert!(
        requests.iter().any(|r| r.raw.starts_with("GET ")),
        "marker miss must issue a bounded ListObjectsV2 probe"
    );
}

#[tokio::test]
async fn stat_trailing_slash_marker_seen_during_prefix_probe_returns_marker() {
    use ovstorage_plugin::{ObjectKind, StatOptions};

    let (endpoint, capture) = spawn_stat_probe_server(200, MARKER_LIST_BODY);
    let backend = build_backend(&endpoint, "bkt");
    let info = backend
        .stat(target("bkt", "dir/"), StatOptions::default(), None)
        .await
        .expect("marker returned by the bounded prefix probe must classify as marker");
    assert_eq!(info.kind, ObjectKind::DirectoryMarker);
    assert_eq!(info.etag.as_deref(), Some("marker"));
    let requests = capture.snapshot();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.raw.starts_with("HEAD "))
            .count(),
        1,
        "the prefix-probe marker row is already enough; no retry HEAD needed"
    );
}

#[tokio::test]
async fn bare_missing_exact_and_fallback_slash_both_return_not_found() {
    use ovstorage_plugin::StatOptions;

    let (endpoint, _capture) = spawn_stat_probe_server(200, EMPTY_LIST_BODY);
    let backend = build_backend(&endpoint, "bkt");
    let err = backend
        .stat(target("bkt", "missing"), StatOptions::default(), None)
        .await
        .expect_err("exact missing object must be NotFound");
    assert_eq!(err.code(), ErrorCode::NotFound);
    let err = backend
        .stat(target("bkt", "missing/"), StatOptions::default(), None)
        .await
        .expect_err("dispatcher fallback slash probe must also be NotFound");
    assert_eq!(err.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn stat_trailing_slash_without_marker_with_descendant_is_inferred() {
    use ovstorage_plugin::{ObjectKind, StatOptions};

    let (endpoint, _capture) = spawn_stat_probe_server(200, DESCENDANT_LIST_BODY);
    let backend = build_backend(&endpoint, "bkt");
    let info = backend
        .stat(target("bkt", "dir/"), StatOptions::default(), None)
        .await
        .expect("descendant prefix probe must infer a directory");
    assert_eq!(info.kind, ObjectKind::DirectoryInferred);
}

#[tokio::test]
async fn stat_trailing_slash_propagates_prefix_probe_permission_error() {
    use ovstorage_plugin::StatOptions;

    let (endpoint, _capture) = spawn_stat_probe_server(403, "");
    let backend = build_backend(&endpoint, "bkt");
    let err = backend
        .stat(target("bkt", "missing/"), StatOptions::default(), None)
        .await
        .expect_err("prefix probe permission errors must not be guessed as missing/inferred");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn stat_without_trailing_slash_keeps_file_kind() {
    use ovstorage_plugin::{ObjectKind, StatOptions};

    let (endpoint, _capture, _) = spawn_capture_server();
    let backend = build_backend(&endpoint, "bkt");
    let info = backend
        .stat(target("bkt", "x.txt"), StatOptions::default(), None)
        .await
        .expect("HEAD against a non-slash key must succeed");
    assert_eq!(info.kind, ObjectKind::File);
}

#[tokio::test]
async fn recursive_list_keeps_directory_marker_and_skips_duplicate_inferred_prefix() {
    use ovstorage_plugin::{ListOptions, ObjectKind};

    let (endpoint, capture) = spawn_stat_probe_server(200, MARKER_AND_PREFIX_LIST_BODY);
    let backend = build_backend(&endpoint, "bkt");
    let items = backend
        .list(
            target("bkt", ""),
            ListOptions {
                recursive: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("recursive list should succeed");
    assert_eq!(
        items.len(),
        1,
        "same address must not be returned as both DirectoryMarker and DirectoryInferred"
    );
    assert_eq!(items[0].address.as_str(), "s3://bkt/foo/");
    assert_eq!(items[0].kind, ObjectKind::DirectoryMarker);
    assert_eq!(items[0].etag.as_deref(), Some("marker"));
    let requests = capture.snapshot();
    let get = requests
        .iter()
        .find(|r| r.raw.starts_with("GET "))
        .expect("expected ListObjectsV2 request");
    assert!(
        !get.raw.contains("delimiter="),
        "recursive S3 list must not request delimiter=/; raw:\n{}",
        get.raw
    );
}
