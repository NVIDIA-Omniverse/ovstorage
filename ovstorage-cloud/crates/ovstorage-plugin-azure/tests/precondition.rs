// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for the Azure plugin's precondition contracts.
//!
//! Mirrors the S3 plugin's `tests/precondition.rs` shape. Each test
//! exercises one of the systemic enforcement contracts the Azure
//! plugin honors (see `git show f1e1643 79ae38a 49bd04f 972530b
//! 8b32818` for the underlying services-client review that motivated
//! them). The intent is twofold: prove the production code refuses
//! caller input that the Azure wire can't enforce, and pin behaviors
//! that were already correct so a future refactor cannot silently
//! regress them.
//!
//! Azure's `If-Match` / `x-ms-source-if-match` carries an ETag only
//! (mirrors S3 in that respect); `size`, `mtime`, `version` are not
//! enforceable on the wire and the helper refuses them at every entry
//! point.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use ovstorage_plugin::{
    BackendId, ByteRange, ConfigValue, CopyOptions, ErrorCode, ReadOptions, ReadResult,
    RenameOptions, ResolvedTarget, SecretBundle, SecretBytes, SecretValue, WriteOptions, address,
    shim::Backend,
};
use ovstorage_plugin_azure::AzureBackend;

// === Helpers ===

fn shared_key_bundle() -> SecretBundle {
    // Encoded Shared-Key with deterministic bytes; the value doesn't
    // matter for these tests because we never round-trip a real SAS
    // signature back to Azure — the fake server below ignores them.
    let key = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
    let mut bundle = SecretBundle::default();
    bundle.fields.insert(
        "account_key".into(),
        SecretValue::Bytes(SecretBytes(key.into_bytes())),
    );
    bundle
}

fn build_backend(account: &str, container: &str) -> Arc<AzureBackend> {
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String(account.into()));
    config.insert("container".into(), ConfigValue::String(container.into()));
    let parsed =
        ovstorage_plugin_azure::__test_only_parse_config(&config).expect("parse azure config");
    Arc::new(
        ovstorage_plugin_azure::__test_only_with_credentials(parsed, shared_key_bundle())
            .expect("backend init"),
    )
}

fn target(account: &str, container: &str, key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId(format!("azure:{account}:{container}")),
        resolved_address: address::parse(&format!("azure://{account}/{container}/{key}")).unwrap(),
    }
}

// === Capture-style fake Azure server ===
//
// Spins up a TCP listener that records every request line + headers
// and responds 201 (or 200) to anything with minimal headers Azure
// returns from a successful Copy/Put. Sufficient for asserting "the
// right header / query parameter was emitted" without bringing in an
// Azurite fixture. Each accepted connection serves exactly one
// request, then closes.

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

#[allow(dead_code)]
fn spawn_capture_server() -> (String, Capture, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("http://{}", addr);
    let capture = Capture::new();
    let requests_for_thread = capture.requests.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_for_thread = counter.clone();

    thread::Builder::new()
        .name("ovs-test-azure-precondition".into())
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
                let response =
                    "HTTP/1.1 202 Accepted\r\nETag: \"fake-etag\"\r\nLast-Modified: Wed, 01 Jan 2026 00:00:00 GMT\r\nx-ms-copy-status: success\r\nContent-Length: 0\r\n\r\n";
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
        .name("ovs-test-azure-stat-probe".into())
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
                let response = if raw.starts_with("HEAD ") {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                } else if raw.starts_with("GET ") && raw.contains("comp=list") {
                    format!(
                        "HTTP/1.1 {list_status} {}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{}",
                        if list_status == 200 { "OK" } else { "Forbidden" },
                        list_body.len(),
                        list_body
                    )
                } else {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_string()
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

const EMPTY_LIST_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://127.0.0.1/" ContainerName="bkt">
  <Prefix>missing/</Prefix>
  <Delimiter>/</Delimiter>
  <Blobs />
  <NextMarker />
</EnumerationResults>"#;

const DESCENDANT_LIST_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://127.0.0.1/" ContainerName="bkt">
  <Prefix>dir/</Prefix>
  <Delimiter>/</Delimiter>
  <Blobs>
    <Blob>
      <Name>dir/file.txt</Name>
      <Properties>
        <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>
        <Etag>0x8DC0A</Etag>
        <Content-Length>1</Content-Length>
      </Properties>
    </Blob>
  </Blobs>
  <NextMarker />
</EnumerationResults>"#;

const MARKER_LIST_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://127.0.0.1/" ContainerName="bkt">
  <Prefix>dir/</Prefix>
  <Delimiter>/</Delimiter>
  <Blobs>
    <Blob>
      <Name>dir/</Name>
      <Properties>
        <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>
        <Etag>0xMARKER</Etag>
        <Content-Length>0</Content-Length>
      </Properties>
    </Blob>
  </Blobs>
  <NextMarker />
</EnumerationResults>"#;

// === Conditional precondition enforcement ===
//
// The SPI's `if_match` is a single opaque etag string. These tests pin
// that the etag-only precondition path is accepted (not rejected) at
// the SPI entry points.

/// Sanity guard: etag-only `if_match` is the supported precondition
/// shape and must NOT be rejected. Exercised via `read` because the
/// read path produces a `ReadResult::Redirect` without touching the
/// wire, so no HTTP fixture is needed.
#[tokio::test]
async fn read_accepts_etag_only_if_match() {
    let backend = build_backend("acct", "bkt");
    backend
        .read(
            target("acct", "bkt", "x"),
            ReadOptions {
                if_match: Some("abc".into()),
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
    // `Content-Length` for the presigned PUT (and on the staged path
    // can't enumerate block IDs up front). Previously fell back to
    // `AZURE_BLOCK_BLOB_MAX_BYTES` and produced mismatches at the
    // follower; now refuses so the host routes through write_stream.
    let backend = build_backend("acct", "bkt");
    let err = backend
        .write_redirect(
            target("acct", "bkt", "x"),
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
    let backend = build_backend("acct", "bkt");
    let err = backend
        .read(
            target("acct", "bkt", "x"),
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

// === Flat namespace stat directory proof ===
//
// On flat Azure Blob accounts, a trailing-slash marker HEAD can prove
// `DirectoryMarker`. A marker miss must not invent an inferred
// directory; it must run a bounded list probe and only infer a
// directory when a descendant is visible. If the probe itself sees the
// marker, the marker still wins.

#[tokio::test]
async fn stat_missing_trailing_slash_without_descendants_returns_not_found() {
    use ovstorage_plugin::StatOptions;

    let (endpoint, capture) = spawn_stat_probe_server(200, EMPTY_LIST_BODY);
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let err = backend
        .stat(
            target("acct", "bkt", "missing/"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("missing marker and empty prefix probe must be NotFound");
    assert_eq!(err.code(), ErrorCode::NotFound);
    let requests = capture.snapshot();
    assert!(
        requests.iter().any(|r| r.raw.starts_with("GET ")),
        "marker miss must issue a bounded List Blobs probe"
    );
}

#[tokio::test]
async fn stat_trailing_slash_marker_seen_during_prefix_probe_returns_marker() {
    use ovstorage_plugin::{ObjectKind, StatOptions};

    let (endpoint, capture) = spawn_stat_probe_server(200, MARKER_LIST_BODY);
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let info = backend
        .stat(target("acct", "bkt", "dir/"), StatOptions::default(), None)
        .await
        .expect("marker returned by the bounded prefix probe must classify as marker");
    assert_eq!(info.kind, ObjectKind::DirectoryMarker);
    assert_eq!(info.etag.as_deref(), Some("0xMARKER"));
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
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let err = backend
        .stat(
            target("acct", "bkt", "missing"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("exact missing blob must be NotFound");
    assert_eq!(err.code(), ErrorCode::NotFound);
    let err = backend
        .stat(
            target("acct", "bkt", "missing/"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("dispatcher fallback slash probe must also be NotFound");
    assert_eq!(err.code(), ErrorCode::NotFound);
}

#[tokio::test]
async fn stat_trailing_slash_without_marker_with_descendant_is_inferred() {
    use ovstorage_plugin::{ObjectKind, StatOptions};

    let (endpoint, _capture) = spawn_stat_probe_server(200, DESCENDANT_LIST_BODY);
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let info = backend
        .stat(target("acct", "bkt", "dir/"), StatOptions::default(), None)
        .await
        .expect("descendant prefix probe must infer a directory");
    assert_eq!(info.kind, ObjectKind::DirectoryInferred);
}

#[tokio::test]
async fn stat_trailing_slash_propagates_prefix_probe_permission_error() {
    use ovstorage_plugin::StatOptions;

    let (endpoint, _capture) = spawn_stat_probe_server(403, "");
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let err = backend
        .stat(
            target("acct", "bkt", "missing/"),
            StatOptions::default(),
            None,
        )
        .await
        .expect_err("prefix probe permission errors must not be guessed as missing/inferred");
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
}

// === Copy emits source-side x-ms-source-if-match ===

#[tokio::test]
async fn copy_emits_source_if_match() {
    // Azure's conditional-copy uses `x-ms-source-if-match` on the
    // source side. If the plugin ever bound `if_match` to the
    // destination's `If-Match` instead, a same-key overwrite would
    // atomic-mutate on the *new* object's current state rather than
    // the caller's expected source identity. Pin both: header
    // present, and with the ETag-quoted value the caller supplied.
    let (endpoint, capture, _) = spawn_capture_server();
    // Spin a backend whose blob host points at the fake server.
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let _ = backend
        .copy(
            target("acct", "bkt", "src.txt"),
            target("acct", "bkt", "dst.txt"),
            CopyOptions {
                if_source: Some("abc123".into()),
                ..Default::default()
            },
            None,
        )
        .await;

    let requests = capture.snapshot();
    let put = requests
        .iter()
        .find(|r| r.raw.starts_with("PUT "))
        .expect("expected a PUT for Copy Blob");
    assert!(
        put.has_header("x-ms-source-if-match"),
        "copy must emit source-side x-ms-source-if-match; raw:\n{}",
        put.raw,
    );
    let value = put
        .header_value("x-ms-source-if-match")
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

// === if_match enforcement on reads: etag passes through to redirect URL ===

#[tokio::test]
async fn read_with_if_match_etag_passes_through_to_redirect_url() {
    // The read path returns `ReadResult::Redirect`. When the caller
    // sets an etag-only `if_match`, the plugin signs an `If-Match`
    // header into the request so the upstream Azure honors the
    // precondition. Pin that the header is on the request handed back
    // to the host follower.
    let backend = build_backend("acct", "bkt");
    let result = backend
        .read(
            target("acct", "bkt", "x.txt"),
            ReadOptions {
                if_match: Some("\"abc\"".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("read should succeed (returns SAS redirect)");
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
}

// === write_stream propagates source errors ===

#[tokio::test]
async fn write_stream_propagates_source_error() {
    // The block-staging path in `write_stream` must propagate a
    // mid-upload body-source error rather than dropping it (no
    // `filter_map(|i| i.ok())` antipattern): the first chunk lands in
    // the staging buffer below the 4 MiB block size, the second
    // iteration returns the error, and the function returns Err
    // before any block is committed.
    use ovstorage_plugin::{BodyStream, Error, Result};
    let backend = build_backend("acct", "bkt");
    let chunks: Vec<Result<Vec<u8>>> = vec![
        Ok(b"first chunk".to_vec()),
        Err(Error::new(ErrorCode::Transient, "synthetic source error")),
    ];
    let body = BodyStream::from_iter(chunks.into_iter());
    let err = backend
        .write_stream(
            target("acct", "bkt", "partial.bin"),
            body,
            WriteOptions::default(),
            None,
        )
        .await
        .expect_err("write_stream must NOT silently succeed");
    // The body source's `Transient` propagates through; only the
    // negative-space contract matters here.
    assert_ne!(err.code(), ErrorCode::Cancelled);
}

// === list_versions pagination ===

#[tokio::test]
async fn list_versions_paginates() {
    // list_versions threads `opts.max_results` and `opts.page_token`
    // into Azure REST's `maxresults` and `marker` query params. We
    // assert both are wired by pointing the backend at a fake server
    // that captures the request line, then verifying both query
    // parameters appear.
    let (endpoint, capture, _) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let _ = backend
        .list_versions(
            target("acct", "bkt", "blob.bin"),
            ovstorage_plugin::ListVersionsOptions {
                max_results: Some(5),
                page_token: Some("marker-abc".into()),
            },
            None,
        )
        .await;
    let requests = capture.snapshot();
    let get = requests
        .iter()
        .find(|r| r.raw.starts_with("GET "))
        .expect("expected a GET for list_versions");
    let line = get.raw.lines().next().unwrap_or("");
    assert!(
        line.contains("maxresults=5"),
        "list_versions must wire max_results to Azure REST's maxresults; raw line:\n{line}",
    );
    assert!(
        line.contains("marker=marker-abc"),
        "list_versions must wire page_token to Azure REST's marker; raw line:\n{line}",
    );
    assert!(
        line.contains("include=versions"),
        "list_versions must request version-listing; raw line:\n{line}",
    );
}

// === write_stream supports unknown-size uploads ===
//
// Historically Azure had no `write_stream` impl; the SPI default
// surfaced `Unsupported`. Combined with `write_redirect` refusing
// `size_hint.is_none()` (see "write_redirect size-hint requirement"
// above), unknown-size streaming uploads would fail entirely. The
// block-staging API is wired into `write_stream`: chunks are buffered
// into 4 MiB blocks, each `Put Block`'d in order, then a final
// `Put Block List` finalizes the blob.

#[tokio::test]
async fn write_stream_succeeds_with_unknown_size() {
    use ovstorage_plugin::BodyStream;
    let (endpoint, capture, _) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);
    let chunks: Vec<ovstorage_plugin::Result<Vec<u8>>> =
        vec![Ok(b"hello ".to_vec()), Ok(b"world".to_vec())];
    let body = BodyStream::from_iter(chunks.into_iter());
    backend
        .write_stream(
            target("acct", "bkt", "stream.bin"),
            body,
            WriteOptions {
                size_hint: None,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("unknown-size streaming write should succeed via block staging");

    let requests = capture.snapshot();
    // Expect at least one PutBlock (the trailing short block) and one
    // PutBlockList commit. The PutBlock carries `comp=block&blockid=`
    // and the commit carries `comp=blocklist`.
    let put_block = requests.iter().find(|r| {
        r.raw.starts_with("PUT ")
            && r.raw.lines().next().unwrap_or("").contains("comp=block")
            && r.raw.lines().next().unwrap_or("").contains("blockid=")
    });
    assert!(
        put_block.is_some(),
        "expected at least one Put Block request; saw:\n{}",
        requests
            .iter()
            .map(|r| r.raw.lines().next().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    );
    let put_block_list = requests.iter().find(|r| {
        r.raw.starts_with("PUT ")
            && r.raw
                .lines()
                .next()
                .unwrap_or("")
                .contains("comp=blocklist")
    });
    assert!(
        put_block_list.is_some(),
        "expected a Put Block List commit; saw:\n{}",
        requests
            .iter()
            .map(|r| r.raw.lines().next().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

// === Non-HNS rename carries source if_match through delete ===
//
// Azure non-HNS rename is copy-then-delete. If the delete went out
// unconditionally, a concurrent source mutation between the
// successful conditional-copy and the delete would let the delete
// proceed, breaking the caller's source `if_match` precondition. The
// same `if_match` is passed to the delete so both wire calls carry
// the conditional.

#[tokio::test]
async fn rename_carries_source_precondition_through_delete() {
    let (endpoint, capture, _) = spawn_capture_server();
    // Non-HNS by default (no hierarchical_namespace flag set).
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let _ = backend
        .rename(
            target("acct", "bkt", "src.txt"),
            target("acct", "bkt", "dst.txt"),
            RenameOptions {
                if_source: Some("abc123".into()),
                ..Default::default()
            },
            None,
        )
        .await;

    let requests = capture.snapshot();
    // Copy is a PUT with x-ms-source-if-match (source-side
    // conditional) — pinned by `copy_emits_source_if_match`. Delete is
    // a DELETE with `If-Match` on the destination's request, which on
    // a non-HNS rename targets the source blob.
    let put = requests
        .iter()
        .find(|r| r.raw.starts_with("PUT "))
        .expect("expected a Copy Blob PUT");
    assert!(
        put.has_header("x-ms-source-if-match"),
        "copy must emit source-side x-ms-source-if-match; raw:\n{}",
        put.raw,
    );

    let delete = requests
        .iter()
        .find(|r| r.raw.starts_with("DELETE "))
        .expect("expected a DELETE for the source after copy");
    assert!(
        delete.has_header("if-match"),
        "delete must carry If-Match so a concurrent source mutation cannot bypass the caller's precondition; raw:\n{}",
        delete.raw,
    );
    let value = delete
        .header_value("if-match")
        .expect("If-Match header should be readable");
    // The SPI documents `if_match` as the raw ETag value the backend
    // handed back; the Azure plugin routes every conditional header
    // through `quote_etag` before sending so Azure receives the
    // RFC 7232 entity-tag shape. Pin the on-wire value so a future
    // refactor that drops quoting (or double-quotes a pre-quoted
    // input) shows up here.
    assert_eq!(
        value, "\"abc123\"",
        "delete's If-Match must carry the caller's ETag in RFC 7232 entity-tag shape",
    );
}

// === Item 3 regression: every If-Match send-site uses entity-tag quoting ===
//
// Azure rejects unquoted `If-Match`/`If-None-Match` values; the SPI
// documents `if_match` as the raw ETag value the backend handed back,
// so the plugin must add the RFC 7232 entity-tag quotes at every
// send-site. The fix routes through `quote_etag` inside
// `AzureClient::send`, so every `AzureRequest.if_match` populator —
// `write`, `write_stream`, `delete`, `rename`'s second leg, etc. —
// inherits the correct shape.

#[tokio::test]
async fn write_quotes_if_match_on_destination_precondition() {
    use ovstorage_plugin::IfDestExists;

    let (endpoint, capture, _) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let _ = backend
        .write(
            target("acct", "bkt", "x.txt"),
            b"hello".to_vec(),
            WriteOptions {
                if_dest: IfDestExists::MatchEtag("plain-etag".into()),
                ..Default::default()
            },
            None,
        )
        .await;

    let requests = capture.snapshot();
    let put = requests
        .iter()
        .find(|r| r.raw.starts_with("PUT "))
        .expect("expected a Put Blob PUT");
    let value = put
        .header_value("if-match")
        .expect("write with MatchEtag must emit If-Match");
    assert_eq!(
        value, "\"plain-etag\"",
        "If-Match must round-trip a raw etag through quote_etag into RFC 7232 entity-tag shape",
    );
}

#[tokio::test]
async fn write_does_not_double_quote_already_quoted_if_match() {
    // Azure's `Get Blob Properties` returns quoted ETags; `parse_object_info`
    // strips quotes inbound (`strip_quotes`). A future caller that re-passes
    // the raw header value (still quoted) must not be double-quoted.
    use ovstorage_plugin::IfDestExists;

    let (endpoint, capture, _) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "bkt", &endpoint);

    let _ = backend
        .write(
            target("acct", "bkt", "x.txt"),
            b"hello".to_vec(),
            WriteOptions {
                if_dest: IfDestExists::MatchEtag("\"already-quoted\"".into()),
                ..Default::default()
            },
            None,
        )
        .await;

    let requests = capture.snapshot();
    let put = requests
        .iter()
        .find(|r| r.raw.starts_with("PUT "))
        .expect("expected a Put Blob PUT");
    let value = put
        .header_value("if-match")
        .expect("write must emit If-Match");
    assert_eq!(
        value, "\"already-quoted\"",
        "quote_etag must be a no-op on a pre-quoted value",
    );
}

// === Endpoint-override helper for capture-server-backed tests ===
//
// The Azure plugin normally builds URLs as
// `https://{account}.blob.{endpoint_suffix}/...` from the config. The
// `__test_only_with_endpoint_override` hook replaces that base with
// e.g. `http://127.0.0.1:NNNN` so requests route at a capture-style
// fake server over plain HTTP. The Shared-Key signing layer doesn't
// depend on the host, only on the account / container / path, so the
// signature still encodes correctly even though the wire socket lives
// on loopback.

fn build_backend_with_endpoint(
    account: &str,
    container: &str,
    endpoint: &str,
) -> Arc<AzureBackend> {
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String(account.into()));
    config.insert("container".into(), ConfigValue::String(container.into()));
    let parsed =
        ovstorage_plugin_azure::__test_only_parse_config(&config).expect("parse azure config");
    let parsed =
        ovstorage_plugin_azure::__test_only_with_endpoint_override(parsed, endpoint.to_string());
    Arc::new(
        ovstorage_plugin_azure::__test_only_with_credentials(parsed, shared_key_bundle())
            .expect("backend init"),
    )
}
