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

use std::time::Duration;

use ovstorage_plugin::{
    ByteRange, CopyOptions, ErrorCode, ReadOptions, ReadResult, RenameOptions, WriteOptions,
};

use ovstorage_plugin_test::{CannedHttpResponse, ScriptedHttpServer};

/// Azure and Azurite stamp `x-ms-request-id` on every response; the acceptance
/// counter requires it, so a fixture standing in for the service sends it.
const AZURE_REQUEST_ID: &str = "5e4d6c0e-201e-0042-3a1f-1f0b7c000000";

mod support;
use support::{
    ProbeResponse, build_backend, build_backend_with_endpoint, build_hns_backend_with_endpoint,
    spawn_capture_server, spawn_stat_probe_server, target,
};

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

// === HNS directory refusal on read ===
//
// `Layer::read` owes a directory address `InvalidArgument` wherever
// `has_real_directories` is advertised, which for azure is exactly
// `hierarchical_namespace`. The rest of `read` mints a signed URL without
// touching the service, so the kind verdict costs one `getStatus` HEAD —
// bought on HNS connections only, and only ever able to turn a read into
// the contract's refusal.

/// The HNS `getStatus` verdict `directory` refuses the read with the
/// contract's `InvalidArgument` and `list()` guidance, and the refusal costs
/// exactly the one preflight RPC.
#[tokio::test]
async fn read_on_hns_directory_refuses_with_list_guidance() {
    let server = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("200 OK", "").with_header("x-ms-resource-type", "directory"),
    );
    let backend = build_hns_backend_with_endpoint("acct", "bkt", server.endpoint());
    let err = backend
        .read(target("acct", "bkt", "dir"), ReadOptions::default(), None)
        .await
        .expect_err("a directory address must be refused");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("list()"),
        "refusal must carry list() guidance: {}",
        err.message()
    );
    assert_eq!(server.hits(), 1, "the refusal costs one preflight");
}

/// A file verdict passes through to the redirect the slot has always
/// returned, having spent exactly one preflight RPC.
#[tokio::test]
async fn read_on_hns_file_redirects_after_one_preflight() {
    let server = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("200 OK", "").with_header("x-ms-resource-type", "file"),
    );
    let backend = build_hns_backend_with_endpoint("acct", "bkt", server.endpoint());
    let result = backend
        .read(
            target("acct", "bkt", "obj.txt"),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("a file address still reads");
    assert!(matches!(result, ReadResult::Redirect { .. }));
    assert_eq!(server.hits(), 1, "one preflight, then the signed URL");
}

/// A preflight the service REFUSES is no verdict: the read proceeds to the
/// redirect exactly as it would have without the probe, so a SAS scoped
/// narrower than the DFS path cannot turn a readable object into a failed read.
/// (The transport-failure arm is covered separately, below.) The directory case rides on the same branch: with
/// no verdict the plugin cannot tell a directory from a file, so it signs, and
/// the contract text says so rather than claiming a refusal it cannot make.
#[tokio::test]
async fn read_on_hns_redirects_when_the_preflight_is_refused() {
    let server = ScriptedHttpServer::spawn(
        CannedHttpResponse::xml("403 Forbidden", "<Error/>")
            .with_header("x-ms-error-code", "AuthorizationPermissionMismatch"),
    );
    let backend = build_hns_backend_with_endpoint("acct", "bkt", server.endpoint());
    let result = backend
        .read(
            target("acct", "bkt", "obj.txt"),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("a refused preflight must not fail the read");
    assert!(matches!(result, ReadResult::Redirect { .. }));
    assert_eq!(server.hits(), 1);
}

/// The other arm of "no verdict": a preflight that never gets a response at
/// all. `hns_reports_directory` has a distinct `Err(error)` arm for a transport
/// failure, and a regression that propagated it would turn a network blip into
/// a failed read of a perfectly readable object.
#[tokio::test]
async fn read_on_hns_redirects_when_the_preflight_cannot_connect() {
    // A port with nothing behind it: `send` fails before any response.
    let backend = build_hns_backend_with_endpoint("acct", "bkt", "http://127.0.0.1:1");
    let result = backend
        .read(
            target("acct", "bkt", "obj.txt"),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("a preflight that cannot connect must not fail the read");
    assert!(matches!(result, ReadResult::Redirect { .. }));
}

/// The third arm of "no verdict", and the expensive one: a `dfs` host that
/// accepts the connection and then never answers. Azure provisions private
/// endpoints per sub-resource, and the `privatelink.dfs` zone does not exist
/// on an account published on `blob` alone — so the public `dfs` address is
/// what resolves, and a VNet with no egress, or a firewall that drops rather
/// than rejects, blackholes it. A probe with no deadline of its own inherits
/// the 60s data-path client timeout, which holds a read that reaches the
/// service nowhere else for a full minute before failing open and signing the
/// same redirect. The bound is what keeps that cost proportionate; the probe
/// answers `false` either way.
///
/// The clock is paused, so the assertions read virtual time: the wait is the
/// probe's deadline, not the suite's runtime.
#[tokio::test(start_paused = true)]
async fn read_on_hns_bounds_a_preflight_that_never_answers() {
    // Accept the connection and hold it open, writing nothing back: `send`
    // neither succeeds nor fails, it just never returns.
    //
    // `bind` happens before the accepting thread exists, so the kernel
    // completes the handshake out of the listen backlog and the probe faces an
    // established connection whether or not the thread has reached `accept`.
    // The measurement does not rest on winning that race: a connect still in
    // flight leaves the probe with no answer too, and either way the only timer
    // the paused clock can reach is a deadline.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a blackhole listener");
    let endpoint = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });

    let backend = build_hns_backend_with_endpoint("acct", "bkt", &endpoint);
    let started = tokio::time::Instant::now();
    let result = backend
        .read(
            target("acct", "bkt", "obj.txt"),
            ReadOptions::default(),
            None,
        )
        .await
        .expect("a preflight that never answers must not fail the read");
    let waited = started.elapsed();

    assert!(matches!(result, ReadResult::Redirect { .. }));
    assert!(
        waited < Duration::from_secs(30),
        "the probe must have a deadline well short of the 60s data-path timeout, waited {waited:?}"
    );
    // The lower bound is what makes the upper bound mean something. Without it
    // a `read` that skipped the probe entirely — or one that reached a host
    // refusing the connection outright, which the sibling test above covers —
    // would satisfy this test while proving nothing about a deadline.
    assert!(
        waited >= Duration::from_secs(1),
        "the read must have waited on a probe and given up on it, not skipped it: {waited:?}"
    );
}

/// The kind probe addresses the DFS path the way this backend creates
/// directories: without the trailing slash. The host canonicalizes a directory
/// address WITH one, so a verbatim probe would ask about `/bkt/dir/` — a path
/// `create_directory` never writes — and, failing open, sign a redirect for a
/// directory anyway.
#[tokio::test]
async fn the_hns_kind_probe_normalizes_a_trailing_slash() {
    let server = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("200 OK", "")
            .with_header("x-ms-resource-type", "directory")
            .with_header("x-ms-request-id", AZURE_REQUEST_ID),
    );
    let backend = build_hns_backend_with_endpoint("acct", "bkt", server.endpoint());
    let err = backend
        .read(target("acct", "bkt", "dir/"), ReadOptions::default(), None)
        .await
        .expect_err("the slash spelling is a directory too");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    let probe = server.requests().first().cloned().expect("one probe");
    assert!(
        probe.contains("/bkt/dir?action=getStatus"),
        "the probe must address the slash-free DFS path: {probe}"
    );
}

/// The control that pins the cost: a flat-namespace connection advertises no
/// real directories, owes no kind verdict, and reaches the wire zero times.
#[tokio::test]
async fn read_on_flat_namespace_issues_no_preflight() {
    let server = ScriptedHttpServer::spawn(
        CannedHttpResponse::new("200 OK", "").with_header("x-ms-resource-type", "directory"),
    );
    let backend = build_backend_with_endpoint("acct", "bkt", server.endpoint());
    let result = backend
        .read(target("acct", "bkt", "dir"), ReadOptions::default(), None)
        .await
        .expect("a flat read never asks the service anything");
    assert!(matches!(result, ReadResult::Redirect { .. }));
    assert_eq!(server.hits(), 0, "flat namespaces pay nothing");
}

// === write_redirect size-hint requirement ===

#[tokio::test]
async fn write_redirect_unknown_size_returns_unsupported() {
    // Without `size_hint`, the plugin can't supply a finite
    // `Content-Length` for the presigned PUT (and on the staged path
    // can't enumerate block IDs up front), so it refuses — rather than
    // assuming `AZURE_BLOCK_BLOB_MAX_BYTES`, which would produce
    // mismatches at the follower — and the host routes through write_stream.
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

    let (endpoint, capture) = spawn_stat_probe_server(ProbeResponse::ok(EMPTY_LIST_BODY));
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

    let (endpoint, capture) = spawn_stat_probe_server(ProbeResponse::ok(MARKER_LIST_BODY));
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

    let (endpoint, _capture) = spawn_stat_probe_server(ProbeResponse::ok(EMPTY_LIST_BODY));
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

    let (endpoint, _capture) = spawn_stat_probe_server(ProbeResponse::ok(DESCENDANT_LIST_BODY));
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

    let (endpoint, _capture) =
        spawn_stat_probe_server(ProbeResponse::failure(403, "Forbidden", String::new()));
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
