// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire-shape coverage for the `blob_endpoint` / `dfs_endpoint`
//! connection-config keys.
//!
//! Azurite (and every other emulator or reverse-proxied deployment)
//! addresses storage path-style: the account is the first path segment
//! rather than a DNS label, so a request for `key` in container `assets` on
//! account `devstoreaccount1` goes out as `/devstoreaccount1/assets/key`.
//! Shared Key canonicalizes as `/{account}` plus the request URI path, so
//! the endpoint's path prefix has to reach the signer too — miss it and
//! every signed request comes back 403.
//!
//! These tests pin that shape without needing a live emulator. The backend
//! is built purely from public config keys and driven at the capture-style
//! fake server in `tests/support`, configured with the same account key the
//! backend signs with: it re-derives each Shared Key signature from the
//! bytes on the wire and answers 403 on a mismatch, so a prefix that is
//! addressed but not signed (or signed but not addressed) fails the
//! operation rather than slipping past on a header that merely *looks*
//! right.
//!
//! The DFS case runs a second listener on its own port so a regression that
//! routed the HNS tier back at the blob endpoint shows up as "no request
//! arrived here" rather than a subtly wrong URL.

mod support;

use ovstorage_plugin::{
    ConfigValue, CreateDirectoryOptions, ErrorCode, ListOptions, ResolvedTarget, WriteOptions,
};
use std::sync::Arc;

use support::{Capture, FakeAzure, SharedKeySigner, SharedKeyVerdict};

const ACCOUNT: &str = "devstoreaccount1";
const CONTAINER: &str = "assets";

const EMPTY_LIST_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://127.0.0.1/" ContainerName="assets">
  <Prefix></Prefix>
  <Delimiter>/</Delimiter>
  <Blobs />
  <NextMarker />
</EnumerationResults>"#;

/// A signature-verifying listener: a container list gets a well-formed empty
/// `EnumerationResults` so the list path parses, everything else gets the
/// 201 + `ETag` / `Last-Modified` pair Azure returns from a successful Put
/// Blob or ADLS Gen2 Path Create.
fn spawn_emulator(label: &str) -> FakeAzure {
    support::spawn_fake_azure(label, Some(SharedKeySigner::new(ACCOUNT)), |raw| {
        // Dispatch on the parsed request line for the same reason the
        // assertions below parse it: a target carrying `xcomp=list` must not
        // be answered as though it were a well-formed List Blobs.
        if support::request_query_param(raw, "comp").as_deref() == Some("list") {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                EMPTY_LIST_BODY.len(),
                EMPTY_LIST_BODY,
            )
        } else {
            "HTTP/1.1 201 Created\r\nETag: \"fake-etag\"\r\nLast-Modified: Wed, 01 Jan 2026 00:00:00 GMT\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_string()
        }
    })
}

fn build_backend(pairs: &[(&str, ConfigValue)]) -> Arc<ovstorage_plugin_azure::AzureBackend> {
    support::build_backend_from_config(support::config_map(ACCOUNT, CONTAINER, pairs))
}

fn target(key: &str) -> ResolvedTarget {
    support::target(ACCOUNT, CONTAINER, key)
}

fn parse_config_err(pairs: &[(&str, ConfigValue)]) -> ovstorage_plugin::Error {
    ovstorage_plugin_azure::__test_only_parse_config(&support::config_map(
        ACCOUNT, CONTAINER, pairs,
    ))
    .err()
    .unwrap_or_else(|| panic!("expected config {pairs:?} to be rejected"))
}

/// Every captured request must have verified as `SharedKey {account}:...`
/// against the fixture's own re-derivation.
fn assert_signatures_verified(capture: &Capture) {
    for request in capture.snapshot() {
        match &request.shared_key {
            SharedKeyVerdict::Valid => {}
            SharedKeyVerdict::Mismatch { string_to_sign } => panic!(
                "Shared Key signature does not cover the URI that was sent.\n\
                 request line: {}\nfixture expected to sign:\n{string_to_sign}",
                request.request_line(),
            ),
            other => panic!(
                "expected a verified Shared Key signature on {}, got {other:?}",
                request.request_line(),
            ),
        }
    }
}

// === Path-style blob-tier addressing and Shared Key signing ===

#[tokio::test]
async fn write_uses_path_style_addressing_and_signs_shared_key() {
    let server = spawn_emulator("azurite-write");
    let backend = build_backend(&[(
        "blob_endpoint",
        ConfigValue::String(format!("{}/{ACCOUNT}", server.endpoint)),
    )]);

    // The fixture answers 403 unless the signature covers the URI it saw, so
    // a successful write is itself the proof that the path prefix reached
    // the signer.
    backend
        .write(
            target("dir/file.txt"),
            b"hello".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("path-style Put Blob should be signed correctly and succeed");

    let put = server.capture.expect_one("PUT");
    // Account segment first, then container, then the key: the whole point
    // of a path-style endpoint. A regression that dropped the endpoint's
    // path prefix would land on `/assets/dir/file.txt`.
    assert_eq!(
        put.path(),
        format!("/{ACCOUNT}/{CONTAINER}/dir/file.txt"),
        "path-style endpoint must address {{account}}/{{container}}/{{key}}; raw line:\n{}",
        put.request_line(),
    );
    let authorization = put
        .header_value("authorization")
        .expect("Shared Key requests must carry an Authorization header");
    assert!(
        authorization.starts_with(&format!("SharedKey {ACCOUNT}:")),
        "expected a Shared Key authorization for the configured account, got {authorization:?}",
    );
    assert_signatures_verified(&server.capture);
}

#[tokio::test]
async fn list_uses_path_style_container_addressing() {
    let server = spawn_emulator("azurite-list");
    let backend = build_backend(&[(
        "blob_endpoint",
        ConfigValue::String(format!("{}/{ACCOUNT}", server.endpoint)),
    )]);

    backend
        .list(target(""), ListOptions::default(), None)
        .await
        .expect("path-style List Blobs should be signed correctly and parse");

    let get = server.capture.expect_one("GET");
    assert_eq!(
        get.path(),
        format!("/{ACCOUNT}/{CONTAINER}"),
        "container-level requests stop at the container under the endpoint prefix; raw line:\n{}",
        get.request_line(),
    );
    // Parsed into key/value pairs, not substring-searched: `?xrestype=...`
    // contains the same text while naming a parameter Azure ignores.
    for (name, expected) in [("restype", "container"), ("comp", "list")] {
        assert_eq!(
            get.query_param(name).as_deref(),
            Some(expected),
            "List Blobs must send {name}={expected}; raw line:\n{}",
            get.request_line(),
        );
    }
    // The container-level canonical path and the query parameters are both
    // part of the canonicalized resource, so this covers them together.
    assert_signatures_verified(&server.capture);
}

/// A prefix AND a key that both need percent-escaping.
///
/// Everything else in this suite is encoding-invariant, so nothing else here
/// can tell the encoded and decoded forms apart — which is precisely how a
/// raw-key signature survived beside an encoding `blob_url`, with the
/// verifier decoding the wire path and agreeing with it. Azure canonicalizes
/// URI-derived parts of the resource "encoded exactly as it is in the URI",
/// the fixture now canonicalizes the wire path verbatim, and this case makes
/// the two meet.
#[tokio::test]
async fn an_escaped_prefix_and_key_are_signed_in_the_form_the_uri_carries() {
    let server = spawn_emulator("azurite-escaped");
    let backend = build_backend(&[(
        "blob_endpoint",
        // A literal space, as an operator would write it behind a reverse
        // proxy whose mount point has one.
        ConfigValue::String(format!("{}/team one/{ACCOUNT}", server.endpoint)),
    )]);

    backend
        .write(
            target("dir/a b+c.txt"),
            b"hello".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .expect("an escaped prefix and key must still produce a signature Azure reproduces");

    let put = server.capture.expect_one("PUT");
    assert_eq!(
        put.path(),
        format!("/team%20one/{ACCOUNT}/{CONTAINER}/dir/a%20b%2Bc.txt"),
        "the request URI must carry both the prefix and the key encoded; raw line:\n{}",
        put.request_line(),
    );
    // The decisive half: the fixture canonicalizes the wire path verbatim,
    // so this passes only if the plugin signed exactly those bytes.
    assert_signatures_verified(&server.capture);
}

// === DFS tier routes at its own endpoint ===

#[tokio::test]
async fn hns_path_operation_lands_on_the_dfs_endpoint() {
    // Two listeners on distinct ports with distinct path prefixes: a
    // regression that routed the HNS tier through `blob_endpoint` shows up
    // as an empty DFS capture rather than a near-miss URL.
    let blob = spawn_emulator("azurite-hns-blob");
    let dfs = spawn_emulator("azurite-hns-dfs");
    let backend = build_backend(&[
        ("hierarchical_namespace", ConfigValue::Bool(true)),
        (
            "blob_endpoint",
            ConfigValue::String(format!("{}/blob/{ACCOUNT}", blob.endpoint)),
        ),
        (
            "dfs_endpoint",
            ConfigValue::String(format!("{}/dfs/{ACCOUNT}", dfs.endpoint)),
        ),
    ]);

    backend
        .create_directory(target("dir"), CreateDirectoryOptions::default(), None)
        .await
        .expect("ADLS Gen2 Path Create should be signed correctly and succeed");

    let put = dfs.capture.expect_one("PUT");
    assert_eq!(
        put.path(),
        format!("/dfs/{ACCOUNT}/{CONTAINER}/dir"),
        "the DFS tier must use the dfs_endpoint's own path prefix; raw line:\n{}",
        put.request_line(),
    );
    assert_eq!(
        put.query_param("resource").as_deref(),
        Some("directory"),
        "HNS create_directory must be an ADLS Gen2 directory Path Create; raw line:\n{}",
        put.request_line(),
    );
    // Signed against the DFS prefix, not the blob one — the two tiers carry
    // different prefixes here precisely so a mix-up cannot verify.
    assert_signatures_verified(&dfs.capture);
    assert!(
        blob.capture.snapshot().is_empty(),
        "no HNS path operation may reach the blob endpoint; saw:\n{}",
        support::render(&blob.capture.snapshot()),
    );
}

// === Rejections ===

#[test]
fn hns_blob_endpoint_without_a_dfs_endpoint_is_rejected() {
    let err = parse_config_err(&[
        ("hierarchical_namespace", ConfigValue::Bool(true)),
        (
            "blob_endpoint",
            ConfigValue::String("http://azurite:10000/devstoreaccount1".into()),
        ),
    ]);
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        err.message().contains("dfs_endpoint"),
        "the rejection must name the key the caller has to add, got {:?}",
        err.message(),
    );

    // NOT the mirror image. The tiers resolve independently, so a lone
    // `dfs_endpoint` is a supported deployment — DFS behind a private
    // gateway with the blob tier still on `endpoint_suffix` — and must be
    // accepted rather than forcing the operator to restate the natural blob
    // host as an undocumented incantation.
    ovstorage_plugin_azure::__test_only_parse_config(&support::config_map(
        ACCOUNT,
        CONTAINER,
        &[
            ("hierarchical_namespace", ConfigValue::Bool(true)),
            (
                "dfs_endpoint",
                ConfigValue::String("https://private.dfs.example.com".into()),
            ),
        ],
    ))
    .expect("a DFS-only override is a supported HNS shape");
}

#[test]
fn non_absolute_and_non_http_blob_endpoints_are_rejected() {
    // `blob_endpoint` is a full service URL, not a host: a bare host:port, a
    // path fragment or a non-http(s) scheme would each silently produce
    // request URLs the signer cannot reproduce. Bare `?`, `#` and `@` are
    // refused on presence — request URLs are built by concatenating
    // `/{container}/{key}` onto the configured base, so a delimiter left
    // there would move the path out of the path component.
    let cases = [
        ("127.0.0.1:10000/devstoreaccount1", "absolute URL"),
        ("/devstoreaccount1", "absolute URL"),
        ("ftp://azurite:10000/devstoreaccount1", "http or https"),
        ("http://azurite:10000/devstoreaccount1?", "query string"),
        ("http://azurite:10000/devstoreaccount1#", "fragment"),
        ("http://@azurite:10000", "credentials"),
        ("", "empty or padded"),
    ];
    for (raw, expected) in cases {
        let err = parse_config_err(&[("blob_endpoint", ConfigValue::String(raw.into()))]);
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "for {raw:?}");
        assert!(
            err.message().contains("blob_endpoint") && err.message().contains(expected),
            "rejection of {raw:?} must name the key and the reason, got {:?}",
            err.message(),
        );
    }
}
