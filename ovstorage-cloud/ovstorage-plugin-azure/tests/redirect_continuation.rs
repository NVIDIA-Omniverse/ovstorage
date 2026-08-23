// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The staged-block continuation must not choose the blob the commit lands on.
//!
//! Under the broker's client-driven `ContinueWrite` RPC the whole
//! `WriteRedirectBatch` is echoed back by the remote caller, while the request
//! address is the value authorization was decided on. So `continue_write`
//! derives the blob key from the address; the continuation carries only the
//! block count.

use std::collections::HashMap;
use std::time::Duration;

use ovstorage_plugin::{
    BackendFactory, ConfigValue, ConnectionRequest, ContinueWriteRequest, Extensions, LayerConfig,
    LayerConnectionRequest, LayerHandle, RedirectResult, RedirectResultBatch, Request,
    WriteOptions, WriteRedirectBatch, WriteRequest, WriteStep, address,
};
use ovstorage_plugin_azure::AzureLayerFactory;

mod support;
use support::{
    build_backend_with_endpoint, spawn_capture_server, spawn_capture_server_serving_verify, target,
};

/// 300 MiB clears Azure's 256 MiB staged threshold: 75 × 4 MiB blocks, so
/// `continue_write` reaches `Put Block List` rather than the single-`Put Blob`
/// branch whose response is itself the commit.
const STAGED_SIZE_BYTES: u64 = 300 * 1024 * 1024;
const BLOCK_COUNT: u32 = 75;

/// Substitution, not modification: a caller holding a genuine staged
/// continuation minted for `minted.bin` presents it against the authorized
/// request address `victim.bin`. `Put Block List` must name `victim.bin`, and
/// its block ids must be the ones derived from that key.
#[tokio::test]
async fn continue_write_commits_to_the_authorized_blob_not_the_continuations() {
    let (endpoint, capture, counter) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "container", &endpoint);

    let minted_for = target("acct", "container", "minted.bin");
    let authorized = target("acct", "container", "victim.bin");

    let opts = WriteOptions {
        size_hint: Some(STAGED_SIZE_BYTES),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(minted_for, opts, None)
        .await
        .expect("staged write_redirect emits a batch");
    assert_eq!(batch.redirects.len(), BLOCK_COUNT as usize);

    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 201,
                captured_headers: vec![("etag".into(), "\"block-etag\"".into())],
                captured_body: Vec::new(),
            })
            .collect(),
    };

    let step = backend
        .continue_write(authorized, batch, results, None, None)
        .await
        .expect("continue_write commits against the authorized blob");
    assert!(matches!(step, WriteStep::Done(_)));

    for _ in 0..100 {
        if counter.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let requests = capture.snapshot();
    let commit = requests
        .iter()
        .find(|request| request.raw.contains("comp=blocklist"))
        .expect("Put Block List must have been sent");
    assert!(
        commit.raw.contains("/container/victim.bin?comp=blocklist"),
        "Put Block List must name the authorized blob, not the continuation's; got:\n{}",
        commit.raw
    );
    assert!(
        !commit.raw.contains("minted.bin"),
        "the continuation's blob key must not appear anywhere on the commit; got:\n{}",
        commit.raw
    );
    // The block ids are `sha256(blob_key)[..12] || seq_be`, so a commit that
    // named the right blob while replaying the continuation's ids would still
    // be wrong. Recompute the first and last independently here.
    for seq in [0u32, BLOCK_COUNT - 1] {
        let expected = expected_block_id("victim.bin", seq);
        assert!(
            commit.raw.contains(&expected),
            "block id {seq} must be derived from the authorized blob key ({expected}); got:\n{}",
            commit.raw
        );
    }
    let stale = expected_block_id("minted.bin", 0);
    assert!(
        !commit.raw.contains(&stale),
        "no block id may be derived from the continuation's blob key; got:\n{}",
        commit.raw
    );
}

/// Independent restatement of the plugin's block-id layout
/// (`base64(sha256(blob_key)[..12] || seq.to_be_bytes())`), so the assertion
/// above does not just re-run the code it is checking.
fn expected_block_id(blob_key: &str, seq: u32) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(blob_key.as_bytes());
    let mut raw = [0u8; 16];
    raw[..12].copy_from_slice(&digest[..12]);
    raw[12..].copy_from_slice(&seq.to_be_bytes());
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// `?versionid=` is dropped when the blob key is derived, so a continuation
/// presented against a version-pinned address would commit to the current blob
/// while authorization was decided on the frozen-version URL. The other
/// mutating verbs refuse such an address; `continue_write` must too.
#[tokio::test]
async fn continue_write_refuses_a_version_pinned_address() {
    let (endpoint, _capture, _counter) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "container", &endpoint);

    let opts = WriteOptions {
        size_hint: Some(STAGED_SIZE_BYTES),
        ..WriteOptions::default()
    };
    let batch = backend
        .write_redirect(target("acct", "container", "minted.bin"), opts, None)
        .await
        .expect("staged write_redirect emits a batch");
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 201,
                captured_headers: vec![("etag".into(), "\"block-etag\"".into())],
                captured_body: Vec::new(),
            })
            .collect(),
    };

    let mut pinned = target("acct", "container", "minted.bin");
    pinned.resolved_address =
        ovstorage_plugin::address::parse("azure://acct/container/minted.bin?versionid=frozen")
            .unwrap();
    let err = backend
        .continue_write(pinned, batch, results, None, None)
        .await
        .expect_err("a version-pinned address must be refused");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
}

/// The single-`Put Blob` branch: the caller's PUT already committed, so
/// `continue_write` builds `ObjectInfo` from the captured headers and makes no
/// outbound call. Pinned here because hoisting `require_blob_address` above the
/// branch put a new failure mode on this path.
#[tokio::test]
async fn continue_write_single_put_blob_reports_from_captured_headers() {
    let (endpoint, _capture, _counter) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "container", &endpoint);

    let batch = backend
        .write_redirect(
            target("acct", "container", "small.bin"),
            WriteOptions {
                size_hint: Some(1024),
                ..WriteOptions::default()
            },
            None,
        )
        .await
        .expect("inline write_redirect emits a batch");
    assert_eq!(batch.redirects.len(), 1);

    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 201,
            captured_headers: vec![
                ("etag".into(), "\"inline-etag\"".into()),
                (
                    "last-modified".into(),
                    "Mon, 01 Jan 2024 00:00:00 GMT".into(),
                ),
            ],
            captured_body: Vec::new(),
        }],
    };
    let step = backend
        .continue_write(
            target("acct", "container", "small.bin"),
            batch,
            results,
            None,
            None,
        )
        .await
        .expect("the single-PutBlob branch reports without an outbound call");
    match step {
        WriteStep::Done(result) => {
            assert_eq!(result.info.etag.as_deref(), Some("inline-etag"));
            assert_eq!(
                result.info.address.as_str(),
                "azure://acct/container/small.bin"
            );
        }
        WriteStep::Redirects(_) => panic!("expected Done"),
    }
}

/// Deriving the blob key applies the account/container containment check to the
/// single-`Put Blob` branch, which previously validated nothing. That is a new
/// refusal after the caller's PUT already landed, so it is pinned rather than
/// left as a side effect of the hoist.
#[tokio::test]
async fn continue_write_refuses_an_address_outside_the_configured_container() {
    let (endpoint, _capture, _counter) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "container", &endpoint);

    let batch = backend
        .write_redirect(
            target("acct", "container", "small.bin"),
            WriteOptions {
                size_hint: Some(1024),
                ..WriteOptions::default()
            },
            None,
        )
        .await
        .expect("inline write_redirect emits a batch");
    let results = RedirectResultBatch {
        results: vec![RedirectResult {
            status_code: 201,
            captured_headers: vec![("etag".into(), "\"inline-etag\"".into())],
            captured_body: Vec::new(),
        }],
    };
    let err = backend
        .continue_write(
            target("acct", "other", "small.bin"),
            batch,
            results,
            None,
            None,
        )
        .await
        .expect_err("an address outside the configured container must be refused");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
}

/// The staged branch takes only the block *count* from the continuation, so a
/// count that disagrees with the redirect batch is refused rather than
/// committing a truncated block list.
#[tokio::test]
async fn continue_write_refuses_a_block_count_that_disagrees_with_the_batch() {
    let (endpoint, _capture, _counter) = spawn_capture_server();
    let backend = build_backend_with_endpoint("acct", "container", &endpoint);

    let mut batch = backend
        .write_redirect(
            target("acct", "container", "large.bin"),
            WriteOptions {
                size_hint: Some(STAGED_SIZE_BYTES),
                ..WriteOptions::default()
            },
            None,
        )
        .await
        .expect("staged write_redirect emits a batch");
    // Drop one redirect so the batch no longer matches the recorded count.
    batch.redirects.pop();
    let results = RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 201,
                captured_headers: vec![("etag".into(), "\"block-etag\"".into())],
                captured_body: Vec::new(),
            })
            .collect(),
    };
    let err = backend
        .continue_write(
            target("acct", "container", "large.bin"),
            batch,
            results,
            None,
            None,
        )
        .await
        .expect_err("a block count that disagrees with the batch must be refused");
    assert_eq!(err.code(), ovstorage_plugin::ErrorCode::InvalidArgument);
}

// ===========================================================================
// The attribution the staged commit persists
// ===========================================================================
//
// These drive `Layer::continue_write` rather than the backend directly. The
// value under test arrives on the request extensions, and the layer is what
// reads them — a backend-level test would supply the value the layer was
// supposed to extract and prove nothing about the extraction.

/// The writer identity a host attribution layer asserts for the request, as it
/// reaches the plugin.
const ATTESTED_WRITER: &str = "alice@example.com";
/// The identity a caller planted in the continuation. Deliberately unrelated to
/// any blob key in this file: an assertion that this string is absent from the
/// captured commit must fail for one reason only.
const PLANTED_WRITER: &str = "impersonated-principal";
/// The principal on the request. Distinct from the asserted writer, so a plugin
/// reading the principal instead of the assertion cannot pass by coincidence.
const REQUEST_PRINCIPAL: &str = "carol@example.com";

fn attributed_request<T>(attested: Option<&str>, input: T) -> Request<T> {
    let mut extensions = Extensions::new();
    if let Some(attested) = attested {
        extensions.insert(
            ovstorage_plugin::ext::ATTRIBUTED_MODIFIED_BY.to_string(),
            attested.as_bytes().to_vec(),
        );
    }
    // Present on every brokered request. A plugin must not read it: whether a
    // write is attributed is the host's placement decision, not "is someone
    // authenticated".
    extensions.insert(
        ovstorage_plugin::ext::PRINCIPAL_ID.to_string(),
        REQUEST_PRINCIPAL.as_bytes().to_vec(),
    );
    Request { extensions, input }
}

async fn layer_for(endpoint: &str) -> LayerHandle {
    let layer = AzureLayerFactory::default()
        .create_backend("azure", &LayerConfig::new(), None)
        .await
        .expect("azure layer");
    let mut config = HashMap::new();
    config.insert("account".into(), ConfigValue::String("acct".into()));
    config.insert("container".into(), ConfigValue::String("container".into()));
    config.insert(
        "__test_endpoint".into(),
        ConfigValue::String(endpoint.into()),
    );
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "azure".into(),
                connection: ConnectionRequest {
                    backend_kind: "azure".into(),
                    config,
                    credentials: support::shared_key_bundle(),
                    persist: false,
                    display_name: None,
                },
            }),
            None,
        )
        .await
        .expect("add_connection");
    layer
}

/// Mint a genuine staged batch whose continuation carries `planted` as the
/// reserved attribution key, for `key` — the same object the commit is
/// authorized against.
///
/// This is the substitution shape, not a malformed input: byte for byte it is
/// what a caller produces by rewriting only that entry in a continuation the
/// host minted for it. Every other check the commit makes still agrees — same
/// blob, same block count, same derived block ids — so the only mechanism that
/// can catch it is the commit-time re-assertion.
async fn staged_batch_naming(layer: &LayerHandle, key: &str, planted: &str) -> WriteRedirectBatch {
    let mut user_metadata = HashMap::new();
    user_metadata.insert("ovstorage-modified-by".to_string(), planted.to_string());
    user_metadata.insert("author".to_string(), "unreserved".to_string());
    let batch = layer
        .write_redirect(
            Request::new(WriteRequest {
                address: address::parse(&format!("azure://acct/container/{key}")).unwrap(),
                body: ovstorage_plugin::Body::Bytes(Vec::new()),
                options: WriteOptions {
                    size_hint: Some(STAGED_SIZE_BYTES),
                    user_metadata: Some(user_metadata),
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect("staged write_redirect emits a batch");
    assert_eq!(
        batch.redirects.len(),
        BLOCK_COUNT as usize,
        "the mint must have produced a staged batch, not an inline one"
    );
    batch
}

fn all_ok(batch: &WriteRedirectBatch) -> RedirectResultBatch {
    RedirectResultBatch {
        results: batch
            .redirects
            .iter()
            .map(|_| RedirectResult {
                status_code: 201,
                captured_headers: vec![("etag".into(), "\"block-etag\"".into())],
                captured_body: Vec::new(),
            })
            .collect(),
    }
}

/// The commit's captured request. `continue_write` has already awaited the
/// response the server wrote after recording it, so it is present by the time
/// this runs.
fn commit_request(capture: &support::Capture) -> String {
    capture
        .snapshot()
        .into_iter()
        .find(|request| request.raw.contains("comp=blocklist"))
        .expect("Put Block List must have been sent")
        .raw
}

/// A genuine continuation naming someone else must not decide who the commit
/// records. `Put Block List` is where a staged blob's metadata is set, so the
/// commit carries the identity the host asserted on the request.
#[tokio::test]
async fn staged_commit_records_the_asserted_writer_over_the_continuations() {
    let (endpoint, capture, _counter) = spawn_capture_server_serving_verify();
    let layer = layer_for(&endpoint).await;
    let batch = staged_batch_naming(&layer, "staged.bin", PLANTED_WRITER).await;
    let results = all_ok(&batch);

    let step = layer
        .continue_write(
            attributed_request(
                Some(ATTESTED_WRITER),
                ContinueWriteRequest {
                    address: address::parse("azure://acct/container/staged.bin").unwrap(),
                    redirects: batch,
                    results,
                },
            ),
            None,
        )
        .await
        .expect("continue_write commits");
    assert!(matches!(step, WriteStep::Done(_)));

    let commit = commit_request(&capture);
    let lower = commit.to_lowercase();
    assert!(
        lower.contains(&format!(
            "x-ms-meta-ovstorage-modified-by: {ATTESTED_WRITER}"
        )),
        "the commit must carry the asserted writer; got:\n{commit}"
    );
    assert!(
        !lower.contains(PLANTED_WRITER),
        "the continuation's writer must not appear on the commit; got:\n{commit}"
    );
    assert!(
        lower.contains("x-ms-meta-author: unreserved"),
        "unreserved caller metadata must still be committed; got:\n{commit}"
    );
}

/// The rejected design, pinned. `ext::PRINCIPAL_ID` is present on every brokered
/// request; a plugin that derived attribution from it would stamp on branches a
/// host composed *not* to attribute — one fronting a backend that cannot hold
/// the key, or a pass-through instance preserving an upstream host's value. So
/// with no assertion on the request, the continuation's metadata is committed
/// exactly as it arrived. This test reddens if a future reader "simplifies" the
/// plugin into reading the principal.
#[tokio::test]
async fn without_an_assertion_the_commit_carries_the_continuations_metadata() {
    let (endpoint, capture, _counter) = spawn_capture_server_serving_verify();
    let layer = layer_for(&endpoint).await;
    let batch = staged_batch_naming(&layer, "unattributed.bin", PLANTED_WRITER).await;
    let results = all_ok(&batch);

    layer
        .continue_write(
            attributed_request(
                None,
                ContinueWriteRequest {
                    address: address::parse("azure://acct/container/unattributed.bin").unwrap(),
                    redirects: batch,
                    results,
                },
            ),
            None,
        )
        .await
        .expect("continue_write commits");

    let commit = commit_request(&capture);
    let lower = commit.to_lowercase();
    assert!(
        lower.contains(&format!(
            "x-ms-meta-ovstorage-modified-by: {PLANTED_WRITER}"
        )),
        "with no host assertion the continuation's value stands; got:\n{commit}"
    );
    assert!(
        !lower.contains(REQUEST_PRINCIPAL),
        "the principal must not be read as an attribution assertion; got:\n{commit}"
    );
}
