// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for the Nucleus plugin's precondition contracts.
//!
//! Mirrors the GCS / services-client `tests/precondition.rs` shape.
//! Each test exercises one of the systemic preconditions enforcement
//! contracts the Nucleus plugin honors. These guard against the
//! cluster of defects observed in the services-client and cloud
//! plugin reviews: compound `if_match` refusal, `write_redirect`
//! `size_hint` requirement, range validation, and capability
//! honesty around unsupported pagination / precondition fields. The
//! intent is twofold: prove the production code refuses caller
//! input that the Nucleus wire can't enforce, and pin behaviors
//! that were already correct so a future refactor cannot silently
//! regress them.
//!
//! Nucleus's only wire conditional on mutating ops is `update_asset`'s
//! optional `etag` argument. `size`, `mtime`, and `version` are not
//! enforceable on the omni1 wire — the `?branch&checkpoint` URL
//! selector is part of the resolved address, not the `if_match`
//! precondition. `delete2` / `copy2` / `rename2` carry no per-path
//! etag and therefore refuse `if_match` entirely.
//!
//! The tests drive a bare `NucleusBackend` (via the crate's
//! `__test_only_backend` construction hook). Every
//! refusal-on-precondition check fires SYNCHRONOUSLY at the SPI entry
//! point, BEFORE any wire or auth interaction; that is the contract
//! under test. No real WebSocket / HTTP server is required.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage_plugin::{
    BackendId, ByteRange, ConfigValue, CopyOptions, DeleteOptions, ErrorCode, ListOptions,
    ListVersionsOptions, ReadOptions, RenameOptions, ResolvedTarget, Url, WriteOptions, address,
};
use ovstorage_plugin_nucleus::NucleusBackend;

// === Helpers ===

fn etag_only_if_match() -> String {
    "v1".into()
}

async fn nucleus_backend() -> Arc<NucleusBackend> {
    let mut config = HashMap::new();
    config.insert("server".into(), ConfigValue::String("srv".into()));
    Arc::new(
        ovstorage_plugin_nucleus::__test_only_backend(&config)
            .expect("bare backend construction succeeds without auth"),
    )
}

fn target(addr: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("nucleus:omniverse://srv/".into()),
        resolved_address: address::parse(addr).expect("address parses"),
    }
}

fn obj(path: &str) -> ResolvedTarget {
    target(&format!("omniverse://srv{path}"))
}

// === Conditional precondition enforcement ===
//
// The SPI's `if_match` is a single opaque etag string. On Nucleus,
// copy/delete/rename refuse the etag precondition entirely because the
// omni1 IDL (`copy2`, `delete2`, `rename2`) has no slot for it on
// those ops.

#[tokio::test]
async fn write_redirect_refuses_unknown_size_hint() {
    // Multipart LFT redirect needs a known total length to compute
    // part offsets. `size_hint = None` MUST refuse rather than fall
    // back to a sentinel like `unwrap_or(MAX_BYTES)`; lessons §1.
    let backend = nucleus_backend().await;
    let err = backend
        .write_redirect(
            obj("/Users/alice/x"),
            WriteOptions {
                size_hint: None,
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("write_redirect must refuse when size_hint is missing");
    assert_eq!(err.code(), ErrorCode::Unsupported);
    let msg = err.to_string();
    assert!(
        msg.contains("size_hint") || msg.contains("LftClient"),
        "error must mention size_hint or LftClient; got: {msg}"
    );
}

#[tokio::test]
async fn delete_refuses_etag_only_if_match() {
    // delete2 has no per-path etag slot, so delete refuses any
    // `if_match` precondition.
    let backend = nucleus_backend().await;
    let err = backend
        .delete(
            obj("/Users/alice/x"),
            DeleteOptions {
                if_match: Some(etag_only_if_match()),
            },
            None,
        )
        .await
        .expect_err(
            "etag-only if_match must be refused on Nucleus delete (omni1 delete2 has no etag)",
        );
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn copy_refuses_etag_only_if_match() {
    // copy2 has no per-path etag slot, so copy refuses any `if_source`
    // precondition. Source-side / destination-side conditional questions
    // are moot for Nucleus because the wire IDL has no slot for the
    // conditional on either side.
    let backend = nucleus_backend().await;
    let err = backend
        .copy(
            obj("/Users/alice/src"),
            obj("/Users/alice/dst"),
            CopyOptions {
                if_source: Some(etag_only_if_match()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("etag-only if_source must be refused on Nucleus copy");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn rename_refuses_etag_only_if_match() {
    // rename2 has no per-path etag slot, so rename refuses any
    // `if_source` precondition. Nucleus rename is a single `rename2` RPC
    // (not copy + delete), so the "carry if_match to both legs" pattern
    // that applies on the cloud plugins doesn't apply here.
    let backend = nucleus_backend().await;
    let err = backend
        .rename(
            obj("/Users/alice/src"),
            obj("/Users/alice/dst"),
            RenameOptions {
                if_source: Some(etag_only_if_match()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("etag-only if_source must be refused on Nucleus rename");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

// === Range validation ===

#[tokio::test]
async fn read_range_inverted_returns_invalid_argument() {
    // Inverted range (start > end_inclusive) must be diagnosed with
    // `InvalidArgument` BEFORE the blanket "ranged reads unsupported"
    // refusal: an inverted range from a buggy caller is best surfaced
    // as a typed error rather than lumped into a less-specific
    // Unsupported case.
    let backend = nucleus_backend().await;
    let err = backend
        .read(
            obj("/Users/alice/x"),
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
    assert!(err.to_string().contains("inverted"));
}

#[tokio::test]
async fn read_well_formed_range_still_returns_unsupported() {
    // omni1 read_asset_version has no range parameter; a well-formed
    // range is refused with `Unsupported`, distinct from the
    // InvalidArgument refusal for malformed ranges above.
    let backend = nucleus_backend().await;
    let err = backend
        .read(
            obj("/Users/alice/x"),
            ReadOptions {
                range: Some(ByteRange {
                    start: 0,
                    end_inclusive: Some(1024),
                }),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("ranged read must error");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

// === List capability honesty ===

#[tokio::test]
async fn list_recursive_returns_unsupported() {
    // The plugin advertises `supports_recursive_list = false`. A
    // caller passing `opts.recursive = true` must get `Unsupported`,
    // not a silent fall-through to a single-level listing. See
    // lessons §1 (`6ed0e6f`).
    let backend = nucleus_backend().await;
    let err = backend
        .list(
            obj("/Users/alice/"),
            ListOptions {
                recursive: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("recursive list must be refused");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn list_page_token_returns_unsupported() {
    // omni1 list2 has no continuation cursor; a caller-supplied
    // page_token cannot be honored, so refuse rather than silently
    // start from scratch (which would loop the caller forever).
    let backend = nucleus_backend().await;
    let err = backend
        .list(
            obj("/Users/alice/"),
            ListOptions {
                page_token: Some("opaque-cursor".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("page_token must be refused");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

// === List versions pagination ===

#[tokio::test]
async fn list_versions_page_token_returns_unsupported() {
    // omni1 get_checkpoints returns the full list in a single response.
    // Silently dropping a caller-supplied page_token would loop them
    // indefinitely.
    let backend = nucleus_backend().await;
    let err = backend
        .list_versions(
            obj("/Users/alice/x"),
            ListVersionsOptions {
                page_token: Some("opaque".into()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("page_token must be refused");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

#[tokio::test]
async fn list_versions_max_results_returns_unsupported() {
    // Silently truncating to max_results would lose checkpoints without
    // telling the host.
    let backend = nucleus_backend().await;
    let err = backend
        .list_versions(
            obj("/Users/alice/x"),
            ListVersionsOptions {
                max_results: Some(10),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("max_results must be refused");
    assert_eq!(err.code(), ErrorCode::Unsupported);
}

// === Sanity guard: etag-only if_match is the SUPPORTED precondition shape ===

#[tokio::test]
async fn read_accepts_etag_only_if_match_at_spi_boundary() {
    // Counterpart to the refusal tests above: an etag-only `if_match`
    // must NOT be rejected. The read will ultimately fail because
    // there's no real Nucleus session attached, but the failure mode
    // must be auth-related, NOT `Unsupported` from a precondition check.
    let backend = nucleus_backend().await;
    let result = backend
        .read(
            obj("/Users/alice/x"),
            ReadOptions {
                if_match: Some(etag_only_if_match()),
                ..Default::default()
            },
            None,
        )
        .await;
    // Whatever happens past the helper, it must NOT be the Unsupported
    // refusal from `require_etag_only_if_match`. Auth-required is
    // the expected outcome here (no session installed); any other code
    // is fine as long as it's not Unsupported with an `if_match.*`
    // message.
    if let Err(err) = result {
        let msg = err.to_string();
        let helper_message = msg.contains("if_match.size")
            || msg.contains("if_match.mtime")
            || msg.contains("if_match.version");
        assert!(
            !helper_message,
            "etag-only if_match must pass the helper; got helper-style refusal: {msg}"
        );
    }
}

#[tokio::test]
async fn write_accepts_etag_only_if_match_at_spi_boundary() {
    // Same sanity guard as `read_accepts_etag_only_if_match_at_spi_boundary`,
    // but for the write path that wires the etag into `update_asset`.
    let backend = nucleus_backend().await;
    let result = backend
        .write(
            obj("/Users/alice/x"),
            b"hi".to_vec(),
            WriteOptions {
                if_dest: ovstorage_plugin::IfDestExists::MatchEtag(etag_only_if_match()),
                ..Default::default()
            },
            None,
        )
        .await;
    if let Err(err) = result {
        let msg = err.to_string();
        let helper_message = msg.contains("if_match.size")
            || msg.contains("if_match.mtime")
            || msg.contains("if_match.version");
        assert!(
            !helper_message,
            "etag-only if_dest must pass the helper; got helper-style refusal: {msg}"
        );
    }
}

// Pin that the `Url` re-export from `ovstorage_plugin` resolves so
// this file fails to compile if the SPI's surface shrinks. (No
// runtime check needed; the import in the use block above already
// drives the check.)
#[allow(dead_code)]
fn _link_marker(_: Url) {}
