// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The shared scenario contract, written against the routed
//! [`ovstorage::Stack`] and the ergonomic [`ovstorage::ext::LayerExt`] verbs.
//! Each scenario is `async fn(&AppState, Backend)`, picks its
//! [`Target`], gates on the backend's real advertised
//! [`Capabilities`](ovstorage::Capabilities), and skips (visibly) when its
//! backend/access/capability isn't configured. The Rust runner
//! (`tests/live.rs`) exercises this set.
//!
//! ## Why some calls are fully-qualified
//!
//! [`ovstorage::Layer`] is deliberately NOT imported here. `LayerExt` shadows
//! eleven `Layer` primitive names (`stat`, `write`, `delete`, `copy`, …), so
//! importing both would make every ergonomic call ambiguous. The four verbs
//! `LayerExt` has no shortcut for — `check_access`, `write_stream`,
//! `list_versions`, `get_latest_version` — are spelled
//! `ovstorage::Layer::verb(stack, Request::new(..), cancel)` instead.

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use ovstorage::ext::LayerExt as _;
use ovstorage::{
    AccessOps, Body, BodyStream, ByteRange, CheckAccessRequest, CopyOptions,
    CreateDirectoryOptions, DeleteDirectoryOptions, ErrorCode, EtagStrength, IfDestExists,
    LayerHandle, ListOptions, ListVersionsOptions, ListVersionsRequest, ObjectInfo, ObjectKind,
    ReadOptions, ReadRequest, RenameOptions, Request, StatOptions, StatRequest,
    UpdateMetadataOptions, UpdateMetadataRequest, Url, UserMetadata, WriteOptions, WriteRequest,
};
use ovstorage_authz::{AttributionLayer, AttributionStrategy, AttributionWrapper};

use crate::{
    Access, AppState, Backend, Target, TempDirs, TempKeys, VersionedTempKeys, scenario_exclusion,
    skip, unique_prefix,
};

/// Resolve the `(backend, access)` target or skip the scenario.
macro_rules! target_or_skip {
    ($app:expr, $backend:expr, $access:expr, $name:expr) => {
        match $app.target($backend, $access) {
            Some(t) => {
                if let Some(why) = scenario_exclusion(t, $name) {
                    return skip(t.backend, t.access, $name, why);
                }
                t
            }
            None => return skip($backend, $access, $name, "target not configured"),
        }
    };
}

/// Skip unless the target advertises `$cap`.
macro_rules! require_cap {
    ($t:expr, $cap:ident, $name:expr) => {
        if !$t.caps.$cap {
            return skip(
                $t.backend,
                $t.access,
                $name,
                concat!("missing capability ", stringify!($cap)),
            );
        }
    };
}

// === universal core ===

/// Write → stat (size) → read (byte-for-byte). The load-bearing cloud-read
/// validator: the redirect-followed read path runs here on every backend.
pub async fn write_stat_read(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "write_stat_read");
    require_cap!(t, supports_write, "write_stat_read");
    let key = format!("{}obj.bin", unique_prefix("write_stat_read"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let payload = b"hello-live-world".to_vec();
    t.put(&key, payload.clone()).await.expect("write");
    let info = t.stat(&key).await.expect("stat");
    assert_target_etag_strength(t.backend, &info, "stat after write");
    assert_eq!(info.size, Some(payload.len() as u64), "stat reports size");
    let (got, read_info) = t
        .stack()
        .read_bytes(t.addr(&key), ReadOptions::default(), None)
        .await
        .expect("read");
    assert_eq!(got, payload, "round-trip bytes match");

    // An unflagged stat may carry a pin the backend had for free; a flagged
    // one must carry it wherever the fixture versions.
    assert_target_versioned_address(t.backend, &info, false, "stat after write");
    let flagged = t
        .stat_with(
            &key,
            StatOptions {
                versioned_address: true,
                ..Default::default()
            },
        )
        .await
        .expect("flagged stat");
    assert_target_versioned_address(t.backend, &flagged, true, "flagged stat after write");
    if let Some(pin) = flagged.versioned_address.clone() {
        // The pin names the bytes: a read through it answers exactly what the
        // head read did.
        let (pinned, pinned_info) = t
            .stack()
            .read_bytes(pin.clone(), ReadOptions::default(), None)
            .await
            .expect("read through the versioned address");
        assert_eq!(pinned, payload, "the pinned read returns the written bytes");
        assert_eq!(
            pinned_info.etag, read_info.etag,
            "the pinned read reports the head read's etag",
        );
        // A pin is not a mutable handle: every versioning plugin refuses to
        // write through one rather than silently dropping the modifier.
        assert_error(
            t.stack()
                .write(
                    pin,
                    Body::Bytes(b"through-the-pin".to_vec()),
                    WriteOptions::default(),
                    None,
                )
                .await
                .map(|_| ()),
            ErrorCode::InvalidArgument,
            "write through a versioned address",
        );
    }
}

/// Delete removes the object; a follow-up stat is `NotFound`.
pub async fn delete(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "delete");
    require_cap!(t, supports_write, "delete");
    require_cap!(t, supports_delete, "delete");
    let key = format!("{}gone.bin", unique_prefix("delete"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    t.put(&key, b"x".to_vec()).await.expect("write");
    t.rm(&key).await.expect("delete");
    assert_error(
        t.stat(&key).await.map(|_| ()),
        ErrorCode::NotFound,
        "stat after delete",
    );
}

/// Non-recursive list folds a child prefix into a directory entry.
pub async fn list_prefix_delimiter(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "list_prefix_delimiter");
    require_cap!(t, supports_write, "list_prefix_delimiter");
    require_cap!(t, supports_list, "list_prefix_delimiter");
    let prefix = unique_prefix("list_prefix_delimiter");
    let mut guard = TempKeys::new(t);

    for key in ["a.txt", "b.txt", "sub/c.txt"] {
        let full = format!("{prefix}{key}");
        guard.track(t.addr(&full));
        t.put(&full, b"data".to_vec()).await.expect("write child");
    }

    let entries = t
        .stack()
        .list_page(t.addr(&prefix), ListOptions::default(), None)
        .await
        .expect("list")
        .items;

    let files: Vec<&str> = entries
        .iter()
        .filter(|e| e.kind == ObjectKind::File)
        .map(|e| e.address.as_str())
        .collect();
    assert!(
        files.iter().any(|a| a.ends_with("a.txt")) && files.iter().any(|a| a.ends_with("b.txt")),
        "list returns the direct file children a.txt + b.txt; got {entries:#?}",
    );
    assert!(
        !files.iter().any(|a| a.ends_with("sub/c.txt")),
        "non-recursive list must not return nested files; got {entries:#?}",
    );
    assert!(
        entries.iter().any(|e| e.kind != ObjectKind::File),
        "list folds sub/ into a directory entry; got {entries:#?}",
    );
}

/// Recursive listing returns nested files, and paging exposes a stable
/// next-page token.
///
/// `LayerExt::list_page` passes `max_results` and `page_token` straight through
/// to the backend, so this exercises REAL backend pagination on every cloud
/// target.
pub async fn list_recursive_and_pagination(app: &AppState, backend: Backend) {
    let t = target_or_skip!(
        app,
        backend,
        Access::Default,
        "list_recursive_and_pagination"
    );
    require_cap!(t, supports_write, "list_recursive_and_pagination");
    require_cap!(t, supports_list, "list_recursive_and_pagination");
    let prefix = unique_prefix("list_recursive_and_pagination");
    let mut guard = TempKeys::new(t);

    for key in ["a.txt", "b.txt", "sub/c.txt"] {
        let full = format!("{prefix}{key}");
        guard.track(t.addr(&full));
        t.put(&full, b"data".to_vec()).await.expect("write child");
    }

    let first = t
        .stack()
        .list_page(
            t.addr(&prefix),
            ListOptions {
                max_results: Some(1),
                full_metadata: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("list page 1");
    assert_eq!(first.items.len(), 1, "first page size");
    let token = first
        .next_page_token
        .clone()
        .expect("first list page should have a continuation token");
    assert!(
        first.items[0].size.is_some() || first.items[0].kind != ObjectKind::File,
        "full_metadata list returns file sizes; got {first:#?}",
    );

    let second = t
        .stack()
        .list_page(
            t.addr(&prefix),
            ListOptions {
                max_results: Some(10),
                page_token: Some(token),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("list page 2");
    assert!(
        !second.items.is_empty(),
        "second list page should contain remaining entries",
    );
    // A non-empty page 2 is not evidence the token was honored: a backend (or a
    // host wrapper) that dropped `page_token` restarts the listing and returns
    // page 1's entry again, which every "did we get more rows?" assertion
    // accepts. Three children under a unique prefix, one per page, so a
    // re-listing is an overlap.
    let first_page: Vec<&str> = first.items.iter().map(|e| e.address.as_str()).collect();
    let repeated: Vec<&str> = second
        .items
        .iter()
        .map(|e| e.address.as_str())
        .filter(|address| first_page.contains(address))
        .collect();
    assert!(
        repeated.is_empty(),
        "the continuation token must advance past page 1, but page 2 repeats {repeated:?}; \
         page 1 = {first_page:?}",
    );

    let recursive = t
        .stack()
        .list_page(
            t.addr(&prefix),
            ListOptions {
                recursive: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("recursive list");
    assert!(
        recursive
            .items
            .iter()
            .any(|entry| entry.address.as_str().ends_with("sub/c.txt")),
        "recursive list includes nested file; got {recursive:#?}",
    );

    // The file backend cannot version, so paying for pins changes nothing:
    // every entry still answers `None`. Cloud fixtures exercise the flagged
    // list where the pin is meaningful, in `get_latest_version`.
    if t.backend == Backend::File {
        let flagged = t
            .stack()
            .list_page(
                t.addr(&prefix),
                ListOptions {
                    recursive: true,
                    versioned_address: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("flagged recursive list");
        assert!(
            !flagged.items.is_empty(),
            "flagged recursive list still returns the children",
        );
        for item in &flagged.items {
            assert_target_versioned_address(t.backend, item, true, "flagged recursive list entry");
        }
    }
}

/// Copy duplicates the object (server-side when supported, else host-buffered).
pub async fn copy(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "copy");
    require_cap!(t, supports_write, "copy");
    let prefix = unique_prefix("copy");
    let (src, dst) = (format!("{prefix}src.bin"), format!("{prefix}dst.bin"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&src));
    guard.track(t.addr(&dst));

    let payload = b"copy-me".to_vec();
    t.put(&src, payload.clone()).await.expect("write src");
    t.stack()
        .copy(t.addr(&src), t.addr(&dst), CopyOptions::default(), None)
        .await
        .expect("copy");
    assert_eq!(
        t.get(&dst).await.expect("read dst"),
        payload,
        "copy preserved bytes"
    );
    // Copy is not move. Asserting only the destination passes a backend (or a
    // host fallback) that implemented copy as copy+delete, or that streamed the
    // source and truncated it — the source has to be intact and unchanged, not
    // merely present.
    assert_eq!(
        t.get(&src).await.expect("read src after copy"),
        payload,
        "copy left the source unchanged",
    );
}

/// Rename moves the object (server-side or copy+delete fallback).
pub async fn rename(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "rename");
    require_cap!(t, supports_write, "rename");
    require_cap!(t, supports_delete, "rename");
    let prefix = unique_prefix("rename");
    let (src, dst) = (format!("{prefix}from.bin"), format!("{prefix}to.bin"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&src));
    guard.track(t.addr(&dst));

    let payload = b"move-me".to_vec();
    t.put(&src, payload.clone()).await.expect("write src");
    t.stack()
        .rename(t.addr(&src), t.addr(&dst), RenameOptions::default(), None)
        .await
        .expect("rename");
    assert_eq!(
        t.get(&dst).await.expect("read dst"),
        payload,
        "rename preserved bytes"
    );
    assert_error(
        t.stat(&src).await.map(|_| ()),
        ErrorCode::NotFound,
        "src gone after rename",
    );
}

/// Set a user-metadata key (a C# identifier, for Azure portability) and read it
/// back, then remove one and confirm it is gone.
pub async fn update_metadata(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "update_metadata");
    require_cap!(t, supports_write, "update_metadata");
    if !t.caps.supports_native_metadata_patch && !t.caps.supports_metadata_rewrite_emulation {
        return skip(
            t.backend,
            t.access,
            "update_metadata",
            "no metadata-patch capability",
        );
    }
    let key = format!("{}meta.bin", unique_prefix("update_metadata"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let payload = b"with-metadata".to_vec();
    t.put(&key, payload.clone()).await.expect("write");
    let mut set = std::collections::HashMap::new();
    set.insert("ov_test_key".to_string(), "ov_test_value".to_string());
    set.insert("ov_remove_key".to_string(), "remove_me".to_string());
    let opts = UpdateMetadataOptions {
        user_metadata_set: set,
        allow_rewrite_emulation: true,
        ..Default::default()
    };
    t.stack()
        .update_metadata(t.addr(&key), opts, None)
        .await
        .expect("update_metadata");

    let remove = UpdateMetadataOptions {
        user_metadata_remove: vec!["ov_remove_key".to_string()],
        allow_rewrite_emulation: true,
        ..Default::default()
    };
    t.stack()
        .update_metadata(t.addr(&key), remove, None)
        .await
        .expect("update_metadata remove");

    let info = t
        .stack()
        .stat(
            t.addr(&key),
            ovstorage::StatOptions {
                full_metadata: true,
                versioned_address: false,
            },
            None,
        )
        .await
        .expect("stat full_metadata");
    let echoed = info
        .user_metadata
        .as_ref()
        .and_then(|m| m.get("ov_test_key"))
        .map(String::as_str);
    assert_eq!(echoed, Some("ov_test_value"), "metadata key echoed back");
    assert!(
        !info
            .user_metadata
            .as_ref()
            .is_some_and(|m| m.contains_key("ov_remove_key")),
        "metadata removal should drop ov_remove_key; got {info:#?}",
    );
    // A metadata patch must not touch the payload. This is the whole risk of
    // the rewrite-emulation path S3 takes: `update_metadata` there is a
    // server-side copy-onto-itself carrying new metadata, so an emulation that
    // dropped or truncated the body would satisfy every assertion above.
    assert_eq!(
        t.get(&key).await.expect("read after metadata updates"),
        payload,
        "updating metadata must leave the object's bytes intact",
    );
    assert_eq!(
        info.size,
        Some(payload.len() as u64),
        "stat after a metadata update still reports the payload size; got {info:#?}",
    );
}

/// A request carrying `principal` under `ovstorage::wrappers::ext::PRINCIPAL_ID`,
/// the way the auth Layer above an attribution wrapper stamps it.
fn attributed<T>(input: T, principal: &str) -> Request<T> {
    let mut request = Request::new(input);
    request.extensions.insert(
        ovstorage::wrappers::ext::PRINCIPAL_ID,
        principal.as_bytes().to_vec(),
    );
    request
}

/// `Layer::stat` with `full_metadata` through an arbitrary handle (the
/// attributing host or the raw Stack).
async fn stat_full(layer: &dyn ovstorage::Layer, address: Url) -> ovstorage::Result<ObjectInfo> {
    ovstorage::Layer::stat(
        layer,
        Request::new(StatRequest {
            address,
            options: ovstorage::StatOptions {
                full_metadata: true,
                ..Default::default()
            },
        }),
        None,
    )
    .await
}

/// The reserved namespace as a caller sees it through an attributing host:
/// absent, whatever the key's case. Spelled as the literal prefix so this
/// scenario pins the namespace independently of the host constant.
fn assert_reserved_namespace_hidden(user_metadata: &Option<UserMetadata>, context: &str) {
    let leaked: Vec<&String> = user_metadata
        .iter()
        .flat_map(|map| map.keys())
        .filter(|key| key.to_ascii_lowercase().starts_with("ovstorage_"))
        .collect();
    assert!(
        leaked.is_empty(),
        "{context}: reserved-namespace keys leaked through the host: {leaked:?}",
    );
}

/// What a mutating verb's own result says about attribution. The plugin
/// conformance guide makes `user_metadata` optional on a write or patch
/// result, so a backend that reports none gives the host nothing to harvest
/// and the typed slot stays empty; a backend that does report it must report
/// the principal, and the reserved key must never come back raw. `stat` is the
/// authority on what is stored, and is asserted strictly by the caller.
fn assert_reported_attribution(
    user_metadata: &Option<UserMetadata>,
    modified_by: &Option<String>,
    principal: &str,
    context: &str,
) {
    if let Some(reported) = modified_by.as_deref() {
        assert_eq!(
            reported, principal,
            "{context}: modified_by names a different principal than the one who wrote",
        );
    }
    assert_reserved_namespace_hidden(user_metadata, context);
}

/// Write, stream and patch through an attributing host, then pin what lands
/// on the wire: the host stamps the principal under the reserved key
/// `ovstorage_modified_by`, hides the reserved namespace from its callers,
/// harvests the stamp back into `ObjectInfo::modified_by`, and treats the
/// hyphenated spelling as ordinary caller metadata.
///
/// The attribution wrapper is composed at the root of the routed Stack.
/// Production places one instance per branch below the router, which differs
/// only for emulated copies (not exercised here).
pub async fn attribution_round_trip(app: &AppState, backend: Backend) {
    const SCENARIO: &str = "attribution_round_trip";
    let t = target_or_skip!(app, backend, Access::Default, SCENARIO);
    require_cap!(t, supports_write, SCENARIO);
    let inner: LayerHandle = t.stack().clone();
    let host: LayerHandle = Arc::new(AttributionWrapper::new(
        "attribution",
        inner,
        AttributionLayer::new(AttributionStrategy::UserMetadata)
            .expect("the user_metadata attribution strategy constructs"),
    ));
    let prefix = unique_prefix(SCENARIO);
    let mut guard = TempKeys::new(t);

    // A buffered write through the host, as alice, beside caller metadata.
    let attributed_key = format!("{prefix}attributed.bin");
    guard.track(t.addr(&attributed_key));
    let caller: UserMetadata = HashMap::from([("author".to_string(), "caller".to_string())]);
    let written = ovstorage::Layer::write(
        host.as_ref(),
        attributed(
            WriteRequest {
                address: t.addr(&attributed_key),
                body: Body::Bytes(b"attributed".to_vec()),
                options: WriteOptions {
                    user_metadata: Some(caller.clone()),
                    ..Default::default()
                },
            },
            "alice@example.com",
        ),
        None,
    )
    .await
    .expect("attributed write");
    assert_reported_attribution(
        &written.info.user_metadata,
        &written.info.modified_by,
        "alice@example.com",
        "write result",
    );

    // Through the host: the typed slot carries the stamp, the caller's own
    // metadata is exactly what was written, and the reserved namespace is
    // hidden whatever its case.
    let seen = stat_full(host.as_ref(), t.addr(&attributed_key))
        .await
        .expect("stat through the attributing host");
    assert_eq!(
        seen.modified_by.as_deref(),
        Some("alice@example.com"),
        "the host harvests the stamp into modified_by; got {seen:#?}",
    );
    assert_eq!(
        seen.user_metadata.as_ref(),
        Some(&caller),
        "caller metadata survives the stamp exactly; got {seen:#?}",
    );
    assert_reserved_namespace_hidden(&seen.user_metadata, "stat through host");

    // Raw, below the host: the stamp is stored under the literal reserved key.
    // S3 lowercases metadata names, the Azure plugin reads them back from
    // lowercased response headers, and GCS preserves case; the stamp is already
    // lowercase, so the same literal round-trips on all three. This is the
    // wire-spelling pin.
    let raw = t
        .stack()
        .stat(
            t.addr(&attributed_key),
            ovstorage::StatOptions {
                full_metadata: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("raw stat below the host");
    let stored = raw
        .user_metadata
        .as_ref()
        .unwrap_or_else(|| panic!("raw stat reports user_metadata; got {raw:#?}"));
    assert_eq!(
        stored.get("ovstorage_modified_by").map(String::as_str),
        Some("alice@example.com"),
        "the stamp is stored under the literal reserved key; got {raw:#?}",
    );
    assert_eq!(
        stored.get("author").map(String::as_str),
        Some("caller"),
        "caller metadata is stored beside the stamp; got {raw:#?}",
    );
    assert_eq!(
        ovstorage::ATTRIBUTION_KEY_MODIFIED_BY,
        "ovstorage_modified_by",
        "the host constant spells the key this scenario pins on the wire",
    );

    // Case normalization, pinned per backend. A raw write below the host plants
    // a mixed-case caller key beside a mixed-case variant of the reserved key;
    // both are C# identifiers, so Azure takes them too. S3 lowercases names and
    // the Azure plugin reads them back lowercased, so on those two the variant
    // lands on the reserved key itself and the host harvests it: a writer below
    // the host is outside the attribution trust boundary, which is why a host
    // composes the layer above every writer it vouches for. GCS preserves
    // case, so there the variant is a distinct key that the host hides and
    // does not harvest.
    let cased_key = format!("{prefix}cased.bin");
    guard.track(t.addr(&cased_key));
    t.stack()
        .write(
            t.addr(&cased_key),
            Body::Bytes(b"cased".to_vec()),
            WriteOptions {
                user_metadata: Some(HashMap::from([
                    ("Author".to_string(), "mixed".to_string()),
                    ("OVSTORAGE_Modified_By".to_string(), "mallory".to_string()),
                ])),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("raw write carrying mixed-case keys");
    let folds_case = matches!(t.backend, Backend::S3 | Backend::Azure);
    let raw = t
        .stack()
        .stat(
            t.addr(&cased_key),
            ovstorage::StatOptions {
                full_metadata: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("raw stat of the mixed-case object");
    let stored = raw
        .user_metadata
        .as_ref()
        .unwrap_or_else(|| panic!("raw stat reports user_metadata; got {raw:#?}"));
    if folds_case {
        assert_eq!(
            stored.get("author").map(String::as_str),
            Some("mixed"),
            "S3 and Azure hand a mixed-case name back lowercased; got {raw:#?}",
        );
        assert_eq!(
            stored.get("ovstorage_modified_by").map(String::as_str),
            Some("mallory"),
            "a folding backend lands the case variant on the reserved key; got {raw:#?}",
        );
    } else {
        assert_eq!(
            stored.get("Author").map(String::as_str),
            Some("mixed"),
            "GCS and file preserve key case; got {raw:#?}",
        );
        assert_eq!(
            stored.get("OVSTORAGE_Modified_By").map(String::as_str),
            Some("mallory"),
            "a case-preserving backend keeps the variant as a distinct key; got {raw:#?}",
        );
        assert!(
            !stored.contains_key("ovstorage_modified_by"),
            "a case-preserving backend does not fold the variant onto the reserved key; got {raw:#?}",
        );
    }
    let seen = stat_full(host.as_ref(), t.addr(&cased_key))
        .await
        .expect("stat the mixed-case object through the attributing host");
    assert_reserved_namespace_hidden(&seen.user_metadata, "stat mixed-case object through host");
    if folds_case {
        assert_eq!(
            seen.modified_by.as_deref(),
            Some("mallory"),
            "on a folding backend the variant is the reserved key, and the host harvests what is stored; got {seen:#?}",
        );
    } else {
        assert_ne!(
            seen.modified_by.as_deref(),
            Some("mallory"),
            "on a case-preserving backend the variant is hidden, not harvested; got {seen:#?}",
        );
    }

    // The streaming path (Azure's Put Block List, S3 multipart) stamps the
    // same key; the buffered write above is Put Blob / a single PUT.
    if t.caps.supports_write_stream {
        let streamed_key = format!("{prefix}streamed.bin");
        guard.track(t.addr(&streamed_key));
        let (_, chunks) = streamed_payload();
        let streamed = ovstorage::Layer::write_stream(
            host.as_ref(),
            attributed(
                WriteRequest {
                    address: t.addr(&streamed_key),
                    body: Body::Stream(BodyStream::from_iter(chunks)),
                    options: WriteOptions {
                        size_hint: None,
                        ..Default::default()
                    },
                },
                "bob@example.com",
            ),
            None,
        )
        .await
        .expect("attributed streaming write");
        assert_reported_attribution(
            &streamed.info.user_metadata,
            &streamed.info.modified_by,
            "bob@example.com",
            "write_stream result",
        );
        let seen = stat_full(host.as_ref(), t.addr(&streamed_key))
            .await
            .expect("stat the streamed object through the attributing host");
        assert_eq!(
            seen.modified_by.as_deref(),
            Some("bob@example.com"),
            "the streaming path stamps the principal; got {seen:#?}",
        );
        assert_reserved_namespace_hidden(&seen.user_metadata, "stat streamed object through host");
    }

    // A metadata patch through the host re-stamps as the patching principal
    // and keeps the caller's patch.
    if t.caps.supports_native_metadata_patch || t.caps.supports_metadata_rewrite_emulation {
        let patched = ovstorage::Layer::update_metadata(
            host.as_ref(),
            attributed(
                UpdateMetadataRequest {
                    address: t.addr(&attributed_key),
                    options: UpdateMetadataOptions {
                        user_metadata_set: HashMap::from([(
                            "author".to_string(),
                            "patched".to_string(),
                        )]),
                        allow_rewrite_emulation: true,
                        ..Default::default()
                    },
                },
                "carol@example.com",
            ),
            None,
        )
        .await
        .expect("attributed update_metadata");
        assert_reported_attribution(
            &patched.user_metadata,
            &patched.modified_by,
            "carol@example.com",
            "update_metadata result",
        );
        let seen = stat_full(host.as_ref(), t.addr(&attributed_key))
            .await
            .expect("stat the patched object through the attributing host");
        assert_eq!(
            seen.modified_by.as_deref(),
            Some("carol@example.com"),
            "a metadata patch re-stamps as the patching principal; got {seen:#?}",
        );
        assert_eq!(
            seen.user_metadata
                .as_ref()
                .and_then(|m| m.get("author"))
                .map(String::as_str),
            Some("patched"),
            "the caller's patch lands beside the stamp; got {seen:#?}",
        );
        assert_reserved_namespace_hidden(&seen.user_metadata, "stat patched object through host");
    } else {
        skip(
            t.backend,
            t.access,
            SCENARIO,
            "no metadata-patch capability",
        );
    }

    // The hyphenated spelling is ordinary caller metadata: neither harvested
    // nor hidden. Azure's own metadata-name rule refuses a hyphen, which is
    // the backend's rule, not the host's, so that backend is not asked.
    if !matches!(t.backend, Backend::Azure) {
        let planted_key = format!("{prefix}planted.bin");
        guard.track(t.addr(&planted_key));
        ovstorage::Layer::write(
            host.as_ref(),
            attributed(
                WriteRequest {
                    address: t.addr(&planted_key),
                    body: Body::Bytes(b"planted".to_vec()),
                    options: WriteOptions {
                        user_metadata: Some(HashMap::from([(
                            "ovstorage-modified-by".to_string(),
                            "planted".to_string(),
                        )])),
                        ..Default::default()
                    },
                },
                "dave@example.com",
            ),
            None,
        )
        .await
        .expect("write carrying the hyphenated key");
        let seen = stat_full(host.as_ref(), t.addr(&planted_key))
            .await
            .expect("stat the planted object through the attributing host");
        assert_eq!(
            seen.modified_by.as_deref(),
            Some("dave@example.com"),
            "the hyphenated key is not harvested into modified_by; got {seen:#?}",
        );
        assert_eq!(
            seen.user_metadata
                .as_ref()
                .and_then(|m| m.get("ovstorage-modified-by"))
                .map(String::as_str),
            Some("planted"),
            "the hyphenated key is ordinary metadata and is not hidden; got {seen:#?}",
        );
    }
}

/// The user metadata a raw `stat` with `full_metadata` reports for `key`.
/// A backend that keeps user metadata reports it here, so an absent map is a
/// failure, not a skip.
async fn stored_user_metadata(t: &Target, key: &str, context: &str) -> UserMetadata {
    let info = stat_full(t.stack().as_ref(), t.addr(key))
        .await
        .unwrap_or_else(|error| panic!("{context}: stat full_metadata failed: {error:?}"));
    info.user_metadata
        .clone()
        .unwrap_or_else(|| panic!("{context}: stat reports no user_metadata; got {info:#?}"))
}

/// Write, copy, and patch carrying a caller `message`, then pin where the
/// annotation lands: in user metadata under the literal key `x_ov_message`,
/// beside the caller's own keys.
///
/// The key is spelled inside the portable subset because every backend that
/// stashes the annotation has to be able to store it, and Azure refuses a
/// metadata name that is not a C# identifier. It is spelled OUTSIDE the
/// reserved `ovstorage_` namespace on purpose: an attributing host strips and
/// hides that namespace, and the annotation is the caller's own note, so it
/// stays visible through such a host. Every write-family row in the coverage
/// baseline whose backend stores user metadata owes this scenario (the file
/// backend stores none, and its row excludes it); it is the coverage whose
/// absence let a metadata header that Azure refuses ship. The literal is the
/// wire-spelling pin, and the shared constant is asserted against it so drift
/// is loud. Every backend that stashes the annotation records it on a write
/// and on a patch, so both halves run wherever the scenario runs. Every
/// backend keeps the source's own keys on a copy that carries a message;
/// whether the copy also records the annotation is per backend, and the
/// scenario pins each answer.
pub async fn message_annotation(app: &AppState, backend: Backend) {
    const SCENARIO: &str = "message_annotation";
    let t = target_or_skip!(app, backend, Access::Default, SCENARIO);
    require_cap!(t, supports_write, SCENARIO);
    let prefix = unique_prefix(SCENARIO);
    let key = format!("{prefix}annotated.bin");
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let caller: UserMetadata = HashMap::from([("author".to_string(), "caller".to_string())]);
    t.stack()
        .write(
            t.addr(&key),
            Body::Bytes(b"annotated".to_vec()),
            WriteOptions {
                user_metadata: Some(caller),
                message: Some("suite annotation".to_string()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("write carrying a message");

    let stored = stored_user_metadata(t, &key, "stat after the annotated write").await;
    assert_eq!(
        stored.get("x_ov_message").map(String::as_str),
        Some("suite annotation"),
        "a write carrying a message stores it under the literal portable key; got {stored:#?}",
    );
    assert_eq!(
        stored.get("author").map(String::as_str),
        Some("caller"),
        "caller metadata is stored beside the annotation; got {stored:#?}",
    );
    assert_eq!(
        ovstorage::MESSAGE_METADATA_KEY,
        "x_ov_message",
        "the shared constant spells the key this scenario pins on the wire",
    );

    // A copy carrying a message keeps the source's own keys: no backend drops
    // caller metadata on a copy. Whether the copy also records the annotation
    // is per backend: the file backend and GCS write it into the destination,
    // while S3 and Azure copy the source's metadata verbatim, so there the
    // destination carries the source's annotation.
    let copied_key = format!("{prefix}copied.bin");
    guard.track(t.addr(&copied_key));
    t.stack()
        .copy(
            t.addr(&key),
            t.addr(&copied_key),
            CopyOptions {
                message: Some("copy note".to_string()),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("copy carrying a message");
    let copied = stored_user_metadata(t, &copied_key, "stat after the annotated copy").await;
    assert_eq!(
        copied.get("author").map(String::as_str),
        Some("caller"),
        "a copy carrying a message keeps the source's own keys; got {copied:#?}",
    );
    // The annotation must not cost the copy its system metadata either: a
    // backend that reports the source's content type reports the same one on
    // the annotated copy. On GCS an annotated rewrite sends a body, which
    // replaces the destination's editable metadata wholesale, so the plugin
    // has to carry the source's fields itself.
    let source_info = stat_full(t.stack().as_ref(), t.addr(&key))
        .await
        .expect("stat the annotated source");
    let copied_info = stat_full(t.stack().as_ref(), t.addr(&copied_key))
        .await
        .expect("stat the annotated copy");
    let content_type = |info: &ObjectInfo| {
        info.system_metadata
            .as_ref()
            .and_then(|m| m.get("content-type"))
            .cloned()
    };
    if let Some(source_type) = content_type(&source_info) {
        assert_eq!(
            content_type(&copied_info),
            Some(source_type),
            "an annotated copy keeps the source's content type; source {source_info:#?}, copy {copied_info:#?}",
        );
    }
    let expected_annotation = if t.backend == Backend::Gcs {
        "copy note"
    } else {
        "suite annotation"
    };
    assert_eq!(
        copied.get("x_ov_message").map(String::as_str),
        Some(expected_annotation),
        "the copy carries the annotation its backend records; got {copied:#?}",
    );

    // A patch carrying a message stores the annotation, replacing any earlier
    // one, and leaves the caller's keys alone, whether the backend patches
    // natively or rewrites the object to carry the new metadata.
    if t.caps.supports_native_metadata_patch || t.caps.supports_metadata_rewrite_emulation {
        t.stack()
            .update_metadata(
                t.addr(&key),
                UpdateMetadataOptions {
                    message: Some("patched annotation".to_string()),
                    allow_rewrite_emulation: true,
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("update_metadata carrying a message");
        let stored = stored_user_metadata(t, &key, "stat after the annotated patch").await;
        assert_eq!(
            stored.get("x_ov_message").map(String::as_str),
            Some("patched annotation"),
            "a patch carrying a message stores the annotation under the literal portable key; \
             got {stored:#?}",
        );
        assert_eq!(
            stored.get("author").map(String::as_str),
            Some("caller"),
            "caller metadata survives an annotated patch; got {stored:#?}",
        );
    } else {
        skip(
            t.backend,
            t.access,
            SCENARIO,
            "no metadata-patch capability",
        );
    }
}

/// `check_access` on a configured target's own root must ALLOW read.
///
/// The verdict is asserted, not merely well-formedness: every credential this
/// suite configures is one the fixture grants read on, so a deny here is a real
/// regression (a broken principal, a mis-scoped SAS) rather than a legitimate
/// policy answer. A scenario that accepted either verdict would pass through
/// exactly that failure.
pub async fn check_access(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "check_access");
    require_cap!(t, supports_access_check, "check_access");
    let decision = ovstorage::Layer::check_access(
        t.stack().as_ref(),
        Request::new(CheckAccessRequest {
            address: t.addr(""),
            operations: AccessOps {
                read: true,
                ..Default::default()
            },
        }),
        None,
    )
    .await
    .expect("check_access");
    assert!(
        decision.allowed && !decision.denied_ops.read,
        "configured default target should allow read access, got {decision:#?}",
    );
}

/// stat/read of a missing key both surface `NotFound`.
pub async fn error_path_not_found(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "error_path_not_found");
    let key = format!("{}missing.bin", unique_prefix("error_path_not_found"));
    assert_error(
        t.stat(&key).await.map(|_| ()),
        ErrorCode::NotFound,
        "stat missing",
    );
    assert_error(
        t.get(&key).await.map(|_| ()),
        ErrorCode::NotFound,
        "read missing",
    );
}

// === extended coverage ===

/// Byte-range read returns exactly the requested sub-range.
pub async fn range_read(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "range_read");
    require_cap!(t, supports_write, "range_read");
    let key = format!("{}ranged.bin", unique_prefix("range_read"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let payload: Vec<u8> = (0u8..32).collect();
    t.put(&key, payload.clone()).await.expect("write");
    let opts = ReadOptions {
        range: Some(ByteRange {
            start: 4,
            end_inclusive: Some(11),
        }),
        ..Default::default()
    };
    match t.stack().read_bytes(t.addr(&key), opts, None).await {
        Ok((bytes, _)) => assert_eq!(bytes, payload[4..=11], "range slice matches"),
        Err(e) if e.code() == ErrorCode::Unsupported => skip(
            t.backend,
            t.access,
            "range_read",
            "backend does not support range reads",
        ),
        Err(e) => panic!("range read failed: {e:?}"),
    }
}

/// Streamed reads and materialization both return the same bytes as a buffered
/// read. On cloud targets `materialize` is served by the redirect follower's
/// staged-temp-file fallback, with no byte cache composed.
pub async fn read_stream_and_materialize(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "read_stream_and_materialize");
    require_cap!(t, supports_write, "read_stream_and_materialize");
    let key = format!(
        "{}stream-read.bin",
        unique_prefix("read_stream_and_materialize")
    );
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    t.put(&key, payload.clone()).await.expect("write");

    let (mut stream, info) = t
        .stack()
        .read_stream(t.addr(&key), ReadOptions::default(), None)
        .await
        .expect("read_stream");
    assert_eq!(info.size, Some(payload.len() as u64), "stream info size");
    let mut streamed = Vec::new();
    while let Some(chunk) = stream.next().await {
        streamed.extend(chunk.expect("read_stream chunk"));
    }
    assert_eq!(streamed, payload, "read_stream bytes match");

    let delegate = t
        .stack()
        .materialize(t.addr(&key), ReadOptions::default(), None)
        .await
        .expect("materialize");
    let materialized = std::fs::read(&delegate.path)
        .unwrap_or_else(|e| panic!("read materialized file {}: {e}", delegate.path.display()));
    assert_eq!(materialized, payload, "materialized bytes match");
}

/// Address composition preserves keys containing URL-reserved characters.
pub async fn key_encoding(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "key_encoding");
    require_cap!(t, supports_write, "key_encoding");
    let key = format!(
        "{}dir/a b%literal?query#fragment.txt",
        unique_prefix("key_encoding")
    );
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let payload = b"reserved-address-chars".to_vec();
    t.put(&key, payload.clone())
        .await
        .expect("write encoded key");
    assert_eq!(
        t.get(&key).await.expect("read encoded key"),
        payload,
        "encoded key round-trips",
    );
}

/// Conditional writes: create-only (no-overwrite) and etag compare-and-set.
pub async fn conditional_write(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "conditional_write");
    require_cap!(t, supports_write, "conditional_write");
    if !t.caps.supports_no_overwrite_write && !t.caps.supports_if_match_write {
        return skip(
            t.backend,
            t.access,
            "conditional_write",
            "no conditional-write capability",
        );
    }
    let key = format!("{}cas.bin", unique_prefix("conditional_write"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));
    t.put(&key, b"v1".to_vec()).await.expect("seed write");
    // What the object must still contain after each REJECTED write. An error
    // code proves the call was refused; it does not prove nothing was written.
    // A backend that streams the body first and evaluates the precondition
    // afterwards returns the right error and still clobbers the object, and
    // that is the failure a conditional write exists to prevent.
    let mut expected: &[u8] = b"v1";

    if t.caps.supports_no_overwrite_write {
        let opts = WriteOptions {
            if_dest: IfDestExists::Fail,
            ..Default::default()
        };
        let res = t
            .stack()
            .write(t.addr(&key), Body::Bytes(b"v2".to_vec()), opts, None)
            .await;
        // Create-only on an existing key: the file backend returns
        // AlreadyExists, while the cloud backends implement no-overwrite as
        // If-None-Match:* and surface the 412 as PreconditionFailed.
        assert_error_one_of(
            res.map(|_| ()),
            &[ErrorCode::AlreadyExists, ErrorCode::PreconditionFailed],
            "create-only on existing key",
        );
        assert_eq!(
            t.get(&key).await.expect("read after rejected create-only"),
            expected,
            "a rejected create-only write must leave the existing object untouched",
        );
    }

    if t.caps.supports_if_match_write {
        let info = t.stat(&key).await.expect("stat for etag");
        assert_target_etag_strength(t.backend, &info, "stat for conditional write");
        let etag = match info.etag {
            Some(e) => e,
            None => {
                return skip(
                    t.backend,
                    t.access,
                    "conditional_write",
                    "backend exposes no etag",
                );
            }
        };
        // Matching etag → success. The new content is a *different size* so the
        // object's etag definitively advances on every backend — including the
        // file backend, whose etag is `size:N,mtime:T` and could otherwise
        // collide for two same-size writes in the same mtime tick.
        let ok = WriteOptions {
            if_dest: IfDestExists::MatchEtag(etag.clone()),
            ..Default::default()
        };
        t.stack()
            .write(
                t.addr(&key),
                Body::Bytes(b"v3-rewritten-content".to_vec()),
                ok,
                None,
            )
            .await
            .expect("if-match write with current etag");
        expected = b"v3-rewritten-content";
        assert_eq!(
            t.get(&key).await.expect("read after accepted if-match"),
            expected,
            "an accepted if-match write must store the new bytes",
        );
        // The matching write advanced the etag, so the *prior* `etag` is now
        // stale and must be rejected. Reusing a real prior etag (rather than a
        // synthetic string) keeps the value a valid shape for every backend:
        // GCS maps MatchEtag to a numeric `ifGenerationMatch` and 400s a
        // non-numeric value before it can evaluate the precondition.
        let stale = WriteOptions {
            if_dest: IfDestExists::MatchEtag(etag),
            ..Default::default()
        };
        let res = t
            .stack()
            .write(t.addr(&key), Body::Bytes(b"v4".to_vec()), stale, None)
            .await;
        // A failed caller precondition maps to ObjectModified on the cloud
        // plugins but PreconditionFailed on the file backend; both mean the
        // etag guard rejected the write.
        assert_error_one_of(
            res.map(|_| ()),
            &[ErrorCode::ObjectModified, ErrorCode::PreconditionFailed],
            "if-match write with stale etag",
        );
        assert_eq!(
            t.get(&key).await.expect("read after rejected if-match"),
            expected,
            "a rejected if-match write must leave the object at its current content",
        );
    }
}

/// Check the declaration promised by the concrete fixtures this suite drives.
/// This is not a universal `ObjectInfo` invariant: other plugins may return an
/// opaque etag with [`EtagStrength::Unspecified`].
fn assert_target_etag_strength(backend: Backend, info: &ObjectInfo, context: &str) {
    let expected = match (&info.etag, backend) {
        (None, _) => EtagStrength::Unspecified,
        (Some(_), Backend::File) => EtagStrength::Weak,
        (Some(_), Backend::Azure | Backend::S3 | Backend::Gcs | Backend::Huggingface) => {
            EtagStrength::Strong
        }
    };
    assert_eq!(
        info.etag_strength,
        expected,
        "{context}: {} fixture returned unexpected etag strength",
        backend.label(),
    );
}

/// Check the pin promised by the concrete fixtures this suite drives. This is
/// not a universal `ObjectInfo` invariant: other plugins may answer `None`.
///
/// `flagged` says whether the request set `versioned_address`. Only then is
/// the per-backend table enforced; an unflagged answer may still carry a pin
/// the backend had for free (over-delivery is legal), so it gets the
/// consistency checks alone.
fn assert_target_versioned_address(
    backend: Backend,
    info: &ObjectInfo,
    flagged: bool,
    context: &str,
) {
    // The query key each fixture pins with; `None` for a backend that never
    // versions. Azure's HNS target answers `None` too, and no call site routes
    // an `Access::Hns` target here.
    let key = match backend {
        Backend::File => None,
        Backend::S3 => Some("versionId"),
        Backend::Azure => Some("versionid"),
        Backend::Gcs => Some("generation"),
        Backend::Huggingface => Some("revision"),
    };
    // Whether a flagged request may still answer `None`: the default S3
    // bucket is unversioned (no id, or the literal `null` of a suspended or
    // never-versioned bucket), Azurite reports no version id, and a Hugging
    // Face object without a resolved revision has nothing to pin; a GCS
    // object always has a generation.
    let none_is_legal = match backend {
        Backend::File => true,
        Backend::Gcs => false,
        Backend::S3 => info.version.as_deref().is_none_or(|v| v == "null"),
        Backend::Azure | Backend::Huggingface => info.version.is_none(),
    };
    match (&info.versioned_address, key) {
        (None, None) => {}
        (Some(pin), None) => panic!(
            "{context}: {} never versions, yet it reported the pin {pin}",
            backend.label(),
        ),
        (None, Some(_)) => assert!(
            !flagged || none_is_legal,
            "{context}: a flagged request on a versioned {} object returned no pin: {info:#?}",
            backend.label(),
        ),
        (Some(pin), Some(key)) => {
            assert_eq!(
                pin.path(),
                info.address.path(),
                "{context}: the pin {pin} names another object than {}",
                info.address,
            );
            let value = pin
                .query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned());
            assert!(
                value.is_some(),
                "{context}: the pin {pin} carries no `{key}` query key",
            );
            // Hugging Face may pin a stat that reports no `version`; every
            // other fixture's `version` IS the pin value.
            if backend != Backend::Huggingface || info.version.is_some() {
                assert_eq!(
                    value.as_deref(),
                    info.version.as_deref(),
                    "{context}: the pin's `{key}` differs from `version` on {info:#?}",
                );
            }
        }
    }
}

/// The streamed payload the streaming-write scenarios upload: 1 MiB chunks
/// (eight of them, or one under `OVSTORAGE_LIVE_FAST`) whose byte `i` is
/// `i % 251`, so a read-back can verify every byte. Returns the total size and
/// the chunk iterator.
fn streamed_payload() -> (
    usize,
    impl Iterator<Item = ovstorage::Result<Vec<u8>>> + Send + 'static,
) {
    let chunk = 1usize << 20; // 1 MiB
    let mib = if std::env::var("OVSTORAGE_LIVE_FAST").is_ok() {
        1
    } else {
        8
    };
    let chunks = (0..mib).map(move |i| -> ovstorage::Result<Vec<u8>> {
        let mut buf = vec![0u8; chunk];
        for (j, b) in buf.iter_mut().enumerate() {
            *b = ((i * chunk + j) % 251) as u8;
        }
        Ok(buf)
    });
    (chunk * mib, chunks)
}

/// Streaming upload that crosses the multipart/block threshold, with a
/// byte-integrity read-back. Size is shrinkable via `OVSTORAGE_LIVE_FAST`.
pub async fn write_stream(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Default, "write_stream");
    require_cap!(t, supports_write_stream, "write_stream");
    let key = format!("{}stream.bin", unique_prefix("write_stream"));
    let mut guard = TempKeys::new(t);
    guard.track(t.addr(&key));

    let (total, chunks) = streamed_payload();
    // `Layer::write_stream` (not the ergonomic `LayerExt::write`, which always
    // dispatches the buffered `write` slot) with size_hint=None routes through
    // the block-staging / multipart streaming path rather than a single
    // presigned PUT. A presigned PUT can't accept a streamed body — the
    // follower would send Transfer-Encoding: chunked, which Azure (400
    // UnsupportedHeader) and S3 (501) reject.
    ovstorage::Layer::write_stream(
        t.stack().as_ref(),
        Request::new(WriteRequest {
            address: t.addr(&key),
            body: Body::Stream(BodyStream::from_iter(chunks)),
            options: WriteOptions {
                size_hint: None,
                ..Default::default()
            },
        }),
        None,
    )
    .await
    .expect("streaming write");

    let got = t.get(&key).await.expect("read back streamed object");
    assert_eq!(got.len(), total, "streamed object size");
    assert!(
        got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8),
        "streamed object byte-integrity",
    );
}

/// Directory create → stat-classify → delete, on a backend with real
/// directories (file = native, Azure = ADLS Gen2 HNS). Pins the host
/// dispatcher's directory-stat path end to end.
pub async fn directory_ops(app: &AppState, backend: Backend) {
    let Some(t) = app.target_where(backend, |c| {
        c.has_real_directories && c.supports_create_directory && c.supports_delete_directory
    }) else {
        return skip(
            backend,
            Access::Default,
            "directory_ops",
            "no real-directory target",
        );
    };
    let dir = format!("{}adir", unique_prefix("directory_ops"));
    let mut guard = TempDirs::new(t);
    guard.track(t.addr(&dir));

    t.stack()
        .create_directory(t.addr(&dir), CreateDirectoryOptions::default(), None)
        .await
        .expect("create_directory");

    let info = t
        .stack()
        .stat(
            t.addr(&format!("{dir}/")),
            ovstorage::StatOptions::default(),
            None,
        )
        .await
        .expect("stat directory");
    assert!(
        matches!(
            info.kind,
            ObjectKind::Directory | ObjectKind::DirectoryMarker | ObjectKind::DirectoryInferred
        ),
        "directory must classify as a directory kind, got {:?}",
        info.kind,
    );

    t.stack()
        .delete_directory(t.addr(&dir), DeleteDirectoryOptions, None)
        .await
        .expect("delete_directory");
}

/// Flat object stores expose directory creation through marker objects rather
/// than real directory inodes. Exercise that advertised surface separately from
/// HNS/file real-directory semantics.
pub async fn directory_marker_ops(app: &AppState, backend: Backend) {
    let Some(t) = app.target_where(backend, |c| {
        !c.has_real_directories && c.supports_create_directory && c.supports_delete_directory
    }) else {
        return skip(
            backend,
            Access::Default,
            "directory_marker_ops",
            "no flat directory-marker target",
        );
    };
    if let Some(why) = scenario_exclusion(t, "directory_marker_ops") {
        return skip(t.backend, t.access, "directory_marker_ops", why);
    }
    let dir = format!("{}marker", unique_prefix("directory_marker_ops"));
    let mut guard = TempDirs::new(t);
    guard.track(t.addr(&dir));

    t.stack()
        .create_directory(t.addr(&dir), CreateDirectoryOptions::default(), None)
        .await
        .expect("create directory marker");
    let info = t
        .stack()
        .stat(
            t.addr(&format!("{dir}/")),
            ovstorage::StatOptions::default(),
            None,
        )
        .await
        .expect("stat directory marker");
    assert!(
        matches!(
            info.kind,
            ObjectKind::DirectoryMarker | ObjectKind::DirectoryInferred | ObjectKind::Directory
        ),
        "flat directory create should classify as directory-like, got {:?}",
        info.kind,
    );
    t.stack()
        .delete_directory(t.addr(&dir), DeleteDirectoryOptions, None)
        .await
        .expect("delete directory marker");
}

/// Two writes to a versioning-enabled target expose ≥2 distinct versions.
pub async fn list_versions(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Versioned, "list_versions");
    require_cap!(t, supports_version_listing, "list_versions");
    let key = format!("{}versioned.bin", unique_prefix("list_versions"));
    let mut guard = VersionedTempKeys::new(t);
    guard.track_base(t.addr(&key));

    t.put(&key, b"v1".to_vec()).await.expect("write v1");
    t.put(&key, b"v2".to_vec()).await.expect("write v2");

    let versions = ovstorage::Layer::list_versions(
        t.stack().as_ref(),
        Request::new(ListVersionsRequest {
            address: t.addr(&key),
            options: ListVersionsOptions::default(),
        }),
        None,
    )
    .await
    .expect("list_versions")
    .items;
    let distinct: std::collections::HashSet<_> =
        versions.iter().filter_map(|v| v.version.clone()).collect();
    assert!(
        distinct.len() >= 2,
        "a versioned target must retain ≥2 distinct versions, got {}: {versions:#?}",
        distinct.len(),
    );
    for v in &versions {
        // A version entry's address is already the pin, so it names itself.
        assert_eq!(
            v.versioned_address.as_ref(),
            Some(&v.address),
            "list_versions entry names itself as its pin: {v:#?}",
        );
        if v.version.is_some() {
            guard.track_pinned(v.address.clone());
        }
    }
    let mut bodies = std::collections::HashSet::new();
    for v in versions.iter().filter(|v| v.version.is_some()) {
        let (bytes, _) = t
            .stack()
            .read_bytes(v.address.clone(), ReadOptions::default(), None)
            .await
            .expect("read pinned version");
        bodies.insert(bytes);
    }
    assert!(
        bodies.contains(b"v1".as_slice()) && bodies.contains(b"v2".as_slice()),
        "version list should expose readable v1 and v2 pins; got bodies={bodies:?}, versions={versions:#?}",
    );
}

/// get_latest_version returns a concrete version id on a versioned target.
pub async fn get_latest_version(app: &AppState, backend: Backend) {
    let t = target_or_skip!(app, backend, Access::Versioned, "get_latest_version");
    require_cap!(t, supports_version_listing, "get_latest_version");
    let prefix = unique_prefix("get_latest_version");
    let key = format!("{prefix}latest.bin");
    let mut guard = VersionedTempKeys::new(t);
    guard.track_base(t.addr(&key));

    t.put(&key, b"v1".to_vec()).await.expect("write v1");
    t.put(&key, b"v2".to_vec()).await.expect("write v2");

    let info = ovstorage::Layer::get_latest_version(
        t.stack().as_ref(),
        Request::new(ReadRequest {
            address: t.addr(&key),
            options: ReadOptions::default(),
        }),
        None,
    )
    .await
    .expect("get_latest_version");
    assert!(
        info.version.is_some(),
        "get_latest_version must return a concrete version id, got {info:#?}",
    );
    assert!(
        info.address.as_str().contains('?'),
        "get_latest_version should return a version-pinned address, got {}",
        info.address,
    );
    assert_eq!(
        info.versioned_address.as_ref(),
        Some(&info.address),
        "get_latest_version names itself as its pin: {info:#?}",
    );
    guard.track_pinned(info.address.clone());
    let latest = t
        .stack()
        .read_bytes(info.address.clone(), ReadOptions::default(), None)
        .await
        .expect("read latest pinned version")
        .0;
    assert_eq!(latest, b"v2", "latest pinned version reads the newest body");

    // The two cheaper routes to the same pin must agree with it: a flagged
    // stat of the head, and a flagged list of the parent prefix (the one
    // place the version-aware listing runs on a fixture that versions).
    let flagged = t
        .stat_with(
            &key,
            StatOptions {
                versioned_address: true,
                ..Default::default()
            },
        )
        .await
        .expect("flagged stat of the head");
    assert_target_versioned_address(t.backend, &flagged, true, "flagged stat of the head");
    assert_eq!(
        flagged.versioned_address.as_ref(),
        Some(&info.address),
        "a flagged stat of the head agrees with get_latest_version: {flagged:#?}",
    );
    let listed = t
        .stack()
        .list_page(
            t.addr(&prefix),
            ListOptions {
                versioned_address: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("flagged list of the parent prefix");
    let entry = listed
        .items
        .iter()
        .find(|item| item.address.as_str().ends_with("latest.bin"))
        .unwrap_or_else(|| panic!("flagged list of {prefix} misses latest.bin: {listed:#?}"));
    assert_target_versioned_address(t.backend, entry, true, "flagged list entry for the head");
    assert_eq!(
        entry.versioned_address.as_ref(),
        Some(&info.address),
        "a flagged list of the parent prefix pins the head at the version get_latest_version reports: {entry:#?}",
    );
}

// === read-only live fixtures ===
//
// The read family: scenarios for a backend that advertises listing but not
// writing (supports_list && !supports_write). They discover an object from the
// fixture itself, pin their follow-up operations to the version the listing
// reported wherever the backend supplies one, and assert only
// self-consistency — stat size == list size == read length, range == slice of
// the full read, pinned re-read == unpinned read — never names, counts, or
// hashes of the third-party fixture.
// Write-capable targets skip them visibly: the write family already covers
// this surface with fixtures it mints itself.

/// Read-family transfer bound: discovery ignores fixture files above this, and
/// buffered reads carry it as `max_bytes`, so a mispointed fixture cannot turn
/// the suite into a download job.
const MAX_READ_OBJECT_BYTES: u64 = 4 * 1024 * 1024;
/// Upper bound on the discovery listing walk.
const MAX_DISCOVERY_PAGES: usize = 20;
/// A syntactically valid version id no repository resolves (the all-zeros git
/// object id), used to prove the backend honors — rather than ignores — a
/// revision pin.
const ABSENT_REVISION: &str = "0000000000000000000000000000000000000000";

/// Recursively list from the target root; return address, listed size, and the
/// listing's version id (when the backend supplies one) of the smallest file
/// whose size is in `[min_size, MAX_READ_OBJECT_BYTES]`.
///
/// The pick is the smallest such file within the first
/// [`MAX_DISCOVERY_PAGES`] pages — an accepted truncation on a larger fixture.
///
/// Panics when the scanned pages hold none: the target connected and listed,
/// so an unusable repo is a broken fixture contract, not a missing capability.
async fn smallest_listed_object(
    t: &Target,
    min_size: u64,
    scenario: &str,
) -> (Url, u64, Option<String>) {
    let mut best: Option<(Url, u64, Option<String>)> = None;
    let mut page_token: Option<String> = None;
    let mut truncated = false;
    for _ in 0..MAX_DISCOVERY_PAGES {
        let page = t
            .stack()
            .list_page(
                t.root.clone(),
                ListOptions {
                    recursive: true,
                    // No page cap: a read-only backend may serve pages by
                    // re-materializing the whole tree, so asking for small
                    // pages multiplies wire crawls instead of bounding them.
                    // MAX_READ_OBJECT_BYTES bounds the transfer that matters.
                    max_results: None,
                    page_token: page_token.take(),
                    full_metadata: true,
                    versioned_address: false,
                },
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("{scenario}: recursive list of {} failed: {e:?}", t.root));
        for entry in page.items {
            if entry.kind != ObjectKind::File {
                continue;
            }
            let Some(size) = entry.size else { continue };
            if size < min_size || size > MAX_READ_OBJECT_BYTES {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|(_, smallest, _)| size < *smallest)
            {
                best = Some((entry.address, size, entry.version));
            }
        }
        match page.next_page_token {
            Some(token) => {
                page_token = Some(token);
                truncated = true;
            }
            None => {
                truncated = false;
                break;
            }
        }
    }
    best.unwrap_or_else(|| {
        if truncated {
            panic!(
                "{scenario}: the fixture repo's first {MAX_DISCOVERY_PAGES} listing pages hold \
                 no file between {min_size} and {MAX_READ_OBJECT_BYTES} bytes under {}; a later \
                 page may — point the fixture (OVSTORAGE_HUGGINGFACE_REPO_ID) at a repo whose \
                 small files list early",
                t.root,
            )
        }
        panic!(
            "{scenario}: the fixture repo lists no file between {min_size} and \
             {MAX_READ_OBJECT_BYTES} bytes under {}; point the fixture \
             (OVSTORAGE_HUGGINGFACE_REPO_ID) at a repo with at least one small file",
            t.root,
        )
    })
}

/// Pin `address` to `version` with the `revision` query key — the pin grammar
/// of the `hf://` scheme, the suite's one read-only address family.
fn revision_pinned(address: &Url, version: &str) -> Url {
    ovstorage::address::with_query_pair(address, "revision", version)
        .expect("append the revision pin")
}

/// `address` pinned at the listing's version when the backend supplied one:
/// list, stat, and read then observe one snapshot, so a fixture push between
/// the calls cannot skew their agreement.
fn listed_snapshot(address: &Url, version: &Option<String>) -> Url {
    match version {
        Some(version) => revision_pinned(address, version),
        None => address.clone(),
    }
}

/// Bounded buffered read: the discovery size cap, enforced on the wire too.
fn bounded_read() -> ReadOptions {
    ReadOptions {
        max_bytes: Some(MAX_READ_OBJECT_BYTES),
        ..Default::default()
    }
}

/// The read family's load-bearing scenario: recursive list from the fixture
/// root, then stat + full read of the smallest listed object, with three-way
/// size agreement (list == stat == read length).
pub async fn read_only_list_stat_read(app: &AppState, backend: Backend) {
    const NAME: &str = "read_only_list_stat_read";
    let t = target_or_skip!(app, backend, Access::Default, NAME);
    require_cap!(t, supports_list, NAME);
    if t.caps.supports_write {
        return skip(
            t.backend,
            t.access,
            NAME,
            "write-capable target; the write family covers it",
        );
    }

    let (address, listed_size, version) = smallest_listed_object(t, 1, NAME).await;
    let snapshot = listed_snapshot(&address, &version);
    let info = t
        .stack()
        .stat(
            snapshot.clone(),
            ovstorage::StatOptions {
                full_metadata: false,
                versioned_address: false,
            },
            None,
        )
        .await
        .expect("stat listed object");
    assert_eq!(
        info.size,
        Some(listed_size),
        "stat size agrees with the listing",
    );
    let (bytes, _) = t
        .stack()
        .read_bytes(snapshot, bounded_read(), None)
        .await
        .expect("read listed object");
    assert_eq!(
        bytes.len() as u64,
        listed_size,
        "read length agrees with the listing",
    );
}

/// Byte-range read of a discovered object equals the strict-interior slice of
/// its full read. Both reads observe the listing's snapshot, and the range
/// excludes both endpoints, so a backend that ignored the range and returned
/// the whole body cannot pass.
pub async fn read_only_range_read(app: &AppState, backend: Backend) {
    const NAME: &str = "read_only_range_read";
    let t = target_or_skip!(app, backend, Access::Default, NAME);
    require_cap!(t, supports_list, NAME);
    if t.caps.supports_write {
        return skip(
            t.backend,
            t.access,
            NAME,
            "write-capable target; the write family covers it",
        );
    }

    let (address, _size, version) = smallest_listed_object(t, 3, NAME).await;
    let snapshot = listed_snapshot(&address, &version);
    let (full, _) = t
        .stack()
        .read_bytes(snapshot.clone(), bounded_read(), None)
        .await
        .expect("full read");
    assert!(full.len() >= 3, "discovery guarantees at least three bytes");

    // Strict interior for every len >= 3: excludes byte 0 and the last byte,
    // so the expected slice is provably shorter than the full body.
    let start = 1u64;
    let end_inclusive = full.len() as u64 - 2;
    let opts = ReadOptions {
        range: Some(ByteRange {
            start,
            end_inclusive: Some(end_inclusive),
        }),
        ..Default::default()
    };
    match t.stack().read_bytes(snapshot, opts, None).await {
        Ok((ranged, _)) => {
            assert!(
                ranged.len() < full.len(),
                "a honored range returns strictly fewer bytes than the full body",
            );
            assert_eq!(
                ranged,
                full[start as usize..=end_inclusive as usize],
                "range equals the slice of the full read",
            );
        }
        Err(e) if e.code() == ErrorCode::Unsupported => skip(
            t.backend,
            t.access,
            NAME,
            "backend does not support range reads",
        ),
        Err(e) => panic!("ranged read failed: {e:?}"),
    }
}

/// Version pinning is honored, not merely tolerated: a pinned re-read at the
/// serving version returns the same bytes, a pin no repository resolves is
/// `NotFound` (an ignored pin would answer the current body instead), and
/// `get_latest_version` returns the discovered address pinned at exactly the
/// version it reports. The listing asserts shape only — mutable refs can be
/// rewritten between calls, so ids observed earlier are not required to remain
/// members; a run whose connection pins `OVSTORAGE_HUGGINGFACE_REVISION` roots
/// every observation in one immutable commit.
pub async fn read_only_version_pinning(app: &AppState, backend: Backend) {
    const NAME: &str = "read_only_version_pinning";
    let t = target_or_skip!(app, backend, Access::Default, NAME);
    require_cap!(t, supports_list, NAME);
    require_cap!(t, supports_version_listing, NAME);
    if t.caps.supports_write {
        return skip(
            t.backend,
            t.access,
            NAME,
            "write-capable target; the write family covers it",
        );
    }

    let (address, _size, _version) = smallest_listed_object(t, 1, NAME).await;
    let (unpinned, info) = t
        .stack()
        .read_bytes(address.clone(), bounded_read(), None)
        .await
        .expect("unpinned read");
    let serving = info
        .version
        .clone()
        .unwrap_or_else(|| panic!("an unpinned read reports its serving version, got {info:#?}"));

    let (pinned, _) = t
        .stack()
        .read_bytes(revision_pinned(&address, &serving), bounded_read(), None)
        .await
        .expect("pinned re-read");
    assert_eq!(
        pinned, unpinned,
        "the pinned re-read returns the same bytes"
    );

    // The pin must steer the read, not decorate it: a version id no repository
    // resolves has to answer NotFound, where an ignored pin would answer the
    // current body.
    assert_error(
        t.stack()
            .read_bytes(
                revision_pinned(&address, ABSENT_REVISION),
                bounded_read(),
                None,
            )
            .await
            .map(|_| ()),
        ErrorCode::NotFound,
        "read pinned at a version no repository resolves",
    );

    let latest = ovstorage::Layer::get_latest_version(
        t.stack().as_ref(),
        Request::new(ReadRequest {
            address: address.clone(),
            options: ReadOptions::default(),
        }),
        None,
    )
    .await
    .expect("get_latest_version");
    let latest_version = latest.version.clone().unwrap_or_else(|| {
        panic!("get_latest_version must return a concrete version id, got {latest:#?}")
    });
    assert_eq!(
        latest.address,
        revision_pinned(&address, &latest_version),
        "get_latest_version pins the discovered address at exactly the version it reports",
    );
    assert_eq!(
        latest.versioned_address.as_ref(),
        Some(&latest.address),
        "get_latest_version names itself as its pin: {latest:#?}",
    );

    let flagged = t
        .stack()
        .stat(
            address.clone(),
            StatOptions {
                versioned_address: true,
                ..Default::default()
            },
            None,
        )
        .await
        .expect("flagged stat of the discovered object");
    assert_target_versioned_address(
        t.backend,
        &flagged,
        true,
        "flagged stat of the discovered object",
    );

    let versions = ovstorage::Layer::list_versions(
        t.stack().as_ref(),
        Request::new(ListVersionsRequest {
            address,
            options: ListVersionsOptions::default(),
        }),
        None,
    )
    .await
    .expect("list_versions")
    .items;
    assert!(
        !versions.is_empty(),
        "a readable object lists at least one version",
    );
    assert!(
        versions.iter().all(|v| v.version.is_some()),
        "every listed version carries an id; got {versions:#?}",
    );
    assert!(
        versions
            .iter()
            .all(|v| v.versioned_address.as_ref() == Some(&v.address)),
        "every listed version names itself as its pin; got {versions:#?}",
    );
}

// === helpers ===

/// Assert `result` is an `Err` carrying exactly `code`.
fn assert_error(result: ovstorage::Result<()>, code: ErrorCode, what: &str) {
    assert_error_one_of(result, &[code], what)
}

/// Assert `result` is an `Err` whose code is one of `codes` (for behaviors
/// whose normalized error differs across backends).
fn assert_error_one_of(result: ovstorage::Result<()>, codes: &[ErrorCode], what: &str) {
    match result {
        Ok(()) => panic!("{what}: expected one of {codes:?}, got Ok"),
        Err(e) => assert!(
            codes.contains(&e.code()),
            "{what}: got {:?} ({}), expected one of {codes:?}",
            e.code(),
            e.message(),
        ),
    }
}
