// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! RFC-0066: registry-as-spec conformance scenarios for the Nucleus
//! provider. Iterates `ScenarioRegistry::with_defaults()` deterministically
//! (BTreeMap, name-ordered) and, per scenario, either DRIVES it or SKIPS it
//! with a concrete reason. Recorder-based `expected_calls` verification is
//! test-backend-only; a provider run verifies outcomes and failure
//! contracts.
//!
//! Data-op scenarios drive against the crate's in-process `MockTransport`
//! (reached through the `#[doc(hidden)]`
//! `__test_only_backend_with_mock` export): each driver enqueues canned
//! omni1 frames and asserts both the SPI-visible outcome and the wire shape
//! the plugin sent. The four `*-type-mismatch` scenarios still skip — that
//! refusal is enforced server-side, so a canned-frame mock would only echo
//! whatever the test enqueued rather than prove provider behavior. The
//! capability gate for the one op Nucleus genuinely does not advertise
//! (`supports_native_metadata_patch = false`) drives on the bare backend:
//! `update_metadata` refuses with a typed `Unsupported` synchronously at
//! the SPI entry point, before any wire or auth interaction — the same
//! external-test idiom as `tests/precondition.rs`.
//!
//! The driven-set is pinned at the bottom so a silently-un-driven scenario
//! fails the test rather than rotting as a skip.

use std::collections::HashMap;
use std::sync::Arc;

use ovstorage_plugin::{
    BackendChangeEvent, BackendId, ChangeKind, ConfigValue, DeleteOptions, ErrorCode, IfDestExists,
    ListOptions, ObjectKind, ReadOptions, ReadResult, ResolvedTarget, StatOptions,
    UpdateMetadataOptions, WatchDirectoryOptions, WriteOptions, address,
};
use ovstorage_plugin_nucleus::NucleusBackend;
use ovstorage_plugin_nucleus::test_support::{CannedResponse, MockTransport, RawFrame};
use ovstorage_plugin_test::{
    ConformanceReport, FailureContract, Scenario, ScenarioOutcome, ScenarioRegistry,
    ScenarioReport, ScenarioRunner,
};
use serde_json::json;

// === bare-backend fixture (mirrors tests/precondition.rs) ===

async fn nucleus_backend() -> Arc<NucleusBackend> {
    let mut config = HashMap::new();
    config.insert("server".into(), ConfigValue::String("srv".into()));
    Arc::new(
        ovstorage_plugin_nucleus::__test_only_backend(&config)
            .expect("bare backend construction succeeds without auth"),
    )
}

/// Backend over the in-process mock transport: canned omni1 frames
/// in, recorded wire requests out. No auth, no network.
async fn mock_backend() -> (Arc<NucleusBackend>, Arc<MockTransport>) {
    let mut config = HashMap::new();
    config.insert("server".into(), ConfigValue::String("srv".into()));
    let (backend, mock) = ovstorage_plugin_nucleus::__test_only_backend_with_mock(&config)
        .expect("mock-transport backend construction succeeds without auth");
    (Arc::new(backend), mock)
}

fn obj(path: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("nucleus:omniverse://srv/".into()),
        resolved_address: address::parse(&format!("omniverse://srv{path}"))
            .expect("address parses"),
    }
}

fn stat2_frames(value: serde_json::Value) -> CannedResponse {
    CannedResponse {
        interface: "Connection".into(),
        method: "stat2".into(),
        frames: vec![RawFrame::from_json(&value)],
    }
}

fn create_asset_ok() -> CannedResponse {
    CannedResponse {
        interface: "Connection".into(),
        method: "create_asset".into(),
        frames: vec![RawFrame::from_json(&json!({
            "status": "OK",
            "etag": "etag-w",
            "transaction_id": 1,
        }))],
    }
}

fn passed(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn failed(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

// === data-op drivers over the mock transport ===

/// stat probes both file and folder shapes for an unannotated address;
/// the file probe answers OK (asset) and the folder probe absorbs an
/// INVALID_URI, materializing a File-kind `ObjectInfo`.
async fn drive_stat_basic(scenario: &Scenario) -> ScenarioReport {
    let (backend, mock) = mock_backend().await;
    mock.enqueue_for_path(
        stat2_frames(json!({
            "status": "OK",
            "type": "asset",
            "uri": "/Users/alice/foo.usd",
            "etag": "etag-1",
            "size": 1024,
            "transaction_id": "tx-9",
        })),
        "/Users/alice/foo.usd",
    );
    mock.enqueue_for_path(
        stat2_frames(json!({"status": "INVALID_URI"})),
        "/Users/alice/foo.usd/",
    );
    match backend
        .stat(obj("/Users/alice/foo.usd"), StatOptions::default(), None)
        .await
    {
        Ok(info) => {
            if info.kind != ObjectKind::File {
                return failed(
                    scenario,
                    format!("stat kind {:?}, expected File", info.kind),
                );
            }
            if info.size != Some(1024) || info.etag.as_deref() != Some("etag-1") {
                return failed(
                    scenario,
                    format!("stat mismatch: size {:?} etag {:?}", info.size, info.etag),
                );
            }
            if mock.requests().iter().any(|r| r.method != "stat2") {
                return failed(scenario, "stat must issue only stat2 RPCs".into());
            }
            passed(scenario)
        }
        Err(err) => failed(scenario, format!("stat failed: {err}")),
    }
}

/// stat on a missing path (both probes answer NOT_EXIST) surfaces exactly
/// the contract's `NotFound`.
async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = match &scenario.failure_contract {
        FailureContract::Errors { method, code } => (*method, *code),
        other => {
            return failed(
                scenario,
                format!("stat-not-found must carry an Errors contract, got {other:?}"),
            );
        }
    };
    let (backend, mock) = mock_backend().await;
    mock.enqueue(stat2_frames(json!({"status": "NOT_EXIST"})));
    mock.enqueue(stat2_frames(json!({"status": "NOT_EXIST"})));
    match backend
        .stat(
            obj("/Users/alice/missing.usd"),
            StatOptions::default(),
            None,
        )
        .await
    {
        Err(err) if err.code() == code => {
            // Both shape probes (file + folder spelling) must have been
            // issued — broken dual-probe logic would leave the second
            // canned frame silently unconsumed.
            if mock.requests().len() != 2 {
                return failed(
                    scenario,
                    format!(
                        "stat must issue both shape probes, saw {} RPCs",
                        mock.requests().len()
                    ),
                );
            }
            passed(scenario)
        }
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(info) => failed(scenario, format!("stat unexpectedly succeeded: {info:?}")),
    }
}

/// Zero-byte read round-trips: Nucleus serves object bytes inline
/// (`ReadResult::Bytes`, no streaming seam), so "empty" must come back as
/// an empty payload with `size == 0`, not an error.
async fn drive_read_empty(scenario: &Scenario) -> ScenarioReport {
    let (backend, mock) = mock_backend().await;
    mock.enqueue(CannedResponse {
        interface: "Connection".into(),
        method: "read_asset_version".into(),
        frames: vec![RawFrame::from_json_with_blob(
            &json!({"status": "OK", "etag": "v1", "size": 0}),
            Vec::new(),
        )],
    });
    match backend
        .read(obj("/Users/alice/empty.usd"), ReadOptions::default(), None)
        .await
    {
        Ok(ReadResult::Bytes { bytes, info }) => {
            if !bytes.is_empty() || info.size != Some(0) {
                return failed(
                    scenario,
                    format!(
                        "empty read yielded {} bytes, info.size {:?}",
                        bytes.len(),
                        info.size
                    ),
                );
            }
            let recorded = mock.requests();
            if recorded.len() != 1
                || recorded[0].method != "read_asset_version"
                || recorded[0].params["path"] != json!({"path": "/Users/alice/empty.usd"})
            {
                return failed(
                    scenario,
                    format!(
                        "read must be exactly one read_asset_version for the target path, got \
                         {recorded:?}"
                    ),
                );
            }
            passed(scenario)
        }
        Ok(other) => failed(
            scenario,
            format!("nucleus read must return ReadResult::Bytes, got {other:?}"),
        ),
        Err(err) => failed(scenario, format!("read failed: {err}")),
    }
}

/// Inline write completes in exactly one `create_asset` with
/// `overwrite=true` (the `IfDestExists::Overwrite` default).
async fn drive_write_done_inline(scenario: &Scenario) -> ScenarioReport {
    let (backend, mock) = mock_backend().await;
    mock.enqueue(create_asset_ok());
    match backend
        .write(
            obj("/Users/alice/new.usd"),
            b"payload".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
    {
        Ok(result) => {
            if result.info.etag.as_deref() != Some("etag-w") {
                return failed(
                    scenario,
                    format!("write etag {:?}, expected etag-w", result.info.etag),
                );
            }
            let recorded = mock.requests();
            if recorded.len() != 1 || recorded[0].method != "create_asset" {
                return failed(
                    scenario,
                    format!("write must be exactly one create_asset, got {recorded:?}"),
                );
            }
            if recorded[0].params["overwrite"] != json!(true)
                || recorded[0].params["path"] != json!({"path": "/Users/alice/new.usd"})
            {
                return failed(
                    scenario,
                    format!(
                        "default write must send overwrite=true at the target path: {:?}",
                        recorded[0].params
                    ),
                );
            }
            // The canned success frame is independent of the request, so
            // the payload bytes must be pinned on the wire explicitly.
            if recorded[0].blob.as_deref() != Some(b"payload".as_slice()) {
                return failed(
                    scenario,
                    format!(
                        "write must carry the object bytes as the binary frame, got {:?}",
                        recorded[0].blob
                    ),
                );
            }
            passed(scenario)
        }
        Err(err) => failed(scenario, format!("write failed: {err}")),
    }
}

/// write then delete: the delete routes through `delete2` with the
/// object's path and both ops succeed.
async fn drive_delete_existing(scenario: &Scenario) -> ScenarioReport {
    let (backend, mock) = mock_backend().await;
    mock.enqueue(create_asset_ok());
    mock.enqueue(CannedResponse {
        interface: "Connection".into(),
        method: "delete2".into(),
        frames: vec![RawFrame::from_json(&json!({
            "status": "OK",
            "responses": ["OK"],
        }))],
    });
    if let Err(err) = backend
        .write(
            obj("/Users/alice/doomed.usd"),
            b"bye".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
    {
        return failed(scenario, format!("seed write failed: {err}"));
    }
    if let Err(err) = backend
        .delete(
            obj("/Users/alice/doomed.usd"),
            DeleteOptions::default(),
            None,
        )
        .await
    {
        return failed(scenario, format!("delete failed: {err}"));
    }
    let recorded = mock.requests();
    if recorded.len() != 2 || recorded[1].method != "delete2" {
        return failed(
            scenario,
            format!("write + delete must be create_asset then delete2, got {recorded:?}"),
        );
    }
    if recorded[1].params["paths_to_delete"] != json!([{"path": "/Users/alice/doomed.usd"}]) {
        return failed(
            scenario,
            format!(
                "delete2 must carry the object path: {:?}",
                recorded[1].params
            ),
        );
    }
    passed(scenario)
}

/// One-level listing folds omni1 entry kinds (`folder` → Directory,
/// `asset` → File); the recursive half of the contract is nucleus's typed
/// LOCAL refusal — omni1 `list2` returns one level per call and the SPI
/// rule forbids silently amplifying one call into N, so `recursive=true`
/// surfaces `Unsupported` without any additional RPC
/// (`supports_recursive_list = false` is advertised).
async fn drive_list_levels(scenario: &Scenario) -> ScenarioReport {
    let (backend, mock) = mock_backend().await;
    mock.enqueue(CannedResponse {
        interface: "Connection".into(),
        method: "list2".into(),
        frames: vec![RawFrame::from_json(&json!({
            "status": "DONE",
            "entries": [
                {"path": "/Users/alice/sub", "path_type": "folder"},
                {"path": "/Users/alice/foo.usd", "path_type": "asset", "size": 17, "etag": "e1"},
            ],
        }))],
    });
    let items = match backend
        .list(obj("/Users/alice/"), ListOptions::default(), None)
        .await
    {
        Ok(items) => items,
        Err(err) => return failed(scenario, format!("flat list failed: {err}")),
    };
    let kinds: Vec<ObjectKind> = items.iter().map(|item| item.kind).collect();
    if kinds != vec![ObjectKind::Directory, ObjectKind::File] {
        return failed(scenario, format!("unexpected flat list fold: {kinds:?}"));
    }
    let flat_rpcs = mock.requests().len();
    match backend
        .list(
            obj("/Users/alice/"),
            ListOptions {
                recursive: true,
                ..ListOptions::default()
            },
            None,
        )
        .await
    {
        Err(err) if err.code() == ErrorCode::Unsupported => {
            if mock.requests().len() != flat_rpcs {
                return failed(
                    scenario,
                    "the recursive refusal must not reach the wire".into(),
                );
            }
            passed(scenario)
        }
        Err(err) => failed(
            scenario,
            format!(
                "recursive list must refuse with Unsupported, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(items) => failed(
            scenario,
            format!(
                "recursive list unexpectedly succeeded with {} items",
                items.len()
            ),
        ),
    }
}

/// `IfDestExists::Fail` rides the wire as `create_asset` with
/// `overwrite=false`, and the omni1 `ALREADY_EXISTS` refusal maps to
/// exactly the documented `AlreadyExists`.
async fn drive_write_no_overwrite(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = match &scenario.failure_contract {
        FailureContract::Errors { method, code } => (*method, *code),
        other => {
            return failed(
                scenario,
                format!("write-no-overwrite-existing must carry an Errors contract, got {other:?}"),
            );
        }
    };
    let (backend, mock) = mock_backend().await;
    mock.enqueue(CannedResponse {
        interface: "Connection".into(),
        method: "create_asset".into(),
        frames: vec![RawFrame::from_json(&json!({"status": "ALREADY_EXISTS"}))],
    });
    match backend
        .write(
            obj("/Users/alice/existing.usd"),
            b"clobber".to_vec(),
            WriteOptions {
                if_dest: IfDestExists::Fail,
                ..WriteOptions::default()
            },
            None,
        )
        .await
    {
        Err(err) if err.code() == code => {
            let recorded = mock.requests();
            if recorded.len() != 1 || recorded[0].params["overwrite"] != json!(false) {
                return failed(
                    scenario,
                    format!(
                        "no-overwrite write must be one create_asset with overwrite=false: \
                         {recorded:?}"
                    ),
                );
            }
            passed(scenario)
        }
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(result) => failed(
            scenario,
            format!(
                "no-overwrite write unexpectedly succeeded: {:?}",
                result.info
            ),
        ),
    }
}

async fn collect_watch_events(
    options: WatchDirectoryOptions,
) -> Result<Vec<(String, ChangeKind)>, String> {
    let (backend, mock) = mock_backend().await;
    mock.enqueue(CannedResponse {
        interface: "Connection".into(),
        method: "subscribe_list".into(),
        frames: vec![
            RawFrame::from_json(&json!({
                "status": "OK",
                "event": "create",
                "entry": {"path": "/Users/alice/top.usd"},
            })),
            RawFrame::from_json(&json!({
                "status": "OK",
                "event": "delete",
                "entry": {"path": "/Users/alice/sub/deep.usd"},
            })),
            RawFrame::from_json(&json!({
                "status": "OK",
                "event": "change_acl",
                "entry": {"path": "/Users/alice/meta.usd"},
            })),
        ],
    });
    let stream = backend
        .watch_directory(obj("/Users/alice/"), options, None)
        .await
        .map_err(|error| format!("watch_directory failed: {error}"))?;
    let mut events = Vec::new();
    for event in stream {
        match event.map_err(|error| format!("watch stream failed: {error}"))? {
            BackendChangeEvent::Object { address, kind, .. } => {
                events.push((address.as_str().to_string(), kind));
            }
            BackendChangeEvent::Lapsed { .. } => {}
        }
    }
    let recorded = mock.requests();
    if recorded.len() != 1 || recorded[0].method != "subscribe_list" {
        return Err(format!(
            "watch must issue exactly one subscribe_list, got {recorded:?}"
        ));
    }
    Ok(events)
}

async fn drive_watch_option_superset(scenario: &Scenario) -> ScenarioReport {
    let narrow = collect_watch_events(WatchDirectoryOptions {
        recursive: false,
        include_metadata_changes: false,
        ..WatchDirectoryOptions::default()
    })
    .await;
    let recursive = collect_watch_events(WatchDirectoryOptions {
        recursive: true,
        include_metadata_changes: false,
        ..WatchDirectoryOptions::default()
    })
    .await;
    let full = collect_watch_events(WatchDirectoryOptions {
        recursive: true,
        include_metadata_changes: true,
        ..WatchDirectoryOptions::default()
    })
    .await;
    let (narrow, recursive, full) = match (narrow, recursive, full) {
        (Ok(narrow), Ok(recursive), Ok(full)) => (narrow, recursive, full),
        (narrow, recursive, full) => {
            return failed(
                scenario,
                format!(
                    "watch collection failed: narrow={narrow:?}, recursive={recursive:?}, \
                     full={full:?}"
                ),
            );
        }
    };

    let top = (
        "omniverse://srv/Users/alice/top.usd".to_string(),
        ChangeKind::Created,
    );
    let nested = (
        "omniverse://srv/Users/alice/sub/deep.usd".to_string(),
        ChangeKind::Deleted,
    );
    let metadata = (
        "omniverse://srv/Users/alice/meta.usd".to_string(),
        ChangeKind::MetadataChanged,
    );
    if narrow != [top.clone()]
        || recursive != [top.clone(), nested.clone()]
        || full != [top, nested, metadata]
    {
        return failed(
            scenario,
            format!(
                "watch options violated strict-superset projection: \
                 narrow={narrow:?}, recursive={recursive:?}, full={full:?}"
            ),
        );
    }
    passed(scenario)
}

// === the bare-backend capability gate ===

/// `capability-gate-update-metadata-unsupported`: Nucleus advertises
/// `supports_native_metadata_patch = false` (omni1 has no free-form
/// user-metadata patch endpoint), and `NucleusBackend::update_metadata`
/// refuses with a typed `Unsupported` synchronously — no session lookup, no
/// transport, no network (`srv` is never contacted; the refusal fires
/// before `ops()` would have raised `AuthRequired`).
async fn drive_update_metadata_gate(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = match &scenario.failure_contract {
        FailureContract::Errors { method, code } => (*method, *code),
        other => {
            return ScenarioReport::failed(
                scenario,
                format!("capability-gate scenario must carry an Errors contract, got {other:?}"),
                Vec::new(),
            );
        }
    };
    if method != "update_metadata" {
        return ScenarioReport::failed(
            scenario,
            format!("driver wired for `update_metadata`, contract names `{method}`"),
            Vec::new(),
        );
    }
    let backend = nucleus_backend().await;
    match backend
        .update_metadata(
            obj("/Users/alice/x"),
            UpdateMetadataOptions::default(),
            None,
        )
        .await
    {
        Err(err) if err.code() == code => {
            // Pin that this is the LOCAL typed refusal (the omni1 gap), not
            // an AuthRequired that a session-needing path would surface.
            let msg = err.to_string();
            if msg.contains("user-metadata patch") {
                ScenarioReport::passed(scenario, Vec::new())
            } else {
                ScenarioReport::failed(
                    scenario,
                    format!("expected the local omni1 metadata-patch refusal, got: {msg}"),
                    Vec::new(),
                )
            }
        }
        Err(err) => ScenarioReport::failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
            Vec::new(),
        ),
        Ok(info) => ScenarioReport::failed(
            scenario,
            format!("expected {code:?} on `{method}`, but the op succeeded: {info:?}"),
            Vec::new(),
        ),
    }
}

// === the conformance pass ===

#[tokio::test]
async fn conformance_scenarios_bare_backend() {
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    let mut driven: Vec<&'static str> = Vec::new();

    for scenario in registry.iter() {
        let entry = match scenario.name {
            "capability-gate-update-metadata-unsupported" => {
                drive_update_metadata_gate(scenario).await
            }
            // Every other gate-table op IS advertised by Nucleus
            // (`native_capabilities()` in src/backend/spi.rs), so there is
            // nothing to self-gate.
            "capability-gate-delete-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_delete` advertised by nucleus; not gateable \
                 per-connection",
            ),
            "capability-gate-write-redirect-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_write_redirect` advertised by nucleus (LFT); not \
                 gateable per-connection",
            ),
            "capability-gate-check-access-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_access_check` advertised by nucleus \
                 (get_acl_resolved); not gateable per-connection",
            ),
            "capability-gate-create-directory-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_create_directory` advertised by nucleus; not \
                 gateable per-connection",
            ),
            "capability-gate-delete-directory-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_delete_directory` advertised by nucleus; not \
                 gateable per-connection",
            ),
            "capability-gate-list-versions-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_version_listing` advertised by nucleus \
                 (checkpoints); not gateable per-connection",
            ),
            "capability-gate-watch-directory-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_watch_directory` advertised by nucleus \
                 (subscribe_list); not gateable per-connection",
            ),
            // Data-op scenarios: driven against the in-process mock
            // transport.
            "stat-basic-objectinfo" => drive_stat_basic(scenario).await,
            "stat-not-found" => drive_stat_not_found(scenario).await,
            "read-streamed-empty" => drive_read_empty(scenario).await,
            "write-done-inline" => drive_write_done_inline(scenario).await,
            "delete-existing-object" => drive_delete_existing(scenario).await,
            "list-one-level-vs-recursive" => drive_list_levels(scenario).await,
            "watch-directory-option-superset" => drive_watch_option_superset(scenario).await,
            "write-no-overwrite-existing" => drive_write_no_overwrite(scenario).await,
            "delete-on-directory-type-mismatch"
            | "delete-directory-on-file-type-mismatch"
            | "list-on-file-type-mismatch"
            | "read-on-directory-type-mismatch" => runner.skip(
                scenario.name,
                "type-mismatch refusals are enforced server-side (delete2/list2 semantics); \
                 a canned-frame mock would only echo whatever the test enqueued — driving \
                 this honestly needs a live Nucleus or a semantic fake",
            ),
            "copy-to-self-preserves-content" => runner.skip(
                scenario.name,
                "data preservation on a same-path copy2 is service-enforced; a canned-frame \
                 mock can only echo the test's own enqueue, proving nothing about the \
                 provider",
            ),
            "rename-no-overwrite-existing" => runner.skip(
                scenario.name,
                "omni1 rename2 has no destination conditional: rename with if_dest != \
                 Overwrite refuses upfront with a typed Unsupported (no wire attempt), so \
                 the AlreadyExists refusal is never observable",
            ),
            "metadata-unsupported-not-called" => runner.skip(
                scenario.name,
                "recorder-based negative assertion (expected_calls) is test-backend-only",
            ),
            "readonly-connection-rejects-mutations" => {
                runner.skip(scenario.name, "provider has no read-only connection mode")
            }
            "compat-gates-v1-capability"
            | "write-redirect-commits-on-done"
            | "retry-never-replays-continue-write"
            | "protocol-slots-pass-through" => runner.skip(
                scenario.name,
                "host/wrapper-side contract; driven in ovstorage's \
                 tests/conformance_protocol_slots.rs",
            ),
            _ => runner.skip(
                scenario.name,
                "no provider driver wired; extend tests/conformance_scenarios.rs",
            ),
        };
        if !matches!(entry.outcome, ScenarioOutcome::Skipped { .. }) {
            driven.push(scenario.name);
        }
        report.push(entry);
    }

    // Pin the exact driven set (registry iteration is name-ordered) so a
    // scenario silently downgraded to a skip fails loudly.
    let expected_driven = vec![
        "capability-gate-update-metadata-unsupported",
        "delete-existing-object",
        "list-one-level-vs-recursive",
        "read-streamed-empty",
        "stat-basic-objectinfo",
        "stat-not-found",
        "watch-directory-option-superset",
        "write-done-inline",
        "write-no-overwrite-existing",
    ];
    assert_eq!(
        driven,
        expected_driven,
        "driven scenario set drifted:\n{}",
        report.render_human()
    );
    assert_eq!(
        report.entries.len(),
        registry.len(),
        "every registry entry must produce exactly one report entry"
    );
    assert_eq!(report.failed(), 0, "{}", report.render_human());
    assert!(report.ok(), "{}", report.render_human());
}
