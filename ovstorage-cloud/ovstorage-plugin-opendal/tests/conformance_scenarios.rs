// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! RFC-0066: registry-as-spec conformance scenarios for the OpenDAL
//! provider. Iterates `ScenarioRegistry::with_defaults()` deterministically
//! (BTreeMap, name-ordered) and, per scenario, either DRIVES it against the
//! ABI-v2 `OpenDalLayer` on the fs profile (a real `TempDir` round trip — no
//! network at all) asserting the outcome matches the registry's
//! `failure_contract`, or SKIPS it with a concrete reason. Recorder-based
//! `expected_calls` verification is test-backend-only; a provider run
//! verifies outcomes and failure contracts.
//!
//! The driven-set is pinned at the bottom so a silently-un-driven scenario
//! fails the test rather than rotting as a skip.
//!
//! For the four `*-type-mismatch` scenarios (`delete`, `delete_directory`,
//! `list`, `read`) the backend mirrors `FileBackend`'s leaf probe, so a
//! mismatched-kind leaf surfaces `InvalidArgument` with guidance (and
//! `delete` refuses *before* removing a directory), and all four drive.

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt as _;
use ovstorage_plugin::{
    AccessOps, BackendFactory, Body, CheckAccessRequest, ConfigValue, ConnectionRequest,
    CopyOptions, CopyRequest, CreateDirectoryOptions, CreateDirectoryRequest,
    DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions, DeleteRequest, ErrorCode,
    LayerConfig, LayerConnectionRequest, LayerHandle, ListOptions, ListRequest,
    ListVersionsOptions, ListVersionsRequest, ObjectKind, ReadOptions, ReadRequest, ReadResult,
    Request, SecretBundle, StatOptions, StatRequest, UpdateMetadataOptions, UpdateMetadataRequest,
    WatchDirectoryOptions, WatchDirectoryRequest, WriteOptions, WriteRequest, WriteResult, address,
};
use ovstorage_plugin_opendal::OpenDalLayerFactory;
use ovstorage_plugin_test::streaming::{StreamingRecorder, assert_streaming_invariants};
use ovstorage_plugin_test::{
    ConformanceReport, FailureContract, Scenario, ScenarioOutcome, ScenarioRegistry,
    ScenarioReport, ScenarioRunner,
};
use tempfile::TempDir;

// === fs-profile fixture (mirrors tests/layer_connection_lifecycle.rs) ===

fn fs_request(root: &TempDir) -> ConnectionRequest {
    let mut config = HashMap::new();
    config.insert("service".into(), ConfigValue::String("fs".into()));
    config.insert(
        "root".into(),
        ConfigValue::String(root.path().display().to_string()),
    );
    ConnectionRequest {
        backend_kind: "opendal".into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    }
}

async fn fs_layer(root: &TempDir) -> LayerHandle {
    let layer = OpenDalLayerFactory::default()
        .create_backend("opendal", &LayerConfig::new(), None)
        .await
        .expect("empty opendal layer builds");
    layer
        .add_connection(
            Request::new(LayerConnectionRequest {
                target: "opendal".into(),
                connection: fs_request(root),
            }),
            None,
        )
        .await
        .expect("fs connection adds against a real TempDir");
    layer
}

async fn write_object(
    layer: &LayerHandle,
    addr: &str,
    body: Vec<u8>,
    options: WriteOptions,
) -> ovstorage_plugin::Result<WriteResult> {
    layer
        .write(
            Request::new(WriteRequest {
                address: address::parse(addr).expect("address parses"),
                body: Body::Bytes(body),
                options,
            }),
            None,
        )
        .await
}

async fn stat_object(
    layer: &LayerHandle,
    addr: &str,
) -> ovstorage_plugin::Result<ovstorage_plugin::ObjectInfo> {
    layer
        .stat(
            Request::new(StatRequest {
                address: address::parse(addr).expect("address parses"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
}

async fn list_prefix(
    layer: &LayerHandle,
    prefix: &str,
    recursive: bool,
) -> ovstorage_plugin::Result<Vec<String>> {
    let page = layer
        .list(
            Request::new(ListRequest {
                prefix: address::parse(prefix).expect("prefix parses"),
                options: ListOptions {
                    recursive,
                    ..ListOptions::default()
                },
            }),
            None,
        )
        .await?;
    Ok(page
        .items
        .iter()
        .map(|item| item.address.as_str().to_string())
        .collect())
}

// === registry-as-spec helpers ===

fn passed(scenario: &Scenario) -> ScenarioReport {
    ScenarioReport::passed(scenario, Vec::new())
}

fn failed(scenario: &Scenario, reason: String) -> ScenarioReport {
    ScenarioReport::failed(scenario, reason, Vec::new())
}

/// The `(method, code)` an `Errors` failure contract demands. Drivers read
/// the expectation from the registry entry itself, never restate it.
fn contract_error(scenario: &Scenario) -> (&'static str, ErrorCode) {
    match &scenario.failure_contract {
        FailureContract::Errors { method, code } => (method, *code),
        other => panic!(
            "scenario `{}` carries {other:?}; drive it with a matching driver",
            scenario.name
        ),
    }
}

// === scenario drivers (fs profile) ===

async fn drive_stat_basic(scenario: &Scenario) -> ScenarioReport {
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/team/file.txt";
    let body = b"conformance-stat".to_vec();
    if let Err(err) = write_object(&layer, addr, body.clone(), WriteOptions::default()).await {
        return failed(scenario, format!("setup write failed: {err}"));
    }
    match stat_object(&layer, addr).await {
        Ok(info) => {
            if info.kind != ObjectKind::File {
                return failed(
                    scenario,
                    format!("stat kind {:?}, expected File", info.kind),
                );
            }
            if info.size != Some(body.len() as u64) {
                return failed(
                    scenario,
                    format!("stat size {:?}, expected Some({})", info.size, body.len()),
                );
            }
            passed(scenario)
        }
        Err(err) => failed(scenario, format!("stat failed: {err}")),
    }
}

async fn drive_stat_not_found(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = contract_error(scenario);
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    match stat_object(&layer, "opendal://fs/never-written.txt").await {
        Err(err) if err.code() == code => passed(scenario),
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(info) => failed(
            scenario,
            format!("expected {code:?} on `{method}`, stat succeeded: {info:?}"),
        ),
    }
}

async fn drive_read_streamed_empty(scenario: &Scenario) -> ScenarioReport {
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/empty.bin";
    if let Err(err) = write_object(&layer, addr, Vec::new(), WriteOptions::default()).await {
        return failed(scenario, format!("setup write failed: {err}"));
    }
    let read = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse(addr).expect("address parses"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await;
    match read {
        Ok(ReadResult::Stream { mut stream, info }) => {
            let mut total = 0usize;
            while let Some(chunk) = stream.next().await {
                match chunk {
                    Ok(bytes) => total += bytes.len(),
                    Err(err) => return failed(scenario, format!("stream chunk failed: {err}")),
                }
            }
            if total != 0 || info.size != Some(0) {
                return failed(
                    scenario,
                    format!(
                        "empty read yielded {total} bytes, info.size {:?}",
                        info.size
                    ),
                );
            }
            passed(scenario)
        }
        Ok(other) => failed(
            scenario,
            format!("fs read must return ReadResult::Stream, got {other:?}"),
        ),
        Err(err) => failed(scenario, format!("read failed: {err}")),
    }
}

async fn drive_write_done_inline(scenario: &Scenario) -> ScenarioReport {
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let body = b"conformance-write".to_vec();
    match write_object(
        &layer,
        "opendal://fs/write.txt",
        body.clone(),
        WriteOptions::default(),
    )
    .await
    {
        Ok(result) if result.info.size == Some(body.len() as u64) => passed(scenario),
        Ok(result) => failed(
            scenario,
            format!(
                "write result size {:?}, expected Some({})",
                result.info.size,
                body.len()
            ),
        ),
        Err(err) => failed(scenario, format!("write failed: {err}")),
    }
}

async fn drive_delete_existing(scenario: &Scenario) -> ScenarioReport {
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/doomed.txt";
    if let Err(err) = write_object(&layer, addr, b"bye".to_vec(), WriteOptions::default()).await {
        return failed(scenario, format!("setup write failed: {err}"));
    }
    if let Err(err) = layer
        .delete(
            Request::new(DeleteRequest {
                address: address::parse(addr).expect("address parses"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
    {
        return failed(scenario, format!("delete failed: {err}"));
    }
    match stat_object(&layer, addr).await {
        Err(err) if err.code() == ErrorCode::NotFound => passed(scenario),
        Err(err) => failed(
            scenario,
            format!("post-delete stat: expected NotFound, got {:?}", err.code()),
        ),
        Ok(info) => failed(
            scenario,
            format!("object survived its delete: {:?}", info.address),
        ),
    }
}

async fn drive_list_levels(scenario: &Scenario) -> ScenarioReport {
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    for (addr, body) in [
        ("opendal://fs/top.txt", b"t".to_vec()),
        ("opendal://fs/nested/inner.txt", b"i".to_vec()),
    ] {
        if let Err(err) = write_object(&layer, addr, body, WriteOptions::default()).await {
            return failed(scenario, format!("setup write of {addr} failed: {err}"));
        }
    }
    let flat = match list_prefix(&layer, "opendal://fs/", false).await {
        Ok(items) => items,
        Err(err) => return failed(scenario, format!("flat list failed: {err}")),
    };
    let recursive = match list_prefix(&layer, "opendal://fs/", true).await {
        Ok(items) => items,
        Err(err) => return failed(scenario, format!("recursive list failed: {err}")),
    };
    let flat_has = |addr: &str| flat.iter().any(|item| item == addr);
    if !flat_has("opendal://fs/top.txt") || !flat_has("opendal://fs/nested/") {
        return failed(
            scenario,
            format!("flat list missing top.txt or nested/: {flat:?}"),
        );
    }
    if flat_has("opendal://fs/nested/inner.txt") {
        return failed(scenario, format!("flat list leaked a nested key: {flat:?}"));
    }
    if !recursive
        .iter()
        .any(|item| item == "opendal://fs/nested/inner.txt")
    {
        return failed(
            scenario,
            format!("recursive list missing nested key: {recursive:?}"),
        );
    }
    passed(scenario)
}

/// Capability self-gates for ops the fs profile genuinely does NOT
/// advertise. The op is invoked against a live fs connection and must be
/// refused with a typed `Unsupported` locally — the fs root makes any
/// accidental IO local, and the post-call root check proves no side effect
/// landed.
async fn drive_capability_gate(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = contract_error(scenario);
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = address::parse("opendal://fs/gated.bin").expect("address parses");
    let outcome: std::result::Result<(), ovstorage_plugin::Error> = match method {
        "write_redirect" => layer
            .write_redirect(
                Request::new(WriteRequest {
                    address: addr,
                    body: Body::Bytes(Vec::new()),
                    options: WriteOptions {
                        size_hint: Some(1),
                        ..WriteOptions::default()
                    },
                }),
                None,
            )
            .await
            .map(|_| ()),
        "update_metadata" => layer
            .update_metadata(
                Request::new(UpdateMetadataRequest {
                    address: addr,
                    options: UpdateMetadataOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "check_access" => layer
            .check_access(
                Request::new(CheckAccessRequest {
                    address: addr,
                    operations: AccessOps {
                        read: true,
                        ..AccessOps::default()
                    },
                }),
                None,
            )
            .await
            .map(|_| ()),
        "list_versions" => layer
            .list_versions(
                Request::new(ListVersionsRequest {
                    address: addr,
                    options: ListVersionsOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        "watch_directory" => layer
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: address::parse("opendal://fs/").expect("prefix parses"),
                    options: WatchDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .map(|_| ()),
        other => {
            return failed(scenario, format!("no gate driver wired for slot `{other}`"));
        }
    };
    match outcome {
        Err(err) if err.code() == code => {
            let residue = std::fs::read_dir(root.path())
                .expect("fs root readable")
                .count();
            if residue == 0 {
                passed(scenario)
            } else {
                failed(
                    scenario,
                    format!("gated `{method}` left {residue} entries under the fs root"),
                )
            }
        }
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(()) => failed(
            scenario,
            format!("expected {code:?} on `{method}`, but the op succeeded"),
        ),
    }
}

/// `delete` on an existing directory refuses with the contract's
/// `InvalidArgument` — and refuses BEFORE the destructive call, so the
/// directory must survive the attempt.
async fn drive_delete_on_directory_mismatch(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = contract_error(scenario);
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    if let Err(err) = layer
        .create_directory(
            Request::new(CreateDirectoryRequest {
                address: address::parse("opendal://fs/realdir/").expect("address parses"),
                options: CreateDirectoryOptions::default(),
            }),
            None,
        )
        .await
    {
        return failed(scenario, format!("setup create_directory failed: {err}"));
    }
    let outcome = layer
        .delete(
            Request::new(DeleteRequest {
                address: address::parse("opendal://fs/realdir").expect("address parses"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == code => {
            if !root.path().join("realdir").is_dir() {
                return failed(
                    scenario,
                    "the refusing delete must not remove the directory".into(),
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
        Ok(()) => failed(
            scenario,
            format!("expected {code:?} on `{method}`, but delete succeeded"),
        ),
    }
}

/// `read` on an existing directory refuses with the contract's
/// `InvalidArgument` instead of handing back a stream the caller
/// cannot consume.
async fn drive_read_on_directory_mismatch(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = contract_error(scenario);
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    if let Err(err) = layer
        .create_directory(
            Request::new(CreateDirectoryRequest {
                address: address::parse("opendal://fs/readdir/").expect("address parses"),
                options: CreateDirectoryOptions::default(),
            }),
            None,
        )
        .await
    {
        return failed(scenario, format!("setup create_directory failed: {err}"));
    }
    let outcome = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse("opendal://fs/readdir").expect("address parses"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == code => passed(scenario),
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(_) => failed(
            scenario,
            format!("expected {code:?} on `{method}`, but read succeeded"),
        ),
    }
}

/// `delete_directory` on an existing file refuses with the
/// contract's `InvalidArgument` and leaves the file intact.
async fn drive_delete_directory_on_file_mismatch(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = contract_error(scenario);
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/leaf.txt";
    if let Err(err) = write_object(&layer, addr, b"keep".to_vec(), WriteOptions::default()).await {
        return failed(scenario, format!("setup write failed: {err}"));
    }
    let outcome = layer
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: address::parse(addr).expect("address parses"),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await;
    match outcome {
        Err(err) if err.code() == code => match stat_object(&layer, addr).await {
            Ok(_) => passed(scenario),
            Err(err) => failed(
                scenario,
                format!("the refused delete_directory must leave the file intact: {err}"),
            ),
        },
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(()) => failed(
            scenario,
            format!("expected {code:?} on `{method}`, but delete_directory succeeded"),
        ),
    }
}

/// `list` with a file leaf as the prefix refuses with the
/// contract's `InvalidArgument` (genuine absence stays `NotFound`).
async fn drive_list_on_file_mismatch(scenario: &Scenario) -> ScenarioReport {
    let (method, code) = contract_error(scenario);
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/plain.txt";
    if let Err(err) = write_object(&layer, addr, b"flat".to_vec(), WriteOptions::default()).await {
        return failed(scenario, format!("setup write failed: {err}"));
    }
    match list_prefix(&layer, addr, false).await {
        Err(err) if err.code() == code => passed(scenario),
        Err(err) => failed(
            scenario,
            format!(
                "expected {code:?} on `{method}`, got {:?}: {err}",
                err.code()
            ),
        ),
        Ok(items) => failed(
            scenario,
            format!("expected {code:?} on `{method}`, but list returned {items:?}"),
        ),
    }
}

/// Data-safety contract: `copy(src, src)` on the fs profile
/// must not lose the object (a copy that opens the destination O_TRUNC
/// before reading the source zeroes it). OpenDAL guards the case itself
/// — `Operator::copy` refuses same-path with `IsSameFile` (mapped
/// `Conflict`) — the refusal half the registry's `SuccessOrRefusal`
/// contract declares conforming, consumed here rather than hard-coded.
async fn drive_copy_to_self(scenario: &Scenario) -> ScenarioReport {
    let (refusal_method, refusal_code) = match &scenario.failure_contract {
        FailureContract::SuccessOrRefusal { method, code } => (*method, *code),
        other => {
            return failed(
                scenario,
                format!("driver expects a SuccessOrRefusal contract, got {other:?}"),
            );
        }
    };
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/self.txt";
    if let Err(err) = write_object(
        &layer,
        addr,
        b"important data".to_vec(),
        WriteOptions::default(),
    )
    .await
    {
        return failed(scenario, format!("setup write failed: {err}"));
    }
    let outcome = layer
        .copy(
            Request::new(CopyRequest {
                source: address::parse(addr).expect("address parses"),
                destination: address::parse(addr).expect("address parses"),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await;
    if let Err(err) = &outcome
        && err.code() != refusal_code
    {
        return failed(
            scenario,
            format!(
                "copy-to-self may succeed or refuse typed with {refusal_code:?} on \
                 `{refusal_method}`, got {:?}: {err}",
                err.code()
            ),
        );
    }
    match std::fs::read(root.path().join("self.txt")) {
        Ok(bytes) if bytes == b"important data" => passed(scenario),
        Ok(bytes) => failed(
            scenario,
            format!(
                "copy-to-self corrupted the object: {} bytes survive of 14",
                bytes.len()
            ),
        ),
        Err(err) => failed(scenario, format!("post-copy read failed: {err}")),
    }
}

// === the conformance pass ===

#[tokio::test]
async fn conformance_scenarios_fs_profile() {
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();
    let mut driven: Vec<&'static str> = Vec::new();

    for scenario in registry.iter() {
        let entry = match scenario.name {
            "stat-basic-objectinfo" => drive_stat_basic(scenario).await,
            "stat-not-found" => drive_stat_not_found(scenario).await,
            "read-streamed-empty" => drive_read_streamed_empty(scenario).await,
            "write-done-inline" => drive_write_done_inline(scenario).await,
            "delete-existing-object" => drive_delete_existing(scenario).await,
            "list-one-level-vs-recursive" => drive_list_levels(scenario).await,
            // Ops the fs profile genuinely does not advertise: the layer
            // must self-gate with a typed Unsupported, locally.
            "capability-gate-write-redirect-unsupported"
            | "capability-gate-update-metadata-unsupported"
            | "capability-gate-check-access-unsupported"
            | "capability-gate-list-versions-unsupported"
            | "capability-gate-watch-directory-unsupported" => {
                drive_capability_gate(scenario).await
            }
            "capability-gate-delete-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_delete` advertised by the fs profile; not gateable \
                 per-connection",
            ),
            "capability-gate-create-directory-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_create_directory` advertised by the fs profile; not \
                 gateable per-connection",
            ),
            "capability-gate-delete-directory-unsupported" => runner.skip(
                scenario.name,
                "capability `supports_delete_directory` advertised by the fs profile; not \
                 gateable per-connection",
            ),
            "write-no-overwrite-existing" => runner.skip(
                scenario.name,
                "fs profile does not advertise the required supports_no_overwrite_write \
                 (only the s3 profile does, and driving the second-write AlreadyExists \
                 refusal there needs a stateful conditional-write S3 mock)",
            ),
            "metadata-unsupported-not-called" => runner.skip(
                scenario.name,
                "recorder-based negative assertion (expected_calls) is test-backend-only",
            ),
            "delete-on-directory-type-mismatch" => {
                drive_delete_on_directory_mismatch(scenario).await
            }
            "delete-directory-on-file-type-mismatch" => {
                drive_delete_directory_on_file_mismatch(scenario).await
            }
            "list-on-file-type-mismatch" => drive_list_on_file_mismatch(scenario).await,
            "read-on-directory-type-mismatch" => drive_read_on_directory_mismatch(scenario).await,
            "copy-to-self-preserves-content" => drive_copy_to_self(scenario).await,
            "rename-no-overwrite-existing" => runner.skip(
                scenario.name,
                "OpenDAL cannot enforce destination preconditions atomically: rename with \
                 if_dest != Overwrite refuses upfront with a typed Unsupported (no wire \
                 attempt), so the AlreadyExists refusal is never observable",
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
        "capability-gate-check-access-unsupported",
        "capability-gate-list-versions-unsupported",
        "capability-gate-update-metadata-unsupported",
        "capability-gate-watch-directory-unsupported",
        "capability-gate-write-redirect-unsupported",
        "copy-to-self-preserves-content",
        "delete-directory-on-file-type-mismatch",
        "delete-existing-object",
        "delete-on-directory-type-mismatch",
        "list-on-file-type-mismatch",
        "list-one-level-vs-recursive",
        "read-on-directory-type-mismatch",
        "read-streamed-empty",
        "stat-basic-objectinfo",
        "stat-not-found",
        "write-done-inline",
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

// === streaming invariants on the fs read seam (RFC-0066) ===

/// First wiring of `assert_streaming_invariants` on a real provider seam:
/// the fs-profile `Layer::read` stream. Scope of the proof: multi-chunk
/// bounded emission at the read seam — the stream yields the object in
/// more than one chunk, each no larger than a small multiple of the
/// observed fs chunk ceiling (2 MiB; bound set at 4 MiB). This does NOT
/// prove the layer never buffers internally: the test loop releases each
/// chunk before pulling the next, so `max_in_flight` structurally equals
/// the largest single chunk, and `min_spread` is ZERO because local-disk
/// arrival pacing is not guaranteed. What the bound does catch is a
/// chunk-size regression (e.g. the seam re-emitting the whole 9 MiB
/// payload as one chunk, or the chunk ceiling silently growing).
#[tokio::test]
async fn fs_read_stream_upholds_streaming_invariants() {
    let root = TempDir::new().expect("tempdir");
    let layer = fs_layer(&root).await;
    let addr = "opendal://fs/big-streamed.bin";
    // Non-uniform payload so a reassembly/order bug cannot cancel out.
    let payload: Vec<u8> = (0..9 * 1024 * 1024u32)
        .map(|index| (index % 251) as u8)
        .collect();
    write_object(&layer, addr, payload.clone(), WriteOptions::default())
        .await
        .expect("large write succeeds");

    let read = layer
        .read(
            Request::new(ReadRequest {
                address: address::parse(addr).expect("address parses"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("large read succeeds");
    let ReadResult::Stream { mut stream, .. } = read else {
        panic!("fs read must return ReadResult::Stream");
    };

    let recorder = StreamingRecorder::new();
    let mut reassembled = Vec::with_capacity(payload.len());
    let mut chunks = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.expect("stream chunk succeeds");
        recorder.record_arrival(chunk.len());
        // Consume the chunk fully before pulling the next one, then
        // release it so the recorder's in-flight high-water mark reflects
        // one chunk at a time.
        reassembled.extend_from_slice(&chunk);
        recorder.record_release(chunk.len());
        chunks += 1;
    }
    assert!(
        chunks > 1,
        "a {}-byte read must stream in multiple chunks, got {chunks}",
        payload.len()
    );
    assert_eq!(reassembled, payload, "reassembled bytes match");
    // 2x the observed opendal fs chunk ceiling (2 MiB): with per-chunk
    // release, max_in_flight is the largest single chunk, so this bound
    // fails if the seam's chunk size grows past 4 MiB.
    let max_chunk_bound = 4 * 1024 * 1024;
    assert_streaming_invariants(&recorder, chunks, Duration::ZERO, Some(max_chunk_bound));
}
