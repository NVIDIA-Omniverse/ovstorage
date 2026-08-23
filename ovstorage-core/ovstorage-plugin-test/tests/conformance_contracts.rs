// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runner coverage for the contract scenarios: the type-mismatch
//! semantics (real-directories mode) and the capability
//! self-gate / read-only-connection contracts, driven
//! against the `TestLayer` surface. The protocol-slot half of the
//! capability contract needs host wrappers and lives in `ovstorage`'s test suite.

use std::collections::HashMap;

use ovstorage_plugin::{
    AccessOps, BackendFactory as _, Body, ConfigValue, CopyOptions, CopyRequest,
    CreateDirectoryOptions, CreateDirectoryRequest, DeleteDirectoryOptions, DeleteDirectoryRequest,
    DeleteOptions, DeleteRequest, ErrorCode, LayerHandle, ListOptions, ListRequest,
    ListVersionsOptions, ListVersionsRequest, ReadOptions, ReadRequest, ReadResult, RenameOptions,
    RenameRequest, Request, StatOptions, StatRequest, UpdateMetadataOptions, UpdateMetadataRequest,
    Url, WatchDirectoryOptions, WatchDirectoryRequest, WriteOptions, WriteRequest, address,
};
use ovstorage_plugin_test::{
    CAPABILITY_GATE_SCENARIOS, ConformanceReport, Recorder, ScenarioRegistry, ScenarioRunner,
    TestLayerFactory,
};

const ROOT: &str = "test://contracts/";

async fn layer_with_knobs(knobs: &[(&str, ConfigValue)]) -> (LayerHandle, Recorder) {
    let factory = TestLayerFactory::default();
    let mut config = HashMap::new();
    config.insert("test_root".into(), ConfigValue::String(ROOT.into()));
    for (key, value) in knobs {
        config.insert((*key).into(), value.clone());
    }
    let layer = factory
        .create_backend("test", &config, None)
        .await
        .expect("create test layer");
    let root = address::parse(ROOT).unwrap();
    let recorder = factory.recorder_for(&root).expect("recorder is wired");
    (layer, recorder)
}

fn address_of(key: &str) -> Url {
    address::parse(&format!("{ROOT}{key}")).unwrap()
}

async fn write_object(layer: &LayerHandle, key: &str, bytes: &[u8]) {
    layer
        .write(
            Request::new(WriteRequest {
                address: address_of(key),
                body: Body::Bytes(bytes.to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect("seed write");
}

/// Type-mismatch conformance scenarios: in real-directories mode a leaf
/// whose kind mismatches the operation surfaces `InvalidArgument` with
/// guidance — and the mismatched entity survives.
#[tokio::test]
async fn runner_drives_type_mismatch_scenarios() {
    let (layer, recorder) =
        layer_with_knobs(&[("test_caps", ConfigValue::String("full".into()))]).await;
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    // delete-on-directory-type-mismatch.
    recorder.clear();
    layer
        .create_directory(
            Request::new(CreateDirectoryRequest {
                address: address_of("subdir"),
                options: CreateDirectoryOptions::default(),
            }),
            None,
        )
        .await
        .expect("create_directory");
    let err = layer
        .delete(
            Request::new(DeleteRequest {
                address: address_of("subdir"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("delete on a directory must be a type mismatch");
    assert!(err.message().contains("use delete_directory"), "{err}");
    report.push(runner.verify_with_failure(
        "delete-on-directory-type-mismatch",
        recorder.snapshot(),
        Some(("delete".into(), err.code())),
    ));
    // Both spellings refuse, as on the read side: directory identities are
    // stored slash-free, so the guard folds the trailing-slash spelling onto
    // the same leaf rather than falling through to NotFound.
    let err = layer
        .delete(
            Request::new(DeleteRequest {
                address: address_of("subdir/"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("delete on the slash-terminated spelling must also be a type mismatch");
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.message().contains("use delete_directory"), "{err}");

    // delete-directory-on-file-type-mismatch. The file survives.
    recorder.clear();
    write_object(&layer, "plain.txt", b"bytes").await;
    let err = layer
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: address_of("plain.txt"),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .expect_err("delete_directory on a file must be a type mismatch");
    assert!(err.message().contains("use delete()"), "{err}");
    report.push(runner.verify_with_failure(
        "delete-directory-on-file-type-mismatch",
        recorder.snapshot(),
        Some(("delete_directory".into(), err.code())),
    ));
    layer
        .stat(
            Request::new(StatRequest {
                address: address_of("plain.txt"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("the mismatched file must survive the refused delete_directory");

    // list-on-file-type-mismatch.
    recorder.clear();
    write_object(&layer, "listed.txt", b"bytes").await;
    let err = layer
        .list(
            Request::new(ListRequest {
                prefix: address_of("listed.txt"),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("list on a file must be a type mismatch");
    assert!(err.message().contains("not a directory"), "{err}");
    report.push(runner.verify_with_failure(
        "list-on-file-type-mismatch",
        recorder.snapshot(),
        Some(("list".into(), err.code())),
    ));

    // read-on-directory-type-mismatch.
    recorder.clear();
    layer
        .create_directory(
            Request::new(CreateDirectoryRequest {
                address: address_of("readdir"),
                options: CreateDirectoryOptions::default(),
            }),
            None,
        )
        .await
        .expect("create_directory");
    let err = layer
        .read(
            Request::new(ReadRequest {
                address: address_of("readdir"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .map(|_| ())
        .expect_err("read on a directory must be a type mismatch");
    assert!(err.message().contains("use list()"), "{err}");
    report.push(runner.verify_with_failure(
        "read-on-directory-type-mismatch",
        recorder.snapshot(),
        Some(("read".into(), err.code())),
    ));
    // Directory identities are stored slash-free while the host
    // canonicalizes directory addresses to trailing-slash form, so both
    // spellings must refuse — `FileBackend` refuses either one.
    let err = layer
        .read(
            Request::new(ReadRequest {
                address: address_of("readdir/"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .map(|_| ())
        .expect_err("read on the slash-terminated spelling must also be a type mismatch");
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.message().contains("use list()"), "{err}");

    assert!(report.ok(), "{}", report.render_human());
    assert_eq!(report.passed(), 4);
}

/// Implicit directories mirror `FileBackend`: `write a/b` materializes `a`
/// as a directory even without `create_directory`, so `delete a` is the
/// same delete-on-directory type mismatch — and `delete_directory a` refuses with
/// `DirectoryNotEmpty` while the child survives, not `InvalidArgument`.
#[tokio::test]
async fn implicit_parent_directories_mirror_file_backend() {
    let (layer, _recorder) =
        layer_with_knobs(&[("test_caps", ConfigValue::String("full".into()))]).await;
    write_object(&layer, "implicit/child.txt", b"bytes").await;

    let err = layer
        .delete(
            Request::new(DeleteRequest {
                address: address_of("implicit"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("delete on an implicit directory must be a type mismatch");
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.message().contains("use delete_directory"), "{err}");

    let err = layer
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: address_of("implicit"),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .expect_err("delete_directory on a non-empty implicit directory must refuse");
    assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err}");
    layer
        .stat(
            Request::new(StatRequest {
                address: address_of("implicit/child.txt"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect("the child must survive both refused deletes");
}

/// Real-filesystem semantics for nested explicit directories: an empty
/// child directory makes the parent non-empty (`DirectoryNotEmpty`),
/// and a successful delete leaves no orphaned `directories` entries
/// that would later turn an unrelated `delete` at that key into a
/// spurious type mismatch.
#[tokio::test]
async fn delete_directory_refuses_and_never_orphans_child_directories() {
    let (layer, _recorder) =
        layer_with_knobs(&[("test_caps", ConfigValue::String("full".into()))]).await;
    for dir in ["parent", "parent/child"] {
        layer
            .create_directory(
                Request::new(CreateDirectoryRequest {
                    address: address_of(dir),
                    options: CreateDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .expect("create_directory");
    }

    let err = layer
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: address_of("parent"),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .expect_err("an empty child directory must still make the parent non-empty");
    assert_eq!(err.code(), ErrorCode::DirectoryNotEmpty, "{err}");

    for dir in ["parent/child", "parent"] {
        layer
            .delete_directory(
                Request::new(DeleteDirectoryRequest {
                    address: address_of(dir),
                    options: DeleteDirectoryOptions,
                }),
                None,
            )
            .await
            .expect("bottom-up delete_directory succeeds");
    }

    // No orphaned entry: a later delete at the child's key must be a
    // plain NotFound, not a directory type mismatch.
    let err = layer
        .delete(
            Request::new(DeleteRequest {
                address: address_of("parent/child"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("nothing exists at the deleted child's key");
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");
}

/// `write-no-overwrite-existing`: the
/// second write with `IfDestExists::Fail` against an existing object
/// surfaces `AlreadyExists` (the documented `IfDestExists` contract).
#[tokio::test]
async fn runner_drives_no_overwrite_scenario() {
    let (layer, recorder) =
        layer_with_knobs(&[("test_caps", ConfigValue::String("full".into()))]).await;
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    recorder.clear();
    write_object(&layer, "guarded.txt", b"first").await;
    let err = layer
        .write(
            Request::new(WriteRequest {
                address: address_of("guarded.txt"),
                body: Body::Bytes(b"second".to_vec()),
                options: WriteOptions {
                    if_dest: ovstorage_plugin::IfDestExists::Fail,
                    ..WriteOptions::default()
                },
            }),
            None,
        )
        .await
        .expect_err("IfDestExists::Fail against an existing object must refuse");
    report.push(runner.verify_with_failure(
        "write-no-overwrite-existing",
        recorder.snapshot(),
        Some(("write".into(), err.code())),
    ));
    assert!(report.ok(), "{}", report.render_human());
    assert_eq!(report.passed(), 1);
}

/// The data-safety scenarios: `copy(src, src)` round-trips the
/// original bytes (no silent zeroing), and a rename with
/// `IfDestExists::Fail` against an existing destination refuses with
/// `AlreadyExists` while the destination survives.
#[tokio::test]
async fn runner_drives_copy_and_rename_data_safety_scenarios() {
    let (layer, recorder) =
        layer_with_knobs(&[("test_caps", ConfigValue::String("full".into()))]).await;
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    // copy-to-self-preserves-content.
    recorder.clear();
    write_object(&layer, "self.txt", b"important data").await;
    layer
        .copy(
            Request::new(CopyRequest {
                source: address_of("self.txt"),
                destination: address_of("self.txt"),
                options: CopyOptions::default(),
            }),
            None,
        )
        .await
        .expect("copy-to-self must not fail");
    let read = layer
        .read(
            Request::new(ReadRequest {
                address: address_of("self.txt"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("post-copy read");
    let ReadResult::Bytes { bytes, .. } = read else {
        panic!("test backend read returns Bytes");
    };
    assert_eq!(
        bytes, b"important data",
        "copy-to-self must preserve the object bytes"
    );
    report.push(runner.verify_recorded("copy-to-self-preserves-content", recorder.snapshot()));

    // rename-no-overwrite-existing. The destination survives.
    recorder.clear();
    write_object(&layer, "move-src.txt", b"source").await;
    write_object(&layer, "move-dst.txt", b"precious").await;
    let err = layer
        .rename(
            Request::new(RenameRequest {
                source: address_of("move-src.txt"),
                destination: address_of("move-dst.txt"),
                options: RenameOptions {
                    if_dest: ovstorage_plugin::IfDestExists::Fail,
                    ..RenameOptions::default()
                },
            }),
            None,
        )
        .await
        .expect_err("no-overwrite rename against an existing destination must refuse");
    report.push(runner.verify_with_failure(
        "rename-no-overwrite-existing",
        recorder.snapshot(),
        Some(("rename".into(), err.code())),
    ));
    let read = layer
        .read(
            Request::new(ReadRequest {
                address: address_of("move-dst.txt"),
                options: ReadOptions::default(),
            }),
            None,
        )
        .await
        .expect("the refused rename must leave the destination readable");
    let ReadResult::Bytes { bytes, .. } = read else {
        panic!("test backend read returns Bytes");
    };
    assert_eq!(
        bytes, b"precious",
        "the refused rename must leave the destination intact"
    );

    assert!(report.ok(), "{}", report.render_human());
    assert_eq!(report.passed(), 2);
}

/// Capability self-gate: with exactly one op's capability bit
/// disabled, invoking that op yields a typed `Unsupported`, records no
/// call (the gate refuses before the backend bodies run), and leaves
/// the store untouched.
#[tokio::test]
async fn runner_drives_capability_gate_scenarios() {
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    for &(name, method) in CAPABILITY_GATE_SCENARIOS {
        // Fresh layer per scenario: full caps minus exactly this op.
        let (layer, recorder) = layer_with_knobs(&[
            ("test_caps", ConfigValue::String("full".into())),
            ("test_caps_disable", ConfigValue::String(method.into())),
        ])
        .await;
        write_object(&layer, "seed.txt", b"seed").await;
        recorder.clear();

        let target = address_of("seed.txt");
        let err = match method {
            "delete" => layer
                .delete(
                    Request::new(DeleteRequest {
                        address: target,
                        options: DeleteOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated delete"),
            "write_redirect" => layer
                .write_redirect(
                    Request::new(WriteRequest {
                        address: target,
                        body: Body::Bytes(Vec::new()),
                        options: WriteOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated write_redirect"),
            "update_metadata" => layer
                .update_metadata(
                    Request::new(UpdateMetadataRequest {
                        address: target,
                        options: UpdateMetadataOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated update_metadata"),
            "check_access" => layer
                .check_access(
                    Request::new(ovstorage_plugin::CheckAccessRequest {
                        address: target,
                        operations: AccessOps {
                            read: true,
                            ..AccessOps::default()
                        },
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated check_access"),
            "create_directory" => layer
                .create_directory(
                    Request::new(CreateDirectoryRequest {
                        address: address_of("gated-dir"),
                        options: CreateDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated create_directory"),
            "delete_directory" => layer
                .delete_directory(
                    Request::new(DeleteDirectoryRequest {
                        address: address_of("gated-dir"),
                        options: DeleteDirectoryOptions,
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated delete_directory"),
            "list_versions" => layer
                .list_versions(
                    Request::new(ListVersionsRequest {
                        address: target,
                        options: ListVersionsOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated list_versions"),
            "watch_directory" => layer
                .watch_directory(
                    Request::new(WatchDirectoryRequest {
                        prefix: address::parse(ROOT).unwrap(),
                        options: WatchDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .map(|_| ())
                .expect_err("gated watch_directory"),
            other => panic!("no driver for gated op `{other}`"),
        };
        assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");

        // The gate refused before the backend bodies ran: nothing recorded.
        report.push(runner.verify_with_failure(
            name,
            recorder.snapshot(),
            Some((method.into(), err.code())),
        ));

        // No side effects: the seed object is intact and readable.
        let read = layer
            .read(
                Request::new(ReadRequest {
                    address: address_of("seed.txt"),
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("seed object survives the gated op");
        drop(read);
    }

    assert!(report.ok(), "{}", report.render_human());
    assert_eq!(report.passed(), CAPABILITY_GATE_SCENARIOS.len());
}

/// A read-only connection's owning backend rejects mutations
/// itself — `write` (primary contract) and `delete` both refuse with
/// `Unsupported`, and nothing is recorded or stored.
#[tokio::test]
async fn runner_drives_readonly_connection_scenario() {
    let (layer, recorder) =
        layer_with_knobs(&[("test_caps", ConfigValue::String("read-only".into()))]).await;
    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    recorder.clear();
    let err = layer
        .write(
            Request::new(WriteRequest {
                address: address_of("denied.txt"),
                body: Body::Bytes(b"denied".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("read-only connection must reject write");
    assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");
    report.push(runner.verify_with_failure(
        "readonly-connection-rejects-mutations",
        recorder.snapshot(),
        Some(("write".into(), err.code())),
    ));

    // Delete is refused the same way (asserted outside the report; the
    // scenario's primary contract is the write refusal).
    let err = layer
        .delete(
            Request::new(DeleteRequest {
                address: address_of("denied.txt"),
                options: DeleteOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("read-only connection must reject delete");
    assert_eq!(err.code(), ErrorCode::Unsupported, "{err}");
    assert!(recorder.snapshot().is_empty(), "nothing may be recorded");

    // Nothing was written.
    let err = layer
        .stat(
            Request::new(StatRequest {
                address: address_of("denied.txt"),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .expect_err("refused write must leave no object behind");
    assert_eq!(err.code(), ErrorCode::NotFound, "{err}");

    assert!(report.ok(), "{}", report.render_human());
    assert_eq!(report.passed(), 1);
}
