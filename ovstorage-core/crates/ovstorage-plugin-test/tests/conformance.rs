// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-tree exemplar of consuming the runner. Drives a small registry
//! set against `TestBackend`, compares the JSON report to a stable
//! checked-in snapshot, and asserts no drift.
//! `OVSTORAGE_REWRITE_CONFORMANCE_SNAPSHOTS=1` emits the report into
//! `tests/conformance/reports/runner_smoke.json` for inspection.

use std::path::PathBuf;

use ovstorage_plugin::shim::Factory as _;
use ovstorage_plugin::{
    BackendId, ConfigValue, ConnectionRequest, DeleteOptions, ReadOptions, ResolvedTarget,
    SecretBundle, StatOptions, WriteOptions, address,
};
use ovstorage_plugin_test::{
    BACKEND_KIND, ConformanceReport, ScenarioRegistry, ScenarioRunner, TestFactory,
};

const RUNNER_SMOKE_SNAPSHOT: &str = include_str!("conformance/snapshots/runner_smoke.json");

fn make_request() -> ConnectionRequest {
    let mut config = std::collections::HashMap::new();
    config.insert(
        "test_root".into(),
        ConfigValue::String("test://demo/".into()),
    );
    ConnectionRequest {
        backend_kind: BACKEND_KIND.into(),
        config,
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    }
}

fn target(key: &str) -> ResolvedTarget {
    ResolvedTarget {
        backend_id: BackendId("test".into()),
        resolved_address: address::parse(&format!("test://demo/{key}")).unwrap(),
    }
}

#[tokio::test]
async fn runner_drives_default_scenarios_and_emits_report() {
    let factory = TestFactory::new();
    let instance = factory.instantiate(&make_request(), None).await.unwrap();
    let backend = instance.backend.clone();
    let root = address::parse("test://demo/").unwrap();
    let recorder = factory.recorder_for(&root).expect("recorder is wired");

    let registry = ScenarioRegistry::with_defaults();
    let runner = ScenarioRunner::new(&registry);
    let mut report = ConformanceReport::new();

    backend
        .write(
            target("smoke.txt"),
            b"smoke".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();

    recorder.clear();
    backend
        .stat(target("smoke.txt"), StatOptions::default(), None)
        .await
        .unwrap();
    report.push(runner.verify_recorded("stat-basic-objectinfo", recorder.snapshot()));

    recorder.clear();
    let err = backend
        .stat(target("does-not-exist.txt"), StatOptions::default(), None)
        .await
        .unwrap_err();
    report.push(runner.verify_with_failure(
        "stat-not-found",
        recorder.snapshot(),
        Some(("stat".into(), err.code())),
    ));

    recorder.clear();
    let _ = backend
        .read(target("smoke.txt"), ReadOptions::default(), None)
        .await
        .unwrap();
    report.push(runner.verify_recorded("read-streamed-empty", recorder.snapshot()));

    recorder.clear();
    backend
        .write(
            target("inline.bin"),
            b"hello".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    report.push(runner.verify_recorded("write-done-inline", recorder.snapshot()));

    recorder.clear();
    backend
        .write(
            target("ephemeral.bin"),
            b"x".to_vec(),
            WriteOptions::default(),
            None,
        )
        .await
        .unwrap();
    backend
        .delete(target("ephemeral.bin"), DeleteOptions::default(), None)
        .await
        .unwrap();
    report.push(runner.verify_recorded("delete-existing-object", recorder.snapshot()));

    // Negative scenario: recorder stays empty.
    recorder.clear();
    report.push(runner.verify_recorded("metadata-unsupported-not-called", recorder.snapshot()));

    report.push(runner.skip(
        "write-no-overwrite-existing",
        "fixture omits ConditionalWrites profile in this smoke run",
    ));

    assert!(
        report.ok(),
        "conformance report failed: {}",
        report.render_human()
    );
    assert_eq!(report.passed(), 6);
    assert_eq!(report.skipped(), 1);
    assert_eq!(report.failed(), 0);

    let json = report.render_json();
    let snapshot_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "conformance",
        "reports",
        "runner_smoke.json",
    ]
    .iter()
    .collect();
    let snapshot_parent = snapshot_path
        .parent()
        .expect("snapshot path includes parent directory");
    if std::env::var_os("OVSTORAGE_REWRITE_CONFORMANCE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(snapshot_parent).expect("create snapshot directory");
        std::fs::write(&snapshot_path, &json).expect("write snapshot");
    } else {
        assert_eq!(
            RUNNER_SMOKE_SNAPSHOT.trim(),
            json.trim(),
            "report snapshot drift; rerun with OVSTORAGE_REWRITE_CONFORMANCE_SNAPSHOTS=1 to emit a local report"
        );
    }
}
