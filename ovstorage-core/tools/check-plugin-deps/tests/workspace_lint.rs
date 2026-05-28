// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use check_plugin_deps::{AllowList, format_violations, lint_crates_dir_with_visited, load_roots};

#[test]
fn every_root_in_roots_toml_has_a_non_empty_visit_set() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots_toml = manifest_dir.join("roots.toml");
    let roots = load_roots(&roots_toml, &manifest_dir)
        .unwrap_or_else(|error| panic!("failed to load {}: {error}", roots_toml.display()));
    assert!(
        !roots.is_empty(),
        "{} produced zero roots",
        roots_toml.display()
    );
    let base = AllowList::permissive_starting();
    let mut all_violations = Vec::new();
    for root in &roots {
        let allowlist = root.allowlist(&base);
        let (violations, visited) = lint_crates_dir_with_visited(&root.crates_dir, &allowlist)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to scan root {} at {}: {error}",
                    root.label,
                    root.crates_dir.display()
                )
            });
        assert!(
            !visited.is_empty(),
            "root {} at {} visited zero plugin manifests; either the path is wrong or the workspace lost its plugins",
            root.label,
            root.crates_dir.display(),
        );
        all_violations.extend(violations);
    }
    if !all_violations.is_empty() {
        panic!("{}", format_violations(&all_violations));
    }
}

#[test]
fn core_root_visits_known_plugin_manifests() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let roots_toml = manifest_dir.join("roots.toml");
    let roots = load_roots(&roots_toml, &manifest_dir).unwrap();
    let core = roots
        .iter()
        .find(|r| r.label == "core")
        .expect("roots.toml must declare a 'core' root");
    let allowlist = core.allowlist(&AllowList::permissive_starting());
    let (_, visited) = lint_crates_dir_with_visited(&core.crates_dir, &allowlist).unwrap();
    for expected in [
        "ovstorage-plugin-file",
        "ovstorage-plugin-http",
        "ovstorage-plugin-test",
    ] {
        assert!(
            visited.iter().any(|v| v == expected),
            "core root visit set missing {expected}; got {visited:?}",
        );
    }
}
