// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace discovery for `xtask`. Replaces hand-curated `WORKSPACES`
//! and `RUSTFMT_MANIFESTS` consts that drifted across PR 42 / PR 43.
//!
//! The repo layout: the root `Cargo.toml` is itself a workspace
//! (members = ["xtask"]). Sibling product workspaces live in
//! repo-root child directories whose `Cargo.toml` declares its own
//! `[workspace]` section. Discovery scans repo-root children and
//! filters to those that match.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Discover sibling workspaces by scanning the repo root for child
/// directories whose `Cargo.toml` declares `[workspace]`. Returns
/// paths relative to repo root, sorted. Excludes `target/`, `dist/`,
/// `_archive/`, and dotfiles.
pub fn discover_workspaces(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let mut workspaces = Vec::new();
    let entries =
        fs::read_dir(repo_root).with_context(|| format!("read_dir {}", repo_root.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !path.is_dir() || name_str.starts_with('.') {
            continue;
        }
        if matches!(name_str.as_ref(), "target" | "dist" | "_archive") {
            continue;
        }
        let manifest = path.join("Cargo.toml");
        if !manifest.exists() {
            continue;
        }
        let body = fs::read_to_string(&manifest)
            .with_context(|| format!("read {}", manifest.display()))?;
        if body.contains("[workspace]") {
            let rel = path.strip_prefix(repo_root)?.to_path_buf();
            workspaces.push(rel);
        }
    }
    workspaces.sort();
    Ok(workspaces)
}

/// Cargo manifests fmt should walk: root + every discovered workspace.
pub fn rustfmt_manifests(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let mut manifests = vec![PathBuf::from("Cargo.toml")];
    for ws in discover_workspaces(repo_root)? {
        manifests.push(ws.join("Cargo.toml"));
    }
    Ok(manifests)
}

/// Paths/globs taplo should format. Includes root TOMLs, xtask TOMLs,
/// each workspace's root Cargo.toml, and `<workspace>/crates/**/*.toml`
/// per workspace. Mirrors the previous hand-curated set.
pub fn toml_format_inputs(repo_root: &Path) -> Result<Vec<String>> {
    let mut inputs = vec![
        "Cargo.toml".into(),
        "deny.toml".into(),
        "rust-toolchain.toml".into(),
        ".cargo/config.toml".into(),
        "xtask/**/*.toml".into(),
    ];
    for ws in discover_workspaces(repo_root)? {
        let ws_str = ws.to_string_lossy();
        inputs.push(format!("{ws_str}/Cargo.toml"));
        inputs.push(format!("{ws_str}/crates/**/*.toml"));
        // ovstorage-core has extra example/tool subtrees; include if present
        let examples = repo_root.join(&ws).join("examples");
        if examples.is_dir() {
            inputs.push(format!("{ws_str}/examples/**/*.toml"));
        }
        let tools = repo_root.join(&ws).join("tools");
        if tools.is_dir() {
            inputs.push(format!("{ws_str}/tools/**/*.toml"));
        }
        let cargo_cfg = repo_root.join(&ws).join(".cargo").join("config.toml");
        if cargo_cfg.is_file() {
            inputs.push(format!("{ws_str}/.cargo/config.toml"));
        }
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root_for_test() -> PathBuf {
        // CARGO_MANIFEST_DIR for xtask points at <repo-root>/xtask;
        // parent is the repo root.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn discover_workspaces_finds_all_active_product_workspaces() {
        let root = repo_root_for_test();
        let found = discover_workspaces(&root).expect("discover_workspaces");
        let names: Vec<String> = found
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        for required in [
            "ovstorage-core",
            "ovstorage-services-client",
            "ovstorage-cloud",
            "ovstorage-nucleus",
            "ovstorage-remote",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "expected workspace '{required}' in {names:?}",
            );
        }
    }

    #[test]
    fn discover_workspaces_excludes_target_dist_archive_dotfiles() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Create a fake repo root with various directories
        for d in ["good-workspace", "target", "dist", "_archive", ".hidden"] {
            let dir = tmp.path().join(d);
            fs::create_dir(&dir).unwrap();
            let manifest = dir.join("Cargo.toml");
            fs::write(&manifest, "[workspace]\nmembers = [\"crates/*\"]\n").unwrap();
        }
        // And one without [workspace]
        let plain = tmp.path().join("plain-crate");
        fs::create_dir(&plain).unwrap();
        fs::write(plain.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();

        let found = discover_workspaces(tmp.path()).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["good-workspace".to_string()]);
    }

    #[test]
    fn discover_workspaces_requires_workspace_directive() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("not-a-workspace");
        fs::create_dir(&dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let found = discover_workspaces(tmp.path()).unwrap();
        assert!(found.is_empty(), "got {found:?}");
    }
}
