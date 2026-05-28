// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask build-test-plugins` — pre-build the cdylib plugins that
//! the `ovstorage` test build.rs
//! files would otherwise produce via nested cargo invocations, and stage
//! them into `<repo>/target/test-plugins/`. Tests pick them up via the
//! `OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE`.
//!
//! Goal: avoid the two-level nested-cargo trees that exhaust a 14 GB
//! GitHub Actions runner (each nested target dir duplicates the entire
//! dep graph because it has no relationship to the outer cargo's
//! incremental cache). Locally, the same path means `make dist` + `make
//! test` share the plugin compile instead of doing it twice.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `(workspace_dir, package_name, cdylib_stem)`. Stem is the filename
/// without the platform prefix/suffix — `dll_filename` adds those.
type Plugin = (&'static str, &'static str, &'static str);

/// All plugins we need to build. Some are used by multiple fixtures.
/// Grouped by workspace at build time so each workspace's cargo
/// invocation resolves deps once.
const PLUGINS: &[Plugin] = &[
    // ovstorage-core
    (
        "ovstorage-core",
        "ovstorage-plugin-file",
        "ovstorage_plugin_file",
    ),
    (
        "ovstorage-core",
        "ovstorage-plugin-test",
        "ovstorage_plugin_test",
    ),
    (
        "ovstorage-core",
        "ovstorage-example-plugin-rust",
        "ovstorage_plugin_example_rust",
    ),
];

const EXAMPLE_PLUGIN_STEM: &str = "ovstorage_plugin_example_rust";

/// Path under the repo root where the staged plugins land.
pub const STAGING_SUBDIR: &str = "target/test-plugins";

pub struct StagedPaths {
    pub example_so: PathBuf,
}

impl StagedPaths {
    /// Resolve the staged paths without running the build. Useful when
    /// callers want to plumb env vars before the artifacts exist (the
    /// build steps come later in the same job).
    pub fn under(root: &Path) -> Self {
        let staging = root.join(STAGING_SUBDIR);
        Self {
            example_so: staging.join(dll_filename(EXAMPLE_PLUGIN_STEM)),
        }
    }

    /// Set `OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE` on a `Command` so a
    /// child `cargo test` skips the nested-cargo path.
    pub fn apply_to(&self, cmd: &mut Command) {
        cmd.env(
            "OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE",
            &self.example_so,
        );
    }
}

pub fn run() -> Result<()> {
    let staged = stage()?;
    println!(
        "OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE={}",
        staged.example_so.display()
    );
    Ok(())
}

pub fn stage() -> Result<StagedPaths> {
    let root = crate::repo_root()?;

    // One cargo invocation per workspace, building every plugin from
    // that workspace at once — deps resolve once, the workspace's
    // outer target/ holds the artifacts.
    let mut by_workspace: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (ws, pkg, _) in PLUGINS {
        by_workspace.entry(ws).or_default().insert(pkg);
    }
    for (ws, pkgs) in &by_workspace {
        build_packages(&root.join(ws), pkgs)?;
    }

    // Map stem → its source target dir so the staging step can find each .so.
    let mut artifact_workspace: BTreeMap<&str, &str> = BTreeMap::new();
    for (ws, _, stem) in PLUGINS {
        artifact_workspace.insert(stem, ws);
    }

    // (Re)create the staging dir so a renamed plugin doesn't leave a stale .so.
    let staged = StagedPaths::under(&root);
    let staging = root.join(STAGING_SUBDIR);
    if staging.exists() {
        fs::remove_dir_all(&staging).with_context(|| format!("clear {}", staging.display()))?;
    }
    fs::create_dir_all(&staging)?;
    let example_src = root
        .join(artifact_workspace[EXAMPLE_PLUGIN_STEM])
        .join("target")
        .join("debug")
        .join(dll_filename(EXAMPLE_PLUGIN_STEM));
    fs::copy(&example_src, &staged.example_so).with_context(|| {
        format!(
            "copy {} → {}",
            example_src.display(),
            staged.example_so.display()
        )
    })?;

    Ok(staged)
}

fn build_packages(workspace_dir: &Path, packages: &BTreeSet<&str>) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").current_dir(workspace_dir);
    for pkg in packages {
        cmd.arg("-p").arg(pkg);
    }
    if !cmd.status()?.success() {
        bail!("cargo build failed in {}", workspace_dir.display());
    }
    Ok(())
}

fn dll_filename(stem: &str) -> String {
    format!(
        "{}{}{}",
        std::env::consts::DLL_PREFIX,
        stem,
        std::env::consts::DLL_SUFFIX
    )
}
