// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Header regeneration gate. Invokes cbindgen as a library against each
//! header-emitting crate's `cbindgen.toml`, writes the result to the
//! checked-in `include/<header>.h`, and (when `verify_clean` is true)
//! fails if `git diff --exit-code` reports any change.
//!
//! The crates' own `build.rs` files perform the same work as a
//! best-effort dev convenience (they swallow errors as `cargo:warning`
//! to keep sandboxed builds working). This xtask is the strict version
//! used by CI: any cbindgen error is a hard failure.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

struct HeaderTarget {
    /// Path to the crate, relative to the repo root.
    crate_path: &'static str,
    /// Path to the header inside the crate, relative to the crate root.
    header: &'static str,
}

const TARGETS: &[HeaderTarget] = &[
    HeaderTarget {
        crate_path: "ovstorage-core/crates/ovstorage-capi",
        header: "include/ovstorage.h",
    },
    HeaderTarget {
        crate_path: "ovstorage-core/crates/ovstorage-plugin",
        header: "include/ovstorage_plugin.h",
    },
    HeaderTarget {
        crate_path: "ovstorage-remote/crates/ovstorage-authz",
        header: "include/ovstorage_authz_plugin.h",
    },
];

pub fn run(verify_clean: bool) -> Result<()> {
    let repo_root = crate::repo_root()?;
    for target in TARGETS {
        if !repo_root.join(target.crate_path).exists() {
            eprintln!("skipping missing header target {}", target.crate_path);
            continue;
        }
        regenerate_one(&repo_root, target)?;
    }
    if verify_clean {
        verify_no_diff(&repo_root)?;
    }
    Ok(())
}

fn regenerate_one(repo_root: &Path, target: &HeaderTarget) -> Result<()> {
    let crate_dir = repo_root.join(target.crate_path);
    let header_path = crate_dir.join(target.header);
    let config_path = crate_dir.join("cbindgen.toml");

    let config = cbindgen::Config::from_file(&config_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", config_path.display()))?;

    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .with_context(|| format!("cbindgen generate for {}", target.crate_path))?;

    if let Some(parent) = header_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }

    let mut new_header = Vec::new();
    bindings.write(&mut new_header);

    let unchanged = std::fs::read(&header_path)
        .map(|existing| existing == new_header)
        .unwrap_or(false);
    if !unchanged {
        std::fs::write(&header_path, &new_header)
            .with_context(|| format!("write {}", header_path.display()))?;
        eprintln!("regenerated {}", header_path.display());
    }
    Ok(())
}

fn verify_no_diff(repo_root: &Path) -> Result<()> {
    let mut paths = Vec::new();
    for target in TARGETS {
        if !repo_root.join(target.crate_path).exists() {
            continue;
        }
        paths.push(PathBuf::from(target.crate_path).join(target.header));
    }
    let output = Command::new("git")
        .arg("diff")
        .arg("--exit-code")
        .arg("--")
        .args(&paths)
        .current_dir(repo_root)
        .output()
        .context("invoke git diff")?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        eprintln!("--- header drift detected ---");
        eprint!("{stdout}");
        anyhow::bail!(
            "checked-in C headers differ from regenerated output. \
             Run `make regenerate-headers` and commit the diff."
        );
    }
    Ok(())
}
