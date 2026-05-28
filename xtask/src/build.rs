// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask build` — `cargo build --workspace` across the active
//! workspaces. Cargo doesn't span workspaces, so each one needs its own
//! invocation.

use anyhow::{Context, Result, bail};
use std::process::Command;

pub(crate) fn workspaces() -> Result<Vec<std::path::PathBuf>> {
    crate::discovery::discover_workspaces(&crate::repo_root()?)
        .context("discover product workspaces for xtask build")
}

pub(crate) fn run(release: bool) -> Result<()> {
    let root = crate::repo_root()?;
    for ws in workspaces()? {
        let dir = root.join(&ws);
        let mut cmd = Command::new("cargo");
        cmd.arg("build").arg("--workspace").current_dir(&dir);
        if release {
            cmd.arg("--release");
        }
        let status = cmd.status()?;
        if !status.success() {
            bail!("cargo build failed in {}", dir.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspaces_includes_all_product_workspaces() {
        let names: Vec<String> = workspaces()
            .expect("workspaces()")
            .into_iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        for required in [
            "ovstorage-core",
            "ovstorage-services-client",
            "ovstorage-cloud",
            "ovstorage-nucleus",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "expected workspace '{required}' in {names:?}",
            );
        }
    }
}
