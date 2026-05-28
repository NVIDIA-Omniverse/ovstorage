// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wrappers around external CLI gates: `cargo fmt` (Rust format), `taplo`
//! (TOML format), `cargo-deny` (license + advisory + dup-version policy),
//! and `cargo-machete` (unused dependency detection).
//!
//! Each gate shells out to the respective binary. If the binary is
//! missing, xtask emits a focused install hint rather than a generic
//! "command not found." Local devs install via:
//!
//! ```sh
//! cargo install taplo-cli cargo-deny cargo-machete
//! ```
//!
//! CI installs the same set in `.github/workflows/verify.yml`.

use std::path::Path;
use std::process::Command;

use anyhow::Result;

fn workspaces() -> Result<Vec<std::path::PathBuf>> {
    crate::discovery::discover_workspaces(&crate::repo_root()?)
}

fn rustfmt_manifests() -> Result<Vec<std::path::PathBuf>> {
    crate::discovery::rustfmt_manifests(&crate::repo_root()?)
}

fn toml_format_inputs() -> Result<Vec<String>> {
    crate::discovery::toml_format_inputs(&crate::repo_root()?)
}

/// `cargo fmt --all --manifest-path ...` for the root xtask plus each
/// ovstorage workspace. Mutates Rust files in place.
pub fn cargo_fmt() -> Result<()> {
    run_cargo_fmt(false)
}

/// `cargo fmt --all --check --manifest-path ...` for the root xtask
/// plus each ovstorage workspace.
pub fn cargo_fmt_check() -> Result<()> {
    run_cargo_fmt(true)
}

/// `taplo fmt --check` over the whole repo. taplo respects `.gitignore`
/// so it won't descend into `target/`.
pub fn taplo_check() -> Result<()> {
    let repo_root = crate::repo_root()?;
    require_tool("taplo", "cargo install taplo-cli --features lsp")?;
    let status = Command::new("taplo")
        .arg("fmt")
        .arg("--check")
        .args(&toml_format_inputs()?)
        .current_dir(&repo_root)
        .status()?;
    if !status.success() {
        anyhow::bail!(
            "taplo fmt --check failed: TOML files are not formatted. \
             Run `make fmt-toml` and commit the diff."
        );
    }
    Ok(())
}

/// `taplo fmt` over the whole repo. Mutates `*.toml` in place.
pub fn taplo_fix() -> Result<()> {
    let repo_root = crate::repo_root()?;
    require_tool("taplo", "cargo install taplo-cli --features lsp")?;
    let status = Command::new("taplo")
        .arg("fmt")
        .args(&toml_format_inputs()?)
        .current_dir(&repo_root)
        .status()?;
    if !status.success() {
        anyhow::bail!("taplo fmt failed");
    }
    Ok(())
}

/// `cargo deny check` against each workspace's `Cargo.toml`, sharing
/// the repo-root `deny.toml` config.
pub fn cargo_deny() -> Result<()> {
    let repo_root = crate::repo_root()?;
    require_tool("cargo-deny", "cargo install cargo-deny")?;
    let config = repo_root.join("deny.toml");
    if !config.exists() {
        anyhow::bail!(
            "deny.toml missing at {}. Re-run from a clean checkout or \
             restore from VCS.",
            config.display()
        );
    }
    for ws in workspaces()? {
        // `--config` is a `check`-subcommand arg in cargo-deny ≥ 0.18;
        // top-level `--all-features` still works.
        run_per_workspace(
            "cargo-deny",
            &repo_root.join(&ws),
            &[
                "deny",
                "--all-features",
                "check",
                "--config",
                config.to_str().expect("utf-8 path"),
            ],
        )?;
    }
    Ok(())
}

/// `cargo machete` per workspace. Reports unused dependencies; exits
/// non-zero if any are found. Per-crate exemptions go in each
/// `Cargo.toml` under `[package.metadata.cargo-machete]`.
pub fn cargo_machete() -> Result<()> {
    let repo_root = crate::repo_root()?;
    require_tool("cargo-machete", "cargo install cargo-machete")?;
    for ws in workspaces()? {
        // Invoke `cargo-machete` directly rather than `cargo machete` —
        // cargo-machete v0.9.1 treats its own subcommand-prefix argv
        // entry as a path, so going through cargo causes it to walk a
        // bogus "machete" directory and bail.
        let dir = repo_root.join(&ws);
        let status = std::process::Command::new("cargo-machete")
            .arg(&dir)
            .status()?;
        if !status.success() {
            anyhow::bail!("cargo-machete failed in {}", dir.display());
        }
    }
    Ok(())
}

/// `cargo clippy --workspace --all-targets --all-features --locked --
/// -D warnings` per workspace. Apollo Ch 2 baseline invocation.
pub fn cargo_clippy() -> Result<()> {
    let repo_root = crate::repo_root()?;
    for ws in workspaces()? {
        run_per_workspace(
            "cargo clippy",
            &repo_root.join(&ws),
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        )?;
    }
    Ok(())
}

/// `cargo doc --no-deps --all-features` per workspace with
/// `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`. The
/// `missing_docs` warn opt-in is deliberately deferred until the
/// per-crate doc backfill (audit F-8.3 / F-8.4 / F-8.6 / F-8.7) lands.
pub fn cargo_doc() -> Result<()> {
    let repo_root = crate::repo_root()?;
    for ws in workspaces()? {
        let dir = repo_root.join(&ws);
        let args = [
            "doc",
            "--workspace",
            "--no-deps",
            "--all-features",
            "--locked",
        ];
        let status = Command::new("cargo")
            .args(args)
            .env("RUSTDOCFLAGS", "-D rustdoc::broken_intra_doc_links")
            // Skip the nested cargo-build chains in build.rs (plugin .so
            // baking and test-plugin staging). They're not needed to
            // document the crates and they exhaust a 14 GB GitHub runner.
            .env("DOCS_RS", "1")
            .current_dir(&dir)
            .status()?;
        if !status.success() {
            anyhow::bail!("cargo doc failed in {}", dir.display());
        }
    }
    Ok(())
}

fn run_per_workspace(label: &str, dir: &Path, args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(args).current_dir(dir);
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("{label} failed in {}", dir.display());
    }
    Ok(())
}

fn run_cargo_fmt(check: bool) -> Result<()> {
    let repo_root = crate::repo_root()?;
    for manifest in rustfmt_manifests()? {
        let manifest = repo_root.join(&manifest);
        let mut args = vec![
            "fmt",
            "--all",
            "--manifest-path",
            manifest.to_str().expect("utf-8 path"),
        ];
        if check {
            args.push("--check");
        }
        let status = Command::new("cargo")
            .args(&args)
            .current_dir(&repo_root)
            .status()?;
        if !status.success() {
            let suffix = if check { " --check" } else { "" };
            anyhow::bail!("cargo fmt{suffix} failed for {}", manifest.display());
        }
    }
    Ok(())
}

fn require_tool(bin: &str, install_hint: &str) -> Result<()> {
    let probe = Command::new(bin).arg("--version").output();
    match probe {
        Ok(out) if out.status.success() => Ok(()),
        _ => anyhow::bail!("`{bin}` is not installed or not on PATH. Install with: {install_hint}"),
    }
}
