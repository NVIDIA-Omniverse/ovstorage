// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Repo-wide tooling. Subcommands shared between `make verify` (developers)
//! and `.github/workflows/verify.yml` (CI). Single source of truth for the
//! cross-cutting gates described in `todo.md`.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod build;
mod discovery;
mod dist;
mod external;
mod public_docs;
mod regenerate;
mod skills;
mod source_headers;
mod test_plugins;
mod third_party_notices;

#[derive(Parser)]
#[command(version, about = "Cross-cutting CI gates for the ovstorage tree")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Regenerate every checked-in C header from its Rust source of truth.
    RegenerateHeaders,
    /// Regenerate headers, then fail if `git diff` shows any change.
    VerifyHeadersClean,
    /// `cargo fmt --all` for the root xtask plus every ovstorage workspace.
    Fmt,
    /// `cargo fmt --all --check` for the root xtask plus every ovstorage
    /// workspace.
    FmtCheck,
    /// `taplo fmt --check`: fail if any TOML file is unformatted.
    FmtTomlCheck,
    /// `taplo fmt`: format every TOML file in place.
    FmtToml,
    /// `cargo deny check` per workspace, using the repo-root `deny.toml`.
    CargoDeny,
    /// `cargo machete` per workspace: fail on unused dependencies.
    CargoMachete,
    /// `cargo clippy --all-targets --all-features --locked -- -D warnings`
    /// per workspace.
    Clippy,
    /// `cargo doc --no-deps --all-features` per workspace with
    /// `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`.
    Doc,
    /// Run every non-test gate (skills, public docs, headers, Rust/TOML
    /// format checks, cargo-deny, cargo-machete, clippy, doc).
    Verify,
    /// Run `cargo test --workspace` across the active workspaces.
    Test,
    /// Validate repo-root agent skills, if any are present.
    ValidateSkills,
    /// Lint `docs/public/`: every markdown link must stay inside the
    /// public surface (no `](../../` link targets).
    LintPublicDocs,
    /// Validate SPDX license/copyright notices in active source files.
    LintSourceHeaders,
    /// Regenerate the Cargo dependency table in `THIRD_PARTY_NOTICES.md`
    /// from `cargo metadata --locked` across every active workspace.
    RegenerateThirdPartyNotices,
    /// Regenerate the Cargo dependency table and fail if it would change.
    /// Wired into `verify` so dependency drift is caught in CI.
    VerifyThirdPartyNoticesClean,
    /// `cargo build --workspace` across the active workspaces.
    Build {
        #[arg(long)]
        release: bool,
    },
    /// Build, then assemble `dist/` at the repo root with binaries +
    /// `plugins/` so `./dist/ovstorage` runs without any env-var setup.
    Dist {
        #[arg(long)]
        release: bool,
        /// Also build the Python wheel into `dist/wheels/` via maturin.
        /// Requires `maturin` on PATH (`make install-tools`).
        #[arg(long)]
        wheel: bool,
    },
    /// Build only the Python wheel into `dist/wheels/`. CI uses this so
    /// it doesn't pay for the full binary+plugin build on every platform.
    Wheel {
        #[arg(long)]
        release: bool,
    },
    /// Print the current `[project] version` from
    /// `ovstorage-python/pyproject.toml`. Used by the release workflow.
    ReleaseVersion,
    /// Alias of `release-version`.
    PrintReleaseVersion,
    /// Assert the current release version is final `X.Y.0` for opening a
    /// new release line from main.
    AssertReleaseOpenVersion,
    /// Print the release-line branch name for the current final version:
    /// `release/vX.Y`.
    ReleaseLineBranch,
    /// Print the next minor final version for main after release-open.
    NextMinorVersion,
    /// Print the next patch final version for a release branch after finalize.
    NextPatchVersion,
    /// Print the final release tag for the current version: `vX.Y.Z`.
    FinalReleaseTag,
    /// Print the next RC number for the current final version from an
    /// existing tag list.
    NextRcNumber { tags: Vec<String> },
    /// Refuse if the current final version's tag is present in the given tag
    /// list.
    AssertFinalTagAbsent { tags: Vec<String> },
    /// Bump the `[project] version` in
    /// `ovstorage-python/pyproject.toml`. Rewrites the file in place.
    BumpVersion {
        /// Bump strategy: `release` (0.1.0rc1 -> 0.1.0), `patch`,
        /// `minor`, `major`, legacy `alpha`, or `to=<version>`
        /// (explicit override).
        #[arg(long)]
        kind: String,
    },
    /// Alias of `bump-version`.
    BumpReleaseVersion {
        /// Bump strategy: `release`, `patch`, `minor`, `major`, legacy
        /// `alpha`, or `to=<version>`.
        kind: String,
    },
    /// Build a full release tarball / zip for one platform:
    /// `dist/ovstorage-v<version>-<platform>.{tar.gz,zip}`. The unpacked
    /// staging tree is left at `dist/ovstorage-v<version>-<platform>/`
    /// for inspection.
    ReleaseArchive {
        #[arg(long, default_value_t = true)]
        release: bool,
        /// Platform tag baked into the archive name. CI passes one of
        /// `linux-x86_64`, `linux-arm64`, `windows-x86_64`.
        #[arg(long)]
        platform: String,
    },
    /// Pre-build the cdylib plugins that test build.rs files would
    /// otherwise produce via nested cargo, and stage them under
    /// `target/test-plugins/`. Prints the `OVSTORAGE_*_OVERRIDE`
    /// env var that points at the staged path.
    BuildTestPlugins,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::RegenerateHeaders => regenerate::run(false),
        Cmd::VerifyHeadersClean => regenerate::run(true),
        Cmd::Fmt => external::cargo_fmt(),
        Cmd::FmtCheck => external::cargo_fmt_check(),
        Cmd::FmtTomlCheck => external::taplo_check(),
        Cmd::FmtToml => external::taplo_fix(),
        Cmd::CargoDeny => external::cargo_deny(),
        Cmd::CargoMachete => external::cargo_machete(),
        Cmd::Clippy => external::cargo_clippy(),
        Cmd::Doc => external::cargo_doc(),
        Cmd::Verify => verify(),
        Cmd::Test => cargo_test_workspaces(),
        Cmd::ValidateSkills => skills::validate(),
        Cmd::LintPublicDocs => public_docs::validate(),
        Cmd::LintSourceHeaders => source_headers::validate(),
        Cmd::RegenerateThirdPartyNotices => third_party_notices::regenerate(),
        Cmd::VerifyThirdPartyNoticesClean => third_party_notices::verify_clean(),
        Cmd::Build { release } => build::run(release),
        Cmd::Dist { release, wheel } => dist::run(release, wheel),
        Cmd::Wheel { release } => dist::wheel_only(release),
        Cmd::ReleaseVersion => dist::print_release_version(),
        Cmd::PrintReleaseVersion => dist::print_release_version(),
        Cmd::AssertReleaseOpenVersion => dist::assert_release_open_version(),
        Cmd::ReleaseLineBranch => dist::print_release_line_branch(),
        Cmd::NextMinorVersion => dist::print_next_minor_version(),
        Cmd::NextPatchVersion => dist::print_next_patch_version(),
        Cmd::FinalReleaseTag => dist::print_final_release_tag(),
        Cmd::NextRcNumber { tags } => dist::print_next_rc_number(&tags),
        Cmd::AssertFinalTagAbsent { tags } => dist::assert_final_tag_absent(&tags),
        Cmd::BumpVersion { kind } => dist::bump_release_version(&kind),
        Cmd::BumpReleaseVersion { kind } => dist::bump_release_version(&kind),
        Cmd::ReleaseArchive { release, platform } => dist::release_archive(release, &platform),
        Cmd::BuildTestPlugins => test_plugins::run(),
    }
}

fn verify() -> Result<()> {
    skills::validate()?;
    public_docs::validate()?;
    source_headers::validate()?;
    third_party_notices::verify_clean()?;
    regenerate::run(true)?;
    external::cargo_fmt_check()?;
    external::taplo_check()?;
    external::cargo_deny()?;
    external::cargo_machete()?;
    external::cargo_clippy()?;
    external::cargo_doc()?;
    Ok(())
}

fn cargo_test_workspaces() -> Result<()> {
    use std::process::Command;
    // A preceding `cargo build --workspace` forces cdylib targets onto disk
    // so integration tests that `dlopen` plugins find them.
    let staged = test_plugins::stage()?;
    let repo_root = repo_root()?;
    for ws in build::workspaces()? {
        let dir = repo_root.join(&ws);
        let mut build_cmd = Command::new("cargo");
        build_cmd.arg("build").arg("--workspace").current_dir(&dir);
        staged.apply_to(&mut build_cmd);
        let build_status = build_cmd.status()?;
        if !build_status.success() {
            anyhow::bail!("cargo build failed in {}", dir.display());
        }
        let mut test_cmd = Command::new("cargo");
        test_cmd.arg("test").arg("--workspace").current_dir(&dir);
        staged.apply_to(&mut test_cmd);
        let test_status = test_cmd.status()?;
        if !test_status.success() {
            anyhow::bail!("cargo test failed in {}", dir.display());
        }
    }
    Ok(())
}

pub(crate) fn repo_root() -> Result<std::path::PathBuf> {
    // CARGO_MANIFEST_DIR for the xtask crate is `<repo>/xtask`. Climb one.
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    let path = std::path::PathBuf::from(manifest);
    Ok(path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("xtask has no parent dir"))?
        .to_path_buf())
}
