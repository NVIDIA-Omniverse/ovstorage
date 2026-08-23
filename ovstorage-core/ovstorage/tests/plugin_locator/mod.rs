// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Locating a workspace-built test plugin cdylib, and refusing to run against a
//! stale one.
//!
//! Shared by the integration tests that `dlopen` a test plugin directly rather
//! than through an `OVSTORAGE_PLUGIN_TEST_SO`-style override. This lives in its
//! own module rather than in `tests/support/` so that every binary declaring it
//! uses everything in it — no item needs a `dead_code` exemption, and
//! `tests/support/`'s own items keep theirs.

use std::path::{Path, PathBuf};

/// Locate a built plugin cdylib next to the test binary's target profile dir.
///
/// When `OVSTORAGE_REQUIRE_TEST_PLUGINS` is set — `make test` / `make test-ci`
/// set it after `build-test-plugins` stages the cdylibs into the profile dir —
/// an absent artifact is a hard error instead of a silent skip, so a suite
/// cannot pass vacuously in a CI job that built the workspace.
pub(crate) fn plugin_so(stem: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // .../target/<profile>/deps/<test-bin>  ->  .../target/<profile>
    let profile_dir = exe.parent()?.parent()?;
    let file = if cfg!(target_os = "windows") {
        format!("{stem}.dll")
    } else if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else {
        format!("lib{stem}.so")
    };
    let path = profile_dir.join(file);
    if path.exists() {
        assert_plugin_so_is_fresh(stem, &path);
        return Some(path);
    }
    assert!(
        std::env::var("OVSTORAGE_REQUIRE_TEST_PLUGINS").as_deref() != Ok("1"),
        "test cdylib `{stem}` not found at {} but OVSTORAGE_REQUIRE_TEST_PLUGINS \
         is set: build the workspace (`cargo test --workspace` / `make test-ci`)",
        path.display(),
    );
    None
}

/// Fail loudly when the cdylib [`plugin_so`] just located is older than any
/// source it was built from.
///
/// The artifact is found by probing a `current_exe()`-relative path, so Cargo
/// has no dependency edge from these tests to it. `cargo test -p ovstorage`
/// recompiles nothing in that cdylib and runs against whatever is already in the
/// profile dir, so an edit that should have changed behaviour yields a green run
/// against the previous build.
///
/// The source set is rustc's own dep-info file, written beside the artifact by
/// the same invocation that produced it. That covers every crate compiled into
/// the image — including the ABI crates the cross-binary tests exercise on the
/// producer side — rather than just the fixture crate's own directory, and it
/// cannot drift the way a hand-maintained list of sibling crates would.
///
/// A dep-info file that is itself stale still names every source of the build
/// that produced the artifact, so an edit to any of them is caught; only a
/// source added since that build is invisible, which is the same blind spot the
/// artifact already has.
///
/// CI is not exposed: every path reaches these tests through `make test-ci`,
/// whose `cargo test --workspace` rebuilds the cdylib as a workspace member.
/// This is a local-developer tripwire.
///
/// Comparing mtimes is sound here. A fresh checkout writes source mtimes before
/// the build, and `Swatinem/rust-cache` strips workspace-member artifacts before
/// saving, so a restored artifact cannot predate a restored source tree.
/// Anything unreadable is skipped rather than failed, so a missing dep-info file
/// or source leaves the existing skip/require decision alone instead of becoming
/// a new failure.
fn assert_plugin_so_is_fresh(stem: &str, so: &Path) {
    let Ok(built) = so.metadata().and_then(|meta| meta.modified()) else {
        return;
    };
    // `libfoo.so` -> `libfoo.d`, beside it in the profile dir.
    let Ok(dep_info) = std::fs::read_to_string(so.with_extension("d")) else {
        return;
    };

    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for line in dep_info.lines() {
        // Dep-info is Makefile-shaped: `<target>: <prerequisite> ...`. Only the
        // right-hand side is a source — the target names a build output (the
        // sibling `.rlib`) whose mtime races the artifact's and would otherwise
        // report itself as newer. Split on the first colon-space, which a
        // Windows drive prefix (`C:\...`) does not contain. A line with no
        // prerequisites is a phony target entry and carries nothing.
        let Some((_target, prerequisites)) = line.split_once(": ") else {
            continue;
        };
        for token in prerequisites.split_ascii_whitespace() {
            // A path containing whitespace splits here and simply fails to
            // stat, which is the same outcome as skipping it.
            let candidate = Path::new(token);
            let Ok(meta) = candidate.metadata() else {
                continue;
            };
            if meta.is_dir() {
                continue;
            }
            let Ok(modified) = meta.modified() else {
                continue;
            };
            if newest.as_ref().is_none_or(|(seen, _)| modified > *seen) {
                newest = Some((modified, candidate.to_path_buf()));
            }
        }
    }

    let Some((modified, source)) = newest else {
        return;
    };
    let package = stem.replace('_', "-");
    assert!(
        built >= modified,
        "stale test cdylib: {} was built before {} was last edited, so this test would run \
         against the previous build of `{package}` and could pass for the wrong reason. \
         Rebuild it first: `cargo build -p {package}` (or `make test` / `make test-ci`, \
         which stage every test plugin).",
        so.display(),
        source.display(),
    );
}
