// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exports the plugin staging directory the harness dlopens from.
//!
//! `make build-test-plugins` (`tools/ovtasks/build_test_plugins.py`) already
//! builds and stages every plugin cdylib under `target/test-plugins/`, so this
//! build script only has to *name* that directory. It deliberately does not
//! invoke nested cargo: a second cargo tree is what exhausted hosted CI
//! runners, and staging owned by two places drifts.
//!
//! The value lands as the compile-time `OVSTORAGE_DEFAULT_PLUGIN_DIR`; at run
//! time `$OVSTORAGE_PLUGIN_DIR` still wins (see `plugin_dir` in `src/lib.rs`),
//! so `make test`'s environment and a bare `cargo test` agree without this
//! script knowing about either.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_INTEGRATION_PLUGIN_DIR_OVERRIDE");

    // docs.rs has no staged plugins and never runs the suite; emit a value that
    // cannot be mistaken for a real directory rather than a plausible path.
    if env::var_os("DOCS_RS").is_some() {
        println!("cargo:rustc-env=OVSTORAGE_DEFAULT_PLUGIN_DIR=__skip_docs_rs__");
        return;
    }

    // Escape hatch for a tree that stages elsewhere (a packaged install layout,
    // a bisect against an older staging dir). Empty is treated as unset so an
    // exported-but-blank variable does not silently point the loader at "".
    if let Some(dir) = env::var_os("OVSTORAGE_INTEGRATION_PLUGIN_DIR_OVERRIDE")
        && !dir.is_empty()
    {
        println!(
            "cargo:rustc-env=OVSTORAGE_DEFAULT_PLUGIN_DIR={}",
            PathBuf::from(dir).display()
        );
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("ovstorage-integration-tests lives one level under the workspace root");
    println!(
        "cargo:rustc-env=OVSTORAGE_DEFAULT_PLUGIN_DIR={}",
        workspace_root.join("target").join("test-plugins").display()
    );
}
