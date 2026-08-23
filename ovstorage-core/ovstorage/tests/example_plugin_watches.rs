// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The example plugin cdylib is produced by a NESTED cargo invocation from
//! this crate's build script, so cargo has no dependency edge from the
//! cdylib to the SDK sources it is compiled against. The only staleness
//! gate is the build script's own `cargo:rerun-if-changed` set: a source
//! file missing from it can change without the cdylib being rebuilt, and
//! `tests/dlopen_plugin.rs` then loads an artifact built against different
//! definitions than the host it is loaded into.
//!
//! `OVSTORAGE_PLUGIN_ABI_V2_VERSION` — the constant the host compares a
//! loaded manifest against — lives in `ovstorage-plugin/src/ffi/v2/mod.rs`,
//! which is exactly the kind of file a hand-maintained watch list drops.
//!
//! These tests derive the example plugin's compile closure from `cargo
//! metadata` — the path dependencies of `ovstorage-example-plugin-rust`,
//! transitively — and require every crate in it to be watched wholesale.
//! Deriving rather than restating the build script's set is what lets a
//! crate that joins the closure fail here instead of escaping both sides:
//! neither a single file nor a whole crate can fall out.
//!
//! They are skipped only where the sibling source trees are intentionally
//! absent (docs.rs, a published/packaged `ovstorage` crate), which the
//! build script reports through `OVSTORAGE_EXAMPLE_PLUGIN_SOURCE_TREES`.
//! A partial or moved workspace layout still fails.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether the sibling crate sources the example plugin compiles against
/// exist in this layout at all.
fn source_trees_available() -> bool {
    env!("OVSTORAGE_EXAMPLE_PLUGIN_SOURCE_TREES") == "present"
}

/// Absolute paths the build script emitted `cargo:rerun-if-changed` for.
fn watched() -> BTreeSet<PathBuf> {
    let manifest = env!("OVSTORAGE_EXAMPLE_PLUGIN_WATCHED_SOURCES");
    std::fs::read_to_string(manifest)
        .unwrap_or_else(|err| panic!("read watched-source manifest {manifest}: {err}"))
        .lines()
        .map(PathBuf::from)
        .collect()
}

fn core_group_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the ovstorage crate is one level under its product-group dir")
        .to_path_buf()
}

fn example_plugin_manifest() -> PathBuf {
    core_group_dir()
        .join("examples")
        .join("plugin-rust")
        .join("Cargo.toml")
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

/// The crate directories the example plugin's cdylib is compiled from:
/// its transitive path dependencies plus the example crate itself.
///
/// Derived through `cargo metadata` rather than through the build
/// script's own manifest walk, so a crate the build script fails to
/// discover is still asserted on here.
fn compile_closure() -> Vec<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest = example_plugin_manifest();
    // `--no-deps` keeps this offline and registry-independent: declared
    // dependency tables are reported without resolving the graph, and
    // every path dependency of interest is a workspace member.
    let output = Command::new(&cargo)
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("run cargo metadata for {}: {err}", manifest.display()));
    assert!(
        output.status.success(),
        "cargo metadata for {} failed: {}",
        manifest.display(),
        String::from_utf8_lossy(&output.stderr),
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata emits JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata reports a packages array");

    let package_at = |dir: &Path| -> Option<&serde_json::Value> {
        let manifest_path = dir.join("Cargo.toml");
        packages.iter().find(|package| {
            Path::new(package["manifest_path"].as_str().unwrap_or_default()) == manifest_path
        })
    };
    let root = package_at(&core_group_dir().join("examples").join("plugin-rust"))
        .expect("cargo metadata reports the example plugin package");

    let mut queue = vec![root];
    let mut crate_dirs = BTreeSet::new();
    while let Some(package) = queue.pop() {
        let dir = Path::new(package["manifest_path"].as_str().unwrap_or_default())
            .parent()
            .expect("a manifest path has a parent")
            .to_path_buf();
        if !crate_dirs.insert(dir) {
            continue;
        }
        for dependency in package["dependencies"].as_array().into_iter().flatten() {
            // Dev dependencies are not compiled into the cdylib; normal
            // and build dependencies are.
            if dependency["kind"].as_str() == Some("dev") {
                continue;
            }
            let Some(path) = dependency["path"].as_str() else {
                continue;
            };
            let path = PathBuf::from(path);
            match package_at(&path) {
                // A path dependency outside this workspace has no entry
                // to recurse into, but is still part of the closure.
                None => {
                    crate_dirs.insert(path);
                }
                Some(package) => queue.push(package),
            }
        }
    }
    crate_dirs.into_iter().collect()
}

#[test]
fn the_plugin_abi_version_constant_is_watched() {
    if !source_trees_available() {
        eprintln!("skipping: this layout has no sibling plugin source trees");
        return;
    }
    let abi_version_source = core_group_dir()
        .join("ovstorage-plugin")
        .join("src")
        .join("ffi")
        .join("v2")
        .join("mod.rs");
    assert!(
        abi_version_source.is_file(),
        "expected the Layer ABI version constant's module at {}",
        abi_version_source.display(),
    );
    assert!(
        watched().contains(&abi_version_source),
        "{} defines OVSTORAGE_PLUGIN_ABI_V2_VERSION but the example-plugin build \
         script does not watch it, so bumping the ABI version leaves the cdylib \
         stale and dlopen_plugin loads a plugin built against the previous version",
        abi_version_source.display(),
    );
}

#[test]
fn every_source_the_example_plugin_compiles_against_is_watched() {
    if !source_trees_available() {
        eprintln!("skipping: this layout has no sibling plugin source trees");
        return;
    }
    let closure = compile_closure();
    assert!(
        closure.len() > 1,
        "the example plugin's derived compile closure is {closure:#?}, which omits \
         its path dependencies — the derivation broke and this test would only \
         assert on the example crate itself",
    );

    let watched = watched();
    let mut missing = Vec::new();
    for crate_dir in &closure {
        let sources = rust_sources(&crate_dir.join("src"));
        assert!(
            !sources.is_empty(),
            "no Rust sources under {}/src — the crate layout moved and this test \
             would silently pass",
            crate_dir.display(),
        );
        for source in sources {
            if !watched.contains(&source) {
                missing.push(source);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "the example-plugin build script does not watch {} source file(s) it \
         compiles against, so editing them leaves the cdylib stale: {missing:#?}",
        missing.len(),
    );
}
