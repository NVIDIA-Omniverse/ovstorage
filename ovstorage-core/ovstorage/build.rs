// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the example Rust plugin into a private target directory so
//! `tests/dlopen_plugin.rs` can `dlopen` it without depending on the
//! caller running `cargo build --workspace`. The path of the produced
//! cdylib artifact is exposed to the test crate as
//! `OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO`.
//!
//! Cargo tracks no dependency edge from that cdylib to the SDK sources it
//! compiles against — the nested cargo run is opaque to the outer build —
//! so this script's own `cargo:rerun-if-changed` set is the artifact's only
//! staleness gate. The watched set is derived from the example plugin's
//! path-dependency closure — whole source trees, no hand-picked crate
//! list — and recorded under `OUT_DIR` as
//! `OVSTORAGE_EXAMPLE_PLUGIN_WATCHED_SOURCES` for
//! `tests/example_plugin_watches.rs`.
//!
//! Skipped under `DOCS_RS`. Uses a private `--target-dir` under the
//! workspace `target/` so nested cargo avoids the outer build locks
//! without inheriting `OUT_DIR`'s deeply nested path.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE");

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let core_group_dir = manifest_dir
        .parent()
        .expect("ovstorage crate is one level under its product-group dir")
        .to_path_buf();
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    emit_source_watches(&core_group_dir, &out_dir);

    if env::var_os("DOCS_RS").is_some() {
        // docs.rs sandboxes the build; no nested cargo, no plugin .so.
        // Emit a sentinel so the test (if it runs) can branch.
        println!("cargo:rustc-env=OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO=__skip_docs_rs__");
        return;
    }

    if let Some(path) = env::var_os("OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE") {
        // Power-user escape hatch for environments where shelling out to
        // cargo isn't acceptable; the developer pre-builds the .so and
        // points us at it.
        println!(
            "cargo:rustc-env=OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO={}",
            path.to_string_lossy()
        );
        return;
    }

    let repo_root = core_group_dir
        .parent()
        .expect("ovstorage-core group dir is one level under the repo root");
    let example_manifest = core_group_dir
        .join("examples")
        .join("plugin-rust")
        .join("Cargo.toml");

    // Anchor at the outer build's resolved target dir so `cargo clean`
    // removes the nested build output too. OUT_DIR is an absolute path
    // inside that target dir no matter how it was configured
    // (CARGO_TARGET_DIR — absolute or relative — config, or flag), and
    // cargo marks the target root with CACHEDIR.TAG.
    let nested_target_dir = resolved_target_dir(&out_dir)
        .unwrap_or_else(|| repo_root.join("target"))
        .join("plugin-build")
        .join("example-rust");

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let status = Command::new(&cargo)
        .arg("build")
        .arg("--manifest-path")
        .arg(&example_manifest)
        .arg("--target-dir")
        .arg(&nested_target_dir)
        .status()
        .expect("failed to invoke cargo to build example plugin");

    if !status.success() {
        panic!(
            "cargo build for ovstorage-example-plugin-rust failed (manifest: {})",
            example_manifest.display()
        );
    }

    let so_name = if cfg!(target_os = "linux") {
        "libovstorage_plugin_example_rust.so"
    } else if cfg!(target_os = "macos") {
        "libovstorage_plugin_example_rust.dylib"
    } else if cfg!(target_os = "windows") {
        "ovstorage_plugin_example_rust.dll"
    } else {
        panic!("unsupported target_os for the dlopen integration test");
    };

    // Default cargo profile under `cargo build` is `debug`. The nested
    // build inherits no profile flag, so the artifact lives under
    // `debug/` regardless of the outer build's profile.
    let so_path = nested_target_dir.join("debug").join(so_name);
    if !so_path.exists() {
        panic!(
            "expected example plugin cdylib at {} after build",
            so_path.display()
        );
    }

    println!(
        "cargo:rustc-env=OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO={}",
        so_path.display()
    );
}

/// Emit `cargo:rerun-if-changed` for the sources the example plugin is
/// compiled against, and record the same set in `OUT_DIR` for
/// `tests/example_plugin_watches.rs`.
fn emit_source_watches(core_group_dir: &Path, out_dir: &Path) {
    // Derive the crate set from the example plugin's path-dependency
    // closure and watch each crate's sources WHOLESALE. A named list —
    // of files or of crates — stops covering the artifact as soon as a
    // definition moves to a new module or a new path dependency joins
    // the closure; the cdylib embeds the Layer ABI version, the SPI
    // vtable layouts, and the proc-macro's expansion, which are spread
    // across those trees.
    let example_manifest = core_group_dir
        .join("examples")
        .join("plugin-rust")
        .join("Cargo.toml");
    // Watch the closure's root manifest even when it is absent, so the
    // set is re-derived if the sibling trees appear.
    println!("cargo:rerun-if-changed={}", example_manifest.display());

    let crate_dirs = path_dependency_closure(&example_manifest);
    let mut watched = Vec::new();
    for crate_dir in &crate_dirs {
        let manifest = crate_dir.join("Cargo.toml");
        if manifest.is_file() {
            watched.push(manifest);
        }
        collect_recursive(&crate_dir.join("src"), &mut watched);
    }
    watched.sort();
    for path in &watched {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // An empty closure means the example plugin's manifest is absent:
    // docs.rs and published-crate layouts have no sibling source trees,
    // and the watch tests have nothing to assert against.
    println!(
        "cargo:rustc-env=OVSTORAGE_EXAMPLE_PLUGIN_SOURCE_TREES={}",
        if crate_dirs.is_empty() {
            "absent"
        } else {
            "present"
        }
    );

    let listing: Vec<String> = watched
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    let manifest = out_dir.join("example-plugin-watched-sources.txt");
    fs::write(&manifest, listing.join("\n")).expect("write watched-source manifest");
    println!(
        "cargo:rustc-env=OVSTORAGE_EXAMPLE_PLUGIN_WATCHED_SOURCES={}",
        manifest.display()
    );
}

/// Every crate directory reachable from `root_manifest` through path
/// dependencies, including the root crate itself. Empty when the root
/// manifest is absent.
///
/// The traversal is over declared manifests rather than `cargo metadata`
/// so it needs neither a subprocess nor cargo's package-cache lock while
/// the outer build holds it.
fn path_dependency_closure(root_manifest: &Path) -> Vec<PathBuf> {
    let workspace_paths = workspace_dependency_paths(root_manifest);
    let mut queue = vec![root_manifest.to_path_buf()];
    let mut seen = std::collections::BTreeSet::new();
    let mut crate_dirs = Vec::new();
    while let Some(manifest) = queue.pop() {
        if !manifest.is_file() {
            continue;
        }
        let Some(crate_dir) = manifest.parent().map(lexically_normalized) else {
            continue;
        };
        if !seen.insert(crate_dir.clone()) {
            continue;
        }
        for dependency in path_dependencies(&manifest, &workspace_paths) {
            queue.push(dependency.join("Cargo.toml"));
        }
        crate_dirs.push(crate_dir);
    }
    crate_dirs.sort();
    crate_dirs
}

/// Paths from every non-dev dependency table in `manifest`, including
/// dependencies inherited from the root workspace table. Dev dependencies
/// are excluded because they are not compiled into the cdylib.
fn path_dependencies(manifest: &Path, workspace_paths: &BTreeMap<String, PathBuf>) -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(manifest) else {
        return Vec::new();
    };
    let Some(crate_dir) = manifest.parent() else {
        return Vec::new();
    };
    let mut in_dependency_table = false;
    let mut detailed_dependency = None;
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.split(']').next().unwrap_or_default();
            in_dependency_table =
                header.contains("dependencies") && !header.contains("dev-dependencies");
            detailed_dependency = in_dependency_table
                .then(|| header.rsplit_once("dependencies.").map(|(_, name)| name))
                .flatten()
                .map(str::to_string);
            continue;
        }
        if in_dependency_table && !line.starts_with('#') {
            found.extend(
                quoted_path_values(line)
                    .into_iter()
                    .map(|path| lexically_normalized(&crate_dir.join(path))),
            );
            if line.contains("workspace = true") {
                let dependency = detailed_dependency
                    .as_deref()
                    .or_else(|| line.split_once('=').map(|(name, _)| name.trim()));
                if let Some(path) = dependency.and_then(|name| workspace_paths.get(name)) {
                    found.push(path.clone());
                }
            }
        }
    }
    found
}

/// Workspace dependency names to their local package directories.
fn workspace_dependency_paths(manifest: &Path) -> BTreeMap<String, PathBuf> {
    let workspace_manifest = manifest
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .map(|directory| directory.join("Cargo.toml"))
        .find(|candidate| {
            fs::read_to_string(candidate)
                .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
        });
    let Some(workspace_manifest) = workspace_manifest else {
        return BTreeMap::new();
    };
    let Some(workspace_dir) = workspace_manifest.parent() else {
        return BTreeMap::new();
    };
    let Ok(text) = fs::read_to_string(&workspace_manifest) else {
        return BTreeMap::new();
    };

    let mut in_workspace_dependencies = false;
    let mut detailed_dependency = None;
    let mut found = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.split(']').next().unwrap_or_default();
            in_workspace_dependencies =
                header == "workspace.dependencies" || header.starts_with("workspace.dependencies.");
            detailed_dependency = header
                .strip_prefix("workspace.dependencies.")
                .map(str::to_string);
            continue;
        }
        if !in_workspace_dependencies || line.starts_with('#') {
            continue;
        }
        let dependency = detailed_dependency
            .as_deref()
            .or_else(|| line.split_once('=').map(|(name, _)| name.trim()));
        let Some(dependency) = dependency else {
            continue;
        };
        if let Some(path) = quoted_path_values(line).into_iter().next() {
            found.insert(
                dependency.to_string(),
                lexically_normalized(&workspace_dir.join(path)),
            );
        }
    }
    found
}

/// The string values of every `path = "..."` key in one manifest line,
/// covering both inline-table and sub-table dependency spellings.
fn quoted_path_values(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(key) = rest.find("path") {
        rest = &rest[key + "path".len()..];
        let Some(after_eq) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        let Some(value) = after_eq.trim_start().strip_prefix('"') else {
            continue;
        };
        let Some(end) = value.find('"') else {
            break;
        };
        found.push(value[..end].to_string());
        rest = &value[end + 1..];
    }
    found
}

/// `path` with `.` and `..` components resolved textually. The closure
/// walk cannot use `canonicalize`, which requires the target to exist.
fn lexically_normalized(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Append every file under `dir`, recursively. A missing directory
/// contributes nothing: `docs.rs` and published-crate layouts have no
/// sibling source trees.
fn collect_recursive(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_recursive(&path, found);
        } else {
            found.push(path);
        }
    }
}

// The outer build's target dir: the OUT_DIR ancestor cargo marks with
// CACHEDIR.TAG.
fn resolved_target_dir(out_dir: &Path) -> Option<PathBuf> {
    out_dir
        .ancestors()
        .find(|dir| dir.join("CACHEDIR.TAG").is_file())
        .map(Path::to_path_buf)
}
