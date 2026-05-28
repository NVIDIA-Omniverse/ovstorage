// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds `ovstorage-plugin-file` as a cdylib into a per-`OUT_DIR`
//! fixture directory and exports the path as
//! `OVSTORAGE_REST_TEST_PLUGIN_DIR`. REST's integration tests dlopen
//! the file plugin to exercise the gateway against a real backend
//! without requiring it as an rlib (which would collide with other
//! plugins' `#[no_mangle]` macro symbols).
//! Private Cargo target dirs live under workspace `target/` so Windows
//! link paths do not inherit `OUT_DIR`'s deeply nested build-script path.
//!
//! Honors `OVSTORAGE_REST_TEST_PLUGIN_DIR_OVERRIDE` for environments
//! that pre-build the artifact and want to skip the nested cargo
//! invocation. Skipped under `DOCS_RS`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_REST_TEST_PLUGIN_DIR_OVERRIDE");

    if env::var_os("DOCS_RS").is_some() {
        println!("cargo:rustc-env=OVSTORAGE_REST_TEST_PLUGIN_DIR=__skip_docs_rs__");
        return;
    }

    if let Some(path) = env::var_os("OVSTORAGE_REST_TEST_PLUGIN_DIR_OVERRIDE") {
        println!(
            "cargo:rustc-env=OVSTORAGE_REST_TEST_PLUGIN_DIR={}",
            path.to_string_lossy()
        );
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let remote_workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("ovstorage-rest is two levels under the workspace root")
        .to_path_buf();
    let core_workspace_root = remote_workspace_root
        .parent()
        .expect("ovstorage-remote workspace has a parent dir")
        .join("ovstorage-core");

    // Watch transitive sources: cargo only auto-tracks this crate, so
    // edits to dlopen'd plugin sources won't otherwise rebuild the fixture.
    for crate_dir in [
        core_workspace_root.join("crates").join("ovstorage-plugin"),
        core_workspace_root
            .join("crates")
            .join("ovstorage-plugin-file"),
        core_workspace_root
            .join("crates")
            .join("ovstorage-plugin-test"),
    ] {
        watch_crate_sources(&crate_dir);
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let fixture_dir = out_dir.join("test-plugins");
    if fixture_dir.exists() {
        fs::remove_dir_all(&fixture_dir).expect("clear test-plugins fixture dir");
    }
    fs::create_dir_all(&fixture_dir).expect("create test-plugins fixture dir");

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for (subdir, stem) in [
        ("ovstorage-plugin-file", "ovstorage_plugin_file"),
        ("ovstorage-plugin-test", "ovstorage_plugin_test"),
    ] {
        let manifest = core_workspace_root
            .join("crates")
            .join(subdir)
            .join("Cargo.toml");
        build_plugin(
            &cargo,
            &manifest,
            &nested_target_dir(&remote_workspace_root, stem),
            stem,
            &fixture_dir,
        );
    }

    println!(
        "cargo:rustc-env=OVSTORAGE_REST_TEST_PLUGIN_DIR={}",
        fixture_dir.display()
    );
}

fn nested_target_dir(workspace_root: &Path, name: &str) -> PathBuf {
    workspace_root
        .join("target")
        .join("plugin-build")
        .join(name)
}

/// Emit `cargo:rerun-if-changed` for every file under a crate's `src/`,
/// `proto/`, `build.rs`, and `Cargo.toml`.
fn watch_crate_sources(crate_dir: &Path) {
    for child in ["Cargo.toml", "build.rs"] {
        let path = crate_dir.join(child);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    for subdir in ["src", "proto"] {
        watch_recursive(&crate_dir.join(subdir));
    }
}

fn watch_recursive(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            watch_recursive(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn build_plugin(
    cargo: &std::ffi::OsStr,
    manifest: &Path,
    target_dir: &Path,
    artifact_stem: &str,
    fixture_dir: &Path,
) {
    let status = Command::new(cargo)
        .arg("build")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .status()
        .unwrap_or_else(|err| panic!("invoke cargo for {}: {err}", manifest.display()));
    if !status.success() {
        panic!("cargo build failed for {}", manifest.display());
    }

    let so_name = if cfg!(target_os = "linux") {
        format!("lib{artifact_stem}.so")
    } else if cfg!(target_os = "macos") {
        format!("lib{artifact_stem}.dylib")
    } else if cfg!(target_os = "windows") {
        format!("{artifact_stem}.dll")
    } else {
        panic!("unsupported target_os for the REST dlopen tests");
    };

    let src = target_dir.join("debug").join(&so_name);
    if !src.exists() {
        panic!("expected cdylib at {} after build", src.display());
    }
    let dest = fixture_dir.join(&so_name);
    fs::copy(&src, &dest)
        .unwrap_or_else(|err| panic!("copy {} → {}: {err}", src.display(), dest.display()));
}
