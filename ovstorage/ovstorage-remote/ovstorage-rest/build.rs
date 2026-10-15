// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the public utility plugins plus `ovstorage-plugin-test-abi` (the
//! conformance backend's ABI-v2 cdylib export) and
//! `ovstorage-plugin-test-layer` (the auth-capable wrapper fixture) into a
//! per-`OUT_DIR` fixture directory and exports the path as
//! `OVSTORAGE_REST_TEST_PLUGIN_DIR`. REST's
//! integration tests dlopen the same core and HTTP providers required by the
//! shipped graph. The test backend export lives in the `-abi` sibling crate
//! precisely so the harness rlib carries no `#[no_mangle]` macro symbols that
//! would collide with other plugins'. The `file` backend is the host's sole
//! native backend, so no `file` cdylib is built here.
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
    let remote_group_dir = manifest_dir
        .parent()
        .expect("ovstorage-rest crate is one level under its product-group dir")
        .to_path_buf();
    let repo_root = remote_group_dir
        .parent()
        .expect("ovstorage-remote group dir is one level under the repo root")
        .to_path_buf();
    let core_group_dir = repo_root.join("ovstorage-core");
    let plugin_test_layer_crate = core_group_dir.join("ovstorage-plugin-test-layer");

    // Watch transitive sources: cargo only auto-tracks this crate, so
    // edits to dlopen'd plugin sources won't otherwise rebuild the fixture.
    for crate_dir in [
        core_group_dir.join("ovstorage-plugin"),
        core_group_dir.join("ovstorage-plugin-core"),
        core_group_dir.join("ovstorage-plugin-core-abi"),
        core_group_dir.join("ovstorage-plugin-http"),
        core_group_dir.join("ovstorage-plugin-http-abi"),
        core_group_dir.join("ovstorage-plugin-test"),
        core_group_dir.join("ovstorage-plugin-test-abi"),
        plugin_test_layer_crate.clone(),
        remote_group_dir.join("ovstorage-authz-context"),
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
    let target_dir = nested_target_dir(&out_dir, &repo_root, "rest-test");
    for (crate_name, stem) in [
        ("ovstorage-plugin-core-abi", "ovstorage_plugin_core"),
        ("ovstorage-plugin-http-abi", "ovstorage_plugin_http"),
        ("ovstorage-plugin-test-abi", "ovstorage_plugin_test_abi"),
    ] {
        let manifest = core_group_dir.join(crate_name).join("Cargo.toml");
        build_plugin(&cargo, &manifest, &target_dir, stem, &fixture_dir);
    }
    build_plugin(
        &cargo,
        &plugin_test_layer_crate.join("Cargo.toml"),
        &nested_target_dir(&out_dir, &repo_root, "rest-test-layer"),
        "ovstorage_plugin_test_layer",
        &fixture_dir,
    );

    println!(
        "cargo:rustc-env=OVSTORAGE_REST_TEST_PLUGIN_DIR={}",
        fixture_dir.display()
    );
}

// Anchored at the outer build's resolved target dir so `cargo clean`
// removes the nested build output too. OUT_DIR is an absolute path
// inside that target dir no matter how it was configured
// (CARGO_TARGET_DIR — absolute or relative — config, or flag), and
// cargo marks the target root with CACHEDIR.TAG.
fn nested_target_dir(out_dir: &Path, repo_root: &Path, name: &str) -> PathBuf {
    out_dir
        .ancestors()
        .find(|dir| dir.join("CACHEDIR.TAG").is_file())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| repo_root.join("target"))
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
