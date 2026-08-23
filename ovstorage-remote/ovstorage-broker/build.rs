// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the cdylib plugins the broker integration tests load
//! (`ovstorage-plugin-broker` plus the public core, cache, and HTTP Layer
//! bundles) into a single fixture directory and exports its path as
//! `OVSTORAGE_BROKER_TEST_PLUGIN_DIR`. The `file` backend is served
//! natively (in-Stack), so no `file` cdylib is bundled.
//!
//! Building the plugins in private nested target dirs (under the
//! repo-root workspace `target/`, so `cargo clean` removes them)
//! avoids contending with the outer build's lock files while keeping
//! Windows paths short.
//!
//! Skipped under `DOCS_RS`. Honors
//! `OVSTORAGE_BROKER_TEST_PLUGIN_DIR_OVERRIDE` for environments that
//! pre-build the artifacts and want to skip the nested cargo invocation.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_BROKER_TEST_PLUGIN_DIR_OVERRIDE");

    if env::var_os("DOCS_RS").is_some() {
        println!("cargo:rustc-env=OVSTORAGE_BROKER_TEST_PLUGIN_DIR=__skip_docs_rs__");
        return;
    }

    if let Some(path) = env::var_os("OVSTORAGE_BROKER_TEST_PLUGIN_DIR_OVERRIDE") {
        println!(
            "cargo:rustc-env=OVSTORAGE_BROKER_TEST_PLUGIN_DIR={}",
            path.to_string_lossy()
        );
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let remote_group_dir = manifest_dir
        .parent()
        .expect("ovstorage-broker crate is one level under its product-group dir")
        .to_path_buf();
    let repo_root = remote_group_dir
        .parent()
        .expect("ovstorage-remote group dir is one level under the repo root")
        .to_path_buf();
    let core_group_dir = repo_root.join("ovstorage-core");

    // Cargo only auto-tracks the broker's own crate dir; without these,
    // edits to dlopen'd plugin sources won't trigger a fixture rebuild.
    let plugin_sdk_crate = core_group_dir.join("ovstorage-plugin");
    let plugin_core_crate = core_group_dir.join("ovstorage-plugin-core");
    let plugin_core_abi_crate = core_group_dir.join("ovstorage-plugin-core-abi");
    let plugin_cache_crate = core_group_dir.join("ovstorage-plugin-cache");
    let plugin_cache_abi_crate = core_group_dir.join("ovstorage-plugin-cache-abi");
    let plugin_http_crate = core_group_dir.join("ovstorage-plugin-http");
    let plugin_http_abi_crate = core_group_dir.join("ovstorage-plugin-http-abi");
    let broker_protocol_crate = remote_group_dir.join("ovstorage-broker-protocol");
    let plugin_broker_crate = remote_group_dir.join("ovstorage-plugin-broker");
    // The test backend's behavior lives in ovstorage-plugin-test; its
    // ABI-v2 cdylib export is the -abi sibling. Watch both.
    let plugin_test_crate = core_group_dir.join("ovstorage-plugin-test");
    let plugin_test_abi_crate = core_group_dir.join("ovstorage-plugin-test-abi");
    let plugin_test_layer_crate = core_group_dir.join("ovstorage-plugin-test-layer");
    for crate_dir in [
        &plugin_sdk_crate,
        &plugin_core_crate,
        &plugin_core_abi_crate,
        &plugin_cache_crate,
        &plugin_cache_abi_crate,
        &plugin_http_crate,
        &plugin_http_abi_crate,
        &broker_protocol_crate,
        &plugin_broker_crate,
        &plugin_test_crate,
        &plugin_test_abi_crate,
        &plugin_test_layer_crate,
    ] {
        watch_crate_sources(crate_dir);
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let fixture_dir = out_dir.join("test-plugins");
    if fixture_dir.exists() {
        fs::remove_dir_all(&fixture_dir).expect("clear test-plugins fixture dir");
    }
    fs::create_dir_all(&fixture_dir).expect("create test-plugins fixture dir");

    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    build_plugin(
        &cargo,
        &plugin_broker_crate.join("Cargo.toml"),
        &nested_target_dir(&out_dir, &repo_root, "broker-plugin"),
        "ovstorage_plugin_broker",
        &fixture_dir,
    );
    build_plugin(
        &cargo,
        &plugin_test_abi_crate.join("Cargo.toml"),
        &nested_target_dir(&out_dir, &repo_root, "broker-test"),
        "ovstorage_plugin_test_abi",
        &fixture_dir,
    );
    for (plugin, stem) in [
        (&plugin_core_abi_crate, "ovstorage_plugin_core"),
        (&plugin_cache_abi_crate, "ovstorage_plugin_cache"),
        (&plugin_http_abi_crate, "ovstorage_plugin_http"),
    ] {
        build_plugin(
            &cargo,
            &plugin.join("Cargo.toml"),
            &nested_target_dir(&out_dir, &repo_root, stem),
            stem,
            &fixture_dir,
        );
    }
    build_plugin(
        &cargo,
        &plugin_test_layer_crate.join("Cargo.toml"),
        &nested_target_dir(&out_dir, &repo_root, "broker-test-layer"),
        "ovstorage_plugin_test_layer",
        &fixture_dir,
    );

    println!(
        "cargo:rustc-env=OVSTORAGE_BROKER_TEST_PLUGIN_DIR={}",
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

    let (so_name, dest_name) = if cfg!(target_os = "linux") {
        (
            format!("lib{artifact_stem}.so"),
            format!("lib{artifact_stem}.so"),
        )
    } else if cfg!(target_os = "macos") {
        (
            format!("lib{artifact_stem}.dylib"),
            format!("lib{artifact_stem}.dylib"),
        )
    } else if cfg!(target_os = "windows") {
        (
            format!("{artifact_stem}.dll"),
            format!("{artifact_stem}.dll"),
        )
    } else {
        panic!("unsupported target_os for the broker dlopen tests");
    };

    let src = target_dir.join("debug").join(&so_name);
    if !src.exists() {
        panic!("expected cdylib at {} after build", src.display());
    }
    let dest = fixture_dir.join(&dest_name);
    fs::copy(&src, &dest)
        .unwrap_or_else(|err| panic!("copy {} → {}: {err}", src.display(), dest.display()));
}
