// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the cdylib plugins the broker integration tests dlopen
//! (`ovstorage-plugin-file` from the core workspace,
//! `ovstorage-plugin-broker` from this workspace) into a single
//! fixture directory and exports its path as
//! `OVSTORAGE_BROKER_TEST_PLUGIN_DIR`.
//!
//! After the workspace split, neither crate is a workspace member of
//! ovstorage-broker; cargo therefore won't auto-produce their cdylib
//! outputs in the broker's `target/<profile>/`. Building them in
//! private nested target dirs avoids contending with the outer build's
//! lock files while keeping Windows paths short.
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
    let remote_workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("ovstorage-broker crate is two levels under the workspace root")
        .to_path_buf();
    let core_workspace_root = remote_workspace_root
        .parent()
        .expect("ovstorage-remote workspace has a parent dir")
        .join("ovstorage-core");

    // Cargo only auto-tracks the broker's own crate dir; without these,
    // edits to dlopen'd plugin sources won't trigger a fixture rebuild.
    let plugin_sdk_crate = core_workspace_root.join("crates").join("ovstorage-plugin");
    let broker_protocol_crate = remote_workspace_root
        .join("crates")
        .join("ovstorage-broker-protocol");
    let plugin_file_crate = core_workspace_root
        .join("crates")
        .join("ovstorage-plugin-file");
    let plugin_broker_crate = remote_workspace_root
        .join("crates")
        .join("ovstorage-plugin-broker");
    let plugin_test_crate = core_workspace_root
        .join("crates")
        .join("ovstorage-plugin-test");
    let plugin_authz_toml_crate = remote_workspace_root
        .join("crates")
        .join("ovstorage-authz-toml");
    for crate_dir in [
        &plugin_sdk_crate,
        &broker_protocol_crate,
        &plugin_file_crate,
        &plugin_broker_crate,
        &plugin_test_crate,
        &plugin_authz_toml_crate,
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
        &plugin_file_crate.join("Cargo.toml"),
        &nested_target_dir(&remote_workspace_root, "broker-file"),
        "ovstorage_plugin_file",
        &fixture_dir,
    );
    build_plugin(
        &cargo,
        &plugin_broker_crate.join("Cargo.toml"),
        &nested_target_dir(&remote_workspace_root, "broker-plugin"),
        "ovstorage_plugin_broker",
        &fixture_dir,
    );
    build_plugin(
        &cargo,
        &plugin_test_crate.join("Cargo.toml"),
        &nested_target_dir(&remote_workspace_root, "broker-test"),
        "ovstorage_plugin_test",
        &fixture_dir,
    );
    // Dir scanner accepts both `libovstorage_plugin_*` (backend) and
    // `libovstorage_authz_*` (authz) prefixes; manifest's `plugin_kind`
    // disambiguates.
    build_plugin(
        &cargo,
        &plugin_authz_toml_crate.join("Cargo.toml"),
        &nested_target_dir(&remote_workspace_root, "broker-authz"),
        "ovstorage_authz_toml",
        &fixture_dir,
    );

    println!(
        "cargo:rustc-env=OVSTORAGE_BROKER_TEST_PLUGIN_DIR={}",
        fixture_dir.display()
    );
}

fn nested_target_dir(workspace_root: &Path, name: &str) -> PathBuf {
    workspace_root
        .join("target")
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
