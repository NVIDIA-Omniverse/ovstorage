// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builds the example Rust plugin into a private target directory so
//! `tests/dlopen_plugin.rs` can `dlopen` it without depending on the
//! caller running `cargo build --workspace`. The path of the produced
//! cdylib artifact is exposed to the test crate as
//! `OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO`.
//!
//! Skipped under `DOCS_RS`. Uses a private `--target-dir` under the
//! workspace `target/` so nested cargo avoids the outer build locks
//! without inheriting `OUT_DIR`'s deeply nested path.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../examples/plugin-rust/src/lib.rs");
    println!("cargo:rerun-if-changed=../../examples/plugin-rust/Cargo.toml");
    // The example cdylib's manifest embeds `PluginKind::BACKEND`'s
    // current value via the proc-macro; rerun when the upstream SPI
    // mod or the macro changes so the cdylib doesn't go stale on a
    // discriminant flip.
    println!("cargo:rerun-if-changed=../ovstorage-plugin/src/ffi/mod.rs");
    println!("cargo:rerun-if-changed=../ovstorage-plugin-macros/src/lib.rs");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE");

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

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("ovstorage crate is two levels under the workspace root")
        .to_path_buf();
    let example_manifest = workspace_root
        .join("examples")
        .join("plugin-rust")
        .join("Cargo.toml");

    let nested_target_dir = workspace_root
        .join("target")
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
