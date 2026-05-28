// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generates `include/ovstorage_plugin.h` from the `ffi` module.
//!
//! The header is checked in alongside the source so reviewers and IDE
//! consumers see the C surface without running cargo, but the source of
//! truth is the Rust definitions in `src/ffi.rs`. This build script
//! re-derives the header on every build and only rewrites the file when
//! the bytes differ — that keeps Cargo's incremental rebuild logic
//! happy and stops a no-op build from churning the working tree.
//!
//! Setting `OVSTORAGE_PLUGIN_ABI_SKIP_CBINDGEN=1` short-circuits the
//! generation step. Useful in environments without filesystem write
//! access, in `cargo doc` runs that don't need an updated header, and
//! in conformance test sandboxes that pre-stage the header.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/ffi");
    println!("cargo:rerun-if-changed=src/types.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_PLUGIN_ABI_SKIP_CBINDGEN");

    if env::var_os("OVSTORAGE_PLUGIN_ABI_SKIP_CBINDGEN").is_some() {
        return;
    }

    let crate_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let header_path = crate_dir.join("include").join("ovstorage_plugin.h");

    let config =
        cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).expect("read cbindgen.toml");

    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => bindings,
        Err(error) => {
            // Hard-fail on cbindgen errors so ABI drift is caught at
            // build time rather than masked as a warning. Set
            // `OVSTORAGE_PLUGIN_ABI_SKIP_CBINDGEN=1` to bypass in
            // sandbox or `cargo doc` environments where header writes
            // aren't desired.
            panic!("ovstorage-plugin: cbindgen generate failed: {error}");
        }
    };

    let mut new_header = Vec::new();
    bindings.write(&mut new_header);

    if let Some(parent) = header_path.parent()
        && !parent.exists()
        && let Err(error) = fs::create_dir_all(parent)
    {
        println!(
            "cargo:warning=ovstorage-plugin: could not create {}: {error}",
            parent.display()
        );
        return;
    }

    let unchanged = fs::read(&header_path)
        .map(|existing| existing == new_header)
        .unwrap_or(false);
    if unchanged {
        return;
    }

    if let Err(error) = fs::write(&header_path, &new_header) {
        println!(
            "cargo:warning=ovstorage-plugin: could not write {}: {error}",
            header_path.display()
        );
    }
}
