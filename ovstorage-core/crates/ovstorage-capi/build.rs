// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generates `include/ovstorage.h` from the public C ABI declarations.
//!
//! The header is checked in alongside the source so reviewers and IDE
//! consumers see the C surface without running cargo. The source of
//! truth is the Rust FFI definitions under `src/ffi/`. The script only
//! rewrites the header when bytes differ, so no-op builds don't churn
//! the working tree.
//!
//! `OVSTORAGE_CAPI_SKIP_CBINDGEN=1` short-circuits generation (useful
//! for read-only filesystems, `cargo doc`, and pre-staged test sandboxes).

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/ffi/mod.rs");
    println!("cargo:rerun-if-changed=src/ffi/ops.rs");
    println!("cargo:rerun-if-changed=src/ffi/builders.rs");
    println!("cargo:rerun-if-changed=src/ffi/connection.rs");
    println!("cargo:rerun-if-changed=src/ffi/aliases.rs");
    println!("cargo:rerun-if-changed=src/ffi/discovery.rs");
    println!("cargo:rerun-if-changed=src/ffi/auth.rs");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_CAPI_SKIP_CBINDGEN");

    // Integration tests dlopen the cdylib through `OVSTORAGE_CAPI_SO`.
    // Resolve `target/<profile>/lib<name>.{so,dll,dylib}` by walking up
    // from `OUT_DIR` (which lives under `target/<profile>/build/<...>/out/`).
    println!("cargo:rerun-if-env-changed=PROFILE");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let profile_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("OUT_DIR is not the expected depth under target/<profile>")
        .to_path_buf();
    let so_name = if cfg!(target_os = "linux") {
        "libovstorage.so"
    } else if cfg!(target_os = "macos") {
        "libovstorage.dylib"
    } else if cfg!(target_os = "windows") {
        "ovstorage.dll"
    } else {
        panic!("unsupported target_os for the capi dlopen tests");
    };
    let so_path = profile_dir.join(so_name);
    println!("cargo:rustc-env=OVSTORAGE_CAPI_SO={}", so_path.display());

    if env::var_os("OVSTORAGE_CAPI_SKIP_CBINDGEN").is_some() {
        return;
    }

    let crate_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let header_path = crate_dir.join("include").join("ovstorage.h");

    let config =
        cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).expect("read cbindgen.toml");

    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => bindings,
        Err(error) => {
            // Skip on cbindgen errors (macro-generated items it can't resolve);
            // the checked-in header is still valid for downstream consumers.
            println!("cargo:warning=ovstorage-capi: cbindgen generate failed: {error}");
            return;
        }
    };

    let mut new_header = Vec::new();
    bindings.write(&mut new_header);

    if let Some(parent) = header_path.parent()
        && !parent.exists()
        && let Err(error) = fs::create_dir_all(parent)
    {
        println!(
            "cargo:warning=ovstorage-capi: could not create {}: {error}",
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
            "cargo:warning=ovstorage-capi: could not write {}: {error}",
            header_path.display()
        );
    }
}
