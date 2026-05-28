// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generates `include/ovstorage_authz_plugin.h` from the `ffi` module.
//! Only rewrites when bytes differ so a no-op build doesn't churn the
//! tree. `OVSTORAGE_AUTHZ_PLUGIN_ABI_SKIP_CBINDGEN=1` short-circuits.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/ffi.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-env-changed=OVSTORAGE_AUTHZ_PLUGIN_ABI_SKIP_CBINDGEN");

    if env::var_os("OVSTORAGE_AUTHZ_PLUGIN_ABI_SKIP_CBINDGEN").is_some() {
        return;
    }

    let crate_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let header_path = crate_dir.join("include").join("ovstorage_authz_plugin.h");

    let config =
        cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).expect("read cbindgen.toml");

    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => bindings,
        Err(error) => {
            println!("cargo:warning=ovstorage-authz: cbindgen generate failed: {error}");
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
            "cargo:warning=ovstorage-authz: could not create {}: {error}",
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
            "cargo:warning=ovstorage-authz: could not write {}: {error}",
            header_path.display()
        );
    }
}
