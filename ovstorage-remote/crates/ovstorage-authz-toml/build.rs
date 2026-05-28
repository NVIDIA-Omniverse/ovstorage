// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exports the cdylib path as `OVSTORAGE_AUTHZ_PLUGIN_TOML_SO` for `dlopen` tests.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let profile_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("OUT_DIR is not the expected depth under target/<profile>")
        .to_path_buf();

    let so_name = if cfg!(target_os = "linux") {
        "libovstorage_authz_toml.so"
    } else if cfg!(target_os = "macos") {
        "libovstorage_authz_toml.dylib"
    } else if cfg!(target_os = "windows") {
        "ovstorage_authz_toml.dll"
    } else {
        panic!("unsupported target_os for the authz-toml plugin dlopen test");
    };

    // `cargo test` builds the cdylib in target/<profile>/deps rather than
    // target/<profile>; the dlopen integration tests run under `cargo test`.
    let so_path = profile_dir.join("deps").join(so_name);
    println!(
        "cargo:rustc-env=OVSTORAGE_AUTHZ_PLUGIN_TOML_SO={}",
        so_path.display()
    );
}
