// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exports the cdylib path as `OVSTORAGE_PLUGIN_FILE_SO` for `tests/loaded.rs` to `dlopen`.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");

    // OUT_DIR = <target>/<profile>/build/<crate-id>/out; three parents up = <target>/<profile>.
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let profile_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("OUT_DIR is not the expected depth under target/<profile>")
        .to_path_buf();

    let so_name = if cfg!(target_os = "linux") {
        "libovstorage_plugin_file.so"
    } else if cfg!(target_os = "macos") {
        "libovstorage_plugin_file.dylib"
    } else if cfg!(target_os = "windows") {
        "ovstorage_plugin_file.dll"
    } else {
        panic!("unsupported target_os for the file-plugin dlopen test");
    };

    let so_path = profile_dir.join(so_name);
    println!(
        "cargo:rustc-env=OVSTORAGE_PLUGIN_FILE_SO={}",
        so_path.display()
    );
}
