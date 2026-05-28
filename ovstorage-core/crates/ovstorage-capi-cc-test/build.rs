// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compiles the public C headers as both C and C++ to catch
//! cbindgen-emitted invalid syntax and missing symbols.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=tests/include_smoke.c");
    println!("cargo:rerun-if-changed=tests/include_smoke.cpp");
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    // The crate sits at ovstorage-core/crates/ovstorage-capi-cc-test;
    // climb three levels to reach the repo root, then descend into each
    // header-emitting crate's include/ dir.
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("walk to repo root");

    let capi_include = repo_root.join("ovstorage-core/crates/ovstorage-capi/include");
    let plugin_include = repo_root.join("ovstorage-core/crates/ovstorage-plugin/include");
    for path in [&capi_include, &plugin_include] {
        println!("cargo:rerun-if-changed={}", path.display());
        if !path.exists() {
            panic!("smoke-test include dir missing: {}", path.display());
        }
    }

    cc::Build::new()
        .file(manifest_dir.join("tests/include_smoke.c"))
        .include(&capi_include)
        .include(&plugin_include)
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Werror")
        .warnings(true)
        .compile("ovstorage_capi_cc_smoke_c");

    cc::Build::new()
        .cpp(true)
        .file(manifest_dir.join("tests/include_smoke.cpp"))
        .include(&capi_include)
        .include(&plugin_include)
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Werror")
        .warnings(true)
        .compile("ovstorage_capi_cc_smoke_cpp");
}
