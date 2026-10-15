// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    nucleus_codegen::init_logging();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = std::path::Path::new(&out_dir).join("generated.rs");

    let generated = nucleus_codegen::generate_from_file("omni1.idl.ts".as_ref())
        .expect("failed to generate from omni1.idl.ts");
    std::fs::write(&out_path, generated).expect("failed to write generated.rs");

    println!("cargo::rerun-if-changed=omni1.idl.ts");
    println!("cargo::rerun-if-changed=build.rs");
}
