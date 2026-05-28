// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Renames the `ovstorage` binary's PDB on Windows MSVC so it does not
//! collide with the `ovstorage-capi` cdylib's PDB. Both targets share
//! the output stem "ovstorage" (the bin's target name and the cdylib's
//! `[lib] name`), so cargo's default `<stem>.pdb` puts them at the
//! same path under `target/<profile>/deps/`. When two link.exe calls
//! race for the same .pdb the second fails with LNK1201
//! ("error writing to program database").
//!
//! `link.exe /PDB:<path>` overrides the default PDB filename per
//! linker invocation, and `cargo:rustc-link-arg-bin=NAME=FLAG` scopes
//! the override to this one binary. No PDB is emitted on non-MSVC
//! targets so the directive is gated on `CARGO_CFG_TARGET_ENV`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");

    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bin=ovstorage=/PDB:ovstorage_cli.pdb");
    }
}
