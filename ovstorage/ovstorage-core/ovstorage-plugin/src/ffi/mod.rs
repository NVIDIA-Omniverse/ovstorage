// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! repr(C) shadow types for the ovstorage plugin C ABI.
//!
//! Names here are unprefixed; cbindgen adds the `OvStorage` prefix on
//! the C side at header-emit time.
//!
//! # Ownership convention
//!
//! Every allocated pointer carries a matching free function. A handle
//! that crosses the FFI boundary is owned by whichever side receives
//! it; the receiver calls the free function exactly once when done.
//! Borrowed pointers are documented as such and never survive the
//! call that received them.
//!
//! # Allocator convention
//!
//! An ABI value and every buffer nested inside it live on the
//! process-wide operating-system heap, reached through [`abi_alloc`], not
//! on the Rust global allocator. The receiving side releases them with the
//! same pair. See [`abi_alloc`] for why the global allocator cannot carry
//! this traffic.

use std::os::raw::c_char;

/// Static plugin manifest exported by storage plugins as
/// `ovstorage_plugin_manifest_v1`. The pointed-at memory is owned by
/// the plugin binary and lives for the lifetime of the loaded
/// dynamic library; the host never frees a manifest.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PluginManifestV1 {
    pub struct_size: usize,
    pub abi_version: u32,
    pub name: *const c_char,
    pub version: *const c_char,
    /// Test-fixture marker. Production hosts (`allow_test_plugins =
    /// false`) refuse to load `test_only = true` plugins and surface
    /// `ErrorCode::PluginRejected`. Older plugins whose manifest
    /// predates this field default to `false` via the `struct_size`
    /// forward-compatibility rule.
    pub test_only: bool,
}

unsafe impl Sync for PluginManifestV1 {}

pub mod abi_alloc;
mod cancel;
mod capabilities;
mod change;
mod connection;
mod error;
mod host_vtable;
mod object;
mod options;
mod payload;
mod primitive;
mod redirect;
mod secrets_auth;
/// ABI-v2 (Layer) additive surface. See [`v2`].
mod v2;

pub use cancel::*;
pub use capabilities::*;
pub use change::*;
pub use connection::*;
pub use error::*;
pub use host_vtable::*;
pub use object::*;
pub use options::*;
pub use payload::*;
pub use primitive::*;
pub use redirect::*;
pub use secrets_auth::*;
pub use v2::*;
