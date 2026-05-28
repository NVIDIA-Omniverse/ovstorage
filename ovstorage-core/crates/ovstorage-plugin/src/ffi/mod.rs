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

use std::os::raw::c_char;

/// C ABI version this header was generated against. Mismatch between
/// the host's value and the plugin's manifest surfaces as
/// `IncompatibleType` before any vtable call is attempted.
///
/// History:
/// - v1: initial SPI.
/// - v2: `Capabilities` gains `supports_write`, `supports_write_stream`,
///   `supports_write_redirect`, `supports_delete`,
///   `supports_create_directory`, `supports_delete_directory` to gate
///   the four methods that moved from required to default `Unsupported`
///   on the `Backend` trait. Layout change; cdylibs must rebuild.
/// - v3: precondition SPI redesign. `ObjectIdentity` removed; `etag` /
///   `version` / `size` / `mtime_unix_ms` lift onto `ObjectInfo` and
///   `BackendItemInfo`. New `ObjectKindV1` discriminator replaces
///   `SubdirKindV1`. New `IfDestExistsV1` tagged-union on
///   `WriteOptions` / `CopyOptions` / `RenameOptions` replaces the
///   `no_overwrite` boolean and the old `if_match: ObjectIdentity`.
///   `CopyOptions` / `RenameOptions` add `if_source` (etag). Read /
///   delete / update-metadata `if_match` becomes `Optional<Str>`.
///   Change events carry `etag: Optional<Str>` in place of
///   `identity: Optional<ObjectIdentity>`. Error context's identity
///   payload carries `new_etag: Optional<Str>`.
/// - v4: list, list_versions, and get_latest_version return
///   `ObjectInfo` directly. Backend list/version wrapper payloads and
///   version selector structs are removed.
pub const OVSTORAGE_PLUGIN_ABI_VERSION: u32 = 4;

/// Static plugin manifest exported by backend plugins as
/// `ovstorage_plugin_manifest_v1`. The pointed-at memory is owned by
/// the plugin binary and lives for the lifetime of the loaded
/// library; the host never frees a manifest.
///
/// Authz plugins export an analogous symbol
/// (`ovstorage_authz_plugin_manifest_v1`); each domain's loader
/// resolves its own symbol name.
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

/// Result returned by `ovstorage_plugin_init_v1` (the backend init
/// entry point). Vtable storage lives inside the plugin binary; the
/// host borrows the pointer for the lifetime of the loaded library.
///
/// Banded ABI handshake: `abi_version` is the canonical version the
/// plugin was compiled against; `[min_supported_abi_version,
/// max_supported_abi_version]` is the inclusive band the plugin's
/// vtable supports. The host validates `min <= host.abi_version <=
/// max`; mismatch surfaces as `ErrorCode::IncompatibleType`.
/// Width-1 bands set both equal to `abi_version`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct BackendPluginInitResultV1 {
    pub struct_size: usize,
    pub abi_version: u32,
    /// Inclusive lower bound of host ABI versions the plugin
    /// supports. Hosts with `abi_version < min` reject the plugin.
    pub min_supported_abi_version: u32,
    /// Inclusive upper bound of host ABI versions the plugin
    /// supports. Hosts with `abi_version > max` reject the plugin.
    pub max_supported_abi_version: u32,
    /// Plugin-allocated state passed verbatim to every vtable method.
    /// Released by the vtable's `drop` slot.
    pub plugin_state: *mut core::ffi::c_void,
    /// Pointer to the plugin's static [`BackendFactoryVTableV1`].
    pub factory_vtable: *const BackendFactoryVTableV1,
}

/// Function-pointer type for the backend plugin's init entry point.
/// Called once at load time; the `host` pointer stays valid for the
/// cdylib's lifetime. Per-call methods do not receive callbacks
/// again.
pub type BackendPluginInitV1 =
    unsafe extern "C" fn(host: *const HostCallbacks) -> BackendPluginInitResultV1;

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
