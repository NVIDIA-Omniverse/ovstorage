// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Host callbacks
// ---------------------------------------------------------------------

/// Composite key for `HostCallbacks::secret_*` (
/// `(backend_kind, connection_id, field) → SecretBytes`).
#[repr(C)]
#[derive(Debug)]
pub struct SecretKey {
    pub backend_kind: Str,
    pub connection_id: ConnectionId,
    pub field: Str,
}

unsafe impl Send for SecretKey {}

/// `secret_get` callback. Writes `Optional::some(value)` on hit,
/// `Optional::none()` on miss; returns a non-null `Error` on
/// host-side secret-store failure.
pub type HostSecretGetFn = unsafe extern "C" fn(
    host_state: *mut core::ffi::c_void,
    key: *const SecretKey,
    out_value: *mut Optional<SecretBytes>,
) -> *mut Error;

/// `secret_put` callback.
pub type HostSecretPutFn = unsafe extern "C" fn(
    host_state: *mut core::ffi::c_void,
    key: *const SecretKey,
    value: *const SecretBytes,
) -> *mut Error;

/// `secret_delete` callback.
pub type HostSecretDeleteFn =
    unsafe extern "C" fn(host_state: *mut core::ffi::c_void, key: *const SecretKey) -> *mut Error;

/// Function the host calls (at most once) inside
/// `auth_refresh_lock_with_refresh` while holding the per-
/// `(backend_kind, connection_id)` file lock.
pub type HostRefreshFn = unsafe extern "C" fn(refresh_state: *mut core::ffi::c_void) -> *mut Error;

/// `auth_refresh_lock_with_refresh` callback. The host acquires the
/// per-`(backend_kind, connection_id)` lock, re-checks freshness
/// against `freshness_window_ms`, and invokes `refresh_fn` only when
/// the snapshot is stale.
pub type HostAuthRefreshLockFn = unsafe extern "C" fn(
    host_state: *mut core::ffi::c_void,
    backend_kind: *const Str,
    connection_id: *const ConnectionId,
    freshness_window_ms: u64,
    refresh_state: *mut core::ffi::c_void,
    refresh_fn: HostRefreshFn,
) -> *mut Error;

/// Severity of a plugin-emitted log event. Matches the canonical
/// `tracing` ordering so a Rust `tracing::Level` casts directly.
/// Unknown future values map to `Info` host-side.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LogLevelV1 {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// Plugin-to-host log forwarding. Plugins (in any language) call this
/// to emit one log event into the host's logging pipeline; the host
/// applies its own filter/format/sink. `target` typically names the
/// emitting subsystem (e.g. `"ovstorage_plugin_nucleus::handshake"`);
/// `message` is the rendered text. Both strings borrowed for the call.
pub type HostLogFn = unsafe extern "C" fn(
    host_state: *mut core::ffi::c_void,
    level: u8,
    target: *const Str,
    message: *const Str,
);

/// Function-pointer table the host hands the plugin once at load
/// time. `host_state` is opaque context the plugin threads verbatim
/// through every callback. Future additions append after the current
/// fields and bump `struct_size`; plugins refuse callbacks beyond
/// the host's declared surface.
#[repr(C)]
pub struct HostCallbacks {
    pub struct_size: usize,
    pub host_state: *mut core::ffi::c_void,
    pub secret_get: HostSecretGetFn,
    pub secret_put: HostSecretPutFn,
    pub secret_delete: HostSecretDeleteFn,
    pub auth_refresh_lock_with_refresh: HostAuthRefreshLockFn,
    /// Identifies the kind of host loading the plugin. Plugins with
    /// configurations unsafe in multi-tenant deployments (e.g.
    /// `file://` rooted at `/`) inspect this and may return
    /// `ErrorCode::Unsupported` from `instantiate`.
    ///
    /// Encoded as `u32` (not an enum) so unknown future values can
    /// be treated as "newer host kind" rather than an error.
    /// Values: 0 = direct in-process host, 1 = broker. See [`HostKindV1`].
    pub host_kind: u32,
    /// Forwards a single log event from the plugin into the host's
    /// logging pipeline. Plugins compiled against an older header
    /// where this field doesn't exist must check `struct_size` before
    /// reading it.
    pub log: HostLogFn,
}

/// Typed shadow of [`HostCallbacks::host_kind`].
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HostKindV1 {
    /// In-process direct host — single-tenant, full filesystem access
    /// allowed.
    Library = 0,
    /// Multi-tenant broker daemon — plugins should refuse
    /// cross-tenant-leaky configurations.
    Broker = 1,
}

unsafe impl Send for HostCallbacks {}
unsafe impl Sync for HostCallbacks {}

/// Synchronous lifecycle slot shared by Layer handles and plugin factories.
pub type VTableDropFn = unsafe extern "C" fn(state: *mut core::ffi::c_void);

/// Per-root address and capability advertisement carried by root-change
/// stream payloads.
#[repr(C)]
pub struct AddressRootEntry {
    pub address: Str,
    pub capabilities: Capabilities,
}

unsafe impl Send for AddressRootEntry {}
