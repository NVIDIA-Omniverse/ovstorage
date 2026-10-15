// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The ABI-v2 cdylib loading surface: the kind descriptor, the
//! three-way factory split (`create_backend` / `create_wrapper` /
//! `create_router`), and the init result.
//!
//! # Symbols and version discrimination
//!
//! A Layer plugin exports the stable symbols
//! `ovstorage_plugin_manifest_v1` (a static [`PluginManifestV1`]) and
//! `ovstorage_plugin_init_v1` (an [`PluginInitV1`] fn). The manifest's
//! `abi_version` must be at or above `OVSTORAGE_PLUGIN_ABI_V2_FLOOR`
//! and exactly equal `OVSTORAGE_PLUGIN_ABI_V2_VERSION`. A cdylib exports
//! one init-result shape.
//!
//! Per RFC §616, a v2 plugin emits only the `abi_version` it implements
//! (no plugin-declared max); acceptance is a host-loader decision. The
//! init result therefore carries no min/max band.

use super::super::*;

/// Layer type produced by a factory. Selects the `create_*` entry point
/// and validates config shape: backend has no edge, wrapper has one
/// `inner`, router has `children`. Mirrors `ovstorage_layer::LayerType`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LayerType {
    Backend = 0,
    Wrapper = 1,
    Router = 2,
}

/// Static, kind-level facts about every instance one Layer factory
/// produces. Mirrors `ovstorage_layer::LayerKindDescriptor`. Carries
/// KIND-scope info only (never connection- or root-scope, which are
/// runtime-queried via `list_connections` / `root_info_for`). The host
/// reads `layer_type` to pick the matching `create_*` factory.
#[repr(C)]
pub struct LayerKindDescriptor {
    pub struct_size: usize,
    pub layer_type: LayerType,
    /// True for backend layers and connection-owning wrapper layers
    /// (e.g. `alias`); false for pure wrappers and routers. Surfaced
    /// explicitly so a UI knows where `add_connection` is valid.
    pub accepts_connections: bool,
    /// Whether a write's `user_metadata` can survive this backend kind. A
    /// static, per-kind declaration read at discovery time; false for wrappers
    /// and routers, which own no storage. A host composes its attribution
    /// wrapper only over branches whose backend declares true.
    pub supports_user_metadata: bool,
    pub kind: Str,
    pub display_name: Str,
    pub description: Optional<Str>,
    pub config_schema: List<ConfigField>,
    pub credential_schema: List<CredentialField>,
    pub credential_methods: List<CredentialMethod>,
    pub icon: Optional<Bytes>,
    /// True only when instances of this kind are safe to compose as a
    /// listener's authentication Layer. Hosts fail closed for false.
    pub auth_capable: bool,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for LayerKindDescriptor {}
unsafe impl Sync for LayerKindDescriptor {}

/// Drop a [`LayerKindDescriptor`]'s nested allocations in place. The
/// pointee itself is caller-owned storage (the `descriptor` /
/// `list_kinds` protocol writes descriptors into caller-provided slots,
/// so this function never frees the descriptor's own memory). Safe with
/// NULL.
///
/// # Safety
///
/// `value`, when non-null, must point at an initialized descriptor whose
/// nested allocations were produced by an ovstorage call and have not
/// already been reclaimed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_layer_kind_descriptor_free(
    value: *mut LayerKindDescriptor,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Factory request for a backend layer (no child). Mirrors RFC
/// `OvStorage_CreateBackendRequest`.
#[repr(C)]
pub struct CreateBackendRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    /// A manifest kind whose `layer_type == Backend`.
    pub kind: Str,
    /// Config-visible instance name (the Stack layer name).
    pub instance_id: Str,
    pub config: List<ConnectionConfigEntry>,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for CreateBackendRequest {}

/// Factory request for a wrapper layer (exactly one `inner` child).
/// Mirrors RFC `OvStorage_CreateWrapperRequest`. `inner` is moved into
/// the wrapper: the factory takes ownership of the handle (and must drop
/// it on failure).
#[repr(C)]
pub struct CreateWrapperRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub inner: LayerHandle,
    pub kind: Str,
    pub instance_id: Str,
    pub config: List<ConnectionConfigEntry>,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for CreateWrapperRequest {}

/// One child of a router layer: its already-built handle. The router
/// takes ownership. Mirrors RFC `OvStorage_RouterChild`.
#[repr(C)]
pub struct RouterChild {
    pub handle: LayerHandle,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for RouterChild {}

/// Factory request for a router layer (many children). Mirrors RFC
/// `OvStorage_CreateRouterRequest`. The router takes ownership of every
/// child handle in `children`.
#[repr(C)]
pub struct CreateRouterRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub kind: Str,
    pub instance_id: Str,
    pub config: List<ConnectionConfigEntry>,
    pub children: *const RouterChild,
    pub child_count: usize,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for CreateRouterRequest {}

/// `create_backend` slot signature. Returns [`FfiStatus`] (0 on success)
/// and, on failure, writes a non-null [`Error`] into `*err`; on success
/// writes the fresh [`LayerHandle`] into `*out`. The spike validated the
/// status + `err` out-param shape (superseding the RFC `void`-return
/// sketch).
pub type CreateBackendFn = unsafe extern "C" fn(
    plugin_state: *mut core::ffi::c_void,
    request: *const CreateBackendRequest,
    out: *mut LayerHandle,
    err: *mut *mut Error,
) -> FfiStatus;

/// `create_wrapper` slot signature.
pub type CreateWrapperFn = unsafe extern "C" fn(
    plugin_state: *mut core::ffi::c_void,
    request: *const CreateWrapperRequest,
    out: *mut LayerHandle,
    err: *mut *mut Error,
) -> FfiStatus;

/// `create_router` slot signature.
pub type CreateRouterFn = unsafe extern "C" fn(
    plugin_state: *mut core::ffi::c_void,
    request: *const CreateRouterRequest,
    out: *mut LayerHandle,
    err: *mut *mut Error,
) -> FfiStatus;

/// The plugin-scope factory vtable returned by `ovstorage_plugin_init_v1`.
/// A plugin populates only the `create_*` slots whose kinds it ships; the
/// host calls the one matching each kind's declared `layer_type`. The
/// host drops `plugin_state` through `drop` after every Layer handle the
/// plugin produced has been dropped.
#[repr(C)]
pub struct PluginVTableV1 {
    pub struct_size: usize,
    pub abi_version: u32,
    pub drop: VTableDropFn,
    pub create_backend: CreateBackendFn,
    pub create_wrapper: CreateWrapperFn,
    pub create_router: CreateRouterFn,
    pub _reserved: [Option<unsafe extern "C" fn(*mut core::ffi::c_void) -> *mut Error>; 16],
}

unsafe impl Sync for PluginVTableV1 {}

/// Result returned by the ABI-v2 `ovstorage_plugin_init_v1`. Init
/// creates plugin-scoped resources only; Layer instances are created
/// later, one per Stack entry, through the `create_*` factories.
///
/// `kinds` points at `kind_count` plugin-owned [`LayerKindDescriptor`]s
/// (the kind-scope manifest data) borrowed by the host for the cdylib's
/// lifetime and released by `plugin_vtable->drop`. Carried here rather
/// than in the static [`PluginManifestV1`] because the descriptors own
/// heap allocations (`Str` / `List`) that a `static` cannot hold.
#[repr(C)]
pub struct PluginInitResultV1 {
    pub struct_size: usize,
    /// The single Layer ABI this plugin implements. It places it in the
    /// v2 family (`>= [OVSTORAGE_PLUGIN_ABI_V2_FLOOR]`) for dispatch, but
    /// the host then validates it by exact match against
    /// [`OVSTORAGE_PLUGIN_ABI_V2_VERSION`] — a stale or unknown-higher
    /// value is rejected, not accepted.
    pub abi_version: u32,
    /// Plugin-scoped state (e.g. a shared HTTP client), released by
    /// `plugin_vtable->drop`.
    pub plugin_state: *mut core::ffi::c_void,
    pub plugin_vtable: *const PluginVTableV1,
    /// Borrowed array of the kinds this cdylib ships.
    pub kinds: *const LayerKindDescriptor,
    pub kind_count: usize,
}

/// Function-pointer type for the ABI-v2 plugin init entry point. The
/// `host` pointer stays valid for the cdylib's lifetime. The stable
/// `ovstorage_plugin_init_v1` symbol is interpreted as this type after
/// manifest validation. Reuses the shared [`HostCallbacks`] substrate.
pub type PluginInitV1 = unsafe extern "C" fn(host: *const HostCallbacks) -> PluginInitResultV1;
