// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! repr(C) shadow types for the authz-plugin C ABI.
//!
//! # Input ownership contract
//!
//! Every `*const T` input on a vtable method transfers ownership to the
//! plugin and MUST be consumed synchronously before the vtable function
//! returns; the host will not free it. Holding an input pointer across
//! an async boundary is UB. Result/error pointers passed to
//! `on_complete` transfer ownership plugin → host.

use ovstorage_plugin::ffi::{
    CancelTokenFFI, ConnectionConfigEntry, Error, KeyValueList, List, Optional, Str, VTableDropFn,
};

// cbindgen runs with `parse_deps = false` and can't monomorphize upstream
// generics; these aliases give each instantiation a distinct name that
// `cbindgen.toml`'s `[export.rename]` redirects to the storage SPI's
// monomorphized typedefs. Rust ABI is unchanged.

pub type OptionalStr = Optional<Str>;
pub type OptionalI64 = Optional<i64>;
pub type OptionalU64 = Optional<u64>;
pub type ListStr = List<Str>;
pub type ListConnectionConfigEntry = List<ConnectionConfigEntry>;
pub type ListAuthzDecisionV1 = List<AuthzDecisionV1>;

/// C ABI version. Separate from `OVSTORAGE_PLUGIN_ABI_VERSION` so the
/// authz vtable can rev independently of the storage one.
pub const OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION: u32 = 1;

/// Result returned by `ovstorage_authz_plugin_init_v1`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuthzPluginInitResultV1 {
    pub struct_size: usize,
    pub abi_version: u32,
    pub plugin_state: *mut core::ffi::c_void,
    pub vtable: *const AuthzPluginVTableV1,
}

/// Identity making the request.
#[repr(C)]
#[derive(Debug)]
pub struct PrincipalV1 {
    pub struct_size: usize,
    pub id: Str,
    pub display_name: OptionalStr,
    pub attributes: KeyValueList,
    pub valid_until_unix_ms: OptionalI64,
    pub source: Str,
}

unsafe impl Send for PrincipalV1 {}

/// Request to authorize one operation against one (optional) address.
/// `operation` is a string (not an enum) so new operations land without an
/// ABI break; old plugins must default-deny on unrecognized values.
#[repr(C)]
#[derive(Debug)]
pub struct AuthzRequestV1 {
    pub struct_size: usize,
    pub principal: PrincipalV1,
    pub operation: Str,
    pub address: OptionalStr,
    pub policy_epoch: u64,
    pub audit_id: OptionalStr,
}

unsafe impl Send for AuthzRequestV1 {}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthzEffectFFI {
    Allow = 0,
    Deny = 1,
}

/// Decision returned by `authorize` or one entry of `filter_list_batch`.
#[repr(C)]
#[derive(Debug)]
pub struct AuthzDecisionV1 {
    pub struct_size: usize,
    pub effect: AuthzEffectFFI,
    pub reason: OptionalStr,
    pub explanation: OptionalStr,
    pub decision_ttl_ms: OptionalU64,
}

unsafe impl Send for AuthzDecisionV1 {}

/// Callback for `configure`; status 0 on success.
pub type AuthzConfigureCallback =
    extern "C" fn(status: i32, error: *mut Error, user_data: *mut core::ffi::c_void);

/// `configure` method signature. `config` is a flat `(key, ConfigValue)`
/// list; `cancel` is borrowed for the call duration and must not be
/// retained past `on_complete`.
pub type AuthzConfigureFn = unsafe extern "C" fn(
    plugin_state: *mut core::ffi::c_void,
    config: *const ListConnectionConfigEntry,
    cancel: *const CancelTokenFFI,
    on_complete: AuthzConfigureCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `authorize`.
pub type AuthzAuthorizeCallback = extern "C" fn(
    status: i32,
    result: *mut AuthzDecisionV1,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// `authorize` method signature.
pub type AuthzAuthorizeFn = unsafe extern "C" fn(
    plugin_state: *mut core::ffi::c_void,
    request: *const AuthzRequestV1,
    cancel: *const CancelTokenFFI,
    on_complete: AuthzAuthorizeCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `filter_list_batch`; result list has one decision per
/// address in the same order.
pub type AuthzFilterCallback = extern "C" fn(
    status: i32,
    result: *mut ListAuthzDecisionV1,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// `filter_list_batch` method signature.
pub type AuthzFilterFn = unsafe extern "C" fn(
    plugin_state: *mut core::ffi::c_void,
    request: *const AuthzRequestV1,
    addresses: *const ListStr,
    cancel: *const CancelTokenFFI,
    on_complete: AuthzFilterCallback,
    user_data: *mut core::ffi::c_void,
);

/// Vtable for one authz plugin instance. Lifecycle: `configure` once,
/// then `authorize` / `filter_list_batch` per request.
#[repr(C)]
pub struct AuthzPluginVTableV1 {
    pub struct_size: usize,
    pub drop: VTableDropFn,
    pub configure: AuthzConfigureFn,
    pub authorize: AuthzAuthorizeFn,
    pub filter_list_batch: AuthzFilterFn,
}

unsafe impl Sync for AuthzPluginVTableV1 {}
