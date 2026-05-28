// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Host callbacks
// ---------------------------------------------------------------------

/// Composite key for `HostCallbacks::keyring_*` (
/// `(backend_kind, connection_id, field) → SecretBytes`).
#[repr(C)]
#[derive(Debug)]
pub struct KeyringKey {
    pub backend_kind: Str,
    pub connection_id: ConnectionId,
    pub field: Str,
}

unsafe impl Send for KeyringKey {}

/// `keyring_get` callback. Writes `Optional::some(value)` on hit,
/// `Optional::none()` on miss; returns a non-null `Error` on
/// host-side keyring failure.
pub type HostKeyringGetFn = unsafe extern "C" fn(
    host_state: *mut core::ffi::c_void,
    key: *const KeyringKey,
    out_value: *mut Optional<SecretBytes>,
) -> *mut Error;

/// `keyring_put` callback.
pub type HostKeyringPutFn = unsafe extern "C" fn(
    host_state: *mut core::ffi::c_void,
    key: *const KeyringKey,
    value: *const SecretBytes,
) -> *mut Error;

/// `keyring_delete` callback.
pub type HostKeyringDeleteFn =
    unsafe extern "C" fn(host_state: *mut core::ffi::c_void, key: *const KeyringKey) -> *mut Error;

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
/// through every callback. Future additions append after the v1
/// fields and bump `struct_size`; plugins refuse callbacks beyond
/// the host's declared surface.
#[repr(C)]
pub struct HostCallbacks {
    pub struct_size: usize,
    pub host_state: *mut core::ffi::c_void,
    pub keyring_get: HostKeyringGetFn,
    pub keyring_put: HostKeyringPutFn,
    pub keyring_delete: HostKeyringDeleteFn,
    pub auth_refresh_lock_with_refresh: HostAuthRefreshLockFn,
    /// Identifies the kind of host loading the plugin. Plugins with
    /// configurations unsafe in multi-tenant deployments (e.g.
    /// `file://` rooted at `/`) inspect this and may return
    /// `ErrorCode::Unsupported` from `instantiate`.
    ///
    /// Encoded as `u32` (not an enum) so unknown future values can
    /// be treated as "newer host kind" rather than an error.
    /// Values: 0 = Library, 1 = Broker. See [`HostKindV1`].
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
    /// In-process library — single-tenant, full filesystem access
    /// allowed.
    Library = 0,
    /// Multi-tenant broker daemon — plugins should refuse
    /// cross-tenant-leaky configurations.
    Broker = 1,
}

unsafe impl Send for HostCallbacks {}
unsafe impl Sync for HostCallbacks {}

// ---------------------------------------------------------------------
// Backend handle + instance
// ---------------------------------------------------------------------

/// Plugin-allocated backend state plus the backend's vtable pointer.
/// The host owns the handle until dropped, then invokes
/// `vtable->drop(state)` exactly once to release per-instance
/// resources.
#[repr(C)]
pub struct BackendHandle {
    pub state: *mut core::ffi::c_void,
    pub vtable: *const BackendVTableV1,
}

unsafe impl Send for BackendHandle {}

impl Drop for BackendHandle {
    fn drop(&mut self) {
        if !self.state.is_null() && !self.vtable.is_null() {
            // SAFETY: `vtable->drop` is valid for the lifetime of `state`.
            unsafe {
                ((*self.vtable).drop)(self.state);
            }
            self.state = std::ptr::null_mut();
            self.vtable = std::ptr::null();
        }
    }
}

/// Per-root entry inside [`BackendInstance::address_roots`]. Capabilities
/// are stamped onto each `Route` from this struct, so per-route gating
/// reflects the plugin's per-root advertisement.
#[repr(C)]
pub struct AddressRootEntry {
    pub address: Str,
    pub capabilities: Capabilities,
}

unsafe impl Send for AddressRootEntry {}

/// Configured backend instance returned by
/// `BackendFactoryVTableV1::instantiate`. Dropping the instance
/// cascades through `BackendHandle`'s drop, which invokes the
/// plugin's `drop` slot to release per-instance state.
#[repr(C)]
pub struct BackendInstance {
    pub backend_id: BackendId,
    pub backend: BackendHandle,
    pub address_roots: List<AddressRootEntry>,
    pub display_name: Optional<Str>,
    pub auth_state: ConnectionAuthState,
}

unsafe impl Send for BackendInstance {}

/// Reclaim a heap-allocated [`BackendInstance`] returned through a
/// `FactoryInstantiateCallback`. Drives the embedded backend's
/// `drop` slot before releasing the outer allocation. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-boxed pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_backend_instance_free(value: *mut BackendInstance) {
    unsafe {
        if value.is_null() {
            return;
        }
        drop(Box::from_raw(value));
    }
}

// ---------------------------------------------------------------------
// Backend SPI vtable (16 async I/O methods + drop)
//
// Sync slot (`drop`):
//   - First parameter: opaque backend `state` pointer.
//   - `drop` does not return.
//
// Async I/O slots: return `void`. Input values passed by `*const T`,
// borrowed for the synchronous prologue and consumed by the plugin's
// thunk before returning. `cancel: *const CancelTokenFFI` is nullable;
// retain past the prologue via `cancel.clone(state)` paired with
// `cancel.drop(state)`. `on_complete` fires exactly once. `user_data`
// is opaque pass-through.
//
// Callback signature: `(status, result, error, user_data)`. Unit-shape
// methods omit `result`.
//
// Outcome dispatch is pointer-presence based, NOT status-based.
// `FFI_STATUS_OK` (0) is reserved exclusively for success because
// `ErrorCode::NotFound = 0` would otherwise collide. Receivers branch
// on `error == null`; `status` is informational so a C handler can
// short-circuit success without dereferencing the error pointer.
//
// Ownership across the callback: both `result` (when non-null) and
// `error` (when non-null) are heap-allocated by the producer and
// reclaimed by the receiver inside its trampoline.
// ---------------------------------------------------------------------

/// `drop` slot common to both backend and factory vtables.
pub type VTableDropFn = unsafe extern "C" fn(state: *mut core::ffi::c_void);

// ---------------------------------------------------------------------
// Async I/O callback typedefs (one per method's return shape)
// ---------------------------------------------------------------------

/// Callback for `BackendVTableV1::stat`.
pub type BackendStatCallback = extern "C" fn(
    status: i32,
    result: *mut ObjectInfo,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::stat`.
pub type BackendStatFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const StatOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendStatCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::read`.
pub type BackendReadCallback = extern "C" fn(
    status: i32,
    result: *mut ReadResult,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::read`.
pub type BackendReadFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const ReadOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendReadCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::write` and `write_stream`.
pub type BackendWriteCallback = extern "C" fn(
    status: i32,
    result: *mut WriteResult,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::write` (buffered).
pub type BackendWriteFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    bytes: *const Bytes,
    opts: *const WriteOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWriteCallback,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::write_stream`.
pub type BackendWriteStreamFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    body: *const BodyStream,
    opts: *const WriteOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWriteCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::write_redirect`.
pub type BackendWriteRedirectCallback = extern "C" fn(
    status: i32,
    result: *mut WriteRedirectBatch,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::write_redirect`.
pub type BackendWriteRedirectFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const WriteOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWriteRedirectCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::continue_write` and `copy`.
pub type BackendWriteStepCallback = extern "C" fn(
    status: i32,
    result: *mut WriteStep,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::continue_write`.
pub type BackendContinueWriteFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    redirects: *const WriteRedirectBatch,
    results: *const RedirectResultBatch,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWriteStepCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for unit-shape methods (`delete`, `delete_directory`,
/// `rename`, factory `update_credentials`).
pub type BackendUnitCallback =
    extern "C" fn(status: i32, error: *mut Error, user_data: *mut core::ffi::c_void);

/// Method signature for `BackendVTableV1::delete`.
pub type BackendDeleteFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const DeleteOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::list`.
pub type BackendListCallback = extern "C" fn(
    status: i32,
    result: *mut List<ObjectInfo>,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::list`.
pub type BackendListFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    prefix: *const ResolvedTarget,
    opts: *const ListOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendListCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::list_versions`.
pub type BackendListVersionsCallback = extern "C" fn(
    status: i32,
    result: *mut List<ObjectInfo>,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::list_versions`.
pub type BackendListVersionsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const ListVersionsOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendListVersionsCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::get_latest_version`.
pub type BackendGetLatestVersionCallback = extern "C" fn(
    status: i32,
    result: *mut ObjectInfo,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::get_latest_version`.
pub type BackendGetLatestVersionFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    cancel: *const CancelTokenFFI,
    on_complete: BackendGetLatestVersionCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::watch_directory`.
pub type BackendWatchDirectoryCallback = extern "C" fn(
    status: i32,
    result: *mut BackendChangeStream,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::watch_directory`.
pub type BackendWatchDirectoryFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    prefix: *const ResolvedTarget,
    opts: *const WatchDirectoryOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWatchDirectoryCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::create_directory` and
/// `update_metadata` — both produce a `BackendItemInfo`.
pub type BackendItemInfoCallback = extern "C" fn(
    status: i32,
    result: *mut BackendItemInfo,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::create_directory`.
pub type BackendCreateDirectoryFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const CreateDirectoryOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendItemInfoCallback,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::delete_directory`.
pub type BackendDeleteDirectoryFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const DeleteDirectoryOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::copy`.
pub type BackendCopyFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    src: *const ResolvedTarget,
    dest: *const ResolvedTarget,
    opts: *const CopyOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWriteStepCallback,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::rename`.
pub type BackendRenameFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    src: *const ResolvedTarget,
    dest: *const ResolvedTarget,
    opts: *const RenameOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::update_metadata`.
pub type BackendUpdateMetadataFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    opts: *const UpdateMetadataOptions,
    cancel: *const CancelTokenFFI,
    on_complete: BackendItemInfoCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::check_access`.
pub type BackendCheckAccessCallback = extern "C" fn(
    status: i32,
    result: *mut AccessDecision,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::check_access`.
pub type BackendCheckAccessFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    target: *const ResolvedTarget,
    ops: *const AccessOps,
    cancel: *const CancelTokenFFI,
    on_complete: BackendCheckAccessCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendVTableV1::watch_address_roots`.
pub type BackendWatchAddressRootsCallback = extern "C" fn(
    status: i32,
    result: *mut BackendAddressRootsStream,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendVTableV1::watch_address_roots`.
pub type BackendWatchAddressRootsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    cancel: *const CancelTokenFFI,
    on_complete: BackendWatchAddressRootsCallback,
    user_data: *mut core::ffi::c_void,
);

/// Vtable for one configured backend instance. The host dispatches
/// object operations through these function-pointer slots.
///
/// `drop` is synchronous; other slots are async per the calling
/// convention at the top of this section.
///
/// Forward compatibility: `struct_size` must cover at least the v1
/// fields. The trailing 16 `_reserved` slots are zero-initialized so
/// a newer host running an older plugin sees `None` for unimplemented
/// methods. New SPI methods consume the next free reserved slot in
/// tree order; existing fields never reorder.
#[repr(C)]
pub struct BackendVTableV1 {
    pub struct_size: usize,
    pub drop: VTableDropFn,
    pub stat: BackendStatFn,
    pub read: BackendReadFn,
    pub write: BackendWriteFn,
    pub write_stream: BackendWriteStreamFn,
    pub write_redirect: BackendWriteRedirectFn,
    pub continue_write: BackendContinueWriteFn,
    pub delete: BackendDeleteFn,
    pub list: BackendListFn,
    pub list_versions: BackendListVersionsFn,
    pub get_latest_version: BackendGetLatestVersionFn,
    pub watch_directory: BackendWatchDirectoryFn,
    pub create_directory: BackendCreateDirectoryFn,
    pub delete_directory: BackendDeleteDirectoryFn,
    pub copy: BackendCopyFn,
    pub rename: BackendRenameFn,
    pub update_metadata: BackendUpdateMetadataFn,
    pub check_access: BackendCheckAccessFn,
    pub watch_address_roots: BackendWatchAddressRootsFn,
    pub _reserved: [Option<unsafe extern "C" fn(*mut core::ffi::c_void) -> *mut Error>; 16],
}

/// Placeholder signature for trailing reserved vtable slots. Reserved
/// slots are `None` until a new SPI method replaces one. The shape is
/// minimal so an "unsupported" stub can return a typed error without
/// further argument plumbing.
pub type VTableReservedFn = unsafe extern "C" fn(*mut core::ffi::c_void) -> *mut Error;

unsafe impl Sync for BackendVTableV1 {}

// ---------------------------------------------------------------------
// Backend factory vtable (1 sync getter + 3 async I/O methods)
// ---------------------------------------------------------------------

/// Sync-getter signature for `BackendFactoryVTableV1::descriptor`.
pub type FactoryDescriptorFn = unsafe extern "C" fn(
    factory_state: *mut core::ffi::c_void,
    out: *mut StorageBackendKindDescriptor,
) -> *mut Error;

/// Callback for `BackendFactoryVTableV1::instantiate`.
pub type FactoryInstantiateCallback = extern "C" fn(
    status: i32,
    result: *mut BackendInstance,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendFactoryVTableV1::instantiate`.
pub type FactoryInstantiateFn = unsafe extern "C" fn(
    factory_state: *mut core::ffi::c_void,
    request: *const ConnectionRequest,
    cancel: *const CancelTokenFFI,
    on_complete: FactoryInstantiateCallback,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendFactoryVTableV1::update_credentials`.
pub type FactoryUpdateCredentialsFn = unsafe extern "C" fn(
    factory_state: *mut core::ffi::c_void,
    connection: *const Connection,
    credentials: *const SecretBundle,
    cancel: *const CancelTokenFFI,
    on_complete: BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
);

/// Callback for `BackendFactoryVTableV1::authenticate`.
pub type FactoryAuthenticateCallback = extern "C" fn(
    status: i32,
    result: *mut AuthEventStream,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

/// Method signature for `BackendFactoryVTableV1::authenticate`.
/// `capability` is the host's declared interactive-auth surface; the
/// plugin uses it to pick PKCE vs. device flow vs. fail-fast.
pub type FactoryAuthenticateFn = unsafe extern "C" fn(
    factory_state: *mut core::ffi::c_void,
    connection: *const Connection,
    capability: InteractiveAuthCapabilityV1,
    cancel: *const CancelTokenFFI,
    on_complete: FactoryAuthenticateCallback,
    user_data: *mut core::ffi::c_void,
);

/// Vtable for one storage-backend factory. The host drives connection
/// management through these slots and reaches individual
/// `BackendInstance`s via `instantiate`. Forward-compat reserved
/// slots: see [`BackendVTableV1`].
#[repr(C)]
pub struct BackendFactoryVTableV1 {
    pub struct_size: usize,
    pub drop: VTableDropFn,
    pub descriptor: FactoryDescriptorFn,
    pub instantiate: FactoryInstantiateFn,
    pub update_credentials: FactoryUpdateCredentialsFn,
    pub authenticate: FactoryAuthenticateFn,
    pub _reserved: [Option<unsafe extern "C" fn(*mut core::ffi::c_void) -> *mut Error>; 16],
}

unsafe impl Sync for BackendFactoryVTableV1 {}

#[cfg(test)]
mod tests {
    use super::*;

    const RESERVED_SLOTS: usize = 16;

    #[test]
    fn backend_vtable_carries_reserved_slots() {
        let v = ffi_static_vtable();
        assert_eq!(v._reserved.len(), RESERVED_SLOTS);
        assert!(v._reserved.iter().all(|slot| slot.is_none()));
    }

    fn ffi_static_vtable() -> &'static BackendVTableV1 {
        &crate::thunks::BACKEND_VTABLE
    }

    #[test]
    fn factory_vtable_carries_reserved_slots() {
        let v = &crate::thunks::FACTORY_VTABLE;
        assert_eq!(v._reserved.len(), RESERVED_SLOTS);
        assert!(v._reserved.iter().all(|slot| slot.is_none()));
    }

    #[test]
    fn vtable_struct_size_is_self_consistent() {
        assert_eq!(
            crate::thunks::BACKEND_VTABLE.struct_size,
            core::mem::size_of::<BackendVTableV1>()
        );
        assert_eq!(
            crate::thunks::FACTORY_VTABLE.struct_size,
            core::mem::size_of::<BackendFactoryVTableV1>()
        );
    }

    #[test]
    fn reserved_slots_use_function_pointer_size() {
        // `Option<extern fn>` benefits from the null-pointer optimization.
        assert_eq!(
            core::mem::size_of::<[Option<VTableReservedFn>; RESERVED_SLOTS]>(),
            RESERVED_SLOTS * core::mem::size_of::<*const ()>()
        );
    }
}
