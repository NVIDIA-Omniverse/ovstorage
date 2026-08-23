// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The ABI-v2 operational Layer vtable — one C-ABI vtable shared by
//! every Layer (backend, wrapper, router) in every language. It is the
//! FFI projection of `ovstorage_layer::Layer`. Rust has no trait
//! reflection, so the `slot_order` test instead parses the `Layer`
//! trait's method names from the `ovstorage-layer` *source* and diffs
//! them against this vtable's slot list — adding or reordering a trait
//! method fails that test until the vtable is updated in lockstep.
//!
//! # Calling convention
//!
//! - **Lifecycle** (`drop`): synchronous; releases per-instance state.
//! - **Identity** (`name`, `descriptor`, `owned_targets`): synchronous,
//!   infallible getters writing into an out-pointer. The `Layer` trait
//!   methods are infallible, so these slots cannot fail.
//! - **Structural introspection** (`list_kinds`): synchronous, fallible.
//!   It returns `*mut Error` (NULL on success) and writes the result into
//!   an out-pointer. `list_kinds` reports fixed manifest/graph metadata
//!   under the trait's no-I/O contract, so it performs no I/O and needs no
//!   cancellation — it is the sole introspection slot still on the
//!   synchronous path.
//! - **Runtime-state queries & object/connection operations**
//!   (`root_info_for`, `list_address_roots`, `list_connections`, plus every
//!   object/connection op): always-async. The three runtime-state queries
//!   inspect live backend state, so they cross the ABI callback-shaped and
//!   cancellable exactly like the data ops. Input passed by `*const
//!   Request` borrowed for the synchronous prologue; `cancel: *const
//!   CancelTokenFFI` is nullable (retain past the prologue via
//!   `cancel.clone`/`cancel.drop` in pairs); [`OnComplete`] fires exactly
//!   once. Outcome is pointer-presence based: `error == NULL` means
//!   success and `result` (when non-null) is the heap-allocated payload
//!   named per slot. The receiver reclaims every non-null pointer it is
//!   handed.
//!   The two `list_*` slots' result payload pairs the snapshot with a
//!   nullable change-stream pointer ([`ListAddressRootsResult`] /
//!   [`ListConnectionsResult`]). `FFI_STATUS_OK` (0) is reserved for
//!   success because `ErrorCode::NotFound = 0` would otherwise collide.

use super::super::*;

/// Layer-owned state plus the Layer's vtable pointer. The host owns the
/// handle until dropped, then invokes `vtable->drop(state)` exactly once.
/// The same opaque handle shape backs every Layer regardless of `layer_type`.
///
/// A handle a completed op hands back -- a body, a change stream, an
/// auth-event stream, a root or connection update stream -- is owned by the
/// host and may outlive the Layer that produced it: the host routinely drops
/// its Layer reference and keeps pulling such a stream. So `drop(state)`
/// relinquishes this handle's owned reference and may free layer state, but it
/// must not invalidate any live derived handle. Each derived handle must be
/// self-contained, or own all producer state it needs -- normally through a
/// counted reference -- and the producer runtime must outlive every live
/// derived handle, not just this one.
#[repr(C)]
pub struct LayerHandle {
    pub state: *mut core::ffi::c_void,
    pub vtable: *const LayerVTableV1,
}

unsafe impl Send for LayerHandle {}

impl Drop for LayerHandle {
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

/// Uniform async completion callback for every object/connection
/// operation. `result` points at the operation-specific heap payload
/// (the type is fixed per slot and documented on each slot below); it is
/// NULL for unit-shaped operations and on error. `error` is non-null
/// exactly on failure. `user_data` is the host's opaque context. Fires
/// exactly once. `result` and `error`, when non-null, are reclaimed by
/// the receiver.
pub type OnComplete = extern "C" fn(
    status: i32,
    result: *mut core::ffi::c_void,
    error: *mut Error,
    user_data: *mut core::ffi::c_void,
);

// ---------------------------------------------------------------------
// Identity slot signatures (synchronous, infallible)
// ---------------------------------------------------------------------

/// `name`: the config Layer name. Writes the owned [`Str`] into `out`.
pub type LayerNameFn = unsafe extern "C" fn(state: *mut core::ffi::c_void, out: *mut Str);

/// `descriptor`: the Layer's own kind descriptor (including
/// `layer_type`). Writes the owned descriptor into `out`.
pub type LayerDescriptorFn =
    unsafe extern "C" fn(state: *mut core::ffi::c_void, out: *mut LayerKindDescriptor);

/// `owned_targets`: connection-owning Layer names reachable through this
/// Layer. Writes the owned list into `out`.
pub type LayerOwnedTargetsFn =
    unsafe extern "C" fn(state: *mut core::ffi::c_void, out: *mut List<Str>);

// ---------------------------------------------------------------------
// Structural introspection slot signature (synchronous, fallible:
// NULL == success)
// ---------------------------------------------------------------------

/// `list_kinds`: enumerate every Layer kind reachable from here. Reports
/// fixed manifest/graph metadata under the trait's no-I/O contract, so it
/// stays synchronous while the three runtime-state queries went async.
/// `extensions` carries the per-request context bag (`*const Extensions`,
/// NULL = none); the host owns the pointer for the call and the plugin
/// borrows it.
pub type LayerListKindsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    extensions: *const Extensions,
    out: *mut List<LayerKindDescriptor>,
) -> *mut Error;

// ---------------------------------------------------------------------
// Runtime-state introspection slot signatures (always-async, cancellable)
//
// `root_info_for` / `list_address_roots` / `list_connections` inspect live
// backend state, so they are callback-shaped like the object ops: a
// borrowed `*const Request`, a nullable `*const CancelTokenFFI`, an
// [`OnComplete`], and `user_data`. The two `list_*` slots' success payload
// pairs the snapshot with a nullable change-stream pointer.
// ---------------------------------------------------------------------

/// `root_info_for` (`result`: [`RootInfo`]). Per-URL root introspection;
/// the [`RootInfoForRequest`] carries the resolved URL and per-request
/// extensions.
pub type LayerRootInfoForFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const RootInfoForRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `list_address_roots` (`result`: [`ListAddressRootsResult`], pairing the
/// [`RootInfoSnapshot`] with a nullable [`RootInfoChangeStream`] pointer).
pub type LayerListAddressRootsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const ListAddressRootsRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `list_connections` (`result`: [`ListConnectionsResult`], pairing the
/// [`ConnectionSnapshot`] with a nullable [`ConnectionChangeStream`]
/// pointer).
pub type LayerListConnectionsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const ListConnectionsRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// Success payload for the `list_address_roots` slot: the complete
/// [`RootInfoSnapshot`] paired with `updates`, a heap
/// [`RootInfoChangeStream`] pointer (NULL when the Layer has no update
/// channel). Heap-allocated by the producer and reclaimed by the receiver;
/// dropping it frees the snapshot's buffers and, when `updates` is
/// non-null, drives the change stream's `drop_fn`. A decoder that adopts
/// the two fields separately must read them out (e.g. `ptr::read`) and skip
/// this `Drop`, so neither buffer is freed twice.
#[repr(C)]
pub struct ListAddressRootsResult {
    pub snapshot: RootInfoSnapshot,
    pub updates: *mut RootInfoChangeStream,
}

unsafe impl Send for ListAddressRootsResult {}

impl Drop for ListAddressRootsResult {
    fn drop(&mut self) {
        if !self.updates.is_null() {
            // SAFETY: `updates`, when non-null, is an ABI heap pointer
            // the producer minted for this payload.
            unsafe { crate::ffi::abi_alloc::abi_box_free(self.updates) };
            self.updates = std::ptr::null_mut();
        }
    }
}

/// Reclaim a heap-allocated [`ListAddressRootsResult`], freeing the
/// snapshot and its optional change stream. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an ovstorage
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_list_address_roots_result_free(
    value: *mut ListAddressRootsResult,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

/// Success payload for the `list_connections` slot: the complete
/// [`ConnectionSnapshot`] paired with `updates`, a heap
/// [`ConnectionChangeStream`] pointer (NULL when the Layer has no update
/// channel). Same ownership contract as [`ListAddressRootsResult`].
#[repr(C)]
pub struct ListConnectionsResult {
    pub snapshot: ConnectionSnapshot,
    pub updates: *mut ConnectionChangeStream,
}

unsafe impl Send for ListConnectionsResult {}

impl Drop for ListConnectionsResult {
    fn drop(&mut self) {
        if !self.updates.is_null() {
            // SAFETY: `updates`, when non-null, is an ABI heap pointer
            // the producer minted for this payload.
            unsafe { crate::ffi::abi_alloc::abi_box_free(self.updates) };
            self.updates = std::ptr::null_mut();
        }
    }
}

/// Reclaim a heap-allocated [`ListConnectionsResult`], freeing the snapshot
/// and its optional change stream. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an ovstorage
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_list_connections_result_free(
    value: *mut ListConnectionsResult,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

// ---------------------------------------------------------------------
// Async operation slot signatures (one per distinct request type)
// ---------------------------------------------------------------------

/// `stat` (`result`: [`ObjectInfo`]).
pub type LayerStatFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const StatRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `read` / `materialize` / `get_latest_version`. `result` is
/// [`ReadResult`] for `read`, [`LocalDelegate`] for `materialize`, and
/// [`ObjectInfo`] for `get_latest_version`.
pub type LayerReadFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const ReadRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `write` / `write_stream` (`result`: [`WriteResult`]) and
/// `write_redirect` (`result`: [`WriteRedirectBatch`]).
pub type LayerWriteFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const WriteRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `continue_write` (`result`: [`WriteStep`]).
pub type LayerContinueWriteFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const ContinueWriteRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `delete` (unit `result`: NULL on success).
pub type LayerDeleteFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const DeleteRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `copy` (`result`: [`WriteStep`]).
pub type LayerCopyFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const CopyRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `rename` (unit `result`: NULL on success).
pub type LayerRenameFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const RenameRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `update_metadata` (`result`: [`BackendItemInfo`]).
pub type LayerUpdateMetadataFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const UpdateMetadataRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `check_access` (`result`: [`AccessDecision`]).
pub type LayerCheckAccessFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const CheckAccessRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `list` (`result`: [`ListPage`]).
pub type LayerListFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const ListRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `list_versions` (`result`: [`VersionPage`]).
pub type LayerListVersionsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const ListVersionsRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `watch_directory` (`result`: [`BackendChangeStream`]).
pub type LayerWatchDirectoryFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const WatchDirectoryRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `create_directory` (`result`: [`BackendItemInfo`]).
pub type LayerCreateDirectoryFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const CreateDirectoryRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `delete_directory` (unit `result`: NULL on success).
pub type LayerDeleteDirectoryFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const DeleteDirectoryRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `probe` / `add_connection` (`result`: [`Connection`]).
pub type LayerConnectionOpFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const LayerConnectionRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `remove_connection` (unit `result`: NULL on success).
pub type LayerRemoveConnectionFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const RemoveConnectionRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `update_connection_credentials` (`result`: [`Connection`]).
pub type LayerUpdateCredentialsFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const UpdateConnectionCredentialsRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `update_connection_attributes` (`result`: [`Connection`]).
pub type LayerUpdateAttributesFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const UpdateConnectionAttributesRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

/// `authenticate_connection` (`result`: [`AuthEventStream`]).
pub type LayerAuthenticateFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    request: *const AuthenticateRequest,
    cancel: *const CancelTokenFFI,
    on_complete: OnComplete,
    user_data: *mut core::ffi::c_void,
);

// ---------------------------------------------------------------------
// The vtable
// ---------------------------------------------------------------------

/// The operational Layer vtable. **Slot order is the freeze**: it
/// mirrors the `ovstorage_layer::Layer` trait method order exactly
/// (`{drop}` is the only C-only lifecycle slot, ahead of the 31 trait
/// slots), enforced by the `slot_order` test. Every slot is always
/// populated — pure wrappers install `OVSTORAGE_PASSTHROUGH_VTABLE`
/// thunks and backends install `OVSTORAGE_UNSUPPORTED_VTABLE` thunks
/// rather than leaving NULLs (see `thunks_v2`). The trailing 16
/// `_reserved` slots grow the ABI additively pre-2.0.
#[repr(C)]
pub struct LayerVTableV1 {
    pub struct_size: usize,
    pub abi_version: u32,

    /// Lifecycle.
    pub drop: VTableDropFn,

    /// Identity.
    pub name: LayerNameFn,
    pub descriptor: LayerDescriptorFn,
    pub owned_targets: LayerOwnedTargetsFn,

    /// Introspection.
    pub root_info_for: LayerRootInfoForFn,
    pub list_kinds: LayerListKindsFn,
    pub list_address_roots: LayerListAddressRootsFn,

    /// Object operations.
    pub stat: LayerStatFn,
    pub read: LayerReadFn,
    pub write: LayerWriteFn,
    pub write_stream: LayerWriteFn,
    pub write_redirect: LayerWriteFn,
    pub continue_write: LayerContinueWriteFn,
    pub delete: LayerDeleteFn,
    pub copy: LayerCopyFn,
    pub rename: LayerRenameFn,
    pub update_metadata: LayerUpdateMetadataFn,
    pub check_access: LayerCheckAccessFn,
    pub materialize: LayerReadFn,
    pub list: LayerListFn,
    pub list_versions: LayerListVersionsFn,
    pub get_latest_version: LayerReadFn,
    pub watch_directory: LayerWatchDirectoryFn,
    pub create_directory: LayerCreateDirectoryFn,
    pub delete_directory: LayerDeleteDirectoryFn,

    /// Connection management.
    pub probe: LayerConnectionOpFn,
    pub add_connection: LayerConnectionOpFn,
    pub remove_connection: LayerRemoveConnectionFn,
    pub list_connections: LayerListConnectionsFn,
    pub update_connection_credentials: LayerUpdateCredentialsFn,
    pub update_connection_attributes: LayerUpdateAttributesFn,
    pub authenticate_connection: LayerAuthenticateFn,

    /// Reserved padding for additive growth pre-2.0.
    pub _reserved: [Option<unsafe extern "C" fn(*mut core::ffi::c_void) -> *mut Error>; 16],
}

unsafe impl Sync for LayerVTableV1 {}

// ---------------------------------------------------------------------
// Slot-order gate (keystone): the C vtable slot list is derived
// mechanically from the Rust `Layer` trait, so drift fails CI rather
// than being caught — or missed — in review.
// ---------------------------------------------------------------------

#[cfg(test)]
mod slot_order {
    /// The 31 operational slots, in the exact order they must appear in
    /// `LayerVTableV1` (after the C-only `drop` lifecycle slot) and in
    /// the `Layer` trait. Kept as data so the test below can diff it
    /// against the live trait source.
    pub(super) const OPERATIONAL_SLOTS: &[&str] = &[
        "name",
        "descriptor",
        "owned_targets",
        "root_info_for",
        "list_kinds",
        "list_address_roots",
        "stat",
        "read",
        "write",
        "write_stream",
        "write_redirect",
        "continue_write",
        "delete",
        "copy",
        "rename",
        "update_metadata",
        "check_access",
        "materialize",
        "list",
        "list_versions",
        "get_latest_version",
        "watch_directory",
        "create_directory",
        "delete_directory",
        "probe",
        "add_connection",
        "remove_connection",
        "list_connections",
        "update_connection_credentials",
        "update_connection_attributes",
        "authenticate_connection",
    ];

    /// Extract the method names of `pub trait Layer` from the
    /// `ovstorage-layer` source, in source order. A deliberately small
    /// scanner (no `syn` build dependency): find the `trait Layer`
    /// block, then collect every `fn <ident>(` / `async fn <ident>(`
    /// declared at the block's top level (brace depth 1).
    fn layer_trait_methods() -> Vec<String> {
        // CARGO_MANIFEST_DIR is .../ovstorage-core/ovstorage-plugin.
        let src = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ovstorage-layer/src/traits.rs"
        );
        let text = std::fs::read_to_string(src).unwrap_or_else(|e| panic!("read {src}: {e}"));
        let start = text
            .find("pub trait Layer")
            .expect("`pub trait Layer` not found in traits.rs");
        let open = text[start..]
            .find('{')
            .map(|i| start + i + 1)
            .expect("trait body open brace");

        let mut methods = Vec::new();
        let mut depth = 1usize;
        let bytes = text.as_bytes();
        let mut i = open;
        // Track the start of the current line so we only pick up method
        // declarations at the trait's top level (depth 1).
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {
                    // The keyword scan slices `text` at byte offset `i`, so `i`
                    // must land on a UTF-8 char boundary — the trait body's doc
                    // comments contain multi-byte characters (e.g. an em dash).
                    // A continuation byte can never begin `fn`/`async fn`, so
                    // skipping it loses no method declaration.
                    if depth == 1 && text.is_char_boundary(i) {
                        let rest = &text[i..];
                        // Match `async fn <name>` or `fn <name>`, but not
                        // the inner `fn ` of an `async fn ` (which would
                        // otherwise double-count every async method).
                        let after_fn = rest.strip_prefix("async fn ").or_else(|| {
                            let preceded_by_async = text[..i].ends_with("async ");
                            (!preceded_by_async)
                                .then(|| rest.strip_prefix("fn "))
                                .flatten()
                        });
                        // Only match when the keyword begins a token
                        // (preceded by whitespace) to avoid matching
                        // inside idents.
                        let boundary = i == open || bytes[i - 1].is_ascii_whitespace();
                        if boundary && let Some(after) = after_fn {
                            let name: String = after
                                .chars()
                                .take_while(|c| c.is_alphanumeric() || *c == '_')
                                .collect();
                            if !name.is_empty() {
                                methods.push(name);
                            }
                        }
                    }
                }
            }
            i += 1;
        }
        methods
    }

    /// `Layer` trait methods that are host-side composition machinery, not
    /// operational slots: they have no `OvStorage_LayerVTable` entry and never
    /// cross the plugin ABI. `inner_layer` is the wrapper default-delegation
    /// hook — plugin layers are leaves on the host side, so it
    /// stays at its `None` default there. `owning_target_for` resolves a
    /// connection op's target-layer name from the values that DO cross the ABI
    /// (`owned_targets` + `root_info_for`), so it needs no slot of its own.
    /// `invalidate_cached_subtree` is the same kind of hook as `inner_layer`
    /// and for the same reason: it walks the host-side wrapper chain to reach
    /// caches BELOW the layer that owns a notification drain, and a plugin layer
    /// is a leaf on that chain, so its default is a no-op there. Giving it a
    /// slot would put a host composition detail into the frozen ABI and oblige
    /// every plugin to answer a question it has no caches to answer.
    ///
    /// The cost is real and worth stating where the decision is: two cache
    /// layers loaded from one cdylib are chained by the HOST, so from inside the
    /// plugin the upper one's inner is a proxy, and a lifecycle sweep it starts
    /// stops there. The cache documents that it degrades to the lower layer's
    /// own expiry in that composition. A cache pair needing the sweep across the
    /// boundary wants a private channel built when the wrappers are, not a slot
    /// here.
    const NON_SLOT_METHODS: &[&str] = &[
        "inner_layer",
        "invalidate_cached_subtree",
        "owning_target_for",
        "supports_buffered_write_capture",
    ];

    #[test]
    fn vtable_slot_order_matches_layer_trait() {
        let methods: Vec<String> = layer_trait_methods()
            .into_iter()
            .filter(|method| !NON_SLOT_METHODS.contains(&method.as_str()))
            .collect();
        assert_eq!(
            methods, OPERATIONAL_SLOTS,
            "OvStorage_LayerVTable slot list drifted from the Rust `Layer` \
             trait. Update `LayerVTableV1`, `OPERATIONAL_SLOTS`, and the v2 \
             thunks in lockstep — this is the ABI freeze point."
        );
    }
}
