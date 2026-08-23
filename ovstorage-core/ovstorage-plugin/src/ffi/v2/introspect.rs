// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! repr(C) shadow types for the ABI-v2 *introspection* and
//! *connection-management* surfaces — the answers the Layer vtable's
//! synchronous slots (`root_info_for`, `list_kinds`,
//! `list_address_roots`, `list_connections`) and the connection ops
//! return. Object-operation request/result types reuse the shared FFI
//! values; these types carry Layer-specific introspection state.
//!
//! Names are unprefixed; cbindgen adds the `OvStoragePlugin_` prefix at
//! header-emit time. Ownership follows the crate convention: every
//! allocation carries a matching free function or rides a parent's
//! `Drop`.

use super::super::*;

// ---------------------------------------------------------------------
// Per-root introspection (`root_info_for`, `list_address_roots`)
// ---------------------------------------------------------------------

/// Whether a root can serve efficient random-access range reads.
/// Mirrors `ovstorage_layer::RangeReadStrategy`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RangeReadStrategy {
    Native = 0,
    CachedReadThrough = 1,
    MaterializeOnly = 2,
    Unsupported = 3,
}

/// Whether a root is presented to listings. Mirrors
/// `ovstorage_layer::AddressVisibility`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AddressVisibility {
    Visible = 0,
    Hidden = 1,
    Suppressed = 2,
}

/// Tag for [`AliasSource`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AliasSourceTag {
    Static = 0,
    Runtime = 1,
    BrokerDelivered = 2,
}

/// Provenance of an alias edge. Mirrors `ovstorage_layer::AliasSource`.
#[repr(C)]
pub struct AliasSource {
    pub tag: AliasSourceTag,
    /// `Static` payload: the config layer that declared the alias.
    pub layer: ConfigLayer,
    /// `Runtime` payload: whether the runtime alias is persisted.
    pub persisted: bool,
    /// `BrokerDelivered` payload: the principal the broker delivered for.
    pub broker_principal: Optional<Str>,
}

unsafe impl Send for AliasSource {}

/// Tag for [`AliasState`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AliasStateTag {
    Live = 0,
    Dangling = 1,
    ChainTooLong = 2,
}

/// Resolution state of an alias root. Mirrors
/// `ovstorage_layer::AliasState`.
#[repr(C)]
pub struct AliasState {
    pub tag: AliasStateTag,
    /// `ChainTooLong` payload: human-readable reason.
    pub reason: Optional<Str>,
}

unsafe impl Send for AliasState {}

/// Tag for [`RouteSource`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RouteSourceTag {
    Static = 0,
    ConnectionContributed = 1,
    BrokerDelivered = 2,
    Alias = 3,
}

/// How a root entered the routing table. Mirrors
/// `ovstorage_layer::RouteSource`. A single discriminated struct (no
/// `MaybeUninit` union) keeps the layout legible for C consumers; only
/// the fields named by `tag` carry meaning.
#[repr(C)]
pub struct RouteSource {
    pub tag: RouteSourceTag,
    /// `Static` payload: declaring config layer.
    pub layer: ConfigLayer,
    /// `ConnectionContributed` / `BrokerDelivered` payload.
    pub connection_id: Optional<ConnectionId>,
    /// `BrokerDelivered` payload: delivering principal.
    pub broker_principal: Optional<Str>,
    /// `Alias` payload: rewrite destination URL.
    pub alias_to: Optional<Str>,
    /// `Alias` payload: provenance of the alias edge.
    pub alias_source: Optional<AliasSource>,
}

unsafe impl Send for RouteSource {}

/// Per-root introspection answer. Mirrors `ovstorage_layer::RootInfo`.
/// Returned by the `root_info_for` vtable slot and carried in
/// [`RootInfoSnapshot`] / [`RootInfoChange`].
#[repr(C)]
pub struct RootInfo {
    pub struct_size: usize,
    /// Post-alias canonical root URL.
    pub root: Str,
    pub display_name: Optional<Str>,
    pub layer_kind: Str,
    pub connection_id: Optional<ConnectionId>,
    pub capabilities: Capabilities,
    pub range_read_strategy: RangeReadStrategy,
    pub source: RouteSource,
    pub visible: bool,
    pub visibility: AddressVisibility,
    pub alias_state: Optional<AliasState>,
    pub icon: Optional<Bytes>,
    pub user_metadata: UserMetadata,
    /// Instance name of the Layer owning connections for this root (the
    /// `ConnectionKey.target` connection ops route by). Reported alongside
    /// `connection_id` so a caller resolves both from one `root_info_for`, and
    /// so a loaded composite plugin's internal owning backend crosses the ABI.
    ///
    /// APPENDED AT THE TAIL, consuming three `_reserved` slots (an
    /// `Optional<Str>` is 24 bytes), so `size_of::<RootInfo>()` is UNCHANGED
    /// and every prior field keeps its offset. A plugin built against the
    /// earlier v7 header (no `owning_target`) zeroes those bytes as part of
    /// `_reserved`, and a zeroed `Optional` decodes as absent (`present ==
    /// false` → `None`) — so no ABI version bump is required and mixed builds
    /// stay memory-safe. The `layout_is_frozen` assertion below pins this.
    pub owning_target: Optional<Str>,
    pub _reserved: [*mut core::ffi::c_void; 5],
}

/// Freeze the `#[repr(C)] RootInfo` binary layout: `owning_target` was appended
/// at the tail against three of the eight original `_reserved` slots, so the
/// total size must equal the original (16 pointers of fixed head/tail framing
/// around the value fields is not asserted here; the SIZE invariant is what
/// keeps an old plugin's zeroed reserved tail decoding `owning_target` as
/// absent). If a future edit shifts a field or changes the size, this fails to
/// compile — forcing a deliberate `OVSTORAGE_PLUGIN_ABI_V2_VERSION` decision.
/// cbindgen:ignore
const _: () = {
    // owning_target (24 bytes) + _reserved[5] (40 bytes) == the original
    // _reserved[8] (64 bytes): the tail budget is exactly preserved.
    assert!(core::mem::size_of::<Optional<Str>>() == 24);
    assert!(core::mem::size_of::<[*mut core::ffi::c_void; 5]>() == 40);
    assert!(
        core::mem::offset_of!(RootInfo, owning_target)
            == core::mem::offset_of!(RootInfo, user_metadata)
                + core::mem::size_of::<UserMetadata>()
    );
};

unsafe impl Send for RootInfo {}

/// Release the nested allocations of a [`RootInfo`] in place, written by
/// the `root_info_for` out-pointer (caller-owned storage). Safe with
/// NULL. The `RootInfo` storage itself is not released.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`RootInfo`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_root_info_free(value: *mut RootInfo) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Complete snapshot of the roots reachable through a Layer, returned
/// by `list_address_roots`. `updates` mirrors whether the slot also
/// produced a [`RootInfoChangeStream`]; the host consults it to decide
/// whether to drain a follow-on stream.
#[repr(C)]
pub struct RootInfoSnapshot {
    pub roots: List<RootInfo>,
    pub updates: bool,
}

unsafe impl Send for RootInfoSnapshot {}

/// Release the nested allocations of a [`RootInfoSnapshot`] in place
/// (caller-owned `out_snapshot` storage). Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`RootInfoSnapshot`] produced by an ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_root_info_snapshot_free(value: *mut RootInfoSnapshot) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Tag for [`RootInfoChange`]. Mirrors `ovstorage_layer::RootInfoChange`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RootInfoChangeTag {
    Snapshot = 0,
    Added = 1,
    Removed = 2,
    Updated = 3,
}

/// One frame in a [`RootInfoChangeStream`]. All variants carry the same
/// payload shape — a list of roots — so a single discriminated struct
/// suffices.
#[repr(C)]
pub struct RootInfoChange {
    pub tag: RootInfoChangeTag,
    pub roots: List<RootInfo>,
}

unsafe impl Send for RootInfoChange {}

/// Drop a [`RootInfoChange`] in place. Safe with NULL. The pointee is
/// caller-owned `out_item` storage.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`RootInfoChange`] produced by an ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_root_info_change_free(value: *mut RootInfoChange) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// `next_fn` signature for [`RootInfoChangeStream`].
pub type RootInfoChangeNextFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    out_item: *mut RootInfoChange,
    out_error: *mut Error,
) -> StreamStep;

/// Plugin-emitted iterator over `Result<RootInfoChange>` — the
/// `list_address_roots` update channel. Same `(state, next_fn, drop_fn)`
/// pull shape as [`BackendChangeStream`].
#[repr(C)]
pub struct RootInfoChangeStream {
    pub state: *mut core::ffi::c_void,
    pub next_fn: RootInfoChangeNextFn,
    pub drop_fn: StreamDropFn,
}

unsafe impl Send for RootInfoChangeStream {}

impl Drop for RootInfoChangeStream {
    fn drop(&mut self) {
        // SAFETY: `drop_fn` is valid for the lifetime of `state`.
        unsafe { (self.drop_fn)(self.state) }
    }
}

/// Reclaim a heap-allocated [`RootInfoChangeStream`]. Drives `drop_fn`
/// exactly once before releasing the outer allocation. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_root_info_change_stream_free(
    value: *mut RootInfoChangeStream,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

// ---------------------------------------------------------------------
// Connection introspection (`list_connections`)
// ---------------------------------------------------------------------

/// Complete snapshot of the connections owned beneath a Layer, returned
/// by `list_connections`. Reuses the existing [`Connection`] shadow.
#[repr(C)]
pub struct ConnectionSnapshot {
    pub connections: List<Connection>,
    pub updates: bool,
}

unsafe impl Send for ConnectionSnapshot {}

/// Release the nested allocations of a [`ConnectionSnapshot`] in place
/// (caller-owned `out_snapshot` storage). Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`ConnectionSnapshot`] produced by an ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_connection_snapshot_free(value: *mut ConnectionSnapshot) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Tag for [`ConnectionChange`]. Mirrors
/// `ovstorage_layer::ConnectionChange`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionChangeTag {
    Added = 0,
    Removed = 1,
    Updated = 2,
    Snapshot = 3,
}

/// One frame in a [`ConnectionChangeStream`]. `Added` / `Updated` carry
/// a single connection in `connection`; `Snapshot` carries the full set
/// in `connections`; `Removed` carries only `removed_id`.
#[repr(C)]
pub struct ConnectionChange {
    pub tag: ConnectionChangeTag,
    pub connection: Optional<Connection>,
    pub connections: List<Connection>,
    pub removed_id: Optional<ConnectionId>,
}

unsafe impl Send for ConnectionChange {}

/// Drop a [`ConnectionChange`] in place. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`ConnectionChange`] produced by an ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_connection_change_free(value: *mut ConnectionChange) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// `next_fn` signature for [`ConnectionChangeStream`].
pub type ConnectionChangeNextFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    out_item: *mut ConnectionChange,
    out_error: *mut Error,
) -> StreamStep;

/// Plugin-emitted iterator over `Result<ConnectionChange>` — the
/// `list_connections` update channel.
#[repr(C)]
pub struct ConnectionChangeStream {
    pub state: *mut core::ffi::c_void,
    pub next_fn: ConnectionChangeNextFn,
    pub drop_fn: StreamDropFn,
}

unsafe impl Send for ConnectionChangeStream {}

impl Drop for ConnectionChangeStream {
    fn drop(&mut self) {
        // SAFETY: `drop_fn` is valid for the lifetime of `state`.
        unsafe { (self.drop_fn)(self.state) }
    }
}

/// Reclaim a heap-allocated [`ConnectionChangeStream`]. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_connection_change_stream_free(
    value: *mut ConnectionChangeStream,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

// ---------------------------------------------------------------------
// Paged object results (`list`, `list_versions`)
// ---------------------------------------------------------------------

/// One page of objects returned by `list`, including the in-band continuation
/// token. Mirrors `ovstorage_layer::ListPage`.
#[repr(C)]
pub struct ListPage {
    pub items: List<ObjectInfo>,
    pub next_page_token: Optional<Str>,
}

unsafe impl Send for ListPage {}

/// Reclaim a heap-allocated [`ListPage`]. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_list_page_free(value: *mut ListPage) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

/// One page of versions, returned by `list_versions`. Mirrors
/// `ovstorage_layer::VersionPage` (identical shape to [`ListPage`]; kept
/// distinct so the two slots' result types are unambiguous).
#[repr(C)]
pub struct VersionPage {
    pub items: List<ObjectInfo>,
    pub next_page_token: Optional<Str>,
}

unsafe impl Send for VersionPage {}

/// Reclaim a heap-allocated [`VersionPage`]. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_version_page_free(value: *mut VersionPage) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

// ---------------------------------------------------------------------
// Connection-management request payloads
// ---------------------------------------------------------------------

/// `(target, id)` connection identity. `target` names the owning Layer;
/// `id` is unique within it. Mirrors `ovstorage_layer::ConnectionKey`.
#[repr(C)]
pub struct ConnectionKey {
    pub target: Str,
    pub id: Str,
}

unsafe impl Send for ConnectionKey {}

/// Request to create or probe a connection on a specific Layer. `target`
/// names the owning Layer; the embedded [`ConnectionRequest`] carries
/// the kind-specific config + credentials. Mirrors
/// `ovstorage_layer::LayerConnectionRequest`.
#[repr(C)]
pub struct LayerConnectionRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub target: Str,
    pub connection: ConnectionRequest,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for LayerConnectionRequest {}

/// Request payload for the `remove_connection` slot: the standard
/// `{struct_size, extensions}` request prefix around the `(target, id)`
/// [`ConnectionKey`], so producer-stamped extensions cross this slot like
/// every other Layer operation. Mirrors
/// `Request<ovstorage_layer::ConnectionKey>`.
#[repr(C)]
pub struct RemoveConnectionRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub key: ConnectionKey,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for RemoveConnectionRequest {}

/// Independently-optional patch applied by `update_connection_attributes`
/// (absent field = leave unchanged). Mirrors
/// `ovstorage_layer::AttributePatch`. Credentials never appear here; they
/// flow only through `update_connection_credentials`.
#[repr(C)]
pub struct AttributePatch {
    pub display_name: Optional<Str>,
    pub access_mode: Optional<Str>,
    pub visible: Optional<bool>,
    /// Keys to set or overwrite.
    pub set_user_metadata: KeyValueList,
    /// Keys to delete.
    pub remove_user_metadata: List<Str>,
}

unsafe impl Send for AttributePatch {}

/// Request payload for the `authenticate_connection` slot. Mirrors
/// `ovstorage_layer::AuthenticateRequest`.
#[repr(C)]
pub struct AuthenticateRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub key: ConnectionKey,
    pub capability: InteractiveAuthCapabilityV1,
    pub auto_open_browser: bool,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for AuthenticateRequest {}

/// Request payload for the `update_connection_credentials` slot. Mirrors
/// `ovstorage_layer::UpdateConnectionCredentialsRequest`.
#[repr(C)]
pub struct UpdateConnectionCredentialsRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub key: ConnectionKey,
    pub credentials: SecretBundle,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for UpdateConnectionCredentialsRequest {}

/// Request payload for the `update_connection_attributes` slot. Mirrors
/// `ovstorage_layer::UpdateConnectionAttributesRequest`.
#[repr(C)]
pub struct UpdateConnectionAttributesRequest {
    pub struct_size: usize,
    pub extensions: *const Extensions,
    pub key: ConnectionKey,
    pub patch: AttributePatch,
    pub _reserved: [*mut core::ffi::c_void; 8],
}

unsafe impl Send for UpdateConnectionAttributesRequest {}
