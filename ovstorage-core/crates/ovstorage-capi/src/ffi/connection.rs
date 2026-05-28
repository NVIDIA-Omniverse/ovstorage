// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Read-side types: `CapabilitiesV1` (flat), `Connection` (opaque)
//! and friends.
//!
//! `CapabilitiesV1` is `#[repr(C)]` with `struct_size` versioning
//! and `has_*` companions for optional fields — the caller
//! stack-allocates and passes a `*mut` to a getter that fills it.
//! Flat layout is the right shape here because every field is a
//! by-value primitive.
//!
//! `Connection` is opaque: it carries variable-length data
//! (addresses, user metadata) and enum-variant payloads (source,
//! auth_state). Accessors expose individual fields; nested
//! capabilities are filled into a caller-provided out-pointer via
//! `ovstorage_connection_capabilities`.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::time::UNIX_EPOCH;

use ovstorage::{Capabilities, ConnectionAuthState, ConnectionSource};

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangeKindSet {
    pub created: bool,
    pub modified: bool,
    pub deleted: bool,
    pub metadata_changed: bool,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VersionListOrder {
    Newest = 0,
    Oldest = 1,
    Unordered = 2,
}

/// Flat capabilities struct. Caller stack-allocates and sets
/// `struct_size = sizeof(OvStorage_CapabilitiesV1)` before passing a
/// `*mut` to a getter. The host writes only fields up to the caller's
/// `struct_size`, so older callers compiled against a smaller v1
/// remain ABI-compatible.
#[repr(C)]
pub struct CapabilitiesV1 {
    pub struct_size: usize,
    pub supports_if_match_write: bool,
    pub supports_no_overwrite_write: bool,
    pub supports_native_metadata_patch: bool,
    pub supports_metadata_rewrite_emulation: bool,
    pub writes_are_atomic: bool,
    pub supports_server_side_copy: bool,
    pub supports_server_side_rename: bool,
    pub supports_atomic_rename: bool,
    pub has_real_directories: bool,
    pub supports_list: bool,
    pub wants_list_backed_stat: bool,
    pub supports_recursive_list: bool,
    pub populates_subdirectory_metadata: bool,
    pub supports_version_listing: bool,
    pub has_version_list_order: bool,
    pub version_list_order: VersionListOrder,
    pub populates_effective_permissions_on_stat: bool,
    pub supports_access_check: bool,
    pub supports_watch_directory: bool,
    pub watch_directory_kinds: ChangeKindSet,
    pub watch_directory_resumable: bool,
    pub has_watch_directory_max_lag: bool,
    pub watch_directory_max_lag_nanos: u64,
    pub has_redirect_size_threshold: bool,
    pub redirect_size_threshold: u64,
}

fn change_kind_set_to_ffi(set: &ovstorage::ChangeKindSet) -> ChangeKindSet {
    ChangeKindSet {
        created: set.created,
        modified: set.modified,
        deleted: set.deleted,
        metadata_changed: set.metadata_changed,
    }
}

fn version_list_order_to_ffi(order: &ovstorage::VersionListOrder) -> VersionListOrder {
    match order {
        ovstorage::VersionListOrder::Newest => VersionListOrder::Newest,
        ovstorage::VersionListOrder::Oldest => VersionListOrder::Oldest,
        ovstorage::VersionListOrder::Unordered => VersionListOrder::Unordered,
    }
}

/// Fill a caller-provided `CapabilitiesV1`. Validates `struct_size`
/// and clamps the writeable region to whatever the caller advertised,
/// so older callers compiled against a smaller v1 see only the prefix
/// they expected.
pub(crate) fn write_capabilities(caps: &Capabilities, out: *mut CapabilitiesV1) {
    if out.is_null() {
        return;
    }
    let caller_size = unsafe { (*out).struct_size };
    let our_size = std::mem::size_of::<CapabilitiesV1>();
    let effective = caller_size.min(our_size);
    // Zero the caller's region up to `effective` bytes, then write
    // the fields we know about. Anything past `effective` is host-only.
    if effective < std::mem::size_of::<usize>() {
        // Caller didn't reserve room for struct_size; bail.
        return;
    }
    unsafe {
        std::ptr::write_bytes(out as *mut u8, 0, effective);
        let v1 = CapabilitiesV1 {
            struct_size: effective,
            supports_if_match_write: caps.supports_if_match_write,
            supports_no_overwrite_write: caps.supports_no_overwrite_write,
            supports_native_metadata_patch: caps.supports_native_metadata_patch,
            supports_metadata_rewrite_emulation: caps.supports_metadata_rewrite_emulation,
            writes_are_atomic: caps.writes_are_atomic,
            supports_server_side_copy: caps.supports_server_side_copy,
            supports_server_side_rename: caps.supports_server_side_rename,
            supports_atomic_rename: caps.supports_atomic_rename,
            has_real_directories: caps.has_real_directories,
            supports_list: caps.supports_list,
            wants_list_backed_stat: caps.wants_list_backed_stat,
            supports_recursive_list: caps.supports_recursive_list,
            populates_subdirectory_metadata: caps.populates_subdirectory_metadata,
            supports_version_listing: caps.supports_version_listing,
            has_version_list_order: caps.version_list_order.is_some(),
            version_list_order: caps
                .version_list_order
                .as_ref()
                .map(version_list_order_to_ffi)
                .unwrap_or(VersionListOrder::Newest),
            populates_effective_permissions_on_stat: caps.populates_effective_permissions_on_stat,
            supports_access_check: caps.supports_access_check,
            supports_watch_directory: caps.supports_watch_directory,
            watch_directory_kinds: change_kind_set_to_ffi(&caps.watch_directory_kinds),
            watch_directory_resumable: caps.watch_directory_resumable,
            has_watch_directory_max_lag: caps.watch_directory_max_lag.is_some(),
            watch_directory_max_lag_nanos: caps
                .watch_directory_max_lag
                .map_or(0, |d| d.as_nanos() as u64),
            has_redirect_size_threshold: caps.redirect_size_threshold.is_some(),
            redirect_size_threshold: caps.redirect_size_threshold.unwrap_or(0),
        };
        std::ptr::copy_nonoverlapping(&v1 as *const _ as *const u8, out as *mut u8, effective);
    }
}

// ---------------------------------------------------------------------
// ConnectionSource / ConfigLayer enums
// ---------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionSourceKind {
    Static = 0,
    Runtime = 1,
    BrokerDelivered = 2,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigLayer {
    Programmatic = 0,
    Env = 1,
    Project = 2,
    User = 3,
    Machine = 4,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionAuthStateKind {
    Authenticated = 0,
    AwaitingAuth = 1,
    AuthFailed = 2,
    Anonymous = 3,
}

fn config_layer_to_ffi(layer: &ovstorage::ConfigLayer) -> ConfigLayer {
    match layer {
        ovstorage::ConfigLayer::Programmatic => ConfigLayer::Programmatic,
        ovstorage::ConfigLayer::Env => ConfigLayer::Env,
        ovstorage::ConfigLayer::Project => ConfigLayer::Project,
        ovstorage::ConfigLayer::User => ConfigLayer::User,
        ovstorage::ConfigLayer::Machine => ConfigLayer::Machine,
    }
}

fn cstring_lossy(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|err| {
        let bytes = err.into_vec();
        let bytes: Vec<u8> = bytes.into_iter().filter(|b| *b != 0).collect();
        CString::new(bytes).unwrap_or_default()
    })
}

// ---------------------------------------------------------------------
// Connection (opaque)
// ---------------------------------------------------------------------

/// Opaque connection handle. Owned strings are pre-baked into
/// CStrings so per-field accessors return borrowed pointers valid
/// for the lifetime of the handle.
///
/// Variant payloads for the `Authenticated` and `AwaitingAuth`
/// auth-state variants are not yet exposed; only `Anonymous` and
/// `AuthFailed` are reachable today.
pub struct Connection {
    pub(crate) inner: ovstorage::Connection,
    id: CString,
    backend_kind: CString,
    display_name: CString,
    addresses: Vec<CString>,
    user_metadata: Vec<(CString, CString)>,
    source_broker_principal: Option<CString>,
    auth_failed_message: Option<CString>,
}

impl Connection {
    pub(crate) fn from_connection(conn: ovstorage::Connection) -> Self {
        let id = cstring_lossy(&conn.id.0);
        let backend_kind = cstring_lossy(&conn.backend_kind);
        let display_name = cstring_lossy(&conn.display_name);
        let addresses = conn
            .current_addresses
            .iter()
            .map(|url| cstring_lossy(url.as_str()))
            .collect();
        let user_metadata = conn
            .user_metadata
            .iter()
            .map(|(k, v)| (cstring_lossy(k), cstring_lossy(v)))
            .collect();
        let source_broker_principal = match &conn.source {
            ConnectionSource::BrokerDelivered { broker_principal } => {
                Some(cstring_lossy(broker_principal))
            }
            _ => None,
        };
        let auth_failed_message = match &conn.auth_state {
            ConnectionAuthState::AuthFailed { error, .. } => Some(cstring_lossy(error.message())),
            _ => None,
        };
        Self {
            inner: conn,
            id,
            backend_kind,
            display_name,
            addresses,
            user_metadata,
            source_broker_principal,
            auth_failed_message,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_destroy(connection: *mut Connection) {
    unsafe {
        if connection.is_null() {
            return;
        }
        drop(Box::from_raw(connection));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_id(connection: *const Connection) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe { (*connection).id.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_backend_kind(
    connection: *const Connection,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe { (*connection).backend_kind.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_display_name(
    connection: *const Connection,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe { (*connection).display_name.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_has_last_probed(
    connection: *const Connection,
) -> bool {
    if connection.is_null() {
        return false;
    }
    unsafe { (*connection).inner.last_probed.is_some() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_last_probed_unix_nanos(
    connection: *const Connection,
) -> u64 {
    if connection.is_null() {
        return 0;
    }
    unsafe {
        (*connection)
            .inner
            .last_probed
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as u64)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_address_count(
    connection: *const Connection,
) -> usize {
    if connection.is_null() {
        return 0;
    }
    unsafe { (*connection).addresses.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_address_at(
    connection: *const Connection,
    index: usize,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe {
        let conn = &*connection;
        conn.addresses
            .get(index)
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_user_metadata_count(
    connection: *const Connection,
) -> usize {
    if connection.is_null() {
        return 0;
    }
    unsafe { (*connection).user_metadata.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_user_metadata_key(
    connection: *const Connection,
    index: usize,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe {
        let conn = &*connection;
        conn.user_metadata
            .get(index)
            .map_or(ptr::null(), |(k, _)| k.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_user_metadata_value(
    connection: *const Connection,
    index: usize,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe {
        let conn = &*connection;
        conn.user_metadata
            .get(index)
            .map_or(ptr::null(), |(_, v)| v.as_ptr())
    }
}

/// Fill the caller-provided `out` with the connection's capabilities.
/// Caller must initialize `out->struct_size = sizeof(...)` before
/// calling. No-op if `connection` or `out` is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_capabilities(
    connection: *const Connection,
    out: *mut CapabilitiesV1,
) {
    if connection.is_null() {
        return;
    }
    unsafe { write_capabilities(&(*connection).inner.capabilities, out) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_source_kind(
    connection: *const Connection,
) -> ConnectionSourceKind {
    if connection.is_null() {
        return ConnectionSourceKind::Runtime;
    }
    unsafe {
        match &(*connection).inner.source {
            ConnectionSource::Static { .. } => ConnectionSourceKind::Static,
            ConnectionSource::Runtime { .. } => ConnectionSourceKind::Runtime,
            ConnectionSource::BrokerDelivered { .. } => ConnectionSourceKind::BrokerDelivered,
        }
    }
}

/// Returns the layer for the `Static` variant. Returns
/// `Programmatic` for any other variant (caller should check
/// `_source_kind` first).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_source_static_layer(
    connection: *const Connection,
) -> ConfigLayer {
    if connection.is_null() {
        return ConfigLayer::Programmatic;
    }
    unsafe {
        match &(*connection).inner.source {
            ConnectionSource::Static { layer } => config_layer_to_ffi(layer),
            _ => ConfigLayer::Programmatic,
        }
    }
}

/// Returns `persisted` for the `Runtime` variant. Returns false for
/// any other variant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_source_runtime_persisted(
    connection: *const Connection,
) -> bool {
    if connection.is_null() {
        return false;
    }
    unsafe {
        match &(*connection).inner.source {
            ConnectionSource::Runtime { persisted } => *persisted,
            _ => false,
        }
    }
}

/// Returns the broker principal cstring for the `BrokerDelivered`
/// variant. Returns null for any other variant. Borrowed; valid as
/// long as the connection handle is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_source_broker_principal(
    connection: *const Connection,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe {
        (*connection)
            .source_broker_principal
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_auth_state_kind(
    connection: *const Connection,
) -> ConnectionAuthStateKind {
    if connection.is_null() {
        return ConnectionAuthStateKind::Anonymous;
    }
    unsafe {
        match &(*connection).inner.auth_state {
            ConnectionAuthState::Authenticated { .. } => ConnectionAuthStateKind::Authenticated,
            ConnectionAuthState::AwaitingAuth { .. } => ConnectionAuthStateKind::AwaitingAuth,
            ConnectionAuthState::AuthFailed { .. } => ConnectionAuthStateKind::AuthFailed,
            ConnectionAuthState::Anonymous => ConnectionAuthStateKind::Anonymous,
        }
    }
}

/// Returns the error message for the AuthFailed variant. Returns
/// NULL for any other variant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_auth_state_failed_message(
    connection: *const Connection,
) -> *const c_char {
    if connection.is_null() {
        return ptr::null();
    }
    unsafe {
        (*connection)
            .auth_failed_message
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

/// Returns the failed-attempt count for the `AuthFailed` variant.
/// Returns 0 for any other variant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_auth_state_failed_attempts(
    connection: *const Connection,
) -> u32 {
    if connection.is_null() {
        return 0;
    }
    unsafe {
        match &(*connection).inner.auth_state {
            ConnectionAuthState::AuthFailed { attempts, .. } => *attempts,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------
// ConnectionList
// ---------------------------------------------------------------------

/// Opaque list of `Connection` handles returned by
/// `ovstorage_library_list_connections`. Items are borrowed from the
/// list — do NOT call `ovstorage_connection_destroy` on items;
/// destroying the list frees them.
pub struct ConnectionList {
    pub(crate) items: Vec<Connection>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_list_destroy(list: *mut ConnectionList) {
    unsafe {
        if list.is_null() {
            return;
        }
        drop(Box::from_raw(list));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_list_len(list: *const ConnectionList) -> usize {
    if list.is_null() {
        return 0;
    }
    unsafe { (*list).items.len() }
}

/// Returns a borrowed `*const Connection` valid until the list handle
/// is destroyed. Returns null if `index` is out of range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_list_item_at(
    list: *const ConnectionList,
    index: usize,
) -> *const Connection {
    if list.is_null() {
        return ptr::null();
    }
    unsafe {
        let l = &*list;
        l.items
            .get(index)
            .map_or(ptr::null(), |c| c as *const Connection)
    }
}
