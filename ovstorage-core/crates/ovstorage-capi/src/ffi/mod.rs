// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! C ABI types and thunks exported by the cdylib.
//!
//! This file owns type definitions, synchronous lifecycle
//! (init/shutdown/cancel-token), accessor getters, parsers, handle
//! constructors, and error mapping. Async I/O thunks live in `ops.rs`;
//! connection-management surface lives in `builders.rs` and
//! `connection.rs`.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use tokio::runtime::Runtime;

use ovstorage::{
    ByteRange, CancellationToken, CreateDirectoryOptions, DeleteDirectoryOptions, ErrorCode,
    IfDestExists, ListOptions, ListVersionsOptions, ObjectInfo, ObjectKind as CoreObjectKind,
    ReadOptions, StatOptions, Url, WriteOptions, address,
};

pub mod aliases;
pub use aliases::*;

pub mod auth;
pub use auth::*;

pub mod builders;
pub use builders::*;

pub mod connection;
pub use connection::*;

pub mod credential;
pub use credential::*;

pub mod discovery;
pub use discovery::*;

pub mod ops;
pub use ops::*;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    AlreadyExists = 2,
    PermissionDenied = 3,
    PreconditionFailed = 4,
    Conflict = 5,
    DirectoryNotEmpty = 6,
    Unsupported = 7,
    InvalidArgument = 8,
    ObjectModified = 9,
    NoRoute = 10,
    Transient = 11,
    Cancelled = 12,
    Internal = 255,
}

#[repr(C)]
pub struct Error {
    pub code: Status,
    pub message: *mut c_char,
}

/// Reserved trailing padding on every public V1 options struct.
///
/// 8 pointer-sized slots reserved for future fields. Callers MUST
/// zero-initialize every slot. New fields are added before
/// `_reserved`; existing fields are never reordered.
pub type ReservedOptionsPadding = [*const core::ffi::c_void; 8];

/// Zero-initialized [`ReservedOptionsPadding`] value.
pub const RESERVED_OPTIONS_PADDING_ZERO: ReservedOptionsPadding = [std::ptr::null(); 8];

#[repr(C)]
pub struct InitAuthSubstrateOptionsV1 {
    pub struct_size: usize,
    /// Borrowed C-string. `NULL` resolves to `$OVSTORAGE_AUTH_DIR` or
    /// a per-process temp dir. Calling
    /// [`ovstorage_init_auth_substrate`] twice with the same resolved
    /// path is a no-op; calling it with a different path returns
    /// [`Status::Unsupported`].
    pub auth_dir: *const c_char,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct LibraryInitOptionsV1 {
    pub struct_size: usize,
    /// Number of worker threads for the library's async runtime.
    /// `0` selects the default (2). Pick based on expected request
    /// fan-out.
    pub runtime_threads: u32,
    /// Host-declared interactive-auth capability.
    /// `-1`=unspecified (use smart default + env-var precedence),
    /// `0`=Browser, `1`=Headless, `2`=None.
    pub interactive_auth_capability: i32,
    /// Credential cache durability. Values match
    /// [`OvCredentialCacheDurability`]: `0`=Persistent (default),
    /// `1`=InMemoryOnly. Older callers (smaller `struct_size`) get
    /// the Persistent default automatically.
    pub credential_cache_durability: i32,
    /// When `true`, registers `credential_callback` as an external
    /// credential provider; `credential_callback_name` is then
    /// required (used in trace span attributes).
    pub has_credential_callback: bool,
    pub credential_callback: credential::OvCredentialCallback,
    /// Borrowed C-string. Required when `has_credential_callback`
    /// is `true`; ignored otherwise.
    pub credential_callback_name: *const c_char,
    /// Allow loading cdylibs whose manifest declares `test_only=true`.
    /// Production callers must leave this `false`.
    pub allow_test_plugins: bool,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct StatOptionsV1 {
    pub struct_size: usize,
    pub full_metadata: bool,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct ReadOptionsV1 {
    pub struct_size: usize,
    pub has_range: bool,
    pub range_start: u64,
    pub has_range_end: bool,
    pub range_end_inclusive: u64,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct WriteOptionsV1 {
    pub struct_size: usize,
    pub no_overwrite: bool,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct ListOptionsV1 {
    pub struct_size: usize,
    pub recursive: bool,
    pub has_max_results: bool,
    pub max_results: u32,
    pub page_token: *const c_char,
    pub full_metadata: bool,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct ListVersionsOptionsV1 {
    pub struct_size: usize,
    pub has_max_results: bool,
    pub max_results: u32,
    pub page_token: *const c_char,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct CreateDirectoryOptionsV1 {
    pub struct_size: usize,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct DeleteDirectoryOptionsV1 {
    pub struct_size: usize,
    pub _reserved: ReservedOptionsPadding,
}

#[repr(C)]
pub struct AccessOps {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub update_metadata: bool,
}

#[repr(C)]
pub struct AccessDecision {
    pub allowed: bool,
    pub denied_ops: AccessOps,
    pub reason: *mut c_char,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    File = 0,
    Directory = 1,
    DirectoryMarker = 2,
    DirectoryInferred = 3,
}

impl From<CoreObjectKind> for ObjectKind {
    fn from(kind: CoreObjectKind) -> Self {
        match kind {
            CoreObjectKind::File => Self::File,
            CoreObjectKind::Directory => Self::Directory,
            CoreObjectKind::DirectoryMarker => Self::DirectoryMarker,
            CoreObjectKind::DirectoryInferred => Self::DirectoryInferred,
        }
    }
}

#[repr(C)]
pub struct Bytes {
    pub data: *const u8,
    pub len: usize,
    pub free_ctx: *mut c_void,
}

// --- callback type aliases ----------------------------------------

pub type StatusCallback =
    Option<unsafe extern "C" fn(status: Status, error: *const Error, user_data: *mut c_void)>;

pub type InfoCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        info: *mut Info,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ReadBytesCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        bytes: Bytes,
        info: *mut Info,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ReadLocalFileCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        delegate: *mut LocalDelegate,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ListCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut List,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ListVersionsCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut VersionList,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type CheckAccessCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        decision: AccessDecision,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ConnectionCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        connection: *mut crate::Connection, /* owned by caller on Ok */
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ConnectionListCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut crate::ConnectionList, /* owned by caller on Ok */
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

/// Multi-fire callback for `ovstorage_library_authenticate_connection`.
///
/// Per-event fire: `event != NULL`, `error == NULL`, `done == false`;
/// the caller owns `event` and must free it with
/// `ovstorage_auth_event_destroy`.
/// Final fire on success: `event == NULL`, `error == NULL`, `done == true`.
/// Final fire on terminal error: `event == NULL`, `error != NULL`,
/// `done == true`; the error message is freed by the host after the
/// callback returns.
pub type AuthEventCallback = Option<
    unsafe extern "C" fn(
        event: *mut crate::AuthEvent,
        error: *const Error,
        done: bool,
        user_data: *mut c_void,
    ),
>;

pub type AliasCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        alias: *mut crate::Alias, /* owned by caller on Ok */
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type AliasListCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut crate::AliasList, /* owned by caller on Ok */
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

/// Multi-fire callback for `ovstorage_library_watch_address_roots`.
/// The caller owns each `list` snapshot and must free it with
/// `ovstorage_address_root_list_destroy`.
pub type AddressRootWatchCallback = Option<
    unsafe extern "C" fn(
        list: *mut crate::AddressRootList,
        error: *const Error,
        done: bool,
        user_data: *mut c_void,
    ),
>;

pub type AddressVisibilityOverrideCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        result: *mut crate::AddressVisibilityOverride,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type AddressVisibilityOverrideListCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut crate::AddressVisibilityOverrideList,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type AddressRootListCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut crate::AddressRootList,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type BackendKindDescriptorListCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        list: *mut crate::BackendKindDescriptorList,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

/// Callback for `ovstorage_library_capabilities_for`. The `caps`
/// pointer is borrowed for the duration of the callback only — copy
/// the struct if you need to retain it.
pub type CapabilitiesCallback = Option<
    unsafe extern "C" fn(
        status: Status,
        caps: *const crate::CapabilitiesV1,
        error: *const Error,
        user_data: *mut c_void,
    ),
>;

pub type ReadStreamCallback = Option<
    unsafe extern "C" fn(chunk: Bytes, error: *const Error, done: bool, user_data: *mut c_void),
>;

// --- opaque handle types ------------------------------------------

pub struct Library {
    /// Public for in-tree Rust consumers (rlib path + integration
    /// tests). C callers see only `*mut Library` and never dereference.
    pub inner: Arc<ovstorage::Library>,
    pub runtime: Arc<Runtime>,
}

pub struct CancelToken {
    pub inner: CancellationToken,
}

pub struct Info {
    info: ObjectInfo,
    address: CString,
    etag: Option<CString>,
    version: Option<CString>,
    system_metadata: Vec<MetadataEntry>,
    user_metadata: Vec<MetadataEntry>,
}

pub struct LocalDelegate {
    #[allow(dead_code)]
    delegate: ovstorage::LocalDelegate,
    path: CString,
    info: Box<Info>,
}

pub struct List {
    items: Vec<ListEntry>,
    next_page_token: Option<CString>,
}

pub struct VersionList {
    items: Vec<VersionEntry>,
    next_page_token: Option<CString>,
}

pub struct UpdateMetadataOptions {
    set: Vec<(String, String)>,
    remove: Vec<String>,
}

struct MetadataEntry {
    key: CString,
    value: CString,
}

struct ListEntry {
    address: CString,
    info: ObjectInfo,
}

struct VersionEntry {
    address: CString,
    info: ObjectInfo,
}

// --- error helpers ------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_error_clear(error: *mut Error) {
    unsafe {
        if error.is_null() {
            return;
        }
        if !(*error).message.is_null() {
            let _ = CString::from_raw((*error).message);
        }
        (*error).code = Status::Ok;
        (*error).message = ptr::null_mut();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_error_message(error: *const Error) -> *const c_char {
    unsafe {
        if error.is_null() {
            return ptr::null();
        }
        (*error).message
    }
}

// --- library init / shutdown --------------------------------------

/// Initialize a library handle. Builds a dedicated async runtime sized by
/// `options.runtime_threads` and returns a handle the caller must free with
/// `ovstorage_library_shutdown`. No plugins are loaded and no routes bound;
/// follow with `ovstorage_library_load_plugins_from_dir` (and optionally
/// `ovstorage_library_load_config`) before calling object operations.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_init(
    options: *const LibraryInitOptionsV1,
    out_library: *mut *mut Library,
    out_error: *mut Error,
) -> Status {
    run_sync(out_error, || {
        let init_options = unsafe { library_init_options(options) }?;
        let out = unsafe { required_mut(out_library, "out_library") }?;
        ovstorage::ensure_auth_substrate_with_default(capi_auth_state_root)?;
        let mut builder = ovstorage::Library::builder()
            .allow_test_plugins(init_options.allow_test_plugins)
            .with_credential_cache_durability(init_options.credential_cache_durability.to_rust());
        if let Some(capability) = init_options.interactive_auth_capability {
            builder = builder.interactive_auth_capability(capability);
        }
        if let Some((name, callback)) = init_options.credential_callback {
            let provider = credential::build_callback_provider(name, callback)?;
            let providers: Vec<Arc<dyn ovstorage::auth::CredentialProvider>> = vec![provider];
            builder = builder.with_credential_providers(providers);
        }
        let inner = builder.open()?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(init_options.runtime_threads)
            .enable_all()
            .thread_name("ovs-capi")
            .build()
            .map_err(|err| {
                ovstorage::Error::new(
                    ErrorCode::Internal,
                    format!("failed to build runtime: {err}"),
                )
            })?;
        *out = Box::into_raw(Box::new(Library {
            inner,
            runtime: Arc::new(runtime),
        }));
        Ok(())
    })
}

/// Explicitly initialize the process-global auth substrate.
///
/// The plugin SPI's host callbacks are set-once-per-process (see the
/// loader comment in `ovstorage::loader::register_host_substrate`), so
/// the `(SecretStore, AuthRefreshLock)` pair is shared across every
/// [`ovstorage_library_init`] call in one process. This function lets
/// callers pin a non-default `auth_dir` before any `Library` is built.
///
/// `options = NULL` uses the default `auth_dir` (resolved from
/// `$OVSTORAGE_AUTH_DIR` or a per-process temp dir). Calling this
/// twice with the same resolved path is a no-op; calling it with a
/// different path returns [`Status::Unsupported`]. Calling
/// [`ovstorage_library_init`] before this function auto-initializes
/// the substrate with the default `auth_dir`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_init_auth_substrate(
    options: *const InitAuthSubstrateOptionsV1,
    out_error: *mut Error,
) -> Status {
    run_sync(out_error, || {
        let auth_dir = unsafe { init_auth_substrate_auth_dir(options)? };
        let auth_root = match auth_dir {
            Some(path) => std::path::PathBuf::from(path),
            None => capi_auth_state_root()?,
        };
        ovstorage::init_auth_substrate(Some(&auth_root))
    })
}

unsafe fn init_auth_substrate_auth_dir(
    ptr: *const InitAuthSubstrateOptionsV1,
) -> ovstorage::Result<Option<String>> {
    unsafe {
        if ptr.is_null() {
            return Ok(None);
        }
        validate_struct_size::<InitAuthSubstrateOptionsV1>(
            (*ptr).struct_size,
            "init_auth_substrate_options",
        )?;
        if (*ptr).auth_dir.is_null() {
            Ok(None)
        } else {
            Ok(Some(cstr_to_string((*ptr).auth_dir, "auth_dir")?))
        }
    }
}

/// Shut down a library and join its runtime workers. Must NOT be
/// called from within an `on_complete` callback — dropping the
/// runtime from a worker thread aborts the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_shutdown(library: *mut Library) {
    if !library.is_null() {
        let _ = unsafe { Box::from_raw(library) };
    }
}

// --- cancel token -------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_cancel_token_create() -> *mut CancelToken {
    Box::into_raw(Box::new(CancelToken {
        inner: CancellationToken::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_cancel_token_destroy(token: *mut CancelToken) {
    if !token.is_null() {
        let _ = unsafe { Box::from_raw(token) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_cancel_token_cancel(token: *const CancelToken) {
    let Some(token) = (unsafe { token.as_ref() }) else {
        return;
    };
    token.inner.cancel();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_cancel_token_is_canceled(token: *const CancelToken) -> bool {
    (unsafe { token.as_ref() })
        .map(|token| token.inner.is_cancelled())
        .unwrap_or(false)
}

// --- update_metadata_options builders -----------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_update_metadata_options_create() -> *mut UpdateMetadataOptions {
    Box::into_raw(Box::new(UpdateMetadataOptions {
        set: Vec::new(),
        remove: Vec::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_update_metadata_options_destroy(
    options: *mut UpdateMetadataOptions,
) {
    if !options.is_null() {
        let _ = unsafe { Box::from_raw(options) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_update_metadata_options_set(
    options: *mut UpdateMetadataOptions,
    key: *const c_char,
    value: *const c_char,
    out_error: *mut Error,
) -> Status {
    run_sync(out_error, || {
        unsafe { required_mut(options, "options") }?
            .set
            .push((unsafe { cstr_to_string(key, "key") }?, unsafe {
                cstr_to_string(value, "value")
            }?));
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_update_metadata_options_remove(
    options: *mut UpdateMetadataOptions,
    key: *const c_char,
    out_error: *mut Error,
) -> Status {
    run_sync(out_error, || {
        unsafe { required_mut(options, "options") }?
            .remove
            .push(unsafe { cstr_to_string(key, "key") }?);
        Ok(())
    })
}

// --- access_decision destructors ----------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_access_decision_clear(decision: *mut AccessDecision) {
    unsafe {
        if decision.is_null() {
            return;
        }
        if !(*decision).reason.is_null() {
            let _ = CString::from_raw((*decision).reason);
        }
        (*decision).reason = ptr::null_mut();
    }
}

// --- bytes_t / info_t accessors -----------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_bytes_destroy(bytes: *mut Bytes) {
    unsafe {
        if bytes.is_null() {
            return;
        }
        if !(*bytes).free_ctx.is_null() {
            let _ = Box::from_raw((*bytes).free_ctx as *mut Vec<u8>);
        }
        (*bytes).data = ptr::null();
        (*bytes).len = 0;
        (*bytes).free_ctx = ptr::null_mut();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_destroy(info: *mut Info) {
    if !info.is_null() {
        let _ = unsafe { Box::from_raw(info) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_address(info: *const Info) -> *const c_char {
    unsafe { required_ref(info, "info") }
        .map(|info| info.address.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_kind(info: *const Info) -> ObjectKind {
    unsafe { required_ref(info, "info") }
        .map(|info| info.info.kind.into())
        .unwrap_or(ObjectKind::File)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_has_size(info: *const Info) -> bool {
    unsafe { required_ref(info, "info") }
        .map(|info| info.info.size.is_some())
        .unwrap_or(false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_size(info: *const Info) -> u64 {
    unsafe { required_ref(info, "info") }
        .ok()
        .and_then(|info| info.info.size)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_has_mtime_unix_nanos(info: *const Info) -> bool {
    unsafe { required_ref(info, "info") }
        .map(|info| info.info.mtime.is_some())
        .unwrap_or(false)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_mtime_unix_nanos(info: *const Info) -> u64 {
    unsafe { required_ref(info, "info") }
        .ok()
        .and_then(|info| info.info.mtime)
        .and_then(system_time_nanos)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_etag(info: *const Info) -> *const c_char {
    unsafe { required_ref(info, "info") }
        .ok()
        .and_then(|info| info.etag.as_ref())
        .map(|value| value.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_version(info: *const Info) -> *const c_char {
    unsafe { required_ref(info, "info") }
        .ok()
        .and_then(|info| info.version.as_ref())
        .map(|value| value.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_user_metadata_len(info: *const Info) -> usize {
    unsafe { required_ref(info, "info") }
        .map(|info| info.user_metadata.len())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_user_metadata_key(
    info: *const Info,
    index: usize,
) -> *const c_char {
    metadata_entry(
        &unsafe { required_ref(info, "info") }
            .ok()
            .map(|info| &info.user_metadata),
        index,
    )
    .map(|entry| entry.key.as_ptr())
    .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_user_metadata_value(
    info: *const Info,
    index: usize,
) -> *const c_char {
    metadata_entry(
        &unsafe { required_ref(info, "info") }
            .ok()
            .map(|info| &info.user_metadata),
        index,
    )
    .map(|entry| entry.value.as_ptr())
    .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_system_metadata_len(info: *const Info) -> usize {
    unsafe { required_ref(info, "info") }
        .map(|info| info.system_metadata.len())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_system_metadata_key(
    info: *const Info,
    index: usize,
) -> *const c_char {
    metadata_entry(
        &unsafe { required_ref(info, "info") }
            .ok()
            .map(|info| &info.system_metadata),
        index,
    )
    .map(|entry| entry.key.as_ptr())
    .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_info_system_metadata_value(
    info: *const Info,
    index: usize,
) -> *const c_char {
    metadata_entry(
        &unsafe { required_ref(info, "info") }
            .ok()
            .map(|info| &info.system_metadata),
        index,
    )
    .map(|entry| entry.value.as_ptr())
    .unwrap_or(ptr::null())
}

// --- local_delegate accessors -------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_local_delegate_destroy(delegate: *mut LocalDelegate) {
    if !delegate.is_null() {
        let _ = unsafe { Box::from_raw(delegate) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_local_delegate_path(
    delegate: *const LocalDelegate,
) -> *const c_char {
    unsafe { required_ref(delegate, "delegate") }
        .map(|delegate| delegate.path.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_local_delegate_info(
    delegate: *const LocalDelegate,
) -> *const Info {
    unsafe { required_ref(delegate, "delegate") }
        .map(|delegate| delegate.info.as_ref() as *const Info)
        .unwrap_or(ptr::null())
}

// --- list / version_list accessors --------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list_destroy(list: *mut List) {
    if !list.is_null() {
        let _ = unsafe { Box::from_raw(list) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list_len(list: *const List) -> usize {
    unsafe { required_ref(list, "list") }
        .map(|list| list.items.len())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list_next_page_token(list: *const List) -> *const c_char {
    unsafe { required_ref(list, "list") }
        .ok()
        .and_then(|list| list.next_page_token.as_ref())
        .map(|token| token.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list_item_address(
    list: *const List,
    index: usize,
) -> *const c_char {
    unsafe { required_ref(list, "list") }
        .ok()
        .and_then(|list| list.items.get(index))
        .map(|entry| entry.address.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list_item_info(list: *const List, index: usize) -> *mut Info {
    unsafe { required_ref(list, "list") }
        .ok()
        .and_then(|list| list.items.get(index))
        .map(|entry| info_handle(entry.info.clone()))
        .unwrap_or(ptr::null_mut())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_version_list_destroy(list: *mut VersionList) {
    if !list.is_null() {
        let _ = unsafe { Box::from_raw(list) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_version_list_len(list: *const VersionList) -> usize {
    unsafe { required_ref(list, "list") }
        .map(|list| list.items.len())
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_version_list_next_page_token(
    list: *const VersionList,
) -> *const c_char {
    unsafe { required_ref(list, "list") }
        .ok()
        .and_then(|list| list.next_page_token.as_ref())
        .map(|token| token.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_version_list_item_address(
    list: *const VersionList,
    index: usize,
) -> *const c_char {
    unsafe { required_ref(list, "list") }
        .ok()
        .and_then(|list| list.items.get(index))
        .map(|entry| entry.address.as_ptr())
        .unwrap_or(ptr::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_version_list_item_info(
    list: *const VersionList,
    index: usize,
) -> *mut Info {
    unsafe { required_ref(list, "list") }
        .ok()
        .and_then(|list| list.items.get(index))
        .map(|entry| info_handle(entry.info.clone()))
        .unwrap_or(ptr::null_mut())
}

// --- sync helpers (used by init + builders) -----------------------

/// Sync error-propagation harness for `library_init` and the
/// trivial-input builders. Async thunks bypass this — they deliver
/// errors through their callback rather than `out_error`.
pub(crate) fn run_sync(out_error: *mut Error, f: impl FnOnce() -> ovstorage::Result<()>) -> Status {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            unsafe {
                clear_success(out_error);
            }
            Status::Ok
        }
        Ok(Err(error)) => unsafe { set_error(out_error, error) },
        Err(_) => unsafe { set_error(out_error, panic_error()) },
    }
}

unsafe fn clear_success(out_error: *mut Error) {
    unsafe {
        if !out_error.is_null() {
            ovstorage_error_clear(out_error);
        }
    }
}

pub(crate) unsafe fn set_error(out_error: *mut Error, error: ovstorage::Error) -> Status {
    unsafe {
        let status = status_from_error(error.code());
        if !out_error.is_null() {
            ovstorage_error_clear(out_error);
            (*out_error).code = status;
            (*out_error).message = cstring_lossy(error.message()).into_raw();
        }
        status
    }
}

pub(crate) fn panic_error() -> ovstorage::Error {
    ovstorage::Error::new(ErrorCode::Internal, "panic crossed the C ABI boundary")
}

/// Null-library misuse chokepoint. With no library there is no
/// runtime to dispatch on, so async entrypoints fire the supplied
/// callback inline with `InvalidArgument`. This remains a useful
/// breakpoint for debugging double-shutdown / pre-init misuse.
pub(crate) fn null_library_warn(fn_name: &str) {
    eprintln!(
        "ovstorage: {fn_name} called with null library handle — \
         firing on_complete inline with InvalidArgument. Did you call \
         ovstorage_library_init() before this call, or has \
         ovstorage_library_shutdown() already run?"
    );
}

// --- input parsers / option decoders ------------------------------

pub(crate) unsafe fn required_ref<'a, T>(ptr: *const T, name: &str) -> ovstorage::Result<&'a T> {
    unsafe {
        if ptr.is_null() {
            Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                format!("{name} must not be null"),
            ))
        } else {
            Ok(&*ptr)
        }
    }
}

unsafe fn required_mut<'a, T>(ptr: *mut T, name: &str) -> ovstorage::Result<&'a mut T> {
    unsafe {
        if ptr.is_null() {
            Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                format!("{name} must not be null"),
            ))
        } else {
            Ok(&mut *ptr)
        }
    }
}

pub(crate) unsafe fn cstr_to_string(ptr: *const c_char, name: &str) -> ovstorage::Result<String> {
    unsafe {
        if ptr.is_null() {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                format!("{name} must not be null"),
            ));
        }
        CStr::from_ptr(ptr)
            .to_str()
            .map(|value| value.to_string())
            .map_err(|_| {
                ovstorage::Error::new(ErrorCode::InvalidArgument, format!("{name} is not UTF-8"))
            })
    }
}

pub(crate) unsafe fn parse_address(ptr: *const c_char) -> ovstorage::Result<Url> {
    unsafe { address::parse(&cstr_to_string(ptr, "address")?) }
}

unsafe fn validate_struct_size<T>(actual: usize, name: &str) -> ovstorage::Result<()> {
    if actual != 0 && actual < std::mem::size_of::<T>() {
        return Err(ovstorage::Error::new(
            ErrorCode::InvalidArgument,
            format!("{name}.struct_size is smaller than this library supports"),
        ));
    }
    Ok(())
}

unsafe fn library_init_options(
    ptr: *const LibraryInitOptionsV1,
) -> ovstorage::Result<LibraryInitOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(LibraryInitOptions::default());
        }
        let actual_size = (*ptr).struct_size;
        validate_struct_size::<LibraryInitOptionsV1>(actual_size, "library_init_options")?;
        let runtime_threads = match (*ptr).runtime_threads {
            0 => DEFAULT_RUNTIME_THREADS,
            n => n as usize,
        };
        // Newer fields live after `runtime_threads`; older callers
        // (smaller `struct_size`) miss them. Use `offset_of!` to detect
        // which fields the caller's struct actually includes.
        let iauth_offset = std::mem::offset_of!(LibraryInitOptionsV1, interactive_auth_capability);
        let durability_offset =
            std::mem::offset_of!(LibraryInitOptionsV1, credential_cache_durability);
        let cb_flag_offset = std::mem::offset_of!(LibraryInitOptionsV1, has_credential_callback);
        let interactive_auth_capability = if actual_size > iauth_offset {
            match (*ptr).interactive_auth_capability {
                -1 => None,
                0 => Some(ovstorage::InteractiveAuthCapability::Browser),
                1 => Some(ovstorage::InteractiveAuthCapability::Headless),
                2 => Some(ovstorage::InteractiveAuthCapability::None),
                other => {
                    return Err(ovstorage::Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid interactive_auth_capability code: {other}"),
                    ));
                }
            }
        } else {
            None
        };
        let credential_cache_durability = if actual_size > durability_offset {
            match (*ptr).credential_cache_durability {
                0 => credential::OvCredentialCacheDurability::Persistent,
                1 => credential::OvCredentialCacheDurability::InMemoryOnly,
                other => {
                    return Err(ovstorage::Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid credential_cache_durability code: {other}"),
                    ));
                }
            }
        } else {
            credential::OvCredentialCacheDurability::Persistent
        };
        let credential_callback = if actual_size > cb_flag_offset && (*ptr).has_credential_callback
        {
            let name = if (*ptr).credential_callback_name.is_null() {
                return Err(ovstorage::Error::new(
                    ErrorCode::InvalidArgument,
                    "credential_callback_name must not be null when has_credential_callback is true",
                ));
            } else {
                cstr_to_string((*ptr).credential_callback_name, "credential_callback_name")?
            };
            Some((name, (*ptr).credential_callback))
        } else {
            None
        };
        let allow_offset = std::mem::offset_of!(LibraryInitOptionsV1, allow_test_plugins);
        let allow_test_plugins = if actual_size > allow_offset {
            (*ptr).allow_test_plugins
        } else {
            false
        };
        Ok(LibraryInitOptions {
            runtime_threads,
            interactive_auth_capability,
            credential_cache_durability,
            credential_callback,
            allow_test_plugins,
        })
    }
}

const DEFAULT_RUNTIME_THREADS: usize = 2;

pub(crate) struct LibraryInitOptions {
    pub(crate) runtime_threads: usize,
    pub(crate) interactive_auth_capability: Option<ovstorage::InteractiveAuthCapability>,
    pub(crate) credential_cache_durability: credential::OvCredentialCacheDurability,
    pub(crate) credential_callback: Option<(String, credential::OvCredentialCallback)>,
    pub(crate) allow_test_plugins: bool,
}

impl Default for LibraryInitOptions {
    fn default() -> Self {
        Self {
            runtime_threads: DEFAULT_RUNTIME_THREADS,
            interactive_auth_capability: None,
            credential_cache_durability: credential::OvCredentialCacheDurability::Persistent,
            credential_callback: None,
            allow_test_plugins: false,
        }
    }
}

pub(crate) unsafe fn stat_options(ptr: *const StatOptionsV1) -> ovstorage::Result<StatOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(StatOptions::default());
        }
        validate_struct_size::<StatOptionsV1>((*ptr).struct_size, "stat_options")?;
        Ok(StatOptions {
            full_metadata: (*ptr).full_metadata,
        })
    }
}

pub(crate) unsafe fn read_options(ptr: *const ReadOptionsV1) -> ovstorage::Result<ReadOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(ReadOptions::default());
        }
        validate_struct_size::<ReadOptionsV1>((*ptr).struct_size, "read_options")?;
        Ok(ReadOptions {
            range: (*ptr).has_range.then_some(ByteRange {
                start: (*ptr).range_start,
                end_inclusive: (*ptr).has_range_end.then_some((*ptr).range_end_inclusive),
            }),
            ..ReadOptions::default()
        })
    }
}

pub(crate) unsafe fn write_options(ptr: *const WriteOptionsV1) -> ovstorage::Result<WriteOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(WriteOptions::default());
        }
        validate_struct_size::<WriteOptionsV1>((*ptr).struct_size, "write_options")?;
        Ok(WriteOptions {
            if_dest: if (*ptr).no_overwrite {
                IfDestExists::Fail
            } else {
                IfDestExists::Overwrite
            },
            ..WriteOptions::default()
        })
    }
}

pub(crate) unsafe fn list_options(ptr: *const ListOptionsV1) -> ovstorage::Result<ListOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(ListOptions::default());
        }
        validate_struct_size::<ListOptionsV1>((*ptr).struct_size, "list_options")?;
        Ok(ListOptions {
            recursive: (*ptr).recursive,
            max_results: (*ptr).has_max_results.then_some((*ptr).max_results),
            page_token: if (*ptr).page_token.is_null() {
                None
            } else {
                Some(cstr_to_string((*ptr).page_token, "page_token")?)
            },
            full_metadata: (*ptr).full_metadata,
        })
    }
}

pub(crate) unsafe fn list_versions_options(
    ptr: *const ListVersionsOptionsV1,
) -> ovstorage::Result<ListVersionsOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(ListVersionsOptions::default());
        }
        validate_struct_size::<ListVersionsOptionsV1>((*ptr).struct_size, "list_versions_options")?;
        Ok(ListVersionsOptions {
            max_results: (*ptr).has_max_results.then_some((*ptr).max_results),
            page_token: if (*ptr).page_token.is_null() {
                None
            } else {
                Some(cstr_to_string((*ptr).page_token, "page_token")?)
            },
        })
    }
}

pub(crate) unsafe fn create_directory_options(
    ptr: *const CreateDirectoryOptionsV1,
) -> ovstorage::Result<CreateDirectoryOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(CreateDirectoryOptions::default());
        }
        validate_struct_size::<CreateDirectoryOptionsV1>(
            (*ptr).struct_size,
            "create_directory_options",
        )?;
        Ok(CreateDirectoryOptions::default())
    }
}

pub(crate) unsafe fn delete_directory_options(
    ptr: *const DeleteDirectoryOptionsV1,
) -> ovstorage::Result<DeleteDirectoryOptions> {
    unsafe {
        if ptr.is_null() {
            return Ok(DeleteDirectoryOptions);
        }
        validate_struct_size::<DeleteDirectoryOptionsV1>(
            (*ptr).struct_size,
            "delete_directory_options",
        )?;
        Ok(DeleteDirectoryOptions)
    }
}

// --- handle constructors ------------------------------------------

pub(crate) fn bytes_handle(bytes: Vec<u8>) -> Bytes {
    let boxed = Box::new(bytes);
    Bytes {
        data: boxed.as_ptr(),
        len: boxed.len(),
        free_ctx: Box::into_raw(boxed) as *mut c_void,
    }
}

pub(crate) fn empty_bytes() -> Bytes {
    Bytes {
        data: ptr::null(),
        len: 0,
        free_ctx: ptr::null_mut(),
    }
}

pub(crate) fn empty_decision() -> AccessDecision {
    AccessDecision {
        allowed: false,
        denied_ops: AccessOps {
            read: false,
            write: false,
            delete: false,
            update_metadata: false,
        },
        reason: ptr::null_mut(),
    }
}

pub(crate) fn info_handle(info: ObjectInfo) -> *mut Info {
    Box::into_raw(Box::new(make_info_handle(info)))
}

fn make_info_handle(info: ObjectInfo) -> Info {
    Info {
        address: cstring_lossy(info.address.as_str()),
        etag: info.etag.as_deref().map(cstring_lossy),
        version: info.version.as_deref().map(cstring_lossy),
        system_metadata: metadata_entries(info.system_metadata.as_ref()),
        user_metadata: metadata_entries(info.user_metadata.as_ref()),
        info,
    }
}

pub(crate) fn local_delegate_handle(
    delegate: ovstorage::LocalDelegate,
) -> ovstorage::Result<*mut LocalDelegate> {
    let path = delegate.path.to_str().ok_or_else(|| {
        ovstorage::Error::new(ErrorCode::InvalidArgument, "local path is not UTF-8")
    })?;
    let info = Box::new(make_info_handle(delegate.info.clone()));
    Ok(Box::into_raw(Box::new(LocalDelegate {
        path: cstring_lossy(path),
        delegate,
        info,
    })))
}

pub(crate) fn list_handle(items: Vec<ObjectInfo>, next_page_token: Option<String>) -> *mut List {
    let items = items
        .into_iter()
        .map(|info| ListEntry {
            address: cstring_lossy(info.address.as_str()),
            info,
        })
        .collect();
    Box::into_raw(Box::new(List {
        items,
        next_page_token: next_page_token.as_deref().map(cstring_lossy),
    }))
}

pub(crate) fn version_list_handle(
    items: Vec<ObjectInfo>,
    next_page_token: Option<String>,
) -> *mut VersionList {
    let items = items
        .into_iter()
        .map(|info| VersionEntry {
            address: cstring_lossy(info.address.as_str()),
            info,
        })
        .collect();
    Box::into_raw(Box::new(VersionList {
        items,
        next_page_token: next_page_token.as_deref().map(cstring_lossy),
    }))
}

pub(crate) fn paginate_versions(
    items: Vec<ObjectInfo>,
    max_results: Option<u32>,
    page_token: Option<String>,
) -> ovstorage::Result<(Vec<ObjectInfo>, Option<String>)> {
    let start = match page_token {
        Some(token) => token
            .parse::<usize>()
            .map_err(|_| ovstorage::Error::new(ErrorCode::InvalidArgument, "invalid page token"))?,
        None => 0,
    };
    if start > items.len() {
        return Err(ovstorage::Error::new(
            ErrorCode::InvalidArgument,
            "page token is out of range",
        ));
    }
    let Some(max_results) = max_results else {
        return Ok((items.into_iter().skip(start).collect(), None));
    };
    if max_results == 0 {
        return Err(ovstorage::Error::new(
            ErrorCode::InvalidArgument,
            "max_results must be greater than zero",
        ));
    }
    let end = (start + max_results as usize).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    Ok((
        items.into_iter().skip(start).take(end - start).collect(),
        next,
    ))
}

fn metadata_entries(
    metadata: Option<&std::collections::HashMap<String, String>>,
) -> Vec<MetadataEntry> {
    let mut entries = metadata
        .into_iter()
        .flat_map(|metadata| metadata.iter())
        .map(|(key, value)| MetadataEntry {
            key: cstring_lossy(key),
            value: cstring_lossy(value),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    entries
}

fn metadata_entry<'a>(
    entries: &Option<&'a Vec<MetadataEntry>>,
    index: usize,
) -> Option<&'a MetadataEntry> {
    entries.and_then(|entries| entries.get(index))
}

pub(crate) fn access_ops(ops: AccessOps) -> ovstorage::AccessOps {
    ovstorage::AccessOps {
        read: ops.read,
        write: ops.write,
        delete: ops.delete,
        update_metadata: ops.update_metadata,
    }
}

pub(crate) fn access_decision(decision: ovstorage::AccessDecision) -> AccessDecision {
    AccessDecision {
        allowed: decision.allowed,
        denied_ops: AccessOps {
            read: decision.denied_ops.read,
            write: decision.denied_ops.write,
            delete: decision.denied_ops.delete,
            update_metadata: decision.denied_ops.update_metadata,
        },
        reason: decision
            .reason
            .as_deref()
            .map(cstring_lossy)
            .map(CString::into_raw)
            .unwrap_or(ptr::null_mut()),
    }
}

fn system_time_nanos(time: std::time::SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
}

pub(crate) fn cstring_lossy(value: &str) -> CString {
    CString::new(value.replace('\0', "\\0")).expect("interior NULs were replaced")
}

pub(crate) fn status_from_error(code: ErrorCode) -> Status {
    match code {
        ErrorCode::NotFound => Status::NotFound,
        ErrorCode::AlreadyExists => Status::AlreadyExists,
        ErrorCode::PermissionDenied => Status::PermissionDenied,
        ErrorCode::PreconditionFailed => Status::PreconditionFailed,
        ErrorCode::Conflict => Status::Conflict,
        ErrorCode::DirectoryNotEmpty => Status::DirectoryNotEmpty,
        ErrorCode::Unsupported => Status::Unsupported,
        ErrorCode::InvalidArgument => Status::InvalidArgument,
        ErrorCode::ObjectModified => Status::ObjectModified,
        ErrorCode::NoRoute => Status::NoRoute,
        ErrorCode::Transient => Status::Transient,
        ErrorCode::Cancelled => Status::Cancelled,
        _ => Status::Internal,
    }
}

/// Resolve the auth-refresh-lock state directory (`auth.sqlite` +
/// flock). Honors `OVSTORAGE_AUTH_DIR`; falls back to a per-process
/// tempdir so no-config callers still get a working library.
fn capi_auth_state_root() -> ovstorage::Result<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(std::path::PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-capi-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        ovstorage::Error::new(
            ErrorCode::Internal,
            format!("failed to create auth state root: {error}"),
        )
    })?;
    Ok(tmp)
}
