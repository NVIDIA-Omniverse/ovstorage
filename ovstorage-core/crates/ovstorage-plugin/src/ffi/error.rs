// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static NEXT_ACTIONS: OnceLock<Mutex<HashMap<usize, Vec<u8>>>> = OnceLock::new();

fn next_actions() -> &'static Mutex<HashMap<usize, Vec<u8>>> {
    NEXT_ACTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn register_error_next_action(message_ptr: *mut c_char, next_action: Option<&str>) {
    if message_ptr.is_null() {
        return;
    }
    let Some(next_action) = next_action else {
        return;
    };
    let bytes = next_action.as_bytes();
    if bytes.is_empty() {
        return;
    }
    if let Ok(mut actions) = next_actions().lock() {
        actions.insert(message_ptr as usize, bytes.to_vec());
    }
}

pub(crate) fn take_error_next_action(message_ptr: *mut c_char) -> Option<String> {
    if message_ptr.is_null() {
        return None;
    }
    let bytes = next_actions()
        .lock()
        .ok()?
        .remove(&(message_ptr as usize))?;
    String::from_utf8(bytes).ok()
}

/// Stable error classification carried by every fallible call.
/// Discriminant values are the ABI contract.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    NotFound = 0,
    AlreadyExists = 1,
    PermissionDenied = 2,
    PreconditionFailed = 3,
    Conflict = 4,
    DirectoryNotEmpty = 5,
    Unsupported = 6,
    InvalidArgument = 7,
    IncompatibleType = 8,
    Locked = 9,
    Cancelled = 10,
    DeadlineExceeded = 11,
    Transient = 12,
    ResourceExhausted = 13,
    IntegrityFailure = 14,
    Internal = 15,
    BrokerUnavailable = 16,
    BrokerRequired = 17,
    RedirectExpired = 18,
    PolicyEpochStale = 19,
    AuthorizationLeaseExpired = 20,
    CacheCorrupt = 21,
    StagingExpired = 22,
    CommitAmbiguous = 23,
    CacheLockContention = 24,
    StateRootUnavailable = 25,
    NetworkFilesystemRefused = 26,
    ObjectModified = 27,
    NoRoute = 28,
    RouteConflict = 29,
    NotConfigured = 30,
    AliasChainTooLong = 31,
    CredentialExpired = 32,
    CredentialUnavailable = 33,
    AuthRequired = 34,
    AuthCancelled = 35,
    AuthExpired = 36,
    ContentMismatch = 37,
    ContentChecksumMismatch = 38,
    PluginRejected = 39,
}

/// Owned error value crossing the FFI boundary.
///
/// `message_ptr` is never null and points at a UTF-8 buffer of
/// `message_len` bytes (NOT NUL-terminated). An empty message uses
/// `message_len == 0` with a one-byte sentinel allocation so
/// consumers need not special-case the null pointer. Pass the struct
/// to `ovstorage_plugin_error_free` exactly once when done.
///
/// `context` is non-null when the error variant carries a stable
/// structured payload (e.g. `AuthRequired` → auth slot), else NULL.
/// The owning side's destructor frees the context alongside the
/// message buffer.
#[repr(C)]
#[derive(Debug)]
pub struct Error {
    pub code: ErrorCode,
    pub message_ptr: *mut c_char,
    pub message_len: usize,
    pub context: *mut ErrorContextV1,
}

unsafe impl Send for Error {}

/// Discriminant for [`ErrorContextV1`]. New variants append; an
/// unrecognized discriminant means "context absent" per the SPI's
/// "ignore unknown" forward-compat rule.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorContextKindV1 {
    /// Identity slot active. Companion to `ErrorCode::ObjectModified`.
    Identity = 0,
    /// Auth slot active. Companion to `ErrorCode::AuthRequired` /
    /// `AuthCancelled` / `AuthExpired`.
    Auth = 1,
}

/// Auth-context payload for [`ErrorContextV1`]. `expired_at_unix_ms`
/// is set only on `ErrorCode::AuthExpired`; clock encoding is Unix
/// milliseconds (the FFI-boundary contract).
#[repr(C)]
#[derive(Debug)]
pub struct AuthErrorContextV1 {
    pub connection_id: ConnectionId,
    pub reason: Optional<Str>,
    pub expired_at_unix_ms: Optional<i64>,
}

unsafe impl Send for AuthErrorContextV1 {}

/// Identity-context payload for [`ErrorContextV1`]. `new_etag` is
/// the etag the backend reported, distinct from the caller's
/// `if_match` / `if_dest` precondition.
#[repr(C)]
#[derive(Debug)]
pub struct IdentityErrorContextV1 {
    pub new_etag: Optional<Str>,
}

unsafe impl Send for IdentityErrorContextV1 {}

/// Typed payload attached to an [`Error`] for variants whose
/// structured fields have a stable shape.
///
/// Tagged union: `kind` selects the active slot; the other slots
/// carry unspecified bytes and must not be read. Released either by
/// the owning [`Error`]'s destructor or via
/// `ovstorage_plugin_error_context_free`.
#[repr(C)]
#[derive(Debug)]
pub struct ErrorContextV1 {
    pub kind: ErrorContextKindV1,
    pub identity: core::mem::MaybeUninit<IdentityErrorContextV1>,
    pub auth: core::mem::MaybeUninit<AuthErrorContextV1>,
}

unsafe impl Send for ErrorContextV1 {}

impl ErrorContextV1 {
    /// Construct an identity-context payload.
    pub fn from_identity(value: IdentityErrorContextV1) -> Self {
        Self {
            kind: ErrorContextKindV1::Identity,
            identity: core::mem::MaybeUninit::new(value),
            auth: core::mem::MaybeUninit::uninit(),
        }
    }

    /// Construct an auth-context payload.
    pub fn from_auth(value: AuthErrorContextV1) -> Self {
        Self {
            kind: ErrorContextKindV1::Auth,
            identity: core::mem::MaybeUninit::uninit(),
            auth: core::mem::MaybeUninit::new(value),
        }
    }
}

impl Drop for ErrorContextV1 {
    fn drop(&mut self) {
        // Only the active slot is initialized; the other carries garbage.
        unsafe {
            match self.kind {
                ErrorContextKindV1::Identity => self.identity.assume_init_drop(),
                ErrorContextKindV1::Auth => self.auth.assume_init_drop(),
            }
        }
    }
}

/// Free an [`ErrorContextV1`] previously produced by an ovstorage
/// call. Safe to call with NULL.
///
/// Use this when host code lifts a context out of its parent
/// [`Error`] and must release it independently. The standard release
/// path (free the parent error) reaches the context automatically.
///
/// # Safety
///
/// `context`, when non-null, must point at a valid [`ErrorContextV1`]
/// produced by an ovstorage call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_error_context_free(context: *mut ErrorContextV1) {
    unsafe {
        if context.is_null() {
            return;
        }
        // Reject misaligned pointers (older-ABI producer that left the
        // field uninitialised); reclaiming would crash the destructor.
        if !(context as usize).is_multiple_of(core::mem::align_of::<ErrorContextV1>()) {
            return;
        }
        let _owned: Box<ErrorContextV1> = Box::from_raw(context);
    }
}

/// Tagged result wrapper for embedding a sum type inside another
/// `repr(C)` struct (e.g. inside a `RedirectResultBatch` slot). Most
/// fallible calls instead return `*mut Error` alongside an
/// out-parameter for the success value.
///
/// Exactly one of `ok` and `err` is initialized, selected by `tag`;
/// the other slot carries unspecified bytes and must not be read.
/// After consumption the receiver releases the active payload (an
/// `err` via `ovstorage_plugin_error_free`; an `ok` per its type's
/// documented convention).
///
/// cbindgen monomorphizes a distinct C type per concrete `T`
/// (e.g. `OvStorageResultObjectInfo`).
#[repr(C)]
#[derive(Debug)]
pub struct Result<T> {
    pub tag: ResultTag,
    pub ok: core::mem::MaybeUninit<T>,
    pub err: core::mem::MaybeUninit<Error>,
}

/// Discriminant for [`Result<T>`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultTag {
    Ok = 0,
    Err = 1,
}

impl<T> Result<T> {
    /// Construct an `Ok` payload.
    pub fn ok(value: T) -> Self {
        Self {
            tag: ResultTag::Ok,
            ok: core::mem::MaybeUninit::new(value),
            err: core::mem::MaybeUninit::uninit(),
        }
    }

    /// Construct an `Err` payload.
    pub fn err(error: Error) -> Self {
        Self {
            tag: ResultTag::Err,
            ok: core::mem::MaybeUninit::uninit(),
            err: core::mem::MaybeUninit::new(error),
        }
    }

    /// True when the result holds an `Ok` payload.
    pub fn is_ok(&self) -> bool {
        matches!(self.tag, ResultTag::Ok)
    }

    /// True when the result holds an `Err` payload.
    pub fn is_err(&self) -> bool {
        matches!(self.tag, ResultTag::Err)
    }
}

impl<T> Drop for Result<T> {
    fn drop(&mut self) {
        // Only the active slot is initialized; the other carries garbage.
        unsafe {
            match self.tag {
                ResultTag::Ok => self.ok.assume_init_drop(),
                ResultTag::Err => self.err.assume_init_drop(),
            }
        }
    }
}

/// Reclaim a heap-allocated [`Error`] returned through a callback.
/// Safe with NULL. Calling twice on the same pointer is UB.
///
/// Caller-owned storage (e.g. an error a stream's `next_fn` writes
/// into a caller-supplied `out_error`) MUST NOT be released via this
/// function — it is not heap-allocated by this crate. Drop such
/// values in place.
///
/// # Safety
///
/// `error`, when non-null, must be a heap pointer produced by an
/// ovstorage call (boxed `Error`). Passing a non-boxed pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_error_free(error: *mut Error) {
    unsafe {
        if error.is_null() {
            return;
        }
        drop(Box::from_raw(error));
    }
}

/// Borrow the optional recovery hint attached to an [`Error`].
///
/// The returned pointer is borrowed from `error` and remains valid
/// until `ovstorage_plugin_error_free` or the owner drops the error.
/// Returns `false` when no hint is present or any pointer is NULL.
///
/// # Safety
///
/// `error`, when non-null, must point at a valid [`Error`] produced
/// by an ovstorage call. `out_ptr` and `out_len`, when non-null, must
/// be valid writable out-parameters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_error_get_next_action(
    error: *const Error,
    out_ptr: *mut *const c_char,
    out_len: *mut usize,
) -> bool {
    unsafe {
        if error.is_null() || out_ptr.is_null() || out_len.is_null() {
            return false;
        }
        let message_ptr = (*error).message_ptr;
        if message_ptr.is_null() {
            return false;
        }
        let Ok(actions) = next_actions().lock() else {
            return false;
        };
        let Some(bytes) = actions.get(&(message_ptr as usize)) else {
            return false;
        };
        if bytes.is_empty() {
            return false;
        }
        *out_ptr = bytes.as_ptr() as *const c_char;
        *out_len = bytes.len();
        true
    }
}

impl Drop for Error {
    fn drop(&mut self) {
        let _ = take_error_next_action(self.message_ptr);
        if !self.message_ptr.is_null() {
            let cap = if self.message_len == 0 {
                1
            } else {
                self.message_len
            };
            // SAFETY: every constructor allocates the message buffer
            // with `len == cap`, matching `shim::error::to_ffi`.
            unsafe {
                let _ = Vec::from_raw_parts(self.message_ptr as *mut u8, self.message_len, cap);
            }
            self.message_ptr = std::ptr::null_mut();
            self.message_len = 0;
        }
        // Skip non-null but misaligned context pointers: those came
        // from an older ABI that did not initialize the field. Leak
        // rather than abort by reclaiming a garbage Box.
        if !self.context.is_null()
            && (self.context as usize).is_multiple_of(core::mem::align_of::<ErrorContextV1>())
        {
            // SAFETY: the context pointer is either NULL or a heap
            // pointer produced by `shim::error::to_ffi`.
            unsafe {
                let _owned: Box<ErrorContextV1> = Box::from_raw(self.context);
            }
        }
        self.context = std::ptr::null_mut();
    }
}

#[cfg(test)]
mod next_action_tests {
    use super::*;

    #[test]
    fn accessor_returns_false_when_next_action_absent() {
        let rust_err = crate::Error::new(crate::ErrorCode::NotFound, "missing");
        let c_err = Box::into_raw(Box::new(crate::shim::error::to_ffi(&rust_err)));
        let mut out_ptr: *const c_char = std::ptr::null();
        let mut out_len: usize = 0;
        let present =
            unsafe { ovstorage_plugin_error_get_next_action(c_err, &mut out_ptr, &mut out_len) };
        assert!(!present);
        unsafe { ovstorage_plugin_error_free(c_err) };
    }

    #[test]
    fn accessor_returns_true_when_next_action_present() {
        let rust_err = crate::Error::new(crate::ErrorCode::NotConfigured, "missing config")
            .with_next_action("Call load_plugin first.");
        let c_err = Box::into_raw(Box::new(crate::shim::error::to_ffi(&rust_err)));
        let mut out_ptr: *const c_char = std::ptr::null();
        let mut out_len: usize = 0;
        let present =
            unsafe { ovstorage_plugin_error_get_next_action(c_err, &mut out_ptr, &mut out_len) };
        assert!(present);
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr as *const u8, out_len) };
        let text = std::str::from_utf8(bytes).expect("utf8");
        assert!(text.contains("load_plugin"), "{text}");
        unsafe { ovstorage_plugin_error_free(c_err) };
    }
}
