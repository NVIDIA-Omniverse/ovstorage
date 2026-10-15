// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

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
    PartialCompletion = 40,
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
///
/// `next_action` is an optional recovery hint. It rides in the struct
/// rather than in a side table: a `static` map is per-image, so the host
/// and a plugin cdylib each get their own and a hint registered on one
/// side is invisible on the other.
#[repr(C)]
#[derive(Debug)]
pub struct Error {
    pub code: ErrorCode,
    pub message_ptr: *mut c_char,
    pub message_len: usize,
    pub context: *mut ErrorContextV1,
    /// Optional recovery hint, carried in the struct so it crosses the
    /// boundary with the rest of the error. Absent when the producer
    /// attached none.
    pub next_action: Optional<Str>,
}

unsafe impl Send for Error {}

/// Discriminant for [`ErrorContextV1`]. New variants append; an
/// unrecognized discriminant means "context absent" per the SPI's
/// "ignore unknown" forward-compat rule.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrorContextKindV1 {
    /// Identity slot active. Companion to `ErrorCode::ObjectModified` and
    /// `ErrorCode::PreconditionFailed`.
    Identity = 0,
    /// Auth slot active. Companion to `ErrorCode::AuthRequired` /
    /// `AuthCancelled` / `AuthExpired`.
    Auth = 1,
    /// Partial slot active. Companion to `ErrorCode::PartialCompletion`.
    Partial = 2,
}

/// Stage of a compound operation, for [`PartialErrorContextV1`]. Named by
/// what the stage acts on rather than by the operation it belongs to, so one
/// vocabulary serves every compound operation. Discriminant values are the
/// ABI contract.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PartialStageV1 {
    /// Not set. A zero-initialised struct lands here, so it can never be
    /// mistaken for a real stage; the host drops the whole context.
    Unspecified = 0,
    /// The object's bytes at the operation's destination.
    ObjectData = 1,
    /// The user-metadata map for the object.
    UserMetadata = 2,
    /// Removal of the source object of a move.
    SourceRemoval = 3,
}

/// Whether a stage that reported failure is known not to have taken effect.
/// Discriminant values are the ABI contract.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StageOutcomeV1 {
    /// Not set; see [`PartialStageV1::Unspecified`].
    Unspecified = 0,
    /// The stage definitively did not take effect.
    NotApplied = 1,
    /// The stage may or may not have taken effect.
    Unknown = 2,
}

/// What undoing the completed stage would do. Discriminant values are the
/// ABI contract.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RollbackEffectV1 {
    /// Not set. **This is the reason zero is reserved on all three enums.**
    /// A C plugin that `memset`s or `calloc`s a `PartialErrorContextV1` would
    /// otherwise assert `RestoresPriorState` — telling the host it is safe to
    /// delete data that is already durable. Zeroed memory must not be able to
    /// say that.
    Unspecified = 0,
    /// Undoing the completed stage returns the system to its prior state.
    RestoresPriorState = 1,
    /// Undoing the completed stage destroys work the caller asked for.
    DestroysRequestedWork = 2,
}

/// Partial-completion payload for [`ErrorContextV1`]: which stage of a
/// compound operation committed durably, which one did not, and what a
/// rollback would do.
///
/// All four fields are plain enums, so this slot owns no allocation and its
/// drop is a no-op.
///
/// Every field reserves 0 for `Unspecified`, so a zero-initialised struct
/// asserts nothing rather than asserting the dangerous default — a plugin that
/// `memset`s or `calloc`s this struct has said "unset", not "rollback is
/// safe". The discriminants match the broker wire enums one-for-one.
///
/// A host that reads this slot is required to drop the whole context when any
/// field is `Unspecified`; the Rust host does so in
/// `marshal::error::context_from_ffi`. The in-tree C host does not read these
/// fields at all today, so the requirement is on readers rather than a
/// statement about every shipped host.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PartialErrorContextV1 {
    pub completed: PartialStageV1,
    pub failed: PartialStageV1,
    pub failed_outcome: StageOutcomeV1,
    pub rollback: RollbackEffectV1,
}

unsafe impl Send for PartialErrorContextV1 {}

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
    pub partial: core::mem::MaybeUninit<PartialErrorContextV1>,
}

unsafe impl Send for ErrorContextV1 {}

impl ErrorContextV1 {
    /// Construct an identity-context payload.
    pub fn from_identity(value: IdentityErrorContextV1) -> Self {
        Self {
            kind: ErrorContextKindV1::Identity,
            identity: core::mem::MaybeUninit::new(value),
            auth: core::mem::MaybeUninit::uninit(),
            partial: core::mem::MaybeUninit::uninit(),
        }
    }

    /// Construct an auth-context payload.
    pub fn from_auth(value: AuthErrorContextV1) -> Self {
        Self {
            kind: ErrorContextKindV1::Auth,
            identity: core::mem::MaybeUninit::uninit(),
            auth: core::mem::MaybeUninit::new(value),
            partial: core::mem::MaybeUninit::uninit(),
        }
    }

    /// Construct a partial-completion payload.
    pub fn from_partial(value: PartialErrorContextV1) -> Self {
        Self {
            kind: ErrorContextKindV1::Partial,
            identity: core::mem::MaybeUninit::uninit(),
            auth: core::mem::MaybeUninit::uninit(),
            partial: core::mem::MaybeUninit::new(value),
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
                // Plain enums: nothing owned, so nothing to release. The arm
                // is spelled out rather than merged so a future slot that
                // does own memory cannot inherit a silent no-op.
                ErrorContextKindV1::Partial => {}
            }
        }
    }
}

/// Free an [`ErrorContextV1`] produced by an ovstorage
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
        crate::ffi::abi_alloc::abi_box_free(context);
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
        crate::ffi::abi_alloc::abi_box_free(error);
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
        let next_action = &(*error).next_action;
        if !next_action.is_some() {
            return false;
        }
        // SAFETY: `present` means the slot is initialized.
        let hint = next_action.value.assume_init_ref();
        if hint.ptr.is_null() || hint.len == 0 {
            return false;
        }
        *out_ptr = hint.ptr as *const c_char;
        *out_len = hint.len;
        true
    }
}

impl Drop for Error {
    fn drop(&mut self) {
        // `next_action` owns its buffer; field drop glue does not run for a
        // type with a manual `Drop`, so release it here.
        unsafe { std::ptr::drop_in_place(&mut self.next_action) };
        if !self.message_ptr.is_null() {
            // SAFETY: every constructor allocates the message buffer on
            // the ABI heap with `cap == abi_capacity(len)`, matching
            // `marshal::error::to_ffi`.
            unsafe {
                crate::ffi::abi_alloc::abi_buffer_free(
                    self.message_ptr as *mut u8,
                    self.message_len,
                );
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
            // SAFETY: the context pointer is either NULL or an ABI heap
            // pointer produced by `marshal::error::to_ffi`.
            unsafe {
                crate::ffi::abi_alloc::abi_box_free(self.context);
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
        let c_err = crate::ffi::abi_alloc::abi_box(crate::marshal::error::to_ffi(&rust_err));
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
        let c_err = crate::ffi::abi_alloc::abi_box(crate::marshal::error::to_ffi(&rust_err));
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
