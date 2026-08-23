// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Read / write payload types
//
// Tagged unions: exactly one payload slot is initialised, selected
// by `tag`. The other slots carry undefined bytes; reading them is UB.
// ---------------------------------------------------------------------

/// Tag for [`Body`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BodyTag {
    Bytes = 0,
    LocalFile = 1,
    Stream = 2,
}

/// Source of bytes the host hands the plugin for `write` /
/// `write_stream`. `Stream` carries a vtable handle the plugin pulls
/// chunks from via `next_fn`.
#[repr(C)]
#[derive(Debug)]
pub struct Body {
    pub tag: BodyTag,
    pub bytes: core::mem::MaybeUninit<Bytes>,
    pub local_file: core::mem::MaybeUninit<Str>,
    pub stream: core::mem::MaybeUninit<BodyStream>,
}

unsafe impl Send for Body {}

impl Body {
    pub fn from_bytes(bytes: Bytes) -> Self {
        Self {
            tag: BodyTag::Bytes,
            bytes: core::mem::MaybeUninit::new(bytes),
            local_file: core::mem::MaybeUninit::uninit(),
            stream: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_local_file(path: Str) -> Self {
        Self {
            tag: BodyTag::LocalFile,
            bytes: core::mem::MaybeUninit::uninit(),
            local_file: core::mem::MaybeUninit::new(path),
            stream: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_stream(stream: BodyStream) -> Self {
        Self {
            tag: BodyTag::Stream,
            bytes: core::mem::MaybeUninit::uninit(),
            local_file: core::mem::MaybeUninit::uninit(),
            stream: core::mem::MaybeUninit::new(stream),
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                BodyTag::Bytes => self.bytes.assume_init_drop(),
                BodyTag::LocalFile => self.local_file.assume_init_drop(),
                BodyTag::Stream => self.stream.assume_init_drop(),
            }
        }
    }
}

/// `next_fn` signature for [`BodyStream`]. Yields one chunk per call.
/// `Yielded` writes `out_chunk` (caller owns); `Failed` writes
/// `out_error` (caller owns); `Ended` writes neither.
pub type BodyStreamNextFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    out_chunk: *mut Bytes,
    out_error: *mut Error,
) -> StreamStep;

/// Plugin-consumable chunk iterator. `state` is opaque to the
/// plugin; `next_fn` and `drop_fn` are non-null. The plugin calls
/// `drop_fn` exactly once when done.
#[repr(C)]
pub struct BodyStream {
    pub state: *mut core::ffi::c_void,
    pub next_fn: BodyStreamNextFn,
    pub drop_fn: StreamDropFn,
}

unsafe impl Send for BodyStream {}

impl Drop for BodyStream {
    fn drop(&mut self) {
        // SAFETY: `drop_fn` is valid for the lifetime of `state`.
        unsafe { (self.drop_fn)(self.state) }
    }
}

impl std::fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BodyStream{{..}}")
    }
}

/// Drop a [`BodyStream`] handle in place, driving its `drop_fn`
/// exactly once. Safe with NULL. The pointee storage is not released.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`BodyStream`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_body_stream_free(value: *mut BodyStream) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Successful write result returned to the host.
#[repr(C)]
#[derive(Debug)]
pub struct WriteResult {
    pub info: ObjectInfo,
}

unsafe impl Send for WriteResult {}

/// Bytes-with-metadata payload of `ReadResult::Bytes`.
#[repr(C)]
#[derive(Debug)]
pub struct ReadResultBytes {
    pub bytes: Bytes,
    pub info: ObjectInfo,
}

unsafe impl Send for ReadResultBytes {}

/// Optional RAII lease pinning a delegate's backing file against
/// reclamation (e.g. cache eviction) for as long as the delegate — or
/// any clone of it — is held. It crosses the ABI so a host-minted lease
/// survives an `export_handle` / `import_handle` boundary instead of
/// being dropped at encode.
///
/// `state == NULL` encodes "no lease": every plugin-produced delegate,
/// and any host delegate without an eviction pin. When `state` is
/// non-null the consumer owns it and drives `drop_fn(state)` exactly once
/// — when the last clone of the delegate is dropped — releasing the
/// producer-side pin. `drop_fn` is `NULL` iff `state` is `NULL`; both the
/// Rust decoder and the pure-C runtime (`ovc_pval_stream_drop`) treat a
/// `NULL` `drop_fn` as a no-op, so an unconditional release is sound.
#[repr(C)]
pub struct LeaseHandle {
    pub state: *mut core::ffi::c_void,
    // Spelled inline (not via the `StreamDropFn` alias) so cbindgen
    // unwraps the `Option` to a bare, nullable `void (*)(void*)` — the
    // `_reserved`-slot precedent. `Option<StreamDropFn>` would instead
    // emit an opaque, incomplete `Option_StreamDropFn` type. A NULL
    // (C-zeroed) callback is modelled soundly as `None`.
    pub drop_fn: Option<unsafe extern "C" fn(state: *mut core::ffi::c_void)>,
}

// SAFETY: `state` is an opaque owned pointer the producer promised is
// `Send + Sync` (it wraps an `Arc<dyn Send + Sync>`); the consumer only
// ever moves the handle and drops it once, inheriting exactly the slot
// contract `ForeignVtableLayer` already relies on.
unsafe impl Send for LeaseHandle {}
unsafe impl Sync for LeaseHandle {}

impl LeaseHandle {
    /// The "no lease" sentinel: NULL state with no drop callback.
    pub fn none() -> Self {
        Self {
            state: core::ptr::null_mut(),
            drop_fn: None,
        }
    }
}

impl Drop for LeaseHandle {
    fn drop(&mut self) {
        // SAFETY: `drop_fn`, when present, is valid for the life of
        // `state` and NULL-safe; a move-only handle drives it exactly once.
        if let Some(drop_fn) = self.drop_fn {
            unsafe { drop_fn(self.state) }
        }
    }
}

impl std::fmt::Debug for LeaseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseHandle")
            .field("leased", &!self.state.is_null())
            .finish()
    }
}

/// Carries a path the host opens directly, plus an optional lease
/// ([`LeaseHandle`]) pinning that path for the lifetime of the delegate.
#[repr(C)]
#[derive(Debug)]
pub struct LocalDelegate {
    pub path: Str,
    pub info: ObjectInfo,
    pub lease: LeaseHandle,
}

unsafe impl Send for LocalDelegate {}

/// Stream-with-metadata payload of `ReadResult::Stream`. Reuses the
/// `BodyStream` chunk-iterator shape; no semantic difference between
/// a streamed read and a streamed write at the chunk level.
#[repr(C)]
#[derive(Debug)]
pub struct ReadResultStream {
    pub stream: BodyStream,
    pub info: ObjectInfo,
}

unsafe impl Send for ReadResultStream {}

/// Tag for [`ReadResult`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReadResultTag {
    Bytes = 0,
    LocalDelegate = 1,
    Redirect = 2,
    Stream = 3,
}

/// What the plugin's `read` returned.
#[repr(C)]
#[derive(Debug)]
pub struct ReadResult {
    pub tag: ReadResultTag,
    pub bytes: core::mem::MaybeUninit<ReadResultBytes>,
    pub local_delegate: core::mem::MaybeUninit<LocalDelegate>,
    pub redirect: core::mem::MaybeUninit<ReadRedirect>,
    pub stream: core::mem::MaybeUninit<ReadResultStream>,
}

unsafe impl Send for ReadResult {}

impl ReadResult {
    pub fn from_bytes(value: ReadResultBytes) -> Self {
        Self {
            tag: ReadResultTag::Bytes,
            bytes: core::mem::MaybeUninit::new(value),
            local_delegate: core::mem::MaybeUninit::uninit(),
            redirect: core::mem::MaybeUninit::uninit(),
            stream: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_local_delegate(value: LocalDelegate) -> Self {
        Self {
            tag: ReadResultTag::LocalDelegate,
            bytes: core::mem::MaybeUninit::uninit(),
            local_delegate: core::mem::MaybeUninit::new(value),
            redirect: core::mem::MaybeUninit::uninit(),
            stream: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_redirect(value: ReadRedirect) -> Self {
        Self {
            tag: ReadResultTag::Redirect,
            bytes: core::mem::MaybeUninit::uninit(),
            local_delegate: core::mem::MaybeUninit::uninit(),
            redirect: core::mem::MaybeUninit::new(value),
            stream: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_stream(value: ReadResultStream) -> Self {
        Self {
            tag: ReadResultTag::Stream,
            bytes: core::mem::MaybeUninit::uninit(),
            local_delegate: core::mem::MaybeUninit::uninit(),
            redirect: core::mem::MaybeUninit::uninit(),
            stream: core::mem::MaybeUninit::new(value),
        }
    }
}

impl Drop for ReadResult {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                ReadResultTag::Bytes => self.bytes.assume_init_drop(),
                ReadResultTag::LocalDelegate => self.local_delegate.assume_init_drop(),
                ReadResultTag::Redirect => self.redirect.assume_init_drop(),
                ReadResultTag::Stream => self.stream.assume_init_drop(),
            }
        }
    }
}

/// Tag for [`WriteStep`].
///
/// `Redirects` carries a contract: **no part of the object may be observable
/// at the backend while a write is in a redirect step.** Stage the transfer
/// somewhere a reader cannot reach — a multipart upload id, an uncommitted
/// block list — and make the object visible only in the transition to `Done`.
/// Abandoning a write mid-flight must leave the address exactly as it was.
///
/// Hosts rely on this to keep their own state coherent: a mid-flight step
/// means the address still holds what it held before, so anything a host
/// derived from it is still valid. A plugin that published partial content
/// there would silently invalidate those derivations.
///
/// The byte cache does not depend on it for safety — it invalidates
/// write-ahead, before `continue_write` runs, so a plugin that breaks this
/// contract cannot make it serve stale bytes. That is belt-and-braces, not a
/// reason to relax the contract: it costs that cache its fallback for the
/// duration of the write, and it says nothing about other hosts.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WriteStepTag {
    Done = 0,
    Redirects = 1,
}

/// What the plugin's `write` / `continue_write` returned this turn.
#[repr(C)]
#[derive(Debug)]
pub struct WriteStep {
    pub tag: WriteStepTag,
    pub done: core::mem::MaybeUninit<WriteResult>,
    pub redirects: core::mem::MaybeUninit<WriteRedirectBatch>,
}

unsafe impl Send for WriteStep {}

impl WriteStep {
    pub fn from_done(value: WriteResult) -> Self {
        Self {
            tag: WriteStepTag::Done,
            done: core::mem::MaybeUninit::new(value),
            redirects: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn from_redirects(value: WriteRedirectBatch) -> Self {
        Self {
            tag: WriteStepTag::Redirects,
            done: core::mem::MaybeUninit::uninit(),
            redirects: core::mem::MaybeUninit::new(value),
        }
    }
}

impl Drop for WriteStep {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                WriteStepTag::Done => self.done.assume_init_drop(),
                WriteStepTag::Redirects => self.redirects.assume_init_drop(),
            }
        }
    }
}

/// Per-backend item metadata. `mtime_unix_ms` is Unix milliseconds; ms
/// precision is the FFI-boundary clock contract.
#[repr(C)]
#[derive(Debug)]
pub struct BackendItemInfo {
    pub kind: ObjectKindV1,
    pub etag: Optional<Str>,
    pub version: Optional<Str>,
    pub size: Optional<u64>,
    pub mtime_unix_ms: Optional<i64>,
    pub checksums: List<ChecksumEntry>,
    pub effective_permissions: Optional<EffectivePermissions>,
    pub system_metadata: Optional<SystemMetadata>,
    pub user_metadata: Optional<UserMetadata>,
    pub modified_by: Optional<Str>,
}

unsafe impl Send for BackendItemInfo {}

/// Authorization decision returned by `Layer::check_access`.
#[repr(C)]
#[derive(Debug)]
pub struct AccessDecision {
    pub allowed: bool,
    pub denied_ops: AccessOps,
    pub reason: Optional<Str>,
}

unsafe impl Send for AccessDecision {}

/// Drop a [`Body`]'s active payload in place. Safe with NULL. The
/// pointee storage is caller-owned.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`Body`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_body_free(value: *mut Body) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Reclaim a heap-allocated [`WriteResult`] returned through a
/// `BackendWriteCallback`. Safe with NULL. Do NOT call on
/// caller-owned storage — UB.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_write_result_free(value: *mut WriteResult) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

/// Reclaim a heap-allocated [`ReadResult`] returned through a
/// `BackendReadCallback`. Safe with NULL. Do NOT call on
/// caller-owned storage — UB.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_read_result_free(value: *mut ReadResult) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

/// Reclaim a heap-allocated [`WriteStep`] returned through a
/// `BackendWriteStepCallback`. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_write_step_free(value: *mut WriteStep) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

/// Reclaim a heap-allocated [`AccessDecision`] returned through a
/// `BackendAccessDecisionCallback`. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_access_decision_free(value: *mut AccessDecision) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}

// ---------------------------------------------------------------------
