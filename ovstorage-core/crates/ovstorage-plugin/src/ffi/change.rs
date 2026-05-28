// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Backend change events
// ---------------------------------------------------------------------

/// Tag for [`BackendChangeEvent`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BackendChangeEventTag {
    Object = 0,
    Lapsed = 1,
}

/// `BackendChangeEvent::Object` payload.
///
/// `mtime_unix_ms` is Unix milliseconds; ms precision is the
/// FFI-boundary clock contract.
#[repr(C)]
#[derive(Debug)]
pub struct BackendChangeEventObject {
    pub address: Str,
    pub kind: ChangeKind,
    /// Etag of the object after the change. Opaque precondition token.
    pub etag: Optional<Str>,
    /// Backend-specific version identifier when the notification
    /// carries it.
    pub version: Optional<Str>,
    /// Object size in bytes when the notification carries it.
    pub size: Optional<u64>,
    /// Last-modified time of the object after the change in Unix
    /// milliseconds, when the notification carries it.
    pub mtime_unix_ms: Optional<i64>,
    pub at_unix_ms: i64,
    pub cursor: WatchDirectoryCursor,
}

unsafe impl Send for BackendChangeEventObject {}

/// `BackendChangeEvent::Lapsed` payload.
#[repr(C)]
#[derive(Debug)]
pub struct BackendChangeEventLapsed {
    pub since_unix_ms: Optional<i64>,
    pub cursor: WatchDirectoryCursor,
}

unsafe impl Send for BackendChangeEventLapsed {}

/// One change event yielded by a [`BackendChangeStream`].
#[repr(C)]
#[derive(Debug)]
pub struct BackendChangeEvent {
    pub tag: BackendChangeEventTag,
    pub object: core::mem::MaybeUninit<BackendChangeEventObject>,
    pub lapsed: core::mem::MaybeUninit<BackendChangeEventLapsed>,
}

unsafe impl Send for BackendChangeEvent {}

impl BackendChangeEvent {
    pub fn from_object(value: BackendChangeEventObject) -> Self {
        Self {
            tag: BackendChangeEventTag::Object,
            object: core::mem::MaybeUninit::new(value),
            lapsed: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn from_lapsed(value: BackendChangeEventLapsed) -> Self {
        Self {
            tag: BackendChangeEventTag::Lapsed,
            object: core::mem::MaybeUninit::uninit(),
            lapsed: core::mem::MaybeUninit::new(value),
        }
    }
}

impl Drop for BackendChangeEvent {
    fn drop(&mut self) {
        unsafe {
            match self.tag {
                BackendChangeEventTag::Object => self.object.assume_init_drop(),
                BackendChangeEventTag::Lapsed => self.lapsed.assume_init_drop(),
            }
        }
    }
}

/// Drop a [`BackendChangeEvent`]'s active payload in place. Safe with
/// NULL. The pointee is caller-owned `out_item` storage.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`BackendChangeEvent`] produced by an ovstorage call.
/// Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_backend_change_event_free(
    value: *mut BackendChangeEvent,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

// ---------------------------------------------------------------------
// Streaming iterator shapes
//
// Two concrete stream types (`AuthEventStream`, `BackendChangeStream`)
// rather than a generic — C consumers get explicit named types.
// Shape: `(state, next_fn, drop_fn)`. `next_fn` writes item or error
// into out-pointers and returns [`StreamStep`]. The plugin must not
// retain `state` after `drop_fn` returns.
// ---------------------------------------------------------------------

/// Three-state status returned by a stream's `next_fn`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StreamStep {
    /// `out_item` has been written; continue calling `next_fn`.
    Yielded = 0,
    /// Stream is exhausted; neither out-pointer is written. Subsequent
    /// calls are no-ops.
    Ended = 1,
    /// `out_error` written; the stream is now exhausted. Subsequent
    /// calls are no-ops.
    Failed = 2,
}

/// `next_fn` signature for [`AuthEventStream`].
pub type AuthEventNextFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    out_item: *mut AuthEvent,
    out_error: *mut Error,
) -> StreamStep;

/// `drop_fn` signature shared by every stream type.
pub type StreamDropFn = unsafe extern "C" fn(state: *mut core::ffi::c_void);

/// Plugin-emitted iterator yielding `AuthEvent`s. `state` is opaque
/// plugin-owned data; `next_fn` and `drop_fn` are non-null.
#[repr(C)]
pub struct AuthEventStream {
    pub state: *mut core::ffi::c_void,
    pub next_fn: AuthEventNextFn,
    pub drop_fn: StreamDropFn,
}

unsafe impl Send for AuthEventStream {}

impl Drop for AuthEventStream {
    fn drop(&mut self) {
        // SAFETY: `drop_fn` is valid for the lifetime of `state`.
        unsafe { (self.drop_fn)(self.state) }
    }
}

/// `next_fn` signature for [`BackendChangeStream`].
pub type BackendChangeNextFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    out_item: *mut BackendChangeEvent,
    out_error: *mut Error,
) -> StreamStep;

/// Plugin-emitted iterator over `Result<BackendChangeEvent>`.
#[repr(C)]
pub struct BackendChangeStream {
    pub state: *mut core::ffi::c_void,
    pub next_fn: BackendChangeNextFn,
    pub drop_fn: StreamDropFn,
}

unsafe impl Send for BackendChangeStream {}

impl Drop for BackendChangeStream {
    fn drop(&mut self) {
        unsafe { (self.drop_fn)(self.state) }
    }
}

/// Reclaim a heap-allocated [`AuthEventStream`] returned through a
/// `FactoryAuthenticateCallback`. Drives `drop_fn` exactly once
/// before releasing the outer allocation. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_auth_event_stream_free(value: *mut AuthEventStream) {
    unsafe {
        if value.is_null() {
            return;
        }
        drop(Box::from_raw(value));
    }
}

/// Reclaim a heap-allocated [`BackendChangeStream`] returned through
/// a `BackendChangeStreamCallback`. Drives `drop_fn` exactly once
/// before releasing the outer allocation. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_backend_change_stream_free(
    value: *mut BackendChangeStream,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        drop(Box::from_raw(value));
    }
}

// ---------------------------------------------------------------------
// Backend address-roots change events
// ---------------------------------------------------------------------

/// Tag for [`BackendAddressRootsChange`]. Mirrors the variants of the
/// crate-root `AddressRootsChange` enum.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BackendAddressRootsChangeTag {
    Snapshot = 0,
    Added = 1,
    Removed = 2,
}

/// One frame in a [`BackendAddressRootsStream`]. All three variants
/// carry the same payload shape — a list of address-root entries —
/// so a single discriminated struct (no MaybeUninit union) suffices.
#[repr(C)]
pub struct BackendAddressRootsChange {
    pub tag: BackendAddressRootsChangeTag,
    pub roots: List<AddressRootEntry>,
}

unsafe impl Send for BackendAddressRootsChange {}

/// Drop a [`BackendAddressRootsChange`] in place. Safe with NULL. The
/// pointee is caller-owned `out_item` storage.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`BackendAddressRootsChange`] produced by an ovstorage call.
/// Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_backend_address_roots_change_free(
    value: *mut BackendAddressRootsChange,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// `next_fn` signature for [`BackendAddressRootsStream`].
pub type BackendAddressRootsNextFn = unsafe extern "C" fn(
    state: *mut core::ffi::c_void,
    out_item: *mut BackendAddressRootsChange,
    out_error: *mut Error,
) -> StreamStep;

/// Plugin-emitted iterator over `Result<BackendAddressRootsChange>`.
/// Address-root deltas are coarse-grained and infrequent; the host
/// drives the iterator from a per-connection task that wakes on each
/// pushed frame.
#[repr(C)]
pub struct BackendAddressRootsStream {
    pub state: *mut core::ffi::c_void,
    pub next_fn: BackendAddressRootsNextFn,
    pub drop_fn: StreamDropFn,
}

unsafe impl Send for BackendAddressRootsStream {}

impl Drop for BackendAddressRootsStream {
    fn drop(&mut self) {
        unsafe { (self.drop_fn)(self.state) }
    }
}

/// Reclaim a heap-allocated [`BackendAddressRootsStream`] returned
/// through a `BackendWatchAddressRootsCallback`. Drives `drop_fn`
/// exactly once before releasing the outer allocation. Safe with NULL.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_backend_address_roots_stream_free(
    value: *mut BackendAddressRootsStream,
) {
    unsafe {
        if value.is_null() {
            return;
        }
        drop(Box::from_raw(value));
    }
}

// ---------------------------------------------------------------------
