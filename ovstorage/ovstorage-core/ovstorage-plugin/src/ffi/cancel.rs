// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-FFI cancellation plumbing.
//!
//! The host hands plugin vtable methods a borrowed
//! `*const CancelTokenFFI`. Plugins materialize a local cancel
//! observer with [`cancel_token_from_ffi`] and react cooperatively.
//!
//! # Lifecycle
//!
//! [`AtomicCancelState`] is a refcounted, atomic-flagged struct
//! shared between host and plugin via raw pointer. The refcount
//! starts at 1; receivers call `clone(state)` to retain past the
//! synchronous prologue and pair every clone with `drop(state)`. The
//! state is freed at refcount 0.
//!
//! # Rules across FFI
//!
//! - `CancelTokenFFI` is `Copy`; its function-pointer slots are
//!   statically linked. Receivers must call only those slots, never
//!   reach into the host's memory beyond `state`.
//! - The `state` pointer is borrowed for the synchronous prologue.
//!   To retain it longer, clone+drop in pairs.
//! - Callbacks registered via `register_callback` MUST NOT call back
//!   into `AtomicCancelState` methods. Their only job is to wake a
//!   local signal.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------

/// Shared state behind a [`CancelTokenFFI`]. Opaque to foreign code;
/// access exclusively via the vtable's function pointers.
pub struct AtomicCancelState {
    canceled: AtomicBool,
    refs: AtomicUsize,
    callbacks: parking_lot::Mutex<CallbackList>,
}

struct CallbackList {
    next_id: u64,
    entries: Vec<CallbackEntry>,
}

struct CallbackEntry {
    id: u64,
    cb: extern "C" fn(*mut c_void),
    user_data: *mut c_void,
}

// SAFETY: `user_data` is owned by the registrant and only ever
// passed back to its callback; the entry is removed before the
// registrant frees the data, or fired once on the canceler's thread.
unsafe impl Send for CallbackEntry {}

impl AtomicCancelState {
    fn new_boxed() -> *const Self {
        let state = Box::new(Self {
            canceled: AtomicBool::new(false),
            refs: AtomicUsize::new(1),
            callbacks: parking_lot::Mutex::new(CallbackList {
                next_id: 1,
                entries: Vec::new(),
            }),
        });
        Box::into_raw(state) as *const Self
    }

    fn already_canceled() -> *const Self {
        let state = Box::new(Self {
            canceled: AtomicBool::new(true),
            refs: AtomicUsize::new(1),
            callbacks: parking_lot::Mutex::new(CallbackList {
                next_id: 1,
                entries: Vec::new(),
            }),
        });
        Box::into_raw(state) as *const Self
    }

    /// Flip canceled false → true and fire all registered callbacks.
    /// Idempotent; only the winning thread fires.
    fn cancel(&self) {
        if self
            .canceled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Hold the lock through firing so unregister can't race a
        // callback that's about to fire. Callbacks MUST NOT re-enter.
        let mut list = self.callbacks.lock();
        let drained: Vec<CallbackEntry> = std::mem::take(&mut list.entries);
        for entry in drained {
            (entry.cb)(entry.user_data);
        }
    }
}

// ---------------------------------------------------------------------
// extern "C" vtable functions
// ---------------------------------------------------------------------

// `is_canceled` slot of the `CancelTokenFFI` vtable; the host calls it
// through the vtable pointer to poll cancellation, never by symbol name.
/// cbindgen:ignore
extern "C" fn ffi_is_canceled(state: *const AtomicCancelState) -> bool {
    if state.is_null() {
        return false;
    }
    // SAFETY: caller's `state` is alive per refcount discipline.
    let state = unsafe { &*state };
    state.canceled.load(Ordering::Acquire)
}

// `register_callback` slot of the `CancelTokenFFI` vtable; invoked through
// the vtable pointer to arm a cancel callback, never by symbol name.
/// cbindgen:ignore
extern "C" fn ffi_register_callback(
    state: *const AtomicCancelState,
    cb: extern "C" fn(*mut c_void),
    user_data: *mut c_void,
) -> u64 {
    if state.is_null() {
        return 0;
    }
    let state = unsafe { &*state };

    // Already-canceled: fire synchronously and return id 0
    // (unregister(0) is a documented no-op).
    if state.canceled.load(Ordering::Acquire) {
        cb(user_data);
        return 0;
    }
    let mut list = state.callbacks.lock();
    // Re-check under the lock: a racing cancel() either sees us in
    // its drain set, or has already swapped the flag.
    if state.canceled.load(Ordering::Acquire) {
        drop(list);
        cb(user_data);
        return 0;
    }
    let id = list.next_id;
    list.next_id = list.next_id.wrapping_add(1).max(1);
    list.entries.push(CallbackEntry { id, cb, user_data });
    id
}

// `unregister_callback` slot of the `CancelTokenFFI` vtable; invoked through
// the vtable pointer to drop a previously-armed callback, never by symbol name.
/// cbindgen:ignore
extern "C" fn ffi_unregister_callback(state: *const AtomicCancelState, sub_id: u64) {
    if state.is_null() || sub_id == 0 {
        return;
    }
    // SAFETY: see ffi_is_canceled.
    let state = unsafe { &*state };
    let mut list = state.callbacks.lock();
    list.entries.retain(|e| e.id != sub_id);
}

// `clone` slot of the `CancelTokenFFI` vtable; invoked through the vtable
// pointer to bump the token state's refcount, never by symbol name.
/// cbindgen:ignore
extern "C" fn ffi_clone(state: *const AtomicCancelState) -> *const AtomicCancelState {
    if state.is_null() {
        return std::ptr::null();
    }
    let s = unsafe { &*state };
    // Resurrecting from refcount 0 means the state is freed (UAF on
    // the input pointer); back out and return null defensively.
    let prev = s.refs.fetch_add(1, Ordering::Relaxed);
    if prev == 0 {
        s.refs.fetch_sub(1, Ordering::Relaxed);
        return std::ptr::null();
    }
    state
}

// `drop` slot of the `CancelTokenFFI` vtable; invoked through the vtable
// pointer to release a token-state refcount, never by symbol name.
/// cbindgen:ignore
extern "C" fn ffi_drop(state: *const AtomicCancelState) {
    if state.is_null() {
        return;
    }
    // SAFETY: see ffi_is_canceled.
    let s = unsafe { &*state };
    let prev = s.refs.fetch_sub(1, Ordering::Release);
    if prev == 1 {
        // Acquire fence pairs with the Release in every clone's
        // fetch_add so prior writes are visible before free.
        std::sync::atomic::fence(Ordering::Acquire);
        // SAFETY: refcount reached 0; exclusive ownership.
        unsafe {
            drop(Box::from_raw(state as *mut AtomicCancelState));
        }
    }
}

// ---------------------------------------------------------------------
// FFI vtable struct
// ---------------------------------------------------------------------

/// Cross-FFI cancellation token handle. `Copy`-passable by value;
/// `state` carries refcount semantics (clone+drop in pairs).
/// Function-pointer slots are statically linked.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CancelTokenFFI {
    pub state: *const AtomicCancelState,
    pub is_canceled: extern "C" fn(*const AtomicCancelState) -> bool,
    pub register_callback: extern "C" fn(
        *const AtomicCancelState,
        cb: extern "C" fn(*mut c_void),
        user_data: *mut c_void,
    ) -> u64,
    pub unregister_callback: extern "C" fn(*const AtomicCancelState, sub_id: u64),
    pub clone: extern "C" fn(*const AtomicCancelState) -> *const AtomicCancelState,
    pub drop: extern "C" fn(*const AtomicCancelState),
}

fn cancel_token_ffi_with_state(state: *const AtomicCancelState) -> CancelTokenFFI {
    CancelTokenFFI {
        state,
        is_canceled: ffi_is_canceled,
        register_callback: ffi_register_callback,
        unregister_callback: ffi_unregister_callback,
        clone: ffi_clone,
        drop: ffi_drop,
    }
}

// ---------------------------------------------------------------------
// Host side: CancellationToken -> CancelTokenFFI (via owned handle)
// ---------------------------------------------------------------------

/// Host-side handle pairing a [`CancelTokenFFI`] value with the
/// bridge task that connects `host_token.cancelled()` to
/// `state.cancel()`. Drop aborts the bridge and drops the host's
/// primary refcount; the state lives on while plugins hold clones.
pub struct CancelTokenHandle {
    ffi: CancelTokenFFI,
    bridge: Option<tokio::task::AbortHandle>,
}

// SAFETY: `state` addresses a thread-safe `AtomicCancelState`; the
// vtable's function pointers carry no per-instance non-Send state.
unsafe impl Send for CancelTokenHandle {}
unsafe impl Sync for CancelTokenHandle {}

impl CancelTokenHandle {
    /// Borrow a `*const CancelTokenFFI` valid for `&self`'s lifetime.
    pub fn as_ffi_ptr(&self) -> *const CancelTokenFFI {
        &self.ffi as *const _
    }

    /// Fire the FFI-side cancel state now, on the calling thread.
    ///
    /// The host's [`CancellationToken`] and the FFI state are two objects, and
    /// [`cancel_token_to_ffi`]'s bridge task is the only path between them —
    /// a path [`Drop`] tears down. A caller that gives up on a call before its
    /// completion arrives (dropping the future that owns this handle) must
    /// therefore signal the producer itself, or the producer, still holding a
    /// refcounted clone of this state, is never told to stop.
    pub fn cancel_producer(&self) {
        if self.ffi.state.is_null() {
            return;
        }
        // SAFETY: the handle holds the host's primary refcount on `state`, so
        // it is live for `&self`; `cancel` takes `&self` and is thread-safe.
        unsafe { (*self.ffi.state).cancel() };
    }
}

impl Drop for CancelTokenHandle {
    fn drop(&mut self) {
        if let Some(bridge) = self.bridge.take() {
            bridge.abort();
        }
        (self.ffi.drop)(self.ffi.state);
    }
}

/// RAII helper holding a state refcount inside the bridge task so
/// abort mid-await still balances the refcount.
struct BridgeStateGuard(*const AtomicCancelState);

unsafe impl Send for BridgeStateGuard {}

impl Drop for BridgeStateGuard {
    fn drop(&mut self) {
        ffi_drop(self.0);
    }
}

/// Convert a host-side `CancellationToken` into a [`CancelTokenHandle`].
/// Caller MUST hold the handle until the cancel observation
/// completes — dropping early aborts the bridge.
///
/// # Panics
///
/// Panics if no tokio runtime is running on the calling thread.
pub fn cancel_token_to_ffi(host_token: CancellationToken) -> CancelTokenHandle {
    // Fast path: skip the bridge task when already canceled.
    if host_token.is_cancelled() {
        let state = AtomicCancelState::already_canceled();
        return CancelTokenHandle {
            ffi: cancel_token_ffi_with_state(state),
            bridge: None,
        };
    }
    let state = AtomicCancelState::new_boxed();
    // Wrap the bridge's refcount in a Send guard so the raw pointer
    // crosses the spawn boundary safely.
    let guard = BridgeStateGuard(ffi_clone(state));
    let bridge = tokio::spawn(async move {
        let guard = guard;
        host_token.cancelled().await;
        // SAFETY: guard.0 is a live state; refcount kept us alive.
        unsafe {
            (*guard.0).cancel();
        }
        drop(guard);
    });
    CancelTokenHandle {
        ffi: cancel_token_ffi_with_state(state),
        bridge: Some(bridge.abort_handle()),
    }
}

// ---------------------------------------------------------------------
// Plugin side: CancelTokenFFI -> local CancellationToken
// ---------------------------------------------------------------------

/// Plugin-side wrapper exposing a local [`CancellationToken`] that
/// fires when the host signals via the FFI handle. Drop unregisters
/// the callback and releases the plugin's refcount.
pub struct CancelTokenLocal {
    token: CancellationToken,
    // Kept solely for its `Drop` impl: unregister + free + decrement.
    #[allow(dead_code)]
    cleanup: CancelTokenLocalCleanup,
}

// SAFETY: shared `AtomicCancelState` is thread-safe; `WakerData` is
// solely owned by this guard.
unsafe impl Send for CancelTokenLocal {}
unsafe impl Sync for CancelTokenLocal {}

impl CancelTokenLocal {
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    /// Clone the underlying token (cleanup still runs when `self`
    /// drops). Useful for `tokio::select!` arms.
    pub fn token_clone(&self) -> CancellationToken {
        self.token.clone()
    }
}

struct CancelTokenLocalCleanup {
    state: *const AtomicCancelState,
    drop_fn: extern "C" fn(*const AtomicCancelState),
    unregister_fn: extern "C" fn(*const AtomicCancelState, u64),
    sub_id: u64,
    waker_data: *mut WakerData,
}

unsafe impl Send for CancelTokenLocalCleanup {}
unsafe impl Sync for CancelTokenLocalCleanup {}

impl Drop for CancelTokenLocalCleanup {
    fn drop(&mut self) {
        // Unregister first: under the cancel-state lock our entry is
        // either removed or already drained.
        (self.unregister_fn)(self.state, self.sub_id);
        if !self.waker_data.is_null() {
            // SAFETY: produced by Box::into_raw; aliasing is ruled
            // out by the lock-serialized unregister above.
            unsafe {
                drop(Box::from_raw(self.waker_data));
            }
        }
        (self.drop_fn)(self.state);
    }
}

struct WakerData {
    token: CancellationToken,
}

// Callback registered via the host token's `register_callback` slot; fired by
// pointer when the host cancels to wake the plugin-local `CancellationToken`.
/// cbindgen:ignore
extern "C" fn wake_local_token(user_data: *mut c_void) {
    if user_data.is_null() {
        return;
    }
    // SAFETY: user_data is `Box::into_raw(WakerData)`, valid until
    // its owning `CancelTokenLocal` unregisters this callback.
    let waker = unsafe { &*(user_data as *const WakerData) };
    waker.token.cancel();
}

/// Materialize a plugin-local [`CancellationToken`] from a borrowed
/// host-side handle. Drop the returned wrapper on task exit to
/// release the refcount and unregister the callback.
pub fn cancel_token_from_ffi(ffi: &CancelTokenFFI) -> CancelTokenLocal {
    let token = CancellationToken::new();
    let waker_data = Box::into_raw(Box::new(WakerData {
        token: token.clone(),
    }));
    let plugin_state = (ffi.clone)(ffi.state);
    let sub_id = (ffi.register_callback)(plugin_state, wake_local_token, waker_data as *mut c_void);
    // sub_id == 0 means host was already canceled and the callback
    // fired synchronously; the token is already canceled.
    CancelTokenLocal {
        token,
        cleanup: CancelTokenLocalCleanup {
            state: plugin_state,
            drop_fn: ffi.drop,
            unregister_fn: ffi.unregister_callback,
            sub_id,
            waker_data,
        },
    }
}

// ---------------------------------------------------------------------
// FFI status helpers (callback status code <-> Result)
// ---------------------------------------------------------------------

/// Status code returned to `on_complete` callbacks. `0`
/// ([`FFI_STATUS_OK`]) is reserved for success; errors return
/// [`FFI_STATUS_ERR`] (`-1`) and carry the real `ErrorCode` on the
/// `*mut Error`. Reserving `0` avoids a collision with
/// `ErrorCode::NotFound` (also discriminant `0`).
pub type FfiStatus = i32;
pub const FFI_STATUS_OK: FfiStatus = 0;
pub const FFI_STATUS_ERR: FfiStatus = -1;

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CounterUserData(Arc<AtomicU32>);

    extern "C" fn count_cb(user_data: *mut c_void) {
        let data = unsafe { &*(user_data as *const CounterUserData) };
        data.0.fetch_add(1, Ordering::SeqCst);
    }

    fn make_state_handle() -> (*const AtomicCancelState, CancelTokenFFI) {
        let state = AtomicCancelState::new_boxed();
        let ffi = cancel_token_ffi_with_state(state);
        (state, ffi)
    }

    #[test]
    fn register_then_cancel_fires_callback_once() {
        let counter = Arc::new(AtomicU32::new(0));
        let data = Box::into_raw(Box::new(CounterUserData(counter.clone())));
        let (state, ffi) = make_state_handle();

        let id = (ffi.register_callback)(state, count_cb, data as *mut c_void);
        assert_ne!(id, 0);
        assert!(!(ffi.is_canceled)(state));

        unsafe {
            (*state).cancel();
        }
        assert!((ffi.is_canceled)(state));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        unsafe {
            (*state).cancel();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        (ffi.drop)(state);
        unsafe {
            drop(Box::from_raw(data));
        }
    }

    #[test]
    fn register_after_cancel_fires_synchronously_returns_zero_id() {
        let counter = Arc::new(AtomicU32::new(0));
        let data = Box::into_raw(Box::new(CounterUserData(counter.clone())));
        let (state, ffi) = make_state_handle();

        unsafe {
            (*state).cancel();
        }
        let id = (ffi.register_callback)(state, count_cb, data as *mut c_void);
        assert_eq!(id, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        (ffi.unregister_callback)(state, 0);

        (ffi.drop)(state);
        unsafe {
            drop(Box::from_raw(data));
        }
    }

    #[test]
    fn unregister_then_cancel_does_not_fire() {
        let counter = Arc::new(AtomicU32::new(0));
        let data = Box::into_raw(Box::new(CounterUserData(counter.clone())));
        let (state, ffi) = make_state_handle();

        let id = (ffi.register_callback)(state, count_cb, data as *mut c_void);
        (ffi.unregister_callback)(state, id);
        unsafe {
            (*state).cancel();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        (ffi.drop)(state);
        unsafe {
            drop(Box::from_raw(data));
        }
    }

    #[test]
    fn clone_then_cancel_via_clone_observed_by_original() {
        let (state, ffi) = make_state_handle();
        let clone = (ffi.clone)(state);
        assert!(!(ffi.is_canceled)(state));
        unsafe {
            (*clone).cancel();
        }
        assert!((ffi.is_canceled)(state));
        assert!((ffi.is_canceled)(clone));
        (ffi.drop)(clone);
        (ffi.drop)(state);
    }

    #[test]
    fn refcount_balanced_drop_frees_state() {
        // Smoke test only — a UAF-detection check belongs under Miri/valgrind.
        let (state, ffi) = make_state_handle();
        let clone = (ffi.clone)(state);
        (ffi.drop)(clone);
        assert!(!(ffi.is_canceled)(state));
        (ffi.drop)(state);
    }

    #[test]
    fn round_trip_host_token_to_local_via_ffi() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let host_token = CancellationToken::new();
            let handle = cancel_token_to_ffi(host_token.clone());
            let local = cancel_token_from_ffi(unsafe { &*handle.as_ffi_ptr() });
            let local_token = local.token_clone();

            let task = tokio::spawn(async move {
                local_token.cancelled().await;
                "cancelled"
            });

            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            host_token.cancel();

            let result = tokio::time::timeout(std::time::Duration::from_millis(500), task)
                .await
                .expect("local token did not fire within 500ms")
                .unwrap();
            assert_eq!(result, "cancelled");

            drop(local);
            drop(handle);
        });
    }

    #[test]
    fn already_canceled_host_token_yields_canceled_local() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let host_token = CancellationToken::new();
            host_token.cancel();
            let handle = cancel_token_to_ffi(host_token);
            assert!((handle.ffi.is_canceled)(handle.ffi.state));

            let local = cancel_token_from_ffi(unsafe { &*handle.as_ffi_ptr() });
            assert!(local.token().is_cancelled());

            drop(local);
            drop(handle);
        });
    }
}
