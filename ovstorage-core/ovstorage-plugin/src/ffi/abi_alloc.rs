// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allocator for every value that crosses the plugin ABI.
//!
//! # Why not the Rust global allocator
//!
//! `#[global_allocator]` is a per-binary choice. The host executable and
//! each plugin cdylib link their own copy of this crate's rlib, so
//! `Box`/`Vec` in the host resolve to the host's global allocator and the
//! same code in a plugin resolves to the plugin's. A plugin that installs
//! jemalloc or mimalloc — both ordinary choices for a plugin author —
//! therefore mints an ABI buffer on one heap that the host releases on
//! another.
//!
//! Routing the release through a producer-exported `ovstorage_plugin_*_free`
//! symbol does not help: those exports live in this rlib too, so a Rust
//! caller binds to its own binary's copy and lands back on its own heap.
//!
//! # The contract
//!
//! Every allocation reachable through an ABI value — the outer heap
//! envelope and every [`Str`](super::Str) / [`Bytes`](super::Bytes) /
//! [`List`](super::List) buffer nested inside it — is minted and reclaimed
//! through [`System`], the operating-system allocator. `System` is not
//! redirectable by `#[global_allocator]`, so it names one process-wide heap
//! that every binary in the process agrees on: `malloc`/`free` on POSIX and
//! the process heap on Win32. That is the same pair the pure-C distribution
//! uses (`ovc_abi_alloc` / `ovc_abi_free` in `ovstorage-c-source`), which is
//! what makes a C host and a Rust plugin interchangeable.
//!
//! Allocations that never cross the boundary — plugin-internal state, host
//! bookkeeping, `user_data` a side hands out and takes back itself — stay on
//! the ordinary global allocator.
//!
//! # Buffer convention
//!
//! Buffer allocations use `capacity == max(len, 1)`: an empty
//! [`Str`](super::Str), [`Bytes`](super::Bytes), or [`List`](super::List)
//! still carries a non-null one-element sentinel so consumers never
//! special-case NULL. [`abi_capacity`] is the single definition of that rule.
//!
//! # Alignment
//!
//! ABI types are `#[repr(C)]` aggregates of pointers and integers, so their
//! alignment never exceeds the allocator's natural alignment. `System`
//! satisfies larger alignments through a shim whose bookkeeping a plain C
//! `free` would not understand, so the helpers reject over-aligned types
//! rather than mint a buffer the C distribution could not release.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

// Largest alignment an ABI buffer may request. Matches the alignment
// `malloc` and the Win32 process heap guarantee, which is what keeps a
// buffer minted here releasable by `ovc_abi_free`. Internal invariant, not
// part of the C surface.
/// cbindgen:ignore
const MAX_ABI_ALIGN: usize = 16;

// Net ABI-heap bytes minted less released, by this binary.
//
// The accounting seam for ownership tests. A `#[global_allocator]` wrapper
// cannot see this traffic — that is the whole property this module provides
// — so a test that needs to prove an ABI value's nested buffers are released
// has no other vantage point. Two relaxed atomic updates per ABI allocation,
// against an allocation that already costs far more.
//
// Per binary, not per process: this crate links as an rlib into the host and
// into every plugin cdylib, so each carries its own `LIVE_BYTES`, and a
// value crossing the ABI moves between two of them.
/// cbindgen:ignore
static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

/// Net ABI-heap bytes this binary has minted less those it has released.
///
/// Not a live-ownership figure. Each binary links its own copy of this
/// crate and so its own counter, and a value handed across the ABI is
/// minted against one and released against the other: after a balanced
/// transfer the producer's counter reads positive and the consumer's
/// negative, with neither describing what is live.
///
/// It is meaningful as a difference across a window in which allocation and
/// release both happen in the reading binary — which is what the
/// same-binary ownership tests use it for.
pub fn abi_live_bytes() -> isize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// Allocated capacity for a buffer of `len` elements. Zero-length buffers
/// carry a one-element sentinel allocation.
#[inline]
pub const fn abi_capacity(len: usize) -> usize {
    if len == 0 { 1 } else { len }
}

/// Layout of an ABI buffer holding `count` elements of `T`.
///
/// Panics when `T` is over-aligned for the ABI allocator or when the size
/// computation overflows.
#[inline]
fn abi_layout<T>(count: usize) -> Layout {
    assert!(
        align_of::<T>() <= MAX_ABI_ALIGN,
        "ABI values are limited to {MAX_ABI_ALIGN}-byte alignment"
    );
    let layout = Layout::array::<T>(count).expect("ABI buffer layout overflows");
    // A zero-sized layout is UB to hand to the allocator, and no ABI type is
    // zero-sized; the sentinel rule keeps `count` at one or more.
    assert!(layout.size() > 0, "ABI buffers are never zero-sized");
    layout
}

/// Mint an uninitialized ABI buffer for `count` elements of `T`.
///
/// Aborts on allocation failure, matching the global allocator's behaviour
/// for an infallible `Vec` growth.
fn abi_alloc_array<T>(count: usize) -> *mut T {
    let layout = abi_layout::<T>(count);
    // SAFETY: `abi_layout` rejects zero-sized layouts implicitly — every
    // caller passes `count >= 1` and `T` is never zero-sized in the ABI.
    let ptr = unsafe { System.alloc(layout) } as *mut T;
    if ptr.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
    ptr
}

/// Release an ABI buffer of `count` elements of `T` without dropping the
/// elements.
///
/// # Safety
///
/// `ptr` must come from [`abi_alloc_array`] (or the C distribution's
/// `ovc_abi_alloc`) with the same `count`, and must not have been released.
/// Elements needing drop must already have been dropped or moved out.
unsafe fn abi_dealloc_array<T>(ptr: *mut T, count: usize) {
    let layout = abi_layout::<T>(count);
    LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    unsafe { System.dealloc(ptr.cast::<u8>(), layout) }
}

/// Move a `Vec<T>` into an ABI buffer, returning the buffer pointer. The
/// buffer holds `value.len()` initialized elements with capacity
/// [`abi_capacity`]`(len)`.
pub fn abi_vec_into_raw<T>(mut value: Vec<T>) -> *mut T {
    let len = value.len();
    let dest = abi_alloc_array::<T>(abi_capacity(len));
    // SAFETY: `dest` has room for `len` elements and the regions are
    // distinct. The source elements are moved, so the `Vec` must not drop
    // them: `set_len(0)` leaves it owning only its (global-allocator)
    // buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), dest, len);
        value.set_len(0);
    }
    dest
}

/// Copy a borrowed slice into an ABI buffer, returning the buffer pointer.
///
/// The [`abi_vec_into_raw`] counterpart for a source the caller keeps —
/// notably a secret buffer the caller must wipe rather than drop.
pub fn abi_slice_into_raw<T: Copy>(value: &[T]) -> *mut T {
    let dest = abi_alloc_array::<T>(abi_capacity(value.len()));
    // SAFETY: `dest` is a fresh allocation with room for `value.len()`
    // elements, so it cannot overlap `value`.
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), dest, value.len()) };
    dest
}

/// Move `len` elements out of an ABI buffer into a `Vec<T>` and release the
/// buffer.
///
/// # Safety
///
/// `ptr` must be a non-null ABI buffer holding `len` initialized elements
/// with capacity [`abi_capacity`]`(len)`, and must not be used afterwards.
pub unsafe fn abi_vec_from_raw<T>(ptr: *mut T, len: usize) -> Vec<T> {
    unsafe {
        let mut out = Vec::<T>::with_capacity(len);
        std::ptr::copy_nonoverlapping(ptr.cast_const(), out.as_mut_ptr(), len);
        out.set_len(len);
        abi_dealloc_array(ptr, abi_capacity(len));
        out
    }
}

/// Release an ABI buffer of `len` elements, dropping each element first.
///
/// # Safety
///
/// Same requirements as [`abi_vec_from_raw`].
pub unsafe fn abi_buffer_free<T>(ptr: *mut T, len: usize) {
    unsafe {
        std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(ptr, len));
        abi_dealloc_array(ptr, abi_capacity(len));
    }
}

/// Move `value` onto the ABI heap, returning the owning pointer. The
/// [`Box::into_raw`] counterpart for values that cross the boundary.
pub fn abi_box<T>(value: T) -> *mut T {
    let ptr = abi_alloc_array::<T>(1);
    // SAFETY: `ptr` is a fresh, correctly aligned, uninitialized `T` slot.
    unsafe { std::ptr::write(ptr, value) };
    ptr
}

/// A type-erased ABI-heap allocation, owned by whoever holds it.
///
/// The point is the *pointer's* type, not the value's. [`AbiOwned::new`] is
/// the only constructor and it mints through [`abi_box`], and the wrapped
/// pointer is private to this module, so a value spelled as an `AbiOwned`
/// cannot have come from anywhere else. That is what
/// `ffi_runtime` uses to type the success payload of an async slot
/// completion: `Box::into_raw` in that position does not typecheck, so an
/// envelope minted on the plugin's own global allocator and reclaimed by the
/// host through `abi_unbox` — a cross-allocator free — cannot be written
/// there. It is `pub(crate)` throughout: nothing outside this crate completes
/// a slot, and an out-of-crate holder could only leak one.
///
/// The ~19 `#[repr(C)]` envelope types cannot carry this guarantee
/// themselves — they are mirrored in `ovstorage_plugin.h` and constructed
/// field-by-field by a C host, so they have no private state and no
/// constructor to restrict.
///
/// It is a handoff token, not an owning smart pointer: the payload type is
/// erased, so dropping one without surrendering it leaks it and there
/// is no destructor that could do otherwise. Every value of this type is
/// built to be handed straight to a consumer.
///
/// Deliberately **not** `Send`. Holding a raw pointer, it does not derive
/// `Send`, and the async slot path does not need it: the envelope is built
/// and surrendered after the last `.await` in `spawn_async_stream_thunk`, so
/// it never enters the spawned task's generator state. Leaving it that way
/// means the compiler re-checks that on every edit — moving the mint across
/// an await fails with "future cannot be sent between threads safely" rather
/// than silently relying on an `unsafe impl` nobody re-derived.
#[must_use = "an AbiOwned is an ABI-heap allocation with no destructor; \
              dropping it without surrendering it leaks it"]
pub(crate) struct AbiOwned(*mut core::ffi::c_void);

impl AbiOwned {
    /// Move `value` onto the ABI heap.
    pub(crate) fn new<T>(value: T) -> Self {
        Self(abi_box(value).cast())
    }

    /// Surrender the allocation to the consumer that will reclaim it.
    pub(crate) fn into_raw(self) -> *mut core::ffi::c_void {
        self.0
    }
}

/// Move the value out of an ABI heap allocation and release it. The
/// [`Box::from_raw`] counterpart.
///
/// # Safety
///
/// `ptr` must be a non-null pointer from [`abi_box`] (or the C
/// distribution's equivalent) that has not been released, and must not be
/// used afterwards.
pub unsafe fn abi_unbox<T>(ptr: *mut T) -> T {
    unsafe {
        let value = std::ptr::read(ptr);
        abi_dealloc_array(ptr, 1);
        value
    }
}

/// Drop the value in an ABI heap allocation and release it. Tolerates NULL.
///
/// # Safety
///
/// Same requirements as [`abi_unbox`].
pub unsafe fn abi_box_free<T>(ptr: *mut T) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        drop(abi_unbox(ptr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffers_carry_a_one_element_sentinel() {
        assert_eq!(abi_capacity(0), 1);
        assert_eq!(abi_capacity(7), 7);
    }

    #[test]
    fn vec_round_trips_through_the_abi_heap() {
        let ptr = abi_vec_into_raw(vec![String::from("a"), String::from("b")]);
        let back = unsafe { abi_vec_from_raw(ptr, 2) };
        assert_eq!(back, vec![String::from("a"), String::from("b")]);
    }

    #[test]
    fn empty_vec_round_trips_through_the_sentinel() {
        let ptr = abi_vec_into_raw(Vec::<u8>::new());
        assert!(!ptr.is_null());
        let back = unsafe { abi_vec_from_raw(ptr, 0) };
        assert!(back.is_empty());
    }

    #[test]
    fn box_round_trips_through_the_abi_heap() {
        let ptr = abi_box(String::from("payload"));
        assert_eq!(unsafe { abi_unbox(ptr) }, "payload");
    }

    #[test]
    fn box_free_tolerates_null() {
        unsafe { abi_box_free(std::ptr::null_mut::<String>()) };
    }

    #[test]
    fn buffer_free_drops_every_element() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static DROPS: AtomicUsize = AtomicUsize::new(0);
        // Carries a payload: `abi_layout` rejects zero-sized types, and no
        // ABI type is zero-sized either.
        struct CountsItsDrop(#[allow(dead_code)] u64);
        impl Drop for CountsItsDrop {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }

        let ptr = abi_vec_into_raw(vec![CountsItsDrop(1), CountsItsDrop(2), CountsItsDrop(3)]);
        assert_eq!(
            DROPS.load(Ordering::Relaxed),
            0,
            "moving into the ABI buffer must not drop anything"
        );

        unsafe { abi_buffer_free(ptr, 3) };
        assert_eq!(
            DROPS.load(Ordering::Relaxed),
            3,
            "releasing the buffer must run every element's destructor, not \
             just reclaim the allocation"
        );
    }
}
