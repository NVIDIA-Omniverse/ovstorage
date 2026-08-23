// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 cdylib of the conformance test backend, built on an
//! **instrumented `#[global_allocator]`**.
//!
//! `#[global_allocator]` is a per-artifact choice. This cdylib installs one;
//! the host executable that loads it installs another. That is the whole
//! point, and it makes both directions of the defect observable:
//!
//! * A value this plugin mints through `Box`/`Vec` lands on
//!   `CountingAllocator`. If the host reclaims it through the host's own
//!   global allocator, this allocator's `dealloc` never runs for that block
//!   and it stays counted by `retained`.
//! * A value the host mints and this plugin frees through `Box`/`Vec`
//!   reaches this allocator's `dealloc` for a block it never minted, and is
//!   counted by `foreign_frees`.
//!
//! The two are reported separately and never netted, because one of each per
//! round-trip would cancel in a single signed total.
//!
//! Values that cross the ABI must therefore not touch this allocator at all:
//! `ovstorage_plugin::ffi::abi_alloc` mints and reclaims them on the shared
//! process heap, which both binaries name identically. Both counters are
//! consequently flat across repeated ABI round-trips.
//!
//! `tests/cross_allocator.rs` drives that across two different iteration
//! counts and asserts neither counter grows with the number of round-trips.
//! Warm-up state (lazy statics, pools, runtime scaffolding) is constant per
//! process and so cancels out of the comparison; a mis-allocated ABI buffer
//! scales with the iteration count and does not.
//!
//! The plugin surface itself is the same `ovstorage-plugin-test` backend the
//! sibling `ovstorage-plugin-test-abi` cdylib exports — only the allocator
//! differs. Keeping it in its own artifact leaves that sibling (and every
//! test that loads it) on the ordinary allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

ovstorage_plugin::ovstorage_layer_plugin!(
    backend,
    ovstorage_plugin_test::TestLayerFactory::default,
    test_only
);

// ---------------------------------------------------------------------
// Live-block membership
//
// The two defects are opposite in sign, so a single net counter lets them
// cancel: one plugin-minted block wrongly released by the host is +1, one
// host-minted block wrongly released through this allocator is -1, and a
// net of zero hides both. Telling them apart needs to know, per block,
// whether this allocator is the one that minted it.
//
// A fixed-capacity direct-mapped table, `WAYS` entries per bucket. Removal
// clears its entry outright, so no tombstones accumulate and capacity is
// governed by blocks live at one instant rather than by total churn. The
// table is static, so tracking never re-enters the allocator.
// ---------------------------------------------------------------------

const BUCKETS: usize = 1 << 16;
const WAYS: usize = 16;
const EMPTY: usize = 0;

static LIVE: [AtomicUsize; BUCKETS * WAYS] = [const { AtomicUsize::new(EMPTY) }; BUCKETS * WAYS];

/// Blocks minted here and not yet returned here.
static RETAINED: AtomicI64 = AtomicI64::new(0);
/// Addresses this allocator minted a second time while the first block at
/// that address was still tracked as live. The only way that happens is if
/// something released the first block without going through this
/// allocator's `dealloc` — the producer-side defect, observed at the point
/// the underlying heap recycles the address.
static ESCAPED: AtomicI64 = AtomicI64::new(0);
/// Releases through this allocator of blocks it never minted.
static FOREIGN_FREES: AtomicI64 = AtomicI64::new(0);
/// Blocks that did not fit their bucket and so are not tracked. Non-zero
/// makes both counters above unreliable, so the test fails on it rather
/// than reading them.
static UNTRACKED: AtomicI64 = AtomicI64::new(0);

fn bucket_of(ptr: usize) -> usize {
    // A full avalanche mixer (splitmix64's finalizer), not a single
    // multiply. Heap pointers arrive as long runs at a fixed stride, and a
    // one-multiply hash maps a fixed stride to a fixed stride: consecutive
    // blocks then land in a short cycle of buckets and overflow their ways
    // while the table as a whole is nearly empty.
    let mut z = ptr as u64;
    z ^= z >> 30;
    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z as usize) % BUCKETS
}

fn remember(ptr: *mut u8) {
    let key = ptr as usize;
    let base = bucket_of(key) * WAYS;
    let bucket = &LIVE[base..base + WAYS];
    // An address already tracked as live cannot legitimately be handed out
    // again: the heap only recycles it once it has been released, and a
    // release that reached this allocator would have cleared the entry.
    // Record the escape and keep the single entry rather than stacking a
    // duplicate, which would saturate the bucket and lose the signal.
    for slot in bucket {
        if slot.load(Ordering::Acquire) == key {
            ESCAPED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    for slot in bucket {
        if slot
            .compare_exchange(EMPTY, key, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            RETAINED.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    UNTRACKED.fetch_add(1, Ordering::Relaxed);
}

/// Clear `ptr`'s entry, reporting whether this allocator minted it.
fn forget(ptr: *mut u8) -> bool {
    let key = ptr as usize;
    let base = bucket_of(key) * WAYS;
    for slot in &LIVE[base..base + WAYS] {
        if slot
            .compare_exchange(key, EMPTY, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            RETAINED.fetch_sub(1, Ordering::Relaxed);
            return true;
        }
    }
    false
}

/// Delegates to [`System`] and tracks membership. Delegating rather than
/// using a genuinely separate heap keeps a cross-allocator free from
/// corrupting the process, so a defect surfaces as a counter that grows with
/// the iteration count instead of as an abort mid-test.
struct CountingAllocator;

// SAFETY: every method forwards its exact arguments to `System`, which
// satisfies the `GlobalAlloc` contract; the bookkeeping is the only
// addition and touches no heap.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            remember(ptr);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            remember(ptr);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !forget(ptr) {
            FOREIGN_FREES.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // `System::realloc` may move the block, so retire the old key and
        // record whatever comes back. A failed realloc leaves the original
        // live, so put it back.
        let was_ours = forget(ptr);
        let out = unsafe { System.realloc(ptr, layout, new_size) };
        if out.is_null() {
            if was_ours {
                remember(ptr);
            }
            return out;
        }
        if was_ours {
            remember(out);
        } else {
            FOREIGN_FREES.fetch_add(1, Ordering::Relaxed);
        }
        out
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// The producer-direction probe: blocks this allocator minted whose release
/// did not come back to it.
///
/// Sums the two ways that shows up — a block still tracked as live, and one
/// whose address the heap has already recycled underneath us. Growth
/// proportional to the round-trip count means values this plugin produces
/// are minted here and released on the host's allocator.
#[unsafe(no_mangle)]
pub extern "C" fn ovstorage_test_abi_alloc_retained() -> i64 {
    RETAINED.load(Ordering::Relaxed) + ESCAPED.load(Ordering::Relaxed)
}

/// Releases through this cdylib's global allocator of blocks it never
/// minted.
///
/// The opposite direction: growth means values the host produces are being
/// released on the plugin's allocator. Counted separately from
/// [`ovstorage_test_abi_alloc_retained`] so the two cannot net out.
#[unsafe(no_mangle)]
pub extern "C" fn ovstorage_test_abi_alloc_foreign_frees() -> i64 {
    FOREIGN_FREES.load(Ordering::Relaxed)
}

/// Blocks the membership table had no room for. Non-zero invalidates both
/// counters above.
#[unsafe(no_mangle)]
pub extern "C" fn ovstorage_test_abi_alloc_untracked() -> i64 {
    UNTRACKED.load(Ordering::Relaxed)
}
