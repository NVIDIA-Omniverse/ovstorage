// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allocation accounting for the `create_router` children array.
//!
//! `CreateRouterRequest` carries `children` as a bare `*const RouterChild`
//! plus a `child_count`, not as an owning `List<RouterChild>`. That splits
//! ownership: the callee takes each child HANDLE (it reads every element
//! out and drops the handles itself), while the array's backing ALLOCATION
//! can only be freed by the host that made it — the plugin has no length-
//! carrying owner to drop and need not even share the host's allocator.
//!
//! `RouterChildArray` is where that split lives. Get it wrong in either
//! direction and the failure is silent: free the elements too and the
//! transferred handles are dropped twice; forget the whole `Vec` and the
//! buffer is freed by neither side. These tests count live bytes across a
//! real drop and count `LayerHandle::drop` calls through a vtable, pinning
//! both halves.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use ovstorage_plugin::marshal::factory::RouterChildArray;
use ovstorage_plugin::{ffi, thunks_v2};

thread_local! {
    /// Live bytes for THIS thread only. A process-global counter cannot work
    /// here: the test harness runs tests concurrently and allocates on its own
    /// threads, so a shared total drifts under any baseline. Every allocation
    /// and free in these tests happens on the test's own thread, so per-thread
    /// accounting is exact. `const` init keeps the TLS slot from allocating on
    /// first touch, which would re-enter the allocator.
    static LIVE_BYTES: Cell<isize> = const { Cell::new(0) };
}

/// `try_with` rather than `with`: during thread teardown the TLS slot may
/// already be destroyed, and panicking inside the global allocator would abort.
fn account(delta: isize) {
    let _ = LIVE_BYTES.try_with(|live| live.set(live.get() + delta));
}

fn live_bytes() -> isize {
    LIVE_BYTES.with(Cell::get)
}

struct Accounting;

// SAFETY: every method forwards to `System` unchanged; the counters are the
// only added behaviour and touch no allocator state.
unsafe impl GlobalAlloc for Accounting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        account(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        account(new_size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Accounting = Accounting;

static HANDLE_DROPS: AtomicUsize = AtomicUsize::new(0);

extern "C" fn counting_drop(_state: *mut core::ffi::c_void) {
    HANDLE_DROPS.fetch_add(1, Ordering::SeqCst);
}

/// A vtable whose `drop` slot only counts, so a child handle can be dropped
/// without owning any state. Leaked deliberately: `'static` keeps it out of
/// the accounting window.
fn counting_vtable() -> &'static ffi::LayerVTableV1 {
    let mut vtable = thunks_v2::layer_vtable_template_for_test();
    vtable.drop = counting_drop;
    Box::leak(Box::new(vtable))
}

/// `state` is a non-null sentinel: `LayerHandle::drop` skips a null state,
/// so a null one would make the drop-count assertions vacuous.
fn children(count: usize, vtable: &'static ffi::LayerVTableV1) -> Vec<ffi::RouterChild> {
    (0..count)
        .map(|_| ffi::RouterChild {
            handle: ffi::LayerHandle {
                state: std::ptr::dangling_mut::<u8>().cast(),
                vtable,
            },
            _reserved: [std::ptr::null_mut(); 8],
        })
        .collect()
}

#[test]
fn dropping_the_array_frees_its_backing_allocation() {
    let vtable = counting_vtable();
    let baseline = live_bytes();
    let array = RouterChildArray::new(children(4, vtable));
    assert_eq!(array.len(), 4);
    assert!(
        live_bytes() > baseline,
        "the fixture must actually allocate, or this test proves nothing",
    );

    drop(array);

    assert_eq!(
        live_bytes(),
        baseline,
        "the children array's backing allocation is freed by neither side: the \
         host hands the plugin a bare `*const RouterChild` it cannot free, so \
         dropping the host's owner must reclaim the buffer",
    );
}

#[test]
fn dropping_the_array_does_not_drop_the_transferred_handles() {
    let vtable = counting_vtable();
    let before = HANDLE_DROPS.load(Ordering::SeqCst);

    drop(RouterChildArray::new(children(3, vtable)));

    assert_eq!(
        HANDLE_DROPS.load(Ordering::SeqCst) - before,
        0,
        "every child handle transfers to the plugin, which drops it on every \
         path; dropping the host's array must not run `LayerHandle::drop` too",
    );
}

#[test]
fn an_empty_children_list_is_representable() {
    let array = RouterChildArray::new(Vec::new());
    assert!(array.is_empty());
    assert_eq!(array.len(), 0);
}
