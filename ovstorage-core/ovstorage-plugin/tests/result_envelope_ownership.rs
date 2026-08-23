// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Allocation accounting for the introspection result envelopes.
//!
//! `ListAddressRootsResult` / `ListConnectionsResult` document that dropping
//! the envelope "frees the snapshot's buffers and, when `updates` is non-null,
//! drives the change stream's `drop_fn`", and the exported
//! `ovstorage_plugin_list_*_result_free` entry points repeat it in the shipped
//! header. Their hand-written `Drop` impls only touch `updates`, which reads
//! like the snapshot leaks — it does not, because Rust runs field drop glue
//! *after* a manual `Drop::drop` body, and `List<T>` / `Optional<T>` / `Str`
//! each carry their own `Drop` (`ffi/primitive.rs`).
//!
//! That is a subtle, entirely implicit guarantee sitting under a documented
//! ABI promise, and reading the `Drop` impls alone suggests the opposite. The
//! test below pins it by counting live ABI-heap bytes across a real drop, so
//! removing any link in that chain — adding `ManuallyDrop`, dropping `List`'s
//! `Drop`, or making the envelope's `Drop` take the fields by value — fails
//! here instead of silently leaking one snapshot per introspection poll on
//! the C/C++ path.
//!
//! The counter comes from `ffi::abi_alloc`, not from a `#[global_allocator]`
//! wrapper: ABI buffers live on the shared process heap precisely so that no
//! per-binary allocator sees them, which leaves a global-allocator wrapper
//! blind to exactly the bytes under test.
//!
//! `abi_live_bytes` is one counter per binary, shared by every thread in
//! this test binary, so the three phases run as one test function in
//! sequence rather than as sibling `#[test]`s the harness would interleave
//! on separate threads. Each phase keeps its own baseline and its own
//! allocate-guard; the cost is diagnostic only, in that the first failing
//! phase masks the ones after it.

use ovstorage_plugin::ffi;
use ovstorage_plugin::ffi::abi_alloc::abi_live_bytes;
use ovstorage_plugin::marshal::primitive::{list_to_ffi, str_ref_to_ffi};

fn live_bytes() -> isize {
    abi_live_bytes()
}

/// A root carrying every owned shape the snapshot can hold: heap `Str`s, an
/// `Optional<Str>`, and a `List`. Field-for-field the producer's encoding.
fn owned_root() -> ffi::RootInfo {
    let mut root = unsafe { std::mem::zeroed::<ffi::RootInfo>() };
    root.struct_size = std::mem::size_of::<ffi::RootInfo>();
    root.root = str_ref_to_ffi("envelope://accounting/root/");
    root.layer_kind = str_ref_to_ffi("envelope-accounting-kind");
    root.display_name = ffi::Optional::some(str_ref_to_ffi("Envelope accounting root"));
    root.owning_target = ffi::Optional::some(str_ref_to_ffi("envelope-accounting-owner"));
    root
}

fn owned_snapshot() -> ffi::RootInfoSnapshot {
    ffi::RootInfoSnapshot {
        roots: list_to_ffi(vec![(), (), ()], |()| owned_root()),
        updates: false,
    }
}

#[test]
fn envelope_and_exported_frees_reclaim_the_whole_snapshot() {
    // Dropping the envelope frees the snapshot's buffers, as its doc and
    // `ovstorage_plugin_list_address_roots_result_free` promise.
    let baseline = live_bytes();
    let envelope = ffi::ListAddressRootsResult {
        snapshot: owned_snapshot(),
        updates: std::ptr::null_mut(),
    };
    assert!(
        live_bytes() > baseline,
        "the fixture must actually allocate, or this test proves nothing",
    );
    drop(envelope);
    assert_eq!(
        live_bytes(),
        baseline,
        "dropping the envelope must free the snapshot's buffers",
    );

    // The exported C entry point frees exactly what `Drop` does — this is the
    // one the pure-C host's `plugin_values.c` counterpart mirrors.
    let baseline = live_bytes();
    let envelope = ffi::abi_alloc::abi_box(ffi::ListAddressRootsResult {
        snapshot: owned_snapshot(),
        updates: std::ptr::null_mut(),
    });
    assert!(live_bytes() > baseline);
    // SAFETY: `envelope` is a live ABI heap pointer.
    unsafe { ffi::ovstorage_plugin_list_address_roots_result_free(envelope) };
    assert_eq!(
        live_bytes(),
        baseline,
        "the exported free must reclaim the snapshot, not just `updates`",
    );

    // In-place snapshot free (`out_snapshot` storage owned by the caller) —
    // the shape the pure-C host uses on the envelope's `snapshot` field.
    let baseline = live_bytes();
    let mut snapshot = owned_snapshot();
    assert!(live_bytes() > baseline);
    // SAFETY: `snapshot` is a live, properly aligned `RootInfoSnapshot`.
    unsafe { ffi::ovstorage_plugin_root_info_snapshot_free(&mut snapshot) };
    assert_eq!(
        live_bytes(),
        baseline,
        "the in-place snapshot free must reclaim every root's owned fields",
    );
    std::mem::forget(snapshot);
}
