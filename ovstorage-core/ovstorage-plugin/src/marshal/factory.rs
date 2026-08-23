// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side ownership helpers for the plugin factory requests.

use std::mem::ManuallyDrop;

use crate::ffi;

/// Host-side owner of the [`ffi::RouterChild`] array a `create_router`
/// request points at.
///
/// Ownership splits across the two sides. Each child HANDLE transfers to
/// the plugin: the callee reads every element out of the array and is
/// responsible for dropping the handles on every path, so the host must
/// not drop them. The array's backing ALLOCATION stays with the host —
/// [`ffi::CreateRouterRequest`] carries a bare `*const RouterChild` plus a
/// count rather than an owning [`ffi::List`], so the plugin has nothing to
/// free it with, and it may not even share the host's allocator.
///
/// Holding the elements as [`std::mem::ManuallyDrop`] expresses exactly
/// that split: the `Vec` frees its buffer when this value goes out of
/// scope, and no element's `LayerHandle::drop` runs.
pub struct RouterChildArray {
    children: Vec<ManuallyDrop<ffi::RouterChild>>,
}

impl RouterChildArray {
    /// Take ownership of the array backing `children`.
    #[must_use]
    pub fn new(children: Vec<ffi::RouterChild>) -> Self {
        Self {
            children: children.into_iter().map(ManuallyDrop::new).collect(),
        }
    }

    /// The `children` pointer for [`ffi::CreateRouterRequest`]. Valid
    /// while `self` is alive.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::RouterChild {
        // `ManuallyDrop<T>` is `repr(transparent)` over `T`, so the
        // element layout the plugin reads is unchanged.
        self.children.as_ptr().cast()
    }

    /// The `child_count` for [`ffi::CreateRouterRequest`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.children.len()
    }

    /// Whether the router was handed no children at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}
