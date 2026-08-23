// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// ---------------------------------------------------------------------
// Address and identity types
// ---------------------------------------------------------------------

/// Backend identifier. Opaque to most consumers; UTF-8-encoded so it
/// can survive any tracing pipeline.
#[repr(C)]
#[derive(Debug)]
pub struct BackendId {
    pub id: Str,
}

unsafe impl Send for BackendId {}

/// Resolved target: the address the plugin should act on plus the
/// backend instance the dispatcher selected.
#[repr(C)]
#[derive(Debug)]
pub struct ResolvedTarget {
    pub backend_id: BackendId,
    pub resolved_address: Str,
}

unsafe impl Send for ResolvedTarget {}

/// Drop a [`BackendId`]'s inner allocation in place. Safe with NULL.
/// `BackendId` is always embedded; the outer pointee is caller-owned.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`BackendId`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_backend_id_free(value: *mut BackendId) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Drop a [`ResolvedTarget`]'s nested allocations in place. Safe
/// with NULL. The pointee is caller-owned.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`ResolvedTarget`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_resolved_target_free(value: *mut ResolvedTarget) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

// ---------------------------------------------------------------------
// Metadata types
// ---------------------------------------------------------------------

/// Permission bitset. `READ = 1<<0`, `WRITE = 1<<1`, `DELETE = 1<<2`,
/// `UPDATE_METADATA = 1<<3`. Consumers ignore unknown bits (forward-compat).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EffectivePermissions {
    pub bits: u32,
}

/// Backend-owned opaque metadata map.
pub type SystemMetadata = KeyValueList;

/// Caller-owned mutable metadata map.
pub type UserMetadata = KeyValueList;

/// File / directory discriminator. Numeric values are the ABI contract.
///
/// - `File`: a regular object.
/// - `Directory`: native directory inode (POSIX file plugins, Nucleus,
///   Azure ADLS Gen2 HNS).
/// - `DirectoryMarker`: zero-byte marker object on a flat-namespace
///   backend (S3/GCS `dir/`-keyed objects).
/// - `DirectoryInferred`: directory inferred from descendant common
///   prefixes by the dispatcher's marker-folding pass; no backing
///   storage object.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum ObjectKindV1 {
    #[default]
    File = 0,
    Directory = 1,
    DirectoryMarker = 2,
    DirectoryInferred = 3,
}

/// Object metadata: address, kind, identity, checksums, optional
/// permissions / metadata. `mtime_unix_ms` is Unix milliseconds; ms
/// precision is the FFI-boundary clock contract.
#[repr(C)]
#[derive(Debug)]
pub struct ObjectInfo {
    pub address: Str,
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

unsafe impl Send for ObjectInfo {}

/// Reclaim a heap-allocated [`ObjectInfo`] returned through a
/// `BackendStatCallback`. Safe with NULL. Do NOT call this on an
/// embedded `ObjectInfo` field — rely on the parent's destructor.
///
/// # Safety
///
/// `value`, when non-null, must be a heap pointer produced by an
/// ovstorage call. Passing a non-heap pointer is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_object_info_free(value: *mut ObjectInfo) {
    unsafe {
        if value.is_null() {
            return;
        }
        crate::ffi::abi_alloc::abi_box_free(value);
    }
}
