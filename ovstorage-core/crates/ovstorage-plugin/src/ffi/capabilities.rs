// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Capabilities + change-kind set + version-list order
// ---------------------------------------------------------------------

/// `ChangeKind` discriminant.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Created = 0,
    Modified = 1,
    Deleted = 2,
    MetadataChanged = 3,
}

/// `ChangeKindSet` bitset-style flag struct.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChangeKindSet {
    pub created: bool,
    pub modified: bool,
    pub deleted: bool,
    pub metadata_changed: bool,
}

/// `VersionListOrder` discriminant.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VersionListOrder {
    Newest = 0,
    Oldest = 1,
    Unordered = 2,
}

/// Capability bitset reported by the plugin per backend instance.
#[repr(C)]
#[derive(Debug)]
pub struct Capabilities {
    pub supports_if_match_write: bool,
    pub supports_no_overwrite_write: bool,
    pub supports_native_metadata_patch: bool,
    pub supports_metadata_rewrite_emulation: bool,
    pub writes_are_atomic: bool,
    pub supports_server_side_copy: bool,
    pub supports_server_side_rename: bool,
    pub supports_atomic_rename: bool,
    pub has_real_directories: bool,
    pub supports_write: bool,
    pub supports_write_stream: bool,
    pub supports_write_redirect: bool,
    pub supports_delete: bool,
    pub supports_list: bool,
    pub wants_list_backed_stat: bool,
    pub supports_recursive_list: bool,
    pub populates_subdirectory_metadata: bool,
    pub supports_create_directory: bool,
    pub supports_delete_directory: bool,
    pub supports_version_listing: bool,
    pub version_list_order: Optional<VersionListOrder>,
    pub populates_effective_permissions_on_stat: bool,
    pub supports_access_check: bool,
    pub supports_watch_directory: bool,
    pub watch_directory_kinds: ChangeKindSet,
    pub watch_directory_resumable: bool,
    pub watch_directory_max_lag_ms: Optional<u64>,
    pub redirect_size_threshold: Optional<u64>,
}

unsafe impl Send for Capabilities {}

// ---------------------------------------------------------------------
