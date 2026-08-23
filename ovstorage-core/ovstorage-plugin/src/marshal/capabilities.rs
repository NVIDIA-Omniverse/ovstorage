// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn change_kind_to_ffi(value: ChangeKind) -> ffi::ChangeKind {
    match value {
        ChangeKind::Created => ffi::ChangeKind::Created,
        ChangeKind::Modified => ffi::ChangeKind::Modified,
        ChangeKind::Deleted => ffi::ChangeKind::Deleted,
        ChangeKind::MetadataChanged => ffi::ChangeKind::MetadataChanged,
    }
}

pub fn change_kind_from_ffi(value: ffi::ChangeKind) -> ChangeKind {
    match value {
        ffi::ChangeKind::Created => ChangeKind::Created,
        ffi::ChangeKind::Modified => ChangeKind::Modified,
        ffi::ChangeKind::Deleted => ChangeKind::Deleted,
        ffi::ChangeKind::MetadataChanged => ChangeKind::MetadataChanged,
    }
}

pub fn change_kind_set_to_ffi(value: ChangeKindSet) -> ffi::ChangeKindSet {
    ffi::ChangeKindSet {
        created: value.created,
        modified: value.modified,
        deleted: value.deleted,
        metadata_changed: value.metadata_changed,
    }
}

pub fn change_kind_set_from_ffi(value: ffi::ChangeKindSet) -> ChangeKindSet {
    ChangeKindSet {
        created: value.created,
        modified: value.modified,
        deleted: value.deleted,
        metadata_changed: value.metadata_changed,
    }
}

pub fn version_list_order_to_ffi(value: VersionListOrder) -> ffi::VersionListOrder {
    match value {
        VersionListOrder::Newest => ffi::VersionListOrder::Newest,
        VersionListOrder::Oldest => ffi::VersionListOrder::Oldest,
        VersionListOrder::Unordered => ffi::VersionListOrder::Unordered,
    }
}

pub fn version_list_order_from_ffi(value: ffi::VersionListOrder) -> VersionListOrder {
    match value {
        ffi::VersionListOrder::Newest => VersionListOrder::Newest,
        ffi::VersionListOrder::Oldest => VersionListOrder::Oldest,
        ffi::VersionListOrder::Unordered => VersionListOrder::Unordered,
    }
}

pub fn capabilities_to_ffi(value: Capabilities) -> ffi::Capabilities {
    ffi::Capabilities {
        supports_if_match_write: value.supports_if_match_write,
        supports_no_overwrite_write: value.supports_no_overwrite_write,
        supports_native_metadata_patch: value.supports_native_metadata_patch,
        supports_metadata_rewrite_emulation: value.supports_metadata_rewrite_emulation,
        writes_are_atomic: value.writes_are_atomic,
        supports_copy: value.supports_copy,
        supports_rename: value.supports_rename,
        supports_server_side_copy: value.supports_server_side_copy,
        supports_server_side_rename: value.supports_server_side_rename,
        supports_atomic_rename: value.supports_atomic_rename,
        has_real_directories: value.has_real_directories,
        supports_write: value.supports_write,
        supports_write_stream: value.supports_write_stream,
        supports_write_redirect: value.supports_write_redirect,
        supports_delete: value.supports_delete,
        supports_list: value.supports_list,
        wants_list_backed_stat: value.wants_list_backed_stat,
        supports_recursive_list: value.supports_recursive_list,
        populates_subdirectory_metadata: value.populates_subdirectory_metadata,
        supports_create_directory: value.supports_create_directory,
        supports_delete_directory: value.supports_delete_directory,
        supports_version_listing: value.supports_version_listing,
        version_list_order: primitive::optional_to_ffi(
            value.version_list_order,
            version_list_order_to_ffi,
        ),
        populates_effective_permissions_on_stat: value.populates_effective_permissions_on_stat,
        supports_access_check: value.supports_access_check,
        supports_watch_directory: value.supports_watch_directory,
        watch_directory_kinds: change_kind_set_to_ffi(value.watch_directory_kinds),
        watch_directory_resumable: value.watch_directory_resumable,
        watch_directory_max_lag_ms: primitive::optional_to_ffi(
            value.watch_directory_max_lag,
            |d| {
                let ms = d.as_millis();
                if ms > u64::MAX as u128 {
                    u64::MAX
                } else {
                    ms as u64
                }
            },
        ),
        redirect_size_threshold: primitive::optional_to_ffi(value.redirect_size_threshold, |n| n),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::Capabilities`] produced by
/// [`capabilities_to_ffi`] or by an FFI counterpart.
pub unsafe fn capabilities_from_ffi(value: ffi::Capabilities) -> Result<Capabilities, Error> {
    unsafe {
        let version_list_order =
            primitive::optional_from_ffi::<ffi::VersionListOrder, VersionListOrder, Error>(
                value.version_list_order,
                |o| Ok(version_list_order_from_ffi(o)),
            )?;
        let watch_directory_max_lag = primitive::optional_from_ffi::<u64, Duration, Error>(
            value.watch_directory_max_lag_ms,
            |ms| Ok(Duration::from_millis(ms)),
        )?;
        Ok(Capabilities {
            supports_if_match_write: value.supports_if_match_write,
            supports_no_overwrite_write: value.supports_no_overwrite_write,
            supports_native_metadata_patch: value.supports_native_metadata_patch,
            supports_metadata_rewrite_emulation: value.supports_metadata_rewrite_emulation,
            writes_are_atomic: value.writes_are_atomic,
            supports_copy: value.supports_copy,
            supports_rename: value.supports_rename,
            supports_server_side_copy: value.supports_server_side_copy,
            supports_server_side_rename: value.supports_server_side_rename,
            supports_atomic_rename: value.supports_atomic_rename,
            has_real_directories: value.has_real_directories,
            supports_write: value.supports_write,
            supports_write_stream: value.supports_write_stream,
            supports_write_redirect: value.supports_write_redirect,
            supports_delete: value.supports_delete,
            supports_list: value.supports_list,
            wants_list_backed_stat: value.wants_list_backed_stat,
            supports_recursive_list: value.supports_recursive_list,
            populates_subdirectory_metadata: value.populates_subdirectory_metadata,
            supports_create_directory: value.supports_create_directory,
            supports_delete_directory: value.supports_delete_directory,
            supports_version_listing: value.supports_version_listing,
            version_list_order,
            populates_effective_permissions_on_stat: value.populates_effective_permissions_on_stat,
            supports_access_check: value.supports_access_check,
            supports_watch_directory: value.supports_watch_directory,
            watch_directory_kinds: change_kind_set_from_ffi(value.watch_directory_kinds),
            watch_directory_resumable: value.watch_directory_resumable,
            watch_directory_max_lag,
            redirect_size_threshold: primitive::optional_from_ffi::<u64, u64, Error>(
                value.redirect_size_threshold,
                Ok,
            )?,
        })
    }
}
