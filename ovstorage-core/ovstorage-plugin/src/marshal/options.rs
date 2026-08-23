// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn byte_range_to_ffi(value: ByteRange) -> ffi::ByteRange {
    ffi::ByteRange {
        start: value.start,
        end_inclusive: primitive::optional_to_ffi(value.end_inclusive, |v| v),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ByteRange`] produced by
/// [`byte_range_to_ffi`] or by an FFI counterpart.
pub unsafe fn byte_range_from_ffi(value: ffi::ByteRange) -> Result<ByteRange, Error> {
    unsafe {
        let end_inclusive =
            primitive::optional_from_ffi::<u64, u64, Error>(value.end_inclusive, Ok)?;
        Ok(ByteRange {
            start: value.start,
            end_inclusive,
        })
    }
}

pub fn stat_options_to_ffi(value: StatOptions) -> ffi::StatOptions {
    ffi::StatOptions {
        struct_size: std::mem::size_of::<ffi::StatOptions>(),
        full_metadata: value.full_metadata,
    }
}

pub fn stat_options_from_ffi(value: ffi::StatOptions) -> Result<StatOptions, Error> {
    ffi::validate_struct_size::<ffi::StatOptions>(value.struct_size, "StatOptions")?;
    Ok(StatOptions {
        full_metadata: value.full_metadata,
    })
}

pub fn read_options_to_ffi(value: ReadOptions) -> ffi::ReadOptions {
    ffi::ReadOptions {
        struct_size: std::mem::size_of::<ffi::ReadOptions>(),
        if_match: primitive::optional_to_ffi(value.if_match, primitive::str_to_ffi),
        range: primitive::optional_to_ffi(value.range, byte_range_to_ffi),
        max_bytes: primitive::optional_to_ffi(value.max_bytes, |v| v),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ReadOptions`] produced by
/// [`read_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn read_options_from_ffi(value: ffi::ReadOptions) -> Result<ReadOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::ReadOptions>(value.struct_size, "ReadOptions")?;
        let if_match_ffi = value.if_match;
        let range_ffi = value.range;
        let max_bytes_ffi = value.max_bytes;
        let if_match = primitive::optional_from_ffi(if_match_ffi, |s| primitive::str_from_ffi(s));
        let range = primitive::optional_from_ffi(range_ffi, |r| byte_range_from_ffi(r));
        let max_bytes = primitive::optional_from_ffi(max_bytes_ffi, Ok);
        Ok(ReadOptions {
            if_match: if_match?,
            range: range?,
            max_bytes: max_bytes?,
        })
    }
}

pub fn write_options_to_ffi(value: WriteOptions) -> ffi::WriteOptions {
    ffi::WriteOptions {
        struct_size: std::mem::size_of::<ffi::WriteOptions>(),
        if_dest: identity::if_dest_exists_to_ffi(value.if_dest),
        size_hint: primitive::optional_to_ffi(value.size_hint, |v| v),
        user_metadata: primitive::optional_to_ffi(
            value.user_metadata,
            metadata::user_metadata_to_ffi,
        ),
        message: primitive::optional_to_ffi(value.message, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WriteOptions`] produced by
/// [`write_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn write_options_from_ffi(value: ffi::WriteOptions) -> Result<WriteOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::WriteOptions>(value.struct_size, "WriteOptions")?;
        // Read every owned field via ptr::read so the parent's Drop
        // doesn't run on already-consumed slots.
        let if_dest_ffi = std::ptr::read(&value.if_dest);
        let size_hint_ffi = std::ptr::read(&value.size_hint);
        let user_metadata_ffi = std::ptr::read(&value.user_metadata);
        let message_ffi = std::ptr::read(&value.message);
        std::mem::forget(value);
        let if_dest = identity::if_dest_exists_from_ffi(if_dest_ffi);
        let size_hint = primitive::optional_from_ffi::<u64, u64, Error>(size_hint_ffi, Ok);
        let user_metadata = primitive::optional_from_ffi(user_metadata_ffi, |kv| {
            metadata::user_metadata_from_ffi(kv)
        });
        let message = primitive::optional_from_ffi(message_ffi, |s| primitive::str_from_ffi(s));
        Ok(WriteOptions {
            if_dest: if_dest?,
            size_hint: size_hint?,
            user_metadata: user_metadata?,
            message: message?,
        })
    }
}

pub fn delete_options_to_ffi(value: DeleteOptions) -> ffi::DeleteOptions {
    ffi::DeleteOptions {
        struct_size: std::mem::size_of::<ffi::DeleteOptions>(),
        if_match: primitive::optional_to_ffi(value.if_match, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::DeleteOptions`] produced by
/// [`delete_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn delete_options_from_ffi(value: ffi::DeleteOptions) -> Result<DeleteOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::DeleteOptions>(value.struct_size, "DeleteOptions")?;
        let if_match =
            primitive::optional_from_ffi(value.if_match, |s| primitive::str_from_ffi(s))?;
        Ok(DeleteOptions { if_match })
    }
}

pub fn list_options_to_ffi(value: ListOptions) -> ffi::ListOptions {
    ffi::ListOptions {
        struct_size: std::mem::size_of::<ffi::ListOptions>(),
        recursive: value.recursive,
        max_results: primitive::optional_to_ffi(value.max_results, |v| v),
        page_token: primitive::optional_to_ffi(value.page_token, primitive::str_to_ffi),
        full_metadata: value.full_metadata,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ListOptions`] produced by
/// [`list_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn list_options_from_ffi(value: ffi::ListOptions) -> Result<ListOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::ListOptions>(value.struct_size, "ListOptions")?;
        let max_results_ffi = value.max_results;
        let page_token_ffi = value.page_token;
        let max_results = primitive::optional_from_ffi::<u32, u32, Error>(max_results_ffi, Ok);
        let page_token =
            primitive::optional_from_ffi(page_token_ffi, |s| primitive::str_from_ffi(s));
        Ok(ListOptions {
            recursive: value.recursive,
            max_results: max_results?,
            page_token: page_token?,
            full_metadata: value.full_metadata,
        })
    }
}

pub fn list_versions_options_to_ffi(value: ListVersionsOptions) -> ffi::ListVersionsOptions {
    ffi::ListVersionsOptions {
        struct_size: std::mem::size_of::<ffi::ListVersionsOptions>(),
        max_results: primitive::optional_to_ffi(value.max_results, |v| v),
        page_token: primitive::optional_to_ffi(value.page_token, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ListVersionsOptions`] produced
/// by [`list_versions_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn list_versions_options_from_ffi(
    value: ffi::ListVersionsOptions,
) -> Result<ListVersionsOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::ListVersionsOptions>(
            value.struct_size,
            "ListVersionsOptions",
        )?;
        let max_results_ffi = value.max_results;
        let page_token_ffi = value.page_token;
        let max_results = primitive::optional_from_ffi::<u32, u32, Error>(max_results_ffi, Ok);
        let page_token =
            primitive::optional_from_ffi(page_token_ffi, |s| primitive::str_from_ffi(s));
        Ok(ListVersionsOptions {
            max_results: max_results?,
            page_token: page_token?,
        })
    }
}

pub fn create_directory_options_to_ffi(
    _value: CreateDirectoryOptions,
) -> ffi::CreateDirectoryOptions {
    ffi::CreateDirectoryOptions {
        struct_size: std::mem::size_of::<ffi::CreateDirectoryOptions>(),
        _reserved: 0,
    }
}

pub fn create_directory_options_from_ffi(
    value: ffi::CreateDirectoryOptions,
) -> Result<CreateDirectoryOptions, Error> {
    ffi::validate_struct_size::<ffi::CreateDirectoryOptions>(
        value.struct_size,
        "CreateDirectoryOptions",
    )?;
    Ok(CreateDirectoryOptions {})
}

pub fn delete_directory_options_to_ffi(
    _value: DeleteDirectoryOptions,
) -> ffi::DeleteDirectoryOptions {
    ffi::DeleteDirectoryOptions {
        struct_size: std::mem::size_of::<ffi::DeleteDirectoryOptions>(),
        _reserved: 0,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::DeleteDirectoryOptions`]
/// produced by [`delete_directory_options_to_ffi`] or by an FFI
/// counterpart.
pub unsafe fn delete_directory_options_from_ffi(
    value: ffi::DeleteDirectoryOptions,
) -> Result<DeleteDirectoryOptions, Error> {
    ffi::validate_struct_size::<ffi::DeleteDirectoryOptions>(
        value.struct_size,
        "DeleteDirectoryOptions",
    )?;
    Ok(DeleteDirectoryOptions)
}

pub fn copy_options_to_ffi(value: CopyOptions) -> ffi::CopyOptions {
    ffi::CopyOptions {
        struct_size: std::mem::size_of::<ffi::CopyOptions>(),
        if_source: primitive::optional_to_ffi(value.if_source, primitive::str_to_ffi),
        if_dest: identity::if_dest_exists_to_ffi(value.if_dest),
        message: primitive::optional_to_ffi(value.message, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::CopyOptions`] produced by
/// [`copy_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn copy_options_from_ffi(value: ffi::CopyOptions) -> Result<CopyOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::CopyOptions>(value.struct_size, "CopyOptions")?;
        let if_source_ffi = std::ptr::read(&value.if_source);
        let if_dest_ffi = std::ptr::read(&value.if_dest);
        let message_ffi = std::ptr::read(&value.message);
        std::mem::forget(value);
        let if_source =
            primitive::optional_from_ffi(if_source_ffi, |s| primitive::str_from_ffi(s))?;
        let if_dest = identity::if_dest_exists_from_ffi(if_dest_ffi)?;
        let message = primitive::optional_from_ffi(message_ffi, |s| primitive::str_from_ffi(s))?;
        Ok(CopyOptions {
            if_source,
            if_dest,
            message,
        })
    }
}

pub fn rename_options_to_ffi(value: RenameOptions) -> ffi::RenameOptions {
    ffi::RenameOptions {
        struct_size: std::mem::size_of::<ffi::RenameOptions>(),
        if_source: primitive::optional_to_ffi(value.if_source, primitive::str_to_ffi),
        if_dest: identity::if_dest_exists_to_ffi(value.if_dest),
        message: primitive::optional_to_ffi(value.message, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::RenameOptions`] produced by
/// [`rename_options_to_ffi`] or by an FFI counterpart.
pub unsafe fn rename_options_from_ffi(value: ffi::RenameOptions) -> Result<RenameOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::RenameOptions>(value.struct_size, "RenameOptions")?;
        let if_source_ffi = std::ptr::read(&value.if_source);
        let if_dest_ffi = std::ptr::read(&value.if_dest);
        let message_ffi = std::ptr::read(&value.message);
        std::mem::forget(value);
        let if_source =
            primitive::optional_from_ffi(if_source_ffi, |s| primitive::str_from_ffi(s))?;
        let if_dest = identity::if_dest_exists_from_ffi(if_dest_ffi)?;
        let message = primitive::optional_from_ffi(message_ffi, |s| primitive::str_from_ffi(s))?;
        Ok(RenameOptions {
            if_source,
            if_dest,
            message,
        })
    }
}

pub fn update_metadata_options_to_ffi(value: UpdateMetadataOptions) -> ffi::UpdateMetadataOptions {
    ffi::UpdateMetadataOptions {
        struct_size: std::mem::size_of::<ffi::UpdateMetadataOptions>(),
        if_match: primitive::optional_to_ffi(value.if_match, primitive::str_to_ffi),
        allow_rewrite_emulation: value.allow_rewrite_emulation,
        user_metadata_set: primitive::key_value_list_to_ffi(value.user_metadata_set),
        user_metadata_remove: primitive::list_to_ffi(
            value.user_metadata_remove,
            primitive::str_to_ffi,
        ),
        message: primitive::optional_to_ffi(value.message, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::UpdateMetadataOptions`]
/// produced by [`update_metadata_options_to_ffi`] or by an FFI
/// counterpart.
pub unsafe fn update_metadata_options_from_ffi(
    value: ffi::UpdateMetadataOptions,
) -> Result<UpdateMetadataOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::UpdateMetadataOptions>(
            value.struct_size,
            "UpdateMetadataOptions",
        )?;
        let if_match_ffi = value.if_match;
        let user_metadata_set_ffi = value.user_metadata_set;
        let user_metadata_remove_ffi = value.user_metadata_remove;
        let message_ffi = value.message;

        let if_match = primitive::optional_from_ffi(if_match_ffi, |s| primitive::str_from_ffi(s));
        let user_metadata_set = primitive::key_value_list_from_ffi(user_metadata_set_ffi);
        let user_metadata_remove =
            primitive::list_from_ffi(user_metadata_remove_ffi, |s| primitive::str_from_ffi(s));
        let message = primitive::optional_from_ffi(message_ffi, |s| primitive::str_from_ffi(s));

        Ok(UpdateMetadataOptions {
            if_match: if_match?,
            allow_rewrite_emulation: value.allow_rewrite_emulation,
            user_metadata_set: user_metadata_set?,
            user_metadata_remove: user_metadata_remove?,
            message: message?,
        })
    }
}

pub fn watch_directory_cursor_to_ffi(value: WatchDirectoryCursor) -> ffi::WatchDirectoryCursor {
    ffi::WatchDirectoryCursor {
        bytes: primitive::bytes_to_ffi(value.0),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WatchDirectoryCursor`] produced
/// by [`watch_directory_cursor_to_ffi`] or by an FFI counterpart.
pub unsafe fn watch_directory_cursor_from_ffi(
    value: ffi::WatchDirectoryCursor,
) -> WatchDirectoryCursor {
    unsafe { WatchDirectoryCursor(primitive::bytes_from_ffi(value.bytes)) }
}

pub fn watch_directory_options_to_ffi(value: WatchDirectoryOptions) -> ffi::WatchDirectoryOptions {
    ffi::WatchDirectoryOptions {
        struct_size: std::mem::size_of::<ffi::WatchDirectoryOptions>(),
        recursive: value.recursive,
        include_metadata_changes: value.include_metadata_changes,
        since: primitive::optional_to_ffi(value.since, watch_directory_cursor_to_ffi),
        poll_interval_ms: clamp_duration_to_ms(value.poll_interval),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WatchDirectoryOptions`]
/// produced by [`watch_directory_options_to_ffi`] or by an FFI
/// counterpart.
pub unsafe fn watch_directory_options_from_ffi(
    value: ffi::WatchDirectoryOptions,
) -> Result<WatchDirectoryOptions, Error> {
    unsafe {
        ffi::validate_struct_size::<ffi::WatchDirectoryOptions>(
            value.struct_size,
            "WatchDirectoryOptions",
        )?;
        let since = primitive::optional_from_ffi::<
            ffi::WatchDirectoryCursor,
            WatchDirectoryCursor,
            Error,
        >(value.since, |c| Ok(watch_directory_cursor_from_ffi(c)))?;
        Ok(WatchDirectoryOptions {
            recursive: value.recursive,
            include_metadata_changes: value.include_metadata_changes,
            since,
            poll_interval: std::time::Duration::from_millis(value.poll_interval_ms),
        })
    }
}

fn clamp_duration_to_ms(duration: std::time::Duration) -> u64 {
    let ms = duration.as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}
