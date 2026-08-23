// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use crate::Error as PluginError;
use crate::ErrorCode as PluginErrorCode;

/// Reject an options struct whose declared `struct_size` is smaller
/// than the receiver's compile-time `size_of::<T>()`. Plugins must
/// call this before reading any tail field; reading uninitialised
/// tail bytes from an under-sized struct would be UB. Larger sizes
/// are accepted (older receiver, newer caller).
#[inline]
pub fn validate_struct_size<T>(
    declared: usize,
    struct_label: &str,
) -> std::result::Result<(), PluginError> {
    let minimum = std::mem::size_of::<T>();
    if declared >= minimum {
        Ok(())
    } else {
        Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            format!(
                "{struct_label} struct_size = {declared} is smaller than the host's \
                 compile-time minimum {minimum}; the caller is using an older ABI than \
                 the receiving end, or passed `struct_size == 0` which would force the \
                 converter to read uninitialised tail fields (reject without reading \
                 later fields)"
            ),
        ))
    }
}

/// Read an options struct after validating the caller's
/// `struct_size`. Reads only the size prefix before committing to a
/// full read so that an under-sized allocation cannot cause UB.
///
/// # Safety
///
/// `ptr` must either be null (returns `InvalidArgument`) or point at
/// a caller-owned allocation whose first field is a `usize` named
/// `struct_size`. After validation, `ptr` must be valid for
/// `(*ptr).struct_size` bytes (which is `>= size_of::<T>()`).
#[inline]
pub unsafe fn read_options_at_ptr<T>(
    ptr: *const T,
    struct_label: &str,
) -> std::result::Result<T, PluginError> {
    if ptr.is_null() {
        return Err(PluginError::new(
            PluginErrorCode::InvalidArgument,
            format!("{struct_label} pointer must not be null"),
        ));
    }
    let declared = unsafe { *(ptr as *const usize) };
    validate_struct_size::<T>(declared, struct_label)?;
    Ok(unsafe { std::ptr::read(ptr) })
}

// ---------------------------------------------------------------------
// Options structs
//
// Flow host → plugin. The host allocates and frees; the plugin reads
// during the call and must not retain pointers past it. No `*_free`
// exports because options never cross the boundary standalone.
// ---------------------------------------------------------------------

/// Half-open or closed byte range used by `ReadOptions::range`.
///
/// `end_inclusive == None` reads through end-of-object.
#[repr(C)]
#[derive(Debug)]
pub struct ByteRange {
    pub start: u64,
    pub end_inclusive: Optional<u64>,
}

unsafe impl Send for ByteRange {}

/// `StatOptions` shadow shape. Every options struct starts with a
/// `struct_size` prefix; receivers validate `>= size_of::<T>()`
/// before reading tail fields.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct StatOptions {
    pub struct_size: usize,
    pub full_metadata: bool,
}

/// Tag for [`IfDestExistsV1`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IfDestExistsTag {
    Overwrite = 0,
    Fail = 1,
    MatchEtag = 2,
}

/// `IfDestExists::MatchEtag` payload.
#[repr(C)]
#[derive(Debug)]
pub struct IfDestExistsMatchEtag {
    pub etag: Str,
}

unsafe impl Send for IfDestExistsMatchEtag {}

/// Destination-side precondition for write / copy / rename. Tagged
/// union mirroring [`crate::IfDestExists`]; only the `match_etag`
/// payload is read when `tag == MatchEtag`.
#[repr(C)]
#[derive(Debug)]
pub struct IfDestExistsV1 {
    pub tag: IfDestExistsTag,
    pub match_etag: core::mem::MaybeUninit<IfDestExistsMatchEtag>,
}

unsafe impl Send for IfDestExistsV1 {}

impl IfDestExistsV1 {
    pub fn overwrite() -> Self {
        Self {
            tag: IfDestExistsTag::Overwrite,
            match_etag: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn fail() -> Self {
        Self {
            tag: IfDestExistsTag::Fail,
            match_etag: core::mem::MaybeUninit::uninit(),
        }
    }
    pub fn match_etag(etag: Str) -> Self {
        Self {
            tag: IfDestExistsTag::MatchEtag,
            match_etag: core::mem::MaybeUninit::new(IfDestExistsMatchEtag { etag }),
        }
    }
}

impl Drop for IfDestExistsV1 {
    fn drop(&mut self) {
        if self.tag == IfDestExistsTag::MatchEtag {
            unsafe {
                self.match_etag.assume_init_drop();
            }
        }
    }
}

/// `ReadOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct ReadOptions {
    pub struct_size: usize,
    pub if_match: Optional<Str>,
    pub range: Optional<ByteRange>,
    pub max_bytes: Optional<u64>,
}

unsafe impl Send for ReadOptions {}

/// `WriteOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct WriteOptions {
    pub struct_size: usize,
    pub if_dest: IfDestExistsV1,
    pub size_hint: Optional<u64>,
    pub user_metadata: Optional<UserMetadata>,
    pub message: Optional<Str>,
}

unsafe impl Send for WriteOptions {}

/// `DeleteOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct DeleteOptions {
    pub struct_size: usize,
    pub if_match: Optional<Str>,
}

unsafe impl Send for DeleteOptions {}

/// `ListOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct ListOptions {
    pub struct_size: usize,
    pub recursive: bool,
    pub max_results: Optional<u32>,
    pub page_token: Optional<Str>,
    pub full_metadata: bool,
}

unsafe impl Send for ListOptions {}

/// `ListVersionsOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct ListVersionsOptions {
    pub struct_size: usize,
    pub max_results: Optional<u32>,
    pub page_token: Optional<Str>,
}

unsafe impl Send for ListVersionsOptions {}

/// `CreateDirectoryOptions` shadow shape. `_reserved` keeps the
/// struct non-zero-size today; set to `0`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CreateDirectoryOptions {
    pub struct_size: usize,
    pub _reserved: u32,
}

/// `DeleteDirectoryOptions` shadow shape. `_reserved` keeps the
/// struct non-zero-size today; set to `0`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DeleteDirectoryOptions {
    pub struct_size: usize,
    pub _reserved: u32,
}

/// `CopyOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct CopyOptions {
    pub struct_size: usize,
    pub if_source: Optional<Str>,
    pub if_dest: IfDestExistsV1,
    pub message: Optional<Str>,
}

unsafe impl Send for CopyOptions {}

/// `RenameOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct RenameOptions {
    pub struct_size: usize,
    pub if_source: Optional<Str>,
    pub if_dest: IfDestExistsV1,
    pub message: Optional<Str>,
}

unsafe impl Send for RenameOptions {}

/// `UpdateMetadataOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct UpdateMetadataOptions {
    pub struct_size: usize,
    pub if_match: Optional<Str>,
    pub allow_rewrite_emulation: bool,
    pub user_metadata_set: KeyValueList,
    pub user_metadata_remove: List<Str>,
    pub message: Optional<Str>,
}

unsafe impl Send for UpdateMetadataOptions {}

/// Opaque watch-directory cursor. Bytes are plugin-defined; hosts
/// pass them back via `WatchDirectoryOptions::since` and MUST NOT
/// inspect, hash, or split them.
#[repr(C)]
#[derive(Debug)]
pub struct WatchDirectoryCursor {
    pub bytes: Bytes,
}

unsafe impl Send for WatchDirectoryCursor {}

/// `WatchDirectoryOptions` shadow shape.
#[repr(C)]
#[derive(Debug)]
pub struct WatchDirectoryOptions {
    pub struct_size: usize,
    pub recursive: bool,
    pub include_metadata_changes: bool,
    pub since: Optional<WatchDirectoryCursor>,
    pub poll_interval_ms: u64,
}

unsafe impl Send for WatchDirectoryOptions {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_struct_size_rejects_zero() {
        let err = validate_struct_size::<ReadOptions>(0, "ReadOptions").unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        assert!(err.message().contains("ReadOptions"));
        assert!(err.message().contains('0'));
    }

    #[test]
    fn validate_struct_size_accepts_exact() {
        let exact = std::mem::size_of::<ReadOptions>();
        assert!(validate_struct_size::<ReadOptions>(exact, "ReadOptions").is_ok());
    }

    #[test]
    fn validate_struct_size_accepts_larger() {
        let larger = std::mem::size_of::<ReadOptions>() + 64;
        assert!(validate_struct_size::<ReadOptions>(larger, "ReadOptions").is_ok());
    }

    #[test]
    fn validate_struct_size_rejects_undersized() {
        let undersized = std::mem::size_of::<ReadOptions>().saturating_sub(8);
        assert!(undersized > 0, "ReadOptions has tail fields");
        let err = validate_struct_size::<ReadOptions>(undersized, "ReadOptions").unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        let message = err.message();
        assert!(message.contains("ReadOptions"));
        assert!(message.contains(&undersized.to_string()));
        assert!(message.contains(&std::mem::size_of::<ReadOptions>().to_string()));
    }

    #[test]
    fn validate_struct_size_rejects_one_byte_undersized() {
        let undersized = std::mem::size_of::<StatOptions>().saturating_sub(1);
        assert!(undersized > 0);
        let err = validate_struct_size::<StatOptions>(undersized, "StatOptions").unwrap_err();
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
        assert!(err.message().contains("StatOptions"));
    }
}

// ---------------------------------------------------------------------
