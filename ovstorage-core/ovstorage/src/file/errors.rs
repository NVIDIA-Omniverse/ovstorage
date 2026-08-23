// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OS-specific `io::Error` → [`Error`] mapping for the built-in
//! [`FileBackend`](super::FileBackend).
//!
//! Ported from the legacy `ovstorage-plugin-file` cdylib so the built-in native
//! backend surfaces the same rich error codes (storage-full, read-only
//! filesystem, path-too-long) the cdylib did. The plain
//! [`ovstorage_layer::io_error`] mapper only covers the portable `io::ErrorKind`
//! arms; the object operations here want the raw-errno arms too.

use std::io;

use crate::{Error, ErrorCode};

/// Map an [`io::Error`] to an [`Error`], inspecting both the portable
/// [`io::ErrorKind`] and (on Unix) the raw OS errno so storage-exhaustion,
/// read-only-filesystem, and invalid-path conditions surface as their specific
/// [`ErrorCode`]s instead of the generic `Transient` fallback.
pub(crate) fn map_io(err: io::Error) -> Error {
    // EISDIR/ENOTDIR signal a file-vs-directory shape mismatch — the path
    // doesn't exist with that shape — so map to NotFound (matches Nucleus's
    // InvalidPath → NotFound precedent).
    let code = match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::IsADirectory => {
            ErrorCode::NotFound
        }
        io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
        // A removal refused because the directory still holds entries. Distinct
        // from the shape-mismatch group above: the path exists with exactly the
        // shape asked for, and the refusal is about its contents. Without this
        // arm the condition falls through to `Transient` and a retrying caller
        // replays a removal that cannot succeed until someone else empties the
        // directory.
        io::ErrorKind::DirectoryNotEmpty => ErrorCode::DirectoryNotEmpty,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::BrokenPipe => ErrorCode::Cancelled,
        io::ErrorKind::InvalidInput => ErrorCode::InvalidArgument,
        // Windows ERROR_FILENAME_EXCED_RANGE (267): the path is too long to be
        // a valid name, so the target cannot exist under that spelling.
        _ if err.raw_os_error() == Some(267) => ErrorCode::NotFound,
        _ if is_invalid_path_error(&err) => ErrorCode::InvalidArgument,
        _ if is_storage_full_error(&err) => ErrorCode::ResourceExhausted,
        _ if is_read_only_filesystem_error(&err) => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, err.to_string())
}

#[cfg(unix)]
fn is_invalid_path_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code) if code == libc::ENAMETOOLONG || code == libc::ELOOP || code == libc::EINVAL
    )
}

#[cfg(not(unix))]
fn is_invalid_path_error(_err: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn is_storage_full_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == libc::ENOSPC)
}

#[cfg(not(unix))]
fn is_storage_full_error(_err: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn is_read_only_filesystem_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if code == libc::EROFS)
}

#[cfg(not(unix))]
fn is_read_only_filesystem_error(_err: &io::Error) -> bool {
    false
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    /// The `DirectoryNotEmpty` arm is reachable on every platform std maps the
    /// native refusal onto — Unix `ENOTEMPTY`, Windows `ERROR_DIR_NOT_EMPTY` —
    /// so this asserts the arm itself without naming an errno. The companion
    /// raw-errno case in the Unix module below covers the errno→kind
    /// translation that a real `remove_dir` failure goes through.
    #[test]
    fn maps_directory_not_empty_to_its_own_code() {
        assert_eq!(
            map_io(io::Error::from(io::ErrorKind::DirectoryNotEmpty)).code(),
            ErrorCode::DirectoryNotEmpty
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Ported from the legacy `ovstorage-plugin-file` cdylib unit test
    // `file_backend_maps_permanent_linux_io_errors_without_transient`: each
    // permanent raw-errno arm maps to its specific `ErrorCode` rather than the
    // generic `Transient` fallback.
    #[test]
    fn maps_permanent_linux_io_errors_without_transient() {
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ENAMETOOLONG)).code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ELOOP)).code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ENOSPC)).code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::EROFS)).code(),
            ErrorCode::PermissionDenied
        );
        // The error value `remove_dir` actually produces is a raw errno, so
        // this exercises the `raw_os_error` → `ErrorKind` translation the
        // portable arm depends on, not just the arm.
        assert_eq!(
            map_io(io::Error::from_raw_os_error(libc::ENOTEMPTY)).code(),
            ErrorCode::DirectoryNotEmpty
        );
    }
}
