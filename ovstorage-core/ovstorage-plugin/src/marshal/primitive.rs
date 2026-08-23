// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ffi::abi_alloc::abi_vec_into_raw;

/// Convert a `String` into an owned [`ffi::Str`].
pub fn str_to_ffi(value: String) -> ffi::Str {
    let bytes = value.into_bytes();
    let len = bytes.len();
    // The empty case still allocates: `abi_vec_into_raw` mints the
    // one-byte sentinel so consumers never see NULL.
    ffi::Str {
        ptr: abi_vec_into_raw(bytes) as *mut std::os::raw::c_char,
        len,
    }
}

/// Copy a `&str` into an owned [`ffi::Str`].
pub fn str_ref_to_ffi(value: &str) -> ffi::Str {
    str_to_ffi(value.to_owned())
}

/// Consume an [`ffi::Str`] and copy its bytes into a `String`. The
/// FFI buffer is freed in either case. Returns `InvalidArgument` on
/// invalid UTF-8.
///
/// # Safety
///
/// `value` must be a valid [`ffi::Str`] produced by [`str_to_ffi`]
/// or an FFI counterpart that uses the ABI allocator.
pub unsafe fn str_from_ffi(value: ffi::Str) -> Result<String, Error> {
    unsafe {
        let bytes = if value.ptr.is_null() || value.len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(value.ptr as *const u8, value.len).to_vec()
        };
        // Drop releases the FFI buffer before we return.
        drop(value);
        String::from_utf8(bytes)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "FFI string is not valid UTF-8"))
    }
}

/// Borrow an [`ffi::Str`] as `&str` **without** consuming it — for strings
/// that live inside a caller-owned struct (e.g. a borrowed manifest or a
/// request the caller still owns). The pointee must outlive the returned
/// reference. Empty/null is a valid empty string.
///
/// # Safety
///
/// `value`'s `ptr`/`len` must describe a valid UTF-8 buffer borrowed for
/// at least as long as the returned reference.
pub unsafe fn str_borrow(value: &ffi::Str) -> Result<&str, Error> {
    if value.ptr.is_null() || value.len == 0 {
        return Ok("");
    }
    let bytes = unsafe { std::slice::from_raw_parts(value.ptr as *const u8, value.len) };
    std::str::from_utf8(bytes)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "FFI string is not valid UTF-8"))
}

/// Convert a `Vec<u8>` into an owned [`ffi::Bytes`].
pub fn bytes_to_ffi(value: Vec<u8>) -> ffi::Bytes {
    let len = value.len();
    ffi::Bytes {
        ptr: abi_vec_into_raw(value),
        len,
    }
}

/// Copy a `&[u8]` into an owned [`ffi::Bytes`], leaving the source in place.
/// The [`bytes_to_ffi`] counterpart for a buffer the caller keeps.
pub fn bytes_ref_to_ffi(value: &[u8]) -> ffi::Bytes {
    ffi::Bytes {
        ptr: crate::ffi::abi_alloc::abi_slice_into_raw(value),
        len: value.len(),
    }
}

/// Consume an [`ffi::Bytes`] into a `Vec<u8>`.
///
/// # Safety
///
/// `value` must be a valid [`ffi::Bytes`] produced by
/// [`bytes_to_ffi`] or an FFI counterpart that uses the ABI allocator.
pub unsafe fn bytes_from_ffi(value: ffi::Bytes) -> Vec<u8> {
    unsafe {
        let copied = if value.ptr.is_null() || value.len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(value.ptr, value.len).to_vec()
        };
        drop(value);
        copied
    }
}

/// Borrow an [`ffi::Bytes`] as `&[u8]` **without** consuming it — for
/// buffers that live inside a caller-owned struct (the [`str_borrow`]
/// counterpart, without the UTF-8 requirement). Empty/null is a valid
/// empty buffer.
///
/// # Safety
///
/// `value`'s `ptr`/`len` must describe a valid buffer borrowed for at
/// least as long as the returned reference.
pub unsafe fn bytes_borrow(value: &ffi::Bytes) -> &[u8] {
    if value.ptr.is_null() || value.len == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(value.ptr, value.len) }
}

/// Convert a `Vec<T>` into an owned [`ffi::List<U>`]. The empty case
/// allocates a one-slot sentinel so consumers never see NULL.
pub fn list_to_ffi<T, U>(items: Vec<T>, mut item_to_ffi: impl FnMut(T) -> U) -> ffi::List<U> {
    let converted: Vec<U> = items.into_iter().map(&mut item_to_ffi).collect();
    let len = converted.len();
    ffi::List {
        ptr: abi_vec_into_raw(converted),
        len,
    }
}

/// Consume an [`ffi::List<T>`] into a `Vec<U>`. The list allocation
/// is freed even on error; unconverted items drop normally.
///
/// # Safety
///
/// `value` must be a valid [`ffi::List<T>`] produced by
/// [`list_to_ffi`] or an FFI counterpart that uses the ABI allocator.
pub unsafe fn list_from_ffi<T, U, E>(
    value: ffi::List<T>,
    mut item_from_ffi: impl FnMut(T) -> Result<U, E>,
) -> Result<Vec<U>, E> {
    unsafe {
        if value.ptr.is_null() {
            return Ok(Vec::new());
        }
        // Move the elements off the ABI heap and forget the shadow so
        // `List: Drop` doesn't double-free. The `Vec` then owns the
        // elements; unconverted items drop normally on early-return.
        let raw_items = crate::ffi::abi_alloc::abi_vec_from_raw(value.ptr, value.len);
        std::mem::forget(value);
        let mut out = Vec::with_capacity(raw_items.len());
        for item in raw_items {
            out.push(item_from_ffi(item)?);
        }
        Ok(out)
    }
}

/// Convert a `HashMap<String, String>` into [`ffi::KeyValueList`].
pub fn key_value_list_to_ffi(map: HashMap<String, String>) -> ffi::KeyValueList {
    let entries: Vec<(String, String)> = map.into_iter().collect();
    list_to_ffi(entries, |(key, value)| ffi::KeyValuePair {
        key: str_to_ffi(key),
        value: str_to_ffi(value),
    })
}

/// Consume a [`ffi::KeyValueList`] into a `HashMap`.
///
/// # Safety
///
/// `value` must be a valid [`ffi::KeyValueList`] produced by
/// [`key_value_list_to_ffi`] or an FFI counterpart that uses the ABI
/// allocator.
pub unsafe fn key_value_list_from_ffi(
    value: ffi::KeyValueList,
) -> Result<HashMap<String, String>, Error> {
    unsafe {
        let pairs = list_from_ffi(value, |pair| {
            let key = str_from_ffi(pair.key)?;
            let val = str_from_ffi(pair.value)?;
            Ok::<_, Error>((key, val))
        })?;
        Ok(pairs.into_iter().collect())
    }
}

/// Convert `(String, Vec<u8>)` extension entries into an owned
/// `ffi::List<ExtensionEntry>` — the [`key_value_list_to_ffi`] analogue
/// for the Bytes-valued `ffi::Extensions` entry shape.
pub fn extension_list_to_ffi(entries: Vec<(String, Vec<u8>)>) -> ffi::List<ffi::ExtensionEntry> {
    list_to_ffi(entries, |(key, value)| ffi::ExtensionEntry {
        key: str_to_ffi(key),
        value: bytes_to_ffi(value),
    })
}

/// Convert an `Option<T>` into [`ffi::Optional<U>`].
pub fn optional_to_ffi<T, U>(
    value: Option<T>,
    item_to_ffi: impl FnOnce(T) -> U,
) -> ffi::Optional<U> {
    match value {
        Some(inner) => ffi::Optional::some(item_to_ffi(inner)),
        None => ffi::Optional::none(),
    }
}

/// Consume an [`ffi::Optional<T>`] into `Option<U>`.
///
/// # Safety
///
/// `value`'s `present` discriminant must match how it was
/// constructed; the conversion takes ownership of the payload.
pub unsafe fn optional_from_ffi<T, U, E>(
    mut value: ffi::Optional<T>,
    item_from_ffi: impl FnOnce(T) -> Result<U, E>,
) -> Result<Option<U>, E> {
    unsafe {
        if value.present {
            // Read out then flip `present = false` so the parent's
            // Drop doesn't re-drop the moved-out payload.
            // SAFETY: `present == true` means `value` was initialized.
            let inner = std::ptr::read(value.value.as_ptr());
            value.present = false;
            Ok(Some(item_from_ffi(inner)?))
        } else {
            Ok(None)
        }
    }
}

/// Convert a `SystemTime` into Unix milliseconds. Sub-ms precision
/// is intentionally lossy; negative results encode pre-epoch.
pub fn system_time_to_unix_ms(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => clamp_to_i64(d.as_millis()),
        Err(error) => -clamp_to_i64(error.duration().as_millis()),
    }
}

/// Convert Unix milliseconds back into a `SystemTime`.
pub fn system_time_from_unix_ms(ms: i64) -> SystemTime {
    if ms >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    }
}

fn clamp_to_i64(value: u128) -> i64 {
    if value > i64::MAX as u128 {
        i64::MAX
    } else {
        value as i64
    }
}
