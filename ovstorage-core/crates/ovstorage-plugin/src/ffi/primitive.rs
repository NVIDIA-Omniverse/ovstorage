// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// ---------------------------------------------------------------------
// Primitive owning containers
//
// Empty values still carry a non-null one-byte sentinel allocation so
// consumers never have to special-case NULL.
// ---------------------------------------------------------------------

/// Owned UTF-8 string buffer. `ptr` is never null; `len` bounds the
/// reads (the buffer is NOT NUL-terminated). UTF-8 validity is
/// enforced at marshalling time. Empty strings carry `len == 0` and
/// a one-byte sentinel allocation.
#[repr(C)]
#[derive(Debug)]
pub struct Str {
    pub ptr: *mut c_char,
    pub len: usize,
}

unsafe impl Send for Str {}

/// Owned byte buffer. Same allocator convention as [`Str`]; no UTF-8
/// requirement.
#[repr(C)]
#[derive(Debug)]
pub struct Bytes {
    pub ptr: *mut u8,
    pub len: usize,
}

unsafe impl Send for Bytes {}

/// Owned homogeneous list of `T`. `ptr` points at exactly `len`
/// elements (capacity == len). Empty lists use a one-element
/// sentinel allocation. cbindgen emits a distinct C type per
/// concrete `T` (e.g. `OvStorageListObjectInfo`).
#[repr(C)]
#[derive(Debug)]
pub struct List<T> {
    pub ptr: *mut T,
    pub len: usize,
}

/// Single `(String, String)` entry inside a [`KeyValueList`].
#[repr(C)]
#[derive(Debug)]
pub struct KeyValuePair {
    pub key: Str,
    pub value: Str,
}

unsafe impl Send for KeyValuePair {}

/// Owned `(String, String)` list. Iteration order is not promised.
pub type KeyValueList = List<KeyValuePair>;

/// Normalized checksum algorithm token (e.g. `"sha256"`, `"crc32c"`).
/// The marshalling layer enforces validation rules on the way in.
#[repr(C)]
#[derive(Debug)]
pub struct ChecksumAlgorithm {
    pub token: Str,
}

unsafe impl Send for ChecksumAlgorithm {}

/// One `(algorithm, bytes)` checksum entry. Field sites embed
/// `List<ChecksumEntry>` directly rather than via a `ChecksumSet`
/// alias — cbindgen 0.27 forward-declares such aliases incompletely
/// when the inner type is processed later in the emission walk.
#[repr(C)]
#[derive(Debug)]
pub struct ChecksumEntry {
    pub algorithm: ChecksumAlgorithm,
    pub bytes: Bytes,
}

unsafe impl Send for ChecksumEntry {}

/// Optional `T`. `present == true` means `value` is initialized;
/// otherwise `value` carries unspecified bytes and must not be read.
/// cbindgen emits a distinct C type per concrete `T`.
#[repr(C)]
#[derive(Debug)]
pub struct Optional<T> {
    pub present: bool,
    pub value: core::mem::MaybeUninit<T>,
}

impl<T> Optional<T> {
    pub fn some(value: T) -> Self {
        Self {
            present: true,
            value: core::mem::MaybeUninit::new(value),
        }
    }

    pub fn none() -> Self {
        Self {
            present: false,
            value: core::mem::MaybeUninit::uninit(),
        }
    }

    pub fn is_some(&self) -> bool {
        self.present
    }

    pub fn is_none(&self) -> bool {
        !self.present
    }
}

/// Release the buffer owned by a [`Str`] in place, zeroing the
/// `Str` slot. Safe with NULL. The `Str` storage itself (the pointee)
/// is not released; only the inner allocation is freed.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`Str`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_str_free(value: *mut Str) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

/// Release the buffer owned by a [`Bytes`] in place. Safe with NULL.
/// Same convention as `ovstorage_plugin_str_free`.
///
/// # Safety
///
/// `value`, when non-null, must point at a valid, properly aligned
/// [`Bytes`] produced by an ovstorage call. Double-freeing is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_plugin_bytes_free(value: *mut Bytes) {
    unsafe {
        if value.is_null() {
            return;
        }
        std::ptr::drop_in_place(value);
    }
}

impl Drop for Str {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let cap = if self.len == 0 { 1 } else { self.len };
            // SAFETY: constructors allocate with `len == cap` (cap=1
            // for the empty sentinel).
            unsafe {
                let _ = Vec::from_raw_parts(self.ptr as *mut u8, self.len, cap);
            }
            self.ptr = std::ptr::null_mut();
            self.len = 0;
        }
    }
}

impl Drop for Bytes {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let cap = if self.len == 0 { 1 } else { self.len };
            // SAFETY: constructors allocate with `len == cap`.
            unsafe {
                let _ = Vec::from_raw_parts(self.ptr, self.len, cap);
            }
            self.ptr = std::ptr::null_mut();
            self.len = 0;
        }
    }
}

// `KeyValuePair` has no `Drop` impl: field-by-field auto-drop runs
// `Str: Drop`, and the absence of `Drop` lets
// `key_value_list_from_ffi` move the two `Str`s out by value.

impl<T> Drop for List<T> {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let cap = if self.len == 0 { 1 } else { self.len };
            // SAFETY: constructors allocate with `len == cap`.
            unsafe {
                let _ = Vec::from_raw_parts(self.ptr, self.len, cap);
            }
            self.ptr = std::ptr::null_mut();
            self.len = 0;
        }
    }
}

impl<T> Drop for Optional<T> {
    fn drop(&mut self) {
        if self.present {
            // SAFETY: `present == true` means `value` was initialized.
            unsafe {
                self.value.assume_init_drop();
            }
            self.present = false;
        }
    }
}
