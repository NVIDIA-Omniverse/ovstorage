// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn object_kind_to_ffi(value: ObjectKind) -> ffi::ObjectKindV1 {
    match value {
        ObjectKind::File => ffi::ObjectKindV1::File,
        ObjectKind::Directory => ffi::ObjectKindV1::Directory,
        ObjectKind::DirectoryMarker => ffi::ObjectKindV1::DirectoryMarker,
        ObjectKind::DirectoryInferred => ffi::ObjectKindV1::DirectoryInferred,
    }
}

pub fn object_kind_from_ffi(value: ffi::ObjectKindV1) -> ObjectKind {
    match value {
        ffi::ObjectKindV1::File => ObjectKind::File,
        ffi::ObjectKindV1::Directory => ObjectKind::Directory,
        ffi::ObjectKindV1::DirectoryMarker => ObjectKind::DirectoryMarker,
        ffi::ObjectKindV1::DirectoryInferred => ObjectKind::DirectoryInferred,
    }
}

pub fn if_dest_exists_to_ffi(value: IfDestExists) -> ffi::IfDestExistsV1 {
    match value {
        IfDestExists::Overwrite => ffi::IfDestExistsV1::overwrite(),
        IfDestExists::Fail => ffi::IfDestExistsV1::fail(),
        IfDestExists::MatchEtag(etag) => {
            ffi::IfDestExistsV1::match_etag(primitive::str_to_ffi(etag))
        }
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::IfDestExistsV1`] produced by
/// [`if_dest_exists_to_ffi`] or by an FFI counterpart.
pub unsafe fn if_dest_exists_from_ffi(value: ffi::IfDestExistsV1) -> Result<IfDestExists, Error> {
    unsafe {
        let tag = value.tag;
        let result = match tag {
            ffi::IfDestExistsTag::Overwrite => Ok(IfDestExists::Overwrite),
            ffi::IfDestExistsTag::Fail => Ok(IfDestExists::Fail),
            ffi::IfDestExistsTag::MatchEtag => {
                let payload = std::ptr::read(&value.match_etag).assume_init();
                primitive::str_from_ffi(payload.etag).map(IfDestExists::MatchEtag)
            }
        };
        // Suppress the parent's Drop — we've taken ownership of the
        // active payload (or it had no payload to take).
        std::mem::forget(value);
        result
    }
}
