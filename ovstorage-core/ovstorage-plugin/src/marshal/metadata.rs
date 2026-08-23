// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn checksum_algorithm_to_ffi(value: ChecksumAlgorithm) -> ffi::ChecksumAlgorithm {
    ffi::ChecksumAlgorithm {
        token: primitive::str_to_ffi(value.as_str().to_owned()),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ChecksumAlgorithm`] produced by
/// [`checksum_algorithm_to_ffi`] or by an FFI counterpart that
/// follows the same allocator convention.
pub unsafe fn checksum_algorithm_from_ffi(
    value: ffi::ChecksumAlgorithm,
) -> Result<ChecksumAlgorithm, Error> {
    unsafe {
        let token = primitive::str_from_ffi(value.token)?;
        ChecksumAlgorithm::new(token)
    }
}

pub fn checksum_set_to_ffi(value: ChecksumSet) -> ffi::List<ffi::ChecksumEntry> {
    let entries: Vec<(ChecksumAlgorithm, Vec<u8>)> = value
        .iter()
        .map(|(algo, bytes)| (algo.clone(), bytes.to_vec()))
        .collect();
    primitive::list_to_ffi(entries, |(algorithm, bytes)| ffi::ChecksumEntry {
        algorithm: checksum_algorithm_to_ffi(algorithm),
        bytes: primitive::bytes_to_ffi(bytes),
    })
}

/// # Safety
///
/// `value` must be a valid `ffi::List<ffi::ChecksumEntry>`
/// produced by [`checksum_set_to_ffi`] or by an FFI counterpart.
pub unsafe fn checksum_set_from_ffi(
    value: ffi::List<ffi::ChecksumEntry>,
) -> Result<ChecksumSet, Error> {
    unsafe {
        let entries = primitive::list_from_ffi(value, |entry| {
            let algo = checksum_algorithm_from_ffi(entry.algorithm)?;
            let bytes = primitive::bytes_from_ffi(entry.bytes);
            Ok::<_, Error>((algo, bytes))
        })?;
        let mut set = ChecksumSet::new();
        for (algo, bytes) in entries {
            set.insert(algo, bytes);
        }
        Ok(set)
    }
}

pub fn effective_permissions_to_ffi(value: EffectivePermissions) -> ffi::EffectivePermissions {
    ffi::EffectivePermissions { bits: value.bits() }
}

/// Convert an [`ffi::EffectivePermissions`] back. Unknown bits are
/// truncated today; the conformance contract has hosts evaluate only
/// known bits, so this is consistent (forward-compat is permission-loss
/// not gain).
pub fn effective_permissions_from_ffi(value: ffi::EffectivePermissions) -> EffectivePermissions {
    EffectivePermissions::from_bits_truncate(value.bits)
}

pub fn system_metadata_to_ffi(value: SystemMetadata) -> ffi::SystemMetadata {
    primitive::key_value_list_to_ffi(value)
}

/// # Safety
///
/// `value` must be a valid [`ffi::SystemMetadata`] produced by
/// [`system_metadata_to_ffi`] or by an FFI counterpart.
pub unsafe fn system_metadata_from_ffi(
    value: ffi::SystemMetadata,
) -> Result<SystemMetadata, Error> {
    unsafe { primitive::key_value_list_from_ffi(value) }
}

pub fn user_metadata_to_ffi(value: UserMetadata) -> ffi::UserMetadata {
    primitive::key_value_list_to_ffi(value)
}

/// # Safety
///
/// `value` must be a valid [`ffi::UserMetadata`] produced by
/// [`user_metadata_to_ffi`] or by an FFI counterpart.
pub unsafe fn user_metadata_from_ffi(value: ffi::UserMetadata) -> Result<UserMetadata, Error> {
    unsafe { primitive::key_value_list_from_ffi(value) }
}

pub fn object_info_to_ffi(value: ObjectInfo) -> ffi::ObjectInfo {
    ffi::ObjectInfo {
        address: address::object_address_to_ffi(value.address),
        kind: identity::object_kind_to_ffi(value.kind),
        etag: primitive::optional_to_ffi(value.etag, primitive::str_to_ffi),
        version: primitive::optional_to_ffi(value.version, primitive::str_to_ffi),
        size: primitive::optional_to_ffi(value.size, |s| s),
        mtime_unix_ms: primitive::optional_to_ffi(value.mtime, primitive::system_time_to_unix_ms),
        checksums: checksum_set_to_ffi(value.checksums),
        effective_permissions: primitive::optional_to_ffi(
            value.effective_permissions,
            effective_permissions_to_ffi,
        ),
        system_metadata: primitive::optional_to_ffi(value.system_metadata, system_metadata_to_ffi),
        user_metadata: primitive::optional_to_ffi(value.user_metadata, user_metadata_to_ffi),
        modified_by: primitive::optional_to_ffi(value.modified_by, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ObjectInfo`] produced by
/// [`object_info_to_ffi`] or by an FFI counterpart.
pub unsafe fn object_info_from_ffi(value: ffi::ObjectInfo) -> Result<ObjectInfo, Error> {
    unsafe {
        // Decompose first so each field's free path runs on error.
        let address_ffi = value.address;
        let kind_ffi = value.kind;
        let etag_ffi = value.etag;
        let version_ffi = value.version;
        let size_ffi = value.size;
        let mtime_ffi = value.mtime_unix_ms;
        let checksums_ffi = value.checksums;
        let perms_ffi = value.effective_permissions;
        let system_ffi = value.system_metadata;
        let user_ffi = value.user_metadata;
        let modified_by_ffi = value.modified_by;

        let address = address::object_address_from_ffi(address_ffi);
        let etag = primitive::optional_from_ffi(etag_ffi, |s| primitive::str_from_ffi(s));
        let version = primitive::optional_from_ffi(version_ffi, |s| primitive::str_from_ffi(s));
        let size = primitive::optional_from_ffi::<u64, u64, Error>(size_ffi, Ok);
        let mtime = primitive::optional_from_ffi::<i64, SystemTime, Error>(mtime_ffi, |ms| {
            Ok(primitive::system_time_from_unix_ms(ms))
        });
        let checksums = checksum_set_from_ffi(checksums_ffi);
        let effective_permissions = primitive::optional_from_ffi::<
            ffi::EffectivePermissions,
            EffectivePermissions,
            Error,
        >(perms_ffi, |p| Ok(effective_permissions_from_ffi(p)));
        let system_metadata =
            primitive::optional_from_ffi(system_ffi, |kv| primitive::key_value_list_from_ffi(kv));
        let user_metadata =
            primitive::optional_from_ffi(user_ffi, |kv| primitive::key_value_list_from_ffi(kv));
        let modified_by =
            primitive::optional_from_ffi(modified_by_ffi, |s| primitive::str_from_ffi(s));

        Ok(ObjectInfo {
            address: address?,
            kind: identity::object_kind_from_ffi(kind_ffi),
            etag: etag?,
            version: version?,
            size: size?,
            mtime: mtime?,
            checksums: checksums?,
            effective_permissions: effective_permissions?,
            system_metadata: system_metadata?,
            user_metadata: user_metadata?,
            modified_by: modified_by?,
        })
    }
}
