// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Marshal a [`Url`] to its FFI string representation.
pub fn object_address_to_ffi(value: Url) -> ffi::Str {
    primitive::str_to_ffi(value.as_str().to_owned())
}

/// # Safety
///
/// `value` must be a valid [`ffi::Str`] produced by
/// [`object_address_to_ffi`] or by an FFI counterpart using the
/// same allocator.
pub unsafe fn object_address_from_ffi(value: ffi::Str) -> Result<Url, Error> {
    unsafe {
        let url = primitive::str_from_ffi(value)?;
        crate::address::parse(&url)
    }
}

pub fn backend_id_to_ffi(value: BackendId) -> ffi::BackendId {
    ffi::BackendId {
        id: primitive::str_to_ffi(value.0),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::BackendId`] produced by
/// [`backend_id_to_ffi`] or by an FFI counterpart.
pub unsafe fn backend_id_from_ffi(value: ffi::BackendId) -> Result<BackendId, Error> {
    unsafe {
        let id = primitive::str_from_ffi(value.id)?;
        if id.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "backend id must not be empty",
            ));
        }
        Ok(BackendId(id))
    }
}

/// Marshal an [`AddressRoot`] to the compact FFI form embedded inside
/// `BackendInstance`. Only `address` and `capabilities` cross the
/// boundary; the host fills the remaining `AddressRoot` fields from
/// connection context.
pub fn address_root_entry_to_ffi(value: AddressRoot) -> ffi::AddressRootEntry {
    ffi::AddressRootEntry {
        address: object_address_to_ffi(value.address),
        capabilities: capabilities::capabilities_to_ffi(value.capabilities),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::AddressRootEntry`] produced by
/// [`address_root_entry_to_ffi`] or by an FFI counterpart. Returned
/// `AddressRoot` carries placeholder defaults for non-instantiate
/// fields (`source`, `visibility`, etc.); the host overrides them
/// while building routes.
pub unsafe fn address_root_entry_from_ffi(
    value: ffi::AddressRootEntry,
) -> Result<AddressRoot, Error> {
    unsafe {
        let address_ffi = value.address;
        let capabilities_ffi = value.capabilities;
        let address = object_address_from_ffi(address_ffi);
        let capabilities = capabilities::capabilities_from_ffi(capabilities_ffi);
        Ok(AddressRoot {
            address: address?,
            display_name: None,
            backend_kind: String::new(),
            connection_id: None,
            capabilities: capabilities?,
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            visibility: AddressVisibility::Visible,
            user_metadata: HashMap::new(),
        })
    }
}

pub fn resolved_target_to_ffi(value: ResolvedTarget) -> ffi::ResolvedTarget {
    ffi::ResolvedTarget {
        backend_id: backend_id_to_ffi(value.backend_id),
        resolved_address: object_address_to_ffi(value.resolved_address),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ResolvedTarget`] produced by
/// [`resolved_target_to_ffi`] or by an FFI counterpart.
pub unsafe fn resolved_target_from_ffi(
    value: ffi::ResolvedTarget,
) -> Result<ResolvedTarget, Error> {
    unsafe {
        // Decompose first so an error in one half doesn't strand the
        // other half's allocation.
        let backend_id_ffi = value.backend_id;
        let resolved_address_ffi = value.resolved_address;
        let backend_id = backend_id_from_ffi(backend_id_ffi);
        let resolved_address = object_address_from_ffi(resolved_address_ffi);
        Ok(ResolvedTarget {
            backend_id: backend_id?,
            resolved_address: resolved_address?,
        })
    }
}
