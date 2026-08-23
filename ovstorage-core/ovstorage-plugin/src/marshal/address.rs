// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Marshal a [`Url`] to its FFI string representation.
pub fn object_address_to_ffi(value: Url) -> ffi::Str {
    primitive::str_to_ffi(value.as_str().to_owned())
}

/// Decode an address a plugin **returned**, validating rather than normalizing.
///
/// The direction matters and inverts the usual rule. An address arriving on a
/// request is the caller's *question*, so normalizing it is the whole point. An
/// address crossing this boundary is the plugin's *answer* — its claim about
/// which object it named — and rewriting an answer is retargeting, not
/// normalizing. A plugin whose literal key is `public%2F..%2Fprivate/secret`
/// would have the address it handed back silently rewritten to
/// `private/secret`, and a later `delete` of the address its caller was given
/// would destroy a different object.
///
/// So the address is checked, and a plugin that cannot express its own key as a
/// canonical address is refused rather than reinterpreted.
///
/// There are two steps that can move an address, and the address is checked
/// against both. `Url::parse` runs first and resolves dot segments, removes
/// ASCII TAB/LF/CR and folds `\` on a special scheme, none of which the parsed
/// form remembers — so a raw `s3://bucket/public/../private/secret` would
/// otherwise arrive already flattened and pass every later check as a fixed
/// point. [`ovstorage_layer::parsing_preserves_node`] answers that step from
/// the raw string, and [`ovstorage_layer::canonicalize_preserves_node`] answers
/// the layer's own canonicalization from the parsed one.
///
/// The second check is deliberately narrow. Of everything `canonicalize`
/// does, only dot-segment resolution can move an address to a different
/// object; lowercasing
/// the host, giving an empty authority path a `/`, dropping the fragment and
/// re-encoding to the canonical escape set all leave the node alone. A plugin
/// returning `omniverse://SERVER/p`, `omniverse://host` or `s3://b/a%7bb` is
/// answering correctly and must not be refused for a spelling the host is about
/// to normalize anyway.
///
/// Decode an address a PLUGIN OR BRIDGE RETURNED, refusing any spelling whose
/// node the host would move.
///
/// The whole doc above applies; this is that logic with no FFI in it, so every
/// boundary that receives a returned address can share one implementation
/// instead of restating the rule.
///
/// **Adopters:** the C plugin ABI (`object_address_from_ffi`), and the Python
/// bridge's `Info.address`. A boundary that receives a REQUEST address wants
/// `address::parse` instead — normalizing a question is the point; normalizing
/// an answer retargets it.
pub fn returned_object_address(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("plugin returned an invalid address URL: {error}"),
        )
    })?;
    if url.cannot_be_a_base() {
        // The same refusal `address::parse` and `root_from_ffi_str` make.
        // `canonicalize_preserves_node` returns `true` unconditionally for
        // this class and `canonicalize` returns it untouched, so without
        // the guard an authority-less address enters here un-normalized and
        // is handed to a caller as an `ObjectInfo.address` that can never
        // be re-parsed — while the identical string is refused wherever
        // `address::parse` is the entry point.
        return Err(Error::new(
            ErrorCode::Internal,
            // The payload is NOT interpolated, the same choice
            // `address::parse`, `root_from_ffi_str` and `url_from_ffi`
            // make for this class: everything after the scheme is one
            // opaque string, userinfo included, and `Error`'s redactor
            // cannot normalize it, because it recognizes only
            // `scheme://`-shaped tokens. `RedactedUrl` renders this class
            // as its scheme alone for the same reason; naming the scheme
            // here says the same thing without depending on it.
            format!(
                "plugin returned an address with no authority; scheme '{}' was \
                 parsed as authority-less",
                url.scheme()
            ),
        ));
    }
    if !ovstorage_layer::parsing_preserves_node(raw) {
        return Err(Error::new(
            ErrorCode::Internal,
            // Only the parsed form is rendered. The rejected spelling is
            // the one the host could not account for, so re-emitting it
            // would put a string of unknown structure through a redactor
            // that works by recognizing structure; the parsed URL has no
            // such gap and names the object the caller would have reached.
            format!(
                "plugin returned an address the URL parser rewrites before it can be \
                 checked: it parses to {}, which is a different object from the one \
                 the spelling names. Return the address as a serialized URL",
                crate::RedactedUrl(&url)
            ),
        ));
    }
    if !ovstorage_layer::canonicalize_preserves_node(&url) {
        let canonical = ovstorage_layer::canonicalize(url.clone());
        return Err(Error::new(
            ErrorCode::Internal,
            // Both spellings are rendered through `RedactedUrl`, which is
            // safe here because the authority-less class is refused above.
            // The two differ in their path, which is what it keeps.
            format!(
                "plugin returned an address that resolves elsewhere: {} names \
                 {}, so a caller acting on it would reach a different object",
                crate::RedactedUrl(&url),
                crate::RedactedUrl(&canonical)
            ),
        ));
    }
    Ok(ovstorage_layer::canonicalize(url))
}

/// # Safety
///
/// `value` must be a valid [`ffi::Str`] produced by
/// [`object_address_to_ffi`] or by an FFI counterpart using the
/// same allocator.
pub unsafe fn object_address_from_ffi(value: ffi::Str) -> Result<Url, Error> {
    unsafe {
        let raw = primitive::str_from_ffi(value)?;
        returned_object_address(&raw)
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

/// Marshal an [`AddressRoot`] to the compact FFI form used by root-change
/// payloads. Only `address` and `capabilities` cross the boundary; the host
/// fills the remaining `AddressRoot` fields from connection context.
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
