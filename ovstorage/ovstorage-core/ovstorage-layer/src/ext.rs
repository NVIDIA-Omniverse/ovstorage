// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Well-known request-extension keys (RFC-0066 well-known registry). Keys live
//! in this module and drop the `_EXTENSION` suffix, so use-sites read
//! `ext::PRINCIPAL_ID`; the string values are the registry's stable ids.
//!
//! These keys are defined canonically here in `ovstorage-layer` so both the
//! host and the plugin SDK (which depends on this crate) can share them.

use crate::{Error, ErrorCode, Extensions, Result, Url};

/// Request-extension key carrying the authenticated request principal — the
/// RFC-0066 well-known registry's `PrincipalExt` key. The value is the
/// principal id as UTF-8 bytes (the typed `PrincipalView` accessor surface
/// arrives with the extension-trait registry). Per the registry's absence
/// semantics, a missing extension means **anonymous** — the single-identity
/// host shape — which cache scoping maps to `principal_id: None`, so an
/// anonymous entry can never collide with a real principal's.
/// Multi-principal hosts (the broker) set this on every request they
/// dispatch on a caller's behalf.
pub const PRINCIPAL_ID: &str = "org.omniverse.ovstorage/principal@1";

/// Request-extension key carrying the writer identity a host attribution layer
/// asserts for this request — the value it wants persisted under
/// [`crate::attribution::ATTRIBUTION_KEY_MODIFIED_BY`], as UTF-8 bytes. Like
/// [`PRINCIPAL_ID`], the typed accessor surface the RFC-0066 registry names for
/// it arrives with the extension-trait registry; until then this key is read
/// through [`crate::attribution::attested_modified_by`].
///
/// It is a strictly narrower claim than [`PRINCIPAL_ID`], which says only that
/// a principal was resolved. Per the registry's absence semantics, a missing
/// extension means **no attribution layer spoke for this request** — the branch
/// carries none because its backend cannot hold the reserved key, the host's
/// strategy passes an upstream host's stamp through untouched, or there is no
/// attributing host in the graph. A plugin that reads it therefore leaves
/// existing metadata alone when it is absent rather than synthesizing a value
/// from the principal, which would attribute writes on exactly the branches a
/// host composed to avoid attributing.
///
/// A plugin needs it only where a redirect write's metadata is applied by the
/// commit call rather than bound when the redirect was minted: that copy
/// travelled out through the caller and back, so the host's value has to be
/// re-asserted over it. See [`crate::attribution::reassert_attribution`].
pub const ATTRIBUTED_MODIFIED_BY: &str = "org.omniverse.ovstorage/attributed_modified_by@1";

/// Request-extension key carrying the human-readable display name of the
/// authenticated request principal. The value is the display name as UTF-8
/// bytes. Absence carries no display name; it never affects cache scoping
/// or authorization, which key off [`PRINCIPAL_ID`] alone.
pub const PRINCIPAL_DISPLAY_NAME: &str = "org.omniverse.ovstorage/principal-display-name@1";

/// Request-extension key carrying the caller's **undecoded** credential
/// material — the RFC-0066 `AuthCredential` (bearer token plus the
/// transport-level peer identity) in its versioned flat wire format. A host
/// gathers transport credentials (only the socket owner can) and stamps this
/// on the request; auth layers (built-in or plugin-provided) are the readers,
/// decoding it to resolve a principal and then stamping [`PRINCIPAL_ID`] down
/// to inner layers. Absence means no credential was presented (anonymous
/// caller).
pub const AUTH_CREDENTIAL: &str = "org.omniverse.ovstorage/auth-credential@1";

/// Request-extension key carrying the address that needs an upstream
/// credential. The value is the address [`Url`] as UTF-8 bytes.
/// Absence means an `authenticate_connection` request is ordinary connection
/// authentication, not brokered upstream authentication. This extension is a
/// fact about which address needs an upstream credential, never a behavior
/// selector.
pub const UPSTREAM_AUTH_ADDRESS: &str = "org.omniverse.ovstorage/upstream-auth-address@1";

/// Request-extension key carrying a broker-resolved OAuth credential
/// reference for one data operation. The value names the backend-scoped
/// keyring entry containing the access token; it never carries secret bytes.
/// The authenticated [`PRINCIPAL_ID`] extension supplies the keyring's
/// connection/principal component. Owning backends consume and remove this
/// extension before dispatching the request.
pub const RESOLVED_OAUTH_CREDENTIAL: &str = "org.omniverse.ovstorage/resolved-oauth-credential@1";

/// Non-secret reference to an OAuth access token in the host keyring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedOAuthCredentialRef {
    /// Canonical backend kind used as the host keyring namespace.
    pub backend_kind: String,
    /// Provider-owned keyring field containing the access token.
    pub keyring_handle: String,
}

const RESOLVED_OAUTH_CREDENTIAL_VERSION: u8 = 1;

/// Insert the canonical byte representation of an upstream-auth address.
pub fn insert_upstream_auth_address(extensions: &mut Extensions, address: &Url) {
    extensions.insert(UPSTREAM_AUTH_ADDRESS, address.as_str().as_bytes().to_vec());
}

/// Decode the optional upstream-auth address from a request extension bag.
///
/// # Errors
///
/// Returns [`ErrorCode::InvalidArgument`] when the registered value is not
/// UTF-8 or is not an absolute URL.
pub fn upstream_auth_address(extensions: &Extensions) -> Result<Option<Url>> {
    let Some(raw) = extensions.get(UPSTREAM_AUTH_ADDRESS) else {
        return Ok(None);
    };
    let value = std::str::from_utf8(raw).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("upstream auth address is not UTF-8: {error}"),
        )
    })?;
    Url::parse(value).map(Some).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid upstream auth address: {error}"),
        )
    })
}

/// Insert the canonical binary representation of a resolved OAuth credential
/// reference.
///
/// # Errors
///
/// Returns [`ErrorCode::InvalidArgument`] when either string is empty or too
/// long for the versioned wire representation.
pub fn insert_resolved_oauth_credential(
    extensions: &mut Extensions,
    credential: &ResolvedOAuthCredentialRef,
) -> Result<()> {
    if credential.backend_kind.is_empty() || credential.keyring_handle.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "resolved OAuth credential reference fields must not be empty",
        ));
    }
    let backend_len = u32::try_from(credential.backend_kind.len()).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "resolved OAuth credential backend kind is too long",
        )
    })?;
    let handle_len = u32::try_from(credential.keyring_handle.len()).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "resolved OAuth credential keyring handle is too long",
        )
    })?;
    let mut encoded = Vec::with_capacity(
        1 + std::mem::size_of::<u32>() * 2
            + credential.backend_kind.len()
            + credential.keyring_handle.len(),
    );
    encoded.push(RESOLVED_OAUTH_CREDENTIAL_VERSION);
    encoded.extend_from_slice(&backend_len.to_be_bytes());
    encoded.extend_from_slice(&handle_len.to_be_bytes());
    encoded.extend_from_slice(credential.backend_kind.as_bytes());
    encoded.extend_from_slice(credential.keyring_handle.as_bytes());
    extensions.insert(RESOLVED_OAUTH_CREDENTIAL, encoded);
    Ok(())
}

/// Remove and decode the optional resolved OAuth credential reference.
/// Consuming the reference prevents an inner layer from accidentally reusing
/// it for a second request.
///
/// # Errors
///
/// Returns [`ErrorCode::InvalidArgument`] when the registered value is not the
/// canonical versioned representation.
pub fn take_resolved_oauth_credential(
    extensions: &mut Extensions,
) -> Result<Option<ResolvedOAuthCredentialRef>> {
    let Some(encoded) = extensions.remove(RESOLVED_OAUTH_CREDENTIAL) else {
        return Ok(None);
    };
    if encoded.len() < 9 || encoded[0] != RESOLVED_OAUTH_CREDENTIAL_VERSION {
        return Err(invalid_resolved_oauth_credential());
    }
    let backend_len = u32::from_be_bytes(
        encoded[1..5]
            .try_into()
            .map_err(|_| invalid_resolved_oauth_credential())?,
    ) as usize;
    let handle_len = u32::from_be_bytes(
        encoded[5..9]
            .try_into()
            .map_err(|_| invalid_resolved_oauth_credential())?,
    ) as usize;
    let expected_len = 9usize
        .checked_add(backend_len)
        .and_then(|len| len.checked_add(handle_len))
        .ok_or_else(invalid_resolved_oauth_credential)?;
    if encoded.len() != expected_len || backend_len == 0 || handle_len == 0 {
        return Err(invalid_resolved_oauth_credential());
    }
    let backend_end = 9 + backend_len;
    let backend_kind = std::str::from_utf8(&encoded[9..backend_end])
        .map_err(|_| invalid_resolved_oauth_credential())?
        .to_string();
    let keyring_handle = std::str::from_utf8(&encoded[backend_end..])
        .map_err(|_| invalid_resolved_oauth_credential())?
        .to_string();
    Ok(Some(ResolvedOAuthCredentialRef {
        backend_kind,
        keyring_handle,
    }))
}

fn invalid_resolved_oauth_credential() -> Error {
    Error::new(
        ErrorCode::InvalidArgument,
        "invalid resolved OAuth credential reference",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_auth_address_round_trips_and_rejects_invalid_values() {
        let address = Url::parse("gs://bucket/object").unwrap();
        let mut extensions = Extensions::new();
        assert!(upstream_auth_address(&extensions).unwrap().is_none());

        insert_upstream_auth_address(&mut extensions, &address);
        assert_eq!(upstream_auth_address(&extensions).unwrap(), Some(address));

        extensions.insert(UPSTREAM_AUTH_ADDRESS, vec![0xff]);
        assert_eq!(
            upstream_auth_address(&extensions).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        extensions.insert(UPSTREAM_AUTH_ADDRESS, b"not a URL".to_vec());
        assert_eq!(
            upstream_auth_address(&extensions).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn resolved_oauth_credential_round_trips_and_is_consumed() {
        let credential = ResolvedOAuthCredentialRef {
            backend_kind: "http".into(),
            keyring_handle: "oauth/upstream-idp".into(),
        };
        let mut extensions = Extensions::new();
        assert!(
            take_resolved_oauth_credential(&mut extensions)
                .unwrap()
                .is_none()
        );

        insert_resolved_oauth_credential(&mut extensions, &credential).unwrap();
        assert_eq!(
            take_resolved_oauth_credential(&mut extensions).unwrap(),
            Some(credential)
        );
        assert!(
            take_resolved_oauth_credential(&mut extensions)
                .unwrap()
                .is_none()
        );

        extensions.insert(RESOLVED_OAUTH_CREDENTIAL, vec![1, 0, 0]);
        assert_eq!(
            take_resolved_oauth_credential(&mut extensions)
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument
        );
    }
}
