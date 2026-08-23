// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared contracts for wrapper Layers and the broker's private
//! directory-normalization wrapper.
//!
//! Public wrapper implementations are supplied by the standard core, cache,
//! and HTTP ABI-v2 plugins. Their behavior relies on the request-extension
//! keys and helper rules retained in this host module:
//!
//! - `RetryWrapper` — transient-error backoff using
//!   [`crate::retry::with_retry_async`]. It retries single-shot, replayable
//!   operations and does **not** retry non-replayable streamed writes or
//!   multi-round redirect operations.
//! - `RedirectFollowerWrapper` — read- and write-path redirect following. On
//!   `read`, a [`ReadResult::Redirect`] is fetched via the streaming follower
//!   (`follow_read_redirect_streaming`) and surfaced as a
//!   [`ReadResult::Stream`]. On `write`/`write_stream`, it attempts
//!   `write_redirect` and, when the backend redirects, drives the
//!   `follow_write_redirects` → `continue_write` multi-round loop (replaying
//!   the body across rounds); otherwise it falls back to the body-typed slot.
//! - `ByteCacheWrapper` — object-byte caching over [`ovstorage_cache::Cache`], composed
//!   **above** `RedirectFollowerWrapper` to cache post-redirect bytes. Caches
//!   `ReadResult::Bytes` reads + `materialize` (with a lease), write-through for
//!   buffered writes, and invalidates on mutating ops.
//! - `MetadataCacheWrapper` — `stat`/`list` caching over [`MetadataCache`],
//!   with parent-prefix invalidation on mutations.
//!
//! ## Stack order
//!
//! Redirect following composes **above** retry so the backend pointer-fetch is
//! retried independently from the external transfer:
//! `… → ByteCache → RedirectFollower → Retry → Router → Backend`. The
//! `RedirectFollowerWrapper`'s own `RetryConfig` covers the follower's HTTP
//! fetches — the buffered write-redirect part uploads
//! (`follow_write_redirects`) and the streaming read follow's header phase
//! (`follow_read_redirect_streaming` retries until response headers arrive;
//! mid-stream replay is impossible, so a mid-body failure still surfaces as a
//! stream error). `materialize` first delegates to the inner Layer and falls
//! back to redirect-following `read` plus local staging when necessary.
//! Connection bring-up and credential-failure re-auth remain concerns of the
//! connection-owning Layer; connection-management slots delegate through the
//! wrapper chain.
//!
//! ## Cache scope & deferrals
//!
//! Cache behavior is split between the byte and metadata wrappers:
//!
//! - **Redirected / streamed `read_bytes` results are cached.**
//!   [`LayerExt::read_bytes`](crate::ext::LayerExt::read_bytes) marks requests
//!   with `READ_TO_BYTES_EXTENSION`;
//!   on that hint the `ByteCacheWrapper` buffers a followed-redirect `Stream`
//!   (or a `LocalDelegate`) and fills the cache under the result's validator,
//!   `read_stream` never fills the cache — a
//!   stream passes through un-buffered (no safe tee/staging semantics) — though
//!   an existing cached entry serves any validated read.
//! - **Byte-cache key identity.** The key is
//!   `partition\0canonical_address\0etag`: an entry is tied to the object
//!   version it was read from, lookups validate against the current `etag`
//!   (an inner stat, served by the metadata cache composed below), and
//!   unversioned content is never cached. Backend identity is deliberately not
//!   part of the key — the validator is, which stays
//!   correct even when routes move between backends or cache roots are
//!   shared.
//! - **Broker-resolved OAuth bytes bypass the byte cache.** A credentialed
//!   origin can return principal-specific representations under the same URL
//!   and validator. Requests carrying [`ext::RESOLVED_OAUTH_CREDENTIAL`]
//!   therefore delegate `read` and `materialize` without consulting or filling
//!   the principal-agnostic content and availability indexes. Ordinary reads
//!   retain the validator-keyed cache behavior above.
//! - **Broker-resolved OAuth metadata bypasses the metadata cache.** Credential
//!   revocation or replacement changes what one principal may observe without
//!   changing its principal id or generating an object mutation. Credentialed
//!   `stat` requests therefore delegate without consulting or filling `Stat`
//!   or list-backed-stat entries. A matching `list` guard also bypasses `List`
//!   and list-backed-stat fills when a credential reference is present; that
//!   guard is forward-looking because the broker currently stamps only
//!   `stat`, `read`, and `materialize`, and does not promise credential
//!   propagation through `list`.
//! - **`stat`-from-cached-parent-list** is owned by
//!   `MetadataCacheWrapper`: the
//!   capability gate reads `inner.root_info_for`, and sitting below the
//!   address wrappers puts parent keys in post-alias space. An eligible
//!   direct `stat` also fills the `Stat` cache on success.
//! - **`materialize` over a local backend double-stores.** The v2 `materialize`
//!   slot returns a uniform `LocalDelegate`, so the wrapper can't tell an
//!   already-canonical local file (the built-in `file://` backend) from a
//!   cloud-staged temp; on a cacheable miss it copies the file into the CAS and
//!   returns the snapshot path.
//!   An extra copy for local backends; read-result-preserving.
//! - **Principal-scoped ordinary metadata keys.** For requests without a
//!   broker-resolved OAuth credential, `MetadataCacheWrapper` scopes every
//!   `Stat`/`List` key by the principal carried in the [`ext::PRINCIPAL_ID`]
//!   request extension: one principal's cached metadata is never served to
//!   another. Absence means anonymous (`principal_id: None`, the
//!   single-identity host shape) and cannot collide with a real principal.
//!   Mutation invalidation is address-wide across principals — the safe
//!   direction.
//!
//! ## Module layout
//!
//! Wrapper families live one-per-module (implementation and tests are split
//! the same way):
//!
//! - `retry` — `RetryWrapper` (`RetryWrapperFactory`)
//! - `redirect_follower` — `RedirectFollowerWrapper` (`RedirectFollowerWrapperFactory`)
//! - `byte_cache` — `ByteCacheWrapper` (`ByteCacheWrapperFactory`)
//! - `metadata_cache` — `MetadataCacheWrapper` (`MetadataCacheWrapperFactory`)
//! - `alias` — `AliasWrapper` (`AliasWrapperFactory`)
//! - `copy_rename_fallback` — `CopyRenameFallbackWrapper` (`CopyRenameFallbackWrapperFactory`)
//!
//! This module keeps the cross-family request-extension keys and small shared
//! config/buffer helpers; everything family-specific lives in the family
//! module in its owning plugin.

use crate::*;

/// Request-extension key set by [`LayerExt::read_bytes`](crate::ext::LayerExt::read_bytes) to signal that the caller
/// wants a fully buffered `Bytes` result. On this hint the `ByteCacheWrapper`
/// buffers a `Stream`/`LocalDelegate` (which streaming callers otherwise get
/// un-buffered) and fills the cache with the materialized bytes, keyed by the
/// resolved address the wrapper sees.
pub(crate) const READ_TO_BYTES_EXTENSION: &str = "ovstorage.read_to_bytes";

/// True when `key` names a host-internal in-band rider — the dotted
/// `ovstorage.` signaling namespace host helpers and wrappers use among
/// themselves (e.g. the crate-private `READ_TO_BYTES_EXTENSION`) — rather
/// than a well-known registry extension (`<domain>/<name>@<version>`, e.g.
/// [`ext::PRINCIPAL_ID`]). Internal riders still cross vtable hops
/// byte-faithfully (foreign layers ignore unknown keys), but language
/// bridges do not project them into user layer code: a Python override's
/// `extensions` keyword carries only registry extensions.
pub fn is_internal_extension(key: &str) -> bool {
    key.starts_with("ovstorage.")
}

/// Well-known request-extension keys (RFC-0066 well-known registry). Keys live
/// in this module and drop the `_EXTENSION` suffix, so use-sites read
/// `ext::PRINCIPAL_ID`; the string values are the registry's stable ids.
pub mod ext {
    /// Request-extension key carrying the authenticated request principal — the
    /// RFC-0066 well-known registry's `PrincipalExt` key. Defined canonically in
    /// `ovstorage-layer` so both the host and the plugin SDK share it; see
    /// [`ovstorage_layer::ext::PRINCIPAL_ID`] for the full semantics.
    pub use ovstorage_layer::ext::PRINCIPAL_ID;

    /// Request-extension key carrying the address that needs an upstream
    /// credential. See [`ovstorage_layer::ext::UPSTREAM_AUTH_ADDRESS`] for the
    /// full semantics.
    pub use ovstorage_layer::ext::{
        RESOLVED_OAUTH_CREDENTIAL, ResolvedOAuthCredentialRef, UPSTREAM_AUTH_ADDRESS,
        insert_resolved_oauth_credential, insert_upstream_auth_address,
        take_resolved_oauth_credential, upstream_auth_address,
    };

    /// Request-extension key carrying the writer identity a host attribution
    /// layer asserts for this request — the RFC-0066 well-known registry's
    /// `AttributedModifiedByExt` key. Defined canonically in `ovstorage-layer`
    /// so both the host and the plugin SDK share it; see
    /// [`ovstorage_layer::ext::ATTRIBUTED_MODIFIED_BY`] for the full semantics,
    /// including why absence is not the same as an anonymous principal.
    pub use ovstorage_layer::ext::ATTRIBUTED_MODIFIED_BY;

    /// Authentication request-extension keys. Defined canonically in
    /// `ovstorage-layer` so both the host and the plugin SDK share them; see
    /// [`ovstorage_layer::ext`] for their full semantics.
    pub use ovstorage_layer::ext::{AUTH_CREDENTIAL, PRINCIPAL_DISPLAY_NAME};
}

/// Buffer a [`ReadStream`] into a `Vec<u8>`, enforcing the optional `read_bytes`
/// size cap. Crossing the cap errors mid-buffer rather than returning a partial
/// object.
pub(crate) async fn buffer_read_stream(
    mut stream: ReadStream,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>> {
    use futures::StreamExt as _;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if let Some(cap) = max_bytes
            && (bytes.len() as u64).saturating_add(chunk.len() as u64) > cap
        {
            return Err(crate::read_helpers::read_bytes_max_bytes_error(cap));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::ext;

    #[test]
    fn ext_principal_id_keeps_the_legacy_value() {
        assert_eq!(ext::PRINCIPAL_ID, "org.omniverse.ovstorage/principal@1");
        assert_eq!(
            ext::UPSTREAM_AUTH_ADDRESS,
            "org.omniverse.ovstorage/upstream-auth-address@1"
        );
        assert_eq!(
            ext::RESOLVED_OAUTH_CREDENTIAL,
            "org.omniverse.ovstorage/resolved-oauth-credential@1"
        );
        assert_eq!(
            ext::AUTH_CREDENTIAL,
            "org.omniverse.ovstorage/auth-credential@1"
        );
        assert_eq!(
            ext::PRINCIPAL_DISPLAY_NAME,
            "org.omniverse.ovstorage/principal-display-name@1"
        );
        assert_eq!(
            ext::ATTRIBUTED_MODIFIED_BY,
            "org.omniverse.ovstorage/attributed_modified_by@1"
        );
    }
}
