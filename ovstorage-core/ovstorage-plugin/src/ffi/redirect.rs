// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

// Redirect / HTTP machinery
// ---------------------------------------------------------------------

/// Caller-requested operation set for `check_access` and the
/// authorization scope of a redirect.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AccessOps {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub update_metadata: bool,
}

/// HTTP method + URL + header set. `headers` iteration order is not
/// promised; receivers needing stable order materialize it locally.
#[repr(C)]
#[derive(Debug)]
pub struct HttpRequest {
    pub method: Str,
    pub url: Str,
    pub headers: KeyValueList,
}

unsafe impl Send for HttpRequest {}

/// Format hint for an `mtime` header parsed out of an HTTP response.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtimeFormat {
    Rfc1123 = 0,
    Iso8601 = 1,
    UnixSeconds = 2,
}

/// One `(algorithm, header_name)` binding inside
/// [`ResponseParsing::checksum_headers`]. Dedicated POD struct so
/// cbindgen emits a stable C type rather than a generic
/// `KeyValuePair`.
#[repr(C)]
#[derive(Debug)]
pub struct ChecksumHeaderBinding {
    pub algorithm: ChecksumAlgorithm,
    pub header: Str,
}

unsafe impl Send for ChecksumHeaderBinding {}

/// Hints for how to parse a redirect response into the redirect's
/// object info (etag / version / size / mtime).
#[repr(C)]
#[derive(Debug)]
pub struct ResponseParsing {
    pub etag_header: Optional<Str>,
    pub version_header: Optional<Str>,
    pub size_header: Optional<Str>,
    pub mtime_header: Optional<Str>,
    pub mtime_format: MtimeFormat,
    pub system_metadata_headers: List<Str>,
    /// See `crate::ResponseParsing::content_checksum_header`.
    pub content_checksum_header: Optional<Str>,
    /// See `crate::ResponseParsing::content_checksum_algorithm`.
    pub content_checksum_algorithm: Optional<ChecksumAlgorithm>,
    /// See `crate::ResponseParsing::checksum_headers`.
    pub checksum_headers: List<ChecksumHeaderBinding>,
}

unsafe impl Send for ResponseParsing {}

/// What a redirect's credential authorizes, declared by the backend that
/// minted it. See `RedirectCredential` in the layer types for the full
/// rationale; in short, a host cannot recover this by inspecting the redirect,
/// because a blob-scoped signature and an account-wide one are the same shape.
///
/// **The discriminant range is part of the ABI contract, not something the
/// host revalidates.** Like every other `#[repr(C)]` enum crossing this
/// boundary, a plugin writing a value outside `0..=3` here is undefined
/// behaviour rather than a fail-safe demotion to `Unspecified`. Two other
/// layers do validate and are the reason this is a contract rather than a
/// hazard: the loader admits only an exact ABI-version match, and the pure-C
/// application shim rejects an out-of-range discriminant in both directions
/// before it reaches this struct. The wire protocol validates too, because
/// there the peer is genuinely untrusted.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RedirectCredential {
    /// The minting backend does not know — it forwards an opaque credential it
    /// did not construct. A host treats this as [`RedirectCredential::Connection`].
    Unspecified = 0,
    /// No credential; the target is fetchable by anyone holding the URL.
    None = 1,
    /// Authorizes this request only, and expires with the redirect.
    Request = 2,
    /// Authorizes the connection at large — other objects, and time beyond this
    /// redirect's expiry.
    Connection = 3,
}

/// Authorization scope a redirect carries.
#[repr(C)]
#[derive(Debug)]
pub struct RedirectScope {
    pub physical_url_prefix: Str,
    pub operations: AccessOps,
    pub expires_at_unix_ms: i64,
    pub credential: RedirectCredential,
}

unsafe impl Send for RedirectScope {}

/// Read redirect — a pre-signed HTTP request the host follows
/// directly through its in-process HTTPS client.
#[repr(C)]
#[derive(Debug)]
pub struct ReadRedirect {
    pub request: HttpRequest,
    pub response_parsing: ResponseParsing,
    pub expires_at_unix_ms: i64,
    pub scope: RedirectScope,
    pub audit_id: Str,
    pub policy_epoch: u64,
}

unsafe impl Send for ReadRedirect {}

/// Tag for [`RedirectBodySource`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RedirectBodySourceTag {
    Empty = 0,
    UserBytes = 1,
    Inline = 2,
}

/// Parameters of [`RedirectBodySourceTag::UserBytes`].
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RedirectBodyUserBytes {
    pub offset: u64,
    pub len: u64,
}

/// Body to attach to a write redirect. `tag` selects the active
/// payload; non-active payloads carry safe defaults so dropping the
/// struct frees at most one allocation.
#[repr(C)]
#[derive(Debug)]
pub struct RedirectBodySource {
    pub tag: RedirectBodySourceTag,
    pub user_bytes: RedirectBodyUserBytes,
    pub inline: Bytes,
}

unsafe impl Send for RedirectBodySource {}

impl RedirectBodySource {
    pub fn empty() -> Self {
        Self {
            tag: RedirectBodySourceTag::Empty,
            user_bytes: RedirectBodyUserBytes { offset: 0, len: 0 },
            inline: Bytes {
                ptr: std::ptr::null_mut(),
                len: 0,
            },
        }
    }

    pub fn user_bytes(offset: u64, len: u64) -> Self {
        Self {
            tag: RedirectBodySourceTag::UserBytes,
            user_bytes: RedirectBodyUserBytes { offset, len },
            inline: Bytes {
                ptr: std::ptr::null_mut(),
                len: 0,
            },
        }
    }

    pub fn inline(bytes: Bytes) -> Self {
        Self {
            tag: RedirectBodySourceTag::Inline,
            user_bytes: RedirectBodyUserBytes { offset: 0, len: 0 },
            inline: bytes,
        }
    }
}

/// Captured-response shape for write redirects.
#[repr(C)]
#[derive(Debug)]
pub struct ResultCapture {
    pub headers: List<Str>,
    pub body_max_bytes: u32,
}

unsafe impl Send for ResultCapture {}

/// Write redirect — a pre-signed HTTP request the host follows; the
/// response is captured via [`ResultCapture`] and handed back to the
/// plugin in a [`RedirectResultBatch`].
#[repr(C)]
#[derive(Debug)]
pub struct WriteRedirect {
    pub request: HttpRequest,
    pub body_source: RedirectBodySource,
    pub result_capture: ResultCapture,
    pub expires_at_unix_ms: i64,
    pub scope: RedirectScope,
    pub audit_id: Str,
    pub policy_epoch: u64,
}

unsafe impl Send for WriteRedirect {}

/// Batch of write redirects + an opaque plugin-owned continuation
/// blob the host echoes back into `continue_write`.
#[repr(C)]
#[derive(Debug)]
pub struct WriteRedirectBatch {
    pub continuation: Bytes,
    pub redirects: List<WriteRedirect>,
}

unsafe impl Send for WriteRedirectBatch {}

/// One redirect's outcome as reported by the party that performed it.
///
/// Caller-supplied input, not an observation. That party is a redirect follower
/// inside a host stack on one route — the library deployment, and equally the
/// broker's own `write` path — or a remote client driving the redirect protocol
/// over the broker's `continue_write` RPC. Check the batch cardinality against
/// the redirect batch yourself, at the top of `continue_write`: no follower
/// route performs that check, and the RPC's own is against a count the same
/// caller supplied. That RPC is also the only place a status outside `200..300`
/// is refused; nothing else is validated, and the echoed continuation blob is
/// unauthenticated too.
///
/// The request address is the only authenticated part of the call, so **derive
/// the object you act on from it** rather than taking it from the continuation.
/// Comparing the continuation's copy against the address is weaker: on the
/// client-driven route the caller supplies both sides, presenting an address it
/// is authorized for beside a blob whose recorded copy it rewrote to match.
/// Values the address cannot supply — a server-issued session
/// handle, the preconditions of the original write — have to travel in the blob;
/// treat those as caller-chosen and do not build a guarantee another principal
/// depends on out of them.
///
/// These values may shape the result returned, and must never be evidence about
/// connection authentication, credential validity, quota, principal identity, or
/// metrics. The test: would this still be true if the caller were lying?
#[repr(C)]
#[derive(Debug)]
pub struct RedirectResult {
    pub status_code: u16,
    pub captured_headers: KeyValueList,
    pub captured_body: Bytes,
}

unsafe impl Send for RedirectResult {}

/// Cardinality-matched result batch corresponding to a
/// [`WriteRedirectBatch`].
#[repr(C)]
#[derive(Debug)]
pub struct RedirectResultBatch {
    pub results: List<RedirectResult>,
}

unsafe impl Send for RedirectResultBatch {}

// ---------------------------------------------------------------------
