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

/// Authorization scope a redirect carries.
#[repr(C)]
#[derive(Debug)]
pub struct RedirectScope {
    pub physical_url_prefix: Str,
    pub operations: AccessOps,
    pub expires_at_unix_ms: i64,
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

/// Captured result of a single redirect's HTTP response.
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
