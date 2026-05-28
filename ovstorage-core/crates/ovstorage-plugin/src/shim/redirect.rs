// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn http_request_to_ffi(value: HttpRequest) -> ffi::HttpRequest {
    let headers: std::collections::HashMap<String, String> = value.headers.into_iter().collect();
    ffi::HttpRequest {
        method: primitive::str_to_ffi(value.method),
        url: primitive::str_to_ffi(value.url),
        headers: primitive::key_value_list_to_ffi(headers),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::HttpRequest`] produced by
/// [`http_request_to_ffi`] or by an FFI counterpart.
pub unsafe fn http_request_from_ffi(value: ffi::HttpRequest) -> Result<HttpRequest, Error> {
    unsafe {
        let method_ffi = value.method;
        let url_ffi = value.url;
        let headers_ffi = value.headers;
        let method = primitive::str_from_ffi(method_ffi);
        let url = primitive::str_from_ffi(url_ffi);
        let headers = primitive::key_value_list_from_ffi(headers_ffi);
        Ok(HttpRequest {
            method: method?,
            url: url?,
            headers: headers?.into_iter().collect(),
        })
    }
}

pub fn mtime_format_to_ffi(value: MtimeFormat) -> ffi::MtimeFormat {
    match value {
        MtimeFormat::Rfc1123 => ffi::MtimeFormat::Rfc1123,
        MtimeFormat::Iso8601 => ffi::MtimeFormat::Iso8601,
        MtimeFormat::UnixSeconds => ffi::MtimeFormat::UnixSeconds,
    }
}

pub fn mtime_format_from_ffi(value: ffi::MtimeFormat) -> MtimeFormat {
    match value {
        ffi::MtimeFormat::Rfc1123 => MtimeFormat::Rfc1123,
        ffi::MtimeFormat::Iso8601 => MtimeFormat::Iso8601,
        ffi::MtimeFormat::UnixSeconds => MtimeFormat::UnixSeconds,
    }
}

pub fn response_parsing_to_ffi(value: ResponseParsing) -> ffi::ResponseParsing {
    let checksum_headers: Vec<(ChecksumAlgorithm, String)> =
        value.checksum_headers.into_iter().collect();
    ffi::ResponseParsing {
        etag_header: primitive::optional_to_ffi(value.etag_header, primitive::str_to_ffi),
        version_header: primitive::optional_to_ffi(value.version_header, primitive::str_to_ffi),
        size_header: primitive::optional_to_ffi(value.size_header, primitive::str_to_ffi),
        mtime_header: primitive::optional_to_ffi(value.mtime_header, primitive::str_to_ffi),
        mtime_format: mtime_format_to_ffi(value.mtime_format),
        system_metadata_headers: primitive::list_to_ffi(
            value.system_metadata_headers,
            primitive::str_to_ffi,
        ),
        content_checksum_header: primitive::optional_to_ffi(
            value.content_checksum_header,
            primitive::str_to_ffi,
        ),
        content_checksum_algorithm: primitive::optional_to_ffi(
            value.content_checksum_algorithm,
            metadata::checksum_algorithm_to_ffi,
        ),
        checksum_headers: primitive::list_to_ffi(checksum_headers, |(algorithm, header)| {
            ffi::ChecksumHeaderBinding {
                algorithm: metadata::checksum_algorithm_to_ffi(algorithm),
                header: primitive::str_to_ffi(header),
            }
        }),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ResponseParsing`] produced by
/// [`response_parsing_to_ffi`] or by an FFI counterpart.
pub unsafe fn response_parsing_from_ffi(
    value: ffi::ResponseParsing,
) -> Result<ResponseParsing, Error> {
    unsafe {
        let etag_ffi = value.etag_header;
        let version_ffi = value.version_header;
        let size_ffi = value.size_header;
        let mtime_ffi = value.mtime_header;
        let mtime_format = mtime_format_from_ffi(value.mtime_format);
        let system_headers_ffi = value.system_metadata_headers;
        let content_checksum_header_ffi = value.content_checksum_header;
        let content_checksum_algorithm_ffi = value.content_checksum_algorithm;
        let checksum_headers_ffi = value.checksum_headers;

        let etag = primitive::optional_from_ffi(etag_ffi, |s| primitive::str_from_ffi(s));
        let version = primitive::optional_from_ffi(version_ffi, |s| primitive::str_from_ffi(s));
        let size = primitive::optional_from_ffi(size_ffi, |s| primitive::str_from_ffi(s));
        let mtime = primitive::optional_from_ffi(mtime_ffi, |s| primitive::str_from_ffi(s));
        let system_metadata_headers =
            primitive::list_from_ffi(system_headers_ffi, |s| primitive::str_from_ffi(s));
        let content_checksum_header =
            primitive::optional_from_ffi(content_checksum_header_ffi, |s| {
                primitive::str_from_ffi(s)
            });
        let content_checksum_algorithm =
            primitive::optional_from_ffi(content_checksum_algorithm_ffi, |a| {
                metadata::checksum_algorithm_from_ffi(a)
            });
        let checksum_headers_pairs = primitive::list_from_ffi(checksum_headers_ffi, |entry| {
            let algorithm = metadata::checksum_algorithm_from_ffi(entry.algorithm)?;
            let header = primitive::str_from_ffi(entry.header)?;
            Ok::<_, Error>((algorithm, header))
        });

        Ok(ResponseParsing {
            etag_header: etag?,
            version_header: version?,
            size_header: size?,
            mtime_header: mtime?,
            mtime_format,
            system_metadata_headers: system_metadata_headers?,
            content_checksum_header: content_checksum_header?,
            content_checksum_algorithm: content_checksum_algorithm?,
            checksum_headers: checksum_headers_pairs?.into_iter().collect(),
        })
    }
}

pub fn redirect_scope_to_ffi(value: RedirectScope) -> ffi::RedirectScope {
    ffi::RedirectScope {
        physical_url_prefix: primitive::str_to_ffi(value.physical_url_prefix),
        operations: access::access_ops_to_ffi(value.operations),
        expires_at_unix_ms: primitive::system_time_to_unix_ms(value.expires_at),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::RedirectScope`] produced by
/// [`redirect_scope_to_ffi`] or by an FFI counterpart.
pub unsafe fn redirect_scope_from_ffi(value: ffi::RedirectScope) -> Result<RedirectScope, Error> {
    unsafe {
        let prefix_ffi = value.physical_url_prefix;
        let operations = access::access_ops_from_ffi(value.operations);
        let expires_at = primitive::system_time_from_unix_ms(value.expires_at_unix_ms);
        let physical_url_prefix = primitive::str_from_ffi(prefix_ffi)?;
        Ok(RedirectScope {
            physical_url_prefix,
            operations,
            expires_at,
        })
    }
}

pub fn read_redirect_to_ffi(value: ReadRedirect) -> ffi::ReadRedirect {
    ffi::ReadRedirect {
        request: http_request_to_ffi(value.request),
        response_parsing: response_parsing_to_ffi(value.response_parsing),
        expires_at_unix_ms: primitive::system_time_to_unix_ms(value.expires_at),
        scope: redirect_scope_to_ffi(value.scope),
        audit_id: primitive::str_to_ffi(value.audit_id),
        policy_epoch: value.policy_epoch,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ReadRedirect`] produced by
/// [`read_redirect_to_ffi`] or by an FFI counterpart.
pub unsafe fn read_redirect_from_ffi(value: ffi::ReadRedirect) -> Result<ReadRedirect, Error> {
    unsafe {
        let request_ffi = value.request;
        let parsing_ffi = value.response_parsing;
        let scope_ffi = value.scope;
        let audit_id_ffi = value.audit_id;
        let expires_at = primitive::system_time_from_unix_ms(value.expires_at_unix_ms);
        let policy_epoch = value.policy_epoch;

        let request = http_request_from_ffi(request_ffi);
        let response_parsing = response_parsing_from_ffi(parsing_ffi);
        let scope = redirect_scope_from_ffi(scope_ffi);
        let audit_id = primitive::str_from_ffi(audit_id_ffi);

        Ok(ReadRedirect {
            request: request?,
            response_parsing: response_parsing?,
            expires_at,
            scope: scope?,
            audit_id: audit_id?,
            policy_epoch,
        })
    }
}

pub fn redirect_body_source_to_ffi(value: RedirectBodySource) -> ffi::RedirectBodySource {
    match value {
        RedirectBodySource::Empty => ffi::RedirectBodySource::empty(),
        RedirectBodySource::UserBytes { offset, len } => {
            ffi::RedirectBodySource::user_bytes(offset, len)
        }
        RedirectBodySource::Inline(bytes) => {
            ffi::RedirectBodySource::inline(primitive::bytes_to_ffi(bytes))
        }
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::RedirectBodySource`] produced by
/// [`redirect_body_source_to_ffi`] or by an FFI counterpart.
pub unsafe fn redirect_body_source_from_ffi(
    value: ffi::RedirectBodySource,
) -> Result<RedirectBodySource, Error> {
    unsafe {
        match value.tag {
            ffi::RedirectBodySourceTag::Empty => {
                // Inline carries `Bytes { ptr: null, len: 0 }`; its
                // Drop is a no-op. Letting `value` drop releases
                // nothing.
                Ok(RedirectBodySource::Empty)
            }
            ffi::RedirectBodySourceTag::UserBytes => {
                let offset = value.user_bytes.offset;
                let len = value.user_bytes.len;
                Ok(RedirectBodySource::UserBytes { offset, len })
            }
            ffi::RedirectBodySourceTag::Inline => {
                // Move `inline` out so its allocation stays alive
                // while we copy the bytes; `bytes_from_ffi` releases
                // it and returns a Rust `Vec<u8>`.
                let bytes_ffi = std::ptr::read(&value.inline as *const _);
                std::mem::forget(value);
                Ok(RedirectBodySource::Inline(primitive::bytes_from_ffi(
                    bytes_ffi,
                )))
            }
        }
    }
}

pub fn result_capture_to_ffi(value: ResultCapture) -> ffi::ResultCapture {
    ffi::ResultCapture {
        headers: primitive::list_to_ffi(value.headers, primitive::str_to_ffi),
        body_max_bytes: value.body_max_bytes,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::ResultCapture`] produced by
/// [`result_capture_to_ffi`] or by an FFI counterpart.
pub unsafe fn result_capture_from_ffi(value: ffi::ResultCapture) -> Result<ResultCapture, Error> {
    unsafe {
        let headers_ffi = value.headers;
        let body_max_bytes = value.body_max_bytes;
        let headers = primitive::list_from_ffi(headers_ffi, |s| primitive::str_from_ffi(s))?;
        Ok(ResultCapture {
            headers,
            body_max_bytes,
        })
    }
}

pub fn write_redirect_to_ffi(value: WriteRedirect) -> ffi::WriteRedirect {
    ffi::WriteRedirect {
        request: http_request_to_ffi(value.request),
        body_source: redirect_body_source_to_ffi(value.body_source),
        result_capture: result_capture_to_ffi(value.result_capture),
        expires_at_unix_ms: primitive::system_time_to_unix_ms(value.expires_at),
        scope: redirect_scope_to_ffi(value.scope),
        audit_id: primitive::str_to_ffi(value.audit_id),
        policy_epoch: value.policy_epoch,
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WriteRedirect`] produced by
/// [`write_redirect_to_ffi`] or by an FFI counterpart.
pub unsafe fn write_redirect_from_ffi(value: ffi::WriteRedirect) -> Result<WriteRedirect, Error> {
    unsafe {
        let request_ffi = value.request;
        let body_source_ffi = value.body_source;
        let result_capture_ffi = value.result_capture;
        let expires_at = primitive::system_time_from_unix_ms(value.expires_at_unix_ms);
        let scope_ffi = value.scope;
        let audit_id_ffi = value.audit_id;
        let policy_epoch = value.policy_epoch;

        let request = http_request_from_ffi(request_ffi);
        let body_source = redirect_body_source_from_ffi(body_source_ffi);
        let result_capture = result_capture_from_ffi(result_capture_ffi);
        let scope = redirect_scope_from_ffi(scope_ffi);
        let audit_id = primitive::str_from_ffi(audit_id_ffi);

        Ok(WriteRedirect {
            request: request?,
            body_source: body_source?,
            result_capture: result_capture?,
            expires_at,
            scope: scope?,
            audit_id: audit_id?,
            policy_epoch,
        })
    }
}

pub fn write_redirect_batch_to_ffi(value: WriteRedirectBatch) -> ffi::WriteRedirectBatch {
    ffi::WriteRedirectBatch {
        continuation: primitive::bytes_to_ffi(value.continuation),
        redirects: primitive::list_to_ffi(value.redirects, write_redirect_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WriteRedirectBatch`] produced
/// by [`write_redirect_batch_to_ffi`] or by an FFI counterpart.
pub unsafe fn write_redirect_batch_from_ffi(
    value: ffi::WriteRedirectBatch,
) -> Result<WriteRedirectBatch, Error> {
    unsafe {
        let continuation_ffi = value.continuation;
        let redirects_ffi = value.redirects;
        let continuation = primitive::bytes_from_ffi(continuation_ffi);
        let redirects = primitive::list_from_ffi(redirects_ffi, |r| write_redirect_from_ffi(r))?;
        Ok(WriteRedirectBatch {
            continuation,
            redirects,
        })
    }
}

pub fn redirect_result_to_ffi(value: RedirectResult) -> ffi::RedirectResult {
    let headers: std::collections::HashMap<String, String> =
        value.captured_headers.into_iter().collect();
    ffi::RedirectResult {
        status_code: value.status_code,
        captured_headers: primitive::key_value_list_to_ffi(headers),
        captured_body: primitive::bytes_to_ffi(value.captured_body),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::RedirectResult`] produced by
/// [`redirect_result_to_ffi`] or by an FFI counterpart.
pub unsafe fn redirect_result_from_ffi(
    value: ffi::RedirectResult,
) -> Result<RedirectResult, Error> {
    unsafe {
        let status_code = value.status_code;
        let headers_ffi = value.captured_headers;
        let body_ffi = value.captured_body;
        let captured_headers = primitive::key_value_list_from_ffi(headers_ffi)?;
        let captured_body = primitive::bytes_from_ffi(body_ffi);
        Ok(RedirectResult {
            status_code,
            captured_headers: captured_headers.into_iter().collect(),
            captured_body,
        })
    }
}

pub fn redirect_result_batch_to_ffi(value: RedirectResultBatch) -> ffi::RedirectResultBatch {
    ffi::RedirectResultBatch {
        results: primitive::list_to_ffi(value.results, redirect_result_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::RedirectResultBatch`] produced
/// by [`redirect_result_batch_to_ffi`] or by an FFI counterpart.
pub unsafe fn redirect_result_batch_from_ffi(
    value: ffi::RedirectResultBatch,
) -> Result<RedirectResultBatch, Error> {
    unsafe {
        let results = primitive::list_from_ffi(value.results, |r| redirect_result_from_ffi(r))?;
        Ok(RedirectResultBatch { results })
    }
}
