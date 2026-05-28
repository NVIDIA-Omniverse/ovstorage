// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) struct FollowedReadRedirect {
    pub(crate) bytes: Vec<u8>,
    pub(crate) info: ObjectInfo,
}

/// Render a `ByteRange` as an HTTP `Range:` header value.
/// `bytes=N-M` for a closed range; `bytes=N-` (open-ended) when
/// `end_inclusive` is `None`. Both forms are RFC 7233 compliant.
fn format_range_header(range: &ByteRange) -> String {
    match range.end_inclusive {
        Some(end) => format!("bytes={}-{}", range.start, end),
        None => format!("bytes={}-", range.start),
    }
}

/// Produce a copy of `base` with a `Range:` header appended. Used by
/// the non-streaming follower whose helper takes `&HttpRequest`.
fn http_request_with_range(base: &HttpRequest, range: &ByteRange) -> HttpRequest {
    let mut headers = base.headers.clone();
    headers.push(("Range".to_string(), format_range_header(range)));
    HttpRequest {
        method: base.method.clone(),
        url: base.url.clone(),
        headers,
    }
}

/// Reject an inverted range (`end_inclusive < start`) — both
/// buffered and streaming slice paths need this guard before they
/// compute byte indices, otherwise the slice would panic and (under
/// the workspace's panic-abort policy) terminate the process.
fn validate_range(range: &ByteRange) -> Result<()> {
    if let Some(end) = range.end_inclusive
        && end < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "range end_inclusive {} is less than start {}",
                end, range.start,
            ),
        ));
    }
    Ok(())
}

/// Slice a 200-OK full body down to the requested range. Used when
/// the origin returned the whole object instead of `206 Partial
/// Content` — e.g. `bytes=0-1000` against a 100-byte object is a
/// legitimate 200 + full-body response.
///
/// Returns `InvalidArgument` for an inverted range (`end < start`)
/// or a start beyond the body. Open-ended ranges (`bytes=N-`) take
/// the tail from `N` to end-of-body.
fn slice_full_body(body: &[u8], range: &ByteRange) -> Result<Vec<u8>> {
    validate_range(range)?;
    let start = range.start as usize;
    if start > body.len() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "range start {} beyond response body length {}",
                range.start,
                body.len(),
            ),
        ));
    }
    let end_exclusive = range
        .end_inclusive
        .map(|e| (e as usize).saturating_add(1).min(body.len()))
        .unwrap_or(body.len());
    Ok(body[start..end_exclusive].to_vec())
}

/// Wrap a `ReadStream` so it yields only the bytes in `range`. Used
/// when the origin responded 200-with-full-body to a Range request:
/// the network already streams the full object, but we drop bytes
/// outside the slice before they reach the caller. The wrapper stops
/// pulling from the underlying stream as soon as the slice is
/// satisfied — dropping the stream cancels the network transfer.
fn range_filter_stream(
    inner: ovstorage_plugin::ReadStream,
    range: ByteRange,
) -> ovstorage_plugin::ReadStream {
    let start = range.start;
    let end_exclusive = range
        .end_inclusive
        .map(|e| e.saturating_add(1))
        .unwrap_or(u64::MAX);
    // INVARIANT: callers (the redirect followers) call
    // `validate_range` before getting here, so
    // `end_exclusive >= start`. The slice indices below depend on
    // that — we add a debug_assert at the slice site as a belt.

    // State: `Some((stream, consumed))` while live, `None` after a
    // terminal frame (Err or stream end past `end_exclusive`).
    let state = Some((inner, 0u64));
    let stream = futures::stream::unfold(state, move |state| async move {
        let (mut inner, mut consumed) = state?;
        loop {
            if consumed >= end_exclusive {
                return None;
            }
            use futures::StreamExt;
            match inner.next().await {
                None => {
                    // End of upstream. If `start > consumed`, the
                    // caller's range starts past EOF — match the
                    // buffered path's behavior and surface an error
                    // rather than silently yielding an empty stream.
                    if start > consumed {
                        return Some((
                            Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "range start {start} beyond response body length {consumed}",
                                ),
                            )),
                            None,
                        ));
                    }
                    return None;
                }
                Some(Err(err)) => return Some((Err(err), None)),
                Some(Ok(chunk)) => {
                    let chunk_len = chunk.len() as u64;
                    let chunk_start = consumed;
                    let chunk_end = consumed + chunk_len;
                    consumed = chunk_end;
                    // Chunk lies entirely before the range start.
                    if chunk_end <= start {
                        continue;
                    }
                    let lo = if chunk_start < start {
                        (start - chunk_start) as usize
                    } else {
                        0
                    };
                    let hi = if chunk_end > end_exclusive {
                        (chunk_len - (chunk_end - end_exclusive)) as usize
                    } else {
                        chunk_len as usize
                    };
                    debug_assert!(
                        lo <= hi,
                        "lo={lo} hi={hi} chunk_len={chunk_len} start={start} end_exclusive={end_exclusive}: \
                         caller bypassed `validate_range`?",
                    );
                    let sliced = chunk.slice(lo..hi);
                    return Some((Ok(sliced), Some((inner, consumed))));
                }
            }
        }
    });
    Box::pin(stream)
}

pub(crate) async fn follow_read_redirect(
    address: Url,
    redirect: &ReadRedirect,
    retry_cfg: &retry::RetryConfig,
    if_match_was_set: bool,
    range: Option<&ByteRange>,
) -> Result<FollowedReadRedirect> {
    if let Some(r) = range {
        validate_range(r)?;
    }
    ensure_redirect_fresh(redirect.expires_at)?;
    let request_with_range = range.map(|r| http_request_with_range(&redirect.request, r));
    let request: &HttpRequest = request_with_range.as_ref().unwrap_or(&redirect.request);
    let result = execute_redirect_request_with_retry(request, &[], retry_cfg).await?;
    if (200..300).contains(&result.status_code) {
        let mut verifier =
            StreamingVerifier::for_response(&redirect.response_parsing, &result.captured_headers);
        verifier.update(&result.captured_body);
        verifier.finalize()?;
        let info = redirect_info_from_result(address, &redirect.response_parsing, &result);
        // 206: origin honored the Range; body IS the slice.
        // 200: origin returned the full body (either it ignored
        // Range, or the requested range covers the whole object —
        // e.g. `bytes=0-1000` on a 100-byte object is legitimately
        // answered with 200 + full body). Slice client-side so the
        // caller gets exactly what they asked for.
        let bytes = if let Some(range) = range
            && result.status_code != 206
        {
            slice_full_body(&result.captured_body, range)?
        } else {
            result.captured_body
        };
        Ok(FollowedReadRedirect { bytes, info })
    } else {
        Err(map_redirect_read_status(
            result.status_code,
            &result.captured_headers,
            if_match_was_set,
        ))
    }
}

pub(crate) struct StreamedReadRedirect {
    pub(crate) stream: ovstorage_plugin::ReadStream,
    pub(crate) info: ObjectInfo,
}

/// Streaming counterpart to [`follow_read_redirect`]. Pulls bytes from
/// `reqwest::Response::bytes_stream()` without materializing the body.
/// HTTP retries do not apply once `bytes_stream()` is open — replay is
/// impossible mid-stream.
pub(crate) async fn follow_read_redirect_streaming(
    address: Url,
    redirect: &ReadRedirect,
    if_match_was_set: bool,
    range: Option<&ByteRange>,
) -> Result<StreamedReadRedirect> {
    if let Some(r) = range {
        validate_range(r)?;
    }
    ensure_redirect_fresh(redirect.expires_at)?;
    let url = url::Url::parse(&redirect.request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!("streaming redirect scheme '{scheme}' is not supported"),
            ));
        }
    }
    let method =
        reqwest::Method::from_bytes(redirect.request.method.as_bytes()).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("redirect HTTP method is invalid: {error}"),
            )
        })?;
    let mut builder = redirect_client().request(method, &redirect.request.url);
    for (name, value) in &redirect.request.headers {
        builder = builder.header(name, value);
    }
    if let Some(range) = range {
        builder = builder.header("Range", format_range_header(range));
    }
    let response = builder
        .send()
        .await
        .map_err(|error| Error::new(ErrorCode::Transient, error.to_string()))?;
    let status = response.status();
    let captured_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    if !status.is_success() {
        return Err(map_redirect_read_status(
            status.as_u16(),
            &captured_headers,
            if_match_was_set,
        ));
    }
    // Whether the origin honored Range with 206 or returned 200 with
    // the full body, we'll slice client-side below for the 200 case.
    let needs_client_side_range_filter = range.is_some() && status.as_u16() != 206;
    // Verifier travels into the streaming task without pinning the
    // response.
    let verifier = StreamingVerifier::for_response(&redirect.response_parsing, &captured_headers);
    // Size comes from Content-Length (or stays None for chunked).
    let mut header_only_result = RedirectResult {
        status_code: status.as_u16(),
        captured_headers,
        captured_body: Vec::new(),
    };
    let info = redirect_info_from_result(address, &redirect.response_parsing, &header_only_result);
    header_only_result.captured_headers.clear();

    let stream = bytes_stream_to_read_stream(response, verifier);
    let stream = if needs_client_side_range_filter {
        // Origin returned 200 with the full body (or a 2xx other than
        // 206). Clip the stream to the requested range so the caller
        // gets exactly what they asked for. The wrapper stops pulling
        // from the underlying response once it has filled the slice,
        // which cancels the network transfer.
        range_filter_stream(stream, range.cloned().expect("range is_some checked above"))
    } else {
        stream
    };
    Ok(StreamedReadRedirect { stream, info })
}

/// `verifier` runs INCREMENTALLY: each chunk is hashed before yield,
/// never accumulated. Mismatch surfaces as a final
/// `Err(ContentChecksumMismatch)` frame; arbitrary-sized objects
/// verify with bounded host memory.
fn bytes_stream_to_read_stream(
    response: reqwest::Response,
    verifier: StreamingVerifier,
) -> ovstorage_plugin::ReadStream {
    use futures::StreamExt;
    let stream = async_stream::stream! {
        let mut verifier = verifier;
        let mut response_stream = response.bytes_stream();
        while let Some(item) = response_stream.next().await {
            match item {
                Ok(bytes) => {
                    verifier.update(&bytes);
                    yield Ok(bytes);
                }
                Err(err) => {
                    yield Err(Error::new(ErrorCode::Transient, err.to_string()));
                    return;
                }
            }
        }
        if let Err(err) = verifier.finalize() {
            yield Err(err);
        }
    };
    Box::pin(stream)
}

/// Streaming wire-integrity verifier. Active when the parsing hint
/// names a header + supported algorithm AND the response carries a
/// parseable expected-value header; otherwise `Inactive`
/// (pass-through). Never accumulates chunk payloads.
pub(crate) enum StreamingVerifier {
    Inactive,
    Sha256 {
        hasher: sha2::Sha256,
        expected: Vec<u8>,
    },
    Md5 {
        hasher: md5::Md5,
        expected: Vec<u8>,
    },
    /// Castagnoli CRC32C (polynomial 0x1EDC6F41); `expected` is the
    /// 4 big-endian wire bytes.
    Crc32c {
        state: u32,
        expected: Vec<u8>,
    },
}

impl StreamingVerifier {
    pub(crate) fn for_response(parsing: &ResponseParsing, headers: &[(String, String)]) -> Self {
        let Some(header_name) = parsing.content_checksum_header.as_deref() else {
            return Self::Inactive;
        };
        let Some(algorithm) = parsing.content_checksum_algorithm.as_ref() else {
            return Self::Inactive;
        };
        // GCS `x-goog-hash` is a multi-value composite tagged
        // `crc32c=<b64>` / `md5=<b64>`; need a tag-aware extractor.
        let raw_owned: Option<String> = if header_name.eq_ignore_ascii_case("x-goog-hash") {
            extract_x_goog_hash(headers, algorithm.as_str())
        } else {
            header_value(headers, Some(header_name)).map(str::to_string)
        };
        let Some(raw) = raw_owned else {
            return Self::Inactive;
        };
        match algorithm.as_str() {
            "sha256" => {
                use sha2::Digest;
                let Some(expected) = parse_checksum_value(&raw, 32) else {
                    return Self::Inactive;
                };
                Self::Sha256 {
                    hasher: sha2::Sha256::new(),
                    expected,
                }
            }
            "md5" => {
                use md5::Digest;
                // Cloud convention is base64; bias parser that way.
                let Some(expected) = parse_short_checksum_value(&raw, 16) else {
                    return Self::Inactive;
                };
                Self::Md5 {
                    hasher: md5::Md5::new(),
                    expected,
                }
            }
            "crc32c" => {
                // Wire convention is base64 of 4 big-endian bytes;
                // `parse_short_checksum_value` tries base64 first.
                let Some(expected) = parse_short_checksum_value(&raw, 4) else {
                    return Self::Inactive;
                };
                Self::Crc32c { state: 0, expected }
            }
            _ => Self::Inactive,
        }
    }

    pub(crate) fn update(&mut self, chunk: &[u8]) {
        match self {
            Self::Inactive => {}
            Self::Sha256 { hasher, .. } => {
                use sha2::Digest;
                hasher.update(chunk);
            }
            Self::Md5 { hasher, .. } => {
                use md5::Digest;
                hasher.update(chunk);
            }
            Self::Crc32c { state, .. } => {
                *state = crc32c::crc32c_append(*state, chunk);
            }
        }
    }

    pub(crate) fn finalize(self) -> Result<()> {
        match self {
            Self::Inactive => Ok(()),
            Self::Sha256 { hasher, expected } => {
                use sha2::Digest;
                let actual = hasher.finalize();
                if actual.as_slice() == expected.as_slice() {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorCode::ContentChecksumMismatch,
                        "streamed body sha256 did not match the upstream content-checksum header",
                    ))
                }
            }
            Self::Md5 { hasher, expected } => {
                use md5::Digest;
                let actual = hasher.finalize();
                if actual.as_slice() == expected.as_slice() {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorCode::ContentChecksumMismatch,
                        "streamed body md5 did not match the upstream content-checksum header",
                    ))
                }
            }
            Self::Crc32c { state, expected } => {
                let actual = state.to_be_bytes();
                if actual.as_slice() == expected.as_slice() {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorCode::ContentChecksumMismatch,
                        "streamed body crc32c did not match the upstream content-checksum header",
                    ))
                }
            }
        }
    }
}

/// Walk every `x-goog-hash` header (GCS sends one or many, comma-
/// separated or repeated) and return the first `<algorithm>=<value>`.
pub(crate) fn extract_x_goog_hash(headers: &[(String, String)], algorithm: &str) -> Option<String> {
    let prefix = format!("{algorithm}=");
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("x-goog-hash") {
            continue;
        }
        for item in value.split(',') {
            let trimmed = item.trim();
            if let Some(rest) = trimmed.strip_prefix(&prefix) {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// Base64-first variant; used for crc32c (4) and md5 (16) where wire
/// convention is base64 and hex-of-half-length would collide. SHA-256
/// stays hex-first (32 bytes → 64 hex vs. 44 base64, unambiguous).
pub(crate) fn parse_short_checksum_value(raw: &str, expected_len: usize) -> Option<Vec<u8>> {
    let trimmed = raw.trim().trim_matches('"');
    if let Some(bytes) = decode_base64(trimmed)
        && bytes.len() == expected_len
    {
        return Some(bytes);
    }
    if let Some(bytes) = decode_hex(trimmed)
        && bytes.len() == expected_len
    {
        return Some(bytes);
    }
    if trimmed.len() == expected_len {
        return Some(trimmed.as_bytes().to_vec());
    }
    None
}

/// Try hex, then base64 (standard + URL-safe), then raw bytes. First
/// decode whose length matches `expected_len` wins. None on no match;
/// callers degrade to pass-through.
pub(crate) fn parse_checksum_value(raw: &str, expected_len: usize) -> Option<Vec<u8>> {
    let trimmed = raw.trim().trim_matches('"');
    if let Some(bytes) = decode_hex(trimmed)
        && bytes.len() == expected_len
    {
        return Some(bytes);
    }
    if let Some(bytes) = decode_base64(trimmed)
        && bytes.len() == expected_len
    {
        return Some(bytes);
    }
    if trimmed.len() == expected_len {
        return Some(trimmed.as_bytes().to_vec());
    }
    None
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Accepts both `+/` and `-_` alphabets; padding optional.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 1);
    for &b in input.as_bytes() {
        let v: u32 = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

pub(crate) enum WriteBody {
    Buffered(Vec<u8>),
    Stream(BodyStream),
}

pub(crate) async fn write_body_from(body: Body) -> Result<WriteBody> {
    match body {
        Body::Bytes(b) => Ok(WriteBody::Buffered(b)),
        // Open as a stream rather than draining the file to a Vec: a
        // multi-GB upload would otherwise OOM the gateway when redirected.
        Body::LocalFile(p) => Ok(WriteBody::Stream(body_stream_from_file(&p)?)),
        Body::Stream(s) => Ok(WriteBody::Stream(s)),
    }
}

pub(crate) async fn follow_write_redirects(
    body: WriteBody,
    batch: &WriteRedirectBatch,
    retry_cfg: &retry::RetryConfig,
) -> Result<RedirectResultBatch> {
    match body {
        WriteBody::Buffered(bytes) => {
            follow_buffered_write_redirects(&bytes, batch, retry_cfg).await
        }
        WriteBody::Stream(stream) => follow_streaming_write_redirects(stream, batch).await,
    }
}

async fn follow_buffered_write_redirects(
    body: &[u8],
    batch: &WriteRedirectBatch,
    retry_cfg: &retry::RetryConfig,
) -> Result<RedirectResultBatch> {
    let mut results = Vec::with_capacity(batch.redirects.len());
    for redirect in &batch.redirects {
        ensure_redirect_fresh(redirect.expires_at)?;
        let request_body = redirect_body_bytes(body, &redirect.body_source)?;
        // Buffered bodies are replayable; the inner helper short-
        // circuits non-idempotent verbs.
        let result =
            execute_redirect_request_with_retry(&redirect.request, &request_body, retry_cfg)
                .await?;
        results.push(capture_redirect_result(result, &redirect.result_capture));
    }
    Ok(RedirectResultBatch { results })
}

/// Drive a `Body::Stream` through a write-redirect batch. UserBytes
/// processed in offset order. Single-redirect batches stream
/// chunk-by-chunk; multi-redirect batches drain `len` bytes per part.
async fn follow_streaming_write_redirects(
    mut stream: BodyStream,
    batch: &WriteRedirectBatch,
) -> Result<RedirectResultBatch> {
    if batch.redirects.is_empty() {
        return Ok(RedirectResultBatch {
            results: Vec::new(),
        });
    }

    if batch.redirects.len() == 1 {
        let redirect = &batch.redirects[0];
        ensure_redirect_fresh(redirect.expires_at)?;
        match &redirect.body_source {
            RedirectBodySource::Empty => {
                let result = execute_redirect_request(&redirect.request, &[]).await?;
                return Ok(RedirectResultBatch {
                    results: vec![capture_redirect_result(result, &redirect.result_capture)],
                });
            }
            RedirectBodySource::Inline(bytes) => {
                let result = execute_redirect_request(&redirect.request, bytes).await?;
                return Ok(RedirectResultBatch {
                    results: vec![capture_redirect_result(result, &redirect.result_capture)],
                });
            }
            RedirectBodySource::UserBytes { offset, len } => {
                if *offset != 0 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "single-redirect stream UserBytes must start at offset 0",
                    ));
                }
                let bounded = bounded_body_stream(stream, *len);
                let result = execute_streaming_request(&redirect.request, bounded).await?;
                return Ok(RedirectResultBatch {
                    results: vec![capture_redirect_result(result, &redirect.result_capture)],
                });
            }
        }
    }

    // Multipart: drain per part, send buffered. Monotonic offsets
    // required — gaps/rewinds are plugin contract violations.
    let mut cursor: u64 = 0;
    let mut results = Vec::with_capacity(batch.redirects.len());
    for redirect in &batch.redirects {
        ensure_redirect_fresh(redirect.expires_at)?;
        let chunk = match &redirect.body_source {
            RedirectBodySource::Empty => Vec::new(),
            RedirectBodySource::Inline(bytes) => bytes.clone(),
            RedirectBodySource::UserBytes { offset, len } => {
                if *offset != cursor {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "multipart stream redirects must be in offset order \
                             (cursor={cursor}, redirect.offset={offset}); streams \
                             cannot be rewound"
                        ),
                    ));
                }
                let (buf, returned) = read_n_from_stream(stream, *len).await?;
                stream = returned;
                cursor += buf.len() as u64;
                buf
            }
        };
        let result = execute_redirect_request(&redirect.request, &chunk).await?;
        results.push(capture_redirect_result(result, &redirect.result_capture));
    }
    Ok(RedirectResultBatch { results })
}

/// Drains `len` bytes from a synchronous `BodyStream` iterator on the
/// blocking pool so the caller's tokio worker stays free for other
/// tasks. The iterator may itself bridge from a sync mpsc (e.g. the
/// REST + broker write paths feed `BodyStream` from `std::sync::mpsc::
/// Receiver::recv`); running `recv` directly on a tokio worker would
/// park it for the duration of each chunk pull. `spawn_blocking` is
/// the right tool: tokio's blocking pool has a separate thread pool,
/// so `recv` blocks one of those instead of an async worker.
async fn read_n_from_stream(stream: BodyStream, len: u64) -> Result<(Vec<u8>, BodyStream)> {
    let target = len as usize;
    let cap = len.min(64 * 1024 * 1024) as usize;
    tokio::task::spawn_blocking(move || {
        let mut buf = Vec::with_capacity(cap);
        let mut s = stream;
        while buf.len() < target {
            let Some(chunk) = s.next_chunk() else {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "stream ended after {} bytes; redirect requested {}",
                        buf.len(),
                        target
                    ),
                ));
            };
            let chunk = chunk?;
            let needed = target - buf.len();
            if chunk.len() <= needed {
                buf.extend_from_slice(&chunk);
            } else {
                buf.extend_from_slice(&chunk[..needed]);
                // Excess can't be pushed back into the stream.
                return Err(Error::new(
                    ErrorCode::Internal,
                    "stream chunk straddles a multipart redirect boundary; \
                     plugin must size chunks to align with redirect part sizes",
                ));
            }
        }
        Ok((buf, s))
    })
    .await
    .map_err(|err| Error::new(ErrorCode::Internal, err.to_string()))?
}

/// Forwards exactly `len` bytes. EOF before `len` →
/// `InvalidArgument`; chunk straddling boundary → `Internal`.
fn bounded_body_stream(stream: BodyStream, len: u64) -> BodyStream {
    let target = len;
    let mut produced: u64 = 0;
    let mut inner = stream;
    let mut done = false;
    BodyStream::from_iter(std::iter::from_fn(move || {
        if done {
            return None;
        }
        if produced >= target {
            done = true;
            return None;
        }
        let chunk = match inner.next_chunk() {
            Some(Ok(bytes)) => bytes,
            Some(Err(err)) => {
                done = true;
                return Some(Err(err));
            }
            None => {
                done = true;
                return Some(Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("stream ended after {produced} bytes; redirect requested {target}"),
                )));
            }
        };
        let remaining = target - produced;
        let chunk_len = chunk.len() as u64;
        if chunk_len > remaining {
            done = true;
            return Some(Err(Error::new(
                ErrorCode::Internal,
                "stream chunk straddles the redirect length boundary; \
                 plugin must size chunks to align with redirect length",
            )));
        }
        produced += chunk_len;
        Some(Ok(chunk))
    }))
}

/// 408 / 429 / 500 / 502 / 503 / 504.
fn http_status_is_retryable(status: u16) -> bool {
    matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
}

/// HTTP status surfaced after redirect-follow exhausts retries. 412 carries
/// `ObjectModified` when the read carried `if_match`; bare 412s (no caller
/// precondition) surface as `PreconditionFailed`.
pub(crate) fn map_redirect_read_status(
    status: u16,
    headers: &[(String, String)],
    if_match_was_set: bool,
) -> Error {
    let body = format!("redirect read returned HTTP {status}");
    let code = match status {
        401 => ErrorCode::AuthRequired,
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        408 | 504 => ErrorCode::DeadlineExceeded,
        412 if if_match_was_set => ErrorCode::ObjectModified,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        429 | 503 => ErrorCode::ResourceExhausted,
        500 | 502 => ErrorCode::Transient,
        _ => ErrorCode::Transient,
    };
    let _ = headers;
    Error::new(code, body)
}

/// Non-idempotent verbs pass through without retry.
fn http_method_is_idempotent(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS"
    )
}

/// Retries idempotent methods on `Transient` + retryable HTTP statuses;
/// honors a `Retry-After` header (seconds) for the next delay.
async fn execute_redirect_request_with_retry(
    request: &HttpRequest,
    body: &[u8],
    retry_cfg: &retry::RetryConfig,
) -> Result<RedirectResult> {
    if !http_method_is_idempotent(&request.method) {
        return execute_redirect_request(request, body).await;
    }
    retry::with_http_retry_async(retry_cfg, |_attempt| async {
        match execute_redirect_request(request, body).await {
            Ok(result) if http_status_is_retryable(result.status_code) => {
                let hint = retry_after_seconds(&result.captured_headers)
                    .map(std::time::Duration::from_secs);
                retry::RetryStep::RetryAfter(
                    Error::new(
                        ErrorCode::Transient,
                        format!("redirect returned HTTP {} (retryable)", result.status_code),
                    ),
                    hint,
                )
            }
            Ok(result) => retry::RetryStep::Done(result),
            Err(error) if retry::is_retryable(error.code()) => {
                retry::RetryStep::RetryAfter(error, None)
            }
            Err(error) => retry::RetryStep::Failed(error),
        }
    })
    .await
}

fn retry_after_seconds(headers: &[(String, String)]) -> Option<u64> {
    header_value(headers, Some("retry-after"))?
        .trim()
        .parse::<u64>()
        .ok()
}

pub(crate) fn capture_redirect_result(
    mut result: RedirectResult,
    capture: &ResultCapture,
) -> RedirectResult {
    if !capture.headers.is_empty() {
        result.captured_headers.retain(|(name, _)| {
            capture
                .headers
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(name))
        });
    }
    let max = capture.body_max_bytes as usize;
    if max == 0 {
        result.captured_body.clear();
    } else if result.captured_body.len() > max {
        result.captured_body.truncate(max);
    }
    result
}

pub(crate) fn ensure_redirect_fresh(expires_at: SystemTime) -> Result<()> {
    if expires_at <= SystemTime::now() {
        return Err(Error::new(
            ErrorCode::RedirectExpired,
            "redirect expired before it could be followed",
        ));
    }
    Ok(())
}

pub(crate) fn redirect_body_bytes(body: &[u8], source: &RedirectBodySource) -> Result<Vec<u8>> {
    match source {
        RedirectBodySource::Empty => Ok(Vec::new()),
        RedirectBodySource::Inline(bytes) => Ok(bytes.clone()),
        RedirectBodySource::UserBytes { offset, len } => {
            let offset = *offset as usize;
            let len = *len as usize;
            let end = offset.checked_add(len).ok_or_else(|| {
                Error::new(ErrorCode::InvalidArgument, "redirect body range overflows")
            })?;
            body.get(offset..end)
                .map(|slice| slice.to_vec())
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "redirect body range exceeds the write body",
                    )
                })
        }
    }
}

pub(crate) async fn execute_redirect_request(
    request: &HttpRequest,
    body: &[u8],
) -> Result<RedirectResult> {
    let url = url::Url::parse(&request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    match url.scheme() {
        "file" => execute_file_redirect(request, &url, body).await,
        "http" => execute_http_redirect(request, &url, body).await,
        "https" => execute_reqwest_redirect(request, body).await,
        scheme => Err(Error::new(
            ErrorCode::Unsupported,
            format!("redirect scheme '{scheme}' is not supported"),
        )),
    }
}

pub(crate) fn redirect_info_from_result(
    address: Url,
    parsing: &ResponseParsing,
    result: &RedirectResult,
) -> ObjectInfo {
    let size = header_value(&result.captured_headers, parsing.size_header.as_deref())
        .and_then(|value| value.parse::<u64>().ok())
        .or(Some(result.captured_body.len() as u64));
    let mtime = header_value(&result.captured_headers, parsing.mtime_header.as_deref())
        .and_then(|value| parse_mtime(value, parsing.mtime_format));
    let system_metadata = if parsing.system_metadata_headers.is_empty() {
        None
    } else {
        let mut metadata = SystemMetadata::new();
        for wanted in &parsing.system_metadata_headers {
            if let Some(value) = header_value(&result.captured_headers, Some(wanted)) {
                metadata.insert(wanted.to_ascii_lowercase(), value.to_string());
            }
        }
        (!metadata.is_empty()).then_some(metadata)
    };
    // Propagation only; verification lives in `StreamingVerifier`.
    // GCS `x-goog-hash` is multi-value; route through the tag-aware
    // extractor so each algorithm picks up its own bytes.
    let mut checksums = ChecksumSet::default();
    for (algorithm, header_name) in &parsing.checksum_headers {
        let value: Option<String> = if header_name.eq_ignore_ascii_case("x-goog-hash") {
            extract_x_goog_hash(&result.captured_headers, algorithm.as_str())
        } else {
            header_value(&result.captured_headers, Some(header_name))
                .map(|v| v.trim().trim_matches('"').to_string())
        };
        if let Some(value) = value {
            checksums.insert(algorithm.clone(), value.into_bytes());
        }
    }
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: header_value(&result.captured_headers, parsing.etag_header.as_deref())
            .map(|value| value.trim_matches('"').to_string()),
        version: header_value(&result.captured_headers, parsing.version_header.as_deref())
            .map(str::to_string),
        size,
        mtime,
        checksums,
        effective_permissions: None,
        system_metadata,
        user_metadata: None,
        modified_by: None,
    }
}

pub(crate) fn header_value<'a>(
    headers: &'a [(String, String)],
    name: Option<&str>,
) -> Option<&'a str> {
    let name = name?;
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(crate) fn parse_mtime(value: &str, format: MtimeFormat) -> Option<SystemTime> {
    match format {
        MtimeFormat::UnixSeconds => value
            .parse::<u64>()
            .ok()
            .map(|seconds| UNIX_EPOCH + std::time::Duration::from_secs(seconds)),
        MtimeFormat::Rfc1123 | MtimeFormat::Iso8601 => None,
    }
}

pub(crate) async fn execute_file_redirect(
    request: &HttpRequest,
    url: &url::Url,
    body: &[u8],
) -> Result<RedirectResult> {
    let path = url
        .to_file_path()
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "file redirect URL is invalid"))?;
    match request.method.as_str() {
        "GET" => {
            let bytes = tokio::fs::read(path).await.map_err(io_error)?;
            Ok(RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: bytes,
            })
        }
        "PUT" => {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(io_error)?;
            }
            tokio::fs::write(path, body).await.map_err(io_error)?;
            Ok(RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            })
        }
        method => Err(Error::new(
            ErrorCode::Unsupported,
            format!("file redirect method '{method}' is not supported"),
        )),
    }
}

/// One Client pools connections + TLS state across redirects.
fn redirect_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client init")
    })
}

/// Each pull goes through `spawn_blocking` so a caller iterator that
/// does blocking I/O won't park a runtime worker.
fn body_stream_to_async(
    stream: BodyStream,
) -> impl futures::Stream<Item = std::io::Result<Vec<u8>>> + Send + 'static {
    futures::stream::unfold(Some(stream), |state| async move {
        let mut s = state?;
        match tokio::task::spawn_blocking(move || (s.next_chunk(), s)).await {
            Ok((Some(Ok(bytes)), s)) => Some((Ok(bytes), Some(s))),
            Ok((Some(Err(err)), _)) => Some((Err(std::io::Error::other(err.to_string())), None)),
            Ok((None, _)) => None,
            Err(join_err) => Some((Err(std::io::Error::other(join_err.to_string())), None)),
        }
    })
}

/// `file://` streams chunk-by-chunk to disk; http/https use chunked
/// transfer encoding (length unknown at request time).
async fn execute_streaming_request(
    request: &HttpRequest,
    stream: BodyStream,
) -> Result<RedirectResult> {
    let url = url::Url::parse(&request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    match url.scheme() {
        "file" => execute_file_streaming_request(request, &url, stream).await,
        "http" | "https" => execute_reqwest_streaming_request(request, stream).await,
        scheme => Err(Error::new(
            ErrorCode::Unsupported,
            format!("streaming redirect scheme '{scheme}' is not supported"),
        )),
    }
}

async fn execute_file_streaming_request(
    request: &HttpRequest,
    url: &url::Url,
    mut stream: BodyStream,
) -> Result<RedirectResult> {
    if request.method != "PUT" {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "file streaming redirect method '{}' is not supported",
                request.method
            ),
        ));
    }
    let path = url
        .to_file_path()
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "file redirect URL is invalid"))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(io_error)?;
    }
    let mut file = tokio::fs::File::create(&path).await.map_err(io_error)?;
    // Hand the stream back across each spawn_blocking so we can resume.
    loop {
        let (chunk, returned) = tokio::task::spawn_blocking(move || (stream.next_chunk(), stream))
            .await
            .map_err(|err| Error::new(ErrorCode::Internal, err.to_string()))?;
        stream = returned;
        match chunk {
            None => break,
            Some(Ok(bytes)) => file.write_all(&bytes).await.map_err(io_error)?,
            Some(Err(err)) => return Err(err),
        }
    }
    file.flush().await.map_err(io_error)?;
    Ok(RedirectResult {
        status_code: 200,
        captured_headers: Vec::new(),
        captured_body: Vec::new(),
    })
}

async fn execute_reqwest_streaming_request(
    request: &HttpRequest,
    stream: BodyStream,
) -> Result<RedirectResult> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect HTTP method is invalid: {error}"),
        )
    })?;
    let body = reqwest::Body::wrap_stream(body_stream_to_async(stream));
    let mut builder = redirect_client().request(method, &request.url);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    let response = builder
        .body(body)
        .send()
        .await
        .map_err(|error| Error::new(ErrorCode::Transient, error.to_string()))?;
    response_to_redirect_result(response).await
}

pub(crate) async fn execute_reqwest_redirect(
    request: &HttpRequest,
    body: &[u8],
) -> Result<RedirectResult> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect HTTP method is invalid: {error}"),
        )
    })?;
    let mut builder = redirect_client().request(method, &request.url);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    let response = builder
        .body(body.to_vec())
        .send()
        .await
        .map_err(|error| Error::new(ErrorCode::Transient, error.to_string()))?;
    response_to_redirect_result(response).await
}

async fn response_to_redirect_result(response: reqwest::Response) -> Result<RedirectResult> {
    let status_code = response.status().as_u16();
    let captured_headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let captured_body = response
        .bytes()
        .await
        .map_err(|error| Error::new(ErrorCode::Transient, error.to_string()))?
        .to_vec();
    Ok(RedirectResult {
        status_code,
        captured_headers,
        captured_body,
    })
}

pub(crate) async fn execute_http_redirect(
    request: &HttpRequest,
    url: &url::Url,
    body: &[u8],
) -> Result<RedirectResult> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "redirect URL has no host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let mut stream = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(io_error)?;
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method,
        path,
        host,
        body.len()
    );
    for (name, value) in &request.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.map_err(io_error)?;
    stream.write_all(body).await.map_err(io_error)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.map_err(io_error)?;
    parse_http_response(response)
}

pub(crate) fn parse_http_response(response: Vec<u8>) -> Result<RedirectResult> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::new(ErrorCode::Transient, "redirect response is malformed"))?;
    let (head, body) = response.split_at(separator + 4);
    let head = std::str::from_utf8(head).map_err(|_| {
        Error::new(
            ErrorCode::Transient,
            "redirect response headers are not valid UTF-8",
        )
    })?;
    let status_code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::new(ErrorCode::Transient, "redirect response status is missing"))?;
    let captured_headers = head
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();
    Ok(RedirectResult {
        status_code,
        captured_headers,
        captured_body: body.to_vec(),
    })
}

/// 64 KiB chunks; lets the dispatcher feed `Body::LocalFile` into
/// `write_stream` without materializing.
pub(crate) fn body_stream_from_file(path: &std::path::Path) -> Result<BodyStream> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(io_error)?;
    Ok(BodyStream::from_iter(std::iter::from_fn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        match file.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some(Ok(buf))
            }
            Err(err) => Some(Err(io_error(err))),
        }
    })))
}

pub(crate) fn io_error(err: std::io::Error) -> Error {
    use std::io::ErrorKind;
    let code = match err.kind() {
        ErrorKind::NotFound => ErrorCode::NotFound,
        ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Transient,
    };
    Error::new(code, err.to_string())
}

#[cfg(test)]
mod content_checksum_tests {
    use super::*;

    fn parsing_with_sha256(header: &str) -> ResponseParsing {
        ResponseParsing {
            content_checksum_header: Some(header.to_string()),
            content_checksum_algorithm: Some(ChecksumAlgorithm::sha256()),
            ..ResponseParsing::default()
        }
    }

    /// Precomputed `sha256(b"abcd")`.
    const ABCD_SHA256_HEX: &str =
        "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589";

    #[test]
    fn happy_path_streaming_sha256_passes_all_chunks_and_finalizes_clean() {
        let parsing = parsing_with_sha256("x-test-checksum");
        let headers = vec![("x-test-checksum".to_string(), ABCD_SHA256_HEX.to_string())];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"a");
        verifier.update(b"b");
        verifier.update(b"c");
        verifier.update(b"d");
        verifier.finalize().expect("matching sha256 should pass");
    }

    #[test]
    fn mismatch_returns_content_checksum_mismatch() {
        let parsing = parsing_with_sha256("x-test-checksum");
        let wrong_hex =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        let headers = vec![("x-test-checksum".to_string(), wrong_hex)];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"abcd");
        let err = verifier
            .finalize()
            .expect_err("wrong sha256 should fail to verify");
        assert_eq!(err.code(), ErrorCode::ContentChecksumMismatch);
    }

    #[test]
    fn unknown_algorithm_degrades_to_passthrough_no_error() {
        // `crc64nvme` is a recognised SPI token but no hasher is
        // wired — must degrade silently.
        let parsing = ResponseParsing {
            content_checksum_header: Some("x-test-checksum".to_string()),
            content_checksum_algorithm: Some(
                ChecksumAlgorithm::new("crc64nvme").expect("crc64nvme parses"),
            ),
            ..ResponseParsing::default()
        };
        let headers = vec![("x-test-checksum".to_string(), "anything".to_string())];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"some bytes");
        verifier
            .finalize()
            .expect("unknown algorithm => verifier must degrade silently");
    }

    #[test]
    fn no_header_in_response_skips_verification() {
        let parsing = parsing_with_sha256("x-test-checksum");
        let headers: Vec<(String, String)> = Vec::new();
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"anything goes");
        verifier
            .finalize()
            .expect("missing header => skip verification");
    }

    #[test]
    fn streaming_bound_multi_chunk_sha256_correct() {
        // sha256("hello world") arriving in 6 chunks.
        let parsing = parsing_with_sha256("x-cs");
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let headers = vec![("x-cs".to_string(), expected_hex.to_string())];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        for chunk in [
            b"hel".as_ref(),
            b"lo".as_ref(),
            b" ".as_ref(),
            b"wo".as_ref(),
            b"rl".as_ref(),
            b"d".as_ref(),
        ] {
            verifier.update(chunk);
        }
        verifier.finalize().expect("multi-chunk sha256 must match");
    }

    #[test]
    fn parse_checksum_value_accepts_hex() {
        let parsed = parse_checksum_value(ABCD_SHA256_HEX, 32).unwrap();
        assert_eq!(parsed.len(), 32);
        assert_eq!(parsed[0], 0x88);
    }

    #[test]
    fn parse_checksum_value_accepts_base64() {
        assert_eq!(parse_checksum_value("aGVsbG8=", 5).unwrap(), b"hello");
    }

    #[test]
    fn parse_checksum_value_strips_etag_quotes_via_trim() {
        let quoted = format!("\"{ABCD_SHA256_HEX}\"");
        let parsed = parse_checksum_value(&quoted, 32).unwrap();
        assert_eq!(parsed.len(), 32);
    }

    #[test]
    fn parse_checksum_value_rejects_garbage() {
        assert!(parse_checksum_value("not-a-real-hash", 32).is_none());
    }

    #[test]
    fn buffered_redirect_path_propagates_checksum_mismatch() {
        // Same verifier as `follow_read_redirect`, no HTTP.
        let parsing = parsing_with_sha256("x-cs");
        let headers = vec![(
            "x-cs".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"actual body bytes");
        let err = verifier.finalize().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ContentChecksumMismatch);
    }

    fn parsing_with(algorithm: ChecksumAlgorithm, header: &str) -> ResponseParsing {
        ResponseParsing {
            content_checksum_header: Some(header.to_string()),
            content_checksum_algorithm: Some(algorithm),
            ..ResponseParsing::default()
        }
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// Precomputed `md5(b"abcd")`.
    const ABCD_MD5_HEX: &str = "e2fc714c4727ee9395f324cd2e7f331f";

    #[test]
    fn streaming_md5_passes_multi_chunk() {
        let expected_bytes = decode_hex(ABCD_MD5_HEX).unwrap();
        let parsing = parsing_with(ChecksumAlgorithm::md5(), "Content-MD5");
        let headers = vec![("Content-MD5".to_string(), b64(&expected_bytes))];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"a");
        verifier.update(b"b");
        verifier.update(b"c");
        verifier.update(b"d");
        verifier.finalize().expect("matching md5 should pass");
    }

    #[test]
    fn streaming_md5_mismatch_returns_content_checksum_mismatch() {
        let parsing = parsing_with(ChecksumAlgorithm::md5(), "Content-MD5");
        let headers = vec![("Content-MD5".to_string(), b64(&[0u8; 16]))];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"abcd");
        let err = verifier
            .finalize()
            .expect_err("wrong md5 should fail to verify");
        assert_eq!(err.code(), ErrorCode::ContentChecksumMismatch);
    }

    #[test]
    fn streaming_crc32c_passes_multi_chunk() {
        // Reference computed with the same crate the verifier uses.
        let expected_u32 = crc32c::crc32c(b"abcd");
        let expected_bytes = expected_u32.to_be_bytes();
        let parsing = parsing_with(ChecksumAlgorithm::crc32c(), "x-test-crc32c");
        let headers = vec![("x-test-crc32c".to_string(), b64(&expected_bytes))];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"a");
        verifier.update(b"b");
        verifier.update(b"c");
        verifier.update(b"d");
        verifier.finalize().expect("matching crc32c should pass");
    }

    #[test]
    fn streaming_crc32c_mismatch_returns_content_checksum_mismatch() {
        let parsing = parsing_with(ChecksumAlgorithm::crc32c(), "x-test-crc32c");
        let headers = vec![("x-test-crc32c".to_string(), b64(&[0u8; 4]))];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"abcd");
        let err = verifier
            .finalize()
            .expect_err("wrong crc32c should fail to verify");
        assert_eq!(err.code(), ErrorCode::ContentChecksumMismatch);
    }

    #[test]
    fn x_goog_hash_extractor_handles_repeated_headers() {
        let md5_b64 = b64(&decode_hex(ABCD_MD5_HEX).unwrap());
        let crc_b64 = b64(&crc32c::crc32c(b"abcd").to_be_bytes());
        let headers = vec![
            ("x-goog-hash".to_string(), format!("md5={md5_b64}")),
            ("x-goog-hash".to_string(), format!("crc32c={crc_b64}")),
        ];
        assert_eq!(
            extract_x_goog_hash(&headers, "md5").as_deref(),
            Some(md5_b64.as_str())
        );
        assert_eq!(
            extract_x_goog_hash(&headers, "crc32c").as_deref(),
            Some(crc_b64.as_str())
        );
        assert!(extract_x_goog_hash(&headers, "sha256").is_none());
    }

    #[test]
    fn x_goog_hash_extractor_handles_comma_separated_single_header() {
        let md5_b64 = b64(&decode_hex(ABCD_MD5_HEX).unwrap());
        let crc_b64 = b64(&crc32c::crc32c(b"abcd").to_be_bytes());
        // Trailing space after the comma — common HTTP style.
        let value = format!("crc32c={crc_b64}, md5={md5_b64}");
        let headers = vec![("X-Goog-Hash".to_string(), value)];
        assert_eq!(
            extract_x_goog_hash(&headers, "md5").as_deref(),
            Some(md5_b64.as_str())
        );
        assert_eq!(
            extract_x_goog_hash(&headers, "crc32c").as_deref(),
            Some(crc_b64.as_str())
        );
    }

    #[test]
    fn streaming_crc32c_via_x_goog_hash_multivalue() {
        let crc_b64 = b64(&crc32c::crc32c(b"abcd").to_be_bytes());
        let md5_b64 = b64(&decode_hex(ABCD_MD5_HEX).unwrap());
        let parsing = parsing_with(ChecksumAlgorithm::crc32c(), "x-goog-hash");
        let headers = vec![
            ("x-goog-hash".to_string(), format!("crc32c={crc_b64}")),
            ("x-goog-hash".to_string(), format!("md5={md5_b64}")),
        ];
        let mut verifier = StreamingVerifier::for_response(&parsing, &headers);
        verifier.update(b"abcd");
        verifier
            .finalize()
            .expect("multi-value x-goog-hash crc32c must verify");
    }

    #[test]
    fn redirect_info_propagates_x_goog_hash_multi_value_into_checksums() {
        let crc_b64 = b64(&crc32c::crc32c(b"abcd").to_be_bytes());
        let md5_b64 = b64(&decode_hex(ABCD_MD5_HEX).unwrap());
        let mut parsing = ResponseParsing::default();
        parsing
            .checksum_headers
            .insert(ChecksumAlgorithm::crc32c(), "x-goog-hash".into());
        parsing
            .checksum_headers
            .insert(ChecksumAlgorithm::md5(), "x-goog-hash".into());
        let result = RedirectResult {
            status_code: 200,
            captured_headers: vec![
                ("x-goog-hash".into(), format!("crc32c={crc_b64}")),
                ("x-goog-hash".into(), format!("md5={md5_b64}")),
            ],
            captured_body: Vec::new(),
        };
        let info = redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result);
        assert_eq!(
            info.checksums.get(&ChecksumAlgorithm::crc32c()),
            Some(crc_b64.as_bytes())
        );
        assert_eq!(
            info.checksums.get(&ChecksumAlgorithm::md5()),
            Some(md5_b64.as_bytes())
        );
    }

    #[test]
    fn redirect_info_propagates_x_goog_hash_comma_separated_into_checksums() {
        let crc_b64 = b64(&crc32c::crc32c(b"abcd").to_be_bytes());
        let md5_b64 = b64(&decode_hex(ABCD_MD5_HEX).unwrap());
        let mut parsing = ResponseParsing::default();
        parsing
            .checksum_headers
            .insert(ChecksumAlgorithm::crc32c(), "x-goog-hash".into());
        parsing
            .checksum_headers
            .insert(ChecksumAlgorithm::md5(), "x-goog-hash".into());
        let result = RedirectResult {
            status_code: 200,
            captured_headers: vec![(
                "x-goog-hash".into(),
                format!("crc32c={crc_b64}, md5={md5_b64}"),
            )],
            captured_body: Vec::new(),
        };
        let info = redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result);
        assert_eq!(
            info.checksums.get(&ChecksumAlgorithm::crc32c()),
            Some(crc_b64.as_bytes())
        );
        assert_eq!(
            info.checksums.get(&ChecksumAlgorithm::md5()),
            Some(md5_b64.as_bytes())
        );
    }

    #[test]
    fn redirect_info_folds_checksum_headers_into_object_info() {
        let mut parsing = ResponseParsing::default();
        parsing
            .checksum_headers
            .insert(ChecksumAlgorithm::sha256(), "x-amz-checksum-sha256".into());
        parsing
            .checksum_headers
            .insert(ChecksumAlgorithm::crc32c(), "x-amz-checksum-crc32c".into());
        let result = RedirectResult {
            status_code: 200,
            captured_headers: vec![
                ("x-amz-checksum-sha256".into(), "AbC=".into()),
                ("x-amz-checksum-crc32c".into(), "wxyZ==".into()),
            ],
            captured_body: Vec::new(),
        };
        let info = redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result);
        let sha = info
            .checksums
            .get(&ChecksumAlgorithm::sha256())
            .expect("sha256 entry");
        assert_eq!(sha, b"AbC=");
        let crc = info
            .checksums
            .get(&ChecksumAlgorithm::crc32c())
            .expect("crc32c entry");
        assert_eq!(crc, b"wxyZ==");
    }
}

#[cfg(test)]
mod userbytes_length_enforcement_tests {
    use super::*;

    fn ok_chunk(s: &[u8]) -> Result<Vec<u8>> {
        Ok(s.to_vec())
    }

    #[test]
    fn bounded_stream_caps_to_target_when_inner_has_more() {
        let chunks = vec![ok_chunk(b"abc"), ok_chunk(b"de")];
        let inner = BodyStream::from_iter(chunks.into_iter());
        let mut bounded = bounded_body_stream(inner, 3);
        let collected: Vec<Vec<u8>> = (&mut bounded).map(|c| c.unwrap()).collect();
        let total: Vec<u8> = collected.into_iter().flatten().collect();
        assert_eq!(total, b"abc");
    }

    #[test]
    fn bounded_stream_reports_invalid_argument_on_short_inner() {
        let chunks = vec![ok_chunk(b"ab")];
        let inner = BodyStream::from_iter(chunks.into_iter());
        let mut bounded = bounded_body_stream(inner, 5);
        let mut last_err: Option<Error> = None;
        for item in &mut bounded {
            match item {
                Ok(_) => {}
                Err(err) => {
                    last_err = Some(err);
                    break;
                }
            }
        }
        let err = last_err.expect("short inner stream must surface an error");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn bounded_stream_errors_internal_when_chunk_straddles_boundary() {
        let chunks = vec![ok_chunk(b"abcdef")];
        let inner = BodyStream::from_iter(chunks.into_iter());
        let mut bounded = bounded_body_stream(inner, 3);
        let mut last_err: Option<Error> = None;
        for item in &mut bounded {
            match item {
                Ok(_) => {}
                Err(err) => {
                    last_err = Some(err);
                    break;
                }
            }
        }
        let err = last_err.expect("boundary-straddling chunk must surface an error");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[tokio::test]
    async fn read_n_from_stream_short_eof_returns_invalid_argument() {
        let chunks = vec![ok_chunk(b"hi")];
        let inner = BodyStream::from_iter(chunks.into_iter());
        let err = read_n_from_stream(inner, 10)
            .await
            .expect_err("short stream must error rather than return less than target");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn read_n_from_stream_aligned_chunks_return_full_buffer() {
        let chunks = vec![ok_chunk(b"abc"), ok_chunk(b"de")];
        let inner = BodyStream::from_iter(chunks.into_iter());
        let (buf, _stream) = read_n_from_stream(inner, 5).await.expect("aligned drain");
        assert_eq!(buf, b"abcde");
    }
}

#[cfg(test)]
mod range_injection_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Behavior of the test HTTP server's response to a Range request.
    #[derive(Clone)]
    enum RangeBehavior {
        /// Honor the request — 206 with the supplied body when Range
        /// was sent, 200 with the supplied body otherwise.
        Honor { body: Vec<u8> },
        /// Ignore the Range header — always 200 with the full body.
        /// Exercises the client-side slicing path.
        Ignore { body: Vec<u8> },
    }

    impl RangeBehavior {
        fn honor() -> Self {
            Self::Honor { body: Vec::new() }
        }
    }

    /// Spin up a one-shot HTTP server on 127.0.0.1:0. Accepts a single
    /// connection, parses request headers, responds based on
    /// `behavior`, and sends the captured headers through the
    /// returned `oneshot`.
    async fn spawn_capture_server(
        behavior: RangeBehavior,
    ) -> (u16, tokio::sync::oneshot::Receiver<Vec<(String, String)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8 * 1024];
            let mut total = 0usize;
            while total < buf.len() {
                let n = socket.read(&mut buf[total..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let headers_blob = String::from_utf8_lossy(&buf[..total]).to_string();
            let mut headers: Vec<(String, String)> = Vec::new();
            for line in headers_blob.lines().skip(1) {
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.push((name.trim().to_string(), value.trim().to_string()));
                }
            }
            let had_range = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("range"));
            let _ = tx.send(headers);
            let (status_line, body) = match (&behavior, had_range) {
                (RangeBehavior::Honor { body }, true) => {
                    let last = body.len().saturating_sub(1);
                    (
                        format!(
                            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{}/{}\r\n",
                            last,
                            body.len(),
                        ),
                        body.clone(),
                    )
                }
                (RangeBehavior::Honor { body }, false) | (RangeBehavior::Ignore { body }, _) => {
                    ("HTTP/1.1 200 OK\r\n".to_string(), body.clone())
                }
            };
            let head = format!("{status_line}Content-Length: {}\r\n\r\n", body.len());
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.shutdown().await;
        });
        (port, rx)
    }

    fn redirect_to(url: String) -> ReadRedirect {
        ReadRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url,
                headers: Vec::new(),
            },
            response_parsing: ResponseParsing::default(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            scope: RedirectScope {
                physical_url_prefix: String::new(),
                operations: AccessOps {
                    read: true,
                    ..Default::default()
                },
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            },
            audit_id: String::new(),
            policy_epoch: 0,
        }
    }

    fn has_range_header(headers: &[(String, String)]) -> Option<&str> {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("range"))
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_adds_range_header() {
        let (port, rx) = spawn_capture_server(RangeBehavior::honor()).await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 100,
            end_inclusive: Some(199),
        };
        let _ = follow_read_redirect(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            &retry::RetryConfig::default(),
            false,
            Some(&range),
        )
        .await
        .expect("follower ok");
        let headers = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("server captured headers within 2s")
            .expect("oneshot fired");
        assert_eq!(
            has_range_header(&headers),
            Some("bytes=100-199"),
            "Range header must be present; got headers={headers:?}",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_streaming_adds_range_header() {
        let (port, rx) = spawn_capture_server(RangeBehavior::honor()).await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 100,
            end_inclusive: Some(199),
        };
        let _ = follow_read_redirect_streaming(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            false,
            Some(&range),
        )
        .await
        .expect("streaming follower ok");
        let headers = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("server captured headers within 2s")
            .expect("oneshot fired");
        assert_eq!(
            has_range_header(&headers),
            Some("bytes=100-199"),
            "Range header must be present on streaming path; got headers={headers:?}",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_open_ended_range_uses_bytes_n_dash() {
        let (port, rx) = spawn_capture_server(RangeBehavior::honor()).await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 42,
            end_inclusive: None,
        };
        let _ = follow_read_redirect(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            &retry::RetryConfig::default(),
            false,
            Some(&range),
        )
        .await
        .expect("follower ok");
        let headers = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("server captured headers within 2s")
            .expect("oneshot fired");
        assert_eq!(has_range_header(&headers), Some("bytes=42-"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_without_range_omits_header() {
        let (port, rx) = spawn_capture_server(RangeBehavior::honor()).await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let _ = follow_read_redirect(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            &retry::RetryConfig::default(),
            false,
            None,
        )
        .await
        .expect("follower ok");
        let headers = tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("server captured headers within 2s")
            .expect("oneshot fired");
        assert!(
            has_range_header(&headers).is_none(),
            "Range header must NOT be synthesized when caller didn't ask; got headers={headers:?}",
        );
    }

    /// An origin that ignores `Range:` and replies 200 OK with the
    /// full body — also the legitimate response when the requested
    /// range covers the whole object (e.g. `bytes=0-1000` on a
    /// 100-byte file). The follower must slice client-side so the
    /// caller still gets the bytes they asked for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_slices_200_response_to_requested_range() {
        let (port, _rx) = spawn_capture_server(RangeBehavior::Ignore {
            body: b"0123456789".to_vec(),
        })
        .await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 2,
            end_inclusive: Some(5),
        };
        let followed = follow_read_redirect(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            &retry::RetryConfig::default(),
            false,
            Some(&range),
        )
        .await
        .expect("follower must slice 200 response, not fail");
        assert_eq!(&followed.bytes[..], b"2345");
    }

    /// Range covers more than the object (`bytes=0-1000` on a 10-byte
    /// file) — server returned 200 with the full body. Slicing should
    /// truncate to body length, not panic or overflow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_slices_200_when_range_exceeds_body() {
        let (port, _rx) = spawn_capture_server(RangeBehavior::Ignore {
            body: b"0123456789".to_vec(),
        })
        .await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(1000),
        };
        let followed = follow_read_redirect(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            &retry::RetryConfig::default(),
            false,
            Some(&range),
        )
        .await
        .expect("range exceeding body is legitimate; return what's available");
        assert_eq!(&followed.bytes[..], b"0123456789");
    }

    /// Inverted range (`end < start`) must be rejected before the
    /// slice would panic. Buffered path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_rejects_inverted_range_on_200() {
        let (port, _rx) = spawn_capture_server(RangeBehavior::Ignore {
            body: b"0123456789".to_vec(),
        })
        .await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 5,
            end_inclusive: Some(2),
        };
        let err = follow_read_redirect(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            &retry::RetryConfig::default(),
            false,
            Some(&range),
        )
        .await
        .err()
        .expect("inverted range must error");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// Streaming counterpart: 200-with-full-body must be sliced
    /// client-side, not rejected. The wrapper stops pulling from the
    /// upstream once the slice is filled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_streaming_slices_200_response() {
        use futures::StreamExt;
        let (port, _rx) = spawn_capture_server(RangeBehavior::Ignore {
            body: b"0123456789".to_vec(),
        })
        .await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 2,
            end_inclusive: Some(5),
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            false,
            Some(&range),
        )
        .await
        .expect("streaming slice must succeed on 200-with-full-body");
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.expect("chunk ok"));
        }
        assert_eq!(&bytes[..], b"2345");
    }

    /// Inverted range on the streaming path: must fail validation at
    /// the entry, NOT reach `range_filter_stream` (whose slice would
    /// panic the worker thread on `slice(5..3)` and — under
    /// `panic = "abort"` — terminate the process).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_streaming_rejects_inverted_range() {
        let (port, _rx) = spawn_capture_server(RangeBehavior::Ignore {
            body: b"0123456789".to_vec(),
        })
        .await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 5,
            end_inclusive: Some(2),
        };
        let err = follow_read_redirect_streaming(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            false,
            Some(&range),
        )
        .await
        .err()
        .expect("inverted range must error");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// A range that starts past EOF on a 200-OK 10-byte body: the
    /// buffered path errors loudly with InvalidArgument; the
    /// streaming path must too. Without the EOF guard, the wrapper
    /// would yield an empty stream and the caller would think the
    /// slice was satisfied.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_streaming_rejects_start_past_eof() {
        use futures::StreamExt;
        let (port, _rx) = spawn_capture_server(RangeBehavior::Ignore {
            body: b"0123456789".to_vec(),
        })
        .await;
        let redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        let range = ByteRange {
            start: 100,
            end_inclusive: Some(200),
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/test").unwrap(),
            &redirect,
            false,
            Some(&range),
        )
        .await
        .expect("entry call should succeed (validation is structural, EOF check streams)");
        // Drain the stream; the wrapper surfaces InvalidArgument at
        // end-of-upstream when no bytes were ever in range.
        let mut last_err = None;
        while let Some(frame) = stream.next().await {
            if let Err(err) = frame {
                last_err = Some(err);
                break;
            }
        }
        let err = last_err.expect("start-past-EOF must surface as Err frame, not silent empty");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}
