// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::*;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::UNIX_EPOCH;

/// Render a `ByteRange` as an HTTP `Range:` header value.
/// `bytes=N-M` for a closed range; `bytes=N-` (open-ended) when
/// `end_inclusive` is `None`. Both forms are RFC 7233 compliant.
fn format_range_header(range: &ByteRange) -> String {
    match range.end_inclusive {
        Some(end) => format!("bytes={}-{}", range.start, end),
        None => format!("bytes={}-", range.start),
    }
}

/// Reject an inverted range (`end_inclusive < start`) — both
/// buffered and streaming slice paths need this guard before they
/// compute byte indices, otherwise the slice would panic the worker
/// thread.
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

/// One streaming HTTP attempt against `redirect`: the redirect's method, URL,
/// and headers, plus the caller's `Range`. Parses the method fresh per call so
/// a re-minted redirect (whose URL/method may differ) is honored.
async fn send_streaming_request(
    redirect: &ReadRedirect,
    range: Option<&ByteRange>,
    if_match: Option<&str>,
) -> std::result::Result<reqwest::Response, reqwest::Error> {
    // `ensure_read_redirect_valid` parses and constrains this to GET/HEAD
    // before any request reaches this helper.
    let method = reqwest::Method::from_bytes(redirect.request.method.as_bytes())
        .expect("validated redirect method");
    let mut builder = redirect_client().request(method, &redirect.request.url);
    for (name, value) in &redirect.request.headers {
        // The URL authority is the capability boundary. Never let a supplied
        // Host header select another virtual host behind an allowed proxy/IP;
        // reqwest derives the authoritative value from the validated URL.
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        // The follower owns these values when it is applying a caller range or
        // resuming a failed response. Replaying the redirect's originals and
        // then appending ours would put duplicate field lines on the wire
        // (`RequestBuilder::header` appends), turning Range into a multi-range
        // request and making If-Match ambiguous.
        if range.is_some() && name.eq_ignore_ascii_case("range") {
            continue;
        }
        if if_match.is_some() && name.eq_ignore_ascii_case("if-match") {
            continue;
        }
        builder = builder.header(name, value);
    }
    if let Some(range) = range {
        builder = builder.header("Range", format_range_header(range));
    }
    if let Some(validator) = if_match {
        builder = builder.header("If-Match", quote_etag(validator));
    }
    builder.send().await
}

/// RFC 7232 requires the entity-tag to travel quoted, and strict origins
/// (S3/GCS presigned URLs — the flagship mid-stream-resume scenario) compare `If-Match`
/// against the literal quoted ETag, answering 412 on an unquoted value.
/// Validators are stored quote-stripped (`redirect_info_from_result`), so
/// re-quote at the wire; already-quoted and weak (`W/"..."`) forms pass
/// through verbatim.
fn quote_etag(value: &str) -> String {
    if value.starts_with('"') || value.starts_with("W/") {
        value.to_string()
    } else {
        format!("\"{value}\"")
    }
}

/// Re-acquire a fresh [`ReadRedirect`] from the backend — supplied by the
/// redirect-follower wrapper (which re-issues the original backend read) so
/// the follower can replace a presigned URL that has expired, or been
/// rejected as invalid, instead of replaying the stale one —
/// both before the response is established and across mid-stream resume
/// attempts.
pub(crate) type RedirectMint = std::sync::Arc<
    dyn Fn() -> futures::future::BoxFuture<'static, Result<ReadRedirect>> + Send + Sync,
>;

/// A freshness-checked redirect: re-minted via `mint` when expired, erring
/// with `RedirectExpired` when no mint source exists.
async fn fresh_redirect(current: &mut ReadRedirect, mint: Option<&RedirectMint>) -> Result<()> {
    let now = SystemTime::now();
    if current.expires_at > now && current.scope.expires_at > now {
        return ensure_read_redirect_valid(current);
    }
    match mint {
        Some(mint) => {
            *current = mint().await?;
            ensure_read_redirect_valid(current)
        }
        None => Err(Error::new(
            ErrorCode::RedirectExpired,
            "redirect expired before it could be followed",
        )),
    }
}

pub(crate) struct StreamedReadRedirect {
    pub(crate) stream: ovstorage_plugin::ReadStream,
    pub(crate) info: ObjectInfo,
    /// The response's headers-phase `Content-Length` (or the file size for a
    /// `file://` redirect), captured before any body byte is consumed. `None`
    /// when the origin reports no length (chunked / unknown). This is the raw
    /// wire length the `RedirectFollowerWrapper` size-gates on, distinct from
    /// `info.size` (which defaults to 0 when the backend's `size_header` isn't
    /// configured).
    pub(crate) content_length: Option<u64>,
    /// The redirect actually in force after the header phase — i.e. the one
    /// re-minted on expiry or 403-rejection, or the original if neither fired.
    /// A size-gate that declines to follow may surface this only when it carries
    /// no ambient credential header; otherwise the host fails closed.
    pub(crate) effective_redirect: ReadRedirect,
}

/// The read-redirect follower: pulls bytes from
/// `reqwest::Response::bytes_stream()` without materializing the body.
///
/// Transient-HTTP retry (the route's `RetryConfig`, honoring `Retry-After`)
/// applies until response headers arrive. Once `bytes_stream()` is open,
/// replay is impossible
/// mid-stream, so a mid-body failure surfaces as a stream error. The
/// redirect's freshness is checked once up front; an attempt that outlives
/// `expires_at` surfaces the origin's non-retryable auth failure.
pub(crate) async fn follow_read_redirect_streaming(
    address: Url,
    redirect: &ReadRedirect,
    if_match_was_set: bool,
    range: Option<&ByteRange>,
    retry_cfg: &retry::RetryConfig,
    mint: Option<RedirectMint>,
) -> Result<StreamedReadRedirect> {
    if let Some(r) = range {
        validate_range(r)?;
    }
    let mut current = redirect.clone();
    // An already-expired redirect is re-minted from the backend instead of
    // failing (or replaying the stale URL).
    fresh_redirect(&mut current, mint.as_ref()).await?;
    let url = url::Url::parse(&current.request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    match url.scheme() {
        "http" | "https" => {}
        // Local-path redirects are the broker-test / air-gapped stand-in for
        // presigned URLs; serve them straight off disk, mirroring the buffered
        // executor's file arm (`execute_file_redirect`).
        "file" => {
            return follow_file_read_redirect_streaming(address, &current, &url, range).await;
        }
        scheme => {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!("streaming redirect scheme '{scheme}' is not supported"),
            ));
        }
    }
    let idempotent = http_method_is_idempotent(&current.request.method);
    // The live redirect travels in shared state: the header-phase retry loop
    // refreshes it, and the mid-stream resume engine keeps
    // using — and re-minting — it long after this function returns.
    let shared_redirect = std::sync::Arc::new(tokio::sync::Mutex::new((current, false)));
    let response = if idempotent {
        // Header-phase retry with re-minting: each attempt re-checks
        // freshness (an attempt that would fire past `expires_at` re-mints
        // first), and a rejection that reads as an invalid/expired
        // presign (403) is re-minted once before surfacing.
        let attempt_state = shared_redirect.clone();
        let mint_ref = mint.clone();
        retry::with_http_retry_async(retry_cfg, move |_attempt| {
            let state = attempt_state.clone();
            let mint = mint_ref.clone();
            let range = range.cloned();
            async move {
                let mut guard = state.lock().await;
                let (redirect, minted_once) = &mut *guard;
                if let Err(error) = fresh_redirect(redirect, mint.as_ref()).await {
                    return retry::RetryStep::Failed(error);
                }
                match send_streaming_request(redirect, range.as_ref(), None).await {
                    Ok(response) if response.status().as_u16() == 403 && !*minted_once => {
                        // A presign the origin rejects as invalid:
                        // re-acquire a fresh redirect once, then retry
                        // immediately.
                        let Some(mint) = mint.as_ref() else {
                            return retry::RetryStep::Done(response);
                        };
                        match mint().await {
                            Ok(fresh) => {
                                *redirect = fresh;
                                *minted_once = true;
                                retry::RetryStep::RetryAfter(
                                    Error::new(
                                        ErrorCode::Transient,
                                        "redirect rejected (HTTP 403); re-minted a fresh redirect",
                                    ),
                                    Some(std::time::Duration::ZERO),
                                )
                            }
                            Err(error) => retry::RetryStep::Failed(error),
                        }
                    }
                    Ok(response) if http_status_is_retryable(response.status().as_u16()) => {
                        let hint = response
                            .headers()
                            .get("retry-after")
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.trim().parse::<u64>().ok())
                            .map(std::time::Duration::from_secs);
                        retry::RetryStep::RetryAfter(
                            Error::new(
                                ErrorCode::Transient,
                                format!(
                                    "redirect returned HTTP {} (retryable)",
                                    response.status().as_u16()
                                ),
                            ),
                            hint,
                        )
                    }
                    Ok(response) => retry::RetryStep::Done(response),
                    Err(error) => {
                        retry::RetryStep::RetryAfter(reqwest_transient_error(error), None)
                    }
                }
            }
        })
        .await?
    } else {
        let guard = shared_redirect.lock().await;
        send_streaming_request(&guard.0, range, None)
            .await
            .map_err(reqwest_transient_error)?
    };
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
    let initial_content_range = if status.as_u16() == 206 {
        Some(validate_single_range_206(
            &response,
            range.map(|requested| requested.start).unwrap_or(0),
            range.and_then(|requested| requested.end_inclusive),
            "initial",
        )?)
    } else {
        None
    };
    // The raw wire length, captured from the response headers before the body
    // stream is opened, is the follower's size-gate input.
    let content_length = response.content_length();
    // The redirect that actually produced this response (re-minted if the
    // header phase re-minted on expiry/403), captured before `shared_redirect`
    // moves into the resume engine — a size-gate decline surfaces this, not the
    // caller's possibly-stale original.
    let effective_redirect = shared_redirect.lock().await.0.clone();
    // Whether the origin honored Range with 206 or returned 200 with
    // the full body, we'll slice client-side below for the 200 case.
    let needs_client_side_range_filter = range.is_some() && status.as_u16() != 206;
    // Verifier travels into the streaming task without pinning the
    // response.
    let verifier = StreamingVerifier::for_streaming_response(
        &redirect.response_parsing,
        &captured_headers,
        status.as_u16(),
        range,
    );
    // The literal HTTP `ETag` header — a real RFC 7232 entity-tag for the
    // resume `If-Match`, captured before `captured_headers` is consumed below.
    // Stored quote-stripped so `quote_etag` re-quotes it uniformly at the wire.
    let http_entity_tag = header_value(&captured_headers, Some("etag"))
        .map(|value| value.trim_matches('"').to_string());
    // Size comes from Content-Length (or stays None for chunked).
    let mut header_only_result = RedirectResult {
        status_code: status.as_u16(),
        captured_headers,
        captured_body: Vec::new(),
    };
    let info = redirect_info_from_result(
        address,
        &redirect.response_parsing,
        &header_only_result,
        false,
    );
    header_only_result.captured_headers.clear();

    // Mid-stream resume: the raw body stream reissues the redirected
    // request with a `Range` starting at the next unread byte on transient
    // failure, guarded by the first response's validator so it never splices
    // bytes from two object versions.
    let initial_offset = if status.as_u16() == 206 {
        range.map(|r| r.start).unwrap_or(0)
    } else {
        0
    };
    let resume = ResumeContext {
        redirect: shared_redirect,
        mint,
        retry_cfg: *retry_cfg,
        parsing: redirect.response_parsing.clone(),
        validator: info.etag.clone(),
        http_entity_tag,
        requested_end: range.and_then(|r| r.end_inclusive),
        idempotent,
    };
    let initial_response_end = initial_content_range.map(|range| range.end);
    let stream = resumable_body_stream(
        response,
        initial_offset,
        initial_response_end,
        verifier,
        resume,
    );
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
    Ok(StreamedReadRedirect {
        stream,
        info,
        content_length,
        effective_redirect,
    })
}

/// The `file://` arm of [`follow_read_redirect_streaming`]: GET only (like
/// `execute_file_redirect`), served off disk chunk-by-chunk. A 200-style
/// full-object stream with client-side range slicing — `info` carries the
/// full object size, matching the buffered file arm's header-less result.
async fn follow_file_read_redirect_streaming(
    address: Url,
    redirect: &ReadRedirect,
    url: &url::Url,
    range: Option<&ByteRange>,
) -> Result<StreamedReadRedirect> {
    use futures::StreamExt;
    if !redirect.request.method.eq_ignore_ascii_case("GET") {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "file redirect method '{}' is not supported",
                redirect.request.method
            ),
        ));
    }
    let path = url
        .to_file_path()
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "file redirect URL is invalid"))?;
    let file = tokio::fs::File::open(&path).await.map_err(io_error)?;
    let metadata = file.metadata().await.map_err(io_error)?;
    let len = metadata.len();
    // NOTE: this is the full object size, whereas the HTTP arm's size-gate input
    // (`response.content_length()`) is the range-sized 206 length. So a ranged
    // read that fits `follow_reads_max_bytes` follows over HTTP but declines over
    // `file://`. Only matters once a host sets the cap (broker); REST leaves
    // it unset. Reconcile the two arms' gate input if that asymmetry bites.
    let content_length = Some(len);
    let info = ObjectInfo {
        address,
        kind: ObjectKind::File,
        // The file backend's canonical validator, so a byte-cache fill from a
        // followed file:// redirect is reachable by the validator a stat of
        // the same file reports.
        etag: Some(synthesize_file_etag(len, metadata.modified().ok())),
        version: None,
        size: Some(len),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    };
    let stream: ovstorage_plugin::ReadStream =
        Box::pin(tokio_util::io::ReaderStream::new(file).map(|chunk| chunk.map_err(io_error)));
    let stream = match range {
        Some(range) => range_filter_stream(stream, range.clone()),
        None => stream,
    };
    Ok(StreamedReadRedirect {
        stream,
        info,
        content_length,
        // A `file://` redirect is served after the expiry re-mint (`&current`),
        // so it is already the effective redirect.
        effective_redirect: redirect.clone(),
    })
}

/// `verifier` runs INCREMENTALLY: each chunk is hashed before yield,
/// never accumulated. Mismatch surfaces as a final
/// `Err(ContentChecksumMismatch)` frame; arbitrary-sized objects
/// verify with bounded host memory.
/// Everything a mid-stream resume needs: the live (re-mintable)
/// redirect, the retry policy, the first response's validator, and the
/// caller's requested end bound.
struct ResumeContext {
    /// The live (re-mintable) redirect plus the 403 re-mint budget. The bool
    /// is **once per READ, shared across the header phase and every
    /// mid-stream resume** (the same tuple travels from the header loop into
    /// this context): a 403 answered on a freshly minted URL means "actually
    /// forbidden", so the follower never loops mints — if the header phase
    /// consumed the budget, a later mid-stream 403 surfaces instead of
    /// minting again. Time-based expiry re-mints via [`fresh_redirect`] are
    /// separate and unlimited.
    redirect: std::sync::Arc<tokio::sync::Mutex<(ReadRedirect, bool)>>,
    mint: Option<RedirectMint>,
    retry_cfg: retry::RetryConfig,
    parsing: ResponseParsing,
    /// The backend's opaque SPI validator (`ObjectInfo.etag`, parsed via
    /// `parsing.etag_header`). Used ONLY to guard against version splicing by
    /// comparing the resumed response's `etag_header` — never sent as an HTTP
    /// `If-Match`, because on some backends it is not an RFC 7232 entity-tag
    /// (GCS maps `x-goog-generation` here; `If-Match: "<generation>"` 412s even
    /// for an unchanged object).
    validator: Option<String>,
    /// The first response's literal HTTP `ETag` header — a true RFC 7232
    /// entity-tag suitable for the resume `If-Match`. Distinct from
    /// `validator`: identical for S3 (`etag_header` == `ETag`), but different
    /// for GCS. `None` when the origin sent no `ETag`; the resume then relies
    /// on the `validator` comparison alone for its version guard.
    http_entity_tag: Option<String>,
    requested_end: Option<u64>,
    idempotent: bool,
}

/// Reissue the redirected request with `Range: bytes={from}-…`, picking up a
/// safely resumable failure at `from`. Guards against version splicing two
/// ways: (1) the resume `If-Match` carries the first response's HTTP
/// entity-tag (`ctx.http_entity_tag`) — NOT the opaque SPI `validator`, which
/// is not a wire ETag on every backend — and (2) the resumed response's
/// `etag_header` is re-compared against `validator`. A single-range `206` is
/// validated to start exactly at `from` (a multi-range/full-body answer is
/// handled by the caller). Re-mints an expired or origin-rejected (403)
/// redirect like the header phase.
async fn resume_response(
    ctx: &ResumeContext,
    from: u64,
    validator: &str,
) -> Result<reqwest::Response> {
    let resume_range = ByteRange {
        start: from,
        end_inclusive: ctx.requested_end,
    };
    let state = ctx.redirect.clone();
    let mint = ctx.mint.clone();
    let parsing = ctx.parsing.clone();
    let validator = validator.to_string();
    let http_entity_tag = ctx.http_entity_tag.clone();
    retry::with_http_retry_async(&ctx.retry_cfg, move |_attempt| {
        let state = state.clone();
        let mint = mint.clone();
        let parsing = parsing.clone();
        let validator = validator.clone();
        let http_entity_tag = http_entity_tag.clone();
        let resume_range = resume_range.clone();
        async move {
            let mut guard = state.lock().await;
            let (redirect, minted_once) = &mut *guard;
            if let Err(error) = fresh_redirect(redirect, mint.as_ref()).await {
                return retry::RetryStep::Failed(error);
            }
            let response = match send_streaming_request(
                redirect,
                Some(&resume_range),
                http_entity_tag.as_deref(),
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    return retry::RetryStep::RetryAfter(reqwest_transient_error(error), None);
                }
            };
            let status = response.status().as_u16();
            if status == 412 {
                // The object changed while the stream was mid-flight: a
                // resumed range would stitch bytes from two versions.
                return retry::RetryStep::Failed(Error::new(
                    ErrorCode::ObjectModified,
                    "object changed during a redirected read; refusing to resume across versions",
                ));
            }
            if status == 403
                && !*minted_once
                && let Some(mint) = mint.as_ref()
            {
                match mint().await {
                    Ok(fresh) => {
                        *redirect = fresh;
                        *minted_once = true;
                        return retry::RetryStep::RetryAfter(
                            Error::new(
                                ErrorCode::Transient,
                                "resume rejected (HTTP 403); re-minted a fresh redirect",
                            ),
                            Some(std::time::Duration::ZERO),
                        );
                    }
                    Err(error) => return retry::RetryStep::Failed(error),
                }
            }
            if http_status_is_retryable(status) {
                let hint = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .map(std::time::Duration::from_secs);
                return retry::RetryStep::RetryAfter(
                    Error::new(
                        ErrorCode::Transient,
                        format!("resume returned HTTP {status} (retryable)"),
                    ),
                    hint,
                );
            }
            if !response.status().is_success() {
                let headers: Vec<(String, String)> = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_string(), value.to_string()))
                    })
                    .collect();
                return retry::RetryStep::Failed(map_redirect_read_status(status, &headers, true));
            }
            // Guard the validator on the resumed response too. The initial
            // response supplied one (otherwise resume is disabled), so every
            // resumed response must repeat the configured header in a textual
            // form. If-Match is advisory on some origins; accepting an absent
            // or malformed validator could splice two object versions.
            let resumed_validator = parsing.etag_header.as_deref().and_then(|etag_header| {
                response
                    .headers()
                    .get(etag_header)
                    .and_then(|value| value.to_str().ok())
            });
            if resumed_validator
                .is_none_or(|resumed| resumed.trim_matches('"') != validator.trim_matches('"'))
            {
                return retry::RetryStep::Failed(Error::new(
                    ErrorCode::ObjectModified,
                    "resumed redirect did not repeat the original object validator; \
                     refusing to resume across versions",
                ));
            }
            if status == 206
                && let Err(error) =
                    validate_single_range_206(&response, from, resume_range.end_inclusive, "resume")
            {
                return retry::RetryStep::Failed(error);
            }
            retry::RetryStep::Done(response)
        }
    })
    .await
}

/// Prove that a `206 Partial Content` response is one complete requested span.
/// Both the initial response and every resumed response map their wire bytes
/// onto object-absolute offsets, so accepting a shifted, short-satisfied,
/// multipart, malformed, or length-inconsistent response would silently splice
/// or truncate the caller's stream.
fn validate_single_range_206(
    response: &reqwest::Response,
    expected_start: u64,
    requested_end: Option<u64>,
    phase: &str,
) -> Result<ParsedContentRange> {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if content_type.is_some_and(|value| {
        value
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("multipart/byteranges")
    }) {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{phase} response answered with a multipart/byteranges 206; \
                 cannot consume a multi-range response"
            ),
        ));
    }
    let parsed = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "{phase} 206 has a missing or malformed Content-Range; \
                     cannot verify byte alignment"
                ),
            )
        })?;
    if parsed.start != expected_start {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{phase} 206 started at byte {}, expected {expected_start}",
                parsed.start
            ),
        ));
    }
    let expected_end = match (requested_end, parsed.total) {
        (Some(requested), Some(total)) => requested.min(total - 1),
        (Some(requested), None) => requested,
        (None, Some(total)) => total - 1,
        (None, None) => parsed.end,
    };
    if parsed.end != expected_end {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{phase} 206 ended at byte {}, expected {expected_end}; \
                 refusing a partially satisfied range",
                parsed.end
            ),
        ));
    }
    let declared_span = parsed.end - parsed.start + 1;
    if response
        .content_length()
        .is_some_and(|length| length != declared_span)
    {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{phase} 206 Content-Length disagrees with its {declared_span}-byte Content-Range"
            ),
        ));
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedContentRange {
    start: u64,
    end: u64,
    total: Option<u64>,
}

/// Parse a satisfiable RFC 7233 `Content-Range` value
/// (`bytes <start>-<end>/<total>`; `<total>` may be `*`).
fn parse_content_range(value: &str) -> Option<ParsedContentRange> {
    let (unit, rest) = value.trim().split_once(char::is_whitespace)?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (span, total) = rest.trim().split_once('/')?;
    let (start, end) = span.trim().split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.trim().parse::<u64>().ok()?;
    if end < start {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        value => {
            let total = value.parse::<u64>().ok()?;
            if total == 0 || end >= total {
                return None;
            }
            Some(total)
        }
    };
    Some(ParsedContentRange { start, end, total })
}

/// The raw body stream with mid-stream resume. Distinguishes two
/// offsets so a resume can never re-emit or over-run delivered bytes:
///
/// - `response_cursor`: the object-absolute position of the next raw byte the
///   CURRENT response will produce. Reset per response (to the resume `from`
///   for a 206, to `0` when a resume is answered with a full body).
/// - `delivered_hwm`: a MONOTONIC high-water mark — one past the highest byte
///   already delivered to the caller. Every resume picks up from here (never
///   from the per-response cursor, which a full-body replay drags backwards),
///   and `skip_until` is never lowered below it, so an already-delivered
///   prefix is dropped exactly once under a single validator.
///
/// Independently, every response is bounded by `ctx.requested_end`: the final
/// chunk is truncated once the delivered offset would pass `requested_end + 1`,
/// so a resume answered with a full-body 200 after an initial 206 cannot run to
/// EOF past the caller's requested upper bound. The wire-integrity verifier
/// continues across responses; the already-delivered prefix of a full-body
/// replay is skipped without re-hashing.
fn resumable_body_stream(
    first: reqwest::Response,
    initial_offset: u64,
    initial_response_end: Option<u64>,
    verifier: StreamingVerifier,
    ctx: ResumeContext,
) -> ovstorage_plugin::ReadStream {
    use futures::StreamExt;
    let stream = async_stream::stream! {
        let mut verifier = verifier;
        // Next raw byte position expected from the CURRENT response.
        let mut response_cursor = initial_offset;
        // A 206 body must contain exactly the inclusive span declared by its
        // validated Content-Range, even when it uses chunked transfer framing.
        let mut response_end_exclusive =
            initial_response_end.map(|end| end.saturating_add(1));
        // One past the highest byte delivered to the caller. Monotonic: every
        // resume picks up here, and `skip_until` is never lowered below it.
        let mut delivered_hwm = initial_offset;
        // Raw positions below this were already delivered to the caller —
        // a full-body-answered resume re-transmits them; drop without
        // re-hashing. Never lowered (kept `>=` a prior value), so a full-body
        // replay that itself fails partway cannot lower the skip target and
        // re-emit already-delivered bytes.
        let mut skip_until = initial_offset;
        // Exclusive upper bound on delivered object bytes, when the caller
        // requested a closed range. `saturating_add` keeps an `end` of
        // `u64::MAX` from wrapping to 0 (it stays effectively unbounded).
        let end_exclusive = ctx.requested_end.map(|end| end.saturating_add(1));
        // Budgets are PER PHASE by design — header-phase attempts and
        // mid-stream resume attempts are independent failure modes:
        // `resumes_left` grants up to `max_attempts` resumes for this
        // stream, and each `resume_response` call below runs its own inner
        // `with_http_retry_async` loop over the same policy. Worst case is
        // therefore O(max_attempts²) origin hits for one pathologically
        // flaky read — bounded, but deliberately NOT one budget shared with
        // the header phase.
        let mut resumes_left = ctx.retry_cfg.max_attempts.max(1);
        let mut body = first.bytes_stream();
        loop {
            match body.next().await {
                Some(Ok(chunk)) => {
                    let mut chunk = chunk;
                    if response_end_exclusive.is_some_and(|expected| {
                        response_cursor.saturating_add(chunk.len() as u64) > expected
                    }) {
                        yield Err(Error::new(
                            ErrorCode::Internal,
                            "redirected 206 body exceeded its declared Content-Range",
                        ));
                        return;
                    }
                    // Drop the already-delivered prefix a full-body replay
                    // re-transmits.
                    if response_cursor < skip_until {
                        let to_skip =
                            (skip_until - response_cursor).min(chunk.len() as u64) as usize;
                        response_cursor += to_skip as u64;
                        chunk = chunk.slice(to_skip..);
                        if chunk.is_empty() {
                            continue;
                        }
                    }
                    // Bound the delivered bytes by the requested end: truncate
                    // the final chunk (and stop) once the cursor would pass
                    // `requested_end + 1`. Applies to EVERY response, so a
                    // full-body 200 answering a resume can't run to EOF.
                    let mut reached_end = false;
                    if let Some(end_exclusive) = end_exclusive {
                        if response_cursor >= end_exclusive {
                            reached_end = true;
                            chunk = chunk.slice(0..0);
                        } else if response_cursor + chunk.len() as u64 > end_exclusive {
                            let keep = (end_exclusive - response_cursor) as usize;
                            chunk = chunk.slice(..keep);
                            reached_end = true;
                        }
                    }
                    if !chunk.is_empty() {
                        verifier.update(&chunk);
                        response_cursor += chunk.len() as u64;
                        delivered_hwm = delivered_hwm.max(response_cursor);
                        yield Ok(chunk);
                    }
                    if reached_end {
                        if let Err(error) = verifier.finalize() {
                            yield Err(error);
                        }
                        return;
                    }
                }
                Some(Err(error)) => {
                    if !ctx.idempotent || resumes_left == 0 {
                        yield Err(reqwest_transient_error(error));
                        return;
                    }
                    let Some(validator) = ctx.validator.clone() else {
                        // Without a validator a resumed stream could splice
                        // bytes from a different object version — surface the
                        // failure instead.
                        yield Err(Error::new(
                            ErrorCode::Transient,
                            format!(
                                "redirected read failed mid-stream and cannot be \
                                 resumed safely (no response validator): {error}"
                            ),
                        ));
                        return;
                    };
                    resumes_left -= 1;
                    // Always resume from the delivered high-water mark, never
                    // from the per-response cursor.
                    let from = delivered_hwm;
                    match resume_response(&ctx, from, &validator).await {
                        Ok(response) => {
                            // Never lower the skip target (guards against a
                            // full-body replay that fails partway through).
                            skip_until = skip_until.max(from);
                            if response.status().as_u16() == 206 {
                                // `resume_response` validated the 206 starts at
                                // `from`; the cursor maps its leading byte there.
                                response_cursor = from;
                                response_end_exclusive = response
                                    .headers()
                                    .get(reqwest::header::CONTENT_RANGE)
                                    .and_then(|value| value.to_str().ok())
                                    .and_then(parse_content_range)
                                    .map(|range| range.end.saturating_add(1));
                            } else {
                                // Origin ignored Range: full body from 0; the
                                // skip logic drops the delivered prefix.
                                response_cursor = 0;
                                response_end_exclusive = None;
                            }
                            body = response.bytes_stream();
                        }
                        Err(resume_error) => {
                            yield Err(resume_error);
                            return;
                        }
                    }
                }
                None => {
                    if response_end_exclusive
                        .is_some_and(|expected| response_cursor != expected)
                    {
                        yield Err(Error::new(
                            ErrorCode::Transient,
                            "redirected 206 body ended before its declared Content-Range",
                        ));
                        return;
                    }
                    if let Err(error) = verifier.finalize() {
                        yield Err(error);
                    }
                    return;
                }
            }
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
    /// Build a verifier only when the bytes consumed by the raw response
    /// stream are provably the whole object. Cloud checksum headers such as
    /// GCS `x-goog-hash` describe the whole object even on a 206, so comparing
    /// one selected range against them would manufacture a mismatch.
    fn for_streaming_response(
        parsing: &ResponseParsing,
        headers: &[(String, String)],
        status: u16,
        requested_range: Option<&ByteRange>,
    ) -> Self {
        let whole_object = if status == 206 {
            header_value(headers, Some("content-range"))
                .and_then(parse_content_range)
                .is_some_and(|range| {
                    range.start == 0
                        && range
                            .total
                            .is_some_and(|total| range.end.checked_add(1) == Some(total))
                })
        } else {
            // A closed range makes the resume stream stop at the requested
            // upper bound even when an origin answers 200 with a full body.
            // An open-ended range consumes the full raw response, so a
            // whole-object checksum can still be verified before slicing.
            requested_range.is_none_or(|range| range.end_inclusive.is_none())
        };
        if !whole_object {
            return Self::Inactive;
        }
        Self::for_response(parsing, headers)
    }

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
    Buffered(Arc<Vec<u8>>),
    /// A seekable file (local spool or `Body::LocalFile`). Per-part seek+read
    /// keeps memory O(part), preserves arbitrary offsets, and allows per-part
    /// HTTP retry — unlike `Stream`, which is one-shot and contiguous-only.
    SeekableFile(std::path::PathBuf),
    Stream(BodyStream),
}

pub(crate) async fn write_body_from(body: Body) -> Result<WriteBody> {
    match body {
        Body::Bytes(bytes) => Ok(WriteBody::Buffered(Arc::new(bytes))),
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
            follow_buffered_write_redirects(bytes.as_slice(), batch, retry_cfg).await
        }
        WriteBody::SeekableFile(path) => {
            follow_seekable_write_redirects(&path, batch, retry_cfg).await
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
        ensure_write_redirect_valid(redirect)?;
        let request_body = redirect_body_bytes(body, &redirect.body_source)?;
        // Buffered bodies are replayable; the inner helper short-
        // circuits non-idempotent verbs.
        let result = execute_redirect_request_with_retry(
            &redirect.request,
            &request_body,
            redirect.result_capture.body_max_bytes,
            retry_cfg,
        )
        .await?;
        results.push(capture_redirect_result(result, &redirect.result_capture));
    }
    Ok(RedirectResultBatch { results })
}

/// Drive a seekable file body (local spool or `Body::LocalFile`) through a
/// write-redirect batch. Each `UserBytes` part is **streamed** from the file at
/// its declared offset (`bounded_file_stream`) rather than read whole into a
/// buffer, so peak memory is one chunk even when a single part covers the entire
/// multi-GiB body — while still supporting arbitrary offsets (seek) and per-part
/// HTTP retry (the stream is re-created, i.e. the file re-read, per attempt).
/// This matches the buffered-path semantics (offsets + retry) without the
/// buffered path's O(part) memory. `Empty`/`Inline` parts are tiny and already
/// in memory, so they take the buffered execute path.
async fn follow_seekable_write_redirects(
    path: &std::path::Path,
    batch: &WriteRedirectBatch,
    retry_cfg: &retry::RetryConfig,
) -> Result<RedirectResultBatch> {
    // The file length backs an upfront range check so a plugin-supplied range
    // that exceeds the body surfaces `InvalidArgument` directly, rather than as
    // a `Transient` buried in the streamed body (which would spuriously retry).
    let file_len = std::fs::metadata(path).map_err(io_error)?.len();
    let mut results = Vec::with_capacity(batch.redirects.len());
    for redirect in &batch.redirects {
        ensure_write_redirect_valid(redirect)?;
        let result = match &redirect.body_source {
            RedirectBodySource::Empty => {
                execute_redirect_request_with_retry(
                    &redirect.request,
                    &[],
                    redirect.result_capture.body_max_bytes,
                    retry_cfg,
                )
                .await?
            }
            RedirectBodySource::Inline(bytes) => {
                execute_redirect_request_with_retry(
                    &redirect.request,
                    bytes,
                    redirect.result_capture.body_max_bytes,
                    retry_cfg,
                )
                .await?
            }
            RedirectBodySource::UserBytes { offset, len } => {
                let end = offset.checked_add(*len).ok_or_else(|| {
                    Error::new(ErrorCode::InvalidArgument, "redirect body range overflows")
                })?;
                if end > file_len {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "redirect body range exceeds the write body",
                    ));
                }
                let path = path.to_path_buf();
                let (offset, len) = (*offset, *len);
                execute_streaming_request_with_retry(
                    &redirect.request,
                    len,
                    redirect.result_capture.body_max_bytes,
                    retry_cfg,
                    move || bounded_file_stream(&path, offset, len),
                )
                .await?
            }
        };
        results.push(capture_redirect_result(result, &redirect.result_capture));
    }
    Ok(RedirectResultBatch { results })
}

/// A [`BodyStream`] over exactly `len` bytes of `path` starting at `offset`,
/// yielded in 64 KiB chunks — O(chunk) memory regardless of `len`. Re-openable
/// per call, so a retry re-creates it from a fresh handle (the seekable body is
/// replayable). A file shorter than `offset + len` (e.g. truncated concurrently
/// after the caller's upfront check) surfaces `InvalidArgument`.
fn bounded_file_stream(path: &std::path::Path, offset: u64, len: u64) -> Result<BodyStream> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(io_error)?;
    file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
    let mut remaining = len;
    Ok(BodyStream::from_iter(std::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        let want = remaining.min(64 * 1024) as usize;
        let mut buf = vec![0u8; want];
        match file.read(&mut buf) {
            Ok(0) => Some(Err(Error::new(
                ErrorCode::InvalidArgument,
                "redirect body range exceeds the write body",
            ))),
            Ok(n) => {
                buf.truncate(n);
                remaining -= n as u64;
                Some(Ok(buf))
            }
            Err(err) => Some(Err(io_error(err))),
        }
    })))
}

/// Drive a `Body::Stream` through a write-redirect batch. UserBytes parts are
/// **streamed** (never buffered whole): each part is a bounded sub-stream of
/// exactly its declared `len` bytes, sent with an explicit `Content-Length`
/// (redirect targets such as S3 UploadPart reject chunked bodies). A chunk
/// that straddles a part boundary is split — the head finishes the current
/// part and the tail is carried into the next — so the plugin need not size
/// chunks to align with part boundaries. Parts must be contiguous and
/// ascending in offset (a stream cannot be rewound); a gap or rewind is a
/// plugin contract violation (`InvalidArgument`), and a stream that ends
/// before a part's `len` is a short body (`InvalidArgument`). Peak memory is
/// one chunk, regardless of declared part sizes.
async fn follow_streaming_write_redirects(
    stream: BodyStream,
    batch: &WriteRedirectBatch,
) -> Result<RedirectResultBatch> {
    if batch.redirects.is_empty() {
        return Ok(RedirectResultBatch {
            results: Vec::new(),
        });
    }

    if batch.redirects.len() == 1 {
        let redirect = &batch.redirects[0];
        ensure_write_redirect_valid(redirect)?;
        match &redirect.body_source {
            RedirectBodySource::Empty => {
                let result = execute_redirect_request(
                    &redirect.request,
                    &[],
                    redirect.result_capture.body_max_bytes,
                )
                .await?;
                return Ok(RedirectResultBatch {
                    results: vec![capture_redirect_result(result, &redirect.result_capture)],
                });
            }
            RedirectBodySource::Inline(bytes) => {
                let result = execute_redirect_request(
                    &redirect.request,
                    bytes,
                    redirect.result_capture.body_max_bytes,
                )
                .await?;
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
                let source = Arc::new(Mutex::new(CarrySource {
                    stream,
                    carry: bytes::Bytes::new(),
                    consumed: 0,
                    error: None,
                }));
                let bounded = carry_part_stream(Arc::clone(&source), *len);
                let result = match execute_streaming_request(
                    &redirect.request,
                    bounded,
                    Some(*len),
                    redirect.result_capture.body_max_bytes,
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => {
                        let stored = source
                            .lock()
                            .expect("carry source mutex poisoned")
                            .error
                            .take();
                        return Err(stored.unwrap_or(error));
                    }
                };
                drain_carry_source_to(Arc::clone(&source), *len).await?;
                ensure_carry_source_eof(
                    source,
                    "write body is longer than the single redirect length",
                )
                .await?;
                return Ok(RedirectResultBatch {
                    results: vec![capture_redirect_result(result, &redirect.result_capture)],
                });
            }
        }
    }

    // Multipart: stream each part as a bounded sub-stream drawn from one shared
    // source, splitting a straddling chunk and carrying the remainder to the
    // next part. Offsets must be contiguous and ascending — a stream can't be
    // rewound.
    let source = Arc::new(Mutex::new(CarrySource {
        stream,
        carry: bytes::Bytes::new(),
        consumed: 0,
        error: None,
    }));
    let mut cursor: u64 = 0;
    let mut saw_user_bytes = false;
    let mut results = Vec::with_capacity(batch.redirects.len());
    for redirect in &batch.redirects {
        ensure_write_redirect_valid(redirect)?;
        let result = match &redirect.body_source {
            RedirectBodySource::Empty => {
                execute_redirect_request(
                    &redirect.request,
                    &[],
                    redirect.result_capture.body_max_bytes,
                )
                .await?
            }
            RedirectBodySource::Inline(bytes) => {
                execute_redirect_request(
                    &redirect.request,
                    bytes,
                    redirect.result_capture.body_max_bytes,
                )
                .await?
            }
            RedirectBodySource::UserBytes { offset, len } => {
                saw_user_bytes = true;
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
                let part = carry_part_stream(Arc::clone(&source), *len);
                let result = match execute_streaming_request(
                    &redirect.request,
                    part,
                    Some(*len),
                    redirect.result_capture.body_max_bytes,
                )
                .await
                {
                    Ok(result) => result,
                    Err(error) => {
                        // Prefer the sub-stream's own error (e.g. an
                        // `InvalidArgument` short body — a permanent contract
                        // violation) over the generic `Transient` the reqwest
                        // layer maps a mid-body stream failure to, so a retry
                        // isn't attempted against an already-consumed stream.
                        let stored = source
                            .lock()
                            .expect("carry source mutex poisoned")
                            .error
                            .take();
                        return Err(stored.unwrap_or(error));
                    }
                };
                cursor += *len;
                // The part's request may have completed (any HTTP status,
                // including an early-abort 4xx/5xx) without draining the whole
                // body. Realign the shared source to `cursor` before the next
                // part, or the next part's sub-stream would forward this part's
                // leftover bytes under the next part's Content-Length.
                drain_carry_source_to(Arc::clone(&source), cursor).await?;
                result
            }
        };
        results.push(capture_redirect_result(result, &redirect.result_capture));
    }
    // A source longer than the summed declared part lengths would silently drop
    // its surplus, letting a truncated object commit — reject a non-empty
    // residual (leftover carry or an undrained trailing chunk). Only when
    // the stream actually backed at least one part; an all-`Empty`/`Inline`
    // batch never draws from it and must not be newly rejected.
    // The trailing `next_chunk` (checking for surplus) can block on the write
    // body's `recv_blocking`, so run the probe on the blocking pool rather than
    // an async worker (same hazard as the deficit drain above).
    if saw_user_bytes {
        ensure_carry_source_eof(
            source,
            "write body is longer than the summed multipart redirect part lengths",
        )
        .await?;
    }
    Ok(RedirectResultBatch { results })
}

/// Consume any declared bytes that the HTTP client did not pull because the
/// origin returned a response before draining the request body. This validates
/// short streams and realigns multipart parts without blocking an async worker.
async fn drain_carry_source_to(source: Arc<Mutex<CarrySource>>, target: u64) -> Result<()> {
    let deficit = {
        let guard = source.lock().expect("carry source mutex poisoned");
        target.saturating_sub(guard.consumed)
    };
    if deficit == 0 {
        return Ok(());
    }
    tokio::task::spawn_blocking(move || {
        let mut drain = carry_part_stream(source, deficit);
        while let Some(item) = drain.next_chunk() {
            item?;
        }
        Ok::<(), Error>(())
    })
    .await
    .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?
}

/// Prove that a streamed write body reaches true EOF after its declared
/// `UserBytes` ranges. Empty chunks do not mean EOF, a non-empty chunk is
/// surplus, and a terminal source error must be surfaced rather than collapsed
/// into a clean end-of-body. The probe runs on the blocking pool because host
/// streams may use a blocking channel receive in `next_chunk`.
async fn ensure_carry_source_eof(
    source: Arc<Mutex<CarrySource>>,
    surplus_message: &'static str,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut guard = source.lock().expect("carry source mutex poisoned");
        if !guard.carry.is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, surplus_message));
        }
        loop {
            match guard.stream.next_chunk() {
                None => return Ok(()),
                Some(Ok(chunk)) if chunk.is_empty() => continue,
                Some(Ok(_)) => {
                    return Err(Error::new(ErrorCode::InvalidArgument, surplus_message));
                }
                Some(Err(error)) => return Err(error),
            }
        }
    })
    .await
    .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?
}

/// Shared, stateful source for multipart streaming: owns the write body stream
/// and any bytes split off a chunk that straddled the previous part's length
/// boundary (the `carry`, which fronts the next part). Multipart parts are
/// driven strictly in sequence (each part's request drains before the next
/// begins), so the mutex is uncontended — it exists only to hand the source
/// between the per-part sub-streams while keeping each `'static + Send`.
struct CarrySource {
    stream: BodyStream,
    /// Bytes split off the previous part's straddling chunk, forwarded first
    /// on the next part. `bytes::Bytes` so the front-split is a cheap refcount
    /// slice rather than a copy.
    carry: bytes::Bytes,
    /// Total bytes actually pulled from this source (carry + stream) across all
    /// parts. Compared against the sum of declared part lengths after each part
    /// so a part whose request aborted before draining its body (e.g. an
    /// early-abort 4xx/5xx) is detected and realigned, rather than forwarding
    /// its leftover bytes into the next part.
    consumed: u64,
    /// The sub-stream's own terminal error (e.g. an `InvalidArgument` short
    /// body), stashed so a failed `send()` can surface it instead of the
    /// generic `Transient` the reqwest layer produces.
    error: Option<Error>,
}

/// A bounded sub-stream forwarding exactly `len` bytes from the shared
/// multipart `source`. The carry (bytes split off the previous part) is
/// forwarded first; then chunks are pulled from the underlying stream, and a
/// chunk that would overshoot the part boundary is split — its head finishes
/// this part and its tail becomes the source's carry for the next part. EOF
/// before `len` is a short body (`InvalidArgument`). Never buffers more than
/// one chunk.
fn carry_part_stream(source: Arc<Mutex<CarrySource>>, len: u64) -> BodyStream {
    let mut produced: u64 = 0;
    BodyStream::from_iter(std::iter::from_fn(move || {
        if produced >= len {
            return None;
        }
        let remaining = (len - produced) as usize;
        let mut guard = source.lock().expect("carry source mutex poisoned");
        // Forward the carry (the previous part's straddling tail) first.
        if !guard.carry.is_empty() {
            let take = remaining.min(guard.carry.len());
            let head = guard.carry.split_to(take);
            produced += take as u64;
            guard.consumed += take as u64;
            return Some(Ok(head.to_vec()));
        }
        match guard.stream.next_chunk() {
            None => {
                let err = Error::new(
                    ErrorCode::InvalidArgument,
                    format!("stream ended after {produced} bytes; redirect part requested {len}"),
                );
                guard.error = Some(err.clone());
                Some(Err(err))
            }
            Some(Err(err)) => {
                guard.error = Some(err.clone());
                Some(Err(err))
            }
            Some(Ok(chunk)) => {
                if chunk.len() <= remaining {
                    produced += chunk.len() as u64;
                    guard.consumed += chunk.len() as u64;
                    Some(Ok(chunk))
                } else {
                    // Straddling chunk: forward the head, carry the tail into
                    // the source for the next part.
                    let chunk = bytes::Bytes::from(chunk);
                    let head = chunk.slice(..remaining);
                    guard.carry = chunk.slice(remaining..);
                    produced += remaining as u64;
                    guard.consumed += remaining as u64;
                    Some(Ok(head.to_vec()))
                }
            }
        }
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
    response_body_max_bytes: u32,
    retry_cfg: &retry::RetryConfig,
) -> Result<RedirectResult> {
    if !http_method_is_idempotent(&request.method) {
        return execute_redirect_request(request, body, response_body_max_bytes).await;
    }
    retry::with_http_retry_async(retry_cfg, |_attempt| async {
        match execute_redirect_request(request, body, response_body_max_bytes).await {
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

/// The streaming counterpart of [`execute_redirect_request_with_retry`]: drives
/// a streaming request and, on an idempotent verb, retries retryable HTTP
/// statuses / transient errors by re-creating the body with `make_stream` (a
/// fresh, rewound read) on each attempt. `content_length` frames the request
/// explicitly (redirect targets such as S3 UploadPart reject chunked bodies). A
/// non-idempotent verb makes a single attempt. A `make_stream` failure (the
/// local re-read itself failing) is terminal — it won't self-heal within the
/// retry window.
async fn execute_streaming_request_with_retry(
    request: &HttpRequest,
    content_length: u64,
    response_body_max_bytes: u32,
    retry_cfg: &retry::RetryConfig,
    mut make_stream: impl FnMut() -> Result<BodyStream>,
) -> Result<RedirectResult> {
    if !http_method_is_idempotent(&request.method) {
        let stream = make_stream()?;
        return execute_streaming_request(
            request,
            stream,
            Some(content_length),
            response_body_max_bytes,
        )
        .await;
    }
    retry::with_http_retry_async(retry_cfg, |_attempt| {
        // Re-created per attempt so a retry sends the body from the start.
        let stream = make_stream();
        async move {
            let stream = match stream {
                Ok(stream) => stream,
                Err(error) => return retry::RetryStep::Failed(error),
            };
            match execute_streaming_request(
                request,
                stream,
                Some(content_length),
                response_body_max_bytes,
            )
            .await
            {
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

pub(crate) fn ensure_read_redirect_valid(redirect: &ReadRedirect) -> Result<()> {
    ensure_redirect_fresh(redirect.expires_at)?;
    let method =
        reqwest::Method::from_bytes(redirect.request.method.as_bytes()).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("redirect HTTP method is invalid: {error}"),
            )
        })?;
    if method != reqwest::Method::GET && method != reqwest::Method::HEAD {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "read redirect method '{}' is not permitted",
                redirect.request.method
            ),
        ));
    }
    ensure_redirect_scope(
        &redirect.request.url,
        &redirect.scope,
        redirect.scope.operations.read,
        "read",
    )
}

fn ensure_write_redirect_valid(redirect: &WriteRedirect) -> Result<()> {
    ensure_redirect_fresh(redirect.expires_at)?;
    let method =
        reqwest::Method::from_bytes(redirect.request.method.as_bytes()).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("redirect HTTP method is invalid: {error}"),
            )
        })?;
    if method != reqwest::Method::PUT
        && method != reqwest::Method::POST
        && method != reqwest::Method::PATCH
    {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "write redirect method '{}' is not permitted",
                redirect.request.method
            ),
        ));
    }
    ensure_redirect_scope(
        &redirect.request.url,
        &redirect.scope,
        redirect.scope.operations.write,
        "write",
    )
}

/// Validate the capability carried beside a redirect before any network or
/// filesystem access. Parsing both URLs canonicalizes dot segments, and the
/// origin-plus-path comparison prevents textual-prefix tricks such as
/// `bucket.example.evil` or `/allowed/../outside`.
fn ensure_redirect_scope(
    request_url: &str,
    scope: &RedirectScope,
    operation_allowed: bool,
    operation: &str,
) -> Result<()> {
    ensure_redirect_fresh(scope.expires_at)?;
    if !operation_allowed {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!("redirect scope does not permit {operation}"),
        ));
    }
    if scope.physical_url_prefix.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "redirect scope physical_url_prefix is empty",
        ));
    }
    let request = url::Url::parse(request_url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    let mut prefix = url::Url::parse(&scope.physical_url_prefix).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect scope physical_url_prefix is invalid: {error}"),
        )
    })?;
    // Several redirect producers use the complete presigned target as the
    // physical prefix. Query parameters and fragments do not participate in
    // the authority/path scope, so normalize them away instead of rejecting a
    // valid signed redirect.
    prefix.set_query(None);
    prefix.set_fragment(None);

    let same_authority = request.scheme() == prefix.scheme()
        && request.username() == prefix.username()
        && request.password() == prefix.password()
        && request.host_str() == prefix.host_str()
        && request.port_or_known_default() == prefix.port_or_known_default();
    let path_matches = if request.scheme() == "file" && prefix.scheme() == "file" {
        // Scope file redirects in the same decoded representation used by
        // `to_file_path`. An encoded separator such as `%2F` can otherwise
        // pass the URL-path prefix check and decode into `../` traversal when
        // the file arm opens it.
        let request_path = request
            .to_file_path()
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, "file redirect URL is invalid"))?;
        let prefix_path = prefix.to_file_path().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "file redirect scope physical_url_prefix is invalid",
            )
        })?;
        let contains_parent = |path: &std::path::Path| {
            path.components()
                .any(|component| component == std::path::Component::ParentDir)
        };
        let lexically_scoped = !contains_parent(&request_path)
            && !contains_parent(&prefix_path)
            && (request_path == prefix_path || request_path.starts_with(&prefix_path));
        if lexically_scoped {
            // A lexical descendant can still escape through a symlinked parent
            // (for example, allowed/out -> /etc). Reject every existing
            // descendant component that is a symlink before the file arm can
            // follow it. PUT may safely replace a symlink at the final target
            // via atomic rename, so only read inspects the leaf itself.
            ensure_no_symlinked_file_descendant(&prefix_path, &request_path, operation == "read")?;
        }
        lexically_scoped
    } else {
        let prefix_path = prefix.path();
        let request_path = request.path();
        request_path == prefix_path
            || request_path
                .strip_prefix(prefix_path)
                .is_some_and(|suffix| prefix_path.ends_with('/') || suffix.starts_with('/'))
    };
    if !same_authority || !path_matches {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            "redirect URL falls outside its physical_url_prefix scope",
        ));
    }
    Ok(())
}

fn ensure_no_symlinked_file_descendant(
    prefix: &std::path::Path,
    request: &std::path::Path,
    inspect_leaf: bool,
) -> Result<()> {
    let relative = request.strip_prefix(prefix).map_err(|_| {
        Error::new(
            ErrorCode::PermissionDenied,
            "file redirect falls outside its physical root",
        )
    })?;
    let mut components: Vec<_> = relative.components().collect();
    if !inspect_leaf {
        components.pop();
    }
    let mut current = prefix.to_path_buf();
    for component in components {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::new(
                    ErrorCode::PermissionDenied,
                    "file redirect scope does not permit symlink traversal",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Once an ancestor is absent, no deeper component exists yet.
                break;
            }
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

pub(crate) fn read_redirect_is_safely_delegable(redirect: &ReadRedirect) -> bool {
    redirect_is_delegable(redirect.scope.credential, &redirect.request.headers)
}

/// Convert a reqwest failure without retaining its request URL. `Error::new`
/// also scans arbitrary text for embedded credentials, covering nested source
/// messages while the primary signed URL is removed at the source.
fn reqwest_transient_error(error: reqwest::Error) -> Error {
    let message = error.without_url().to_string();
    Error::new(ErrorCode::Transient, redact_message(&message).into_owned())
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

/// Dispatch a buffered redirect by URL scheme.
///
/// `http` and `https` share the one reqwest client, so every framing header —
/// `Host` above all — is derived from the URL authority. That matters because a
/// presigned redirect signs `host` (including a non-default port) into the
/// signature: an origin that recomputes the canonical request, as MinIO does,
/// rejects any replay whose `Host` disagrees with the signed value.
pub(crate) async fn execute_redirect_request(
    request: &HttpRequest,
    body: &[u8],
    response_body_max_bytes: u32,
) -> Result<RedirectResult> {
    let url = url::Url::parse(&request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    match url.scheme() {
        "file" => execute_file_redirect(request, &url, body).await,
        "http" | "https" => execute_reqwest_redirect(request, body, response_body_max_bytes).await,
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
    captured_body_is_complete: bool,
) -> ObjectInfo {
    let size = if result.status_code == 206 {
        // Content-Length on a 206 is the selected span, not the object. The
        // validated Content-Range total is the only trustworthy object size.
        header_value(&result.captured_headers, Some("content-range"))
            .and_then(parse_content_range)
            .and_then(|range| range.total)
    } else {
        header_value(&result.captured_headers, parsing.size_header.as_deref())
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| captured_body_is_complete.then_some(result.captured_body.len() as u64))
    };
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

/// Offset `UNIX_EPOCH` by a signed second count plus nanoseconds, yielding
/// `None` when the instant falls outside the platform's representable range.
///
/// `SystemTime`'s `Add`/`Sub` panic on overflow, and the seconds arrive from an
/// origin-controlled response header — Windows' `FILETIME` epoch is 1601, so a
/// year-1000 timestamp is unrepresentable there while parsing fine here.
fn system_time_from_unix(seconds: i64, nanos: u32) -> Option<SystemTime> {
    let whole = if seconds >= 0 {
        UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds as u64))
    } else {
        UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(seconds.unsigned_abs()))
    }?;
    whole.checked_add(std::time::Duration::from_nanos(u64::from(nanos)))
}

pub(crate) fn parse_mtime(value: &str, format: MtimeFormat) -> Option<SystemTime> {
    match format {
        MtimeFormat::UnixSeconds => value
            .parse::<u64>()
            .ok()
            .and_then(|seconds| UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds))),
        MtimeFormat::Rfc1123 => httpdate::parse_http_date(value).ok(),
        MtimeFormat::Iso8601 => time::OffsetDateTime::parse(
            value,
            &time::format_description::well_known::Iso8601::DEFAULT,
        )
        .ok()
        .and_then(|datetime| {
            system_time_from_unix(datetime.unix_timestamp(), datetime.nanosecond())
        }),
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
            // Use the same O_EXCL staging + atomic rename primitive as the
            // streamed arm. Writing in place would follow a pre-existing
            // destination symlink and could leave a truncated file on error.
            let stream = BodyStream::from_iter(vec![Ok(body.to_vec())].into_iter());
            execute_file_streaming_request(request, url, stream).await
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

/// `file://` streams chunk-by-chunk to disk; http/https stream the body with
/// an explicit `Content-Length` when `content_length` is known (redirect
/// targets such as S3 UploadPart reject chunked transfer encoding), falling
/// back to chunked when it is `None`.
async fn execute_streaming_request(
    request: &HttpRequest,
    stream: BodyStream,
    content_length: Option<u64>,
    response_body_max_bytes: u32,
) -> Result<RedirectResult> {
    let url = url::Url::parse(&request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect URL is invalid: {error}"),
        )
    })?;
    match url.scheme() {
        "file" => execute_file_streaming_request(request, &url, stream).await,
        "http" | "https" => {
            execute_reqwest_streaming_request(
                request,
                stream,
                content_length,
                response_body_max_bytes,
            )
            .await
        }
        scheme => Err(Error::new(
            ErrorCode::Unsupported,
            format!("streaming redirect scheme '{scheme}' is not supported"),
        )),
    }
}

async fn execute_file_streaming_request(
    request: &HttpRequest,
    url: &url::Url,
    stream: BodyStream,
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
    // Stage + atomically rename off the runtime (the `BodyStream` iterator is
    // blocking): a short/errored/cancelled body never leaves a partial prefix
    // at the target, and the staging file is an O_EXCL temp with restrictive
    // perms whose RAII guard removes it unless the write completes cleanly.
    tokio::task::spawn_blocking(move || write_streamed_file_atomically(&path, stream))
        .await
        .map_err(|err| Error::new(ErrorCode::Internal, err.to_string()))??;
    Ok(RedirectResult {
        status_code: 200,
        captured_headers: Vec::new(),
        captured_body: Vec::new(),
    })
}

/// Stream `stream` to a randomized same-directory temp file and atomically
/// rename it onto `path`. Security properties (hardening, matching
/// `SpooledReplayBody`):
///
/// - The staging file is a `tempfile::NamedTempFile` — `O_EXCL` on a random
///   name (0600), so a local attacker cannot pre-create it as a symlink and
///   have the follower truncate an arbitrary target (the old predictable
///   `.name.ovstaging-<pid>-<seq>` opened with `File::create` did exactly
///   that). The temp is created via the crate's collision-retry loop, so PID
///   reuse is a non-issue.
/// - The `NamedTempFile` is an armed RAII guard: on any early return (short
///   body, chunk error, panic, cancellation) it drops and removes the staged
///   bytes. It is disarmed only by `persist`, after a clean full-length write.
/// - `persist` renames over `path`, replacing whatever is there (a regular
///   file or a symlink) with our regular file; it never writes *through* an
///   existing symlink, so a symlinked destination's target is left untouched.
/// - An atomic rename swaps inodes, which would drop the prior file's mode; to
///   avoid a silent `0600 -> 0644` downgrade the destination's existing mode is
///   copied onto the temp before the rename (regular-file destinations only —
///   a symlinked destination has no meaningful mode to carry over).
fn write_streamed_file_atomically(path: &std::path::Path, mut stream: BodyStream) -> Result<()> {
    use std::io::Write as _;
    // Same directory as the destination so the final rename is atomic (same
    // filesystem). An empty parent (a bare file name) means the current dir.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut temp = tempfile::NamedTempFile::new_in(&parent).map_err(io_error)?;
    loop {
        match stream.next_chunk() {
            None => break,
            // The `NamedTempFile` guard removes the staged bytes on this
            // early return.
            Some(Err(err)) => return Err(err),
            Some(Ok(bytes)) => temp.as_file_mut().write_all(&bytes).map_err(io_error)?,
        }
    }
    temp.as_file_mut().flush().map_err(io_error)?;
    temp.as_file_mut().sync_all().map_err(io_error)?;
    // Preserve the destination's existing mode across the inode swap. Use
    // `symlink_metadata` (no follow) so a symlinked destination is recognized
    // as such and skipped — we do not copy an unrelated target's mode.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_file()
    {
        use std::os::unix::fs::PermissionsExt as _;
        // Copy only the rwx permission bits (`& 0o777`); never propagate the
        // setuid/setgid/sticky bits (`0o7000`) from the pre-existing destination
        // onto the freshly downloaded, externally-influenced content. Carrying
        // them across the atomic inode swap of a pre-seeded setuid destination
        // would be a privilege-escalation primitive. Mirrors the mask
        // already applied on the local-materialize path (redirect.rs:3259).
        let mode = meta.permissions().mode() & 0o777;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(io_error)?;
    }
    // Atomic rename; only reached after a clean full-length write. `persist`
    // consumes (disarms) the RAII guard, and on failure the returned error
    // still owns the temp, which is then dropped and removed.
    temp.persist(path).map_err(|err| io_error(err.error))?;
    Ok(())
}

async fn execute_reqwest_streaming_request(
    request: &HttpRequest,
    stream: BodyStream,
    content_length: Option<u64>,
    response_body_max_bytes: u32,
) -> Result<RedirectResult> {
    let declared_content_length =
        validate_redirect_content_length(&request.headers, content_length)?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect HTTP method is invalid: {error}"),
        )
    })?;
    let body = reqwest::Body::wrap_stream(body_stream_to_async(stream));
    let mut builder = redirect_client().request(method, &request.url);
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(name, value);
    }
    // A wrapped stream has unknown length, so reqwest defaults to chunked
    // transfer encoding. Add the known length only when the redirect did not
    // provide one. A redirect-provided value was validated above and is replayed
    // verbatim because it may be covered by a signature.
    if let Some(len) = content_length
        && declared_content_length.is_none()
    {
        builder = builder.header(reqwest::header::CONTENT_LENGTH, len);
    }
    let response = builder
        .body(body)
        .send()
        .await
        .map_err(reqwest_transient_error)?;
    response_to_redirect_result(response, response_body_max_bytes).await
}

pub(crate) async fn execute_reqwest_redirect(
    request: &HttpRequest,
    body: &[u8],
    response_body_max_bytes: u32,
) -> Result<RedirectResult> {
    validate_redirect_content_length(&request.headers, Some(body.len() as u64))?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect HTTP method is invalid: {error}"),
        )
    })?;
    let mut builder = redirect_client().request(method, &request.url);
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(name, value);
    }
    let response = builder
        .body(body.to_vec())
        .send()
        .await
        .map_err(reqwest_transient_error)?;
    response_to_redirect_result(response, response_body_max_bytes).await
}

/// Validate a redirect-provided `Content-Length` before constructing a request.
/// Exactly one literal value may be supplied. When the body length is known,
/// the literal must parse to that value; callers still replay the original text
/// because a presigned request may include it in its signature.
fn validate_redirect_content_length(
    headers: &[(String, String)],
    expected: Option<u64>,
) -> Result<Option<&str>> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "redirect must provide exactly one Content-Length header",
        ));
    }
    // RFC 9110 `Content-Length` is `1*DIGIT`: Rust's integer parser is looser
    // (it accepts a leading `+`), so screen the digits before parsing rather
    // than letting a malformed value reach reqwest or the origin.
    let trimmed = value.trim();
    let declared = if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        None
    } else {
        trimmed.parse::<u64>().ok()
    };
    let declared = declared.ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect Content-Length '{value}' is not a length"),
        )
    })?;
    if let Some(expected) = expected
        && declared != expected
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("redirect Content-Length {declared} disagrees with the {expected} byte body"),
        ));
    }
    Ok(Some(value))
}

async fn response_to_redirect_result(
    response: reqwest::Response,
    body_max_bytes: u32,
) -> Result<RedirectResult> {
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
    let max = usize::try_from(body_max_bytes).unwrap_or(usize::MAX);
    let mut captured_body = Vec::with_capacity(max.min(64 * 1024));
    if max > 0 {
        use futures::StreamExt as _;
        let mut body = response.bytes_stream();
        while captured_body.len() < max {
            let Some(chunk) = body.next().await else {
                break;
            };
            let chunk = chunk.map_err(reqwest_transient_error)?;
            let remaining = max - captured_body.len();
            captured_body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
        // Dropping the stream here aborts any unread response bytes. The
        // capture limit is a memory and work bound, not post-hoc truncation.
    }
    Ok(RedirectResult {
        status_code,
        captured_headers,
        captured_body,
    })
}

// `body_stream_from_file` (64 KiB chunked `Body::LocalFile` streamer) and
// `io_error` live in `ovstorage-layer` so native backend plugins can reuse
// them. These crate-local re-exports keep wrapper and built-in backend imports
// concise.
pub(crate) use ovstorage_layer::{body_stream_from_file, io_error};

fn synthesize_file_etag(size: u64, mtime: Option<SystemTime>) -> String {
    ovstorage_layer::synthesize_file_etag(size, mtime)
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
    fn closed_range_skips_whole_object_checksum_verification() {
        let parsing = parsing_with_sha256("x-test-checksum");
        let headers = vec![
            ("x-test-checksum".to_string(), ABCD_SHA256_HEX.to_string()),
            ("content-range".to_string(), "bytes 0-1/4".to_string()),
        ];
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(1),
        };

        let mut verifier =
            StreamingVerifier::for_streaming_response(&parsing, &headers, 206, Some(&range));
        verifier.update(b"ab");
        verifier
            .finalize()
            .expect("a whole-object checksum cannot reject a selected range");
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
        let info =
            redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result, true);
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
        let info =
            redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result, true);
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
        let info =
            redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result, true);
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

    #[test]
    fn redirect_info_uses_content_range_total_for_partial_response_size() {
        let parsing = ResponseParsing {
            size_header: Some("content-length".into()),
            ..ResponseParsing::default()
        };
        let result = RedirectResult {
            status_code: 206,
            captured_headers: vec![
                ("content-length".into(), "10".into()),
                ("content-range".into(), "bytes 100-109/1000".into()),
            ],
            captured_body: Vec::new(),
        };

        let info =
            redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result, false);

        assert_eq!(info.size, Some(1000));
    }

    #[test]
    fn header_only_chunked_response_has_unknown_size() {
        let parsing = ResponseParsing {
            size_header: Some("content-length".into()),
            ..ResponseParsing::default()
        };
        let result = RedirectResult {
            status_code: 200,
            captured_headers: vec![("transfer-encoding".into(), "chunked".into())],
            captured_body: Vec::new(),
        };

        let info =
            redirect_info_from_result(Url::parse("mock://o").unwrap(), &parsing, &result, false);

        assert_eq!(info.size, None);
    }

    #[test]
    fn redirected_read_preserves_standard_modification_times() {
        let expected = UNIX_EPOCH + std::time::Duration::from_secs(784_111_777);
        for (format, value) in [
            (MtimeFormat::Rfc1123, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (MtimeFormat::Iso8601, "1994-11-06T08:49:37Z"),
        ] {
            let parsing = ResponseParsing {
                mtime_header: Some("last-modified".into()),
                mtime_format: format,
                ..ResponseParsing::default()
            };
            let result = RedirectResult {
                status_code: 200,
                captured_headers: vec![("Last-Modified".into(), value.into())],
                captured_body: Vec::new(),
            };

            let info = redirect_info_from_result(
                Url::parse("mock://object").unwrap(),
                &parsing,
                &result,
                false,
            );

            assert_eq!(info.mtime, Some(expected), "{format:?}");
        }
    }
}

#[cfg(test)]
mod userbytes_length_enforcement_tests {
    use super::*;

    fn ok_chunk(s: &[u8]) -> Result<Vec<u8>> {
        Ok(s.to_vec())
    }

    /// An atomic content replacement must never carry the setuid/setgid/
    /// sticky bits of a pre-existing (possibly attacker-pre-seeded) destination
    /// onto the freshly downloaded content.
    #[cfg(unix)]
    #[test]
    fn atomic_write_strips_setuid_from_preexisting_destination() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4755)).unwrap();

        let chunks = vec![ok_chunk(b"new content")];
        let stream = BodyStream::from_iter(chunks.into_iter());
        write_streamed_file_atomically(&path, stream).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o7000,
            0,
            "the replacement must not be setuid/setgid/sticky (mode {mode:o})"
        );
        assert_eq!(mode & 0o777, 0o755, "rwx permission bits are preserved");
        assert_eq!(std::fs::read(&path).unwrap(), b"new content");
    }

    fn carry_source(chunks: Vec<Result<Vec<u8>>>) -> Arc<Mutex<CarrySource>> {
        Arc::new(Mutex::new(CarrySource {
            stream: BodyStream::from_iter(chunks.into_iter()),
            carry: bytes::Bytes::new(),
            consumed: 0,
            error: None,
        }))
    }

    #[tokio::test]
    async fn eof_probe_skips_empty_chunks_and_rejects_later_surplus() {
        let source = carry_source(vec![ok_chunk(b""), ok_chunk(b"surplus")]);
        let error = ensure_carry_source_eof(source, "surplus")
            .await
            .expect_err("a zero-length chunk is not EOF");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn eof_probe_surfaces_terminal_source_error_after_empty_chunk() {
        let expected = Error::new(ErrorCode::PermissionDenied, "source failed");
        let source = carry_source(vec![ok_chunk(b""), Err(expected.clone())]);
        let error = ensure_carry_source_eof(source, "surplus")
            .await
            .expect_err("a terminal source error must not become clean EOF");
        assert_eq!(error, expected);
    }

    #[tokio::test]
    async fn eof_probe_accepts_empty_chunks_followed_by_true_eof() {
        let source = carry_source(vec![ok_chunk(b""), ok_chunk(b"")]);
        ensure_carry_source_eof(source, "surplus")
            .await
            .expect("only true EOF completes the probe");
    }

    /// Drain one `carry_part_stream` part fully into a byte vector.
    fn drain_part(source: &Arc<Mutex<CarrySource>>, len: u64) -> Result<Vec<u8>> {
        let mut part = carry_part_stream(Arc::clone(source), len);
        let mut out = Vec::new();
        while let Some(item) = part.next_chunk() {
            out.extend_from_slice(&item?);
        }
        Ok(out)
    }

    #[test]
    fn carry_part_short_eof_returns_invalid_argument() {
        let source = carry_source(vec![ok_chunk(b"hi")]);
        let err = drain_part(&source, 10)
            .expect_err("short stream must error rather than return less than the part length");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn carry_part_exact_boundary_chunks_return_full_part() {
        // Chunks align exactly to the part boundary: no split, no carry.
        let source = carry_source(vec![ok_chunk(b"abc"), ok_chunk(b"de")]);
        assert_eq!(drain_part(&source, 5).expect("aligned part"), b"abcde");
    }

    #[test]
    fn carry_part_exact_boundary_splits_across_two_parts() {
        // Two chunks, each exactly one part: the second part draws a fresh
        // chunk with no carry involved.
        let source = carry_source(vec![ok_chunk(b"abc"), ok_chunk(b"def")]);
        assert_eq!(drain_part(&source, 3).expect("part 0"), b"abc");
        assert_eq!(drain_part(&source, 3).expect("part 1"), b"def");
    }

    #[test]
    fn carry_part_splits_straddling_chunk_and_carries_remainder() {
        // A single chunk straddles the boundary between two 3-byte parts: the
        // head finishes part 0 and the tail is carried into part 1 (the old
        // per-part `read_n_from_stream` rejected this as `Internal`).
        let source = carry_source(vec![ok_chunk(b"abcdef")]);
        assert_eq!(drain_part(&source, 3).expect("part 0"), b"abc");
        assert_eq!(drain_part(&source, 3).expect("part 1"), b"def");
    }

    #[test]
    fn carry_part_carry_larger_than_next_part_is_split_again() {
        // One big chunk spans three small parts: the carry itself straddles
        // each subsequent boundary and is re-split.
        let source = carry_source(vec![ok_chunk(b"aabbcc")]);
        assert_eq!(drain_part(&source, 2).expect("part 0"), b"aa");
        assert_eq!(drain_part(&source, 2).expect("part 1"), b"bb");
        assert_eq!(drain_part(&source, 2).expect("part 2"), b"cc");
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
            // Range-injection tests request bytes=100-199. Keep the synthetic
            // 206 internally consistent now that the follower validates both
            // the declared span and Content-Length.
            Self::Honor { body: vec![0; 100] }
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
            let requested_range = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("range"))
                .map(|(_, value)| value.clone());
            let had_range = requested_range.is_some();
            let _ = tx.send(headers);
            let (status_line, body) = match (&behavior, had_range) {
                (RangeBehavior::Honor { body }, true) => {
                    let range = requested_range
                        .as_deref()
                        .and_then(|value| value.strip_prefix("bytes="))
                        .expect("test request carries a bytes range");
                    (
                        format!(
                            "HTTP/1.1 206 Partial Content\r\n\
                             Content-Range: bytes {range}/*\r\n",
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
        let physical_url_prefix = url.clone();
        ReadRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url,
                headers: Vec::new(),
            },
            response_parsing: ResponseParsing::default(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            scope: RedirectScope {
                physical_url_prefix,
                operations: AccessOps {
                    read: true,
                    ..Default::default()
                },
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                credential: RedirectCredential::None,
            },
            audit_id: String::new(),
            policy_epoch: 0,
        }
    }

    /// The write-path twin of [`redirect_to`], identical in every field the
    /// delegability predicate reads, so a read/write comparison measures the
    /// predicate rather than a difference between two fixtures.
    fn write_redirect_to(url: String) -> WriteRedirect {
        let physical_url_prefix = url.clone();
        WriteRedirect {
            request: HttpRequest {
                method: "PUT".into(),
                url,
                headers: Vec::new(),
            },
            body_source: RedirectBodySource::Empty,
            result_capture: ResultCapture::default(),
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            scope: RedirectScope {
                physical_url_prefix,
                operations: AccessOps {
                    write: true,
                    ..Default::default()
                },
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                credential: RedirectCredential::None,
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

    #[test]
    fn redirect_scope_requires_the_requested_operation() {
        let mut redirect = redirect_to("https://storage.example/bucket/object".into());
        redirect.scope.operations.read = false;

        let error = ensure_read_redirect_valid(&redirect).expect_err("read must be denied");

        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn redirect_methods_are_constrained_by_operation() {
        let mut read = redirect_to("https://storage.example/object".into());
        read.request.method = "DELETE".into();
        let error = ensure_read_redirect_valid(&read)
            .expect_err("a read capability must not authorize DELETE");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        read.request.method = "not a method".into();
        let error = ensure_read_redirect_valid(&read)
            .expect_err("a malformed method must not silently become GET");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);

        let expires_at = SystemTime::now() + std::time::Duration::from_secs(60);
        let mut write = WriteRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url: "https://storage.example/object".into(),
                headers: Vec::new(),
            },
            body_source: RedirectBodySource::Empty,
            result_capture: ResultCapture::default(),
            expires_at,
            scope: RedirectScope {
                physical_url_prefix: "https://storage.example/object".into(),
                operations: AccessOps {
                    write: true,
                    ..Default::default()
                },
                expires_at,
                credential: RedirectCredential::None,
            },
            audit_id: String::new(),
            policy_epoch: 0,
        };
        let error = ensure_write_redirect_valid(&write)
            .expect_err("a write capability must not authorize GET");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        write.request.method = "DELETE".into();
        let error = ensure_write_redirect_valid(&write)
            .expect_err("a write capability must not authorize DELETE");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        for method in ["PUT", "POST", "PATCH"] {
            write.request.method = method.into();
            ensure_write_redirect_valid(&write)
                .unwrap_or_else(|error| panic!("{method} should be permitted: {error}"));
        }
    }

    #[test]
    fn ambient_credential_headers_make_a_read_redirect_non_delegable() {
        for name in ["Authorization", "Proxy-Authorization", "Cookie"] {
            let mut redirect = redirect_to("https://storage.example/object".into());
            redirect
                .request
                .headers
                .push((name.into(), "secret".into()));
            assert!(!read_redirect_is_safely_delegable(&redirect), "{name}");
        }
        let mut presigned =
            redirect_to("https://storage.example/object?X-Amz-Signature=resource-scoped".into());
        presigned.scope.physical_url_prefix = "https://storage.example/object".into();
        assert!(read_redirect_is_safely_delegable(&presigned));
    }

    /// The shared predicate's answer for each of the four declarations, and
    /// that this crate's read wrapper does not diverge from it.
    ///
    /// **This is not the symmetry test**, and an earlier version of this
    /// comment claimed it was. `read_redirect_is_safely_delegable` is defined
    /// as a call to `redirect_is_delegable` with the same two arguments, so
    /// comparing the two here is comparing a function to itself; what the
    /// comparison is worth is that the wrapper keeps forwarding rather than
    /// growing a rule of its own. The table is the substance: it fails if any
    /// declaration's answer changes.
    ///
    /// The real read/write symmetry constraint is between the two host guards,
    /// which are separately written functions with different return types.
    /// This crate cannot see them — it has no dependency on any broker crate —
    /// so that assertion lives in the broker, as
    /// `the_read_and_write_guards_agree_on_every_declaration`.
    #[test]
    fn the_shared_predicate_answers_each_declaration_the_same_way_both_wrappers_do() {
        let cases = [
            (RedirectCredential::Unspecified, false),
            (RedirectCredential::None, true),
            (RedirectCredential::Request, true),
            (RedirectCredential::Connection, false),
        ];
        // A header set that the inert allowlist accepts, so this test measures
        // the declaration rather than the backstop.
        let inert = vec![("Content-Type".to_string(), "text/plain".to_string())];

        for (declared, expected) in cases {
            let mut read = redirect_to("https://storage.example/object".into());
            read.scope.credential = declared;
            read.request.headers = inert.clone();

            let mut write = write_redirect_to("https://storage.example/object".into());
            write.scope.credential = declared;
            write.request.headers = inert.clone();

            let read_allows = read_redirect_is_safely_delegable(&read);
            // The bare predicate, spelled as a host's out-edge spells it. This
            // is the same function the wrapper above forwards to, so the
            // equality below is weak; the per-row expectation is what carries
            // this test.
            let write_allows =
                redirect_is_delegable(write.scope.credential, &write.request.headers);

            assert_eq!(
                read_allows, expected,
                "read path disagreed for {declared:?}"
            );
            assert_eq!(
                read_allows, write_allows,
                "read and write paths disagreed for {declared:?}: \
                 read={read_allows}, write={write_allows}"
            );
        }
    }

    /// The declaration decides, and inspection may only lower it. A backend
    /// that declares a request-scoped credential and then attaches a header
    /// this host cannot account for is treated as connection-scoped — which is
    /// what makes a declaration mistake cost a proxied transfer instead of a
    /// disclosure.
    #[test]
    fn an_unrecognised_header_demotes_a_request_scoped_declaration() {
        // Not `Authorization`: the point is that the backstop no longer depends
        // on knowing a credential's name. This is the header set Nucleus LFT
        // actually attaches, which the old three-name check let through.
        for name in ["Authorization-Token", "Connection-Signature"] {
            let mut redirect = redirect_to("https://storage.example/object".into());
            redirect.scope.credential = RedirectCredential::Request;
            redirect
                .request
                .headers
                .push((name.into(), "secret".into()));
            assert!(
                !read_redirect_is_safely_delegable(&redirect),
                "{name} must demote a Request declaration"
            );
        }

        // And the demotion is one-way: an inert header set cannot raise a
        // connection-wide declaration into a delegable one.
        let mut declared_broad = redirect_to("https://storage.example/object".into());
        declared_broad.scope.credential = RedirectCredential::Connection;
        assert!(!read_redirect_is_safely_delegable(&declared_broad));
    }

    #[test]
    fn redirect_scope_rejects_a_canonicalized_path_escape() {
        let mut redirect = redirect_to("https://storage.example/allowed/../outside/object".into());
        redirect.scope.physical_url_prefix = "https://storage.example/allowed/".into();

        let error = ensure_read_redirect_valid(&redirect).expect_err("escaped URL must be denied");

        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn redirect_scope_ignores_signed_prefix_query_and_fragment() {
        let mut redirect =
            redirect_to("https://storage.example/bucket/object?X-Amz-Signature=request".into());
        redirect.scope.physical_url_prefix =
            "https://storage.example/bucket/object?X-Amz-Signature=scope#ignored".into();

        ensure_read_redirect_valid(&redirect)
            .expect("query and fragment do not narrow an authority/path scope");
    }

    #[cfg(unix)]
    #[test]
    fn file_redirect_scope_rejects_percent_decoded_parent_escape() {
        let root = tempfile::tempdir().expect("tempdir");
        let allowed = root.path().join("nested/allowed");
        let prefix = url::Url::from_directory_path(&allowed).expect("directory URL");
        let escaped = format!("{}..%2F..%2Foutside", prefix.as_str());
        let mut redirect = redirect_to(escaped);
        redirect.scope.physical_url_prefix = prefix.to_string();

        let error = ensure_read_redirect_valid(&redirect)
            .expect_err("decoded parent components must not escape the file scope");

        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn file_redirect_scope_rejects_symlinked_parent_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("tempdir");
        let allowed = root.path().join("allowed");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&allowed).expect("allowed");
        std::fs::create_dir_all(&outside).expect("outside");
        symlink(&outside, allowed.join("out")).expect("symlink");
        let prefix = url::Url::from_directory_path(&allowed).expect("directory URL");
        let request = url::Url::from_file_path(allowed.join("out/secret")).expect("file URL");
        let mut redirect = redirect_to(request.to_string());
        redirect.scope.physical_url_prefix = prefix.to_string();

        let error = ensure_read_redirect_valid(&redirect)
            .expect_err("a planted symlink must not escape the file scope");

        assert_eq!(error.code(), ErrorCode::PermissionDenied);

        let expires_at = SystemTime::now() + std::time::Duration::from_secs(60);
        let write = WriteRedirect {
            request: HttpRequest {
                method: "PUT".into(),
                url: request.to_string(),
                headers: Vec::new(),
            },
            body_source: RedirectBodySource::Empty,
            result_capture: ResultCapture::default(),
            expires_at,
            scope: RedirectScope {
                physical_url_prefix: prefix.to_string(),
                operations: AccessOps {
                    write: true,
                    ..Default::default()
                },
                expires_at,
                credential: RedirectCredential::None,
            },
            audit_id: String::new(),
            policy_epoch: 0,
        };
        let error = ensure_write_redirect_valid(&write)
            .expect_err("a write must not follow a symlinked parent outside the file scope");
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn redirect_scope_expiry_is_a_hard_deadline() {
        let mut redirect = redirect_to("https://storage.example/bucket/object".into());
        redirect.scope.expires_at = SystemTime::now() - std::time::Duration::from_secs(1);

        let error = ensure_read_redirect_valid(&redirect).expect_err("scope must be expired");

        assert_eq!(error.code(), ErrorCode::RedirectExpired);
    }

    #[tokio::test]
    async fn reqwest_failures_do_not_expose_the_signed_request_url() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        drop(listener);
        let request = HttpRequest {
            method: "GET".into(),
            url: format!(
                "http://{address}/object?X-Amz-Credential=credential&X-Amz-Signature=TOPSECRET"
            ),
            headers: Vec::new(),
        };

        let error = execute_reqwest_redirect(&request, &[], 0)
            .await
            .expect_err("closed listener must fail");

        assert_eq!(error.code(), ErrorCode::Transient);
        assert!(!error.to_string().contains("TOPSECRET"));
        assert!(!error.to_string().contains("X-Amz-Signature"));
        assert!(!error.to_string().contains(&address.to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_body_capture_does_not_drain_an_unbounded_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = vec![0u8; 4096];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nbody-prefix")
                .await
                .expect("write response prefix");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let request = HttpRequest {
            method: "PUT".into(),
            url: format!("http://{address}/upload"),
            headers: Vec::new(),
        };

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            execute_reqwest_redirect(&request, &[], 0),
        )
        .await
        .expect("a zero-byte capture must return after headers")
        .expect("response headers are valid");

        assert!(result.captured_body.is_empty());
    }

    // Retry transient HTTP failures during the header phase; mid-stream replay
    // stays out of scope.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follow_read_redirect_streaming_retries_transient_http_until_headers() {
        use futures::StreamExt;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let server_hits = hits.clone();
        tokio::spawn(async move {
            // First request: one-off 503. Second: 200 with the body.
            for round in 0..2 {
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
                server_hits.fetch_add(1, Ordering::SeqCst);
                let response: &[u8] = if round == 0 {
                    b"HTTP/1.1 503 Service Unavailable\r\nretry-after: 0\r\n\
                      content-length: 0\r\nconnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\
                      connection: close\r\n\r\nretried"
                };
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            }
        });

        let redirect = redirect_to(format!("http://127.0.0.1:{port}/object"));
        let retry_cfg = retry::RetryConfig {
            initial_delay_ms: 1,
            max_delay_ms: 5,
            max_attempts: 3,
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            None,
            &retry_cfg,
            None,
        )
        .await
        .expect("a one-off 503 must be retried until response headers arrive");
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk.expect("body chunk"));
        }
        assert_eq!(bytes, b"retried");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "exactly one retry");
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
            &retry::RetryConfig::default(),
            None,
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
    async fn follower_emits_one_authoritative_range_and_if_match_header() {
        let (port, rx) = spawn_capture_server(RangeBehavior::honor()).await;
        let mut redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        redirect.request.headers = vec![
            ("Range".into(), "bytes=0-9".into()),
            ("If-Match".into(), "\"stale\"".into()),
        ];
        let range = ByteRange {
            start: 100,
            end_inclusive: Some(199),
        };

        let _response = send_streaming_request(&redirect, Some(&range), Some("current"))
            .await
            .expect("request succeeds");
        let headers = rx.await.expect("server captured headers");
        let range_values: Vec<_> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("range"))
            .map(|(_, value)| value.as_str())
            .collect();
        let if_match_values: Vec<_> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("if-match"))
            .map(|(_, value)| value.as_str())
            .collect();

        assert_eq!(range_values, vec!["bytes=100-199"]);
        assert_eq!(if_match_values, vec!["\"current\""]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follower_derives_host_from_the_validated_url() {
        let (port, rx) = spawn_capture_server(RangeBehavior::honor()).await;
        let mut redirect = redirect_to(format!("http://127.0.0.1:{port}/test"));
        redirect
            .request
            .headers
            .push(("Host".into(), "admin.internal".into()));

        let _response = send_streaming_request(&redirect, None, None)
            .await
            .expect("request succeeds");
        let headers = rx.await.expect("server captured headers");
        let host = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str());

        let expected_host = format!("127.0.0.1:{port}");
        assert_eq!(host, Some(expected_host.as_str()));
        assert_ne!(host, Some("admin.internal"));
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
            &retry::RetryConfig::default(),
            None,
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
    /// panic the worker thread on `slice(5..3)`).
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
            &retry::RetryConfig::default(),
            None,
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
            &retry::RetryConfig::default(),
            None,
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

/// Regression coverage for the mid-stream-resume and file-staging hardening.
#[cfg(test)]
mod resume_hardening_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Per-connection captured request headers, indexed by connection order.
    type CapturedRequests = Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>;

    /// One scripted HTTP response, served on its own connection.
    struct ScriptedResponse {
        /// Status line + headers, WITHOUT the trailing blank line or
        /// `Content-Length` (the server appends `Content-Length`).
        head: String,
        /// Bytes actually written to the socket before it is closed.
        body: Vec<u8>,
        /// Declared `Content-Length`. When it exceeds `body.len()` the
        /// transfer is truncated — reqwest surfaces a mid-stream body error,
        /// which drives the resume engine.
        content_length: usize,
    }

    /// Accept one connection per scripted response, recording each request's
    /// headers into the returned shared vector (indexed by connection order).
    async fn spawn_scripted_server(responses: Vec<ScriptedResponse>) -> (u16, CapturedRequests) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let captured: CapturedRequests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_task = captured.clone();
        tokio::spawn(async move {
            for response in responses {
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
                let blob = String::from_utf8_lossy(&buf[..total]).to_string();
                let mut headers: Vec<(String, String)> = Vec::new();
                for line in blob.lines().skip(1) {
                    if line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        headers.push((name.trim().to_string(), value.trim().to_string()));
                    }
                }
                captured_task.lock().unwrap().push(headers);
                let head = format!(
                    "{}\r\nContent-Length: {}\r\n\r\n",
                    response.head, response.content_length
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&response.body).await;
                let _ = socket.shutdown().await;
            }
        });
        (port, captured)
    }

    fn redirect_with_parsing(url: String, parsing: ResponseParsing) -> ReadRedirect {
        let physical_url_prefix = url.clone();
        ReadRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url,
                headers: Vec::new(),
            },
            response_parsing: parsing,
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
            scope: RedirectScope {
                physical_url_prefix,
                operations: AccessOps {
                    read: true,
                    ..Default::default()
                },
                expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                credential: RedirectCredential::None,
            },
            audit_id: String::new(),
            policy_epoch: 0,
        }
    }

    fn if_match_header(headers: &[(String, String)]) -> Option<&str> {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("if-match"))
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_206_requires_single_range_alignment() {
        let cases = [
            (
                "HTTP/1.1 206 Partial Content".to_string(),
                "missing Content-Range",
            ),
            (
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-9/200".to_string(),
                "shifted Content-Range",
            ),
            (
                "HTTP/1.1 206 Partial Content\r\n\
                 Content-Range: bytes 100-109/200\r\n\
                 Content-Type: multipart/byteranges; boundary=parts"
                    .to_string(),
                "multipart response",
            ),
        ];
        for (head, label) in cases {
            let (port, _captured) = spawn_scripted_server(vec![ScriptedResponse {
                head,
                body: vec![0; 10],
                content_length: 10,
            }])
            .await;
            let redirect = redirect_with_parsing(
                format!("http://127.0.0.1:{port}/object"),
                ResponseParsing::default(),
            );
            let range = ByteRange {
                start: 100,
                end_inclusive: Some(109),
            };
            let error = follow_read_redirect_streaming(
                url::Url::parse("omni://server/object").unwrap(),
                &redirect,
                false,
                Some(&range),
                &retry::RetryConfig::default(),
                None,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("{label} must be rejected"));
            assert_eq!(error.code(), ErrorCode::Internal, "case: {label}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_206_rejects_a_partially_satisfied_requested_range() {
        let (port, _captured) = spawn_scripted_server(vec![ScriptedResponse {
            head: "HTTP/1.1 206 Partial Content\r\n\
                   Content-Range: bytes 0-49/100"
                .into(),
            body: vec![0; 50],
            content_length: 50,
        }])
        .await;
        let redirect = redirect_with_parsing(
            format!("http://127.0.0.1:{port}/object"),
            ResponseParsing::default(),
        );
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(99),
        };

        let error = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            Some(&range),
            &retry::RetryConfig::default(),
            None,
        )
        .await
        .err()
        .expect("a short-satisfied 206 must fail at the header phase");

        assert_eq!(error.code(), ErrorCode::Internal);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chunked_206_clean_eof_before_declared_end_is_an_error_frame() {
        use futures::StreamExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = vec![0u8; 4096];
            let _ = socket.read(&mut request).await;
            socket
                .write_all(
                    b"HTTP/1.1 206 Partial Content\r\n\
                      Content-Range: bytes 0-99/100\r\n\
                      Transfer-Encoding: chunked\r\n\r\n\
                      32\r\n00000000000000000000000000000000000000000000000000\r\n0\r\n\r\n",
                )
                .await
                .expect("write response");
        });
        let redirect = redirect_with_parsing(
            format!("http://127.0.0.1:{port}/object"),
            ResponseParsing::default(),
        );
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(99),
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            Some(&range),
            &retry::RetryConfig::default(),
            None,
        )
        .await
        .expect("headers describe the requested span");

        let mut error = None;
        while let Some(frame) = stream.next().await {
            if let Err(stream_error) = frame {
                error = Some(stream_error);
                break;
            }
        }

        assert_eq!(
            error.expect("clean short EOF must surface an error").code(),
            ErrorCode::Transient
        );
    }

    /// An initial `206` that fails mid-body, resumed with a
    /// full-body `200`, must deliver the requested range exactly — no
    /// re-emitted (duplicate) prefix bytes AND the upper bound honored even
    /// though the first response's 206 turned the outer range filter OFF.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_200_after_206_honors_upper_bound_without_duplicates() {
        use futures::StreamExt;
        // Object bytes are position-encoded so any duplicate/overrun is visible.
        let object: Vec<u8> = (0u16..300).map(|i| i as u8).collect();
        let parsing = ResponseParsing {
            etag_header: Some("etag".into()),
            ..ResponseParsing::default()
        };
        let responses = vec![
            // 206 for bytes 100-199, but only 50 bytes are sent before the
            // socket closes → mid-stream error → resume.
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\n\
                       Content-Range: bytes 100-199/300\r\nETag: \"v1\""
                    .into(),
                body: object[100..150].to_vec(),
                content_length: 100,
            },
            // Resume answered with a FULL-BODY 200 (origin ignored Range).
            // Without the internal upper bound this would stream to EOF.
            ScriptedResponse {
                head: "HTTP/1.1 200 OK\r\nETag: \"v1\"".into(),
                body: object.clone(),
                content_length: object.len(),
            },
        ];
        let (port, _captured) = spawn_scripted_server(responses).await;
        let redirect = redirect_with_parsing(format!("http://127.0.0.1:{port}/object"), parsing);
        let range = ByteRange {
            start: 100,
            end_inclusive: Some(199),
        };
        let retry_cfg = retry::RetryConfig {
            initial_delay_ms: 1,
            max_delay_ms: 5,
            max_attempts: 3,
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            Some(&range),
            &retry_cfg,
            None,
        )
        .await
        .expect("header phase succeeds on the initial 206");
        let mut bytes = Vec::new();
        while let Some(frame) = stream.next().await {
            bytes.extend_from_slice(&frame.expect("no error frame"));
        }
        assert_eq!(
            bytes,
            object[100..200].to_vec(),
            "delivered bytes must equal the requested range exactly — no duplicated \
             prefix, no run past the upper bound",
        );
    }

    /// A resume 206 whose `Content-Range` is missing (or malformed) can't
    /// prove its byte alignment, so it must be rejected — never spliced onto
    /// `from`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_206_missing_content_range_is_rejected() {
        use futures::StreamExt;
        let object: Vec<u8> = (0u16..100).map(|i| i as u8).collect();
        let parsing = ResponseParsing {
            etag_header: Some("etag".into()),
            ..ResponseParsing::default()
        };
        let responses = vec![
            // Initial 206 for 0-99, but only 50 bytes before the socket closes
            // → mid-stream error → resume from byte 50.
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\n\
                       Content-Range: bytes 0-99/100\r\nETag: \"v1\""
                    .into(),
                body: object[0..50].to_vec(),
                content_length: 100,
            },
            // Resume answered with a 206 that OMITS Content-Range → unverifiable.
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\nETag: \"v1\"".into(),
                body: object[50..100].to_vec(),
                content_length: 50,
            },
        ];
        let (port, _captured) = spawn_scripted_server(responses).await;
        let redirect = redirect_with_parsing(format!("http://127.0.0.1:{port}/object"), parsing);
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(99),
        };
        let retry_cfg = retry::RetryConfig {
            initial_delay_ms: 1,
            max_delay_ms: 5,
            max_attempts: 3,
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            Some(&range),
            &retry_cfg,
            None,
        )
        .await
        .expect("header phase succeeds on the initial 206");
        let mut saw_error = false;
        let mut delivered = Vec::new();
        while let Some(frame) = stream.next().await {
            match frame {
                Ok(chunk) => delivered.extend_from_slice(&chunk),
                Err(_) => {
                    saw_error = true;
                    break;
                }
            }
        }
        assert!(
            saw_error,
            "a resume 206 with a missing Content-Range must error, not splice a body"
        );
        assert!(
            delivered.len() <= 50,
            "no misaligned bytes may be spliced past the verified 50-byte prefix (got {})",
            delivered.len()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_missing_original_validator_is_rejected() {
        use futures::StreamExt;
        let object: Vec<u8> = (0u16..100).map(|i| i as u8).collect();
        let parsing = ResponseParsing {
            etag_header: Some("x-object-version".into()),
            ..ResponseParsing::default()
        };
        let responses = vec![
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\n\
                       Content-Range: bytes 0-99/100\r\n\
                       x-object-version: v1"
                    .into(),
                body: object[..50].to_vec(),
                content_length: 100,
            },
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\n\
                       Content-Range: bytes 50-99/100"
                    .into(),
                body: object[50..].to_vec(),
                content_length: 50,
            },
        ];
        let (port, _captured) = spawn_scripted_server(responses).await;
        let redirect = redirect_with_parsing(format!("http://127.0.0.1:{port}/object"), parsing);
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(99),
        };
        let retry_cfg = retry::RetryConfig {
            initial_delay_ms: 1,
            max_delay_ms: 5,
            max_attempts: 3,
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            Some(&range),
            &retry_cfg,
            None,
        )
        .await
        .expect("initial response headers are valid");
        let mut error = None;
        while let Some(frame) = stream.next().await {
            if let Err(stream_error) = frame {
                error = Some(stream_error);
                break;
            }
        }

        assert_eq!(
            error.expect("resume must fail closed").code(),
            ErrorCode::ObjectModified
        );
    }

    /// The resume `If-Match` must carry the response's real HTTP
    /// `ETag`, never the opaque SPI validator. A GCS-style backend maps
    /// `x-goog-generation` to `ObjectInfo.etag`; sending that as `If-Match`
    /// 412s every resume.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn resume_if_match_uses_http_etag_not_opaque_validator() {
        use futures::StreamExt;
        let object: Vec<u8> = (0u16..100).map(|i| i as u8).collect();
        // Validator (SPI etag) is the GCS generation; the real wire ETag is
        // a separate opaque token.
        let parsing = ResponseParsing {
            etag_header: Some("x-goog-generation".into()),
            ..ResponseParsing::default()
        };
        let responses = vec![
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\n\
                       Content-Range: bytes 0-99/100\r\n\
                       x-goog-generation: 1600000000000001\r\nETag: \"realwiretag\""
                    .into(),
                body: object[0..50].to_vec(),
                content_length: 100,
            },
            ScriptedResponse {
                head: "HTTP/1.1 206 Partial Content\r\n\
                       Content-Range: bytes 50-99/100\r\n\
                       x-goog-generation: 1600000000000001\r\nETag: \"realwiretag\""
                    .into(),
                body: object[50..100].to_vec(),
                content_length: 50,
            },
        ];
        let (port, captured) = spawn_scripted_server(responses).await;
        let redirect = redirect_with_parsing(format!("http://127.0.0.1:{port}/object"), parsing);
        let range = ByteRange {
            start: 0,
            end_inclusive: Some(99),
        };
        let retry_cfg = retry::RetryConfig {
            initial_delay_ms: 1,
            max_delay_ms: 5,
            max_attempts: 3,
        };
        let StreamedReadRedirect { mut stream, .. } = follow_read_redirect_streaming(
            url::Url::parse("omni://server/object").unwrap(),
            &redirect,
            false,
            Some(&range),
            &retry_cfg,
            None,
        )
        .await
        .expect("header phase ok");
        let mut bytes = Vec::new();
        while let Some(frame) = stream.next().await {
            bytes.extend_from_slice(&frame.expect("no error frame"));
        }
        assert_eq!(bytes, object, "the resume must reassemble the full range");
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2, "exactly one resume connection");
        let resume_if_match = if_match_header(&captured[1]).expect("resume must carry an If-Match");
        assert_eq!(
            resume_if_match, "\"realwiretag\"",
            "resume If-Match must be the real HTTP ETag",
        );
        assert!(
            !resume_if_match.contains("1600000000000001"),
            "resume must NOT send the opaque SPI validator (generation) as If-Match; got {resume_if_match:?}",
        );
    }

    fn put_redirect(path: &std::path::Path) -> (HttpRequest, url::Url) {
        let url = url::Url::from_file_path(path).expect("file url");
        (
            HttpRequest {
                method: "PUT".into(),
                url: url.to_string(),
                headers: Vec::new(),
            },
            url,
        )
    }

    fn staging_leftovers(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains("ovstaging") || name.starts_with(".tmp"))
            .collect()
    }

    /// A destination that pre-exists as a symlink must NOT have its
    /// target truncated — the follower replaces the link with a regular file.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_streaming_does_not_truncate_symlink_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"SECRET-DO-NOT-TRUNCATE").expect("write secret");
        let dest = dir.path().join("dest");
        std::os::unix::fs::symlink(&secret, &dest).expect("symlink");

        let (request, url) = put_redirect(&dest);
        let stream = BodyStream::from_iter(vec![Ok(b"fresh-upload".to_vec())].into_iter());
        execute_file_streaming_request(&request, &url, stream)
            .await
            .expect("streaming PUT succeeds");

        assert_eq!(
            std::fs::read(&secret).expect("secret readable"),
            b"SECRET-DO-NOT-TRUNCATE",
            "the symlink target must be left completely untouched",
        );
        assert!(
            !std::fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the destination symlink must be replaced by a regular file",
        );
        assert_eq!(
            std::fs::read(&dest).expect("dest readable"),
            b"fresh-upload",
        );
        assert!(
            staging_leftovers(dir.path()).is_empty(),
            "no staging file may be left behind",
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_buffered_does_not_truncate_symlink_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"SECRET-DO-NOT-TRUNCATE").expect("write secret");
        let dest = dir.path().join("dest");
        std::os::unix::fs::symlink(&secret, &dest).expect("symlink");

        let (request, url) = put_redirect(&dest);
        execute_file_redirect(&request, &url, b"fresh-upload")
            .await
            .expect("buffered PUT succeeds");

        assert_eq!(
            std::fs::read(&secret).expect("secret readable"),
            b"SECRET-DO-NOT-TRUNCATE",
        );
        assert!(
            !std::fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink(),
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"fresh-upload");
        assert!(staging_leftovers(dir.path()).is_empty());
    }

    /// A short/errored body must leave the destination unchanged and
    /// remove the staging file (RAII cleanup).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_streaming_errored_body_leaves_destination_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("dest");
        std::fs::write(&dest, b"ORIGINAL").expect("seed dest");

        let (request, url) = put_redirect(&dest);
        let stream = BodyStream::from_iter(
            vec![
                Ok(b"partial".to_vec()),
                Err(Error::new(ErrorCode::Transient, "boom")),
            ]
            .into_iter(),
        );
        let err = execute_file_streaming_request(&request, &url, stream)
            .await
            .expect_err("errored body must fail the PUT");
        assert_eq!(err.code(), ErrorCode::Transient);
        assert_eq!(
            std::fs::read(&dest).expect("dest readable"),
            b"ORIGINAL",
            "a failed streaming PUT must not disturb the existing destination",
        );
        assert!(
            staging_leftovers(dir.path()).is_empty(),
            "the RAII guard must remove the staged temp on error",
        );
    }

    /// Replacing an existing destination must preserve its mode (the
    /// atomic rename must not silently downgrade, e.g. `0600 -> 0644`). Seeded
    /// with `0640` — distinct from the `NamedTempFile` default (`0600`) — so the
    /// assertion fails unless the prior mode is actively copied onto the temp.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_streaming_preserves_existing_destination_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("dest");
        std::fs::write(&dest, b"old").expect("seed dest");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o640))
            .expect("chmod 0640");

        let (request, url) = put_redirect(&dest);
        let stream = BodyStream::from_iter(vec![Ok(b"new-contents".to_vec())].into_iter());
        execute_file_streaming_request(&request, &url, stream)
            .await
            .expect("streaming PUT succeeds");

        assert_eq!(
            std::fs::read(&dest).expect("dest readable"),
            b"new-contents"
        );
        let mode = std::fs::metadata(&dest)
            .expect("dest metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o640,
            "the destination's existing mode must survive replacement"
        );
    }
}

#[cfg(test)]
mod mtime_range_tests {
    use super::*;

    #[test]
    fn out_of_range_instants_yield_none_instead_of_panicking() {
        // `SystemTime`'s `Add`/`Sub` panic on overflow and the seconds come from
        // an origin-controlled header, so the conversion must be total at both
        // extremes. Which instants are *representable* is platform-dependent —
        // a Unix-epoch `SystemTime` spans the whole `i64` second range, while
        // Windows' 1601-epoch `FILETIME` rejects far more — so this asserts
        // totality, and the `UnixSeconds` case below pins a hard `None`.
        let _ = system_time_from_unix(i64::MAX, u32::MAX);
        let _ = system_time_from_unix(i64::MIN, u32::MAX);
    }

    #[test]
    fn an_origin_controlled_iso8601_mtime_never_panics() {
        // Year 1000 is representable on a Unix-epoch `SystemTime` and not on
        // Windows' 1601-epoch `FILETIME`: either outcome is fine, panicking is
        // not.
        let parsed = parse_mtime("1000-01-01T00:00:00Z", MtimeFormat::Iso8601);
        if let Some(parsed) = parsed {
            assert!(parsed < UNIX_EPOCH);
        }
    }

    #[test]
    fn an_in_range_iso8601_mtime_round_trips() {
        let parsed = parse_mtime("2026-07-31T12:00:00Z", MtimeFormat::Iso8601)
            .expect("an in-range timestamp parses");
        assert_eq!(
            parsed
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs(),
            1_785_499_200
        );
    }

    #[test]
    fn an_out_of_range_unix_seconds_mtime_yields_none() {
        assert_eq!(
            parse_mtime(&u64::MAX.to_string(), MtimeFormat::UnixSeconds),
            None
        );
    }
}
