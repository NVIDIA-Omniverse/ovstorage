// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Object-route handlers: the HTTP projection of the `Stack` API.
//!
//! # Errors
//!
//! Every handler funnels failures through
//! [`error_response`]: the
//! [`ovstorage::Error`] raised by the underlying [`Stack`] call (the
//! shared [`ovstorage::ErrorCode`] taxonomy — see the `# Errors`
//! sections on the [`Layer`] trait methods) is
//! serialized as a JSON [`schema::ErrorEnvelope`] carrying the code
//! name and redacted message, under the HTTP status chosen by
//! [`status_for_error`]. That
//! function is the single, exhaustive `ErrorCode` → status table for
//! the gateway; the `responses(...)` lists in each handler's
//! `#[utoipa::path]` annotation are the OpenAPI view of the statuses
//! that route is expected to produce, not a separate mapping.

use super::*;

/// Read an object's bytes; the gateway may respond `307` with an
/// upstream `Location` and `X-OV-Audit-Id` when the backend prefers
/// the client fetch directly.
///
/// An optional `If-Match: "<etag>"` header (RFC 7232) refuses the
/// read unless the target's current etag matches. The etag MAY be
/// sent unquoted; the `W/` weak-etag prefix is tolerated. The
/// wildcard form `If-Match: *` is rejected because ovstorage
/// preconditions require a concrete etag.
#[utoipa::path(
    get,
    path = "/v1/objects",
    tag = "objects",
    params(
        ("address" = String, Query, description = "Object address to read"),
        ("If-Match" = Option<String>, Header, description = "Etag precondition: refuse the read unless the target's current etag matches"),
        ("Range" = Option<String>, Header, description = "Byte range as `bytes=START-END` (inclusive); `END` may be omitted for open-ended"),
    ),
    responses(
        (status = 200, description = "Object bytes", body = Vec<u8>),
        (status = 307, description = "Redirect to upstream — body is at the URL in the Location header"),
        (status = 400, body = schema::ErrorEnvelope, description = "If-Match: * is not supported; supply a concrete etag"),
        (status = 403, body = schema::ErrorEnvelope, description = "The backend's redirect carries a credential broader than this request and `redirect_credential_disclosure` is `refuse`, with no follower in the graph to fetch the bytes instead"),
        (status = 404, body = schema::ErrorEnvelope, description = "Object not found at the given address"),
        (status = 412, body = schema::ErrorEnvelope, description = "If-Match precondition failed"),
    ),
)]
pub(crate) async fn read_object(
    State(stack): State<Arc<Stack>>,
    State(RedirectDisclosure(disclose_credentials)): State<RedirectDisclosure>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let opts = match read_options(&headers) {
        Ok(opts) => opts,
        Err(error) => return error_response(error),
    };
    // Authorization is the Stack's top-of-stack auth layer: it gates
    // `Read` on the address before dispatch. The gateway
    // Stack's follower is composed `follow_reads=false`, so a backend read
    // `Redirect` flows up unfollowed for the caller to fetch directly (surfaced
    // below as HTTP 307) instead of being proxied — unless the operator's
    // `redirect_credential_disclosure` refuses that redirect's credential, in
    // which case the follower fetches the object and this handler streams it.
    let request = cx.request(ReadRequest {
        address,
        options: opts,
    });
    match stack.read(request, None).await {
        Ok(ReadResult::Bytes { bytes, .. }) => (StatusCode::OK, bytes).into_response(),
        Ok(ReadResult::Stream { stream, .. }) => {
            // Public-facing memory-DoS gate: forward SPI chunks chunk-by-chunk
            // into axum's body; never collect to Vec. Peak memory stays bounded
            // by chunk size × in-flight chunks.
            use futures::StreamExt;
            let body_stream =
                stream.map(|chunk| chunk.map_err(|err| std::io::Error::other(err.to_string())));
            axum::body::Body::from_stream(body_stream).into_response()
        }
        Ok(ReadResult::Redirect(redirect)) => {
            // Out-edge guard. The in-graph follower applies the same policy
            // first and can degrade gracefully, fetching the bytes itself; this
            // fires only where the operator's graph has no follower, or one that
            // does not see this path. There are no bytes in reach here, so the
            // only available answer is a refusal.
            //
            // The `307` carries no request headers, only the URL — so the
            // disclosure this prevents is a credential riding in the URL's
            // query, which the same declaration covers because the minting
            // backend declares what its credential authorizes rather than where
            // it put it.
            if !disclose_credentials
                && !ovstorage::redirect_is_delegable(
                    redirect.scope.credential,
                    &redirect.request.headers,
                )
            {
                return error_response(Error::new(
                    ErrorCode::PermissionDenied,
                    "this redirect carries a credential that authorizes more than the redirected \
                     request, and `redirect_credential_disclosure` is `refuse`",
                ));
            }
            (
                StatusCode::TEMPORARY_REDIRECT,
                [
                    (axum::http::header::LOCATION, redirect.request.url),
                    (
                        axum::http::header::HeaderName::from_static("x-ov-audit-id"),
                        redirect.audit_id,
                    ),
                ],
            )
                .into_response()
        }
        Ok(ReadResult::LocalDelegate(local)) => match tokio::fs::File::open(&local.path).await {
            Ok(file) => {
                let stream = tokio_util::io::ReaderStream::new(file);
                axum::body::Body::from_stream(stream).into_response()
            }
            Err(error) => error_response(Error::new(
                ErrorCode::Internal,
                format!("failed to open local-delegate file: {error}"),
            )),
        },
        Err(error) => error_response(error),
    }
}

/// Write an object. Destination preconditions are expressed with
/// standard RFC 7232 headers:
/// - no precondition header — clobber unconditionally.
/// - `If-None-Match: *` — refuse if the destination exists
///   (`409 AlreadyExists`).
/// - `If-Match: "<etag>"` — overwrite only when the destination's
///   current etag matches (`412` on mismatch). The etag MAY also be
///   sent unquoted; the `W/` weak-etag prefix is tolerated. The
///   wildcard form `If-Match: *` is rejected because ovstorage
///   preconditions require a concrete etag.
///
/// `If-Match` and `If-None-Match` are mutually exclusive on a single
/// request: sending both returns `400 InvalidArgument`. Only the
/// literal `*` is accepted for `If-None-Match`; any other value
/// returns `400` (negative etag matching is not supported).
#[utoipa::path(
    put,
    path = "/v1/objects",
    tag = "objects",
    params(
        ("dest" = String, Query, description = "Destination address"),
        ("If-Match" = Option<String>, Header, description = "Overwrite only when the destination's current etag matches"),
        ("If-None-Match" = Option<String>, Header, description = "Only the literal `*` is accepted: refuse if the destination already exists"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (status = 200, body = schema::ObjectInfoResponse, description = "Object written; response reflects the new etag/version/size/mtime"),
        (status = 400, body = schema::ErrorEnvelope, description = "If-Match and If-None-Match both present, If-Match is '*', or If-None-Match value is not '*'"),
        (status = 409, body = schema::ErrorEnvelope, description = "`If-None-Match: *` specified and the target already exists, or `PartialCompletion`: a later stage failed after an earlier one committed durably. Read `error.code` to tell them apart — 409 is NOT safe to treat as a benign conditional-create conflict — and `error.partial` before undoing anything."),
        (status = 412, body = schema::ErrorEnvelope, description = "If-Match precondition failed against the destination's current etag"),
    ),
)]
pub(crate) async fn write_object(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let dest = match required_param(&params, "dest").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let opts = match write_options(&headers) {
        Ok(opts) => opts,
        Err(error) => return error_response(error),
    };
    // `modified_by` attribution is applied by the inner `attribution` wrapper,
    // which reads the principal the auth layer stamped DOWN.
    // Public-facing memory-DoS gate: bridge axum's async body chunk-by-chunk
    // into the sync SPI `BodyStream`; NEVER materialize the request body
    // into a single Vec<u8>.
    //
    // `async_channel` exposes both an async send (yields when full, never
    // blocks the tokio worker) and a `recv_blocking` that uses raw OS
    // primitives (no panic from inside a tokio executor — unlike
    // `tokio::sync::mpsc::blocking_recv`). The producer stays on the main
    // runtime; the plugin's `BodyStream::next_chunk` calls `recv_blocking`
    // from the plugin runtime's worker thread, which is a separate thread
    // from the main executor, so blocking there is safe.
    //
    // Peak in-flight bytes ≤ CAP × chunk_size.
    const CAP: usize = 16;
    let (tx, rx) = async_channel::bounded::<Result<Vec<u8>, Error>>(CAP);
    tokio::spawn(async move {
        use futures::StreamExt;
        let mut data_stream = body.into_data_stream();
        while let Some(chunk) = data_stream.next().await {
            let item = chunk.map(|b| b.to_vec()).map_err(|e| {
                Error::new(
                    ErrorCode::Transient,
                    format!("REST request body read error: {e}"),
                )
            });
            let send_failed = item.is_err();
            if tx.send(item).await.is_err() {
                break;
            }
            if send_failed {
                break;
            }
        }
    });
    let stream = ovstorage_plugin::BodyStream::from_iter(std::iter::from_fn(move || {
        rx.recv_blocking().ok()
    }));
    // Reject-before-drain: the axum body is a lazy
    // `Body::Stream`, and the top-of-stack auth layer gates `Write`
    // on the address BEFORE delegating inward, so an unauthorized write is
    // rejected before the backend consumes the body — naturally, with no probe
    // (REST has no byte cache to reject ahead of). The bounded producer task
    // above stops once the receiver drops on the deny return.
    //
    // Body-bearing writes follow redirects server-side (the follower's
    // `follow_reads=false` suppresses only read-follow), so a multi-step
    // `WriteStep::Redirects` (e.g. s3 multipart) completes here rather than
    // failing as an un-expressible 307. `Body::Stream` size is unknown; the
    // follower derives the size hint and dispatches the body-typed slot.
    let request = cx.request(WriteRequest {
        address: dest,
        body: Body::Stream(stream),
        options: opts,
    });
    match stack.write(request, None).await {
        Ok(result) => Json(to_object_info(&result.info)).into_response(),
        Err(error) => error_response(error),
    }
}

/// Delete an object. An optional `If-Match: "<etag>"` header (RFC 7232)
/// guards against concurrent writes. The etag MAY be sent unquoted;
/// the `W/` weak-etag prefix is tolerated. The wildcard form
/// `If-Match: *` is rejected because ovstorage preconditions require
/// a concrete etag.
#[utoipa::path(
    delete,
    path = "/v1/objects",
    tag = "objects",
    params(
        ("address" = String, Query, description = "Object address to delete"),
        ("If-Match" = Option<String>, Header, description = "Etag precondition: refuse the delete unless the target's current etag matches"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, body = schema::ErrorEnvelope, description = "If-Match: * is not supported; supply a concrete etag"),
        (status = 404, body = schema::ErrorEnvelope, description = "Object did not exist"),
        (status = 412, body = schema::ErrorEnvelope, description = "If-Match precondition failed"),
    ),
)]
pub(crate) async fn delete_object(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let opts = match if_match_single_operand(&headers) {
        Ok(if_match) => DeleteOptions { if_match },
        Err(error) => return error_response(error),
    };
    let request = cx.request(DeleteRequest {
        address,
        options: opts,
    });
    match stack.delete(request, None).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

/// Look up an object's metadata without reading its bytes.
#[utoipa::path(
    get,
    path = "/v1/objects:stat",
    tag = "objects",
    params(
        ("address" = String, Query, description = "Object to stat"),
        ("full_metadata" = Option<bool>, Query, description = "Include user metadata (may require an extra backend call on listing-backed stat implementations)"),
    ),
    responses(
        (status = 200, body = schema::ObjectInfoResponse),
        (status = 404, body = schema::ErrorEnvelope),
    ),
)]
pub(crate) async fn stat_object(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let full_metadata = match bool_param(&params, "full_metadata") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match stat_object_or_directory(&stack, &cx, address, StatOptions { full_metadata }).await {
        Ok(info) => Json(to_object_info(&info)).into_response(),
        Err(error) => error_response(error),
    }
}

/// Stat `address`; if the object form is `NotFound`, retry the directory form so a stat of a
/// directory-shaped path still resolves (the Stack canonicalizes each request).
///
/// Split re-authorization: the object-form stat authorizes
/// `Stat` on the object address in the Layer; the `NotFound` directory retry
/// re-`stat`s the `to_directory` form, which the Layer re-authorizes
/// independently — fail-closed only at the exact object/dir boundary (the safe
/// direction), matching a top-of-stack authz Layer that cannot know the retry
/// reuses the first decision.
async fn stat_object_or_directory(
    stack: &Stack,
    cx: &CallCx,
    address: Url,
    options: StatOptions,
) -> ovstorage::Result<ObjectInfo> {
    let request = cx.request(StatRequest {
        address: address.clone(),
        options: options.clone(),
    });
    match stack.stat(request, None).await {
        Ok(info) => Ok(info),
        Err(error) if error.code() == ErrorCode::NotFound && !address::is_directory(&address) => {
            let dir = address::to_directory(&address)?;
            stack
                .stat(
                    cx.request(StatRequest {
                        address: dir,
                        options,
                    }),
                    None,
                )
                .await
        }
        Err(error) => Err(error),
    }
}

/// List objects under a prefix; defaults to immediate children.
/// `recursive=true` deep-walks (or returns `Unsupported`).
#[utoipa::path(
    get,
    path = "/v1/objects:list",
    tag = "objects",
    params(
        ("prefix" = String, Query, description = "Address prefix to list under"),
        ("recursive" = Option<bool>, Query, description = "Walk all descendants, not just immediate children"),
        ("full_metadata" = Option<bool>, Query, description = "Populate per-item user metadata"),
    ),
    responses((status = 200, body = schema::ObjectInfoList)),
)]
pub(crate) async fn list_objects(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let prefix = match required_param(&params, "prefix").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let recursive = match bool_param(&params, "recursive") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let full_metadata = match bool_param(&params, "full_metadata") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    // Pass the prefix into the Stack as the caller wrote it. The trailing
    // slash is not part of node identity, so authorization decides the same
    // way for either spelling (List pre-check + per-item Stat post-filter) and
    // the backend derives its own directory key. The handler neither
    // normalizes, authz-filters, nor unwraps attribution host-side — the inner
    // `attribution` wrapper harvests `modified_by`.
    let request = cx.request(ListRequest {
        prefix,
        options: ListOptions {
            recursive,
            full_metadata,
            ..ListOptions::default()
        },
    });
    let items = match stack.list(request, None).await {
        Ok(page) => page.items,
        Err(error) => return error_response(error),
    };
    let visible: Vec<schema::ObjectInfoResponse> = items.iter().map(to_object_info).collect();
    Json(schema::ObjectInfoList { items: visible }).into_response()
}

/// List an object's version history; empty on backends without
/// `capabilities.supports_version_listing`.
#[utoipa::path(
    get,
    path = "/v1/objects:versions",
    tag = "objects",
    params(
        ("address" = String, Query, description = "Object whose versions to list"),
        ("max_results" = Option<u32>, Query, description = "Page size cap"),
        ("page_token" = Option<String>, Query, description = "Continuation token from a prior page"),
    ),
    responses((status = 200, body = schema::VersionList)),
)]
pub(crate) async fn list_versions(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let max_results = match u32_param(&params, "max_results") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let opts = ListVersionsOptions {
        max_results,
        page_token: params.get("page_token").cloned(),
    };
    let request = cx.request(ListVersionsRequest {
        address,
        options: opts,
    });
    match stack.list_versions(request, None).await {
        Ok(page) => Json(schema::VersionList {
            items: page.items.iter().map(to_version_info).collect(),
        })
        .into_response(),
        Err(error) => error_response(error),
    }
}

/// Resolve an address to the latest object version.
#[utoipa::path(
    get,
    path = "/v1/objects:latest-version",
    tag = "objects",
    params(("address" = String, Query, description = "Object whose latest version to resolve")),
    responses((status = 200, body = schema::LatestVersionResponse)),
)]
pub(crate) async fn get_latest_version(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let request = cx.request(ReadRequest {
        address,
        options: ReadOptions::default(),
    });
    match stack.get_latest_version(request, None).await {
        Ok(item) => Json(schema::LatestVersionResponse {
            version: to_version_info(&item),
        })
        .into_response(),
        Err(error) => error_response(error),
    }
}

/// Copy an object; server-side when supported, else read+write
/// fallback. Copy has two precondition operands (source and
/// destination), each carried on its own header:
/// - Source-side: `X-OV-If-Source-Match: "<etag>"` — the source must
///   match this etag.
/// - Destination-side: `X-OV-If-Dest-Match: "<etag>"` — the
///   destination must match this etag, or `If-None-Match: *` — the
///   destination must not exist.
///
/// RFC 7232's `If-Match` header has no operand binding and is
/// ambiguous on a two-operand route; sending it on copy returns
/// `400 InvalidArgument`. `X-OV-If-Dest-Match` and `If-None-Match`
/// both target the destination, so sending both also returns `400`.
/// Etag values accept the quoted (`"<etag>"`) or bare form; a leading
/// `W/` weak-etag prefix is tolerated.
#[utoipa::path(
    post,
    path = "/v1/objects:copy",
    tag = "objects",
    params(
        ("X-OV-If-Source-Match" = Option<String>, Header, description = "Source-side etag precondition: refuse the copy unless the source's current etag matches"),
        ("X-OV-If-Dest-Match" = Option<String>, Header, description = "Destination-side etag precondition: refuse the copy unless the destination's current etag matches"),
        ("If-None-Match" = Option<String>, Header, description = "Only the literal `*` is accepted: refuse if the destination already exists"),
    ),
    request_body = schema::CopyRenameBody,
    responses(
        (status = 200, body = schema::ObjectInfoResponse, description = "Destination identity after copy"),
        (status = 400, body = schema::ErrorEnvelope, description = "If-Match present (ambiguous on copy), X-OV-If-Dest-Match and If-None-Match both present, or If-None-Match value is not '*'"),
        (status = 403, body = schema::ErrorEnvelope, description = "Authz denied source or destination"),
        (status = 409, body = schema::ErrorEnvelope, description = "`If-None-Match: *` specified and the destination already exists, or `PartialCompletion`: a later stage failed after an earlier one committed durably. Read `error.code` to tell them apart — 409 is NOT safe to treat as a benign conditional-create conflict — and `error.partial` before undoing anything."),
        (status = 412, body = schema::ErrorEnvelope, description = "Source or destination precondition failed"),
    ),
)]
pub(crate) async fn copy_object(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    headers: HeaderMap,
    Json(body): Json<schema::CopyRenameBody>,
) -> Response {
    let src = match address::parse(&body.src) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    let dest = match address::parse(&body.dest) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    // Security invariant: Copy decomposes into Read(src) + Write(dst) — the
    // Stack's auth layer gates both in `copy` (no standalone Copy op).
    let source_etag = match if_source_match(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let dest_precondition = match if_dest_copy_rename(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let request = cx.request(CopyRequest {
        source: src,
        destination: dest,
        options: CopyOptions {
            if_source: source_etag,
            if_dest: dest_precondition,
            message: None,
        },
    });
    // The `copy_rename_fallback` wrapper decides server-side vs. read+write copy;
    // a completed copy is a terminal `WriteStep::Done`.
    match stack.copy(request, None).await {
        Ok(WriteStep::Done(result)) => Json(to_object_info(&result.info)).into_response(),
        Ok(WriteStep::Redirects(_)) => error_response(Error::new(
            ErrorCode::Unsupported,
            "server-side copy returned redirect continuation",
        )),
        Err(error) => error_response(error),
    }
}

/// Rename (move) an object; atomic when the backend advertises
/// `supports_atomic_rename`, else copy+delete with a non-atomic window.
/// Rename has two precondition operands (source and destination),
/// each carried on its own header:
/// - Source-side: `X-OV-If-Source-Match: "<etag>"` — the source must
///   match this etag.
/// - Destination-side: `X-OV-If-Dest-Match: "<etag>"` — the
///   destination must match this etag, or `If-None-Match: *` — the
///   destination must not exist.
///
/// RFC 7232's `If-Match` header has no operand binding and is
/// ambiguous on a two-operand route; sending it on rename returns
/// `400 InvalidArgument`. `X-OV-If-Dest-Match` and `If-None-Match`
/// both target the destination, so sending both also returns `400`.
/// Etag values accept the quoted (`"<etag>"`) or bare form; a leading
/// `W/` weak-etag prefix is tolerated.
#[utoipa::path(
    post,
    path = "/v1/objects:rename",
    tag = "objects",
    params(
        ("X-OV-If-Source-Match" = Option<String>, Header, description = "Source-side etag precondition: refuse the rename unless the source's current etag matches"),
        ("X-OV-If-Dest-Match" = Option<String>, Header, description = "Destination-side etag precondition: refuse the rename unless the destination's current etag matches"),
        ("If-None-Match" = Option<String>, Header, description = "Only the literal `*` is accepted: refuse if the destination already exists"),
    ),
    request_body = schema::CopyRenameBody,
    responses(
        (status = 204, description = "Renamed"),
        (status = 400, body = schema::ErrorEnvelope, description = "If-Match present (ambiguous on rename), X-OV-If-Dest-Match and If-None-Match both present, or If-None-Match value is not '*'"),
        (status = 409, body = schema::ErrorEnvelope, description = "`If-None-Match: *` specified and the destination already exists, or `PartialCompletion`: a later stage failed after an earlier one committed durably. Read `error.code` to tell them apart — 409 is NOT safe to treat as a benign conditional-create conflict — and `error.partial` before undoing anything."),
        (status = 412, body = schema::ErrorEnvelope, description = "Source or destination precondition failed"),
    ),
)]
pub(crate) async fn rename_object(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    headers: HeaderMap,
    Json(body): Json<schema::CopyRenameBody>,
) -> Response {
    let src = match address::parse(&body.src) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    let dest = match address::parse(&body.dest) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    // Security invariant: Rename decomposes into Read(src) + Delete(src) +
    // Write(dst) — the Stack's auth layer gates all three in `rename`
    // (no standalone Rename op).
    let source_etag = match if_source_match(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let dest_precondition = match if_dest_copy_rename(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let request = cx.request(RenameRequest {
        source: src,
        destination: dest,
        options: RenameOptions {
            if_source: source_etag,
            if_dest: dest_precondition,
            message: None,
        },
    });
    match stack.rename(request, None).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

/// Patch user metadata; sets `set` keys and removes `remove` keys.
/// `allow_rewrite_emulation=true` opts into the non-atomic rewrite
/// fallback when only `supports_metadata_rewrite_emulation` is set.
#[utoipa::path(
    patch,
    path = "/v1/objects:metadata",
    tag = "objects",
    params(
        ("address" = String, Query),
        ("If-Match" = Option<String>, Header, description = "Etag precondition: refuse the metadata update unless the target's current etag matches"),
    ),
    request_body = schema::MetadataPatchBody,
    responses(
        (status = 200, body = schema::ObjectInfoResponse),
        (status = 400, body = schema::ErrorEnvelope, description = "If-Match: * is not supported; supply a concrete etag"),
        (status = 412, body = schema::ErrorEnvelope, description = "If-Match precondition failed"),
    ),
)]
pub(crate) async fn update_metadata(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<schema::MetadataPatchBody>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let etag_precondition = match if_match_single_operand(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    // The Stack's `update_metadata` does not validate the patch (that check is
    // private to the core), so reject a set-and-remove-same-key request here
    // instead of silently applying the set.
    if let Err(error) = validate_metadata_patch(&body.set, &body.remove) {
        return error_response(error);
    }
    let opts = UpdateMetadataOptions {
        if_match: etag_precondition,
        allow_rewrite_emulation: body.allow_rewrite_emulation,
        user_metadata_set: body.set,
        user_metadata_remove: body.remove,
        message: body.message,
    };
    // `modified_by` attribution (stamp on the way down, harvest on the way up)
    // is the inner `attribution` wrapper's job. The Stack
    // returns a `BackendItemInfo`; stamp the caller-facing address back on.
    let request = cx.request(UpdateMetadataRequest {
        address: address.clone(),
        options: opts,
    });
    match stack.update_metadata(request, None).await {
        Ok(item) => {
            let info = ObjectInfo::from((address, item));
            Json(to_object_info(&info)).into_response()
        }
        Err(error) => error_response(error),
    }
}

/// Probe whether the caller could perform the requested operations
/// against the address; returns `Unsupported` without
/// `capabilities.supports_access_check`.
#[utoipa::path(
    post,
    path = "/v1/objects:check-access",
    tag = "objects",
    request_body = schema::CheckAccessBody,
    responses((status = 200, body = schema::AccessDecisionResponse)),
)]
pub(crate) async fn check_access(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Json(body): Json<schema::CheckAccessBody>,
) -> Response {
    let address = match address::parse(&body.address) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    let ops = AccessOps {
        read: body.read,
        write: body.write,
        delete: body.delete,
        update_metadata: body.update_metadata,
    };
    // The Stack's auth layer gates `CheckAccess` and intersects the
    // backend's per-op decision with the authz policy, so an
    // op the policy denies surfaces as `allowed=false` + the matching
    // `denied_ops` bit with the Layer's neutral `"denied by authz policy"`
    // reason — no host-side intersect.
    let request = cx.request(CheckAccessRequest {
        address,
        operations: ops,
    });
    let decision = match stack.check_access(request, None).await {
        Ok(decision) => decision,
        Err(error) => return error_response(error),
    };
    Json(schema::AccessDecisionResponse {
        allowed: decision.allowed,
        denied_ops: to_access_ops(&decision.denied_ops),
        reason: decision.reason,
    })
    .into_response()
}

/// Create a directory; emulated via a zero-byte marker on flat
/// namespaces (S3, GCS), real directory on hierarchical backends.
#[utoipa::path(
    put,
    path = "/v1/directories",
    tag = "directories",
    params(("address" = String, Query)),
    responses((status = 200, body = schema::ObjectInfoResponse)),
)]
pub(crate) async fn create_directory(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    // Pass the `address` into the Stack as the caller wrote it; the backend
    // derives its own directory key. `dir` is computed only to stamp the
    // caller-facing directory address onto the returned info.
    let dir = match address::to_directory(&address) {
        Ok(dir) => dir,
        Err(error) => return error_response(error),
    };
    let request = cx.request(CreateDirectoryRequest {
        address,
        options: CreateDirectoryOptions::default(),
    });
    match stack.create_directory(request, None).await {
        Ok(item) => {
            let info = ObjectInfo::from((dir, item));
            Json(to_object_info(&info)).into_response()
        }
        Err(error) => error_response(error),
    }
}

/// Delete an empty directory; returns `409` if non-empty.
#[utoipa::path(
    delete,
    path = "/v1/directories",
    tag = "directories",
    params(("address" = String, Query)),
    responses(
        (status = 204, description = "Deleted"),
        (status = 409, body = schema::ErrorEnvelope, description = "Directory not empty"),
    ),
)]
pub(crate) async fn delete_directory(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    // The address as the caller wrote it; the backend derives its own
    // directory key.
    let request = cx.request(DeleteDirectoryRequest {
        address,
        options: DeleteDirectoryOptions,
    });
    match stack.delete_directory(request, None).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

/// Look up the capabilities of the backend serving a prefix
/// (feature detection for clients).
#[utoipa::path(
    get,
    path = "/v1/capabilities",
    tag = "discovery",
    params(("prefix" = String, Query)),
    responses((status = 200, body = schema::CapabilitiesResponse)),
)]
pub(crate) async fn get_capabilities(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let prefix = match required_param(&params, "prefix").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    // `root_info_for` is non-per-principal metadata, ungated by the auth layer
    // (mirroring the broker); the gathered credential travels for uniformity.
    match stack.root_info_for(&prefix, &cx.extensions(), None).await {
        Ok(root) => Json(to_capabilities(&root.capabilities)).into_response(),
        Err(error) => error_response(error),
    }
}

/// List every address root currently routed by this gateway.
/// Aliases appear only if their `visibility` is `visible`.
#[utoipa::path(
    get,
    path = "/v1/address-roots",
    tag = "discovery",
    responses((status = 200, body = schema::AddressRootList)),
)]
pub(crate) async fn list_address_roots(State(stack): State<Arc<Stack>>, cx: CallCx) -> Response {
    // The auth layer gates this slot (ListAddressRoots pre-check + per-root
    // Read/List filter) off the principal it resolves from the gathered
    // credential; the alias wrapper below it projects the
    // snapshot (visibility filtering, alias-root synthesis). The handler only
    // gathers the credential and reshapes each surviving root.
    let roots = match stack.list_address_roots(&cx.extensions(), None).await {
        Ok((snapshot, _updates)) => snapshot
            .roots
            .into_iter()
            .map(root_info_to_address_root)
            .collect::<Vec<_>>(),
        Err(error) => return error_response(error),
    };
    Json(schema::AddressRootList {
        items: roots.iter().map(to_address_root).collect(),
    })
    .into_response()
}

/// List the backend kinds this gateway can serve.
#[utoipa::path(
    get,
    path = "/v1/backend-kinds",
    tag = "discovery",
    responses((status = 200, body = schema::BackendKindList)),
)]
pub(crate) async fn list_backend_kinds(
    State(backend_kinds): State<BackendKinds>,
    State(auth_layer): State<ListenerAuth>,
    cx: CallCx,
) -> Response {
    // Backend kinds are served from the set captured at build time, not through
    // the Stack, so no in-stack gate covers this endpoint. Gate it on
    // `ListBackendKinds` off listener auth. Plugin auth routes the gate through
    // its retained Layer's `list_kinds` slot for its authorization side effect.
    let extensions = cx.extensions();
    let authorized = auth_layer.authorize_list_backend_kinds(&extensions);
    if let Err(error) = authorized {
        return error_response(error);
    }
    Json(schema::BackendKindList {
        items: backend_kinds.0.iter().map(to_backend_kind).collect(),
    })
    .into_response()
}

/// Stream directory change events as SSE; pass the latest `cursor`
/// as `since` to resume. A `lapsed` event signals the client should
/// re-list before resuming.
#[utoipa::path(
    get,
    path = "/v1/objects:watch-directory",
    tag = "objects",
    params(
        ("prefix" = String, Query, description = "Directory prefix to watch"),
        ("recursive" = Option<bool>, Query, description = "Include changes in subdirectories"),
        ("include_metadata_changes" = Option<bool>, Query, description = "Emit events for metadata-only changes (default: bytes-changing events only)"),
        ("since" = Option<String>, Query, description = "Resume cursor from a previous watch session"),
        ("poll_interval_ms" = Option<u64>, Query, description = "Polling cadence for backends without push notifications (default 1000ms)"),
    ),
    responses((status = 200, description = "SSE stream of ChangeEventResponse JSON frames", body = schema::ChangeEventResponse, content_type = "text/event-stream")),
)]
pub(crate) async fn watch_directory_sse(
    State(stack): State<Arc<Stack>>,
    cx: CallCx,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let prefix = match required_param(&params, "prefix").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    let recursive = match bool_param(&params, "recursive") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let include_metadata_changes = match bool_param(&params, "include_metadata_changes") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let poll_interval_ms = match u64_param_with_floor(&params, "poll_interval_ms", 100) {
        Ok(value) => value.unwrap_or(1000),
        Err(error) => return error_response(error),
    };
    let opts = WatchDirectoryOptions {
        recursive,
        include_metadata_changes,
        since: params
            .get("since")
            .map(|v| WatchDirectoryCursor(v.as_bytes().to_vec())),
        poll_interval: Duration::from_millis(poll_interval_ms),
    };
    // Pass the prefix into the Stack as the caller wrote it: the authz Layer
    // gates WatchDirectory and re-authorizes `Read` per emitted `Object` event
    // on the returned stream, and the backend derives its own directory key.
    // The per-event Read filter is the
    // Layer's job now — this handler only forwards the already-filtered stream.
    let request = cx.request(WatchDirectoryRequest {
        prefix,
        options: opts,
    });
    let stream = match stack.watch_directory(request, None).await {
        Ok(stream) => stream,
        Err(error) => return error_response(error),
    };
    let (sender, receiver) =
        tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(16);
    std::thread::Builder::new()
        .name("ovs-rest-watch".into())
        .spawn(move || {
            for event in stream {
                let payload = match event {
                    Ok(ev) => match Event::default().json_data(to_change_event(&ev)) {
                        Ok(ev) => ev,
                        Err(_) => continue,
                    },
                    Err(err) => Event::default().event("error").data(format!(
                        r#"{{"code":"{:?}","message":{:?}}}"#,
                        err.code(),
                        err.message()
                    )),
                };
                if sender.blocking_send(Ok(payload)).is_err() {
                    break;
                }
            }
        })
        .expect("failed to spawn thread");
    Sse::new(ReceiverStream::new(receiver))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}
