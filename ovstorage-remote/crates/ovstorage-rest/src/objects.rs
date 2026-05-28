// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
        (status = 404, body = schema::ErrorEnvelope, description = "Object not found at the given address"),
        (status = 412, body = schema::ErrorEnvelope, description = "If-Match precondition failed"),
    ),
)]
pub(crate) async fn read_object(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(&authz, &principal, Operation::Read, Some(&address)).await {
        return error_response(error);
    }
    let opts = match read_options(&headers) {
        Ok(opts) => opts,
        Err(error) => return error_response(error),
    };
    // `read_raw` lets us forward backend redirects to the caller
    // instead of materializing the body server-side.
    match library.read_raw(address, opts, None).await {
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
        Ok(ReadResult::Redirect(redirect)) => (
            StatusCode::TEMPORARY_REDIRECT,
            [
                (axum::http::header::LOCATION, redirect.request.url),
                (
                    axum::http::header::HeaderName::from_static("x-ov-audit-id"),
                    redirect.audit_id,
                ),
            ],
        )
            .into_response(),
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
        (status = 409, body = schema::ErrorEnvelope, description = "If-None-Match: * specified and target already exists"),
        (status = 412, body = schema::ErrorEnvelope, description = "If-Match precondition failed against the destination's current etag"),
    ),
)]
pub(crate) async fn write_object(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    let dest = match required_param(&params, "dest").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(&authz, &principal, Operation::Write, Some(&dest)).await {
        return error_response(error);
    }
    let mut opts = match write_options(&headers) {
        Ok(opts) => opts,
        Err(error) => return error_response(error),
    };
    attribution.stamp_write(&principal, &mut opts);
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
    match library.write(dest, Body::Stream(stream), opts, None).await {
        Ok(mut result) => {
            attribution.unwrap_read(&mut result.info);
            Json(to_object_info(&result.info)).into_response()
        }
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(&authz, &principal, Operation::Delete, Some(&address)).await {
        return error_response(error);
    }
    let opts = match if_match_single_operand(&headers) {
        Ok(if_match) => DeleteOptions { if_match },
        Err(error) => return error_response(error),
    };
    match library.delete(address, opts, None).await {
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(&authz, &principal, Operation::Stat, Some(&address)).await {
        return error_response(error);
    }
    let full_metadata = match bool_param(&params, "full_metadata") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match library
        .stat(address, StatOptions { full_metadata }, None)
        .await
    {
        Ok(mut info) => {
            attribution.unwrap_read(&mut info);
            Json(to_object_info(&info)).into_response()
        }
        Err(error) => error_response(error),
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let prefix = match required_param(&params, "prefix").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(&authz, &principal, Operation::List, Some(&prefix)).await {
        return error_response(error);
    }
    let recursive = match bool_param(&params, "recursive") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let full_metadata = match bool_param(&params, "full_metadata") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let items = match library
        .list(
            prefix.clone(),
            ListOptions {
                recursive,
                full_metadata,
                ..ListOptions::default()
            },
            None,
        )
        .await
    {
        Ok(items) => items,
        Err(error) => return error_response(error),
    };
    // Per-item Read filter (security): an authz plugin denying Read
    // on a specific address must not see it leak through `list`.
    let addresses: Vec<Url> = items.iter().map(|item| item.address.clone()).collect();
    let keep = match crate::filter_list_addresses(&authz, &principal, &prefix, &addresses).await {
        Ok(mask) => mask,
        Err(error) => return error_response(error),
    };
    let visible: Vec<schema::ObjectInfoResponse> = items
        .into_iter()
        .zip(keep)
        .filter_map(|(item, allowed)| {
            if !allowed {
                return None;
            }
            let mut info = item;
            attribution.unwrap_read(&mut info);
            Some(to_object_info(&info))
        })
        .collect();
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) =
        authorize_op(&authz, &principal, Operation::ListVersions, Some(&address)).await
    {
        return error_response(error);
    }
    let max_results = match u32_param(&params, "max_results") {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let opts = ListVersionsOptions {
        max_results,
        page_token: params.get("page_token").cloned(),
    };
    match library.list_versions(address, opts, None).await {
        Ok(mut items) => {
            for item in items.iter_mut() {
                attribution.unwrap_read(item);
            }
            Json(schema::VersionList {
                items: items.iter().map(to_version_info).collect(),
            })
            .into_response()
        }
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) =
        authorize_op(&authz, &principal, Operation::ListVersions, Some(&address)).await
    {
        return error_response(error);
    }
    match library.get_latest_version(address, None).await {
        Ok(mut item) => {
            attribution.unwrap_read(&mut item);
            Json(schema::LatestVersionResponse {
                version: to_version_info(&item),
            })
            .into_response()
        }
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
        (status = 409, body = schema::ErrorEnvelope, description = "If-None-Match: * specified and destination already exists"),
        (status = 412, body = schema::ErrorEnvelope, description = "Source or destination precondition failed"),
    ),
)]
pub(crate) async fn copy_object(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
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
    // Security invariant: Copy decomposes into Read(src) + Write(dst);
    // no standalone Copy authz op.
    if let Err(error) = authorize_op(&authz, &principal, Operation::Read, Some(&src)).await {
        return error_response(error);
    }
    if let Err(error) = authorize_op(&authz, &principal, Operation::Write, Some(&dest)).await {
        return error_response(error);
    }
    let source_etag = match if_source_match(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let dest_precondition = match if_dest_copy_rename(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match library
        .copy(
            src,
            dest,
            CopyOptions {
                if_source: source_etag,
                if_dest: dest_precondition,
                message: None,
            },
            None,
        )
        .await
    {
        Ok(mut result) => {
            attribution.unwrap_read(&mut result.info);
            Json(to_object_info(&result.info)).into_response()
        }
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
        (status = 409, body = schema::ErrorEnvelope, description = "If-None-Match: * specified and destination already exists"),
        (status = 412, body = schema::ErrorEnvelope, description = "Source or destination precondition failed"),
    ),
)]
pub(crate) async fn rename_object(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
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
    // Security invariant: Rename decomposes into Read(src) + Delete(src) + Write(dst);
    // no standalone Rename authz op.
    if let Err(error) = authorize_op(&authz, &principal, Operation::Read, Some(&src)).await {
        return error_response(error);
    }
    if let Err(error) = authorize_op(&authz, &principal, Operation::Delete, Some(&src)).await {
        return error_response(error);
    }
    if let Err(error) = authorize_op(&authz, &principal, Operation::Write, Some(&dest)).await {
        return error_response(error);
    }
    let source_etag = match if_source_match(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let dest_precondition = match if_dest_copy_rename(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    match library
        .rename(
            src,
            dest,
            RenameOptions {
                if_source: source_etag,
                if_dest: dest_precondition,
                message: None,
            },
            None,
        )
        .await
    {
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<schema::MetadataPatchBody>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(
        &authz,
        &principal,
        Operation::UpdateMetadata,
        Some(&address),
    )
    .await
    {
        return error_response(error);
    }
    let etag_precondition = match if_match_single_operand(&headers) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let mut opts = UpdateMetadataOptions {
        if_match: etag_precondition,
        allow_rewrite_emulation: body.allow_rewrite_emulation,
        user_metadata_set: body.set,
        user_metadata_remove: body.remove,
        message: body.message,
    };
    attribution.stamp_update_metadata(&principal, &mut opts);
    match library.update_metadata(address, opts, None).await {
        Ok(mut info) => {
            attribution.unwrap_read(&mut info);
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Json(body): Json<schema::CheckAccessBody>,
) -> Response {
    let address = match address::parse(&body.address) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    if let Err(error) =
        authorize_op(&authz, &principal, Operation::CheckAccess, Some(&address)).await
    {
        return error_response(error);
    }
    let ops = AccessOps {
        read: body.read,
        write: body.write,
        delete: body.delete,
        update_metadata: body.update_metadata,
    };
    let mut decision = match library
        .check_access(address.clone(), ops.clone(), None)
        .await
    {
        Ok(decision) => decision,
        Err(error) => return error_response(error),
    };
    let context = RequestContext {
        principal: principal.clone(),
        policy_epoch: authz.policy.current_epoch(),
        audit_id: None,
    };
    if let Err(error) = ovstorage_authz::compose::apply_authz_access_decision(
        &authz,
        &context,
        &address,
        &ops,
        &mut decision,
        "denied by REST authz",
    )
    .await
    {
        return error_response(error);
    }
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    State(attribution): State<AttributionLayer>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(
        &authz,
        &principal,
        Operation::CreateDirectory,
        Some(&address),
    )
    .await
    {
        return error_response(error);
    }
    match library
        .create_directory(address, CreateDirectoryOptions::default(), None)
        .await
    {
        Ok(mut info) => {
            attribution.unwrap_read(&mut info);
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let address = match required_param(&params, "address").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(
        &authz,
        &principal,
        Operation::DeleteDirectory,
        Some(&address),
    )
    .await
    {
        return error_response(error);
    }
    match library
        .delete_directory(address, DeleteDirectoryOptions, None)
        .await
    {
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let prefix = match required_param(&params, "prefix").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    // No dedicated `Capabilities` authz op; reuse `Stat`.
    if let Err(error) = authorize_op(&authz, &principal, Operation::Stat, Some(&prefix)).await {
        return error_response(error);
    }
    match library.capabilities_for(&prefix) {
        Ok(caps) => Json(to_capabilities(&caps)).into_response(),
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
pub(crate) async fn list_address_roots(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
) -> Response {
    if let Err(error) = authorize_op(&authz, &principal, Operation::ListAddressRoots, None).await {
        return error_response(error);
    }
    let roots = match library.list_address_roots() {
        Ok(roots) => roots,
        Err(error) => return error_response(error),
    };
    let context = RequestContext {
        principal: principal.clone(),
        policy_epoch: authz.policy.current_epoch(),
        audit_id: None,
    };
    let roots = match ovstorage_authz::compose::filter_address_roots(&authz, &context, roots).await
    {
        Ok(roots) => roots,
        Err(error) => return error_response(error),
    };
    Json(schema::AddressRootList {
        items: roots.iter().map(to_address_root).collect(),
    })
    .into_response()
}

/// List backend kinds available to `POST /v1/connections`.
#[utoipa::path(
    get,
    path = "/v1/backend-kinds",
    tag = "discovery",
    responses((status = 200, body = schema::BackendKindList)),
)]
pub(crate) async fn list_backend_kinds(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
) -> Response {
    if let Err(error) = authorize_op(&authz, &principal, Operation::ListBackendKinds, None).await {
        return error_response(error);
    }
    match library.list_backend_kinds() {
        Ok(kinds) => Json(schema::BackendKindList {
            items: kinds.iter().map(to_backend_kind).collect(),
        })
        .into_response(),
        Err(error) => error_response(error),
    }
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
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let prefix = match required_param(&params, "prefix").and_then(|s| address::parse(&s)) {
        Ok(address) => address,
        Err(error) => return error_response(error),
    };
    if let Err(error) =
        authorize_op(&authz, &principal, Operation::WatchDirectory, Some(&prefix)).await
    {
        return error_response(error);
    }
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
    // Per-event Read filter (security): object events for addresses
    // the principal can't Read are dropped silently; upstream `Lapsed`
    // events still pass through.
    let stream = match library.watch_directory(prefix, opts, None).await {
        Ok(stream) => stream,
        Err(error) => return error_response(error),
    };
    let (sender, receiver) =
        tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(16);
    let watch_authz = authz.clone();
    let watch_principal = principal.clone();
    let runtime_handle = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("ovs-rest-watch".into())
        .spawn(move || {
            for event in stream {
                let event = match event {
                    Ok(ChangeEvent::Object { ref address, .. }) => {
                        let allowed_result = runtime_handle.block_on(authz_allows_read(
                            &watch_authz,
                            &watch_principal,
                            address,
                        ));
                        match allowed_result {
                            Ok(true) => event,
                            Ok(false) => continue,
                            Err(err) if err.code() == ErrorCode::PermissionDenied => continue,
                            Err(err) => Err(err),
                        }
                    }
                    _ => event,
                };
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
