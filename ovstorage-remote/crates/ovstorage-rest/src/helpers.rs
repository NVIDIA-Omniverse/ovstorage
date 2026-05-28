// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) fn parse_visibility(value: Option<&str>) -> ovstorage::Result<AddressVisibility> {
    match value {
        None | Some("visible") => Ok(AddressVisibility::Visible),
        Some("hidden") => Ok(AddressVisibility::Hidden),
        Some("suppressed") => Ok(AddressVisibility::Suppressed),
        Some(other) => Err(invalid(format!(
            "unknown visibility '{other}' (use 'visible', 'hidden', or 'suppressed')"
        ))),
    }
}

pub(crate) fn visibility_str(visibility: &AddressVisibility) -> &'static str {
    match visibility {
        AddressVisibility::Visible => "visible",
        AddressVisibility::Hidden => "hidden",
        AddressVisibility::Suppressed => "suppressed",
    }
}

pub(crate) fn to_connection(c: &ovstorage::Connection) -> schema::ConnectionResponse {
    schema::ConnectionResponse {
        id: c.id.0.clone(),
        backend_kind: c.backend_kind.clone(),
        display_name: c.display_name.clone(),
        current_addresses: c.current_addresses.iter().map(|a| a.to_string()).collect(),
    }
}

pub(crate) fn to_alias(a: &ovstorage::Alias) -> schema::AliasResponse {
    schema::AliasResponse {
        id: a.id.0.clone(),
        from: a.from.to_string(),
        to: a.to.to_string(),
        visibility: visibility_str(&a.visibility).into(),
        display_name: a.display_name.clone(),
    }
}

pub(crate) fn to_visibility_override(
    o: &ovstorage::AddressVisibilityOverride,
) -> schema::VisibilityOverrideResponse {
    schema::VisibilityOverrideResponse {
        address: o.address.to_string(),
        visibility: visibility_str(&o.visibility).into(),
        persisted: o.persisted,
    }
}

pub(crate) fn to_auth_event(event: &AuthEvent) -> schema::AuthEventResponse {
    match event {
        AuthEvent::OpenBrowser { url, .. } => {
            schema::AuthEventResponse::OpenBrowser { url: url.clone() }
        }
        AuthEvent::DeviceCode {
            user_code,
            verification_url,
            ..
        } => schema::AuthEventResponse::DeviceCode {
            user_code: user_code.clone(),
            verification_url: verification_url.clone(),
        },
        AuthEvent::Progress { message } => schema::AuthEventResponse::Progress {
            message: message.clone(),
        },
        AuthEvent::Succeeded {
            connection,
            credentials: _,
        } => schema::AuthEventResponse::Succeeded {
            connection: to_connection(connection),
        },
        AuthEvent::Failed { error } => schema::AuthEventResponse::Failed {
            error: schema::ErrorBody {
                code: format!("{:?}", error.code()),
                message: error.message().to_string(),
            },
        },
        AuthEvent::Cancelled => schema::AuthEventResponse::Cancelled,
    }
}

pub(crate) fn to_change_event(event: &ChangeEvent) -> schema::ChangeEventResponse {
    match event {
        ChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            cursor,
            ..
        } => schema::ChangeEventResponse::Object {
            address: address.to_string(),
            kind: match kind {
                ChangeKind::Created => "created".into(),
                ChangeKind::Modified => "modified".into(),
                ChangeKind::Deleted => "deleted".into(),
                ChangeKind::MetadataChanged => "metadata_changed".into(),
            },
            etag: etag.clone(),
            version: version.clone(),
            size: *size,
            mtime_unix_nanos: mtime.and_then(system_time_to_unix_nanos),
            cursor: String::from_utf8_lossy(&cursor.0).into(),
        },
        ChangeEvent::Lapsed { cursor, .. } => schema::ChangeEventResponse::Lapsed {
            cursor: String::from_utf8_lossy(&cursor.0).into(),
        },
    }
}

pub(crate) fn u32_param(
    params: &HashMap<String, String>,
    key: &str,
) -> ovstorage::Result<Option<u32>> {
    match params.get(key) {
        None => Ok(None),
        Some(value) => value.parse::<u32>().map(Some).map_err(|_| {
            invalid(format!(
                "'{key}' must be a non-negative integer (got {value:?})"
            ))
        }),
    }
}

pub(crate) fn bool_param(params: &HashMap<String, String>, key: &str) -> ovstorage::Result<bool> {
    match params.get(key).map(String::as_str) {
        None => Ok(false),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(other) => Err(invalid(format!(
            "'{key}' must be 'true', 'false', '1', or '0' (got {other:?})"
        ))),
    }
}

pub(crate) fn u64_param_with_floor(
    params: &HashMap<String, String>,
    key: &str,
    floor: u64,
) -> ovstorage::Result<Option<u64>> {
    match params.get(key) {
        None => Ok(None),
        Some(value) => {
            let parsed = value.parse::<u64>().map_err(|_| {
                invalid(format!(
                    "'{key}' must be a non-negative integer (got {value:?})"
                ))
            })?;
            if parsed < floor {
                return Err(invalid(format!(
                    "'{key}' must be >= {floor} (got {parsed})"
                )));
            }
            Ok(Some(parsed))
        }
    }
}

pub(crate) fn required_param(
    params: &HashMap<String, String>,
    key: &str,
) -> ovstorage::Result<String> {
    params.get(key).cloned().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("missing '{key}' query parameter"),
        )
    })
}

pub(crate) fn read_options(headers: &HeaderMap) -> ovstorage::Result<ReadOptions> {
    Ok(ReadOptions {
        if_match: if_match_single_operand(headers)?,
        range: range_header(headers)?,
        max_bytes: None,
    })
}

pub(crate) fn write_options(headers: &HeaderMap) -> ovstorage::Result<WriteOptions> {
    Ok(WriteOptions {
        if_dest: if_dest_single_operand(headers)?,
        ..WriteOptions::default()
    })
}

/// Error message for the 400 returned when a copy / rename request
/// carries a bare `If-Match` header. RFC 7232's `If-Match` is
/// ambiguous on copy / rename because there are two precondition
/// operands (source and destination); callers must use the explicit
/// `X-OV-If-Source-Match` and / or `X-OV-If-Dest-Match` headers.
const COPY_RENAME_IF_MATCH_REJECTION: &str = "If-Match not accepted on copy / rename (ambiguous). Use X-OV-If-Source-Match or X-OV-If-Dest-Match.";

/// Normalize the etag value out of a quoted-or-bare RFC 7232 etag
/// header. Strips a leading `W/` (weak-etag prefix, tolerated but
/// compared strongly) and any surrounding double quotes. Returns
/// `Ok(None)` when the header is absent or empty.
///
/// RFC 7232's wildcard form (`If-Match: *`) means "match any current
/// representation", which the SPI cannot represent as an etag string.
/// Reject it explicitly instead of silently dropping the precondition.
fn parse_etag_header(
    headers: &HeaderMap,
    header_name: &str,
    display_name: &str,
) -> ovstorage::Result<Option<String>> {
    let Some(value) = headers.get(header_name) else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| invalid(format!("{display_name} must be valid UTF-8")))?
        .trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if raw == "*" {
        return Err(invalid(format!(
            "{display_name}: '*' is not supported; supply a concrete etag or omit the header"
        )));
    }
    let etag = raw.strip_prefix("W/").unwrap_or(raw);
    let etag = etag.strip_prefix('"').unwrap_or(etag);
    let etag = etag.strip_suffix('"').unwrap_or(etag);
    Ok(Some(etag.to_string()))
}

/// Parse the standard RFC 7232 `If-Match` header for routes with a
/// single precondition operand (read / delete / update-metadata; the
/// target is the only thing the precondition can apply to).
///
/// Accepts both the quoted form `"<etag>"` (canonical) and a bare
/// `<etag>`; strips a leading `W/` (weak-etag prefix, tolerated but
/// compared strongly) and any surrounding double quotes before
/// returning the inner opaque etag.
///
/// Returns `Ok(None)` when the header is absent or empty. The wildcard
/// form `If-Match: *` is rejected with `InvalidArgument`; callers must
/// use a concrete etag for ovstorage preconditions.
pub(crate) fn if_match_single_operand(headers: &HeaderMap) -> ovstorage::Result<Option<String>> {
    parse_etag_header(headers, "if-match", "If-Match")
}

/// Parse the standard RFC 7232 `If-Match` and `If-None-Match` headers
/// into the SPI's [`IfDestExists`] for the single-operand write route
/// (the target is the destination).
///
/// Mapping:
/// - neither header — [`IfDestExists::Overwrite`] (default for an
///   unconditional PUT).
/// - `If-None-Match: *` — [`IfDestExists::Fail`] (RFC 7232: evaluate
///   as if no current entity exists; only `*` is supported, any other
///   value is rejected with 400).
/// - `If-Match: "<etag>"` (or bare `<etag>`) — [`IfDestExists::MatchEtag`]
///   carrying the unquoted opaque etag.
///
/// `If-Match` and `If-None-Match` are mutually exclusive on a single
/// write request: presenting both returns 400.
pub(crate) fn if_dest_single_operand(headers: &HeaderMap) -> ovstorage::Result<IfDestExists> {
    let if_match_value = headers.get("if-match");
    let if_none_match_value = headers.get("if-none-match");
    if if_match_value.is_some() && if_none_match_value.is_some() {
        return Err(invalid(
            "If-Match and If-None-Match are mutually exclusive on a single request",
        ));
    }
    if let Some(value) = if_none_match_value {
        let raw = value
            .to_str()
            .map_err(|_| invalid("If-None-Match must be valid UTF-8"))?
            .trim();
        return match raw {
            "*" => Ok(IfDestExists::Fail),
            other => Err(invalid(format!(
                "If-None-Match must be '*' (got {other:?}); negative etag matching is not supported"
            ))),
        };
    }
    match if_match_single_operand(headers)? {
        Some(etag) => Ok(IfDestExists::MatchEtag(etag)),
        None => Ok(IfDestExists::Overwrite),
    }
}

/// Parse the source-side precondition header `X-OV-If-Source-Match`
/// for copy / rename routes.
///
/// Copy / rename carry two precondition operands (source and
/// destination) but RFC 7232's `If-Match` defines only one operand
/// per request — so a bare `If-Match` on copy / rename is ambiguous
/// and rejected with 400 (see [`if_dest_copy_rename`]). The source
/// side rides on this dedicated header; the destination side rides
/// on `X-OV-If-Dest-Match` (mirroring AWS S3's
/// `x-amz-copy-source-if-match` / `x-amz-copy-source-if-none-match`
/// split).
///
/// Accepts both the quoted form `"<etag>"` and a bare `<etag>`;
/// strips a leading `W/` weak-etag prefix and any surrounding double
/// quotes — symmetric with `If-Match` normalization on the
/// single-operand routes.
pub(crate) fn if_source_match(headers: &HeaderMap) -> ovstorage::Result<Option<String>> {
    parse_etag_header(headers, "x-ov-if-source-match", "X-OV-If-Source-Match")
}

/// Parse the destination-side precondition headers for copy / rename
/// routes: `X-OV-If-Dest-Match` (etag must match) and
/// `If-None-Match: *` (destination must not exist).
///
/// Mapping:
/// - neither header — [`IfDestExists::Overwrite`] (default for an
///   unconditional copy / rename).
/// - `If-None-Match: *` — [`IfDestExists::Fail`].
/// - `X-OV-If-Dest-Match: "<etag>"` — [`IfDestExists::MatchEtag`]
///   carrying the unquoted opaque etag.
///
/// A bare RFC 7232 `If-Match` header is rejected with 400: it is
/// ambiguous on copy / rename because it has no operand binding.
/// Callers point at `X-OV-If-Source-Match` (source side) and / or
/// `X-OV-If-Dest-Match` (destination side) explicitly.
///
/// `X-OV-If-Dest-Match` and `If-None-Match` both target the
/// destination; presenting both returns 400.
pub(crate) fn if_dest_copy_rename(headers: &HeaderMap) -> ovstorage::Result<IfDestExists> {
    if headers.get("if-match").is_some() {
        return Err(invalid(COPY_RENAME_IF_MATCH_REJECTION));
    }
    let if_dest_match_value = headers.get("x-ov-if-dest-match");
    let if_none_match_value = headers.get("if-none-match");
    if if_dest_match_value.is_some() && if_none_match_value.is_some() {
        return Err(invalid(
            "X-OV-If-Dest-Match and If-None-Match both target the destination and are mutually exclusive on a single request",
        ));
    }
    if let Some(value) = if_none_match_value {
        let raw = value
            .to_str()
            .map_err(|_| invalid("If-None-Match must be valid UTF-8"))?
            .trim();
        return match raw {
            "*" => Ok(IfDestExists::Fail),
            other => Err(invalid(format!(
                "If-None-Match must be '*' (got {other:?}); negative etag matching is not supported"
            ))),
        };
    }
    match parse_etag_header(headers, "x-ov-if-dest-match", "X-OV-If-Dest-Match")? {
        Some(etag) => Ok(IfDestExists::MatchEtag(etag)),
        None => Ok(IfDestExists::Overwrite),
    }
}

pub(crate) fn range_header(headers: &HeaderMap) -> ovstorage::Result<Option<ByteRange>> {
    let Some(value) = headers.get("range") else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| invalid("Range must be valid UTF-8"))?;
    let Some(range) = value.strip_prefix("bytes=") else {
        return Err(invalid("only bytes ranges are supported"));
    };
    let Some((start, end)) = range.split_once('-') else {
        return Err(invalid("Range must be bytes=START-END"));
    };
    Ok(Some(ByteRange {
        start: start
            .parse()
            .map_err(|_| invalid("Range start must be an integer"))?,
        end_inclusive: if end.is_empty() {
            None
        } else {
            Some(
                end.parse()
                    .map_err(|_| invalid("Range end must be an integer"))?,
            )
        },
    }))
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

pub(crate) fn to_object_info(info: &ovstorage::ObjectInfo) -> schema::ObjectInfoResponse {
    schema::ObjectInfoResponse {
        address: info.address.to_string(),
        kind: object_kind_str(info.kind).into(),
        etag: info.etag.clone(),
        version: info.version.clone(),
        size: info.size,
        mtime_unix_nanos: info.mtime.and_then(system_time_to_unix_nanos),
        system_metadata: info.system_metadata.clone(),
        user_metadata: info.user_metadata.clone(),
    }
}

/// Stable wire string for [`ObjectKind`]. Delegates to the canonical
/// SPI helper so REST and MCP (and any future agent-facing surface)
/// emit the same shape.
pub(crate) fn object_kind_str(kind: ovstorage::ObjectKind) -> &'static str {
    kind.as_str()
}

/// Convert a `SystemTime` to Unix nanoseconds. Returns `None` for
/// times before the epoch (defensive — no valid mtime is pre-1970).
fn system_time_to_unix_nanos(time: std::time::SystemTime) -> Option<i128> {
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i128)
}

pub(crate) fn to_version_info(info: &ovstorage::ObjectInfo) -> schema::ObjectInfoResponse {
    to_object_info(info)
}

pub(crate) fn to_access_ops(ops: &ovstorage::AccessOps) -> schema::AccessOpsResponse {
    schema::AccessOpsResponse {
        read: ops.read,
        write: ops.write,
        delete: ops.delete,
        update_metadata: ops.update_metadata,
    }
}

pub(crate) fn to_capabilities(c: &ovstorage::Capabilities) -> schema::CapabilitiesResponse {
    schema::CapabilitiesResponse {
        supports_if_match_write: c.supports_if_match_write,
        supports_no_overwrite_write: c.supports_no_overwrite_write,
        supports_native_metadata_patch: c.supports_native_metadata_patch,
        supports_metadata_rewrite_emulation: c.supports_metadata_rewrite_emulation,
        writes_are_atomic: c.writes_are_atomic,
        supports_server_side_copy: c.supports_server_side_copy,
        supports_server_side_rename: c.supports_server_side_rename,
        supports_atomic_rename: c.supports_atomic_rename,
        has_real_directories: c.has_real_directories,
        supports_list: c.supports_list,
        wants_list_backed_stat: c.wants_list_backed_stat,
        supports_recursive_list: c.supports_recursive_list,
        populates_subdirectory_metadata: c.populates_subdirectory_metadata,
        supports_version_listing: c.supports_version_listing,
        populates_effective_permissions_on_stat: c.populates_effective_permissions_on_stat,
        supports_access_check: c.supports_access_check,
        supports_watch_directory: c.supports_watch_directory,
        watch_directory_resumable: c.watch_directory_resumable,
        supports_write: c.supports_write,
        supports_write_stream: c.supports_write_stream,
        supports_write_redirect: c.supports_write_redirect,
        supports_delete: c.supports_delete,
        supports_create_directory: c.supports_create_directory,
        supports_delete_directory: c.supports_delete_directory,
    }
}

pub(crate) fn to_address_root(root: &ovstorage::AddressRoot) -> schema::AddressRootResponse {
    schema::AddressRootResponse {
        address: root.address.to_string(),
        display_name: root.display_name.clone(),
        backend_kind: root.backend_kind.clone(),
        connection_id: root.connection_id.as_ref().map(|c| c.0.clone()),
        capabilities: to_capabilities(&root.capabilities),
    }
}

pub(crate) fn to_backend_kind(
    k: &ovstorage::StorageBackendKindDescriptor,
) -> schema::BackendKindResponse {
    schema::BackendKindResponse {
        kind: k.kind.clone(),
        display_name: k.display_name.clone(),
        description: k.description.clone(),
        supports_runtime_add: k.supports_runtime_add,
    }
}

pub(crate) fn error_response(error: Error) -> Response {
    (
        status_for_error(error.code()),
        Json(schema::ErrorEnvelope {
            error: schema::ErrorBody {
                code: format!("{:?}", error.code()),
                message: error.message().to_string(),
            },
        }),
    )
        .into_response()
}

pub(crate) fn status_for_error(code: ErrorCode) -> StatusCode {
    // Exhaustive match: a wildcard would silently collapse new
    // variants to 500 and lose retryability information for clients.
    match code {
        ErrorCode::NotFound | ErrorCode::NoRoute | ErrorCode::NotConfigured => {
            StatusCode::NOT_FOUND
        }
        ErrorCode::PermissionDenied | ErrorCode::PluginRejected => StatusCode::FORBIDDEN,
        ErrorCode::AuthRequired
        | ErrorCode::AuthExpired
        | ErrorCode::AuthCancelled
        | ErrorCode::CredentialExpired
        | ErrorCode::CredentialUnavailable
        | ErrorCode::AuthorizationLeaseExpired => StatusCode::UNAUTHORIZED,
        ErrorCode::InvalidArgument | ErrorCode::AliasChainTooLong => StatusCode::BAD_REQUEST,
        ErrorCode::AlreadyExists
        | ErrorCode::Conflict
        | ErrorCode::DirectoryNotEmpty
        | ErrorCode::IncompatibleType
        | ErrorCode::RouteConflict
        | ErrorCode::PolicyEpochStale => StatusCode::CONFLICT,
        ErrorCode::Locked => StatusCode::LOCKED,
        // 412 is canonical for precondition mismatches; both
        // PreconditionFailed and ObjectModified round-trip to it.
        ErrorCode::PreconditionFailed | ErrorCode::ObjectModified => {
            StatusCode::PRECONDITION_FAILED
        }
        // 422 fits content-integrity violations: server understood
        // the request but rejected the payload as semantically wrong.
        ErrorCode::IntegrityFailure
        | ErrorCode::ContentMismatch
        | ErrorCode::ContentChecksumMismatch => StatusCode::UNPROCESSABLE_ENTITY,
        // 410 fits expired/gone resources (redirect URLs, staged uploads).
        ErrorCode::RedirectExpired | ErrorCode::StagingExpired => StatusCode::GONE,
        ErrorCode::Unsupported => StatusCode::NOT_IMPLEMENTED,
        ErrorCode::ResourceExhausted | ErrorCode::CacheLockContention => {
            StatusCode::TOO_MANY_REQUESTS
        }
        // 504 fits cancellation/deadline-exceeded — both indicate the
        // server didn't get to a result before the client/scheduler
        // gave up.
        ErrorCode::Cancelled | ErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        // 502 is "upstream returned a transient/unavailable signal";
        // 503 is "this server can't handle requests right now (state-
        // root unreachable, broker-required mode rejecting unbrokered)".
        ErrorCode::Transient | ErrorCode::BrokerUnavailable => StatusCode::BAD_GATEWAY,
        ErrorCode::BrokerRequired
        | ErrorCode::StateRootUnavailable
        | ErrorCode::NetworkFilesystemRefused => StatusCode::SERVICE_UNAVAILABLE,
        // Genuinely internal: server-side data corruption or
        // ambiguity; surface as 500 so clients don't auto-retry.
        ErrorCode::Internal | ErrorCode::CacheCorrupt | ErrorCode::CommitAmbiguous => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        // Defensive: future ErrorCode variants surface as 500 until
        // they get an explicit arm. `ErrorCode` is `#[non_exhaustive]`.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
