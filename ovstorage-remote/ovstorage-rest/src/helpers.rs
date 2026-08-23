// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Reject a metadata patch that both sets and removes the same user-metadata
/// key. The Stack's `update_metadata` does not re-check, and the file backend applies
/// remove-then-set, so an overlapping key would otherwise silently resolve to a
/// set instead of `InvalidArgument` (400).
pub(crate) fn validate_metadata_patch(
    set: &HashMap<String, String>,
    remove: &[String],
) -> ovstorage::Result<()> {
    for key in remove {
        if set.contains_key(key) {
            return Err(invalid(
                "metadata update cannot set and remove the same key",
            ));
        }
    }
    Ok(())
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

/// Stable wire string for [`ovstorage::ObjectKind`]. Delegates to the canonical
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
        supports_copy: c.supports_copy,
        supports_rename: c.supports_rename,
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

/// Project a Stack `RootInfo` (the `list_address_roots` element) to the
/// public [`AddressRoot`] the authz root filter and response encoder
/// consume. The extra `RootInfo` fields (range-read strategy, alias state,
/// icon) have no gateway-facing surface and are dropped.
pub(crate) fn root_info_to_address_root(root: RootInfo) -> AddressRoot {
    AddressRoot {
        address: root.root,
        display_name: root.display_name,
        backend_kind: root.layer_kind,
        connection_id: root.connection_id,
        capabilities: root.capabilities,
        source: root.source,
        visibility: root.visibility,
        user_metadata: root.user_metadata,
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
    // The status class is coarse — `PartialCompletion` shares 409 with
    // `AlreadyExists`, whose meaning is the opposite ("nothing was written") —
    // so everything a caller acts on has to be in the body.
    let partial = match error.context() {
        Some(ovstorage::ErrorContext::Partial {
            completed,
            failed,
            failed_outcome,
            rollback,
        }) => Some(schema::PartialBody {
            completed: completed.as_str().to_string(),
            failed: failed.as_str().to_string(),
            failed_outcome: failed_outcome.as_str().to_string(),
            rollback: rollback.as_str().to_string(),
        }),
        // `new_etag` IS actionable and is dropped here: REST has no field or
        // header for it, so a conditional-retry loop against this gateway
        // cannot read it the way a gRPC client can. A stated gap.
        Some(ovstorage::ErrorContext::Identity { .. }) => None,
        // Likewise `connection_id`, `reason` and `expired_at`, which a client
        // would use to pick a connection to re-authenticate and to tell an
        // expiry apart from a refusal. Also a gap, and a separate one —
        // sharing an arm with `Identity` would have let one justification
        // stand for both payloads.
        Some(ovstorage::ErrorContext::Auth { .. }) => None,
        None => None,
    };
    (
        status_for_error(error.code()),
        Json(schema::ErrorEnvelope {
            error: schema::ErrorBody {
                code: format!("{:?}", error.code()),
                message: error.message().to_string(),
                next_action: error.next_action().map(str::to_string),
                partial,
            },
        }),
    )
        .into_response()
}

pub(crate) fn status_for_error(code: ErrorCode) -> StatusCode {
    // Every code in `ErrorCode::KNOWN` has an explicit arm. The trailing
    // wildcard is required because `ErrorCode` is `#[non_exhaustive]` and
    // defined in another crate; it is a hazard, not a safety net, since a new
    // code without an arm collapses to 500 and loses its retryability
    // information for clients. `every_known_code_has_an_explicit_status`
    // walks `ErrorCode::KNOWN` and is what catches the omission.
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
        // 409 rather than 500: generic retry middleware and SDK retry
        // policies replay PUT on 5xx before any application code reads the
        // body, re-committing bytes that are already durable and changing the
        // etag — the exact replay `CONFORMANCE.md` forbids. 4xx is final for
        // every standard retry policy, so the body payload reaches the caller
        // intact. `code` carries `"PartialCompletion"` verbatim and the
        // `partial` object carries the rollback consequence; a client that
        // reads both can distinguish it from `AlreadyExists`, which also maps
        // here. `CONFORMANCE.md` under multi-stage durability states that
        // status-class retry is wrong for this code.
        ErrorCode::PartialCompletion => StatusCode::CONFLICT,
        // Defensive: future ErrorCode variants surface as 500 until
        // they get an explicit arm. `ErrorCode` is `#[non_exhaustive]`.
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod error_status_tests {
    use super::*;

    /// `status_for_error` needs a trailing `_` arm because `ErrorCode` is
    /// `#[non_exhaustive]` and defined in another crate. That arm silently
    /// collapses an unclassified code onto 500 and loses its retryability
    /// information, so walk `KNOWN` and assert every code was classified on
    /// purpose. The proxy for "explicit arm" is that the status is not the
    /// wildcard's 500 — except for the codes that legitimately map to 500,
    /// which are named here so adding one is a deliberate edit.
    #[test]
    fn every_known_code_has_an_explicit_status() {
        const DELIBERATE_500: &[ErrorCode] = &[
            ErrorCode::Internal,
            ErrorCode::CacheCorrupt,
            ErrorCode::CommitAmbiguous,
        ];
        assert!(
            !ErrorCode::KNOWN.is_empty(),
            "KNOWN is empty, so this test asserts nothing",
        );
        for &code in ErrorCode::KNOWN {
            let status = status_for_error(code);
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                assert!(
                    DELIBERATE_500.contains(&code),
                    "{code:?} maps to 500. If that is intended, add it to \
                     DELIBERATE_500; otherwise it is falling through the \
                     wildcard and has no explicit arm.",
                );
            }
        }
    }

    /// 409 stops generic retry middleware from replaying the PUT (which
    /// would re-commit already-durable bytes). The body is what carries the
    /// distinction from `AlreadyExists`, so assert the code name is in it
    /// verbatim and that both can be told apart without touching the status.
    #[test]
    fn partial_completion_is_409_and_names_itself_in_the_body() {
        assert_eq!(
            status_for_error(ErrorCode::PartialCompletion),
            StatusCode::CONFLICT,
        );
        // Read `code` out of the RESPONSE `error_response` builds, not out of a
        // re-implementation of its formatting expression. The earlier version
        // asserted on its own `format!` copy, so changing `error_response` to
        // emit a bucket name — or to drop `code` entirely — left it green while
        // destroying the only thing that distinguishes this from a generic 409.
        let code_of = |code: ErrorCode| -> String {
            let response = error_response(Error::new(code, "x"));
            let body =
                futures::executor::block_on(axum::body::to_bytes(response.into_body(), 64 * 1024))
                    .expect("body");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            json["error"]["code"]
                .as_str()
                .expect("code is a string")
                .to_string()
        };
        assert_eq!(code_of(ErrorCode::PartialCompletion), "PartialCompletion");
        // Distinguishable from `AlreadyExists`, which also maps to 409.
        assert_ne!(
            code_of(ErrorCode::PartialCompletion),
            code_of(ErrorCode::AlreadyExists)
        );
    }

    /// The status is coarse, so an HTTP caller can only decide whether undoing
    /// the committed stage is safe by reading the body. Assert the whole
    /// payload reaches the wire — a caller that cannot see
    /// `destroys_requested_work` will guess, and the natural guess (delete and
    /// re-issue) destroys the committed object.
    #[test]
    fn a_partial_completion_body_carries_the_rollback_advice() {
        let error = Error::new(ErrorCode::PartialCompletion, "object committed")
            .with_context(ovstorage::ErrorContext::Partial {
                completed: ovstorage::PartialStage::ObjectData,
                failed: ovstorage::PartialStage::UserMetadata,
                failed_outcome: ovstorage::StageOutcome::NotApplied,
                rollback: ovstorage::RollbackEffect::DestroysRequestedWork,
            })
            .with_next_action("Re-apply the user metadata.");

        let response = error_response(error);
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 64 * 1024))
                .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let error = &json["error"];

        assert_eq!(error["code"], "PartialCompletion");
        assert_eq!(error["partial"]["completed"], "object_data");
        assert_eq!(error["partial"]["failed"], "user_metadata");
        assert_eq!(error["partial"]["failed_outcome"], "not_applied");
        assert_eq!(error["partial"]["rollback"], "destroys_requested_work");
        assert_eq!(error["next_action"], "Re-apply the user metadata.");
    }

    /// The new fields must not appear on ordinary errors, or every existing
    /// client parsing this envelope sees two nulls it did not have before.
    #[test]
    fn an_ordinary_error_body_gains_no_new_fields() {
        let response = error_response(Error::new(ErrorCode::NotFound, "missing"));
        let body =
            futures::executor::block_on(axum::body::to_bytes(response.into_body(), 64 * 1024))
                .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let error = &json["error"];
        assert_eq!(error["code"], "NotFound");
        assert!(error.get("partial").is_none(), "got {error}");
        assert!(error.get("next_action").is_none(), "got {error}");
    }
}
