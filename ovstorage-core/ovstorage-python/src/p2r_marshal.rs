// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust-to-Python request payload marshaling for the Python `Layer` bridge.
//!
//! This module projects request payloads and decodes finite override results.
//! Keeping conversion separate from `PyLayerAdapter` makes the signature-table
//! contract independently testable and prevents the scheduler from growing
//! ad-hoc, per-slot Python dictionaries.

use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

use crate::ovs;
use crate::ovs::{Body, CancellationToken, Error as OvError, ErrorCode, IfDestExists, Request};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyTuple};

use crate::ConnectionRequest;

/// The Python arguments for one override invocation.
///
/// The native extension bag's registry entries cross faithfully as an
/// `extensions` keyword argument carrying a `dict[str, bytes]` copy
/// (read-only: a base-method forward constructs a fresh `Request`, so
/// extensions do not flow back through the base methods). Host-internal
/// riders (`ovs::wrappers::is_internal_extension`, e.g. the buffered-read
/// hint) are wrapper-chain signaling, not user payload,
/// and are not projected. When nothing remains, no keyword is added, so
/// overrides without an `extensions` parameter keep working until a
/// registry extension actually reaches them. Native wrapper delegation
/// bypasses this type and retains the original request unchanged.
pub(super) struct MarshalledCall {
    pub(super) args: Py<PyTuple>,
    pub(super) kwargs: Py<PyDict>,
    pub(super) cancel: CancellationToken,
}

impl MarshalledCall {
    fn new(
        py: Python<'_>,
        args: impl IntoPy<PyObject>,
        kwargs: Bound<'_, PyDict>,
        cancel: CancellationToken,
        extensions: ovs::Extensions,
    ) -> Result<Self, OvError> {
        if !extensions.is_empty() {
            let bag = PyDict::new_bound(py);
            for (key, value) in extensions {
                if ovs::wrappers::is_internal_extension(&key) {
                    continue;
                }
                bag.set_item(key, PyBytes::new_bound(py, &value))
                    .map_err(py_failure)?;
            }
            if !bag.is_empty() {
                kwargs.set_item("extensions", bag).map_err(py_failure)?;
            }
        }
        let args: Py<PyTuple> = args.into_py(py).extract(py).map_err(py_failure)?;
        Ok(Self {
            args,
            kwargs: kwargs.unbind(),
            cancel,
        })
    }
}

fn py_failure(error: PyErr) -> OvError {
    OvError::new(
        ErrorCode::Internal,
        format!("could not marshal request for Python override: {error}"),
    )
}

fn binding_exception_code(value: &Bound<'_, PyAny>) -> Option<ErrorCode> {
    macro_rules! code_for {
        ($($exception:ty => $code:ident),+ $(,)?) => {
            $(
                if value.is_instance_of::<$exception>() {
                    return Some(ErrorCode::$code);
                }
            )+
        };
    }

    code_for! {
        crate::NotFoundError => NotFound,
        crate::AlreadyExistsError => AlreadyExists,
        crate::PermissionDeniedError => PermissionDenied,
        crate::PreconditionFailedError => PreconditionFailed,
        crate::ConflictError => Conflict,
        crate::DirectoryNotEmptyError => DirectoryNotEmpty,
        crate::UnsupportedError => Unsupported,
        crate::InvalidArgumentError => InvalidArgument,
        crate::IncompatibleTypeError => IncompatibleType,
        crate::LockedError => Locked,
        crate::CancelledError => Cancelled,
        crate::DeadlineExceededError => DeadlineExceeded,
        crate::TransientError => Transient,
        crate::ResourceExhaustedError => ResourceExhausted,
        crate::IntegrityFailureError => IntegrityFailure,
        crate::InternalError => Internal,
        crate::BrokerUnavailableError => BrokerUnavailable,
        crate::BrokerRequiredError => BrokerRequired,
        crate::RedirectExpiredError => RedirectExpired,
        crate::PolicyEpochStaleError => PolicyEpochStale,
        crate::AuthorizationLeaseExpiredError => AuthorizationLeaseExpired,
        crate::CacheCorruptError => CacheCorrupt,
        crate::StagingExpiredError => StagingExpired,
        crate::CommitAmbiguousError => CommitAmbiguous,
        crate::PartialCompletionError => PartialCompletion,
        crate::CacheLockContentionError => CacheLockContention,
        crate::StateRootUnavailableError => StateRootUnavailable,
        crate::NetworkFilesystemRefusedError => NetworkFilesystemRefused,
        crate::ObjectModifiedError => ObjectModified,
        crate::NoRouteError => NoRoute,
        crate::RouteConflictError => RouteConflict,
        crate::NotConfiguredError => NotConfigured,
        crate::AliasChainTooLongError => AliasChainTooLong,
        crate::CredentialExpiredError => CredentialExpired,
        crate::CredentialUnavailableError => CredentialUnavailable,
        crate::AuthRequiredError => AuthRequired,
        crate::AuthCancelledError => AuthCancelled,
        crate::AuthExpiredError => AuthExpired,
        crate::ContentMismatchError => ContentMismatch,
        crate::ContentChecksumMismatchError => ContentChecksumMismatch,
        crate::PluginRejectedError => PluginRejected,
    }
    None
}

/// Turn an exception raised by a Python override back into the error taxonomy
/// exposed by the binding. `py_error` attaches the stable Rust code to its
/// instances, while exceptions raised directly by user code are recognized by
/// their binding class. Re-exporting a class preserves that process-global
/// type object, so this does not depend on the module path it is raised from.
pub(super) fn override_failure(py: Python<'_>, error: PyErr) -> OvError {
    let value = error.value_bound(py);
    let is_binding_error = value.is_instance_of::<crate::Error>();
    let code = is_binding_error
        .then(|| {
            value
                .getattr("code")
                .ok()
                .and_then(|value| value.extract::<String>().ok())
                .and_then(|name| {
                    ErrorCode::KNOWN
                        .iter()
                        .copied()
                        .find(|code| code.as_str() == name)
                })
                .or_else(|| binding_exception_code(value))
        })
        .flatten()
        .unwrap_or(ErrorCode::Internal);
    let next_action = is_binding_error
        .then(|| {
            value
                .getattr("next_action")
                .ok()
                .and_then(|value| value.extract::<Option<String>>().ok())
                .flatten()
        })
        .flatten();
    let mapped = OvError::new(code, format!("Python override raised: {error}"));
    match next_action {
        Some(next_action) => mapped.with_next_action(next_action),
        None => mapped,
    }
}

fn incompatible(slot: &str, detail: impl std::fmt::Display) -> OvError {
    OvError::new(
        ErrorCode::IncompatibleType,
        format!("Python {slot} result has an incompatible shape: {detail}"),
    )
}

fn attr<'py>(
    value: &Bound<'py, PyAny>,
    name: &str,
    slot: &str,
) -> Result<Bound<'py, PyAny>, OvError> {
    value
        .getattr(name)
        .map_err(|_| incompatible(slot, format!("missing `{name}` attribute")))
}

fn extract_attr<'py, T: FromPyObject<'py>>(
    value: &Bound<'py, PyAny>,
    name: &str,
    slot: &str,
) -> Result<T, OvError> {
    attr(value, name, slot)?
        .extract()
        .map_err(|_| incompatible(slot, format!("`{name}` has the wrong type")))
}

fn object_kind(value: &str, slot: &str) -> Result<ovs::ObjectKind, OvError> {
    match value {
        "file" => Ok(ovs::ObjectKind::File),
        "directory" => Ok(ovs::ObjectKind::Directory),
        "directory_marker" => Ok(ovs::ObjectKind::DirectoryMarker),
        "directory_inferred" => Ok(ovs::ObjectKind::DirectoryInferred),
        _ => Err(incompatible(slot, "`kind` is not a known object kind")),
    }
}

fn object_info(value: &Bound<'_, PyAny>, slot: &str) -> Result<ovs::ObjectInfo, OvError> {
    let address: String = extract_attr(value, "address", slot)?;
    // A RETURNED address, so it is decoded with the returned-address battery
    // and not with `address::parse`. `parse` canonicalizes, which is right for
    // a request — normalizing a question is the point — and wrong for an
    // answer: a `list` entry naming the real key `s3://b/a//b` would be
    // rewritten to `s3://b/a/b`, pass the page's scope check, and be handed to
    // a caller as the address of a different object. This is the same decoder
    // the C plugin ABI uses for the same reason.
    let address = ovs::marshal::address::returned_object_address(&address).map_err(|error| {
        // The inner message already names what moved and renders both
        // spellings through `RedactedUrl`; it is not re-wrapped around the raw
        // string, which for the authority-less class carries the payload.
        incompatible(slot, error.message())
    })?;
    let kind: String = extract_attr(value, "kind", slot)?;
    let mtime_unix_nanos: Option<u64> = extract_attr(value, "mtime_unix_nanos", slot)?;
    Ok(ovs::ObjectInfo {
        address,
        kind: object_kind(&kind, slot)?,
        size: extract_attr(value, "size", slot)?,
        mtime: mtime_unix_nanos.map(|nanos| UNIX_EPOCH + Duration::from_nanos(nanos)),
        etag: extract_attr(value, "etag", slot)?,
        version: extract_attr(value, "version", slot)?,
        checksums: ovs::ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: Some(extract_attr::<HashMap<String, String>>(
            value,
            "system_metadata",
            slot,
        )?),
        user_metadata: Some(extract_attr::<HashMap<String, String>>(
            value,
            "user_metadata",
            slot,
        )?),
        modified_by: None,
    })
}

/// Which spelling rule a slot's response address is held to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressRule {
    /// The slot can answer about either a file or a directory, so the returned
    /// `ObjectKind` decides — see [`answers_for`].
    ByKind,
    /// The slot is directory-facing by contract, so node identity is the whole
    /// test whatever `kind` says. `create_directory` answers about a directory
    /// because that is what it just made, and `CONFORMANCE.md` is explicit that
    /// the host does NOT rewrite the slash for a directory-facing verb — so
    /// `x://d/` answering a request for `x://d` is the expected shape. Holding
    /// it to the kind would reject that whenever a layer reports the default
    /// `"file"`, which duck-typed `Info` shims commonly do.
    Node,
}

fn checked_info(
    value: &Bound<'_, PyAny>,
    slot: &str,
    expected_address: Option<&ovs::Url>,
    rule: AddressRule,
) -> Result<ovs::ObjectInfo, OvError> {
    let info = object_info(value, slot)?;
    if let Some(expected) = expected_address
        && !match rule {
            AddressRule::Node => ovs::address::same_node(&info.address, expected),
            AddressRule::ByKind => answers_for(&info, expected),
        }
    {
        return Err(incompatible(
            slot,
            "Info.address differs from the request address",
        ));
    }
    Ok(info)
}

/// Whether `info` is an answer about `expected`.
///
/// **Node-aware for a directory answer; node-aware plus the trailing separator
/// for an object answer.** Not exact URL equality in either case — see below.
///
/// The relaxation exists for one shape: a directory answered as
/// `file:///data/root/` for a request of `file:///data/root`. Those are two
/// spellings of one node, the caller asked about that node, and raw equality
/// rejected the answer as `IncompatibleType` — through the shared validator
/// behind `stat`, `read`, `write`, `copy`, `get_latest_version`,
/// `update_metadata` and `create_directory`, so it reached all of them.
///
/// Applied to an object answer it is too weak. On a flat store `docs` and
/// `docs/` may be two distinct objects with different bytes, size and etag, so
/// a layer asked to `read` or `stat` `s3://b/docs` could return the payload of
/// `s3://b/docs/` and the validator would pass it through. A response
/// validator cannot afford that: the cost of accepting the wrong answer is the
/// wrong bytes reaching a caller that named one object.
///
/// So the returned [`ovs::ObjectKind`] decides. Every directory-like kind gets
/// the node-aware comparison; `File` additionally requires the two to agree on
/// the trailing separator, which is the only spelling difference `same_node`
/// erases and the only one that can name a second object on a flat store.
///
/// It is deliberately NOT `==`. Raw equality would make userinfo and the exact
/// percent-encoding identity-bearing again, and neither is part of a node —
/// which is the whole subject of this change. `same_node` plus the separator
/// is the narrowest predicate that separates `docs` from `docs/` without
/// reintroducing the spelling sensitivity the model removes.
///
/// Reading the kind off the ANSWER rather than the request is deliberate: the
/// request is a bare address and does not say which was meant, and a layer that
/// mislabels an object as a directory to widen this check has only relaxed a
/// check on itself.
fn answers_for(info: &ovs::ObjectInfo, expected: &ovs::Url) -> bool {
    if !ovs::address::same_node(&info.address, expected) {
        return false;
    }
    match info.kind {
        ovs::ObjectKind::Directory
        | ovs::ObjectKind::DirectoryMarker
        | ovs::ObjectKind::DirectoryInferred => true,
        ovs::ObjectKind::File => {
            ovs::address::is_directory(&info.address) == ovs::address::is_directory(expected)
        }
    }
}

fn bytes(value: &Bound<'_, PyAny>, slot: &str) -> Result<Vec<u8>, OvError> {
    crate::bytes_from_python_buffer(value)
        .map_err(|_| incompatible(slot, "expected a valid bytes-like value"))?
        .ok_or_else(|| incompatible(slot, "expected a bytes-like value"))
}

fn conservative_info(address: ovs::Url, size: Option<u64>) -> ovs::ObjectInfo {
    ovs::ObjectInfo {
        address,
        kind: ovs::ObjectKind::File,
        size,
        etag: None,
        version: None,
        checksums: ovs::ChecksumSet::default(),
        effective_permissions: None,
        mtime: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// Decode the result of `stat` or `get_latest_version`.
pub(super) fn result_stat(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::ObjectInfo, OvError> {
    checked_info(value, "stat", Some(expected_address), AddressRule::ByKind)
}

pub(super) fn result_get_latest_version(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::ObjectInfo, OvError> {
    checked_info(
        value,
        "get_latest_version",
        Some(expected_address),
        AddressRule::ByKind,
    )
}

/// Decode buffered Python reads. Async-iterator read bridging is owned by the
/// adapter because it must retain the captured Python loop and cancellation
/// token; passing one here is therefore a typed shape error rather than a
/// misleading local/redirect result.
pub(super) fn result_read(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::ReadResult, OvError> {
    if value.hasattr("__aiter__").unwrap_or(false) {
        return Err(incompatible(
            "read",
            "async iterator bridging requires the adapter dispatch context",
        ));
    }
    if let Ok(tuple) = value.downcast::<PyTuple>() {
        if tuple.len() != 2 {
            return Err(incompatible(
                "read",
                "tuple results must be `(bytes, Info)`",
            ));
        }
        let payload = bytes(
            &tuple
                .get_item(0)
                .map_err(|_| incompatible("read", "missing bytes"))?,
            "read",
        )?;
        let info = checked_info(
            &tuple
                .get_item(1)
                .map_err(|_| incompatible("read", "missing Info"))?,
            "read",
            Some(expected_address),
            AddressRule::ByKind,
        )?;
        return Ok(ovs::ReadResult::Bytes {
            bytes: payload,
            info,
        });
    }
    let payload = bytes(value, "read")?;
    Ok(ovs::ReadResult::Bytes {
        info: conservative_info(expected_address.clone(), Some(payload.len() as u64)),
        bytes: payload,
    })
}

fn write_result(
    value: &Bound<'_, PyAny>,
    slot: &str,
    expected_address: &ovs::Url,
) -> Result<ovs::WriteResult, OvError> {
    Ok(ovs::WriteResult {
        info: checked_info(value, slot, Some(expected_address), AddressRule::ByKind)?,
    })
}

pub(super) fn result_write(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::WriteResult, OvError> {
    write_result(value, "write", expected_address)
}

pub(super) fn result_write_stream(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::WriteResult, OvError> {
    write_result(value, "write_stream", expected_address)
}

pub(super) fn result_copy(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::WriteStep, OvError> {
    Ok(ovs::WriteStep::Done(write_result(
        value,
        "copy",
        expected_address,
    )?))
}

fn backend_item(
    value: &Bound<'_, PyAny>,
    slot: &str,
    expected_address: &ovs::Url,
    rule: AddressRule,
) -> Result<ovs::BackendItemInfo, OvError> {
    Ok(checked_info(value, slot, Some(expected_address), rule)?.into())
}

pub(super) fn result_update_metadata(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::BackendItemInfo, OvError> {
    backend_item(
        value,
        "update_metadata",
        expected_address,
        AddressRule::ByKind,
    )
}

pub(super) fn result_create_directory(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::BackendItemInfo, OvError> {
    backend_item(
        value,
        "create_directory",
        expected_address,
        AddressRule::Node,
    )
}

pub(super) fn unit(value: &Bound<'_, PyAny>, slot: &str) -> Result<(), OvError> {
    if value.is_none() {
        Ok(())
    } else {
        Err(incompatible(slot, "expected None"))
    }
}

pub(super) fn result_delete(value: &Bound<'_, PyAny>) -> Result<(), OvError> {
    unit(value, "delete")
}

pub(super) fn result_rename(value: &Bound<'_, PyAny>) -> Result<(), OvError> {
    unit(value, "rename")
}

pub(super) fn result_delete_directory(value: &Bound<'_, PyAny>) -> Result<(), OvError> {
    unit(value, "delete_directory")
}

pub(super) fn result_check_access(
    value: &Bound<'_, PyAny>,
) -> Result<ovs::AccessDecision, OvError> {
    Ok(ovs::AccessDecision {
        allowed: extract_attr(value, "allowed", "check_access")?,
        denied_ops: ovs::AccessOps {
            read: extract_attr(value, "denied_read", "check_access")?,
            write: extract_attr(value, "denied_write", "check_access")?,
            delete: extract_attr(value, "denied_delete", "check_access")?,
            update_metadata: extract_attr(value, "denied_update_metadata", "check_access")?,
        },
        reason: extract_attr(value, "reason", "check_access")?,
    })
}

fn page(
    value: &Bound<'_, PyAny>,
    slot: &str,
    request_scope: &ovs::Url,
    allow_descendants: bool,
) -> Result<(Vec<ovs::ObjectInfo>, Option<String>), OvError> {
    let items: Vec<Py<PyAny>> = extract_attr(value, "items", slot)?;
    let items = items
        .iter()
        .map(|item| {
            let info = checked_info(item.bind(value.py()), slot, None, AddressRule::ByKind)?;
            let in_scope = if allow_descendants {
                ovs::address::is_ancestor_or_self(request_scope, &info.address)
            } else {
                // `list_versions` is object-facing: every item is a version of
                // the ONE object requested, so it gets the same rule the other
                // object-bearing slots get. `same_node` alone would let a
                // version of the slash sibling through, which on a flat store
                // is a different object with different bytes.
                answers_for(&info, request_scope)
            };
            if !in_scope {
                return Err(incompatible(
                    slot,
                    if allow_descendants {
                        "page item Info.address is outside the request prefix"
                    } else {
                        "page item Info.address differs from the request address"
                    },
                ));
            }
            Ok(info)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((items, extract_attr(value, "next_page_token", slot)?))
}

pub(super) fn result_list(
    value: &Bound<'_, PyAny>,
    request_prefix: &ovs::Url,
) -> Result<ovs::ListPage, OvError> {
    let (items, next_page_token) = page(value, "list", request_prefix, true)?;
    Ok(ovs::ListPage {
        items,
        next_page_token,
    })
}

pub(super) fn result_list_versions(
    value: &Bound<'_, PyAny>,
    request_address: &ovs::Url,
) -> Result<ovs::VersionPage, OvError> {
    let (items, next_page_token) = page(value, "list_versions", request_address, false)?;
    Ok(ovs::VersionPage {
        items,
        next_page_token,
    })
}

pub(super) fn result_materialize(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> Result<ovs::LocalDelegate, OvError> {
    let delegate: PyRef<'_, crate::LocalDelegate> = value
        .extract()
        .map_err(|_| incompatible("materialize", "expected an open LocalDelegate"))?;
    if delegate.closed {
        return Err(incompatible("materialize", "LocalDelegate is closed"));
    }
    // Same split as `checked_info`: `materialize` is an object-bearing slot —
    // it hands back an on-disk path whose BYTES the caller then reads — so a
    // `File` answer must name the requested node in the requested
    // trailing-separator spelling.
    if !answers_for(&delegate.inner.info, expected_address) {
        return Err(incompatible(
            "materialize",
            "LocalDelegate.info.address differs from the request address",
        ));
    }
    Ok(delegate.inner.clone())
}

pub(super) fn result_probe(value: &Bound<'_, PyAny>) -> Result<ovs::Connection, OvError> {
    value
        .extract::<PyRef<'_, crate::Connection>>()
        .map(|connection| connection.inner.clone())
        .map_err(|_| incompatible("probe", "expected a Connection"))
}

fn kwargs(py: Python<'_>) -> Bound<'_, PyDict> {
    PyDict::new_bound(py)
}

fn destination_mode(value: &IfDestExists) -> (&'static str, Option<&str>) {
    match value {
        IfDestExists::Overwrite => ("overwrite", None),
        IfDestExists::Fail => ("fail", None),
        IfDestExists::MatchEtag(etag) => ("match_etag", Some(etag)),
    }
}

fn destination_kwargs(kwargs: &Bound<'_, PyDict>, value: &IfDestExists) -> Result<(), OvError> {
    let (mode, etag) = destination_mode(value);
    kwargs
        .set_item("if_dest_exists", mode)
        .map_err(py_failure)?;
    kwargs.set_item("if_dest_etag", etag).map_err(py_failure)
}

fn read_kwargs(kwargs: &Bound<'_, PyDict>, options: &ovs::ReadOptions) -> Result<(), OvError> {
    kwargs
        .set_item("if_match", &options.if_match)
        .map_err(py_failure)?;
    kwargs
        .set_item(
            "range_start",
            options.range.as_ref().map(|range| range.start),
        )
        .map_err(py_failure)?;
    kwargs
        .set_item(
            "range_end_inclusive",
            options.range.as_ref().and_then(|range| range.end_inclusive),
        )
        .map_err(py_failure)?;
    kwargs
        .set_item("max_bytes", options.max_bytes)
        .map_err(py_failure)
}

fn stream_body_input(
    py: Python<'_>,
    body: Body,
    cancel: CancellationToken,
) -> Result<PyObject, OvError> {
    crate::p2r_body::body_to_python(py, body, cancel)
}

/// Marshal `stat(address, *, full_metadata=False)`.
pub(super) fn stat(
    py: Python<'_>,
    request: Request<ovs::StatRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let kw = kwargs(py);
    kw.set_item("full_metadata", input.options.full_metadata)
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.address.to_string(),), kw, cancel, extensions)
}

/// Marshal all read-shaped slots: `read`, `materialize`, and
/// `get_latest_version` share the same flattened request shape.
pub(super) fn read(
    py: Python<'_>,
    request: Request<ovs::ReadRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let kw = kwargs(py);
    read_kwargs(&kw, &input.options)?;
    MarshalledCall::new(py, (input.address.to_string(),), kw, cancel, extensions)
}

/// Marshal `materialize`; its request payload is identical to `read`.
pub(super) fn materialize(
    py: Python<'_>,
    request: Request<ovs::ReadRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    read(py, request, cancel)
}

/// Marshal `get_latest_version`; its request payload is identical to `read`.
pub(super) fn get_latest_version(
    py: Python<'_>,
    request: Request<ovs::ReadRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    read(py, request, cancel)
}

pub(super) fn write(
    py: Python<'_>,
    request: Request<ovs::WriteRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let Body::Bytes(bytes) = input.body else {
        return Err(OvError::new(
            ErrorCode::Unsupported,
            "Python write overrides accept only buffered bytes; use write_stream for streamed bodies",
        ));
    };
    let kw = kwargs(py);
    destination_kwargs(&kw, &input.options.if_dest)?;
    kw.set_item("size_hint", input.options.size_hint)
        .map_err(py_failure)?;
    kw.set_item("user_metadata", input.options.user_metadata)
        .map_err(py_failure)?;
    kw.set_item("message", input.options.message)
        .map_err(py_failure)?;
    MarshalledCall::new(
        py,
        (input.address.to_string(), PyBytes::new_bound(py, &bytes)),
        kw,
        cancel,
        extensions,
    )
}

pub(super) fn write_stream(
    py: Python<'_>,
    request: Request<ovs::WriteRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let body = stream_body_input(py, input.body, cancel.clone())?;
    let kw = kwargs(py);
    destination_kwargs(&kw, &input.options.if_dest)?;
    kw.set_item("size_hint", input.options.size_hint)
        .map_err(py_failure)?;
    kw.set_item("user_metadata", input.options.user_metadata)
        .map_err(py_failure)?;
    kw.set_item("message", input.options.message)
        .map_err(py_failure)?;
    MarshalledCall::new(
        py,
        (input.address.to_string(), body),
        kw,
        cancel,
        extensions,
    )
}

pub(super) fn delete(
    py: Python<'_>,
    request: Request<ovs::DeleteRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let kw = kwargs(py);
    kw.set_item("if_match", input.options.if_match)
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.address.to_string(),), kw, cancel, extensions)
}

struct TransferInput {
    source: ovs::Url,
    destination: ovs::Url,
    if_source: Option<String>,
    if_dest: IfDestExists,
    message: Option<String>,
}

fn transfer(
    py: Python<'_>,
    input: TransferInput,
    cancel: CancellationToken,
    extensions: ovs::Extensions,
) -> Result<MarshalledCall, OvError> {
    let kw = kwargs(py);
    kw.set_item("if_source", input.if_source)
        .map_err(py_failure)?;
    destination_kwargs(&kw, &input.if_dest)?;
    kw.set_item("message", input.message).map_err(py_failure)?;
    MarshalledCall::new(
        py,
        (input.source.to_string(), input.destination.to_string()),
        kw,
        cancel,
        extensions,
    )
}

pub(super) fn copy(
    py: Python<'_>,
    request: Request<ovs::CopyRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    transfer(
        py,
        TransferInput {
            source: input.source,
            destination: input.destination,
            if_source: input.options.if_source,
            if_dest: input.options.if_dest,
            message: input.options.message,
        },
        cancel,
        extensions,
    )
}

pub(super) fn rename(
    py: Python<'_>,
    request: Request<ovs::RenameRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    transfer(
        py,
        TransferInput {
            source: input.source,
            destination: input.destination,
            if_source: input.options.if_source,
            if_dest: input.options.if_dest,
            message: input.options.message,
        },
        cancel,
        extensions,
    )
}

pub(super) fn update_metadata(
    py: Python<'_>,
    request: Request<ovs::UpdateMetadataRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let options = input.options;
    let kw = kwargs(py);
    kw.set_item("if_match", options.if_match)
        .map_err(py_failure)?;
    kw.set_item("allow_rewrite_emulation", options.allow_rewrite_emulation)
        .map_err(py_failure)?;
    kw.set_item("user_metadata_set", options.user_metadata_set)
        .map_err(py_failure)?;
    kw.set_item("user_metadata_remove", options.user_metadata_remove)
        .map_err(py_failure)?;
    kw.set_item("message", options.message)
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.address.to_string(),), kw, cancel, extensions)
}

pub(super) fn check_access(
    py: Python<'_>,
    request: Request<ovs::CheckAccessRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let kw = kwargs(py);
    kw.set_item("read", input.operations.read)
        .map_err(py_failure)?;
    kw.set_item("write", input.operations.write)
        .map_err(py_failure)?;
    kw.set_item("delete", input.operations.delete)
        .map_err(py_failure)?;
    kw.set_item("update_metadata", input.operations.update_metadata)
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.address.to_string(),), kw, cancel, extensions)
}

pub(super) fn list(
    py: Python<'_>,
    request: Request<ovs::ListRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let options = input.options;
    let kw = kwargs(py);
    kw.set_item("recursive", options.recursive)
        .map_err(py_failure)?;
    kw.set_item("max_results", options.max_results)
        .map_err(py_failure)?;
    kw.set_item("page_token", options.page_token)
        .map_err(py_failure)?;
    kw.set_item("full_metadata", options.full_metadata)
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.prefix.to_string(),), kw, cancel, extensions)
}

pub(super) fn list_versions(
    py: Python<'_>,
    request: Request<ovs::ListVersionsRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let kw = kwargs(py);
    kw.set_item("max_results", input.options.max_results)
        .map_err(py_failure)?;
    kw.set_item("page_token", input.options.page_token)
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.address.to_string(),), kw, cancel, extensions)
}

pub(super) fn create_directory(
    py: Python<'_>,
    request: Request<ovs::CreateDirectoryRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    MarshalledCall::new(
        py,
        (input.address.to_string(),),
        kwargs(py),
        cancel,
        extensions,
    )
}

pub(super) fn delete_directory(
    py: Python<'_>,
    request: Request<ovs::DeleteDirectoryRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    MarshalledCall::new(
        py,
        (input.address.to_string(),),
        kwargs(py),
        cancel,
        extensions,
    )
}

/// Marshal `probe(target, request)`.  This clones the request wrapper rather
/// than exposing its Rust fields; in particular, no secret payload is read or
/// converted to Python bytes.
pub(super) fn probe(
    py: Python<'_>,
    request: Request<ovs::LayerConnectionRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let connection = Py::new(
        py,
        ConnectionRequest {
            inner: std::sync::Mutex::new(Some(input.connection)),
        },
    )
    .map_err(py_failure)?;
    MarshalledCall::new(
        py,
        (input.target, connection),
        kwargs(py),
        cancel,
        extensions,
    )
}

pub(super) fn watch_directory(
    py: Python<'_>,
    request: Request<ovs::WatchDirectoryRequest>,
    cancel: CancellationToken,
) -> Result<MarshalledCall, OvError> {
    let Request { extensions, input } = request;
    let options = input.options;
    let kw = kwargs(py);
    kw.set_item("recursive", options.recursive)
        .map_err(py_failure)?;
    kw.set_item("include_metadata_changes", options.include_metadata_changes)
        .map_err(py_failure)?;
    kw.set_item(
        "since",
        options
            .since
            .map(|cursor| PyBytes::new_bound(py, &cursor.0).unbind()),
    )
    .map_err(py_failure)?;
    kw.set_item("poll_interval_seconds", options.poll_interval.as_secs_f64())
        .map_err(py_failure)?;
    MarshalledCall::new(py, (input.prefix.to_string(),), kw, cancel, extensions)
}

#[cfg(all(test, feature = "no-extension-module-link"))]
mod tests {
    use super::*;
    use crate::ovs::address;

    fn token() -> CancellationToken {
        CancellationToken::new()
    }

    #[test]
    fn read_uses_the_signature_table_keywords_and_retains_the_shared_token() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let cancel = token();
            let call = read(
                py,
                Request::new(ovs::ReadRequest {
                    address: address::parse("file:///tmp/object").unwrap(),
                    options: ovs::ReadOptions {
                        if_match: Some("etag-1".into()),
                        range: Some(ovs::ByteRange {
                            start: 4,
                            end_inclusive: Some(9),
                        }),
                        max_bytes: Some(64),
                    },
                }),
                cancel.clone(),
            )
            .unwrap();

            assert_eq!(
                call.args
                    .bind(py)
                    .get_item(0)
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "file:///tmp/object"
            );
            assert_eq!(
                call.kwargs
                    .bind(py)
                    .get_item("if_match")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "etag-1"
            );
            assert_eq!(
                call.kwargs
                    .bind(py)
                    .get_item("range_start")
                    .unwrap()
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                4
            );
            assert_eq!(
                call.kwargs
                    .bind(py)
                    .get_item("range_end_inclusive")
                    .unwrap()
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                9
            );
            assert_eq!(
                call.kwargs
                    .bind(py)
                    .get_item("max_bytes")
                    .unwrap()
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                64
            );
            assert!(
                call.kwargs
                    .bind(py)
                    .get_item("extensions")
                    .unwrap()
                    .is_none(),
                "an empty extension bag adds no `extensions` keyword"
            );
            call.cancel.cancel();
            assert!(cancel.is_cancelled());
        });
    }

    #[test]
    fn non_empty_extensions_marshal_as_a_bytes_valued_dict_keyword() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut extensions = ovs::Extensions::new();
            extensions.insert("org.example/principal@1", b"alice".to_vec());
            extensions.insert("org.example/binary@1", vec![0x00, 0xFF, 0x80]);
            // Host-internal wrapper-chain riders are filtered out of the
            // Python projection (they still cross vtable hops natively).
            extensions.insert("ovstorage.read_to_bytes", vec![1]);
            let call = stat(
                py,
                Request {
                    extensions,
                    input: ovs::StatRequest {
                        address: address::parse("file:///tmp/object").unwrap(),
                        options: ovs::StatOptions {
                            full_metadata: false,
                        },
                    },
                },
                token(),
            )
            .unwrap();

            let bag = call
                .kwargs
                .bind(py)
                .get_item("extensions")
                .unwrap()
                .expect("non-empty extensions cross as an `extensions` keyword");
            let bag = bag.downcast::<PyDict>().unwrap();
            assert_eq!(bag.len(), 2, "internal riders must not reach Python");
            assert_eq!(
                bag.get_item("org.example/principal@1")
                    .unwrap()
                    .unwrap()
                    .extract::<Vec<u8>>()
                    .unwrap(),
                b"alice".to_vec()
            );
            assert_eq!(
                bag.get_item("org.example/binary@1")
                    .unwrap()
                    .unwrap()
                    .extract::<Vec<u8>>()
                    .unwrap(),
                vec![0x00, 0xFF, 0x80],
                "binary (non-UTF-8) extension values cross byte-faithfully"
            );
        });
    }

    #[test]
    fn write_rejects_non_buffered_bodies_with_a_typed_error() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let result = write(
                py,
                Request::new(ovs::WriteRequest {
                    address: address::parse("file:///tmp/object").unwrap(),
                    body: Body::LocalFile("/definitely/not/read/by-write".into()),
                    options: ovs::WriteOptions::default(),
                }),
                token(),
            );
            let Err(error) = result else {
                panic!("streaming write body unexpectedly marshaled as bytes-only write");
            };
            assert_eq!(error.code(), ErrorCode::Unsupported);
        });
    }

    #[test]
    fn body_input_teardown_does_not_cancel_the_operation_token() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let operation_cancel = token();
            let body = stream_body_input(
                py,
                Body::Stream(ovs::BodyStream::from_iter(std::iter::empty::<
                    Result<Vec<u8>, OvError>,
                >())),
                operation_cancel.clone(),
            )
            .unwrap();
            drop(body);
            assert!(!operation_cancel.is_cancelled());
        });
    }

    #[test]
    fn probe_projects_a_write_only_connection_request() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut credentials = ovs::SecretBundle::default();
            credentials.fields.insert(
                "token".into(),
                ovs::SecretValue::Bytes(ovs::SecretBytes(b"not-readable".to_vec())),
            );
            let call = probe(
                py,
                Request::new(ovs::LayerConnectionRequest {
                    target: "python-backend".into(),
                    connection: ovs::ConnectionRequest {
                        backend_kind: "test".into(),
                        config: Default::default(),
                        credentials,
                        persist: false,
                        display_name: None,
                    },
                }),
                token(),
            )
            .unwrap();
            let connection = call.args.bind(py).get_item(1).unwrap();
            assert!(connection.getattr("credentials").is_err());
            assert!(connection.getattr("inner").is_err());
            assert!(
                !connection
                    .repr()
                    .unwrap()
                    .to_string()
                    .contains("not-readable")
            );
        });
    }

    fn result_value<'py>(py: Python<'py>, expression: &str) -> Bound<'py, PyAny> {
        py.eval_bound(expression, None, None).unwrap()
    }

    #[test]
    fn result_converters_decode_real_layer_types_and_reject_bad_shapes() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            py.run_bound(
                "from types import SimpleNamespace as NS\n\
                 info = NS(address='file:///tmp/object', kind='file', size=3, \
                 mtime_unix_nanos=7, etag='etag', version='v1', \
                 system_metadata={'system': 'value'}, user_metadata={'user': 'value'})\n\
                 access = NS(allowed=False, denied_read=True, denied_write=False, \
                 denied_delete=True, denied_update_metadata=False, reason='policy')\n\
                 page = NS(items=[info], next_page_token='next')",
                None,
                None,
            )
            .unwrap();
            let expected = address::parse("file:///tmp/object").unwrap();

            let info = result_value(py, "info");
            let stat = result_stat(&info, &expected).unwrap();
            assert_eq!(stat.address, expected);
            assert_eq!(stat.size, Some(3));

            let read = result_read(&result_value(py, "(b'abc', info)"), &expected).unwrap();
            assert!(matches!(read, ovs::ReadResult::Bytes { bytes, .. } if bytes == b"abc"));
            assert!(matches!(
                result_copy(&info, &expected).unwrap(),
                ovs::WriteStep::Done(ovs::WriteResult { .. })
            ));
            assert_eq!(
                result_update_metadata(&info, &expected)
                    .unwrap()
                    .etag
                    .as_deref(),
                Some("etag")
            );

            let access = result_check_access(&result_value(py, "access")).unwrap();
            assert!(!access.allowed);
            assert!(access.denied_ops.read && access.denied_ops.delete);
            let list = result_list(&result_value(py, "page"), &expected).unwrap();
            assert_eq!(list.items.len(), 1);
            assert_eq!(list.next_page_token.as_deref(), Some("next"));
            let outside = address::parse("file:///elsewhere").unwrap();
            assert_eq!(
                result_list(&result_value(py, "page"), &outside)
                    .unwrap_err()
                    .code(),
                ErrorCode::IncompatibleType
            );
            assert_eq!(
                result_list_versions(&result_value(py, "page"), &outside)
                    .unwrap_err()
                    .code(),
                ErrorCode::IncompatibleType
            );
            let none_object = py.None();
            let none = none_object.bind(py);
            assert!(result_delete(&none).is_ok());
            assert_eq!(
                result_read(&result_value(py, "object()"), &expected)
                    .unwrap_err()
                    .code(),
                ErrorCode::IncompatibleType
            );
            assert_eq!(
                result_stat(
                    &result_value(
                        py,
                        "NS(**{**info.__dict__, 'address': 'file:///tmp/other'})"
                    ),
                    &expected
                )
                .unwrap_err()
                .code(),
                ErrorCode::IncompatibleType
            );
        });
    }

    #[test]
    fn override_errors_use_binding_classes_and_reject_duck_typed_codes() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let direct = crate::NotFoundError::new_err("missing");
            assert_eq!(override_failure(py, direct).code(), ErrorCode::NotFound);

            let duck_typed = PyErr::from_value_bound(result_value(
                py,
                "type('E', (Exception,), {'code': 'NotFound'})('missing')",
            ));
            assert_eq!(override_failure(py, duck_typed).code(), ErrorCode::Internal);
        });
    }
}
