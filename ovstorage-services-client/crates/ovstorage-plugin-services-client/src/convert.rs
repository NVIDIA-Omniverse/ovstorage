// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure conversions between Omniverse Storage Service proto types and ovstorage SPI types.
//!
//! Error mapping mirrors the C++ `provider_omnistorage` translation table at
//! `provider_omnistorage/StorageProvider.cpp:290-331`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage_plugin::{
    BackendItemInfo, ChecksumSet, Error, ErrorCode, ObjectInfo, ObjectKind, Result, Url,
};
use ovstorage_services_protos::nvidia::omniverse::storage::fileobject::v1alpha as fo;
use tonic::Status;

pub fn map_status(status: Status) -> Error {
    use tonic::Code;
    let code = match status.code() {
        Code::Ok => return Error::new(ErrorCode::Internal, "OK status surfaced as Error"),
        Code::Cancelled => ErrorCode::Cancelled,
        Code::Unknown => ErrorCode::Internal,
        Code::InvalidArgument => ErrorCode::InvalidArgument,
        Code::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        Code::NotFound => ErrorCode::NotFound,
        Code::AlreadyExists => ErrorCode::AlreadyExists,
        Code::PermissionDenied => ErrorCode::PermissionDenied,
        Code::ResourceExhausted => ErrorCode::ResourceExhausted,
        Code::FailedPrecondition => ErrorCode::PreconditionFailed,
        Code::Aborted => ErrorCode::Conflict,
        Code::OutOfRange => ErrorCode::InvalidArgument,
        Code::Unimplemented => ErrorCode::Unsupported,
        Code::Internal => ErrorCode::Internal,
        Code::Unavailable => ErrorCode::Transient,
        Code::DataLoss => ErrorCode::IntegrityFailure,
        Code::Unauthenticated => ErrorCode::AuthRequired,
    };
    Error::new(
        code,
        format!("omniverse-storage-service: {}", status.message()),
    )
}

/// Flat fields a `Metadata` + etag contribute to `ObjectInfo` / `BackendItemInfo`.
///
/// Helper struct lets the construction sites stay readable: pull the
/// raw values once, then spread them into the parent struct alongside
/// kind / checksums / per-call extras.
pub struct ObjectFields {
    pub etag: Option<String>,
    pub size: Option<u64>,
    pub mtime: Option<SystemTime>,
}

/// Extract the (etag, size, mtime) trio from a proto `Metadata` and an
/// optional precomputed etag (passed in when the caller already knows
/// the server-issued ResourceIdentity, e.g. on the Read RPC where the
/// identity is implicit from the request).
pub fn fields_from_metadata(meta: Option<&fo::Metadata>, etag: Option<String>) -> ObjectFields {
    ObjectFields {
        etag,
        size: meta.and_then(|m| m.data_object_size),
        mtime: meta
            .and_then(|m| m.last_modified_timestamp.as_ref())
            .and_then(timestamp_to_system_time),
    }
}

pub fn timestamp_to_system_time(
    ts: &ovstorage_services_protos::google::protobuf::Timestamp,
) -> Option<SystemTime> {
    let seconds = u64::try_from(ts.seconds).ok()?;
    let nanos = u32::try_from(ts.nanos.max(0)).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
}

pub fn object_info_from(address: Url, info: &fo::ResourceInfo) -> ObjectInfo {
    let etag = info
        .resource_identity
        .as_ref()
        .map(|i| i.encoded_identity.clone())
        .filter(|s| !s.is_empty());
    let fields = fields_from_metadata(info.metadata.as_ref(), etag);
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: fields.etag,
        version: None,
        size: fields.size,
        mtime: fields.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

pub fn item_info_from(info: &fo::ResourceInfo) -> BackendItemInfo {
    let etag = info
        .resource_identity
        .as_ref()
        .map(|i| i.encoded_identity.clone())
        .filter(|s| !s.is_empty());
    let fields = fields_from_metadata(info.metadata.as_ref(), etag);
    BackendItemInfo {
        kind: ObjectKind::File,
        etag: fields.etag,
        version: None,
        size: fields.size,
        mtime: fields.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// Pull the ETag-equivalent identity string from a `fo::ResourceIdentity`.
pub fn resource_identity_from(identity: &Option<String>) -> Option<fo::ResourceIdentity> {
    identity
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|s| fo::ResourceIdentity {
            encoded_identity: s.clone(),
        })
}

pub fn map_decode_err<E: std::fmt::Display>(label: &'static str) -> impl FnOnce(E) -> Error {
    move |err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: failed to decode {label}: {err}"),
        )
    }
}

pub fn require_field<T>(value: Option<T>, field: &'static str) -> Result<T> {
    value.ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: server response missing {field}"),
        )
    })
}

/// No-op generic helper kept as a call site so call paths read uniformly
/// across plugins. The SPI's `if_match` is already an opaque etag string
/// (the OvCS wire's `encoded_identity`), so there's no narrowing left to do.
#[inline]
pub fn require_etag_only_if_match<S: AsRef<str> + ?Sized>(_if_match: Option<&S>) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_status_canonical_codes() {
        assert_eq!(
            map_status(Status::not_found("missing")).code(),
            ErrorCode::NotFound
        );
        assert_eq!(
            map_status(Status::unavailable("retry")).code(),
            ErrorCode::Transient
        );
        assert_eq!(
            map_status(Status::unauthenticated("token")).code(),
            ErrorCode::AuthRequired
        );
        assert_eq!(
            map_status(Status::permission_denied("acl")).code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            map_status(Status::failed_precondition("etag")).code(),
            ErrorCode::PreconditionFailed
        );
        assert_eq!(
            map_status(Status::unimplemented("nope")).code(),
            ErrorCode::Unsupported
        );
        assert_eq!(
            map_status(Status::internal("oops")).code(),
            ErrorCode::Internal
        );
    }

    #[test]
    fn require_etag_only_accepts_none() {
        require_etag_only_if_match::<str>(None).expect("None is no precondition");
    }

    #[test]
    fn require_etag_only_accepts_some_etag() {
        require_etag_only_if_match(Some("v1")).expect("any string is accepted");
    }
}
