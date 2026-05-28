// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Convert a crate-root `Error` into an owned [`ffi::Error`]. The
/// returned struct owns its message buffer; release via
/// `ovstorage_plugin_error_free` or [`from_ffi`].
pub fn to_ffi(error: &Error) -> ffi::Error {
    let mut bytes = error.message().as_bytes().to_vec();
    bytes.shrink_to_fit();
    let len = bytes.len();
    let ptr = if len == 0 {
        // 1-byte sentinel so consumers never see a null pointer; the
        // matching Drop reconstructs a Vec with capacity 1.
        let mut empty = Vec::<u8>::with_capacity(1);
        empty.push(0);
        empty.shrink_to_fit();
        let raw = empty.as_mut_ptr();
        std::mem::forget(empty);
        raw
    } else {
        let raw = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        raw
    };
    let context = match error.context() {
        None => std::ptr::null_mut(),
        Some(ctx) => Box::into_raw(Box::new(context_to_ffi(ctx))),
    };
    ffi::register_error_next_action(ptr as *mut std::os::raw::c_char, error.next_action());
    ffi::Error {
        code: code_to_ffi(error.code()),
        message_ptr: ptr as *mut std::os::raw::c_char,
        message_len: if len == 0 { 0 } else { len },
        context,
    }
}

/// Consume an [`ffi::Error`] into a crate-root `Error`, releasing
/// the FFI value's message buffer. Treat `error` as moved.
///
/// # Safety
///
/// `error` must be a valid [`ffi::Error`] produced by [`to_ffi`] or
/// an FFI counterpart with the same allocator convention.
pub unsafe fn from_ffi(error: ffi::Error) -> Error {
    unsafe {
        let code = code_from_ffi(error.code);
        let message = if error.message_ptr.is_null() || error.message_len == 0 {
            String::new()
        } else {
            let bytes =
                std::slice::from_raw_parts(error.message_ptr as *const u8, error.message_len);
            String::from_utf8_lossy(bytes).into_owned()
        };
        // Lift context out so the parent's Drop does not double-free.
        // Misaligned pointers signal an older-ABI producer that left
        // the field uninitialised; treat as absent context rather
        // than crash on dereference. A failed context round-trip
        // (e.g. malformed ConnectionId) is also non-fatal — surface
        // the original error without its context.
        let mut error = error;
        let next_action = ffi::take_error_next_action(error.message_ptr);
        let context_ptr = error.context;
        error.context = std::ptr::null_mut();
        let context = if context_ptr.is_null()
            || !(context_ptr as usize).is_multiple_of(std::mem::align_of::<ffi::ErrorContextV1>())
        {
            None
        } else {
            let boxed: Box<ffi::ErrorContextV1> = Box::from_raw(context_ptr);
            context_from_ffi(*boxed).ok()
        };
        drop(error);
        let mut out = Error::new(code, message);
        if let Some(ctx) = context {
            out = out.with_context(ctx);
        }
        if let Some(next_action) = next_action {
            out = out.with_next_action(next_action);
        }
        out
    }
}

/// Convert a crate-root [`ErrorContext`] into its FFI shadow. The
/// caller takes ownership of the returned value; release via the
/// parent [`ffi::Error`]'s destructor or
/// `ovstorage_plugin_error_context_free`.
pub fn context_to_ffi(context: &ErrorContext) -> ffi::ErrorContextV1 {
    match context {
        ErrorContext::Identity { new_etag } => {
            ffi::ErrorContextV1::from_identity(ffi::IdentityErrorContextV1 {
                new_etag: primitive::optional_to_ffi(new_etag.clone(), primitive::str_to_ffi),
            })
        }
        ErrorContext::Auth {
            connection_id,
            reason,
            expired_at,
        } => ffi::ErrorContextV1::from_auth(ffi::AuthErrorContextV1 {
            connection_id: connection::connection_id_to_ffi(connection_id.clone()),
            reason: primitive::optional_to_ffi(reason.clone(), primitive::str_to_ffi),
            expired_at_unix_ms: primitive::optional_to_ffi(
                *expired_at,
                primitive::system_time_to_unix_ms,
            ),
        }),
    }
}

/// Consume an [`ffi::ErrorContextV1`] into [`ErrorContext`],
/// releasing nested allocations. Treat `value` as moved.
///
/// # Safety
///
/// `value` must be a valid [`ffi::ErrorContextV1`] produced by
/// [`context_to_ffi`] or an FFI counterpart with the same allocator
/// convention.
pub unsafe fn context_from_ffi(value: ffi::ErrorContextV1) -> Result<ErrorContext, Error> {
    unsafe {
        // Move the active slot out before `value`'s Drop can touch
        // the wrong half: read kind, `assume_init_read` the payload,
        // then forget `value`.
        let kind = value.kind;
        let payload = match kind {
            ffi::ErrorContextKindV1::Identity => {
                let inner = value.identity.assume_init_read();
                std::mem::forget(value);
                let new_etag =
                    primitive::optional_from_ffi::<ffi::Str, String, Error>(inner.new_etag, |s| {
                        primitive::str_from_ffi(s)
                    })?;
                ErrorContext::Identity { new_etag }
            }
            ffi::ErrorContextKindV1::Auth => {
                let inner = value.auth.assume_init_read();
                std::mem::forget(value);
                let connection_id = connection::connection_id_from_ffi(inner.connection_id)?;
                let reason =
                    primitive::optional_from_ffi::<ffi::Str, String, Error>(inner.reason, |s| {
                        primitive::str_from_ffi(s)
                    })?;
                let expired_at = primitive::optional_from_ffi::<i64, SystemTime, Error>(
                    inner.expired_at_unix_ms,
                    |ms| Ok(primitive::system_time_from_unix_ms(ms)),
                )?;
                ErrorContext::Auth {
                    connection_id,
                    reason,
                    expired_at,
                }
            }
        };
        Ok(payload)
    }
}

/// Convert a crate-root [`ErrorCode`] into its [`ffi::ErrorCode`]
/// counterpart.
pub fn code_to_ffi(code: ErrorCode) -> ffi::ErrorCode {
    match code {
        ErrorCode::NotFound => ffi::ErrorCode::NotFound,
        ErrorCode::AlreadyExists => ffi::ErrorCode::AlreadyExists,
        ErrorCode::PermissionDenied => ffi::ErrorCode::PermissionDenied,
        ErrorCode::PreconditionFailed => ffi::ErrorCode::PreconditionFailed,
        ErrorCode::Conflict => ffi::ErrorCode::Conflict,
        ErrorCode::DirectoryNotEmpty => ffi::ErrorCode::DirectoryNotEmpty,
        ErrorCode::Unsupported => ffi::ErrorCode::Unsupported,
        ErrorCode::InvalidArgument => ffi::ErrorCode::InvalidArgument,
        ErrorCode::IncompatibleType => ffi::ErrorCode::IncompatibleType,
        ErrorCode::Locked => ffi::ErrorCode::Locked,
        ErrorCode::Cancelled => ffi::ErrorCode::Cancelled,
        ErrorCode::DeadlineExceeded => ffi::ErrorCode::DeadlineExceeded,
        ErrorCode::Transient => ffi::ErrorCode::Transient,
        ErrorCode::ResourceExhausted => ffi::ErrorCode::ResourceExhausted,
        ErrorCode::IntegrityFailure => ffi::ErrorCode::IntegrityFailure,
        ErrorCode::Internal => ffi::ErrorCode::Internal,
        ErrorCode::BrokerUnavailable => ffi::ErrorCode::BrokerUnavailable,
        ErrorCode::BrokerRequired => ffi::ErrorCode::BrokerRequired,
        ErrorCode::RedirectExpired => ffi::ErrorCode::RedirectExpired,
        ErrorCode::PolicyEpochStale => ffi::ErrorCode::PolicyEpochStale,
        ErrorCode::AuthorizationLeaseExpired => ffi::ErrorCode::AuthorizationLeaseExpired,
        ErrorCode::CacheCorrupt => ffi::ErrorCode::CacheCorrupt,
        ErrorCode::StagingExpired => ffi::ErrorCode::StagingExpired,
        ErrorCode::CommitAmbiguous => ffi::ErrorCode::CommitAmbiguous,
        ErrorCode::CacheLockContention => ffi::ErrorCode::CacheLockContention,
        ErrorCode::StateRootUnavailable => ffi::ErrorCode::StateRootUnavailable,
        ErrorCode::NetworkFilesystemRefused => ffi::ErrorCode::NetworkFilesystemRefused,
        ErrorCode::ObjectModified => ffi::ErrorCode::ObjectModified,
        ErrorCode::NoRoute => ffi::ErrorCode::NoRoute,
        ErrorCode::RouteConflict => ffi::ErrorCode::RouteConflict,
        ErrorCode::NotConfigured => ffi::ErrorCode::NotConfigured,
        ErrorCode::AliasChainTooLong => ffi::ErrorCode::AliasChainTooLong,
        ErrorCode::CredentialExpired => ffi::ErrorCode::CredentialExpired,
        ErrorCode::CredentialUnavailable => ffi::ErrorCode::CredentialUnavailable,
        ErrorCode::AuthRequired => ffi::ErrorCode::AuthRequired,
        ErrorCode::AuthCancelled => ffi::ErrorCode::AuthCancelled,
        ErrorCode::AuthExpired => ffi::ErrorCode::AuthExpired,
        ErrorCode::ContentMismatch => ffi::ErrorCode::ContentMismatch,
        ErrorCode::ContentChecksumMismatch => ffi::ErrorCode::ContentChecksumMismatch,
        ErrorCode::PluginRejected => ffi::ErrorCode::PluginRejected,
    }
}

/// Convert an [`ffi::ErrorCode`] into its crate-root counterpart.
pub fn code_from_ffi(code: ffi::ErrorCode) -> ErrorCode {
    match code {
        ffi::ErrorCode::NotFound => ErrorCode::NotFound,
        ffi::ErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        ffi::ErrorCode::PermissionDenied => ErrorCode::PermissionDenied,
        ffi::ErrorCode::PreconditionFailed => ErrorCode::PreconditionFailed,
        ffi::ErrorCode::Conflict => ErrorCode::Conflict,
        ffi::ErrorCode::DirectoryNotEmpty => ErrorCode::DirectoryNotEmpty,
        ffi::ErrorCode::Unsupported => ErrorCode::Unsupported,
        ffi::ErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        ffi::ErrorCode::IncompatibleType => ErrorCode::IncompatibleType,
        ffi::ErrorCode::Locked => ErrorCode::Locked,
        ffi::ErrorCode::Cancelled => ErrorCode::Cancelled,
        ffi::ErrorCode::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        ffi::ErrorCode::Transient => ErrorCode::Transient,
        ffi::ErrorCode::ResourceExhausted => ErrorCode::ResourceExhausted,
        ffi::ErrorCode::IntegrityFailure => ErrorCode::IntegrityFailure,
        ffi::ErrorCode::Internal => ErrorCode::Internal,
        ffi::ErrorCode::BrokerUnavailable => ErrorCode::BrokerUnavailable,
        ffi::ErrorCode::BrokerRequired => ErrorCode::BrokerRequired,
        ffi::ErrorCode::RedirectExpired => ErrorCode::RedirectExpired,
        ffi::ErrorCode::PolicyEpochStale => ErrorCode::PolicyEpochStale,
        ffi::ErrorCode::AuthorizationLeaseExpired => ErrorCode::AuthorizationLeaseExpired,
        ffi::ErrorCode::CacheCorrupt => ErrorCode::CacheCorrupt,
        ffi::ErrorCode::StagingExpired => ErrorCode::StagingExpired,
        ffi::ErrorCode::CommitAmbiguous => ErrorCode::CommitAmbiguous,
        ffi::ErrorCode::CacheLockContention => ErrorCode::CacheLockContention,
        ffi::ErrorCode::StateRootUnavailable => ErrorCode::StateRootUnavailable,
        ffi::ErrorCode::NetworkFilesystemRefused => ErrorCode::NetworkFilesystemRefused,
        ffi::ErrorCode::ObjectModified => ErrorCode::ObjectModified,
        ffi::ErrorCode::NoRoute => ErrorCode::NoRoute,
        ffi::ErrorCode::RouteConflict => ErrorCode::RouteConflict,
        ffi::ErrorCode::NotConfigured => ErrorCode::NotConfigured,
        ffi::ErrorCode::AliasChainTooLong => ErrorCode::AliasChainTooLong,
        ffi::ErrorCode::CredentialExpired => ErrorCode::CredentialExpired,
        ffi::ErrorCode::CredentialUnavailable => ErrorCode::CredentialUnavailable,
        ffi::ErrorCode::AuthRequired => ErrorCode::AuthRequired,
        ffi::ErrorCode::AuthCancelled => ErrorCode::AuthCancelled,
        ffi::ErrorCode::AuthExpired => ErrorCode::AuthExpired,
        ffi::ErrorCode::ContentMismatch => ErrorCode::ContentMismatch,
        ffi::ErrorCode::ContentChecksumMismatch => ErrorCode::ContentChecksumMismatch,
        ffi::ErrorCode::PluginRejected => ErrorCode::PluginRejected,
    }
}
