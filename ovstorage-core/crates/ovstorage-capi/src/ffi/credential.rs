// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! External-token-injection surface.
//!
//! Two pieces:
//! - **Continuation callback** (`OvCredentialCallback`) for an
//!   external credential provider implemented by the host. The
//!   `resolve` thunk takes a completion function pointer plus opaque
//!   userdata and fires `completion(...)` exactly once, on any thread,
//!   when the async work is done. Returning from `resolve` does NOT
//!   mean the work has completed.
//! - **Direct cache injection** via `ovstorage_library_set_credential`,
//!   used for proactive token-push patterns where a control-plane
//!   portal mints fresh tokens out of band.
//!
//! Cancellation contract:
//! - `completion` MUST be called exactly once, even on cancellation
//!   or failure. Cancellation paths fire
//!   `completion(..., status_with_error, NULL)` before cleaning up.
//! - Calling `completion` twice is undefined behavior — the host's
//!   internal sender is consumed on the first call. The C ABI trusts
//!   the caller; the C++/Python wrappers enforce single-fire.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use tokio::sync::oneshot;

use ovstorage::auth::{
    CallbackCredentialProvider, CredentialError, CredentialProvider, PrincipalView,
    ResolvedCredential,
};
use ovstorage::{BackendId, Error as OvError, ErrorCode, SecretBundle};

use super::builders::{SecretValue, take_secret_value};
use super::{
    Error, Library, ReservedOptionsPadding, Status, cstr_to_string, required_ref, run_sync,
    set_error,
};

// ---------------------------------------------------------------------
// Resolved-credential wire shape
// ---------------------------------------------------------------------

/// Resolved-credential payload passed into the host (via
/// `ovstorage_library_set_credential` or
/// `OvCredentialCallbackCompletion`).
///
/// The bundle is built via
/// `ovstorage_resolved_credential_bundle_create` +
/// `ovstorage_resolved_credential_bundle_add_field`. `source_name`
/// is borrowed for the duration of the call only — the host copies
/// it internally.
#[repr(C)]
pub struct OvResolvedCredentialV1 {
    pub struct_size: usize,
    /// Opaque secret-bundle handle; consumed by the host on success.
    pub bundle: *mut OvResolvedCredentialBundle,
    pub has_expires_at: bool,
    pub expires_at_unix_nanos: u64,
    /// Borrowed C-string. Required (non-null). Must be valid UTF-8.
    pub source_name: *const c_char,
    pub _reserved: ReservedOptionsPadding,
}

/// Opaque secret-bundle handle for `OvResolvedCredentialV1`. Built
/// with `ovstorage_resolved_credential_bundle_create`, populated via
/// `_add_field`, consumed by the host on success.
pub struct OvResolvedCredentialBundle {
    inner: Option<SecretBundle>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_resolved_credential_bundle_create()
-> *mut OvResolvedCredentialBundle {
    Box::into_raw(Box::new(OvResolvedCredentialBundle {
        inner: Some(SecretBundle::default()),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_resolved_credential_bundle_destroy(
    bundle: *mut OvResolvedCredentialBundle,
) {
    if !bundle.is_null() {
        let _ = unsafe { Box::from_raw(bundle) };
    }
}

/// Add a `(key, value)` field to a credential bundle. Consumes the
/// `SecretValue` handle on success — the caller must NOT call
/// `ovstorage_secret_value_destroy` on it after a successful return.
/// On failure the value is dropped here, so the caller never
/// double-frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_resolved_credential_bundle_add_field(
    bundle: *mut OvResolvedCredentialBundle,
    key: *const c_char,
    value: *mut SecretValue,
    out_error: *mut Error,
) -> Status {
    run_sync(out_error, || unsafe {
        if bundle.is_null() {
            return Err(OvError::new(
                ErrorCode::InvalidArgument,
                "bundle must not be null",
            ));
        }
        let key_str = cstr_to_string(key, "key")?;
        let secret = take_secret_value(value).ok_or_else(|| {
            OvError::new(
                ErrorCode::InvalidArgument,
                "secret_value handle is null or already consumed",
            )
        })?;
        let bundle_ref = (*bundle).inner.as_mut().ok_or_else(|| {
            OvError::new(
                ErrorCode::InvalidArgument,
                "credential bundle has already been consumed",
            )
        })?;
        bundle_ref.fields.insert(key_str, secret);
        Ok(())
    })
}

// ---------------------------------------------------------------------
// Continuation-callback shape
// ---------------------------------------------------------------------

/// One-shot completion callback fired by the host's `resolve`
/// implementation when the async credential-fetch is done.
///
/// `status == Status::Ok` and `credential != NULL` on success; any
/// other status with `credential == NULL` on failure. Fire EXACTLY
/// ONCE — the host's internal sender is consumed on the call.
pub type OvCredentialCallbackCompletion = unsafe extern "C" fn(
    completion_userdata: *mut c_void,
    status: Status,
    credential: *const OvResolvedCredentialV1,
);

/// Async resolve thunk. The implementation MUST call `completion(...)`
/// exactly once (on any thread) when the work completes. Returning
/// from `resolve` does NOT mean the work has completed.
pub type OvCredentialCallbackResolveFn = unsafe extern "C" fn(
    userdata: *mut c_void,
    backend_id: *const c_char,
    principal_id: *const c_char,
    completion: OvCredentialCallbackCompletion,
    completion_userdata: *mut c_void,
);

/// Optional cleanup hook for the callback's `userdata`. Invoked once
/// at library shutdown. NULL = no cleanup.
pub type OvCredentialCallbackFreeFn = unsafe extern "C" fn(*mut c_void);

/// `resolve` may be NULL when `has_credential_callback` is `false` in
/// `LibraryInitOptionsV1` (zero-initialized form). When
/// `has_credential_callback` is `true`, `resolve` MUST be non-NULL.
/// `free_userdata` is always optional (NULL = no cleanup).
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct OvCredentialCallback {
    pub resolve: Option<
        unsafe extern "C" fn(
            userdata: *mut c_void,
            backend_id: *const c_char,
            principal_id: *const c_char,
            completion: OvCredentialCallbackCompletion,
            completion_userdata: *mut c_void,
        ),
    >,
    pub free_userdata: Option<unsafe extern "C" fn(*mut c_void)>,
    pub userdata: *mut c_void,
}

/// Host-side RAII wrapper around `OvCredentialCallback`. `Drop`
/// invokes `free_userdata` exactly once when set. The `Send + Sync`
/// impls are an unsafe contract: the C caller is responsible for
/// ensuring its `userdata` is safe to read from any thread.
pub(crate) struct OvCredentialCallbackOwned {
    pub(crate) callback: OvCredentialCallback,
}

unsafe impl Send for OvCredentialCallbackOwned {}
unsafe impl Sync for OvCredentialCallbackOwned {}

impl Drop for OvCredentialCallbackOwned {
    fn drop(&mut self) {
        if let Some(free) = self.callback.free_userdata {
            unsafe { free(self.callback.userdata) };
        }
    }
}

/// Internal completion thunk. Consumes the boxed sender exactly once;
/// receiver-drop (cancellation / shutdown) is handled gracefully.
extern "C" fn completion_thunk(
    completion_userdata: *mut c_void,
    status: Status,
    credential: *const OvResolvedCredentialV1,
) {
    // SAFETY: `completion_userdata` was minted from a Box at
    // `resolve`-call time; we own it back here. Caller MUST not invoke
    // this thunk twice — second call would double-free.
    let tx: Box<oneshot::Sender<Result<ResolvedCredential, CredentialError>>> =
        unsafe { Box::from_raw(completion_userdata as *mut _) };
    let result = if matches!(status, Status::Ok) && !credential.is_null() {
        // SAFETY: the FFI struct must outlive the `completion` call;
        // the C contract forbids the caller from freeing it before
        // returning. We deep-copy bundle + source_name into Rust here.
        match unsafe { resolved_credential_from_ffi(&*credential) } {
            Ok(value) => Ok(value),
            Err(err) => Err(CredentialError::Backend(err)),
        }
    } else {
        Err(CredentialError::Backend(OvError::new(
            error_code_from_status(status),
            "C credential callback returned error",
        )))
    };
    let _ = tx.send(result);
}

/// Build a host-side `CredentialProvider` that delegates to an
/// `OvCredentialCallback`. Each resolve clones the callback's `Arc`
/// and awaits a oneshot receiver fed by `completion_thunk`.
pub(crate) fn build_callback_provider(
    name: String,
    callback: OvCredentialCallback,
) -> Result<Arc<dyn CredentialProvider>, OvError> {
    let resolve_fn = callback.resolve.ok_or_else(|| {
        OvError::new(
            ErrorCode::InvalidArgument,
            "OvCredentialCallback.resolve must not be null when has_credential_callback is true",
        )
    })?;
    let owned = Arc::new(OvCredentialCallbackOwned { callback });
    let provider = CallbackCredentialProvider::new(name, move |backend, principal| {
        let owned = owned.clone();
        async move {
            let backend_c = CString::new(backend.0.clone()).map_err(|_| {
                CredentialError::Backend(OvError::new(
                    ErrorCode::InvalidArgument,
                    "backend_id contains an interior NUL byte",
                ))
            })?;
            let principal_c = CString::new(principal.id.clone()).map_err(|_| {
                CredentialError::Backend(OvError::new(
                    ErrorCode::InvalidArgument,
                    "principal id contains an interior NUL byte",
                ))
            })?;
            let (tx, rx) = oneshot::channel::<Result<ResolvedCredential, CredentialError>>();
            let tx_box = Box::into_raw(Box::new(tx)) as *mut c_void;
            // SAFETY: the C-side resolve function pointer is
            // documented to fire `completion_thunk(...)` exactly once
            // on any thread. The `tx_box` is consumed by that thunk.
            // Receiver-drop (Library shutdown) is handled gracefully.
            unsafe {
                resolve_fn(
                    owned.callback.userdata,
                    backend_c.as_ptr(),
                    principal_c.as_ptr(),
                    completion_thunk,
                    tx_box,
                );
            }
            rx.await.map_err(|_| {
                CredentialError::Backend(OvError::new(
                    ErrorCode::Internal,
                    "C credential callback dropped completion sender without firing",
                ))
            })?
        }
    });
    Ok(Arc::new(provider))
}

/// Marshal `OvResolvedCredentialV1` into a host `ResolvedCredential`.
/// The bundle handle is consumed only on success — all non-owning
/// validation runs before `Box::from_raw`, so a failed validation
/// leaves the caller's bundle intact.
unsafe fn resolved_credential_from_ffi(
    ffi: &OvResolvedCredentialV1,
) -> Result<ResolvedCredential, OvError> {
    if ffi.struct_size != 0 && ffi.struct_size < std::mem::size_of::<OvResolvedCredentialV1>() {
        return Err(OvError::new(
            ErrorCode::InvalidArgument,
            "OvResolvedCredentialV1.struct_size is smaller than this library supports",
        ));
    }
    if ffi.bundle.is_null() {
        return Err(OvError::new(
            ErrorCode::InvalidArgument,
            "OvResolvedCredentialV1.bundle must not be null",
        ));
    }
    if ffi.source_name.is_null() {
        return Err(OvError::new(
            ErrorCode::InvalidArgument,
            "OvResolvedCredentialV1.source_name must not be null",
        ));
    }
    let source = unsafe { CStr::from_ptr(ffi.source_name) }
        .to_str()
        .map_err(|_| {
            OvError::new(
                ErrorCode::InvalidArgument,
                "OvResolvedCredentialV1.source_name is not UTF-8",
            )
        })?
        .to_string();
    let expires_at = ffi
        .has_expires_at
        .then(|| UNIX_EPOCH + Duration::from_nanos(ffi.expires_at_unix_nanos));
    let bundle = unsafe { Box::from_raw(ffi.bundle) }.inner.ok_or_else(|| {
        OvError::new(
            ErrorCode::InvalidArgument,
            "OvResolvedCredentialV1.bundle has already been consumed",
        )
    })?;
    Ok(ResolvedCredential {
        bytes: bundle,
        expires_at,
        source_name: source,
    })
}

fn error_code_from_status(status: Status) -> ErrorCode {
    match status {
        Status::Ok => ErrorCode::Internal, // unreachable: only called on error paths
        Status::NotFound => ErrorCode::NotFound,
        Status::AlreadyExists => ErrorCode::AlreadyExists,
        Status::PermissionDenied => ErrorCode::PermissionDenied,
        Status::PreconditionFailed => ErrorCode::PreconditionFailed,
        Status::Conflict => ErrorCode::Conflict,
        Status::DirectoryNotEmpty => ErrorCode::DirectoryNotEmpty,
        Status::Unsupported => ErrorCode::Unsupported,
        Status::InvalidArgument => ErrorCode::InvalidArgument,
        Status::ObjectModified => ErrorCode::ObjectModified,
        Status::NoRoute => ErrorCode::NoRoute,
        Status::Transient => ErrorCode::Transient,
        Status::Cancelled => ErrorCode::Cancelled,
        Status::Internal => ErrorCode::Internal,
    }
}

// ---------------------------------------------------------------------
// Cache durability enum
// ---------------------------------------------------------------------

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OvCredentialCacheDurability {
    Persistent = 0,
    InMemoryOnly = 1,
}

impl OvCredentialCacheDurability {
    pub(crate) fn to_rust(self) -> ovstorage::auth::CredentialCacheDurability {
        match self {
            Self::Persistent => ovstorage::auth::CredentialCacheDurability::Persistent,
            Self::InMemoryOnly => ovstorage::auth::CredentialCacheDurability::InMemoryOnly,
        }
    }
}

// ---------------------------------------------------------------------
// Direct cache injection: ovstorage_library_set_credential
// ---------------------------------------------------------------------

/// Inject a credential into the cache, bypassing the provider chain.
/// Async; fires `on_complete` from the runtime.
///
/// `backend_id` and `principal_id` are borrowed C-strings; copied at
/// prologue time. `credential->bundle` is consumed on success — do
/// NOT call `ovstorage_resolved_credential_bundle_destroy` on it
/// after a successful return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_set_credential(
    library: *mut Library,
    backend_id: *const c_char,
    principal_id: *const c_char,
    credential: *const OvResolvedCredentialV1,
    on_complete: super::StatusCallback,
    user_data: *mut c_void,
) {
    let user_data_addr = user_data as usize;
    let prologue: Result<_, OvError> = (|| unsafe {
        let lib = required_ref(library, "library")?;
        let backend = BackendId(cstr_to_string(backend_id, "backend_id")?);
        let principal = PrincipalView::new(cstr_to_string(principal_id, "principal_id")?);
        if credential.is_null() {
            return Err(OvError::new(
                ErrorCode::InvalidArgument,
                "credential must not be null",
            ));
        }
        let resolved = resolved_credential_from_ffi(&*credential)?;
        Ok((
            lib.inner.clone(),
            lib.runtime.clone(),
            backend,
            principal,
            resolved,
        ))
    })();
    let runtime = match &prologue {
        Ok((_, runtime, _, _, _)) => runtime.clone(),
        Err(_) => {
            // No runtime available (library was null). Spawn a
            // one-shot thread so on_complete still fires eventually.
            std::thread::Builder::new()
                .name("ovs-capi-err".into())
                .spawn(move || {
                    fire_status(on_complete, user_data_addr, prologue.err());
                })
                .expect("failed to spawn thread");
            return;
        }
    };
    runtime.spawn(async move {
        let result = match prologue {
            Ok((lib, _runtime, backend, principal, credential)) => {
                lib.set_credential(backend, principal, credential).await
            }
            Err(err) => Err(err),
        };
        fire_status(on_complete, user_data_addr, result.err());
    });
}

fn fire_status(on_complete: super::StatusCallback, user_data_addr: usize, err: Option<OvError>) {
    let Some(cb) = on_complete else { return };
    let user_data = user_data_addr as *mut c_void;
    let mut ffi_error = Error {
        code: Status::Ok,
        message: ptr::null_mut(),
    };
    let status = match err {
        None => Status::Ok,
        Some(error) => unsafe { set_error(&mut ffi_error, error) },
    };
    unsafe {
        cb(status, &ffi_error, user_data);
        if !ffi_error.message.is_null() {
            let _ = CString::from_raw(ffi_error.message);
        }
    }
}
