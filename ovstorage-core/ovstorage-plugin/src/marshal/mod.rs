// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Marshalling between crate-root Rust types and their `ffi::T`
//! shadow types.
//!
//! Conversions consume their input in both directions so each
//! `ffi::T` allocation has exactly one ownership home — preventing
//! double-frees by construction.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::{Duration, SystemTime};

use crate::ffi;
use crate::{
    AccessDecision, AccessOps, AddressRoot, AddressVisibility, AuthAttempt, AuthEvent, AuthReason,
    BackendChangeEvent, BackendId, BackendItemInfo, Body, BodyStream, ByteRange, Capabilities,
    ChangeKind, ChangeKindSet, ChecksumAlgorithm, ChecksumSet, ConfigField, ConfigFieldKind,
    ConfigLayer, ConfigValue, Connection, ConnectionAuthState, ConnectionId, ConnectionRequest,
    ConnectionSource, CopyOptions, CreateDirectoryOptions, CredentialField, CredentialMethod,
    DeleteDirectoryOptions, DeleteOptions, EffectivePermissions, EnumSource, Error, ErrorCode,
    ErrorContext, HttpRequest, IfDestExists, ListOptions, ListVersionsOptions, LocalDelegate,
    MtimeFormat, ObjectInfo, ObjectKind, PartialStage, ReadOptions, ReadRedirect, ReadResult,
    ReadStream, RedirectBodySource, RedirectCredential, RedirectResult, RedirectResultBatch,
    RedirectScope, RenameOptions, ResolvedTarget, ResponseParsing, ResultCapture, RollbackEffect,
    RouteSource, SecretBundle, SecretBytes, SecretValue, StageOutcome, StatOptions,
    StorageBackendKindDescriptor, SystemMetadata, UpdateMetadataOptions, Url, UserMetadata,
    VersionListOrder, WatchDirectoryCursor, WatchDirectoryOptions, WriteOptions, WriteRedirect,
    WriteRedirectBatch, WriteResult, WriteStep,
};

pub mod access;
pub mod address;
pub mod auth;
pub mod capabilities;
pub mod change;
pub mod connection;
pub mod descriptor;
pub mod error;
pub mod factory;
pub mod identity;
pub mod metadata;
pub mod options;
pub mod payload;
pub mod primitive;
pub mod redirect;

// ---------------------------------------------------------------------
// Plugin SPI traits + host-callback wrapper
// ---------------------------------------------------------------------

/// Process-local storage for the host callbacks pointer.
// Internal process singleton holding the host callback table pointer stashed by
// the init thunk; an atomic pointer slot, not a C ABI symbol.
/// cbindgen:ignore
static REGISTERED_HOST: AtomicPtr<ffi::HostCallbacks> = AtomicPtr::new(std::ptr::null_mut());

/// Stash the host callbacks pointer for the plugin's lifetime; the
/// init thunk calls this once. Reach the value later via [`host`].
///
/// # Safety
///
/// `ptr`, when non-null, must point at an `ffi::HostCallbacks`
/// whose function-pointer fields stay valid for the cdylib's
/// lifetime.
pub unsafe fn register_host(ptr: *const ffi::HostCallbacks) {
    REGISTERED_HOST.store(ptr as *mut ffi::HostCallbacks, Ordering::SeqCst);
}

/// Borrow the registered host callbacks. Returns `None` before init
/// or if the registered pointer is null.
pub fn host() -> Option<HostCallbacks<'static>> {
    let ptr = REGISTERED_HOST.load(Ordering::SeqCst) as *const ffi::HostCallbacks;
    // SAFETY: pointer is valid for the cdylib's lifetime per the host's contract.
    unsafe { HostCallbacks::from_raw(ptr) }
}

/// Safe wrapper over `ffi::HostCallbacks`. Plugin code reaches one
/// via [`host`] after init.
pub struct HostCallbacks<'a> {
    raw: &'a ffi::HostCallbacks,
}

impl<'a> HostCallbacks<'a> {
    /// Wrap a `*const ffi::HostCallbacks`. Returns `None` on null;
    /// plugin thunks treat that as `ErrorCode::InvalidArgument`.
    ///
    /// # Safety
    ///
    /// `raw`, when non-null, must point at a valid
    /// `ffi::HostCallbacks` whose function-pointer fields are valid
    /// for `'a`.
    pub unsafe fn from_raw(raw: *const ffi::HostCallbacks) -> Option<Self> {
        unsafe {
            if raw.is_null() {
                return None;
            }
            Some(Self { raw: &*raw })
        }
    }

    /// Return the kind of host loading the plugin. Unknown future values fall
    /// through to the direct-host variant; prefer `is_broker()` for
    /// forward-compatibility.
    pub fn host_kind(&self) -> ffi::HostKindV1 {
        match self.raw.host_kind {
            x if x == ffi::HostKindV1::Broker as u32 => ffi::HostKindV1::Broker,
            _ => ffi::HostKindV1::Library,
        }
    }

    /// `true` when the plugin is loaded inside a broker daemon.
    pub fn is_broker(&self) -> bool {
        self.raw.host_kind == ffi::HostKindV1::Broker as u32
    }

    /// Forward a single log event to the host. Silently no-ops if the
    /// host is too old to expose the `log` field (older `struct_size`),
    /// so plugins compiled against a newer header still load against
    /// older hosts.
    pub fn log(&self, level: ffi::LogLevelV1, target: &str, message: &str) {
        // Forward-compat: only call into the slot when the host
        // declared a `struct_size` that covers it.
        let required =
            std::mem::offset_of!(ffi::HostCallbacks, log) + std::mem::size_of::<ffi::HostLogFn>();
        if self.raw.struct_size < required {
            return;
        }
        // ffi::Str's Drop reclaims its buffer as a Vec — correct for owned
        // values but UB for these views over borrowed `&str` slices. Wrap
        // each in ManuallyDrop so the destructor never fires; the
        // borrowed bytes belong to the caller.
        let target_ffi = std::mem::ManuallyDrop::new(ffi::Str {
            ptr: target.as_ptr() as *mut std::os::raw::c_char,
            len: target.len(),
        });
        let message_ffi = std::mem::ManuallyDrop::new(ffi::Str {
            ptr: message.as_ptr() as *mut std::os::raw::c_char,
            len: message.len(),
        });
        // SAFETY: `target` and `message` outlive the call (they're
        // borrows held until this returns); the host treats them as
        // borrowed strings and copies before freeing.
        unsafe {
            (self.raw.log)(
                self.raw.host_state,
                level as u8,
                &*target_ffi,
                &*message_ffi,
            );
        }
    }

    /// Read a secret from the host's secret store.
    pub fn secret_get(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
    ) -> Result<Option<SecretBytes>, Error> {
        let key = self.build_key(backend_kind, connection_id, field);
        let mut out_value = ffi::Optional::<ffi::SecretBytes>::none();
        // SAFETY: `key` and `out_value` are stack-locals valid for the call.
        let err_ptr = unsafe { (self.raw.secret_get)(self.raw.host_state, &key, &mut out_value) };
        drop(key);
        Self::check_error(err_ptr)?;
        // SAFETY: host populated `out_value` on success.
        let opt = unsafe {
            primitive::optional_from_ffi::<ffi::SecretBytes, SecretBytes, Error>(out_value, |sb| {
                Ok(descriptor::secret_bytes_from_ffi(sb))
            })
        }?;
        Ok(opt)
    }

    /// Write a secret into the host's secret store.
    pub fn secret_put(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
        value: &SecretBytes,
    ) -> Result<(), Error> {
        let key = self.build_key(backend_kind, connection_id, field);
        let value_ffi = descriptor::secret_bytes_to_ffi(value.clone());
        // SAFETY: see `secret_get`.
        let err_ptr = unsafe { (self.raw.secret_put)(self.raw.host_state, &key, &value_ffi) };
        drop(key);
        drop(value_ffi);
        Self::check_error(err_ptr)
    }

    /// Remove a secret from the host's secret store.
    pub fn secret_delete(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
    ) -> Result<(), Error> {
        let key = self.build_key(backend_kind, connection_id, field);
        // SAFETY: see `secret_get`.
        let err_ptr = unsafe { (self.raw.secret_delete)(self.raw.host_state, &key) };
        drop(key);
        Self::check_error(err_ptr)
    }

    /// Drive the host's per-`(backend_kind, connection_id)` refresh
    /// lock. `refresh_fn` runs at most once — skipped when the
    /// snapshot is fresh inside the critical section.
    pub fn auth_refresh_lock_with_refresh<F>(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        freshness_window: std::time::Duration,
        refresh_fn: F,
    ) -> Result<(), Error>
    where
        F: FnOnce() -> Result<(), Error>,
    {
        // Trampoline turning `FnOnce<F>` into `extern "C" fn`.
        unsafe extern "C" fn invoke<F>(state: *mut core::ffi::c_void) -> *mut ffi::Error
        where
            F: FnOnce() -> Result<(), Error>,
        {
            unsafe {
                let slot = &mut *(state as *mut Option<F>);
                match slot.take() {
                    Some(f) => match f() {
                        Ok(()) => std::ptr::null_mut(),
                        Err(error) => crate::ffi::abi_alloc::abi_box(error::to_ffi(&error)),
                    },
                    None => {
                        let err = Error::new(
                            ErrorCode::Internal,
                            "host invoked auth_refresh_lock_with_refresh's closure twice",
                        );
                        crate::ffi::abi_alloc::abi_box(error::to_ffi(&err))
                    }
                }
            }
        }

        let backend_kind_ffi = primitive::str_ref_to_ffi(backend_kind);
        let connection_id_ffi = connection::connection_id_to_ffi(connection_id.clone());
        let mut state: Option<F> = Some(refresh_fn);
        let freshness_window_ms = clamp_duration_to_ms(freshness_window);

        // SAFETY: callback callable for `self.raw`'s lifetime; `state`
        // is a stack-local `Option<F>` valid across the call.
        let err_ptr = unsafe {
            (self.raw.auth_refresh_lock_with_refresh)(
                self.raw.host_state,
                &backend_kind_ffi,
                &connection_id_ffi,
                freshness_window_ms,
                &mut state as *mut _ as *mut core::ffi::c_void,
                invoke::<F>,
            )
        };
        drop(backend_kind_ffi);
        drop(connection_id_ffi);
        Self::check_error(err_ptr)
    }

    fn build_key(
        &self,
        backend_kind: &str,
        connection_id: &ConnectionId,
        field: &str,
    ) -> ffi::SecretKey {
        ffi::SecretKey {
            backend_kind: primitive::str_ref_to_ffi(backend_kind),
            connection_id: connection::connection_id_to_ffi(connection_id.clone()),
            field: primitive::str_ref_to_ffi(field),
        }
    }

    /// Consume an `*mut ffi::Error` returned by a host callback.
    /// Null maps to `Ok(())`.
    fn check_error(err_ptr: *mut ffi::Error) -> Result<(), Error> {
        if err_ptr.is_null() {
            return Ok(());
        }
        // SAFETY: non-null `*mut ffi::Error` from a callback is an ABI
        // heap pointer per host/plugin contract.
        let inner = unsafe { crate::ffi::abi_alloc::abi_unbox(err_ptr) };
        Err(unsafe { error::from_ffi(inner) })
    }
}

fn clamp_duration_to_ms(duration: std::time::Duration) -> u64 {
    let ms = duration.as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

#[cfg(test)]
mod tests;
