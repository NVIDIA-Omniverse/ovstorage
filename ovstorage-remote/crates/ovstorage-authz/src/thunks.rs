// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side helpers bridging the authz plugin C ABI's
//! `(status, result, error, user_data)` callbacks to
//! `tokio::sync::oneshot` so the host can `await` the result.

use std::sync::Arc;

use ovstorage_plugin::ffi as plugin_ffi;
use ovstorage_plugin::{Error, ErrorCode, Result};
use tokio::sync::oneshot;

/// FFI callback outcome: status code, plugin-allocated result pointer,
/// and possibly-non-null error pointer.
pub struct Outcome<T> {
    pub status: i32,
    pub result: *mut T,
    pub error: *mut plugin_ffi::Error,
}

// SAFETY: heap pointers transfer plugin → receiver on callback; the async receiver does the conversion.
unsafe impl<T> Send for Outcome<T> {}

/// Pack a oneshot sender into a heap-allocated `user_data` pointer.
pub fn into_user_data<T>(tx: oneshot::Sender<Outcome<T>>) -> *mut core::ffi::c_void {
    Box::into_raw(Box::new(tx)) as *mut core::ffi::c_void
}

/// Reclaim the oneshot sender from a `user_data` pointer.
///
/// # Safety
///
/// `user_data` must come from [`into_user_data`] and not yet be consumed.
pub unsafe fn from_user_data<T>(
    user_data: *mut core::ffi::c_void,
) -> Box<oneshot::Sender<Outcome<T>>> {
    unsafe { Box::from_raw(user_data as *mut oneshot::Sender<Outcome<T>>) }
}

/// Convert an `Outcome` into `Result<U>`, freeing the FFI error and
/// boxing back the result pointer before running `convert`.
///
/// # Safety
///
/// `outcome.result`/`outcome.error` must be plugin-produced and unfreed.
pub unsafe fn outcome_into_result<T, U>(
    outcome: Outcome<T>,
    convert: impl FnOnce(T) -> Result<U>,
) -> Result<U> {
    unsafe {
        if !outcome.error.is_null() {
            let error_ffi = *Box::from_raw(outcome.error);
            let err = ovstorage_plugin::shim::error::from_ffi(error_ffi);
            return Err(err);
        }
        if outcome.status != 0 {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "plugin callback returned non-zero status {}",
                    outcome.status
                ),
            ));
        }
        if outcome.result.is_null() {
            return Err(Error::new(
                ErrorCode::Internal,
                "plugin callback returned null result with status=0",
            ));
        }
        let value = *Box::from_raw(outcome.result);
        convert(value)
    }
}

/// Status-only outcome (no result struct); used by `configure`.
pub struct StatusOutcome {
    pub status: i32,
    pub error: *mut plugin_ffi::Error,
}

unsafe impl Send for StatusOutcome {}

pub fn into_status_user_data(tx: oneshot::Sender<StatusOutcome>) -> *mut core::ffi::c_void {
    Box::into_raw(Box::new(tx)) as *mut core::ffi::c_void
}

/// # Safety
///
/// `user_data` must come from [`into_status_user_data`] and not yet be consumed.
pub unsafe fn from_status_user_data(
    user_data: *mut core::ffi::c_void,
) -> Box<oneshot::Sender<StatusOutcome>> {
    unsafe { Box::from_raw(user_data as *mut oneshot::Sender<StatusOutcome>) }
}

/// # Safety
///
/// `outcome.error` must be a pointer the plugin produced.
pub unsafe fn status_into_result(outcome: StatusOutcome) -> Result<()> {
    unsafe {
        if !outcome.error.is_null() {
            let error_ffi = *Box::from_raw(outcome.error);
            return Err(ovstorage_plugin::shim::error::from_ffi(error_ffi));
        }
        if outcome.status != 0 {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "plugin callback returned non-zero status {}",
                    outcome.status
                ),
            ));
        }
        Ok(())
    }
}

/// Refcounted library + vtable handle. Drop order:
/// plugin_state → vtable.drop → library (dlclose).
pub(crate) struct AuthzPluginHandle {
    pub plugin_state: *mut core::ffi::c_void,
    pub vtable: *const crate::ffi::AuthzPluginVTableV1,
    pub _library: Arc<libloading::Library>,
}

impl Drop for AuthzPluginHandle {
    fn drop(&mut self) {
        if !self.vtable.is_null() && !self.plugin_state.is_null() {
            // SAFETY: vtable.drop is a valid function pointer for the
            // lifetime of the loaded library; library is held alongside.
            unsafe {
                ((*self.vtable).drop)(self.plugin_state);
            }
            self.plugin_state = std::ptr::null_mut();
            self.vtable = std::ptr::null();
        }
    }
}

// SAFETY: Arc<Library> keeps the plugin's memory image loaded for the handle's lifetime.
unsafe impl Send for AuthzPluginHandle {}
unsafe impl Sync for AuthzPluginHandle {}
