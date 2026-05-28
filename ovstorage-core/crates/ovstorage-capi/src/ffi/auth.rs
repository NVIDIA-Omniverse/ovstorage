// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Streaming `authenticate_connection` event types.
//!
//! `AuthEvent` is an opaque, single-event handle.
//! `ovstorage_library_authenticate_connection` fires its multi-fire
//! callback once per drained event; each event handle is owned by
//! the callback (free with `ovstorage_auth_event_destroy`). The
//! final fire (`done=true`) delivers either a null event + null
//! error (success) or a null event + non-null error (terminal
//! failure).
//!
//! Variant-specific accessors return NULL/0 for the wrong variant.
//! For the Succeeded variant, `_succeeded_connection` returns a
//! borrowed `*const Connection` valid only while the event handle
//! lives — do NOT call `_connection_destroy` on it.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;
use std::time::UNIX_EPOCH;

use super::{Connection, Status, cstring_lossy, status_from_error};

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthEventKind {
    OpenBrowser = 0,
    DeviceCode = 1,
    Progress = 2,
    Succeeded = 3,
    Failed = 4,
    Cancelled = 5,
}

/// Opaque single-event handle. Variant is read via
/// `ovstorage_auth_event_kind`; accessors for non-matching variants
/// return NULL/0.
pub struct AuthEvent {
    kind: AuthEventKind,
    open_browser_url: Option<CString>,
    open_browser_expires_at_unix_nanos: u64,
    device_code_user_code: Option<CString>,
    device_code_verification_url: Option<CString>,
    device_code_expires_at_unix_nanos: u64,
    device_code_interval_nanos: u64,
    progress_message: Option<CString>,
    succeeded_connection: Option<Connection>,
    failed_error_code: Status,
    failed_error_message: Option<CString>,
}

impl AuthEvent {
    pub(crate) fn from_event(event: ovstorage::AuthEvent) -> Self {
        let mut this = Self {
            kind: AuthEventKind::Cancelled,
            open_browser_url: None,
            open_browser_expires_at_unix_nanos: 0,
            device_code_user_code: None,
            device_code_verification_url: None,
            device_code_expires_at_unix_nanos: 0,
            device_code_interval_nanos: 0,
            progress_message: None,
            succeeded_connection: None,
            failed_error_code: Status::Ok,
            failed_error_message: None,
        };
        match event {
            ovstorage::AuthEvent::OpenBrowser { url, expires_at } => {
                this.kind = AuthEventKind::OpenBrowser;
                this.open_browser_url = Some(cstring_lossy(&url));
                this.open_browser_expires_at_unix_nanos = expires_at
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64);
            }
            ovstorage::AuthEvent::DeviceCode {
                user_code,
                verification_url,
                expires_at,
                interval,
            } => {
                this.kind = AuthEventKind::DeviceCode;
                this.device_code_user_code = Some(cstring_lossy(&user_code));
                this.device_code_verification_url = Some(cstring_lossy(&verification_url));
                this.device_code_expires_at_unix_nanos = expires_at
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64);
                this.device_code_interval_nanos = interval.as_nanos() as u64;
            }
            ovstorage::AuthEvent::Progress { message } => {
                this.kind = AuthEventKind::Progress;
                this.progress_message = Some(cstring_lossy(&message));
            }
            ovstorage::AuthEvent::Succeeded { connection, .. } => {
                this.kind = AuthEventKind::Succeeded;
                this.succeeded_connection = Some(Connection::from_connection(*connection));
            }
            ovstorage::AuthEvent::Failed { error } => {
                this.kind = AuthEventKind::Failed;
                this.failed_error_code = status_from_error(error.code());
                this.failed_error_message = Some(cstring_lossy(error.message()));
            }
            ovstorage::AuthEvent::Cancelled => {
                this.kind = AuthEventKind::Cancelled;
            }
        }
        this
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_destroy(event: *mut AuthEvent) {
    unsafe {
        if event.is_null() {
            return;
        }
        drop(Box::from_raw(event));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_kind(event: *const AuthEvent) -> AuthEventKind {
    if event.is_null() {
        return AuthEventKind::Cancelled;
    }
    unsafe { (*event).kind }
}

// --- OpenBrowser accessors ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_open_browser_url(
    event: *const AuthEvent,
) -> *const c_char {
    if event.is_null() {
        return ptr::null();
    }
    unsafe {
        (*event)
            .open_browser_url
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_open_browser_expires_at_unix_nanos(
    event: *const AuthEvent,
) -> u64 {
    if event.is_null() {
        return 0;
    }
    unsafe { (*event).open_browser_expires_at_unix_nanos }
}

// --- DeviceCode accessors ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_device_code_user_code(
    event: *const AuthEvent,
) -> *const c_char {
    if event.is_null() {
        return ptr::null();
    }
    unsafe {
        (*event)
            .device_code_user_code
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_device_code_verification_url(
    event: *const AuthEvent,
) -> *const c_char {
    if event.is_null() {
        return ptr::null();
    }
    unsafe {
        (*event)
            .device_code_verification_url
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_device_code_expires_at_unix_nanos(
    event: *const AuthEvent,
) -> u64 {
    if event.is_null() {
        return 0;
    }
    unsafe { (*event).device_code_expires_at_unix_nanos }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_device_code_interval_nanos(
    event: *const AuthEvent,
) -> u64 {
    if event.is_null() {
        return 0;
    }
    unsafe { (*event).device_code_interval_nanos }
}

// --- Progress accessors ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_progress_message(
    event: *const AuthEvent,
) -> *const c_char {
    if event.is_null() {
        return ptr::null();
    }
    unsafe {
        (*event)
            .progress_message
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}

// --- Succeeded accessors ---

/// Returns a borrowed `*const Connection` valid until the AuthEvent
/// is destroyed. Returns null if the variant is not Succeeded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_succeeded_connection(
    event: *const AuthEvent,
) -> *const Connection {
    if event.is_null() {
        return ptr::null();
    }
    unsafe {
        (*event)
            .succeeded_connection
            .as_ref()
            .map_or(ptr::null(), |c| c as *const Connection)
    }
}

// --- Failed accessors ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_failed_error_code(event: *const AuthEvent) -> Status {
    if event.is_null() {
        return Status::Ok;
    }
    unsafe { (*event).failed_error_code }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_auth_event_failed_error_message(
    event: *const AuthEvent,
) -> *const c_char {
    if event.is_null() {
        return ptr::null();
    }
    unsafe {
        (*event)
            .failed_error_message
            .as_ref()
            .map_or(ptr::null(), |c| c.as_ptr())
    }
}
