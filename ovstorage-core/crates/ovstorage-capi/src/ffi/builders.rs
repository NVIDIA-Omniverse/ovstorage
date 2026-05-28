// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Builder types: `ConfigValue`, `SecretValue`, `ConnectionRequest`,
//! `SecretBundle`, plus per-variant constructors / accessors /
//! destructors.
//!
//! The C surface is constructor-based: per-variant `_create_*`
//! functions return a `*mut <handle_t>`; one shared `_destroy` frees
//! it. `ConfigValue` exposes read-side accessors (`_kind` + `_as_*`).
//! `SecretValue` is write-only — credentials never flow back across
//! the C ABI.
//!
//! Ownership: when these handles are added to a `ConnectionRequest`
//! via `_add_config` / `_add_credential`, the caller's `*mut`
//! becomes invalid on success (the request consumes the handle). On
//! failure the caller still owns it and must `_destroy`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::time::{Duration, UNIX_EPOCH};

use ovstorage::SecretBytes;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigValueKind {
    String = 0,
    Int = 1,
    Bool = 2,
    /// Reserialized TOML payload (a nested table or array of tables).
    /// The plugin reading the value parses the string with its own
    /// TOML deserializer.
    Toml = 3,
}

/// Opaque config-value handle. Built via `ovstorage_config_value_create_*`;
/// freed via `ovstorage_config_value_destroy` (or consumed by
/// `ovstorage_connection_request_add_config`).
pub struct ConfigValue {
    /// `Some` until consumed by `connection_request_add_config`; once
    /// the request takes the value, accessors observe the empty state.
    pub(crate) inner: Option<ovstorage::ConfigValue>,
    /// Stable CString backing for `_as_string` / `_as_toml` accessors;
    /// `None` for Int/Bool variants.
    string_cache: Option<CString>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_create_string(
    value: *const c_char,
) -> *mut ConfigValue {
    unsafe {
        if value.is_null() {
            return ptr::null_mut();
        }
        let Ok(s) = CStr::from_ptr(value).to_str() else {
            return ptr::null_mut();
        };
        let owned = s.to_string();
        let cached = CString::new(owned.clone()).unwrap_or_default();
        Box::into_raw(Box::new(ConfigValue {
            inner: Some(ovstorage::ConfigValue::String(owned)),
            string_cache: Some(cached),
        }))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_create_int(value: i64) -> *mut ConfigValue {
    Box::into_raw(Box::new(ConfigValue {
        inner: Some(ovstorage::ConfigValue::Int(value)),
        string_cache: None,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_create_bool(value: bool) -> *mut ConfigValue {
    Box::into_raw(Box::new(ConfigValue {
        inner: Some(ovstorage::ConfigValue::Bool(value)),
        string_cache: None,
    }))
}

/// Build a Toml-variant `ConfigValue` from a TOML-formatted string.
/// Used to carry nested tables / arrays of tables across the ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_create_toml(
    toml: *const c_char,
) -> *mut ConfigValue {
    unsafe {
        if toml.is_null() {
            return ptr::null_mut();
        }
        let Ok(s) = CStr::from_ptr(toml).to_str() else {
            return ptr::null_mut();
        };
        let owned = s.to_string();
        let cached = CString::new(owned.clone()).unwrap_or_default();
        Box::into_raw(Box::new(ConfigValue {
            inner: Some(ovstorage::ConfigValue::Toml(owned)),
            string_cache: Some(cached),
        }))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_destroy(value: *mut ConfigValue) {
    unsafe {
        if value.is_null() {
            return;
        }
        drop(Box::from_raw(value));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_kind(value: *const ConfigValue) -> ConfigValueKind {
    unsafe {
        if value.is_null() {
            return ConfigValueKind::String;
        }
        let inner = (*value).inner.as_ref();
        match inner {
            Some(ovstorage::ConfigValue::String(_)) => ConfigValueKind::String,
            Some(ovstorage::ConfigValue::Int(_)) => ConfigValueKind::Int,
            Some(ovstorage::ConfigValue::Bool(_)) => ConfigValueKind::Bool,
            Some(ovstorage::ConfigValue::Toml(_)) => ConfigValueKind::Toml,
            // Already-consumed handle: pick a canonical answer rather
            // than panic across the FFI boundary.
            None => ConfigValueKind::String,
        }
    }
}

/// Returns a borrowed `*const c_char` that is valid until the handle
/// is destroyed. Returns null if the variant is not String or the
/// handle is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_as_string(
    value: *const ConfigValue,
) -> *const c_char {
    unsafe {
        if value.is_null() {
            return ptr::null();
        }
        match (*value).inner.as_ref() {
            Some(ovstorage::ConfigValue::String(_)) => (*value)
                .string_cache
                .as_ref()
                .map_or(ptr::null(), |c| c.as_ptr()),
            _ => ptr::null(),
        }
    }
}

/// Returns the inner i64. Returns 0 if the variant is not Int or the
/// handle is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_as_int(value: *const ConfigValue) -> i64 {
    unsafe {
        if value.is_null() {
            return 0;
        }
        match (*value).inner.as_ref() {
            Some(ovstorage::ConfigValue::Int(n)) => *n,
            _ => 0,
        }
    }
}

/// Returns the inner bool. Returns false if the variant is not Bool
/// or the handle is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_as_bool(value: *const ConfigValue) -> bool {
    unsafe {
        if value.is_null() {
            return false;
        }
        match (*value).inner.as_ref() {
            Some(ovstorage::ConfigValue::Bool(b)) => *b,
            _ => false,
        }
    }
}

/// Returns a borrowed `*const c_char` pointing at the reserialized TOML
/// payload, valid until the handle is destroyed. Returns null if the
/// variant is not Toml or the handle is null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_config_value_as_toml(
    value: *const ConfigValue,
) -> *const c_char {
    unsafe {
        if value.is_null() {
            return ptr::null();
        }
        match (*value).inner.as_ref() {
            Some(ovstorage::ConfigValue::Toml(_)) => (*value)
                .string_cache
                .as_ref()
                .map_or(ptr::null(), |c| c.as_ptr()),
            _ => ptr::null(),
        }
    }
}

/// Consume a `ConfigValue` handle and take the inner value. Returns
/// `None` if `ptr` is null or the handle was already consumed.
pub(crate) unsafe fn take_config_value(ptr: *mut ConfigValue) -> Option<ovstorage::ConfigValue> {
    unsafe {
        if ptr.is_null() {
            return None;
        }
        let mut handle = Box::from_raw(ptr);
        handle.inner.take()
    }
}

// ---------------------------------------------------------------------
// SecretValue
// ---------------------------------------------------------------------

/// Opaque secret-value handle. Write-only — secrets never flow back
/// out across the C ABI.
///
/// All `_create_*` constructors copy the input bytes into a host-owned
/// zero-on-drop buffer; the caller may free input pointers as soon as
/// the constructor returns.
pub struct SecretValue {
    pub(crate) inner: Option<ovstorage::SecretValue>,
}

fn copy_secret_bytes(data: *const u8, len: usize) -> SecretBytes {
    if data.is_null() || len == 0 {
        return SecretBytes(Vec::new());
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    SecretBytes(slice.to_vec())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_value_create_bytes(
    data: *const u8,
    len: usize,
) -> *mut SecretValue {
    let bytes = copy_secret_bytes(data, len);
    Box::into_raw(Box::new(SecretValue {
        inner: Some(ovstorage::SecretValue::Bytes(bytes)),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_value_create_file(
    data: *const u8,
    len: usize,
) -> *mut SecretValue {
    let bytes = copy_secret_bytes(data, len);
    Box::into_raw(Box::new(SecretValue {
        inner: Some(ovstorage::SecretValue::File(bytes)),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_value_create_oauth_token(
    token: *const u8,
    token_len: usize,
    refresh: *const u8,
    refresh_len: usize,
    has_refresh: bool,
    expires_at_unix_nanos: u64,
    has_expires_at: bool,
) -> *mut SecretValue {
    let token_bytes = copy_secret_bytes(token, token_len);
    let refresh_bytes = if has_refresh {
        Some(copy_secret_bytes(refresh, refresh_len))
    } else {
        None
    };
    let expires_at = if has_expires_at {
        Some(UNIX_EPOCH + Duration::from_nanos(expires_at_unix_nanos))
    } else {
        None
    };
    Box::into_raw(Box::new(SecretValue {
        inner: Some(ovstorage::SecretValue::OAuthToken {
            token: token_bytes,
            refresh: refresh_bytes,
            expires_at,
        }),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_value_create_mtls_cert_pair(
    cert_pem: *const u8,
    cert_len: usize,
    key_pem: *const u8,
    key_len: usize,
) -> *mut SecretValue {
    let cert = copy_secret_bytes(cert_pem, cert_len);
    let key = copy_secret_bytes(key_pem, key_len);
    Box::into_raw(Box::new(SecretValue {
        inner: Some(ovstorage::SecretValue::MtlsCertPair {
            cert_pem: cert,
            key_pem: key,
        }),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_value_create_system_identity() -> *mut SecretValue {
    Box::into_raw(Box::new(SecretValue {
        inner: Some(ovstorage::SecretValue::SystemIdentity),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_value_destroy(value: *mut SecretValue) {
    unsafe {
        if value.is_null() {
            return;
        }
        drop(Box::from_raw(value));
    }
}

/// Consume a `SecretValue` handle and take the inner value. Returns
/// `None` if `ptr` is null or the handle was already consumed.
pub(crate) unsafe fn take_secret_value(ptr: *mut SecretValue) -> Option<ovstorage::SecretValue> {
    unsafe {
        if ptr.is_null() {
            return None;
        }
        let mut handle = Box::from_raw(ptr);
        handle.inner.take()
    }
}

// ---------------------------------------------------------------------
// ConnectionRequest builder
// ---------------------------------------------------------------------

/// Opaque connection-request builder. Built with
/// `ovstorage_connection_request_create` + per-field setters;
/// consumed by `ovstorage_library_add_connection`. On success the
/// caller's `*mut` is invalidated; on a prologue error the caller
/// still owns it and must free with
/// `ovstorage_connection_request_destroy`.
pub struct ConnectionRequest {
    pub(crate) inner: Option<ovstorage::ConnectionRequest>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_request_create(
    backend_kind: *const c_char,
) -> *mut ConnectionRequest {
    unsafe {
        if backend_kind.is_null() {
            return ptr::null_mut();
        }
        let Ok(kind) = CStr::from_ptr(backend_kind).to_str() else {
            return ptr::null_mut();
        };
        Box::into_raw(Box::new(ConnectionRequest {
            inner: Some(ovstorage::ConnectionRequest {
                backend_kind: kind.to_string(),
                config: HashMap::new(),
                credentials: ovstorage::SecretBundle::default(),
                persist: false,
                display_name: None,
            }),
        }))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_request_destroy(request: *mut ConnectionRequest) {
    unsafe {
        if request.is_null() {
            return;
        }
        drop(Box::from_raw(request));
    }
}

/// Set the request's display name. Pass `NULL` to clear.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_request_set_display_name(
    request: *mut ConnectionRequest,
    display_name: *const c_char,
) {
    unsafe {
        if request.is_null() {
            return;
        }
        let Some(inner) = (*request).inner.as_mut() else {
            return;
        };
        if display_name.is_null() {
            inner.display_name = None;
        } else if let Ok(s) = CStr::from_ptr(display_name).to_str() {
            inner.display_name = Some(s.to_string());
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_request_set_persist(
    request: *mut ConnectionRequest,
    persist: bool,
) {
    unsafe {
        if request.is_null() {
            return;
        }
        if let Some(inner) = (*request).inner.as_mut() {
            inner.persist = persist;
        }
    }
}

/// Add a config entry to the request. On success, the request takes
/// ownership of `value` and the caller's `*value` is invalidated. On
/// failure (null arg, non-UTF-8 key, request already consumed), the
/// caller still owns `value` and must `_destroy` it.
///
/// Returns `true` on success, `false` on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_request_add_config(
    request: *mut ConnectionRequest,
    key: *const c_char,
    value: *mut ConfigValue,
) -> bool {
    unsafe {
        if request.is_null() || key.is_null() || value.is_null() {
            return false;
        }
        let Ok(key_str) = CStr::from_ptr(key).to_str() else {
            return false;
        };
        let Some(inner) = (*request).inner.as_mut() else {
            return false;
        };
        // From this point the caller's `value` pointer is invalid
        // regardless of outcome — the only failure path here is an
        // already-consumed handle, which means it was stale anyway.
        let Some(cv) = take_config_value(value) else {
            return false;
        };
        inner.config.insert(key_str.to_string(), cv);
        true
    }
}

/// Add a credential entry to the request. On success, the request
/// takes ownership of `value` and the caller's `*value` is invalidated.
/// On failure (null arg, non-UTF-8 key, request already consumed), the
/// caller still owns `value` and must `_destroy` it.
///
/// Returns `true` on success, `false` on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_connection_request_add_credential(
    request: *mut ConnectionRequest,
    key: *const c_char,
    value: *mut SecretValue,
) -> bool {
    unsafe {
        if request.is_null() || key.is_null() || value.is_null() {
            return false;
        }
        let Ok(key_str) = CStr::from_ptr(key).to_str() else {
            return false;
        };
        let Some(inner) = (*request).inner.as_mut() else {
            return false;
        };
        let Some(sv) = take_secret_value(value) else {
            return false;
        };
        inner.credentials.fields.insert(key_str.to_string(), sv);
        true
    }
}

/// Consume a `ConnectionRequest` handle and take the inner value.
/// Returns `None` if `ptr` is null or the handle was already consumed.
pub(crate) unsafe fn take_connection_request(
    ptr: *mut ConnectionRequest,
) -> Option<ovstorage::ConnectionRequest> {
    unsafe {
        if ptr.is_null() {
            return None;
        }
        let mut handle = Box::from_raw(ptr);
        handle.inner.take()
    }
}

// ---------------------------------------------------------------------
// SecretBundle builder for update_connection_credentials.
// ---------------------------------------------------------------------

/// Opaque secret-bundle handle used by
/// `ovstorage_library_update_connection_credentials` to refresh an
/// existing connection's credentials.
///
/// On success the bundle is consumed; on a prologue error the caller
/// still owns it and must free with `ovstorage_secret_bundle_destroy`.
pub struct SecretBundle {
    pub(crate) inner: Option<ovstorage::SecretBundle>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_bundle_create() -> *mut SecretBundle {
    Box::into_raw(Box::new(SecretBundle {
        inner: Some(ovstorage::SecretBundle::default()),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_bundle_destroy(bundle: *mut SecretBundle) {
    unsafe {
        if bundle.is_null() {
            return;
        }
        drop(Box::from_raw(bundle));
    }
}

/// Add a credential entry to the bundle. On success, the bundle takes
/// ownership of `value` and the caller's `*value` is invalidated. On
/// failure (null arg, non-UTF-8 key, bundle already consumed), the
/// caller still owns `value` and must `_destroy` it.
///
/// Returns `true` on success, `false` on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_secret_bundle_add(
    bundle: *mut SecretBundle,
    key: *const c_char,
    value: *mut SecretValue,
) -> bool {
    unsafe {
        if bundle.is_null() || key.is_null() || value.is_null() {
            return false;
        }
        let Ok(key_str) = CStr::from_ptr(key).to_str() else {
            return false;
        };
        let Some(inner) = (*bundle).inner.as_mut() else {
            return false;
        };
        let Some(sv) = take_secret_value(value) else {
            return false;
        };
        inner.fields.insert(key_str.to_string(), sv);
        true
    }
}

/// Consume a `SecretBundle` handle and take the inner value. Returns
/// `None` if `ptr` is null or the handle was already consumed.
pub(crate) unsafe fn take_secret_bundle(ptr: *mut SecretBundle) -> Option<ovstorage::SecretBundle> {
    unsafe {
        if ptr.is_null() {
            return None;
        }
        let mut handle = Box::from_raw(ptr);
        handle.inner.take()
    }
}
