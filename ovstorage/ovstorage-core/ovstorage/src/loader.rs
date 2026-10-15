// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host callback substrate shared by loaded ABI-v2 plugins.

use std::ptr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ovstorage_plugin::{ConnectionId, Error, ErrorCode, Result, ffi, marshal};
use tracing::{debug_span, error, info};

use crate::auth::{
    AuthRefreshLock, AuthRefreshSnapshot, RefreshOutcome, RefreshRecord, SecretStore,
};

/// Long-lived state shared by every plugin loaded in the process.
/// Each plugin's `ffi::HostCallbacks::host_state` points at an `Arc` of
/// this.
pub(crate) struct HostCallbacksProvider {
    pub secret_store: Arc<dyn SecretStore>,
    pub refresh_lock: Arc<AuthRefreshLock>,
}

impl HostCallbacksProvider {
    pub fn new(
        secret_store: Arc<dyn SecretStore>,
        refresh_lock: Arc<AuthRefreshLock>,
    ) -> Arc<Self> {
        Arc::new(Self {
            secret_store,
            refresh_lock,
        })
    }
}

pub(crate) struct HostCallbacksState {
    pub(crate) provider: Arc<HostCallbacksProvider>,
}

/// Process-global host registration. The plugin SPI's
/// `ovstorage_plugin_init_v1` is set-once-per-process — plugins stash
/// the host pointer and assume it stays valid for the cdylib's
/// lifetime. Multiple Stack builds in one process share one
/// substrate; conflicting substrates fail with `Unsupported`.
struct RegisteredHost {
    provider: Arc<HostCallbacksProvider>,
    // Pinned for the static's lifetime; plugins dereference into the
    // state box from their callbacks.
    _callbacks: Box<ffi::HostCallbacks>,
    _state: Box<HostCallbacksState>,
}

// SAFETY: pointers are read-only after init; the boxes don't move
// once placed in the OnceLock.
unsafe impl Send for RegisteredHost {}
unsafe impl Sync for RegisteredHost {}

static REGISTERED: OnceLock<RegisteredHost> = OnceLock::new();

/// Read the process-global substrate, if it has been registered.
/// `crate::init_auth_substrate` is the only public entry point that
/// registers it.
pub(crate) fn substrate() -> Option<Arc<HostCallbacksProvider>> {
    REGISTERED.get().map(|r| r.provider.clone())
}

/// First call wins; same Arcs are no-ops; different Arcs return Err.
pub(crate) fn register_host_substrate(provider: Arc<HostCallbacksProvider>) -> Result<()> {
    let mut newly_registered = false;
    let existing = REGISTERED.get_or_init(|| {
        newly_registered = true;
        let (callbacks, state) = build_host_callbacks(provider.clone(), ffi::HostKindV1::Library);
        let ptr: *const ffi::HostCallbacks = &*callbacks;
        // SAFETY: callbacks lives in the static for the process's
        // lifetime; the box's address is stable.
        unsafe {
            marshal::register_host(ptr);
        }
        RegisteredHost {
            provider: provider.clone(),
            _callbacks: callbacks,
            _state: state,
        }
    });
    if newly_registered {
        info!("host substrate registered");
    }
    if Arc::ptr_eq(&existing.provider, &provider)
        || (Arc::ptr_eq(&existing.provider.secret_store, &provider.secret_store)
            && Arc::ptr_eq(&existing.provider.refresh_lock, &provider.refresh_lock))
    {
        Ok(())
    } else {
        error!(error.code = ?ErrorCode::Unsupported, "host substrate conflict: a different SecretStore/AuthRefreshLock pair was already registered");
        Err(Error::new(
            ErrorCode::Unsupported,
            "ovstorage host callbacks are process-global (plugin SPI \
             registers them set-once-per-process); a different \
             SecretStore + AuthRefreshLock pair has already been \
             registered. Reuse the existing substrate or run the \
             second Stack host in a separate process.",
        ))
    }
}

/// Returned boxes must outlive any raw pointer derived from them.
pub(crate) fn build_host_callbacks(
    provider: Arc<HostCallbacksProvider>,
    host_kind: ffi::HostKindV1,
) -> (Box<ffi::HostCallbacks>, Box<HostCallbacksState>) {
    let mut state = Box::new(HostCallbacksState { provider });
    let callbacks = Box::new(ffi::HostCallbacks {
        struct_size: std::mem::size_of::<ffi::HostCallbacks>(),
        host_state: &mut *state as *mut HostCallbacksState as *mut core::ffi::c_void,
        secret_get: host_secret_get,
        secret_put: host_secret_put,
        secret_delete: host_secret_delete,
        auth_refresh_lock_with_refresh: host_auth_refresh_lock_with_refresh,
        host_kind: host_kind as u32,
        log: host_log,
    });
    (callbacks, state)
}

/// Forwards one plugin event into the host's logging pipeline. Routed
/// through `log::log!` (not `tracing::event!`) because the plugin's
/// target is only known at runtime, and `tracing::event!`'s `target:`
/// requires a const expression. `tracing-log::LogTracer` (installed by
/// `tracing_init::init_tracing`) translates the log record into a
/// tracing event whose metadata target IS the plugin's runtime target,
/// so `RUST_LOG=ovstorage_plugin_nucleus=trace` filters work normally.
unsafe extern "C" fn host_log(
    _state: *mut core::ffi::c_void,
    level: u8,
    target: *const ffi::Str,
    message: *const ffi::Str,
) {
    unsafe {
        let target = read_log_str(target);
        let message = read_log_str(message);
        let target_ref = target.as_deref().unwrap_or("plugin");
        let message_ref = message
            .as_deref()
            .unwrap_or("<plugin emitted unreadable log message>");
        let log_level = match level {
            x if x == ffi::LogLevelV1::Trace as u8 => log::Level::Trace,
            x if x == ffi::LogLevelV1::Debug as u8 => log::Level::Debug,
            x if x == ffi::LogLevelV1::Warn as u8 => log::Level::Warn,
            x if x == ffi::LogLevelV1::Error as u8 => log::Level::Error,
            // Info plus any unknown future level falls through here.
            _ => log::Level::Info,
        };
        log::log!(target: target_ref, log_level, "{message_ref}");
    }
}

/// Read a borrowed plugin-supplied UTF-8 string. Returns `None` for null
/// pointer or non-UTF-8 bytes; the host then substitutes a placeholder
/// rather than dropping the event.
unsafe fn read_log_str(value: *const ffi::Str) -> Option<String> {
    unsafe {
        if value.is_null() {
            return None;
        }
        let s = &*value;
        if s.ptr.is_null() {
            return None;
        }
        let bytes = std::slice::from_raw_parts(s.ptr as *const u8, s.len);
        std::str::from_utf8(bytes).ok().map(str::to_string)
    }
}

unsafe extern "C" fn host_secret_get(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
    out_value: *mut ffi::Optional<ffi::SecretBytes>,
) -> *mut ffi::Error {
    let span = debug_span!("host.secret_get");
    let _enter = span.enter();
    unsafe {
        let result = (|| -> Result<()> {
            let provider = host_provider(state)?;
            let key = read_secret_key(key)?;
            match provider
                .secret_store
                .get(&key.backend_kind, &key.connection_id.0, &key.field)?
            {
                Some(bytes) => {
                    let ffi_bytes = marshal::descriptor::secret_bytes_to_ffi(bytes);
                    ptr::write(out_value, ffi::Optional::some(ffi_bytes));
                }
                None => {
                    ptr::write(out_value, ffi::Optional::none());
                }
            }
            Ok(())
        })();
        error_into_raw(result)
    }
}

unsafe extern "C" fn host_secret_put(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
    value: *const ffi::SecretBytes,
) -> *mut ffi::Error {
    let span = debug_span!("host.secret_put");
    let _enter = span.enter();
    unsafe {
        let result = (|| -> Result<()> {
            let provider = host_provider(state)?;
            let key = read_secret_key(key)?;
            if value.is_null() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "secret_put: value pointer is null",
                ));
            }
            let bytes_slice =
                std::slice::from_raw_parts((*value).bytes.ptr as *const u8, (*value).bytes.len);
            let secret = ovstorage_plugin::SecretBytes(bytes_slice.to_vec());
            provider
                .secret_store
                .put(&key.backend_kind, &key.connection_id.0, &key.field, &secret)
        })();
        error_into_raw(result)
    }
}

unsafe extern "C" fn host_secret_delete(
    state: *mut core::ffi::c_void,
    key: *const ffi::SecretKey,
) -> *mut ffi::Error {
    let span = debug_span!("host.secret_delete");
    let _enter = span.enter();
    unsafe {
        let result = (|| -> Result<()> {
            let provider = host_provider(state)?;
            let key = read_secret_key(key)?;
            provider
                .secret_store
                .delete(&key.backend_kind, &key.connection_id.0, &key.field)
        })();
        error_into_raw(result)
    }
}

unsafe extern "C" fn host_auth_refresh_lock_with_refresh(
    state: *mut core::ffi::c_void,
    backend_kind: *const ffi::Str,
    connection_id: *const ffi::ConnectionId,
    freshness_window_ms: u64,
    refresh_state: *mut core::ffi::c_void,
    refresh_fn: ffi::HostRefreshFn,
) -> *mut ffi::Error {
    let span = debug_span!("host.auth_refresh_lock");
    let _enter = span.enter();
    unsafe {
        let result = (|| -> Result<()> {
            let provider = host_provider(state)?;
            if backend_kind.is_null() || connection_id.is_null() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "auth_refresh_lock_with_refresh: backend_kind/connection_id is null",
                ));
            }
            let backend_kind = borrow_str(&*backend_kind, "backend_kind")?;
            let connection_id_str = borrow_str(&(*connection_id).id, "connection_id")?;
            let window = Duration::from_millis(freshness_window_ms);
            let outcome = provider.refresh_lock.with_refresh::<()>(
                backend_kind,
                connection_id_str,
                window,
                || {
                    let err_ptr = refresh_fn(refresh_state);
                    if err_ptr.is_null() {
                        Ok(RefreshRecord {
                            value: (),
                            snapshot: AuthRefreshSnapshot {
                                refreshed_unix_ms: unix_ms(),
                                expires_at_unix_ms: None,
                            },
                        })
                    } else {
                        Err(marshal::error::from_ffi(ffi::abi_alloc::abi_unbox(err_ptr)))
                    }
                },
            )?;
            // Both Refreshed(()) and Skipped(_) signal success to the plugin.
            match outcome {
                RefreshOutcome::Refreshed(()) => (),
                RefreshOutcome::Skipped(_) => (),
            };
            Ok(())
        })();
        error_into_raw(result)
    }
}

unsafe fn host_provider(state: *mut core::ffi::c_void) -> Result<Arc<HostCallbacksProvider>> {
    unsafe {
        if state.is_null() {
            return Err(Error::new(
                ErrorCode::Internal,
                "host callback invoked with null host_state",
            ));
        }
        let state = &*(state as *const HostCallbacksState);
        Ok(Arc::clone(&state.provider))
    }
}

struct DecodedKey {
    backend_kind: String,
    connection_id: ConnectionId,
    field: String,
}

unsafe fn read_secret_key(key: *const ffi::SecretKey) -> Result<DecodedKey> {
    unsafe {
        if key.is_null() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "keyring callback: key pointer is null",
            ));
        }
        let key = &*key;
        let backend_kind = borrow_str(&key.backend_kind, "backend_kind")?.to_owned();
        let connection_id = borrow_str(&key.connection_id.id, "connection_id")?.to_owned();
        let field = borrow_str(&key.field, "field")?.to_owned();
        if connection_id.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "connection id must not be empty",
            ));
        }
        Ok(DecodedKey {
            backend_kind,
            connection_id: ConnectionId(connection_id),
            field,
        })
    }
}

unsafe fn borrow_str<'a>(value: &'a ffi::Str, field: &str) -> Result<&'a str> {
    unsafe {
        if value.ptr.is_null() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{field} is null"),
            ));
        }
        let bytes = std::slice::from_raw_parts(value.ptr as *const u8, value.len);
        std::str::from_utf8(bytes)
            .map_err(|_| Error::new(ErrorCode::InvalidArgument, format!("{field} is not UTF-8")))
    }
}

fn error_into_raw(result: Result<()>) -> *mut ffi::Error {
    match result {
        Ok(()) => ptr::null_mut(),
        Err(error) => ffi::abi_alloc::abi_box(marshal::error::to_ffi(&error)),
    }
}

fn unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}
