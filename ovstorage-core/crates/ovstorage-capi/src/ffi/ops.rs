// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async I/O thunks for the C ABI.
//!
//! Every `ovstorage_<op>` function follows the same four-step shape:
//!
//! 1. NULL callback → return immediately (nothing to surface to).
//! 2. NULL library → fire the supplied callback with
//!    `InvalidArgument` inline, because no library runtime exists to
//!    dispatch on.
//! 3. Synchronously parse all caller-owned inputs (address strings,
//!    options structs) before spawning — those pointers are not
//!    guaranteed valid past return.
//! 4. `runtime.spawn` the work, wrap in `catch_unwind` (panics
//!    become `ErrorCode::Internal`), and fire the per-shape `fire_*`
//!    helper.
//!
//! Each `fire_*` helper handles one callback shape because
//! `extern "C" fn` cannot capture state. All helpers free any
//! borrowed `Error` message before returning.

use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use futures::FutureExt;

use ovstorage::{Body, CopyOptions, DeleteOptions, ErrorCode, ObjectInfo, RenameOptions, Storage};

use super::*;

/// `Send`-able wrapper around the opaque `user_data` pointer the
/// caller hands every async op. The C caller is responsible for
/// ensuring whatever lives behind the pointer is safe to touch from
/// a worker thread.
#[derive(Clone, Copy)]
pub(crate) struct UserData(pub(crate) *mut c_void);

unsafe impl Send for UserData {}

fn null_library_error(fn_name: &str) -> ovstorage::Error {
    null_library_warn(fn_name);
    ovstorage::Error::new(
        ErrorCode::InvalidArgument,
        format!("{fn_name}: library pointer is null"),
    )
}

macro_rules! require_library {
    ($library:expr, $callback:expr, $user_data:expr, $fn_name:literal, result $fire:ident) => {{
        match unsafe { $library.as_ref() } {
            Some(l) => l,
            None => {
                unsafe { $fire($callback, $user_data, Err(null_library_error($fn_name))) };
                return;
            }
        }
    }};
    ($library:expr, $callback:expr, $user_data:expr, $fn_name:literal, error $fire:ident) => {{
        match unsafe { $library.as_ref() } {
            Some(l) => l,
            None => {
                unsafe { $fire($callback, $user_data, null_library_error($fn_name)) };
                return;
            }
        }
    }};
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_stat(
    library: *mut Library,
    address: *const c_char,
    options: *const StatOptionsV1,
    cancel: *const CancelToken,
    on_complete: InfoCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library =
        require_library!(library, callback, user_data, "ovstorage_stat", result fire_info);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { stat_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            inner.stat(address, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_info(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_read_bytes(
    library: *mut Library,
    address: *const c_char,
    options: *const ReadOptionsV1,
    cancel: *const CancelToken,
    on_complete: ReadBytesCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_read_bytes", result fire_read_bytes);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { read_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            inner.read_bytes(address, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_read_bytes(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_read_stream(
    library: *mut Library,
    address: *const c_char,
    options: *const ReadOptionsV1,
    cancel: *const CancelToken,
    on_complete: ReadStreamCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_read_stream", error fire_stream_error);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { read_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let (address, opts, cancel_token) = match parsed {
            Ok(v) => v,
            Err(error) => {
                unsafe { fire_stream_error(callback, user_data, error) };
                return;
            }
        };
        let result = AssertUnwindSafe(async {
            inner.read_stream(address, opts, cancel_token.clone()).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        match result {
            Err(error) => unsafe { fire_stream_error(callback, user_data, error) },
            Ok((mut stream, _info)) => {
                use futures::StreamExt;
                let mut iter_error: Option<ovstorage::Error> = None;
                while let Some(chunk) = stream.next().await {
                    if cancel_token
                        .as_ref()
                        .map(|t| t.is_cancelled())
                        .unwrap_or(false)
                    {
                        iter_error = Some(ovstorage::Error::new(
                            ErrorCode::Cancelled,
                            "cancelled by caller",
                        ));
                        break;
                    }
                    match chunk {
                        Ok(bytes) => {
                            let chunk = bytes_handle(bytes.to_vec());
                            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                                callback(chunk, ptr::null(), false, user_data.0);
                            }));
                        }
                        Err(error) => {
                            iter_error = Some(error);
                            break;
                        }
                    }
                }
                match iter_error {
                    Some(error) => unsafe { fire_stream_error(callback, user_data, error) },
                    None => {
                        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                            callback(empty_bytes(), ptr::null(), true, user_data.0);
                        }));
                    }
                }
            }
        }
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_read_local_file(
    library: *mut Library,
    address: *const c_char,
    options: *const ReadOptionsV1,
    cancel: *const CancelToken,
    on_complete: ReadLocalFileCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_read_local_file", result fire_local_delegate);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { read_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            inner.materialize(address, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_local_delegate(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_write(
    library: *mut Library,
    address: *const c_char,
    data: *const u8,
    len: usize,
    options: *const WriteOptionsV1,
    cancel: *const CancelToken,
    on_complete: InfoCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library =
        require_library!(library, callback, user_data, "ovstorage_write", result fire_info);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    // Body bytes copied synchronously — caller may reuse the buffer
    // as soon as this function returns.
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        if data.is_null() && len != 0 {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                "data must not be null when len is nonzero",
            ));
        }
        let body = if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
        };
        let opts = unsafe { write_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, body, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, body, opts, cancel_token) = parsed?;
            inner
                .write(address, Body::Bytes(body), opts, cancel_token)
                .await
                .map(|result| result.info)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_info(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_delete(
    library: *mut Library,
    address: *const c_char,
    cancel: *const CancelToken,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library =
        require_library!(library, callback, user_data, "ovstorage_delete", result fire_status);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, cancel_token) = parsed?;
            inner
                .delete(address, DeleteOptions::default(), cancel_token)
                .await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list(
    library: *mut Library,
    prefix: *const c_char,
    options: *const ListOptionsV1,
    cancel: *const CancelToken,
    on_complete: ListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library =
        require_library!(library, callback, user_data, "ovstorage_list", result fire_list);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let prefix = unsafe { parse_address(prefix) }?;
        let opts = unsafe { list_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((prefix, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (prefix, opts, cancel_token) = parsed?;
            inner.list_page(prefix, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_list(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_list_versions(
    library: *mut Library,
    address: *const c_char,
    options: *const ListVersionsOptionsV1,
    cancel: *const CancelToken,
    on_complete: ListVersionsCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_list_versions", result fire_list_versions);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { list_versions_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            let backend_options = opts.clone();
            inner
                .list_versions(address, backend_options, cancel_token)
                .await
                .and_then(|items| paginate_versions(items, opts.max_results, opts.page_token))
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_list_versions(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_copy(
    library: *mut Library,
    src: *const c_char,
    dest: *const c_char,
    cancel: *const CancelToken,
    on_complete: InfoCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library =
        require_library!(library, callback, user_data, "ovstorage_copy", result fire_info);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let src = unsafe { parse_address(src) }?;
        let dest = unsafe { parse_address(dest) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((src, dest, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (src, dest, cancel_token) = parsed?;
            inner
                .copy(src, dest, CopyOptions::default(), cancel_token)
                .await
                .map(|result| result.info)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_info(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_rename(
    library: *mut Library,
    src: *const c_char,
    dest: *const c_char,
    cancel: *const CancelToken,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library =
        require_library!(library, callback, user_data, "ovstorage_rename", result fire_status);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let src = unsafe { parse_address(src) }?;
        let dest = unsafe { parse_address(dest) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((src, dest, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (src, dest, cancel_token) = parsed?;
            inner
                .rename(src, dest, RenameOptions::default(), cancel_token)
                .await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_create_directory(
    library: *mut Library,
    address: *const c_char,
    options: *const CreateDirectoryOptionsV1,
    cancel: *const CancelToken,
    on_complete: InfoCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_create_directory", result fire_info);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { create_directory_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            inner.create_directory(address, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_info(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_delete_directory(
    library: *mut Library,
    address: *const c_char,
    options: *const DeleteDirectoryOptionsV1,
    cancel: *const CancelToken,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_delete_directory", result fire_status);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let opts = unsafe { delete_directory_options(options) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, opts, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            inner.delete_directory(address, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_update_metadata(
    library: *mut Library,
    address: *const c_char,
    options: *const UpdateMetadataOptions,
    cancel: *const CancelToken,
    on_complete: InfoCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_update_metadata", result fire_info);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let ffi_options = unsafe { required_ref(options, "options") }?;
        let mut rust_options = ovstorage::UpdateMetadataOptions::default();
        for (key, value) in &ffi_options.set {
            rust_options
                .user_metadata_set
                .insert(key.clone(), value.clone());
        }
        rust_options.user_metadata_remove = ffi_options.remove.clone();
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, rust_options, cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, opts, cancel_token) = parsed?;
            inner.update_metadata(address, opts, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_info(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_check_access(
    library: *mut Library,
    address: *const c_char,
    ops: AccessOps,
    cancel: *const CancelToken,
    on_complete: CheckAccessCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_check_access", result fire_check_access);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<_> = (|| {
        let address = unsafe { parse_address(address) }?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((address, access_ops(ops), cancel_token))
    })();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (address, ops, cancel_token) = parsed?;
            inner.check_access(address, ops, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_check_access(callback, user_data, outcome) };
    });
}

/// Register a new connection on the library. The result is delivered
/// through `on_complete` as a `*mut Connection` the caller owns and
/// must free with `ovstorage_connection_destroy`.
///
/// Ownership rules for `request`:
/// - On a prologue validation error (null library, null/already-
///   consumed request), `*request` is NOT consumed — the caller
///   still owns it and must free with
///   `ovstorage_connection_request_destroy` (or fix and retry).
/// - On any other path (callback fires with success or with a
///   library-side error), the request was passed to the library and
///   is consumed; the caller must NOT call `_destroy` on it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_add_connection(
    library: *mut Library,
    request: *mut ConnectionRequest,
    cancel: *const CancelToken,
    on_complete: ConnectionCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_add_connection", result fire_connection);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();

    // Validate without consuming so callers can retry on prologue
    // errors without losing their request handle.
    let prologue_ok = unsafe { request.as_ref() }
        .map(|r| r.inner.is_some())
        .unwrap_or(false);

    let parsed: ovstorage::Result<(
        ovstorage::ConnectionRequest,
        Option<ovstorage::CancellationToken>,
    )> = if prologue_ok {
        let req = unsafe { crate::take_connection_request(request) }.expect("validated above");
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((req, cancel_token))
    } else {
        Err(ovstorage::Error::new(
            ErrorCode::InvalidArgument,
            "ovstorage_library_add_connection: request is null or already consumed",
        ))
    };

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (req, cancel_token) = parsed?;
            inner.add_connection(req, cancel_token).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_connection(callback, user_data, outcome) };
    });
}

/// List all connections registered on the library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_list_connections(
    library: *mut Library,
    cancel: *const CancelToken,
    on_complete: ConnectionListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_list_connections", result fire_connection_list);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    // `cancel` has no effect today — accepted for surface uniformity.
    let _ = unsafe { cancel.as_ref() };
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move { inner.list_connections() })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_connection_list(callback, user_data, outcome) };
    });
}

/// Load and register a single plugin cdylib at `path` (UTF-8 nul-terminated).
/// Idempotent — re-registering an already-known backend kind replaces the
/// prior factory entry.
///
/// # Safety
///
/// `dlopen` runs platform loader hooks; `path` must point to a trusted
/// plugin file.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_load_plugin(
    library: *mut Library,
    path: *const c_char,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_load_plugin", result fire_status);
    let path_str = match unsafe { super::cstr_to_string(path, "path") } {
        Ok(s) => s,
        Err(error) => {
            unsafe { fire_status(callback, user_data, Err(error)) };
            return;
        }
    };
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            // SAFETY: dlopen-trust contract documented on the C function.
            unsafe { inner.load_plugin(std::path::Path::new(&path_str)) }
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

/// Scan a directory for `libovstorage_plugin_*.{so,dylib,dll}` and load each.
/// `dir = NULL` resolves to `OVSTORAGE_PLUGIN_DIR` or `<exe-dir>/plugins/`.
/// A non-existent directory fires success with no plugins loaded.
///
/// # Safety
///
/// Each candidate is `dlopen`'d in-process; trust the directory contents.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_load_plugins_from_dir(
    library: *mut Library,
    dir: *const c_char,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_load_plugins_from_dir", result fire_status);
    let dir_owned: Option<String> = if dir.is_null() {
        None
    } else {
        match unsafe { super::cstr_to_string(dir, "dir") } {
            Ok(s) => Some(s),
            Err(error) => {
                unsafe { fire_status(callback, user_data, Err(error)) };
                return;
            }
        }
    };
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let dir_path = dir_owned.as_deref().map(std::path::Path::new);
            // SAFETY: dlopen-trust contract documented on the C function.
            unsafe { inner.load_plugins_from_dir(dir_path) }
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

/// Load `ovstorage.toml` and register every `[[connections]]` entry on the
/// live library. `path = NULL` uses the default search path
/// (`./ovstorage.toml` then `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`).
/// On success `on_complete` fires with the freshly registered list. No file
/// at `NULL` search path returns an empty list.
///
/// Credential refs resolve against the same `SecretStore` namespace the
/// library was initialized with, so a CLI `write-config --secrets keyring`
/// flow is picked up transparently.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_load_config(
    library: *mut Library,
    path: *const c_char,
    on_complete: ConnectionListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_load_config", result fire_connection_list);
    let path_owned: Option<String> = if path.is_null() {
        None
    } else {
        match unsafe { super::cstr_to_string(path, "path") } {
            Ok(s) => Some(s),
            Err(error) => {
                unsafe { fire_connection_list(callback, user_data, Err(error)) };
                return;
            }
        }
    };
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let cfg_path = path_owned.as_deref().map(std::path::Path::new);
            inner.load_config(cfg_path).await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_connection_list(callback, user_data, outcome) };
    });
}

/// Remove a registered connection by id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_remove_connection(
    library: *mut Library,
    connection_id: *const c_char,
    cancel: *const CancelToken,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_remove_connection", result fire_status);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let parsed: ovstorage::Result<ovstorage::ConnectionId> = (|| {
        if connection_id.is_null() {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                "connection_id is null",
            ));
        }
        let s = unsafe { CStr::from_ptr(connection_id) }
            .to_str()
            .map_err(|_| {
                ovstorage::Error::new(ErrorCode::InvalidArgument, "connection_id is not UTF-8")
            })?;
        Ok(ovstorage::ConnectionId(s.to_string()))
    })();
    let _ = unsafe { cancel.as_ref() };
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let id = parsed?;
            inner.remove_connection(&id)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

/// Refresh the credentials on an existing connection. Consumes the
/// `credentials` handle on success; on prologue error the caller
/// still owns it and must free with `ovstorage_secret_bundle_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_update_connection_credentials(
    library: *mut Library,
    connection_id: *const c_char,
    credentials: *mut SecretBundle,
    cancel: *const CancelToken,
    on_complete: ConnectionCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_update_connection_credentials", result fire_connection);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();

    // Validate without consuming so prologue errors don't strand the
    // caller's bundle handle.
    let prologue_ok = !connection_id.is_null()
        && unsafe { credentials.as_ref() }
            .map(|c| c.inner.is_some())
            .unwrap_or(false);

    let parsed: ovstorage::Result<(
        ovstorage::ConnectionId,
        ovstorage::SecretBundle,
        Option<ovstorage::CancellationToken>,
    )> = if prologue_ok {
        let s = match unsafe { CStr::from_ptr(connection_id) }.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                runtime.spawn(async move {
                    unsafe {
                        fire_connection(
                            callback,
                            user_data,
                            Err(ovstorage::Error::new(
                                ErrorCode::InvalidArgument,
                                "connection_id is not UTF-8",
                            )),
                        )
                    };
                });
                return;
            }
        };
        let bundle = unsafe { crate::take_secret_bundle(credentials) }.expect("validated above");
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((ovstorage::ConnectionId(s), bundle, cancel_token))
    } else {
        Err(ovstorage::Error::new(
            ErrorCode::InvalidArgument,
            "connection_id is null, or credentials handle is null/already consumed",
        ))
    };

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let (id, bundle, cancel_token) = parsed?;
            inner
                .update_connection_credentials(&id, bundle, cancel_token)
                .await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_connection(callback, user_data, outcome) };
    });
}

/// Drive the connection's authentication flow. The library returns
/// a stream of `AuthEvent`s; this thunk drains it and fires the
/// multi-fire callback once per event, with a final `done=true`
/// fire on end-of-stream or terminal error. Cancellation is polled
/// between events.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_authenticate_connection(
    library: *mut Library,
    connection_id: *const c_char,
    cancel: *const CancelToken,
    on_complete: AuthEventCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_authenticate_connection", error fire_auth_event_error);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();

    let parsed: ovstorage::Result<(
        ovstorage::ConnectionId,
        Option<ovstorage::CancellationToken>,
    )> = (|| {
        if connection_id.is_null() {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                "connection_id is null",
            ));
        }
        let s = unsafe { CStr::from_ptr(connection_id) }
            .to_str()
            .map_err(|_| {
                ovstorage::Error::new(ErrorCode::InvalidArgument, "connection_id is not UTF-8")
            })?;
        let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());
        Ok((ovstorage::ConnectionId(s.to_string()), cancel_token))
    })();

    runtime.spawn(async move {
        let (id, cancel_token) = match parsed {
            Ok(v) => v,
            Err(error) => {
                unsafe { fire_auth_event_error(callback, user_data, error) };
                return;
            }
        };
        let result = AssertUnwindSafe(async {
            inner
                .authenticate_connection(&id, cancel_token.clone())
                .await
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));

        match result {
            Err(error) => unsafe { fire_auth_event_error(callback, user_data, error) },
            Ok(stream) => {
                let mut iter_error: Option<ovstorage::Error> = None;
                for event_result in stream {
                    if cancel_token
                        .as_ref()
                        .map(|t| t.is_cancelled())
                        .unwrap_or(false)
                    {
                        iter_error = Some(ovstorage::Error::new(
                            ErrorCode::Cancelled,
                            "cancelled by caller",
                        ));
                        break;
                    }
                    match event_result {
                        Ok(event) => {
                            let handle =
                                Box::into_raw(Box::new(crate::AuthEvent::from_event(event)));
                            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                                callback(handle, ptr::null(), false, user_data.0);
                            }));
                        }
                        Err(error) => {
                            iter_error = Some(error);
                            break;
                        }
                    }
                }
                match iter_error {
                    Some(error) => unsafe { fire_auth_event_error(callback, user_data, error) },
                    None => {
                        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                            callback(ptr::null_mut(), ptr::null(), true, user_data.0);
                        }));
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------
// Alias surface (add / remove / list / watch)
// ---------------------------------------------------------------------

/// Add an alias to the library. Consumes the request handle on
/// success; on prologue error the caller still owns it and must
/// free with `ovstorage_alias_request_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_add_alias(
    library: *mut Library,
    request: *mut AliasRequest,
    cancel: *const CancelToken,
    on_complete: AliasCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_add_alias", result fire_alias);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };

    let prologue_ok = unsafe { request.as_ref() }
        .map(|r| r.inner.is_some())
        .unwrap_or(false);

    let parsed: ovstorage::Result<ovstorage::AliasRequest> = if prologue_ok {
        Ok(unsafe { crate::take_alias_request(request) }.expect("validated above"))
    } else {
        Err(ovstorage::Error::new(
            ErrorCode::InvalidArgument,
            "alias_request is null or already consumed",
        ))
    };

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let req = parsed?;
            inner.add_alias(req)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_alias(callback, user_data, outcome) };
    });
}

/// Remove an alias by id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_remove_alias(
    library: *mut Library,
    alias_id: *const c_char,
    cancel: *const CancelToken,
    on_complete: StatusCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_remove_alias", result fire_status);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };

    let parsed: ovstorage::Result<ovstorage::AliasId> = (|| {
        if alias_id.is_null() {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                "alias_id is null",
            ));
        }
        let s = unsafe { CStr::from_ptr(alias_id) }.to_str().map_err(|_| {
            ovstorage::Error::new(ErrorCode::InvalidArgument, "alias_id is not UTF-8")
        })?;
        Ok(ovstorage::AliasId(s.to_string()))
    })();

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let id = parsed?;
            inner.remove_alias(&id)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_status(callback, user_data, outcome) };
    });
}

/// List all aliases registered on the library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_list_aliases(
    library: *mut Library,
    cancel: *const CancelToken,
    on_complete: AliasListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_list_aliases", result fire_alias_list);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move { inner.list_aliases() })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_alias_list(callback, user_data, outcome) };
    });
}

/// Watch address-root table changes. Emits a full snapshot on subscribe
/// and after every routing-table change until cancelled or shutdown.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_watch_address_roots(
    library: *mut Library,
    cancel: *const CancelToken,
    on_complete: AddressRootWatchCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_watch_address_roots", error fire_address_root_watch_error);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let cancel_token = unsafe { cancel.as_ref() }.map(|t| t.inner.clone());

    runtime.spawn(async move {
        let cancel_for_watch = cancel_token.clone();
        let result = AssertUnwindSafe(async move { inner.watch_address_roots(cancel_for_watch) })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(panic_error()));
        match result {
            Err(error) => unsafe { fire_address_root_watch_error(callback, user_data, error) },
            Ok(stream) => {
                let mut iter_error: Option<ovstorage::Error> = None;
                for snapshot_result in stream {
                    if cancel_token
                        .as_ref()
                        .map(|t| t.is_cancelled())
                        .unwrap_or(false)
                    {
                        break;
                    }
                    match snapshot_result {
                        Ok(roots) => {
                            let handle = Box::into_raw(Box::new(crate::AddressRootList {
                                items: roots
                                    .into_iter()
                                    .map(crate::AddressRoot::from_root)
                                    .collect(),
                            }));
                            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                                callback(handle, ptr::null(), false, user_data.0);
                            }));
                        }
                        Err(error) => {
                            iter_error = Some(error);
                            break;
                        }
                    }
                }
                match iter_error {
                    Some(error) => unsafe {
                        fire_address_root_watch_error(callback, user_data, error)
                    },
                    None => {
                        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                            callback(ptr::null_mut(), ptr::null(), true, user_data.0);
                        }));
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------
// Visibility overrides + discovery
// ---------------------------------------------------------------------

/// Set or update an address-visibility override. Returns the
/// resulting `AddressVisibilityOverride` via the callback (caller
/// owns; free with `ovstorage_address_visibility_override_destroy`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_set_address_visibility(
    library: *mut Library,
    address: *const c_char,
    visibility: AddressVisibility,
    persist: bool,
    cancel: *const CancelToken,
    on_complete: AddressVisibilityOverrideCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_set_address_visibility", result fire_address_visibility_override);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };

    let parsed: ovstorage::Result<ovstorage::Url> = (|| {
        if address.is_null() {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                "address is null",
            ));
        }
        let s = unsafe { CStr::from_ptr(address) }.to_str().map_err(|_| {
            ovstorage::Error::new(ErrorCode::InvalidArgument, "address is not UTF-8")
        })?;
        ovstorage::address::parse(s)
    })();

    let visibility_rust = match visibility {
        AddressVisibility::Visible => ovstorage::AddressVisibility::Visible,
        AddressVisibility::Hidden => ovstorage::AddressVisibility::Hidden,
        AddressVisibility::Suppressed => ovstorage::AddressVisibility::Suppressed,
    };

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let url = parsed?;
            inner.set_address_visibility(url, visibility_rust, persist)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_address_visibility_override(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_list_address_visibility_overrides(
    library: *mut Library,
    cancel: *const CancelToken,
    on_complete: AddressVisibilityOverrideListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_list_address_visibility_overrides", result fire_address_visibility_override_list);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move { inner.list_address_visibility_overrides() })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_address_visibility_override_list(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_list_address_roots(
    library: *mut Library,
    cancel: *const CancelToken,
    on_complete: AddressRootListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_list_address_roots", result fire_address_root_list);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move { inner.list_address_roots() })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_address_root_list(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_list_backend_kinds(
    library: *mut Library,
    cancel: *const CancelToken,
    on_complete: BackendKindDescriptorListCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_list_backend_kinds", result fire_backend_kind_descriptor_list);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };
    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move { inner.list_backend_kinds() })
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_backend_kind_descriptor_list(callback, user_data, outcome) };
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_library_capabilities_for(
    library: *mut Library,
    prefix: *const c_char,
    cancel: *const CancelToken,
    on_complete: CapabilitiesCallback,
    user_data: *mut c_void,
) {
    let Some(callback) = on_complete else { return };
    let user_data = UserData(user_data);
    let library = require_library!(library, callback, user_data, "ovstorage_library_capabilities_for", result fire_capabilities);
    let inner = library.inner.clone();
    let runtime = library.runtime.clone();
    let _ = unsafe { cancel.as_ref() };

    let parsed: ovstorage::Result<ovstorage::Url> = (|| {
        if prefix.is_null() {
            return Err(ovstorage::Error::new(
                ErrorCode::InvalidArgument,
                "prefix is null",
            ));
        }
        let s = unsafe { CStr::from_ptr(prefix) }.to_str().map_err(|_| {
            ovstorage::Error::new(ErrorCode::InvalidArgument, "prefix is not UTF-8")
        })?;
        ovstorage::address::parse(s)
    })();

    runtime.spawn(async move {
        let outcome = AssertUnwindSafe(async move {
            let url = parsed?;
            inner.capabilities_for(&url)
        })
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(panic_error()));
        unsafe { fire_capabilities(callback, user_data, outcome) };
    });
}

// --- callback firing helpers --------------------------------------

unsafe fn fire_status(
    callback: unsafe extern "C" fn(Status, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<()>,
) {
    match outcome {
        Ok(()) => {
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_connection(
    callback: unsafe extern "C" fn(Status, *mut crate::Connection, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::Connection>,
) {
    match outcome {
        Ok(conn) => {
            let handle = Box::into_raw(Box::new(crate::Connection::from_connection(conn)));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_connection_list(
    callback: unsafe extern "C" fn(Status, *mut crate::ConnectionList, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<Vec<ovstorage::Connection>>,
) {
    match outcome {
        Ok(connections) => {
            let items: Vec<crate::Connection> = connections
                .into_iter()
                .map(crate::Connection::from_connection)
                .collect();
            let handle = Box::into_raw(Box::new(crate::ConnectionList { items }));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_info(
    callback: unsafe extern "C" fn(Status, *mut Info, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ObjectInfo>,
) {
    match outcome {
        Ok(info) => {
            let info_ptr = info_handle(info);
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, info_ptr, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_read_bytes(
    callback: unsafe extern "C" fn(Status, Bytes, *mut Info, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<(Vec<u8>, ObjectInfo)>,
) {
    match outcome {
        Ok((bytes, info)) => {
            let chunk = bytes_handle(bytes);
            let info_ptr = info_handle(info);
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, chunk, info_ptr, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, empty_bytes(), ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_local_delegate(
    callback: unsafe extern "C" fn(Status, *mut LocalDelegate, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::LocalDelegate>,
) {
    let outcome = outcome.and_then(local_delegate_handle);
    match outcome {
        Ok(delegate) => {
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, delegate, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_list(
    callback: unsafe extern "C" fn(Status, *mut List, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::ListPage>,
) {
    match outcome {
        Ok(page) => {
            let list_ptr = list_handle(page.items, page.next_page_token);
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, list_ptr, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_list_versions(
    callback: unsafe extern "C" fn(Status, *mut VersionList, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<(Vec<ObjectInfo>, Option<String>)>,
) {
    match outcome {
        Ok((items, next_page_token)) => {
            let list_ptr = version_list_handle(items, next_page_token);
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, list_ptr, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_check_access(
    callback: unsafe extern "C" fn(Status, AccessDecision, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::AccessDecision>,
) {
    match outcome {
        Ok(decision) => {
            let decision = access_decision(decision);
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, decision, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, empty_decision(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_stream_error(
    callback: unsafe extern "C" fn(Bytes, *const Error, bool, *mut c_void),
    user_data: UserData,
    error: ovstorage::Error,
) {
    let status = status_from_error(error.code());
    let message = cstring_lossy(error.message()).into_raw();
    let err = Error {
        code: status,
        message,
    };
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        callback(empty_bytes(), &err, true, user_data.0);
    }));
    unsafe {
        let _ = CString::from_raw(message);
    }
}

unsafe fn fire_auth_event_error(
    callback: unsafe extern "C" fn(*mut crate::AuthEvent, *const Error, bool, *mut c_void),
    user_data: UserData,
    error: ovstorage::Error,
) {
    let status = status_from_error(error.code());
    let message = cstring_lossy(error.message()).into_raw();
    let err = Error {
        code: status,
        message,
    };
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        callback(ptr::null_mut(), &err, true, user_data.0);
    }));
    unsafe {
        let _ = CString::from_raw(message);
    }
}

unsafe fn fire_alias(
    callback: unsafe extern "C" fn(Status, *mut crate::Alias, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::Alias>,
) {
    match outcome {
        Ok(alias) => {
            let handle = Box::into_raw(Box::new(crate::Alias::from_alias(alias)));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_alias_list(
    callback: unsafe extern "C" fn(Status, *mut crate::AliasList, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<Vec<ovstorage::Alias>>,
) {
    match outcome {
        Ok(aliases) => {
            let items: Vec<crate::Alias> =
                aliases.into_iter().map(crate::Alias::from_alias).collect();
            let handle = Box::into_raw(Box::new(crate::AliasList { items }));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_address_root_watch_error(
    callback: unsafe extern "C" fn(*mut crate::AddressRootList, *const Error, bool, *mut c_void),
    user_data: UserData,
    error: ovstorage::Error,
) {
    let status = status_from_error(error.code());
    let message = cstring_lossy(error.message()).into_raw();
    let err = Error {
        code: status,
        message,
    };
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        callback(ptr::null_mut(), &err, true, user_data.0);
    }));
    unsafe {
        let _ = CString::from_raw(message);
    }
}

unsafe fn fire_address_visibility_override(
    callback: unsafe extern "C" fn(
        Status,
        *mut crate::AddressVisibilityOverride,
        *const Error,
        *mut c_void,
    ),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::AddressVisibilityOverride>,
) {
    match outcome {
        Ok(o) => {
            let handle =
                Box::into_raw(Box::new(crate::AddressVisibilityOverride::from_override(o)));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_address_visibility_override_list(
    callback: unsafe extern "C" fn(
        Status,
        *mut crate::AddressVisibilityOverrideList,
        *const Error,
        *mut c_void,
    ),
    user_data: UserData,
    outcome: ovstorage::Result<Vec<ovstorage::AddressVisibilityOverride>>,
) {
    match outcome {
        Ok(items) => {
            let items: Vec<crate::AddressVisibilityOverride> = items
                .into_iter()
                .map(crate::AddressVisibilityOverride::from_override)
                .collect();
            let handle = Box::into_raw(Box::new(crate::AddressVisibilityOverrideList { items }));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_address_root_list(
    callback: unsafe extern "C" fn(Status, *mut crate::AddressRootList, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<Vec<ovstorage::AddressRoot>>,
) {
    match outcome {
        Ok(items) => {
            let items: Vec<crate::AddressRoot> = items
                .into_iter()
                .map(crate::AddressRoot::from_root)
                .collect();
            let handle = Box::into_raw(Box::new(crate::AddressRootList { items }));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_backend_kind_descriptor_list(
    callback: unsafe extern "C" fn(
        Status,
        *mut crate::BackendKindDescriptorList,
        *const Error,
        *mut c_void,
    ),
    user_data: UserData,
    outcome: ovstorage::Result<Vec<ovstorage::StorageBackendKindDescriptor>>,
) {
    match outcome {
        Ok(items) => {
            let items: Vec<crate::BackendKindDescriptor> = items
                .into_iter()
                .map(crate::BackendKindDescriptor::from_descriptor)
                .collect();
            let handle = Box::into_raw(Box::new(crate::BackendKindDescriptorList { items }));
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, handle, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null_mut(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}

unsafe fn fire_capabilities(
    callback: unsafe extern "C" fn(Status, *const crate::CapabilitiesV1, *const Error, *mut c_void),
    user_data: UserData,
    outcome: ovstorage::Result<ovstorage::Capabilities>,
) {
    match outcome {
        Ok(caps) => {
            // Stack-local CapabilitiesV1 filled via write_capabilities;
            // borrowed pointer passed to the callback.
            let mut v1 = crate::CapabilitiesV1 {
                struct_size: std::mem::size_of::<crate::CapabilitiesV1>(),
                supports_if_match_write: false,
                supports_no_overwrite_write: false,
                supports_native_metadata_patch: false,
                supports_metadata_rewrite_emulation: false,
                writes_are_atomic: false,
                supports_server_side_copy: false,
                supports_server_side_rename: false,
                supports_atomic_rename: false,
                has_real_directories: false,
                supports_list: false,
                wants_list_backed_stat: false,
                supports_recursive_list: false,
                populates_subdirectory_metadata: false,
                supports_version_listing: false,
                has_version_list_order: false,
                version_list_order: crate::VersionListOrder::Newest,
                populates_effective_permissions_on_stat: false,
                supports_access_check: false,
                supports_watch_directory: false,
                watch_directory_kinds: crate::ChangeKindSet::default(),
                watch_directory_resumable: false,
                has_watch_directory_max_lag: false,
                watch_directory_max_lag_nanos: 0,
                has_redirect_size_threshold: false,
                redirect_size_threshold: 0,
            };
            crate::write_capabilities(&caps, &mut v1 as *mut crate::CapabilitiesV1);
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(Status::Ok, &v1, ptr::null(), user_data.0);
            }));
        }
        Err(error) => {
            let status = status_from_error(error.code());
            let message = cstring_lossy(error.message()).into_raw();
            let err = Error {
                code: status,
                message,
            };
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
                callback(status, ptr::null(), &err, user_data.0);
            }));
            unsafe {
                let _ = CString::from_raw(message);
            }
        }
    }
}
