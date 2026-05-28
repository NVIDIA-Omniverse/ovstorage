// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side `StorageBackend` adapter driving a plugin's
//! `BackendVTableV1` through dlopen'd function pointers.
//!
//! Each async I/O slot is callback-shaped: the host invokes the vtable
//! method, which spawns work on the plugin's runtime and returns
//! immediately; the plugin fires `on_complete(status, result, error,
//! user_data)` exactly once. Per-method trampolines box a `oneshot`
//! sender as `user_data`, decode the FFI result, and the trait method
//! `await`s the receiver.
//!
//! Heap-owning inputs (`ResolvedTarget`, etc.) are consumed by the
//! plugin's thunk via `ptr::read`; the host carrier is `mem::forget`'d.

use std::ffi::c_void;
use std::mem;
use std::sync::Arc;
use std::time::Instant;

use ovstorage_plugin::{
    AccessDecision, AccessOps, BackendAddressRootsStream, BackendChangeStream, BackendItemInfo,
    BodyStream, CancellationToken, CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions,
    DeleteOptions, Error, ErrorCode, ListOptions, ListVersionsOptions, ObjectInfo, ReadOptions,
    ReadResult, RedirectResultBatch, RenameOptions, ResolvedTarget, Result, StatOptions,
    UpdateMetadataOptions, WatchDirectoryOptions, WriteOptions, WriteRedirectBatch, WriteResult,
    WriteStep, ffi, shim,
};
use tokio::sync::oneshot;

use crate::loader::HostPlugin;
use crate::metrics::{SPI_CALLS_TOTAL, SPI_DURATION_SECONDS, error_code_label};

pub(crate) struct LoadedBackend {
    // Keeps the cdylib alive while any instance produced from it is.
    plugin: Arc<HostPlugin>,
    handle: BackendHandle,
    /// Cached plugin name for metric labels; avoids crossing into the
    /// HostPlugin manifest on every SPI call.
    plugin_name: String,
}

#[derive(Clone, Copy)]
struct BackendHandle {
    state: *mut c_void,
    vtable: *const ffi::BackendVTableV1,
}

unsafe impl Send for BackendHandle {}
unsafe impl Sync for BackendHandle {}

unsafe impl Send for LoadedBackend {}
unsafe impl Sync for LoadedBackend {}

impl LoadedBackend {
    pub fn new(
        plugin: Arc<HostPlugin>,
        state: *mut c_void,
        vtable: *const ffi::BackendVTableV1,
    ) -> Self {
        let plugin_name = plugin.manifest().name.to_string();
        Self {
            plugin,
            handle: BackendHandle { state, vtable },
            plugin_name,
        }
    }

    fn handle(&self) -> BackendHandle {
        self.handle
    }
}

impl BackendHandle {
    fn vtable(&self) -> &ffi::BackendVTableV1 {
        // SAFETY: callers (the LoadedBackend that produced this handle)
        // keep the cdylib alive via Arc<HostPlugin>.
        unsafe { &*self.vtable }
    }
}

impl Drop for LoadedBackend {
    fn drop(&mut self) {
        if !self.handle.state.is_null() && !self.handle.vtable.is_null() {
            // SAFETY: vtable->drop is the per-instance teardown the
            // plugin author wired up.
            unsafe {
                ((*self.handle.vtable).drop)(self.handle.state);
            }
            self.handle.state = std::ptr::null_mut();
            self.handle.vtable = std::ptr::null();
        }
        let _ = &self.plugin;
    }
}

/// Decode `(status, result, error)` into `Result<R, Error>`.
///
/// **Pointer presence is the primary signal**, not `status`:
/// `ErrorCode::NotFound` has discriminant `0`, colliding with
/// "0 = success."
pub(crate) fn decode_async_result<FfiR, R>(
    _status: i32,
    result: *mut FfiR,
    error: *mut ffi::Error,
    on_ok: impl FnOnce(*mut FfiR) -> Result<R>,
) -> Result<R> {
    if !error.is_null() {
        if !result.is_null() {
            // Reclaim the spurious result so it doesn't leak.
            unsafe {
                drop(Box::from_raw(result));
            }
        }
        // SAFETY: contract — error was Box::into_raw'd by the plugin.
        let boxed = unsafe { Box::from_raw(error) };
        Err(unsafe { shim::error::from_ffi(*boxed) })
    } else if !result.is_null() {
        on_ok(result)
    } else {
        Err(Error::new(
            ErrorCode::Internal,
            "plugin produced null result and null error in non-unit method",
        ))
    }
}

/// Unit variant of `decode_async_result`.
fn decode_async_unit_result(_status: i32, error: *mut ffi::Error) -> Result<()> {
    if error.is_null() {
        Ok(())
    } else {
        let boxed = unsafe { Box::from_raw(error) };
        Err(unsafe { shim::error::from_ffi(*boxed) })
    }
}

fn emit_spi_metrics<T>(
    op: &'static str,
    plugin: &str,
    result: &Result<T>,
    elapsed: std::time::Duration,
) {
    let outcome = match result {
        Ok(_) => "ok",
        Err(e) => error_code_label(e.code()),
    };
    metrics::counter!(SPI_CALLS_TOTAL, "op" => op, "plugin" => plugin.to_owned(), "outcome" => outcome).increment(1);
    metrics::histogram!(SPI_DURATION_SECONDS, "op" => op, "plugin" => plugin.to_owned())
        .record(elapsed.as_secs_f64());
}

/// Plugin dropped its `on_complete` Sender before firing.
fn dropped_sender_error() -> Error {
    Error::new(
        ErrorCode::Internal,
        "plugin dropped on_complete sender without firing",
    )
}

#[async_trait::async_trait]
impl shim::Backend for LoadedBackend {
    #[tracing::instrument(level = "debug", skip_all, fields(op = "stat"))]
    async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::stat_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<ObjectInfo>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_stat(
            status: i32,
            result: *mut ffi::ObjectInfo,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<ObjectInfo>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::metadata::object_info_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().stat)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_stat,
                user_data,
            );
        }
        mem::forget(target_ffi);
        let _ = opts_ffi; // Copy POD

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("stat", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "read"))]
    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::read_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<ReadResult>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_read(
            status: i32,
            result: *mut ffi::ReadResult,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<ReadResult>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::read_result_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().read)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_read,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("read", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "write"))]
    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let bytes_ffi = shim::primitive::bytes_to_ffi(bytes);
        let opts_ffi = shim::options::write_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<WriteResult>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_write(
            status: i32,
            result: *mut ffi::WriteResult,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<WriteResult>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::write_result_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().write)(
                handle.state,
                &target_ffi,
                &bytes_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_write,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(bytes_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("write", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "write_stream"))]
    async fn write_stream(
        &self,
        target: ResolvedTarget,
        body: BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let body_ffi = shim::payload::body_stream_to_ffi(body);
        let opts_ffi = shim::options::write_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<WriteResult>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_write_stream(
            status: i32,
            result: *mut ffi::WriteResult,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<WriteResult>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::write_result_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().write_stream)(
                handle.state,
                &target_ffi,
                &body_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_write_stream,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(body_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("write_stream", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "write_redirect"))]
    async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::write_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<WriteRedirectBatch>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_write_redirect(
            status: i32,
            result: *mut ffi::WriteRedirectBatch,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<WriteRedirectBatch>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::redirect::write_redirect_batch_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().write_redirect)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_write_redirect,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "write_redirect",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "continue_write"))]
    async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let redirects_ffi = shim::redirect::write_redirect_batch_to_ffi(redirects);
        let results_ffi = shim::redirect::redirect_result_batch_to_ffi(results);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<WriteStep>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_continue_write(
            status: i32,
            result: *mut ffi::WriteStep,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<WriteStep>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::write_step_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().continue_write)(
                handle.state,
                &target_ffi,
                &redirects_ffi,
                &results_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_continue_write,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(redirects_ffi);
        mem::forget(results_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "continue_write",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "delete"))]
    async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::delete_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<()>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_delete(status: i32, error: *mut ffi::Error, user_data: *mut c_void) {
            let tx: Box<oneshot::Sender<Result<()>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let _ = tx.send(decode_async_unit_result(status, error));
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().delete)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_delete,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("delete", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "list"))]
    async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let handle = self.handle();
        let prefix_ffi = shim::address::resolved_target_to_ffi(prefix);
        let opts_ffi = shim::options::list_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<Vec<ObjectInfo>>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_list(
            status: i32,
            result: *mut ffi::List<ffi::ObjectInfo>,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<Vec<ObjectInfo>>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::primitive::list_from_ffi(*Box::from_raw(r), |item| {
                    shim::metadata::object_info_from_ffi(item)
                })
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().list)(
                handle.state,
                &prefix_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_list,
                user_data,
            );
        }
        mem::forget(prefix_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("list", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "list_versions"))]
    async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::list_versions_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<Vec<ObjectInfo>>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_list_versions(
            status: i32,
            result: *mut ffi::List<ffi::ObjectInfo>,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<Vec<ObjectInfo>>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::primitive::list_from_ffi(*Box::from_raw(r), |item| {
                    shim::metadata::object_info_from_ffi(item)
                })
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().list_versions)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_list_versions,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("list_versions", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "get_latest_version"))]
    async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<ObjectInfo>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_get_latest_version(
            status: i32,
            result: *mut ffi::ObjectInfo,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<ObjectInfo>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::metadata::object_info_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().get_latest_version)(
                handle.state,
                &target_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_get_latest_version,
                user_data,
            );
        }
        mem::forget(target_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "get_latest_version",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "watch_directory"))]
    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let handle = self.handle();
        let prefix_ffi = shim::address::resolved_target_to_ffi(prefix);
        let opts_ffi = shim::options::watch_directory_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<BackendChangeStream>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_watch(
            status: i32,
            result: *mut ffi::BackendChangeStream,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<BackendChangeStream>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| {
                let ffi_stream = unsafe { *Box::from_raw(r) };
                let stream = unsafe { shim::change::BackendChangeStream::from_ffi(ffi_stream) };
                Ok(Box::new(stream) as BackendChangeStream)
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().watch_directory)(
                handle.state,
                &prefix_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_watch,
                user_data,
            );
        }
        mem::forget(prefix_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "watch_directory",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "watch_address_roots"))]
    async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        let handle = self.handle();
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<BackendAddressRootsStream>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_watch_roots(
            status: i32,
            result: *mut ffi::BackendAddressRootsStream,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<BackendAddressRootsStream>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| {
                let ffi_stream = unsafe { *Box::from_raw(r) };
                let iter =
                    unsafe { shim::change::BackendAddressRootsStreamIter::from_ffi(ffi_stream) };
                Ok(bridge_address_roots_iter(iter))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().watch_address_roots)(
                handle.state,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_watch_roots,
                user_data,
            );
        }

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "watch_address_roots",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "create_directory"))]
    async fn create_directory(
        &self,
        target: ResolvedTarget,
        opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::create_directory_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<BackendItemInfo>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_create_directory(
            status: i32,
            result: *mut ffi::BackendItemInfo,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<BackendItemInfo>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::backend_item_info_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().create_directory)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_create_directory,
                user_data,
            );
        }
        mem::forget(target_ffi);
        let _ = opts_ffi; // CreateDirectoryOptions is Copy POD

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "create_directory",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "delete_directory"))]
    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::delete_directory_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<()>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_delete_directory(
            status: i32,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<()>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let _ = tx.send(decode_async_unit_result(status, error));
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().delete_directory)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_delete_directory,
                user_data,
            );
        }
        mem::forget(target_ffi);
        let _ = opts_ffi;

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "delete_directory",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "copy"))]
    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let handle = self.handle();
        let src_ffi = shim::address::resolved_target_to_ffi(src);
        let dest_ffi = shim::address::resolved_target_to_ffi(dest);
        let opts_ffi = shim::options::copy_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<WriteStep>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_copy(
            status: i32,
            result: *mut ffi::WriteStep,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<WriteStep>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::write_step_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().copy)(
                handle.state,
                &src_ffi,
                &dest_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_copy,
                user_data,
            );
        }
        mem::forget(src_ffi);
        mem::forget(dest_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("copy", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "rename"))]
    async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let handle = self.handle();
        let src_ffi = shim::address::resolved_target_to_ffi(src);
        let dest_ffi = shim::address::resolved_target_to_ffi(dest);
        let opts_ffi = shim::options::rename_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<()>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_rename(status: i32, error: *mut ffi::Error, user_data: *mut c_void) {
            let tx: Box<oneshot::Sender<Result<()>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let _ = tx.send(decode_async_unit_result(status, error));
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().rename)(
                handle.state,
                &src_ffi,
                &dest_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_rename,
                user_data,
            );
        }
        mem::forget(src_ffi);
        mem::forget(dest_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("rename", &self.plugin_name, &result, start.elapsed());
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "update_metadata"))]
    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let opts_ffi = shim::options::update_metadata_options_to_ffi(opts);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<BackendItemInfo>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_update_metadata(
            status: i32,
            result: *mut ffi::BackendItemInfo,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<BackendItemInfo>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::backend_item_info_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().update_metadata)(
                handle.state,
                &target_ffi,
                &opts_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_update_metadata,
                user_data,
            );
        }
        mem::forget(target_ffi);
        mem::forget(opts_ffi);

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics(
            "update_metadata",
            &self.plugin_name,
            &result,
            start.elapsed(),
        );
        result
    }

    #[tracing::instrument(level = "debug", skip_all, fields(op = "check_access"))]
    async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let handle = self.handle();
        let target_ffi = shim::address::resolved_target_to_ffi(target);
        let ops_ffi = shim::access::access_ops_to_ffi(ops);
        let cancel_handle = cancel.map(ffi::cancel_token_to_ffi);

        let (tx, rx) = oneshot::channel::<Result<AccessDecision>>();
        let user_data = Box::into_raw(Box::new(tx)) as *mut c_void;

        extern "C" fn on_check_access(
            status: i32,
            result: *mut ffi::AccessDecision,
            error: *mut ffi::Error,
            user_data: *mut c_void,
        ) {
            let tx: Box<oneshot::Sender<Result<AccessDecision>>> =
                unsafe { Box::from_raw(user_data as *mut _) };
            let res = decode_async_result(status, result, error, |r| unsafe {
                shim::payload::access_decision_from_ffi(*Box::from_raw(r))
            });
            let _ = tx.send(res);
        }

        let start = Instant::now();
        unsafe {
            (handle.vtable().check_access)(
                handle.state,
                &target_ffi,
                &ops_ffi,
                cancel_handle
                    .as_ref()
                    .map_or(std::ptr::null(), |h| h.as_ffi_ptr()),
                on_check_access,
                user_data,
            );
        }
        mem::forget(target_ffi);
        let _ = ops_ffi; // AccessOps is Copy POD

        let result = rx.await.unwrap_or_else(|_| Err(dropped_sender_error()));
        drop(cancel_handle);
        emit_spi_metrics("check_access", &self.plugin_name, &result, start.elapsed());
        result
    }
}

/// Forward each `Result<AddressRootsChange>` from the FFI sync iterator
/// onto a tokio mpsc channel, then expose the receiver as the SPI's
/// async stream shape. Drives the FFI iterator on a dedicated
/// `ovs-rt-watch` std thread because the iterator's `next_fn` may park
/// awaiting a server-pushed frame, and a tokio worker cannot block.
fn bridge_address_roots_iter(
    iter: shim::change::BackendAddressRootsStreamIter,
) -> BackendAddressRootsStream {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<ovstorage_plugin::AddressRootsChange>>(8);
    std::thread::Builder::new()
        .name("ovs-rt-watch".into())
        .spawn(move || {
            let mut iter = iter;
            for item in iter.by_ref() {
                if tx.blocking_send(item).is_err() {
                    break;
                }
            }
        })
        .expect("ovs-rt-watch thread");
    Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))
}
