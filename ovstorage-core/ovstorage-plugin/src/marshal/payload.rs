// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Marshal a `Body` for the FFI boundary.
pub fn body_to_ffi(value: Body) -> ffi::Body {
    match value {
        Body::Bytes(bytes) => ffi::Body::from_bytes(primitive::bytes_to_ffi(bytes)),
        Body::LocalFile(path) => {
            ffi::Body::from_local_file(primitive::str_to_ffi(path_to_string(&path)))
        }
        Body::Stream(stream) => ffi::Body::from_stream(body_stream_to_ffi(stream)),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::Body`] produced by [`body_to_ffi`]
/// or by an FFI counterpart.
pub unsafe fn body_from_ffi(value: ffi::Body) -> Result<Body, Error> {
    unsafe {
        let result = match value.tag {
            ffi::BodyTag::Bytes => {
                let bytes = std::ptr::read(value.bytes.as_ptr());
                std::mem::forget(value);
                Body::Bytes(primitive::bytes_from_ffi(bytes))
            }
            ffi::BodyTag::LocalFile => {
                let path_ffi = std::ptr::read(value.local_file.as_ptr());
                std::mem::forget(value);
                let path = primitive::str_from_ffi(path_ffi)?;
                Body::LocalFile(PathBuf::from(path))
            }
            ffi::BodyTag::Stream => {
                let stream_ffi = std::ptr::read(value.stream.as_ptr());
                std::mem::forget(value);
                Body::Stream(body_stream_from_ffi(stream_ffi))
            }
        };
        Ok(result)
    }
}

/// State behind an [`ffi::BodyStream`] handle. `terminal` latches
/// after a `None`/`Err` so subsequent `next_fn` calls short-circuit
/// per the stream contract.
struct PluginBodyStreamState {
    stream: BodyStream,
    terminal: bool,
}

/// Wrap a Rust `BodyStream` in an FFI vtable handle. The boxed state
/// is freed by `drop_fn`. Enforces the [`ffi::StreamStep::Failed`]
/// terminal-state contract at the boundary regardless of the
/// underlying iterator's post-error behavior.
pub fn body_stream_to_ffi(stream: BodyStream) -> ffi::BodyStream {
    let state = Box::into_raw(Box::new(PluginBodyStreamState {
        stream,
        terminal: false,
    })) as *mut core::ffi::c_void;
    ffi::BodyStream {
        state,
        next_fn: body_stream_next_thunk,
        drop_fn: body_stream_drop_thunk,
    }
}

/// Unwrap an FFI `BodyStream` into a Rust `BodyStream`. Dropping the
/// returned iterator runs the FFI `drop_fn` exactly once.
///
/// # Safety
///
/// `stream` must be a valid [`ffi::BodyStream`] produced by
/// [`body_stream_to_ffi`] or an FFI counterpart.
pub unsafe fn body_stream_from_ffi(stream: ffi::BodyStream) -> BodyStream {
    BodyStream::from_iter(BodyStreamIter {
        stream,
        terminal: false,
    })
}

// `next_fn` slot of the response body byte-stream's type-erased state vtable;
// called through the `BodyStream` pointer to pull the next chunk, not by symbol.
/// cbindgen:ignore
unsafe extern "C" fn body_stream_next_thunk(
    state: *mut core::ffi::c_void,
    out_chunk: *mut ffi::Bytes,
    out_error: *mut ffi::Error,
) -> ffi::StreamStep {
    unsafe {
        let s = &mut *(state as *mut PluginBodyStreamState);
        if s.terminal {
            return ffi::StreamStep::Ended;
        }
        match s.stream.next_chunk() {
            None => {
                s.terminal = true;
                ffi::StreamStep::Ended
            }
            Some(Ok(bytes)) => {
                std::ptr::write(out_chunk, primitive::bytes_to_ffi(bytes));
                ffi::StreamStep::Yielded
            }
            Some(Err(err)) => {
                std::ptr::write(out_error, error::to_ffi(&err));
                s.terminal = true;
                ffi::StreamStep::Failed
            }
        }
    }
}

// `drop_fn` slot of the response body byte-stream's type-erased state vtable;
// called through the `BodyStream` pointer to free its erased state.
/// cbindgen:ignore
unsafe extern "C" fn body_stream_drop_thunk(state: *mut core::ffi::c_void) {
    if state.is_null() {
        return;
    }
    crate::ffi_runtime::guard_drop("BodyStream", || unsafe {
        let _owned = Box::from_raw(state as *mut PluginBodyStreamState);
    });
}

/// Iterator adapter driving an `ffi::BodyStream` handle. `terminal`
/// latches after `Ended` / `Failed` so subsequent calls return `None`.
struct BodyStreamIter {
    stream: ffi::BodyStream,
    terminal: bool,
}

impl Iterator for BodyStreamIter {
    type Item = Result<Vec<u8>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.terminal {
            return None;
        }
        let mut chunk = std::mem::MaybeUninit::<ffi::Bytes>::uninit();
        let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();
        let step = unsafe {
            (self.stream.next_fn)(self.stream.state, chunk.as_mut_ptr(), error.as_mut_ptr())
        };
        match step {
            ffi::StreamStep::Ended => {
                self.terminal = true;
                None
            }
            ffi::StreamStep::Yielded => {
                let bytes = unsafe { chunk.assume_init() };
                Some(Ok(unsafe { primitive::bytes_from_ffi(bytes) }))
            }
            // Body streams are terminal-on-error; `TransientError` folds
            // into `Failed`.
            ffi::StreamStep::Failed | ffi::StreamStep::TransientError => {
                self.terminal = true;
                let err_ffi = unsafe { error.assume_init() };
                let err = unsafe { error::from_ffi(err_ffi) };
                Some(Err(err))
            }
        }
    }
}

pub fn write_result_to_ffi(value: WriteResult) -> ffi::WriteResult {
    ffi::WriteResult {
        info: metadata::object_info_to_ffi(value.info),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WriteResult`] produced by
/// [`write_result_to_ffi`] or by an FFI counterpart.
pub unsafe fn write_result_from_ffi(value: ffi::WriteResult) -> Result<WriteResult, Error> {
    unsafe {
        let info = metadata::object_info_from_ffi(value.info)?;
        Ok(WriteResult { info })
    }
}

pub fn local_delegate_to_ffi(value: LocalDelegate) -> ffi::LocalDelegate {
    ffi::LocalDelegate {
        path: primitive::str_to_ffi(path_to_string(&value.path)),
        info: metadata::object_info_to_ffi(value.info),
        lease: lease_to_ffi(value.guard),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::LocalDelegate`] produced by
/// [`local_delegate_to_ffi`] or by an FFI counterpart.
pub unsafe fn local_delegate_from_ffi(value: ffi::LocalDelegate) -> Result<LocalDelegate, Error> {
    unsafe {
        // Take the lease first, so it is reconstructed (and released on
        // any error return below) regardless of how path/info decode.
        let guard = lease_from_ffi(value.lease);
        let path = primitive::str_from_ffi(value.path);
        let info = metadata::object_info_from_ffi(value.info);
        Ok(LocalDelegate {
            path: PathBuf::from(path?),
            info: info?,
            guard,
        })
    }
}

/// Encode a delegate's opaque RAII `guard` into a crossable
/// [`ffi::LeaseHandle`]. A present guard is leaked behind the handle as a
/// `Box<Arc<dyn Send + Sync>>`; `None` encodes the NULL sentinel.
fn lease_to_ffi(guard: Option<Arc<dyn Send + Sync>>) -> ffi::LeaseHandle {
    match guard {
        Some(guard) => ffi::LeaseHandle {
            state: Box::into_raw(Box::new(guard)) as *mut core::ffi::c_void,
            drop_fn: Some(lease_drop_thunk),
        },
        None => ffi::LeaseHandle::none(),
    }
}

/// Reconstruct a delegate's `guard` from a crossed [`ffi::LeaseHandle`].
/// A real lease (`state != NULL`) is wrapped so its Drop crosses back
/// over `drop_fn`, releasing the producer-side pin when the last clone of
/// the delegate is dropped; the NULL sentinel decodes to `None`. Consumes
/// `lease` — the NULL case still drops the (no-op) handle.
fn lease_from_ffi(lease: ffi::LeaseHandle) -> Option<Arc<dyn Send + Sync>> {
    if lease.state.is_null() {
        drop(lease);
        None
    } else {
        Some(Arc::new(lease) as Arc<dyn Send + Sync>)
    }
}

/// `drop_fn` for a lease minted by [`lease_to_ffi`]: reclaims the leaked
/// `Box<Arc<dyn Send + Sync>>`, whose `Arc` Drop then releases one
/// reference to the producer-side pin. NULL-safe and driven exactly once.
// `drop_fn` slot for a body lease's type-erased state; called through the
// lease pointer to release one Arc reference to the producer pin, not by symbol.
/// cbindgen:ignore
unsafe extern "C" fn lease_drop_thunk(state: *mut core::ffi::c_void) {
    unsafe {
        if state.is_null() {
            return;
        }
        drop(Box::from_raw(state as *mut Arc<dyn Send + Sync>));
    }
}

pub fn read_result_to_ffi(value: ReadResult) -> ffi::ReadResult {
    match value {
        ReadResult::Bytes { bytes, info } => ffi::ReadResult::from_bytes(ffi::ReadResultBytes {
            bytes: primitive::bytes_to_ffi(bytes),
            info: metadata::object_info_to_ffi(info),
        }),
        ReadResult::Stream { stream, info } => {
            // Bridge async stream → sync FFI iterator via bounded mpsc.
            // Capacity 16: peak memory ≈ chunk_size × 16.
            let body_stream = body_stream_from_async_stream(stream);
            ffi::ReadResult::from_stream(ffi::ReadResultStream {
                stream: body_stream_to_ffi(body_stream),
                info: metadata::object_info_to_ffi(info),
            })
        }
        ReadResult::LocalDelegate(delegate) => {
            ffi::ReadResult::from_local_delegate(local_delegate_to_ffi(delegate))
        }
        ReadResult::Redirect(redirect) => {
            ffi::ReadResult::from_redirect(redirect::read_redirect_to_ffi(redirect))
        }
    }
}

/// Bridge a `ReadStream` to the sync FFI iterator via a bounded
/// async-channel. `bytes::Bytes` → `Vec<u8>` is one copy at the
/// boundary; the FFI `Bytes` type owns its buffer.
fn body_stream_from_async_stream(stream: ReadStream) -> BodyStream {
    use futures::StreamExt;
    let (tx, rx) = async_channel::bounded::<Result<Vec<u8>, Error>>(16);
    tokio::spawn(async move {
        let mut s = stream;
        while let Some(item) = s.next().await {
            let item: Result<Vec<u8>, Error> = item.map(|b| b.to_vec());
            let is_err = item.is_err();
            if tx.send(item).await.is_err() {
                return;
            }
            if is_err {
                return;
            }
        }
    });
    BodyStream::from_iter(std::iter::from_fn(move || rx.recv_blocking().ok()))
}

/// # Safety
///
/// `value` must be a valid [`ffi::ReadResult`] produced by
/// [`read_result_to_ffi`] or by an FFI counterpart.
pub unsafe fn read_result_from_ffi(value: ffi::ReadResult) -> Result<ReadResult, Error> {
    unsafe {
        let result = match value.tag {
            ffi::ReadResultTag::Bytes => {
                let bytes_payload = std::ptr::read(value.bytes.as_ptr());
                std::mem::forget(value);
                let ffi::ReadResultBytes { bytes, info } = bytes_payload;
                let info = metadata::object_info_from_ffi(info)?;
                ReadResult::Bytes {
                    bytes: primitive::bytes_from_ffi(bytes),
                    info,
                }
            }
            ffi::ReadResultTag::Stream => {
                let stream_payload = std::ptr::read(value.stream.as_ptr());
                std::mem::forget(value);
                let ffi::ReadResultStream { stream, info } = stream_payload;
                // A metadata decode failure here would drop `stream` — a
                // producer-owned `BodyStream` whose `Drop` drives the
                // producer's `drop_fn` — inside the producer's own `on_read`
                // callback. Hand it to the surrounding completion's retirement
                // so it is released off that frame, holding the call's pin so
                // the Layer state it came from cannot go first.
                let info = match metadata::object_info_from_ffi(info) {
                    Ok(info) => info,
                    Err(error) => {
                        crate::consume_v2::orphan_producer_value(stream);
                        return Err(error);
                    }
                };
                let body = body_stream_from_ffi(stream);
                // Drain on `std::thread::spawn`, not `spawn_blocking`:
                // this runs inside the FFI `on_read` callback, which is
                // invoked by whichever thread the plugin chose to fire it
                // on. There is no contract that thread carries a tokio
                // context, so `spawn_blocking` would panic.
                let (tx, rx) = async_channel::bounded::<Result<bytes::Bytes, Error>>(16);
                std::thread::Builder::new()
                    .name("ovs-read-bridge".into())
                    .spawn(move || {
                        let mut iter = body;
                        while let Some(chunk) = iter.next_chunk() {
                            let item = chunk.map(bytes::Bytes::from);
                            let is_err = item.is_err();
                            if tx.send_blocking(item).is_err() {
                                return;
                            }
                            if is_err {
                                return;
                            }
                        }
                    })
                    .expect("failed to spawn thread");
                ReadResult::Stream {
                    stream: Box::pin(rx),
                    info,
                }
            }
            ffi::ReadResultTag::LocalDelegate => {
                let delegate_ffi = std::ptr::read(value.local_delegate.as_ptr());
                std::mem::forget(value);
                ReadResult::LocalDelegate(local_delegate_from_ffi(delegate_ffi)?)
            }
            ffi::ReadResultTag::Redirect => {
                let redirect_ffi = std::ptr::read(value.redirect.as_ptr());
                std::mem::forget(value);
                ReadResult::Redirect(redirect::read_redirect_from_ffi(redirect_ffi)?)
            }
        };
        Ok(result)
    }
}

pub fn write_step_to_ffi(value: WriteStep) -> ffi::WriteStep {
    match value {
        WriteStep::Done(result) => ffi::WriteStep::from_done(write_result_to_ffi(result)),
        WriteStep::Redirects(batch) => {
            ffi::WriteStep::from_redirects(redirect::write_redirect_batch_to_ffi(batch))
        }
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::WriteStep`] produced by
/// [`write_step_to_ffi`] or by an FFI counterpart.
pub unsafe fn write_step_from_ffi(value: ffi::WriteStep) -> Result<WriteStep, Error> {
    unsafe {
        let step = match value.tag {
            ffi::WriteStepTag::Done => {
                let done_ffi = std::ptr::read(value.done.as_ptr());
                std::mem::forget(value);
                WriteStep::Done(write_result_from_ffi(done_ffi)?)
            }
            ffi::WriteStepTag::Redirects => {
                let redirects_ffi = std::ptr::read(value.redirects.as_ptr());
                std::mem::forget(value);
                WriteStep::Redirects(redirect::write_redirect_batch_from_ffi(redirects_ffi)?)
            }
        };
        Ok(step)
    }
}

pub fn backend_item_info_to_ffi(value: BackendItemInfo) -> ffi::BackendItemInfo {
    ffi::BackendItemInfo {
        kind: identity::object_kind_to_ffi(value.kind),
        etag: primitive::optional_to_ffi(value.etag, primitive::str_to_ffi),
        version: primitive::optional_to_ffi(value.version, primitive::str_to_ffi),
        size: primitive::optional_to_ffi(value.size, |s| s),
        mtime_unix_ms: primitive::optional_to_ffi(value.mtime, primitive::system_time_to_unix_ms),
        checksums: metadata::checksum_set_to_ffi(value.checksums),
        effective_permissions: primitive::optional_to_ffi(
            value.effective_permissions,
            metadata::effective_permissions_to_ffi,
        ),
        system_metadata: primitive::optional_to_ffi(
            value.system_metadata,
            metadata::system_metadata_to_ffi,
        ),
        user_metadata: primitive::optional_to_ffi(
            value.user_metadata,
            metadata::user_metadata_to_ffi,
        ),
        modified_by: primitive::optional_to_ffi(value.modified_by, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::BackendItemInfo`] produced by
/// [`backend_item_info_to_ffi`] or by an FFI counterpart.
pub unsafe fn backend_item_info_from_ffi(
    value: ffi::BackendItemInfo,
) -> Result<BackendItemInfo, Error> {
    unsafe {
        let kind_ffi = value.kind;
        let etag_ffi = value.etag;
        let version_ffi = value.version;
        let size_ffi = value.size;
        let mtime_ffi = value.mtime_unix_ms;
        let checksums_ffi = value.checksums;
        let perms_ffi = value.effective_permissions;
        let system_ffi = value.system_metadata;
        let user_ffi = value.user_metadata;
        let modified_by_ffi = value.modified_by;

        let etag = primitive::optional_from_ffi(etag_ffi, |s| primitive::str_from_ffi(s));
        let version = primitive::optional_from_ffi(version_ffi, |s| primitive::str_from_ffi(s));
        let size = primitive::optional_from_ffi::<u64, u64, Error>(size_ffi, Ok);
        let mtime = primitive::optional_from_ffi::<i64, SystemTime, Error>(mtime_ffi, |ms| {
            Ok(primitive::system_time_from_unix_ms(ms))
        });
        let checksums = metadata::checksum_set_from_ffi(checksums_ffi);
        let effective_permissions =
            primitive::optional_from_ffi::<ffi::EffectivePermissions, EffectivePermissions, Error>(
                perms_ffi,
                |p| Ok(metadata::effective_permissions_from_ffi(p)),
            );
        let system_metadata =
            primitive::optional_from_ffi(system_ffi, |kv| primitive::key_value_list_from_ffi(kv));
        let user_metadata =
            primitive::optional_from_ffi(user_ffi, |kv| primitive::key_value_list_from_ffi(kv));
        let modified_by =
            primitive::optional_from_ffi(modified_by_ffi, |s| primitive::str_from_ffi(s));

        Ok(BackendItemInfo {
            kind: identity::object_kind_from_ffi(kind_ffi),
            etag: etag?,
            version: version?,
            size: size?,
            mtime: mtime?,
            checksums: checksums?,
            effective_permissions: effective_permissions?,
            system_metadata: system_metadata?,
            user_metadata: user_metadata?,
            modified_by: modified_by?,
        })
    }
}

pub fn access_decision_to_ffi(value: AccessDecision) -> ffi::AccessDecision {
    ffi::AccessDecision {
        allowed: value.allowed,
        denied_ops: access::access_ops_to_ffi(value.denied_ops),
        reason: primitive::optional_to_ffi(value.reason, primitive::str_to_ffi),
    }
}

/// # Safety
///
/// `value` must be a valid [`ffi::AccessDecision`] produced by
/// [`access_decision_to_ffi`].
pub unsafe fn access_decision_from_ffi(
    value: ffi::AccessDecision,
) -> Result<AccessDecision, Error> {
    unsafe {
        let denied_ops = access::access_ops_from_ffi(value.denied_ops);
        let allowed = value.allowed;
        let reason_ffi = value.reason;
        let reason = primitive::optional_from_ffi(reason_ffi, |s| primitive::str_from_ffi(s))?;
        Ok(AccessDecision {
            allowed,
            denied_ops,
            reason,
        })
    }
}

fn path_to_string(path: &std::path::Path) -> String {
    // C ABI requires UTF-8; lossy is the documented behavior for
    // non-UTF-8 paths.
    path.to_string_lossy().into_owned()
}
