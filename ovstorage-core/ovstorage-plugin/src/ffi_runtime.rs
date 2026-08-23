// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime and stream helpers shared by ABI-v2 FFI thunks.
//!
//! Async I/O slots are callback-shaped: the thunk converts inputs
//! synchronously, spawns the work on the plugin's runtime, and fires
//! `on_complete` exactly once when the future completes (success,
//! error, panic, or cancellation).
//!
//! # The completion chokepoint
//!
//! This module is the only place in the crate that spells the completion
//! callback. A thunk hands [`spawn_async_thunk`] an `encode` closure that
//! *returns* the result envelope as an [`ffi::abi_alloc::AbiOwned`], and
//! [`fire_complete_ok`] / [`fire_complete_err`] do the call.
//!
//! That routing is what makes the mint side enforceable rather than
//! conventional. The host reclaims a result envelope with
//! `abi_alloc::abi_unbox`, so an envelope minted with `Box::into_raw` lands on
//! the plugin binary's Rust global allocator and is freed on the host's — a
//! cross-allocator free, and heap corruption against a plugin running
//! jemalloc or mimalloc. `AbiOwned`
//! is constructible only through `abi_box`, so a completion payload spelled
//! that way does not typecheck.
//!
//! Two envelopes stay outside it: the nested `updates` stream a
//! `ListAddressRootsResult` / `ListConnectionsResult` carries is a field of
//! the result, not the completion payload.
//!
//! `make lint-abi-mint-chokepoint` backs this up by rejecting a call to the
//! completion callback anywhere else in the crate — the one shape the type
//! cannot reach, since a thunk that bypasses these helpers is back to a bare
//! pointer. That check reads Rust as text and is a convention gate, not a
//! boundary: `AbiOwned` is what makes the defect unwritable.
//!
//! # Panic safety
//!
//! Every spawned task wraps its await in `AssertUnwindSafe(...).
//! catch_unwind()` so a plugin panic surfaces as
//! `ErrorCode::Internal` via `on_complete` rather than leaving the
//! host trampoline parked on its oneshot.

use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::OnceLock;

use futures::FutureExt;
use tracing::{Instrument, debug_span, error};

use crate::ffi;
use crate::marshal;
use crate::{Error, ErrorCode};

// ---------------------------------------------------------------------
// Plugin-wide tokio runtime
// ---------------------------------------------------------------------

/// Process-wide tokio runtime driving plugin async methods.
/// Multi-thread (1 worker) rather than current-thread: single-thread
/// runtimes restrict `block_on` to one calling thread at a time,
/// which deadlocks under concurrent FFI calls.
pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name("ovs-plugin-rt")
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("plugin tokio runtime")
    })
}
/// Run a drop-thunk body under `catch_unwind`. A drop thunk is an
/// `extern "C"` frame that reclaims plugin-owned state and therefore runs
/// the plugin's `Drop`. A plugin `Drop` that panics must NEVER unwind
/// across the C ABI (undefined behavior); a caught panic is swallowed and
/// logged, mirroring how the sync/async thunks report plugin panics. A
/// drop thunk has no way to return an error, so swallowing is the only
/// ABI-safe outcome.
pub(crate) fn guard_drop(what: &'static str, body: impl FnOnce()) {
    if std::panic::catch_unwind(AssertUnwindSafe(body)).is_err() {
        error!(
            what = what,
            error.code = ?ErrorCode::Internal,
            "plugin panicked in drop thunk"
        );
    }
}
/// `Send` wrapper around the opaque `user_data` pointer so it crosses
/// `tokio::spawn`'s bound. The pointer is only ever passed through.
struct SendUserData(*mut core::ffi::c_void);
unsafe impl Send for SendUserData {}

/// Materialize a `CancelTokenLocal` from a borrowed FFI handle, or
/// `None` for null. Drop decrements the shared refcount.
pub(crate) fn local_cancel(cancel: *const ffi::CancelTokenFFI) -> Option<ffi::CancelTokenLocal> {
    if cancel.is_null() {
        None
    } else {
        // SAFETY: non-null `cancel` is valid for this call's prologue.
        Some(ffi::cancel_token_from_ffi(unsafe { &*cancel }))
    }
}

/// Complete an async slot with an error.
///
/// The error direction's mint chokepoint, and (with [`fire_complete_ok`]) one
/// of the only two places in this crate that spells the FFI completion
/// callback. A thunk reaches for it directly only in its synchronous
/// prologue, where a request fails to decode before there is a future to
/// spawn.
pub(crate) fn fire_complete_err(
    e: Error,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let err = ffi::abi_alloc::abi_box(marshal::error::to_ffi(&e));
    on_complete(ffi::FFI_STATUS_ERR, std::ptr::null_mut(), err, user_data);
}

/// Complete an async slot with success, carrying `result` — the envelope for
/// a value-returning slot, `None` for a unit slot.
///
/// The success direction's mint chokepoint. [`ffi::abi_alloc::AbiOwned`] is
/// what makes it one: the envelope can only have been minted on the ABI heap,
/// because that is the only way to obtain the type. The cross-allocator free
/// — `Box::into_raw` here, `abi_unbox` in the host — is unspellable in this
/// position rather than merely absent from it.
fn fire_complete_ok(
    result: Option<ffi::abi_alloc::AbiOwned>,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
) {
    let ptr = result.map_or(std::ptr::null_mut(), ffi::abi_alloc::AbiOwned::into_raw);
    on_complete(ffi::FFI_STATUS_OK, ptr, std::ptr::null_mut(), user_data);
}

/// Spawn an async thunk wrapping panic-safety + cancel guard + outcome
/// dispatch. `make_future` builds the SPI call; `encode` turns its value into
/// the result envelope (`None` for a unit slot). Delegates to
/// [`spawn_async_stream_thunk`] so the spawn / panic-guard / instrumentation
/// logic lives in exactly one place; a one-shot op drops the cancel guard when
/// its future resolves.
pub(crate) fn spawn_async_thunk<R, MakeFut, Encode>(
    op: &'static str,
    cancel_local: Option<ffi::CancelTokenLocal>,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
    make_future: MakeFut,
    encode: Encode,
) where
    MakeFut: FnOnce(
            Option<tokio_util::sync::CancellationToken>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<R, Error>> + Send>>
        + Send
        + 'static,
    Encode: FnOnce(R) -> Option<ffi::abi_alloc::AbiOwned> + Send + 'static,
    R: Send + 'static,
{
    spawn_async_stream_thunk(
        op,
        cancel_local,
        on_complete,
        user_data,
        make_future,
        move |value, cancel_guard| {
            drop(cancel_guard);
            encode(value)
        },
    );
}

/// Spawn an async thunk that returns a stream, retaining the cancellation
/// guard after the open future resolves so the host token remains connected
/// for the returned stream's lifetime — `encode` receives it and stores it in
/// the stream state it builds.
pub(crate) fn spawn_async_stream_thunk<R, MakeFut, Encode>(
    op: &'static str,
    cancel_local: Option<ffi::CancelTokenLocal>,
    on_complete: ffi::OnComplete,
    user_data: *mut core::ffi::c_void,
    make_future: MakeFut,
    encode: Encode,
) where
    MakeFut: FnOnce(
            Option<tokio_util::sync::CancellationToken>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<R, Error>> + Send>>
        + Send
        + 'static,
    Encode: FnOnce(R, Option<ffi::CancelTokenLocal>) -> Option<ffi::abi_alloc::AbiOwned>
        + Send
        + 'static,
    R: Send + 'static,
{
    let cancel_token = cancel_local.as_ref().map(|c| c.token_clone());
    let user_data_send = SendUserData(user_data);
    let span = debug_span!("plugin.thunk_async_stream", op = op);
    runtime().spawn(
        async move {
            let cancel_guard = cancel_local;
            let user_data_send = user_data_send;
            // The workspace keeps the default `panic = "unwind"`, so a
            // panic in plugin code inside this spawned task unwinds into
            // the `catch_unwind` below and converts to `Err(Internal)`
            // rather than escaping the task. This wall is the panic-safety
            // contract for both first-party and foreign plugins —
            // unwinding across the C ABI frame stack would be UB.
            let outcome = AssertUnwindSafe(async move { make_future(cancel_token).await })
                .catch_unwind()
                .await;
            let user_data = user_data_send.0;
            let result = match outcome {
                Ok(result) => result,
                Err(_panic) => {
                    error!(op = op, error.code = ?ErrorCode::Internal, "plugin thunk panicked");
                    Err(Error::new(
                        ErrorCode::Internal,
                        format!("plugin panicked inside async stream thunk: {op}"),
                    ))
                }
            };
            match result {
                Ok(value) => {
                    fire_complete_ok(encode(value, cancel_guard), on_complete, user_data);
                }
                Err(e) => {
                    drop(cancel_guard);
                    fire_complete_err(e, on_complete, user_data);
                }
            }
        }
        .instrument(span),
    );
}
pub(crate) mod stream {
    //! Wrap a Rust iterator as the matching FFI stream shape
    //! (`AuthEventStream` / `BackendChangeStream`).

    use super::*;

    // The `terminal` latch defends the `ffi::StreamStep` contract on
    // the plugin side: once we return `Failed` / `Ended`, subsequent
    // `next_fn` calls short-circuit even if the underlying iterator
    // would yield more. Prevents a misbehaving iterator from leaking
    // post-Failed items through the C ABI.

    struct StreamState<T> {
        iter: Box<dyn Iterator<Item = crate::Result<T>> + Send>,
        terminal: bool,
        _cancel_guard: Option<ffi::CancelTokenLocal>,
    }

    enum EncodedStep<T> {
        Yielded(T),
        Failed(ffi::Error),
        Ended,
    }

    unsafe fn next<T: 'static, FfiT>(
        state: *mut core::ffi::c_void,
        out_item: *mut FfiT,
        out_error: *mut ffi::Error,
        panic_message: &'static str,
        encode: impl FnOnce(T) -> FfiT,
    ) -> ffi::StreamStep {
        unsafe {
            let state = &mut *(state as *mut StreamState<T>);
            if state.terminal {
                return ffi::StreamStep::Ended;
            }
            let encoded = std::panic::catch_unwind(AssertUnwindSafe(|| match state.iter.next() {
                Some(Ok(item)) => EncodedStep::Yielded(encode(item)),
                Some(Err(error)) => EncodedStep::Failed(marshal::error::to_ffi(&error)),
                None => EncodedStep::Ended,
            }));
            match encoded {
                Ok(EncodedStep::Yielded(item)) => {
                    std::ptr::write(out_item, item);
                    ffi::StreamStep::Yielded
                }
                Ok(EncodedStep::Failed(error)) => {
                    std::ptr::write(out_error, error);
                    state.terminal = true;
                    ffi::StreamStep::Failed
                }
                Ok(EncodedStep::Ended) => {
                    state.terminal = true;
                    ffi::StreamStep::Ended
                }
                Err(_) => {
                    std::ptr::write(
                        out_error,
                        marshal::error::to_ffi(&Error::new(ErrorCode::Internal, panic_message)),
                    );
                    state.terminal = true;
                    ffi::StreamStep::Failed
                }
            }
        }
    }

    unsafe fn drop_state<T: 'static>(state: *mut core::ffi::c_void, what: &'static str) {
        guard_drop(what, || unsafe {
            let _ = Box::from_raw(state as *mut StreamState<T>);
        });
    }

    /// Convert `crate::AuthEventStream` → `ffi::AuthEventStream` while
    /// retaining the cancellation guard for the stream's lifetime: an
    /// interactive auth flow parks inside the stream, and the guard is what
    /// keeps a host cancel able to wake the plugin-local token that stream
    /// polls.
    pub fn auth_event_stream_to_ffi_with_cancel(
        stream: crate::AuthEventStream,
        cancel_guard: Option<ffi::CancelTokenLocal>,
    ) -> ffi::AuthEventStream {
        let outer: Box<StreamState<crate::AuthEvent>> = Box::new(StreamState {
            iter: stream,
            terminal: false,
            _cancel_guard: cancel_guard,
        });
        ffi::AuthEventStream {
            state: Box::into_raw(outer) as *mut core::ffi::c_void,
            next_fn: auth_event_next_thunk,
            drop_fn: auth_event_drop_thunk,
        }
    }

    // `next_fn` slot of the auth-event change stream's type-erased state vtable;
    // called through the `AuthEventStream` pointer, never by C symbol name.
    /// cbindgen:ignore
    unsafe extern "C" fn auth_event_next_thunk(
        state: *mut core::ffi::c_void,
        out_item: *mut ffi::AuthEvent,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            next(
                state,
                out_item,
                out_error,
                "plugin panicked iterating or encoding an AuthEventStream",
                marshal::auth::auth_event_to_ffi,
            )
        }
    }

    // `drop_fn` slot of the auth-event change stream's type-erased state vtable;
    // called through the `AuthEventStream` pointer to free its erased state.
    /// cbindgen:ignore
    unsafe extern "C" fn auth_event_drop_thunk(state: *mut core::ffi::c_void) {
        unsafe { drop_state::<crate::AuthEvent>(state, "AuthEventStream") };
    }

    /// Convert `crate::BackendChangeStream` to its FFI shape while retaining
    /// the cancellation guard for the stream's lifetime.
    pub fn change_stream_to_ffi_with_cancel(
        stream: crate::BackendChangeStream,
        cancel_guard: Option<ffi::CancelTokenLocal>,
    ) -> ffi::BackendChangeStream {
        let outer: Box<StreamState<crate::BackendChangeEvent>> = Box::new(StreamState {
            iter: stream,
            terminal: false,
            _cancel_guard: cancel_guard,
        });
        ffi::BackendChangeStream {
            state: Box::into_raw(outer) as *mut core::ffi::c_void,
            next_fn: change_next_thunk,
            drop_fn: change_drop_thunk,
        }
    }

    // `next_fn` slot of the directory `BackendChangeStream`'s type-erased state
    // vtable; called through the stream pointer, never by C symbol name.
    /// cbindgen:ignore
    unsafe extern "C" fn change_next_thunk(
        state: *mut core::ffi::c_void,
        out_item: *mut ffi::BackendChangeEvent,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            next(
                state,
                out_item,
                out_error,
                "plugin panicked iterating or encoding a BackendChangeStream",
                marshal::change::backend_change_event_to_ffi,
            )
        }
    }

    // `drop_fn` slot of the directory `BackendChangeStream`'s type-erased state
    // vtable; called through the stream pointer to free its erased state.
    /// cbindgen:ignore
    unsafe extern "C" fn change_drop_thunk(state: *mut core::ffi::c_void) {
        unsafe { drop_state::<crate::BackendChangeEvent>(state, "BackendChangeStream") };
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encoding_panic_becomes_terminal_internal_error() {
            let state = Box::new(StreamState {
                iter: Box::new(std::iter::once(Ok(7_i32))),
                terminal: false,
                _cancel_guard: None,
            });
            let state = Box::into_raw(state) as *mut core::ffi::c_void;
            let mut item = std::mem::MaybeUninit::<i32>::uninit();
            let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();
            let step = unsafe {
                next(
                    state,
                    item.as_mut_ptr(),
                    error.as_mut_ptr(),
                    "conversion panic",
                    |_: i32| -> i32 { panic!("encode failed") },
                )
            };
            assert_eq!(step, ffi::StreamStep::Failed);
            let error = unsafe { marshal::error::from_ffi(error.assume_init()) };
            assert_eq!(error.code(), ErrorCode::Internal);
            assert_eq!(error.message(), "conversion panic");

            let mut terminal_error = std::mem::MaybeUninit::<ffi::Error>::uninit();
            let step = unsafe {
                next(
                    state,
                    item.as_mut_ptr(),
                    terminal_error.as_mut_ptr(),
                    "unused",
                    |item| item,
                )
            };
            assert_eq!(step, ffi::StreamStep::Ended);
            unsafe { drop_state::<i32>(state, "test stream") };
        }
    }
}

#[cfg(test)]
mod cancel_tests {
    use super::*;

    /// `user_data` for [`capture_completion`]: the channel the host end of a
    /// completion reports on.
    type CompletionSink = std::sync::mpsc::Sender<Result<(), Error>>;

    /// Stands in for the host's completion trampoline, reclaiming the error
    /// envelope exactly as `loaded_v2::LoadedV2Layer` does — through
    /// `abi_unbox`, which is what makes the producer's mint side load-bearing.
    extern "C" fn capture_completion(
        _status: i32,
        _result: *mut core::ffi::c_void,
        error: *mut ffi::Error,
        user_data: *mut core::ffi::c_void,
    ) {
        // SAFETY: `user_data` is the `CompletionSink` the caller leaked below,
        // and the callback fires at most once per spawn.
        let sink = unsafe { &*(user_data as *const CompletionSink) };
        let outcome = if error.is_null() {
            Ok(())
        } else {
            // SAFETY: a non-null error envelope is an ABI-heap allocation the
            // consumer owns, per the slot contract.
            Err(unsafe { marshal::error::from_ffi(ffi::abi_alloc::abi_unbox(error)) })
        };
        sink.send(outcome).expect("send thunk outcome");
    }

    #[test]
    fn eager_future_construction_panic_fires_internal_error() {
        let (sender, receiver) = std::sync::mpsc::channel();
        // Leaked so the pointer stays valid for however long the spawned task
        // takes; one `Sender` per test run.
        let sink: &'static CompletionSink = Box::leak(Box::new(sender));
        spawn_async_thunk(
            "eager-panic",
            None,
            capture_completion,
            sink as *const CompletionSink as *mut core::ffi::c_void,
            |_| -> Pin<Box<dyn std::future::Future<Output = crate::Result<()>> + Send>> {
                panic!("future construction failed")
            },
            |()| None,
        );
        let error = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("callback must fire")
            .expect_err("panic must become an error");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert!(error.message().contains("eager-panic"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ParkedWatchStream {
        yielded_first: bool,
        cancel: tokio_util::sync::CancellationToken,
        dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Iterator for ParkedWatchStream {
        type Item = Result<crate::BackendChangeEvent, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            if !self.yielded_first {
                self.yielded_first = true;
                return Some(Ok(crate::BackendChangeEvent::Object {
                    address: crate::Url::parse("test://root/a.bin").unwrap(),
                    kind: crate::ChangeKind::Created,
                    etag: None,
                    version: None,
                    size: None,
                    mtime: None,
                    at: marshal::primitive::system_time_from_unix_ms(1_700_000_000_000),
                    cursor: crate::WatchDirectoryCursor(vec![1]),
                }));
            }
            loop {
                if self.cancel.is_cancelled() {
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    }

    impl Drop for ParkedWatchStream {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retained_guard_lets_host_cancel_unblock_parked_next() {
        use std::sync::atomic::Ordering;

        let host_token = tokio_util::sync::CancellationToken::new();
        let handle = ffi::cancel_token_to_ffi(host_token.clone());
        let local = ffi::cancel_token_from_ffi(unsafe { &*handle.as_ffi_ptr() });

        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let plugin_iter: crate::BackendChangeStream = Box::new(ParkedWatchStream {
            yielded_first: false,
            cancel: local.token_clone(),
            dropped: dropped.clone(),
        });
        let ffi_stream = stream::change_stream_to_ffi_with_cancel(plugin_iter, Some(local));
        let host_iter = unsafe { marshal::change::BackendChangeStream::from_ffi(ffi_stream) };
        let mut guarded = marshal::change::CancelGuardedChangeStream::new(host_iter, Some(handle));

        let (tx, rx) = std::sync::mpsc::channel();
        let puller = std::thread::spawn(move || {
            let first = guarded.next();
            tx.send(("first", first.is_some())).unwrap();
            let second = guarded.next();
            tx.send(("second", second.is_some())).unwrap();
            guarded
        });

        let (which, some) = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(which, "first");
        assert!(some, "first pull should yield the scripted event");

        host_token.cancel();
        let (which, some) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("parked next() did not unblock after host cancel (cancel regression)");
        assert_eq!(which, "second");
        assert!(!some, "parked next() must return None once cancelled");

        let guarded = puller.join().unwrap();
        assert!(!dropped.load(Ordering::SeqCst));
        drop(guarded);
        assert!(dropped.load(Ordering::SeqCst));
    }
}
