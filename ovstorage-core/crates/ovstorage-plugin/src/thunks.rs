// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Generic FFI vtable thunks shared by every plugin.
//!
//! Async I/O slots are callback-shaped: the thunk converts inputs
//! synchronously, spawns the work on the plugin's runtime, and fires
//! `on_complete` exactly once when the future completes (success,
//! error, panic, or cancellation).
//!
//! # Ownership
//!
//! `factory_state` and backend-instance state are
//! `Box<Arc<dyn ...>>::into_raw` pointers — the outer Box keeps the
//! canonical handle; the inner Arc clones into spawned tasks. The
//! drop thunks reclaim via `Box::from_raw`. Sync-slot `*mut Error`
//! returns and async `on_complete` payloads are both heap-allocated
//! by the producer and reclaimed by the receiver.
//!
//! # Panic safety
//!
//! Every spawned task wraps its await in `AssertUnwindSafe(...).
//! catch_unwind()` so a plugin panic surfaces as
//! `ErrorCode::Internal` via `on_complete` rather than leaving the
//! host trampoline parked on its oneshot.

use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use futures::FutureExt;
use tracing::{Instrument, debug_span, error};

use crate::ffi;
use crate::shim::{self, Backend, Factory};
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

// ---------------------------------------------------------------------
// Static vtables
// ---------------------------------------------------------------------

/// Process-wide factory vtable referenced from
/// `ovstorage_plugin_init_v1`.
pub static FACTORY_VTABLE: ffi::BackendFactoryVTableV1 = ffi::BackendFactoryVTableV1 {
    struct_size: std::mem::size_of::<ffi::BackendFactoryVTableV1>(),
    drop: factory_drop_thunk,
    descriptor: factory_descriptor_thunk,
    instantiate: factory_instantiate_thunk,
    update_credentials: factory_update_credentials_thunk,
    authenticate: factory_authenticate_thunk,
    _reserved: [None; 16],
};

/// Process-wide backend vtable. Instantiate hands this pointer back
/// inside every `ffi::BackendInstance`.
pub static BACKEND_VTABLE: ffi::BackendVTableV1 = ffi::BackendVTableV1 {
    struct_size: std::mem::size_of::<ffi::BackendVTableV1>(),
    drop: backend_drop_thunk,
    stat: backend_stat_thunk,
    read: backend_read_thunk,
    write: backend_write_thunk,
    write_stream: backend_write_stream_thunk,
    write_redirect: backend_write_redirect_thunk,
    continue_write: backend_continue_write_thunk,
    delete: backend_delete_thunk,
    list: backend_list_thunk,
    list_versions: backend_list_versions_thunk,
    get_latest_version: backend_get_latest_version_thunk,
    watch_directory: backend_watch_directory_thunk,
    create_directory: backend_create_directory_thunk,
    delete_directory: backend_delete_directory_thunk,
    copy: backend_copy_thunk,
    rename: backend_rename_thunk,
    update_metadata: backend_update_metadata_thunk,
    check_access: backend_check_access_thunk,
    watch_address_roots: backend_watch_address_roots_thunk,
    _reserved: [None; 16],
};

// ---------------------------------------------------------------------
// Sync helpers
// ---------------------------------------------------------------------

/// Wrap a sync user-trait call in `catch_unwind`, write the success
/// value to the out-pointer if any, and return `*mut ffi::Error`
/// (null on success). Used by the sync `descriptor` slot.
fn run_sync_thunk<F, R>(op: &'static str, body: F, write_ok: impl FnOnce(R)) -> *mut ffi::Error
where
    F: FnOnce() -> Result<R, Error>,
{
    let span = debug_span!("plugin.thunk_sync", op = op);
    let _enter = span.enter();
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => {
            write_ok(value);
            std::ptr::null_mut()
        }
        Ok(Err(error)) => allocate_error(error),
        Err(_) => {
            error!(op = op, error.code = ?ErrorCode::Internal, "plugin thunk panicked");
            allocate_error(Error::new(
                ErrorCode::Internal,
                format!("plugin panicked in thunk: {op}"),
            ))
        }
    }
}

/// Allocate an FFI error on the heap and return its pointer.
fn allocate_error(error: Error) -> *mut ffi::Error {
    Box::into_raw(Box::new(shim::error::to_ffi(&error)))
}

/// All error paths return [`ffi::FFI_STATUS_ERR`]; status `0` is
/// reserved for success because `ErrorCode::NotFound = 0` would
/// otherwise collide.
fn error_status(_code: ErrorCode) -> i32 {
    ffi::FFI_STATUS_ERR
}

// ---------------------------------------------------------------------
// Async helpers (callback-shaped thunks)
// ---------------------------------------------------------------------

/// `Send` wrapper around the opaque `user_data` pointer so it crosses
/// `tokio::spawn`'s bound. The pointer is only ever passed through.
struct SendUserData(*mut core::ffi::c_void);
unsafe impl Send for SendUserData {}

/// Materialize a `CancelTokenLocal` from a borrowed FFI handle, or
/// `None` for null. Drop decrements the shared refcount.
fn local_cancel(cancel: *const ffi::CancelTokenFFI) -> Option<ffi::CancelTokenLocal> {
    if cancel.is_null() {
        None
    } else {
        // SAFETY: non-null `cancel` is valid for this call's prologue.
        Some(ffi::cancel_token_from_ffi(unsafe { &*cancel }))
    }
}

/// Spawn an async thunk wrapping panic-safety + cancel guard + outcome
/// dispatch. `make_future` builds the SPI call; `fire` runs the FFI
/// callback per outcome.
fn spawn_async_thunk<R, MakeFut, Fire>(
    op: &'static str,
    cancel_local: Option<ffi::CancelTokenLocal>,
    user_data: *mut core::ffi::c_void,
    make_future: MakeFut,
    fire: Fire,
) where
    MakeFut: FnOnce(
            Option<tokio_util::sync::CancellationToken>,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<R, Error>> + Send>>
        + Send
        + 'static,
    Fire: FnOnce(Result<R, Error>, *mut core::ffi::c_void) + Send + 'static,
    R: Send + 'static,
{
    let cancel_token = cancel_local.as_ref().map(|c| c.token_clone());
    let user_data_send = SendUserData(user_data);
    let span = debug_span!("plugin.thunk_async", op = op);
    runtime().spawn(
        async move {
            // Hold the cancel guard for the work; drop on task exit
            // unregisters and decrements the shared refcount.
            let _cancel_guard = cancel_local;
            let user_data_send = user_data_send;
            // The workspace builds with `panic = "abort"`, so the panic
            // arm below is unreachable for first-party plugins. Retained
            // as defense in depth for a foreign plugin compiled with
            // `panic = "unwind"`: unwinding across the C ABI frame stack
            // would be UB; `catch_unwind` converts to `Err(Internal)`.
            let outcome = AssertUnwindSafe(make_future(cancel_token))
                .catch_unwind()
                .await;
            let user_data = user_data_send.0;
            match outcome {
                Ok(result) => fire(result, user_data),
                Err(_panic) => {
                    error!(op = op, error.code = ?ErrorCode::Internal, "plugin thunk panicked");
                    let e = Error::new(
                        ErrorCode::Internal,
                        format!("plugin panicked inside async thunk: {op}"),
                    );
                    fire(Err(e), user_data);
                }
            }
        }
        .instrument(span),
    );
}

/// Fire a sync-prologue error: callback receives `(status, null, error_box, user_data)`.
fn fire_unit_error(
    e: Error,
    on_complete: ffi::BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
) {
    let status = error_status(e.code());
    let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
    on_complete(status, err_ptr, user_data);
}

// ---------------------------------------------------------------------
// Stream Rust-to-FFI helpers
// ---------------------------------------------------------------------

mod stream {
    //! Wrap a Rust iterator as the matching FFI stream shape
    //! (`AuthEventStream` / `BackendChangeStream`).

    use super::*;

    // The `terminal` latch defends the `ffi::StreamStep` contract on
    // the plugin side: once we return `Failed` / `Ended`, subsequent
    // `next_fn` calls short-circuit even if the underlying iterator
    // would yield more. Prevents a misbehaving iterator from leaking
    // post-Failed items through the C ABI.

    struct AuthEventState {
        iter: crate::AuthEventStream,
        terminal: bool,
    }

    /// Convert `crate::AuthEventStream` → `ffi::AuthEventStream`.
    pub fn auth_event_stream_to_ffi(stream: crate::AuthEventStream) -> ffi::AuthEventStream {
        let outer: Box<AuthEventState> = Box::new(AuthEventState {
            iter: stream,
            terminal: false,
        });
        ffi::AuthEventStream {
            state: Box::into_raw(outer) as *mut core::ffi::c_void,
            next_fn: auth_event_next_thunk,
            drop_fn: auth_event_drop_thunk,
        }
    }

    unsafe extern "C" fn auth_event_next_thunk(
        state: *mut core::ffi::c_void,
        out_item: *mut ffi::AuthEvent,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            let s = &mut *(state as *mut AuthEventState);
            if s.terminal {
                return ffi::StreamStep::Ended;
            }
            match std::panic::catch_unwind(AssertUnwindSafe(|| s.iter.next())) {
                Ok(Some(Ok(event))) => {
                    std::ptr::write(out_item, shim::auth::auth_event_to_ffi(event));
                    ffi::StreamStep::Yielded
                }
                Ok(Some(Err(error))) => {
                    std::ptr::write(out_error, shim::error::to_ffi(&error));
                    s.terminal = true;
                    ffi::StreamStep::Failed
                }
                Ok(None) => {
                    s.terminal = true;
                    ffi::StreamStep::Ended
                }
                Err(_) => {
                    std::ptr::write(
                        out_error,
                        shim::error::to_ffi(&Error::new(
                            ErrorCode::Internal,
                            "plugin panicked iterating an AuthEventStream",
                        )),
                    );
                    s.terminal = true;
                    ffi::StreamStep::Failed
                }
            }
        }
    }

    unsafe extern "C" fn auth_event_drop_thunk(state: *mut core::ffi::c_void) {
        unsafe {
            let _ = Box::from_raw(state as *mut AuthEventState);
        }
    }

    struct BackendChangeState {
        iter: crate::BackendChangeStream,
        terminal: bool,
    }

    /// Convert `crate::BackendChangeStream` → `ffi::BackendChangeStream`.
    pub fn change_stream_to_ffi(stream: crate::BackendChangeStream) -> ffi::BackendChangeStream {
        let outer: Box<BackendChangeState> = Box::new(BackendChangeState {
            iter: stream,
            terminal: false,
        });
        ffi::BackendChangeStream {
            state: Box::into_raw(outer) as *mut core::ffi::c_void,
            next_fn: change_next_thunk,
            drop_fn: change_drop_thunk,
        }
    }

    unsafe extern "C" fn change_next_thunk(
        state: *mut core::ffi::c_void,
        out_item: *mut ffi::BackendChangeEvent,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            let s = &mut *(state as *mut BackendChangeState);
            if s.terminal {
                return ffi::StreamStep::Ended;
            }
            match std::panic::catch_unwind(AssertUnwindSafe(|| s.iter.next())) {
                Ok(Some(Ok(event))) => {
                    std::ptr::write(out_item, shim::change::backend_change_event_to_ffi(event));
                    ffi::StreamStep::Yielded
                }
                Ok(Some(Err(error))) => {
                    std::ptr::write(out_error, shim::error::to_ffi(&error));
                    s.terminal = true;
                    ffi::StreamStep::Failed
                }
                Ok(None) => {
                    s.terminal = true;
                    ffi::StreamStep::Ended
                }
                Err(_) => {
                    std::ptr::write(
                        out_error,
                        shim::error::to_ffi(&Error::new(
                            ErrorCode::Internal,
                            "plugin panicked iterating a BackendChangeStream",
                        )),
                    );
                    s.terminal = true;
                    ffi::StreamStep::Failed
                }
            }
        }
    }

    unsafe extern "C" fn change_drop_thunk(state: *mut core::ffi::c_void) {
        unsafe {
            let _ = Box::from_raw(state as *mut BackendChangeState);
        }
    }

    struct AddressRootsState {
        stream: crate::BackendAddressRootsStream,
        terminal: bool,
    }

    /// Convert `crate::BackendAddressRootsStream` → `ffi::BackendAddressRootsStream`.
    /// Each `next_fn` call drives the async stream once on the plugin
    /// runtime via `block_on`; the wrapper waits for the next pushed
    /// frame, matching the SPI's "park until the connection produces
    /// a frame" semantics.
    pub fn address_roots_stream_to_ffi(
        stream: crate::BackendAddressRootsStream,
    ) -> ffi::BackendAddressRootsStream {
        let outer: Box<AddressRootsState> = Box::new(AddressRootsState {
            stream,
            terminal: false,
        });
        ffi::BackendAddressRootsStream {
            state: Box::into_raw(outer) as *mut core::ffi::c_void,
            next_fn: address_roots_next_thunk,
            drop_fn: address_roots_drop_thunk,
        }
    }

    unsafe extern "C" fn address_roots_next_thunk(
        state: *mut core::ffi::c_void,
        out_item: *mut ffi::BackendAddressRootsChange,
        out_error: *mut ffi::Error,
    ) -> ffi::StreamStep {
        unsafe {
            let s = &mut *(state as *mut AddressRootsState);
            if s.terminal {
                return ffi::StreamStep::Ended;
            }
            let pulled = std::panic::catch_unwind(AssertUnwindSafe(|| {
                use futures::StreamExt;
                runtime().block_on(s.stream.next())
            }));
            match pulled {
                Ok(Some(Ok(change))) => {
                    std::ptr::write(out_item, shim::change::address_roots_change_to_ffi(change));
                    ffi::StreamStep::Yielded
                }
                Ok(Some(Err(error))) => {
                    std::ptr::write(out_error, shim::error::to_ffi(&error));
                    s.terminal = true;
                    ffi::StreamStep::Failed
                }
                Ok(None) => {
                    s.terminal = true;
                    ffi::StreamStep::Ended
                }
                Err(_) => {
                    std::ptr::write(
                        out_error,
                        shim::error::to_ffi(&Error::new(
                            ErrorCode::Internal,
                            "plugin panicked iterating a BackendAddressRootsStream",
                        )),
                    );
                    s.terminal = true;
                    ffi::StreamStep::Failed
                }
            }
        }
    }

    unsafe extern "C" fn address_roots_drop_thunk(state: *mut core::ffi::c_void) {
        unsafe {
            let _ = Box::from_raw(state as *mut AddressRootsState);
        }
    }
}

// ---------------------------------------------------------------------
// Factory thunks
// ---------------------------------------------------------------------

/// Cast factory state pointer back to `&Arc<dyn Factory>`.
unsafe fn factory_ref<'a>(state: *mut core::ffi::c_void) -> &'a Arc<dyn Factory> {
    unsafe { &*(state as *const Arc<dyn Factory>) }
}

/// Clone the factory's `Arc` for shared ownership across a spawned
/// task. The outer Box keeps the canonical handle alive; this produces
/// an additional reference whose lifetime is independent of the FFI
/// call's synchronous prologue.
unsafe fn clone_factory_arc(state: *mut core::ffi::c_void) -> Arc<dyn Factory> {
    unsafe { Arc::clone(&*(state as *const Arc<dyn Factory>)) }
}

unsafe extern "C" fn factory_drop_thunk(state: *mut core::ffi::c_void) {
    unsafe {
        if state.is_null() {
            return;
        }
        let _ = Box::from_raw(state as *mut Arc<dyn Factory>);
    }
}

unsafe extern "C" fn factory_descriptor_thunk(
    state: *mut core::ffi::c_void,
    out: *mut ffi::StorageBackendKindDescriptor,
) -> *mut ffi::Error {
    unsafe {
        run_sync_thunk(
            "descriptor",
            || Ok::<_, Error>(factory_ref(state).descriptor()),
            |descriptor| {
                std::ptr::write(
                    out,
                    shim::descriptor::storage_backend_kind_descriptor_to_ffi(descriptor),
                )
            },
        )
    }
}

unsafe extern "C" fn factory_instantiate_thunk(
    state: *mut core::ffi::c_void,
    request: *const ffi::ConnectionRequest,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::FactoryInstantiateCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        shim::descriptor::connection_request_from_ffi(std::ptr::read(request))
    }));
    let request = match prologue {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let status = error_status(e.code());
            let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
            on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            return;
        }
        Err(_) => {
            let e = Error::new(
                ErrorCode::Internal,
                "plugin panicked in Factory::instantiate prologue",
            );
            let status = error_status(e.code());
            let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
            on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            return;
        }
    };
    let factory = unsafe { clone_factory_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "instantiate",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let factory = factory;
                factory.instantiate(&request, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(instance) => {
                let result_ptr = Box::into_raw(Box::new(backend_instance_to_ffi(instance)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn factory_update_credentials_thunk(
    state: *mut core::ffi::c_void,
    connection: *const ffi::Connection,
    credentials: *const ffi::SecretBundle,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let connection = shim::auth::connection_from_ffi(std::ptr::read(connection))?;
            let credentials =
                shim::descriptor::secret_bundle_from_ffi(std::ptr::read(credentials))?;
            Ok((connection, credentials))
        }
    }));
    let (connection, credentials) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return fire_unit_error(e, on_complete, user_data),
        Err(_) => {
            return fire_unit_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Factory::update_credentials prologue",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let factory = unsafe { clone_factory_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "update_credentials",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let factory = factory;
                factory
                    .update_credentials(&connection, credentials, cancel_token)
                    .await
            })
        },
        move |result, user_data| match result {
            Ok(()) => on_complete(0, std::ptr::null_mut(), user_data),
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn factory_authenticate_thunk(
    state: *mut core::ffi::c_void,
    connection: *const ffi::Connection,
    capability: ffi::InteractiveAuthCapabilityV1,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::FactoryAuthenticateCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        shim::auth::connection_from_ffi(std::ptr::read(connection))
    }));
    let connection = match prologue {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            let status = error_status(e.code());
            let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
            on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            return;
        }
        Err(_) => {
            let e = Error::new(
                ErrorCode::Internal,
                "plugin panicked in Factory::authenticate prologue",
            );
            let status = error_status(e.code());
            let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
            on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            return;
        }
    };
    let capability = shim::auth::interactive_auth_capability_from_ffi(capability);
    let factory = unsafe { clone_factory_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "authenticate",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let factory = factory;
                factory
                    .authenticate(connection, capability, cancel_token)
                    .await
            })
        },
        move |result, user_data| match result {
            Ok(stream) => {
                let result_ptr = Box::into_raw(Box::new(stream::auth_event_stream_to_ffi(stream)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

fn backend_instance_to_ffi(instance: shim::BackendInstance) -> ffi::BackendInstance {
    let backend_arc: Arc<dyn Backend> = instance.backend;
    let outer: Box<Arc<dyn Backend>> = Box::new(backend_arc);
    ffi::BackendInstance {
        backend_id: shim::address::backend_id_to_ffi(instance.backend_id),
        backend: ffi::BackendHandle {
            state: Box::into_raw(outer) as *mut core::ffi::c_void,
            vtable: &BACKEND_VTABLE,
        },
        address_roots: shim::primitive::list_to_ffi(
            instance.address_roots,
            shim::address::address_root_entry_to_ffi,
        ),
        display_name: shim::primitive::optional_to_ffi(
            instance.display_name,
            shim::primitive::str_to_ffi,
        ),
        auth_state: shim::auth::connection_auth_state_to_ffi(instance.auth_state),
    }
}

// ---------------------------------------------------------------------
// Backend thunks
// ---------------------------------------------------------------------

/// Clone the backend's `Arc` for shared ownership across a spawned task.
unsafe fn clone_backend_arc(state: *mut core::ffi::c_void) -> Arc<dyn Backend> {
    unsafe { Arc::clone(&*(state as *const Arc<dyn Backend>)) }
}

unsafe extern "C" fn backend_drop_thunk(state: *mut core::ffi::c_void) {
    unsafe {
        if state.is_null() {
            return;
        }
        let _ = Box::from_raw(state as *mut Arc<dyn Backend>);
    }
}

unsafe extern "C" fn backend_stat_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::StatOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendStatCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts = shim::options::stat_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::StatOptions,
            >(opts, "StatOptions")?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::stat prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "stat",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.stat(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(info) => {
                let result_ptr = Box::into_raw(Box::new(shim::metadata::object_info_to_ffi(info)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

/// Helper for firing an Err synchronously through a method-specific
/// callback. The caller binds the typed callback shape via a closure.
fn fire_typed_error<F: FnOnce(i32, *mut ffi::Error)>(e: Error, fire: F) {
    let status = error_status(e.code());
    let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
    fire(status, err_ptr);
}

unsafe extern "C" fn backend_read_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::ReadOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendReadCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts = shim::options::read_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::ReadOptions,
            >(opts, "ReadOptions")?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::read prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "read",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.read(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(r) => {
                let result_ptr = Box::into_raw(Box::new(shim::payload::read_result_to_ffi(r)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_write_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    bytes: *const ffi::Bytes,
    opts: *const ffi::WriteOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWriteCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let bytes = shim::primitive::bytes_from_ffi(std::ptr::read(bytes));
            let opts = shim::options::write_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::WriteOptions,
            >(opts, "WriteOptions")?)?;
            Ok((target, bytes, opts))
        }
    }));
    let (target, bytes, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::write prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "write",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.write(target, bytes, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(r) => {
                let result_ptr = Box::into_raw(Box::new(shim::payload::write_result_to_ffi(r)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_write_stream_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    body: *const ffi::BodyStream,
    opts: *const ffi::WriteOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWriteCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let stream = shim::payload::body_stream_from_ffi(std::ptr::read(body));
            let opts = shim::options::write_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::WriteOptions,
            >(opts, "WriteOptions")?)?;
            Ok((target, stream, opts))
        }
    }));
    let (target, stream, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::write_stream prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "write_stream",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend
                    .write_stream(target, stream, opts, cancel_token)
                    .await
            })
        },
        move |result, user_data| match result {
            Ok(r) => {
                let result_ptr = Box::into_raw(Box::new(shim::payload::write_result_to_ffi(r)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_write_redirect_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::WriteOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWriteRedirectCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts = shim::options::write_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::WriteOptions,
            >(opts, "WriteOptions")?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::write_redirect prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "write_redirect",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.write_redirect(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(batch) => {
                let result_ptr =
                    Box::into_raw(Box::new(shim::redirect::write_redirect_batch_to_ffi(batch)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_continue_write_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    redirects: *const ffi::WriteRedirectBatch,
    results: *const ffi::RedirectResultBatch,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWriteStepCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let redirects =
                shim::redirect::write_redirect_batch_from_ffi(std::ptr::read(redirects))?;
            let results = shim::redirect::redirect_result_batch_from_ffi(std::ptr::read(results))?;
            Ok((target, redirects, results))
        }
    }));
    let (target, redirects, results) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::continue_write prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "continue_write",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend
                    .continue_write(target, redirects, results, cancel_token)
                    .await
            })
        },
        move |result, user_data| match result {
            Ok(step) => {
                let result_ptr = Box::into_raw(Box::new(shim::payload::write_step_to_ffi(step)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_delete_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::DeleteOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts =
                shim::options::delete_options_from_ffi(ffi::read_options_at_ptr::<
                    ffi::DeleteOptions,
                >(opts, "DeleteOptions")?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return fire_unit_error(e, on_complete, user_data),
        Err(_) => {
            return fire_unit_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::delete prologue",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "delete",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.delete(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(()) => on_complete(0, std::ptr::null_mut(), user_data),
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_list_thunk(
    state: *mut core::ffi::c_void,
    prefix: *const ffi::ResolvedTarget,
    opts: *const ffi::ListOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendListCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let prefix = shim::address::resolved_target_from_ffi(std::ptr::read(prefix))?;
            let opts = shim::options::list_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::ListOptions,
            >(opts, "ListOptions")?)?;
            Ok((prefix, opts))
        }
    }));
    let (prefix, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::list prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "list",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.list(prefix, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(items) => {
                let list_ffi =
                    shim::primitive::list_to_ffi(items, shim::metadata::object_info_to_ffi);
                let result_ptr = Box::into_raw(Box::new(list_ffi));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_list_versions_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::ListVersionsOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendListVersionsCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts = shim::options::list_versions_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::ListVersionsOptions,
            >(
                opts,
                "ListVersionsOptions",
            )?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::list_versions prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "list_versions",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.list_versions(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(items) => {
                let list_ffi =
                    shim::primitive::list_to_ffi(items, shim::metadata::object_info_to_ffi);
                let result_ptr = Box::into_raw(Box::new(list_ffi));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_get_latest_version_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendGetLatestVersionCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe { shim::address::resolved_target_from_ffi(std::ptr::read(target)) }
    }));
    let target = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::get_latest_version prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "get_latest_version",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.get_latest_version(target, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(item) => {
                let result_ptr = Box::into_raw(Box::new(shim::metadata::object_info_to_ffi(item)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_watch_directory_thunk(
    state: *mut core::ffi::c_void,
    prefix: *const ffi::ResolvedTarget,
    opts: *const ffi::WatchDirectoryOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWatchDirectoryCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let prefix = shim::address::resolved_target_from_ffi(std::ptr::read(prefix))?;
            let opts =
                shim::options::watch_directory_options_from_ffi(ffi::read_options_at_ptr::<
                    ffi::WatchDirectoryOptions,
                >(
                    opts, "WatchDirectoryOptions"
                )?)?;
            Ok((prefix, opts))
        }
    }));
    let (prefix, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::watch_directory prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "watch_directory",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.watch_directory(prefix, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(stream) => {
                let result_ptr = Box::into_raw(Box::new(stream::change_stream_to_ffi(stream)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_watch_address_roots_thunk(
    state: *mut core::ffi::c_void,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWatchAddressRootsCallback,
    user_data: *mut core::ffi::c_void,
) {
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "watch_address_roots",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.watch_address_roots(cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(stream) => {
                let result_ptr =
                    Box::into_raw(Box::new(stream::address_roots_stream_to_ffi(stream)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_create_directory_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::CreateDirectoryOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendItemInfoCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts =
                shim::options::create_directory_options_from_ffi(ffi::read_options_at_ptr::<
                    ffi::CreateDirectoryOptions,
                >(
                    opts,
                    "CreateDirectoryOptions",
                )?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::create_directory prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "create_directory",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.create_directory(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(info) => {
                let result_ptr =
                    Box::into_raw(Box::new(shim::payload::backend_item_info_to_ffi(info)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_delete_directory_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::DeleteDirectoryOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts =
                shim::options::delete_directory_options_from_ffi(ffi::read_options_at_ptr::<
                    ffi::DeleteDirectoryOptions,
                >(
                    opts,
                    "DeleteDirectoryOptions",
                )?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return fire_unit_error(e, on_complete, user_data),
        Err(_) => {
            return fire_unit_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::delete_directory prologue",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "delete_directory",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.delete_directory(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(()) => on_complete(0, std::ptr::null_mut(), user_data),
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_copy_thunk(
    state: *mut core::ffi::c_void,
    src: *const ffi::ResolvedTarget,
    dest: *const ffi::ResolvedTarget,
    opts: *const ffi::CopyOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendWriteStepCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let src = shim::address::resolved_target_from_ffi(std::ptr::read(src))?;
            let dest = shim::address::resolved_target_from_ffi(std::ptr::read(dest))?;
            let opts = shim::options::copy_options_from_ffi(ffi::read_options_at_ptr::<
                ffi::CopyOptions,
            >(opts, "CopyOptions")?)?;
            Ok((src, dest, opts))
        }
    }));
    let (src, dest, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::copy prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "copy",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.copy(src, dest, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(step) => {
                let result_ptr = Box::into_raw(Box::new(shim::payload::write_step_to_ffi(step)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_rename_thunk(
    state: *mut core::ffi::c_void,
    src: *const ffi::ResolvedTarget,
    dest: *const ffi::ResolvedTarget,
    opts: *const ffi::RenameOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendUnitCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let src = shim::address::resolved_target_from_ffi(std::ptr::read(src))?;
            let dest = shim::address::resolved_target_from_ffi(std::ptr::read(dest))?;
            let opts =
                shim::options::rename_options_from_ffi(ffi::read_options_at_ptr::<
                    ffi::RenameOptions,
                >(opts, "RenameOptions")?)?;
            Ok((src, dest, opts))
        }
    }));
    let (src, dest, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return fire_unit_error(e, on_complete, user_data),
        Err(_) => {
            return fire_unit_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::rename prologue",
                ),
                on_complete,
                user_data,
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "rename",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.rename(src, dest, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(()) => on_complete(0, std::ptr::null_mut(), user_data),
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_update_metadata_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    opts: *const ffi::UpdateMetadataOptions,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendItemInfoCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let opts =
                shim::options::update_metadata_options_from_ffi(ffi::read_options_at_ptr::<
                    ffi::UpdateMetadataOptions,
                >(
                    opts, "UpdateMetadataOptions"
                )?)?;
            Ok((target, opts))
        }
    }));
    let (target, opts) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::update_metadata prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "update_metadata",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.update_metadata(target, opts, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(info) => {
                let result_ptr =
                    Box::into_raw(Box::new(shim::payload::backend_item_info_to_ffi(info)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

unsafe extern "C" fn backend_check_access_thunk(
    state: *mut core::ffi::c_void,
    target: *const ffi::ResolvedTarget,
    ops: *const ffi::AccessOps,
    cancel: *const ffi::CancelTokenFFI,
    on_complete: ffi::BackendCheckAccessCallback,
    user_data: *mut core::ffi::c_void,
) {
    let prologue = std::panic::catch_unwind(AssertUnwindSafe(|| -> Result<_, Error> {
        unsafe {
            let target = shim::address::resolved_target_from_ffi(std::ptr::read(target))?;
            let ops = shim::access::access_ops_from_ffi(std::ptr::read(ops));
            Ok((target, ops))
        }
    }));
    let (target, ops) = match prologue {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            return fire_typed_error(e, |s, e| on_complete(s, std::ptr::null_mut(), e, user_data));
        }
        Err(_) => {
            return fire_typed_error(
                Error::new(
                    ErrorCode::Internal,
                    "plugin panicked in Backend::check_access prologue",
                ),
                |s, e| on_complete(s, std::ptr::null_mut(), e, user_data),
            );
        }
    };
    let backend = unsafe { clone_backend_arc(state) };
    let cancel_local = local_cancel(cancel);
    spawn_async_thunk(
        "check_access",
        cancel_local,
        user_data,
        move |cancel_token| {
            Box::pin(async move {
                let backend = backend;
                backend.check_access(target, ops, cancel_token).await
            })
        },
        move |result, user_data| match result {
            Ok(decision) => {
                let result_ptr =
                    Box::into_raw(Box::new(shim::payload::access_decision_to_ffi(decision)));
                on_complete(0, result_ptr, std::ptr::null_mut(), user_data);
            }
            Err(e) => {
                let status = error_status(e.code());
                let err_ptr = Box::into_raw(Box::new(shim::error::to_ffi(&e)));
                on_complete(status, std::ptr::null_mut(), err_ptr, user_data);
            }
        },
    );
}

// ---------------------------------------------------------------------
// `Arc<dyn Factory>` builder used by the macro.
// ---------------------------------------------------------------------

/// Allocate a shared-ownership factory and return its
/// `factory_state` pointer. Invoked from
/// `ovstorage_plugin!`-generated init code.
pub fn leak_factory<F: Factory + 'static>(factory: F) -> *mut core::ffi::c_void {
    let arc: Arc<dyn Factory> = Arc::new(factory);
    let outer: Box<Arc<dyn Factory>> = Box::new(arc);
    Box::into_raw(outer) as *mut core::ffi::c_void
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_drop_thunk_handles_null() {
        unsafe { factory_drop_thunk(std::ptr::null_mut()) };
    }

    #[test]
    fn backend_drop_thunk_handles_null() {
        unsafe { backend_drop_thunk(std::ptr::null_mut()) };
    }

    #[test]
    fn stream_change_event_round_trip_preserves_iteration() {
        let events = vec![
            Ok(crate::BackendChangeEvent::Object {
                address: crate::Url::parse("test://root/a.bin").unwrap(),
                kind: crate::ChangeKind::Created,
                etag: None,
                version: None,
                size: None,
                mtime: None,
                at: shim::primitive::system_time_from_unix_ms(1_700_000_000_000),
                cursor: crate::WatchDirectoryCursor(vec![1]),
            }),
            Ok(crate::BackendChangeEvent::Lapsed {
                since: None,
                cursor: crate::WatchDirectoryCursor(vec![2]),
            }),
        ];
        let stream: crate::BackendChangeStream = Box::new(events.clone().into_iter());
        let ffi_stream = stream::change_stream_to_ffi(stream);

        let mut collected = Vec::new();
        loop {
            let mut item = std::mem::MaybeUninit::<ffi::BackendChangeEvent>::uninit();
            let mut error = std::mem::MaybeUninit::<ffi::Error>::uninit();
            let step = unsafe {
                (ffi_stream.next_fn)(ffi_stream.state, item.as_mut_ptr(), error.as_mut_ptr())
            };
            match step {
                ffi::StreamStep::Yielded => {
                    let event = unsafe { item.assume_init() };
                    let event =
                        unsafe { shim::change::backend_change_event_from_ffi(event) }.unwrap();
                    collected.push(event);
                }
                ffi::StreamStep::Ended => break,
                ffi::StreamStep::Failed => {
                    panic!("unexpected Failed");
                }
            }
        }
        drop(ffi_stream);

        let expected: Vec<crate::BackendChangeEvent> =
            events.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(collected, expected);
    }
}
