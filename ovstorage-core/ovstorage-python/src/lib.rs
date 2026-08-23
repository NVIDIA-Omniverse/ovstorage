// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
// pyo3 0.21 `#[pymethods]` emits unsafe ops inside `unsafe extern "C"` thunks; Rust 2024 lint fires once per method. Pinned-allow until a pyo3 bump.
#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::{CStr, c_void};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovs::auth::{CallbackCredentialProvider, CredentialError, PrincipalView, ResolvedCredential};
use ovs::{
    BackendId, Body, CancellationToken, DeleteOptions, Error as OvError, ErrorCode,
    InteractiveAuthCapability as RustInteractiveAuthCapability, ListOptions,
    LocalDelegate as RustLocalDelegate, ObjectInfo, ReadOptions, ReadStream,
    SecretBundle as RustSecretBundle, SecretBytes, SecretValue as RustSecretValue, StatOptions,
    WriteOptions, address,
};
// Trait-method scope only (`stack.add_connection` in the composer build);
// `ovs::Layer` stays path-qualified everywhere else.
use ovs::Layer as _;
use ovstorage_rust as ovs;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration};
use pyo3::prelude::*;
use pyo3::sync::GILOnceCell;
use pyo3::types::{
    PyByteArray, PyBytes, PyCapsule, PyDict, PyList, PyMapping, PyMemoryView, PyTuple,
};
use pyo3::{PyTraverseError, PyVisit};
use pyo3_async_runtimes::tokio as pyo3_tokio;
use tokio::sync::{Mutex as TokioMutex, mpsc};

mod auth_credential;
mod bridge_gil;
mod p2r_adapter;
mod p2r_body;
mod p2r_marshal;
mod p2r_stream;
mod py_address;

use auth_credential::{AuthCredential, NamedPipeTransport, TcpTransport, UdsTransport};

pyo3::create_exception!(ovstorage, Error, pyo3::exceptions::PyException);

// One base per `ErrorBucket` (ovstorage-layer errors.rs), each extending
// `Error`. Callers `isinstance`-match on these to handle a whole coarse
// taxonomy bucket (e.g. every retryable-transient code) without enumerating
// every per-code exception. Every per-code exception below is re-parented
// under the base for its `ErrorCode::bucket()`; the exhaustive
// `_error_bucket_pairs` gate (consumed by the Python test suite) fails if a
// per-code parent drifts from `bucket()`.
pyo3::create_exception!(ovstorage, NotFoundBucketError, Error);
pyo3::create_exception!(ovstorage, PermissionBucketError, Error);
pyo3::create_exception!(ovstorage, PreconditionBucketError, Error);
pyo3::create_exception!(ovstorage, InvalidBucketError, Error);
pyo3::create_exception!(ovstorage, TransientBucketError, Error);
pyo3::create_exception!(ovstorage, ResourceExhaustedBucketError, Error);
pyo3::create_exception!(ovstorage, UnsupportedBucketError, Error);
pyo3::create_exception!(ovstorage, CancelledBucketError, Error);
pyo3::create_exception!(ovstorage, InternalBucketError, Error);

// Per-code exceptions, parented under their `ErrorCode::bucket()` base.
pyo3::create_exception!(ovstorage, NotFoundError, NotFoundBucketError);
pyo3::create_exception!(ovstorage, AlreadyExistsError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, PermissionDeniedError, PermissionBucketError);
pyo3::create_exception!(ovstorage, PreconditionFailedError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, ConflictError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, DirectoryNotEmptyError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, UnsupportedError, UnsupportedBucketError);
pyo3::create_exception!(ovstorage, InvalidArgumentError, InvalidBucketError);
pyo3::create_exception!(ovstorage, IncompatibleTypeError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, LockedError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, CancelledError, CancelledBucketError);
pyo3::create_exception!(ovstorage, DeadlineExceededError, TransientBucketError);
pyo3::create_exception!(ovstorage, TransientError, TransientBucketError);
pyo3::create_exception!(
    ovstorage,
    ResourceExhaustedError,
    ResourceExhaustedBucketError
);
pyo3::create_exception!(ovstorage, IntegrityFailureError, InternalBucketError);
pyo3::create_exception!(ovstorage, InternalError, InternalBucketError);
pyo3::create_exception!(ovstorage, BrokerUnavailableError, TransientBucketError);
pyo3::create_exception!(ovstorage, BrokerRequiredError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, RedirectExpiredError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, PolicyEpochStaleError, PreconditionBucketError);
pyo3::create_exception!(
    ovstorage,
    AuthorizationLeaseExpiredError,
    TransientBucketError
);
pyo3::create_exception!(ovstorage, CacheCorruptError, InternalBucketError);
pyo3::create_exception!(ovstorage, StagingExpiredError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, CommitAmbiguousError, InternalBucketError);
// Base class follows the bucket: `PartialCompletion` is `ErrorBucket::Internal`,
// so it is non-retryable and not in the "it did not happen" family.
pyo3::create_exception!(ovstorage, PartialCompletionError, InternalBucketError);
pyo3::create_exception!(ovstorage, CacheLockContentionError, TransientBucketError);
pyo3::create_exception!(
    ovstorage,
    StateRootUnavailableError,
    PreconditionBucketError
);
pyo3::create_exception!(
    ovstorage,
    NetworkFilesystemRefusedError,
    InternalBucketError
);
pyo3::create_exception!(ovstorage, ObjectModifiedError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, NoRouteError, NotFoundBucketError);
pyo3::create_exception!(ovstorage, RouteConflictError, PreconditionBucketError);
pyo3::create_exception!(ovstorage, NotConfiguredError, NotFoundBucketError);
pyo3::create_exception!(ovstorage, AliasChainTooLongError, InvalidBucketError);
pyo3::create_exception!(ovstorage, CredentialExpiredError, PermissionBucketError);
pyo3::create_exception!(ovstorage, CredentialUnavailableError, PermissionBucketError);
pyo3::create_exception!(ovstorage, AuthRequiredError, PermissionBucketError);
pyo3::create_exception!(ovstorage, AuthCancelledError, PermissionBucketError);
pyo3::create_exception!(ovstorage, AuthExpiredError, PermissionBucketError);
pyo3::create_exception!(ovstorage, ContentMismatchError, PreconditionBucketError);
pyo3::create_exception!(
    ovstorage,
    ContentChecksumMismatchError,
    PreconditionBucketError
);
pyo3::create_exception!(ovstorage, PluginRejectedError, PermissionBucketError);

type AddressRootSnapshotReceiver = mpsc::Receiver<Result<Vec<ovs::AddressRoot>, OvError>>;

/// The credential bridge's spelling of "the interpreter is going away".
fn credential_shutdown() -> CredentialError {
    CredentialError::Backend(OvError::new(
        ErrorCode::Internal,
        "Python interpreter is finalizing; bridge dispatch is unavailable",
    ))
}

/// Deferred dispatch of one native operation.
///
/// Boxed so the generic future type stays inside the closure and
/// [`DeferredCall`] itself remains non-generic (a `#[pyclass]` cannot be).
/// `Send` because the closure owns the Rust future until it is spawned, and a
/// `#[pyclass]` must be `Send`; the elided lifetime binds higher-ranked, so the
/// closure accepts whatever GIL token `__call__` happens to hold.
///
/// The `Vec<PyObject>` is the closure's Python captures, handed back to it at
/// dispatch. See [`DeferredCall`] for why they travel beside the closure rather
/// than inside it.
type DeferredSpawn = Box<dyn FnOnce(Python<'_>, Vec<PyObject>) -> PyResult<PyObject> + Send>;

/// The one-shot callable handed to `ovstorage._async._dispatch`.
///
/// Calling it spawns the Rust future on the process tokio runtime and returns
/// the `asyncio.Future` that future resolves into. The closure is taken on the
/// first call, so a second call — a coroutine somehow driven twice — raises
/// instead of dispatching the same operation again.
///
/// **Python captures live in `captures`, never in the closure.** `Box<dyn
/// FnOnce>` is opaque, so a `Py<...>` the closure owned would be a strong
/// reference no visitor could reach, and lazy dispatch is what makes that
/// reachable at all: the closure outlives the call now, so a caller who roots
/// the coroutine on an object that same call captured — say `leaf.pending =
/// Stack(...).backend(leaf).build()` — closes a cycle through it. Before
/// laziness the spawn happened immediately and nothing held a caller's objects
/// past the call.
///
/// So the handles a call site would have captured are moved here instead, and
/// `__traverse__` reports exactly them. Each site takes them back as the
/// `Vec<PyObject>` argument at dispatch: `Stack.build` its declarations and an
/// explicit `loop=`, `update_connection_credentials` its `SecretValue` map,
/// `probe` its `ConnectionRequest`, `write_stream` its body object, and the two
/// body-channel gate probes their observed iterator. Every other deferred site
/// captures only Rust values.
///
/// **The rule for a new deferred call site: a Python handle the operation needs
/// at dispatch goes in `captures`, not in the closure.** Traversal cannot see
/// what the closure owns, and there is no compiler check for this — under-
/// reporting is safe (the collector treats the referent as externally reachable
/// and simply declines to collect the cycle, as it did before this existed) but
/// it silently restores the leak for that site.
///
/// What this does **not** reach, and deliberately: Python handles that live
/// inside `Arc`-shared Rust state rather than on a `#[pyclass]`. A layer handle
/// (`Arc<dyn Layer>`) whose composition contains a Python layer holds
/// `Py<PyAny>`; so does a built stack's credential resolver, which retains the
/// `credential_callback` for the life of the stack, so `self.stack = await
/// ovstorage.Stack(credential_callback=self.fetch, ...).build()` is a cycle no
/// collector can see.
///
/// Both are properties of the built objects rather than of deferral —
/// `LayerBase` holds the same `Arc` whether or not a call is in flight — and
/// neither is reachable by the pattern above. An `Arc` may be shared by several
/// `#[pyclass]` wrappers, and a `__traverse__` from each would report the same
/// reference more than once. Over-reporting is the direction that frees a live
/// object, so extending traversal into shared Rust state needs single ownership
/// established first, not another visit call.

#[pyclass]
struct DeferredCall {
    spawn: Option<DeferredSpawn>,
    captures: Vec<PyObject>,
}

#[pymethods]
impl DeferredCall {
    fn __call__(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let spawn = self.spawn.take().ok_or_else(|| {
            PyRuntimeError::new_err("ovstorage: native operation was already dispatched")
        })?;
        spawn(py, std::mem::take(&mut self.captures))
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        for capture in &self.captures {
            visit.call(capture)?;
        }
        Ok(())
    }

    /// Break the cycle by dropping the captures, and the closure with them.
    ///
    /// The closure is dropped rather than left callable because it is written
    /// to receive its captures back: handing it an emptied `Vec` would fail
    /// deep inside the operation instead of at the boundary. A `__call__` after
    /// this raises "already dispatched", which is the accurate thing to say
    /// about a coroutine the collector has taken apart.
    fn __clear__(&mut self) {
        self.captures.clear();
        self.spawn = None;
    }
}

/// The callables of the `ovstorage._async` shim, resolved once per process.
struct AsyncShim {
    dispatch: Py<PyAny>,
    ready: Py<PyAny>,
}

static ASYNC_SHIM: GILOnceCell<AsyncShim> = GILOnceCell::new();

/// The `ovstorage._async` shim, imported on first use and cached for the life
/// of the interpreter.
///
/// The import is lazy rather than done at module init: the shim is a submodule
/// of the package that re-exports this extension, so importing it eagerly from
/// `#[pymodule]` would run during our own initialization.
///
/// Returns the whole struct so callers name the field they want. Selecting by
/// string would need a fallback arm for a name that cannot occur, and the
/// compiler could not check the two call sites; a field access makes the
/// invalid case unrepresentable instead.
fn async_shim(py: Python<'_>) -> PyResult<&'static AsyncShim> {
    ASYNC_SHIM.get_or_try_init(py, || {
        let module = py.import_bound("ovstorage._async")?;
        Ok::<_, PyErr>(AsyncShim {
            dispatch: module.getattr("_dispatch")?.unbind(),
            ready: module.getattr("_ready")?.unbind(),
        })
    })
}

/// Present a deferred spawn to Python as a coroutine.
///
/// Dispatch is lazy: the returned coroutine calls `spawn` on its first step, so
/// a coroutine that is never awaited never reaches the Rust side, and — with
/// the default task factory — a task cancelled before the scheduler resumes it
/// leaves nothing running. `asyncio.eager_task_factory` takes that first step
/// inside `create_task`, so there the spawn has already happened.
///
/// `qualname` sets `__name__` (the leaf after the last `.`) and `__qualname__`
/// on the returned coroutine so that CPython's "never awaited" `RuntimeWarning`,
/// `repr()`, and task names identify the originating method rather than the
/// internal shim.
fn deferred_coroutine<'py>(
    py: Python<'py>,
    qualname: &str,
    captures: Vec<PyObject>,
    spawn: DeferredSpawn,
) -> PyResult<Bound<'py, PyAny>> {
    let deferred = Py::new(
        py,
        DeferredCall {
            spawn: Some(spawn),
            captures,
        },
    )?;
    let coro = async_shim(py)?.dispatch.bind(py).call1((deferred,))?;
    let name = qualname.rsplit_once('.').map_or(qualname, |(_, n)| n);
    coro.setattr("__name__", name)?;
    coro.setattr("__qualname__", qualname)?;
    Ok(coro)
}

/// Hand a Rust future to Python as a coroutine.
///
/// Every awaitable this extension exposes goes through here (or through
/// [`cancellable_coroutine_into_py`] / [`ready_coroutine`]), so that
/// `async def` in the type stubs is the truth and `asyncio.create_task`,
/// `asyncio.run_coroutine_threadsafe`, and `asyncio.iscoroutine` all work.
///
/// The deferred spawn goes through [`bridge_gil`], not the pyo3 helper
/// directly: deferring dispatch to the first step moves it later in the
/// process's life, not out of the pre-finalization fence's scope. The gate is
/// what refuses new work once the fence begins, and it must still be held
/// across publication at whatever moment the spawn actually happens.
fn coroutine_into_py<'py, F, T>(
    py: Python<'py>,
    qualname: &str,
    fut: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    deferred_coroutine(
        py,
        qualname,
        Vec::new(),
        Box::new(move |py, _captures| Ok(bridge_gil::future_into_py(py, fut)?.unbind())),
    )
}

/// As [`coroutine_into_py`], for an operation that must take a GIL-held action
/// at the moment it is dispatched rather than when it is called.
///
/// `setup` runs on the coroutine's first step, under the GIL, and yields the
/// future to spawn. That makes it the place for side effects which must happen
/// if and only if the operation is really dispatched — `Stack.build()` claims
/// its Python layer declarations here, so an abandoned build coroutine leaves
/// them reusable.
fn coroutine_into_py_with_setup<'py, S, F, T>(
    py: Python<'py>,
    qualname: &str,
    captures: Vec<PyObject>,
    setup: S,
) -> PyResult<Bound<'py, PyAny>>
where
    S: FnOnce(Python<'_>, Vec<PyObject>) -> PyResult<F> + Send + 'static,
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    deferred_coroutine(
        py,
        qualname,
        captures,
        Box::new(move |py, captures| {
            Ok(bridge_gil::future_into_py(py, setup(py, captures)?)?.unbind())
        }),
    )
}

/// As [`coroutine_into_py`], plus propagation of asyncio cancellation into the
/// operation's [`CancellationToken`].
///
/// Cancelling the awaiting task cancels the `asyncio.Future` the coroutine is
/// suspended on, which fires the forwarding done-callback `bridge_gil`
/// registers. Cancelling before the first step is stronger still: the spawn
/// never happens.
fn cancellable_coroutine_into_py<'py, F, T>(
    py: Python<'py>,
    cancel: CancellationToken,
    qualname: &str,
    fut: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    cancellable_coroutine_into_py_with_setup(
        py,
        cancel,
        qualname,
        Vec::new(),
        move |_py, _captures| Ok(fut),
    )
}

/// [`cancellable_coroutine_into_py`] with the GIL-held first-step `setup` of
/// [`coroutine_into_py_with_setup`].
///
/// This is where an operation builds resources that must not exist unless it is
/// really dispatched. `write_stream` converts its Python input here: doing so at
/// call time would call `__aiter__` and start a bridge producer pulling the
/// caller's iterator for a write that may never run.
///
/// A `setup` that fails leaves no future and no callback — the error surfaces
/// from the first step, like any other error raised inside a coroutine.
///
/// Cancellation is forwarded by `bridge_gil` rather than by a callback attached
/// here. Its `PyCancelForward` is registered unconditionally and does strictly
/// more: besides tripping the operation's token it trips an `abandon` token
/// that drops the Rust future, so an abandoned pull cannot run on and consume a
/// chunk nobody receives.
fn cancellable_coroutine_into_py_with_setup<'py, S, F, T>(
    py: Python<'py>,
    cancel: CancellationToken,
    qualname: &str,
    captures: Vec<PyObject>,
    setup: S,
) -> PyResult<Bound<'py, PyAny>>
where
    S: FnOnce(Python<'_>, Vec<PyObject>) -> PyResult<F> + Send + 'static,
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    deferred_coroutine(
        py,
        qualname,
        captures,
        Box::new(move |py, captures| {
            Ok(bridge_gil::cancellable_future_into_py(py, cancel, setup(py, captures)?)?.unbind())
        }),
    )
}

/// Present an already-computed value as a coroutine.
///
/// Unlike an `asyncio.Future`, this needs no running event loop to construct.
fn ready_coroutine<'py>(
    py: Python<'py>,
    qualname: &str,
    value: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    let coro = async_shim(py)?.ready.bind(py).call1((value,))?;
    let name = qualname.rsplit_once('.').map_or(qualname, |(_, n)| n);
    coro.setattr("__name__", name)?;
    coro.setattr("__qualname__", qualname)?;
    Ok(coro)
}

fn destination_precondition(mode: &str, etag: Option<String>) -> PyResult<ovs::IfDestExists> {
    match (mode, etag) {
        ("overwrite", None) => Ok(ovs::IfDestExists::Overwrite),
        ("fail", None) => Ok(ovs::IfDestExists::Fail),
        ("match_etag", Some(etag)) => Ok(ovs::IfDestExists::MatchEtag(etag)),
        ("match_etag", None) => Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "if_dest_etag is required when if_dest_exists is 'match_etag'",
        ))),
        ("overwrite" | "fail", Some(_)) => Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "if_dest_etag is only valid when if_dest_exists is 'match_etag'",
        ))),
        _ => Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "if_dest_exists must be 'overwrite', 'fail', or 'match_etag'",
        ))),
    }
}

fn byte_range(start: Option<u64>, end_inclusive: Option<u64>) -> PyResult<Option<ovs::ByteRange>> {
    let start = match (start, end_inclusive) {
        (None, None) => return Ok(None),
        (Some(start), _) => start,
        (None, Some(_)) => 0,
    };
    if end_inclusive.is_some_and(|end| end < start) {
        return Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "range_end_inclusive must be greater than or equal to range_start",
        )));
    }
    Ok(Some(ovs::ByteRange {
        start,
        end_inclusive,
    }))
}

pub(crate) fn bytes_from_python_buffer(value: &Bound<'_, PyAny>) -> PyResult<Option<Vec<u8>>> {
    if value.is_instance_of::<PyBytes>() {
        return Ok(Some(value.downcast::<PyBytes>()?.as_bytes().to_vec()));
    }
    if value.is_instance_of::<PyByteArray>() {
        return Ok(Some(value.downcast::<PyByteArray>()?.to_vec()));
    }
    if value.is_instance_of::<PyMemoryView>() {
        return Ok(Some(
            value
                .call_method0("tobytes")?
                .downcast_into::<PyBytes>()
                .map_err(PyErr::from)?
                .as_bytes()
                .to_vec(),
        ));
    }
    Ok(None)
}

async fn pull_python_body_chunk(
    task_locals: &pyo3_async_runtimes::TaskLocals,
    loop_handle: &Py<PyAny>,
    iterator: &Py<PyAny>,
    cancel: &CancellationToken,
) -> Result<Option<Vec<u8>>, OvError> {
    let (callable, call) = crate::bridge_gil::with_bridge_gil(|py| {
        let callable = iterator.bind(py).getattr("__anext__").map_err(|error| {
            OvError::new(
                ErrorCode::IncompatibleType,
                format!("write_stream iterator lost `__anext__`: {error}"),
            )
        })?;
        Ok::<_, OvError>((
            callable.unbind(),
            p2r_marshal::MarshalledCall {
                args: PyTuple::empty_bound(py).unbind(),
                kwargs: PyDict::new_bound(py).unbind(),
                cancel: cancel.clone(),
            },
        ))
    })?;

    p2r_adapter::dispatch_callable_with_context(
        task_locals,
        loop_handle,
        "write_stream.__anext__",
        bridge_gil::Admission::Dispatch,
        p2r_adapter::AwaitableRequirement::Awaitable,
        &callable,
        call,
        |_, value| {
            bytes_from_python_buffer(&value)
                .map_err(|error| {
                    OvError::new(
                        ErrorCode::IncompatibleType,
                        format!("write_stream iterator yielded an invalid buffer: {error}"),
                    )
                })?
                .map(Some)
                .ok_or_else(|| {
                    OvError::new(
                        ErrorCode::IncompatibleType,
                        "write_stream iterator must yield bytes-like values",
                    )
                })
        },
        |py, error| {
            if error.is_instance_of::<PyStopAsyncIteration>(py) {
                Ok(None)
            } else {
                Err(p2r_marshal::override_failure(py, error))
            }
        },
    )
    .await
}

/// Adapt a Python `BodyInput` into the native body. Buffers retain their
/// bytes form; async iterators are bridged to the sync-pull Layer ABI through
/// a bounded channel whose receiver is safe to block on outside Tokio.
fn body_from_python_input(
    py: Python<'_>,
    data: PyObject,
    cancel: CancellationToken,
) -> PyResult<Body> {
    if let Some(bytes) = bytes_from_python_buffer(data.bind(py))? {
        return Ok(Body::Bytes(bytes));
    }
    if !data.bind(py).hasattr("__aiter__")? {
        return Err(py_error(OvError::new(
            ErrorCode::IncompatibleType,
            "write_stream data must be a bytes-like buffer or async byte iterator",
        )));
    }
    let iterator = data
        .bind(py)
        .call_method0("__aiter__")
        .map_err(|error| {
            py_error(OvError::new(
                ErrorCode::IncompatibleType,
                format!("write_stream data is not an async iterator: {error}"),
            ))
        })?
        .unbind();
    let locals = pyo3_tokio::get_current_locals(py)?;
    let loop_handle = locals.event_loop(py).unbind();
    let (tx, rx) = async_channel::bounded(p2r_adapter::PY_BRIDGE_CHANNEL_CAPACITY);
    let state = Arc::new(PythonBodyState::new());
    let producer_state = state.clone();
    let producer_cancel = cancel.child_token();
    let task_cancel = producer_cancel.clone();
    let scope_locals = locals.clone();
    let producer_guard = p2r_adapter::BridgeTaskGuard::new();
    pyo3_tokio::get_runtime().spawn(pyo3_async_runtimes::tokio::scope(
        scope_locals,
        async move {
            let _producer_guard = producer_guard;
            loop {
                if task_cancel.is_cancelled() {
                    producer_state.fail(cancelled_body_error());
                    break;
                }
                match pull_python_body_chunk(&locals, &loop_handle, &iterator, &task_cancel).await {
                    Ok(Some(bytes)) => {
                        let sent = tokio::select! {
                            biased;
                            _ = task_cancel.cancelled() => {
                                producer_state.fail(cancelled_body_error());
                                false
                            }
                            _ = tx.closed() => false,
                            result = tx.send(bytes) => result.is_ok(),
                        };
                        if !sent {
                            break;
                        }
                    }
                    Ok(None) => {
                        if task_cancel.is_cancelled() {
                            producer_state.fail(cancelled_body_error());
                        } else {
                            producer_state.finish();
                        }
                        break;
                    }
                    Err(error) => {
                        producer_state.fail(if task_cancel.is_cancelled() {
                            cancelled_body_error()
                        } else {
                            error
                        });
                        break;
                    }
                }
            }
            p2r_adapter::close_async_iterator_best_effort(
                &locals,
                &loop_handle,
                &iterator,
                "write_stream.aclose",
            )
            .await;
        },
    ));
    Ok(Body::Stream(ovs::BodyStream::from_iter(
        PythonBodyReceiver {
            rx,
            state,
            producer_cancel,
            ended: false,
        },
    )))
}

struct PythonBodyState {
    complete: AtomicBool,
    terminal: StdMutex<Option<OvError>>,
}

impl PythonBodyState {
    fn new() -> Self {
        Self {
            complete: AtomicBool::new(false),
            terminal: StdMutex::new(None),
        }
    }

    fn finish(&self) {
        self.complete.store(true, Ordering::Release);
    }

    fn fail(&self, error: OvError) {
        if self.complete.load(Ordering::Acquire) {
            return;
        }
        let mut terminal = self
            .terminal
            .lock()
            .expect("Python write body terminal mutex poisoned");
        if terminal.is_none() {
            *terminal = Some(error);
        }
    }

    fn take_terminal(&self) -> Option<OvError> {
        self.terminal
            .lock()
            .expect("Python write body terminal mutex poisoned")
            .take()
    }
}

struct PythonBodyReceiver {
    rx: async_channel::Receiver<Vec<u8>>,
    state: Arc<PythonBodyState>,
    producer_cancel: CancellationToken,
    ended: bool,
}

impl Drop for PythonBodyReceiver {
    fn drop(&mut self) {
        // The child token interrupts a pending Python `__anext__` without
        // cancelling the containing operation or token-sharing siblings.
        self.producer_cancel.cancel();
    }
}

impl Iterator for PythonBodyReceiver {
    type Item = ovs::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }
        match self.rx.recv_blocking() {
            Ok(bytes) => Some(Ok(bytes)),
            Err(_) => {
                self.ended = true;
                if let Some(error) = self.state.take_terminal() {
                    Some(Err(error))
                } else if self.state.complete.load(Ordering::Acquire) {
                    None
                } else {
                    Some(Err(OvError::new(
                        ErrorCode::Internal,
                        "Python write_stream body producer ended without completion",
                    )))
                }
            }
        }
    }
}

fn cancelled_body_error() -> OvError {
    OvError::new(
        ErrorCode::Cancelled,
        "write_stream body production was cancelled",
    )
}

/// Durability selector for the Python binding's credential cache.
/// Class-attribute ints; pass to `Stack(credential_cache_durability=...)`.
/// The binding always builds the process-local Rust cache, so
/// `PERSISTENT` has nothing behind it and `Stack` rejects it.
#[pyclass(name = "CredentialCacheDurability")]
struct CredentialCacheDurability;

#[pymethods]
impl CredentialCacheDurability {
    /// Reserved for a future Python persistent-cache implementation. Passing
    /// this value to `Stack` currently raises `ovstorage.Error`.
    #[classattr]
    const PERSISTENT: i32 = 0;
    /// Keep resolved credentials only for the lifetime of the built Stack.
    #[classattr]
    const IN_MEMORY_ONLY: i32 = 1;
}

/// Mirrors `ovstorage_plugin::InteractiveAuthCapability`.
#[pyclass(name = "InteractiveAuthCapability")]
struct InteractiveAuthCapability;

#[pymethods]
impl InteractiveAuthCapability {
    #[classattr]
    const BROWSER: i32 = 0;
    #[classattr]
    const HEADLESS: i32 = 1;
    #[classattr]
    const NONE: i32 = 2;
}

/// Resolves and caches credentials for one built Python Stack.
struct CredentialResolver {
    cache: Arc<ovs::auth::CredentialCache>,
    providers: Vec<Arc<dyn ovs::auth::CredentialProvider>>,
    interactive_auth_capability: RustInteractiveAuthCapability,
}

impl CredentialResolver {
    async fn resolve(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<ResolvedCredential, CredentialError> {
        self.cache
            .resolve(backend, principal, &self.providers)
            .await
    }

    async fn insert(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
        credential: ResolvedCredential,
    ) -> Result<(), CredentialError> {
        self.cache.insert(backend, principal, credential).await
    }

    fn invalidate(
        &self,
        backend: &BackendId,
        principal: &PrincipalView,
    ) -> Result<(), CredentialError> {
        self.cache.invalidate(backend, principal)
    }

    fn cred_epoch(&self) -> u64 {
        self.cache.cred_epoch()
    }

    fn interactive_auth_capability(&self) -> RustInteractiveAuthCapability {
        self.interactive_auth_capability
    }
}

/// Owns the operational graph and credential state of a built Python Stack.
///
/// `stack` is the immutable operational graph used for layer dispatch. The
/// credential resolver owns the provider chain, cache, and resolved
/// interactive-auth capability. Keeping both under one `Arc` makes Python
/// layer objects retain the callback and cache for exactly as long as they can
/// dispatch through the built Stack.
///
/// The two halves are wired: `Stack.build()` resolves the
/// provider chain into each declared connection's empty `SecretBundle`
/// before bring-up, and `set_credential`/`refresh_credentials` propagate to
/// the live connections through `Layer::update_connection_credentials`,
/// falling back to remove + re-add for backends that reject in-place swaps.
/// `cred_epoch` therefore observes a cache that moves only in lockstep with
/// the connections (cache commits happen after propagation succeeds).
struct StackOwner {
    stack: Arc<ovs::Stack>,
    credentials: CredentialResolver,
    // The single-identity principal (build-time `principal_id`) every chain
    // resolution and refresh uses by default.
    principal: PrincipalView,
    // Exact (target, id) records for every build-declared connection, captured
    // from the build-time `add_connection` returns — the join
    // `set_credential`'s fan-out keys on (live `Connection` snapshots carry no
    // target). The lock is acquired AFTER chain resolution — holding it across
    // a user credential callback would deadlock a callback that itself awaits
    // `set_credential`/`refresh_credentials` on this layer — and covers apply
    // + the cache mutation as one critical section, so racing calls cannot
    // leave the cache ahead of the connections. The lock IS held across the
    // backend connection-lifecycle awaits, so a p2r Python layer body (e.g. a
    // Python backend's `add_connection`) that itself awaits
    // `set_credential`/`refresh_credentials` on the same built Stack would
    // deadlock — credential mutation from within a layer body on the same Stack
    // is unsupported; `lock_records` breaks that circular wait after 60s with
    // a typed `Locked` error instead of hanging forever.
    connections: TokioMutex<Vec<ConnectionRecord>>,
}

/// One build-declared connection the runtime credential fan-out governs.
/// Connections added out-of-band (through an exported handle or the
/// low-level `update_connection_credentials` primitive) are intentionally
/// not tracked here.
struct ConnectionRecord {
    target: String,
    /// `None` = a fallback removed the connection and its re-add failed;
    /// the next apply for this kind re-enters directly at the add leg.
    id: Option<ovs::ConnectionId>,
    backend_kind: String,
    /// The declared request with `credentials` cleared (declared secrets
    /// are never retained); fallback re-adds reuse it with the new bundle.
    request: ovs::ConnectionRequest,
}

impl ConnectionRecord {
    fn describe(&self) -> String {
        match &self.id {
            Some(id) => format!("{}/{} ({})", self.target, id.0, self.backend_kind),
            None => format!(
                "{}/<removed, pending re-add> ({})",
                self.target, self.backend_kind
            ),
        }
    }
}

impl StackOwner {
    /// One-shot GIL-holding constructor retained for unit tests. Production
    /// `Stack.build()` opens the resolver off the GIL and uses [`from_parts`].
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn build(
        py: Python<'_>,
        stack: ovs::Stack,
        interactive_auth_capability: Option<i32>,
        credential_cache_durability: Option<i32>,
        credential_callback: Option<PyObject>,
        credential_callback_name: Option<String>,
    ) -> PyResult<Arc<Self>> {
        let callback_provider =
            credential_callback_provider(py, credential_callback, credential_callback_name)?;
        let credentials = open_credential_resolver(
            interactive_auth_capability,
            credential_cache_durability,
            callback_provider,
        )?;
        Ok(Self::from_parts(
            stack,
            credentials,
            PrincipalView::new(""),
            Vec::new(),
        ))
    }

    /// Wrap an already-built Stack and credential resolver. The async
    /// `Stack.build()` path opens the resolver off the GIL, so it constructs
    /// the owner from parts rather than through the test-only `StackOwner::build`.
    fn from_parts(
        stack: ovs::Stack,
        credentials: CredentialResolver,
        principal: PrincipalView,
        records: Vec<ConnectionRecord>,
    ) -> Arc<Self> {
        Arc::new(Self {
            stack: Arc::new(stack),
            credentials,
            principal,
            connections: TokioMutex::new(records),
        })
    }

    fn handle(&self) -> ovs::LayerHandle {
        // This erased handle is also the r2p boundary handed to a native
        // Python wrapper. It must remain the Stack, never `stack.root()`:
        // Stack::Layer canonicalizes request.input addresses before any Rust
        // root, router, wrapper, or backend observes them.
        self.stack.clone()
    }

    /// Records-lock acquisition with a deadlock breaker: credential mutation
    /// from within a layer body or credential callback on the same Stack is
    /// unsupported (see the field note) and would otherwise hang forever —
    /// surface it (or a genuinely stalled concurrent mutation) as a typed
    /// `Locked` error instead.
    async fn lock_records(
        &self,
    ) -> ovs::Result<tokio::sync::MutexGuard<'_, Vec<ConnectionRecord>>> {
        tokio::time::timeout(Duration::from_secs(60), self.connections.lock())
            .await
            .map_err(|_| {
                OvError::new(
                    ErrorCode::Locked,
                    "credential mutation lock not acquired within 60s: either a concurrent \
                     set_credential/refresh_credentials is stalled, or this call reentered \
                     from a layer body / credential callback on the same Stack (unsupported)",
                )
            })
    }

    async fn set_credential(
        &self,
        backend: BackendId,
        principal: PrincipalView,
        credential: ResolvedCredential,
    ) -> ovs::Result<()> {
        let mut records = self.lock_records().await?;
        self.apply_credentials_locked(&mut records, &backend, &credential.bytes)
            .await?;
        // Cache-insert only after full propagation success: `cred_epoch`
        // must never advance past connections still holding the old bundle.
        // The records lock is still held, so a racing call cannot observe
        // (or interleave into) a cache-ahead-of-connections state. If the
        // cache commit itself fails after a successful apply, the connections keep the new
        // bundle while the call reports failure; a retry converges.
        self.credentials
            .insert(&backend, &principal, credential)
            .await
            .map_err(credential_error_to_ov)
    }

    /// Re-run the provider chain for `backend` and propagate the result to
    /// the live connections. The chain resolution (which may invoke the
    /// Python `credential_callback`) runs OUTSIDE the records lock — see the
    /// `connections` field note for the reentrancy rationale.
    ///
    /// Cache invariant (same as [`Self::set_credential`]): the cache commits
    /// only after apply succeeds, under the records lock. Every cache
    /// mutation except `resolve`'s internal store-on-resolve (and the
    /// pre-resolve invalidate that forces the chain to re-run) happens
    /// under the records lock, so a scrub can never delete a concurrent
    /// call's just-committed entry unnoticed: a scrub that supersedes a
    /// concurrent commit is immediately followed by this call's own
    /// apply + commit (or leaves the cache empty on apply failure —
    /// converging on the next use). During the in-flight resolve there is
    /// still a window where the cache briefly holds the resolved value.
    /// Concurrent credential mutation on one Stack converges to
    /// last-committed-under-lock: both the connections and the cache commit
    /// inside the same critical section. The extra `cred_epoch` movements
    /// (resolve store + scrub + commit) are inherent and advisory.
    async fn refresh_credentials(
        &self,
        backend: BackendId,
        principal: Option<PrincipalView>,
    ) -> ovs::Result<()> {
        let principal = principal.unwrap_or_else(|| self.principal.clone());
        // Invalidate first so the chain genuinely re-runs instead of
        // serving the still-fresh L1 entry.
        self.credentials
            .invalidate(&backend, &principal)
            .map_err(credential_error_to_ov)?;
        let resolved = self
            .credentials
            .resolve(&backend, &principal)
            .await
            .map_err(credential_error_to_ov)?;
        let mut records = self.lock_records().await?;
        // `resolve` cached the new credential as a side effect
        // (store-on-resolve is inherent to the cache); scrub it under the
        // records lock — a blind scrub outside the lock could delete a
        // concurrent `set_credential`'s just-committed entry. Here the
        // scrub is immediately followed by this call's own apply + commit,
        // and on apply failure the cache is simply left empty.
        self.credentials
            .invalidate(&backend, &principal)
            .map_err(credential_error_to_ov)?;
        self.apply_credentials_locked(&mut records, &backend, &resolved.bytes)
            .await?;
        // Commit only after full propagation success, with the records lock
        // still held — the same invariant as `set_credential`: `cred_epoch`
        // never advances past connections still holding the old bundle, and
        // racing calls converge to last-committed-under-lock. On apply
        // failure there is nothing to undo: the cache was already scrubbed.
        self.credentials
            .insert(&backend, &principal, resolved)
            .await
            .map_err(credential_error_to_ov)
    }

    /// Propagate `bundle` to every tracked connection of `backend` kind.
    /// Per-record state machine: in-place update; on
    /// `Unsupported`, remove + re-add with the new bundle; a record already
    /// pending re-add (our own fallback removed it) re-enters directly at
    /// the add leg. A TRACKED connection that turns out to be gone
    /// (`NotFound` from the in-place update or from the fallback's remove)
    /// was removed out-of-band and is NOT resurrected: the record is
    /// dropped from the fan-out and reported as a per-record failure.
    /// Attempts ALL matching records before reporting; partial application
    /// is real and the aggregate error says how to reconcile.
    async fn apply_credentials_locked(
        &self,
        records: &mut Vec<ConnectionRecord>,
        backend: &BackendId,
        bundle: &RustSecretBundle,
    ) -> ovs::Result<()> {
        let handle = self.handle();
        let mut matched = 0usize;
        let mut succeeded: Vec<String> = Vec::new();
        let mut failures: Vec<(String, OvError)> = Vec::new();
        let mut dropped: Vec<usize> = Vec::new();
        for (index, record) in records
            .iter_mut()
            .enumerate()
            .filter(|(_, record)| record.backend_kind == backend.0)
        {
            matched += 1;
            match apply_bundle_to_record(&handle, record, bundle).await {
                Ok(()) => succeeded.push(record.describe()),
                Err(RecordFailure::Keep(error)) => failures.push((record.describe(), error)),
                Err(RecordFailure::Drop(error)) => {
                    failures.push((record.describe(), error));
                    dropped.push(index);
                }
            }
        }
        // Untrack records whose connection was removed out-of-band:
        // re-adding them would resurrect state another owner deliberately
        // deleted. Reverse order keeps the collected indices valid.
        for index in dropped.into_iter().rev() {
            records.remove(index);
        }
        if matched == 0 {
            // A cache-only insert would be permanently inert on this
            // surface (there is no post-build connection declaration), so
            // an unmatched kind is a loud error, not a silent no-op.
            let mut declared: Vec<&str> = records
                .iter()
                .map(|record| record.backend_kind.as_str())
                .collect();
            declared.sort_unstable();
            declared.dedup();
            return Err(OvError::new(
                ErrorCode::NotFound,
                format!(
                    "no declared connection has backend kind '{}' (declared kinds: [{}]); \
                     the credential was NOT cached",
                    backend.0,
                    declared.join(", ")
                ),
            ));
        }
        if failures.is_empty() {
            return Ok(());
        }
        // Auth/verify failures are more actionable than swap-capability
        // rejections, so the first non-`Unsupported` code wins the
        // aggregate; the message still lists every failure.
        let code = failures
            .iter()
            .map(|(_, error)| error.code())
            .find(|code| *code != ErrorCode::Unsupported)
            .unwrap_or_else(|| failures[0].1.code());
        let failed = failures
            .iter()
            .map(|(name, error)| format!("{name}: {error}"))
            .collect::<Vec<_>>()
            .join("; ");
        Err(OvError::new(
            code,
            format!(
                "credential propagation failed for {}/{} '{}' connection(s): [{failed}]; \
                 succeeded: [{}]; the credential cache was NOT updated — retry \
                 set_credential/refresh_credentials with a valid credential to reconcile \
                 (connections pending re-add are re-created on retry)",
                failures.len(),
                matched,
                backend.0,
                succeeded.join(", "),
            ),
        ))
    }

    fn cred_epoch(&self) -> u64 {
        self.credentials.cred_epoch()
    }

    fn interactive_auth_capability(&self) -> RustInteractiveAuthCapability {
        self.credentials.interactive_auth_capability()
    }
}

/// A failed fan-out leg's disposition for
/// [`StackOwner::apply_credentials_locked`].
enum RecordFailure {
    /// The record stays tracked; a corrected retry reconciles it.
    Keep(OvError),
    /// The tracked connection is gone (removed out-of-band): drop
    /// the record from the fan-out instead of resurrecting it.
    Drop(OvError),
}

/// The per-record failure for a tracked connection that was removed
/// out-of-band (e.g. through a shared exported handle).
fn out_of_band_removed() -> OvError {
    OvError::new(
        ErrorCode::NotFound,
        "connection does not exist (removed out of band); it is not governed \
         by set_credential — declare and add it again explicitly",
    )
}

/// One record's leg of the credential fan-out. See
/// [`StackOwner::apply_credentials_locked`] for the state-machine contract.
async fn apply_bundle_to_record(
    handle: &ovs::LayerHandle,
    record: &mut ConnectionRecord,
    bundle: &RustSecretBundle,
) -> Result<(), RecordFailure> {
    // A record wedged by a prior failed fallback enters directly at the
    // add leg — retry-with-corrected-credential is always a recovery path.
    let Some(id) = record.id.clone() else {
        return readd_record(handle, record, bundle)
            .await
            .map_err(RecordFailure::Keep);
    };
    let key = ovs::ConnectionKey {
        target: record.target.clone(),
        id,
    };
    let update = ovs::UpdateConnectionCredentialsRequest {
        key: key.clone(),
        credentials: bundle.clone(),
    };
    match handle
        .update_connection_credentials(ovs::Request::new(update), None)
        .await
    {
        Ok(connection) => {
            record.id = Some(connection.id);
            Ok(())
        }
        Err(error) if error.code() == ErrorCode::Unsupported => {
            // In-place swap rejected (gcs/azure/opendal reject all updates;
            // s3 rejects shape changes): obtain-verify-then-swap. Probe the
            // declared request with the replacement bundle FIRST, so a bad
            // replacement credential is rejected before the live connection
            // is torn down; only probe-`Unsupported` backends retain the
            // legacy remove-first risk.
            let mut connection = record.request.clone();
            connection.credentials = bundle.clone();
            let probe = ovs::LayerConnectionRequest {
                target: record.target.clone(),
                connection,
            };
            match handle.probe(ovs::Request::new(probe), None).await {
                Ok(_) => {}
                // The backend cannot pre-validate: proceed with the legacy
                // remove-first swap (documented residual risk — a failed
                // re-add leaves the record pending until a corrected retry).
                Err(error) if error.code() == ErrorCode::Unsupported => {}
                // Probe rejected the replacement credential: fail this
                // record WITHOUT removing anything — the live connection
                // keeps its old credentials (fail-safe).
                Err(error) => return Err(RecordFailure::Keep(error)),
            }
            // Fall back to remove + re-add with the new bundle. A backend
            // that also rejects `remove` (the file backend supports neither
            // slot) fails loudly here WITHOUT having removed anything — the
            // intended semantics for credential-less backends.
            match handle.remove_connection(ovs::Request::new(key), None).await {
                Ok(()) => readd_record(handle, record, bundle)
                    .await
                    .map_err(RecordFailure::Keep),
                // The tracked connection was already gone: removed
                // out-of-band. Do NOT re-add — see the update-NotFound arm.
                Err(error) if error.code() == ErrorCode::NotFound => {
                    Err(RecordFailure::Drop(out_of_band_removed()))
                }
                Err(error) => Err(RecordFailure::Keep(error)),
            }
        }
        Err(error) if error.code() == ErrorCode::NotFound => {
            // `record.id` is `Some`, so this is not our own pending
            // removal (that path re-entered at the add leg above): the
            // connection was removed out-of-band through a shared handle.
            // Target routing is structurally stable post-build (router
            // targets derive from static `owned_targets`), so NotFound
            // cannot mean anything else. Do NOT resurrect state another
            // owner deliberately deleted — drop the record.
            Err(RecordFailure::Drop(out_of_band_removed()))
        }
        // Any other error (e.g. an s3 rotation whose verify failed) is a
        // per-record failure with NO fallback: the old credentials stay
        // live, which is the fail-safe outcome.
        Err(error) => Err(RecordFailure::Keep(error)),
    }
}

/// The fallback's add leg: re-create the connection from the declared
/// request with `bundle` as its credentials. On failure the record is left
/// pending (`id = None`) so the next apply re-enters here.
async fn readd_record(
    handle: &ovs::LayerHandle,
    record: &mut ConnectionRecord,
    bundle: &RustSecretBundle,
) -> ovs::Result<()> {
    record.id = None;
    let mut connection = record.request.clone();
    connection.credentials = bundle.clone();
    let request = ovs::LayerConnectionRequest {
        target: record.target.clone(),
        connection,
    };
    let connected = handle
        .add_connection(ovs::Request::new(request), None)
        .await?;
    record.id = Some(connected.id);
    Ok(())
}

/// Map a chain error onto the public error surface for `refresh_credentials`:
/// an explicit refresh that produces nothing is an error (`AuthRequired`),
/// unlike build-time resolution where `Unavailable` means proceed
/// credential-less.
fn credential_error_to_ov(error: CredentialError) -> OvError {
    match error {
        CredentialError::Backend(error) => error,
        CredentialError::Unavailable { details } => OvError::new(
            ErrorCode::AuthRequired,
            format!("credential refresh produced no credential: {details}"),
        ),
    }
}

/// A forwarding [`ovs::Layer`] that retains a built Stack's `Arc<StackOwner>`
/// for the life of every handle [`LayerBase::export_handle`] mints from it.
///
/// Exporting a built Stack must keep more alive than the bare `Arc<Stack>`:
/// the Stack does not own its credential resolver, so leaking `stack.clone()`
/// alone would drop the callback/cache substrate with the Python object. This
/// newtype carries the whole `Arc<StackOwner>` and delegates every operational
/// slot to `owner.handle()`, the canonicalizing `Arc<Stack>` — never
/// `stack.root()`, preserving the address-canonicalization boundary.
struct CredentialRetainingLayer {
    // `owner.handle()`, cached so `inner_layer` can hand out a borrow. Every
    // pass-through `Layer` slot delegates here, re-entering Rust at the Stack's
    // canonicalization boundary.
    inner: ovs::LayerHandle,
    // Retains the credential callback/cache substrate; never read directly.
    _owner: Arc<StackOwner>,
}

impl CredentialRetainingLayer {
    fn new(owner: Arc<StackOwner>) -> Self {
        Self {
            inner: owner.handle(),
            _owner: owner,
        }
    }
}

impl ovs::Layer for CredentialRetainingLayer {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn descriptor(&self) -> ovs::LayerKindDescriptor {
        self.inner.descriptor()
    }

    fn inner_layer(&self) -> Option<&ovs::LayerHandle> {
        Some(&self.inner)
    }

    // The retained handle is the transparent Stack, so present its identity
    // rather than self-prepending — that would double-count the root, exactly
    // as `Stack` avoids for these two introspection slots.
    fn owned_targets(&self) -> Vec<String> {
        self.inner.owned_targets()
    }

    fn list_kinds(&self, cx: &ovs::Extensions) -> ovs::Result<Vec<ovs::LayerKindDescriptor>> {
        self.inner.list_kinds(cx)
    }
}

/// Capsule name tagging an `export_handle(capsule=True)` PyCapsule, so
/// `import_handle` can reject a foreign capsule before dereferencing its
/// pointer.
const LAYER_HANDLE_CAPSULE_NAME: &CStr = c"ovstorage.LayerHandle";

/// PyCapsule destructor for an unclaimed `export_handle(capsule=True)` handle:
/// when `import_handle` never stole the pointer, drop the heap
/// `Box<ffi::LayerHandle>` here — its `ffi::LayerHandle::drop` fires the vtable
/// `drop` slot, releasing the producer-side `Arc`. A stolen slot is NULL and
/// this is a no-op.
fn drop_unclaimed_handle_capsule(slot: AtomicPtr<ovs::ffi::LayerHandle>, _context: *mut c_void) {
    let ptr = slot.into_inner();
    if !ptr.is_null() {
        // SAFETY: `ptr` is a `Box<ffi::LayerHandle>` minted by the capsule form
        // of `export_handle` and not yet stolen by `import_handle` (the swap in
        // `import_raw_from_capsule` NULLs the slot to disarm this path).
        drop(unsafe { Box::from_raw(ptr) });
    }
}

/// Steal the `Box<ffi::LayerHandle>` out of an `export_handle(capsule=True)`
/// PyCapsule: verify the tag, swap the slot to NULL (disarming the destructor),
/// then move the pair out and free the box the capsule owned.
fn import_raw_from_capsule(capsule: &Bound<'_, PyCapsule>) -> PyResult<ovs::ffi::LayerHandle> {
    match capsule.name()? {
        Some(name) if name == LAYER_HANDLE_CAPSULE_NAME => {}
        _ => {
            return Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "import_handle expects an ovstorage.LayerHandle capsule",
            )));
        }
    }
    // SAFETY: the tag check above proved the capsule value is the
    // `AtomicPtr<ffi::LayerHandle>` slot minted by the capsule export path.
    let slot = unsafe { capsule.reference::<AtomicPtr<ovs::ffi::LayerHandle>>() };
    let ptr = slot.swap(std::ptr::null_mut(), Ordering::AcqRel);
    if ptr.is_null() {
        return Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "this LayerHandle capsule has already been imported",
        )));
    }
    // SAFETY: the swap stole the pointer exactly once, so this is the sole
    // owner of the capsule's `Box<ffi::LayerHandle>`. Move the pair out (the
    // box heap is freed) without running `ffi::LayerHandle::drop` — ownership
    // of the pair passes to `import_handle`.
    let boxed = unsafe { Box::from_raw(ptr) };
    Ok(*boxed)
}

/// Copy the `{state, vtable}` pair out of an `export_handle()` int handle
/// **without** freeing the outer allocation: a raw int carries no
/// allocation provenance (it may be ctypes caller storage), so the exporter's
/// caller frees the outer box separately via [`_free_exported_handle`].
///
/// The int is **single-use**, mirroring the capsule form's consumed-guard
/// ([`import_raw_from_capsule`]): the pair is nulled back through `ptr` as it is
/// moved out, so a second import of the same int raises rather than re-reading
/// the pair and double-freeing the producer-side `Arc`. Nulling both fields
/// matches [`ovs::ffi::LayerHandle`]'s own `Drop`, so the husk — whether an
/// `export_handle()` heap box or ctypes caller storage — is left inert and
/// [`_free_exported_handle`] still reclaims it without re-firing the vtable
/// `drop` slot.
fn import_raw_from_int(handle: &Bound<'_, PyAny>) -> PyResult<ovs::ffi::LayerHandle> {
    let addr: usize = handle.extract().map_err(|_| {
        py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "import_handle expects an int handle pointer or a PyCapsule",
        ))
    })?;
    if addr == 0 {
        return Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "import_handle received a null handle pointer",
        )));
    }
    let ptr = addr as *mut ovs::ffi::LayerHandle;
    // SAFETY: `ptr` is an `export_handle()` int handle. `state`/`vtable` are
    // `Copy`, so reading them leaves the outer allocation intact.
    let state = unsafe { (*ptr).state };
    let vtable = unsafe { (*ptr).vtable };
    // Consumed-guard mirroring `import_raw_from_capsule`: a NULL field means a
    // prior import already moved the pair out, so re-importing would
    // `Box::from_raw` a dangling `state` → double-free. Reject before taking
    // ownership.
    if state.is_null() || vtable.is_null() {
        return Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "this LayerHandle int has already been imported",
        )));
    }
    // Null the pair back through `ptr` so the int is single-use: a second import
    // trips the guard above, and the inert husk still frees cleanly. This
    // mirrors `ffi::LayerHandle::drop`, which nulls both fields after firing the
    // drop slot.
    // SAFETY: `ptr` addresses either the `export_handle()` heap box or the
    // ctypes caller storage that produced this int; both are valid writable
    // `*mut ffi::LayerHandle`.
    unsafe {
        (*ptr).state = std::ptr::null_mut();
        (*ptr).vtable = std::ptr::null();
    }
    Ok(ovs::ffi::LayerHandle { state, vtable })
}

/// Native Python dispatch surface shared by every Rust-backed layer.
///
/// `LayerHandle` is `Arc<dyn Layer>`; keeping that erased handle here means
/// concrete backend, wrapper, and router Python classes all dispatch through
/// the same Rust trait without another runtime or an FFI round trip.
///
/// Projection-form instances are the Rust-to-Python inner-handle (r2p)
/// boundary: Python awaits operations on a Rust-owned `LayerHandle`.
/// Declaration-form instances are bound by `Stack.build()` to the in-process
/// `PyLayerAdapter`, which implements `Layer` and dispatches selected slots
/// back to the captured Python loop without a C-ABI round trip.
#[pyclass(subclass)]
struct LayerBase {
    // A declared Python layer becomes dispatchable only after `Stack.build()`
    // supplies its native handle. Keeping the declaration here makes the
    // Python surface follow StackBuilder's data/factory split instead of
    // constructing a hidden, one-layer stack per Python object.
    inner: Option<ovs::LayerHandle>,
    // Present only for a layer projected from a built Python Stack. Besides
    // retaining the Stack itself, this keeps the Rust-owned credential
    // callback/cache substrate alive for all native dispatch.
    owner: Option<Arc<StackOwner>>,
    layer_type: ovs::LayerType,
    spec: ovs::LayerSpec,
    // Present only for an explicit Python declaration. Native declarations
    // continue to use `spec` alone, while a projection is deliberately never
    // eligible for p2r binding.
    pub(crate) declaration: Option<LayerDeclaration>,
}

/// Declaration-only state retained until the composer binds this Python
/// object. `bound` is intentionally irreversible: binding injects a native
/// handle into the Python instance, so reusing it would mutate an already
/// composed graph.
pub(crate) struct LayerDeclaration {
    pub(crate) name: String,
    pub(crate) layer_type: ovs::LayerType,
    #[allow(dead_code)] // Retains the declared edge independently of LayerSpec.
    pub(crate) inner: Option<String>,
    pub(crate) roots: Vec<String>,
    pub(crate) bound: bool,
}

/// A set of native plugin libraries whose Layer factories may be used by a
/// Python `Stack` composition.
///
/// Each entry is either a plugin library file or a directory of them; a
/// directory is scanned one level deep for `libovstorage_plugin_*.so` /
/// `.dylib` / `ovstorage_plugin_*.dll` in sorted order.
///
/// Paths are retained until `Stack.build()`: loading happens only after the
/// process-global auth substrate has been initialized, and the returned
/// factories retain the plugin mappings for the lifetime of the built Stack.
#[pyclass]
#[derive(Clone, Default)]
struct PluginRegistry {
    paths: Vec<PathBuf>,
    // Shared across clones (`with_registry` clones the registry into the
    // composer), keyed by canonicalized path. Loading a plugin dlopens the
    // library and pins it for the process lifetime, so without this cache every
    // `Stack.build()` on a reused registry — or a retried build — would
    // re-dlopen and re-init each plugin, leaking a handle per call. Cached
    // factories are cheap `Arc` clones handed to each build.
    cache: Arc<StdMutex<HashMap<PathBuf, Vec<ovs::LoadedLayerFactory>>>>,
}

/// Declarative Python composer over the native `StackBuilder`.
///
/// Layer objects contribute `LayerSpec` data. The built-in `file` factory is
/// registered at build time, followed by factories from `registry`; no Layer
/// is instantiated and no graph edge is interpreted on the Python side.
#[pyclass(name = "Stack")]
struct StackComposer {
    root: Option<String>,
    layers: Vec<ovs::LayerSpec>,
    connections: Vec<ovs::LayerConnectionRequest>,
    registry: Option<PluginRegistry>,
    interactive_auth_capability: Option<i32>,
    credential_cache_durability: Option<i32>,
    credential_callback: Option<PyObject>,
    credential_callback_name: Option<String>,
    // The single-identity principal build-time chain resolution and the
    // built layer's `refresh_credentials` default resolve under. `""` is
    // the anonymous single-identity scope the built Stack dispatches as.
    principal_id: String,
    allow_test_plugins: bool,
    // Strong references keep every supplied Python object alive until
    // `build()` can classify operational overrides. Declaration-form objects
    // are additionally claimed and handed to the in-process factories.
    declarations: Vec<Py<LayerBase>>,
}

#[pyclass]
#[derive(Clone)]
struct Info {
    #[pyo3(get)]
    address: String,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    size: Option<u64>,
    #[pyo3(get)]
    mtime_unix_nanos: Option<u64>,
    #[pyo3(get)]
    etag: Option<String>,
    #[pyo3(get)]
    version: Option<String>,
    #[pyo3(get)]
    system_metadata: HashMap<String, String>,
    #[pyo3(get)]
    user_metadata: HashMap<String, String>,
}

#[pyclass]
struct ListPage {
    #[pyo3(get)]
    items: Vec<Info>,
    #[pyo3(get)]
    next_page_token: Option<String>,
}

#[pyclass]
struct VersionPage {
    #[pyo3(get)]
    items: Vec<Info>,
    #[pyo3(get)]
    next_page_token: Option<String>,
}

/// Holds the Rust `LocalDelegate` (and its cache lease) for the lifetime
/// of the Python wrapper; attribute reads project from `inner` lazily so
/// the lease is not dropped at the end of the async block.
#[pyclass]
struct LocalDelegate {
    inner: RustLocalDelegate,
    closed: bool,
}

#[pyclass]
struct AccessDecision {
    #[pyo3(get)]
    allowed: bool,
    #[pyo3(get)]
    denied_read: bool,
    #[pyo3(get)]
    denied_write: bool,
    #[pyo3(get)]
    denied_delete: bool,
    #[pyo3(get)]
    denied_update_metadata: bool,
    #[pyo3(get)]
    reason: Option<String>,
}

/// Python async iterator over a backend `ReadStream`. `__anext__` holds
/// the tokio mutex across `.next().await` so concurrent `anext()` calls
/// serialize and a cancelled future drops the guard without taking the
/// stream out — the next iteration resumes from the same position. The
/// `Option` flips to `None` only after the underlying stream returns `None`.
#[pyclass]
struct AsyncReadStream {
    inner: Arc<TokioMutex<Option<ReadStream>>>,
}

/// One item yielded by `LayerBase.watch_directory()`.
#[pyclass]
#[derive(Clone)]
struct ChangeEvent {
    inner: ovs::ChangeEvent,
}

/// Async pull surface over a native Layer change stream. The native stream is
/// a synchronous iterator (including ABI-v2's `StreamStep` adapter), so one
/// blocking producer owns it and forwards bounded results to asyncio.
///
/// Whole-stream teardown is producer-owned: dropping this object (`Drop`) or
/// calling `aclose()` trips the shared token, stopping the producer and the
/// underlying Layer watch. Cancelling a single pending `__anext__` (e.g. an
/// `asyncio.wait_for` per-item timeout) does NOT tear the stream down — that
/// pull is abandoned cancel-safely (the mpsc buffer keeps any unread event)
/// and later `__anext__` calls keep working.
#[pyclass]
struct AsyncChangeEventStream {
    rx: Arc<TokioMutex<mpsc::Receiver<Result<ovs::ChangeEvent, OvError>>>>,
    cancel: CancellationToken,
}

impl Drop for AsyncChangeEventStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Wraps `ovs::ConfigValue`. Construct via classmethod factories
/// (`ConfigValue.string("foo")`, `ConfigValue.int_(42)`, …); inspect
/// via the `kind` property and `as_*` accessors.
#[pyclass]
#[derive(Clone)]
struct ConfigValue {
    inner: ovs::ConfigValue,
}

/// Wraps `ovs::SecretValue`. Write-only — Python cannot read back
/// credential bytes (matches the C ABI's redaction promise).
#[pyclass]
struct SecretValue {
    inner: StdMutex<Option<ovs::SecretValue>>,
}

#[pyclass]
struct ConnectionRequest {
    inner: StdMutex<Option<ovs::ConnectionRequest>>,
}

#[pyclass]
struct SecretBundle {
    inner: StdMutex<Option<ovs::SecretBundle>>,
}

#[pyclass]
#[derive(Clone)]
struct Capabilities {
    inner: ovs::Capabilities,
}

#[pyclass]
#[derive(Clone)]
struct Connection {
    inner: ovs::Connection,
}

#[pyclass]
#[derive(Clone)]
struct AuthEvent {
    inner: ovs::AuthEvent,
}

/// Async iterator over `ovs::AuthEventStream`. A single dedicated
/// `spawn_blocking` producer per stream forwards items into a bounded
/// `mpsc::channel(8)`; `__anext__` only awaits the channel. `Drop` trips
/// the cancel token so Python-side stream drop signals the underlying
/// auth flow to terminate at its next checkpoint.
#[pyclass]
struct AsyncAuthEventStream {
    rx: Arc<TokioMutex<mpsc::Receiver<Result<ovs::AuthEvent, OvError>>>>,
    cancel: CancellationToken,
}

impl Drop for AsyncAuthEventStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[pyclass]
struct AliasRequest {
    inner: StdMutex<Option<ovs::AliasRequest>>,
}

#[pyclass]
#[derive(Clone)]
struct Alias {
    inner: ovs::Alias,
}

#[pyclass]
struct AsyncAddressRootSnapshotStream {
    rx: Arc<TokioMutex<AddressRootSnapshotReceiver>>,
    cancel: CancellationToken,
}

impl Drop for AsyncAddressRootSnapshotStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[pyclass]
#[derive(Clone)]
struct AddressVisibilityOverride {
    inner: ovs::AddressVisibilityOverride,
}

#[pyclass]
#[derive(Clone)]
struct AddressRoot {
    inner: ovs::AddressRoot,
}

#[pyclass]
#[derive(Clone)]
struct BackendKindDescriptor {
    inner: ovs::StorageBackendKindDescriptor,
}

impl LayerBase {
    /// Construct the Python base for a Rust-backed concrete Layer class.
    /// Layer type is instance metadata supplied by the native descriptor, not
    /// inferred from the Python wrapper class name.
    fn from_handle(inner: ovs::LayerHandle) -> Self {
        let descriptor = inner.descriptor();
        let spec = match descriptor.layer_type {
            ovs::LayerType::Backend => ovs::LayerSpec::backend(inner.name(), descriptor.kind),
            ovs::LayerType::Wrapper => {
                // A built handle does not retain its graph edge. This spec is
                // only diagnostic; declarations retain their exact edge below.
                ovs::LayerSpec::wrapper(inner.name(), descriptor.kind, "<built>")
            }
            ovs::LayerType::Router => {
                ovs::LayerSpec::router(inner.name(), descriptor.kind, Vec::new())
            }
        };
        Self {
            inner: Some(inner),
            owner: None,
            layer_type: descriptor.layer_type,
            spec,
            declaration: None,
        }
    }

    /// Project a built Stack through the common LayerBase dispatch surface
    /// while retaining its credential substrate. A native Python wrapper can
    /// retain this object as its inner and override operations top-down;
    /// forwarding re-enters Rust at the canonicalizing Stack boundary.
    fn from_owner(owner: Arc<StackOwner>) -> Self {
        let inner = owner.handle();
        let mut layer = Self::from_handle(inner);
        layer.owner = Some(owner);
        layer
    }

    fn declaration(spec: ovs::LayerSpec) -> Self {
        Self {
            inner: None,
            owner: None,
            layer_type: spec.layer_type,
            spec,
            declaration: None,
        }
    }

    fn python_declaration(
        name: String,
        layer_type: ovs::LayerType,
        inner: Option<String>,
        roots: Vec<String>,
    ) -> Self {
        let kind = match layer_type {
            ovs::LayerType::Backend => p2r_adapter::PYTHON_BACKEND_KIND,
            ovs::LayerType::Wrapper => p2r_adapter::PYTHON_WRAPPER_KIND,
            ovs::LayerType::Router => {
                unreachable!("Python routers are rejected by the constructor")
            }
        };
        let spec = match layer_type {
            ovs::LayerType::Backend => ovs::LayerSpec::backend(name.clone(), kind),
            ovs::LayerType::Wrapper => ovs::LayerSpec::wrapper(
                name.clone(),
                kind,
                inner.clone().expect("validated Python wrapper declaration"),
            ),
            ovs::LayerType::Router => {
                unreachable!("Python routers are rejected by the constructor")
            }
        };
        Self {
            inner: None,
            owner: None,
            layer_type,
            spec,
            declaration: Some(LayerDeclaration {
                name,
                layer_type,
                inner,
                roots,
                bound: false,
            }),
        }
    }

    fn claim_declaration(&mut self) -> PyResult<()> {
        let Some(declaration) = &mut self.declaration else {
            return Ok(());
        };
        if declaration.bound {
            return Err(py_error(OvError::new(
                ErrorCode::Conflict,
                format!(
                    "Python layer declaration '{}' has already been bound to a Stack",
                    declaration.name
                ),
            )));
        }
        declaration.bound = true;
        Ok(())
    }

    fn handle(&self) -> PyResult<ovs::LayerHandle> {
        self.inner.clone().ok_or_else(|| {
            py_error(OvError::new(
                ErrorCode::NotConfigured,
                format!(
                    "layer '{}' is a Stack declaration; build its Stack before dispatching",
                    self.spec.name
                ),
            ))
        })
    }

    fn owner(&self) -> PyResult<Arc<StackOwner>> {
        self.owner.clone().ok_or_else(|| {
            py_error(OvError::new(
                ErrorCode::NotConfigured,
                format!("layer '{}' is not owned by a built Stack", self.spec.name),
            ))
        })
    }

    fn resolve_authenticate_capability(
        &self,
        capability: Option<i32>,
    ) -> PyResult<RustInteractiveAuthCapability> {
        match capability {
            Some(value) => interactive_auth_capability_from_int(value),
            None => Ok(self
                .owner
                .as_ref()
                .map(|owner| owner.interactive_auth_capability())
                .unwrap_or_else(|| resolve_interactive_capability(None, &ovs::auth::StdEnv))),
        }
    }

    /// Clone the one-way r2p projection used as the Rust base of a native
    /// Python subclass.
    ///
    /// A direct Rust layer (for example a `FileBackend`) has no `StackOwner`,
    /// while the handle returned by `Stack.build()` does. Native operation
    /// dispatch needs only the erased handle; retaining the optional owner is
    /// solely a lifetime requirement for a composed Stack's credential
    /// substrate. Requiring an owner here incorrectly excluded direct handles.
    fn wrapper_projection(&self) -> PyResult<Self> {
        Ok(Self {
            inner: Some(self.handle()?),
            owner: self.owner.clone(),
            layer_type: self.layer_type,
            spec: self.spec.clone(),
            declaration: None,
        })
    }
}

fn configured_layer_spec(
    mut spec: ovs::LayerSpec,
    config: Option<&Bound<'_, PyMapping>>,
) -> PyResult<ovs::LayerSpec> {
    let Some(config) = config else {
        return Ok(spec);
    };
    let items = config.items()?;
    for index in 0..items.len()? {
        let entry = items.get_item(index)?;
        let entry = entry.downcast::<PyTuple>()?;
        let key = entry.get_item(0)?;
        let value = entry.get_item(1)?;
        let key: String = key.extract().map_err(|_| {
            py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "Layer config keys must be strings",
            ))
        })?;
        let value: PyRef<'_, ConfigValue> = value.extract().map_err(|_| {
            py_error(OvError::new(
                ErrorCode::InvalidArgument,
                format!("Layer config value for '{key}' must be a ConfigValue"),
            ))
        })?;
        spec.config.insert(key, value.inner.clone());
    }
    Ok(spec)
}

/// Native `file` backend declaration. Factories are attached by `Stack`, while
/// this class contributes only `LayerSpec::backend(name, "file")`.
#[pyclass(extends = LayerBase, subclass, module = "ovstorage.file")]
struct FileBackend;

#[pymethods]
impl FileBackend {
    #[new]
    #[pyo3(signature = (name, config = None))]
    fn new(
        name: String,
        config: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        let spec = configured_layer_spec(
            ovs::LayerSpec::backend(name, ovs::layers::FILE_BACKEND_KIND),
            config,
        )?;
        Ok(PyClassInitializer::from(LayerBase::declaration(spec)).add_subclass(Self))
    }
}

/// A backend declared by plugin kind.
///
/// Resolution happens when its owning Stack is built against the composer's
/// already-loaded ABI-v2 factory registry. S3 and every other shipped plugin
/// kind use the native Layer ABI.
#[pyclass(extends = LayerBase, subclass, module = "ovstorage.plugin")]
struct PluginBackend;

#[pymethods]
impl PluginBackend {
    #[new]
    #[pyo3(signature = (kind, name = None, config = None))]
    fn new(
        kind: String,
        name: Option<String>,
        config: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        if kind.is_empty() {
            return Err(py_error_msg("plugin backend kind must not be empty"));
        }
        let name = name.unwrap_or_else(|| kind.clone());
        let spec = configured_layer_spec(ovs::LayerSpec::backend(name, kind), config)?;
        Ok(PyClassInitializer::from(LayerBase::declaration(spec)).add_subclass(Self))
    }
}

/// Router declaration. Its child names are graph data, not factory state.
#[pyclass(extends = LayerBase, subclass, module = "ovstorage.router")]
struct Router;

#[pymethods]
impl Router {
    #[new]
    #[pyo3(signature = (name, children, config = None))]
    fn new(
        name: String,
        children: Vec<String>,
        config: Option<&Bound<'_, PyMapping>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        let spec = configured_layer_spec(
            ovs::LayerSpec::router(name, ovs::layers::ROUTER_KIND, children),
            config,
        )?;
        Ok(PyClassInitializer::from(LayerBase::declaration(spec)).add_subclass(Self))
    }
}

macro_rules! wrapper_layer_class {
    ($struct_name:ident, $python_name:literal, $module:literal, $kind:expr) => {
        #[pyclass(extends = LayerBase, subclass, name = $python_name, module = $module)]
        struct $struct_name;

        #[pymethods]
        impl $struct_name {
            #[new]
            #[pyo3(signature = (name, inner, config = None))]
            fn new(
                name: String,
                inner: String,
                config: Option<&Bound<'_, PyMapping>>,
            ) -> PyResult<PyClassInitializer<Self>> {
                let spec =
                    configured_layer_spec(ovs::LayerSpec::wrapper(name, $kind, inner), config)?;
                Ok(PyClassInitializer::from(LayerBase::declaration(spec)).add_subclass(Self))
            }
        }
    };
}

wrapper_layer_class!(
    ByteCache,
    "ByteCache",
    "ovstorage.byte_cache",
    ovs::layers::BYTE_CACHE_KIND
);
wrapper_layer_class!(
    MetadataCache,
    "MetadataCache",
    "ovstorage.metadata_cache",
    ovs::layers::METADATA_CACHE_KIND
);
wrapper_layer_class!(Retry, "Retry", "ovstorage.retry", ovs::layers::RETRY_KIND);
wrapper_layer_class!(
    RedirectFollower,
    "RedirectFollower",
    "ovstorage.redirect_follower",
    ovs::layers::REDIRECT_FOLLOWER_KIND
);
wrapper_layer_class!(
    AliasWrapper,
    "Alias",
    "ovstorage.alias",
    ovs::layers::ALIAS_KIND
);
wrapper_layer_class!(
    CopyRenameFallback,
    "CopyRenameFallback",
    "ovstorage.copy_rename_fallback",
    ovs::layers::COPY_RENAME_FALLBACK_KIND
);

#[pymethods]
impl PluginRegistry {
    #[new]
    #[pyo3(signature = (paths = Vec::new()))]
    fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            ..Default::default()
        }
    }

    /// Add a plugin library file, or a directory of plugin libraries, to this
    /// registry. Nothing is opened until a Stack using the registry is built.
    fn add<'py>(mut slf: PyRefMut<'py, Self>, path: PathBuf) -> PyRefMut<'py, Self> {
        slf.paths.push(path);
        slf
    }
}

/// Reject declarations the graph builder would silently drop: every declared
/// layer must be reachable from `root` (following router `children` and wrapper
/// `inner` edges). Without this, a bottom-up composition with no explicit root
/// — e.g. `Stack().backend("fs").wrapper("cache", "fs")` picks `fs` as root —
/// leaves `cache` unreachable and returns a bare backend with no error.
fn ensure_layers_reachable(root: &str, layers: &[ovs::LayerSpec]) -> ovs::Result<()> {
    let by_name: HashMap<&str, &ovs::LayerSpec> = layers
        .iter()
        .map(|spec| (spec.name.as_str(), spec))
        .collect();
    // If root isn't a declared layer, let StackBuilder::build report that
    // rather than a confusing orphan list.
    if !by_name.contains_key(root) {
        return Ok(());
    }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut pending = vec![root];
    while let Some(name) = pending.pop() {
        if !seen.insert(name) {
            continue;
        }
        if let Some(spec) = by_name.get(name) {
            if let Some(inner) = spec.inner.as_deref() {
                pending.push(inner);
            }
            for child in &spec.children {
                pending.push(child.as_str());
            }
        }
    }
    let orphans: Vec<&str> = layers
        .iter()
        .map(|spec| spec.name.as_str())
        .filter(|name| !seen.contains(name))
        .collect();
    if !orphans.is_empty() {
        return Err(OvError::new(
            ErrorCode::InvalidArgument,
            format!(
                "declared layer(s) not reachable from root '{root}': {}; \
                 pass root=... or wire them into the graph",
                orphans.join(", ")
            ),
        ));
    }
    Ok(())
}

impl StackComposer {
    fn push_layer(&mut self, layer: &LayerBase) {
        if self.root.is_none() {
            self.root = Some(layer.spec.name.clone());
        }
        self.layers.push(layer.spec.clone());
    }

    fn retain_declaration(&mut self, layer: &Bound<'_, LayerBase>) {
        // `layer` is a borrowed Python instance supplied by the caller;
        // retain a strong reference without moving its Rust payload. Native
        // declarations are retained too so build-time override detection can
        // preserve override-free concrete subclasses while rejecting an
        // implicit Python operational node.
        self.declarations.push(layer.clone().unbind());
    }

    fn push_typed_layer(&mut self, layer: &LayerBase, expected: ovs::LayerType) -> PyResult<()> {
        if layer.layer_type != expected {
            return Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "layer '{}' has layer_type '{}', expected '{}'",
                    layer.spec.name,
                    layer_type_name(layer.layer_type),
                    layer_type_name(expected)
                ),
            )));
        }
        self.push_layer(layer);
        Ok(())
    }
}

/// Plugin dlopen + auth-substrate init are blocking (flock/sqlite); this runs
/// on a blocking thread from `Stack.build()` rather than the event-loop thread.
/// Free function (not a `&self` method) so it needs only `Send` data.
fn load_registry_factories(
    registry: &Option<PluginRegistry>,
    allow_test_plugins: bool,
) -> PyResult<Vec<ovs::LoadedLayerFactory>> {
    let Some(registry) = registry else {
        return Ok(Vec::new());
    };

    // `load_layer_plugin` requires the shared SPI auth substrate. The build
    // later creates the credential resolver with the complete Python options;
    // this call only establishes the same process-global substrate before
    // factory discovery.
    ovs::ensure_auth_substrate_with_default(auth_state_root).map_err(py_error)?;
    let mut cache = registry
        .cache
        .lock()
        .map_err(|_| py_error_msg("PluginRegistry cache lock poisoned"))?;
    let mut factories = Vec::new();
    for path in &registry.paths {
        let loaded = if path.is_dir() {
            load_registry_directory(&mut cache, path, allow_test_plugins)
        } else {
            load_registry_file(&mut cache, path, allow_test_plugins)
        };
        factories.extend(loaded.map_err(py_error)?);
    }
    Ok(factories)
}

/// Load one registry entry that names a plugin library file, reusing the
/// registry's dlopen cache.
fn load_registry_file(
    cache: &mut HashMap<PathBuf, Vec<ovs::LoadedLayerFactory>>,
    path: &Path,
    allow_test_plugins: bool,
) -> ovs::Result<Vec<ovs::LoadedLayerFactory>> {
    // Canonicalize so distinct spellings/symlinks of one library share a
    // cache entry (and one dlopen); fall back to the raw path if it
    // can't be resolved, letting `load_layer_plugin` surface the error.
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(hit) = cache.get(&key) {
        // Cheap `Arc` clones. The library stays mapped for the process
        // either way, so this only avoids a redundant dlopen + re-init.
        return Ok(hit.clone());
    }
    // SAFETY: loading a plugin runs platform loader hooks. Python made the
    // trusted path explicit by placing it in PluginRegistry.
    let loaded = unsafe { ovs::load_layer_plugin(path, allow_test_plugins) }?;
    cache.insert(key, loaded.clone());
    Ok(loaded)
}

/// Load one registry entry that names a directory: every plugin library
/// directly inside it, in sorted order.
///
/// Candidates the scan steps over (no manifest symbol, `test_only` refused by
/// policy, foreign ABI) are the same set the native
/// `load_layer_plugins_from_dir` skips — one stale file beside the plugins
/// must not hide them. A directory that contributes no factories at all is an
/// error instead: the caller named this directory expecting plugins from it,
/// and registering nothing would surface later as an unrelated "unknown layer
/// kind" from `Stack.build()`.
fn load_registry_directory(
    cache: &mut HashMap<PathBuf, Vec<ovs::LoadedLayerFactory>>,
    dir: &Path,
    allow_test_plugins: bool,
) -> ovs::Result<Vec<ovs::LoadedLayerFactory>> {
    let candidates = ovs::discover_plugin_libraries(dir)?;
    let mut factories = Vec::new();
    let mut kinds = std::collections::HashSet::new();
    for path in &candidates {
        match load_registry_file(cache, path, allow_test_plugins) {
            Ok(loaded) => {
                ovs::validate_unique_loaded_plugin_kinds(&mut kinds, &loaded)?;
                factories.extend(loaded);
            }
            // Logged, not dropped. A directory where SOME candidates are
            // skipped is the case this function's empty-directory error exists
            // to make legible, and silence here reproduces exactly the failure
            // that error avoids: the kind never registers and the user meets it
            // later as an unrelated "unknown layer kind" from `Stack.build()`.
            // The native sibling logs the same way.
            Err(error) if ovs::is_skippable_discovery_error(&error) => {
                tracing::debug!(
                    plugin.path = %path.display(),
                    error.message = %error.message(),
                    "skipping non-loadable candidate during directory scan",
                );
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    if factories.is_empty() {
        return Err(OvError::new(
            ErrorCode::InvalidArgument,
            format!(
                "no usable plugin libraries in directory '{}'; expected files named \
                 '{}' directly inside it (subdirectories are not scanned) — pass the path \
                 of a plugin library file instead to see why a specific file is rejected",
                dir.display(),
                ovs::PLUGIN_LIBRARY_FILENAME_PATTERN,
            ),
        ));
    }
    Ok(factories)
}

/// Assemble the native `StackBuilder` from declared specs + loaded factories.
/// Non-blocking, so `Stack.build()` runs it inline after the blocking load.
fn native_builder(
    root: Option<String>,
    layers: &[ovs::LayerSpec],
    factories: Vec<ovs::LoadedLayerFactory>,
    python_factories: Option<p2r_adapter::PyLayerFactories>,
) -> ovs::Result<ovs::StackBuilder> {
    let root = root.ok_or_else(|| {
        OvError::new(
            ErrorCode::InvalidArgument,
            "Stack has no root; pass root=... or add at least one layer",
        )
    })?;
    ensure_layers_reachable(&root, layers)?;
    for factory in &factories {
        let kind = factory.descriptor().kind;
        ensure_plugin_kind_is_not_reserved(&kind)?;
    }
    let mut builder = ovs::layers::register_default_layer_factories(ovs::Stack::builder(root));
    for factory in factories {
        builder = match factory {
            ovs::LoadedLayerFactory::Backend(factory) => builder.backend_factory(factory),
            ovs::LoadedLayerFactory::Wrapper(factory) => builder.wrapper_factory(factory),
            ovs::LoadedLayerFactory::Router(factory) => builder.router_factory(factory),
        };
    }
    if let Some(python_factories) = python_factories {
        builder = python_factories.register(builder);
    }
    for spec in layers {
        builder = builder.layer(spec.clone());
    }
    // Declared connections are intentionally NOT passed to the builder:
    // `StackComposer::build` applies them itself after `build()` so it can
    // capture each returned `Connection.id`.
    Ok(builder)
}

fn ensure_plugin_kind_is_not_reserved(kind: &str) -> ovs::Result<()> {
    if matches!(
        kind,
        p2r_adapter::PYTHON_BACKEND_KIND | p2r_adapter::PYTHON_WRAPPER_KIND
    ) {
        return Err(OvError::new(
            ErrorCode::Conflict,
            format!("plugin layer kind '{kind}' collides with a reserved in-process Python kind"),
        ));
    }
    Ok(())
}

#[pyfunction]
fn _verify_reserved_python_kinds() -> PyResult<()> {
    for kind in [
        p2r_adapter::PYTHON_BACKEND_KIND,
        p2r_adapter::PYTHON_WRAPPER_KIND,
    ] {
        let error = ensure_plugin_kind_is_not_reserved(kind).expect_err("reserved kind accepted");
        if error.code() != ErrorCode::Conflict {
            return Err(py_error(OvError::new(
                ErrorCode::Internal,
                format!("reserved Python kind '{kind}' did not produce Conflict"),
            )));
        }
    }
    Ok(())
}

#[pyfunction]
fn _bridge_local_file_body(py: Python<'_>, path: PathBuf) -> PyResult<PyObject> {
    p2r_adapter::ensure_interpreter_active().map_err(py_error)?;
    p2r_body::body_to_python(py, Body::LocalFile(path), CancellationToken::new()).map_err(py_error)
}

/// Gate probe for the Python-to-native body channel with a retained, idle
/// consumer. Cancellation must retire the Python producer without waiting for
/// channel capacity, and the eventual native drain must end in `Cancelled`.
#[pyfunction]
fn _probe_full_python_body_cancel<'py>(
    py: Python<'py>,
    iterator: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    let observer = iterator.clone_ref(py);
    let cancel = CancellationToken::new();
    let body = body_from_python_input(py, iterator, cancel.clone())?;
    let Body::Stream(mut stream) = body else {
        return Err(py_error(OvError::new(
            ErrorCode::Internal,
            "full Python body probe did not create Body::Stream",
        )));
    };
    // The observed iterator is a Python handle held until dispatch, so it
    // goes in the captures rather than in the closure.
    coroutine_into_py_with_setup(
        py,
        "_probe_full_python_body_cancel",
        vec![observer],
        move |_py, captures| {
            let observer = captures
                .into_iter()
                .next()
                .ok_or_else(|| py_error_msg("probe observer capture was cleared"))?;
            Ok(async move {
                let deadline = tokio::time::Instant::now() + p2r_adapter::PY_POST_CANCEL_TIMEOUT;
                loop {
                    let pulls = crate::bridge_gil::with_bridge_gil_py(|py| {
                        observer.bind(py).getattr("pulls")?.extract::<usize>()
                    })?;
                    if pulls > p2r_adapter::PY_BRIDGE_CHANNEL_CAPACITY {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(py_error(OvError::new(
                            ErrorCode::DeadlineExceeded,
                            "Python body producer did not fill the bounded channel",
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                cancel.cancel();
                if !p2r_adapter::quiesce_bridge_tasks(p2r_adapter::PY_POST_CANCEL_TIMEOUT).await {
                    return Err(py_error(OvError::new(
                        ErrorCode::DeadlineExceeded,
                        "full Python body producer did not retire after cancellation",
                    )));
                }
                let buffered = tokio::task::spawn_blocking(move || {
                    let mut buffered = 0;
                    loop {
                        match stream.next_chunk() {
                            Some(Ok(_)) => buffered += 1,
                            Some(Err(error)) if error.code() == ErrorCode::Cancelled => {
                                return Ok(buffered);
                            }
                            Some(Err(error)) => return Err(error),
                            None => {
                                return Err(OvError::new(
                                    ErrorCode::Internal,
                                    "full Python body probe observed clean EOF",
                                ));
                            }
                        }
                    }
                })
                .await
                .map_err(|error| {
                    py_error(OvError::new(
                        ErrorCode::Internal,
                        format!("full Python body drain worker failed: {error}"),
                    ))
                })?
                .map_err(py_error)?;
                if buffered != p2r_adapter::PY_BRIDGE_CHANNEL_CAPACITY {
                    return Err(py_error(OvError::new(
                        ErrorCode::Internal,
                        format!(
                            "full Python body probe drained {buffered} items, expected {}",
                            p2r_adapter::PY_BRIDGE_CHANNEL_CAPACITY
                        ),
                    )));
                }
                Ok(buffered)
            })
        },
    )
}

/// Gate probe for native abandonment while a Python body pull is pending.
/// Dropping the receiver must cancel only its producer child token, allowing
/// the retained `__anext__` task and iterator cleanup to retire immediately.
#[pyfunction]
fn _probe_drop_python_body_receiver<'py>(
    py: Python<'py>,
    iterator: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    let observer = iterator.clone_ref(py);
    let operation_cancel = CancellationToken::new();
    let body = body_from_python_input(py, iterator, operation_cancel.clone())?;
    let Body::Stream(stream) = body else {
        return Err(py_error(OvError::new(
            ErrorCode::Internal,
            "receiver-drop probe did not create Body::Stream",
        )));
    };
    // The observed iterator is a Python handle held until dispatch, so it
    // goes in the captures rather than in the closure.
    coroutine_into_py_with_setup(
        py,
        "_probe_drop_python_body_receiver",
        vec![observer],
        move |_py, captures| {
            let observer = captures
                .into_iter()
                .next()
                .ok_or_else(|| py_error_msg("probe observer capture was cleared"))?;
            Ok(async move {
                let deadline = tokio::time::Instant::now() + p2r_adapter::PY_POST_CANCEL_TIMEOUT;
                loop {
                    let blocked = crate::bridge_gil::with_bridge_gil_py(|py| {
                        observer
                            .bind(py)
                            .getattr("blocked")?
                            .call_method0("is_set")?
                            .extract::<bool>()
                    })?;
                    if blocked {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(py_error(OvError::new(
                            ErrorCode::DeadlineExceeded,
                            "Python body receiver-drop probe did not enter __anext__",
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }

                drop(stream);
                if operation_cancel.is_cancelled() {
                    return Err(py_error(OvError::new(
                        ErrorCode::Internal,
                        "dropping a Python body receiver cancelled the operation token",
                    )));
                }
                if !p2r_adapter::quiesce_bridge_tasks(p2r_adapter::PY_POST_CANCEL_TIMEOUT).await {
                    return Err(py_error(OvError::new(
                        ErrorCode::DeadlineExceeded,
                        "Python body producer did not retire after receiver drop",
                    )));
                }
                Ok(())
            })
        },
    )
}

/// Gate probe for the row-5 error conversion path. The Python caller retains
/// the GIL while a native thread constructs the forced-finalization error; any
/// accidental `with_gil` in that branch makes the bounded receive fail.
#[pyfunction]
fn _probe_finalization_safe_error_conversion() -> PyResult<()> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let thread = std::thread::spawn(move || {
        drop(py_error_with_interpreter_state(
            p2r_adapter::finalizing_error(),
            true,
        ));
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(1)).map_err(|_| {
        py_error(OvError::new(
            ErrorCode::DeadlineExceeded,
            "finalization-safe error conversion attempted to acquire the GIL",
        ))
    })?;
    thread.join().map_err(|_| {
        py_error(OvError::new(
            ErrorCode::Internal,
            "finalization-safe error conversion thread panicked",
        ))
    })?;
    Ok(())
}

/// Free the outer heap allocation of an `export_handle()` **int** handle after
/// it has been imported. The int form's `import_handle` copies the
/// `{state, vtable}` pair out but never frees the box, so the exporter's caller
/// reclaims it here — the pure-Python equivalent of `free(ptr)`.
///
/// This frees **only** the outer box; it must not run `ffi::LayerHandle::drop`
/// (its vtable `drop` slot already fired through the importer), so the husk is
/// moved out and forgotten. Call it exactly once, only after a successful
/// `import_handle(ptr)`; for a handle that might never be imported, use the
/// capsule form instead (its destructor releases the producer-side reference).
#[pyfunction]
fn _free_exported_handle(ptr: usize) {
    if ptr == 0 {
        return;
    }
    // SAFETY: `ptr` is an `export_handle()` int handle whose pair was already
    // consumed by `import_handle`. Reclaim the box's heap (via the move-out)
    // and forget the husk so the already-fired drop slot is not run again.
    let boxed = unsafe { Box::from_raw(ptr as *mut ovs::ffi::LayerHandle) };
    std::mem::forget(*boxed);
}

/// Debug-build count of live `LayerHandle`s minted by this extension's
/// `export_handle` that have not yet been dropped or imported. Always `0` in
/// release builds (the accounting is compiled out). Private teardown/leak
/// probe for the handoff tests.
#[pyfunction]
fn _live_export_count() -> usize {
    ovs::live_export_count()
}

/// Gate probe: enter the fence's first phase without running the whole fence.
///
/// `DRAINING` is the state the three-state design exists for -- new work
/// refused, retirement still admitted -- and it is otherwise unobservable,
/// because `_fence_bridge_gil` passes through it in microseconds.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_begin_draining() {
    bridge_gil::begin_draining();
}

/// Gate probe: the finalization guard's two readings, which one boolean cannot
/// separate.
///
/// Returns `(confirmed, guarded)`. `guarded` fails closed -- it is `true` both
/// when the interpreter really is finalizing and when neither `Py_IsFinalizing`
/// spelling resolved on this host, because a host that cannot answer the
/// question cannot be attached to safely. `confirmed` is `true` only in the
/// first case. So `(false, false)` is the one state the fence's window is in,
/// and `(false, true)` isolates "the symbol did not resolve here" -- which is a
/// per-interpreter property worth asserting rather than assuming.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_finalization_guard_state() -> (bool, bool) {
    (
        p2r_adapter::interpreter_is_confirmed_finalizing(),
        p2r_adapter::interpreter_is_finalizing(),
    )
}

/// Gate probe: can a thread CPython does not own attach right now?
///
/// Spawns a real OS thread and has it take the ordinary dispatch route. This is
/// the operation the fence exists to make safe, performed from the kind of
/// thread that is unsafe -- which no flag read from the Python thread can stand
/// in for.
///
/// Three outcomes, not two. `"admitted"` and `"refused"` are the gate's own
/// answers; `"timeout"` is the third thing that can happen and it must not
/// collapse into either. From CPython 3.13.8 a thread forbidden to attach
/// during finalization is made to hang rather than terminated, so a boolean
/// would report a wedged thread as a clean refusal -- turning the one outcome
/// that means "the premise this asserts has broken" into a pass.
///
/// The GIL is released for the wait. Holding it would leave the spawned thread
/// unable to acquire it, and every build would report `"timeout"`.
///
/// The thread is deliberately not joined. On the `"timeout"` path it is by
/// definition not going to return, and blocking the interpreter's exit on it
/// would convert a legible failure into a hang.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_foreign_thread_attach(py: Python<'_>) -> &'static str {
    py.allow_threads(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = tx.send(bridge_gil::with_bridge_gil(|_py| Ok(())).is_ok());
        });
        // A refusal answers without attaching at all; an admitted attach waits
        // only for the GIL. Neither needs long.
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(true) => "admitted",
            Ok(false) => "refused",
            Err(_) => "timeout",
        }
    })
}

/// Gate probe: a panicking bridge future must still settle its awaitable.
///
/// The dependency's conversion layer caught the join error and raised
/// `RustPanic`. Owning the conversion means owning that too -- without it a
/// panic leaves the caller awaiting something that can never complete.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_panicking_bridge_future(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    bridge_gil::future_into_py(py, async move {
        panic!("probe panic");
        #[allow(unreachable_code)]
        Ok::<(), PyErr>(())
    })
}

/// Set by [`_probe_abandon_on_cancel`]'s future if it is ever allowed to run to
/// completion.
#[cfg(feature = "test-probes")]
static ABANDON_PROBE_COMPLETED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Gate probe: cancelling the awaitable must drop the Rust future.
///
/// The dependency did this by discarding the inner future, which is exactly
/// the path that attached unguarded. The replacement stops the task from its
/// own side instead, and this probe is what proves it still stops: if the
/// future runs on, it sets a flag the test can see.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_abandon_on_cancel(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    ABANDON_PROBE_COMPLETED.store(false, std::sync::atomic::Ordering::Release);
    bridge_gil::future_into_py(py, async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        ABANDON_PROBE_COMPLETED.store(true, std::sync::atomic::Ordering::Release);
        Ok::<(), PyErr>(())
    })
}

/// Whether [`_probe_abandon_on_cancel`]'s future ran to completion.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_abandon_completed() -> bool {
    ABANDON_PROBE_COMPLETED.load(std::sync::atomic::Ordering::Acquire)
}

/// Fence the bridge against interpreter finalization.
///
/// Registered with `atexit`, which CPython runs while the interpreter is still
/// fully usable — before the finalizing flag is set and before foreign threads
/// start being terminated on attach. That window is the only place this can be
/// done, and it is what makes the admission gate sound rather than another
/// check-then-act.
///
/// Three phases, in this order:
///
/// 1. Stop admitting new dispatches, while still admitting the cleanup they
///    provoke. An in-flight dispatch notices at its next liveness poll and
///    retires itself through paths that still need the interpreter.
/// 2. Settle, bounded, so that retirement actually happens.
/// 3. Close admission outright and wait for anyone still attached to leave.
///
/// **Phases 2 and 3 must both run without the GIL, and that is an invariant,
/// not an optimisation.** Phase 2 needs it because the loop thread services
/// the cancellations phase 1 provokes, and cannot without the GIL. Phase 3
/// needs it because an admitted thread is typically blocked in
/// `PyEval_RestoreThread` waiting for precisely this GIL, so draining while
/// holding it deadlocks until the watchdog. Anything added to this sequence
/// belongs inside the same `allow_threads`.
///
/// Returns whether the drain completed. `atexit` discards the value, so
/// [`_bridge_gil_drained`] exposes the same fact to tests and to anyone
/// diagnosing a shutdown; a `false` here means a thread was still attached
/// when finalization proceeded.
#[pyfunction]
fn _fence_bridge_gil(py: Python<'_>) -> bool {
    bridge_gil::begin_draining();
    let drained = py.allow_threads(|| {
        let deadline = std::time::Instant::now() + p2r_adapter::PY_POST_CANCEL_TIMEOUT;
        while p2r_adapter::bridge_task_count() > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        bridge_gil::close_admission();
        bridge_gil::wait_for_drain(bridge_gil::FENCE_DRAIN_TIMEOUT)
    });
    if !drained {
        // `atexit` discards the return value, so without this the one case the
        // fence cannot handle -- a thread that holds admission across Python
        // code which releases the GIL for longer than the drain budget -- would
        // proceed to finalization silently and, if it loses the race, abort
        // with no explanation at all. Name it while there is still an
        // interpreter to name it with. The wording states what was measured:
        // admission was still held when the drain gave up. That thread may
        // still leave before finalization reaches anything dangerous.
        let _ = py.import_bound("warnings").and_then(|warnings| {
            warnings.call_method1(
                "warn",
                (
                    "ovstorage: a bridge thread was still inside the Python interpreter when \
                     the shutdown fence stopped waiting; if this process aborts during \
                     shutdown, that is why",
                    py.get_type_bound::<pyo3::exceptions::PyRuntimeWarning>(),
                ),
            )
        });
    }
    drained
}

/// Whether the bridge gate is currently drained. Test-only visibility into the
/// fence's post-condition.
#[pyfunction]
fn _bridge_gil_drained() -> bool {
    bridge_gil::drained()
}

/// Producer-lifetime tripwire, registered with `atexit`: in debug builds it
/// panics (surfaced as a printed atexit exception, never a hard abort) when an
/// exported handle is still live as the interpreter finalizes — the producer
/// being torn down out from under a consumer. A no-op in release builds.
#[pyfunction]
fn _debug_assert_no_live_exports() {
    ovs::debug_assert_no_live_exports(
        "ovstorage Python interpreter finalization: an exported LayerHandle is still live",
    );
}

/// Deep-assertion probe: force a Python-exported handle down
/// the *foreign* import path and drive it entirely from a non-Python tokio
/// worker. The C driver TU covers the same raw-vtable consumption from a
/// separate image; this probe covers the assertions that TU can't express —
/// forcing the foreign wrap in-process (the same-binary fast path would collapse
/// to Arc identity and never touch the FFI slots), and driving a genuinely
/// foreign import against a Python leaf running on its own `OwnedLoop` (the
/// producer-owned-loop decoupling contract). `ForeignVtableLayer` *is* the raw-slot consumer, so
/// there is no second hand-rolled vtable driver here.
///
/// `handle` is an `export_handle()` int; the pair is copied out (never freed —
/// the caller frees the outer box via [`_free_exported_handle`]) and consumed by
/// the forced-foreign import, exactly like the int-form `import_handle`. The
/// returned awaitable drives `stat`, buffered `read`, a streamed `read` (drained
/// chunk by chunk to prove `ReadResult::Stream` crosses), `write`, and `list`,
/// then drops the foreign import — releasing the producer-side reference across
/// the bridge — and resolves to a summary dict the pytest asserts on.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_drive_foreign_import<'py>(
    py: Python<'py>,
    handle: usize,
    address: String,
    stream_address: String,
    list_prefix: String,
    write_address: String,
    payload: Vec<u8>,
) -> PyResult<Bound<'py, PyAny>> {
    use futures::StreamExt as _;

    if handle == 0 {
        return Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            "_probe_drive_foreign_import received a null handle pointer",
        )));
    }
    let ptr = handle as *const ovs::ffi::LayerHandle;
    // SAFETY: `ptr` is an `export_handle()` int handle; `state`/`vtable` are
    // `Copy`, so the read leaves the outer box intact for `_free_exported_handle`.
    let raw = ovs::ffi::LayerHandle {
        state: unsafe { (*ptr).state },
        vtable: unsafe { (*ptr).vtable },
    };
    let stat_address = address::parse(&address).map_err(py_error)?;
    let stream_address = address::parse(&stream_address).map_err(py_error)?;
    let list_prefix = address::parse(&list_prefix).map_err(py_error)?;
    let write_address = address::parse(&write_address).map_err(py_error)?;
    // SAFETY: `raw` is a live Layer-ABI handle whose producer outlives it; the
    // forced-foreign import genuinely takes ownership of the copied-out pair.
    let imported = unsafe { ovs::import_handle_force_foreign(raw) }.map_err(py_error)?;

    coroutine_into_py(py, "_probe_drive_foreign_import", async move {
        let stat = imported
            .stat(
                ovs::Request::new(ovs::StatRequest {
                    address: stat_address.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .map_err(py_error)?;

        let (read_bytes, _info) = read_layer_bytes(Arc::clone(&imported), stat_address, None, None)
            .await
            .map_err(py_error)?;

        // Drive the streamed variant explicitly so the drain (not just the
        // buffered collapse) exercises the foreign `ReadResult::Stream` bridge.
        let mut stream_bytes = Vec::new();
        let was_stream = match imported
            .read(
                ovs::Request::new(ovs::ReadRequest {
                    address: stream_address,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .map_err(py_error)?
        {
            ovs::ReadResult::Stream { mut stream, .. } => {
                while let Some(chunk) = stream.next().await {
                    stream_bytes.extend_from_slice(&chunk.map_err(py_error)?);
                }
                true
            }
            ovs::ReadResult::Bytes { bytes, .. } => {
                stream_bytes = bytes;
                false
            }
            other => {
                return Err(py_error(OvError::new(
                    ErrorCode::Internal,
                    format!("streamed read probe got an unexpected result: {other:?}"),
                )));
            }
        };

        let write = imported
            .write(
                ovs::Request::new(ovs::WriteRequest {
                    address: write_address,
                    body: Body::Bytes(payload),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .map_err(py_error)?;

        let page = imported
            .list(
                ovs::Request::new(ovs::ListRequest {
                    prefix: list_prefix,
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .map_err(py_error)?;

        bridge_gil::with_bridge_gil_py(|py| {
            let summary = PyDict::new_bound(py);
            summary.set_item("stat_size", stat.size)?;
            summary.set_item("read_bytes", PyBytes::new_bound(py, &read_bytes))?;
            summary.set_item("stream_bytes", PyBytes::new_bound(py, &stream_bytes))?;
            summary.set_item("was_stream", was_stream)?;
            summary.set_item("write_size", write.info.size)?;
            summary.set_item("list_count", page.items.len())?;
            Ok(summary.into_py(py))
        })
        // `imported` drops here: the foreign wrapper's `drop` slot reclaims the
        // producer-side `Box<Arc<dyn Layer>>` across the bridge.
    })
}

/// Does this composition contain any Python-implemented layer?
///
/// Decides whether `StackComposer::build`'s setup closure captures `TaskLocals`
/// on the coroutine's first step. An all-native composition needs no asyncio
/// loop at all, so it must not be made to demand one.
///
/// One definition, called from one place. If a second caller ever needs the
/// same question answered, it calls this rather than spelling the predicate out
/// again — two copies that disagree would let a composition capture without
/// being recognised as needing to, or the reverse.
fn has_python_nodes(py: Python<'_>, declarations: &[Py<LayerBase>]) -> bool {
    declarations
        .iter()
        .any(|object| object.bind(py).borrow().declaration.is_some())
}

fn claim_python_declarations(py: Python<'_>, declarations: &[Py<LayerBase>]) -> PyResult<()> {
    let mut seen = std::collections::HashSet::new();
    for object in declarations {
        let layer = object.bind(py).borrow();
        let Some(declaration) = &layer.declaration else {
            continue;
        };
        if declaration.bound || !seen.insert(object.as_ptr() as usize) {
            return Err(py_error(OvError::new(
                ErrorCode::Conflict,
                format!(
                    "Python layer declaration '{}' has already been bound to a Stack",
                    declaration.name
                ),
            )));
        }
    }
    // The first pass guarantees this pass cannot fail partway through, so a
    // composer either claims all of its declaration instances or none.
    for object in declarations {
        object.bind(py).borrow_mut().claim_declaration()?;
    }
    Ok(())
}

/// Capture the asyncio `TaskLocals` under which p2r bridges dispatch Python
/// layer bodies for the duration of the built stack.
///
/// With no `event_loop` this captures the currently running loop (the default —
/// called on the coroutine's first step, this is the loop `Stack.build()` is
/// awaited on, and the loop that must stay alive for the built stack).
/// When `Stack.build(loop=...)` designates a producer-owned loop instead, that
/// loop must outlive every handle exported from the built stack (the RFC-0066
/// R8 contract); once it stops, dispatch surfaces typed `NotConfigured` per
/// call rather than hanging or hitting UB. The loop is validated open here so a
/// stale handle is rejected before any Python leaf is bound to it.
fn capture_python_task_locals(
    py: Python<'_>,
    event_loop: Option<&PyObject>,
) -> PyResult<pyo3_async_runtimes::TaskLocals> {
    let Some(event_loop) = event_loop else {
        // Capture both the caller's running asyncio loop and its contextvars
        // synchronously under the GIL. Every synthetic factory receives a
        // clone of this immutable build-time context.
        return pyo3_async_runtimes::TaskLocals::with_running_loop(py)
            .and_then(|locals| locals.copy_context(py))
            .map_err(|error| {
                py_error(OvError::new(
                    ErrorCode::NotConfigured,
                    format!(
                        "Python layer composition requires a running asyncio loop to capture: {error}"
                    ),
                ))
            });
    };
    let event_loop = event_loop.bind(py);
    // A closed loop can never run a dispatch, so reject it up front with the
    // same typed code a later stop surfaces. `is_closed()` also validates the
    // argument is loop-shaped before it is handed to `TaskLocals::new`.
    let closed = event_loop
        .call_method0("is_closed")
        .and_then(|value| value.extract::<bool>())
        .map_err(|error| {
            py_error(OvError::new(
                ErrorCode::InvalidArgument,
                format!("Stack.build(loop=...) expects an asyncio event loop: {error}"),
            ))
        })?;
    if closed {
        return Err(py_error(OvError::new(
            ErrorCode::NotConfigured,
            "Stack.build(loop=...) was given a closed event loop",
        )));
    }
    // Snapshot the current contextvars, mirroring `with_running_loop`'s
    // `copy_context`, so producer-owned dispatch runs under the build-time
    // context rather than whatever context happens to be current on the loop
    // thread.
    let context = py
        .import_bound("contextvars")
        .and_then(|module| module.call_method0("copy_context"))
        .map_err(|error| {
            py_error(OvError::new(
                ErrorCode::NotConfigured,
                format!(
                    "failed to copy the contextvars context for Stack.build(loop=...): {error}"
                ),
            ))
        })?;
    Ok(pyo3_async_runtimes::TaskLocals::new(event_loop.clone()).with_context(context))
}

fn prepare_python_factories(
    py: Python<'_>,
    declarations: &[Py<LayerBase>],
    task_locals: pyo3_async_runtimes::TaskLocals,
) -> PyResult<p2r_adapter::PyLayerFactories> {
    let mut nodes = HashMap::new();
    for object in declarations {
        let layer = object.bind(py).borrow();
        let Some(declaration) = &layer.declaration else {
            continue;
        };

        let roots = declaration
            .roots
            .iter()
            // `address::parse` canonicalizes, so the declared root reaches the
            // node in the same spelling a request will.
            .map(|root| ovs::address::parse(root).map_err(py_error))
            .collect::<PyResult<Vec<_>>>()?;
        nodes.insert(
            declaration.name.clone(),
            Arc::new(p2r_adapter::PyLayerFactoryNode::new(
                object.clone_ref(py),
                declaration.layer_type,
                roots,
            )),
        );
    }
    Ok(p2r_adapter::PyLayerFactories::new(nodes, task_locals))
}

fn ensure_no_implicit_python_nodes(py: Python<'_>, declarations: &[Py<LayerBase>]) -> PyResult<()> {
    for object in declarations {
        let layer = object.bind(py).borrow();
        let is_python_declaration = layer.declaration.is_some();
        let is_projection = layer.inner.is_some();
        let name = layer.spec.name.clone();
        drop(layer);

        let py_obj = object.clone_ref(py).into_any();
        let overrides = p2r_adapter::detect_overrides(py, &py_obj).map_err(py_error)?;
        if is_python_declaration {
            // Explicit declarations are valid Python nodes, but classify
            // their callables synchronously so malformed overrides fail
            // before declaration ownership is claimed.
            continue;
        }
        if overrides.is_empty() {
            // In particular, an override-free subclass of FileBackend or
            // another concrete declaration remains a pure-native spec.
            continue;
        }
        let operation_names = overrides
            .keys()
            .map(|slot| slot.name())
            .collect::<Vec<_>>()
            .join(", ");
        if is_projection {
            return Err(py_error(OvError::new(
                ErrorCode::NotConfigured,
                format!(
                    "override-bearing LayerBase projection '{name}' has no declaration state \
                     (overrides: {operation_names}); construct it with name= and layer_type= \
                     before adding it to Stack"
                ),
            )));
        }
        return Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            format!(
                "native layer declaration '{name}' defines operational override(s) \
                 {operation_names}; express it as an explicit LayerBase declaration"
            ),
        )));
    }
    Ok(())
}

/// A native Router can discover only the static roots published by each
/// child. Follow wrapper edges to catch the equally broken
/// `router -> wrapper(s) -> rootless Python backend` shape before it builds a
/// route table that misleadingly returns `NoRoute` for every address.
fn ensure_python_router_leaves_have_roots(
    layers: &[ovs::LayerSpec],
    declarations: &[Py<LayerBase>],
    py: Python<'_>,
) -> PyResult<()> {
    let specs: HashMap<&str, &ovs::LayerSpec> = layers
        .iter()
        .map(|spec| (spec.name.as_str(), spec))
        .collect();
    let rootless: std::collections::HashSet<String> = declarations
        .iter()
        .filter_map(|object| {
            let layer = object.bind(py).borrow();
            layer.declaration.as_ref().and_then(|declaration| {
                (declaration.layer_type == ovs::LayerType::Backend && declaration.roots.is_empty())
                    .then(|| declaration.name.clone())
            })
        })
        .collect();

    fn rootless_leaf<'a>(
        name: &'a str,
        specs: &HashMap<&'a str, &'a ovs::LayerSpec>,
        rootless: &std::collections::HashSet<String>,
        seen: &mut std::collections::HashSet<&'a str>,
    ) -> Option<&'a str> {
        if rootless.contains(name) {
            return Some(name);
        }
        if !seen.insert(name) {
            return None;
        }
        let spec = specs.get(name)?;
        match spec.layer_type {
            ovs::LayerType::Wrapper => spec
                .inner
                .as_deref()
                .and_then(|inner| rootless_leaf(inner, specs, rootless, seen)),
            ovs::LayerType::Backend | ovs::LayerType::Router => None,
        }
    }

    for router in layers
        .iter()
        .filter(|spec| spec.layer_type == ovs::LayerType::Router)
    {
        for child in &router.children {
            if let Some(leaf) = rootless_leaf(
                child,
                &specs,
                &rootless,
                &mut std::collections::HashSet::new(),
            ) {
                return Err(py_error(OvError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "Python backend '{leaf}' is reachable under native router '{}' but has \
                         no declared address roots; pass roots=[...] to its LayerBase declaration",
                        router.name
                    ),
                )));
            }
        }
    }
    Ok(())
}

fn declaration_string(
    py: Python<'_>,
    value: Option<PyObject>,
    argument: &str,
) -> PyResult<Option<String>> {
    value
        .map(|value| {
            value.bind(py).extract::<String>().map_err(|_| {
                py_error(OvError::new(
                    ErrorCode::IncompatibleType,
                    format!("LayerBase declaration {argument}= must be a string"),
                ))
            })
        })
        .transpose()
}

fn declaration_roots(py: Python<'_>, value: Option<PyObject>) -> PyResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let roots = value.bind(py).downcast::<PyList>().map_err(|_| {
        py_error(OvError::new(
            ErrorCode::IncompatibleType,
            "LayerBase declaration roots= must be a list of address-root strings",
        ))
    })?;
    roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            let root = root.extract::<String>().map_err(|_| {
                py_error(OvError::new(
                    ErrorCode::IncompatibleType,
                    format!("LayerBase declaration roots[{index}] must be a string"),
                ))
            })?;
            ovs::Url::parse(&root).map_err(|error| {
                py_error(OvError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid LayerBase declaration roots[{index}] '{root}': {error}"),
                ))
            })?;
            Ok(root)
        })
        .collect()
}

#[pymethods]
impl StackComposer {
    /// The composer holds the same Python handles the deferred `build()` does
    /// — the declarations and the credential callback — and holds them for as
    /// long as the caller keeps the composer. `leaf.stack =
    /// ovstorage.Stack(root="x").backend(leaf)` closes a cycle with no
    /// coroutine involved at all, so this type needs the traversal for the
    /// same reason `DeferredCall` does.
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        for declaration in &self.declarations {
            visit.call(declaration)?;
        }
        if let Some(callback) = &self.credential_callback {
            visit.call(callback)?;
        }
        Ok(())
    }

    /// Drop only what `__traverse__` reports.
    ///
    /// This does not leave a composer that fails cleanly: `root`, `layers` and
    /// `connections` survive, so an all-native cleared composer would still
    /// build, minus the Python-node checks its declarations drive. That is
    /// unreachable rather than handled — `tp_clear` runs only on objects the
    /// collector has already found unreachable, which no caller can still
    /// name.
    fn __clear__(&mut self) {
        self.declarations.clear();
        self.credential_callback = None;
    }

    #[new]
    #[pyo3(signature = (
        root=None,
        interactive_auth_capability=None,
        credential_cache_durability=None,
        credential_callback=None,
        credential_callback_name=None,
        principal_id=None,
        allow_test_plugins=false,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        root: Option<String>,
        interactive_auth_capability: Option<i32>,
        credential_cache_durability: Option<i32>,
        credential_callback: Option<PyObject>,
        credential_callback_name: Option<String>,
        principal_id: Option<String>,
        allow_test_plugins: bool,
    ) -> Self {
        Self {
            root,
            layers: Vec::new(),
            connections: Vec::new(),
            registry: None,
            interactive_auth_capability,
            credential_cache_durability,
            credential_callback,
            credential_callback_name,
            principal_id: principal_id.unwrap_or_default(),
            allow_test_plugins,
            declarations: Vec::new(),
        }
    }

    /// Add one exact `LayerSpec` declaration to the composition. The first
    /// declaration becomes the root when the constructor omitted `root`.
    fn layer<'py>(
        mut slf: PyRefMut<'py, Self>,
        layer: Bound<'py, LayerBase>,
    ) -> PyRefMut<'py, Self> {
        slf.push_layer(&layer.borrow());
        slf.retain_declaration(&layer);
        slf
    }

    /// Typed convenience for a backend declaration. This still contributes
    /// the declaration object's `LayerSpec::backend`; it is not a terminal
    /// shortcut and does not bypass the graph builder.
    fn backend<'py>(
        mut slf: PyRefMut<'py, Self>,
        layer: Bound<'py, LayerBase>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.push_typed_layer(&layer.borrow(), ovs::LayerType::Backend)?;
        slf.retain_declaration(&layer);
        Ok(slf)
    }

    /// Typed convenience for a wrapper declaration, preserving its exact
    /// `LayerSpec::wrapper` inner edge.
    fn wrapper<'py>(
        mut slf: PyRefMut<'py, Self>,
        layer: Bound<'py, LayerBase>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.push_typed_layer(&layer.borrow(), ovs::LayerType::Wrapper)?;
        slf.retain_declaration(&layer);
        Ok(slf)
    }

    /// Typed convenience for a router declaration, preserving its exact
    /// `LayerSpec::router` children.
    fn router<'py>(
        mut slf: PyRefMut<'py, Self>,
        layer: Bound<'py, LayerBase>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.push_typed_layer(&layer.borrow(), ovs::LayerType::Router)?;
        slf.retain_declaration(&layer);
        Ok(slf)
    }

    /// Attach a native plugin-factory registry. The built-in `file` factory is
    /// always registered independently.
    fn with_registry<'py>(
        mut slf: PyRefMut<'py, Self>,
        registry: PyRef<'_, PluginRegistry>,
    ) -> PyRefMut<'py, Self> {
        slf.registry = Some(registry.clone());
        slf
    }

    /// Add a connection request owned by the named Layer, consuming the
    /// mutable request.
    fn connection<'py>(
        mut slf: PyRefMut<'py, Self>,
        target: String,
        request: &ConnectionRequest,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let connection = request
            .inner
            .lock()
            .map_err(|_| py_error_msg("ConnectionRequest lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
        slf.connections
            .push(ovs::LayerConnectionRequest { target, connection });
        Ok(slf)
    }

    /// Build the immutable all-native Stack, then wrap it in the Stack owner
    /// carrying the configured credential providers/cache/auth capability.
    ///
    /// `loop` optionally designates a producer-owned asyncio event loop to run
    /// any Python layer bodies on (see `ovstorage.OwnedLoop`), instead of the
    /// caller's running loop. It must outlive every handle exported from the
    /// built stack (the RFC-0066 R8 contract). An all-native stack ignores it.
    #[pyo3(signature = (r#loop = None))]
    fn build<'py>(&self, py: Python<'py>, r#loop: Option<PyObject>) -> PyResult<Bound<'py, PyAny>> {
        // Cheap synchronous failures do not consume declaration identity.
        // These are pure validation: they inspect the declarations without
        // marking them, so a `build()` that never runs leaves nothing behind.
        ensure_python_router_leaves_have_roots(&self.layers, &self.declarations, py)?;
        ensure_no_implicit_python_nodes(py, &self.declarations)?;
        // The declarations, an explicit `loop=`, and the credential callback
        // are the Python handles this
        // operation needs at dispatch, so they travel as `DeferredCall`
        // captures rather than inside the closure, where no visitor could
        // reach them. An absent `loop=` or callback rides along as Python
        // `None`; neither is ever legitimately `None`.
        // A mis-paired credential callback is a caller error, so it fails here
        // rather than at the first step, even though the provider it feeds is
        // not built until then.
        ensure_credential_callback_pairing(
            self.credential_callback.as_ref(),
            self.credential_callback_name.as_ref(),
        )?;
        let mut captures: Vec<PyObject> = vec![
            r#loop.unwrap_or_else(|| py.None()),
            self.credential_callback
                .as_ref()
                .map_or_else(|| py.None(), |callback| callback.clone_ref(py)),
        ];
        captures.extend(
            self.declarations
                .iter()
                .map(|object| object.clone_ref(py).into_any()),
        );
        let registry = self.registry.clone();
        let allow_test_plugins = self.allow_test_plugins;
        let root = self.root.clone();
        let layers = self.layers.clone();
        let connections = self.connections.clone();
        let interactive_auth_capability = self.interactive_auth_capability;
        let credential_cache_durability = self.credential_cache_durability;
        let principal_id = self.principal_id.clone();
        let credential_callback_name = self.credential_callback_name.clone();

        // Declaration identity is claimed on the coroutine's FIRST STEP, not at
        // call time. A `build()` coroutine that is closed, or whose task is
        // cancelled before the scheduler resumes it, is never dispatched — so
        // it must leave its declarations reusable, or cancellation would be
        // unrecoverable. Claiming here, under the GIL and before the Rust
        // future is spawned, keeps that boundary exact: either the build was
        // dispatched and the declarations are consumed, or neither happened.
        // Once dispatched, claiming remains irreversible for that attempt.
        coroutine_into_py_with_setup(py, "Stack.build", captures, move |py, captures| {
            let mut captures = captures.into_iter();
            let r#loop = captures.next().filter(|value| !value.is_none(py));
            let credential_callback = captures.next().filter(|value| !value.is_none(py));
            let declarations = captures
                .map(|object| object.extract::<Py<LayerBase>>(py))
                .collect::<PyResult<Vec<_>>>()?;
            // The provider needs the GIL to inspect the Python callable, and
            // the first step holds it. Building it here rather than at call
            // time is what keeps the callable in `captures`, where the
            // collector can see it.
            let callback_provider =
                credential_callback_provider(py, credential_callback, credential_callback_name)?;
            // Capture the dispatch context here, on the coroutine's first step,
            // so the captured loop is the one actually stepping this coroutine —
            // not the loop that was running when `build()` was called. With no
            // `loop=`, `with_running_loop` captures the current running loop,
            // which is by construction the one that will own the built stack's
            // Python-layer dispatch. `loop=` remains the explicit cross-loop
            // handoff path and is unaffected by this ordering.
            //
            // BEFORE the claim, and that order is load-bearing. This is the last
            // step that can still fail without dispatching: an explicit `loop=`
            // is rejected here for being the wrong shape, being closed, or
            // failing to copy its contextvars. The call-time probe cannot cover
            // those — it has no loop to inspect until this point — so if the
            // claim came first, `build(loop=<closed>)` would raise its typed
            // error having already bound every declaration permanently, and a
            // retry with a good loop would hit "already been bound" with no way
            // back. That is exactly what the comment above promises cannot
            // happen.
            let task_locals = if has_python_nodes(py, &declarations) {
                Some(capture_python_task_locals(py, r#loop.as_ref())?)
            } else {
                None
            };
            claim_python_declarations(py, &declarations)?;
            let python_factories = match task_locals {
                Some(task_locals) => {
                    Some(prepare_python_factories(py, &declarations, task_locals)?)
                }
                None => None,
            };
            Ok(async move {
                // Plugin dlopen + auth-substrate init are blocking (flock/sqlite);
                // run them on a blocking thread so neither the event loop nor the
                // GIL is held across them while the async future is pending.
                let factories = tokio::task::spawn_blocking(move || {
                    load_registry_factories(&registry, allow_test_plugins)
                })
                .await
                .map_err(|error| py_error_msg(format!("plugin load task failed: {error}")))??;

                // The credential resolver opens BEFORE the operational graph is
                // built: the fill-if-empty resolution below consults its provider
                // chain, so the `credential_callback` governs connection bring-up.
                // Chain resolution is not cancellable — like the
                // rest of this build future, a hung callback hangs the build.
                let credentials = tokio::task::spawn_blocking(move || {
                    open_credential_resolver(
                        interactive_auth_capability,
                        credential_cache_durability,
                        callback_provider,
                    )
                })
                .await
                .map_err(|error| {
                    py_error_msg(format!("credential resolver open task failed: {error}"))
                })??;

                // Fill-if-empty: an explicit `add_credential` bundle wins and
                // suppresses the chain for that connection. `Unavailable`
                // (declined callback / empty chain) keeps the connection
                // credential-less exactly as before; a Backend error fails the
                // build, matching the chain's own short-circuit contract.
                let principal = PrincipalView::new(principal_id);
                let mut connections = connections;
                for connection in &mut connections {
                    if !connection.connection.credentials.fields.is_empty() {
                        continue;
                    }
                    let backend = BackendId(connection.connection.backend_kind.clone());
                    match credentials.resolve(&backend, &principal).await {
                        Ok(resolved) => connection.connection.credentials = resolved.bytes,
                        Err(CredentialError::Unavailable { .. }) => {}
                        Err(CredentialError::Backend(error)) => return Err(py_error(error)),
                    }
                }

                // StackBuilder owns all structural validation. Its InvalidArgument
                // and NotConfigured codes are mapped by `py_error` to the public
                // typed Python exception hierarchy without message inspection.
                let builder =
                    native_builder(root, &layers, factories, python_factories).map_err(py_error)?;
                let stack = builder.build().await.map_err(py_error)?;

                // Apply the declared connections here instead of through the
                // builder: this is the same declaration-order `add_connection`
                // loop `StackBuilder::build_with_cancel` runs (ovstorage-layer
                // `traits.rs`, `build_with_cancel`), duplicated so each returned
                // `Connection.id` can be captured into the exact (target, id)
                // records the runtime credential fan-out keys on.
                // Known divergence: a composer-built Stack reports
                // `Stack::spec().connections` as empty — the live connections
                // exist on the layers, not in the retained spec.
                let mut records = Vec::with_capacity(connections.len());
                for connection in connections {
                    let connected = match stack
                        .add_connection(ovs::Request::new(connection.clone()), None)
                        .await
                    {
                        Ok(connected) => connected,
                        // Same rule as the loop this mirrors, and it has to be
                        // repeated because the loop is: a declared connection
                        // whose caller-facing route is already served cannot be
                        // routed however the host reacts, so refusing to build
                        // costs every unrelated backend in the graph while
                        // buying that connection nothing. Reported and skipped,
                        // not fatal.
                        //
                        // A skipped connection contributes no `ConnectionRecord`
                        // — it has no id, and the credential fan-out keys on
                        // (target, id) — which is correct: nothing routes to it.
                        //
                        // Keep this in step with `StackBuilder::build_with_cancel`
                        // in ovstorage-layer `traits.rs`, which carries the full
                        // reasoning and the caveat that `RouteConflict` is a
                        // requirement on the refusing Layer rather than a checked
                        // fact.
                        Err(err) if err.code() == ovs::ErrorCode::RouteConflict => {
                            tracing::warn!(
                                target: "ovstorage.stack",
                                layer = %connection.target,
                                reason = %err.message(),
                                "skipping a declared connection whose route is already served; \
                                 the rest of the stack is unaffected"
                            );
                            continue;
                        }
                        Err(err) => return Err(py_error(err)),
                    };
                    let mut request = connection.connection;
                    request.credentials = ovs::SecretBundle::default();
                    records.push(ConnectionRecord {
                        target: connection.target,
                        id: Some(connected.id),
                        backend_kind: request.backend_kind.clone(),
                        request,
                    });
                }

                Ok(LayerBase::from_owner(StackOwner::from_parts(
                    stack,
                    credentials,
                    principal,
                    records,
                )))
            })
        })
    }
}

#[pymethods]
impl LayerBase {
    /// Construct either a projection of a built Rust layer or a Python layer
    /// declaration for in-process dispatch through `PyLayerAdapter`.
    ///
    /// `inner` may project any built Rust Layer handle, including a direct
    /// `FileBackend` or the object returned by `Stack.build()`. For a Stack,
    /// cloning the erased `Arc<Stack>` (not `Stack::root()`) preserves the
    /// canonicalization boundary and retains its optional Stack owner.
    /// Declaration form records only graph metadata here; `Stack.build()` binds
    /// the Python object to its adapter exactly once.
    #[new]
    #[pyo3(signature = (*args, name = None, layer_type = None, inner = None, roots = None))]
    fn new(
        py: Python<'_>,
        args: &Bound<'_, PyTuple>,
        name: Option<PyObject>,
        layer_type: Option<PyObject>,
        inner: Option<PyObject>,
        roots: Option<PyObject>,
    ) -> PyResult<Self> {
        let declaration_form = name.is_some() || layer_type.is_some();
        if !declaration_form {
            if roots.is_some() || args.len() > 1 || (args.len() == 1 && inner.is_some()) {
                return Err(py_error(OvError::new(
                    ErrorCode::InvalidArgument,
                    "LayerBase projection requires exactly one built LayerBase inner handle, either positional or as inner=",
                )));
            }
            let inner = match (args.len(), inner) {
                (1, None) => args.get_item(0)?.unbind(),
                (0, Some(inner)) => inner,
                _ => {
                    return Err(py_error(OvError::new(
                        ErrorCode::InvalidArgument,
                        "LayerBase projection requires exactly one built LayerBase inner handle, either positional or as inner=",
                    )));
                }
            };
            let inner = inner
                .bind(py)
                .extract::<PyRef<'_, LayerBase>>()
                .map_err(|_| {
                    py_error(OvError::new(
                        ErrorCode::IncompatibleType,
                        "LayerBase projection inner must be a built LayerBase handle",
                    ))
                })?;
            return inner.wrapper_projection();
        }

        if !args.is_empty() {
            return Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "cannot mix a projection-form LayerBase inner with declaration arguments",
            )));
        }

        let name = declaration_string(py, name, "name")?.ok_or_else(|| {
            py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "LayerBase declaration requires both name= and layer_type=",
            ))
        })?;
        let layer_type = declaration_string(py, layer_type, "layer_type")?.ok_or_else(|| {
            py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "LayerBase declaration requires both name= and layer_type=",
            ))
        })?;
        let declaration_type = match layer_type.as_str() {
            "backend" => ovs::LayerType::Backend,
            "wrapper" => ovs::LayerType::Wrapper,
            "router" => {
                return Err(py_error(OvError::new(
                    ErrorCode::Unsupported,
                    "Python router declarations are not supported",
                )));
            }
            _ => {
                return Err(py_error(OvError::new(
                    ErrorCode::InvalidArgument,
                    "LayerBase declaration layer_type must be 'backend' or 'wrapper'",
                )));
            }
        };
        let inner = declaration_string(py, inner, "inner")?;
        let roots = declaration_roots(py, roots)?;
        match declaration_type {
            ovs::LayerType::Backend if inner.is_some() => Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "a Python backend declaration cannot have an inner layer",
            ))),
            ovs::LayerType::Wrapper if inner.is_none() => Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "a Python wrapper declaration requires inner='<layer name>'",
            ))),
            ovs::LayerType::Wrapper if !roots.is_empty() => Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "a Python wrapper declaration cannot publish static roots",
            ))),
            _ => Ok(Self::python_declaration(
                name,
                declaration_type,
                inner,
                roots,
            )),
        }
    }

    #[getter]
    fn layer_type(&self) -> &'static str {
        layer_type_name(self.layer_type)
    }

    /// Export this built layer as a raw ABI-v2 `LayerHandle` for cross-language
    /// / cross-binary live handoff, minting one owned producer-side reference.
    ///
    /// A built Stack retains its whole `Arc<StackOwner>` through a
    /// [`CredentialRetainingLayer`] (exporting the Stack `Arc` alone would drop
    /// the credential substrate); a direct Rust handle exports its inner `Arc`
    /// directly. Either way the handle delegates through `owner.handle()` — the
    /// canonicalizing Stack, never `stack.root()`. A declaration that has not
    /// been built has no handle to export and raises `NotConfigured`.
    ///
    /// Returns, per `capsule`:
    /// - `False` (default): the `int` address of a heap `Box<ffi::LayerHandle>`.
    ///   `import_handle` copies the pair out (nulling it back through the box)
    ///   but never frees this box; after a successful import the caller frees it
    ///   with [`_free_exported_handle`] (or a plain `free()`). The int is
    ///   single-use — a second import of the same int raises — and assumes the
    ///   handle *will* be imported.
    /// - `True`: a `PyCapsule` owning the box. `import_handle` steals and frees
    ///   it; if it is never imported, its destructor drops the box (releasing
    ///   the producer-side `Arc`), so the capsule form is leak-safe on its own.
    ///
    /// The producer — this interpreter, plus the loop captured at `Stack.build`
    /// for any Python leaf — must outlive every exported handle (a debug-build
    /// tripwire fences interpreter finalization).
    #[pyo3(signature = (capsule = false))]
    fn export_handle(&self, py: Python<'_>, capsule: bool) -> PyResult<PyObject> {
        let layer: ovs::LayerHandle = match &self.owner {
            Some(owner) => {
                Arc::new(CredentialRetainingLayer::new(Arc::clone(owner))) as ovs::LayerHandle
            }
            None => self.handle()?,
        };
        let ptr = Box::into_raw(Box::new(ovs::export_handle(layer)));
        if capsule {
            match PyCapsule::new_bound_with_destructor(
                py,
                AtomicPtr::new(ptr),
                Some(LAYER_HANDLE_CAPSULE_NAME.to_owned()),
                drop_unclaimed_handle_capsule,
            ) {
                Ok(capsule) => Ok(capsule.into_any().unbind()),
                Err(error) => {
                    // The capsule never took ownership; reclaim the box so the
                    // export is not leaked on the (allocation-only) failure.
                    // SAFETY: `ptr` is the box just minted above, still owned.
                    drop(unsafe { Box::from_raw(ptr) });
                    Err(error)
                }
            }
        } else {
            Ok((ptr as usize).into_py(py))
        }
    }

    /// Import a raw `LayerHandle` produced by [`Self::export_handle`] as a
    /// projected `LayerBase`, taking ownership of the producer-side reference.
    ///
    /// `handle` is either the `int` (int form: the pair is copied out and nulled
    /// back through the box — single-use, so a second import of the same int
    /// raises; the caller still owns and must free the outer box) or the
    /// `PyCapsule` (capsule form: the box is stolen, the destructor disarmed,
    /// and the box freed here). A same-binary handle restores Arc identity with
    /// zero FFI; a foreign one wraps the producer's vtable. An ABI-handshake
    /// mismatch (a corrupted or undersized handle) raises `IncompatibleType`.
    #[staticmethod]
    fn import_handle(handle: &Bound<'_, PyAny>) -> PyResult<Self> {
        let raw = match handle.downcast::<PyCapsule>() {
            Ok(capsule) => import_raw_from_capsule(capsule)?,
            Err(_) => import_raw_from_int(handle)?,
        };
        // SAFETY: `raw` is a live Layer-ABI handle whose producer outlives it
        // (the same trust contract as `ovstorage::import_handle`), and its
        // ownership genuinely transfers here — the int form copied the pair
        // once, the capsule form stole and disarmed it.
        let inner = unsafe { ovs::import_handle(raw) }.map_err(py_error)?;
        Ok(Self::from_handle(inner))
    }

    /// Push a credential to the built Stack's live connections, then cache it.
    ///
    /// Every build-declared connection whose backend kind equals
    /// `backend_id` is updated in place through the connection lifecycle;
    /// backends that reject in-place swaps are handled by removing and
    /// re-adding the connection with the new bundle. Where the backend
    /// supports `probe`, a bad replacement credential is rejected before
    /// the live connection is touched; where probe is unsupported and the
    /// re-add fails, the connection stays removed (pending) until a
    /// corrected retry re-creates it. The cache insert — and therefore the
    /// `cred_epoch` bump — happens only after every matching
    /// connection accepted the credential; on failure the error names the
    /// succeeded/failed connections and a corrected retry re-creates any
    /// connection whose re-add failed. A `backend_id` matching no declared
    /// connection raises (a cache-only insert could never affect I/O).
    /// Credential-less backends (e.g. `file`) support neither update nor
    /// remove and fail loudly. `principal_id` names the credential-cache
    /// row only — connections are single-identity per Stack, so the bundle
    /// applies to every declared connection of `backend_id` regardless of
    /// principal (same as `refresh_credentials`). `credential` is the
    /// ResolvedCredential dict shape: `{"source_name": str,
    /// "expires_at_unix_nanos": int?, "fields": {name: bytes_or_str}}`.
    fn set_credential<'py>(
        &self,
        py: Python<'py>,
        backend_id: String,
        principal_id: String,
        credential: PyObject,
    ) -> PyResult<Bound<'py, PyAny>> {
        let resolved = resolved_credential_from_pydict(py, credential)?;
        let owner = self.owner()?;
        coroutine_into_py(py, "LayerBase.set_credential", async move {
            owner
                .set_credential(
                    BackendId(backend_id),
                    PrincipalView::new(principal_id),
                    resolved,
                )
                .await
                .map_err(py_error)
        })
    }

    /// Re-run the credential provider chain (the `credential_callback`) for
    /// `backend_id` and push the result to the live connections.
    ///
    /// The cached entry is invalidated first so the chain genuinely
    /// re-resolves (token rotation), then the resolved credential propagates
    /// exactly like `set_credential`: the cache commits only after every
    /// matching connection accepted the credential. A refresh that produces
    /// no credential raises `AuthRequiredError`; if propagation fails, the
    /// cache holds no entry for the row — retry to reconcile (the extra
    /// `cred_epoch` movements are inherent and advisory).
    /// `principal_id` defaults to the `Stack(principal_id=...)` the layer
    /// was built with.
    #[pyo3(signature = (backend_id, principal_id = None))]
    fn refresh_credentials<'py>(
        &self,
        py: Python<'py>,
        backend_id: String,
        principal_id: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let owner = self.owner()?;
        coroutine_into_py(py, "LayerBase.refresh_credentials", async move {
            owner
                .refresh_credentials(BackendId(backend_id), principal_id.map(PrincipalView::new))
                .await
                .map_err(py_error)
        })
    }

    /// Low-level, single-connection credential update — the Python mirror of
    /// the C ABI's `ovstorage_update_connection_credentials`.
    ///
    /// Routes `Layer::update_connection_credentials` at `(target,
    /// connection_id)` through the layer handle only, so it also works on
    /// imported handles (which have no credential owner) and on connections
    /// added out-of-band that `set_credential`'s fan-out does not govern.
    /// No fallback, no cache interaction. `credentials` is a bundle mapping
    /// `{field_name: SecretValue}` — the `ConnectionRequest.add_credential`
    /// shape, NOT the ResolvedCredential dict `set_credential` takes; each
    /// `SecretValue` is consumed only once the whole call validates (a
    /// failed call leaves every `SecretValue` reusable).
    fn update_connection_credentials<'py>(
        &self,
        py: Python<'py>,
        target: String,
        connection_id: String,
        credentials: &Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let layer = self.handle()?;
        // Validate the whole call before consuming any secret (the
        // `ConnectionRequest.add_credential` rationale): a failed call must
        // leave every `SecretValue` reusable, or a retry would misreport the
        // sources as consumed. Passing the same `SecretValue` under two keys
        // still errors "already consumed" on the second take — a caller
        // error, and the message is accurate.
        let mut entries: Vec<(String, Py<SecretValue>)> = Vec::with_capacity(credentials.len());
        for (key, value) in credentials.iter() {
            let key: String = key
                .extract()
                .map_err(|_| py_error_msg("credential field names must be strings"))?;
            let value = value.downcast::<SecretValue>().map_err(|_| {
                py_error_msg(
                    "credential values must be ovstorage.SecretValue instances \
                     (the ConnectionRequest.add_credential shape)",
                )
            })?;
            entries.push((key, value.clone().unbind()));
        }
        // The `SecretValue` handles are the Python objects this operation needs
        // at dispatch, so they travel as captures rather than inside the
        // closure. The field names stay with the closure: they are Rust
        // strings, and the two are re-paired by position at dispatch.
        let (keys, captures): (Vec<String>, Vec<PyObject>) = entries
            .into_iter()
            .map(|(key, value)| (key, value.into_any()))
            .unzip();
        // Take the secrets on the coroutine's first step, not here: a call that
        // never dispatched has certainly not validated, so it must leave every
        // `SecretValue` reusable. Consuming at call time would spend the secret
        // material irrecoverably for an update that never ran.
        coroutine_into_py_with_setup(
            py,
            "LayerBase.update_connection_credentials",
            captures,
            move |py, captures| {
                // `zip` truncates, and this is the one site where a short
                // capture list would not fail loudly: it would build an EMPTY
                // bundle and push it, wiping the connection's credentials and
                // reporting success. Refuse at the boundary instead, as every
                // other site does.
                if captures.len() != keys.len() {
                    return Err(py_error_msg(
                        "credential field names and captures disagree in length",
                    ));
                }
                let entries: Vec<(String, Py<SecretValue>)> = keys
                    .into_iter()
                    .zip(captures)
                    .map(|(key, value)| Ok((key, value.extract::<Py<SecretValue>>(py)?)))
                    .collect::<PyResult<_>>()?;
                // Check pass: verify all secrets are available and non-duplicate
                // before consuming any. The first pass guarantees the second cannot
                // fail partway through, so a failed call leaves every `SecretValue`
                // reusable. Passing the same `SecretValue` under two keys still
                // errors "already consumed" on the second check — a caller error,
                // and the message is accurate.
                let mut seen = std::collections::HashSet::new();
                for (_, value) in &entries {
                    let bound = value.bind(py);
                    let borrowed = bound.borrow();
                    let guard = borrowed
                        .inner
                        .lock()
                        .map_err(|_| py_error_msg("SecretValue lock poisoned"))?;
                    if guard.is_none() || !seen.insert(value.as_ptr() as usize) {
                        return Err(py_error_msg("SecretValue already consumed"));
                    }
                }
                // Take pass: consume all secrets; cannot fail since availability
                // and uniqueness are confirmed above under the same GIL hold.
                let mut bundle = ovs::SecretBundle::default();
                for (key, value) in &entries {
                    let secret = value
                        .bind(py)
                        .borrow()
                        .inner
                        .lock()
                        .map_err(|_| py_error_msg("SecretValue lock poisoned"))?
                        .take()
                        .expect("SecretValue was Some in check pass");
                    bundle.fields.insert(key.clone(), secret);
                }
                Ok(async move {
                    layer
                        .update_connection_credentials(
                            ovs::Request::new(ovs::UpdateConnectionCredentialsRequest {
                                key: ovs::ConnectionKey {
                                    target,
                                    id: ovs::ConnectionId(connection_id),
                                },
                                credentials: bundle,
                            }),
                            None,
                        )
                        .await
                        .map(|_| ())
                        .map_err(py_error)
                })
            },
        )
    }

    /// Start the connection's interactive authentication flow.
    ///
    /// The returned awaitable resolves to an `AsyncAuthEventStream`. It raises
    /// before producing a stream when the connection is unknown (`NotFound`),
    /// the layer has no interactive auth flow (`Unsupported`), or the request
    /// is invalid (`InvalidArgument`). Authentication failures reported as
    /// events have kind `"Failed"`; stream-level iterator errors after startup
    /// raise a typed `ovstorage.Error` while pulling and cancel the stream.
    ///
    /// `auto_open_browser=True` permits the layer to launch a browser in
    /// addition to emitting an `OpenBrowser` event. A host that opens the event
    /// URL itself should leave the flag false. Dropping or `aclose()`-ing the
    /// stream cancels the flow at its next checkpoint. When a `"Succeeded"`
    /// event has a non-`None` `oauth_access_token`, the host must re-apply those
    /// scoped credentials with `update_connection_credentials`.
    #[pyo3(signature = (target, connection_id, capability = None, auto_open_browser = false))]
    fn authenticate_connection<'py>(
        &self,
        py: Python<'py>,
        target: String,
        connection_id: String,
        capability: Option<PyObject>,
        auto_open_browser: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let layer = self.handle()?;
        let capability = capability
            .map(|value| {
                value.extract::<i32>(py).map_err(|_| {
                    py_error(OvError::new(
                        ErrorCode::InvalidArgument,
                        "interactive_auth_capability must be an integer in the i32 range",
                    ))
                })
            })
            .transpose()?;
        let capability = self.resolve_authenticate_capability(capability)?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.authenticate_connection",
            async move {
                // Unlike finite calls, do not install a drop guard here: ownership
                // of the token moves into the returned iterator on success.
                let stream = layer
                    .authenticate_connection(
                        ovs::Request::new(ovs::AuthenticateRequest {
                            key: ovs::ConnectionKey {
                                target,
                                id: ovs::ConnectionId(connection_id),
                            },
                            capability,
                            auto_open_browser,
                        }),
                        Some(cancel.clone()),
                    )
                    .await
                    .map_err(py_error)?;
                let rx = spawn_blocking_iterator_producer(stream, cancel.clone());
                Ok(AsyncAuthEventStream {
                    rx: Arc::new(TokioMutex::new(rx)),
                    cancel,
                })
            },
        )
    }

    /// Monotonic epoch of the built Stack's credential cache. Bumps in
    /// lockstep with successful `set_credential`/`refresh_credentials`
    /// propagation (plus chain resolutions), never past the connections.
    #[getter]
    fn cred_epoch(&self) -> PyResult<u64> {
        Ok(self.owner()?.cred_epoch())
    }

    /// Resolved builder > environment > runtime-default auth capability.
    #[getter]
    fn interactive_auth_capability(&self) -> PyResult<i32> {
        Ok(interactive_auth_capability_to_int(
            self.owner()?.interactive_auth_capability(),
        ))
    }

    /// Return the composed Stack's current connection snapshot.
    ///
    /// Update streams from ABI-v2-loaded plugins are snapshot-only at this
    /// boundary. Native layers may observe live changes internally, but this
    /// method intentionally returns one coherent point-in-time list.
    fn list_connections<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        // Routed through the bare handle (not the Stack owner) so imported
        // handles can enumerate connection ids for
        // `update_connection_credentials` — C-ABI parity, which exposes both
        // on the handle.
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.list_connections",
            async move {
                let _guard = cancel.clone().drop_guard();
                let (snapshot, _updates) = layer
                    .list_connections(&ovs::Extensions::new(), Some(cancel))
                    .await
                    .map_err(py_error)?;
                // ABI-v2-loaded plugins are snapshot-only at this boundary: both
                // the plugin thunk and `LoadedV2Layer` discard connection update
                // streams.
                Ok(snapshot
                    .connections
                    .into_iter()
                    .map(|inner| Connection { inner })
                    .collect::<Vec<_>>())
            },
        )
    }

    /// Return the composed Stack's current address-root snapshot.
    ///
    /// Live change-stream observation is available only to
    /// native layers such as the file backend. ABI-v2-loaded plugin streams
    /// remain snapshot-only at this boundary.
    fn list_address_roots<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        // Handle-routed for the same imported-handle parity as
        // `list_connections` above.
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.list_address_roots",
            async move {
                let _guard = cancel.clone().drop_guard();
                let (snapshot, _updates) = layer
                    .list_address_roots(&ovs::Extensions::new(), Some(cancel))
                    .await
                    .map_err(py_error)?;
                // Live change-stream observation is native-layer-only at this
                // boundary; keep this snapshot-based.
                Ok(snapshot
                    .roots
                    .into_iter()
                    .map(address_root_from_root_info)
                    .map(|inner| AddressRoot { inner })
                    .collect::<Vec<_>>())
            },
        )
    }

    #[pyo3(signature = (address, full_metadata = false))]
    fn stat<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        full_metadata: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.stat", async move {
            let _guard = cancel.clone().drop_guard();
            layer
                .stat(
                    ovs::Request::new(ovs::StatRequest {
                        address,
                        options: StatOptions { full_metadata },
                    }),
                    Some(cancel),
                )
                .await
                .map(info_from_object)
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (address, max_bytes = None))]
    fn read_bytes<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        max_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.read_bytes", async move {
            let _guard = cancel.clone().drop_guard();
            let (bytes, info) = read_layer_bytes(layer, address, max_bytes, Some(cancel))
                .await
                .map_err(py_error)?;
            bridge_gil::with_bridge_gil_py(|py| {
                let bytes: Py<PyBytes> = PyBytes::new_bound(py, &bytes).into();
                Ok((bytes, info_from_object(info)))
            })
        })
    }

    /// Read an object into memory, applying the full read option surface.
    ///
    /// This is the override-facing counterpart of `read_bytes`.  It retains
    /// the latter's buffered `(bytes, Info)` result shape, including native
    /// local-delegate handling and the typed unfollowed-redirect error.
    #[pyo3(signature = (
        address,
        if_match = None,
        range_start = None,
        range_end_inclusive = None,
        max_bytes = None,
    ))]
    fn read<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        if_match: Option<String>,
        range_start: Option<u64>,
        range_end_inclusive: Option<u64>,
        max_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let options = ReadOptions {
            if_match,
            range: byte_range(range_start, range_end_inclusive)?,
            max_bytes,
        };
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.read", async move {
            let _guard = cancel.clone().drop_guard();
            let (bytes, info) =
                read_layer_bytes_with_options(layer, address, options, Some(cancel))
                    .await
                    .map_err(py_error)?;
            bridge_gil::with_bridge_gil_py(|py| {
                let bytes: Py<PyBytes> = PyBytes::new_bound(py, &bytes).into();
                Ok((bytes, info_from_object(info)))
            })
        })
    }

    #[pyo3(signature = (
        address,
        data,
        if_dest_exists = "overwrite",
        if_dest_etag = None,
        size_hint = None,
        user_metadata = None,
        message = None,
    ))]
    #[allow(clippy::too_many_arguments)] // Matches the public Python signature table.
    fn write<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        data: PyObject,
        if_dest_exists: &str,
        if_dest_etag: Option<String>,
        size_hint: Option<u64>,
        user_metadata: Option<HashMap<String, String>>,
        message: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let body = Body::Bytes(bytes_from_python_buffer(data.bind(py))?.ok_or_else(|| {
            py_error(OvError::new(
                ErrorCode::IncompatibleType,
                "write data must be a bytes-like buffer",
            ))
        })?);
        let if_dest = destination_precondition(if_dest_exists, if_dest_etag)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.write", async move {
            let _guard = cancel.clone().drop_guard();
            layer
                .write(
                    ovs::Request::new(ovs::WriteRequest {
                        address,
                        body,
                        options: WriteOptions {
                            if_dest,
                            size_hint,
                            user_metadata,
                            message,
                        },
                    }),
                    Some(cancel),
                )
                .await
                .map(|result| info_from_object(result.info))
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (
        address,
        data,
        if_dest_exists = "overwrite",
        if_dest_etag = None,
        size_hint = None,
        user_metadata = None,
        message = None,
    ))]
    #[allow(clippy::too_many_arguments)] // Matches the public Python signature table.
    fn write_stream<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        data: PyObject,
        if_dest_exists: &str,
        if_dest_etag: Option<String>,
        size_hint: Option<u64>,
        user_metadata: Option<HashMap<String, String>>,
        message: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let if_dest = destination_precondition(if_dest_exists, if_dest_etag)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        // A bytes-like body is snapshotted HERE, at call time. Copying it has
        // no observable effect on the caller's object, and deferring the copy
        // would be a silent data bug: a caller that hands over a `bytearray`
        // and reuses the buffer before awaiting would write whatever it held at
        // the first step rather than what it passed. `write` snapshots eagerly
        // for the same reason; these two stay in step.
        let prefetched = bytes_from_python_buffer(data.bind(py))?;
        // Everything else waits. For an async-iterator input
        // `body_from_python_input` calls `__aiter__` and spawns a bridge
        // producer that starts pulling `__anext__` — observable side effects in
        // the caller's own object. A `write_stream` coroutine that is closed, or
        // whose task is cancelled before the scheduler resumes it, must not
        // touch that iterator at all.
        let setup_cancel = cancel.clone();
        cancellable_coroutine_into_py_with_setup(
            py,
            cancel.clone(),
            "LayerBase.write_stream",
            // The body object is the Python handle this operation needs at
            // dispatch, so it is a capture rather than a closure field.
            vec![data],
            move |py, captures| {
                let data = captures
                    .into_iter()
                    .next()
                    .ok_or_else(|| py_error_msg("write_stream body capture was cleared"))?;
                let body = match prefetched {
                    Some(bytes) => Body::Bytes(bytes),
                    None => body_from_python_input(py, data, setup_cancel)?,
                };
                let buffered = matches!(&body, Body::Bytes(_));
                Ok(async move {
                    let _guard = cancel.clone().drop_guard();
                    let request = ovs::Request::new(ovs::WriteRequest {
                        address,
                        body,
                        options: WriteOptions {
                            if_dest,
                            size_hint,
                            user_metadata,
                            message,
                        },
                    });
                    let result = if buffered {
                        // Buffered bodies never perform a synchronous channel pull,
                        // so keep their entire layer future on ordinary runtime
                        // workers.
                        layer.write_stream(request, Some(cancel)).await
                    } else {
                        // `BodyStream` is sync-pull and native implementations may
                        // call `next_chunk()` directly from their async write
                        // future. Run only that genuinely streaming path on a
                        // blocking worker so the runtime can continue driving the
                        // Python producer.
                        let consumer_guard = p2r_adapter::BridgeTaskGuard::new();
                        tokio::task::spawn_blocking(move || {
                            let _consumer_guard = consumer_guard;
                            pyo3_tokio::get_runtime()
                                .handle()
                                .block_on(layer.write_stream(request, Some(cancel)))
                        })
                        .await
                        .map_err(|error| {
                            py_error(OvError::new(
                                ErrorCode::Internal,
                                format!("write_stream blocking worker failed: {error}"),
                            ))
                        })?
                    };
                    result
                        .map(|result| info_from_object(result.info))
                        .map_err(py_error)
                })
            },
        )
    }

    #[pyo3(signature = (
        source,
        destination,
        if_source = None,
        if_dest_exists = "overwrite",
        if_dest_etag = None,
        message = None,
    ))]
    #[allow(clippy::too_many_arguments)] // Matches the public Python signature table.
    fn copy<'py>(
        &self,
        py: Python<'py>,
        source: &str,
        destination: &str,
        if_source: Option<String>,
        if_dest_exists: &str,
        if_dest_etag: Option<String>,
        message: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = address::parse(source).map_err(py_error)?;
        let destination = address::parse(destination).map_err(py_error)?;
        let if_dest = destination_precondition(if_dest_exists, if_dest_etag)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.copy", async move {
            let _guard = cancel.clone().drop_guard();
            match layer
                .copy(
                    ovs::Request::new(ovs::CopyRequest {
                        source,
                        destination,
                        options: ovs::CopyOptions {
                            if_source,
                            if_dest,
                            message,
                        },
                    }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)?
            {
                ovs::WriteStep::Done(result) => Ok(info_from_object(result.info)),
                ovs::WriteStep::Redirects(_) => Err(py_error(OvError::new(
                    ErrorCode::Unsupported,
                    "copy returned redirects; use the Rust redirect-following surface",
                ))),
            }
        })
    }

    #[pyo3(signature = (
        source,
        destination,
        if_source = None,
        if_dest_exists = "overwrite",
        if_dest_etag = None,
        message = None,
    ))]
    #[allow(clippy::too_many_arguments)] // Matches the public Python signature table.
    fn rename<'py>(
        &self,
        py: Python<'py>,
        source: &str,
        destination: &str,
        if_source: Option<String>,
        if_dest_exists: &str,
        if_dest_etag: Option<String>,
        message: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = address::parse(source).map_err(py_error)?;
        let destination = address::parse(destination).map_err(py_error)?;
        let if_dest = destination_precondition(if_dest_exists, if_dest_etag)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.rename", async move {
            let _guard = cancel.clone().drop_guard();
            layer
                .rename(
                    ovs::Request::new(ovs::RenameRequest {
                        source,
                        destination,
                        options: ovs::RenameOptions {
                            if_source,
                            if_dest,
                            message,
                        },
                    }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (
        address,
        if_match = None,
        allow_rewrite_emulation = false,
        user_metadata_set = None,
        user_metadata_remove = None,
        message = None,
    ))]
    #[allow(clippy::too_many_arguments)] // Matches the public Python signature table.
    fn update_metadata<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        if_match: Option<String>,
        allow_rewrite_emulation: bool,
        user_metadata_set: Option<HashMap<String, String>>,
        user_metadata_remove: Option<Vec<String>>,
        message: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.update_metadata",
            async move {
                let _guard = cancel.clone().drop_guard();
                layer
                    .update_metadata(
                        ovs::Request::new(ovs::UpdateMetadataRequest {
                            address: address.clone(),
                            options: ovs::UpdateMetadataOptions {
                                if_match,
                                allow_rewrite_emulation,
                                user_metadata_set: user_metadata_set.unwrap_or_default(),
                                user_metadata_remove: user_metadata_remove.unwrap_or_default(),
                                message,
                            },
                        }),
                        Some(cancel),
                    )
                    .await
                    .map(|info| info_from_object((address, info).into()))
                    .map_err(py_error)
            },
        )
    }

    fn create_directory<'py>(&self, py: Python<'py>, address: &str) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.create_directory",
            async move {
                let _guard = cancel.clone().drop_guard();
                layer
                    .create_directory(
                        ovs::Request::new(ovs::CreateDirectoryRequest {
                            address: address.clone(),
                            options: ovs::CreateDirectoryOptions::default(),
                        }),
                        Some(cancel),
                    )
                    .await
                    .map(|info| info_from_object((address, info).into()))
                    .map_err(py_error)
            },
        )
    }

    fn delete_directory<'py>(&self, py: Python<'py>, address: &str) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.delete_directory",
            async move {
                let _guard = cancel.clone().drop_guard();
                layer
                    .delete_directory(
                        ovs::Request::new(ovs::DeleteDirectoryRequest {
                            address,
                            options: ovs::DeleteDirectoryOptions,
                        }),
                        Some(cancel),
                    )
                    .await
                    .map_err(py_error)
            },
        )
    }

    #[pyo3(signature = (prefix, recursive = false, max_results = None, page_token = None, full_metadata = false))]
    fn list<'py>(
        &self,
        py: Python<'py>,
        prefix: &str,
        recursive: bool,
        max_results: Option<u32>,
        page_token: Option<String>,
        full_metadata: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let prefix = address::parse(prefix).map_err(py_error)?;
        let options = ListOptions {
            recursive,
            max_results,
            page_token,
            full_metadata,
        };
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.list", async move {
            let _guard = cancel.clone().drop_guard();
            let page = layer
                .list(
                    ovs::Request::new(ovs::ListRequest { prefix, options }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)?;
            Ok(ListPage {
                items: page.items.into_iter().map(info_from_object).collect(),
                next_page_token: page.next_page_token,
            })
        })
    }

    #[pyo3(signature = (address, if_match = None))]
    fn delete<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        if_match: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.delete", async move {
            let _guard = cancel.clone().drop_guard();
            layer
                .delete(
                    ovs::Request::new(ovs::DeleteRequest {
                        address,
                        options: DeleteOptions { if_match },
                    }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (
        address,
        if_match = None,
        range_start = None,
        range_end_inclusive = None,
        max_bytes = None,
    ))]
    fn materialize<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        if_match: Option<String>,
        range_start: Option<u64>,
        range_end_inclusive: Option<u64>,
        max_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let options = ReadOptions {
            if_match,
            range: byte_range(range_start, range_end_inclusive)?,
            max_bytes,
        };
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.materialize", async move {
            let _guard = cancel.clone().drop_guard();
            let delegate = layer
                .materialize(
                    ovs::Request::new(ovs::ReadRequest { address, options }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)?;
            Ok(LocalDelegate {
                inner: delegate,
                closed: false,
            })
        })
    }

    #[pyo3(signature = (address, read = false, write = false, delete = false, update_metadata = false))]
    fn check_access<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        read: bool,
        write: bool,
        delete: bool,
        update_metadata: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.check_access", async move {
            let _guard = cancel.clone().drop_guard();
            let decision = layer
                .check_access(
                    ovs::Request::new(ovs::CheckAccessRequest {
                        address,
                        operations: ovs::AccessOps {
                            read,
                            write,
                            delete,
                            update_metadata,
                        },
                    }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)?;
            Ok(AccessDecision {
                allowed: decision.allowed,
                denied_read: decision.denied_ops.read,
                denied_write: decision.denied_ops.write,
                denied_delete: decision.denied_ops.delete,
                denied_update_metadata: decision.denied_ops.update_metadata,
                reason: decision.reason,
            })
        })
    }

    #[pyo3(signature = (address, max_results = None, page_token = None))]
    fn list_versions<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        max_results: Option<u32>,
        page_token: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(py, cancel.clone(), "LayerBase.list_versions", async move {
            let _guard = cancel.clone().drop_guard();
            let page = layer
                .list_versions(
                    ovs::Request::new(ovs::ListVersionsRequest {
                        address,
                        options: ovs::ListVersionsOptions {
                            max_results,
                            page_token,
                        },
                    }),
                    Some(cancel),
                )
                .await
                .map_err(py_error)?;
            Ok(VersionPage {
                items: page.items.into_iter().map(info_from_object).collect(),
                next_page_token: page.next_page_token,
            })
        })
    }

    #[pyo3(signature = (
        address,
        if_match = None,
        range_start = None,
        range_end_inclusive = None,
        max_bytes = None,
    ))]
    fn get_latest_version<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        if_match: Option<String>,
        range_start: Option<u64>,
        range_end_inclusive: Option<u64>,
        max_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let address = address::parse(address).map_err(py_error)?;
        let layer = self.handle()?;
        let options = ReadOptions {
            if_match,
            range: byte_range(range_start, range_end_inclusive)?,
            max_bytes,
        };
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.get_latest_version",
            async move {
                let _guard = cancel.clone().drop_guard();
                layer
                    .get_latest_version(
                        ovs::Request::new(ovs::ReadRequest { address, options }),
                        Some(cancel),
                    )
                    .await
                    .map(info_from_object)
                    .map_err(py_error)
            },
        )
    }

    fn probe<'py>(
        &self,
        py: Python<'py>,
        target: String,
        request: &Bound<'py, ConnectionRequest>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let layer = self.handle()?;
        let request = request.clone().unbind();
        let cancel = CancellationToken::new();
        // Consume the request on the coroutine's first step, not here. A probe
        // coroutine that is closed, or whose task is cancelled before the
        // scheduler resumes it, never ran — so it must leave the
        // `ConnectionRequest` reusable rather than burn it for nothing.
        cancellable_coroutine_into_py_with_setup(
            py,
            cancel.clone(),
            "LayerBase.probe",
            // The request is the Python handle this operation needs at
            // dispatch, so it is a capture rather than a closure field.
            vec![request.into_any()],
            move |py, captures| {
                let request = captures
                    .into_iter()
                    .next()
                    .ok_or_else(|| py_error_msg("probe request capture was cleared"))?
                    .extract::<Py<ConnectionRequest>>(py)?;
                let connection = request.bind(py).borrow().take()?;
                Ok(async move {
                    let _guard = cancel.clone().drop_guard();
                    layer
                        .probe(
                            ovs::Request::new(ovs::LayerConnectionRequest { target, connection }),
                            Some(cancel),
                        )
                        .await
                        .map(|inner| Connection { inner })
                        .map_err(py_error)
                })
            },
        )
    }

    #[pyo3(signature = (
        prefix,
        recursive = false,
        include_metadata_changes = true,
        since = None,
        poll_interval_seconds = 1.0,
    ))]
    fn watch_directory<'py>(
        &self,
        py: Python<'py>,
        prefix: &str,
        recursive: bool,
        include_metadata_changes: bool,
        since: Option<Vec<u8>>,
        poll_interval_seconds: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let prefix = address::parse(prefix).map_err(py_error)?;
        let poll_interval = Duration::try_from_secs_f64(poll_interval_seconds).map_err(|_| {
            py_error(OvError::new(
                ErrorCode::InvalidArgument,
                "poll_interval_seconds must be finite and non-negative",
            ))
        })?;
        let options = ovs::WatchDirectoryOptions {
            recursive,
            include_metadata_changes,
            since: since.map(ovs::WatchDirectoryCursor),
            poll_interval,
        };
        let layer = self.handle()?;
        let cancel = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            cancel.clone(),
            "LayerBase.watch_directory",
            async move {
                // Unlike finite calls, do not install a drop guard here: ownership
                // of the token moves into the returned iterator on success.
                let stream = layer
                    .watch_directory(
                        ovs::Request::new(ovs::WatchDirectoryRequest { prefix, options }),
                        Some(cancel.clone()),
                    )
                    .await
                    .map_err(py_error)?;
                let rx = spawn_blocking_iterator_producer(stream, cancel.clone());
                Ok(AsyncChangeEventStream {
                    rx: Arc::new(TokioMutex::new(rx)),
                    cancel,
                })
            },
        )
    }
}

/// The `credential_callback` / `credential_callback_name` pairing rule.
///
/// Checked at `Stack.build()` call time, where a mis-paired constructor is a
/// caller error that must not need a dispatch to surface, and again where the
/// provider is actually built — one rule, one place to change it.
fn ensure_credential_callback_pairing(
    credential_callback: Option<&PyObject>,
    credential_callback_name: Option<&String>,
) -> PyResult<()> {
    if credential_callback.is_some() && credential_callback_name.is_none() {
        return Err(py_error_msg(
            "credential_callback_name must be provided when credential_callback is set",
        ));
    }
    Ok(())
}

/// Build the optional Python credential-callback provider.
///
/// Needs the GIL, because it asks `asyncio.iscoroutinefunction` about the
/// callable, so it runs on the deferred coroutine's first step — which holds
/// the GIL and is where the callable comes back out of the `DeferredCall`
/// captures. The `Send` provider it returns is what
/// [`open_credential_resolver`] takes onto its blocking thread.
fn credential_callback_provider(
    py: Python<'_>,
    credential_callback: Option<PyObject>,
    credential_callback_name: Option<String>,
) -> PyResult<Option<Arc<dyn ovs::auth::CredentialProvider>>> {
    ensure_credential_callback_pairing(
        credential_callback.as_ref(),
        credential_callback_name.as_ref(),
    )?;
    match (credential_callback, credential_callback_name) {
        (Some(callback), Some(name)) => {
            Ok(Some(build_python_callback_provider(py, name, callback)?))
        }
        _ => Ok(None),
    }
}

fn resolve_interactive_capability<E: ovs::auth::EnvSource>(
    explicit: Option<RustInteractiveAuthCapability>,
    env: &E,
) -> RustInteractiveAuthCapability {
    explicit
        .or_else(|| ovs::auth::read_env_capability(env))
        .unwrap_or_else(|| ovs::auth::detect_default_capability(env))
}

/// Open the credential resolver used by a built Python Stack.
///
/// GIL-free and potentially blocking while the process-global auth substrate
/// initializes, so `Stack.build()` runs it on a blocking thread with the
/// callback provider already built.
fn open_credential_resolver(
    interactive_auth_capability: Option<i32>,
    credential_cache_durability: Option<i32>,
    callback_provider: Option<Arc<dyn ovs::auth::CredentialProvider>>,
) -> PyResult<CredentialResolver> {
    // Preserve the Python binding's state-root default while respecting an
    // earlier explicit init_auth_substrate(auth_dir=...).
    ovs::ensure_auth_substrate_with_default(auth_state_root).map_err(py_error)?;

    match credential_cache_durability {
        None | Some(CredentialCacheDurability::IN_MEMORY_ONLY) => {}
        Some(CredentialCacheDurability::PERSISTENT) => {
            return Err(py_error_msg(
                "persistent credential caching is not implemented by the Python binding; \
                 use CredentialCacheDurability.IN_MEMORY_ONLY",
            ));
        }
        Some(other) => {
            return Err(py_error_msg(format!(
                "invalid credential_cache_durability: {other}"
            )));
        }
    };
    // Stack-construction validation intentionally retains its generic `Error`
    // contract; per-flow validation uses typed `InvalidArgumentError`.
    let interactive_capability = match interactive_auth_capability {
        None => None,
        Some(InteractiveAuthCapability::BROWSER) => Some(RustInteractiveAuthCapability::Browser),
        Some(InteractiveAuthCapability::HEADLESS) => Some(RustInteractiveAuthCapability::Headless),
        Some(InteractiveAuthCapability::NONE) => Some(RustInteractiveAuthCapability::None),
        Some(other) => {
            return Err(py_error_msg(format!(
                "invalid interactive_auth_capability: {other}"
            )));
        }
    };

    // Python currently exposes only the in-memory cache constructor.
    let cache = Arc::new(ovs::auth::CredentialCache::new(
        ovs::auth::CredentialCacheConfig::default(),
    ));
    let providers = callback_provider.into_iter().collect();
    let interactive_auth_capability =
        resolve_interactive_capability(interactive_capability, &ovs::auth::StdEnv);
    Ok(CredentialResolver {
        cache,
        providers,
        interactive_auth_capability,
    })
}

#[pymethods]
impl LocalDelegate {
    #[getter]
    fn path(&self) -> PyResult<String> {
        self.ensure_open()?;
        Ok(self.inner.path.to_string_lossy().into_owned())
    }

    #[getter]
    fn info(&self) -> PyResult<Info> {
        self.ensure_open()?;
        Ok(info_from_object(self.inner.info.clone()))
    }

    fn __fspath__(&self) -> PyResult<String> {
        self.ensure_open()?;
        Ok(self.inner.path.to_string_lossy().into_owned())
    }

    #[getter]
    fn closed(&self) -> bool {
        self.closed
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyResult<PyRef<'_, Self>> {
        if slf.closed {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "LocalDelegate is already closed",
            ));
        }
        Ok(slf)
    }

    #[pyo3(signature = (_exc_type=None, _exc=None, _tb=None))]
    fn __exit__(
        &mut self,
        _exc_type: Option<PyObject>,
        _exc: Option<PyObject>,
        _tb: Option<PyObject>,
    ) -> PyResult<bool> {
        self.do_close();
        Ok(false)
    }

    fn __aenter__<'py>(slf: PyRef<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        if slf.closed {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "LocalDelegate is already closed",
            ));
        }
        ready_coroutine(py, "LocalDelegate.__aenter__", slf.into_py(py))
    }

    #[pyo3(signature = (_exc_type=None, _exc=None, _tb=None))]
    fn __aexit__<'py>(
        mut slf: PyRefMut<'py, Self>,
        py: Python<'py>,
        _exc_type: Option<PyObject>,
        _exc: Option<PyObject>,
        _tb: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyAny>> {
        slf.do_close();
        ready_coroutine(py, "LocalDelegate.__aexit__", py.None())
    }

    /// Release the local-path lease synchronously.
    ///
    /// Cleanup performs no asynchronous work. Keeping `close()` synchronous
    /// lets both synchronous and asynchronous callers release the lease
    /// without coordinating an asyncio loop.
    ///
    /// Deliberately NOT converted alongside the awaiting methods: the shipped
    /// stub declares `def close(self) -> None`, so making this a coroutine
    /// would put the runtime and the stub back out of step — the exact
    /// divergence that conversion set out to remove. `__aexit__` remains a
    /// coroutine, so `async with` and `create_task` still drive cleanup the
    /// async way.
    fn close(&mut self) {
        self.do_close();
    }
}

impl LocalDelegate {
    fn do_close(&mut self) {
        if !self.closed {
            self.inner.guard.take();
            self.closed = true;
        }
    }

    /// After `close()` the lease guard is dropped and the byte cache may evict
    /// the file, so a returned `path`/`info` would dangle. Getters guard on
    /// this the way `__enter__`/`__aenter__` already do.
    fn ensure_open(&self) -> PyResult<()> {
        if self.closed {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "LocalDelegate is already closed",
            ));
        }
        Ok(())
    }
}

#[pymethods]
impl AsyncReadStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        use futures::StreamExt;
        let inner = self.inner.clone();
        coroutine_into_py(py, "AsyncReadStream.__anext__", async move {
            let mut guard = inner.lock().await;
            let chunk = match guard.as_mut() {
                Some(stream) => stream.next().await,
                None => None,
            };
            match chunk {
                None => {
                    *guard = None;
                    Err(PyStopAsyncIteration::new_err(()))
                }
                Some(Err(err)) => Err(py_error(err)),
                Some(Ok(bytes)) => bridge_gil::with_bridge_gil_py(|py| {
                    let py_bytes: Py<PyBytes> = PyBytes::new_bound(py, &bytes).into();
                    Ok(py_bytes)
                }),
            }
        })
    }
}

fn layer_type_name(layer_type: ovs::LayerType) -> &'static str {
    match layer_type {
        ovs::LayerType::Backend => "backend",
        ovs::LayerType::Wrapper => "wrapper",
        ovs::LayerType::Router => "router",
    }
}

fn interactive_auth_capability_to_int(capability: RustInteractiveAuthCapability) -> i32 {
    match capability {
        RustInteractiveAuthCapability::Browser => InteractiveAuthCapability::BROWSER,
        RustInteractiveAuthCapability::Headless => InteractiveAuthCapability::HEADLESS,
        RustInteractiveAuthCapability::None => InteractiveAuthCapability::NONE,
    }
}

fn interactive_auth_capability_from_int(value: i32) -> PyResult<RustInteractiveAuthCapability> {
    match value {
        InteractiveAuthCapability::BROWSER => Ok(RustInteractiveAuthCapability::Browser),
        InteractiveAuthCapability::HEADLESS => Ok(RustInteractiveAuthCapability::Headless),
        InteractiveAuthCapability::NONE => Ok(RustInteractiveAuthCapability::None),
        other => Err(py_error(OvError::new(
            ErrorCode::InvalidArgument,
            format!("invalid interactive_auth_capability: {other}"),
        ))),
    }
}

fn address_root_from_root_info(info: ovs::RootInfo) -> ovs::AddressRoot {
    ovs::AddressRoot {
        address: info.root,
        display_name: info.display_name,
        backend_kind: info.layer_kind,
        connection_id: info.connection_id,
        capabilities: info.capabilities,
        source: info.source,
        visibility: info.visibility,
        user_metadata: info.user_metadata,
    }
}

fn unix_nanos(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
}

fn read_bytes_cap_error(cap: u64) -> OvError {
    OvError::new(
        ErrorCode::ResourceExhausted,
        format!("read exceeded max_bytes cap of {cap} bytes"),
    )
    .with_next_action("Increase max_bytes or use a streaming read surface.")
}

fn ensure_read_bytes_within_cap(bytes: &[u8], max_bytes: Option<u64>) -> ovs::Result<()> {
    if let Some(cap) = max_bytes
        && bytes.len() as u64 > cap
    {
        return Err(read_bytes_cap_error(cap));
    }
    Ok(())
}

fn materialized_read_error(error: std::io::Error) -> OvError {
    let code = match error.kind() {
        std::io::ErrorKind::NotFound => ErrorCode::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        // A delegate path that is a directory, or is otherwise unopenable as
        // bytes, is caller input rather than a defect in this bridge: it
        // belongs in a typed, non-retryable argument error and not in the
        // residual `Internal` arm.
        //
        // Depth-only: every in-tree backend that produces a `LocalDelegate`
        // refuses a directory at the layer (`FileBackend`'s
        // `reject_directory_target`), and a Python-implemented layer can only
        // return `Bytes`/`Stream`, so no end-to-end call in this repository
        // reaches this arm — a foreign plugin handing back such a delegate is
        // the reachable case. The table itself is still pinned, directly, by
        // `_probe_materialized_read_error_code`.
        //
        // The file backend's `map_io` agrees on `InvalidInput` and
        // deliberately disagrees on `IsADirectory`, which it maps to
        // `NotFound` because there the wrong-shaped component is a *path*
        // that does not exist with that shape; here the unopenable path IS
        // the object the caller asked for.
        std::io::ErrorKind::IsADirectory | std::io::ErrorKind::InvalidInput => {
            ErrorCode::InvalidArgument
        }
        _ => ErrorCode::Internal,
    };
    OvError::new(code, "failed to read materialized object")
}

/// Map one `io::ErrorKind` through [`materialized_read_error`] and hand back
/// the resulting [`ErrorCode::as_str`] name, so the gating pytest suite can
/// pin the table above.
///
/// It needs a probe because the mapping is unreachable end to end: it runs
/// only for a `ReadResult::LocalDelegate` whose path will not open, and no
/// in-tree layer produces one — `FileBackend` refuses a directory up front,
/// and a Python-implemented layer can return only `Bytes`/`Stream`. Driving
/// it through a real stack would mean adding a backend whose sole purpose is
/// to hand back a broken delegate. Without the probe a typo'd arm or a
/// dropped one would leave CI green, since `[lib] test = false` keeps the
/// Rust unit-test block out of every in-tree command.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_materialized_read_error_code(kind: &str) -> PyResult<&'static str> {
    // Named rather than numeric: `io::ErrorKind` has no stable integer
    // repr, so the pytest spells the kinds it cares about.
    let kind = match kind {
        "not_found" => std::io::ErrorKind::NotFound,
        "permission_denied" => std::io::ErrorKind::PermissionDenied,
        "is_a_directory" => std::io::ErrorKind::IsADirectory,
        "invalid_input" => std::io::ErrorKind::InvalidInput,
        "unexpected_eof" => std::io::ErrorKind::UnexpectedEof,
        other => {
            return Err(py_error(OvError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "_probe_materialized_read_error_code: unknown io::ErrorKind name {other:?}"
                ),
            )));
        }
    };
    Ok(materialized_read_error(std::io::Error::from(kind))
        .code()
        .as_str())
}

/// Drive a native `stat` request carrying one canonical auth credential into
/// a built Python layer. Public Python callers do not construct native request
/// extension bags, so the gating pytest uses this probe to exercise the real
/// Rust-to-Python override bridge rather than a hand-built Python dictionary.
#[cfg(feature = "test-probes")]
#[pyfunction]
fn _probe_stat_with_auth_credential<'py>(
    py: Python<'py>,
    layer: PyRef<'_, LayerBase>,
    address: &str,
    credential: &[u8],
) -> PyResult<Bound<'py, PyAny>> {
    let address = address::parse(address).map_err(py_error)?;
    let layer = layer.handle()?;
    let cancel = CancellationToken::new();
    let mut request = ovs::Request::new(ovs::StatRequest {
        address,
        options: StatOptions::default(),
    });
    request
        .extensions
        .insert(ovs::wrappers::ext::AUTH_CREDENTIAL, credential.to_vec());

    cancellable_coroutine_into_py(
        py,
        cancel.clone(),
        "_probe_stat_with_auth_credential",
        async move {
            let _guard = cancel.clone().drop_guard();
            layer
                .stat(request, Some(cancel))
                .await
                .map(info_from_object)
                .map_err(py_error)
        },
    )
}

/// Invoke `Layer::read` directly and normalize its native result into the
/// bounded value shape promised by Python's `read_bytes` method.
async fn read_layer_bytes(
    layer: ovs::LayerHandle,
    address: ovs::Url,
    max_bytes: Option<u64>,
    cancel: Option<CancellationToken>,
) -> ovs::Result<(Vec<u8>, ObjectInfo)> {
    read_layer_bytes_with_options(
        layer,
        address,
        ReadOptions {
            max_bytes,
            ..ReadOptions::default()
        },
        cancel,
    )
    .await
}

/// Buffered `Layer::read` normalization shared by `read_bytes` and the
/// override-facing `read` method.  Keeping option construction outside this
/// helper leaves `read_bytes`'s default-option behavior unchanged.
async fn read_layer_bytes_with_options(
    layer: ovs::LayerHandle,
    address: ovs::Url,
    options: ReadOptions,
    cancel: Option<CancellationToken>,
) -> ovs::Result<(Vec<u8>, ObjectInfo)> {
    use futures::StreamExt as _;

    let max_bytes = options.max_bytes;
    let mut request = ovs::Request::new(ovs::ReadRequest { address, options });
    // This is the Python binding's native hint to byte-cache wrappers. It remains an
    // extension rather than a Layer method so wrappers can pass it through.
    request
        .extensions
        .insert("ovstorage.read_to_bytes", vec![1]);

    match layer.read(request, cancel).await? {
        ovs::ReadResult::Bytes { bytes, info } => {
            ensure_read_bytes_within_cap(&bytes, max_bytes)?;
            Ok((bytes, info))
        }
        ovs::ReadResult::Stream { mut stream, info } => {
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                if let Some(cap) = max_bytes
                    && (bytes.len() as u64).saturating_add(chunk.len() as u64) > cap
                {
                    return Err(read_bytes_cap_error(cap));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok((bytes, info))
        }
        ovs::ReadResult::LocalDelegate(local) => match max_bytes {
            Some(cap) => {
                use tokio::io::AsyncReadExt as _;
                // A LocalDelegate is a whole-object read that FileBackend
                // intentionally leaves unbounded, expecting a byte-cache
                // wrapper to enforce `max_bytes`. With no such wrapper in the
                // graph, buffering the whole file before the cap check would
                // defeat `max_bytes` for large untrusted objects (an OOM risk),
                // so bound the read at the source — reading at most `cap + 1`
                // bytes so an over-cap object is rejected without allocating it,
                // mirroring the incremental check in the `Stream` arm above.
                let mut reader = tokio::fs::File::open(&local.path)
                    .await
                    .map_err(materialized_read_error)?
                    .take(cap.saturating_add(1));
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(materialized_read_error)?;
                ensure_read_bytes_within_cap(&bytes, max_bytes)?;
                Ok((bytes, local.info))
            }
            None => {
                let bytes = tokio::fs::read(&local.path)
                    .await
                    .map_err(materialized_read_error)?;
                Ok((bytes, local.info))
            }
        },
        ovs::ReadResult::Redirect(_) => Err(OvError::new(
            ErrorCode::Internal,
            "LayerBase received an unfollowed read redirect",
        )),
    }
}

#[pymethods]
impl ChangeEvent {
    #[getter]
    fn event_type(&self) -> &'static str {
        match self.inner {
            ovs::ChangeEvent::Object { .. } => "object",
            ovs::ChangeEvent::Lapsed { .. } => "lapsed",
        }
    }

    #[getter]
    fn address(&self) -> Option<String> {
        match &self.inner {
            ovs::ChangeEvent::Object { address, .. } => Some(address.to_string()),
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn kind(&self) -> Option<&'static str> {
        match &self.inner {
            ovs::ChangeEvent::Object { kind, .. } => Some(match kind {
                ovs::ChangeKind::Created => "Created",
                ovs::ChangeKind::Modified => "Modified",
                ovs::ChangeKind::Deleted => "Deleted",
                ovs::ChangeKind::MetadataChanged => "MetadataChanged",
            }),
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn etag(&self) -> Option<String> {
        match &self.inner {
            ovs::ChangeEvent::Object { etag, .. } => etag.clone(),
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn version(&self) -> Option<String> {
        match &self.inner {
            ovs::ChangeEvent::Object { version, .. } => version.clone(),
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn size(&self) -> Option<u64> {
        match self.inner {
            ovs::ChangeEvent::Object { size, .. } => size,
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn mtime_unix_nanos(&self) -> Option<u64> {
        match self.inner {
            ovs::ChangeEvent::Object { mtime, .. } => mtime.and_then(unix_nanos),
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn at_unix_nanos(&self) -> Option<u64> {
        match self.inner {
            ovs::ChangeEvent::Object { at, .. } => unix_nanos(at),
            ovs::ChangeEvent::Lapsed { .. } => None,
        }
    }

    #[getter]
    fn since_unix_nanos(&self) -> Option<u64> {
        match self.inner {
            ovs::ChangeEvent::Object { .. } => None,
            ovs::ChangeEvent::Lapsed { since, .. } => since.and_then(unix_nanos),
        }
    }

    #[getter]
    fn cursor<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let cursor = match &self.inner {
            ovs::ChangeEvent::Object { cursor, .. } | ovs::ChangeEvent::Lapsed { cursor, .. } => {
                &cursor.0
            }
        };
        PyBytes::new_bound(py, cursor)
    }
}

#[pymethods]
impl AsyncChangeEventStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
        let cancel = self.cancel.clone();
        // A *per-pull* token, never the shared stream token: cancelling one
        // `__anext__` must abandon only that pull.
        // `cancellable_coroutine_into_py` trips it from the done-callback on the
        // future the pull coroutine awaits, when (and only when) that future was
        // cancelled, so whole-stream teardown stays owned by `aclose()`/`Drop`.
        //
        // The token is also observed *inside* the body, ahead of `recv`. That
        // is belt-and-braces today: `bridge_gil`'s select is biased and takes
        // its abandon arm before polling this future at all, so an abandoned
        // pull is dropped without reaching the channel either way. It is kept
        // because the property it protects is the one that matters and is
        // cheap to state locally — an abandoned pull must not take a landing
        // event off the channel and drop it, which would lose that event for
        // every later pull, leaving them to see a drained channel and report
        // exhaustion.
        let pull = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            pull.clone(),
            "AsyncChangeEventStream.__anext__",
            async move {
                let mut guard = rx.lock().await;
                tokio::select! {
                    // Biased so an explicit teardown wins over a buffered event:
                    // once the token is tripped, exhaustion is reported determinis-
                    // tically rather than racing a pending `recv`.
                    biased;
                    // Explicit teardown: report exhaustion, not a cancel error.
                    _ = cancel.cancelled() => Err(PyStopAsyncIteration::new_err(())),
                    // This pull alone was abandoned: leave the channel untouched.
                    // Python never sees this value — the future it would resolve is
                    // already cancelled — so it only has to be non-terminal.
                    _ = pull.cancelled() => Err(py_error(OvError::new(
                        ErrorCode::Cancelled,
                        "watch_directory pull was cancelled",
                    ))),
                    item = guard.recv() => match item {
                        None => Err(PyStopAsyncIteration::new_err(())),
                        Some(Err(error)) => {
                            cancel.cancel();
                            Err(py_error(error))
                        }
                        Some(Ok(event)) => Ok(ChangeEvent { inner: event }),
                    },
                }
            },
        )
    }

    /// Explicit whole-stream teardown, distinct from per-pull cancellation:
    /// trips the shared token so the producer and the underlying watch stop,
    /// then resolves. Idempotent; `Drop` does the same if never called.
    fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.cancel.cancel();
        ready_coroutine(py, "AsyncChangeEventStream.aclose", py.None())
    }
}

fn info_from_object(info: ObjectInfo) -> Info {
    Info {
        address: info.address.to_string(),
        kind: info.kind.as_str().into(),
        size: info.size,
        mtime_unix_nanos: info.mtime.and_then(unix_nanos),
        etag: info.etag,
        version: info.version,
        system_metadata: info.system_metadata.unwrap_or_default(),
        user_metadata: info.user_metadata.unwrap_or_default(),
    }
}

/// Exhaustive `(code, bucket)` name pairs from `ErrorCode::bucket()`, so the
/// Python test suite can assert every per-code exception is parented under the
/// base for its bucket. Underscore-prefixed to stay out of `__all__` and the
/// typed stub; it exists only to keep the exception hierarchy from drifting
/// away from the Rust taxonomy.
#[pyfunction]
fn _error_bucket_pairs() -> Vec<(String, String)> {
    ErrorCode::KNOWN
        .iter()
        .map(|code| (code.as_str().to_owned(), code.bucket().as_str().to_owned()))
        .collect()
}

/// The Python projection of the shared error taxonomy: every binding
/// funnels a failing [`ovs::Error`] through here.
///
/// Each [`ErrorCode`] maps to the exception class of the same name
/// (`NotFound` → `ovstorage.NotFoundError`, ...) declared in the
/// `create_exception!` block at the top of this file. Every per-code
/// class is parented under one of the nine `*BucketError` bases —
/// one per `ErrorCode::bucket()` value (`ErrorBucket`, ovstorage-layer
/// `errors.rs`) — and every base extends `ovstorage.Error`, so callers
/// can `except` at whichever granularity they need. A code this build
/// does not know falls back to plain `ovstorage.Error`. The raised
/// exception's message is `"<CodeName>: <redacted message>"`, and its
/// `code` / `next_action` attributes carry the machine-readable code
/// name and the taxonomy's suggested recovery (`None` when absent).
/// The `_error_bucket_pairs` gate keeps the class hierarchy from
/// drifting away from `ErrorCode::bucket()`.
fn py_error(error: ovs::Error) -> PyErr {
    let finalizing = p2r_adapter::interpreter_is_confirmed_finalizing();
    py_error_with_interpreter_state(error, finalizing)
}

/// [`py_error`] with the interpreter-finalization probe hoisted out:
/// when `finalizing`, the `code`/`next_action` attributes are skipped
/// because setting them would re-acquire the GIL from a runtime worker.
fn py_error_with_interpreter_state(error: ovs::Error, finalizing: bool) -> PyErr {
    let code_str = error.code().as_str().to_owned();
    let msg = format!("{code_str}: {}", error.message());
    let next_action = error.next_action().map(str::to_owned);
    let err = match error.code() {
        ErrorCode::NotFound => NotFoundError::new_err(msg),
        ErrorCode::AlreadyExists => AlreadyExistsError::new_err(msg),
        ErrorCode::PermissionDenied => PermissionDeniedError::new_err(msg),
        ErrorCode::PreconditionFailed => PreconditionFailedError::new_err(msg),
        ErrorCode::Conflict => ConflictError::new_err(msg),
        ErrorCode::DirectoryNotEmpty => DirectoryNotEmptyError::new_err(msg),
        ErrorCode::Unsupported => UnsupportedError::new_err(msg),
        ErrorCode::InvalidArgument => InvalidArgumentError::new_err(msg),
        ErrorCode::IncompatibleType => IncompatibleTypeError::new_err(msg),
        ErrorCode::Locked => LockedError::new_err(msg),
        ErrorCode::Cancelled => CancelledError::new_err(msg),
        ErrorCode::DeadlineExceeded => DeadlineExceededError::new_err(msg),
        ErrorCode::Transient => TransientError::new_err(msg),
        ErrorCode::ResourceExhausted => ResourceExhaustedError::new_err(msg),
        ErrorCode::IntegrityFailure => IntegrityFailureError::new_err(msg),
        ErrorCode::Internal => InternalError::new_err(msg),
        ErrorCode::BrokerUnavailable => BrokerUnavailableError::new_err(msg),
        ErrorCode::BrokerRequired => BrokerRequiredError::new_err(msg),
        ErrorCode::RedirectExpired => RedirectExpiredError::new_err(msg),
        ErrorCode::PolicyEpochStale => PolicyEpochStaleError::new_err(msg),
        ErrorCode::AuthorizationLeaseExpired => AuthorizationLeaseExpiredError::new_err(msg),
        ErrorCode::CacheCorrupt => CacheCorruptError::new_err(msg),
        ErrorCode::StagingExpired => StagingExpiredError::new_err(msg),
        ErrorCode::CommitAmbiguous => CommitAmbiguousError::new_err(msg),
        ErrorCode::PartialCompletion => PartialCompletionError::new_err(msg),
        ErrorCode::CacheLockContention => CacheLockContentionError::new_err(msg),
        ErrorCode::StateRootUnavailable => StateRootUnavailableError::new_err(msg),
        ErrorCode::NetworkFilesystemRefused => NetworkFilesystemRefusedError::new_err(msg),
        ErrorCode::ObjectModified => ObjectModifiedError::new_err(msg),
        ErrorCode::NoRoute => NoRouteError::new_err(msg),
        ErrorCode::RouteConflict => RouteConflictError::new_err(msg),
        ErrorCode::NotConfigured => NotConfiguredError::new_err(msg),
        ErrorCode::AliasChainTooLong => AliasChainTooLongError::new_err(msg),
        ErrorCode::CredentialExpired => CredentialExpiredError::new_err(msg),
        ErrorCode::CredentialUnavailable => CredentialUnavailableError::new_err(msg),
        ErrorCode::AuthRequired => AuthRequiredError::new_err(msg),
        ErrorCode::AuthCancelled => AuthCancelledError::new_err(msg),
        ErrorCode::AuthExpired => AuthExpiredError::new_err(msg),
        ErrorCode::ContentMismatch => ContentMismatchError::new_err(msg),
        ErrorCode::ContentChecksumMismatch => ContentChecksumMismatchError::new_err(msg),
        ErrorCode::PluginRejected => PluginRejectedError::new_err(msg),
        _ => Error::new_err(msg),
    };
    // Constructing a PyErr is lazy, but inspecting its value is not. Once
    // finalization starts, acquiring the GIL from a runtime worker can abort
    // the process on supported CPython versions, so row-5 failures deliberately
    // omit the convenience attributes rather than crossing back into Python.
    if !finalizing {
        // Fails closed on a host exposing neither `Py_IsFinalizing` spelling,
        // where finalization cannot be detected at all. Losing `code` and
        // `next_action` there is the right trade: that same host cannot
        // dispatch either, so the attributes decorate errors from a bridge
        // that does not work, and attaching blind is how this crate aborts.
        let _ = bridge_gil::with_bridge_gil_cleanup(|py| {
            let value = err.value_bound(py);
            let _ = value.setattr("code", code_str);
            let _ = value.setattr("next_action", next_action);
            Ok(())
        });
    }
    err
}

fn py_error_msg(message: impl Into<String>) -> PyErr {
    Error::new_err(message.into())
}

/// Map a Python callback's return value onto the provider-chain protocol.
///
/// `None` means the callback declines this `(backend, principal)` pair —
/// `CredentialError::Unavailable` — so the chain falls through and the
/// build-time fill-if-empty resolution proceeds credential-less for that
/// connection (the kind-selective-callback contract). Any other
/// non-credential value stays `Backend`: a malformed credential dict must
/// fail loudly, not silently skip.
fn callback_result_to_credential(
    py: Python<'_>,
    value: Bound<'_, PyAny>,
    backend: &str,
    origin: &str,
) -> std::result::Result<ResolvedCredential, CredentialError> {
    if value.is_none() {
        return Err(CredentialError::Unavailable {
            details: format!("{origin} returned None (declined) for backend '{backend}'"),
        });
    }
    resolved_credential_from_pyany(py, value).map_err(|e| {
        CredentialError::Backend(OvError::new(
            ErrorCode::Internal,
            format!("{origin} returned non-credential value: {e}"),
        ))
    })
}

/// Build a `CallbackCredentialProvider` from a Python callable (sync or
/// `async def`). `asyncio.iscoroutinefunction` is checked once at
/// construction; the async path bridges via
/// `pyo3_async_runtimes::tokio::into_future` so the asyncio loop drives
/// the coroutine on the per-module tokio runtime.
///
/// Return-value protocol: a credential dict resolves; `None` declines
/// (`CredentialError::Unavailable`, falls through the chain); a raise is a
/// `Backend` error (short-circuits — see `callback_result_to_credential`).
fn build_python_callback_provider(
    py: Python<'_>,
    name: String,
    callable: PyObject,
) -> PyResult<Arc<dyn ovs::auth::CredentialProvider>> {
    let asyncio = py.import_bound("asyncio")?;
    let iscoroutinefunction = asyncio.getattr("iscoroutinefunction")?;
    let is_async: bool = iscoroutinefunction.call1((callable.bind(py),))?.extract()?;
    let callable = Arc::new(callable);
    let provider = CallbackCredentialProvider::new(name, move |backend, principal| {
        let callable = callable.clone();
        let backend_str = backend.0;
        let principal_str = principal.id;
        async move {
            if is_async {
                let coro = bridge_gil::with_bridge_gil_py(|py| {
                    let bound = callable.bind(py);
                    bound
                        .call1((backend_str.clone(), principal_str.clone()))
                        .map(|c| c.into_py(py))
                })
                .map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!(
                            "python callback raised: {}",
                            bridge_gil::describe_py_error(&e)
                        ),
                    ))
                })?;
                let fut = bridge_gil::with_bridge_gil_py(|py| {
                    let bound = coro.into_bound(py);
                    bridge_gil::into_future(bound)
                })
                .map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!(
                            "python coroutine bridge failed: {}",
                            bridge_gil::describe_py_error(&e)
                        ),
                    ))
                })?;
                let py_result = fut.await.map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!(
                            "python callback awaited error: {}",
                            bridge_gil::describe_py_error(&e)
                        ),
                    ))
                })?;
                bridge_gil::attach_for_dispatch(|py| {
                    let bound = py_result.into_bound(py);
                    callback_result_to_credential(py, bound, &backend_str, "python coroutine")
                })
                .unwrap_or_else(|| Err(credential_shutdown()))
            } else {
                bridge_gil::attach_for_dispatch(|py| {
                    let bound = callable.bind(py);
                    let py_result =
                        bound
                            .call1((backend_str.clone(), principal_str))
                            .map_err(|e| {
                                CredentialError::Backend(OvError::new(
                                    ErrorCode::Internal,
                                    format!(
                                        "python callback raised: {}",
                                        bridge_gil::describe_py_error(&e)
                                    ),
                                ))
                            })?;
                    callback_result_to_credential(py, py_result, &backend_str, "python callback")
                })
                .unwrap_or_else(|| Err(credential_shutdown()))
            }
        }
    });
    Ok(Arc::new(provider))
}

/// Decode a Python dict into `ResolvedCredential`. Shape:
/// `{"source_name": str, "expires_at_unix_nanos": int?,
///   "fields": {field_name: bytes_or_str}}`.
fn resolved_credential_from_pyany<'py>(
    _py: Python<'py>,
    value: Bound<'py, PyAny>,
) -> PyResult<ResolvedCredential> {
    let dict: &Bound<'py, PyDict> = value
        .downcast::<PyDict>()
        .map_err(|_| py_error_msg("credential must be a dict (got a non-dict value)"))?;
    let source_name: String = dict
        .get_item("source_name")?
        .ok_or_else(|| py_error_msg("credential dict missing 'source_name'"))?
        .extract()?;
    let expires_at = if let Some(value) = dict.get_item("expires_at_unix_nanos")? {
        let nanos: u64 = value.extract()?;
        Some(UNIX_EPOCH + std::time::Duration::from_nanos(nanos))
    } else {
        None
    };
    let fields_value = dict
        .get_item("fields")?
        .ok_or_else(|| py_error_msg("credential dict missing 'fields'"))?;
    let fields: &Bound<'py, PyDict> = fields_value
        .downcast::<PyDict>()
        .map_err(|_| py_error_msg("credential['fields'] must be a dict"))?;
    let mut bundle = RustSecretBundle::default();
    for (key, val) in fields.iter() {
        let key_str: String = key.extract()?;
        // bytes or str: both are valid bearer-token shapes.
        let bytes: Vec<u8> = if let Ok(b) = val.downcast::<PyBytes>() {
            b.as_bytes().to_vec()
        } else if let Ok(s) = val.extract::<String>() {
            s.into_bytes()
        } else {
            return Err(py_error_msg(format!(
                "credential['fields'][{key_str}] must be bytes or str"
            )));
        };
        bundle
            .fields
            .insert(key_str, RustSecretValue::Bytes(SecretBytes(bytes)));
    }
    Ok(ResolvedCredential {
        bytes: bundle,
        expires_at,
        source_name,
    })
}

fn resolved_credential_from_pydict(
    py: Python<'_>,
    credential: PyObject,
) -> PyResult<ResolvedCredential> {
    let bound = credential.into_bound(py);
    resolved_credential_from_pyany(py, bound)
}

/// Directory used by the auth-refresh-lock substrate (`auth.sqlite` +
/// flock). Honors `OVSTORAGE_AUTH_DIR`, then the platform per-user data
/// directory — the same resolution every other host uses.
fn auth_state_root() -> std::path::PathBuf {
    ovs::auth::default_state_root()
}

/// Explicitly initialize the process-global auth substrate.
///
/// `auth_dir = None` resolves to `$OVSTORAGE_AUTH_DIR` or a per-process
/// temp dir. Calling this twice with the same path is a no-op; with a
/// different path raises.
///
/// `Stack.build()` auto-initializes the substrate with defaults on
/// first call, so calling this function is only required when you want
/// to pin a non-default `auth_dir` before any Stack is built.
#[pyfunction]
#[pyo3(signature = (auth_dir=None))]
fn init_auth_substrate(auth_dir: Option<String>) -> PyResult<()> {
    let auth_root = match auth_dir {
        Some(value) => std::path::PathBuf::from(value),
        None => auth_state_root(),
    };
    ovs::init_auth_substrate(Some(&auth_root)).map_err(py_error)
}

#[pymethods]
impl ConfigValue {
    #[classmethod]
    fn string(_cls: &Bound<'_, pyo3::types::PyType>, value: String) -> Self {
        Self {
            inner: ovs::ConfigValue::String(value),
        }
    }
    #[classmethod]
    #[pyo3(name = "int_")]
    fn int_(_cls: &Bound<'_, pyo3::types::PyType>, value: i64) -> Self {
        Self {
            inner: ovs::ConfigValue::Int(value),
        }
    }
    #[classmethod]
    #[pyo3(name = "bool_")]
    fn bool_(_cls: &Bound<'_, pyo3::types::PyType>, value: bool) -> Self {
        Self {
            inner: ovs::ConfigValue::Bool(value),
        }
    }
    #[classmethod]
    fn toml(_cls: &Bound<'_, pyo3::types::PyType>, toml: String) -> Self {
        Self {
            inner: ovs::ConfigValue::Toml(toml),
        }
    }

    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            ovs::ConfigValue::String(_) => "String",
            ovs::ConfigValue::Int(_) => "Int",
            ovs::ConfigValue::Bool(_) => "Bool",
            ovs::ConfigValue::Toml(_) => "Toml",
        }
    }
    #[getter]
    fn as_string(&self) -> Option<String> {
        match &self.inner {
            ovs::ConfigValue::String(s) => Some(s.clone()),
            _ => None,
        }
    }
    #[getter]
    fn as_int(&self) -> Option<i64> {
        match self.inner {
            ovs::ConfigValue::Int(n) => Some(n),
            _ => None,
        }
    }
    #[getter]
    fn as_bool(&self) -> Option<bool> {
        match self.inner {
            ovs::ConfigValue::Bool(b) => Some(b),
            _ => None,
        }
    }
    #[getter]
    fn as_toml(&self) -> Option<String> {
        match &self.inner {
            ovs::ConfigValue::Toml(s) => Some(s.clone()),
            _ => None,
        }
    }
}

#[pymethods]
impl SecretValue {
    #[classmethod]
    fn bytes(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::SecretValue::Bytes(ovs::SecretBytes(
                data.to_vec(),
            )))),
        }
    }
    #[classmethod]
    fn file(_cls: &Bound<'_, pyo3::types::PyType>, data: &[u8]) -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::SecretValue::File(ovs::SecretBytes(
                data.to_vec(),
            )))),
        }
    }
    #[classmethod]
    #[pyo3(signature = (token, refresh = None, expires_at_unix_nanos = None))]
    fn oauth_token(
        _cls: &Bound<'_, pyo3::types::PyType>,
        token: &[u8],
        refresh: Option<&[u8]>,
        expires_at_unix_nanos: Option<u64>,
    ) -> Self {
        let expires_at =
            expires_at_unix_nanos.map(|n| UNIX_EPOCH + std::time::Duration::from_nanos(n));
        Self {
            inner: StdMutex::new(Some(ovs::SecretValue::OAuthToken {
                token: ovs::SecretBytes(token.to_vec()),
                refresh: refresh.map(|r| ovs::SecretBytes(r.to_vec())),
                expires_at,
            })),
        }
    }
    #[classmethod]
    fn mtls_cert_pair(
        _cls: &Bound<'_, pyo3::types::PyType>,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::SecretValue::MtlsCertPair {
                cert_pem: ovs::SecretBytes(cert_pem.to_vec()),
                key_pem: ovs::SecretBytes(key_pem.to_vec()),
            })),
        }
    }
    #[classmethod]
    fn system_identity(_cls: &Bound<'_, pyo3::types::PyType>) -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::SecretValue::SystemIdentity)),
        }
    }
}

#[pymethods]
impl ConnectionRequest {
    #[new]
    fn new(backend_kind: String) -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::ConnectionRequest {
                backend_kind,
                config: HashMap::new(),
                credentials: ovs::SecretBundle::default(),
                persist: false,
                display_name: None,
            })),
        }
    }

    fn add_config(&self, key: String, value: ConfigValue) -> PyResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| py_error_msg("ConnectionRequest lock poisoned"))?;
        let req = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
        req.config.insert(key, value.inner);
        Ok(())
    }

    fn add_credential(&self, key: String, value: &SecretValue) -> PyResult<()> {
        // Lock/validate the target first, then take the source. Taking the
        // secret before the target is validated would empty it on the
        // "ConnectionRequest already consumed" error path (partial mutation),
        // and a retry would then misreport the source as consumed.
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| py_error_msg("ConnectionRequest lock poisoned"))?;
        let req = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
        let sv = value
            .inner
            .lock()
            .map_err(|_| py_error_msg("SecretValue lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("SecretValue already consumed"))?;
        req.credentials.fields.insert(key, sv);
        Ok(())
    }

    fn set_persist(&self, persist: bool) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let r = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
        r.persist = persist;
        Ok(())
    }

    fn set_display_name(&self, display_name: Option<String>) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let r = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
        r.display_name = display_name;
        Ok(())
    }
}

impl ConnectionRequest {
    /// Move the write-only request into a one-shot connection operation.
    /// Like secrets, connection requests cannot safely be cloned: a probe
    /// consumes its credential bundle and therefore makes reuse explicit.
    fn take(&self) -> PyResult<ovs::ConnectionRequest> {
        self.inner
            .lock()
            .map_err(|_| py_error_msg("ConnectionRequest lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))
    }
}

#[pymethods]
impl SecretBundle {
    #[new]
    fn new() -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::SecretBundle::default())),
        }
    }
    fn add(&self, key: String, value: &SecretValue) -> PyResult<()> {
        // Validate the target bundle before consuming the source secret, so a
        // consumed SecretBundle doesn't empty the source on the error path.
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let bundle = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("SecretBundle already consumed"))?;
        let sv = value
            .inner
            .lock()
            .map_err(|_| py_error_msg("SecretValue lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("SecretValue already consumed"))?;
        bundle.fields.insert(key, sv);
        Ok(())
    }
}

#[pymethods]
impl Capabilities {
    #[getter]
    fn supports_if_match_write(&self) -> bool {
        self.inner.supports_if_match_write
    }
    #[getter]
    fn supports_no_overwrite_write(&self) -> bool {
        self.inner.supports_no_overwrite_write
    }
    #[getter]
    fn supports_recursive_list(&self) -> bool {
        self.inner.supports_recursive_list
    }
    #[getter]
    fn has_real_directories(&self) -> bool {
        self.inner.has_real_directories
    }
    #[getter]
    fn writes_are_atomic(&self) -> bool {
        self.inner.writes_are_atomic
    }
    /// Availability: a `copy` naming this root can be attempted, natively or
    /// by emulation above the backend.
    #[getter]
    fn supports_copy(&self) -> bool {
        self.inner.supports_copy
    }
    /// Availability: a `rename` naming this root can be attempted.
    #[getter]
    fn supports_rename(&self) -> bool {
        self.inner.supports_rename
    }
    #[getter]
    fn supports_access_check(&self) -> bool {
        self.inner.supports_access_check
    }
    #[getter]
    fn supports_watch_directory(&self) -> bool {
        self.inner.supports_watch_directory
    }
    #[getter]
    fn supports_version_listing(&self) -> bool {
        self.inner.supports_version_listing
    }
    #[getter]
    fn redirect_size_threshold(&self) -> Option<u64> {
        self.inner.redirect_size_threshold
    }
}

#[pymethods]
impl Connection {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.0.clone()
    }
    #[getter]
    fn backend_kind(&self) -> String {
        self.inner.backend_kind.clone()
    }
    #[getter]
    fn display_name(&self) -> String {
        self.inner.display_name.clone()
    }
    #[getter]
    fn addresses(&self) -> Vec<String> {
        self.inner
            .current_addresses
            .iter()
            .map(|u| u.to_string())
            .collect()
    }
    #[getter]
    fn auth_state_kind(&self) -> &'static str {
        match self.inner.auth_state {
            ovs::ConnectionAuthState::Authenticated { .. } => "Authenticated",
            ovs::ConnectionAuthState::AwaitingAuth { .. } => "AwaitingAuth",
            ovs::ConnectionAuthState::AuthFailed { .. } => "AuthFailed",
            ovs::ConnectionAuthState::Anonymous => "Anonymous",
        }
    }
    #[getter]
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            inner: self.inner.capabilities.clone(),
        }
    }
    #[getter]
    fn user_metadata(&self) -> HashMap<String, String> {
        self.inner.user_metadata.clone()
    }
}

#[pymethods]
impl AuthEvent {
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            ovs::AuthEvent::OpenBrowser { .. } => "OpenBrowser",
            ovs::AuthEvent::DeviceCode { .. } => "DeviceCode",
            ovs::AuthEvent::Progress { .. } => "Progress",
            ovs::AuthEvent::Succeeded { .. } => "Succeeded",
            ovs::AuthEvent::Failed { .. } => "Failed",
            ovs::AuthEvent::Cancelled => "Cancelled",
        }
    }
    #[getter]
    fn url(&self) -> Option<String> {
        match &self.inner {
            ovs::AuthEvent::OpenBrowser { url, .. } => Some(url.clone()),
            _ => None,
        }
    }
    #[getter]
    fn user_code(&self) -> Option<String> {
        match &self.inner {
            ovs::AuthEvent::DeviceCode { user_code, .. } => Some(user_code.clone()),
            _ => None,
        }
    }
    #[getter]
    fn verification_url(&self) -> Option<String> {
        match &self.inner {
            ovs::AuthEvent::DeviceCode {
                verification_url, ..
            } => Some(verification_url.clone()),
            _ => None,
        }
    }
    #[getter]
    fn expires_at_unix_nanos(&self) -> Option<u64> {
        match self.inner {
            ovs::AuthEvent::OpenBrowser { expires_at, .. }
            | ovs::AuthEvent::DeviceCode { expires_at, .. } => unix_nanos(expires_at),
            _ => None,
        }
    }
    #[getter]
    fn interval_seconds(&self) -> Option<f64> {
        match self.inner {
            ovs::AuthEvent::DeviceCode { interval, .. } => Some(interval.as_secs_f64()),
            _ => None,
        }
    }
    #[getter]
    fn message(&self) -> Option<String> {
        match &self.inner {
            ovs::AuthEvent::Progress { message } => Some(message.clone()),
            ovs::AuthEvent::Failed { error } => Some(error.message().to_string()),
            _ => None,
        }
    }
    #[getter]
    fn connection(&self) -> Option<Connection> {
        match &self.inner {
            ovs::AuthEvent::Succeeded { connection, .. } => Some(Connection {
                inner: (**connection).clone(),
            }),
            _ => None,
        }
    }
    #[getter]
    fn oauth_access_token<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.inner {
            ovs::AuthEvent::Succeeded {
                credentials: Some(credentials),
                ..
            } => match credentials.fields.get("oauth") {
                Some(RustSecretValue::OAuthToken { token, .. }) => {
                    Some(PyBytes::new_bound(py, &token.0))
                }
                _ => None,
            },
            _ => None,
        }
    }
    #[getter]
    fn oauth_refresh_token<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.inner {
            ovs::AuthEvent::Succeeded {
                credentials: Some(credentials),
                ..
            } => match credentials.fields.get("oauth") {
                Some(RustSecretValue::OAuthToken {
                    refresh: Some(refresh),
                    ..
                }) => Some(PyBytes::new_bound(py, &refresh.0)),
                _ => None,
            },
            _ => None,
        }
    }
    #[getter]
    fn error_code(&self) -> Option<String> {
        match &self.inner {
            ovs::AuthEvent::Failed { error } => Some(format!("{:?}", error.code())),
            _ => None,
        }
    }
}

#[pymethods]
impl AsyncAuthEventStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
        let cancel = self.cancel.clone();
        // A *per-pull* token, never the shared stream token: cancelling one
        // `__anext__` must abandon only that pull.
        // `cancellable_coroutine_into_py` trips it from the done-callback on the
        // future the pull coroutine awaits, when (and only when) that future was
        // cancelled, so whole-stream teardown stays owned by `aclose()`/`Drop`.
        //
        // The token is also observed *inside* the body, ahead of `recv`. That
        // protects the important local property: an abandoned pull must not take
        // a landing event off the channel and lose it for every later pull.
        let pull = CancellationToken::new();
        cancellable_coroutine_into_py(
            py,
            pull.clone(),
            "AsyncAuthEventStream.__anext__",
            async move {
                let mut guard = rx.lock().await;
                tokio::select! {
                    // Biased so an explicit teardown wins over a buffered event:
                    // once the token is tripped, exhaustion is reported determinis-
                    // tically rather than racing a pending `recv`.
                    biased;
                    // Explicit teardown: report exhaustion, not a cancel error.
                    _ = cancel.cancelled() => Err(PyStopAsyncIteration::new_err(())),
                    // This pull alone was abandoned: leave the channel untouched.
                    // Python never sees this value — the future it would resolve is
                    // already cancelled — so it only has to be non-terminal.
                    _ = pull.cancelled() => Err(py_error(OvError::new(
                        ErrorCode::Cancelled,
                        "authenticate_connection pull was cancelled",
                    ))),
                    item = guard.recv() => match item {
                        None => Err(PyStopAsyncIteration::new_err(())),
                        Some(Err(error)) => {
                            cancel.cancel();
                            Err(py_error(error))
                        }
                        Some(Ok(event)) => Ok(AuthEvent { inner: event }),
                    },
                }
            },
        )
    }

    /// Explicit whole-stream teardown, distinct from per-pull cancellation:
    /// trips the shared token so the producer and the underlying auth flow stop,
    /// then resolves. Idempotent; `Drop` does the same if never called.
    fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.cancel.cancel();
        ready_coroutine(py, "AsyncAuthEventStream.aclose", py.None())
    }
}

/// Drive a synchronous plugin iterator on one dedicated `spawn_blocking`
/// worker per stream, forwarding into a bounded `mpsc::channel(8)`. The
/// producer exits on iterator end, receiver drop, or cancel-token trip
/// between iterations or while waiting for bounded-channel capacity.
///
/// `spawn_blocking` does not interrupt its closure on `JoinHandle` drop,
/// so a plugin `next()` that blocks cancellation-blind leaks one worker
/// per stream until that wait resolves — the channel shape bounds the
/// leak to one worker, not one per pulled event.
fn spawn_blocking_iterator_producer<T, I>(
    iter: I,
    cancel: CancellationToken,
) -> mpsc::Receiver<Result<T, OvError>>
where
    T: Send + 'static,
    I: Iterator<Item = Result<T, OvError>> + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Result<T, OvError>>(8);
    let guard = p2r_adapter::BridgeTaskGuard::new();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let mut iter = iter;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match iter.next() {
                None => break,
                Some(item) => {
                    if !blocking_send_while_active(&tx, &cancel, item) {
                        break;
                    }
                }
            }
        }
    });
    rx
}

const ITERATOR_SEND_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn blocking_send_while_active<T>(
    tx: &mpsc::Sender<T>,
    cancel: &CancellationToken,
    mut item: T,
) -> bool {
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        match tx.try_send(item) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
            Err(mpsc::error::TrySendError::Full(returned)) => {
                item = returned;
                std::thread::park_timeout(ITERATOR_SEND_POLL_INTERVAL);
            }
        }
    }
}

#[pymethods]
impl AliasRequest {
    #[new]
    fn new(from: &str, to: &str) -> PyResult<Self> {
        let from_url = address::parse(from).map_err(py_error)?;
        let to_url = address::parse(to).map_err(py_error)?;
        Ok(Self {
            inner: StdMutex::new(Some(ovs::AliasRequest {
                from: from_url,
                to: to_url,
                visibility: ovs::AddressVisibility::Visible,
                persist: false,
                display_name: None,
                user_metadata: HashMap::new(),
            })),
        })
    }
    fn set_visibility(&self, visibility: &str) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let r = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("AliasRequest already consumed"))?;
        let v = match visibility {
            "Visible" => ovs::AddressVisibility::Visible,
            "Hidden" => ovs::AddressVisibility::Hidden,
            "Suppressed" => ovs::AddressVisibility::Suppressed,
            other => return Err(py_error_msg(format!("unknown visibility: {other}"))),
        };
        r.visibility = v;
        Ok(())
    }
    fn set_persist(&self, persist: bool) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let r = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("AliasRequest already consumed"))?;
        r.persist = persist;
        Ok(())
    }
    fn set_display_name(&self, display_name: Option<String>) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let r = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("AliasRequest already consumed"))?;
        r.display_name = display_name;
        Ok(())
    }
    fn add_user_metadata(&self, key: String, value: String) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let r = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("AliasRequest already consumed"))?;
        r.user_metadata.insert(key, value);
        Ok(())
    }
}

#[pymethods]
impl Alias {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.0.clone()
    }
    /// Exposed as `from_` (with trailing underscore) because `from`
    /// is a Python keyword and cannot be a Python attribute name.
    #[getter]
    #[pyo3(name = "from_")]
    fn from_(&self) -> String {
        self.inner.from.to_string()
    }
    #[getter]
    fn to(&self) -> String {
        self.inner.to.to_string()
    }
    #[getter]
    fn visibility(&self) -> &'static str {
        match self.inner.visibility {
            ovs::AddressVisibility::Visible => "Visible",
            ovs::AddressVisibility::Hidden => "Hidden",
            ovs::AddressVisibility::Suppressed => "Suppressed",
        }
    }
    #[getter]
    fn state_kind(&self) -> &'static str {
        match self.inner.state {
            ovs::AliasState::Live => "Live",
            ovs::AliasState::Dangling => "Dangling",
            ovs::AliasState::ChainTooLong { .. } => "ChainTooLong",
        }
    }
    #[getter]
    fn display_name(&self) -> Option<String> {
        self.inner.display_name.clone()
    }
    #[getter]
    fn user_metadata(&self) -> HashMap<String, String> {
        self.inner.user_metadata.clone()
    }
}

#[pymethods]
impl AsyncAddressRootSnapshotStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
        coroutine_into_py(py, "AsyncAddressRootSnapshotStream.__anext__", async move {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                None => Err(PyStopAsyncIteration::new_err(())),
                Some(Err(err)) => Err(py_error(err)),
                Some(Ok(roots)) => Ok(roots
                    .into_iter()
                    .map(|r| AddressRoot { inner: r })
                    .collect::<Vec<_>>()),
            }
        })
    }
}

#[pymethods]
impl AddressVisibilityOverride {
    #[getter]
    fn address(&self) -> String {
        self.inner.address.to_string()
    }
    #[getter]
    fn visibility(&self) -> &'static str {
        match self.inner.visibility {
            ovs::AddressVisibility::Visible => "Visible",
            ovs::AddressVisibility::Hidden => "Hidden",
            ovs::AddressVisibility::Suppressed => "Suppressed",
        }
    }
    #[getter]
    fn persisted(&self) -> bool {
        self.inner.persisted
    }
}

#[pymethods]
impl AddressRoot {
    #[getter]
    fn address(&self) -> String {
        self.inner.address.to_string()
    }
    #[getter]
    fn backend_kind(&self) -> String {
        self.inner.backend_kind.clone()
    }
    #[getter]
    fn display_name(&self) -> Option<String> {
        self.inner.display_name.clone()
    }
    #[getter]
    fn connection_id(&self) -> Option<String> {
        self.inner.connection_id.as_ref().map(|id| id.0.clone())
    }
    #[getter]
    fn visibility(&self) -> &'static str {
        match self.inner.visibility {
            ovs::AddressVisibility::Visible => "Visible",
            ovs::AddressVisibility::Hidden => "Hidden",
            ovs::AddressVisibility::Suppressed => "Suppressed",
        }
    }
    #[getter]
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            inner: self.inner.capabilities.clone(),
        }
    }
    #[getter]
    fn user_metadata(&self) -> HashMap<String, String> {
        self.inner.user_metadata.clone()
    }
}

#[pymethods]
impl BackendKindDescriptor {
    #[getter]
    fn kind(&self) -> String {
        self.inner.kind.clone()
    }
    #[getter]
    fn display_name(&self) -> String {
        self.inner.display_name.clone()
    }
    #[getter]
    fn description(&self) -> Option<String> {
        self.inner.description.clone()
    }
    #[getter]
    fn supports_runtime_add(&self) -> bool {
        self.inner.supports_runtime_add
    }
}

#[pymodule]
fn ovstorage(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    p2r_adapter::initialize_finalization_guard(py);
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(2).enable_all().thread_name("ovs-py");
    pyo3_tokio::init(builder);

    module.add("__version__", "0.2.1")?;
    module.add("Error", py.get_type_bound::<Error>())?;
    // Bucket bases (one per `ErrorBucket`); registered before the per-code
    // exceptions that subclass them.
    module.add(
        "NotFoundBucketError",
        py.get_type_bound::<NotFoundBucketError>(),
    )?;
    module.add(
        "PermissionBucketError",
        py.get_type_bound::<PermissionBucketError>(),
    )?;
    module.add(
        "PreconditionBucketError",
        py.get_type_bound::<PreconditionBucketError>(),
    )?;
    module.add(
        "InvalidBucketError",
        py.get_type_bound::<InvalidBucketError>(),
    )?;
    module.add(
        "TransientBucketError",
        py.get_type_bound::<TransientBucketError>(),
    )?;
    module.add(
        "ResourceExhaustedBucketError",
        py.get_type_bound::<ResourceExhaustedBucketError>(),
    )?;
    module.add(
        "UnsupportedBucketError",
        py.get_type_bound::<UnsupportedBucketError>(),
    )?;
    module.add(
        "CancelledBucketError",
        py.get_type_bound::<CancelledBucketError>(),
    )?;
    module.add(
        "InternalBucketError",
        py.get_type_bound::<InternalBucketError>(),
    )?;
    module.add("NotFoundError", py.get_type_bound::<NotFoundError>())?;
    module.add(
        "AlreadyExistsError",
        py.get_type_bound::<AlreadyExistsError>(),
    )?;
    module.add(
        "PermissionDeniedError",
        py.get_type_bound::<PermissionDeniedError>(),
    )?;
    module.add(
        "PreconditionFailedError",
        py.get_type_bound::<PreconditionFailedError>(),
    )?;
    module.add("ConflictError", py.get_type_bound::<ConflictError>())?;
    module.add(
        "DirectoryNotEmptyError",
        py.get_type_bound::<DirectoryNotEmptyError>(),
    )?;
    module.add("UnsupportedError", py.get_type_bound::<UnsupportedError>())?;
    module.add(
        "InvalidArgumentError",
        py.get_type_bound::<InvalidArgumentError>(),
    )?;
    module.add(
        "IncompatibleTypeError",
        py.get_type_bound::<IncompatibleTypeError>(),
    )?;
    module.add("LockedError", py.get_type_bound::<LockedError>())?;
    module.add("CancelledError", py.get_type_bound::<CancelledError>())?;
    module.add(
        "DeadlineExceededError",
        py.get_type_bound::<DeadlineExceededError>(),
    )?;
    module.add("TransientError", py.get_type_bound::<TransientError>())?;
    module.add(
        "ResourceExhaustedError",
        py.get_type_bound::<ResourceExhaustedError>(),
    )?;
    module.add(
        "IntegrityFailureError",
        py.get_type_bound::<IntegrityFailureError>(),
    )?;
    module.add("InternalError", py.get_type_bound::<InternalError>())?;
    module.add(
        "BrokerUnavailableError",
        py.get_type_bound::<BrokerUnavailableError>(),
    )?;
    module.add(
        "BrokerRequiredError",
        py.get_type_bound::<BrokerRequiredError>(),
    )?;
    module.add(
        "RedirectExpiredError",
        py.get_type_bound::<RedirectExpiredError>(),
    )?;
    module.add(
        "PolicyEpochStaleError",
        py.get_type_bound::<PolicyEpochStaleError>(),
    )?;
    module.add(
        "AuthorizationLeaseExpiredError",
        py.get_type_bound::<AuthorizationLeaseExpiredError>(),
    )?;
    module.add(
        "CacheCorruptError",
        py.get_type_bound::<CacheCorruptError>(),
    )?;
    module.add(
        "StagingExpiredError",
        py.get_type_bound::<StagingExpiredError>(),
    )?;
    module.add(
        "CommitAmbiguousError",
        py.get_type_bound::<CommitAmbiguousError>(),
    )?;
    module.add(
        "PartialCompletionError",
        py.get_type_bound::<PartialCompletionError>(),
    )?;
    module.add(
        "CacheLockContentionError",
        py.get_type_bound::<CacheLockContentionError>(),
    )?;
    module.add(
        "StateRootUnavailableError",
        py.get_type_bound::<StateRootUnavailableError>(),
    )?;
    module.add(
        "NetworkFilesystemRefusedError",
        py.get_type_bound::<NetworkFilesystemRefusedError>(),
    )?;
    module.add(
        "ObjectModifiedError",
        py.get_type_bound::<ObjectModifiedError>(),
    )?;
    module.add("NoRouteError", py.get_type_bound::<NoRouteError>())?;
    module.add(
        "RouteConflictError",
        py.get_type_bound::<RouteConflictError>(),
    )?;
    module.add(
        "NotConfiguredError",
        py.get_type_bound::<NotConfiguredError>(),
    )?;
    module.add(
        "AliasChainTooLongError",
        py.get_type_bound::<AliasChainTooLongError>(),
    )?;
    module.add(
        "CredentialExpiredError",
        py.get_type_bound::<CredentialExpiredError>(),
    )?;
    module.add(
        "CredentialUnavailableError",
        py.get_type_bound::<CredentialUnavailableError>(),
    )?;
    module.add(
        "AuthRequiredError",
        py.get_type_bound::<AuthRequiredError>(),
    )?;
    module.add(
        "AuthCancelledError",
        py.get_type_bound::<AuthCancelledError>(),
    )?;
    module.add("AuthExpiredError", py.get_type_bound::<AuthExpiredError>())?;
    module.add(
        "ContentMismatchError",
        py.get_type_bound::<ContentMismatchError>(),
    )?;
    module.add(
        "ContentChecksumMismatchError",
        py.get_type_bound::<ContentChecksumMismatchError>(),
    )?;
    module.add(
        "PluginRejectedError",
        py.get_type_bound::<PluginRejectedError>(),
    )?;
    module.add_class::<LayerBase>()?;
    module.add_class::<PluginRegistry>()?;
    module.add_class::<StackComposer>()?;
    module.add_class::<AuthCredential>()?;
    module.add_class::<TcpTransport>()?;
    module.add_class::<UdsTransport>()?;
    module.add_class::<NamedPipeTransport>()?;
    module.add("EXT_AUTH_CREDENTIAL", ovs::wrappers::ext::AUTH_CREDENTIAL)?;
    module.add("EXT_PRINCIPAL_ID", ovs::wrappers::ext::PRINCIPAL_ID)?;
    module.add(
        "EXT_PRINCIPAL_DISPLAY_NAME",
        ovs::wrappers::ext::PRINCIPAL_DISPLAY_NAME,
    )?;
    module.add(
        "ANONYMOUS_PRINCIPAL_ID",
        ovstorage_authz_context::ANONYMOUS_PRINCIPAL_ID,
    )?;
    let modules = py.import_bound("sys")?.getattr("modules")?;
    let file_module = PyModule::new_bound(py, "file")?;
    file_module.add_class::<FileBackend>()?;
    file_module.add("__all__", vec!["FileBackend"])?;
    module.add_submodule(&file_module)?;
    modules.set_item("ovstorage.file", &file_module)?;
    let plugin_module = PyModule::new_bound(py, "plugin")?;
    plugin_module.add_class::<PluginBackend>()?;
    plugin_module.add("__all__", vec!["PluginBackend"])?;
    module.add_submodule(&plugin_module)?;
    modules.set_item("ovstorage.plugin", &plugin_module)?;
    let router_module = PyModule::new_bound(py, "router")?;
    router_module.add_class::<Router>()?;
    router_module.add("__all__", vec!["Router"])?;
    module.add_submodule(&router_module)?;
    modules.set_item("ovstorage.router", &router_module)?;
    let byte_cache_module = PyModule::new_bound(py, "byte_cache")?;
    byte_cache_module.add_class::<ByteCache>()?;
    byte_cache_module.add("__all__", vec!["ByteCache"])?;
    module.add_submodule(&byte_cache_module)?;
    modules.set_item("ovstorage.byte_cache", &byte_cache_module)?;
    let metadata_cache_module = PyModule::new_bound(py, "metadata_cache")?;
    metadata_cache_module.add_class::<MetadataCache>()?;
    metadata_cache_module.add("__all__", vec!["MetadataCache"])?;
    module.add_submodule(&metadata_cache_module)?;
    modules.set_item("ovstorage.metadata_cache", &metadata_cache_module)?;
    let retry_module = PyModule::new_bound(py, "retry")?;
    retry_module.add_class::<Retry>()?;
    retry_module.add("__all__", vec!["Retry"])?;
    module.add_submodule(&retry_module)?;
    modules.set_item("ovstorage.retry", &retry_module)?;
    let redirect_follower_module = PyModule::new_bound(py, "redirect_follower")?;
    redirect_follower_module.add_class::<RedirectFollower>()?;
    redirect_follower_module.add("__all__", vec!["RedirectFollower"])?;
    module.add_submodule(&redirect_follower_module)?;
    modules.set_item("ovstorage.redirect_follower", &redirect_follower_module)?;
    let alias_module = PyModule::new_bound(py, "alias")?;
    alias_module.add_class::<AliasWrapper>()?;
    alias_module.add("__all__", vec!["Alias"])?;
    module.add_submodule(&alias_module)?;
    modules.set_item("ovstorage.alias", &alias_module)?;
    let copy_rename_fallback_module = PyModule::new_bound(py, "copy_rename_fallback")?;
    copy_rename_fallback_module.add_class::<CopyRenameFallback>()?;
    copy_rename_fallback_module.add("__all__", vec!["CopyRenameFallback"])?;
    module.add_submodule(&copy_rename_fallback_module)?;
    modules.set_item(
        "ovstorage.copy_rename_fallback",
        &copy_rename_fallback_module,
    )?;
    // Free-function submodule (no layer class): the string-in/string-out
    // projection of the native `address` helpers.
    py_address::register(py, module)?;
    module.add_class::<Info>()?;
    module.add_class::<ListPage>()?;
    // Native-only protocol projections remain importable even when
    // declaration-form Python layers cannot author those stream families.
    module.add_class::<VersionPage>()?;
    module.add_class::<LocalDelegate>()?;
    module.add_class::<AccessDecision>()?;
    module.add_class::<AsyncReadStream>()?;
    module.add_class::<p2r_body::AsyncBodyInput>()?;
    module.add_class::<ChangeEvent>()?;
    module.add_class::<AsyncChangeEventStream>()?;
    module.add_class::<ConfigValue>()?;
    module.add_class::<SecretValue>()?;
    module.add_class::<SecretBundle>()?;
    module.add_class::<ConnectionRequest>()?;
    module.add_class::<Connection>()?;
    module.add_class::<Capabilities>()?;
    module.add_class::<AuthEvent>()?;
    module.add_class::<AsyncAuthEventStream>()?;
    module.add_class::<AliasRequest>()?;
    module.add_class::<Alias>()?;
    module.add_class::<AsyncAddressRootSnapshotStream>()?;
    module.add_class::<AddressVisibilityOverride>()?;
    module.add_class::<AddressRoot>()?;
    module.add_class::<BackendKindDescriptor>()?;
    module.add_class::<CredentialCacheDurability>()?;
    module.add_class::<InteractiveAuthCapability>()?;
    module.add_function(wrap_pyfunction!(init_auth_substrate, module)?)?;
    module.add_function(wrap_pyfunction!(p2r_adapter::_bridge_task_count, module)?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_quiesce_bridge_tasks,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_verify_q7_snapshot_riders,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_probe_cancelled_read_stream,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_probe_full_read_channel_cancel,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_probe_adapter_body_variants,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_probe_cancel_before_publication,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_probe_post_cancel_deadline,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_adapter::_probe_cancelled_watch_stream,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(_verify_reserved_python_kinds, module)?)?;
    module.add_function(wrap_pyfunction!(_bridge_local_file_body, module)?)?;
    module.add_function(wrap_pyfunction!(_probe_full_python_body_cancel, module)?)?;
    module.add_function(wrap_pyfunction!(_probe_drop_python_body_receiver, module)?)?;
    module.add_function(wrap_pyfunction!(
        p2r_body::_probe_full_body_channel_cancel,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_body::_probe_close_during_blocking_body_pull,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        p2r_body::_probe_panicking_body_source,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        _probe_finalization_safe_error_conversion,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(_error_bucket_pairs, module)?)?;
    module.add_function(wrap_pyfunction!(_free_exported_handle, module)?)?;
    module.add_function(wrap_pyfunction!(_live_export_count, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_begin_draining, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_finalization_guard_state, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_foreign_thread_attach, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_panicking_bridge_future, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_abandon_on_cancel, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_abandon_completed, module)?)?;
    module.add_function(wrap_pyfunction!(_fence_bridge_gil, module)?)?;
    module.add_function(wrap_pyfunction!(_bridge_gil_drained, module)?)?;
    module.add_function(wrap_pyfunction!(_debug_assert_no_live_exports, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_drive_foreign_import, module)?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(
        _probe_materialized_read_error_code,
        module
    )?)?;
    #[cfg(feature = "test-probes")]
    module.add_function(wrap_pyfunction!(_probe_stat_with_auth_credential, module)?)?;
    // Producer-lifetime tripwire: fence interpreter finalization so a
    // debug build flags any exported LayerHandle still live when the producer
    // (this interpreter) is torn down. Registered while holding the GIL at
    // import; fires before finalization completes.
    // `atexit` runs handlers last-registered-first. Registering the fence
    // before anything else at import time therefore makes it run *last* — after
    // every handler a user registers later, so code that still drives the
    // bridge during `atexit` keeps working right up until the fence closes it.
    py.import_bound("atexit")?
        .call_method1("register", (module.getattr("_fence_bridge_gil")?,))?;
    py.import_bound("atexit")?.call_method1(
        "register",
        (module.getattr("_debug_assert_no_live_exports")?,),
    )?;
    let mut exports: Vec<String> = module.dict().keys().extract()?;
    exports.retain(|name| !name.starts_with('_'));
    exports.push("__version__".to_owned());
    exports.sort_unstable();
    module.add("__all__", exports)?;
    Ok(())
}

// pyo3 `extension-module` cannot link a `cargo test` binary (no CPython
// symbols). These tests are downstream/manual-only: no in-tree CI command
// compiles them. A downstream must drop that pyo3 feature and enable
// `no-extension-module-link`; repository coverage comes from `tests/*.py`.
#[cfg(test)]
#[cfg(feature = "no-extension-module-link")]
mod tests {
    use super::*;

    #[test]
    fn layer_base_exports_r2p_override_surface() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let layer_base = py.get_type_bound::<LayerBase>();
            for method in [
                "read",
                "check_access",
                "probe",
                "list_versions",
                "get_latest_version",
                "watch_directory",
                "authenticate_connection",
                "write_stream",
                "copy",
                "rename",
                "update_metadata",
                "create_directory",
                "delete_directory",
            ] {
                assert!(
                    layer_base.hasattr(method).unwrap(),
                    "LayerBase is missing {method}"
                );
            }
        });
    }

    #[test]
    fn resolved_credential_from_pydict_round_trips_minimal_shape() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new_bound(py);
            dict.set_item("source_name", "portal").unwrap();
            let fields = PyDict::new_bound(py);
            fields
                .set_item("access_token", PyBytes::new_bound(py, b"bearer-bytes"))
                .unwrap();
            dict.set_item("fields", fields).unwrap();

            let resolved = resolved_credential_from_pyany(py, dict.into_any()).unwrap();
            assert_eq!(resolved.source_name, "portal");
            assert!(resolved.bytes.fields.contains_key("access_token"));
            match resolved.bytes.fields.get("access_token").unwrap() {
                RustSecretValue::Bytes(b) => assert_eq!(b.0, b"bearer-bytes".to_vec()),
                _ => panic!("expected SecretValue::Bytes"),
            }
            assert!(resolved.expires_at.is_none());
        });
    }

    #[test]
    fn resolved_credential_from_pydict_accepts_string_fields() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new_bound(py);
            dict.set_item("source_name", "portal").unwrap();
            let fields = PyDict::new_bound(py);
            fields.set_item("access_token", "string-bearer").unwrap();
            dict.set_item("fields", fields).unwrap();
            let resolved = resolved_credential_from_pyany(py, dict.into_any()).unwrap();
            match resolved.bytes.fields.get("access_token").unwrap() {
                RustSecretValue::Bytes(b) => assert_eq!(b.0, b"string-bearer".to_vec()),
                _ => panic!("expected Bytes variant"),
            }
        });
    }

    #[test]
    fn resolved_credential_from_pydict_carries_expires_at() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new_bound(py);
            dict.set_item("source_name", "portal").unwrap();
            // 2030-01-01 in nanos
            dict.set_item("expires_at_unix_nanos", 1_893_456_000_000_000_000_u64)
                .unwrap();
            let fields = PyDict::new_bound(py);
            dict.set_item("fields", fields).unwrap();
            let resolved = resolved_credential_from_pyany(py, dict.into_any()).unwrap();
            assert!(resolved.expires_at.is_some());
        });
    }

    #[test]
    fn resolved_credential_from_pydict_rejects_missing_fields() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let dict = PyDict::new_bound(py);
            dict.set_item("source_name", "portal").unwrap();
            let err = resolved_credential_from_pyany(py, dict.into_any()).unwrap_err();
            assert!(err.to_string().contains("fields"));
        });
    }

    #[test]
    fn build_python_callback_provider_routes_sync_python_callable() {
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let provider = Python::with_gil(|py| {
            let pycode = r#"
def fetch(backend_id, principal_id):
    return {"source_name": "portal", "fields": {"access_token": "sync-token"}}
"#;
            let module =
                PyModule::from_code_bound(py, pycode, "test_module.py", "test_module").unwrap();
            let callable = module.getattr("fetch").unwrap();
            build_python_callback_provider(py, "test-portal".into(), callable.unbind()).unwrap()
        });
        let resolved = runtime.block_on(async {
            provider
                .resolve(&BackendId("b".into()), &PrincipalView::new("p"))
                .await
                .unwrap()
        });
        assert_eq!(resolved.source_name, "portal");
        match resolved.bytes.fields.get("access_token").unwrap() {
            RustSecretValue::Bytes(b) => assert_eq!(b.0, b"sync-token".to_vec()),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn build_python_callback_provider_maps_none_to_unavailable() {
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let provider = Python::with_gil(|py| {
            let pycode = r#"
def fetch(backend_id, principal_id):
    if backend_id == "served":
        return {"source_name": "portal", "fields": {"access_token": "t"}}
    return None
"#;
            let module =
                PyModule::from_code_bound(py, pycode, "test_module.py", "test_module").unwrap();
            let callable = module.getattr("fetch").unwrap();
            build_python_callback_provider(py, "test-portal".into(), callable.unbind()).unwrap()
        });
        // A kind the callback declines falls through as Unavailable, so a
        // kind-selective callback cannot abort a mixed-stack build.
        let err = runtime.block_on(async {
            provider
                .resolve(&BackendId("declined".into()), &PrincipalView::new("p"))
                .await
                .unwrap_err()
        });
        match err {
            CredentialError::Unavailable { details } => {
                assert!(details.contains("declined"), "details: {details}")
            }
            other => panic!("expected Unavailable, got: {other}"),
        }
        // The served kind still resolves through the same provider.
        let resolved = runtime.block_on(async {
            provider
                .resolve(&BackendId("served".into()), &PrincipalView::new("p"))
                .await
                .unwrap()
        });
        assert_eq!(resolved.source_name, "portal");
    }

    #[test]
    fn build_python_callback_provider_maps_raise_and_junk_to_backend_error() {
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (raising, junk) = Python::with_gil(|py| {
            let pycode = r#"
def raising(backend_id, principal_id):
    raise RuntimeError("portal outage")

def junk(backend_id, principal_id):
    return "not-a-credential-dict"
"#;
            let module =
                PyModule::from_code_bound(py, pycode, "test_module.py", "test_module").unwrap();
            (
                build_python_callback_provider(
                    py,
                    "p1".into(),
                    module.getattr("raising").unwrap().unbind(),
                )
                .unwrap(),
                build_python_callback_provider(
                    py,
                    "p2".into(),
                    module.getattr("junk").unwrap().unbind(),
                )
                .unwrap(),
            )
        });
        let raise_err = runtime.block_on(async {
            raising
                .resolve(&BackendId("b".into()), &PrincipalView::new("p"))
                .await
                .unwrap_err()
        });
        assert!(
            matches!(raise_err, CredentialError::Backend(_)),
            "raise must short-circuit as Backend, got: {raise_err}"
        );
        let junk_err = runtime.block_on(async {
            junk.resolve(&BackendId("b".into()), &PrincipalView::new("p"))
                .await
                .unwrap_err()
        });
        assert!(
            matches!(junk_err, CredentialError::Backend(_)),
            "non-None junk must stay Backend, got: {junk_err}"
        );
    }

    #[test]
    fn relocated_value_classes_keep_public_constants() {
        assert_eq!(CredentialCacheDurability::PERSISTENT, 0);
        assert_eq!(CredentialCacheDurability::IN_MEMORY_ONLY, 1);
        assert_eq!(InteractiveAuthCapability::BROWSER, 0);
        assert_eq!(InteractiveAuthCapability::HEADLESS, 1);
        assert_eq!(InteractiveAuthCapability::NONE, 2);
    }

    #[test]
    fn interactive_capability_int_conversion_covers_public_constants() {
        pyo3::prepare_freethreaded_python();
        assert_eq!(
            interactive_auth_capability_from_int(InteractiveAuthCapability::BROWSER).unwrap(),
            RustInteractiveAuthCapability::Browser
        );
        assert_eq!(
            interactive_auth_capability_from_int(InteractiveAuthCapability::HEADLESS).unwrap(),
            RustInteractiveAuthCapability::Headless
        );
        assert_eq!(
            interactive_auth_capability_from_int(InteractiveAuthCapability::NONE).unwrap(),
            RustInteractiveAuthCapability::None
        );
        Python::with_gil(|py| {
            let error = interactive_auth_capability_from_int(99).unwrap_err();
            assert!(error.is_instance_of::<InvalidArgumentError>(py));
            assert_eq!(
                error.to_string(),
                "InvalidArgument: invalid interactive_auth_capability: 99"
            );
        });
    }

    #[test]
    fn auth_event_projects_only_variant_specific_timing_fields() {
        let expires_at = UNIX_EPOCH + Duration::from_secs(123) + Duration::from_nanos(456);
        let open_browser = AuthEvent {
            inner: ovs::AuthEvent::OpenBrowser {
                url: "https://example.invalid/login".into(),
                expires_at,
            },
        };
        assert_eq!(open_browser.expires_at_unix_nanos(), Some(123_000_000_456));
        assert_eq!(open_browser.interval_seconds(), None);

        let device_code = AuthEvent {
            inner: ovs::AuthEvent::DeviceCode {
                user_code: "ABCD-EFGH".into(),
                verification_url: "https://example.invalid/device".into(),
                expires_at,
                interval: Duration::from_millis(5_500),
            },
        };
        assert_eq!(device_code.expires_at_unix_nanos(), Some(123_000_000_456));
        assert_eq!(device_code.interval_seconds(), Some(5.5));

        let progress = AuthEvent {
            inner: ovs::AuthEvent::Progress {
                message: "waiting".into(),
            },
        };
        assert_eq!(progress.expires_at_unix_nanos(), None);
        assert_eq!(progress.interval_seconds(), None);

        let far_future_nanos = i64::MAX as u64 + 1;
        let far_future = AuthEvent {
            inner: ovs::AuthEvent::OpenBrowser {
                url: "https://example.invalid/future".into(),
                expires_at: UNIX_EPOCH + Duration::from_nanos(far_future_nanos),
            },
        };
        assert_eq!(far_future.expires_at_unix_nanos(), Some(far_future_nanos));
    }

    #[test]
    fn interactive_capability_preserves_explicit_env_default_precedence() {
        let env = ovs::auth::MockEnv::new()
            .with(ovs::auth::INTERACTIVE_AUTH_CAPABILITY_ENV_VAR, "headless");
        assert_eq!(
            resolve_interactive_capability(Some(RustInteractiveAuthCapability::Browser), &env,),
            RustInteractiveAuthCapability::Browser,
        );
        assert_eq!(
            resolve_interactive_capability(None, &env),
            RustInteractiveAuthCapability::Headless,
        );

        let env = ovs::auth::MockEnv::new();
        assert_eq!(
            resolve_interactive_capability(None, &env),
            ovs::auth::detect_default_capability(&env),
        );
    }

    #[test]
    fn owner_retains_stack_callback_cache_and_capability() {
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let stack = runtime.block_on(async {
            ovs::layers::register_default_layer_factories(ovs::Stack::builder("routes"))
                .router_factory(Arc::new(ovstorage_plugin_core::RouterFactoryImpl))
                .layer(ovs::LayerSpec::router(
                    "routes",
                    ovs::layers::ROUTER_KIND,
                    Vec::new(),
                ))
                .build()
                .await
                .unwrap()
        });
        let owner = Python::with_gil(|py| {
            let module = PyModule::from_code_bound(
                py,
                r#"
def fetch(backend_id, principal_id):
    return {"source_name": "owner-callback", "fields": {"access_token": "token"}}
"#,
                "test_owner.py",
                "test_owner",
            )
            .unwrap();
            StackOwner::build(
                py,
                stack,
                Some(InteractiveAuthCapability::NONE),
                Some(CredentialCacheDurability::IN_MEMORY_ONLY),
                Some(module.getattr("fetch").unwrap().unbind()),
                Some("owner-callback".into()),
            )
            .unwrap()
        });

        assert_eq!(owner.stack.root().name(), "routes");
        let dispatch_handle = owner.handle();
        let stack_handle: ovs::LayerHandle = owner.stack.clone();
        assert_eq!(dispatch_handle.name(), "routes");
        assert!(Arc::ptr_eq(&dispatch_handle, &stack_handle));
        assert!(!Arc::ptr_eq(&dispatch_handle, owner.stack.root()));
        assert_eq!(
            owner.interactive_auth_capability(),
            RustInteractiveAuthCapability::None
        );
        let (snapshot, _updates) = runtime
            .block_on(
                owner
                    .handle()
                    .list_connections(&ovs::Extensions::new(), None),
            )
            .unwrap();
        assert!(snapshot.connections.is_empty());
        let (roots, _updates) = runtime
            .block_on(
                owner
                    .handle()
                    .list_address_roots(&ovs::Extensions::new(), None),
            )
            .unwrap();
        assert!(roots.roots.is_empty());

        let backend = BackendId("test-backend".into());
        let principal = PrincipalView::new("test-principal");
        let callback_credential = runtime
            .block_on(owner.credentials.resolve(&backend, &principal))
            .unwrap();
        assert_eq!(callback_credential.source_name, "owner-callback");
        let epoch_after_callback = owner.cred_epoch();
        assert!(epoch_after_callback > 0);

        // Zero-connection stack: `set_credential` must fail loudly (a
        // cache-only insert could never affect I/O) and must NOT bump the
        // epoch (zero-match policy).
        let pushed_credential = Python::with_gil(|py| {
            let dict = PyDict::new_bound(py);
            dict.set_item("source_name", "control-plane").unwrap();
            dict.set_item("fields", PyDict::new_bound(py)).unwrap();
            resolved_credential_from_pyany(py, dict.into_any()).unwrap()
        });
        let error = runtime
            .block_on(owner.set_credential(backend, principal, pushed_credential))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert!(
            error.to_string().contains("NOT cached"),
            "unexpected message: {error}"
        );
        assert_eq!(owner.cred_epoch(), epoch_after_callback);

        let built_layer = LayerBase::from_owner(owner);
        assert_eq!(built_layer.cred_epoch().unwrap(), epoch_after_callback);
        assert_eq!(
            built_layer.interactive_auth_capability().unwrap(),
            InteractiveAuthCapability::NONE
        );
        assert_eq!(
            built_layer.resolve_authenticate_capability(None).unwrap(),
            RustInteractiveAuthCapability::None
        );
    }

    #[test]
    fn set_credential_fails_loud_on_swapless_file_connection() {
        // The file backend overrides neither `update_connection_credentials`
        // nor `remove_connection`: the apply state machine must fail the
        // record loudly WITHOUT removing the connection, and the cache
        // (epoch) must not move (fallback-failure semantics;
        // fallback-success is covered by the pytest matrix).
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = std::env::temp_dir().join(format!("ovs-cred-wire-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let stack = runtime.block_on(async {
            ovs::layers::register_default_layer_factories(ovs::Stack::builder("files"))
                .layer(ovs::LayerSpec::backend(
                    "files",
                    ovs::layers::FILE_BACKEND_KIND,
                ))
                .build()
                .await
                .unwrap()
        });
        let mut config = HashMap::new();
        config.insert(
            "root".to_string(),
            ovs::ConfigValue::String(dir.to_string_lossy().into_owned()),
        );
        let request = ovs::ConnectionRequest {
            backend_kind: ovs::layers::FILE_BACKEND_KIND.to_string(),
            config,
            credentials: RustSecretBundle::default(),
            persist: false,
            display_name: None,
        };
        let connected = runtime
            .block_on(stack.add_connection(
                ovs::Request::new(ovs::LayerConnectionRequest {
                    target: "files".into(),
                    connection: request.clone(),
                }),
                None,
            ))
            .unwrap();

        let credentials =
            open_credential_resolver(None, Some(CredentialCacheDurability::IN_MEMORY_ONLY), None)
                .unwrap();
        let owner = StackOwner::from_parts(
            stack,
            credentials,
            PrincipalView::new(""),
            vec![ConnectionRecord {
                target: "files".into(),
                id: Some(connected.id),
                backend_kind: ovs::layers::FILE_BACKEND_KIND.to_string(),
                request,
            }],
        );

        let mut bundle = RustSecretBundle::default();
        bundle.fields.insert(
            "token".into(),
            RustSecretValue::Bytes(SecretBytes(b"tok".to_vec())),
        );
        let credential = ResolvedCredential {
            bytes: bundle,
            expires_at: None,
            source_name: "control-plane".into(),
        };
        let error = runtime
            .block_on(owner.set_credential(
                BackendId(ovs::layers::FILE_BACKEND_KIND.to_string()),
                PrincipalView::new("p"),
                credential,
            ))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(
            error.to_string().contains("NOT updated"),
            "unexpected message: {error}"
        );
        assert_eq!(owner.cred_epoch(), 0);
        // No fallback removal happened: the connection survived intact.
        let (snapshot, _updates) = runtime
            .block_on(
                owner
                    .handle()
                    .list_connections(&ovs::Extensions::new(), None),
            )
            .unwrap();
        assert_eq!(snapshot.connections.len(), 1);
    }

    #[test]
    fn layer_type_metadata_maps_all_native_variants() {
        assert_eq!(layer_type_name(ovs::LayerType::Backend), "backend");
        assert_eq!(layer_type_name(ovs::LayerType::Wrapper), "wrapper");
        assert_eq!(layer_type_name(ovs::LayerType::Router), "router");
    }

    #[test]
    fn layer_base_exposes_stack_owner_credential_surface() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new_bound(py, "ovstorage").unwrap();
            ovstorage(py, &module).unwrap();
            let layer_base = module.getattr("LayerBase").unwrap();
            assert!(layer_base.hasattr("set_credential").unwrap());
            assert!(layer_base.hasattr("cred_epoch").unwrap());
            assert!(layer_base.hasattr("interactive_auth_capability").unwrap());
            assert!(layer_base.hasattr("list_connections").unwrap());
            assert!(layer_base.hasattr("list_address_roots").unwrap());
        });
    }

    #[test]
    fn native_python_wrapper_can_retain_and_forward_to_built_stack() {
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let stack = runtime.block_on(async {
            ovs::layers::register_default_layer_factories(ovs::Stack::builder("routes"))
                .router_factory(Arc::new(ovstorage_plugin_core::RouterFactoryImpl))
                .layer(ovs::LayerSpec::router(
                    "routes",
                    ovs::layers::ROUTER_KIND,
                    Vec::new(),
                ))
                .build()
                .await
                .unwrap()
        });

        Python::with_gil(|py| {
            let owner = StackOwner::build(
                py,
                stack,
                Some(InteractiveAuthCapability::NONE),
                Some(CredentialCacheDurability::IN_MEMORY_ONLY),
                None,
                None,
            )
            .unwrap();
            let built: Py<LayerBase> = Py::new(py, LayerBase::from_owner(owner.clone())).unwrap();
            let module = PyModule::new_bound(py, "test_forwarding_wrapper").unwrap();
            module
                .add("LayerBase", py.get_type_bound::<LayerBase>())
                .unwrap();
            py.run_bound(
                r#"
class ForwardingWrapper(LayerBase):
    def __init__(self, inner):
        self.inner = inner

    def forwarded_cred_epoch(self):
        return self.inner.cred_epoch

    def stat(self, address):
        return self.inner.stat(address)
"#,
                Some(&module.dict()),
                None,
            )
            .unwrap();
            let wrapper = module
                .getattr("ForwardingWrapper")
                .unwrap()
                .call1((built,))
                .unwrap();

            assert_eq!(
                wrapper
                    .call_method0("forwarded_cred_epoch")
                    .unwrap()
                    .extract::<u64>()
                    .unwrap(),
                owner.cred_epoch()
            );
            assert!(
                wrapper
                    .is_instance(&py.get_type_bound::<LayerBase>())
                    .unwrap()
            );
            assert!(wrapper.getattr("inner").unwrap().hasattr("stat").unwrap());
        });
    }

    fn stack_composer(root: &str, layers: Vec<ovs::LayerSpec>) -> StackComposer {
        StackComposer {
            root: Some(root.into()),
            layers,
            connections: Vec::new(),
            registry: None,
            interactive_auth_capability: None,
            credential_cache_durability: Some(CredentialCacheDurability::IN_MEMORY_ONLY),
            credential_callback: None,
            credential_callback_name: None,
            principal_id: String::new(),
            allow_test_plugins: false,
            declarations: Vec::new(),
        }
    }

    #[test]
    fn layer_base_declaration_constructor_validates_and_binds_once() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new_bound(py, "test_layer_declaration").unwrap();
            ovstorage(py, &module).unwrap();
            py.run_bound(
                r#"
class Backend(LayerBase):
    pass

class Wrapper(LayerBase):
    pass

backend = Backend(name="python-files", layer_type="backend", roots=["memory://files/"])
wrapper = Wrapper(name="cache", layer_type="wrapper", inner="python-files")
assert backend.layer_type == "backend"
assert wrapper.layer_type == "wrapper"

try:
    Wrapper(backend, name="mixed", layer_type="wrapper", inner="python-files")
except InvalidArgumentError:
    pass
else:
    raise AssertionError("mixed construction was accepted")

try:
    Wrapper(name="bad-edge", layer_type="wrapper", inner=backend)
except IncompatibleTypeError:
    pass
else:
    raise AssertionError("object edge was accepted")

try:
    Backend(name="router", layer_type="router")
except UnsupportedError:
    pass
else:
    raise AssertionError("Python router declaration was accepted")

async def bind_once():
    first = Stack(
        credential_cache_durability=CredentialCacheDurability.IN_MEMORY_ONLY
    ).backend(backend).build()
    try:
        Stack(
            credential_cache_durability=CredentialCacheDurability.IN_MEMORY_ONLY
        ).backend(backend).build()
    except ConflictError:
        pass
    else:
        raise AssertionError("a declaration was bound twice")
    assert first.cancel()

import asyncio
asyncio.run(bind_once())
"#,
                Some(&module.dict()),
                None,
            )
            .unwrap();

            let backend: Py<LayerBase> = module.getattr("backend").unwrap().extract().unwrap();
            let backend = backend.borrow(py);
            let declaration = backend.declaration.as_ref().unwrap();
            assert_eq!(declaration.name, "python-files");
            assert_eq!(declaration.layer_type, ovs::LayerType::Backend);
            assert_eq!(declaration.inner, None);
            assert_eq!(declaration.roots, ["memory://files/"]);
            assert!(declaration.bound);
        });
    }

    #[test]
    fn python_factories_build_independent_backend_and_wrapper_adapters() {
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (factories, layers, wrapper_object, loop_handle) = Python::with_gil(|py| {
            let module = PyModule::new_bound(py, "test_python_factories").unwrap();
            module
                .add("LayerBase", py.get_type_bound::<LayerBase>())
                .unwrap();
            py.run_bound(
                r#"
class Backend(LayerBase):
    pass

class Wrapper(LayerBase):
    pass

backend = Backend(name="python-backend", layer_type="backend", roots=["memory://items/"])
wrapper = Wrapper(name="python-wrapper", layer_type="wrapper", inner="python-backend")
"#,
                Some(&module.dict()),
                None,
            )
            .unwrap();
            let backend: Py<LayerBase> = module.getattr("backend").unwrap().extract().unwrap();
            let wrapper: Py<LayerBase> = module.getattr("wrapper").unwrap().extract().unwrap();
            let loop_handle = py
                .import_bound("asyncio")
                .unwrap()
                .call_method0("new_event_loop")
                .unwrap()
                .unbind();
            let context = py
                .import_bound("contextvars")
                .unwrap()
                .call_method0("copy_context")
                .unwrap();
            let locals = pyo3_async_runtimes::TaskLocals::new(loop_handle.bind(py).clone())
                .with_context(context);
            let declarations = vec![backend, wrapper.clone_ref(py)];
            let factories = prepare_python_factories(py, &declarations, locals).unwrap();
            let layers: Vec<_> = declarations
                .iter()
                .map(|object| object.bind(py).borrow().spec.clone())
                .collect();
            (factories, layers, wrapper, loop_handle)
        });

        let builder = native_builder(
            Some("python-wrapper".into()),
            &layers,
            Vec::new(),
            Some(factories),
        )
        .unwrap();
        let stack = runtime.block_on(builder.build()).unwrap();
        assert_eq!(
            stack.root().descriptor().kind,
            p2r_adapter::PYTHON_WRAPPER_KIND
        );
        let inner = stack.root().inner_layer().unwrap();
        assert_eq!(inner.descriptor().kind, p2r_adapter::PYTHON_BACKEND_KIND);
        let (roots, updates) = runtime
            .block_on(inner.list_address_roots(&ovs::Extensions::new(), None))
            .unwrap();
        assert_eq!(roots.roots[0].root.as_str(), "memory://items/");
        assert!(!roots.updates);
        assert!(updates.is_none());

        Python::with_gil(|py| {
            let wrapper = wrapper_object.bind(py).borrow();
            assert!(Arc::ptr_eq(wrapper.inner.as_ref().unwrap(), inner));
            assert!(wrapper.owner.is_none());
            loop_handle.bind(py).call_method0("close").unwrap();
        });
    }

    #[test]
    fn composer_rejects_rootless_router_leaf_and_native_declaration_override() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new_bound(py, "test_python_compose_validation").unwrap();
            ovstorage(py, &module).unwrap();
            py.run_bound(
                r#"
class Backend(LayerBase):
    pass

class NativeOverride(file.FileBackend):
    async def stat(self, address):
        return await super().stat(address)

rootless = Backend(name="rootless", layer_type="backend")
native_override = NativeOverride("native")
"#,
                Some(&module.dict()),
                None,
            )
            .unwrap();
            let rootless: Py<LayerBase> = module.getattr("rootless").unwrap().extract().unwrap();
            let router =
                ovs::LayerSpec::router("routes", ovs::layers::ROUTER_KIND, vec!["rootless".into()]);
            let backend = rootless.bind(py).borrow().spec.clone();
            let error = ensure_python_router_leaves_have_roots(&[router, backend], &[rootless], py)
                .unwrap_err();
            assert!(error.is_instance_of::<InvalidArgumentError>(py));
            assert!(error.to_string().contains("roots=[...]"));

            let native: Py<LayerBase> = module
                .getattr("native_override")
                .unwrap()
                .extract()
                .unwrap();
            let error = ensure_no_implicit_python_nodes(py, &[native]).unwrap_err();
            assert!(error.is_instance_of::<InvalidArgumentError>(py));
            assert!(error.to_string().contains("explicit LayerBase declaration"));
        });
    }

    #[test]
    fn stack_composer_builds_an_all_rust_stack_with_default_factories() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let composer = stack_composer(
            "routes",
            vec![
                ovs::LayerSpec::router("routes", ovs::layers::ROUTER_KIND, vec!["files".into()]),
                ovs::LayerSpec::backend("files", ovs::layers::FILE_BACKEND_KIND),
            ],
        );
        let builder = native_builder(
            composer.root.clone(),
            &composer.layers,
            vec![ovs::LoadedLayerFactory::Router(Arc::new(
                ovstorage_plugin_core::RouterFactoryImpl,
            ))],
            None,
        )
        .unwrap();
        let stack = runtime.block_on(builder.build()).unwrap();

        assert_eq!(stack.root().name(), "routes");
        assert_eq!(stack.spec().layers, composer.layers);
    }

    #[test]
    fn stack_composer_delegates_graph_errors_to_native_stack_builder() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let cases = [
            (
                ErrorCode::InvalidArgument,
                "cycle",
                stack_composer(
                    "a",
                    vec![
                        ovs::LayerSpec::wrapper("a", ovs::layers::RETRY_KIND, "b"),
                        ovs::LayerSpec::wrapper("b", ovs::layers::RETRY_KIND, "a"),
                    ],
                ),
            ),
            (
                ErrorCode::InvalidArgument,
                "referenced but not declared",
                stack_composer(
                    "outer",
                    vec![ovs::LayerSpec::wrapper(
                        "outer",
                        ovs::layers::RETRY_KIND,
                        "missing",
                    )],
                ),
            ),
            (
                ErrorCode::InvalidArgument,
                "declared more than once",
                stack_composer(
                    "files",
                    vec![
                        ovs::LayerSpec::backend("files", ovs::layers::FILE_BACKEND_KIND),
                        ovs::LayerSpec::backend("files", ovs::layers::FILE_BACKEND_KIND),
                    ],
                ),
            ),
            (
                ErrorCode::InvalidArgument,
                "referenced more than once",
                stack_composer(
                    "routes",
                    vec![
                        ovs::LayerSpec::router(
                            "routes",
                            ovs::layers::ROUTER_KIND,
                            vec!["files".into(), "files".into()],
                        ),
                        ovs::LayerSpec::backend("files", ovs::layers::FILE_BACKEND_KIND),
                    ],
                ),
            ),
            (
                ErrorCode::NotConfigured,
                "no factory registered",
                stack_composer(
                    "mystery",
                    vec![ovs::LayerSpec::backend("mystery", "unknown-kind")],
                ),
            ),
            (
                ErrorCode::InvalidArgument,
                "mismatched layer_type",
                stack_composer(
                    "wrong",
                    vec![ovs::LayerSpec::backend("wrong", ovs::layers::ROUTER_KIND)],
                ),
            ),
        ];

        for (expected_code, expected_message, composer) in cases {
            let builder =
                native_builder(composer.root.clone(), &composer.layers, Vec::new(), None).unwrap();
            let error = runtime.block_on(builder.build()).err().unwrap();
            assert_eq!(error.code(), expected_code);
            assert!(
                error.to_string().contains(expected_message),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn stack_graph_error_codes_map_to_typed_python_exceptions() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let invalid = py_error(OvError::new(ErrorCode::InvalidArgument, "invalid graph"));
            assert!(invalid.is_instance_of::<InvalidArgumentError>(py));
            let missing = py_error(OvError::new(ErrorCode::NotConfigured, "unknown kind"));
            assert!(missing.is_instance_of::<NotConfiguredError>(py));
            for kind in [
                p2r_adapter::PYTHON_BACKEND_KIND,
                p2r_adapter::PYTHON_WRAPPER_KIND,
            ] {
                let collision = py_error(ensure_plugin_kind_is_not_reserved(kind).unwrap_err());
                assert!(collision.is_instance_of::<ConflictError>(py));
            }
        });
    }

    #[test]
    fn stack_composer_is_registered_with_the_fluent_shape() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new_bound(py, "ovstorage").unwrap();
            ovstorage(py, &module).unwrap();
            let stack = module.getattr("Stack").unwrap().call0().unwrap();
            for method in [
                "layer",
                "backend",
                "wrapper",
                "router",
                "connection",
                "with_registry",
                "build",
            ] {
                assert!(stack.hasattr(method).unwrap(), "missing Stack.{method}");
            }
            assert!(module.getattr("PluginRegistry").is_ok());
        });
    }

    #[test]
    fn layer_classes_are_registered_by_layer_and_do_not_export_library() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let module = PyModule::new_bound(py, "ovstorage").unwrap();
            ovstorage(py, &module).unwrap();

            assert!(module.getattr("Library").is_err());
            let file = module.getattr("file").unwrap();
            let files = file
                .getattr("FileBackend")
                .unwrap()
                .call1(("files",))
                .unwrap();
            assert_eq!(
                files
                    .getattr("layer_type")
                    .unwrap()
                    .extract::<&str>()
                    .unwrap(),
                "backend"
            );

            let plugin = module.getattr("plugin").unwrap();
            let s3 = plugin
                .getattr("PluginBackend")
                .unwrap()
                .call1(("s3",))
                .unwrap();
            assert_eq!(
                s3.getattr("layer_type").unwrap().extract::<&str>().unwrap(),
                "backend"
            );

            let router = module.getattr("router").unwrap();
            let routes = router
                .getattr("Router")
                .unwrap()
                .call1(("routes", vec!["files"]))
                .unwrap();
            assert_eq!(
                routes
                    .getattr("layer_type")
                    .unwrap()
                    .extract::<&str>()
                    .unwrap(),
                "router"
            );

            for (module_name, class_name) in [
                ("byte_cache", "ByteCache"),
                ("metadata_cache", "MetadataCache"),
                ("retry", "Retry"),
                ("redirect_follower", "RedirectFollower"),
                ("alias", "Alias"),
                ("copy_rename_fallback", "CopyRenameFallback"),
            ] {
                let wrapper = module
                    .getattr(module_name)
                    .unwrap()
                    .getattr(class_name)
                    .unwrap()
                    .call1(("outer", "inner"))
                    .unwrap();
                assert_eq!(
                    wrapper
                        .getattr("layer_type")
                        .unwrap()
                        .extract::<&str>()
                        .unwrap(),
                    "wrapper"
                );
            }
        });
    }

    #[test]
    fn native_python_wrapper_drives_a_generic_file_layer_handle() {
        use ovs::BackendFactory as _;

        let root = std::env::temp_dir().join(format!(
            "ovstorage-python-layerbase-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("value.bin");
        std::fs::write(&path, b"layer bytes").unwrap();
        let root_url = ovs::Url::from_directory_path(&root).unwrap();
        let address = ovs::Url::from_file_path(&path).unwrap();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut config = ovs::LayerConfig::new();
            config.insert(
                "root".into(),
                ovs::ConfigValue::String(root_url.to_string()),
            );
            let handle = ovs::layers::FileBackendFactory
                .create_backend("files", &config, None)
                .await
                .unwrap();
            let base = LayerBase::from_handle(handle.clone());
            assert_eq!(base.layer_type(), "backend");
            assert_eq!(
                base.resolve_authenticate_capability(Some(InteractiveAuthCapability::HEADLESS))
                    .unwrap(),
                RustInteractiveAuthCapability::Headless
            );
            assert_eq!(
                base.resolve_authenticate_capability(None).unwrap(),
                resolve_interactive_capability(None, &ovs::auth::StdEnv)
            );

            // A native Python subclass is constructed with the direct,
            // ownerless FileBackend projection. Its PyO3 base must retain the
            // exact erased handle instead of requiring a Python Stack owner.
            let projected = Python::with_gil(|py| {
                let direct = Py::new(py, base).unwrap();
                let module = PyModule::new_bound(py, "test_direct_wrapper").unwrap();
                module
                    .add("LayerBase", py.get_type_bound::<LayerBase>())
                    .unwrap();
                py.run_bound(
                    r#"
class ForwardingWrapper(LayerBase):
    def __init__(self, inner):
        self.inner = inner

    async def read_bytes(self, address, max_bytes=None):
        return await self.inner.read_bytes(address, max_bytes)

    async def write(self, address, data):
        return await self.inner.write(address, data)

    async def list(self, prefix, **options):
        return await self.inner.list(prefix, **options)

    async def watch_directory(self, prefix, **options):
        return await self.inner.watch_directory(prefix, **options)
"#,
                    Some(&module.dict()),
                    None,
                )
                .unwrap();
                let wrapper = module
                    .getattr("ForwardingWrapper")
                    .unwrap()
                    .call1((direct,))
                    .unwrap();
                assert_eq!(
                    wrapper
                        .getattr("layer_type")
                        .unwrap()
                        .extract::<&str>()
                        .unwrap(),
                    "backend"
                );
                let projected: Py<LayerBase> = wrapper.extract().unwrap();
                let projected = projected.borrow(py);
                assert!(projected.owner().is_err());
                projected.handle().unwrap()
            });
            assert!(Arc::ptr_eq(&projected, &handle));

            let (bytes, info) = read_layer_bytes(projected.clone(), address.clone(), None, None)
                .await
                .unwrap();
            assert_eq!(bytes, b"layer bytes");
            assert_eq!(info.address, address);

            let error = read_layer_bytes(projected.clone(), info.address, Some(4), None)
                .await
                .unwrap_err();
            assert_eq!(error.code(), ErrorCode::ResourceExhausted);

            let written = projected
                .write(
                    ovs::Request::new(ovs::WriteRequest {
                        address: address.clone(),
                        body: Body::Bytes(b"written through wrapper".to_vec()),
                        options: WriteOptions::default(),
                    }),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(written.info.address, address);

            let page = projected
                .list(
                    ovs::Request::new(ovs::ListRequest {
                        prefix: root_url.clone(),
                        options: ListOptions {
                            recursive: true,
                            ..ListOptions::default()
                        },
                    }),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(page.items.len(), 1);
            assert_eq!(page.items[0].address, address);

            let cancel = CancellationToken::new();
            let changes = projected
                .watch_directory(
                    ovs::Request::new(ovs::WatchDirectoryRequest {
                        prefix: root_url,
                        options: ovs::WatchDirectoryOptions {
                            recursive: true,
                            poll_interval: Duration::from_millis(1),
                            ..ovs::WatchDirectoryOptions::default()
                        },
                    }),
                    Some(cancel.clone()),
                )
                .await
                .unwrap();
            // This is the same bridge used by `AsyncChangeEventStream`: the
            // Rust iterator may itself be the ABI-v2 StreamStep adapter, while
            // Python only awaits the bounded receiver and never drives plugin
            // work on the asyncio thread.
            let mut change_rx = spawn_blocking_iterator_producer(changes, cancel.clone());
            projected
                .write(
                    ovs::Request::new(ovs::WriteRequest {
                        address: address.clone(),
                        body: Body::Bytes(b"watch this change".to_vec()),
                        options: WriteOptions::default(),
                    }),
                    None,
                )
                .await
                .unwrap();
            let event = tokio::time::timeout(Duration::from_secs(2), change_rx.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(matches!(
                event,
                ovs::ChangeEvent::Object {
                    address: changed,
                    ..
                } if changed == address
            ));
            cancel.cancel();
        });

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dropping_change_iterator_cancels_native_watch() {
        let (_tx, rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let stream = AsyncChangeEventStream {
            rx: Arc::new(TokioMutex::new(rx)),
            cancel: cancel.clone(),
        };
        assert!(!cancel.is_cancelled());
        drop(stream);
        assert!(cancel.is_cancelled());
    }

    /// `py_error_with_interpreter_state` for `PartialCompletion` must yield
    /// `PartialCompletionError`, not its `InternalBucketError` parent or the
    /// generic `InternalError`. Deleting the arm leaves both the hierarchy and
    /// bucket-taxonomy tests green while callers can no longer catch the
    /// specific type.
    #[test]
    fn partial_completion_code_yields_partial_completion_exception() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let err = py_error_with_interpreter_state(
                OvError::new(ErrorCode::PartialCompletion, "bytes committed"),
                false,
            );
            assert!(
                err.is_instance_of::<PartialCompletionError>(py),
                "ErrorCode::PartialCompletion must convert to PartialCompletionError, \
                 not its parent InternalError",
            );
        });
    }

    /// A `PartialCompletionError` raised directly by a Python plugin (without
    /// the `.code` convenience attribute that `py_error_with_interpreter_state`
    /// adds) must map back to `ErrorCode::PartialCompletion` via the
    /// `binding_exception_code` fallback in `override_failure`. Removing that
    /// arm makes `InternalBucketError`-bucket exceptions report `Internal`,
    /// while the R2P test above stays green.
    #[test]
    fn partial_completion_exception_p2r_yields_partial_completion_code() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            // Create the exception without the `.code` attribute so the
            // `binding_exception_code` fallback is exercised.
            let pyerr = PartialCompletionError::new_err("sidecar not written");
            let ov_error = p2r_marshal::override_failure(py, pyerr);
            assert_eq!(
                ov_error.code(),
                ErrorCode::PartialCompletion,
                "PartialCompletionError raised by a Python plugin must convert to \
                 ErrorCode::PartialCompletion, got {:?}",
                ov_error.code(),
            );
        });
    }

    #[test]
    fn dropping_auth_iterator_cancels_native_flow() {
        let (_tx, rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let stream = AsyncAuthEventStream {
            rx: Arc::new(TokioMutex::new(rx)),
            cancel: cancel.clone(),
        };
        assert!(!cancel.is_cancelled());
        drop(stream);
        assert!(cancel.is_cancelled());
    }
}
