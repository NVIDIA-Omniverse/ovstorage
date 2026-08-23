// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Python-to-Rust dispatch core for declaration-form Python layers.
//!
//! This module owns the one difficult part of the p2r frontier: turning a
//! Python coroutine into a retained `asyncio.Task` which a Rust cancellation
//! token can cancel without holding the GIL across an await.  Per-operation
//! `Layer` methods and stream producers deliberately build on this primitive;
//! they must not introduce a second scheduling path.
//!
//! The normative loop-ownership, cancellation, liveness, and failure-mode
//! contract is recorded in the Python-to-Rust bridge contract in the
//! maintainer docs.

use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::c_char;
use std::ffi::{c_int, c_void};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyTuple};
use pyo3_async_runtimes::TaskLocals;
use tokio::sync::{Notify, oneshot};
use tokio::time::{Instant, MissedTickBehavior};

use crate::p2r_marshal::{self, MarshalledCall};
use crate::p2r_stream;
use crate::{LayerBase, ovs};

pub(super) const PYTHON_BACKEND_KIND: &str = "__python-backend__";
pub(super) const PYTHON_WRAPPER_KIND: &str = "__python-wrapper__";
pub(super) const PY_LOOP_LIVENESS_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub(super) const PY_POST_CANCEL_TIMEOUT: Duration = Duration::from_secs(1);
pub(super) const PY_BRIDGE_CHANNEL_CAPACITY: usize = 8;

/// Number of scheduled Python bridge tasks which have not run their terminal
/// callback yet.  Counting starts before `call_soon_threadsafe` so the queued
/// start-helper window is observable too.
static PY_BRIDGE_TASK_COUNT: AtomicUsize = AtomicUsize::new(0);
static PY_BRIDGE_TASK_QUIESCED: Notify = Notify::const_new();

type PyIsFinalizing = unsafe extern "C" fn() -> c_int;
static PY_IS_FINALIZING: OnceLock<Option<PyIsFinalizing>> = OnceLock::new();
static FINALIZATION_GUARD_WARNING: OnceLock<()> = OnceLock::new();

// `Py_IsFinalizing` entered the public stable ABI after our abi3-py310 floor,
// and Python 3.14 removed the older `_Py_IsFinalizing` export.  Resolve either
// spelling once rather than introducing an unavailable static symbol into an
// abi3 wheel. Asking `sys.is_finalizing()` is not a substitute because that
// would acquire the GIL before learning whether doing so is safe.
#[cfg(unix)]
#[cfg_attr(target_env = "gnu", link(name = "dl"))]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

#[cfg(unix)]
fn resolve_finalization_guard() -> Option<PyIsFinalizing> {
    // SAFETY: `dlopen(NULL, RTLD_LAZY)` returns a process-global lookup handle
    // on supported Unix loaders. It is intentionally retained for process
    // lifetime; the resolved CPython function has that same lifetime.
    unsafe {
        const RTLD_LAZY: c_int = 1;
        let handle = dlopen(std::ptr::null(), RTLD_LAZY);
        if handle.is_null() {
            return None;
        }
        for symbol in [b"Py_IsFinalizing\0".as_slice(), b"_Py_IsFinalizing\0"] {
            let address = dlsym(handle, symbol.as_ptr().cast());
            if !address.is_null() {
                return Some(std::mem::transmute::<*mut c_void, PyIsFinalizing>(address));
            }
        }
        None
    }
}

#[cfg(windows)]
fn resolve_finalization_guard(py: Python<'_>) -> Option<PyIsFinalizing> {
    // `generate-import-lib` uses a conventional Windows import library, so
    // taking the address of a pyo3 C-API function may identify a jump thunk in
    // this extension rather than python3x.dll. `sys.dllhandle` is CPython's
    // authoritative HMODULE for the loaded Python DLL and avoids both that
    // ambiguity and versioned-DLL name probing.
    let module = py
        .import_bound("sys")
        .ok()?
        .getattr("dllhandle")
        .ok()?
        .extract::<usize>()
        .ok()? as *mut c_void;
    if module.is_null() {
        return None;
    }

    unsafe {
        for symbol in [b"Py_IsFinalizing\0".as_slice(), b"_Py_IsFinalizing\0"] {
            let address = GetProcAddress(module, symbol.as_ptr());
            if !address.is_null() {
                return Some(std::mem::transmute::<*mut c_void, PyIsFinalizing>(address));
            }
        }
        None
    }
}

#[cfg(not(any(unix, windows)))]
fn resolve_finalization_guard() -> Option<PyIsFinalizing> {
    None
}

pub(super) fn initialize_finalization_guard(py: Python<'_>) {
    #[cfg(windows)]
    {
        let resolved = resolve_finalization_guard(py);
        let guard = PY_IS_FINALIZING.get_or_init(|| resolved);
        debug_assert!(
            guard.is_some(),
            "could not resolve Py_IsFinalizing from the CPython DLL in sys.dllhandle; \
             the Python-to-Rust bridge will fail closed"
        );
    }
    #[cfg(unix)]
    {
        let _ = py;
        let guard = PY_IS_FINALIZING.get_or_init(resolve_finalization_guard);
        debug_assert!(
            guard.is_some(),
            "could not resolve Py_IsFinalizing from the process-global symbol table; \
             the Python-to-Rust bridge will fail closed"
        );
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = PY_IS_FINALIZING.get_or_init(resolve_finalization_guard);
    }

    if PY_IS_FINALIZING.get().is_some_and(Option::is_none)
        && FINALIZATION_GUARD_WARNING.set(()).is_ok()
    {
        let message = "could not resolve Py_IsFinalizing; the Python-to-Rust bridge fails \
                       closed, so dispatch is unavailable and binding errors lose their typed \
                       `code`/`next_action` attributes";
        let _ = py.import_bound("warnings").and_then(|warnings| {
            warnings
                .call_method1(
                    "warn",
                    (
                        message,
                        py.get_type_bound::<pyo3::exceptions::PyRuntimeWarning>(),
                    ),
                )
                .map(|_| ())
        });
    }
}

pub(super) fn interpreter_is_finalizing() -> bool {
    // Windows resolution must happen at module import while holding the GIL,
    // because the authoritative DLL handle lives on `sys`. Do not try to
    // initialize it lazily from a teardown path.
    #[cfg(windows)]
    let function = PY_IS_FINALIZING.get().copied().flatten();
    #[cfg(not(windows))]
    let function = *PY_IS_FINALIZING.get_or_init(resolve_finalization_guard);
    // SAFETY: both resolved spellings take no arguments, return an integer
    // flag, and are explicitly designed to be queried without the GIL.
    // A host exposing neither spelling cannot establish that acquiring the
    // GIL is safe. Fail closed there: dispatch reports Internal and teardown
    // skips Python calls.
    function
        .map(|function| unsafe { function() != 0 })
        .unwrap_or(true)
}

/// Distinguish confirmed interpreter shutdown from an unavailable stable-ABI
/// symbol, so an error raised during ordinary operation is not mistaken for
/// one raised during teardown.
///
/// This does **not** mean the attributes survive on a host exposing neither
/// spelling. Decorating an error still attaches, and attaching goes through
/// the gate, which fails closed there. That host cannot dispatch either, so
/// the bridge is unusable on it regardless; the attributes are not what is
/// worth attaching blind for.
pub(super) fn interpreter_is_confirmed_finalizing() -> bool {
    #[cfg(windows)]
    let function = PY_IS_FINALIZING.get().copied().flatten();
    #[cfg(not(windows))]
    let function = *PY_IS_FINALIZING.get_or_init(resolve_finalization_guard);
    function.is_some_and(|function| unsafe { function() != 0 })
}

pub(super) fn finalizing_error() -> ovs::Error {
    ovs::Error::new(
        ovs::ErrorCode::Internal,
        "Python interpreter is finalizing; bridge dispatch is unavailable",
    )
}

fn bridge_error(context: &str, error: impl std::fmt::Display) -> ovs::Error {
    ovs::Error::new(
        ovs::ErrorCode::Internal,
        format!("Python bridge {context}: {error}"),
    )
}

pub(super) fn increment_bridge_task_count() {
    let previous = PY_BRIDGE_TASK_COUNT.fetch_add(1, Ordering::AcqRel);
    assert!(
        previous < usize::MAX,
        "Python bridge task counter overflowed"
    );
}

pub(super) fn decrement_bridge_task_count() {
    let previous = PY_BRIDGE_TASK_COUNT.fetch_sub(1, Ordering::AcqRel);
    assert!(previous > 0, "Python bridge task counter underflowed");
    if previous == 1 {
        PY_BRIDGE_TASK_QUIESCED.notify_waiters();
    }
}

pub(super) fn bridge_task_count() -> usize {
    PY_BRIDGE_TASK_COUNT.load(Ordering::Acquire)
}

pub(super) fn ensure_interpreter_active() -> ovs::Result<()> {
    if interpreter_is_finalizing() {
        Err(finalizing_error())
    } else {
        Ok(())
    }
}

/// Count one Rust-owned bridge producer from construction through teardown.
/// The guard may be created before spawning; dropping an unpolled future still
/// retires the count exactly once.
pub(super) struct BridgeTaskGuard;

impl BridgeTaskGuard {
    pub(super) fn new() -> Self {
        increment_bridge_task_count();
        Self
    }
}

impl Drop for BridgeTaskGuard {
    fn drop(&mut self) {
        decrement_bridge_task_count();
    }
}

/// Wait without the GIL until every task scheduled before (or during) the
/// wait has reached its done callback.  The double check around `notified()`
/// closes the usual Notify lost-wakeup race.
pub(super) async fn quiesce_bridge_tasks(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if bridge_task_count() == 0 {
            return true;
        }
        let quiesced = PY_BRIDGE_TASK_QUIESCED.notified();
        if bridge_task_count() == 0 {
            return true;
        }
        if tokio::time::timeout_at(deadline, quiesced).await.is_err() {
            return bridge_task_count() == 0;
        }
    }
}

/// Test-only visibility into the bridge counter.  It stays private at the
/// Python API level and is intentionally omitted from `__all__`.
#[pyfunction]
pub(super) fn _bridge_task_count() -> usize {
    bridge_task_count()
}

/// Deadline-bounded quiescence hook used by Python bridge/stream tests.
///
/// Returning `false` is preferable to raising on timeout: teardown assertions
/// can report the still-live count via `_bridge_task_count()` without losing
/// the original test failure.
#[pyfunction]
#[pyo3(signature = (timeout_seconds = 1.0))]
pub(super) fn _quiesce_bridge_tasks(
    py: Python<'_>,
    timeout_seconds: f64,
) -> PyResult<Bound<'_, PyAny>> {
    let timeout = Duration::try_from_secs_f64(timeout_seconds).map_err(|_| {
        crate::py_error(ovs::Error::new(
            ovs::ErrorCode::InvalidArgument,
            "timeout_seconds must be finite and non-negative",
        ))
    })?;
    // Avoid sending the overwhelmingly common already-quiescent case through
    // a worker runtime only to resolve immediately. Besides being cheaper,
    // this gives teardown tests a ready result even while the process-global
    // Tokio runtime is itself winding down.
    if bridge_task_count() == 0 {
        return crate::ready_coroutine(py, "_quiesce_bridge_tasks", true.into_py(py));
    }
    if timeout.is_zero() {
        return crate::ready_coroutine(py, "_quiesce_bridge_tasks", false.into_py(py));
    }
    crate::coroutine_into_py(py, "_quiesce_bridge_tasks", async move {
        Ok(quiesce_bridge_tasks(timeout).await)
    })
}

struct GateSnapshotRider {
    saw_extension: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ovs::Layer for GateSnapshotRider {
    fn name(&self) -> &str {
        "gate-snapshot-rider"
    }

    fn descriptor(&self) -> ovs::LayerKindDescriptor {
        synthetic_descriptor("gate-snapshot-rider", ovs::LayerType::Backend)
    }

    async fn list_address_roots(
        &self,
        _cx: &ovs::Extensions,
        _cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<(ovs::RootInfoSnapshot, Option<ovs::RootInfoUpdateStream>)> {
        Ok((
            ovs::RootInfoSnapshot {
                roots: Vec::new(),
                updates: true,
            },
            Some(Box::pin(futures::stream::iter(vec![Ok(
                ovs::RootInfoChange::Added(Vec::new()),
            )]))),
        ))
    }

    async fn list_connections(
        &self,
        _cx: &ovs::Extensions,
        _cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<(ovs::ConnectionSnapshot, Option<ovs::ConnectionUpdateStream>)> {
        Ok((
            ovs::ConnectionSnapshot {
                connections: Vec::new(),
                updates: true,
            },
            Some(Box::pin(futures::stream::iter(vec![Ok(
                ovs::ConnectionChange::Snapshot(Vec::new()),
            )]))),
        ))
    }

    async fn stat(
        &self,
        request: ovs::Request<ovs::StatRequest>,
        _cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::ObjectInfo> {
        self.saw_extension.store(
            request.extensions.get("gate-extension") == Some(b"retained"),
            Ordering::Release,
        );
        Err(ovs::Error::new(
            ovs::ErrorCode::Unsupported,
            "gate extension probe",
        ))
    }
}

/// Gate-only probe for the complete native snapshot tuple passthrough.
#[pyfunction]
pub(super) fn _verify_q7_snapshot_riders(py: Python<'_>) -> PyResult<()> {
    use futures::StreamExt as _;
    use ovs::Layer as _;

    let saw_extension = Arc::new(AtomicBool::new(false));
    let inner: ovs::LayerHandle = Arc::new(GateSnapshotRider {
        saw_extension: saw_extension.clone(),
    });
    let object = Py::new(py, LayerBase::from_handle(inner.clone()))?;
    let task_locals = TaskLocals::with_running_loop(py)?.copy_context(py)?;
    let adapter = PyLayerAdapter::new(
        py,
        "gate-python-wrapper".into(),
        ovs::LayerType::Wrapper,
        object.into_any(),
        Some(inner),
        task_locals,
        Vec::new(),
    )
    .map_err(crate::py_error)?;

    let (root_snapshot, root_updates) =
        futures::executor::block_on(adapter.list_address_roots(&ovs::Extensions::new(), None))
            .map_err(crate::py_error)?;
    let (connection_snapshot, connection_updates) =
        futures::executor::block_on(adapter.list_connections(&ovs::Extensions::new(), None))
            .map_err(crate::py_error)?;
    let root_update = futures::executor::block_on(
        root_updates
            .ok_or_else(|| {
                crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::Internal,
                    "snapshot-rider probe lost the native root update rider",
                ))
            })?
            .next(),
    );
    let connection_update = futures::executor::block_on(
        connection_updates
            .ok_or_else(|| {
                crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::Internal,
                    "snapshot-rider probe lost the native connection update rider",
                ))
            })?
            .next(),
    );

    let gate_address =
        ovs::Url::parse("memory://gate/object").expect("hard-coded gate probe address must parse");
    let mut extensions = ovs::Extensions::new();
    extensions.insert("gate-extension", b"retained".to_vec());
    let stat_request = ovs::Request {
        extensions,
        input: ovs::StatRequest {
            address: gate_address.clone(),
            options: ovs::StatOptions {
                full_metadata: false,
            },
        },
    };
    let stat_error = futures::executor::block_on(adapter.stat(stat_request, None))
        .expect_err("native extension probe unexpectedly succeeded");

    let mut marshalled_extensions = ovs::Extensions::new();
    marshalled_extensions.insert("gate-extension", b"marshalled".to_vec());
    let marshalled = p2r_marshal::stat(
        py,
        ovs::Request {
            extensions: marshalled_extensions,
            input: ovs::StatRequest {
                address: gate_address.clone(),
                options: ovs::StatOptions {
                    full_metadata: false,
                },
            },
        },
        ovs::CancellationToken::new(),
    )
    .map_err(crate::py_error)?;
    // A non-empty bag round-trips into the override call as the
    // `extensions` keyword: a dict-of-bytes copy of the native entries — a
    // faithful crossing that carries the bag rather than stripping it.
    let marshalled_bag: Option<HashMap<String, Vec<u8>>> = marshalled
        .kwargs
        .bind(py)
        .get_item("extensions")?
        .map(|bag| bag.extract())
        .transpose()?;
    let forwarded = ovs::Request::new(ovs::StatRequest {
        address: gate_address,
        options: ovs::StatOptions {
            full_metadata: false,
        },
    });

    let valid = root_snapshot.updates
        && connection_snapshot.updates
        && matches!(
            root_update,
            Some(Ok(ovs::RootInfoChange::Added(roots))) if roots.is_empty()
        )
        && matches!(
            connection_update,
            Some(Ok(ovs::ConnectionChange::Snapshot(connections))) if connections.is_empty()
        )
        && stat_error.code() == ovs::ErrorCode::Unsupported
        && saw_extension.load(Ordering::Acquire)
        && marshalled_bag
            .as_ref()
            .and_then(|bag| bag.get("gate-extension"))
            .map(Vec::as_slice)
            == Some(b"marshalled".as_slice())
        && forwarded.extensions.is_empty();
    if !valid {
        return Err(crate::py_error(ovs::Error::new(
            ovs::ErrorCode::Internal,
            "snapshot-rider probe observed a rebuilt or truncated native snapshot tuple",
        )));
    }
    Ok(())
}

/// Gate-only probe that consumes a p2r read stream after cancelling its shared
/// token. Clean EOF is a test failure: a live Rust consumer must receive the
/// terminal `Cancelled` item after any buffered prefix.
#[pyfunction]
pub(super) fn _probe_cancelled_read_stream<'py>(
    py: Python<'py>,
    iterator: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    use futures::StreamExt as _;

    let task_locals = crate::pyo3_tokio::get_current_locals(py)?;
    let loop_handle = task_locals.event_loop(py).unbind();
    let iterator = p2r_stream::read_async_iterator(iterator.bind(py)).map_err(crate::py_error)?;
    let cancel = ovs::CancellationToken::new();
    let stream_cancel = cancel.clone();
    crate::coroutine_into_py(py, "_probe_cancelled_read_stream", async move {
        let mut stream = p2r_stream::read_stream(task_locals, loop_handle, iterator, stream_cancel);
        let first = stream
            .next()
            .await
            .ok_or_else(|| {
                crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::Internal,
                    "cancel probe stream ended before its prefix",
                ))
            })?
            .map_err(crate::py_error)?;
        cancel.cancel();
        let terminal = tokio::time::timeout(PY_POST_CANCEL_TIMEOUT, stream.next())
            .await
            .map_err(|_| {
                crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::DeadlineExceeded,
                    "cancel probe did not receive a terminal stream item",
                ))
            })?;
        match terminal {
            Some(Err(error)) if error.code() == ovs::ErrorCode::Cancelled => Ok(first.len()),
            Some(Err(error)) => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                format!(
                    "cancel probe received {:?} instead of Cancelled",
                    error.code()
                ),
            ))),
            Some(Ok(_)) => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                "cancel probe received data after cancellation",
            ))),
            None => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                "cancel probe observed clean EOF after a partial stream",
            ))),
        }
    })
}

/// Gate-only probe for cancellation while all eight data slots are occupied.
/// The producer must close and retire before this retained consumer drains.
#[pyfunction]
pub(super) fn _probe_full_read_channel_cancel<'py>(
    py: Python<'py>,
    iterator: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    use futures::StreamExt as _;

    let task_locals = crate::pyo3_tokio::get_current_locals(py)?;
    let loop_handle = task_locals.event_loop(py).unbind();
    let observer = iterator.clone_ref(py);
    let iterator = p2r_stream::read_async_iterator(iterator.bind(py)).map_err(crate::py_error)?;
    let cancel = ovs::CancellationToken::new();
    let stream_cancel = cancel.clone();
    crate::coroutine_into_py(py, "_probe_full_read_channel_cancel", async move {
        let mut stream = p2r_stream::read_stream(task_locals, loop_handle, iterator, stream_cancel);
        let deadline = Instant::now() + PY_POST_CANCEL_TIMEOUT;
        loop {
            let pulls = crate::bridge_gil::with_bridge_gil_py(|py| {
                observer.bind(py).getattr("pulls")?.extract::<usize>()
            })?;
            if pulls > PY_BRIDGE_CHANNEL_CAPACITY {
                break;
            }
            if Instant::now() >= deadline {
                return Err(crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::DeadlineExceeded,
                    "read producer did not fill the bounded bridge channel",
                )));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        cancel.cancel();
        if !quiesce_bridge_tasks(PY_POST_CANCEL_TIMEOUT).await {
            return Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::DeadlineExceeded,
                "full-channel read producer did not retire after cancellation",
            )));
        }

        let mut buffered = 0;
        loop {
            let item = tokio::time::timeout(PY_POST_CANCEL_TIMEOUT, stream.next())
                .await
                .map_err(|_| {
                    crate::py_error(ovs::Error::new(
                        ovs::ErrorCode::DeadlineExceeded,
                        "full-channel read probe did not reach its terminal item",
                    ))
                })?;
            match item {
                Some(Ok(_)) => buffered += 1,
                Some(Err(error)) if error.code() == ovs::ErrorCode::Cancelled => break,
                Some(Err(error)) => {
                    return Err(crate::py_error(ovs::Error::new(
                        ovs::ErrorCode::Internal,
                        format!(
                            "full-channel read probe received {:?} instead of Cancelled",
                            error.code()
                        ),
                    )));
                }
                None => {
                    return Err(crate::py_error(ovs::Error::new(
                        ovs::ErrorCode::Internal,
                        "full-channel read probe observed clean EOF",
                    )));
                }
            }
        }
        if buffered != PY_BRIDGE_CHANNEL_CAPACITY {
            return Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                format!(
                    "full-channel read probe drained {buffered} items, expected {PY_BRIDGE_CHANNEL_CAPACITY}"
                ),
            )));
        }
        Ok(buffered)
    })
}

/// Gate-only probe for adapter body disposition. `write` must reject blocking
/// bodies without pulling them, while `write_stream` must preserve all three
/// native body variants through the Python override.
#[pyfunction]
pub(super) fn _probe_adapter_body_variants<'py>(
    py: Python<'py>,
    layer: PyObject,
    local_file: std::path::PathBuf,
    addresses: Vec<String>,
) -> PyResult<Bound<'py, PyAny>> {
    use ovs::Layer as _;

    if addresses.len() != 6 {
        return Err(crate::py_error(ovs::Error::new(
            ovs::ErrorCode::InvalidArgument,
            "adapter body probe requires exactly six target addresses",
        )));
    }
    let task_locals = crate::pyo3_tokio::get_current_locals(py)?;
    let adapter = Arc::new(
        PyLayerAdapter::new(
            py,
            "gate-body-probe".into(),
            ovs::LayerType::Backend,
            layer,
            None,
            task_locals,
            Vec::new(),
        )
        .map_err(crate::py_error)?,
    );

    crate::coroutine_into_py(py, "_probe_adapter_body_variants", async move {
        ensure_interpreter_active().map_err(crate::py_error)?;
        let request = |address: &str, body: ovs::Body| -> PyResult<_> {
            Ok(ovs::Request::new(ovs::WriteRequest {
                address: ovs::Url::parse(address).map_err(|error| {
                    crate::py_error(ovs::Error::new(
                        ovs::ErrorCode::InvalidArgument,
                        format!("invalid adapter body probe address: {error}"),
                    ))
                })?,
                body,
                options: ovs::WriteOptions::default(),
            }))
        };

        adapter
            .write(
                request(&addresses[0], ovs::Body::Bytes(b"write-bytes".to_vec()))?,
                None,
            )
            .await
            .map_err(crate::py_error)?;

        let rejected_pulls = Arc::new(AtomicUsize::new(0));
        let rejected_observer = rejected_pulls.clone();
        let mut rejected_chunks = vec![Ok(b"must-not-pull".to_vec())].into_iter();
        let rejected_stream = ovs::BodyStream::from_iter(std::iter::from_fn(move || {
            rejected_observer.fetch_add(1, Ordering::AcqRel);
            rejected_chunks.next()
        }));
        let rejected = adapter
            .write(
                request(&addresses[1], ovs::Body::Stream(rejected_stream))?,
                None,
            )
            .await;
        if !matches!(rejected, Err(ref error) if error.code() == ovs::ErrorCode::Unsupported) {
            return Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                "adapter write did not reject Body::Stream with Unsupported",
            )));
        }
        let rejected = adapter
            .write(
                request(&addresses[2], ovs::Body::LocalFile(local_file.clone()))?,
                None,
            )
            .await;
        if !matches!(rejected, Err(ref error) if error.code() == ovs::ErrorCode::Unsupported) {
            return Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                "adapter write did not reject Body::LocalFile with Unsupported",
            )));
        }

        adapter
            .write_stream(
                request(
                    &addresses[3],
                    ovs::Body::Bytes(b"write-stream-bytes".to_vec()),
                )?,
                None,
            )
            .await
            .map_err(crate::py_error)?;
        let accepted_pulls = Arc::new(AtomicUsize::new(0));
        let accepted_observer = accepted_pulls.clone();
        let mut accepted_chunks =
            vec![Ok(b"write-stream-".to_vec()), Ok(b"chunks".to_vec())].into_iter();
        let accepted_stream = ovs::BodyStream::from_iter(std::iter::from_fn(move || {
            accepted_observer.fetch_add(1, Ordering::AcqRel);
            accepted_chunks.next()
        }));
        adapter
            .write_stream(
                request(&addresses[4], ovs::Body::Stream(accepted_stream))?,
                None,
            )
            .await
            .map_err(crate::py_error)?;
        adapter
            .write_stream(
                request(&addresses[5], ovs::Body::LocalFile(local_file))?,
                None,
            )
            .await
            .map_err(crate::py_error)?;

        Ok((
            rejected_pulls.load(Ordering::Acquire),
            accepted_pulls.load(Ordering::Acquire),
        ))
    })
}

/// Gate-only probe for cancellation before the queued start callback can
/// publish its asyncio task.
#[pyfunction]
pub(super) fn _probe_cancel_before_publication<'py>(
    py: Python<'py>,
    callable: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    let task_locals = crate::pyo3_tokio::get_current_locals(py)?;
    let loop_handle = task_locals.event_loop(py).unbind();
    let cancel = ovs::CancellationToken::new();
    cancel.cancel();
    let call = MarshalledCall {
        args: PyTuple::empty_bound(py).unbind(),
        kwargs: PyDict::new_bound(py).unbind(),
        cancel,
    };
    crate::coroutine_into_py(py, "_probe_cancel_before_publication", async move {
        match dispatch_callable_with_context(
            &task_locals,
            &loop_handle,
            "cancel-before-publication probe",
            crate::bridge_gil::Admission::Dispatch,
            AwaitableRequirement::Coroutine,
            &callable,
            call,
            |_, _| Ok(()),
            |py, error| Err(p2r_marshal::override_failure(py, error)),
        )
        .await
        {
            Err(error) if error.code() == ovs::ErrorCode::Cancelled => Ok(()),
            Err(error) => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                format!(
                    "cancel-before-publication probe received {:?} instead of Cancelled",
                    error.code()
                ),
            ))),
            Ok(()) => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                "cancel-before-publication probe completed unexpectedly",
            ))),
        }
    })
}

/// Gate-only probe for the bounded post-cancel failure path. `started` is an
/// asyncio.Event set by a coroutine which suppresses cancellation.
#[pyfunction]
pub(super) fn _probe_post_cancel_deadline<'py>(
    py: Python<'py>,
    callable: PyObject,
    started: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    let task_locals = crate::pyo3_tokio::get_current_locals(py)?;
    let loop_handle = task_locals.event_loop(py).unbind();
    let cancel = ovs::CancellationToken::new();
    let call = MarshalledCall {
        args: PyTuple::empty_bound(py).unbind(),
        kwargs: PyDict::new_bound(py).unbind(),
        cancel: cancel.clone(),
    };
    crate::coroutine_into_py(py, "_probe_post_cancel_deadline", async move {
        let dispatch = dispatch_callable_with_context(
            &task_locals,
            &loop_handle,
            "post-cancel deadline probe",
            crate::bridge_gil::Admission::Dispatch,
            AwaitableRequirement::Coroutine,
            &callable,
            call,
            |_, _| Ok(()),
            |py, error| Err(p2r_marshal::override_failure(py, error)),
        );
        tokio::pin!(dispatch);
        let start_deadline = Instant::now() + PY_POST_CANCEL_TIMEOUT;
        loop {
            tokio::select! {
                result = &mut dispatch => {
                    return match result {
                        Ok(()) => Err(crate::py_error(ovs::Error::new(
                            ovs::ErrorCode::Internal,
                            "post-cancel probe completed before cancellation",
                        ))),
                        Err(error) => Err(crate::py_error(error)),
                    };
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    let is_set = crate::bridge_gil::with_bridge_gil_py(|py| {
                        started.bind(py).call_method0("is_set")?.extract::<bool>()
                    })?;
                    if is_set {
                        break;
                    }
                    if Instant::now() >= start_deadline {
                        return Err(crate::py_error(ovs::Error::new(
                            ovs::ErrorCode::DeadlineExceeded,
                            "post-cancel probe coroutine did not start",
                        )));
                    }
                }
            }
        }

        cancel.cancel();
        match dispatch.await {
            Err(error) if error.code() == ovs::ErrorCode::DeadlineExceeded => Ok(()),
            Err(error) => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                format!(
                    "post-cancel probe received {:?} instead of DeadlineExceeded",
                    error.code()
                ),
            ))),
            Ok(()) => Err(crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                "post-cancel probe completed within the cancellation bound",
            ))),
        }
    })
}

/// Gate-only counterpart for the blocking `ChangeStream` consumer surface.
#[pyfunction]
pub(super) fn _probe_cancelled_watch_stream<'py>(
    py: Python<'py>,
    iterator: PyObject,
) -> PyResult<Bound<'py, PyAny>> {
    let task_locals = crate::pyo3_tokio::get_current_locals(py)?;
    let loop_handle = task_locals.event_loop(py).unbind();
    let iterator = p2r_stream::async_iterator(iterator.bind(py)).map_err(crate::py_error)?;
    let cancel = ovs::CancellationToken::new();
    let stream_cancel = cancel.clone();
    let prefix = ovs::address::parse("file:///").map_err(crate::py_error)?;
    crate::coroutine_into_py(py, "_probe_cancelled_watch_stream", async move {
        let mut stream = p2r_stream::change_stream(
            task_locals,
            loop_handle,
            iterator,
            stream_cancel,
            prefix,
            true,
        );
        tokio::task::spawn_blocking(move || {
            let first = stream
                .next()
                .ok_or_else(|| {
                    crate::py_error(ovs::Error::new(
                        ovs::ErrorCode::Internal,
                        "watch cancel probe ended before its first event",
                    ))
                })?
                .map_err(crate::py_error)?;
            cancel.cancel();
            match stream.next() {
                Some(Err(error)) if error.code() == ovs::ErrorCode::Cancelled => match first {
                    ovs::ChangeEvent::Object { address, .. } => Ok(address.to_string()),
                    ovs::ChangeEvent::Lapsed { .. } => Err(crate::py_error(ovs::Error::new(
                        ovs::ErrorCode::Internal,
                        "watch cancel probe expected an object event",
                    ))),
                },
                Some(Err(error)) => Err(crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::Internal,
                    format!(
                        "watch cancel probe received {:?} instead of Cancelled",
                        error.code()
                    ),
                ))),
                Some(Ok(_)) => Err(crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::Internal,
                    "watch cancel probe received an event after cancellation",
                ))),
                None => Err(crate::py_error(ovs::Error::new(
                    ovs::ErrorCode::Internal,
                    "watch cancel probe observed clean EOF after a partial stream",
                ))),
            }
        })
        .await
        .map_err(|error| {
            crate::py_error(ovs::Error::new(
                ovs::ErrorCode::Internal,
                format!("watch cancel probe worker failed: {error}"),
            ))
        })?
    })
}

/// The operation slots which may enter Python.  Connection mutation,
/// redirect protocol, and synchronous snapshot methods are intentionally not
/// represented here and therefore cannot accidentally cross this frontier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum OverrideSlot {
    Stat,
    Read,
    Write,
    WriteStream,
    Delete,
    Copy,
    Rename,
    UpdateMetadata,
    CheckAccess,
    Materialize,
    List,
    ListVersions,
    GetLatestVersion,
    CreateDirectory,
    DeleteDirectory,
    Probe,
    WatchDirectory,
}

impl OverrideSlot {
    pub(super) const ALL: [Self; 17] = [
        Self::Stat,
        Self::Read,
        Self::Write,
        Self::WriteStream,
        Self::Delete,
        Self::Copy,
        Self::Rename,
        Self::UpdateMetadata,
        Self::CheckAccess,
        Self::Materialize,
        Self::List,
        Self::ListVersions,
        Self::GetLatestVersion,
        Self::CreateDirectory,
        Self::DeleteDirectory,
        Self::Probe,
        Self::WatchDirectory,
    ];

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Stat => "stat",
            Self::Read => "read",
            Self::Write => "write",
            Self::WriteStream => "write_stream",
            Self::Delete => "delete",
            Self::Copy => "copy",
            Self::Rename => "rename",
            Self::UpdateMetadata => "update_metadata",
            Self::CheckAccess => "check_access",
            Self::Materialize => "materialize",
            Self::List => "list",
            Self::ListVersions => "list_versions",
            Self::GetLatestVersion => "get_latest_version",
            Self::CreateDirectory => "create_directory",
            Self::DeleteDirectory => "delete_directory",
            Self::Probe => "probe",
            Self::WatchDirectory => "watch_directory",
        }
    }
}

pub(super) type OverrideMap = HashMap<OverrideSlot, Py<PyAny>>;

pub(super) fn detect_overrides(
    py: Python<'_>,
    py_obj: &Py<PyAny>,
) -> Result<OverrideMap, ovs::Error> {
    let object = py_obj.bind(py);
    let object_type = object.get_type();
    let base_type = py.get_type_bound::<LayerBase>();
    let inspect = py.import_bound("inspect").map_err(|error| {
        bridge_error(
            "could not import inspect for Python LayerBase override classification",
            error,
        )
    })?;
    let iscoroutinefunction = inspect.getattr("iscoroutinefunction").map_err(|error| {
        bridge_error(
            "could not inspect Python LayerBase override classification helper",
            error,
        )
    })?;
    let isasyncgenfunction = inspect.getattr("isasyncgenfunction").map_err(|error| {
        bridge_error(
            "could not inspect Python LayerBase async-generator classification helper",
            error,
        )
    })?;
    let mut overrides = HashMap::with_capacity(OverrideSlot::ALL.len());

    for slot in OverrideSlot::ALL {
        let resolved = match object_type.getattr(slot.name()) {
            Ok(value) => Some(value),
            Err(error) if error.is_instance_of::<pyo3::exceptions::PyAttributeError>(py) => None,
            Err(error) => {
                return Err(bridge_error(
                    "could not inspect Python LayerBase override",
                    format!("{}: {error}", slot.name()),
                ));
            }
        };
        let base = match base_type.getattr(slot.name()) {
            Ok(value) => Some(value),
            Err(error) if error.is_instance_of::<pyo3::exceptions::PyAttributeError>(py) => None,
            Err(error) => {
                return Err(bridge_error(
                    "could not inspect LayerBase operation slot",
                    format!("{}: {error}", slot.name()),
                ));
            }
        };
        let is_override = match (&resolved, &base) {
            (Some(resolved), Some(base)) => !resolved.is(base),
            // A downstream r2p-surface unit adds the remaining base methods.
            // Until then, a subclass definition is still unambiguously an
            // override; a missing definition on both types is unoverridden.
            (Some(_), None) => true,
            (None, _) => false,
        };
        if is_override {
            let callable = object.getattr(slot.name()).map_err(|error| {
                bridge_error(
                    "could not bind a detected LayerBase override",
                    format!("{}: {error}", slot.name()),
                )
            })?;
            if !callable.is_callable() {
                return Err(ovs::Error::new(
                    ovs::ErrorCode::InvalidArgument,
                    format!(
                        "Python LayerBase override `{}` must be callable",
                        slot.name()
                    ),
                ));
            }
            let is_async = iscoroutinefunction
                .call1((&callable,))
                .and_then(|value| value.extract::<bool>())
                .map_err(|error| {
                    bridge_error(
                        "could not classify Python LayerBase override",
                        format!("{}: {error}", slot.name()),
                    )
                })?;
            if !is_async {
                let is_async_generator = isasyncgenfunction
                    .call1((&callable,))
                    .and_then(|value| value.extract::<bool>())
                    .map_err(|error| {
                        bridge_error(
                            "could not classify Python LayerBase async-generator override",
                            format!("{}: {error}", slot.name()),
                        )
                    })?;
                if is_async_generator {
                    return Err(ovs::Error::new(
                        ovs::ErrorCode::InvalidArgument,
                        format!(
                            "Python LayerBase override `{}` is an async generator function; \
                             define an `async def` method that returns the async iterator",
                            slot.name()
                        ),
                    ));
                }
                return Err(ovs::Error::new(
                    ovs::ErrorCode::InvalidArgument,
                    format!(
                        "Python LayerBase override `{}` must be declared with `async def`",
                        slot.name()
                    ),
                ));
            }
            overrides.insert(slot, callable.unbind());
        }
    }
    Ok(overrides)
}

/// One declaration captured by `Stack.build()` for the synthetic in-process
/// factories. The Python handle is never exported through a plugin ABI; the
/// factory indexes it by the ordinary `LayerSpec.name` supplied by
/// `StackBuilder`.
pub(super) struct PyLayerFactoryNode {
    pub(super) py_obj: Py<LayerBase>,
    pub(super) layer_type: ovs::LayerType,
    pub(super) roots: Vec<ovs::Url>,
}

impl PyLayerFactoryNode {
    pub(super) fn new(
        py_obj: Py<LayerBase>,
        layer_type: ovs::LayerType,
        roots: Vec<ovs::Url>,
    ) -> Self {
        Self {
            py_obj,
            layer_type,
            roots,
        }
    }
}

/// The two reserved-kind factories share a name-indexed declaration table and
/// the loop/context snapshot captured synchronously by `Stack.build()`.
/// Keeping the table behind `Arc` gives every fabricated Python node its own
/// `PyLayerAdapter` while retaining one unambiguous Python instance per name.
pub(super) struct PyLayerFactories {
    nodes: Arc<HashMap<String, Arc<PyLayerFactoryNode>>>,
    task_locals: TaskLocals,
}

impl PyLayerFactories {
    pub(super) fn new(
        nodes: HashMap<String, Arc<PyLayerFactoryNode>>,
        task_locals: TaskLocals,
    ) -> Self {
        Self {
            nodes: Arc::new(nodes),
            task_locals,
        }
    }

    pub(super) fn register(self, builder: ovs::StackBuilder) -> ovs::StackBuilder {
        let nodes = self.nodes;
        if nodes.is_empty() {
            return builder;
        }
        builder
            .backend_factory(Arc::new(PyBackendFactory {
                nodes: nodes.clone(),
                task_locals: self.task_locals.clone(),
            }))
            .wrapper_factory(Arc::new(PyWrapperFactory {
                nodes,
                task_locals: self.task_locals,
            }))
    }
}

struct PyBackendFactory {
    nodes: Arc<HashMap<String, Arc<PyLayerFactoryNode>>>,
    task_locals: TaskLocals,
}

struct PyWrapperFactory {
    nodes: Arc<HashMap<String, Arc<PyLayerFactoryNode>>>,
    task_locals: TaskLocals,
}

fn synthetic_descriptor(kind: &str, layer_type: ovs::LayerType) -> ovs::LayerKindDescriptor {
    ovs::LayerKindDescriptor {
        kind: kind.to_owned(),
        layer_type,
        display_name: match layer_type {
            ovs::LayerType::Backend => "Python backend",
            ovs::LayerType::Wrapper => "Python wrapper",
            ovs::LayerType::Router => unreachable!("Python routers are not supported"),
        }
        .to_owned(),
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        // The Python Layer API exposes no way to declare user-metadata support,
        // so a Python backend declares none and a host composes no attribution
        // layer over it — rather than stamping a reserved key the Layer never
        // said it could keep.
        supports_user_metadata: false,
    }
}

fn factory_node(
    nodes: &HashMap<String, Arc<PyLayerFactoryNode>>,
    name: &str,
    expected: ovs::LayerType,
) -> ovs::Result<Arc<PyLayerFactoryNode>> {
    let node = nodes.get(name).cloned().ok_or_else(|| {
        ovs::Error::new(
            ovs::ErrorCode::NotConfigured,
            format!("no Python declaration instance retained for layer '{name}'"),
        )
    })?;
    if node.layer_type != expected {
        return Err(ovs::Error::new(
            ovs::ErrorCode::InvalidArgument,
            format!("Python declaration '{name}' has a mismatched layer_type"),
        ));
    }
    Ok(node)
}

// Keep these factory implementations hand-expanded so their boxed dynamic
// future ABI is explicit beside the in-process trait-object registration.
impl ovs::BackendFactory for PyBackendFactory {
    fn descriptor(&self) -> ovs::LayerKindDescriptor {
        synthetic_descriptor(PYTHON_BACKEND_KIND, ovs::LayerType::Backend)
    }

    fn create_backend<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        name: &'life1 str,
        _config: &'life2 ovs::LayerConfig,
        _cancel: Option<ovs::CancellationToken>,
    ) -> Pin<Box<dyn Future<Output = ovs::Result<ovs::LayerHandle>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let node = factory_node(&self.nodes, name, ovs::LayerType::Backend);
        let name = name.to_owned();
        let task_locals = self.task_locals.clone();
        Box::pin(async move {
            let node = node?;
            crate::bridge_gil::with_bridge_gil(|py| {
                let py_obj = node.py_obj.clone_ref(py).into_any();
                let adapter = PyLayerAdapter::new(
                    py,
                    name,
                    ovs::LayerType::Backend,
                    py_obj,
                    None,
                    task_locals,
                    node.roots.clone(),
                )?;
                Ok(Arc::new(adapter) as ovs::LayerHandle)
            })
        })
    }
}

impl ovs::WrapperFactory for PyWrapperFactory {
    fn descriptor(&self) -> ovs::LayerKindDescriptor {
        synthetic_descriptor(PYTHON_WRAPPER_KIND, ovs::LayerType::Wrapper)
    }

    fn create_wrapper<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        name: &'life1 str,
        _config: &'life2 ovs::LayerConfig,
        inner: ovs::LayerHandle,
        _cancel: Option<ovs::CancellationToken>,
    ) -> Pin<Box<dyn Future<Output = ovs::Result<ovs::LayerHandle>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let node = factory_node(&self.nodes, name, ovs::LayerType::Wrapper);
        let name = name.to_owned();
        let task_locals = self.task_locals.clone();
        Box::pin(async move {
            let node = node?;
            crate::bridge_gil::with_bridge_gil(|py| {
                let py_obj = node.py_obj.clone_ref(py).into_any();
                let adapter = PyLayerAdapter::new(
                    py,
                    name,
                    ovs::LayerType::Wrapper,
                    py_obj,
                    Some(inner.clone()),
                    task_locals,
                    Vec::new(),
                )?;
                // Base-method forwarding re-enters only the validated native
                // inner. It deliberately receives no StackOwner. Delaying the
                // mutation avoids exposing an operational declaration when
                // adapter validation fails.
                {
                    let mut base = node.py_obj.bind(py).borrow_mut();
                    base.inner = Some(inner);
                    base.owner = None;
                }
                Ok(Arc::new(adapter) as ovs::LayerHandle)
            })
        })
    }
}

/// Immutable state captured when a declaration-form Python layer is bound.
///
/// The per-slot `Layer` implementation either delegates the original request
/// to `inner`, or marshals and calls the cached override through
/// [`Self::dispatch`].
pub(super) struct PyLayerAdapter {
    #[allow(dead_code)] // Strong ownership keeps the bound declaration alive.
    pub(super) py_obj: Py<PyAny>,
    pub(super) inner: Option<Arc<dyn ovs::Layer>>,
    pub(super) task_locals: TaskLocals,
    pub(super) loop_handle: Py<PyAny>,
    pub(super) declared_roots: ovs::RootInfoSnapshot,
    pub(super) overrides: OverrideMap,
    pub(super) name: String,
    pub(super) layer_type: ovs::LayerType,
}

impl PyLayerAdapter {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        py: Python<'_>,
        name: String,
        layer_type: ovs::LayerType,
        py_obj: Py<PyAny>,
        inner: Option<Arc<dyn ovs::Layer>>,
        task_locals: TaskLocals,
        declared_roots: Vec<ovs::Url>,
    ) -> Result<Self, ovs::Error> {
        match layer_type {
            ovs::LayerType::Backend if inner.is_some() => {
                return Err(ovs::Error::new(
                    ovs::ErrorCode::InvalidArgument,
                    "a Python backend declaration cannot have an inner layer",
                ));
            }
            ovs::LayerType::Wrapper if inner.is_none() => {
                return Err(ovs::Error::new(
                    ovs::ErrorCode::InvalidArgument,
                    "a Python wrapper declaration requires an inner layer",
                ));
            }
            ovs::LayerType::Wrapper if !declared_roots.is_empty() => {
                return Err(ovs::Error::new(
                    ovs::ErrorCode::InvalidArgument,
                    "a Python wrapper declaration cannot publish static roots",
                ));
            }
            ovs::LayerType::Router => {
                return Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "Python router declarations are not supported",
                ));
            }
            _ => {}
        }

        let overrides = detect_overrides(py, &py_obj)?;
        let declared_roots = declared_roots
            .into_iter()
            .map(|root| declared_root_info(root, &overrides))
            .collect();
        let loop_handle = task_locals.event_loop(py).unbind();
        Ok(Self {
            py_obj,
            inner,
            task_locals,
            loop_handle,
            declared_roots: ovs::RootInfoSnapshot {
                roots: declared_roots,
                updates: false,
            },
            overrides,
            name,
            layer_type,
        })
    }

    pub(super) fn is_overridden(&self, slot: OverrideSlot) -> bool {
        self.overrides.contains_key(&slot)
    }

    pub(super) fn override_callable(&self, slot: OverrideSlot) -> Option<&Py<PyAny>> {
        self.overrides.get(&slot)
    }

    /// Invoke and await one cached Python coroutine override.
    ///
    /// This is the sole scheduler for finite calls, stream startup, iterator
    /// pulls, and async close.  The GIL is scoped to invocation, synchronous
    /// loop checks, task-cancel enqueueing, and final result decoding; every
    /// `.await` occurs after those scopes have ended.
    pub(super) async fn dispatch<T, Decode>(
        &self,
        slot: OverrideSlot,
        call: MarshalledCall,
        decode: Decode,
    ) -> Result<T, ovs::Error>
    where
        T: Send,
        Decode: for<'py> FnOnce(Python<'py>, Bound<'py, PyAny>) -> Result<T, ovs::Error> + Send,
    {
        let callable = self.override_callable(slot).ok_or_else(|| {
            ovs::Error::new(
                ovs::ErrorCode::Unsupported,
                format!("Python layer does not override `{}`", slot.name()),
            )
        })?;
        self.dispatch_callable(slot.name(), callable, call, decode)
            .await
    }

    async fn dispatch_callable<T, Decode>(
        &self,
        operation: &'static str,
        callable: &Py<PyAny>,
        call: MarshalledCall,
        decode: Decode,
    ) -> Result<T, ovs::Error>
    where
        T: Send,
        Decode: for<'py> FnOnce(Python<'py>, Bound<'py, PyAny>) -> Result<T, ovs::Error> + Send,
    {
        dispatch_callable_with_context(
            &self.task_locals,
            &self.loop_handle,
            operation,
            crate::bridge_gil::Admission::Dispatch,
            AwaitableRequirement::Coroutine,
            callable,
            call,
            decode,
            |py, error| Err(p2r_marshal::override_failure(py, error)),
        )
        .await
    }
}

#[derive(Clone, Copy)]
pub(super) enum AwaitableRequirement {
    Coroutine,
    Awaitable,
}

enum DispatchScheduleOutcome {
    Scheduled,
    RejectedAwaitable(Py<PyAny>),
}

/// Schedule one Python awaitable against a captured loop/context pair.
///
/// Stream producers retain only these two Python handles, rather than the
/// complete adapter, but still enter Python through exactly the same retained
/// task, cancellation, and liveness machinery as finite operations. The error
/// decoder is customizable solely so iterator `StopAsyncIteration` can become
/// clean exhaustion; ordinary slots use [`p2r_marshal::override_failure`].
#[allow(clippy::too_many_arguments)] // One shared primitive carries both result decoders.
pub(super) async fn dispatch_callable_with_context<T, Decode, DecodeError>(
    task_locals: &TaskLocals,
    loop_handle: &Py<PyAny>,
    operation: &'static str,
    admission: crate::bridge_gil::Admission,
    requirement: AwaitableRequirement,
    callable: &Py<PyAny>,
    call: MarshalledCall,
    decode: Decode,
    decode_error: DecodeError,
) -> Result<T, ovs::Error>
where
    T: Send,
    Decode: for<'py> FnOnce(Python<'py>, Bound<'py, PyAny>) -> Result<T, ovs::Error> + Send,
    DecodeError: for<'py> FnOnce(Python<'py>, PyErr) -> Result<T, ovs::Error> + Send,
{
    if call.cancel.is_cancelled() {
        return Err(ovs::Error::new(
            ovs::ErrorCode::Cancelled,
            format!("Python `{operation}` was cancelled before dispatch"),
        ));
    }

    let (tx, mut rx) = oneshot::channel();
    let lifecycle = Arc::new(DispatchLifecycle::new(tx));
    let scheduled = crate::bridge_gil::with_bridge_gil_as(admission, |py| {
        let result = callable
            .bind(py)
            .call(call.args.bind(py), Some(call.kwargs.bind(py)))
            .map_err(|error| p2r_marshal::override_failure(py, error))?;

        let inspect = py
            .import_bound("inspect")
            .map_err(|error| bridge_error("could not import inspect", error))?;
        let predicate = match requirement {
            AwaitableRequirement::Coroutine => "iscoroutine",
            AwaitableRequirement::Awaitable => "isawaitable",
        };
        let accepted: bool = inspect
            .call_method1(predicate, (&result,))
            .and_then(|value| value.extract())
            .map_err(|error| bridge_error("could not classify override result", error))?;
        if !accepted {
            let is_awaitable: bool = inspect
                .call_method1("isawaitable", (&result,))
                .and_then(|value| value.extract())
                .map_err(|error| {
                    bridge_error("could not classify rejected override result", error)
                })?;
            if is_awaitable {
                return Ok(DispatchScheduleOutcome::RejectedAwaitable(result.unbind()));
            }
            let required = match requirement {
                AwaitableRequirement::Coroutine => "be async def and return a coroutine",
                AwaitableRequirement::Awaitable => "return an awaitable",
            };
            return Err(ovs::Error::new(
                ovs::ErrorCode::IncompatibleType,
                format!("Python `{operation}` must {required}"),
            ));
        }

        if let Err(error) = require_loop_runnable(loop_handle.bind(py), LoopRole::Captured) {
            close_unscheduled_coroutine(&result);
            return Err(error);
        }

        let coroutine = result.unbind();
        // Retain a second handle only until scheduling succeeds so a
        // call_soon_threadsafe failure can explicitly close the otherwise
        // unowned coroutine instead of emitting a RuntimeWarning later.
        let close_on_failure = coroutine.clone_ref(py);
        let start_helper = Py::new(
            py,
            PyBridgeStart {
                coroutine: Some(coroutine),
                loop_handle: loop_handle.clone_ref(py),
                lifecycle: lifecycle.clone(),
                prescheduled: false,
            },
        )
        .map_err(|error| bridge_error("could not allocate start callback", error))?;

        let kwargs = PyDict::new_bound(py);
        kwargs
            .set_item("context", task_locals.context(py))
            .map_err(|error| bridge_error("could not attach dispatch context", error))?;
        increment_bridge_task_count();
        lifecycle.counted.store(true, Ordering::Release);
        if let Err(error) =
            loop_handle
                .bind(py)
                .call_method("call_soon_threadsafe", (start_helper,), Some(&kwargs))
        {
            close_unscheduled_coroutine(close_on_failure.bind(py));
            lifecycle.abandon();
            return Err(loop_schedule_failure(
                loop_handle.bind(py),
                error,
                LoopRole::Captured,
            ));
        }
        Ok(DispatchScheduleOutcome::Scheduled)
    });
    match scheduled? {
        DispatchScheduleOutcome::Scheduled => {}
        DispatchScheduleOutcome::RejectedAwaitable(awaitable) => {
            let retired = retire_rejected_awaitable(awaitable).await?;
            let required = match requirement {
                AwaitableRequirement::Coroutine => "be async def and return a coroutine",
                AwaitableRequirement::Awaitable => "return an awaitable",
            };
            // A rejected value that was already scheduled may have mutated the
            // backend before it was retired, so the caller must not read this
            // as "nothing happened".
            // Retirement disposed of the value; neither disposal says whether
            // work behind it ran, so the caveat states the mechanism only.
            let caveat = match retired {
                RetiredAwaitable::ClosedLocally => {
                    "; the value returned was discarded rather than awaited, \
                     which undoes nothing it or the override may already have \
                     done"
                }
                RetiredAwaitable::DiscardedUnscheduled => {
                    "; the value returned is not a Future or Task, so \
                     retirement had no owner loop to reach it through and \
                     released it without scheduling it or calling `__await__` \
                     or `close()` on it, which undoes nothing the override may \
                     already have done"
                }
                RetiredAwaitable::RetiredViaLoop => {
                    "; retirement tried to cancel the value returned on its \
                     owning loop, which cannot undo work already performed, so \
                     the underlying operation may already have completed"
                }
            };
            return Err(ovs::Error::new(
                ovs::ErrorCode::IncompatibleType,
                format!("Python `{operation}` must {required}{caveat}"),
            ));
        }
    }

    let mut drop_guard = DispatchDropGuard::new(lifecycle.clone(), loop_handle.clone());
    let mut liveness = liveness_interval();
    loop {
        tokio::select! {
            biased;
            result = &mut rx => {
                drop_guard.disarm();
                return decode_completion(
                    operation,
                    loop_handle,
                    result,
                    decode,
                    decode_error,
                ).await;
            }
            _ = call.cancel.cancelled() => {
                if let Err(error) = request_task_cancel(&lifecycle, loop_handle) {
                    // The task may have settled between cancellation winning
                    // the select and the loop-state check above. Preserve that
                    // single completed value even if the loop closed in the
                    // same interleave.
                    let completion = ready_completion_or(&mut rx, error)?;
                    drop_guard.disarm();
                    return decode_completion(
                        operation,
                        loop_handle,
                        Ok(completion),
                        decode,
                        decode_error,
                    ).await;
                }
                let result = wait_after_cancel(&mut rx, loop_handle, LoopRole::Captured).await;
                if result.is_ok() {
                    drop_guard.disarm();
                }
                return match result {
                    Ok(completion) => decode_completion(
                        operation,
                        loop_handle,
                        Ok(completion),
                        decode,
                        decode_error,
                    ).await,
                    Err(error) => Err(error),
                };
            }
            _ = liveness.tick() => {
                poll_loop_runnable(loop_handle, LoopRole::Captured, admission)?;
            }
        }
    }
}

/// Invoke an iterator's optional `aclose` through the retained-task scheduler.
/// Cleanup has its own bounded token because the operation token is commonly
/// cancelled before teardown starts.
pub(super) async fn close_async_iterator_best_effort(
    task_locals: &TaskLocals,
    loop_handle: &Py<PyAny>,
    iterator: &Py<PyAny>,
    operation: &'static str,
) {
    if poll_loop_runnable(
        loop_handle,
        LoopRole::Captured,
        crate::bridge_gil::Admission::Cleanup,
    )
    .is_err()
    {
        return;
    }

    let admitted = crate::bridge_gil::with_bridge_gil_cleanup(|py| {
        Ok((|| {
            let callable = iterator.bind(py).getattr("aclose").ok()?;
            if !callable.is_callable() {
                return None;
            }
            let cleanup_cancel = ovs::CancellationToken::new();
            let call = MarshalledCall {
                args: PyTuple::empty_bound(py).unbind(),
                kwargs: PyDict::new_bound(py).unbind(),
                cancel: cleanup_cancel.clone(),
            };
            Some((callable.unbind(), call, cleanup_cancel))
        })())
    });
    let Some((callable, call, cleanup_cancel)) = admitted.ok().flatten() else {
        return;
    };

    let close = dispatch_callable_with_context(
        task_locals,
        loop_handle,
        operation,
        crate::bridge_gil::Admission::Cleanup,
        AwaitableRequirement::Awaitable,
        &callable,
        call,
        |_, _| Ok(()),
        |py, error| Err(p2r_marshal::override_failure(py, error)),
    );
    tokio::pin!(close);

    tokio::select! {
        biased;
        _ = &mut close => {}
        _ = tokio::time::sleep(PY_POST_CANCEL_TIMEOUT) => {
            cleanup_cancel.cancel();
            let _ = close.await;
        }
    }
}

fn declared_root_info(root: ovs::Url, overrides: &OverrideMap) -> ovs::RootInfo {
    let has = |slot| overrides.contains_key(&slot);
    let mut capabilities = ovs::Capabilities::empty();
    capabilities.supports_write = has(OverrideSlot::Write);
    capabilities.supports_write_stream = has(OverrideSlot::WriteStream);
    capabilities.supports_if_match_write =
        capabilities.supports_write || capabilities.supports_write_stream;
    capabilities.supports_no_overwrite_write =
        capabilities.supports_write || capabilities.supports_write_stream;
    capabilities.supports_delete = has(OverrideSlot::Delete);
    capabilities.supports_server_side_copy = has(OverrideSlot::Copy);
    capabilities.supports_server_side_rename = has(OverrideSlot::Rename);
    capabilities.supports_copy = has(OverrideSlot::Copy);
    capabilities.supports_rename = has(OverrideSlot::Rename);
    capabilities.supports_native_metadata_patch = has(OverrideSlot::UpdateMetadata);
    capabilities.supports_access_check = has(OverrideSlot::CheckAccess);
    capabilities.supports_list = has(OverrideSlot::List);
    capabilities.supports_recursive_list = has(OverrideSlot::List);
    capabilities.supports_version_listing = has(OverrideSlot::ListVersions);
    capabilities.supports_create_directory = has(OverrideSlot::CreateDirectory);
    capabilities.supports_delete_directory = has(OverrideSlot::DeleteDirectory);
    capabilities.supports_watch_directory = has(OverrideSlot::WatchDirectory);

    let range_read_strategy = if has(OverrideSlot::Read) {
        ovs::RangeReadStrategy::Native
    } else if has(OverrideSlot::Materialize) {
        ovs::RangeReadStrategy::MaterializeOnly
    } else {
        ovs::RangeReadStrategy::Unsupported
    };
    ovs::RootInfo {
        root,
        display_name: None,
        layer_kind: PYTHON_BACKEND_KIND.to_owned(),
        connection_id: None,
        owning_target: None,
        capabilities,
        range_read_strategy,
        source: ovs::RouteSource::Static {
            layer: ovs::ConfigLayer::Programmatic,
        },
        visible: true,
        visibility: ovs::AddressVisibility::Visible,
        alias_state: None,
        icon: None,
        user_metadata: ovs::UserMetadata::new(),
    }
}

/// The adapter is transparent for every slot which is not eligible for Python
/// dispatch.  In particular, connection lifecycle and redirect protocol calls
/// remain entirely native: Python never sees their requests or their streams.
///
/// `inner_layer` deliberately supplies the trait's standard delegation for
/// the seven async native-only slots (`write_redirect`, `continue_write`, the
/// three connection updates/authentication, and add/remove connection).  That
/// gives a backend-position adapter the trait's typed `Unsupported` default,
/// while a wrapper-position adapter forwards the exact request and cancellation
/// token to its native inner layer.
#[async_trait::async_trait]
impl ovs::Layer for PyLayerAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> ovs::LayerKindDescriptor {
        ovs::LayerKindDescriptor {
            kind: match self.layer_type {
                ovs::LayerType::Backend => PYTHON_BACKEND_KIND,
                ovs::LayerType::Wrapper => PYTHON_WRAPPER_KIND,
                ovs::LayerType::Router => unreachable!("Python routers are not supported"),
            }
            .to_owned(),
            layer_type: self.layer_type,
            display_name: self.name.clone(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            // Connection ownership and every lifecycle operation are native
            // delegation only, so this adapter never advertises itself as an
            // independent connection target.
            accepts_connections: false,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    fn inner_layer(&self) -> Option<&ovs::LayerHandle> {
        self.inner.as_ref()
    }

    async fn list_connections(
        &self,
        cx: &ovs::Extensions,
        cancel: Option<ovs::CancellationToken>,
    ) -> Result<(ovs::ConnectionSnapshot, Option<ovs::ConnectionUpdateStream>), ovs::Error> {
        // Forced-native disposition: this slot never dispatches into Python
        // and never acquires the GIL. Do not destructure and rebuild this
        // tuple: the optional stream is producer-owned by the native layer
        // and must cross a Python wrapper unchanged.
        match &self.inner {
            Some(inner) => inner.list_connections(cx, cancel).await,
            None => Ok((
                ovs::ConnectionSnapshot {
                    connections: Vec::new(),
                    updates: false,
                },
                None,
            )),
        }
    }

    async fn list_address_roots(
        &self,
        cx: &ovs::Extensions,
        cancel: Option<ovs::CancellationToken>,
    ) -> Result<(ovs::RootInfoSnapshot, Option<ovs::RootInfoUpdateStream>), ovs::Error> {
        // Forced-native disposition: no Python call and no GIL on this path.
        match &self.inner {
            // Preserve the native producer and its update stream as one
            // tuple. The adapter neither refreshes roots nor creates a
            // Python-owned stream.
            Some(inner) => inner.list_address_roots(cx, cancel).await,
            // Leaf Python backends publish only the declaration-time root
            // snapshot. `new` captures it once, and construction rejects
            // roots on wrappers, making this position unambiguous.
            None => Ok((self.declared_roots.clone(), None)),
        }
    }

    async fn root_info_for(
        &self,
        url: &ovs::Url,
        cx: &ovs::Extensions,
        cancel: Option<ovs::CancellationToken>,
    ) -> Result<ovs::RootInfo, ovs::Error> {
        // Forced-native disposition: no Python call and no GIL on this path.
        if let Some(inner) = &self.inner {
            return inner.root_info_for(url, cx, cancel).await;
        }
        self.declared_roots
            .roots
            .iter()
            .filter(|root| ovs::address::is_ancestor_or_self(&root.root, url))
            .max_by_key(|root| ovs::address::node_rank(&root.root))
            .cloned()
            .ok_or_else(|| {
                ovs::Error::new(
                    ovs::ErrorCode::NoRoute,
                    "no declared Python address root matches address",
                )
            })
    }

    async fn stat(
        &self,
        request: ovs::Request<ovs::StatRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::ObjectInfo> {
        if !self.is_overridden(OverrideSlot::Stat) {
            return match &self.inner {
                Some(inner) => inner.stat(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "stat is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::stat(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Stat, call, move |_py, value| {
            p2r_marshal::result_stat(&value, &address)
        })
        .await
    }

    async fn read(
        &self,
        request: ovs::Request<ovs::ReadRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::ReadResult> {
        if !self.is_overridden(OverrideSlot::Read) {
            return match &self.inner {
                Some(inner) => inner.read(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "read is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        let cancel = cancel.unwrap_or_default();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::read(py, request, cancel.clone())
        })?;
        let result = self
            .dispatch(OverrideSlot::Read, call, move |_py, value| {
                decode_read_result(&value, &address)
            })
            .await?;
        match result {
            DecodedReadResult::Buffered(result) => Ok(result),
            DecodedReadResult::Stream { iterator, info } => Ok(ovs::ReadResult::Stream {
                stream: p2r_stream::read_stream(
                    self.task_locals.clone(),
                    self.loop_handle.clone(),
                    iterator,
                    cancel,
                ),
                info,
            }),
        }
    }

    async fn write(
        &self,
        request: ovs::Request<ovs::WriteRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::WriteResult> {
        if !self.is_overridden(OverrideSlot::Write) {
            return match &self.inner {
                Some(inner) => inner.write(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "write is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        // `p2r_marshal::write` accepts Bytes only. In particular, it rejects
        // Stream and LocalFile with Unsupported rather than collecting an
        // unbounded body just to satisfy a bytes-only Python override.
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::write(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Write, call, move |_py, value| {
            p2r_marshal::result_write(&value, &address)
        })
        .await
    }

    async fn write_stream(
        &self,
        request: ovs::Request<ovs::WriteRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::WriteResult> {
        if !self.is_overridden(OverrideSlot::WriteStream) {
            return match &self.inner {
                Some(inner) => inner.write_stream(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "write_stream is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        // The marshaler turns every Body variant into the declaration-form
        // stream signature. Stream and LocalFile use AsyncBodyInput, whose
        // bounded producer observes this same cancellation token.
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::write_stream(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::WriteStream, call, move |_py, value| {
            p2r_marshal::result_write_stream(&value, &address)
        })
        .await
    }

    async fn delete(
        &self,
        request: ovs::Request<ovs::DeleteRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<()> {
        if !self.is_overridden(OverrideSlot::Delete) {
            return match &self.inner {
                Some(inner) => inner.delete(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "delete is unsupported",
                )),
            };
        }
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::delete(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Delete, call, move |_py, value| {
            p2r_marshal::result_delete(&value)
        })
        .await
    }

    async fn copy(
        &self,
        request: ovs::Request<ovs::CopyRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::WriteStep> {
        if !self.is_overridden(OverrideSlot::Copy) {
            return match &self.inner {
                Some(inner) => inner.copy(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "copy is unsupported",
                )),
            };
        }
        let destination = request.input.destination.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::copy(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Copy, call, move |_py, value| {
            p2r_marshal::result_copy(&value, &destination)
        })
        .await
    }

    async fn rename(
        &self,
        request: ovs::Request<ovs::RenameRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<()> {
        if !self.is_overridden(OverrideSlot::Rename) {
            return match &self.inner {
                Some(inner) => inner.rename(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "rename is unsupported",
                )),
            };
        }
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::rename(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Rename, call, move |_py, value| {
            p2r_marshal::result_rename(&value)
        })
        .await
    }

    async fn update_metadata(
        &self,
        request: ovs::Request<ovs::UpdateMetadataRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::BackendItemInfo> {
        if !self.is_overridden(OverrideSlot::UpdateMetadata) {
            return match &self.inner {
                Some(inner) => inner.update_metadata(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "update_metadata is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::update_metadata(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::UpdateMetadata, call, move |_py, value| {
            p2r_marshal::result_update_metadata(&value, &address)
        })
        .await
    }

    async fn check_access(
        &self,
        request: ovs::Request<ovs::CheckAccessRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::AccessDecision> {
        if !self.is_overridden(OverrideSlot::CheckAccess) {
            return match &self.inner {
                Some(inner) => inner.check_access(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "check_access is unsupported",
                )),
            };
        }
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::check_access(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::CheckAccess, call, move |_py, value| {
            p2r_marshal::result_check_access(&value)
        })
        .await
    }

    async fn materialize(
        &self,
        request: ovs::Request<ovs::ReadRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::LocalDelegate> {
        if !self.is_overridden(OverrideSlot::Materialize) {
            return match &self.inner {
                Some(inner) => inner.materialize(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "materialize is unsupported",
                )),
            };
        }
        let expected_address = request.input.address.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::materialize(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Materialize, call, move |_py, value| {
            p2r_marshal::result_materialize(&value, &expected_address)
        })
        .await
    }

    async fn list(
        &self,
        request: ovs::Request<ovs::ListRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::ListPage> {
        if !self.is_overridden(OverrideSlot::List) {
            return match &self.inner {
                Some(inner) => inner.list(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "list is unsupported",
                )),
            };
        }
        let request_prefix = request.input.prefix.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::list(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::List, call, move |_py, value| {
            p2r_marshal::result_list(&value, &request_prefix)
        })
        .await
    }

    async fn list_versions(
        &self,
        request: ovs::Request<ovs::ListVersionsRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::VersionPage> {
        if !self.is_overridden(OverrideSlot::ListVersions) {
            return match &self.inner {
                Some(inner) => inner.list_versions(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "list_versions is unsupported",
                )),
            };
        }
        let request_address = request.input.address.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::list_versions(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::ListVersions, call, move |_py, value| {
            p2r_marshal::result_list_versions(&value, &request_address)
        })
        .await
    }

    async fn get_latest_version(
        &self,
        request: ovs::Request<ovs::ReadRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::ObjectInfo> {
        if !self.is_overridden(OverrideSlot::GetLatestVersion) {
            return match &self.inner {
                Some(inner) => inner.get_latest_version(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "get_latest_version is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::get_latest_version(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::GetLatestVersion, call, move |_py, value| {
            p2r_marshal::result_get_latest_version(&value, &address)
        })
        .await
    }

    async fn create_directory(
        &self,
        request: ovs::Request<ovs::CreateDirectoryRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::BackendItemInfo> {
        if !self.is_overridden(OverrideSlot::CreateDirectory) {
            return match &self.inner {
                Some(inner) => inner.create_directory(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "create_directory is unsupported",
                )),
            };
        }
        let address = request.input.address.clone();
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::create_directory(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::CreateDirectory, call, move |_py, value| {
            p2r_marshal::result_create_directory(&value, &address)
        })
        .await
    }

    async fn delete_directory(
        &self,
        request: ovs::Request<ovs::DeleteDirectoryRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<()> {
        if !self.is_overridden(OverrideSlot::DeleteDirectory) {
            return match &self.inner {
                Some(inner) => inner.delete_directory(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "delete_directory is unsupported",
                )),
            };
        }
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::delete_directory(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::DeleteDirectory, call, move |_py, value| {
            p2r_marshal::result_delete_directory(&value)
        })
        .await
    }

    async fn watch_directory(
        &self,
        request: ovs::Request<ovs::WatchDirectoryRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::ChangeStream> {
        if !self.is_overridden(OverrideSlot::WatchDirectory) {
            return match &self.inner {
                // `ChangeStream` is deliberately a blocking iterator. Keep the
                // wrapper path lazy by forwarding the complete native stream;
                // callers already drain it away from async executor workers.
                Some(inner) => inner.watch_directory(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "watch_directory is unsupported",
                )),
            };
        }

        let cancel = cancel.unwrap_or_default();
        let prefix = request.input.prefix.clone();
        let recursive = request.input.options.recursive;
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::watch_directory(py, request, cancel.clone())
        })?;
        let iterator = self
            .dispatch(OverrideSlot::WatchDirectory, call, |_, value| {
                p2r_stream::async_iterator(&value)
            })
            .await?;
        Ok(p2r_stream::change_stream(
            self.task_locals.clone(),
            self.loop_handle.clone(),
            iterator,
            cancel,
            prefix,
            recursive,
        ))
    }

    async fn probe(
        &self,
        request: ovs::Request<ovs::LayerConnectionRequest>,
        cancel: Option<ovs::CancellationToken>,
    ) -> ovs::Result<ovs::Connection> {
        if !self.is_overridden(OverrideSlot::Probe) {
            return match &self.inner {
                Some(inner) => inner.probe(request, cancel).await,
                None => Err(ovs::Error::new(
                    ovs::ErrorCode::Unsupported,
                    "probe is unsupported",
                )),
            };
        }
        let call = crate::bridge_gil::with_bridge_gil(|py| {
            p2r_marshal::probe(py, request, cancel.unwrap_or_default())
        })?;
        self.dispatch(OverrideSlot::Probe, call, move |_py, value| {
            p2r_marshal::result_probe(&value)
        })
        .await
    }
}

enum DecodedReadResult {
    Buffered(ovs::ReadResult),
    Stream {
        iterator: Py<PyAny>,
        info: ovs::ObjectInfo,
    },
}

/// Classify Python reads before buffered decoding. `__aiter__` is the sole
/// runtime discriminator and deliberately wins before bytes/tuple inspection.
fn decode_read_result(
    value: &Bound<'_, PyAny>,
    expected_address: &ovs::Url,
) -> ovs::Result<DecodedReadResult> {
    let is_stream = value.hasattr("__aiter__").map_err(|error| {
        ovs::Error::new(
            ovs::ErrorCode::IncompatibleType,
            format!("Python read result could not inspect `__aiter__`: {error}"),
        )
    })?;
    if is_stream {
        let info = if value.hasattr("info").map_err(|error| {
            ovs::Error::new(
                ovs::ErrorCode::IncompatibleType,
                format!("Python read stream could not inspect optional `info`: {error}"),
            )
        })? {
            // `Info` uses the same ObjectInfo projection for stat and read.
            // Reuse its checked decoder so a stream cannot report metadata for
            // a different canonical request address.
            p2r_marshal::result_stat(
                &value.getattr("info").map_err(|error| {
                    ovs::Error::new(
                        ovs::ErrorCode::IncompatibleType,
                        format!("Python read stream could not access `info`: {error}"),
                    )
                })?,
                expected_address,
            )?
        } else {
            conservative_read_stream_info(expected_address.clone())
        };
        // Validate metadata before invoking `__aiter__`. A rejected result has
        // not created an iterator and therefore has nothing asynchronous to
        // close on this synchronous decode path.
        let iterator = p2r_stream::read_async_iterator(value)?;
        return Ok(DecodedReadResult::Stream { iterator, info });
    }
    p2r_marshal::result_read(value, expected_address).map(DecodedReadResult::Buffered)
}

fn conservative_read_stream_info(address: ovs::Url) -> ovs::ObjectInfo {
    ovs::ObjectInfo {
        address,
        kind: ovs::ObjectKind::File,
        size: None,
        etag: None,
        version: None,
        checksums: ovs::ChecksumSet::default(),
        effective_permissions: None,
        mtime: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn close_unscheduled_coroutine(coroutine: &Bound<'_, PyAny>) {
    let _ = coroutine.call_method0("close");
}

fn retire_rejected_locally(awaitable: &Bound<'_, PyAny>, prescheduled: bool) {
    if prescheduled {
        let _ = awaitable.call_method0("cancel");
    } else {
        close_unscheduled_coroutine(awaitable);
    }
}

/// Which loop a liveness failure should blame in user-facing diagnostics: the
/// bridge's captured loop, or the owner loop of a rejected foreign future.
#[derive(Clone, Copy)]
enum LoopRole {
    Captured,
    Owner,
}

impl LoopRole {
    fn describe(self) -> &'static str {
        match self {
            LoopRole::Captured => "captured Python event loop",
            LoopRole::Owner => "rejected awaitable's owner event loop",
        }
    }
}

fn require_loop_runnable(loop_handle: &Bound<'_, PyAny>, role: LoopRole) -> Result<(), ovs::Error> {
    let is_closed: bool = loop_handle
        .call_method0("is_closed")
        .and_then(|value| value.extract())
        .map_err(|error| bridge_error("could not query loop.is_closed()", error))?;
    if is_closed {
        return Err(ovs::Error::new(
            ovs::ErrorCode::NotConfigured,
            format!("{} is closed", role.describe()),
        ));
    }
    let is_running: bool = loop_handle
        .call_method0("is_running")
        .and_then(|value| value.extract())
        .map_err(|error| bridge_error("could not query loop.is_running()", error))?;
    if !is_running {
        return Err(ovs::Error::new(
            ovs::ErrorCode::NotConfigured,
            format!("{} is not running", role.describe()),
        ));
    }
    Ok(())
}

fn loop_schedule_failure(
    loop_handle: &Bound<'_, PyAny>,
    error: PyErr,
    role: LoopRole,
) -> ovs::Error {
    require_loop_runnable(loop_handle, role)
        .err()
        .unwrap_or_else(|| bridge_error("could not schedule override", error))
}

fn poll_loop_runnable(
    loop_handle: &Py<PyAny>,
    role: LoopRole,
    admission: crate::bridge_gil::Admission,
) -> Result<(), ovs::Error> {
    crate::bridge_gil::with_bridge_gil_as(admission, |py| {
        require_loop_runnable(loop_handle.bind(py), role)
    })
}

fn liveness_interval() -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(
        Instant::now() + PY_LOOP_LIVENESS_POLL_INTERVAL,
        PY_LOOP_LIVENESS_POLL_INTERVAL,
    );
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

async fn wait_after_cancel(
    rx: &mut oneshot::Receiver<PyResult<PyObject>>,
    loop_handle: &Py<PyAny>,
    role: LoopRole,
) -> Result<PyResult<PyObject>, ovs::Error> {
    let deadline = Instant::now() + PY_POST_CANCEL_TIMEOUT;
    let mut liveness = liveness_interval();
    loop {
        tokio::select! {
            biased;
            result = &mut *rx => {
                return result.map_err(|_| completion_channel_error(loop_handle, role));
            }
            _ = liveness.tick() => {
                poll_loop_runnable(loop_handle, role, crate::bridge_gil::Admission::Cleanup)?;
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(ovs::Error::new(
                    ovs::ErrorCode::DeadlineExceeded,
                    "Python task did not settle within the post-cancel deadline",
                ));
            }
        }
    }
}

fn ready_completion_or(
    rx: &mut oneshot::Receiver<PyResult<PyObject>>,
    fallback: ovs::Error,
) -> Result<PyResult<PyObject>, ovs::Error> {
    rx.try_recv().map_err(|_| fallback)
}

async fn decode_completion<T, Decode, DecodeError>(
    operation: &str,
    loop_handle: &Py<PyAny>,
    completion: Result<PyResult<PyObject>, oneshot::error::RecvError>,
    decode: Decode,
    decode_error: DecodeError,
) -> Result<T, ovs::Error>
where
    Decode: for<'py> FnOnce(Python<'py>, Bound<'py, PyAny>) -> Result<T, ovs::Error> + Send,
    DecodeError: for<'py> FnOnce(Python<'py>, PyErr) -> Result<T, ovs::Error> + Send,
{
    let completion =
        completion.map_err(|_| completion_channel_error(loop_handle, LoopRole::Captured))?;
    match completion {
        Ok(value) => {
            let is_awaitable = crate::bridge_gil::with_bridge_gil_as(
                crate::bridge_gil::Admission::Cleanup,
                |py| {
                    py.import_bound("inspect")
                        .and_then(|inspect| inspect.call_method1("isawaitable", (value.bind(py),)))
                        .and_then(|result| result.extract::<bool>())
                        .map_err(|error| {
                            bridge_error("could not classify completed override result", error)
                        })
                },
            )?;
            if is_awaitable {
                let retired = retire_rejected_awaitable(value).await?;
                return Err(nested_awaitable_error(operation, retired));
            }
            crate::bridge_gil::with_bridge_gil_as(crate::bridge_gil::Admission::Cleanup, |py| {
                decode(py, value.into_bound(py))
            })
        }
        Err(error) => {
            crate::bridge_gil::with_bridge_gil_as(crate::bridge_gil::Admission::Cleanup, |py| {
                if is_cancelled_error(py, &error) {
                    Err(ovs::Error::new(
                        ovs::ErrorCode::Cancelled,
                        format!("Python `{operation}` override was cancelled"),
                    ))
                } else {
                    decode_error(py, error)
                }
            })
        }
    }
}

/// Word the nested-awaitable protocol error for what retirement found.
///
/// The error code stays [`ovs::ErrorCode::IncompatibleType`] on both arms — the
/// category really is "you returned the wrong type", and callers must not
/// switch on message text. Only the advice differs, and it differs only in what
/// each arm can honestly say about the rejected object: neither licenses a
/// retry, because neither knows what the override started before returning.
fn nested_awaitable_error(operation: &str, retired: RetiredAwaitable) -> ovs::Error {
    let detail = match retired {
        RetiredAwaitable::ClosedLocally => {
            "did you forget `await`? The returned coroutine was discarded \
             rather than awaited. Discarding it does not run it to completion, \
             and undoes nothing it or the override may already have done."
        }
        RetiredAwaitable::DiscardedUnscheduled => {
            "did you forget `await`? The returned awaitable is not a Future or \
             Task, so retirement had no owner loop to reach it through: it \
             scheduled nothing and called neither `__await__` nor `close()` on \
             it, and released it instead. Releasing it can still run the \
             value's own finalization, the override may have driven it before \
             returning it, and nothing here cancels work behind it."
        }
        RetiredAwaitable::RetiredViaLoop => {
            "did you forget `await`? The returned awaitable is owned by an \
             event loop, so retirement tried to cancel it there; whether that \
             was delivered depends on the loop still running. Cancellation \
             cannot undo work already performed, so the underlying operation \
             may already have completed: do not assume it did not happen."
        }
    };
    ovs::Error::new(
        ovs::ErrorCode::IncompatibleType,
        format!("Python `{operation}` override returned a nested awaitable; {detail}"),
    )
}

/// How retirement disposed of the rejected object.
///
/// These name the *mechanism* deliberately. Earlier revisions named the
/// conclusion — "never started" / "already started" — and both were wrong,
/// because the classification cannot reach either conclusion: it is
/// `inspect.iscoroutine` and `asyncio.isfuture` on the returned value, which
/// report what kind of object it is and who owns it, not whether any work
/// exists behind it or has run.
///
/// Two measured counter-examples, either of which falsifies a
/// conclusion-shaped claim:
///
/// - a bare `loop.create_future()` is a Future with no work behind it, yet is
///   indistinguishable here from a live Task;
/// - `iscoroutine` is true of a coroutine already driven past its first
///   suspension, whose body has therefore run, and closing such a coroutine
///   additionally runs its `finally` blocks.
///
/// So neither variant licenses a statement about whether the operation ran, and
/// neither implies the call is safe to retry. Word each arm for what retirement
/// *did*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetiredAwaitable {
    /// The value was a coroutine object, so retirement discarded it in place,
    /// closing it where that was permitted — cleanup admission can refuse
    /// during finalization, and `close()` itself can raise.
    ClosedLocally,
    /// The value was neither a coroutine object nor an asyncio Future, so
    /// retirement had no owner loop to reach it through. It created no task for
    /// it and called neither `__await__` nor `close()` on it; it released its
    /// reference and nothing more.
    ///
    /// Two things that does not say. **Releasing the reference is not inert:**
    /// if it was the last one, CPython finalizes the object, and a
    /// `@types.coroutine` generator the override already stepped runs its
    /// `finally` blocks when it is collected. That is the value's own
    /// finalization, not a call retirement made, and it would happen to any
    /// dropped reference — but it is not "nothing ran". **And the value may
    /// still front live work:** an awaitable delegating to a running Task is
    /// `isawaitable` while being neither `iscoroutine` nor `isfuture`, so it
    /// arrives here, and nothing on this arm cancels what is behind it.
    DiscardedUnscheduled,
    /// The value was reached through an owner loop, so retirement went that
    /// way. Cancellation is *attempted*, not guaranteed: the pre-schedule
    /// runnability check returns on this arm before any cancel is requested,
    /// and settlement is bounded.
    RetiredViaLoop,
}

/// Retire an awaitable rejected by the operation protocol.
///
/// Only a Future or Task is owned by a loop, and only that arm is cancelled and
/// observed there — through `call_soon_threadsafe`, so the cancel runs on the
/// owner's thread rather than this Tokio worker. The direct `cancel()` on the
/// enqueue-failure path is the exception, and it is reached only once that
/// enqueue has already been refused.
///
/// A coroutine object and any other awaitable belong to no loop, so both are
/// discarded where they are, unscheduled.
async fn retire_rejected_awaitable(awaitable: Py<PyAny>) -> Result<RetiredAwaitable, ovs::Error> {
    let (is_coroutine, owner_loop) = crate::bridge_gil::with_bridge_gil_cleanup(
        |py| -> Result<(bool, Option<Py<PyAny>>), ovs::Error> {
            let inspect = py
                .import_bound("inspect")
                .map_err(|error| bridge_error("could not import inspect", error))?;
            let is_coroutine = inspect
                .call_method1("iscoroutine", (awaitable.bind(py),))
                .and_then(|result| result.extract::<bool>())
                .map_err(|error| bridge_error("could not classify rejected awaitable", error))?;
            if is_coroutine {
                return Ok((true, None));
            }

            let asyncio = py
                .import_bound("asyncio")
                .map_err(|error| bridge_error("could not import asyncio", error))?;
            let is_future = asyncio
                .call_method1("isfuture", (awaitable.bind(py),))
                .and_then(|result| result.extract::<bool>())
                .map_err(|error| bridge_error("could not classify rejected Future", error))?;
            let owner_loop = if is_future {
                let bound = awaitable.bind(py);
                let owner = match bound.call_method0("get_loop") {
                    Ok(owner) => owner,
                    Err(error)
                        if error.is_instance_of::<pyo3::exceptions::PyAttributeError>(py) =>
                    {
                        bound.getattr("_loop").map_err(|error| {
                            bridge_error("could not query Future owner loop", error)
                        })?
                    }
                    Err(error) => {
                        return Err(bridge_error("could not query Future.get_loop()", error));
                    }
                };
                Some(owner.unbind())
            } else {
                None
            };
            Ok((false, owner_loop))
        },
    )?;
    if is_coroutine {
        let _ = crate::bridge_gil::with_bridge_gil_cleanup(|py| {
            close_unscheduled_coroutine(awaitable.bind(py));
            Ok(())
        });
        return Ok(RetiredAwaitable::ClosedLocally);
    }

    let Some(retirement_loop) = owner_loop else {
        // A custom `__await__` object belongs to no loop, so there is no task
        // to attach to and nothing scheduled to cancel. Wrapping it with
        // `asyncio.ensure_future` would create a task retirement owns rather
        // than one the override started, and creating that task is the only
        // way retirement could enter the value: under the default task factory
        // the cancel lands before the wrapper's first step, and under
        // `asyncio.eager_task_factory` `create_task` steps the wrapper
        // synchronously and the value's body runs.
        //
        // Nor is any method called on it. `close()` is meaningful on a
        // coroutine object, which the arm above handles; on an arbitrary
        // object it is whatever the author made it — a session teardown, a
        // blocking wait, an `async def` returning a coroutine nobody awaits —
        // and any such call would be made holding the GIL on a Tokio worker,
        // with no bound to offer it. Releasing the reference still lets
        // CPython finalize the value, which is the disposal every dropped
        // reference gets; what it does not do is choose a method to call.
        drop(awaitable);
        return Ok(RetiredAwaitable::DiscardedUnscheduled);
    };
    let role = LoopRole::Owner;
    if crate::bridge_gil::with_bridge_gil_cleanup(|py| {
        require_loop_runnable(retirement_loop.bind(py), role)
    })
    .is_err()
    {
        return Ok(RetiredAwaitable::RetiredViaLoop);
    }

    let (tx, mut rx) = oneshot::channel();
    let lifecycle = Arc::new(DispatchLifecycle::new(tx));
    lifecycle.cancel_requested.store(true, Ordering::Release);
    let schedule_result = crate::bridge_gil::with_bridge_gil_cleanup(|py| {
        let retirement_loop = retirement_loop.bind(py);
        require_loop_runnable(retirement_loop, role)?;
        let close_on_failure = awaitable.clone_ref(py);
        let start_helper = Py::new(
            py,
            PyBridgeStart {
                coroutine: Some(awaitable),
                loop_handle: retirement_loop.clone().unbind(),
                lifecycle: lifecycle.clone(),
                prescheduled: true,
            },
        )
        .map_err(|error| bridge_error("could not allocate rejected-awaitable callback", error))?;

        increment_bridge_task_count();
        lifecycle.counted.store(true, Ordering::Release);
        if let Err(error) = retirement_loop.call_method1("call_soon_threadsafe", (start_helper,)) {
            retire_rejected_locally(close_on_failure.bind(py), true);
            lifecycle.abandon();
            return Err(loop_schedule_failure(retirement_loop, error, role));
        }
        Ok(())
    });
    if schedule_result.is_err() {
        return Ok(RetiredAwaitable::RetiredViaLoop);
    }

    let mut drop_guard = DispatchDropGuard::new(lifecycle, retirement_loop.clone());
    let completion = wait_after_cancel(&mut rx, &retirement_loop, role).await;
    if completion.is_ok() {
        drop_guard.disarm();
    }
    match completion {
        Ok(_) => Ok(RetiredAwaitable::RetiredViaLoop),
        Err(error) if error.code() == ovs::ErrorCode::NotConfigured => {
            // Retirement is best-effort once ownership belongs to another loop.
            // Preserve the actionable nested-awaitable protocol error when that
            // owner loop stops while cancellation is settling.
            Ok(RetiredAwaitable::RetiredViaLoop)
        }
        Err(error) => Err(error),
    }
}

fn completion_channel_error(loop_handle: &Py<PyAny>, role: LoopRole) -> ovs::Error {
    // Diagnosing a channel that already closed is retirement: the dispatch it
    // belonged to is over either way, and refusing the probe would replace a
    // specific loop-state error with a generic one.
    poll_loop_runnable(loop_handle, role, crate::bridge_gil::Admission::Cleanup)
        .err()
        .unwrap_or_else(|| {
            bridge_error(
                "completion channel closed before the done callback",
                format!(
                    "sender dropped while the {} remained runnable",
                    role.describe()
                ),
            )
        })
}

fn is_cancelled_error(py: Python<'_>, error: &PyErr) -> bool {
    py.import_bound("asyncio")
        .and_then(|asyncio| asyncio.getattr("CancelledError"))
        .is_ok_and(|cancelled| error.matches(py, cancelled))
}

fn request_task_cancel(
    lifecycle: &Arc<DispatchLifecycle>,
    loop_handle: &Py<PyAny>,
) -> Result<(), ovs::Error> {
    lifecycle.cancel_requested.store(true, Ordering::Release);
    crate::bridge_gil::with_bridge_gil_cleanup(|py| {
        let loop_handle = loop_handle.bind(py);
        let is_closed: bool = loop_handle
            .call_method0("is_closed")
            .and_then(|value| value.extract())
            .map_err(|error| bridge_error("could not query loop.is_closed()", error))?;
        if is_closed {
            lifecycle.abandon();
            return Err(ovs::Error::new(
                ovs::ErrorCode::NotConfigured,
                "captured Python event loop is closed",
            ));
        }
        let is_running: bool = loop_handle
            .call_method0("is_running")
            .and_then(|value| value.extract())
            .map_err(|error| bridge_error("could not query loop.is_running()", error))?;
        let task = lifecycle
            .task
            .lock()
            .expect("Python bridge task mutex poisoned")
            .as_ref()
            .map(|task| task.clone_ref(py));
        if let Some(task) = task {
            enqueue_task_cancel(py, loop_handle, task, lifecycle.clone())
                .map_err(|error| loop_schedule_failure(loop_handle, error, LoopRole::Captured))?;
        }
        if !is_running {
            lifecycle.abandon();
            return Err(ovs::Error::new(
                ovs::ErrorCode::NotConfigured,
                "captured Python event loop is not running",
            ));
        }
        Ok(())
    })
}

fn request_task_cancel_best_effort(lifecycle: &Arc<DispatchLifecycle>, loop_handle: &Py<PyAny>) {
    if lifecycle.finished.load(Ordering::Acquire) {
        return;
    }
    lifecycle.cancel_requested.store(true, Ordering::Release);
    // Cancellation is retirement, not new work, so it stays admissible while
    // the fence drains. Refusing it here is what would leave the very tasks
    // this exists to cancel pending at finalization.
    let admitted = crate::bridge_gil::with_bridge_gil_cleanup(|py| {
        let loop_handle = loop_handle.bind(py);
        let Ok(is_closed) = loop_handle
            .call_method0("is_closed")
            .and_then(|value| value.extract::<bool>())
        else {
            lifecycle.abandon();
            return Ok(());
        };
        if is_closed {
            lifecycle.abandon();
            return Ok(());
        }
        let is_running = loop_handle
            .call_method0("is_running")
            .and_then(|value| value.extract::<bool>())
            .unwrap_or(false);
        let task = lifecycle
            .task
            .lock()
            .expect("Python bridge task mutex poisoned")
            .as_ref()
            .map(|task| task.clone_ref(py));
        if let Some(task) = task
            && enqueue_task_cancel(py, loop_handle, task, lifecycle.clone()).is_err()
        {
            lifecycle.abandon();
            return Ok(());
        }
        if !is_running {
            lifecycle.abandon();
        }
        Ok(())
    });
    if admitted.is_err() {
        lifecycle.abandon();
    }
}

fn enqueue_task_cancel(
    py: Python<'_>,
    loop_handle: &Bound<'_, PyAny>,
    task: Py<PyAny>,
    lifecycle: Arc<DispatchLifecycle>,
) -> PyResult<()> {
    let cancel = Py::new(
        py,
        PyBridgeCancel {
            task: Some(task),
            lifecycle: Some(lifecycle),
        },
    )?;
    loop_handle.call_method1("call_soon_threadsafe", (cancel,))?;
    Ok(())
}

struct DispatchLifecycle {
    sender: Mutex<Option<oneshot::Sender<PyResult<PyObject>>>>,
    task: Mutex<Option<Py<PyAny>>>,
    cancel_requested: AtomicBool,
    counted: AtomicBool,
    finished: AtomicBool,
}

impl DispatchLifecycle {
    fn new(sender: oneshot::Sender<PyResult<PyObject>>) -> Self {
        Self {
            sender: Mutex::new(Some(sender)),
            task: Mutex::new(None),
            cancel_requested: AtomicBool::new(false),
            counted: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        }
    }

    /// Complete the one available sender and retire the counted task exactly
    /// once, even if task cancellation and normal completion race.
    fn finish(&self, result: PyResult<PyObject>) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.task
            .lock()
            .expect("Python bridge task mutex poisoned")
            .take();
        if self.counted.swap(false, Ordering::AcqRel) {
            decrement_bridge_task_count();
        }
        if let Some(sender) = self
            .sender
            .lock()
            .expect("Python bridge sender mutex poisoned")
            .take()
        {
            let _ = sender.send(result);
        }
    }

    /// Undo the scheduled-task accounting when scheduling itself fails.
    fn abandon(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.task
            .lock()
            .expect("Python bridge task mutex poisoned")
            .take();
        self.sender
            .lock()
            .expect("Python bridge sender mutex poisoned")
            .take();
        if self.counted.swap(false, Ordering::AcqRel) {
            decrement_bridge_task_count();
        }
    }
}

impl Drop for DispatchLifecycle {
    fn drop(&mut self) {
        // A queued Python callback may be discarded when its loop closes.
        // Retire accounting even when neither finish nor abandon could run;
        // their swaps make this fallback exactly once.
        if self.counted.swap(false, Ordering::AcqRel) {
            decrement_bridge_task_count();
        }
    }
}

#[pyclass]
struct PyBridgeStart {
    coroutine: Option<Py<PyAny>>,
    loop_handle: Py<PyAny>,
    lifecycle: Arc<DispatchLifecycle>,
    /// The awaitable is already an asyncio Future/Task owned by
    /// `loop_handle`; attach to it directly instead of calling ensure_future.
    prescheduled: bool,
}

#[pymethods]
impl PyBridgeStart {
    fn __call__(&mut self, py: Python<'_>) -> PyResult<()> {
        let Some(coroutine) = self.coroutine.take() else {
            return Ok(());
        };
        if self.lifecycle.finished.load(Ordering::Acquire) {
            retire_rejected_locally(coroutine.bind(py), self.prescheduled);
            return Ok(());
        }
        if self.lifecycle.cancel_requested.load(Ordering::Acquire) {
            let is_coroutine = py
                .import_bound("inspect")
                .and_then(|inspect| inspect.call_method1("iscoroutine", (coroutine.bind(py),)))
                .and_then(|result| result.extract::<bool>());
            match is_coroutine {
                Ok(true) => {
                    close_unscheduled_coroutine(coroutine.bind(py));
                    self.lifecycle
                        .finish(Err(pyo3::exceptions::asyncio::CancelledError::new_err(())));
                    return Ok(());
                }
                Ok(false) => {
                    // A Future or other awaitable may already own running work.
                    // Publish it below, then cancel and observe that work.
                }
                Err(error) => {
                    self.lifecycle.finish(Err(error));
                    return Ok(());
                }
            }
        }
        let result = self.start(py, &coroutine);
        if let Err(error) = result {
            retire_rejected_locally(coroutine.bind(py), self.prescheduled);
            self.lifecycle.finish(Err(error));
        }
        Ok(())
    }
}

impl Drop for PyBridgeStart {
    fn drop(&mut self) {
        let Some(coroutine) = self.coroutine.take() else {
            return;
        };
        if !interpreter_is_finalizing() {
            let _ = crate::bridge_gil::with_bridge_gil_cleanup(|py| {
                retire_rejected_locally(coroutine.bind(py), self.prescheduled);
                Ok(())
            });
        }
        self.lifecycle.abandon();
    }
}

impl PyBridgeStart {
    fn start(&self, py: Python<'_>, coroutine: &Py<PyAny>) -> PyResult<()> {
        let task = if self.prescheduled {
            coroutine.bind(py).clone()
        } else {
            let asyncio = py.import_bound("asyncio")?;
            let kwargs = PyDict::new_bound(py);
            kwargs.set_item("loop", self.loop_handle.bind(py))?;
            asyncio.call_method("ensure_future", (coroutine.bind(py),), Some(&kwargs))?
        };
        *self
            .lifecycle
            .task
            .lock()
            .expect("Python bridge task mutex poisoned") = Some(task.clone().unbind());

        let done = Py::new(
            py,
            PyBridgeDone {
                lifecycle: self.lifecycle.clone(),
            },
        )?;
        if let Err(error) = task.call_method1("add_done_callback", (done,)) {
            let _ = task.call_method0("cancel");
            return Err(error);
        }
        if self.lifecycle.cancel_requested.load(Ordering::Acquire) {
            // The helper already runs on the thread of the loop it was
            // scheduled onto; calling Task.cancel directly here closes the
            // publication race without another cross-thread callback.
            task.call_method0("cancel")?;
        }
        Ok(())
    }
}

#[pyclass]
struct PyBridgeDone {
    lifecycle: Arc<DispatchLifecycle>,
}

#[pyclass]
struct PyBridgeCancel {
    task: Option<Py<PyAny>>,
    lifecycle: Option<Arc<DispatchLifecycle>>,
}

#[pymethods]
impl PyBridgeCancel {
    fn __call__(&mut self, py: Python<'_>) -> PyResult<()> {
        let Some(task) = self.task.take() else {
            if let Some(lifecycle) = self.lifecycle.take() {
                lifecycle.abandon();
            }
            return Ok(());
        };
        if let Err(error) = task.bind(py).call_method0("cancel") {
            if let Some(lifecycle) = self.lifecycle.take() {
                lifecycle.abandon();
            }
            return Err(error);
        }
        // The done callback now owns settlement. Dropping a callback before
        // this point instead runs the abandonment path below.
        self.lifecycle.take();
        Ok(())
    }
}

impl Drop for PyBridgeCancel {
    fn drop(&mut self) {
        self.task.take();
        if let Some(lifecycle) = self.lifecycle.take() {
            lifecycle.abandon();
        }
    }
}

#[pymethods]
impl PyBridgeDone {
    fn __call__(&self, task: &Bound<'_, PyAny>) -> PyResult<()> {
        if self.lifecycle.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = task.call_method0("result").map(|value| value.unbind());
        self.lifecycle.finish(result);
        Ok(())
    }
}

struct DispatchDropGuard {
    lifecycle: Arc<DispatchLifecycle>,
    loop_handle: Py<PyAny>,
    armed: bool,
}

impl DispatchDropGuard {
    fn new(lifecycle: Arc<DispatchLifecycle>, loop_handle: Py<PyAny>) -> Self {
        Self {
            lifecycle,
            loop_handle,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DispatchDropGuard {
    fn drop(&mut self) {
        if self.armed {
            // Drop never waits for operation completion. It may briefly block
            // acquiring the GIL to enqueue cancellation on the owning loop.
            request_task_cancel_best_effort(&self.lifecycle, &self.loop_handle);
        }
    }
}

// Like the other Rust unit tests in this crate, these are manual/downstream
// tests because the production extension-module feature cannot link a normal
// in-tree test executable.  They are still kept beside the primitive so a
// consumer using the documented no-extension-module test configuration can
// exercise the exact completion/cancellation races.
#[cfg(test)]
#[cfg(feature = "no-extension-module-link")]
mod tests {
    use std::sync::{Arc, Mutex};

    use futures::StreamExt;
    use ovs::Layer as _;
    use pyo3::types::{PyDict, PyModule, PyTuple};

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const TEST_LAYER: &str = r#"
import asyncio
import threading

loop = asyncio.new_event_loop()
cancel_started = threading.Event()
cancel_finished = threading.Event()

class TestLayer(LayerBase):
    async def stat(self, mode, started=None):
        if mode == "complete":
            return 41
        if mode == "cancel":
            cancel_started.set()
            try:
                await asyncio.Future()
            finally:
                cancel_finished.set()
        if mode == "race":
            started.set()
            await asyncio.sleep(0)
            return 7
        raise AssertionError(mode)
"#;

    struct Harness {
        adapter: Arc<PyLayerAdapter>,
        loop_handle: Py<PyAny>,
        cancel_started: Py<PyAny>,
        cancel_finished: Py<PyAny>,
    }

    impl Harness {
        fn new(runtime: &tokio::runtime::Runtime) -> Self {
            use ovs::BackendFactory as _;

            let mut config = ovs::LayerConfig::new();
            let root = ovs::Url::from_directory_path(std::env::temp_dir()).unwrap();
            config.insert("root".into(), ovs::ConfigValue::String(root.to_string()));
            let native = runtime
                .block_on(ovs::layers::FileBackendFactory.create_backend(
                    "test-native",
                    &config,
                    None,
                ))
                .unwrap();

            let (adapter, loop_handle, cancel_started, cancel_finished) = Python::with_gil(|py| {
                initialize_finalization_guard(py);
                let base = Py::new(py, LayerBase::from_handle(native)).unwrap();
                let module = PyModule::new_bound(py, "p2r_adapter_test").unwrap();
                module
                    .add("LayerBase", py.get_type_bound::<LayerBase>())
                    .unwrap();
                py.run_bound(TEST_LAYER, Some(&module.dict()), None)
                    .unwrap();
                let object = module
                    .getattr("TestLayer")
                    .unwrap()
                    .call1((base,))
                    .unwrap()
                    .unbind();
                let loop_handle = module.getattr("loop").unwrap().unbind();
                let context = py
                    .import_bound("contextvars")
                    .unwrap()
                    .call_method0("copy_context")
                    .unwrap();
                let task_locals =
                    TaskLocals::new(loop_handle.bind(py).clone()).with_context(context);
                let adapter = PyLayerAdapter::new(
                    py,
                    "python-test".into(),
                    ovs::LayerType::Backend,
                    object,
                    None,
                    task_locals,
                    Vec::new(),
                )
                .unwrap();
                assert!(adapter.is_overridden(OverrideSlot::Stat));
                (
                    Arc::new(adapter),
                    loop_handle,
                    module.getattr("cancel_started").unwrap().unbind(),
                    module.getattr("cancel_finished").unwrap().unbind(),
                )
            });

            Self {
                adapter,
                loop_handle,
                cancel_started,
                cancel_finished,
            }
        }

        fn shutdown(self) {
            drop(self.adapter);
            Python::with_gil(|py| {
                self.loop_handle.bind(py).call_method0("close").unwrap();
            });
        }
    }

    /// Run the captured asyncio loop on the test thread while Rust work runs
    /// independently. This mirrors production ownership and avoids ever
    /// blocking the loop thread on a Rust join.
    fn run_while_loop<T: Send + 'static>(
        loop_handle: &Py<PyAny>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let worker_loop = Python::with_gil(|py| loop_handle.clone_ref(py));
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let running = Python::with_gil(|py| {
                    worker_loop
                        .bind(py)
                        .call_method0("is_running")
                        .unwrap()
                        .extract::<bool>()
                        .unwrap()
                });
                if running {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "captured test event loop did not start"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let result = work();
            Python::with_gil(|py| {
                worker_loop
                    .bind(py)
                    .call_method1(
                        "call_soon_threadsafe",
                        (worker_loop.bind(py).getattr("stop").unwrap(),),
                    )
                    .unwrap();
            });
            result
        });
        Python::with_gil(|py| {
            loop_handle.bind(py).call_method0("run_forever").unwrap();
        });
        worker.join().unwrap()
    }

    fn call(
        py: Python<'_>,
        args: impl IntoPy<PyObject>,
        cancel: ovs::CancellationToken,
    ) -> MarshalledCall {
        MarshalledCall {
            args: args.into_py(py).extract::<Py<PyTuple>>(py).unwrap(),
            kwargs: PyDict::new_bound(py).unbind(),
            cancel,
        }
    }

    fn decode_i64(_py: Python<'_>, value: Bound<'_, PyAny>) -> Result<i64, ovs::Error> {
        value
            .extract()
            .map_err(|error| bridge_error("test decoder rejected result", error))
    }

    #[test]
    fn override_detection_rejects_a_non_callable_slot() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            initialize_finalization_guard(py);
            let module = PyModule::from_code_bound(
                py,
                "class BadLayer:\n    list = 17\n",
                "p2r_bad_layer.py",
                "p2r_bad_layer",
            )
            .unwrap();
            let object = module
                .getattr("BadLayer")
                .unwrap()
                .call0()
                .unwrap()
                .unbind();
            let error = detect_overrides(py, &object).unwrap_err();
            assert_eq!(error.code(), ovs::ErrorCode::InvalidArgument);
            assert!(error.to_string().contains("`list` must be callable"));
        });
    }

    #[test]
    fn override_detection_rejects_a_sync_coroutine_factory_without_calling_it() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            initialize_finalization_guard(py);
            let module = PyModule::from_code_bound(
                py,
                "called = False\n\
                 async def result():\n    return b'data'\n\
                 class BadLayer:\n\
                     def read(self, *args, **kwargs):\n\
                         global called\n\
                         called = True\n\
                         return result()\n",
                "p2r_sync_factory.py",
                "p2r_sync_factory",
            )
            .unwrap();
            let object = module
                .getattr("BadLayer")
                .unwrap()
                .call0()
                .unwrap()
                .unbind();
            let error = detect_overrides(py, &object).unwrap_err();
            assert_eq!(error.code(), ovs::ErrorCode::InvalidArgument);
            assert!(error.to_string().contains("`read` must be declared"));
            assert!(!module.getattr("called").unwrap().extract::<bool>().unwrap());
        });
    }

    #[test]
    fn lifecycle_drop_retires_unfinished_task_accounting() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let before = bridge_task_count();
        let (sender, _receiver) = oneshot::channel();
        let lifecycle = DispatchLifecycle::new(sender);
        increment_bridge_task_count();
        lifecycle.counted.store(true, Ordering::Release);

        drop(lifecycle);

        assert_eq!(bridge_task_count(), before);
    }

    #[test]
    fn cancellation_failure_preserves_a_ready_completion() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let (sender, mut receiver) = oneshot::channel();
            sender.send(Ok(17_i64.into_py(py))).unwrap();
            let completion = ready_completion_or(
                &mut receiver,
                ovs::Error::new(ovs::ErrorCode::NotConfigured, "closed loop"),
            )
            .unwrap()
            .unwrap();
            assert_eq!(completion.extract::<i64>(py).unwrap(), 17);
        });
    }

    #[test]
    fn read_decoder_prioritizes_async_iterators_and_keeps_bytes_buffered() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let address = ovs::Url::parse("file:///read-shape").unwrap();
            let bytes = py.eval_bound("b'abc'", None, None).unwrap();
            assert!(matches!(
                decode_read_result(&bytes, &address),
                Ok(DecodedReadResult::Buffered(ovs::ReadResult::Bytes { bytes, info }))
                    if bytes == b"abc" && info.address == address
            ));

            let stream = py
                .eval_bound(
                    "type('Stream', (), {\
                    '__aiter__': lambda self: self, \
                    '__anext__': lambda self: None\
                })()",
                    None,
                    None,
                )
                .unwrap();
            assert!(matches!(
                decode_read_result(&stream, &address),
                Ok(DecodedReadResult::Stream { info, .. })
                    if info.address == address && info.size.is_none()
            ));

            let stream_with_info = py
                .eval_bound(
                    "type('Stream', (), {\
                    '__aiter__': lambda self: self, \
                    '__anext__': lambda self: None, \
                    'info': type('Info', (), {\
                        'address': 'file:///read-shape', \
                        'kind': 'file', \
                        'size': 17, \
                        'mtime_unix_nanos': None, \
                        'etag': 'stream-etag', \
                        'version': None, \
                        'system_metadata': {}, \
                        'user_metadata': {}\
                    })()\
                })()",
                    None,
                    None,
                )
                .unwrap();
            assert!(matches!(
                decode_read_result(&stream_with_info, &address),
                Ok(DecodedReadResult::Stream { info, .. })
                    if info.address == address
                        && info.size == Some(17)
                        && info.etag.as_deref() == Some("stream-etag")
            ));
        });
    }

    struct NativeSnapshotRider;

    #[async_trait::async_trait]
    impl ovs::Layer for NativeSnapshotRider {
        fn name(&self) -> &str {
            "native-rider"
        }

        fn descriptor(&self) -> ovs::LayerKindDescriptor {
            ovs::LayerKindDescriptor {
                kind: "native-rider".into(),
                layer_type: ovs::LayerType::Backend,
                display_name: "native rider".into(),
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                auth_capable: false,
                supports_user_metadata: false,
            }
        }

        async fn list_address_roots(
            &self,
            _cx: &ovs::Extensions,
            _cancel: Option<ovs::CancellationToken>,
        ) -> Result<(ovs::RootInfoSnapshot, Option<ovs::RootInfoUpdateStream>), ovs::Error>
        {
            Ok((
                ovs::RootInfoSnapshot {
                    roots: Vec::new(),
                    updates: true,
                },
                Some(Box::pin(futures::stream::iter(vec![Ok(
                    ovs::RootInfoChange::Added(Vec::new()),
                )]))),
            ))
        }

        async fn list_connections(
            &self,
            _cx: &ovs::Extensions,
            _cancel: Option<ovs::CancellationToken>,
        ) -> Result<(ovs::ConnectionSnapshot, Option<ovs::ConnectionUpdateStream>), ovs::Error>
        {
            Ok((
                ovs::ConnectionSnapshot {
                    connections: Vec::new(),
                    updates: true,
                },
                Some(Box::pin(futures::stream::iter(vec![Ok(
                    ovs::ConnectionChange::Snapshot(Vec::new()),
                )]))),
            ))
        }
    }

    fn adapter_for_snapshots(
        py: Python<'_>,
        layer_type: ovs::LayerType,
        inner: Option<ovs::LayerHandle>,
        declared_roots: Vec<ovs::Url>,
    ) -> (PyLayerAdapter, Py<PyAny>) {
        initialize_finalization_guard(py);
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
        let locals = TaskLocals::new(loop_handle.bind(py).clone()).with_context(context);
        let adapter = PyLayerAdapter::new(
            py,
            "python-snapshots".into(),
            layer_type,
            py.None(),
            inner,
            locals,
            declared_roots,
        )
        .unwrap();
        (adapter, loop_handle)
    }

    #[test]
    fn q7_wrapper_forwards_native_snapshot_tuples_and_update_riders() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let inner: ovs::LayerHandle = Arc::new(NativeSnapshotRider);
            let (wrapper, wrapper_loop) =
                adapter_for_snapshots(py, ovs::LayerType::Wrapper, Some(inner), Vec::new());

            // This is a Python wrapper position over a native producer.  The
            // `Some` and its item are observable here, before LayerBase's
            // Python API intentionally drops update riders from the tuple.
            let cx = ovs::Extensions::new();
            let (root_snapshot, root_updates) =
                futures::executor::block_on(wrapper.list_address_roots(&cx, None)).unwrap();
            assert!(root_snapshot.updates);
            assert!(matches!(
                futures::executor::block_on(root_updates.unwrap().next()),
                Some(Ok(ovs::RootInfoChange::Added(roots))) if roots.is_empty()
            ));
            let (connection_snapshot, connection_updates) =
                futures::executor::block_on(wrapper.list_connections(&cx, None)).unwrap();
            assert!(connection_snapshot.updates);
            assert!(matches!(
                futures::executor::block_on(connection_updates.unwrap().next()),
                Some(Ok(ovs::ConnectionChange::Snapshot(connections))) if connections.is_empty()
            ));
            drop(wrapper);
            wrapper_loop.bind(py).call_method0("close").unwrap();

            // Python leaves have no native producer to preserve: they publish
            // their declaration-time roots and explicitly return no rider.
            let declared_root = ovs::Url::parse("file:///declared/").unwrap();
            let (leaf, leaf_loop) = adapter_for_snapshots(
                py,
                ovs::LayerType::Backend,
                None,
                vec![declared_root.clone()],
            );
            let (snapshot, updates) =
                futures::executor::block_on(leaf.list_address_roots(&cx, None)).unwrap();
            assert_eq!(snapshot.roots.len(), 1);
            assert_eq!(snapshot.roots[0].root, declared_root);
            assert_eq!(snapshot.roots[0].layer_kind, PYTHON_BACKEND_KIND);
            assert!(!snapshot.updates);
            assert!(updates.is_none());
            drop(leaf);
            leaf_loop.bind(py).call_method0("close").unwrap();
        });
    }

    async fn wait_for_thread_event(event: Py<PyAny>) {
        let observed = tokio::task::spawn_blocking(move || {
            Python::with_gil(|py| {
                event
                    .bind(py)
                    .call_method1("wait", (2.0,))
                    .unwrap()
                    .extract::<bool>()
                    .unwrap()
            })
        })
        .await
        .unwrap();
        assert!(
            observed,
            "timed out waiting for deterministic Python barrier"
        );
    }

    #[test]
    fn dispatch_completes() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let harness = Harness::new(&runtime);

        let complete =
            Python::with_gil(|py| call(py, ("complete",), ovs::CancellationToken::new()));
        let adapter = harness.adapter.clone();
        let worker_runtime = runtime.clone();
        let value = run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                let value = adapter
                    .dispatch(OverrideSlot::Stat, complete, decode_i64)
                    .await
                    .unwrap();
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
                value
            })
        });
        assert_eq!(value, 41);
        harness.shutdown();
    }

    #[test]
    fn dispatch_cancels_the_retained_task_and_settles_once() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let harness = Harness::new(&runtime);
        let token = ovs::CancellationToken::new();
        let dispatch = Python::with_gil(|py| call(py, ("cancel",), token.clone()));
        let adapter = harness.adapter.clone();
        let cancel_started = Python::with_gil(|py| harness.cancel_started.clone_ref(py));
        let cancel_finished = Python::with_gil(|py| harness.cancel_finished.clone_ref(py));
        let worker_runtime = runtime.clone();
        let error = run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                let task = tokio::spawn(async move {
                    adapter
                        .dispatch(OverrideSlot::Stat, dispatch, decode_i64)
                        .await
                });
                wait_for_thread_event(cancel_started).await;
                token.cancel();
                let error = tokio::time::timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap_err();
                wait_for_thread_event(cancel_finished).await;
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
                error
            })
        });
        assert_eq!(error.code(), ovs::ErrorCode::Cancelled);
        assert_eq!(bridge_task_count(), 0);
        harness.shutdown();
    }

    #[test]
    fn dispatch_cancel_racing_completion_never_double_settles_or_leaks() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let harness = Harness::new(&runtime);
        let adapter = harness.adapter.clone();
        let worker_runtime = runtime.clone();
        run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                for _ in 0..32 {
                    let (started, call) = Python::with_gil(|py| {
                        let started = py
                            .import_bound("threading")
                            .unwrap()
                            .getattr("Event")
                            .unwrap()
                            .call0()
                            .unwrap()
                            .unbind();
                        let call = call(
                            py,
                            ("race", started.bind(py)),
                            ovs::CancellationToken::new(),
                        );
                        (started, call)
                    });
                    let token = call.cancel.clone();
                    let adapter = adapter.clone();
                    let task = tokio::spawn(async move {
                        adapter.dispatch(OverrideSlot::Stat, call, decode_i64).await
                    });
                    wait_for_thread_event(started).await;
                    token.cancel();
                    match tokio::time::timeout(Duration::from_secs(2), task)
                        .await
                        .unwrap()
                        .unwrap()
                    {
                        Ok(value) => assert_eq!(value, 7),
                        Err(error) => assert_eq!(error.code(), ovs::ErrorCode::Cancelled),
                    }
                }
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
            });
        });
        assert_eq!(bridge_task_count(), 0);
        harness.shutdown();
    }
}
