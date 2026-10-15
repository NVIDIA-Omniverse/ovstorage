// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interpreter attachment for Rust-owned threads, and the async conversion
//! layer built on it.
//!
//! # The defect this module exists to prevent
//!
//! When a thread that CPython does not own calls `PyEval_RestoreThread` while
//! the interpreter is finalizing, CPython terminates it with
//! `PyThread_exit_thread()`. `pthread_exit` then forced-unwinds through Rust
//! frames, which are not cancellation-aware, and glibc calls `abort()`. The
//! process dies with SIGABRT and prints nothing but
//! `FATAL: exception not rethrown`.
//!
//! A finalization check before the attach cannot prevent this. The check and
//! `PyGILState_Ensure` are not atomic, and CPython exposes no "attach only if
//! finalization has not begun" variant. Re-checking narrows the window; it
//! never closes it.
//!
//! # What does prevent it
//!
//! An admission gate that closes **once**, before finalization begins, plus a
//! drain that waits for the threads already inside an attach to leave.
//! [`close_admission`] and [`wait_for_drain`] are called from an `atexit`
//! handler, which runs while the interpreter is still fully usable — the window
//! a fence needs. Refusal is unconditional: after the close every attach is
//! refused. The waiting is what is bounded, by [`FENCE_DRAIN_TIMEOUT`], so a
//! timeout means admission was still held when the drain gave up — not that the
//! thread is still there once finalization does anything dangerous, since its
//! ticket may drop a moment later. The caller reports the measurement rather
//! than asserting the post-condition.
//!
//! The gate is only sound if *every* attach from a Rust-owned thread passes
//! through it. That is why this module also owns the Rust-future-to-Python-
//! awaitable conversion: `pyo3-async-runtimes` performs its own unguarded
//! attaches to deliver results, on paths that cannot be intercepted from
//! outside it. Wrapping its futures does not work, and was tried:
//!
//! * `generic.rs:609` attaches to deliver every completion.
//! * `Cancellable::poll` (`generic.rs:699`) polls the inner future first, and
//!   when the *Python* future has been cancelled it returns `Ready` and
//!   discards the inner future entirely — so a wrapper that parks instead of
//!   resolving is bypassed by cancellation.
//! * `into_future_with_locals` (`lib.rs:653`) attaches *inside* the future it
//!   returns when the sender is dropped, so a wrapper regains control only
//!   after the attach has already happened.
//!
//! The same defect is present in 0.27, where `Python::with_gil` was renamed to
//! `Python::attach` and nothing else changed. Upgrading is not a fix.
//!
//! [`future_into_py_with_locals`] and [`into_future`] below are replacements
//! rather than wrappers: they deliver results through [`with_bridge_gil`], and
//! when admission is refused they simply do not attach. The Python future is
//! left pending, which is the state that is already safe at interpreter exit.

use std::future::Future;

use futures::FutureExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use pyo3_async_runtimes::TaskLocals;
use tokio::sync::oneshot;

use crate::p2r_adapter::{finalizing_error, interpreter_is_finalizing};
use ovstorage_rust as ovs;

/// How long the fence waits for admitted attachers to leave.
///
/// The bound is risk reduction, not a guarantee. An admitted section can run
/// arbitrary user code — an override's `__call__`, a result's buffer protocol,
/// a coroutine's `finally` block — and such code may release the GIL while
/// still holding admission. When that outlasts the wait, the fence reports a
/// failed drain rather than pretending otherwise.
pub(crate) const FENCE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Admission state.
///
/// Three states are needed, not two. Cleanup runs *because* work is being
/// retired, and cleanup attaches to cancel tasks and close coroutines; a gate
/// that admitted nothing during teardown would leave every in-flight task
/// unretired. So the fence first moves to [`STATE_DRAINING`], which refuses new
/// dispatches while still admitting the cleanup they provoke, and only then to
/// [`STATE_CLOSED`].
const STATE_OPEN: usize = 0;
const STATE_DRAINING: usize = 1;
const STATE_CLOSED: usize = 2;

const STATE_MASK: usize = 0b11;
const ONE_ADMISSION: usize = 0b100;

/// Packed `(state, admitted count)`. The count lives above the state bits so a
/// single atomic carries both and admission is one compare-and-swap: the state
/// is bits 0-1, the count is everything above, so admitting is `+
/// ONE_ADMISSION` and reading the count is `>> 2`.
static ADMISSION: AtomicUsize = AtomicUsize::new(STATE_OPEN);

static DRAIN_MUTEX: Mutex<()> = Mutex::new(());
static DRAIN_SIGNAL: Condvar = Condvar::new();

fn state_of(packed: usize) -> usize {
    packed & STATE_MASK
}

fn admitted_of(packed: usize) -> usize {
    packed >> 2
}

/// Proof that the holder is counted by the fence for as long as it lives.
///
/// Constructed only by [`admit`], and released on drop. The ticket must span
/// the whole attach, not merely its acquisition: a section that has the GIL is
/// exactly what the drain has to wait for.
struct AttachTicket;

impl Drop for AttachTicket {
    fn drop(&mut self) {
        let previous = ADMISSION.fetch_sub(ONE_ADMISSION, Ordering::AcqRel);
        if admitted_of(previous) == 1 && state_of(previous) != STATE_OPEN {
            // Signal under the mutex the waiter uses for its predicate.
            // Notifying outside it would let a release that lands between the
            // fence's read and its wait go unseen, turning every exit with an
            // in-flight attach into a full-timeout stall.
            let _guard = DRAIN_MUTEX.lock().expect("bridge drain mutex poisoned");
            DRAIN_SIGNAL.notify_all();
        }
    }
}

/// Take a ticket unless the gate refuses.
///
/// `for_dispatch` distinguishes new work from the cleanup of work already
/// started. New dispatches are refused as soon as the fence begins; cleanup is
/// admitted until the gate closes outright.
fn admit(for_dispatch: bool) -> Option<AttachTicket> {
    let admissible = |state: usize| match state {
        STATE_OPEN => true,
        STATE_DRAINING => !for_dispatch,
        _ => false,
    };
    ADMISSION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |packed| {
            admissible(state_of(packed)).then(|| packed + ONE_ADMISSION)
        })
        .ok()
        .map(|_| AttachTicket)
}

/// Which population an attach belongs to.
///
/// The distinction is what makes the middle gate state useful: the fence has
/// to stop new work while still letting work already started retire itself,
/// and retiring needs the interpreter to cancel a task or close a coroutine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// New work. Refused as soon as the fence begins.
    Dispatch,
    /// Retiring work already started. Refused only once the gate closes.
    Cleanup,
}

/// [`with_bridge_gil`] with the population chosen by the caller, for helpers
/// that serve both -- the dispatch primitive also drives `aclose`, and the
/// liveness poll runs under both.
pub(crate) fn with_bridge_gil_as<T>(
    admission: Admission,
    f: impl FnOnce(Python<'_>) -> Result<T, ovs::Error>,
) -> Result<T, ovs::Error> {
    if interpreter_is_finalizing() {
        return Err(finalizing_error());
    }
    let Some(_ticket) = admit(admission == Admission::Dispatch) else {
        return Err(finalizing_error());
    };
    Python::with_gil(f)
}

/// Attach to the interpreter from a Rust-owned thread to run `f`.
///
/// This is the only place in the crate permitted to spell `Python::with_gil`
/// outside `#[cfg(test)]`; `tools/ovtasks/lint_bridge_gil.py` enforces that.
///
/// `#[pyfunction]` and `#[pymethods]` bodies must **not** come through here.
/// They already hold the GIL on a thread CPython owns, so they are never at
/// risk, and routing them through the gate would make them fail during
/// `atexit` for no reason.
pub(crate) fn with_bridge_gil<T>(
    f: impl FnOnce(Python<'_>) -> Result<T, ovs::Error>,
) -> Result<T, ovs::Error> {
    // Retained for the host that exposes neither `Py_IsFinalizing` spelling,
    // where `interpreter_is_finalizing` fails closed, and for the embedder
    // that finalizes without ever running `atexit`. It is no longer what makes
    // the attach safe.
    if interpreter_is_finalizing() {
        return Err(finalizing_error());
    }
    let Some(_ticket) = admit(true) else {
        return Err(finalizing_error());
    };
    Python::with_gil(f)
}

/// [`with_bridge_gil`] for closures that speak `PyResult`.
///
/// The closure's own error is propagated **unchanged**. Routing it through
/// `ovs::Error` and back would rewrite every exception into `InternalError`
/// with a new message, and callers here branch on exception identity —
/// `p2r_body` tests for `StopAsyncIteration` and `CancelledError` to tell
/// clean exhaustion and cancellation from failure. Only a refused admission
/// produces an error of this function's own making.
pub(crate) fn with_bridge_gil_py<T>(f: impl FnOnce(Python<'_>) -> PyResult<T>) -> PyResult<T> {
    if interpreter_is_finalizing() {
        return Err(crate::py_error(finalizing_error()));
    }
    let Some(_ticket) = admit(true) else {
        return Err(crate::py_error(finalizing_error()));
    };
    Python::with_gil(f)
}

/// [`with_bridge_gil`] for callers whose error type is neither `ovs::Error`
/// nor `PyErr`. `None` means admission was refused; the caller maps that onto
/// whatever its own signature calls a shutdown.
///
/// This is **new work**, like [`with_bridge_gil`] and unlike
/// [`with_bridge_gil_cleanup`] -- it differs only in how refusal is reported,
/// not in when it is refused.
pub(crate) fn attach_for_dispatch<T>(f: impl FnOnce(Python<'_>) -> T) -> Option<T> {
    if interpreter_is_finalizing() {
        return None;
    }
    let _ticket = admit(true)?;
    Some(Python::with_gil(f))
}

/// Attach to retire work that has already started.
///
/// Admitted while the fence is draining, when [`with_bridge_gil`] is not. Use
/// only for cancellation and close paths, which exist to *reduce* what is left
/// live at finalization; refusing them is what leaves tasks pending and
/// coroutines unclosed.
pub(crate) fn with_bridge_gil_cleanup<T>(
    f: impl FnOnce(Python<'_>) -> Result<T, ovs::Error>,
) -> Result<T, ovs::Error> {
    if interpreter_is_finalizing() {
        return Err(finalizing_error());
    }
    let Some(_ticket) = admit(false) else {
        return Err(finalizing_error());
    };
    Python::with_gil(f)
}

/// Render a `PyErr` to text from a Rust-owned thread.
///
/// `PyErr`'s `Display` impl attaches to the interpreter itself -- pyo3 0.21's
/// `err/mod.rs:950` opens with `Python::with_gil` to read the type name and
/// `str()`. So `format!("{err}")` off the Python thread is an ungated attach,
/// and it is one no text lint can see, because it hides behind `{}`.
///
/// Anything that needs a `PyErr`'s text outside an admitted section must come
/// through here. On refusal the caller still gets a message, just a generic
/// one -- attaching to a closing interpreter to improve an error string is
/// exactly the trade this module exists to refuse.
pub(crate) fn describe_py_error(error: &PyErr) -> String {
    with_bridge_gil_cleanup(|py| Ok(error.value_bound(py).to_string()))
        .unwrap_or_else(|_| "<error text unavailable; interpreter is shutting down>".to_owned())
}

/// Refuse new dispatches while still admitting cleanup. Idempotent.
pub(crate) fn begin_draining() {
    let _ = ADMISSION.fetch_update(Ordering::AcqRel, Ordering::Acquire, |packed| {
        (state_of(packed) == STATE_OPEN).then(|| packed - STATE_OPEN + STATE_DRAINING)
    });
}

/// Refuse every attach from a Rust-owned thread. One-way and idempotent.
pub(crate) fn close_admission() {
    let _ = ADMISSION.fetch_update(Ordering::AcqRel, Ordering::Acquire, |packed| {
        (state_of(packed) != STATE_CLOSED).then(|| packed - state_of(packed) + STATE_CLOSED)
    });
}

/// True when no thread holds admission.
pub(crate) fn drained() -> bool {
    admitted_of(ADMISSION.load(Ordering::Acquire)) == 0
}

/// Block until every admitted thread has left, or `timeout` elapses.
///
/// **The caller must not hold the GIL.** An admitted thread is typically
/// blocked in `PyEval_RestoreThread` waiting for exactly that GIL, so waiting
/// while holding it deadlocks until the timeout. `_fence_bridge_gil` calls this
/// inside `Python::allow_threads` for that reason.
pub(crate) fn wait_for_drain(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut guard = DRAIN_MUTEX.lock().expect("bridge drain mutex poisoned");
    loop {
        if drained() {
            return true;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return drained();
        };
        let (next, _) = DRAIN_SIGNAL
            .wait_timeout(guard, remaining)
            .expect("bridge drain mutex poisoned");
        guard = next;
    }
}

/// Propagate Python-side cancellation back into Rust.
///
/// Replaces `pyo3-async-runtimes`' `PyDoneCallback`, and the difference is the
/// whole point of owning this layer. That callback feeds a channel which lets
/// `Cancellable` return `Ready` and **discard** the pending Rust future,
/// dropping the spawned task straight into an unguarded attach. Here
/// `abandon` stops the spawned task from its own side, so the future is
/// dropped without anything attaching.
///
/// `operation` is the caller's own cancellation token where it has one, so a
/// cancelled awaitable also cancels the storage operation underneath it rather
/// than merely abandoning the future waiting on it.
#[pyclass]
struct PyCancelForward {
    operation: Option<ovs::CancellationToken>,
    abandon: ovs::CancellationToken,
}

#[pymethods]
impl PyCancelForward {
    fn __call__(&self, future: &Bound<'_, PyAny>) -> PyResult<()> {
        if future.getattr("cancelled")?.call0()?.is_truthy()? {
            if let Some(operation) = &self.operation {
                operation.cancel();
            }
            self.abandon.cancel();
        }
        Ok(())
    }
}

/// The panic payload's message, for the `RustPanic` a panicking bridge future
/// surfaces to Python.
fn panic_message(payload: &dyn std::any::Any) -> &str {
    if let Some(text) = payload.downcast_ref::<&str>() {
        text
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text
    } else {
        "unknown error"
    }
}

/// Settle a Python future on its own loop, skipping one already cancelled.
///
/// `set_result` on a cancelled future raises `InvalidStateError`, and the
/// check has to happen on the loop thread rather than here, because the future
/// can be cancelled between the two.
#[pyclass]
struct CheckedCompletor;

#[pymethods]
impl CheckedCompletor {
    fn __call__(
        &self,
        future: &Bound<'_, PyAny>,
        complete: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        if future.getattr("cancelled")?.call0()?.is_truthy()? {
            return Ok(());
        }
        complete.call1((value,))?;
        Ok(())
    }
}

fn call_soon_threadsafe(
    event_loop: &Bound<'_, PyAny>,
    context: &Bound<'_, PyAny>,
    args: impl IntoPy<Py<PyTuple>>,
) -> PyResult<()> {
    let kwargs = PyDict::new_bound(event_loop.py());
    kwargs.set_item("context", context)?;
    event_loop.call_method("call_soon_threadsafe", args, Some(&kwargs))?;
    Ok(())
}

/// Hand one completed Rust future's result back to Python.
///
/// Refusal is silent and deliberate: the fence has closed admission, the
/// interpreter is being torn down, and the correct action is to attach to
/// nothing and leave the Python future pending. That is precisely the state a
/// parked dispatch is already in today, and it is safe.
fn deliver<T>(locals: &TaskLocals, py_future: &Py<PyAny>, result: PyResult<T>)
where
    T: IntoPy<PyObject>,
{
    // Delivery stops at the closed gate, not at the finalizing flag.
    //
    // That is forced: settling a Python future means attaching, and admitting
    // an attach after `wait_for_drain` has returned would break the very
    // post-condition the fence exists to establish. So a result that arrives
    // after the gate closes cannot be delivered, and its awaitable stays
    // pending.
    //
    // The cost is real and is not papered over here: a caller still awaiting
    // such an operation never learns what happened to it. What is avoidable is
    // *starting* work that can never be delivered, and
    // `future_into_py_with_locals` handles that by settling the finalization
    // error up front, on the Python thread, while it still holds the GIL.
    if interpreter_is_finalizing() {
        return;
    }
    let _ = with_bridge_gil_cleanup(|py| {
        let future = py_future.bind(py);
        let event_loop = locals.event_loop(py);
        let (complete, value) = match result {
            Ok(value) => (
                future
                    .getattr("set_result")
                    .map_err(|error| bridge_failure("set_result", error))?,
                value.into_py(py),
            ),
            Err(error) => (
                future
                    .getattr("set_exception")
                    .map_err(|error| bridge_failure("set_exception", error))?,
                error.into_py(py),
            ),
        };
        let none = py.None().into_bound(py);
        call_soon_threadsafe(
            &event_loop,
            &none,
            (CheckedCompletor, future, complete, value),
        )
        .map_err(|error| bridge_failure("call_soon_threadsafe", error))
    });
}

fn bridge_failure(what: &str, error: PyErr) -> ovs::Error {
    ovs::Error::new(
        ovs::ErrorCode::Internal,
        format!("Python bridge could not {what}: {error}"),
    )
}

/// Convert a Rust future into a Python awaitable, resolved through the gate.
///
/// Replacement for `pyo3_async_runtimes::tokio::future_into_py`. `cancel` is
/// signalled if Python cancels the returned awaitable, which folds in what
/// `cancellable_future_into_py` used to add on top.
pub(crate) fn future_into_py_with_locals<'py, F, T>(
    py: Python<'py>,
    locals: TaskLocals,
    cancel: Option<ovs::CancellationToken>,
    fut: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    let py_future = locals.event_loop(py).call_method0("create_future")?;
    // Hold Dispatch admission across publication, rather than reading the gate
    // state and then spawning.
    //
    // Two reasons, and the weaker one is the race: a plain read leaves the gate
    // free to close between the check and the spawn. The stronger one is that
    // this is new work, and the fence's first phase exists to stop new work --
    // reading for `CLOSED` would keep publishing right through `DRAINING`,
    // including the second that phase 2 spends inside `allow_threads`, where
    // another Python thread is free to call in. Every other dispatch path is
    // refused in `DRAINING`; this is the primary one from Python and must be
    // too.
    //
    // Refusing here is what keeps the promise `deliver` makes: do not start
    // work that can never be delivered. This runs on a CPython-owned thread
    // holding the GIL, so settling the error is safe and the caller gets a
    // typed failure instead of an awaitable that never resolves.
    //
    // The two conditions must match what *delivery* refuses on, or work runs
    // that can never be reported. `interpreter_is_finalizing` fails closed
    // when neither `Py_IsFinalizing` spelling resolves, and `deliver` consults
    // it unconditionally; gating publication on admission alone would leave
    // the gate `OPEN` on such a host, so a `write` would commit to disk and
    // its awaitable would then hang forever — including for pure-Rust
    // operations with no Python in the path, which do not otherwise depend on
    // that symbol at all.
    // The ticket is held across the spawn below, so publication cannot slip
    // through a gate that closes between the check and the spawn.
    let admission = if interpreter_is_finalizing() {
        None
    } else {
        admit(true)
    };
    let Some(_admission) = admission else {
        py_future.call_method1("set_exception", (crate::py_error(finalizing_error()),))?;
        return Ok(py_future);
    };
    // Registered unconditionally. Cancelling a Python awaitable used to drop
    // the Rust future through the dependency's `Cancellable`; leaving that
    // unreplaced would let an abandoned `__anext__` run on, consume a chunk
    // nobody receives, and hold its lock against the next call.
    let abandon = ovs::CancellationToken::new();
    py_future.call_method1(
        "add_done_callback",
        (PyCancelForward {
            operation: cancel,
            abandon: abandon.clone(),
        },),
    )?;

    let handle: Py<PyAny> = py_future.clone().unbind();
    let scoped_locals = locals.clone();
    crate::pyo3_tokio::get_runtime().spawn(pyo3_async_runtimes::tokio::scope(
        scoped_locals.clone(),
        async move {
            let completed = tokio::select! {
                biased;
                // Abandonment drops `fut` and returns without attaching. The
                // awaitable is already cancelled, so it needs no result.
                () = abandon.cancelled() => return,
                completed = std::panic::AssertUnwindSafe(fut).catch_unwind() => completed,
            };
            match completed {
                Ok(result) => deliver(&scoped_locals, &handle, result),
                // A panicking bridge future must still settle its awaitable.
                // Dropping the panic would leave the caller awaiting something
                // that can never complete.
                Err(payload) => deliver::<PyObject>(
                    &scoped_locals,
                    &handle,
                    Err(PyErr::new::<pyo3_async_runtimes::err::RustPanic, _>(
                        format!("rust future panicked: {}", panic_message(&*payload)),
                    )),
                ),
            }
        },
    ));

    Ok(py_future)
}

/// [`future_into_py_with_locals`] against the running loop's locals.
pub(crate) fn future_into_py<'py, F, T>(py: Python<'py>, fut: F) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    let locals = crate::pyo3_tokio::get_current_locals(py)?;
    future_into_py_with_locals(py, locals, None, fut)
}

/// [`future_into_py_with_locals`] against the running loop's locals, forwarding
/// Python-side cancellation to `cancel`.
pub(crate) fn cancellable_future_into_py<'py, F, T>(
    py: Python<'py>,
    cancel: ovs::CancellationToken,
    fut: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject> + Send + 'static,
{
    let locals = crate::pyo3_tokio::get_current_locals(py)?;
    future_into_py_with_locals(py, locals, Some(cancel), fut)
}

/// Schedule a Python awaitable and report its result over a channel.
///
/// Runs on the loop thread, so it holds the GIL by construction and needs no
/// admission.
#[pyclass]
struct PyEnsureFuture {
    awaitable: Option<Py<PyAny>>,
    tx: Option<oneshot::Sender<PyResult<PyObject>>>,
}

#[pymethods]
impl PyEnsureFuture {
    fn __call__(&mut self, py: Python<'_>) -> PyResult<()> {
        let Some(awaitable) = self.awaitable.take() else {
            return Ok(());
        };
        let task = py
            .import_bound("asyncio")?
            .call_method1("ensure_future", (awaitable.bind(py),))?;
        task.call_method1(
            "add_done_callback",
            (PyTaskCompleter { tx: self.tx.take() },),
        )?;
        Ok(())
    }
}

/// Forward a finished Python task's outcome to the awaiting Rust future.
#[pyclass]
struct PyTaskCompleter {
    tx: Option<oneshot::Sender<PyResult<PyObject>>>,
}

#[pymethods]
impl PyTaskCompleter {
    fn __call__(&mut self, task: &Bound<'_, PyAny>) -> PyResult<()> {
        let Some(tx) = self.tx.take() else {
            return Ok(());
        };
        let _ = tx.send(task.call_method0("result").map(|value| value.unbind()));
        Ok(())
    }
}

/// Convert a Python awaitable into a Rust future.
///
/// Replacement for `pyo3_async_runtimes::into_future_with_locals`, whose
/// sender-dropped branch attaches to raise `CancelledError` from whatever
/// thread happens to be polling — the exact abort this module prevents. Here
/// the error is constructed without attaching: `PyErr::new` in PyO3 0.21 is
/// lazy and normalizes only when the value is first needed, which happens on a
/// thread that already holds the GIL.
pub(crate) fn into_future_with_locals(
    locals: TaskLocals,
    awaitable: Bound<'_, PyAny>,
) -> PyResult<impl Future<Output = PyResult<PyObject>> + Send + use<>> {
    let py = awaitable.py();
    let (tx, rx) = oneshot::channel();

    call_soon_threadsafe(
        &locals.event_loop(py),
        &locals.context(py),
        (PyEnsureFuture {
            awaitable: Some(awaitable.unbind()),
            tx: Some(tx),
        },),
    )?;

    Ok(async move {
        rx.await.unwrap_or_else(|_| {
            Err(PyErr::new::<pyo3::exceptions::asyncio::CancelledError, _>(
                "Python awaitable was discarded before it completed",
            ))
        })
    })
}

/// [`into_future_with_locals`] against the running loop's locals.
pub(crate) fn into_future(
    awaitable: Bound<'_, PyAny>,
) -> PyResult<impl Future<Output = PyResult<PyObject>> + Send + use<>> {
    let locals = crate::pyo3_tokio::get_current_locals(awaitable.py())?;
    into_future_with_locals(locals, awaitable)
}
