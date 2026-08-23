// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Rust-to-Python bridge for streaming write bodies.
//!
//! `BodyStream::next_chunk` and local-file reads are blocking operations. A
//! single `spawn_blocking` producer owns either source and forwards chunks
//! through the same bounded channel. Python's async iterator only awaits that
//! channel; it never pulls the blocking source on a Tokio worker. Cancellation
//! is observable between source pulls and during channel backpressure; the
//! blocking iterator contract cannot preempt an in-progress `next_chunk()`.

use std::io::Read as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::time::Duration;

use pyo3::exceptions::PyStopAsyncIteration;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use tokio::sync::{Mutex as TokioMutex, mpsc};
use tokio::task::JoinHandle;

use crate::ovs::{Body, BodyStream, CancellationToken, Error as OvError, ErrorCode};
use crate::p2r_adapter::{
    PY_BRIDGE_CHANNEL_CAPACITY, decrement_bridge_task_count, increment_bridge_task_count,
};

type BodyInputReceiver = mpsc::Receiver<Vec<u8>>;

// A full receiver can leave a blocking producer waiting for capacity while
// Python retains but does not drain the iterator. `try_send` plus a
// blocking-thread poll deliberately bounds cancellation and newly available
// capacity detection to 10 ms. This avoids coupling Tokio wakeups to an
// arbitrary synchronous BodyStream while keeping the bound below one event-loop
// scheduling turn for normal workloads.
const PRODUCER_SEND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const LOCAL_FILE_CHUNK_SIZE: usize = 64 * 1024;

struct BodyBridgeTaskGuard;

impl BodyBridgeTaskGuard {
    fn new() -> Self {
        increment_bridge_task_count();
        Self
    }
}

impl Drop for BodyBridgeTaskGuard {
    fn drop(&mut self) {
        decrement_bridge_task_count();
    }
}

struct ProducerControl {
    cancel: CancellationToken,
    handle: StdMutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
    state: Arc<BodyInputState>,
}

impl ProducerControl {
    fn stop(&self) {
        if self.stopped.swap(true, Ordering::AcqRel) {
            return;
        }
        self.state.close();
        self.cancel.cancel();
        if let Some(handle) = self
            .handle
            .lock()
            .expect("Python body producer handle mutex poisoned")
            .take()
        {
            // `abort` prevents a queued blocking task from starting. A task
            // which has started observes `cancel` between pulls or while
            // waiting for channel capacity and exits on its own.
            handle.abort();
        }
    }
}

struct BodyInputState {
    closed: AtomicBool,
    complete: AtomicBool,
    terminal: StdMutex<Option<OvError>>,
    close_signal: CancellationToken,
}

impl BodyInputState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            complete: AtomicBool::new(false),
            terminal: StdMutex::new(None),
            close_signal: CancellationToken::new(),
        }
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            // CancellationToken is level-triggered: waiters which register
            // after this call still complete immediately. Notify::notify_waiters
            // would lose that close edge.
            self.close_signal.cancel();
        }
    }

    fn finish(&self) {
        self.complete.store(true, Ordering::Release);
    }

    fn fail(&self, error: OvError) {
        if self.closed.load(Ordering::Acquire) || self.complete.load(Ordering::Acquire) {
            return;
        }
        let mut terminal = self
            .terminal
            .lock()
            .expect("Python body terminal mutex poisoned");
        if terminal.is_none() {
            *terminal = Some(error);
        }
    }

    fn take_terminal(&self) -> Option<OvError> {
        self.terminal
            .lock()
            .expect("Python body terminal mutex poisoned")
            .take()
    }
}

/// Bounded async byte iterator presented to Python `write_stream` overrides.
///
/// The iterator owns its producer. Dropping it or calling `aclose()` stops the
/// producer idempotently. The producer token is a child of the operation token:
/// operation cancellation reaches the producer, while consumer abandonment
/// does not cancel the containing operation or token-sharing siblings.
#[pyclass(module = "ovstorage")]
pub(super) struct AsyncBodyInput {
    rx: Arc<TokioMutex<BodyInputReceiver>>,
    producer: ProducerControl,
    state: Arc<BodyInputState>,
}

impl Drop for AsyncBodyInput {
    fn drop(&mut self) {
        self.producer.stop();
    }
}

#[pymethods]
impl AsyncBodyInput {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.rx.clone();
        let state = self.state.clone();
        crate::coroutine_into_py(py, "AsyncBodyInput.__anext__", async move {
            if state.closed.load(Ordering::Acquire) {
                return Err(PyStopAsyncIteration::new_err(()));
            }
            let mut guard = tokio::select! {
                biased;
                _ = state.close_signal.cancelled() => {
                    return Err(PyStopAsyncIteration::new_err(()));
                }
                guard = rx.lock() => guard,
            };
            if state.closed.load(Ordering::Acquire) {
                return Err(PyStopAsyncIteration::new_err(()));
            }
            let item = tokio::select! {
                biased;
                _ = state.close_signal.cancelled() => {
                    return Err(PyStopAsyncIteration::new_err(()));
                }
                item = guard.recv() => item,
            };
            if state.closed.load(Ordering::Acquire) {
                return Err(PyStopAsyncIteration::new_err(()));
            }
            match item {
                None => {
                    if let Some(error) = state.take_terminal() {
                        state.close();
                        Err(crate::py_error(error))
                    } else if state.complete.load(Ordering::Acquire) {
                        state.close();
                        Err(PyStopAsyncIteration::new_err(()))
                    } else {
                        state.close();
                        Err(crate::py_error(OvError::new(
                            ErrorCode::Internal,
                            "write_stream body producer ended without completion",
                        )))
                    }
                }
                Some(bytes) => crate::bridge_gil::with_bridge_gil_py(|py| {
                    Ok(PyBytes::new_bound(py, &bytes).unbind())
                }),
            }
        })
    }

    /// Stop this iterator's producer. Repeated calls are harmless.
    fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.producer.stop();
        crate::ready_coroutine(py, "AsyncBodyInput.aclose", py.None())
    }
}

/// Convert a native write body to the declaration-form Python signature.
/// Buffered bodies remain ordinary Python `bytes`; only blocking bodies get a
/// producer and an `AsyncBodyInput` wrapper.
pub(super) fn body_to_python(
    py: Python<'_>,
    body: Body,
    operation_cancel: CancellationToken,
) -> Result<PyObject, OvError> {
    match body {
        Body::Bytes(bytes) => Ok(PyBytes::new_bound(py, &bytes).unbind().into_py(py)),
        Body::Stream(stream) => {
            streaming_body_to_python(py, operation_cancel, move |tx, cancel, state| {
                produce_stream(stream, tx, cancel, state);
            })
        }
        Body::LocalFile(path) => {
            streaming_body_to_python(py, operation_cancel, move |tx, cancel, state| {
                produce_local_file(path, tx, cancel, state);
            })
        }
    }
}

fn streaming_body_to_python(
    py: Python<'_>,
    operation_cancel: CancellationToken,
    produce: impl FnOnce(&mpsc::Sender<Vec<u8>>, &CancellationToken, &BodyInputState) + Send + 'static,
) -> Result<PyObject, OvError> {
    let (tx, rx) = mpsc::channel(PY_BRIDGE_CHANNEL_CAPACITY);
    let state = Arc::new(BodyInputState::new());
    let producer_cancel = operation_cancel.child_token();
    let task_cancel = producer_cancel.clone();
    let task_state = state.clone();
    // Count before scheduling so the queued spawn-blocking window is visible.
    // If an immediately-aborted task never starts, dropping its captured guard
    // still retires the count exactly once.
    let task_guard = BodyBridgeTaskGuard::new();
    let handle = crate::pyo3_tokio::get_runtime().spawn_blocking(move || {
        let _task_guard = task_guard;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            produce(&tx, &task_cancel, &task_state);
        }));
        if outcome.is_err() {
            task_state.fail(OvError::new(
                ErrorCode::Internal,
                "write_stream body producer panicked",
            ));
        }
        drop(tx);
    });
    Py::new(
        py,
        AsyncBodyInput {
            rx: Arc::new(TokioMutex::new(rx)),
            producer: ProducerControl {
                cancel: producer_cancel,
                handle: StdMutex::new(Some(handle)),
                stopped: AtomicBool::new(false),
                state: state.clone(),
            },
            state,
        },
    )
    .map(|input| input.into_py(py))
    .map_err(|error| {
        OvError::new(
            ErrorCode::Internal,
            format!("could not allocate Python body iterator: {error}"),
        )
    })
}

fn produce_stream(
    mut stream: BodyStream,
    tx: &mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
    state: &BodyInputState,
) {
    loop {
        if cancel.is_cancelled() {
            state.fail(cancelled_error());
            return;
        }
        let Some(chunk) = stream.next_chunk() else {
            if cancel.is_cancelled() {
                state.fail(cancelled_error());
            } else {
                state.finish();
            }
            return;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                state.fail(error);
                return;
            }
        };
        if !send_while_active(tx, cancel, chunk) {
            if cancel.is_cancelled() {
                state.fail(cancelled_error());
            }
            return;
        }
    }
}

fn produce_local_file(
    path: std::path::PathBuf,
    tx: &mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
    state: &BodyInputState,
) {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            state.fail(io_error("open", error));
            return;
        }
    };
    let mut buffer = vec![0_u8; LOCAL_FILE_CHUNK_SIZE];
    loop {
        if cancel.is_cancelled() {
            state.fail(cancelled_error());
            return;
        }
        match file.read(&mut buffer) {
            Ok(0) => {
                if cancel.is_cancelled() {
                    state.fail(cancelled_error());
                } else {
                    state.finish();
                }
                return;
            }
            Ok(count) => {
                if !send_while_active(tx, cancel, buffer[..count].to_vec()) {
                    if cancel.is_cancelled() {
                        state.fail(cancelled_error());
                    }
                    return;
                }
            }
            Err(error) => {
                state.fail(io_error("read", error));
                return;
            }
        }
    }
}

fn cancelled_error() -> OvError {
    OvError::new(
        ErrorCode::Cancelled,
        "write_stream body production was cancelled",
    )
}

fn send_while_active(
    tx: &mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
    mut item: Vec<u8>,
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
                std::thread::park_timeout(PRODUCER_SEND_POLL_INTERVAL);
            }
        }
    }
}

fn io_error(action: &str, error: std::io::Error) -> OvError {
    use std::io::ErrorKind;
    let code = match error.kind() {
        ErrorKind::NotFound => ErrorCode::NotFound,
        ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        _ => ErrorCode::Internal,
    };
    OvError::new(code, format!("could not {action} write body: {error}"))
}

async fn await_body_method(
    locals: &pyo3_async_runtimes::TaskLocals,
    body: &Py<PyAny>,
    method: &str,
) -> PyResult<PyObject> {
    let future = crate::bridge_gil::with_bridge_gil_py(|py| {
        let awaitable = body.bind(py).call_method0(method)?;
        crate::bridge_gil::into_future_with_locals(locals.clone(), awaitable)
    })?;
    future.await
}

/// Gate probe for a cancelled producer with every bounded data slot occupied.
/// Cleanup must retire before the retained Python consumer drains its prefix,
/// and the next item after that prefix must be a typed cancellation error.
#[pyfunction]
pub(super) fn _probe_full_body_channel_cancel<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let locals = crate::pyo3_tokio::get_current_locals(py)?;
    let pulls = Arc::new(AtomicUsize::new(0));
    let producer_pulls = pulls.clone();
    let stream = BodyStream::from_iter(std::iter::from_fn(move || {
        producer_pulls.fetch_add(1, Ordering::AcqRel);
        Some(Ok(vec![b'x']))
    }));
    let cancel = CancellationToken::new();
    let body = body_to_python(py, Body::Stream(stream), cancel.clone()).map_err(crate::py_error)?;
    crate::coroutine_into_py(py, "_probe_full_body_channel_cancel", async move {
        let deadline = tokio::time::Instant::now() + crate::p2r_adapter::PY_POST_CANCEL_TIMEOUT;
        while pulls.load(Ordering::Acquire) <= PY_BRIDGE_CHANNEL_CAPACITY {
            if tokio::time::Instant::now() >= deadline {
                return Err(crate::py_error(OvError::new(
                    ErrorCode::DeadlineExceeded,
                    "body producer did not fill the bounded bridge channel",
                )));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        cancel.cancel();
        if !crate::p2r_adapter::quiesce_bridge_tasks(crate::p2r_adapter::PY_POST_CANCEL_TIMEOUT)
            .await
        {
            return Err(crate::py_error(OvError::new(
                ErrorCode::DeadlineExceeded,
                "full-channel body producer did not retire after cancellation",
            )));
        }

        let mut buffered = 0;
        loop {
            match await_body_method(&locals, &body, "__anext__").await {
                Ok(_) => buffered += 1,
                Err(error) => {
                    let cancelled = crate::bridge_gil::with_bridge_gil(|py| {
                        Ok(error.is_instance_of::<crate::CancelledError>(py))
                    })
                    .unwrap_or(false);
                    if !cancelled {
                        return Err(error);
                    }
                    break;
                }
            }
        }
        if buffered != PY_BRIDGE_CHANNEL_CAPACITY {
            return Err(crate::py_error(OvError::new(
                ErrorCode::Internal,
                format!(
                    "full-channel body probe drained {buffered} items, expected {PY_BRIDGE_CHANNEL_CAPACITY}"
                ),
            )));
        }
        Ok((buffered, pulls.load(Ordering::Acquire)))
    })
}

/// Gate probe that closes an iterator while its blocking source pull is stuck.
/// The pending Python pull must stop immediately; the producer remains counted
/// only until this probe releases the deliberately blocked source.
#[pyfunction]
pub(super) fn _probe_close_during_blocking_body_pull<'py>(
    py: Python<'py>,
) -> PyResult<Bound<'py, PyAny>> {
    let locals = crate::pyo3_tokio::get_current_locals(py)?;
    let started = Arc::new(AtomicBool::new(false));
    let gate = Arc::new((StdMutex::new(false), Condvar::new()));
    let producer_started = started.clone();
    let producer_gate = gate.clone();
    let stream = BodyStream::from_iter(std::iter::once_with(move || {
        producer_started.store(true, Ordering::Release);
        let (lock, ready) = &*producer_gate;
        let mut released = lock.lock().expect("body probe gate mutex poisoned");
        while !*released {
            released = ready
                .wait(released)
                .expect("body probe gate mutex poisoned while waiting");
        }
        Ok(vec![b'x'])
    }));
    let body = body_to_python(py, Body::Stream(stream), CancellationToken::new())
        .map_err(crate::py_error)?;
    crate::coroutine_into_py(py, "_probe_close_during_blocking_body_pull", async move {
        let pull = await_body_method(&locals, &body, "__anext__");
        tokio::pin!(pull);
        let deadline = tokio::time::Instant::now() + crate::p2r_adapter::PY_POST_CANCEL_TIMEOUT;
        while !started.load(Ordering::Acquire) {
            if tokio::time::Instant::now() >= deadline {
                return Err(crate::py_error(OvError::new(
                    ErrorCode::DeadlineExceeded,
                    "blocking body source did not start",
                )));
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        await_body_method(&locals, &body, "aclose").await?;
        let outcome =
            tokio::time::timeout(crate::p2r_adapter::PY_POST_CANCEL_TIMEOUT, &mut pull).await;

        let (lock, ready) = &*gate;
        *lock.lock().expect("body probe gate mutex poisoned") = true;
        ready.notify_all();
        let quiesced =
            crate::p2r_adapter::quiesce_bridge_tasks(crate::p2r_adapter::PY_POST_CANCEL_TIMEOUT)
                .await;

        let error = outcome
            .map_err(|_| {
                crate::py_error(OvError::new(
                    ErrorCode::DeadlineExceeded,
                    "pending body pull did not stop after aclose",
                ))
            })?
            .expect_err("closed body pull unexpectedly yielded bytes");
        let stopped = crate::bridge_gil::with_bridge_gil(|py| {
            Ok(error.is_instance_of::<PyStopAsyncIteration>(py))
        })
        .unwrap_or(false);
        if !stopped || !quiesced {
            return Err(crate::py_error(OvError::new(
                ErrorCode::Internal,
                "blocking body close probe did not stop and retire cleanly",
            )));
        }
        Ok(())
    })
}

/// Gate probe that ensures a panicking native body producer cannot look like
/// successful end-of-stream to Python.
#[pyfunction]
pub(super) fn _probe_panicking_body_source<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let locals = crate::pyo3_tokio::get_current_locals(py)?;
    let stream = BodyStream::from_iter(std::iter::once_with(|| -> Result<Vec<u8>, OvError> {
        panic!("intentional body probe panic")
    }));
    let body = body_to_python(py, Body::Stream(stream), CancellationToken::new())
        .map_err(crate::py_error)?;
    crate::coroutine_into_py(py, "_probe_panicking_body_source", async move {
        let error = await_body_method(&locals, &body, "__anext__")
            .await
            .expect_err("panicking body source unexpectedly reached EOF");
        if !crate::bridge_gil::with_bridge_gil(|py| {
            Ok(error.is_instance_of::<crate::InternalError>(py))
        })
        .unwrap_or(false)
        {
            return Err(error);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn send_stops_when_cancelled_even_if_the_bounded_channel_is_full() {
        let (tx, _rx) = super::mpsc::channel(1);
        tx.try_send(vec![1]).unwrap();
        let cancel = super::CancellationToken::new();
        cancel.cancel();
        assert!(!super::send_while_active(&tx, &cancel, vec![2]));
    }

    #[test]
    fn task_guard_accounts_exactly_once() {
        let before = crate::p2r_adapter::bridge_task_count();
        let guard = super::BodyBridgeTaskGuard::new();
        assert_eq!(crate::p2r_adapter::bridge_task_count(), before + 1);
        drop(guard);
        assert_eq!(crate::p2r_adapter::bridge_task_count(), before);
    }

    #[test]
    fn configured_channel_capacity_is_eight() {
        assert_eq!(super::PY_BRIDGE_CHANNEL_CAPACITY, 8);
    }

    #[test]
    fn close_signal_is_level_triggered_for_late_waiters() {
        let state = super::BodyInputState::new();
        state.close();

        futures::executor::block_on(state.close_signal.cancelled());
        futures::executor::block_on(state.close_signal.cancelled());
    }
}
