// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Python-to-Rust bridges for `read` and `watch_directory` iterators.
//!
//! A counted Tokio producer owns each Python async iterator and feeds a bounded
//! channel. Every `__anext__` and `aclose` awaitable uses the adapter's
//! retained-task dispatch primitive; this module does not schedule Python work
//! directly. Terminal state is kept outside the bounded data channel so
//! cancellation cannot delay cleanup when all eight slots are occupied.
//! `ReadStream` exposes its receiver asynchronously, while the Rust side of
//! `ChangeStream` is intentionally blocking.
//!
//! The supplied cancellation token is treated as operation-exclusive: early
//! consumer drop cancels that same token. Callers which need independent
//! sibling operations must provide independent tokens.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::Stream;
use pyo3::exceptions::PyStopAsyncIteration;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyTuple};
use pyo3_async_runtimes::TaskLocals;
use tokio::sync::mpsc;

use crate::ovs;
use crate::p2r_marshal::{self, MarshalledCall};

use crate::p2r_adapter::{
    AwaitableRequirement, BridgeTaskGuard, PY_BRIDGE_CHANNEL_CAPACITY,
    close_async_iterator_best_effort, dispatch_callable_with_context,
};

type ChangeReceiver = mpsc::Receiver<ovs::Result<ovs::ChangeEvent>>;

/// Shared whole-stream teardown state. The operation token is the one supplied
/// by the Rust caller; consumer abandonment never manufactures a second token.
struct StreamControl {
    cancel: ovs::CancellationToken,
    stopped: AtomicBool,
    complete: AtomicBool,
    incomplete_reported: AtomicBool,
    terminal: Mutex<Option<ovs::Error>>,
    operation: &'static str,
}

impl StreamControl {
    fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            self.cancel.cancel();
        }
    }

    fn finish(&self) {
        self.complete.store(true, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
    }

    fn set_terminal_if_live(&self, error: ovs::Error) {
        if self.stopped.load(Ordering::Acquire) {
            return;
        }
        let mut terminal = self
            .terminal
            .lock()
            .expect("Python stream terminal mutex poisoned");
        if terminal.is_none() {
            *terminal = Some(error);
        }
    }

    fn take_terminal(&self) -> Option<ovs::Error> {
        self.terminal
            .lock()
            .expect("Python stream terminal mutex poisoned")
            .take()
    }

    fn take_terminal_or_incomplete(&self) -> Option<ovs::Error> {
        if let Some(error) = self.take_terminal() {
            self.incomplete_reported.store(true, Ordering::Release);
            return Some(error);
        }
        (!self.complete.load(Ordering::Acquire)
            && !self.incomplete_reported.swap(true, Ordering::AcqRel))
        .then(|| {
            ovs::Error::new(
                ovs::ErrorCode::Internal,
                format!(
                    "Python {} stream producer ended without completion",
                    self.operation
                ),
            )
        })
    }
}

fn set_terminal_if_live(control: &StreamControl, error: ovs::Error) {
    control.set_terminal_if_live(error);
}

fn set_cancelled_if_live(control: &StreamControl, operation: &str) {
    set_terminal_if_live(
        control,
        ovs::Error::new(
            ovs::ErrorCode::Cancelled,
            format!("Python {operation} stream was cancelled"),
        ),
    );
}

/// Blocking consumer surface required by `ovs::ChangeStream`.
struct PythonChangeStream {
    rx: ChangeReceiver,
    control: Arc<StreamControl>,
}

impl Iterator for PythonChangeStream {
    type Item = ovs::Result<ovs::ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rx
            .blocking_recv()
            .or_else(|| self.control.take_terminal_or_incomplete().map(Err))
    }
}

impl Drop for PythonChangeStream {
    fn drop(&mut self) {
        self.control.stop();
    }
}

/// Async consumer surface required by `ovs::ReadStream`.
struct PythonReadStream<T> {
    rx: mpsc::Receiver<ovs::Result<T>>,
    control: Arc<StreamControl>,
}

impl<T: Unpin> Stream for PythonReadStream<T> {
    type Item = ovs::Result<T>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(None) => Poll::Ready(self.control.take_terminal_or_incomplete().map(Err)),
            result => result,
        }
    }
}

impl<T> Drop for PythonReadStream<T> {
    fn drop(&mut self) {
        self.control.stop();
    }
}

/// Normalize the override result through the Python async-iterator protocol.
pub(super) fn async_iterator(value: &Bound<'_, PyAny>) -> ovs::Result<Py<PyAny>> {
    normalize_async_iterator(value, "watch_directory")
}

/// Normalize a stream-shaped `read` result through the async-iterator
/// protocol. Runtime classification happens before this call: merely exposing
/// `__aiter__` gives the result stream precedence over all buffered shapes.
pub(super) fn read_async_iterator(value: &Bound<'_, PyAny>) -> ovs::Result<Py<PyAny>> {
    normalize_async_iterator(value, "read")
}

fn normalize_async_iterator(value: &Bound<'_, PyAny>, operation: &str) -> ovs::Result<Py<PyAny>> {
    let iterator = value.call_method0("__aiter__").map_err(|error| {
        ovs::Error::new(
            ovs::ErrorCode::IncompatibleType,
            format!("Python {operation} result is not an async iterator: {error}"),
        )
    })?;
    let has_anext = iterator.hasattr("__anext__").map_err(|error| {
        ovs::Error::new(
            ovs::ErrorCode::IncompatibleType,
            format!("Python {operation} iterator could not inspect `__anext__`: {error}"),
        )
    })?;
    if !has_anext {
        return Err(ovs::Error::new(
            ovs::ErrorCode::IncompatibleType,
            format!("Python {operation} result is missing `__anext__`"),
        ));
    }
    Ok(iterator.unbind())
}

/// Start the producer-owned Python byte iterator bridge.
pub(super) fn read_stream(
    task_locals: TaskLocals,
    loop_handle: Py<PyAny>,
    iterator: Py<PyAny>,
    cancel: ovs::CancellationToken,
) -> ovs::ReadStream {
    let (tx, rx) = mpsc::channel(PY_BRIDGE_CHANNEL_CAPACITY);
    let control = Arc::new(StreamControl {
        cancel,
        stopped: AtomicBool::new(false),
        complete: AtomicBool::new(false),
        incomplete_reported: AtomicBool::new(false),
        terminal: Mutex::new(None),
        operation: "read",
    });

    // Count the producer itself in addition to each retained Python task. This
    // makes bridge quiescence cover bounded-channel backpressure and the
    // queued-to-start window, exactly as it does for change streams.
    let guard = BridgeTaskGuard::new();
    let producer_control = control.clone();
    let scope_locals = task_locals.clone();
    tokio::spawn(pyo3_async_runtimes::tokio::scope(
        scope_locals,
        async move {
            let _guard = guard;
            produce_read(
                task_locals,
                loop_handle,
                iterator,
                &tx,
                producer_control.clone(),
            )
            .await;
            // Keep `tx` alive until `finish()` below marks the control
            // unstoppable. A consumer can only observe EOF after this store, so
            // dropping a naturally-completed stream cannot cancel a shared token.
            producer_control.finish();
        },
    ));

    Box::pin(PythonReadStream { rx, control })
}

/// Start the producer-owned Python change iterator bridge.
pub(super) fn change_stream(
    task_locals: TaskLocals,
    loop_handle: Py<PyAny>,
    iterator: Py<PyAny>,
    cancel: ovs::CancellationToken,
    prefix: ovs::Url,
    recursive: bool,
) -> ovs::ChangeStream {
    let (tx, rx) = mpsc::channel(PY_BRIDGE_CHANNEL_CAPACITY);
    let control = Arc::new(StreamControl {
        cancel,
        stopped: AtomicBool::new(false),
        complete: AtomicBool::new(false),
        incomplete_reported: AtomicBool::new(false),
        terminal: Mutex::new(None),
        operation: "watch_directory",
    });

    // Count before spawning so quiescence also observes the queued-to-start
    // window. If the runtime drops the unpolled future, its owned guard still
    // retires the count exactly once.
    let guard = BridgeTaskGuard::new();
    let producer_control = control.clone();
    let scope_locals = task_locals.clone();
    tokio::spawn(pyo3_async_runtimes::tokio::scope(
        scope_locals,
        async move {
            let _guard = guard;
            produce(
                task_locals,
                loop_handle,
                iterator,
                &tx,
                producer_control.clone(),
                prefix,
                recursive,
            )
            .await;
            producer_control.finish();
        },
    ));

    Box::new(PythonChangeStream { rx, control })
}

async fn produce(
    task_locals: TaskLocals,
    loop_handle: Py<PyAny>,
    iterator: Py<PyAny>,
    tx: &mpsc::Sender<ovs::Result<ovs::ChangeEvent>>,
    control: Arc<StreamControl>,
    prefix: ovs::Url,
    recursive: bool,
) {
    loop {
        if control.cancel.is_cancelled() {
            set_cancelled_if_live(&control, "watch_directory");
            break;
        }

        match pull(
            &task_locals,
            &loop_handle,
            &iterator,
            &control.cancel,
            &prefix,
            recursive,
        )
        .await
        {
            Ok(Some(event)) => {
                tokio::select! {
                    biased;
                    _ = control.cancel.cancelled() => {
                        set_cancelled_if_live(&control, "watch_directory");
                        break;
                    }
                    sent = tx.send(Ok(event)) => {
                        if sent.is_err() {
                            control.stop();
                            break;
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) if control.cancel.is_cancelled() => {
                set_cancelled_if_live(&control, "watch_directory");
                break;
            }
            Err(error) => {
                // Terminal state is out of band so a full data channel cannot
                // defer iterator cleanup. The consumer observes it once after
                // draining any already-buffered events.
                set_terminal_if_live(&control, error);
                break;
            }
        }
    }

    // A separate bounded cleanup token is necessary here: the operation token
    // is normally already cancelled on early drop, while `aclose()` must still
    // get one opportunity to run. It is cleanup control, never an iterator-pull
    // token, and all Python scheduling still goes through dispatch.
    close_async_iterator_best_effort(
        &task_locals,
        &loop_handle,
        &iterator,
        "watch_directory.aclose",
    )
    .await;
}

async fn produce_read<T>(
    task_locals: TaskLocals,
    loop_handle: Py<PyAny>,
    iterator: Py<PyAny>,
    tx: &mpsc::Sender<ovs::Result<T>>,
    control: Arc<StreamControl>,
) where
    T: Send + From<Vec<u8>> + 'static,
{
    loop {
        if control.cancel.is_cancelled() {
            set_cancelled_if_live(&control, "read");
            break;
        }

        match pull_bytes(&task_locals, &loop_handle, &iterator, &control.cancel).await {
            Ok(Some(bytes)) => {
                tokio::select! {
                    biased;
                    _ = control.cancel.cancelled() => {
                        set_cancelled_if_live(&control, "read");
                        break;
                    }
                    sent = tx.send(Ok(bytes.into())) => {
                        if sent.is_err() {
                            control.stop();
                            break;
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) if control.cancel.is_cancelled() => {
                set_cancelled_if_live(&control, "read");
                break;
            }
            Err(error) => {
                set_terminal_if_live(&control, error);
                break;
            }
        }
    }

    close_async_iterator_best_effort(&task_locals, &loop_handle, &iterator, "read.aclose").await;
}

async fn pull(
    task_locals: &TaskLocals,
    loop_handle: &Py<PyAny>,
    iterator: &Py<PyAny>,
    cancel: &ovs::CancellationToken,
    prefix: &ovs::Url,
    recursive: bool,
) -> ovs::Result<Option<ovs::ChangeEvent>> {
    let (callable, call) = crate::bridge_gil::with_bridge_gil(|py| {
        let callable = iterator.bind(py).getattr("__anext__").map_err(|error| {
            ovs::Error::new(
                ovs::ErrorCode::IncompatibleType,
                format!("Python watch_directory iterator lost `__anext__`: {error}"),
            )
        })?;
        Ok::<_, ovs::Error>((callable.unbind(), empty_call(py, cancel.clone())))
    })?;

    let event = dispatch_callable_with_context(
        task_locals,
        loop_handle,
        "watch_directory.__anext__",
        crate::bridge_gil::Admission::Dispatch,
        AwaitableRequirement::Awaitable,
        &callable,
        call,
        |_, value| {
            let event = value
                .extract::<PyRef<'_, crate::ChangeEvent>>()
                .map_err(|error| {
                    ovs::Error::new(
                        ovs::ErrorCode::IncompatibleType,
                        format!(
                            "Python watch_directory iterator must yield ChangeEvent values: {error}"
                        ),
                    )
                })?;
            Ok(Some(event.inner.clone()))
        },
        |py, error| {
            if error.is_instance_of::<PyStopAsyncIteration>(py) {
                Ok(None)
            } else {
                Err(p2r_marshal::override_failure(py, error))
            }
        },
    )
    .await?;
    if let Some(event) = &event {
        validate_change_event_scope(event, prefix, recursive)?;
    }
    Ok(event)
}

fn validate_change_event_scope(
    event: &ovs::ChangeEvent,
    prefix: &ovs::Url,
    recursive: bool,
) -> ovs::Result<()> {
    let ovs::ChangeEvent::Object { address, .. } = event else {
        return Ok(());
    };
    if !ovs::address::is_ancestor_or_self(prefix, address) {
        return Err(ovs::Error::new(
            ovs::ErrorCode::IncompatibleType,
            format!(
                "Python watch_directory yielded address `{address}` outside request prefix `{prefix}`"
            ),
        ));
    }
    if !recursive && path_depth(address) > path_depth(prefix).saturating_add(1) {
        return Err(ovs::Error::new(
            ovs::ErrorCode::IncompatibleType,
            format!(
                "Python non-recursive watch_directory yielded nested address `{address}` for prefix `{prefix}`"
            ),
        ));
    }
    Ok(())
}

fn path_depth(address: &ovs::Url) -> usize {
    address
        .path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).count())
        .unwrap_or_default()
}

async fn pull_bytes(
    task_locals: &TaskLocals,
    loop_handle: &Py<PyAny>,
    iterator: &Py<PyAny>,
    cancel: &ovs::CancellationToken,
) -> ovs::Result<Option<Vec<u8>>> {
    let (callable, call) = crate::bridge_gil::with_bridge_gil(|py| {
        let callable = iterator.bind(py).getattr("__anext__").map_err(|error| {
            ovs::Error::new(
                ovs::ErrorCode::IncompatibleType,
                format!("Python read iterator lost `__anext__`: {error}"),
            )
        })?;
        Ok::<_, ovs::Error>((callable.unbind(), empty_call(py, cancel.clone())))
    })?;

    dispatch_callable_with_context(
        task_locals,
        loop_handle,
        "read.__anext__",
        crate::bridge_gil::Admission::Dispatch,
        AwaitableRequirement::Awaitable,
        &callable,
        call,
        |_, value| {
            crate::bytes_from_python_buffer(&value)
                .map_err(|error| {
                    ovs::Error::new(
                        ovs::ErrorCode::IncompatibleType,
                        format!("Python read iterator yielded an invalid buffer: {error}"),
                    )
                })?
                .map(Some)
                .ok_or_else(|| {
                    ovs::Error::new(
                        ovs::ErrorCode::IncompatibleType,
                        "Python read iterator must yield bytes-like values",
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

fn empty_call(py: Python<'_>, cancel: ovs::CancellationToken) -> MarshalledCall {
    MarshalledCall {
        args: PyTuple::empty_bound(py).unbind(),
        kwargs: PyDict::new_bound(py).unbind(),
        cancel,
    }
}

#[cfg(test)]
#[cfg(feature = "no-extension-module-link")]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use ovs::Layer as _;
    use pyo3::types::PyModule;

    use super::*;
    use crate::LayerBase;
    use crate::p2r_adapter::{
        OverrideSlot, PyLayerAdapter, bridge_task_count, initialize_finalization_guard,
        quiesce_bridge_tasks,
    };

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const WATCH_LAYER: &str = r#"
import asyncio
import threading

loop = asyncio.new_event_loop()
pull_started = threading.Event()
close_finished = threading.Event()
close_calls = 0
events = []

class ExpectedError(TransientError):

class WatchIterator:
    def __init__(self, mode):
        self.mode = mode

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.mode == "events":
            if events:
                return events.pop(0)
            raise StopAsyncIteration
        if self.mode == "error":
            raise ExpectedError("watch failed")
        if self.mode == "cancel":
            pull_started.set()
            await asyncio.Future()
        raise AssertionError(self.mode)

    async def aclose(self):
        global close_calls
        close_calls += 1
        await asyncio.sleep(0)
        close_finished.set()

class ReadIterator:
    def __init__(self, mode):
        self.mode = mode
        self.chunks = [b"one", bytearray(b"two"), memoryview(b"three")]

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.mode == "chunks":
            if self.chunks:
                return self.chunks.pop(0)
            raise StopAsyncIteration
        if self.mode == "error":
            raise ExpectedError("read failed")
        if self.mode == "cancel":
            pull_started.set()
            await asyncio.Future()
        raise AssertionError(self.mode)

    async def aclose(self):
        global close_calls
        close_calls += 1
        await asyncio.sleep(0)
        close_finished.set()

class WatchLayer(LayerBase):
    async def read(self, address, **options):
        if "/read-chunks" in address:
            return ReadIterator("chunks")
        if "/read-error" in address:
            return ReadIterator("error")
        if "/read-cancel" in address:
            return ReadIterator("cancel")
        raise AssertionError(address)

    async def watch_directory(self, prefix, **options):
        if "/events/" in prefix:
            return WatchIterator("events")
        if "/error/" in prefix:
            return WatchIterator("error")
        if "/cancel/" in prefix:
            return WatchIterator("cancel")
        raise AssertionError(prefix)
"#;

    struct EmptyLayer;

    impl ovs::Layer for EmptyLayer {
        fn name(&self) -> &str {
            "empty"
        }

        fn descriptor(&self) -> ovs::LayerKindDescriptor {
            ovs::LayerKindDescriptor {
                kind: "empty".into(),
                layer_type: ovs::LayerType::Backend,
                display_name: "empty".into(),
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
    }

    struct NativeWatch {
        event: ovs::ChangeEvent,
    }

    #[async_trait::async_trait]
    impl ovs::Layer for NativeWatch {
        fn name(&self) -> &str {
            "native-watch"
        }

        fn descriptor(&self) -> ovs::LayerKindDescriptor {
            EmptyLayer.descriptor()
        }

        async fn watch_directory(
            &self,
            _request: ovs::Request<ovs::WatchDirectoryRequest>,
            _cancel: Option<ovs::CancellationToken>,
        ) -> ovs::Result<ovs::ChangeStream> {
            Ok(Box::new(vec![Ok(self.event.clone())].into_iter()))
        }
    }

    struct Harness {
        adapter: Arc<PyLayerAdapter>,
        loop_handle: Py<PyAny>,
        module: Py<PyModule>,
    }

    impl Harness {
        fn new(events: &[ovs::ChangeEvent]) -> Self {
            Python::with_gil(|py| {
                initialize_finalization_guard(py);
                let base = Py::new(py, LayerBase::from_handle(Arc::new(EmptyLayer))).unwrap();
                let module = PyModule::new_bound(py, "p2r_watch_test").unwrap();
                module
                    .add("LayerBase", py.get_type_bound::<LayerBase>())
                    .unwrap();
                module
                    .add(
                        "TransientError",
                        py.get_type_bound::<crate::TransientError>(),
                    )
                    .unwrap();
                py.run_bound(WATCH_LAYER, Some(&module.dict()), None)
                    .unwrap();
                let py_events = module.getattr("events").unwrap();
                for event in events {
                    py_events
                        .call_method1(
                            "append",
                            (Py::new(
                                py,
                                crate::ChangeEvent {
                                    inner: event.clone(),
                                },
                            )
                            .unwrap(),),
                        )
                        .unwrap();
                }
                let object = module
                    .getattr("WatchLayer")
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
                    "python-watch".into(),
                    ovs::LayerType::Backend,
                    object,
                    None,
                    task_locals,
                    Vec::new(),
                )
                .unwrap();
                assert!(adapter.is_overridden(OverrideSlot::WatchDirectory));
                Self {
                    adapter: Arc::new(adapter),
                    loop_handle,
                    module: module.unbind(),
                }
            })
        }

        fn shutdown(self) {
            drop(self.adapter);
            drop(self.module);
            Python::with_gil(|py| {
                self.loop_handle.bind(py).call_method0("close").unwrap();
            });
        }
    }

    fn event(address: &str, cursor: u8) -> ovs::ChangeEvent {
        ovs::ChangeEvent::Object {
            address: ovs::Url::parse(address).unwrap(),
            kind: ovs::ChangeKind::Modified,
            etag: Some(format!("etag-{cursor}")),
            version: None,
            size: Some(cursor.into()),
            mtime: None,
            at: SystemTime::UNIX_EPOCH,
            cursor: ovs::WatchDirectoryCursor(vec![cursor]),
        }
    }

    fn request(path: &str) -> ovs::Request<ovs::WatchDirectoryRequest> {
        ovs::Request::new(ovs::WatchDirectoryRequest {
            prefix: ovs::Url::parse(path).unwrap(),
            options: ovs::WatchDirectoryOptions::default(),
        })
    }

    fn read_request(path: &str) -> ovs::Request<ovs::ReadRequest> {
        ovs::Request::new(ovs::ReadRequest {
            address: ovs::Url::parse(path).unwrap(),
            options: ovs::ReadOptions::default(),
        })
    }

    fn run_while_loop<T: Send + 'static>(
        loop_handle: &Py<PyAny>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let worker_loop = Python::with_gil(|py| loop_handle.clone_ref(py));
        let worker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !Python::with_gil(|py| {
                worker_loop
                    .bind(py)
                    .call_method0("is_running")
                    .unwrap()
                    .extract::<bool>()
                    .unwrap()
            }) {
                assert!(std::time::Instant::now() < deadline);
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

    async fn wait_for_event(event: Py<PyAny>) {
        let ready = tokio::task::spawn_blocking(move || {
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
        assert!(ready, "timed out waiting for Python stream barrier");
    }

    #[test]
    fn python_watch_yields_ends_and_surfaces_typed_errors() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let expected = vec![event("file:///events/a", 1), event("file:///events/b", 2)];
        let harness = Harness::new(&expected);
        let adapter = harness.adapter.clone();
        let worker_runtime = runtime.clone();
        let observed = run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                let stream = adapter
                    .watch_directory(request("file:///events/"), None)
                    .await
                    .unwrap();
                let values = tokio::task::spawn_blocking(move || stream.collect::<Vec<_>>())
                    .await
                    .unwrap();

                let stream = adapter
                    .watch_directory(request("file:///error/"), None)
                    .await
                    .unwrap();
                let errors = tokio::task::spawn_blocking(move || stream.collect::<Vec<_>>())
                    .await
                    .unwrap();
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
                (values, errors)
            })
        });
        let values = observed
            .0
            .into_iter()
            .collect::<ovs::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(values, expected);
        assert_eq!(observed.1.len(), 1);
        assert_eq!(
            observed.1[0].as_ref().unwrap_err().code(),
            ovs::ErrorCode::Transient
        );
        assert_eq!(bridge_task_count(), 0);
        harness.shutdown();
    }

    #[test]
    fn python_read_yields_bytes_like_chunks_and_surfaces_typed_errors() {
        use futures::StreamExt as _;

        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let harness = Harness::new(&[]);
        let adapter = harness.adapter.clone();
        let worker_runtime = runtime.clone();
        let observed = run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                let (mut chunks, info) = match adapter
                    .read(read_request("file:///read-chunks"), None)
                    .await
                    .unwrap()
                {
                    ovs::ReadResult::Stream { stream, info } => (stream, info),
                    result => panic!("expected stream-shaped read, got {result:?}"),
                };
                let chunks = chunks.by_ref().collect::<Vec<_>>().await;

                let mut errors = match adapter
                    .read(read_request("file:///read-error"), None)
                    .await
                    .unwrap()
                {
                    ovs::ReadResult::Stream { stream, .. } => stream,
                    result => panic!("expected stream-shaped read, got {result:?}"),
                };
                let error = errors.next().await.unwrap().unwrap_err();
                assert!(errors.next().await.is_none());
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
                (chunks, info, error)
            })
        });
        let chunks = observed
            .0
            .into_iter()
            .collect::<ovs::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            chunks
                .iter()
                .map(|chunk| chunk.as_ref())
                .collect::<Vec<_>>(),
            [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()]
        );
        assert_eq!(observed.1.address.as_str(), "file:///read-chunks");
        assert_eq!(observed.1.size, None);
        assert_eq!(observed.2.code(), ovs::ErrorCode::Transient);
        assert_eq!(bridge_task_count(), 0);
        harness.shutdown();
    }

    #[test]
    fn read_drop_cancels_shared_token_closes_once_and_quiesces() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let harness = Harness::new(&[]);
        let adapter = harness.adapter.clone();
        let pull_started = Python::with_gil(|py| {
            harness
                .module
                .bind(py)
                .getattr("pull_started")
                .unwrap()
                .unbind()
        });
        let close_finished = Python::with_gil(|py| {
            harness
                .module
                .bind(py)
                .getattr("close_finished")
                .unwrap()
                .unbind()
        });
        let module = Python::with_gil(|py| harness.module.clone_ref(py));
        let worker_runtime = runtime.clone();
        run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                let cancel = ovs::CancellationToken::new();
                let stream = match adapter
                    .read(read_request("file:///read-cancel"), Some(cancel.clone()))
                    .await
                    .unwrap()
                {
                    ovs::ReadResult::Stream { stream, .. } => stream,
                    result => panic!("expected stream-shaped read, got {result:?}"),
                };
                wait_for_event(pull_started).await;
                drop(stream);
                assert!(cancel.is_cancelled());
                cancel.cancel();
                wait_for_event(close_finished).await;
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
                let close_calls = Python::with_gil(|py| {
                    module
                        .bind(py)
                        .getattr("close_calls")
                        .unwrap()
                        .extract::<usize>()
                        .unwrap()
                });
                assert_eq!(close_calls, 1);
            });
        });
        assert_eq!(bridge_task_count(), 0);
        harness.shutdown();
    }

    #[test]
    fn shared_token_cancel_then_drop_closes_once_and_quiesces() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let harness = Harness::new(&[]);
        let adapter = harness.adapter.clone();
        let pull_started = Python::with_gil(|py| {
            harness
                .module
                .bind(py)
                .getattr("pull_started")
                .unwrap()
                .unbind()
        });
        let close_finished = Python::with_gil(|py| {
            harness
                .module
                .bind(py)
                .getattr("close_finished")
                .unwrap()
                .unbind()
        });
        let module = Python::with_gil(|py| harness.module.clone_ref(py));
        let worker_runtime = runtime.clone();
        run_while_loop(&harness.loop_handle, move || {
            worker_runtime.block_on(async move {
                let cancel = ovs::CancellationToken::new();
                let stream = adapter
                    .watch_directory(request("file:///cancel/"), Some(cancel.clone()))
                    .await
                    .unwrap();
                wait_for_event(pull_started).await;
                cancel.cancel();
                cancel.cancel();
                drop(stream);
                wait_for_event(close_finished).await;
                assert!(quiesce_bridge_tasks(Duration::from_secs(2)).await);
                let close_calls = Python::with_gil(|py| {
                    module
                        .bind(py)
                        .getattr("close_calls")
                        .unwrap()
                        .extract::<usize>()
                        .unwrap()
                });
                assert_eq!(close_calls, 1);
            });
        });
        assert_eq!(bridge_task_count(), 0);
        harness.shutdown();
    }

    #[test]
    fn stopped_loop_skips_aclose_without_waiting() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (locals, loop_handle, iterator, module) = Python::with_gil(|py| {
            initialize_finalization_guard(py);
            let module = PyModule::from_code_bound(
                py,
                "class I:\n    close_calls = 0\n    async def aclose(self):\n        self.close_calls += 1\n",
                "stopped_close.py",
                "stopped_close",
            )
            .unwrap();
            let iterator = module.getattr("I").unwrap().call0().unwrap().unbind();
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
            (
                TaskLocals::new(loop_handle.bind(py).clone()).with_context(context),
                loop_handle,
                iterator,
                module.unbind(),
            )
        });
        runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(50),
                close_async_iterator_best_effort(&locals, &loop_handle, &iterator, "test.aclose"),
            )
            .await
            .expect("stopped-loop close must not hang");
        });
        Python::with_gil(|py| {
            assert_eq!(
                iterator
                    .bind(py)
                    .getattr("close_calls")
                    .unwrap()
                    .extract::<usize>()
                    .unwrap(),
                0
            );
            drop(module);
            loop_handle.bind(py).call_method0("close").unwrap();
        });
    }

    #[test]
    fn unoverridden_wrapper_delegates_the_native_change_stream() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        pyo3::prepare_freethreaded_python();
        let expected = event("file:///native/item", 9);
        let (adapter, loop_handle) = Python::with_gil(|py| {
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
            let inner: ovs::LayerHandle = Arc::new(NativeWatch {
                event: expected.clone(),
            });
            let adapter = PyLayerAdapter::new(
                py,
                "transparent-watch".into(),
                ovs::LayerType::Wrapper,
                py.None(),
                Some(inner),
                TaskLocals::new(loop_handle.bind(py).clone()).with_context(context),
                Vec::new(),
            )
            .unwrap();
            (adapter, loop_handle)
        });
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let values = runtime
            .block_on(adapter.watch_directory(request("file:///native/"), None))
            .unwrap()
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1);
        assert_eq!(values.into_iter().next().unwrap().unwrap(), expected);
        drop(adapter);
        Python::with_gil(|py| {
            loop_handle.bind(py).call_method0("close").unwrap();
        });
    }
}
