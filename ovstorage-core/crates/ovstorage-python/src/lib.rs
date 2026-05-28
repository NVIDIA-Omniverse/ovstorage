// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
// pyo3 0.21 `#[pymethods]` emits unsafe ops inside `unsafe extern "C"` thunks; Rust 2024 lint fires once per method. Pinned-allow until a pyo3 bump.
#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::UNIX_EPOCH;

use ovs::auth::{
    CallbackCredentialProvider, CredentialCacheDurability, CredentialError, PrincipalView,
    ResolvedCredential,
};
use ovs::{
    AccessOps, BackendId, Body, CancellationToken, CopyOptions, CreateDirectoryOptions,
    DeleteDirectoryOptions, DeleteOptions, Error as OvError, ErrorCode, InteractiveAuthCapability,
    Library as RustLibrary, ListOptions, ListVersionsOptions, LocalDelegate as RustLocalDelegate,
    ObjectInfo, ReadOptions, ReadStream, RenameOptions, SecretBundle as RustSecretBundle,
    SecretBytes, SecretValue as RustSecretValue, StatOptions, Storage, UpdateMetadataOptions,
    WriteOptions, address,
};
use ovstorage_rust as ovs;
use pyo3::exceptions::PyStopAsyncIteration;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3_async_runtimes::tokio as pyo3_tokio;
use tokio::sync::{Mutex as TokioMutex, mpsc};

pyo3::create_exception!(ovstorage, Error, pyo3::exceptions::PyException);
pyo3::create_exception!(ovstorage, NotFoundError, Error);
pyo3::create_exception!(ovstorage, AlreadyExistsError, Error);
pyo3::create_exception!(ovstorage, PermissionDeniedError, Error);
pyo3::create_exception!(ovstorage, PreconditionFailedError, Error);
pyo3::create_exception!(ovstorage, ConflictError, Error);
pyo3::create_exception!(ovstorage, DirectoryNotEmptyError, Error);
pyo3::create_exception!(ovstorage, UnsupportedError, Error);
pyo3::create_exception!(ovstorage, InvalidArgumentError, Error);
pyo3::create_exception!(ovstorage, IncompatibleTypeError, Error);
pyo3::create_exception!(ovstorage, LockedError, Error);
pyo3::create_exception!(ovstorage, CancelledError, Error);
pyo3::create_exception!(ovstorage, DeadlineExceededError, Error);
pyo3::create_exception!(ovstorage, TransientError, Error);
pyo3::create_exception!(ovstorage, ResourceExhaustedError, Error);
pyo3::create_exception!(ovstorage, IntegrityFailureError, Error);
pyo3::create_exception!(ovstorage, InternalError, Error);
pyo3::create_exception!(ovstorage, BrokerUnavailableError, Error);
pyo3::create_exception!(ovstorage, BrokerRequiredError, Error);
pyo3::create_exception!(ovstorage, RedirectExpiredError, Error);
pyo3::create_exception!(ovstorage, PolicyEpochStaleError, Error);
pyo3::create_exception!(ovstorage, AuthorizationLeaseExpiredError, Error);
pyo3::create_exception!(ovstorage, CacheCorruptError, Error);
pyo3::create_exception!(ovstorage, StagingExpiredError, Error);
pyo3::create_exception!(ovstorage, CommitAmbiguousError, Error);
pyo3::create_exception!(ovstorage, CacheLockContentionError, Error);
pyo3::create_exception!(ovstorage, StateRootUnavailableError, Error);
pyo3::create_exception!(ovstorage, NetworkFilesystemRefusedError, Error);
pyo3::create_exception!(ovstorage, ObjectModifiedError, Error);
pyo3::create_exception!(ovstorage, NoRouteError, Error);
pyo3::create_exception!(ovstorage, RouteConflictError, Error);
pyo3::create_exception!(ovstorage, NotConfiguredError, Error);
pyo3::create_exception!(ovstorage, AliasChainTooLongError, Error);
pyo3::create_exception!(ovstorage, CredentialExpiredError, Error);
pyo3::create_exception!(ovstorage, CredentialUnavailableError, Error);
pyo3::create_exception!(ovstorage, AuthRequiredError, Error);
pyo3::create_exception!(ovstorage, AuthCancelledError, Error);
pyo3::create_exception!(ovstorage, AuthExpiredError, Error);
pyo3::create_exception!(ovstorage, ContentMismatchError, Error);
pyo3::create_exception!(ovstorage, ContentChecksumMismatchError, Error);
pyo3::create_exception!(ovstorage, PluginRejectedError, Error);

type AddressRootSnapshotReceiver = mpsc::Receiver<Result<Vec<ovs::AddressRoot>, OvError>>;

#[pyclass]
struct PyCancelCallback {
    cancel: CancellationToken,
}

#[pymethods]
impl PyCancelCallback {
    fn __call__(&self, fut: &Bound<'_, PyAny>) -> PyResult<()> {
        if fut.getattr("cancelled")?.call0()?.is_truthy()? {
            self.cancel.cancel();
        }
        Ok(())
    }
}

fn cancellable_future_into_py<'py, F, T>(
    py: Python<'py>,
    cancel: CancellationToken,
    fut: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: IntoPy<PyObject>,
{
    let py_fut = pyo3_tokio::future_into_py(py, fut)?;
    py_fut.call_method1("add_done_callback", (PyCancelCallback { cancel },))?;
    Ok(py_fut)
}

fn ready_future<'py>(py: Python<'py>, value: PyObject) -> PyResult<Bound<'py, PyAny>> {
    let asyncio = py.import_bound("asyncio")?;
    let event_loop = asyncio.call_method0("get_running_loop")?;
    let future = event_loop.call_method0("create_future")?;
    future.call_method1("set_result", (value,))?;
    Ok(future)
}

/// Mirrors `ovstorage::auth::CredentialCacheDurability`. Class-attribute
/// ints; pass to `Library.open(credential_cache_durability=...)`.
#[pyclass(name = "CredentialCacheDurability")]
struct PyCredentialCacheDurability;

#[pymethods]
impl PyCredentialCacheDurability {
    #[classattr]
    const PERSISTENT: i32 = 0;
    #[classattr]
    const IN_MEMORY_ONLY: i32 = 1;
}

/// Mirrors `ovstorage_plugin::InteractiveAuthCapability`.
#[pyclass(name = "InteractiveAuthCapability")]
struct PyInteractiveAuthCapability;

#[pymethods]
impl PyInteractiveAuthCapability {
    #[classattr]
    const BROWSER: i32 = 0;
    #[classattr]
    const HEADLESS: i32 = 1;
    #[classattr]
    const NONE: i32 = 2;
}

#[pyclass]
struct Library {
    inner: Arc<RustLibrary>,
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

#[pymethods]
impl Library {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        Self::open(py, None, None, None, None, false)
    }

    /// Build a `Library` against the process-global auth substrate.
    ///
    /// Plugin loading is explicit — `open()` does not discover plugins.
    /// Call `await library.load_plugins_from_dir(None)` (defaults to
    /// `$OVSTORAGE_PLUGIN_DIR`) after `open()`. Routes are similarly
    /// explicit via `add_connection` / `load_config`.
    ///
    /// The first `open()` (or explicit `init_auth_substrate`) in a
    /// process pins the auth substrate; subsequent `open()` calls
    /// share the same substrate and may freely vary the per-`Library`
    /// config below.
    ///
    /// `credential_callback` is auto-detected as sync vs. coroutine via
    /// `asyncio.iscoroutinefunction`; when provided,
    /// `credential_callback_name` is required.
    #[staticmethod]
    #[pyo3(signature = (
        interactive_auth_capability=None,
        credential_cache_durability=None,
        credential_callback=None,
        credential_callback_name=None,
        allow_test_plugins=false,
    ))]
    fn open(
        py: Python<'_>,
        interactive_auth_capability: Option<i32>,
        credential_cache_durability: Option<i32>,
        credential_callback: Option<PyObject>,
        credential_callback_name: Option<String>,
        allow_test_plugins: bool,
    ) -> PyResult<Self> {
        ovs::ensure_auth_substrate_with_default(auth_state_root).map_err(py_error)?;

        let durability = match credential_cache_durability.unwrap_or(0) {
            0 => CredentialCacheDurability::Persistent,
            1 => CredentialCacheDurability::InMemoryOnly,
            other => {
                return Err(py_error_msg(format!(
                    "invalid credential_cache_durability: {other}"
                )));
            }
        };
        let interactive_capability = match interactive_auth_capability {
            None => None,
            Some(0) => Some(InteractiveAuthCapability::Browser),
            Some(1) => Some(InteractiveAuthCapability::Headless),
            Some(2) => Some(InteractiveAuthCapability::None),
            Some(other) => {
                return Err(py_error_msg(format!(
                    "invalid interactive_auth_capability: {other}"
                )));
            }
        };
        let callback_provider = match (credential_callback, credential_callback_name) {
            (Some(callback), Some(name)) => {
                Some(build_python_callback_provider(py, name, callback)?)
            }
            (Some(_), None) => {
                return Err(py_error_msg(
                    "credential_callback_name must be provided when credential_callback is set",
                ));
            }
            _ => None,
        };

        let mut builder = RustLibrary::builder()
            .with_credential_cache_durability(durability)
            .allow_test_plugins(allow_test_plugins);
        if let Some(capability) = interactive_capability {
            builder = builder.interactive_auth_capability(capability);
        }
        if let Some(provider) = callback_provider {
            builder = builder.with_credential_providers(vec![provider]);
        }
        let inner = builder.open().map_err(py_error)?;
        Ok(Self { inner })
    }

    /// Inject a credential into the cache, bypassing the provider chain.
    /// Awaitable resolves to `None` once committed.
    ///
    /// `credential` is a dict with shape:
    /// ```python
    /// {
    ///   "source_name": "portal",
    ///   "expires_at_unix_nanos": 1700000000_000_000_000,  # optional
    ///   "fields": {"access_token": b"bearer-bytes"},
    /// }
    /// ```
    fn set_credential<'py>(
        &self,
        py: Python<'py>,
        backend_id: String,
        principal_id: String,
        credential: PyObject,
    ) -> PyResult<Bound<'py, PyAny>> {
        let resolved = resolved_credential_from_pydict(py, credential)?;
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.set_credential(
                BackendId(backend_id),
                PrincipalView::new(principal_id),
                resolved,
            )
            .await
            .map_err(py_error)
        })
    }

    #[pyo3(signature = (address, full_metadata = false))]
    fn stat<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        full_metadata: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.stat(addr, StatOptions { full_metadata }, Some(cancel))
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
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let opts = ReadOptions {
                max_bytes,
                ..ReadOptions::default()
            };
            let (bytes, info) = lib
                .read_bytes(addr, opts, Some(cancel))
                .await
                .map_err(py_error)?;
            Python::with_gil(|py| {
                let py_bytes: Py<PyBytes> = PyBytes::new_bound(py, &bytes).into();
                Ok((py_bytes, info_from_object(info)))
            })
        })
    }

    #[pyo3(signature = (address, max_bytes = None))]
    fn read_stream<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        max_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let opts = ReadOptions {
                max_bytes,
                ..ReadOptions::default()
            };
            let (stream, info) = lib
                .read_stream(addr, opts, Some(cancel))
                .await
                .map_err(py_error)?;
            Python::with_gil(|py| {
                let async_stream = AsyncReadStream {
                    inner: Arc::new(TokioMutex::new(Some(stream))),
                };
                let stream_py = Py::new(py, async_stream)?;
                Ok((stream_py, info_from_object(info)))
            })
        })
    }

    fn materialize<'py>(&self, py: Python<'py>, address: &str) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let delegate = lib
                .materialize(addr, ReadOptions::default(), Some(cancel))
                .await
                .map_err(py_error)?;
            Ok(LocalDelegate {
                inner: delegate,
                closed: false,
            })
        })
    }

    fn write<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        data: &[u8],
    ) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let body = Body::Bytes(data.to_vec());
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.write(addr, body, WriteOptions::default(), Some(cancel))
                .await
                .map(|result| info_from_object(result.info))
                .map_err(py_error)
        })
    }

    fn delete<'py>(&self, py: Python<'py>, address: &str) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.delete(addr, DeleteOptions::default(), Some(cancel))
                .await
                .map_err(py_error)
        })
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
        let opts = ListOptions {
            recursive,
            max_results,
            page_token,
            full_metadata,
        };
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let page = lib
                .list_page(prefix, opts, Some(cancel))
                .await
                .map_err(py_error)?;
            Ok(ListPage {
                items: page.items.into_iter().map(info_from_object).collect(),
                next_page_token: page.next_page_token,
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
        let options = ListVersionsOptions {
            max_results,
            page_token,
        };
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let backend_options = options.clone();
            let items = lib
                .list_versions(addr, backend_options, Some(cancel))
                .await
                .map_err(py_error)?;
            let (items, next_page_token) =
                paginate_versions(items, options.max_results, options.page_token)
                    .map_err(py_error)?;
            Ok(VersionPage {
                items: items.into_iter().map(info_from_object).collect(),
                next_page_token,
            })
        })
    }

    fn get_latest_version<'py>(
        &self,
        py: Python<'py>,
        address: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let item = lib
                .get_latest_version(addr, Some(cancel))
                .await
                .map_err(py_error)?;
            Ok(info_from_object(item))
        })
    }

    fn copy<'py>(&self, py: Python<'py>, src: &str, dest: &str) -> PyResult<Bound<'py, PyAny>> {
        let src = address::parse(src).map_err(py_error)?;
        let dest = address::parse(dest).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.copy(src, dest, CopyOptions::default(), Some(cancel))
                .await
                .map(|result| info_from_object(result.info))
                .map_err(py_error)
        })
    }

    fn rename<'py>(&self, py: Python<'py>, src: &str, dest: &str) -> PyResult<Bound<'py, PyAny>> {
        let src = address::parse(src).map_err(py_error)?;
        let dest = address::parse(dest).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.rename(src, dest, RenameOptions::default(), Some(cancel))
                .await
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (address))]
    fn create_directory<'py>(&self, py: Python<'py>, address: &str) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.create_directory(addr, CreateDirectoryOptions::default(), Some(cancel))
                .await
                .map(info_from_object)
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (address))]
    fn delete_directory<'py>(&self, py: Python<'py>, address: &str) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.delete_directory(addr, DeleteDirectoryOptions, Some(cancel))
                .await
                .map_err(py_error)
        })
    }

    #[pyo3(signature = (address, set = None, remove = None, message = None))]
    fn update_metadata<'py>(
        &self,
        py: Python<'py>,
        address: &str,
        set: Option<HashMap<String, String>>,
        remove: Option<Vec<String>>,
        message: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = UpdateMetadataOptions {
            user_metadata_set: set.unwrap_or_default(),
            user_metadata_remove: remove.unwrap_or_default(),
            message,
            ..UpdateMetadataOptions::default()
        };
        let addr = address::parse(address).map_err(py_error)?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.update_metadata(addr, options, Some(cancel))
                .await
                .map(info_from_object)
                .map_err(py_error)
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
        let addr = address::parse(address).map_err(py_error)?;
        let ops = AccessOps {
            read,
            write,
            delete,
            update_metadata,
        };
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            let decision = lib
                .check_access(addr, ops, Some(cancel))
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
}

#[pymethods]
impl LocalDelegate {
    #[getter]
    fn path(&self) -> String {
        self.inner.path.to_string_lossy().into_owned()
    }

    #[getter]
    fn info(&self) -> Info {
        info_from_object(self.inner.info.clone())
    }

    fn __fspath__(&self) -> String {
        self.inner.path.to_string_lossy().into_owned()
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
        ready_future(py, slf.into_py(py))
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
        ready_future(py, py.None())
    }

    fn close<'py>(mut slf: PyRefMut<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        slf.do_close();
        ready_future(py, py.None())
    }
}

impl LocalDelegate {
    fn do_close(&mut self) {
        if !self.closed {
            self.inner.guard.take();
            self.closed = true;
        }
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
        pyo3_tokio::future_into_py(py, async move {
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
                Some(Ok(bytes)) => Python::with_gil(|py| {
                    let py_bytes: Py<PyBytes> = PyBytes::new_bound(py, &bytes).into();
                    Ok(py_bytes)
                }),
            }
        })
    }
}

fn info_from_object(info: ObjectInfo) -> Info {
    Info {
        address: info.address.to_string(),
        kind: info.kind.as_str().into(),
        size: info.size,
        mtime_unix_nanos: info.mtime.and_then(|mtime| {
            mtime
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        }),
        etag: info.etag,
        version: info.version,
        system_metadata: info.system_metadata.unwrap_or_default(),
        user_metadata: info.user_metadata.unwrap_or_default(),
    }
}

fn paginate_versions(
    items: Vec<ObjectInfo>,
    max_results: Option<u32>,
    page_token: Option<String>,
) -> ovs::Result<(Vec<ObjectInfo>, Option<String>)> {
    let start = match page_token {
        Some(token) => token
            .parse::<usize>()
            .map_err(|_| ovs::Error::new(ovs::ErrorCode::InvalidArgument, "invalid page token"))?,
        None => 0,
    };
    if start > items.len() {
        return Err(ovs::Error::new(
            ovs::ErrorCode::InvalidArgument,
            "page token is out of range",
        ));
    }
    let Some(max_results) = max_results else {
        return Ok((items.into_iter().skip(start).collect(), None));
    };
    if max_results == 0 {
        return Err(ovs::Error::new(
            ovs::ErrorCode::InvalidArgument,
            "max_results must be greater than zero",
        ));
    }
    let end = (start + max_results as usize).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    Ok((
        items.into_iter().skip(start).take(end - start).collect(),
        next,
    ))
}

fn py_error(error: ovs::Error) -> PyErr {
    let code_str = format!("{:?}", error.code());
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
    Python::with_gil(|py| {
        let value = err.value_bound(py);
        let _ = value.setattr("code", code_str);
        let _ = value.setattr("next_action", next_action);
    });
    err
}

fn py_error_msg(message: impl Into<String>) -> PyErr {
    Error::new_err(message.into())
}

/// Build a `CallbackCredentialProvider` from a Python callable (sync or
/// `async def`). `asyncio.iscoroutinefunction` is checked once at
/// construction; the async path bridges via
/// `pyo3_async_runtimes::tokio::into_future` so the asyncio loop drives
/// the coroutine on the per-module tokio runtime.
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
                let coro = Python::with_gil(|py| {
                    let bound = callable.bind(py);
                    bound
                        .call1((backend_str.clone(), principal_str.clone()))
                        .map(|c| c.into_py(py))
                })
                .map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!("python callback raised: {e}"),
                    ))
                })?;
                let fut = Python::with_gil(|py| {
                    let bound = coro.into_bound(py);
                    pyo3_tokio::into_future(bound)
                })
                .map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!("python coroutine bridge failed: {e}"),
                    ))
                })?;
                let py_result = fut.await.map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!("python callback awaited error: {e}"),
                    ))
                })?;
                Python::with_gil(|py| {
                    let bound = py_result.into_bound(py);
                    resolved_credential_from_pyany(py, bound)
                })
                .map_err(|e| {
                    CredentialError::Backend(OvError::new(
                        ErrorCode::Internal,
                        format!("python coroutine returned non-credential value: {e}"),
                    ))
                })
            } else {
                Python::with_gil(|py| {
                    let bound = callable.bind(py);
                    let py_result = bound.call1((backend_str, principal_str)).map_err(|e| {
                        CredentialError::Backend(OvError::new(
                            ErrorCode::Internal,
                            format!("python callback raised: {e}"),
                        ))
                    })?;
                    resolved_credential_from_pyany(py, py_result).map_err(|e| {
                        CredentialError::Backend(OvError::new(
                            ErrorCode::Internal,
                            format!("python callback returned non-credential value: {e}"),
                        ))
                    })
                })
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
/// flock). Honors `OVSTORAGE_AUTH_DIR`; falls back to a per-process
/// `tempdir()` so no-config callers still get a working `Library`.
fn auth_state_root() -> ovs::Result<std::path::PathBuf> {
    if let Some(value) = std::env::var_os("OVSTORAGE_AUTH_DIR") {
        return Ok(std::path::PathBuf::from(value));
    }
    let tmp = std::env::temp_dir().join(format!("ovstorage-py-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|error| {
        ovs::Error::new(
            ErrorCode::Internal,
            format!("failed to create auth state root: {error}"),
        )
    })?;
    Ok(tmp)
}

/// Explicitly initialize the process-global auth substrate.
///
/// `auth_dir = None` resolves to `$OVSTORAGE_AUTH_DIR` or a per-process
/// temp dir. Calling this twice with the same path is a no-op; with a
/// different path raises.
///
/// `Library.open()` auto-initializes the substrate with defaults on
/// first call, so calling this function is only required when you want
/// to pin a non-default `auth_dir` before any `Library` is built.
#[pyfunction]
#[pyo3(signature = (auth_dir=None))]
fn init_auth_substrate(auth_dir: Option<String>) -> PyResult<()> {
    let auth_root = match auth_dir {
        Some(value) => std::path::PathBuf::from(value),
        None => auth_state_root().map_err(py_error)?,
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
        let sv = value
            .inner
            .lock()
            .map_err(|_| py_error_msg("SecretValue lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("SecretValue already consumed"))?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| py_error_msg("ConnectionRequest lock poisoned"))?;
        let req = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
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

#[pymethods]
impl SecretBundle {
    #[new]
    fn new() -> Self {
        Self {
            inner: StdMutex::new(Some(ovs::SecretBundle::default())),
        }
    }
    fn add(&self, key: String, value: &SecretValue) -> PyResult<()> {
        let sv = value
            .inner
            .lock()
            .map_err(|_| py_error_msg("SecretValue lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("SecretValue already consumed"))?;
        let mut guard = self.inner.lock().map_err(|_| py_error_msg("lock"))?;
        let bundle = guard
            .as_mut()
            .ok_or_else(|| py_error_msg("SecretBundle already consumed"))?;
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
        pyo3_tokio::future_into_py(py, async move {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                None => Err(PyStopAsyncIteration::new_err(())),
                Some(Err(err)) => Err(py_error(err)),
                Some(Ok(event)) => Ok(AuthEvent { inner: event }),
            }
        })
    }
}

/// Drive a synchronous plugin iterator on one dedicated `spawn_blocking`
/// worker per stream, forwarding into a bounded `mpsc::channel(8)`. The
/// producer exits on iterator end, receiver drop, or cancel-token trip
/// between iterations.
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
    tokio::task::spawn_blocking(move || {
        let mut iter = iter;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match iter.next() {
                None => break,
                Some(item) => {
                    if tx.blocking_send(item).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
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
        pyo3_tokio::future_into_py(py, async move {
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

#[pymethods]
impl Library {
    fn add_connection<'py>(
        &self,
        py: Python<'py>,
        request: &ConnectionRequest,
    ) -> PyResult<Bound<'py, PyAny>> {
        let req = request
            .inner
            .lock()
            .map_err(|_| py_error_msg("ConnectionRequest lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("ConnectionRequest already consumed"))?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.add_connection(req, Some(cancel))
                .await
                .map(|conn| Connection { inner: conn })
                .map_err(py_error)
        })
    }

    /// Load and register a single plugin cdylib at `path`. Caller must trust
    /// the path — `dlopen` runs platform loader hooks.
    fn load_plugin<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            // SAFETY: dlopen runs platform loader hooks; caller-provided trust.
            unsafe { lib.load_plugin(std::path::Path::new(&path)) }.map_err(py_error)
        })
    }

    /// Scan `dir` for `libovstorage_plugin_*.{so,dylib,dll}` and load each.
    /// `dir=None` resolves to `OVSTORAGE_PLUGIN_DIR` or `<exe-dir>/plugins/`.
    fn load_plugins_from_dir<'py>(
        &self,
        py: Python<'py>,
        dir: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            let dir_path = dir.as_deref().map(std::path::Path::new);
            // SAFETY: each candidate is dlopen'd in-process; trust the directory.
            unsafe { lib.load_plugins_from_dir(dir_path) }.map_err(py_error)
        })
    }

    /// Load `ovstorage.toml` and register its `[[connections]]` on this
    /// library. `path=None` uses the default search path
    /// (`./ovstorage.toml`, then `$XDG_CONFIG_HOME/ovstorage/ovstorage.toml`).
    /// Returns the freshly registered list (empty when no file found).
    fn load_config<'py>(
        &self,
        py: Python<'py>,
        path: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            let cfg_path = path.as_deref().map(std::path::Path::new);
            lib.load_config(cfg_path)
                .await
                .map(|connections| {
                    connections
                        .into_iter()
                        .map(|c| Connection { inner: c })
                        .collect::<Vec<_>>()
                })
                .map_err(py_error)
        })
    }

    fn remove_connection<'py>(
        &self,
        py: Python<'py>,
        connection_id: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.remove_connection(&ovs::ConnectionId(connection_id))
                .map_err(py_error)
        })
    }

    fn list_connections<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.list_connections()
                .map(|connections| {
                    connections
                        .into_iter()
                        .map(|c| Connection { inner: c })
                        .collect::<Vec<_>>()
                })
                .map_err(py_error)
        })
    }

    fn update_connection_credentials<'py>(
        &self,
        py: Python<'py>,
        connection_id: String,
        credentials: &SecretBundle,
    ) -> PyResult<Bound<'py, PyAny>> {
        let bundle = credentials
            .inner
            .lock()
            .map_err(|_| py_error_msg("SecretBundle lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("SecretBundle already consumed"))?;
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let _guard = cancel.clone().drop_guard();
            lib.update_connection_credentials(
                &ovs::ConnectionId(connection_id),
                bundle,
                Some(cancel),
            )
            .await
            .map(|conn| Connection { inner: conn })
            .map_err(py_error)
        })
    }

    fn authenticate_connection<'py>(
        &self,
        py: Python<'py>,
        connection_id: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let stream = lib
                .authenticate_connection(&ovs::ConnectionId(connection_id), Some(cancel.clone()))
                .await
                .map_err(py_error)?;
            let rx = spawn_blocking_iterator_producer(stream, cancel.clone());
            Python::with_gil(|py| {
                let s = AsyncAuthEventStream {
                    rx: Arc::new(TokioMutex::new(rx)),
                    cancel,
                };
                Py::new(py, s)
            })
        })
    }

    fn add_alias<'py>(
        &self,
        py: Python<'py>,
        request: &AliasRequest,
    ) -> PyResult<Bound<'py, PyAny>> {
        let req = request
            .inner
            .lock()
            .map_err(|_| py_error_msg("AliasRequest lock poisoned"))?
            .take()
            .ok_or_else(|| py_error_msg("AliasRequest already consumed"))?;
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.add_alias(req)
                .map(|alias| Alias { inner: alias })
                .map_err(py_error)
        })
    }

    fn remove_alias<'py>(&self, py: Python<'py>, alias_id: String) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.remove_alias(&ovs::AliasId(alias_id)).map_err(py_error)
        })
    }

    fn list_aliases<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.list_aliases()
                .map(|aliases| {
                    aliases
                        .into_iter()
                        .map(|a| Alias { inner: a })
                        .collect::<Vec<_>>()
                })
                .map_err(py_error)
        })
    }

    fn set_address_visibility<'py>(
        &self,
        py: Python<'py>,
        address: String,
        visibility: &str,
        persist: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let addr = address::parse(&address).map_err(py_error)?;
        let v = match visibility {
            "Visible" => ovs::AddressVisibility::Visible,
            "Hidden" => ovs::AddressVisibility::Hidden,
            "Suppressed" => ovs::AddressVisibility::Suppressed,
            other => return Err(py_error_msg(format!("unknown visibility: {other}"))),
        };
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.set_address_visibility(addr, v, persist)
                .map(|o| AddressVisibilityOverride { inner: o })
                .map_err(py_error)
        })
    }

    fn list_address_visibility_overrides<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.list_address_visibility_overrides()
                .map(|items| {
                    items
                        .into_iter()
                        .map(|o| AddressVisibilityOverride { inner: o })
                        .collect::<Vec<_>>()
                })
                .map_err(py_error)
        })
    }

    fn list_address_roots<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.list_address_roots()
                .map(|items| {
                    items
                        .into_iter()
                        .map(|r| AddressRoot { inner: r })
                        .collect::<Vec<_>>()
                })
                .map_err(py_error)
        })
    }

    fn watch_address_roots<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        let cancel = CancellationToken::new();
        cancellable_future_into_py(py, cancel.clone(), async move {
            let stream = lib
                .watch_address_roots(Some(cancel.clone()))
                .map_err(py_error)?;
            let rx = spawn_blocking_iterator_producer(stream, cancel.clone());
            Python::with_gil(|py| {
                let s = AsyncAddressRootSnapshotStream {
                    rx: Arc::new(TokioMutex::new(rx)),
                    cancel,
                };
                Py::new(py, s)
            })
        })
    }

    fn list_backend_kinds<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.list_backend_kinds()
                .map(|items| {
                    items
                        .into_iter()
                        .map(|d| BackendKindDescriptor { inner: d })
                        .collect::<Vec<_>>()
                })
                .map_err(py_error)
        })
    }

    fn capabilities_for<'py>(
        &self,
        py: Python<'py>,
        prefix: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let url = address::parse(&prefix).map_err(py_error)?;
        let lib = self.inner.clone();
        pyo3_tokio::future_into_py(py, async move {
            lib.capabilities_for(&url)
                .map(|caps| Capabilities { inner: caps })
                .map_err(py_error)
        })
    }
}

#[pymodule]
fn ovstorage(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.worker_threads(2).enable_all().thread_name("ovs-py");
    pyo3_tokio::init(builder);

    module.add("__version__", "0.1.0")?;
    module.add("Error", py.get_type_bound::<Error>())?;
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
    module.add_class::<Library>()?;
    module.add_class::<Info>()?;
    module.add_class::<ListPage>()?;
    module.add_class::<VersionPage>()?;
    module.add_class::<LocalDelegate>()?;
    module.add_class::<AccessDecision>()?;
    module.add_class::<AsyncReadStream>()?;
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
    module.add_class::<PyCredentialCacheDurability>()?;
    module.add_class::<PyInteractiveAuthCapability>()?;
    module.add_function(wrap_pyfunction!(init_auth_substrate, module)?)?;
    Ok(())
}

// pyo3 `extension-module` cannot link a `cargo test` binary (no CPython
// symbols). Tests below are gated behind `no-extension-module-link`
// for downstreams that drop the feature; pytest runs `tests/*.py`.
#[cfg(test)]
#[cfg(feature = "no-extension-module-link")]
mod tests {
    use super::*;

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
}
