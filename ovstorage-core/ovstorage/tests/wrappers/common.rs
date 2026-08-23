// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared probe backends and request/stack helpers for the per-family
//! wrapper test modules.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::StreamExt as _;

use ovstorage::{
    AddressVisibility, BackendFactory, BackendItemInfo, Body, BodyStream, CancellationToken,
    Capabilities, ChangeEvent, ChangeKind, ChangeStream, ChecksumSet, ConfigLayer, ConfigValue,
    ContinueWriteRequest, CopyRequest, CreateDirectoryRequest, DeleteDirectoryRequest,
    DeleteRequest, Error, ErrorCode, Layer, LayerConfig, LayerHandle, LayerKindDescriptor,
    LayerSpec, LayerType, ListPage, ListRequest, LocalDelegate, ObjectInfo, ObjectKind,
    RangeReadStrategy, ReadOptions, ReadRedirect, ReadRequest, ReadResult, RedirectResultBatch,
    RenameRequest, Request, Result, RootInfo, RouteSource, Stack, StatRequest,
    UpdateMetadataRequest, Url, UserMetadata, WatchDirectoryCursor, WatchDirectoryRequest,
    WrapperFactory, WriteRedirectBatch, WriteRequest, WriteResult, WriteStep,
};

pub(crate) const PROBE_KIND: &str = "probe";

/// What the probe backend's `read` returns.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReadPlan {
    /// Fail the first `fail` read attempts with `code`, then succeed with
    /// `body`. `fail = 0` always succeeds immediately.
    FlakyBytes {
        fail: usize,
        code: ErrorCode,
        body: Vec<u8>,
    },
    /// Always answer `read` with this redirect.
    Redirect(ReadRedirect),
}

/// A programmable leaf backend Layer. Counts `read` and `write_stream`
/// attempts so tests can assert exactly how many times the wrapper re-invoked
/// the inner Layer. Only the slots the tests touch are implemented; the rest
/// inherit the `Layer` trait's `Unsupported` defaults.
pub(crate) struct ProbeBackend {
    pub(crate) reads: AtomicUsize,
    pub(crate) write_stream_calls: AtomicUsize,
    pub(crate) plan: ReadPlan,
    stat_mtime: Option<SystemTime>,
}

impl ProbeBackend {
    pub(crate) fn flaky(fail: usize, code: ErrorCode, body: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            reads: AtomicUsize::new(0),
            write_stream_calls: AtomicUsize::new(0),
            plan: ReadPlan::FlakyBytes {
                fail,
                code,
                body: body.to_vec(),
            },
            stat_mtime: None,
        })
    }

    pub(crate) fn redirecting(redirect: ReadRedirect) -> Arc<Self> {
        Arc::new(Self {
            reads: AtomicUsize::new(0),
            write_stream_calls: AtomicUsize::new(0),
            plan: ReadPlan::Redirect(redirect),
            stat_mtime: None,
        })
    }

    pub(crate) fn redirecting_with_stat_mtime(
        redirect: ReadRedirect,
        stat_mtime: SystemTime,
    ) -> Arc<Self> {
        Arc::new(Self {
            reads: AtomicUsize::new(0),
            write_stream_calls: AtomicUsize::new(0),
            plan: ReadPlan::Redirect(redirect),
            stat_mtime: Some(stat_mtime),
        })
    }
}

#[async_trait]
impl Layer for ProbeBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let Some(mtime) = self.stat_mtime else {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "probe stat is not configured",
            ));
        };
        let mut info = object_info(request.input.address, 0);
        info.mtime = Some(mtime);
        Ok(info)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let attempt = self.reads.fetch_add(1, Ordering::SeqCst);
        match &self.plan {
            ReadPlan::FlakyBytes { fail, code, body } => {
                if attempt < *fail {
                    Err(Error::new(*code, "injected read failure"))
                } else {
                    Ok(ReadResult::Bytes {
                        bytes: body.clone(),
                        info: object_info(request.input.address, body.len() as u64),
                    })
                }
            }
            ReadPlan::Redirect(redirect) => Ok(ReadResult::Redirect(redirect.clone())),
        }
    }

    async fn write_stream(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write_stream_calls.fetch_add(1, Ordering::SeqCst);
        Err(Error::new(
            ErrorCode::Transient,
            "injected write_stream failure",
        ))
    }
}

/// Backend factory that hands out one shared backend `Layer` so the test keeps
/// a typed handle to its call counters.
pub(crate) struct SharedBackendFactory {
    pub(crate) backend: LayerHandle,
}

#[async_trait]
impl BackendFactory for SharedBackendFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(self.backend.clone())
    }
}

/// A backend whose `write` fails `fail` times transiently then succeeds,
/// counting attempts — exercises `RetryWrapper::write`'s buffered-`Body::Bytes`
/// retry. `write_redirect` always declines with `Unsupported`, so a
/// `RedirectFollower` composed above the retry layer falls through into
/// `RetryWrapper::write`.
pub(crate) struct FlakyWriteBackend {
    pub(crate) writes: AtomicUsize,
    pub(crate) write_redirects: AtomicUsize,
    pub(crate) fail: usize,
}

impl FlakyWriteBackend {
    pub(crate) fn new(fail: usize) -> Arc<Self> {
        Arc::new(Self {
            writes: AtomicUsize::new(0),
            write_redirects: AtomicUsize::new(0),
            fail,
        })
    }
}

#[async_trait]
impl Layer for FlakyWriteBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let attempt = self.writes.fetch_add(1, Ordering::SeqCst);
        if attempt < self.fail {
            Err(Error::new(ErrorCode::Transient, "injected write failure"))
        } else {
            Ok(WriteResult {
                info: object_info(request.input.address, 0),
            })
        }
    }

    async fn write_redirect(
        &self,
        _request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        self.write_redirects.fetch_add(1, Ordering::SeqCst);
        Err(Error::new(
            ErrorCode::Unsupported,
            "backend does not redirect writes",
        ))
    }
}

pub(crate) fn backend_descriptor(kind: &str) -> LayerKindDescriptor {
    LayerKindDescriptor {
        display_name: kind.to_string(),
        kind: kind.to_string(),
        layer_type: LayerType::Backend,
        description: None,
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: true,
    }
}

pub(crate) fn object_info(address: Url, size: u64) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(size),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

/// A retry-policy `LayerConfig` with zero delays so tests don't sleep.
pub(crate) fn retry_config(max_attempts: i64) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert("initial_delay_ms".into(), ConfigValue::Int(0));
    config.insert("max_delay_ms".into(), ConfigValue::Int(0));
    config.insert("max_attempts".into(), ConfigValue::Int(max_attempts));
    config
}

pub(crate) fn read_request(url: &str) -> Request<ReadRequest> {
    Request::new(ReadRequest {
        address: Url::parse(url).unwrap(),
        options: ReadOptions::default(),
    })
}

/// Compose `wrapper_kind` (registered via `wrapper_factory`) above the shared
/// `backend`, returning the built `Stack` (or the build error).
pub(crate) async fn build_stack(
    wrapper_kind: &str,
    wrapper_factory: Arc<dyn WrapperFactory>,
    backend: LayerHandle,
    config: LayerConfig,
) -> Result<Stack> {
    let mut wrapper_spec = LayerSpec::wrapper("wrapper", wrapper_kind, "backend");
    wrapper_spec.config = config;
    Stack::builder("wrapper")
        .wrapper_factory(wrapper_factory)
        .backend_factory(Arc::new(SharedBackendFactory { backend }))
        .layer(wrapper_spec)
        .layer(LayerSpec::backend("backend", PROBE_KIND))
        .build()
        .await
}

/// A `Body::Stream` yielding `bytes` as a single chunk — a one-shot,
/// non-replayable body for the consume-once tests.
pub(crate) fn stream_body(bytes: &[u8]) -> Body {
    let chunk: Result<Vec<u8>> = Ok(bytes.to_vec());
    Body::Stream(BodyStream::from_iter(std::iter::once(chunk)))
}

/// A `Body::Stream` yielding `bytes` in `chunk_size`-byte chunks — a multi-chunk
/// streamed write body (the write-tee spools chunk-by-chunk, so a cap breach or
/// mid-stream mutation must be exercised across several chunks, not one).
pub(crate) fn chunked_stream_body(bytes: &[u8], chunk_size: usize) -> Body {
    let chunk_size = chunk_size.max(1);
    let bytes = bytes.to_vec();
    let mut offset = 0;
    Body::Stream(BodyStream::from_iter(std::iter::from_fn(move || {
        if offset >= bytes.len() {
            return None;
        }
        let end = (offset + chunk_size).min(bytes.len());
        let chunk = bytes[offset..end].to_vec();
        offset = end;
        Some(Ok(chunk))
    })))
}

pub(crate) async fn collect(result: ReadResult) -> Vec<u8> {
    match result {
        ReadResult::Bytes { bytes, .. } => bytes,
        ReadResult::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("stream chunk"));
            }
            out
        }
        // Cache hits for non-buffering callers are served as LocalDelegate
        // (bounded memory); read the file to compare bytes in tests.
        ReadResult::LocalDelegate(local) => tokio::fs::read(&local.path)
            .await
            .expect("collect: LocalDelegate read"),
        other => panic!("unexpected read result: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// ByteCacheWrapper / MetadataCacheWrapper
// ---------------------------------------------------------------------------

/// A backend Layer for the cache wrappers: `read`/`stat` return fixed content,
/// `list` returns fixed items, mutating ops succeed; every slot counts calls so
/// tests can assert a cache hit avoided a backend round-trip.
pub(crate) struct CacheProbe {
    pub(crate) content: Vec<u8>,
    pub(crate) list_items: Vec<ObjectInfo>,
    /// On-disk file the backend's `materialize` hands back (its bytes are
    /// `content`); `None` for backends whose tests never call `materialize`.
    pub(crate) materialize_source: Option<PathBuf>,
    /// When true, `continue_write` returns `WriteStep::Redirects` (mid-flight)
    /// instead of `WriteStep::Done` (terminal) — exercises the negative
    /// invalidation contract: a non-terminal step must NOT touch the cache.
    pub(crate) continue_redirects: bool,
    pub(crate) reads: AtomicUsize,
    pub(crate) stats: AtomicUsize,
    pub(crate) lists: AtomicUsize,
    pub(crate) materializes: AtomicUsize,
    /// Monotonic object version: `stat`/`read`/`materialize` report
    /// `etag = Some("v{n}")` and every mutation bumps it, so the byte-cache
    /// wrapper's validator-keyed entries become unreachable after a
    /// mutation exactly as a real backend's etag change would make them.
    pub(crate) version: AtomicUsize,
    /// When set, `stat` errs with this code — drives the byte-cache
    /// wrapper's stat-error discrimination (availability fallback vs
    /// definitive answer vs propagation).
    pub(crate) stat_error: std::sync::Mutex<Option<ovstorage::ErrorCode>>,
    /// When set, `delete` errs with this code without bumping the version —
    /// a mutation the backend refused, or one whose outcome the caller cannot
    /// determine.
    pub(crate) delete_error: std::sync::Mutex<Option<ovstorage::ErrorCode>>,
    /// When set, `read` errs with this code. Paired with `stat_error` it gives
    /// a request the backend refuses OUTRIGHT, which is the only way to observe
    /// what a refused read leaves behind: with `stat_error` alone the read still
    /// succeeds and legitimately caches a body, so anything the read path
    /// records is indistinguishable from the commit point recording it.
    pub(crate) read_error: std::sync::Mutex<Option<ovstorage::ErrorCode>>,
    /// When set, `stat` reports no etag while `read` still does.
    pub(crate) stat_omits_validator: AtomicBool,
    /// When set, `read` answers `ReadResult::Stream` rather than `Bytes`, so
    /// the byte cache fills through its streaming tee instead of
    /// `fill_and_publish`.
    pub(crate) read_streams: AtomicBool,
}

impl CacheProbe {
    pub(crate) fn build(
        content: &[u8],
        list_items: Vec<ObjectInfo>,
        materialize_source: Option<PathBuf>,
        continue_redirects: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            content: content.to_vec(),
            list_items,
            materialize_source,
            continue_redirects,
            reads: AtomicUsize::new(0),
            stats: AtomicUsize::new(0),
            lists: AtomicUsize::new(0),
            materializes: AtomicUsize::new(0),
            version: AtomicUsize::new(1),
            stat_error: std::sync::Mutex::new(None),
            read_error: std::sync::Mutex::new(None),
            delete_error: std::sync::Mutex::new(None),
            stat_omits_validator: AtomicBool::new(false),
            read_streams: AtomicBool::new(false),
        })
    }

    /// Answer reads as a stream, so the byte cache fills through its tee.
    pub(crate) fn stream_reads(&self) {
        self.read_streams.store(true, Ordering::SeqCst);
    }

    /// A backend that names a version on its `read` but not on its `stat` — a
    /// redirecting backend, where the location the read follows carries the
    /// validator and the metadata call cannot. It is the shape that separates
    /// the byte cache's registration on the way IN to a read (keyed on the
    /// stat's validator, so absent here) from the one at the commit point.
    pub(crate) fn omit_stat_validator(&self) {
        self.stat_omits_validator.store(true, Ordering::SeqCst);
    }

    pub(crate) fn new(content: &[u8], list_items: Vec<ObjectInfo>) -> Arc<Self> {
        Self::build(content, list_items, None, false)
    }

    pub(crate) fn materializing(content: &[u8], source: PathBuf) -> Arc<Self> {
        Self::build(content, Vec::new(), Some(source), false)
    }

    /// A backend whose `continue_write` reports a mid-flight
    /// `WriteStep::Redirects` rather than a terminal `Done`.
    pub(crate) fn redirecting_continue(content: &[u8], list_items: Vec<ObjectInfo>) -> Arc<Self> {
        Self::build(content, list_items, None, true)
    }
}

impl CacheProbe {
    /// The current validator, matching what a mutation-bumped backend would
    /// report.
    pub(crate) fn etag(&self) -> String {
        format!("v{}", self.version.load(Ordering::SeqCst))
    }

    /// Advance the object version — a mutation (or an out-of-band change a
    /// test simulates) invalidates every already-issued validator.
    pub(crate) fn bump_version(&self) {
        self.version.fetch_add(1, Ordering::SeqCst);
    }

    /// Set the object version directly (an out-of-band revert a test
    /// simulates: a validator seen before becomes current again).
    pub(crate) fn set_version(&self, version: usize) {
        self.version.store(version, Ordering::SeqCst);
    }

    /// Make `stat` err with `code` (or answer normally again with `None`).
    pub(crate) fn set_stat_error(&self, code: Option<ovstorage::ErrorCode>) {
        *self.stat_error.lock().unwrap() = code;
    }

    /// Make `read` err with `code` (or succeed again with `None`).
    pub(crate) fn set_read_error(&self, code: Option<ovstorage::ErrorCode>) {
        *self.read_error.lock().unwrap() = code;
    }

    /// Make `delete` err with `code` (or succeed again with `None`).
    pub(crate) fn set_delete_error(&self, code: Option<ovstorage::ErrorCode>) {
        *self.delete_error.lock().unwrap() = code;
    }

    fn versioned_info(&self, address: Url, size: u64) -> ObjectInfo {
        let mut info = object_info(address, size);
        info.etag = Some(self.etag());
        info
    }
}

#[async_trait]
impl Layer for CacheProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = *self.read_error.lock().unwrap() {
            return Err(Error::new(code, "injected read failure"));
        }
        let info = self.versioned_info(request.input.address, self.content.len() as u64);
        if self.read_streams.load(Ordering::SeqCst) {
            let body = bytes::Bytes::from(self.content.clone());
            let stream: ovstorage::ReadStream = Box::pin(futures::stream::iter([Ok(body)]));
            return Ok(ReadResult::Stream { stream, info });
        }
        Ok(ReadResult::Bytes {
            bytes: self.content.clone(),
            info,
        })
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stats.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(Error::new(code, "scripted stat failure"));
        }
        let mut info = self.versioned_info(request.input.address, self.content.len() as u64);
        if self.stat_omits_validator.load(Ordering::SeqCst) {
            info.etag = None;
        }
        Ok(info)
    }

    async fn list(
        &self,
        _request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        Ok(ListPage {
            items: self.list_items.clone(),
            next_page_token: None,
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.bump_version();
        Ok(WriteResult {
            info: self.versioned_info(request.input.address, 0),
        })
    }

    async fn delete(
        &self,
        _request: Request<DeleteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if let Some(code) = *self.delete_error.lock().unwrap() {
            return Err(ovstorage::Error::new(code, "delete refused by the probe"));
        }
        self.bump_version();
        Ok(())
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.bump_version();
        Ok(WriteResult {
            info: self.versioned_info(request.input.address, 0),
        })
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        if self.continue_redirects {
            // Mid-flight: more redirect rounds remain — NOT a terminal step.
            return Ok(WriteStep::Redirects(WriteRedirectBatch {
                continuation: Vec::new(),
                redirects: Vec::new(),
            }));
        }
        // Terminal completion of the direct write_redirect→continue_write API.
        self.bump_version();
        Ok(WriteStep::Done(WriteResult {
            info: self.versioned_info(request.input.address, 0),
        }))
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.materializes.fetch_add(1, Ordering::SeqCst);
        let path = self
            .materialize_source
            .clone()
            .expect("materialize_source set");
        Ok(LocalDelegate {
            path,
            info: self.versioned_info(request.input.address, self.content.len() as u64),
            guard: None,
        })
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        self.bump_version();
        Ok(WriteStep::Done(WriteResult {
            info: self.versioned_info(request.input.destination, 0),
        }))
    }

    async fn rename(
        &self,
        _request: Request<RenameRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.bump_version();
        Ok(())
    }

    async fn update_metadata(
        &self,
        _request: Request<UpdateMetadataRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.bump_version();
        Ok(backend_item_info())
    }

    async fn create_directory(
        &self,
        _request: Request<CreateDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        Ok(backend_item_info())
    }

    async fn watch_directory(
        &self,
        _request: Request<WatchDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        // Emit one `Created` event per configured list item so a test can
        // observe the `MetadataCacheWrapper` invalidating cached entries as
        // watch events flow through.
        let items = self.list_items.clone();
        Ok(Box::new(items.into_iter().map(|item| {
            Ok(ChangeEvent::Object {
                address: item.address,
                kind: ChangeKind::Created,
                etag: None,
                version: None,
                size: item.size,
                mtime: None,
                at: SystemTime::now(),
                cursor: WatchDirectoryCursor::default(),
            })
        })))
    }

    async fn delete_directory(
        &self,
        _request: Request<DeleteDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.bump_version();
        Ok(())
    }
}

/// A backend whose `read` returns a chunked `ReadResult::Stream` (chunk size
/// configurable), for exercising the byte-cache stream tee. `stat` reports the
/// same identity the stream carries, so the wrapper's stat-first lookup keys on
/// the same validator the tee commits under.
pub(crate) struct StreamProbe {
    content: Vec<u8>,
    chunk_size: usize,
    etag: Option<String>,
    pub(crate) reads: AtomicUsize,
    pub(crate) stats: AtomicUsize,
}

impl StreamProbe {
    pub(crate) fn new(content: &[u8], chunk_size: usize, etag: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            content: content.to_vec(),
            chunk_size: chunk_size.max(1),
            etag: etag.map(str::to_string),
            reads: AtomicUsize::new(0),
            stats: AtomicUsize::new(0),
        })
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: self.etag.clone(),
            ..object_info(address, self.content.len() as u64)
        }
    }
}

#[async_trait]
impl Layer for StreamProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stats.fetch_add(1, Ordering::SeqCst);
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let chunks: Vec<Result<bytes::Bytes>> = self
            .content
            .chunks(self.chunk_size)
            .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
            .collect();
        let stream: ovstorage::ReadStream = Box::pin(futures::stream::iter(chunks));
        Ok(ReadResult::Stream {
            stream,
            info: self.info(request.input.address),
        })
    }
}

/// A backend whose `read` returns a `ReadResult::LocalDelegate` pointing at a
/// fixed on-disk file, for exercising the brokered-delegate warm path and its
/// pre-read cap. `info.size` is the declared size (the real file length);
/// `stat` reports the same identity.
pub(crate) struct DelegateReadProbe {
    path: PathBuf,
    size: u64,
    etag: Option<String>,
    pub(crate) reads: AtomicUsize,
    pub(crate) stats: AtomicUsize,
}

impl DelegateReadProbe {
    pub(crate) fn new(path: PathBuf, etag: Option<&str>) -> Arc<Self> {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Arc::new(Self {
            path,
            size,
            etag: etag.map(str::to_string),
            reads: AtomicUsize::new(0),
            stats: AtomicUsize::new(0),
        })
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: self.etag.clone(),
            ..object_info(address, self.size)
        }
    }
}

#[async_trait]
impl Layer for DelegateReadProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stats.fetch_add(1, Ordering::SeqCst);
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(ReadResult::LocalDelegate(LocalDelegate {
            path: self.path.clone(),
            info: self.info(request.input.address),
            guard: None,
        }))
    }
}

pub(crate) fn backend_item_info() -> BackendItemInfo {
    BackendItemInfo {
        kind: ObjectKind::File,
        etag: None,
        version: None,
        size: Some(0),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

pub(crate) fn empty_continue_write(address: &str) -> Request<ContinueWriteRequest> {
    Request::new(ContinueWriteRequest {
        address: Url::parse(address).unwrap(),
        redirects: WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: Vec::new(),
        },
        results: RedirectResultBatch {
            results: Vec::new(),
        },
    })
}

/// A minimal `RootInfo` for a physical root `prefix`, `Visible`/`Static`.
pub(crate) fn test_root(prefix: &str) -> RootInfo {
    RootInfo {
        root: Url::parse(prefix).unwrap(),
        display_name: None,
        layer_kind: PROBE_KIND.to_string(),
        connection_id: None,
        owning_target: None,
        capabilities: Capabilities::empty(),
        range_read_strategy: RangeReadStrategy::default(),
        source: RouteSource::Static {
            layer: ConfigLayer::Programmatic,
        },
        visible: true,
        visibility: AddressVisibility::Visible,
        alias_state: None,
        icon: None,
        user_metadata: UserMetadata::default(),
    }
}
