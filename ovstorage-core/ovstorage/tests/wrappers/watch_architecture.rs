// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Final-state integration coverage for cache notification drains: each cache
//! wrapper opens its own recursive, metadata-bearing watch on the backend to
//! invalidate its entries on change.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ovstorage::layers::{BYTE_CACHE_KIND, METADATA_CACHE_KIND};
use ovstorage::{
    CancellationToken, ChangeEvent, ChangeKind, ChangeStream, ConfigValue, ConnectionId, ErrorCode,
    Layer, LayerConfig, LayerHandle, LayerKindDescriptor, LayerSpec, ListOptions, ListPage,
    ListRequest, ObjectInfo, ObjectKind, ReadRequest, ReadResult, Request, Result, RootInfo,
    RootInfoChange, RootInfoSnapshot, RootInfoUpdateStream, Stack, StatOptions, StatRequest, Url,
    WatchDirectoryCursor, WatchDirectoryOptions, WatchDirectoryRequest,
};
use ovstorage_plugin_cache::{ByteCacheWrapperFactory, MetadataCacheWrapperFactory};

use crate::common::*;

#[derive(Default)]
struct WatchQueue {
    events: Mutex<VecDeque<ChangeEvent>>,
    ready: Condvar,
    opens: AtomicUsize,
    active: AtomicUsize,
    options: Mutex<Vec<WatchDirectoryOptions>>,
    prefixes: Mutex<Vec<Url>>,
    scopes: Mutex<Vec<Option<Vec<u8>>>>,
    credentials: Mutex<Vec<bool>>,
}

struct CountingWatchBackend {
    inner: Arc<CacheProbe>,
    queue: Arc<WatchQueue>,
    supports_watch: bool,
    watch_open: WatchOpen,
    // Update streams handed out on successive `list_address_roots` calls: the
    // first at Stack build, later ones on each resnapshot/resubscribe. A test
    // that queues more than one exercises the replacement-stream adoption path.
    root_update_streams: Mutex<VecDeque<RootInfoUpdateStream>>,
    // Count of `list_address_roots` calls, so tests can assert a resnapshot ran.
    list_calls: AtomicUsize,
    // Per-call scripted outcomes for successive `list_address_roots` calls
    // (popped front-first): `Some(code)` fails that call, `None` forces a normal
    // snapshot for that call. Once this queue drains, calls fall back to
    // `persistent_list_error`. Lets a test drive an initial discovery failure and
    // its retry, or a first success followed by later failures.
    list_errors: Mutex<VecDeque<Option<ErrorCode>>>,
    // Error returned by every `list_address_roots` call once `list_errors` is
    // exhausted; `None` means fall through to a normal snapshot.
    persistent_list_error: Mutex<Option<ErrorCode>>,
}

#[derive(Clone)]
enum WatchOpen {
    Park,
    Finite,
    Error(ErrorCode),
    Blocked(Arc<std::sync::atomic::AtomicBool>),
    /// The first open ends immediately (empty, like `Finite`), forcing a
    /// backoff reconnect; every later open blocks until the flag is set, then
    /// parks. Lets a test prime the cache while the SECOND open is held open
    /// (before its activation sweep) to prove the reopen re-arms the sweep.
    FiniteThenBlocked(Arc<std::sync::atomic::AtomicBool>),
    /// Refuses every RECURSIVE open and parks non-recursive ones. Models the
    /// refusals recursion can actually cause: the file backend walks descendant
    /// directories to build a recursive watch's snapshot, so one the filesystem
    /// denies fails the recursive form only, and the Storage Service client maps
    /// recursion onto a wider remote filter.
    RefuseRecursive {
        code: ErrorCode,
    },
    /// Refuses any open whose prefix is not strictly under `allowed`, and parks
    /// the rest. Models a least-privilege policy that grants `watch_directory`
    /// on a subtree and not on the root above it.
    RefuseUnlessUnder {
        allowed: Url,
        code: ErrorCode,
        /// An open on exactly this prefix never returns, modelling a watch that
        /// is selected but whose stream has not come up yet.
        stall: Option<Url>,
    },
}

impl CountingWatchBackend {
    fn new(inner: Arc<CacheProbe>) -> Arc<Self> {
        Self::with_watch_behavior(inner, true, WatchOpen::Park)
    }

    fn with_watch_behavior(
        inner: Arc<CacheProbe>,
        supports_watch: bool,
        watch_open: WatchOpen,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            queue: Arc::new(WatchQueue::default()),
            supports_watch,
            watch_open,
            root_update_streams: Mutex::new(VecDeque::new()),
            list_calls: AtomicUsize::new(0),
            list_errors: Mutex::new(VecDeque::new()),
            persistent_list_error: Mutex::new(None),
        })
    }

    /// A backend whose successive `list_address_roots` calls first return the
    /// scripted `errors` (front-first) and then a normal watch-capable snapshot,
    /// so a test can exercise an initial discovery failure and its recovery.
    fn with_initial_list_errors(inner: Arc<CacheProbe>, errors: Vec<ErrorCode>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            queue: Arc::new(WatchQueue::default()),
            supports_watch: true,
            watch_open: WatchOpen::Park,
            root_update_streams: Mutex::new(VecDeque::new()),
            list_calls: AtomicUsize::new(0),
            list_errors: Mutex::new(errors.into_iter().map(Some).collect()),
            persistent_list_error: Mutex::new(None),
        })
    }

    /// A backend whose initial discovery fails retryably with `first` and whose
    /// every later resnapshot fails with `rest`, never succeeding — a cold start
    /// that hits a terminal error after a transient one.
    fn cold_start_then_persistent_error(
        inner: Arc<CacheProbe>,
        first: ErrorCode,
        rest: ErrorCode,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            queue: Arc::new(WatchQueue::default()),
            supports_watch: true,
            watch_open: WatchOpen::Park,
            root_update_streams: Mutex::new(VecDeque::new()),
            list_calls: AtomicUsize::new(0),
            list_errors: Mutex::new(VecDeque::from([Some(first)])),
            persistent_list_error: Mutex::new(Some(rest)),
        })
    }

    /// A backend whose first discovery succeeds (handing out one live update
    /// stream) and whose every later resnapshot fails with `terminal`. Returns
    /// the sender for the initial stream so a test can end it and force the
    /// resnapshot. Models a backend that was live and then goes terminal.
    fn live_then_persistent_error(
        inner: Arc<CacheProbe>,
        terminal: ErrorCode,
    ) -> (
        Arc<Self>,
        futures::channel::mpsc::UnboundedSender<Result<RootInfoChange>>,
    ) {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        (
            Arc::new(Self {
                inner,
                queue: Arc::new(WatchQueue::default()),
                supports_watch: false,
                watch_open: WatchOpen::Park,
                root_update_streams: Mutex::new(VecDeque::from([
                    Box::pin(rx) as RootInfoUpdateStream
                ])),
                list_calls: AtomicUsize::new(0),
                list_errors: Mutex::new(VecDeque::from([None])),
                persistent_list_error: Mutex::new(Some(terminal)),
            }),
            tx,
        )
    }

    fn with_root_updates(
        inner: Arc<CacheProbe>,
    ) -> (
        Arc<Self>,
        futures::channel::mpsc::UnboundedSender<Result<RootInfoChange>>,
    ) {
        let (backend, mut senders) = Self::with_root_update_streams(inner, 1);
        (backend, senders.remove(0))
    }

    /// Build a backend that hands out `count` distinct update streams across
    /// successive `list_address_roots` calls, returning a sender per stream so a
    /// test can drive the initial stream and each resnapshot's replacement.
    fn with_root_update_streams(
        inner: Arc<CacheProbe>,
        count: usize,
    ) -> (
        Arc<Self>,
        Vec<futures::channel::mpsc::UnboundedSender<Result<RootInfoChange>>>,
    ) {
        let mut senders = Vec::new();
        let mut streams: VecDeque<RootInfoUpdateStream> = VecDeque::new();
        for _ in 0..count {
            let (tx, rx) = futures::channel::mpsc::unbounded();
            senders.push(tx);
            streams.push_back(Box::pin(rx));
        }
        (
            Arc::new(Self {
                inner,
                queue: Arc::new(WatchQueue::default()),
                supports_watch: false,
                watch_open: WatchOpen::Park,
                root_update_streams: Mutex::new(streams),
                list_calls: AtomicUsize::new(0),
                list_errors: Mutex::new(VecDeque::new()),
                persistent_list_error: Mutex::new(None),
            }),
            senders,
        )
    }

    fn inject(&self, event: ChangeEvent) {
        self.queue.events.lock().unwrap().push_back(event);
        self.queue.ready.notify_all();
    }
}

struct CountingWatchStream {
    queue: Arc<WatchQueue>,
    cancel: CancellationToken,
}

impl Iterator for CountingWatchStream {
    type Item = Result<ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut events = self.queue.events.lock().unwrap();
        loop {
            if let Some(event) = events.pop_front() {
                return Some(Ok(event));
            }
            if self.cancel.is_cancelled() {
                return None;
            }
            (events, _) = self
                .queue
                .ready
                .wait_timeout(events, Duration::from_millis(10))
                .unwrap();
        }
    }
}

impl Drop for CountingWatchStream {
    fn drop(&mut self) {
        self.queue.active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Layer for CountingWatchBackend {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn list_address_roots(
        &self,
        _cx: &ovstorage::Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        let scripted = match self.list_errors.lock().unwrap().pop_front() {
            Some(entry) => entry,
            None => *self.persistent_list_error.lock().unwrap(),
        };
        if let Some(code) = scripted {
            return Err(ovstorage::Error::new(
                code,
                "scripted list_address_roots error",
            ));
        }
        let mut root = test_root("mem:///");
        root.capabilities.supports_watch_directory = self.supports_watch;
        let updates = self.root_update_streams.lock().unwrap().pop_front();
        Ok((
            RootInfoSnapshot {
                roots: vec![root],
                updates: updates.is_some(),
            },
            updates,
        ))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.inner.stat(request, cancel).await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.inner.read(request, cancel).await
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        self.inner.list(request, cancel).await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        self.queue.opens.fetch_add(1, Ordering::SeqCst);
        self.queue.scopes.lock().unwrap().push(
            request
                .extensions
                .get(ovstorage::wrappers::ext::PRINCIPAL_ID)
                .map(<[u8]>::to_vec),
        );
        self.queue.credentials.lock().unwrap().push(
            request
                .extensions
                .get(ovstorage::wrappers::ext::AUTH_CREDENTIAL)
                .is_some(),
        );
        self.queue
            .options
            .lock()
            .unwrap()
            .push(request.input.options.clone());
        self.queue
            .prefixes
            .lock()
            .unwrap()
            .push(request.input.prefix.clone());
        match &self.watch_open {
            WatchOpen::Error(code) => {
                return Err(ovstorage::Error::new(*code, "scripted watch-open error"));
            }
            WatchOpen::Finite => return Ok(Box::new(std::iter::empty())),
            WatchOpen::Park => {}
            WatchOpen::Blocked(release) => {
                while !release.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            WatchOpen::RefuseRecursive { code } => {
                if request.input.options.recursive {
                    return Err(ovstorage::Error::new(*code, "scripted recursive refusal"));
                }
            }
            WatchOpen::RefuseUnlessUnder {
                allowed,
                code,
                stall,
            } => {
                if !request.input.prefix.as_str().starts_with(allowed.as_str()) {
                    return Err(ovstorage::Error::new(*code, "scripted prefix refusal"));
                }
                if stall.as_ref().is_some_and(|at| *at == request.input.prefix) {
                    std::future::pending::<()>().await;
                }
            }
            WatchOpen::FiniteThenBlocked(release) => {
                // `opens` was already incremented above: the first open ends
                // empty to drive a reconnect; the second (and later) open blocks
                // until released, then parks.
                if self.queue.opens.load(Ordering::SeqCst) == 1 {
                    return Ok(Box::new(std::iter::empty()));
                }
                while !release.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        self.queue.active.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CountingWatchStream {
            queue: self.queue.clone(),
            cancel: cancel.unwrap_or_default(),
        }))
    }
}

fn byte_config(dir: &std::path::Path) -> LayerConfig {
    std::fs::create_dir_all(dir.join("cache")).unwrap();
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let mut config = LayerConfig::new();
    config.insert(
        "cache_root".into(),
        ConfigValue::String(dir.join("cache").to_string_lossy().into_owned()),
    );
    config.insert(
        "state_root".into(),
        ConfigValue::String(dir.join("state").to_string_lossy().into_owned()),
    );
    config.insert("watch_invalidation".into(), ConfigValue::Bool(true));
    config
}

async fn cache_stack(backend: LayerHandle, dir: &std::path::Path) -> Stack {
    let mut byte = LayerSpec::wrapper("byte", BYTE_CACHE_KIND, "metadata");
    byte.config = byte_config(dir);
    Stack::builder("byte")
        .wrapper_factory(Arc::new(ByteCacheWrapperFactory::default()))
        .wrapper_factory(Arc::new(MetadataCacheWrapperFactory::default()))
        .attach("backend", backend)
        .layer(byte)
        .layer(LayerSpec::wrapper(
            "metadata",
            METADATA_CACHE_KIND,
            "backend",
        ))
        .build()
        .await
        .unwrap()
}

async fn metadata_stack(backend: LayerHandle) -> Stack {
    metadata_stack_with_watch_invalidation(backend, true).await
}

async fn metadata_stack_with_watch_invalidation(
    backend: LayerHandle,
    watch_invalidation: bool,
) -> Stack {
    let mut metadata = LayerSpec::wrapper("metadata", METADATA_CACHE_KIND, "backend");
    metadata.config.insert(
        "watch_invalidation".into(),
        ConfigValue::Bool(watch_invalidation),
    );
    Stack::builder("metadata")
        .wrapper_factory(Arc::new(MetadataCacheWrapperFactory::default()))
        .attach("backend", backend)
        .layer(metadata)
        .build()
        .await
        .unwrap()
}

fn modified(address: &str) -> ChangeEvent {
    ChangeEvent::Object {
        address: Url::parse(address).unwrap(),
        kind: ChangeKind::Modified,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at: std::time::SystemTime::now(),
        cursor: WatchDirectoryCursor::default(),
    }
}

fn watch_root(supports_watch: bool) -> RootInfo {
    let mut root = test_root("mem:///");
    root.capabilities.supports_watch_directory = supports_watch;
    root
}

/// A watch-capable root at the same URL as [`watch_root`] but with a distinct
/// routing identity (`connection_id`), so a same-URL re-announcement is a route
/// rebind rather than a no-op under identity-aware reconciliation.
fn watch_root_with_connection(supports_watch: bool, connection_id: &str) -> RootInfo {
    let mut root = watch_root(supports_watch);
    root.connection_id = Some(ConnectionId(connection_id.to_string()));
    root
}

fn stat_request(address: &Url) -> Request<StatRequest> {
    Request::new(StatRequest {
        address: address.clone(),
        options: StatOptions::default(),
    })
}

async fn wait_for(counter: &AtomicUsize, expected: usize, what: &str) {
    for _ in 0..500 {
        if counter.load(Ordering::SeqCst) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "timed out waiting for {what}: expected {expected}, got {}",
        counter.load(Ordering::SeqCst)
    );
}

/// Block until the drain's activation sweep for `address`'s scope has run, then
/// leave the cache empty for the caller to fill.
///
/// `wait_for(&backend.queue.active, 1, ..)` is NOT that barrier: the backend
/// bumps `active` inside its own `watch_directory`, while the cache layer
/// dispatches the sweep after that call returns and runs it on the blocking
/// pool. A fill placed on the strength of `active` can therefore be wiped
/// hundreds of milliseconds later — which is a flake where the test then asserts
/// the entry survives, and a FALSE GREEN where it asserts the entry is gone,
/// because a sweep is indistinguishable from the event-driven invalidation those
/// tests mean to observe.
///
/// The sweep is observable, though: it wipes the entry. The caller's first
/// `stat` fills the cache *before* the watch opens, so the sweep that open
/// dispatches is ordered after that fill — and polling until the entry is gone
/// is an observation that happens-after the sweep. Everything the caller does
/// next is therefore deterministically post-sweep, with no sleep and no retry
/// budget. `reopen_re_arms_activation_sweep` uses the same idea against a held
/// open.
async fn await_activation_sweep(stack: &Stack, backend: &CountingWatchBackend, address: &Url) {
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    for _ in 0..500 {
        if stack.stat(stat_request(address), None).await.is_err() {
            backend.inner.set_stat_error(None);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    backend.inner.set_stat_error(None);
    panic!(
        "the entry primed before the watch opened was never invalidated, so the \
         activation sweep cannot be ordered against: the caller's fill would \
         race it"
    );
}

async fn prime_caches(stack: &Stack, backend: &CountingWatchBackend) -> (usize, usize) {
    let address = "mem:///obj";
    backend.inner.set_stat_error(None);
    stack.read(read_request(address), None).await.unwrap();
    stack.read(read_request(address), None).await.unwrap();
    (
        backend.inner.reads.load(Ordering::SeqCst),
        backend.inner.stats.load(Ordering::SeqCst),
    )
}

async fn assert_both_caches_invalidated(
    stack: &Stack,
    backend: &CountingWatchBackend,
    reads_before: usize,
    stats_before: usize,
) {
    let address = "mem:///obj";

    for _ in 0..500 {
        let _ = stack
            .stat(stat_request(&Url::parse(address).unwrap()), None)
            .await;
        stack.read(read_request(address), None).await.unwrap();
        if backend.inner.stats.load(Ordering::SeqCst) > stats_before
            && backend.inner.reads.load(Ordering::SeqCst) > reads_before
        {
            backend.inner.set_stat_error(None);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the watch event did not invalidate both metadata and byte caches");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_drain_invalidates_and_rebuild_hands_over_cleanly() {
    let inner = CacheProbe::new(b"payload", Vec::new());
    let backend = CountingWatchBackend::new(inner);
    let first_dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), first_dir.path()).await;

    wait_for(&backend.queue.opens, 1, "first notification drain").await;
    let (reads_before, stats_before) = prime_caches(&stack, &backend).await;
    // The cache's own notification drain opens a single recursive,
    // metadata-bearing watch on the backend.
    assert_eq!(backend.queue.active.load(Ordering::SeqCst), 1);
    let physical = backend.queue.options.lock().unwrap()[0].clone();
    assert!(physical.recursive);
    assert!(physical.include_metadata_changes);

    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    backend.inject(modified("mem:///obj"));
    assert_both_caches_invalidated(&stack, &backend, reads_before, stats_before).await;

    drop(stack);
    wait_for(&backend.queue.active, 0, "old Stack watch teardown").await;

    let second_dir = tempfile::tempdir().unwrap();
    let rebuilt = cache_stack(backend.clone(), second_dir.path()).await;
    wait_for(&backend.queue.opens, 2, "rebuilt notification drain").await;
    assert_eq!(backend.queue.active.load(Ordering::SeqCst), 1);
    let (reads_before, stats_before) = prime_caches(&rebuilt, &backend).await;
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    backend.inject(modified("mem:///obj"));
    assert_both_caches_invalidated(&rebuilt, &backend, reads_before, stats_before).await;
    drop(rebuilt);
    wait_for(&backend.queue.active, 0, "rebuilt Stack watch teardown").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_direct_stack_notification_drain_invalidates() {
    let inner = CacheProbe::new(b"payload", Vec::new());
    // The open is HELD, which is what makes the activation sweep orderable.
    // This root drain opens during stack construction, so unlike the scoped
    // tests there is no pre-open fill for `await_activation_sweep` to watch
    // disappear. Holding the open supplies one: fill while it is blocked, let
    // it through, and the sweep it dispatches is ordered after that fill.
    //
    // Waiting on `queue.active` alone is NOT that barrier — the backend bumps
    // `active` inside its own `watch_directory`, before the cache layer
    // dispatches the sweep. Here that would be a FALSE GREEN rather than a
    // flake: the polling loop below asserts `is_err() && stats increased`, and
    // a late sweep produces exactly that with no event ever processed.
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = CountingWatchBackend::with_watch_behavior(
        inner,
        true,
        WatchOpen::Blocked(Arc::clone(&release)),
    );
    let stack = metadata_stack(backend.clone()).await;
    wait_for(&backend.queue.opens, 1, "the held metadata drain open").await;

    let address = Url::parse("mem:///obj").unwrap();
    // Filled while the open is held, so the sweep cannot have run yet.
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the entry must be cached before the open is released");

    release.store(true, Ordering::SeqCst);
    wait_for(&backend.queue.active, 1, "metadata notification drain").await;

    // Watching that entry go is the barrier: the observation happens-after the
    // activation sweep, so everything below is deterministically past it.
    let mut swept = false;
    for _ in 0..500 {
        if stack.stat(stat_request(&address), None).await.is_err() {
            swept = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        swept,
        "the entry primed before the open was never invalidated, so the \
         activation sweep cannot be ordered against and the assertions below \
         would race it"
    );

    // Now refill, past the sweep, and let the EVENT be the only thing that can
    // remove it.
    backend.inner.set_stat_error(None);
    stack.stat(stat_request(&address), None).await.unwrap();
    let stats_before = backend.inner.stats.load(Ordering::SeqCst);
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the entry must be served from cache first, or the event proves nothing");
    backend.inject(modified(address.as_str()));

    for _ in 0..500 {
        let result = stack.stat(stat_request(&address), None).await;
        if result.is_err() && backend.inner.stats.load(Ordering::SeqCst) > stats_before {
            drop(stack);
            wait_for(&backend.queue.active, 0, "metadata drain teardown").await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the direct-Stack metadata drain did not invalidate its stat entry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_invalidation_is_opt_in_and_capability_gated() {
    let enabled_backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::Park,
    );
    let disabled = metadata_stack_with_watch_invalidation(enabled_backend.clone(), false).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(enabled_backend.queue.opens.load(Ordering::SeqCst), 0);
    drop(disabled);

    let unsupported_root = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        false,
        WatchOpen::Park,
    );
    let enabled = metadata_stack_with_watch_invalidation(unsupported_root.clone(), true).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(unsupported_root.queue.opens.load(Ordering::SeqCst), 0);
    drop(enabled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_unsupported_watch_falls_back_without_retrying() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::Error(ErrorCode::Unsupported),
    );
    let stack = metadata_stack(backend.clone()).await;
    wait_for(&backend.queue.opens, 1, "unsupported notification watch").await;
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        1,
        "runtime Unsupported must select TTL-only invalidation without retries"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quick_empty_finite_watches_reconnect_with_backoff() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::Finite,
    );
    let stack = metadata_stack(backend.clone()).await;

    wait_for(&backend.queue.opens, 1, "first finite notification watch").await;
    // An empty completion must reconnect: a second open actually occurs (this
    // fails a give-up-after-first regression, which leaves opens at 1).
    wait_for(
        &backend.queue.opens,
        2,
        "backoff reconnect after empty completion",
    )
    .await;
    // ...but the exponential backoff must hold the third open well past the
    // second. The gap after the second empty end is ~2s; no third open lands
    // inside this shorter window (this fails a no-backoff hot-reconnect, which
    // would race opens past 2).
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        2,
        "exponential backoff must delay the third reconnect beyond the second open"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_capability_updates_start_and_stop_drains() {
    let (backend, updates) =
        CountingWatchBackend::with_root_updates(CacheProbe::new(b"payload", Vec::new()));
    let stack = metadata_stack(backend.clone()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(backend.queue.opens.load(Ordering::SeqCst), 0);

    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();
    wait_for(&backend.queue.opens, 1, "newly watch-capable root").await;
    wait_for(&backend.queue.active, 1, "new root notification drain").await;

    // A capability downgrade (same URL, `supports_watch` -> false) must stop the
    // drain just like a removal: the root is no longer watch-eligible.
    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(false)])))
        .unwrap();
    wait_for(&backend.queue.active, 0, "capability-downgraded root drain").await;

    // Re-enabling the capability restarts a drain...
    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();
    wait_for(
        &backend.queue.active,
        1,
        "re-enabled root notification drain",
    )
    .await;

    // ...and an outright removal stops it again.
    updates
        .unbounded_send(Ok(RootInfoChange::Removed(vec![watch_root(true)])))
        .unwrap();
    wait_for(&backend.queue.active, 0, "removed root notification drain").await;
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_update_error_resyncs_and_keeps_processing_updates() {
    // The initial update stream errors; the drain manager must resnapshot AND
    // adopt the replacement stream the resnapshot returns. The watch-capable
    // root is announced only on that *replacement* stream (no follow-up delta on
    // the errored original), so a manager that discards the replacement (the
    // pre-fix bug) or freezes never starts the drain -- this test fails against
    // it. The initial snapshot is not watch-capable, so the drain cannot come
    // from a resnapshot's snapshot roots either.
    let (backend, mut senders) =
        CountingWatchBackend::with_root_update_streams(CacheProbe::new(b"payload", Vec::new()), 2);
    let replacement = senders.remove(1);
    let original = senders.remove(0);
    let stack = metadata_stack(backend.clone()).await;

    original
        .unbounded_send(Err(ovstorage::Error::new(
            ErrorCode::Internal,
            "simulated BroadcastStream lag",
        )))
        .unwrap();
    // Announced only on the replacement stream the resnapshot hands back.
    replacement
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();

    wait_for(&backend.queue.opens, 1, "post-lag notification drain").await;
    wait_for(&backend.queue.active, 1, "post-lag active drain").await;
    assert!(
        backend.list_calls.load(Ordering::SeqCst) >= 2,
        "the error must trigger a resnapshot (a second list_address_roots call)"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_updated_resync_nudge_resnapshots_and_starts_drain() {
    // An empty `Updated` is a resync nudge (the alias wrapper emits one when its
    // inner `list_address_roots` fails transiently and it cannot compute a precise
    // delta). The drain manager must treat it like a stream error/EOF: resnapshot
    // AND adopt the replacement stream the resnapshot returns. The watch-capable
    // root is announced only on that *replacement* stream, and the initial
    // snapshot is not watch-capable, so a manager that treats the empty `Updated`
    // as a no-op (the pre-fix bug) never resnapshots, never adopts the
    // replacement, and never opens the drain -- this test times out against it.
    let (backend, mut senders) =
        CountingWatchBackend::with_root_update_streams(CacheProbe::new(b"payload", Vec::new()), 2);
    let replacement = senders.remove(1);
    let original = senders.remove(0);
    let stack = metadata_stack(backend.clone()).await;

    // The empty resync nudge on the original stream must trigger the resnapshot.
    original
        .unbounded_send(Ok(RootInfoChange::Updated(Vec::new())))
        .unwrap();
    // Announced only on the replacement stream the resnapshot hands back.
    replacement
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();

    wait_for(&backend.queue.opens, 1, "post-nudge notification drain").await;
    wait_for(&backend.queue.active, 1, "post-nudge active drain").await;
    assert!(
        backend.list_calls.load(Ordering::SeqCst) >= 2,
        "an empty Updated resync nudge must trigger a resnapshot (a second list_address_roots call)"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clean_root_update_eof_resubscribes_and_starts_drain() {
    // The initial update stream ends CLEANLY (its sender is dropped, not an
    // error). A clean EOF is recoverable, not a shutdown: the drain manager must
    // resnapshot AND adopt the replacement stream the resnapshot returns. The
    // watch-capable root is announced only on that *replacement* stream, so a
    // manager that parks on clean EOF (the pre-fix behavior) or discards the
    // replacement never opens the drain -- this test times out against it. The
    // initial snapshot is not watch-capable, so the drain cannot arise from a
    // resnapshot's snapshot roots either.
    let (backend, mut senders) =
        CountingWatchBackend::with_root_update_streams(CacheProbe::new(b"payload", Vec::new()), 2);
    let replacement = senders.remove(1);
    let original = senders.remove(0);
    let stack = metadata_stack(backend.clone()).await;

    // Announced only on the replacement stream the resnapshot hands back.
    replacement
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();
    // End the original stream cleanly (EOF, not error) by dropping its sender.
    drop(original);

    wait_for(&backend.queue.opens, 1, "post-clean-EOF notification drain").await;
    wait_for(&backend.queue.active, 1, "post-clean-EOF active drain").await;
    assert!(
        backend.list_calls.load(Ordering::SeqCst) >= 2,
        "a clean EOF must trigger a resnapshot (a second list_address_roots call)"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retryable_initial_discovery_failure_retries_and_opens_drain() {
    // The FIRST `list_address_roots` fails with a retryable error (backend/broker
    // not ready at startup); the SECOND returns a watch-capable snapshot. The
    // drain manager must NOT give up permanently: it must retry discovery under
    // bounded backoff (like the resubscribe path) and open the drain once the
    // backend recovers. (Fails against the pre-fix "return on any initial error"
    // behavior, where the manager terminates, `list_calls` stays 1, and no drain
    // ever opens.)
    let backend = CountingWatchBackend::with_initial_list_errors(
        CacheProbe::new(b"payload", Vec::new()),
        vec![ErrorCode::Transient],
    );
    let stack = metadata_stack(backend.clone()).await;

    wait_for(&backend.queue.opens, 1, "post-retry notification drain").await;
    wait_for(&backend.queue.active, 1, "post-retry active drain").await;
    assert!(
        backend.list_calls.load(Ordering::SeqCst) >= 2,
        "a retryable initial discovery failure must be retried (a second \
         list_address_roots call)"
    );
    drop(stack);
    wait_for(&backend.queue.active, 0, "post-retry drain teardown").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonretryable_initial_discovery_failure_stays_ttl_only() {
    // A non-retryable initial `list_address_roots` failure is terminal: the
    // backend cannot support root discovery, so permanent TTL-only invalidation
    // is correct. The manager must NOT retry and must open no drain.
    let backend = CountingWatchBackend::with_initial_list_errors(
        CacheProbe::new(b"payload", Vec::new()),
        vec![ErrorCode::Internal],
    );
    let stack = metadata_stack(backend.clone()).await;

    // The spawned manager task runs discovery asynchronously: wait for the
    // initial call to actually happen before asserting it does not climb.
    wait_for(&backend.list_calls, 1, "initial discovery call").await;
    // Then, over a bounded window well past the initial backoff, it must NOT
    // retry: the call count stays pinned at 1.
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            backend.list_calls.load(Ordering::SeqCst),
            1,
            "a non-retryable initial discovery failure must not be retried"
        );
    }
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        0,
        "a terminal discovery failure must open no notification drain (TTL-only)"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_start_terminal_after_retryable_gives_up_to_ttl_only() {
    // Cold start: the initial discovery fails retryably (Transient), so the
    // manager enters the resubscribe backoff loop. The very next resnapshot then
    // fails with a genuinely terminal error (Internal) while discovery has NEVER
    // succeeded. The manager must give up to permanent TTL-only rather than retry
    // a terminal error forever. (Fails against a retry-every-error resubscribe
    // loop, where `list_calls` climbs past 2 without bound.)
    let backend = CountingWatchBackend::cold_start_then_persistent_error(
        CacheProbe::new(b"payload", Vec::new()),
        ErrorCode::Transient,
        ErrorCode::Internal,
    );
    let stack = metadata_stack(backend.clone()).await;

    // The retryable initial failure is retried once: the terminal resnapshot.
    wait_for(
        &backend.list_calls,
        2,
        "cold-start resnapshot after a retryable initial failure",
    )
    .await;
    // Having hit a terminal error while never having succeeded, the manager must
    // STOP: `list_calls` stays pinned at 2 over a bounded window (later retries
    // would land at ~150ms/~350ms under backoff), and no drain opens.
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            backend.list_calls.load(Ordering::SeqCst),
            2,
            "a terminal error during cold-start discovery must not be retried forever"
        );
    }
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        0,
        "a terminal cold-start discovery error must open no notification drain (TTL-only)"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn was_live_then_terminal_resnapshot_keeps_retrying() {
    // Discovery SUCCEEDS once (a live update stream), so the manager has been
    // live. The stream then errors, forcing a resnapshot that fails with a
    // terminal error. Because discovery previously succeeded, a terminal blip is
    // NOT treated as give-up: the manager keeps retrying under backoff (a backend
    // that worked before may recover). `list_calls` must climb past the first
    // resnapshot, confirming the was-live behavior is unchanged.
    let (backend, updates) = CountingWatchBackend::live_then_persistent_error(
        CacheProbe::new(b"payload", Vec::new()),
        ErrorCode::Internal,
    );
    let stack = metadata_stack(backend.clone()).await;

    // First discovery succeeded and the manager is polling the live stream.
    wait_for(&backend.list_calls, 1, "initial live discovery").await;
    // End the live stream with an error to force a resnapshot.
    updates
        .unbounded_send(Err(ovstorage::Error::new(
            ErrorCode::Internal,
            "simulated stream lag",
        )))
        .unwrap();

    // The resnapshot (call 2) fails terminally, but the was-live manager keeps
    // retrying under backoff: `list_calls` climbs beyond the first resnapshot.
    // (Against a give-up-on-terminal-always policy this would freeze at 2.)
    let mut kept_retrying = false;
    for _ in 0..500 {
        if backend.list_calls.load(Ordering::SeqCst) >= 3 {
            kept_retrying = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        kept_retrying,
        "a was-live manager must keep retrying resnapshots after a terminal blip; \
         list_calls did not climb past the first resnapshot"
    );
    drop(stack);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_removal_sweeps_cached_subtree() {
    let (backend, updates) =
        CountingWatchBackend::with_root_updates(CacheProbe::new(b"payload", Vec::new()));
    let stack = metadata_stack(backend.clone()).await;

    // Announce a watch-capable root so a drain (and its activation sweep) exists.
    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();
    wait_for(&backend.queue.opens, 1, "watch-capable root drain").await;
    wait_for(&backend.queue.active, 1, "active root drain").await;

    // Prime the metadata cache AFTER the activation sweep has run (the drain is
    // open) so the primed entry can only be cleared by the removal sweep.
    let address = Url::parse("mem:///obj").unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    let stats_before = backend.inner.stats.load(Ordering::SeqCst);
    backend.inner.set_stat_error(Some(ErrorCode::Transient));

    // Removing the root must SWEEP its cached subtree, not merely stop the drain.
    updates
        .unbounded_send(Ok(RootInfoChange::Removed(vec![watch_root(true)])))
        .unwrap();
    wait_for(&backend.queue.active, 0, "removed root drain stopped").await;

    // The subtree sweep cleared the primed stat: a subsequent stat misses the
    // cache and hits the now-erroring backend. (Fails against a removal that
    // stops the drain without sweeping -- the stale entry keeps answering.)
    for _ in 0..500 {
        if stack.stat(stat_request(&address), None).await.is_err()
            && backend.inner.stats.load(Ordering::SeqCst) > stats_before
        {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("root removal did not sweep the cached subtree");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_url_route_rebind_reopens_drain() {
    let (backend, updates) =
        CountingWatchBackend::with_root_updates(CacheProbe::new(b"payload", Vec::new()));
    let stack = metadata_stack(backend.clone()).await;

    // A watch-capable root on one routing identity opens the first drain.
    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![
            watch_root_with_connection(true, "conn-a"),
        ])))
        .unwrap();
    wait_for(&backend.queue.opens, 1, "initial route drain").await;
    wait_for(&backend.queue.active, 1, "initial active drain").await;

    // Same URL, DIFFERENT routing identity (connection) -> a rebind. It must
    // cancel the old drain and open a fresh physical watch. (Fails against
    // URL-only reconciliation, which keeps the old drain and never reopens, so
    // `opens` stays at 1.)
    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![
            watch_root_with_connection(true, "conn-b"),
        ])))
        .unwrap();
    wait_for(
        &backend.queue.opens,
        2,
        "route rebind reopens a fresh watch",
    )
    .await;

    // The old drain was cancelled, not left running alongside the new one: the
    // active count settles back to exactly one.
    for _ in 0..500 {
        if backend.queue.active.load(Ordering::SeqCst) == 1
            && backend.queue.opens.load(Ordering::SeqCst) == 2
        {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "route rebind did not settle to a single live drain: opens={}, active={}",
        backend.queue.opens.load(Ordering::SeqCst),
        backend.queue.active.load(Ordering::SeqCst)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopen_re_arms_activation_sweep() {
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let address = Url::parse("mem:///obj").unwrap();
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", vec![object_info(address.clone(), 7)]),
        true,
        WatchOpen::FiniteThenBlocked(release.clone()),
    );
    let stack = metadata_stack(backend.clone()).await;

    // First open ends empty (activation sweep #1), then the drain reconnects
    // under backoff and BLOCKS on the second open -- before its activation sweep,
    // which runs only after `watch_directory` returns.
    wait_for(
        &backend.queue.opens,
        2,
        "second physical watch open (blocked)",
    )
    .await;

    // Prime the metadata cache while the second open is held: this fill lands
    // after sweep #1 and before sweep #2.
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    let stats_before = backend.inner.stats.load(Ordering::SeqCst);
    backend.inner.set_stat_error(Some(ErrorCode::Transient));

    // Release the second open: the drain re-arms the subtree sweep (sweep #2),
    // which must clear the primed stat. (Fails against a sweep-only-on-first-open
    // regression, where the primed entry survives the cursorless reopen.)
    release.store(true, Ordering::SeqCst);
    wait_for(&backend.queue.active, 1, "second open live after release").await;

    for _ in 0..500 {
        if stack.stat(stat_request(&address), None).await.is_err()
            && backend.inner.stats.load(Ordering::SeqCst) > stats_before
        {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the second watch open did not re-arm the activation sweep");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_drain_stays_bounded_across_principals() {
    let backend = CountingWatchBackend::new(CacheProbe::new(b"payload", Vec::new()));
    let stack = metadata_stack(backend.clone()).await;
    let address = Url::parse("mem:///obj").unwrap();
    wait_for(&backend.queue.opens, 1, "shared notification drain").await;

    for principal in 0..600 {
        let mut request = stat_request(&address);
        request.extensions.insert(
            ovstorage::wrappers::ext::PRINCIPAL_ID,
            format!("principal-{principal}").into_bytes(),
        );
        stack.stat(request, None).await.unwrap();
    }
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        1,
        "principal churn must not multiply permanent notification drains"
    );
    assert_eq!(
        backend.queue.scopes.lock().unwrap().as_slice(),
        &[None],
        "the address-wide cache drain is identity-free"
    );
    assert_eq!(
        backend.queue.credentials.lock().unwrap().as_slice(),
        &[false],
        "the shared cache drain must not retain raw credentials"
    );

    let mut alice_watch = Request::new(WatchDirectoryRequest {
        prefix: Url::parse("mem:///").unwrap(),
        options: WatchDirectoryOptions::default(),
    });
    alice_watch
        .extensions
        .insert(ovstorage::wrappers::ext::PRINCIPAL_ID, b"alice".to_vec());
    let caller = stack.watch_directory(alice_watch, None).await.unwrap();
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        2,
        "an external caller opens its own physical watch, distinct from the \
         identity-free cache drain"
    );

    drop(caller);
    drop(stack);
    wait_for(&backend.queue.active, 0, "shared drain teardown").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newly_watchable_root_sweeps_only_after_watch_open_succeeds() {
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (updates, root_updates) = futures::channel::mpsc::unbounded();
    let address = Url::parse("mem:///obj").unwrap();
    let backend = Arc::new(CountingWatchBackend {
        inner: CacheProbe::new(b"payload", vec![object_info(address.clone(), 7)]),
        queue: Arc::new(WatchQueue::default()),
        supports_watch: false,
        watch_open: WatchOpen::Blocked(release.clone()),
        root_update_streams: Mutex::new(VecDeque::from([
            Box::pin(root_updates) as RootInfoUpdateStream
        ])),
        list_calls: AtomicUsize::new(0),
        list_errors: Mutex::new(VecDeque::new()),
        persistent_list_error: Mutex::new(None),
    });
    let stack = metadata_stack(backend.clone()).await;

    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("mem:///").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    let stats_after_fill = backend.inner.stats.load(Ordering::SeqCst);
    assert_eq!(
        stats_after_fill, 0,
        "stat must be served from the list-filled cache"
    );
    backend.inner.set_stat_error(Some(ErrorCode::Transient));

    updates
        .unbounded_send(Ok(RootInfoChange::Updated(vec![watch_root(true)])))
        .unwrap();
    wait_for(&backend.queue.opens, 1, "blocked notification watch open").await;
    let before_open = stack.stat(stat_request(&address), None).await;
    release.store(true, Ordering::SeqCst);
    before_open.expect("activation must not sweep before the watch is live");
    assert_eq!(backend.inner.stats.load(Ordering::SeqCst), stats_after_fill);

    for _ in 0..500 {
        if stack.stat(stat_request(&address), None).await.is_err()
            && backend.inner.stats.load(Ordering::SeqCst) > stats_after_fill
        {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("activation sweep did not run after the watch opened");
}

// ---------------------------------------------------------------------------
// Scoped watches: a root watch a least-privilege policy refuses
// ---------------------------------------------------------------------------

/// Prefixes the backend has been asked to watch, in open order.
fn watched_prefixes(backend: &CountingWatchBackend) -> Vec<String> {
    backend
        .queue
        .prefixes
        .lock()
        .unwrap()
        .iter()
        .map(|prefix| prefix.as_str().to_string())
        .collect()
}

async fn read_dirs(stack: &Stack, addresses: &[&str]) {
    for address in addresses {
        stack.read(read_request(address), None).await.unwrap();
    }
}

/// **The good input.** A root whose watch is granted keeps opening exactly one
/// watch, on the root, however many directories the cache reads. Scoped
/// watching is a fallback, not a new default, and this is what says so.
///
/// The assertion is not vacuous in the "nothing happened" direction: it also
/// asserts the root watch itself opened, so a change that stopped the drain
/// entirely would fail here rather than pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_granted_root_watch_stays_one_watch_however_much_is_read() {
    let backend = CountingWatchBackend::new(CacheProbe::new(b"payload", Vec::new()));
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "root notification drain").await;

    read_dirs(
        &stack,
        &[
            "mem:///alpha/one",
            "mem:///beta/two",
            "mem:///gamma/three",
            "mem:///alpha/four",
        ],
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        watched_prefixes(&backend),
        vec!["mem:///".to_string()],
        "a granted root watch must not be joined by per-directory watches"
    );
    assert_eq!(backend.queue.active.load(Ordering::SeqCst), 1);
    drop(stack);
}

/// **The issue.** A root watch refused with `PermissionDenied`, and
/// `watch_directory` granted under one directory, must produce a live watch on
/// that directory and real invalidation from it. Treating the refusal as
/// terminal instead leaves the whole root TTL-only with no watch at all, which
/// is what this reddens against.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_root_watches_the_directory_the_cache_reads() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///folder/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: None,
        },
    );
    let stack = metadata_stack(backend.clone()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    let address = Url::parse("mem:///folder/obj").unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    wait_for(
        &backend.queue.active,
        1,
        "scoped watch on the read directory",
    )
    .await;

    let prefixes = watched_prefixes(&backend);
    assert_eq!(prefixes[0], "mem:///", "the root is still tried first");
    assert!(
        prefixes.contains(&"mem:///folder/".to_string()),
        "the refused root must fall back to the directory that was read, got {prefixes:?}"
    );

    // The scoped watch is a real invalidation path, not just an open stream.
    //
    // Fill AFTER the watch is live AND after its activation sweep. The two
    // stats above ran before it opened, and every successful open sweeps its
    // prefix before any event is consumed — but `active` does not order against
    // that sweep, so filling on it alone lets the sweep land later and clear the
    // entry. The polling loop below would then see exactly what an invalidated
    // entry looks like, with scoped events never processed at all: a false
    // green, not a flake. Waiting for the earlier entry to disappear is the
    // barrier, since that observation happens-after the sweep.
    await_activation_sweep(&stack, &backend, &address).await;
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    let stats_before = backend.inner.stats.load(Ordering::SeqCst);
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the entry must be served from cache first, or the event proves nothing");
    assert_eq!(
        backend.inner.stats.load(Ordering::SeqCst),
        stats_before,
        "and served without reaching the backend"
    );

    // Only now does the event have anything to invalidate: a stat that reaches
    // the failing backend proves the entry was dropped by the event.
    backend.inject(modified(address.as_str()));
    for _ in 0..500 {
        let result = stack.stat(stat_request(&address), None).await;
        if result.is_err() && backend.inner.stats.load(Ordering::SeqCst) > stats_before {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the scoped watch delivered no invalidation");
}

/// The byte cache owns the drains in the shipped `byte_cache` over
/// `metadata_cache` composition, so it is the layer that has to observe what
/// the stack reads — including the `list` and `stat` it does not itself cache.
/// Without its registering pass-throughs a caller's own listing would be
/// cached below and left unwatched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_drain_owning_layer_registers_a_listing_it_does_not_cache() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///folder/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: None,
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    let prefix = Url::parse("mem:///folder/").unwrap();
    stack
        .list(
            Request::new(ListRequest {
                prefix: prefix.clone(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    wait_for(
        &backend.queue.active,
        1,
        "scoped watch from a listing alone",
    )
    .await;
    assert!(
        watched_prefixes(&backend).contains(&"mem:///folder/".to_string()),
        "a cacheable listing must register its own prefix"
    );
    drop(stack);
}

/// A lifecycle sweep owned by the byte layer reaches the metadata rows beneath
/// it.
///
/// Change events reach every cache in a stack because they travel back up the
/// stacked `watch_directory` wrappers. The drain's LIFECYCLE sweeps do not: they
/// are invoked directly by the layer that owns the drain, and in the shipped
/// byte-over-metadata composition only the byte layer carries
/// `watch_invalidation`. Without a path down the chain, the activation sweep
/// clears cached bodies and leaves the stat rows below answering for a subtree
/// no watch was covering.
///
/// Driven through the ACTIVATION sweep, since that is the one a test can order
/// against: fill while the open is held, release, and the entry must go.
///
/// This stack is composed NATIVELY, and the distinction is load-bearing rather
/// than incidental: `invalidate_cached_subtree` has no ABI slot, so a proxy
/// standing in for a layer across the plugin boundary takes its no-op default.
/// Loaded from `libovstorage_plugin_cache` — where the byte and metadata
/// factories are exported separately and the host chains them — the sweep stops
/// at the byte cache and the metadata rows fall back to `ttl_seconds`. So this
/// asserts the path works where the chain is native; it is not evidence about
/// the loaded-plugin composition, which is a stated bound on the PR.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_byte_layer_lifecycle_sweep_reaches_the_metadata_cache() {
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::Blocked(Arc::clone(&release)),
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "the held root watch open").await;

    // Fill a METADATA row while the open is held, so no sweep has run yet. A
    // stat goes to the metadata cache; the byte cache holds bodies.
    let address = Url::parse("mem:///obj").unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the metadata row must be cached before the open is released");

    release.store(true, Ordering::SeqCst);
    wait_for(&backend.queue.active, 1, "the root watch going live").await;

    // The activation sweep is the byte layer's, and it must reach this row.
    for _ in 0..500 {
        if stack.stat(stat_request(&address), None).await.is_err() {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "the byte layer's activation sweep left the metadata row below it \
         intact, so a mutation before the watch opened stays invisible until \
         the metadata TTL"
    );
}

/// An oversized DIRECTORY-ONLY listing registers no watch candidate, where the
/// metadata layer owns the registry.
///
/// Registration and storage are meant to share a predicate — a page with no
/// retained entry has nothing for a watch to keep fresh — and the cacheability
/// test alone cannot deliver that: `MetadataCache::insert` drops a payload
/// larger than the whole budget, so a cacheable page can still store nothing.
/// A page of directories has no per-file stat rows to fall back on, so when the
/// listing itself is dropped the prefix holds nothing at all, and registering it
/// spends one of `MAX_CANDIDATE_SCOPES` and a probe on a directory the cache is
/// not caching.
///
/// A METADATA-ONLY stack deliberately, because that is the composition where the
/// tighter choice is available: only the layer holding the cache knows whether
/// its insert was retained. In byte-over-metadata the byte layer owns the drain
/// and registers on the cacheability predicate alone, which over-registers on
/// purpose — see `ByteCacheWrapper::list`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_directory_only_listing_registers_no_candidate() {
    let items: Vec<ObjectInfo> = (0..64)
        .map(|i| {
            let mut info = object_info(Url::parse(&format!("mem:///d/sub{i}/")).unwrap(), 0);
            info.kind = ObjectKind::Directory;
            info
        })
        .collect();
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", items),
        true,
        WatchOpen::Error(ErrorCode::PermissionDenied),
    );
    // A budget far smaller than the page, so the listing cannot be retained.
    let mut metadata = LayerSpec::wrapper("metadata", METADATA_CACHE_KIND, "backend");
    metadata
        .config
        .insert("watch_invalidation".into(), ConfigValue::Bool(true));
    metadata
        .config
        .insert("max_entries".into(), ConfigValue::Int(4));
    let stack = Stack::builder("metadata")
        .wrapper_factory(Arc::new(MetadataCacheWrapperFactory::default()))
        .attach("backend", backend.clone())
        .layer(metadata)
        .build()
        .await
        .unwrap();
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("mem:///d/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();

    // The root's watch is refused, so any scoped probe would be this listing's.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        1,
        "a listing the cache could not retain must not buy a scoped watch"
    );
    drop(stack);
}

/// An etag-less route still gets its directory watched.
///
/// The read path's registration keys on the stat having HAPPENED, not on it
/// having returned a validator. The metadata layer stores a `Stat` row for any
/// cacheable address whether or not it carries an etag, so a validator gate
/// would exclude exactly the routes with NO validator — the ones a watch matters
/// most for, since nothing catches the change on read either.
///
/// Isolating it needs a read that also commits no body, because the commit
/// points register on their own: `max_object_bytes` below the payload gives
/// that, leaving a stat row and nothing else. The narrowness is the point —
/// the common path was already covered, which is why the gate survived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_etagless_read_still_registers_its_directory() {
    let probe = CacheProbe::new(b"payload", Vec::new());
    probe.stat_omits_validator.store(true, Ordering::SeqCst);
    let backend = CountingWatchBackend::with_watch_behavior(
        probe,
        true,
        WatchOpen::Error(ErrorCode::PermissionDenied),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut byte = LayerSpec::wrapper("byte", BYTE_CACHE_KIND, "metadata");
    byte.config = byte_config(dir.path());
    // Smaller than the payload, so nothing commits and no commit-point
    // registration can stand in for the one under test.
    byte.config
        .insert("max_object_bytes".into(), ConfigValue::Int(1));
    let stack = Stack::builder("byte")
        .wrapper_factory(Arc::new(ByteCacheWrapperFactory::default()))
        .wrapper_factory(Arc::new(MetadataCacheWrapperFactory::default()))
        .attach("backend", backend.clone())
        .layer(byte)
        .layer(LayerSpec::wrapper(
            "metadata",
            METADATA_CACHE_KIND,
            "backend",
        ))
        .build()
        .await
        .unwrap();
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    stack
        .read(read_request("mem:///d/obj"), None)
        .await
        .expect("the read must succeed to leave a metadata row behind");

    // The root's watch is refused, so the only way this directory is watched at
    // all is as a scoped candidate — which is what the registration produces.
    // Bounded below rather than pinned: a refused scope costs a recursive open
    // and a non-recursive retry, and this test is about whether the probe
    // happens at all.
    for _ in 0..500 {
        if backend.queue.opens.load(Ordering::SeqCst) > 1 {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "an etag-less read left a metadata row with no scoped-watch candidate: \
         only the root open ever happened"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_drain_owning_layer_registers_where_a_body_commits() {
    let probe = CacheProbe::new(b"payload", Vec::new());
    probe.omit_stat_validator();
    let backend = CountingWatchBackend::with_watch_behavior(
        probe,
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///folder/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: None,
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    let address = Url::parse("mem:///folder/obj").unwrap();
    assert!(
        backend
            .inner
            .stat(stat_request(&address), None)
            .await
            .unwrap()
            .etag
            .is_none(),
        "the backend must supply no validator on stat, or this test proves nothing"
    );
    stack
        .read(read_request(address.as_str()), None)
        .await
        .unwrap();
    wait_for(
        &backend.queue.active,
        1,
        "scoped watch from a committed body alone",
    )
    .await;
    assert!(
        watched_prefixes(&backend).contains(&"mem:///folder/".to_string()),
        "the directory holding a committed body must be watched, got {:?}",
        watched_prefixes(&backend)
    );
    drop(stack);

    // The other commit shape, and the one that needed the registry threaded
    // across a task boundary: a streamed body commits in the tee, long after
    // the `read` that started it returned.
    let probe = CacheProbe::new(b"payload", Vec::new());
    probe.omit_stat_validator();
    probe.stream_reads();
    let backend = CountingWatchBackend::with_watch_behavior(
        probe,
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///streamed/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: None,
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    let streamed = Url::parse("mem:///streamed/obj").unwrap();
    let result = stack
        .read(read_request(streamed.as_str()), None)
        .await
        .unwrap();
    let ReadResult::Stream { mut stream, .. } = result else {
        panic!("the backend must answer a stream, or this half proves nothing");
    };
    // The tee commits at clean EOF, so the stream has to be drained.
    use futures::StreamExt as _;
    while stream.next().await.is_some() {}
    wait_for(
        &backend.queue.active,
        1,
        "scoped watch from a streamed commit alone",
    )
    .await;
    assert!(
        watched_prefixes(&backend).contains(&"mem:///streamed/".to_string()),
        "the directory holding a streamed body must be watched, got {:?}",
        watched_prefixes(&backend)
    );
    drop(stack);
}

/// A negative answer is a cache entry too. The metadata layer below caches a
/// list-backed miss as a live entry and *then* returns `NotFound`, so the
/// drain-owning layer has to register the directory on that path as well —
/// exiting through `?` would leave the parent listing that answered the miss
/// unwatched, and with the root watch refused an object created afterwards
/// stays invisible behind it until the metadata cache's TTL expires the listing
/// — thirty seconds by default, since `ttl_seconds` unset means the default
/// rather than none.
///
/// This also covers the `cache_stack` `stat` pass-through at all: every other
/// scoped test on that build goes through `read` or `list`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_drain_owning_layer_registers_a_stat_that_answers_not_found() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///folder/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: None,
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    backend.inner.set_stat_error(Some(ErrorCode::NotFound));
    let address = Url::parse("mem:///folder/missing").unwrap();
    assert!(
        stack.stat(stat_request(&address), None).await.is_err(),
        "the stat must actually answer NotFound, or this test proves nothing"
    );
    wait_for(
        &backend.queue.active,
        1,
        "scoped watch from a negative stat alone",
    )
    .await;
    assert!(
        watched_prefixes(&backend).contains(&"mem:///folder/".to_string()),
        "a stat that answers NotFound must still register its directory, got {:?}",
        watched_prefixes(&backend)
    );

    // The negative half of the cacheability predicate, which decides whether
    // registering is worth a candidate slot at all: a `full_metadata` stat and a
    // paginated list produce no cache entry below, so neither may open a watch.
    let opens_before = backend.queue.opens.load(Ordering::SeqCst);
    stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("mem:///other/missing").unwrap(),
                options: StatOptions {
                    full_metadata: true,
                },
            }),
            None,
        )
        .await
        .expect_err("the scripted stat error still applies");
    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("mem:///other/?page=2").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        backend.queue.opens.load(Ordering::SeqCst),
        opens_before,
        "a form that caches nothing must not spend a watch, got {:?}",
        watched_prefixes(&backend)
    );
    drop(stack);
}

/// A read the stack REFUSED must not choose where a watch opens.
///
/// Gating the registration on `cacheable` alone —
/// `if_match.is_none() && range.is_none()` — decides it from the REQUEST, before
/// the backend is asked anything, so a caller the backend turns away still names
/// a prefix. Three things follow: the layer below takes `?` on the refusal and
/// caches nothing, so the scope protects an empty set; it spends one of four
/// watch slots; and the drain that opens it carries no principal, so a refused
/// caller steers what a more privileged component subscribes to.
///
/// Both errors are injected because either alone proves nothing. With only the
/// stat refused the read still succeeds and legitimately caches a body, and the
/// commit point registers the same scope — indistinguishable from the defect.
///
/// The two halves use DIFFERENT directories, and the control is awaited rather
/// than slept on. Sharing one prefix makes the pair unfalsifiable: under the
/// defect the refused read registers it, and a supervisor that is merely slow
/// satisfies the negative assertion and then the control, with the watch the
/// control "proves" being the one the refusal opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_read_registers_no_watch_candidate() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///folder/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: None,
        },
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    backend
        .inner
        .set_stat_error(Some(ErrorCode::PermissionDenied));
    backend
        .inner
        .set_read_error(Some(ErrorCode::PermissionDenied));
    stack
        .read(read_request("mem:///folder/denied/secret"), None)
        .await
        .expect_err("the read must actually be refused, or this proves nothing");

    // The allowed half, under its own directory. Awaiting ITS watch is what
    // orders the assertion below: the supervisor has demonstrably run a
    // selection pass after the refused read, so a missing `denied/` watch is a
    // decision rather than a race.
    backend.inner.set_stat_error(None);
    backend.inner.set_read_error(None);
    stack
        .read(read_request("mem:///folder/allowed/obj"), None)
        .await
        .expect("the allowed read must succeed");
    wait_for(
        &backend.queue.active,
        1,
        "a watch for the directory an ALLOWED read named",
    )
    .await;
    assert!(
        watched_prefixes(&backend).contains(&"mem:///folder/allowed/".to_string()),
        "control: an allowed read must still register its directory, got {:?}",
        watched_prefixes(&backend)
    );
    assert!(
        !watched_prefixes(&backend).contains(&"mem:///folder/denied/".to_string()),
        "a refused read must not name a watch prefix, got {:?}",
        watched_prefixes(&backend)
    );
    drop(stack);
}

/// The narrowing trigger is `PermissionDenied` and nothing else. Authorization
/// is the mechanism that is prefix-scoped by construction, so a refusal is the
/// one code where a narrower prefix has a reason to answer differently; the
/// others would spend the probe budget on a guess.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_refusal_narrows_the_watch() {
    for code in [ErrorCode::Unsupported, ErrorCode::Internal] {
        let backend = CountingWatchBackend::with_watch_behavior(
            CacheProbe::new(b"payload", Vec::new()),
            true,
            WatchOpen::Error(code),
        );
        let dir = tempfile::tempdir().unwrap();
        let stack = cache_stack(backend.clone(), dir.path()).await;
        wait_for(&backend.queue.opens, 1, "terminal root watch").await;

        read_dirs(&stack, &["mem:///folder/obj", "mem:///other/obj"]).await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        assert_eq!(
            watched_prefixes(&backend),
            vec!["mem:///".to_string()],
            "{code:?} must stay TTL-only rather than probe narrower prefixes"
        );
        drop(stack);
    }
}

/// A deployment that grants no watch at any prefix must cost a bounded number
/// of refused opens, not one per directory the cache ever reads.
///
/// The bound is the root's probe budget, not the candidate registry's size.
/// The registry is a bookkeeping table sized for the working set rather than
/// for the watch budget, so it cannot be what stops a workload walking fresh
/// directories from probing each of them — that is exactly the axis
/// `MAX_CONSECUTIVE_SCOPE_FAILURES` exists for: eight consecutive scope
/// failures under one root, with none granted in between, stop new probes under
/// it for the retry interval.
///
/// Each failure costs up to TWO refused opens, because a refused recursive
/// watch is retried for the directory's immediate children before being
/// recorded as denied.
///
/// The drain count is NOT the failure budget. `MAX_WATCH_SCOPES` (4) drains
/// start unprompted, charged to nothing, and each failure before the budget is
/// spent frees a slot that the same reconcile refills — so failures 1..7 buy
/// seven replacements and the ceiling is 4 + 7 = 11 drains, or 1 + 2 * 11 = 23
/// opens against forty directories read.
///
/// Which number a run actually reaches depends only on how drain deaths batch
/// up at the supervisor's wake: all four observed together gives 8 drains and
/// 17 opens, one at a time gives 11 and 23. Both are ordinary interleavings, so
/// the bound has to be the worst case — asserting the best case is a coin
/// flip, not a property.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deployment_that_grants_no_watch_probes_a_bounded_number_of_times() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::Error(ErrorCode::PermissionDenied),
    );
    let dir = tempfile::tempdir().unwrap();
    let stack = cache_stack(backend.clone(), dir.path()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    for i in 0..40 {
        stack
            .read(read_request(&format!("mem:///dir{i}/obj")), None)
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    let opens = backend.queue.opens.load(Ordering::SeqCst);
    assert!(
        opens > 1,
        "the refusal must be probed at least once, or this test proves nothing"
    );
    assert!(
        // 1 + 2 * (MAX_WATCH_SCOPES + MAX_CONSECUTIVE_SCOPE_FAILURES - 1),
        // spelled out because those constants are private to the cache crate.
        opens <= 23,
        "40 directories may not become 40 probes: the root plus two attempts \
         for each of the at most eleven drains the probe budget allows, saw \
         {opens} opens"
    );
    drop(stack);
}

/// Selection is not coverage. A broader candidate covers the scopes beneath it
/// only once its own watch is open and recursive — until then it is a scope
/// that has proved nothing, and its open may take a long time or never
/// succeed, an ordinary broker restart being enough to keep it retrying with
/// backoff indefinitely.
///
/// So a working narrower watch is kept. Retiring it in favour of the unproven
/// cover would sweep its subtree and leave every later read under it filling
/// entries with no watch at all, served until the metadata TTL rather than
/// invalidated when they actually change.
///
/// The covering watch here never opens, which is what makes the test isolate
/// the rule: nothing but the narrower drain can be reporting this subtree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_narrower_watch_is_kept_until_its_cover_actually_opens() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::RefuseUnlessUnder {
            allowed: Url::parse("mem:///a/").unwrap(),
            code: ErrorCode::PermissionDenied,
            stall: Some(Url::parse("mem:///a/").unwrap()),
        },
    );
    let stack = metadata_stack(backend.clone()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    let address = Url::parse("mem:///a/b/obj").unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    wait_for(&backend.queue.active, 1, "scoped watch on mem:///a/b/").await;

    // Fill AFTER the watch is live AND after the activation sweep that open
    // dispatches has run. Filling on `active` alone proves nothing: the sweep
    // is dispatched after the backend returns the stream, so it can land later
    // and wipe the entry.
    await_activation_sweep(&stack, &backend, &address).await;
    stack.stat(stat_request(&address), None).await.unwrap();
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the entry must be cached first, or this test proves nothing");
    backend.inner.set_stat_error(None);

    // A listing of the parent registers a candidate that would cover the scope
    // above — but its own watch stalls and never opens.
    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("mem:///a/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        backend.queue.active.load(Ordering::SeqCst),
        1,
        "the working narrower watch must be kept while its cover has not opened"
    );

    // And it is still doing its job: the backend's stat now fails, so an answer
    // can only come from an entry the narrower watch is still protecting.
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the subtree the kept watch protects must still be served");
    drop(stack);
}

/// The mirror of the test above, and the direction that makes the feature
/// harmful if it is wrong: a scope whose watch was refused before it ever
/// opened protected nothing, so retiring it must NOT sweep.
///
/// Sweeping it anyway would delete a subtree of cache entries on every refusal
/// — in the deployment where every scope is refused, that is a periodic cache
/// wipe for no benefit at all, leaving the feature strictly worse than leaving
/// it switched off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retiring_a_scope_that_never_opened_does_not_sweep() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::Error(ErrorCode::PermissionDenied),
    );
    let stack = metadata_stack(backend.clone()).await;
    wait_for(&backend.queue.opens, 1, "refused root watch").await;

    let address = Url::parse("mem:///a/b/obj").unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();

    // The directory is probed recursively, refused, retried for its immediate
    // children, refused again, and then retired. Three opens is the root plus
    // both of those probes; asserting it keeps the test from passing because
    // nothing ever happened.
    wait_for(&backend.queue.opens, 3, "both refused scope probes").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        backend.queue.active.load(Ordering::SeqCst),
        0,
        "the refused probe must not have left a live watch"
    );

    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("a refused scope protected nothing, so retiring it must not discard the cache");
    drop(stack);
}

/// **The honest case for the narrower ask.** A directory whose RECURSIVE watch
/// is refused and whose non-recursive watch is granted must end up watched, not
/// recorded as denied.
///
/// Recursion is a second axis a watch can be narrowed on, and on some backends
/// it is the axis that was actually refused: the file backend walks descendant
/// directories to build a recursive snapshot, so a descendant the filesystem
/// denies fails only the recursive form, and the Storage Service client maps
/// recursion onto a wider remote filter. Treating the first refusal as final
/// would leave those deployments TTL-only for a watch they were willing to
/// grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_recursive_scope_is_watched_narrowly_rather_than_denied() {
    let backend = CountingWatchBackend::with_watch_behavior(
        CacheProbe::new(b"payload", Vec::new()),
        true,
        WatchOpen::RefuseRecursive {
            code: ErrorCode::PermissionDenied,
        },
    );
    let stack = metadata_stack(backend.clone()).await;
    wait_for(&backend.queue.opens, 1, "the refused recursive root watch").await;

    let address = Url::parse("mem:///folder/obj").unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();

    // The scope is asked recursively, refused, and asked again for its
    // immediate children — which this backend grants.
    wait_for(&backend.queue.active, 1, "the narrowed scope watch").await;
    let opens: Vec<(String, bool)> = {
        let prefixes = backend.queue.prefixes.lock().unwrap();
        let options = backend.queue.options.lock().unwrap();
        prefixes
            .iter()
            .zip(options.iter())
            .map(|(p, o)| (p.as_str().to_string(), o.recursive))
            .collect()
    };
    assert!(
        opens.contains(&("mem:///folder/".to_string(), true)),
        "the recursive form must be tried first, got {opens:?}"
    );
    assert!(
        opens.contains(&("mem:///folder/".to_string(), false)),
        "and the refusal must be retried with the smaller ask, got {opens:?}"
    );

    // And the narrowed watch is a real invalidation path, not just an open
    // stream. Fill AFTER it is live AND after its activation sweep: the stats
    // above ran before the open, whose sweep removes their entry before any
    // event is consumed. `active` does not order against that sweep, so filling
    // on it alone lets the sweep land later and clear the entry — and the loop
    // below cannot tell a swept entry from an invalidated one, so that is a
    // false green rather than a flake. Waiting for the earlier entry to
    // disappear is the barrier.
    await_activation_sweep(&stack, &backend, &address).await;
    stack.stat(stat_request(&address), None).await.unwrap();
    stack.stat(stat_request(&address), None).await.unwrap();
    let stats_before = backend.inner.stats.load(Ordering::SeqCst);
    backend.inner.set_stat_error(Some(ErrorCode::Transient));
    stack
        .stat(stat_request(&address), None)
        .await
        .expect("the entry must be served from cache first, or the event proves nothing");
    assert_eq!(
        backend.inner.stats.load(Ordering::SeqCst),
        stats_before,
        "and served without reaching the backend"
    );
    backend.inject(modified(address.as_str()));
    for _ in 0..500 {
        let result = stack.stat(stat_request(&address), None).await;
        if result.is_err() && backend.inner.stats.load(Ordering::SeqCst) > stats_before {
            drop(stack);
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the narrowed scope watch delivered no invalidation");
}
