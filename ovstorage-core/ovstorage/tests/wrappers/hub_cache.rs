// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `HubCacheWrapper` behavior at the `Stack` level: hit/miss/revalidation on
//! an etag change, the two cross-process races (`PENDING_WRITE` and
//! `ALREADY_EXISTS`), hub-down pass-through, the extension trap, handle-leak
//! accounting, the no-validator rule, stale-never behavior under concurrent
//! readers, and the streaming-tee invariant. Each test composes
//! `HubCacheWrapperFactory` above a programmable backend `Layer` through
//! [`common::build_stack`] and an in-process [`FakeHub`], and drives the
//! composition through the public `Stack` API, exactly as the other wrapper
//! suites do.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::StreamExt as _;
use ovstorage::{
    CancellationToken, ConfigValue, EtagStrength, Layer, LayerConfig, LayerHandle,
    LayerKindDescriptor, ObjectInfo, ReadRequest, ReadResult, ReadStream, Request, Result, Stack,
    StatRequest, Url,
};
use ovstorage_hub_client::fake::{EntryState, FakeHub};
use ovstorage_hub_client::{HubCacheClient, HubClientConfig, KeyScheme, WriteOpen, hub_key};
use ovstorage_plugin_hub_cache::{HUB_CACHE_KIND, HubCacheWrapperFactory};

use crate::common::*;

/// An already-canonical address: the `Stack` canonicalization boundary
/// (`ovstorage_layer::address::canonicalize`) is a no-op on it, so parsing
/// this string directly derives the same key the wrapper derives from the
/// request it actually receives.
const ADDRESS: &str = "test:///assets/scene.usd";

/// The `partition` every test leaves at its config default.
const PARTITION: &str = "local";

/// The fixed body every backend in this file answers `ADDRESS` with, unless
/// a test overrides it.
const CONTENT: &[u8] = b"the cached scene body";

/// A `hub_cache` config pointing `endpoint` at `hub`; `partition` and
/// `key_scheme` are left at their defaults (`local`, `ovstorage`).
fn hub_cache_config(hub: &FakeHub) -> LayerConfig {
    let mut config = LayerConfig::new();
    config.insert("endpoint".to_string(), ConfigValue::String(hub.endpoint()));
    config
}

/// Composes [`HubCacheWrapperFactory`] above `backend`, pointed at `hub`.
async fn hub_cache_stack(backend: LayerHandle, hub: &FakeHub) -> Stack {
    build_stack(
        HUB_CACHE_KIND,
        Arc::new(HubCacheWrapperFactory),
        backend,
        hub_cache_config(hub),
    )
    .await
    .expect("the hub_cache stack builds")
}

/// The hub key a default-configured wrapper derives for `url` at `etag`.
fn key_for(url: &str, etag: &str) -> String {
    let parsed = Url::parse(url).unwrap();
    hub_key(KeyScheme::Ovstorage, PARTITION, &parsed, etag, None)
        .expect("a non-empty etag keys")
        .key
}

/// The hub key a default-configured wrapper derives for [`ADDRESS`] at
/// `etag`.
fn expected_key(etag: &str) -> String {
    key_for(ADDRESS, etag)
}

/// A `HubCacheClient` dialed directly at `hub`, for the tests that hold a
/// raw lease the wrapper's own client cannot see — the wrapper (and the
/// client it owns) is private to the composed `Stack`.
fn raw_client(hub: &FakeHub) -> HubCacheClient {
    HubCacheClient::new(HubClientConfig {
        endpoint: hub.endpoint(),
        ..HubClientConfig::default()
    })
}

// ---------------------------------------------------------------------------
// 1. hit / miss / revalidation on an etag change
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_miss_fills_a_hit_reuses_it_and_a_changed_etag_fills_a_second_entry() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = hub_cache_stack(backend.clone(), &hub).await;

    // First read misses and fills.
    let first = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(first).await, CONTENT);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    let v1_key = expected_key(&backend.etag());
    assert!(matches!(
        hub.entry(&v1_key),
        Some(EntryState::Committed { .. })
    ));

    // Second read hits: no second backend read, identical bytes.
    let second = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(second).await, CONTENT);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "a hit must not re-read the backend"
    );

    // The source changes underneath the warm entry: the validator moves, so
    // the old key can no longer answer and the read misses again under the
    // new etag.
    backend.bump_version();
    let v2_key = expected_key(&backend.etag());
    assert_ne!(v1_key, v2_key, "a changed etag must derive a different key");

    let third = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(third).await, CONTENT);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a changed etag is a miss, not a hit on the stale entry"
    );
    hub.wait_for("the second entry commits", |hub| {
        matches!(hub.entry(&v2_key), Some(EntryState::Committed { .. }))
    })
    .await;
    // The first entry is untouched — simply unreachable now, not
    // invalidated: write-once keys give a stale entry nothing to
    // invalidate.
    assert!(matches!(
        hub.entry(&v1_key),
        Some(EntryState::Committed { .. })
    ));

    // Fourth read hits the new entry.
    let fourth = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(fourth).await, CONTENT);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the fourth read hits the v2 entry"
    );
}

// ---------------------------------------------------------------------------
// 2. PENDING_WRITE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_pending_write_is_served_from_the_backend_without_a_second_write_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = hub_cache_stack(backend.clone(), &hub).await;

    // Another client holds a raw write lease on the exact key this read
    // will derive.
    let holder = raw_client(&hub);
    let key = hub_key(
        KeyScheme::Ovstorage,
        PARTITION,
        &Url::parse(ADDRESS).unwrap(),
        &backend.etag(),
        None,
    )
    .unwrap();
    let WriteOpen::Opened(pending) = holder
        .open_for_write(
            &key.key,
            &key.provider,
            &key.extension,
            CONTENT.len() as u64,
        )
        .await
        .unwrap()
    else {
        panic!("the holder reserves the key");
    };

    let result = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(result).await, CONTENT);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        hub.counters().opens_for_write,
        1,
        "a pending key is not refilled"
    );

    pending.abort().await;
}

// ---------------------------------------------------------------------------
// 3. ALREADY_EXISTS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn already_exists_serves_the_backend_without_disturbing_the_committed_entry() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = hub_cache_stack(backend.clone(), &hub).await;

    // Warm the cache.
    let first = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(first).await, CONTENT);
    let key = expected_key(&backend.etag());
    hub.wait_for("the fill commits", |hub| {
        matches!(hub.entry(&key), Some(EntryState::Committed { .. }))
    })
    .await;
    let committed_before = hub.committed_bytes(&key);
    assert_eq!(committed_before.as_deref(), Some(CONTENT));

    // Arm the deterministic reproduction of the cross-process fill race:
    // this reader's own lookup answers not-cached even though the entry is
    // committed, as if another client's commit had landed between this
    // reader's `stat` and its own `OpenForRead`.
    hub.answer_not_cached_once(&key);

    let second = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(second).await, CONTENT);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "a lookup that saw not-cached still serves the backend"
    );
    assert!(
        matches!(hub.entry(&key), Some(EntryState::Committed { .. })),
        "the already-committed entry must not be disturbed by the racer's ALREADY_EXISTS"
    );
    assert_eq!(
        hub.committed_bytes(&key),
        committed_before,
        "the racer's ALREADY_EXISTS must not touch the committed bytes"
    );

    // The override was one-shot: the read after that hits normally again.
    let third = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(third).await, CONTENT);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        2,
        "the override is consumed, so the entry answers again"
    );
}

// ---------------------------------------------------------------------------
// 4. hub-down pass-through
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_hub_that_shuts_down_serves_reads_from_the_backend() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = hub_cache_stack(backend.clone(), &hub).await;
    hub.shutdown();

    for _ in 0..2 {
        let result = stack.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
    }
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_stack_pointed_at_an_endpoint_that_never_existed_serves_reads_from_the_backend() {
    // A loopback port nothing is listening on: bind it, then drop the
    // listener before the stack ever dials it, so a connection attempt is
    // refused rather than hanging.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    drop(listener);

    let backend = CacheProbe::new(CONTENT, Vec::new());
    let mut config = LayerConfig::new();
    config.insert("endpoint".to_string(), ConfigValue::String(endpoint));
    let stack = build_stack(
        HUB_CACHE_KIND,
        Arc::new(HubCacheWrapperFactory),
        backend.clone(),
        config,
    )
    .await
    .expect("the stack builds without dialing the hub");

    let result = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(result).await, CONTENT);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// 5. extension-trap guard
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_extension_trap_serves_the_backend_without_a_fill_and_leaks_no_handle() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = hub_cache_stack(backend.clone(), &hub).await;

    // The entry exists under the key this read derives, but was written
    // with an extension other than the fixed one the `ovstorage` key scheme
    // always uses (`bin`), so the path the hub answers with does not exist.
    let key = expected_key(&backend.etag());
    hub.seed_entry(&key, "usd", CONTENT);

    let result = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(result).await, CONTENT);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        hub.counters().opens_for_write,
        0,
        "a taken key is never refilled"
    );

    // The wrapper's client is private, so quiesce by polling the hub's own
    // handle count instead of the client directly.
    hub.wait_for_open_handles(0).await;
}

// ---------------------------------------------------------------------------
// 6. handle-leak accounting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_mixed_sequence_of_outcomes_leaks_no_handle() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = hub_cache_stack(backend.clone(), &hub).await;
    let etag = backend.etag();

    // Miss + fill.
    let miss_url = "test:///assets/miss.usd";
    let missed = stack.read(read_request(miss_url), None).await.unwrap();
    assert_eq!(collect(missed).await, CONTENT);

    // Hit, served as a leased delegate.
    let hit = stack.read(read_request(miss_url), None).await.unwrap();
    assert!(matches!(hit, ReadResult::LocalDelegate(_)));
    assert_eq!(collect(hit).await, CONTENT);

    // A trap: an entry exists but under a different extension.
    let trap_url = "test:///assets/trap.usd";
    let trap_key = key_for(trap_url, &etag);
    hub.seed_entry(&trap_key, "usd", CONTENT);
    let trapped = stack.read(read_request(trap_url), None).await.unwrap();
    assert_eq!(collect(trapped).await, CONTENT);

    // A write another client is in the middle of.
    let pending_url = "test:///assets/pending.usd";
    let pending_key = hub_key(
        KeyScheme::Ovstorage,
        PARTITION,
        &Url::parse(pending_url).unwrap(),
        &etag,
        None,
    )
    .unwrap();
    let holder = raw_client(&hub);
    let WriteOpen::Opened(pending) = holder
        .open_for_write(
            &pending_key.key,
            &pending_key.provider,
            &pending_key.extension,
            CONTENT.len() as u64,
        )
        .await
        .unwrap()
    else {
        panic!("the holder reserves the key");
    };
    let served = stack.read(read_request(pending_url), None).await.unwrap();
    assert_eq!(collect(served).await, CONTENT);
    pending.abort().await;
    hub.wait_for("the pending key is released", |hub| {
        hub.entry(&pending_key.key).is_none()
    })
    .await;

    // The hub going down mid-sequence.
    hub.shutdown();
    let down_url = "test:///assets/down.usd";
    let down = stack.read(read_request(down_url), None).await.unwrap();
    assert_eq!(collect(down).await, CONTENT);

    // Every handle this sequence opened was matched by a close or a
    // remove: nothing pins an entry once the sequence settles.
    hub.wait_for_open_handles(0).await;
    // The trap entry was never disturbed (its key was already taken).
    assert!(matches!(
        hub.entry(&trap_key),
        Some(EntryState::Committed { .. })
    ));
}

// ---------------------------------------------------------------------------
// 7. no-validator => no fill
// ---------------------------------------------------------------------------

#[tokio::test]
async fn omitting_the_stat_validator_never_touches_the_hub() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = CacheProbe::new(CONTENT, Vec::new());
    backend.omit_stat_validator();
    let stack = hub_cache_stack(backend.clone(), &hub).await;

    for _ in 0..2 {
        let result = stack.read(read_request(ADDRESS), None).await.unwrap();
        assert_eq!(collect(result).await, CONTENT);
    }
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
    assert_eq!(hub.counters().opens_for_read, 0);
    assert_eq!(hub.counters().opens_for_write, 0);
}

// ---------------------------------------------------------------------------
// 8. stale-never under concurrent readers
// ---------------------------------------------------------------------------

/// Pulls the `info` and body out of a `ReadResult` without discarding
/// `info` the way [`common::collect`] does — the stale-never assertion needs
/// the etag every concurrent reader actually saw.
async fn collect_with_info(result: ReadResult) -> (ObjectInfo, Vec<u8>) {
    match result {
        ReadResult::Bytes { bytes, info } => (info, bytes),
        ReadResult::Stream { mut stream, info } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk.expect("stream chunk"));
            }
            (info, out)
        }
        ReadResult::LocalDelegate(local) => {
            let bytes = tokio::fs::read(&local.path)
                .await
                .expect("delegate path reads");
            (local.info, bytes)
        }
        other => panic!("unexpected read result: {other:?}"),
    }
}

/// A backend whose body embeds its own version, so a reader wrongly served a
/// stale hub entry gets provably wrong bytes back instead of the same fixed
/// [`CONTENT`] every version would produce. Without this the 8-concurrent-
/// readers test below could not fail: [`CacheProbe`]'s body never changes
/// between versions, so a reader served the stale v1 hub entry and a reader
/// served the fresh v2 body are byte-for-byte indistinguishable.
struct VersionedProbe {
    version: AtomicUsize,
}

impl VersionedProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            version: AtomicUsize::new(1),
        })
    }

    fn etag(&self) -> String {
        format!("v{}", self.version.load(Ordering::SeqCst))
    }

    fn body(&self) -> Vec<u8> {
        format!("body-v{}", self.version.load(Ordering::SeqCst)).into_bytes()
    }

    fn bump_version(&self) {
        self.version.fetch_add(1, Ordering::SeqCst);
    }

    fn info(&self, address: Url) -> ObjectInfo {
        let body = self.body();
        ObjectInfo {
            etag: Some(self.etag()),
            etag_strength: EtagStrength::Strong,
            ..object_info(address, body.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for VersionedProbe {
    fn name(&self) -> &str {
        "versioned"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        Ok(ReadResult::Bytes {
            bytes: self.body(),
            info: self.info(request.input.address),
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_concurrent_readers_never_see_a_stale_entry_after_the_source_changes() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let backend = VersionedProbe::new();
    let stack = Arc::new(hub_cache_stack(backend.clone(), &hub).await);

    // Warm the v1 entry.
    let warm = stack.read(read_request(ADDRESS), None).await.unwrap();
    assert_eq!(collect(warm).await, backend.body());
    let v1_key = expected_key(&backend.etag());
    hub.wait_for("the v1 entry commits", |hub| {
        matches!(hub.entry(&v1_key), Some(EntryState::Committed { .. }))
    })
    .await;

    // The source changes underneath the warm entry.
    backend.bump_version();
    let v2_etag = backend.etag();
    let v2_body = backend.body();
    let v2_key = expected_key(&v2_etag);
    assert_ne!(v1_key, v2_key);

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let stack = stack.clone();
        tasks.push(tokio::spawn(async move {
            let result = stack.read(read_request(ADDRESS), None).await.unwrap();
            collect_with_info(result).await
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.expect("reader task"));
    }

    for (info, bytes) in &results {
        assert_eq!(
            info.etag.as_deref(),
            Some(v2_etag.as_str()),
            "no reader may be served the stale v1 etag"
        );
        assert_eq!(
            bytes, &v2_body,
            "every reader gets the current backend body, not the stale hub entry's"
        );
    }

    // The v1 entry is simply unreachable now — no reader could have named
    // it, and nothing invalidates it.
    assert!(matches!(
        hub.entry(&v1_key),
        Some(EntryState::Committed { .. })
    ));
    hub.wait_for("a v2 entry commits", |hub| {
        matches!(hub.entry(&v2_key), Some(EntryState::Committed { .. }))
    })
    .await;
}

// ---------------------------------------------------------------------------
// 9. streaming invariant
// ---------------------------------------------------------------------------

/// Splits [`CONTENT`] into 4-byte chunks for the flow-counting backend.
fn flow_chunks() -> Vec<Vec<u8>> {
    CONTENT.chunks(4).map(<[u8]>::to_vec).collect()
}

/// Tracks how many chunks a [`FlowCountingBackend`]'s stream has produced
/// and how many the test has finished with, so a test can assert the
/// wrapper's tee never runs the backend ahead of its own consumer: `produced`
/// only advances when the backend's stream is polled, `released` only
/// advances when the test says a chunk is done, and `peak_in_flight` is the
/// high-water mark of `produced - released`.
#[derive(Default)]
struct FlowCounters {
    produced: AtomicUsize,
    released: AtomicUsize,
    peak_in_flight: AtomicUsize,
}

impl FlowCounters {
    fn record_produce(&self) {
        let produced = self.produced.fetch_add(1, Ordering::SeqCst) + 1;
        let released = self.released.load(Ordering::SeqCst);
        self.peak_in_flight
            .fetch_max(produced - released, Ordering::SeqCst);
    }

    fn record_release(&self) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }

    fn produced(&self) -> usize {
        self.produced.load(Ordering::SeqCst)
    }

    fn peak_in_flight(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }
}

/// A backend whose `read` streams [`CONTENT`] one chunk at a time, producing
/// the next chunk only when its stream is polled for it — nothing is ever
/// generated ahead of the chunk the caller currently holds. `stat` reports a
/// fixed etag so the wrapper's tee engages.
struct FlowCountingBackend {
    counters: Arc<FlowCounters>,
}

impl FlowCountingBackend {
    const ETAG: &'static str = "flow-etag";

    fn new(counters: Arc<FlowCounters>) -> Arc<Self> {
        Arc::new(Self { counters })
    }

    fn info(&self, address: Url) -> ObjectInfo {
        ObjectInfo {
            etag: Some(Self::ETAG.to_string()),
            etag_strength: EtagStrength::Strong,
            ..object_info(address, CONTENT.len() as u64)
        }
    }
}

#[async_trait::async_trait]
impl Layer for FlowCountingBackend {
    fn name(&self) -> &str {
        "flow"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        Ok(self.info(request.input.address))
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let info = self.info(request.input.address);
        let counters = self.counters.clone();
        let stream: ReadStream = Box::pin(futures::stream::unfold(
            flow_chunks().into_iter(),
            move |mut chunks| {
                let counters = counters.clone();
                async move {
                    let chunk = chunks.next()?;
                    counters.record_produce();
                    Some((Ok(bytes::Bytes::from(chunk)), chunks))
                }
            },
        ));
        Ok(ReadResult::Stream { stream, info })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_streamed_fill_tees_one_chunk_at_a_time_and_a_mid_stream_drop_commits_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let hub = FakeHub::start(dir.path()).await;
    let counters = Arc::new(FlowCounters::default());
    let backend = FlowCountingBackend::new(counters.clone());
    let stack = hub_cache_stack(backend, &hub).await;

    let result = stack.read(read_request(ADDRESS), None).await.unwrap();
    let ReadResult::Stream { mut stream, info } = result else {
        panic!("a miss on a streaming backend stays a stream");
    };
    assert_eq!(info.etag.as_deref(), Some(FlowCountingBackend::ETAG));

    let total_chunks = flow_chunks().len();
    assert!(
        total_chunks > 2,
        "the test needs bytes left unpulled to drop mid-stream"
    );

    for expected_pulls in 1..=2 {
        let chunk = stream.next().await.expect("a chunk").expect("ok");
        assert_eq!(
            counters.produced(),
            expected_pulls,
            "one pull of the caller's stream must produce exactly one chunk"
        );
        assert!(
            counters.peak_in_flight() <= 1,
            "no more than one chunk may be in flight at once"
        );
        assert!(!chunk.is_empty());
        counters.record_release();
    }
    let produced_before_drop = counters.produced();

    // Drop mid-stream: the caller abandons the body before it ends. Nothing
    // else ever polls this stream, so production cannot advance further.
    drop(stream);
    assert_eq!(
        counters.produced(),
        produced_before_drop,
        "dropping the caller's stream must not pull further chunks"
    );

    let key = expected_key(FlowCountingBackend::ETAG);
    hub.wait_for("the abandoned fill leaves no committed entry", |hub| {
        hub.entry(&key).is_none()
    })
    .await;
    hub.wait_for_open_handles(0).await;
}

// ---------------------------------------------------------------------------
// 10. live tier (env-gated, opt-in)
// ---------------------------------------------------------------------------

/// Exercises a real, already-running hub at the default endpoint. Opt-in:
/// most environments have no hub listening on `127.0.0.1:14093`, so this
/// self-skips unless `OVSTORAGE_HUB_LIVE_TEST` is set, mirroring the
/// self-skip style `tests/plugin_loading.rs` uses for its environment-gated
/// legs. `make test-hub-live` runs this tier as one command, launching a
/// hub first when none is listening.
#[tokio::test]
async fn live_hub_round_trip() {
    if std::env::var_os("OVSTORAGE_HUB_LIVE_TEST").is_none() {
        eprintln!("skipping: OVSTORAGE_HUB_LIVE_TEST not set");
        return;
    }

    let backend = CacheProbe::new(CONTENT, Vec::new());
    let stack = build_stack(
        HUB_CACHE_KIND,
        Arc::new(HubCacheWrapperFactory),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .expect("the default-endpoint stack builds");

    // A unique address per run/process, so repeated runs against a real,
    // persistent hub never collide with a previous run's entry.
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let unique = format!(
        "test:///assets/live-hub-round-trip-{}-{}.usd",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    );

    let first = stack.read(read_request(&unique), None).await.unwrap();
    assert_eq!(collect(first).await, CONTENT);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);

    let second = stack.read(read_request(&unique), None).await.unwrap();
    assert_eq!(collect(second).await, CONTENT);
    assert_eq!(
        backend.reads.load(Ordering::SeqCst),
        1,
        "the second read must hit the live hub's cached entry"
    );
}
