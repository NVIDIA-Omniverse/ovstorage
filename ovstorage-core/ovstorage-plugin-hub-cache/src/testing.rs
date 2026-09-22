// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scaffolding the `read` and `materialize` tests share: a scriptable inner
//! layer, and a fixture that stands a fake hub in front of it.
//!
//! One `Probe` serves both paths so the two cannot drift over what the
//! inner layer answered — the cases that matter (a validator that drifts
//! between `stat` and the body, a backend that streams but cannot stage a
//! file) are the same cases in both.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::StreamExt as _;
use ovstorage_hub_client::fake::{FakeHub, FakeHubConfig};
use ovstorage_hub_client::{KeyScheme, hub_key};
use ovstorage_plugin::*;

use crate::{HUB_CACHE_KIND, HubCacheWrapper, HubCacheWrapperFactory};

pub(crate) const CONTENT: &[u8] = b"the cached body";
pub(crate) const ADDRESS: &str = "test:///assets/scene.usd";
pub(crate) const ETAG: &str = "v1";

/// What [`Probe::materialize`] answers.
pub(crate) enum MaterializeAnswer {
    /// The composition this layer exists for: a backend that streams bytes
    /// but cannot produce a local file, so its `materialize` refuses.
    Unsupported,
    /// A file the inner layer already staged and can hand back itself.
    Staged(PathBuf),
}

/// A programmable inner layer: `stat` reports `etag`/`stat_size`, `read`
/// answers `CONTENT` as bytes, a chunked stream, or a delegate under
/// `read_etag`, `materialize` answers `materialize_answer`, and every slot
/// counts its calls.
pub(crate) struct Probe {
    pub(crate) reads: AtomicUsize,
    pub(crate) stats: AtomicUsize,
    pub(crate) materializes: AtomicUsize,
    pub(crate) etag: Mutex<Option<String>>,
    /// The strength `stat` declares for its etag. Strong by default, since
    /// only a strong validator keys the cache at all.
    pub(crate) etag_strength: Mutex<EtagStrength>,
    pub(crate) read_etag: Mutex<Option<String>>,
    /// The modification time `stat` and `read` report, when set — cached
    /// answers must not echo it back for the hub's own file.
    pub(crate) mtime: Mutex<Option<std::time::SystemTime>>,
    /// The strength `read` declares, when it differs from `stat`'s — a
    /// source that demotes its validator mid-flight.
    pub(crate) read_etag_strength: Mutex<Option<EtagStrength>>,
    pub(crate) stat_size: Mutex<Option<u64>>,
    pub(crate) stat_error: Mutex<Option<ErrorCode>>,
    pub(crate) stream_chunk: Mutex<Option<usize>>,
    /// When set, `read` answers with a delegate at this path instead of a
    /// body.
    pub(crate) read_delegate: Mutex<Option<PathBuf>>,
    pub(crate) materialize_answer: Mutex<MaterializeAnswer>,
    /// When set, `read` answers `Err` with this code instead of a body.
    pub(crate) read_error: Mutex<Option<ErrorCode>>,
    /// When set and `stream_chunk` is also set, the streamed read yields
    /// this many `Ok` chunks and then one `Err` — an injected mid-body
    /// failure rather than a clean or truncated end.
    pub(crate) stream_error_after: Mutex<Option<usize>>,
    /// When set, `read`'s body is these bytes instead of [`CONTENT`], while
    /// `stat_size` is untouched — so a streamed or buffered body can be
    /// longer or shorter than the size the validator probe declared.
    pub(crate) content_override: Mutex<Option<Vec<u8>>>,
    /// When set, `stat` and `read` report this raw md5 digest in their
    /// checksums, the way a backend surfaces a `Content-MD5` header.
    pub(crate) md5: Mutex<Option<Vec<u8>>>,
    /// When set, `read` cancels this token before answering — the caller
    /// gives up exactly as the body starts flowing.
    pub(crate) cancel_on_read: Mutex<Option<CancellationToken>>,
    /// When set, `stat` cancels this token before answering — the caller
    /// gives up while the validator probe is in flight, so every later
    /// stage sees an already-fired token.
    pub(crate) cancel_on_stat: Mutex<Option<CancellationToken>>,
    /// When set alongside `stream_chunk`, the streamed body yields this
    /// many chunks and then stays pending forever — a source that stops
    /// answering mid-body without erroring or ending.
    pub(crate) stall_after: Mutex<Option<usize>>,
    /// When set alongside `stall_after`, the stream cancels this token as
    /// it enters its stall — a caller that gives up exactly while the next
    /// chunk is being awaited.
    pub(crate) cancel_on_stall: Mutex<Option<CancellationToken>>,
}

impl Probe {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            reads: AtomicUsize::new(0),
            stats: AtomicUsize::new(0),
            materializes: AtomicUsize::new(0),
            etag: Mutex::new(Some(ETAG.to_string())),
            etag_strength: Mutex::new(EtagStrength::Strong),
            read_etag: Mutex::new(Some(ETAG.to_string())),
            mtime: Mutex::new(None),
            read_etag_strength: Mutex::new(None),
            stat_size: Mutex::new(Some(CONTENT.len() as u64)),
            stat_error: Mutex::new(None),
            stream_chunk: Mutex::new(None),
            read_delegate: Mutex::new(None),
            materialize_answer: Mutex::new(MaterializeAnswer::Unsupported),
            read_error: Mutex::new(None),
            stream_error_after: Mutex::new(None),
            content_override: Mutex::new(None),
            md5: Mutex::new(None),
            cancel_on_read: Mutex::new(None),
            cancel_on_stat: Mutex::new(None),
            stall_after: Mutex::new(None),
            cancel_on_stall: Mutex::new(None),
        })
    }

    fn info(&self, address: Url, etag: Option<String>, strength: EtagStrength) -> ObjectInfo {
        let mut checksums = ChecksumSet::default();
        if let Some(digest) = self.md5.lock().unwrap().clone() {
            checksums.insert(ChecksumAlgorithm::md5(), digest);
        }
        ObjectInfo {
            address,
            kind: ObjectKind::File,
            etag,
            etag_strength: strength,
            version: None,
            size: Some(CONTENT.len() as u64),
            mtime: *self.mtime.lock().unwrap(),
            checksums,
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
            versioned_address: None,
        }
    }
}

#[async_trait::async_trait]
impl Layer for Probe {
    fn name(&self) -> &str {
        "probe"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            display_name: "probe".to_string(),
            kind: "probe".to_string(),
            layer_type: LayerType::Backend,
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

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.stats.fetch_add(1, Ordering::SeqCst);
        if let Some(token) = self.cancel_on_stat.lock().unwrap().take() {
            token.cancel();
        }
        if let Some(code) = *self.stat_error.lock().unwrap() {
            return Err(Error::new(code, "scripted stat failure"));
        }
        let mut info = self.info(
            request.input.address,
            self.etag.lock().unwrap().clone(),
            *self.etag_strength.lock().unwrap(),
        );
        info.size = *self.stat_size.lock().unwrap();
        Ok(info)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(token) = self.cancel_on_read.lock().unwrap().take() {
            token.cancel();
        }
        if let Some(code) = *self.read_error.lock().unwrap() {
            return Err(Error::new(code, "scripted read failure"));
        }
        let content = self
            .content_override
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| CONTENT.to_vec());
        let strength = self
            .read_etag_strength
            .lock()
            .unwrap()
            .unwrap_or(*self.etag_strength.lock().unwrap());
        let mut info = self.info(
            request.input.address,
            self.read_etag.lock().unwrap().clone(),
            strength,
        );
        info.size = Some(content.len() as u64);
        if let Some(path) = self.read_delegate.lock().unwrap().clone() {
            return Ok(ReadResult::LocalDelegate(LocalDelegate {
                path,
                info,
                guard: None,
            }));
        }
        if let Some(chunk_size) = *self.stream_chunk.lock().unwrap() {
            let mut chunks: Vec<Result<bytes::Bytes>> = content
                .chunks(chunk_size)
                .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
                .collect();
            if let Some(after) = *self.stream_error_after.lock().unwrap() {
                chunks.truncate(after);
                chunks.push(Err(Error::new(
                    ErrorCode::Transient,
                    "scripted stream failure",
                )));
            }
            if let Some(after) = *self.stall_after.lock().unwrap() {
                chunks.truncate(after);
                let cancel = self.cancel_on_stall.lock().unwrap().take();
                let stall = futures::stream::once(async move {
                    if let Some(token) = cancel {
                        token.cancel();
                    }
                    std::future::pending::<Result<bytes::Bytes>>().await
                });
                let stream: ReadStream = Box::pin(futures::stream::iter(chunks).chain(stall));
                return Ok(ReadResult::Stream { stream, info });
            }
            let stream: ReadStream = Box::pin(futures::stream::iter(chunks));
            return Ok(ReadResult::Stream { stream, info });
        }
        Ok(ReadResult::Bytes {
            bytes: content,
            info,
        })
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        self.materializes.fetch_add(1, Ordering::SeqCst);
        let info = self.info(
            request.input.address,
            self.read_etag.lock().unwrap().clone(),
            *self.etag_strength.lock().unwrap(),
        );
        match &*self.materialize_answer.lock().unwrap() {
            MaterializeAnswer::Unsupported => Err(Error::new(
                ErrorCode::Unsupported,
                "the probe stages no local files",
            )),
            MaterializeAnswer::Staged(path) => Ok(LocalDelegate {
                path: path.clone(),
                info,
                guard: None,
            }),
        }
    }
}

pub(crate) struct Fixture {
    // Held for its Drop: the fake serves files out of this directory.
    _dir: tempfile::TempDir,
    pub(crate) hub: FakeHub,
    pub(crate) probe: Arc<Probe>,
    pub(crate) wrapper: HubCacheWrapper,
}

pub(crate) async fn fixture(tweak: impl FnOnce(&mut LayerConfig)) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let hub = FakeHub::start(dir.path().to_path_buf()).await;
    let probe = Probe::new();
    let mut config = LayerConfig::new();
    config.insert("endpoint".to_string(), ConfigValue::String(hub.endpoint()));
    tweak(&mut config);
    let wrapper = HubCacheWrapperFactory
        .build("hub-cache", &config, probe.clone())
        .expect("the wrapper builds");
    assert_eq!(wrapper.descriptor.kind, HUB_CACHE_KIND);
    Fixture {
        _dir: dir,
        hub,
        probe,
        wrapper,
    }
}

/// Builds a [`Fixture`] like [`fixture`], but starts the fake hub with
/// `hub_config` instead of [`FakeHubConfig::default`] — the only way a test
/// can drive the hub's own refusals (an entry size over `max_entry_size`,
/// an advertised interface list, a software version).
pub(crate) async fn fixture_with_hub_config(
    hub_config: FakeHubConfig,
    tweak: impl FnOnce(&mut LayerConfig),
) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let hub = FakeHub::start_with(dir.path().to_path_buf(), hub_config).await;
    let probe = Probe::new();
    let mut config = LayerConfig::new();
    config.insert("endpoint".to_string(), ConfigValue::String(hub.endpoint()));
    tweak(&mut config);
    let wrapper = HubCacheWrapperFactory
        .build("hub-cache", &config, probe.clone())
        .expect("the wrapper builds");
    assert_eq!(wrapper.descriptor.kind, HUB_CACHE_KIND);
    Fixture {
        _dir: dir,
        hub,
        probe,
        wrapper,
    }
}

/// An [`ObjectInfo`] carrying the fixture's identity — a strong [`ETAG`]
/// and [`CONTENT`]'s size — for tests that build a [`crate::read::ValidatorProbe`]
/// by hand.
pub(crate) fn probe_object_info(address: &Url) -> ObjectInfo {
    ObjectInfo {
        address: address.clone(),
        kind: ObjectKind::File,
        etag: Some(ETAG.to_string()),
        etag_strength: EtagStrength::Strong,
        version: None,
        size: Some(CONTENT.len() as u64),
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
        versioned_address: None,
    }
}

pub(crate) fn read_request(url: &str) -> Request<ReadRequest> {
    Request::new(ReadRequest {
        address: Url::parse(url).unwrap(),
        options: ReadOptions::default(),
    })
}

/// The hub key a default-configured wrapper derives for [`ADDRESS`] at
/// [`ETAG`].
pub(crate) fn expected_key() -> String {
    let url = Url::parse(ADDRESS).unwrap();
    hub_key(KeyScheme::Ovstorage, "local", &url, ETAG, None)
        .expect("the etag keys")
        .key
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
        ReadResult::LocalDelegate(local) => tokio::fs::read(&local.path)
            .await
            .expect("the delegate path reads"),
        other => panic!("unexpected read result: {other:?}"),
    }
}

// --- A tiny metrics::Recorder for the metrics tests ---

type LabelSet = Vec<(String, String)>;

fn label_set(key: &metrics::Key) -> LabelSet {
    let mut labels: LabelSet = key
        .labels()
        .map(|label| (label.key().to_string(), label.value().to_string()))
        .collect();
    labels.sort();
    labels
}

/// A [`metrics::CounterFn`]/[`metrics::HistogramFn`] handle that bumps a
/// shared count for its `(name, labels)` key. A histogram's "count" is how
/// many times `record` was called, not the recorded values — the tests this
/// crate needs only care that a lookup was timed once per request.
struct Sink {
    name: String,
    labels: LabelSet,
    counts: Arc<Mutex<std::collections::HashMap<(String, LabelSet), u64>>>,
}

impl Sink {
    fn bump(&self, amount: u64) {
        *self
            .counts
            .lock()
            .unwrap()
            .entry((self.name.clone(), self.labels.clone()))
            .or_insert(0) += amount;
    }
}

impl metrics::CounterFn for Sink {
    fn increment(&self, value: u64) {
        self.bump(value);
    }

    fn absolute(&self, value: u64) {
        self.bump(value);
    }
}

impl metrics::HistogramFn for Sink {
    fn record(&self, _value: f64) {
        self.bump(1);
    }
}

/// A minimal [`metrics::Recorder`] for `with_local_recorder`: captures
/// `(name, labels) -> count` for every counter increment and histogram
/// record, and nothing else (no gauges, no descriptions).
#[derive(Default)]
pub(crate) struct TestRecorder {
    counts: Arc<Mutex<std::collections::HashMap<(String, LabelSet), u64>>>,
}

impl metrics::Recorder for TestRecorder {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }

    fn register_counter(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        metrics::Counter::from_arc(Arc::new(Sink {
            name: key.name().to_string(),
            labels: label_set(key),
            counts: self.counts.clone(),
        }))
    }

    fn register_gauge(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::from_arc(Arc::new(Sink {
            name: key.name().to_string(),
            labels: label_set(key),
            counts: self.counts.clone(),
        }))
    }
}

impl TestRecorder {
    /// The count recorded for `name` under exactly `labels` (order does not
    /// matter), or `0` if nothing was ever recorded there.
    pub(crate) fn count(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        let mut key: LabelSet = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        key.sort();
        self.counts
            .lock()
            .unwrap()
            .get(&(name.to_string(), key))
            .copied()
            .unwrap_or(0)
    }

    /// The count recorded for `name` summed across every label set, so a
    /// test can assert nothing at all was recorded for a metric without
    /// pinning down every possible label combination.
    pub(crate) fn total(&self, name: &str) -> u64 {
        self.counts
            .lock()
            .unwrap()
            .iter()
            .filter(|((metric, _), _)| metric == name)
            .map(|(_, count)| *count)
            .sum()
    }
}
