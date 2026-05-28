// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metadata cache with TTL and notification-driven invalidation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::{ListOptions, ListPage, ListVersionsOptions, ObjectInfo, StatOptions, Url};

pub const DEFAULT_TTL: Duration = Duration::from_secs(30);
/// Budget is counted in **ObjectInfos**: a Stat entry charges 1, a
/// List/ListVersions entry charges one per item it carries. 65536 is
/// roughly 32–64 MB at typical ObjectInfo sizes.
pub const DEFAULT_MAX_ENTRIES: usize = 65536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetadataKind {
    Stat,
    List,
    ListVersions,
}

/// `principal_id` is `None` for stat/list_versions and `Some(...)`
/// for list pages stored after caller-specific filtering.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MetadataCacheKey {
    pub kind: MetadataKind,
    pub principal_id: Option<String>,
    pub address: String,
    pub options_hash: u64,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum MetadataCachePayload {
    Stat(ObjectInfo),
    List(ListPage),
    ListVersions(Vec<ObjectInfo>),
}

#[derive(Clone, Debug)]
struct Entry {
    payload: MetadataCachePayload,
    inserted_at: Instant,
    last_accessed: Instant,
    ttl: Duration,
    /// ObjectInfos this entry charges to the cache budget.
    /// Stat=1, List/ListVersions=one per item.
    size: usize,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<MetadataCacheKey, Entry>,
    /// Sum of `Entry::size` across all entries. Maintained inline so
    /// inserts/evictions don't have to re-scan.
    current_size: usize,
}

pub struct MetadataCache {
    /// `Mutex` rather than `RwLock` because every `get` updates
    /// `last_accessed` to drive LRU eviction — there are no read-only paths.
    state: Mutex<CacheState>,
    max_entries: usize,
    ttl: Duration,
    invalidation_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl MetadataCache {
    pub fn new(config: &MetadataCacheConfig) -> Self {
        let max_entries = config.max_entries.unwrap_or(DEFAULT_MAX_ENTRIES).max(1);
        let ttl = config
            .ttl_seconds
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TTL);
        tracing::info!(
            target: "ovstorage.metadata_cache",
            max_entries,
            ttl_secs = ttl.as_secs(),
            "metadata cache initialized"
        );
        Self {
            state: Mutex::new(CacheState::default()),
            max_entries,
            ttl,
            invalidation_handles: Mutex::new(Vec::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// `None` on miss or TTL expiry. On hit, bumps `last_accessed`; on
    /// expiry, evicts the stale entry.
    pub fn get(&self, key: &MetadataCacheKey) -> Option<MetadataCachePayload> {
        let mut state = self.state.lock();
        let entry = state.entries.get_mut(key)?;
        if entry.inserted_at.elapsed() >= entry.ttl {
            let size = entry.size;
            state.entries.remove(key);
            state.current_size -= size;
            tracing::event!(
                target: "ovstorage.metadata_cache",
                tracing::Level::DEBUG,
                cache.hit = false,
                cache.kind = "metadata",
                cache.operation = operation_label(key.kind),
                address = %key.address,
                "metadata cache miss"
            );
            return None;
        }
        entry.last_accessed = Instant::now();
        let payload = entry.payload.clone();
        tracing::event!(
            target: "ovstorage.metadata_cache",
            tracing::Level::DEBUG,
            cache.hit = true,
            cache.kind = "metadata",
            cache.operation = operation_label(key.kind),
            address = %key.address,
            "metadata cache hit"
        );
        metrics::counter!(
            "ovstorage_metadata_cache_hits_total",
            "kind" => operation_label(key.kind)
        )
        .increment(1);
        Some(payload)
    }

    pub fn insert(&self, key: MetadataCacheKey, payload: MetadataCachePayload) {
        let now = Instant::now();
        let ttl = self.ttl;
        let size = object_info_count(&payload).max(1);
        if size > self.max_entries {
            tracing::warn!(
                target: "ovstorage.metadata_cache",
                size,
                budget = self.max_entries,
                "metadata cache entry exceeds total budget; not caching"
            );
            return;
        }
        let mut state = self.state.lock();
        if let Some(existing) = state.entries.remove(&key) {
            state.current_size -= existing.size;
        }
        // Evict LRU entries until the new one fits. The min-scan is
        // O(N) and the loop is O(N²) in the worst case (single big
        // insert clearing the whole cache), but eviction only runs
        // when the budget is tight.
        while state.current_size + size > self.max_entries && !state.entries.is_empty() {
            let Some(victim) = state
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_accessed)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(evicted) = state.entries.remove(&victim) {
                state.current_size -= evicted.size;
            }
        }
        state.entries.insert(
            key,
            Entry {
                payload,
                inserted_at: now,
                last_accessed: now,
                ttl,
                size,
            },
        );
        state.current_size += size;
    }

    /// Drop rows with an exact `address` match.
    pub fn invalidate_address(&self, address: &Url) {
        let needle = address.as_str();
        let mut state = self.state.lock();
        retain_with_size(&mut state, |k, _| k.address != needle);
    }

    /// Drop rows whose `address` starts with `prefix`.
    pub fn invalidate_prefix(&self, prefix: &Url) {
        let needle = prefix.as_str();
        let mut state = self.state.lock();
        retain_with_size(&mut state, |k, _| !k.address.starts_with(needle));
    }

    /// Drop List rows whose key address is a prefix of `address`.
    pub fn invalidate_lists_containing(&self, address: &Url) {
        let target = address.as_str();
        let mut state = self.state.lock();
        retain_with_size(&mut state, |k, _| {
            !(k.kind == MetadataKind::List && target.starts_with(&k.address))
        });
    }

    pub fn invalidate_all(&self) {
        let mut state = self.state.lock();
        state.entries.clear();
        state.current_size = 0;
    }

    pub fn purge_expired(&self) {
        let mut state = self.state.lock();
        retain_with_size(&mut state, |_, e| e.inserted_at.elapsed() < e.ttl);
    }

    pub fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.lock().entries.is_empty()
    }

    /// Total ObjectInfo budget currently consumed.
    pub fn current_size(&self) -> usize {
        self.state.lock().current_size
    }

    /// Spawn a drain task that applies `events` as invalidations.
    pub fn spawn_invalidation_task(self: &Arc<Self>, mut events: mpsc::Receiver<Invalidation>) {
        let cache = Arc::clone(self);
        let handle = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                match event {
                    Invalidation::Address(url) => cache.invalidate_address(&url),
                    Invalidation::Prefix(url) => cache.invalidate_prefix(&url),
                    Invalidation::All => cache.invalidate_all(),
                }
            }
        });
        self.invalidation_handles.lock().push(handle);
    }

    /// Periodic sweeper so routes without a notification source don't
    /// grow unbounded between `get` calls.
    pub fn spawn_ttl_sweeper(self: &Arc<Self>, interval: Duration) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::debug!(
                target: "ovstorage.metadata_cache",
                "metadata cache TTL sweeper not spawned because no tokio runtime is active"
            );
            return;
        };
        let cache = Arc::clone(self);
        let join = handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                cache.purge_expired();
            }
        });
        self.invalidation_handles.lock().push(join);
    }
}

impl Drop for MetadataCache {
    fn drop(&mut self) {
        for handle in self.invalidation_handles.lock().iter() {
            handle.abort();
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MetadataCacheConfig {
    /// Budget is counted in **ObjectInfos**: a Stat entry charges 1, a
    /// List/ListVersions entry charges one per item. At typical sizes,
    /// 65536 ≈ 32–64 MB of resident memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notification_sources: Vec<NotificationSourceConfig>,
}

impl Default for MetadataCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: Some(DEFAULT_MAX_ENTRIES),
            ttl_seconds: Some(DEFAULT_TTL.as_secs()),
            notification_sources: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationSourceConfig {
    pub prefix: String,
    #[serde(flatten)]
    pub source: NotificationSourceKind,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotificationSourceKind {
    S3Sqs {
        queue_url: String,
        region: String,
    },
    GcpPubsub {
        subscription: String,
        project: String,
    },
    AzureEventGrid {
        endpoint: String,
        subscription_id: String,
    },
}

#[derive(Clone, Debug)]
pub enum Invalidation {
    Address(Url),
    Prefix(Url),
    All,
}

/// External event source that translates cloud notifications into
/// cache invalidations. Concrete impls today are stubs returning
/// `Unsupported`; real SDK wiring will land in the per-backend plugin.
#[async_trait::async_trait]
pub trait NotificationDispatcher: Send + Sync {
    async fn start(&self) -> crate::Result<mpsc::Receiver<Invalidation>>;
}

/// No-op dispatcher; the receiver yields `None` immediately.
pub struct DisabledDispatcher;

#[async_trait::async_trait]
impl NotificationDispatcher for DisabledDispatcher {
    async fn start(&self) -> crate::Result<mpsc::Receiver<Invalidation>> {
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        Ok(rx)
    }
}

pub struct S3SqsDispatcher {
    pub queue_url: String,
    pub region: String,
}

#[async_trait::async_trait]
impl NotificationDispatcher for S3SqsDispatcher {
    async fn start(&self) -> crate::Result<mpsc::Receiver<Invalidation>> {
        Err(crate::Error::new(
            crate::ErrorCode::Unsupported,
            format!(
                "S3 SQS notification dispatcher is not yet wired (queue={}, region={}); \
                 falling back to TTL-only invalidation",
                self.queue_url, self.region
            ),
        ))
    }
}

pub struct GcpPubsubDispatcher {
    pub subscription: String,
    pub project: String,
}

#[async_trait::async_trait]
impl NotificationDispatcher for GcpPubsubDispatcher {
    async fn start(&self) -> crate::Result<mpsc::Receiver<Invalidation>> {
        Err(crate::Error::new(
            crate::ErrorCode::Unsupported,
            format!(
                "GCP Pub/Sub notification dispatcher is not yet wired (sub={}, project={}); \
                 falling back to TTL-only invalidation",
                self.subscription, self.project
            ),
        ))
    }
}

pub struct AzureEventGridDispatcher {
    pub endpoint: String,
    pub subscription_id: String,
}

#[async_trait::async_trait]
impl NotificationDispatcher for AzureEventGridDispatcher {
    async fn start(&self) -> crate::Result<mpsc::Receiver<Invalidation>> {
        Err(crate::Error::new(
            crate::ErrorCode::Unsupported,
            format!(
                "Azure Event Grid notification dispatcher is not yet wired \
                 (endpoint={}, subscription_id={}); falling back to TTL-only invalidation",
                self.endpoint, self.subscription_id
            ),
        ))
    }
}

/// Build a dispatcher from config and spawn the drain task that pumps
/// invalidations into `cache`. No-op when no tokio runtime is current.
pub fn spawn_notification_source(cache: &Arc<MetadataCache>, source: &NotificationSourceConfig) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::debug!(
            target: "ovstorage.metadata_cache",
            "notification dispatcher not spawned because no tokio runtime is active"
        );
        return;
    };
    let dispatcher: Box<dyn NotificationDispatcher> = match &source.source {
        NotificationSourceKind::S3Sqs { queue_url, region } => Box::new(S3SqsDispatcher {
            queue_url: queue_url.clone(),
            region: region.clone(),
        }),
        NotificationSourceKind::GcpPubsub {
            subscription,
            project,
        } => Box::new(GcpPubsubDispatcher {
            subscription: subscription.clone(),
            project: project.clone(),
        }),
        NotificationSourceKind::AzureEventGrid {
            endpoint,
            subscription_id,
        } => Box::new(AzureEventGridDispatcher {
            endpoint: endpoint.clone(),
            subscription_id: subscription_id.clone(),
        }),
    };
    let prefix = source.prefix.clone();
    let cache = Arc::clone(cache);
    handle.spawn(async move {
        match dispatcher.start().await {
            Ok(rx) => cache.spawn_invalidation_task(rx),
            Err(error) => tracing::warn!(
                target: "ovstorage.metadata_cache",
                prefix = %prefix,
                error = %error,
                "notification dispatcher failed to start; cache remains TTL-only"
            ),
        }
    });
}

/// Hash for cache keys; stable within a process.
pub fn hash_stat_options(options: &StatOptions) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    options.full_metadata.hash(&mut hasher);
    hasher.finish()
}

pub fn hash_list_options(options: &ListOptions) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    options.recursive.hash(&mut hasher);
    options.max_results.hash(&mut hasher);
    options.page_token.hash(&mut hasher);
    options.full_metadata.hash(&mut hasher);
    hasher.finish()
}

pub fn hash_list_versions_options(options: &ListVersionsOptions) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    options.max_results.hash(&mut hasher);
    options.page_token.hash(&mut hasher);
    hasher.finish()
}

/// ObjectInfos chargeable to the cache budget for `payload`. Stat = 1,
/// List = number of items in the page, ListVersions = number of versions.
fn object_info_count(payload: &MetadataCachePayload) -> usize {
    match payload {
        MetadataCachePayload::Stat(_) => 1,
        MetadataCachePayload::List(page) => page.items.len(),
        MetadataCachePayload::ListVersions(versions) => versions.len(),
    }
}

/// `HashMap::retain` that also keeps `CacheState::current_size` in sync.
fn retain_with_size<F>(state: &mut CacheState, mut keep: F)
where
    F: FnMut(&MetadataCacheKey, &Entry) -> bool,
{
    let mut freed = 0;
    state.entries.retain(|k, e| {
        if keep(k, e) {
            true
        } else {
            freed += e.size;
            false
        }
    });
    state.current_size -= freed;
}

fn operation_label(kind: MetadataKind) -> &'static str {
    match kind {
        MetadataKind::Stat => "stat",
        MetadataKind::List => "list",
        MetadataKind::ListVersions => "list_versions",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChecksumSet, ObjectKind};

    fn cfg() -> MetadataCacheConfig {
        MetadataCacheConfig {
            max_entries: Some(8),
            ttl_seconds: Some(60),
            notification_sources: Vec::new(),
        }
    }

    fn url(s: &str) -> Url {
        crate::address::parse(s).unwrap()
    }

    fn stub_info() -> ObjectInfo {
        ObjectInfo {
            address: url("file:///tmp/x"),
            kind: ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        }
    }

    #[test]
    fn cache_round_trips_stat_payload() {
        let cache = MetadataCache::new(&cfg());
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: "file:/tmp/x".into(),
            options_hash: 0,
        };
        assert!(cache.get(&key).is_none());
        cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
        assert!(matches!(
            cache.get(&key),
            Some(MetadataCachePayload::Stat(_))
        ));
    }

    #[test]
    fn invalidate_address_removes_matching_keys() {
        let cache = MetadataCache::new(&cfg());
        let target = url("file:///tmp/x");
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: target.as_str().into(),
            options_hash: 0,
        };
        cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.invalidate_address(&target);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn invalidate_prefix_removes_subtree() {
        let cache = MetadataCache::new(&cfg());
        let prefix = url("file:///tmp/");
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: prefix.join("x").unwrap().as_str().into(),
            options_hash: 0,
        };
        let other = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: url("file:///other/y").as_str().into(),
            options_hash: 0,
        };
        cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.insert(other.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.invalidate_prefix(&prefix);
        assert!(cache.get(&key).is_none());
        assert!(cache.get(&other).is_some());
    }

    #[test]
    fn ttl_expiry_returns_none() {
        let cache = MetadataCache::new(&MetadataCacheConfig {
            max_entries: Some(8),
            ttl_seconds: Some(0),
            notification_sources: Vec::new(),
        });
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: "file:/tmp/x".into(),
            options_hash: 0,
        };
        cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
        assert!(cache.get(&key).is_none());
    }

    #[tokio::test]
    async fn invalidation_channel_drives_address_invalidate() {
        let cache = Arc::new(MetadataCache::new(&cfg()));
        let (tx, rx) = mpsc::channel(4);
        cache.spawn_invalidation_task(rx);
        let target = url("file:///tmp/x");
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: target.as_str().into(),
            options_hash: 0,
        };
        cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
        tx.send(Invalidation::Address(target.clone()))
            .await
            .unwrap();
        for _ in 0..50 {
            if cache.get(&key).is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("invalidation task did not invalidate the entry within 500ms");
    }

    #[test]
    fn options_hash_is_stable_within_process() {
        let a = StatOptions {
            full_metadata: true,
        };
        let b = StatOptions {
            full_metadata: true,
        };
        assert_eq!(hash_stat_options(&a), hash_stat_options(&b));
        let c = StatOptions {
            full_metadata: false,
        };
        assert_ne!(hash_stat_options(&a), hash_stat_options(&c));
    }
}
