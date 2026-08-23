// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Metadata cache with TTL and notification-driven invalidation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use ovstorage_layer::{
    ListOptions, ListPage, ListVersionsOptions, ObjectInfo, Result, StatOptions, Url, node_address,
    node_spellings,
};

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MetadataCacheKey {
    pub kind: MetadataKind,
    /// Identifies the principal a cached result was authorized and computed
    /// for. Under authorization, **every** kind is principal-dependent: a
    /// stat can be denied (so even an object's existence and metadata are
    /// privileged), `effective_permissions` reflects *this* principal's
    /// rights, and list pages are access-filtered. Leaving this `None` shares
    /// one entry across principals and leaks data — the multi-principal broker
    /// must always set it. `None` is correct only when a single identity
    /// consumes the cache (direct-library use with no per-request
    /// authorization).
    pub principal_id: Option<String>,
    /// The address with userinfo removed, so the two spellings of one node
    /// share a row and an invalidation written without a credential reaches
    /// one written with it.
    ///
    /// The credential does not vanish with it — see [`Self::credential_scope`],
    /// which keeps it out of this field and still out of the shared row.
    pub address: String,
    /// A digest of any credential the address carried, and `None` when it
    /// carried none.
    ///
    /// **Userinfo is not part of node identity but it IS part of what a
    /// response means.** `plugin-http` hands the dispatch URL whole to
    /// `reqwest`, which turns `user:pass` in the authority into an
    /// `Authorization: Basic` header — so the origin answers one credential
    /// with `200` and another with `403`, and `principal_id` cannot tell them
    /// apart: it comes only from the request extension and is `None` for every
    /// direct-library caller. Folding the credential into [`Self::address`]
    /// would let one caller's `stat` — existence, size, etag, user metadata —
    /// and one caller's whole `list` page be served to another who was never
    /// authenticated for them.
    ///
    /// A digest rather than the credential itself: the key is cloned into
    /// eviction victim lists and appears in trace fields.
    pub credential_scope: Option<u64>,
    pub options_hash: u64,
}

/// The credential-scope component for `url`, or `None` when it carries none.
///
/// Callers building a [`MetadataCacheKey`] should use this rather than hashing
/// by hand, so every cache row agrees about what a credential is.
#[must_use]
pub fn credential_scope(url: &Url) -> Option<u64> {
    use std::hash::{Hash, Hasher};

    if url.username().is_empty() && url.password().is_none() {
        return None;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.username().hash(&mut hasher);
    url.password().hash(&mut hasher);
    Some(hasher.finish())
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
        let Some(entry) = state.entries.get_mut(key) else {
            record_miss(key);
            return None;
        };
        if entry.inserted_at.elapsed() >= entry.ttl {
            let size = entry.size;
            state.entries.remove(key);
            state.current_size = state.current_size.saturating_sub(size);
            record_miss(key);
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
            address = %redacted_key_address(&key.address),
            "metadata cache hit"
        );
        metrics::counter!(
            "ovstorage_metadata_cache_hits_total",
            "kind" => operation_label(key.kind)
        )
        .increment(1);
        Some(payload)
    }

    /// Returns whether the payload was RETAINED.
    ///
    /// Callers that register side state keyed on "this address is cached" need
    /// the answer: an oversized payload is dropped here after the prior value
    /// has already been removed, so a caller that assumes storage would be
    /// registering for an entry that does not exist.
    pub fn insert(&self, key: MetadataCacheKey, payload: MetadataCachePayload) -> bool {
        let now = Instant::now();
        let ttl = self.ttl;
        let size = object_info_count(&payload).max(1);
        let mut state = self.state.lock();
        // Drop any prior value for this key *before* the oversized-payload
        // check, so a refresh that does not fit the budget can't leave the
        // stale entry behind to be served as a hit until TTL.
        if let Some(existing) = state.entries.remove(&key) {
            state.current_size = state.current_size.saturating_sub(existing.size);
        }
        if size > self.max_entries {
            tracing::warn!(
                target: "ovstorage.metadata_cache",
                size,
                budget = self.max_entries,
                "metadata cache entry exceeds total budget; not caching"
            );
            return false;
        }
        // Evict LRU entries until the new one fits. Sort once O(N log N) then
        // drain from the front, avoiding the O(N²) repeated min-scan.
        if state.current_size + size > self.max_entries && !state.entries.is_empty() {
            let mut victims: Vec<_> = state
                .entries
                .iter()
                .map(|(k, e)| (e.last_accessed, k.clone()))
                .collect();
            victims.sort_unstable_by_key(|(t, _)| *t);
            for (_, victim) in victims {
                if state.current_size + size <= self.max_entries {
                    break;
                }
                if let Some(evicted) = state.entries.remove(&victim) {
                    state.current_size = state.current_size.saturating_sub(evicted.size);
                }
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
        true
    }

    /// Drop every row naming the node `address` names.
    ///
    /// `x` and `x/` are one node, so both rows go. A `stat` cached under the
    /// slashless spelling and a `list` cached under the slashed one describe
    /// the same directory; dropping only the spelling the writer used serves
    /// the other from cache after the object changed.
    pub fn invalidate_address(&self, address: &Url) {
        let (bare, slashed) = node_spellings(address);
        let mut state = self.state.lock();
        retain_with_size(&mut state, |k, _| k.address != bare && k.address != slashed);
    }

    /// Drop rows whose `address` is `prefix` itself or sits under it.
    pub fn invalidate_prefix(&self, prefix: &Url) {
        // `node_address`, matching what the rows are keyed on: userinfo is not
        // part of node identity, so a needle carrying a credential must still
        // reach a row stored without one.
        let needle = node_address(prefix);
        let needle = needle.as_str();
        let mut state = self.state.lock();
        retain_with_size(&mut state, |k, _| !is_under_prefix(&k.address, needle));
    }

    /// Drop List rows whose key address is `address` itself or a path-prefix
    /// of it (i.e. listings that would have contained `address`).
    pub fn invalidate_lists_containing(&self, address: &Url) {
        let target = node_address(address);
        let target = target.as_str();
        let mut state = self.state.lock();
        retain_with_size(&mut state, |k, _| {
            !(k.kind == MetadataKind::List && is_under_prefix(target, &k.address))
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
    ///
    /// The task holds only a [`std::sync::Weak`] reference, so it never keeps
    /// the cache alive: once the owning `Arc` is dropped the next event (or
    /// the `Drop`-driven `abort`) ends the task.
    pub fn spawn_invalidation_task(self: &Arc<Self>, mut events: mpsc::Receiver<Invalidation>) {
        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let Some(cache) = weak.upgrade() else { break };
                cache.apply_invalidation(event);
            }
        });
        self.invalidation_handles.lock().push(handle);
    }

    /// Apply one invalidation event. An object-level `Address` change drops
    /// both the exact address *and* the parent listings that contained it,
    /// mirroring the local mutation path (`invalidate_metadata_for_parent`);
    /// without the `invalidate_lists_containing` call a notification-driven
    /// create/delete would leave parent List pages stale until TTL.
    fn apply_invalidation(&self, event: Invalidation) {
        match event {
            Invalidation::Address(url) => {
                self.invalidate_address(&url);
                self.invalidate_lists_containing(&url);
            }
            Invalidation::Prefix(url) => self.invalidate_prefix(&url),
            Invalidation::All => self.invalidate_all(),
        }
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
        // `tokio::time::interval` panics on a zero period; clamp to 1ms.
        let interval = interval.max(Duration::from_millis(1));
        // Hold only a `Weak`: a strong clone here would keep the cache alive
        // for the process lifetime (the loop never returns on its own), making
        // `Drop`'s `abort` unreachable. Upgrading per tick lets the owning
        // `Arc` reach zero, at which point `Drop` aborts this task.
        let weak = Arc::downgrade(self);
        let join = handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let Some(cache) = weak.upgrade() else { break };
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
}

impl Default for MetadataCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: Some(DEFAULT_MAX_ENTRIES),
            ttl_seconds: Some(DEFAULT_TTL.as_secs()),
        }
    }
}

#[derive(Clone, Debug)]
pub enum Invalidation {
    Address(Url),
    Prefix(Url),
    All,
}

/// External event source that translates out-of-band change notifications
/// into cache invalidations. Hosts with a notification transport that does
/// not flow through a backend's `watch_directory` can implement this and
/// wire the receiver via [`MetadataCache::spawn_invalidation_task`].
#[async_trait::async_trait]
pub trait NotificationDispatcher: Send + Sync {
    async fn start(&self) -> Result<mpsc::Receiver<Invalidation>>;
}

/// No-op dispatcher; the receiver yields `None` immediately.
pub struct DisabledDispatcher;

#[async_trait::async_trait]
impl NotificationDispatcher for DisabledDispatcher {
    async fn start(&self) -> Result<mpsc::Receiver<Invalidation>> {
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        Ok(rx)
    }
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
    state.current_size = state.current_size.saturating_sub(freed);
}

/// True when `addr` names the node `prefix` names, or a descendant of it.
///
/// The same rule `address::is_ancestor_or_self` applies, on the serialized
/// forms these rows are keyed on. It is spelled out here rather than delegated
/// because invalidation scans every row on a mutation, and parsing each one
/// back into a `Url` would put a `Url::parse` per cached entry on the write
/// path.
///
/// **Both operands split at the query first.** Comparing the whole
/// serialization stops the boundary test at the `?`, which loses two cases in
/// opposite directions: a pinned row such as `s3://b/dir?versionId=1` survived
/// a `delete_directory` sweep of `s3://b/dir` — stale metadata for an object
/// that was just destroyed — and a prefix carrying its own query could not
/// strip its path's trailing slash at all, because the serialization does not
/// end in one.
///
/// Node-aware on the path: dropping one trailing `/` from the prefix makes the
/// remainder start with `/` for the slashed spelling of the node itself just as
/// it does for a child, so a prefix written either way covers both spellings.
/// A query on the prefix pins: it must equal the address's own.
fn is_under_prefix(addr: &str, prefix: &str) -> bool {
    let (addr_path, addr_query) = split_query(addr);
    let (prefix_path, prefix_query) = split_query(prefix);
    if prefix_query.is_some() && prefix_query != addr_query {
        return false;
    }
    let prefix_path = prefix_path.strip_suffix('/').unwrap_or(prefix_path);
    match addr_path.strip_prefix(prefix_path) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Split a serialized address at its query. There is no fragment to consider:
/// canonicalization strips it before an address reaches a cache key.
fn split_query(value: &str) -> (&str, Option<&str>) {
    match value.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (value, None),
    }
}

fn operation_label(kind: MetadataKind) -> &'static str {
    match kind {
        MetadataKind::Stat => "stat",
        MetadataKind::List => "list",
        MetadataKind::ListVersions => "list_versions",
    }
}

/// A cache key's address rendered for a trace field.
///
/// The key stores the address as [`node_address`] produced it, which strips
/// userinfo and **keeps the query** — deliberately, because a version pin
/// selects a different node and so belongs to cache identity. On a
/// query-pinned route the query is also the credential (a SAS `sig`, a signed
/// CDN token), so the trace field is where it has to go rather than the key.
/// `credential_scope` on the same struct is digested for this reason; this
/// closes the sibling field.
///
/// The whole query is dropped, not filtered. `redact::redact_url` scrubs only
/// the provider parameter names it knows, and a signed token can be spelled
/// anything — `hdnts`, `Key-Pair-Id`, `api_key` — so a filter here would close
/// the case that has a name and leave the one that does not. The scheme, host
/// and path identify the row; whether two rows differ by version pin is not
/// worth a credential.
fn redacted_key_address(address: &str) -> String {
    let Ok(mut url) = Url::parse(address) else {
        // No in-repo production caller reaches this: every one of them fills
        // the field from `node_address` or `node_spellings`, which return a
        // parsed `Url`'s serialization. The field is `pub` on a `pub` struct
        // re-exported from `ovstorage`, though, so the set is not closed —
        // hence a rendering rather than an `unreachable!`. It names nothing
        // rather than falling back to the raw string, which is the value this
        // function exists to avoid.
        return format!("<unparseable address, {} bytes>", address.len());
    };
    if url.cannot_be_a_base() {
        // Everything after the scheme is one opaque payload, userinfo
        // included, which no structural redactor can split.
        return format!("<opaque {} address, {} bytes>", url.scheme(), address.len());
    }
    let had_query = url.query().is_some();
    url.set_query(None);
    url.set_fragment(None);
    let _ = url.set_password(None);
    let _ = url.set_username("");
    if had_query {
        format!("{url}?<redacted>")
    } else {
        url.to_string()
    }
}

/// Emit the miss trace event + counter. Called for both a plain absence and a
/// TTL-expiry eviction so both hits and misses are counted and hit-rate
/// (`hits / (hits + misses)`) is computable.
fn record_miss(key: &MetadataCacheKey) {
    tracing::event!(
        target: "ovstorage.metadata_cache",
        tracing::Level::DEBUG,
        cache.hit = false,
        cache.kind = "metadata",
        cache.operation = operation_label(key.kind),
        address = %redacted_key_address(&key.address),
        "metadata cache miss"
    );
    metrics::counter!(
        "ovstorage_metadata_cache_misses_total",
        "kind" => operation_label(key.kind)
    )
    .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage_layer::{ChecksumSet, ObjectKind};

    fn cfg() -> MetadataCacheConfig {
        MetadataCacheConfig {
            max_entries: Some(8),
            ttl_seconds: Some(60),
        }
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
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

    /// The trace rendering of a cache key's address drops every credential it
    /// could carry, and stays useful for the rows that carry none.
    ///
    /// The key keeps the query on purpose — a version pin selects a different
    /// node — so this rendering is the only thing standing between a
    /// query-pinned route's signature and a DEBUG log written on every cache
    /// hit and every miss. Two of the rows use parameter names that are NOT in
    /// `REDACTED_QUERY_KEYS`, which is the case a filtering redactor gets
    /// wrong and a whole-query drop does not.
    ///
    /// Load-bearing line: the `url.set_query(None)`. Replacing this function's
    /// body with `address.to_string()` turns every secret row red, and
    /// replacing the drop with `redact::redact_url` turns the two unlisted
    /// rows red and leaves the `sig` row green.
    #[test]
    fn a_traced_cache_key_address_carries_no_credential() {
        for (address, secret) in [
            (
                "https://acct.blob.core.windows.net/c/o?sig=SECRET",
                "SECRET",
            ),
            ("https://cdn.example.invalid/a?hdnts=SECRET", "SECRET"),
            ("https://cdn.example.invalid/a?api_key=SECRET", "SECRET"),
            ("https://user:SECRET@origin.invalid/a", "SECRET"),
            ("s3:reader:SECRET@bucket/a", "SECRET"),
        ] {
            let rendered = redacted_key_address(address);
            assert!(
                !rendered.contains(secret),
                "{address} rendered as {rendered}, which carries its credential"
            );
        }
        // And the ordinary case is still legible, or the redaction would have
        // traded a leak for an unusable trace.
        assert_eq!(
            redacted_key_address("s3://bucket/team/report.usd"),
            "s3://bucket/team/report.usd"
        );
        assert_eq!(
            redacted_key_address("s3://bucket/team/report.usd?versionId=7"),
            "s3://bucket/team/report.usd?<redacted>"
        );
    }

    /// `insert` reports whether it RETAINED the payload.
    ///
    /// Callers register side state keyed on "this address is cached" — the
    /// metadata wrapper registers a scoped-watch candidate for a listing's
    /// prefix — and an oversized payload is dropped here after the prior value
    /// has already been removed. Without an answer, such a caller registers for
    /// an entry that does not exist.
    #[test]
    fn insert_reports_whether_it_retained_the_payload() {
        let cache = MetadataCache::new(&cfg());
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: "file:/tmp/x".into(),
            credential_scope: None,
            options_hash: 0,
        };
        assert!(
            cache.insert(key, MetadataCachePayload::Stat(stub_info())),
            "a payload that fits is retained and says so"
        );

        // A page larger than the whole budget (`max_entries` is 8) is dropped.
        let big = MetadataCacheKey {
            kind: MetadataKind::List,
            principal_id: None,
            address: "file:/tmp/dir/".into(),
            credential_scope: None,
            options_hash: 0,
        };
        let page = ListPage {
            items: (0..64).map(|_| stub_info()).collect(),
            next_page_token: None,
        };
        assert!(
            !cache.insert(big.clone(), MetadataCachePayload::List(page)),
            "a payload over the whole budget is dropped, and says so"
        );
        assert!(
            cache.get(&big).is_none(),
            "and really is absent, so a caller that registered on it would be \
             registering for nothing"
        );
    }

    #[test]
    fn cache_round_trips_stat_payload() {
        let cache = MetadataCache::new(&cfg());
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: "file:/tmp/x".into(),
            credential_scope: None,
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
            credential_scope: None,
            options_hash: 0,
        };
        cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.invalidate_address(&target);
        assert!(cache.get(&key).is_none());
    }

    /// Both spellings of one node are one node, so a write to either drops
    /// both rows.
    ///
    /// A `stat` cached under `file:///tmp/docs` and a `list` cached under
    /// `file:///tmp/docs/` describe the same directory. Invalidating on the
    /// serialized string drops whichever spelling the writer happened to use
    /// and serves the other from cache afterwards — stale metadata for an
    /// object that was just changed.
    #[test]
    fn invalidate_address_removes_both_spellings_of_one_node() {
        for written in ["file:///tmp/docs", "file:///tmp/docs/"] {
            let cache = MetadataCache::new(&cfg());
            let bare = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: url("file:///tmp/docs").as_str().into(),
                credential_scope: None,
                options_hash: 0,
            };
            let slashed = MetadataCacheKey {
                kind: MetadataKind::List,
                principal_id: None,
                address: url("file:///tmp/docs/").as_str().into(),
                credential_scope: None,
                options_hash: 0,
            };
            // A sibling whose name merely starts with the node's: the two
            // spellings must not become a substring match.
            let sibling = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: url("file:///tmp/docsx").as_str().into(),
                credential_scope: None,
                options_hash: 0,
            };
            cache.insert(bare.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.insert(
                slashed.clone(),
                MetadataCachePayload::List(ListPage {
                    items: vec![stub_info()],
                    next_page_token: None,
                }),
            );
            cache.insert(sibling.clone(), MetadataCachePayload::Stat(stub_info()));

            cache.invalidate_address(&url(written));

            assert!(
                cache.get(&bare).is_none(),
                "a write spelled {written} must drop the slashless row"
            );
            assert!(
                cache.get(&slashed).is_none(),
                "a write spelled {written} must drop the slashed row"
            );
            assert!(
                cache.get(&sibling).is_some(),
                "a write spelled {written} must not reach a sibling node"
            );
        }
    }

    /// A pinned row is inside the directory it pins, so a sweep reaches it.
    ///
    /// Comparing whole serializations stopped the boundary test at the `?`, so
    /// `s3://b/dir?versionId=1` survived a `delete_directory` of `s3://b/dir`
    /// and served metadata for an object that had just been destroyed. It is
    /// cacheable: a slashless path is not a directory form, so `stat` caches
    /// it.
    #[test]
    fn a_prefix_sweep_reaches_a_pinned_row_under_it() {
        for prefix in ["s3://b/dir", "s3://b/dir/"] {
            let cache = MetadataCache::new(&cfg());
            let pinned = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: ovstorage_layer::node_address(&url("s3://b/dir?versionId=1")),
                credential_scope: None,
                options_hash: 0,
            };
            let sibling = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: ovstorage_layer::node_address(&url("s3://b/dirx?versionId=1")),
                credential_scope: None,
                options_hash: 0,
            };
            cache.insert(pinned.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.insert(sibling.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.invalidate_prefix(&url(prefix));
            assert!(
                cache.get(&pinned).is_none(),
                "a sweep of {prefix} must reach the pinned row under it"
            );
            assert!(
                cache.get(&sibling).is_some(),
                "a sweep of {prefix} must not reach a textual sibling"
            );
        }
    }

    /// A qualified listing is swept only by a change in the same
    /// qualification.
    ///
    /// A prefix carrying its own query could not strip its path's trailing
    /// slash at all — the serialization ends in the query, not in the slash —
    /// so it matched nothing whatsoever. It now matches, and the pin then
    /// decides: a change to the live object does not disturb a listing of a
    /// snapshot, because it did not change what that snapshot contains.
    #[test]
    fn a_qualified_listing_is_swept_by_a_change_in_the_same_qualification() {
        for (changed, swept) in [
            ("s3://b/d/child?snapshot=7", true),
            ("s3://b/d/child", false),
            ("s3://b/other/child?snapshot=7", false),
        ] {
            let cache = MetadataCache::new(&cfg());
            let list_key = MetadataCacheKey {
                kind: MetadataKind::List,
                principal_id: None,
                address: ovstorage_layer::node_address(&url("s3://b/d/?snapshot=7")),
                credential_scope: None,
                options_hash: 0,
            };
            cache.insert(
                list_key.clone(),
                MetadataCachePayload::List(ListPage {
                    items: vec![stub_info()],
                    next_page_token: None,
                }),
            );
            cache.invalidate_lists_containing(&url(changed));
            assert_eq!(
                cache.get(&list_key).is_none(),
                swept,
                "a change at {changed} against a listing of s3://b/d/?snapshot=7"
            );
        }
    }

    /// A pin narrows: a differently-pinned prefix is a different scope.
    #[test]
    fn a_prefix_pinned_to_one_version_does_not_sweep_another() {
        let cache = MetadataCache::new(&cfg());
        let other = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: ovstorage_layer::node_address(&url("s3://b/dir/x?versionId=2")),
            credential_scope: None,
            options_hash: 0,
        };
        cache.insert(other.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.invalidate_prefix(&url("s3://b/dir/?versionId=1"));
        assert!(cache.get(&other).is_some());
    }

    /// A credential IS part of what a response means, even though it is not
    /// part of what an address names.
    ///
    /// `plugin-http` hands the dispatch URL whole to `reqwest`, which turns
    /// `user:pass` in the authority into an `Authorization: Basic` header — so
    /// the origin answers one credential with `200` and another with `403`.
    /// `principal_id` cannot tell them apart: it comes only from the request
    /// extension and is `None` for every direct-library caller. Folding the
    /// credential into the address field would let one caller's `stat` — and
    /// one caller's whole `list` page — be served to another who was never
    /// authenticated for it.
    #[test]
    fn two_credentials_do_not_share_one_row() {
        let cache = MetadataCache::new(&cfg());
        let alice = url("https://alice:pw@origin/private/x");
        let mallory = url("https://mallory:wrong@origin/private/x");
        let anonymous = url("https://origin/private/x");

        let key_for = |address: &Url| MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            credential_scope: credential_scope(address),
            address: ovstorage_layer::node_address(address),
            options_hash: 0,
        };

        cache.insert(key_for(&alice), MetadataCachePayload::Stat(stub_info()));
        assert!(
            cache.get(&key_for(&alice)).is_some(),
            "control: the caller who filled the row reads it back"
        );
        assert!(
            cache.get(&key_for(&mallory)).is_none(),
            "a different credential must not read another's cached metadata"
        );
        assert!(
            cache.get(&key_for(&anonymous)).is_none(),
            "an unauthenticated caller must not read a credentialed row"
        );

        // Invalidation still reaches it: the address field carries no
        // credential, so a needle written without one matches.
        cache.invalidate_address(&anonymous);
        assert!(cache.get(&key_for(&alice)).is_none());
    }

    /// A credential in an address is not part of what it names.
    ///
    /// Userinfo is carried through and never consulted for identity, so two
    /// addresses differing only in it are one node. Keying rows on the raw
    /// serialization split that node into one row per credential and left an
    /// invalidation written without one reaching none of them — stale metadata
    /// served for an object that had just been deleted.
    #[test]
    fn invalidation_reaches_a_row_regardless_of_the_credential_in_the_address() {
        for (stored, invalidated) in [
            ("gs://alice@bucket/dir/x", "gs://bucket/dir/x"),
            ("gs://bucket/dir/x", "gs://alice@bucket/dir/x"),
            ("gs://alice@bucket/dir/x", "gs://bob@bucket/dir/x"),
        ] {
            let cache = MetadataCache::new(&cfg());
            let key = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: ovstorage_layer::node_address(&url(stored)),
                credential_scope: None,
                options_hash: 0,
            };
            cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.invalidate_address(&url(invalidated));
            assert!(
                cache.get(&key).is_none(),
                "a row stored for {stored} must be dropped by an invalidation of {invalidated}"
            );

            let cache = MetadataCache::new(&cfg());
            cache.insert(key.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.invalidate_prefix(&url(invalidated));
            assert!(
                cache.get(&key).is_none(),
                "a row stored for {stored} must be swept by a prefix of {invalidated}"
            );
        }
    }

    /// A prefix covers the node it names under either spelling.
    ///
    /// `invalidate_prefix(file:///tmp/docs/)` is how a `delete_directory`
    /// clears its subtree. Rows cached under the slashless spelling of the
    /// directory itself are inside that subtree and must go with it.
    #[test]
    fn invalidate_prefix_covers_the_node_it_names_under_either_spelling() {
        for written in ["file:///tmp/docs", "file:///tmp/docs/"] {
            let cache = MetadataCache::new(&cfg());
            let bare = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: url("file:///tmp/docs").as_str().into(),
                credential_scope: None,
                options_hash: 0,
            };
            let child = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: url("file:///tmp/docs/a").as_str().into(),
                credential_scope: None,
                options_hash: 0,
            };
            let sibling = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: url("file:///tmp/docsx").as_str().into(),
                credential_scope: None,
                options_hash: 0,
            };
            cache.insert(bare.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.insert(child.clone(), MetadataCachePayload::Stat(stub_info()));
            cache.insert(sibling.clone(), MetadataCachePayload::Stat(stub_info()));

            cache.invalidate_prefix(&url(written));

            assert!(
                cache.get(&bare).is_none(),
                "prefix spelled {written} must cover the node itself"
            );
            assert!(
                cache.get(&child).is_none(),
                "prefix spelled {written} must cover a child"
            );
            assert!(
                cache.get(&sibling).is_some(),
                "prefix spelled {written} must not cover a textual sibling"
            );
        }
    }

    #[test]
    fn invalidate_prefix_removes_subtree() {
        let cache = MetadataCache::new(&cfg());
        let prefix = url("file:///tmp/");
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: prefix.join("x").unwrap().as_str().into(),
            credential_scope: None,
            options_hash: 0,
        };
        let other = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: url("file:///other/y").as_str().into(),
            credential_scope: None,
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
        });
        let key = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: "file:/tmp/x".into(),
            credential_scope: None,
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
            credential_scope: None,
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

    #[test]
    fn oversized_reinsert_drops_stale_entry() {
        let cache = MetadataCache::new(&MetadataCacheConfig {
            max_entries: Some(2),
            ttl_seconds: Some(60),
        });
        let key = MetadataCacheKey {
            kind: MetadataKind::ListVersions,
            principal_id: None,
            address: "file:///d".into(),
            credential_scope: None,
            options_hash: 0,
        };
        // A small value that fits the budget.
        cache.insert(
            key.clone(),
            MetadataCachePayload::ListVersions(vec![stub_info()]),
        );
        assert!(cache.get(&key).is_some());
        // Refresh with a payload larger than the entire budget: it must not be
        // cached, and must not leave the old value behind to be served stale.
        cache.insert(
            key.clone(),
            MetadataCachePayload::ListVersions(vec![stub_info(), stub_info(), stub_info()]),
        );
        assert!(
            cache.get(&key).is_none(),
            "stale entry served after oversized refresh"
        );
        assert_eq!(cache.current_size(), 0);
    }

    #[test]
    fn invalidate_prefix_respects_path_boundary() {
        let cache = MetadataCache::new(&cfg());
        let descendant = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: url("file:///foo/x").as_str().into(),
            credential_scope: None,
            options_hash: 0,
        };
        let sibling = MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: None,
            address: url("file:///foobar").as_str().into(),
            credential_scope: None,
            options_hash: 0,
        };
        cache.insert(descendant.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.insert(sibling.clone(), MetadataCachePayload::Stat(stub_info()));
        cache.invalidate_prefix(&url("file:///foo"));
        assert!(
            cache.get(&descendant).is_none(),
            "descendant of the prefix should be invalidated"
        );
        assert!(
            cache.get(&sibling).is_some(),
            "textual-prefix sibling (file:///foobar) must survive"
        );
    }

    #[tokio::test]
    async fn notification_address_invalidates_parent_list() {
        let cache = Arc::new(MetadataCache::new(&cfg()));
        let (tx, rx) = mpsc::channel(4);
        cache.spawn_invalidation_task(rx);

        let list_key = MetadataCacheKey {
            kind: MetadataKind::List,
            principal_id: None,
            address: url("file:///d/").as_str().into(),
            credential_scope: None,
            options_hash: 0,
        };
        cache.insert(
            list_key.clone(),
            MetadataCachePayload::List(ListPage {
                items: vec![stub_info()],
                next_page_token: None,
            }),
        );

        // A single-object change under the directory must invalidate the
        // cached listing, not merely an exact-address stat row.
        tx.send(Invalidation::Address(url("file:///d/child")))
            .await
            .unwrap();
        for _ in 0..50 {
            if cache.get(&list_key).is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("parent list not invalidated by notification within 500ms");
    }

    #[tokio::test]
    async fn ttl_sweeper_does_not_pin_cache_alive() {
        let cache = Arc::new(MetadataCache::new(&cfg()));
        cache.spawn_ttl_sweeper(Duration::from_secs(3600));
        let weak = Arc::downgrade(&cache);
        // Let the immediate first tick run; the task then parks on the long
        // interval holding only a Weak.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(cache);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            weak.upgrade().is_none(),
            "ttl sweeper task kept the cache alive (Arc cycle)"
        );
    }
}
