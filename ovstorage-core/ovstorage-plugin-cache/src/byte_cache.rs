// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ByteCacheWrapper` caches object bytes over [`ovstorage_cache::Cache`], composed
//! **above** `RedirectFollowerWrapper` to cache post-redirect bytes. Caches
//! `ReadResult::Bytes` reads + `materialize` (with a lease), write-through for
//! buffered writes, and invalidates on mutating ops. See the
//! [module docs](super) for the cache-scope deferrals (key identity, redirected
//! reads, multi-principal composition).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ovstorage_cache::{Cache, CacheConfig, CacheOptions};

use crate::layers::{BYTE_CACHE_KIND, descriptor};
use crate::notification_drain::{
    CacheWatchState, CommitRegistrar, GapSweepStream, MANAGED_NOTIFICATION_DRAIN_EXTENSION,
    parse_watch_invalidation,
};
use crate::*;

use super::{READ_TO_BYTES_EXTENSION, buffer_read_stream, cache_config_field, config_u64, ext};

/// Build a cached [`ObjectInfo`] for a cache hit — `address` + `size` come
/// from the byte cache, and `etag` is the validator the hit was proven fresh
/// against.
fn cached_object_info(address: Url, size: u64, etag: Option<String>) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag,
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

fn require_path(config: &LayerConfig, key: &str) -> Result<PathBuf> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => Ok(PathBuf::from(value)),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("byte cache config `{key}` must be a string path"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("byte cache config requires `{key}`"),
        )),
    }
}

fn config_string<'a>(config: &'a LayerConfig, key: &str) -> Option<&'a str> {
    match config.get(key) {
        Some(ConfigValue::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// A shared byte-cache stream-tee generations registry (the resurrection
/// guard map). A host that reuses one [`Cache`] across a rebuild — the broker's
/// SIGHUP `reload`, which process-caches the `Arc<Cache>` by `cache_root`
/// — threads the SAME registry into every
/// `ByteCacheWrapper` built over that cache, so an in-flight tee registered by a
/// pre-reload wrapper still observes a post-reload mutation's generation bump
/// and refuses to resurrect a stale row. Without a shared registry each wrapper
/// mints its own map, and an old-Stack tee could commit stale bytes a
/// new-Stack mutation had cleared. Cheap to clone (an `Arc`).
#[derive(Clone, Default)]
pub struct ByteCacheGenerations(Arc<Mutex<GenerationMap>>);

impl ByteCacheGenerations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether two handles share the same underlying registry (`Arc::ptr_eq`) —
    /// the invariant the process-cache-by-`cache_root` reuse must preserve.
    pub fn shares_registry_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// [`WrapperFactory`] for the `byte_cache` wrapper kind ([`BYTE_CACHE_KIND`]).
#[derive(Default)]
pub struct ByteCacheWrapperFactory {
    /// When set, created wrappers reuse this cache instance so a rebuilt Stack
    /// can share the host's byte cache rather than opening a fresh one from
    /// `cache_root`/`state_root`.
    cache: Option<Arc<Cache>>,
    /// When set, created wrappers share this tee-generations registry instead of
    /// minting a fresh one, so wrappers rebuilt over one process-cached `Cache`
    /// share the resurrection guard across a SIGHUP reload.
    generations: Option<ByteCacheGenerations>,
}

impl ByteCacheWrapperFactory {
    /// Build a factory whose wrappers reuse `cache`,
    /// ignoring the `cache_root`/`state_root`/`max_bytes` config keys. Each
    /// wrapper mints a fresh tee-generations registry (one wrapper owns the
    /// registry, so the guard holds).
    pub fn with_cache(cache: Arc<Cache>) -> Self {
        Self {
            cache: Some(cache),
            generations: None,
        }
    }

    /// Build a factory whose wrappers reuse `cache` AND share `generations`. A
    /// host reusing one `Cache` across a rebuild (the broker's SIGHUP reload)
    /// threads the SAME registry keyed by the same `cache_root`, so an in-flight
    /// tee from a pre-reload wrapper still sees a post-reload mutation's bump.
    pub fn with_cache_and_generations(
        cache: Arc<Cache>,
        generations: ByteCacheGenerations,
    ) -> Self {
        Self {
            cache: Some(cache),
            generations: Some(generations),
        }
    }
}

#[async_trait]
impl WrapperFactory for ByteCacheWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        let mut descriptor = descriptor(BYTE_CACHE_KIND, LayerType::Wrapper, false);
        descriptor.config_schema = vec![
            cache_config_field(
                "cache_root",
                "Cache root",
                ConfigFieldKind::Path,
                true,
                "Directory holding the content-addressed cache blobs",
            ),
            cache_config_field(
                "state_root",
                "State root",
                ConfigFieldKind::Path,
                true,
                "Directory holding the cache index/state database",
            ),
            cache_config_field(
                "max_bytes",
                "Max bytes",
                ConfigFieldKind::Integer,
                false,
                "Optional cache size budget in bytes (evicts least-recently-used beyond it)",
            ),
            cache_config_field(
                "max_streaming_fills",
                "Max concurrent streaming fills",
                ConfigFieldKind::Integer,
                false,
                "Optional cap on concurrent streaming (tee) cache fills; at the limit a \
                 streaming read serves uncached (default 64). `0` disables streaming fills",
            ),
            cache_config_field(
                "partition",
                "Policy partition",
                ConfigFieldKind::Text,
                false,
                "Cache-key partition prefix isolating tenants/policies (default `local`)",
            ),
            cache_config_field(
                "lost_backing_fallback",
                "Serve on lost backing store",
                ConfigFieldKind::Bool,
                false,
                "Treat a NotFound validator stat as unavailability and serve the last \
                 proven content (the broker's survive-backing-loss contract); default \
                 false — an out-of-band-deleted object stops being served",
            ),
            cache_config_field(
                "max_object_bytes",
                "Max cacheable object bytes",
                ConfigFieldKind::Integer,
                false,
                "Per-object fill cap: a read whose body exceeds it streams through \
                 uncached (the tee aborts mid-stream) and a brokered delegate over it \
                 passes through unwarmed; unset = unbounded",
            ),
            cache_config_field(
                "warm_delegates",
                "Warm local delegates",
                ConfigFieldKind::Bool,
                false,
                "Warm a cacheable `LocalDelegate` read into the CAS (pre-read capped by \
                 `max_object_bytes`) even without the broker read hint — the bespoke \
                 broker stack's way to opt into delegate warming; default false",
            ),
            cache_config_field(
                "watch_invalidation",
                "Watch invalidation",
                ConfigFieldKind::Bool,
                false,
                "Open background watches for watch-capable roots and invalidate cached bytes \
                 on out-of-band changes (default false)",
            ),
        ];
        descriptor
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let cache = match &self.cache {
            Some(cache) => cache.clone(),
            None => {
                let cache_root = require_path(config, "cache_root")?;
                let state_root = require_path(config, "state_root")?;
                let mut options = CacheOptions::default();
                if let Some(value) = config.get("max_bytes") {
                    options.max_bytes = Some(config_u64(value, "max_bytes")?);
                }
                if let Some(value) = config.get("max_streaming_fills") {
                    options.max_streaming_fills =
                        Some(config_u64(value, "max_streaming_fills")? as usize);
                }
                Arc::new(Cache::open_with_options(
                    CacheConfig {
                        state_root,
                        cache_root,
                    },
                    options,
                )?)
            }
        };
        let partition = config_string(config, "partition")
            .unwrap_or("local")
            .to_string();
        // Wrong-typed values fail the build (matching `config_u64`'s
        // convention): silently defaulting to `false` would build the
        // broker's composition with its survive-backing-loss behavior off.
        let lost_backing_fallback = match config.get("lost_backing_fallback") {
            None => false,
            Some(ConfigValue::Bool(value)) => *value,
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "cache config `lost_backing_fallback` must be a boolean",
                ));
            }
        };
        let max_object_bytes = match config.get("max_object_bytes") {
            Some(value) => Some(config_u64(value, "max_object_bytes")?),
            None => None,
        };
        // Wrong-typed values fail the build (matching the `lost_backing_fallback`
        // convention above): silently defaulting to `false` would build the
        // broker's bespoke stack with delegate warming off.
        let warm_delegates = match config.get("warm_delegates") {
            None => false,
            Some(ConfigValue::Bool(value)) => *value,
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "cache config `warm_delegates` must be a boolean",
                ));
            }
        };
        let watch_invalidation = parse_watch_invalidation(config)?;
        let watch_inner = inner.clone();
        // Reclaim the availability rows of the abandoned key namespaces before
        // serving: they are unreachable under the current key, so nothing else
        // will ever remove them.
        sweep_legacy_availability_rows(&cache, &partition);
        // Read once: `status()` is a query, and the budget is fixed for the
        // cache's lifetime. A failure here is fatal to the build rather than
        // silently unbudgeted -- swallowing it would disable the coexistence
        // check for the wrapper's whole lifetime on one transient error, and a
        // cache that cannot report its own status has a real problem worth
        // surfacing at construction.
        let max_cache_bytes = cache.status()?.max_bytes;
        let wrapper = Arc::new(ByteCacheWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            watch_state: CacheWatchState::new(watch_invalidation),
            inner,
            cache,
            partition,
            lost_backing_fallback,
            max_object_bytes,
            max_cache_bytes,
            warm_delegates,
            // Share the injected registry (SIGHUP reuse across wrappers over one
            // process-cached `Cache`); otherwise mint a fresh one.
            generations: match &self.generations {
                Some(shared) => shared.0.clone(),
                None => Arc::new(Mutex::new(HashMap::new())),
            },
        });
        // Own the notification drains here so they travel with the cache layer
        // (host-agnostic). As the top-most cache layer (byte composes
        // above metadata), pulling this layer's `watch_directory` fires both
        // this cache's and the metadata cache's invalidation hooks.
        let sweep_cache = Arc::clone(&wrapper.cache);
        let sweep_partition = wrapper.partition.clone();
        let sweep_generations = Arc::clone(&wrapper.generations);
        // The drain's lifecycle sweeps go down the chain, not just into this
        // cache. Events already reach every layer, because they travel back up
        // through the stacked `watch_directory` wrappers; these sweeps are
        // invoked directly by the layer owning the drain, so they need the
        // explicit path, and `invalidate_cached_subtree` forwards by default so
        // an intervening wrapper participates without knowing about caches.
        //
        // How far down depends on how the stack was built, and it stops at the
        // first plugin boundary. `invalidate_cached_subtree` has no ABI slot, so
        // a `ForeignVtableLayer` overrides neither it nor `inner_layer` and
        // takes the no-op default. Composed natively — the tests here, and any
        // host linking these wrappers directly — the sweep reaches the metadata
        // cache. Loaded from `libovstorage_plugin_cache`, where the two
        // factories are exported separately and the host chains them, this
        // layer's `inner` is such a proxy and the sweep clears byte rows only.
        // The metadata rows it cannot reach expire on their own — `ttl_seconds`
        // defaults to 30s — so that composition degrades to bounded staleness
        // rather than to the unbounded kind, which is the byte cache's, and the
        // byte cache is the one this closure always clears.
        let sweep_inner = watch_inner.clone();
        wrapper.watch_state.start(
            wrapper.clone() as Arc<dyn Layer>,
            watch_inner,
            watch_invalidation,
            Arc::new(move |prefix| {
                let _ =
                    clear_subtree_impl(&sweep_cache, &sweep_partition, &sweep_generations, prefix);
                sweep_inner.invalidate_cached_subtree(prefix);
            }),
        );
        Ok(wrapper)
    }
}

/// Caches object bytes, keyed by the object's **validator**: the cache
/// key is `partition\0canonical_address\0etag`, so an entry is tied to the
/// object version it was read from. Composes **above**
/// `RedirectFollowerWrapper` so it caches *post-redirect* bytes.
///
/// **Lookups validate first**: a cacheable read/materialize obtains the
/// object's current `etag` via an inner `stat` (served by the
/// `MetadataCacheWrapper` composed below in the default chain, so repeats are
/// cheap) and looks up under that validator — a changed object is never
/// served older bytes than the validator source knows about, and a request
/// whose current validator is unknown (the stat answered without an `etag`)
/// bypasses the cache.
///
/// **Consistency bound.** Composed above a metadata cache, the validating stat
/// may be served from a TTL-fresh metadata
/// entry: for out-of-band changes with no watcher, the freshness guarantee
/// is bounded by the metadata cache's TTL rather than lasting until the next
/// mutation, and governed by the one TTL knob
/// an operator already tunes. A byte cache composed WITHOUT a metadata cache
/// validates against the backend on every lookup: absolute freshness, at one
/// stat round-trip per read.
/// **Fills require a validator**: content is inserted only under the `etag`
/// the result itself reports; unversioned content is never cached. A
/// superseded validator's entry is unreachable by construction on the strict
/// path, and its content row is best-effort reclaimed — the availability
/// index names the exact predecessor, so each new fill prunes the row it
/// supersedes ([`ByteCacheWrapper::record_latest`]) and every mutation
/// through this stack reclaims the row it clears
/// ([`ByteCacheWrapper::clear_latest`] /
/// [`ByteCacheWrapper::clear_subtree`]) — keeping the steady state at ~one
/// content row per address even in the default no-budget configuration, with
/// size-budget eviction as the backstop only when the index entry itself was
/// evicted.
///
/// Since the v2 `Layer::read` is a single slot (no `read_bytes` vs
/// `read_stream` caller intent), the wrapper caches a `ReadResult::Bytes`
/// result directly and **tees** a cacheable `ReadResult::Stream` into the
/// cache as its chunks pass to the caller (spooling to a disk staging file,
/// committing only on clean stream completion, capped by `max_object_bytes` —
/// so the whole object is never held in memory and a cancelled/truncated read
/// leaves no half-cached row). A `LocalDelegate` is warmed via the brokered
/// pre-read-capped spool below. `materialize` caches the staged file with a
/// [`Lease`](ovstorage_cache::Lease). Writes cache write-through under the write
/// result's new validator: a buffered (`Body::Bytes`) write stores its whole
/// buffer, and a streamed (`Body::Stream`) write tees chunk-by-chunk into a
/// staging file as the backend drains it — the write counterpart of the read
/// stream tee, capped by `max_object_bytes` and guarded, committing only
/// on clean completion so a cancelled/failed/over-cap streamed write leaves no
/// half-cached row.
struct ByteCacheWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    watch_state: CacheWatchState,
    inner: LayerHandle,
    cache: Arc<Cache>,
    partition: String,
    /// When set (the broker's composition), a `NotFound` validator stat is
    /// treated as lost backing store and the availability fallback may
    /// answer; by default `NotFound` is a definitive answer and the cache is
    /// bypassed, so an out-of-band-deleted object stops being served.
    lost_backing_fallback: bool,
    /// Per-object fill cap and cache-DoS gate. A streamed body past it aborts the tee
    /// mid-stream (the caller's stream continues intact); `None` = unbounded.
    max_object_bytes: Option<u64>,
    /// The cache's whole-store size budget, read once at construction. Used to
    /// refuse objects that cannot coexist with their own availability row; see
    /// [`Self::within_object_cap`]. `None` = unbudgeted, so nothing is refused.
    ///
    /// **Partial coverage.** The refusal is applied only where
    /// [`Self::within_object_cap`] is called: the three buffered
    /// `ReadResult::Bytes` fills. It is NOT applied to the read stream tee, the
    /// streamed write-through, buffered write-through, delegate warming, or
    /// `materialize` — which are the paths large objects actually take, so the
    /// degradation it exists to refuse is still reachable there. Those fills
    /// learn their size only as they stream (or, for `materialize`, are
    /// deliberately uncapped), so gating them means a running total against the
    /// budget rather than a check, and that is a larger change than this one.
    max_cache_bytes: Option<u64>,
    /// When set (the broker's bespoke stack), a cacheable `LocalDelegate` read
    /// warms the CAS via [`Self::warm_delegate`] even without the broker read
    /// hint on the request; by default a delegate warms only when the hint is
    /// present, so an unbrokered composition passes delegates through unwarmed.
    warm_delegates: bool,
    /// Per-address mutation generation for the stream-tee resurrection guard.
    /// A tee registers its address on start ([`TeeRegistration`]),
    /// capturing the address's current generation; a mutation through this
    /// stack ([`bump_generation_key`] / [`Self::clear_latest`] / the
    /// write-through fill / a subtree clear) advances the generation of every
    /// *registered* address; and the tee publishes its fill only if the
    /// generation is unchanged at commit — so a mutation (e.g. a delete) that
    /// lands while a caller holds the read stream open is prevented from being
    /// undone by the tee later re-publishing the content + availability index.
    ///
    /// The map holds an entry only while at least one tee is registered for the
    /// address: the registration is ref-counted and dropped when the last tee
    /// on the address completes/drops, so the map is bounded by in-flight tees,
    /// not by lifetime mutation cardinality — a mutation with no in-flight tee
    /// finds no registration, bumps nothing, and leaks nothing.
    ///
    /// The generation check is read-then-commit, so a mutation landing between
    /// the check and the availability publish slips past *it*; the persisted
    /// availability row's publication fence (see [`encode_avail`]) is what
    /// covers that window, and it covers the buffered fills the generation map
    /// does not track at all.
    generations: Arc<Mutex<GenerationMap>>,
}

/// What the pre-read `stat` amounted to, for both questions its caller asks.
///
/// Two separate questions, and only the backend can answer either: which version
/// to key a lookup on, and whether it refused the address outright. They travel
/// together because they are learned by one call, and because deciding the
/// second anywhere else means deciding it without having asked.
struct ValidatorProbe {
    /// The version to key a cache lookup on, when one is usable.
    validator: Option<String>,
    /// The backend did NOT refuse this address.
    ///
    /// Exactly that, and no more: it is false for the refusal codes —
    /// `PermissionDenied`, the auth/credential family, `InvalidArgument` — and
    /// true for every other outcome, including an outage that answered nothing.
    /// It is **not** a statement that the caller has rights, because a backend
    /// may answer `NotFound` for a path the caller may not see, and this layer
    /// cannot tell that from an ordinary absence — nor should it try, since the
    /// metadata layer caches a list-backed negative and the directory holding it
    /// is one a watch has to cover.
    ///
    /// So it closes a refused read choosing a watch prefix. A backend that
    /// masks refusals as absences keeps that capability, and closing it belongs
    /// where the masking happens.
    registers: bool,
}

impl ValidatorProbe {
    /// No validator, and no evidence this address may name a scope.
    fn silent() -> Self {
        Self {
            validator: None,
            registers: false,
        }
    }
}

impl ByteCacheWrapper {
    /// `partition\0canonical_address\0etag`. The `etag` dimension ties
    /// the entry to the object version it was read from. Backend instance IDs
    /// deliberately do not participate: the validator, not a resolved route
    /// identity, is the
    /// cache identity — correct even when routes move between backends.
    fn cache_key(&self, address: &Url, etag: &str) -> String {
        content_cache_key(&self.partition, address, etag)
    }

    /// The validator to look up under. Preferred source: the object's
    /// current `etag` via an inner `stat` carrying the caller's request
    /// extensions (so principal scoping and tracing flow); a backend that
    /// answers without an `etag` means bypass (`None`) — unversioned content
    /// is never served.
    ///
    /// A stat **error** is discriminated by shape:
    ///
    /// - **Availability-shaped** (`Transient`, `DeadlineExceeded`,
    ///   `ResourceExhausted`, `Internal`, `BrokerUnavailable`,
    ///   `NetworkFilesystemRefused`, `StateRootUnavailable`,
    ///   `RedirectExpired`) — the backend could not answer freshly at all:
    ///   the last-known-validator index answers,
    ///   preserving availability by serving the last content it proved until a
    ///   mutation through this stack clears it.
    /// - **`NotFound`** — definitive by default (an out-of-band-deleted
    ///   object must stop being served); compositions that opt in via
    ///   `lost_backing_fallback` (the broker's survive-backing-loss
    ///   contract) treat it as lost backing store instead.
    ///
    /// Answers TWO questions, because both need the backend and only one of them
    /// looks like it does. Which validator to look up is the first. Whether the
    /// backend refused the address is the second, and the alternative to
    /// answering it here is `cacheable` — a property of the REQUEST, computed
    /// before the backend is consulted at all, which admits a refused read to
    /// the watch registration and lets a caller the backend turned away choose
    /// which directories a credential-free background drain subscribes to.
    /// - **`Unsupported`** — explicit bypass: a stat-less backend gets no
    ///   validation at all, so index-serving would create stale-until-mutation
    ///   behavior for that whole backend class.
    /// - **`Cancelled`** — propagates: a cancelled stat must not produce a
    ///   read.
    /// - **Everything else** (`PermissionDenied`, the auth/credential
    ///   family, `InvalidArgument`, …) — an answer, not an outage: bypass,
    ///   never the index (a principal the backend refuses must not be served
    ///   partition-shared content).
    async fn lookup_etag(
        &self,
        extensions: &Extensions,
        address: &Url,
        cancel: Option<CancellationToken>,
    ) -> Result<ValidatorProbe> {
        match self
            .inner
            .stat(
                Request {
                    extensions: extensions.clone(),
                    input: StatRequest {
                        address: address.clone(),
                        options: StatOptions::default(),
                    },
                },
                cancel,
            )
            .await
        {
            // An empty etag is no validator: it cannot distinguish two
            // versions, so a lookup keyed on it would serve the first fill
            // through every later change the backend reports the same way.
            // [`ProvenValidator`] refuses to publish one; this refuses to look
            // one up, so neither end of the strict path can key on it.
            Ok(info) => Ok(ValidatorProbe {
                validator: info.etag.filter(|etag| !etag.is_empty()),
                registers: true,
            }),
            Err(error) => match error.code() {
                ErrorCode::Cancelled => Err(error),
                // An outage, not a verdict on the address. `registers` stays
                // true here for the same reason this arm consults the
                // availability index at all: the cache may well hold entries
                // under the directory, and a prefix-wide outage is when their
                // watch matters most. Keying it on a recovered validator instead
                // would refuse to register for every etag-less backend, since
                // nothing writes an availability row without one — which is the
                // unversioned route the registration exists to cover.
                ErrorCode::Transient
                | ErrorCode::DeadlineExceeded
                | ErrorCode::ResourceExhausted
                | ErrorCode::Internal
                | ErrorCode::BrokerUnavailable
                | ErrorCode::NetworkFilesystemRefused
                | ErrorCode::StateRootUnavailable
                | ErrorCode::RedirectExpired => Ok(ValidatorProbe {
                    validator: self.last_known_validator(address).await,
                    registers: true,
                }),
                // `NotFound` registers on both arms — the same rule the `stat`
                // pass-through applies, and for the same reason: the metadata
                // layer caches a list-backed negative, and this layer cannot
                // tell one of those from a backend's own.
                ErrorCode::NotFound if self.lost_backing_fallback => Ok(ValidatorProbe {
                    validator: self.last_known_validator(address).await,
                    registers: true,
                }),
                ErrorCode::NotFound => Ok(ValidatorProbe {
                    validator: None,
                    registers: true,
                }),
                // A stat-less backend gets no silent staleness: an
                // explicit arm so a future code addition can't reclassify it
                // through the catch-all. It still registers — a capability gap
                // is not a statement about this caller or this address — and a
                // body it goes on to cache registers again at the commit point.
                ErrorCode::Unsupported => Ok(ValidatorProbe {
                    validator: None,
                    registers: true,
                }),
                // The one bucket that does not register: `PermissionDenied`, the
                // auth/credential family and `InvalidArgument` — the codes this
                // function's own classification above calls an answer rather
                // than an outage. The layer below takes `?` on them and caches
                // nothing, so there is no row for a watch to protect, and
                // registering lets a caller the backend refused choose which
                // directories a credential-free background drain subscribes to.
                _ => Ok(ValidatorProbe::silent()),
            },
        }
    }

    /// The availability index's current value for `address`, if any.
    async fn last_known_validator(&self, address: &Url) -> Option<String> {
        last_known_validator_impl(&self.cache, &self.partition, address).await
    }

    /// Record `etag` as the address's newest-fill validator (the availability
    /// fallback the mutation overrides clear), best-effort pruning the
    /// superseded validator's content row: the index remembers the newest
    /// fill, so its previous value names exactly the row a new fill
    /// supersedes — including out-of-band changes — keeping the
    /// validator-keyed cache at ~one content row per address instead of one
    /// per version (eviction remains the backstop when the index itself was
    /// evicted).
    ///
    /// Publishes only if the availability row still holds exactly the bytes
    /// `snapshot` captured at the read's start — so a slow pre-mutation read
    /// can't re-publish a validator a concurrent mutation
    /// ([`Self::clear_latest`] or a write-through publish)
    /// superseded. `snapshot` is `None` when the row could neither be read nor
    /// seeded, which skips the publish rather than leaving it unfenced.
    ///
    /// Best-effort: the availability index answers only while the backend
    /// cannot, so a bookkeeping failure must not fail a read that already
    /// holds valid bytes.
    ///
    /// This is for callers whose fill is a *read*. A write-through uses the
    /// mutation publication path instead.
    async fn record_latest(
        &self,
        address: &Url,
        snapshot: Option<Vec<u8>>,
        etag: &str,
        guard: Option<ReadGuard>,
    ) -> PublishOutcome {
        record_latest_guarded_impl(&self.cache, &self.partition, address, snapshot, etag, guard)
            .await
    }

    /// The address's availability row as of now (see [`snapshot_avail`]).
    async fn snapshot(&self, address: &Url) -> Option<Vec<u8>> {
        snapshot_avail(&self.cache, &self.partition, address).await
    }

    /// Take back a seed no fill will ever publish against.
    ///
    /// [`snapshot_avail`] seeds an absent row, so a read that then proves no
    /// validator — an error, or a backend that names no versions — would leave
    /// a row and a CAS blob behind for a path that was only ever probed.
    ///
    /// Removal is conditional in two ways, and both matter. It only touches a
    /// row that carries **no validator**: a snapshot that names one is a
    /// fallback some earlier fill established, and this read has proved nothing
    /// that supersedes it. And it is a compare-and-swap against the exact bytes
    /// snapshotted, so a mutation or fill that rewrote the row in the meantime
    /// keeps its own state. What is left to remove is therefore either this
    /// read's own seed or a tombstone, and an absent row and a tombstone answer
    /// every lookup alike — the cost is one re-seed on the next read.
    async fn discard_unused_seed(&self, address: &Url, snapshot: Option<&[u8]>) {
        let Some(snapshot) = snapshot else {
            return;
        };
        if parse_avail(snapshot).is_some() {
            return;
        }
        let key = availability_index_key(&self.partition, address);
        let cache = Arc::clone(&self.cache);
        let expected = snapshot.to_vec();
        // Best-effort, and off the runtime for the same reason every other
        // compare-and-swap here is: it stages, fsyncs and commits.
        let _ =
            tokio::task::spawn_blocking(move || cache.compare_and_put(&key, Some(&expected), None))
                .await;
    }

    /// A mutation through this stack invalidates the availability fallback
    /// and best-effort reclaims the superseded content row it names. Content
    /// correctness never depends on this — a superseded validator is
    /// unreachable on the strict path by construction.
    async fn clear_latest(&self, address: &Url) -> Result<()> {
        clear_latest_impl(&self.cache, &self.partition, &self.generations, address).await
    }

    /// Whether an object of `len` bytes is within the per-object fill cap. A
    /// `None` cap is unbounded. Gates every byte-path fill so an object served
    /// as `Bytes` cannot bypass the cap the stream tee already enforces.
    fn within_object_cap(&self, len: usize, etag: &str) -> bool {
        if self.max_object_bytes.is_some_and(|cap| len as u64 > cap) {
            return false;
        }
        // An object must also fit alongside its own availability row. At the
        // margin the two cannot both survive: the fill evicts the row (the
        // older, smaller candidate), and the publish then compares against a
        // row that is gone and refuses -- so the object is cached and its
        // fallback is silently absent, with every read path reporting success.
        //
        // Ordering does not rescue it. Publishing first was measured during the
        // fence work and did not help: the published row is larger than the
        // seed it replaces, so a fill that would evict one evicts the other,
        // and publish-first additionally opens a window where a validator names
        // content that does not exist yet.
        //
        // Refuse instead. An object the cache cannot serve coherently is better
        // declined than admitted at the cost of an invisible degradation, and
        // declining leaves the budget for objects it can serve.
        // The row's size is exact, not estimated: the etag is the one the
        // completed result reported and the same `String` this fill publishes
        // under, so `encode_avail`'s width is known here. A fixed reserve was
        // wrong in both directions -- it refused small objects on a small
        // budget, and admitted objects whose row was larger than the guess,
        // which is the case it existed to prevent.
        fits_alongside_its_row(len as u64, etag, self.max_cache_bytes)
    }

    /// Directory-shaped mutations must clear the whole subtree: fills are per
    /// object, so [`Self::clear_latest`] on the directory address covers none
    /// of the children. Prefix-remove every child's availability-index row —
    /// otherwise a deleted child keeps answering via the fallback whenever
    /// its post-delete stat errs (under `lost_backing_fallback` the
    /// post-delete `NotFound` is the steady state, not an outage) — and
    /// best-effort reclaim the children's content rows, mirroring
    /// `clear_latest`'s single-object reclamation. The appended `/` keeps a
    /// sibling prefix (`dir` vs `dir2`) out of the sweep; the `\u{2}` / `\0`
    /// separators keep the two namespaces disjoint.
    fn clear_subtree(&self, address: &Url) -> Result<()> {
        clear_subtree_impl(&self.cache, &self.partition, &self.generations, address)
    }

    /// Settle the availability row for a completed read-family op that proved
    /// no usable validator.
    ///
    /// The two ways to have none are not the same evidence, and both `read` and
    /// `materialize` owe the distinction -- so it lives here rather than being
    /// written out twice.
    ///
    /// A backend that reports NO etag has said nothing about versions, so a row
    /// an earlier fill established still stands and only this op's own seed is
    /// residue; an in-tree example is an HTTP origin serving no `ETag` header.
    /// A backend that reports an EMPTY one has answered: it read a version and
    /// named it with a string that cannot be told from any other. A row naming
    /// an older, real validator no longer describes the object, so leaving it
    /// is the one outcome that serves bytes this op disproved, once a stat
    /// outage engages the fallback. Note `discard_unused_seed` cannot cover
    /// that case by construction: it deliberately keeps a row that names a real
    /// validator, which is exactly the row that is now wrong.
    async fn settle_without_validator(
        &self,
        address: &Url,
        reported_etag: Option<&str>,
        snapshot: Option<&[u8]>,
    ) {
        if reported_etag == Some("") {
            // Best-effort: the op holds a good answer, and an unwritable index
            // must not fail it.
            let _ = self.clear_latest(address).await;
        } else {
            self.discard_unused_seed(address, snapshot).await;
        }
    }

    /// Fill the content row for `etag`, publish it as the address's newest
    /// validator, and disarm `guard` if that settled the row -- the whole
    /// buffered-fill sequence, in the one order that is safe.
    ///
    /// Every buffered read arm ends this way and the ordering is subtle enough
    /// that three copies of it were three chances to drift, on exactly the
    /// invariant the guards exist to hold. The arms differ only in the result
    /// shape they build, so that is all they keep.
    ///
    /// Fill first, then publish: a validator must never name content that
    /// failed to land. Refusing to publish is also right when the seed was
    /// evicted by pressure unrelated to this fill, which the publish cannot
    /// distinguish -- at a budget too small to hold the object alongside its
    /// bookkeeping, the seed can be evicted by this very fill. Publishing first
    /// does not rescue that (the published row is larger than the seed it
    /// replaces, and eviction orders by a millisecond-granularity access time,
    /// so which of the two is the victim is timing-dependent at the margin) and
    /// it opens a window where a validator names content that does not exist.
    ///
    /// The insert is idempotent and takes no stampede lock. A fill failure
    /// degrades to serving uncached rather than failing a read the backend has
    /// already answered; the caller's guard clears on the way out, because this
    /// read proved `etag` current and every exit from here must leave the index
    /// no longer naming an older validator.
    async fn fill_and_publish(
        &self,
        address: &Url,
        etag: &str,
        bytes: &[u8],
        snapshot: Option<Vec<u8>>,
        guard: &mut Option<ReadGuard>,
    ) {
        if !self.within_object_cap(bytes.len(), etag) {
            // Over-cap: this validator cannot be retained, and the index may
            // still name an older one. The guard clears it.
            return;
        }
        if self
            .cache
            .put(&self.cache_key(address, etag), bytes)
            .is_err()
        {
            return;
        }
        // A commit point: the body is in the cache from here, which the register
        // on the way IN to a read cannot know. That one keys on the inner
        // `stat` having answered for the address, and a backend can serve a read
        // whose stat did not — a stat-less one answers `Unsupported`, and a
        // redirecting one names a version on its read while its stat names none.
        // So a body published here can be one that register never saw. Neither
        // reaches a refused read: nothing commits. The other commit points are
        // `tee_into_cache` for a
        // streamed body, `warm_delegate` and `materialize` for a leased spool,
        // and `finalize_committed_tee` for a write-through; each registers where
        // it commits, for this same reason.
        self.watch_state.note_cached(address);
        let guard = guard.take();
        let _ = self.record_latest(address, snapshot, etag, guard).await;
    }

    /// Warm the byte cache from a brokered `LocalDelegate` without loading the
    /// object into memory: the delegate size is checked against
    /// `max_object_bytes` **pre-read**, and within the cap the file is spooled
    /// into the CAS via `put_path_and_lease` (streamed, no whole-file `Vec`).
    /// The returned delegate points at the leased CAS copy (so a later read
    /// survives backing-store loss), and the
    /// fill is recorded as the address's newest validator. An object with no
    /// etag, one over the cap, or a cache-write failure passes the original
    /// delegate through uncached.
    /// `snapshot` is the caller's availability row captured BEFORE the read
    /// that produced `local` — threaded in (not recaptured) so the fence covers
    /// a `clear_latest` landing during the delegate fetch / CAS copy.
    ///
    /// `guard` is the caller's, moved in rather than re-armed. Exactly one
    /// guard may govern a row: a second one armed here would be disarmed by
    /// this function's publish while the caller's stayed armed, and the
    /// caller's drop would then clear the row this warm had just published —
    /// leaving the CAS body cached but unreachable through the fallback that
    /// warming exists to provide.
    async fn warm_delegate(
        &self,
        address: &Url,
        local: LocalDelegate,
        snapshot: Option<Vec<u8>>,
        guard: ReadGuard,
    ) -> Result<ReadResult> {
        let Some(proof) = ProvenValidator::proved(&local.info) else {
            return Ok(ReadResult::LocalDelegate(local));
        };
        let etag = proof.etag().to_string();
        // The delegate is a completed read, so from here every exit that does
        // not reach the publish clears: over-cap, an unleased spool and a
        // failed spool all leave the index naming a validator this read
        // superseded.
        if let Some(cap) = self.max_object_bytes
            && delegate_size(&local).await > cap
        {
            // Over-cap: the current validator can't be retained, so the
            // availability index must not keep naming an older, now-superseded
            // one. The guard clears on the way out.
            return Ok(ReadResult::LocalDelegate(local));
        }
        match self
            .cache
            .put_path_and_lease(&self.cache_key(address, &etag), &local.path)
        {
            // Only swap in the leased CAS copy when a real lease was minted: a
            // guard-less delegate at `put.entry.path` can be evicted the instant
            // it is published (e.g. an object larger than the cache budget),
            // leaving the returned path stale. Without a lease, hand back the
            // original delegate and skip the availability index.
            Ok(put) => match put.lease {
                Some(lease) => {
                    // Best-effort index write: a perfectly good delegate is in
                    // hand, so an index failure must not fail the read. The
                    // fence uses the caller's PRE-read `snapshot`. This sits
                    // inside the lease arm because only a leased spool may be
                    // published at all -- the lease is the evidence.
                    let _ = self
                        .record_latest(address, snapshot, &etag, Some(guard))
                        .await;
                    // A leased spool is a committed body, the same as
                    // `fill_and_publish`'s put. The pre-read registration keys
                    // on the inner `stat` having answered, and a delegate warm
                    // proves a body exists whether or not it did.
                    self.watch_state.note_cached(address);
                    Ok(ReadResult::LocalDelegate(LocalDelegate {
                        path: put.entry.path,
                        info: local.info,
                        guard: Some(Arc::new(lease) as Arc<dyn Send + Sync>),
                    }))
                }
                // No lease minted, so nothing may be published; the guard
                // clears the row this read superseded.
                None => Ok(ReadResult::LocalDelegate(local)),
            },
            // The spool failed; the guard clears, as in the over-cap branch.
            Err(_) => Ok(ReadResult::LocalDelegate(local)),
        }
    }

    /// Streamed write-through: tee the request's `Body::Stream` into the cache
    /// as the inner write drains it, committing the teed body under the write
    /// result's new validator on clean completion. `use_write_stream` selects
    /// the inner slot (`write_stream` vs `write`).
    ///
    /// Mirrors the read stream tee: the body spools chunk-by-chunk into a cache
    /// staging file capped by `max_object_bytes` (never held whole in memory); a
    /// cap breach or a body error abandons the fill (the write's body streams on
    /// intact), and a commit lands only when the whole body flowed through
    /// (`reached_eof`), the write result carried a validator, the staged length
    /// matched the result's declared size, and the address was not mutated
    /// since the tee started (the write registers against the generations
    /// map exactly as the read tee and other mutation paths do). A write the tee
    /// could not fully observe — cache unavailable, backend that did not drain
    /// the body, cap breach, or missing validator — invalidates the address
    /// instead, so the availability index never keeps naming the pre-write
    /// validator. The commit is off-runtime (`sync_all` + CAS publication + SQLite
    /// publish), matching the read tee.
    async fn streamed_write_through(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
        use_write_stream: bool,
    ) -> Result<WriteResult> {
        let address = request.input.address.clone();
        let Body::Stream(stream) =
            std::mem::replace(&mut request.input.body, Body::Bytes(Vec::new()))
        else {
            unreachable!("streamed_write_through is only entered for a Body::Stream");
        };
        // Mutation discipline, armed before anything can reach the backend.
        // Both branches below call it -- the degraded one included -- so the
        // guard has to cover the whole function, not just the tee'd path.
        // Arming earlier only ever widens what a failure clears, so it cannot
        // regress the fast path.
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        // Stage under a provisional key — the validator is only known from the
        // write result, and `StreamingPut::commit_to` retargets to the real key
        // at commit. A cache that cannot open a streaming fill degrades to an
        // uncached write that invalidates the address. That is not only the
        // read-only case: `begin_streaming_put` also refuses when the shared
        // streaming fill-slot budget is exhausted, which is ordinary load on a
        // perfectly healthy cache with a fully populated index.
        let put = match self.cache.begin_streaming_put(
            &self.cache_key(&address, PROVISIONAL_WRITE_ETAG),
            self.max_object_bytes,
        ) {
            Ok(put) => put,
            Err(_) => {
                request.input.body = Body::Stream(stream);
                let result = self
                    .dispatch_inner_write(request, cancel, use_write_stream)
                    .await?;
                self.clear_latest(&address).await?;
                guard.disarm(None);
                return Ok(result);
            }
        };
        // As in the buffered path: the availability row as it stood before the
        // backend write is what this tee's publish is fenced on.
        let snapshot = self.snapshot(&address).await;
        // Register this write tee against the address's generation slot for the
        // duration of the inner write, capturing the start generation so a
        // *concurrent* mutation that lands mid-write invalidates the late commit.
        // Dropped on every terminal path, keeping the map bounded.
        let (registration, start_generation) =
            TeeRegistration::register(self.generations.clone(), &address);
        let shared = Arc::new(Mutex::new(WriteTeeState {
            put: Some(put),
            reached_eof: false,
            aborted: false,
        }));
        request.input.body = Body::Stream(write_tee_body(stream, Arc::clone(&shared)));
        let result = self
            .dispatch_inner_write(request, cancel, use_write_stream)
            .await;
        // Reclaim the tee state regardless of the write outcome.
        let (put, reached_eof, aborted) = {
            let mut state = shared.lock().expect("write-tee state lock poisoned");
            (state.put.take(), state.reached_eof, state.aborted)
        };
        let result = match result {
            Ok(result) => result,
            // The write failed. Whether it landed is unknowable from here, so
            // the guard clears on the way out; dropping `put` and the
            // registration discards the staging file.
            Err(error) => {
                drop(put);
                drop(registration);
                return Err(error);
            }
        };
        // Commit only a fully-observed, still-current, validator-carrying fill
        // (commit-only-on-complete). `registration.current()` is read BEFORE the
        // commit-time bump below, so the write's own mutation bump never fails
        // its own check.
        // `ProvenValidator`, not the raw etag: an empty one keys a content row
        // no lookup can ever match (the lookup refuses it for the same reason),
        // so committing under it stores bytes nothing can read and nothing
        // evicts. Same rule, same type, as every other fill site.
        let commit = match (put, ProvenValidator::proved(&result.info)) {
            (Some(put), Some(proof))
                if reached_eof
                    && !aborted
                    && result.info.size.is_none_or(|size| put.staged_len() == size)
                    && registration.current() == start_generation =>
            {
                let key = self.cache_key(&address, proof.etag());
                let committed = tokio::task::spawn_blocking(move || put.commit_to(&key).is_ok())
                    .await
                    .unwrap_or(false);
                committed.then(|| proof.etag().to_string())
            }
            // Not committable: discard the staging file (drop removes it).
            (put, _) => {
                drop(put);
                None
            }
        };
        let published = commit.clone();
        match commit {
            Some(etag) => {
                self.finalize_committed_tee(
                    &address,
                    snapshot,
                    &etag,
                    &registration,
                    start_generation,
                )
                .await?;
            }
            // Nothing provable to cache — invalidate (also bumps concurrent read
            // tees, since the object still mutated).
            None => self.clear_latest(&address).await?,
        }
        // The validator this write published, if it published one.
        guard.disarm(published.as_deref());
        drop(registration);
        Ok(result)
    }

    /// Buffered write-through without a second whole-body allocation. The
    /// caller's `Vec` is borrowed once into a staging fill before ownership is
    /// handed to the inner layer, preserving `Body::Bytes` semantics across
    /// plugin boundaries while retaining an independent on-disk copy for the
    /// post-write cache commit.
    async fn buffered_write_through(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let address = request.input.address.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        let mut put = match self.cache.begin_streaming_put(
            &self.cache_key(&address, PROVISIONAL_WRITE_ETAG),
            self.max_object_bytes,
        ) {
            Ok(put) => put,
            Err(_) => {
                let result = self.inner.write(request, cancel).await?;
                self.clear_latest(&address).await?;
                guard.disarm(None);
                return Ok(result);
            }
        };
        let snapshot = self.snapshot(&address).await;
        let (registration, start_generation) =
            TeeRegistration::register(self.generations.clone(), &address);
        let Body::Bytes(bytes) = &request.input.body else {
            unreachable!("buffered_write_through is only entered for Body::Bytes");
        };
        if put.write_chunk(bytes).is_err() {
            drop(put);
            drop(registration);
            let result = self.inner.write(request, cancel).await?;
            self.clear_latest(&address).await?;
            guard.disarm(None);
            return Ok(result);
        }

        let result = self.inner.write(request, cancel).await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                drop(put);
                drop(registration);
                return Err(error);
            }
        };
        let commit = match ProvenValidator::proved(&result.info) {
            Some(proof) if registration.current() == start_generation => {
                let key = self.cache_key(&address, proof.etag());
                let committed = tokio::task::spawn_blocking(move || put.commit_to(&key).is_ok())
                    .await
                    .unwrap_or(false);
                committed.then(|| proof.etag().to_string())
            }
            _ => {
                drop(put);
                None
            }
        };
        let published = commit.clone();
        match commit {
            Some(etag) => {
                self.finalize_committed_tee(
                    &address,
                    snapshot,
                    &etag,
                    &registration,
                    start_generation,
                )
                .await?;
            }
            None => self.clear_latest(&address).await?,
        }
        guard.disarm(published.as_deref());
        drop(registration);
        Ok(result)
    }

    /// Publish (or discard) a committed streamed write-through tee's row,
    /// re-checking the mutation generation AFTER the off-runtime commit
    /// (`spawn_blocking` sync_all + CAS publication + SQLite publish) and around the
    /// availability publish. The pre-commit guard in
    /// [`Self::streamed_write_through`] only covers the file commit; a concurrent
    /// delete or newer write that bumps/clears the generation *during* the commit
    /// window must still win. Publishing this now-stale tee's row and validator
    /// would overwrite the mutation's [`Self::clear_latest`] and, under the
    /// lost-backing fallback, resurrect superseded/deleted content — the exact
    /// class the guard exists to prevent. The re-check reads against
    /// `start_generation` (the pre-commit snapshot, captured before this write's
    /// own mutation bump below), so the write never invalidates itself.
    async fn finalize_committed_tee(
        &self,
        address: &Url,
        snapshot: Option<Vec<u8>>,
        etag: &str,
        registration: &TeeRegistration,
        start_generation: u64,
    ) -> Result<()> {
        let current_generation = registration.current();
        let outcome = finalize_committed_tee_impl(
            &self.cache,
            &self.partition,
            &self.generations,
            address,
            TeeCommit {
                snapshot,
                etag,
                current_generation,
                start_generation,
            },
        )
        .await;
        // Both write-through paths reach here with a body already committed, so
        // this is a commit point like the read-side ones: a caller that only
        // ever writes fills the byte cache for every object it stores, and
        // without this none of those directories is watched. Gated on the same
        // condition the publish is, because the other branch of that call is a
        // DISCARD — the address moved under the write, so the row is removed and
        // the cache is left holding nothing to watch.
        if current_generation == start_generation {
            self.watch_state.note_cached(address);
        }
        outcome
    }

    /// Dispatch to the inner `write_stream` or `write` slot — the streamed
    /// write-through tee drives whichever slot the caller entered on.
    async fn dispatch_inner_write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
        use_write_stream: bool,
    ) -> Result<WriteResult> {
        if use_write_stream {
            self.inner.write_stream(request, cancel).await
        } else {
            self.inner.write(request, cancel).await
        }
    }
}

/// On-disk size of a delegate for the pre-read cap check: the real file length
/// (accurate and cheap) with the delegate's declared `info.size` as a fallback.
async fn delegate_size(local: &LocalDelegate) -> u64 {
    match tokio::fs::metadata(&local.path).await {
        Ok(meta) => meta.len(),
        Err(_) => local.info.size.unwrap_or(0),
    }
}

/// Content cache key `partition\0canonical_address\0etag`. Shared by the
/// wrapper's [`ByteCacheWrapper::cache_key`] and the stream tee so the row a
/// tee commits is looked up under exactly the same key.
fn content_cache_key(partition: &str, address: &Url, etag: &str) -> String {
    format!("{partition}\0{address}\0{etag}")
}

/// Availability-index key `partition\u{2}canonical_address` — a `\u{2}`
/// namespace disjoint from every `\0` content key.
///
/// The `\u{1}` namespace is abandoned and never read. It holds rows in two
/// encodings that cannot be told apart from each other or from
/// [`encode_avail`]'s shape with acceptable confidence — a bare UTF-8 etag, and
/// `epoch (u64 LE) || etag`, whose leading NUL bytes decode as valid UTF-8 and
/// whose tombstone reads as a live validator. A row that cannot be identified
/// must not be interpreted, so the whole namespace is unreachable rather than
/// misread, and [`sweep_legacy_availability_rows`] reclaims it at construction
/// so it does not wait on eviction.
fn availability_index_key(partition: &str, address: &Url) -> String {
    format!("{partition}\u{2}{address}")
}

/// Key prefix of the abandoned availability-index namespaces.
fn legacy_availability_prefix(partition: &str) -> String {
    format!("{partition}\u{1}")
}

/// Drop every row left under the abandoned availability-index namespace, and
/// the partition's cached bodies with them. Runs once per wrapper construction.
///
/// # Why the bodies go too
///
/// A legacy availability row is the only record of which validator a legacy
/// body was filled under, and it is in an encoding this build refuses to
/// interpret — see [`availability_index_key`]. So the validator cannot be
/// recovered to prune that body precisely: removing the row destroys the last
/// pointer to it. Content keys are unchanged, so the body stays reachable while
/// the object still has its old validator, but the moment it changes, nothing
/// keys on the old etag again, the strict path cannot see the row, and the
/// default no-budget cache never evicts it. That is one stranded object per
/// legacy address, permanently, on upgrade of a warm cache.
///
/// The cost is one cold start for a cache written by a version whose
/// availability state this build already declines to trust. The alternative —
/// keeping bodies whose reclaim pointer has been destroyed — is the leak this
/// whole change exists to close.
///
/// # Why this needs no migration marker
///
/// The legacy rows are the marker. They are removed in the same pass, so a
/// later construction finds none and leaves a freshly populated cache alone.
/// The content flush runs FIRST for crash-safety: interrupted between the two,
/// the legacy rows survive and the next construction repeats the migration (by
/// then a no-op on content). The other order would strand exactly what this
/// exists to reclaim.
///
/// Best-effort throughout — a read-only cache cannot remove, and failing to
/// reclaim dead rows must not fail the build.
fn sweep_legacy_availability_rows(cache: &Cache, partition: &str) {
    let legacy = legacy_availability_prefix(partition);
    if !cache.has_any_with_prefix(&legacy).unwrap_or(false) {
        return;
    }
    let _ = cache.remove_prefix(&content_prefix(partition));
    let _ = cache.remove_prefix(&legacy);
}

/// Key prefix of every content row in `partition`. Disjoint from both
/// availability namespaces, which use `\u{2}` and `\u{1}`.
fn content_prefix(partition: &str) -> String {
    format!("{partition}\0")
}

/// Encoding version of an availability row.
const AVAIL_VERSION: u8 = 1;

/// Width of the publication nonce.
const AVAIL_NONCE_LEN: usize = 16;

/// Version byte + nonce.
const AVAIL_HEADER_LEN: usize = 1 + AVAIL_NONCE_LEN;

/// Whether `len` bytes fit in `budget` alongside the availability row a fill
/// under `etag` publishes. Extracted from [`ByteCacheWrapper::within_object_cap`]
/// so the arithmetic is testable on its own: the whole point is that the row's
/// width tracks the etag rather than a fixed reserve, and an end-to-end test
/// cannot tell the two apart -- at a budget tight enough to matter, eviction
/// produces the same observable miss whatever the admission check decided.
fn fits_alongside_its_row(len: u64, etag: &str, budget: Option<u64>) -> bool {
    let row = (AVAIL_HEADER_LEN + etag.len()) as u64;
    budget.is_none_or(|budget| len + row <= budget)
}

/// Attempts a read-modify-write loop makes before giving up. Every iteration
/// re-reads the row, so an uncontended swap lands on the first pass and a
/// contended one on the second; exhausting the budget means the row is not
/// converging, and the caller is better served by an unconditional removal than
/// by spinning against it.
const AVAIL_CAS_ATTEMPTS: usize = 8;

/// An availability row is `version || nonce (16 bytes) || etag (UTF-8)`. An
/// empty etag is a **tombstone** — the address has no current validator.
///
/// `nonce` is fresh random on every write of the row and carries no ordering;
/// its only job is to make the row's bytes **non-reusable**, so that "the row
/// holds exactly the bytes I saw when my read began" is a sound proof that no
/// mutation touched this address in between. Every mutation through this stack
/// rewrites the row ([`clear_latest_impl`] to a tombstone, a write-through's
/// [`publish_mutation_impl`] to the new validator), and a read-path fill
/// publishes only by [`Cache::compare_and_put`] against the exact bytes it
/// snapshotted at read start. That makes the fence total over the ways the row
/// can move underneath a slow read:
///
/// - a mutation rewrites it — the bytes differ, the swap refuses;
/// - size-pressure eviction or a subtree `remove_prefix` deletes it — the row
///   is absent where the snapshot was present, the swap refuses;
/// - delete/re-upload/delete cycles restore a row of the *same shape* — the
///   nonce differs, the swap refuses. A monotonic epoch would not survive this
///   last one, because deleting the row resets any per-address counter.
///
/// A counter would need durable, non-evictable storage to be non-reusable; a
/// random nonce is non-reusable with no persisted state at all.
///
/// Note: a legitimately-empty backend etag (`""`) encodes identically to a
/// tombstone, so `last_known_validator` reports no validator for it. This is
/// harmless — an empty etag is not a usable validator (the strict
/// validator-keyed path can't lookup under it either), so treating it as
/// "no fallback" is the safe outcome, not a lost cache entry.
fn encode_avail(etag: &str) -> Vec<u8> {
    let mut value = Vec::with_capacity(AVAIL_HEADER_LEN + etag.len());
    value.push(AVAIL_VERSION);
    let mut nonce = [0u8; AVAIL_NONCE_LEN];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    value.extend_from_slice(&nonce);
    value.extend_from_slice(etag.as_bytes());
    value
}

/// The validator an availability row names. A row of an unrecognized version, a
/// short row, or a tombstone yields `None`.
fn parse_avail(bytes: &[u8]) -> Option<String> {
    if bytes.len() < AVAIL_HEADER_LEN || bytes[0] != AVAIL_VERSION {
        return None;
    }
    let etag = &bytes[AVAIL_HEADER_LEN..];
    if etag.is_empty() {
        return None;
    }
    String::from_utf8(etag.to_vec()).ok()
}

/// The availability row's raw bytes and the validator they name.
///
/// Clears an address's availability row on drop unless disarmed.
///
/// The invariant is global — the availability row must never name a validator
/// the backend has superseded — but every enforcement point is local, and the
/// idiomatic Rust for a fallible step (`?`) is an early return. The language's
/// easy path is therefore exactly the defect: a step that returns early
/// silently skips the invalidation the success path performs. Arming a guard
/// makes the invalidation happen on `?`, on `return`, on `break` and on
/// panic-unwind, so the omission stops being expressible.
///
/// Removal is the safe direction in every case: an absent row names no
/// validator and matches no snapshot, so a spurious clear costs a fallback
/// entry and can never serve superseded bytes.
struct AvailabilityClear {
    cache: Arc<Cache>,
    key: String,
    /// The address these diagnostics name, redacted. The index key embeds the
    /// raw URL, and a URL can carry userinfo or signed-URL credentials, so the
    /// key itself must not reach a log line -- see [`redact_url`].
    address: String,
    /// The content row the row being cleared was the only pointer to, if the
    /// arming caller knew of one.
    ///
    /// Clearing the availability row and stopping there strands that content
    /// row: it is keyed by a validator no future read will look up, so the
    /// strict path can never reach it, and a cache with no size budget never
    /// evicts it. Every clear therefore reclaims the body its own clear made
    /// unreachable, on the abandoned paths as much as the explicit ones.
    superseded_content_key: Option<String>,
    armed: bool,
}

impl AvailabilityClear {
    fn new(cache: &Arc<Cache>, partition: &str, address: &Url) -> Self {
        Self {
            cache: Arc::clone(cache),
            key: availability_index_key(partition, address),
            address: redact_url(address),
            superseded_content_key: None,
            armed: true,
        }
    }
}

/// Reclaims a content row if a blocking clear unwinds before doing so itself.
///
/// [`clear_latest_impl`] tombstones the availability row and then reclaims the
/// body that row was the only pointer to. Those two run in one detached
/// blocking task: cancelling the async caller does not drop this guard or skip
/// the reclaim after a landed tombstone.
///
/// The guard remains for panic-unwind inside that task. The two interrupted
/// states are not symmetric, and it picks the recoverable one: an absent body
/// under a row that still names it costs the next read a miss and a re-fetch,
/// where a live body under no row is unreachable forever.
///
/// Firing spuriously is therefore cheap by construction -- if the swap never
/// landed, this deletes a body the row still names, which is that same
/// recoverable miss.
struct ContentReclaim {
    cache: Arc<Cache>,
    key: Option<String>,
    /// The address the reclaimed body belongs to, REDACTED, for the drop
    /// diagnostic.
    ///
    /// The content key is `{partition}\0{address}\0{etag}` and embeds the raw
    /// `Url`, so logging the key would publish userinfo and signed-URL
    /// credentials -- the same reason `AvailabilityClear` carries a redacted
    /// address rather than its own key.
    address: String,
}

impl ContentReclaim {
    fn arm(cache: &Arc<Cache>, address: &Url, key: Option<String>) -> Self {
        Self {
            cache: Arc::clone(cache),
            key,
            address: redact_url(address),
        }
    }

    /// Reclaim now, on the path that owns the decision, and stand down.
    fn reclaim(&mut self) {
        if let Some(key) = self.key.take() {
            let _ = self.cache.remove_index(&key);
        }
    }

    /// The swap did not land, so the row still names this body and the caller
    /// is about to try again with whatever it names next.
    fn stand_down(&mut self) {
        self.key = None;
    }
}

impl Drop for ContentReclaim {
    fn drop(&mut self) {
        // Synchronous and infallible-by-swallowing, for the reasons spelled out
        // on `AvailabilityClear::drop`: this can run during unwind, so it must
        // not panic, and handing it to a detached task would trade a bounded
        // stall for a reclaim that may silently never run.
        //
        // Logged for the same reason that drop logs its own removals, and with
        // more cause: a failure here -- busy-timeout exhaustion under
        // cross-process contention, an I/O fault on the blob unlink -- strands
        // the body permanently, which is the exact outcome this guard exists to
        // prevent. Swallowing it silently would make the one case worth knowing
        // about indistinguishable from success.
        if let Some(key) = self.key.take()
            && let Err(error) = self.cache.remove_index(&key)
        {
            // The redacted address, never `key`: the key embeds the raw URL.
            tracing::debug!(
                address = %self.address,
                error.message = %error.message(),
                "an interrupted clear could not reclaim the body it made unreachable",
            );
        }
    }
}

impl Drop for AvailabilityClear {
    /// # Why this does blocking I/O, deliberately
    ///
    /// `remove_index` takes a blocking mutex, runs a handful of SQLite
    /// statements and may unlink a file, and this runs on a runtime worker —
    /// including when an async caller is cancelled and a read stream tee is
    /// dropped mid-flight. That is a considered trade, not an oversight:
    ///
    /// - **It is synchronous because it must survive unwind.** `Drop` can run
    ///   while a panic unwinds. Handing the work to `spawn_blocking` would make
    ///   it a detached task whose failure nobody observes, trading a bounded
    ///   stall for an invalidation that may silently never run — which is the
    ///   defect class this guard exists to eliminate. An invalidation that
    ///   might not happen is worth less than one that blocks.
    /// - **The 5s figure is a ceiling, not a cost.** It is the `busy_timeout`
    ///   reached only under cross-process contention on one state root.
    ///   Uncontended, this is a mutex acquisition and a few statements.
    /// - **It only fires on the abandoned path.** A drained tee and a completed
    ///   fill both disarm first, so no success path pays anything.
    ///
    /// If measurement ever shows this mattering, the answer is a bounded async
    /// cleanup queue whose failures are observable — not fire-and-forget.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Every failure here is swallowed. `Drop` can run during unwind, where
        // a panic aborts the process, so this must not be able to panic: the
        // whole `remove_index` call tree returns `Result` and unwraps no lock.
        // Keep it that way. Losing a clear costs a fallback entry; aborting
        // the process does not compare.
        if let Err(error) = self.cache.remove_index(&self.key) {
            tracing::debug!(
                address = self.address,
                error = %error,
                "byte cache could not clear an availability row on an unwound path"
            );
        }
        // Reclaim the body that row was the only pointer to. Best-effort for
        // the same reason the clear is: losing it costs disk, and a `Drop` that
        // can panic during unwind costs the process.
        if let Some(content) = &self.superseded_content_key
            && let Err(error) = self.cache.remove_index(content)
        {
            tracing::debug!(
                address = self.address,
                error = %error,
                "byte cache could not reclaim a superseded body on an unwound path"
            );
        }
    }
}

/// Invalidates `address` unless the mutation path reaches its own explicit
/// publish or clear. **Armed BEFORE the backend op.**
///
/// A failed backend mutation is ambiguous: a timeout can arrive after the
/// server has already committed, and that case is indistinguishable from a
/// clean refusal without per-backend knowledge this layer does not have. So a
/// failed mutation invalidates rather than assuming nothing happened. The
/// price is one lost fallback entry per failed mutation; the alternative is
/// serving a body the backend has already replaced. Do not "optimize" this by
/// disarming on error codes that look clean — that is the exact case the
/// ambiguity argument covers.
///
/// # Disarming without publishing or clearing
///
/// There is a third case, and it is deliberate: a step that returns
/// successfully having changed nothing at the backend. Such a step must disarm
/// without publishing and without clearing, because the row's existing
/// contents are still **accurate** — clearing would discard a correct fallback
/// entry, and publishing would name a validator that does not exist yet.
///
/// The only site is [`WriteStep::Redirects`] from `continue_write`. A
/// mid-flight redirect batch means the transfer is still in progress: its
/// parts have been uploaded but the object is not visible at the backend, so
/// the pre-write validator is still the current one and the body it names is
/// still worth keeping. `arm` has already cleared the availability row by this
/// point, so this exit restores it (see [`MutationGuard::disarm_unchanged`]):
/// preserving the body without the row that names it would keep bytes nothing
/// can reach.
///
/// This rests on a contract, not on luck — see [`WriteStep::Redirects`]'s
/// documentation. A backend that made partial content observable at a redirect
/// step would break it, and that site would have to clear rather than disarm.
/// Note that no shipping backend exercises this today: S3 emits all parts in
/// one batch, so its `continue_write` returns `Done`, and Azure commits and
/// returns `Done` too. The only producers are the test plugin and probes, so
/// the discipline is contract-enforced rather than production-exercised.
struct MutationGuard {
    clear: AvailabilityClear,
    /// The validator this mutation supersedes, and the content row holding its
    /// body — read out of the availability row *before* the write-ahead clear,
    /// because that row is the only record of either.
    ///
    /// Nothing else can recover it. The content row is keyed by an etag no
    /// future read will look up, so it is invisible to the strict path, and an
    /// unbudgeted cache never evicts it. Reclaiming it is therefore this
    /// guard's job and only this guard's job.
    superseded: Option<(String, String)>,
    /// The availability row's raw bytes as they stood before the write-ahead
    /// clear, for the one exit that must put them back — see
    /// [`Self::disarm_unchanged`].
    preserved: Option<Vec<u8>>,
}

impl MutationGuard {
    /// Arm the guard **and clear the row immediately** — write-ahead
    /// invalidation.
    ///
    /// Clearing after the backend call, however promptly, leaves an interval in
    /// which the object has changed and the index has not. Nothing in process
    /// closes that interval: a SIGKILL, an OOM kill or a container eviction
    /// inside it leaves the row naming a superseded validator with that
    /// validator's body still cached, and nothing repairs it until the address
    /// is next written, watched, or evicted. On a cache with no size budget
    /// that is indefinite.
    ///
    /// Clearing first removes the interval rather than shrinking it. From this
    /// point the row either names nothing or names something the backend
    /// actually has, at every instant, including instants the process does not
    /// survive.
    ///
    /// The cost is availability, never staleness: the address has no fallback
    /// from here until the operation publishes one, so a backing-store outage
    /// overlapping a long streamed write finds nothing to serve. That is the
    /// same direction this guard already fails in, and the alternative — a
    /// durable in-flight journal replayed at startup — is a new on-disk
    /// structure with its own crash semantics.
    async fn arm(cache: &Arc<Cache>, partition: &str, address: &Url) -> Self {
        let mut cleared = AvailabilityClear::new(cache, partition, address);
        // Read before clearing. The clear below destroys the only record of
        // which validator the cached body was filled under, and the reclaim
        // needs it.
        let (preserved, superseded) = match read_avail(cache, partition, address).await {
            Ok((raw, etag)) => (
                raw,
                etag.map(|etag| {
                    let key = content_cache_key(partition, address, &etag);
                    (etag, key)
                }),
            ),
            Err(_) => (None, None),
        };
        // Every exit that neither publishes nor explicitly clears drops this
        // guard, and its clear removes the only pointer to the superseded body.
        // Hand the clear that body so it reclaims rather than strands it. The
        // two explicit exits both take the field back: `disarm` reclaims
        // conditionally (an identical rewrite republishes the same validator),
        // and `disarm_unchanged` keeps the body because nothing superseded it.
        cleared.superseded_content_key = superseded.as_ref().map(|(_, key)| key.clone());
        // A failure here does NOT abort the mutation, and that is deliberate.
        //
        // If it did, an unwritable cache index would refuse the caller's
        // writes: a cache would be blocking the data path over its own
        // bookkeeping, which is the wrong trade in every direction. Nor does it
        // fail the mutation afterwards — by then the backend has committed, and
        // reporting failure would have callers retry a write that already
        // landed.
        //
        // What it costs is real and worth naming: the old row survives, the
        // backend moves, and the later clear and this guard's `Drop` are likely
        // to fail for the same reason — so the row can go on answering the
        // fallback with a superseded validator. That needs no crash. It does
        // need `lost_backing_fallback` enabled AND a later backing-store outage
        // AND a cache index that cannot be written, all at once, each of which
        // is already a degraded state. Hence `warn`: this is the signal an
        // operator needs, not a `debug` line.
        if let Err(error) = remove_index_off_runtime(cache, &cleared.key).await {
            tracing::warn!(
                address = cleared.address,
                error = %error,
                "byte cache could not clear an availability row ahead of a mutation; \
                 the availability fallback for this address may now name a superseded \
                 validator"
            );
        }
        Self {
            clear: cleared,
            superseded,
            preserved,
        }
    }

    /// The mutation completed. Reclaim the body of the validator it superseded,
    /// unless that is the validator now published — a rewrite of identical
    /// content republishes the same etag, and reclaiming it would evict the
    /// body this operation just stored.
    ///
    /// # Why this reclaim stays inline
    ///
    /// Every caller is an `async fn`, so this is a runtime worker parked on
    /// SQLite for as long as the removal takes — the cost profile
    /// [`remove_index_off_runtime`] exists to move, and this is one of the
    /// content reclaims its test rules out. Both orderings of an awaited
    /// version lose something a bounded stall does not. Reclaiming first: this
    /// method consumes the guard, so an await inside it is a point at which the
    /// caller's future can be dropped with the guard still armed, and the
    /// `Drop` below would clear the availability row the mutation just
    /// published. Disarming first: a cancelled reclaim strands the superseded
    /// body, which is keyed by a validator no read looks up and which an
    /// unbudgeted cache never evicts, so nothing else can ever reclaim it.
    fn disarm(self, now_published: Option<&str>) {
        if let Some((etag, content_key)) = &self.superseded
            && Some(etag.as_str()) != now_published
        {
            let _ = self.clear.cache.remove_index(content_key);
        }
        let mut guard = self;
        guard.clear.armed = false;
        // The reclaim above is the authoritative one, and it is conditional;
        // the clear's copy is the unconditional fallback for exits that never
        // get here. Take it back so a later drop cannot evict the body this
        // operation just republished.
        guard.clear.superseded_content_key = None;
    }

    /// The operation returned without changing anything at the backend, so the
    /// pre-write state is still current: **restore the row the write-ahead
    /// clear removed**, and keep the body it names.
    ///
    /// Restoring is what makes this exit whole rather than merely quiet. The
    /// row is the address's only last-known-validator fallback AND the only
    /// pointer to the cached body, so leaving it absent both discards a
    /// fallback that is still accurate and strands that body — the next guard
    /// reads an absent row, captures no superseded validator, and reclaims
    /// nothing.
    ///
    /// It is safe for exactly the reason this exit exists: the step reported
    /// that nothing landed at the backend, so the validator being restored is
    /// still the one the backend holds, and the write-ahead invariant ("the row
    /// names nothing, or something the backend actually has") continues to
    /// hold at every instant.
    ///
    /// The restore is a compare-and-swap against the absent row `arm` left. A
    /// refusal means something else wrote the row in between — a concurrent
    /// mutation or fill — and that state is newer than this one, so it stands.
    /// See the disarm-without-publishing discipline documented on this type.
    async fn disarm_unchanged(mut self) {
        self.clear.armed = false;
        // The body stays, so the clear's unconditional reclaim must not fire
        // even if this frame unwinds below.
        self.clear.superseded_content_key = None;
        let Some(preserved) = self.preserved.take() else {
            return;
        };
        let key = self.clear.key.clone();
        match compare_and_put_off_runtime(&self.clear.cache, &key, None, preserved).await {
            Ok(true) => {}
            // Best-effort in both remaining directions. A refusal is a newer
            // row this must not overwrite; an error leaves the row absent,
            // which costs the fallback and never serves stale bytes.
            Ok(false) => tracing::debug!(
                address = self.clear.address,
                "byte cache did not restore an availability row after a mid-flight \
                 redirect: the row moved during the step"
            ),
            Err(error) => tracing::debug!(
                address = self.clear.address,
                error = %error,
                "byte cache could not restore an availability row after a mid-flight redirect"
            ),
        }
    }
}

/// `Cache::compare_and_put` on the blocking pool.
///
/// It stages a file, fsyncs it and commits a transaction, all synchronously, so
/// calling it straight from an async fn parks a runtime worker on an fsync for
/// the duration. The fourth compare-and-swap site, [`snapshot_avail`]'s seed,
/// already hops for the same reason.
///
/// [`AvailabilityClear::drop`] is not one of these: it calls `remove_index`,
/// not this, and must stay synchronous regardless because a detached task's
/// failure during unwind is unobservable — see the reasoning there. The
/// `remove_index` calls that have the same cost profile as this hop through
/// [`remove_index_off_runtime`], which names the sites that deliberately do
/// not.
async fn compare_and_put_off_runtime(
    cache: &Arc<Cache>,
    key: &str,
    expected: Option<Vec<u8>>,
    new: Vec<u8>,
) -> Result<bool> {
    let cache = Arc::clone(cache);
    let key = key.to_string();
    tokio::task::spawn_blocking(move || {
        cache.compare_and_put(&key, expected.as_deref(), Some(&new))
    })
    .await
    .map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("cache compare-and-put task panicked: {error}"),
        )
    })?
}

/// `Cache::remove_index` on the blocking pool.
///
/// It takes the connection mutex, runs a handful of SQLite statements and may
/// unlink a blob, all synchronously, so calling it straight from an async fn
/// parks a runtime worker for as long as the index write takes — bounded by the
/// `busy_timeout` ceiling under cross-process contention on one state root.
///
/// # The test a removal must pass before it hops
///
/// Calling this instead of `remove_index` is not a free swap: it introduces an
/// await, and an await does two things at once. It is a point at which the
/// caller's whole future can be dropped, so nothing after it in the operation
/// is guaranteed to run. And dropping it detaches the `spawn_blocking` task,
/// which removes `key` anyway, unconditionally, whenever a blocking thread next
/// frees up — possibly after some other operation has published that same key.
///
/// So a site may hop only if **a cancelled removal lands in the same state a
/// completed one does**, which needs both halves:
///
/// - **Skipping it costs nothing.** An armed [`AvailabilityClear`] is live
///   across the await and its `Drop` performs the same removal, so a cancelled
///   caller repeats the work rather than abandoning it.
/// - **Doing it late costs nothing.** Removing an availability row costs one
///   fallback entry and never strands bytes: the body a row names is still
///   reachable on the strict path while the backend reports that validator,
///   which is exactly the case for the newer row a late removal could hit.
///
/// The four reclaims of **content** rows fail both halves, and that is why each
/// of them calls `remove_index` inline. A content reclaim runs after the only
/// row naming that body has been cleared, tombstoned or superseded, so no guard
/// holds the same key as a backstop, no read looks up a validator the backend
/// does not report, and a cache with no size budget never evicts: skipping it
/// strands the body permanently, and doing it late can delete a body some other
/// operation has since republished under the same validator. The four are
/// [`MutationGuard::disarm`], [`record_latest_guarded_impl`]'s prune of the
/// validator a fill supersedes, [`clear_latest_impl`]'s prune of the validator
/// a clear tombstones, and [`finalize_committed_tee_impl`]'s discard of a tee
/// body a concurrent mutation invalidated.
///
/// [`record_latest_guarded_impl`]'s prune travels in the same blocking task as
/// its publish and owns the caller's [`ReadGuard`] there. That keeps
/// cancellation from inserting an async drop between the landed swap, the
/// content reclaim and the disarm.
///
/// Two further places keep an inline `remove_index` for reasons of their own:
///
/// - [`AvailabilityClear::drop`] must survive unwind, and a detached task's
///   failure there is unobservable.
/// - [`clear_watched_object`]'s only caller is the synchronous change-event
///   hook of a [`GapSweepStream`], which cannot await and whose logged failure
///   would be lost to a detached task.
async fn remove_index_off_runtime(cache: &Arc<Cache>, key: &str) -> Result<()> {
    let cache = Arc::clone(cache);
    let key = key.to_string();
    tokio::task::spawn_blocking(move || cache.remove_index(&key))
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("cache index-removal task panicked: {error}"),
            )
        })?
}

/// Remove an availability row and reclaim the content row named by the exact
/// bytes that were deleted.
///
/// [`Cache::remove_index_returning`] holds an IMMEDIATE transaction across the
/// read and delete, so the parsed validator cannot be from an earlier row that
/// a concurrent writer has since replaced. The content reclaim is synchronous
/// in the same blocking task: cancellation may detach the task, but cannot
/// separate the row removal from the cleanup it determines.
fn retry_transient_once<T>(mut operation: impl FnMut() -> Result<T>) -> Result<T> {
    let first = operation();
    if matches!(&first, Err(error) if error.code() == ErrorCode::Transient) {
        operation()
    } else {
        first
    }
}

fn remove_availability_and_reclaim(
    cache: &Cache,
    key: &str,
    partition: &str,
    address: &Url,
) -> Result<()> {
    let removed = match retry_transient_once(|| cache.remove_index_returning(key)) {
        Ok(removed) => removed,
        Err(error) => {
            // Invalidating the row outranks reporting its bytes. A transient
            // database error received one fresh attempt above; if exact
            // inspection still fails, retain the fail-safe behavior and
            // remove the index entry without guessing which body it named.
            cache.remove_index(key)?;
            tracing::debug!(
                address = %redact_url(address),
                error = %error,
                "byte cache removed an availability row it could not inspect without \
                 reclaiming the body it named"
            );
            return Ok(());
        }
    };
    if let Some(previous) = removed
        .as_ref()
        .and_then(|object| parse_avail(&object.bytes))
        && let Err(error) = cache.remove_index(&content_cache_key(partition, address, &previous))
    {
        tracing::debug!(
            address = %redact_url(address),
            error = %error,
            "byte cache could not reclaim the body named by a removed availability row"
        );
    }
    Ok(())
}

async fn remove_availability_and_reclaim_off_runtime(
    cache: &Arc<Cache>,
    key: &str,
    partition: &str,
    address: &Url,
) -> Result<()> {
    let cache = Arc::clone(cache);
    let key = key.to_string();
    let partition = partition.to_string();
    let address = address.clone();
    tokio::task::spawn_blocking(move || {
        remove_availability_and_reclaim(&cache, &key, &partition, &address)
    })
    .await
    .map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("cache availability-removal task panicked: {error}"),
        )
    })?
}

/// Compare-and-tombstone on the blocking pool, with the body reclaim owned by
/// the same detached task.
async fn clear_compare_off_runtime(
    cache: &Arc<Cache>,
    key: &str,
    expected: Option<Vec<u8>>,
    new: Vec<u8>,
    partition: &str,
    address: &Url,
    previous_content_key: Option<String>,
) -> Result<bool> {
    let cache = Arc::clone(cache);
    let key = key.to_string();
    let partition = partition.to_string();
    let address = address.clone();
    tokio::task::spawn_blocking(move || {
        let mut reclaim = ContentReclaim::arm(&cache, &address, previous_content_key);
        match cache.compare_and_put(&key, expected.as_deref(), Some(&new)) {
            Ok(true) => {
                reclaim.reclaim();
                Ok(true)
            }
            Ok(false) => {
                reclaim.stand_down();
                Ok(false)
            }
            Err(compare_error) => {
                // The failure is ambiguous: the tombstone may have committed.
                // Remove the row that exists now and reclaim the body it
                // actually named. Reclaim the pre-swap validator as well; if
                // the tombstone did land, the removed row names no body.
                tracing::debug!(
                    address = %redact_url(&address),
                    error = %compare_error,
                    "byte cache compare-and-tombstone failed; settling invalidation by removal"
                );
                let cleanup = remove_availability_and_reclaim(&cache, &key, &partition, &address);
                reclaim.reclaim();
                cleanup?;
                Ok(true)
            }
        }
    })
    .await
    .map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("cache compare-and-clear task panicked: {error}"),
        )
    })?
}

/// The object info a read result reports, whichever shape it took. A redirect
/// carries none — the follower below this layer resolves it into one of the
/// other shapes before the cache sees a validator.
fn result_info(result: &ReadResult) -> Option<&ObjectInfo> {
    match result {
        ReadResult::Bytes { info, .. } => Some(info),
        ReadResult::Stream { info, .. } => Some(info),
        ReadResult::LocalDelegate(local) => Some(&local.info),
        ReadResult::Redirect(_) => None,
    }
}

/// Whether a publish attempt left the availability row in a state its caller
/// may stop guarding.
///
/// A [`ReadGuard`] may only disarm on [`Settled`](Self::Settled). The
/// distinction is not "did the publish succeed": both a published validator
/// and a removed row are safe, because an absent row names nothing. What is
/// unsafe is the row still naming a validator the fill superseded, which is
/// what happens when the publish could neither be attempted nor undone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
enum PublishOutcome {
    /// The row names this fill's validator, or names nothing at all.
    Settled,
    /// The row may still name a validator this fill superseded. The caller
    /// must keep its guard armed so `Drop` tries the removal again.
    Unsettled,
}

/// A validator the backend has already returned from a completed read.
///
/// This exists so [`ReadGuard`] cannot be armed too early. Before `inner.read`
/// returns there is no [`ObjectInfo`], so there is no `ProvenValidator`, so
/// there is no `ReadGuard` — the discipline is a type error rather than a
/// comment someone has to remember.
struct ProvenValidator(String);

impl ProvenValidator {
    /// The validator a completed read reported, if it reported a usable one.
    ///
    /// An empty etag is rejected. The availability encoding already treats it
    /// as a tombstone, so it can never be published there; the strict path has
    /// no such filter and would key a content row on the empty string, which
    /// never changes between versions -- an out-of-band update would then be
    /// served from the first fill indefinitely. A validator that cannot
    /// distinguish two versions is not a validator.
    fn proved(info: &ObjectInfo) -> Option<Self> {
        info.etag.clone().filter(|etag| !etag.is_empty()).map(Self)
    }

    fn etag(&self) -> &str {
        &self.0
    }
}

/// Invalidates `address` unless the fill reaches its publish. **Armed only
/// AFTER the backend read has returned successfully**, which
/// [`ProvenValidator`] enforces.
///
/// The arming point is not a style choice. A read never mutates, so a failed
/// read must not invalidate — and arming across `inner.read` would mean one
/// failed read destroys the very fallback that read exists to fall back on,
/// which is the feature inverting itself. Once the read has returned a
/// validator, though, that validator is proof the row's current contents are
/// superseded, and every exit before the publish must clear.
struct ReadGuard(AvailabilityClear);

impl ReadGuard {
    /// `snapshot` is the availability row as it stood at the read's start —
    /// the same bytes the publish is fenced on. The validator it names is the
    /// one this read has proved superseded, so the body under it is
    /// unreachable the moment this guard's clear fires: the strict path keys on
    /// validators a backend still reports, and an unbudgeted cache never
    /// evicts. Reclaiming it here is the counterpart of the prune
    /// [`record_latest_guarded_impl`] does on the path that publishes instead.
    fn arm(
        cache: &Arc<Cache>,
        partition: &str,
        address: &Url,
        proof: &ProvenValidator,
        snapshot: Option<&[u8]>,
    ) -> Self {
        let mut clear = AvailabilityClear::new(cache, partition, address);
        clear.superseded_content_key = snapshot
            .and_then(parse_avail)
            // A read that re-proves the validator the row already names has
            // superseded nothing; reclaiming there would evict the body this
            // very read is about to serve from.
            .filter(|previous| previous != proof.etag())
            .map(|previous| content_cache_key(partition, address, &previous));
        Self(clear)
    }
}

/// A read failure propagates. The read-modify-write loops below exit only when
/// this read and the swap agree on the row's current value, so collapsing an
/// unreadable row to "absent" would make their exit condition unreachable
/// whenever the row is present but its blob cannot be read.
async fn read_avail(
    cache: &Arc<Cache>,
    partition: &str,
    address: &Url,
) -> Result<(Option<Vec<u8>>, Option<String>)> {
    let raw = cache
        .get_entry_async(&availability_index_key(partition, address))
        .await?
        .map(|object| object.bytes);
    let etag = raw.as_deref().and_then(parse_avail);
    Ok((raw, etag))
}

/// Snapshot the address's availability row at the START of a cacheable read, so
/// a later fill can prove no mutation landed during the read. Threaded to
/// [`ByteCacheWrapper::record_latest`], which publishes only against these exact
/// bytes.
///
/// An absent row is **seeded** with a tombstone first. An absent row is the one
/// state that carries no information: a snapshot of "absent" cannot tell a
/// never-mutated address from one whose tombstone was evicted mid-read, which
/// is precisely how a superseded validator gets republished. Seeding costs one
/// small write, on the cold path only (a row that exists is snapshotted as-is),
/// where it is dwarfed by the backend round-trip the read is about to make.
///
/// `None` means the row could neither be read nor seeded — a read-only cache,
/// or an I/O fault. The fill then has nothing to prove itself against and
/// [`record_latest_guarded_impl`] skips the availability index. Whether the
/// read's content fill lands is a separate question the cache answers for
/// itself: a read-only cache refuses that too, an I/O fault may or may not.
async fn snapshot_avail(cache: &Arc<Cache>, partition: &str, address: &Url) -> Option<Vec<u8>> {
    let key = availability_index_key(partition, address);
    for _ in 0..AVAIL_CAS_ATTEMPTS {
        let (raw, _) = read_avail(cache, partition, address).await.ok()?;
        if raw.is_some() {
            return raw;
        }
        // `compare_and_put` stages, fsyncs and commits synchronously. Run it
        // on the blocking pool, as `get_entry_async` above already does, so a
        // cold read does not park a runtime worker on an fsync.
        let seed = encode_avail("");
        let seed_cache = Arc::clone(cache);
        let seed_key = key.clone();
        let seed_bytes = seed.clone();
        let seeded = tokio::task::spawn_blocking(move || {
            seed_cache.compare_and_put(&seed_key, None, Some(&seed_bytes))
        })
        .await
        .ok()?
        .ok()?;
        if seeded {
            return Some(seed);
        }
    }
    None
}

/// A registered address's mutation-generation slot. Present in the
/// [`GenerationMap`] only while `refcount` in-flight tees hold it.
struct GenerationEntry {
    /// Number of live [`TeeRegistration`]s for the address; the entry is
    /// removed when this reaches zero.
    refcount: usize,
    /// Bump counter — advanced by a mutation while the entry is registered,
    /// compared against a tee's start snapshot at commit.
    generation: u64,
}

/// Address string → mutation-generation slot for addresses with an in-flight
/// stream tee. Bounded by concurrent tees, not lifetime mutation cardinality.
type GenerationMap = HashMap<String, GenerationEntry>;

/// RAII registration of an in-flight stream tee against an address's mutation
/// generation. While at least one registration is live for an address the map
/// holds its [`GenerationEntry`], so a mutation through this stack can bump the
/// generation and invalidate the tee's late commit; dropping the last
/// registration removes the entry, keeping the map bounded by in-flight tees.
struct TeeRegistration {
    generations: Arc<Mutex<GenerationMap>>,
    address: String,
}

impl TeeRegistration {
    /// Register a tee for `address`, returning the handle and the generation
    /// snapshot to re-check at commit. Ref-counts an existing entry so
    /// overlapping tees on the same address share one slot.
    fn register(generations: Arc<Mutex<GenerationMap>>, address: &Url) -> (Self, u64) {
        let key = address.as_str().to_string();
        let start = generations
            .lock()
            .map(|mut map| {
                let entry = map.entry(key.clone()).or_insert(GenerationEntry {
                    refcount: 0,
                    generation: 0,
                });
                entry.refcount += 1;
                entry.generation
            })
            .unwrap_or(0);
        (
            Self {
                generations,
                address: key,
            },
            start,
        )
    }

    /// The address's current mutation generation, for the commit-time check.
    fn current(&self) -> u64 {
        self.generations
            .lock()
            .ok()
            .and_then(|map| map.get(&self.address).map(|entry| entry.generation))
            .unwrap_or(0)
    }
}

impl Drop for TeeRegistration {
    fn drop(&mut self) {
        if let Ok(mut map) = self.generations.lock()
            && let Some(entry) = map.get_mut(&self.address)
        {
            entry.refcount = entry.refcount.saturating_sub(1);
            if entry.refcount == 0 {
                map.remove(&self.address);
            }
        }
    }
}

/// Advance a single registered address's mutation generation; a no-op when no
/// tee is registered for it (so an untracked mutation neither bumps nor leaks).
fn bump_generation_key(generations: &Mutex<GenerationMap>, address: &str) {
    if let Ok(mut map) = generations.lock()
        && let Some(entry) = map.get_mut(address)
    {
        entry.generation += 1;
    }
}

/// Advance the mutation generation of every registered address whose key falls
/// under the address-string prefix `dir`, invalidating in-flight tees under a
/// subtree-shaped mutation. Bounded by the registered (in-flight) tees.
fn bump_generations_under_prefix(generations: &Mutex<GenerationMap>, dir: &str) {
    if let Ok(mut map) = generations.lock() {
        for (address, entry) in map.iter_mut() {
            if address.starts_with(dir) {
                entry.generation += 1;
            }
        }
    }
}

/// Invalidate a single watched object: **fence in-flight reads first, then
/// drop the row.**
///
/// The ordering is the point, and it is the same one `clear_subtree_impl`
/// needs. The bump is in-memory and instant; the removal is a SQLite statement
/// that can wait out the busy timeout and unlink a blob. Removing first leaves
/// a window in which a read tee draining this address commits, finds its
/// generation unchanged AND the row unchanged, and republishes the validator
/// this event is invalidating — so a deleted object answers the fallback as
/// current. Bumping first closes the tee's check from the first instant,
/// whatever the removal then costs or whether it succeeds at all.
///
/// The removal is synchronous because the only caller is the change-event hook
/// of a [`GapSweepStream`], a `Fn(&ChangeEvent)` with no await point. Handing
/// it to a detached blocking task is the one alternative that fits that
/// signature, and it would discard the `Err` the caller logs.
fn clear_watched_object(
    cache: &Cache,
    partition: &str,
    generations: &Mutex<GenerationMap>,
    address: &Url,
) -> Result<()> {
    bump_generation_key(generations, address.as_str());
    remove_availability_and_reclaim(
        cache,
        &availability_index_key(partition, address),
        partition,
        address,
    )
}

/// Remove every availability-index and content row under `address`'s subtree,
/// and bump the mutation generation of any in-flight tee registered under it so
/// the tee cannot re-publish a cleared row. Shared by the directory-mutation
/// overrides ([`ByteCacheWrapper::clear_subtree`]) and `watch_directory`'s
/// Deleted/Lapsed invalidation. The appended `/` keeps a sibling prefix (`dir`
/// vs `dir2`) out of the sweep; the `\u{2}` / `\0` separators keep the
/// availability-index and content namespaces disjoint.
///
/// Removing an availability row rather than tombstoning it is safe for the
/// publication fence: a read that snapshotted the row finds it absent and its
/// swap refuses, and a read that arrives afterwards seeds a fresh row whose
/// nonce matches no earlier snapshot.
fn clear_subtree_impl(
    cache: &Cache,
    partition: &str,
    generations: &Mutex<GenerationMap>,
    address: &Url,
) -> Result<()> {
    let mut dir = address.as_str().to_string();
    if !dir.ends_with('/') {
        dir.push('/');
    }
    // Fence in-flight reads FIRST. This is in-memory and infallible, and it is
    // the only step that reaches a read tee already streaming a child: without
    // it the tee's generation check passes, its read-start snapshot still
    // matches the child's untouched row, and its commit republishes the
    // validator of an object this call is deleting. Bumping before the sweeps
    // is also strictly more conservative than bumping after.
    bump_generations_under_prefix(generations, &dir);
    // Both sweeps run even if the first fails; the caller's mutation has
    // already committed at the backend, so returning between them would leave
    // one of the two namespaces still naming pre-delete state. The first error
    // is reported after both have been attempted.
    let availability = cache.remove_prefix(&format!("{partition}\u{2}{dir}"));
    let content = cache.remove_prefix(&format!("{partition}\0{dir}"));
    availability.and(content)
}

#[cfg(test)]
async fn record_latest_impl(
    cache: &Arc<Cache>,
    partition: &str,
    address: &Url,
    snapshot: Option<Vec<u8>>,
    etag: &str,
) -> PublishOutcome {
    record_latest_guarded_impl(cache, partition, address, snapshot, etag, None).await
}

/// Record `etag` as the address's newest-fill validator, best-effort pruning
/// the superseded validator's content row. Shared by
/// [`ByteCacheWrapper::record_latest`] and the stream tee's commit. Both are
/// best-effort: the availability index answers only while the backend cannot,
/// so failing to record it must not fail a read that already holds valid
/// bytes. The publish is fenced on `snapshot`; see
/// [`ByteCacheWrapper::record_latest`].
///
/// The blocking task owns `guard` while the compare-and-put is in flight. A
/// caller cancelled after the guarded write commits therefore detaches a task
/// that still owns both halves of the transition: it prunes the superseded
/// body and disarms before releasing the guard. If cancellation wins before
/// the write, dropping the still-armed guard clears the old row instead.
async fn record_latest_guarded_impl(
    cache: &Arc<Cache>,
    partition: &str,
    address: &Url,
    snapshot: Option<Vec<u8>>,
    etag: &str,
    guard: Option<ReadGuard>,
) -> PublishOutcome {
    // No snapshot: the row could neither be read nor seeded at read start, so
    // this fill has nothing to prove itself against and must not publish. That
    // leaves the row naming whatever it named before, which this read has just
    // superseded -- unsettled, so the caller's guard clears it. The content row
    // still lands and the strict validator-keyed path is unaffected.
    let Some(snapshot) = snapshot else {
        return PublishOutcome::Unsettled;
    };
    // Exactly one attempt, and no retry. The publish is legitimate only while
    // the row still holds the bytes this read snapshotted; a refusal means
    // something rewrote or removed it, which is precisely the case that must
    // NOT publish. Re-reading and retrying would defeat the fence.
    let key = availability_index_key(partition, address);
    let new = encode_avail(etag);
    let task_cache = Arc::clone(cache);
    let task_key = key.clone();
    let task_snapshot = snapshot;
    let task_partition = partition.to_string();
    let task_address = address.clone();
    let task_etag = etag.to_string();
    let task = tokio::task::spawn_blocking(move || {
        let mut guard = guard;
        let swapped = task_cache.compare_and_put(&task_key, Some(&task_snapshot), Some(&new));
        if matches!(swapped, Ok(true)) {
            // Best-effort prune of the validator this fill supersedes.
            //
            // This runs in the same cancellation-detached task as the publish,
            // before the guard is disarmed. No async caller can drop the guard
            // in the span between those two steps.
            if let Some(previous) = parse_avail(&task_snapshot)
                && previous != task_etag
            {
                let _ = task_cache.remove_index(&content_cache_key(
                    &task_partition,
                    &task_address,
                    &previous,
                ));
            }
            if let Some(guard) = guard.as_mut() {
                guard.0.armed = false;
            }
        }
        (swapped, guard)
    })
    .await;
    let (swapped, mut guard) = match task {
        Ok(result) => result,
        Err(error) => {
            // A panic unwinds the blocking closure and drops its still-armed
            // guard there, so the row has already taken the fail-safe path.
            tracing::debug!(
                address = %redact_url(address),
                error = %error,
                "byte cache availability publish task panicked"
            );
            return PublishOutcome::Unsettled;
        }
    };
    let outcome = match swapped {
        Ok(true) => PublishOutcome::Settled,
        // The row moved since this read began. That is NOT proof a newer
        // state won it: a concurrent reader that started at the same point can
        // have published an OLDER validator, if it read before an out-of-band
        // change this read saw. This read holds a validator it proved current
        // and can see the row holds something else, so leaving it would be
        // knowingly answering the fallback with content this read superseded.
        //
        // Drop the row instead. Uniformly safe -- an absent row names no
        // validator -- and it costs at most a fallback entry, which the next
        // read re-seeds.
        Ok(false) => {
            // One re-read, and only to ask a narrower question than the swap
            // did: does the row already name the validator this read proved
            // current? Two concurrent misses on a hot address snapshot the same
            // bytes and prove the same validator, so the loser's swap refuses
            // on the winner's nonce alone -- and removing the row there empties
            // the fallback for a correct, current entry, under exactly the read
            // concurrency the fallback exists to serve.
            //
            // This is not a retry, and it must not become one: the row is left
            // as the winner wrote it, never rewritten. Only the answer changes,
            // from "remove" to "this is already what I would have published".
            // Any other value still means the world moved past this read, and
            // the removal below stands.
            if let Ok((_, current)) = read_avail(cache, partition, address).await
                && current.as_deref() == Some(etag)
            {
                PublishOutcome::Settled
            } else {
                tracing::debug!(
                    address = %redact_url(address),
                    "byte cache availability publish refused: the row moved during the read"
                );
                settled_by_removal(cache, address, &key).await
            }
        }
        // Best-effort by contract: the availability index is a fallback that
        // answers only while the backend cannot, so failing to record it must
        // not fail a read that already holds valid bytes. Erroring here would
        // make the same I/O fault fail or spare a read purely by whether the
        // read started before or after the fault.
        //
        // But this read proved `etag` current, so the row must not be left
        // naming an older validator whose bytes are still cached. Drop it: an
        // absent row costs the fallback, which beats answering with content
        // this read just superseded.
        Err(error) => {
            tracing::debug!(
                address = %redact_url(address),
                error = %error,
                "byte cache could not record the availability validator; invalidating"
            );
            settled_by_removal(cache, address, &key).await
        }
    };
    if outcome == PublishOutcome::Settled
        && let Some(guard) = guard.as_mut()
    {
        guard.0.armed = false;
    }
    outcome
}

/// Remove the row, reporting whether that actually settled it. A removal that
/// fails leaves the row naming whatever it named, so the caller's guard has to
/// stay armed rather than trusting this frame to have handled it.
async fn settled_by_removal(cache: &Arc<Cache>, address: &Url, key: &str) -> PublishOutcome {
    match remove_index_off_runtime(cache, key).await {
        Ok(()) => PublishOutcome::Settled,
        Err(error) => {
            tracing::debug!(
                address = %redact_url(address),
                error = %error,
                "byte cache could not clear an availability row it could not publish"
            );
            PublishOutcome::Unsettled
        }
    }
}

/// Publish `etag` as the address's validator **as the mutation itself**, fenced
/// on `snapshot` — the availability row as it stood BEFORE the backend write
/// this publishes for.
///
/// The fence has to be the pre-write row, and the swap has to be a single
/// attempt. A write-through learns its validator only after `inner.write`
/// returns, and a delete can complete in that window; the delete rewrites the
/// row, so the swap refuses. Re-reading and retrying would find the delete's
/// tombstone and overwrite it with this write's validator — resurrecting a
/// deleted object under the lost-backing fallback, which is the exact race the
/// fence exists to stop. A refusal here means the world moved past this write,
/// and the state that moved it stands.
async fn publish_mutation_impl(
    cache: &Arc<Cache>,
    partition: &str,
    address: &Url,
    snapshot: Option<Vec<u8>>,
    etag: &str,
) -> Result<()> {
    let key = availability_index_key(partition, address);
    // No pre-write snapshot: nothing proves this write is the newest thing to
    // touch the row, so it must not publish. Drop the row — it may still name
    // the validator this write superseded, and absent names nothing.
    let Some(snapshot) = snapshot else {
        return remove_index_off_runtime(cache, &key).await;
    };
    let new = encode_avail(etag);
    match compare_and_put_off_runtime(cache, &key, Some(snapshot.clone()), new).await {
        // The superseded body is reclaimed by `MutationGuard`, which captured
        // the validator naming it before the write-ahead clear removed the row.
        // By here the snapshot is that clear's tombstone and names nothing.
        Ok(true) => Ok(()),
        // The row moved since this write began, and what moved it is NOT
        // necessarily newer. A concurrent read-path fill republishes the
        // validator it read at ITS start, which may be the one this write just
        // superseded; a concurrent write that lost the backend race publishes
        // a validator the backend no longer holds. Neither is distinguishable
        // from a racing delete's tombstone here, and leaving any of them is the
        // stale-fallback bug this fence exists to close.
        //
        // Remove instead. An absent row names no validator and matches no
        // snapshot, so this is fail-safe in every direction: against a racing
        // delete it costs nothing (a tombstone and an absent row answer alike),
        // and against a racing fill it costs the fallback, which is degradation
        // rather than staleness.
        Ok(false) => remove_index_off_runtime(cache, &key).await,
        // The backend write has already landed, so returning here would leave
        // the row naming the validator this write superseded with no later pass
        // to correct it. A full cache disk (ENOSPC) or a busy sibling process
        // (SQLITE_BUSY) are ordinary conditions for a cache, not reasons to
        // keep serving the old body. Drop the row instead.
        Err(_) => remove_index_off_runtime(cache, &key).await,
    }
}

/// The availability index's current validator for `address`, if any. Free-form
/// twin of [`ByteCacheWrapper::last_known_validator`] so the commit-finalize path
/// is exercisable without a full wrapper.
async fn last_known_validator_impl(
    cache: &Arc<Cache>,
    partition: &str,
    address: &Url,
) -> Option<String> {
    // The row may be a tombstone; return only a live validator. Best-effort:
    // this feeds a fallback that answers only while the backend cannot, so an
    // unreadable row is one more reason to report no fallback rather than to
    // fail the caller's stat.
    read_avail(cache, partition, address)
        .await
        .ok()
        .and_then(|(_, etag)| etag)
}

/// Invalidate the availability fallback for `address` and best-effort reclaim the
/// superseded content row it names. Free-form twin of
/// [`ByteCacheWrapper::clear_latest`].
async fn clear_latest_impl(
    cache: &Arc<Cache>,
    partition: &str,
    generations: &Mutex<GenerationMap>,
    address: &Url,
) -> Result<()> {
    bump_generation_key(generations, address.as_str());
    let key = availability_index_key(partition, address);
    for _ in 0..AVAIL_CAS_ATTEMPTS {
        let Ok((current, cur_etag)) = read_avail(cache, partition, address).await else {
            break;
        };
        // TOMBSTONE the validator (empty etag) rather than removing the row.
        // Both invalidate the fallback and both fence every concurrent fill
        // (either way the row stops matching a snapshot taken before this
        // clear), but a tombstone leaves the next read a row to snapshot
        // instead of making it re-seed one.
        let new = encode_avail("");
        // As in `publish_mutation_impl`: a write-side failure falls through to
        // the removal below rather than propagating past it. The mutation this
        // clear accompanies has already landed at the backend, so an early
        // return would leave the fallback naming a deleted object's validator.
        // The blocking task owns the reclaim with the swap, so dropping this
        // async caller detaches both steps together rather than firing a guard
        // before the still-running swap has committed.
        let previous_content_key = cur_etag
            .as_ref()
            .map(|previous| content_cache_key(partition, address, previous));
        match clear_compare_off_runtime(
            cache,
            &key,
            current.clone(),
            new,
            partition,
            address,
            previous_content_key,
        )
        .await
        {
            Ok(true) => {
                return Ok(());
            }
            // The row moved under us, so whoever moved it captured this
            // validator and owns its reclaim -- `record_latest_impl`'s prune,
            // `MutationGuard::superseded`, or another clear's own reclaim.
            // Re-read and work from whatever the row names now.
            Ok(false) => continue,
            // A task-level failure means its unwind guard already reclaimed
            // the last-read body. Fall through to remove the current row and
            // reclaim whatever it actually names.
            Err(_) => break,
        }
    }
    // The row could not be read or written, or the swap never converged. An
    // invalidation must not fail open, and it must not spin: drop the row
    // outright. An absent row names no validator and matches no snapshot, so
    // this is fail-safe for the ROW in both directions.
    //
    // Remove-and-return identifies the exact row deleted under one SQLite
    // transaction, so a concurrent publisher cannot make this reclaim act on
    // an earlier observation. The detached blocking task owns both steps.
    remove_availability_and_reclaim_off_runtime(cache, &key, partition, address).await
}

/// What a committed streamed write-through tee needs to decide publication:
/// the availability row as it stood before the backend write, the validator the
/// write reported, and the generation pair the post-commit re-check compares.
struct TeeCommit<'a> {
    snapshot: Option<Vec<u8>>,
    etag: &'a str,
    current_generation: u64,
    start_generation: u64,
}

/// Publish (or discard) a committed streamed write-through tee's row based on the
/// post-commit generation re-check. When `current_generation` does not
/// match `start_generation`, a concurrent mutation landed during the commit
/// window: discard the just-committed content row and clear the availability
/// entry so the stale bytes are never published. Otherwise bump (mutation
/// semantics) and record the new validator. Free-form twin of
/// [`ByteCacheWrapper::finalize_committed_tee`], exercisable with a synchronously
/// bumped generation.
async fn finalize_committed_tee_impl(
    cache: &Arc<Cache>,
    partition: &str,
    generations: &Mutex<GenerationMap>,
    address: &Url,
    commit: TeeCommit<'_>,
) -> Result<()> {
    let TeeCommit {
        snapshot,
        etag,
        current_generation,
        start_generation,
    } = commit;
    if current_generation != start_generation {
        // Synchronous, and it must precede the first await in this branch. The
        // generation moved, so the backend holds a validator other than `etag`
        // and no read will ever look this row up; the guard covering this write
        // reclaims the validator the write superseded, not this one. Awaiting
        // ahead of the discard lets a cancelled caller leave the committed body
        // reachable from nothing — see the test on
        // [`remove_index_off_runtime`].
        let _ = cache.remove_index(&content_cache_key(partition, address, etag));
        clear_latest_impl(cache, partition, generations, address).await
    } else {
        bump_generation_key(generations, address.as_str());
        // This tee's fill is the write's own mutation, fenced on the row as it
        // stood before the backend write.
        publish_mutation_impl(cache, partition, address, snapshot, etag).await
    }
}

/// Provisional validator dimension for a streamed write's staging key: the real
/// validator is only known from the write result, so the tee begins its
/// [`StreamingPut`](ovstorage_cache::StreamingPut) under this placeholder and
/// retargets to the post-write validator key via `commit_to`. It only names the
/// staging file's derivation and is replaced before the row is written, so it
/// never reaches the CAS index.
const PROVISIONAL_WRITE_ETAG: &str = "\u{0}pending-streamed-write";

/// Shared state between a streamed write's body-tee iterator (which spools
/// chunks as the inner write pulls them) and `streamed_write_through`'s post-
/// write commit. The tee runs on whichever thread drives the inner write, so the
/// state is behind a `Mutex`; no `await` is held across the lock.
struct WriteTeeState {
    /// The in-flight staging fill; taken (dropped) on abort so the staging file
    /// is discarded, and taken by the commit path once the write returns.
    put: Option<ovstorage_cache::StreamingPut>,
    /// Set when the body iterator reached EOF — proof the whole body flowed
    /// through the tee (an unbounded stream body only ends when the backend
    /// pulls `None`, so a successful streamed write necessarily reaches it).
    reached_eof: bool,
    /// Set on a cap breach, a staging I/O error, or a body error: the fill is
    /// abandoned and must not commit.
    aborted: bool,
}

/// Wrap a streamed write body so each chunk spools into `shared`'s staging fill
/// as it passes to the inner write. A cap breach or staging I/O error abandons
/// the fill (dropping the `StreamingPut` discards the staging file) while the
/// write's own body streams on intact; a body error marks the fill abandoned so
/// a truncated body never commits; reaching EOF records that the whole body was
/// observed. The staging write is bounded to one chunk — the body is never held
/// whole in memory.
fn write_tee_body(body: BodyStream, shared: Arc<Mutex<WriteTeeState>>) -> BodyStream {
    let mut body = body;
    BodyStream::from_iter(std::iter::from_fn(move || match body.next() {
        Some(Ok(chunk)) => {
            if let Ok(mut state) = shared.lock()
                && let Some(put) = state.put.as_mut()
            {
                let failed = put.write_chunk(&chunk).is_err();
                if failed {
                    // Cap breach or staging I/O error: drop the fill (discards
                    // the staging file) and keep serving the write's body.
                    state.put = None;
                    state.aborted = true;
                }
            }
            Some(Ok(chunk))
        }
        Some(Err(error)) => {
            if let Ok(mut state) = shared.lock() {
                state.put = None;
                state.aborted = true;
            }
            Some(Err(error))
        }
        None => {
            if let Ok(mut state) = shared.lock() {
                state.reached_eof = true;
            }
            None
        }
    }))
}

/// Tee `stream`'s chunks into `put` as they pass to the caller. On clean
/// completion the staged bytes are committed and the fill is recorded as the
/// address's newest validator (the availability index — pruning its
/// predecessor). A mid-stream cap breach or staging I/O error abandons the
/// fill and serves the rest of the stream unaffected; a stream error
/// (truncation) or the caller dropping the stream early (cancellation) drops
/// `put` un-committed, so no half-cached row (and no index entry) is left
/// behind. The staging writes are bounded to one chunk — the whole object is
/// never held in memory.
#[allow(clippy::too_many_arguments)]
fn tee_into_cache(
    stream: ReadStream,
    put: ovstorage_cache::StreamingPut,
    cache: Arc<Cache>,
    partition: String,
    address: Url,
    etag: String,
    snapshot: Option<Vec<u8>>,
    guard: ReadGuard,
    expected_size: Option<u64>,
    registration: TeeRegistration,
    start_generation: u64,
    registrar: CommitRegistrar,
) -> ReadStream {
    use futures::StreamExt as _;
    /// The teeing context, boxed so the active variant doesn't bloat `State`
    /// (`StreamingPut` carries a hasher — see clippy `large_enum_variant`).
    struct TeeState {
        stream: ReadStream,
        put: ovstorage_cache::StreamingPut,
        cache: Arc<Cache>,
        partition: String,
        address: Url,
        etag: String,
        /// The availability row as it stood when the READ began, carried
        /// through the whole drain and published against at EOF.
        snapshot: Option<Vec<u8>>,
        /// Rides the tee rather than the call that created it: this fill
        /// completes long after `read` returned, so a scope guard there would
        /// clear the row while the stream was still healthy. Dropped when the
        /// tee ends by any route — clean EOF without a publish, a truncated or
        /// errored body, or the caller dropping the stream mid-flight.
        guard: ReadGuard,
        /// The object's declared size (`info.size`), when known: a clean EOF
        /// only commits when the staged byte count matches, so a backend that
        /// ends the stream short of `info.size` never publishes a truncated
        /// body into the CAS.
        expected_size: Option<u64>,
        /// RAII registration keeping this address's generation slot live for
        /// the duration of the tee; dropped on every terminal path so the
        /// generations map stays bounded by in-flight tees.
        registration: TeeRegistration,
        /// Mutation generation captured when the tee started; a commit is
        /// dropped if the address was mutated since.
        start_generation: u64,
        /// Records the directory holding a body this tee commits. A streamed
        /// read's body lands here rather than in `fill_and_publish`, and the
        /// registration on the way in is keyed on the stat's validator — which
        /// a redirecting backend does not supply.
        registrar: CommitRegistrar,
    }
    enum State {
        Teeing(Box<TeeState>),
        Passthrough { stream: ReadStream },
        Done,
    }
    Box::pin(futures::stream::unfold(
        State::Teeing(Box::new(TeeState {
            stream,
            put,
            cache,
            partition,
            address,
            etag,
            snapshot,
            guard,
            expected_size,
            registration,
            start_generation,
            registrar,
        })),
        |state| async move {
            match state {
                State::Teeing(mut tee) => match tee.stream.next().await {
                    Some(Ok(chunk)) => match tee.put.write_chunk(&chunk) {
                        Ok(()) => Some((Ok(chunk), State::Teeing(tee))),
                        // Cap breach or staging I/O error: abandon the fill
                        // (drop discards the staging file), keep serving. The
                        // stream carries the object's *current* validator, so
                        // the availability index must not keep naming an older,
                        // now-superseded validator a later stat outage could
                        // serve as current; best-effort clear it.
                        Err(_) => {
                            let TeeState { stream, put, .. } = *tee;
                            drop(put);
                            // Dropping the rest of the state drops the guard,
                            // which clears the row this abandoned fill can no
                            // longer publish.
                            Some((Ok(chunk), State::Passthrough { stream }))
                        }
                    },
                    // Truncated/errored stream: no commit — drop discards.
                    Some(Err(error)) => Some((Err(error), State::Done)),
                    // Clean completion: publish the row, then record it as the
                    // newest validator. Both are best-effort — the caller's
                    // read already succeeded, and a superseded validator is
                    // unreachable on the strict path regardless.
                    None => {
                        let TeeState {
                            put,
                            cache,
                            partition,
                            address,
                            etag,
                            snapshot,
                            guard,
                            expected_size,
                            registration,
                            start_generation,
                            registrar,
                            ..
                        } = *tee;
                        // Only publish a fill that is (a) the full declared
                        // object — a short clean EOF is a truncated body, not a
                        // cacheable result — and (b) still current: an
                        // address mutated since the tee started must not be
                        // resurrected by this late commit. Otherwise drop
                        // `put` uncommitted.
                        let size_ok =
                            expected_size.is_none_or(|expected| put.staged_len() == expected);
                        let unmutated = registration.current() == start_generation;
                        if size_ok && unmutated {
                            // `commit` runs `sync_all` + CAS publication + a SQLite
                            // publish; run it off the runtime worker so the
                            // stream's final `poll_next` returns immediately
                            // instead of stalling on synchronous fsync.
                            let committed =
                                tokio::task::spawn_blocking(move || put.commit().is_ok())
                                    .await
                                    .unwrap_or(false);
                            if committed {
                                // The commit has returned and no lock is held.
                                // A streamed body is committed here rather than
                                // in `fill_and_publish`, so without this the
                                // directory holding it is watched only where the
                                // pre-read registration already covered it, and
                                // that one turns on the inner `stat` rather than
                                // on a body reaching the cache.
                                registrar.note_cached(&address);
                                // Publish against the READ-start snapshot the
                                // tee carried, not a fresh read of the row: the
                                // generation check only covers mutations that
                                // landed after `inner.read` returned, and a
                                // delete completing while it was still pending
                                // bumps no registration.
                                let _ = record_latest_guarded_impl(
                                    &cache,
                                    &partition,
                                    &address,
                                    snapshot,
                                    &etag,
                                    Some(guard),
                                )
                                .await;
                            }
                        }
                        // Every other route out -- a short body, a failed
                        // commit, a mutation during the tee -- drops the guard,
                        // which clears the row this fill cannot publish.
                        None
                    }
                },
                State::Passthrough { mut stream } => stream
                    .next()
                    .await
                    .map(|item| (item, State::Passthrough { stream })),
                State::Done => None,
            }
        },
    ))
}

#[async_trait]
impl Layer for ByteCacheWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Slots with no byte-cache interaction delegate to `inner` via the trait
    /// defaults.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    /// Clear this cache's subtree, then as far down the chain as the default
    /// forward reaches; a plugin boundary stops it. See
    /// [`Layer::invalidate_cached_subtree`].
    fn invalidate_cached_subtree(&self, prefix: &Url) {
        let _ = clear_subtree_impl(&self.cache, &self.partition, &self.generations, prefix);
        if let Some(inner) = self.inner_layer() {
            inner.invalidate_cached_subtree(prefix);
        }
    }

    fn supports_buffered_write_capture(&self) -> bool {
        self.inner.supports_buffered_write_capture()
    }

    /// Forwards exactly as the trait default does, and records the scope of a
    /// stat that produced a metadata-cache entry below — including a negative
    /// one, which the layer below caches as a live entry.
    ///
    /// This layer caches no metadata, but in the shipped `byte_cache` over
    /// `metadata_cache` composition it is the layer that owns the notification
    /// drains — its watch pull fires both caches' invalidation hooks — so it is
    /// also the layer that has to observe what the stack reads. Without this,
    /// a stack whose `watch_invalidation` is set on the byte layer alone would
    /// leave every metadata row the caller's own `stat`s filled unwatched.
    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let watching = self.watch_state.watches()
            && crate::routing::stat_is_cacheable(&request.input.address, &request.input.options);
        let address = watching.then(|| request.input.address.clone());
        let info = self.inner.stat(request, cancel).await;
        // `NotFound` counts, which is why this does not exit through `?`. The
        // metadata layer below caches a list-backed negative as a live entry and
        // *then* answers `NotFound`, so returning early would leave the parent
        // listing that produced the answer unwatched — and with the root watch
        // refused, an object created afterwards stays invisible behind that
        // listing until the metadata cache's TTL expires it, thirty seconds by
        // default. Bounded, unlike the byte cache, which has no TTL at all —
        // but a watch is what makes it prompt.
        //
        // A backend's own `NotFound` is indistinguishable from that one here and
        // registers too. Deliberate: it costs one candidate slot for a directory
        // that may hold nothing, which is the cost the `read` path already
        // accepts for a fill that caches nothing, and the alternative —
        // registering before forwarding — spends that slot on every failed stat
        // rather than on the negative answers alone.
        let registers = match &info {
            Ok(_) => true,
            Err(error) => error.code() == ErrorCode::NotFound,
        };
        if let Some(address) = address
            && registers
        {
            self.watch_state.note_cached(&address);
        }
        info
    }

    /// Forwards exactly as the trait default does, and records the scope of a
    /// listing that MAY have produced a metadata-cache entry below. See
    /// [`Self::stat`] for why this layer observes reads it does not itself
    /// cache.
    ///
    /// "May" is the honest word and the difference matters. This layer applies
    /// the cacheability predicate; only the metadata layer knows whether its
    /// cache retained anything, because `MetadataCache::insert` drops a payload
    /// larger than the whole budget. So in a byte-over-metadata stack — where
    /// this layer owns the drain and the metadata layer's own registry is off —
    /// a listing too large to store still registers a candidate here.
    ///
    /// Left that way deliberately, on this file's standing asymmetry: an
    /// unnecessary candidate costs one of `MAX_CANDIDATE_SCOPES` and a probe,
    /// both recoverable, while a missing one costs entries that the byte cache
    /// never expires. Narrowing it would need this layer to ask the layer below
    /// what it kept, which is a query the `Layer` trait does not have and should
    /// not grow for this. `MetadataCacheWrapper::store_list` makes the tighter
    /// choice where it CAN be made — when the metadata layer owns the registry.
    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let watching = self.watch_state.watches()
            && crate::routing::list_is_cacheable(&request.input.prefix, &request.input.options);
        let prefix = watching.then(|| request.input.prefix.clone());
        let page = self.inner.list(request, cancel).await?;
        if let Some(prefix) = prefix {
            self.watch_state.note_cached(&prefix);
        }
        Ok(page)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        // A broker-resolved OAuth credential can make the representation vary
        // by principal even when the origin reuses one validator for every
        // caller. This cache's content and availability keys are deliberately
        // principal-agnostic, so such reads must neither consult nor populate
        // it. Delegate before even issuing the validator `stat`: otherwise a
        // cached body from another principal could answer under a shared ETag
        // or through the lost-backing fallback.
        if request
            .extensions
            .get(ext::RESOLVED_OAUTH_CREDENTIAL)
            .is_some()
        {
            return self.inner.read(request, cancel).await;
        }
        // Conditional/partial reads are never cached (the cached full object
        // would hide the precondition / range for later unconditional reads).
        // `read_bytes` sets this to say the caller wants a fully buffered result,
        // so a streamed/delegated object can be buffered here and cached.
        // Streaming callers don't set it, so their
        // reads still pass `Stream`/`LocalDelegate` through un-buffered.
        let to_bytes = request.extensions.get(READ_TO_BYTES_EXTENSION).is_some();
        // A cacheable delegate warms into the CAS when the composition opts in
        // via `warm_delegates` — the broker Stack sets it while the default
        // remains off. Warming spools the delegate into the CAS and
        // hands back a leased copy, so a brokered read survives backing-store
        // loss, driven by composition rather than a per-request hint.
        let warm = self.warm_delegates;
        let cacheable =
            request.input.options.if_match.is_none() && request.input.options.range.is_none();
        let max_bytes = request.input.options.max_bytes;
        let address = request.input.address.clone();
        // Validator-checked lookup: the current etag proves a cached
        // entry fresh; without one the cache is bypassed.
        let probe = if cacheable {
            self.lookup_etag(&request.extensions, &address, cancel.clone())
                .await?
        } else {
            ValidatorProbe::silent()
        };
        let validator = probe.validator;
        // Registered on the way in, for the entry the inner `stat` leaves in
        // the metadata cache below: that row exists whether or not this read
        // goes on to publish a body, and in the shipped composition this layer
        // is the only one observing on its behalf. The body's own registration
        // is in `fill_and_publish`, which is the only place that knows an entry
        // was committed. Registering here for a read that ends up caching
        // nothing costs a candidate slot; not registering a row that is cached
        // costs an entry nothing will ever invalidate.
        //
        // Keyed on the stat not having been REFUSED, rather than on it having
        // carried an etag or on the request's shape. Two different mistakes sit
        // on either side of that.
        //
        // Gating on the validator withholds registration from every unversioned
        // route, and the row the sentence above is about is stored either way —
        // the metadata layer caches a `Stat` for any cacheable address. A
        // backend that returns no etag is exactly the one whose rows a watch has
        // to invalidate, since there is no validator to catch the change on
        // read.
        //
        // Gating on `cacheable` alone — `if_match.is_none() && range.is_none()`,
        // decided before anything is asked — admits a directory the caller was
        // refused, for which the layer below takes `?` and caches nothing. That
        // is a scope holding nothing, taken from a budget of four, chosen by a
        // caller the backend turned away, and then watched by a drain that
        // carries no principal.
        if cacheable && probe.registers {
            self.watch_state.note_cached(&address);
        }
        if let Some(etag) = &validator {
            let etag = etag.clone();
            if to_bytes {
                // A buffering caller (`read_bytes`, marked by `to_bytes`) gets a
                // whole-object `Bytes` result on a hit. Streaming callers — the
                // broker among them, which sets no per-request hint — fall to the
                // leased-delegate branch below and never re-materialize the object
                // into one allocation.
                if let Some(object) = self
                    .cache
                    .get_entry_async(&self.cache_key(&address, &etag))
                    .await?
                {
                    return Ok(ReadResult::Bytes {
                        bytes: object.bytes,
                        info: cached_object_info(address, object.entry.size, Some(etag)),
                    });
                }
            } else if let Some(lookup) = self.cache.lookup(&self.cache_key(&address, &etag))? {
                // A non-buffering caller (`read_stream`) must not have the whole
                // object re-materialized into one `Bytes` allocation on a hit.
                // Hand back a leased on-disk delegate
                // the caller can read chunk-bounded. Follow-up: an async,
                // file-backed chunk stream — `lookup`'s verify-read is sync.
                let guard = lookup
                    .lease
                    .map(|lease| Arc::new(lease) as Arc<dyn Send + Sync>);
                return Ok(ReadResult::LocalDelegate(LocalDelegate {
                    path: lookup.cached.entry.path,
                    info: cached_object_info(address, lookup.cached.entry.size, Some(etag)),
                    guard,
                }));
            }
        }
        // Snapshot the availability row BEFORE the inner read: a fill
        // publishes its validator only against these exact bytes, so any
        // mutation landing during the read fences it out.
        //
        // Gated on the read being cacheable, and NOT on the stat's validator.
        // The publish below is gated on the READ's validator, and the two are
        // not the same backend answer: a redirecting backend names versions on
        // its read (the follower below this layer resolves the redirect and
        // carries the validator back with the bytes) while its stat may name
        // none. Gating the snapshot on the stat's would leave every such
        // address with no fallback at all -- exactly the brokered
        // survive-backing-loss path the index exists for.
        //
        // Snapshotting an absent row SEEDS it, so the exits that will never
        // publish against that seed take it back: the read's own error path,
        // and a read that proves no validator. A read of an address that does
        // not exist would otherwise leave a row and a CAS blob behind for a
        // path that was only ever probed -- an asset resolver walking candidate
        // paths would write one of each per miss, and the default cache has no
        // size budget to reclaim them. Every exit that DOES prove a validator
        // is covered by the guard below instead, which clears rather than
        // discards.
        let snapshot = if cacheable {
            self.snapshot(&address).await
        } else {
            None
        };
        let result = match self.inner.read(request, cancel).await {
            Ok(result) => result,
            Err(error) => {
                self.discard_unused_seed(&address, snapshot.as_deref())
                    .await;
                return Err(error);
            }
        };
        // ONE guard over every arm below, armed the moment the read proves a
        // validator. Arming inside each arm instead would leave the arms that
        // fill nothing -- over-cap results, a refused streaming fill, a
        // pass-through delegate, a body that failed to buffer -- silently
        // exempt, and those exits have proven the index's validator superseded
        // just as surely as the ones that fill. Any arm that does not publish
        // now clears by dropping this.
        //
        // Non-cacheable reads (conditional, ranged) are deliberately outside
        // it: they do not participate in the cache at all, and clearing on
        // every ranged read would empty the fallback under exactly the
        // range-heavy traffic it exists to serve.
        let proof = if cacheable {
            result_info(&result).and_then(ProvenValidator::proved)
        } else {
            None
        };
        // No validator: nothing below can publish, and no guard is armed to
        // clear on the way out.
        //
        // The two ways to have none are not the same evidence. A backend that
        // reports NO etag has said nothing about versions, so a row an earlier
        // fill established still stands and only this read's own seed is
        // residue -- an in-tree example is an HTTP origin serving no `ETag`
        // header. A backend that reports an EMPTY one has answered: it read a
        // version and named it with a string that cannot be told from any
        // other. A row naming an older, real validator no longer describes the
        // object, so leaving it is the one outcome that serves bytes this read
        // disproved, once a stat outage engages the fallback.
        if proof.is_none() {
            let reported = if cacheable {
                result_info(&result).and_then(|info| info.etag.as_deref())
            } else {
                None
            };
            self.settle_without_validator(&address, reported, snapshot.as_deref())
                .await;
        }
        let mut guard = proof.as_ref().map(|proof| {
            ReadGuard::arm(
                &self.cache,
                &self.partition,
                &address,
                proof,
                snapshot.as_deref(),
            )
        });
        match result {
            ReadResult::Bytes { bytes, info } => {
                // Fill only under the result's own validator; unversioned
                // content is never inserted. The per-object cap gates the
                // byte-path fill too, or an over-cap object returned as `Bytes`
                // would bypass the broker's cache-DoS gate.
                if let Some(proof) = &proof {
                    let etag = proof.etag();
                    self.fill_and_publish(&address, etag, &bytes, snapshot, &mut guard)
                        .await;
                    // Over-cap: this validator can't be retained, and the index
                    // may still name an older, now-superseded one. Dropping the
                    // guard clears it, so a later stat outage under
                    // `lost_backing_fallback` cannot serve bytes this read just
                    // proved stale.
                }
                Ok(ReadResult::Bytes { bytes, info })
            }
            // For a buffering `read_bytes`, materialize the stream / local
            // delegate to bytes and fill the cache, so a redirected, streaming,
            // or delegated read warms the
            // cache instead of re-fetching on every call.
            ReadResult::Stream { stream, info } if cacheable && to_bytes => {
                let bytes = buffer_read_stream(stream, max_bytes).await?;
                if let Some(proof) = &proof {
                    let etag = proof.etag();
                    // Guarded exactly as the `Bytes` arm above; over-cap falls
                    // through and the guard clears.
                    self.fill_and_publish(&address, etag, &bytes, snapshot, &mut guard)
                        .await;
                }
                Ok(ReadResult::Bytes { bytes, info })
            }
            // Stream-tee fill: a streaming caller's object
            // streams through to the caller while chunks spool to a cache
            // staging file, committed only on clean completion and capped by
            // `max_object_bytes`. On commit the fill is recorded as the newest
            // validator (availability index). An etag-less stream can't be
            // identity-keyed, so it passes through uncached.
            ReadResult::Stream { stream, info } if cacheable => {
                match proof.as_ref() {
                    Some(proof) => match self.cache.begin_streaming_put(
                        &self.cache_key(&address, proof.etag()),
                        self.max_object_bytes,
                    ) {
                        Ok(put) => {
                            // The guard travels with the tee, not this call:
                            // the fill finishes after `read` returns. Taking it
                            // here keeps this arm from clearing on return.
                            let Some(guard) = guard.take() else {
                                unreachable!("a proven validator armed the guard above");
                            };
                            // Register this tee against the address's generation
                            // slot for its whole lifetime; the handle bumps the
                            // refcount now and drops it on every terminal path,
                            // keeping the generations map bounded.
                            let (registration, start_generation) =
                                TeeRegistration::register(self.generations.clone(), &address);
                            Ok(ReadResult::Stream {
                                stream: tee_into_cache(
                                    stream,
                                    put,
                                    self.cache.clone(),
                                    self.partition.clone(),
                                    address.clone(),
                                    proof.etag().to_string(),
                                    snapshot,
                                    guard,
                                    info.size,
                                    registration,
                                    start_generation,
                                    self.watch_state.registrar(),
                                ),
                                info,
                            })
                        }
                        // `begin_streaming_put` failed: an unwritable cache
                        // (read-only), OR — on a writable cache — fill-slot /
                        // staging-byte exhaustion. In the latter case the
                        // availability index may still name an older validator this
                        // newer read supersedes, so a later stat outage under
                        // `lost_backing_fallback` could serve the stale bytes.
                        // Best-effort clear before serving uncached; a no-op
                        // on the unwritable-cache case where clearing is impossible.
                        Err(_) => {
                            let _ = self.clear_latest(&address).await;
                            Ok(ReadResult::Stream { stream, info })
                        }
                    },
                    None => Ok(ReadResult::Stream { stream, info }),
                }
            }
            // Brokered delegate warm: spool the file into the CAS pre-read
            // capped by `max_object_bytes`, without loading it into memory, and
            // hand back a leased delegate the broker streams (survives
            // backing-store loss).
            // The guard moves into the warm, as it does into the stream tee:
            // the publish happens in there, so leaving one armed out here would
            // clear the row that publish just wrote.
            ReadResult::LocalDelegate(local) if cacheable && warm => {
                match guard.take() {
                    Some(guard) => self.warm_delegate(&address, local, snapshot, guard).await,
                    // No proven validator, so nothing to warm under and no row
                    // to protect; `proof` gates both.
                    None => Ok(ReadResult::LocalDelegate(local)),
                }
            }
            // `read_bytes` over a local delegate: the caller wants `Bytes`. The
            // cap is checked **pre-read** from the delegate size, so an
            // over-cap object errors without slurping the whole file.
            ReadResult::LocalDelegate(local) if cacheable && to_bytes => {
                if let Some(cap) = max_bytes
                    && delegate_size(&local).await > cap
                {
                    return Err(crate::read_helpers::read_bytes_max_bytes_error(cap));
                }
                let bytes = tokio::fs::read(&local.path)
                    .await
                    .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
                // Post-read double-check: the pre-read size is only a metadata
                // estimate (and falls back to 0 when the stat fails), and the
                // file can grow between the stat and the read, so re-enforce the
                // caller's `max_bytes` against the bytes actually read.
                if let Some(cap) = max_bytes
                    && bytes.len() as u64 > cap
                {
                    return Err(crate::read_helpers::read_bytes_max_bytes_error(cap));
                }
                if let Some(proof) = &proof {
                    let etag = proof.etag();
                    // Guarded exactly as the `Bytes` arm above; over-cap falls
                    // through and the guard clears.
                    self.fill_and_publish(&address, etag, &bytes, snapshot, &mut guard)
                        .await;
                }
                Ok(ReadResult::Bytes {
                    bytes,
                    info: local.info,
                })
            }
            // Streams and local delegates pass through uncached (a stream
            // can't be cached without buffering the whole object). They still
            // proved a validator, so dropping the guard clears an index that
            // may still name an older one -- the default `warm_delegates =
            // false` composition reaches this arm on every delegate read.
            other => Ok(other),
        }
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        // `materialize` shares the same principal-agnostic content and
        // availability indexes as `read`, so credentialed requests take the
        // same complete bypass (lookup, fallback, and fill).
        if request
            .extensions
            .get(ext::RESOLVED_OAUTH_CREDENTIAL)
            .is_some()
        {
            return self.inner.materialize(request, cancel).await;
        }
        let cacheable =
            request.input.options.if_match.is_none() && request.input.options.range.is_none();
        let address = request.input.address.clone();
        let probe = if cacheable {
            self.lookup_etag(&request.extensions, &address, cancel.clone())
                .await?
        } else {
            ValidatorProbe::silent()
        };
        let validator = probe.validator;
        // See `read`: registered for the metadata row the inner `stat` leaves
        // below, and only where that stat answered for this address — the body's
        // own registration is in `fill_and_publish`.
        if cacheable && probe.registers {
            self.watch_state.note_cached(&address);
        }
        if let Some(etag) = validator.clone()
            && let Some(lookup) = self.cache.lookup(&self.cache_key(&address, &etag))?
        {
            let guard = lookup
                .lease
                .map(|lease| Arc::new(lease) as Arc<dyn Send + Sync>);
            return Ok(LocalDelegate {
                path: lookup.cached.entry.path,
                info: cached_object_info(address, lookup.cached.entry.size, Some(etag)),
                guard,
            });
        }
        // Snapshot the availability row BEFORE the fetch so a `clear_latest`
        // landing during `inner.materialize` fences the publish below:
        // materialize is a read-family op with no preceding mutation and no S2
        // generation guard, so a post-fetch snapshot would miss the race.
        // Gated on the op being cacheable, as in `read`, and on nothing else:
        // the publish is gated on the STAGED result's validator, which a
        // backend can name where its stat does not. Snapshotting an absent row
        // seeds it, so the exits that never publish take the seed back.
        let snapshot = if cacheable {
            self.snapshot(&address).await
        } else {
            None
        };
        let local = match self.inner.materialize(request, cancel).await {
            Ok(local) => local,
            Err(error) => {
                self.discard_unused_seed(&address, snapshot.as_deref())
                    .await;
                return Err(error);
            }
        };
        // Fill only under the staged result's own validator. NOTE: unlike
        // the read-path fills, this spool is NOT gated by `max_object_bytes` —
        // the delegate is already on disk, so the cap (a DoS gate against
        // *fetching* oversize objects into the CAS) is less load-bearing here,
        // but a bespoke host wiring the cap should decide
        // whether materialize fills are also capped for cache-disk budgeting.
        let proof = if cacheable {
            ProvenValidator::proved(&local.info)
        } else {
            None
        };
        // Nothing will publish against the seed, and no guard is armed to clear
        // it. Settled exactly as `read` settles it -- an empty validator is an
        // answer that supersedes the row, an absent one is not.
        if proof.is_none() {
            let reported = if cacheable {
                local.info.etag.as_deref()
            } else {
                None
            };
            self.settle_without_validator(&address, reported, snapshot.as_deref())
                .await;
        }
        if let Some(proof) = proof {
            let etag = proof.etag().to_string();
            // A completed materialize: every exit before the publish clears.
            let fence = ReadGuard::arm(
                &self.cache,
                &self.partition,
                &address,
                &proof,
                snapshot.as_deref(),
            );
            // A failed spool degrades to the delegate the backend staged
            // rather than failing a materialize it already answered; the guard
            // clears on the way out.
            let Ok(put) = self
                .cache
                .put_path_and_lease(&self.cache_key(&address, &etag), &local.path)
            else {
                return Ok(local);
            };
            // Only hand back the CAS copy when a real lease was minted, as
            // `warm_delegate` already does. An object larger than the cache
            // budget is published and then evicted by its own fill, so
            // `put_path_and_lease` returns no lease and `put.entry.path` names
            // a file that is already gone. `materialize` exists for callers
            // that open or mmap the path directly, so returning a stale one
            // reports success and fails at their open; without a lease there is
            // no promise the file stays readable, and the delegate the backend
            // staged is the only answer that holds.
            let Some(lease) = put.lease else {
                return Ok(local);
            };
            let _ = self
                .record_latest(&address, snapshot, &etag, Some(fence))
                .await;
            // The commit point, as distinct from the registration on the way in
            // above: that one is gated on the inner `stat` not having refused
            // the address, and this is the point a body is certain to be cached.
            self.watch_state.note_cached(&address);
            Ok(LocalDelegate {
                path: put.entry.path,
                info: local.info,
                guard: Some(Arc::new(lease) as Arc<dyn Send + Sync>),
            })
        } else {
            Ok(local)
        }
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        match &request.input.body {
            Body::Bytes(_) => return self.buffered_write_through(request, cancel).await,
            Body::Stream(_) => return self.streamed_write_through(request, cancel, false).await,
            Body::LocalFile(_) => {}
        }
        let address = request.input.address.clone();
        // A `LocalFile` body leaves no observable bytes, so invalidate the
        // superseded availability entry after the backend accepts the write.
        // Mutation discipline: armed BEFORE the backend write, which also
        // clears the row write-ahead. A failed write is ambiguous -- it can
        // have committed server-side before the error reached us -- so every
        // exit from here that does not reach an explicit publish or clear
        // invalidates.
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        let result = self.inner.write(request, cancel).await?;
        self.clear_latest(&address).await?;
        guard.disarm(None);
        Ok(result)
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        match &request.input.body {
            Body::Stream(_) => return self.streamed_write_through(request, cancel, true).await,
            Body::Bytes(_) | Body::LocalFile(_) => {}
        }
        let address = request.input.address.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        let result = self.inner.write_stream(request, cancel).await?;
        self.clear_latest(&address).await?;
        guard.disarm(None);
        Ok(result)
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let address = request.input.address.clone();
        // Armed across the call, and disarmed for the mid-flight step: a
        // `Redirects` step has not finalized anything, so the index is
        // deliberately untouched. A failed `continue_write` is ambiguous like
        // any other mutation and invalidates.
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        let step = self.inner.continue_write(request, cancel).await?;
        // Terminal completion of the direct write_redirect→continue_write API
        // finalizes the object without passing through `write`/`write_stream`;
        // `WriteStep::Redirects` is mid-flight and leaves the index untouched.
        if matches!(step, WriteStep::Done(_)) {
            self.clear_latest(&address).await?;
            guard.disarm(None);
        } else {
            // Mid-flight: nothing landed, so the pre-write row is still
            // accurate and the body it names is still the current one. Put the
            // row back and keep both.
            guard.disarm_unchanged().await;
        }
        Ok(step)
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let address = request.input.address.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        self.inner.delete(request, cancel).await?;
        self.clear_latest(&address).await?;
        guard.disarm(None);
        Ok(())
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let destination = request.input.destination.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &destination).await;
        let result = self.inner.copy(request, cancel).await?;
        // Both invalidations run even if the first fails; the guard covers any
        // exit that reaches neither. The subtree sweep is outside the guard's
        // reach -- it spans a prefix, not one row -- so it keeps its explicit
        // ordering.
        let cleared = self.clear_latest(&destination).await;
        // A directory-shaped copy lands children under the destination too.
        let subtree = self.clear_subtree(&destination);
        cleared.and(subtree)?;
        guard.disarm(None);
        Ok(result)
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let source = request.input.source.clone();
        let destination = request.input.destination.clone();
        // One guard per address the rename changes. The subtree sweeps stay
        // explicit: a prefix is outside a row-keyed guard's reach.
        let source_guard = MutationGuard::arm(&self.cache, &self.partition, &source).await;
        let destination_guard =
            MutationGuard::arm(&self.cache, &self.partition, &destination).await;
        self.inner.rename(request, cancel).await?;
        // The backend rename has committed, and it changed FOUR scopes. Every
        // one is invalidated even if an earlier one fails: a `?` between them
        // would skip the rest, leaving (for instance) the destination still
        // naming the validator it held before the rename overwrote it. The
        // first error is reported after all of them have been attempted.
        let source_cleared = self.clear_latest(&source).await;
        let destination_cleared = self.clear_latest(&destination).await;
        // Directory-shaped renames move the children too; for a plain object
        // the `/`-terminated prefixes match nothing.
        let source_subtree = self.clear_subtree(&source);
        let destination_subtree = self.clear_subtree(&destination);
        source_cleared
            .and(destination_cleared)
            .and(source_subtree)
            .and(destination_subtree)?;
        source_guard.disarm(None);
        destination_guard.disarm(None);
        Ok(())
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let address = request.input.address.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        let result = self.inner.update_metadata(request, cancel).await?;
        self.clear_latest(&address).await?;
        guard.disarm(None);
        Ok(result)
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        // A mutating endpoint like any other. It creates no byte object, which
        // is exactly why it needs invalidating: the address may have held a
        // file whose row and body are still cached, and after this call that
        // address is a directory. Leaving the row would let a stat outage serve
        // the old file's bytes for it.
        let address = request.input.address.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        let result = self.inner.create_directory(request, cancel).await?;
        self.clear_latest(&address).await?;
        guard.disarm(None);
        Ok(result)
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let address = request.input.address.clone();
        let guard = MutationGuard::arm(&self.cache, &self.partition, &address).await;
        self.inner.delete_directory(request, cancel).await?;
        // Both scopes are invalidated even if the first fails; see `rename`.
        // The subtree sweep stays explicit, being outside the guard's reach.
        let cleared = self.clear_latest(&address).await;
        let subtree = self.clear_subtree(&address);
        cleared.and(subtree)?;
        guard.disarm(None);
        Ok(())
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let watched_prefix = request.input.prefix.clone();
        let teardown = cancel.clone();
        let sweep_on_clean_end = request
            .extensions
            .get(MANAGED_NOTIFICATION_DRAIN_EXTENSION)
            .is_none();
        let stream = self.inner.watch_directory(request, cancel).await?;

        // A watched change proves the last-filled content superseded: clear the
        // availability index so the stat-error fallback cannot serve it.
        // Content entries need nothing on the strict path — the changed
        // validator makes them unreachable, and the metadata cache below drops
        // its stat entries on the same events so the next validator lookup is
        // fresh. Mirrors `MetadataCacheWrapper::watch_directory`:
        //
        // - `Object` drops the address's index entry; a `Deleted` object
        //   additionally drops everything UNDER it (a deleted directory takes
        //   its children's fallback entries with it — for a file address the
        //   prefix sweep matches nothing extra).
        // - `Lapsed` means events were lost, so anything under the watched
        //   prefix may be stale: drop the whole watched subtree.
        // - A stream error is an out-of-band coverage gap, so
        //   `GapSweepStream`'s `on_gap` sweeps the subtree. An ordinary caller
        //   stream also sweeps on a clean end. The cache-owned managed drain
        //   reconnects finite clean batches with bounded backoff instead, so
        //   it does not wipe the cache on every batch.
        //
        // Each clear also bumps the mutation generation of any in-flight tee it
        // covers, so a concurrent tee cannot re-publish a just-cleared row.
        let cache = Arc::clone(&self.cache);
        let partition = self.partition.clone();
        let generations = Arc::clone(&self.generations);
        let event_prefix = watched_prefix.clone();
        let gap_cache = Arc::clone(&self.cache);
        let gap_partition = self.partition.clone();
        let gap_generations = Arc::clone(&self.generations);
        let gap_prefix = watched_prefix;
        Ok(Box::new(GapSweepStream::new(
            stream,
            teardown,
            sweep_on_clean_end,
            move |event: &ChangeEvent| match event {
                ChangeEvent::Object { address, kind, .. } => {
                    if let Err(error) =
                        clear_watched_object(&cache, &partition, &generations, address)
                    {
                        // The fence has already been raised, so an in-flight
                        // tee cannot republish; the row itself outliving this
                        // event is a lost invalidation worth a line.
                        tracing::debug!(
                            address = %redact_url(address),
                            error = %error,
                            "byte cache could not drop a watched object's availability row"
                        );
                    }
                    if *kind == ChangeKind::Deleted {
                        let _ = clear_subtree_impl(&cache, &partition, &generations, address);
                    }
                }
                ChangeEvent::Lapsed { .. } => {
                    let _ = clear_subtree_impl(&cache, &partition, &generations, &event_prefix);
                }
            },
            move || {
                let _ =
                    clear_subtree_impl(&gap_cache, &gap_partition, &gap_generations, &gap_prefix);
            },
        )))
    }
}

#[cfg(test)]
mod generation_registry_tests {
    //! The generations map is bounded by in-flight tees, not by
    //! lifetime mutation cardinality, while the resurrection guard still
    //! fires. These exercise the registry primitives directly (the map is a
    //! private field, so an integration test can't observe its size).
    use super::*;

    fn registry() -> Arc<Mutex<GenerationMap>> {
        Arc::new(Mutex::new(GenerationMap::new()))
    }

    fn len(generations: &Mutex<GenerationMap>) -> usize {
        generations.lock().unwrap().len()
    }

    fn generation_of(generations: &Mutex<GenerationMap>, address: &Url) -> Option<u64> {
        generations
            .lock()
            .unwrap()
            .get(address.as_str())
            .map(|entry| entry.generation)
    }

    #[test]
    fn mutation_without_active_tee_neither_bumps_nor_leaks() {
        let generations = registry();
        let address = Url::parse("mem:///obj").unwrap();

        // No registration: a mutation must not insert an entry (the leak
        // was one String+u64 per distinct mutated address).
        bump_generation_key(&generations, address.as_str());
        assert_eq!(len(&generations), 0, "an untracked mutation must not leak");
        assert_eq!(generation_of(&generations, &address), None);
    }

    #[test]
    fn registration_bounds_the_map_and_the_guard_fires() {
        let generations = registry();
        let address = Url::parse("mem:///obj").unwrap();

        // A tee registers: the entry exists only for the tee's lifetime.
        let (registration, start) = TeeRegistration::register(generations.clone(), &address);
        assert_eq!(start, 0);
        assert_eq!(len(&generations), 1);

        // A mutation during the in-flight tee bumps the registered slot, so the
        // commit-time check sees a changed generation and drops the fill.
        bump_generation_key(&generations, address.as_str());
        assert_eq!(registration.current(), 1);
        assert_ne!(
            registration.current(),
            start,
            "a mutation during the tee must invalidate its commit"
        );

        // Dropping the last registration removes the entry: the map is bounded
        // by in-flight tees, not lifetime mutation cardinality.
        drop(registration);
        assert_eq!(len(&generations), 0, "the map empties once the tee ends");

        // A post-tee mutation is untracked again — no resurrection of the slot.
        bump_generation_key(&generations, address.as_str());
        assert_eq!(len(&generations), 0);
    }

    #[test]
    fn overlapping_tees_share_one_refcounted_slot() {
        let generations = registry();
        let address = Url::parse("mem:///obj").unwrap();

        let (first, _) = TeeRegistration::register(generations.clone(), &address);
        let (second, _) = TeeRegistration::register(generations.clone(), &address);
        assert_eq!(len(&generations), 1, "overlapping tees share one slot");

        // The slot survives while any tee is registered.
        drop(first);
        assert_eq!(len(&generations), 1, "the slot lives while a tee remains");
        drop(second);
        assert_eq!(len(&generations), 0, "the last tee drop clears the slot");
    }

    #[test]
    fn subtree_bump_hits_only_registered_children() {
        let generations = registry();
        let child = Url::parse("mem:///dir/child").unwrap();
        let sibling = Url::parse("mem:///dir2/child").unwrap();

        let (_child, _) = TeeRegistration::register(generations.clone(), &child);
        let (_sibling, _) = TeeRegistration::register(generations.clone(), &sibling);

        // A directory-shaped mutation bumps only the tees under the `/`-bounded
        // prefix — the sibling outside it is untouched (for subtree clears).
        bump_generations_under_prefix(&generations, "mem:///dir/");
        assert_eq!(generation_of(&generations, &child), Some(1));
        assert_eq!(generation_of(&generations, &sibling), Some(0));
    }
}

#[cfg(test)]
mod tee_finalize_tests {
    //! The post-commit generation re-check. A streamed
    //! write-through tee whose generation is bumped/cleared *during* the commit
    //! window (after the pre-commit guard passes, before publication) must NOT
    //! publish — its committed content row is discarded and the availability entry
    //! is cleared, so a concurrent delete/newer-write wins and later reads cannot
    //! resurrect the stale bytes under the lost-backing fallback.
    //!
    //! The commit window is internal to `streamed_write_through` and not
    //! deterministically reachable via real concurrency (a bump during the inner
    //! write lands before the pre-commit guard, not inside the post-commit
    //! window). So these drive the extracted finalize primitive directly, forcing
    //! the mismatch synchronously via the generation-registration seam — exactly
    //! the branch the production `finalize_committed_tee` executes.
    use super::*;

    fn open_cache() -> (Arc<Cache>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(CacheConfig {
            state_root: dir.path().join("state"),
            cache_root: dir.path().join("cache"),
        })
        .expect("cache opens");
        (Arc::new(cache), dir)
    }

    #[tokio::test]
    async fn a_refused_publish_keeps_a_row_naming_the_same_validator() {
        // Two cache-miss reads of one hot address snapshot the same bytes and
        // prove the same validator. The first publishes; the second's fenced
        // swap then refuses, because the row holds the first's nonce. Removing
        // the row there empties the fallback for a correct, current entry --
        // and under sustained read concurrency it empties it for exactly the
        // hottest objects.
        let (cache, dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///hot").unwrap();

        let shared = snapshot_avail(&cache, partition, &address).await;
        let first = record_latest_impl(&cache, partition, &address, shared.clone(), "v1").await;
        assert_eq!(first, PublishOutcome::Settled);

        // The second read, fenced on the same pre-read bytes.
        let second = record_latest_impl(&cache, partition, &address, shared, "v1").await;

        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string()),
            "a refusal by a publisher of the SAME validator must not empty the fallback"
        );
        assert_eq!(
            second,
            PublishOutcome::Settled,
            "the row names this read's validator, so its guard may disarm"
        );
        drop(dir);
    }

    #[test]
    fn budget_admission_scales_the_row_with_the_etag() {
        // A fixed reserve is wrong in both directions, and only a pair of cases
        // whose answers DIFFER for the same body and budget can tell an exact
        // width from a guess: one etag must fit and a longer one must not.
        let short = "v1";
        let long = "v-".to_string() + &"e".repeat(60);
        let body = 64_u64;

        let budget = body + (AVAIL_HEADER_LEN + short.len()) as u64;
        assert!(
            fits_alongside_its_row(body, short, Some(budget)),
            "the pair fits exactly"
        );
        assert!(
            !fits_alongside_its_row(body, short, Some(budget - 1)),
            "one byte short, it does not"
        );
        assert!(
            !fits_alongside_its_row(body, &long, Some(budget)),
            "the same body and budget must be refused for a longer etag: a \
             reserve that admits both cannot be measuring the row"
        );

        // And the longer etag fits once the budget covers its own row.
        let wider = body + (AVAIL_HEADER_LEN + long.len()) as u64;
        assert!(fits_alongside_its_row(body, &long, Some(wider)));
        assert!(
            fits_alongside_its_row(body, &long, None),
            "no budget, no limit"
        );
    }

    #[tokio::test]
    async fn guard_diagnostics_name_a_redacted_address() {
        // The guards' diagnostics used to carry the composite index key, which
        // embeds the raw URL. A URL can carry userinfo or a signed-URL
        // credential, and the `MutationGuard::arm` line is a WARN reachable
        // under ordinary ENOSPC or SQLITE_BUSY contention, so enabling logs
        // would disclose them.
        let (cache, _dir) = open_cache();
        let address =
            Url::parse("https://user:secret@example.com/obj?X-Amz-Signature=deadbeef").unwrap();
        let clear = AvailabilityClear::new(&cache, "p", &address);
        assert!(
            !clear.address.contains("secret"),
            "userinfo must not reach a log line: {}",
            clear.address
        );
        assert!(
            !clear.address.contains("deadbeef"),
            "a signed-URL credential must not reach a log line: {}",
            clear.address
        );
        assert!(
            clear.address.contains("example.com"),
            "the redacted form must still identify the object: {}",
            clear.address
        );
    }

    #[tokio::test]
    async fn racing_tee_commit_is_discarded_not_published() {
        let (cache, _dir) = open_cache();
        let generations = Arc::new(Mutex::new(GenerationMap::new()));
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let etag = "etag-race";
        let content_key = content_cache_key(partition, &address, etag);

        // The tee has already committed its content row (commit_to published it).
        cache
            .put(&content_key, b"stale-tee-bytes")
            .expect("seed row");

        // A tee is in-flight; capture its start generation.
        let (registration, start) = TeeRegistration::register(generations.clone(), &address);
        // A concurrent mutation lands DURING the commit window: it bumps the
        // registered slot (as a delete/newer-write would).
        bump_generation_key(&generations, address.as_str());
        assert_ne!(registration.current(), start, "the slot was bumped");

        // Finalize with the post-commit re-check: the generation moved, so the row
        // must be discarded and no validator published.
        finalize_committed_tee_impl(
            &cache,
            partition,
            &generations,
            &address,
            TeeCommit {
                snapshot: snapshot_avail(&cache, partition, &address).await,
                etag,
                current_generation: registration.current(),
                start_generation: start,
            },
        )
        .await
        .expect("finalize");

        assert!(
            cache
                .get_entry_async(&content_key)
                .await
                .expect("lookup")
                .is_none(),
            "the stale tee's committed content row must be discarded"
        );
        assert!(
            last_known_validator_impl(&cache, partition, &address)
                .await
                .is_none(),
            "no availability validator may be published for the racing tee"
        );
    }

    #[tokio::test]
    async fn non_racing_tee_commit_publishes() {
        let (cache, _dir) = open_cache();
        let generations = Arc::new(Mutex::new(GenerationMap::new()));
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let etag = "etag-clean";
        let content_key = content_cache_key(partition, &address, etag);

        cache.put(&content_key, b"fresh-bytes").expect("seed row");
        let (registration, start) = TeeRegistration::register(generations.clone(), &address);
        // No concurrent mutation: the generation is unchanged at commit.
        assert_eq!(registration.current(), start);

        finalize_committed_tee_impl(
            &cache,
            partition,
            &generations,
            &address,
            TeeCommit {
                snapshot: snapshot_avail(&cache, partition, &address).await,
                etag,
                current_generation: registration.current(),
                start_generation: start,
            },
        )
        .await
        .expect("finalize");

        assert!(
            cache
                .get_entry_async(&content_key)
                .await
                .expect("lookup")
                .is_some(),
            "the non-racing commit keeps its content row"
        );
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some(etag.to_string()),
            "the non-racing commit publishes its validator"
        );
    }
}

#[cfg(test)]
mod availability_index_tests {
    //! The availability index's publication integrity: the fence a read-path
    //! fill publishes under, its behaviour when the row moves underneath the
    //! read (mutation, eviction, subtree removal, delete/re-upload cycles), and
    //! the abandoned key namespace that keeps two earlier row encodings from
    //! being misread.
    use super::*;

    fn open_cache() -> (Arc<Cache>, tempfile::TempDir) {
        open_capped_cache(None)
    }

    fn open_capped_cache(max_bytes: Option<u64>) -> (Arc<Cache>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open_with_options(
            CacheConfig {
                state_root: dir.path().join("state"),
                cache_root: dir.path().join("cache"),
            },
            CacheOptions {
                max_bytes,
                ..CacheOptions::default()
            },
        )
        .expect("cache opens");
        (Arc::new(cache), dir)
    }

    fn generations() -> Arc<Mutex<GenerationMap>> {
        Arc::new(Mutex::new(GenerationMap::new()))
    }

    #[test]
    fn exact_removal_retries_only_transient_failures_once() {
        let mut attempts = 0;
        let value = retry_transient_once(|| {
            attempts += 1;
            if attempts == 1 {
                Err(Error::new(ErrorCode::Transient, "database is busy"))
            } else {
                Ok("removed")
            }
        })
        .expect("the transient retry succeeds");
        assert_eq!(value, "removed");
        assert_eq!(attempts, 2);

        attempts = 0;
        let error = retry_transient_once(|| -> Result<()> {
            attempts += 1;
            Err(Error::new(ErrorCode::Internal, "corrupt value"))
        })
        .expect_err("a non-transient failure is returned directly");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(attempts, 1);
    }

    /// The bare-UTF-8-etag row of the first availability encoding.
    fn legacy_v1_row(etag: &str) -> Vec<u8> {
        etag.as_bytes().to_vec()
    }

    /// The untagged `epoch (u64 LE) || etag` row of the second encoding.
    fn legacy_v2_row(epoch: u64, etag: &str) -> Vec<u8> {
        let mut row = epoch.to_le_bytes().to_vec();
        row.extend_from_slice(etag.as_bytes());
        row
    }

    #[tokio::test]
    async fn legacy_encodings_are_unreachable_and_reclaimed() {
        // Both abandoned encodings are ambiguous against each other and against
        // the current one: an untagged small-epoch row leads with NUL bytes,
        // which decode as valid UTF-8, so reading it as a bare etag hands back
        // a corrupt validator, and an untagged tombstone reads as a live one.
        // The current key namespace must not see either, and the sweep must
        // reclaim them rather than leave them to eviction.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///legacy").unwrap();
        let legacy_key = format!("{}{}", legacy_availability_prefix(partition), address);

        for row in [
            legacy_v1_row("v1-abcde"),
            legacy_v2_row(0, "abc123"),
            legacy_v2_row(1, ""),
            // The case that corrupts rather than merely confuses: an epoch of
            // 1 puts a `1` in the byte the current encoding reads as its
            // version, and a validator of ordinary hash length carries the row
            // past the header, so this parses as a live validator built from
            // the tail of a real etag.
            legacy_v2_row(1, "0123456789abcdef0123456789abcdef"),
        ] {
            cache.put(&legacy_key, &row).expect("seed a legacy row");
            assert_eq!(
                last_known_validator_impl(&cache, partition, &address).await,
                None,
                "a row under an abandoned namespace must never answer the fallback"
            );
        }

        sweep_legacy_availability_rows(&cache, partition);
        assert!(
            cache.get_entry_async(&legacy_key).await.unwrap().is_none(),
            "the sweep must reclaim abandoned rows rather than wait on eviction"
        );
    }

    #[tokio::test]
    async fn the_legacy_sweep_reclaims_the_bodies_those_rows_named() {
        // The legacy availability row is the only record of which validator a
        // legacy body was filled under, and it is in an encoding this build
        // refuses to interpret -- so the validator cannot be recovered to prune
        // that body precisely. Removing the row without the body strands one
        // full object per legacy address: nothing keys on the old etag once the
        // object changes, and the default cache has no budget to evict it.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///legacy").unwrap();

        let content_key = content_cache_key(partition, &address, "v1");
        cache
            .put(&content_key, b"legacy body")
            .expect("seed a body");
        cache
            .put(
                &format!("{}{address}", legacy_availability_prefix(partition)),
                b"legacy row",
            )
            .expect("seed a legacy row");

        sweep_legacy_availability_rows(&cache, partition);

        assert!(
            cache.get_entry_async(&content_key).await.unwrap().is_none(),
            "the sweep must reclaim the bodies whose only reclaim pointer it removes"
        );
    }

    #[tokio::test]
    async fn the_legacy_sweep_leaves_a_cache_that_has_no_legacy_rows_alone() {
        // The legacy rows are the migration marker: with none present there is
        // nothing to migrate, and flushing content would cold-start a healthy
        // cache on every construction.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///current").unwrap();
        let content_key = content_cache_key(partition, &address, "v1");
        cache
            .put(&content_key, b"current body")
            .expect("seed a body");

        sweep_legacy_availability_rows(&cache, partition);

        assert!(
            cache.get_entry_async(&content_key).await.unwrap().is_some(),
            "a cache with no legacy rows must keep its content"
        );
    }

    #[tokio::test]
    async fn row_of_an_unknown_version_reports_no_validator() {
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///future").unwrap();
        let mut row = encode_avail("v-future");
        row[0] = AVAIL_VERSION + 1;
        cache
            .put(&availability_index_key(partition, &address), &row)
            .expect("seed a future-version row");

        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "a row this build cannot interpret must not answer the fallback"
        );
    }

    #[tokio::test]
    async fn write_through_publish_fences_a_concurrent_pre_write_read() {
        // A read snapshots the row, a write-through of a newer version lands,
        // and only then does the read's fill try to publish. The write's
        // validator must survive, and so must its content row.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let v1_content = content_cache_key(partition, &address, "v1");
        let v2_content = content_cache_key(partition, &address, "v2");

        // Steady state: v1 is the published validator.
        cache
            .put(&v1_content, b"v1-bytes")
            .expect("seed v1 content");
        let seed = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, seed, "v1").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string())
        );

        // A read starts and snapshots the row.
        let read_snapshot = snapshot_avail(&cache, partition, &address).await;

        // A write-through of v2 lands while that read is in flight.
        cache
            .put(&v2_content, b"v2-bytes")
            .expect("write v2 content");
        let write_snapshot = snapshot_avail(&cache, partition, &address).await;
        publish_mutation_impl(&cache, partition, &address, write_snapshot, "v2")
            .await
            .expect("publish v2");

        // The slow read finally publishes. The row moved, so it must not.
        cache
            .put(&v1_content, b"v1-bytes")
            .expect("read re-fills v1");
        let _ = record_latest_impl(&cache, partition, &address, read_snapshot, "v1").await;

        // The safety property: whatever the row ends up naming, it must not be
        // the validator the write superseded.
        //
        // It ends up naming nothing. A refused publish removes the row, because
        // a reader cannot tell whether the state that beat it is newer or older
        // than its own -- so it cannot leave a validator it knows differs from
        // the one it proved. Here the row held v2, which was correct, and the
        // refusal discards it: the cost of that rule is a lost fallback entry
        // when a read loses a race to a write. The next read re-seeds it.
        assert_ne!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string()),
            "the pre-write read must not republish the validator the write superseded"
        );
        assert!(
            cache
                .get_entry_async(&v2_content)
                .await
                .expect("lookup")
                .is_some(),
            "the fenced publish must not prune the write's content row"
        );
    }

    #[tokio::test]
    async fn clear_fences_a_concurrent_read_under_size_pressure() {
        // A read snapshots the row, a clear tombstones it, and cache pressure
        // then evicts everything it can before the read publishes. Losing the
        // tombstone must not restore the fill's licence to publish: an absent
        // row matches no snapshot.
        let (cache, _dir) = open_capped_cache(Some(64));
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();

        let read_snapshot = snapshot_avail(&cache, partition, &address).await;
        assert!(
            read_snapshot.is_some(),
            "an absent row is seeded, not skipped"
        );

        clear_latest_impl(&cache, partition, &generations(), &address)
            .await
            .expect("clear");

        // Blow past the budget. Availability rows are ordinary evictable rows,
        // and the tombstone is both the oldest and the smallest.
        for index in 0..8 {
            cache
                .put(
                    &content_cache_key(partition, &address, &format!("filler-{index}")),
                    &[b'x'; 64],
                )
                .expect("filler fill");
        }

        assert!(
            cache
                .get_entry_async(&availability_index_key(partition, &address))
                .await
                .expect("lookup")
                .is_none(),
            "the premise of this test is that size pressure took the tombstone"
        );

        let _ = record_latest_impl(&cache, partition, &address, read_snapshot, "v1").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "the cleared validator must not be republished after size pressure"
        );
    }

    #[tokio::test]
    async fn subtree_removal_and_reupload_cycle_cannot_restore_a_snapshot() {
        // The ABA construction: a subtree delete removes the row, the object is
        // re-uploaded, and it is deleted again. A per-address counter restarts
        // at zero on the removal and can land back on the value the slow read
        // captured; the row's nonce cannot be re-derived, so the snapshot never
        // matches again.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let parent = Url::parse("mem:///dir/").unwrap();
        let address = Url::parse("mem:///dir/obj").unwrap();

        let seed = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, seed, "v2").await;

        // A slow read snapshots the published row.
        let read_snapshot = snapshot_avail(&cache, partition, &address).await;

        // delete `dir/` -> re-upload -> delete `dir/` again.
        clear_subtree_impl(&cache, partition, &generations(), &parent).expect("subtree delete");
        let reupload_snapshot = snapshot_avail(&cache, partition, &address).await;
        publish_mutation_impl(&cache, partition, &address, reupload_snapshot, "v3")
            .await
            .expect("re-upload");
        clear_subtree_impl(&cache, partition, &generations(), &parent).expect("subtree delete");

        let _ = record_latest_impl(&cache, partition, &address, read_snapshot.clone(), "v2").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "a twice-deleted object must not regain a validator from a stale read"
        );

        // The assertion above holds for a reason weaker than the one under
        // test: the row is absent, so ANY expected value refuses. Recreate it
        // naming `v2` -- the validator the stale snapshot itself names -- so the
        // encoding and the validator both match and the NONCE is the only
        // difference left between the two rows. A constant nonce would make
        // them byte-identical and let the stale read publish below.
        let key = availability_index_key(partition, &address);
        let reborn = encode_avail("v2");
        assert_ne!(
            Some(&reborn),
            read_snapshot.as_ref(),
            "encoding one validator twice must not reproduce the same row"
        );
        assert!(
            compare_and_put_off_runtime(&cache, &key, None, reborn.clone())
                .await
                .expect("recreate the row"),
            "the row is absent, so the seed applies"
        );
        let _ = record_latest_impl(&cache, partition, &address, read_snapshot, "v2").await;
        // Both rows name `v2`, so "the row names v2" can no longer tell a
        // refusal from a landed publish. What distinguishes them is the bytes:
        // the successor's row must still be exactly what was written above, not
        // the stale read's re-publication of its own snapshot.
        let (current, _) = read_avail(&cache, partition, &address)
            .await
            .expect("the row is readable");
        assert_eq!(
            current.as_ref(),
            Some(&reborn),
            "a snapshot of a retired row must not publish against its successor, \
             even when both name the same validator"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn an_unreadable_row_neither_spins_nor_fails_the_read() {
        // The `entries` row is present but its blob cannot be read. Collapsing
        // that to "row absent" computes the same expected value on every pass
        // while the swap keeps refusing against the present row, so a retry
        // loop's exit condition is unreachable. And the failure must stay
        // best-effort: erroring here would fail or spare the caller's read
        // purely by whether it started before or after the fault.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let key = availability_index_key(partition, &address);
        let entry = cache.put(&key, &encode_avail("v1")).expect("seed row");

        // Replace the blob with a symlink to itself: the row still resolves,
        // and reading it fails with a loop error rather than NotFound (which
        // would self-heal into a clean miss). Unlinking it still works, so the
        // clear's fallback path is exercised rather than a stand-in failure.
        std::fs::remove_file(&entry.path).expect("unlink blob");
        std::os::unix::fs::symlink(&entry.path, &entry.path).expect("blob path becomes unreadable");

        assert_eq!(
            snapshot_avail(&cache, partition, &address).await,
            None,
            "an unreadable row yields no snapshot to publish against"
        );
        // Terminates, and reports nothing to the caller.
        let _ = record_latest_impl(&cache, partition, &address, None, "v2").await;

        // A clear must not spin either, and must still invalidate: an
        // invalidation that cannot converge drops the row outright.
        clear_latest_impl(&cache, partition, &generations(), &address)
            .await
            .expect("clear falls back to an unconditional removal");
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "the clear invalidated the fallback despite the unreadable row"
        );
    }

    #[tokio::test]
    async fn a_snapshotless_read_skips_the_availability_publish() {
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();

        let _ = record_latest_impl(&cache, partition, &address, None, "v1").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "a fill with no snapshot must not publish an unfenced validator"
        );
    }

    #[tokio::test]
    async fn a_first_fill_publishes_against_its_seeded_row() {
        // The fence must not cost the common case: a cold read seeds a
        // tombstone, and its own fill publishes against exactly that row.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///cold").unwrap();

        let snapshot = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, snapshot, "v1").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string()),
            "a cold read's own fill must publish"
        );
    }

    /// Two caches over one state root: `writable` for setting rows up, and
    /// `blocked`, whose CAS root is a regular file so every blob publication
    /// fails at `create_dir_all`. Models a cache whose disk refuses writes
    /// (ENOSPC) or whose SQLite is contended -- both ordinary conditions for a
    /// cache, and both reaching the same error path.
    ///
    /// Blocking the CAS root rather than the individual shards is what makes
    /// this deterministic: `encode_avail` picks a fresh random nonce, so the
    /// blob's shard is uniformly random and per-shard blocking leaves a
    /// one-in-however-many-shards-already-exist chance that the publication
    /// simply succeeds.
    ///
    /// `blocked` is opened FIRST, while the shared index is still empty: its
    /// crash recovery reaps `entries` rows whose blobs are missing, and every
    /// blob written later through `writable` is missing from `blocked`'s root.
    fn blocked_cache_pair() -> (Arc<Cache>, Arc<Cache>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_root = dir.path().join("state");
        let blocked_root = dir.path().join("blocked");
        std::fs::create_dir_all(&blocked_root).expect("blocked root");
        std::fs::write(blocked_root.join("sha256"), b"").expect("block the CAS root");
        let blocked = Cache::open(CacheConfig {
            state_root: state_root.clone(),
            cache_root: blocked_root,
        })
        .expect("blocked cache opens");
        let writable = Cache::open(CacheConfig {
            state_root,
            cache_root: dir.path().join("cache"),
        })
        .expect("writable cache opens");
        (Arc::new(writable), Arc::new(blocked), dir)
    }

    #[tokio::test]
    async fn a_racing_delete_survives_a_write_through_publish() {
        // The mainline delete-versus-write race. The write completes at the
        // backend, and the delete lands before the write publishes its
        // validator. Retrying the swap would read the delete's tombstone and
        // overwrite it, resurrecting a deleted object under the fallback.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();

        let seed = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, seed, "v0").await;

        // The write snapshots the row, then its backend write runs.
        let write_snapshot = snapshot_avail(&cache, partition, &address).await;

        // A delete completes during that window.
        clear_latest_impl(&cache, partition, &generations(), &address)
            .await
            .expect("delete");

        // Only now does the write publish.
        publish_mutation_impl(&cache, partition, &address, write_snapshot, "v1")
            .await
            .expect("publish is refused, not failed");

        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "a delete that landed during the write must not be overwritten by it"
        );
    }

    #[tokio::test]
    async fn a_write_through_publish_that_cannot_write_removes_the_stale_row() {
        // The backend write has already landed, so the availability row names
        // a validator this write superseded. If the swap cannot be written,
        // leaving that row is the one outcome that later serves the pre-write
        // body under the lost-backing fallback.
        let (writable, blocked, _dir) = blocked_cache_pair();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let key = availability_index_key(partition, &address);

        let seed = snapshot_avail(&writable, partition, &address).await;
        let _ = record_latest_impl(&writable, partition, &address, seed, "v0").await;
        let write_snapshot = snapshot_avail(&writable, partition, &address).await;
        assert_eq!(
            last_known_validator_impl(&writable, partition, &address).await,
            Some("v0".to_string())
        );

        publish_mutation_impl(&blocked, partition, &address, write_snapshot, "v1")
            .await
            .expect("an unwritable publish falls back to removal");

        // Assert the ROW is gone, not merely that no validator reads back: a
        // tombstone and an absent row both report `None`, so the weaker
        // assertion would pass without the fail-safe firing.
        assert!(
            writable
                .get_entry_async(&key)
                .await
                .expect("lookup")
                .is_none(),
            "the superseded validator's row must not survive a failed publish"
        );
    }

    #[tokio::test]
    async fn a_clear_that_cannot_write_removes_the_stale_row() {
        // Same shape for invalidation: the backend delete has landed, so a
        // tombstone that cannot be written must become a removal rather than
        // leaving the deleted object's validator answering.
        let (writable, blocked, _dir) = blocked_cache_pair();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let key = availability_index_key(partition, &address);

        let seed = snapshot_avail(&writable, partition, &address).await;
        let _ = record_latest_impl(&writable, partition, &address, seed, "v0").await;

        clear_latest_impl(&blocked, partition, &generations(), &address)
            .await
            .expect("an unwritable clear falls back to removal");

        // A tombstone would also read back as `None`, so assert the row itself
        // is gone -- otherwise this cannot distinguish the fail-safe from an
        // ordinary successful tombstone.
        assert!(
            writable
                .get_entry_async(&key)
                .await
                .expect("lookup")
                .is_none(),
            "a deleted object's row must not survive a failed clear"
        );
    }

    #[tokio::test]
    async fn a_cold_read_publishes_when_the_budget_holds_object_and_bookkeeping() {
        // Whenever the budget has room for the object plus its bookkeeping,
        // the seeded row survives the fill and the publish lands.
        let budget = 4096;
        let (cache, _dir) = open_capped_cache(Some(budget));
        let partition = "p";
        let address = Url::parse("mem:///big").unwrap();
        let content_key = content_cache_key(partition, &address, "v1");

        let snapshot = snapshot_avail(&cache, partition, &address).await;
        // Fill, then publish -- the order the read paths use.
        cache
            .put(&content_key, &vec![b'x'; budget as usize - 128])
            .expect("content fill");
        let _ = record_latest_impl(&cache, partition, &address, snapshot, "v1").await;

        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string()),
            "a cold read of a large object must still publish its validator"
        );
        assert!(
            cache.get_entry_async(&content_key).await.unwrap().is_some(),
            "and must keep the content that validator names"
        );
    }

    #[tokio::test]
    async fn a_budget_too_small_for_object_plus_bookkeeping_keeps_the_object() {
        // Pins the known limitation rather than hiding it. An object sized at
        // the whole budget cannot coexist with any bookkeeping row, so the
        // availability row -- the older and smaller candidate -- is evicted by
        // the fill and the publish then refuses. The address keeps its content
        // and loses its fallback.
        //
        // Ordering does not change this: the published row is the same size as
        // the seed it replaces, so publishing first merely means the fill
        // evicts the published row instead of the seed. The remedy is
        // configuration -- `max_object_bytes` well under `max_bytes`.
        let budget = 512u64;
        let partition = "p";
        let address = Url::parse("mem:///exact").unwrap();
        let content_key = content_cache_key(partition, &address, "v1");
        let body = vec![b'x'; budget as usize];

        let (cache, _dir) = open_capped_cache(Some(budget));
        let snapshot = snapshot_avail(&cache, partition, &address).await;
        cache.put(&content_key, &body).expect("content fill");
        let _ = record_latest_impl(&cache, partition, &address, snapshot, "v1").await;

        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "the bookkeeping row is the first eviction candidate at this budget"
        );
        assert!(
            cache.get_entry_async(&content_key).await.unwrap().is_some(),
            "the object itself is retained, and the strict path still serves it"
        );
    }

    #[tokio::test]
    async fn a_read_that_finds_no_validator_leaves_no_row_behind() {
        // Snapshotting an absent row seeds it, so the snapshot has to be gated
        // on the object existing. An existence-check-heavy workload -- an asset
        // resolver walking candidate paths -- would otherwise write one row and
        // one CAS blob per path it fails to find, and the default cache has no
        // size budget to reclaim them.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///missing").unwrap();
        let key = availability_index_key(partition, &address);

        // What the read path does when `lookup_etag` yields nothing: no
        // snapshot, hence no seed.
        let snapshot: Option<Vec<u8>> = None;
        let _ = record_latest_impl(&cache, partition, &address, snapshot, "v1").await;

        assert!(
            cache.get_entry_async(&key).await.expect("lookup").is_none(),
            "a probe of a nonexistent address must leave no availability row"
        );
    }

    #[tokio::test]
    async fn a_stream_tee_publishes_against_the_read_start_snapshot() {
        // A delete that completes while `inner.read` is still pending is
        // invisible to the tee's generation guard: the tee registers only after
        // `inner.read` returns, so the delete bumps nothing. The read-start
        // snapshot is the only evidence the tee carries that the world moved,
        // so the commit at EOF must publish against it rather than re-reading
        // the row -- a re-read would find the delete's tombstone and treat it
        // as the state to overwrite.
        use futures::StreamExt as _;

        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///streamed").unwrap();

        let seed = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, seed, "v0").await;

        // The read begins and snapshots the row.
        let read_snapshot = snapshot_avail(&cache, partition, &address).await;

        // A delete completes while `inner.read` is still pending. It bumps the
        // generations map, but no tee is registered yet, so nothing is marked.
        let generations = generations();
        clear_latest_impl(&cache, partition, &generations, &address)
            .await
            .expect("delete");

        // Only now does the read return a stream and the tee register.
        let (registration, start_generation) = TeeRegistration::register(generations, &address);
        assert_eq!(
            registration.current(),
            start_generation,
            "the delete landed before registration, so the guard sees nothing"
        );

        let body = b"old-body".to_vec();
        let put = cache
            .begin_streaming_put(&content_cache_key(partition, &address, "v1"), None)
            .expect("streaming put");
        let source: ReadStream = Box::pin(futures::stream::iter([Ok(bytes::Bytes::from(
            body.clone(),
        ))]));
        let guard = ReadGuard::arm(
            &cache,
            partition,
            &address,
            &ProvenValidator::proved(&cached_object_info(
                address.clone(),
                body.len() as u64,
                Some("v1".to_string()),
            ))
            .expect("a read result with a validator"),
            read_snapshot.as_deref(),
        );
        let mut teed = tee_into_cache(
            source,
            put,
            Arc::clone(&cache),
            partition.to_string(),
            address.clone(),
            "v1".to_string(),
            read_snapshot,
            guard,
            Some(body.len() as u64),
            registration,
            start_generation,
            CacheWatchState::new(false).registrar(),
        );
        while teed.next().await.is_some() {}

        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            None,
            "a stream that began before a delete must not republish its validator"
        );
    }

    #[test]
    fn an_empty_etag_is_not_a_provable_validator() {
        // The availability encoding treats an empty etag as a tombstone, so a
        // backend reporting `Some("")` can never have a validator published.
        // The strict path has no such filter: it would key a content row on the
        // empty string, and since every version reports the same empty etag the
        // key never changes -- so an out-of-band update would go on being
        // served from the first fill indefinitely. Reject it at the type whose
        // whole job is to mean "a validator I can rely on".
        let address = Url::parse("mem:///obj").unwrap();
        assert!(
            ProvenValidator::proved(&cached_object_info(address.clone(), 1, Some(String::new())))
                .is_none(),
            "an empty etag is not a usable validator"
        );
        assert!(
            ProvenValidator::proved(&cached_object_info(address.clone(), 1, None)).is_none(),
            "an absent etag is not a validator"
        );
        assert!(
            ProvenValidator::proved(&cached_object_info(address, 1, Some("v1".to_string())))
                .is_some(),
            "an ordinary validator is usable"
        );
    }

    #[tokio::test]
    async fn a_refused_read_publish_does_not_leave_a_validator_it_knows_is_stale() {
        // Two reads race an out-of-band change. R1 is slow: it snapshots the
        // row, reads v1, and publishes late. R2 snapshots the same row, reads
        // v2, and loses the swap to R1. R1 publishing v1 is unavoidable -- the
        // layer cannot see an out-of-band mutation -- but R2 knows v2 is
        // current AND knows the row now holds something else, and must not
        // throw that away: a refusal is not proof that a NEWER state won.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();

        let seed = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, seed, "v0").await;

        // Both reads begin against the same row.
        let r1 = snapshot_avail(&cache, partition, &address).await;
        let r2 = snapshot_avail(&cache, partition, &address).await;
        assert_eq!(r1, r2, "both reads begin against the same row");

        // R1 (slow, holding the older validator) publishes first and wins.
        let _ = record_latest_impl(&cache, partition, &address, r1, "v1").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string()),
            "R1 took the row"
        );

        // R2, which read v2, is refused.
        let _ = record_latest_impl(&cache, partition, &address, r2, "v2").await;

        assert_ne!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v1".to_string()),
            "a reader that knows v2 is current must not leave v1 answering the fallback"
        );
    }

    #[tokio::test]
    async fn a_read_fill_inside_a_write_window_cannot_leave_the_pre_write_validator() {
        // The refusal path. A read-path fill is NOT necessarily newer than the
        // write it beats to the row: it republishes the validator IT read at
        // its own start, which here is the one the write is superseding. Both
        // publish exactly once by design, so the write cannot retry -- if a
        // refusal left the row alone, the row would name the pre-write
        // validator with its bytes cached, and a later stat outage would serve
        // the pre-write body as current.
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///obj").unwrap();
        let v0_content = content_cache_key(partition, &address, "v0");

        // Steady state: the row names v0. Its content row has been evicted,
        // which is the ordinary state for a capped cache -- availability rows
        // are tens of bytes and survive, content rows do not.
        let seed = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, seed, "v0").await;

        // Read R and write W both snapshot the same unchanged row.
        let read_snapshot = snapshot_avail(&cache, partition, &address).await;
        let write_snapshot = snapshot_avail(&cache, partition, &address).await;
        assert_eq!(
            read_snapshot, write_snapshot,
            "both operations begin against the same row"
        );

        // R's read returns v0 (still current at its stat), re-fills v0's
        // content, and publishes -- winning the row while W is still uploading.
        cache
            .put(&v0_content, b"v0-bytes")
            .expect("read re-fills v0");
        let _ = record_latest_impl(&cache, partition, &address, read_snapshot, "v0").await;
        assert_eq!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v0".to_string()),
            "the read's fill took the row"
        );

        // Only now does W complete at the backend with v1 and try to publish.
        publish_mutation_impl(&cache, partition, &address, write_snapshot, "v1")
            .await
            .expect("a refused publish is not an error");

        assert_ne!(
            last_known_validator_impl(&cache, partition, &address).await,
            Some("v0".to_string()),
            "the row must not still name the validator the write superseded"
        );
    }

    #[tokio::test]
    async fn a_failed_watched_object_clear_still_fences_in_flight_reads() {
        // The single-object twin of the subtree case. A watch event invalidates
        // one address, and the fence must be raised before the removal is
        // attempted -- the removal is a SQLite statement that can block or
        // fail, and until the fence is up a draining read tee can commit
        // against an unchanged generation and an unchanged row.
        //
        // A read-only cache refuses the removal outright, which pins the
        // invariant: whatever the removal does, the fence is already up.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open_with_options(
            CacheConfig {
                state_root: dir.path().join("state"),
                cache_root: dir.path().join("cache"),
            },
            CacheOptions {
                coordination: ovstorage_cache::CacheCoordination::ReadOnly,
                ..CacheOptions::default()
            },
        )
        .expect("cache opens");

        let generations = generations();
        let address = Url::parse("mem:///watched").unwrap();
        let (registration, start) = TeeRegistration::register(generations.clone(), &address);

        let cleared = clear_watched_object(&cache, "p", &generations, &address);

        assert!(
            cleared.is_err(),
            "the premise of this test is that the removal could not run"
        );
        assert_ne!(
            registration.current(),
            start,
            "an in-flight read must be fenced even when the removal fails"
        );
    }

    #[tokio::test]
    async fn watched_object_clear_reclaims_the_body_named_by_its_row() {
        let (cache, _dir) = open_cache();
        let partition = "p";
        let address = Url::parse("mem:///watched").unwrap();
        let content_key = content_cache_key(partition, &address, "v1");
        cache
            .put(&content_key, b"warm unbudgeted body")
            .expect("seed body");
        let snapshot = snapshot_avail(&cache, partition, &address).await;
        let _ = record_latest_impl(&cache, partition, &address, snapshot, "v1").await;

        clear_watched_object(&cache, partition, &generations(), &address)
            .expect("watch invalidation");

        assert!(
            cache
                .get_entry_async(&content_key)
                .await
                .expect("lookup")
                .is_none(),
            "removing the only availability pointer must reclaim its content row"
        );
    }

    #[tokio::test]
    async fn a_failed_subtree_sweep_still_fences_and_still_sweeps_content() {
        // A subtree invalidation does three things, and a `?` between them
        // skips the rest. Both later steps are asserted here:
        //
        //  - the generation bump, the only step that reaches a read tee
        //    already streaming a child. Without it the tee's generation check
        //    passes, its read-start snapshot still matches the child's
        //    untouched row, and its commit republishes the validator of an
        //    object the caller just deleted.
        //  - the content sweep, which a `?` on the availability sweep skips.
        //
        // Only the AVAILABILITY sweep is made to fail, via a trigger on that
        // key namespace. A read-only cache would fail both, and then the
        // content assertion could not tell a `?` from running both.
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Arc::new(
            Cache::open(CacheConfig {
                state_root: dir.path().join("state"),
                cache_root: dir.path().join("cache"),
            })
            .expect("cache opens"),
        );
        let partition = "p";
        let parent = Url::parse("mem:///dir/").unwrap();
        let child = Url::parse("mem:///dir/child").unwrap();

        let seed = snapshot_avail(&cache, partition, &child).await;
        let _ = record_latest_impl(&cache, partition, &child, seed, "v0").await;
        let content_key = content_cache_key(partition, &child, "v0");
        cache
            .put(&content_key, b"child-body")
            .expect("content fill");

        let generations = generations();
        let (registration, start) = TeeRegistration::register(generations.clone(), &child);

        // Refuse deletes in the availability namespace only. A second
        // connection is enough: triggers are schema-level, and the cache's own
        // connection sees it on its next statement.
        let side = rusqlite::Connection::open(dir.path().join("state").join("index.sqlite"))
            .expect("side connection");
        side.execute_batch(
            "CREATE TRIGGER block_availability BEFORE DELETE ON entries \
             WHEN OLD.resolved_target LIKE 'p' || char(2) || '%' \
             BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
        )
        .expect("install trigger");
        drop(side);

        let swept = clear_subtree_impl(&cache, partition, &generations, &parent);

        assert!(
            swept.is_err(),
            "the premise of this test is that the availability sweep could not run"
        );
        assert_ne!(
            registration.current(),
            start,
            "an in-flight read under the subtree must be fenced even when a sweep fails"
        );
        assert!(
            cache
                .get_entry_async(&content_key)
                .await
                .expect("lookup")
                .is_none(),
            "the content sweep must still run when the availability sweep failed"
        );
    }
}

#[cfg(test)]
mod off_runtime_tests {
    //! Which index removals on async paths run on the blocking pool, and which
    //! must not.
    //!
    //! Two halves. The first starves the blocking pool: a passing functional
    //! test cannot show a hop, because the removal produces the same rows
    //! either way, so the runtime is built with exactly one blocking thread and
    //! that thread is occupied — anything that hops has to wait for it and
    //! anything that runs inline finishes immediately.
    //!
    //! The second half is the other direction, and it is the one the hops
    //! answer to: the removals that must stay inline are the ones whose step
    //! has to be indivisible from what precedes it. A future is droppable only
    //! where it yields, so these poll by hand and inspect the cache at every
    //! yield — see [`dropped_at_an_unprotected_yield`] and the test on
    //! [`remove_index_off_runtime`].
    use super::*;
    use ovstorage_cache::CompareAndPutPhase;
    use std::future::Future;
    use std::sync::mpsc;
    use std::task::{Context, Waker};
    use std::time::Duration;

    fn open_cache() -> (Arc<Cache>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(CacheConfig {
            state_root: dir.path().join("state"),
            cache_root: dir.path().join("cache"),
        })
        .expect("cache opens");
        (Arc::new(cache), dir)
    }

    fn one_blocking_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("runtime builds")
    }

    /// Occupy the runtime's only blocking thread until the returned sender is
    /// used, and return a handle that resolves once it is released.
    async fn occupy_blocking_pool() -> (mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
        let (release, wait) = mpsc::channel::<()>();
        let (started, running) = mpsc::channel::<()>();
        let occupier = tokio::task::spawn_blocking(move || {
            started.send(()).expect("the test is still waiting");
            let _ = wait.recv();
        });
        running.recv().expect("the blocking thread starts");
        (release, occupier)
    }

    #[test]
    fn remove_index_off_runtime_waits_for_a_blocking_thread() {
        let runtime = one_blocking_thread();
        let (cache, _dir) = open_cache();
        runtime.block_on(async {
            let (release, occupier) = occupy_blocking_pool().await;
            let key = availability_index_key("p", &Url::parse("mem:///obj").unwrap());
            let mut removal = Box::pin(remove_index_off_runtime(&cache, &key));

            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut removal)
                    .await
                    .is_err(),
                "the removal completed while the blocking pool was fully occupied, \
                 so it ran on the runtime worker instead of hopping"
            );

            release.send(()).expect("the occupier is still waiting");
            occupier.await.expect("the occupier finishes");
            removal
                .await
                .expect("the removal completes once a thread frees");
        });
    }

    #[test]
    fn a_publish_that_falls_back_to_removal_waits_for_a_blocking_thread() {
        // The removal reached through a call site rather than the helper
        // directly: `settled_by_removal` is what `record_latest_impl` uses on
        // both of its fail-safe exits.
        let runtime = one_blocking_thread();
        let (cache, _dir) = open_cache();
        runtime.block_on(async {
            let address = Url::parse("mem:///obj").unwrap();
            let key = availability_index_key("p", &address);
            let (release, occupier) = occupy_blocking_pool().await;
            let mut settled = Box::pin(settled_by_removal(&cache, &address, &key));

            assert!(
                tokio::time::timeout(Duration::from_millis(250), &mut settled)
                    .await
                    .is_err(),
                "the fail-safe removal completed while the blocking pool was fully \
                 occupied, so it ran on the runtime worker instead of hopping"
            );

            release.send(()).expect("the occupier is still waiting");
            occupier.await.expect("the occupier finishes");
            assert_eq!(settled.await, PublishOutcome::Settled);
        });
    }

    /// A bound on the hand-driven polling below. Each iteration sleeps a
    /// millisecond, so this is seconds of grace for a `spawn_blocking` hop to
    /// come back, and a bounded failure rather than a hung test if it never
    /// does.
    const MAX_POLLS: usize = 5_000;

    /// Poll `future` by hand and drop it at the first point it yields with
    /// `unprotected` reporting true — durable state already changed and the
    /// step that keeps it reachable not yet run. Reports whether such a point
    /// exists.
    ///
    /// This is the whole question a hop raises. A future can only be dropped
    /// where it yields, so a step that runs with no await between it and the
    /// thing that protects it is indivisible from the caller's point of view,
    /// and one that awaits is not. `false` here means the step ran to
    /// completion without ever exposing the intermediate state — the property
    /// the inline `remove_index` calls exist to hold.
    async fn dropped_at_an_unprotected_yield<F: Future>(
        future: F,
        unprotected: impl Fn() -> bool,
    ) -> bool {
        let mut future = Box::pin(future);
        // A no-op waker: nothing reschedules this future, so the loop below is
        // the only thing driving it, which is what makes every yield point
        // observable.
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..MAX_POLLS {
            if future.as_mut().poll(&mut context).is_ready() {
                return false;
            }
            if unprotected() {
                drop(future);
                return true;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the future under test never completed");
    }

    /// The validator the availability row names, read synchronously so a yield
    /// predicate can call it.
    fn row_names(cache: &Cache, partition: &str, address: &Url) -> Option<String> {
        cache
            .get_entry(&availability_index_key(partition, address))
            .ok()
            .flatten()
            .and_then(|object| parse_avail(&object.bytes))
    }

    fn body_present(cache: &Cache, partition: &str, address: &Url, etag: &str) -> bool {
        cache
            .get_entry(&content_cache_key(partition, address, etag))
            .ok()
            .flatten()
            .is_some()
    }

    #[test]
    fn an_unpolled_publish_drops_its_guard_before_any_swap_can_start() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime builds");
        let (cache, _dir) = open_cache();
        runtime.block_on(async {
            let partition = "p";
            let address = Url::parse("mem:///unpolled-publish").unwrap();
            let seed = snapshot_avail(&cache, partition, &address).await;
            let _ = record_latest_impl(&cache, partition, &address, seed, "v1").await;
            cache
                .put(&content_cache_key(partition, &address, "v1"), b"old body")
                .expect("the superseded body stores");

            let snapshot = snapshot_avail(&cache, partition, &address).await;
            let proof = ProvenValidator::proved(&cached_object_info(
                address.clone(),
                8,
                Some("v2".to_string()),
            ))
            .expect("a read result with a validator");
            let guard = ReadGuard::arm(&cache, partition, &address, &proof, snapshot.as_deref());
            let publish = record_latest_guarded_impl(
                &cache,
                partition,
                &address,
                snapshot,
                "v2",
                Some(guard),
            );

            drop(publish);

            assert_eq!(
                row_names(&cache, partition, &address),
                None,
                "dropping before the first poll must clear the superseded availability row"
            );
            assert!(
                !body_present(&cache, partition, &address, "v1"),
                "the unpolled future's guard must reclaim the superseded body"
            );
        });
    }

    #[test]
    fn a_publish_detached_on_either_side_of_its_swap_completes_cleanup() {
        // Pause the blocking task on either side of its guarded write. Once
        // spawned, the task owns the guard, so dropping the async caller must
        // let it finish the publish, superseded-body prune and disarm.
        let runtime = tokio::runtime::Runtime::new().expect("runtime builds");
        runtime.block_on(async {
            for paused_phase in [CompareAndPutPhase::Observed, CompareAndPutPhase::Published] {
                let (cache, _dir) = open_cache();
                let partition = "p";
                let address =
                    Url::parse(&format!("mem:///cancelled-publish/{paused_phase:?}")).unwrap();

                // A first validator with a body, so the publish below has a
                // real content row to prune.
                let seed = snapshot_avail(&cache, partition, &address).await;
                let _ = record_latest_impl(&cache, partition, &address, seed, "v1").await;
                cache
                    .put(&content_cache_key(partition, &address, "v1"), b"old body")
                    .expect("the superseded body stores");

                let snapshot = snapshot_avail(&cache, partition, &address).await;
                let proof = ProvenValidator::proved(&cached_object_info(
                    address.clone(),
                    8,
                    Some("v2".to_string()),
                ))
                .expect("a read result with a validator");
                let guard =
                    ReadGuard::arm(&cache, partition, &address, &proof, snapshot.as_deref());

                let key = availability_index_key(partition, &address);
                let seam_key = key.clone();
                let (paused_tx, paused_rx) = mpsc::channel();
                let (release_tx, release_rx) = mpsc::channel();
                let release_rx = Arc::new(Mutex::new(release_rx));
                cache.set_compare_and_put_seam(Arc::new(move |target, phase| {
                    if target == seam_key && phase == paused_phase {
                        paused_tx
                            .send(())
                            .expect("the test is waiting at this swap phase");
                        release_rx
                            .lock()
                            .expect("release lock")
                            .recv_timeout(Duration::from_secs(5))
                            .expect("the detached publish is released");
                    }
                }));

                let mut publish = Box::pin(record_latest_guarded_impl(
                    &cache,
                    partition,
                    &address,
                    snapshot,
                    "v2",
                    Some(guard),
                ));
                let mut context = Context::from_waker(Waker::noop());
                assert!(
                    publish.as_mut().poll(&mut context).is_pending(),
                    "the publish must yield while its blocking task is paused"
                );
                paused_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("the blocking task reaches the selected phase");
                drop(publish);

                let expected_while_paused = match paused_phase {
                    CompareAndPutPhase::Observed => "v1",
                    CompareAndPutPhase::Published => "v2",
                };
                assert_eq!(
                    row_names(&cache, partition, &address).as_deref(),
                    Some(expected_while_paused),
                    "the seam must expose the selected side of the guarded write"
                );

                release_tx.send(()).expect("release the blocking task");
                for _ in 0..200 {
                    if !body_present(&cache, partition, &address, "v1") {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert!(
                    !body_present(&cache, partition, &address, "v1"),
                    "the detached publish task must prune the superseded body before disarming"
                );
                assert_eq!(
                    row_names(&cache, partition, &address).as_deref(),
                    Some("v2"),
                    "the detached task must finish the publish and leave its validator live"
                );
            }
        });
    }

    #[test]
    fn a_clear_cancelled_after_its_tombstone_reclaims_a_republished_body() {
        // Pause after the tombstone commits. The async caller is dropped, then
        // the same validator body is republished before the detached task may
        // continue. Cleanup must still run after that publication; a guard
        // owned by the async frame fires too early and strands the replacement.
        let runtime = tokio::runtime::Runtime::new().expect("runtime builds");
        let (cache, _dir) = open_cache();
        runtime.block_on(async {
            let partition = "p";
            let address = Url::parse("mem:///cancelled-clear").unwrap();
            let generations = Mutex::new(GenerationMap::new());
            let content_key = content_cache_key(partition, &address, "v1");

            let seed = snapshot_avail(&cache, partition, &address).await;
            let _ = record_latest_impl(&cache, partition, &address, seed, "v1").await;
            cache.put(&content_key, b"first body").expect("body stores");

            let key = availability_index_key(partition, &address);
            let seam_key = key.clone();
            let (published_tx, published_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let release_rx = Arc::new(Mutex::new(release_rx));
            cache.set_compare_and_put_seam(Arc::new(move |target, phase| {
                if target == seam_key && phase == CompareAndPutPhase::Published {
                    published_tx
                        .send(())
                        .expect("the test is waiting for the tombstone");
                    release_rx
                        .lock()
                        .expect("release lock")
                        .recv_timeout(Duration::from_secs(5))
                        .expect("the tombstone is released");
                }
            }));

            let mut clear = Box::pin(clear_latest_impl(&cache, partition, &generations, &address));
            let mut context = Context::from_waker(Waker::noop());
            let mut published = false;
            for _ in 0..MAX_POLLS {
                assert!(
                    clear.as_mut().poll(&mut context).is_pending(),
                    "the clear completed before its published seam paused it"
                );
                if published_rx.try_recv().is_ok() {
                    published = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert!(published, "the tombstone never reached its published seam");
            drop(clear);

            cache.remove_index(&content_key).expect("remove first body");
            cache
                .put(&content_key, b"replacement body")
                .expect("republish the same validator body");
            release_tx.send(()).expect("release the blocking clear");

            for _ in 0..200 {
                if !body_present(&cache, partition, &address, "v1") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(
                !body_present(&cache, partition, &address, "v1"),
                "the detached clear must reclaim the body republished before it resumed"
            );
            assert_eq!(
                row_names(&cache, partition, &address),
                None,
                "the tombstone names no validator"
            );
        });
    }

    #[test]
    fn a_clear_exhausting_cas_retries_reclaims_the_row_it_removes() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime builds");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = CacheConfig {
            state_root: dir.path().join("state"),
            cache_root: dir.path().join("cache"),
        };
        let cache = Arc::new(Cache::open(config).expect("cache opens"));
        runtime.block_on(async {
            let partition = "p";
            let address = Url::parse("mem:///contended-clear").unwrap();
            let generations = Mutex::new(GenerationMap::new());
            let key = availability_index_key(partition, &address);

            let seed = snapshot_avail(&cache, partition, &address).await;
            let _ = record_latest_impl(&cache, partition, &address, seed, "v0").await;

            let mut contested_rows = Vec::new();
            for attempt in 0..AVAIL_CAS_ATTEMPTS {
                let validator = format!("raced-{attempt}");
                cache
                    .put(
                        &content_cache_key(partition, &address, &validator),
                        validator.as_bytes(),
                    )
                    .expect("contending body stores");
                let encoded = encode_avail(&validator);
                let entry = cache
                    .put(&format!("seam://availability/{attempt}"), &encoded)
                    .expect("contending availability object stores");
                contested_rows.push((entry.cas_key, encoded.len() as u64));
            }

            let side = Arc::new(Mutex::new(
                rusqlite::Connection::open(dir.path().join("state").join("index.sqlite"))
                    .expect("side connection opens"),
            ));
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let seam_attempts = Arc::clone(&attempts);
            let seam_side = Arc::clone(&side);
            let seam_key = key.clone();
            cache.set_compare_and_put_seam(Arc::new(move |target, phase| {
                if target != seam_key || phase != CompareAndPutPhase::Observed {
                    return;
                }
                let attempt = seam_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (cas_key, size) = &contested_rows[attempt];
                seam_side
                    .lock()
                    .expect("side connection lock")
                    .execute(
                        "UPDATE entries SET cas_key = ?2, size = ?3 \
                         WHERE resolved_target = ?1",
                        rusqlite::params![target, cas_key, size],
                    )
                    .expect("contending row publishes");
            }));

            let removal_key = key.clone();
            let (removed_tx, removed_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let release_rx = Arc::new(Mutex::new(release_rx));
            cache.set_remove_index_returning_seam(Arc::new(move |target| {
                if target == removal_key {
                    removed_tx
                        .send(())
                        .expect("the test is waiting for exact row removal");
                    release_rx
                        .lock()
                        .expect("release lock")
                        .recv_timeout(Duration::from_secs(5))
                        .expect("the detached removal is released");
                }
            }));

            let mut clear = Box::pin(clear_latest_impl(&cache, partition, &generations, &address));
            let mut context = Context::from_waker(Waker::noop());
            let mut removed = false;
            for _ in 0..MAX_POLLS {
                assert!(
                    clear.as_mut().poll(&mut context).is_pending(),
                    "the clear completed before its exact-removal seam paused it"
                );
                if removed_rx.try_recv().is_ok() {
                    removed = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert!(removed, "fall-through never removed its exact row");

            assert_eq!(
                attempts.load(std::sync::atomic::Ordering::SeqCst),
                AVAIL_CAS_ATTEMPTS,
                "every bounded CAS attempt must be contested before fall-through"
            );
            let last = format!("raced-{}", AVAIL_CAS_ATTEMPTS - 1);
            assert!(
                cache
                    .get_entry(&availability_index_key(partition, &address))
                    .expect("availability lookup succeeds")
                    .is_none(),
                "fall-through must remove the availability row rather than tombstoning it"
            );
            assert!(
                body_present(&cache, partition, &address, &last),
                "the seam must pause before cleanup derived from the removed row"
            );
            drop(clear);
            release_tx.send(()).expect("release the detached removal");

            for _ in 0..200 {
                if !body_present(&cache, partition, &address, &last) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(
                !body_present(&cache, partition, &address, &last),
                "cancelling the async clear must not stop its detached task from reclaiming \
                 the body named by the exact row it removed"
            );
        });
    }

    #[test]
    fn a_stale_tee_discards_its_body_before_it_can_yield() {
        // A tee whose generation moved committed a body under a validator the
        // backend no longer holds, so no read will look it up and the write's
        // `MutationGuard` reclaims the validator the write superseded, not this
        // one. The discard is therefore the only thing that can free it, and it
        // has to run before the first await in the branch.
        let runtime = tokio::runtime::Runtime::new().expect("runtime builds");
        let (cache, _dir) = open_cache();
        runtime.block_on(async {
            let partition = "p";
            let address = Url::parse("mem:///stale-tee").unwrap();
            let generations = Mutex::new(GenerationMap::new());

            cache
                .put(&content_cache_key(partition, &address, "v2"), b"tee body")
                .expect("the committed tee body stores");
            let snapshot = snapshot_avail(&cache, partition, &address).await;

            let dropped = dropped_at_an_unprotected_yield(
                finalize_committed_tee_impl(
                    &cache,
                    partition,
                    &generations,
                    &address,
                    TeeCommit {
                        snapshot,
                        etag: "v2",
                        current_generation: 2,
                        start_generation: 1,
                    },
                ),
                || body_present(&cache, partition, &address, "v2"),
            )
            .await;

            assert!(
                !dropped,
                "the finalize yielded with the stale tee's body still indexed, which is \
                 a body nothing can reach"
            );
            assert!(
                !body_present(&cache, partition, &address, "v2"),
                "control: the finalize must have discarded the stale tee's body"
            );
        });
    }
}
