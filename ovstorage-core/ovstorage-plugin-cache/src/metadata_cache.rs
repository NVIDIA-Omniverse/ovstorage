// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `MetadataCacheWrapper` provides `stat`/`list` caching over [`MetadataCache`],
//! list-backed stat for opted-in routes, principal-scoped cache keys, and a
//! complete bypass for broker-resolved OAuth metadata, with parent-prefix
//! invalidation on mutations and watch-event invalidation on
//! `watch_directory` streams.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ovstorage_cache::metadata::*;

use crate::layers::{METADATA_CACHE_KIND, descriptor};
use crate::notification_drain::{
    CacheWatchState, GapSweepStream, MANAGED_NOTIFICATION_DRAIN_EXTENSION, parse_watch_invalidation,
};
use crate::*;

use super::{cache_config_field, config_u64, ext};

/// [`WrapperFactory`] for the `metadata_cache` wrapper kind
/// ([`METADATA_CACHE_KIND`]).
#[derive(Default)]
pub struct MetadataCacheWrapperFactory {
    /// When set, created wrappers reuse a host-owned cache instance rather than
    /// building one from config.
    cache: Option<Arc<MetadataCache>>,
}

impl MetadataCacheWrapperFactory {
    /// Build a factory whose wrappers reuse `cache`, ignoring the
    /// `max_entries`/`ttl_seconds` config keys.
    pub fn with_cache(cache: Arc<MetadataCache>) -> Self {
        Self { cache: Some(cache) }
    }
}

#[async_trait]
impl WrapperFactory for MetadataCacheWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        let mut descriptor = descriptor(METADATA_CACHE_KIND, LayerType::Wrapper, false);
        descriptor.config_schema = vec![
            cache_config_field(
                "max_entries",
                "Max entries",
                ConfigFieldKind::Integer,
                false,
                "Optional cap on cached metadata entries (evicts least-recently-used beyond it)",
            ),
            cache_config_field(
                "ttl_seconds",
                "TTL seconds",
                ConfigFieldKind::Integer,
                false,
                "Optional time-to-live for cached metadata entries, in seconds",
            ),
            cache_config_field(
                "watch_invalidation",
                "Watch invalidation",
                ConfigFieldKind::Bool,
                false,
                "Open background watches for watch-capable roots and invalidate cached metadata \
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
                let mut cache_config = MetadataCacheConfig::default();
                if let Some(value) = config.get("max_entries") {
                    cache_config.max_entries = Some(config_u64(value, "max_entries")? as usize);
                }
                if let Some(value) = config.get("ttl_seconds") {
                    cache_config.ttl_seconds = Some(config_u64(value, "ttl_seconds")?);
                }
                let cache = Arc::new(MetadataCache::new(&cache_config));
                cache.spawn_ttl_sweeper(Duration::from_secs(60));
                cache
            }
        };
        let watch_invalidation = parse_watch_invalidation(config)?;
        let watch_inner = inner.clone();
        let wrapper = Arc::new(MetadataCacheWrapper {
            name: name.to_string(),
            descriptor: self.descriptor(),
            watch_state: CacheWatchState::new(watch_invalidation),
            inner,
            cache,
        });
        // Own the notification drains here so they travel with the cache layer
        // (host-agnostic). Held `Weak` so a drain never pins the wrapper;
        // each pulls this layer's own `watch_directory` (invalidating this cache
        // and, through the stacked wrappers below, the caches beneath it).
        let sweep_cache = Arc::clone(&wrapper.cache);
        wrapper.watch_state.start(
            wrapper.clone() as Arc<dyn Layer>,
            watch_inner,
            watch_invalidation,
            Arc::new(move |prefix| {
                sweep_cache.invalidate_prefix(prefix);
                sweep_cache.invalidate_lists_containing(prefix);
            }),
        );
        Ok(wrapper)
    }
}

/// Caches `stat`/`list` metadata, preserving the host metadata-cache
/// behavior over the [`MetadataCache`]. `stat` is served
/// from the `Stat` cache (non-directory; the row's cost flags must cover the
/// request's); `list` fills a `List` entry plus a per-file `Stat` entry (so
/// later `stat`s hit). Rows are one per address and record the cost flags
/// (`full_metadata`, `versioned_address`) they were fetched under; a request
/// the row covers is served, a wider one goes upstream once under the union
/// and replaces the row. Rows a listing fills record only the
/// `versioned_address` flag the listing was asked to carry, never
/// `full_metadata`, which only a direct `stat` can vouch for. Mutations
/// (`write`/`delete`/`copy`/`rename`/`create_directory`/`delete_directory`/
/// `update_metadata`) invalidate the affected address and any parent listings,
/// including parent listings.
///
/// An eligible successful direct `stat` fills the `Stat` cache under its lookup
/// key, so repeated direct stats hit. The list-backed stat fallback also
/// lives here: an eligible stat miss is
/// answered from the parent listing — cached, or freshly fetched for routes
/// whose `inner.root_info_for` capabilities opt in via
/// `wants_list_backed_stat` — before the direct backend stat runs.
///
/// `stat` requests carrying [`ext::RESOLVED_OAUTH_CREDENTIAL`] bypass every
/// metadata-cache lookup and fill. Principal scoping prevents cross-principal
/// reuse, but it cannot represent credential revocation or replacement within
/// one principal's slot. Delegating these requests ensures a later request
/// after revocation cannot reuse metadata obtained with the prior bearer. The
/// matching `list` guard is forward-looking: it protects any caller that stamps
/// the reference, while the broker currently propagates it only through
/// `stat`, `read`, and `materialize`.
///
/// **Staleness contract.** Cached entries carry the full `ObjectInfo` a
/// principal saw at fill time — including principal-specific
/// `effective_permissions` — and invalidation is mutation/watch-driven only.
/// A pure policy change (no data mutation) therefore keeps serving the
/// pre-change metadata until the entry's TTL expires. A policy-epoch key
/// component can tighten this
/// once the policy epoch travels in request extensions.
struct MetadataCacheWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    watch_state: CacheWatchState,
    inner: LayerHandle,
    cache: Arc<MetadataCache>,
}

/// Outcome of the list-backed stat probe. `Found`/`NotFound` are
/// authoritative: a cached or freshly fetched parent listing answers the stat
/// without asking the backend; `NotFound` becomes the stat's error.
/// `Unavailable` falls through to the direct backend stat.
enum ListBackedStat {
    Found(Box<ObjectInfo>),
    NotFound,
    Unavailable,
}

impl MetadataCacheWrapper {
    /// The cache scope of a request: the principal carried in the
    /// [`ext::PRINCIPAL_ID`] extension, or `None` for anonymous /
    /// single-identity hosts. The encoding is injective by
    /// construction — valid UTF-8 ids scope as `s:<id>`, anything else as
    /// `b:<hex>` — so two distinct principal byte strings can never collapse
    /// into one scope (lossy decoding would map every invalid byte to
    /// U+FFFD, merging distinct malformed ids), and neither class can
    /// collide with the other or with anonymous.
    fn principal_of(extensions: &Extensions) -> Option<String> {
        extensions
            .get(ext::PRINCIPAL_ID)
            .map(|bytes| match std::str::from_utf8(bytes) {
                Ok(id) => format!("s:{id}"),
                Err(_) => {
                    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
                    encoded.push_str("b:");
                    for byte in bytes {
                        use std::fmt::Write as _;
                        let _ = write!(encoded, "{byte:02x}");
                    }
                    encoded
                }
            })
    }

    /// Drop the address's `Stat` entry and any parent `List`s containing it.
    fn invalidate_for(&self, address: &Url) {
        self.cache.invalidate_address(address);
        self.cache.invalidate_lists_containing(address);
    }

    /// Fill the `List` entry + per-file `Stat` entries from a list response
    /// under `principal`'s scope when the options are cacheable.
    fn store_list(
        &self,
        prefix: &Url,
        options: &ListOptions,
        page: &ListPage,
        principal: Option<&str>,
    ) {
        if !crate::routing::list_is_cacheable(prefix, options) {
            return;
        }
        // A listing vouches only for the pin it was asked to carry: under the
        // flag every versioning backend pays for the pin on each file entry,
        // so its rows may answer a flagged stat. No listing carries the
        // per-object metadata a `full_metadata` stat pays for (S3
        // `ListObjectsV2` and Azure `List Blobs` return none), so its rows
        // never claim that flag and such a stat reaches the backend.
        let flags = CostFlags {
            full_metadata: false,
            versioned_address: options.versioned_address,
        };
        let mut retained = self.cache.insert(
            MetadataCacheKey {
                kind: MetadataKind::List,
                principal_id: principal.map(str::to_string),
                // The DIRECTORY spelling of the node, so `list docs` and
                // `list docs/` share one row. They return the same page — the
                // trailing slash is not part of node identity — and the
                // list-backed stat lookup below derives its parent with the
                // slash, so keying on the caller's spelling wrote a row
                // nothing could read.
                address: ovstorage_layer::node_spellings(prefix).1,
                credential_scope: credential_scope(prefix),
            },
            MetadataCachePayload::List(page.clone()),
            flags,
        );
        for item in &page.items {
            if item.kind == ObjectKind::File {
                retained |= self.cache.insert(
                    MetadataCacheKey {
                        kind: MetadataKind::Stat,
                        principal_id: principal.map(str::to_string),
                        address: ovstorage_layer::node_address(&item.address),
                        // The scope of the REQUEST, exactly as the `List` row
                        // above takes it — never the entry's own address. A
                        // listing entry is synthesized by the plugin from the
                        // configured root and carries no userinfo, so scoping
                        // on it writes every per-item row under `None`: an
                        // anonymous `stat` would read a row a credentialed
                        // caller's listing filled, and that caller's own later
                        // `stat` — which keys on its address's digest — would
                        // miss it. What a row may be shown for is decided by
                        // the credential the backend answered under, and only
                        // the request carries that.
                        credential_scope: credential_scope(prefix),
                    },
                    MetadataCachePayload::Stat(item.clone()),
                    flags,
                );
            }
        }
        // Registered AFTER the inserts, and only if one of them stuck.
        //
        // Registration and storage share a predicate here: a page with no
        // retained entry has nothing for a watch to keep fresh. The
        // cacheability test alone cannot deliver that, because `insert` drops a
        // payload larger than the whole budget, so a cacheable page can still
        // store nothing. A directory-only page over the budget stores neither
        // the list nor any per-file row, and registering it would spend one of
        // `MAX_CANDIDATE_SCOPES` on a directory the cache is not holding.
        //
        // `retained` is an OR across the page rather than the list's own
        // outcome: an oversized listing whose per-file stat rows fit leaves
        // exactly the entries a watch on this prefix protects.
        if retained {
            self.watch_state.note_cached(prefix);
        }
    }

    /// Answer eligible direct-stat misses from a parent listing: use the
    /// cached listing when present, else issue a fresh
    /// `inner.list` for routes that opt in (`wants_list_backed_stat`:
    /// backends where listing the parent is cheaper than per-object stats).
    /// The route/capability gate reads `inner.root_info_for(parent)`. Because
    /// this wrapper sits below the address wrappers, parent prefixes are
    /// already in post-alias physical space.
    async fn stat_from_parent_list(
        &self,
        request: &Request<StatRequest>,
        requested: CostFlags,
        cancel: Option<CancellationToken>,
    ) -> ListBackedStat {
        let addr = &request.input.address;
        // Version-selected (query/fragment) URLs never answer from a listing.
        if addr.query().is_some() || addr.fragment().is_some() {
            return ListBackedStat::Unavailable;
        }
        // Directory-form stats always delegate: the RFC narrows list-backed
        // eligibility to unversioned, non-directory object requests, and
        // listing entries spell subdirectory addresses backend-dependently
        // (with or without a trailing slash), so a listing can never answer
        // a directory stat authoritatively.
        if address::is_directory(addr) {
            return ListBackedStat::Unavailable;
        }
        let Some((parent, _name)) = address::parent_and_name(addr) else {
            return ListBackedStat::Unavailable;
        };
        // A cached parent listing answers when its flags cover the stat's:
        // the list is already paid for, whatever route it came from.
        let principal = Self::principal_of(&request.extensions);
        let list_key = MetadataCacheKey {
            kind: MetadataKind::List,
            principal_id: principal.clone(),
            // The same directory spelling `store_list` writes, so a page the
            // caller's own list cached is found whichever spelling they used.
            address: ovstorage_layer::node_spellings(&parent).1,
            credential_scope: credential_scope(&parent),
        };
        if let MetadataLookup::Hit(MetadataCachePayload::List(page)) =
            self.cache.get(&list_key, requested)
        {
            return Self::find_in_page(&page, addr);
        }
        // A flag means the caller pays for THIS object, not for a listing of
        // its directory: a flagged stat never buys a listing of its own, and
        // the backend stat is the cheaper answer.
        if !requested.is_empty() {
            return ListBackedStat::Unavailable;
        }
        // A fresh listing is fetched only for routes that opt in.
        let opted_in = self
            .inner
            .root_info_for(&parent, &Extensions::new(), cancel.clone())
            .await
            .map(|root| root.capabilities.supports_list && root.capabilities.wants_list_backed_stat)
            .unwrap_or(false);
        if !opted_in {
            return ListBackedStat::Unavailable;
        }
        let list = Request {
            extensions: request.extensions.clone(),
            input: ListRequest {
                prefix: parent.clone(),
                options: ListOptions::default(),
            },
        };
        let page = match self.inner.list(list, cancel).await {
            Ok(page) => page,
            Err(_) => return ListBackedStat::Unavailable,
        };
        // Fill the cache exactly as a caller-issued list would, so sibling
        // stats hit and the usual mutation invalidation applies.
        self.store_list(
            &parent,
            &ListOptions::default(),
            &page,
            principal.as_deref(),
        );
        Self::find_in_page(&page, addr)
    }

    /// A three-way scan, because "no `File` here" and "nothing here" are
    /// different answers.
    ///
    /// - A `File` at the exact address answers the stat.
    /// - A **directory-like** entry naming the same node delegates. The two
    ///   spellings of a node are one node, and a listing entry does not carry
    ///   what a directory `stat` returns, so the cache defers instead of
    ///   answering. Without this branch a directory the very same listing
    ///   reported came back as an authoritative `NotFound` that never reached
    ///   the backend — reachable today, because the file backend emits
    ///   slashless directory addresses.
    /// - Absent is `NotFound` only when the page is complete. A paginated
    ///   listing (`next_page_token` set) proves nothing about its later pages.
    ///
    /// The `File` match keeps the exact path spelling while the directory match
    /// is node-aware, and the asymmetry is deliberate: a flat store can hold
    /// both an object `docs` and a slash-terminated object `docs/` with content,
    /// which the backend classifies as two files. Answering a stat of one with
    /// the metadata of the other would report the wrong size and etag. A
    /// directory entry carries no such payload to confuse, so widening that
    /// side only turns a wrong answer into a delegation.
    ///
    /// What the `File` match does drop is **userinfo**, via
    /// [`ovstorage_layer::node_address`], and that is not a widening: a
    /// caller's credentials are not part of what an address names anywhere else
    /// in the stack, and a plugin synthesizes its listing entries from the
    /// configured root, which carries none. A whole-`Url` comparison makes
    /// `stat s3://caller@bucket/key` miss the entry the very same page holds,
    /// and a complete page turns that miss into an authoritative `NotFound`
    /// that never reaches the backend.
    fn find_in_page(page: &ListPage, addr: &Url) -> ListBackedStat {
        // Two passes, because one loop would let page order decide. A flat
        // store can list both an object `docs` and a marker `docs/`, and with a
        // single loop whichever the plugin emitted first would win: the same
        // stat answers from cache or delegates depending on nothing the caller
        // can see.
        for item in &page.items {
            if ovstorage_layer::node_address(&item.address) == ovstorage_layer::node_address(addr)
                && item.kind == ObjectKind::File
            {
                let mut info = item.clone();
                info.address = addr.clone();
                return ListBackedStat::Found(Box::new(info));
            }
        }
        for item in &page.items {
            if item.kind != ObjectKind::File
                && ovstorage_layer::node_key(&item.address) == ovstorage_layer::node_key(addr)
            {
                return ListBackedStat::Unavailable;
            }
        }
        if page.next_page_token.is_some() {
            ListBackedStat::Unavailable
        } else {
            ListBackedStat::NotFound
        }
    }
}

#[async_trait]
impl Layer for MetadataCacheWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Slots with no metadata-cache interaction delegate to `inner` via the
    /// trait defaults.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    /// The same pair the `Lapsed` and gap handlers use, so a lifecycle sweep
    /// leaves this cache in the state a lapse would.
    ///
    /// `invalidate_lists_containing` as well as `invalidate_prefix`: a listing
    /// held ABOVE the swept prefix names entries inside it, so dropping only the
    /// subtree would leave a parent listing asserting the contents of a
    /// directory nothing is watching.
    fn invalidate_cached_subtree(&self, prefix: &Url) {
        self.cache.invalidate_prefix(prefix);
        self.cache.invalidate_lists_containing(prefix);
        if let Some(inner) = self.inner_layer() {
            inner.invalidate_cached_subtree(prefix);
        }
    }

    fn supports_buffered_write_capture(&self) -> bool {
        self.inner.supports_buffered_write_capture()
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        // A broker-resolved OAuth credential can make metadata depend on a
        // bearer that is revoked or replaced independently of this cache's
        // mutation/watch invalidation. Principal scoping alone cannot express
        // that credential epoch, so bypass the Stat cache and list-backed
        // fallback completely, including fills.
        if request
            .extensions
            .get(ext::RESOLVED_OAUTH_CREDENTIAL)
            .is_some()
        {
            return self.inner.stat(request, cancel).await;
        }
        let address = request.input.address.clone();
        let requested = CostFlags::from(&request.input.options);
        let cache_key = crate::routing::stat_is_cacheable(&address).then(|| MetadataCacheKey {
            kind: MetadataKind::Stat,
            principal_id: Self::principal_of(&request.extensions),
            address: ovstorage_layer::node_address(&address),
            credential_scope: credential_scope(&address),
        });
        // The flags the backend call carries: the request's own, widened to a
        // narrower row's when one exists, so one refetch replaces the row with
        // one that answers both.
        let mut upstream = requested;
        if let Some(key) = &cache_key {
            match self.cache.get(key, requested) {
                MetadataLookup::Hit(MetadataCachePayload::Stat(mut info)) => {
                    // A hit registers too: a directory read constantly but
                    // always served from cache would otherwise be the
                    // least-recently-used scope and lose the very watch keeping
                    // it hittable.
                    self.watch_state.note_cached(&address);
                    // Only the address is the caller's spelling; the pin is the
                    // row's own answer and stays.
                    info.address = address;
                    return Ok(info);
                }
                MetadataLookup::Narrower { stored } => upstream = stored.union(requested),
                MetadataLookup::Hit(_) | MetadataLookup::Miss => {}
            }
        }
        // List-backed fallback for eligible object-form stats that
        // missed the Stat cache (directory forms delegate inside the probe).
        if cache_key.is_some() {
            match self
                .stat_from_parent_list(&request, requested, cancel.clone())
                .await
            {
                ListBackedStat::Found(info) => {
                    self.watch_state.note_cached(&address);
                    return Ok(*info);
                }
                ListBackedStat::NotFound => {
                    // The parent listing answered, so it is a live cache entry
                    // whose directory is in use — even though this stat is an
                    // error. Without this touch a hot negative lookup lets its
                    // own directory age out of the watch budget.
                    self.watch_state.note_cached(&address);
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        "object not found in cached parent listing",
                    ));
                }
                ListBackedStat::Unavailable => {}
            }
        }
        let mut request = request;
        upstream.widen_stat(&mut request.input.options);
        let info = self.inner.stat(request, cancel).await?;
        // Fill the `Stat` cache from an eligible successful direct stat
        // under exactly the key the lookup above uses, stored under the flags
        // the call went upstream with — the union when a narrower row was
        // found — so the row only widens between refreshes. List also fills
        // `Stat` entries only from `list`, so every repeated direct stat
        // re-delegated; the layered cache closes that hole. The mutation
        // invalidation below removes these entries the same way it removes
        // list-filled ones (identical key space).
        if let Some(key) = cache_key {
            self.cache
                .insert(key, MetadataCachePayload::Stat(info.clone()), upstream);
            self.watch_state.note_cached(&address);
        }
        Ok(info)
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        // Forward-looking guard: a credentialed listing could carry privileged
        // ObjectInfo entries and seed per-file Stat entries. The broker does
        // not stamp list today, but keep both forms out of the cache for any
        // host that does so in the future.
        if request
            .extensions
            .get(ext::RESOLVED_OAUTH_CREDENTIAL)
            .is_some()
        {
            return self.inner.list(request, cancel).await;
        }
        let prefix = request.input.prefix.clone();
        let options = request.input.options.clone();
        let principal = Self::principal_of(&request.extensions);
        let page = self.inner.list(request, cancel).await?;
        self.store_list(&prefix, &options, &page, principal.as_deref());
        Ok(page)
    }

    /// Pass streaming listings through without populating metadata-cache rows.
    ///
    /// Gen1 list-backed stat treats a cached, terminal [`ListPage`] as an
    /// authoritative view of a directory. A stream may be dropped after any
    /// entry, so caching entries as they pass would let a partial listing
    /// answer a later stat with a false `NotFound`. Streaming entries therefore
    /// remain uncached until the cache has a completeness-aware representation.
    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        self.inner.list_stream(request, cancel).await
    }

    // --- mutations: invalidate after success --------------------------------

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let address = request.input.address.clone();
        let result = self.inner.write(request, cancel).await?;
        self.invalidate_for(&address);
        Ok(result)
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let address = request.input.address.clone();
        let result = self.inner.write_stream(request, cancel).await?;
        self.invalidate_for(&address);
        Ok(result)
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let address = request.input.address.clone();
        self.inner.delete(request, cancel).await?;
        self.invalidate_for(&address);
        Ok(())
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let destination = request.input.destination.clone();
        let result = self.inner.copy(request, cancel).await?;
        self.invalidate_for(&destination);
        Ok(result)
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let source = request.input.source.clone();
        let destination = request.input.destination.clone();
        self.inner.rename(request, cancel).await?;
        self.invalidate_for(&source);
        self.invalidate_for(&destination);
        Ok(())
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let address = request.input.address.clone();
        let result = self.inner.update_metadata(request, cancel).await?;
        self.invalidate_for(&address);
        Ok(result)
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let address = request.input.address.clone();
        let result = self.inner.create_directory(request, cancel).await?;
        self.invalidate_for(&address);
        Ok(result)
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let address = request.input.address.clone();
        self.inner.delete_directory(request, cancel).await?;
        self.invalidate_for(&address);
        self.cache.invalidate_prefix(&address);
        Ok(())
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let address = request.input.address.clone();
        let step = self.inner.continue_write(request, cancel).await?;
        // The direct `write_redirect → continue_write` API (broker upload
        // completion) finalizes the object without passing through this
        // wrapper's `write`/`write_stream` invalidation, so a terminal step
        // must invalidate the parent listings and stat.
        // `WriteStep::Redirects` is mid-flight and leaves the cache untouched.
        if matches!(step, WriteStep::Done(_)) {
            self.invalidate_for(&address);
        }
        Ok(step)
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

        // Invalidate cached `Stat`/`List` metadata as watch events flow so a
        // watched mutation
        // can't leave a stale entry behind the cache. Per event:
        //
        // - `Created`/`Modified`/`MetadataChanged` drop the address's entries
        //   plus any parent listings containing it.
        // - `Deleted` additionally drops everything UNDER the address: a
        //   deleted directory takes its children's cached entries with it
        //   (for a file address the prefix sweep matches nothing extra).
        // - `Lapsed` means events were lost — anything cached under the
        //   watched prefix may be stale, so the whole watched subtree (and
        //   the listings containing it) is dropped.
        //
        // A stream error is an out-of-band coverage gap:
        // `GapSweepStream` runs `on_gap` — the same subtree sweep — and the
        // terminal signal flows up through any wrapper above so its cache
        // sweeps too. An ordinary caller stream also sweeps on a clean end.
        // The cache-owned managed drain does not: its loop reconnects finite
        // clean batches with bounded backoff, avoiding a sweep on every batch.
        // Invalidation is address-wide across principals (the safe direction,
        // like the mutation overrides).
        let event_cache = Arc::clone(&self.cache);
        let event_prefix = watched_prefix.clone();
        let gap_cache = Arc::clone(&self.cache);
        let gap_prefix = watched_prefix;
        Ok(Box::new(GapSweepStream::new(
            stream,
            teardown,
            sweep_on_clean_end,
            move |event: &ChangeEvent| match event {
                ChangeEvent::Object { address, kind, .. } => {
                    event_cache.invalidate_address(address);
                    event_cache.invalidate_lists_containing(address);
                    if *kind == ChangeKind::Deleted {
                        event_cache.invalidate_prefix(address);
                    }
                }
                ChangeEvent::Lapsed { .. } => {
                    event_cache.invalidate_prefix(&event_prefix);
                    event_cache.invalidate_lists_containing(&event_prefix);
                }
            },
            move || {
                gap_cache.invalidate_prefix(&gap_prefix);
                gap_cache.invalidate_lists_containing(&gap_prefix);
            },
        )))
    }
}

#[cfg(test)]
mod list_stream_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::StreamExt as _;

    use super::*;

    const STREAM_ITEMS: usize = 128;
    const CONSUMED_ITEMS: usize = 3;

    #[derive(Clone, Default)]
    struct FlowCounters {
        produced: Arc<AtomicUsize>,
        released: Arc<AtomicUsize>,
        peak_in_flight: Arc<AtomicUsize>,
    }

    struct PullListingLayer {
        counters: FlowCounters,
    }

    #[async_trait]
    impl Layer for PullListingLayer {
        fn name(&self) -> &str {
            "pull-listing"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("pull-listing", LayerType::Backend, false)
        }

        async fn list_stream(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListStream> {
            let counters = self.counters.clone();
            Ok(Box::pin(futures::stream::unfold(0usize, move |index| {
                let counters = counters.clone();
                async move {
                    if index == STREAM_ITEMS {
                        return None;
                    }
                    let produced = counters.produced.fetch_add(1, Ordering::SeqCst) + 1;
                    let in_flight =
                        produced.saturating_sub(counters.released.load(Ordering::SeqCst));
                    counters
                        .peak_in_flight
                        .fetch_max(in_flight, Ordering::SeqCst);
                    Some((Ok(item(index)), index + 1))
                }
            })))
        }
    }

    fn item(index: usize) -> ObjectInfo {
        ObjectInfo::from((
            Url::parse(&format!("test:///root/item-{index}")).unwrap(),
            BackendItemInfo {
                kind: ObjectKind::File,
                ..BackendItemInfo::default()
            },
        ))
    }

    fn request() -> Request<ListRequest> {
        Request::new(ListRequest {
            prefix: Url::parse("test:///root/").unwrap(),
            options: ListOptions::default(),
        })
    }

    #[tokio::test]
    async fn streaming_invariant_passes_entries_without_caching_partial_state() {
        let counters = FlowCounters::default();
        let cache = Arc::new(MetadataCache::new(&MetadataCacheConfig::default()));
        let wrapper = MetadataCacheWrapperFactory::with_cache(Arc::clone(&cache))
            .create_wrapper(
                "metadata-cache",
                &LayerConfig::new(),
                Arc::new(PullListingLayer {
                    counters: counters.clone(),
                }),
                None,
            )
            .await
            .unwrap();

        let mut stream = wrapper.list_stream(request(), None).await.unwrap();
        assert_eq!(
            counters.produced.load(Ordering::SeqCst),
            0,
            "opening the wrapper must not prefetch the inner stream"
        );

        for index in 0..CONSUMED_ITEMS {
            assert_eq!(stream.next().await.unwrap().unwrap(), item(index));
            assert_eq!(
                counters.produced.load(Ordering::SeqCst),
                index + 1,
                "one consumer pull must produce exactly one inner entry"
            );
            counters.released.fetch_add(1, Ordering::SeqCst);
        }
        drop(stream);

        assert_eq!(
            counters.produced.load(Ordering::SeqCst),
            CONSUMED_ITEMS,
            "dropping a partial stream must stop inner production"
        );
        assert!(
            counters.peak_in_flight.load(Ordering::SeqCst) <= 1,
            "the wrapper accumulated more than one entry"
        );

        let prefix = Url::parse("test:///root/").unwrap();
        let list_key = MetadataCacheKey {
            kind: MetadataKind::List,
            principal_id: None,
            address: ovstorage_layer::node_spellings(&prefix).1,
            credential_scope: credential_scope(&prefix),
        };
        assert!(
            cache.get(&list_key, CostFlags::default()).hit().is_none(),
            "a partial stream must not seed an authoritative List row"
        );
        for index in 0..CONSUMED_ITEMS {
            let address = item(index).address;
            let stat_key = MetadataCacheKey {
                kind: MetadataKind::Stat,
                principal_id: None,
                address: ovstorage_layer::node_address(&address),
                credential_scope: credential_scope(&prefix),
            };
            assert!(
                cache.get(&stat_key, CostFlags::default()).hit().is_none(),
                "a streamed entry must not seed list-backed Stat state"
            );
        }
    }
}
