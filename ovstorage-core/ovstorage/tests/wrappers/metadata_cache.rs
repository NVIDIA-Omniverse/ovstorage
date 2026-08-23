// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `MetadataCacheWrapper` behavior: stat-after-list serving, mutation and
//! watch-event invalidation, prefix invalidation, and factory config
//! validation.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ovstorage::layers::METADATA_CACHE_KIND;
use ovstorage::wrappers::ext;
use ovstorage::{
    Body, ConfigValue, DeleteDirectoryOptions, DeleteDirectoryRequest, ErrorCode, Layer,
    LayerConfig, LayerHandle, ListOptions, ListRequest, ObjectInfo, RenameOptions, RenameRequest,
    Request, Stack, StatOptions, StatRequest, Url, WatchDirectoryOptions, WatchDirectoryRequest,
    WriteOptions, WriteRequest, WriteResult, WriteStep,
};
use ovstorage_plugin_cache::MetadataCacheWrapperFactory;

use crate::common::*;

#[tokio::test]
async fn metadata_cache_accepts_watch_invalidation_on_directly_composed_stacks() {
    let config = LayerConfig::from([("watch_invalidation".into(), ConfigValue::Bool(false))]);
    let _stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        CacheProbe::new(b"content", Vec::new()),
        config,
    )
    .await
    .expect("directly composed caches support notification drains");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_serves_stat_after_list() {
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("file:///d/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let info = stack
        .stat(
            Request::new(StatRequest {
                address: file.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(info.address, file);
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);
    // The per-file Stat entry filled by `list` serves the stat — no backend stat.
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn metadata_cache_fills_stat_from_direct_stat() {
    // An eligible successful direct stat fills the Stat cache under its
    // lookup key — a second equivalent stat hits without delegating, and the
    // usual mutation invalidation removes the entry like a list-filled one.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "the second direct stat must be served from the cache"
    );

    stack
        .write(
            Request::new(WriteRequest {
                address: file.clone(),
                body: Body::Bytes(b"x".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "the write must invalidate the direct-stat-filled entry"
    );
}

/// Two credentials for one address must not share a cache row.
///
/// Userinfo is not part of node identity — nothing in ovstorage consults it —
/// so the cache key strips it, which is right for the *address* and wrong on
/// its own for the *row*: `alice:pw` and `mallory:wrong` then produce an
/// identical key, and the second caller is served the `ObjectInfo` the first
/// one was authorized to fetch. `credential_scope` is a digest of the userinfo
/// carried alongside the stripped address to keep the two rows apart.
///
/// **Driven through the wrapper on purpose.** A key-level test constructs the
/// key itself, so it passes whether or not the wrapper ever populates the
/// field — which is exactly how this shipped with `credential_scope` defined,
/// tested, and hardcoded to `None` at all four construction sites.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_does_not_serve_one_credential_from_another() {
    let alice = Url::parse("https://alice:pw@origin/private/x").unwrap();
    let mallory = Url::parse("https://mallory:wrong@origin/private/x").unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack.stat(stat_request(&alice), None).await.unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);

    stack.stat(stat_request(&alice), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "the control: the SAME credential must still be served from the cache, \
         or this test would pass with caching switched off entirely"
    );

    stack.stat(stat_request(&mallory), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "a different credential must reach the backend, not read the first \
         caller's cached ObjectInfo"
    );
}

/// A listing entry and a stat that spell one node differently still meet.
///
/// On a scheme with no authority — a broker route is spelled both `broker:/x`
/// and `broker:///x` in this tree — the parser normalizes neither spelling, so
/// the two reach the cache as distinct strings while `node_key` calls them one
/// node. `find_in_page` matches a File entry by the key form and a directory
/// entry by `node_key`, so if the key form did not collapse them, one page
/// would answer a directory stat and turn the file into an authoritative
/// `NotFound` the backend never sees.
///
/// The assertion is that the stat SUCCEEDS from the listing. A miss here is not
/// a delegation: the page is complete, so it is an error handed to the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_matches_a_listed_entry_across_spellings_of_one_node() {
    let listed = Url::parse("broker:///d/f").unwrap();
    let requested = Url::parse("broker:/d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(listed.clone(), 7)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("broker:/d/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    let info = stack
        .stat(stat_request(&requested), None)
        .await
        .expect("the listing holds this object under its other spelling");
    assert_eq!(
        info.address, requested,
        "the answer must come back in the caller's own spelling"
    );
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        0,
        "the listing answered it; a backend stat would mean the entry was missed"
    );

    // The other half, and the one that decides whether a stale answer can be
    // served: a mutation issued through ONE spelling must reach the row the
    // other spelling filled. Two keys for one node means a write leaves the
    // other row live.
    stack
        .write(
            Request::new(WriteRequest {
                address: listed.clone(),
                body: Body::Bytes(b"x".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.stat(stat_request(&requested), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "a write through one spelling must invalidate the row the other filled"
    );
}

/// A listing's per-item `Stat` rows are scoped to the credential the LISTING
/// was fetched under, not to the entry's own address.
///
/// A listing entry is synthesized by the plugin from the configured root and
/// carries no userinfo — this test's probe spells its entry exactly that way,
/// which is the whole mechanism. Scoping the row on the entry writes every one
/// of them under `None`, so an anonymous `stat` reads a row a credentialed
/// caller's listing filled, and that caller's own later `stat` — which keys on
/// its address's digest — misses the row it just paid for. Both halves are
/// asserted, because each on its own can be satisfied by caching nothing.
///
/// **Driven through the wrapper, not through the key.** The sibling test above
/// records why: `credential_scope` was defined, tested and hardcoded to `None`
/// at every construction site, and only a wrapper-level test could see it.
/// That one drives the direct-stat path and sees neither arm of this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_scopes_listed_entries_to_the_listing_credential() {
    let entry = Url::parse("https://origin/team/x").unwrap();
    let alice_dir = Url::parse("https://alice:pw@origin/team/").unwrap();
    let alice_entry = Url::parse("https://alice:pw@origin/team/x").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(entry.clone(), 7)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .list(
            Request::new(ListRequest {
                prefix: alice_dir,
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);

    stack.stat(stat_request(&entry), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "an anonymous stat must reach the backend, not read the row a \
         credentialed caller's listing filled"
    );

    stack.stat(stat_request(&alice_entry), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "the control: the credential that fetched the listing must be served \
         from it, or this test would pass with the per-item rows not written \
         at all"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_invalidates_stat_on_write() {
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .list(
            Request::new(ListRequest {
                prefix: Url::parse("file:///d/").unwrap(),
                options: ListOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack
        .write(
            Request::new(WriteRequest {
                address: file.clone(),
                body: Body::Bytes(b"x".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack
        .stat(
            Request::new(StatRequest {
                address: file.clone(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    // The write invalidated the cached Stat — the stat re-hits the backend.
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn metadata_cache_invalidates_stat_on_watch_event() {
    // Cached stat/list metadata is invalidated as watch events flow through
    // `compose_change_event`. The `MetadataCacheWrapper` must map the watch
    // stream and drop the affected entry, so a stat after a watched change
    // re-hits the backend instead of serving stale metadata. Regression — the
    // wrapper delegated `watch_directory` unchanged.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let stack = metadata_cache_stack(backend.clone()).await;

    // Prime the Stat cache via a list, then confirm a direct stat is a hit.
    stack.list(list_request("file:///d/"), None).await.unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        0,
        "the stat should be served from the list-filled cache"
    );

    // Pull the watch stream: a `Created` event for `file` must invalidate its
    // cached Stat as it flows through the wrapper.
    let mut events = stack
        .watch_directory(
            Request::new(WatchDirectoryRequest {
                prefix: Url::parse("file:///d/").unwrap(),
                options: WatchDirectoryOptions {
                    recursive: false,
                    include_metadata_changes: false,
                    since: None,
                    poll_interval: std::time::Duration::from_secs(0),
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert!(events.next().is_some(), "the backend emits one watch event");

    // The next stat re-hits the backend — the watch event invalidated the entry.
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "the watch event must invalidate the cached stat"
    );
}

/// Build a `metadata_cache` stack over `backend`.
async fn metadata_cache_stack(backend: LayerHandle) -> Stack {
    build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap()
}

fn list_request(prefix: &str) -> Request<ListRequest> {
    Request::new(ListRequest {
        prefix: Url::parse(prefix).unwrap(),
        options: ListOptions::default(),
    })
}

fn stat_request(address: &Url) -> Request<StatRequest> {
    Request::new(StatRequest {
        address: address.clone(),
        options: StatOptions::default(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_invalidates_on_direct_continue_write() {
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let stack = metadata_cache_stack(backend.clone()).await;

    stack.list(list_request("file:///d/"), None).await.unwrap(); // fills Stat(f)
    stack
        .continue_write(empty_continue_write("file:///d/f"), None)
        .await
        .unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    // The terminal continue_write invalidated the cached Stat.
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_keeps_cache_on_mid_flight_continue_write() {
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::redirecting_continue(b"content", vec![object_info(file.clone(), 7)]);
    let stack = metadata_cache_stack(backend.clone()).await;

    stack.list(list_request("file:///d/"), None).await.unwrap(); // fills Stat(f)
    let step = stack
        .continue_write(empty_continue_write("file:///d/f"), None)
        .await
        .unwrap();
    assert!(matches!(step, WriteStep::Redirects(_)));
    stack.stat(stat_request(&file), None).await.unwrap();
    // Mid-flight step left the cached Stat intact — served without a backend stat.
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);
}

// --- metadata-cache prefix / sibling invalidation ---------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_invalidate_prefix_on_delete_directory() {
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let stack = metadata_cache_stack(backend.clone()).await;

    stack.list(list_request("file:///d/"), None).await.unwrap(); // caches Stat(f)
    // delete_directory drops every cached entry under the prefix.
    stack
        .delete_directory(
            Request::new(DeleteDirectoryRequest {
                address: Url::parse("file:///d/").unwrap(),
                options: DeleteDirectoryOptions,
            }),
            None,
        )
        .await
        .unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_cache_invalidates_stat_on_rename() {
    let src = Url::parse("file:///d/src").unwrap();
    let dest = Url::parse("file:///d/dest").unwrap();
    let backend = CacheProbe::new(
        b"content",
        vec![object_info(src.clone(), 7), object_info(dest.clone(), 7)],
    );
    let stack = metadata_cache_stack(backend.clone()).await;

    stack.list(list_request("file:///d/"), None).await.unwrap(); // caches both Stats
    stack
        .rename(
            Request::new(RenameRequest {
                source: src.clone(),
                destination: dest.clone(),
                options: RenameOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.stat(stat_request(&src), None).await.unwrap();
    stack.stat(stat_request(&dest), None).await.unwrap();
    // rename invalidated both the source and destination Stat entries.
    assert_eq!(backend.stats.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn metadata_cache_factory_rejects_negative_ttl() {
    let backend = CacheProbe::new(b"", Vec::new());
    let mut config = LayerConfig::new();
    config.insert("ttl_seconds".into(), ConfigValue::Int(-5));
    let error = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend,
        config,
    )
    .await
    .err()
    .expect("negative ttl_seconds must fail the build");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
}

/// A backend whose root opts into list-backed stat
/// (`wants_list_backed_stat` + `supports_list`), counting `stat`/`list`
/// calls so the wrapper's routing between the two is observable.
struct ListBackedProbe {
    items: Vec<ObjectInfo>,
    opted_in: bool,
    /// The route the probe publishes. Parameterized so a scheme that carries
    /// userinfo can be exercised; `file:` cannot.
    root: &'static str,
    /// When set, list responses carry a `next_page_token` — a partial page.
    paginated: bool,
    stats: AtomicUsize,
    lists: AtomicUsize,
}

impl ListBackedProbe {
    fn new(items: Vec<ObjectInfo>, opted_in: bool) -> Arc<Self> {
        Self::rooted("file:///d/", items, opted_in)
    }

    fn rooted(root: &'static str, items: Vec<ObjectInfo>, opted_in: bool) -> Arc<Self> {
        Arc::new(Self {
            items,
            opted_in,
            root,
            paginated: false,
            stats: AtomicUsize::new(0),
            lists: AtomicUsize::new(0),
        })
    }

    fn paginated(items: Vec<ObjectInfo>, opted_in: bool) -> Arc<Self> {
        Arc::new(Self {
            items,
            opted_in,
            root: "file:///d/",
            paginated: true,
            stats: AtomicUsize::new(0),
            lists: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl Layer for ListBackedProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        backend_descriptor(PROBE_KIND)
    }

    async fn root_info_for(
        &self,
        _url: &Url,
        _cx: &ovstorage::Extensions,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ovstorage::RootInfo> {
        let mut root = test_root(self.root);
        root.capabilities.supports_list = true;
        root.capabilities.wants_list_backed_stat = self.opted_in;
        Ok(root)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ObjectInfo> {
        self.stats.fetch_add(1, Ordering::SeqCst);
        Ok(object_info(request.input.address, 7))
    }

    async fn list(
        &self,
        _request: Request<ListRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ovstorage::ListPage> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        Ok(ovstorage::ListPage {
            items: self.items.clone(),
            next_page_token: self.paginated.then(|| "next".to_string()),
        })
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<WriteResult> {
        Ok(WriteResult {
            info: object_info(request.input.address, 0),
        })
    }
}

#[tokio::test]
async fn list_backed_stat_serves_opted_in_route_without_backend_stat() {
    // An eligible stat miss on an opted-in route fetches the parent
    // listing (once) and answers from it; a sibling stat and an
    // absent-object stat are then both answered from the cached listing —
    // zero backend stats.
    let file = Url::parse("file:///d/f").unwrap();
    let sibling = Url::parse("file:///d/g").unwrap();
    let backend = ListBackedProbe::new(
        vec![
            object_info(file.clone(), 7),
            object_info(sibling.clone(), 8),
        ],
        true,
    );
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let info = stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(info.address, file);
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);

    stack.stat(stat_request(&sibling), None).await.unwrap();
    assert_eq!(
        backend.lists.load(Ordering::SeqCst),
        1,
        "sibling served from the cached listing"
    );

    let missing = Url::parse("file:///d/missing").unwrap();
    let error = stack.stat(stat_request(&missing), None).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        0,
        "NotFound answered from the listing"
    );
}

#[tokio::test]
async fn list_backed_stat_respects_opt_out_and_ineligible_requests() {
    let file = Url::parse("file:///d/f").unwrap();
    let backend = ListBackedProbe::new(vec![object_info(file.clone(), 7)], false);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Opted out: the direct backend stat path is preserved.
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
    assert_eq!(backend.lists.load(Ordering::SeqCst), 0);

    // Even opted in, full_metadata and version-selected URLs bypass the
    // listing path and delegate.
    let backend = ListBackedProbe::new(vec![object_info(file.clone(), 7)], true);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();
    stack
        .stat(
            Request::new(StatRequest {
                address: file.clone(),
                options: StatOptions {
                    full_metadata: true,
                },
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
    stack
        .stat(
            Request::new(StatRequest {
                address: Url::parse("file:///d/f?version=2").unwrap(),
                options: StatOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 2);
    assert_eq!(backend.lists.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn list_backed_stat_refetches_after_mutation_invalidates_listing() {
    // The cached listing and mutation invalidation interact predictably: a
    // write drops the parent listing, so the next stat re-fetches it instead
    // of serving stale entries.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = ListBackedProbe::new(vec![object_info(file.clone(), 7)], true);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);

    stack
        .write(
            Request::new(WriteRequest {
                address: file.clone(),
                body: Body::Bytes(b"x".to_vec()),
                options: WriteOptions::default(),
            }),
            None,
        )
        .await
        .unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        backend.lists.load(Ordering::SeqCst),
        2,
        "the write invalidated the parent listing; the stat re-fetches it"
    );
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);
}

fn stat_request_as(address: &Url, principal: &str) -> Request<StatRequest> {
    let mut request = stat_request(address);
    request
        .extensions
        .insert(ext::PRINCIPAL_ID.to_string(), principal.as_bytes().to_vec());
    request
}

fn with_resolved_oauth_credential<T>(mut request: Request<T>) -> Request<T> {
    ext::insert_resolved_oauth_credential(
        &mut request.extensions,
        &ext::ResolvedOAuthCredentialRef {
            backend_kind: "http".into(),
            keyring_handle: "oauth/test".into(),
        },
    )
    .unwrap();
    request
}

#[tokio::test]
async fn credentialed_stat_bypasses_lookup_and_fill_across_revocation() {
    let cached_before_auth = Url::parse("https://origin.example/cached-before-auth").unwrap();
    let revoked = Url::parse("https://origin.example/revoked").unwrap();
    let backend = CacheProbe::new(b"privileged", Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Prime ordinary metadata for this principal, then make the origin reject
    // requests. A credentialed stat must bypass that existing cache entry.
    stack
        .stat(stat_request_as(&cached_before_auth, "alice"), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::AuthRequired));
    let error = stack
        .stat(
            with_resolved_oauth_credential(stat_request_as(&cached_before_auth, "alice")),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuthRequired);
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "a credentialed stat must not reuse ordinary metadata for the same principal"
    );

    // Restore the origin and issue a successful authenticated stat at a fresh
    // address. Removing the resolved-credential reference models deletion of
    // the principal's durable provider row: the next request must reach the
    // now-revoking origin instead of receiving the privileged ObjectInfo.
    backend.set_stat_error(None);
    stack
        .stat(
            with_resolved_oauth_credential(stat_request_as(&revoked, "alice")),
            None,
        )
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::AuthRequired));
    let error = stack
        .stat(stat_request_as(&revoked, "alice"), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuthRequired);
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        4,
        "a successful credentialed stat must not fill metadata that survives credential deletion"
    );
}

#[tokio::test]
async fn credentialed_list_does_not_seed_privileged_stat_entries() {
    let file = Url::parse("https://origin.example/d/private").unwrap();
    let backend = CacheProbe::new(b"privileged", vec![object_info(file.clone(), 10)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let mut list = list_request("https://origin.example/d/");
    list.extensions.insert(ext::PRINCIPAL_ID, b"alice".to_vec());
    stack
        .list(with_resolved_oauth_credential(list), None)
        .await
        .unwrap();
    backend.set_stat_error(Some(ErrorCode::AuthRequired));

    let error = stack
        .stat(stat_request_as(&file, "alice"), None)
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::AuthRequired);
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "credentialed list results must not seed reusable per-file Stat entries"
    );
}

#[tokio::test]
async fn metadata_cache_scopes_stat_entries_by_principal() {
    // Cached metadata is scoped by the request principal — one
    // principal's entries are never served to another, and an anonymous
    // request (no extension) has its own scope.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // alice fills her scope; her second stat hits.
    stack
        .stat(stat_request_as(&file, "alice"), None)
        .await
        .unwrap();
    stack
        .stat(stat_request_as(&file, "alice"), None)
        .await
        .unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);

    // bob's stat must not observe alice's entry.
    stack
        .stat(stat_request_as(&file, "bob"), None)
        .await
        .unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "a second principal must not be served another principal's cache"
    );

    // Anonymous (no extension) is its own scope, colliding with neither.
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn metadata_cache_scopes_list_fills_by_principal() {
    // A list issued by one principal fills per-file Stat entries in that
    // principal's scope only.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let mut list = list_request("file:///d/");
    list.extensions
        .insert(ext::PRINCIPAL_ID.to_string(), b"alice".to_vec());
    stack.list(list, None).await.unwrap();

    // alice's stat hits the list-filled entry; bob's does not.
    stack
        .stat(stat_request_as(&file, "alice"), None)
        .await
        .unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);
    stack
        .stat(stat_request_as(&file, "bob"), None)
        .await
        .unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn metadata_cache_mutation_invalidates_across_principals() {
    // Invalidation is address-wide — the safe direction: any principal's
    // mutation drops every principal's entries for the address.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack
        .stat(stat_request_as(&file, "alice"), None)
        .await
        .unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 1);

    // bob writes; alice's cached entry must not survive.
    let mut write = Request::new(WriteRequest {
        address: file.clone(),
        body: Body::Bytes(b"x".to_vec()),
        options: WriteOptions::default(),
    });
    write
        .extensions
        .insert(ext::PRINCIPAL_ID.to_string(), b"bob".to_vec());
    stack.write(write, None).await.unwrap();

    stack
        .stat(stat_request_as(&file, "alice"), None)
        .await
        .unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "another principal's mutation must invalidate alice's entry"
    );
}

#[tokio::test]
async fn list_backed_stat_never_answers_not_found_from_partial_listing() {
    // A paginated parent listing (next_page_token set) proves nothing about
    // its later pages: an absent item must fall through to the backend stat
    // instead of returning an authoritative NotFound.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = ListBackedProbe::paginated(vec![object_info(file.clone(), 7)], true);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Present on the first page: still served from the listing.
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.stats.load(Ordering::SeqCst), 0);

    // Absent from the (partial) first page: delegate, don't declare NotFound.
    let missing = Url::parse("file:///d/zz").unwrap();
    stack.stat(stat_request(&missing), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "a partial listing must not answer NotFound authoritatively"
    );
}

#[tokio::test]
async fn list_backed_stat_delegates_directory_form_addresses() {
    // Directory-form stats are never list-backed (the RFC's eligibility
    // rule): even with the parent listing cached, a directory stat delegates
    // to the backend rather than risking a spurious NotFound from
    // backend-dependent subdirectory address spellings.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = ListBackedProbe::new(vec![object_info(file.clone(), 7)], true);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Prime the parent listing.
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);

    let dir = Url::parse("file:///d/sub/").unwrap();
    stack.stat(stat_request(&dir), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "a directory-form stat must delegate to the backend"
    );
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn metadata_cache_distinct_non_utf8_principals_get_distinct_scopes() {
    // Two different non-UTF-8 principal ids must not collapse into one cache
    // scope (lossy decoding would map both to U+FFFD): the second principal's
    // stat delegates instead of hitting the first's entry.
    let file = Url::parse("file:///d/f").unwrap();
    let backend = CacheProbe::new(b"content", Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let stat_as_bytes = |principal: &[u8]| {
        let mut request = stat_request(&file);
        request
            .extensions
            .insert(ext::PRINCIPAL_ID.to_string(), principal.to_vec());
        request
    };

    stack
        .stat(stat_as_bytes(&[0xff, 0x01]), None)
        .await
        .unwrap();
    stack
        .stat(stat_as_bytes(&[0xff, 0x01]), None)
        .await
        .unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "the same malformed principal reuses its own scope"
    );

    stack
        .stat(stat_as_bytes(&[0xfe, 0x01]), None)
        .await
        .unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "a different malformed principal must not share the first's scope"
    );
}

/// Delegates `stat`/`list`/`write` to a [`CacheProbe`] and answers
/// `watch_directory` with a scripted event sequence — lets a test deliver a
/// directory delete or a `Lapsed` marker and observe the wrapper's
/// invalidation.
struct ScriptedWatchProbe {
    inner: Arc<CacheProbe>,
    events: std::sync::Mutex<Vec<ovstorage::ChangeEvent>>,
}

impl ScriptedWatchProbe {
    fn new(inner: Arc<CacheProbe>, events: Vec<ovstorage::ChangeEvent>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            events: std::sync::Mutex::new(events),
        })
    }
}

#[async_trait::async_trait]
impl Layer for ScriptedWatchProbe {
    fn name(&self) -> &str {
        "backend"
    }

    fn descriptor(&self) -> ovstorage::LayerKindDescriptor {
        self.inner.descriptor()
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ovstorage::ObjectInfo> {
        self.inner.stat(request, cancel).await
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ovstorage::ListPage> {
        self.inner.list(request, cancel).await
    }

    async fn watch_directory(
        &self,
        _request: Request<WatchDirectoryRequest>,
        _cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ovstorage::ChangeStream> {
        let events = std::mem::take(&mut *self.events.lock().unwrap());
        Ok(Box::new(events.into_iter().map(Ok)))
    }
}

fn deleted_directory_event(address: &Url) -> ovstorage::ChangeEvent {
    ovstorage::ChangeEvent::Object {
        address: address.clone(),
        kind: ovstorage::ChangeKind::Deleted,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at: std::time::SystemTime::now(),
        cursor: ovstorage::WatchDirectoryCursor::default(),
    }
}

async fn drain(stream: ovstorage::ChangeStream) {
    for event in stream {
        event.unwrap();
    }
}

#[tokio::test]
async fn watch_deleted_directory_invalidates_child_entries() {
    // A watched directory delete must take the cached entries of its
    // CHILDREN with it — address + parent-list invalidation alone leaves a
    // child's list-filled Stat entry serving stale metadata.
    let dir = Url::parse("file:///d/sub/").unwrap();
    let file = Url::parse("file:///d/sub/f").unwrap();
    let inner = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let backend = ScriptedWatchProbe::new(inner.clone(), vec![deleted_directory_event(&dir)]);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // Prime: the listing fills the List entry + the child's Stat entry.
    stack
        .list(list_request("file:///d/sub/"), None)
        .await
        .unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        inner.stats.load(Ordering::SeqCst),
        0,
        "primed from the listing"
    );

    // The watched delete of the parent directory flows through the wrapper.
    drain(
        stack
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: Url::parse("file:///d/").unwrap(),
                    options: WatchDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .unwrap(),
    )
    .await;

    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        inner.stats.load(Ordering::SeqCst),
        1,
        "the deleted directory's child entry must not survive the watch event"
    );
}

#[tokio::test]
async fn watch_lapsed_invalidates_the_watched_subtree() {
    // `Lapsed` means events were lost — anything cached under the
    // watched prefix may be stale and must be dropped.
    let file = Url::parse("file:///d/f").unwrap();
    let inner = CacheProbe::new(b"content", vec![object_info(file.clone(), 7)]);
    let backend = ScriptedWatchProbe::new(
        inner.clone(),
        vec![ovstorage::ChangeEvent::Lapsed {
            since: None,
            cursor: ovstorage::WatchDirectoryCursor::default(),
        }],
    );
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack.list(list_request("file:///d/"), None).await.unwrap();
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(inner.stats.load(Ordering::SeqCst), 0);

    drain(
        stack
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: Url::parse("file:///d/").unwrap(),
                    options: WatchDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .unwrap(),
    )
    .await;

    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        inner.stats.load(Ordering::SeqCst),
        1,
        "a lapsed watch must drop the watched subtree's cached entries"
    );
}

#[tokio::test]
async fn metadata_cache_empty_watch_end_sweeps_only_watched_subtree() {
    let inside = Url::parse("file:///d/inside").unwrap();
    let outside = Url::parse("file:///other/outside").unwrap();
    let inner = CacheProbe::new(b"content", Vec::new());
    let backend = ScriptedWatchProbe::new(inner.clone(), Vec::new());
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend,
        LayerConfig::new(),
    )
    .await
    .unwrap();

    stack.stat(stat_request(&inside), None).await.unwrap();
    stack.stat(stat_request(&outside), None).await.unwrap();
    assert_eq!(inner.stats.load(Ordering::SeqCst), 2);

    drain(
        stack
            .watch_directory(
                Request::new(WatchDirectoryRequest {
                    prefix: Url::parse("file:///d/").unwrap(),
                    options: WatchDirectoryOptions::default(),
                }),
                None,
            )
            .await
            .unwrap(),
    )
    .await;

    stack.stat(stat_request(&inside), None).await.unwrap();
    assert_eq!(
        inner.stats.load(Ordering::SeqCst),
        3,
        "an empty-ended watch must sweep the watched metadata subtree"
    );
    stack.stat(stat_request(&outside), None).await.unwrap();
    assert_eq!(
        inner.stats.load(Ordering::SeqCst),
        3,
        "the terminal sweep must not clear unrelated metadata"
    );
}

#[tokio::test]
async fn list_backed_stat_delegates_for_a_slashless_directory_entry() {
    // The directory-form guard in `stat_from_parent_list` tests the REQUEST
    // SPELLING, so a directory whose listed address carries no trailing slash
    // slips past it and reaches `find_in_page`. What that finds is a
    // directory-like entry at the same node, which is not something a listing
    // page can answer a `stat` with — so the cache delegates. Matching
    // `ObjectKind::File` alone turned the miss into an authoritative
    // `NotFound` for a directory the very same listing reported, without ever
    // consulting the backend. The file backend emits slashless directory
    // addresses (`Url::from_file_path` never appends a separator), so that was
    // reachable in ordinary use.
    //
    // `opted_in` is false so the wrapper cannot fetch a listing of its own:
    // the only thing that can answer here is the page the caller's own `list`
    // cached, which is exactly the reported scenario.
    let file = Url::parse("file:///d/f").unwrap();
    let dir = Url::parse("file:///d/docs").unwrap();
    let mut dir_entry = object_info(dir.clone(), 0);
    dir_entry.kind = ovstorage::ObjectKind::Directory;
    dir_entry.size = None;

    let backend = ListBackedProbe::new(vec![object_info(file.clone(), 7), dir_entry], false);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    // A plain caller-issued listing of the parent, as a browser would do.
    stack.list(list_request("file:///d/"), None).await.unwrap();
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);

    stack
        .stat(stat_request(&dir), None)
        .await
        .expect("a directory the listing reported must not come back NotFound");
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        1,
        "the slashless spelling delegates to the backend"
    );

    // The other spelling of the same node takes the documented directory-form
    // path and delegates too, so both spellings agree.
    let dir_slash = Url::parse("file:///d/docs/").unwrap();
    stack.stat(stat_request(&dir_slash), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "the slash spelling delegates to the backend"
    );

    // The page still answers for a file, from cache, without a backend stat.
    stack.stat(stat_request(&file), None).await.unwrap();
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        2,
        "a File entry in a complete page still answers the stat from cache"
    );
}

/// A caller's credentials are not part of what an address names, so they must
/// not decide whether the cache can see the entry the listing reported.
///
/// Routing, `node_key`, the policy matcher and the cache key itself all treat
/// userinfo as irrelevant to identity, and a plugin synthesizes its listing
/// entries from the configured root — which carries none. A `File` match on
/// full `Url` equality is the one comparison that disagrees with all of them:
/// `stat s3://caller@bucket/key` routes, lists, misses its own entry, and a
/// complete page turns that miss into an authoritative `NotFound` without
/// consulting the backend.
///
/// The trailing slash stays load-bearing on this arm: `docs` and `docs/` may be
/// two objects on a flat store, so the comparison drops userinfo and nothing
/// else.
#[tokio::test]
async fn list_backed_stat_ignores_caller_credentials_when_matching_an_entry() {
    let entry = Url::parse("s3://bucket/key").unwrap();
    let with_credentials = Url::parse("s3://caller@bucket/key").unwrap();
    let backend =
        ListBackedProbe::rooted("s3://bucket/", vec![object_info(entry.clone(), 7)], true);
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();

    let info = stack
        .stat(stat_request(&with_credentials), None)
        .await
        .expect("a credential-bearing address must find its own listing entry");
    assert_eq!(
        info.size,
        Some(7),
        "the answer must come from the listing entry, not a synthesized one"
    );
    assert_eq!(
        info.address, with_credentials,
        "the answer is addressed as the caller asked"
    );
    assert_eq!(backend.lists.load(Ordering::SeqCst), 1);
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        0,
        "answered from the listing"
    );

    // The good input's mirror: an address that genuinely is not in a complete
    // page is still an authoritative NotFound, so the widened comparison did
    // not turn the whole arm off.
    let missing = Url::parse("s3://caller@bucket/absent").unwrap();
    let error = stack.stat(stat_request(&missing), None).await.unwrap_err();
    assert_eq!(error.code(), ErrorCode::NotFound);

    // And the trailing slash still distinguishes two objects on a flat store,
    // which is the half of the comparison that must NOT be widened. The page
    // holds a slash-terminated object; a stat of the slashless name must not be
    // answered with its size and etag. (The mirror — a directory-form stat —
    // never reaches this scan at all: `stat_from_parent_list` delegates every
    // `address::is_directory` request before it.)
    let slashed_entry = Url::parse("s3://bucket/key/").unwrap();
    let backend = ListBackedProbe::rooted(
        "s3://bucket/",
        vec![object_info(slashed_entry.clone(), 7)],
        true,
    );
    let stack = build_stack(
        METADATA_CACHE_KIND,
        Arc::new(MetadataCacheWrapperFactory::default()),
        backend.clone(),
        LayerConfig::new(),
    )
    .await
    .unwrap();
    let error = stack
        .stat(stat_request(&with_credentials), None)
        .await
        .unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::NotFound,
        "the trailing slash must stay load-bearing on the File arm"
    );
    assert_eq!(
        backend.stats.load(Ordering::SeqCst),
        0,
        "and the answer is the page's, not the backend's"
    );
}
