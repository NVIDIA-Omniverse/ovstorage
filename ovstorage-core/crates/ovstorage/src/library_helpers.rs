// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Identity needed to mint routes for a watched connection without
/// looking up an existing route. Captured in `add_connection` so the
/// dynamic-roots watcher can populate routes from an empty starting
/// state — required for backends that defer route discovery until
/// after interactive auth (e.g. the services-client on cold-start OIDC).
#[derive(Clone)]
pub(crate) struct WatchedRouteSeed {
    pub display_name: Option<String>,
    pub backend_id: BackendId,
    pub backend_kind: String,
    pub backend: Arc<dyn shim::Backend>,
}

pub(crate) struct AddressRootsWatcherHandle {
    pub cancel: CancellationToken,
    pub status: tokio::sync::watch::Receiver<AddressRootsWatcherStatus>,
    pub seed: WatchedRouteSeed,
}

#[derive(Clone, Debug)]
pub(crate) enum AddressRootsWatcherStatus {
    Pending,
    Applied,
    Ended,
    Failed(Error),
}

pub(crate) struct AddressRootWatcher {
    library: Weak<Library>,
    rx: std::sync::mpsc::Receiver<()>,
    snapshot: Vec<AddressRoot>,
    emit_snapshot: bool,
    cancel: Option<CancellationToken>,
}

impl AddressRootWatcher {
    pub(crate) fn new(
        library: Weak<Library>,
        rx: std::sync::mpsc::Receiver<()>,
        snapshot: Vec<AddressRoot>,
        cancel: Option<CancellationToken>,
    ) -> Self {
        Self {
            library,
            rx,
            snapshot,
            emit_snapshot: true,
            cancel,
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
    }
}

impl Iterator for AddressRootWatcher {
    type Item = Result<Vec<AddressRoot>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cancelled() {
            return None;
        }
        if self.emit_snapshot {
            self.emit_snapshot = false;
            return Some(Ok(self.snapshot.clone()));
        }

        loop {
            if self.cancelled() {
                return None;
            }
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    while self.rx.try_recv().is_ok() {}
                    let library = self.library.upgrade()?;
                    return Some(library.list_address_roots());
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

fn lookup_stat_from_metadata_list(
    cache: &MetadataCache,
    parent: &Url,
    addr: &Url,
) -> Option<MetadataStatLookup> {
    let key = MetadataCacheKey {
        kind: MetadataKind::List,
        principal_id: None,
        address: parent.as_str().to_string(),
        options_hash: hash_list_options(&ListOptions::default()),
    };
    let Some(MetadataCachePayload::List(page)) = cache.get(&key) else {
        return None;
    };
    for item in page.items {
        if item.address == *addr && item.kind == ObjectKind::File {
            let mut info = item;
            info.address = addr.clone();
            return Some(MetadataStatLookup::Found(info));
        }
    }
    Some(MetadataStatLookup::NotFound)
}

impl Library {
    pub async fn list_page(
        &self,
        prefix: Url,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let _span = tracing::info_span!(
            "ovstorage.list_page",
            object.address = %RedactedUrl(&prefix),
            recursive = opts.recursive,
            full_metadata = opts.full_metadata,
            max_results = opts.max_results
        );
        let prefix = address::to_directory(&prefix)?;
        let (route, target) = self.resolve(&prefix)?;
        if !route.capabilities.supports_list {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support list",
            ));
        }
        let backend_opts = ListOptions {
            max_results: None,
            page_token: None,
            ..opts.clone()
        };
        let items = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let backend_opts = backend_opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.list(target, backend_opts, cancel).await }
            })
            .await?
            .into_iter()
            .map(|item| project_object_info(&prefix, &target.resolved_address, item, "list"))
            .collect::<Result<Vec<_>>>()?;
        let items = fold_markers_and_infer_subdir_kinds(
            &prefix,
            items,
            route.capabilities.has_real_directories,
            opts.recursive,
        );
        let page = paginate_list_items(items, opts.max_results, opts.page_token.clone())?;
        self.maybe_store_metadata_list(&prefix, &opts, &page);
        Ok(page)
    }

    pub(crate) async fn stat_once(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let (route, target) = self.resolve(&addr)?;
        let retry_cfg = route.retry.unwrap_or(self.retry_default);
        let mut info = retry::with_retry_async(&retry_cfg, || {
            let target = target.clone();
            let opts = opts.clone();
            let backend = route.backend.clone();
            let cancel = cancel.clone();
            async move { backend.stat(target, opts, cancel).await }
        })
        .await?;
        info.address = addr;
        Ok(info)
    }

    pub(crate) async fn stat_from_parent_list(
        &self,
        addr: &Url,
        cancel: Option<CancellationToken>,
    ) -> MetadataStatLookup {
        let Some(cache) = &self.metadata_cache else {
            return MetadataStatLookup::Unavailable;
        };
        if addr.query().is_some() || addr.fragment().is_some() {
            return MetadataStatLookup::Unavailable;
        }
        let Some((parent, _name)) = address::parent_and_name(addr) else {
            return MetadataStatLookup::Unavailable;
        };

        if let Some(result) = lookup_stat_from_metadata_list(cache, &parent, addr) {
            return result;
        }

        if !self
            .resolve_route(&parent)
            .map(|route| {
                let capabilities = &route.capabilities;
                capabilities.supports_list && capabilities.wants_list_backed_stat
            })
            .unwrap_or(false)
        {
            return MetadataStatLookup::Unavailable;
        }

        let items = match self
            .list(parent.clone(), ListOptions::default(), cancel)
            .await
        {
            Ok(items) => items,
            Err(_) => return MetadataStatLookup::Unavailable,
        };
        if let Some(result) = lookup_stat_from_metadata_list(cache, &parent, addr) {
            return result;
        }
        items
            .into_iter()
            .find_map(|item| {
                if item.address == *addr && item.kind == ObjectKind::File {
                    let mut info = item;
                    info.address = addr.clone();
                    Some(MetadataStatLookup::Found(info))
                } else {
                    None
                }
            })
            .unwrap_or(MetadataStatLookup::NotFound)
    }

    pub async fn broker_read_step(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::ReadResult> {
        let (route, target) = self.resolve(&addr)?;
        let cache_key = cache_key(&target, self.policy_partition());
        let cacheable_read = opts.if_match.is_none() && opts.range.is_none();
        if cacheable_read && let Some(cache) = &self.cache {
            if let Some(cached) = cache.get_entry_async(&cache_key).await? {
                return Ok(ReadResult::Bytes {
                    bytes: cached.bytes,
                    info: cached_info(addr, cached.entry.size),
                });
            }
            // Concurrent races tolerated; cache insert is idempotent.
            match route
                .backend
                .read(target.clone(), opts.clone(), cancel.clone())
                .await?
            {
                ReadResult::Bytes { bytes, mut info } => {
                    info.address = addr.clone();
                    self.cache_bytes(&cache_key, &bytes)?;
                    return Ok(ReadResult::Bytes { bytes, info });
                }
                ReadResult::Stream { stream, mut info } => {
                    info.address = addr.clone();
                    // Stream passes through to the broker; never drain
                    // to a Vec. Cache bypassed for streamed reads.
                    return Ok(ReadResult::Stream { stream, info });
                }
                ReadResult::LocalDelegate(local) => {
                    let bytes = tokio::fs::read(&local.path).await.map_err(io_error)?;
                    let mut info = local.info;
                    info.address = addr.clone();
                    self.cache_bytes(&cache_key, &bytes)?;
                    return Ok(ReadResult::Bytes { bytes, info });
                }
                ReadResult::Redirect(redirect) => {
                    return Ok(ReadResult::Redirect(redirect));
                }
            }
        }
        match route.backend.read(target, opts, cancel).await? {
            ReadResult::Bytes { bytes, mut info } => {
                info.address = addr;
                if cacheable_read {
                    self.cache_bytes(&cache_key, &bytes)?;
                }
                Ok(ReadResult::Bytes { bytes, info })
            }
            ReadResult::Stream { stream, mut info } => {
                info.address = addr;
                Ok(ReadResult::Stream { stream, info })
            }
            ReadResult::LocalDelegate(mut local) => {
                local.info.address = addr;
                Ok(ReadResult::LocalDelegate(local))
            }
            ReadResult::Redirect(redirect) => Ok(ReadResult::Redirect(redirect)),
        }
    }

    pub(crate) fn resolve_route(&self, addr: &Url) -> Result<Route> {
        self.resolve_backend_route(addr).map(|(route, _)| route)
    }

    /// Run `op` under the route's retry policy. On
    /// `PermissionDenied` / `AuthRequired` / `AuthExpired`,
    /// invalidates the resolved-credential cache and re-runs `op`
    /// exactly once. A second auth failure propagates without a third
    /// attempt.
    pub(crate) async fn with_route_retry<T, F, Fut>(&self, route: &Route, mut op: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        // Lazy bring-up: if the route's connection is parked
        // (`AwaitingAuth` / `AuthFailed`), drive `bring_up_or_fail` before
        // dispatching. `Anonymous` and `Authenticated` connections take the
        // fast path. Routes without a connection_id (e.g. programmatic
        // add_rewrite_route) skip this entirely.
        if let Some(conn_id) = route.connection_id.as_ref() {
            let needs_bringup = self
                .lookup_connection(conn_id)
                .map(|c| {
                    matches!(
                        c.auth_state,
                        ConnectionAuthState::AwaitingAuth { .. }
                            | ConnectionAuthState::AuthFailed { .. }
                    )
                })
                .unwrap_or(false);
            if needs_bringup {
                self.bring_up_or_fail(conn_id).await?;
            }
        }
        let cfg = route.retry.unwrap_or(self.retry_default);
        let first = retry::with_retry_async(&cfg, &mut op).await;
        match first {
            Err(err) if is_credential_failure(&err) => {
                let principal = self.principal_for_route(route);
                self.invalidate_credentials(&route.backend_id, &principal);
                tracing::debug!(
                    plugin = route.backend_id.0.as_str(),
                    error.code = ?err.code(),
                    "credential failure: invalidated cache and retrying once"
                );
                retry::with_retry_async(&cfg, op).await
            }
            other => other,
        }
    }

    /// Falls back to the route's connection_id when the dispatcher
    /// doesn't have a per-call principal — keeps the cache key stable
    /// across calls on the same connection.
    pub(crate) fn principal_for_route(&self, route: &Route) -> auth::PrincipalView {
        match &route.connection_id {
            Some(id) => auth::PrincipalView::new(id.0.clone()),
            None => auth::PrincipalView::new("default"),
        }
    }

    pub(crate) fn resolve(&self, addr: &Url) -> Result<(Route, ResolvedTarget)> {
        let (route, dispatch_addr) = self.resolve_backend_route(addr)?;
        let resolved_address = match &route.rewrite_to {
            Some(rewrite_to) => address::replace_prefix(&dispatch_addr, &route.prefix, rewrite_to)?,
            None => dispatch_addr,
        };
        tracing::debug!(
            route.id = route.backend_id.0.as_str(),
            route.prefix = %RedactedUrl(&route.prefix),
            resolved.address = %RedactedUrl(&resolved_address),
            "resolved route"
        );
        let backend_id = route.backend_id.clone();
        Ok((
            route,
            ResolvedTarget {
                backend_id,
                resolved_address,
            },
        ))
    }

    pub(crate) fn resolve_backend_route(&self, addr: &Url) -> Result<(Route, Url)> {
        self.resolve_backend_route_inner(addr, false, 0)
    }

    pub(crate) fn resolve_backend_route_inner(
        &self,
        addr: &Url,
        via_alias: bool,
        alias_depth: usize,
    ) -> Result<(Route, Url)> {
        let alias = self.matching_alias(addr)?;
        let route = self.matching_backend_route(addr)?;
        let alias_wins = match (&alias, &route) {
            (Some(alias), Some(route)) => alias.from.as_str().len() > route.prefix.as_str().len(),
            (Some(_), None) => true,
            _ => false,
        };
        if alias_wins {
            if alias_depth > 0 {
                return Err(Error::new(
                    ErrorCode::AliasChainTooLong,
                    "aliases resolve only once",
                ));
            }
            let alias = alias.expect("alias_wins guarantees an alias");
            let rewritten = address::replace_prefix(addr, &alias.from, &alias.to)?;
            return self.resolve_backend_route_inner(&rewritten, true, alias_depth + 1);
        }
        let route = route.ok_or_else(|| {
            if via_alias {
                Error::new(
                    ErrorCode::NotConfigured,
                    "alias target does not match a route",
                )
                .with_next_action(
                    "Add a connection for the backend this alias points at via \
                     library.add_connection(...), then retry.",
                )
            } else {
                Error::new(ErrorCode::NoRoute, "no route matches address").with_next_action(
                    "Call library.add_connection(...) for a backend that serves \
                         this address prefix, or load a saved configuration via \
                         library.load_config(...).",
                )
            }
        })?;
        if !via_alias && self.visibility_for(&route.prefix)? == AddressVisibility::Suppressed {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "address is suppressed by route visibility",
            ));
        }
        Ok((route, addr.clone()))
    }

    pub(crate) fn cache_bytes(&self, cache_key: &str, bytes: &[u8]) -> Result<()> {
        if let Some(cache) = &self.cache {
            cache.put(cache_key, bytes)?;
        }
        Ok(())
    }

    pub(crate) fn materialize_for_local_delegate(
        &self,
        cache_key: &str,
        bytes: &[u8],
        cacheable_read: bool,
    ) -> Result<(std::path::PathBuf, Option<std::sync::Arc<dyn Send + Sync>>)> {
        if cacheable_read && let Some(cache) = &self.cache {
            let put = cache.put_and_lease(cache_key, bytes)?;
            let guard = put
                .lease
                .map(|lease| std::sync::Arc::new(lease) as std::sync::Arc<dyn Send + Sync>);
            return Ok((put.entry.path, guard));
        }
        Ok((materialize_temp_file(bytes)?, None))
    }

    pub(crate) fn materialize_staged_file_for_local_delegate(
        &self,
        cache_key: &str,
        staged_path: &std::path::Path,
        cacheable_read: bool,
    ) -> Result<(std::path::PathBuf, Option<std::sync::Arc<dyn Send + Sync>>)> {
        if cacheable_read && let Some(cache) = &self.cache {
            let put = cache.put_path_and_lease(cache_key, staged_path)?;
            let guard = put
                .lease
                .map(|lease| std::sync::Arc::new(lease) as std::sync::Arc<dyn Send + Sync>);
            return Ok((put.entry.path, guard));
        }
        Ok((staged_path.to_path_buf(), None))
    }

    pub(crate) fn remove_cached(&self, cache_key: &str) -> Result<()> {
        if let Some(cache) = &self.cache {
            cache.remove_index(cache_key)?;
        }
        Ok(())
    }

    pub(crate) fn maybe_store_metadata_list(
        &self,
        prefix: &Url,
        opts: &ListOptions,
        page: &ListPage,
    ) {
        if !list_options_are_cacheable_for_stat(opts)
            || prefix.query().is_some()
            || prefix.fragment().is_some()
        {
            return;
        }
        if let Some(cache) = &self.metadata_cache {
            cache.insert(
                MetadataCacheKey {
                    kind: MetadataKind::List,
                    principal_id: None,
                    address: prefix.as_str().to_string(),
                    options_hash: hash_list_options(opts),
                },
                MetadataCachePayload::List(page.clone()),
            );
            for item in &page.items {
                if item.kind == ObjectKind::File {
                    cache.insert(
                        MetadataCacheKey {
                            kind: MetadataKind::Stat,
                            principal_id: None,
                            address: item.address.as_str().to_string(),
                            options_hash: hash_stat_options(&StatOptions::default()),
                        },
                        MetadataCachePayload::Stat(item.clone()),
                    );
                }
            }
        }
    }

    pub(crate) fn invalidate_metadata_for_parent(&self, addr: &Url) {
        let Some(cache) = &self.metadata_cache else {
            return;
        };
        cache.invalidate_address(addr);
        cache.invalidate_lists_containing(addr);
    }

    pub(crate) fn invalidate_metadata_prefix(&self, prefix: &Url) {
        let Some(cache) = &self.metadata_cache else {
            return;
        };
        cache.invalidate_prefix(prefix);
    }

    /// Drive the backend's `watch_address_roots` stream and apply each
    /// change to the route table. Cancellation comes from
    /// `address_roots_watchers`; the task also exits cleanly when the
    /// library's `self_weak` upgrade fails.
    ///
    /// `seed` carries the metadata needed to mint new routes — without it
    /// a connection that starts with empty `address_roots` (e.g. a
    /// services-client connection waiting on OIDC sign-in) would have nothing
    /// to clone backend identity from when the first Snapshot arrives.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(connection.id = %connection_id.0, backend.kind = %seed.backend_kind),
    )]
    pub(crate) fn spawn_address_roots_watcher(
        &self,
        connection_id: ConnectionId,
        seed: WatchedRouteSeed,
    ) {
        use futures::StreamExt;

        let cancel = CancellationToken::new();
        let (status_tx, status_rx) =
            tokio::sync::watch::channel(AddressRootsWatcherStatus::Pending);
        self.address_roots_watchers.lock().insert(
            connection_id.clone(),
            AddressRootsWatcherHandle {
                cancel: cancel.clone(),
                status: status_rx,
                seed: seed.clone(),
            },
        );
        let weak = self.self_weak.lock().clone();
        let backend = seed.backend.clone();
        tokio::spawn(async move {
            let mut stream = match backend.watch_address_roots(Some(cancel.clone())).await {
                Ok(s) => s,
                Err(error) => {
                    let _ = status_tx.send(AddressRootsWatcherStatus::Failed(error.clone()));
                    if error.code() != ErrorCode::Unsupported {
                        tracing::warn!(
                            connection.id = %connection_id.0,
                            backend.kind = %seed.backend_kind,
                            error = %error.message(),
                            "address-roots watcher: open failed"
                        );
                    }
                    return;
                }
            };
            loop {
                let next = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    next = stream.next() => next,
                };
                match next {
                    None => break,
                    Some(Err(error)) => {
                        let _ = status_tx.send(AddressRootsWatcherStatus::Failed(error.clone()));
                        tracing::warn!(
                            connection.id = %connection_id.0,
                            backend.kind = %seed.backend_kind,
                            error = %error.message(),
                            "address-roots watcher: stream error; ending subscription"
                        );
                        return;
                    }
                    Some(Ok(change)) => {
                        let Some(library) = weak.upgrade() else {
                            break;
                        };
                        library.apply_address_roots_change(&connection_id, &seed, change);
                        let _ = status_tx.send(AddressRootsWatcherStatus::Applied);
                    }
                }
            }
            let _ = status_tx.send(AddressRootsWatcherStatus::Ended);
        });
    }

    pub(crate) async fn wait_for_address_roots_watcher(
        &self,
        connection_id: &ConnectionId,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let Some(mut status) = self
            .address_roots_watchers
            .lock()
            .get(connection_id)
            .map(|handle| handle.status.clone())
        else {
            return Ok(());
        };

        let wait = async {
            loop {
                match status.borrow().clone() {
                    AddressRootsWatcherStatus::Pending => {}
                    AddressRootsWatcherStatus::Applied | AddressRootsWatcherStatus::Ended => {
                        return Ok(());
                    }
                    AddressRootsWatcherStatus::Failed(error)
                        if error.code() == ErrorCode::Unsupported =>
                    {
                        return Ok(());
                    }
                    AddressRootsWatcherStatus::Failed(error) => return Err(error),
                }

                match cancel.as_ref() {
                    Some(cancel) => {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                return Err(Error::new(ErrorCode::Cancelled, "address-roots refresh cancelled"));
                            }
                            changed = status.changed() => {
                                if changed.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    None => {
                        if status.changed().await.is_err() {
                            return Ok(());
                        }
                    }
                }
            }
        };

        match tokio::time::timeout(ADDRESS_ROOTS_REFRESH_TIMEOUT, wait).await {
            Ok(result) => result,
            Err(_) => Err(Error::new(
                ErrorCode::DeadlineExceeded,
                format!(
                    "address-roots refresh timed out after {:?} before backend reported a snapshot",
                    ADDRESS_ROOTS_REFRESH_TIMEOUT
                ),
            )),
        }
    }

    pub(crate) async fn refresh_address_roots_once(
        &self,
        connection_id: &ConnectionId,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        use futures::StreamExt;

        let refresh = async {
            let Some(seed) = self
                .address_roots_watchers
                .lock()
                .get(connection_id)
                .map(|handle| handle.seed.clone())
            else {
                return Ok(());
            };

            let mut stream = match seed.backend.watch_address_roots(cancel.clone()).await {
                Ok(stream) => stream,
                Err(error) if error.code() == ErrorCode::Unsupported => return Ok(()),
                Err(error) => return Err(error),
            };

            let next = match cancel.as_ref() {
                Some(cancel) => {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            return Err(Error::new(ErrorCode::Cancelled, "address-roots refresh cancelled"));
                        }
                        next = stream.next() => next,
                    }
                }
                None => stream.next().await,
            };

            match next {
                Some(Ok(change)) => {
                    self.apply_address_roots_change(connection_id, &seed, change);
                    Ok(())
                }
                Some(Err(error)) if error.code() == ErrorCode::Unsupported => Ok(()),
                Some(Err(error)) => Err(error),
                None => Ok(()),
            }
        };

        match tokio::time::timeout(ADDRESS_ROOTS_REFRESH_TIMEOUT, refresh).await {
            Ok(result) => result,
            Err(_) => Err(Error::new(
                ErrorCode::DeadlineExceeded,
                format!(
                    "address-roots refresh timed out after {:?} before backend reported a snapshot",
                    ADDRESS_ROOTS_REFRESH_TIMEOUT
                ),
            )),
        }
    }

    /// `Snapshot` replaces all routes for the connection; `Added`
    /// appends; `Removed` drops matching. Bumps `route_epoch` once.
    /// `connection.current_addresses` is kept in sync so callers reading
    /// the connection list see the same view as the route table.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            connection.id = %connection_id.0,
            backend.kind = %seed.backend_kind,
            change = match &change {
                AddressRootsChange::Snapshot(r) => format!("Snapshot[{}]", r.len()),
                AddressRootsChange::Added(r) => format!("Added[{}]", r.len()),
                AddressRootsChange::Removed(r) => format!("Removed[{}]", r.len()),
            },
        ),
    )]
    pub(crate) fn apply_address_roots_change(
        &self,
        connection_id: &ConnectionId,
        seed: &WatchedRouteSeed,
        change: AddressRootsChange,
    ) {
        // Bail if the connection was removed mid-flight — re-creating
        // routes for it would resurrect a half-detached connection.
        if !self
            .lock_connections()
            .iter()
            .any(|c| c.id == *connection_id)
        {
            tracing::debug!(
                connection.id = %connection_id.0,
                backend.kind = %seed.backend_kind,
                "address-roots watcher: connection removed; dropping change"
            );
            return;
        }

        let mut routes = self.lock_routes_mut();
        match change {
            AddressRootsChange::Snapshot(roots) => {
                routes.retain(|route| route.connection_id.as_ref() != Some(connection_id));
                for root in roots {
                    routes.push(Route {
                        prefix: root.address,
                        rewrite_to: None,
                        backend_id: seed.backend_id.clone(),
                        backend: seed.backend.clone(),
                        backend_kind: seed.backend_kind.clone(),
                        display_name: seed.display_name.clone(),
                        connection_id: Some(connection_id.clone()),
                        source: RouteSource::ConnectionContributed {
                            connection_id: connection_id.clone(),
                        },
                        capabilities: root.capabilities,
                        retry: None,
                    });
                }
            }
            AddressRootsChange::Added(roots) => {
                for root in roots {
                    if routes.iter().any(|route| route.prefix == root.address) {
                        continue;
                    }
                    routes.push(Route {
                        prefix: root.address,
                        rewrite_to: None,
                        backend_id: seed.backend_id.clone(),
                        backend: seed.backend.clone(),
                        backend_kind: seed.backend_kind.clone(),
                        display_name: seed.display_name.clone(),
                        connection_id: Some(connection_id.clone()),
                        source: RouteSource::ConnectionContributed {
                            connection_id: connection_id.clone(),
                        },
                        capabilities: root.capabilities,
                        retry: None,
                    });
                }
            }
            AddressRootsChange::Removed(roots) => {
                routes.retain(|route| {
                    route.connection_id.as_ref() != Some(connection_id)
                        || !roots.iter().any(|root| root.address == route.prefix)
                });
            }
        }
        sort_routes(&mut routes);
        let new_addresses: Vec<Url> = routes
            .iter()
            .filter(|route| route.connection_id.as_ref() == Some(connection_id))
            .map(|route| route.prefix.clone())
            .collect();
        let new_capabilities = routes
            .iter()
            .find(|route| route.connection_id.as_ref() == Some(connection_id))
            .map(|route| route.capabilities.clone())
            .unwrap_or_else(Capabilities::empty);
        drop(routes);
        if let Some(slot) = self
            .lock_connections()
            .iter_mut()
            .find(|c| c.id == *connection_id)
        {
            slot.current_addresses = new_addresses;
            slot.capabilities = new_capabilities;
        }
        self.bump_route_epoch();
    }

    /// Connect-or-park: try to bring `request` live silently against its
    /// registered factory. On full success the real backend is installed
    /// the same way as `Storage::add_connection`; on any failure (auth
    /// missing, refresh expired, broker unreachable, transient network)
    /// the cached top-level addresses are seeded as routes against an
    /// `AwaitingAuthStub` and the connection enters `AwaitingAuth`.
    /// First-run (no cache) connections fall through to the live path.
    pub(crate) async fn add_connection_lazy(
        &self,
        request: ConnectionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.persist {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "persistent direct-mode connections require a keyring-backed config layer",
            ));
        }
        let factory = self.factory_for_kind(&request.backend_kind)?;
        let identity = auth::connection_identity(&request);
        let cached = match self.auth_lock() {
            Some(lock) => lock.load_address_roots(&identity)?,
            None => None,
        };

        let connection = match cached {
            Some(cached) => match try_live_bringup(&factory, &request, cancel).await {
                Ok(instance)
                    if matches!(
                        instance.auth_state,
                        ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
                    ) =>
                {
                    let conn = self.install_live_connection(&request, instance)?;
                    self.persist_address_roots(&identity, &conn);
                    conn
                }
                Ok(instance) => {
                    // Plugin reported a non-authenticated state without
                    // erroring — typically a dynamic-roots backend that
                    // returns an empty address list until the user signs
                    // in. Treat as a stub install on the cached roots so
                    // the user keeps the routes they had before.
                    let reason = match &instance.auth_state {
                        ConnectionAuthState::AwaitingAuth { reason, .. } => reason.clone(),
                        _ => AuthReason::NeverAuthenticated,
                    };
                    let conn = self.install_stub_connection(
                        &request,
                        &cached,
                        reason,
                        Error::new(
                            ErrorCode::AuthRequired,
                            "silent bring-up returned without authenticated state",
                        ),
                    )?;
                    let seed = WatchedRouteSeed {
                        display_name: Some(conn.display_name.clone()),
                        backend_id: instance.backend_id,
                        backend_kind: conn.backend_kind.clone(),
                        backend: instance.backend,
                    };
                    self.spawn_address_roots_watcher(conn.id.clone(), seed);
                    conn
                }
                Err(err) => {
                    let reason = match &err {
                        BringupError::Auth(_) => AuthReason::NeverAuthenticated,
                        BringupError::Backend(_) => AuthReason::BackendUnreachable,
                    };
                    self.install_stub_connection(&request, &cached, reason, err.into_error())?
                }
            },
            None => {
                // First run: defer to the standard live path so failures
                // surface to load_config (no cached fallback exists).
                let conn = <Self as Storage>::add_connection(self, request.clone(), cancel).await?;
                self.persist_address_roots(&identity, &conn);
                conn
            }
        };
        self.retain_request(&connection.id, request);
        Ok(connection)
    }

    pub(crate) fn factory_for_kind(&self, kind: &str) -> Result<Arc<dyn shim::Factory>> {
        self.backend_factories
            .read()
            .get(kind)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotConfigured, "backend kind is not registered"))
    }

    pub(crate) fn auth_lock(&self) -> Option<Arc<auth::AuthRefreshLock>> {
        crate::loader::substrate().map(|provider| provider.refresh_lock.clone())
    }

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend.kind = %request.backend_kind, roots = instance.address_roots.len()),
    )]
    pub(crate) fn install_live_connection(
        &self,
        request: &ConnectionRequest,
        instance: shim::BackendInstance,
    ) -> Result<Connection> {
        let now = SystemTime::now();
        let id = ConnectionId(fresh_id("conn"));
        let display_name = request
            .display_name
            .clone()
            .or_else(|| instance.display_name.clone())
            .unwrap_or_else(|| request.backend_kind.clone());
        let connection_capabilities = instance
            .address_roots
            .first()
            .map(|root| root.capabilities.clone())
            .unwrap_or_else(Capabilities::empty);
        let connection = Connection {
            id,
            backend_kind: request.backend_kind.clone(),
            display_name,
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: connection_capabilities,
            current_addresses: instance
                .address_roots
                .iter()
                .map(|root| root.address.clone())
                .collect(),
            auth_state: instance.auth_state.clone(),
            last_probed: Some(now),
            user_metadata: UserMetadata::new(),
        };
        let seed = WatchedRouteSeed {
            display_name: Some(connection.display_name.clone()),
            backend_id: instance.backend_id.clone(),
            backend_kind: connection.backend_kind.clone(),
            backend: instance.backend.clone(),
        };
        self.add_connection_routes(&connection, instance)?;
        self.lock_connections().push(connection.clone());
        self.bump_route_epoch();
        // Always spawn; backends that don't expose a roots stream return
        // `Unsupported` and the watcher exits quietly.
        self.spawn_address_roots_watcher(connection.id.clone(), seed);
        Ok(connection)
    }

    fn install_stub_connection(
        &self,
        request: &ConnectionRequest,
        cached: &auth::CachedAddressRoots,
        reason: AuthReason,
        last_error: Error,
    ) -> Result<Connection> {
        let now = SystemTime::now();
        let id = ConnectionId(fresh_id("conn"));
        let display_name = request
            .display_name
            .clone()
            .or_else(|| cached.display_name.clone())
            .unwrap_or_else(|| request.backend_kind.clone());
        let mut current_addresses = Vec::with_capacity(cached.addresses.len());
        for raw in &cached.addresses {
            current_addresses.push(address::parse(raw)?);
        }
        let connection = Connection {
            id: id.clone(),
            backend_kind: request.backend_kind.clone(),
            display_name,
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: current_addresses.clone(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: reason.clone(),
                last_attempt: Some(AuthAttempt {
                    at: now,
                    error: Some(last_error),
                }),
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        };
        let stub: Arc<dyn shim::Backend> =
            crate::stub_backend::AwaitingAuthStub::new(id.clone(), reason);
        // Reuse add_connection_routes by synthesizing a BackendInstance
        // wrapping the stub.
        let synthetic = shim::BackendInstance {
            backend_id: BackendId(format!("awaiting-auth:{}", id.0)),
            backend: stub,
            address_roots: current_addresses
                .iter()
                .map(|addr| AddressRoot {
                    address: addr.clone(),
                    display_name: Some(connection.display_name.clone()),
                    backend_kind: connection.backend_kind.clone(),
                    connection_id: Some(id.clone()),
                    capabilities: Capabilities::empty(),
                    source: RouteSource::ConnectionContributed {
                        connection_id: id.clone(),
                    },
                    visibility: AddressVisibility::Visible,
                    user_metadata: UserMetadata::new(),
                })
                .collect(),
            display_name: Some(connection.display_name.clone()),
            auth_state: connection.auth_state.clone(),
        };
        self.add_connection_routes(&connection, synthetic)?;
        self.lock_connections().push(connection.clone());
        self.bump_route_epoch();
        Ok(connection)
    }

    /// Drive a stub-installed connection live on first dispatch. Idempotent
    /// across concurrent callers via a per-connection async mutex.
    ///
    /// `force` skips the per-connection cooldown so `reauth` can retry an
    /// unreachable backend immediately.
    /// Silent retry of `try_live_bringup` for a parked connection. Returns
    /// `Ok(())` when the connection moves to `Authenticated`; returns an
    /// `Error` (typed `AuthRequired` / `BackendUnreachable` / network) when
    /// it can't, leaving the stub backend in place.
    ///
    /// **Does not drive interactive auth.** When silent fails with an auth
    /// error, the typed `AuthRequired` propagates to the caller — the host
    /// or app then decides whether to invoke
    /// [`Library::authenticate_connection`] to drive the interactive flow
    /// (which returns an `AuthEventStream` so URLs / device codes can be
    /// surfaced through the host's UI). Re-running the silent path on every
    /// dispatch attempt is gated by a per-connection cooldown to avoid
    /// probe-storms on a known-down backend.
    pub(crate) async fn bring_up_or_fail(&self, connection_id: &ConnectionId) -> Result<()> {
        // Fast path: already authenticated or anonymous (no auth needed).
        let initial = self.lookup_connection(connection_id);
        match &initial {
            Some(conn)
                if matches!(
                    conn.auth_state,
                    ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous,
                ) =>
            {
                return Ok(());
            }
            None => {
                return Err(Error::new(ErrorCode::NotFound, "connection does not exist"));
            }
            Some(_) => {}
        }

        if self.in_cooldown(connection_id) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "connection awaiting bring-up; retry after cooldown or call \
                 `authenticate_connection` to drive interactive auth",
            ));
        }

        let lock = self.bringup_lock_for(connection_id);
        let _guard = lock.lock().await;

        // Re-check state under lock — another waiter may have already brought it up.
        let connection = self.lookup_connection(connection_id);
        let Some(connection) = connection else {
            return Err(Error::new(ErrorCode::NotFound, "connection does not exist"));
        };
        if matches!(
            connection.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ) {
            return Ok(());
        }

        let request = self.retained_request(connection_id)?;
        let factory = self.factory_for_kind(&connection.backend_kind)?;

        match try_live_bringup(&factory, &request, None).await {
            Ok(instance)
                if matches!(
                    instance.auth_state,
                    ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
                ) =>
            {
                self.swap_stub_for_live(connection_id, instance)?;
                let identity = auth::connection_identity(&request);
                if let Some(connection) = self.lookup_connection(connection_id) {
                    self.persist_address_roots(&identity, &connection);
                }
                self.clear_cooldown(connection_id);
                Ok(())
            }
            Ok(_instance) => {
                // Plugin succeeded silently but stayed `AwaitingAuth` (e.g.
                // a dynamic-roots backend whose `instantiate` returns empty
                // address roots until the user signs in). Leave the stub in
                // place; the user needs to drive `authenticate_connection`
                // to make progress.
                let err = Error::new(
                    ErrorCode::AuthRequired,
                    "silent bring-up succeeded without authenticated state — \
                     call `authenticate_connection` to drive the interactive flow",
                );
                self.record_attempt(connection_id, err.clone());
                self.set_cooldown(connection_id);
                Err(err)
            }
            Err(err) => {
                let err = err.into_error();
                self.record_attempt(connection_id, err.clone());
                self.set_cooldown(connection_id);
                Err(err)
            }
        }
    }

    pub(crate) fn lookup_connection(&self, id: &ConnectionId) -> Option<Connection> {
        self.lock_connections()
            .iter()
            .find(|c| &c.id == id)
            .cloned()
    }

    fn bringup_lock_for(&self, id: &ConnectionId) -> Arc<tokio::sync::Mutex<()>> {
        self.bringup_locks
            .lock()
            .entry(id.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn in_cooldown(&self, id: &ConnectionId) -> bool {
        self.bringup_cooldowns
            .lock()
            .get(id)
            .map(|t| t.elapsed() < crate::BRINGUP_COOLDOWN)
            .unwrap_or(false)
    }

    fn set_cooldown(&self, id: &ConnectionId) {
        self.bringup_cooldowns
            .lock()
            .insert(id.clone(), Instant::now());
    }

    fn clear_cooldown(&self, id: &ConnectionId) {
        self.bringup_cooldowns.lock().remove(id);
    }

    /// Flip the connection slot to `Authenticated` after the plugin's
    /// `factory.authenticate` yields `AuthEvent::Succeeded`. Without
    /// this the slot stays `AwaitingAuth` and `with_route_retry` drives
    /// `bring_up_or_fail` on the next dispatch — which calls
    /// `factory.instantiate` again and re-parks the connection because
    /// the silent path doesn't replay the keyring warm-continue.
    pub(crate) fn mark_connection_authenticated(&self, id: &ConnectionId) {
        let now = SystemTime::now();
        if let Some(slot) = self.lock_connections().iter_mut().find(|c| &c.id == id) {
            slot.auth_state = ConnectionAuthState::Authenticated {
                last_authenticated_at: now,
                expires_at: None,
            };
            slot.last_probed = Some(now);
        }
        self.clear_cooldown(id);
    }

    fn record_attempt(&self, id: &ConnectionId, error: Error) {
        if let Some(slot) = self.lock_connections().iter_mut().find(|c| &c.id == id)
            && let ConnectionAuthState::AwaitingAuth { last_attempt, .. } = &mut slot.auth_state
        {
            *last_attempt = Some(AuthAttempt {
                at: SystemTime::now(),
                error: Some(error),
            });
        }
    }

    fn retained_request(&self, id: &ConnectionId) -> Result<Arc<ConnectionRequest>> {
        self.connection_requests
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::NotFound,
                    "no retained ConnectionRequest for connection (lazy bring-up unavailable)",
                )
            })
    }

    pub(crate) fn retain_request(&self, id: &ConnectionId, request: ConnectionRequest) {
        self.connection_requests
            .lock()
            .insert(id.clone(), Arc::new(request));
    }

    pub(crate) fn forget_request(&self, id: &ConnectionId) {
        self.connection_requests.lock().remove(id);
    }

    fn swap_stub_for_live(
        &self,
        connection_id: &ConnectionId,
        instance: shim::BackendInstance,
    ) -> Result<()> {
        let now = SystemTime::now();
        let connection_capabilities = instance
            .address_roots
            .first()
            .map(|root| root.capabilities.clone())
            .unwrap_or_else(Capabilities::empty);
        let new_addresses: Vec<Url> = instance
            .address_roots
            .iter()
            .map(|r| r.address.clone())
            .collect();

        // Drop existing connection-contributed routes for this id.
        self.lock_routes_mut()
            .retain(|route| route.connection_id.as_ref() != Some(connection_id));

        // Update the Connection slot.
        if let Some(slot) = self
            .lock_connections()
            .iter_mut()
            .find(|c| &c.id == connection_id)
        {
            slot.capabilities = connection_capabilities;
            slot.current_addresses = new_addresses;
            slot.auth_state = ConnectionAuthState::Authenticated {
                last_authenticated_at: now,
                expires_at: None,
            };
            slot.last_probed = Some(now);
        }

        let connection = self
            .lookup_connection(connection_id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection vanished mid-bringup"))?;
        self.add_connection_routes(&connection, instance)?;
        self.bump_route_epoch();
        Ok(())
    }

    fn persist_address_roots(&self, identity: &str, connection: &Connection) {
        let Some(lock) = self.auth_lock() else { return };
        let entry = auth::CachedAddressRoots {
            backend_kind: connection.backend_kind.clone(),
            display_name: Some(connection.display_name.clone()),
            addresses: connection
                .current_addresses
                .iter()
                .map(|u| u.to_string())
                .collect(),
            cached_unix_ms: now_unix_ms(),
        };
        if let Err(err) = lock.store_address_roots(identity, &entry) {
            tracing::warn!(
                error.code = ?err.code(),
                error.message = %err.message(),
                "failed to persist cached address roots"
            );
        }
    }

    pub(crate) fn add_connection_routes(
        &self,
        connection: &Connection,
        instance: shim::BackendInstance,
    ) -> Result<()> {
        let mut routes = self.lock_routes_mut();
        for prefix in &connection.current_addresses {
            if routes.iter().any(|route| route.prefix == *prefix) {
                return Err(Error::new(
                    ErrorCode::RouteConflict,
                    format!("connection route prefix '{prefix}' already exists"),
                ));
            }
            // Match the prefix to an instance.address_roots entry so each
            // route gets that root's capability profile, not a flat one.
            let capabilities = instance
                .address_roots
                .iter()
                .find(|root| &root.address == prefix)
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty);
            routes.push(Route {
                prefix: prefix.clone(),
                rewrite_to: None,
                backend_id: instance.backend_id.clone(),
                backend: instance.backend.clone(),
                backend_kind: connection.backend_kind.clone(),
                display_name: Some(connection.display_name.clone()),
                connection_id: Some(connection.id.clone()),
                source: RouteSource::ConnectionContributed {
                    connection_id: connection.id.clone(),
                },
                capabilities,
                retry: None,
            });
        }
        sort_routes(&mut routes);
        Ok(())
    }

    pub(crate) fn matching_backend_route(&self, addr: &Url) -> Result<Option<Route>> {
        Ok(self
            .lock_routes()
            .iter()
            .filter(|route| address::is_prefix_of(&route.prefix, addr))
            .max_by(|left, right| left.prefix.as_str().len().cmp(&right.prefix.as_str().len()))
            .cloned())
    }

    pub(crate) fn matching_alias(&self, addr: &Url) -> Result<Option<Alias>> {
        Ok(self
            .lock_aliases()
            .iter()
            .filter(|alias| address::is_prefix_of(&alias.from, addr))
            .max_by(|left, right| left.from.as_str().len().cmp(&right.from.as_str().len()))
            .cloned())
    }

    pub(crate) fn alias_state_for_target(&self, target: &Url) -> Result<AliasState> {
        let alias = self.matching_alias(target)?;
        let route = self.matching_backend_route(target)?;
        let alias_wins = match (&alias, &route) {
            (Some(alias), Some(route)) => alias.from.as_str().len() > route.prefix.as_str().len(),
            (Some(_), None) => true,
            _ => false,
        };
        if alias_wins {
            Ok(AliasState::ChainTooLong {
                reason: "target resolves to another alias".into(),
            })
        } else if route.is_some() {
            Ok(AliasState::Live)
        } else {
            Ok(AliasState::Dangling)
        }
    }

    pub(crate) fn visibility_for(&self, address: &Url) -> Result<AddressVisibility> {
        Ok(self
            .lock_visibility_overrides()
            .iter()
            .find(|row| row.address == *address)
            .map(|row| row.visibility)
            .unwrap_or(AddressVisibility::Visible))
    }

    // parking_lot locks never poison; the `_mut` siblings give an
    // explicit write guard for `RwLock`-backed fields.

    pub(crate) fn lock_routes(&self) -> parking_lot::RwLockReadGuard<'_, Vec<Route>> {
        self.routes.read()
    }

    pub(crate) fn lock_routes_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Vec<Route>> {
        self.routes.write()
    }

    pub(crate) fn lock_connections(&self) -> parking_lot::MutexGuard<'_, Vec<Connection>> {
        self.connections.lock()
    }

    pub(crate) fn lock_aliases(&self) -> parking_lot::RwLockReadGuard<'_, Vec<Alias>> {
        self.aliases.read()
    }

    pub(crate) fn lock_aliases_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Vec<Alias>> {
        self.aliases.write()
    }

    pub(crate) fn lock_visibility_overrides(
        &self,
    ) -> parking_lot::RwLockReadGuard<'_, Vec<AddressVisibilityOverride>> {
        self.visibility_overrides.read()
    }

    pub(crate) fn lock_visibility_overrides_mut(
        &self,
    ) -> parking_lot::RwLockWriteGuard<'_, Vec<AddressVisibilityOverride>> {
        self.visibility_overrides.write()
    }
}

/// Codes that trigger credential-cache invalidation; see
/// `Library::with_route_retry`.
pub(crate) fn is_credential_failure(err: &Error) -> bool {
    matches!(
        err.code(),
        ErrorCode::PermissionDenied | ErrorCode::AuthRequired | ErrorCode::AuthExpired,
    )
}

/// Result of trying to bring a connection up silently (no interactive auth).
/// Either the connection went live (caller installs the real backend) or it
/// failed; the failure reason determines whether the dispatcher should defer
/// to interactive auth or simply retry the silent path on the next request.
pub(crate) enum BringupError {
    /// Silent auth couldn't acquire credentials. Driving
    /// `Factory::authenticate` is the fix.
    Auth(Error),
    /// Probe / instantiate failed for a non-auth reason — backend unreachable,
    /// transient network error, config issue. Retrying the silent path is
    /// the fix; interactive auth wouldn't help.
    Backend(Error),
}

impl BringupError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            BringupError::Auth(e) | BringupError::Backend(e) => e,
        }
    }
}

/// Run `factory.instantiate(...)` silently and classify any failure.
/// Used by both `add_connection_lazy` (at startup) and `bring_up_or_fail`
/// (on first dispatch).
pub(crate) async fn try_live_bringup(
    factory: &Arc<dyn shim::Factory>,
    request: &ConnectionRequest,
    cancel: Option<CancellationToken>,
) -> std::result::Result<shim::BackendInstance, BringupError> {
    factory
        .instantiate(request, cancel)
        .await
        .map_err(classify_bringup_error)
}

fn classify_bringup_error(err: Error) -> BringupError {
    if is_credential_failure(&err) {
        BringupError::Auth(err)
    } else {
        BringupError::Backend(err)
    }
}

pub(crate) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}
