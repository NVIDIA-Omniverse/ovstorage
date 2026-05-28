// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Bridge the async `factory.update_credentials` into the sync iterator
/// adapter on `AuthEventStream`. Spawns a one-off thread + tokio runtime
/// because the iterator consumer's context isn't guaranteed to be tokio.
fn block_on_factory_update(
    factory: Arc<dyn shim::Factory>,
    connection: Connection,
    bundle: SecretBundle,
    cancel: Option<CancellationToken>,
) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("ovs-cred-inst".into())
        .spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = tx.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!("update_credentials bridge: runtime create failed: {err}"),
                    )));
                    return;
                }
            };
            let result = rt.block_on(factory.update_credentials(&connection, bundle, cancel));
            let _ = tx.send(result);
        });
    rx.recv().unwrap_or_else(|err| {
        Err(Error::new(
            ErrorCode::Internal,
            format!("update_credentials bridge: channel closed: {err}"),
        ))
    })
}

/// Bridge a one-shot dynamic-roots refresh into the sync
/// `AuthEventStream` adapter.
fn block_on_address_roots_refresh(
    library: Arc<Library>,
    connection_id: ConnectionId,
    cancel: Option<CancellationToken>,
) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("ovs-root-wait".into())
        .spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = tx.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!("address-roots refresh bridge: runtime create failed: {err}"),
                    )));
                    return;
                }
            };
            let result = rt.block_on(library.refresh_address_roots_once(&connection_id, cancel));
            let _ = tx.send(result);
        });
    rx.recv().unwrap_or_else(|err| {
        Err(Error::new(
            ErrorCode::Internal,
            format!("address-roots refresh bridge: channel closed: {err}"),
        ))
    })
}

fn read_bytes_max_bytes_error(cap: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("read exceeded max_bytes cap of {cap} bytes"),
    )
    .with_next_action(
        "Increase ReadOptions::max_bytes, narrow the read range \
         via ReadOptions::range, or use read_stream to consume \
         the object incrementally.",
    )
}

fn read_stream_max_bytes_error(cap: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!("read_stream exceeded max_bytes cap of {cap} bytes"),
    )
    .with_next_action(
        "Increase ReadOptions::max_bytes or narrow the read range \
         via ReadOptions::range.",
    )
}

fn ensure_read_bytes_within_max_bytes(len: usize, max_bytes: Option<u64>) -> Result<()> {
    if let Some(cap) = max_bytes
        && (len as u64) > cap
    {
        return Err(read_bytes_max_bytes_error(cap));
    }
    Ok(())
}

fn cap_read_stream(inner: ReadStream, cap: u64) -> ReadStream {
    use futures::StreamExt;
    Box::pin(futures::stream::unfold(
        (inner, 0u64, false),
        move |(mut inner, mut total, done)| async move {
            if done {
                return None;
            }
            let chunk_res = inner.next().await?;
            match chunk_res {
                Ok(chunk) => {
                    total = total.saturating_add(chunk.len() as u64);
                    if total > cap {
                        Some((Err(read_stream_max_bytes_error(cap)), (inner, total, true)))
                    } else {
                        Some((Ok(chunk), (inner, total, false)))
                    }
                }
                Err(error) => Some((Err(error), (inner, total, true))),
            }
        },
    ))
}

fn maybe_cap_read_stream(stream: ReadStream, max_bytes: Option<u64>) -> ReadStream {
    match max_bytes {
        Some(cap) => cap_read_stream(stream, cap),
        None => stream,
    }
}

struct TempFileGuard {
    path: Option<std::path::PathBuf>,
}

impl TempFileGuard {
    fn from_path(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> &std::path::Path {
        self.path.as_deref().expect("temp path present")
    }

    fn into_path(mut self) -> std::path::PathBuf {
        self.path.take().expect("temp path present")
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn cancelled_error() -> Error {
    Error::new(ErrorCode::Cancelled, "cancelled by caller")
}

fn check_cancelled(cancel: &Option<CancellationToken>) -> Result<()> {
    if cancel
        .as_ref()
        .map(|token| token.is_cancelled())
        .unwrap_or(false)
    {
        return Err(cancelled_error());
    }
    Ok(())
}

pub(crate) async fn materialize_stream_to_temp_file(
    stream: ReadStream,
    cancel: Option<CancellationToken>,
) -> Result<std::path::PathBuf> {
    materialize_stream_to_path(stream, cancel, materialize_temp_path()).await
}

#[cfg(test)]
pub(crate) async fn materialize_stream_to_test_path(
    stream: ReadStream,
    cancel: Option<CancellationToken>,
    path: std::path::PathBuf,
) -> Result<std::path::PathBuf> {
    materialize_stream_to_path(stream, cancel, path).await
}

async fn materialize_stream_to_path(
    mut stream: ReadStream,
    cancel: Option<CancellationToken>,
    path: std::path::PathBuf,
) -> Result<std::path::PathBuf> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;

    let guard = TempFileGuard::from_path(path);
    let mut file = tokio::fs::File::create(guard.path())
        .await
        .map_err(io_error)?;
    check_cancelled(&cancel)?;
    loop {
        let next = match cancel.as_ref() {
            Some(token) => {
                tokio::select! {
                    _ = token.cancelled() => return Err(cancelled_error()),
                    chunk = stream.next() => chunk,
                }
            }
            None => stream.next().await,
        };
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk?;
        file.write_all(&chunk).await.map_err(io_error)?;
        check_cancelled(&cancel)?;
    }
    file.sync_all().await.map_err(io_error)?;
    drop(file);
    Ok(guard.into_path())
}

#[async_trait::async_trait]
impl Storage for Library {
    fn capabilities_for(&self, prefix: &Url) -> Result<Capabilities> {
        let _span = tracing::info_span!(
            "ovstorage.capabilities_for",
            object.address = %RedactedUrl(prefix)
        );
        let route = self.resolve_route(prefix)?;
        Ok(route.capabilities)
    }

    fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
        let routes = self.lock_routes().clone();
        let aliases = self.lock_aliases().clone();
        let mut roots = Vec::new();
        for route in routes {
            let visibility = self.visibility_for(&route.prefix)?;
            if visibility != AddressVisibility::Visible {
                continue;
            }
            roots.push(AddressRoot {
                address: route.prefix.clone(),
                display_name: route.display_name.clone(),
                backend_kind: route.backend_kind.clone(),
                connection_id: route.connection_id.clone(),
                capabilities: route.capabilities.clone(),
                source: route.source.clone(),
                visibility,
                user_metadata: UserMetadata::new(),
            });
        }
        for alias in aliases {
            if alias.visibility != AddressVisibility::Visible {
                continue;
            }
            roots.push(AddressRoot {
                address: alias.from.clone(),
                display_name: alias.display_name.clone(),
                backend_kind: "alias".into(),
                connection_id: None,
                capabilities: Capabilities::empty(),
                source: RouteSource::Alias {
                    to: alias.to.clone(),
                    alias_source: alias.source.clone(),
                },
                visibility: alias.visibility,
                user_metadata: alias.user_metadata.clone(),
            });
        }
        roots.sort_by(|left, right| left.address.as_str().cmp(right.address.as_str()));
        Ok(roots)
    }

    fn list_backend_kinds(&self) -> Result<Vec<StorageBackendKindDescriptor>> {
        let factories = self.backend_factories.read();
        let mut descriptors = factories
            .values()
            .map(|factory| factory.descriptor())
            .collect::<Vec<_>>();
        descriptors.sort_by(|left, right| left.kind.cmp(&right.kind));
        Ok(descriptors)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend.kind = %request.backend_kind))]
    async fn add_connection(
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
        let factory = self
            .backend_factories
            .read()
            .get(&request.backend_kind)
            .cloned()
            .ok_or_else(|| {
                Error::new(ErrorCode::NotConfigured, "backend kind is not registered")
                    .with_next_action(
                        "Load the backend plugin via library.load_plugin(path) or \
                         library.load_plugins_from_dir(dir) before opening connections \
                         of this kind.",
                    )
            })?;
        let instance = factory.instantiate(&request, cancel.clone()).await?;
        let mut connection = self.install_live_connection(&request, instance)?;
        if connection.current_addresses.is_empty()
            && matches!(
                connection.auth_state,
                ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
            )
        {
            if let Err(error) = self
                .wait_for_address_roots_watcher(&connection.id, cancel)
                .await
            {
                let _ = self.remove_connection(&connection.id);
                return Err(error);
            }
            if let Some(updated) = self.lookup_connection(&connection.id) {
                connection = updated;
            }
        }
        self.retain_request(&connection.id, request);
        Ok(connection)
    }

    fn remove_connection(&self, id: &ConnectionId) -> Result<()> {
        let mut connections = self.lock_connections();
        let before = connections.len();
        connections.retain(|connection| &connection.id != id);
        if connections.len() == before {
            return Err(Error::new(ErrorCode::NotFound, "connection does not exist"));
        }
        drop(connections);
        self.lock_routes_mut()
            .retain(|route| route.connection_id.as_ref() != Some(id));
        if let Some(handle) = self.address_roots_watchers.lock().remove(id) {
            handle.cancel.cancel();
        }
        self.forget_request(id);
        self.bringup_locks.lock().remove(id);
        self.bringup_cooldowns.lock().remove(id);
        self.bump_route_epoch();
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(connection.id = %id.0))]
    async fn update_connection_credentials(
        &self,
        id: &ConnectionId,
        credentials: SecretBundle,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        // parking_lot guards aren't Send — release before awaiting.
        let (factory, mut connection, refresh_roots) = {
            let connections = self.lock_connections();
            let connection = connections
                .iter()
                .find(|connection| &connection.id == id)
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection does not exist"))?;
            let factory = self
                .backend_factories
                .read()
                .get(&connection.backend_kind)
                .cloned()
                .ok_or_else(|| {
                    Error::new(ErrorCode::NotConfigured, "backend kind is not registered")
                })?;
            let refresh_roots = matches!(
                connection.auth_state,
                ConnectionAuthState::AwaitingAuth { .. } | ConnectionAuthState::AuthFailed { .. }
            ) || connection.current_addresses.is_empty();
            (factory, connection, refresh_roots)
        };
        factory
            .update_credentials(&connection, credentials, cancel.clone())
            .await?;
        connection.auth_state = ConnectionAuthState::Authenticated {
            last_authenticated_at: SystemTime::now(),
            expires_at: None,
        };
        {
            let mut connections = self.lock_connections();
            if let Some(slot) = connections.iter_mut().find(|c| &c.id == id) {
                *slot = connection.clone();
            }
        }
        if refresh_roots {
            self.refresh_address_roots_once(id, cancel).await?;
        }
        self.lock_connections()
            .iter()
            .find(|c| &c.id == id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection does not exist"))
    }

    fn list_connections(&self) -> Result<Vec<Connection>> {
        Ok(self.lock_connections().clone())
    }

    fn watch_connections(&self) -> Result<ConnectionChangeStream> {
        let snapshot = self.list_connections()?;
        Ok(Box::new(std::iter::once(Ok(ConnectionChange::Snapshot(
            snapshot,
        )))))
    }

    fn add_alias(&self, request: AliasRequest) -> Result<Alias> {
        if request.persist {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "persistent aliases require the user-config layer",
            ));
        }
        if self
            .matching_backend_route(&request.from)?
            .filter(|route| route.prefix == request.from)
            .is_some()
            || self
                .matching_alias(&request.from)?
                .filter(|alias| alias.from == request.from)
                .is_some()
        {
            return Err(Error::new(
                ErrorCode::RouteConflict,
                "alias source collides with an existing route",
            ));
        }
        let state = self.alias_state_for_target(&request.to)?;
        if matches!(state, AliasState::ChainTooLong { .. }) {
            return Err(Error::new(
                ErrorCode::AliasChainTooLong,
                "alias target currently resolves to another alias",
            ));
        }
        let alias = Alias {
            id: AliasId(fresh_id("alias")),
            from: request.from,
            to: request.to,
            visibility: request.visibility,
            source: AliasSource::Runtime { persisted: false },
            state,
            display_name: request.display_name,
            user_metadata: request.user_metadata,
        };
        self.lock_aliases_mut().push(alias.clone());
        self.bump_route_epoch();
        Ok(alias)
    }

    fn remove_alias(&self, id: &AliasId) -> Result<()> {
        let mut aliases = self.lock_aliases_mut();
        let before = aliases.len();
        aliases.retain(|alias| &alias.id != id);
        if aliases.len() == before {
            return Err(Error::new(ErrorCode::NotFound, "alias does not exist"));
        }
        drop(aliases);
        self.bump_route_epoch();
        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<Alias>> {
        let mut aliases = self.lock_aliases().clone();
        for alias in &mut aliases {
            alias.state = self.alias_state_for_target(&alias.to)?;
        }
        Ok(aliases)
    }

    fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<AddressRootSnapshotStream> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.address_root_watch_senders.lock().push(tx);
        let snapshot = self.list_address_roots()?;
        let library = self.self_weak.lock().clone();
        Ok(Box::new(library_helpers::AddressRootWatcher::new(
            library, rx, snapshot, cancel,
        )))
    }

    fn set_address_visibility(
        &self,
        address: Url,
        visibility: AddressVisibility,
        persist: bool,
    ) -> Result<AddressVisibilityOverride> {
        if persist {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "persistent visibility overrides require the user-config layer",
            ));
        }
        let route_exists = self
            .lock_routes()
            .iter()
            .any(|route| route.prefix == address);
        let mut aliases = self.lock_aliases_mut();
        let alias = aliases.iter_mut().find(|alias| alias.from == address);
        if !route_exists && alias.is_none() {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "visibility can only be set on an existing route row",
            ));
        }
        if let Some(alias) = alias {
            alias.visibility = visibility;
        }
        drop(aliases);
        let override_row = AddressVisibilityOverride {
            address: address.clone(),
            visibility,
            persisted: false,
        };
        let mut overrides = self.lock_visibility_overrides_mut();
        if let Some(existing) = overrides.iter_mut().find(|row| row.address == address) {
            *existing = override_row.clone();
        } else {
            overrides.push(override_row.clone());
        }
        drop(overrides);
        self.bump_route_epoch();
        Ok(override_row)
    }

    fn list_address_visibility_overrides(&self) -> Result<Vec<AddressVisibilityOverride>> {
        Ok(self.lock_visibility_overrides().clone())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(connection.id = %id.0))]
    async fn authenticate_connection(
        &self,
        id: &ConnectionId,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let (connection, factory) = {
            let connections = self.lock_connections();
            let connection = connections
                .iter()
                .find(|connection| &connection.id == id)
                .cloned()
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection does not exist"))?;
            let factory = self
                .backend_factories
                .read()
                .get(&connection.backend_kind)
                .cloned()
                .ok_or_else(|| {
                    Error::new(ErrorCode::NotConfigured, "backend kind is not registered")
                })?;
            (connection, factory)
        };
        let stream = factory
            .authenticate(connection, self.interactive_auth_capability, cancel.clone())
            .await?;
        // The OAuth flow surfaces tokens on Succeeded; route them to the
        // backend via `update_credentials` before forwarding the event so
        // the next RPC sees an authenticated channel. Also flip the
        // connection slot to `Authenticated` so the next dispatch's
        // `with_route_retry` skips `bring_up_or_fail` — plugins driving
        // warm-continue emit Succeeded with `credentials: None` after
        // installing tokens internally; without this transition the
        // host re-instantiates a fresh stub on the next op.
        let factory_for_install = factory.clone();
        let library_weak = self.self_weak.lock().clone();
        let id_for_event = id.clone();
        let mapped: AuthEventStream = Box::new(stream.map(move |event| match event {
            Ok(AuthEvent::Succeeded {
                connection,
                credentials: Some(bundle),
            }) => match block_on_factory_update(
                factory_for_install.clone(),
                (*connection).clone(),
                bundle.clone(),
                cancel.clone(),
            ) {
                Ok(()) => {
                    if let Some(library) = library_weak.upgrade() {
                        library.mark_connection_authenticated(&id_for_event);
                        if let Err(error) = block_on_address_roots_refresh(
                            library,
                            id_for_event.clone(),
                            cancel.clone(),
                        ) {
                            return Ok(AuthEvent::Failed { error });
                        }
                    }
                    Ok(AuthEvent::Succeeded {
                        connection,
                        credentials: Some(bundle),
                    })
                }
                Err(error) => Ok(AuthEvent::Failed { error }),
            },
            Ok(AuthEvent::Succeeded {
                connection,
                credentials: None,
            }) => {
                if let Some(library) = library_weak.upgrade() {
                    library.mark_connection_authenticated(&id_for_event);
                    if let Err(error) = block_on_address_roots_refresh(
                        library,
                        id_for_event.clone(),
                        cancel.clone(),
                    ) {
                        return Ok(AuthEvent::Failed { error });
                    }
                }
                Ok(AuthEvent::Succeeded {
                    connection,
                    credentials: None,
                })
            }
            other => other,
        }));
        Ok(mapped)
    }

    async fn stat(
        &self,
        addr: Url,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _span = tracing::info_span!(
            "ovstorage.stat",
            object.address = %RedactedUrl(&addr),
            full_metadata = opts.full_metadata
        );
        if !address::is_directory(&addr) {
            if !opts.full_metadata {
                if let Some(cache) = &self.metadata_cache {
                    let key = MetadataCacheKey {
                        kind: MetadataKind::Stat,
                        principal_id: None,
                        address: addr.as_str().to_string(),
                        options_hash: hash_stat_options(&opts),
                    };
                    if let Some(MetadataCachePayload::Stat(mut info)) = cache.get(&key) {
                        info.address = addr;
                        return Ok(info);
                    }
                }
                match self.stat_from_parent_list(&addr, cancel.clone()).await {
                    MetadataStatLookup::Found(info) => {
                        tracing::debug!(cache.hit = true, cache.kind = "parent_list");
                        return Ok(info);
                    }
                    MetadataStatLookup::NotFound => {
                        tracing::debug!(cache.hit = false, cache.kind = "parent_list");
                        return Err(Error::new(
                            ErrorCode::NotFound,
                            "object not found in cached parent listing",
                        ));
                    }
                    MetadataStatLookup::Unavailable => {}
                }
            }
            match self
                .stat_once(addr.clone(), opts.clone(), cancel.clone())
                .await
            {
                Ok(info) => return Ok(info),
                Err(error) if error.code() == ErrorCode::NotFound => {}
                Err(error) => return Err(error),
            }
            let dir_addr = address::to_directory(&addr)?;
            return self.stat_once(dir_addr, opts, cancel).await;
        }
        self.stat_once(addr, opts, cancel).await
    }

    async fn read_bytes(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(Vec<u8>, ObjectInfo)> {
        let _span = tracing::info_span!(
            "ovstorage.read_bytes",
            object.address = %RedactedUrl(&addr),
            range = opts.range.is_some()
        );
        let max_bytes = opts.max_bytes;
        let (route, target) = self.resolve(&addr)?;
        let cache_key = cache_key(&target, self.policy_partition());
        let cacheable_read = opts.if_match.is_none() && opts.range.is_none();
        if cacheable_read
            && let Some(cache) = &self.cache
            && let Some(cached) = cache.get_entry_async(&cache_key).await?
        {
            tracing::debug!(cache.hit = true, cache.kind = "bytes");
            ensure_read_bytes_within_max_bytes(cached.bytes.len(), max_bytes)?;
            let info = ObjectInfo {
                address: addr,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(cached.entry.size),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            };
            return Ok((cached.bytes, info));
        }
        // No stampede lock — cache insert is idempotent.
        let read_result = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.read(target, opts, cancel).await }
            })
            .await?;
        match read_result {
            ReadResult::Bytes { bytes, mut info } => {
                info.address = addr;
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                if cacheable_read {
                    self.cache_bytes(&cache_key, &bytes)?;
                }
                Ok((bytes, info))
            }
            ReadResult::Stream {
                mut stream,
                mut info,
            } => {
                info.address = addr;
                // O(object) memory is intrinsic to `read_bytes`;
                // streaming callers use `read_stream` instead.
                use futures::StreamExt;
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    if let Some(cap) = max_bytes
                        && (bytes.len() as u64).saturating_add(chunk.len() as u64) > cap
                    {
                        return Err(read_bytes_max_bytes_error(cap));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                if cacheable_read {
                    self.cache_bytes(&cache_key, &bytes)?;
                }
                Ok((bytes, info))
            }
            ReadResult::LocalDelegate(local) => {
                let bytes = tokio::fs::read(&local.path).await.map_err(io_error)?;
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                let mut info = local.info;
                info.address = addr;
                if cacheable_read {
                    self.cache_bytes(&cache_key, &bytes)?;
                }
                Ok((bytes, info))
            }
            ReadResult::Redirect(redirect) => {
                let retry_cfg = route.retry.unwrap_or(self.retry_default);
                let redirected = follow_read_redirect(
                    addr.clone(),
                    &redirect,
                    &retry_cfg,
                    opts.if_match.is_some(),
                    opts.range.as_ref(),
                )
                .await?;
                let bytes = redirected.bytes;
                let info = redirected.info;
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                if cacheable_read {
                    self.cache_bytes(&cache_key, &bytes)?;
                }
                Ok((bytes, info))
            }
        }
    }

    async fn read_stream(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ReadStream, ObjectInfo)> {
        let _span = tracing::info_span!(
            "ovstorage.read_stream",
            object.address = %RedactedUrl(&addr),
            range = opts.range.is_some()
        );
        let max_bytes = opts.max_bytes;
        let (route, target) = self.resolve(&addr)?;
        let cache_key = cache_key(&target, self.policy_partition());
        let cacheable_read = opts.if_match.is_none() && opts.range.is_none();
        // Cache hit becomes a one-shot stream; miss path calls the
        // backend and yields true chunk-by-chunk streaming.
        if cacheable_read
            && let Some(cache) = &self.cache
            && let Some(cached) = cache.get_entry_async(&cache_key).await?
        {
            tracing::debug!(cache.hit = true, cache.kind = "bytes_to_stream");
            let info = ObjectInfo {
                address: addr,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(cached.entry.size),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            };
            ensure_read_bytes_within_max_bytes(cached.bytes.len(), max_bytes)?;
            let stream: ReadStream = Box::pin(futures::stream::once(async move {
                Ok(bytes::Bytes::from(cached.bytes))
            }));
            return Ok((stream, info));
        }
        let read_result = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.read(target, opts, cancel).await }
            })
            .await?;
        match read_result {
            ReadResult::Stream { stream, mut info } => {
                info.address = addr;
                Ok((maybe_cap_read_stream(stream, max_bytes), info))
            }
            ReadResult::Bytes { bytes, mut info } => {
                info.address = addr;
                ensure_read_bytes_within_max_bytes(bytes.len(), max_bytes)?;
                let stream: ReadStream = Box::pin(futures::stream::once(async move {
                    Ok(bytes::Bytes::from(bytes))
                }));
                Ok((stream, info))
            }
            ReadResult::LocalDelegate(local) => {
                let mut info = local.info;
                info.address = addr;
                let file = tokio::fs::File::open(&local.path).await.map_err(io_error)?;
                let reader = tokio_util::io::ReaderStream::new(file);
                use futures::StreamExt;
                let stream: ReadStream = Box::pin(reader.map(|chunk| chunk.map_err(io_error)));
                Ok((maybe_cap_read_stream(stream, max_bytes), info))
            }
            ReadResult::Redirect(redirect) => {
                let streamed = follow_read_redirect_streaming(
                    addr,
                    &redirect,
                    opts.if_match.is_some(),
                    opts.range.as_ref(),
                )
                .await?;
                Ok((
                    maybe_cap_read_stream(streamed.stream, max_bytes),
                    streamed.info,
                ))
            }
        }
    }

    async fn materialize(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let _span = tracing::info_span!(
            "ovstorage.materialize",
            object.address = %RedactedUrl(&addr),
            range = opts.range.is_some()
        );
        let (route, target) = self.resolve(&addr)?;
        let cache_key = cache_key(&target, self.policy_partition());
        let cacheable_read = opts.if_match.is_none() && opts.range.is_none();
        if cacheable_read
            && let Some(cache) = &self.cache
            && let Some(lookup) = cache.lookup(&cache_key)?
        {
            tracing::debug!(cache.hit = true, cache.kind = "local_file");
            let guard = lookup
                .lease
                .map(|lease| std::sync::Arc::new(lease) as std::sync::Arc<dyn Send + Sync>);
            return Ok(LocalDelegate {
                path: lookup.cached.entry.path,
                info: cached_info(addr, lookup.cached.entry.size),
                guard,
            });
        }
        let read_result = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.read(target, opts, cancel).await }
            })
            .await?;
        match read_result {
            ReadResult::LocalDelegate(mut local) => {
                local.info.address = addr;
                Ok(local)
            }
            ReadResult::Bytes { bytes, mut info } => {
                info.address = addr;
                let (path, guard) =
                    self.materialize_for_local_delegate(&cache_key, &bytes, cacheable_read)?;
                Ok(LocalDelegate { path, info, guard })
            }
            ReadResult::Stream { stream, mut info } => {
                info.address = addr;
                let staged_path = materialize_stream_to_temp_file(stream, cancel.clone()).await?;
                let staged_result = self.materialize_staged_file_for_local_delegate(
                    &cache_key,
                    &staged_path,
                    cacheable_read,
                );
                let (path, guard) = match staged_result {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = std::fs::remove_file(&staged_path);
                        return Err(error);
                    }
                };
                if path != staged_path {
                    let _ = std::fs::remove_file(&staged_path);
                }
                Ok(LocalDelegate { path, info, guard })
            }
            ReadResult::Redirect(redirect) => {
                let redirected = follow_read_redirect_streaming(
                    addr.clone(),
                    &redirect,
                    opts.if_match.is_some(),
                    opts.range.as_ref(),
                )
                .await?;
                let info = redirected.info;
                let staged_path =
                    materialize_stream_to_temp_file(redirected.stream, cancel.clone()).await?;
                let staged_result = self.materialize_staged_file_for_local_delegate(
                    &cache_key,
                    &staged_path,
                    cacheable_read,
                );
                let (path, guard) = match staged_result {
                    Ok(value) => value,
                    Err(error) => {
                        let _ = std::fs::remove_file(&staged_path);
                        return Err(error);
                    }
                };
                if path != staged_path {
                    let _ = std::fs::remove_file(&staged_path);
                }
                Ok(LocalDelegate { path, info, guard })
            }
        }
    }

    async fn read_raw(
        &self,
        addr: Url,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let _span = tracing::info_span!(
            "ovstorage.read_raw",
            object.address = %RedactedUrl(&addr),
        );
        let (route, target) = self.resolve(&addr)?;
        let mut result = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.read(target, opts, cancel).await }
            })
            .await?;
        // Normalize embedded address to caller-facing so REST emits
        // the right `Location:` and `info.address`.
        match &mut result {
            ReadResult::Bytes { info, .. } => info.address = addr,
            ReadResult::Stream { info, .. } => info.address = addr,
            ReadResult::LocalDelegate(local) => local.info.address = addr,
            ReadResult::Redirect(_) => {}
        }
        Ok(result)
    }

    async fn write(
        &self,
        dest: Url,
        body: Body,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _span = tracing::info_span!(
            "ovstorage.write",
            object.address = %RedactedUrl(&dest)
        );
        let (route, target) = self.resolve(&dest)?;
        let cache_key = cache_key(&target, self.policy_partition());

        let size_hint = match opts.size_hint {
            Some(hint) => Some(hint),
            None => match &body {
                Body::Bytes(bytes) => Some(bytes.len() as u64),
                Body::LocalFile(path) => {
                    let path = path.clone();
                    tokio::fs::metadata(path).await.ok().map(|m| m.len())
                }
                Body::Stream(_) => None,
            },
        };
        let opts = WriteOptions { size_hint, ..opts };
        let caps = route.capabilities.clone();
        let retry_cfg = route.retry.unwrap_or(self.retry_default);

        // 0-byte known writes skip redirect (pure overhead); unknown
        // size always tries — plugin decides via Unsupported. Plugins
        // that don't advertise `supports_write_redirect` skip the
        // round-trip entirely.
        let try_redirect = caps.supports_write_redirect
            && match opts.size_hint {
                Some(0) => false,
                Some(n) => caps.redirect_size_threshold.is_none_or(|t| n >= t),
                None => true,
            };
        if try_redirect {
            match route
                .backend
                .write_redirect(target.clone(), opts.clone(), cancel.clone())
                .await
            {
                Ok(mut batch) => {
                    // Replay source for multi-round redirects:
                    //   - Bytes: refcount-shared via bytes::Bytes; cache fill
                    //     on success aliases the same buffer (F-3.6).
                    //   - LocalFile: re-opened as a stream per round, never
                    //     materialized to a Vec (F-3.2; multi-GB safe).
                    //   - Stream: consumed once; nested redirects error.
                    let bytes_handle: Option<bytes::Bytes> = match &body {
                        Body::Bytes(b) => Some(bytes::Bytes::copy_from_slice(b)),
                        _ => None,
                    };
                    let local_path: Option<std::path::PathBuf> = match &body {
                        Body::LocalFile(p) => Some(p.clone()),
                        _ => None,
                    };
                    let mut consumed_body = Some(body);
                    loop {
                        let redirect_body = if let Some(b) = &bytes_handle {
                            WriteBody::Buffered(b.to_vec())
                        } else if let Some(p) = &local_path {
                            WriteBody::Stream(body_stream_from_file(p)?)
                        } else {
                            match consumed_body.take() {
                                Some(body) => write_body_from(body).await?,
                                _ => {
                                    return Err(Error::new(
                                        ErrorCode::Unsupported,
                                        "nested write redirects against a streaming body \
                                 (the stream was consumed in the first redirect round)",
                                    ));
                                }
                            }
                        };
                        let results =
                            follow_write_redirects(redirect_body, &batch, &retry_cfg).await?;
                        match route
                            .backend
                            .continue_write(target.clone(), batch, results, cancel.clone())
                            .await?
                        {
                            WriteStep::Done(mut result) => {
                                result.info.address = dest.clone();
                                self.invalidate_metadata_for_parent(&dest);
                                if let Some(bytes) = &bytes_handle {
                                    self.cache_bytes(&cache_key, bytes)?;
                                }
                                return Ok(result);
                            }
                            WriteStep::Redirects(next_batch) => {
                                batch = next_batch;
                                if bytes_handle.is_none() && local_path.is_none() {
                                    consumed_body = None;
                                }
                            }
                        }
                    }
                }
                Err(error) if error.code() == ErrorCode::Unsupported => {
                    // Fall through to body-typed write.
                }
                Err(error) => return Err(error),
            }
        }

        // `Body::LocalFile` is opened as a stream — never materialized
        // to a Vec — so multi-GB writes don't OOM the gateway.
        match body {
            Body::Bytes(bytes) => {
                if caps.supports_write {
                    let result = self
                        .with_route_retry(&route, || {
                            let target = target.clone();
                            let bytes = bytes.clone();
                            let opts = opts.clone();
                            let backend = route.backend.clone();
                            let cancel = cancel.clone();
                            async move { backend.write(target, bytes, opts, cancel).await }
                        })
                        .await?;
                    let mut result = result;
                    result.info.address = dest.clone();
                    self.invalidate_metadata_for_parent(&dest);
                    self.cache_bytes(&cache_key, &bytes)?;
                    Ok(result)
                } else if caps.supports_write_stream {
                    // Buffered body promoted to a one-chunk stream so
                    // write-stream-only backends still service `Body::
                    // Bytes` callers.
                    let stream = {
                        let buf = bytes.clone();
                        BodyStream::from_iter(std::iter::once(Ok(buf)))
                    };
                    let mut result = route
                        .backend
                        .write_stream(target.clone(), stream, opts.clone(), cancel)
                        .await?;
                    result.info.address = dest.clone();
                    self.invalidate_metadata_for_parent(&dest);
                    self.cache_bytes(&cache_key, &bytes)?;
                    Ok(result)
                } else {
                    Err(Error::new(
                        ErrorCode::Unsupported,
                        "route does not support write",
                    ))
                }
            }
            Body::LocalFile(path) => {
                if !caps.supports_write_stream {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "route does not support write_stream",
                    ));
                }
                let stream = body_stream_from_file(&path)?;
                let mut result = route
                    .backend
                    .write_stream(target.clone(), stream, opts.clone(), cancel)
                    .await?;
                result.info.address = dest.clone();
                self.invalidate_metadata_for_parent(&dest);
                Ok(result)
            }
            Body::Stream(stream) => {
                if !caps.supports_write_stream {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "route does not support write_stream",
                    ));
                }
                let mut result = route
                    .backend
                    .write_stream(target.clone(), stream, opts.clone(), cancel)
                    .await?;
                result.info.address = dest.clone();
                self.invalidate_metadata_for_parent(&dest);
                Ok(result)
            }
        }
    }

    async fn write_redirect(
        &self,
        dest: Url,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let _span = tracing::info_span!(
            "ovstorage.write_redirect",
            object.address = %RedactedUrl(&dest)
        );
        let (route, target) = self.resolve(&dest)?;
        if !route.capabilities.supports_write_redirect {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support write_redirect",
            ));
        }
        route.backend.write_redirect(target, opts, cancel).await
    }

    async fn continue_write(
        &self,
        dest: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let _span = tracing::info_span!(
            "ovstorage.continue_write",
            object.address = %RedactedUrl(&dest)
        );
        let (route, target) = self.resolve(&dest)?;
        // `continue_write` is only valid after a `write_redirect` round
        // returned a non-empty batch; the bit gating `write_redirect`
        // therefore also gates the continuation.
        if !route.capabilities.supports_write_redirect {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support write_redirect / continue_write",
            ));
        }
        match route
            .backend
            .continue_write(target, redirects, results, cancel)
            .await?
        {
            WriteStep::Done(mut result) => {
                result.info.address = dest.clone();
                self.invalidate_metadata_for_parent(&dest);
                Ok(WriteStep::Done(result))
            }
            WriteStep::Redirects(batch) => Ok(WriteStep::Redirects(batch)),
        }
    }

    async fn delete(
        &self,
        addr: Url,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _span = tracing::info_span!(
            "ovstorage.delete",
            object.address = %RedactedUrl(&addr)
        );
        let (route, target) = self.resolve(&addr)?;
        if !route.capabilities.supports_delete {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support delete",
            ));
        }
        let cache_key = cache_key(&target, self.policy_partition());
        self.with_route_retry(&route, || {
            let target = target.clone();
            let opts = opts.clone();
            let backend = route.backend.clone();
            let cancel = cancel.clone();
            async move { backend.delete(target, opts, cancel).await }
        })
        .await?;
        self.invalidate_metadata_for_parent(&addr);
        self.remove_cached(&cache_key)
    }

    async fn list(
        &self,
        prefix: Url,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _span = tracing::info_span!(
            "ovstorage.list",
            object.address = %RedactedUrl(&prefix),
            recursive = opts.recursive,
            full_metadata = opts.full_metadata
        );
        self.list_page(prefix, opts, cancel)
            .await
            .map(|page| page.items)
    }

    async fn list_versions(
        &self,
        addr: Url,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let _span = tracing::info_span!(
            "ovstorage.list_versions",
            object.address = %RedactedUrl(&addr)
        );
        let (route, target) = self.resolve(&addr)?;
        if !route.capabilities.supports_version_listing {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support version listing",
            ));
        }
        self.with_route_retry(&route, || {
            let target = target.clone();
            let opts = opts.clone();
            let backend = route.backend.clone();
            let cancel = cancel.clone();
            async move { backend.list_versions(target, opts, cancel).await }
        })
        .await?
        .into_iter()
        .map(|item| project_object_info(&addr, &target.resolved_address, item, "version"))
        .collect()
    }

    async fn get_latest_version(
        &self,
        addr: Url,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _span = tracing::info_span!(
            "ovstorage.get_latest_version",
            object.address = %RedactedUrl(&addr)
        );
        let (route, target) = self.resolve(&addr)?;
        if !route.capabilities.supports_version_listing {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support version listing",
            ));
        }
        let item = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.get_latest_version(target, cancel).await }
            })
            .await?;
        project_object_info(&addr, &target.resolved_address, item, "version")
    }

    async fn watch_directory(
        &self,
        prefix: Url,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let _span = tracing::info_span!(
            "ovstorage.watch_directory",
            object.address = %RedactedUrl(&prefix),
            recursive = opts.recursive
        );
        let prefix = address::to_directory(&prefix)?;
        let (route, target) = self.resolve(&prefix)?;
        if !route.capabilities.supports_watch_directory {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support watch_directory",
            ));
        }
        // Only the open is retried; mid-stream failures surface to the
        // caller, who can re-open if they choose.
        let stream = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.watch_directory(target, opts, cancel).await }
            })
            .await?;
        let metadata_cache = self.metadata_cache.clone();
        let resolved_prefix = target.resolved_address.clone();
        Ok(Box::new(stream.map(move |event| {
            compose_change_event(&prefix, &resolved_prefix, event?, metadata_cache.as_deref())
        })))
    }

    async fn create_directory(
        &self,
        addr: Url,
        opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _span = tracing::info_span!(
            "ovstorage.create_directory",
            object.address = %RedactedUrl(&addr)
        );
        let addr = address::to_directory(&addr)?;
        let (route, target) = self.resolve(&addr)?;
        if !route.capabilities.supports_create_directory {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support create_directory",
            ));
        }
        let info = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.create_directory(target, opts, cancel).await }
            })
            .await?;
        self.invalidate_metadata_for_parent(&addr);
        Ok(public_info(addr, info))
    }

    async fn delete_directory(
        &self,
        addr: Url,
        opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _span = tracing::info_span!(
            "ovstorage.delete_directory",
            object.address = %RedactedUrl(&addr),
        );
        let addr = address::to_directory(&addr)?;
        let (route, target) = self.resolve(&addr)?;
        if !route.capabilities.supports_delete_directory {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support delete_directory",
            ));
        }
        let cache_key = cache_key(&target, self.policy_partition());
        self.with_route_retry(&route, || {
            let target = target.clone();
            let opts = opts.clone();
            let backend = route.backend.clone();
            let cancel = cancel.clone();
            async move { backend.delete_directory(target, opts, cancel).await }
        })
        .await?;
        self.invalidate_metadata_for_parent(&addr);
        self.invalidate_metadata_prefix(&addr);
        self.remove_cached(&cache_key)
    }

    async fn copy(
        &self,
        src: Url,
        dest: Url,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let _span = tracing::info_span!(
            "ovstorage.copy",
            source.address = %RedactedUrl(&src),
            destination.address = %RedactedUrl(&dest)
        );
        let (src_route, src_target) = self.resolve(&src)?;
        let (dest_route, dest_target) = self.resolve(&dest)?;
        let dest_cache_key = cache_key(&dest_target, self.policy_partition());
        if same_backend(&src_route, &dest_route) && src_route.capabilities.supports_server_side_copy
        {
            let copy_result = self
                .with_route_retry(&src_route, || {
                    let src_target = src_target.clone();
                    let dest_target = dest_target.clone();
                    let opts = opts.clone();
                    let backend = src_route.backend.clone();
                    let cancel = cancel.clone();
                    async move { backend.copy(src_target, dest_target, opts, cancel).await }
                })
                .await;
            match copy_result {
                Ok(WriteStep::Done(mut result)) => {
                    result.info.address = dest.clone();
                    self.invalidate_metadata_for_parent(&dest);
                    self.remove_cached(&dest_cache_key)?;
                    return Ok(result);
                }
                Ok(WriteStep::Redirects(_)) => {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "server-side copy returned redirect continuation",
                    ));
                }
                Err(error) if error.code() == ErrorCode::Unsupported => {}
                Err(error) => return Err(error),
            }
        }

        let (bytes, _) = self
            .read_bytes(
                src,
                ReadOptions {
                    if_match: opts.if_source.clone(),
                    ..ReadOptions::default()
                },
                cancel.clone(),
            )
            .await?;
        self.write(
            dest,
            Body::Bytes(bytes),
            WriteOptions {
                if_dest: opts.if_dest,
                ..WriteOptions::default()
            },
            cancel,
        )
        .await
    }

    async fn rename(
        &self,
        src: Url,
        dest: Url,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let _span = tracing::info_span!(
            "ovstorage.rename",
            source.address = %RedactedUrl(&src),
            destination.address = %RedactedUrl(&dest)
        );
        let (src_route, src_target) = self.resolve(&src)?;
        let (dest_route, dest_target) = self.resolve(&dest)?;
        let src_cache_key = cache_key(&src_target, self.policy_partition());
        let dest_cache_key = cache_key(&dest_target, self.policy_partition());
        if same_backend(&src_route, &dest_route)
            && src_route.capabilities.supports_server_side_rename
        {
            let rename_result = self
                .with_route_retry(&src_route, || {
                    let src_target = src_target.clone();
                    let dest_target = dest_target.clone();
                    let opts = opts.clone();
                    let backend = src_route.backend.clone();
                    let cancel = cancel.clone();
                    async move { backend.rename(src_target, dest_target, opts, cancel).await }
                })
                .await;
            match rename_result {
                Ok(()) => {
                    self.invalidate_metadata_for_parent(&src);
                    self.invalidate_metadata_for_parent(&dest);
                    self.remove_cached(&src_cache_key)?;
                    self.remove_cached(&dest_cache_key)?;
                    return Ok(());
                }
                Err(error) if error.code() == ErrorCode::Unsupported => {}
                Err(error) => return Err(error),
            }
        }

        self.copy(
            src.clone(),
            dest,
            CopyOptions {
                if_source: opts.if_source.clone(),
                if_dest: opts.if_dest.clone(),
                message: opts.message.clone(),
            },
            cancel.clone(),
        )
        .await?;
        self.delete(
            src,
            DeleteOptions {
                if_match: opts.if_source,
            },
            cancel,
        )
        .await
    }

    async fn update_metadata(
        &self,
        addr: Url,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let _span = tracing::info_span!(
            "ovstorage.update_metadata",
            object.address = %RedactedUrl(&addr)
        );
        validate_update_metadata_options(&opts)?;
        let (route, target) = self.resolve(&addr)?;
        let capabilities = &route.capabilities;
        if !(capabilities.supports_native_metadata_patch
            || opts.allow_rewrite_emulation && capabilities.supports_metadata_rewrite_emulation)
        {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support metadata updates",
            ));
        }
        let cache_key = cache_key(&target, self.policy_partition());
        let info = self
            .with_route_retry(&route, || {
                let target = target.clone();
                let opts = opts.clone();
                let backend = route.backend.clone();
                let cancel = cancel.clone();
                async move { backend.update_metadata(target, opts, cancel).await }
            })
            .await?;
        self.invalidate_metadata_for_parent(&addr);
        self.remove_cached(&cache_key)?;
        Ok(public_info(addr, info))
    }

    async fn check_access(
        &self,
        addr: Url,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let _span = tracing::info_span!(
            "ovstorage.check_access",
            object.address = %RedactedUrl(&addr)
        );
        let (route, target) = self.resolve(&addr)?;
        if !route.capabilities.supports_access_check {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "route does not support access checks",
            ));
        }
        self.with_route_retry(&route, || {
            let target = target.clone();
            let ops = ops.clone();
            let backend = route.backend.clone();
            let cancel = cancel.clone();
            async move { backend.check_access(target, ops, cancel).await }
        })
        .await
    }
}
