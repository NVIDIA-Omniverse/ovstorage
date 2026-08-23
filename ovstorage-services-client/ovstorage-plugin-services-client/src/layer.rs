// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the Omniverse Storage Service backend.
//!
//! A single [`Layer`] owns its connections and routes addresses to the right
//! backend instance by longest prefix. Connection *lifecycle* (the
//! `ConnectionAuthState` machine, single-flight bring-up, cooldown,
//! background-refresh scheduling, cross-process coalescing, and the
//! data-path recovery loop) is delegated to a generic
//! [`ConnectionSet<OmniverseStorageDriver>`] (RFC-0066); the
//! layer keeps only the `id → instance` routing handle. Address-root discovery
//! stays here (the backend publishes them); credential/auth ownership lives in
//! the `ConnectionSet` via the [`OmniverseStorageDriver`].

use std::sync::{Arc, Weak};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::*;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::DiscoveryState;
use crate::backend::OmniverseStorageBackend;
use crate::config;
use crate::driver::OmniverseStorageDriver;
use crate::factory::{OmniverseStorageFactory, list_top_level_addresses};
use crate::transport::OmniverseStorageTransport;

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds the
/// static kind descriptor computed once; every built layer owns its own
/// `ConnectionSet` + longest-prefix route table.
pub struct OmniverseStorageLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for OmniverseStorageLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: OmniverseStorageFactory.descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for OmniverseStorageLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let (root_change_tx, _) = broadcast::channel(16);
        let layer = Arc::new_cyclic(|weak| OmniverseStorageLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            instances: RwLock::new(Vec::new()),
            route_table: RwLock::new(RouteTable::empty()),
            root_change_tx,
            cancel: CancellationToken::new(),
            weak_self: weak.clone(),
        });
        let mut seeded_id = None;
        if !config.is_empty() {
            let request = ConnectionRequest {
                backend_kind: self.descriptor.kind.clone(),
                config: config.clone(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            };
            let instance = layer
                .instantiate_connection(
                    request,
                    ConnectionSource::Static {
                        layer: ConfigLayer::Programmatic,
                    },
                    cancel,
                )
                .await?;
            seeded_id = Some(instance.connection_id.clone());
            layer.instances.write().push(instance.clone());
            layer.start_root_watcher(&instance);
        }
        layer.rebuild_routes();
        // Route table built → announce the seeded connection's deferred `Added`.
        if let Some(id) = seeded_id {
            layer.connection_set.announce_connection(&id);
        }
        Ok(layer)
    }
}

struct OmniverseStorageLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle (RFC-0066). The layer
    /// keeps `instances` only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<OmniverseStorageDriver>>,
    instances: RwLock<Vec<Arc<OmniverseStorageInstance>>>,
    /// Precomputed longest-prefix route table, rebuilt on every instance/root
    /// mutation so per-request routing is a cheap lookup.
    route_table: RwLock<RouteTable<Arc<OmniverseStorageInstance>>>,
    root_change_tx: broadcast::Sender<RootInfoChange>,
    /// Parent token for every per-instance root watcher; cancelled on `Drop`.
    cancel: CancellationToken,
    weak_self: Weak<OmniverseStorageLayer>,
}

impl Drop for OmniverseStorageLayer {
    fn drop(&mut self) {
        // Each instance watcher holds a child of this token, so this stops them
        // all deterministically rather than relying on stream end.
        self.cancel.cancel();
    }
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct OmniverseStorageInstance {
    connection_id: ConnectionId,
    /// Provenance of the owning connection (for root `RouteSource`).
    source: ConnectionSource,
    backend_id: BackendId,
    backend: Arc<OmniverseStorageBackend>,
    /// Mutable so a background `watch_address_roots` task can apply
    /// backend-emitted Snapshot/Added/Removed deltas.
    roots: RwLock<Vec<RootInfo>>,
    /// Child of the layer token; cancelled when this instance is removed.
    cancel: CancellationToken,
}

/// Per-connection scaffold built from a [`ConnectionRequest`]: the transport +
/// backend + driver + initial `Connection` view, before any validation. Shared
/// by `instantiate_connection` (registers + discovers roots) and `probe`
/// (validates only). Construction performs no network I/O and no
/// `ConnectionSet` mutation.
struct ConnectionScaffold {
    connection_id: ConnectionId,
    backend_id: BackendId,
    connection: Connection,
    driver: Arc<OmniverseStorageDriver>,
    backend: Arc<OmniverseStorageBackend>,
}

impl OmniverseStorageLayer {
    /// Assemble the per-connection transport, backend, driver, and the initial
    /// (parked) `Connection` view from `request`. No I/O; no lifecycle effects.
    fn build_scaffold(
        &self,
        request: &ConnectionRequest,
        source: &ConnectionSource,
    ) -> Result<ConnectionScaffold> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        let location = config::service_location(&request.config)?;
        let locator = location.locator().to_string();
        let client_name = config::oidc_client_name(&request.config);
        let persistence_id = config::persistence_id(&request.config)?;
        let display_name = request
            .display_name
            .clone()
            .unwrap_or_else(|| format!("{}:{locator}", config::KIND));

        // The shared token cell the transport interceptor reads and the driver's
        // grants install into; one http client shared for grants.
        let http = reqwest::Client::new();
        let state = DiscoveryState::new(client_name);
        let discovery_url = location.discovery_url().map(str::to_string);
        let transport = OmniverseStorageTransport::new(location, state.clone());
        let backend = Arc::new(OmniverseStorageBackend::new(
            locator.clone(),
            crate::factory::connection_capabilities(discovery_url.is_some()),
            transport.clone(),
        ));
        let driver = Arc::new(OmniverseStorageDriver::new(
            discovery_url,
            state,
            transport,
            http,
            &persistence_id,
            config::allow_plaintext_credentials(&request.config),
        )?);

        let connection_id = ConnectionId(fresh_id(&self.descriptor.kind));
        let backend_id = BackendId(format!("{}:{locator}", config::KIND));
        let connection = Connection {
            id: connection_id.clone(),
            backend_kind: self.descriptor.kind.clone(),
            display_name,
            source: source.clone(),
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        };
        Ok(ConnectionScaffold {
            connection_id,
            backend_id,
            connection,
            driver,
            backend,
        })
    }

    /// Build a connection: construct the per-connection backend + transport +
    /// [`OmniverseStorageDriver`], hand the driver to the `ConnectionSet` (which
    /// validates + owns the lifecycle), then discover address roots and publish
    /// them via `set_addresses`. Returns the routing instance.
    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<OmniverseStorageInstance>> {
        let ConnectionScaffold {
            connection_id,
            backend_id,
            connection,
            driver,
            backend,
        } = self.build_scaffold(&request, &source)?;
        // `ConnectionSet` validates (via the driver), records auth state, and
        // spawns background refresh. `Added` is DEFERRED: the caller installs the
        // route and calls `announce_connection`. Root discovery below runs
        // pre-announce, so its `set_addresses` is folded into the pending `Added`.
        let auth_state = self
            .connection_set
            .add_connection_deferred(connection, driver, request.credentials, cancel.clone())
            .await?;

        // Discover address roots once authenticated (the backend publishes them);
        // parked connections advertise nothing until sign-in.
        let mut root_infos = Vec::new();
        if matches!(
            auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        ) {
            // Root discovery runs AFTER `add_connection` registered the
            // connection. All post-validation network work is covered by
            // `race_cancel` so a cancellation arriving here promptly returns
            // `Cancelled` instead of blocking in backend I/O and registering a
            // connection after cancellation. On failure / empty / cancellation,
            // roll the registration back — but WITHOUT purging the durable
            // secret (`unregister_connection`): the grant `add_connection` just
            // drove may have rotated the refresh token, and a transient
            // discovery blip must not erase the only live successor.
            let discovery = race_cancel(cancel.as_ref(), async {
                match list_top_level_addresses(backend.transport()).await {
                    Ok(urls) if !urls.is_empty() => Ok(urls),
                    Ok(_) => Err(Error::new(
                        ErrorCode::NotConfigured,
                        "omniverse-storage-service: server published no top-level addresses",
                    )),
                    Err(error) => Err(error),
                }
            })
            .await;
            let urls = match discovery {
                Ok(urls) => urls,
                Err(error) => {
                    let _ = self
                        .connection_set
                        .unregister_connection(&connection_id)
                        .await;
                    return Err(error);
                }
            };
            for address in urls {
                let capabilities = match race_cancel(cancel.as_ref(), async {
                    Ok(backend.capabilities_for_root(&address).await)
                })
                .await
                {
                    Ok(caps) => caps,
                    // Cancelled mid-probe: roll back (keep the secret) so no
                    // half-populated connection is registered after cancellation.
                    Err(error) => {
                        let _ = self
                            .connection_set
                            .unregister_connection(&connection_id)
                            .await;
                        return Err(error);
                    }
                };
                root_infos.push(self.root_info(address, &connection_id, &source, capabilities));
            }
            let caps = root_infos
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty);
            let addresses = root_infos.iter().map(|root| root.root.clone()).collect();
            // Publish the discovered roots onto the ConnectionSet's `Connection` view.
            self.connection_set
                .set_addresses(&connection_id, addresses, caps);
        }

        Ok(Arc::new(OmniverseStorageInstance {
            connection_id,
            source,
            backend_id,
            backend,
            roots: RwLock::new(root_infos),
            cancel: self.cancel.child_token(),
        }))
    }

    fn root_info(
        &self,
        address: Url,
        connection_id: &ConnectionId,
        source: &ConnectionSource,
        capabilities: Capabilities,
    ) -> RootInfo {
        // Provenance follows the connection source: static config stays `Static`
        // even though it now carries a connection id.
        let route_source = match source {
            ConnectionSource::Static { layer } => RouteSource::Static { layer: *layer },
            _ => RouteSource::ConnectionContributed {
                connection_id: connection_id.clone(),
            },
        };
        RootInfo {
            root: address,
            display_name: None,
            layer_kind: self.descriptor.kind.clone(),
            connection_id: Some(connection_id.clone()),
            owning_target: None,
            capabilities,
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: UserMetadata::new(),
        }
    }

    /// Subscribe to the backend's dynamic-root feed (if any) for `instance`.
    /// Static-roots backends return `Unsupported` and the watcher exits quietly.
    fn start_root_watcher(&self, instance: &Arc<OmniverseStorageInstance>) {
        spawn_root_watcher(
            self.weak_self.clone(),
            Arc::downgrade(instance),
            instance.backend.clone(),
            instance.connection_id.clone(),
            instance.cancel.clone(),
        );
    }

    /// Apply a backend-emitted root change to `instance`, refresh the
    /// connection's advertised addresses, and republish the layer's roots.
    fn apply_backend_roots_change(
        &self,
        instance: &Arc<OmniverseStorageInstance>,
        connection_id: &ConnectionId,
        change: AddressRootsChange,
    ) {
        let source = instance.source.clone();
        let (new_addresses, caps) = {
            let mut roots = instance.roots.write();
            match change {
                AddressRootsChange::Snapshot(snapshot) => {
                    *roots = snapshot
                        .into_iter()
                        .map(|root| {
                            self.root_info(root.address, connection_id, &source, root.capabilities)
                        })
                        .collect();
                }
                AddressRootsChange::Added(added) => {
                    for root in added {
                        // Node-aware, not `==`. A snapshot carrying
                        // `omniverse://h/team/` followed by
                        // `Removed(omniverse://h/team)` left the root installed,
                        // and the inverse order installed a duplicate of a root
                        // the router already resolves as one.
                        if roots
                            .iter()
                            .any(|existing| address::same_node(&existing.root, &root.address))
                        {
                            continue;
                        }
                        roots.push(self.root_info(
                            root.address,
                            connection_id,
                            &source,
                            root.capabilities,
                        ));
                    }
                }
                AddressRootsChange::Removed(removed) => {
                    roots.retain(|existing| {
                        !removed
                            .iter()
                            .any(|root| address::same_node(&root.address, &existing.root))
                    });
                }
            }
            let caps = roots
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty);
            (
                roots
                    .iter()
                    .map(|root| root.root.clone())
                    .collect::<Vec<_>>(),
                caps,
            )
        };
        self.connection_set
            .set_addresses(connection_id, new_addresses, caps);
        self.rebuild_and_notify();
    }

    /// Rebuild the precomputed route table from the current instances + roots.
    fn rebuild_routes(&self) {
        let items: Vec<(RootInfo, Arc<OmniverseStorageInstance>)> = self
            .instances
            .read()
            .iter()
            .flat_map(|instance| {
                instance
                    .roots
                    .read()
                    .iter()
                    .cloned()
                    .map(|root| (root, instance.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        *self.route_table.write() = RouteTable::build(items);
    }

    fn rebuild_and_notify(&self) {
        self.rebuild_routes();
        let _ = self
            .root_change_tx
            .send(RootInfoChange::Snapshot(self.current_roots()));
    }

    fn route_instance(&self, url: &Url) -> Result<Arc<OmniverseStorageInstance>> {
        self.route_table
            .read()
            .lookup(url)
            .map(|(_, instance)| instance.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    fn target(&self, url: &Url) -> Result<(Arc<OmniverseStorageInstance>, ResolvedTarget)> {
        let instance = self.route_instance(url)?;
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            // `resolved_address` is serialized into every RPC this backend
            // sends, so it is a wire address and not the caller's spelling.
            // Routing reads no userinfo, so a caller may spell a credential on
            // an address whose published root has none; without the strip this
            // process forwards that credential to the Storage Service.
            resolved_address: address::wire_address(url),
        };
        Ok((instance, target))
    }

    /// Route `url` to its instance and run `op` under the connection's
    /// data-path recovery: a driver-classified credential error invalidates the
    /// cached creds, refreshes, and retries `op` **once** before surfacing.
    /// `op` must be replayable (no consumed streaming body) — used for the
    /// read/metadata ops, not `write_stream`/multi-round writes.
    async fn recover<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<OmniverseStorageInstance>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (instance, target) = self.target(url)?;
        let id = instance.connection_id.clone();
        self.connection_set
            .with_recovery(&id, || op(instance.clone(), target.clone()))
            .await
    }

    /// Resolve a `ConnectionKey` to its id, enforcing the target-plus-id routing
    /// contract: a request addressed to another target must not mutate /
    /// authenticate / patch this layer's connection even if the id collides.
    /// Returns `NotFound` on a target mismatch (mirrors `probe`/`add`/`remove`).
    fn checked_key_id(&self, key: &ConnectionKey) -> Result<ConnectionId> {
        if key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        Ok(key.id.clone())
    }

    /// Instance owning connection `id` (for `remove_connection`).
    fn instance_for_id(&self, id: &ConnectionId) -> Option<Arc<OmniverseStorageInstance>> {
        self.instances
            .read()
            .iter()
            .find(|instance| &instance.connection_id == id)
            .cloned()
    }

    fn current_roots(&self) -> Vec<RootInfo> {
        let mut roots: Vec<RootInfo> = self.route_table.read().roots().cloned().collect();
        roots.sort_by(|left, right| left.root.as_str().cmp(right.root.as_str()));
        roots
    }
}

/// Whether opening the root watcher ended in an expected non-watching state.
///
/// [`ErrorCode::Unsupported`] means a static-roots backend has no delta feed.
/// [`ErrorCode::Cancelled`] is expected only when the instance's child token
/// fired because the layer is being dropped or the connection was removed. A
/// cancellation returned by the service while the token is live is an open
/// failure.
fn watch_open_exit_is_expected(code: ErrorCode, cancel: &CancellationToken) -> bool {
    match code {
        ErrorCode::Unsupported => true,
        ErrorCode::Cancelled => cancel.is_cancelled(),
        _ => false,
    }
}

fn spawn_root_watcher(
    layer: Weak<OmniverseStorageLayer>,
    instance: Weak<OmniverseStorageInstance>,
    backend: Arc<OmniverseStorageBackend>,
    connection_id: ConnectionId,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut stream = match backend.watch_address_roots(Some(cancel.clone())).await {
            Ok(stream) => stream,
            Err(error) => {
                if watch_open_exit_is_expected(error.code(), &cancel) {
                    tracing::debug!(error = %error, "watch_address_roots closed without opening");
                } else {
                    tracing::warn!(error = %error, "watch_address_roots failed to open");
                }
                return;
            }
        };
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                next = stream.next() => match next {
                    Some(Ok(change)) => {
                        let (Some(layer), Some(instance)) = (layer.upgrade(), instance.upgrade())
                        else {
                            break;
                        };
                        layer.apply_backend_roots_change(&instance, &connection_id, change);
                    }
                    Some(Err(_)) | None => break,
                },
            }
        }
    });
}

#[async_trait]
impl Layer for OmniverseStorageLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    fn owned_targets(&self) -> Vec<String> {
        if self.descriptor.supports_runtime_add {
            vec![self.name.clone()]
        } else {
            Vec::new()
        }
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.route_table
            .read()
            .lookup(url)
            .map(|(root, _)| root.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    fn list_kinds(&self, _cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        Ok(vec![self.descriptor()])
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        let stream: RootInfoUpdateStream = Box::pin(
            BroadcastStream::new(self.root_change_tx.subscribe())
                .map(|r| r.map_err(|e| Error::new(ErrorCode::Internal, e.to_string()))),
        );
        let roots = self.current_roots();
        Ok((
            RootInfoSnapshot {
                roots,
                updates: true,
            },
            Some(stream),
        ))
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let options = request.input.options;
        self.recover(&request.input.address, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { instance.backend.stat(target, options, cancel).await }
        })
        .await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let options = request.input.options;
        self.recover(&request.input.address, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { instance.backend.read(target, options, cancel).await }
        })
        .await
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // Writes consume their body / span multiple rounds, so they are not run
        // under the retry-once recovery loop; the credential error surfaces to
        // the caller.
        let (instance, target) = self.target(&request.input.address)?;
        match request.input.body {
            Body::Bytes(bytes) => {
                instance
                    .backend
                    .write(target, bytes, request.input.options, cancel)
                    .await
            }
            Body::LocalFile(path) => {
                let stream = body_stream_from_file(&path)?;
                instance
                    .backend
                    .write_stream(target, stream, request.input.options, cancel)
                    .await
            }
            Body::Stream(stream) => {
                instance
                    .backend
                    .write_stream(target, stream, request.input.options, cancel)
                    .await
            }
        }
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write(request, cancel).await
    }

    async fn write_redirect(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let (instance, target) = self.target(&request.input.address)?;
        instance
            .backend
            .write_redirect(target, request.input.options, cancel)
            .await
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let (instance, target) = self.target(&request.input.address)?;
        // The commit stashes metadata that travelled out through the caller
        // inside the continuation, so a host attribution layer's value is taken
        // from the request instead. Read before the input is moved.
        let attested = ovstorage_plugin::attested_modified_by(&request.extensions);
        instance
            .backend
            .continue_write(
                target,
                request.input.redirects,
                request.input.results,
                attested.as_deref(),
                cancel,
            )
            .await
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let options = request.input.options;
        self.recover(&request.input.address, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { instance.backend.delete(target, options, cancel).await }
        })
        .await
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let options = request.input.options;
        let max_results = options.max_results;
        let page_token = options.page_token.clone();
        let items = self
            .recover(&request.input.prefix, move |instance, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move { instance.backend.list(target, options, cancel).await }
            })
            .await?;
        paginate_list_items(items, max_results, page_token)
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let options = request.input.options;
        let items = self
            .recover(&request.input.address, move |instance, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move {
                    instance
                        .backend
                        .list_versions(target, options, cancel)
                        .await
                }
            })
            .await?;
        Ok(VersionPage {
            items,
            next_page_token: None,
        })
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        self.recover(&request.input.address, move |instance, target| {
            let cancel = cancel.clone();
            async move { instance.backend.get_latest_version(target, cancel).await }
        })
        .await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        // Establish the auth-gated subscription through `recover` so an
        // `UNAUTHENTICATED` during stream ESTABLISHMENT (replayable) triggers the
        // silent refresh-and-retry-once, like the other replayable ops.
        // Only establishment is retried; mid-stream errors still surface via the
        // mapped stream below.
        let options = request.input.options;
        let stream = self
            .recover(&request.input.prefix, move |instance, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move {
                    instance
                        .backend
                        .watch_directory(target, options, cancel)
                        .await
                }
            })
            .await?;
        Ok(Box::new(
            stream.map(|event| event.and_then(backend_change_to_change)),
        ))
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let options = request.input.options;
        self.recover(&request.input.address, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move {
                instance
                    .backend
                    .create_directory(target, options, cancel)
                    .await
            }
        })
        .await
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let options = request.input.options;
        self.recover(&request.input.address, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move {
                instance
                    .backend
                    .delete_directory(target, options, cancel)
                    .await
            }
        })
        .await
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let (source_instance, source) = self.target(&request.input.source)?;
        let (dest_instance, destination) = self.target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service does not support cross-connection copy",
            ));
        }
        let id = source_instance.connection_id.clone();
        let options = request.input.options;
        self.connection_set
            .with_recovery(&id, || {
                let (instance, source, destination, options, cancel) = (
                    source_instance.clone(),
                    source.clone(),
                    destination.clone(),
                    options.clone(),
                    cancel.clone(),
                );
                async move {
                    instance
                        .backend
                        .copy(source, destination, options, cancel)
                        .await
                }
            })
            .await
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let (source_instance, source) = self.target(&request.input.source)?;
        let (dest_instance, destination) = self.target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service does not support cross-connection rename",
            ));
        }
        let id = source_instance.connection_id.clone();
        let options = request.input.options;
        self.connection_set
            .with_recovery(&id, || {
                let (instance, source, destination, options, cancel) = (
                    source_instance.clone(),
                    source.clone(),
                    destination.clone(),
                    options.clone(),
                    cancel.clone(),
                );
                async move {
                    instance
                        .backend
                        .rename(source, destination, options, cancel)
                        .await
                }
            })
            .await
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let options = request.input.options;
        self.recover(&request.input.address, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move {
                instance
                    .backend
                    .update_metadata(target, options, cancel)
                    .await
            }
        })
        .await
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let operations = request.input.operations;
        self.recover(&request.input.address, move |instance, target| {
            let operations = operations.clone();
            let cancel = cancel.clone();
            async move {
                instance
                    .backend
                    .check_access(target, operations, cancel)
                    .await
            }
        })
        .await
    }

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if !self.descriptor.supports_runtime_add {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service does not support runtime connections",
            ));
        }
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        // A probe is transient and MUST be side-effect-free: it validates the
        // prospective credentials but never registers the connection, persists a
        // secret, spawns refresh, or emits connection-change events. `persist` is
        // therefore ignored here — the probe never persists.
        let req = request.input.connection;
        let source = ConnectionSource::Runtime { persisted: false };
        let ConnectionScaffold {
            connection,
            driver,
            backend,
            ..
        } = self.build_scaffold(&req, &source)?;
        // `probe_connection` now returns a `ProbeOutcome` verdict (obtain →
        // verify on driver-private staging state — never the live cell); map it
        // onto the parked scaffold `Connection` the SPI `probe` returns.
        let now = SystemTime::now();
        let mut view = connection;
        let outcome = self
            .connection_set
            .probe_connection(driver, req.credentials, cancel)
            .await?;
        match outcome {
            ProbeOutcome::Authenticated { expires_at } => {
                view.auth_state = ConnectionAuthState::Authenticated {
                    last_authenticated_at: now,
                    expires_at,
                };
            }
            ProbeOutcome::Anonymous => {
                view.auth_state = ConnectionAuthState::Anonymous;
            }
            ProbeOutcome::NeedsInteractive { reason } => {
                view.auth_state = ConnectionAuthState::AwaitingAuth {
                    reason,
                    last_attempt: None,
                };
            }
            // A soft backend/IdP rejection is a delivered "not authenticated"
            // verdict, not a hard error — surface it as `AwaitingAuth` carrying
            // the rejection (matching the pre-reshape probe behavior), never
            // mutating any durable state.
            ProbeOutcome::Rejected { error } => {
                view.auth_state = ConnectionAuthState::AwaitingAuth {
                    reason: AuthReason::NeverAuthenticated,
                    last_attempt: Some(AuthAttempt {
                        at: now,
                        error: Some(error),
                    }),
                };
            }
            // The bundle could only be tested by consuming a one-time refresh
            // token; a probe never does. Tell the caller to register instead.
            ProbeOutcome::Unverifiable => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "probing this credential shape would consume a one-time refresh token; \
                     add the connection instead",
                ));
            }
        }
        view.last_probed = Some(now);
        // Read-only root discovery so the probe result advertises the addresses
        // it *would* route. This mutates nothing on the `ConnectionSet` (the
        // transient connection was never registered). Mirror the add-path
        // verdict so probe and add agree: `add_connection` treats a discovery
        // error / empty root list as a hard `NotConfigured` failure, so a probe
        // that authenticates but discovers no roots must NOT report a healthy
        // `Authenticated` with no addresses — surface `NotConfigured` too.
        //
        // LATENT (probe address-fill on an empty live cell; no product callers
        // today): `probe_connection` is side-effect-free — `obtain` grants on
        // driver-private staging and `verify` probes over an EPHEMERAL transport —
        // so the driver's LIVE `self.state` token cell stays EMPTY. This
        // `list_top_level_addresses(backend.transport())` fill then runs over the
        // scaffold transport, whose interceptor reads that empty cell and sends an
        // empty bearer, so on an auth-gated backend the fill would fail. It is
        // unreached because the SPI `probe` verb has no product callers (all
        // routing goes through the internal add/bring-up delegations); if `probe`
        // is ever wired to a host, this discovery must run over an ephemeral
        // transport seeded with the proven bearer (as `verify` does), not the live
        // cell.
        if matches!(
            view.auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        ) {
            match list_top_level_addresses(backend.transport()).await {
                Ok(urls) if !urls.is_empty() => view.current_addresses = urls,
                Ok(_) => {
                    return Err(Error::new(
                        ErrorCode::NotConfigured,
                        "omniverse-storage-service: server published no top-level addresses",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(view)
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if !self.descriptor.supports_runtime_add {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service does not support runtime connections",
            ));
        }
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let persist = request.input.connection.persist;
        let instance = self
            .instantiate_connection(
                request.input.connection,
                ConnectionSource::Runtime { persisted: persist },
                cancel,
            )
            .await?;
        let id = instance.connection_id.clone();
        self.instances.write().push(instance.clone());
        self.start_root_watcher(&instance);
        self.rebuild_and_notify();
        // Snapshot the (not-yet-announced) view BEFORE announcing so a
        // remove-on-`Added` subscriber cannot null it out between the announce
        // and this read; then announce now that the route is installed.
        let connection = self.connection_set.connection(&id).ok_or_else(|| {
            // Defensive rollback (mirrors `remove_connection`'s teardown): an
            // empty lookup would otherwise strand the just-installed route and
            // its root watcher. Unreachable now that `list_connections` hides
            // deferred connections, but kept as a decaying-invariant guard.
            let removed = {
                let mut instances = self.instances.write();
                instances
                    .iter()
                    .position(|instance| instance.connection_id == id)
                    .map(|index| instances.remove(index))
            };
            if let Some(removed) = removed {
                removed.cancel.cancel();
            }
            self.rebuild_and_notify();
            Error::new(
                ErrorCode::Internal,
                "add_connection did not create a connection",
            )
        })?;
        self.connection_set.announce_connection(&id);
        Ok(connection)
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        // Subscribe BEFORE snapshotting so a `ConnectionChange` emitted between
        // the two calls lands on the stream rather than being lost from both.
        let updates = self.connection_set.subscribe();
        Ok((self.connection_set.list_connections(), Some(updates)))
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if key.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        self.connection_set.remove_connection(&key.input.id).await?;
        // Take the write guard ONCE: an `if let Some(_) =
        // self.instances.write()...` that held the guard across the block (Rust
        // 2024 if-let temporary scoping) would let the inner
        // `self.instances.write()` re-acquire the same non-reentrant lock and
        // deadlock every removal.
        let removed = {
            let mut instances = self.instances.write();
            instances
                .iter()
                .position(|instance| instance.connection_id == key.input.id)
                .map(|index| instances.remove(index))
        };
        if let Some(removed) = removed {
            removed.cancel.cancel();
        }
        self.rebuild_and_notify();
        Ok(())
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let id = self.checked_key_id(&request.input.key)?;
        self.connection_set
            .update_credentials(&id, request.input.credentials, cancel)
            .await?;
        // Credential rotation may reveal new roots; refresh the routing view.
        if let Some(instance) = self.instance_for_id(&id)
            && let Ok(urls) = list_top_level_addresses(instance.backend.transport()).await
            && !urls.is_empty()
        {
            let mut root_infos = Vec::with_capacity(urls.len());
            for address in urls {
                let caps = instance.backend.capabilities_for_root(&address).await;
                root_infos.push(self.root_info(address, &id, &instance.source, caps));
            }
            let caps = root_infos
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty);
            let addresses = root_infos.iter().map(|root| root.root.clone()).collect();
            *instance.roots.write() = root_infos;
            self.connection_set.set_addresses(&id, addresses, caps);
            self.rebuild_and_notify();
        }
        self.connection_set
            .connection(&id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let id = self.checked_key_id(&request.input.key)?;
        self.connection_set
            .authenticate(&id, request.input.capability, cancel)
            .await
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        // Delegate display_name / user_metadata patching to the ConnectionSet,
        // which owns the published connection view.
        let id = self.checked_key_id(&request.input.key)?;
        let patch = request.input.patch;
        self.connection_set.update_attributes(
            &id,
            patch.display_name,
            patch.user_metadata.into_iter().collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn test_layer() -> Arc<OmniverseStorageLayer> {
        let descriptor = OmniverseStorageFactory.descriptor();
        let (root_change_tx, _) = broadcast::channel(16);
        Arc::new_cyclic(|weak| OmniverseStorageLayer {
            name: "svc".to_string(),
            descriptor,
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            instances: RwLock::new(Vec::new()),
            route_table: RwLock::new(RouteTable::empty()),
            root_change_tx,
            cancel: CancellationToken::new(),
            weak_self: weak.clone(),
        })
    }

    /// A backend whose transport points at an unconnectable endpoint. The
    /// routing/introspection paths under test never dispatch an RPC.
    fn detached_backend() -> Arc<OmniverseStorageBackend> {
        use tonic::transport::{Channel, Endpoint};
        let endpoint = Endpoint::try_from("http://[::1]:1").unwrap();
        let channel = Channel::balance_list(std::iter::once(endpoint));
        let transport =
            OmniverseStorageTransport::with_channel(channel, DiscoveryState::new("default"));
        Arc::new(OmniverseStorageBackend::new(
            "http://test".into(),
            Capabilities::empty(),
            transport,
        ))
    }

    #[test]
    fn watch_open_expected_exit_codes_are_classified() {
        let token = CancellationToken::new();
        let unavailable = crate::convert::map_status(tonic::Status::unavailable("unavailable"));
        assert!(watch_open_exit_is_expected(ErrorCode::Unsupported, &token));
        assert!(!watch_open_exit_is_expected(ErrorCode::Cancelled, &token));
        assert!(!watch_open_exit_is_expected(ErrorCode::Internal, &token));
        assert_eq!(unavailable.code(), ErrorCode::Transient);
        assert!(!watch_open_exit_is_expected(unavailable.code(), &token));
        assert!(!watch_open_exit_is_expected(ErrorCode::NotFound, &token));

        token.cancel();
        assert!(watch_open_exit_is_expected(ErrorCode::Cancelled, &token));
    }

    #[tokio::test]
    async fn watch_open_with_pre_cancelled_token_is_expected() {
        let backend = detached_backend();
        let token = CancellationToken::new();
        token.cancel();

        let error = match backend.watch_address_roots(Some(token.clone())).await {
            Ok(_) => panic!("pre-cancelled watch open must fail"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(watch_open_exit_is_expected(error.code(), &token));
    }

    /// Push a routing instance serving `root`, and rebuild the route table.
    /// (Routing state only; connection identity is exercised separately since
    /// it requires the network-backed `ConnectionSet::add_connection`.)
    fn seed(layer: &Arc<OmniverseStorageLayer>, root: &str, backend_id: &str) {
        let root_url = Url::parse(root).unwrap();
        let connection_id = ConnectionId(backend_id.into());
        let info = layer.root_info(
            root_url,
            &connection_id,
            &ConnectionSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            Capabilities::empty(),
        );
        let instance = Arc::new(OmniverseStorageInstance {
            connection_id,
            source: ConnectionSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            backend_id: BackendId(backend_id.into()),
            backend: detached_backend(),
            roots: RwLock::new(vec![info]),
            cancel: layer.cancel.child_token(),
        });
        layer.instances.write().push(instance);
        layer.rebuild_routes();
    }

    #[test]
    fn descriptor_maps_to_backend_layer_kind() {
        let factory = OmniverseStorageLayerFactory::default();
        let descriptor = BackendFactory::descriptor(&factory);
        assert_eq!(descriptor.kind, config::KIND);
        assert!(matches!(descriptor.layer_type, LayerType::Backend));
        // `supports_runtime_add` → `accepts_connections` on the layer kind.
        assert!(descriptor.accepts_connections);
    }

    #[tokio::test]
    async fn empty_layer_routes_nothing() {
        let layer = test_layer();
        let url = Url::parse("omniverse://host/a").unwrap();
        assert_eq!(
            layer
                .root_info_for(&url, &ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap_err()
                .code(),
            ErrorCode::NoRoute
        );
        let (snapshot, updates) = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert!(snapshot.roots.is_empty());
        assert!(updates.is_some(), "layer advertises a root-update stream");
        assert_eq!(
            layer
                .list_kinds(&ovstorage_plugin::Extensions::new())
                .unwrap()
                .len(),
            1
        );
        let stat = layer
            .stat(
                Request::new(StatRequest {
                    address: url,
                    options: StatOptions::default(),
                }),
                None,
            )
            .await;
        assert_eq!(stat.unwrap_err().code(), ErrorCode::NoRoute);
    }

    /// A credential the CALLER spelled does not reach the wire.
    ///
    /// Routing compares scheme, host, port and node path and reads no
    /// userinfo, so `omniverse://alice:password@host/team/file.usd` matches a
    /// connection published as `omniverse://host/team/`. `resolved_address` is
    /// serialized into the gRPC `resource_address` of every RPC this backend
    /// sends, so without the strip this process forwards the caller's
    /// credential to the remote Storage Service.
    ///
    /// The request itself is still honoured — userinfo is not part of what an
    /// address names, so it is dropped rather than refused.
    #[tokio::test]
    async fn a_callers_credential_does_not_reach_the_wire() {
        let layer = test_layer();
        seed(&layer, "omniverse://host/team/", "b");

        let (_, target) = layer
            .target(&Url::parse("omniverse://alice:password@host/team/file.usd").unwrap())
            .expect("routing reads no userinfo, so this matches");
        assert_eq!(
            target.resolved_address.as_str(),
            "omniverse://host/team/file.usd",
            "the caller's credential must not be serialized into the RPC"
        );

        // The honest address is untouched, including its query.
        let (_, honest) = layer
            .target(&Url::parse("omniverse://host/team/file.usd?versionId=7").unwrap())
            .unwrap();
        assert_eq!(
            honest.resolved_address.as_str(),
            "omniverse://host/team/file.usd?versionId=7"
        );
    }

    #[tokio::test]
    async fn longest_prefix_routing_selects_instance() {
        let layer = test_layer();
        seed(&layer, "omniverse://host/team/", "b-shallow");
        seed(&layer, "omniverse://host/team/project/", "b-deep");

        let (_, shallow) = layer
            .target(&Url::parse("omniverse://host/team/file.usd").unwrap())
            .unwrap();
        assert_eq!(shallow.backend_id, BackendId("b-shallow".into()));

        let (_, deep) = layer
            .target(&Url::parse("omniverse://host/team/project/file.usd").unwrap())
            .unwrap();
        assert_eq!(deep.backend_id, BackendId("b-deep".into()));

        let miss = layer
            .route_instance(&Url::parse("s3://other/x").unwrap())
            .err()
            .expect("unmatched address has no route");
        assert_eq!(miss.code(), ErrorCode::NoRoute);

        // Both seeded roots surface through introspection.
        let roots = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        assert_eq!(roots.len(), 2);
    }
}
