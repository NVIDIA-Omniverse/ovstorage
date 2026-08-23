// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the Nucleus backend (RFC-0066).
//!
//! A single [`NucleusLayer`] owns its connections and routes addresses to
//! the right [`NucleusBackend`] instance by longest prefix. Connection
//! *lifecycle* is delegated to a generic [`ConnectionSet<NucleusDriver>`]
//! (RFC-0066); the layer keeps only the routing state.
//! Nucleus roots are config-derived and fixed at connect time
//! (`omniverse://{server}/`), so `list_address_roots` is snapshot-only — no
//! dynamic-root stream.
//!
//! Sessions are live state on the connection's `NucleusShared` cell: the
//! driver's verify-time handshake proves the credential and stages the
//! session, `on_authenticated` installs it, and the `recover` loop
//! (via `NucleusDriver::refresh`) re-establishes it when the server reports
//! `TOKEN_EXPIRED` mid-stream through the shared retry-once recovery path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::*;
use parking_lot::RwLock;

use crate::backend::session::NucleusShared;
use crate::backend::spi::{NucleusBackend, native_capabilities};
use crate::config::{
    NucleusConfig, nucleus_config_schema, nucleus_credential_methods, nucleus_credential_schema,
};
use crate::driver::NucleusDriver;

/// The static backend descriptor; converted to the v2 `LayerKindDescriptor`
/// via `descriptor_to_layer_kind` at the factory/layer surface.
pub(crate) fn kind_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: crate::address::NUCLEUS_KIND.into(),
        display_name: "Nucleus".into(),
        description: Some(
            "Native Omniverse Nucleus backend (SOWS discovery + ConnLib + LFT)".into(),
        ),
        config_schema: nucleus_config_schema(),
        credential_schema: nucleus_credential_schema(),
        credential_methods: nucleus_credential_methods(),
        icon: None,
        supports_runtime_add: true,
        // Nucleus has no metadata facet: `write`, `write_stream` and
        // `write_redirect` reject a non-empty `user_metadata` with
        // `Unsupported` rather than dropping it silently, and `stat` never
        // returns any. A host that stamped a reserved key here would fail every
        // write it touched.
        supports_user_metadata: false,
    }
}

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds
/// the static kind descriptor; every built layer owns its own `ConnectionSet`
/// and longest-prefix route table.
pub struct NucleusLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for NucleusLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: kind_descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for NucleusLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let layer = Arc::new(NucleusLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(NucleusLayerState {
                instances: Vec::new(),
                routes: RouteTable::empty(),
                pending_roots: Vec::new(),
            }),
            next_instance_counter: AtomicU64::new(0),
        });
        // A non-empty layer config seeds one static connection (the
        // config-as-Stack path); runtime connections arrive via
        // `add_connection`.
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
            let id = instance.connection_id.clone();
            layer.install(instance);
            // Route installed → announce.
            layer.connection_set.announce_connection(&id);
        }
        Ok(layer)
    }
}

/// Native ABI-v2 `Layer` for the Nucleus backend.
pub(crate) struct NucleusLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle (RFC-0066). The layer
    /// keeps [`Self::state`] only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<NucleusDriver>>,
    /// Connections and the longest-prefix route table derived from them,
    /// under a single lock so a mutation and its route-table rebuild are
    /// published atomically.
    state: RwLock<NucleusLayerState>,
    /// Disambiguates trace/routing-only `BackendId`s for byte-identical configs;
    /// connection identity is the `ConnectionId`.
    next_instance_counter: AtomicU64,
}

struct NucleusLayerState {
    instances: Vec<Arc<NucleusInstance>>,
    routes: RouteTable<Arc<NucleusInstance>>,
    /// Roots reserved by in-flight `instantiate_connection` calls that have
    /// not reached [`NucleusLayer::install`] yet. A reservation makes the
    /// duplicate-root check atomic across the (awaiting) gap between the
    /// conflict check and route publication: a concurrent same-root add
    /// observes the reservation and fails `RouteConflict` instead of both
    /// registering and FIFO-shadowing each other in the route table.
    pending_roots: Vec<Url>,
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct NucleusInstance {
    connection_id: ConnectionId,
    backend_id: BackendId,
    backend: Arc<NucleusBackend>,
    roots: Vec<RootInfo>,
}

/// Longest-prefix route table over the current instance set.
fn build_routes(instances: &[Arc<NucleusInstance>]) -> RouteTable<Arc<NucleusInstance>> {
    let items: Vec<(RootInfo, Arc<NucleusInstance>)> = instances
        .iter()
        .flat_map(|instance| {
            instance
                .roots
                .iter()
                .cloned()
                .map(|root| (root, instance.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    RouteTable::build(items)
}

impl NucleusLayer {
    /// Build a connection: parse the config, build the per-connection live
    /// session cell + [`NucleusBackend`], hand a [`NucleusDriver`] to the
    /// `ConnectionSet` (which validates + owns the lifecycle), then publish
    /// the config-derived root via `set_addresses`.
    ///
    /// `NucleusShared` is deduplicated per address root: multiple `Connection`
    /// handles share one cell, and a re-add with a different
    /// `prefix`/`endpoint` is `InvalidArgument`. One connection owns
    /// one cell, so a second connection for the SAME server is a
    /// `RouteConflict` — the root is `omniverse://{server}/` regardless of
    /// `prefix` (the prefix scopes paths, it does not distinguish roots), so
    /// two same-server connections would otherwise FIFO-shadow each other in
    /// the route table (all I/O silently routed to whichever registered
    /// first). The root is RESERVED atomically before the `ConnectionSet`
    /// registration and released on any failure, so a concurrent same-root
    /// add cannot slip between the check and `install`.
    ///
    /// Roots are published **unconditionally** (even for a parked
    /// `AwaitingAuth` connection): they derive from config rather than
    /// auth-gated discovery.
    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<NucleusInstance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        // Config SHAPE errors fail the add outright (deterministic); the
        // handshake runs on the driver's verify path
        // below, so an unreachable server or rejected credential PARKS the
        // connection (`AwaitingAuth`) instead of hard-failing the add.
        let config = NucleusConfig::from_request(&request)?;
        let root = config.root.clone();
        self.reserve_root(&root)?;
        let result = self
            .instantiate_reserved(request, source, cancel, config)
            .await;
        if result.is_err() {
            self.release_root_reservation(&root);
        }
        result
    }

    /// The reserved remainder of [`Self::instantiate_connection`]; the caller
    /// holds the root reservation and releases it if this returns `Err`.
    async fn instantiate_reserved(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
        config: NucleusConfig,
    ) -> Result<Arc<NucleusInstance>> {
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        let backend_id = BackendId(format!("nucleus:{}:{counter}", config.root));
        let capabilities = native_capabilities();

        let shared = NucleusShared::new(config.clone(), request.credentials.clone());
        let backend = Arc::new(NucleusBackend::from_shared(Arc::clone(&shared)));
        let driver = Arc::new(NucleusDriver::new(Arc::clone(&shared)));

        let connection_id = ConnectionId(fresh_id("nucleus"));
        let display_name = request
            .display_name
            .clone()
            .unwrap_or_else(|| format!("Nucleus {}", config.server));
        let connection = Connection {
            id: connection_id.clone(),
            backend_kind: self.descriptor.kind.clone(),
            display_name,
            source: source.clone(),
            capabilities: capabilities.clone(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        };
        // `ConnectionSet` validates (via the driver) and records auth state; a
        // soft obtain/verify failure parks the connection (`AwaitingAuth`)
        // instead of erroring. `Added` is DEFERRED until the route is installed
        // and `announce_connection` runs. `set_addresses` below therefore
        // rides pre-announce and is folded into the pending `Added`.
        self.connection_set
            .add_connection_deferred(connection, driver, request.credentials, cancel)
            .await?;

        let root = self.root_info(
            config.root.clone(),
            &connection_id,
            &source,
            capabilities.clone(),
        );
        self.connection_set.set_addresses(
            &connection_id,
            vec![root.root.clone()],
            capabilities.clone(),
        );

        Ok(Arc::new(NucleusInstance {
            connection_id,
            backend_id,
            backend,
            roots: vec![root],
        }))
    }

    /// Atomically reserve `root` against both installed instances and other
    /// in-flight adds. `RouteConflict` on an exact duplicate.
    fn reserve_root(&self, root: &Url) -> Result<()> {
        let mut state = self.state.write();
        let occupied = state
            .instances
            .iter()
            .any(|instance| instance.roots.iter().any(|info| info.root == *root))
            || state.pending_roots.contains(root);
        if occupied {
            return Err(Error::new(
                ErrorCode::RouteConflict,
                format!(
                    "a nucleus connection for '{root}' already exists; remove it before adding \
                     another connection to the same server"
                ),
            ));
        }
        state.pending_roots.push(root.clone());
        Ok(())
    }

    /// Release a reservation whose instantiate failed (or whose install was
    /// rolled back) so the root becomes addable again.
    fn release_root_reservation(&self, root: &Url) {
        let mut state = self.state.write();
        if let Some(position) = state.pending_roots.iter().position(|held| held == root) {
            state.pending_roots.swap_remove(position);
        }
    }

    fn root_info(
        &self,
        address: Url,
        connection_id: &ConnectionId,
        source: &ConnectionSource,
        capabilities: Capabilities,
    ) -> RootInfo {
        // Provenance follows the connection source: static config stays
        // `Static` even though it carries a connection id.
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
            // The omni1 read path rejects every populated byte range
            // (`read_with_range_returns_unsupported`), so advertising
            // `Native` would steer capability-driven random-access clients
            // onto a guaranteed failure; honest until ranged reads exist.
            range_read_strategy: RangeReadStrategy::Unsupported,
            source: route_source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: UserMetadata::new(),
        }
    }

    /// Install `instance` and republish the route table atomically,
    /// converting its root reservation into the published route.
    fn install(&self, instance: Arc<NucleusInstance>) {
        let mut state = self.state.write();
        for info in &instance.roots {
            if let Some(position) = state
                .pending_roots
                .iter()
                .position(|held| *held == info.root)
            {
                state.pending_roots.swap_remove(position);
            }
        }
        state.instances.push(instance);
        state.routes = build_routes(&state.instances);
    }

    /// Roll an [`Self::install`] back (the post-install registration check
    /// failed): drop the instance and republish the route table so no orphan
    /// route outlives its `ConnectionSet` entry.
    fn uninstall(&self, id: &ConnectionId) {
        let mut state = self.state.write();
        state
            .instances
            .retain(|instance| instance.connection_id != *id);
        state.routes = build_routes(&state.instances);
    }

    /// The `add_connection` tail: install the instance's route, then announce
    /// the connection's deferred `Added`. Because the connection is
    /// registered but NOT yet announced until this point, no subscriber can
    /// remove it out from under the install — the set's two-phase commit
    /// (`add_connection_deferred` → install → `announce_connection`) makes the
    /// route-before-`Added` ordering authoritative rather than racy. The view is
    /// snapshotted BEFORE announcing so a remove-on-`Added` subscriber cannot
    /// null it out before we return it; the defensive `uninstall`-on-empty
    /// rollback is retained for the (now unreachable) empty-lookup case.
    fn commit_installed(&self, instance: Arc<NucleusInstance>) -> Result<Connection> {
        let id = instance.connection_id.clone();
        self.install(instance);
        let connection = self.connection_set.connection(&id).ok_or_else(|| {
            self.uninstall(&id);
            Error::new(
                ErrorCode::Internal,
                "add_connection did not create a connection",
            )
        })?;
        self.connection_set.announce_connection(&id);
        Ok(connection)
    }

    fn target(&self, url: &Url) -> Result<(Arc<NucleusInstance>, ResolvedTarget)> {
        let instance = self
            .state
            .read()
            .routes
            .lookup(url)
            .map(|(_, instance)| instance.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))?;
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            resolved_address: url.clone(),
        };
        Ok((instance, target))
    }

    /// Route `url` to its instance and run `op` under the connection's
    /// data-path recovery loop: a `TOKEN_EXPIRED` (`AuthExpired`) classifies
    /// as a recoverable credential, `NucleusDriver::refresh` re-establishes
    /// the session single-flight, and `op` re-runs **once**. `op` must be
    /// replayable (no consumed streaming body) — writes bypass this.
    async fn recover<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<NucleusInstance>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (instance, target) = self.target(url)?;
        let id = instance.connection_id.clone();
        self.connection_set
            .with_recovery(&id, || op(instance.clone(), target.clone()))
            .await
    }

    /// Resolve a `ConnectionKey` to its id, enforcing the target-plus-id
    /// routing contract (a request addressed to another target must not act
    /// on this layer's connection even if the id collides).
    fn checked_key_id(&self, key: &ConnectionKey) -> Result<ConnectionId> {
        if key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        Ok(key.id.clone())
    }

    fn current_roots(&self) -> Vec<RootInfo> {
        let mut roots: Vec<RootInfo> = self.state.read().routes.roots().cloned().collect();
        roots.sort_by(|left, right| left.root.as_str().cmp(right.root.as_str()));
        roots
    }
}

#[async_trait]
impl Layer for NucleusLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    fn owned_targets(&self) -> Vec<String> {
        vec![self.name.clone()]
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        self.state
            .read()
            .routes
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
        // Roots are fixed at connect time (config-derived), so this is
        // snapshot-only.
        Ok((
            RootInfoSnapshot {
                roots: self.current_roots(),
                updates: false,
            },
            None,
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
        // `read` may return `ReadResult::Redirect` (an LFT direct GET), which
        // the host follows.
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
        // Writes consume their body / span multiple rounds, so they are not
        // run under the retry-once recovery loop (the sibling template); a
        // credential error surfaces to the caller.
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
        // The finalization is REPLAYABLE (keyed by content_id; the body was
        // consumed by the redirect rounds, not here), so it runs under the
        // one-shot recovery fence; a `TOKEN_EXPIRED` at finalize time would
        // otherwise strand fully-uploaded multipart content.
        let (instance, target) = self.target(&request.input.address)?;
        let id = instance.connection_id.clone();
        let (redirects, results) = (request.input.redirects, request.input.results);
        self.connection_set
            .with_recovery(&id, || {
                let (instance, target, redirects, results, cancel) = (
                    instance.clone(),
                    target.clone(),
                    redirects.clone(),
                    results.clone(),
                    cancel.clone(),
                );
                async move {
                    instance
                        .backend
                        .continue_write(target, redirects, results, cancel)
                        .await
                }
            })
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
        // Uniform ABI-v2 pagination (the sibling-port shape): omni1 `list2`
        // has no wire cursor, so the backend fetches the COMPLETE one-level
        // listing (`max_results`/`page_token` cleared — the backend would
        // otherwise truncate / refuse them) and the layer pages the
        // materialized result with the shared offset-token convention.
        // `recursive` still passes through: the backend's `Unsupported`
        // refusal is pinned capability honesty.
        let options = request.input.options;
        let max_results = options.max_results;
        let page_token = options.page_token.clone();
        let backend_options = ListOptions {
            max_results: None,
            page_token: None,
            ..options
        };
        let items = self
            .recover(&request.input.prefix, move |instance, target| {
                let options = backend_options.clone();
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
        // Establish the subscription through `recover` so a `TOKEN_EXPIRED`
        // during stream ESTABLISHMENT (replayable) triggers the silent
        // refresh-and-retry-once; mid-stream errors surface unrecovered via
        // the mapped stream (the pump emits `Lapsed` and the host
        // re-subscribes — nucleus watch is non-resumable).
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
                "nucleus does not support cross-connection copy",
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
                "nucleus does not support cross-connection rename",
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
        // Always `Unsupported` on the omni1 wire, but routed through the
        // backend so the refusal (and its message) stay pinned in one place.
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
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        // A probe is transient and side-effect-free: it validates the
        // prospective credentials (obtain classification + the verify-time
        // handshake for credentialed shapes, staged on a THROWAWAY driver so
        // nothing reaches a live cell) but never registers the connection or
        // emits connection-change events. Bail before any validation work if
        // the caller already cancelled.
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            return Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
        }
        let req = request.input.connection;
        if req.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    req.backend_kind, self.descriptor.kind
                ),
            ));
        }
        let config = NucleusConfig::from_request(&req)?;
        let capabilities = native_capabilities();
        let shared = NucleusShared::new(config.clone(), req.credentials.clone());
        let driver = Arc::new(NucleusDriver::new(shared));
        let now = SystemTime::now();
        let mut view = Connection {
            id: ConnectionId(fresh_id("nucleus")),
            backend_kind: self.descriptor.kind.clone(),
            display_name: req
                .display_name
                .clone()
                .unwrap_or_else(|| format!("Nucleus {}", config.server)),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities,
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        };
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
            ProbeOutcome::Rejected { error } => {
                view.auth_state = ConnectionAuthState::AwaitingAuth {
                    reason: AuthReason::NeverAuthenticated,
                    last_attempt: Some(AuthAttempt {
                        at: now,
                        error: Some(error),
                    }),
                };
            }
            // `obtain` never consumes (pure classification) and the verify
            // handshake is a repeatable grant, so nothing a probe drives is
            // one-time-consuming; unreachable, but handled honestly.
            ProbeOutcome::Unverifiable => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "probing this credential shape would consume a one-time credential; \
                     add the connection instead",
                ));
            }
        }
        view.last_probed = Some(now);
        // The advertised root derives from config — no RPC needed.
        view.current_addresses = vec![config.root];
        Ok(view)
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
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
        self.commit_installed(instance)
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        // Subscribe BEFORE snapshotting so a `ConnectionChange` emitted
        // between the two calls lands on the stream rather than being lost
        // from both.
        let updates = self.connection_set.subscribe();
        Ok((self.connection_set.list_connections(), Some(updates)))
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let id = self.checked_key_id(&key.input)?;
        self.connection_set.remove_connection(&id).await?;
        // Single write guard: drop the instance and republish the route
        // table atomically.
        let mut state = self.state.write();
        state
            .instances
            .retain(|instance| instance.connection_id != id);
        state.routes = build_routes(&state.instances);
        Ok(())
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        // Nucleus has ONE credentialed shape (every connection needs a
        // session), so rotation delegates to the `ConnectionSet`: obtain runs
        // a fresh handshake on private staging, then activate atomically
        // installs the effective bundle + session under the identity fence.
        // Roots are config-derived and unchanged, so no routing refresh is
        // needed.
        let id = self.checked_key_id(&request.input.key)?;
        let instance = self
            .state
            .read()
            .instances
            .iter()
            .find(|instance| instance.connection_id == id)
            .cloned();
        // Observed BEFORE the rotation: the failure-path teardown below must
        // not erase a session a concurrent CREDENTIAL WINNER installed after
        // this point (the clear runs outside the set's per-connection lock).
        // `identity_gen`, not a bump-on-every-install counter, is the fence: a
        // same-identity background refresh landing in the window must still let
        // the teardown proceed (the old identity has to go), so it deliberately
        // does not advance this generation.
        let observed_gen = instance.as_ref().map(|instance| {
            instance
                .backend
                .shared()
                .identity_gen
                .load(std::sync::atomic::Ordering::Acquire)
        });
        let updated = self
            .connection_set
            .update_credentials(&id, request.input.credentials, cancel)
            .await;
        if let Err(error) = &updated {
            // A failed rotation must not leave the old
            // identity's live state serving — data dispatch gates on session
            // presence, not `ConnectionAuthState`, so the set's park() alone
            // would report `AwaitingAuth { CredentialsRotated }` while
            // stat/read/write kept flowing as the previous identity. The
            // teardown covers BOTH halves of that identity: the live session
            // (identity-generation-gated, so a concurrently installed newer
            // IDENTITY survives while a same-identity refresh does not block the
            // teardown) and the durable identity-scoped keyring refresh_token,
            // here on the completed-failure outcome so a later interactive
            // attempt cannot warm-continue as the previous identity). A
            // cancelled rotation is the one exception on both: nothing was
            // proven or disproven, so the working session AND its
            // warm-continuation token survive. A SUCCESSFUL rotation needs
            // neither: `install_handshake_output` replaces the token, or
            // deletes it when the fresh session carries none.
            if error.code() != ErrorCode::Cancelled
                && let (Some(instance), Some(observed_gen)) = (instance.as_ref(), observed_gen)
                && crate::backend::session::clear_session_state_if_identity_unchanged(
                    instance.backend.shared(),
                    observed_gen,
                )
            {
                // BOTH teardown halves ride the same generation outcome. Route
                // durable deletion through `ConnectionSet`, which owns the
                // driver's persistence hooks and preserves a shared stable-id
                // entry while another live connection still uses it.
                let _ = self.connection_set.purge_persisted_credentials(&id).await;
            }
        }
        updated?;
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
        let id = self.checked_key_id(&request.input.key)?;
        let patch = request.input.patch;
        // Fail closed on patch fields this layer cannot store/enforce:
        // silently dropping a requested restriction (`access_mode:
        // read-only`, `visible: false`) while returning Ok would let a
        // caller mistake an ignored restriction for an applied one.
        // Rejected BEFORE any part of the patch applies, so a mixed patch
        // cannot be half-honored.
        if patch.access_mode.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the nucleus backend does not support updating 'access_mode'",
            ));
        }
        if patch.visible.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the nucleus backend does not support updating 'visible'",
            ));
        }
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
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use crate::backend::session::{HandshakeOverride, TEST_HANDSHAKE_OVERRIDE};
    use crate::handshake::{HandshakeOutput, NucleusSession};
    use crate::ops::{NucleusOps, RuntimeOps};
    use crate::test_support::{CannedResponse, MockTransport, MockTransportHandle, RawFrame};
    use serde_json::json;

    fn synthetic_session() -> NucleusSession {
        NucleusSession {
            access_token: "test-access".into(),
            refresh_token: None,
            tokens_url: "wss://test.invalid/tokens".into(),
            principal: "test-user".into(),
        }
    }

    /// Install an ambient handshake override whose "session" serves ops from
    /// the returned `MockTransport`; also returns the handshake call counter.
    fn install_mock_handshake() -> (Arc<MockTransport>, Arc<AtomicUsize>) {
        let mock = Arc::new(MockTransport::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let mock_for_cb = Arc::clone(&mock);
        let counter_for_cb = Arc::clone(&counter);
        let callback: HandshakeOverride = Arc::new(move || {
            counter_for_cb.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(MockTransportHandle::new(
                Arc::clone(&mock_for_cb),
            )));
            Ok(HandshakeOutput {
                ops,
                lft: None,
                session: synthetic_session(),
            })
        });
        TEST_HANDSHAKE_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(callback));
        (mock, counter)
    }

    fn install_failing_handshake(code: ErrorCode) {
        let callback: HandshakeOverride =
            Arc::new(move || Err(Error::new(code, "handshake denied by test")));
        TEST_HANDSHAKE_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(callback));
    }

    fn clear_handshake_override() {
        TEST_HANDSHAKE_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
        crate::backend::session::TEST_REFRESH_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }

    /// Install an ambient refresh override serving ops from `mock`; returns
    /// the refresh call counter. Cleared by [`clear_handshake_override`].
    fn install_mock_refresh(mock: &Arc<MockTransport>) -> Arc<AtomicUsize> {
        let counter = Arc::new(AtomicUsize::new(0));
        let mock_for_cb = Arc::clone(mock);
        let counter_for_cb = Arc::clone(&counter);
        let callback: crate::backend::session::RefreshOverride = Arc::new(move || {
            counter_for_cb.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(MockTransportHandle::new(
                Arc::clone(&mock_for_cb),
            )));
            Ok((ops, None, synthetic_session()))
        });
        crate::backend::session::TEST_REFRESH_OVERRIDE
            .with(|slot| *slot.borrow_mut() = Some(callback));
        counter
    }

    fn api_token_request(server: &str) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("server".into(), ConfigValue::String(server.into()));
        let mut credentials = SecretBundle::default();
        credentials.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"tok".to_vec())),
        );
        ConnectionRequest {
            backend_kind: "nucleus".into(),
            config,
            credentials,
            persist: false,
            display_name: None,
        }
    }

    fn anonymous_request(server: &str) -> ConnectionRequest {
        let mut request = api_token_request(server);
        request.credentials = SecretBundle::default();
        request
    }

    async fn empty_layer() -> LayerHandle {
        NucleusLayerFactory::default()
            .create_backend("nucleus", &LayerConfig::new(), None)
            .await
            .unwrap()
    }

    async fn add(layer: &LayerHandle, request: ConnectionRequest) -> Connection {
        layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "nucleus".into(),
                    connection: request,
                }),
                None,
            )
            .await
            .unwrap()
    }

    /// The verify-time handshake authenticates an api-token add; the session
    /// installs onto the live cell (`on_authenticated` promotes the staged
    /// output) and the data path serves through the Layer slots.
    #[tokio::test]
    async fn add_api_token_connection_authenticates_and_serves() {
        let (mock, handshakes) = install_mock_handshake();
        let layer = empty_layer().await;
        let connection = add(&layer, api_token_request("srv")).await;
        clear_handshake_override();
        assert!(
            matches!(
                connection.auth_state,
                ConnectionAuthState::Authenticated { .. }
            ),
            "verify-time handshake authenticates, got {:?}",
            connection.auth_state
        );
        assert_eq!(connection.current_addresses[0].as_str(), "omniverse://srv/");
        assert_eq!(
            handshakes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one verify handshake; on_authenticated promotes the STAGED session"
        );
        layer
            .root_info_for(
                &address::parse("omniverse://srv/Users/alice/foo.usd").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .expect("config-derived root routes");

        // Data path: a stat through the Layer slot reaches the mock ops the
        // handshake installed (file probe OK; folder probe absorbed).
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "type": "asset",
                "uri": "/Users/alice/foo.usd",
                "etag": "etag-1",
                "size": 7,
                "transaction_id": "tx-1",
            }))],
        });
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "INVALID_URI"}))],
        });
        let info = layer
            .stat(
                Request::new(StatRequest {
                    address: address::parse("omniverse://srv/Users/alice/foo.usd").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.etag.as_deref(), Some("etag-1"));
    }

    /// A denied verify handshake PARKS the connection (`AwaitingAuth`)
    /// instead of failing the add: the connection registers and its
    /// config-derived root still routes.
    #[tokio::test]
    async fn denied_verify_handshake_parks_connection_instead_of_failing_add() {
        install_failing_handshake(ErrorCode::PermissionDenied);
        let layer = empty_layer().await;
        let connection = add(&layer, api_token_request("srv")).await;
        clear_handshake_override();
        assert!(
            matches!(
                connection.auth_state,
                ConnectionAuthState::AwaitingAuth { .. }
            ),
            "a denied handshake parks, got {:?}",
            connection.auth_state
        );
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.connections.len(), 1);
        layer
            .root_info_for(
                &address::parse("omniverse://srv/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .expect("parked connection still publishes its config-derived root");
    }

    /// Credential-less adds park awaiting sign-in (nucleus has no anonymous
    /// data path) — and object I/O against the parked connection surfaces
    /// `AuthRequired`.
    #[tokio::test]
    async fn missing_credentials_park_and_object_io_requires_auth() {
        let layer = empty_layer().await;
        let connection = add(&layer, anonymous_request("srv")).await;
        assert!(matches!(
            connection.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ));
        let err = layer
            .stat(
                Request::new(StatRequest {
                    address: address::parse("omniverse://srv/Users/alice/foo.usd").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AuthRequired);
    }

    /// Config-SHAPE errors are the arm that still fails outright: nothing
    /// registers and nothing routes.
    #[tokio::test]
    async fn invalid_config_fails_add_outright_without_registration() {
        let layer = empty_layer().await;
        let err = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "nucleus".into(),
                    connection: ConnectionRequest {
                        backend_kind: "nucleus".into(),
                        config: HashMap::new(), // `server` is required
                        credentials: SecretBundle::default(),
                        persist: false,
                        display_name: None,
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert!(snapshot.connections.is_empty());
        assert!(
            layer
                .root_info_for(
                    &address::parse("omniverse://srv/x").unwrap(),
                    &ovstorage_plugin::Extensions::new(),
                    None,
                )
                .await
                .is_err()
        );
    }

    /// Probe drives the verify handshake without registering anything, and a
    /// pre-cancelled probe returns `Cancelled` before any validation.
    #[tokio::test]
    async fn probe_validates_without_registering() {
        let (_mock, handshakes) = install_mock_handshake();
        let layer = empty_layer().await;
        let probed = layer
            .probe(
                Request::new(LayerConnectionRequest {
                    target: "nucleus".into(),
                    connection: api_token_request("srv"),
                }),
                None,
            )
            .await
            .unwrap();
        clear_handshake_override();
        assert!(matches!(
            probed.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
        assert!(probed.last_probed.is_some());
        assert_eq!(probed.current_addresses[0].as_str(), "omniverse://srv/");
        assert_eq!(handshakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert!(
            snapshot.connections.is_empty(),
            "probe must not register a connection"
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let err = layer
            .probe(
                Request::new(LayerConnectionRequest {
                    target: "nucleus".into(),
                    connection: api_token_request("srv"),
                }),
                Some(cancelled),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    /// A credential-less probe reports `AwaitingAuth` (needs interactive) —
    /// no handshake is driven, nothing consumed.
    #[tokio::test]
    async fn probe_without_credentials_reports_needs_interactive() {
        let layer = empty_layer().await;
        let probed = layer
            .probe(
                Request::new(LayerConnectionRequest {
                    target: "nucleus".into(),
                    connection: anonymous_request("srv"),
                }),
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            probed.auth_state,
            ConnectionAuthState::AwaitingAuth { .. }
        ));
    }

    /// Credential rotation re-runs obtain → verify (a fresh handshake) →
    /// on_authenticated (installs the fresh session): nucleus supports
    /// rotation through the generic `ConnectionSet` path.
    #[tokio::test]
    async fn credential_rotation_reruns_handshake() {
        let (_mock, handshakes) = install_mock_handshake();
        let layer = empty_layer().await;
        let connection = add(&layer, api_token_request("srv")).await;
        assert_eq!(handshakes.load(std::sync::atomic::Ordering::SeqCst), 1);

        let mut rotated = SecretBundle::default();
        rotated.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"tok-2".to_vec())),
        );
        let updated = layer
            .update_connection_credentials(
                Request::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: "nucleus".into(),
                        id: connection.id.clone(),
                    },
                    credentials: rotated,
                }),
                None,
            )
            .await
            .unwrap();
        clear_handshake_override();
        assert!(matches!(
            updated.auth_state,
            ConnectionAuthState::Authenticated { .. }
        ));
        assert_eq!(
            handshakes.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "rotation drives one fresh verify handshake"
        );
    }

    /// A FAILED rotation must not leave the OLD identity's live session
    /// serving: data dispatch gates on session presence, not
    /// `ConnectionAuthState`, so the layer clears the session cell when the
    /// set's rotation errs. (Parallel to
    /// `interactive_failed_re_auth_clears_installed_session`.)
    #[tokio::test]
    async fn failed_rotation_clears_live_session() {
        // The per-cell handshake override is captured at connection creation,
        // so a single callback with a flip-switch drives both phases: the add
        // succeeds, the rotation's verify handshake is DENIED.
        let deny = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = Arc::new(MockTransport::new());
        let (deny_for_cb, mock_for_cb) = (Arc::clone(&deny), Arc::clone(&mock));
        let callback: HandshakeOverride = Arc::new(move || {
            if deny_for_cb.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::PermissionDenied,
                    "handshake denied by test",
                ));
            }
            let ops: Arc<dyn NucleusOps> = Arc::new(RuntimeOps::new(MockTransportHandle::new(
                Arc::clone(&mock_for_cb),
            )));
            Ok(HandshakeOutput {
                ops,
                lft: None,
                session: synthetic_session(),
            })
        });
        TEST_HANDSHAKE_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(callback));
        let layer = empty_layer().await;
        let connection = add(&layer, api_token_request("srv")).await;
        deny.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut rotated = SecretBundle::default();
        rotated.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"tok-revoked".to_vec())),
        );
        layer
            .update_connection_credentials(
                Request::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: "nucleus".into(),
                        id: connection.id.clone(),
                    },
                    credentials: rotated,
                }),
                None,
            )
            .await
            .expect_err("a denied rotation surfaces");
        clear_handshake_override();
        // The previous identity's session is gone: the data path refuses
        // with AuthRequired instead of serving as the old identity.
        let err = layer
            .stat(
                Request::new(StatRequest {
                    address: address::parse("omniverse://srv/Users/alice/foo.usd").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::AuthRequired,
            "old session must not keep serving after a failed rotation"
        );
    }

    /// A CANCELLED rotation is the exception on BOTH teardown halves:
    /// nothing was proven or disproven, so the live session keeps serving
    /// (and, untestably here — `oauth_secret_store` is a host-callback no-op in
    /// plugin tests — the durable warm-continuation token also survives).
    #[tokio::test]
    async fn cancelled_rotation_preserves_live_session() {
        let (mock, _handshakes) = install_mock_handshake();
        let layer = empty_layer().await;
        let connection = add(&layer, api_token_request("srv")).await;

        let cancelled = ovstorage_plugin::CancellationToken::new();
        cancelled.cancel();
        let mut rotated = SecretBundle::default();
        rotated.fields.insert(
            "api_token".into(),
            SecretValue::Bytes(SecretBytes(b"tok-2".to_vec())),
        );
        let err = layer
            .update_connection_credentials(
                Request::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: "nucleus".into(),
                        id: connection.id.clone(),
                    },
                    credentials: rotated,
                }),
                Some(cancelled),
            )
            .await
            .unwrap_err();
        clear_handshake_override();
        assert_eq!(err.code(), ErrorCode::Cancelled);

        // The working session still serves the data path.
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "type": "asset",
                "uri": "/Users/alice/foo.usd",
                "etag": "etag-1",
                "size": 7,
                "transaction_id": "tx-1",
            }))],
        });
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "stat2".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "INVALID_URI"}))],
        });
        layer
            .stat(
                Request::new(StatRequest {
                    address: address::parse("omniverse://srv/Users/alice/foo.usd").unwrap(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .expect("cancelled rotation must leave the working session serving");
    }

    /// Attribute patches fail CLOSED on restriction fields the layer cannot
    /// store/enforce (`access_mode`, `visible`) — a mixed patch is rejected
    /// whole — while a supported display-name patch still lands.
    #[tokio::test]
    async fn attribute_patch_restriction_fields_fail_closed() {
        let layer = empty_layer().await;
        let connection = add(&layer, anonymous_request("srv")).await;
        let key = || ConnectionKey {
            target: "nucleus".into(),
            id: connection.id.clone(),
        };

        for patch in [
            AttributePatch {
                display_name: Some("renamed".into()),
                access_mode: Some("read-only".into()),
                ..AttributePatch::default()
            },
            AttributePatch {
                display_name: Some("renamed".into()),
                visible: Some(false),
                ..AttributePatch::default()
            },
        ] {
            let err = layer
                .update_connection_attributes(
                    Request::new(UpdateConnectionAttributesRequest { key: key(), patch }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::Unsupported);
            let (snapshot, _) = layer
                .list_connections(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap();
            assert_ne!(
                snapshot.connections[0].display_name, "renamed",
                "a rejected mixed patch must not be partially applied"
            );
        }

        let updated = layer
            .update_connection_attributes(
                Request::new(UpdateConnectionAttributesRequest {
                    key: key(),
                    patch: AttributePatch {
                        display_name: Some("renamed".into()),
                        ..AttributePatch::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(updated.display_name, "renamed");
    }

    /// A `prefix` spelling that canonicalization moves is refused at
    /// connection creation, because accepting it produces a live connection
    /// that answers nothing.
    ///
    /// The prefix is stored as a bare path and compared against the decoded
    /// path of an address `address::parse` has canonicalized, so
    /// `prefix = "/team//docs"` can never match: every request beneath it
    /// resolves to `/team/docs/…`. On 0.2.0 the collapse did not happen and the
    /// spelling worked, which is what makes silent acceptance the wrong
    /// migration behaviour — the operator sees `NoRoute` for the whole
    /// connection with nothing to read.
    ///
    /// The good input is asserted beside each refusal, and it is the half that
    /// matters here: the comparison is against the DECODED path, so a space or
    /// a literal `%` in a Nucleus folder name still loads. A serialization
    /// comparison would have refused both.
    #[tokio::test]
    async fn a_prefix_no_request_can_reach_is_refused_at_creation() {
        for (prefix, resolved) in [
            ("/team//docs", "/team/docs"),
            ("/team/../docs", "/docs"),
            ("/team/./docs", "/team/docs"),
        ] {
            let layer = empty_layer().await;
            let mut request = anonymous_request("srv");
            request
                .config
                .insert("prefix".into(), ConfigValue::String(prefix.into()));
            let err = layer
                .add_connection(
                    Request::new(LayerConnectionRequest {
                        target: "nucleus".into(),
                        connection: request,
                    }),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{prefix}");
            assert!(
                err.message().contains(resolved),
                "{prefix}: the refusal must name the scope it resolves to, got {}",
                err.message()
            );
        }

        for prefix in [
            "/Projects",
            "/Projects/",
            "Projects",
            "/my docs",
            "/100%",
            // The `%HH` rows are the point of encoding the prefix before it
            // becomes a URL: these name folders whose literal bytes include a
            // `%`, and a raw splice would read them as escapes, refuse them,
            // and recommend `/aAb` and `/100%` — different folders that would
            // then be accepted, silently rescoping the connection.
            "/a%41b",
            "/100%25",
            "/team%2Fsub",
            "/a-b_c.d",
            "/",
        ] {
            let layer = empty_layer().await;
            let mut request = anonymous_request("srv");
            request
                .config
                .insert("prefix".into(), ConfigValue::String(prefix.into()));
            add(&layer, request).await;
            let (snapshot, _) = layer
                .list_connections(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap();
            assert_eq!(snapshot.connections.len(), 1, "{prefix} must load");
        }
    }

    /// A second connection for the SAME server is a `RouteConflict` (the
    /// root ignores `prefix`, so it would otherwise be FIFO-shadowed):
    /// nothing new registers, nothing new routes, and the first connection
    /// keeps serving.
    #[tokio::test]
    async fn same_server_second_add_is_route_conflict() {
        let layer = empty_layer().await;
        add(&layer, anonymous_request("srv")).await;

        // Same server, different prefix: still the same root.
        let mut second = anonymous_request("srv");
        second
            .config
            .insert("prefix".into(), ConfigValue::String("/Projects".into()));
        let err = layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "nucleus".into(),
                    connection: second,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::RouteConflict);
        let (snapshot, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(
            snapshot.connections.len(),
            1,
            "the conflicting add must not register"
        );
        layer
            .root_info_for(
                &address::parse("omniverse://srv/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .expect("the first connection keeps serving its root");

        // A DIFFERENT server routes independently alongside the first.
        add(&layer, anonymous_request("other")).await;
        layer
            .root_info_for(
                &address::parse("omniverse://other/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .expect("second server routes");
        layer
            .root_info_for(
                &address::parse("omniverse://srv/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .expect("first server still routes");
    }

    /// A removed root becomes addable again (the reservation dies with the
    /// instance, not permanently).
    #[tokio::test]
    async fn removed_root_is_addable_again() {
        let layer = empty_layer().await;
        let first = add(&layer, anonymous_request("srv")).await;
        layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "nucleus".into(),
                    id: first.id.clone(),
                }),
                None,
            )
            .await
            .unwrap();
        add(&layer, anonymous_request("srv")).await;
        layer
            .root_info_for(
                &address::parse("omniverse://srv/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .expect("re-added root routes");
    }

    fn enqueue_three_entry_listing(mock: &MockTransport) {
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "list2".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "DONE",
                "entries": [
                    {"path": "/Users/alice/a.usd", "path_type": "asset", "size": 1, "etag": "e1"},
                    {"path": "/Users/alice/b.usd", "path_type": "asset", "size": 2, "etag": "e2"},
                    {"path": "/Users/alice/c.usd", "path_type": "asset", "size": 3, "etag": "e3"},
                ],
            }))],
        });
    }

    /// Uniform ABI-v2 pagination: the layer fetches the complete one-level
    /// listing and pages it with the shared offset-token convention — a
    /// paged caller sees every entry across pages instead of a truncated
    /// first page with no continuation token.
    #[tokio::test]
    async fn list_paginates_the_materialized_listing() {
        let (mock, _handshakes) = install_mock_handshake();
        let layer = empty_layer().await;
        add(&layer, api_token_request("srv")).await;
        clear_handshake_override();

        let prefix = address::parse("omniverse://srv/Users/alice/").unwrap();
        enqueue_three_entry_listing(&mock);
        let first = layer
            .list(
                Request::new(ListRequest {
                    prefix: prefix.clone(),
                    options: ListOptions {
                        max_results: Some(2),
                        ..ListOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(first.items.len(), 2);
        let token = first
            .next_page_token
            .clone()
            .expect("a truncated page carries a continuation token");

        // Each page re-fetches the full listing (omni1 has no wire cursor).
        enqueue_three_entry_listing(&mock);
        let second = layer
            .list(
                Request::new(ListRequest {
                    prefix: prefix.clone(),
                    options: ListOptions {
                        max_results: Some(2),
                        page_token: Some(token),
                        ..ListOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(second.next_page_token.is_none());
        let union: Vec<_> = first
            .items
            .iter()
            .chain(second.items.iter())
            .map(|item| item.address.as_str().to_string())
            .collect();
        assert_eq!(
            union,
            vec![
                "omniverse://srv/Users/alice/a.usd",
                "omniverse://srv/Users/alice/b.usd",
                "omniverse://srv/Users/alice/c.usd",
            ],
            "the paged union equals the full listing"
        );

        // max_results = 0 is the shared convention's InvalidArgument.
        enqueue_three_entry_listing(&mock);
        let err = layer
            .list(
                Request::new(ListRequest {
                    prefix,
                    options: ListOptions {
                        max_results: Some(0),
                        ..ListOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// `continue_write`'s finalization is replayable (keyed by content_id):
    /// a `TOKEN_EXPIRED` at finalize time refreshes once and retries instead
    /// of stranding fully-uploaded multipart content.
    #[tokio::test]
    async fn continue_write_finalize_recovers_after_token_expired() {
        use crate::backend::spi::{NucleusContinuation, encode_nucleus_continuation};
        use std::time::Duration;

        let (mock, _handshakes) = install_mock_handshake();
        let refreshes = install_mock_refresh(&mock);
        let layer = empty_layer().await;
        add(&layer, api_token_request("srv")).await;
        clear_handshake_override();

        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({"status": "TOKEN_EXPIRED"}))],
        });
        mock.enqueue(CannedResponse {
            interface: "Connection".into(),
            method: "create_asset".into(),
            frames: vec![RawFrame::from_json(&json!({
                "status": "OK",
                "etag": "lft-etag",
                "transaction_id": 7,
            }))],
        });

        let cont = NucleusContinuation {
            path: "/Users/alice/big.bin".into(),
            branch: None,
            content_id: 4242,
            if_match_etag: None,
            no_overwrite: false,
            message: None,
        };
        let expires = SystemTime::now() + Duration::from_secs(60);
        let redirects = WriteRedirectBatch {
            continuation: encode_nucleus_continuation(&cont),
            redirects: vec![WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    url: "http://lft.invalid/content/".into(),
                    headers: Vec::new(),
                },
                body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
                result_capture: ResultCapture::default(),
                expires_at: expires,
                scope: RedirectScope {
                    physical_url_prefix: "http://lft.invalid/content/".into(),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at: expires,
                    credential: RedirectCredential::None,
                },
                audit_id: "test-audit".into(),
                policy_epoch: 0,
            }],
        };
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            }],
        };

        let step = layer
            .continue_write(
                Request::new(ContinueWriteRequest {
                    address: address::parse("omniverse://srv/Users/alice/big.bin").unwrap(),
                    redirects,
                    results,
                }),
                None,
            )
            .await
            .unwrap();
        clear_handshake_override();
        match step {
            WriteStep::Done(result) => {
                assert_eq!(result.info.etag.as_deref(), Some("lft-etag"));
            }
            other => panic!("expected Done after the one-shot retry, got {other:?}"),
        }
        assert_eq!(
            refreshes.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly one refresh between the TOKEN_EXPIRED and the retry"
        );
    }

    /// The advertised range strategy matches the read path: nucleus rejects
    /// every populated byte range, so the root must not claim `Native`.
    #[tokio::test]
    async fn range_strategy_unsupported_matches_ranged_read_refusal() {
        let layer = empty_layer().await;
        add(&layer, anonymous_request("srv")).await;
        let root = layer
            .root_info_for(
                &address::parse("omniverse://srv/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(root.range_read_strategy, RangeReadStrategy::Unsupported);

        let err = layer
            .read(
                Request::new(ReadRequest {
                    address: address::parse("omniverse://srv/Users/alice/foo.usd").unwrap(),
                    options: ReadOptions {
                        range: Some(ByteRange {
                            start: 0,
                            end_inclusive: Some(9),
                        }),
                        ..ReadOptions::default()
                    },
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::Unsupported,
            "the refusal the strategy advertises"
        );
    }

    /// The post-install registration check rolls the route back when a
    /// concurrent removal won the add/remove window: no orphan route
    /// may outlive its `ConnectionSet` entry.
    #[tokio::test]
    async fn lost_add_remove_race_rolls_the_route_back() {
        let factory = NucleusLayerFactory::default();
        let layer = Arc::new(NucleusLayer {
            name: "nucleus".into(),
            descriptor: factory.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(NucleusLayerState {
                instances: Vec::new(),
                routes: RouteTable::empty(),
                pending_roots: Vec::new(),
            }),
            next_instance_counter: AtomicU64::new(0),
        });
        let instance = layer
            .instantiate_connection(
                anonymous_request("srv"),
                ConnectionSource::Runtime { persisted: false },
                None,
            )
            .await
            .unwrap();
        let id = instance.connection_id.clone();
        // The racer: the set entry vanishes between registration and install.
        layer.connection_set.remove_connection(&id).await.unwrap();
        // The production add tail must detect the loss and roll back.
        let outcome = layer.commit_installed(instance);
        assert!(outcome.is_err());
        assert!(
            layer
                .root_info_for(
                    &address::parse("omniverse://srv/x").unwrap(),
                    &ovstorage_plugin::Extensions::new(),
                    None,
                )
                .await
                .is_err(),
            "no orphan route survives the lost race"
        );
    }

    /// Teardown: removal drops the route.
    #[tokio::test]
    async fn remove_connection_tears_down_route() {
        let layer = empty_layer().await;
        let connection = add(&layer, anonymous_request("srv")).await;
        layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "nucleus".into(),
                    id: connection.id.clone(),
                }),
                None,
            )
            .await
            .unwrap();
        let err = layer
            .root_info_for(
                &address::parse("omniverse://srv/x").unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NoRoute);
    }
}

#[cfg(test)]
mod user_metadata_declaration_tests {
    use super::*;

    /// This kind's `supports_user_metadata` declaration is what a host reads to
    /// decide whether to compose its attribution layer over this backend's
    /// branch. Asserted here, in the crate that owns the answer, because a host
    /// crate cannot reach it: a plugin crate may not depend on a host-side
    /// crate, and two plugin rlibs in one test binary are a duplicate-symbol
    /// link error under `rust-lld`.
    ///
    /// Flipping it is a behaviour change for every host that loads this plugin —
    /// has no metadata facet and rejects a non-empty `user_metadata` with `Unsupported`.
    #[test]
    fn nucleus_declares_its_user_metadata_support() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "nucleus");
        assert!(
            !descriptor.supports_user_metadata,
            "nucleus's user-metadata declaration changed; a host composes its \
             attribution layer from it"
        );
    }
}
