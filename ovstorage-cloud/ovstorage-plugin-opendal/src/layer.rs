// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the OpenDAL backend (RFC-0066).
//!
//! A single [`OpenDalLayer`] owns its connections and routes addresses to
//! the right [`OpenDalBackend`] instance by longest prefix. Connection *lifecycle*
//! is delegated to a generic [`ConnectionSet<OpenDalDriver>`] (RFC-0066);
//! the layer keeps only the routing state. OpenDAL
//! roots are config-derived and fixed at connect time (the caller-chosen
//! `prefix`), so `list_address_roots` is
//! snapshot-only — no dynamic-root stream.
//!
//! Credentials are **frozen at add time** (static config strings baked into
//! an immutable `Operator`; no live cell), so every
//! `update_connection_credentials` is rejected with remove-and-re-add
//! guidance because the `Operator` owns immutable credential configuration.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::*;
use parking_lot::RwLock;

use crate::driver::OpenDalDriver;
use crate::{
    OpenDalBackend, build_operator, driver_capabilities, kind_descriptor, parse_connection_config,
};

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds
/// the static kind descriptor; every built layer owns its own `ConnectionSet`
/// and longest-prefix route table.
pub struct OpenDalLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for OpenDalLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: kind_descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for OpenDalLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let layer = Arc::new(OpenDalLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(OpenDalLayerState {
                instances: Vec::new(),
                routes: RouteTable::empty(),
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

/// Native ABI-v2 `Layer` for the OpenDAL backend.
pub(crate) struct OpenDalLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle (RFC-0066). The layer
    /// keeps [`Self::state`] only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<OpenDalDriver>>,
    /// Connections and the longest-prefix route table derived from them,
    /// under a single lock so a mutation and its route-table rebuild are
    /// published atomically.
    state: RwLock<OpenDalLayerState>,
    /// Disambiguates trace/routing-only `BackendId`s for byte-identical configs;
    /// connection identity is the `ConnectionId`.
    next_instance_counter: AtomicU64,
}

struct OpenDalLayerState {
    instances: Vec<Arc<OpenDalInstance>>,
    routes: RouteTable<Arc<OpenDalInstance>>,
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct OpenDalInstance {
    connection_id: ConnectionId,
    backend_id: BackendId,
    backend: Arc<OpenDalBackend>,
    /// fs/webdav profiles have REAL directories; the s3 profile folds
    /// markers. Per-connection (the `service` config picks the profile);
    /// drives the `Layer::list` fold.
    has_real_directories: bool,
    roots: Vec<RootInfo>,
}

/// Longest-prefix route table over the current instance set.
fn build_routes(instances: &[Arc<OpenDalInstance>]) -> RouteTable<Arc<OpenDalInstance>> {
    let items: Vec<(RootInfo, Arc<OpenDalInstance>)> = instances
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

impl OpenDalLayer {
    /// Build a connection: parse the config, resolve+freeze the auth into an
    /// [`OpenDalBackend`], hand an [`OpenDalDriver`] to the `ConnectionSet`
    /// (which validates + owns the lifecycle), then publish the
    /// config-derived root via `set_addresses`.
    ///
    /// Roots are published **unconditionally** (even for a parked
    /// `AwaitingAuth` connection): they derive from config, not from an
    /// auth-gated discovery, so callers can still locate and authenticate a
    /// parked connection.
    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<OpenDalInstance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        let config = parse_connection_config(&request)?;
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        let backend_id = BackendId(format!(
            "opendal:{}:{}:{counter}",
            config.driver.service, config.prefix
        ));

        // Credentials are static strings baked into an immutable `Operator`
        // at construction. Construction validates config SHAPE only; the
        // reachability/credential `Operator::check()` runs on the driver's
        // verify path below, so a
        // failed check PARKS the connection (`AwaitingAuth`) instead of
        // hard-failing the add.
        let capabilities = driver_capabilities(config.driver);
        let operator = build_operator(config.driver, &request.config, &request.credentials.fields)?;
        let backend = Arc::new(OpenDalBackend {
            service: config.driver.service,
            operator,
            prefix: config.prefix.clone(),
            capabilities: capabilities.clone(),
        });
        let driver = Arc::new(OpenDalDriver::new(config.driver, request.config.clone()));

        let connection_id = ConnectionId(fresh_id("opendal"));
        let display_name = request
            .display_name
            .clone()
            .unwrap_or_else(|| config.driver.display_name.to_string());
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
        // instead of erroring. `Added` is DEFERRED until the caller installs the
        // route and calls `announce_connection`, so a subscriber reacting to
        // `Added` by removing the connection cannot race route install.
        self.connection_set
            .add_connection_deferred(connection, driver, request.credentials, cancel)
            .await?;

        let root = self.root_info(
            config.prefix.clone(),
            &connection_id,
            &source,
            capabilities.clone(),
        );
        self.connection_set.set_addresses(
            &connection_id,
            vec![root.root.clone()],
            capabilities.clone(),
        );

        Ok(Arc::new(OpenDalInstance {
            connection_id,
            backend_id,
            backend,
            has_real_directories: capabilities.has_real_directories,
            roots: vec![root],
        }))
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
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: UserMetadata::new(),
        }
    }

    /// Install `instance` and republish the route table atomically.
    fn install(&self, instance: Arc<OpenDalInstance>) {
        let mut state = self.state.write();
        state.instances.push(instance);
        state.routes = build_routes(&state.instances);
    }

    fn target(&self, url: &Url) -> Result<(Arc<OpenDalInstance>, ResolvedTarget)> {
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
    /// data-path recovery loop. With `OpenDalDriver::refresh` unsupported
    /// (credentials are static config strings — nothing to re-mint) the loop
    /// degrades to classify-and-surface, which is correct: `op` here only
    /// wraps replayable operations (no consumed streaming body; writes
    /// bypass `recover`).
    async fn recover<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<OpenDalInstance>, ResolvedTarget) -> Fut,
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
impl Layer for OpenDalLayer {
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
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        bail_if_cancelled(&cancel)?;
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
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        bail_if_cancelled(&cancel)?;
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
        // run under the retry-once recovery loop; a credential error surfaces
        // to the caller.
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
        instance
            .backend
            .continue_write(
                target,
                request.input.redirects,
                request.input.results,
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
        // Pull the full set
        // (no backend-side paging), fold flat directory markers / infer
        // subdirectory kinds, then paginate the folded result so synthesized
        // entries land on stable page boundaries.
        let prefix = request.input.prefix.clone();
        let options = request.input.options;
        let max_results = options.max_results;
        let page_token = options.page_token.clone();
        let recursive = options.recursive;
        let backend_options = ListOptions {
            max_results: None,
            page_token: None,
            ..options
        };
        // The fold flag is read from the SAME routed instance that serves
        // the listing (single lookup): fs/webdav profiles have real
        // directories, the s3 profile folds markers.
        let (items, has_real_directories) = self
            .recover(&request.input.prefix, move |instance, target| {
                let options = backend_options.clone();
                let cancel = cancel.clone();
                async move {
                    let items = instance.backend.list(target, options, cancel).await?;
                    Ok((items, instance.has_real_directories))
                }
            })
            .await?;
        let items =
            fold_markers_and_infer_subdir_kinds(&prefix, items, has_real_directories, recursive);
        paginate_list_items(items, max_results, page_token)
    }

    // `list_versions`, `get_latest_version`, `watch_directory`, and
    // `update_metadata` keep the `Layer` trait defaults (`Unsupported`) —
    // OpenDAL exposes none of them and relies on the optional operation defaults.

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
                "opendal does not support cross-connection copy",
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
                "opendal does not support cross-connection rename",
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
        // prospective credentials but never registers the connection or
        // emits connection-change events.
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
        // Nothing below may run for an already-cancelled probe: the fs shape
        // validation and the remote operator construction are cheap, but a
        // caller that cancelled must observe `Cancelled`, not a completed
        // validation.
        if cancel.as_ref().is_some_and(|token| token.is_cancelled()) {
            return Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
        }
        let config = parse_connection_config(&req)?;
        let is_anonymous = req.credentials.fields.is_empty();
        let capabilities = driver_capabilities(config.driver);
        // Probe parity with add, minus the side effect: `FsBuilder::build`
        // `create_dir_all`s a missing root, so constructing an fs operator
        // here would durably create caller-chosen directory trees from a
        // "side-effect-free" probe — the fs profile validates the config map
        // only. The remote profiles construct (and drop) a throwaway operator
        // (their builders are pure); the reachability RPC runs inside
        // `probe_connection` via the driver's verify (credentialed bundles),
        // exactly the probe an add performs.
        if matches!(config.driver.profile, crate::DriverCapabilityProfile::Fs) {
            crate::build_operator_map(config.driver, &req.config, &req.credentials.fields)?;
        } else {
            let _ = build_operator(config.driver, &req.config, &req.credentials.fields)?;
        }
        let driver = Arc::new(OpenDalDriver::new(config.driver, req.config.clone()));
        let now = SystemTime::now();
        let mut view = Connection {
            id: ConnectionId(fresh_id("opendal")),
            backend_kind: self.descriptor.kind.clone(),
            display_name: req
                .display_name
                .clone()
                .unwrap_or_else(|| config.driver.display_name.to_string()),
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
                debug_assert!(is_anonymous);
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
            // Nothing opendal resolves is one-time-consuming; unreachable,
            // but
            // handled honestly.
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
        view.current_addresses = vec![config.prefix];
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
        let id = instance.connection_id.clone();
        self.install(instance);
        // Snapshot the (not-yet-announced) view BEFORE announcing so a
        // remove-on-`Added` subscriber cannot null it out between the announce
        // and this read; then announce now that the route is installed.
        let connection = self.connection_set.connection(&id).ok_or_else(|| {
            // Defensive rollback: an empty lookup would otherwise strand the
            // just-installed route as an orphan. Unreachable now that
            // `list_connections` hides deferred connections (so the id cannot
            // leak pre-announce), but "unreachable" invariants decay — mirror
            // nucleus's retained guard.
            let mut state = self.state.write();
            state
                .instances
                .retain(|instance| instance.connection_id != id);
            state.routes = build_routes(&state.instances);
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
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        bail_if_cancelled(&cancel)?;
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
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let id = self.checked_key_id(&request.input.key)?;
        // OpenDAL credentials are FROZEN at add time: static config strings
        // baked into an immutable `Operator` (no live cell), so an accepted
        // update would change
        // nothing. Remove-and-re-add is the rotation path and bakes in the new
        // credentials.
        if self.connection_set.connection(&id).is_none() {
            return Err(Error::new(ErrorCode::NotFound, "connection not found"));
        }
        Err(Error::new(
            ErrorCode::Unsupported,
            "opendal credentials are fixed at connection time; remove this connection and \
             re-add it with the new credentials",
        ))
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
        // Fail closed on patch fields this layer cannot store/enforce (the
        // http layer's rule): silently dropping a requested restriction
        // (`access_mode: read-only`, `visible: false`) while returning Ok
        // would let a caller mistake an ignored restriction for an applied
        // one. Rejected BEFORE any part of the patch applies, so a mixed
        // patch cannot be half-honored.
        if patch.access_mode.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the opendal backend does not support updating 'access_mode'",
            ));
        }
        if patch.visible.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "the opendal backend does not support updating 'visible'",
            ));
        }
        self.connection_set.update_attributes(
            &id,
            patch.display_name,
            patch.user_metadata.into_iter().collect(),
        )
    }
}
