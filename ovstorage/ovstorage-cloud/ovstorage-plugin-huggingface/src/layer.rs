// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the Hugging Face Hub backend (RFC-0066).
//!
//! A single [`HfLayer`] owns its connections and routes addresses to the
//! right [`HfBackend`] instance by longest prefix. Connection *lifecycle* is
//! delegated to a generic [`ConnectionSet<HfDriver>`]; the layer keeps only
//! the routing state. Roots are config-derived (`hf://{plural}/{repo_id}/`)
//! and fixed at connect time, so `list_address_roots` is snapshot-only.
//!
//! Only the read slots are implemented. Every mutating slot keeps the `Layer`
//! trait default, which answers `ErrorCode::Unsupported` on a leaf backend —
//! matching the all-false write bits in [`crate::hf_capabilities`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::*;
use parking_lot::RwLock;

use crate::driver::{HfDriver, validate_credentials};
use crate::{HfBackend, HfConnectionConfig, build_http_client, hf_capabilities, kind_descriptor};

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds
/// the static kind descriptor; every built layer owns its own `ConnectionSet`
/// and longest-prefix route table.
pub struct HfLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for HfLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: kind_descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for HfLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let layer = Arc::new(HfLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(HfLayerState {
                instances: Vec::new(),
                routes: RouteTable::empty(),
            }),
            next_instance_counter: AtomicU64::new(0),
        });
        // A non-empty layer config seeds one static connection (the
        // config-as-Stack path); runtime connections arrive via
        // `add_connection`. Static credentials arrive on the
        // `[[ovstorage.connections]]` path, where the descriptor's
        // `${HF_TOKEN}` default resolves at TOML load — this seed is
        // anonymous.
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
            if let Err(error) = layer.install(instance) {
                let _ = layer.connection_set.unregister_connection(&id).await;
                return Err(error);
            }
            // Route installed → announce.
            layer.connection_set.announce_connection(&id);
        }
        Ok(layer)
    }
}

/// Native ABI-v2 `Layer` for the Hugging Face Hub backend.
pub(crate) struct HfLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle. The layer keeps
    /// [`Self::state`] only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<HfDriver>>,
    /// Connections and the longest-prefix route table derived from them,
    /// under a single lock so a mutation and its route-table rebuild publish
    /// atomically.
    state: RwLock<HfLayerState>,
    /// Disambiguates trace/routing-only `BackendId`s for byte-identical
    /// configs; connection identity is the `ConnectionId`.
    next_instance_counter: AtomicU64,
}

struct HfLayerState {
    instances: Vec<Arc<HfInstance>>,
    routes: RouteTable<Arc<HfInstance>>,
}

/// One backend instance serving one connection (one repository).
struct HfInstance {
    connection_id: ConnectionId,
    backend_id: BackendId,
    backend: Arc<HfBackend>,
    roots: Vec<RootInfo>,
    /// Whether the connection was added without credentials. The backend
    /// SHAPE is the same either way (only the live cell differs), but the
    /// anonymous/tokened distinction is frozen here so credential updates can
    /// refuse a shape change whose halves the live cell cannot express.
    anonymous: bool,
}

/// Longest-prefix route table over the current instance set.
fn build_routes(instances: &[Arc<HfInstance>]) -> RouteTable<Arc<HfInstance>> {
    let items: Vec<(RootInfo, Arc<HfInstance>)> = instances
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

/// The `user_metadata` every connection row derived from `config` carries:
/// the repository's ordinary Hub-URL spellings under
/// [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`], so an alias wrapper above can
/// auto-generate hidden alias rules for them. Shared by
/// `instantiate_connection` and `probe` — like `owning_target`, the contract
/// is stamped on BOTH row-construction sites, so the preview row a probe
/// returns matches the row the subsequent add produces.
fn spellings_metadata(config: &HfConnectionConfig) -> UserMetadata {
    let mut user_metadata = UserMetadata::new();
    let url_spellings = config.alternate_url_prefixes();
    if !url_spellings.is_empty() {
        user_metadata.insert(
            ACCEPTED_URL_SPELLINGS_METADATA_KEY.to_string(),
            encode_url_spellings(&url_spellings),
        );
    }
    user_metadata
}

impl HfLayer {
    /// Build a connection: parse the config, wire the shared live-token cell
    /// into an [`HfBackend`] + [`HfDriver`] pair, hand the driver to the
    /// `ConnectionSet` (which validates and owns the lifecycle), then publish
    /// the config-derived root via `set_addresses`.
    ///
    /// Roots are published unconditionally (even for a parked `AwaitingAuth`
    /// connection): they derive from config, not from auth-gated discovery,
    /// so callers can still locate and re-credential a parked connection.
    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<HfInstance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        let config = HfConnectionConfig::from_request(&request)?;
        let anonymous = validate_credentials(&request.credentials)?.is_none();
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        let backend_id = BackendId(format!("huggingface:{}:{counter}", config.address_root));

        // The live cell starts empty; the `ConnectionSet` grant path
        // (obtain → verify → activate) installs the proven token, and the
        // backend re-reads the cell per request.
        let http = build_http_client(crate::endpoint_is_cleartext_loopback(&config.endpoint))?;
        let live_token = Arc::new(RwLock::new(None));
        let backend = Arc::new(HfBackend::new(
            config.clone(),
            http.clone(),
            live_token.clone(),
        ));
        let capabilities = hf_capabilities();
        let driver = Arc::new(HfDriver::new(config.clone(), http, live_token));

        let connection_id = ConnectionId(fresh_id("huggingface"));
        let display_name = request.display_name.clone().unwrap_or_else(|| {
            format!(
                "Hugging Face: {}/{}",
                config.repo_type.plural(),
                config.repo_id
            )
        });
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
            user_metadata: spellings_metadata(&config),
            // This layer owns the connection, and its instance name is the
            // `ConnectionKey::target` that reaches it — the same name
            // `owned_targets` reports and `remove_connection` gates on.
            owning_target: Some(self.name.clone()),
        };
        // `ConnectionSet` validates (via the driver) and records auth state; a
        // soft obtain/verify failure parks the connection (`AwaitingAuth`)
        // instead of erroring, so one expired token cannot stop a host from
        // starting. `Added` is deferred until the caller installs the route
        // and calls `announce_connection`.
        self.connection_set
            .add_connection_deferred(connection, driver, request.credentials, cancel)
            .await?;

        let root = self.root_info(
            config.address_root.clone(),
            &connection_id,
            &source,
            capabilities.clone(),
        );
        self.connection_set
            .set_addresses(&connection_id, vec![root.root.clone()], capabilities);

        Ok(Arc::new(HfInstance {
            connection_id,
            backend_id,
            backend,
            roots: vec![root],
            anonymous,
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
            // The resolve endpoint and the CDN both honor `Range`.
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: UserMetadata::new(),
        }
    }

    /// Push an instance and republish the derived route table atomically.
    ///
    /// A caller-facing prefix another connection already serves is refused
    /// with `RouteConflict` rather than installed: `RouteTable::build` would
    /// shadow the duplicate with only a warning, leaving the second
    /// connection registered but permanently unroutable. Roots carry no
    /// revision, so two connections to one repository collide even with
    /// different `revision` configs — intended; alternate revisions ride as
    /// address pins on one connection.
    fn install(&self, instance: Arc<HfInstance>) -> Result<()> {
        let mut state = self.state.write();
        if let Some(clash) = state.instances.iter().find_map(|existing| {
            existing.roots.iter().find(|root| {
                instance
                    .roots
                    .iter()
                    .any(|new| address::same_node(&new.root, &root.root))
            })
        }) {
            // Name only the origin: a display name is free-form caller text
            // the shared redaction pass does not inspect.
            return Err(Error::new(
                ErrorCode::RouteConflict,
                format!(
                    "another connection already serves an address prefix on '{}'",
                    ovstorage_plugin::redact::origin_only(&clash.root)
                ),
            ));
        }
        state.instances.push(instance);
        state.routes = build_routes(&state.instances);
        Ok(())
    }

    fn target(&self, url: &Url) -> Result<(Arc<HfInstance>, ResolvedTarget)> {
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
    /// data-path recovery loop. With `HfDriver::refresh` unsupported the
    /// recovery half degrades to classify-and-surface, which is correct for a
    /// static bearer. `op` must be replayable (all read slots are).
    async fn recover<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<HfInstance>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (instance, target) = self.target(url)?;
        let id = instance.connection_id.clone();
        self.connection_set
            .with_recovery(&id, || op(instance.clone(), target.clone()))
            .await
    }

    /// Resolve a `ConnectionKey` to its id, enforcing the target-plus-id
    /// routing contract.
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
impl Layer for HfLayer {
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
        // Roots are fixed at connect time (config-derived): snapshot-only,
        // no dynamic-root stream.
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

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        // Pull the full set (pagination is the shared numeric-offset
        // convention, never the Hub cursor), fold, then paginate so
        // normalized entries land on stable page boundaries.
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
        let items = self
            .recover(&request.input.prefix, move |instance, target| {
                let options = backend_options.clone();
                let cancel = cancel.clone();
                async move { instance.backend.list(target, options, cancel).await }
            })
            .await?;
        // Real directories: the fold dedups concrete-over-inferred and
        // normalizes directory spellings; nothing is synthesized.
        let items = fold_markers_and_infer_subdir_kinds(&prefix, items, true, recursive);
        paginate_list_items(items, max_results, page_token)
    }

    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        let prefix = request.input.prefix;
        let options = request.input.options;
        if options.max_results.is_some() || options.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }

        let recursive = options.recursive;
        let backend_options = ListOptions {
            max_results: None,
            page_token: None,
            ..options
        };
        let stream_cancel = cancel.clone();
        let stream = self
            .recover(&prefix, move |instance, target| {
                let options = backend_options.clone();
                let cancel = cancel.clone();
                async move { instance.backend.list_stream(target, options, cancel).await }
            })
            .await?;
        Ok(cancel_list_stream(
            Box::pin(IncrementalListFold::new(stream, &prefix, true, recursive)),
            stream_cancel,
        ))
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        // The backend walks the full commit history; the layer applies the
        // shared numeric-offset paging so a truncated page still yields a
        // resumable `next_page_token` and `max_results = 0` is rejected — the
        // same convention `list` uses.
        let options = request.input.options.clone();
        let max_results = options.max_results;
        let page_token = options.page_token.clone();
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
        let page = paginate_list_items(items, max_results, page_token)?;
        Ok(VersionPage {
            items: page.items,
            next_page_token: page.next_page_token,
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

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        // A probe is transient and side-effect-free: it validates the
        // prospective credentials but never registers the connection or emits
        // connection-change events.
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
        let config = HfConnectionConfig::from_request(&req)?;
        let is_anonymous = validate_credentials(&req.credentials)?.is_none();
        let capabilities = hf_capabilities();
        let driver = Arc::new(HfDriver::new(
            config.clone(),
            build_http_client(crate::endpoint_is_cleartext_loopback(&config.endpoint))?,
            Arc::new(RwLock::new(None)),
        ));
        let now = SystemTime::now();
        let mut view = Connection {
            id: ConnectionId(fresh_id("huggingface")),
            backend_kind: self.descriptor.kind.clone(),
            display_name: req.display_name.clone().unwrap_or_else(|| {
                format!(
                    "Hugging Face: {}/{}",
                    config.repo_type.plural(),
                    config.repo_id
                )
            }),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities,
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: spellings_metadata(&config),
            owning_target: Some(self.name.clone()),
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
            // A static token is never one-time-consuming; unreachable, but
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
        view.current_addresses = vec![config.address_root];
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
        if let Err(error) = self.install(instance) {
            // Roll back the registered-but-unannounced connection so a
            // refused route does not strand an orphan row.
            let _ = self.connection_set.unregister_connection(&id).await;
            return Err(error);
        }
        // Snapshot the (not-yet-announced) view BEFORE announcing, then
        // announce now that the route is installed.
        let connection = self.connection_set.connection(&id).ok_or_else(|| {
            // Defensive rollback: an empty lookup would otherwise strand the
            // just-installed route as an orphan.
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
        // Subscribe BEFORE snapshotting so a change emitted between the two
        // calls lands on the stream rather than being lost from both.
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
        let id = self.checked_key_id(&request.input.key)?;
        // The anonymous/tokened distinction is frozen at instantiate time, so
        // a shape-changing update is rejected with guidance in both
        // directions: `activate` only ever installs a token (an empty bundle
        // never clears the cell), so accepting either flip would report a
        // state the live cell does not express. Remove-and-re-add is the
        // shape change.
        let anonymous_instance = self
            .state
            .read()
            .instances
            .iter()
            .find(|instance| instance.connection_id == id)
            .map(|instance| instance.anonymous);
        let empty_bundle = validate_credentials(&request.input.credentials)?.is_none();
        match anonymous_instance {
            None => {
                return Err(Error::new(ErrorCode::NotFound, "connection not found"));
            }
            Some(true) => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "this huggingface connection was added without credentials (anonymous); \
                     remove it and re-add it with a token to attach one",
                ));
            }
            Some(false) if empty_bundle => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "this huggingface connection was added with a token; updating with an \
                     empty bundle cannot detach it — remove the connection and re-add it \
                     without credentials for anonymous access",
                ));
            }
            Some(false) => {}
        }
        // obtain → verify → activate installs the proven token into the live
        // cell the backend reads; roots are config-derived and unchanged.
        self.connection_set
            .update_credentials(&id, request.input.credentials, cancel)
            .await?;
        self.connection_set
            .connection(&id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let id = self.checked_key_id(&request.input.key)?;
        let patch = request.input.patch;
        self.connection_set.update_attributes(
            &id,
            patch.display_name,
            patch.user_metadata.into_iter().collect(),
        )
    }

    // `authenticate_connection` deliberately keeps the trait default
    // (`Unsupported`): there is no interactive flow, and the default is the
    // simpler honest spelling of the same answer the driver would give.
}
