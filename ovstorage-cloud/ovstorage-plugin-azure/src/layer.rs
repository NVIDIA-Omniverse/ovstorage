// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the Azure backend (RFC-0066).
//!
//! A single [`AzureLayer`] owns its connections and routes addresses to the
//! right [`AzureBackend`] instance by longest prefix. Connection *lifecycle*
//! is delegated to a generic [`ConnectionSet<AzureDriver>`] (RFC-0066);
//! the layer keeps only the routing state. Azure roots
//! are config-derived and fixed at connect time, so `list_address_roots` is
//! snapshot-only — no dynamic-root stream.
//!
//! Credentials are **frozen at add time** (an `AzureAuth` is immutable and
//! there is no shared live cell, unlike s3), so every
//! `update_connection_credentials` is rejected with remove-and-re-add
//! guidance because the client owns no live credential cell to update.
//!
//! With `anonymous_fallback = ["azure"]` on the layer table the route table
//! carries one more entry, the hidden `azure:///` scheme root bound to an
//! [`AzureSchemeFallback`]: an `azure://` address no connection serves routes
//! there and is attempted anonymously and read-only (see `crate::fallback`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::fallback::{
    ANONYMOUS_FALLBACK_KEY, decode_anonymous_fallback, is_anonymous_fallback_key, schemes_for_kind,
    split_anonymous_fallback_keys,
};
use ovstorage_plugin::instance_metadata::is_instance_metadata_url;
use ovstorage_plugin::*;
use parking_lot::RwLock;

use crate::auth::{AuthSource, AzureAuth};
use crate::backend::{AzureBackend, azure_capabilities};
use crate::client::{OperationEvidence, with_operation_evidence};
use crate::config::{self, AzureConnectionConfig};
use crate::driver::AzureDriver;
use crate::fallback::{AZURE_SCHEME, AzureFallbackPolicy, AzureSchemeFallback};

/// The loopback-only test hook a layer table may carry for the fallback.
const TEST_ENDPOINT_KEY: &str = "__test_endpoint";

/// The static backend descriptor; converted to the v2 `LayerKindDescriptor`
/// via [`descriptor_to_layer_kind`] at the factory/layer surface.
pub(crate) fn kind_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: "azure".into(),
        display_name: "Azure Blob Storage".into(),
        description: Some(
            "Native Azure Blob Storage and ADLS Gen2 backend with Shared Key signing, Service SAS redirects, Entra OAuth2 token caching, and staged-commit block uploads"
                .into(),
        ),
        config_schema: config::azure_config_schema(),
        credential_schema: config::azure_credential_schema(),
        credential_methods: config::azure_credential_methods(),
        icon: None,
        supports_runtime_add: true,
        supports_user_metadata: true,
    }
}

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds
/// the static kind descriptor; every built layer owns its own `ConnectionSet`
/// and longest-prefix route table.
pub struct AzureLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for AzureLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: kind_descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for AzureLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // The fallback keys are policy for this layer, not a connection to
        // seed, so they come off the table before the seed check below reads
        // it. The tunables are validated whether or not the grant names this
        // kind's scheme, so a misplaced key is refused at startup rather than
        // sitting inert.
        let (policy, mut connection) = split_anonymous_fallback_keys(config);
        let grant = decode_anonymous_fallback(&policy)?;
        let served = schemes_for_kind(&self.descriptor.kind);
        if let Some(scheme) = grant
            .iter()
            .find(|scheme| !served.contains(&scheme.as_str()))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{ANONYMOUS_FALLBACK_KEY}` on layer `{name}` (kind {}) names scheme \
                     `{scheme}`, which this kind does not serve; it serves {}",
                    self.descriptor.kind,
                    served.join(", ")
                ),
            ));
        }
        let tunables = AzureFallbackPolicy::parse(&policy)?;
        let fallback = if grant.contains(AZURE_SCHEME) {
            // The loopback-only `__test_endpoint` hook is shared with the
            // connection the table may also describe. When the table holds
            // nothing else, the hook is the fallback's alone and no static
            // connection is seeded from it.
            let test_endpoint = config::layer_test_endpoint(&connection)?;
            if connection.keys().all(|key| key == TEST_ENDPOINT_KEY) {
                connection.clear();
            }
            Some(Arc::new(AzureSchemeFallback::new(
                &self.descriptor,
                tunables,
                test_endpoint,
            )?))
        } else {
            None
        };
        let layer = Arc::new(AzureLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(AzureLayerState {
                instances: Vec::new(),
                routes: build_routes(&[], fallback.as_ref()),
            }),
            fallback,
            next_instance_counter: AtomicU64::new(0),
        });
        // A non-empty connection table seeds one static connection (the
        // config-as-Stack path); runtime connections arrive via
        // `add_connection`.
        if !connection.is_empty() {
            let request = ConnectionRequest {
                backend_kind: self.descriptor.kind.clone(),
                config: connection,
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

/// Native ABI-v2 `Layer` for the Azure backend.
pub(crate) struct AzureLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle (RFC-0066). The layer
    /// keeps [`Self::state`] only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<AzureDriver>>,
    /// Connections and the longest-prefix route table derived from them,
    /// under a single lock so a mutation and its route-table rebuild are
    /// published atomically.
    state: RwLock<AzureLayerState>,
    /// The anonymous `azure://` fallback, when the layer table grants it.
    /// Fixed at construction; every route-table rebuild re-appends its root.
    fallback: Option<Arc<AzureSchemeFallback>>,
    /// Disambiguates trace/routing-only `BackendId`s for byte-identical configs;
    /// connection identity is the `ConnectionId`.
    next_instance_counter: AtomicU64,
}

struct AzureLayerState {
    instances: Vec<Arc<AzureInstance>>,
    routes: RouteTable<AzureRoute>,
}

/// What a route-table entry binds an address to: a configured connection's
/// instance, or the scheme fallback that answers an address no connection
/// serves.
#[derive(Clone)]
enum AzureRoute {
    Connection(Arc<AzureInstance>),
    Fallback(Arc<AzureSchemeFallback>),
}

/// What an operation needs from whichever route answered it: the backend to
/// call and the namespace model that drives the `list` fold. A connection's
/// instance supplies both; the fallback supplies an anonymous backend over a
/// flat namespace.
#[derive(Clone)]
struct Routed {
    backend: Arc<AzureBackend>,
    has_real_directories: bool,
}

impl Routed {
    fn of(instance: &AzureInstance) -> Self {
        Self {
            backend: instance.backend.clone(),
            has_real_directories: instance.has_real_directories,
        }
    }
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct AzureInstance {
    connection_id: ConnectionId,
    backend_id: BackendId,
    backend: Arc<AzureBackend>,
    /// ADLS Gen2 (hierarchical namespace) has REAL directories; flat blob
    /// namespaces fold markers. Drives the `Layer::list` fold.
    has_real_directories: bool,
    roots: Vec<RootInfo>,
}

/// What one operation is allowed to be judged on, built BEFORE that operation
/// runs and installed around it by [`AcceptanceWitness::scope`].
///
/// The two halves are scoped differently, and the asymmetry is the point.
///
/// **Acceptance is the operation's own.** A connection is one `AzureClient`
/// shared by every operation running against it, and under the broker those are
/// unrelated remote callers. Judging on a connection-wide tally lets a caller
/// whose own operation never reached the service — a flat-namespace `read` that
/// only mints a redirect — be vindicated by a neighbour's request.
///
/// **Refusal is the connection's.** The credential is one object: a refusal
/// answered to anyone signing through this connection's client condemns it for
/// all of them, and an operation that merely avoided hearing the bad news must
/// not be promoted on the strength of that. (`verify` and `probe` build
/// ephemeral backends with their own client, so their refusals are theirs
/// alone — parking is their control, not this one.)
/// A per-operation refusal sink would also discard refusals belonging to no
/// operation at all — a change-feed poll's — and let a staged write that was
/// accepted before a key rotation promote on that stale acceptance. So the
/// witness snapshots the connection's refusal epoch and requires it unchanged.
///
/// Both are needed. Either alone promotes something it should not.
struct AcceptanceWitness {
    instance: Arc<AzureInstance>,
    evidence: Arc<OperationEvidence>,
    refusal_epoch_before: u64,
}

impl AcceptanceWitness {
    fn take(instance: &Arc<AzureInstance>) -> Self {
        Self {
            refusal_epoch_before: instance.backend.refusal_epoch(),
            instance: instance.clone(),
            evidence: Arc::new(OperationEvidence::default()),
        }
    }

    /// Run `future` with this witness's acceptance sink installed.
    ///
    /// **Every call site must wrap its operation in this.** A witness that is
    /// built and read but never scoped records no acceptance, so `proved`
    /// answers `false` for ever and the connection stays parked however well its
    /// operations go — a working credential reporting `AwaitingAuth`, which is
    /// the condition this whole mechanism exists to end. Only the ordering of
    /// the snapshot is structural; this part is not, so [`Self::proved`] asserts
    /// on it.
    async fn scope<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        with_operation_evidence(self.evidence.clone(), future).await
    }

    /// Whether the service answered a request THIS operation signed, no
    /// refusal reached the connection while it ran, the IdP has not refused the
    /// credential, and the instance that ran it is still installed.
    ///
    /// All four clauses carry weight.
    ///
    /// The epoch clause is what makes this safe to read on a failed operation.
    /// A multi-request op — `rename`'s copy then delete, a paged `list`,
    /// `stat`'s fallback probe — can have one request accepted and the next
    /// refused when a SAS expires or a key rotates mid-flight, and "something
    /// was accepted" would promote a connection whose credential had just died.
    /// Being connection-wide, it also catches the refusal a concurrent
    /// operation heard and the refusal a change-feed poll heard, neither of
    /// which reaches this operation's own sink.
    ///
    /// The instance clause covers removal: `remove_connection` unregisters
    /// before it drops the route, so an operation resolved against a retired
    /// instance must not vindicate whatever is registered now.
    ///
    /// The latched clause covers the refusal the epoch does not count. The
    /// proactive token refresh talks to the IdP rather than to storage and
    /// advances no epoch, so a refusal it meets is invisible here however the
    /// two overlap in time; and on failure it keeps the cached bearer, which the
    /// service goes on accepting until that bearer expires. So the operation
    /// genuinely does see an acceptance and no refusal. It also covers a
    /// refusal that landed BEFORE this witness took its snapshot, which an
    /// epoch comparison cannot reach by construction.
    fn proved(&self, layer: &AzureLayer) -> bool {
        if !self.evidence.require_installed("azure") {
            return false;
        }
        self.evidence.saw_acceptance()
            && self.instance.backend.refusal_epoch() == self.refusal_epoch_before
            && !self.instance.backend.credential_refused()
            && layer.instance_is_installed(&self.instance)
    }
}

/// Longest-prefix route table over the current instance set, plus the scheme
/// root when the fallback is granted. The table ranks the depth-0 scheme root
/// last on its own; appending it last keeps the input in the same order.
fn build_routes(
    instances: &[Arc<AzureInstance>],
    fallback: Option<&Arc<AzureSchemeFallback>>,
) -> RouteTable<AzureRoute> {
    let mut items: Vec<(RootInfo, AzureRoute)> = instances
        .iter()
        .flat_map(|instance| {
            instance
                .roots
                .iter()
                .cloned()
                .map(|root| (root, AzureRoute::Connection(instance.clone())))
                .collect::<Vec<_>>()
        })
        .collect();
    if let Some(fallback) = fallback {
        items.push((
            fallback.root().clone(),
            AzureRoute::Fallback(fallback.clone()),
        ));
    }
    RouteTable::build(items)
}

/// Advisory only, in the same spirit as the cleartext-endpoint warning: an
/// operator who points a connection at a cloud instance-metadata host chose
/// to, so the connection is honoured, and the warning names the exposure once
/// at construction. The unconditional refusal applies only to hosts derived
/// from a caller's address, which no configured connection has.
fn warn_on_instance_metadata_endpoint(config: &AzureConnectionConfig) {
    let mut bases = vec![config.blob_url_base()];
    if config.hierarchical_namespace {
        bases.push(config.dfs_url_base());
    }
    if config.change_feed_enabled {
        bases.push(config.change_feed_base_url());
    }
    for base in bases {
        let Ok(url) = Url::parse(&format!("{base}/")) else {
            continue;
        };
        if is_instance_metadata_url(&url) {
            tracing::warn!(
                plugin = "azure",
                endpoint = %origin_only(&url),
                "Azure connection endpoint is a cloud instance-metadata host; it is honoured \
                 because an operator configured it, but every request this connection signs \
                 goes to that host"
            );
        }
    }
}

/// The `user_metadata` every connection row derived from `config` carries:
/// the container's ordinary cloud-URL spellings under
/// [`ACCEPTED_URL_SPELLINGS_METADATA_KEY`], so an alias wrapper above can
/// auto-generate hidden alias rules for them. Shared by
/// `instantiate_connection` and `probe` — like `owning_target`, the contract
/// is stamped on BOTH row-construction sites, so the preview row a probe
/// returns matches the row the subsequent add produces.
fn spellings_metadata(config: &AzureConnectionConfig) -> UserMetadata {
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

impl AzureLayer {
    /// Refuse a connection request that carries a fallback layer key. The
    /// parser would refuse it as an unknown field anyway; it gets its own
    /// message here because the operator's mistake is one of placement rather
    /// than spelling, and this is where the layer table's name is known.
    fn refuse_fallback_keys(&self, config: &LayerConfig) -> Result<()> {
        if let Some(key) = config
            .keys()
            .filter(|key| is_anonymous_fallback_key(key))
            .min()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{key}` is a layer key, not connection config; set it on \
                     [ovstorage.layers.{}]",
                    self.name
                ),
            ));
        }
        Ok(())
    }

    /// Build a connection: parse the config, resolve+freeze the auth into an
    /// [`AzureBackend`], hand an [`AzureDriver`] to the `ConnectionSet`
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
    ) -> Result<Arc<AzureInstance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        self.refuse_fallback_keys(&request.config)?;
        let config = AzureConnectionConfig::from_request(&request)?;
        warn_on_instance_metadata_endpoint(&config);
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        // The label is the effective endpoint, not the raw suffix, so two
        // connections that differ only by `blob_endpoint` stay
        // distinguishable in diagnostics.
        let backend_id = BackendId(format!(
            "azure:{}:{}/{}:{counter}",
            config.endpoint_label(),
            config.account,
            config.container
        ));

        // Auth is resolved ONCE and frozen into the backend (no live cell;
        // OAuth arms self-refresh inside `AzureAuth`). The same resolution
        // failure surfaces here before any lifecycle registration.
        let auth = AzureAuth::resolve(&request.credentials)?;
        let backend = Arc::new(AzureBackend::new(config.clone(), auth)?);
        let capabilities = backend.capabilities();
        let driver = Arc::new(AzureDriver::new(config.clone()));

        let connection_id = ConnectionId(fresh_id("azure"));
        let display_name = request.display_name.clone().unwrap_or_else(|| {
            format!("Azure Blob Storage {}/{}", config.account, config.container)
        });
        let user_metadata = spellings_metadata(&config);
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
            user_metadata,
            // This layer owns the connection, and its instance name is the
            // `ConnectionKey::target` that reaches it -- the same name
            // `owned_targets` reports and `remove_connection` gates on. Stamped
            // at construction so the row carries it wherever it goes, including
            // out of `ConnectionSet`'s change stream.
            owning_target: Some(self.name.clone()),
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
            config.address_root.clone(),
            &connection_id,
            &source,
            capabilities.clone(),
        );
        self.connection_set
            .set_addresses(&connection_id, vec![root.root.clone()], capabilities);

        Ok(Arc::new(AzureInstance {
            connection_id,
            backend_id,
            backend,
            has_real_directories: config.hierarchical_namespace,
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

    /// Install `instance` and republish the route table atomically. Any
    /// fallback backend cached for a node the connection publishes is
    /// evicted: the prefix tier answers that node from now on.
    fn install(&self, instance: Arc<AzureInstance>) {
        if let Some(fallback) = &self.fallback {
            for root in &instance.roots {
                fallback.evict_node(&root.root);
            }
        }
        let mut state = self.state.write();
        state.instances.push(instance);
        state.routes = build_routes(&state.instances, self.fallback.as_ref());
    }

    /// Route `url`: the connection whose root is its longest prefix, or the
    /// fallback when nothing is and the layer grants one. A fallback hit
    /// resolves the node from the address here, so an address that names no
    /// account is refused on every slot before anything else happens.
    fn target(&self, url: &Url) -> Result<(AzureRoute, ResolvedTarget)> {
        let route = self
            .state
            .read()
            .routes
            .lookup(url)
            .map(|(_, route)| route.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))?;
        let target = match &route {
            AzureRoute::Connection(instance) => ResolvedTarget {
                backend_id: instance.backend_id.clone(),
                resolved_address: url.clone(),
            },
            AzureRoute::Fallback(fallback) => fallback.resolved_target(url)?,
        };
        Ok((route, target))
    }

    /// The instance a mutating slot may act on. A fallback route is refused
    /// here — before any witness is taken, any body is read or any request is
    /// built — because the fallback is read-only by construction.
    fn mutable_instance(route: AzureRoute, target: &ResolvedTarget) -> Result<Arc<AzureInstance>> {
        match route {
            AzureRoute::Connection(instance) => Ok(instance),
            AzureRoute::Fallback(fallback) => {
                Err(fallback.mutation_refused(&target.resolved_address))
            }
        }
    }

    /// Route `url` to its instance and run `op` under the connection's
    /// data-path recovery loop. With `AzureDriver::refresh` unsupported the
    /// loop degrades to classify-and-surface, which is correct — OAuth token
    /// freshness is owned by `AzureAuth` internally, not by the set. `op`
    /// must be replayable (no consumed streaming body).
    ///
    /// A parked connection is promoted when the run PROVED its credentials, and
    /// the proof is measured rather than assumed: `AzureClient::send` credits
    /// an acceptance to the operation that earned it, and an operation holding
    /// one had a request answered by the service. No slot has to be classified
    /// as "reaches the wire" — `read` mints a URL on a flat namespace and sends
    /// a kind preflight on a hierarchical one, and both answers are correct for
    /// the run that produced them.
    ///
    /// Evidence is read at the operation boundary, and acceptance belongs to
    /// the operation that earned it, so a background task earns none of it for
    /// anyone: `watch_directory` returns before its producer sends anything,
    /// and the producer runs on a task of its own, outside every operation's
    /// sink. A watch-only connection therefore stays parked until some other
    /// operation runs. Its REFUSALS are still seen, because those belong to the
    /// connection rather than to an operation.
    ///
    /// The instance is re-checked too: an operation resolved against an
    /// instance that has since been removed proves nothing about the layer's
    /// current state, and `remove_connection` unregisters the connection before
    /// it drops the route, so the two are briefly out of step. This layer mints
    /// a process-unique `ConnectionId` per instantiation, so a re-add cannot
    /// reuse an id here and the `ConnectionSet`'s own identity fence would
    /// catch that case anyway — this check is the cheap local one for plain
    /// removal.
    ///
    /// A fallback route has none of this: no connection to park or promote,
    /// no credential to prove. The anonymous backend is resolved (built on
    /// first touch, under `cancel`) and `op` runs against it directly.
    async fn recover<T, F, Fut>(
        &self,
        url: &Url,
        cancel: Option<CancellationToken>,
        op: F,
    ) -> Result<T>
    where
        F: Fn(Routed, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        match self.target(url)? {
            (AzureRoute::Connection(instance), target) => {
                self.recover_on(instance, target, op).await
            }
            (AzureRoute::Fallback(fallback), _) => {
                let (backend, target) = fallback.backend_for(url, cancel).await?;
                op(
                    Routed {
                        backend,
                        has_real_directories: false,
                    },
                    target,
                )
                .await
            }
        }
    }

    /// [`Self::recover`] for a mutating slot: a connection runs `op` under the
    /// same recovery loop; the fallback is refused before anything runs.
    async fn recover_mutation<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Routed, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (route, target) = self.target(url)?;
        let instance = Self::mutable_instance(route, &target)?;
        self.recover_on(instance, target, op).await
    }

    /// The connection half of [`Self::recover`]: the witness, the recovery
    /// loop and the promotion rule described there.
    async fn recover_on<T, F, Fut>(
        &self,
        instance: Arc<AzureInstance>,
        target: ResolvedTarget,
        op: F,
    ) -> Result<T>
    where
        F: Fn(Routed, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        self.connection_set
            .with_recovery_promoting_if(
                &id,
                || witness.proved(self),
                || witness.scope(op(Routed::of(&instance), target.clone())),
            )
            .await
    }

    /// Whether `instance` is still the installed instance for its connection —
    /// pointer identity, not a routing lookup, so a re-added connection's fresh
    /// instance does not answer for a retired one.
    fn instance_is_installed(&self, instance: &Arc<AzureInstance>) -> bool {
        self.state
            .read()
            .instances
            .iter()
            .any(|installed| Arc::ptr_eq(installed, instance))
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
impl Layer for AzureLayer {
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
        self.recover(
            &request.input.address,
            cancel.clone(),
            move |routed, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move { routed.backend.stat(target, options, cancel).await }
            },
        )
        .await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let options = request.input.options;
        self.recover(
            &request.input.address,
            cancel.clone(),
            move |routed, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move { routed.backend.read(target, options, cancel).await }
            },
        )
        .await
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        // Writes consume their body / span multiple rounds, so they are not
        // run under the retry-once recovery loop; a credential error surfaces
        // to the caller. The acceptance an inline write earns still counts,
        // though — a connection whose `Put Blob` the service answered has
        // proved its credentials as surely as any other operation.
        let (route, target) = self.target(&request.input.address)?;
        let instance = Self::mutable_instance(route, &target)?;
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        let options = request.input.options;
        let body = request.input.body;
        self.connection_set
            .with_promotion_if(
                &id,
                || witness.proved(self),
                witness.scope(async move {
                    match body {
                        Body::Bytes(bytes) => {
                            instance.backend.write(target, bytes, options, cancel).await
                        }
                        Body::LocalFile(path) => {
                            let stream = body_stream_from_file(&path)?;
                            instance
                                .backend
                                .write_stream(target, stream, options, cancel)
                                .await
                        }
                        Body::Stream(stream) => {
                            instance
                                .backend
                                .write_stream(target, stream, options, cancel)
                                .await
                        }
                    }
                }),
            )
            .await
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
        let (route, target) = self.target(&request.input.address)?;
        let instance = Self::mutable_instance(route, &target)?;
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
        let (route, target) = self.target(&request.input.address)?;
        let instance = Self::mutable_instance(route, &target)?;
        // The staged path commits with a signed `Put Block List` of our own, so
        // the client sees that response and it counts like any other.
        //
        // A single-redirect write leaves no evidence here, and the 2xx the
        // caller reports back is NOT a substitute. `results` is caller-supplied
        // and the caller is not always in-process — the broker takes it
        // straight off the wire — so a remote client could report a 201 it
        // never performed and flip an operator's shared connection to
        // `Authenticated` with no request leaving the process. That is this
        // defect inverted and handed to an untrusted party. A redirect-only
        // writer stays parked until some other operation reaches the service.
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        // The staged commit applies metadata that travelled out through the
        // caller inside the continuation, so a host attribution layer's value
        // is taken from the request instead. Read before the input is moved.
        let attested = ovstorage_plugin::attested_modified_by(&request.extensions);
        let (redirects, results) = (request.input.redirects, request.input.results);
        self.connection_set
            .with_promotion_if(
                &id,
                || witness.proved(self),
                witness.scope(async move {
                    instance
                        .backend
                        .continue_write(target, redirects, results, attested.as_deref(), cancel)
                        .await
                }),
            )
            .await
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let options = request.input.options;
        self.recover_mutation(&request.input.address, move |routed, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { routed.backend.delete(target, options, cancel).await }
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
        // entries land on stable page boundaries. ADLS Gen2 (HNS) has real
        // directories, so the fold passes through concrete kinds there.
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
        // The fold flag is read from the SAME routed instance that serves the
        // listing (inside the closure — a single lookup), so a concurrent
        // remove/re-add with a different `hierarchical_namespace` can't fold
        // one instance's items with another's flag.
        let (items, has_real_directories) = self
            .recover(
                &request.input.prefix,
                cancel.clone(),
                move |routed, target| {
                    let options = backend_options.clone();
                    let cancel = cancel.clone();
                    async move {
                        let items = routed.backend.list(target, options, cancel).await?;
                        Ok((items, routed.has_real_directories))
                    }
                },
            )
            .await?;
        let items =
            fold_markers_and_infer_subdir_kinds(&prefix, items, has_real_directories, recursive);
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
        // Read the namespace model from the same routed instance that opens
        // the stream, exactly as buffered `list` does for its whole-set fold.
        let (stream, has_real_directories) = self
            .recover(&prefix, cancel.clone(), move |routed, target| {
                let options = backend_options.clone();
                let cancel = cancel.clone();
                async move {
                    let stream = routed.backend.list_stream(target, options, cancel).await?;
                    Ok((stream, routed.has_real_directories))
                }
            })
            .await?;
        Ok(cancel_list_stream(
            Box::pin(IncrementalListFold::new(
                stream,
                &prefix,
                has_real_directories,
                recursive,
            )),
            stream_cancel,
        ))
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let options = request.input.options;
        let items = self
            .recover(
                &request.input.address,
                cancel.clone(),
                move |routed, target| {
                    let options = options.clone();
                    let cancel = cancel.clone();
                    async move { routed.backend.list_versions(target, options, cancel).await }
                },
            )
            .await?;
        // Current behavior: the backend paginates natively and internally;
        // the host never chained pages.
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
        self.recover(
            &request.input.address,
            cancel.clone(),
            move |routed, target| {
                let cancel = cancel.clone();
                async move { routed.backend.get_latest_version(target, cancel).await }
            },
        )
        .await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        // Establish the change-feed subscription under `recover`
        // (establishment is replayable); mid-stream errors surface via the
        // mapped stream. The fallback is refused like a mutation: a watch is
        // a standing subscription on a node nobody configured, and the
        // fallback's read-only root withholds the watch bit.
        let options = request.input.options;
        let stream = self
            .recover_mutation(&request.input.prefix, move |routed, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move {
                    routed
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
        self.recover_mutation(&request.input.address, move |routed, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move {
                routed
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
        self.recover_mutation(&request.input.address, move |routed, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move {
                routed
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
        let (source_route, source) = self.target(&request.input.source)?;
        let (dest_route, destination) = self.target(&request.input.destination)?;
        // Both ends are resolved before anything runs, and either end on the
        // fallback refuses the whole operation before any read of the source:
        // the fallback performs no mutation, and a copy is one whichever side
        // of it the fallback node is on. The refusal names that node.
        let source_instance = Self::mutable_instance(source_route, &source)?;
        let dest_instance = Self::mutable_instance(dest_route, &destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "azure does not support cross-connection copy",
            ));
        }
        let id = source_instance.connection_id.clone();
        let options = request.input.options;
        // Same evidence gate as `recover`; this slot resolves two instances of
        // its own, so it cannot route through that helper.
        let witness = AcceptanceWitness::take(&source_instance);
        self.connection_set
            .with_recovery_promoting_if(
                &id,
                || witness.proved(self),
                || {
                    let (instance, source, destination, options, cancel) = (
                        source_instance.clone(),
                        source.clone(),
                        destination.clone(),
                        options.clone(),
                        cancel.clone(),
                    );
                    witness.scope(async move {
                        instance
                            .backend
                            .copy(source, destination, options, cancel)
                            .await
                    })
                },
            )
            .await
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let (source_route, source) = self.target(&request.input.source)?;
        let (dest_route, destination) = self.target(&request.input.destination)?;
        // Both ends are checked, as in `copy`: a rename deletes its source,
        // so a fallback source is as much a mutation as a fallback destination.
        let source_instance = Self::mutable_instance(source_route, &source)?;
        let dest_instance = Self::mutable_instance(dest_route, &destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "azure does not support cross-connection rename",
            ));
        }
        let id = source_instance.connection_id.clone();
        let options = request.input.options;
        // Same evidence gate as `recover`; this slot resolves two instances of
        // its own, so it cannot route through that helper.
        let witness = AcceptanceWitness::take(&source_instance);
        self.connection_set
            .with_recovery_promoting_if(
                &id,
                || witness.proved(self),
                || {
                    let (instance, source, destination, options, cancel) = (
                        source_instance.clone(),
                        source.clone(),
                        destination.clone(),
                        options.clone(),
                        cancel.clone(),
                    );
                    witness.scope(async move {
                        instance
                            .backend
                            .rename(source, destination, options, cancel)
                            .await
                    })
                },
            )
            .await
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let options = request.input.options;
        self.recover_mutation(&request.input.address, move |routed, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move {
                routed
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
        self.recover(
            &request.input.address,
            cancel.clone(),
            move |routed, target| {
                let operations = operations.clone();
                let cancel = cancel.clone();
                async move {
                    routed
                        .backend
                        .check_access(target, operations, cancel)
                        .await
                }
            },
        )
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
        self.refuse_fallback_keys(&req.config)?;
        let config = AzureConnectionConfig::from_request(&req)?;
        let is_anonymous = matches!(
            AzureAuth::resolve(&req.credentials)?.source(),
            AuthSource::Anonymous
        );
        let capabilities = azure_capabilities(
            config.hierarchical_namespace,
            config.change_feed_enabled,
            is_anonymous,
        );
        let driver = Arc::new(AzureDriver::new(config.clone()));
        let now = SystemTime::now();
        let mut view = Connection {
            id: ConnectionId(fresh_id("azure")),
            backend_kind: self.descriptor.kind.clone(),
            display_name: req.display_name.clone().unwrap_or_else(|| {
                format!("Azure Blob Storage {}/{}", config.account, config.container)
            }),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities,
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            // The preview row carries the same spellings contract the
            // registered row will, so a host can show "these URLs will also
            // resolve" before the caller commits.
            user_metadata: spellings_metadata(&config),
            // This layer owns the connection, and its instance name is the
            // `ConnectionKey::target` that reaches it -- the same name
            // `owned_targets` reports and `remove_connection` gates on. Stamped
            // at construction so the row carries it wherever it goes, including
            // out of `ConnectionSet`'s change stream.
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
            // Nothing azure resolves is one-time-consuming; unreachable, but
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
            state.routes = build_routes(&state.instances, self.fallback.as_ref());
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
        state.routes = build_routes(&state.instances, self.fallback.as_ref());
        Ok(())
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let id = self.checked_key_id(&request.input.key)?;
        // Azure credentials are FROZEN at add time: an `AzureAuth` is
        // immutable once resolved into the backend's client (there is no
        // shared live cell like s3's, and the OAuth arms self-refresh
        // internally). Accepting an update would validate the new bundle and
        // silently change nothing. Remove-and-re-add is the rotation path and
        // constructs a new client with the new credentials.
        if self.connection_set.connection(&id).is_none() {
            return Err(Error::new(ErrorCode::NotFound, "connection not found"));
        }
        Err(Error::new(
            ErrorCode::Unsupported,
            "azure credentials are fixed at connection time; remove this connection and \
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
        self.connection_set.update_attributes(
            &id,
            patch.display_name,
            patch.user_metadata.into_iter().collect(),
        )
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
    /// stores `x-ms-meta-*` on Put Blob, on the presigned PUT, and at Put Block List.
    #[test]
    fn azure_declares_its_user_metadata_support() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "azure");
        assert!(
            descriptor.supports_user_metadata,
            "azure's user-metadata declaration changed; a host composes its \
             attribution layer from it"
        );
    }
}
