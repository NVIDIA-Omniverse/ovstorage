// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the GCS backend (RFC-0066).
//!
//! A single [`GcsLayer`] owns its connections and routes addresses to the
//! right [`GcsBackend`] instance by longest prefix. Connection *lifecycle*
//! is delegated to a generic [`ConnectionSet<GcsDriver>`] (RFC-0066);
//! the layer keeps only the routing state. GCS roots
//! are config-derived and fixed at connect time, so `list_address_roots` is
//! snapshot-only — no dynamic-root stream.
//!
//! Credentials are **frozen at add time** (an `Authenticator` is immutable
//! and there is no shared live cell, unlike s3), so every
//! `update_connection_credentials` is rejected with remove-and-re-add
//! guidance because the client owns no live credential cell to update.

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

use crate::auth::Authenticator;
use crate::driver::GcsDriver;
use crate::fallback::{FallbackPolicy, GcsSchemeFallback, SCHEME};
use crate::promotion::{OperationEvidence, with_operation_evidence};
use crate::{
    GcsBackend, GcsConnectionConfig, build_http_client, gcs_capabilities, kind_descriptor,
};

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds
/// the static kind descriptor; every built layer owns its own `ConnectionSet`
/// and longest-prefix route table.
pub struct GcsLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for GcsLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: kind_descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for GcsLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        // The fallback policy is split off FIRST: the static-connection seed
        // below treats any non-empty table as a connection, and a layer whose
        // only key is `anonymous_fallback = ["gs"]` describes no connection.
        let (policy, connection) = split_anonymous_fallback_keys(config);
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
        // Tunables are validated whether or not the grant is present, so a bad
        // value fails at startup rather than on the day the grant is added.
        let fallback_policy = FallbackPolicy::parse(&policy, name)?;
        let fallback = if grant.contains(SCHEME) {
            Some(Arc::new(GcsSchemeFallback::new(
                fallback_policy,
                &self.descriptor.kind,
                self.descriptor.icon.clone(),
            )?))
        } else {
            None
        };
        let layer = Arc::new(GcsLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(GcsLayerState {
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

/// Native ABI-v2 `Layer` for the GCS backend.
pub(crate) struct GcsLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle (RFC-0066). The layer
    /// keeps [`Self::state`] only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<GcsDriver>>,
    /// Connections and the longest-prefix route table derived from them,
    /// under a single lock so a mutation and its route-table rebuild are
    /// published atomically.
    state: RwLock<GcsLayerState>,
    /// The anonymous `gs://` fallback, present only when the layer's
    /// `anonymous_fallback` grant names `gs`. Fixed for the life of the layer:
    /// the grant is layer config, not a connection anyone can add or remove.
    fallback: Option<Arc<GcsSchemeFallback>>,
    /// Disambiguates trace/routing-only `BackendId`s for byte-identical configs;
    /// connection identity is the `ConnectionId`.
    next_instance_counter: AtomicU64,
}

struct GcsLayerState {
    instances: Vec<Arc<GcsInstance>>,
    routes: RouteTable<GcsRoute>,
}

/// What a route-table hit binds to: a configured connection's instance, or the
/// scheme fallback when the address matched nothing and the table's second
/// tier answered.
#[derive(Clone)]
enum GcsRoute {
    Connection(Arc<GcsInstance>),
    Fallback(Arc<GcsSchemeFallback>),
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct GcsInstance {
    connection_id: ConnectionId,
    backend_id: BackendId,
    backend: Arc<GcsBackend>,
    roots: Vec<RootInfo>,
}

/// What one operation is allowed to be judged on, built BEFORE that operation
/// runs and installed around it by [`AcceptanceWitness::scope`].
///
/// The two halves are scoped differently, and the asymmetry is the point.
///
/// **Acceptance is the operation's own.** One `GcsBackend` serves every caller
/// of a connection, and under the broker those are unrelated remote callers.
/// Judging on a connection-wide tally lets a caller whose own operation never
/// reached the service — a `read`, which only mints a signed URL — be
/// vindicated by a neighbour's request. (`read` on a service-account connection
/// is exactly that: it mints a signed URL and sends nothing. On an
/// authorized-user connection it cannot sign one, so it fetches instead — which
/// is why this is measured per run rather than declared per slot.)
///
/// **Refusal is the connection's.** The credential is one object: a refusal
/// answered to anyone signing with this connection's bearer condemns it for all
/// of them, including the Pub/Sub poller, which belongs to no operation at all.
/// (`verify` and `probe` build ephemeral authenticators of their own, so their
/// refusals are theirs alone — parking is their control, not this one.)
///
/// A third clause covers the refusal neither can see. The proactive token
/// refresh talks to the IdP rather than to storage, so it advances no storage
/// epoch however it overlaps an operation in time, and on failure it keeps the
/// cached bearer — which storage goes on accepting until that bearer expires.
/// `Authenticator::credential_refused` latches a refused grant until a later
/// one supersedes it.
///
/// That clause is covered at the UNIT level only —
/// `a_refused_grant_latches_until_one_is_accepted` and its siblings pin the
/// latch being set, cleared, and not cleared by a transient. Reaching it end to
/// end means driving the background refresh to failure while a cached bearer is
/// still live, and the obstacle is not the refresh deadline — `auth`'s own
/// tests cross that with `#[tokio::test(start_paused = true)]`. It is that
/// paused time AUTO-ADVANCES whenever the runtime is idle, and this suite's
/// endpoints are blocking `std::thread` servers that register no work with the
/// runtime: the clock jumps to the client's own request timeout before the
/// thread answers, so every request fails transiently. Measured — the probe
/// never reaches the wire and the lenient verify passes it.
///
/// Closing it would mean porting these fixtures onto tokio listeners, as
/// `auth::tests::spawn_mock_token_endpoint` is. Until then the conjunct in
/// [`Self::proved`] rests on review rather than on a test; worth knowing before
/// deleting it.
struct AcceptanceWitness {
    instance: Arc<GcsInstance>,
    evidence: Arc<OperationEvidence>,
    refusal_epoch_before: u64,
}

impl AcceptanceWitness {
    fn take(instance: &Arc<GcsInstance>) -> Self {
        Self {
            refusal_epoch_before: instance.backend.authenticator().refusal_epoch(),
            instance: instance.clone(),
            evidence: Arc::new(OperationEvidence::default()),
        }
    }

    /// Run `future` with this witness's acceptance sink installed.
    ///
    /// **Every call site must wrap its operation in this.** A witness that is
    /// built and read but never scoped records no acceptance, so
    /// [`Self::proved`] answers `false` for ever and the connection stays parked
    /// however well its operations go — a working credential reporting
    /// `AwaitingAuth`, which is the condition this whole mechanism exists to
    /// end. Only the ordering of the snapshot is structural; this part is not,
    /// so [`Self::proved`] asserts on it.
    async fn scope<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        with_operation_evidence(self.evidence.clone(), future).await
    }

    /// Whether the service answered a request THIS operation signed, no refusal
    /// reached the connection while it ran, the IdP has not refused the
    /// credential, and the instance that ran it is still installed.
    ///
    /// The epoch clause is what makes this safe to read on a failed operation.
    /// A multi-request op — `rename`'s copy then delete, a paged `list`, a
    /// resumable upload — can have one request accepted and the next refused
    /// when a bearer dies mid-flight, and "something was accepted" would promote
    /// a connection whose credential had just died.
    ///
    /// What no clause here reaches is a storage refusal that landed BEFORE the
    /// snapshot: an epoch comparison cannot see it by construction. A sticky
    /// storage-refusal latch would, and was rejected on the merits — it turns
    /// "parked until the next clean operation" into "parked for ever", which is
    /// the inverse defect. So the guarantee is bounded and stated as such.
    ///
    /// The instance clause covers removal: `remove_connection` unregisters
    /// before it drops the route, so an operation resolved against a retired
    /// instance must not vindicate whatever is registered now.
    fn proved(&self, layer: &GcsLayer) -> bool {
        if !self.evidence.require_installed("gcs") {
            return false;
        }
        let auth = self.instance.backend.authenticator();
        self.evidence.saw_acceptance()
            && auth.refusal_epoch() == self.refusal_epoch_before
            && !auth.credential_refused()
            && layer.instance_is_installed(&self.instance)
    }
}

/// Longest-prefix route table over the current instance set, plus the marked
/// scheme root when a fallback is granted. The table ranks the scheme root
/// last on its own (it is the shortest prefix there is) and consults it only
/// through its second tier, so appending it here is bookkeeping, not ranking.
fn build_routes(
    instances: &[Arc<GcsInstance>],
    fallback: Option<&Arc<GcsSchemeFallback>>,
) -> RouteTable<GcsRoute> {
    let mut items: Vec<(RootInfo, GcsRoute)> = instances
        .iter()
        .flat_map(|instance| {
            instance
                .roots
                .iter()
                .cloned()
                .map(|root| (root, GcsRoute::Connection(instance.clone())))
                .collect::<Vec<_>>()
        })
        .collect();
    if let Some(fallback) = fallback {
        items.push((
            fallback.root().clone(),
            GcsRoute::Fallback(fallback.clone()),
        ));
    }
    RouteTable::build(items)
}

impl GcsLayer {
    /// Build a connection: parse the config, resolve+freeze the auth into an
    /// [`GcsBackend`], hand a [`GcsDriver`] to the `ConnectionSet`
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
    ) -> Result<Arc<GcsInstance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        self.refuse_fallback_keys_on_connection(&request.config)?;
        let config = GcsConnectionConfig::from_request(&request)?;
        self.warn_if_endpoint_is_instance_metadata(&config);
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        let backend_id = BackendId(format!("gcs:{}:{counter}", config.address_root));

        // Auth is resolved ONCE and frozen into the backend (no live cell;
        // the OAuth token cache self-refreshes inside `Authenticator`). The
        // same resolution failure surfaces here, before any lifecycle
        // registration. The DURABLE instance is
        // the one that installs the background refresh (the driver's
        // ephemeral verify backend deliberately does not).
        let http = build_http_client()?;
        let authenticator = Arc::new(Authenticator::new(&request.credentials, http.clone())?);
        authenticator.install_background_refresh(Authenticator::DEFAULT_REFRESH_INTERVAL);
        let backend = Arc::new(GcsBackend::new(config.clone(), http, authenticator));
        let capabilities = gcs_capabilities(&config);
        let driver = Arc::new(GcsDriver::new(config.clone()));

        let connection_id = ConnectionId(fresh_id("gcs"));
        let display_name = request
            .display_name
            .clone()
            .unwrap_or_else(|| format!("Google Cloud Storage: {}", config.bucket));
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

        Ok(Arc::new(GcsInstance {
            connection_id,
            backend_id,
            backend,
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

    /// Refuse a connection request that carries a fallback key. Those keys
    /// belong to the layer table; on a connection they would parse as nothing,
    /// and the operator would believe the grant took effect.
    fn refuse_fallback_keys_on_connection(&self, config: &LayerConfig) -> Result<()> {
        if let Some(key) = config.keys().find(|key| is_anonymous_fallback_key(key)) {
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

    /// Advisory only: an operator who points a configured connection at a cloud
    /// instance-metadata host chose to, so the connection is built — but the
    /// choice is worth a line in the log, because the fallback refuses the same
    /// host outright and the asymmetry should be visible.
    fn warn_if_endpoint_is_instance_metadata(&self, config: &GcsConnectionConfig) {
        if let Some(endpoint) = config.endpoint.as_deref()
            && let Ok(endpoint) = Url::parse(endpoint)
            && is_instance_metadata_url(&endpoint)
        {
            tracing::warn!(
                layer = %self.name,
                endpoint = %origin_only(&endpoint),
                "configured GCS endpoint is a cloud instance-metadata host"
            );
        }
    }

    /// Install `instance` and republish the route table atomically. A
    /// fallback backend cached for a bucket the new connection serves is
    /// evicted: the first tier answers that bucket for as long as the
    /// connection is installed.
    fn install(&self, instance: Arc<GcsInstance>) {
        let mut state = self.state.write();
        if let Some(fallback) = &self.fallback {
            for root in &instance.roots {
                fallback.evict_node(&root.root);
            }
        }
        state.instances.push(instance);
        state.routes = build_routes(&state.instances, self.fallback.as_ref());
    }

    fn target(&self, url: &Url) -> Result<(GcsRoute, ResolvedTarget)> {
        let route = self
            .state
            .read()
            .routes
            .lookup(url)
            .map(|(_, route)| route.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))?;
        let target = match &route {
            GcsRoute::Connection(instance) => ResolvedTarget {
                backend_id: instance.backend_id.clone(),
                resolved_address: url.clone(),
            },
            GcsRoute::Fallback(fallback) => fallback.resolved_target(url),
        };
        Ok((route, target))
    }

    /// Route `url` to a configured connection, refusing a fallback-served
    /// address before anything else runs. Every mutating slot and
    /// `watch_directory` resolve through here, so the refusal lands before a
    /// witness is taken, a body is touched, or a request is built.
    fn connection_target(&self, url: &Url) -> Result<(Arc<GcsInstance>, ResolvedTarget)> {
        match self.target(url)? {
            (GcsRoute::Connection(instance), target) => Ok((instance, target)),
            (GcsRoute::Fallback(fallback), _) => Err(fallback.mutation_refused(url)),
        }
    }

    /// Route `url` to its instance and run `op` under the connection's
    /// data-path recovery loop, promoting a parked connection if the service
    /// demonstrably accepted one of this operation's own requests. With
    /// `GcsDriver::refresh` unsupported the recovery half degrades to
    /// classify-and-surface, which is correct — OAuth token freshness is owned
    /// by the `Authenticator` internally, not by the set. `op` must be
    /// replayable (no consumed streaming body).
    ///
    /// The evidence is per-operation, so an operation that reaches no request
    /// earns nothing for anyone: a `read` that mints a signed URL sends nothing,
    /// and `watch_directory` contributes nothing in either direction — both its
    /// establishing `get_subscription` and its later pulls run on the Pub/Sub
    /// transport, which is deliberately unwitnessed (see
    /// `subscription::send_with_cancel`), for the same reasons the s3 half
    /// excludes SQS. A watch-only or redirect-only connection therefore stays
    /// parked until some other operation runs. Refusals heard by a CONCURRENT
    /// operation are seen, because those belong to the connection rather than to
    /// an operation.
    ///
    /// A fallback-served address has no connection to park or promote: the
    /// anonymous backend is resolved (minted on first touch) and `op` runs once,
    /// directly. `cancel` bounds that resolution; the operation's own
    /// cancellation is the closure's business, as before.
    async fn recover<T, F, Fut>(
        &self,
        url: &Url,
        cancel: Option<CancellationToken>,
        op: F,
    ) -> Result<T>
    where
        F: Fn(Arc<GcsBackend>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        match self.target(url)? {
            (GcsRoute::Connection(instance), target) => self.recover_on(instance, target, op).await,
            (GcsRoute::Fallback(fallback), _) => {
                let (backend, target) = fallback.backend_for(url, cancel).await?;
                op(backend, target).await
            }
        }
    }

    /// [`Self::recover`] for a mutating slot: a fallback-served address is
    /// refused before the recovery loop is entered.
    async fn recover_mutation<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<GcsBackend>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (instance, target) = self.connection_target(url)?;
        self.recover_on(instance, target, op).await
    }

    /// The connection half of [`Self::recover`]: run `op` under the
    /// connection's recovery loop with a promotion witness around it.
    async fn recover_on<T, F, Fut>(
        &self,
        instance: Arc<GcsInstance>,
        target: ResolvedTarget,
        op: F,
    ) -> Result<T>
    where
        F: Fn(Arc<GcsBackend>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        self.connection_set
            .with_recovery_promoting_if(
                &id,
                || witness.proved(self),
                || witness.scope(op(instance.backend.clone(), target.clone())),
            )
            .await
    }

    /// Whether `instance` is still the installed instance for its connection —
    /// pointer identity, not a routing lookup, so a re-added connection's fresh
    /// instance does not answer for a retired one.
    fn instance_is_installed(&self, instance: &Arc<GcsInstance>) -> bool {
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
impl Layer for GcsLayer {
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
            move |backend, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move { backend.stat(target, options, cancel).await }
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
            move |backend, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move { backend.read(target, options, cancel).await }
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
        // though — a connection whose upload the service answered has proved its
        // credentials as surely as any other operation.
        //
        // A fallback-served address is refused here, before the body is
        // touched and before any witness exists.
        let (instance, target) = self.connection_target(&request.input.address)?;
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
        // Witnessed because on gcs this slot always reaches the service:
        // `GcsBackend::write_redirect` routes every batch through
        // `initiate_resumable_redirect`, which opens the session with a signed
        // request of our own before handing back the upload URL. The bytes then
        // travel on the host's follower, which reports back a status this
        // connection does not count — only the initiate is evidence.
        let (instance, target) = self.connection_target(&request.input.address)?;
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        let options = request.input.options;
        self.connection_set
            .with_promotion_if(
                &id,
                || witness.proved(self),
                witness.scope(async move {
                    instance
                        .backend
                        .write_redirect(target, options, cancel)
                        .await
                }),
            )
            .await
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        // NOT witnessed, unlike the s3 sibling, because `GcsBackend::continue_write`
        // issues no request: the resumable session finalizes on the redirect PUT
        // the HOST performed, and this slot only validates the results the caller
        // hands back. There is nothing for an evidence sink to record, and a
        // witness here would be inert.
        //
        // The 2xx in those results is not a substitute. `results` is
        // caller-supplied and the caller is not always in-process — the broker
        // takes it straight off the wire — so a remote client could report a
        // status it never received and flip an operator's shared connection to
        // `Authenticated` with no request leaving the process. A redirect-only
        // writer stays parked until some other operation reaches the service.
        let (instance, target) = self.connection_target(&request.input.address)?;
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
        self.recover_mutation(&request.input.address, move |backend, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { backend.delete(target, options, cancel).await }
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
        let items = self
            .recover(
                &request.input.prefix,
                cancel.clone(),
                move |backend, target| {
                    let options = backend_options.clone();
                    let cancel = cancel.clone();
                    async move { backend.list(target, options, cancel).await }
                },
            )
            .await?;
        // GCS is a flat namespace: never real directories.
        let items = fold_markers_and_infer_subdir_kinds(&prefix, items, false, recursive);
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
            .recover(&prefix, cancel.clone(), move |backend, target| {
                let options = backend_options.clone();
                let cancel = cancel.clone();
                async move { backend.list_stream(target, options, cancel).await }
            })
            .await?;
        // GCS is flat. Recursive requests are byte-sorted object items; the
        // non-recursive items-then-prefixes order is preserved without a sort
        // check by the mode-conditional incremental fold.
        Ok(cancel_list_stream(
            Box::pin(IncrementalListFold::new(stream, &prefix, false, recursive)),
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
                move |backend, target| {
                    let options = options.clone();
                    let cancel = cancel.clone();
                    async move { backend.list_versions(target, options, cancel).await }
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
            move |backend, target| {
                let cancel = cancel.clone();
                async move { backend.get_latest_version(target, cancel).await }
            },
        )
        .await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        // Establish the change-feed subscription under the recovery loop
        // (establishment is replayable); mid-stream errors surface via the
        // mapped stream. A fallback-served prefix is refused first: a watch is
        // a standing server-side registration, and the anonymous fallback has
        // no identity to hold one.
        let options = request.input.options;
        let stream = self
            .recover_mutation(&request.input.prefix, move |backend, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move { backend.watch_directory(target, options, cancel).await }
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
        self.recover_mutation(&request.input.address, move |backend, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { backend.create_directory(target, options, cancel).await }
        })
        .await
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let options = request.input.options;
        self.recover_mutation(&request.input.address, move |backend, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { backend.delete_directory(target, options, cancel).await }
        })
        .await
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        // Both ends resolve before anything runs: a fallback-served source OR
        // destination is refused here, before any read of the source.
        let (source_instance, source) = self.connection_target(&request.input.source)?;
        let (dest_instance, destination) = self.connection_target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "gcs does not support cross-connection copy",
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
        // Both ends resolve before anything runs: a fallback-served source OR
        // destination is refused here, before any read of the source.
        let (source_instance, source) = self.connection_target(&request.input.source)?;
        let (dest_instance, destination) = self.connection_target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "gcs does not support cross-connection rename",
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
        self.recover_mutation(&request.input.address, move |backend, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { backend.update_metadata(target, options, cancel).await }
        })
        .await
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        // Witnessed like any other slot, unlike the s3 sibling, which suppresses
        // this one's evidence entirely. The difference follows from the veto
        // rules rather than from a different view of what `check_access` is:
        // there, every 403 vetoes, so a permission-checking host provoking one
        // per visible row would keep the connection's refusal epoch moving
        // continuously. Here only a 401 vetoes, and a scoped principal is
        // answered 403 — so the probe's refusals cost a concurrent operation
        // nothing, and its successes are ordinary signed requests the service
        // answered.
        let operations = request.input.operations;
        self.recover(
            &request.input.address,
            cancel.clone(),
            move |backend, target| {
                let operations = operations.clone();
                let cancel = cancel.clone();
                async move { backend.check_access(target, operations, cancel).await }
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
        self.refuse_fallback_keys_on_connection(&req.config)?;
        let config = GcsConnectionConfig::from_request(&req)?;
        self.warn_if_endpoint_is_instance_metadata(&config);
        let is_anonymous =
            Authenticator::new(&req.credentials, build_http_client()?)?.is_anonymous();
        let capabilities = gcs_capabilities(&config);
        let driver = Arc::new(GcsDriver::new(config.clone()));
        let now = SystemTime::now();
        let mut view = Connection {
            id: ConnectionId(fresh_id("gcs")),
            backend_kind: self.descriptor.kind.clone(),
            display_name: req
                .display_name
                .clone()
                .unwrap_or_else(|| format!("Google Cloud Storage: {}", config.bucket)),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities,
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
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
            // Nothing gcs resolves is one-time-consuming; unreachable, but
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
        // GCS credentials are FROZEN at add time: an `Authenticator` is
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
            "gcs credentials are fixed at connection time; remove this connection and \
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
