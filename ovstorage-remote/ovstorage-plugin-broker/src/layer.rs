// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the broker **client** backend.
//!
//! A single [`Layer`] owns its connections and routes addresses to the right
//! backend instance by longest prefix. Connection *lifecycle* (the
//! `ConnectionAuthState` machine, single-flight bring-up, cooldown,
//! background-refresh scheduling, cross-process coalescing, and the
//! data-path recovery loop) is delegated to a generic
//! [`ConnectionSet<BrokerDriver>`]; the layer keeps only the `id → instance`
//! routing handle. Address roots are published by the broker itself (via the
//! transport's `list_address_roots` / `watch_address_roots` RPCs); credential /
//! auth ownership lives in the `ConnectionSet` via the [`BrokerDriver`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::*;
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::DiscoveryState;
use crate::driver::BrokerDriver;
use crate::{BrokerClientBackend, ConnectionAuthBlock, KIND, discovery_url};

/// The `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds
/// the static kind descriptor computed once; every built layer owns its own
/// `ConnectionSet` + longest-prefix route table.
pub struct BrokerClientLayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for BrokerClientLayerFactory {
    fn default() -> Self {
        Self {
            descriptor: broker_descriptor(),
        }
    }
}

/// The broker-client kind descriptor used by the CLI/host UI and
/// `oidc_client_name` selection;
/// projected to a `LayerKindDescriptor` via `descriptor_to_layer_kind`.
pub(crate) fn broker_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: KIND.into(),
        display_name: "ovstorage broker".into(),
        description: Some("Routes storage operations through an ovstorage broker endpoint".into()),
        config_schema: vec![
            ConfigField {
                key: "address".into(),
                display_name: "Broker address".into(),
                kind: ConfigFieldKind::Text,
                required: true,
                default: None,
                help: Some(
                    "Broker address. Accepts: a path (UDS), pipe:NAME (Windows \
                 named pipe), https://host (discovery), http://host (local \
                 dev discovery), grpc[+tls/+tcp]://host:port (direct gRPC), \
                 or bare host[:port] (auto http/https based on locality)."
                        .into(),
                ),
                example: Some("https://broker.example.com".into()),
                group: Some("broker".into()),
                advanced: false,
            },
            ConfigField {
                key: "oidc_client_name".into(),
                display_name: "OIDC client name".into(),
                kind: ConfigFieldKind::Text,
                required: false,
                default: None,
                help: Some(
                    "Selects an entry from the broker's published auth-config \
                 clients. Set this only when a deployment publishes its \
                 auth-config under a non-default key."
                        .into(),
                ),
                example: Some("default".into()),
                group: Some("auth".into()),
                advanced: true,
            },
            ConfigField {
                key: "persistence_id".into(),
                display_name: "Credential persistence ID".into(),
                kind: ConfigFieldKind::Text,
                required: false,
                default: None,
                help: Some(
                    "Durable account discriminator. Give each connection to the same \
                 broker address and OIDC client its own value so each keeps a \
                 separate stored credential; without it, two connections meant \
                 for different accounts share one. Choose it once and keep it: \
                 changing it moves the connection to a fresh credential and \
                 requires signing in again."
                        .into(),
                ),
                example: Some("alice-work".into()),
                group: Some("auth".into()),
                advanced: true,
            },
        ],
        credential_schema: vec![
            CredentialField {
                key: "client_id".into(),
                display_name: "Client ID".into(),
                default: None,
                help: Some(
                    "OIDC client identifier for client-credentials grants \
                     (only valid against discovery addresses)"
                        .into(),
                ),
                advanced: false,
            },
            CredentialField {
                key: "client_secret".into(),
                display_name: "Client secret".into(),
                default: None,
                help: Some("OIDC client secret paired with `client_id`".into()),
                advanced: false,
            },
        ],
        credential_methods: vec![CredentialMethod {
            key: "client_credentials".into(),
            display_name: "OIDC client credentials".into(),
            fields: vec!["client_id".into(), "client_secret".into()],
            help: Some(
                "Only valid when the address is a discovery URL: authenticates \
                     to the IDP with a client ID and secret."
                    .into(),
            ),
            advanced: true,
        }],
        icon: None,
        supports_runtime_add: true,
        supports_user_metadata: true,
    }
}

#[async_trait]
impl BackendFactory for BrokerClientLayerFactory {
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
        let layer = Arc::new_cyclic(|weak| BrokerClientLayer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            instances: RwLock::new(Vec::new()),
            route_table: RwLock::new(RouteTable::empty()),
            route_gen: AtomicU64::new(0),
            root_change_tx,
            cancel: CancellationToken::new(),
            weak_self: weak.clone(),
        });
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
            layer.instances.write().push(instance.clone());
            layer.start_root_watcher(&instance);
        }
        layer.rebuild_routes();
        Ok(layer)
    }
}

pub(crate) struct BrokerClientLayer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    connection_set: Arc<ConnectionSet<BrokerDriver>>,
    instances: RwLock<Vec<Arc<BrokerClientInstance>>>,
    route_table: RwLock<RouteTable<Arc<BrokerClientInstance>>>,
    /// Bumped under `instances.write()` on every add/remove. `rebuild_routes`
    /// snapshots it alongside the instance set and re-checks it under the
    /// `route_table` write lock, discarding a stale build so a preempted
    /// watcher cannot resurrect a removed instance's route.
    route_gen: AtomicU64,
    root_change_tx: broadcast::Sender<RootInfoChange>,
    /// Parent token for every per-instance root watcher; cancelled on `Drop`.
    cancel: CancellationToken,
    weak_self: Weak<BrokerClientLayer>,
}

impl Drop for BrokerClientLayer {
    fn drop(&mut self) {
        self.cancel.cancel();
        // Host teardown without a prior `remove_connection` must still join every
        // instance's root-watcher on this (Drop) thread before the instances —
        // and the plugin cdylib — are dropped, so no watcher thread survives into
        // unload (SIGSEGV). The parent-token cancel above already propagated to
        // each child watcher; cancel each instance token too, then join. A
        // watcher mid-`apply_backend_roots_change` holds a strong layer Arc (its
        // `weak_self` upgrade), so this `Drop` cannot run until it releases — the
        // join here only ever waits on a watcher parked in its select, never one
        // contending for the `instances` lock held across this loop.
        for instance in self.instances.write().drain(..) {
            instance.cancel.cancel();
            if let Some((_, join)) = instance.root_watcher.lock().take() {
                let _ = join.join();
            }
        }
    }
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct BrokerClientInstance {
    connection_id: ConnectionId,
    source: ConnectionSource,
    backend_id: BackendId,
    backend: Arc<BrokerClientBackend>,
    /// Mutable so a background `watch_address_roots` thread can apply
    /// broker-emitted Snapshot/Added/Removed deltas.
    roots: RwLock<Vec<RootInfo>>,
    /// Child of the layer token; cancelled when this instance is removed. Also
    /// the PARENT of each root-watcher's own cancel token, so cancelling it
    /// tears down whichever watcher is currently running.
    cancel: CancellationToken,
    /// The background root-watcher thread, paired with its own cancel token (a
    /// child of `cancel`). `Option` because a reactivated parked connection may
    /// have none running until [`BrokerClientLayer::repopulate_roots`] restarts
    /// it. Dlopen-safe: joined on a host thread by `remove_connection` /
    /// `BrokerClientLayer`'s `Drop` (and on restart by `ensure_root_watcher`) so
    /// the thread leaves plugin code before the cdylib can be unloaded; the
    /// instance `Drop` join is a self-join-safe backstop, not the guarantee.
    root_watcher: Mutex<Option<(CancellationToken, std::thread::JoinHandle<()>)>>,
}

impl Drop for BrokerClientInstance {
    fn drop(&mut self) {
        // Cancel the watcher's lifetime token (propagating to the watcher's
        // child token) so its selects wake. A `tokio::spawn`'d watcher would
        // outlive the cdylib and execute freed code on unload (SIGSEGV); the
        // dedicated thread is instead joined before the plugin `.so` is torn
        // down, mirroring the `watch_directory` bridge's teardown.
        self.cancel.cancel();
        // Backstop only: the dlopen-unload guarantee is the caller-side join in
        // `remove_connection` / `BrokerClientLayer`'s `Drop`, which joins the
        // watcher on a host thread while a strong instance Arc is still held, so
        // the watcher is never the last ref. By the time this runs the handle is
        // normally already taken, so this `take()` yields `None`. Join whatever
        // remains — UNLESS Drop is itself running on the watcher thread (it held
        // the last strong ref via its temporary `Weak` upgrade), where joining
        // our own handle would deadlock (EDEADLK); that self-join skip detaches
        // the thread, which is why this guard alone cannot ensure the invariant —
        // the caller-side join is what does.
        if let Some((_, join)) = self.root_watcher.lock().take()
            && join.thread().id() != std::thread::current().id()
        {
            let _ = join.join();
        }
    }
}

/// Per-connection scaffold built from a [`ConnectionRequest`]: the backend +
/// driver + initial `Connection` view, before any validation. Construction
/// performs no network I/O and no `ConnectionSet` mutation.
struct ConnectionScaffold {
    connection_id: ConnectionId,
    backend_id: BackendId,
    connection: Connection,
    driver: Arc<BrokerDriver>,
    backend: Arc<BrokerClientBackend>,
}

/// Whether a broker address is a DIRECT endpoint — one the channel opens
/// against without fetching a discovery document, and which therefore exposes
/// no OAuth surface. Its credential is whatever bring-up resolves: a
/// `token_file` bearer, or none.
///
/// Defined as the COMPLEMENT of the two discovery schemes, so `grpc://`,
/// `grpc+tcp://`, `grpc+tls://`, `unix:` and `npipe:` are all direct — a REMOTE
/// broker over TLS is direct too, which is why this is not a locality test.
///
/// Being a complement, it also answers `true` for a scheme nobody recognises.
/// That is deliberate rather than incidental — an unrecognised address has no
/// discovery document to fetch, so it has no interactive flow either — but it
/// means this is NOT the same set as the allowlists in
/// `ConnectionAuthBlock::validate_against_address` and `parse_direct_endpoint`,
/// which name their schemes explicitly. An address outside every list, like
/// `foo://host`, is direct here and fails later where the channel is actually
/// opened. The three definitions agree on every scheme the broker supports.
///
/// `BrokerDriver::interactive` answers `Unsupported` for a direct endpoint, so
/// this predicate decides which connections have an interactive flow at all.
fn is_direct_endpoint(broker_url: &str) -> bool {
    !(broker_url.starts_with("http://") || broker_url.starts_with("https://"))
}

impl BrokerClientLayer {
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
        let broker_url = discovery_url(&request.config)?;
        let is_direct = is_direct_endpoint(&broker_url);
        let auth_block = ConnectionAuthBlock::parse(&request.config)?;
        if let Some(block) = auth_block.as_ref() {
            block.validate_against_address(&broker_url)?;
        }
        let token_file = auth_block.as_ref().and_then(|b| b.token_file.clone());
        let client_secret_file = auth_block
            .as_ref()
            .and_then(|b| b.client_secret_file.clone());
        let client_name = request
            .config
            .get("oidc_client_name")
            .and_then(|v| match v {
                ConfigValue::String(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("default")
            .to_string();
        // Durable account discriminator: immutable operator-chosen config that
        // keeps two same-address, same-client connections on separate stored
        // credentials. Absent, the connection relies on the stored identity
        // binding and persistence-key exclusivity.
        let persistence_id = match request.config.get("persistence_id") {
            Some(ConfigValue::String(value)) => {
                ovstorage_plugin::oauth_secret_store::validate_persistence_id(value)?.to_string()
            }
            _ => String::new(),
        };
        let display_name = request
            .display_name
            .clone()
            .unwrap_or_else(|| "broker".to_string());

        // The shared token cell the transport interceptor reads and the driver's
        // grants install into; one http client shared for OIDC grants.
        let http = reqwest::Client::new();
        let state = DiscoveryState::new(client_name);
        let backend = Arc::new(BrokerClientBackend::new(broker_url.clone(), state.clone()));
        let driver = Arc::new(
            BrokerDriver::new(
                broker_url.clone(),
                is_direct,
                token_file,
                client_secret_file,
                state,
                http,
                // Back-reference so the driver's `on_authenticated` hook can
                // repopulate the layer's routing view after a deferred interactive
                // sign-in (a connection parked `AwaitingAuth` at bring-up advertised
                // no roots). `Weak` — the layer owns the `ConnectionSet` that owns
                // the driver, so an `Arc` would be a cycle.
                self.weak_self.clone(),
            )
            .with_persistence_id(&persistence_id),
        );

        let connection_id = ConnectionId(fresh_id(&self.descriptor.kind));
        let backend_id = BackendId(format!("broker:{broker_url}"));
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

    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<BrokerClientInstance>> {
        let ConnectionScaffold {
            connection_id,
            backend_id,
            connection,
            driver,
            backend,
        } = self.build_scaffold(&request, &source)?;
        let auth_state = self
            .connection_set
            .add_connection(connection, driver, request.credentials, cancel.clone())
            .await?;

        // Discover address roots once authenticated (the broker publishes them);
        // parked connections advertise nothing until sign-in.
        let mut root_infos = Vec::new();
        if matches!(
            auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        ) {
            let discovery = race_cancel(cancel.as_ref(), async {
                match backend.list_address_roots().await {
                    Ok(roots) if !roots.is_empty() => Ok(roots),
                    Ok(_) => Err(Error::new(
                        ErrorCode::NotConfigured,
                        "broker did not publish any address roots",
                    )),
                    Err(error) => Err(error),
                }
            })
            .await;
            let roots = match discovery {
                Ok(roots) => roots,
                Err(error) => {
                    // Roll the registration back WITHOUT purging the durable
                    // secret: a transient discovery blip must not erase a
                    // just-rotated refresh token.
                    let _ = self
                        .connection_set
                        .unregister_connection(&connection_id)
                        .await;
                    return Err(error);
                }
            };
            root_infos = roots
                .into_iter()
                .map(|root| self.root_info(root, &connection_id, &source))
                .collect();
            let caps = root_infos
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty);
            let addresses = root_infos.iter().map(|root| root.root.clone()).collect();
            self.connection_set
                .set_addresses(&connection_id, addresses, caps);
        }

        Ok(Arc::new(BrokerClientInstance {
            connection_id,
            source,
            backend_id,
            backend,
            roots: RwLock::new(root_infos),
            cancel: self.cancel.child_token(),
            root_watcher: Mutex::new(None),
        }))
    }

    /// Project a broker-published [`AddressRoot`] onto a routing [`RootInfo`].
    fn root_info(
        &self,
        root: AddressRoot,
        connection_id: &ConnectionId,
        source: &ConnectionSource,
    ) -> RootInfo {
        let route_source = match source {
            ConnectionSource::Static { layer } => RouteSource::Static { layer: *layer },
            _ => RouteSource::ConnectionContributed {
                connection_id: connection_id.clone(),
            },
        };
        RootInfo {
            root: root.address,
            display_name: root.display_name,
            layer_kind: self.descriptor.kind.clone(),
            connection_id: Some(connection_id.clone()),
            owning_target: None,
            capabilities: root.capabilities,
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: true,
            visibility: root.visibility,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: root.user_metadata,
        }
    }

    /// Build a fresh root-watcher handle with its OWN cancel token (a child of
    /// the instance's, so [`Self::ensure_root_watcher`] can stop just this
    /// watcher without disturbing the instance-lifetime token that
    /// `Drop`/`remove_connection` cancel). Does NOT touch `root_watcher`; the
    /// caller stores the returned pair under whatever lock discipline it holds.
    fn spawn_watcher_handle(
        &self,
        instance: &Arc<BrokerClientInstance>,
    ) -> (CancellationToken, std::thread::JoinHandle<()>) {
        let cancel = instance.cancel.child_token();
        let join = spawn_root_watcher(
            self.weak_self.clone(),
            Arc::downgrade(instance),
            instance.backend.discovery_url().to_string(),
            instance.backend.auth_state().clone(),
            instance.connection_id.clone(),
            cancel.clone(),
        );
        (cancel, join)
    }

    /// Start the initial root-watcher for a freshly-built instance whose
    /// `root_watcher` slot is still `None` (right after construction in
    /// `create_backend` / `add_connection`). A single lock acquisition.
    fn start_root_watcher(&self, instance: &Arc<BrokerClientInstance>) {
        *instance.root_watcher.lock() = Some(self.spawn_watcher_handle(instance));
    }

    /// Ensure a LIVE root-watcher exists for `instance`, as ONE atomic critical
    /// section held across the whole check→take→join→respawn under the
    /// `root_watcher` lock.
    ///
    /// A healthy running watcher is left untouched: `repopulate_roots` re-drives
    /// this on EVERY authenticated transition (including each routine background
    /// token refresh), and tearing down + respawning the thread+`Runtime`+
    /// transport+`WatchAddressRoots` stream each time would churn — and drop root
    /// deltas in the window. Only a dead (`is_finished`) or absent handle is
    /// replaced — e.g. a reactivated parked connection whose bearer-less watcher
    /// terminated on its initial failed open — and the finished thread is joined
    /// (immediate: it has already left plugin code, preserving the dlopen-unload
    /// invariant) before the fresh watcher is spawned and stored.
    ///
    /// Holding the lock across the whole section serializes concurrent callers.
    /// `repopulate_roots` is reachable concurrently for ONE instance (the
    /// interactive-`Succeeded` hook runs detached on the host runtime, alongside
    /// the inline refresh/validate hooks and `update_connection_credentials`), and
    /// without one critical section two callers could each spawn a watcher and
    /// overwrite the other's handle un-joined — orphaning a live thread that could
    /// still be unwinding plugin code at cdylib unload (SIGSEGV). One held lock
    /// guarantees at most one watcher exists and every replaced handle is joined.
    /// The watcher never locks `root_watcher` (it touches only `roots` /
    /// `route_table` / `connection_set` via `apply_backend_roots_change`), so
    /// holding the lock across `join()` cannot deadlock — and the join is
    /// immediate regardless, since only a finished handle is ever joined here.
    fn ensure_root_watcher(&self, instance: &Arc<BrokerClientInstance>) {
        let mut slot = instance.root_watcher.lock();
        if slot.as_ref().is_some_and(|(_, join)| !join.is_finished()) {
            return;
        }
        if let Some((cancel, join)) = slot.take() {
            cancel.cancel();
            let _ = join.join();
        }
        *slot = Some(self.spawn_watcher_handle(instance));
    }

    fn apply_backend_roots_change(
        &self,
        instance: &Arc<BrokerClientInstance>,
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
                        .map(|root| self.root_info(root, connection_id, &source))
                        .collect();
                }
                AddressRootsChange::Added(added) => {
                    for root in added {
                        // Node-aware, not `==`. Two spellings of one root are
                        // one root to the router, so an exact comparison here
                        // installs a duplicate and leaves a removal unmatched.
                        if roots
                            .iter()
                            .any(|existing| address::same_node(&existing.root, &root.address))
                        {
                            continue;
                        }
                        roots.push(self.root_info(root, connection_id, &source));
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

    fn rebuild_routes(&self) {
        // Snapshot the instance set and the generation TOGETHER under the
        // `instances` read lock so they cannot tear against a concurrent
        // add/remove (both bump `route_gen` while holding `instances.write()`).
        let (items, snapshot_gen) = {
            let instances = self.instances.read();
            let items: Vec<(RootInfo, Arc<BrokerClientInstance>)> = instances
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
            (items, self.route_gen.load(Ordering::SeqCst))
        };
        // Publish only if no add/remove intervened since the snapshot. A stale
        // build is dropped: the mutator that bumped the generation has already
        // published, or will publish, the authoritative table. The re-read is
        // ordered after the bump via the `route_table` lock (the bumping
        // mutator's own publish release-synchronizes with this acquire).
        let mut route_table = self.route_table.write();
        if self.route_gen.load(Ordering::SeqCst) == snapshot_gen {
            *route_table = RouteTable::build(items);
        }
    }

    fn rebuild_and_notify(&self) {
        self.rebuild_routes();
        let _ = self
            .root_change_tx
            .send(RootInfoChange::Snapshot(self.current_roots()));
    }

    fn route_instance(&self, url: &Url) -> Result<Arc<BrokerClientInstance>> {
        self.route_table
            .read()
            .lookup(url)
            .map(|(_, instance)| instance.clone())
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    fn target(&self, url: &Url) -> Result<(Arc<BrokerClientInstance>, ResolvedTarget)> {
        let instance = self.route_instance(url)?;
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            // `resolved_address` is serialized into every RPC this backend
            // sends, so it is a wire address and not the caller's spelling.
            // Routing reads no userinfo, so a caller may spell a credential on
            // an address whose published root has none; without the strip this
            // process forwards that credential to the upstream broker.
            resolved_address: address::wire_address(url),
        };
        Ok((instance, target))
    }

    /// Route `url` to its instance and run `op` under the connection's
    /// data-path recovery: a driver-classified credential error invalidates the
    /// cached creds, refreshes, and retries `op` **once** before surfacing. `op`
    /// must be replayable (no consumed streaming body).
    async fn recover<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<BrokerClientInstance>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (instance, target) = self.target(url)?;
        let id = instance.connection_id.clone();
        self.connection_set
            .with_recovery(&id, || op(instance.clone(), target.clone()))
            .await
    }

    fn checked_key_id(&self, key: &ConnectionKey) -> Result<ConnectionId> {
        if key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        Ok(key.id.clone())
    }

    fn instance_for_id(&self, id: &ConnectionId) -> Option<Arc<BrokerClientInstance>> {
        self.instances
            .read()
            .iter()
            .find(|instance| &instance.connection_id == id)
            .cloned()
    }

    /// Re-list the broker's address roots for `id`'s instance, republish them
    /// into the routing view, and (re)start its root watcher. Called after any
    /// event that may reveal roots a parked/earlier bring-up couldn't fetch:
    /// a credential rotation ([`Layer::update_connection_credentials`]) and a
    /// deferred interactive sign-in (`BrokerDriver::on_authenticated`).
    ///
    /// A connection parked `AwaitingAuth` at bring-up needs one of them: its
    /// initial root discovery was skipped and its original watcher's
    /// stream-open failed on the empty bearer and terminated, so without a
    /// repopulation the route table stays empty and every object op returns
    /// `NoRoute` until process restart. Both routes are open to a discovery
    /// endpoint: it can sign in, and it can be handed a credential. A direct
    /// endpoint has no flow to sign in with — `BrokerDriver::interactive`
    /// answers `Unsupported` there — so `update_connection_credentials` is its
    /// only route, and in practice its `token_file` one: that is the direct
    /// shape that can be left parked, since a `token_file`-less direct
    /// connection resolves `Anonymous` at bring-up and is rolled back rather
    /// than parked if its root discovery fails. Such a credential update
    /// reaches the hook when it resolves `Authenticated`; the explicit call
    /// below covers the `Anonymous` outcome, which `set_state` commits without
    /// running the hook. A transient listing error is swallowed
    /// (the connection stays authenticated rather than being parked); the next
    /// credential change or a restart retries.
    pub(crate) async fn repopulate_roots(&self, id: &ConnectionId) {
        let Some(instance) = self.instance_for_id(id) else {
            return;
        };
        let roots = match instance.backend.list_address_roots().await {
            Ok(roots) if !roots.is_empty() => roots,
            _ => return,
        };
        let root_infos: Vec<RootInfo> = roots
            .into_iter()
            .map(|root| self.root_info(root, id, &instance.source))
            .collect();
        let caps = root_infos
            .first()
            .map(|root| root.capabilities.clone())
            .unwrap_or_else(Capabilities::empty);
        let addresses = root_infos.iter().map(|root| root.root.clone()).collect();
        *instance.roots.write() = root_infos;
        self.connection_set.set_addresses(id, addresses, caps);
        self.rebuild_and_notify();
        // Ensure a live watcher: a reactivated parked connection's original watcher
        // terminated when its bearer-less open failed and must be respawned so
        // ongoing root deltas arrive; a healthy watcher (the routine-refresh case)
        // is left running rather than torn down and respawned.
        self.ensure_root_watcher(&instance);
    }

    fn current_roots(&self) -> Vec<RootInfo> {
        let mut roots: Vec<RootInfo> = self.route_table.read().roots().cloned().collect();
        roots.sort_by(|left, right| left.root.as_str().cmp(right.root.as_str()));
        roots
    }
}

/// Spawn the background root-watcher on a DEDICATED std::thread with its own
/// tokio `Runtime`, returning the join handle so [`BrokerClientInstance::drop`]
/// can join it before the cdylib unloads. A `tokio::spawn`'d task would run on
/// the HOST runtime and outlive the plugin `.so`, executing freed code on
/// unload (SIGSEGV) — the same reason the `watch_directory` transport bridge
/// uses a joined thread. The watcher opens a FRESH transport on its own runtime
/// (never the shared, host-runtime channel) and streams the broker's
/// `WatchAddressRoots` deltas back into the layer.
fn spawn_root_watcher(
    layer: Weak<BrokerClientLayer>,
    instance: Weak<BrokerClientInstance>,
    discovery_url: String,
    auth_state: DiscoveryState,
    connection_id: ConnectionId,
    cancel: CancellationToken,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("ovs-bc-roots".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            runtime.block_on(async move {
                // Open the watch stream over a fresh transport on THIS runtime;
                // bail promptly if cancelled during connect/discovery.
                let opened = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    opened = async {
                        let transport =
                            crate::transport_for_with_auth(&discovery_url, Some(auth_state)).await?;
                        transport.watch_address_roots().await
                    } => opened,
                };
                let mut stream = match opened {
                    Ok(stream) => stream,
                    Err(error) => {
                        if error.code() != ErrorCode::Unsupported {
                            tracing::warn!(error = %error, "broker: watch_address_roots failed to open");
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
                                let (Some(layer), Some(instance)) =
                                    (layer.upgrade(), instance.upgrade())
                                else {
                                    break;
                                };
                                // Map the wire (protocol) enum onto the SPI enum
                                // — the same translation the backend's
                                // `watch_address_roots` did; both carry
                                // `Vec<AddressRoot>` so this is a plain remap.
                                use ovstorage_broker_protocol::AddressRootsChange as Wire;
                                let change = match change {
                                    Wire::Snapshot(roots) => AddressRootsChange::Snapshot(roots),
                                    Wire::Added(roots) => AddressRootsChange::Added(roots),
                                    Wire::Removed(roots) => AddressRootsChange::Removed(roots),
                                };
                                layer.apply_backend_roots_change(&instance, &connection_id, change);
                            }
                            Some(Err(_)) | None => break,
                        },
                    }
                }
            });
        })
        .expect("failed to spawn thread")
}

#[async_trait]
impl Layer for BrokerClientLayer {
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
        // Writes consume their body / span multiple rounds, so they are NOT run
        // under the retry-once recovery loop; a credential error surfaces to
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
        // The caller's `max_results`/`page_token` ride down inside `options` to
        // the broker, which returns an already server-paginated `ListPage`; pass
        // it straight through. Re-paginating locally (as the fully-materializing
        // backends do) would truncate the page and hide the broker's real
        // `next_page_token`, making pages 2+ unreachable.
        let options = request.input.options;
        self.recover(&request.input.prefix, move |instance, target| {
            let options = options.clone();
            let cancel = cancel.clone();
            async move { instance.backend.list(target, options, cancel).await }
        })
        .await
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
                "broker does not support cross-connection copy",
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
                "broker does not support cross-connection rename",
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
                "broker does not support runtime connections",
            ));
        }
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let req = request.input.connection;
        let source = ConnectionSource::Runtime { persisted: false };
        let ConnectionScaffold {
            connection,
            driver,
            backend,
            ..
        } = self.build_scaffold(&req, &source)?;
        let now = std::time::SystemTime::now();
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
            ProbeOutcome::Rejected { error } => {
                view.auth_state = ConnectionAuthState::AwaitingAuth {
                    reason: AuthReason::NeverAuthenticated,
                    last_attempt: Some(AuthAttempt {
                        at: now,
                        error: Some(error),
                    }),
                };
            }
            ProbeOutcome::Unverifiable => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "probing this credential shape would consume a one-time refresh token; \
                     add the connection instead",
                ));
            }
        }
        view.last_probed = Some(now);
        // LATENT (probe address-fill on an empty live cell; no product callers
        // today): `probe_connection` never touches the shared live token cell —
        // `obtain` grants on a driver-private staging `DiscoveryState` and
        // `verify` probes over an EPHEMERAL transport (see `driver.rs`), so the
        // `state` cell shared with `backend` stays EMPTY (only `activate`
        // installs a proven bearer). This `backend.list_address_roots()` fill
        // then runs over the scaffold transport, whose interceptor reads that
        // empty cell and sends an empty bearer, so on an auth-gated broker the
        // fill would fail. It is unreached because the SPI `probe` verb has no
        // product callers (all routing goes through the internal add/bring-up
        // delegations); if `probe` is ever wired to a host, this discovery must
        // run over an ephemeral transport seeded with the proven bearer (as
        // `verify` does), not the live cell.
        if matches!(
            view.auth_state,
            ConnectionAuthState::Authenticated { .. } | ConnectionAuthState::Anonymous
        ) {
            match backend.list_address_roots().await {
                Ok(roots) if !roots.is_empty() => {
                    view.current_addresses = roots.into_iter().map(|root| root.address).collect();
                }
                Ok(_) => {
                    return Err(Error::new(
                        ErrorCode::NotConfigured,
                        "broker did not publish any address roots",
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
                "broker does not support runtime connections",
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
        {
            let mut instances = self.instances.write();
            instances.push(instance.clone());
            // Fence against a concurrent `rebuild_routes` snapshot (see
            // `route_gen`): bump while holding the write lock so the new
            // instance and the new generation become visible atomically.
            self.route_gen.fetch_add(1, Ordering::SeqCst);
        }
        self.start_root_watcher(&instance);
        self.rebuild_and_notify();
        self.connection_set.connection(&id).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "add_connection did not create a connection",
            )
        })
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        // Subscribe BEFORE snapshotting so a change emitted between the two
        // lands on the stream rather than being lost from both.
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
        let removed = {
            let mut instances = self.instances.write();
            let removed = instances
                .iter()
                .position(|instance| instance.connection_id == key.input.id)
                .map(|index| instances.remove(index));
            if removed.is_some() {
                // Fence against a preempted `rebuild_routes` snapshot (see
                // `route_gen`): bump while still holding the write lock so a
                // stale watcher build cannot resurrect this instance's route.
                self.route_gen.fetch_add(1, Ordering::SeqCst);
            }
            removed
        };
        if let Some(removed) = removed {
            removed.cancel.cancel();
            // Join the watcher on THIS (host) thread before releasing `removed`,
            // so the watcher can never be the last strong ref and self-drop —
            // which would have to detach its own `JoinHandle`, leaving an
            // unjoined thread that survives cdylib unload (SIGSEGV). The
            // cancelled watcher wakes on its biased cancel select, drops its
            // transient Arc, and exits; the join then returns. The `instances`
            // write lock is already released (it lived only in the inner block),
            // and the watcher never locks `root_watcher`, so take()ing the handle
            // here cannot deadlock against it — mirroring the blocking join in
            // `ensure_root_watcher`.
            if let Some((_, join)) = removed.root_watcher.lock().take() {
                let _ = join.join();
            }
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
        // A successful rotation to `Authenticated` runs the driver's
        // `on_authenticated` hook INLINE inside `update_credentials` (ConnectionSet
        // → `BrokerDriver::on_authenticated` → `repopulate_roots`), refreshing the
        // routing view once. Repopulating again here for that case would re-list
        // roots + rebuild redundantly (and restart the watcher a second time) —
        // let the shared hook own it.
        //
        // An `Anonymous` outcome is also a success, but it commits via `set_state`,
        // which does NOT run `on_authenticated`. A connection parked `AwaitingAuth`
        // at bring-up (empty route table, its bearer-less watcher already
        // terminated) whose credentials resolve `Anonymous` would otherwise keep an
        // empty routing view and a dead watcher — every object op `NoRoute` until
        // process restart (the AwaitingAuth-at-bring-up failure mode). Repopulate explicitly for the
        // `Anonymous` branch the hook does not cover.
        let state = self
            .connection_set
            .update_credentials(&id, request.input.credentials, cancel)
            .await?;
        if matches!(state, ConnectionAuthState::Anonymous) {
            self.repopulate_roots(&id).await;
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
        if let Some(address) = ovstorage::wrappers::ext::upstream_auth_address(&request.extensions)?
        {
            let instance = self
                .instance_for_id(&id)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection instance not found"))?;
            let connection = self
                .connection_set
                .connection(&id)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
            let transport = instance.backend.transport().await?;
            return crate::auth::drive_upstream_auth(
                transport.as_ref(),
                address,
                request.input.capability,
                connection,
                cancel,
            )
            .await;
        }
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
mod tests {
    use super::*;
    use ovstorage_broker_protocol::{BrokerClientTransport, BrokerClientWatchDirectoryStream};

    /// Which addresses are direct decides which connections have an interactive
    /// flow at all: `BrokerDriver::interactive` answers `Unsupported` for a
    /// direct endpoint. The distinction is discovery-vs-direct, NOT
    /// local-vs-remote — a remote broker reached over `grpc+tls://` is direct,
    /// because the channel opens against it without fetching a discovery
    /// document and it publishes no auth-config to drive a flow from.
    ///
    /// The predicate is a complement, so it also calls an unrecognised scheme
    /// direct — pinned below, because that is the one case where it and the
    /// scheme allowlists in `lib.rs` disagree, and a reader should see that
    /// answer chosen rather than inferred.
    #[test]
    fn direct_endpoints_are_every_scheme_that_is_not_discovery() {
        for direct in [
            "grpc+tls://broker.example.com:443",
            "grpc+tcp://broker.example.com:50051",
            "grpc://broker.example.com:50051",
            "unix:/run/ovstorage/broker.sock",
            "npipe:/ovstorage-broker",
            // Not a scheme the broker supports. It is direct HERE because this
            // predicate is a complement, and it fails later at
            // `parse_direct_endpoint`. Pinned so that answer is deliberate: it
            // is the one case where this predicate and the two scheme
            // allowlists in `lib.rs` disagree.
            "foo://host",
        ] {
            assert!(
                is_direct_endpoint(direct),
                "{direct} opens directly and has no OAuth surface"
            );
        }
        for discovery in ["http://127.0.0.1:8080/", "https://broker.example.com/"] {
            assert!(
                !is_direct_endpoint(discovery),
                "{discovery} fetches auth-config and can drive a real flow"
            );
        }
    }

    fn test_layer() -> Arc<BrokerClientLayer> {
        let (root_change_tx, _) = broadcast::channel(16);
        Arc::new_cyclic(|weak| BrokerClientLayer {
            name: "broker".to_string(),
            descriptor: broker_descriptor(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            instances: RwLock::new(Vec::new()),
            route_table: RwLock::new(RouteTable::empty()),
            route_gen: AtomicU64::new(0),
            root_change_tx,
            cancel: CancellationToken::new(),
            weak_self: weak.clone(),
        })
    }

    /// A backend whose transport points at an unconnectable endpoint. The
    /// routing/introspection paths under test never dispatch an RPC.
    fn detached_backend() -> Arc<BrokerClientBackend> {
        Arc::new(BrokerClientBackend::new(
            "https://broker.invalid".into(),
            DiscoveryState::new("default"),
        ))
    }

    fn seed(layer: &Arc<BrokerClientLayer>, root: &str, backend_id: &str) {
        seed_with_backend(layer, root, backend_id, detached_backend());
    }

    fn seed_with_backend(
        layer: &Arc<BrokerClientLayer>,
        root: &str,
        backend_id: &str,
        backend: Arc<BrokerClientBackend>,
    ) {
        let root_url = Url::parse(root).unwrap();
        let connection_id = ConnectionId(backend_id.into());
        let info = layer.root_info(
            AddressRoot {
                address: root_url,
                display_name: None,
                backend_kind: KIND.into(),
                connection_id: Some(connection_id.clone()),
                capabilities: Capabilities::empty(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            },
            &connection_id,
            &ConnectionSource::Static {
                layer: ConfigLayer::Programmatic,
            },
        );
        let instance = Arc::new(BrokerClientInstance {
            connection_id,
            source: ConnectionSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            backend_id: BackendId(backend_id.into()),
            backend,
            roots: RwLock::new(vec![info]),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        });
        layer.instances.write().push(instance);
        layer.rebuild_routes();
    }

    #[test]
    fn descriptor_maps_to_backend_layer_kind() {
        let factory = BrokerClientLayerFactory::default();
        let descriptor = BackendFactory::descriptor(&factory);
        assert_eq!(descriptor.kind, KIND);
        assert!(matches!(descriptor.layer_type, LayerType::Backend));
        assert!(descriptor.accepts_connections);
    }

    #[tokio::test]
    async fn empty_layer_routes_nothing() {
        let layer = test_layer();
        let url = Url::parse("broker://host/a").unwrap();
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

    /// A credential the CALLER spelled does not reach the upstream broker.
    ///
    /// The services-client has the identical pass-through and the identical
    /// test; `plugin-http`'s `physical_url` identity arm is where the rule was
    /// written first. Routing reads no userinfo, so a caller may spell a
    /// credential on an address whose published root has none, and
    /// `resolved_address` is serialized verbatim into the upstream broker's
    /// `address` field.
    #[tokio::test]
    async fn a_callers_credential_does_not_reach_the_upstream() {
        let layer = test_layer();
        seed(&layer, "broker://host/team/", "b");

        let (_, target) = layer
            .target(&Url::parse("broker://alice:password@host/team/file.usd").unwrap())
            .expect("routing reads no userinfo, so this matches");
        assert_eq!(
            target.resolved_address.as_str(),
            "broker://host/team/file.usd",
            "the caller's credential must not be forwarded upstream"
        );

        let (_, honest) = layer
            .target(&Url::parse("broker://host/team/file.usd?versionId=7").unwrap())
            .unwrap();
        assert_eq!(
            honest.resolved_address.as_str(),
            "broker://host/team/file.usd?versionId=7"
        );
    }

    #[tokio::test]
    async fn longest_prefix_routing_selects_instance() {
        let layer = test_layer();
        seed(&layer, "broker://host/team/", "b-shallow");
        seed(&layer, "broker://host/team/project/", "b-deep");

        let (_, shallow) = layer
            .target(&Url::parse("broker://host/team/file.usd").unwrap())
            .unwrap();
        assert_eq!(shallow.backend_id, BackendId("b-shallow".into()));

        let (_, deep) = layer
            .target(&Url::parse("broker://host/team/project/file.usd").unwrap())
            .unwrap();
        assert_eq!(deep.backend_id, BackendId("b-deep".into()));

        let miss = layer
            .route_instance(&Url::parse("s3://other/x").unwrap())
            .err()
            .expect("unmatched address has no route");
        assert_eq!(miss.code(), ErrorCode::NoRoute);

        let roots = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        assert_eq!(roots.len(), 2);
    }

    /// Recording transport that models the broker's server-side pagination and
    /// captures each address and capability used to open an upstream-auth stream.
    struct RecordingTransport {
        total: usize,
        auth_requests: Arc<Mutex<Vec<(Url, InteractiveAuthCapability)>>>,
    }

    #[async_trait]
    impl BrokerClientTransport for RecordingTransport {
        async fn list(&self, prefix: Url, options: ListOptions) -> Result<ListPage> {
            let start: usize = options
                .page_token
                .as_deref()
                .map(|t| t.parse().expect("test cursor is a valid index"))
                .unwrap_or(0);
            let max = options
                .max_results
                .map(|n| n as usize)
                .unwrap_or(self.total);
            let end = (start + max).min(self.total);
            let items = (start..end)
                .map(|i| ObjectInfo {
                    address: prefix.join(&format!("obj-{i}")).unwrap(),
                    kind: ObjectKind::File,
                    etag: None,
                    version: None,
                    size: None,
                    mtime: None,
                    checksums: ChecksumSet::default(),
                    effective_permissions: None,
                    system_metadata: None,
                    user_metadata: None,
                    modified_by: None,
                })
                .collect();
            let next_page_token = (end < self.total).then(|| end.to_string());
            Ok(ListPage {
                items,
                next_page_token,
            })
        }

        // These tests dispatch only `list` and `auth_stream`; the rest are unreachable.
        async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
            unreachable!()
        }
        async fn stat(&self, _address: Url, _options: StatOptions) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn read(&self, _address: Url, _options: ReadOptions) -> Result<ReadResult> {
            unreachable!()
        }
        async fn write(
            &self,
            _address: Url,
            _body: Body,
            _options: WriteOptions,
        ) -> Result<WriteStep> {
            unreachable!()
        }
        async fn write_redirect(
            &self,
            _address: Url,
            _options: WriteOptions,
        ) -> Result<WriteRedirectBatch> {
            unreachable!()
        }
        async fn continue_write(
            &self,
            _address: Url,
            _redirects: WriteRedirectBatch,
            _results: RedirectResultBatch,
        ) -> Result<WriteStep> {
            unreachable!()
        }
        async fn delete(&self, _address: Url, _options: DeleteOptions) -> Result<()> {
            unreachable!()
        }
        async fn list_versions(
            &self,
            _address: Url,
            _options: ListVersionsOptions,
        ) -> Result<Vec<ObjectInfo>> {
            unreachable!()
        }
        async fn get_latest_version(&self, _address: Url) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn watch_directory(
            &self,
            _prefix: Url,
            _opts: WatchDirectoryOptions,
        ) -> Result<BrokerClientWatchDirectoryStream> {
            unreachable!()
        }
        async fn create_directory(
            &self,
            _address: Url,
            _options: CreateDirectoryOptions,
        ) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn delete_directory(
            &self,
            _address: Url,
            _options: DeleteDirectoryOptions,
        ) -> Result<()> {
            unreachable!()
        }
        async fn copy(
            &self,
            _source: Url,
            _destination: Url,
            _options: CopyOptions,
        ) -> Result<WriteResult> {
            unreachable!()
        }
        async fn rename(
            &self,
            _source: Url,
            _destination: Url,
            _options: RenameOptions,
        ) -> Result<()> {
            unreachable!()
        }
        async fn update_metadata(
            &self,
            _address: Url,
            _options: UpdateMetadataOptions,
        ) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn check_access(
            &self,
            _address: Url,
            _operations: AccessOps,
        ) -> Result<AccessDecision> {
            unreachable!()
        }

        async fn auth_stream(
            &self,
            address: Url,
            capability: InteractiveAuthCapability,
        ) -> Result<ovstorage_broker_protocol::UpstreamAuthStream> {
            self.auth_requests.lock().push((address, capability));
            Ok(Box::pin(futures::stream::iter([Ok(
                ovstorage_broker_protocol::AuthEventPartial::Succeeded {
                    connection_id: "upstream".into(),
                },
            )])))
        }
    }

    /// Pagination regression: the broker paginates on its own stack, so the layer must
    /// surface the daemon's real `next_page_token` and make pages 2+ reachable.
    /// The pre-fix layer re-ran `paginate_list_items` on the already-server-paged
    /// vector, which — for a first page of exactly `max_results` entries —
    /// reported `next_page_token: None` and stranded the remaining entries.
    #[tokio::test]
    async fn list_surfaces_broker_next_page_token_and_reaches_page_two() {
        let layer = test_layer();
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(RecordingTransport {
            total: 5,
            auth_requests: Arc::new(Mutex::new(Vec::new())),
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        seed_with_backend(&layer, "broker://host/dir/", "b-page", backend);

        let prefix = Url::parse("broker://host/dir/").unwrap();
        let page_of = |token: Option<String>| ListRequest {
            prefix: prefix.clone(),
            options: ListOptions {
                max_results: Some(2),
                page_token: token,
                ..Default::default()
            },
        };

        // Page 1: 2 of 5 entries. The broker reports more, so the layer must
        // surface its continuation token instead of swallowing it.
        let page1 = layer
            .list(Request::new(page_of(None)), None)
            .await
            .expect("page 1 lists");
        assert_eq!(page1.items.len(), 2);
        let token = page1
            .next_page_token
            .expect("broker has 5 > 2 entries, so page 1 carries a continuation token");

        // Page 2 is reachable via that token, and still reports more.
        let page2 = layer
            .list(Request::new(page_of(Some(token))), None)
            .await
            .expect("page 2 lists");
        assert_eq!(page2.items.len(), 2);
        assert!(
            page2.next_page_token.is_some(),
            "entries 4-5 remain, so page 2 must also carry a continuation token"
        );
    }

    #[tokio::test]
    async fn authenticate_routes_upstream_address_and_capability_only_when_present() {
        let layer = test_layer();
        let auth_requests = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(RecordingTransport {
            total: 0,
            auth_requests: auth_requests.clone(),
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        let connection_id = ConnectionId("auth-connection".into());
        seed_with_backend(&layer, "broker://host/team/", &connection_id.0, backend);

        let driver = Arc::new(BrokerDriver::new(
            "unix:/run/ovstorage/broker.sock".into(),
            true,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        ));
        let mut connection = detached_connection();
        connection.id = connection_id.clone();
        layer
            .connection_set
            .add_connection(connection, driver, SecretBundle::default(), None)
            .await
            .expect("test connection registers");

        let authenticate_request = |capability| AuthenticateRequest {
            key: ConnectionKey {
                target: layer.name.clone(),
                id: connection_id.clone(),
            },
            capability,
            auto_open_browser: false,
        };

        // Ordinary connection auth routes to the tier-1 driver. This fixture's
        // driver is a direct endpoint, whose tier-1 answer is the `Unsupported`
        // no-flow refusal — receiving exactly that error (and no recorded
        // transport stream) is what proves the request went to the driver
        // rather than the tier-3 upstream path.
        let error = match layer
            .authenticate_connection(
                Request::new(authenticate_request(InteractiveAuthCapability::Browser)),
                None,
            )
            .await
        {
            Ok(_) => panic!("a direct-endpoint tier-1 driver offers no interactive flow"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(
            error
                .message()
                .contains("no interactive authentication flow")
        );
        assert!(
            auth_requests.lock().is_empty(),
            "an ordinary authenticate request must not open upstream auth"
        );

        let upstream_address = Url::parse("s3://bucket/private/object.usd").unwrap();
        for capability in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
        ] {
            let mut extensions = Extensions::new();
            ovstorage::wrappers::ext::insert_upstream_auth_address(
                &mut extensions,
                &upstream_address,
            );
            let mut upstream = layer
                .authenticate_connection(
                    Request {
                        extensions,
                        input: authenticate_request(capability),
                    },
                    None,
                )
                .await
                .expect("address-bearing auth opens the broker upstream stream");
            let event = upstream.next().expect("one upstream auth event").unwrap();
            match event {
                AuthEvent::Succeeded {
                    connection,
                    credentials,
                } => {
                    assert_eq!(connection.id, connection_id);
                    assert!(
                        credentials.is_none(),
                        "the daemon persists upstream credentials instead of returning them"
                    );
                }
                other => panic!("upstream auth returned an unexpected event: {other:?}"),
            }
        }
        assert_eq!(
            auth_requests.lock().as_slice(),
            &[
                (upstream_address.clone(), InteractiveAuthCapability::None),
                (upstream_address, InteractiveAuthCapability::Headless),
            ]
        );

        let mut malformed = Extensions::new();
        malformed.insert(
            ovstorage::wrappers::ext::UPSTREAM_AUTH_ADDRESS,
            b"not a URL".to_vec(),
        );
        let error = match layer
            .authenticate_connection(
                Request {
                    extensions: malformed,
                    input: authenticate_request(InteractiveAuthCapability::Browser),
                },
                None,
            )
            .await
        {
            Ok(_) => panic!("a malformed upstream address must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert_eq!(
            auth_requests.lock().len(),
            2,
            "a malformed address must fail before opening a transport stream"
        );
    }

    /// A transport modelling an AUTH-ENFORCING broker: its read RPCs require a
    /// bearer. `list_address_roots` returns `AuthRequired` until `authed` flips,
    /// then publishes one root. The anonymous `file_broker_stack` integration
    /// fixture CANNOT reproduce the parked-connection failure — its watcher populates roots even on a
    /// parked (bearer-less) connection — so the gate is modelled here instead.
    struct GatingTransport {
        authed: Arc<std::sync::atomic::AtomicBool>,
        root: Url,
    }

    #[async_trait]
    impl BrokerClientTransport for GatingTransport {
        async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
            if !self.authed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::AuthRequired,
                    "broker: bearer required to list address roots",
                ));
            }
            Ok(vec![AddressRoot {
                address: self.root.clone(),
                display_name: None,
                backend_kind: KIND.into(),
                connection_id: None,
                capabilities: Capabilities::empty(),
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visibility: AddressVisibility::Visible,
                user_metadata: UserMetadata::new(),
            }])
        }

        async fn stat(&self, address: Url, _options: StatOptions) -> Result<ObjectInfo> {
            Ok(ObjectInfo {
                address,
                kind: ObjectKind::File,
                etag: None,
                version: None,
                size: Some(0),
                mtime: None,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            })
        }

        // The parked-connection test only dispatches `list_address_roots` + `stat`; the rest
        // are unreachable.
        async fn list(&self, _prefix: Url, _options: ListOptions) -> Result<ListPage> {
            unreachable!()
        }
        async fn read(&self, _address: Url, _options: ReadOptions) -> Result<ReadResult> {
            unreachable!()
        }
        async fn write(
            &self,
            _address: Url,
            _body: Body,
            _options: WriteOptions,
        ) -> Result<WriteStep> {
            unreachable!()
        }
        async fn write_redirect(
            &self,
            _address: Url,
            _options: WriteOptions,
        ) -> Result<WriteRedirectBatch> {
            unreachable!()
        }
        async fn continue_write(
            &self,
            _address: Url,
            _redirects: WriteRedirectBatch,
            _results: RedirectResultBatch,
        ) -> Result<WriteStep> {
            unreachable!()
        }
        async fn delete(&self, _address: Url, _options: DeleteOptions) -> Result<()> {
            unreachable!()
        }
        async fn list_versions(
            &self,
            _address: Url,
            _options: ListVersionsOptions,
        ) -> Result<Vec<ObjectInfo>> {
            unreachable!()
        }
        async fn get_latest_version(&self, _address: Url) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn watch_directory(
            &self,
            _prefix: Url,
            _opts: WatchDirectoryOptions,
        ) -> Result<BrokerClientWatchDirectoryStream> {
            unreachable!()
        }
        async fn create_directory(
            &self,
            _address: Url,
            _options: CreateDirectoryOptions,
        ) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn delete_directory(
            &self,
            _address: Url,
            _options: DeleteDirectoryOptions,
        ) -> Result<()> {
            unreachable!()
        }
        async fn copy(
            &self,
            _source: Url,
            _destination: Url,
            _options: CopyOptions,
        ) -> Result<WriteResult> {
            unreachable!()
        }
        async fn rename(
            &self,
            _source: Url,
            _destination: Url,
            _options: RenameOptions,
        ) -> Result<()> {
            unreachable!()
        }
        async fn update_metadata(
            &self,
            _address: Url,
            _options: UpdateMetadataOptions,
        ) -> Result<ObjectInfo> {
            unreachable!()
        }
        async fn check_access(
            &self,
            _address: Url,
            _operations: AccessOps,
        ) -> Result<AccessDecision> {
            unreachable!()
        }
    }

    /// Parked-connection regression: a connection parked `AwaitingAuth` at bring-up advertises
    /// no roots, and (against an auth-enforcing broker) its bearer-less root
    /// watcher terminated, so its route table is empty and every object op
    /// returns `NoRoute`. The driver's `on_authenticated` hook — fired by the
    /// `ConnectionSet` on the deferred interactive sign-in — must repopulate the
    /// routes so an object op routes instead of returning `NoRoute`. Pre-fix,
    /// `on_authenticated` was the trait's no-op default and the table stayed
    /// empty until process restart.
    #[tokio::test(flavor = "multi_thread")]
    async fn on_authenticated_repopulates_routes_for_a_parked_connection() {
        use ovstorage_plugin::connection::ConnectionAuthDriver as _;

        let layer = test_layer();
        let root = Url::parse("broker://host/team/").unwrap();
        let authed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(GatingTransport {
            authed: authed.clone(),
            root: root.clone(),
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));

        // A parked connection: registered on the layer with EMPTY roots (its
        // authenticated bring-up never ran), so it contributes no routes.
        let connection_id = ConnectionId("parked-conn".into());
        let instance = Arc::new(BrokerClientInstance {
            connection_id: connection_id.clone(),
            source: ConnectionSource::Runtime { persisted: false },
            backend_id: BackendId("broker:parked".into()),
            backend,
            roots: RwLock::new(Vec::new()),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        });
        layer.instances.write().push(instance);
        layer.rebuild_routes();

        // Precondition: the parked connection routes nothing — an object op
        // fails `NoRoute` (the parked-connection symptom).
        let object = Url::parse("broker://host/team/file.usd").unwrap();
        let before = layer
            .stat(
                Request::new(StatRequest {
                    address: object.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await;
        assert_eq!(
            before.unwrap_err().code(),
            ErrorCode::NoRoute,
            "a parked connection advertises no roots, so the op has no route"
        );

        // Interactive sign-in lands the bearer; the broker now serves roots.
        authed.store(true, std::sync::atomic::Ordering::SeqCst);

        // Drive the hook exactly as the `ConnectionSet` does on the `Succeeded`
        // transition, through a driver holding a `Weak` back to the layer.
        let driver = BrokerDriver::new(
            "https://broker.example.com".into(),
            false,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Arc::downgrade(&layer),
        );
        let mut connection = detached_connection();
        connection.id = connection_id;
        driver
            .on_authenticated(&connection, None)
            .await
            .expect("on_authenticated repopulates without error");

        // The route table is now populated, and the same object op routes.
        let roots = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        assert_eq!(roots.len(), 1, "the broker root is published after sign-in");
        let after = layer
            .stat(
                Request::new(StatRequest {
                    address: object,
                    options: StatOptions::default(),
                }),
                None,
            )
            .await;
        assert!(
            after.is_ok(),
            "the object op routes after sign-in, got {:?}",
            after.err()
        );
    }

    /// A dropping layer (`Weak::upgrade` == None) makes `on_authenticated` a
    /// safe no-op — no panic — rather than an `unwrap` on a dead weak.
    #[tokio::test]
    async fn on_authenticated_is_a_noop_when_the_layer_is_gone() {
        use ovstorage_plugin::connection::ConnectionAuthDriver as _;

        let driver = BrokerDriver::new(
            "https://broker.example.com".into(),
            false,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Weak::new(),
        );
        driver
            .on_authenticated(&detached_connection(), None)
            .await
            .expect("no-op when the layer weak is dead");
    }

    /// Build a live-but-detached instance served by an always-authed
    /// `GatingTransport` (publishes one root), registered on `layer` with an
    /// empty `root_watcher` slot. The backend's discovery URL is unreachable, so
    /// any real watcher this spawns races to exit — fine for the routing/liveness
    /// assertions, which never depend on the watcher streaming.
    fn seed_watchable_instance(
        layer: &Arc<BrokerClientLayer>,
        id: &str,
        root: &Url,
    ) -> Arc<BrokerClientInstance> {
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(GatingTransport {
            authed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            root: root.clone(),
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        let instance = Arc::new(BrokerClientInstance {
            connection_id: ConnectionId(id.into()),
            source: ConnectionSource::Runtime { persisted: false },
            backend_id: BackendId(format!("broker:{id}")),
            backend,
            roots: RwLock::new(Vec::new()),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        });
        layer.instances.write().push(instance.clone());
        layer.rebuild_routes();
        instance
    }

    /// Concurrency regression (Bug 1): two `repopulate_roots` racing on ONE
    /// instance — as the detached interactive-`Succeeded` hook can run alongside
    /// an inline refresh/validate hook — must leave EXACTLY ONE watcher tracked,
    /// with every replaced handle joined. Pre-fix, `restart_root_watcher` took →
    /// released the lock → joined → re-locked to store as three separate critical
    /// sections, so two racers could each spawn a watcher and overwrite the
    /// other's handle un-joined, orphaning a live thread (SIGSEGV on cdylib
    /// unload). The serialized `ensure_root_watcher` holds the lock across the
    /// whole check→take→join→respawn, so this test's `join()` cannot deadlock
    /// (the watcher never locks `root_watcher`) and the slot holds one handle.
    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_repopulate_tracks_exactly_one_joinable_watcher() {
        let layer = test_layer();
        let root = Url::parse("broker://host/team/").unwrap();
        let instance = seed_watchable_instance(&layer, "racy-conn", &root);
        let id = instance.connection_id.clone();

        let (l1, id1) = (layer.clone(), id.clone());
        let (l2, id2) = (layer.clone(), id.clone());
        let t1 = tokio::spawn(async move { l1.repopulate_roots(&id1).await });
        let t2 = tokio::spawn(async move { l2.repopulate_roots(&id2).await });
        t1.await.unwrap();
        t2.await.unwrap();

        // Exactly one watcher is tracked; take + join it. An orphaned second
        // watcher would be untracked (absent here); a deadlock would hang.
        let tracked = instance.root_watcher.lock().take();
        let (cancel, join) = tracked.expect("exactly one watcher is tracked");
        cancel.cancel();
        join.join()
            .expect("the single tracked watcher joins cleanly");
        assert!(
            instance.root_watcher.lock().is_none(),
            "no second (orphan) watcher lingers in the slot"
        );

        // The race still repopulated the routing view.
        assert_eq!(
            layer
                .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap()
                .0
                .roots
                .len(),
            1
        );
    }

    /// Churn regression (Bug 2): `repopulate_roots` runs on EVERY authenticated
    /// transition, including every routine background token refresh. A HEALTHY
    /// running watcher must be left alone — not torn down and respawned each
    /// time. Pre-fix, `restart_root_watcher` unconditionally cancelled + joined +
    /// respawned, churning the thread+`Runtime`+stream and dropping deltas in the
    /// window; `ensure_root_watcher` leaves a live handle in place.
    #[tokio::test(flavor = "multi_thread")]
    async fn repopulate_leaves_a_healthy_watcher_running() {
        let layer = test_layer();
        let root = Url::parse("broker://host/team/").unwrap();
        let instance = seed_watchable_instance(&layer, "healthy-conn", &root);
        let id = instance.connection_id.clone();

        // Model a HEALTHY watcher: a thread parked until its cancel fires, so
        // `is_finished()` stays false (the real network watcher would race to
        // exit against the unreachable endpoint; a parked stand-in makes
        // "healthy" deterministic).
        let watcher_cancel = instance.cancel.child_token();
        let parked = watcher_cancel.clone();
        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("test watcher runtime");
            rt.block_on(parked.cancelled());
        });
        let original_thread = join.thread().id();
        *instance.root_watcher.lock() = Some((watcher_cancel, join));
        assert!(
            !instance
                .root_watcher
                .lock()
                .as_ref()
                .unwrap()
                .1
                .is_finished(),
            "the modelled watcher is running"
        );

        // A routine refresh re-lists roots + rebuilds, but must NOT churn the
        // healthy watcher: the same thread survives, still running.
        layer.repopulate_roots(&id).await;

        {
            let guard = instance.root_watcher.lock();
            let (_, current) = guard.as_ref().expect("a watcher is still tracked");
            assert!(!current.is_finished(), "the watcher is still running");
            assert_eq!(
                current.thread().id(),
                original_thread,
                "repopulate left the healthy watcher untouched (no restart)"
            );
        }

        // Roots were still repopulated for this transition.
        assert_eq!(
            layer
                .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap()
                .0
                .roots
                .len(),
            1
        );
    }

    /// Teardown regression: `remove_connection` must JOIN the
    /// instance's root-watcher on the host thread — not merely cancel it — so the
    /// watcher can never become the last strong ref and self-drop. A self-drop
    /// would have to detach its own `JoinHandle` (skipping the self-join to avoid
    /// EDEADLK), leaving an unjoined thread executing plugin code as the cdylib
    /// unloads (SIGSEGV). After `remove_connection` returns, the watcher thread
    /// has already exited (its `exited` flag is set with no wait here, proving the
    /// join ran inline) and the `root_watcher` slot is emptied.
    #[tokio::test(flavor = "multi_thread")]
    async fn remove_connection_joins_the_root_watcher() {
        let layer = test_layer();
        let root = Url::parse("broker://host/team/").unwrap();
        let instance = seed_watchable_instance(&layer, "removed-conn", &root);
        let id = instance.connection_id.clone();

        // Register the connection in the set so `remove_connection` reaches the
        // instance-teardown path. A direct-endpoint credential-less driver
        // resolves `Anonymous` offline (mirrors the `Anonymous`-branch test).
        let driver = Arc::new(BrokerDriver::new(
            "unix:/run/ovstorage/broker.sock".into(),
            true,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Arc::downgrade(&layer),
        ));
        let mut connection = detached_connection();
        connection.id = id.clone();
        layer
            .connection_set
            .add_connection(connection, driver, SecretBundle::default(), None)
            .await
            .expect("connection registers");

        // Install a HEALTHY watcher: a thread parked on its cancel token (a child
        // of the instance token) that flips `exited` only as it winds down, so
        // `is_finished()` stays false until `remove_connection` cancels + joins.
        // A parked stand-in makes the join deterministic (the real network watcher
        // would race to exit against the unreachable endpoint).
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher_cancel = instance.cancel.child_token();
        let (parked, flag) = (watcher_cancel.clone(), exited.clone());
        let join = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("test watcher runtime");
            rt.block_on(parked.cancelled());
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        *instance.root_watcher.lock() = Some((watcher_cancel, join));
        assert!(
            !instance
                .root_watcher
                .lock()
                .as_ref()
                .unwrap()
                .1
                .is_finished(),
            "the modelled watcher is running before removal"
        );

        // Remove the connection: this must cancel + JOIN the watcher inline.
        layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: layer.name.clone(),
                    id: id.clone(),
                }),
                None,
            )
            .await
            .expect("remove succeeds");

        // The join completed synchronously inside `remove_connection`: the watcher
        // thread has exited (flag set, checked with no wait) and the slot is
        // emptied, so no detached watcher survives into unload.
        assert!(
            exited.load(std::sync::atomic::Ordering::SeqCst),
            "remove_connection joined the watcher before returning (thread exited)"
        );
        assert!(
            instance.root_watcher.lock().is_none(),
            "remove_connection emptied the root_watcher slot"
        );
        assert!(
            !layer
                .instances
                .read()
                .iter()
                .any(|existing| existing.connection_id == id),
            "the connection was removed from the layer"
        );
    }

    /// Parked-connection regression, `Anonymous` branch: a connection parked `AwaitingAuth` at
    /// bring-up (empty routes, its bearer-less watcher already dead) has creds
    /// pushed via `update_connection_credentials`; the broker resolves them
    /// `Obtained::Anonymous` — a SUCCESS that commits through `set_state`, which
    /// (unlike `Authenticated`) does NOT run the `on_authenticated` hook. So the
    /// hook cannot own the repopulate here: `update_connection_credentials` must
    /// re-list the roots + revive the watcher itself for the `Anonymous` outcome,
    /// or every object op returns `NoRoute` until process restart. The
    /// `Authenticated` outcome stays hook-owned (covered by
    /// `on_authenticated_repopulates_routes_for_a_parked_connection`, and NOT
    /// double-restarted — asserted by `repopulate_leaves_a_healthy_watcher_running`).
    /// Pre-fix this branch left the route table empty; the op still `NoRoute`s.
    #[tokio::test(flavor = "multi_thread")]
    async fn update_credentials_anonymous_repopulates_routes_for_a_parked_connection() {
        let layer = test_layer();
        let root = Url::parse("broker://host/team/").unwrap();

        // A live-but-detached instance served by an always-authed transport
        // (publishes one root), registered with EMPTY roots and NO watcher —
        // the state a connection parked `AwaitingAuth` at bring-up leaves behind
        // (its bearer-less watcher terminated when its empty-bearer open failed).
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(GatingTransport {
            authed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            root: root.clone(),
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        let connection_id = ConnectionId("anon-parked".into());
        let instance = Arc::new(BrokerClientInstance {
            connection_id: connection_id.clone(),
            source: ConnectionSource::Runtime { persisted: false },
            backend_id: BackendId("broker:anon-parked".into()),
            backend,
            roots: RwLock::new(Vec::new()),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        });
        layer.instances.write().push(instance.clone());
        layer.rebuild_routes();

        // Register the connection in the set behind a DIRECT-endpoint driver with
        // no token file: its `obtain` resolves `Obtained::Anonymous` offline, so
        // the credential update below commits `Anonymous` via `set_state` (never
        // the `on_authenticated` hook).
        let driver = Arc::new(BrokerDriver::new(
            "unix:/run/ovstorage/broker.sock".into(),
            true,
            None,
            None,
            DiscoveryState::new("default"),
            reqwest::Client::new(),
            Arc::downgrade(&layer),
        ));
        let mut connection = detached_connection();
        connection.id = connection_id.clone();
        let added = layer
            .connection_set
            .add_connection(connection, driver, SecretBundle::default(), None)
            .await
            .expect("anonymous connection registers");
        assert!(
            matches!(added, ConnectionAuthState::Anonymous),
            "the direct-endpoint credential-less connection is anonymous"
        );

        // Precondition: the parked instance routes nothing, with no live watcher.
        let object = Url::parse("broker://host/team/file.usd").unwrap();
        let before = layer
            .stat(
                Request::new(StatRequest {
                    address: object.clone(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await;
        assert_eq!(
            before.unwrap_err().code(),
            ErrorCode::NoRoute,
            "a parked connection advertises no roots, so the op has no route"
        );
        assert!(
            instance.root_watcher.lock().is_none(),
            "the parked bring-up left no live watcher"
        );

        // Push credentials that resolve `Anonymous`. `update_credentials` returns
        // `Anonymous` (not `Authenticated`), so the `on_authenticated` hook never
        // fires — `update_connection_credentials` owns the repopulate.
        layer
            .update_connection_credentials(
                Request::new(UpdateConnectionCredentialsRequest {
                    key: ConnectionKey {
                        target: layer.name.clone(),
                        id: connection_id.clone(),
                    },
                    credentials: SecretBundle::default(),
                }),
                None,
            )
            .await
            .expect("anonymous credential update succeeds");

        // The route table is now populated and the same object op routes.
        assert_eq!(
            layer
                .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap()
                .0
                .roots
                .len(),
            1,
            "the Anonymous update republished the broker root"
        );
        let after = layer
            .stat(
                Request::new(StatRequest {
                    address: object,
                    options: StatOptions::default(),
                }),
                None,
            )
            .await;
        assert!(
            after.is_ok(),
            "the object op routes after the Anonymous update, got {:?}",
            after.err()
        );

        // A watcher populates the empty slot. Its stream opens
        // over a fresh transport against the unreachable discovery URL and races
        // to exit, so assert only that ONE is tracked, then cancel + join it to
        // avoid leaving an orphan thread behind.
        let tracked = instance.root_watcher.lock().take();
        let (cancel, join) = tracked.expect("the Anonymous update revived the watcher");
        cancel.cancel();
        join.join().expect("the revived watcher joins cleanly");
    }

    /// A `Connection` view with a parked auth state, for the hook tests.
    fn detached_connection() -> Connection {
        Connection {
            id: ConnectionId("c1".into()),
            backend_kind: KIND.into(),
            display_name: "broker".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
        }
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
    /// forwards `WriteOptions` verbatim upstream, which is what preserves the
    /// original principal across a broker chain.
    #[test]
    fn broker_declares_its_user_metadata_support() {
        let descriptor = broker_descriptor();
        assert_eq!(descriptor.kind, "broker");
        assert!(
            descriptor.supports_user_metadata,
            "broker's user-metadata declaration changed; a host composes its \
             attribution layer from it"
        );
    }
}
