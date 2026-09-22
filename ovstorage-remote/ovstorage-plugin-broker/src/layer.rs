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

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::subscription::{AckHandle, AckingStream, UpstreamFactory, WatchCoalescer};
use ovstorage_plugin::*;
use parking_lot::{Mutex, RwLock};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::DiscoveryState;
use crate::driver::BrokerDriver;
use crate::{BrokerClientBackend, ConnectionAuthBlock, KIND, discovery_url};

const MIN_BROKER_WATCH_CADENCE: Duration = Duration::from_millis(1);

/// Maximum number of entries retained from one broker `List` response while
/// adapting the unary cursor protocol to [`Layer::list_stream`].
const BROKER_LIST_STREAM_PAGE_SIZE: u32 = 1_000;

/// Number of recently followed broker cursors retained to catch pagination
/// cycles without growing stream residency with the number of pages consumed.
const BROKER_LIST_STREAM_TOKEN_WINDOW: usize = 32;

/// Normalize a logical subscriber's cadence before the coalescer negotiates
/// the opening cohort. Values below one millisecond, including zero, are
/// floored to the broker wire's resolution.
fn effective_broker_watch_cadence(requested: Duration) -> Duration {
    requested.max(MIN_BROKER_WATCH_CADENCE)
}

/// The root the fallback refusal names for `url`: its origin with userinfo,
/// path, query and fragment removed (`s3://bucket/`, `azure://account/`).
///
/// A backend layer names the node root it derives for the address
/// (`azure://account/container/`), but this client routes for every scheme the
/// broker serves and knows none of their node shapes, so the origin is the
/// deepest ancestor it can name. The path and query are the caller's and are
/// not this layer's to print; the userinfo is a credential and must not reach
/// an error message. The userinfo setters fail only for a URL with no host,
/// which reaches the fallback as a first-tier hit under the scheme root
/// itself, so the refusal then names that root and nothing is lost.
fn fallback_node_root(url: &Url) -> Url {
    let mut root = url.clone();
    let _ = root.set_username("");
    let _ = root.set_password(None);
    root.set_path("/");
    root.set_query(None);
    root.set_fragment(None);
    root
}

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
        // The layer table carries two unrelated things: the optional static
        // connection (`address`, auth, ...) and the operator's fallback grant.
        // Split before the seed check so a table holding only the grant is
        // not read as a connection with no address.
        let (policy, connection) = fallback::split_anonymous_fallback_keys(config);
        // The brokered client reads one fallback key: the grant. Any other
        // `anonymous_fallback_*` key here is a misplaced tunable or the
        // broker's top-level `anonymous_fallback_schemes`; refuse it by name
        // so it cannot sit inert while the operator believes it took effect,
        // as the s3/gcs/azure factories do.
        if let Some(key) = policy
            .keys()
            .find(|key| key.as_str() != fallback::ANONYMOUS_FALLBACK_KEY)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{key}` on layer `{name}` is not a key the broker layer reads; its only \
                     fallback key is `{}` (`anonymous_fallback_schemes` is a host top-level \
                     key, not a layer key)",
                    fallback::ANONYMOUS_FALLBACK_KEY
                ),
            ));
        }
        let anonymous_fallback = fallback::decode_anonymous_fallback(&policy)?;
        // The grant decodes against the closed scheme set, which includes the
        // http tier so its switch parses. Every host refuses to grant that
        // tier this release; the client refuses the same grant with the same
        // words, so it cannot honour a wire-advertised http root that no host
        // is permitted to publish.
        if let Some(scheme) = anonymous_fallback.iter().find(|scheme| {
            !fallback::ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES.contains(&scheme.as_str())
        }) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{}` on layer `{name}` grants `{scheme}`: http anonymous fallback is not \
                     available in this release; grant only {}",
                    fallback::ANONYMOUS_FALLBACK_KEY,
                    fallback::ANONYMOUS_FALLBACK_AVAILABLE_SCHEMES.join(", ")
                ),
            ));
        }
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
            anonymous_fallback,
        });
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
    /// Schemes whose wire-advertised scheme fallback root this process
    /// honours. A broker may advertise a marked `s3:///` root, but the client
    /// operator, not the broker's, decides whether this process treats that
    /// broker as its catch-all for `s3://`: an advertised root outside this
    /// set is dropped at ingestion, so without a local grant the client fails
    /// closed to the same `NoRoute` an unmarked table gives.
    anonymous_fallback: BTreeSet<String>,
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
    /// One generation-scoped coalescing registry per broker connection.
    /// Identity-changing credential writes cancel and replace the registry so a
    /// new principal can never attach to a stream authorized for its predecessor.
    watch_coalescer: Mutex<IdentityWatchCoalescer>,
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

struct IdentityWatchCoalescer {
    identity_generation: u64,
    coalescer: Arc<WatchCoalescer>,
}

impl IdentityWatchCoalescer {
    fn new(identity_generation: u64) -> Self {
        Self {
            identity_generation,
            coalescer: WatchCoalescer::new(),
        }
    }
}

impl BrokerClientInstance {
    /// Return the registry for the live credential identity. The generation is
    /// part of the opaque key as a second fence, while replacing the registry
    /// actively terminates streams authorized for the previous identity.
    fn coalescer_for_current_identity(&self) -> (u64, Arc<WatchCoalescer>) {
        let identity_generation = self.backend.auth_state().identity_generation();
        let mut state = self.watch_coalescer.lock();
        if state.identity_generation != identity_generation {
            state.coalescer.cancel_all();
            *state = IdentityWatchCoalescer::new(identity_generation);
        }
        (identity_generation, state.coalescer.clone())
    }

    fn synchronize_watch_identity(&self) {
        let _ = self.coalescer_for_current_identity();
    }
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
    #[cfg(feature = "_test_support")]
    pub(crate) async fn new_for_tests(
        transport: Arc<dyn ovstorage_broker_protocol::BrokerClientTransport>,
        auth_state: DiscoveryState,
        token_file: Option<String>,
    ) -> Result<LayerHandle> {
        let (root_change_tx, _) = broadcast::channel(16);
        let layer = Arc::new_cyclic(|weak| BrokerClientLayer {
            name: "broker".to_string(),
            descriptor: broker_descriptor(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            instances: RwLock::new(Vec::new()),
            route_table: RwLock::new(RouteTable::empty()),
            route_gen: AtomicU64::new(0),
            root_change_tx,
            cancel: CancellationToken::new(),
            weak_self: weak.clone(),
            anonymous_fallback: BTreeSet::new(),
        });

        let roots = transport.list_address_roots().await?;
        let connection_id = ConnectionId("broker-test-connection".into());
        let source = ConnectionSource::Static {
            layer: ConfigLayer::Programmatic,
        };
        let root_infos: Vec<_> = roots
            .into_iter()
            .filter_map(|root| layer.ingest_root(root, &connection_id, &source))
            .collect();
        // Keep the synthetic routed instance in the real lifecycle registry so
        // integration tests can exercise remove/credential-update through the
        // public Layer verbs instead of reaching into private cancellation
        // state. A unique direct endpoint keeps grant resolution offline; the
        // optional token file exercises authenticated replacement while the
        // injected transport supplies its acceptance probe.
        let driver = Arc::new(
            BrokerDriver::new(
                format!("unix:/{}", fresh_id("broker-test")),
                true,
                token_file,
                None,
                auth_state.clone(),
                reqwest::Client::new(),
                Arc::downgrade(&layer),
            )
            .with_test_verify_transport(transport.clone()),
        );
        let connection = Connection {
            id: connection_id.clone(),
            backend_kind: KIND.into(),
            display_name: "broker test connection".into(),
            source: source.clone(),
            capabilities: root_infos
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty),
            current_addresses: root_infos.iter().map(|root| root.root.clone()).collect(),
            auth_state: ConnectionAuthState::AwaitingAuth {
                reason: AuthReason::NeverAuthenticated,
                last_attempt: None,
            },
            last_probed: None,
            user_metadata: UserMetadata::new(),
            // Same rule as the production path: this layer answers connection
            // ops keyed on its own name, so that name is what reaches this row.
            owning_target: Some(layer.name.clone()),
        };
        layer
            .connection_set
            .add_connection(connection, driver, SecretBundle::default(), None)
            .await?;
        let backend = Arc::new(BrokerClientBackend::new_for_tests_with_auth_state(
            "https://broker.example.test",
            transport,
            auth_state,
        ));
        let identity_generation = backend.auth_state().identity_generation();
        layer.instances.write().push(Arc::new(BrokerClientInstance {
            connection_id,
            source,
            backend_id: BackendId("broker:test".into()),
            backend,
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(identity_generation)),
            roots: RwLock::new(root_infos),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        }));
        layer.rebuild_routes();
        Ok(layer)
    }

    /// Refuse a connection request that carries a fallback layer key. Such a
    /// key on a connection would be ignored silently otherwise, and the
    /// operator would believe the grant took effect. The static seed never
    /// trips this: `create_backend` splits the policy keys off before it
    /// builds the connection.
    fn refuse_fallback_keys(&self, config: &LayerConfig) -> Result<()> {
        if let Some(key) = config
            .keys()
            .find(|key| fallback::is_anonymous_fallback_key(key))
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
        self.refuse_fallback_keys(&request.config)?;
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
            // This layer answers connection ops keyed on its own name, so that
            // name is what reaches this row -- stamped whether or not
            // `owned_targets` currently publishes it. Those two answer different
            // questions: `owned_targets` is gated on `supports_runtime_add` and
            // says which targets the graph will route to, while this says which
            // target addresses this row. A row naming a target the Router does
            // not route is a diagnosable condition, not a reason to report no
            // owner at all.
            owning_target: Some(self.name.clone()),
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
                .filter_map(|root| self.ingest_root(root, &connection_id, &source))
                .collect();
            let caps = root_infos
                .first()
                .map(|root| root.capabilities.clone())
                .unwrap_or_else(Capabilities::empty);
            let addresses = root_infos.iter().map(|root| root.root.clone()).collect();
            self.connection_set
                .set_addresses(&connection_id, addresses, caps);
        }

        let identity_generation = backend.auth_state().identity_generation();
        Ok(Arc::new(BrokerClientInstance {
            connection_id,
            source,
            backend_id,
            backend,
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(identity_generation)),
            roots: RwLock::new(root_infos),
            cancel: self.cancel.child_token(),
            root_watcher: Mutex::new(None),
        }))
    }

    /// Whether a broker-published root, projected onto its routing
    /// [`RootInfo`], may enter the client's routing view. Suppressed roots
    /// stay fail-closed even if received from the wire. A scheme fallback
    /// root — the marked hostless root the shared route table consults once
    /// every prefix misses — enters only when the local operator granted its
    /// scheme: the broker's operator can advertise the root, but only this
    /// process's operator decides whether an unrouted `s3://` address here is
    /// sent to that broker, and without a grant the client fails closed. The
    /// test runs on the projection rather than the wire shape so it is the
    /// same predicate the route table applies when it registers the tier.
    fn should_ingest_root(&self, root: &RootInfo) -> bool {
        if root.visibility == AddressVisibility::Suppressed {
            return false;
        }
        if !fallback::is_scheme_fallback_root(root) {
            return true;
        }
        let granted = self.anonymous_fallback.contains(root.root.scheme());
        if !granted {
            tracing::debug!(
                scheme = root.root.scheme(),
                root = %origin_only(&root.root),
                "broker advertised a scheme fallback root without a local grant; dropping it"
            );
        }
        granted
    }

    /// Project a broker-published [`AddressRoot`] onto a routing [`RootInfo`]
    /// and admit it through [`Self::should_ingest_root`]; `None` is a root
    /// this client refuses to route.
    fn ingest_root(
        &self,
        root: AddressRoot,
        connection_id: &ConnectionId,
        source: &ConnectionSource,
    ) -> Option<RootInfo> {
        let info = self.root_info(root, connection_id, source);
        self.should_ingest_root(&info).then_some(info)
    }

    /// Project a broker-published [`AddressRoot`] onto a routing [`RootInfo`].
    ///
    /// A scheme fallback root leaves here read-only whatever the wire
    /// asserted. The broker publishes the root with the capabilities its own
    /// layer advertises, but this client does not trust the wire to have
    /// lowered them: a fallback root that advertises `write` or `delete` lets
    /// a local caller start a mutation the broker refuses only after the round
    /// trip, and hands a host consulting the root before it acts a promise
    /// nobody keeps. Lowering at projection is what makes the brokered client
    /// hold the invariant every backend layer states through
    /// `scheme_fallback_root`: a fallback root never advertises a mutation.
    fn root_info(
        &self,
        mut root: AddressRoot,
        connection_id: &ConnectionId,
        source: &ConnectionSource,
    ) -> RootInfo {
        let route_source = match source {
            ConnectionSource::Static { layer } => RouteSource::Static { layer: *layer },
            _ => RouteSource::ConnectionContributed {
                connection_id: connection_id.clone(),
            },
        };
        // The broker wire exposes only unary List. This adapter bounds client
        // residency by walking its cursor, but every page still enters the
        // daemon's buffered Layer::list. An upstream layer whose cursor is an
        // offset over a whole-prefix materialization can therefore repeat
        // enumeration and folding once per client page. Advertise the bit
        // because the adapter supplies bounded client residency and
        // cancellation; it does not promise bounded server work.
        root.capabilities.supports_list_stream = root.capabilities.supports_list;
        let mut info = RootInfo {
            root: root.address,
            display_name: root.display_name,
            layer_kind: self.descriptor.kind.clone(),
            connection_id: Some(connection_id.clone()),
            owning_target: None,
            capabilities: root.capabilities,
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: root.visibility == AddressVisibility::Visible,
            visibility: root.visibility,
            alias_state: None,
            icon: self.descriptor.icon.clone(),
            user_metadata: root.user_metadata,
        };
        // Judged on the projection, as `should_ingest_root` judges admission,
        // so the root that is lowered is exactly the root the route table's
        // second tier registers. `read_only_capabilities` keeps
        // `supports_list_stream` as passed, so the list-stream rule above
        // survives the lowering.
        if fallback::is_scheme_fallback_root(&info) {
            info.capabilities = fallback::read_only_capabilities(info.capabilities);
        }
        info
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
                        .filter_map(|root| self.ingest_root(root, connection_id, &source))
                        .collect();
                }
                AddressRootsChange::Added(added) => {
                    for root in added {
                        let Some(root) = self.ingest_root(root, connection_id, &source) else {
                            continue;
                        };
                        // Node-aware, not `==`. Two spellings of one root are
                        // one root to the router, so an exact comparison here
                        // installs a duplicate and leaves a removal unmatched.
                        if roots
                            .iter()
                            .any(|existing| address::same_node(&existing.root, &root.root))
                        {
                            continue;
                        }
                        roots.push(root);
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

    fn route(&self, url: &Url) -> Result<(RootInfo, Arc<BrokerClientInstance>)> {
        self.route_table
            .read()
            .lookup(url)
            .map(|(root, instance)| (root.clone(), instance.clone()))
            .ok_or_else(|| Error::new(ErrorCode::NoRoute, "no route matches address"))
    }

    fn target(&self, url: &Url) -> Result<(Arc<BrokerClientInstance>, ResolvedTarget)> {
        let (_, instance, target) = self.route_target(url)?;
        Ok((instance, target))
    }

    /// [`Self::target`] for a slot that mutates or watches; see
    /// [`Self::mutation_route_target`] for the refusal it adds.
    fn mutation_target(&self, url: &Url) -> Result<(Arc<BrokerClientInstance>, ResolvedTarget)> {
        let (_, instance, target) = self.mutation_route_target(url)?;
        Ok((instance, target))
    }

    /// [`Self::route_target`] for a slot that mutates or watches. The lookup is
    /// the same; the answer is refused when the root that matched is an
    /// ingested scheme fallback root. That root is anonymous and read-only by
    /// contract and the broker refuses the same operation on arrival, so
    /// refusing here trades a round trip that would fail for the error the
    /// cloud layers return for the same address, before any body is buffered,
    /// any continuation decoded or any request sent.
    fn mutation_route_target(
        &self,
        url: &Url,
    ) -> Result<(RootInfo, Arc<BrokerClientInstance>, ResolvedTarget)> {
        let routed = self.route_target(url)?;
        if fallback::is_scheme_fallback_root(&routed.0) {
            return Err(fallback::fallback_mutation_refused(
                url.scheme(),
                &fallback_node_root(url),
            ));
        }
        Ok(routed)
    }

    fn route_target(
        &self,
        url: &Url,
    ) -> Result<(RootInfo, Arc<BrokerClientInstance>, ResolvedTarget)> {
        let (root, instance) = self.route(url)?;
        let target = ResolvedTarget {
            backend_id: instance.backend_id.clone(),
            // `resolved_address` is serialized into every RPC this backend
            // sends, so it is a wire address and not the caller's spelling.
            // Routing reads no userinfo, so a caller may spell a credential on
            // an address whose published root has none; without the strip this
            // process forwards that credential to the upstream broker.
            resolved_address: address::wire_address(url),
        };
        Ok((root, instance, target))
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
        self.recover_with_route(url, move |instance, target, _| op(instance, target))
            .await
    }

    /// [`Self::recover`] for a slot that mutates: the route is taken through
    /// [`Self::mutation_route_target`], so an address the scheme fallback
    /// answers is refused before the recovery loop runs.
    async fn recover_mutation<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<BrokerClientInstance>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.recover_mutation_with_route(url, move |instance, target, _| op(instance, target))
            .await
    }

    /// Recovery variant for operations that need facts from the exact root
    /// selected by the route table. This keeps capability selection and dispatch
    /// on one longest-prefix/FIFO decision.
    async fn recover_with_route<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<BrokerClientInstance>, ResolvedTarget, RootInfo) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.run_routed(self.route_target(url)?, op).await
    }

    /// [`Self::recover_with_route`] for a slot that mutates or watches, routed
    /// through [`Self::mutation_route_target`].
    async fn recover_mutation_with_route<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<BrokerClientInstance>, ResolvedTarget, RootInfo) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.run_routed(self.mutation_route_target(url)?, op).await
    }

    /// Run `op` against an already routed `(root, instance, target)` under the
    /// connection's data-path recovery. The one body behind every `recover*`
    /// wrapper, so the retry-once contract is stated in one place.
    async fn run_routed<T, F, Fut>(
        &self,
        (root, instance, target): (RootInfo, Arc<BrokerClientInstance>, ResolvedTarget),
        op: F,
    ) -> Result<T>
    where
        F: Fn(Arc<BrokerClientInstance>, ResolvedTarget, RootInfo) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let id = instance.connection_id.clone();
        self.connection_set
            .with_recovery(&id, || op(instance.clone(), target.clone(), root.clone()))
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
        // `on_authenticated` reaches this path after both explicit credential
        // replacement and interactive sign-in. Cancel streams authorized under
        // the old identity before doing any discovery I/O for the new one.
        instance.synchronize_watch_identity();
        let roots = match instance.backend.list_address_roots().await {
            Ok(roots) if !roots.is_empty() => roots,
            _ => return,
        };
        let root_infos: Vec<RootInfo> = roots
            .into_iter()
            .filter_map(|root| self.ingest_root(root, id, &instance.source))
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
        // the caller. A fallback-routed address is refused here, before the
        // body is touched.
        let (instance, target) = self.mutation_target(&request.input.address)?;
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
        let (instance, target) = self.mutation_target(&request.input.address)?;
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
        let (instance, target) = self.mutation_target(&request.input.address)?;
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
        self.recover_mutation(&request.input.address, move |instance, target| {
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

    async fn list_stream(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListStream> {
        if request.input.options.max_results.is_some() || request.input.options.page_token.is_some()
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }

        // Make a token cancelled before open observable before routing or an
        // RPC is attempted. The same token remains captured by the stream and
        // is checked between entries and between pages below.
        race_cancel(cancel.as_ref(), async { Ok(()) }).await?;
        let (instance, target) = self.target(&request.input.prefix)?;
        let mut options = request.input.options;
        options.max_results = Some(BROKER_LIST_STREAM_PAGE_SIZE);

        Ok(Box::pin(async_stream::stream! {
            // A cursor is retained before it becomes the next request's input,
            // so the window always includes the cursor used for the current
            // request. The fixed bound keeps arbitrarily long walks bounded.
            let mut recent_tokens = VecDeque::with_capacity(BROKER_LIST_STREAM_TOKEN_WINDOW);
            loop {
                if cancel
                    .as_ref()
                    .is_some_and(CancellationToken::is_cancelled)
                {
                    yield Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
                    break;
                }

                let page = match instance
                    .backend
                    .list(target.clone(), options.clone(), cancel.clone())
                    .await
                {
                    Ok(page) => page,
                    Err(error) => {
                        // `BrokerClientBackend::list` already preserves the
                        // transport error mapping; stream it unchanged.
                        yield Err(error);
                        break;
                    }
                };

                let ListPage {
                    items,
                    next_page_token,
                } = page;
                for item in items {
                    if cancel
                        .as_ref()
                        .is_some_and(CancellationToken::is_cancelled)
                    {
                        yield Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
                        return;
                    }
                    yield Ok(item);
                }
                if cancel
                    .as_ref()
                    .is_some_and(CancellationToken::is_cancelled)
                {
                    yield Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
                    break;
                }

                match next_page_token {
                    Some(next_page_token) => {
                        let no_progress = options.page_token.as_deref()
                            == Some(next_page_token.as_str());
                        let recent_cycle = recent_tokens
                            .iter()
                            .any(|token| token == &next_page_token);
                        if no_progress || recent_cycle {
                            yield Err(Error::new(
                                ErrorCode::Transient,
                                "the broker reissued a continuation token it had already handed \
                                 back, so the listing cannot be advanced",
                            ));
                            break;
                        }
                        if recent_tokens.len() == BROKER_LIST_STREAM_TOKEN_WINDOW {
                            recent_tokens.pop_front();
                        }
                        recent_tokens.push_back(next_page_token.clone());
                        options.page_token = Some(next_page_token);
                    }
                    None => break,
                }
            }
        }))
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
            .recover_mutation_with_route(&request.input.prefix, move |instance, target, root| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move {
                    let (identity_generation, coalescer) =
                        instance.coalescer_for_current_identity();
                    if root.capabilities.watch_directory_resumable {
                        return instance
                            .backend
                            .watch_directory(target, options, cancel)
                            .await;
                    }

                    let prefix = target.resolved_address.clone();
                    let key = format!("{identity_generation}\0{}", prefix.as_str());
                    let effective_cadence = effective_broker_watch_cadence(options.poll_interval);
                    let backend = instance.backend.clone();
                    let upstream: UpstreamFactory = Arc::new(move |cancel, cadence| {
                        let backend = backend.clone();
                        let target = target.clone();
                        Box::pin(async move {
                            let stream = backend
                                .watch_directory(
                                    target,
                                    WatchDirectoryOptions {
                                        recursive: true,
                                        include_metadata_changes: true,
                                        since: None,
                                        poll_interval: cadence,
                                    },
                                    Some(cancel),
                                )
                                .await?;
                            if backend.auth_state().identity_generation() != identity_generation {
                                return Err(Error::new(
                                    ErrorCode::Cancelled,
                                    "broker watch identity changed during upstream open",
                                ));
                            }
                            let auth_state = backend.auth_state().clone();
                            let acking: AckingStream = Box::new(stream.map(move |event| {
                                if auth_state.identity_generation() != identity_generation {
                                    return Err(Error::new(
                                        ErrorCode::Cancelled,
                                        "broker watch identity changed during delivery",
                                    ));
                                }
                                event.map(|event| {
                                    let ack: AckHandle = Box::new(|| Ok(()));
                                    (event, ack)
                                })
                            }));
                            Ok(acking)
                        })
                    });
                    coalescer
                        .subscribe(key, prefix, options, effective_cadence, cancel, upstream)
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
        self.recover_mutation(&request.input.address, move |instance, target| {
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
        self.recover_mutation(&request.input.address, move |instance, target| {
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
        let (source_instance, source) = self.mutation_target(&request.input.source)?;
        let (dest_instance, destination) = self.mutation_target(&request.input.destination)?;
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
        let (source_instance, source) = self.mutation_target(&request.input.source)?;
        let (dest_instance, destination) = self.mutation_target(&request.input.destination)?;
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
        self.recover_mutation(&request.input.address, move |instance, target| {
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
        // Authenticated commits synchronize through `on_authenticated` above;
        // keep this explicit fence for Anonymous commits and for any future
        // successful state that does not run that hook.
        if let Some(instance) = self.instance_for_id(&id) {
            instance.synchronize_watch_identity();
        }
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

    #[test]
    fn coalesced_watch_cadence_normalizes_to_wire_floor() {
        assert_eq!(
            effective_broker_watch_cadence(Duration::ZERO),
            MIN_BROKER_WATCH_CADENCE
        );
        assert_eq!(
            effective_broker_watch_cadence(Duration::from_nanos(1)),
            MIN_BROKER_WATCH_CADENCE
        );
        assert_eq!(
            effective_broker_watch_cadence(Duration::from_millis(250)),
            Duration::from_millis(250)
        );
    }

    fn test_layer() -> Arc<BrokerClientLayer> {
        test_layer_with_grant(&[])
    }

    /// A layer whose own operator granted the anonymous fallback for
    /// `schemes`, the way `anonymous_fallback = [..]` on the layer table does.
    fn test_layer_with_grant(schemes: &[&str]) -> Arc<BrokerClientLayer> {
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
            anonymous_fallback: schemes.iter().map(|scheme| scheme.to_string()).collect(),
        })
    }

    fn wire_root(address: &str, visibility: AddressVisibility) -> AddressRoot {
        AddressRoot {
            address: Url::parse(address).unwrap(),
            display_name: None,
            backend_kind: KIND.into(),
            connection_id: None,
            capabilities: Capabilities::empty(),
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            visibility,
            user_metadata: UserMetadata::new(),
        }
    }

    /// A wire root carrying the scheme-fallback marker, as a broker whose own
    /// operator granted the fallback advertises it.
    fn marked_wire_root(address: &str, visibility: AddressVisibility) -> AddressRoot {
        let mut root = wire_root(address, visibility);
        root.user_metadata.insert(
            fallback::SCHEME_FALLBACK_METADATA_KEY.to_string(),
            fallback::SCHEME_FALLBACK_ANONYMOUS.to_string(),
        );
        root
    }

    /// Ingest `roots` as one broker connection's advertised snapshot through
    /// the path a live root watcher takes, returning the instance so a test
    /// can see what survived ingestion. The connection is not registered with
    /// the `ConnectionSet`, whose `set_addresses` ignores an unknown id.
    fn ingest_snapshot(
        layer: &Arc<BrokerClientLayer>,
        connection_id: &str,
        roots: Vec<AddressRoot>,
    ) -> Arc<BrokerClientInstance> {
        ingest_snapshot_with_backend(layer, connection_id, detached_backend(), roots)
    }

    /// [`ingest_snapshot`] with the backend the instance dispatches to chosen
    /// by the test, so a transport that panics on a slot can prove the slot
    /// was never reached.
    fn ingest_snapshot_with_backend(
        layer: &Arc<BrokerClientLayer>,
        connection_id: &str,
        backend: Arc<BrokerClientBackend>,
        roots: Vec<AddressRoot>,
    ) -> Arc<BrokerClientInstance> {
        let id = ConnectionId(connection_id.into());
        let instance = Arc::new(BrokerClientInstance {
            connection_id: id.clone(),
            source: ConnectionSource::Runtime { persisted: false },
            backend_id: BackendId(format!("broker:{connection_id}")),
            backend,
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(0)),
            roots: RwLock::new(Vec::new()),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        });
        layer.instances.write().push(instance.clone());
        layer.apply_backend_roots_change(&instance, &id, AddressRootsChange::Snapshot(roots));
        instance
    }

    #[test]
    fn broker_roots_advertise_list_stream_where_unary_list_is_available() {
        let layer = test_layer();
        let connection_id = ConnectionId("broker-caps".into());
        let source = ConnectionSource::Static {
            layer: ConfigLayer::Programmatic,
        };
        let mut root = wire_root("broker://host/dir/", AddressVisibility::Visible);
        root.capabilities.supports_list = true;

        let info = layer.root_info(root, &connection_id, &source);

        assert!(info.capabilities.supports_list);
        assert!(info.capabilities.supports_list_stream);
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
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(0)),
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

    #[test]
    fn root_info_derives_visible_from_each_wire_visibility() {
        let layer = test_layer();
        let connection_id = ConnectionId("visibility".into());
        let source = ConnectionSource::Runtime { persisted: false };

        for visibility in [
            AddressVisibility::Visible,
            AddressVisibility::Hidden,
            AddressVisibility::Suppressed,
        ] {
            let info = layer.root_info(
                wire_root("broker://host/team/", visibility),
                &connection_id,
                &source,
            );
            assert_eq!(info.visibility, visibility);
            assert_eq!(info.visible, visibility == AddressVisibility::Visible);
        }
    }

    #[tokio::test]
    async fn test_constructor_drops_suppressed_roots() {
        let root = Url::parse("broker://host/suppressed/").unwrap();
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(GatingTransport {
            authed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            root: root.clone(),
            visibility: AddressVisibility::Suppressed,
        });
        let layer =
            BrokerClientLayer::new_for_tests(transport, DiscoveryState::new("default"), None)
                .await
                .expect("test layer builds");

        let (snapshot, _) = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .expect("test layer lists roots");
        assert!(snapshot.roots.is_empty());
        let object = root.join("object.usd").unwrap();
        assert_eq!(
            layer
                .root_info_for(&object, &ovstorage_plugin::Extensions::new(), None)
                .await
                .expect_err("suppressed constructor root has no route")
                .code(),
            ErrorCode::NoRoute
        );
    }

    #[tokio::test]
    async fn snapshots_and_additions_route_hidden_but_drop_suppressed_roots() {
        let layer = test_layer();
        let connection_id = ConnectionId("visibility-deltas".into());
        let instance = Arc::new(BrokerClientInstance {
            connection_id: connection_id.clone(),
            source: ConnectionSource::Runtime { persisted: false },
            backend_id: BackendId("broker:visibility-deltas".into()),
            backend: detached_backend(),
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(0)),
            roots: RwLock::new(Vec::new()),
            cancel: layer.cancel.child_token(),
            root_watcher: Mutex::new(None),
        });
        layer.instances.write().push(instance.clone());

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
        layer
            .connection_set
            .add_connection(connection, driver, SecretBundle::default(), None)
            .await
            .expect("test connection registers");

        layer.apply_backend_roots_change(
            &instance,
            &connection_id,
            AddressRootsChange::Snapshot(vec![
                wire_root("broker://host/visible/", AddressVisibility::Visible),
                wire_root("broker://host/hidden/", AddressVisibility::Hidden),
                wire_root("broker://host/suppressed/", AddressVisibility::Suppressed),
            ]),
        );

        let roots = layer.current_roots();
        assert_eq!(roots.len(), 2);
        let hidden = roots
            .iter()
            .find(|root| root.root.as_str() == "broker://host/hidden/")
            .expect("hidden snapshot root remains in the route table");
        assert_eq!(hidden.visibility, AddressVisibility::Hidden);
        assert!(!hidden.visible);
        assert!(
            layer
                .route(&Url::parse("broker://host/hidden/object.usd").unwrap())
                .is_ok(),
            "hidden roots remain dispatchable"
        );
        assert_eq!(
            layer
                .route(&Url::parse("broker://host/suppressed/object.usd").unwrap())
                .err()
                .expect("suppressed snapshot root has no route")
                .code(),
            ErrorCode::NoRoute
        );
        let connection = layer
            .connection_set
            .connection(&connection_id)
            .expect("registered connection remains available");
        assert!(
            connection
                .current_addresses
                .iter()
                .any(|address| address.as_str() == "broker://host/hidden/"),
            "set_addresses receives hidden roots"
        );
        assert!(
            connection
                .current_addresses
                .iter()
                .all(|address| address.as_str() != "broker://host/suppressed/"),
            "set_addresses does not receive suppressed snapshot roots"
        );

        layer.apply_backend_roots_change(
            &instance,
            &connection_id,
            AddressRootsChange::Added(vec![
                wire_root("broker://host/hidden-added/", AddressVisibility::Hidden),
                wire_root(
                    "broker://host/suppressed-added/",
                    AddressVisibility::Suppressed,
                ),
            ]),
        );

        assert!(
            layer
                .route(&Url::parse("broker://host/hidden-added/object.usd").unwrap())
                .is_ok(),
            "hidden added roots remain dispatchable"
        );
        assert_eq!(
            layer
                .route(&Url::parse("broker://host/suppressed-added/object.usd").unwrap())
                .err()
                .expect("suppressed added root has no route")
                .code(),
            ErrorCode::NoRoute
        );
        assert!(instance.roots.read().iter().all(|root| {
            root.visibility != AddressVisibility::Suppressed
                && root.root.as_str() != "broker://host/suppressed-added/"
        }));
        let connection = layer
            .connection_set
            .connection(&connection_id)
            .expect("registered connection remains available");
        assert!(
            connection
                .current_addresses
                .iter()
                .all(|address| address.as_str() != "broker://host/suppressed-added/"),
            "set_addresses does not receive suppressed added roots"
        );
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
            .route(&Url::parse("s3://other/x").unwrap())
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

    /// A broker whose operator granted the anonymous fallback advertises a
    /// marked `s3:///` root; this process honours it only when its own operator
    /// granted the scheme too. Without the local grant the root is dropped at
    /// ingestion rather than merely left unrouted, so it is absent from the
    /// routing view and the root listing alike.
    #[tokio::test]
    async fn an_advertised_marked_scheme_root_routes_an_unmatched_address_only_with_a_local_grant()
    {
        let unrouted = Url::parse("s3://x/y").unwrap();
        let advertised = || vec![marked_wire_root("s3:///", AddressVisibility::Hidden)];

        let granted = test_layer_with_grant(&["s3"]);
        ingest_snapshot(&granted, "granted", advertised());
        let (root, instance, target) = granted
            .route_target(&unrouted)
            .expect("the granted scheme root answers an address no prefix matches");
        assert_eq!(root.root.as_str(), "s3:///");
        assert!(fallback::is_scheme_fallback_root(&root));
        assert_eq!(root.visibility, AddressVisibility::Hidden);
        assert!(
            !root.visible,
            "the wire visibility is kept on the projection"
        );
        assert!(
            address::relative_suffix(&unrouted, &root.root).is_none(),
            "a scheme-fallback hit is not a prefix hit; dispatch derives no suffix from it"
        );
        assert_eq!(target.backend_id, instance.backend_id);
        assert_eq!(
            target.resolved_address.as_str(),
            "s3://x/y",
            "the caller's address is forwarded to the broker verbatim"
        );
        let info = granted
            .root_info_for(&unrouted, &ovstorage_plugin::Extensions::new(), None)
            .await
            .expect("root_info_for answers from the same table");
        assert_eq!(info.root.as_str(), "s3:///");
        let listed = granted
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        assert_eq!(
            listed
                .iter()
                .map(|root| root.root.as_str())
                .collect::<Vec<_>>(),
            ["s3:///"],
            "the granted root is listed, hidden, for hosts that filter by `visible`"
        );

        // The same advertisement without a local grant is dropped at ingestion,
        // from a snapshot and from an `Added` delta alike.
        let ungranted = test_layer();
        let instance = ingest_snapshot(&ungranted, "ungranted", advertised());
        assert!(
            instance.roots.read().is_empty(),
            "dropped at ingestion, not merely unrouted"
        );
        assert_eq!(
            ungranted
                .route(&unrouted)
                .err()
                .expect("no local grant, no route")
                .code(),
            ErrorCode::NoRoute
        );
        assert!(
            ungranted
                .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
                .await
                .unwrap()
                .0
                .roots
                .is_empty()
        );
        ungranted.apply_backend_roots_change(
            &instance,
            &instance.connection_id,
            AddressRootsChange::Added(advertised()),
        );
        assert!(instance.roots.read().is_empty());
        assert_eq!(
            ungranted
                .route(&unrouted)
                .err()
                .expect("still no route")
                .code(),
            ErrorCode::NoRoute
        );

        // A grant names schemes, so one for `gs` does not admit an `s3` root.
        let other_scheme = test_layer_with_grant(&["gs"]);
        ingest_snapshot(&other_scheme, "gs-only", advertised());
        assert_eq!(
            other_scheme
                .route(&unrouted)
                .err()
                .expect("a `gs` grant does not cover `s3`")
                .code(),
            ErrorCode::NoRoute
        );
    }

    /// The grant admits marked roots; it does not make every hostless root a
    /// catch-all. An unmarked `s3:///` from the wire stays an ordinary prefix
    /// root for its own hostless node and answers nothing hosted.
    #[test]
    fn an_unmarked_hostless_root_still_leaves_an_unmatched_address_without_a_route() {
        let layer = test_layer_with_grant(&["s3"]);
        ingest_snapshot(
            &layer,
            "hostless",
            vec![wire_root("s3:///", AddressVisibility::Hidden)],
        );

        let miss = layer
            .route(&Url::parse("s3://other/x").unwrap())
            .err()
            .expect("unmatched address has no route");
        assert_eq!(miss.code(), ErrorCode::NoRoute);
        assert!(
            layer.route(&Url::parse("s3:///k").unwrap()).is_ok(),
            "the unmarked root still serves its own hostless node by prefix"
        );
        assert_eq!(
            layer.current_roots().len(),
            1,
            "the root itself is ingested"
        );
    }

    /// The marker on a bucket root is inert: the root is admitted as an
    /// ordinary prefix root (nothing about it needs a grant) and answers
    /// nothing outside its bucket.
    #[test]
    fn a_marked_bucket_root_from_the_wire_is_not_a_catch_all() {
        let layer = test_layer_with_grant(&["s3"]);
        ingest_snapshot(
            &layer,
            "bucket",
            vec![marked_wire_root("s3://bucket/", AddressVisibility::Hidden)],
        );

        assert!(
            layer.route(&Url::parse("s3://bucket/x").unwrap()).is_ok(),
            "the bucket root serves its own prefix"
        );
        assert_eq!(
            layer
                .route(&Url::parse("s3://other/x").unwrap())
                .err()
                .expect("a marked bucket root answers no other bucket")
                .code(),
            ErrorCode::NoRoute
        );
    }

    /// The wire is not where the fallback's read-only promise is enforced: a
    /// broker publishes its fallback root with whatever bits its own layer
    /// advertises, and a peer that is not this codebase may assert anything.
    /// Whatever mutation bits arrive, the projected root advertises none and
    /// keeps its read side, so a host consulting the root before it acts
    /// learns locally what the broker would refuse. A prefix root asserting
    /// the same bits keeps them: the lowering is scoped to the fallback root.
    #[tokio::test]
    async fn an_ingested_scheme_fallback_root_advertises_no_mutation_bits() {
        let asserted = Capabilities {
            supports_write: true,
            supports_write_stream: true,
            supports_write_redirect: true,
            supports_delete: true,
            supports_create_directory: true,
            supports_delete_directory: true,
            supports_copy: true,
            supports_rename: true,
            supports_native_metadata_patch: true,
            supports_watch_directory: true,
            watch_directory_resumable: true,
            supports_list: true,
            supports_recursive_list: true,
            supports_version_listing: true,
            supports_access_check: true,
            has_real_directories: true,
            ..Capabilities::empty()
        };
        let mut fallback_root = marked_wire_root("s3:///", AddressVisibility::Hidden);
        fallback_root.capabilities = asserted.clone();
        let mut prefix_root = wire_root("s3://bucket/", AddressVisibility::Visible);
        prefix_root.capabilities = asserted.clone();

        let layer = test_layer_with_grant(&["s3"]);
        ingest_snapshot(&layer, "caps", vec![fallback_root, prefix_root]);

        let (routed, _, _) = layer
            .route_target(&Url::parse("s3://x/y").unwrap())
            .expect("the fallback root answers the unmatched address");
        assert!(fallback::is_scheme_fallback_root(&routed));
        let caps = &routed.capabilities;
        assert!(
            !caps.supports_write
                && !caps.supports_write_stream
                && !caps.supports_write_redirect
                && !caps.supports_delete
                && !caps.supports_create_directory
                && !caps.supports_delete_directory
                && !caps.supports_copy
                && !caps.supports_rename
                && !caps.supports_native_metadata_patch
                && !caps.supports_watch_directory
                && !caps.watch_directory_resumable,
            "no mutation or watch bit survives ingestion: {caps:?}"
        );
        assert_eq!(
            *caps,
            fallback::read_only_capabilities(caps.clone()),
            "the projected set is already the lowered set"
        );
        assert!(
            caps.supports_list
                && caps.supports_list_stream
                && caps.supports_recursive_list
                && caps.supports_version_listing
                && caps.supports_access_check
                && caps.has_real_directories,
            "the read side is kept, list-stream included: {caps:?}"
        );

        let (routed, _, _) = layer
            .route_target(&Url::parse("s3://bucket/y").unwrap())
            .expect("the prefix root answers its own bucket");
        assert!(!fallback::is_scheme_fallback_root(&routed));
        assert!(
            routed.capabilities.supports_write
                && routed.capabilities.supports_delete
                && routed.capabilities.supports_watch_directory,
            "a prefix root keeps the bits the wire asserted"
        );
        assert!(
            routed.capabilities.supports_list_stream,
            "the list-stream rule applies to every root the broker publishes"
        );

        // The listing a host reads before it acts advertises the same.
        let listed = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap()
            .0
            .roots;
        let advertised = listed
            .iter()
            .find(|root| root.root.as_str() == "s3:///")
            .expect("the fallback root is listed");
        assert!(!advertised.capabilities.supports_write);
        assert!(advertised.capabilities.supports_list);
    }

    /// A mutation or a watch on an address the fallback answers is refused in
    /// this process, before the broker is asked. The transport panics on every
    /// mutating call, so the refusal is proven local rather than relayed; the
    /// error is the one the cloud layers return for the same address, and its
    /// next action names the origin an operator would add a connection for,
    /// never the caller's path or credential. `copy` and `rename` are refused
    /// whichever endpoint the fallback answers, as the cloud layers refuse
    /// them; both endpoints sit on one instance so the same-connection check
    /// is not what refuses.
    #[tokio::test]
    async fn a_write_to_a_fallback_routed_address_is_refused_locally() {
        let layer = test_layer_with_grant(&["s3"]);
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(RecordingTransport {
            total: 0,
            auth_requests: Arc::new(Mutex::new(Vec::new())),
            list_requests: Arc::new(Mutex::new(Vec::new())),
            scripted_next_tokens: None,
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        ingest_snapshot_with_backend(
            &layer,
            "fallback",
            backend,
            vec![
                marked_wire_root("s3:///", AddressVisibility::Hidden),
                wire_root("s3://bucket/", AddressVisibility::Visible),
            ],
        );

        // Userinfo is read by no routing step, so the address routes with it;
        // the refusal must not echo it.
        let unrouted = Url::parse("s3://user:secret@x/dir/y").unwrap();
        let configured = Url::parse("s3://bucket/z").unwrap();
        let (root, _, _) = layer
            .route_target(&unrouted)
            .expect("the address routes; the refusal is not a missing route");
        assert!(fallback::is_scheme_fallback_root(&root));

        let refused = |error: Error| {
            assert_eq!(error.code(), ErrorCode::Unsupported);
            assert_eq!(
                error.message(),
                "this address is reached through the anonymous s3:// fallback, which is read-only"
            );
            let next_action = error
                .next_action()
                .expect("the refusal says what to configure");
            assert!(
                next_action.contains("s3://x/"),
                "names the origin root: {next_action}"
            );
            assert!(
                !next_action.contains("dir") && !next_action.contains("secret"),
                "prints neither the caller's path nor the credential: {next_action}"
            );
        };

        refused(
            layer
                .write(
                    Request::new(WriteRequest {
                        address: unrouted.clone(),
                        body: Body::Bytes(b"payload".to_vec()),
                        options: WriteOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("write is refused"),
        );
        refused(
            layer
                .write_redirect(
                    Request::new(WriteRequest {
                        address: unrouted.clone(),
                        body: Body::Bytes(Vec::new()),
                        options: WriteOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("write_redirect is refused"),
        );
        refused(
            layer
                .continue_write(
                    Request::new(ContinueWriteRequest {
                        address: unrouted.clone(),
                        redirects: WriteRedirectBatch {
                            continuation: Vec::new(),
                            redirects: Vec::new(),
                        },
                        results: RedirectResultBatch {
                            results: Vec::new(),
                        },
                    }),
                    None,
                )
                .await
                .expect_err("continue_write is refused"),
        );
        refused(
            layer
                .delete(
                    Request::new(DeleteRequest {
                        address: unrouted.clone(),
                        options: DeleteOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("delete is refused"),
        );
        refused(
            layer
                .create_directory(
                    Request::new(CreateDirectoryRequest {
                        address: unrouted.clone(),
                        options: CreateDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("create_directory is refused"),
        );
        refused(
            layer
                .delete_directory(
                    Request::new(DeleteDirectoryRequest {
                        address: unrouted.clone(),
                        options: DeleteDirectoryOptions,
                    }),
                    None,
                )
                .await
                .expect_err("delete_directory is refused"),
        );
        refused(
            layer
                .update_metadata(
                    Request::new(UpdateMetadataRequest {
                        address: unrouted.clone(),
                        options: UpdateMetadataOptions::default(),
                    }),
                    None,
                )
                .await
                .expect_err("update_metadata is refused"),
        );
        refused(
            layer
                .watch_directory(
                    Request::new(WatchDirectoryRequest {
                        prefix: unrouted.clone(),
                        options: WatchDirectoryOptions::default(),
                    }),
                    None,
                )
                .await
                .err()
                .expect("watch_directory is refused"),
        );
        for (source, destination) in [
            (unrouted.clone(), configured.clone()),
            (configured.clone(), unrouted.clone()),
        ] {
            refused(
                layer
                    .copy(
                        Request::new(CopyRequest {
                            source: source.clone(),
                            destination: destination.clone(),
                            options: CopyOptions::default(),
                        }),
                        None,
                    )
                    .await
                    .expect_err("copy is refused whichever endpoint the fallback answers"),
            );
            refused(
                layer
                    .rename(
                        Request::new(RenameRequest {
                            source,
                            destination,
                            options: RenameOptions::default(),
                        }),
                        None,
                    )
                    .await
                    .expect_err("rename is refused whichever endpoint the fallback answers"),
            );
        }
    }

    /// The shipped layer table for a brokered client may hold only the grant
    /// (`anonymous_fallback = ["s3"]`): the grant is policy, not a connection,
    /// so it must not be read as a static connection with no address. A grant
    /// of the wrong shape is refused at startup.
    #[tokio::test]
    async fn a_grant_only_layer_table_seeds_no_connection() {
        let factory = BrokerClientLayerFactory::default();
        let mut config = LayerConfig::new();
        config.insert(
            fallback::ANONYMOUS_FALLBACK_KEY.to_string(),
            ConfigValue::Toml("anonymous_fallback = [\"s3\"]\n".to_string()),
        );
        let layer = factory
            .create_backend("broker", &config, None)
            .await
            .expect("a grant alone is a valid layer table");
        let (connections, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert!(
            connections.connections.is_empty(),
            "the grant seeds no static connection"
        );
        let (snapshot, _) = layer
            .list_address_roots(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert!(
            snapshot.roots.is_empty(),
            "a grant admits an advertised root; it publishes none of its own"
        );

        config.insert(
            fallback::ANONYMOUS_FALLBACK_KEY.to_string(),
            ConfigValue::String("s3".to_string()),
        );
        let error = factory
            .create_backend("broker", &config, None)
            .await
            .err()
            .expect("a grant that is not a TOML array is refused at startup");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }

    /// The broker layer reads one fallback key, the grant. Any other
    /// `anonymous_fallback_*` key on its table — a tunable that belongs to a
    /// cloud layer, or the host's top-level `anonymous_fallback_schemes` written
    /// one table too deep — is refused by name at startup rather than split
    /// off and discarded, whether it stands alone or beside a valid grant.
    #[tokio::test]
    async fn a_stray_anonymous_fallback_key_on_the_broker_layer_is_refused() {
        let factory = BrokerClientLayerFactory::default();
        for stray in ["anonymous_fallback_schemes", "anonymous_fallback_region"] {
            let mut config = LayerConfig::new();
            config.insert(
                stray.to_string(),
                ConfigValue::Toml(format!("{stray} = [\"s3\"]\n")),
            );
            let error = factory
                .create_backend("broker", &config, None)
                .await
                .err()
                .expect("a stray fallback key alone is refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{stray}");
            assert!(
                error.message().contains(stray) && error.message().contains("layer `broker`"),
                "{}",
                error.message()
            );

            config.insert(
                fallback::ANONYMOUS_FALLBACK_KEY.to_string(),
                ConfigValue::Toml("anonymous_fallback = [\"s3\"]\n".to_string()),
            );
            let error = factory
                .create_backend("broker", &config, None)
                .await
                .err()
                .expect("a stray fallback key beside a valid grant is refused");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{stray}");
            assert!(error.message().contains(stray), "{}", error.message());
        }
    }

    /// The grant parses against the closed scheme set, which includes the http
    /// tier so its switch exists; every host refuses to grant that tier this
    /// release, and the brokered client refuses it with the same words, so a
    /// client cannot honour a wire-advertised http root no host may publish. A
    /// mixed grant is refused whole, so a partly valid array does not slip in.
    #[tokio::test]
    async fn an_http_grant_on_the_broker_layer_is_refused_this_release() {
        let factory = BrokerClientLayerFactory::default();
        for grant in ["[\"http\"]", "[\"https\"]", "[\"s3\", \"http\"]"] {
            let mut config = LayerConfig::new();
            config.insert(
                fallback::ANONYMOUS_FALLBACK_KEY.to_string(),
                ConfigValue::Toml(format!("anonymous_fallback = {grant}\n")),
            );
            let error = factory
                .create_backend("broker", &config, None)
                .await
                .err()
                .expect("an http grant is refused at startup");
            assert_eq!(error.code(), ErrorCode::InvalidArgument, "{grant}");
            assert!(
                error.message().contains("not available in this release"),
                "{}",
                error.message()
            );
        }
    }

    /// Fallback keys belong to the layer table. On a connection request — probe
    /// or add — they are refused with guidance before any address is parsed or
    /// any transport is opened, and nothing is registered.
    #[tokio::test]
    async fn a_connection_request_carrying_a_fallback_key_is_refused() {
        let layer = test_layer();
        for key in ["anonymous_fallback", "anonymous_fallback_region"] {
            let mut request = ConnectionRequest {
                backend_kind: KIND.into(),
                config: LayerConfig::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            };
            request.config.insert(
                "address".to_string(),
                ConfigValue::String("https://broker.example.test".to_string()),
            );
            request.config.insert(
                key.to_string(),
                ConfigValue::Toml(format!("{key} = [\"s3\"]\n")),
            );
            let expected = format!(
                "`{key}` is a layer key, not connection config; set it on [ovstorage.layers.broker]"
            );

            let probe_error = layer
                .probe(
                    Request::new(LayerConnectionRequest {
                        target: "broker".into(),
                        connection: request.clone(),
                    }),
                    None,
                )
                .await
                .expect_err("probe refuses a fallback key");
            assert_eq!(
                probe_error.code(),
                ErrorCode::InvalidArgument,
                "probe {key}"
            );
            assert_eq!(probe_error.message(), expected);

            let add_error = layer
                .add_connection(
                    Request::new(LayerConnectionRequest {
                        target: "broker".into(),
                        connection: request,
                    }),
                    None,
                )
                .await
                .expect_err("add_connection refuses a fallback key");
            assert_eq!(add_error.code(), ErrorCode::InvalidArgument, "add {key}");
            assert_eq!(add_error.message(), expected);
        }
        let (connections, _) = layer
            .list_connections(&ovstorage_plugin::Extensions::new(), None)
            .await
            .unwrap();
        assert!(
            connections.connections.is_empty(),
            "a refused request registers nothing"
        );
    }

    /// Recording transport that models the broker's server-side pagination and
    /// captures each address and capability used to open an upstream-auth stream.
    struct RecordingTransport {
        total: usize,
        auth_requests: Arc<Mutex<Vec<(Url, InteractiveAuthCapability)>>>,
        list_requests: Arc<Mutex<Vec<ListOptions>>>,
        scripted_next_tokens: Option<Arc<Mutex<VecDeque<Option<String>>>>>,
    }

    #[async_trait]
    impl BrokerClientTransport for RecordingTransport {
        async fn list(&self, prefix: Url, options: ListOptions) -> Result<ListPage> {
            let request_index = {
                let mut requests = self.list_requests.lock();
                let request_index = requests.len();
                requests.push(options.clone());
                request_index
            };
            if let Some(scripted_next_tokens) = &self.scripted_next_tokens {
                let next_page_token = scripted_next_tokens
                    .lock()
                    .pop_front()
                    .expect("scripted list transport has a response for every request");
                return Ok(ListPage {
                    items: vec![ObjectInfo {
                        etag_strength: Default::default(),
                        address: prefix.join(&format!("obj-{request_index}")).unwrap(),
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
                        versioned_address: None,
                    }],
                    next_page_token,
                });
            }
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
                    etag_strength: Default::default(),
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
                    versioned_address: None,
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
        async fn watch_directory_with_cancel(
            &self,
            _prefix: Url,
            _opts: WatchDirectoryOptions,
            _cancel: Option<CancellationToken>,
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
            list_requests: Arc::new(Mutex::new(Vec::new())),
            scripted_next_tokens: None,
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
    async fn list_stream_walks_broker_pages_in_order() {
        let layer = test_layer();
        let total = BROKER_LIST_STREAM_PAGE_SIZE as usize * 2 + 1;
        let list_requests = Arc::new(Mutex::new(Vec::new()));
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(RecordingTransport {
            total,
            auth_requests: Arc::new(Mutex::new(Vec::new())),
            list_requests: list_requests.clone(),
            scripted_next_tokens: None,
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        seed_with_backend(&layer, "broker://host/dir/", "b-stream", backend);

        let prefix = Url::parse("broker://host/dir/").unwrap();
        let mut stream = layer
            .list_stream(
                Request::new(ListRequest {
                    prefix: prefix.clone(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect("stream opens");

        let mut addresses = Vec::new();
        while let Some(item) = stream.next().await {
            addresses.push(item.expect("stream entry").address);
        }

        let expected: Vec<_> = (0..total)
            .map(|i| prefix.join(&format!("obj-{i}")).unwrap())
            .collect();
        assert_eq!(addresses, expected);

        let requests = list_requests.lock();
        assert_eq!(requests.len(), 3);
        assert!(
            requests
                .iter()
                .all(|request| request.max_results == Some(BROKER_LIST_STREAM_PAGE_SIZE))
        );
        assert_eq!(requests[0].page_token, None);
        let second_page_token = BROKER_LIST_STREAM_PAGE_SIZE.to_string();
        assert_eq!(
            requests[1].page_token.as_deref(),
            Some(second_page_token.as_str())
        );
        let third_page_token = (BROKER_LIST_STREAM_PAGE_SIZE * 2).to_string();
        assert_eq!(
            requests[2].page_token.as_deref(),
            Some(third_page_token.as_str())
        );
    }

    #[tokio::test]
    async fn list_stream_rejects_caller_paging_before_dispatch() {
        let layer = test_layer();
        for options in [
            ListOptions {
                max_results: Some(1),
                ..Default::default()
            },
            ListOptions {
                page_token: Some("opaque".into()),
                ..Default::default()
            },
        ] {
            let error = match layer
                .list_stream(
                    Request::new(ListRequest {
                        prefix: Url::parse("broker://host/dir/").unwrap(),
                        options,
                    }),
                    None,
                )
                .await
            {
                Ok(_) => panic!("paged list_stream request must be rejected"),
                Err(error) => error,
            };
            assert_eq!(error.code(), ErrorCode::InvalidArgument);
        }
    }

    async fn drive_scripted_list_stream(
        next_tokens: impl IntoIterator<Item = Option<&'static str>>,
    ) -> (usize, Error, Vec<ListOptions>) {
        let layer = test_layer();
        let list_requests = Arc::new(Mutex::new(Vec::new()));
        let scripted_next_tokens = next_tokens
            .into_iter()
            .map(|token| token.map(str::to_owned))
            .collect();
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(RecordingTransport {
            total: 0,
            auth_requests: Arc::new(Mutex::new(Vec::new())),
            list_requests: list_requests.clone(),
            scripted_next_tokens: Some(Arc::new(Mutex::new(scripted_next_tokens))),
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        seed_with_backend(&layer, "broker://host/dir/", "b-cycle", backend);

        let mut stream = layer
            .list_stream(
                Request::new(ListRequest {
                    prefix: Url::parse("broker://host/dir/").unwrap(),
                    options: ListOptions::default(),
                }),
                None,
            )
            .await
            .expect("stream opens");
        let mut item_count = 0;
        let error = loop {
            match stream.next().await {
                Some(Ok(_)) => item_count += 1,
                Some(Err(error)) => break error,
                None => panic!("cyclic broker cursor must terminate with an error"),
            }
        };
        assert!(stream.next().await.is_none());
        let requests = list_requests.lock().clone();
        (item_count, error, requests)
    }

    #[tokio::test]
    async fn list_stream_rejects_a_cursor_reissued_without_progress() {
        let (item_count, error, requests) =
            drive_scripted_list_stream([Some("cursor-a"), Some("cursor-a")]).await;

        assert_eq!(item_count, 2);
        assert_eq!(error.code(), ErrorCode::Transient);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].page_token, None);
        assert_eq!(requests[1].page_token.as_deref(), Some("cursor-a"));
    }

    #[tokio::test]
    async fn list_stream_rejects_a_recent_cursor_cycle() {
        let (item_count, error, requests) =
            drive_scripted_list_stream([Some("cursor-a"), Some("cursor-b"), Some("cursor-a")])
                .await;

        assert_eq!(item_count, 3);
        assert_eq!(error.code(), ErrorCode::Transient);
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].page_token, None);
        assert_eq!(requests[1].page_token.as_deref(), Some("cursor-a"));
        assert_eq!(requests[2].page_token.as_deref(), Some("cursor-b"));
    }

    #[tokio::test]
    async fn list_stream_cancellation_between_pages_stops_before_another_rpc() {
        let layer = test_layer();
        let total = BROKER_LIST_STREAM_PAGE_SIZE as usize + 1;
        let list_requests = Arc::new(Mutex::new(Vec::new()));
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(RecordingTransport {
            total,
            auth_requests: Arc::new(Mutex::new(Vec::new())),
            list_requests: list_requests.clone(),
            scripted_next_tokens: None,
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        seed_with_backend(&layer, "broker://host/dir/", "b-cancel", backend);

        let cancel = CancellationToken::new();
        let mut stream = layer
            .list_stream(
                Request::new(ListRequest {
                    prefix: Url::parse("broker://host/dir/").unwrap(),
                    options: ListOptions::default(),
                }),
                Some(cancel.clone()),
            )
            .await
            .expect("stream opens");

        for _ in 0..BROKER_LIST_STREAM_PAGE_SIZE {
            stream
                .next()
                .await
                .expect("first page has every requested entry")
                .expect("first-page entry succeeds");
        }
        assert_eq!(list_requests.lock().len(), 1);

        cancel.cancel();
        let error = stream
            .next()
            .await
            .expect("cancellation is surfaced")
            .expect_err("cancellation terminates the stream");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(
            list_requests.lock().len(),
            1,
            "cancellation between pages must prevent the next unary List RPC"
        );
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn list_stream_cancellation_after_the_final_entry_is_terminal() {
        let layer = test_layer();
        let list_requests = Arc::new(Mutex::new(Vec::new()));
        let transport: Arc<dyn BrokerClientTransport> = Arc::new(RecordingTransport {
            total: 1,
            auth_requests: Arc::new(Mutex::new(Vec::new())),
            list_requests: list_requests.clone(),
            scripted_next_tokens: None,
        });
        let backend = Arc::new(BrokerClientBackend::new_for_tests(
            "https://broker.example.com",
            transport,
        ));
        seed_with_backend(&layer, "broker://host/dir/", "b-final-cancel", backend);

        let cancel = CancellationToken::new();
        let mut stream = layer
            .list_stream(
                Request::new(ListRequest {
                    prefix: Url::parse("broker://host/dir/").unwrap(),
                    options: ListOptions::default(),
                }),
                Some(cancel.clone()),
            )
            .await
            .expect("stream opens");

        stream
            .next()
            .await
            .expect("final page has one entry")
            .expect("final entry succeeds");
        cancel.cancel();
        let error = stream
            .next()
            .await
            .expect("cancellation after the final entry is surfaced")
            .expect_err("cancellation terminates the stream");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(list_requests.lock().len(), 1);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn authenticate_routes_upstream_address_and_capability_only_when_present() {
        let layer = test_layer();
        let auth_requests = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(RecordingTransport {
            total: 0,
            auth_requests: auth_requests.clone(),
            list_requests: Arc::new(Mutex::new(Vec::new())),
            scripted_next_tokens: None,
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
        visibility: AddressVisibility,
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
                visibility: self.visibility,
                user_metadata: UserMetadata::new(),
            }])
        }

        async fn stat(&self, address: Url, _options: StatOptions) -> Result<ObjectInfo> {
            Ok(ObjectInfo {
                etag_strength: Default::default(),
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
                versioned_address: None,
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
        async fn watch_directory_with_cancel(
            &self,
            _prefix: Url,
            _opts: WatchDirectoryOptions,
            _cancel: Option<CancellationToken>,
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
            visibility: AddressVisibility::Visible,
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
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(0)),
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
            visibility: AddressVisibility::Visible,
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
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(0)),
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
            visibility: AddressVisibility::Visible,
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
            watch_coalescer: Mutex::new(IdentityWatchCoalescer::new(0)),
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
            owning_target: Some("broker".into()),
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
