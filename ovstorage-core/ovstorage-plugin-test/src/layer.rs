// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! ABI-v2 `Layer` surface over the test backend.
//!
//! [`TestLayerFactory`] / [`TestLayer`] wrap the same [`TestFactory`] /
//! [`TestBackend`] bodies, sharing one store, recorder, and knob set per
//! root. The layer self-routes across its connections by longest prefix and
//! self-gates optional slots on the connection's capabilities.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::channel::mpsc;

use ovstorage_plugin::*;

use crate::config::TestConfig;
use crate::recorder::ObservedCall;
use crate::{BACKEND_KIND, Recorder, TestBackend, TestFactory, TestInstance, token_matches};

/// Recovery hint the test layer attaches to its `root_info_for` `NoRoute`
/// error.
///
/// Exported so the cross-`.so` test can assert the exact string arrives at
/// the host: `next_action` has to travel inside the `Error` struct, and a
/// host-side check against a locally-known constant is the only way to tell
/// "the plugin's hint crossed" from "the host invented one".
pub const TEST_LAYER_NO_ROUTE_NEXT_ACTION: &str = "Add a connection whose root prefixes this URL.";

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates.
///
/// Holds the shared per-root instance map (via [`TestFactory`]) so store
/// bytes, counters, and recorders survive Stack rebuilds: the host re-runs
/// `create_backend` while retaining the factory.
pub struct TestLayerFactory {
    shared: Arc<TestFactory>,
}

impl Default for TestLayerFactory {
    fn default() -> Self {
        Self {
            shared: Arc::new(TestFactory::new()),
        }
    }
}

impl TestLayerFactory {
    /// Clone the [`Recorder`] for `root`, or `None` if no connection has
    /// minted an instance for it yet.
    pub fn recorder_for(&self, root: &Url) -> Option<Recorder> {
        self.shared.recorder_for(root)
    }
}

#[async_trait]
impl BackendFactory for TestLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.shared.descriptor())
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let _ = &cancel; // conformance plugin op: no async work to cancel.
        let layer = Arc::new(TestLayer {
            name: name.to_string(),
            shared: self.shared.clone(),
            state: Mutex::new(LayerState::default()),
        });
        // Non-empty layer config is a static connection; a host may instead
        // build with empty config and add roots through `add_connection`.
        if !config.is_empty() {
            let request = ConnectionRequest {
                backend_kind: BACKEND_KIND.into(),
                config: config.clone(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            };
            layer.install_connection(
                request,
                ConnectionSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
            )?;
        }
        Ok(layer)
    }
}

/// One served root: the connection that contributed it and the shared
/// per-root instance the operational slots dispatch to.
struct RootEntry {
    root: Url,
    instance: Arc<TestInstance>,
    connection_id: ConnectionId,
    source: ConnectionSource,
}

/// Roots, connections, **and the update-stream subscribers**, under one guard.
///
/// The subscriber lists live in here, rather than beside `TestLayer`, so that
/// this struct is the only handle on the senders: the *only* way to reach
/// [`announce_roots`](Self::announce_roots) /
/// [`announce_connection`](Self::announce_connection) is to be holding the
/// `state` guard. An announcement written outside the critical section that
/// commits the change it describes does not compile. Announcing is a capability
/// the commit hands out, which is the property
/// `ovstorage_layer::ordered::Ordered` offers production layers; see
/// [`TestLayer::install_connection`] for why `Ordered` itself does not fit here.
///
/// A runtime assertion at the emission site cannot express this. It is a
/// separate statement, so it certifies "the lock is held at this line" rather
/// than "these sends happen under the lock", and it stays silent for the
/// likeliest regression: extracting an `emit_changes()` helper and calling it
/// after the block leaves the assertion behind.
///
/// The guarantee is against code *motion*, which is the regression shape: the
/// senders are unreachable from `&self`, so an announcement cannot be relocated
/// out of its critical section, and neither `state.` nor `self.state.` compiles
/// from outside one. It does not stop someone deliberately taking a second lock
/// to announce in a fresh critical section — that is a rewrite, not a slip, and
/// no type can prevent it.
#[derive(Default)]
struct LayerState {
    roots: Vec<RootEntry>,
    connections: Vec<Connection>,
    /// Live subscribers to the `list_address_roots` update stream;
    /// registered before the snapshot is read so a root added in that
    /// window arrives on the stream rather than being lost.
    root_subs: Vec<mpsc::UnboundedSender<Result<RootInfoChange>>>,
    /// Live subscribers to the `list_connections` update stream.
    conn_subs: Vec<mpsc::UnboundedSender<Result<ConnectionChange>>>,
}

impl LayerState {
    /// Announce a root change to every live subscriber, dropping those whose
    /// receiver has gone. Reachable only through the `state` guard.
    fn announce_roots(&mut self, change: RootInfoChange) {
        self.root_subs
            .retain(|tx| tx.unbounded_send(Ok(change.clone())).is_ok());
    }

    /// Announce a connection change to every live subscriber. Reachable only
    /// through the `state` guard.
    fn announce_connection(&mut self, change: ConnectionChange) {
        self.conn_subs
            .retain(|tx| tx.unbounded_send(Ok(change.clone())).is_ok());
    }
}

/// ABI-v2 `Layer` over the shared test-backend instances.
pub struct TestLayer {
    name: String,
    shared: Arc<TestFactory>,
    state: Mutex<LayerState>,
}

impl TestLayer {
    fn install_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
    ) -> Result<Connection> {
        if request.backend_kind != BACKEND_KIND {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{BACKEND_KIND}'",
                    request.backend_kind
                ),
            ));
        }
        let display_name = request.display_name.clone();
        let cfg = TestConfig::from_request(&request)?;
        // Add-time gate BEFORE any state mutation (`shared_instance`
        // replaces the instance cfg, so it counts): a rejected add — in
        // particular a fallback re-add with a bad token — must leave no
        // ghost RootEntry/Connection and notify no subscriber.
        if cfg.reject_bad_token_at_add && !crate::token_matches(&cfg, &request.credentials) {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "test-plugin: test_reject_bad_token_at_add: connection credentials do not \
                 carry the required 'token'",
            ));
        }
        let instance = self.shared.shared_instance(cfg.clone());
        // The connection's live bundle — unconditionally overwritten so a
        // re-add cannot inherit a stale bundle from the instance that
        // survives `remove_connection`.
        *instance.credentials.lock().expect("instance credentials") = request.credentials;
        let connection_id = ConnectionId(fresh_id(BACKEND_KIND));
        let connection = Connection {
            id: connection_id.clone(),
            backend_kind: BACKEND_KIND.to_string(),
            display_name: display_name.unwrap_or_else(|| "Test backend".to_string()),
            source: source.clone(),
            capabilities: cfg.capabilities.clone(),
            current_addresses: vec![cfg.root.clone()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: Some(SystemTime::now()),
            user_metadata: UserMetadata::new(),
        };
        let entry = RootEntry {
            root: cfg.root,
            instance,
            connection_id,
            source,
        };
        let root_info = self.root_info(&entry);
        {
            // The mutation and BOTH announcements happen under one guard.
            // Announcing after the guard closes lets a concurrent
            // `remove_connection` commit its own mutation and announce
            // `Removed` in the window, delivering it to a subscriber ahead of
            // this `Added` — an order no host can reconcile. `announce_*` are
            // methods on the guarded state, so they cannot be moved out of this
            // critical section without a compile error. Holding the guard
            // across the sends is safe because these are unbounded channels:
            // `unbounded_send` never blocks.
            //
            // That "announce under the lock, on a non-blocking sender"
            // discipline is what `ovstorage_layer::ordered::Ordered` packages
            // for production layers. It is deliberately not used here:
            // `Ordered` carries exactly one sender and these fixtures announce
            // on two from the same critical section, and its `Emitter` trait is
            // sealed to the tokio channel types, whereas the update streams
            // here are `futures::channel::mpsc` and lossless — migrating would
            // mean bounded-lossy delivery with `Lagged` handling in a
            // conformance harness whose subscribers rely on losslessness.
            let mut state = self.state.lock().expect("test-layer state");
            // Most-recent cfg wins (matches `shared_instance`): a repeat
            // connection for the same root replaces the prior entry.
            state.roots.retain(|existing| existing.root != entry.root);
            state.roots.push(entry);
            state.connections.push(connection.clone());
            state.announce_roots(RootInfoChange::Added(vec![root_info]));
            state.announce_connection(ConnectionChange::Added(connection.clone()));
        }
        Ok(connection)
    }

    fn root_info(&self, entry: &RootEntry) -> RootInfo {
        // Provenance follows the connection source: static config stays
        // `Static` even though it carries a connection id.
        let route_source = match &entry.source {
            ConnectionSource::Static { layer } => RouteSource::Static { layer: *layer },
            _ => RouteSource::ConnectionContributed {
                connection_id: entry.connection_id.clone(),
            },
        };
        let capabilities = entry
            .instance
            .cfg
            .lock()
            .expect("instance cfg")
            .capabilities
            .clone();
        RootInfo {
            root: entry.root.clone(),
            display_name: None,
            layer_kind: BACKEND_KIND.to_string(),
            connection_id: Some(entry.connection_id.clone()),
            owning_target: None,
            capabilities,
            range_read_strategy: RangeReadStrategy::Native,
            source: route_source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    /// Longest-prefix route for `url`: the backend handle plus the
    /// route's live capabilities (most-recent cfg wins).
    fn route(&self, url: &Url) -> Result<(TestBackend, Capabilities)> {
        let state = self.state.lock().expect("test-layer state");
        let entry = state
            .roots
            .iter()
            .filter(|entry| ovstorage_plugin::address::is_ancestor_or_self(&entry.root, url))
            .max_by_key(|entry| ovstorage_plugin::address::node_rank(&entry.root))
            .ok_or_else(|| {
                // The hint is load-bearing for the cross-`.so` test that
                // pins `next_action` surviving the plugin ABI.
                Error::new(
                    ErrorCode::NoRoute,
                    format!("test-plugin: no route matches {}", url.as_str()),
                )
                .with_next_action(TEST_LAYER_NO_ROUTE_NEXT_ACTION)
            })?;
        let capabilities = entry
            .instance
            .cfg
            .lock()
            .expect("instance cfg")
            .capabilities
            .clone();
        Ok((
            TestBackend {
                instance: entry.instance.clone(),
            },
            capabilities,
        ))
    }

    fn target(&self, url: &Url) -> Result<(TestBackend, ResolvedTarget)> {
        let (backend, _) = self.route(url)?;
        let target = resolved_target(&backend, url);
        Ok((backend, target))
    }

    /// Route and gate the operation on the target root's capability bit.
    fn gated_target(
        &self,
        url: &Url,
        what: &str,
        supported: impl FnOnce(&Capabilities) -> bool,
    ) -> Result<(TestBackend, ResolvedTarget)> {
        let (backend, capabilities) = self.route(url)?;
        if !supported(&capabilities) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!("test-plugin: route does not support {what}"),
            ));
        }
        let target = resolved_target(&backend, url);
        Ok((backend, target))
    }

    fn connection_for_key(&self, key: &ConnectionKey) -> Result<Connection> {
        if key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        self.state
            .lock()
            .expect("test-layer state")
            .connections
            .iter()
            .find(|connection| connection.id == key.id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))
    }
}

/// Stage materialized bytes to a unique temp file (std-only; the harness
/// carries no tempfile dependency in its library target).
fn stage_to_temp_file(bytes: &[u8]) -> Result<std::path::PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "ovstorage-plugin-test-materialize-{}-{seq}.bin",
        std::process::id()
    ));
    std::fs::write(&path, bytes).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("test-plugin: stage materialize temp file: {err}"),
        )
    })?;
    Ok(path)
}

fn resolved_target(backend: &TestBackend, url: &Url) -> ResolvedTarget {
    let root = backend
        .instance
        .cfg
        .lock()
        .expect("instance cfg")
        .root
        .clone();
    ResolvedTarget {
        backend_id: BackendId(format!("test:{root}")),
        resolved_address: url.clone(),
    }
}

#[async_trait]
impl Layer for TestLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.shared.descriptor())
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let state = self.state.lock().expect("test-layer state");
        state
            .roots
            .iter()
            .filter(|entry| ovstorage_plugin::address::is_ancestor_or_self(&entry.root, url))
            .max_by_key(|entry| ovstorage_plugin::address::node_rank(&entry.root))
            .map(|entry| self.root_info(entry))
            .ok_or_else(|| {
                // The hint is load-bearing for the cross-`.so` test that
                // pins `next_action` surviving the plugin ABI.
                Error::new(
                    ErrorCode::NoRoute,
                    format!("test-plugin: no route matches {}", url.as_str()),
                )
                .with_next_action(TEST_LAYER_NO_ROUTE_NEXT_ACTION)
            })
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        // Register the subscriber before reading the snapshot so a root added
        // between the two is observed on the stream rather than lost.
        let (tx, rx) = mpsc::unbounded();
        let mut state = self.state.lock().expect("test-layer state");
        state.root_subs.push(tx);
        let stream: RootInfoUpdateStream = Box::pin(rx);
        let mut roots = Vec::with_capacity(state.roots.len());
        for entry in &state.roots {
            let backend = TestBackend {
                instance: entry.instance.clone(),
            };
            // Recorder, counters, and injection knobs are per-root state
            // (roots and instances are 1:1, keyed by root), so recording
            // inside the loop is once per call in each root's OWN log —
            // the count a test polls via one root's `__test_meta` stays 1
            // per host call. An injection knob on any root intentionally
            // fails the whole call, matching every other recorded slot.
            backend.enter_recorded("list_address_roots", Some(ObservedCall::ListAddressRoots))?;
            roots.push(self.root_info(entry));
        }
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
        let (backend, target) = self.target(&request.input.address)?;
        backend.stat(target, request.input.options, cancel).await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let (backend, target) = self.target(&request.input.address)?;
        backend.read(target, request.input.options, cancel).await
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let (backend, caps) = self.route(&request.input.address)?;
        let target = resolved_target(&backend, &request.input.address);
        match request.input.body {
            Body::Bytes(bytes) if caps.supports_write => {
                backend
                    .write(target, bytes, request.input.options, cancel)
                    .await
            }
            // Promote a buffered body to a one-chunk stream so
            // write-stream-only configs still service `Body::Bytes` callers.
            Body::Bytes(bytes) if caps.supports_write_stream => {
                let stream = BodyStream::from_iter(std::iter::once(Ok(bytes)));
                backend
                    .write_stream(target, stream, request.input.options, cancel)
                    .await
            }
            Body::Bytes(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: route does not support write",
            )),
            Body::LocalFile(_) | Body::Stream(_) if !caps.supports_write_stream => Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: route does not support write_stream",
            )),
            Body::LocalFile(path) => {
                let stream = body_stream_from_file(&path)?;
                backend
                    .write_stream(target, stream, request.input.options, cancel)
                    .await
            }
            Body::Stream(stream) => {
                backend
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
        let (backend, target) =
            self.gated_target(&request.input.address, "write_redirect", |caps| {
                caps.supports_write_redirect
            })?;
        backend
            .write_redirect(target, request.input.options, cancel)
            .await
    }

    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let (backend, target) = self.gated_target(
            &request.input.address,
            "write_redirect / continue_write",
            |caps| caps.supports_write_redirect,
        )?;
        backend
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
        let (backend, target) = self.gated_target(&request.input.address, "delete", |caps| {
            caps.supports_delete
        })?;
        backend.delete(target, request.input.options, cancel).await
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        // Gate on the source route's availability bit, like every other
        // mutating verb — otherwise a read-only route can be mutated through
        // `copy`, contradicting the capabilities it publishes.
        let (source_backend, source) =
            self.gated_target(&request.input.source, "copy", |caps| caps.supports_copy)?;
        let (dest_backend, destination) = self.target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_backend.instance, &dest_backend.instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: cross-instance copy is not supported",
            ));
        }
        source_backend
            .copy(source, destination, request.input.options, cancel)
            .await
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let (source_backend, source) =
            self.gated_target(&request.input.source, "rename", |caps| caps.supports_rename)?;
        let (dest_backend, destination) = self.target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_backend.instance, &dest_backend.instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: cross-instance rename is not supported",
            ));
        }
        source_backend
            .rename(source, destination, request.input.options, cancel)
            .await
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let allow_rewrite_emulation = request.input.options.allow_rewrite_emulation;
        let (backend, target) =
            self.gated_target(&request.input.address, "metadata updates", |caps| {
                caps.supports_native_metadata_patch
                    || (allow_rewrite_emulation && caps.supports_metadata_rewrite_emulation)
            })?;
        backend
            .update_metadata(target, request.input.options, cancel)
            .await
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let (backend, target) =
            self.gated_target(&request.input.address, "access checks", |caps| {
                caps.supports_access_check
            })?;
        backend
            .check_access(target, request.input.operations, cancel)
            .await
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        // Compat parity: the adapter services materialize via the backend
        // `read` + host-side temp staging, so the recorded call is `read`
        // on both paths. The staging happens here (plugin-side) because
        // the harness has no access to the host's staging helper.
        let (backend, target) = self.target(&request.input.address)?;
        match backend.read(target, request.input.options, cancel).await? {
            ReadResult::LocalDelegate(local) => Ok(local),
            ReadResult::Bytes { bytes, info } => Ok(LocalDelegate {
                path: stage_to_temp_file(&bytes)?,
                info,
                guard: None,
            }),
            ReadResult::Stream { mut stream, info } => {
                use futures::StreamExt as _;
                // Harness objects are small by construction; drain then
                // stage rather than streaming to disk.
                let mut bytes = Vec::new();
                while let Some(chunk) = stream.next().await {
                    bytes.extend_from_slice(&chunk?);
                }
                Ok(LocalDelegate {
                    path: stage_to_temp_file(&bytes)?,
                    info,
                    guard: None,
                })
            }
            ReadResult::Redirect(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: materialize on a redirect-configured root needs a host-side \
                 follower; compose a redirect-follower / byte-cache wrapper above this layer",
            )),
        }
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let prefix = request.input.prefix;
        let (backend, caps) = self.route(&prefix)?;
        if !caps.supports_list {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "test-plugin: route does not support list",
            ));
        }
        let target = resolved_target(&backend, &prefix);
        let options = request.input.options;
        let max_results = options.max_results;
        let page_token = options.page_token.clone();
        let recursive = options.recursive;
        // This scenario rejects pagination knobs; pull the full set, fold
        // flat directory markers / infer subdirectory kinds, then paginate
        // the folded result.
        let backend_options = ListOptions {
            max_results: None,
            page_token: None,
            ..options
        };
        let items = backend.list(target, backend_options, cancel).await?;
        let items = fold_markers_and_infer_subdir_kinds(
            &prefix,
            items,
            caps.has_real_directories,
            recursive,
        );
        paginate_list_items(items, max_results, page_token)
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let (backend, target) =
            self.gated_target(&request.input.address, "version listing", |caps| {
                caps.supports_version_listing
            })?;
        let items = backend
            .list_versions(target, request.input.options, cancel)
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
        let (backend, target) =
            self.gated_target(&request.input.address, "version listing", |caps| {
                caps.supports_version_listing
            })?;
        backend.get_latest_version(target, cancel).await
    }

    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let (backend, target) =
            self.gated_target(&request.input.prefix, "watch_directory", |caps| {
                caps.supports_watch_directory
            })?;
        let stream = backend
            .watch_directory(target, request.input.options, cancel)
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
        let (backend, target) =
            self.gated_target(&request.input.address, "create_directory", |caps| {
                caps.supports_create_directory
            })?;
        backend
            .create_directory(target, request.input.options, cancel)
            .await
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let (backend, target) =
            self.gated_target(&request.input.address, "delete_directory", |caps| {
                caps.supports_delete_directory
            })?;
        backend
            .delete_directory(target, request.input.options, cancel)
            .await
    }

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let _ = &cancel; // conformance plugin op: no async work to cancel.
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        // Validate the config and return the would-be connection without
        // installing anything.
        let persist = request.input.connection.persist;
        let display_name = request.input.connection.display_name.clone();
        let cfg = TestConfig::from_request(&request.input.connection)?;
        // Credential-validating probe: the knob rides the
        // probe request itself, so the gate checks the request's own bundle
        // against the request's own `require_token` — before any other
        // probe behavior.
        if cfg.probe_validates_token && !token_matches(&cfg, &request.input.connection.credentials)
        {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                "test-plugin: test_probe_validates_token: probed credentials do not carry \
                 the required 'token'",
            ));
        }
        Ok(Connection {
            id: ConnectionId(fresh_id(BACKEND_KIND)),
            backend_kind: BACKEND_KIND.to_string(),
            display_name: display_name.unwrap_or_else(|| "Test backend".to_string()),
            source: ConnectionSource::Runtime { persisted: persist },
            capabilities: cfg.capabilities.clone(),
            current_addresses: vec![cfg.root],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: Some(SystemTime::now()),
            user_metadata: UserMetadata::new(),
        })
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let _ = &cancel; // conformance plugin op: no async work to cancel.
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let persist = request.input.connection.persist;
        self.install_connection(
            request.input.connection,
            ConnectionSource::Runtime { persisted: persist },
        )
    }

    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        if key.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        {
            // Mutation and both announcements under one guard — see
            // `install_connection` for why, and for why `Ordered` is not used.
            // An unknown id is rejected before anything is announced, so no
            // subscriber sees a `Removed` for a connection it never saw
            // `Added`.
            let mut state = self.state.lock().expect("test-layer state");
            let index = state
                .connections
                .iter()
                .position(|connection| connection.id == key.input.id)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
            state.connections.remove(index);
            let mut removed_roots = Vec::new();
            state.roots.retain(|entry| {
                if entry.connection_id == key.input.id {
                    removed_roots.push(self.root_info(entry));
                    false
                } else {
                    true
                }
            });
            if !removed_roots.is_empty() {
                state.announce_roots(RootInfoChange::Removed(removed_roots));
            }
            state.announce_connection(ConnectionChange::Removed { id: key.input.id });
        }
        Ok(())
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        // Subscribe before snapshotting for the same at-least-once
        // discipline as `list_address_roots`.
        let (tx, rx) = mpsc::unbounded();
        let mut state = self.state.lock().expect("test-layer state");
        state.conn_subs.push(tx);
        let stream: ConnectionUpdateStream = Box::pin(rx);
        Ok((
            ConnectionSnapshot {
                connections: state.connections.clone(),
                updates: true,
            },
            Some(stream),
        ))
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let connection = self.connection_for_key(&request.input.key)?;
        self.shared
            .update_credentials(&connection, request.input.credentials, cancel)
            .await?;
        Ok(connection)
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.key.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let mut state = self.state.lock().expect("test-layer state");
        let connection = state
            .connections
            .iter_mut()
            .find(|connection| connection.id == request.input.key.id)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "connection not found"))?;
        if let Some(display_name) = request.input.patch.display_name {
            connection.display_name = display_name;
        }
        for (key, value) in request.input.patch.user_metadata {
            match value {
                Some(value) => {
                    connection.user_metadata.insert(key, value);
                }
                None => {
                    connection.user_metadata.remove(&key);
                }
            }
        }
        Ok(connection.clone())
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let connection = self.connection_for_key(&request.input.key)?;
        // `TestFactory::authenticate` owns the flow synthesis, counter bumps,
        // and host-callback driving.
        self.shared
            .authenticate(connection, request.input.capability, cancel)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn layer_with_root(root: &str) -> TestLayer {
        let factory = TestLayerFactory::default();
        let layer = TestLayer {
            name: "test".to_string(),
            shared: factory.shared,
            state: Mutex::new(LayerState::default()),
        };
        let mut config = HashMap::new();
        config.insert("test_root".into(), ConfigValue::String(root.into()));
        layer
            .install_connection(
                ConnectionRequest {
                    backend_kind: BACKEND_KIND.into(),
                    config,
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
                ConnectionSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
            )
            .expect("install static connection");
        layer
    }

    fn runtime_connection(root: &str) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("test_root".into(), ConfigValue::String(root.into()));
        ConnectionRequest {
            backend_kind: BACKEND_KIND.into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    /// Poll one already-queued item off an update stream.
    ///
    /// Every announcement runs synchronously before the slot returns, so the
    /// item is queued by the time the caller gets here; `now_or_never` reads it
    /// without blocking on a stream that would otherwise never end. `None`
    /// means nothing was announced.
    fn queued<T>(
        stream: Option<impl futures::Stream<Item = Result<T>> + Unpin>,
    ) -> Option<Result<T>> {
        use futures::FutureExt as _;
        use futures::StreamExt as _;
        stream
            .expect("update stream present")
            .next()
            .now_or_never()
            .flatten()
    }

    /// `install_connection` announces the connection and its root.
    ///
    /// The announcements cannot be tested for "inside the guard" at runtime —
    /// see [`LayerState`]: `announce_roots`/`announce_connection` are methods on
    /// the guarded state, so announcing outside the critical section does not
    /// compile, and there is nothing left for a runtime assertion to catch.
    #[tokio::test]
    async fn install_connection_announces_the_connection_and_its_root() {
        let layer = layer_with_root("test://demo/");
        let (_conn_snapshot, conn_updates) = layer
            .list_connections(&Extensions::new(), None)
            .await
            .expect("subscribe to connection updates");
        let (_root_snapshot, root_updates) = layer
            .list_address_roots(&Extensions::new(), None)
            .await
            .expect("subscribe to root updates");

        let installed = layer
            .install_connection(
                runtime_connection("test://second/"),
                ConnectionSource::Runtime { persisted: false },
            )
            .expect("install the runtime connection");

        let conn_event = queued(conn_updates);
        assert!(
            matches!(conn_event, Some(Ok(ConnectionChange::Added(ref c))) if c.id == installed.id),
            "installing a connection must announce ConnectionChange::Added, got {conn_event:?}",
        );
        let root_event = queued(root_updates);
        let announced = match root_event {
            Some(Ok(RootInfoChange::Added(ref roots))) => {
                roots.iter().any(|r| r.root.as_str() == "test://second/")
            }
            _ => false,
        };
        assert!(
            announced,
            "installing a connection must announce its root, got {root_event:?}",
        );
    }

    /// Removing an id this layer never installed is rejected before anything is
    /// announced, so no subscriber sees a `Removed` for a connection it never
    /// saw `Added`.
    #[tokio::test]
    async fn removing_an_unknown_connection_is_not_found_and_announces_nothing() {
        let layer = layer_with_root("test://demo/");
        let (_conn_snapshot, conn_updates) = layer
            .list_connections(&Extensions::new(), None)
            .await
            .expect("subscribe to connection updates");

        let err = layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "test".to_string(),
                    id: ConnectionId("never-installed".to_string()),
                }),
                None,
            )
            .await
            .expect_err("removing an unknown connection must fail");
        assert_eq!(err.code(), ErrorCode::NotFound);

        let conn_event = queued(conn_updates);
        assert!(
            conn_event.is_none(),
            "a rejected removal must announce nothing, got {conn_event:?}",
        );
    }

    /// `remove_connection` announces `Removed` on both streams.
    #[tokio::test]
    async fn remove_connection_announces_on_both_streams() {
        let layer = layer_with_root("test://demo/");
        let installed = layer
            .install_connection(
                runtime_connection("test://second/"),
                ConnectionSource::Runtime { persisted: false },
            )
            .expect("install the runtime connection");

        // Subscribe after the install so each stream carries only the removal.
        let (_conn_snapshot, conn_updates) = layer
            .list_connections(&Extensions::new(), None)
            .await
            .expect("subscribe to connection updates");
        let (_root_snapshot, root_updates) = layer
            .list_address_roots(&Extensions::new(), None)
            .await
            .expect("subscribe to root updates");

        layer
            .remove_connection(
                Request::new(ConnectionKey {
                    target: "test".to_string(),
                    id: installed.id.clone(),
                }),
                None,
            )
            .await
            .expect("remove the connection");

        let conn_event = queued(conn_updates);
        assert!(
            matches!(
                conn_event,
                Some(Ok(ConnectionChange::Removed { ref id })) if *id == installed.id
            ),
            "removing a connection must announce ConnectionChange::Removed, got {conn_event:?}",
        );
        let root_event = queued(root_updates);
        let retracted = match root_event {
            Some(Ok(RootInfoChange::Removed(ref roots))) => {
                roots.iter().any(|r| r.root.as_str() == "test://second/")
            }
            _ => false,
        };
        assert!(
            retracted,
            "removing a connection must announce RootInfoChange::Removed for its root, got \
             {root_event:?}",
        );
    }

    #[test]
    fn routes_by_longest_prefix_and_rejects_unrouted() {
        let layer = layer_with_root("test://demo/");
        let owned = Url::parse("test://demo/a/b").unwrap();
        assert!(layer.route(&owned).is_ok());
        let unrouted = Url::parse("test://other/x").unwrap();
        let err = match layer.route(&unrouted) {
            Ok(_) => panic!("expected NoRoute for unrouted address"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::NoRoute);
    }

    #[tokio::test]
    async fn static_config_installs_connection_and_root() {
        let layer = layer_with_root("test://demo/");
        let (snapshot, _) = layer
            .list_connections(&Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.connections.len(), 1);
        let (roots, stream) = layer
            .list_address_roots(&Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(roots.roots.len(), 1);
        assert_eq!(roots.roots[0].root.as_str(), "test://demo/");
        assert!(stream.is_some());
    }

    /// `materialize` is serviced through `read`, so the recorded call is
    /// `read`, and returns a readable staged temp file.
    #[tokio::test]
    async fn materialize_stages_via_read_and_records_read() {
        let layer = layer_with_root("test://demo/");
        let address = Url::parse("test://demo/staged.txt").unwrap();
        layer
            .write(
                Request::new(WriteRequest {
                    address: address.clone(),
                    body: Body::Bytes(b"staged-bytes".to_vec()),
                    options: WriteOptions::default(),
                }),
                None,
            )
            .await
            .expect("seed write");
        let recorder = layer
            .shared
            .recorder_for(&Url::parse("test://demo/").unwrap())
            .expect("recorder");
        recorder.clear();

        let delegate = layer
            .materialize(
                Request::new(ReadRequest {
                    address,
                    options: ReadOptions::default(),
                }),
                None,
            )
            .await
            .expect("materialize stages the object");
        let staged = std::fs::read(&delegate.path).expect("staged file readable");
        assert_eq!(staged, b"staged-bytes");
        std::fs::remove_file(&delegate.path).ok();

        let recorded: Vec<&str> = recorder
            .snapshot()
            .iter()
            .map(|call| call.method_name())
            .collect();
        assert_eq!(
            recorded,
            vec!["read"],
            "materialize must record its delegated `read`"
        );
    }
}
