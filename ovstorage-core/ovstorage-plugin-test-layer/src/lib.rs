// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal Layer test backend, exported as a cdylib via the
//! `ovstorage_layer_plugin!` macro. It exercises the plugin macro and native
//! host loader end-to-end: a host can load this `mini://` backend alongside
//! the built-in `FileBackend` in one Stack and round-trip `write`, `read`, and
//! `stat` against each.
//!
//! Storage is an in-memory map; the backend implements the slots the
//! mixed-layer Stack test needs (identity, `root_info_for`, `list_address_roots`,
//! `stat`, `read`, `write`) plus runtime connection management
//! (`add_connection`/`list_connections`) so a host can point it at a root
//! through a connection, mirroring the built-in `FileBackend`.
//!
//! It additionally ships cheap scripted implementations of the remaining
//! operational slots (`materialize`, `copy`/`rename`, `update_metadata`,
//! `check_access`, `list_versions`, `get_latest_version`,
//! `create_directory`/`delete_directory`, `probe`, `remove_connection`,
//! `update_connection_credentials`/`update_connection_attributes`,
//! `authenticate_connection`) so the characterization suite can drive
//! **every** `LoadedV2Layer` trait method across the FFI boundary. The cdylib
//! also advertises `mini-wrapper` (wrapper), `mini-router` (router), and
//! `mini-auth` (auth-capable wrapper) kinds so a host can exercise v2
//! composition, including listener authentication.
//!
//! A `#[no_mangle]` symbol, `ovstorage_test_export_malformed_descriptor`,
//! hands a host a `LayerHandle` whose `descriptor` slot writes an
//! ill-formed-UTF-8 `display_name`, forcing the host's
//! `layer_kind_descriptor_from_ffi` decode-error / fallback path. The
//! malformed bytes are injected **only at the FFI boundary** (a bespoke
//! `descriptor` thunk builds the `ffi::Str` from leaked raw bytes) so no
//! invalid Rust `String` is ever constructed. See the "malformed-descriptor
//! export" section near the bottom of this file.
//!
//! A second `#[no_mangle]` symbol, `ovstorage_test_export_stack`, is
//! additionally hand-rolled outside the plugin manifest/init handshake
//! above: `ovstorage/tests/handoff_cross_binary.rs` `dlopen`s this cdylib
//! directly and resolves it by name, so the exported `ffi::LayerHandle`
//! genuinely carries a second linked image's `LAYER_VTABLE` — proving the
//! cross-binary handoff (`export_handle` / `import_handle`)
//! takes the foreign-wrap path rather than the same-binary fast path. See
//! the "Cross-binary export symbol" section near the bottom of this file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::time::SystemTime;

use async_trait::async_trait;
use futures::channel::mpsc;
use ovstorage_plugin::*;

/// Backend layer kind this cdylib ships.
pub const KIND: &str = "mini-v2";
/// Wrapper layer kind this cdylib ships (composition characterization).
pub const WRAPPER_KIND: &str = "mini-wrapper";
/// Router layer kind this cdylib ships (composition characterization).
pub const ROUTER_KIND: &str = "mini-router";
/// Auth-capable wrapper kind this cdylib ships (listener-auth characterization).
pub const AUTH_KIND: &str = "mini-auth";
/// URL scheme the backend owns by default.
pub const DEFAULT_ROOT: &str = "mini://store/";
/// Unique-suffix source for `materialize` scratch files (see
/// [`MiniV2Backend::materialize`]).
static MATERIALIZE_SEQ: AtomicU64 = AtomicU64::new(0);

fn descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: KIND.to_string(),
        layer_type: LayerType::Backend,
        display_name: "Mini v2 test backend".to_string(),
        description: Some("In-memory ABI-v2 test backend".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: true,
        auth_capable: false,
        supports_user_metadata: true,
    }
}

fn wrapper_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: WRAPPER_KIND.to_string(),
        layer_type: LayerType::Wrapper,
        display_name: "Mini v2 test wrapper".to_string(),
        description: Some("Pass-through ABI-v2 test wrapper".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: false,
    }
}

fn router_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: ROUTER_KIND.to_string(),
        layer_type: LayerType::Router,
        display_name: "Mini v2 test router".to_string(),
        description: Some("Owns-nothing ABI-v2 test router".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        supports_user_metadata: false,
        auth_capable: false,
    }
}

fn auth_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: AUTH_KIND.to_string(),
        layer_type: LayerType::Wrapper,
        display_name: "Mini v2 test auth layer".to_string(),
        description: Some("Credential-decoding ABI-v2 listener auth wrapper".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: true,
        supports_user_metadata: false,
    }
}

/// The base descriptor for the malformed-descriptor rig (the produce side of
/// the host `layer_kind_descriptor_from_ffi` decode-error characterization).
/// **Every field here is valid** — including `display_name` — so no ill-formed
/// Rust `String` ever exists: the non-UTF-8 `display_name` that actually drives
/// the host decoder's error path is injected only at the FFI boundary, by
/// [`malformed_descriptor_thunk`]. The `kind` is deliberately a *valid,
/// distinct* string (`mini-v2-live`) so a test can tell a successful decode
/// (would surface `mini-v2-live`) from the decode-failure fallback.
fn malformed_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: "mini-v2-live".to_string(),
        layer_type: LayerType::Backend,
        display_name: "Mini v2 live test backend".to_string(),
        description: Some("In-memory ABI-v2 test backend".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: true,
        auth_capable: false,
        supports_user_metadata: true,
    }
}

fn object_info(address: Url, size: u64) -> ObjectInfo {
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: Some(format!("size:{size}")),
        version: None,
        size: Some(size),
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn capabilities() -> Capabilities {
    Capabilities {
        supports_write: true,
        supports_list: true,
        // The layer implements both verbs; these report availability, not a
        // server-side mechanism.
        supports_copy: true,
        supports_rename: true,
        ..Capabilities::empty()
    }
}

/// Factory for `MiniV2Backend`. Reads an optional `root` config key
/// (default [`DEFAULT_ROOT`]).
#[derive(Default)]
pub struct MiniV2Factory;

#[async_trait]
impl BackendFactory for MiniV2Factory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor()
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let root_raw = match config.get("root") {
            Some(ConfigValue::String(root)) => root.as_str(),
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "mini-v2 backend `root` must be a string",
                ));
            }
            None => DEFAULT_ROOT,
        };
        let root = Url::parse(root_raw)
            .map_err(|e| Error::new(ErrorCode::InvalidArgument, format!("invalid root: {e}")))?;
        Ok(Arc::new(MiniV2Backend {
            name: name.to_string(),
            state: Mutex::new(MiniState {
                roots: vec![MiniRoot {
                    url: root,
                    connection_id: None,
                }],
                ..MiniState::default()
            }),
            store: Mutex::new(HashMap::new()),
            snapshot_gate: Mutex::new(None),
        }))
    }
}

/// A served root plus the connection that contributed it.
///
/// `create_backend`'s configured root carries `None` and is never retracted;
/// roots added by `add_connection` carry that connection's id so
/// `remove_connection` can retract exactly its own rather than guessing from
/// URL equality (a connection may legally point at the configured root).
/// Mirrors `RootEntry` in the sibling fixture,
/// `ovstorage-plugin-test/src/layer.rs`.
#[derive(Clone)]
struct MiniRoot {
    url: Url,
    connection_id: Option<ConnectionId>,
}

/// Roots, connections, **and the update-stream subscribers**, under one guard.
///
/// A connection touches both lists, so they share one guard: the mutation and
/// the announcements that describe it occupy a single critical section.
///
/// The subscriber lists live in here, rather than beside this struct, for a
/// stronger reason: it is the only handle on the senders, so the *only* way to
/// reach [`announce_roots`](Self::announce_roots) /
/// [`announce_connection`](Self::announce_connection) is to be holding this
/// guard. An announcement written outside the critical section that commits the
/// change it describes does not compile. Announcing is a capability the commit
/// hands out, which is the property `ovstorage_layer::ordered::Ordered` offers
/// production layers; see [`MiniV2Backend::add_connection`] for why `Ordered`
/// itself does not fit here.
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
struct MiniState {
    /// Served roots: the `create_backend` config root plus any added at
    /// runtime via `add_connection`. With empty config the root falls back to
    /// [`DEFAULT_ROOT`], and hosts can point the Layer at a real root through a
    /// connection.
    ///
    /// One entry per *contributor*, so the same URL can appear more than once
    /// when two connections are configured with it. The observable surface —
    /// the snapshot and the `Added`/`Removed` stream — is per URL: see
    /// [`Self::serves`].
    roots: Vec<MiniRoot>,
    connections: Vec<Connection>,
    /// Live subscribers to the `list_address_roots` update stream. Each
    /// `list_address_roots` call registers one; `add_connection` announces a
    /// `RootInfoChange::Added` to all of them so a host exercises the FFI
    /// root-update bridge (a root discovered after the initial snapshot).
    root_subs: Vec<mpsc::UnboundedSender<Result<RootInfoChange>>>,
    /// Live subscribers to the `list_connections` update stream, driven the
    /// same way for the connection-update bridge.
    conn_subs: Vec<mpsc::UnboundedSender<Result<ConnectionChange>>>,
}

impl MiniState {
    /// Whether any surviving entry contributes `url`.
    ///
    /// Root multiplicity is internal: two connections configured with the same
    /// URL are two contributors to one served root. `Added` is announced only
    /// when a URL becomes served and `Removed` only when its last contributor
    /// leaves, so a host tracking roots by URL never sees a retraction for one
    /// this backend still answers for.
    fn serves(&self, url: &Url) -> bool {
        self.roots.iter().any(|root| root.url == *url)
    }

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

struct MiniV2Backend {
    name: String,
    state: Mutex<MiniState>,
    store: Mutex<HashMap<String, Vec<u8>>>,
    /// Test-only rendezvous placed *between* subscriber registration and the
    /// snapshot read in `list_address_roots`, so a test can inject a root-add
    /// into that exact window and prove the ordering keeps it at-least-once.
    /// Always `None` in production — never armed outside the crate's own tests.
    snapshot_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
}

impl MiniV2Backend {
    fn owns(&self, url: &Url) -> bool {
        self.state
            .lock()
            .unwrap()
            .roots
            .iter()
            .any(|root| ovstorage_plugin::address::is_ancestor_or_self(&root.url, url))
    }

    fn require_owned(&self, url: &Url) -> Result<()> {
        if self.owns(url) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::NotFound,
                "address not owned by backend",
            ))
        }
    }

    /// The `RootInfo` a subscriber and a snapshot see for one served root.
    ///
    /// Carries the contributing connection's id and provenance, so the host can
    /// tell a runtime-contributed root from the `create_backend` configured
    /// one. Matches how the sibling fixture builds `RootInfo`
    /// (`ovstorage-plugin-test/src/layer.rs`).
    fn root_info(&self, root: &MiniRoot) -> RootInfo {
        let source = match &root.connection_id {
            Some(connection_id) => RouteSource::ConnectionContributed {
                connection_id: connection_id.clone(),
            },
            None => RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
        };
        RootInfo {
            root: root.url.clone(),
            display_name: Some("Mini v2 store".to_string()),
            layer_kind: KIND.to_string(),
            connection_id: root.connection_id.clone(),
            owning_target: None,
            capabilities: capabilities(),
            range_read_strategy: RangeReadStrategy::Native,
            source,
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::new(),
        }
    }

    /// The stored byte length of `url`, or 0 when absent — used by the
    /// scripted metadata slots to fill a plausible `size`.
    fn stored_size(&self, url: &Url) -> u64 {
        self.store
            .lock()
            .unwrap()
            .get(url.as_str())
            .map_or(0, |bytes| bytes.len() as u64)
    }

    /// A synthetic [`Connection`] carrying the given id and addresses — the
    /// scripted `probe`/`update_connection_*` slots return one without
    /// mutating state, so a host can drive `connection_from_ffi` decoding.
    fn synthetic_connection(&self, id: String, addresses: Vec<Url>) -> Connection {
        Connection {
            id: ConnectionId(id),
            backend_kind: KIND.to_string(),
            display_name: "Mini v2".to_string(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: capabilities(),
            current_addresses: addresses,
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: Some(SystemTime::now()),
            user_metadata: UserMetadata::new(),
        }
    }
}

#[async_trait]
impl Layer for MiniV2Backend {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor()
    }

    async fn root_info_for(
        &self,
        url: &Url,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let root = self
            .state
            .lock()
            .unwrap()
            .roots
            .iter()
            .find(|root| ovstorage_plugin::address::is_ancestor_or_self(&root.url, url))
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "address not owned by backend"))?;
        Ok(self.root_info(&root))
    }

    async fn list_address_roots(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        // Register the subscriber before reading the snapshot so a root added
        // between the two is observed on the stream rather than lost.
        // `list_connections` below already subscribes before cloning its snapshot.
        let (tx, rx) = mpsc::unbounded();
        self.state.lock().unwrap().root_subs.push(tx);
        let stream: RootInfoUpdateStream = Box::pin(rx);
        // Test-only: pause here — after registering the subscriber, before
        // taking the snapshot — so a test can add a root into that window. A
        // no-op in production (the gate is never armed). Moving the subscriber
        // registration below the snapshot (the pre-89ef4844 order) would drop
        // such a root, which the race regression test asserts against.
        if let Some(gate) = self.snapshot_gate.lock().unwrap().clone() {
            gate.wait();
            gate.wait();
        }
        // One `RootInfo` per served URL, not per contributor: two connections
        // configured with the same root are one served root to a host, and
        // `Added`/`Removed` are announced on that same per-URL basis.
        let state = self.state.lock().unwrap();
        let mut seen: Vec<&Url> = Vec::new();
        let mut roots = Vec::new();
        for root in &state.roots {
            if seen.contains(&&root.url) {
                continue;
            }
            seen.push(&root.url);
            roots.push(self.root_info(root));
        }
        drop(state);
        Ok((
            RootInfoSnapshot {
                roots,
                updates: true,
            },
            Some(stream),
        ))
    }

    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        if request.input.target != self.name {
            return Err(Error::new(ErrorCode::NotFound, "target layer not found"));
        }
        let root = match request.input.connection.config.get("root") {
            Some(ConfigValue::String(raw)) => Url::parse(raw).map_err(|e| {
                Error::new(ErrorCode::InvalidArgument, format!("invalid root: {e}"))
            })?,
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "mini-v2 connection `root` must be a string",
                ));
            }
            None => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "mini-v2 connection needs a `root`",
                ));
            }
        };
        let connection = Connection {
            id: ConnectionId(routing::fresh_id(KIND)),
            backend_kind: KIND.to_string(),
            display_name: request
                .input
                .connection
                .display_name
                .unwrap_or_else(|| "Mini v2".to_string()),
            source: ConnectionSource::Runtime {
                persisted: request.input.connection.persist,
            },
            capabilities: capabilities(),
            current_addresses: vec![root.clone()],
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: Some(SystemTime::now()),
            user_metadata: UserMetadata::new(),
        };
        {
            // The mutation and BOTH emissions happen under one `state` guard.
            // Emitting after it closes lets a concurrent `remove_connection`
            // commit and emit `Removed` in the window, delivering it to a
            // subscriber ahead of this `Added` — an order no host can
            // reconcile. Holding the guard across the sends is safe because
            // these are unbounded channels: `unbounded_send` never blocks.
            //
            // That "emit under the lock, on a non-blocking sender" discipline
            // is what `ovstorage_layer::ordered::Ordered` packages for
            // production layers, and it is deliberately not used here:
            // `Ordered` carries exactly one sender while this critical section
            // emits on two, and its `Emitter` trait is sealed to the tokio
            // channel types whereas these update streams are
            // `futures::channel::mpsc` and lossless — migrating would mean
            // bounded-lossy delivery with `Lagged` handling in a conformance
            // fixture whose subscribers rely on losslessness.
            let mut state = self.state.lock().unwrap();
            // A URL already served by another contributor stays served; only
            // its contributor count changes, so there is no new root to
            // announce (`remove_connection` retracts on the same basis).
            let newly_served = !state.serves(&root);
            let entry = MiniRoot {
                url: root,
                connection_id: Some(connection.id.clone()),
            };
            let root_added = RootInfoChange::Added(vec![self.root_info(&entry)]);
            state.connections.push(connection.clone());
            state.roots.push(entry);
            // Announce so a host watching the update streams observes the new
            // root/connection *after* its initial snapshot — the end-to-end
            // exercise of the v2 FFI update-stream bridge. `announce_*` are
            // methods on the guarded state, so these cannot be moved out of
            // this critical section without a compile error.
            if newly_served {
                state.announce_roots(root_added);
            }
            state.announce_connection(ConnectionChange::Added(connection.clone()));
        }
        Ok(connection)
    }

    async fn list_connections(
        &self,
        _cx: &Extensions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        let (tx, rx) = mpsc::unbounded();
        let mut state = self.state.lock().unwrap();
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

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address;
        self.require_owned(&address)?;
        let store = self.store.lock().unwrap();
        match store.get(address.as_str()) {
            Some(bytes) => Ok(object_info(address, bytes.len() as u64)),
            None => Err(Error::new(ErrorCode::NotFound, "object not found")),
        }
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let address = request.input.address;
        self.require_owned(&address)?;
        // Honor the cancel token so the host's cancel marshalling
        // (CancelTokenFFI -> CancelTokenLocal) is exercised end to end.
        if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
            return Err(Error::new(ErrorCode::Cancelled, "read cancelled"));
        }
        let bytes = {
            let store = self.store.lock().unwrap();
            match store.get(address.as_str()) {
                Some(bytes) => bytes.clone(),
                None => return Err(Error::new(ErrorCode::NotFound, "object not found")),
            }
        };
        let info = object_info(address.clone(), bytes.len() as u64);
        // A `/stream` suffix returns the bytes as a chunk stream, so the
        // host's `ReadResult::Stream` marshalling path is exercised
        // (otherwise only the buffered `Bytes` variant is).
        if address.as_str().ends_with("/stream") {
            let chunks: Vec<Result<bytes::Bytes>> = bytes
                .chunks(4)
                .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
                .collect();
            let stream: ReadStream = Box::pin(futures::stream::iter(chunks));
            Ok(ReadResult::Stream { stream, info })
        } else {
            Ok(ReadResult::Bytes { bytes, info })
        }
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let address = request.input.address;
        self.require_owned(&address)?;
        let bytes = match request.input.body {
            Body::Bytes(bytes) => bytes,
            Body::LocalFile(path) => std::fs::read(&path)
                .map_err(|e| Error::new(ErrorCode::Internal, format!("read local file: {e}")))?,
            Body::Stream(mut stream) => {
                let mut buf = Vec::new();
                while let Some(chunk) = stream.next_chunk() {
                    buf.extend_from_slice(&chunk?);
                }
                buf
            }
        };
        let size = bytes.len() as u64;
        self.store
            .lock()
            .unwrap()
            .insert(address.as_str().to_string(), bytes);
        Ok(WriteResult {
            info: object_info(address, size),
        })
    }

    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        self.write(request, cancel).await
    }

    // ---- Scripted slots for the characterization suite ---------------
    // Cheap, in-memory implementations of the remaining operational slots so a
    // host can drive every `LoadedV2Layer` trait method across the FFI vtable.

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let address = request.input.address;
        self.require_owned(&address)?;
        if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
            return Err(Error::new(ErrorCode::Cancelled, "materialize cancelled"));
        }
        let bytes = {
            let store = self.store.lock().unwrap();
            match store.get(address.as_str()) {
                Some(bytes) => bytes.clone(),
                None => return Err(Error::new(ErrorCode::NotFound, "object not found")),
            }
        };
        // The plugin has no host-side cache lease to pin (that is
        // `ByteCacheWrapper`'s concern), so materialize hands back a plain
        // scratch file with `guard: None`. A unique per-call name avoids
        // cross-test collisions in the shared temp dir.
        let seq = MATERIALIZE_SEQ.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = std::env::temp_dir().join(format!(
            "mini-v2-materialize-{}-{seq}.bin",
            std::process::id()
        ));
        std::fs::write(&path, &bytes)
            .map_err(|e| Error::new(ErrorCode::Internal, format!("write scratch file: {e}")))?;
        Ok(LocalDelegate {
            path,
            info: object_info(address, bytes.len() as u64),
            guard: None,
        })
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let CopyRequest {
            source,
            destination,
            ..
        } = request.input;
        self.require_owned(&source)?;
        self.require_owned(&destination)?;
        let bytes = {
            let store = self.store.lock().unwrap();
            match store.get(source.as_str()) {
                Some(bytes) => bytes.clone(),
                None => return Err(Error::new(ErrorCode::NotFound, "copy source not found")),
            }
        };
        let size = bytes.len() as u64;
        self.store
            .lock()
            .unwrap()
            .insert(destination.as_str().to_string(), bytes);
        Ok(WriteStep::Done(WriteResult {
            info: object_info(destination, size),
        }))
    }

    async fn rename(
        &self,
        request: Request<RenameRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let RenameRequest {
            source,
            destination,
            ..
        } = request.input;
        self.require_owned(&source)?;
        self.require_owned(&destination)?;
        let bytes = {
            let mut store = self.store.lock().unwrap();
            match store.remove(source.as_str()) {
                Some(bytes) => bytes,
                None => return Err(Error::new(ErrorCode::NotFound, "rename source not found")),
            }
        };
        self.store
            .lock()
            .unwrap()
            .insert(destination.as_str().to_string(), bytes);
        Ok(())
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let address = request.input.address;
        self.require_owned(&address)?;
        let size = self.stored_size(&address);
        Ok(BackendItemInfo::from(object_info(address, size)))
    }

    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        self.require_owned(&request.input.address)?;
        Ok(AccessDecision {
            allowed: true,
            denied_ops: AccessOps::default(),
            reason: None,
        })
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let address = request.input.address;
        self.require_owned(&address)?;
        let size = self.stored_size(&address);
        Ok(VersionPage {
            items: vec![object_info(address, size)],
            next_page_token: None,
        })
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address;
        self.require_owned(&address)?;
        let size = {
            let store = self.store.lock().unwrap();
            match store.get(address.as_str()) {
                Some(bytes) => bytes.len() as u64,
                None => return Err(Error::new(ErrorCode::NotFound, "object not found")),
            }
        };
        Ok(object_info(address, size))
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        self.require_owned(&request.input.address)?;
        Ok(BackendItemInfo {
            kind: ObjectKind::Directory,
            ..BackendItemInfo::default()
        })
    }

    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        self.require_owned(&request.input.address)?;
        Ok(())
    }

    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let addresses = match request.input.connection.config.get("root") {
            Some(ConfigValue::String(raw)) => vec![Url::parse(raw).map_err(|e| {
                Error::new(ErrorCode::InvalidArgument, format!("invalid root: {e}"))
            })?],
            _ => Vec::new(),
        };
        Ok(self.synthetic_connection(routing::fresh_id(KIND), addresses))
    }

    /// Retract a runtime connection: drop it, drop the roots it contributed,
    /// and announce both.
    ///
    /// Every `Added` this layer announces earns a matching retraction, so a
    /// host driving the update-stream bridge sees both directions of it.
    ///
    /// Four cases the announcements distinguish:
    ///
    /// * **An id this layer never announced** — return `Ok(())` and announce
    ///   nothing. Removal stays idempotent (`loaded_plugin_characterization`
    ///   removes `"absent"` and expects success, which is a real statement
    ///   about the unit-result decode path), but a `Removed` for a connection
    ///   no subscriber ever saw `Added` is a phantom event a host cannot
    ///   reconcile. The sibling `TestLayer` instead returns `NotFound`; this
    ///   fixture's idempotence is characterized by that test, so it stays
    ///   idempotent and simply says nothing.
    /// * **An existing connection contributing no roots** — still announce the
    ///   connection removal. Only the *root* half is conditional.
    /// * **A root another connection still contributes** — announce
    ///   `RootInfoChange::Updated` naming the surviving contributor, not
    ///   `Removed`. Roots are matched by contributing connection id, not URL,
    ///   so this connection's own entry goes; but two connections may be
    ///   configured with the same URL. Retracting a root the backend still
    ///   serves would tell a host tracking roots by URL that an address is gone
    ///   while `root_info_for` keeps answering for it, and staying silent would
    ///   leave that host holding a `connection_id` this call just announced as
    ///   removed. The configured root is covered by the same rule, since it
    ///   carries no connection id and so always survives as a contributor.
    /// * **A root whose announced contributor is unchanged** — announce
    ///   nothing. Only the first entry per URL reaches a subscriber, so
    ///   removing any other contributor is invisible.
    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        _cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let id = key.input.id;
        // Mutation and both announcements under one guard — see
        // `add_connection` for why, and for why `Ordered` is not used.
        let mut state = self.state.lock().unwrap();
        if !state.connections.iter().any(|c| c.id == id) {
            return Ok(());
        }
        state.connections.retain(|c| c.id != id);
        // The entry a subscriber currently holds for each URL this connection
        // contributes. A snapshot announces the first entry per URL, so that is
        // the identity to compare against once the removal lands.
        let mut held: Vec<MiniRoot> = Vec::new();
        for root in &state.roots {
            if root.connection_id.as_ref() != Some(&id) || held.iter().any(|h| h.url == root.url) {
                continue;
            }
            let announced = state
                .roots
                .iter()
                .find(|candidate| candidate.url == root.url)
                .expect("the URL was just found in this list");
            held.push(announced.clone());
        }
        state
            .roots
            .retain(|root| root.connection_id.as_ref() != Some(&id));

        let mut retracted = Vec::new();
        let mut updated = Vec::new();
        for prior in &held {
            match state.roots.iter().find(|root| root.url == prior.url) {
                // No contributor remains: the URL drops out of service.
                None => retracted.push(self.root_info(prior)),
                // Still served, but under a different contributor than the one
                // a subscriber holds. Announce the survivor so the stream and a
                // fresh snapshot agree on which connection backs the root.
                Some(survivor) if survivor.connection_id != prior.connection_id => {
                    updated.push(self.root_info(survivor));
                }
                // Still served under the same contributor: nothing changed.
                Some(_) => {}
            }
        }
        if !retracted.is_empty() {
            state.announce_roots(RootInfoChange::Removed(retracted));
        }
        if !updated.is_empty() {
            state.announce_roots(RootInfoChange::Updated(updated));
        }
        state.announce_connection(ConnectionChange::Removed { id });
        Ok(())
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        Ok(self.synthetic_connection(request.input.key.id.0, Vec::new()))
    }

    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        Ok(self.synthetic_connection(request.input.key.id.0, Vec::new()))
    }

    async fn authenticate_connection(
        &self,
        _request: Request<AuthenticateRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let events = vec![Ok(AuthEvent::Progress {
            message: "authenticating".to_string(),
        })];
        Ok(Box::new(events.into_iter()) as AuthEventStream)
    }
}

/// Listener-auth fixture that exercises credential decoding and the
/// DOWN-stamped principal contract across a real cdylib boundary: raw
/// credential in, `ext::PRINCIPAL_ID` stamped DOWN on every delegation.
struct MiniAuth {
    name: String,
    inner: LayerHandle,
}

impl MiniAuth {
    fn principal(credential: &ovstorage_authz_context::AuthCredential) -> Result<String> {
        if let Some(forwarded) = &credential.forwarded {
            let mut identities = forwarded.values.iter().map(|(_, value)| value.as_str());
            if let Some(identity) = identities.next() {
                if identities.next().is_some() {
                    return Err(Error::new(
                        ErrorCode::AuthRequired,
                        "mini-auth rejects ambiguous forwarded identity metadata",
                    ));
                }
                if identity == "deny" {
                    return Err(Error::new(
                        ErrorCode::PermissionDenied,
                        "mini-auth sentinel identity denied request",
                    ));
                }
                return Ok(format!("mini:forwarded:{identity}"));
            }
        }
        if credential.bearer.as_deref() == Some(b"deny") {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                "mini-auth sentinel credential denied request",
            ));
        }

        if let Some(bearer) = &credential.bearer {
            // Test-only deterministic identity for round-trip assertions. A
            // production auth layer must never derive or persist a principal
            // from reversible bearer material.
            use std::fmt::Write as _;

            let mut principal = String::from("mini:bearer:");
            for byte in bearer {
                write!(&mut principal, "{byte:02x}")
                    .expect("formatting a byte into a String cannot fail");
            }
            return Ok(principal);
        }

        let principal = match &credential.transport {
            ovstorage_authz_context::Transport::Tcp { peer_addr, .. } => {
                format!("mini:tcp:{peer_addr}")
            }
            ovstorage_authz_context::Transport::Uds { uid, .. } => format!("mini:uid:{uid}"),
            ovstorage_authz_context::Transport::NamedPipe { sid, .. } => {
                format!("mini:sid:{sid}")
            }
        };
        Ok(principal)
    }

    /// Decode and consume the raw credential, then stamp the resolved
    /// principal DOWN on the delegated extensions — the documented
    /// auth-wrapper contract for every operation this wrapper forwards.
    fn authenticate(&self, extensions: &mut Extensions) -> Result<()> {
        let encoded = extensions.remove(ext::AUTH_CREDENTIAL).ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "mini-auth requires an auth credential",
            )
        })?;
        let credential =
            ovstorage_authz_context::AuthCredential::decode(&encoded).map_err(|e| {
                Error::new(
                    ErrorCode::AuthRequired,
                    format!("mini-auth credential decode failed: {e}"),
                )
            })?;
        let principal = Self::principal(&credential)?;
        extensions.insert(ext::PRINCIPAL_ID.to_string(), principal.as_bytes().to_vec());
        Ok(())
    }

    fn context(&self, extensions: &Extensions) -> Result<Extensions> {
        let mut extensions = extensions.clone();
        self.authenticate(&mut extensions)?;
        Ok(extensions)
    }
}

macro_rules! impl_mini_auth_layer {
    ($(($method:ident, $request:ty, $output:ty)),* $(,)?) => {
        #[async_trait]
        impl Layer for MiniAuth {
            fn name(&self) -> &str {
                &self.name
            }

            fn descriptor(&self) -> LayerKindDescriptor {
                auth_descriptor()
            }

            fn inner_layer(&self) -> Option<&LayerHandle> {
                Some(&self.inner)
            }

            fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
                let cx = self.context(cx)?;
                self.inner.list_kinds(&cx).map(|mut kinds| {
                    kinds.insert(0, auth_descriptor());
                    kinds
                })
            }

            async fn root_info_for(
                &self,
                url: &Url,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Result<RootInfo> {
                let cx = self.context(cx)?;
                self.inner.root_info_for(url, &cx, cancel).await
            }

            async fn list_address_roots(
                &self,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
                let cx = self.context(cx)?;
                self.inner.list_address_roots(&cx, cancel).await
            }

            async fn list_connections(
                &self,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
                let cx = self.context(cx)?;
                self.inner.list_connections(&cx, cancel).await
            }

            $(
                async fn $method(
                    &self,
                    mut request: Request<$request>,
                    cancel: Option<CancellationToken>,
                ) -> Result<$output> {
                    self.authenticate(&mut request.extensions)?;
                    self.inner.$method(request, cancel).await
                }
            )*
        }
    };
}

impl_mini_auth_layer!(
    (stat, StatRequest, ObjectInfo),
    (read, ReadRequest, ReadResult),
    (materialize, ReadRequest, LocalDelegate),
    (write, WriteRequest, WriteResult),
    (write_stream, WriteRequest, WriteResult),
    (write_redirect, WriteRequest, WriteRedirectBatch),
    (continue_write, ContinueWriteRequest, WriteStep),
    (delete, DeleteRequest, ()),
    (copy, CopyRequest, WriteStep),
    (rename, RenameRequest, ()),
    (update_metadata, UpdateMetadataRequest, BackendItemInfo),
    (check_access, CheckAccessRequest, AccessDecision),
    (list, ListRequest, ListPage),
    (list_versions, ListVersionsRequest, VersionPage),
    (get_latest_version, ReadRequest, ObjectInfo),
    (create_directory, CreateDirectoryRequest, BackendItemInfo),
    (delete_directory, DeleteDirectoryRequest, ()),
    (watch_directory, WatchDirectoryRequest, ChangeStream),
    // The connection lifecycle also authenticates and stamps: the trait
    // defaults would forward these delegations unstamped, which the host's
    // credential boundary fails closed.
    (probe, LayerConnectionRequest, Connection),
    (add_connection, LayerConnectionRequest, Connection),
    (remove_connection, ConnectionKey, ()),
    (
        update_connection_credentials,
        UpdateConnectionCredentialsRequest,
        Connection
    ),
    (
        update_connection_attributes,
        UpdateConnectionAttributesRequest,
        Connection
    ),
    (
        authenticate_connection,
        AuthenticateRequest,
        AuthEventStream
    ),
);

/// Factory for `MiniAuth`. The config is intentionally empty: credential
/// behavior is deterministic so broker tests need no external identity service.
#[derive(Default)]
pub struct MiniAuthFactory;

#[async_trait]
impl WrapperFactory for MiniAuthFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        auth_descriptor()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(MiniAuth {
            name: name.to_string(),
            inner,
        }))
    }
}

/// Pass-through wrapper layer: delegates every operational slot to its inner
/// via the `Layer` trait defaults. The host hands it a child across the FFI
/// (`export_handle` → `import_child`), so `inner` is typically a
/// plugin-side `ForeignVtableLayer` over a host-exported handle.
struct MiniWrapper {
    name: String,
    inner: LayerHandle,
}

#[async_trait]
impl Layer for MiniWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        wrapper_descriptor()
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }
}

/// Factory for `MiniWrapper`, driven end-to-end by the composition
/// characterization (the host exports the child and this plugin imports it
/// as a foreign layer).
#[derive(Default)]
pub struct MiniWrapperFactory;

#[async_trait]
impl WrapperFactory for MiniWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        wrapper_descriptor()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(MiniWrapper {
            name: name.to_string(),
            inner,
        }))
    }
}

/// Owns-nothing router layer: no dispatch logic of its own, it only
/// aggregates `owned_targets` across its children — enough for the
/// composition characterization to prove the router → foreign child →
/// backend chain crosses the FFI.
struct MiniRouter {
    name: String,
    children: Vec<LayerHandle>,
}

#[async_trait]
impl Layer for MiniRouter {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        router_descriptor()
    }

    fn owned_targets(&self) -> Vec<String> {
        self.children
            .iter()
            .flat_map(|child| child.owned_targets())
            .collect()
    }
}

/// Factory for `MiniRouter`.
#[derive(Default)]
pub struct MiniRouterFactory;

#[async_trait]
impl RouterFactory for MiniRouterFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        router_descriptor()
    }

    async fn create_router(
        &self,
        name: &str,
        _config: &LayerConfig,
        children: Vec<LayerHandle>,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(MiniRouter {
            name: name.to_string(),
            children,
        }))
    }
}

// Backend first, so `plugin.kinds().first()` (the host's descriptor-decode
// fallback) resolves to the `mini-v2` backend kind.
ovstorage_layer_plugin!(
    (
        (backend, || MiniV2Factory),
        (wrapper, || MiniWrapperFactory),
        (wrapper, || MiniAuthFactory),
        (router, || MiniRouterFactory),
    ),
    test_only
);

// =====================================================================
// Cross-binary export symbol
// =====================================================================
//
// Everything below is independent of the plugin manifest/init handshake
// above — `ovstorage_test_export_stack` is a plain `#[no_mangle]` symbol the
// cross-binary test resolves directly via `libloading`, the same way
// `load_v2_plugin` resolves `ovstorage_plugin_manifest_v1` /
// `ovstorage_plugin_init_v1` (`ovstorage/src/loaded_v2.rs`).

fn handoff_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: HANDOFF_KIND.to_string(),
        layer_type: LayerType::Backend,
        display_name: "handoff export backend".to_string(),
        description: Some("In-memory backend exported by ovstorage_test_export_stack".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: true,
    }
}

/// Generation allocator for exported `HandoffBackend`s. Starts at **1**, so
/// every backend carries a strictly positive generation and a first-export
/// assertion of `dropped_gen < mine` is never the vacuous `0 < 0` against
/// [`OVSTORAGE_TEST_HANDOFF_DROPPED_GEN`]'s initial `0`.
static HANDOFF_GEN: AtomicU64 = AtomicU64::new(1);

/// Producer-side drop observability for the cross-binary test: the highest
/// generation whose exported `HandoffBackend` has released. The host test
/// cannot reach into this linked image's heap any other way, so it `dlsym`s
/// this data symbol (mirroring how `load_v2_plugin` reads
/// `ovstorage_plugin_manifest_v1`) to observe the producer Arc actually
/// dropping across the FFI boundary.
///
/// A generation rather than a bool because a release can migrate off the
/// thread that dropped the import: the host's `CallPin::drop` retires a
/// last-reference teardown onto a detached `ovs-layer-retire` thread
/// (`ovstorage-plugin/src/consume_v2.rs`), so an *earlier* test's producer
/// release can land at any later wall-clock moment — including between a
/// later test's export and its read. A bool carries no identity and cannot
/// tell those apart; a generation can, because exports are serialized by the
/// test file's `SERIAL` mutex and so generations increase in test-body order.
/// A straggling release therefore always carries a strictly earlier
/// generation, which `HandoffBackend::drop`'s `fetch_max` discards.
#[unsafe(no_mangle)]
pub static OVSTORAGE_TEST_HANDOFF_DROPPED_GEN: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// The generation [`HandoffBackend::seeded`] most recently allocated on
    /// this thread.
    ///
    /// [`ovstorage_test_export_stack`] does not construct the backend itself —
    /// [`HandoffFactory::create_backend`] does, inside the `block_on` below —
    /// so the export symbol reads the generation back out through this slot
    /// rather than allocating a second one (two allocation sites would
    /// silently desynchronise). Thread-local rather than a process-global
    /// "latest": with a global, two concurrent exports A and B would have A
    /// read B's generation, and A would then misreport its own producer's
    /// release. `block_on` runs `create_backend` on the calling thread, so
    /// this slot is exactly as handle-specific as the call is.
    static LAST_SEEDED_GEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Rendezvous barrier backing the `/gated` read address's deterministic
/// mid-flight-cancellation window (see [`HandoffBackend::read`]). Same
/// two-rendezvous idiom as `snapshot_gate` above, generalized to cross an FFI
/// boundary: since the test can't hand this cdylib a reference to its own
/// `Barrier`, it drives the second rendezvous through the exported
/// [`ovstorage_test_release_handoff_gate`] instead.
static HANDOFF_GATE: OnceLock<Arc<Barrier>> = OnceLock::new();

fn handoff_gate() -> Arc<Barrier> {
    HANDOFF_GATE
        .get_or_init(|| Arc::new(Barrier::new(2)))
        .clone()
}

/// Release one rendezvous on `HANDOFF_GATE`. The cross-binary test calls
/// this twice around firing cancellation on the in-flight `/gated` read:
/// once to confirm the read has actually entered its blocking window (so the
/// cancel that follows lands on a call that is genuinely in flight, not a
/// race against a sleep), once to let it proceed and observe that
/// cancellation.
#[unsafe(no_mangle)]
pub extern "C" fn ovstorage_test_release_handoff_gate() {
    handoff_gate().wait();
}

const HANDOFF_KIND: &str = "handoff-test";

/// Minimal in-memory backend [`ovstorage_test_export_stack`] exports: seeded
/// `stat`/`read`/`write`/`list`, plus `/stream` and `/gated` read-address
/// modifiers the cross-binary test drives for streaming and deterministic
/// mid-flight cancellation. Kept separate from [`MiniV2Backend`] so this
/// test's state (the drop flag, the gate) can't leak into the plugin-load /
/// composition characterizations that reuse `MiniV2Backend`.
struct HandoffBackend {
    name: String,
    store: Mutex<HashMap<String, Vec<u8>>>,
    /// This backend's export generation — see
    /// [`OVSTORAGE_TEST_HANDOFF_DROPPED_GEN`]. Carried on the instance so its
    /// release identifies *itself* rather than merely reporting that some
    /// `HandoffBackend` released.
    generation: u64,
}

impl HandoffBackend {
    fn seeded() -> Arc<Self> {
        let mut store = HashMap::new();
        store.insert(
            "handoff://data/a.bin".to_string(),
            b"handoff cross-binary payload".to_vec(),
        );
        let generation = HANDOFF_GEN.fetch_add(1, Ordering::SeqCst);
        LAST_SEEDED_GEN.with(|slot| slot.set(generation));
        Arc::new(Self {
            name: "handoff".to_string(),
            store: Mutex::new(store),
            generation,
        })
    }
}

impl Drop for HandoffBackend {
    fn drop(&mut self) {
        // `fetch_max`, not `store`: a straggling release from an earlier
        // export must never pull the published generation backwards past a
        // later export's already-observed release.
        OVSTORAGE_TEST_HANDOFF_DROPPED_GEN.fetch_max(self.generation, Ordering::SeqCst);
    }
}

#[async_trait]
impl Layer for HandoffBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        handoff_descriptor()
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address;
        let store = self.store.lock().unwrap();
        match store.get(address.as_str()) {
            Some(bytes) => Ok(object_info(address, bytes.len() as u64)),
            None => Err(Error::new(ErrorCode::NotFound, "object not found")),
        }
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let address = request.input.address;
        let raw = address.as_str();
        let (base, gated) = match raw.strip_suffix("/gated") {
            Some(base) => (base, true),
            None => (raw, false),
        };
        let (base, streamed) = match base.strip_suffix("/stream") {
            Some(base) => (base, true),
            None => (base, false),
        };
        if gated {
            // RV1: tell the test we've arrived and are about to block. RV2:
            // wait to be released — the test fires cancellation in between,
            // so the check below observes a cancellation that landed on a
            // call that was genuinely still in flight.
            handoff_gate().wait();
            handoff_gate().wait();
            if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
                return Err(Error::new(ErrorCode::Cancelled, "gated read cancelled"));
            }
        }
        let bytes = {
            let store = self.store.lock().unwrap();
            match store.get(base) {
                Some(bytes) => bytes.clone(),
                None => return Err(Error::new(ErrorCode::NotFound, "object not found")),
            }
        };
        let info = object_info(address.clone(), bytes.len() as u64);
        if streamed {
            // Same chunked-stream marshalling exercise as `MiniV2Backend`'s
            // own `/stream` suffix: proves `ReadResult::Stream` crosses the
            // bridge, here specifically from a genuinely foreign vtable.
            let chunks: Vec<Result<bytes::Bytes>> = bytes
                .chunks(4)
                .map(|chunk| Ok(bytes::Bytes::copy_from_slice(chunk)))
                .collect();
            let stream: ReadStream = Box::pin(futures::stream::iter(chunks));
            Ok(ReadResult::Stream { stream, info })
        } else {
            Ok(ReadResult::Bytes { bytes, info })
        }
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let address = request.input.address;
        let bytes = match request.input.body {
            Body::Bytes(bytes) => bytes,
            Body::LocalFile(path) => std::fs::read(&path)
                .map_err(|e| Error::new(ErrorCode::Internal, format!("read local file: {e}")))?,
            Body::Stream(mut stream) => {
                let mut buf = Vec::new();
                while let Some(chunk) = stream.next_chunk() {
                    buf.extend_from_slice(&chunk?);
                }
                buf
            }
        };
        let size = bytes.len() as u64;
        self.store
            .lock()
            .unwrap()
            .insert(address.as_str().to_string(), bytes);
        Ok(WriteResult {
            info: object_info(address, size),
        })
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        _cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let prefix = request.input.prefix;
        // Segment-aligned containment, not a raw string prefix. The host does
        // not rewrite a directory-verb address, so listing on the serialized
        // form verbatim returns `…/docsx/secret` for a listing of `…/docs` —
        // a disclosure, and disclosure cannot be undone.
        let mut items: Vec<ObjectInfo> = self
            .store
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| {
                Url::parse(key).is_ok_and(|address| {
                    ovstorage_plugin::address::is_ancestor_or_self(&prefix, &address)
                })
            })
            .map(|(key, bytes)| object_info(Url::parse(key).unwrap(), bytes.len() as u64))
            .collect();
        items.sort_by(|a, b| a.address.as_str().cmp(b.address.as_str()));
        Ok(ListPage {
            items,
            next_page_token: None,
        })
    }
}

/// Factory for [`HandoffBackend`], used only by [`ovstorage_test_export_stack`]
/// to build its one-layer in-crate `Stack` — never registered on the
/// cdylib's own `ovstorage_plugin_init_v1` factory set above, since this
/// backend exists solely for the cross-binary export symbol.
#[derive(Default)]
struct HandoffFactory;

#[async_trait]
impl BackendFactory for HandoffFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        handoff_descriptor()
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(HandoffBackend::seeded())
    }
}

/// Builds a tiny in-crate single-backend `Stack` over `HandoffBackend` and
/// `export_handle`s its root into `*out` — the produce side of the
/// cross-binary test. Returns `0` on success (the only failure mode is a
/// broken build of this crate's own fixture Stack, which panics instead of
/// returning a status code, matching every other `#[no_mangle]` entry point
/// in this file).
///
/// Writes the exported backend's generation to `out_generation`, paired with
/// the handle write and published only once construction has succeeded. The
/// caller needs its *own* handle's generation to interpret
/// [`OVSTORAGE_TEST_HANDOFF_DROPPED_GEN`]; there is deliberately no
/// "generation of the latest export" symbol to read instead, because two
/// concurrent exports would then each read the other's.
///
/// Nothing is reset per export. A `dlclose`d cdylib is not reliably unmapped
/// (Rust cdylibs commonly register TLS/`atexit` destructors that make the
/// dynamic linker keep the image resident), so a test process that `dlopen`s
/// this cdylib once per `#[test]` fn is very likely reusing the same mapped
/// image and therefore the same statics. The generation scheme makes that
/// reuse the point rather than a hazard: the published counter is
/// monotonically increasing across the whole process, and each caller
/// compares it against the generation it was handed.
///
/// # Safety
///
/// `out` must be a valid, writable `*mut ffi::LayerHandle`, and
/// `out_generation` a valid, writable `*mut u64`, for the duration of the
/// call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_test_export_stack(
    out: *mut ffi::LayerHandle,
    out_generation: *mut u64,
) -> i32 {
    // `StackBuilder::build` is async and this symbol is a plain synchronous
    // `extern "C" fn`; the one-backend stack below does no real I/O, so a
    // bare `block_on` needs no reactor (`futures` — already a dependency for
    // the stream-bridge machinery above — ships one). It also runs
    // `HandoffFactory::create_backend` on this thread, which is what makes
    // `LAST_SEEDED_GEN` below this call's own.
    let stack = futures::executor::block_on(
        Stack::builder(HANDOFF_KIND)
            .backend_factory(Arc::new(HandoffFactory))
            .layer(LayerSpec::backend(HANDOFF_KIND, HANDOFF_KIND))
            .build(),
    )
    .expect("build the handoff export stack");
    let generation = LAST_SEEDED_GEN.with(std::cell::Cell::get);
    let handle = export_handle(stack.root().clone());
    // SAFETY: `out`/`out_generation` are valid and writable for the call per
    // this function's safety contract.
    unsafe {
        out.write(handle);
        out_generation.write(generation);
    }
    0
}

// =====================================================================
// Malformed-descriptor export (host decode-error characterization)
// =====================================================================
//
// The host's `descriptor` decode-error path — `layer_kind_descriptor_from_ffi`
// rejecting a non-UTF-8 `display_name`, then `ForeignVtableLayer::descriptor`
// falling back — is characterized by handing the host a `LayerHandle` whose
// `descriptor` slot writes an ill-formed-UTF-8 `display_name`. A valid Rust
// `LayerKindDescriptor` cannot represent such a value (its `display_name` is a
// `String`, whose bytes are always valid UTF-8), and building one with
// `String::from_utf8_unchecked` is instant UB. So the malformed bytes are
// injected **only at the FFI boundary**, by a bespoke `descriptor` thunk that
// encodes the (valid) descriptor via the canonical vtable thunk and then swaps
// in a hand-built `ffi::Str` — every Rust `String` in the rig stays valid.

/// The backing layer for [`ovstorage_test_export_malformed_descriptor`]. Its
/// [`descriptor`](Layer::descriptor) is entirely valid (distinct `kind`
/// `mini-v2-live`, valid `display_name`); the ill-formed-UTF-8 `display_name`
/// is injected downstream by [`malformed_descriptor_thunk`], never as a Rust
/// `String`. Only `name`/`descriptor` are exercised (via the custom vtable's
/// canonical `name`/`drop` slots and the malformed `descriptor` slot); the
/// remaining `Layer` slots keep their `Unsupported` defaults.
struct MalformedDescriptorLayer;

impl Layer for MalformedDescriptorLayer {
    fn name(&self) -> &str {
        "malformed"
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        malformed_descriptor()
    }
}

/// `descriptor` slot for the malformed-descriptor handle. Delegates to the
/// canonical [`thunks_v2::LAYER_VTABLE`] `descriptor` thunk to encode the
/// layer's valid [`malformed_descriptor`] (`kind = "mini-v2-live"`), then
/// overwrites `display_name` with a deliberately ill-formed-UTF-8 `ffi::Str`.
///
/// The replacement `ffi::Str` is built exactly the way
/// `marshal::primitive::str_to_ffi` builds a valid one — an ABI-heap buffer
/// whose capacity equals its length — so the host's `str_from_ffi` releases
/// it through the same ABI allocator the contract requires. The valid
/// `display_name` the canonical thunk produced is dropped in place, freeing
/// its buffer.
///
/// # Safety
///
/// `state` must be the canonical `Box<Arc<dyn Layer>>` (`leak_layer`) and
/// `out` a valid, writable `*mut ffi::LayerKindDescriptor`, as the `descriptor`
/// slot contract requires.
unsafe extern "C" fn malformed_descriptor_thunk(
    state: *mut core::ffi::c_void,
    out: *mut ffi::LayerKindDescriptor,
) {
    // Encode the fully-valid descriptor through the canonical slot (same
    // linked image), leaving `*out` initialized.
    unsafe { (thunks_v2::LAYER_VTABLE.descriptor)(state, out) };

    // Mint an ill-formed-UTF-8 buffer on the ABI heap with capacity ==
    // length, mirroring `str_to_ffi`'s non-empty allocation so the consumer
    // frees it correctly.
    let raw = vec![0xffu8, 0xfe, 0xfd];
    let len = raw.len();
    let ptr = ffi::abi_alloc::abi_vec_into_raw(raw);
    let mut invalid = ffi::Str {
        ptr: ptr as *mut std::os::raw::c_char,
        len,
    };

    // SAFETY: the canonical thunk just wrote an initialized descriptor to
    // `out`. Swap in the invalid `Str` and drop the valid one it produced,
    // freeing that buffer in this image.
    let descriptor = unsafe { &mut *out };
    std::mem::swap(&mut descriptor.display_name, &mut invalid);
    drop(invalid);
}

/// The single custom `LayerVTableV1` this image installs for the
/// malformed-descriptor handle: a bitwise copy of the canonical
/// [`thunks_v2::LAYER_VTABLE`] with only the `descriptor` slot replaced by
/// [`malformed_descriptor_thunk`]. Every other slot (notably the canonical
/// `name` and `drop`) is unchanged, so the handle imports, caches its name,
/// and drops exactly like any factory-minted one.
fn malformed_descriptor_vtable() -> *const ffi::LayerVTableV1 {
    static VT_ADDR: OnceLock<usize> = OnceLock::new();
    let addr = *VT_ADDR.get_or_init(|| {
        // SAFETY: `LayerVTableV1` is a `#[repr(C)]` POD of function pointers
        // and integers with no `Drop`, so a bitwise copy of the canonical
        // vtable is sound and independent of the original static.
        let mut vt = unsafe { std::ptr::read(&thunks_v2::LAYER_VTABLE) };
        vt.descriptor = malformed_descriptor_thunk;
        Box::leak(Box::new(vt)) as *const ffi::LayerVTableV1 as usize
    });
    addr as *const ffi::LayerVTableV1
}

/// Mint a `LayerHandle` whose `descriptor` slot returns an *undecodable*
/// (ill-formed-UTF-8 `display_name`) descriptor — the produce side of the host
/// descriptor decode-error characterization
/// (`loaded_plugin_characterization::loaded_v2_descriptor_decode_failure_falls_back`).
/// The handle carries `malformed_descriptor_vtable`, so the malformed bytes
/// are injected only at the FFI boundary; the backing `MalformedDescriptorLayer`
/// and every Rust `String` it holds stay valid. Returns `0` on success.
///
/// # Safety
///
/// `out` must be a valid, writable `*mut ffi::LayerHandle` for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ovstorage_test_export_malformed_descriptor(
    out: *mut ffi::LayerHandle,
) -> i32 {
    let layer: Arc<dyn Layer> = Arc::new(MalformedDescriptorLayer);
    let handle = ffi::LayerHandle {
        // Canonical `Box<Arc<dyn Layer>>` state the copied `name`/`drop`/
        // canonical `descriptor` slots expect.
        state: thunks_v2::leak_layer(layer),
        vtable: malformed_descriptor_vtable(),
    };
    // SAFETY: `out` is valid and writable for the call per this function's
    // safety contract.
    unsafe { out.write(handle) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt as _;
    use futures::StreamExt as _;
    use std::sync::Barrier;

    impl MiniV2Backend {
        fn for_test(root: &str) -> Arc<MiniV2Backend> {
            Arc::new(MiniV2Backend {
                name: "mini".to_string(),
                state: Mutex::new(MiniState {
                    roots: vec![MiniRoot {
                        url: Url::parse(root).unwrap(),
                        connection_id: None,
                    }],
                    ..MiniState::default()
                }),
                store: Mutex::new(HashMap::new()),
                snapshot_gate: Mutex::new(None),
            })
        }

        /// Push a root and announce `Added` to live subscribers — the same two
        /// effects `add_connection` has, isolated for the race test.
        fn test_add_root(&self, root: Url) {
            let mut state = self.state.lock().unwrap();
            let entry = MiniRoot {
                url: root,
                connection_id: None,
            };
            let added = RootInfoChange::Added(vec![self.root_info(&entry)]);
            state.roots.push(entry);
            state.announce_roots(added);
        }
    }

    /// `list_address_roots` must register its update subscriber BEFORE reading
    /// the snapshot, so a root added concurrently in that window is delivered on
    /// the stream rather than lost (the 89ef4844 fix). We drive the race
    /// deterministically: the backend pauses at a gate right after registering
    /// the subscriber, the test adds a root (broadcasting `Added` to the
    /// now-registered subscriber), then releases the backend to snapshot.
    ///
    /// The assertion is on the STREAM specifically — not the snapshot — because
    /// `test_add_root` also pushes to `roots`, so the post-gate snapshot would
    /// contain the root under either ordering. Only a subscriber that was
    /// already registered when the broadcast fired receives it; reverting the
    /// registration below the snapshot leaves the gate ahead of an unregistered
    /// subscriber, the broadcast reaches nobody, and this fails.
    #[test]
    fn list_address_roots_registers_subscriber_before_snapshot() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let gate = Arc::new(Barrier::new(2));
        *backend.snapshot_gate.lock().unwrap() = Some(gate.clone());

        let worker = backend.clone();
        let handle = std::thread::spawn(move || {
            futures::executor::block_on(
                worker.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
            )
        });

        // Rendezvous A: subscriber registered, backend paused before snapshot.
        gate.wait();
        let new_root = Url::parse("mini://b/").unwrap();
        backend.test_add_root(new_root.clone());
        // Rendezvous B: release the backend to take its snapshot.
        gate.wait();

        let (_snapshot, stream) = handle.join().unwrap().unwrap();
        let mut stream = stream.expect("update stream present");
        // The broadcast was sent synchronously before the backend returned, so
        // it is already queued; poll once without blocking.
        let on_stream = stream
            .next()
            .now_or_never()
            .flatten()
            .map(|item| {
                matches!(item, Ok(RootInfoChange::Added(roots))
                    if roots.iter().any(|r| r.root == new_root))
            })
            .unwrap_or(false);
        assert!(
            on_stream,
            "a root added after subscriber registration must arrive on the update \
             stream; if it doesn't, the subscriber was registered after the snapshot"
        );
    }

    fn connection_request(root: &str) -> Request<LayerConnectionRequest> {
        let mut config = LayerConfig::new();
        config.insert("root".to_string(), ConfigValue::String(root.to_string()));
        Request::new(LayerConnectionRequest {
            target: "mini".to_string(),
            connection: ConnectionRequest {
                backend_kind: KIND.to_string(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        })
    }

    /// Poll one already-queued item off an update stream.
    ///
    /// Every announcement runs synchronously before the slot returns, so the
    /// item is queued by the time the caller gets here; `now_or_never` reads it
    /// without blocking on a stream that would otherwise never end. `None`
    /// means nothing was announced, which several assertions below want.
    fn queued<T>(
        stream: Option<impl futures::Stream<Item = Result<T>> + Unpin>,
    ) -> Option<Result<T>> {
        stream
            .expect("update stream present")
            .next()
            .now_or_never()
            .flatten()
    }

    /// `add_connection` announces the connection and its new root.
    ///
    /// The emissions cannot be tested for "inside the guard" at runtime — see
    /// [`MiniState`]: `announce_roots`/`announce_connection` are methods on the
    /// guarded state, so an emission outside the critical section does not
    /// compile, and there is nothing left for a runtime assertion to catch.
    #[test]
    fn add_connection_announces_the_connection_and_its_root() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let (_snapshot, conn_updates) = futures::executor::block_on(
            backend.list_connections(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to connection updates");
        let (_snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to root updates");

        let added = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the connection");

        let conn_event = queued(conn_updates);
        assert!(
            matches!(conn_event, Some(Ok(ConnectionChange::Added(ref c))) if c.id == added.id),
            "adding a connection must announce ConnectionChange::Added, got {conn_event:?}",
        );
        let root_event = queued(root_updates);
        let announced = match root_event {
            Some(Ok(RootInfoChange::Added(ref roots))) => roots.iter().any(|r| {
                r.root.as_str() == "mini://b/" && r.connection_id.as_ref() == Some(&added.id)
            }),
            _ => false,
        };
        assert!(
            announced,
            "adding a connection must announce its root, carrying the contributing \
             connection id so a host can tell it from the configured root; got {root_event:?}",
        );
    }

    /// `remove_connection` retracts what `add_connection` announced: the
    /// connection, the root it contributed, and a `Removed` on **both** update
    /// streams.
    #[test]
    fn remove_connection_retracts_root_and_announces_both() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let added = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the connection");
        assert!(
            backend.owns(&Url::parse("mini://b/x").unwrap()),
            "the connection's root is served while the connection lives",
        );

        // Subscribe after the add so each stream carries only the removal.
        let (_conn_snapshot, conn_updates) = futures::executor::block_on(
            backend.list_connections(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to connection updates");
        let (_root_snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to root updates");

        futures::executor::block_on(backend.remove_connection(
            Request::new(ConnectionKey {
                target: "mini".to_string(),
                id: added.id.clone(),
            }),
            None,
        ))
        .expect("remove the connection");

        assert!(
            !backend.owns(&Url::parse("mini://b/x").unwrap()),
            "removing the connection retracts the root it contributed",
        );
        assert!(
            backend.owns(&Url::parse("mini://a/x").unwrap()),
            "the configured root carries no connection id and is never retracted",
        );

        let conn_event = queued(conn_updates);
        assert!(
            matches!(conn_event, Some(Ok(ConnectionChange::Removed { ref id })) if *id == added.id),
            "removing a connection must announce ConnectionChange::Removed, got {conn_event:?}",
        );
        let root_event = queued(root_updates);
        let retracted = match root_event {
            Some(Ok(RootInfoChange::Removed(ref roots))) => {
                roots.iter().any(|r| r.root.as_str() == "mini://b/")
            }
            _ => false,
        };
        assert!(
            retracted,
            "removing a connection must announce RootInfoChange::Removed for its root, got \
             {root_event:?}",
        );
    }

    /// Removing an id this layer never announced is silent.
    ///
    /// Removal is idempotent — `loaded_plugin_characterization` removes
    /// `"absent"` and expects `Ok`, a real statement about the unit-result
    /// decode path — but announcing `Removed` for a connection no subscriber
    /// ever saw `Added` is a phantom event a host cannot reconcile.
    #[test]
    fn removing_an_unknown_connection_announces_nothing() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let (_snapshot, conn_updates) = futures::executor::block_on(
            backend.list_connections(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to connection updates");

        futures::executor::block_on(backend.remove_connection(
            Request::new(ConnectionKey {
                target: "mini".to_string(),
                id: ConnectionId("never-installed".to_string()),
            }),
            None,
        ))
        .expect("removing an unknown connection stays idempotent");

        let conn_event = queued(conn_updates);
        assert!(
            conn_event.is_none(),
            "removing an id that was never installed must announce nothing, got \
             {conn_event:?}",
        );
    }

    /// Two connections configured with the SAME root: removing one must not
    /// announce `RootInfoChange::Removed` for a URL the backend still serves.
    ///
    /// Root multiplicity is internal — the second `add_connection` adds a
    /// contributor, not a second served root — so `Added` fires once and
    /// `Removed` only when the last contributor leaves. Matching retraction by
    /// contributing connection id alone is not enough: it retracts this
    /// connection's entry correctly but tells a host the address is gone while
    /// `root_info_for` keeps answering for it.
    #[test]
    fn removing_one_of_two_connections_sharing_a_root_updates_rather_than_retracts() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let first = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the first connection");

        // Subscribe before the SECOND add: the URL is already served, so that
        // add contributes to an existing root rather than creating one, and
        // must announce no `RootInfoChange::Added` — the mirror of the
        // retraction rule below. The connection itself is still announced.
        let (_snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to root updates");
        let (_snapshot, conn_updates) = futures::executor::block_on(
            backend.list_connections(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to connection updates");
        let second = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the second connection");
        let root_event = queued(root_updates);
        assert!(
            root_event.is_none(),
            "a second contributor to an already-served URL adds no root, so nothing may be \
             announced on the root stream; got {root_event:?}",
        );
        let conn_event = queued(conn_updates);
        assert!(
            matches!(conn_event, Some(Ok(ConnectionChange::Added(ref c))) if c.id == second.id),
            "the second connection is still announced, got {conn_event:?}",
        );

        // The shared URL is one served root.
        let (snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("resubscribe to root updates");
        assert_eq!(
            snapshot
                .roots
                .iter()
                .filter(|r| r.root.as_str() == "mini://b/")
                .count(),
            1,
            "two contributors to one URL are one served root in the snapshot",
        );

        futures::executor::block_on(backend.remove_connection(
            Request::new(ConnectionKey {
                target: "mini".to_string(),
                id: first.id,
            }),
            None,
        ))
        .expect("remove the first connection");

        assert!(
            backend.owns(&Url::parse("mini://b/x").unwrap()),
            "the second connection still contributes the root",
        );
        // The URL is still served, so it is not retracted — but the identity a
        // subscriber holds for it just left, so the survivor is announced.
        let root_event = queued(root_updates);
        assert!(
            !matches!(root_event, Some(Ok(RootInfoChange::Removed(_)))),
            "a root another connection still contributes must not be retracted; got \
             {root_event:?}",
        );
        let reannounced = match root_event {
            Some(Ok(RootInfoChange::Updated(ref roots))) => roots.iter().any(|r| {
                r.root.as_str() == "mini://b/" && r.connection_id.as_ref() == Some(&second.id)
            }),
            _ => false,
        };
        assert!(
            reannounced,
            "the surviving contributor must be announced, so a subscriber stops holding the \
             connection it was just told is gone; got {root_event:?}",
        );

        // The last contributor leaving does retract it.
        let (_snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("resubscribe to root updates");
        futures::executor::block_on(backend.remove_connection(
            Request::new(ConnectionKey {
                target: "mini".to_string(),
                id: second.id,
            }),
            None,
        ))
        .expect("remove the second connection");
        assert!(
            !backend.owns(&Url::parse("mini://b/x").unwrap()),
            "the last contributor leaving retracts the root",
        );
        let root_event = queued(root_updates);
        let retracted = match root_event {
            Some(Ok(RootInfoChange::Removed(ref roots))) => {
                roots.iter().any(|r| r.root.as_str() == "mini://b/")
            }
            _ => false,
        };
        assert!(
            retracted,
            "the last contributor leaving must announce RootInfoChange::Removed, got \
             {root_event:?}",
        );
    }

    /// Removing a contributor whose identity a subscriber does not hold is
    /// silent: the announced `RootInfo` for the URL is unchanged, so there is
    /// nothing to tell anyone.
    #[test]
    fn removing_a_non_announced_contributor_announces_no_root_change() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let first = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the first connection");
        let second = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the second connection");

        let (_snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to root updates");

        // The snapshot announces the FIRST contributor, so removing the second
        // changes nothing a subscriber can observe about the root.
        futures::executor::block_on(backend.remove_connection(
            Request::new(ConnectionKey {
                target: "mini".to_string(),
                id: second.id,
            }),
            None,
        ))
        .expect("remove the second connection");

        let root_event = queued(root_updates);
        assert!(
            root_event.is_none(),
            "the announced identity for the URL is unchanged, so no root change may be \
             announced; got {root_event:?}",
        );
        let (snapshot, _updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("resnapshot");
        let root = snapshot
            .roots
            .iter()
            .find(|r| r.root.as_str() == "mini://b/")
            .expect("the first connection still contributes the root");
        assert_eq!(root.connection_id.as_ref(), Some(&first.id));
    }

    /// A subscriber that applies every announcement holds the same `RootInfo` a
    /// fresh snapshot reports.
    ///
    /// The announced `RootInfo` names one contributing connection. When that
    /// contributor leaves a root another connection still serves, the root
    /// survives under new identity: a stream carrying only the connection's
    /// removal leaves the subscriber holding a `connection_id` it was just told
    /// is gone, while the snapshot reports the survivor. Announcing the
    /// survivor's identity is what keeps the two in step.
    #[test]
    fn removing_a_shared_root_contributor_keeps_stream_and_snapshot_in_step() {
        let backend = MiniV2Backend::for_test("mini://a/");
        let first = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the first connection");
        let second = futures::executor::block_on(
            backend.add_connection(connection_request("mini://b/"), None),
        )
        .expect("add the second connection");

        // What a subscriber holds for `mini://b/` after the initial snapshot.
        let (snapshot, root_updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("subscribe to root updates");
        let mut held = snapshot
            .roots
            .iter()
            .find(|r| r.root.as_str() == "mini://b/")
            .cloned()
            .expect("the shared root is in the snapshot");
        assert_eq!(held.connection_id.as_ref(), Some(&first.id));

        futures::executor::block_on(backend.remove_connection(
            Request::new(ConnectionKey {
                target: "mini".to_string(),
                id: first.id,
            }),
            None,
        ))
        .expect("remove the first connection");

        // Apply whatever the stream announced.
        let root_event = queued(root_updates);
        match root_event {
            Some(Ok(RootInfoChange::Updated(ref roots)))
            | Some(Ok(RootInfoChange::Added(ref roots))) => {
                if let Some(fresh) = roots.iter().find(|r| r.root.as_str() == "mini://b/") {
                    held = fresh.clone();
                }
            }
            Some(Ok(RootInfoChange::Removed(ref roots))) => {
                assert!(
                    !roots.iter().any(|r| r.root.as_str() == "mini://b/"),
                    "a root another connection still contributes must not be retracted",
                );
            }
            _ => {}
        }

        // What a caller arriving fresh sees.
        let (snapshot, _updates) = futures::executor::block_on(
            backend.list_address_roots(&ovstorage_plugin::Extensions::new(), None),
        )
        .expect("resnapshot");
        let fresh = snapshot
            .roots
            .iter()
            .find(|r| r.root.as_str() == "mini://b/")
            .expect("the root is still served by the surviving connection");

        assert_eq!(
            held.connection_id, fresh.connection_id,
            "a subscriber that applied every announcement must hold the same contributing \
             connection a fresh snapshot reports; the stream left it naming {:?} while the \
             snapshot reports {:?}",
            held.connection_id, fresh.connection_id,
        );
        assert_eq!(
            held.connection_id.as_ref(),
            Some(&second.id),
            "the surviving contributor is the second connection",
        );
    }
}
