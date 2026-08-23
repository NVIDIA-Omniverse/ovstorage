// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native ABI-v2 `Layer` for the S3 backend (RFC-0066).
//!
//! A single [`S3Layer`] owns its connections and routes addresses to the right
//! [`S3Backend`] instance by longest prefix. Connection *lifecycle* (the
//! `ConnectionAuthState` machine, single-flight bring-up, cooldown, and the
//! data-path recovery loop) is delegated to a generic
//! [`ConnectionSet<S3Driver>`] (RFC-0066); the layer keeps
//! only the routing state. S3 roots are config-derived and fixed at connect
//! time (the SQS watch never changes roots), so `list_address_roots` is
//! snapshot-only — no dynamic-root stream.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use ovstorage_plugin::connection::{ConnectionSet, ProbeOutcome};
use ovstorage_plugin::*;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use crate::backend::{S3Backend, anonymous_capabilities, s3_capabilities_for_config};
use crate::client::{OperationEvidence, with_operation_evidence, without_promotion_evidence};
use crate::config::{self, S3Config};
use crate::credentials::{self, AwsCredentials};
use crate::driver::S3Driver;

/// The static backend descriptor; converted to the v2 `LayerKindDescriptor`
/// via [`descriptor_to_layer_kind`] at the factory/layer surface.
pub(crate) fn kind_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
        kind: "s3".into(),
        display_name: "S3-compatible object store".into(),
        description: Some(
            "S3 / S3-compatible backend on the AWS SDK for Rust with a static AWS credential chain"
                .into(),
        ),
        config_schema: config::config_schema(),
        credential_schema: config::credential_schema(),
        credential_methods: config::credential_methods(),
        icon: None,
        supports_runtime_add: true,
        supports_user_metadata: true,
    }
}

/// `BackendFactory` the `ovstorage_layer_plugin!` macro instantiates. Holds the
/// static kind descriptor; every built layer owns its own `ConnectionSet` and
/// longest-prefix route table.
pub struct S3LayerFactory {
    descriptor: StorageBackendKindDescriptor,
}

impl Default for S3LayerFactory {
    fn default() -> Self {
        Self {
            descriptor: kind_descriptor(),
        }
    }
}

#[async_trait]
impl BackendFactory for S3LayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor_to_layer_kind(&self.descriptor)
    }

    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        let layer = Arc::new(S3Layer {
            name: name.to_string(),
            descriptor: self.descriptor.clone(),
            connection_set: Arc::new(ConnectionSet::with_defaults()),
            state: RwLock::new(S3LayerState {
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

/// Native ABI-v2 `Layer` for the S3 backend.
pub(crate) struct S3Layer {
    name: String,
    descriptor: StorageBackendKindDescriptor,
    /// Owns connection identity + auth lifecycle (RFC-0066). The layer
    /// keeps [`Self::state`] only for longest-prefix routing + `with_recovery`.
    connection_set: Arc<ConnectionSet<S3Driver>>,
    /// Connections and the longest-prefix route table derived from them, under
    /// a single lock so a mutation and its route-table rebuild are published
    /// atomically (a separate pair would let concurrent add/remove publish a
    /// stale table).
    state: RwLock<S3LayerState>,
    /// Keeps byte-identical config and empty credentials from colliding on the
    /// same trace/routing-only `BackendId`; connection identity is the
    /// `ConnectionId`.
    next_instance_counter: AtomicU64,
}

struct S3LayerState {
    instances: Vec<Arc<S3Instance>>,
    routes: RouteTable<Arc<S3Instance>>,
}

/// One backend instance serving one connection. Routing/dispatch state only —
/// connection identity + auth live in the layer's [`ConnectionSet`], keyed by
/// [`Self::connection_id`].
struct S3Instance {
    connection_id: ConnectionId,
    backend_id: BackendId,
    backend: Arc<S3Backend>,
    roots: Vec<RootInfo>,
}

/// What one operation is allowed to be judged on, built BEFORE that operation
/// runs and installed around it by [`AcceptanceWitness::scope`].
///
/// The two halves are scoped differently, and the asymmetry is the point.
///
/// **Acceptance is the operation's own.** A connection is one set of SDK
/// clients shared by every operation running against it, and under the broker
/// those are unrelated remote callers. Judging on a connection-wide tally lets
/// a caller whose own operation never reached the store — a `read`, which only
/// presigns a URL — be vindicated by a neighbour's request.
///
/// **Refusal is the connection's.** The credential is one object: a refusal
/// answered to anyone signing with this connection's keys condemns it for all
/// of them, and an operation that merely avoided hearing the bad news must not
/// be promoted on the strength of that. (`verify` and `probe` build ephemeral
/// clients with a refusal epoch of their own, so their refusals are theirs
/// alone — parking is their control, not this one.)
///
/// Both are needed. Either alone promotes something it should not.
struct AcceptanceWitness {
    instance: Arc<S3Instance>,
    evidence: Arc<OperationEvidence>,
    refusal_epoch_before: u64,
}

impl AcceptanceWitness {
    fn take(instance: &Arc<S3Instance>) -> Self {
        Self {
            refusal_epoch_before: instance.backend.refusal_epoch(),
            instance: instance.clone(),
            evidence: Arc::new(OperationEvidence::default()),
        }
    }

    /// Run `future` with this witness's acceptance sink installed.
    ///
    /// **Every call site must wrap its operation in this.** A witness that is
    /// built and read but never scoped records no acceptance, so [`Self::proved`]
    /// answers `false` for ever and the connection stays parked however well its
    /// operations go — a working credential reporting `AwaitingAuth`, which is
    /// the condition this whole mechanism exists to end. Only the ordering of
    /// the snapshot is structural; this part is not, so [`Self::proved`] asserts
    /// on it.
    async fn scope<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        with_operation_evidence(self.evidence.clone(), future).await
    }

    /// Whether the store answered a request THIS operation signed, no refusal
    /// reached the connection while it ran, and the instance that ran it is
    /// still installed.
    ///
    /// The epoch clause is what makes this safe to read on a failed operation.
    /// A multi-request op — `rename`'s copy then delete, a paged `list`, a
    /// multipart upload — can have one request accepted and the next refused
    /// when a key is revoked mid-flight, and "something was accepted" would
    /// promote a connection whose credential had just died. Being
    /// connection-wide, it also catches the refusal a concurrent operation
    /// heard, which never reaches this operation's own sink.
    ///
    /// What it cannot reach, by construction, is a refusal that landed BEFORE
    /// the snapshot. The azure and gcs siblings close part of that gap with a
    /// latch on their IdP grant, and static S3 keys have no grant to latch. A
    /// sticky latch on STORAGE refusals would close the rest, and is not used
    /// here: nothing would ever clear it — `S3Driver::refresh` is `Unsupported`
    /// and no data-path operation un-refuses a credential — so one refusal
    /// would park a connection for the life of the process, which is the
    /// inverse defect. The guarantee is therefore bounded, and stated rather
    /// than implied: a refusal DURING the operation withholds the promotion,
    /// and one before it is answered by the next operation that hears its own.
    ///
    /// The instance clause covers removal: `remove_connection` unregisters
    /// before it drops the route, so an operation resolved against a retired
    /// instance must not vindicate whatever is registered now.
    fn proved(&self, layer: &S3Layer) -> bool {
        if !self.evidence.require_installed("s3") {
            return false;
        }
        self.evidence.saw_acceptance()
            && self.instance.backend.refusal_epoch() == self.refusal_epoch_before
            && layer.instance_is_installed(&self.instance)
    }
}

/// Longest-prefix route table over the current instance set.
fn build_routes(instances: &[Arc<S3Instance>]) -> RouteTable<Arc<S3Instance>> {
    let items: Vec<(RootInfo, Arc<S3Instance>)> = instances
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

impl S3Layer {
    /// Build a connection: parse the config, construct the per-connection
    /// backend sharing a live credential cell with an [`S3Driver`], hand the
    /// driver to the `ConnectionSet` (which validates + owns the lifecycle),
    /// then publish the config-derived root via `set_addresses`.
    ///
    /// Roots are published **unconditionally** (even for a parked
    /// `AwaitingAuth` connection): they derive from config, not from an
    /// auth-gated discovery, so callers can still locate and authenticate a
    /// parked connection
    /// after a Stack rebuild regardless of the verify outcome.
    async fn instantiate_connection(
        &self,
        request: ConnectionRequest,
        source: ConnectionSource,
        cancel: Option<CancellationToken>,
    ) -> Result<Arc<S3Instance>> {
        if request.backend_kind != self.descriptor.kind {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "connection backend_kind '{}' does not match layer kind '{}'",
                    request.backend_kind, self.descriptor.kind
                ),
            ));
        }
        let config = config::parse_config(&request.config)?;
        let counter = self.next_instance_counter.fetch_add(1, Ordering::Relaxed);
        let backend_id = BackendId(format!(
            "s3:{}:{counter}",
            config_fingerprint(&config, &request.credentials)
        ));

        // Pre-resolve only to pick the backend shape (anonymous = read-only,
        // no signed clients) and the advertised capabilities; the credential
        // contents are installed by the
        // driver's verify→activate, not here.
        let is_anonymous = credentials::resolve_bundle(&request.credentials)?.is_none();
        let live_cell: Arc<Mutex<Option<AwsCredentials>>> = Arc::new(Mutex::new(None));
        let backend = if is_anonymous {
            Arc::new(S3Backend::anonymous(config.clone())?)
        } else {
            Arc::new(S3Backend::with_credentials_cell(
                config.clone(),
                live_cell.clone(),
            )?)
        };
        let capabilities = if is_anonymous {
            anonymous_capabilities()
        } else {
            s3_capabilities_for_config(Some(&config))
        };
        let driver = Arc::new(S3Driver::new(config.clone(), live_cell));

        let connection_id = ConnectionId(fresh_id("s3"));
        let display_name = request
            .display_name
            .clone()
            .unwrap_or_else(|| format!("S3 {}", config.bucket));
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
            config.address_root.clone(),
            &connection_id,
            &source,
            capabilities.clone(),
        );
        self.connection_set
            .set_addresses(&connection_id, vec![root.root.clone()], capabilities);

        Ok(Arc::new(S3Instance {
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

    /// Install `instance` and republish the route table atomically.
    fn install(&self, instance: Arc<S3Instance>) {
        let mut state = self.state.write();
        state.instances.push(instance);
        state.routes = build_routes(&state.instances);
    }

    fn target(&self, url: &Url) -> Result<(Arc<S3Instance>, ResolvedTarget)> {
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
    /// data-path recovery loop, promoting a parked connection if the store
    /// demonstrably accepted one of this operation's own requests. With
    /// `S3Driver::refresh` unsupported (static keys) the recovery half degrades
    /// to classify-and-surface, which is correct — and positions s3 for a
    /// future STS driver without touching call sites. `op` must be replayable
    /// (no consumed streaming body).
    ///
    /// The evidence is per-operation, so an operation that reaches no request
    /// earns nothing for anyone: a `read` mints a presigned URL and sends
    /// nothing, and `watch_directory` returns before its SQS producer polls,
    /// that producer running on a task of its own outside every operation's
    /// sink. A watch-only or redirect-only connection therefore stays parked
    /// until some other operation runs, and the SQS client carries no evidence
    /// interceptor either (see `build_sqs_client`), so a watch contributes
    /// nothing in either direction. Refusals heard by a CONCURRENT operation are
    /// seen, because those belong to the connection rather than to an
    /// operation.
    async fn recover<T, F, Fut>(&self, url: &Url, op: F) -> Result<T>
    where
        F: Fn(Arc<S3Instance>, ResolvedTarget) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (instance, target) = self.target(url)?;
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        self.connection_set
            .with_recovery_promoting_if(
                &id,
                || witness.proved(self),
                || witness.scope(op(instance.clone(), target.clone())),
            )
            .await
    }

    /// Whether `instance` is still the installed instance for its connection —
    /// pointer identity, not a routing lookup, so a re-added connection's fresh
    /// instance does not answer for a retired one.
    fn instance_is_installed(&self, instance: &Arc<S3Instance>) -> bool {
        self.state
            .read()
            .instances
            .iter()
            .any(|installed| Arc::ptr_eq(installed, instance))
    }

    /// Resolve a `ConnectionKey` to its id, enforcing the target-plus-id
    /// routing contract (a request addressed to another target must not act on
    /// this layer's connection even if the id collides).
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

/// Identity fingerprint over the connection's config and credential identity.
/// `BackendId` is trace-only; connection identity is the `ConnectionId`, and
/// credential identity is the driver's generation.
fn config_fingerprint(config: &S3Config, credentials: &SecretBundle) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v2\0");
    hasher.update(config.bucket.as_bytes());
    hasher.update(b"\0");
    hasher.update(config.region.as_bytes());
    hasher.update(b"\0");
    hasher.update(config.endpoint.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(config.profile_name.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(config.compatibility.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update([config.force_path_style as u8]);
    hasher.update([config.force_request_payer as u8]);
    hasher.update(b"\0watch\0");
    hasher.update(config.sqs_queue_url.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(config.sqs_max_messages.to_le_bytes());
    hasher.update(config.sqs_wait_seconds.to_le_bytes());
    hasher.update(config.sqs_visibility_timeout.to_le_bytes());
    hasher.update(b"\0cred\0");
    for key in ["aws_access_key_id", "aws_session_token"] {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        if let Some(bytes) = credential_identity_bytes(credentials, key) {
            hasher.update(bytes);
        }
        hasher.update(b"\0");
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn credential_identity_bytes<'a>(bundle: &'a SecretBundle, key: &str) -> Option<&'a [u8]> {
    match bundle.fields.get(key)? {
        SecretValue::Bytes(b) | SecretValue::File(b) => Some(&b.0),
        _ => None,
    }
}

#[async_trait]
impl Layer for S3Layer {
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
        // Roots are fixed at connect time (config-derived; SQS watch never
        // changes them), so this is snapshot-only.
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
        // to the caller. The acceptance an inline write earns still counts,
        // though — a connection whose `PutObject` the store answered has proved
        // its credentials as surely as any other operation.
        let (instance, target) = self.target(&request.input.address)?;
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
        // Unlike the azure sibling this slot is witnessed, because on s3 it
        // reaches the store: a multipart redirect batch opens the upload with a
        // signed `CreateMultipartUpload` of our own before it presigns the part
        // URLs. A single-part batch presigns only, sends nothing, and earns
        // nothing — the per-operation evidence tells the two apart without this
        // slot having to classify itself.
        let (instance, target) = self.target(&request.input.address)?;
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
        // The staged path commits with a signed `CompleteMultipartUpload` of
        // our own, so the store's answer to that counts like any other.
        //
        // A single-redirect write leaves no evidence here, and the 2xx the
        // caller reports back is NOT a substitute. `results` is caller-supplied
        // and the caller is not always in-process — the broker takes it
        // straight off the wire — so a remote client could report a 200 it
        // never performed and flip an operator's shared connection to
        // `Authenticated` with no request leaving the process. A redirect-only
        // writer stays parked until some other operation reaches the store.
        let (instance, target) = self.target(&request.input.address)?;
        let id = instance.connection_id.clone();
        let witness = AcceptanceWitness::take(&instance);
        let (redirects, results) = (request.input.redirects, request.input.results);
        self.connection_set
            .with_promotion_if(
                &id,
                || witness.proved(self),
                witness.scope(async move {
                    instance
                        .backend
                        .continue_write(target, redirects, results, cancel)
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
        // Pull the full set — the backend walks S3's own
        // `NextContinuationToken` to the end of the prefix — then fold flat
        // directory markers / infer subdirectory kinds, and paginate the folded
        // result so synthesized entries land on stable page boundaries.
        // Surfacing S3's native continuation token to the CALLER instead, so a
        // host page maps onto an S3 page, remains a behavior change deferred
        // past gen1; what is not deferred is completeness, because a folded set
        // built from a truncated listing reports absent objects as missing.
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
        // S3 is a flat namespace: never real directories.
        let items = fold_markers_and_infer_subdir_kinds(&prefix, items, false, recursive);
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
        // Current behavior: the backend honors `page_token` natively but the
        // host never chained pages; keep the same shape.
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
        // Establish the SQS subscription under `recover` (establishment is
        // replayable); mid-stream errors surface via the mapped stream.
        let options = request.input.options;
        let stream = self
            .recover(&request.input.prefix, move |instance, target| {
                let options = options.clone();
                let cancel = cancel.clone();
                async move {
                    // S3 ignores `opts.poll_interval`: the SQS long-poll
                    // duration is config-only, so the coalescer negotiates over
                    // this connection-normalized cadence.
                    let effective_cadence =
                        Duration::from_secs(instance.backend.config().sqs_wait_seconds.into());
                    instance
                        .backend
                        .watch_directory(target, options, effective_cadence, cancel)
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
                "s3 does not support cross-connection copy",
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
        let (source_instance, source) = self.target(&request.input.source)?;
        let (dest_instance, destination) = self.target(&request.input.destination)?;
        if !Arc::ptr_eq(&source_instance, &dest_instance) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "s3 does not support cross-connection rename",
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
        // Runs under recovery, but its SUCCESSES contribute no promotion
        // evidence: this slot asks the store what the caller may do by provoking
        // the answer, so a 200 it receives is the answer to its own question
        // rather than something the connection earned.
        //
        // Its REFUSALS still count, deliberately — see `EVIDENCE_SUPPRESSED`. A
        // 403 here is indistinguishable from a disabled key, and dropping it
        // would let a concurrent operation's earlier acceptance promote a dead
        // credential. The cost of that choice is real and is recorded at
        // `vetoes_promotion`.
        let operations = request.input.operations;
        self.recover(&request.input.address, move |instance, target| {
            let operations = operations.clone();
            let cancel = cancel.clone();
            without_promotion_evidence(async move {
                instance
                    .backend
                    .check_access(target, operations, cancel)
                    .await
            })
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
        let config = config::parse_config(&req.config)?;
        let is_anonymous = credentials::resolve_bundle(&req.credentials)?.is_none();
        let capabilities = if is_anonymous {
            anonymous_capabilities()
        } else {
            s3_capabilities_for_config(Some(&config))
        };
        let driver = Arc::new(S3Driver::new(config.clone(), Arc::new(Mutex::new(None))));
        let now = SystemTime::now();
        let mut view = Connection {
            id: ConnectionId(fresh_id("s3")),
            backend_kind: self.descriptor.kind.clone(),
            display_name: req
                .display_name
                .clone()
                .unwrap_or_else(|| format!("S3 {}", config.bucket)),
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
            // Static keys never consume; unreachable, but handled honestly.
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
        let id = self.checked_key_id(&key.input)?;
        self.connection_set.remove_connection(&id).await?;
        // Single write guard: drop the instance and republish the route table
        // atomically.
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
        // The backend SHAPE is frozen at instantiate time, so a shape-changing
        // update is rejected with guidance in BOTH directions:
        //
        // - anonymous → credentialed: an anonymous connection built an
        //   `S3Backend::anonymous` (no signed clients, its own empty cell,
        //   read-only capabilities) that never reads the driver's live cell.
        //   Accepting credentials would activate an orphan cell and report
        //   `Authenticated` while every read stays unsigned.
        // - credentialed → anonymous (empty bundle): `obtain` maps an empty
        //   bundle to `Anonymous` and the set records the transition, but
        //   `activate` never clears the live cell — the backend would keep
        //   presigning with the PREVIOUS keys while the connection reports
        //   `Anonymous`.
        //
        // Both are a success-that-isn't; remove-and-re-add is the shape
        // change and constructs the correctly shaped client.
        let anonymous_instance = self
            .state
            .read()
            .instances
            .iter()
            .find(|instance| instance.connection_id == id)
            .map(|instance| instance.backend.is_anonymous());
        let empty_bundle = credentials::resolve_bundle(&request.input.credentials)?.is_none();
        match anonymous_instance {
            Some(true) => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "this s3 connection was added without credentials (anonymous, read-only); \
                     remove it and re-add it with credentials to attach them",
                ));
            }
            Some(false) if empty_bundle => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "this s3 connection was added with credentials; updating with an empty \
                     bundle cannot detach them — remove it and re-add it without credentials \
                     for anonymous access",
                ));
            }
            _ => {}
        }
        // obtain → verify → activate installs the proven keys into the live
        // cell the backend's SDK clients read; roots are config-derived and
        // unchanged, so no re-discovery.
        self.connection_set
            .update_credentials(&id, request.input.credentials, cancel)
            .await?;
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
    /// stores `x-amz-meta-*` on `PutObject`, on multipart, and signed into a presign.
    #[test]
    fn s3_declares_its_user_metadata_support() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "s3");
        assert!(
            descriptor.supports_user_metadata,
            "s3's user-metadata declaration changed; a host composes its \
             attribution layer from it"
        );
    }
}
