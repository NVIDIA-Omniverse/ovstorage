// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;

use crate::*;

pub type LayerHandle = Arc<dyn Layer>;
pub type LayerConfig = HashMap<String, ConfigValue>;

#[derive(Clone, Default)]
pub struct Extensions {
    entries: BTreeMap<String, Vec<u8>>,
    /// Native-wrapper-only context. These values clone with a request inside
    /// one process and are deliberately omitted by the FFI marshaller.
    local: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions")
            .field("entries", &self.entries)
            .field("local_values", &self.local.len())
            .finish()
    }
}

impl PartialEq for Extensions {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for Extensions {}

impl Extensions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Vec<u8>) -> Option<Vec<u8>> {
        self.entries.insert(key.into(), value)
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    /// Attach native wrapper context that must not cross a plugin ABI
    /// boundary. Cloning the extensions refcount-shares the value.
    #[doc(hidden)]
    pub fn insert_local<T: Any + Send + Sync>(&mut self, value: T) -> Option<Arc<T>> {
        self.local
            .insert(TypeId::of::<T>(), Arc::new(value))
            .and_then(|prior| prior.downcast::<T>().ok())
    }

    /// Read native wrapper context previously attached by [`Self::insert_local`].
    #[doc(hidden)]
    pub fn get_local<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.local
            .get(&TypeId::of::<T>())
            .and_then(|value| value.downcast_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate the entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_slice()))
    }
}

impl IntoIterator for Extensions {
    type Item = (String, Vec<u8>);
    type IntoIter = std::collections::btree_map::IntoIter<String, Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<T> {
    pub extensions: Extensions,
    pub input: T,
}

impl<T> Request<T> {
    pub fn new(input: T) -> Self {
        Self {
            extensions: Extensions::new(),
            input,
        }
    }
}

/// Fail fast when the caller's token has ALREADY fired, for a slot whose only
/// meaningful observation point is entry.
///
/// The [`Layer`] contract makes [`ErrorCode::Cancelled`] the answer for a token
/// that fired before the operation completed. The three runtime-state queries
/// (`root_info_for` / `list_address_roots` / `list_connections`) are often
/// short enough that entry is the only place an implementor can check — but
/// "short" is not "free", and answering an already-cancelled caller with a
/// successful snapshot is wrong however cheap the answer was. Sharing one
/// helper keeps every implementor's phrasing and error code identical, so
/// hosts cannot disagree about what a fired token yields.
///
/// # Errors
///
/// - [`ErrorCode::Cancelled`] — `cancel` is present and already fired.
pub fn bail_if_cancelled(cancel: &Option<CancellationToken>) -> Result<()> {
    match cancel {
        Some(token) if token.is_cancelled() => Err(Error::new(
            ErrorCode::Cancelled,
            "cancelled before the query started",
        )),
        _ => Ok(()),
    }
}

/// The [`ConnectionKey::target`](crate::ConnectionKey) a connection op routes
/// to for a host-side leaf that owns a root: its sole `owned_targets` entry when
/// it declares exactly one (the connection-owning name a loaded plugin reports
/// across the ABI, not its outer host name), else its own `name`. THE single
/// home for the leaf-ownership rule — shared by [`Layer::owning_target_for`]'s
/// default and the loaded-plugin host-fill in `ovstorage-plugin`'s
/// `root_info_for`, so the two cannot drift.
pub fn leaf_owning_target(owned_targets: &[String], name: &str) -> String {
    match owned_targets {
        [only] => only.clone(),
        _ => name.to_string(),
    }
}

/// The uniform operation surface every layer in a chain implements.
///
/// # Errors contract
///
/// `Layer` is implemented by arbitrary backends, wrappers, routers, and
/// loaded plugins, so no operation's error set is closed. Each
/// `Result`-returning method documents its contract set — the
/// [`ErrorCode`]s a caller must be prepared to handle for that operation.
/// On top of each per-method set, any operation may surface:
///
/// - [`ErrorCode::Cancelled`] — every method taking
///   `cancel: Option<CancellationToken>` returns this when the token fires
///   before the operation completes.
/// - [`ErrorCode::Internal`] — an implementation fault (e.g. a plugin
///   bridge or background-task failure) that is not the caller's fault and
///   is not safe to blindly retry.
/// - Transient-bucket codes ([`ErrorCode::Transient`],
///   [`ErrorCode::DeadlineExceeded`], …) — upstream I/O failures that are
///   safe to retry; see [`ErrorBucket::retryable`].
/// - [`ErrorCode::PermissionDenied`] or [`ErrorCode::AuthRequired`] — when
///   an authorization layer gates the chain.
#[async_trait]
pub trait Layer: Send + Sync {
    fn name(&self) -> &str;

    fn descriptor(&self) -> LayerKindDescriptor;

    /// The wrapped inner layer, when this layer is a wrapper.
    ///
    /// Wrapper layers implement this to return their `inner` handle; every
    /// pass-through default method below then delegates to it automatically,
    /// so a wrapper only writes bespoke bodies for the operations it actually
    /// intercepts, and a newly added `Layer` slot delegates through existing
    /// wrappers by default instead of silently reverting to the backend
    /// `Unsupported` default. Backend and router layers keep
    /// the `None` default, which preserves the `Unsupported`/empty defaults.
    ///
    /// This is host-side composition machinery, not an operational slot: it
    /// has no `OvStorage_LayerVTable` entry and never crosses the plugin ABI.
    /// A new operational slot's default body must use the same
    /// `inner_layer()` match shape so wrappers stay delegation-safe.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        None
    }

    /// Whether this layer and every wrapper down to a native redirect follower
    /// preserve both the request-local extension map and buffered write bytes.
    ///
    /// This is host-side composition machinery, not an operational ABI slot.
    /// It defaults to false so FFI, language adapters, and body-transforming
    /// wrappers cannot accidentally opt a byte cache into the private buffered
    /// write-capture protocol merely by exposing an inner layer.
    #[doc(hidden)]
    fn supports_buffered_write_capture(&self) -> bool {
        false
    }

    /// Drop every cached entry under `prefix`, in this layer and in every layer
    /// below it that this one can reach — see the plugin-boundary note below.
    ///
    /// The lifecycle counterpart to a `Lapsed` event. Change events reach every
    /// cache in a stack because they travel back up through the stacked
    /// `watch_directory` wrappers, but the notification drain's own lifecycle
    /// sweeps — the one it arms when a watch opens, and the ones it runs when a
    /// watch is retired, rebound or dies — are invoked directly by the layer
    /// that OWNS the drain. In the shipped byte-over-metadata composition only
    /// the byte layer carries `watch_invalidation`, so without a path down the
    /// chain those sweeps clear the byte cache and leave the metadata rows
    /// beneath it answering for a subtree no watch was covering.
    ///
    /// Forwarding by default, like [`Layer::owned_targets`], so a wrapper that
    /// merely exposes an inner layer participates without knowing about caches.
    /// A layer holding its own cache overrides this to clear its own entries and
    /// then call the default.
    ///
    /// **It walks the host-side wrapper chain only, and stops at a plugin
    /// boundary.** It has no vtable slot, so the proxy standing in for a layer
    /// across the ABI overrides neither this nor [`Layer::inner_layer`] and
    /// therefore takes the no-op default. A cache reached only through such a
    /// proxy does not receive these sweeps and falls back to whatever expiry it
    /// has of its own. Giving it a slot would put a host composition detail into
    /// the frozen ABI and oblige every plugin to answer a question it has no
    /// caches to answer; the alternative for a cache pair that must stay
    /// connected across the boundary is a private channel established when the
    /// wrappers are built, rather than this universal trait method.
    fn invalidate_cached_subtree(&self, prefix: &Url) {
        if let Some(inner) = self.inner_layer() {
            inner.invalidate_cached_subtree(prefix);
        }
    }

    fn owned_targets(&self) -> Vec<String> {
        let mut targets = if self.descriptor().accepts_connections {
            vec![self.name().to_string()]
        } else {
            Vec::new()
        };
        if let Some(inner) = self.inner_layer() {
            targets.extend(inner.owned_targets());
        }
        targets
    }

    /// Per-URL root introspection: resolve the [`RootInfo`] for `url`.
    ///
    /// This is one of three **runtime-state queries** — with
    /// [`list_address_roots`](Layer::list_address_roots) and
    /// [`list_connections`](Layer::list_connections) — that inspect live
    /// backend state rather than fixed manifest metadata. All three are `async`
    /// and cancellable: an implementation may perform filesystem or network I/O
    /// to answer, and must honor `cancel` exactly like the data ops
    /// (`stat`/`read`/…) do — observing the token and returning promptly once
    /// it fires. A `None` token means "no cancellation".
    ///
    /// `cx` carries the same per-request [`Extensions`] bag the data ops
    /// receive through [`Request::extensions`], so these introspection slots
    /// are context-carrying too. The bag holds request *facts* (e.g. the
    /// caller principal under `ext::PRINCIPAL_ID`), never instructions: a Layer
    /// may read `cx` to gate or filter its answer, but a Layer that does not
    /// gate introspection simply forwards `cx` unchanged through the
    /// `inner_layer()` delegation, exactly like the data-op defaults. Backends
    /// and other leaf Layers accept `cx` and ignore it.
    ///
    /// # Synchronous structural methods
    ///
    /// The remaining non-data methods — [`name`](Layer::name),
    /// [`descriptor`](Layer::descriptor),
    /// [`owned_targets`](Layer::owned_targets),
    /// [`list_kinds`](Layer::list_kinds), and
    /// [`inner_layer`](Layer::inner_layer) — stay synchronous under a strict
    /// no-I/O contract. Each performs only bounded in-memory work over
    /// already-resolved manifest/topology state: no filesystem or network
    /// access, no blocking locks, no async-runtime entry (no `block_on`), and
    /// no dependency on a foreign event loop or the Python GIL. In particular
    /// [`list_kinds`](Layer::list_kinds) reports manifest/fixed-graph metadata
    /// — the layer kinds wired into this chain at build time — not runtime
    /// discovery, which is why it stays synchronous rather than joining the
    /// three cancellable queries above.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::NoRoute`] — no configured root matches `url`.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the query
    ///   answered.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn root_info_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        match self.inner_layer() {
            Some(inner) => inner.root_info_for(url, cx, cancel).await,
            None => Err(unsupported("root_info_for")),
        }
    }

    /// The owning Layer instance name serving `url`: the
    /// [`ConnectionKey::target`](crate::ConnectionKey) a connection op
    /// (`add`/`remove`/`authenticate`/`update_credentials`) must address to
    /// reach the connection behind `url`. Distinct from
    /// [`RootInfo::layer_kind`](crate::RootInfo), the descriptor kind:
    /// connection ops route by the graph-unique instance name, so a backend
    /// Layer named differently from its kind (e.g. `s3_prod` of kind `s3`) is
    /// still reachable. `None` when no Layer here serves `url`.
    ///
    /// This is host-side composition machinery, not an operational slot: like
    /// [`inner_layer`](Layer::inner_layer) it has no `OvStorage_LayerVTable`
    /// entry and never crosses the plugin ABI. It resolves ownership from the
    /// values that DO cross the ABI, so it survives a loaded composite plugin
    /// (a wrapper/router `.so` that internally owns a differently-named
    /// backend): a wrapper delegates to its inner; a host-side leaf that serves
    /// `url` returns its sole [`owned_targets`](Layer::owned_targets) entry
    /// (the connection-owning name a loaded plugin reports across the ABI, not
    /// its own root name), falling back to its [`name`](Layer::name) when it
    /// declares no single owned target. A router layer overrides this to route
    /// by `url` first (it has no single inner). See
    /// [`root_info_for`](Layer::root_info_for) for the `cx` context contract.
    ///
    /// Resolving ownership asks [`root_info_for`](Layer::root_info_for) whether
    /// a leaf serves `url`, so this joins that method's cancellable async group
    /// rather than the synchronous no-I/O slots.
    async fn owning_target_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Option<String> {
        if let Some(inner) = self.inner_layer() {
            return inner.owning_target_for(url, cx, cancel).await;
        }
        // A host-side leaf owns `url` only if it serves it. Its routing target
        // is its connection-owning name: `owned_targets` reports that even for
        // a loaded plugin whose internal composition the host cannot traverse
        // (the plugin's backend name, not the host layer name), so a single
        // owned target is authoritative over `name()`.
        if self.root_info_for(url, cx, cancel).await.is_err() {
            return None;
        }
        Some(leaf_owning_target(&self.owned_targets(), self.name()))
    }

    /// Enumerate every Layer kind reachable from here. This is fixed
    /// manifest/topology metadata, so it stays synchronous under the no-I/O
    /// contract described on [`root_info_for`](Layer::root_info_for), which
    /// also defines the `cx` context contract.
    ///
    /// # Errors
    ///
    /// The default body cannot fail on its own; it propagates any error
    /// from the delegated inner [`list_kinds`](Layer::list_kinds). A
    /// plugin-bridged layer may surface [`ErrorCode::Internal`]; a gating
    /// layer may answer [`ErrorCode::PermissionDenied`].
    fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        let mut kinds = vec![self.descriptor()];
        if let Some(inner) = self.inner_layer() {
            kinds.extend(inner.list_kinds(cx)?);
        }
        Ok(kinds)
    }

    /// Snapshot of address roots plus an optional live update stream. See
    /// [`root_info_for`](Layer::root_info_for) for the `cx` context contract.
    ///
    /// # Errors
    ///
    /// The leaf default answers an empty snapshot rather than an error.
    /// Aggregating implementations (e.g. the router) propagate child
    /// failures:
    ///
    /// - [`ErrorCode::Transient`] — backend I/O while enumerating roots.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired during the fan-out.
    async fn list_address_roots(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        match self.inner_layer() {
            Some(inner) => inner.list_address_roots(cx, cancel).await,
            None => Ok((
                RootInfoSnapshot {
                    roots: Vec::new(),
                    updates: false,
                },
                None,
            )),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — nothing exists at the address.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not inspect the
    ///   address.
    /// - [`ErrorCode::InvalidArgument`] — the address cannot be mapped to
    ///   this backend's storage.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the stat
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        match self.inner_layer() {
            Some(inner) => inner.stat(request, cancel).await,
            None => Err(unsupported("stat")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — no object exists at the address.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not read the
    ///   object.
    /// - [`ErrorCode::ObjectModified`] — an `if_match` precondition did
    ///   not match the object's current etag. The read path reports this
    ///   rather than [`ErrorCode::PreconditionFailed`] because a backend
    ///   may detect the mismatch only once bytes are already moving.
    /// - [`ErrorCode::InvalidArgument`] — the address or byte range is
    ///   malformed, or the address names a directory rather than an
    ///   object. A backend advertising `has_real_directories` owes this
    ///   refusal. The `read-on-directory-type-mismatch` conformance scenario
    ///   checks it where a provider's harness can drive the scenario at all —
    ///   nucleus and services-client advertise the capability but skip it,
    ///   their verdict being server-side and their canned-frame harnesses
    ///   unable to script it, so for those the requirement stands unpinned
    ///   in-tree.
    ///
    ///   A backend that answers `read` with a presigned redirect holds no kind
    ///   verdict of its own and must ask the service for one before it signs.
    ///   What it does with the answer is asymmetric on purpose: an affirmative
    ///   directory verdict refuses, and anything else — a refused question, a
    ///   failure, an answer carrying no kind — signs, because a backend that
    ///   invented a refusal there would fail readable objects for every caller
    ///   whose credentials cannot reach the kind probe. So the obligation is to
    ///   ASK and to honour a verdict it gets; the scenario exercises the
    ///   affirmative-verdict case, and has no way to express the rest.
    /// - [`ErrorCode::Unsupported`] — the object is not readable as bytes
    ///   (e.g. a special filesystem object); also the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the read
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    ///
    /// A [`ReadResult::Stream`] reports failures after this call returns
    /// as `Err` items on the stream, using the same codes.
    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        match self.inner_layer() {
            Some(inner) => inner.read(request, cancel).await,
            None => Err(unsupported("read")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not write the
    ///   address.
    /// - [`ErrorCode::AlreadyExists`] — the destination exists and the
    ///   options demand creating a fresh object.
    /// - [`ErrorCode::PreconditionFailed`] — a destination etag precondition
    ///   did not match.
    /// - [`ErrorCode::InvalidArgument`] — the address or options are
    ///   malformed (e.g. the destination is a directory).
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the write
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn write(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        match self.inner_layer() {
            Some(inner) => inner.write(request, cancel).await,
            None => Err(unsupported("write")),
        }
    }

    /// # Errors
    ///
    /// The same contract as [`write`](Layer::write):
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`],
    /// [`ErrorCode::AlreadyExists`], [`ErrorCode::PreconditionFailed`],
    /// [`ErrorCode::InvalidArgument`], [`ErrorCode::Unsupported`] (the
    /// leaf default), [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`].
    async fn write_stream(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        match self.inner_layer() {
            Some(inner) => inner.write_stream(request, cancel).await,
            None => Err(unsupported("write_stream")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::Unsupported`] — the backend does not speak the
    ///   redirected-write protocol (callers fall back to
    ///   [`write`](Layer::write)); also the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not write the
    ///   address.
    /// - [`ErrorCode::InvalidArgument`] — the address or options are
    ///   malformed.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the batch was
    ///   issued.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn write_redirect(
        &self,
        request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        match self.inner_layer() {
            Some(inner) => inner.write_redirect(request, cancel).await,
            None => Err(unsupported("write_redirect")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::RedirectExpired`] — a redirect grant from the
    ///   preceding [`write_redirect`](Layer::write_redirect) lapsed
    ///   before the caller continued.
    /// - [`ErrorCode::StagingExpired`] — the staged upload was reclaimed
    ///   before the commit.
    /// - [`ErrorCode::CommitAmbiguous`] — the commit outcome is unknown;
    ///   the caller must verify before retrying.
    /// - [`ErrorCode::PreconditionFailed`] — a destination etag precondition
    ///   did not match; nothing was committed.
    /// - [`ErrorCode::InvalidArgument`] — the continuation does not match
    ///   an in-flight redirected write.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the step
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn continue_write(
        &self,
        request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        match self.inner_layer() {
            Some(inner) => inner.continue_write(request, cancel).await,
            None => Err(unsupported("continue_write")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the target does not exist. The
    ///   built-in file backend treats a missing target as success
    ///   (idempotent delete), but not every backend does.
    /// - [`ErrorCode::PreconditionFailed`] — an `if_match` precondition did
    ///   not match the object's current etag.
    /// - [`ErrorCode::InvalidArgument`] — the target is a directory (use
    ///   [`delete_directory`](Layer::delete_directory)).
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not delete the
    ///   object.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the delete
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn delete(
        &self,
        request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        match self.inner_layer() {
            Some(inner) => inner.delete(request, cancel).await,
            None => Err(unsupported("delete")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the source does not exist.
    /// - [`ErrorCode::AlreadyExists`] — the destination exists and the
    ///   options demand creating a fresh object.
    /// - [`ErrorCode::PreconditionFailed`] — a source or destination etag
    ///   precondition did not match, checked before anything is committed.
    /// - [`ErrorCode::ObjectModified`] — the source changed *during* a
    ///   transfer that had already started, such as a backend's re-check
    ///   of `if_source` after staging the bytes.
    /// - [`ErrorCode::Unsupported`] — this layer does not perform the
    ///   operation for this request and no `copy_rename_fallback` layer is
    ///   composed above it. Differing roots are one such reason, as is a
    ///   precondition the backend cannot enforce; also the leaf default,
    ///   when [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the source
    ///   or destination.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not read the
    ///   source or write the destination.
    /// - [`ErrorCode::ResourceExhausted`] — an emulated transfer exceeded
    ///   its buffering limit.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired mid-transfer.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        match self.inner_layer() {
            Some(inner) => inner.copy(request, cancel).await,
            None => Err(unsupported("copy")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the source does not exist.
    /// - [`ErrorCode::AlreadyExists`] — the destination exists and the
    ///   options demand creating a fresh object.
    /// - [`ErrorCode::PreconditionFailed`] — a source or destination etag
    ///   precondition did not match, checked before anything is committed.
    /// - [`ErrorCode::ObjectModified`] — the source changed *during* a
    ///   transfer that had already started. An emulated rename runs as a
    ///   copy, so it inherits the copy path's post-staging re-check.
    /// - [`ErrorCode::Unsupported`] — this layer does not perform the
    ///   operation for this request and no `copy_rename_fallback` layer is
    ///   composed above it. Differing roots are one such reason, as is a
    ///   precondition the backend cannot enforce; also the leaf default,
    ///   when [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the source
    ///   or destination.
    /// - [`ErrorCode::CommitAmbiguous`] — an emulated rename committed the
    ///   destination but could not confirm the source delete, so the object
    ///   may exist at both addresses.
    /// - [`ErrorCode::DirectoryNotEmpty`] — a directory is renamed onto a
    ///   destination directory that has children, which a native rename cannot
    ///   replace. Non-retryable: replaying the rename cannot empty it. A
    ///   *file* renamed onto a directory is a different refusal and does not
    ///   reach this code.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not move the
    ///   object.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the rename
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn rename(
        &self,
        request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        match self.inner_layer() {
            Some(inner) => inner.rename(request, cancel).await,
            None => Err(unsupported("rename")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — nothing exists at the address.
    /// - [`ErrorCode::PreconditionFailed`] — an `if_match` precondition
    ///   did not match the object's current etag. Detected before
    ///   anything is written, so it is not [`ErrorCode::ObjectModified`].
    /// - [`ErrorCode::InvalidArgument`] — the metadata patch is malformed.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not modify the
    ///   object's metadata.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the update
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        match self.inner_layer() {
            Some(inner) => inner.update_metadata(request, cancel).await,
            None => Err(unsupported("update_metadata")),
        }
    }

    /// # Errors
    ///
    /// A denial is not an error — it is reported in the returned
    /// [`AccessDecision`]. The call itself fails with:
    ///
    /// - [`ErrorCode::NotFound`] — nothing exists at the address.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the check
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn check_access(
        &self,
        request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        match self.inner_layer() {
            Some(inner) => inner.check_access(request, cancel).await,
            None => Err(unsupported("check_access")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — no object exists at the address.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not read the
    ///   object.
    /// - [`ErrorCode::InvalidArgument`] — the address names a directory
    ///   rather than an object. Refuse it here rather than returning a
    ///   [`LocalDelegate`]: the delegate is a path the *host* opens, so a
    ///   directory that is not caught up front fails at the host's `open`,
    ///   far from the call that asked for it. The same guard belongs on any
    ///   op whose result is a handle the caller opens itself.
    /// - [`ErrorCode::Unsupported`] — the layer cannot produce a local
    ///   file for the object; also the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the object was
    ///   materialized.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        match self.inner_layer() {
            Some(inner) => inner.materialize(request, cancel).await,
            None => Err(unsupported("materialize")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the prefix does not exist.
    /// - [`ErrorCode::InvalidArgument`] — the prefix is an object rather
    ///   than a directory, or the page token is malformed.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the prefix.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not enumerate
    ///   the prefix.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the page was
    ///   assembled.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        match self.inner_layer() {
            Some(inner) => inner.list(request, cancel).await,
            None => Err(unsupported("list")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::Unsupported`] — the backend is not versioned; also
    ///   the leaf default, when [`inner_layer`](Layer::inner_layer) is
    ///   `None`.
    /// - [`ErrorCode::NotFound`] — nothing exists at the address.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not enumerate
    ///   versions.
    /// - [`ErrorCode::InvalidArgument`] — the page token is malformed.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the page was
    ///   assembled.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        match self.inner_layer() {
            Some(inner) => inner.list_versions(request, cancel).await,
            None => Err(unsupported("list_versions")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — nothing exists at the address.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not inspect the
    ///   object.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the lookup
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        match self.inner_layer() {
            Some(inner) => inner.get_latest_version(request, cancel).await,
            None => Err(unsupported("get_latest_version")),
        }
    }

    /// Subscribe to changes under a directory prefix.
    ///
    /// Concurrent successful calls are independent logical subscriptions:
    /// from the point each call returns, every subscription receives every
    /// event eligible under its own options. A competing-consumer transport
    /// (each notification delivered to exactly one reader) must self-coalesce
    /// overlapping subscriptions onto one physical consumer in the backend via
    /// the SDK `WatchCoalescer` and pass the
    /// `watch-concurrent-cross-prefix-no-split` conformance scenario, rather
    /// than allowing concurrent calls to split the event stream. For a fixed
    /// prefix and poll interval, a recursive watch MUST contain every event
    /// eligible for the corresponding non-recursive watch, and a
    /// metadata-inclusive watch MUST contain every event eligible when metadata
    /// changes are excluded. This strict-superset contract permits one physical
    /// watch to serve narrower logical subscriptions by filtering. A `since`
    /// cursor requests replay: a resumable backend may serve it from a dedicated
    /// seek reader with real replay, while a non-resumable competing-consumer
    /// backend coalesces onto the live stream and prepends a single initial
    /// `Lapsed` (it does not own a private replay). Either way a `since`
    /// subscription must never attach behind an already-live subscription that
    /// could truncate its replay.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the watched prefix does not exist.
    /// - [`ErrorCode::InvalidArgument`] — the prefix is an object rather
    ///   than a directory.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the prefix.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not watch the
    ///   prefix.
    /// - [`ErrorCode::Unsupported`] — the backend cannot watch; also the
    ///   leaf default, when [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Internal`] — the initial snapshot task failed.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the stream was
    ///   established.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    ///
    /// After this call returns, watch failures surface as `Err` frames on
    /// the returned [`ChangeStream`], using the same codes.
    async fn watch_directory(
        &self,
        request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        match self.inner_layer() {
            Some(inner) => inner.watch_directory(request, cancel).await,
            None => Err(unsupported("watch_directory")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::AlreadyExists`] — the address is already occupied
    ///   by an object.
    /// - [`ErrorCode::InvalidArgument`] — the address is malformed for
    ///   this backend.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not create the
    ///   directory.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the create
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        match self.inner_layer() {
            Some(inner) => inner.create_directory(request, cancel).await,
            None => Err(unsupported("create_directory")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::DirectoryNotEmpty`] — the directory still holds
    ///   entries.
    /// - [`ErrorCode::InvalidArgument`] — the target is an object (use
    ///   [`delete`](Layer::delete)).
    /// - [`ErrorCode::NotFound`] — the directory does not exist.
    /// - [`ErrorCode::NoRoute`] — no configured root matches the address.
    /// - [`ErrorCode::PermissionDenied`] — the caller may not remove the
    ///   directory.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the remove
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable backend I/O failure.
    async fn delete_directory(
        &self,
        request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        match self.inner_layer() {
            Some(inner) => inner.delete_directory(request, cancel).await,
            None => Err(unsupported("delete_directory")),
        }
    }

    /// probe is fed typed-in credentials only; saved/refresh-only connections are
    /// checked via the registered warm-continue `add_connection` path.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — `target` names no layer in this chain.
    /// - [`ErrorCode::InvalidArgument`] — the connection config is
    ///   malformed or incomplete for the backend kind.
    /// - [`ErrorCode::PermissionDenied`], [`ErrorCode::AuthRequired`], or
    ///   [`ErrorCode::CredentialUnavailable`] — the typed-in credentials
    ///   were rejected or are insufficient.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the probe
    ///   finished.
    /// - [`ErrorCode::Transient`] — the backend was unreachable.
    async fn probe(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        match self.inner_layer() {
            Some(inner) => inner.probe(request, cancel).await,
            None => Err(unsupported("probe")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — `target` names no layer in this chain.
    /// - [`ErrorCode::InvalidArgument`] — the connection config is
    ///   malformed or incomplete for the backend kind.
    /// - [`ErrorCode::AlreadyExists`] — an equivalent connection or rule
    ///   is already registered.
    /// - [`ErrorCode::PermissionDenied`], [`ErrorCode::AuthRequired`], or
    ///   [`ErrorCode::CredentialUnavailable`] — the supplied credentials
    ///   were rejected or are insufficient.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the connection
    ///   was registered.
    /// - [`ErrorCode::Transient`] — the backend was unreachable.
    /// - [`ErrorCode::CommitAmbiguous`] — the connection WAS registered on
    ///   its backend, but a layer above it could not confirm that its own
    ///   derived state caught up (the router's route table, for one). Not
    ///   retryable: re-issuing would report `AlreadyExists` for a connection
    ///   that exists. Re-read [`list_connections`](Layer::list_connections)
    ///   instead.
    async fn add_connection(
        &self,
        request: Request<LayerConnectionRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        match self.inner_layer() {
            Some(inner) => inner.add_connection(request, cancel).await,
            None => Err(unsupported("add_connection")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the key names no registered
    ///   connection.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the removal
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable I/O failure while
    ///   deregistering.
    /// - [`ErrorCode::CommitAmbiguous`] — the connection WAS deregistered,
    ///   but a layer above it could not confirm its own derived state caught
    ///   up. Not retryable: re-issuing would report `NotFound` for a
    ///   connection that is already gone. Re-read
    ///   [`list_connections`](Layer::list_connections) instead.
    async fn remove_connection(
        &self,
        key: Request<ConnectionKey>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        match self.inner_layer() {
            Some(inner) => inner.remove_connection(key, cancel).await,
            None => Err(unsupported("remove_connection")),
        }
    }

    /// Snapshot of connections plus an optional live update stream. See
    /// [`root_info_for`](Layer::root_info_for) for the `cx` context contract.
    ///
    /// # Errors
    ///
    /// The leaf default answers an empty snapshot rather than an error.
    /// Aggregating implementations (e.g. the router) propagate child
    /// failures:
    ///
    /// - [`ErrorCode::Transient`] — backend I/O while enumerating
    ///   connections.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired during the fan-out.
    async fn list_connections(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        match self.inner_layer() {
            Some(inner) => inner.list_connections(cx, cancel).await,
            None => Ok((
                ConnectionSnapshot {
                    connections: Vec::new(),
                    updates: false,
                },
                None,
            )),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the key names no registered
    ///   connection.
    /// - [`ErrorCode::InvalidArgument`] — the credential bundle is
    ///   malformed for the backend kind.
    /// - [`ErrorCode::PermissionDenied`], [`ErrorCode::AuthRequired`], or
    ///   [`ErrorCode::CredentialUnavailable`] — the new credentials were
    ///   rejected.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the update
    ///   completed.
    /// - [`ErrorCode::Transient`] — the backend was unreachable.
    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        match self.inner_layer() {
            Some(inner) => inner.update_connection_credentials(request, cancel).await,
            None => Err(unsupported("update_connection_credentials")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the key names no registered
    ///   connection.
    /// - [`ErrorCode::InvalidArgument`] — the attribute patch is
    ///   malformed.
    /// - [`ErrorCode::Unsupported`] — the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the update
    ///   completed.
    /// - [`ErrorCode::Transient`] — retryable I/O failure while
    ///   persisting the patch.
    /// - [`ErrorCode::CommitAmbiguous`] — the patch WAS applied, but a layer
    ///   above it could not confirm its own derived state caught up. Not
    ///   retryable; re-read [`list_connections`](Layer::list_connections)
    ///   instead.
    async fn update_connection_attributes(
        &self,
        request: Request<UpdateConnectionAttributesRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        match self.inner_layer() {
            Some(inner) => inner.update_connection_attributes(request, cancel).await,
            None => Err(unsupported("update_connection_attributes")),
        }
    }

    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — the key names no registered
    ///   connection.
    /// - [`ErrorCode::Unsupported`] — the connection's backend has no
    ///   interactive authentication flow; also the leaf default, when
    ///   [`inner_layer`](Layer::inner_layer) is `None`.
    /// - [`ErrorCode::InvalidArgument`] — the request does not match the
    ///   advertised [`InteractiveAuthCapability`].
    /// - [`ErrorCode::Cancelled`] — `cancel` fired before the flow
    ///   started.
    ///
    /// Flow failures after the stream is established —
    /// [`ErrorCode::AuthRequired`], [`ErrorCode::AuthCancelled`], and
    /// [`ErrorCode::AuthExpired`] — surface as `Err` events on the
    /// returned [`AuthEventStream`].
    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        match self.inner_layer() {
            Some(inner) => inner.authenticate_connection(request, cancel).await,
            None => Err(unsupported("authenticate_connection")),
        }
    }
}

#[async_trait]
pub trait BackendFactory: Send + Sync {
    fn descriptor(&self) -> LayerKindDescriptor;

    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `config` is malformed or
    ///   incomplete for this kind.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired during construction.
    async fn create_backend(
        &self,
        name: &str,
        config: &LayerConfig,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle>;
}

#[async_trait]
pub trait WrapperFactory: Send + Sync {
    fn descriptor(&self) -> LayerKindDescriptor;

    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `config` is malformed or
    ///   incomplete for this kind.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired during construction.
    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle>;
}

#[async_trait]
pub trait RouterFactory: Send + Sync {
    fn descriptor(&self) -> LayerKindDescriptor;

    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — `config` is malformed, or two
    ///   children claim the same connection target.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired during construction.
    /// - Any error a child returns while the router enumerates its
    ///   address roots (see [`Layer::list_address_roots`]).
    async fn create_router(
        &self,
        name: &str,
        config: &LayerConfig,
        children: Vec<LayerHandle>,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerSpec {
    pub name: String,
    pub kind: String,
    pub layer_type: LayerType,
    pub config: LayerConfig,
    pub inner: Option<String>,
    pub children: Vec<String>,
}

impl LayerSpec {
    pub fn backend(name: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            layer_type: LayerType::Backend,
            config: LayerConfig::new(),
            inner: None,
            children: Vec::new(),
        }
    }

    pub fn wrapper(
        name: impl Into<String>,
        kind: impl Into<String>,
        inner: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            layer_type: LayerType::Wrapper,
            config: LayerConfig::new(),
            inner: Some(inner.into()),
            children: Vec::new(),
        }
    }

    pub fn router(name: impl Into<String>, kind: impl Into<String>, children: Vec<String>) -> Self {
        Self {
            name: name.into(),
            kind: kind.into(),
            layer_type: LayerType::Router,
            config: LayerConfig::new(),
            inner: None,
            children,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackSpec {
    pub root: String,
    pub layers: Vec<LayerSpec>,
    pub connections: Vec<LayerConnectionRequest>,
}

impl StackSpec {
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            layers: Vec::new(),
            connections: Vec::new(),
        }
    }
}

/// A built layer chain, addressable through the [`Layer`] trait.
///
/// `Stack` is the canonicalization boundary for the chain: its [`Layer`] impl
/// [`canonicalize`]s every address-bearing request (and `root_info_for` query)
/// before delegating to `root`, so **every layer below sees a canonical URL
/// spelling** — the precondition the alias/rewrite wrappers, the caches
/// (cache-key identity), and the router rely on. Because the contract is
/// enforced at the `Stack` boundary, consumers using any binding get the same
/// validation. See
/// [`crate::address`] for the canonicalization rule itself.
pub struct Stack {
    spec: StackSpec,
    root: LayerHandle,
}

impl Stack {
    pub fn builder(root: impl Into<String>) -> StackBuilder {
        StackBuilder::new(root)
    }

    pub fn spec(&self) -> &StackSpec {
        &self.spec
    }

    pub fn root(&self) -> &LayerHandle {
        &self.root
    }
}

#[async_trait]
impl Layer for Stack {
    fn name(&self) -> &str {
        self.root.name()
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.root.descriptor()
    }

    /// Pure pass-through slots (root/connection introspection + the
    /// connection lifecycle) delegate to `root` via the trait defaults; the
    /// address-bearing ops below stay bespoke because they canonicalize
    /// before delegating.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.root)
    }

    // `Stack` is transparent — it presents the root layer's identity rather
    // than adding a layer of its own (see `name`/`descriptor` above), so the
    // self-prepending wrapper defaults for these two slots would double-count
    // the root layer.

    fn owned_targets(&self) -> Vec<String> {
        self.root.owned_targets()
    }

    fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
        self.root.list_kinds(cx)
    }

    async fn root_info_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let canonical = canonicalize(url.clone());
        self.root.root_info_for(&canonical, cx, cancel).await
    }

    /// The default body delegates straight through, which would route an
    /// unnormalized URL. `Stack` is the normalization boundary, so it
    /// canonicalizes here for the same reason it does on every request slot.
    /// An address with no canonical form has no owner.
    async fn owning_target_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Option<String> {
        let canonical = canonicalize(url.clone());
        self.root.owning_target_for(&canonical, cx, cancel).await
    }

    async fn stat(
        &self,
        mut request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        request.input.address = canonicalize(request.input.address);
        self.root.stat(request, cancel).await
    }

    async fn read(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        request.input.address = canonicalize(request.input.address);
        self.root.read(request, cancel).await
    }

    async fn write(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        request.input.address = canonicalize(request.input.address);
        self.root.write(request, cancel).await
    }

    async fn write_stream(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        request.input.address = canonicalize(request.input.address);
        self.root.write_stream(request, cancel).await
    }

    async fn write_redirect(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        request.input.address = canonicalize(request.input.address);
        self.root.write_redirect(request, cancel).await
    }

    async fn continue_write(
        &self,
        mut request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        request.input.address = canonicalize(request.input.address);
        self.root.continue_write(request, cancel).await
    }

    async fn delete(
        &self,
        mut request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        request.input.address = canonicalize(request.input.address);
        self.root.delete(request, cancel).await
    }

    async fn copy(
        &self,
        mut request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        request.input.source = canonicalize(request.input.source);
        request.input.destination = canonicalize(request.input.destination);
        self.root.copy(request, cancel).await
    }

    async fn rename(
        &self,
        mut request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        request.input.source = canonicalize(request.input.source);
        request.input.destination = canonicalize(request.input.destination);
        self.root.rename(request, cancel).await
    }

    async fn update_metadata(
        &self,
        mut request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        request.input.address = canonicalize(request.input.address);
        self.root.update_metadata(request, cancel).await
    }

    async fn check_access(
        &self,
        mut request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        request.input.address = canonicalize(request.input.address);
        self.root.check_access(request, cancel).await
    }

    async fn materialize(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        request.input.address = canonicalize(request.input.address);
        self.root.materialize(request, cancel).await
    }

    async fn list(
        &self,
        mut request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        request.input.prefix = canonicalize(request.input.prefix);
        self.root.list(request, cancel).await
    }

    async fn list_versions(
        &self,
        mut request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        request.input.address = canonicalize(request.input.address);
        self.root.list_versions(request, cancel).await
    }

    async fn get_latest_version(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        request.input.address = canonicalize(request.input.address);
        self.root.get_latest_version(request, cancel).await
    }

    async fn watch_directory(
        &self,
        mut request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        request.input.prefix = canonicalize(request.input.prefix);
        self.root.watch_directory(request, cancel).await
    }

    async fn create_directory(
        &self,
        mut request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        request.input.address = canonicalize(request.input.address);
        self.root.create_directory(request, cancel).await
    }

    async fn delete_directory(
        &self,
        mut request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        request.input.address = canonicalize(request.input.address);
        self.root.delete_directory(request, cancel).await
    }
}

pub struct StackBuilder {
    spec: StackSpec,
    factories: HashMap<String, FactoryEntry>,
    factory_collisions: Vec<String>,
    attached: HashMap<String, LayerHandle>,
}

impl StackBuilder {
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            spec: StackSpec::new(root),
            factories: HashMap::new(),
            factory_collisions: Vec::new(),
            attached: HashMap::new(),
        }
    }

    pub fn layer(mut self, spec: LayerSpec) -> Self {
        self.spec.layers.push(spec);
        self
    }

    /// Mount a pre-built [`LayerHandle`] under `name` as a child. `build()`
    /// uses the handle verbatim instead of resolving a factory, and
    /// `validate_graph` counts the attached name as one reference like any
    /// declared layer — so a shared attached handle is still rejected. This is
    /// the primitive that lets several per-listener stacks (e.g. one authz
    /// Layer per authenticated listener) share one inner `Stack`.
    pub fn attach(mut self, name: impl Into<String>, handle: LayerHandle) -> Self {
        self.attached.insert(name.into(), handle);
        self
    }

    pub fn connection(mut self, connection: LayerConnectionRequest) -> Self {
        self.spec.connections.push(connection);
        self
    }

    pub fn backend_factory(mut self, factory: Arc<dyn BackendFactory>) -> Self {
        let descriptor = factory.descriptor();
        if self
            .factories
            .insert(descriptor.kind.clone(), FactoryEntry::Backend(factory))
            .is_some()
        {
            self.factory_collisions.push(descriptor.kind);
        }
        self
    }

    pub fn wrapper_factory(mut self, factory: Arc<dyn WrapperFactory>) -> Self {
        let descriptor = factory.descriptor();
        if self
            .factories
            .insert(descriptor.kind.clone(), FactoryEntry::Wrapper(factory))
            .is_some()
        {
            self.factory_collisions.push(descriptor.kind);
        }
        self
    }

    pub fn router_factory(mut self, factory: Arc<dyn RouterFactory>) -> Self {
        let descriptor = factory.descriptor();
        if self
            .factories
            .insert(descriptor.kind.clone(), FactoryEntry::Router(factory))
            .is_some()
        {
            self.factory_collisions.push(descriptor.kind);
        }
        self
    }

    /// # Errors
    ///
    /// The same contract as [`build_with_cancel`](Self::build_with_cancel)
    /// (with no cancellation token).
    pub async fn build(self) -> Result<Stack> {
        self.build_with_cancel(None).await
    }

    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the layer graph is invalid: a
    ///   layer declared more than once, referenced but not declared,
    ///   referenced by two parents, shaped wrongly for its `layer_type`,
    ///   part of a cycle, or two registered factories advertise the same kind.
    /// - [`ErrorCode::NotConfigured`] — a declared kind has no registered
    ///   factory.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired during the build.
    /// - Any error a factory returns while instantiating a layer, or a
    ///   layer returns while applying a configured connection (see
    ///   [`Layer::add_connection`]).
    pub async fn build_with_cancel(self, cancel: Option<CancellationToken>) -> Result<Stack> {
        if let Some(kind) = self.factory_collisions.first() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("more than one Layer factory advertises kind '{kind}'"),
            ));
        }
        let specs = self.layer_map()?;
        validate_graph(&self.spec.root, &specs, &self.factories, &self.attached)?;
        let mut memo = HashMap::new();
        let root = instantiate_layer(
            &self.spec.root,
            &specs,
            &self.factories,
            &self.attached,
            &mut memo,
            &cancel,
        )
        .await?;

        for connection in &self.spec.connections {
            // A build-time connection apply is a trusted host/config action that
            // flows through the management slots un-gated: the built-in auth Layer
            // does not gate management ops, so the host applies its own configured
            // `[[connections]]` without a per-principal check.
            let request = Request::new(connection.clone());
            let target = connection.target.clone();
            match root.add_connection(request, cancel.clone()).await {
                Ok(_) => {}
                // A declared connection whose caller-facing route is already
                // served cannot be routed no matter how the host reacts to
                // it: the address it would answer for resolves to the
                // connection that claimed the route first. Refusing to build
                // therefore buys nothing for that connection while costing
                // every unrelated backend in the graph — one duplicated
                // `[[connections]]` entry would stop the whole host, and a
                // host that auto-restarts turns that into a restart loop.
                //
                // So this is reported and skipped, not fatal. The runtime
                // `add_connection` path still returns the refusal, where a
                // caller is present to read it and act.
                //
                // The arm below catches `RouteConflict` and nothing else,
                // the code that conventionally means "the caller-facing route
                // is already served". Skipping is safe exactly when that
                // convention holds: if the refusing Layer already holds — or has
                // reserved — a connection publishing the newcomer's root,
                // then the addresses the newcomer would answer for resolve
                // to the incumbent within that Layer whatever the host does,
                // so skipping costs it nothing. Both in-tree producers satisfy
                // it: nucleus keys on exact-root equality, and plugin-http keys
                // on node equality (`assets` and `assets/` are one root), which
                // satisfies it for the same reason — the route table merges
                // those two spellings, so the newcomer's addresses resolve to
                // the incumbent there as well. What the requirement forbids is
                // refusing a root that merely *contains* the newcomer's.
                //
                // This arm does not verify that; it is a requirement placed
                // on a Layer that returns the code, not a checked fact. A
                // Layer returning `RouteConflict` for a *containing* root
                // would break it — `x://h/a/` refusing `x://h/a/b/`, which
                // are independently routable under longest-prefix lookup —
                // and its connection would be dropped rather than shadowed.
                //
                // It is also NOT a graph-wide exclusivity guarantee. Two
                // sibling Layers can each accept a connection on one root
                // without either raising anything, because neither sees the
                // other's roots; the route table logs an overlap warning and
                // keeps both. That case never reaches this arm.
                //
                // Do not widen this arm. A broader catch would swallow
                // refusals that mean something else — the alias layer's
                // duplicate-*id* `AlreadyExists` names no address at all, and
                // skipping it would silently drop an enforced visibility
                // rule. Every other error still aborts the build, which is
                // what a malformed `root_url` or an unknown target relies on.
                //
                // This loop is mirrored in `ovstorage-python`'s composer
                // (`ovstorage-core/ovstorage-python/src/lib.rs`), which runs
                // its own copy so it can capture each returned `Connection`
                // id. Any change to this arm belongs there too — the copy
                // shipped without this tolerance and aborted a Python host's
                // whole stack build on one duplicate.
                Err(err) if err.code() == ErrorCode::RouteConflict => {
                    tracing::warn!(
                        target: "ovstorage.stack",
                        layer = %target,
                        reason = %crate::redact::redact_message(err.message()),
                        "skipping a declared connection whose route is already served; \
                         the rest of the stack is unaffected"
                    );
                }
                Err(err) => return Err(err),
            }
        }

        Ok(Stack {
            spec: self.spec,
            root,
        })
    }

    fn layer_map(&self) -> Result<HashMap<String, LayerSpec>> {
        let mut specs = HashMap::new();
        for spec in &self.spec.layers {
            if specs.insert(spec.name.clone(), spec.clone()).is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("layer '{}' is declared more than once", spec.name),
                ));
            }
        }
        Ok(specs)
    }
}

enum FactoryEntry {
    Backend(Arc<dyn BackendFactory>),
    Wrapper(Arc<dyn WrapperFactory>),
    Router(Arc<dyn RouterFactory>),
}

impl FactoryEntry {
    fn descriptor(&self) -> LayerKindDescriptor {
        match self {
            Self::Backend(factory) => factory.descriptor(),
            Self::Wrapper(factory) => factory.descriptor(),
            Self::Router(factory) => factory.descriptor(),
        }
    }
}

fn validate_graph(
    root: &str,
    specs: &HashMap<String, LayerSpec>,
    factories: &HashMap<String, FactoryEntry>,
    attached: &HashMap<String, LayerHandle>,
) -> Result<()> {
    let mut visits = HashMap::<String, usize>::new();
    let mut active = HashSet::new();
    walk(root, specs, factories, attached, &mut visits, &mut active)?;
    for (name, count) in visits {
        if count > 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("layer '{name}' is referenced more than once"),
            ));
        }
    }
    Ok(())
}

fn walk(
    name: &str,
    specs: &HashMap<String, LayerSpec>,
    factories: &HashMap<String, FactoryEntry>,
    attached: &HashMap<String, LayerHandle>,
    visits: &mut HashMap<String, usize>,
    active: &mut HashSet<String>,
) -> Result<()> {
    // An attached handle is an opaque pre-built leaf: it has no `LayerSpec`,
    // factory, or children to descend into, but it counts as a reference so a
    // handle shared by two parents is still rejected.
    if attached.contains_key(name) {
        *visits.entry(name.to_string()).or_insert(0) += 1;
        return Ok(());
    }

    let spec = specs.get(name).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("layer '{name}' is referenced but not declared"),
        )
    })?;
    let descriptor = factory_for(spec, factories)?.descriptor();
    if descriptor.layer_type != spec.layer_type {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("layer '{}' declares a mismatched layer_type", spec.name),
        ));
    }
    validate_shape(spec)?;

    *visits.entry(name.to_string()).or_insert(0) += 1;
    if !active.insert(name.to_string()) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("layer graph contains a cycle at '{name}'"),
        ));
    }

    for child in child_names(spec) {
        walk(child, specs, factories, attached, visits, active)?;
    }
    active.remove(name);
    Ok(())
}

fn validate_shape(spec: &LayerSpec) -> Result<()> {
    match spec.layer_type {
        LayerType::Backend => {
            if spec.inner.is_some() || !spec.children.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("backend layer '{}' must not declare children", spec.name),
                ));
            }
        }
        LayerType::Wrapper => {
            if spec.inner.is_none() || !spec.children.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "wrapper layer '{}' must declare exactly one inner",
                        spec.name
                    ),
                ));
            }
        }
        LayerType::Router => {
            // A router routes to children, never to an `inner`. Zero children is
            // a valid degenerate state (a Stack with no backends configured):
            // every address then routes to `NoRoute`.
            if spec.inner.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "router layer '{}' must not declare an inner (it routes to children)",
                        spec.name
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn child_names(spec: &LayerSpec) -> impl Iterator<Item = &str> {
    spec.inner
        .iter()
        .map(String::as_str)
        .chain(spec.children.iter().map(String::as_str))
}

fn factory_for<'a>(
    spec: &LayerSpec,
    factories: &'a HashMap<String, FactoryEntry>,
) -> Result<&'a FactoryEntry> {
    factories.get(&spec.kind).ok_or_else(|| {
        Error::new(
            ErrorCode::NotConfigured,
            format!("no factory registered for layer kind '{}'", spec.kind),
        )
    })
}

async fn instantiate_layer(
    name: &str,
    specs: &HashMap<String, LayerSpec>,
    factories: &HashMap<String, FactoryEntry>,
    attached: &HashMap<String, LayerHandle>,
    memo: &mut HashMap<String, LayerHandle>,
    cancel: &Option<CancellationToken>,
) -> Result<LayerHandle> {
    if let Some(existing) = memo.get(name) {
        return Ok(existing.clone());
    }

    // A pre-built attached handle is used verbatim — no factory resolution.
    if let Some(handle) = attached.get(name) {
        memo.insert(name.to_string(), handle.clone());
        return Ok(handle.clone());
    }

    let spec = specs.get(name).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("layer '{name}' is referenced but not declared"),
        )
    })?;

    let handle = match factory_for(spec, factories)? {
        FactoryEntry::Backend(factory) => {
            factory
                .create_backend(name, &spec.config, cancel.clone())
                .await?
        }
        FactoryEntry::Wrapper(factory) => {
            let inner_name = spec
                .inner
                .as_deref()
                .expect("wrapper shape validated before instantiation");
            let inner = Box::pin(instantiate_layer(
                inner_name, specs, factories, attached, memo, cancel,
            ))
            .await?;
            factory
                .create_wrapper(name, &spec.config, inner, cancel.clone())
                .await?
        }
        FactoryEntry::Router(factory) => {
            let mut children = Vec::with_capacity(spec.children.len());
            for child in &spec.children {
                children.push(
                    Box::pin(instantiate_layer(
                        child, specs, factories, attached, memo, cancel,
                    ))
                    .await?,
                );
            }
            factory
                .create_router(name, &spec.config, children, cancel.clone())
                .await?
        }
    };

    memo.insert(name.to_string(), handle.clone());
    Ok(handle)
}

fn unsupported(slot: &str) -> Error {
    Error::new(
        ErrorCode::Unsupported,
        format!("layer does not support {slot}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn extensions_clone_local_values_without_serializing_them() {
        let marker = Arc::new(());
        let mut extensions = Extensions::new();
        extensions.insert("wire", vec![1, 2, 3]);
        extensions.insert_local(Arc::clone(&marker));

        let cloned = extensions.clone();
        assert!(Arc::ptr_eq(
            cloned.get_local::<Arc<()>>().expect("local marker"),
            &marker
        ));

        let mut wire_only = Extensions::new();
        wire_only.insert("wire", vec![1, 2, 3]);
        assert_eq!(cloned, wire_only);
        assert_eq!(
            cloned.into_iter().collect::<Vec<_>>(),
            vec![("wire".to_string(), vec![1, 2, 3])]
        );
    }

    #[test]
    fn layer_trait_is_object_safe_send_sync() {
        fn assert_layer_object(_: Arc<dyn Layer + Send + Sync>) {}
        assert_layer_object(Arc::new(MockLayer::new(
            "object-safe",
            descriptor("mock", LayerType::Backend, false),
        )));
    }

    #[tokio::test]
    async fn stack_builder_rejects_duplicate_factory_kinds() {
        let result = Stack::builder("root")
            .backend_factory(Arc::new(MockBackendFactory {
                accepts_connections: false,
            }))
            .backend_factory(Arc::new(MockBackendFactory {
                accepts_connections: true,
            }))
            .layer(LayerSpec::backend("root", "backend"))
            .build()
            .await;
        let error = match result {
            Ok(_) => panic!("duplicate factory kinds must not silently overwrite"),
            Err(error) => error,
        };

        assert_eq!(error.code(), ErrorCode::InvalidArgument);
        assert!(
            error
                .message()
                .contains("more than one Layer factory advertises kind 'backend'"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn stack_builder_rejects_cycles() {
        let err = match Stack::builder("a")
            .wrapper_factory(Arc::new(MockWrapperFactory))
            .layer(LayerSpec::wrapper("a", "wrapper", "b"))
            .layer(LayerSpec::wrapper("b", "wrapper", "a"))
            .build()
            .await
        {
            Ok(_) => panic!("cycle should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("cycle"), "{err}");
    }

    #[tokio::test]
    async fn stack_builder_rejects_duplicate_connection_owner() {
        let err = match Stack::builder("router")
            .backend_factory(Arc::new(MockBackendFactory {
                accepts_connections: true,
            }))
            .router_factory(Arc::new(MockRouterFactory))
            .layer(LayerSpec::router(
                "router",
                "router",
                vec!["backend".into(), "backend".into()],
            ))
            .layer(LayerSpec::backend("backend", "backend"))
            .build()
            .await
        {
            Ok(_) => panic!("duplicate connection owner should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("referenced more than once"), "{err}");
    }

    #[tokio::test]
    async fn stack_builder_rejects_shared_non_connection_layers() {
        let backend_creates = Arc::new(AtomicUsize::new(0));
        let err = match Stack::builder("router")
            .backend_factory(Arc::new(CountingBackendFactory {
                creates: backend_creates.clone(),
            }))
            .wrapper_factory(Arc::new(MockWrapperFactory))
            .router_factory(Arc::new(MockRouterFactory))
            .layer(LayerSpec::router(
                "router",
                "router",
                vec!["left".into(), "right".into()],
            ))
            .layer(LayerSpec::wrapper("left", "wrapper", "backend"))
            .layer(LayerSpec::wrapper("right", "wrapper", "backend"))
            .layer(LayerSpec::backend("backend", "backend"))
            .build()
            .await
        {
            Ok(_) => panic!("shared non-connection layer should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(
            err.message()
                .contains("layer 'backend' is referenced more than once"),
            "{err}"
        );
        assert_eq!(backend_creates.load(Ordering::SeqCst), 0);
    }

    /// A pre-built `LayerHandle` mounted with `attach` builds as a child and
    /// routed ops reach it — the primitive that lets per-listener auth stacks
    /// share one inner `Stack`.
    #[tokio::test]
    async fn attach_mounts_a_prebuilt_handle_as_child() {
        let inner: LayerHandle = build_probe_inner_stack();
        let stack = Stack::builder("top")
            .wrapper_factory(Arc::new(PassthroughWrapperFactory))
            .layer(LayerSpec::wrapper("top", "passthrough", "inner"))
            .attach("inner", inner.clone())
            .build()
            .await
            .expect("attach builds a 2-node tree");
        // a routed op reaches the attached inner
        assert!(stack.stat(probe_stat_request(), None).await.is_ok());
    }

    /// The same attached name referenced by two parents is still rejected by
    /// `validate_graph` — an attached handle counts as one reference like any
    /// other layer.
    #[tokio::test]
    async fn attach_handle_counts_as_one_reference() {
        let inner: LayerHandle = build_probe_inner_stack();
        let err = match Stack::builder("router")
            .router_factory(Arc::new(MockRouterFactory))
            .wrapper_factory(Arc::new(PassthroughWrapperFactory))
            .layer(LayerSpec::router(
                "router",
                "router",
                vec!["a".into(), "b".into()],
            ))
            .layer(LayerSpec::wrapper("a", "passthrough", "inner"))
            .layer(LayerSpec::wrapper("b", "passthrough", "inner"))
            .attach("inner", inner)
            .build()
            .await
        {
            Ok(_) => panic!("shared attached handle should be rejected"),
            Err(err) => err,
        };
        assert!(err.message().contains("referenced more than once"), "{err}");
    }

    #[tokio::test]
    async fn router_factory_receives_owned_targets_for_wrapped_backend() {
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        Stack::builder("router")
            .backend_factory(Arc::new(MockBackendFactory {
                accepts_connections: true,
            }))
            .wrapper_factory(Arc::new(MockWrapperFactory))
            .router_factory(Arc::new(OwnedTargetsRouterFactory {
                observed: observed.clone(),
            }))
            .layer(LayerSpec::router(
                "router",
                "router",
                vec!["wrapper".into()],
            ))
            .layer(LayerSpec::wrapper("wrapper", "wrapper", "backend"))
            .layer(LayerSpec::backend("backend", "backend"))
            .build()
            .await
            .unwrap();

        assert_eq!(
            *observed.lock().unwrap(),
            vec![("wrapper".to_string(), vec!["backend".to_string()])]
        );
    }

    #[tokio::test]
    async fn stack_builder_threads_cancellation_to_factories_and_connections() {
        let counters = Arc::new(CancelCounters::default());
        let cancel = CancellationToken::new();
        Stack::builder("router")
            .backend_factory(Arc::new(CancelBackendFactory {
                counters: counters.clone(),
            }))
            .wrapper_factory(Arc::new(CancelWrapperFactory {
                counters: counters.clone(),
            }))
            .router_factory(Arc::new(CancelRouterFactory {
                counters: counters.clone(),
            }))
            .layer(LayerSpec::router(
                "router",
                "router",
                vec!["wrapper".into()],
            ))
            .layer(LayerSpec::wrapper("wrapper", "wrapper", "backend"))
            .layer(LayerSpec::backend("backend", "backend"))
            .connection(LayerConnectionRequest {
                target: "router".into(),
                connection: ConnectionRequest {
                    backend_kind: "router".into(),
                    config: HashMap::new(),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            })
            .build_with_cancel(Some(cancel))
            .await
            .unwrap();

        assert_eq!(counters.backend.load(Ordering::SeqCst), 1);
        assert_eq!(counters.wrapper.load(Ordering::SeqCst), 1);
        assert_eq!(counters.router.load(Ordering::SeqCst), 1);
        assert_eq!(counters.connection.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stack_builder_builds_bottom_up_and_applies_connections() {
        let stack = Stack::builder("wrapper")
            .backend_factory(Arc::new(MockBackendFactory {
                accepts_connections: true,
            }))
            .wrapper_factory(Arc::new(MockWrapperFactory))
            .layer(LayerSpec::wrapper("wrapper", "wrapper", "backend"))
            .layer(LayerSpec::backend("backend", "backend"))
            .connection(LayerConnectionRequest {
                target: "backend".into(),
                connection: ConnectionRequest {
                    backend_kind: "backend".into(),
                    config: HashMap::new(),
                    credentials: SecretBundle::default(),
                    persist: false,
                    display_name: None,
                },
            })
            .build()
            .await
            .unwrap();

        let (snapshot, _) = stack
            .list_connections(&Extensions::new(), None)
            .await
            .unwrap();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].id.0, "created");
    }

    /// A wrapper that overrides only `inner_layer` (plus the
    /// required `name`/`descriptor`) must delegate every pass-through slot to
    /// its inner layer through the trait defaults — no bespoke method bodies.
    struct MinimalWrapper {
        inner: LayerHandle,
    }

    #[async_trait]
    impl Layer for MinimalWrapper {
        fn name(&self) -> &str {
            "minimal-wrapper"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("minimal-wrapper", LayerType::Wrapper, false)
        }

        fn inner_layer(&self) -> Option<&LayerHandle> {
            Some(&self.inner)
        }
    }

    /// Records every operational-slot invocation and answers with a
    /// `NotFound` sentinel, so a delegated call is distinguishable from the
    /// `Unsupported` a missed delegation (leaf default) would produce.
    #[derive(Default)]
    struct RecordingLayer {
        calls: std::sync::Mutex<Vec<&'static str>>,
    }

    impl RecordingLayer {
        fn record<T>(&self, slot: &'static str) -> Result<T> {
            self.calls.lock().unwrap().push(slot);
            Err(Error::new(ErrorCode::NotFound, "recorded"))
        }
    }

    macro_rules! recording_layer_impl {
        ($(($method:ident, $request:ty, $response:ty)),* $(,)?) => {
            #[async_trait]
            impl Layer for RecordingLayer {
                fn name(&self) -> &str {
                    "recorder"
                }

                fn descriptor(&self) -> LayerKindDescriptor {
                    descriptor("recorder", LayerType::Backend, true)
                }

                async fn root_info_for(
                    &self,
                    _url: &Url,
                    _cx: &Extensions,
                    _cancel: Option<CancellationToken>,
                ) -> Result<RootInfo> {
                    self.record("root_info_for")
                }

                async fn list_address_roots(
                    &self,
                    _cx: &Extensions,
                    _cancel: Option<CancellationToken>,
                ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
                    self.record("list_address_roots")
                }

                async fn list_connections(
                    &self,
                    _cx: &Extensions,
                    _cancel: Option<CancellationToken>,
                ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
                    self.record("list_connections")
                }

                $(
                    async fn $method(
                        &self,
                        _request: Request<$request>,
                        _cancel: Option<CancellationToken>,
                    ) -> Result<$response> {
                        self.record(stringify!($method))
                    }
                )*
            }
        };
    }

    recording_layer_impl!(
        (stat, StatRequest, ObjectInfo),
        (read, ReadRequest, ReadResult),
        (write, WriteRequest, WriteResult),
        (write_stream, WriteRequest, WriteResult),
        (write_redirect, WriteRequest, WriteRedirectBatch),
        (continue_write, ContinueWriteRequest, WriteStep),
        (delete, DeleteRequest, ()),
        (copy, CopyRequest, WriteStep),
        (rename, RenameRequest, ()),
        (update_metadata, UpdateMetadataRequest, BackendItemInfo),
        (check_access, CheckAccessRequest, AccessDecision),
        (materialize, ReadRequest, LocalDelegate),
        (list, ListRequest, ListPage),
        (list_versions, ListVersionsRequest, VersionPage),
        (get_latest_version, ReadRequest, ObjectInfo),
        (watch_directory, WatchDirectoryRequest, ChangeStream),
        (create_directory, CreateDirectoryRequest, BackendItemInfo),
        (delete_directory, DeleteDirectoryRequest, ()),
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

    #[tokio::test]
    async fn wrapper_defaults_delegate_every_pass_through_slot_to_inner() {
        let recorder = Arc::new(RecordingLayer::default());
        let wrapper = MinimalWrapper {
            inner: recorder.clone(),
        };

        let url = || Url::parse("test://root/obj").unwrap();
        let read = || ReadRequest {
            address: url(),
            options: ReadOptions::default(),
        };
        let write = || WriteRequest {
            address: url(),
            body: Body::Bytes(Vec::new()),
            options: WriteOptions::default(),
        };
        let connection = || LayerConnectionRequest {
            target: "recorder".into(),
            connection: ConnectionRequest {
                backend_kind: "recorder".into(),
                config: HashMap::new(),
                credentials: SecretBundle::default(),
                persist: false,
                display_name: None,
            },
        };
        let key = || ConnectionKey {
            target: "recorder".into(),
            id: ConnectionId("c1".into()),
        };

        // Every pass-through slot, driven through the wrapper in the frozen
        // vtable slot order, must reach the recorder (the `NotFound` sentinel;
        // a missed delegation would surface the leaf `Unsupported` default).
        let sentinel = ErrorCode::NotFound;
        assert_eq!(
            wrapper
                .root_info_for(&url(), &Extensions::new(), None)
                .await
                .unwrap_err()
                .code(),
            sentinel
        );
        let code = match wrapper.list_address_roots(&Extensions::new(), None).await {
            Ok(_) => panic!("`list_address_roots` unexpectedly succeeded"),
            Err(err) => err.code(),
        };
        assert_eq!(code, sentinel, "`list_address_roots` did not delegate");
        macro_rules! assert_delegates {
            ($method:ident, $request:expr) => {
                let code = match wrapper.$method(Request::new($request), None).await {
                    Ok(_) => panic!(concat!(
                        "`",
                        stringify!($method),
                        "` unexpectedly succeeded"
                    )),
                    Err(err) => err.code(),
                };
                assert_eq!(
                    code, sentinel,
                    concat!("`", stringify!($method), "` did not delegate"),
                );
            };
        }
        assert_delegates!(
            stat,
            StatRequest {
                address: url(),
                options: StatOptions::default(),
            }
        );
        assert_delegates!(read, read());
        assert_delegates!(write, write());
        assert_delegates!(write_stream, write());
        assert_delegates!(write_redirect, write());
        assert_delegates!(
            continue_write,
            ContinueWriteRequest {
                address: url(),
                redirects: WriteRedirectBatch {
                    continuation: Vec::new(),
                    redirects: Vec::new(),
                },
                results: RedirectResultBatch {
                    results: Vec::new(),
                },
            }
        );
        assert_delegates!(
            delete,
            DeleteRequest {
                address: url(),
                options: DeleteOptions::default(),
            }
        );
        assert_delegates!(
            copy,
            CopyRequest {
                source: url(),
                destination: url(),
                options: CopyOptions::default(),
            }
        );
        assert_delegates!(
            rename,
            RenameRequest {
                source: url(),
                destination: url(),
                options: RenameOptions::default(),
            }
        );
        assert_delegates!(
            update_metadata,
            UpdateMetadataRequest {
                address: url(),
                options: UpdateMetadataOptions::default(),
            }
        );
        assert_delegates!(
            check_access,
            CheckAccessRequest {
                address: url(),
                operations: AccessOps::default(),
            }
        );
        assert_delegates!(materialize, read());
        assert_delegates!(
            list,
            ListRequest {
                prefix: url(),
                options: ListOptions::default(),
            }
        );
        assert_delegates!(
            list_versions,
            ListVersionsRequest {
                address: url(),
                options: ListVersionsOptions::default(),
            }
        );
        assert_delegates!(get_latest_version, read());
        assert_delegates!(
            watch_directory,
            WatchDirectoryRequest {
                prefix: url(),
                options: WatchDirectoryOptions::default(),
            }
        );
        assert_delegates!(
            create_directory,
            CreateDirectoryRequest {
                address: url(),
                options: CreateDirectoryOptions::default(),
            }
        );
        assert_delegates!(
            delete_directory,
            DeleteDirectoryRequest {
                address: url(),
                options: DeleteDirectoryOptions,
            }
        );
        assert_delegates!(probe, connection());
        assert_delegates!(add_connection, connection());
        assert_delegates!(remove_connection, key());
        let code = match wrapper.list_connections(&Extensions::new(), None).await {
            Ok(_) => panic!("`list_connections` unexpectedly succeeded"),
            Err(err) => err.code(),
        };
        assert_eq!(code, sentinel, "`list_connections` did not delegate");
        assert_delegates!(
            update_connection_credentials,
            UpdateConnectionCredentialsRequest {
                key: key(),
                credentials: SecretBundle::default(),
            }
        );
        assert_delegates!(
            update_connection_attributes,
            UpdateConnectionAttributesRequest {
                key: key(),
                patch: AttributePatch::default(),
            }
        );
        assert_delegates!(
            authenticate_connection,
            AuthenticateRequest {
                key: key(),
                capability: InteractiveAuthCapability::None,
                auto_open_browser: false,
            }
        );

        // The recorder saw exactly the slots above, in order.
        assert_eq!(
            *recorder.calls.lock().unwrap(),
            vec![
                "root_info_for",
                "list_address_roots",
                "stat",
                "read",
                "write",
                "write_stream",
                "write_redirect",
                "continue_write",
                "delete",
                "copy",
                "rename",
                "update_metadata",
                "check_access",
                "materialize",
                "list",
                "list_versions",
                "get_latest_version",
                "watch_directory",
                "create_directory",
                "delete_directory",
                "probe",
                "add_connection",
                "remove_connection",
                "list_connections",
                "update_connection_credentials",
                "update_connection_attributes",
                "authenticate_connection",
            ],
        );

        // Structural defaults compose the wrapper with the inner layer.
        assert_eq!(wrapper.owned_targets(), vec!["recorder".to_string()]);
        let kinds: Vec<String> = wrapper
            .list_kinds(&Extensions::new())
            .unwrap()
            .into_iter()
            .map(|kind| kind.kind)
            .collect();
        assert_eq!(kinds, vec!["minimal-wrapper", "recorder"]);

        // A leaf without an inner layer keeps the `Unsupported` default, so a
        // backend that opts out of a slot is untouched by the delegation hook.
        let leaf = MockLayer::new("leaf", descriptor("leaf", LayerType::Backend, false));
        assert_eq!(
            leaf.stat(
                Request::new(StatRequest {
                    address: url(),
                    options: StatOptions::default(),
                }),
                None,
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::Unsupported,
        );
    }

    /// `Stack` presents the root layer's identity (`name`/`descriptor`
    /// mirror `root`), so its `owned_targets`/`list_kinds` must not
    /// self-prepend the way the wrapper delegation defaults do — that would
    /// double-count the root layer.
    #[test]
    fn stack_presents_root_identity_without_adding_a_layer() {
        let recorder: LayerHandle = Arc::new(RecordingLayer::default());
        let stack = Stack {
            spec: StackSpec::new("recorder"),
            root: recorder,
        };
        assert_eq!(stack.owned_targets(), vec!["recorder".to_string()]);
        let kinds: Vec<String> = stack
            .list_kinds(&Extensions::new())
            .unwrap()
            .into_iter()
            .map(|kind| kind.kind)
            .collect();
        assert_eq!(kinds, vec!["recorder".to_string()]);
    }

    struct MockLayer {
        name: String,
        descriptor: LayerKindDescriptor,
        inner: Option<LayerHandle>,
        children: Vec<LayerHandle>,
        connection_cancel_observer: Option<Arc<CancelCounters>>,
        connections: std::sync::Mutex<Vec<Connection>>,
    }

    impl MockLayer {
        fn new(name: &str, descriptor: LayerKindDescriptor) -> Self {
            Self {
                name: name.into(),
                descriptor,
                inner: None,
                children: Vec::new(),
                connection_cancel_observer: None,
                connections: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn with_inner(name: &str, descriptor: LayerKindDescriptor, inner: LayerHandle) -> Self {
            Self {
                name: name.into(),
                descriptor,
                inner: Some(inner),
                children: Vec::new(),
                connection_cancel_observer: None,
                connections: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn with_children(
            name: &str,
            descriptor: LayerKindDescriptor,
            children: Vec<LayerHandle>,
        ) -> Self {
            Self {
                name: name.into(),
                descriptor,
                inner: None,
                children,
                connection_cancel_observer: None,
                connections: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn with_connection_cancel_observer(
            name: &str,
            descriptor: LayerKindDescriptor,
            observer: Arc<CancelCounters>,
            children: Vec<LayerHandle>,
        ) -> Self {
            Self {
                name: name.into(),
                descriptor,
                inner: None,
                children,
                connection_cancel_observer: Some(observer),
                connections: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Layer for MockLayer {
        fn name(&self) -> &str {
            &self.name
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            self.descriptor.clone()
        }

        fn owned_targets(&self) -> Vec<String> {
            let mut targets = if self.descriptor.accepts_connections {
                vec![self.name.clone()]
            } else {
                Vec::new()
            };
            if let Some(inner) = &self.inner {
                targets.extend(inner.owned_targets());
            }
            for child in &self.children {
                targets.extend(child.owned_targets());
            }
            targets
        }

        async fn add_connection(
            &self,
            request: Request<LayerConnectionRequest>,
            cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            if cancel.is_some()
                && let Some(observer) = &self.connection_cancel_observer
            {
                observer.connection.fetch_add(1, Ordering::SeqCst);
            }
            if self.name != request.input.target {
                if let Some(inner) = &self.inner {
                    return inner.add_connection(request, cancel).await;
                }
                for child in &self.children {
                    if child
                        .owned_targets()
                        .iter()
                        .any(|target| target == &request.input.target)
                    {
                        return child.add_connection(request, cancel).await;
                    }
                }
                return Err(Error::new(ErrorCode::NotFound, "target not found"));
            }
            let connection = Connection {
                id: ConnectionId("created".into()),
                backend_kind: request.input.connection.backend_kind,
                display_name: "created".into(),
                source: ConnectionSource::Runtime { persisted: false },
                capabilities: Capabilities::empty(),
                current_addresses: Vec::new(),
                auth_state: ConnectionAuthState::Anonymous,
                last_probed: None,
                user_metadata: UserMetadata::new(),
            };
            self.connections.lock().unwrap().push(connection.clone());
            Ok(connection)
        }

        async fn list_connections(
            &self,
            cx: &Extensions,
            cancel: Option<CancellationToken>,
        ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
            // Snapshot the local connections and drop the guard before any
            // `await` so the future stays `Send`.
            let mut connections = self.connections.lock().unwrap().clone();
            if let Some(inner) = &self.inner {
                connections.extend(
                    inner
                        .list_connections(cx, cancel.clone())
                        .await?
                        .0
                        .connections,
                );
            }
            for child in &self.children {
                connections.extend(
                    child
                        .list_connections(cx, cancel.clone())
                        .await?
                        .0
                        .connections,
                );
            }
            Ok((
                ConnectionSnapshot {
                    connections,
                    updates: false,
                },
                None,
            ))
        }
    }

    struct CountingBackendFactory {
        creates: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BackendFactory for CountingBackendFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("backend", LayerType::Backend, false)
        }

        async fn create_backend(
            &self,
            name: &str,
            _config: &LayerConfig,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            self.creates.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(MockLayer::new(name, self.descriptor())))
        }
    }

    #[derive(Default)]
    struct CancelCounters {
        backend: AtomicUsize,
        wrapper: AtomicUsize,
        router: AtomicUsize,
        connection: AtomicUsize,
    }

    struct CancelBackendFactory {
        counters: Arc<CancelCounters>,
    }

    #[async_trait]
    impl BackendFactory for CancelBackendFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("backend", LayerType::Backend, false)
        }

        async fn create_backend(
            &self,
            name: &str,
            _config: &LayerConfig,
            cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            if cancel.is_some() {
                self.counters.backend.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Arc::new(MockLayer::new(name, self.descriptor())))
        }
    }

    struct CancelWrapperFactory {
        counters: Arc<CancelCounters>,
    }

    #[async_trait]
    impl WrapperFactory for CancelWrapperFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("wrapper", LayerType::Wrapper, false)
        }

        async fn create_wrapper(
            &self,
            name: &str,
            _config: &LayerConfig,
            inner: LayerHandle,
            cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            if cancel.is_some() {
                self.counters.wrapper.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Arc::new(MockLayer::with_inner(
                name,
                self.descriptor(),
                inner,
            )))
        }
    }

    struct CancelRouterFactory {
        counters: Arc<CancelCounters>,
    }

    #[async_trait]
    impl RouterFactory for CancelRouterFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("router", LayerType::Router, false)
        }

        async fn create_router(
            &self,
            name: &str,
            _config: &LayerConfig,
            children: Vec<LayerHandle>,
            cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            if cancel.is_some() {
                self.counters.router.fetch_add(1, Ordering::SeqCst);
            }
            Ok(Arc::new(MockLayer::with_connection_cancel_observer(
                name,
                self.descriptor(),
                self.counters.clone(),
                children,
            )))
        }
    }

    struct MockBackendFactory {
        accepts_connections: bool,
    }

    #[async_trait]
    impl BackendFactory for MockBackendFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("backend", LayerType::Backend, self.accepts_connections)
        }

        async fn create_backend(
            &self,
            name: &str,
            _config: &LayerConfig,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            Ok(Arc::new(MockLayer::new(name, self.descriptor())))
        }
    }

    struct MockWrapperFactory;

    #[async_trait]
    impl WrapperFactory for MockWrapperFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("wrapper", LayerType::Wrapper, false)
        }

        async fn create_wrapper(
            &self,
            name: &str,
            _config: &LayerConfig,
            inner: LayerHandle,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            Ok(Arc::new(MockLayer::with_inner(
                name,
                self.descriptor(),
                inner,
            )))
        }
    }

    struct MockRouterFactory;

    #[async_trait]
    impl RouterFactory for MockRouterFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("router", LayerType::Router, false)
        }

        async fn create_router(
            &self,
            name: &str,
            _config: &LayerConfig,
            children: Vec<LayerHandle>,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            Ok(Arc::new(MockLayer::with_children(
                name,
                self.descriptor(),
                children,
            )))
        }
    }

    type ObservedRouterChildren = Arc<std::sync::Mutex<Vec<(String, Vec<String>)>>>;

    struct OwnedTargetsRouterFactory {
        observed: ObservedRouterChildren,
    }

    #[async_trait]
    impl RouterFactory for OwnedTargetsRouterFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("router", LayerType::Router, false)
        }

        async fn create_router(
            &self,
            name: &str,
            _config: &LayerConfig,
            children: Vec<LayerHandle>,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            let mut observed = self.observed.lock().unwrap();
            *observed = children
                .iter()
                .map(|child| (child.name().to_string(), child.owned_targets()))
                .collect();
            Ok(Arc::new(MockLayer::with_children(
                name,
                self.descriptor(),
                children,
            )))
        }
    }

    /// A leaf backend whose `stat` answers `Ok`, so a routed op that reaches it
    /// is distinguishable from the `Unsupported`/`NotFound` a missed hop yields.
    struct ProbeInner;

    #[async_trait]
    impl Layer for ProbeInner {
        fn name(&self) -> &str {
            "probe-inner"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("probe-inner", LayerType::Backend, false)
        }

        async fn stat(
            &self,
            request: Request<StatRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            Ok(ObjectInfo::from((
                request.input.address,
                BackendItemInfo::default(),
            )))
        }
    }

    /// A pre-built `LayerHandle` a builder can `attach`.
    fn build_probe_inner_stack() -> LayerHandle {
        Arc::new(ProbeInner)
    }

    fn probe_stat_request() -> Request<StatRequest> {
        Request::new(StatRequest {
            address: Url::parse("test://root/obj").unwrap(),
            options: StatOptions::default(),
        })
    }

    /// A wrapper factory whose layer delegates every pass-through slot to its
    /// inner (via the `inner_layer()` default), so a routed op reaches the
    /// attached child.
    struct PassthroughWrapperFactory;

    #[async_trait]
    impl WrapperFactory for PassthroughWrapperFactory {
        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor("passthrough", LayerType::Wrapper, false)
        }

        async fn create_wrapper(
            &self,
            _name: &str,
            _config: &LayerConfig,
            inner: LayerHandle,
            _cancel: Option<CancellationToken>,
        ) -> Result<LayerHandle> {
            Ok(Arc::new(MinimalWrapper { inner }))
        }
    }

    fn descriptor(
        kind: &str,
        layer_type: LayerType,
        accepts_connections: bool,
    ) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: kind.into(),
            layer_type,
            display_name: kind.into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections,
            auth_capable: false,
            // These are graph-wiring fixtures rather than storage: nothing
            // built here persists a write, so no host should compose an
            // attribution layer over one.
            supports_user_metadata: false,
        }
    }
}
