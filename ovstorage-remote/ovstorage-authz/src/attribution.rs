// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-layer attribution of `modified_by`.
//!
//! ## Why
//! The brokered case forces a separation between *the principal that
//! authenticated to the broker* (e.g. `alice@example.com` via OIDC) and
//! *the principal the backend sees* (the broker's service account).
//! Backends that record per-write identity natively will record the
//! broker, not Alice. Backends that don't record it at all (S3, GCS,
//! Azure) leave `modified_by` empty in direct Stack mode.
//!
//! This layer is the trust boundary's overlay: the broker, having just
//! authenticated Alice, stamps her identity into a reserved key in
//! `user_metadata` (`ovstorage-modified-by`) on every mutating call that
//! carries caller metadata — `write`, `write_stream`, `write_redirect`
//! and `update_metadata`. `copy`, `rename` and `create_directory` carry
//! no `user_metadata` in their options, so there is nothing to stamp.
//! `continue_write` carries no options either, and the metadata its
//! commit applies rode out to the client inside a plugin-encoded
//! continuation; the identity is asserted on that request's extensions
//! instead, and the plugin performing the commit applies it — see
//! [`AttributionLayer::stamp_continue_write`].
//! It harvests the same key back into the typed
//! [`ObjectInfo::modified_by`](ovstorage_plugin::ObjectInfo::modified_by)
//! field, and hides it from the surfaced `user_metadata` map, on every
//! result that carries such a pair — reads and stats, list and version
//! pages, and the results of writes, continuations, copies, metadata
//! updates and directory creation.
//!
//! ## Strategies
//! - [`AttributionStrategy::UserMetadata`] (default): stamp + harvest
//!   the reserved key.
//! - [`AttributionStrategy::Passthrough`]: no-op. Use for intermediate
//!   brokers in a chain so the upstream broker's stamp survives
//!   end-to-end (`UserMetadata → Passthrough → backend` preserves
//!   the original principal — on writes whose bytes go through the
//!   host; see the redirect discussion under Threat model, where what
//!   survives is a copy the client held).
//! - [`AttributionStrategy::ExternalDb`]: reserved for v2; broker
//!   refuses to start with `NotConfigured`.
//!
//! ## Cost gating
//! Populating `modified_by` from a plugin's *native* source can require
//! extra OS calls (POSIX `getpwuid_r`, Windows DACL probe) or extra
//! round-trips. `StatOptions::full_metadata` / `ListOptions::full_metadata`
//! exist for a plugin to gate that behind; the file backend is the only
//! one in this tree that does, and the cloud plugins report no native
//! `modified_by` at all. Harvesting a broker-attested stamp is not gated
//! and costs nothing extra: the key is already in the `user_metadata`
//! the backend returned.
//!
//! ## Placement
//! Hosts compose this Layer **below the router, one instance per
//! branch**, and only on branches whose backend kind declares it can
//! carry a `user_metadata` key
//! ([`crate::UserMetadataKinds::carries_attribution`]). Two properties
//! follow, and they are why the placement is what it is:
//!
//! - The `copy_rename_fallback` wrapper emulates a copy or rename by
//!   fabricating a write and issuing it through its own `inner`. Only a
//!   Layer below that wrapper is in the fabricated write's path, so a
//!   branch instance attributes an emulated copy and an instance at the
//!   graph root does not.
//! - A branch whose backend kind declares that it does not accept the
//!   host's stamp omits the Layer, so the host never manufactures
//!   metadata that backend must refuse. **Omission follows the
//!   declaration, not a capability**: a kind that declines may still
//!   store `user_metadata` a caller supplies, and a kind that leaves
//!   the field unset declines by default without its author deciding
//!   anything. So an omitted branch is not one where a planted reserved
//!   key is known to be refused — see the threat model below, which
//!   turns on exactly that. That holds within one host. It does not
//!   survive a
//!   broker chain: a `broker` branch carries the Layer, so the
//!   client-facing host stamps and the map travels in `WriteOptions` to
//!   the host it fronts — which may route it at exactly such a backend.
//!   The receiving host strips nothing on that branch, under any
//!   strategy, because `strip_reserved` runs only inside the two stamp
//!   functions and that branch has no Layer to run them. No placement
//!   fixes it either, since the stamping branch is in another process:
//!   the levers are routing that connection at a backend which carries
//!   metadata, or giving up attribution at the client-facing host.
//!   Fixing it by placement would need a sanitize-only mode this Layer
//!   does not have.
//!
//! [`crate::ensure_branch_attribution`] is what makes that composition a
//! guarantee rather than a convention.
//!
//! ## Threat model
//! **Scoped to branches that carry this Layer in `UserMetadata` mode,
//! and to writes whose bytes go through the host.** There, the broker
//! overwrites whatever the client supplied for `ovstorage-modified-by`,
//! so a client cannot succeed at spoofing through the broker, and it
//! strips other `ovstorage-*` keys from the inbound `user_metadata`
//! (defensive — the namespace is reserved).
//!
//! **A redirect write is the exception, and it depends on the backend.**
//! The stamp is placed in options the backend turns into a presigned
//! request, and what happens to it next is the backend's business, not
//! this Layer's. Three shapes:
//!
//! - **Bound at mint, server-side.** S3 signs `x-amz-meta-*` into the
//!   presigned URL, so altering the stamp invalidates the signature, and
//!   holds a multipart upload's metadata from `CreateMultipartUpload`
//!   onward. GCS commits it when the resumable session is initiated,
//!   before the client uploads at all. The client never holds the copy
//!   that lands on the object. It does hold the copy the **reported**
//!   `ObjectInfo` is built from — S3's multipart commit rebuilds it from
//!   the continuation, and GCS parses it out of the response body the
//!   caller captured — but that copy is put right here rather than in
//!   any plugin: see
//!   [`AttributionLayer::assert_reported_attribution`]. On a single host
//!   those name the same principal whenever one principal drives the
//!   whole upload; where a different principal finalizes, the report
//!   names the finalizer and the object keeps the minter.
//!
//!   **Reported and persisted can also differ by host rather than by
//!   principal**, in two places worth knowing. On a chain the report is
//!   asserted by the *outer* host and the object is written by the
//!   *deeper* one, so `UserMetadata → UserMetadata` reports the outer
//!   broker's principal over an object holding the deeper one's — which
//!   also means a redirect write and a host-bytes write through the same
//!   chain report different principals, since `write` only harvests what
//!   came back. And where the persisted write is best-effort (the
//!   services-client's post-commit metadata update) the report is
//!   asserted whether or not that update landed: it is a true statement
//!   about who this host authenticated for the write, over an object
//!   that may still carry the previous writer until the stash succeeds.
//! - **Applied by a commit this host performs.** Azure's staged
//!   block-blob path sets metadata on `Put Block List`, because a block
//!   blob does not exist while its blocks are staged; the
//!   services-client's metadata service is addressed by the resource the
//!   commit creates. Both carry the stamp in the plugin's continuation,
//!   which the caller echoes back to `continue_write` — so
//!   [`AttributionLayer::stamp_continue_write`] asserts the authenticated principal
//!   on that request's extensions and the plugin puts it over whatever
//!   travelled. What is persisted is the value this host held at commit
//!   — for the services-client, as far as a best-effort metadata update
//!   after the object is already written can carry it: that update is
//!   not part of the commit, so a failure leaves the key at whatever the
//!   object held before, and a delayed one can land after another writer
//!   has overwritten the address. Making it an audit guarantee needs the
//!   service to accept attribution as part of the atomic commit.
//!   `write_redirect` and `continue_write` are separately authorized
//!   calls and nothing binds them to one principal, so where a different
//!   principal finalizes an upload it is *that* principal who is
//!   recorded — the one this host authenticated and authorized for
//!   `Write` on the address the commit lands on. The alternative on this
//!   path is not the minter's identity but an unauthenticated copy of it.
//! - **Committed by the client's own PUT.** Azure's inline path returns
//!   `x-ms-meta-*` as ordinary request headers and its SAS signs no
//!   headers; S3's single-PUT redirect is the client's request too.
//!   There is no later call of ours to write anything with, so **a client
//!   taking the inline Azure redirect can rewrite or drop the stamp on
//!   the object.** That is a property of the plugin's presign, not of
//!   placement — it held with this Layer at the graph root too. The
//!   `ObjectInfo` `continue_write` reports for such a write is parsed
//!   from headers the caller captured, and is put right here like every
//!   other report: the object's value is the caller's, but a
//!   broker-vouched *report* naming someone else is not.
//!
//! **The two halves of the commit-time assertion sit in different
//! places, because only one of them can be made anywhere else.** What is
//! *reported* is asserted here, in [`AttributionLayer::assert_reported_attribution`],
//! which every `continue_write` result passes through. What is
//! *persisted* can only be asserted by the plugin, because only the
//! plugin can decode its own continuation — so that is the one duty a
//! backend owes, and a backend this build has never heard of gets correct
//! reports without knowing anything about it — on the branches that carry
//! this Layer at all, which is the ones whose kind declares it can hold the
//! reserved key.
//!
//! **The persisted assertion is made by the host that performs the
//! commit**, which in a chain is the deepest one. `UserMetadata →
//! UserMetadata` therefore persists the deeper broker's principal, the
//! same re-stamp the chain already performs at mint. `UserMetadata →
//! Passthrough` persists whatever the continuation carried: the deeper
//! host is composed to assert nothing, extensions do not cross the broker
//! RPC, and so the value the client echoed is the one applied. Closing
//! that needs the deeper host to trust an assertion made by the host
//! above it — the trusted-upstream-broker delegation noted below.
//!
//! **Only the persisted half of that chain is open.** The outer host
//! holds its own authenticated principal and asserts the reported value
//! on the way back out, so a client forging the reserved key in a
//! continuation does not get it returned as this host's `modified_by` —
//! it gets it written to the object beneath a host that was told not to
//! interfere.
//!
//! **The `broker` branch is why the reported assertion is made here.**
//! Its plugin forwards over an RPC that carries no extensions, so it
//! cannot be told what to assert and could not do this for itself; an
//! outer host would otherwise harvest whatever the inner one returned.
//!
//! On a branch that omits the Layer, and under `Passthrough` on any
//! branch, neither happens: `strip_reserved` has no caller outside the
//! stamp functions, and nothing else on the path sanitizes client
//! metadata. A client's value for the reserved key then reaches the
//! backend, and **whether it is stored is the backend's own business —
//! nothing here establishes that it is not.** A branch omits the Layer
//! because its kind declared `supports_user_metadata = false`, or left
//! the field unset, and neither is a statement that the backend refuses
//! or discards what it is handed. `opendal` is the in-tree case: it
//! declines the host's stamp while keeping a caller's own keys on the
//! drivers that advertise them. A third-party kind that stores
//! `user_metadata` and declares `false` persists the planted key, and a
//! kind whose author never set the field reaches the same place without
//! deciding anything. So the set of branches that store a planted
//! reserved key is not knowable from the declaration, and it is wider
//! than a `Passthrough` instance in front of a storing backend.
//!
//! **That absence is local to one branch of one host; the harvest is
//! not.** On the unsanitized branch itself a planted key stays a raw
//! `user_metadata` entry, and `modified_by` reports whatever the backend
//! natively knows, if anything. But a `broker` branch carries this Layer
//! deliberately, so that an upstream stamp survives a chain — and it
//! harvests whatever the host beneath it returned. A client writes the
//! reserved key through broker B on a branch that omits the Layer;
//! broker A fronts B through a `broker` connection; on stat through A
//! the plugin forwards B's `user_metadata` verbatim, [`unwrap_read`]
//! promotes the planted value into `modified_by` and hides the
//! namespace, and a client of A cannot tell it from an attested one.
//!
//! **So `modified_by` from a chained broker is only as trustworthy as
//! the sanitizing on every branch beneath it.** No policy decision reads
//! `modified_by`, so the impact is on display and audit integrity rather
//! than access control. Closing it needs a sanitize-only mode of this
//! Layer, or an inbound `strip_reserved` at a host protocol boundary, on
//! the branches that omit the stamp. Until one of those exists, treat
//! `modified_by` as host-vouched only where this host performed the
//! commit and every branch beneath it sanitizes.
//!
//! [`unwrap_read`]: AttributionLayer::unwrap_read
//!
//! A direct Stack writer that bypasses the broker entirely can write any
//! value to the reserved key; the broker has no signature to verify.
//! Treat the broker as the only mutating path or use HMAC-signed values
//! (deferred).
//!
//! ## Chained brokers
//! `client → local broker (UserMetadata) → remote broker (Passthrough)
//! → backend` preserves Alice's identity end-to-end for writes whose
//! bytes go through the hosts. Two `UserMetadata` brokers in a chain
//! re-stamp at the deeper broker and lose the original principal —
//! documented behavior; trusted-upstream-broker delegation is a future
//! enhancement.
//!
//! **A redirect write commits at the deeper host, and only the deeper
//! host's assertion reaches the plugin**: extensions do not cross the
//! broker RPC, which builds a fresh bag per request precisely so a
//! client cannot inject one. So the two chains diverge on a redirect —
//! `UserMetadata → UserMetadata` persists the deeper broker's principal,
//! and `UserMetadata → Passthrough` persists whatever the continuation
//! carried, which a client held. The same trusted-upstream-broker
//! delegation is what would close it.

use ovstorage_plugin::{Error, ErrorCode, ObjectInfo, Result, UpdateMetadataOptions, WriteOptions};

use crate::Principal;

use std::sync::Arc;

use async_trait::async_trait;
use ovstorage::wrappers::ext;
use ovstorage::{
    BackendItemInfo, CancellationToken, ContinueWriteRequest, CopyRequest, CreateDirectoryRequest,
    Extensions, Layer, LayerConfig, LayerHandle, LayerKindDescriptor, LayerType, ListPage,
    ListRequest, ListVersionsRequest, LocalDelegate, ReadRequest, ReadResult, Request, StatRequest,
    UpdateMetadataRequest, VersionPage, WrapperFactory, WriteRedirectBatch, WriteRequest,
    WriteResult, WriteStep,
};

// The key and its namespace are defined in `ovstorage-layer`, the crate this
// overlay and the plugin SDK both depend on: a plugin that commits a redirect
// write re-asserts this key over the copy that came back through the caller,
// and `check-plugin-deps` forbids a plugin crate from depending on this
// host-side crate. One definition, so the stamp and the re-assertion cannot
// drift to two spellings.
pub use ovstorage_plugin::{ATTRIBUTION_KEY_MODIFIED_BY, RESERVED_METADATA_PREFIX};
use ovstorage_plugin::{
    is_reserved_metadata_key as is_reserved_key, strip_reserved_metadata as strip_reserved,
};

/// Storage channel for broker-attested attribution. Configurable so
/// chained-broker setups (`UserMetadata → Passthrough`) can preserve
/// the original principal end-to-end.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum AttributionStrategy {
    /// Default. Stamp `ovstorage-modified-by` into `user_metadata`
    /// and read it back on stat/list.
    #[default]
    UserMetadata,
    /// Don't touch `user_metadata`. The plugin's native modified_by
    /// (or any reserved keys forwarded from an upstream broker) flow
    /// through unchanged.
    Passthrough,
    /// Reserved for a future external-DB strategy. Current hosts refuse to start.
    ExternalDb,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttributionLayer {
    strategy: AttributionStrategy,
}

impl AttributionLayer {
    pub fn new(strategy: AttributionStrategy) -> Result<Self> {
        if strategy == AttributionStrategy::ExternalDb {
            return Err(Error::new(
                ErrorCode::NotConfigured,
                "external_db attribution strategy is not yet implemented",
            ));
        }
        Ok(Self { strategy })
    }

    pub fn strategy(&self) -> AttributionStrategy {
        self.strategy
    }

    pub fn stamp_write(&self, principal: &Principal, opts: &mut WriteOptions) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        let map = opts.user_metadata.get_or_insert_with(Default::default);
        strip_reserved(map);
        map.insert(
            ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
            principal.id.clone(),
        );
    }

    /// Assert the writer identity for a redirect commit, on the request
    /// extensions rather than in any options — `ContinueWriteRequest` carries
    /// no options, and the metadata the commit applies lives inside a
    /// plugin-encoded continuation this layer cannot decode.
    ///
    /// A plugin whose backend **persists** that metadata at commit reads
    /// [`ext::ATTRIBUTED_MODIFIED_BY`] and puts this value over whatever the
    /// continuation carried. It is the only duty a plugin owes here: what a
    /// `continue_write` *reports* is asserted by
    /// [`Self::assert_reported_attribution`] on the way back out.
    ///
    /// The extension says "an attribution layer spoke for this request", which
    /// is narrower than [`ext::PRINCIPAL_ID`]: a branch
    /// fronting a backend that cannot hold the reserved key carries no instance
    /// of this layer, and a `Passthrough` instance asserts nothing. A plugin
    /// reading the principal directly would attribute on both.
    pub fn stamp_continue_write(&self, principal: &Principal, extensions: &mut Extensions) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        extensions.insert(
            ext::ATTRIBUTED_MODIFIED_BY.to_string(),
            principal.id.clone().into_bytes(),
        );
    }

    /// Put the resolved principal over the reserved key in a result the
    /// caller's own data shaped, before [`Self::unwrap_read`] harvests it into
    /// the typed `modified_by`.
    ///
    /// Only for `continue_write`. Every other verb's result comes back from the
    /// backend describing what the backend stored, and overwriting the reserved
    /// key there would discard an upstream host's attested value on a chain
    /// rather than protect anything.
    ///
    /// This makes `modified_by` on a `continue_write` result an attestation
    /// about who performed the finalize rather than a read-back of what the
    /// object stores, and the plugin CONFORMANCE guide exempts that one field
    /// on that one verb for exactly this reason. The two differ where the
    /// backend bound its copy earlier, where a chained host wrote the object,
    /// and where the attribution write is a separate best-effort step; `stat`
    /// remains the authority on what is stored.
    pub fn assert_reported_attribution(&self, principal: &Principal, info: &mut ObjectInfo) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        ovstorage_plugin::reassert_attribution(Some(&principal.id), &mut info.user_metadata);
    }

    pub fn stamp_update_metadata(&self, principal: &Principal, opts: &mut UpdateMetadataOptions) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        strip_reserved(&mut opts.user_metadata_set);
        opts.user_metadata_remove.retain(|k| !is_reserved_key(k));
        opts.user_metadata_set.insert(
            ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
            principal.id.clone(),
        );
    }

    /// Promote the broker-attested key into the typed `modified_by`
    /// slot, and hide the reserved namespace from clients. Applied to
    /// every result carrying that pair, not only stat and list.
    pub fn unwrap_read(&self, info: &mut ObjectInfo) {
        self.unwrap_fields(&mut info.user_metadata, &mut info.modified_by);
    }

    /// The field-level body of [`Self::unwrap_read`], operating on the
    /// `user_metadata` / `modified_by` pair carried by both
    /// [`ObjectInfo`] and
    /// [`BackendItemInfo`]. The
    /// in-stack `attribution` Layer unwraps
    /// `BackendItemInfo` results (`create_directory` / `update_metadata`)
    /// through this seam; `unwrap_read` unwraps `ObjectInfo`.
    pub fn unwrap_fields(
        &self,
        user_metadata: &mut Option<std::collections::HashMap<String, String>>,
        modified_by: &mut Option<String>,
    ) {
        if self.strategy != AttributionStrategy::UserMetadata {
            return;
        }
        let Some(map) = user_metadata.as_mut() else {
            return;
        };
        if let Some(value) = map.remove(ATTRIBUTION_KEY_MODIFIED_BY) {
            *modified_by = Some(value);
        }
        // Hide any other reserved-namespace keys so they don't leak
        // to clients; only the typed slot exposes broker state.
        map.retain(|k, _| !is_reserved_key(k));
        if map.is_empty() {
            *user_metadata = None;
        }
    }
}

// ===========================================================================
// Attribution as an in-stack storage Layer
// ===========================================================================

/// Layer kind string for the in-stack attribution wrapper. Referenced by core
/// composers by string only; core never names this type.
pub const ATTRIBUTION_KIND: &str = "attribution";

fn attribution_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        display_name: ATTRIBUTION_KIND.to_string(),
        kind: ATTRIBUTION_KIND.to_string(),
        layer_type: LayerType::Wrapper,
        description: Some("Broker-attested modified_by attribution overlay".to_string()),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: false,
        supports_user_metadata: false,
    }
}

/// [`WrapperFactory`] for the in-stack [`AttributionWrapper`]. The strategy is
/// **injected** by the host (like the cache-instance injection), not read from
/// layer config — the broker owns its `attribution_strategy` config.
///
/// One factory serves a whole process, so every wrapper it creates shares that
/// one strategy: a graph can vary attribution's *placement* per branch but not
/// its *behaviour*. A branch that must not stamp omits the Layer rather than
/// configuring it differently.
pub struct AttributionWrapperFactory {
    strategy: AttributionStrategy,
}

impl AttributionWrapperFactory {
    pub fn new(strategy: AttributionStrategy) -> Self {
        Self { strategy }
    }
}

#[async_trait]
impl WrapperFactory for AttributionWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        attribution_descriptor()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Arc::new(AttributionWrapper::new(
            name,
            inner,
            AttributionLayer::new(self.strategy)?,
        )))
    }
}

/// Attribution as an in-stack storage [`Layer`]. It relocates the broker's
/// host-side attribution overlay (`stamp_write` / `stamp_update_metadata` /
/// `unwrap_read`) below the per-listener auth Layer: it reads the resolved
/// principal from [`ext::PRINCIPAL_ID`] (stamped DOWN by the auth Layer above
/// it), stamps `modified_by` into the mutating verbs' options on the way down,
/// and harvests it back into the typed `modified_by` slot on the way up. All
/// other slots auto-delegate through the [`Layer::inner_layer`] default.
///
/// The `Passthrough` strategy makes every stamp/unwrap a no-op (the overlay's
/// own strategy check), so an intermediate-broker chain preserves an upstream
/// stamp end-to-end even with this Layer composed.
pub struct AttributionWrapper {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    overlay: AttributionLayer,
}

impl AttributionWrapper {
    pub fn new(name: impl Into<String>, inner: LayerHandle, overlay: AttributionLayer) -> Self {
        Self {
            name: name.into(),
            descriptor: attribution_descriptor(),
            inner,
            overlay,
        }
    }

    /// The resolved principal stamped by the auth Layer above, or the anonymous
    /// id when absent (matching the auth Layer's own absence semantics).
    fn principal(&self, cx: &Extensions) -> Principal {
        let id = match cx.get(ext::PRINCIPAL_ID) {
            Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            None => ovstorage_authz_context::ANONYMOUS_PRINCIPAL_ID.to_string(),
        };
        Principal {
            id,
            display_name: None,
            attributes: std::collections::HashMap::new(),
            valid_until: None,
            source: String::new(),
        }
    }

    /// Harvest attribution out of a [`BackendItemInfo`] result
    /// (`create_directory` / `update_metadata`).
    fn unwrap_item(&self, item: &mut BackendItemInfo) {
        self.overlay
            .unwrap_fields(&mut item.user_metadata, &mut item.modified_by);
    }
}

#[async_trait]
impl Layer for AttributionWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let mut info = self.inner.stat(request, cancel).await?;
        self.overlay.unwrap_read(&mut info);
        Ok(info)
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        match self.inner.read(request, cancel).await? {
            ReadResult::Bytes { bytes, mut info } => {
                self.overlay.unwrap_read(&mut info);
                Ok(ReadResult::Bytes { bytes, info })
            }
            ReadResult::Stream { stream, mut info } => {
                self.overlay.unwrap_read(&mut info);
                Ok(ReadResult::Stream { stream, info })
            }
            ReadResult::LocalDelegate(mut local) => {
                self.overlay.unwrap_read(&mut local.info);
                Ok(ReadResult::LocalDelegate(local))
            }
            other @ ReadResult::Redirect(_) => Ok(other),
        }
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        // Mirror `read`'s LocalDelegate arm: the direct-disk verb also returns
        // an `ObjectInfo` whose reserved attribution keys must be unwrapped.
        let mut local = self.inner.materialize(request, cancel).await?;
        self.overlay.unwrap_read(&mut local.info);
        Ok(local)
    }

    async fn write(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let principal = self.principal(&request.extensions);
        self.overlay
            .stamp_write(&principal, &mut request.input.options);
        let mut result = self.inner.write(request, cancel).await?;
        self.overlay.unwrap_read(&mut result.info);
        Ok(result)
    }

    async fn write_stream(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let principal = self.principal(&request.extensions);
        self.overlay
            .stamp_write(&principal, &mut request.input.options);
        let mut result = self.inner.write_stream(request, cancel).await?;
        self.overlay.unwrap_read(&mut result.info);
        Ok(result)
    }

    async fn write_redirect(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let principal = self.principal(&request.extensions);
        self.overlay
            .stamp_write(&principal, &mut request.input.options);
        self.inner.write_redirect(request, cancel).await
    }

    async fn continue_write(
        &self,
        mut request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let principal = self.principal(&request.extensions);
        self.overlay
            .stamp_continue_write(&principal, &mut request.extensions);
        let mut step = self.inner.continue_write(request, cancel).await?;
        if let WriteStep::Done(result) = &mut step {
            // The reported half of the assertion, made here and nowhere else.
            // Some `continue_write` results are built from what the caller
            // handed back — S3's multipart commit rebuilds its metadata from
            // the continuation, GCS parses it out of a captured response body,
            // Azure's inline branch out of captured headers — and others come
            // straight from the backend. Rather than sort them, this asserts
            // the reserved key on all of them: it is the value this host is
            // entitled to state either way, and this is the one place every
            // result passes through, including the `broker` branch, whose
            // plugin forwards over an RPC that carries no extensions and so
            // could not be told what to assert. Doing it here rather than per
            // plugin is what makes a backend this build has never heard of
            // report honestly, on a branch carrying this wrapper, without
            // owing anything. What a plugin still owns
            // alone is the *persisted* copy: only the plugin can decode its
            // own continuation.
            self.overlay
                .assert_reported_attribution(&principal, &mut result.info);
            self.overlay.unwrap_read(&mut result.info);
        }
        Ok(step)
    }

    async fn copy(
        &self,
        request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let mut step = self.inner.copy(request, cancel).await?;
        if let WriteStep::Done(result) = &mut step {
            self.overlay.unwrap_read(&mut result.info);
        }
        Ok(step)
    }

    async fn update_metadata(
        &self,
        mut request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let principal = self.principal(&request.extensions);
        self.overlay
            .stamp_update_metadata(&principal, &mut request.input.options);
        let mut item = self.inner.update_metadata(request, cancel).await?;
        self.unwrap_item(&mut item);
        Ok(item)
    }

    async fn create_directory(
        &self,
        request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let mut item = self.inner.create_directory(request, cancel).await?;
        self.unwrap_item(&mut item);
        Ok(item)
    }

    async fn list(
        &self,
        request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let mut page = self.inner.list(request, cancel).await?;
        for item in page.items.iter_mut() {
            self.overlay.unwrap_read(item);
        }
        Ok(page)
    }

    async fn list_versions(
        &self,
        request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let mut page = self.inner.list_versions(request, cancel).await?;
        for item in page.items.iter_mut() {
            self.overlay.unwrap_read(item);
        }
        Ok(page)
    }

    async fn get_latest_version(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let mut info = self.inner.get_latest_version(request, cancel).await?;
        self.overlay.unwrap_read(&mut info);
        Ok(info)
    }
}

#[cfg(test)]
mod tests {

    /// Two attribution instances on one request must behave as one. The graph
    /// guarantee makes that unreachable within a single host, but a broker chain
    /// still stacks them: a `UserMetadata` broker fronting another one applies the
    /// overlay twice to the same options.
    ///
    /// `stamp_update_metadata` is where that is least obvious. It strips the
    /// reserved namespace from `user_metadata_set` before inserting its own key, so
    /// the second pass removes the first pass's insert and re-adds it — a no-op
    /// only because both see the same principal. And it filters reserved keys out
    /// of `user_metadata_remove`, so a client's attempt to delete the stamp
    /// survives neither pass.
    #[test]
    fn stamping_update_metadata_twice_matches_stamping_it_once() {
        let overlay = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let principal = Principal {
            id: "alice".to_string(),
            display_name: None,
            attributes: std::collections::HashMap::new(),
            valid_until: None,
            source: String::new(),
        };

        let fresh = || UpdateMetadataOptions {
            user_metadata_set: std::collections::HashMap::from([
                ("note".to_string(), "hello".to_string()),
                (
                    ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
                    "mallory".to_string(),
                ),
            ]),
            user_metadata_remove: vec![
                ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
                "obsolete".to_string(),
            ],
            ..UpdateMetadataOptions::default()
        };

        let mut once = fresh();
        overlay.stamp_update_metadata(&principal, &mut once);

        let mut twice = fresh();
        overlay.stamp_update_metadata(&principal, &mut twice);
        overlay.stamp_update_metadata(&principal, &mut twice);

        assert_eq!(once.user_metadata_set, twice.user_metadata_set);
        assert_eq!(once.user_metadata_remove, twice.user_metadata_remove);
        assert_eq!(
            twice.user_metadata_set.get(ATTRIBUTION_KEY_MODIFIED_BY),
            Some(&"alice".to_string()),
            "the client's value is overwritten, and survives neither pass"
        );
        assert_eq!(
            twice.user_metadata_remove,
            vec!["obsolete".to_string()],
            "a removal of the reserved key is dropped; an ordinary one is kept"
        );
    }
    use super::*;
    use crate::Principal;
    use std::collections::HashMap;

    fn principal(id: &str) -> Principal {
        Principal {
            id: id.to_string(),
            display_name: None,
            attributes: HashMap::new(),
            valid_until: None,
            source: "test".to_string(),
        }
    }

    fn info_with_metadata(pairs: &[(&str, &str)]) -> ObjectInfo {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert((*k).to_string(), (*v).to_string());
        }
        ObjectInfo {
            address: ovstorage_plugin::address::parse("file:///tmp/x").unwrap(),
            kind: ovstorage_plugin::ObjectKind::File,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: Default::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: if map.is_empty() { None } else { Some(map) },
            modified_by: None,
        }
    }

    #[test]
    fn external_db_strategy_refuses_construction() {
        let err = AttributionLayer::new(AttributionStrategy::ExternalDb).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn user_metadata_stamp_round_trips_through_unwrap() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut opts = WriteOptions::default();
        layer.stamp_write(&principal("alice"), &mut opts);

        let mut info = info_with_metadata(&[("ovstorage-modified-by", "alice")]);
        layer.unwrap_read(&mut info);
        assert_eq!(info.modified_by.as_deref(), Some("alice"));
        assert!(info.user_metadata.is_none());
    }

    #[test]
    fn stamp_strips_client_supplied_reserved_keys() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut opts = WriteOptions::default();
        let mut user_meta = HashMap::new();
        user_meta.insert("ovstorage-modified-by".to_string(), "bob".to_string());
        user_meta.insert("ovstorage-some-future-key".to_string(), "x".to_string());
        user_meta.insert("regular-key".to_string(), "kept".to_string());
        opts.user_metadata = Some(user_meta);

        layer.stamp_write(&principal("alice"), &mut opts);

        let metadata = opts.user_metadata.expect("metadata present after stamp");
        // Client-supplied reserved keys gone; only broker stamp + regular key remain.
        assert_eq!(
            metadata.get("regular-key").map(String::as_str),
            Some("kept")
        );
        assert_eq!(
            metadata.get("ovstorage-modified-by").map(String::as_str),
            Some("alice"),
        );
        assert!(!metadata.contains_key("ovstorage-some-future-key"));
    }

    #[test]
    fn stamp_update_metadata_strips_reserved_in_set_and_remove() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut opts = UpdateMetadataOptions {
            user_metadata_set: {
                let mut map = HashMap::new();
                map.insert("ovstorage-modified-by".to_string(), "spoofed".to_string());
                map.insert("normal-key".to_string(), "v".to_string());
                map
            },
            user_metadata_remove: vec![
                "ovstorage-modified-by".to_string(),
                "user-asked-to-remove".to_string(),
            ],
            ..Default::default()
        };

        layer.stamp_update_metadata(&principal("alice"), &mut opts);

        assert_eq!(
            opts.user_metadata_set
                .get("ovstorage-modified-by")
                .map(String::as_str),
            Some("alice"),
        );
        assert_eq!(
            opts.user_metadata_set.get("normal-key").map(String::as_str),
            Some("v")
        );
        // Removal of the reserved key is dropped silently; non-reserved removal preserved.
        assert_eq!(
            opts.user_metadata_remove,
            vec!["user-asked-to-remove".to_string()]
        );
    }

    #[test]
    fn passthrough_is_a_true_no_op() {
        let layer = AttributionLayer::new(AttributionStrategy::Passthrough).unwrap();
        let mut opts = WriteOptions::default();
        let mut user_meta = HashMap::new();
        // Simulate an upstream broker's stamp arriving at this passthrough broker.
        user_meta.insert("ovstorage-modified-by".to_string(), "alice".to_string());
        opts.user_metadata = Some(user_meta);

        layer.stamp_write(&principal("local-broker-svc"), &mut opts);

        // Upstream stamp preserved verbatim; local broker did not re-stamp.
        let metadata = opts.user_metadata.unwrap();
        assert_eq!(
            metadata.get("ovstorage-modified-by").map(String::as_str),
            Some("alice"),
        );
    }

    #[test]
    fn passthrough_unwrap_does_not_promote() {
        let layer = AttributionLayer::new(AttributionStrategy::Passthrough).unwrap();
        let mut info = info_with_metadata(&[("ovstorage-modified-by", "alice")]);
        layer.unwrap_read(&mut info);
        // Passthrough leaves the typed slot alone; client sees raw plugin output.
        assert!(info.modified_by.is_none());
        assert!(info.user_metadata.is_some());
    }

    #[test]
    fn unwrap_read_strips_other_reserved_keys() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut info = info_with_metadata(&[
            ("ovstorage-modified-by", "alice"),
            ("ovstorage-future-key", "should-be-hidden"),
            ("user-key", "visible"),
        ]);
        layer.unwrap_read(&mut info);

        assert_eq!(info.modified_by.as_deref(), Some("alice"));
        let metadata = info.user_metadata.expect("non-reserved key remains");
        assert_eq!(
            metadata.get("user-key").map(String::as_str),
            Some("visible")
        );
        assert!(!metadata.contains_key("ovstorage-future-key"));
    }

    #[test]
    fn unwrap_read_with_no_reserved_key_preserves_native_modified_by() {
        let layer = AttributionLayer::new(AttributionStrategy::UserMetadata).unwrap();
        let mut info = info_with_metadata(&[("user-key", "v")]);
        info.modified_by = Some("plugin-native".to_string());
        layer.unwrap_read(&mut info);
        // No broker stamp present; plugin's native value left alone.
        assert_eq!(info.modified_by.as_deref(), Some("plugin-native"));
    }

    // -----------------------------------------------------------------------
    // AttributionWrapper (in-stack Layer) tests
    //
    // The underlying `AttributionLayer` overlay is well covered above, but the
    // in-stack `AttributionWrapper` Layer — which reads `ext::PRINCIPAL_ID`,
    // stamps the mutating verbs' options on the way down, and harvests the
    // reserved key back into the typed `modified_by` on the way up — had none.
    // These wrap a recording inner and drive real verbs through the Layer.
    // -----------------------------------------------------------------------

    use async_trait::async_trait;
    use ovstorage::wrappers::ext;
    use ovstorage::{
        CancellationToken, Extensions, Layer, LayerHandle, LayerKindDescriptor, LayerType,
        ListPage, ListRequest, LocalDelegate, ReadRequest, ReadResult, RedirectResultBatch,
        Request, StatRequest, UpdateMetadataRequest, WriteRequest, WriteResult,
    };

    /// The reserved value a backend "persisted" and echoes back on reads, so the
    /// wrapper's unwrap path has something to promote into `modified_by`.
    const BACKEND_STORED: &str = "backend-writer";

    /// A recording leaf Layer: captures the `user_metadata` the wrapper stamped
    /// onto mutating verbs, and returns results carrying the reserved
    /// attribution key so the wrapper's unwrap path can be observed.
    #[derive(Default)]
    struct AttrRecordingInner {
        write_user_metadata: std::sync::Mutex<Option<HashMap<String, String>>>,
        update_metadata_set: std::sync::Mutex<Option<HashMap<String, String>>>,
        /// `continue_write` carries no options, so what the wrapper asserts for
        /// it is on the extensions — the seam a plugin reads. Recorded whole so
        /// a test can assert the key's absence as well as its value.
        continue_write_extensions: std::sync::Mutex<Option<Extensions>>,
        /// Return the shape an upstream `UserMetadata` host produces: the
        /// reserved key already harvested into the typed slot.
        harvested_upstream_report: std::sync::Mutex<bool>,
    }

    fn stored_object_info() -> ObjectInfo {
        info_with_metadata(&[(ATTRIBUTION_KEY_MODIFIED_BY, BACKEND_STORED)])
    }

    fn stored_backend_item() -> BackendItemInfo {
        let mut map = HashMap::new();
        map.insert(
            ATTRIBUTION_KEY_MODIFIED_BY.to_string(),
            BACKEND_STORED.to_string(),
        );
        BackendItemInfo {
            user_metadata: Some(map),
            ..Default::default()
        }
    }

    #[async_trait]
    impl Layer for AttrRecordingInner {
        fn name(&self) -> &str {
            "recorder"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                display_name: "recorder".to_string(),
                kind: "recorder".to_string(),
                layer_type: LayerType::Backend,
                description: None,
                config_schema: Vec::new(),
                credential_schema: Vec::new(),
                credential_methods: Vec::new(),
                icon: None,
                accepts_connections: false,
                auth_capable: false,
                supports_user_metadata: true,
            }
        }

        async fn stat(
            &self,
            _request: Request<StatRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            Ok(stored_object_info())
        }

        async fn read(
            &self,
            _request: Request<ReadRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ReadResult> {
            Ok(ReadResult::Bytes {
                bytes: Vec::new(),
                info: stored_object_info(),
            })
        }

        async fn materialize(
            &self,
            _request: Request<ReadRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<LocalDelegate> {
            Ok(LocalDelegate {
                path: std::path::PathBuf::from("/dev/null"),
                info: stored_object_info(),
                guard: None,
            })
        }

        async fn write(
            &self,
            request: Request<WriteRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<WriteResult> {
            *self.write_user_metadata.lock().unwrap() = request.input.options.user_metadata;
            Ok(WriteResult {
                info: info_with_metadata(&[]),
            })
        }

        async fn continue_write(
            &self,
            request: Request<ContinueWriteRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<WriteStep> {
            *self.continue_write_extensions.lock().unwrap() = Some(request.extensions);
            if *self.harvested_upstream_report.lock().unwrap() {
                let mut info = info_with_metadata(&[("author", "unreserved")]);
                info.modified_by = Some("upstream-principal".to_string());
                return Ok(WriteStep::Done(WriteResult { info }));
            }
            // What a plugin that did not assert anything returns: a result
            // built from data the caller handed back, reserved key and all.
            // That is the shape from a plugin reading a continuation, a
            // captured body or captured headers, and from a `broker` plugin
            // whose upstream host is `Passthrough`. A `UserMetadata` upstream
            // returns the other shape — key already harvested — which
            // `wrapper_continue_write_overrides_a_harvested_upstream_report`
            // covers.
            Ok(WriteStep::Done(WriteResult {
                info: info_with_metadata(&[
                    (ATTRIBUTION_KEY_MODIFIED_BY, "impersonated-principal"),
                    ("author", "unreserved"),
                ]),
            }))
        }

        async fn update_metadata(
            &self,
            request: Request<UpdateMetadataRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<BackendItemInfo> {
            *self.update_metadata_set.lock().unwrap() =
                Some(request.input.options.user_metadata_set);
            Ok(stored_backend_item())
        }

        async fn list(
            &self,
            _request: Request<ListRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ListPage> {
            Ok(ListPage {
                items: vec![stored_object_info()],
                next_page_token: None,
            })
        }
    }

    fn attribution_wrapper(inner: Arc<AttrRecordingInner>) -> AttributionWrapper {
        wrapper_with_strategy(inner, AttributionStrategy::UserMetadata)
    }

    fn wrapper_with_strategy(
        inner: Arc<AttrRecordingInner>,
        strategy: AttributionStrategy,
    ) -> AttributionWrapper {
        AttributionWrapper::new(
            "attribution",
            inner as LayerHandle,
            AttributionLayer::new(strategy).unwrap(),
        )
    }

    fn continue_write_input() -> ContinueWriteRequest {
        ContinueWriteRequest {
            address: ovstorage::address::parse("file:///tmp/x").unwrap(),
            redirects: WriteRedirectBatch {
                continuation: b"opaque".to_vec(),
                redirects: Vec::new(),
            },
            results: RedirectResultBatch {
                results: Vec::new(),
            },
        }
    }

    /// A request stamping `ext::PRINCIPAL_ID` = `principal` (the value the auth
    /// Layer above would have set).
    fn principal_request<T>(principal: &str, input: T) -> Request<T> {
        let mut extensions = Extensions::new();
        extensions.insert(ext::PRINCIPAL_ID.to_string(), principal.as_bytes().to_vec());
        Request { extensions, input }
    }

    fn read_input() -> ReadRequest {
        ReadRequest {
            address: ovstorage::address::parse("file:///tmp/x").unwrap(),
            options: Default::default(),
        }
    }

    #[tokio::test]
    async fn wrapper_write_stamps_resolved_principal_into_options() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = attribution_wrapper(inner.clone());
        wrapper
            .write(
                principal_request(
                    "alice",
                    WriteRequest {
                        address: ovstorage::address::parse("file:///tmp/x").unwrap(),
                        body: ovstorage::Body::Bytes(Vec::new()),
                        options: Default::default(),
                    },
                ),
                None,
            )
            .await
            .unwrap();
        let stamped = inner.write_user_metadata.lock().unwrap().clone();
        assert_eq!(
            stamped
                .as_ref()
                .and_then(|map| map.get(ATTRIBUTION_KEY_MODIFIED_BY))
                .map(String::as_str),
            Some("alice"),
            "write must stamp the resolved principal into write options"
        );
    }

    /// The one mutating verb whose metadata makes a round trip through the
    /// client: what the commit applies came back inside a continuation the
    /// caller echoed. The wrapper asserts the resolved principal on the
    /// extensions so the plugin that performs the commit can put it over
    /// whatever travelled.
    #[tokio::test]
    async fn wrapper_continue_write_asserts_resolved_principal_on_the_extensions() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = attribution_wrapper(inner.clone());
        wrapper
            .continue_write(principal_request("alice", continue_write_input()), None)
            .await
            .unwrap();
        let seen = inner
            .continue_write_extensions
            .lock()
            .unwrap()
            .clone()
            .expect("inner observed the request");
        assert_eq!(
            seen.get(ext::ATTRIBUTED_MODIFIED_BY),
            Some(b"alice".as_slice()),
            "continue_write must assert the resolved principal for the commit"
        );
    }

    /// A plugin that asserted nothing — the `broker` branch cannot, since its
    /// RPC carries no extensions — must not have the caller's value harvested
    /// into the typed slot as though this host vouched for it.
    ///
    /// This stands in for the per-plugin tests that asserting here replaces:
    /// the recording inner returns what a plugin building an `ObjectInfo` out
    /// of a continuation, a captured body or captured headers returns, so one
    /// test covers every adopter of that shape including ones this build has
    /// never heard of. That a given kind's branch actually carries this wrapper
    /// is pinned separately, by the composition test over
    /// [`crate::UserMetadataKinds`]; the two together are what the deleted
    /// per-plugin tests used to assert at once. Composing a *real* plugin under
    /// this wrapper is not available — a
    /// plugin crate may not depend on this one, no host crate dev-depends on a
    /// plugin, and two plugin rlibs in one test binary are a duplicate-symbol
    /// link error under `rust-lld` — so plugin-specific end-to-end coverage of
    /// the reported copy is a stated gap rather than an oversight.
    #[tokio::test]
    async fn wrapper_continue_write_reports_the_resolved_principal_over_the_results() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = attribution_wrapper(inner.clone());
        let step = wrapper
            .continue_write(principal_request("alice", continue_write_input()), None)
            .await
            .unwrap();
        let info = match step {
            WriteStep::Done(result) => result.info,
            WriteStep::Redirects(_) => panic!("the recorder returns Done"),
        };
        assert_eq!(
            info.modified_by.as_deref(),
            Some("alice"),
            "the harvested writer must be the resolved principal, not the result's"
        );
        assert_eq!(
            info.user_metadata
                .as_ref()
                .and_then(|map| map.get("author"))
                .map(String::as_str),
            Some("unreserved"),
            "unreserved metadata in the result must survive"
        );
    }

    /// The other shape a result arrives in: an upstream host running
    /// `UserMetadata` already harvested the reserved key into the typed slot,
    /// so what crosses its RPC carries no reserved key and a `modified_by` that
    /// host resolved. This host's report is its own principal — it authenticated
    /// this caller for this call, and the upstream one authenticated its own —
    /// so the typed slot must be overwritten rather than passed through.
    #[tokio::test]
    async fn wrapper_continue_write_overrides_a_harvested_upstream_report() {
        let inner = Arc::new(AttrRecordingInner::default());
        *inner.harvested_upstream_report.lock().unwrap() = true;
        let wrapper = attribution_wrapper(inner.clone());
        let step = wrapper
            .continue_write(principal_request("alice", continue_write_input()), None)
            .await
            .unwrap();
        let info = match step {
            WriteStep::Done(result) => result.info,
            WriteStep::Redirects(_) => panic!("the recorder returns Done"),
        };
        assert_eq!(
            info.modified_by.as_deref(),
            Some("alice"),
            "an upstream host's harvested value must not stand in for this host's"
        );
    }

    /// `Passthrough` leaves the reported value alone for the same reason it
    /// stamps nothing: on a chain the deeper host's value is the one to
    /// preserve, and overwriting it here would lose the original principal.
    #[tokio::test]
    async fn wrapper_continue_write_leaves_the_report_alone_under_passthrough() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = wrapper_with_strategy(inner.clone(), AttributionStrategy::Passthrough);
        let step = wrapper
            .continue_write(principal_request("alice", continue_write_input()), None)
            .await
            .unwrap();
        let info = match step {
            WriteStep::Done(result) => result.info,
            WriteStep::Redirects(_) => panic!("the recorder returns Done"),
        };
        assert_eq!(
            info.modified_by, None,
            "passthrough harvests nothing into the typed slot"
        );
        assert_eq!(
            info.user_metadata
                .as_ref()
                .and_then(|map| map.get(ATTRIBUTION_KEY_MODIFIED_BY))
                .map(String::as_str),
            Some("impersonated-principal"),
            "passthrough must not overwrite what came back, so an upstream stamp survives"
        );
    }

    /// `Passthrough` exists so an upstream host's stamp survives a chain. It
    /// asserts nothing here either, or the deeper host would overwrite the
    /// original principal at the commit it was composed to preserve it through.
    #[tokio::test]
    async fn wrapper_continue_write_asserts_nothing_under_passthrough() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = wrapper_with_strategy(inner.clone(), AttributionStrategy::Passthrough);
        wrapper
            .continue_write(principal_request("alice", continue_write_input()), None)
            .await
            .unwrap();
        let seen = inner
            .continue_write_extensions
            .lock()
            .unwrap()
            .clone()
            .expect("inner observed the request");
        assert_eq!(
            seen.get(ext::PRINCIPAL_ID),
            Some(b"alice".as_slice()),
            "the principal itself still reaches inner; only the assertion is withheld"
        );
        assert_eq!(
            seen.get(ext::ATTRIBUTED_MODIFIED_BY),
            None,
            "passthrough must not assert an attribution for the commit"
        );
    }

    #[tokio::test]
    async fn wrapper_write_without_principal_falls_back_to_anonymous() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = attribution_wrapper(inner.clone());
        // No `ext::PRINCIPAL_ID`: the wrapper stamps the literal `"anonymous"`.
        wrapper
            .write(
                Request::new(WriteRequest {
                    address: ovstorage::address::parse("file:///tmp/x").unwrap(),
                    body: ovstorage::Body::Bytes(Vec::new()),
                    options: Default::default(),
                }),
                None,
            )
            .await
            .unwrap();
        let stamped = inner.write_user_metadata.lock().unwrap().clone();
        assert_eq!(
            stamped
                .as_ref()
                .and_then(|map| map.get(ATTRIBUTION_KEY_MODIFIED_BY))
                .map(String::as_str),
            Some("anonymous"),
            "a missing principal must stamp \"anonymous\""
        );
    }

    #[tokio::test]
    async fn wrapper_update_metadata_stamps_principal() {
        let inner = Arc::new(AttrRecordingInner::default());
        let wrapper = attribution_wrapper(inner.clone());
        let item = wrapper
            .update_metadata(
                principal_request(
                    "alice",
                    UpdateMetadataRequest {
                        address: ovstorage::address::parse("file:///tmp/x").unwrap(),
                        options: Default::default(),
                    },
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            inner
                .update_metadata_set
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|map| map.get(ATTRIBUTION_KEY_MODIFIED_BY))
                .map(String::as_str),
            Some("alice"),
            "update_metadata must stamp the principal into the set map"
        );
        // The returned BackendItemInfo is also unwrapped on the way back up.
        assert_eq!(item.modified_by.as_deref(), Some(BACKEND_STORED));
        assert!(item.user_metadata.is_none());
    }

    #[tokio::test]
    async fn wrapper_stat_unwraps_reserved_key_into_modified_by() {
        let wrapper = attribution_wrapper(Arc::new(AttrRecordingInner::default()));
        let info = wrapper
            .stat(
                principal_request(
                    "alice",
                    StatRequest {
                        address: ovstorage::address::parse("file:///tmp/x").unwrap(),
                        options: Default::default(),
                    },
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(info.modified_by.as_deref(), Some(BACKEND_STORED));
        assert!(info.user_metadata.is_none());
    }

    #[tokio::test]
    async fn wrapper_read_unwraps_reserved_key_into_modified_by() {
        let wrapper = attribution_wrapper(Arc::new(AttrRecordingInner::default()));
        let result = wrapper
            .read(principal_request("alice", read_input()), None)
            .await
            .unwrap();
        match result {
            ReadResult::Bytes { info, .. } => {
                assert_eq!(info.modified_by.as_deref(), Some(BACKEND_STORED));
                assert!(info.user_metadata.is_none());
            }
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrapper_materialize_unwraps_local_delegate_info() {
        // Covers the `LocalDelegate` arm of the unwrap path (the direct-disk verb).
        let wrapper = attribution_wrapper(Arc::new(AttrRecordingInner::default()));
        let local = wrapper
            .materialize(principal_request("alice", read_input()), None)
            .await
            .unwrap();
        assert_eq!(local.info.modified_by.as_deref(), Some(BACKEND_STORED));
        assert!(local.info.user_metadata.is_none());
    }

    #[tokio::test]
    async fn wrapper_list_unwraps_each_item() {
        let wrapper = attribution_wrapper(Arc::new(AttrRecordingInner::default()));
        let page = wrapper
            .list(
                principal_request(
                    "alice",
                    ListRequest {
                        prefix: ovstorage::address::parse("file:///tmp/").unwrap(),
                        options: Default::default(),
                    },
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].modified_by.as_deref(), Some(BACKEND_STORED));
        assert!(page.items[0].user_metadata.is_none());
    }
}
