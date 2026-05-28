// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub struct Broker {
    pub(crate) library: Arc<Library>,
    pub(crate) authz: Arc<dyn AuthzPlugin>,
    pub(crate) route_policies: BrokerRoutePolicies,
    pub(crate) policy_state: Arc<BrokerPolicyEpochState>,
    pub(crate) watch_directory_hub: Arc<WatchDirectoryHub>,
    /// Disk-backed byte cache for plugin-driven read redirects below
    /// `cache_max_object_bytes`. Kept under its own row namespace
    /// (`broker\0<address>`) so it doesn't collide with library entries
    /// keyed on `<partition>\0<backend_id>\0<resolved>`.
    pub(crate) byte_cache: Option<Arc<ovstorage_cache::Cache>>,
    pub(crate) redirect_http: Arc<reqwest::Client>,
    pub(crate) oauth_providers: Arc<crate::OAuthProviderRegistry>,
    pub(crate) oauth_route_bindings: crate::BrokerOAuthRouteBindings,
    pub(crate) attribution: AttributionLayer,
}

/// What `Broker::read` produced: materialized `Bytes`, a chunk-by-chunk
/// `Stream` (never buffered whole at the broker), or a presigned
/// `Redirect` the client follows directly.
pub enum BrokerReadOutcome {
    Bytes {
        info: ObjectInfo,
        bytes: Vec<u8>,
    },
    Stream {
        info: ObjectInfo,
        stream: ovstorage::ReadStream,
    },
    Redirect(ReadRedirect),
}

impl std::fmt::Debug for BrokerReadOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerReadOutcome::Bytes { info, bytes } => f
                .debug_struct("Bytes")
                .field("info", info)
                .field("bytes_len", &bytes.len())
                .finish(),
            BrokerReadOutcome::Stream { info, .. } => {
                f.debug_struct("Stream").field("info", info).finish()
            }
            BrokerReadOutcome::Redirect(redirect) => {
                f.debug_tuple("Redirect").field(redirect).finish()
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerWriteOutcome {
    Redirects(WriteRedirectBatch),
    Done(WriteResult),
}

impl Broker {
    pub fn new(library: Arc<Library>) -> Self {
        Self::with_authz_plugin(library, Arc::new(AllowAllAuthzPlugin))
    }

    pub fn with_route_policy(library: Arc<Library>, route_policy: BrokerRoutePolicy) -> Self {
        Self::with_authz_plugin_and_policy(library, Arc::new(AllowAllAuthzPlugin), route_policy)
    }

    pub fn with_authz_plugin(library: Arc<Library>, authz: Arc<dyn AuthzPlugin>) -> Self {
        Self::with_authz_plugin_and_policies(library, authz, BrokerRoutePolicies::default())
    }

    pub fn with_authz_plugin_and_policy_freshness(
        library: Arc<Library>,
        authz: Arc<dyn AuthzPlugin>,
        route_policy: BrokerRoutePolicy,
        freshness: BrokerPolicyFreshness,
    ) -> Self {
        Self::with_authz_plugin_policies_and_epoch_state(
            library,
            authz,
            BrokerRoutePolicies::single(route_policy),
            BrokerPolicyEpochState::in_memory(0, freshness),
        )
    }

    pub fn with_authz_plugin_and_policy(
        library: Arc<Library>,
        authz: Arc<dyn AuthzPlugin>,
        route_policy: BrokerRoutePolicy,
    ) -> Self {
        Self::with_authz_plugin_policies_and_epoch_state(
            library,
            authz,
            BrokerRoutePolicies::single(route_policy),
            BrokerPolicyEpochState::in_memory(0, BrokerPolicyFreshness::Strict),
        )
    }

    pub fn with_authz_plugin_and_policies(
        library: Arc<Library>,
        authz: Arc<dyn AuthzPlugin>,
        route_policies: BrokerRoutePolicies,
    ) -> Self {
        Self::with_authz_plugin_policies_and_epoch_state(
            library,
            authz,
            route_policies,
            BrokerPolicyEpochState::in_memory(0, BrokerPolicyFreshness::Strict),
        )
    }

    pub(crate) fn with_authz_plugin_policies_and_epoch_state(
        library: Arc<Library>,
        authz: Arc<dyn AuthzPlugin>,
        route_policies: BrokerRoutePolicies,
        policy_state: Arc<BrokerPolicyEpochState>,
    ) -> Self {
        Self {
            library,
            authz,
            route_policies,
            policy_state,
            watch_directory_hub: Arc::new(WatchDirectoryHub::default()),
            byte_cache: None,
            redirect_http: Arc::new(crate::redirect_fetch::redirect_client()),
            oauth_providers: Arc::new(crate::OAuthProviderRegistry::new()),
            oauth_route_bindings: crate::BrokerOAuthRouteBindings::new(),
            attribution: AttributionLayer::new(AttributionStrategy::default())
                .expect("default UserMetadata strategy is always valid"),
        }
    }

    /// Replace the default `UserMetadata` attribution strategy. Use
    /// `Passthrough` for intermediate brokers in a chain so the
    /// upstream broker's stamp survives end-to-end.
    pub fn with_attribution_strategy(
        mut self,
        strategy: AttributionStrategy,
    ) -> ovstorage::Result<Self> {
        self.attribution = AttributionLayer::new(strategy)?;
        Ok(self)
    }

    pub fn attribution_strategy(&self) -> AttributionStrategy {
        self.attribution.strategy()
    }

    /// Install the OAuth provider registry + per-route bindings.
    /// Arc-wrapped so SIGHUP can swap without disturbing in-flight RPCs.
    pub fn with_oauth_providers(
        mut self,
        providers: Arc<crate::OAuthProviderRegistry>,
        bindings: crate::BrokerOAuthRouteBindings,
    ) -> Self {
        self.oauth_providers = providers;
        self.oauth_route_bindings = bindings;
        self
    }

    pub fn oauth_providers(&self) -> &Arc<crate::OAuthProviderRegistry> {
        &self.oauth_providers
    }

    pub fn oauth_route_bindings(&self) -> &crate::BrokerOAuthRouteBindings {
        &self.oauth_route_bindings
    }

    /// Install the byte cache. Independent of the library's cache so
    /// the broker's redirect-fetch CAS rows stay distinguishable.
    pub fn with_byte_cache(mut self, cache: Arc<ovstorage_cache::Cache>) -> Self {
        self.byte_cache = Some(cache);
        self
    }

    pub fn byte_cache(&self) -> Option<&Arc<ovstorage_cache::Cache>> {
        self.byte_cache.as_ref()
    }

    /// Drop broker-owned byte-cache rows referencing `address`.
    /// Metadata invalidation happens inside the core library write path.
    pub(crate) async fn invalidate_metadata_for(&self, address: &Url) {
        if let Some(cache) = &self.byte_cache {
            let key = crate::redirect_fetch::broker_byte_cache_key(address);
            let info_key = crate::redirect_fetch::broker_byte_cache_info_key(address);
            // Best-effort; cache bookkeeping must not fail the parent op.
            let _ = cache.remove_index(&key);
            let _ = cache.remove_index(&info_key);
        }
    }

    pub fn with_authorizer(library: Arc<Library>, authorizer: Arc<dyn AuthzPlugin>) -> Self {
        Self::with_authz_plugin(library, authorizer)
    }

    pub fn with_authorizer_and_policy(
        library: Arc<Library>,
        authorizer: Arc<dyn AuthzPlugin>,
        route_policy: BrokerRoutePolicy,
    ) -> Self {
        Self::with_authz_plugin_and_policy(library, authorizer, route_policy)
    }

    pub fn with_authorizer_and_policy_freshness(
        library: Arc<Library>,
        authorizer: Arc<dyn AuthzPlugin>,
        route_policy: BrokerRoutePolicy,
        freshness: BrokerPolicyFreshness,
    ) -> Self {
        Self::with_authz_plugin_and_policy_freshness(library, authorizer, route_policy, freshness)
    }

    pub fn library(&self) -> &Arc<Library> {
        &self.library
    }

    pub fn route_policy(&self) -> &BrokerRoutePolicy {
        self.route_policies.default_policy()
    }

    pub fn current_policy_epoch(&self) -> u64 {
        self.policy_state.current_epoch()
    }

    pub fn context_for_principal(&self, principal: Principal) -> RequestContext {
        RequestContext {
            principal,
            policy_epoch: self.current_policy_epoch(),
            audit_id: None,
        }
    }

    pub fn advance_policy_epoch(&self) -> ovstorage::Result<u64> {
        self.policy_state.advance()
    }

    /// Pre-flight authorize so the gRPC layer can reject unauthorized
    /// writers before buffering body bytes.
    pub async fn authorize_for_grpc(
        &self,
        context: &RequestContext,
        operation: Operation,
        address: Option<&Url>,
    ) -> ovstorage::Result<()> {
        self.authorize(context, operation, address).await
    }

    pub fn invalidate_policy_epochs_for_test(
        &self,
        epochs: Vec<u64>,
    ) -> ovstorage::Result<(u64, Vec<u64>)> {
        self.policy_state.invalidate(&epochs)?;
        Ok((self.current_policy_epoch(), epochs))
    }

    pub fn health(&self) -> ovstorage::Result<()> {
        self.library.list_backend_kinds()?;
        Ok(())
    }

    pub async fn list_backend_kinds(
        &self,
        context: &RequestContext,
    ) -> ovstorage::Result<Vec<StorageBackendKindDescriptor>> {
        self.authorize(context, Operation::ListBackendKinds, None)
            .await?;
        self.library.list_backend_kinds()
    }

    pub async fn list_address_roots(
        &self,
        context: &RequestContext,
    ) -> ovstorage::Result<Vec<ovstorage::AddressRoot>> {
        use tracing::Instrument;
        let span = tracing::info_span!(
            "broker.list_address_roots",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
        );
        async move {
            self.authorize(context, Operation::ListAddressRoots, None)
                .await?;
            let mut roots = ovstorage_authz::compose::filter_address_roots(
                self,
                context,
                self.library.list_address_roots()?,
            )
            .await?;
            // Caps munging: when the broker's route policy enables
            // broker-issued write redirects for a route, the broker
            // becomes the redirect-issuer regardless of the upstream
            // backend's caps. Forward that to broker-client by ORing
            // `supports_write_redirect = true` into the route caps so
            // the host dispatcher routes `write` through `write_redirect`
            // (which broker-client wires correctly via the daemon's
            // `WriteRedirect` RPC) instead of through `write` (which
            // errors when the daemon emits redirects mid-RPC). See
            // `BrokerRoutePolicy::should_redirect_write` for the policy
            // shape.
            for root in &mut roots {
                let policy = self.route_policies.policy_for(&root.address);
                if policy.write_redirect_endpoint.is_some() {
                    root.capabilities.supports_write_redirect = true;
                }
            }
            Ok(roots)
        }
        .instrument(span)
        .await
    }

    pub async fn stat(
        &self,
        context: &RequestContext,
        address: Url,
        options: StatOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        use tracing::Instrument;
        let span = tracing::info_span!(
            "broker.stat",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
            object.address = %crate::trace::RedactedUrl(&address),
            cache.hit = tracing::field::Empty,
        );
        let span_record = span.clone();
        async move {
            self.authorize(context, Operation::Stat, Some(&address))
                .await?;
            // authz BEFORE cache lookup; revoking a principal must drop
            // them on next request even with hot cache.
            if let Some(cache) = self.library.metadata_cache().cloned() {
                let key = MetadataCacheKey {
                    kind: MetadataKind::Stat,
                    principal_id: None,
                    address: address.as_str().into(),
                    options_hash: ovstorage::metadata_cache::hash_stat_options(&options),
                };
                if let Some(MetadataCachePayload::Stat(info)) = cache.get(&key) {
                    span_record.record("cache.hit", true);
                    return Ok(info);
                }
                span_record.record("cache.hit", false);
                let mut info = self.library.stat(address, options, None).await?;
                self.attribution.unwrap_read(&mut info);
                cache.insert(key, MetadataCachePayload::Stat(info.clone()));
                return Ok(info);
            }
            let mut info = self.library.stat(address, options, None).await?;
            self.attribution.unwrap_read(&mut info);
            Ok(info)
        }
        .instrument(span)
        .await
    }

    pub async fn read(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::ReadOptions,
    ) -> ovstorage::Result<BrokerReadOutcome> {
        use tracing::Instrument;
        let span = tracing::info_span!(
            "broker.read",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
            object.address = %crate::trace::RedactedUrl(&address),
            cache.hit = tracing::field::Empty,
            redirect.kind = tracing::field::Empty,
            audit_id = tracing::field::Empty,
        );
        let span_record = span.clone();
        async move {
            self.authorize(context, Operation::Read, Some(&address))
                .await?;
            // authz BEFORE byte-cache lookup; a hit must not serve a
            // principal who lost Read since the last fetch.
            let byte_cache_key = crate::redirect_fetch::broker_byte_cache_key(&address);
            let info_cache_key = crate::redirect_fetch::broker_byte_cache_info_key(&address);
            if let Some(cache) = &self.byte_cache {
                if options.if_match.is_none() && options.range.is_none() {
                    if let Some(cached) = cache.get_entry_async(&byte_cache_key).await? {
                        span_record.record("cache.hit", true);
                        tracing::info!(
                            target: "ovstorage.metric",
                            metric = "cache.hit",
                            kind = "object",
                            operation = "read",
                            "broker byte cache hit"
                        );
                        metrics::counter!(crate::observability::CACHE_OBJECT_HITS).increment(1);
                        // Identity sidecar so cache hits return the same
                        // etag/mtime as the first read.
                        let mut info = cache
                            .get_async(&info_cache_key)
                            .await?
                            .and_then(|sidecar| {
                                crate::redirect_fetch::decode_cached_object_info(
                                    address.clone(),
                                    &sidecar,
                                )
                            })
                            .unwrap_or_else(|| ObjectInfo {
                                address: address.clone(),
                                kind: ObjectKind::File,
                                etag: None,
                                version: None,
                                size: Some(cached.entry.size),
                                mtime: None,
                                checksums: Default::default(),
                                effective_permissions: None,
                                system_metadata: None,
                                user_metadata: None,
                                modified_by: None,
                            });
                        self.attribution.unwrap_read(&mut info);
                        return Ok(BrokerReadOutcome::Bytes {
                            info,
                            bytes: cached.bytes,
                        });
                    }
                }
            }
            let route_policy = self.route_policies.policy_for(&address);
            if route_policy.read_redirect_endpoint.is_some()
                && route_policy.cache_max_object_bytes.is_some()
            {
                let info = self
                    .library
                    .stat(address.clone(), StatOptions::default(), None)
                    .await?;
                if route_policy.should_redirect_read(info.size) {
                    let redirect = self.read_redirect(context, route_policy, &address)?;
                    span_record.record("redirect.kind", "read");
                    span_record.record("audit_id", redirect.audit_id.as_str());
                    metrics::counter!(crate::observability::REDIRECT_EMISSIONS, "kind" => "read").increment(1);
                    return Ok(BrokerReadOutcome::Redirect(redirect));
                }
            }
            let cacheable_options = options.if_match.is_none() && options.range.is_none();
            match self
                .library
                .broker_read_step(address.clone(), options, None)
                .await?
            {
                ovstorage_plugin::ReadResult::Bytes { bytes, mut info } => {
                    span_record.record("cache.hit", false);
                    self.attribution.unwrap_read(&mut info);
                    Ok(BrokerReadOutcome::Bytes { info, bytes })
                }
                ovstorage_plugin::ReadResult::Stream { stream, mut info } => {
                    // Streamed reads bypass the byte cache; capturing
                    // would re-buffer the whole body and defeat
                    // streaming. Cache fills happen on a future Bytes
                    // read.
                    span_record.record("cache.hit", false);
                    self.attribution.unwrap_read(&mut info);
                    Ok(BrokerReadOutcome::Stream { info, stream })
                }
                ovstorage_plugin::ReadResult::LocalDelegate(local) => {
                    // Open the local file as a chunk-by-chunk stream;
                    // `fs::read` of the whole file would buffer
                    // multi-GB locals at the broker and serve them
                    // back as `Bytes` (defeating end-to-end streaming).
                    use futures::StreamExt;
                    let file = tokio::fs::File::open(&local.path)
                        .await
                        .map_err(map_io)?;
                    let stream: ovstorage::ReadStream =
                        Box::pin(tokio_util::io::ReaderStream::new(file).map(
                            |chunk: Result<bytes::Bytes, std::io::Error>| chunk.map_err(map_io),
                        ));
                    let mut info = local.info;
                    self.attribution.unwrap_read(&mut info);
                    Ok(BrokerReadOutcome::Stream { info, stream })
                }
                ovstorage_plugin::ReadResult::Redirect(redirect) => {
                    // With byte cache + route's `cache_max_object_bytes`,
                    // fetch through the broker and serve as Bytes;
                    // otherwise forward the redirect unchanged.
                    if cacheable_options {
                        if let (Some(cache), Some(cap)) =
                            (&self.byte_cache, route_policy.cache_max_object_bytes)
                        {
                            if cap > 0 {
                                match crate::redirect_fetch::follow_read_redirect(
                                    &self.redirect_http,
                                    &redirect,
                                    &address,
                                    cap,
                                )
                                .await?
                                {
                                    crate::redirect_fetch::RedirectFetchOutcome::Fetched {
                                        bytes,
                                        mut info,
                                    } => {
                                        cache.put(&byte_cache_key, &bytes)?;
                                        // Best-effort identity sidecar;
                                        // SQLite errors here must not
                                        // fail the parent read.
                                        let info_bytes =
                                            crate::redirect_fetch::encode_cached_object_info(&info);
                                        if !info_bytes.is_empty() {
                                            let _ = cache.put(&info_cache_key, &info_bytes);
                                        }
                                        span_record.record("cache.hit", false);
                                        tracing::info!(
                                            target: "ovstorage.metric",
                                            metric = "cache.fill",
                                            kind = "object",
                                            operation = "read",
                                            size = bytes.len() as u64,
                                            "broker fetched + cached redirect bytes"
                                        );
                                        metrics::counter!(crate::observability::CACHE_OBJECT_FILLS, "outcome" => "ok").increment(1);
                                        self.attribution.unwrap_read(&mut info);
                                        return Ok(BrokerReadOutcome::Bytes { info, bytes });
                                    }
                                    crate::redirect_fetch::RedirectFetchOutcome::NotCacheable {
                                        reason,
                                    } => {
                                        tracing::debug!(
                                            target: "ovstorage.broker.byte_cache",
                                            ?reason,
                                            "broker redirect not cacheable; forwarding"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    span_record.record("redirect.kind", "read");
                    span_record.record("audit_id", redirect.audit_id.as_str());
                    metrics::counter!(crate::observability::REDIRECT_EMISSIONS, "kind" => "read").increment(1);
                    Ok(BrokerReadOutcome::Redirect(redirect))
                }
            }
        }
        .instrument(span)
        .await
    }

    pub async fn write(
        &self,
        context: &RequestContext,
        address: Url,
        body: Body,
        mut options: WriteOptions,
    ) -> ovstorage::Result<BrokerWriteOutcome> {
        use tracing::Instrument;
        let span = tracing::info_span!(
            "broker.write",
            principal.id = %context.principal.id,
            policy_epoch = context.policy_epoch,
            object.address = %crate::trace::RedactedUrl(&address),
            redirect.kind = tracing::field::Empty,
        );
        let span_record = span.clone();
        async move {
            self.authorize(context, Operation::Write, Some(&address))
                .await?;
            self.attribution
                .stamp_write(&context.principal, &mut options);
            let route_policy = self.route_policies.policy_for(&address);
            if route_policy.should_redirect_write(options.size_hint) {
                span_record.record("redirect.kind", "write");
                return Ok(BrokerWriteOutcome::Redirects(self.write_redirect_batch(
                    context,
                    route_policy,
                    &address,
                    &body,
                    &options,
                )?));
            }
            let mut result = self
                .library
                .write(address.clone(), body, options, None)
                .await?;
            self.attribution.unwrap_read(&mut result.info);
            self.invalidate_metadata_for(&address).await;
            Ok(BrokerWriteOutcome::Done(result))
        }
        .instrument(span)
        .await
    }

    pub async fn write_redirect(
        &self,
        context: &RequestContext,
        address: Url,
        mut options: WriteOptions,
    ) -> ovstorage::Result<WriteRedirectBatch> {
        self.authorize(context, Operation::Write, Some(&address))
            .await?;
        self.attribution
            .stamp_write(&context.principal, &mut options);
        // Broker-policy redirect: daemon manufactures the redirect for
        // routes wired to `write_redirect_endpoint`, independent of
        // plugin caps.
        let route_policy = self.route_policies.policy_for(&address);
        if route_policy.should_redirect_write(options.size_hint) {
            // Without size_hint we can't produce a faithful redirect: the
            // bodyless write_redirect RPC has no stream to forward, and
            // an empty Body::Bytes would silently finalize as a zero-byte
            // upload. Reject so callers stream via write() instead.
            if options.size_hint.is_none() {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "write_redirect requires WriteOptions::size_hint on routes configured \
                     for broker-policy redirect; stream via write() instead",
                ));
            }
            return self.write_redirect_batch(
                context,
                route_policy,
                &address,
                &Body::Bytes(Vec::new()),
                &options,
            );
        }
        let batch = self.library.write_redirect(address, options, None).await?;
        metrics::counter!(crate::observability::REDIRECT_EMISSIONS, "kind" => "write").increment(1);
        Ok(batch)
    }

    pub async fn continue_write(
        &self,
        context: &RequestContext,
        address: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
    ) -> ovstorage::Result<ovstorage_plugin::WriteStep> {
        self.authorize(context, Operation::Write, Some(&address))
            .await?;
        ovstorage::validate_redirect_results(&redirects, &results)?;
        if let Some(result) = results
            .results
            .iter()
            .find(|result| !(200..300).contains(&result.status_code))
        {
            return Err(Error::new(
                ErrorCode::Transient,
                format!("redirect write returned HTTP {}", result.status_code),
            ));
        }
        let route_policy = self.route_policies.policy_for(&address);
        if route_policy.write_redirect_endpoint.is_none() {
            let mut step = self
                .library
                .continue_write(address, redirects, results, None)
                .await?;
            if let ovstorage_plugin::WriteStep::Done(WriteResult { info }) = &mut step {
                self.attribution.unwrap_read(info);
            }
            return Ok(step);
        }
        let mut info = self
            .library
            .stat(address, StatOptions::default(), None)
            .await?;
        self.attribution.unwrap_read(&mut info);
        Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
    }

    pub async fn delete(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::DeleteOptions,
    ) -> ovstorage::Result<()> {
        self.authorize(context, Operation::Delete, Some(&address))
            .await?;
        let result = self.library.delete(address.clone(), options, None).await;
        if result.is_ok() {
            self.invalidate_metadata_for(&address).await;
        }
        result
    }

    pub async fn list(
        &self,
        context: &RequestContext,
        prefix: Url,
        options: ovstorage::ListOptions,
    ) -> ovstorage::Result<ovstorage::ListPage> {
        self.authorize(context, Operation::List, Some(&prefix))
            .await?;
        // List rows are post-filter; principal_id in the key prevents
        // serving a hit to a principal who can't Read those addresses.
        let metadata_cache = self.library.metadata_cache().cloned();
        let cache_key = metadata_cache.as_ref().map(|_| MetadataCacheKey {
            kind: MetadataKind::List,
            principal_id: Some(context.principal.id.clone()),
            address: prefix.as_str().into(),
            options_hash: ovstorage::metadata_cache::hash_list_options(&options),
        });
        if let (Some(cache), Some(key)) = (metadata_cache.as_ref(), cache_key.as_ref()) {
            if let Some(MetadataCachePayload::List(page)) = cache.get(key) {
                return Ok(page);
            }
        }
        let mut page = self
            .library
            .list_page(prefix.clone(), options, None)
            .await?;
        for item in page.items.iter_mut() {
            self.attribution.unwrap_read(item);
        }
        let addresses = page
            .items
            .iter()
            .map(|item| item.address.clone())
            .collect::<Vec<_>>();
        let filter_request = AuthzRequest::from_context(context, Operation::Read, Some(&prefix));
        let decisions = self
            .authz
            .filter_list_batch(&filter_request, &addresses)
            .await?;
        if decisions.len() != page.items.len() {
            return Err(Error::new(
                ErrorCode::Internal,
                "authz list filter returned the wrong number of decisions",
            ));
        }
        page.items = page
            .items
            .into_iter()
            .zip(decisions)
            .filter_map(|(item, decision)| decision.is_allow().then_some(item))
            .collect();
        if let (Some(cache), Some(key)) = (metadata_cache.as_ref(), cache_key) {
            cache.insert(key, MetadataCachePayload::List(page.clone()));
        }
        Ok(page)
    }

    pub async fn list_versions(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::ListVersionsOptions,
    ) -> ovstorage::Result<Vec<ovstorage::ObjectInfo>> {
        self.authorize(context, Operation::ListVersions, Some(&address))
            .await?;
        if let Some(cache) = self.library.metadata_cache().cloned() {
            let key = MetadataCacheKey {
                kind: MetadataKind::ListVersions,
                principal_id: None,
                address: address.as_str().into(),
                options_hash: ovstorage::metadata_cache::hash_list_versions_options(&options),
            };
            if let Some(MetadataCachePayload::ListVersions(versions)) = cache.get(&key) {
                return Ok(versions);
            }
            let mut versions = self.library.list_versions(address, options, None).await?;
            for v in versions.iter_mut() {
                self.attribution.unwrap_read(v);
            }
            cache.insert(key, MetadataCachePayload::ListVersions(versions.clone()));
            return Ok(versions);
        }
        let mut versions = self.library.list_versions(address, options, None).await?;
        for v in versions.iter_mut() {
            self.attribution.unwrap_read(v);
        }
        Ok(versions)
    }

    pub async fn get_latest_version(
        &self,
        context: &RequestContext,
        address: Url,
    ) -> ovstorage::Result<ovstorage::ObjectInfo> {
        self.authorize(context, Operation::ListVersions, Some(&address))
            .await?;
        let mut item = self.library.get_latest_version(address, None).await?;
        self.attribution.unwrap_read(&mut item);
        Ok(item)
    }

    pub async fn create_directory(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::CreateDirectoryOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        self.authorize(context, Operation::CreateDirectory, Some(&address))
            .await?;
        let mut info = self
            .library
            .create_directory(address.clone(), options, None)
            .await?;
        self.attribution.unwrap_read(&mut info);
        self.invalidate_metadata_for(&address).await;
        Ok(info)
    }

    pub async fn delete_directory(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::DeleteDirectoryOptions,
    ) -> ovstorage::Result<()> {
        self.authorize(context, Operation::DeleteDirectory, Some(&address))
            .await?;
        self.library
            .delete_directory(address.clone(), options, None)
            .await?;
        self.invalidate_metadata_for(&address).await;
        Ok(())
    }

    pub async fn copy(
        &self,
        context: &RequestContext,
        source: Url,
        destination: Url,
        options: ovstorage::CopyOptions,
    ) -> ovstorage::Result<WriteResult> {
        // Copy decomposes to Read(src) + Write(dst); not a standalone op.
        self.authorize(context, Operation::Read, Some(&source))
            .await?;
        self.authorize(context, Operation::Write, Some(&destination))
            .await?;
        let mut result = self
            .library
            .copy(source, destination.clone(), options, None)
            .await?;
        self.attribution.unwrap_read(&mut result.info);
        self.invalidate_metadata_for(&destination).await;
        Ok(result)
    }

    pub async fn rename(
        &self,
        context: &RequestContext,
        source: Url,
        destination: Url,
        options: ovstorage::RenameOptions,
    ) -> ovstorage::Result<()> {
        // Rename decomposes to Read(src) + Delete(src) + Write(dst).
        self.authorize(context, Operation::Read, Some(&source))
            .await?;
        self.authorize(context, Operation::Delete, Some(&source))
            .await?;
        self.authorize(context, Operation::Write, Some(&destination))
            .await?;
        self.library
            .rename(source.clone(), destination.clone(), options, None)
            .await?;
        self.invalidate_metadata_for(&source).await;
        self.invalidate_metadata_for(&destination).await;
        Ok(())
    }

    pub async fn update_metadata(
        &self,
        context: &RequestContext,
        address: Url,
        mut options: ovstorage::UpdateMetadataOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        self.authorize(context, Operation::UpdateMetadata, Some(&address))
            .await?;
        self.attribution
            .stamp_update_metadata(&context.principal, &mut options);
        let mut info = self
            .library
            .update_metadata(address.clone(), options, None)
            .await?;
        self.attribution.unwrap_read(&mut info);
        self.invalidate_metadata_for(&address).await;
        Ok(info)
    }

    pub async fn check_access(
        &self,
        context: &RequestContext,
        address: Url,
        operations: AccessOps,
    ) -> ovstorage::Result<ovstorage::AccessDecision> {
        self.authorize(context, Operation::CheckAccess, Some(&address))
            .await?;
        let mut decision = self
            .library
            .check_access(address.clone(), operations.clone(), None)
            .await?;
        ovstorage_authz::compose::apply_authz_access_decision(
            self,
            context,
            &address,
            &operations,
            &mut decision,
            "denied by broker authz",
        )
        .await?;
        Ok(decision)
    }

    pub async fn watch_directory(
        &self,
        context: &RequestContext,
        prefix: Url,
        opts: ovstorage::WatchDirectoryOptions,
    ) -> ovstorage::Result<BrokerClientWatchDirectoryStream> {
        self.authorize(context, Operation::WatchDirectory, Some(&prefix))
            .await?;
        let stream = self
            .watch_directory_hub
            .watch_directory(self.library.clone(), prefix, opts)
            .await?;
        let authz = self.authz.clone();
        let policy_state = self.policy_state.clone();
        let context = context.clone();
        // Captured handle lets per-event authorize call back into the
        // runtime from the non-tokio consumer thread.
        let runtime_handle = tokio::runtime::Handle::current();
        Ok(Box::new(stream.into_iter().filter_map(
            move |event| match event {
                Ok(ovstorage::ChangeEvent::Object {
                    address,
                    kind,
                    etag,
                    version,
                    size,
                    mtime,
                    at,
                    cursor,
                }) => {
                    let request =
                        AuthzRequest::from_context(&context, Operation::Read, Some(&address));
                    let authz_result = runtime_handle.block_on(authz.authorize(&request));
                    match policy_state.check(context.policy_epoch).and(authz_result) {
                        Ok(decision) if decision.is_allow() => {
                            Some(Ok(ovstorage::ChangeEvent::Object {
                                address,
                                kind,
                                etag,
                                version,
                                size,
                                mtime,
                                at,
                                cursor,
                            }))
                        }
                        Ok(_) => None,
                        Err(error) if error.code() == ErrorCode::PermissionDenied => None,
                        Err(error) => Some(Err(error)),
                    }
                }
                Ok(event @ ovstorage::ChangeEvent::Lapsed { .. }) => Some(Ok(event)),
                Err(error) => Some(Err(error)),
            },
        )))
    }

    pub async fn add_connection(
        &self,
        context: &RequestContext,
        request: ConnectionRequest,
    ) -> ovstorage::Result<Connection> {
        self.authorize(context, Operation::AddConnection, None)
            .await?;
        self.library.add_connection(request, None).await
    }

    pub async fn remove_connection(
        &self,
        context: &RequestContext,
        id: ovstorage::ConnectionId,
    ) -> ovstorage::Result<()> {
        self.authorize(context, Operation::RemoveConnection, None)
            .await?;
        self.library.remove_connection(&id)
    }

    pub async fn update_connection_credentials(
        &self,
        context: &RequestContext,
        id: ovstorage::ConnectionId,
        credentials: SecretBundle,
    ) -> ovstorage::Result<Connection> {
        self.authorize(context, Operation::UpdateConnectionCredentials, None)
            .await?;
        self.library
            .update_connection_credentials(&id, credentials, None)
            .await
    }

    pub async fn list_connections(
        &self,
        context: &RequestContext,
    ) -> ovstorage::Result<Vec<Connection>> {
        self.authorize(context, Operation::ListConnections, None)
            .await?;
        self.library.list_connections()
    }

    pub async fn add_alias(
        &self,
        context: &RequestContext,
        request: AliasRequest,
    ) -> ovstorage::Result<Alias> {
        // AddAlias keeps its op (registering a route), AND Read(to) so
        // an alias never exposes data the caller can't access.
        self.authorize(context, Operation::AddAlias, Some(&request.from))
            .await?;
        self.authorize(context, Operation::Read, Some(&request.to))
            .await?;
        self.library.add_alias(request)
    }

    pub async fn list_aliases(&self, context: &RequestContext) -> ovstorage::Result<Vec<Alias>> {
        self.authorize(context, Operation::ListAliases, None)
            .await?;
        self.library.list_aliases()
    }

    async fn authorize(
        &self,
        context: &RequestContext,
        operation: Operation,
        address: Option<&Url>,
    ) -> ovstorage::Result<()> {
        self.policy_state.check(context.policy_epoch)?;
        let request = AuthzRequest::from_context(context, operation, address);
        let decision = match self.authz.authorize(&request).await {
            Ok(decision) => decision,
            Err(err) => {
                metrics::counter!(crate::observability::AUTHZ_DECISIONS, "outcome" => "error")
                    .increment(1);
                return Err(err);
            }
        };
        let outcome = if decision.is_allow() { "allow" } else { "deny" };
        metrics::counter!(crate::observability::AUTHZ_DECISIONS, "outcome" => outcome).increment(1);
        decision.into_result(&request)
    }

    pub(crate) fn read_redirect(
        &self,
        context: &RequestContext,
        route_policy: &BrokerRoutePolicy,
        address: &Url,
    ) -> ovstorage::Result<ReadRedirect> {
        let endpoint = route_policy
            .read_redirect_endpoint
            .as_deref()
            .ok_or_else(|| invalid_config("broker read redirect endpoint is not configured"))?;
        let expires_at = SystemTime::now() + route_policy.redirect_ttl;
        Ok(ReadRedirect {
            request: redirect_request("GET", endpoint, address),
            response_parsing: ovstorage::ResponseParsing::default(),
            expires_at,
            scope: RedirectScope {
                physical_url_prefix: address.to_string(),
                operations: AccessOps {
                    read: true,
                    ..AccessOps::default()
                },
                expires_at,
            },
            audit_id: audit_id_for(context),
            policy_epoch: context.policy_epoch,
        })
    }

    pub(crate) fn write_redirect_batch(
        &self,
        context: &RequestContext,
        route_policy: &BrokerRoutePolicy,
        address: &Url,
        body: &Body,
        options: &WriteOptions,
    ) -> ovstorage::Result<WriteRedirectBatch> {
        let endpoint = route_policy
            .write_redirect_endpoint
            .as_deref()
            .ok_or_else(|| invalid_config("broker write redirect endpoint is not configured"))?;
        let expires_at = SystemTime::now() + route_policy.redirect_ttl;
        let batch = WriteRedirectBatch {
            continuation: Vec::new(),
            redirects: vec![WriteRedirect {
                request: redirect_request("PUT", endpoint, address),
                body_source: redirect_body_source(body, options)?,
                result_capture: ovstorage::ResultCapture::default(),
                expires_at,
                scope: RedirectScope {
                    physical_url_prefix: address.to_string(),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at,
                },
                audit_id: audit_id_for(context),
                policy_epoch: context.policy_epoch,
            }],
        };
        metrics::counter!(crate::observability::REDIRECT_EMISSIONS, "kind" => "write").increment(1);
        Ok(batch)
    }

    /// Open the upstream OAuth event stream for `address`. Token
    /// redemption happens host-side; the resolved credential lands back
    /// via `register_upstream_credential`.
    ///
    /// `capability` is the host-declared interactive-auth capability
    /// (sourced at the gRPC layer from the `x-ov-iauth` listener-level
    /// metadata header): `None` suppresses `OpenBrowser`/`DeviceCode`
    /// events, `Headless` allows device flow only, `Browser` allows
    /// the configured strategy. It is NOT part of the authz
    /// `RequestContext` — it's a listener-authn signal that travels
    /// alongside.
    pub async fn open_upstream_auth_stream(
        &self,
        context: &RequestContext,
        capability: ovstorage_plugin::InteractiveAuthCapability,
        address: Url,
    ) -> ovstorage::Result<
        std::pin::Pin<
            Box<
                dyn futures_core::Stream<
                        Item = std::result::Result<
                            ovstorage_broker_protocol::pb::AuthEventEnvelope,
                            tonic::Status,
                        >,
                    > + Send
                    + 'static,
            >,
        >,
    > {
        use futures::StreamExt;
        use ovstorage_broker_protocol::auth_event_to_proto_with_context;

        let audit_id = audit_id_for(context);
        let policy_epoch = context.policy_epoch;
        let to_proto = {
            let address = address.clone();
            let audit_id = audit_id.clone();
            move |event: &ovstorage_plugin::AuthEvent| {
                auth_event_to_proto_with_context(
                    event,
                    Some(&address),
                    Some(&audit_id),
                    Some(policy_epoch),
                )
            }
        };

        let provider_name = self.oauth_route_bindings.provider_for(&address);
        let Some(provider_name) = provider_name else {
            // No binding: single Failed{AuthRequired} event then close.
            let event = ovstorage_plugin::AuthEvent::Failed {
                error: ovstorage::Error::new(
                    ovstorage::ErrorCode::AuthRequired,
                    format!("broker: no upstream-OAuth provider registered for route {address}"),
                ),
            };
            return Ok(Box::pin(tokio_stream::once(Ok(to_proto(&event)))));
        };
        let Some(provider) = self.oauth_providers.lookup(provider_name) else {
            // Binding references unknown provider; CredentialUnavailable
            // distinguishes "retry later" from "no auth ever".
            let event = ovstorage_plugin::AuthEvent::Failed {
                error: ovstorage::Error::new(
                    ovstorage::ErrorCode::CredentialUnavailable,
                    format!(
                        "broker: oauth provider '{provider_name}' bound to route \
                         {address} is not registered"
                    ),
                ),
            };
            return Ok(Box::pin(tokio_stream::once(Ok(to_proto(&event)))));
        };

        let backend = ovstorage_plugin::BackendId(address.scheme().to_string());
        let flow = match provider.build_flow(backend, capability) {
            Ok(flow) => flow,
            Err(error) => {
                // Surface build-time refusal as terminal Failed so the
                // None capability never emits OpenBrowser/DeviceCode.
                let event = ovstorage_plugin::AuthEvent::Failed { error };
                return Ok(Box::pin(tokio_stream::once(Ok(to_proto(&event)))));
            }
        };
        let stream = flow.run().await.map_err(|err| err.into_error())?;
        let mapped = stream.map(move |item| match item {
            Ok(event) => Ok(to_proto(&event)),
            Err(error) => {
                // Surface as terminal Failed envelope (not tonic status)
                // so the host SDK sees a single shape.
                let event = ovstorage_plugin::AuthEvent::Failed { error };
                Ok(to_proto(&event))
            }
        });
        Ok(Box::pin(mapped))
    }

    /// Persist a host-resolved credential against the broker's
    /// `(BackendId, PrincipalView)` cache slot for `address`.
    pub async fn register_upstream_credential(
        &self,
        context: &RequestContext,
        address: Url,
        payload: ovstorage_broker_protocol::RegisterCredentialPayload,
    ) -> ovstorage::Result<()> {
        let Some(provider_name) = self.oauth_route_bindings.provider_for(&address) else {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::Unsupported,
                format!(
                    "broker: register_upstream_credential has no oauth_provider \
                     binding for route {address}"
                ),
            ));
        };
        let Some(provider) = self.oauth_providers.lookup(provider_name) else {
            return Err(ovstorage::Error::new(
                ovstorage::ErrorCode::CredentialUnavailable,
                format!(
                    "broker: oauth provider '{provider_name}' bound to route \
                     {address} is not registered"
                ),
            ));
        };
        let backend = ovstorage_plugin::BackendId(address.scheme().to_string());
        let principal = ovstorage::auth::PrincipalView::new(context.principal.id.clone());
        provider
            .accept_credential(
                &backend,
                &principal,
                payload.access_token,
                payload.refresh_token,
                payload.expires_at,
            )
            .await
    }
}

#[async_trait::async_trait]
impl ovstorage_authz::compose::AuthzCheck for Broker {
    async fn check(
        &self,
        context: &RequestContext,
        operation: Operation,
        address: &Url,
    ) -> ovstorage::Result<bool> {
        self.policy_state.check(context.policy_epoch)?;
        let request = AuthzRequest::from_context(context, operation, Some(address));
        Ok(self.authz.authorize(&request).await?.is_allow())
    }
}
