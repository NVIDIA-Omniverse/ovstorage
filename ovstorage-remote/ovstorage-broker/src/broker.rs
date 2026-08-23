// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// The per-request context the broker threads into each data op. It carries the
/// caller's **gathered credential material** (transport peer creds + bearer,
/// UNDECODED), not a resolved principal: the per-listener auth layer resolves
/// identity and authorizes. `audit_id` correlates request spans, errors, and
/// redirect audit trails without participating in authorization.
#[derive(Clone, Debug, Default)]
pub struct RequestContext {
    pub credential: Option<AuthCredential>,
    pub audit_id: Option<String>,
}

pub struct Broker {
    /// The per-listener auth Stack the daemon dispatches every data op through:
    /// the built-in **auth layer** (`builtin-auth`) `attach`ed over the shared
    /// auth-free inner (`upstream_credential → alias → copy_rename_fallback →
    /// [byte_cache] → [metadata_cache] → redirect_follower → retry → router →
    /// [attribution_<kind> →] backend-per-kind`, the attribution overlay sitting
    /// per-branch below the router). The auth layer
    /// resolves the caller's `ext::AUTH_CREDENTIAL`, authorizes, and stamps
    /// `ext::PRINCIPAL_ID` DOWN; the broker performs **no** host-side
    /// authentication, authorization, or principal resolution.
    ///
    /// The broker runs one listener per process (N=1), so this is a single
    /// shared auth Stack with transport-branched authn, not a fan-out of
    /// per-listener policy instances; the `attach`/shared-inner design supports
    /// multiple per-listener auth stacks over one inner, but that is not
    /// instantiated here.
    pub(crate) stack: Arc<Stack>,
    /// Auth-free inner Stack retained for structural health/readiness probes.
    /// Listener auth is request-facing and may correctly reject the empty
    /// context carried by the unauthenticated gRPC health protocol.
    pub(crate) health_stack: Arc<Stack>,
    /// Connectable backend kinds captured from the loaded plugin factories at
    /// compose time. The immutable Stack advertises only its *connected* kinds
    /// through `list_kinds`, so discovery reads this captured set instead.
    pub(crate) backend_kinds: Vec<StorageBackendKindDescriptor>,
    /// The listener-auth handle. Built-in auth retains its concrete reload and
    /// preflight gates; plugin auth retains its kind for lifecycle behavior.
    /// `None` for a broker wrapped around a bare Stack (`Broker::new`).
    pub(crate) auth_layer: Option<ListenerAuth>,
    pub(crate) watch_directory_state: Arc<WatchDirectoryState>,
    pub(crate) oauth_providers: Arc<crate::OAuthProviderRegistry>,
    pub(crate) oauth_route_bindings: Arc<crate::BrokerOAuthRouteBindings>,
    /// Whether a redirect carrying a credential broader than the redirected
    /// request may leave this process.
    ///
    /// The in-stack follower carries the same setting and applies it earlier,
    /// where it can still fetch the bytes and degrade gracefully. This copy is
    /// the **guarantee**: the layer graph is operator config and may rename or
    /// omit the follower entirely, so a policy that lived only there would
    /// silently vanish from such a deployment. Here it cannot be composed away.
    ///
    /// There is no graceful option at this edge — by the time a redirect
    /// reaches it the follower has already declined to fetch the bytes and the
    /// broker cannot stream them itself — so this check refuses rather than
    /// degrading. In a stock composition it never fires.
    pub(crate) disclose_redirect_credentials: bool,
}

/// What `Broker::read` produced: materialized `Bytes`, a chunk-by-chunk
/// `Stream` (never buffered whole at the broker), or a backend-emitted
/// `Redirect` the broker forwards for the client to follow directly.
///
/// The broker itself never mints a redirect: the configured backend plugins
/// hold the credentials in this process and do the presigning, and the broker
/// forwards what comes back. Whether it may forward one carrying a credential
/// broader than the redirected request is the operator's
/// `redirect_credential_disclosure` — see `guard_read_redirect`.
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

/// Project a Stack `RootInfo` to the discovery-facing `AddressRoot`. The alias
/// wrapper (outermost) has already applied visibility filtering + alias-root
/// synthesis, so this is a field-for-field reshape.
fn root_info_to_address_root(root: ovstorage::RootInfo) -> ovstorage::AddressRoot {
    ovstorage::AddressRoot {
        address: root.root,
        display_name: root.display_name,
        backend_kind: root.layer_kind,
        connection_id: root.connection_id,
        capabilities: root.capabilities,
        source: root.source,
        visibility: root.visibility,
        user_metadata: root.user_metadata,
    }
}

impl Broker {
    /// Wrap a bare composed Stack. The Stack is expected to be a per-listener
    /// auth Stack (auth layer over the shared inner); a broker built this way
    /// carries no concrete auth handle, so it cannot reload the policy in place
    /// (`auth_layer` is `None`). Production composes through
    /// [`Broker::from_composed`], which retains the handle.
    pub fn new(stack: Arc<Stack>) -> Self {
        Self {
            health_stack: stack.clone(),
            stack,
            backend_kinds: Vec::new(),
            auth_layer: None,
            watch_directory_state: Arc::new(WatchDirectoryState::default()),
            oauth_providers: Arc::new(crate::OAuthProviderRegistry::new()),
            oauth_route_bindings: Arc::new(crate::BrokerOAuthRouteBindings::new()),
            // Refuse by default. A broker built without operator config must
            // not disclose more than one built with it.
            disclose_redirect_credentials: false,
        }
    }

    /// Wrap a fully composed [`BrokerStack`] — the per-listener auth Stack plus
    /// the concrete auth-layer handle (for reload) and the discovered backend
    /// kinds. The production construction path.
    pub fn from_composed(composed: crate::BrokerStack) -> Self {
        Self {
            stack: composed.stack,
            health_stack: composed.health_stack,
            backend_kinds: composed.backend_kinds,
            auth_layer: Some(composed.auth_layer),
            watch_directory_state: Arc::new(WatchDirectoryState::default()),
            oauth_providers: composed.oauth_providers,
            oauth_route_bindings: composed.oauth_bindings,
            // Refuse by default. A broker built without operator config must
            // not disclose more than one built with it.
            disclose_redirect_credentials: false,
        }
    }

    /// Record the connectable backend kinds discovered at compose time. Consumed
    /// by the discovery endpoint (`list_backend_kinds`).
    pub fn with_backend_kinds(mut self, kinds: Vec<StorageBackendKindDescriptor>) -> Self {
        self.backend_kinds = kinds;
        self
    }

    /// Set the operator's redirect credential disclosure policy
    /// (`redirect_credential_disclosure`).
    pub fn with_redirect_disclosure(mut self, disclose: bool) -> Self {
        self.disclose_redirect_credentials = disclose;
        self
    }

    /// Refuse to emit a read redirect whose credential authorizes more than the
    /// redirected request.
    ///
    /// This fires only when the in-stack follower did not already handle it —
    /// which means the operator's graph has no follower, or one that does not
    /// see this path. There are no bytes in reach here, so the only available
    /// answer is a refusal.
    pub(crate) fn guard_read_redirect(&self, redirect: &ReadRedirect) -> ovstorage::Result<()> {
        if self.disclose_redirect_credentials
            || ovstorage::redirect_is_delegable(
                redirect.scope.credential,
                &redirect.request.headers,
            )
        {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::PermissionDenied,
            "this redirect carries a credential that authorizes more than the redirected \
             request, and `redirect_credential_disclosure` is `refuse`",
        ))
    }

    /// Whether every redirect in a write batch may be handed to the client.
    ///
    /// The same predicate `guard_read_redirect` uses, over the same
    /// declaration. `the_read_and_write_guards_agree_on_every_declaration`
    /// walks all four declarations through both and fails if they diverge.
    pub(crate) fn write_batch_is_delegable(&self, batch: &WriteRedirectBatch) -> bool {
        self.disclose_redirect_credentials
            || batch.redirects.iter().all(|redirect| {
                ovstorage::redirect_is_delegable(
                    redirect.scope.credential,
                    &redirect.request.headers,
                )
            })
    }

    /// Reload the built-in auth layer's policy in place from `policy_toml`,
    /// swapping the live `Arc<Policy>` atomically. A no-op (`Ok`) for a broker
    /// with no concrete auth handle (`Broker::new`); plugin auth reports that
    /// hot reload is unsupported. Production SIGHUP rebuilds
    /// the whole broker (which reconstructs the auth layer from fresh config);
    /// this is the fine-grained primitive for a policy-only reload.
    pub fn reload_auth_policy(&self, policy_toml: &str) -> ovstorage::Result<()> {
        match &self.auth_layer {
            Some(layer) => layer.reload_policy(policy_toml),
            None => Ok(()),
        }
    }

    pub fn oauth_providers(&self) -> &Arc<crate::OAuthProviderRegistry> {
        &self.oauth_providers
    }

    pub fn oauth_route_bindings(&self) -> &crate::BrokerOAuthRouteBindings {
        &self.oauth_route_bindings
    }

    /// Stamp the caller's gathered credential material onto a **fresh**
    /// [`ovstorage::Extensions`] bag under
    /// [`ovstorage::wrappers::ext::AUTH_CREDENTIAL`]
    /// — the UNDECODED input
    /// the per-listener auth layer resolves into a principal.
    ///
    /// **Security invariant (credential-injection).** The bag starts at
    /// [`ovstorage::Extensions::new()`] — the broker NEVER merges client-supplied
    /// extensions into a request, so a network client cannot inject
    /// `ext::PRINCIPAL_ID` (or any downstream extension) to impersonate a
    /// principal: only the transport-gathered `AUTH_CREDENTIAL` crosses this
    /// seam, and only the auth layer stamps `PRINCIPAL_ID` (DOWN, from its own
    /// resolution). Every Stack request the broker dispatches is built here (or
    /// through [`Broker::credential_req`]); there is no other seam.
    fn credential_cx(&self, context: &RequestContext) -> ovstorage::Extensions {
        ovstorage_authz_layer::stamp_credential(context.credential.as_ref())
    }

    /// Wrap `input` in a Stack [`Request`] carrying the caller's gathered
    /// credential (see [`Broker::credential_cx`]). This is the single request
    /// construction seam for every data operation.
    fn credential_req<T>(&self, context: &RequestContext, input: T) -> ovstorage::Request<T> {
        ovstorage::Request {
            extensions: self.credential_cx(context),
            input,
        }
    }

    pub fn stack(&self) -> &Arc<Stack> {
        &self.stack
    }

    pub fn health(&self) -> ovstorage::Result<()> {
        self.health_stack
            .list_kinds(&ovstorage::Extensions::new())?;
        Ok(())
    }

    /// Body-admission policy selected by the listener-auth implementation.
    ///
    /// Built-in auth has a typed host preflight and can authorize before the
    /// gRPC handler drains a replayable small body. A plugin auth wrapper has
    /// no separate preflight slot, so its authoritative `write` call must see a
    /// lazy body whose source is untouched until the authenticated inner path
    /// pulls its first chunk.
    pub(crate) fn write_admission(&self) -> ListenerWriteAdmission {
        self.auth_layer
            .as_ref()
            .map(ListenerAuth::write_admission)
            .unwrap_or(ListenerWriteAdmission::HostPreflight)
    }

    pub async fn list_backend_kinds(
        &self,
        context: &RequestContext,
    ) -> ovstorage::Result<Vec<StorageBackendKindDescriptor>> {
        // Backend kinds are served from a set captured at compose time, not
        // through the Stack, so no in-stack gate covers this endpoint. Gate it on
        // `ListBackendKinds` off listener auth so a policy can restrict
        // discovery. Plugin auth routes the authorization side effect through
        // its retained Layer's `list_kinds` slot. A bare Broker leaves it
        // ungated.
        if let Some(auth_layer) = &self.auth_layer {
            let cx = self.credential_cx(context);
            auth_layer.authorize_list_backend_kinds(&cx)?;
        }
        Ok(self.backend_kinds.clone())
    }

    pub async fn list_address_roots(
        &self,
        context: &RequestContext,
    ) -> ovstorage::Result<Vec<ovstorage::AddressRoot>> {
        use tracing::Instrument;
        let span = tracing::info_span!("broker.list_address_roots",);
        async move {
            // The in-stack auth Layer gates this slot (ListAddressRoots pre-check
            // + per-root Read/List filter) off the principal it resolves from the
            // request credential in `cx`; the alias wrapper below it projects the
            // snapshot (visibility filtering, alias-root synthesis). The broker
            // only stamps the request facts and reshapes each surviving `RootInfo`.
            let (snapshot, _updates) = self
                .stack
                .list_address_roots(&self.credential_cx(context), None)
                .await?;
            let roots = snapshot
                .roots
                .into_iter()
                .map(root_info_to_address_root)
                .collect::<Vec<_>>();
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
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            // Authorization is the top-of-stack auth Layer, which runs before the
            // in-stack metadata cache — revoking a principal (a policy reload)
            // drops them on the next request even with a hot cache.
            //
            // Canonicalize at broker entry — the same boundary normalization the
            // Stack applies to every routed request — so the object-vs-directory
            // decision below agrees with what the Stack routes (an authority-form
            // `mock://team` canonicalizes to `mock://team/`; deciding on the raw
            // form would probe the same directory address twice and never ask the
            // backend the object form). For a non-directory address, stat the
            // object form and
            // on `NotFound` retry the `to_directory` form, so a path-form directory
            // addressed without a trailing slash still resolves.
            //
            // Split re-authorization: the object-form
            // stat authorizes `Stat` on the object address in the Layer; the
            // `NotFound` directory retry re-`stat`s the `to_directory` form, so
            // the Layer re-authorizes the directory form independently. This is
            // fail-closed only at the exact object/dir boundary (object-form
            // allowed but dir-form denied on a real directory) — the safe
            // direction — matching a top-of-stack authz Layer that cannot know
            // the retry reuses the first decision.
            let address = canonicalize(address);
            let info = if !address::is_directory(&address) {
                match self
                    .stack
                    .stat(
                        self.credential_req(
                            context,
                            StatRequest {
                                address: address.clone(),
                                options: options.clone(),
                            },
                        ),
                        None,
                    )
                    .await
                {
                    Ok(info) => info,
                    Err(error) if error.code() == ErrorCode::NotFound => {
                        let dir_addr = address::to_directory(&address)?;
                        self.stack
                            .stat(
                                self.credential_req(
                                    context,
                                    StatRequest {
                                        address: dir_addr,
                                        options,
                                    },
                                ),
                                None,
                            )
                            .await?
                    }
                    Err(error) => return Err(error),
                }
            } else {
                self.stack
                    .stat(
                        self.credential_req(context, StatRequest { address, options }),
                        None,
                    )
                    .await?
            };
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
            object.address = %crate::trace::RedactedUrl(&address),
            redirect.kind = tracing::field::Empty,
            audit_id = tracing::field::Empty,
        );
        let span_record = span.clone();
        async move {
            // Dispatch through the stack. The per-policy-class follower decides
            // follow-vs-forward (small reads follow into the byte cache above;
            // oversize/forward-class reads surface the `Redirect` unfollowed),
            // and the in-stack byte cache serves hits as `Bytes`.
            match self
                .stack
                .read(
                    self.credential_req(
                        context,
                        ReadRequest {
                            address: address.clone(),
                            options,
                        },
                    ),
                    None,
                )
                .await?
            {
                ReadResult::Bytes { bytes, info } => Ok(BrokerReadOutcome::Bytes { info, bytes }),
                ReadResult::Stream { stream, info } => {
                    Ok(BrokerReadOutcome::Stream { info, stream })
                }
                ReadResult::LocalDelegate(local) => {
                    // Open the local file as a chunk-by-chunk stream;
                    // `fs::read` of the whole file would buffer
                    // multi-GB locals at the broker and serve them
                    // back as `Bytes` (defeating end-to-end streaming).
                    use futures::StreamExt;
                    let file = tokio::fs::File::open(&local.path).await.map_err(map_io)?;
                    let stream: ovstorage::ReadStream =
                        Box::pin(tokio_util::io::ReaderStream::new(file).map(
                            |chunk: Result<bytes::Bytes, std::io::Error>| chunk.map_err(map_io),
                        ));
                    let info = local.info;
                    Ok(BrokerReadOutcome::Stream { info, stream })
                }
                ReadResult::Redirect(redirect) => {
                    self.guard_read_redirect(&redirect)?;
                    span_record.record("redirect.kind", "read");
                    span_record.record("audit_id", redirect.audit_id.as_str());
                    metrics::counter!(crate::observability::REDIRECT_EMISSIONS, "kind" => "read")
                        .increment(1);
                    Ok(BrokerReadOutcome::Redirect(redirect))
                }
            }
        }
        .instrument(span)
        .await
    }

    /// Pre-flight a `Write` authorization on `address` for built-in auth so the
    /// gRPC handler can reject BEFORE draining or buffering the request body.
    /// Plugin auth has no separate preflight slot and returns `Unsupported` from
    /// this method; the gRPC handler instead dispatches its authoritative
    /// in-stack `write` with a lazy body whose source cannot be read before auth.
    /// A broker with no auth handle (`Broker::new`, tests) leaves it ungated.
    /// This does not double-count metrics — the metered decision is the in-stack
    /// gate the subsequent dispatch runs.
    pub fn authorize_write(
        &self,
        context: &RequestContext,
        address: &Url,
    ) -> ovstorage::Result<()> {
        match &self.auth_layer {
            Some(layer) => layer.authorize_write_preflight(&self.credential_cx(context), address),
            None => Ok(()),
        }
    }

    pub async fn write(
        &self,
        context: &RequestContext,
        address: Url,
        body: Body,
        options: WriteOptions,
    ) -> ovstorage::Result<BrokerWriteOutcome> {
        use tracing::Instrument;
        let span = tracing::info_span!(
            "broker.write",
            object.address = %crate::trace::RedactedUrl(&address),
        );
        async move {
            // Body-type dispatch (Bytes vs Stream) is owned by the in-stack
            // follower; call `write` uniformly. The in-stack metadata cache
            // self-invalidates on this mutation as it traverses the stack.
            let result = self
                .stack
                .write(
                    self.credential_req(
                        context,
                        WriteRequest {
                            address,
                            body,
                            options,
                        },
                    ),
                    None,
                )
                .await?;
            // `Stack::write` drives the redirect protocol internally through the
            // in-stack follower and answers with a completed write, so this
            // method has no batch to hand over and nothing here to gate.
            //
            // `BrokerWriteOutcome::Redirects` has no producer anywhere. If one
            // is ever added — a `write` that surfaces the batch rather than
            // driving it — **it must go through `write_batch_is_delegable`
            // first**, as `write_redirect` does. Both consumers of that variant
            // (the gRPC `Write` response and the client transport) put the batch
            // straight in front of a remote caller without checking it, so a
            // producer added here would disclose whatever the backend declared.
            Ok(BrokerWriteOutcome::Done(result))
        }
        .instrument(span)
        .await
    }

    pub async fn write_redirect(
        &self,
        context: &RequestContext,
        address: Url,
        options: WriteOptions,
    ) -> ovstorage::Result<WriteRedirectBatch> {
        // Backend-emitted write-redirect protocol: the multi-round client-driven
        // upload passes through the follower to the backend, which presigns the
        // redirect targets. The broker forwards; it never mints redirects itself.
        let batch = self
            .stack
            .write_redirect(
                self.credential_req(
                    context,
                    WriteRequest {
                        address,
                        body: Body::Bytes(Vec::new()),
                        options,
                    },
                ),
                None,
            )
            .await?;
        // Refuse to hand over a batch whose credential authorizes more than the
        // redirected request.
        //
        // `Unsupported` rather than `PermissionDenied`, deliberately: it is the
        // one code the client-side redirect follower turns into a body write
        // through this broker, so the write still completes — proxied — instead
        // of failing. That reuse is a compatibility choice, not sloppiness. The
        // honest name for this outcome would say "policy refused, proxy
        // instead", but a code no existing client recognises would abort the
        // write on every client that has not been updated for it, including the
        // C host and older replicas, which is a worse answer for the population
        // least able to adapt.
        if !self.write_batch_is_delegable(&batch) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "this broker will not delegate a write redirect carrying a credential that \
                 authorizes more than the redirected request; send the body through the broker \
                 instead, or set `redirect_credential_disclosure` to `allow` if these clients \
                 are inside the trust boundary",
            ));
        }
        metrics::counter!(crate::observability::REDIRECT_EMISSIONS, "kind" => "write").increment(1);
        Ok(batch)
    }

    pub async fn continue_write(
        &self,
        context: &RequestContext,
        address: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
    ) -> ovstorage::Result<ovstorage::WriteStep> {
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
        // The backend-emitted write-redirect protocol finalizes through the
        // stack: `continue_write` traverses the in-stack metadata-cache wrapper
        // so its invalidation fires as the finalize passes through.
        let step = self
            .stack
            .continue_write(
                self.credential_req(
                    context,
                    ContinueWriteRequest {
                        address,
                        redirects,
                        results,
                    },
                ),
                None,
            )
            .await?;
        // A multi-round upload can return a further batch, and this one has not
        // been handed over yet. Round one was forwarded because it declared a
        // credential scoped to the redirected request, so refusing here still
        // prevents a real disclosure rather than closing a door the client is
        // already through.
        //
        // There is no graceful answer mid-upload: the client-side follower's
        // fallback to a body write exists only at the first probe, and the body
        // may already be consumed. So this fails the write, and parts already
        // uploaded are orphaned until the bucket's lifecycle rules collect them.
        // That is the correct trade — a failed upload is recoverable and a
        // disclosed connection-wide credential is not — but it is a real cost,
        // so it is documented rather than buried.
        //
        // For every in-tree backend the declaration is a property of the
        // connection's auth mode, so a batch that starts delegable stays
        // delegable and this never fires. It guards a plugin that changes
        // mechanism between rounds.
        if let ovstorage::WriteStep::Redirects(batch) = &step
            && !self.write_batch_is_delegable(batch)
        {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                "a later round of this redirected write carries a credential that authorizes \
                 more than the redirected request, and `redirect_credential_disclosure` is \
                 `refuse`",
            ));
        }
        Ok(step)
    }

    pub async fn delete(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::DeleteOptions,
    ) -> ovstorage::Result<()> {
        self.stack
            .delete(
                self.credential_req(context, DeleteRequest { address, options }),
                None,
            )
            .await
    }

    pub async fn list(
        &self,
        context: &RequestContext,
        prefix: Url,
        options: ovstorage::ListOptions,
    ) -> ovstorage::Result<ovstorage::ListPage> {
        // Pass the `prefix` into the Stack as the caller wrote it. The
        // trailing slash is not part of node identity, so authorization
        // decides the same way for either spelling (List pre-check + per-item
        // Stat post-filter) and the backend derives its own directory key. The
        // broker does not normalize or authz-filter host-side; attribution is
        // unwrapped by the in-stack attribution wrapper below the auth layer.
        let page = self
            .stack
            .list(
                self.credential_req(context, ListRequest { prefix, options }),
                None,
            )
            .await?;
        Ok(page)
    }

    pub async fn list_versions(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::ListVersionsOptions,
    ) -> ovstorage::Result<Vec<ovstorage::ObjectInfo>> {
        let versions = self
            .stack
            .list_versions(
                self.credential_req(context, ListVersionsRequest { address, options }),
                None,
            )
            .await?
            .items;
        Ok(versions)
    }

    pub async fn get_latest_version(
        &self,
        context: &RequestContext,
        address: Url,
    ) -> ovstorage::Result<ovstorage::ObjectInfo> {
        let item = self
            .stack
            .get_latest_version(
                self.credential_req(
                    context,
                    ReadRequest {
                        address,
                        options: ovstorage::ReadOptions::default(),
                    },
                ),
                None,
            )
            .await?;
        Ok(item)
    }

    pub async fn create_directory(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::CreateDirectoryOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        // Pass the `address` into the Stack as the caller wrote it; the
        // backend derives its own directory key. `dir` is computed only to
        // stamp the caller-facing directory address onto the returned info.
        let dir = address::to_directory(&address)?;
        let item = self
            .stack
            .create_directory(
                self.credential_req(context, CreateDirectoryRequest { address, options }),
                None,
            )
            .await?;
        let info = ObjectInfo::from((dir, item));
        Ok(info)
    }

    pub async fn delete_directory(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::DeleteDirectoryOptions,
    ) -> ovstorage::Result<()> {
        // The address as the caller wrote it; the backend derives its own
        // directory key.
        self.stack
            .delete_directory(
                self.credential_req(context, DeleteDirectoryRequest { address, options }),
                None,
            )
            .await
    }

    pub async fn copy(
        &self,
        context: &RequestContext,
        source: Url,
        destination: Url,
        options: ovstorage::CopyOptions,
    ) -> ovstorage::Result<WriteResult> {
        // Copy decomposes to Read(src) + Write(dst) in the authz Layer.
        let step = self
            .stack
            .copy(
                self.credential_req(
                    context,
                    CopyRequest {
                        source,
                        destination,
                        options,
                    },
                ),
                None,
            )
            .await?;
        match step {
            ovstorage::WriteStep::Done(result) => Ok(result),
            ovstorage::WriteStep::Redirects(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "server-side copy returned redirect continuation",
            )),
        }
    }

    pub async fn rename(
        &self,
        context: &RequestContext,
        source: Url,
        destination: Url,
        options: ovstorage::RenameOptions,
    ) -> ovstorage::Result<()> {
        // Rename decomposes to Read(src) + Delete(src) + Write(dst) in the
        // authz Layer.
        self.stack
            .rename(
                self.credential_req(
                    context,
                    RenameRequest {
                        source,
                        destination,
                        options,
                    },
                ),
                None,
            )
            .await
    }

    pub async fn update_metadata(
        &self,
        context: &RequestContext,
        address: Url,
        options: ovstorage::UpdateMetadataOptions,
    ) -> ovstorage::Result<ObjectInfo> {
        // Validate before dispatch: a key present in both `user_metadata_set`
        // and `user_metadata_remove` is `InvalidArgument`.
        ovstorage::validate_update_metadata_options(&options)?;
        let item = self
            .stack
            .update_metadata(
                self.credential_req(
                    context,
                    UpdateMetadataRequest {
                        address: address.clone(),
                        options,
                    },
                ),
                None,
            )
            .await?;
        let info = ObjectInfo::from((address, item));
        Ok(info)
    }

    pub async fn check_access(
        &self,
        context: &RequestContext,
        address: Url,
        operations: AccessOps,
    ) -> ovstorage::Result<ovstorage::AccessDecision> {
        // The in-stack authz Layer runs the CheckAccess pre-check AND intersects
        // the backend decision with per-op authz (emitting the neutral "denied
        // by authz policy" reason); the broker just dispatches.
        self.stack
            .check_access(
                self.credential_req(
                    context,
                    CheckAccessRequest {
                        address,
                        operations,
                    },
                ),
                None,
            )
            .await
    }

    pub async fn watch_directory(
        &self,
        context: &RequestContext,
        prefix: Url,
        opts: ovstorage::WatchDirectoryOptions,
    ) -> ovstorage::Result<BrokerClientWatchDirectoryStream> {
        // Pass the RAW `prefix` + the caller's request context into
        // `watch_directory_state`, which threads it into `stack.watch_directory`.
        // The in-stack auth Layer runs the WatchDirectory pre-check AND
        // per-`Object`-event Read re-auth (dropping a mid-stream revoke on the
        // next event); the backend derives its own directory key for the
        // watch. Per-subscriber security and
        // visibility filtering is the auth Layer's job: the backend coalescer is
        // principal-blind (it keys physical subscriptions by connection/prefix,
        // never by principal, and enforces no per-principal watcher cap). The
        // broker performs no host-side per-event authz.
        let stream = self
            .watch_directory_state
            .watch_directory(
                self.stack.clone(),
                prefix,
                opts,
                self.credential_cx(context),
            )
            .await?;
        Ok(stream)
    }

    pub async fn list_connections(
        &self,
        context: &RequestContext,
    ) -> ovstorage::Result<Vec<Connection>> {
        // The in-stack authz Layer gates this slot (ListConnections) off the
        // principal + epoch carried in `cx`.
        let (snapshot, _updates) = self
            .stack
            .list_connections(&self.credential_cx(context), None)
            .await?;
        Ok(snapshot.connections)
    }

    async fn upstream_dispatch(
        &self,
        context: &RequestContext,
        address: &Url,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<(ovstorage::Extensions, ovstorage::ConnectionKey)> {
        let mut extensions = self.credential_cx(context);
        ovstorage::wrappers::ext::insert_upstream_auth_address(&mut extensions, address);
        let root = Layer::root_info_for(self.stack.as_ref(), address, &extensions, cancel).await?;
        let target = root.owning_target.ok_or_else(|| {
            Error::new(
                ErrorCode::NoRoute,
                "resolved root has no connection-owning layer",
            )
        })?;
        let id = root.connection_id.ok_or_else(|| {
            Error::new(
                ErrorCode::NoRoute,
                "resolved root has no connection id for upstream authentication",
            )
        })?;
        Ok((extensions, ovstorage::ConnectionKey { target, id }))
    }

    /// A daemon-owned PKCE callback is reachable only when the caller is on
    /// the daemon host. A remote browser request can still use a bound device
    /// provider, so downgrade that request to the headless/device flow instead
    /// of rejecting an interaction the provider can safely serve.
    fn upstream_auth_capability(
        &self,
        context: &RequestContext,
        address: &Url,
        requested: ovstorage::InteractiveAuthCapability,
    ) -> ovstorage::Result<ovstorage::InteractiveAuthCapability> {
        if requested != ovstorage::InteractiveAuthCapability::Browser {
            return Ok(requested);
        }
        let browser_is_local = context.credential.as_ref().is_some_and(|credential| {
            matches!(
                &credential.transport,
                ovstorage_authz_context::Transport::Uds { .. }
                    | ovstorage_authz_context::Transport::NamedPipe { .. }
            )
        });
        if browser_is_local {
            return Ok(requested);
        }
        let Some(provider_name) = self.oauth_route_bindings.provider_for(address) else {
            // Preserve the capability so the upstream wrapper can return its
            // specific unbound-route failure without opening a flow.
            return Ok(requested);
        };
        let Some(provider) = self.oauth_providers.lookup(provider_name) else {
            // Likewise, an unknown binding has a more useful typed failure in
            // the upstream wrapper and cannot construct a loopback flow.
            return Ok(requested);
        };
        if provider.supports_device_flow() {
            return Ok(ovstorage::InteractiveAuthCapability::Headless);
        }
        Err(Error::new(
            ErrorCode::Unsupported,
            "broker: remote browser authentication requires a device-capable provider; the \
             production broker-client does not run PKCE locally, so client tooling must complete \
             PKCE and call RegisterCredential explicitly",
        ))
    }

    /// Return the configuration-derived authentication diagnostic, if any,
    /// that the gRPC relay may safely disclose for this route. Provider flow
    /// errors are deliberately absent from this classification and remain
    /// fully redacted at the daemon boundary.
    pub(crate) fn upstream_auth_failure_diagnostic(
        &self,
        address: &Url,
    ) -> Option<crate::upstream_credential::RemoteAuthFailureDiagnostic> {
        crate::upstream_credential::RemoteAuthFailureDiagnostic::for_route(
            &self.oauth_route_bindings,
            &self.oauth_providers,
            address,
        )
    }

    /// Open the upstream authentication event stream for `address` through the
    /// broker's Stack. The in-stack auth layer resolves and stamps the caller's
    /// principal before the upstream-credential layer handles the request.
    /// A remote browser cannot reach a callback listener bound to the daemon's
    /// loopback interface. Device-capable providers therefore downgrade a
    /// remote browser request to device flow. PKCE-only providers return
    /// [`ErrorCode::Unsupported`]. The production broker-client has no
    /// automatic client-side PKCE fallback; separate client tooling must run
    /// PKCE locally and call `RegisterCredential` explicitly with the result.
    pub async fn open_upstream_auth_stream(
        &self,
        context: &RequestContext,
        capability: ovstorage::InteractiveAuthCapability,
        address: Url,
        cancel: Option<ovstorage::CancellationToken>,
    ) -> ovstorage::Result<ovstorage::AuthEventStream> {
        let (extensions, key) = self
            .upstream_dispatch(context, &address, cancel.clone())
            .await?;
        let capability = self.upstream_auth_capability(context, &address, capability)?;

        Layer::authenticate_connection(
            self.stack.as_ref(),
            ovstorage::Request {
                extensions,
                input: ovstorage::AuthenticateRequest {
                    key,
                    capability,
                    auto_open_browser: false,
                },
            },
            cancel,
        )
        .await
    }

    /// Register a client-resolved upstream OAuth credential through the
    /// broker's Stack. Principal selection and credential persistence remain
    /// inside the authenticated stack.
    pub async fn register_upstream_credential(
        &self,
        context: &RequestContext,
        address: Url,
        payload: protocol::RegisterCredentialPayload,
    ) -> ovstorage::Result<()> {
        let (extensions, key) = self.upstream_dispatch(context, &address, None).await?;
        let mut credentials = ovstorage::SecretBundle::default();
        credentials.fields.insert(
            "oauth".into(),
            ovstorage::SecretValue::OAuthToken {
                token: ovstorage::SecretBytes(payload.access_token),
                refresh: payload.refresh_token.map(ovstorage::SecretBytes),
                expires_at: payload.expires_at,
            },
        );

        Layer::update_connection_credentials(
            self.stack.as_ref(),
            ovstorage::Request {
                extensions,
                input: ovstorage::UpdateConnectionCredentialsRequest { key, credentials },
            },
            None,
        )
        .await
        .map(|_| ())
    }
}

#[cfg(test)]
mod upstream_dispatch_tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use async_trait::async_trait;
    use ovstorage::wrappers::ext;
    use ovstorage::{
        AddressVisibility, AuthEventStream, AuthenticateRequest, CancellationToken, Capabilities,
        ConfigLayer, Connection, ConnectionAuthState, ConnectionId, ConnectionSource, Error,
        ErrorCode, Extensions, InteractiveAuthCapability, Layer, LayerHandle, LayerKindDescriptor,
        LayerType, RangeReadStrategy, Request, RootInfo, RouteSource, Stack,
        UpdateConnectionCredentialsRequest, Url, UserMetadata,
    };

    use super::{Broker, RequestContext};

    struct DispatchProbe {
        route_error: bool,
        owning_target: Option<String>,
        connection_id: Option<ConnectionId>,
        root_extensions: Mutex<Vec<Extensions>>,
        auth_request: Mutex<Option<Request<AuthenticateRequest>>>,
        update_request: Mutex<Option<Request<UpdateConnectionCredentialsRequest>>>,
    }

    impl DispatchProbe {
        fn routable() -> Self {
            Self {
                route_error: false,
                owning_target: Some("backend".into()),
                connection_id: Some(ConnectionId("connection-1".into())),
                root_extensions: Mutex::new(Vec::new()),
                auth_request: Mutex::new(None),
                update_request: Mutex::new(None),
            }
        }

        fn missing_owner() -> Self {
            Self {
                owning_target: None,
                ..Self::routable()
            }
        }

        fn route_error() -> Self {
            Self {
                route_error: true,
                ..Self::routable()
            }
        }
    }

    fn descriptor() -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "dispatch-probe".into(),
            layer_type: LayerType::Backend,
            display_name: "dispatch probe".into(),
            description: None,
            config_schema: Vec::new(),
            credential_schema: Vec::new(),
            credential_methods: Vec::new(),
            icon: None,
            accepts_connections: true,
            auth_capable: false,
            supports_user_metadata: false,
        }
    }

    fn root_info(
        address: &Url,
        owning_target: Option<String>,
        connection_id: Option<ConnectionId>,
    ) -> RootInfo {
        RootInfo {
            root: address.clone(),
            display_name: None,
            layer_kind: "dispatch-probe".into(),
            connection_id,
            owning_target,
            capabilities: Capabilities::empty(),
            range_read_strategy: RangeReadStrategy::default(),
            source: RouteSource::Static {
                layer: ConfigLayer::Programmatic,
            },
            visible: true,
            visibility: AddressVisibility::Visible,
            alias_state: None,
            icon: None,
            user_metadata: UserMetadata::default(),
        }
    }

    fn connection(key: &ovstorage::ConnectionKey) -> Connection {
        Connection {
            id: key.id.clone(),
            backend_kind: "dispatch-probe".into(),
            display_name: "dispatch probe".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: UserMetadata::default(),
        }
    }

    #[async_trait]
    impl Layer for DispatchProbe {
        fn name(&self) -> &str {
            "dispatch-probe"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            descriptor()
        }

        async fn root_info_for(
            &self,
            address: &Url,
            extensions: &Extensions,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<RootInfo> {
            self.root_extensions
                .lock()
                .unwrap()
                .push(extensions.clone());
            if self.route_error {
                return Err(Error::new(ErrorCode::NoRoute, "probe has no route"));
            }
            Ok(root_info(
                address,
                self.owning_target.clone(),
                self.connection_id.clone(),
            ))
        }

        async fn authenticate_connection(
            &self,
            request: Request<AuthenticateRequest>,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<AuthEventStream> {
            *self.auth_request.lock().unwrap() = Some(request);
            Ok(Box::new(std::iter::empty()))
        }

        async fn update_connection_credentials(
            &self,
            request: Request<UpdateConnectionCredentialsRequest>,
            _cancel: Option<CancellationToken>,
        ) -> ovstorage::Result<Connection> {
            let result = connection(&request.input.key);
            *self.update_request.lock().unwrap() = Some(request);
            Ok(result)
        }
    }

    async fn broker_for(probe: Arc<DispatchProbe>) -> Broker {
        let root: LayerHandle = probe;
        let stack = Stack::builder("probe")
            .attach("probe", root)
            .build()
            .await
            .unwrap();
        Broker::new(Arc::new(stack))
    }

    fn assert_broker_extensions(extensions: &Extensions, address: &Url) {
        assert_eq!(
            extensions.get(ext::UPSTREAM_AUTH_ADDRESS),
            Some(address.as_str().as_bytes())
        );
        assert!(extensions.get(ext::AUTH_CREDENTIAL).is_some());
        assert!(extensions.get(ext::PRINCIPAL_ID).is_none());
    }

    fn context() -> RequestContext {
        RequestContext {
            credential: Some(ovstorage_authz_context::AuthCredential {
                bearer: Some(b"opaque-bearer".to_vec()),
                transport: ovstorage_authz_context::Transport::Uds {
                    uid: 1000,
                    gid: 1000,
                    pid: 42,
                },
                forwarded: None,
            }),
            audit_id: None,
        }
    }

    fn tcp_context(peer_addr: &str) -> RequestContext {
        RequestContext {
            credential: Some(ovstorage_authz_context::AuthCredential {
                bearer: None,
                transport: ovstorage_authz_context::Transport::Tcp {
                    peer_addr: peer_addr.to_string(),
                    tls_client_cert: None,
                },
                forwarded: None,
            }),
            audit_id: None,
        }
    }

    #[tokio::test]
    async fn open_auth_resolves_route_and_dispatches_credential_derived_extensions() {
        let probe = Arc::new(DispatchProbe::routable());
        let broker = broker_for(probe.clone()).await;
        let address = Url::parse("s3://bucket/object").unwrap();

        let _stream = broker
            .open_upstream_auth_stream(
                &context(),
                InteractiveAuthCapability::Headless,
                address.clone(),
                Some(CancellationToken::new()),
            )
            .await
            .unwrap();

        let roots = probe.root_extensions.lock().unwrap();
        assert_eq!(roots.len(), 1);
        assert_broker_extensions(&roots[0], &address);
        let request = probe.auth_request.lock().unwrap().take().unwrap();
        assert_eq!(request.extensions, roots[0]);
        assert_eq!(request.input.key.target, "backend");
        assert_eq!(request.input.key.id, ConnectionId("connection-1".into()));
        assert_eq!(
            request.input.capability,
            InteractiveAuthCapability::Headless
        );
        assert!(!request.input.auto_open_browser);
    }

    #[tokio::test]
    async fn remote_tcp_browser_request_without_a_binding_dispatches_typed_failure_path() {
        let probe = Arc::new(DispatchProbe::routable());
        let broker = broker_for(probe.clone()).await;
        let address = Url::parse("s3://bucket/object").unwrap();

        let _stream = broker
            .open_upstream_auth_stream(
                &tcp_context("203.0.113.8:41000"),
                InteractiveAuthCapability::Browser,
                address,
                None,
            )
            .await
            .expect("the upstream wrapper owns the unbound-route failure");

        let request = probe.auth_request.lock().unwrap().take().unwrap();
        assert_eq!(request.input.capability, InteractiveAuthCapability::Browser);
    }

    #[tokio::test]
    async fn remote_tcp_browser_request_with_unknown_provider_dispatches_typed_failure_path() {
        let probe = Arc::new(DispatchProbe::routable());
        let mut broker = broker_for(probe.clone()).await;
        let address = Url::parse("s3://bucket/object").unwrap();
        broker.oauth_route_bindings = Arc::new(
            crate::BrokerOAuthRouteBindings::new()
                .with_route(Url::parse("s3://bucket/").unwrap(), "ghost-provider"),
        );

        let _stream = broker
            .open_upstream_auth_stream(
                &tcp_context("203.0.113.8:41000"),
                InteractiveAuthCapability::Browser,
                address,
                None,
            )
            .await
            .expect("the upstream wrapper owns the unknown-provider failure");

        let request = probe.auth_request.lock().unwrap().take().unwrap();
        assert_eq!(request.input.capability, InteractiveAuthCapability::Browser);
    }

    #[tokio::test]
    async fn remote_tcp_browser_pkce_only_provider_requires_explicit_registration() {
        let probe = Arc::new(DispatchProbe::routable());
        let mut broker = broker_for(probe.clone()).await;
        let address = Url::parse("http://127.0.0.1/object").unwrap();
        let state_root = std::env::temp_dir().join(format!(
            "ovstorage-broker-pkce-capability-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_root).unwrap();
        let provider = Arc::new(ovstorage::auth::OAuthCredentialProvider::new(
            "pkce-only",
            "http",
            ovstorage::auth::OAuthEndpoints {
                authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                client_id: "client".into(),
                scope: None,
            },
            Arc::new(
                ovstorage::auth::SqliteSecretStore::open(&state_root).expect("open sqlite store"),
            ),
            Arc::new(ovstorage::auth::AuthRefreshLock::open(&state_root).unwrap()),
            ovstorage::auth::OAuthStrategy::Pkce {
                redirect_base: Url::parse("http://127.0.0.1/callback").unwrap(),
            },
        ));
        broker.oauth_providers =
            Arc::new(crate::OAuthProviderRegistry::new().with_provider("pkce-only", provider));
        broker.oauth_route_bindings = Arc::new(
            crate::BrokerOAuthRouteBindings::new()
                .with_route(Url::parse("http://127.0.0.1/").unwrap(), "pkce-only"),
        );

        let error = broker
            .open_upstream_auth_stream(
                &tcp_context("127.0.0.1:41000"),
                InteractiveAuthCapability::Browser,
                address,
                None,
            )
            .await
            .err()
            .expect("TCP does not prove that the browser can reach daemon loopback");

        assert_eq!(error.code(), ErrorCode::Unsupported);
        assert!(
            error
                .message()
                .contains("production broker-client does not run PKCE locally")
        );
        assert!(error.message().contains("RegisterCredential explicitly"));
        assert!(probe.auth_request.lock().unwrap().is_none());
        drop(broker);
        let _ = std::fs::remove_dir_all(state_root);
    }

    #[tokio::test]
    async fn uds_browser_request_keeps_the_browser_flow() {
        let probe = Arc::new(DispatchProbe::routable());
        let broker = broker_for(probe.clone()).await;
        let address = Url::parse("s3://bucket/object").unwrap();

        let _stream = broker
            .open_upstream_auth_stream(
                &context(),
                InteractiveAuthCapability::Browser,
                address,
                None,
            )
            .await
            .unwrap();

        let request = probe.auth_request.lock().unwrap().take().unwrap();
        assert_eq!(request.input.capability, InteractiveAuthCapability::Browser);
    }

    #[tokio::test]
    async fn register_credential_maps_oauth_payload_and_dispatches_extensions() {
        let probe = Arc::new(DispatchProbe::routable());
        let broker = broker_for(probe.clone()).await;
        let address = Url::parse("s3://bucket/object").unwrap();
        let expires_at = SystemTime::now() + Duration::from_secs(3_600);

        broker
            .register_upstream_credential(
                &context(),
                address.clone(),
                ovstorage_broker_protocol::RegisterCredentialPayload {
                    access_token: b"access".to_vec(),
                    refresh_token: Some(b"refresh".to_vec()),
                    expires_at: Some(expires_at),
                },
            )
            .await
            .unwrap();

        let roots = probe.root_extensions.lock().unwrap();
        assert_eq!(roots.len(), 1);
        assert_broker_extensions(&roots[0], &address);
        let request = probe.update_request.lock().unwrap().take().unwrap();
        assert_eq!(request.extensions, roots[0]);
        assert_eq!(request.input.key.target, "backend");
        assert_eq!(request.input.key.id, ConnectionId("connection-1".into()));
        let oauth = request.input.credentials.fields.get("oauth").unwrap();
        let ovstorage::SecretValue::OAuthToken {
            token,
            refresh,
            expires_at: actual_expiry,
        } = oauth
        else {
            panic!("oauth field must contain an OAuthToken");
        };
        assert_eq!(token.as_bytes(), b"access");
        assert_eq!(refresh.as_ref().unwrap().as_bytes(), b"refresh");
        assert_eq!(*actual_expiry, Some(expires_at));
    }

    #[tokio::test]
    async fn route_resolution_failures_remain_typed_errors() {
        let address = Url::parse("s3://bucket/object").unwrap();
        let route_error = Arc::new(DispatchProbe::route_error());
        let broker = broker_for(route_error.clone()).await;
        let error = broker
            .open_upstream_auth_stream(
                &RequestContext::default(),
                InteractiveAuthCapability::None,
                address.clone(),
                None,
            )
            .await
            .err()
            .expect("route error");
        assert_eq!(error.code(), ErrorCode::NoRoute);
        assert!(route_error.auth_request.lock().unwrap().is_none());

        let missing_owner = Arc::new(DispatchProbe::missing_owner());
        let broker = broker_for(missing_owner.clone()).await;
        let error = broker
            .register_upstream_credential(
                &RequestContext::default(),
                address,
                ovstorage_broker_protocol::RegisterCredentialPayload {
                    access_token: Vec::new(),
                    refresh_token: None,
                    expires_at: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::NoRoute);
        assert!(missing_owner.update_request.lock().unwrap().is_none());
    }
}
