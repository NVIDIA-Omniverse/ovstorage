// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-principal upstream OAuth credential handling inside the broker Stack.
//!
//! This wrapper sits below the listener's built-in auth layer. The auth layer
//! authorizes the request and stamps [`ext::PRINCIPAL_ID`] on the way down;
//! this layer uses only that stamp to select the broker-side credential slot.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage::auth::{
    CredentialError, OAuthCredentialProvider, PrincipalView, ResolvedOAuthCredentialLease,
};
use ovstorage::wrappers::ext;
use ovstorage::{
    AuthEvent, AuthEventStream, AuthenticateRequest, BackendId, CancellationToken, Capabilities,
    Connection, ConnectionAuthState, ConnectionSource, Error, ErrorCode, Layer, LayerConfig,
    LayerHandle, LayerKindDescriptor, LayerType, LocalDelegate, ObjectInfo, ReadRequest,
    ReadResult, Request, Result, SecretBundle, SecretValue, StatRequest,
    UpdateConnectionCredentialsRequest, Url, WrapperFactory, bail_if_cancelled,
};

use crate::{BrokerOAuthRouteBindings, OAuthProviderRegistry, UpstreamOAuthConsumerCapability};

/// Built-in wrapper kind for the broker's per-principal upstream credentials.
pub const UPSTREAM_CREDENTIAL_KIND: &str = "upstream_credential";

/// Each admitted long-lived flow owns one current-thread runtime on an OS
/// thread. The process-wide permit is acquired immediately before that worker
/// is spawned. Terminal validation failures can still use the short-lived gRPC
/// relay thread, but they do not create a flow worker and are not counted here.
const MAX_CONCURRENT_UPSTREAM_AUTH_FLOWS: usize = 32;
/// PKCE advertises a five-minute prompt lifetime. Enforce the same ceiling at
/// the broker boundary so a caller cannot park a flow indefinitely.
const UPSTREAM_AUTH_FLOW_TIMEOUT: Duration = Duration::from_secs(300);

static ACTIVE_UPSTREAM_AUTH_FLOWS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn active_upstream_auth_flows_for_test() -> usize {
    ACTIVE_UPSTREAM_AUTH_FLOWS.load(Ordering::Acquire)
}

struct UpstreamAuthFlowPermit {
    active: &'static AtomicUsize,
}

impl UpstreamAuthFlowPermit {
    fn acquire() -> Result<Self> {
        Self::acquire_from(
            &ACTIVE_UPSTREAM_AUTH_FLOWS,
            MAX_CONCURRENT_UPSTREAM_AUTH_FLOWS,
        )
    }

    fn acquire_from(active_flows: &'static AtomicUsize, limit: usize) -> Result<Self> {
        active_flows
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .map(|_| Self {
                active: active_flows,
            })
            .map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    format!("broker: at most {limit} upstream OAuth flows may run concurrently"),
                )
            })
    }
}

impl Drop for UpstreamAuthFlowPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        kind: UPSTREAM_CREDENTIAL_KIND.to_string(),
        layer_type: LayerType::Wrapper,
        display_name: "Upstream credential".to_string(),
        description: Some(
            "Stores broker-side upstream OAuth credentials in the authenticated principal's slot"
                .to_string(),
        ),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        // The boundary handles per-request upstream credentials; it is not a
        // listener-auth layer and cannot authenticate callers.
        auth_capable: false,
        supports_user_metadata: false,
    }
}

/// Factory for [`UpstreamCredentialWrapper`].
#[derive(Clone)]
pub struct UpstreamCredentialWrapperFactory {
    providers: Arc<OAuthProviderRegistry>,
    bindings: Arc<BrokerOAuthRouteBindings>,
}

impl UpstreamCredentialWrapperFactory {
    pub fn new(
        providers: Arc<OAuthProviderRegistry>,
        bindings: impl Into<Arc<BrokerOAuthRouteBindings>>,
    ) -> Self {
        Self {
            providers,
            bindings: bindings.into(),
        }
    }
}

#[async_trait]
impl WrapperFactory for UpstreamCredentialWrapperFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        _config: &LayerConfig,
        inner: LayerHandle,
        cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        bail_if_cancelled(&cancel)?;
        self.providers.validate()?;
        Ok(Arc::new(UpstreamCredentialWrapper {
            name: name.to_string(),
            inner,
            providers: Arc::clone(&self.providers),
            bindings: Arc::clone(&self.bindings),
        }))
    }
}

/// Broker Stack layer that installs upstream OAuth credentials after policy
/// authorization has stamped the caller principal on the request.
pub struct UpstreamCredentialWrapper {
    name: String,
    inner: LayerHandle,
    providers: Arc<OAuthProviderRegistry>,
    bindings: Arc<BrokerOAuthRouteBindings>,
}

impl UpstreamCredentialWrapper {
    pub fn new(
        name: impl Into<String>,
        inner: LayerHandle,
        providers: Arc<OAuthProviderRegistry>,
        bindings: impl Into<Arc<BrokerOAuthRouteBindings>>,
    ) -> Self {
        Self {
            name: name.into(),
            inner,
            providers,
            bindings: bindings.into(),
        }
    }

    fn principal(extensions: &ovstorage::Extensions) -> PrincipalView {
        let id = extensions
            .get(ext::PRINCIPAL_ID)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_else(|| ovstorage_authz_context::ANONYMOUS_PRINCIPAL_ID.to_string());
        PrincipalView::new(id)
    }

    fn resolve_provider(
        &self,
        address: &Url,
    ) -> std::result::Result<Arc<OAuthCredentialProvider>, ProviderResolutionError> {
        let Some(provider_name) = self.bindings.provider_for(address) else {
            return Err(ProviderResolutionError::Unbound);
        };
        self.providers.lookup(provider_name).ok_or_else(|| {
            ProviderResolutionError::UnknownProvider {
                name: provider_name.to_string(),
            }
        })
    }

    /// Require a production read-side credential consumer. This is an
    /// in-memory registry lookup; data operations rely on the owning backend's
    /// mandatory backend-kind check rather than resolving the route a second
    /// time before normal dispatch resolves it below.
    fn ensure_provider_read_consumer(&self, provider: &OAuthCredentialProvider) -> Result<()> {
        self.providers.validate_backend_slots()?;
        if !self.providers.has_consumer_capability(
            provider.backend_kind(),
            UpstreamOAuthConsumerCapability::ReadSide,
        ) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "broker: oauth provider '{}' targets backend kind '{}', which has no registered production read-side consumer for broker-resolved OAuth credentials on stat/read/materialize",
                    provider.name(),
                    provider.backend_kind(),
                ),
            ));
        }
        Ok(())
    }

    /// Before reporting that an authentication or registration succeeded,
    /// verify that the resolved route is owned by the registered consumer.
    /// These credential-establishing operations are infrequent; ordinary data
    /// requests avoid this duplicate route walk and are still fail-closed by
    /// the consumer's backend-kind validation.
    async fn ensure_provider_route_owner(
        &self,
        provider: &OAuthCredentialProvider,
        address: &Url,
        extensions: &ovstorage::Extensions,
        cancel: &Option<CancellationToken>,
    ) -> Result<()> {
        self.ensure_provider_read_consumer(provider)?;
        let root = self
            .inner
            .root_info_for(address, extensions, cancel.clone())
            .await?;
        if root.layer_kind != provider.backend_kind() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "broker: oauth provider '{}' targets backend kind '{}' but route {} is owned by backend kind '{}'",
                    provider.name(),
                    provider.backend_kind(),
                    address,
                    root.layer_kind,
                ),
            ));
        }
        Ok(())
    }

    /// Resolve the current principal's provider slot and pass only its
    /// non-secret keyring reference to the owning backend for this request.
    /// A cold slot remains an anonymous request so the backend can surface its
    /// ordinary authentication challenge; provider failures do not silently
    /// weaken to anonymous access.
    async fn stamp_resolved_oauth_credential(
        &self,
        address: &Url,
        extensions: &mut ovstorage::Extensions,
        cancel: &Option<CancellationToken>,
    ) -> Result<Option<ResolvedOAuthSlot>> {
        // This mandatory boundary is the sole minter. Remove any inbound
        // reference before declining an unbound/cold request so a future
        // composition seam cannot forward a caller-selected keyring handle.
        let _ = ext::take_resolved_oauth_credential(extensions)?;
        bail_if_cancelled(cancel)?;
        let provider = match self.resolve_provider(address) {
            Ok(provider) => provider,
            Err(ProviderResolutionError::Unbound) => return Ok(None),
            Err(ProviderResolutionError::UnknownProvider { name }) => {
                return Err(Error::new(
                    ErrorCode::CredentialUnavailable,
                    format!(
                        "broker: oauth provider '{name}' bound to route {address} is not registered"
                    ),
                ));
            }
        };
        self.ensure_provider_read_consumer(&provider)?;
        let backend = BackendId(provider.backend_kind().to_string());
        let principal = Self::principal(extensions);
        match provider
            .resolve_access_keyring_handle_lease(&backend, &principal)
            .await
        {
            Ok(lease) => {
                ext::insert_resolved_oauth_credential(
                    extensions,
                    &ext::ResolvedOAuthCredentialRef {
                        backend_kind: backend.0.clone(),
                        keyring_handle: lease.keyring_handle().to_string(),
                    },
                )?;
                Ok(Some(ResolvedOAuthSlot {
                    provider,
                    backend,
                    principal,
                    lease,
                }))
            }
            Err(CredentialError::Unavailable { .. }) => Ok(None),
            Err(CredentialError::Backend(error)) => {
                let code = error.code();
                tracing::warn!(
                    provider = provider.name(),
                    error_code = ?code,
                    "broker upstream OAuth credential refresh failed"
                );
                Err(Error::new(
                    code,
                    "broker: upstream OAuth credential refresh failed",
                ))
            }
        }
    }

    async fn recover_rejected_oauth_credential<T>(
        &self,
        rejected: &ResolvedOAuthSlot,
        address: &Url,
        request: &mut Request<T>,
        cancel: &Option<CancellationToken>,
    ) -> Result<bool> {
        match rejected
            .provider
            .invalidate_access_token_if_lease(
                &rejected.backend,
                &rejected.principal,
                &rejected.lease,
            )
            .await
        {
            Ok(_) => {}
            Err(CredentialError::Unavailable { .. }) => return Ok(false),
            Err(CredentialError::Backend(error)) => {
                let code = error.code();
                tracing::warn!(
                    provider = rejected.provider.name(),
                    error_code = ?code,
                    "broker upstream OAuth credential invalidation failed"
                );
                return Err(Error::new(
                    code,
                    "broker: upstream OAuth credential invalidation failed",
                ));
            }
        }
        Ok(self
            .stamp_resolved_oauth_credential(address, &mut request.extensions, cancel)
            .await?
            .is_some())
    }

    /// Dispatch one credential-aware read operation and recover at most once
    /// from rejection of the credential minted for that request.
    ///
    /// A rejection is eligible only after the route is resolved back to the
    /// registered provider backend. This keeps a mismatched route or unrelated
    /// backend's `AuthRequired` response from invalidating a valid provider
    /// slot. The operation closure is invoked once normally and at most once
    /// more after conditional invalidation and single-flight re-resolution.
    async fn dispatch_with_oauth_recovery<T, O, F, Fut>(
        &self,
        mut request: Request<T>,
        address: Url,
        cancel: Option<CancellationToken>,
        dispatch: F,
    ) -> Result<O>
    where
        T: Clone,
        F: Fn(Request<T>, Option<CancellationToken>) -> Fut,
        Fut: Future<Output = Result<O>>,
    {
        let resolved = self
            .stamp_resolved_oauth_credential(&address, &mut request.extensions, &cancel)
            .await?;
        // The retry copy exists only when a credential was minted for this
        // request — recovery is unreachable otherwise, so a route with no
        // OAuth binding (the default deployment) pays no clone.
        let retry = match resolved.is_some() {
            true => {
                let mut retry = request.clone();
                let _ = ext::take_resolved_oauth_credential(&mut retry.extensions)?;
                Some(retry)
            }
            false => None,
        };
        let error = match dispatch(request, cancel.clone()).await {
            Ok(output) => return Ok(output),
            Err(error) => error,
        };
        let Some(resolved) = resolved.filter(|_| error.code() == ErrorCode::AuthRequired) else {
            return Err(error);
        };
        let Some(mut retry) = retry else {
            return Err(error);
        };

        // Recovery is best-effort: whatever the recovery machinery itself
        // fails with — a mismatched route owner, a transient root walk, a
        // failed refresh — the caller must see the error the backend produced.
        // `AuthRequired` is the signal a client keys on to authenticate;
        // substituting a broker-side condition would turn a recoverable
        // rejection into a permanent one, and would put configuration detail
        // on the data path that the `Auth` stream deliberately routes through
        // an allowlist.
        if let Err(declined) = self
            .ensure_provider_route_owner(&resolved.provider, &address, &retry.extensions, &cancel)
            .await
        {
            tracing::warn!(
                provider = resolved.provider.name(),
                error_code = ?declined.code(),
                "broker upstream OAuth recovery declined: provider route-owner check failed"
            );
            return Err(error);
        }
        match self
            .recover_rejected_oauth_credential(&resolved, &address, &mut retry, &cancel)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(error),
            Err(declined) => {
                tracing::warn!(
                    provider = resolved.provider.name(),
                    error_code = ?declined.code(),
                    "broker upstream OAuth recovery declined: credential re-resolution failed"
                );
                return Err(error);
            }
        }
        dispatch(retry, cancel).await
    }
}

struct ResolvedOAuthSlot {
    provider: Arc<OAuthCredentialProvider>,
    backend: BackendId,
    principal: PrincipalView,
    lease: ResolvedOAuthCredentialLease,
}

enum ProviderResolutionError {
    Unbound,
    UnknownProvider { name: String },
}

/// Configuration-derived authentication failure that is safe to disclose to
/// a remote caller. This classification is computed independently of the
/// provider-produced [`Error`], so raw IdP response text can never opt itself
/// into the daemon-to-client allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RemoteAuthFailureDiagnostic {
    /// The route has no configured upstream OAuth provider.
    UnboundRoute,
    /// The route names a provider absent from the daemon registry. The stored
    /// name contains only a bounded, display-safe identifier alphabet.
    UnknownProvider { name: String },
}

impl RemoteAuthFailureDiagnostic {
    pub(crate) fn for_route(
        bindings: &BrokerOAuthRouteBindings,
        providers: &OAuthProviderRegistry,
        address: &Url,
    ) -> Option<Self> {
        let Some(name) = bindings.provider_for(address) else {
            return Some(Self::UnboundRoute);
        };
        providers
            .lookup(name)
            .is_none()
            .then(|| Self::UnknownProvider {
                name: sanitize_provider_diagnostic_name(name),
            })
    }

    pub(crate) fn expected_code(&self) -> ErrorCode {
        match self {
            Self::UnboundRoute => ErrorCode::AuthRequired,
            Self::UnknownProvider { .. } => ErrorCode::CredentialUnavailable,
        }
    }

    pub(crate) fn remote_message(&self) -> String {
        match self {
            Self::UnboundRoute => {
                "broker: no upstream OAuth provider is configured for this route".to_string()
            }
            Self::UnknownProvider { name } => {
                format!("broker: configured OAuth provider '{name}' is not registered")
            }
        }
    }
}

const MAX_PROVIDER_DIAGNOSTIC_CHARS: usize = 128;

fn sanitize_provider_diagnostic_name(name: &str) -> String {
    let mut chars = name.chars();
    let mut sanitized = String::with_capacity(name.len().min(MAX_PROVIDER_DIAGNOSTIC_CHARS));
    for character in chars.by_ref().take(MAX_PROVIDER_DIAGNOSTIC_CHARS) {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
            sanitized.push(character);
        } else {
            sanitized.push('_');
        }
    }
    if chars.next().is_some() {
        sanitized.push_str("...");
    }
    if sanitized.is_empty() {
        sanitized.push_str("unnamed-provider");
    }
    sanitized
}

fn failed_stream(error: Error) -> AuthEventStream {
    Box::new(std::iter::once(Ok(AuthEvent::Failed { error })))
}

type OAuthCredentialParts = (Vec<u8>, Option<Vec<u8>>, Option<SystemTime>);

fn take_oauth_credential(mut bundle: SecretBundle) -> Result<OAuthCredentialParts> {
    match bundle.fields.remove("oauth") {
        Some(SecretValue::OAuthToken {
            token,
            refresh,
            expires_at,
        }) => Ok((
            token.into_inner(),
            refresh.map(|value| value.into_inner()),
            expires_at,
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "broker: upstream credential field 'oauth' must be an OAuthToken",
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            "broker: upstream credential bundle is missing OAuthToken field 'oauth'",
        )),
    }
}

struct OAuthEventBridge {
    receiver: std::sync::mpsc::IntoIter<Result<AuthEvent>>,
    cancel: Option<CancellationToken>,
    shutdown: CancellationToken,
    join: Option<std::thread::JoinHandle<()>>,
    terminal: bool,
}

impl Iterator for OAuthEventBridge {
    type Item = Result<AuthEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.terminal {
            return None;
        }
        let event = self.receiver.next();
        // The worker normally emits `Cancelled`; synthesize it only when the
        // channel closes first because shutdown won the worker's cancellation
        // race.
        if event.is_none()
            && self
                .cancel
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
        {
            self.terminal = true;
            self.shutdown.cancel();
            return Some(Ok(AuthEvent::Cancelled));
        }
        if event.as_ref().is_some_and(|event| {
            matches!(
                event,
                Ok(AuthEvent::Succeeded { .. })
                    | Ok(AuthEvent::Failed { .. })
                    | Ok(AuthEvent::Cancelled)
            )
        }) {
            self.terminal = true;
        }
        event
    }
}

impl Drop for OAuthEventBridge {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

async fn wait_for_cancellation(cancel: &Option<CancellationToken>) {
    match cancel {
        Some(token) => token.cancelled().await,
        None => std::future::pending::<()>().await,
    }
}

async fn persist_flow_event(
    event: Result<AuthEvent>,
    provider: &OAuthCredentialProvider,
    backend: &BackendId,
    principal: &PrincipalView,
) -> AuthEvent {
    match event {
        Ok(AuthEvent::Succeeded {
            connection,
            credentials: Some(bundle),
        }) => {
            let (access, refresh, expires_at) = match take_oauth_credential(bundle) {
                Ok(parts) => parts,
                Err(error) => return AuthEvent::Failed { error },
            };
            match provider
                .accept_credential(backend, principal, access, refresh, expires_at)
                .await
            {
                Ok(()) => AuthEvent::Succeeded {
                    connection,
                    credentials: None,
                },
                Err(error) => AuthEvent::Failed { error },
            }
        }
        Ok(event) => event,
        Err(error) => AuthEvent::Failed { error },
    }
}

async fn run_flow_bridge(
    flow: ovstorage::OAuthFlow,
    provider: Arc<OAuthCredentialProvider>,
    backend: BackendId,
    principal: PrincipalView,
    cancel: Option<CancellationToken>,
    shutdown: CancellationToken,
    sender: std::sync::mpsc::Sender<Result<AuthEvent>>,
) {
    let deadline = tokio::time::sleep(UPSTREAM_AUTH_FLOW_TIMEOUT);
    tokio::pin!(deadline);
    let mut stream = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return,
        _ = wait_for_cancellation(&cancel) => {
            let _ = sender.send(Ok(AuthEvent::Cancelled));
            return;
        }
        _ = &mut deadline => {
            let _ = sender.send(Ok(AuthEvent::Failed {
                error: Error::new(
                    ErrorCode::DeadlineExceeded,
                    "broker: upstream OAuth flow exceeded its five-minute lifetime",
                ),
            }));
            return;
        }
        result = flow.run() => match result {
            Ok(stream) => stream,
            Err(error) => {
                let _ = sender.send(Ok(AuthEvent::Failed {
                    error: error.into_error(),
                }));
                return;
            }
        },
    };

    loop {
        let event = tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = wait_for_cancellation(&cancel) => {
                let _ = sender.send(Ok(AuthEvent::Cancelled));
                return;
            }
            _ = &mut deadline => {
                let _ = sender.send(Ok(AuthEvent::Failed {
                    error: Error::new(
                        ErrorCode::DeadlineExceeded,
                        "broker: upstream OAuth flow exceeded its five-minute lifetime",
                    ),
                }));
                return;
            }
            event = stream.next() => event,
        };
        let Some(event) = event else {
            return;
        };
        let event = persist_flow_event(event, &provider, &backend, &principal).await;
        let terminal = matches!(
            event,
            AuthEvent::Succeeded { .. } | AuthEvent::Failed { .. } | AuthEvent::Cancelled
        );
        if sender.send(Ok(event)).is_err() || terminal {
            return;
        }
    }
}

fn bridge_flow(
    flow: ovstorage::OAuthFlow,
    provider: Arc<OAuthCredentialProvider>,
    backend: BackendId,
    principal: PrincipalView,
    cancel: Option<CancellationToken>,
) -> Result<AuthEventStream> {
    let permit = UpstreamAuthFlowPermit::acquire()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let shutdown = CancellationToken::new();
    let thread_shutdown = shutdown.clone();
    let bridge_cancel = cancel.clone();
    let join = std::thread::Builder::new()
        .name("ovs-broker-upstream-cred".into())
        .spawn(move || {
            let _permit = permit;
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = sender.send(Ok(AuthEvent::Failed {
                    error: Error::new(
                        ErrorCode::ResourceExhausted,
                        "broker: failed to create upstream OAuth flow runtime",
                    ),
                }));
                return;
            };
            runtime.block_on(run_flow_bridge(
                flow,
                provider,
                backend,
                principal,
                cancel,
                thread_shutdown,
                sender,
            ));
        })
        .map_err(|error| {
            Error::new(
                ErrorCode::ResourceExhausted,
                format!("broker: failed to spawn upstream OAuth flow thread: {error}"),
            )
        })?;
    Ok(Box::new(OAuthEventBridge {
        receiver: receiver.into_iter(),
        cancel: bridge_cancel,
        shutdown,
        join: Some(join),
        terminal: false,
    }))
}

fn accepted_connection(
    key: ovstorage::ConnectionKey,
    address: Url,
    backend: &BackendId,
    expires_at: Option<SystemTime>,
) -> Connection {
    let now = SystemTime::now();
    Connection {
        id: key.id,
        backend_kind: backend.0.clone(),
        display_name: format!("oauth({})", backend.0),
        source: ConnectionSource::Runtime { persisted: false },
        capabilities: Capabilities::empty(),
        current_addresses: vec![address],
        auth_state: ConnectionAuthState::Authenticated {
            last_authenticated_at: now,
            expires_at,
        },
        last_probed: None,
        user_metadata: std::collections::HashMap::new(),
    }
}

#[async_trait]
impl Layer for UpstreamCredentialWrapper {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        descriptor()
    }

    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    async fn stat(
        &self,
        request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let address = request.input.address.clone();
        let inner = Arc::clone(&self.inner);
        self.dispatch_with_oauth_recovery(request, address, cancel, move |request, cancel| {
            let inner = Arc::clone(&inner);
            async move { inner.stat(request, cancel).await }
        })
        .await
    }

    async fn read(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let address = request.input.address.clone();
        let inner = Arc::clone(&self.inner);
        self.dispatch_with_oauth_recovery(request, address, cancel, move |request, cancel| {
            let inner = Arc::clone(&inner);
            async move { inner.read(request, cancel).await }
        })
        .await
    }

    async fn materialize(
        &self,
        request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let address = request.input.address.clone();
        let inner = Arc::clone(&self.inner);
        self.dispatch_with_oauth_recovery(request, address, cancel, move |request, cancel| {
            let inner = Arc::clone(&inner);
            async move { inner.materialize(request, cancel).await }
        })
        .await
    }

    async fn authenticate_connection(
        &self,
        request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        let Some(address) = ext::upstream_auth_address(&request.extensions)? else {
            return self.inner.authenticate_connection(request, cancel).await;
        };
        if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
            return Ok(Box::new(std::iter::once(Ok(AuthEvent::Cancelled))));
        }
        let principal = Self::principal(&request.extensions);
        let provider = match self.resolve_provider(&address) {
            Ok(provider) => provider,
            Err(ProviderResolutionError::Unbound) => {
                return Ok(failed_stream(Error::new(
                    ErrorCode::AuthRequired,
                    format!("broker: no upstream-OAuth provider registered for route {address}"),
                )));
            }
            Err(ProviderResolutionError::UnknownProvider { name }) => {
                return Ok(failed_stream(Error::new(
                    ErrorCode::CredentialUnavailable,
                    format!(
                        "broker: oauth provider '{name}' bound to route {address} is not registered"
                    ),
                )));
            }
        };
        if let Err(error) = self
            .ensure_provider_route_owner(&provider, &address, &request.extensions, &cancel)
            .await
        {
            return Ok(failed_stream(error));
        }
        let backend = BackendId(provider.backend_kind().to_string());
        let flow = match provider.build_flow(backend.clone(), request.input.capability) {
            Ok(flow) => flow,
            Err(error) => return Ok(failed_stream(error)),
        };
        bridge_flow(flow, provider, backend, principal, cancel)
    }

    async fn update_connection_credentials(
        &self,
        request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        let Some(address) = ext::upstream_auth_address(&request.extensions)? else {
            return self
                .inner
                .update_connection_credentials(request, cancel)
                .await;
        };
        bail_if_cancelled(&cancel)?;
        let principal = Self::principal(&request.extensions);
        let provider = match self.resolve_provider(&address) {
            Ok(provider) => provider,
            Err(ProviderResolutionError::Unbound) => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!(
                        "broker: update_connection_credentials has no oauth_provider binding for route {address}"
                    ),
                ));
            }
            Err(ProviderResolutionError::UnknownProvider { name }) => {
                return Err(Error::new(
                    ErrorCode::CredentialUnavailable,
                    format!(
                        "broker: oauth provider '{name}' bound to route {address} is not registered"
                    ),
                ));
            }
        };
        self.ensure_provider_route_owner(&provider, &address, &request.extensions, &cancel)
            .await?;
        let backend = BackendId(provider.backend_kind().to_string());
        let Request { input, .. } = request;
        let (access, refresh, expires_at) = take_oauth_credential(input.credentials)?;
        provider
            .accept_credential(&backend, &principal, access, refresh, expires_at)
            .await?;
        Ok(accepted_connection(
            input.key, address, &backend, expires_at,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use ovstorage::auth::flow::test_support::FakeIdp;
    use ovstorage::auth::{AuthRefreshLock, OAuthStrategy};
    use ovstorage::{
        AddressVisibility, ConfigLayer, ConnectionId, InteractiveAuthCapability, RangeReadStrategy,
        RootInfo, RouteSource, SecretBytes, SecretValue, UserMetadata,
    };

    use super::*;

    static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

    fn test_descriptor() -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "http".into(),
            layer_type: LayerType::Backend,
            display_name: "Recording".into(),
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

    fn connection(id: &str) -> Connection {
        Connection {
            id: ConnectionId(id.into()),
            backend_kind: "http".into(),
            display_name: "recording".into(),
            source: ConnectionSource::Runtime { persisted: false },
            capabilities: Capabilities::empty(),
            current_addresses: Vec::new(),
            auth_state: ConnectionAuthState::Anonymous,
            last_probed: None,
            user_metadata: std::collections::HashMap::new(),
        }
    }

    struct RecordingLayer {
        auth: Mutex<Option<Request<AuthenticateRequest>>>,
        update: Mutex<Option<Request<UpdateConnectionCredentialsRequest>>>,
        materialize: Mutex<Option<Request<ReadRequest>>>,
        root_info_calls: AtomicUsize,
        root_kind: &'static str,
    }

    impl Default for RecordingLayer {
        fn default() -> Self {
            Self {
                auth: Mutex::new(None),
                update: Mutex::new(None),
                materialize: Mutex::new(None),
                root_info_calls: AtomicUsize::new(0),
                root_kind: "http",
            }
        }
    }

    #[async_trait]
    impl Layer for RecordingLayer {
        fn name(&self) -> &str {
            "recording"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            test_descriptor()
        }

        async fn root_info_for(
            &self,
            address: &Url,
            _extensions: &ovstorage::Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<RootInfo> {
            self.root_info_calls.fetch_add(1, Ordering::Relaxed);
            Ok(RootInfo {
                root: address.clone(),
                display_name: None,
                layer_kind: self.root_kind.into(),
                connection_id: Some(ConnectionId("request-id".into())),
                owning_target: Some("broker".into()),
                capabilities: Capabilities::empty(),
                range_read_strategy: RangeReadStrategy::Unsupported,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visible: true,
                visibility: AddressVisibility::Visible,
                alias_state: None,
                icon: None,
                user_metadata: UserMetadata::new(),
            })
        }

        async fn authenticate_connection(
            &self,
            request: Request<AuthenticateRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<AuthEventStream> {
            *self.auth.lock().unwrap() = Some(request);
            Ok(Box::new(std::iter::once(Ok(AuthEvent::Progress {
                message: "delegated".into(),
            }))))
        }

        async fn update_connection_credentials(
            &self,
            request: Request<UpdateConnectionCredentialsRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<Connection> {
            *self.update.lock().unwrap() = Some(request);
            Ok(connection("delegated"))
        }

        async fn materialize(
            &self,
            request: Request<ReadRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<LocalDelegate> {
            let address = request.input.address.clone();
            *self.materialize.lock().unwrap() = Some(request);
            Ok(LocalDelegate {
                path: std::env::temp_dir().join("ovstorage-upstream-materialize-probe"),
                info: ObjectInfo {
                    address,
                    kind: ovstorage::ObjectKind::File,
                    etag: Some("probe-etag".into()),
                    version: None,
                    size: Some(0),
                    mtime: None,
                    checksums: ovstorage::ChecksumSet::default(),
                    effective_permissions: None,
                    system_metadata: None,
                    user_metadata: None,
                    modified_by: None,
                },
                guard: None,
            })
        }
    }

    struct AuthRequiredStatLayer {
        stat_calls: AtomicUsize,
        root_info_calls: AtomicUsize,
    }

    #[async_trait]
    impl Layer for AuthRequiredStatLayer {
        fn name(&self) -> &str {
            "auth-required-stat"
        }

        fn descriptor(&self) -> LayerKindDescriptor {
            LayerKindDescriptor {
                kind: "other-backend".into(),
                ..test_descriptor()
            }
        }

        async fn root_info_for(
            &self,
            address: &Url,
            _extensions: &ovstorage::Extensions,
            _cancel: Option<CancellationToken>,
        ) -> Result<RootInfo> {
            self.root_info_calls.fetch_add(1, Ordering::Relaxed);
            Ok(RootInfo {
                root: address.clone(),
                display_name: None,
                layer_kind: "other-backend".into(),
                connection_id: Some(ConnectionId("other".into())),
                owning_target: Some("other".into()),
                capabilities: Capabilities::empty(),
                range_read_strategy: RangeReadStrategy::Unsupported,
                source: RouteSource::Static {
                    layer: ConfigLayer::Programmatic,
                },
                visible: true,
                visibility: AddressVisibility::Visible,
                alias_state: None,
                icon: None,
                user_metadata: UserMetadata::new(),
            })
        }

        async fn stat(
            &self,
            _request: Request<StatRequest>,
            _cancel: Option<CancellationToken>,
        ) -> Result<ObjectInfo> {
            self.stat_calls.fetch_add(1, Ordering::Relaxed);
            Err(Error::new(
                ErrorCode::AuthRequired,
                "other backend requires its own credential",
            ))
        }
    }

    fn key(id: &str) -> ovstorage::ConnectionKey {
        ovstorage::ConnectionKey {
            target: "broker".into(),
            id: ConnectionId(id.into()),
        }
    }

    fn auth_request(capability: InteractiveAuthCapability) -> Request<AuthenticateRequest> {
        Request::new(AuthenticateRequest {
            key: key("request-id"),
            capability,
            auto_open_browser: false,
        })
    }

    fn update_request(credentials: SecretBundle) -> Request<UpdateConnectionCredentialsRequest> {
        Request::new(UpdateConnectionCredentialsRequest {
            key: key("request-id"),
            credentials,
        })
    }

    fn with_address<T>(mut request: Request<T>, address: &Url) -> Request<T> {
        ext::insert_upstream_auth_address(&mut request.extensions, address);
        request
    }

    fn wrapper(
        inner: LayerHandle,
        providers: OAuthProviderRegistry,
        bindings: BrokerOAuthRouteBindings,
    ) -> UpstreamCredentialWrapper {
        UpstreamCredentialWrapper::new("upstream", inner, Arc::new(providers), bindings)
    }

    #[test]
    fn cancellation_does_not_replace_an_already_received_terminal_event() {
        let (sender, receiver) = std::sync::mpsc::channel();
        sender
            .send(Ok(AuthEvent::Succeeded {
                connection: Box::new(connection("persisted")),
                credentials: None,
            }))
            .unwrap();
        drop(sender);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut bridge = OAuthEventBridge {
            receiver: receiver.into_iter(),
            cancel: Some(cancel),
            shutdown: CancellationToken::new(),
            join: None,
            terminal: false,
        };

        match bridge.next().expect("queued terminal event").unwrap() {
            AuthEvent::Succeeded { connection, .. } => {
                assert_eq!(connection.id, ConnectionId("persisted".into()));
            }
            event => panic!("cancellation replaced the terminal event: {event:?}"),
        }
        assert!(bridge.next().is_none());
    }

    #[test]
    fn upstream_flow_permit_enforces_and_releases_its_limit() {
        static TEST_ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let permit = UpstreamAuthFlowPermit::acquire_from(&TEST_ACTIVE, 1).unwrap();
        let error = UpstreamAuthFlowPermit::acquire_from(&TEST_ACTIVE, 1)
            .err()
            .expect("a second flow must be refused at the limit");
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);

        drop(permit);
        assert!(UpstreamAuthFlowPermit::acquire_from(&TEST_ACTIVE, 1).is_ok());
    }

    #[tokio::test]
    async fn absent_address_delegates_both_slots_verbatim() {
        let inner = Arc::new(RecordingLayer::default());
        let layer = wrapper(
            inner.clone(),
            OAuthProviderRegistry::new(),
            BrokerOAuthRouteBindings::new(),
        );
        let mut auth = auth_request(InteractiveAuthCapability::Browser);
        auth.extensions.insert("example.opaque", vec![0, 1, 255]);
        let expected_auth = auth.clone();
        let mut stream = layer
            .authenticate_connection(auth, None)
            .await
            .expect("delegate authenticate");
        assert!(matches!(
            stream.next().expect("delegated event").expect("ok event"),
            AuthEvent::Progress { ref message } if message == "delegated"
        ));
        assert_eq!(*inner.auth.lock().unwrap(), Some(expected_auth));

        let mut update = update_request(SecretBundle::default());
        update.extensions.insert("example.opaque", vec![3, 2, 1]);
        let expected_update = update.clone();
        let returned = layer
            .update_connection_credentials(update, None)
            .await
            .expect("delegate update");
        assert_eq!(returned, connection("delegated"));
        assert_eq!(*inner.update.lock().unwrap(), Some(expected_update));
    }

    #[tokio::test]
    async fn unbound_route_has_auth_required_stream_and_unsupported_update() {
        let address = Url::parse("nucleus://prod/object").unwrap();
        let layer = wrapper(
            Arc::new(RecordingLayer::default()),
            OAuthProviderRegistry::new(),
            BrokerOAuthRouteBindings::new(),
        );
        let mut stream = layer
            .authenticate_connection(
                with_address(auth_request(InteractiveAuthCapability::Browser), &address),
                None,
            )
            .await
            .unwrap();
        match stream.next().expect("terminal event").unwrap() {
            AuthEvent::Failed { error } => {
                assert_eq!(error.code(), ErrorCode::AuthRequired);
                assert!(error.message().contains(address.as_str()));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(stream.next().is_none());

        let error = layer
            .update_connection_credentials(
                with_address(update_request(SecretBundle::default()), &address),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn bound_unknown_provider_names_provider_and_is_unavailable() {
        let address = Url::parse("nucleus://prod/object").unwrap();
        let bindings = BrokerOAuthRouteBindings::new()
            .with_route(Url::parse("nucleus://prod/").unwrap(), "ghost-provider");
        let layer = wrapper(
            Arc::new(RecordingLayer::default()),
            OAuthProviderRegistry::new(),
            bindings,
        );
        let mut stream = layer
            .authenticate_connection(
                with_address(auth_request(InteractiveAuthCapability::Browser), &address),
                None,
            )
            .await
            .unwrap();
        match stream.next().expect("terminal event").unwrap() {
            AuthEvent::Failed { error } => {
                assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
                assert!(error.message().contains("ghost-provider"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }

        let error = layer
            .update_connection_credentials(
                with_address(update_request(SecretBundle::default()), &address),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::CredentialUnavailable);
        assert!(error.message().contains("ghost-provider"));
    }

    #[tokio::test]
    async fn data_boundary_clears_inbound_credential_reference_when_unbound_or_cold() {
        let state_root = temp_state_root();
        std::fs::create_dir_all(&state_root).unwrap();
        let provider = Arc::new(OAuthCredentialProvider::new(
            "upstream-idp",
            "http",
            ovstorage::auth::OAuthEndpoints {
                authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                client_id: "test".into(),
                scope: None,
            },
            sqlite_store(&state_root),
            Arc::new(AuthRefreshLock::open(&state_root).unwrap()),
            OAuthStrategy::Device,
        ));
        let layer = wrapper(
            Arc::new(RecordingLayer::default()),
            OAuthProviderRegistry::new().with_provider("upstream-idp", provider),
            BrokerOAuthRouteBindings::new().with_route(
                Url::parse("https://bound.example/").unwrap(),
                "upstream-idp",
            ),
        );

        for address in [
            Url::parse("https://unbound.example/object").unwrap(),
            Url::parse("https://bound.example/cold-object").unwrap(),
        ] {
            let mut extensions = ovstorage::Extensions::new();
            extensions.insert(ext::PRINCIPAL_ID, b"alice".to_vec());
            ext::insert_resolved_oauth_credential(
                &mut extensions,
                &ext::ResolvedOAuthCredentialRef {
                    backend_kind: "http".into(),
                    keyring_handle: "caller-selected-handle".into(),
                },
            )
            .unwrap();

            layer
                .stamp_resolved_oauth_credential(&address, &mut extensions, &None)
                .await
                .unwrap();

            assert!(
                extensions.get(ext::RESOLVED_OAUTH_CREDENTIAL).is_none(),
                "an unbound or cold request must not forward an inbound reference"
            );
        }
        let _ = std::fs::remove_dir_all(state_root);
    }

    fn temp_state_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ovstorage-upstream-credential-{}-{}",
            std::process::id(),
            TEMP_SERIAL.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn sqlite_store(state_root: &std::path::Path) -> Arc<dyn ovstorage::auth::SecretStore> {
        Arc::new(ovstorage::auth::SqliteSecretStore::open(state_root).expect("open sqlite store"))
    }

    fn oauth_bundle(access: &[u8], refresh: &[u8]) -> SecretBundle {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "oauth".into(),
            SecretValue::OAuthToken {
                token: SecretBytes(access.to_vec()),
                refresh: Some(SecretBytes(refresh.to_vec())),
                expires_at: Some(SystemTime::now() + Duration::from_secs(3_600)),
            },
        );
        bundle
    }

    async fn simulate_pkce_callback(open_browser_url: &str) {
        let parsed = Url::parse(open_browser_url).expect("OpenBrowser URL parses");
        let mut redirect_uri = String::new();
        let mut state = String::new();
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "redirect_uri" => redirect_uri = value.into_owned(),
                "state" => state = value.into_owned(),
                _ => {}
            }
        }
        reqwest::get(format!("{redirect_uri}?code=fake-code&state={state}"))
            .await
            .expect("callback reaches loopback listener");
    }

    #[tokio::test]
    async fn programmatic_provider_requires_a_registered_matching_read_route_owner() {
        let address = Url::parse("https://prod.example/object").unwrap();
        for (provider_kind, route_kind, register, expected) in [
            (
                "gcs",
                "gcs",
                false,
                Some("no registered production read-side consumer"),
            ),
            ("http", "test", false, Some("owned by backend kind 'test'")),
            ("gcs", "gcs", true, None),
        ] {
            let state_root = temp_state_root();
            std::fs::create_dir_all(&state_root).unwrap();
            let provider = Arc::new(OAuthCredentialProvider::new(
                "upstream-idp",
                provider_kind,
                ovstorage::auth::OAuthEndpoints {
                    authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                    token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                    client_id: "test".into(),
                    scope: None,
                },
                sqlite_store(&state_root),
                Arc::new(AuthRefreshLock::open(&state_root).unwrap()),
                OAuthStrategy::Device,
            ));
            let inner = Arc::new(RecordingLayer {
                root_kind: route_kind,
                ..RecordingLayer::default()
            });
            let mut providers =
                OAuthProviderRegistry::new().with_provider("upstream-idp", provider.clone());
            if register {
                providers = providers.with_consumer_capability(
                    provider_kind,
                    UpstreamOAuthConsumerCapability::ReadSide,
                );
            }
            let layer = wrapper(
                inner,
                providers,
                BrokerOAuthRouteBindings::new()
                    .with_route(Url::parse("https://prod.example/").unwrap(), "upstream-idp"),
            );

            let result = layer
                .ensure_provider_route_owner(
                    &provider,
                    &address,
                    &ovstorage::Extensions::new(),
                    &None,
                )
                .await;
            match expected {
                Some(expected) => {
                    let error = result.expect_err("consumer validation must fail closed");
                    assert_eq!(error.code(), ErrorCode::Unsupported);
                    assert!(error.message().contains(expected), "{error:?}");
                }
                None => result.expect("a registered matching consumer must be accepted"),
            }
            let _ = std::fs::remove_dir_all(state_root);
        }
    }

    #[tokio::test]
    async fn materialize_stamps_a_warm_principal_credential_for_the_inner_layer() {
        let state_root = temp_state_root();
        std::fs::create_dir_all(&state_root).unwrap();
        let provider = Arc::new(OAuthCredentialProvider::new(
            "upstream-idp",
            "http",
            ovstorage::auth::OAuthEndpoints {
                authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                client_id: "test".into(),
                scope: None,
            },
            sqlite_store(&state_root),
            Arc::new(AuthRefreshLock::open(&state_root).unwrap()),
            OAuthStrategy::Device,
        ));
        let principal = PrincipalView::new("materialize-alice");
        provider
            .accept_credential(
                &BackendId("http".into()),
                &principal,
                b"materialize-access".to_vec(),
                None,
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .unwrap();
        let inner = Arc::new(RecordingLayer::default());
        let layer = wrapper(
            inner.clone(),
            OAuthProviderRegistry::new().with_provider("upstream-idp", provider),
            BrokerOAuthRouteBindings::new()
                .with_route(Url::parse("https://prod.example/").unwrap(), "upstream-idp"),
        );
        let address = Url::parse("https://prod.example/object").unwrap();
        let mut request = Request::new(ReadRequest {
            address: address.clone(),
            options: ovstorage::ReadOptions::default(),
        });
        request
            .extensions
            .insert(ext::PRINCIPAL_ID, principal.id.as_bytes().to_vec());

        let local = layer.materialize(request, None).await.unwrap();
        assert_eq!(local.info.address, address);
        assert_eq!(
            inner.root_info_calls.load(Ordering::Relaxed),
            0,
            "credential stamping must not duplicate the normal data-path route resolution"
        );
        let mut delegated = inner
            .materialize
            .lock()
            .unwrap()
            .take()
            .expect("inner materialize receives the request");
        assert_eq!(
            ext::take_resolved_oauth_credential(&mut delegated.extensions).unwrap(),
            Some(ext::ResolvedOAuthCredentialRef {
                backend_kind: "http".into(),
                keyring_handle: "oauth/upstream-idp".into(),
            })
        );
        assert_eq!(
            delegated.extensions.get(ext::PRINCIPAL_ID),
            Some(principal.id.as_bytes())
        );

        let _ = std::fs::remove_dir_all(state_root);
    }

    #[tokio::test]
    async fn mismatched_route_auth_required_does_not_invalidate_provider_credential() {
        let state_root = temp_state_root();
        std::fs::create_dir_all(&state_root).unwrap();
        let refresh_lock = Arc::new(AuthRefreshLock::open(&state_root).unwrap());
        let secret_store = sqlite_store(&state_root);
        let provider = Arc::new(OAuthCredentialProvider::new(
            "upstream-idp",
            "http",
            ovstorage::auth::OAuthEndpoints {
                authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                client_id: "test".into(),
                scope: None,
            },
            Arc::clone(&secret_store),
            Arc::clone(&refresh_lock),
            OAuthStrategy::Device,
        ));
        let backend = BackendId("http".into());
        let principal = PrincipalView::new("mismatched-route-alice");
        provider
            .accept_credential(
                &backend,
                &principal,
                b"still-valid-access".to_vec(),
                None,
                Some(SystemTime::now() + Duration::from_secs(3_600)),
            )
            .await
            .unwrap();
        let before = refresh_lock
            .load_secret_token(&backend.0, &principal.id)
            .unwrap()
            .expect("credential metadata is persisted");
        let inner = Arc::new(AuthRequiredStatLayer {
            stat_calls: AtomicUsize::new(0),
            root_info_calls: AtomicUsize::new(0),
        });
        let layer = wrapper(
            inner.clone(),
            OAuthProviderRegistry::new().with_provider("upstream-idp", provider),
            BrokerOAuthRouteBindings::new().with_route(
                Url::parse("https://mismatched.example/").unwrap(),
                "upstream-idp",
            ),
        );
        let address = Url::parse("https://mismatched.example/object").unwrap();
        let mut request = Request::new(StatRequest {
            address,
            options: ovstorage::StatOptions::default(),
        });
        request
            .extensions
            .insert(ext::PRINCIPAL_ID, principal.id.as_bytes().to_vec());

        let error = layer.stat(request, None).await.unwrap_err();

        // The mismatched route owner declines recovery, but the caller must
        // still see the backend's own error: `AuthRequired` is the signal a
        // client keys on to authenticate, and the broker's configuration
        // detail stays off the data path.
        assert_eq!(error.code(), ErrorCode::AuthRequired);
        assert!(
            error
                .message()
                .contains("other backend requires its own credential")
        );
        assert!(
            !error.message().contains("owned by backend kind"),
            "the route-owner diagnosis must not replace the backend error"
        );
        assert_eq!(inner.stat_calls.load(Ordering::Relaxed), 1);
        assert_eq!(inner.root_info_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            refresh_lock
                .load_secret_token(&backend.0, &principal.id)
                .unwrap(),
            Some(before.clone()),
            "a rejection from an unrelated route owner must not mutate metadata"
        );
        assert_eq!(
            secret_store
                .get(&backend.0, &principal.id, &before.secret_handle)
                .unwrap()
                .expect("valid access token remains installed")
                .as_bytes(),
            b"still-valid-access"
        );

        let _ = std::fs::remove_dir_all(state_root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn registered_provider_uses_backend_kind_and_stamped_principal() {
        let idp = FakeIdp::start_with_token("stream-access-secret").await;
        let state_root = temp_state_root();
        std::fs::create_dir_all(&state_root).unwrap();
        let refresh_lock = Arc::new(AuthRefreshLock::open(&state_root).unwrap());
        let secret_store = sqlite_store(&state_root);
        let provider = Arc::new(OAuthCredentialProvider::new(
            "upstream-idp",
            "http",
            idp.endpoints(false),
            secret_store,
            refresh_lock.clone(),
            OAuthStrategy::Pkce {
                redirect_base: Url::parse("http://127.0.0.1").unwrap(),
            },
        ));
        let layer = wrapper(
            Arc::new(RecordingLayer::default()),
            OAuthProviderRegistry::new().with_provider("upstream-idp", provider.clone()),
            BrokerOAuthRouteBindings::new()
                .with_route(Url::parse("https://prod.example/").unwrap(), "upstream-idp"),
        );
        let address = Url::parse("https://prod.example/object").unwrap();

        let mut none_stream = layer
            .authenticate_connection(
                with_address(auth_request(InteractiveAuthCapability::None), &address),
                None,
            )
            .await
            .unwrap();
        let none_events = none_stream.by_ref().collect::<Vec<_>>();
        assert_eq!(none_events.len(), 1);
        assert!(matches!(
            &none_events[0],
            Ok(AuthEvent::Failed { error }) if error.code() == ErrorCode::AuthRequired
        ));
        assert!(!none_events.iter().any(|event| matches!(
            event,
            Ok(AuthEvent::OpenBrowser { .. } | AuthEvent::DeviceCode { .. })
        )));

        let cancel = CancellationToken::new();
        let mut cancelled_request =
            with_address(auth_request(InteractiveAuthCapability::Browser), &address);
        cancelled_request
            .extensions
            .insert(ext::PRINCIPAL_ID, b"cancelled-user".to_vec());
        let mut cancelled_stream = layer
            .authenticate_connection(cancelled_request, Some(cancel.clone()))
            .await
            .unwrap();
        assert!(matches!(
            cancelled_stream.next().unwrap().unwrap(),
            AuthEvent::OpenBrowser { .. }
        ));
        cancel.cancel();
        let tail = cancelled_stream.collect::<Vec<_>>();
        let (last, preceding) = tail
            .split_last()
            .expect("cancellation emits a terminal event");
        assert!(matches!(last, Ok(AuthEvent::Cancelled)));
        assert!(
            preceding
                .iter()
                .all(|event| matches!(event, Ok(AuthEvent::Progress { .. }))),
            "an already-received progress event may precede cancellation: {tail:?}"
        );

        let mut auth = with_address(auth_request(InteractiveAuthCapability::Browser), &address);
        auth.extensions
            .insert(ext::PRINCIPAL_ID, b"stamped-alice".to_vec());
        let mut stream = layer.authenticate_connection(auth, None).await.unwrap();
        let browser_url = match stream.next().expect("first event").unwrap() {
            AuthEvent::OpenBrowser { url, .. } => url,
            other => panic!("expected OpenBrowser, got {other:?}"),
        };
        simulate_pkce_callback(&browser_url).await;
        let mut saw_success = false;
        for event in stream {
            match event.unwrap() {
                AuthEvent::Succeeded {
                    connection,
                    credentials,
                } => {
                    assert_eq!(connection.backend_kind, "http");
                    assert!(credentials.is_none(), "credential bytes must be stripped");
                    saw_success = true;
                }
                AuthEvent::Failed { error } => panic!("OAuth flow failed: {error:?}"),
                _ => {}
            }
        }
        assert!(saw_success);
        assert!(
            refresh_lock
                .load_secret_token("http", "stamped-alice")
                .unwrap()
                .is_some()
        );
        assert!(
            refresh_lock
                .load_secret_token("https", "stamped-alice")
                .unwrap()
                .is_none(),
            "the URL scheme must not select the provider credential slot"
        );
        assert!(
            refresh_lock
                .load_secret_token("http", "request-id")
                .unwrap()
                .is_none()
        );
        let resolved = ovstorage::auth::CredentialProvider::resolve(
            provider.as_ref(),
            &BackendId("http".into()),
            &PrincipalView::new("stamped-alice"),
        )
        .await
        .expect("the provider must resolve from its backend-kind slot");
        match resolved.bytes.fields.get("oauth") {
            Some(SecretValue::OAuthToken { token, .. }) => {
                assert_eq!(token.as_bytes(), b"stream-access-secret")
            }
            other => panic!("expected the persisted OAuth token, got {other:?}"),
        }

        let mut update = with_address(
            update_request(oauth_bundle(
                b"update-access-secret",
                b"update-refresh-secret",
            )),
            &address,
        );
        update
            .extensions
            .insert(ext::PRINCIPAL_ID, b"stamped-bob".to_vec());
        let returned = layer
            .update_connection_credentials(update, None)
            .await
            .expect("provider accepts proactive credential");
        assert_eq!(returned.id, ConnectionId("request-id".into()));
        assert_eq!(returned.backend_kind, "http");
        assert_eq!(returned.display_name, "oauth(http)");
        assert_eq!(returned.current_addresses, vec![address]);
        assert!(
            refresh_lock
                .load_secret_token("http", "stamped-bob")
                .unwrap()
                .is_some()
        );
        assert!(
            refresh_lock
                .load_secret_token("https", "stamped-bob")
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(state_root);
    }

    #[tokio::test]
    async fn registered_provider_uses_anonymous_when_principal_stamp_is_absent() {
        let state_root = temp_state_root();
        std::fs::create_dir_all(&state_root).unwrap();
        let refresh_lock = Arc::new(AuthRefreshLock::open(&state_root).unwrap());
        let provider = Arc::new(OAuthCredentialProvider::new(
            "upstream-idp",
            "http",
            ovstorage::auth::OAuthEndpoints {
                authorization_endpoint: Url::parse("https://idp.example/authorize").unwrap(),
                token_endpoint: Url::parse("https://idp.example/token").unwrap(),
                client_id: "test".into(),
                scope: None,
            },
            sqlite_store(&state_root),
            refresh_lock.clone(),
            OAuthStrategy::Device,
        ));
        let layer = wrapper(
            Arc::new(RecordingLayer::default()),
            OAuthProviderRegistry::new().with_provider("upstream-idp", provider),
            BrokerOAuthRouteBindings::new()
                .with_route(Url::parse("https://prod.example/").unwrap(), "upstream-idp"),
        );
        let address = Url::parse("https://prod.example/object").unwrap();
        layer
            .update_connection_credentials(
                with_address(
                    update_request(oauth_bundle(b"anonymous-access", b"anonymous-refresh")),
                    &address,
                ),
                None,
            )
            .await
            .unwrap();
        assert!(
            refresh_lock
                .load_secret_token("http", "anonymous")
                .unwrap()
                .is_some()
        );
        let _ = std::fs::remove_dir_all(state_root);
    }
}
