// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authorization as an ordinary storage [`Layer`]. This crate
//! hosts the [`BuiltinAuthLayer`] — the combined **authn + authz** layer (`kind
//! = "builtin-auth"`) — over the moved [`Policy`] engine. It reads the caller's
//! [`ext::AUTH_CREDENTIAL`], resolves a principal (signed JWT, trusted-proxy,
//! or mTLS authn for `Tcp`; OS peer-credential / dev current-user authn for
//! `Uds`/`NamedPipe`),
//! evaluates the *fresh* policy, and on allow stamps [`ext::PRINCIPAL_ID`] DOWN
//! to `inner`. It gates data verbs, the two per-principal introspection slots
//! (`list_address_roots` / `list_connections`), and the two slots that establish
//! credentials on a connection (`authenticate_connection` /
//! `update_connection_credentials`). The remaining management slots are
//! config-time/ungated and auto-delegate through the [`Layer::inner_layer`]
//! default. The per-verb gate catalog is documented on [`BuiltinAuthLayer`].
//!
//! **No decision caching** — the check runs on every request, so a host policy
//! reload (an atomic [`ArcSwap`] swap) drops a revoked principal on their next
//! request even with a hot cache composed below.
//!
//! ## Composition
//!
//! Modeled on the `copy_rename_fallback` wrapper template: [`Layer::inner_layer`] returns
//! the wrapped handle, and only the gated verbs carry bespoke bodies. The host
//! composes it outermost, above the caches, so authz-before-cache is structural.
//! Because `Stack` canonicalizes addresses before the root, a top-of-stack auth
//! Layer authorizes the canonical address — the same spelling the host
//! authorized incoming, before any alias rewrite (which happens on a layer
//! below).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use futures::StreamExt as _;
use ovstorage::wrappers::ext;
use ovstorage::{
    AccessDecision, AuthEventStream, AuthenticateRequest, BackendItemInfo, CancellationToken,
    ChangeEvent, ChangeStream, CheckAccessRequest, ConfigValue, Connection, ConnectionKey,
    ConnectionSnapshot, ConnectionUpdateStream, ContinueWriteRequest, CopyRequest,
    CreateDirectoryRequest, DeleteDirectoryRequest, DeleteRequest, Error, ErrorCode, Extensions,
    Layer, LayerConfig, LayerConnectionRequest, LayerHandle, LayerKindDescriptor, LayerType,
    ListPage, ListRequest, ListVersionsRequest, LoadedLayerFactory, LocalDelegate, ObjectInfo,
    ReadRequest, ReadResult, RenameRequest, Request, Result, RootInfo, RootInfoChange,
    RootInfoSnapshot, RootInfoUpdateStream, Stack, StatRequest, UpdateConnectionAttributesRequest,
    UpdateConnectionCredentialsRequest, UpdateMetadataRequest, Url, VersionPage,
    WatchDirectoryRequest, WrapperFactory, WriteRedirectBatch, WriteRequest, WriteResult,
    WriteStep, canonicalize,
};
use ovstorage_authz_context::{
    ANONYMOUS_PRINCIPAL_ID, AuthCredential, ForwardedHeaders, Transport,
};
use ovstorage_authz_policy::{
    Operation, Policy, apply_authz_access_decision, filter_list_batch, is_root_visible,
    operation_name,
};

mod authn;

use authn::jwt::{JwtConfig, UnsignedJwtClaimChecks, resolve_jwt, resolve_unsigned_jwt};
use authn::peer::{PeerConfig, resolve_peer};
use sha2::{Digest, Sha256};

/// [`LayerConfig`] key the factory reads for the policy rule set (a TOML
/// document, the same shape the first-party plugin read). The concrete
/// `[ovstorage.layers.authz.*]` schema belongs to the stack config; this wires
/// the rules through.
pub const POLICY_CONFIG_KEY: &str = "policy";

/// Build the policy rule set from layer config: the [`POLICY_CONFIG_KEY`] TOML
/// document, or an empty (deny-all) policy when absent.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the `policy` config has the wrong type
///   (must be a TOML string).
fn policy_from_config(config: &LayerConfig) -> Result<Policy> {
    match config.get(POLICY_CONFIG_KEY) {
        Some(ConfigValue::Toml(toml)) | Some(ConfigValue::String(toml)) => Policy::from_toml(toml),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("authz layer `{POLICY_CONFIG_KEY}` config must be a TOML string"),
        )),
        None => Policy::from_config(Default::default()),
    }
}

// ===========================================================================
// Built-in combined auth layer
// ===========================================================================

/// Layer kind string for the built-in combined auth layer (authn front-end +
/// policy authz). Referenced by core composers by string only — core never
/// names this type.
pub const BUILTIN_AUTH_KIND: &str = "builtin-auth";

/// Counter of auth-layer decisions, labelled `outcome` = `allow` | `deny` |
/// `error`. Emitted via the `metrics` API from `BuiltinAuthLayer::authorize`
/// so any host with a recorder installed (e.g. the broker's OTel bridge)
/// captures allow/deny observability the pre-N6 `PermissionCheckLayer` lost.
pub const AUTH_DECISIONS: &str = "ovstorage_auth_decisions_total";

/// Layer name of the per-listener built-in auth layer composed over the shared
/// inner. Both network hosts use it so the composed topology names the same
/// layer in logs, metrics, and errors.
pub const AUTH_LAYER_NAME: &str = "auth";

/// OIDC bearer-JWT parameters shared by listener hosts. The broker and REST
/// retain source-compatible public aliases while using this single definition.
#[derive(Clone, Debug)]
pub struct JwtParams {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
}

impl JwtParams {
    /// Project the triplet onto the three `jwt_*` [`LayerConfig`] keys the
    /// built-in auth layer reads. The single home for that mapping: a host
    /// writing the keys by hand can drift from `jwt_params_from_config`'s
    /// all-three-or-none contract.
    pub fn apply_to(&self, config: &mut LayerConfig) {
        config.insert(
            JWT_ISSUER_CONFIG_KEY.to_string(),
            ConfigValue::String(self.issuer.clone()),
        );
        config.insert(
            JWT_AUDIENCE_CONFIG_KEY.to_string(),
            ConfigValue::String(self.audience.clone()),
        );
        config.insert(
            JWT_JWKS_URL_CONFIG_KEY.to_string(),
            ConfigValue::String(self.jwks_url.clone()),
        );
    }
}

/// Stamp transport-gathered credential material onto a fresh extension bag.
/// Client-supplied extensions are deliberately never merged at this boundary.
pub fn stamp_credential(credential: Option<&AuthCredential>) -> Extensions {
    let mut extensions = Extensions::new();
    if let Some(credential) = credential {
        extensions.insert(ext::AUTH_CREDENTIAL.to_string(), credential.encode());
    }
    extensions
}

/// Write-admission contract exposed by one listener's authentication Layer.
///
/// Built-in auth offers a typed host preflight that can reject a write before
/// the host constructs its body. Plugin auth uses the ordinary Layer ABI, so
/// the authoritative write must enter the Stack with a pull-driven body that
/// remains unread until the auth wrapper delegates it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenerWriteAdmission {
    /// The host may call [`ListenerAuth::authorize_write_preflight`] before it
    /// drains or buffers the request body.
    HostPreflight,
    /// The host must dispatch a pull-driven body through the auth Stack.
    InStackLazyBody,
}

/// Opaque host handle for one listener's authentication Layer.
///
/// Backend-kind discovery is an unusual host endpoint: its response is
/// captured before listener auth composition, so it does not naturally flow
/// through the auth Stack. Callers must invoke
/// [`ListenerAuth::authorize_list_backend_kinds`] before returning that
/// response. The plugin variant invokes its Layer's [`Layer::list_kinds`] slot,
/// giving the plugin Layer the opportunity to deny.
#[derive(Clone)]
pub struct ListenerAuth {
    inner: ListenerAuthInner,
}

#[derive(Clone)]
enum ListenerAuthInner {
    Builtin(Arc<BuiltinAuthLayer>),
    Plugin { kind: String, layer: LayerHandle },
}

impl ListenerAuth {
    fn builtin(layer: Arc<BuiltinAuthLayer>) -> Self {
        Self {
            inner: ListenerAuthInner::Builtin(layer),
        }
    }

    fn plugin(kind: String, layer: LayerHandle) -> Self {
        Self {
            inner: ListenerAuthInner::Plugin { kind, layer },
        }
    }

    /// Selected listener-auth kind.
    pub fn kind(&self) -> &str {
        match &self.inner {
            ListenerAuthInner::Builtin(_) => BUILTIN_AUTH_KIND,
            ListenerAuthInner::Plugin { kind, .. } => kind,
        }
    }

    /// Describe how the host must admit write request bodies.
    pub fn write_admission(&self) -> ListenerWriteAdmission {
        match &self.inner {
            ListenerAuthInner::Builtin(_) => ListenerWriteAdmission::HostPreflight,
            ListenerAuthInner::Plugin { .. } => ListenerWriteAdmission::InStackLazyBody,
        }
    }

    /// Reload the built-in policy without rebuilding the Layer.
    ///
    /// Plugin auth Layers are immutable after construction and are refreshed
    /// when the production SIGHUP path rebuilds the host.
    ///
    /// # Errors
    ///
    /// - The errors returned by [`BuiltinAuthLayer::reload`] for built-in auth.
    /// - [`ErrorCode::Unsupported`] for plugin auth Layers.
    pub fn reload_policy(&self, policy_toml: &str) -> Result<()> {
        match &self.inner {
            ListenerAuthInner::Builtin(layer) => layer.reload(policy_toml),
            ListenerAuthInner::Plugin { kind, .. } => Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "plugin listener auth kind `{kind}` has no policy hot-reload; production SIGHUP rebuilds the host"
                ),
            )),
        }
    }

    /// Authorize the host's captured backend-kind discovery response.
    ///
    /// Built-in auth uses its typed policy gate. Plugin auth dispatches the
    /// retained Layer's `list_kinds` slot solely for its authorization side
    /// effect; the host continues returning its separately captured
    /// backend-kind set.
    ///
    /// # Errors
    ///
    /// Propagates the selected auth Layer's authorization or bridge error.
    pub fn authorize_list_backend_kinds(&self, cx: &Extensions) -> Result<()> {
        match &self.inner {
            ListenerAuthInner::Builtin(layer) => layer.authorize_list_backend_kinds(cx),
            ListenerAuthInner::Plugin { layer, .. } => layer.list_kinds(cx).map(drop),
        }
    }

    /// Run the write preflight when this auth implementation supports one.
    ///
    /// Hosts inspect [`ListenerAuth::write_admission`] before calling this
    /// method. Plugin auth returns [`ErrorCode::Unsupported`] so an accidental
    /// eager-body path fails closed instead of bypassing the in-Stack gate.
    pub fn authorize_write_preflight(&self, cx: &Extensions, address: &Url) -> Result<()> {
        match &self.inner {
            ListenerAuthInner::Builtin(layer) => layer.authorize_write_preflight(cx, address),
            ListenerAuthInner::Plugin { kind, .. } => Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "plugin listener auth kind `{kind}` requires lazy in-stack write admission"
                ),
            )),
        }
    }
}

/// The shared result of composing one listener's auth layer over an auth-free
/// inner stack.
///
/// The default handle type preserves the original built-in-only API. The
/// factory-aware composition route widens it to [`ListenerAuth`].
pub struct ListenerAuthStack<A = Arc<BuiltinAuthLayer>> {
    pub stack: Arc<Stack>,
    pub auth_layer: A,
}

/// Host-owned boundary immediately below a plugin listener-auth wrapper.
///
/// The plugin receives the raw listener credential so it can authenticate the
/// caller. Every delegation below the plugin crosses this layer, which removes
/// the credential before the request can reach routers, caches, or backend
/// plugins, and — on the data and introspection path — enforces the
/// documented auth-wrapper contract: a delegation must carry a non-empty
/// UTF-8 [`ext::PRINCIPAL_ID`] stamped DOWN — the copy routing, cache
/// scoping, and attribution read. A delegation without the stamp fails
/// closed with [`ErrorCode::Internal`] before it reaches inner. The
/// connection-management slots are the exception: they are config-time and
/// ungated by this crate's contract (under `builtin-auth` they auto-delegate
/// through the [`Layer::inner_layer`] default), so this boundary strips the
/// credential on them but does not require the stamp. Keeping the removal
/// and the conformance check on the host side makes credential confinement
/// and principal conformance independent of the plugin wrapper's
/// implementation.
struct PluginCredentialBoundary {
    kind: String,
    inner: LayerHandle,
}

impl PluginCredentialBoundary {
    /// Enforce the DOWN-stamp contract on one delegation: the plugin wrapper
    /// must have stamped a present, valid-UTF-8, non-empty
    /// [`ext::PRINCIPAL_ID`] before delegating below the boundary.
    fn enforce_principal_stamp(&self, cx: &Extensions) -> Result<()> {
        let principal = cx.get(ext::PRINCIPAL_ID).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "plugin listener auth kind `{}` delegated without stamping a principal",
                    self.kind
                ),
            )
        })?;
        let principal = std::str::from_utf8(principal).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "plugin listener auth kind `{}` delegated a non-UTF-8 principal stamp",
                    self.kind
                ),
            )
        })?;
        if principal.is_empty() {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "plugin listener auth kind `{}` delegated an empty principal stamp",
                    self.kind
                ),
            ));
        }
        Ok(())
    }

    fn strip(&self, cx: &Extensions) -> Result<Extensions> {
        self.enforce_principal_stamp(cx)?;
        let mut cx = cx.clone();
        cx.remove(ext::AUTH_CREDENTIAL);
        Ok(cx)
    }

    fn strip_request<T>(&self, mut request: Request<T>) -> Result<Request<T>> {
        self.enforce_principal_stamp(&request.extensions)?;
        request.extensions.remove(ext::AUTH_CREDENTIAL);
        Ok(request)
    }

    /// Strip without the stamp check, for the connection-management slots.
    ///
    /// Management is config-time and ungated by this crate's contract:
    /// `BuiltinAuthLayer` auto-delegates these slots through the
    /// [`Layer::inner_layer`] default without stamping a principal, so
    /// requiring a stamp here would make the two auth kinds diverge on
    /// behavior that has nothing to do with auth — a wrapper that only stamps
    /// the data path would lose connection re-crediting and the interactive
    /// backend auth flow. Credential confinement is not conditional, though:
    /// the raw listener credential is still removed before the delegation
    /// crosses below the boundary.
    fn strip_request_ungated<T>(&self, mut request: Request<T>) -> Request<T> {
        request.extensions.remove(ext::AUTH_CREDENTIAL);
        request
    }
}

macro_rules! impl_plugin_credential_boundary {
    (gated: [$(($method:ident, $request:ty, $output:ty)),* $(,)?],
     management: [$(($m_method:ident, $m_request:ty, $m_output:ty)),* $(,)?]) => {
        #[async_trait]
        impl Layer for PluginCredentialBoundary {
            fn name(&self) -> &str {
                self.inner.name()
            }

            fn descriptor(&self) -> LayerKindDescriptor {
                self.inner.descriptor()
            }

            fn owned_targets(&self) -> Vec<String> {
                self.inner.owned_targets()
            }

            async fn root_info_for(
                &self,
                url: &Url,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Result<RootInfo> {
                self.inner
                    .root_info_for(url, &self.strip(cx)?, cancel)
                    .await
            }

            async fn owning_target_for(
                &self,
                url: &Url,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Option<String> {
                // This host-side topology helper has no error channel; a
                // delegation violating the boundary contract fails closed by
                // owning no target.
                let cx = self.strip(cx).ok()?;
                self.inner.owning_target_for(url, &cx, cancel).await
            }

            fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>> {
                self.inner.list_kinds(&self.strip(cx)?)
            }

            async fn list_address_roots(
                &self,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
                self.inner
                    .list_address_roots(&self.strip(cx)?, cancel)
                    .await
            }

            async fn list_connections(
                &self,
                cx: &Extensions,
                cancel: Option<CancellationToken>,
            ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
                self.inner.list_connections(&self.strip(cx)?, cancel).await
            }

            $(
                async fn $method(
                    &self,
                    request: Request<$request>,
                    cancel: Option<CancellationToken>,
                ) -> Result<$output> {
                    self.inner
                        .$method(self.strip_request(request)?, cancel)
                        .await
                }
            )*

            // Connection management: strip-only, ungated. See
            // `strip_request_ungated` for why these slots skip the stamp
            // check that gates the data path.
            $(
                async fn $m_method(
                    &self,
                    request: Request<$m_request>,
                    cancel: Option<CancellationToken>,
                ) -> Result<$m_output> {
                    self.inner
                        .$m_method(self.strip_request_ungated(request), cancel)
                        .await
                }
            )*
        }
    };
}

impl_plugin_credential_boundary!(
    gated: [
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
    ],
    management: [
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
    ]
);

async fn compose_builtin_listener_auth_stack(
    name: &str,
    config: &LayerConfig,
    inner: LayerHandle,
    cancel: Option<CancellationToken>,
) -> Result<ListenerAuthStack> {
    let auth_layer = BuiltinAuthLayerFactory::build_layer(name, config, inner).await?;
    let stack = Stack::builder(name)
        .attach(name, auth_layer.clone())
        .build_with_cancel(cancel)
        .await?;
    Ok(ListenerAuthStack {
        stack: Arc::new(stack),
        auth_layer,
    })
}

/// Build the concrete built-in auth layer and attach it as a thin Stack root.
/// Both network hosts use this path so their listener-auth topology cannot
/// silently diverge.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the layer config is malformed or
///   incomplete for the auth kind.
/// - [`ErrorCode::Cancelled`] — `cancel` (via the stack build) fired during
///   construction.
/// - Any error `BuiltinAuthLayerFactory::build_layer` returns (policy parse
///   failures, JWT authn config errors).
pub async fn compose_listener_auth_stack(
    name: &str,
    config: &LayerConfig,
    inner: LayerHandle,
) -> Result<ListenerAuthStack> {
    compose_builtin_listener_auth_stack(name, config, inner, None).await
}

/// Return the plugin auth kinds from the effective loaded factory set.
///
/// Factory registration is last-wins by kind, matching [`ovstorage::StackBuilder`]:
/// a later host override replaces an earlier plugin or default factory with the
/// same kind. Only an effective wrapper whose descriptor also identifies it as
/// an auth-capable wrapper is admitted. Keeping this projection beside listener
/// auth composition ensures config resolution and construction select the same
/// duplicate-kind winner.
pub fn registered_plugin_auth_kinds(factories: &[LoadedLayerFactory]) -> BTreeSet<String> {
    let mut effective = BTreeMap::new();
    for factory in factories {
        effective.insert(factory.descriptor().kind, factory);
    }
    effective
        .into_iter()
        .filter_map(|(kind, factory)| {
            let LoadedLayerFactory::Wrapper(_) = factory else {
                return None;
            };
            let descriptor = factory.descriptor();
            (descriptor.layer_type == LayerType::Wrapper && descriptor.auth_capable).then_some(kind)
        })
        .collect()
}

/// Compose a selected listener auth kind over the shared auth-free inner.
///
/// `builtin-auth` uses the in-tree factory and retains its concrete handle.
/// Every other kind must resolve to an auth-capable wrapper factory. The
/// descriptor checks are fail-closed so a backend, router, ordinary wrapper,
/// or malformed factory cannot become a silently unauthenticated listener.
///
/// A plugin auth wrapper composes directly over a host-owned credential
/// boundary: raw credential in, DOWN-stamped [`ext::PRINCIPAL_ID`] out. The
/// boundary strips the credential and enforces the DOWN stamp on every
/// delegation below the wrapper.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — `kind` is unknown, is not a wrapper, or
///   does not advertise listener-auth capability.
/// - [`ErrorCode::Cancelled`] — `cancel` fires during factory creation or Stack
///   construction.
/// - Any error returned by the selected factory.
pub async fn compose_listener_auth_stack_with_factories(
    name: &str,
    kind: &str,
    config: &LayerConfig,
    inner: LayerHandle,
    factories: &[LoadedLayerFactory],
    cancel: Option<CancellationToken>,
) -> Result<ListenerAuthStack<ListenerAuth>> {
    if kind == BUILTIN_AUTH_KIND {
        let composed = compose_builtin_listener_auth_stack(name, config, inner, cancel).await?;
        return Ok(ListenerAuthStack {
            stack: composed.stack,
            auth_layer: ListenerAuth::builtin(composed.auth_layer),
        });
    }

    // StackBuilder registration is last-wins by kind. Select the same effective
    // factory here so config admission and listener composition cannot disagree
    // when a host override shadows a loaded plugin kind.
    let loaded = factories
        .iter()
        .rev()
        .find(|factory| factory.descriptor().kind == kind)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("listener auth kind `{kind}` has no loaded layer factory"),
            )
        })?;
    let descriptor = loaded.descriptor();
    let LoadedLayerFactory::Wrapper(factory) = loaded else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("listener auth kind `{kind}` must be a wrapper layer"),
        ));
    };
    if descriptor.layer_type != LayerType::Wrapper || !descriptor.auth_capable {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("listener auth kind `{kind}` must be an auth-capable wrapper layer"),
        ));
    }

    // The plugin wrapper composes directly over the host-owned credential
    // boundary: raw credential in, DOWN-stamped principal out, and the boundary
    // strips the credential and enforces the stamp below the wrapper.
    let credential_boundary: LayerHandle = Arc::new(PluginCredentialBoundary {
        kind: kind.to_string(),
        inner,
    });
    let auth_layer = factory
        .create_wrapper(name, config, credential_boundary, cancel.clone())
        .await?;
    let stack = Stack::builder(name)
        .attach(name, auth_layer.clone())
        .build_with_cancel(cancel)
        .await?;
    Ok(ListenerAuthStack {
        stack: Arc::new(stack),
        auth_layer: ListenerAuth::plugin(kind.to_string(), auth_layer),
    })
}

/// A principal resolved by the auth layer's authn front-end: the stable id fed
/// to the policy decision and stamped into [`ext::PRINCIPAL_ID`], an optional
/// human-readable display name, and the resolved attributes (JWT claims for a
/// bearer principal). Attributes are consumed by policy (future attribute-based
/// rules) and never marshaled.
#[derive(Debug)]
pub(crate) struct ResolvedPrincipal {
    pub(crate) id: String,
    pub(crate) display_name: Option<String>,
    // Carried for future attribute-based policy (mirrors `Principal::attributes`
    // in `ovstorage-authz-context`); no current gate reads them.
    #[allow(dead_code)]
    pub(crate) attributes: HashMap<String, String>,
}

impl ResolvedPrincipal {
    /// The anonymous principal — no credential presented, or a credential that
    /// carries no usable identity. Matches the policy engine's `"anonymous"`
    /// and the well-known registry's absence semantics.
    fn anonymous() -> Self {
        Self {
            id: ANONYMOUS_PRINCIPAL_ID.to_string(),
            display_name: None,
            attributes: HashMap::new(),
        }
    }
}

/// Authn front-end for the built-in combined auth layer. TCP uses the configured
/// signed-JWT, trusted-proxy, mTLS, or anonymous method; `Uds`/`NamedPipe` route
/// through the peer/dev front-end ([`resolve_peer`]).
enum TcpAuthnMode {
    Anonymous,
    JwtVerify(JwtConfig),
    TrustedUnsignedJwt {
        trusted_peers: Vec<CidrConstraint>,
        /// Optional `iss`/`aud` claim checks; see [`UnsignedJwtClaimChecks`].
        claims: UnsignedJwtClaimChecks,
    },
    TrustedForwardedHeaders {
        trusted_peers: Vec<CidrConstraint>,
        headers: ForwardedHeaderConfig,
    },
    Mtls,
}

struct BuiltinAuthn {
    tcp: TcpAuthnMode,
    peer: PeerConfig,
}

impl BuiltinAuthn {
    fn new(tcp: TcpAuthnMode, peer: PeerConfig) -> Self {
        Self { tcp, peer }
    }

    /// Resolve a principal from the optional decoded credential. `Uds`/
    /// `NamedPipe` peer identity resolves through [`resolve_peer`] (`uid:{uid}` /
    /// `sid:{sid}`, or the host user in `dev_current_user` mode); a `Tcp` bearer
    /// is validated as a JWT when the layer has JWT config, and an invalid token
    /// is `AuthRequired`. When JWT IS configured, a `Tcp` credential with an
    /// absent or blank bearer is `AuthRequired` (fail-closed — an unauthenticated
    /// caller on a JWT listener is rejected, never silently anonymous). A `Tcp`
    /// credential on a listener with NO JWT config resolves to anonymous.
    fn resolve(&self, credential: Option<&AuthCredential>) -> Result<ResolvedPrincipal> {
        let Some(credential) = credential else {
            return Ok(ResolvedPrincipal::anonymous());
        };
        match &credential.transport {
            Transport::Uds { .. } | Transport::NamedPipe { .. } => {
                resolve_peer(&credential.transport, &self.peer)
            }
            Transport::Tcp {
                peer_addr,
                tls_client_cert,
            } => match &self.tcp {
                TcpAuthnMode::Anonymous => Ok(ResolvedPrincipal::anonymous()),
                TcpAuthnMode::JwtVerify(cfg) => {
                    required_bearer(credential).and_then(|bearer| resolve_jwt(bearer, cfg))
                }
                TcpAuthnMode::TrustedUnsignedJwt {
                    trusted_peers,
                    claims,
                } => {
                    enforce_trusted_peer(peer_addr, trusted_peers)?;
                    required_bearer(credential)
                        .and_then(|bearer| resolve_unsigned_jwt(bearer, claims))
                }
                TcpAuthnMode::TrustedForwardedHeaders {
                    trusted_peers,
                    headers,
                } => {
                    enforce_trusted_peer(peer_addr, trusted_peers)?;
                    resolve_forwarded_headers(credential.forwarded.as_ref(), headers)
                }
                TcpAuthnMode::Mtls => resolve_mtls(tls_client_cert.as_deref()),
            },
        }
    }
}

fn required_bearer(credential: &AuthCredential) -> Result<&[u8]> {
    credential
        .bearer
        .as_deref()
        .filter(|bearer| !bearer_is_blank(bearer))
        .ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "bearer token required on this TCP listener",
            )
        })
}

fn resolve_forwarded_headers(
    forwarded: Option<&ForwardedHeaders>,
    config: &ForwardedHeaderConfig,
) -> Result<ResolvedPrincipal> {
    let forwarded = forwarded.ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "trusted forwarded identity header is missing",
        )
    })?;
    let required_value = |header: &str| -> Result<Option<String>> {
        let mut values = forwarded
            .values
            .iter()
            .filter(|(name, _)| name == header)
            .map(|(_, value)| value);
        let value = values.next().cloned();
        if values.next().is_some() {
            return Err(Error::new(
                ErrorCode::AuthRequired,
                format!("trusted forwarded header '{header}' has multiple values"),
            ));
        }
        Ok(value)
    };
    let id = required_value(&config.identity_header)?
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::AuthRequired,
                "trusted forwarded identity header is missing",
            )
        })?;
    let mut attributes = HashMap::new();
    for (claim, header) in &config.claim_headers {
        if let Some(value) = required_value(header)? {
            attributes.insert(claim.clone(), value);
        }
    }
    Ok(ResolvedPrincipal {
        id,
        display_name: None,
        attributes,
    })
}

fn resolve_mtls(cert: Option<&[u8]>) -> Result<ResolvedPrincipal> {
    let cert = cert.filter(|cert| !cert.is_empty()).ok_or_else(|| {
        Error::new(
            ErrorCode::AuthRequired,
            "a verified TLS client certificate is required on this listener",
        )
    })?;
    let digest = Sha256::digest(cert);
    let fingerprint = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(ResolvedPrincipal {
        id: format!("mtls:sha256:{fingerprint}"),
        display_name: None,
        attributes: HashMap::new(),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CidrConstraint {
    base: IpAddr,
    prefix_len: u8,
}

impl CidrConstraint {
    fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("trusted peer '{value}' must be a CIDR (host/prefix)"),
            )
        })?;
        let base = address.parse::<IpAddr>().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("trusted peer '{value}' has an invalid address: {error}"),
            )
        })?;
        let prefix_len = prefix.parse::<u8>().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("trusted peer '{value}' has an invalid prefix: {error}"),
            )
        })?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("trusted peer '{value}' prefix exceeds /{max}"),
            ));
        }
        Ok(Self { base, prefix_len })
    }

    fn contains(self, peer: IpAddr) -> bool {
        match (self.base, peer) {
            (IpAddr::V4(base), IpAddr::V4(peer)) => {
                let shift = 32 - u32::from(self.prefix_len);
                let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
                (u32::from(base) & mask) == (u32::from(peer) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(peer)) => {
                let shift = 128 - u32::from(self.prefix_len);
                let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
                (u128::from(base) & mask) == (u128::from(peer) & mask)
            }
            (IpAddr::V4(base), IpAddr::V6(peer)) => peer.to_ipv4_mapped().is_some_and(|peer| {
                Self {
                    base: IpAddr::V4(base),
                    prefix_len: self.prefix_len,
                }
                .contains(IpAddr::V4(peer))
            }),
            _ => false,
        }
    }
}

fn enforce_trusted_peer(peer_addr: &str, trusted_peers: &[CidrConstraint]) -> Result<()> {
    let peer = peer_addr.parse::<SocketAddr>().map_err(|_| {
        Error::new(
            ErrorCode::AuthRequired,
            "trusted proxy authentication requires a captured TCP peer address",
        )
    })?;
    if trusted_peers.iter().any(|cidr| cidr.contains(peer.ip())) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::AuthRequired,
            format!("peer {peer} is not in the trusted proxy CIDR allowlist"),
        ))
    }
}

/// Whether a bearer credential carries no usable token: empty, or only
/// whitespace. A blank bearer is treated as absent so a JWT-configured listener
/// fails closed rather than validating an empty string.
fn bearer_is_blank(bearer: &[u8]) -> bool {
    bearer.iter().all(u8::is_ascii_whitespace)
}

fn builtin_auth_descriptor() -> LayerKindDescriptor {
    LayerKindDescriptor {
        display_name: BUILTIN_AUTH_KIND.to_string(),
        kind: BUILTIN_AUTH_KIND.to_string(),
        layer_type: LayerType::Wrapper,
        description: Some(
            "Built-in combined auth layer (authn front-end + policy authz)".to_string(),
        ),
        config_schema: Vec::new(),
        credential_schema: Vec::new(),
        credential_methods: Vec::new(),
        icon: None,
        accepts_connections: false,
        auth_capable: true,
        supports_user_metadata: false,
    }
}

/// [`LayerConfig`] keys the built-in auth factory reads to configure bearer JWT
/// authn. How they are read depends on the `authn_mode`:
///
/// - `jwt_verify` (and the inferred mode when `authn_mode` is absent): all three
///   must appear together, or all be absent — no JWT authn, `Tcp` bearers fall
///   through to anonymous. A partial set is a config error
///   (`jwt_params_from_config`).
/// - `trusted_unsigned_jwt`: [`JWT_ISSUER_CONFIG_KEY`] and
///   [`JWT_AUDIENCE_CONFIG_KEY`] are each independently optional `iss`/`aud`
///   claim checks, and [`JWT_JWKS_URL_CONFIG_KEY`] is rejected — the fronting
///   proxy owns signature verification (`unsigned_jwt_claim_checks`).
/// - every other mode: all three are rejected.
pub const JWT_ISSUER_CONFIG_KEY: &str = "jwt_issuer";
/// See [`JWT_ISSUER_CONFIG_KEY`].
pub const JWT_AUDIENCE_CONFIG_KEY: &str = "jwt_audience";
/// See [`JWT_ISSUER_CONFIG_KEY`].
pub const JWT_JWKS_URL_CONFIG_KEY: &str = "jwt_jwks_url";
pub const AUTHN_MODE_CONFIG_KEY: &str = "authn_mode";
pub const FORWARDED_IDENTITY_HEADER_CONFIG_KEY: &str = "forwarded_identity_header";
pub const FORWARDED_CLAIM_HEADERS_CONFIG_KEY: &str = "forwarded_claim_headers";
const TRUSTED_PEERS_CONFIG_KEY: &str = "__host_trusted_peers";
/// Host-injected identity of the listener this auth layer serves (the operator's
/// `bind` string), used to name the listener in layer diagnostics. A host that
/// injects nothing gets unqualified messages.
const LISTENER_ID_CONFIG_KEY: &str = "__host_listener_id";
/// Private keys a listener host may inject after operator config has passed the
/// [`AUTH_CONFIG_KEYS`] allowlist. They are intentionally unavailable in the
/// operator-facing `auth.config` namespace.
const HOST_INJECTED_CONFIG_KEYS: &[&str] = &[TRUSTED_PEERS_CONFIG_KEY, LISTENER_ID_CONFIG_KEY];

/// TCP authentication modes understood by the built-in auth layer. Hosts use
/// this same parsed type for startup validation and transport credential
/// gathering, so mode names cannot drift between crates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthnMode {
    JwtVerify,
    TrustedUnsignedJwt,
    TrustedForwardedHeaders,
    Mtls,
}

impl AuthnMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JwtVerify => "jwt_verify",
            Self::TrustedUnsignedJwt => "trusted_unsigned_jwt",
            Self::TrustedForwardedHeaders => "trusted_forwarded_headers",
            Self::Mtls => "mtls",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "jwt_verify" => Ok(Self::JwtVerify),
            "trusted_unsigned_jwt" => Ok(Self::TrustedUnsignedJwt),
            "trusted_forwarded_headers" => Ok(Self::TrustedForwardedHeaders),
            "mtls" => Ok(Self::Mtls),
            other => Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unknown builtin-auth authn_mode '{other}' (expected jwt_verify, \
                     trusted_unsigned_jwt, trusted_forwarded_headers, or mtls)"
                ),
            )),
        }
    }
}

/// [`LayerConfig`] key (boolean) enabling `dev_current_user` peer authn: a peer
/// (`Uds`/`NamedPipe`) connection resolves to the host's current OS user instead
/// of the peer's transport credentials. Absent → disabled. A local-development
/// convenience mirroring the broker's `dev_current_user` listener mode.
pub const PEER_DEV_CURRENT_USER_CONFIG_KEY: &str = "peer_dev_current_user";

/// The auth-kind string an operator writes to opt a listener into unauthenticated
/// allow-all: `auth = "anonymous"`. Sugar for `(builtin-auth, allow-all policy)`.
pub const ANONYMOUS_AUTH_KIND: &str = "anonymous";

/// The complete set of keys accepted inside an `auth.config` table. Any other key
/// is a config error ([`layer_config_from_table`]) — fail-closed against typos
/// that would silently change the security posture.
const AUTH_CONFIG_KEYS: &[&str] = &[
    POLICY_CONFIG_KEY,
    JWT_ISSUER_CONFIG_KEY,
    JWT_AUDIENCE_CONFIG_KEY,
    JWT_JWKS_URL_CONFIG_KEY,
    AUTHN_MODE_CONFIG_KEY,
    FORWARDED_IDENTITY_HEADER_CONFIG_KEY,
    FORWARDED_CLAIM_HEADERS_CONFIG_KEY,
    PEER_DEV_CURRENT_USER_CONFIG_KEY,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardedHeaderConfig {
    pub identity_header: String,
    pub claim_headers: HashMap<String, String>,
}

/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — a CIDR in `trusted_peers` is malformed
///   (when `trusted_proxy` is true).
pub fn configure_trusted_proxy(
    config: &mut LayerConfig,
    trusted_proxy: bool,
    trusted_peers: &[String],
) -> Result<()> {
    if !trusted_proxy {
        return Ok(());
    }
    validate_trusted_peers(trusted_peers)?;
    config.insert(
        TRUSTED_PEERS_CONFIG_KEY.to_string(),
        ConfigValue::String(trusted_peers.join(",")),
    );
    Ok(())
}

/// Record which listener this auth layer serves, so layer-level diagnostics can
/// name it. `id` is the operator-facing listener identity (its `bind` string).
/// Purely descriptive: nothing in the authn/authz decision path reads it.
pub fn configure_listener_id(config: &mut LayerConfig, id: &str) {
    config.insert(
        LISTENER_ID_CONFIG_KEY.to_string(),
        ConfigValue::String(id.to_string()),
    );
}

/// The host-injected listener identity, or `"<unnamed>"` when the host injected
/// none (an embedding host that never calls [`configure_listener_id`]).
fn listener_id(config: &LayerConfig) -> &str {
    match config.get(LISTENER_ID_CONFIG_KEY) {
        Some(ConfigValue::String(id)) if !id.trim().is_empty() => id,
        _ => "<unnamed>",
    }
}

/// Validate host-supplied trusted-peer CIDRs using the same parser runtime
/// enforcement uses.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — a CIDR in `trusted_peers` is malformed
///   (not a valid address/prefix pair, invalid address, invalid prefix length).
pub fn validate_trusted_peers(trusted_peers: &[String]) -> Result<()> {
    for peer in trusted_peers {
        CidrConstraint::parse(peer)?;
    }
    Ok(())
}

/// Return whether a captured TCP peer belongs to the configured trusted-proxy
/// CIDR allowlist.
///
/// Hosts use this before copying forwarded identity metadata into an
/// [`AuthCredential`]. A missing or malformed captured socket address is not a
/// trusted peer; malformed operator CIDRs remain a startup error.
pub fn is_trusted_peer(peer_addr: &str, trusted_peers: &[String]) -> Result<bool> {
    let Ok(peer) = peer_addr.parse::<SocketAddr>() else {
        return Ok(false);
    };
    trusted_peers
        .iter()
        .map(|cidr| CidrConstraint::parse(cidr))
        .try_fold(false, |matched, cidr| {
            cidr.map(|cidr| matched || cidr.contains(peer.ip()))
        })
}

/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — forwarded-header config keys are
///   present but `authn_mode` is not `trusted_forwarded_headers`, or header
///   names fail validation.
pub fn forwarded_header_config(config: &LayerConfig) -> Result<Option<ForwardedHeaderConfig>> {
    let mode = configured_authn_mode(config)?;
    if mode != Some(AuthnMode::TrustedForwardedHeaders) {
        if config.contains_key(FORWARDED_IDENTITY_HEADER_CONFIG_KEY)
            || config.contains_key(FORWARDED_CLAIM_HEADERS_CONFIG_KEY)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "forwarded header settings require authn_mode = \"trusted_forwarded_headers\"",
            ));
        }
        return Ok(None);
    }
    forwarded_header_config_for_mode(config).map(Some)
}

/// Parse the standard listener-side forwarded-header capture fields for a
/// plugin auth wrapper.
///
/// Unlike [`forwarded_header_config`], this does not inspect `authn_mode`: the
/// plugin owns authentication semantics. The broker calls this only for a TCP
/// listener whose host-owned `trusted_proxy` flag and `trusted_peers` CIDRs are
/// configured, and passes the same config unchanged to the plugin factory.
pub fn plugin_forwarded_header_config(config: &LayerConfig) -> Result<ForwardedHeaderConfig> {
    forwarded_header_config_for_mode(config)
}

fn forwarded_header_config_for_mode(config: &LayerConfig) -> Result<ForwardedHeaderConfig> {
    let identity_header = metadata_header_name(
        &string_config(config, FORWARDED_IDENTITY_HEADER_CONFIG_KEY)?
            .unwrap_or_else(|| "x-forwarded-user".to_string()),
    )?;
    let claim_headers = toml_string_map(config, FORWARDED_CLAIM_HEADERS_CONFIG_KEY)?
        .into_iter()
        .map(|(claim, header)| Ok((claim, metadata_header_name(&header)?)))
        .collect::<Result<_>>()?;
    Ok(ForwardedHeaderConfig {
        identity_header,
        claim_headers,
    })
}

/// The `trusted_unsigned_jwt` claim-check keys this config leaves unset — the
/// claims the layer compares nothing against, so the fronting proxy is their
/// sole authority. Empty when the mode is not selected, or when both keys are
/// configured.
///
/// A proxy that verifies signatures but not audience admits tokens the IdP
/// minted for a different relying party, so an unset [`JWT_AUDIENCE_CONFIG_KEY`]
/// is the notable case; [`JWT_ISSUER_CONFIG_KEY`] is reported alongside it
/// because a token from an unexpected issuer is the same class of confusion.
/// This is a warning signal, not an error: a proxy that enforces these claims
/// itself is a valid deployment. The layer logs it at build time, so every
/// construction path is covered; this function is public so a host can surface
/// the same signal from a config check that builds nothing.
///
/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the `authn_mode` config is an unknown mode
///   string, or a `jwt_*` value is present with a wrong type or empty value.
pub fn trusted_unsigned_jwt_unenforced_claims(config: &LayerConfig) -> Result<Vec<&'static str>> {
    if configured_authn_mode(config)? != Some(AuthnMode::TrustedUnsignedJwt) {
        return Ok(Vec::new());
    }
    let mut unenforced = Vec::new();
    if string_config(config, JWT_ISSUER_CONFIG_KEY)?.is_none() {
        unenforced.push(JWT_ISSUER_CONFIG_KEY);
    }
    if string_config(config, JWT_AUDIENCE_CONFIG_KEY)?.is_none() {
        unenforced.push(JWT_AUDIENCE_CONFIG_KEY);
    }
    Ok(unenforced)
}

/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the `authn_mode` config is an unknown
///   mode string.
pub fn configured_authn_mode(config: &LayerConfig) -> Result<Option<AuthnMode>> {
    string_config(config, AUTHN_MODE_CONFIG_KEY)?
        .map(|mode| AuthnMode::parse(&mode))
        .transpose()
}

fn metadata_header_name(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || value == "authorization"
        || value.ends_with("-bin")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("'{value}' is not a valid gRPC metadata header name"),
        ));
    }
    Ok(value)
}

/// The allow-all policy `auth = "anonymous"` expands to: allow every principal
/// every operation on every address. The single home for the allow-all rule set:
/// hosts reference this const rather than defining their own per-crate
/// `ALLOW_ALL_POLICY`, so the only route to allow-all is the explicit
/// `"anonymous"` opt-in, never a silent fallback (fail-closed).
pub const ANONYMOUS_ALLOW_ALL_POLICY: &str = r#"
[[policy]]
id = "allow-all"
effect = "allow"
principal = "*"
operations = ["*"]
prefix = "*"
"#;

/// Shared listener-auth resolution plan used by network hosts.
///
/// A programmatic built-in config is already resolved. An operator listener
/// value is resolved before plugin loading when possible, or deliberately held
/// until the effective loaded factory set is available. This type keeps that
/// state transition in one place so hosts cannot accidentally represent
/// "waiting for plugins" as an ordinary empty built-in config.
#[derive(Clone)]
pub struct ListenerAuthBuildPlan {
    source: ListenerAuthBuildSource,
}

#[derive(Clone)]
enum ListenerAuthBuildSource {
    ResolvedBuiltin(LayerConfig),
    Listener {
        raw: Option<toml::Value>,
        listener_name: String,
    },
}

/// Effective listener-auth kind and factory config produced by a
/// [`ListenerAuthBuildPlan`].
#[derive(Clone, Debug)]
pub struct ResolvedListenerAuth {
    kind: String,
    config: LayerConfig,
}

impl ResolvedListenerAuth {
    /// Effective factory kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Whether this plan selects the in-tree auth implementation.
    pub fn is_builtin(&self) -> bool {
        self.kind == BUILTIN_AUTH_KIND
    }

    /// Config passed to the selected auth factory.
    pub fn config(&self) -> &LayerConfig {
        &self.config
    }

    /// Mutable config for host-owned built-in additions such as listener id or
    /// trusted-proxy CIDRs. Hosts must guard these additions with
    /// [`ResolvedListenerAuth::is_builtin`].
    pub fn config_mut(&mut self) -> &mut LayerConfig {
        &mut self.config
    }

    /// Compose this resolved selection over an auth-free inner Layer.
    pub async fn compose(
        &self,
        name: &str,
        inner: LayerHandle,
        factories: &[LoadedLayerFactory],
        cancel: Option<CancellationToken>,
    ) -> Result<ListenerAuthStack<ListenerAuth>> {
        compose_listener_auth_stack_with_factories(
            name,
            &self.kind,
            &self.config,
            inner,
            factories,
            cancel,
        )
        .await
    }
}

impl ListenerAuthBuildPlan {
    /// Build a plan from a programmatically supplied built-in config.
    pub fn resolved_builtin(config: LayerConfig) -> Self {
        Self {
            source: ListenerAuthBuildSource::ResolvedBuiltin(config),
        }
    }

    /// Build a plan from one listener/server `auth` value.
    pub fn listener(raw: Option<toml::Value>, listener_name: impl Into<String>) -> Self {
        Self {
            source: ListenerAuthBuildSource::Listener {
                raw,
                listener_name: listener_name.into(),
            },
        }
    }

    /// Resolve without loading plugins when the input cannot name a plugin.
    ///
    /// `Ok(None)` is the typed deferred state: the listener names a
    /// syntactically plugin-shaped kind and needs the effective factory set.
    /// Invalid built-in, anonymous, absent, or malformed inputs return their
    /// fail-closed error immediately.
    pub fn preflight(&self) -> Result<Option<ResolvedListenerAuth>> {
        match &self.source {
            ListenerAuthBuildSource::ResolvedBuiltin(config) => Ok(Some(ResolvedListenerAuth {
                kind: BUILTIN_AUTH_KIND.to_string(),
                config: config.clone(),
            })),
            ListenerAuthBuildSource::Listener { raw, listener_name }
                if listener_auth_needs_plugin_factories(raw.as_ref()) =>
            {
                Ok(None)
            }
            ListenerAuthBuildSource::Listener { raw, listener_name } => {
                let (kind, config) =
                    resolve_listener_auth(raw.clone(), listener_name, std::iter::empty::<&str>())?;
                Ok(Some(ResolvedListenerAuth { kind, config }))
            }
        }
    }

    /// Resolve against the effective loaded factory set.
    ///
    /// Factory eligibility and last-wins selection are projected through
    /// [`registered_plugin_auth_kinds`], the same rules used by composition.
    pub fn resolve(&self, factories: &[LoadedLayerFactory]) -> Result<ResolvedListenerAuth> {
        if let Some(resolved) = self.preflight()? {
            return Ok(resolved);
        }
        let ListenerAuthBuildSource::Listener { raw, listener_name } = &self.source else {
            unreachable!("a resolved built-in plan always completes during preflight")
        };
        let (kind, config) = resolve_listener_auth(
            raw.clone(),
            listener_name,
            registered_plugin_auth_kinds(factories),
        )?;
        Ok(ResolvedListenerAuth { kind, config })
    }
}

/// Whether listener auth resolution must wait for the host's loaded plugin
/// factory set.
///
/// Only a table with a string `kind` other than the built-in kind or the
/// `anonymous` shorthand can name a plugin. Absent, scalar, malformed,
/// built-in, and anonymous values can be resolved (or rejected) before plugin
/// loading. This is a syntactic preflight classifier; [`resolve_listener_auth`]
/// remains the canonical validator and fail-closed resolver.
pub fn listener_auth_needs_plugin_factories(raw: Option<&toml::Value>) -> bool {
    matches!(
        raw,
        Some(toml::Value::Table(table))
            if table.get("kind").and_then(toml::Value::as_str).is_some_and(|kind| {
                kind != BUILTIN_AUTH_KIND && kind != ANONYMOUS_AUTH_KIND
            })
    )
}

/// Resolve a listener/server `auth` config value into `(kind, LayerConfig)`.
/// `raw` is the deserialized TOML value of the `auth` field (`None` when the
/// operator omitted it). `registered_plugin_auth_kinds` names the auth-capable
/// plugin factories the host has made available for this listener.
///
/// This is pure config shaping — the host does no authn here. It never decodes a
/// credential, resolves a principal, or evaluates policy; it only maps operator
/// TOML onto the [`LayerConfig`] the auth layer reads (the host/layer split).
///
/// - `None` → fail-closed error (`listener <name> has no auth configured`). An
///   unconfigured listener refuses to build; there is no silent allow-all.
/// - `Some("anonymous")` → `(builtin-auth, { policy = allow-all })`, the explicit
///   unauthenticated opt-in.
/// - `Some({ kind, config })` → validate `kind` against [`BUILTIN_AUTH_KIND`]
///   plus `registered_plugin_auth_kinds`, and convert the `config` table into a
///   [`LayerConfig`] (nested values → [`ConfigValue::Toml`], scalars → the
///   matching variant), passed verbatim to the selected factory. The built-in
///   kind additionally enforces its private config-key allowlist.
/// - any other bare string → unknown-kind error.
/// - anything else (e.g. `auth = 3`) → a malformed-config error.
///
/// # Errors
///
/// - [`ErrorCode::NotConfigured`] — `raw` is `None` (listener has no auth
///   configured).
/// - [`ErrorCode::InvalidArgument`] — the auth value is malformed, unknown
///   `kind`, unknown `config` key, wrong-typed config field, or config key is
///   reserved for host injection.
pub fn resolve_listener_auth(
    raw: Option<toml::Value>,
    listener_name: &str,
    registered_plugin_auth_kinds: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(String, LayerConfig)> {
    let mut registered_auth_kinds: BTreeSet<String> = registered_plugin_auth_kinds
        .into_iter()
        .map(|kind| kind.as_ref().to_string())
        .collect();
    // `anonymous` is listener-config sugar, not a factory kind. Keep its table
    // form invalid even if a malformed plugin descriptor claims that name.
    registered_auth_kinds.remove(ANONYMOUS_AUTH_KIND);
    registered_auth_kinds.insert(BUILTIN_AUTH_KIND.to_string());

    let Some(value) = raw else {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!("listener {listener_name} has no auth configured"),
        ));
    };
    match value {
        toml::Value::String(kind) if kind == ANONYMOUS_AUTH_KIND => {
            let mut config = LayerConfig::new();
            config.insert(
                POLICY_CONFIG_KEY.to_string(),
                ConfigValue::Toml(ANONYMOUS_ALLOW_ALL_POLICY.to_string()),
            );
            Ok((BUILTIN_AUTH_KIND.to_string(), config))
        }
        toml::Value::String(other) => Err(unknown_auth_kind(&other, &registered_auth_kinds)),
        toml::Value::Table(mut table) => {
            let kind = match table.remove("kind") {
                Some(toml::Value::String(kind)) => kind,
                Some(_) => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("listener {listener_name} auth.kind must be a string"),
                    ));
                }
                None => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("listener {listener_name} auth table must set `kind`"),
                    ));
                }
            };
            let is_builtin = kind == BUILTIN_AUTH_KIND;
            if !is_builtin && !registered_auth_kinds.contains(&kind) {
                return Err(unknown_auth_kind(&kind, &registered_auth_kinds));
            }
            let config_table = match table.remove("config") {
                None => toml::value::Table::new(),
                Some(toml::Value::Table(config)) => config,
                Some(_) => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        format!("listener {listener_name} auth.config must be a table"),
                    ));
                }
            };
            // Only `kind` and `config` are consumed; a leftover key is an
            // operator typo (e.g. `cfg` for `config`), which would otherwise
            // silently drop the policy and yield an empty deny-all config.
            // Reject it, naming the offending key(s) — fail-closed ergonomics.
            if !table.is_empty() {
                let mut keys: Vec<String> = table.keys().map(|key| format!("'{key}'")).collect();
                keys.sort();
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "listener {listener_name} unknown auth config key(s): {} \
                         (expected 'kind' and 'config')",
                        keys.join(", ")
                    ),
                ));
            }
            let config = layer_config_from_table(listener_name, config_table, is_builtin)?;
            Ok((kind, config))
        }
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "listener {listener_name} auth must be the string \"anonymous\" or a \
                 {{ kind, config }} table"
            ),
        )),
    }
}

fn unknown_auth_kind(kind: &str, registered_auth_kinds: &BTreeSet<String>) -> Error {
    let registered = registered_auth_kinds
        .iter()
        .map(|kind| format!("'{kind}'"))
        .collect::<Vec<_>>()
        .join(", ");
    Error::new(
        ErrorCode::InvalidArgument,
        format!(
            "unknown auth kind '{kind}' (registered auth kinds: {registered}). Set \
             kind to a registered auth kind under [listener.auth], or auth = \
             \"anonymous\" for an explicitly unauthenticated listener"
        ),
    )
}

/// Convert an `auth.config` TOML table into a [`LayerConfig`]: scalars map onto
/// the matching [`ConfigValue`] variant and nested tables/arrays reserialize to
/// [`ConfigValue::Toml`]. A float/datetime value is an unsupported-type config
/// error. `enforce_builtin_allowlist` applies the built-in factory's config-key
/// vocabulary without imposing those semantics on plugin factories.
fn layer_config_from_table(
    listener_name: &str,
    table: toml::value::Table,
    enforce_builtin_allowlist: bool,
) -> Result<LayerConfig> {
    let mut config = LayerConfig::new();
    for (key, value) in table {
        if HOST_INJECTED_CONFIG_KEYS.contains(&key.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "listener {listener_name} auth.config key '{key}' is reserved for listener host injection"
                ),
            ));
        }
        // Reject an unknown built-in `auth.config` key rather than silently
        // accepting it — a typo (e.g. `jwt_issuers`) would otherwise drop the
        // value and quietly change the security posture (JWT silently disabled).
        // Plugin factories own their config vocabulary, so their keys pass
        // through after the shared reserved-key and value-type checks.
        if enforce_builtin_allowlist && !AUTH_CONFIG_KEYS.contains(&key.as_str()) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "listener {listener_name} unknown auth.config key '{key}' \
                     (expected one of: {})",
                    AUTH_CONFIG_KEYS.join(", ")
                ),
            ));
        }
        let converted = match value {
            toml::Value::String(value) => ConfigValue::String(value),
            toml::Value::Integer(value) => ConfigValue::Int(value),
            toml::Value::Boolean(value) => ConfigValue::Bool(value),
            nested @ (toml::Value::Table(_) | toml::Value::Array(_)) => {
                let document = toml::to_string(&nested).map_err(|err| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "listener {listener_name} auth.config `{key}` could not be \
                             reserialized to TOML: {err}"
                        ),
                    )
                })?;
                ConfigValue::Toml(document)
            }
            toml::Value::Float(_) | toml::Value::Datetime(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "listener {listener_name} auth.config `{key}` has an unsupported type \
                         (only string, integer, boolean, and table/array are accepted)"
                    ),
                ));
            }
        };
        config.insert(key, converted);
    }
    Ok(config)
}

/// Read a required-string config value, failing closed on a present-but-wrong
/// shape. Absent → `None`. A present, non-empty string → `Some`. A present
/// non-string value, or a present empty/blank string, is an `InvalidArgument`
/// config error rather than a silent `None` — a wrong-typed or empty `jwt_*`
/// value must not disable JWT authn silently (it would admit every bearer as
/// anonymous, or fail later with an opaque JWKS error).
fn string_config(config: &LayerConfig, key: &str) -> Result<Option<String>> {
    match config.get(key) {
        None => Ok(None),
        Some(ConfigValue::String(value)) if value.trim().is_empty() => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("builtin-auth `{key}` config must not be empty"),
        )),
        Some(ConfigValue::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("builtin-auth `{key}` config must be a string"),
        )),
    }
}

fn toml_string_map(config: &LayerConfig, key: &str) -> Result<HashMap<String, String>> {
    let Some(value) = config.get(key) else {
        return Ok(HashMap::new());
    };
    let ConfigValue::Toml(document) = value else {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("builtin-auth `{key}` config must be a string map"),
        ));
    };
    toml::from_str(document).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("builtin-auth `{key}` config must be a string map: {error}"),
        )
    })
}

fn trusted_peers_from_config(config: &LayerConfig) -> Result<Vec<CidrConstraint>> {
    match config.get(TRUSTED_PEERS_CONFIG_KEY) {
        Some(ConfigValue::String(peers)) if !peers.is_empty() => {
            peers.split(',').map(CidrConstraint::parse).collect()
        }
        Some(ConfigValue::String(_)) | None => Err(Error::new(
            ErrorCode::InvalidArgument,
            "trusted proxy authn requires trusted_proxy = true and non-empty trusted_peers",
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "host-injected trusted peer config has the wrong type",
        )),
    }
}

/// Parse the OIDC JWT parameters from layer config. Absent (all three keys
/// missing) → `None` (no JWT authn). Present (all three) → `Some`. A partial set
/// is an `InvalidArgument` config error (a half-configured validator would
/// silently admit every bearer as anonymous). A present-but-wrong-typed or empty
/// `jwt_*` value is rejected by [`string_config`] before the all-or-nothing check.
fn jwt_params_from_config(config: &LayerConfig) -> Result<Option<JwtParams>> {
    let issuer = string_config(config, JWT_ISSUER_CONFIG_KEY)?;
    let audience = string_config(config, JWT_AUDIENCE_CONFIG_KEY)?;
    let jwks_url = string_config(config, JWT_JWKS_URL_CONFIG_KEY)?;
    match (issuer, audience, jwks_url) {
        (None, None, None) => Ok(None),
        (Some(issuer), Some(audience), Some(jwks_url)) => Ok(Some(JwtParams {
            issuer,
            audience,
            jwks_url,
        })),
        _ => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "builtin-auth JWT config requires `{JWT_ISSUER_CONFIG_KEY}`, \
                 `{JWT_AUDIENCE_CONFIG_KEY}`, and `{JWT_JWKS_URL_CONFIG_KEY}` together"
            ),
        )),
    }
}

/// Parse the `trusted_unsigned_jwt` claim checks from layer config.
///
/// `jwt_issuer` / `jwt_audience` are each independently optional here — unlike
/// the signed path's all-three-or-none triplet — because the proxy, not this
/// layer, holds the signing keys. A configured value is enforced as a claim
/// string-compare ([`UnsignedJwtClaimChecks`]); an omitted one leaves that claim
/// to the upstream verifier. `jwt_jwks_url` is rejected: this mode performs no
/// signature verification, so a JWKS would be silently unused, and an operator
/// who supplies one has misjudged what the mode does.
fn unsigned_jwt_claim_checks(config: &LayerConfig) -> Result<UnsignedJwtClaimChecks> {
    if string_config(config, JWT_JWKS_URL_CONFIG_KEY)?.is_some() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "authn_mode = \"trusted_unsigned_jwt\" does not accept \
                 `{JWT_JWKS_URL_CONFIG_KEY}` — the fronting proxy owns signature \
                 verification; use `{JWT_ISSUER_CONFIG_KEY}` and \
                 `{JWT_AUDIENCE_CONFIG_KEY}` to enforce claim values"
            ),
        ));
    }
    // Every construction path — the daemon, `BrokerStackBuilder::build`, an
    // embedding host, and the SIGHUP rebuild — funnels through here exactly once
    // per layer build, so this is the single owner of the operator-facing
    // warning. Host config validation is deliberately NOT a second emission
    // point: those functions are pure predicates and run more than once per
    // startup, so a log there would duplicate.
    let unenforced = trusted_unsigned_jwt_unenforced_claims(config)?;
    if !unenforced.is_empty() {
        tracing::warn!(
            target: "ovstorage.auth",
            listener = listener_id(config),
            unenforced = unenforced.join(", "),
            "listener leaves trusted_unsigned_jwt claim checks unenforced: the layer \
             compares them against nothing, so the fronting proxy MUST reject tokens \
             issued for other services or by other issuers. Set jwt_audience and \
             jwt_issuer to enforce them here."
        );
    }
    Ok(UnsignedJwtClaimChecks {
        issuer: string_config(config, JWT_ISSUER_CONFIG_KEY)?,
        audience: string_config(config, JWT_AUDIENCE_CONFIG_KEY)?,
    })
}

/// Parse the peer/dev authn config: the [`PEER_DEV_CURRENT_USER_CONFIG_KEY`]
/// boolean flag (absent → disabled). A wrong-typed value is an
/// [`ErrorCode::InvalidArgument`] config error rather than a silent default.
fn peer_config_from_config(config: &LayerConfig) -> Result<PeerConfig> {
    let dev_current_user = match config.get(PEER_DEV_CURRENT_USER_CONFIG_KEY) {
        None => false,
        Some(ConfigValue::Bool(value)) => *value,
        Some(_) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "builtin-auth `{PEER_DEV_CURRENT_USER_CONFIG_KEY}` config must be a boolean"
                ),
            ));
        }
    };
    Ok(PeerConfig { dev_current_user })
}

/// Build the authn front-end from layer config. An explicit `authn_mode`
/// selects a TCP mode; for compatibility, an omitted mode infers `jwt_verify`
/// when the OIDC triplet is present and anonymous TCP otherwise.
///
/// The `jwt_*` keys are read per mode (see [`JWT_ISSUER_CONFIG_KEY`]).
/// `jwt_verify` consumes the all-or-nothing triplet and fetches the JWKS;
/// `trusted_unsigned_jwt` instead takes `jwt_issuer`/`jwt_audience` as optional
/// claim string-compares applied to a proxy-verified token; the remaining modes
/// accept no JWT settings at all.
async fn authn_from_config(config: &LayerConfig) -> Result<BuiltinAuthn> {
    let mode = configured_authn_mode(config)?;
    // `trusted_unsigned_jwt` reads `jwt_issuer`/`jwt_audience` as standalone
    // claim checks, so the all-three-or-none OIDC triplet rule does not apply to
    // it; `unsigned_jwt_claim_checks` owns that mode's key validation.
    let jwt_params = match mode {
        Some(AuthnMode::TrustedUnsignedJwt) => None,
        _ => jwt_params_from_config(config)?,
    };
    if mode != Some(AuthnMode::TrustedForwardedHeaders) {
        forwarded_header_config(config)?;
    }
    let tcp = match mode {
        None if jwt_params.is_none() => TcpAuthnMode::Anonymous,
        None | Some(AuthnMode::JwtVerify) => {
            let params = jwt_params.ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "authn_mode = \"jwt_verify\" requires the jwt_issuer, jwt_audience, and jwt_jwks_url settings",
                )
            })?;
            TcpAuthnMode::JwtVerify(
                JwtConfig::fetch(params.issuer, params.audience, &params.jwks_url).await?,
            )
        }
        Some(AuthnMode::TrustedUnsignedJwt) => TcpAuthnMode::TrustedUnsignedJwt {
            trusted_peers: trusted_peers_from_config(config)?,
            claims: unsigned_jwt_claim_checks(config)?,
        },
        Some(AuthnMode::TrustedForwardedHeaders) => {
            if jwt_params.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "trusted_forwarded_headers does not accept signed-JWT validation settings",
                ));
            }
            TcpAuthnMode::TrustedForwardedHeaders {
                trusted_peers: trusted_peers_from_config(config)?,
                headers: forwarded_header_config_for_mode(config)?,
            }
        }
        Some(AuthnMode::Mtls) => {
            if jwt_params.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "mtls does not accept signed-JWT validation settings",
                ));
            }
            TcpAuthnMode::Mtls
        }
    };
    let peer = peer_config_from_config(config)?;
    Ok(BuiltinAuthn::new(tcp, peer))
}

/// [`WrapperFactory`] for the built-in combined auth layer. Reads the policy
/// rule set from [`POLICY_CONFIG_KEY`] and the OIDC JWT parameters from the
/// `jwt_*` keys. The built-in evaluates the fresh policy on every request.
#[derive(Default)]
pub struct BuiltinAuthLayerFactory;

impl BuiltinAuthLayerFactory {
    pub fn new() -> Self {
        Self
    }

    /// Build the **concrete** [`BuiltinAuthLayer`] from layer config, fetching
    /// the JWKS when OIDC params are configured. A host that composes the auth
    /// layer directly (the broker) uses this to retain the typed
    /// `Arc<BuiltinAuthLayer>` for [`BuiltinAuthLayer::reload`] while still
    /// `attach`ing it as a `Layer` over the shared inner. [`WrapperFactory::create_wrapper`]
    /// erases the type to a [`LayerHandle`]; this keeps it.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the layer config is malformed or
    ///   incomplete: missing required JWT params, duplicate/conflicting authn
    ///   mode settings, unsupported header names, or wrong-typed config values.
    /// - [`ErrorCode::Transient`] — JWKS fetch failed when JWT authn is
    ///   configured.
    pub async fn build_layer(
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
    ) -> Result<Arc<BuiltinAuthLayer>> {
        let policy = policy_from_config(config)?;
        let authn = authn_from_config(config).await?;
        Ok(Arc::new(BuiltinAuthLayer::new(
            name,
            inner,
            Arc::new(ArcSwap::from_pointee(policy)),
            authn,
        )))
    }
}

#[async_trait]
impl WrapperFactory for BuiltinAuthLayerFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        builtin_auth_descriptor()
    }

    async fn create_wrapper(
        &self,
        name: &str,
        config: &LayerConfig,
        inner: LayerHandle,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Ok(Self::build_layer(name, config, inner).await?)
    }
}

/// The built-in combined auth layer: authn front-end + policy authz as one
/// [`Layer`]. For each gated verb it decodes the caller's
/// [`ext::AUTH_CREDENTIAL`], resolves a principal, evaluates the fresh
/// [`Policy`] for `(principal, operation, address)`, and on allow stamps
/// [`ext::PRINCIPAL_ID`] (+ display name) DOWN to `inner` before delegating; a
/// deny returns `PermissionDenied` and never reaches `inner`. The policy is held
/// in an [`ArcSwap`] so a host reload hook can swap it atomically without
/// rebuilding the layer.
///
/// Data verbs, the two per-principal introspection slots
/// (`list_address_roots` / `list_connections`), and the two slots that establish
/// connection credentials (`authenticate_connection` /
/// `update_connection_credentials`) are gated. The remaining management slots
/// are config-time and ungated, so they auto-delegate through the
/// [`Layer::inner_layer`] default.
pub struct BuiltinAuthLayer {
    name: String,
    descriptor: LayerKindDescriptor,
    inner: LayerHandle,
    authn: BuiltinAuthn,
    policy: Arc<ArcSwap<Policy>>,
}

/// Rewrite an address the layer is about to **delegate** into the canonical
/// spelling the policy matcher works in, and return it for the check.
///
/// The gate and the backend have to judge the same bytes. Canonicalizing a
/// local copy authorizes one node and delegates another: with
/// `allow * on s3://b/` plus `deny * on s3://b/private/`, a
/// `read s3://b/private%2F..%2Fpublic` arriving below the `Stack` boundary
/// evaluates as `s3://b/public` and is allowed by the broad rule, while the S3
/// backend derives its key from the address it was handed and reads the literal
/// flat key `private/../public` — which the deny covers. The allow is load
/// bearing in that example: a deny-only policy denies everything by default,
/// and it is the pair that produces the split.
///
/// Rewriting the request's own field closes it at the source.
///
/// `canonicalize` is idempotent, so an address a `Stack` already canonicalized
/// above passes through unchanged.
fn canonicalize_delegated(address: &mut Url) -> &mut Url {
    *address = canonicalize(address.clone());
    address
}

impl BuiltinAuthLayer {
    fn new(
        name: impl Into<String>,
        inner: LayerHandle,
        policy: Arc<ArcSwap<Policy>>,
        authn: BuiltinAuthn,
    ) -> Self {
        Self {
            name: name.into(),
            descriptor: builtin_auth_descriptor(),
            inner,
            authn,
            policy,
        }
    }

    /// Decode the caller's credential material and run the authn front-end to
    /// resolve a principal. An absent credential resolves to anonymous; a
    /// malformed one is `AuthRequired` (the caller presented material that could
    /// not be parsed).
    fn resolve_principal(&self, cx: &Extensions) -> Result<ResolvedPrincipal> {
        let credential = match cx.get(ext::AUTH_CREDENTIAL) {
            Some(bytes) => Some(AuthCredential::decode(bytes).map_err(|error| {
                Error::new(
                    ErrorCode::AuthRequired,
                    format!("malformed auth credential: {error}"),
                )
            })?),
            None => None,
        };
        self.authn.resolve(credential.as_ref())
    }

    /// Evaluate `policy` for `(principal, operation, address)`; map a deny to
    /// `PermissionDenied`. The caller passes the single per-request policy
    /// snapshot (loaded once in [`BuiltinAuthLayer::authorize`]) so every check
    /// belonging to one request evaluates against the same policy — a reload
    /// landing mid-request cannot authorize an op that neither the pre- nor
    /// post-reload policy allows. The principal is resolved by the authn
    /// front-end rather than read from `cx`.
    fn check(
        &self,
        policy: &Policy,
        principal: &str,
        operation: Operation,
        address: Option<&Url>,
    ) -> Result<()> {
        // The address is NOT canonicalized here. `Policy::matching_rule` does
        // it, which is the one point every evaluation converges on — this gate,
        // and equally the post-filters that call `Policy::is_allowed` directly
        // for a listing page, for route visibility and per watch event. Doing
        // it here as well would have left those four call sites judging the raw
        // spelling while this one judged the canonical, which is how the gate
        // and a listing filter come to disagree about the same address.
        //
        // What this layer still owes is the DELEGATION half — see
        // [`canonicalize_delegated`]. Authorization does not trust the chain
        // above it: every other layer degrades to a cache miss or a `NoRoute`
        // under an unnormalized spelling, this one would degrade to a bypass,
        // and `Stack::root()` is public API.
        let decision = policy.evaluate(principal, operation, address);
        if decision.is_allow() {
            return Ok(());
        }
        let address = address
            .map(ToString::to_string)
            .unwrap_or_else(|| "<none>".into());
        let reason = decision.reason.unwrap_or_else(|| {
            format!(
                "principal '{}' is not authorized for {} on {}",
                principal,
                operation_name(operation),
                address
            )
        });
        Err(Error::new(ErrorCode::PermissionDenied, reason))
    }

    /// Resolve the principal, emitting an `error` auth decision if authn fails.
    fn resolve_principal_metered(&self, cx: &Extensions) -> Result<ResolvedPrincipal> {
        self.resolve_principal(cx).inspect_err(|_| {
            metrics::counter!(AUTH_DECISIONS, "outcome" => "error").increment(1);
        })
    }

    /// Run one policy check against the per-request snapshot, emitting its
    /// `allow`/`deny` auth decision. Verbs that decompose into several checks
    /// (copy, rename) call this per check — all against the same snapshot — so
    /// every decision reaches `ovstorage_auth_decisions_total`.
    fn check_metered(
        &self,
        policy: &Policy,
        principal: &str,
        operation: Operation,
        address: Option<&Url>,
    ) -> Result<()> {
        match self.check(policy, principal, operation, address) {
            Ok(()) => {
                metrics::counter!(AUTH_DECISIONS, "outcome" => "allow").increment(1);
                Ok(())
            }
            Err(err) => {
                metrics::counter!(AUTH_DECISIONS, "outcome" => "deny").increment(1);
                Err(err)
            }
        }
    }

    /// The single decision gate: resolve the principal, load ONE policy snapshot
    /// for the whole request, then authorize `(operation, address)`. Returns the
    /// resolved principal (for downstream stamping on allow) and the snapshot, so
    /// a verb that runs a post-filter (`list`, `check_access`,
    /// `list_address_roots`, `watch_directory`) filters against the SAME policy it
    /// authorized with — one request, one policy.
    /// The address is taken by `&mut` and rewritten to its canonical spelling
    /// before the check, so the request that is delegated afterwards carries
    /// the address the policy actually judged. Taking `&Url` here is what let
    /// the gate and the backend disagree, and the `&mut` makes the split
    /// unwritable at every verb routed through this function.
    fn authorize(
        &self,
        cx: &Extensions,
        operation: Operation,
        address: Option<&mut Url>,
    ) -> Result<(ResolvedPrincipal, Arc<Policy>)> {
        let principal = self.resolve_principal_metered(cx)?;
        let policy = self.policy.load_full();
        let address = address.map(canonicalize_delegated);
        self.check_metered(&policy, &principal.id, operation, address.map(|url| &*url))?;
        Ok((principal, policy))
    }

    /// Stamp the resolved principal DOWN to inner layers: [`ext::PRINCIPAL_ID`]
    /// (and [`ext::PRINCIPAL_DISPLAY_NAME`] when the authn front-end resolved
    /// one). The raw credential is consumed here and removed before delegation;
    /// downstream cache scoping and attribution read only the plain principal
    /// values.
    fn stamp(&self, cx: &mut Extensions, principal: &ResolvedPrincipal) {
        cx.remove(ext::AUTH_CREDENTIAL);
        cx.insert(
            ext::PRINCIPAL_ID.to_string(),
            principal.id.as_bytes().to_vec(),
        );
        if let Some(display_name) = &principal.display_name {
            cx.insert(
                ext::PRINCIPAL_DISPLAY_NAME.to_string(),
                display_name.as_bytes().to_vec(),
            );
        }
    }

    /// Apply the shared authorization contract for both slots that establish
    /// credentials on a connection. An upstream-auth address is the policy
    /// resource when present; ordinary connection authentication is evaluated
    /// without an address. Keeping the operation mapping and principal stamp in
    /// this one helper prevents the two slots from drifting apart.
    fn authorize_and_stamp_credential_slot(&self, cx: &mut Extensions) -> Result<()> {
        let mut address = ext::upstream_auth_address(cx)?;
        let (principal, _) =
            self.authorize(cx, Operation::UpdateConnectionCredentials, address.as_mut())?;
        self.stamp(cx, &principal);
        Ok(())
    }

    /// Atomically swap the live policy for one parsed from `policy_toml`, the
    /// host's reload hook (broker SIGHUP / REST admin edit). Parses through the
    /// same [`Policy::from_toml`] the factory uses to build the initial policy,
    /// then stores the new policy into the [`ArcSwap`] so in-flight evaluations
    /// finish on the policy they loaded and subsequent requests see the new one.
    /// A parse failure returns `Err` and leaves the live policy untouched — a bad
    /// document never replaces a good policy.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the policy TOML is malformed or
    ///   contains invalid rules.
    /// - [`ErrorCode::Unsupported`] — the policy names an unsupported plugin
    ///   kind.
    pub fn reload(&self, policy_toml: &str) -> Result<()> {
        let new_policy = Policy::from_toml(policy_toml)?;
        self.policy.store(Arc::new(new_policy));
        Ok(())
    }

    /// Gate the `list_backend_kinds` discovery endpoint. Hosts serve backend
    /// kinds from a set captured at compose time rather than through the Stack,
    /// so no in-stack gate covers it; the host calls this to authorize
    /// [`Operation::ListBackendKinds`] (address-less) for the caller resolved
    /// from `cx`, emitting the same allow/deny/error metric as the in-stack
    /// gates. On deny returns `PermissionDenied`; the principal is not stamped
    /// (the endpoint does not dispatch through `inner`).
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the operation.
    pub fn authorize_list_backend_kinds(&self, cx: &Extensions) -> Result<()> {
        let (_principal, _policy) = self.authorize(cx, Operation::ListBackendKinds, None)?;
        Ok(())
    }

    /// Pre-flight a `Write` authorization on `address` for the caller resolved
    /// from `cx`, so a host can reject an unauthorized write BEFORE draining or
    /// buffering the request body (reject-before-drain). This does NOT emit a
    /// decision metric or stamp the principal: the authoritative, metered `Write`
    /// decision is the in-stack gate the subsequent dispatch runs — this pre-flight
    /// only avoids buffering a body that will be rejected anyway. On deny returns
    /// `PermissionDenied`.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the operation.
    pub fn authorize_write_preflight(&self, cx: &Extensions, address: &Url) -> Result<()> {
        let principal = self.resolve_principal(cx)?;
        let policy = self.policy.load_full();
        self.check(&policy, &principal.id, Operation::Write, Some(address))
    }
}

#[async_trait]
impl Layer for BuiltinAuthLayer {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptor(&self) -> LayerKindDescriptor {
        self.descriptor.clone()
    }

    /// Every remaining un-gated slot (including config-time management slots)
    /// delegates to `inner` via the trait defaults.
    fn inner_layer(&self) -> Option<&LayerHandle> {
        Some(&self.inner)
    }

    /// Per-URL root introspection, gated with the SAME visibility predicate
    /// [`list_address_roots`](Self::list_address_roots) applies per root
    /// ([`is_root_visible`] — `Read` OR `List` on the URL). Without this override
    /// the trait default auto-delegates to `inner`, letting a caller probe
    /// hidden-route existence (e.g. REST `get_capabilities`). On deny it returns
    /// the SAME [`ErrorCode::NoRoute`] a non-existent route yields, so a probe
    /// cannot distinguish hidden-and-denied from absent (existence is not
    /// leaked). Combined with the JWT fail-closed authn front-end, an
    /// unauthenticated caller on a JWT listener is rejected before this.
    ///
    /// # Errors
    ///
    /// The [`Layer::root_info_for`] contract: [`ErrorCode::NoRoute`] (including
    /// when the route is hidden by the policy), [`ErrorCode::Unsupported`],
    /// [`ErrorCode::Cancelled`], and [`ErrorCode::Transient`]. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn root_info_for(
        &self,
        url: &Url,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<RootInfo> {
        let principal = self.resolve_principal_metered(cx)?;
        let policy = self.policy.load_full();
        // The visibility predicate and the delegated lookup take the same
        // spelling; see [`canonicalize_delegated`]. `url` arrives by shared
        // reference from the trait, so the canonical form is a local that is
        // then delegated in place of the caller's.
        let mut url = url.clone();
        let url = canonicalize_delegated(&mut url);
        if !is_root_visible(&policy, &principal.id, url) {
            metrics::counter!(AUTH_DECISIONS, "outcome" => "deny").increment(1);
            // Match the router's own not-found error verbatim so a hidden root is
            // indistinguishable from an absent one.
            return Err(Error::new(ErrorCode::NoRoute, "no route matches address"));
        }
        metrics::counter!(AUTH_DECISIONS, "outcome" => "allow").increment(1);
        let mut cx = cx.clone();
        self.stamp(&mut cx, &principal);
        self.inner.root_info_for(url, &cx, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::list_address_roots`] contract with filtering applied to
    /// roots: [`ErrorCode::Transient`] from child enumeration and
    /// [`ErrorCode::Cancelled`] when `cancel` fires during the fan-out. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the operation.
    async fn list_address_roots(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)> {
        let (principal, policy) = self.authorize(cx, Operation::ListAddressRoots, None)?;
        let mut cx = cx.clone();
        self.stamp(&mut cx, &principal);
        let (mut snapshot, updates) = self.inner.list_address_roots(&cx, cancel).await?;
        snapshot
            .roots
            .retain(|root| is_root_visible(&policy, &principal.id, &root.root));
        // The initial snapshot is filtered above; the live update stream must be
        // filtered with the SAME principal id + per-request policy snapshot, or a
        // later `Added`/`Updated`/`Snapshot` change would leak a hidden root to
        // stream consumers. Mirrors `watch_directory`'s per-event filtering; the
        // captured snapshot is not re-keyed on a mid-stream policy swap (§7 R2).
        let updates =
            updates.map(|stream| filter_root_update_stream(stream, principal.id.clone(), policy));
        Ok((snapshot, updates))
    }

    /// # Errors
    ///
    /// The [`Layer::list_connections`] contract: [`ErrorCode::Transient`] and
    /// [`ErrorCode::Cancelled`]. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the operation.
    async fn list_connections(
        &self,
        cx: &Extensions,
        cancel: Option<CancellationToken>,
    ) -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)> {
        let (principal, _) = self.authorize(cx, Operation::ListConnections, None)?;
        let mut cx = cx.clone();
        self.stamp(&mut cx, &principal);
        self.inner.list_connections(&cx, cancel).await
    }

    /// Gate credential replacement as [`Operation::UpdateConnectionCredentials`].
    /// When [`ext::UPSTREAM_AUTH_ADDRESS`] is present, its URL is the policy
    /// resource; otherwise the decision is address-less. Policy authors use this
    /// operation for both credential-establishing slots because both answer the
    /// same question: may this caller establish credentials on a connection?
    ///
    /// # Errors
    ///
    /// The [`Layer::update_connection_credentials`] contract. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the operation.
    async fn update_connection_credentials(
        &self,
        mut request: Request<UpdateConnectionCredentialsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<Connection> {
        self.authorize_and_stamp_credential_slot(&mut request.extensions)?;
        self.inner
            .update_connection_credentials(request, cancel)
            .await
    }

    /// Gate interactive authentication as
    /// [`Operation::UpdateConnectionCredentials`]. When
    /// [`ext::UPSTREAM_AUTH_ADDRESS`] is present, its URL is the policy resource;
    /// otherwise the decision is address-less. Policy authors use this operation
    /// for both credential-establishing slots because both answer the same
    /// question: may this caller establish credentials on a connection?
    ///
    /// # Errors
    ///
    /// The [`Layer::authenticate_connection`] contract. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the operation.
    async fn authenticate_connection(
        &self,
        mut request: Request<AuthenticateRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AuthEventStream> {
        self.authorize_and_stamp_credential_slot(&mut request.extensions)?;
        self.inner.authenticate_connection(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::stat`] contract: [`ErrorCode::NoRoute`],
    /// [`ErrorCode::PermissionDenied`] (including authz denial),
    /// [`ErrorCode::InvalidArgument`], [`ErrorCode::Unsupported`],
    /// [`ErrorCode::Cancelled`], and [`ErrorCode::Transient`]. The
    /// [`ErrorCode::NotFound`] and [`ErrorCode::PermissionDenied`] codes from the
    /// base contract have extended semantics:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn stat(
        &self,
        mut request: Request<StatRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Stat,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.stat(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::read`] contract with extended [`ErrorCode::PermissionDenied`]
    /// semantics: includes authz denial by policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn read(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Read,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.read(request, cancel).await
    }

    /// `materialize` is the direct-disk read verb (`ReadRequest` → an on-disk
    /// `LocalDelegate` path). It is gated identically to `read`: the same `Read`
    /// authorization on the request address, then the resolved principal stamped
    /// DOWN before delegating. Without this override the trait default would
    /// auto-delegate to the unauthorized inner, letting a principal with no
    /// `Read` right resolve an on-disk path and read the bytes directly — a
    /// bypass of the `read` gate.
    ///
    /// # Errors
    ///
    /// The [`Layer::materialize`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn materialize(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<LocalDelegate> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Read,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.materialize(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::write`] contract with extended [`ErrorCode::PermissionDenied`]
    /// semantics: includes authz denial by policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn write(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Write,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.write(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::write_stream`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn write_stream(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Write,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.write_stream(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::write_redirect`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn write_redirect(
        &self,
        mut request: Request<WriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Write,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.write_redirect(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::continue_write`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn continue_write(
        &self,
        mut request: Request<ContinueWriteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Write,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.continue_write(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::delete`] contract with extended [`ErrorCode::PermissionDenied`]
    /// semantics: includes authz denial by policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn delete(
        &self,
        mut request: Request<DeleteRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::Delete,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.delete(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::copy`] contract with extended [`ErrorCode::PermissionDenied`]
    /// semantics: includes authz denial by policy (evaluates both `Read` on
    /// source and `Write` on destination against the same policy snapshot).
    /// Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn copy(
        &self,
        mut request: Request<CopyRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        // Copy decomposes to Read(src) + Write(dst); one resolved principal, one
        // policy snapshot, two checks — both against the same snapshot so a reload
        // between them cannot authorize a copy neither policy allows.
        //
        // Both endpoints are rewritten before the checks rather than through
        // `authorize`, because this verb runs `check_metered` directly. See
        // [`canonicalize_delegated`] for why the delegated request must carry
        // the addresses that were judged.
        let principal = self.resolve_principal_metered(&request.extensions)?;
        let policy = self.policy.load_full();
        canonicalize_delegated(&mut request.input.source);
        canonicalize_delegated(&mut request.input.destination);
        self.check_metered(
            &policy,
            &principal.id,
            Operation::Read,
            Some(&request.input.source),
        )?;
        self.check_metered(
            &policy,
            &principal.id,
            Operation::Write,
            Some(&request.input.destination),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.copy(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::rename`] contract with extended [`ErrorCode::PermissionDenied`]
    /// semantics: includes authz denial by policy (evaluates `Read` on source,
    /// `Delete` on source, and `Write` on destination against the same policy
    /// snapshot). Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn rename(
        &self,
        mut request: Request<RenameRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // Rename decomposes to Read(src) + Delete(src) + Write(dst); one resolved
        // principal, one policy snapshot, three checks — all against the same
        // snapshot so a reload between them cannot authorize a rename neither
        // policy allows.
        //
        // Both endpoints are rewritten before the checks rather than through
        // `authorize`, because this verb runs `check_metered` directly. See
        // [`canonicalize_delegated`] for why the delegated request must carry
        // the addresses that were judged.
        let principal = self.resolve_principal_metered(&request.extensions)?;
        let policy = self.policy.load_full();
        canonicalize_delegated(&mut request.input.source);
        canonicalize_delegated(&mut request.input.destination);
        self.check_metered(
            &policy,
            &principal.id,
            Operation::Read,
            Some(&request.input.source),
        )?;
        self.check_metered(
            &policy,
            &principal.id,
            Operation::Delete,
            Some(&request.input.source),
        )?;
        self.check_metered(
            &policy,
            &principal.id,
            Operation::Write,
            Some(&request.input.destination),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.rename(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::update_metadata`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn update_metadata(
        &self,
        mut request: Request<UpdateMetadataRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::UpdateMetadata,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.update_metadata(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::check_access`] contract: the call itself fails with
    /// [`ErrorCode::NotFound`], [`ErrorCode::NoRoute`], [`ErrorCode::Unsupported`],
    /// [`ErrorCode::Cancelled`], and [`ErrorCode::Transient`]. The returned
    /// [`AccessDecision`] captures authz denials (they are not errors; the call
    /// succeeds). Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    /// - [`ErrorCode::PermissionDenied`] — the policy denies the pre-flight
    ///   authorization for the checked address.
    async fn check_access(
        &self,
        mut request: Request<CheckAccessRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let (principal, policy) = self.authorize(
            &request.extensions,
            Operation::CheckAccess,
            Some(&mut request.input.address),
        )?;
        let address = request.input.address.clone();
        let operations = request.input.operations.clone();
        self.stamp(&mut request.extensions, &principal);
        let mut decision = self.inner.check_access(request, cancel).await?;
        apply_authz_access_decision(
            &policy,
            &principal.id,
            &address,
            &operations,
            &mut decision,
            "denied by authz policy",
        );
        Ok(decision)
    }

    /// # Errors
    ///
    /// The [`Layer::list`] contract with filtering applied to returned items:
    /// [`ErrorCode::NotFound`], [`ErrorCode::InvalidArgument`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`] (including authz
    /// denial), [`ErrorCode::Unsupported`], [`ErrorCode::Cancelled`], and
    /// [`ErrorCode::Transient`]. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn list(
        &self,
        mut request: Request<ListRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let (principal, policy) = self.authorize(
            &request.extensions,
            Operation::List,
            Some(&mut request.input.prefix),
        )?;
        self.stamp(&mut request.extensions, &principal);
        let mut page = self.inner.list(request, cancel).await?;
        // Post-filter with STAT visibility, not Read: list entries are metadata,
        // and the metadata-cache wrapper serves stats authoritatively from cached
        // parent listings — a Read-filtered page would deny a stat-but-not-read
        // principal metadata it can stat directly. Byte reads stay protected by
        // the separate Read check in `read`.
        let addresses = page
            .items
            .iter()
            .map(|item| item.address.clone())
            .collect::<Vec<_>>();
        let decisions = filter_list_batch(&policy, &principal.id, Operation::Stat, &addresses);
        page.items = page
            .items
            .into_iter()
            .zip(decisions)
            .filter_map(|(item, allow)| allow.then_some(item))
            .collect();
        Ok(page)
    }

    /// # Errors
    ///
    /// The [`Layer::list_versions`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn list_versions(
        &self,
        mut request: Request<ListVersionsRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<VersionPage> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::ListVersions,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.list_versions(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::get_latest_version`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn get_latest_version(
        &self,
        mut request: Request<ReadRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::ListVersions,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.get_latest_version(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::create_directory`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn create_directory(
        &self,
        mut request: Request<CreateDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::CreateDirectory,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.create_directory(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::delete_directory`] contract with extended
    /// [`ErrorCode::PermissionDenied`] semantics: includes authz denial by
    /// policy. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn delete_directory(
        &self,
        mut request: Request<DeleteDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let (principal, _) = self.authorize(
            &request.extensions,
            Operation::DeleteDirectory,
            Some(&mut request.input.address),
        )?;
        self.stamp(&mut request.extensions, &principal);
        self.inner.delete_directory(request, cancel).await
    }

    /// # Errors
    ///
    /// The [`Layer::watch_directory`] contract with filtering applied to stream
    /// events: [`ErrorCode::NotFound`], [`ErrorCode::InvalidArgument`],
    /// [`ErrorCode::NoRoute`], [`ErrorCode::PermissionDenied`] (including authz
    /// denial), [`ErrorCode::Unsupported`], [`ErrorCode::Internal`],
    /// [`ErrorCode::Cancelled`], and [`ErrorCode::Transient`]. Plus:
    ///
    /// - [`ErrorCode::AuthRequired`] — the caller presented a malformed
    ///   credential or a bearer token is required but absent.
    async fn watch_directory(
        &self,
        mut request: Request<WatchDirectoryRequest>,
        cancel: Option<CancellationToken>,
    ) -> Result<ChangeStream> {
        let (principal, policy) = self.authorize(
            &request.extensions,
            Operation::WatchDirectory,
            Some(&mut request.input.prefix),
        )?;
        // The WatchDirectory pre-check gates opening the stream. Each emitted
        // `Object` event is then evaluated for `Read` against the same per-request
        // policy snapshot used for the pre-check — this is per-event visibility
        // filtering, not revocation: the built-in does not react to mid-stream
        // policy swaps (a later `ArcSwap` swap does not re-key the live stream),
        // per design §7 R2 ("the built-in lets the stream live").
        let principal_id = principal.id.clone();
        self.stamp(&mut request.extensions, &principal);
        let stream = self.inner.watch_directory(request, cancel).await?;
        Ok(Box::new(stream.filter_map(move |event| {
            let event = match event {
                Ok(event) => event,
                Err(error) => return Some(Err(error)),
            };
            let address = match &event {
                ChangeEvent::Object { address, .. } => address.clone(),
                // Lapsed carries no address; pass through unfiltered.
                ChangeEvent::Lapsed { .. } => return Some(Ok(event)),
            };
            policy
                .is_allowed(&principal_id, Operation::Read, Some(&address))
                .then_some(Ok(event))
        })))
    }
}

/// Wrap a [`RootInfoUpdateStream`] so each emitted [`RootInfoChange`] is filtered
/// to the roots `principal_id` may see under `policy` (the per-request snapshot),
/// dropping hidden roots and dropping a change that becomes empty. Applied by
/// [`BuiltinAuthLayer::list_address_roots`] so the live stream never leaks a root
/// the filtered initial snapshot hides.
fn filter_root_update_stream(
    stream: RootInfoUpdateStream,
    principal_id: String,
    policy: Arc<Policy>,
) -> RootInfoUpdateStream {
    Box::pin(stream.filter_map(move |item| {
        let kept = match item {
            Ok(change) => filter_root_change(change, &principal_id, &policy).map(Ok),
            // Errors pass through unfiltered (mirrors `watch_directory`).
            Err(error) => Some(Err(error)),
        };
        std::future::ready(kept)
    }))
}

/// Filter one [`RootInfoChange`]'s roots to those visible to `principal_id` under
/// `policy`. A `Snapshot` is always emitted (even when empty): it is a full-state
/// replacement, so an empty/all-hidden snapshot is a meaningful "no visible roots"
/// convergence signal a consumer must observe. Incremental deltas
/// (`Added`/`Updated`/`Removed`) that become empty carry no information and are
/// dropped (`None`).
fn filter_root_change(
    change: RootInfoChange,
    principal_id: &str,
    policy: &Policy,
) -> Option<RootInfoChange> {
    let visible = |roots: Vec<RootInfo>| -> Vec<RootInfo> {
        roots
            .into_iter()
            .filter(|root| is_root_visible(policy, principal_id, &root.root))
            .collect()
    };
    match change {
        // Full-state replacement: always emit so consumers converge even when the
        // filtered set is empty.
        RootInfoChange::Snapshot(roots) => Some(RootInfoChange::Snapshot(visible(roots))),
        // Incremental deltas: drop when nothing visible remains.
        RootInfoChange::Added(roots) => {
            let roots = visible(roots);
            (!roots.is_empty()).then_some(RootInfoChange::Added(roots))
        }
        RootInfoChange::Updated(roots) => {
            let roots = visible(roots);
            (!roots.is_empty()).then_some(RootInfoChange::Updated(roots))
        }
        RootInfoChange::Removed(roots) => {
            let roots = visible(roots);
            (!roots.is_empty()).then_some(RootInfoChange::Removed(roots))
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod auth_config_tests {
    use super::{
        AuthnMode, BUILTIN_AUTH_KIND, ConfigValue, LayerConfig, ListenerAuthBuildPlan,
        POLICY_CONFIG_KEY, configured_authn_mode, forwarded_header_config,
        listener_auth_needs_plugin_factories, trusted_unsigned_jwt_unenforced_claims,
        unsigned_jwt_claim_checks,
    };
    use ovstorage_authz_policy::{Operation, Policy};

    fn resolve_listener_auth(
        raw: Option<toml::Value>,
        listener_name: &str,
    ) -> ovstorage::Result<(String, LayerConfig)> {
        super::resolve_listener_auth(raw, listener_name, std::iter::empty::<&str>())
    }

    /// Extract and parse the policy carried in a resolved [`LayerConfig`].
    fn policy_of(config: &LayerConfig) -> Policy {
        match config.get(POLICY_CONFIG_KEY) {
            Some(ConfigValue::Toml(toml)) | Some(ConfigValue::String(toml)) => {
                Policy::from_toml(toml).expect("policy parses")
            }
            other => panic!("expected a policy config value, got {other:?}"),
        }
    }

    #[test]
    fn absent_auth_is_fail_closed() {
        let err = resolve_listener_auth(None, "broker").unwrap_err();
        assert!(
            err.message().contains("has no auth configured"),
            "unexpected message: {}",
            err.message()
        );
    }

    #[test]
    fn only_plugin_shaped_tables_need_loaded_factories() {
        let plugin: toml::Value = "kind = \"plugin-auth\"".parse().unwrap();
        let builtin: toml::Value = "kind = \"builtin-auth\"".parse().unwrap();
        let anonymous_table: toml::Value = "kind = \"anonymous\"".parse().unwrap();
        let malformed: toml::Value = "kind = 3".parse().unwrap();

        assert!(listener_auth_needs_plugin_factories(Some(&plugin)));
        assert!(!listener_auth_needs_plugin_factories(Some(&builtin)));
        assert!(!listener_auth_needs_plugin_factories(Some(
            &anonymous_table
        )));
        assert!(!listener_auth_needs_plugin_factories(Some(&malformed)));
        assert!(!listener_auth_needs_plugin_factories(Some(
            &toml::Value::String("anonymous".to_string())
        )));
        assert!(!listener_auth_needs_plugin_factories(None));
    }

    #[test]
    fn build_plan_uses_a_typed_deferred_plugin_state() {
        let plugin: toml::Value = "kind = \"plugin-auth\"".parse().unwrap();
        let plugin = ListenerAuthBuildPlan::listener(Some(plugin), "rest");
        assert!(
            plugin.preflight().unwrap().is_none(),
            "plugin auth must remain unresolved until effective factories load",
        );

        let builtin: toml::Value = "kind = \"builtin-auth\"".parse().unwrap();
        let builtin = ListenerAuthBuildPlan::listener(Some(builtin), "rest")
            .preflight()
            .unwrap()
            .expect("built-in auth resolves before plugin loading");
        assert!(builtin.is_builtin());
    }

    #[test]
    fn anonymous_expands_to_builtin_auth_allow_all() {
        let (kind, config) =
            resolve_listener_auth(Some(toml::Value::String("anonymous".into())), "rest").unwrap();
        assert_eq!(kind, BUILTIN_AUTH_KIND);
        let policy = policy_of(&config);
        // Allow-all: every principal/op/address is admitted.
        assert!(policy.is_allowed("nobody", Operation::Write, None));
        assert!(policy.is_allowed("someone", Operation::Read, None));
    }

    #[test]
    fn gated_table_round_trips_policy_into_layer_config() {
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config.policy]
plugin = "ovstorage-authz-toml"
[[config.policy.policy]]
id = "read-only"
effect = "allow"
principal = "*"
operations = ["read"]
prefix = "*"
"#
        .parse()
        .unwrap();
        let (kind, config) = resolve_listener_auth(Some(auth), "rest").unwrap();
        assert_eq!(kind, BUILTIN_AUTH_KIND);
        let policy = policy_of(&config);
        // The config-sourced policy gates: read is allowed, write is denied.
        assert!(policy.is_allowed("alice", Operation::Read, None));
        assert!(!policy.is_allowed("alice", Operation::Write, None));
    }

    #[test]
    fn registered_plugin_kind_round_trips_verbatim_config() {
        let auth: toml::Value = r#"
kind = "plugin-auth"
[config]
issuer_alias = "corp"
attempts = 3
enabled = true
[config.options]
mode = "strict"
"#
        .parse()
        .unwrap();
        let (kind, config) =
            super::resolve_listener_auth(Some(auth), "rest", ["plugin-auth"]).unwrap();

        assert_eq!(kind, "plugin-auth");
        assert_eq!(
            config.get("issuer_alias"),
            Some(&ConfigValue::String("corp".to_string()))
        );
        assert_eq!(config.get("attempts"), Some(&ConfigValue::Int(3)));
        assert_eq!(config.get("enabled"), Some(&ConfigValue::Bool(true)));
        let Some(ConfigValue::Toml(options)) = config.get("options") else {
            panic!("expected nested plugin options to remain TOML");
        };
        let options: toml::Value = options.parse().unwrap();
        assert_eq!(
            options.get("mode").and_then(toml::Value::as_str),
            Some("strict")
        );
    }

    #[test]
    fn unregistered_kind_names_all_registered_auth_kinds() {
        let auth: toml::Value = r#"kind = "missing-auth""#.parse().unwrap();
        let err = super::resolve_listener_auth(Some(auth), "rest", ["zeta-auth", "acme-auth"])
            .unwrap_err();
        let message = err.message();

        assert!(
            message.contains("unknown auth kind 'missing-auth'"),
            "{message}"
        );
        assert!(
            message.contains("registered auth kinds: 'acme-auth', 'builtin-auth', 'zeta-auth'"),
            "{message}"
        );
    }

    #[test]
    fn registered_plugin_kind_rejects_host_injected_config_keys() {
        for key in ["__host_trusted_peers", "__host_listener_id"] {
            let auth: toml::Value = format!(
                r#"
kind = "plugin-auth"
[config]
{key} = "forged"
"#
            )
            .parse()
            .unwrap();
            let err =
                super::resolve_listener_auth(Some(auth), "rest", ["plugin-auth"]).unwrap_err();

            assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
            assert!(
                err.message()
                    .contains("reserved for listener host injection"),
                "message: {}",
                err.message()
            );
        }
    }

    #[test]
    fn unknown_kind_is_rejected_with_actionable_message() {
        let auth: toml::Value = r#"kind = "entra""#.parse().unwrap();
        let err = resolve_listener_auth(Some(auth), "rest").unwrap_err();
        let message = err.message();
        assert!(message.contains("entra"), "message: {message}");
        assert!(message.contains("builtin-auth"), "message: {message}");
        // The operator gets the remedy, not an issue number they cannot open.
        assert!(message.contains("anonymous"), "message: {message}");
        assert!(!message.contains('#'), "message: {message}");
    }

    #[test]
    fn bare_non_anonymous_string_is_unknown_kind() {
        let err =
            resolve_listener_auth(Some(toml::Value::String("entra".into())), "rest").unwrap_err();
        assert!(
            err.message().contains("unknown auth kind 'entra'"),
            "message: {}",
            err.message()
        );
    }

    #[test]
    fn scalar_auth_value_is_malformed() {
        let err = resolve_listener_auth(Some(toml::Value::Integer(3)), "rest").unwrap_err();
        assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
    }

    #[test]
    fn unknown_auth_table_key_is_rejected() {
        // `cfg` is a typo of `config`; silently dropping it would yield an empty
        // deny-all policy with no error. The resolver must reject it and name the
        // offending key (robustness / operator ergonomics, still fail-closed).
        let auth: toml::Value = r#"
kind = "builtin-auth"
cfg = { policy = "unused" }
"#
        .parse()
        .unwrap();
        let err = resolve_listener_auth(Some(auth), "rest").unwrap_err();
        assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
        let message = err.message();
        assert!(message.contains("'cfg'"), "message: {message}");
        assert!(message.contains("config"), "message: {message}");
    }

    #[test]
    fn unknown_auth_config_key_is_rejected() {
        // `jwt_issuers` is a typo of `jwt_issuer`; silently accepting it would
        // drop the value and quietly disable JWT authn. The resolver must reject
        // it and name the offending key (fail-closed, like the outer `auth` table).
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
jwt_issuers = "https://issuer.test"
"#
        .parse()
        .unwrap();
        let err = resolve_listener_auth(Some(auth), "rest").unwrap_err();
        assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
        assert!(
            err.message().contains("jwt_issuers"),
            "message: {}",
            err.message()
        );
    }

    #[test]
    fn host_injected_auth_config_keys_are_rejected_from_operator_config() {
        // Every host-injected key is off-limits in operator config, so an
        // operator cannot forge the trusted-peer allowlist or spoof the listener
        // identity that names a listener in diagnostics.
        for key in ["__host_trusted_peers", "__host_listener_id"] {
            let auth: toml::Value = format!(
                r#"
kind = "builtin-auth"
[config]
{key} = "127.0.0.1/32"
"#
            )
            .parse()
            .unwrap();
            let err = resolve_listener_auth(Some(auth), "grpc").unwrap_err();
            assert_eq!(err.code(), ovstorage::ErrorCode::InvalidArgument);
            assert!(
                err.message()
                    .contains("reserved for listener host injection"),
                "message: {}",
                err.message()
            );
        }
    }

    #[test]
    fn forwarded_header_config_normalizes_names_and_maps_claims() {
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_forwarded_headers"
forwarded_identity_header = "X-Authenticated-User"
[config.forwarded_claim_headers]
team = "X-Authenticated-Team"
"#
        .parse()
        .unwrap();
        let (_, config) = resolve_listener_auth(Some(auth), "broker").unwrap();
        let forwarded = forwarded_header_config(&config).unwrap().unwrap();
        assert_eq!(forwarded.identity_header, "x-authenticated-user");
        assert_eq!(
            forwarded.claim_headers.get("team").map(String::as_str),
            Some("x-authenticated-team")
        );
    }

    #[test]
    fn trusted_unsigned_jwt_toml_passes_mode_and_claim_checks_through() {
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
jwt_issuer = "https://issuer.test"
jwt_audience = "ovstorage"
"#
        .parse()
        .unwrap();
        let (kind, config) = resolve_listener_auth(Some(auth), "broker").unwrap();
        assert_eq!(kind, BUILTIN_AUTH_KIND);
        assert_eq!(
            configured_authn_mode(&config).unwrap(),
            Some(AuthnMode::TrustedUnsignedJwt)
        );
        let checks = unsigned_jwt_claim_checks(&config).unwrap();
        assert_eq!(checks.issuer.as_deref(), Some("https://issuer.test"));
        assert_eq!(checks.audience.as_deref(), Some("ovstorage"));
    }

    #[test]
    fn trusted_unsigned_jwt_toml_without_claim_checks_leaves_them_unset() {
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
"#
        .parse()
        .unwrap();
        let (_, config) = resolve_listener_auth(Some(auth), "broker").unwrap();
        assert_eq!(
            configured_authn_mode(&config).unwrap(),
            Some(AuthnMode::TrustedUnsignedJwt)
        );
        let checks = unsigned_jwt_claim_checks(&config).unwrap();
        assert!(checks.issuer.is_none());
        assert!(checks.audience.is_none());
    }

    #[test]
    fn unenforced_claims_are_reported_only_for_the_unsigned_mode() {
        let unenforced = |toml_src: &str| {
            let auth: toml::Value = toml_src.parse().unwrap();
            let (_, config) = resolve_listener_auth(Some(auth), "broker").unwrap();
            trusted_unsigned_jwt_unenforced_claims(&config).unwrap()
        };

        // The risky posture: mode selected, neither claim to compare.
        assert_eq!(
            unenforced(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
"#
            ),
            vec!["jwt_issuer", "jwt_audience"]
        );
        // An issuer alone still leaves the audience unenforced.
        assert_eq!(
            unenforced(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
jwt_issuer = "https://issuer.test"
"#
            ),
            vec!["jwt_audience"]
        );
        // ...and an audience alone still leaves the issuer unenforced, so a
        // token from an unexpected issuer is reported too.
        assert_eq!(
            unenforced(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
jwt_audience = "ovstorage"
"#
            ),
            vec!["jwt_issuer"]
        );
        // Both configured — nothing to warn about.
        assert!(
            unenforced(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
jwt_issuer = "https://issuer.test"
jwt_audience = "ovstorage"
"#
            )
            .is_empty()
        );
        // Other modes are never reported: `jwt_verify` enforces both claims as
        // part of signature validation, and the rest take no bearer claims.
        assert!(
            unenforced(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "mtls"
"#
            )
            .is_empty()
        );
        assert!(unenforced(r#"kind = "builtin-auth""#).is_empty());
    }

    /// Capture `warn`-level events emitted while `body` runs, as
    /// `"<message> | <field>=<value> ..."` strings.
    fn captured_warnings(body: impl FnOnce()) -> Vec<String> {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<String>>>);

        struct Visitor(String);

        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" | {}={:?}", field.name(), value));
            }
        }

        impl<S: tracing::Subscriber> Layer<S> for Capture {
            fn on_event(&self, event: &tracing::Event<'_>, _cx: Context<'_, S>) {
                if *event.metadata().level() != tracing::Level::WARN {
                    return;
                }
                let mut visitor = Visitor(String::new());
                event.record(&mut visitor);
                self.0.lock().unwrap().push(visitor.0);
            }
        }

        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(Arc::clone(&captured)));
        tracing::subscriber::with_default(subscriber, body);
        captured.lock().unwrap().clone()
    }

    /// Resolve `toml_src` into layer config, inject a listener identity the way
    /// a host does, then run the claim-check parse under warning capture.
    fn warnings_for(toml_src: &str, listener: &str) -> Vec<String> {
        let auth: toml::Value = toml_src.parse().unwrap();
        let (_, mut config) = resolve_listener_auth(Some(auth), listener).unwrap();
        super::configure_listener_id(&mut config, listener);
        captured_warnings(|| {
            unsigned_jwt_claim_checks(&config).unwrap();
        })
    }

    #[test]
    fn unenforced_claims_warn_once_naming_the_listener() {
        // The operator-facing guarantee: a permissive `trusted_unsigned_jwt`
        // posture produces exactly one WARN naming the listener's bind and the
        // unenforced keys. A `debug!` here would be invisible under the default
        // `warn,ovstorage=info` filter.
        let warnings = warnings_for(
            r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
"#,
            "0.0.0.0:8787",
        );
        assert_eq!(warnings.len(), 1, "expected one warning, got {warnings:?}");
        let warning = &warnings[0];
        assert!(warning.contains("0.0.0.0:8787"), "{warning}");
        assert!(warning.contains("jwt_issuer"), "{warning}");
        assert!(warning.contains("jwt_audience"), "{warning}");
    }

    #[test]
    fn a_partially_enforced_listener_warns_only_about_the_unset_claim() {
        let warnings = warnings_for(
            r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
jwt_issuer = "https://issuer.test"
"#,
            "0.0.0.0:8787",
        );
        assert_eq!(warnings.len(), 1, "expected one warning, got {warnings:?}");
        assert!(warnings[0].contains("jwt_audience"), "{}", warnings[0]);
    }

    #[test]
    fn fully_enforced_and_other_modes_warn_nothing() {
        // Both claims configured: silence. A warning here would train operators
        // to ignore the one that matters.
        assert!(
            warnings_for(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
jwt_issuer = "https://issuer.test"
jwt_audience = "ovstorage"
"#,
                "0.0.0.0:8787",
            )
            .is_empty()
        );
    }

    #[test]
    fn the_warning_survives_the_default_production_log_filter() {
        // The regression this pins: emitting below `warn` from an
        // `ovstorage`-prefixed target is invisible under the shipped default
        // filter, so the documented operator guarantee silently delivers
        // nothing. Assert against the real filter string, not a permissive one.
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

        struct Count(Arc<Mutex<usize>>);
        impl<S: tracing::Subscriber> Layer<S> for Count {
            fn on_event(&self, _event: &tracing::Event<'_>, _cx: Context<'_, S>) {
                *self.0.lock().unwrap() += 1;
            }
        }

        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
"#
        .parse()
        .unwrap();
        let (_, mut config) = resolve_listener_auth(Some(auth), "0.0.0.0:8787").unwrap();
        super::configure_listener_id(&mut config, "0.0.0.0:8787");

        let seen = Arc::new(Mutex::new(0usize));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                ovstorage::DEFAULT_LOG_FILTER,
            ))
            .with(Count(Arc::clone(&seen)));
        tracing::subscriber::with_default(subscriber, || {
            unsigned_jwt_claim_checks(&config).unwrap();
        });
        assert_eq!(
            *seen.lock().unwrap(),
            1,
            "the unenforced-claims diagnostic must pass the default filter"
        );
    }

    #[test]
    fn a_host_that_injects_no_listener_id_still_warns() {
        // An embedding host that never calls `configure_listener_id` gets the
        // warning unqualified rather than losing it.
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_unsigned_jwt"
"#
        .parse()
        .unwrap();
        let (_, config) = resolve_listener_auth(Some(auth), "embedded").unwrap();
        let warnings = captured_warnings(|| {
            unsigned_jwt_claim_checks(&config).unwrap();
        });
        assert_eq!(warnings.len(), 1, "expected one warning, got {warnings:?}");
        assert!(warnings[0].contains("<unnamed>"), "{}", warnings[0]);
    }

    #[test]
    fn forwarded_settings_require_the_forwarded_authn_mode() {
        let auth: toml::Value = r#"
kind = "builtin-auth"
[config]
forwarded_identity_header = "x-authenticated-user"
"#
        .parse()
        .unwrap();
        let (_, config) = resolve_listener_auth(Some(auth), "broker").unwrap();
        let error = forwarded_header_config(&config).unwrap_err();
        assert_eq!(error.code(), ovstorage::ErrorCode::InvalidArgument);
        assert!(error.message().contains("trusted_forwarded_headers"));
    }

    #[test]
    fn forwarded_headers_cannot_capture_authorization_or_binary_metadata() {
        for header in ["authorization", "x-identity-bin"] {
            let auth: toml::Value = format!(
                r#"
kind = "builtin-auth"
[config]
authn_mode = "trusted_forwarded_headers"
forwarded_identity_header = "{header}"
"#
            )
            .parse()
            .unwrap();
            let (_, config) = resolve_listener_auth(Some(auth), "broker").unwrap();
            assert_eq!(
                forwarded_header_config(&config).unwrap_err().code(),
                ovstorage::ErrorCode::InvalidArgument
            );
        }
    }
}
