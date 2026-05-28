// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod authn;
mod jwt;
pub mod metrics_layer;
mod schema;
mod trace;

#[cfg(test)]
mod test_utils;

pub use jwt::JwtAuthenticator;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use ovstorage::{
    AccessOps, AddressVisibility, AliasId, AliasRequest, AuthEvent, Body, ByteRange, ChangeEvent,
    ChangeKind, ConfigValue, ConnectionId, ConnectionRequest, CopyOptions, CreateDirectoryOptions,
    DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, IfDestExists, Library, ListOptions,
    ListVersionsOptions, ReadOptions, ReadResult, RenameOptions, SecretBundle, SecretBytes,
    SecretValue, StatOptions, Storage, UpdateMetadataOptions, Url, UserMetadata,
    WatchDirectoryCursor, WatchDirectoryOptions, WriteOptions, address,
};
use ovstorage_authz::{
    AttributionLayer, AttributionStrategy, AuthzPlugin, AuthzRequest, Operation, PolicyEpochState,
    PolicyFreshness, Principal, RequestContext,
};
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;

/// Aggregate state every handler extracts from via `FromRef`.
#[derive(Clone)]
pub struct AppState {
    pub library: Arc<Library>,
    pub authz: Option<Arc<dyn AuthzPlugin>>,
    /// Policy-epoch state, kept in-memory because REST has no reload story.
    pub policy_state: Arc<PolicyEpochState>,
    /// Trust-boundary attribution overlay for `modified_by`. Default
    /// `UserMetadata` strategy stamps the authn'd principal into a
    /// reserved key in `user_metadata`; `Passthrough` for chained
    /// gateways that forward an upstream broker's stamp unchanged.
    pub attribution: AttributionLayer,
    /// Pre-rendered OpenAPI JSON, built once so spec endpoints skip per-request serialization.
    openapi_json: Arc<String>,
    openapi_yaml: Arc<String>,
}

/// Bundled authz plugin + policy state extracted together by handlers.
#[derive(Clone)]
pub struct AuthzState {
    pub plugin: Option<Arc<dyn AuthzPlugin>>,
    pub policy: Arc<PolicyEpochState>,
}

impl FromRef<AppState> for Arc<Library> {
    fn from_ref(s: &AppState) -> Self {
        s.library.clone()
    }
}

impl FromRef<AppState> for AuthzState {
    fn from_ref(s: &AppState) -> Self {
        AuthzState {
            plugin: s.authz.clone(),
            policy: s.policy_state.clone(),
        }
    }
}

impl FromRef<AppState> for AttributionLayer {
    fn from_ref(s: &AppState) -> Self {
        s.attribution.clone()
    }
}

#[derive(Clone)]
struct RenderedSpec {
    json: Arc<String>,
    yaml: Arc<String>,
}

impl FromRef<AppState> for RenderedSpec {
    fn from_ref(s: &AppState) -> Self {
        Self {
            json: s.openapi_json.clone(),
            yaml: s.openapi_yaml.clone(),
        }
    }
}

/// Extractor for the authenticated principal; falls back to anonymous in dev mode.
pub struct Caller(pub Principal);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<Principal>()
                .cloned()
                .unwrap_or_else(Principal::anonymous),
        ))
    }
}

/// Run the per-method authz check before dispatching to the library;
/// `plugin = None` allows everything (dev mode).
async fn authorize_op(
    authz: &AuthzState,
    principal: &Principal,
    operation: Operation,
    address: Option<&Url>,
) -> ovstorage::Result<()> {
    let Some(plugin) = authz.plugin.as_ref() else {
        return Ok(());
    };
    let request = AuthzRequest {
        principal: principal.clone(),
        operation,
        address: address.cloned(),
        policy_epoch: authz.policy.current_epoch(),
        audit_id: None,
    };
    authz.policy.check(request.policy_epoch)?;
    plugin.authorize(&request).await?.into_result(&request)
}

/// Per-item `Read` filter for a `list` page; returns a keep-mask.
pub(crate) async fn filter_list_addresses(
    authz: &AuthzState,
    principal: &Principal,
    prefix: &Url,
    addresses: &[Url],
) -> ovstorage::Result<Vec<bool>> {
    let Some(plugin) = authz.plugin.as_ref() else {
        return Ok(vec![true; addresses.len()]);
    };
    let request = AuthzRequest {
        principal: principal.clone(),
        operation: Operation::Read,
        address: Some(prefix.clone()),
        policy_epoch: authz.policy.current_epoch(),
        audit_id: None,
    };
    authz.policy.check(request.policy_epoch)?;
    let decisions = plugin.filter_list_batch(&request, addresses).await?;
    if decisions.len() != addresses.len() {
        return Err(Error::new(
            ErrorCode::Internal,
            "authz list filter returned the wrong number of decisions",
        ));
    }
    Ok(decisions.iter().map(|d| d.is_allow()).collect())
}

/// Single-address `Read` check for the watch_directory per-event filter.
pub(crate) async fn authz_allows_read(
    authz: &AuthzState,
    principal: &Principal,
    address: &Url,
) -> ovstorage::Result<bool> {
    let Some(plugin) = authz.plugin.as_ref() else {
        return Ok(true);
    };
    let request = AuthzRequest {
        principal: principal.clone(),
        operation: Operation::Read,
        address: Some(address.clone()),
        policy_epoch: authz.policy.current_epoch(),
        audit_id: None,
    };
    authz.policy.check(request.policy_epoch)?;
    Ok(plugin.authorize(&request).await?.is_allow())
}

/// `AuthzCheck` impl wiring REST handlers into the shared
/// composition helpers (`ovstorage_authz::compose`). `plugin = None`
/// allows everything to match the dev-mode behavior of `authorize_op`.
#[async_trait::async_trait]
impl ovstorage_authz::compose::AuthzCheck for AuthzState {
    async fn check(
        &self,
        context: &RequestContext,
        operation: Operation,
        address: &Url,
    ) -> ovstorage::Result<bool> {
        let Some(plugin) = self.plugin.as_ref() else {
            return Ok(true);
        };
        self.policy.check(context.policy_epoch)?;
        let request = AuthzRequest::from_context(context, operation, Some(address));
        Ok(plugin.authorize(&request).await?.is_allow())
    }
}

/// Static OpenAPI metadata; paths and schemas are auto-collected by
/// the `OpenApiRouter` machinery in `router(...)`.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "ovstorage REST",
        description = "Public REST gateway for ovstorage. The OpenAPI document is the versioned contract; the gRPC `.proto` is internal between the broker daemon and the broker plugin.",
        version = env!("CARGO_PKG_VERSION"),
    ),
    tags(
        (name = "objects", description = "Object operations (read/write/list/etc.)"),
        (name = "directories", description = "Directory create/delete"),
        (name = "discovery", description = "Capabilities, address roots, backend kinds"),
        (name = "connections", description = "Connection add/remove/list/authenticate"),
        (name = "aliases", description = "Address alias add/remove/list"),
        (name = "visibility", description = "Address visibility overrides"),
        (name = "spec", description = "OpenAPI document"),
    ),
)]
pub struct ApiDoc;

/// Build the OpenAPI document from the same router the gateway serves,
/// guaranteeing the spec and the routes can't disagree.
pub fn openapi_spec() -> utoipa::openapi::OpenApi {
    let (_router, api) = build_open_api_router().split_for_parts();
    api
}

/// Construct the `OpenApiRouter` populated with every handler.
fn build_open_api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(read_object, write_object, delete_object))
        .routes(routes!(stat_object))
        .routes(routes!(list_objects))
        .routes(routes!(list_versions))
        .routes(routes!(get_latest_version))
        .routes(routes!(copy_object))
        .routes(routes!(rename_object))
        .routes(routes!(update_metadata))
        .routes(routes!(check_access))
        .routes(routes!(create_directory, delete_directory))
        .routes(routes!(get_capabilities))
        .routes(routes!(list_address_roots))
        .routes(routes!(list_backend_kinds))
        .routes(routes!(watch_directory_sse))
        .routes(routes!(add_connection, list_connections))
        .routes(routes!(remove_connection))
        .routes(routes!(authenticate_connection_sse))
        .routes(routes!(add_alias, list_aliases))
        .routes(routes!(remove_alias))
        .routes(routes!(set_visibility, list_visibility))
        .routes(routes!(openapi_json))
        .routes(routes!(openapi_yaml))
}

/// Render the OpenAPI document as JSON.
#[utoipa::path(
    get,
    path = "/v1/openapi.json",
    tag = "spec",
    responses((status = 200, description = "OpenAPI 3 document", content_type = "application/json")),
)]
async fn openapi_json(State(spec): State<RenderedSpec>) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        (*spec.json).clone(),
    )
        .into_response()
}

/// Render the OpenAPI document as YAML.
#[utoipa::path(
    get,
    path = "/v1/openapi.yaml",
    tag = "spec",
    responses((status = 200, description = "OpenAPI 3 document", content_type = "application/yaml")),
)]
async fn openapi_yaml(State(spec): State<RenderedSpec>) -> Response {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/yaml")],
        (*spec.yaml).clone(),
    )
        .into_response()
}

/// Build the REST router fronting an `ovstorage::Library`.
///
/// `authenticator = None` skips authn (dev mode); `authz = None` allows
/// everything (dev mode). Uses the default `UserMetadata` attribution
/// strategy; for chained-gateway setups call
/// [`router_with_attribution`] instead.
pub fn router(
    library: Arc<Library>,
    authenticator: Option<Arc<JwtAuthenticator>>,
    authz: Option<Arc<dyn AuthzPlugin>>,
) -> Router {
    router_with_attribution(
        library,
        authenticator,
        authz,
        AttributionStrategy::default(),
    )
    .expect("default UserMetadata strategy is always valid")
}

/// Like [`router`] but lets the operator pick the attribution
/// strategy. `Passthrough` is the right choice for an intermediate
/// REST gateway that fronts another broker — the upstream broker's
/// `ovstorage-modified-by` stamp survives end-to-end.
pub fn router_with_attribution(
    library: Arc<Library>,
    authenticator: Option<Arc<JwtAuthenticator>>,
    authz: Option<Arc<dyn AuthzPlugin>>,
    attribution_strategy: AttributionStrategy,
) -> ovstorage::Result<Router> {
    let api = openapi_spec();
    let openapi_json = Arc::new(serde_json::to_string(&api).expect("OpenAPI JSON"));
    let openapi_yaml = Arc::new(serde_yaml::to_string(&api).expect("OpenAPI YAML"));
    let policy_state = PolicyEpochState::in_memory(0, PolicyFreshness::Strict);
    let state = AppState {
        library,
        authz,
        policy_state,
        attribution: AttributionLayer::new(attribution_strategy)?,
        openapi_json,
        openapi_yaml,
    };
    let (mut router, _) = build_open_api_router().with_state(state).split_for_parts();
    if let Some(authenticator) = authenticator {
        router = router.layer(axum::middleware::from_fn_with_state(
            authenticator,
            authn::jwt_auth_middleware,
        ));
    }
    metrics_layer::describe_rest_metrics();
    // Tracing is the outermost layer so authn rejections are also logged
    // under the request span; metrics layer is next in so it times the
    // full handler including authn.
    Ok(router
        .layer(axum::middleware::from_fn(
            metrics_layer::record_request_metrics,
        ))
        .layer(axum::middleware::from_fn(trace::span_per_request)))
}

mod helpers;
mod management;
mod objects;

#[allow(unused_imports)]
pub use helpers::*;
pub use management::*;
pub use objects::*;

#[cfg(test)]
mod tests;
