// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

pub mod metrics_layer;
mod schema;
mod trace;

#[cfg(test)]
mod test_utils;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use ovstorage::{
    AccessOps, AddressRoot, Body, ByteRange, ChangeEvent, ChangeKind, CheckAccessRequest,
    CopyOptions, CopyRequest, CreateDirectoryOptions, CreateDirectoryRequest,
    DeleteDirectoryOptions, DeleteDirectoryRequest, DeleteOptions, DeleteRequest, Error, ErrorCode,
    IfDestExists, Layer, ListOptions, ListRequest, ListVersionsOptions, ListVersionsRequest,
    ObjectInfo, ReadOptions, ReadRequest, ReadResult, RenameOptions, RenameRequest, Request,
    RootInfo, Stack, StatOptions, StatRequest, StorageBackendKindDescriptor, UpdateMetadataOptions,
    UpdateMetadataRequest, Url, WatchDirectoryCursor, WatchDirectoryOptions, WatchDirectoryRequest,
    WriteOptions, WriteRequest, WriteStep, address,
};
use ovstorage_authz_context::{AuthCredential, Transport, bearer_from_authorization_value};
use ovstorage_authz_layer::{ListenerAuth, stamp_credential};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;

/// Aggregate state every handler extracts from via `FromRef`.
#[derive(Clone)]
pub struct AppState {
    /// The gateway's selected per-listener auth layer `attach`ed over the
    /// shared auth-free inner
    /// (`alias → copy_rename_fallback →
    /// redirect_follower(follow_reads=false) → router →
    /// [attribution_<kind> →] backend-per-kind`, the attribution overlay sitting
    /// per-branch below the router).
    /// Handlers dispatch every object/discovery op through its `Layer`-trait
    /// surface; the auth layer resolves the caller's `ext::AUTH_CREDENTIAL`,
    /// authorizes, and stamps `ext::PRINCIPAL_ID` DOWN. REST is single-listener
    /// (N=1): this is one shared auth Stack, not a fan-out of per-listener
    /// instances (the `attach`/shared-inner design supports N>1, uninstantiated).
    pub stack: Arc<Stack>,
    /// The selected listener-auth handle. `GET /v1/backend-kinds` is served from
    /// the captured set below, so its handler uses this handle for the gate.
    pub auth_layer: ListenerAuth,
    /// Connectable backend kinds, captured at build time from the loaded plugin
    /// factories: the immutable Stack only advertises *connected* kinds via
    /// `list_kinds`, so `GET /v1/backend-kinds` reads this instead.
    pub backend_kinds: Arc<Vec<StorageBackendKindDescriptor>>,
    /// The operator's redirect credential disclosure policy, extracted by the
    /// read handler's `307` arm. See [`RedirectDisclosure`].
    pub disclose_redirect_credentials: bool,
    /// Pre-rendered OpenAPI JSON, built once so spec endpoints skip per-request serialization.
    openapi_json: Arc<String>,
    openapi_yaml: Arc<String>,
}

/// The operator's `redirect_credential_disclosure`, as the read handler sees it.
///
/// The gateway's out-edge copy of a policy the in-graph follower also holds. The
/// follower applies it first and can degrade gracefully — it fetches the bytes
/// itself and returns a stream. This copy is the guarantee: the layer graph is
/// operator config and may rename or omit the follower, so a policy that lived
/// only there would silently vanish from such a deployment and the `307` arm
/// would forward whatever the graph left it.
///
/// A `307` carries no request headers (the read handler emits only
/// `Location` and `X-OV-Audit-Id`), so what this gates is a credential riding in
/// the redirect **URL** — an operator-supplied Azure `sas_token`, say.
#[derive(Clone, Copy)]
pub struct RedirectDisclosure(pub bool);

/// The connectable backend kinds, extracted by the `list_backend_kinds` handler.
#[derive(Clone)]
pub struct BackendKinds(pub Arc<Vec<StorageBackendKindDescriptor>>);

impl FromRef<AppState> for Arc<Stack> {
    fn from_ref(s: &AppState) -> Self {
        s.stack.clone()
    }
}

impl FromRef<AppState> for BackendKinds {
    fn from_ref(s: &AppState) -> Self {
        BackendKinds(s.backend_kinds.clone())
    }
}

impl FromRef<AppState> for RedirectDisclosure {
    fn from_ref(s: &AppState) -> Self {
        RedirectDisclosure(s.disclose_redirect_credentials)
    }
}

impl FromRef<AppState> for ListenerAuth {
    fn from_ref(s: &AppState) -> Self {
        s.auth_layer.clone()
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

/// Per-request credential-gathering seam. It collects the
/// caller's [`AuthCredential`] from the HTTP request — the UNDECODED bearer from
/// the `Authorization` header (scheme prefix stripped) plus the TCP peer address
/// from the connection — and stamps it under
/// [`ovstorage::wrappers::ext::AUTH_CREDENTIAL`] on a
/// **fresh** [`Extensions`](ovstorage::Extensions) bag. The per-listener auth
/// layer resolves identity from it and stamps
/// [`ovstorage::wrappers::ext::PRINCIPAL_ID`] DOWN; the
/// host performs no authentication, authorization, or principal resolution.
///
/// **Security invariant (credential-injection).** The bag starts at
/// [`Extensions::new()`](ovstorage::Extensions) — the handler NEVER merges
/// client-supplied extensions into a request, so a network client cannot inject
/// `ext::PRINCIPAL_ID` (or any downstream extension) to impersonate a principal:
/// only the gathered `AUTH_CREDENTIAL` crosses this seam, and only the auth layer
/// stamps `PRINCIPAL_ID` (DOWN, from its own resolution). Every Stack request a
/// handler dispatches is built through `CallCx::request` / `CallCx::extensions`;
/// there is no other seam.
pub struct CallCx {
    stamped: ovstorage::Extensions,
}

impl CallCx {
    /// Wrap `input` in a Stack [`Request`] carrying the caller's gathered
    /// credential. One seam for every op the handler dispatches to the Stack.
    pub(crate) fn request<T>(&self, input: T) -> Request<T> {
        Request {
            extensions: self.stamped.clone(),
            input,
        }
    }

    /// The fresh credential-stamped extensions bag, for the introspection slots
    /// that take a bare `&Extensions` (`list_address_roots` / `root_info_for`).
    pub(crate) fn extensions(&self) -> ovstorage::Extensions {
        self.stamped.clone()
    }
}

impl FromRequestParts<AppState> for CallCx {
    type Rejection = Infallible;
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(bearer_from_authorization_value);
        // Best-effort peer address: the axum server is served with
        // `ConnectInfo<SocketAddr>` in production; absent it (e.g. the tower
        // `oneshot` test harness) the auth layer's `Tcp` resolution keys on the
        // bearer only, so an empty peer address is harmless.
        let peer_addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.to_string())
            .unwrap_or_default();
        let credential = AuthCredential::new(
            bearer,
            Transport::Tcp {
                peer_addr,
                tls_client_cert: None,
            },
        );
        // FRESH bag — never merged with client/header-supplied extensions.
        Ok(Self {
            stamped: stamp_credential(Some(&credential)),
        })
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

/// Build the REST router fronting the gateway's per-listener auth [`Stack`].
///
/// Authentication, authorization, and principal resolution all live in the
/// gateway's selected auth layer; each handler gathers the
/// caller's credential through the [`CallCx`] seam and dispatches into that
/// layer. The attribution strategy is chosen at Stack-compose time
/// ([`GatewayStackBuilder::attribution_strategy`]), not here.
pub fn router(gateway: GatewayStack) -> Router {
    let api = openapi_spec();
    let openapi_json = Arc::new(serde_json::to_string(&api).expect("OpenAPI JSON"));
    let openapi_yaml = Arc::new(serde_yaml::to_string(&api).expect("OpenAPI YAML"));
    let state = AppState {
        stack: gateway.stack,
        auth_layer: gateway.auth_layer,
        backend_kinds: Arc::new(gateway.backend_kinds),
        disclose_redirect_credentials: gateway.disclose_redirect_credentials,
        openapi_json,
        openapi_yaml,
    };
    let (router, _) = build_open_api_router().with_state(state).split_for_parts();
    metrics_layer::describe_rest_metrics();
    // Tracing is the outermost layer so every request is logged under the
    // request span; metrics layer is next in so it times the full handler.
    router
        .layer(axum::middleware::from_fn(
            metrics_layer::record_request_metrics,
        ))
        .layer(axum::middleware::from_fn(trace::span_per_request))
}

mod helpers;
mod objects;
mod stack;

#[allow(unused_imports)]
pub use helpers::*;
pub use objects::*;
pub use stack::{GatewayStack, GatewayStackBuilder, RestJwtParams, rest_stack_config};

#[cfg(test)]
mod tests;
