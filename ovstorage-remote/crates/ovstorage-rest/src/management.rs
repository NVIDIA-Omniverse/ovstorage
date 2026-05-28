// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// Register a new connection (and its address roots) at runtime.
///
/// `backend_kind` must appear in `GET /v1/backend-kinds` with
/// `supports_runtime_add: true`. The resulting connection's
/// address roots show up in `GET /v1/address-roots`.
#[utoipa::path(
    post,
    path = "/v1/connections",
    tag = "connections",
    request_body = schema::AddConnectionBody,
    responses((status = 200, body = schema::ConnectionResponse)),
)]
pub(crate) async fn add_connection(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Json(body): Json<schema::AddConnectionBody>,
) -> Response {
    tracing::info!(target: "ovstorage.rest", op = "add_connection", principal_id = %principal.id, "management handler entry");
    if let Err(error) = authorize_op(&authz, &principal, Operation::AddConnection, None).await {
        return error_response(error);
    }
    let mut config = HashMap::new();
    for (key, value) in body.config {
        let v = match value {
            serde_json::Value::String(s) => ConfigValue::String(s),
            serde_json::Value::Bool(b) => ConfigValue::Bool(b),
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(i) => ConfigValue::Int(i),
                None => {
                    return error_response(invalid("non-integer numbers not supported in config"));
                }
            },
            _ => return error_response(invalid("config values must be string, bool, or integer")),
        };
        config.insert(key, v);
    }
    let mut credentials = SecretBundle::default();
    for (key, value) in body.credentials {
        credentials
            .fields
            .insert(key, SecretValue::Bytes(SecretBytes(value.into_bytes())));
    }
    let request = ConnectionRequest {
        backend_kind: body.backend_kind,
        config,
        credentials,
        persist: body.persist,
        display_name: body.display_name,
    };
    match library.add_connection(request, None).await {
        Ok(connection) => Json(to_connection(&connection)).into_response(),
        Err(error) => error_response(error),
    }
}

/// Remove a connection. Its address roots unregister; in-flight
/// requests against them complete with `NoRoute`.
#[utoipa::path(
    delete,
    path = "/v1/connections/{id}",
    tag = "connections",
    params(("id" = String, Path, description = "Connection ID from POST /v1/connections")),
    responses((status = 204, description = "Removed")),
)]
pub(crate) async fn remove_connection(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Path(id): Path<String>,
) -> Response {
    if let Err(error) = authorize_op(&authz, &principal, Operation::RemoveConnection, None).await {
        return error_response(error);
    }
    match library.remove_connection(&ConnectionId(id)) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

/// List every connection currently registered with the gateway.
#[utoipa::path(
    get,
    path = "/v1/connections",
    tag = "connections",
    responses((status = 200, body = schema::ConnectionList)),
)]
pub(crate) async fn list_connections(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
) -> Response {
    if let Err(error) = authorize_op(&authz, &principal, Operation::ListConnections, None).await {
        return error_response(error);
    }
    match library.list_connections() {
        Ok(items) => Json(schema::ConnectionList {
            items: items.iter().map(to_connection).collect(),
        })
        .into_response(),
        Err(error) => error_response(error),
    }
}

/// Initiate a connection's authentication flow as an SSE stream of
/// `AuthEventResponse`; terminal events are `succeeded`/`failed`/`cancelled`.
#[utoipa::path(
    post,
    path = "/v1/connections:authenticate",
    tag = "connections",
    params(("id" = String, Query, description = "Connection ID")),
    responses((status = 200, description = "SSE stream of AuthEventResponse JSON frames", body = schema::AuthEventResponse, content_type = "text/event-stream")),
)]
pub(crate) async fn authenticate_connection_sse(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Err(error) = authorize_op(
        &authz,
        &principal,
        Operation::UpdateConnectionCredentials,
        None,
    )
    .await
    {
        return error_response(error);
    }
    let id = match required_param(&params, "id") {
        Ok(id) => id,
        Err(error) => return error_response(error),
    };
    let stream = match library
        .authenticate_connection(&ConnectionId(id), None)
        .await
    {
        Ok(stream) => stream,
        Err(error) => return error_response(error),
    };
    let (sender, receiver) =
        tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(16);
    std::thread::Builder::new()
        .name("ovs-rest-auth".into())
        .spawn(move || {
            for event in stream {
                let payload = match event {
                    Ok(ev) => match Event::default().json_data(to_auth_event(&ev)) {
                        Ok(ev) => ev,
                        Err(_) => continue,
                    },
                    Err(err) => Event::default().event("error").data(format!(
                        r#"{{"code":"{:?}","message":{:?}}}"#,
                        err.code(),
                        err.message()
                    )),
                };
                if sender.blocking_send(Ok(payload)).is_err() {
                    break;
                }
            }
        })
        .expect("failed to spawn thread");
    Sse::new(ReceiverStream::new(receiver))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Register an alias: requests to `from` resolve as if they targeted `to`.
#[utoipa::path(
    post,
    path = "/v1/aliases",
    tag = "aliases",
    request_body = schema::AddAliasBody,
    responses((status = 200, body = schema::AliasResponse)),
)]
pub(crate) async fn add_alias(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Json(body): Json<schema::AddAliasBody>,
) -> Response {
    let from = match address::parse(&body.from) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    let to = match address::parse(&body.to) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    // Security invariant: AddAlias requires AddAlias on `from` AND Read
    // on `to` — you can't alias to data you couldn't read yourself,
    // since any caller hitting `from` would gain that access.
    if let Err(error) = authorize_op(&authz, &principal, Operation::AddAlias, Some(&from)).await {
        return error_response(error);
    }
    if let Err(error) = authorize_op(&authz, &principal, Operation::Read, Some(&to)).await {
        return error_response(error);
    }
    let visibility = match parse_visibility(body.visibility.as_deref()) {
        Ok(v) => v,
        Err(error) => return error_response(error),
    };
    let request = AliasRequest {
        from,
        to,
        visibility,
        persist: body.persist,
        display_name: body.display_name,
        user_metadata: UserMetadata::new(),
    };
    match library.add_alias(request) {
        Ok(alias) => Json(to_alias(&alias)).into_response(),
        Err(error) => error_response(error),
    }
}

/// Remove an alias.
#[utoipa::path(
    delete,
    path = "/v1/aliases/{id}",
    tag = "aliases",
    params(("id" = String, Path, description = "Alias ID from POST /v1/aliases")),
    responses((status = 204, description = "Removed")),
)]
pub(crate) async fn remove_alias(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Path(id): Path<String>,
) -> Response {
    if let Err(error) = authorize_op(&authz, &principal, Operation::RemoveAlias, None).await {
        return error_response(error);
    }
    match library.remove_alias(&AliasId(id)) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error_response(error),
    }
}

/// List every alias currently registered.
#[utoipa::path(
    get,
    path = "/v1/aliases",
    tag = "aliases",
    responses((status = 200, body = schema::AliasList)),
)]
pub(crate) async fn list_aliases(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
) -> Response {
    if let Err(error) = authorize_op(&authz, &principal, Operation::ListAliases, None).await {
        return error_response(error);
    }
    match library.list_aliases() {
        Ok(items) => Json(schema::AliasList {
            items: items.iter().map(to_alias).collect(),
        })
        .into_response(),
        Err(error) => error_response(error),
    }
}

/// Set a visibility override: `visible` lists the address, `hidden`
/// keeps it functional but unlisted, `suppressed` removes it from listings.
#[utoipa::path(
    put,
    path = "/v1/address-visibility",
    tag = "visibility",
    request_body = schema::SetVisibilityBody,
    responses((status = 200, body = schema::VisibilityOverrideResponse)),
)]
pub(crate) async fn set_visibility(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
    Json(body): Json<schema::SetVisibilityBody>,
) -> Response {
    let address = match address::parse(&body.address) {
        Ok(a) => a,
        Err(error) => return error_response(error),
    };
    if let Err(error) = authorize_op(
        &authz,
        &principal,
        Operation::SetAddressVisibility,
        Some(&address),
    )
    .await
    {
        return error_response(error);
    }
    let visibility = match parse_visibility(Some(&body.visibility)) {
        Ok(v) => v,
        Err(error) => return error_response(error),
    };
    match library.set_address_visibility(address, visibility, body.persist) {
        Ok(override_) => Json(to_visibility_override(&override_)).into_response(),
        Err(error) => error_response(error),
    }
}

/// List active visibility overrides.
#[utoipa::path(
    get,
    path = "/v1/address-visibility",
    tag = "visibility",
    responses((status = 200, body = schema::VisibilityList)),
)]
pub(crate) async fn list_visibility(
    State(library): State<Arc<Library>>,
    State(authz): State<AuthzState>,
    Caller(principal): Caller,
) -> Response {
    if let Err(error) =
        authorize_op(&authz, &principal, Operation::SetAddressVisibility, None).await
    {
        return error_response(error);
    }
    match library.list_address_visibility_overrides() {
        Ok(items) => Json(schema::VisibilityList {
            items: items.iter().map(to_visibility_override).collect(),
        })
        .into_response(),
        Err(error) => error_response(error),
    }
}
