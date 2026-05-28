// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! REST authn middleware: OIDC bearer JWT validation.
//!
//! On success the validated `Principal` is attached to the request as
//! an extension; handlers extract it via `Extension<Principal>`.
//! Basic auth and API keys are out of scope and return `401`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use ovstorage::ErrorCode;
use ovstorage_authz::Principal;
use serde_json::json;

use crate::JwtAuthenticator;

/// Axum middleware requiring a valid OIDC bearer token; returns `401`
/// on missing/invalid tokens and populates `Extension<Principal>` on success.
pub async fn jwt_auth_middleware(
    State(authenticator): State<Arc<JwtAuthenticator>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    let bearer = match extract_bearer(&headers) {
        Ok(b) => b,
        Err(reason) => {
            tracing::debug!(
                target: "ovstorage.rest.authn",
                outcome = "reject",
                reason = %reason,
                "authn rejected: bearer token extraction failed"
            );
            return unauthorized(reason);
        }
    };
    match authenticator.authenticate(&bearer).await {
        Ok(principal) => {
            tracing::debug!(
                target: "ovstorage.rest.authn",
                principal_id = %principal.id,
                principal_kind = "jwt",
                outcome = "ok",
                "authn succeeded"
            );
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => {
            tracing::debug!(
                target: "ovstorage.rest.authn",
                error_code = ?error.code(),
                outcome = "reject",
                "authn rejected: token validation failed"
            );
            unauthorized(error.message().to_string())
        }
    }
}

fn extract_bearer(headers: &HeaderMap) -> Result<String, String> {
    let value = headers
        .get("authorization")
        .ok_or_else(|| "missing Authorization header".to_string())?;
    let text = value
        .to_str()
        .map_err(|_| "Authorization header is not valid UTF-8".to_string())?;
    let token = text
        .strip_prefix("Bearer ")
        .or_else(|| text.strip_prefix("bearer "))
        .ok_or_else(|| {
            "only Bearer scheme is accepted (Basic / API key are not supported)".to_string()
        })?;
    if token.is_empty() {
        return Err("Bearer token is empty".to_string());
    }
    Ok(token.to_string())
}

fn unauthorized(reason: impl Into<String>) -> Response {
    let reason = reason.into();
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "code": format!("{:?}", ErrorCode::AuthRequired),
                "message": reason,
            }
        })),
    )
        .into_response()
}

/// Returns the authenticated principal, falling back to anonymous when
/// the middleware is not layered (dev mode).
#[allow(dead_code)]
pub(crate) fn principal_or_anonymous(extension: Option<axum::Extension<Principal>>) -> Principal {
    extension.map(|e| e.0).unwrap_or_else(Principal::anonymous)
}
