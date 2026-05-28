// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async Azure REST client used by `backend.rs`.
//!
//! Owns one async `reqwest::Client` per backend and applies whichever
//! credential the connection resolved to: Shared Key signing, Bearer header
//! from Entra OAuth2, or a SAS token appended to the URL. Requests outside the
//! data path (single-shot `Put Blob`, `Get Blob Properties`, `Set Blob
//! Metadata`, `List Blobs`, `Put Block List`, HNS path operations) flow
//! through here. Stage-block uploads escape this client because they are
//! delegated to the host follower as `WriteRedirect`s; only the commit hop
//! returns to this client.

use std::sync::Arc;
use std::time::Duration;

use ovstorage_plugin::{ConnectionId, Error, ErrorCode, ErrorContext, Result};
use reqwest::header::{HeaderMap as ReqHeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method, RequestBuilder, Response};

use crate::auth::{AuthSource, AzureAuth};
use crate::parse::HeaderMap;
use crate::signing::{
    DEFAULT_SAS_VERSION, SharedKeyRequest, shared_key_authorization_value, shared_key_signature,
    shared_key_string_to_sign,
};

const X_MS_VERSION: &str = "x-ms-version";
const X_MS_DATE: &str = "x-ms-date";

pub(crate) struct AzureRequest<'a> {
    pub method: Method,
    pub url: String,
    pub canonical_path: &'a str,
    pub canonical_query: Vec<(String, String)>,
    pub extra_headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub content_md5: Option<String>,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    pub range: Option<String>,
    pub body: Option<Vec<u8>>,
}

pub(crate) struct AzureResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl AzureResponse {
    pub fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    pub fn body_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.body).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("Azure response body is not valid UTF-8: {e}"),
            )
        })
    }
}

#[derive(Clone)]
pub(crate) struct AzureClient {
    http: Client,
    auth: Arc<AzureAuth>,
    account: String,
}

impl AzureClient {
    pub fn new(account: String, auth: AzureAuth) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to build Azure HTTP client: {e}"),
                )
            })?;
        let auth = Arc::new(auth);
        // Proactively refresh OAuth bearers at ~90% of TTL so
        // long-lived processes don't hit `Unauthenticated` mid-RPC.
        // No-op for SharedKey/SAS/Anonymous sources (nothing to
        // refresh). The task holds only `Weak<AzureAuth>` and aborts
        // on `Drop` of the last `Arc`.
        auth.install_background_refresh(AzureAuth::DEFAULT_REFRESH_INTERVAL);
        Ok(Self {
            http,
            auth,
            account,
        })
    }

    pub fn auth(&self) -> &AzureAuth {
        &self.auth
    }

    pub fn http(&self) -> &Client {
        &self.http
    }

    #[allow(dead_code)]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Send a request, signing it with whichever auth the connection resolved to.
    pub async fn send(&self, req: AzureRequest<'_>) -> Result<AzureResponse> {
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let mut headers: Vec<(String, String)> = Vec::new();
        headers.push((X_MS_VERSION.into(), DEFAULT_SAS_VERSION.into()));
        headers.push((X_MS_DATE.into(), date));
        for (name, value) in &req.extra_headers {
            headers.push((name.clone(), value.clone()));
        }

        let body_len = req.body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
        let mut url = req.url.clone();

        match self.auth.source() {
            AuthSource::Sas { sas_token } => {
                let separator = if url.contains('?') { '&' } else { '?' };
                url.push(separator);
                url.push_str(sas_token);
            }
            AuthSource::SharedKey { account_key_bytes } => {
                let signing_request = SharedKeyRequest {
                    method: req.method.as_str(),
                    account: &self.account,
                    canonical_path: req.canonical_path,
                    canonical_query: &req.canonical_query,
                    headers: &headers,
                    content_length: if body_len == 0 { None } else { Some(body_len) },
                    content_type: req.content_type.as_deref(),
                    content_md5: req.content_md5.as_deref(),
                    if_match: req.if_match.as_deref(),
                    if_none_match: req.if_none_match.as_deref(),
                    range: req.range.as_deref(),
                };
                let canonical = shared_key_string_to_sign(&signing_request);
                let signature = shared_key_signature(account_key_bytes, &canonical)?;
                let auth_value = shared_key_authorization_value(&self.account, &signature);
                headers.push(("Authorization".into(), auth_value));
            }
            AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
                let bearer = self.auth.bearer_token(&self.http).await?;
                headers.push(("Authorization".into(), format!("Bearer {bearer}")));
            }
            AuthSource::Anonymous => {}
        }

        let mut builder: RequestBuilder = self.http.request(req.method.clone(), &url);
        if let Some(content_type) = req.content_type.as_deref() {
            builder = builder.header("Content-Type", content_type);
        }
        if let Some(content_md5) = req.content_md5.as_deref() {
            builder = builder.header("Content-MD5", content_md5);
        }
        if let Some(if_match) = req.if_match.as_deref() {
            // Azure requires RFC 7232 entity-tag quoting on conditional
            // headers; the SPI documents `if_match` as the raw etag
            // value the backend handed back. `quote_etag` is a no-op
            // if the caller already supplied the quoted form.
            builder = builder.header("If-Match", crate::backend::quote_etag(if_match));
        }
        if let Some(if_none_match) = req.if_none_match.as_deref() {
            // `If-None-Match: *` is the only wildcard the no-overwrite
            // path uses; everything else is an entity-tag that must
            // round-trip through `quote_etag`.
            let value = if if_none_match == "*" {
                if_none_match.to_string()
            } else {
                crate::backend::quote_etag(if_none_match)
            };
            builder = builder.header("If-None-Match", value);
        }
        if let Some(range) = req.range.as_deref() {
            builder = builder.header("Range", range);
        }
        builder = builder.headers(to_reqwest_headers(&headers)?);
        if let Some(body) = req.body {
            builder = builder.body(body);
        }
        let response: Response = builder.send().await.map_err(|e| {
            Error::new(
                ErrorCode::Transient,
                format!("Azure request failed for {}: {e}", req.url),
            )
        })?;
        let status = response.status().as_u16();
        let mut header_map = HeaderMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                header_map.insert(name.as_str(), value_str);
            }
        }
        let body = response.bytes().await.map_err(|e| {
            Error::new(
                ErrorCode::Transient,
                format!("Azure response body read failed: {e}"),
            )
        })?;
        Ok(AzureResponse {
            status,
            headers: header_map,
            body: body.to_vec(),
        })
    }
}

fn to_reqwest_headers(headers: &[(String, String)]) -> Result<ReqHeaderMap> {
    let mut map = ReqHeaderMap::new();
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("invalid header name '{name}': {e}"),
            )
        })?;
        let header_value = HeaderValue::from_str(value).map_err(|e| {
            Error::new(
                ErrorCode::Internal,
                format!("invalid header value for '{name}': {e}"),
            )
        })?;
        map.append(header_name, header_value);
    }
    Ok(map)
}

/// Translate a non-2xx Azure response into the typed error code best matching the HTTP status.
///
/// 401 → `AuthRequired` so the host's `with_route_retry` invalidates cached creds and retries
/// with fresh Bearer/SAS/shared-key signatures. 403 → `PermissionDenied` (final): the principal
/// is authenticated but the RBAC role on the container/blob lacks the operation.
pub(crate) fn map_status_to_error(response: &AzureResponse, operation: &str) -> Error {
    let status = response.status;
    let body_text = std::str::from_utf8(&response.body).unwrap_or("");
    let trimmed = if body_text.len() > 512 {
        &body_text[..512]
    } else {
        body_text
    };
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("Azure {operation} requires authentication (HTTP 401): {trimmed}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("azure_unauthorized".into()),
            expired_at: None,
        });
    }
    let code = match status {
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        409 => ErrorCode::AlreadyExists,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        // match-arm order matters: 408/504 + 429/503 must precede the 500..=599 catchall.
        408 | 504 => ErrorCode::DeadlineExceeded,
        429 | 503 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Transient,
    };
    Error::new(
        code,
        format!("Azure {operation} returned HTTP {status}: {trimmed}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_status(status: u16, body: &[u8]) -> AzureResponse {
        AzureResponse {
            status,
            headers: HeaderMap::default(),
            body: body.to_vec(),
        }
    }

    #[test]
    fn map_status_to_error_401_is_auth_required_with_context() {
        let response = response_with_status(401, b"<Error>InvalidAuthenticationInfo</Error>");
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("azure_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn map_status_to_error_403_is_permission_denied_no_context() {
        let response = response_with_status(403, b"<Error>AuthorizationFailure</Error>");
        let err = map_status_to_error(&response, "GetBlob");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn map_status_to_error_404_410_are_not_found() {
        let r404 = response_with_status(404, b"<Error>BlobNotFound</Error>");
        assert_eq!(
            map_status_to_error(&r404, "GetBlob").code(),
            ErrorCode::NotFound
        );
        let r410 = response_with_status(410, b"");
        assert_eq!(
            map_status_to_error(&r410, "GetBlob").code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn map_status_to_error_412_is_precondition_failed() {
        let r = response_with_status(412, b"<Error>ConditionNotMet</Error>");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::PreconditionFailed
        );
    }

    #[test]
    fn map_status_to_error_416_is_invalid_argument() {
        let r = response_with_status(416, b"<Error>InvalidRange</Error>");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn map_status_to_error_408_504_are_deadline_exceeded() {
        let r408 = response_with_status(408, b"");
        assert_eq!(
            map_status_to_error(&r408, "GetBlob").code(),
            ErrorCode::DeadlineExceeded
        );
        let r504 = response_with_status(504, b"");
        assert_eq!(
            map_status_to_error(&r504, "GetBlob").code(),
            ErrorCode::DeadlineExceeded
        );
    }

    #[test]
    fn map_status_to_error_429_503_are_resource_exhausted() {
        let r429 = response_with_status(429, b"<Error>ServerBusy</Error>");
        assert_eq!(
            map_status_to_error(&r429, "GetBlob").code(),
            ErrorCode::ResourceExhausted
        );
        let r503 = response_with_status(503, b"<Error>ServerBusy</Error>");
        assert_eq!(
            map_status_to_error(&r503, "GetBlob").code(),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn map_status_to_error_500_502_are_transient() {
        let r500 = response_with_status(500, b"");
        assert_eq!(
            map_status_to_error(&r500, "GetBlob").code(),
            ErrorCode::Transient
        );
        let r502 = response_with_status(502, b"");
        assert_eq!(
            map_status_to_error(&r502, "GetBlob").code(),
            ErrorCode::Transient
        );
    }

    /// Unknown 5xx surfaces as Transient (library will retry).
    #[test]
    fn map_status_to_error_unknown_5xx_is_transient() {
        let r = response_with_status(599, b"");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::Transient
        );
    }

    /// Unknown non-5xx still surfaces as Transient (proxy/gateway weirdness),
    /// never Internal — Internal is reserved for plugin-detected logic bugs.
    #[test]
    fn map_status_to_error_unknown_non_5xx_is_transient() {
        let r = response_with_status(418, b"");
        assert_eq!(
            map_status_to_error(&r, "GetBlob").code(),
            ErrorCode::Transient
        );
    }
}
