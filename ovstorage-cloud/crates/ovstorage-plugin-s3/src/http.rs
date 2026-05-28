// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Async reqwest wrapper for direct S3 API calls (HEAD/LIST/DELETE/etc.).
//! Presigned read/write traffic flows through the host redirect-follower instead.

use std::time::Duration;

use ovstorage_plugin::{ConnectionId, Error, ErrorCode, ErrorContext, Result};
use reqwest::Client;

/// One client per backend instance — gives each connection its own trust scope.
pub fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("S3 HTTP client init failed: {err}"),
            )
        })
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[allow(dead_code)]
    pub fn into_text(self) -> Result<String> {
        String::from_utf8(self.body)
            .map_err(|_| Error::new(ErrorCode::Internal, "S3 response body was not valid UTF-8"))
    }
}

pub async fn execute(
    client: &Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpResponse> {
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid HTTP method '{method}': {err}"),
        )
    })?;
    let mut builder = client.request(method, url);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(name, value);
    }
    if !body.is_empty() {
        builder = builder.body(body.to_vec());
    }
    let response = builder
        .send()
        .await
        .map_err(|err| Error::new(ErrorCode::Transient, format!("S3 request failed: {err}")))?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let body = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("S3 response body could not be read: {err}"),
        )
    })?;
    Ok(HttpResponse {
        status,
        headers,
        body: body.to_vec(),
    })
}

/// Map an S3 HTTP status to a typed `ErrorCode`.
pub fn map_error_status(status: u16, body: &[u8]) -> Error {
    let summary = String::from_utf8_lossy(body);
    let summary = summary.trim();
    let trail = if summary.is_empty() {
        String::new()
    } else if summary.len() > 256 {
        format!(": {}…", &summary[..256])
    } else {
        format!(": {summary}")
    };
    match status {
        // 401 → AuthRequired so host with_route_retry invalidates cached creds and retries once.
        401 => Error::new(
            ErrorCode::AuthRequired,
            format!("S3 request requires authentication (HTTP 401){trail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("s3_unauthorized".into()),
            expired_at: None,
        }),
        403 => Error::new(
            ErrorCode::PermissionDenied,
            format!("S3 request forbidden (HTTP 403){trail}"),
        ),
        404 | 410 => Error::new(
            ErrorCode::NotFound,
            format!("S3 object not found (HTTP {status}){trail}"),
        ),
        409 => Error::new(
            ErrorCode::Conflict,
            format!("S3 reported conflict (HTTP 409){trail}"),
        ),
        412 => Error::new(
            ErrorCode::PreconditionFailed,
            format!("S3 precondition failed (HTTP 412){trail}"),
        ),
        416 => Error::new(
            ErrorCode::InvalidArgument,
            format!("S3 range not satisfiable (HTTP 416){trail}"),
        ),
        // match-arm order matters: 408/504 + 429/503 must precede the 500..=599 catchall.
        408 | 504 => Error::new(
            ErrorCode::DeadlineExceeded,
            format!("S3 deadline exceeded (HTTP {status}){trail}"),
        ),
        429 | 503 => Error::new(
            ErrorCode::ResourceExhausted,
            format!("S3 rate-limited (HTTP {status}){trail}"),
        ),
        500..=599 => Error::new(
            ErrorCode::Transient,
            format!("S3 returned transient HTTP {status}{trail}"),
        ),
        status => Error::new(
            ErrorCode::Transient,
            format!("S3 returned unexpected HTTP {status}{trail}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 401 must surface as AuthRequired so with_route_retry invalidates cached creds.
    #[test]
    fn map_error_status_401_is_auth_required() {
        let err = map_error_status(401, b"signature mismatch");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("s3_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    /// 403 stays PermissionDenied with no Auth context; reauth wouldn't change the outcome.
    #[test]
    fn map_error_status_403_is_permission_denied() {
        let err = map_error_status(403, b"AccessDenied");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    #[test]
    fn map_error_status_412_is_precondition_failed() {
        let err = map_error_status(412, b"PreconditionFailed");
        assert_eq!(err.code(), ErrorCode::PreconditionFailed);
    }

    #[test]
    fn map_error_status_410_is_not_found() {
        let err = map_error_status(410, b"NoSuchKey");
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn map_error_status_416_is_invalid_argument() {
        let err = map_error_status(416, b"InvalidRange");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn map_error_status_408_504_are_deadline_exceeded() {
        assert_eq!(
            map_error_status(408, b"").code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            map_error_status(504, b"").code(),
            ErrorCode::DeadlineExceeded
        );
    }

    #[test]
    fn map_error_status_429_503_are_resource_exhausted() {
        assert_eq!(
            map_error_status(429, b"SlowDown").code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            map_error_status(503, b"ServiceUnavailable").code(),
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn map_error_status_500_502_are_transient() {
        assert_eq!(map_error_status(500, b"").code(), ErrorCode::Transient);
        assert_eq!(map_error_status(502, b"").code(), ErrorCode::Transient);
    }

    /// Unknown statuses surface as Transient (not Internal): unknown gateway/proxy
    /// errors are still upstream failures, not plugin logic bugs.
    #[test]
    fn map_error_status_unknown_is_transient() {
        assert_eq!(map_error_status(418, b"").code(), ErrorCode::Transient);
    }
}
