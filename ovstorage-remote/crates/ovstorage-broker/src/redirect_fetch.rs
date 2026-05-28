// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Broker-side redirect follower for fetching + caching sub-threshold
//! plugin-driven `ReadResult::Redirect` payloads.
//!
//! DoS gating: read at most `cache_max_object_bytes` from the response.
//! Responses without `Content-Length` are NOT fetched — "size unknown"
//! + "cache cap" together imply a hostile upstream could fill the cap.

use std::time::SystemTime;

use ovstorage::{Error, ErrorCode, ObjectInfo, ObjectKind, ReadRedirect, Url};
use reqwest::header::LOCATION;
use tracing::Instrument;

use crate::trace::RedactedUrl;

#[derive(Debug)]
pub enum RedirectFetchOutcome {
    /// Body fits the cap; ready to insert + serve.
    Fetched { bytes: Vec<u8>, info: ObjectInfo },
    /// Forward the redirect to the client unchanged.
    NotCacheable { reason: NotCacheableReason },
}

#[derive(Debug, Clone, Copy)]
pub enum NotCacheableReason {
    UnknownSize,
    Oversized { reported: u64, cap: u64 },
}

const MAX_REDIRECT_HOPS: usize = 10;

/// HTTP client used by broker fetch-through. Redirects are handled
/// manually below so all 3xx responses, including 300 with `Location`,
/// can be constrained to the redirect's original origin.
pub(crate) fn redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("redirect-disabled reqwest client builder should not fail")
}

/// Follow a `ReadRedirect` with the DoS gate.
pub async fn follow_read_redirect(
    client: &reqwest::Client,
    redirect: &ReadRedirect,
    address: &Url,
    cache_max_object_bytes: u64,
) -> ovstorage::Result<RedirectFetchOutcome> {
    let span = tracing::info_span!(
        "broker.redirect",
        op = "read",
        audit_id = %redirect.audit_id,
        policy_epoch = redirect.policy_epoch,
        object.address = %RedactedUrl(address),
        redirect.kind = "fetch-through",
        outcome = tracing::field::Empty,
    );
    async move {
        let result =
            follow_read_redirect_inner(client, redirect, address, cache_max_object_bytes).await;
        match &result {
            Ok(RedirectFetchOutcome::Fetched { .. }) => {
                tracing::info!(
                    target: "ovstorage.broker.redirect",
                    redirect_kind = "fetch-through",
                    "redirect kind chosen"
                );
                tracing::Span::current().record("outcome", "ok");
            }
            Ok(RedirectFetchOutcome::NotCacheable { reason }) => {
                let reason_str = match reason {
                    NotCacheableReason::UnknownSize => "unknown-size",
                    NotCacheableReason::Oversized { .. } => "oversized",
                };
                tracing::info!(
                    target: "ovstorage.broker.redirect",
                    redirect_kind = "passthrough",
                    not_cacheable_reason = reason_str,
                    "redirect kind chosen"
                );
                tracing::Span::current().record("outcome", "ok");
            }
            Err(_) => {
                tracing::Span::current().record("outcome", "err");
            }
        }
        result
    }
    .instrument(span)
    .await
}

async fn follow_read_redirect_inner(
    client: &reqwest::Client,
    redirect: &ReadRedirect,
    address: &Url,
    cache_max_object_bytes: u64,
) -> ovstorage::Result<RedirectFetchOutcome> {
    if redirect.expires_at <= SystemTime::now() {
        return Err(Error::new(
            ErrorCode::Transient,
            "broker read redirect has expired",
        ));
    }

    let method = method_from_str(&redirect.request.method)?;
    let original_url = url::Url::parse(&redirect.request.url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker read redirect URL is invalid: {error}"),
        )
    })?;
    let mut current_url = original_url.clone();
    let mut hops = 0usize;
    let response = loop {
        let mut builder = client.request(method.clone(), current_url.clone());
        for (name, value) in &redirect.request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let response = builder.send().await.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("broker read redirect fetch failed: {err}"),
            )
        })?;
        let status = response.status();
        if !status.is_redirection() {
            break response;
        }
        let Some(location) = response.headers().get(LOCATION) else {
            break response;
        };
        if hops >= MAX_REDIRECT_HOPS {
            return Err(Error::new(
                ErrorCode::Transient,
                format!("broker read redirect exceeded {MAX_REDIRECT_HOPS} hops"),
            ));
        }
        let location = location.to_str().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker read redirect Location header is invalid: {error}"),
            )
        })?;
        let next_url = current_url.join(location).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker read redirect Location URL is invalid: {error}"),
            )
        })?;
        if !same_origin(&original_url, &next_url) {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                format!(
                    "broker read redirect crossed origin from {} to {}",
                    origin_label(&original_url),
                    origin_label(&next_url)
                ),
            ));
        }
        hops += 1;
        current_url = next_url;
    };
    let status = response.status();
    if !status.is_success() {
        return Err(Error::new(
            ErrorCode::Transient,
            format!(
                "broker read redirect returned HTTP {} from {}",
                status.as_u16(),
                redirect.request.url
            ),
        ));
    }
    let content_length = response.content_length();
    let Some(reported) = content_length else {
        return Ok(RedirectFetchOutcome::NotCacheable {
            reason: NotCacheableReason::UnknownSize,
        });
    };
    if reported > cache_max_object_bytes {
        return Ok(RedirectFetchOutcome::NotCacheable {
            reason: NotCacheableReason::Oversized {
                reported,
                cap: cache_max_object_bytes,
            },
        });
    }
    let headers_snapshot: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let bytes = response.bytes().await.map_err(|err| {
        Error::new(
            ErrorCode::Transient,
            format!("broker read redirect body read failed: {err}"),
        )
    })?;
    if bytes.len() as u64 > cache_max_object_bytes {
        // Defense-in-depth: upstream misreported Content-Length.
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!(
                "broker read redirect body ({} B) exceeded cache cap ({} B); upstream \
                 misreported Content-Length",
                bytes.len(),
                cache_max_object_bytes
            ),
        ));
    }
    let info = parse_object_info(
        address.clone(),
        &redirect.response_parsing,
        &headers_snapshot,
    );
    Ok(RedirectFetchOutcome::Fetched {
        bytes: bytes.to_vec(),
        info,
    })
}

fn same_origin(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn origin_label(url: &url::Url) -> String {
    match (url.host_str(), url.port_or_known_default()) {
        (Some(host), Some(port)) => format!("{}://{}:{}", url.scheme(), host, port),
        (Some(host), None) => format!("{}://{}", url.scheme(), host),
        _ => url.scheme().to_string(),
    }
}

fn method_from_str(method: &str) -> ovstorage::Result<reqwest::Method> {
    method.parse::<reqwest::Method>().map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid HTTP method: {err}"),
        )
    })
}

/// Translate response headers into `ObjectInfo` per the plugin's
/// `ResponseParsing` config.
fn parse_object_info(
    address: Url,
    parsing: &ovstorage::ResponseParsing,
    headers: &[(String, String)],
) -> ObjectInfo {
    let etag = parsing
        .etag_header
        .as_deref()
        .and_then(|name| header_value(headers, name))
        .map(|value| value.trim_matches('"').to_string());
    let version = parsing
        .version_header
        .as_deref()
        .and_then(|name| header_value(headers, name))
        .map(str::to_string);
    let size = parsing
        .size_header
        .as_deref()
        .and_then(|name| header_value(headers, name))
        .and_then(|value| value.parse::<u64>().ok());
    let mtime = parsing
        .mtime_header
        .as_deref()
        .and_then(|name| header_value(headers, name))
        .and_then(|value| parse_mtime(value, parsing.mtime_format));
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag,
        version,
        size,
        mtime,
        checksums: Default::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn parse_mtime(value: &str, format: ovstorage::MtimeFormat) -> Option<SystemTime> {
    match format {
        ovstorage::MtimeFormat::Rfc1123 => httpdate::parse_http_date(value).ok(),
        ovstorage::MtimeFormat::Iso8601 => {
            // No chrono dep: plugins needing ISO 8601 mtime should pick
            // a Unix-seconds MtimeFormat. None is safe (mtime optional).
            None.or_else(|| {
                value.parse::<i64>().ok().and_then(|secs| {
                    if secs >= 0 {
                        Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
                    } else {
                        None
                    }
                })
            })
        }
        ovstorage::MtimeFormat::UnixSeconds => value.parse::<i64>().ok().and_then(|secs| {
            if secs >= 0 {
                Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
            } else {
                None
            }
        }),
    }
}

/// Broker byte-cache key: `broker\0<address>`. The leading literal
/// namespaces broker rows from library rows (which key on
/// `<partition>\0<backend_id>\0<resolved>`).
pub fn broker_byte_cache_key(address: &Url) -> String {
    format!("broker\0{}", address.as_str())
}

/// Sidecar key for the persisted identity (etag/mtime) so byte-cache
/// hits return the same metadata as the first read.
pub fn broker_byte_cache_info_key(address: &Url) -> String {
    format!("{}.info", broker_byte_cache_key(address))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedObjectIdentity {
    etag: Option<String>,
    version: Option<String>,
    size: Option<u64>,
    mtime_unix_secs: Option<i64>,
}

/// Serialize the identity slice for `Cache::put` alongside the body.
pub fn encode_cached_object_info(info: &ObjectInfo) -> Vec<u8> {
    let payload = CachedObjectIdentity {
        etag: info.etag.clone(),
        version: info.version.clone(),
        size: info.size,
        mtime_unix_secs: info.mtime.and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64)
        }),
    };
    serde_json::to_vec(&payload).unwrap_or_default()
}

/// Reconstruct an `ObjectInfo` from a sidecar payload; `None` on
/// malformed bytes (callers fall back to size-only).
pub fn decode_cached_object_info(address: Url, bytes: &[u8]) -> Option<ObjectInfo> {
    let payload: CachedObjectIdentity = serde_json::from_slice(bytes).ok()?;
    Some(ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: payload.etag,
        version: payload.version,
        size: payload.size,
        mtime: payload.mtime_unix_secs.and_then(|secs| {
            if secs < 0 {
                None
            } else {
                Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
            }
        }),
        checksums: Default::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovstorage::{HttpRequest, RedirectScope, ResponseParsing};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn url(s: &str) -> Url {
        ovstorage::address::parse(s).unwrap()
    }

    fn active_redirect(request_url: String) -> ReadRedirect {
        ReadRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url: request_url.clone(),
                headers: Vec::new(),
            },
            response_parsing: ResponseParsing::default(),
            expires_at: SystemTime::now() + Duration::from_secs(60),
            scope: RedirectScope {
                physical_url_prefix: request_url,
                operations: Default::default(),
                expires_at: SystemTime::now() + Duration::from_secs(60),
            },
            audit_id: "test".into(),
            policy_epoch: 0,
        }
    }

    async fn spawn_same_origin_redirect_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request.split_whitespace().nth(1).unwrap_or("/");
                    let response = match path {
                        "/start" => {
                            "HTTP/1.1 300 Multiple Choices\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n".to_string()
                        }
                        "/final" => {
                            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: \"same\"\r\n\r\nok".to_string()
                        }
                        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
                    };
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}/start")
    }

    async fn spawn_body_server() -> (String, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (hit_tx, hit_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let _ = hit_tx.send(());
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let response =
                        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: \"cross\"\r\n\r\ncross";
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (format!("http://{addr}/final"), hit_rx)
    }

    async fn spawn_cross_origin_redirect_server(location: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let location = location.clone();
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        format!("http://{addr}/start")
    }

    #[test]
    fn header_value_is_case_insensitive() {
        let headers = vec![("Content-Length".into(), "1234".into())];
        assert_eq!(header_value(&headers, "content-length"), Some("1234"));
        assert_eq!(header_value(&headers, "CONTENT-LENGTH"), Some("1234"));
    }

    #[test]
    fn parse_object_info_reads_etag_and_size() {
        let headers = vec![
            ("etag".into(), "\"abc\"".into()),
            ("content-length".into(), "42".into()),
        ];
        let info = parse_object_info(url("file:///tmp/x"), &ResponseParsing::default(), &headers);
        assert_eq!(info.etag.as_deref(), Some("abc"));
        assert_eq!(info.size, Some(42));
    }

    #[test]
    fn broker_cache_key_is_stable() {
        assert_eq!(
            broker_byte_cache_key(&url("file:///tmp/x")),
            "broker\0file:///tmp/x"
        );
    }

    #[tokio::test]
    async fn expired_redirect_returns_transient() {
        let client = reqwest::Client::new();
        let redirect = ReadRedirect {
            request: HttpRequest {
                method: "GET".into(),
                url: "http://127.0.0.1:1/expired".into(),
                headers: Vec::new(),
            },
            response_parsing: ResponseParsing::default(),
            expires_at: SystemTime::now() - Duration::from_secs(1),
            scope: RedirectScope {
                physical_url_prefix: "http://".into(),
                operations: Default::default(),
                expires_at: SystemTime::now() - Duration::from_secs(1),
            },
            audit_id: "test".into(),
            policy_epoch: 0,
        };
        let err = follow_read_redirect(&client, &redirect, &url("file:///tmp/x"), 1024)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Transient);
    }

    #[tokio::test]
    async fn same_origin_300_redirect_is_followed_for_fetch_through() {
        let client = redirect_client();
        let start_url = spawn_same_origin_redirect_server().await;
        let redirect = active_redirect(start_url);

        let outcome = follow_read_redirect(&client, &redirect, &url("file:///tmp/x"), 1024)
            .await
            .unwrap();

        match outcome {
            RedirectFetchOutcome::Fetched { bytes, info } => {
                assert_eq!(bytes, b"ok");
                assert_eq!(info.etag.as_deref(), Some("same"));
            }
            other => panic!("expected fetched redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cross_origin_redirect_is_rejected_for_fetch_through() {
        let client = redirect_client();
        let (target_url, mut target_hits) = spawn_body_server().await;
        let start_url = spawn_cross_origin_redirect_server(target_url).await;
        let redirect = active_redirect(start_url);

        let err = follow_read_redirect(&client, &redirect, &url("file:///tmp/x"), 1024)
            .await
            .unwrap_err();

        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target_hits.recv())
                .await
                .is_err(),
            "cross-origin target must not be fetched"
        );
    }

    #[test]
    fn redirect_fetch_error_message_redacts_signed_url() {
        let signed = "https://bucket.s3.amazonaws.com/key\
                      ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                      &X-Amz-Credential=AKIA/20260513/us-east-1/s3/aws4_request\
                      &X-Amz-Signature=DO_NOT_LEAK";
        let err = Error::new(
            ErrorCode::Transient,
            format!("broker read redirect returned HTTP 503 from {signed}"),
        );
        let msg = err.message();
        assert!(msg.contains("X-Amz-Signature=REDACTED"), "{msg}");
        assert!(!msg.contains("DO_NOT_LEAK"), "{msg}");
        assert!(msg.contains("HTTP 503"), "{msg}");
    }
}
