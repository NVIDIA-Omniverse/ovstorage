// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! V4 signed-URL minting for GCS.
//!
//! Same query-string V4 flavour as S3 with Google-specific tweaks: algorithm
//! `GOOG4-RSA-SHA256`, service `storage`, terminator `goog4_request`.
//! Signatures are RSA-SHA256 over the service-account private key (not
//! HMAC), so authorized-user ADC creds cannot use this path.

use std::time::SystemTime;

use base64::Engine as _;
use ovstorage_plugin::{Error, ErrorCode, Result};
use sha2::{Digest, Sha256};
use tracing::trace;

use crate::auth::ServiceAccountKey;

const ALGORITHM: &str = "GOOG4-RSA-SHA256";
const SERVICE: &str = "storage";
const REQUEST_TYPE: &str = "goog4_request";
const DEFAULT_HOST: &str = "storage.googleapis.com";
const DEFAULT_SCHEME: &str = "https";
pub const DEFAULT_EXPIRY_SECONDS: u64 = 300;

/// Inputs to a V4 signing operation. `object` is raw (not percent-encoded);
/// `query` carries non-signing params (`generation`, `response-content-type`,
/// etc.). `endpoint` overrides the global host for fake-GCS / private
/// endpoints; the V4 scope is host-independent.
pub struct V4Request<'a> {
    pub method: &'a str,
    pub bucket: &'a str,
    pub object: &'a str,
    pub query: &'a [(String, String)],
    pub now: SystemTime,
    pub expires_in_seconds: u64,
    pub endpoint: Option<&'a str>,
}

/// A signed URL plus the `host:` header it must be issued against (the
/// signature only signs `host`, so the request must hit that exact host).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedUrl {
    pub url: String,
    pub host_header: String,
}

/// Mint a V4-signed URL for `request` using `sa`'s RSA private key.
/// Defaults to the global `storage.googleapis.com` host (GCS routes signed
/// URLs through the global frontend regardless of bucket region).
pub fn sign_url(sa: &ServiceAccountKey, request: V4Request<'_>) -> Result<SignedUrl> {
    if request.method.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "V4 signing requires a non-empty HTTP method",
        ));
    }
    let datetime = format_signing_datetime(request.now)?;
    let date = &datetime[..8];
    let credential_scope = format!("{date}/auto/{SERVICE}/{REQUEST_TYPE}");
    let credential = format!("{}/{}", sa.client_email, credential_scope);

    let mut signed_query: Vec<(String, String)> = vec![
        ("X-Goog-Algorithm".to_string(), ALGORITHM.to_string()),
        ("X-Goog-Credential".to_string(), credential),
        ("X-Goog-Date".to_string(), datetime.clone()),
        (
            "X-Goog-Expires".to_string(),
            request.expires_in_seconds.to_string(),
        ),
        ("X-Goog-SignedHeaders".to_string(), "host".to_string()),
    ];
    for (k, v) in request.query {
        signed_query.push((k.clone(), v.clone()));
    }
    signed_query.sort_by(|a, b| match a.0.cmp(&b.0) {
        std::cmp::Ordering::Equal => a.1.cmp(&b.1),
        other => other,
    });
    let canonical_query = signed_query
        .iter()
        .map(|(k, v)| format!("{}={}", encode_query(k), encode_query(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_uri = canonical_uri(request.bucket, request.object);
    let (scheme, host) = resolve_endpoint(request.endpoint)?;
    let canonical_headers = format!("host:{host}\n");
    let signed_headers = "host";
    let payload = "UNSIGNED-PAYLOAD";
    let canonical_request = format!(
        "{method}\n{uri}\n{query}\n{headers}\n{signed_headers}\n{payload}",
        method = request.method,
        uri = canonical_uri,
        query = canonical_query,
        headers = canonical_headers,
        signed_headers = signed_headers,
        payload = payload,
    );
    let canonical_request_hash = hex_sha256(canonical_request.as_bytes());

    // Intentionally trace!-only: canonical request and string-to-sign contain auth material.
    trace!(canonical_request = %canonical_request, "gcs v4 canonical request");

    let string_to_sign =
        format!("{ALGORITHM}\n{datetime}\n{credential_scope}\n{canonical_request_hash}");

    // Intentionally trace!-only: string-to-sign is the pre-image of the signature.
    trace!(string_to_sign = %string_to_sign, "gcs v4 string-to-sign");

    let signature_bytes = rsa_sign(sa, string_to_sign.as_bytes())?;
    let signature_hex = hex::encode(signature_bytes);

    // Intentionally trace!-only: signature is a derived credential.
    trace!(signature = %signature_hex, "gcs v4 signature");

    let mut url = format!("{scheme}://{host}{canonical_uri}?{canonical_query}");
    url.push_str("&X-Goog-Signature=");
    url.push_str(&signature_hex);
    Ok(SignedUrl {
        url,
        host_header: host,
    })
}

// Host carries the port when set so the canonical `host:` header matches
// the URL byte-for-byte (V4 signs `host`).
fn resolve_endpoint(endpoint: Option<&str>) -> Result<(String, String)> {
    let Some(raw) = endpoint else {
        return Ok((DEFAULT_SCHEME.to_string(), DEFAULT_HOST.to_string()));
    };
    let parsed = url::Url::parse(raw).map_err(|err| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS endpoint override is not a valid URL: {err}"),
        )
    })?;
    let scheme = parsed.scheme().to_string();
    if scheme.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS endpoint override must include a scheme",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "GCS endpoint override must include a host",
            )
        })?
        .to_string();
    let host_with_port = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok((scheme, host_with_port))
}

// Shares the JWT issuer's encoding key path so PEM errors report identically.
fn rsa_sign(sa: &ServiceAccountKey, input: &[u8]) -> Result<Vec<u8>> {
    use jsonwebtoken::crypto::sign;
    let key =
        jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|err| {
            Error::new(
                ErrorCode::CredentialUnavailable,
                format!("GCS service-account private key is not RSA PEM: {err}"),
            )
        })?;
    let signature_b64 = sign(input, &key, jsonwebtoken::Algorithm::RS256).map_err(|err| {
        Error::new(
            ErrorCode::CredentialUnavailable,
            format!("V4 RSA-SHA256 signing failed: {err}"),
        )
    })?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("V4 signature was not valid base64: {err}"),
            )
        })
}

// Each segment percent-encoded; `/` between segments preserved. GCS rejects
// the URL if the canonical URI does not match the path byte-for-byte.
fn canonical_uri(bucket: &str, object: &str) -> String {
    let mut uri = String::from("/");
    uri.push_str(&encode_path_segment(bucket));
    uri.push('/');
    let segments: Vec<String> = object.split('/').map(encode_path_segment).collect();
    uri.push_str(&segments.join("/"));
    uri
}

fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if is_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if is_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

// V4 percent-encoding requires uppercase hex; lowercase escapes fail validation.
fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => unreachable!("nibble is always in range"),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

// V4 timestamp: `YYYYMMDDTHHMMSSZ`.
fn format_signing_datetime(now: SystemTime) -> Result<String> {
    let timestamp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|err| Error::new(ErrorCode::Internal, err.to_string()))?
        .as_secs();
    let datetime = time::OffsetDateTime::from_unix_timestamp(timestamp as i64).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("invalid signing timestamp: {err}"),
        )
    })?;
    Ok(format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ServiceAccountKey;
    use std::time::{Duration, UNIX_EPOCH};

    const SYNTHETIC_PEM: &str = include_str!("../tests/synthetic_rsa_pkcs8.pem");

    fn fixture_sa() -> ServiceAccountKey {
        ServiceAccountKey {
            client_email: "tester@example.iam.gserviceaccount.com".into(),
            private_key: SYNTHETIC_PEM.into(),
            token_uri: "https://oauth2.example/token".into(),
            private_key_id: None,
        }
    }

    #[test]
    fn signed_url_canonical_request_matches_known_fixture() {
        // Pinned instant so the URL is byte-deterministic.
        let fixed = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let request = V4Request {
            method: "GET",
            bucket: "asset-bucket",
            object: "dir/file.txt",
            query: &[],
            now: fixed,
            expires_in_seconds: DEFAULT_EXPIRY_SECONDS,
            endpoint: None,
        };
        let signed = sign_url(&fixture_sa(), request).expect("sign");
        assert_eq!(signed.host_header, "storage.googleapis.com");
        assert!(
            signed
                .url
                .starts_with("https://storage.googleapis.com/asset-bucket/dir/file.txt?"),
            "url: {}",
            signed.url
        );
        assert!(signed.url.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(signed
            .url
            .contains("X-Goog-Credential=tester%40example.iam.gserviceaccount.com%2F20231114%2Fauto%2Fstorage%2Fgoog4_request"));
        assert!(signed.url.contains("X-Goog-Date=20231114T221320Z"));
        assert!(signed.url.contains("X-Goog-Expires=300"));
        assert!(signed.url.contains("X-Goog-SignedHeaders=host"));
        assert!(signed.url.contains("&X-Goog-Signature="));
    }

    #[test]
    fn canonical_uri_percent_encodes_each_segment_but_keeps_slashes() {
        let uri = canonical_uri("bucket", "dir/sub dir/name with space.txt");
        assert_eq!(uri, "/bucket/dir/sub%20dir/name%20with%20space.txt");
    }

    #[test]
    fn signed_url_includes_caller_query_in_canonical_form() {
        let fixed = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let extra = vec![("generation".to_string(), "42".to_string())];
        let request = V4Request {
            method: "GET",
            bucket: "asset-bucket",
            object: "dir/file.txt",
            query: &extra,
            now: fixed,
            expires_in_seconds: 60,
            endpoint: None,
        };
        let signed = sign_url(&fixture_sa(), request).expect("sign");
        assert!(signed.url.contains("generation=42"));
        assert!(signed.url.contains("X-Goog-Expires=60"));
    }

    #[test]
    fn signed_url_honors_endpoint_override_to_localhost() {
        let fixed = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let request = V4Request {
            method: "GET",
            bucket: "asset-bucket",
            object: "dir/file.txt",
            query: &[],
            now: fixed,
            expires_in_seconds: DEFAULT_EXPIRY_SECONDS,
            endpoint: Some("http://localhost:9000"),
        };
        let signed = sign_url(&fixture_sa(), request).expect("sign");
        assert_eq!(signed.host_header, "localhost:9000");
        assert!(
            signed
                .url
                .starts_with("http://localhost:9000/asset-bucket/dir/file.txt?"),
            "url: {}",
            signed.url
        );
        assert!(signed.url.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(signed.url.contains("&X-Goog-Signature="));
    }

    #[test]
    fn endpoint_override_default_for_none_returns_global_host() {
        let (scheme, host) = resolve_endpoint(None).unwrap();
        assert_eq!(scheme, "https");
        assert_eq!(host, "storage.googleapis.com");
    }

    #[test]
    fn endpoint_override_keeps_port_in_host() {
        let (scheme, host) = resolve_endpoint(Some("http://127.0.0.1:4443")).unwrap();
        assert_eq!(scheme, "http");
        assert_eq!(host, "127.0.0.1:4443");
    }

    #[test]
    fn endpoint_override_rejects_garbage() {
        assert!(resolve_endpoint(Some("not-a-url")).is_err());
    }
}
