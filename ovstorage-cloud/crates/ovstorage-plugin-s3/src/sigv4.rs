// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hand-rolled AWS SigV4. Shapes track AWS's published reference test vectors so unit tests can
//! validate against them; pulling `aws-sigv4` would drag in most of the AWS SDK for one HMAC chain.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tracing::trace;

use crate::credentials::AwsCredentials;

pub const SIGNED_PAYLOAD_UNSIGNED: &str = "UNSIGNED-PAYLOAD";

type HmacSha256 = Hmac<Sha256>;

/// One canonical SigV4 request. Signer injects `host`/date/payload-hash headers in lowercase form.
#[derive(Clone, Debug)]
pub struct CanonicalRequest<'a> {
    pub method: &'a str,
    pub canonical_uri: String,
    pub canonical_query: String,
    pub host: &'a str,
    pub extra_signed_headers: Vec<(String, String)>,
    pub payload_hash: String,
}

/// Per-request signing inputs.
#[derive(Clone, Debug)]
pub struct SigningContext<'a> {
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ` ISO basic format.
    pub amz_date: &'a str,
    /// `YYYYMMDD`, derived from `amz_date`.
    pub date_stamp: &'a str,
}

/// Header-mode signing output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHeaderSet {
    pub authorization: String,
    pub headers: Vec<(String, String)>,
    pub signed_headers: String,
    pub canonical_request: String,
    pub string_to_sign: String,
    pub signature: String,
}

/// SigV4 Authorization-header mode. Auto-injects `host` + `x-amz-date` only (matches AWS test vectors);
/// S3-required `x-amz-content-sha256` flows through `extra_signed_headers` so non-S3 fixtures still verify.
pub fn sign_request(
    creds: &AwsCredentials,
    ctx: &SigningContext<'_>,
    canonical: &CanonicalRequest<'_>,
) -> SignedHeaderSet {
    // Span at sign entry; host/path are config-level, not credential data.
    let _span = tracing::trace_span!(
        "s3.sigv4",
        method = canonical.method,
        host = canonical.host,
        path = canonical.canonical_uri.as_str(),
    )
    .entered();

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("host".to_string(), canonical.host.to_string());
    headers.insert("x-amz-date".to_string(), ctx.amz_date.to_string());
    if let Some(token) = creds.session_token.as_deref() {
        headers.insert("x-amz-security-token".to_string(), token.to_string());
    }
    for (name, value) in &canonical.extra_signed_headers {
        headers.insert(name.to_ascii_lowercase(), value.clone());
    }

    let signed_headers = signed_headers_string(&headers);
    let canonical_headers = canonical_headers_string(&headers);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        canonical.method,
        canonical.canonical_uri,
        canonical.canonical_query,
        canonical_headers,
        signed_headers,
        canonical.payload_hash,
    );

    let credential_scope = credential_scope(ctx);
    let string_to_sign = string_to_sign(ctx, &credential_scope, &canonical_request);

    // Intentionally trace!-only: these contain signed credential material.
    trace!(canonical_request = %canonical_request, "sigv4 canonical request");
    trace!(string_to_sign = %string_to_sign, "sigv4 string-to-sign");

    let key = signing_key(creds, ctx);
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    // Intentionally trace!-only: authorization header contains the signature.
    trace!(signature = %signature, "sigv4 signature");

    let credential = format!("{}/{}", creds.access_key_id, credential_scope);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={credential}, SignedHeaders={signed_headers}, Signature={signature}",
    );

    let mut header_pairs: Vec<(String, String)> = headers.into_iter().collect();
    header_pairs.push(("authorization".to_string(), authorization.clone()));
    SignedHeaderSet {
        authorization,
        headers: header_pairs,
        signed_headers,
        canonical_request,
        string_to_sign,
        signature,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresignedQuery {
    pub query: String,
    pub canonical_request: String,
    pub string_to_sign: String,
    pub signature: String,
}

/// SigV4 query-string mode for presigned URLs; preserves existing params (versionId, response-overrides, etc.).
#[allow(clippy::too_many_arguments)]
pub fn presign_query(
    creds: &AwsCredentials,
    ctx: &SigningContext<'_>,
    method: &str,
    canonical_uri: &str,
    host: &str,
    existing_query: &str,
    expires_secs: u32,
    extra_signed_headers: &[(String, String)],
) -> PresignedQuery {
    let credential_scope = credential_scope(ctx);
    let credential_param = format!("{}/{}", creds.access_key_id, credential_scope);

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    headers.insert("host".to_string(), host.to_string());
    for (name, value) in extra_signed_headers {
        headers.insert(name.to_ascii_lowercase(), value.clone());
    }
    let signed_headers = signed_headers_string(&headers);
    let canonical_headers = canonical_headers_string(&headers);

    let mut params: Vec<(String, String)> = parse_query(existing_query);
    params.push((
        "X-Amz-Algorithm".to_string(),
        "AWS4-HMAC-SHA256".to_string(),
    ));
    params.push(("X-Amz-Credential".to_string(), credential_param));
    params.push(("X-Amz-Date".to_string(), ctx.amz_date.to_string()));
    params.push(("X-Amz-Expires".to_string(), expires_secs.to_string()));
    if let Some(token) = creds.session_token.as_deref() {
        params.push(("X-Amz-Security-Token".to_string(), token.to_string()));
    }
    params.push(("X-Amz-SignedHeaders".to_string(), signed_headers.clone()));

    let canonical_query = canonicalize_query(&params);
    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{SIGNED_PAYLOAD_UNSIGNED}",
    );

    let string_to_sign = string_to_sign(ctx, &credential_scope, &canonical_request);
    let key = signing_key(creds, ctx);
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    let mut query = canonical_query;
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str("X-Amz-Signature=");
    query.push_str(&signature);

    PresignedQuery {
        query,
        canonical_request,
        string_to_sign,
        signature,
    }
}

pub fn signing_key(creds: &AwsCredentials, ctx: &SigningContext<'_>) -> [u8; 32] {
    let secret = creds.secret_access_key.as_bytes();
    let mut k_secret = Vec::with_capacity(4 + secret.len());
    k_secret.extend_from_slice(b"AWS4");
    k_secret.extend_from_slice(secret);
    let k_date = hmac_sha256(&k_secret, ctx.date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, ctx.region.as_bytes());
    let k_service = hmac_sha256(&k_region, ctx.service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

pub fn credential_scope(ctx: &SigningContext<'_>) -> String {
    format!(
        "{}/{}/{}/aws4_request",
        ctx.date_stamp, ctx.region, ctx.service
    )
}

pub fn string_to_sign(
    ctx: &SigningContext<'_>,
    credential_scope: &str,
    canonical_request: &str,
) -> String {
    let hashed = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        ctx.amz_date, credential_scope, hashed
    )
}

pub fn payload_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Canonical-URI path for a key: each segment percent-encoded with the unreserved alphabet, `/` literal.
pub fn canonical_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 1);
    out.push('/');
    let mut first = true;
    for segment in key.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        out.push_str(&encode_uri_segment(segment));
    }
    out
}

/// Canonical URI `/{bucket}/{key}` for path-style; bucket unencoded, key canonicalised.
pub fn canonical_path_path_style(bucket: &str, key: &str) -> String {
    let mut out = String::with_capacity(key.len() + bucket.len() + 2);
    out.push('/');
    out.push_str(bucket);
    if key.is_empty() {
        return out;
    }
    out.push('/');
    let mut first = true;
    for segment in key.split('/') {
        if !first {
            out.push('/');
        }
        first = false;
        out.push_str(&encode_uri_segment(segment));
    }
    out
}

fn encode_uri_segment(value: &str) -> String {
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

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => unreachable!("nibble in range"),
    }
}

pub fn canonicalize_query(params: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (encode_query_token(k), encode_query_token(v)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_query_token(value: &str) -> String {
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

pub fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|piece| !piece.is_empty())
        .map(|piece| match piece.split_once('=') {
            Some((k, v)) => (decode_query_token(k), decode_query_token(v)),
            None => (decode_query_token(piece), String::new()),
        })
        .collect()
}

fn decode_query_token(value: &str) -> String {
    urlencoding::decode(value)
        .map(|decoded| decoded.into_owned())
        .unwrap_or_else(|_| value.to_string())
}

fn canonical_headers_string(headers: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        out.push_str(name);
        out.push(':');
        out.push_str(value.trim());
        out.push('\n');
    }
    out
}

fn signed_headers_string(headers: &BTreeMap<String, String>) -> String {
    headers.keys().cloned().collect::<Vec<_>>().join(";")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::AwsCredentials;

    fn vector_credentials() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    fn vector_ctx() -> SigningContext<'static> {
        SigningContext {
            region: "us-east-1",
            service: "service",
            amz_date: "20150830T123600Z",
            date_stamp: "20150830",
        }
    }

    /// AWS reference vector "get-vanilla": host + x-amz-date as the only signed headers.
    #[test]
    fn aws_vector_get_vanilla() {
        let canonical = CanonicalRequest {
            method: "GET",
            canonical_uri: "/".into(),
            canonical_query: String::new(),
            host: "example.amazonaws.com",
            extra_signed_headers: Vec::new(),
            payload_hash: payload_hash(&[]),
        };
        let signed = sign_request(&vector_credentials(), &vector_ctx(), &canonical);

        let expected_canonical = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(signed.canonical_request, expected_canonical);

        let expected_string_to_sign = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
        assert_eq!(signed.string_to_sign, expected_string_to_sign);

        assert_eq!(
            signed.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        );
    }

    /// AWS reference vector "get-utf8": multi-byte path segments must be percent-encoded.
    #[test]
    fn aws_vector_get_utf8() {
        let canonical = CanonicalRequest {
            method: "GET",
            canonical_uri: canonical_path("ሴ"),
            canonical_query: String::new(),
            host: "example.amazonaws.com",
            extra_signed_headers: Vec::new(),
            payload_hash: payload_hash(&[]),
        };
        assert_eq!(canonical.canonical_uri, "/%E1%88%B4");
        let signed = sign_request(&vector_credentials(), &vector_ctx(), &canonical);

        assert_eq!(
            signed.signature,
            "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85",
        );
    }

    /// AWS reference vector "post-vanilla-query": query params sorted and percent-encoded before signing.
    #[test]
    fn aws_vector_post_vanilla_query() {
        let mut params: Vec<(String, String)> = vec![("Param1".into(), "value1".into())];
        params.sort();
        let canonical = CanonicalRequest {
            method: "POST",
            canonical_uri: "/".into(),
            canonical_query: canonicalize_query(&params),
            host: "example.amazonaws.com",
            extra_signed_headers: Vec::new(),
            payload_hash: payload_hash(&[]),
        };
        assert_eq!(canonical.canonical_query, "Param1=value1");
        let signed = sign_request(&vector_credentials(), &vector_ctx(), &canonical);

        assert_eq!(
            signed.signature,
            "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11",
        );
    }

    #[test]
    fn presign_query_emits_amz_signature_at_end() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let ctx = SigningContext {
            region: "us-east-1",
            service: "s3",
            amz_date: "20130524T000000Z",
            date_stamp: "20130524",
        };
        let signed = presign_query(
            &creds,
            &ctx,
            "GET",
            "/test.txt",
            "examplebucket.s3.amazonaws.com",
            "",
            86400,
            &[],
        );
        assert!(signed.query.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(signed.query.contains("X-Amz-Expires=86400"));
        assert!(
            signed
                .query
                .ends_with(&format!("X-Amz-Signature={}", signed.signature))
        );
    }

    #[test]
    fn parse_query_round_trips_percent_encoding() {
        let params = parse_query("a=1&b=hello%20world&c=%E1%88%B4");
        assert_eq!(params[0], ("a".into(), "1".into()));
        assert_eq!(params[1], ("b".into(), "hello world".into()));
        assert_eq!(params[2].1, "ሴ");
    }
}
