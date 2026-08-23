// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared Key signing and Service SAS minting for Azure Blob.
//!
//! Both signers operate on the canonical strings documented at
//! <https://learn.microsoft.com/rest/api/storageservices/authorize-with-shared-key>
//! and the service-SAS construction at
//! <https://learn.microsoft.com/rest/api/storageservices/create-service-sas>.
//!
//! The Shared Key path is the one Microsoft uses for Blob and Queue; the
//! signed string is HMAC-SHA256ed with the base64-decoded account key. The
//! Service SAS path emits a query string that callers append directly to the
//! request URL. Service SAS is preferred for `ReadResult::Redirect` because it
//! lets the host follower replay the URL without holding the account key.

use std::collections::BTreeMap;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use ovstorage_plugin::{Error, ErrorCode, Result};
use sha2::Sha256;

const SAS_VERSION: &str = "2021-12-02";

type HmacSha256 = Hmac<Sha256>;

/// Inputs for a Blob Shared Key signature.
pub(crate) struct SharedKeyRequest<'a> {
    pub method: &'a str,
    pub account: &'a str,
    pub canonical_path: &'a str,
    pub canonical_query: &'a [(String, String)],
    pub headers: &'a [(String, String)],
    pub content_length: Option<u64>,
    pub content_type: Option<&'a str>,
    pub content_md5: Option<&'a str>,
    pub if_match: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub range: Option<&'a str>,
}

/// Build the Shared Key string-to-sign per the Microsoft REST docs.
pub(crate) fn shared_key_string_to_sign(req: &SharedKeyRequest<'_>) -> String {
    let canonical_headers = canonicalize_ms_headers(req.headers);
    let canonical_resource =
        canonicalize_resource(req.account, req.canonical_path, req.canonical_query);

    let content_length = match req.content_length {
        Some(0) | None => String::new(),
        Some(n) => n.to_string(),
    };

    format!(
        "{method}\n\
         \n\
         \n\
         {content_length}\n\
         {content_md5}\n\
         {content_type}\n\
         \n\
         \n\
         {if_match}\n\
         {if_none_match}\n\
         \n\
         {range}\n\
         {canonical_headers}{canonical_resource}",
        method = req.method,
        content_length = content_length,
        content_md5 = req.content_md5.unwrap_or(""),
        content_type = req.content_type.unwrap_or(""),
        if_match = req.if_match.unwrap_or(""),
        if_none_match = req.if_none_match.unwrap_or(""),
        range = req.range.unwrap_or(""),
    )
}

/// HMAC-SHA256 the canonical string with `account_key_bytes` (already base64-decoded).
pub(crate) fn shared_key_signature(account_key_bytes: &[u8], canonical: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(account_key_bytes).map_err(|e| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("Azure account key is not valid HMAC material: {e}"),
        )
    })?;
    mac.update(canonical.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

/// Build `Authorization: SharedKey {account}:{sig}`.
pub(crate) fn shared_key_authorization_value(account: &str, signature: &str) -> String {
    format!("SharedKey {account}:{signature}")
}

/// Canonicalize `x-ms-*` headers per Azure: lowercased name, alpha-sorted, `name:value\n`-joined,
/// values with whitespace collapsed to single spaces.
fn canonicalize_ms_headers(headers: &[(String, String)]) -> String {
    let mut sorted: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !lower.starts_with("x-ms-") {
            continue;
        }
        let normalized = collapse_whitespace(value.trim());
        sorted.insert(lower, normalized);
    }
    let mut out = String::new();
    for (name, value) in sorted {
        out.push_str(&name);
        out.push(':');
        out.push_str(&value);
        out.push('\n');
    }
    out
}

fn collapse_whitespace(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_space = false;
    for ch in value.chars() {
        if ch == ' ' || ch == '\t' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out
}

/// Canonical resource for Shared Key: `/{account}{path}\n{name:v1,v2\n...}` — query names
/// lowercased, values comma-joined per name. `path` must include a leading slash.
fn canonicalize_resource(
    account: &str,
    canonical_path: &str,
    canonical_query: &[(String, String)],
) -> String {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in canonical_query {
        let lower = name.to_ascii_lowercase();
        grouped.entry(lower).or_default().push(value.clone());
    }
    let mut resource = String::new();
    resource.push('/');
    resource.push_str(account);
    resource.push_str(canonical_path);
    if grouped.is_empty() {
        return resource;
    }
    for (name, mut values) in grouped {
        values.sort();
        resource.push('\n');
        resource.push_str(&name);
        resource.push(':');
        resource.push_str(&values.join(","));
    }
    resource
}

/// Permission characters accepted in service-SAS `sp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SasPermission {
    Read,
    Write,
    Create,
    #[allow(dead_code)]
    Delete,
}

impl SasPermission {
    fn as_char(self) -> char {
        match self {
            Self::Read => 'r',
            Self::Write => 'w',
            Self::Create => 'c',
            Self::Delete => 'd',
        }
    }
}

/// Inputs for a Service SAS over a single blob path.
pub(crate) struct ServiceSasRequest<'a> {
    pub account: &'a str,
    pub container: &'a str,
    pub blob_path: &'a str,
    pub permissions: &'a [SasPermission],
    pub start: Option<&'a str>,
    pub expiry: &'a str,
    pub protocol: Option<&'a str>,
    pub version: &'a str,
}

impl<'a> ServiceSasRequest<'a> {
    pub fn permission_string(&self) -> String {
        let mut chars: Vec<char> = self.permissions.iter().map(|p| p.as_char()).collect();
        chars.sort();
        chars.dedup();
        chars.into_iter().collect()
    }
}

/// Build the Service SAS string-to-sign for a blob-scoped grant.
///
/// `signedResource = b` is hard-coded: callers always grant a single blob path.
/// Container/directory SAS would use `c`/`d`.
pub(crate) fn service_sas_string_to_sign(req: &ServiceSasRequest<'_>) -> String {
    let canonicalized = format!("/blob/{}/{}/{}", req.account, req.container, req.blob_path);
    let permissions = req.permission_string();
    format!(
        "{permissions}\n\
         {start}\n\
         {expiry}\n\
         {canonicalized}\n\
         \n\
         \n\
         {protocol}\n\
         {version}\n\
         b\n\
         \n\
         \n\
         \n\
         \n\
         \n\
         \n\
         ",
        permissions = permissions,
        start = req.start.unwrap_or(""),
        expiry = req.expiry,
        canonicalized = canonicalized,
        protocol = req.protocol.unwrap_or(""),
        version = req.version,
    )
}

/// Mint a complete service-SAS query string (no leading `?`).
pub(crate) fn service_sas_query(
    account_key_bytes: &[u8],
    req: &ServiceSasRequest<'_>,
) -> Result<String> {
    let canonical = service_sas_string_to_sign(req);
    let signature = shared_key_signature(account_key_bytes, &canonical)?;
    let permissions = req.permission_string();

    let mut params: Vec<(&str, String)> = Vec::new();
    params.push(("sv", req.version.to_string()));
    params.push(("sr", "b".to_string()));
    if let Some(start) = req.start {
        params.push(("st", start.to_string()));
    }
    params.push(("se", req.expiry.to_string()));
    params.push(("sp", permissions));
    if let Some(protocol) = req.protocol {
        params.push(("spr", protocol.to_string()));
    }
    params.push(("sig", signature));

    let encoded: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();
    Ok(encoded.join("&"))
}

pub(crate) const DEFAULT_SAS_VERSION: &str = SAS_VERSION;

/// Decode an account-key string (Azure ships them as standard base64).
pub(crate) fn decode_account_key(raw: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|e| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure account key is not valid base64: {e}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the documented Microsoft List Blobs Shared Key example.
    #[test]
    fn shared_key_string_to_sign_matches_microsoft_list_blobs_example() {
        let headers = vec![
            (
                "x-ms-date".to_string(),
                "Fri, 26 Jun 2015 23:39:12 GMT".to_string(),
            ),
            ("x-ms-version".to_string(), "2015-02-21".to_string()),
        ];
        let query = vec![
            ("comp".to_string(), "list".to_string()),
            ("restype".to_string(), "container".to_string()),
        ];
        let req = SharedKeyRequest {
            method: "GET",
            account: "myaccount",
            canonical_path: "/mycontainer",
            canonical_query: &query,
            headers: &headers,
            content_length: None,
            content_type: None,
            content_md5: None,
            if_match: None,
            if_none_match: None,
            range: None,
        };
        let canonical = shared_key_string_to_sign(&req);
        let expected = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:list\nrestype:container";
        assert_eq!(canonical, expected);
    }

    #[test]
    fn shared_key_signature_is_stable_for_pinned_inputs() {
        let key =
            base64::engine::general_purpose::STANDARD.encode(b"this-is-a-fake-account-key-32byt");
        let key_bytes = decode_account_key(&key).unwrap();
        let canonical = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:list\nrestype:container";
        let sig = shared_key_signature(&key_bytes, canonical).unwrap();
        assert_eq!(sig, "CcjAGKAZVJwQcZtK7f8EdQsP7JYVQoptEDs3qreW9KU=");
    }

    #[test]
    fn ms_headers_are_lowercased_sorted_and_whitespace_collapsed() {
        let headers = vec![
            ("X-MS-Version".to_string(), "2021-12-02".to_string()),
            (
                "X-Ms-Meta-Author".to_string(),
                "  Alice    Two  ".to_string(),
            ),
            ("Content-Type".to_string(), "text/plain".to_string()),
            (
                "X-Ms-Date".to_string(),
                "Mon, 01 Jan 2024 00:00:00 GMT".to_string(),
            ),
        ];
        let canonical = canonicalize_ms_headers(&headers);
        let expected = "x-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\nx-ms-meta-author:Alice Two\nx-ms-version:2021-12-02\n";
        assert_eq!(canonical, expected);
    }

    #[test]
    fn service_sas_query_signs_a_pinned_blob_request() {
        let key = base64::engine::general_purpose::STANDARD.encode([0xABu8; 32]);
        let key_bytes = decode_account_key(&key).unwrap();
        let req = ServiceSasRequest {
            account: "myaccount",
            container: "mycontainer",
            blob_path: "folder/blob.bin",
            permissions: &[SasPermission::Read],
            start: None,
            expiry: "2030-01-01T00:00:00Z",
            protocol: Some("https"),
            version: DEFAULT_SAS_VERSION,
        };
        let query = service_sas_query(&key_bytes, &req).unwrap();
        let expected = "sv=2021-12-02&sr=b&se=2030-01-01T00%3A00%3A00Z&sp=r&spr=https&sig=mNRhahQKl%2BTUsBbqjtJW95R3VQVHyRp%2Fwh40%2BFZSZvw%3D";
        assert_eq!(query, expected);
    }

    #[test]
    fn permission_string_is_sorted_and_deduped() {
        let req = ServiceSasRequest {
            account: "a",
            container: "c",
            blob_path: "b",
            permissions: &[
                SasPermission::Write,
                SasPermission::Read,
                SasPermission::Read,
                SasPermission::Create,
            ],
            start: None,
            expiry: "x",
            protocol: None,
            version: DEFAULT_SAS_VERSION,
        };
        assert_eq!(req.permission_string(), "crw");
    }

    #[test]
    fn canonicalize_resource_groups_and_sorts_query_values() {
        let query = vec![
            ("Comp".to_string(), "list".to_string()),
            ("include".to_string(), "metadata".to_string()),
            ("include".to_string(), "snapshots".to_string()),
        ];
        let canonical = canonicalize_resource("acct", "/c", &query);
        assert_eq!(canonical, "/acct/c\ncomp:list\ninclude:metadata,snapshots");
    }
}
