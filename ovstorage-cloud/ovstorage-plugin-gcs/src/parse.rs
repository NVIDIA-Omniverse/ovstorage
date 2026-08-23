// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parse GCS JSON `Object` / `Objects` resources into ovstorage's typed
//! identity, checksum, and metadata vocabulary. Vendor-specific fields
//! (`metageneration`, `storageClass`, retention/hold flags) ride opaque
//! under their raw names in `SystemMetadata`.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use ovstorage_plugin::{
    ChecksumAlgorithm, ChecksumSet, Error, ErrorCode, Result, SystemMetadata, UserMetadata,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GcsObject {
    pub name: Option<String>,
    pub etag: Option<String>,
    pub generation: Option<String>,
    pub metageneration: Option<String>,
    pub size: Option<String>,
    pub updated: Option<String>,
    pub time_created: Option<String>,
    #[serde(rename = "timeCreated")]
    pub time_created_camel: Option<String>,
    #[serde(rename = "md5Hash")]
    pub md5_hash: Option<String>,
    #[serde(rename = "crc32c")]
    pub crc32c: Option<String>,
    #[serde(rename = "storageClass")]
    pub storage_class: Option<String>,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(rename = "contentEncoding")]
    pub content_encoding: Option<String>,
    #[serde(rename = "temporaryHold")]
    pub temporary_hold: Option<bool>,
    #[serde(rename = "eventBasedHold")]
    pub event_based_hold: Option<bool>,
    #[serde(rename = "retentionExpirationTime")]
    pub retention_expiration_time: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct GcsList {
    #[serde(default)]
    pub items: Vec<GcsObject>,
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(rename = "nextPageToken", default)]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RewriteResponse {
    pub done: bool,
    #[serde(rename = "rewriteToken", default)]
    pub rewrite_token: Option<String>,
    #[serde(default)]
    pub resource: Option<GcsObject>,
}

#[derive(Debug, Deserialize)]
pub struct TestIamPermissionsResponse {
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Parsed view of a GCS `Object`: flat identity fields + typed checksum and
/// metadata side-tables. Address is attached by the caller since the same
/// resource feeds `stat`, `list`, and write-completion paths.
pub struct ParsedObject {
    pub etag: Option<String>,
    pub version: Option<String>,
    pub size: Option<u64>,
    pub mtime: Option<SystemTime>,
    pub checksums: ChecksumSet,
    pub system_metadata: SystemMetadata,
    pub user_metadata: UserMetadata,
}

pub fn parse_object(object: &GcsObject) -> Result<ParsedObject> {
    // GCS interprets the SPI `if_match` etag string as a numeric
    // generation on the wire (`ifGenerationMatch=<n>`), so the etag
    // returned on `ObjectInfo` is the generation — that's what
    // `stat -> if_match=info.etag` must round-trip to. The HTTP-level
    // etag from the response body is stashed in `system_metadata` for
    // diagnostics; it is not a precondition token under the new SPI.
    let etag = object.generation.clone();
    let version = object.generation.clone();
    let size = parse_optional_u64(&object.size, "size")?;
    let mtime = parse_optional_rfc3339(object.updated.as_deref().or_else(|| {
        object
            .time_created_camel
            .as_deref()
            .or(object.time_created.as_deref())
    }))?;

    let mut checksums = ChecksumSet::new();
    if let Some(crc) = &object.crc32c {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(crc.as_bytes())
            .map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("GCS crc32c is not base64: {err}"),
                )
            })?;
        checksums.insert(ChecksumAlgorithm::crc32c(), bytes);
    }
    if let Some(md5) = &object.md5_hash {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(md5.as_bytes())
            .map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("GCS md5Hash is not base64: {err}"),
                )
            })?;
        checksums.insert(ChecksumAlgorithm::md5(), bytes);
    }

    let mut system_metadata = SystemMetadata::new();
    if let Some(value) = &object.etag {
        system_metadata.insert("x-goog-http-etag".into(), value.clone());
    }
    if let Some(value) = &object.metageneration {
        system_metadata.insert("x-goog-metageneration".into(), value.clone());
    }
    if let Some(value) = &object.storage_class {
        system_metadata.insert("x-goog-storage-class".into(), value.clone());
    }
    if let Some(value) = &object.content_encoding {
        system_metadata.insert("x-goog-stored-content-encoding".into(), value.clone());
    }
    if let Some(value) = &object.content_type {
        system_metadata.insert("content-type".into(), value.clone());
    }
    if let Some(value) = object.temporary_hold {
        system_metadata.insert("x-goog-temporary-hold".into(), value.to_string());
    }
    if let Some(value) = object.event_based_hold {
        system_metadata.insert("x-goog-event-based-hold".into(), value.to_string());
    }
    if let Some(value) = &object.retention_expiration_time {
        system_metadata.insert("x-goog-retention-expiration".into(), value.clone());
    }

    let user_metadata: UserMetadata = object.metadata.clone();

    Ok(ParsedObject {
        etag,
        version,
        size,
        mtime,
        checksums,
        system_metadata,
        user_metadata,
    })
}

fn parse_optional_u64(value: &Option<String>, field: &str) -> Result<Option<u64>> {
    let Some(raw) = value else { return Ok(None) };
    raw.parse::<u64>().map(Some).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("GCS '{field}' is not a u64: {err}"),
        )
    })
}

// `None` for missing input keeps the identity envelope honest about which
// fields the response actually supplied.
fn parse_optional_rfc3339(value: Option<&str>) -> Result<Option<SystemTime>> {
    let Some(raw) = value else { return Ok(None) };
    let parsed = time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("GCS timestamp '{raw}' is not RFC3339: {err}"),
        )
    })?;
    let unix_seconds = parsed.unix_timestamp();
    let nanos = parsed.nanosecond();
    if unix_seconds < 0 {
        return Ok(Some(
            SystemTime::UNIX_EPOCH - Duration::from_nanos((-unix_seconds) as u64 * 1_000_000_000),
        ));
    }
    Ok(Some(
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(unix_seconds as u64)
            + Duration::from_nanos(nanos as u64),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_object_resource_into_typed_identity_and_checksums() {
        let json = r#"{
            "kind": "storage#object",
            "name": "dir/file.txt",
            "bucket": "asset-bucket",
            "generation": "1700000000000001",
            "metageneration": "3",
            "etag": "CKi6w7vP2QIEAQ=",
            "size": "1024",
            "updated": "2023-11-14T22:13:20.123Z",
            "md5Hash": "Q2FjaGVNZTU=",
            "crc32c": "AAAAAA==",
            "storageClass": "STANDARD",
            "contentType": "text/plain",
            "contentEncoding": "gzip",
            "temporaryHold": false,
            "eventBasedHold": true,
            "metadata": {
                "owner": "alice",
                "purpose": "demo"
            }
        }"#;
        let object: GcsObject = serde_json::from_str(json).unwrap();
        let parsed = parse_object(&object).unwrap();
        assert_eq!(parsed.etag.as_deref(), Some("1700000000000001"));
        assert_eq!(parsed.version.as_deref(), Some("1700000000000001"));
        assert_eq!(
            parsed
                .system_metadata
                .get("x-goog-http-etag")
                .map(String::as_str),
            Some("CKi6w7vP2QIEAQ="),
        );
        assert_eq!(parsed.size, Some(1024));
        assert!(parsed.mtime.is_some());

        assert!(parsed.checksums.get(&ChecksumAlgorithm::crc32c()).is_some());
        assert!(parsed.checksums.get(&ChecksumAlgorithm::md5()).is_some());

        assert_eq!(
            parsed
                .system_metadata
                .get("x-goog-metageneration")
                .map(String::as_str),
            Some("3")
        );
        assert_eq!(
            parsed
                .system_metadata
                .get("x-goog-storage-class")
                .map(String::as_str),
            Some("STANDARD")
        );
        assert_eq!(
            parsed
                .system_metadata
                .get("x-goog-stored-content-encoding")
                .map(String::as_str),
            Some("gzip")
        );
        assert_eq!(
            parsed
                .system_metadata
                .get("x-goog-event-based-hold")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            parsed.user_metadata.get("owner").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            parsed.user_metadata.get("purpose").map(String::as_str),
            Some("demo")
        );
    }

    #[test]
    fn parses_list_response_with_items_and_prefixes() {
        let json = r#"{
            "kind": "storage#objects",
            "items": [
                {
                    "name": "dir/file.txt",
                    "bucket": "asset-bucket",
                    "generation": "1",
                    "metageneration": "1",
                    "size": "10",
                    "etag": "abc"
                }
            ],
            "prefixes": ["dir/sub/", "dir/other/"],
            "nextPageToken": "page-2"
        }"#;
        let listing: GcsList = serde_json::from_str(json).unwrap();
        assert_eq!(listing.items.len(), 1);
        assert_eq!(listing.items[0].name.as_deref(), Some("dir/file.txt"));
        assert_eq!(listing.prefixes, vec!["dir/sub/", "dir/other/"]);
        assert_eq!(listing.next_page_token.as_deref(), Some("page-2"));
    }
}
