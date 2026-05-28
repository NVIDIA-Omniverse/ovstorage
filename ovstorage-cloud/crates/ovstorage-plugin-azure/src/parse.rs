// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP-response parsing for Azure Blob and ADLS Gen2 endpoints.
//!
//! Three layers, all called from `backend.rs`:
//!
//! - [`parse_object_info`] reads the vendor-header surface returned by
//!   `Get Blob Properties` / `HEAD Blob` / `Put Blob` and packs it into the
//!   provider-neutral `ObjectInfo`. The header pinning lives in this module
//!   so a renamed Azure header surfaces as one diff in one file.
//! - [`parse_blob_list_xml`] parses the `EnumerationResults` XML from
//!   `List Blobs`, including `Blobs`, `BlobPrefixes`, and version metadata.
//! - [`parse_dfs_path_list_json`] parses the JSON from
//!   `Filesystem - List Paths` (ADLS Gen2 HNS).

use std::collections::HashMap;
use std::time::SystemTime;

use base64::Engine as _;
use ovstorage_plugin::{
    ChecksumAlgorithm, ChecksumSet, Error, ErrorCode, ObjectInfo, ObjectKind, Result,
    SystemMetadata, Url, UserMetadata, address,
};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde::Deserialize;

/// Headers recorded under `system_metadata` even if no specific column pulls them out by name.
pub(crate) const SYSTEM_METADATA_HEADERS: &[&str] = &[
    "x-ms-blob-type",
    "x-ms-access-tier",
    "x-ms-archive-status",
    "x-ms-server-encrypted",
    "x-ms-encryption-key-sha256",
    "x-ms-encryption-scope",
    "x-ms-copy-status",
    "x-ms-copy-id",
    "x-ms-lease-state",
    "x-ms-lease-status",
    "x-ms-blob-content-encoding",
    "content-type",
    "cache-control",
];

/// HNS path-properties extras kept under `system_metadata` for HNS routes.
pub(crate) const HNS_SYSTEM_METADATA_HEADERS: &[&str] =
    &["x-ms-permissions", "x-ms-owner", "x-ms-group", "x-ms-acl"];

/// Build an `ObjectInfo` from response headers (case-insensitive); address is caller-provided.
pub(crate) fn parse_object_info(
    address: Url,
    headers: &HeaderMap,
    include_hns_headers: bool,
) -> Result<ObjectInfo> {
    let etag = headers.first("etag").map(strip_quotes);
    let version = headers.first("x-ms-version-id").map(str::to_string);
    let size = headers.first("content-length").and_then(|s| s.parse().ok());
    let mtime = headers
        .first("last-modified")
        .and_then(|s| httpdate::parse_http_date(s).ok());

    let mut checksums = ChecksumSet::new();
    if let Some(b64) = headers.first("content-md5")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim())
    {
        checksums.insert(ChecksumAlgorithm::md5(), bytes);
    }
    if let Some(b64) = headers.first("x-ms-blob-content-md5")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim())
    {
        checksums.insert(ChecksumAlgorithm::md5(), bytes);
    }
    if let Some(b64) = headers.first("x-ms-content-crc64")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64.trim())
    {
        checksums.insert(ChecksumAlgorithm::new("crc64nvme")?, bytes);
    }

    let mut system_metadata: SystemMetadata = HashMap::new();
    for key in SYSTEM_METADATA_HEADERS {
        if let Some(value) = headers.first(key) {
            system_metadata.insert((*key).to_string(), value.to_string());
        }
    }
    if include_hns_headers {
        for key in HNS_SYSTEM_METADATA_HEADERS {
            if let Some(value) = headers.first(key) {
                system_metadata.insert((*key).to_string(), value.to_string());
            }
        }
    }

    let mut user_metadata: UserMetadata = HashMap::new();
    for (name, value) in headers.iter() {
        let lower = name.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("x-ms-meta-") {
            // Azure docs say preserve original casing; most stacks lowercase, so this is best-effort.
            if !rest.is_empty() {
                user_metadata.insert(rest.to_string(), value.to_string());
            }
        }
    }

    // ADLS Gen2 (HNS) `getStatus` populates `x-ms-resource-type`
    // (`"directory"` or `"file"`) — native directory inodes carry an
    // authoritative kind on HEAD, so use it when present. Flat
    // Azure-Blob HEADs never set this header; in that case the kind
    // is decided by the caller after a marker-style probe (the
    // `stat` site stamps `DirectoryMarker` for trailing-slash hits).
    let kind = match headers.first("x-ms-resource-type") {
        Some(value) if value.eq_ignore_ascii_case("directory") => ObjectKind::Directory,
        _ => ObjectKind::File,
    };
    Ok(ObjectInfo {
        address,
        kind,
        etag,
        version,
        size,
        mtime,
        checksums,
        effective_permissions: None,
        system_metadata: if system_metadata.is_empty() {
            None
        } else {
            Some(system_metadata)
        },
        user_metadata: if user_metadata.is_empty() {
            None
        } else {
            Some(user_metadata)
        },
        modified_by: None,
    })
}

/// Strip Azure's literal-double-quote ETag wrapping so cross-provider comparisons work.
fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// Case-insensitive header lookup that preserves insertion order.
#[derive(Default, Debug, Clone)]
pub(crate) struct HeaderMap {
    entries: Vec<(String, String)>,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut map = Self::new();
        for (name, value) in pairs {
            map.insert(name.as_ref(), value.as_ref());
        }
        map
    }

    pub fn insert(&mut self, name: &str, value: &str) {
        self.entries.push((name.to_string(), value.to_string()));
    }

    pub fn first(&self, name: &str) -> Option<&str> {
        let needle = name.to_ascii_lowercase();
        self.entries
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == needle)
            .map(|(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }
}

/// Result of parsing `EnumerationResults`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ParsedBlobList {
    pub items: Vec<BlobListEntry>,
    pub prefixes: Vec<String>,
    pub next_marker: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BlobListEntry {
    pub name: String,
    pub etag: Option<String>,
    pub size: Option<u64>,
    pub last_modified: Option<SystemTime>,
    pub content_md5: Option<Vec<u8>>,
    pub content_type: Option<String>,
    pub version_id: Option<String>,
    pub is_current_version: Option<bool>,
}

/// Hand-rolled `EnumerationResults` parser. `quick-xml` element-event mode handles
/// `Blobs/Blob/...` vs `Blobs/BlobPrefix` nesting that serde-derive doesn't capture cleanly.
pub(crate) fn parse_blob_list_xml(xml: &str) -> Result<ParsedBlobList> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut out = ParsedBlobList::default();
    let mut path: Vec<String> = Vec::new();
    let mut current_blob: Option<BlobListEntry> = None;
    let mut text_buf: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "failed to parse Azure blob list XML at position {}: {e}",
                        reader.buffer_position()
                    ),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(Event::Start(start)) => {
                let name = std::str::from_utf8(start.name().as_ref())
                    .map_err(|_| invalid_xml("non-utf8 element name"))?
                    .to_string();
                if name == "Blob" {
                    current_blob = Some(BlobListEntry {
                        name: String::new(),
                        etag: None,
                        size: None,
                        last_modified: None,
                        content_md5: None,
                        content_type: None,
                        version_id: None,
                        is_current_version: None,
                    });
                }
                path.push(name);
                text_buf.push(String::new());
            }
            Ok(Event::Text(text)) => {
                if let Some(top) = text_buf.last_mut() {
                    top.push_str(
                        text.unescape()
                            .map_err(|e| invalid_xml(&format!("escape error: {e}")))?
                            .as_ref(),
                    );
                }
            }
            Ok(Event::End(end)) => {
                let name = std::str::from_utf8(end.name().as_ref())
                    .map_err(|_| invalid_xml("non-utf8 element name"))?
                    .to_string();
                let text = text_buf.pop().unwrap_or_default();
                if path.last().map(String::as_str) != Some(name.as_str()) {
                    return Err(invalid_xml("mismatched XML close tag"));
                }
                path.pop();

                match name.as_str() {
                    "NextMarker" if !text.is_empty() => {
                        out.next_marker = Some(text);
                    }
                    "Name" => {
                        // BlobPrefix/Name vs Blob/Name vs EnumerationResults/Name disambiguated by parent on stack.
                        if let Some(parent) = path.last() {
                            match parent.as_str() {
                                "Blob" => {
                                    if let Some(blob) = current_blob.as_mut() {
                                        blob.name = text;
                                    }
                                }
                                "BlobPrefix" => {
                                    out.prefixes.push(text);
                                }
                                _ => {}
                            }
                        }
                    }
                    "Etag" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.etag = Some(strip_quotes(&text));
                        }
                    }
                    "Last-Modified" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.last_modified = httpdate::parse_http_date(&text).ok();
                        }
                    }
                    "Content-Length" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.size = text.parse().ok();
                        }
                    }
                    "Content-MD5" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.content_md5 = base64::engine::general_purpose::STANDARD
                                .decode(text.trim())
                                .ok();
                        }
                    }
                    "Content-Type" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.content_type = Some(text);
                        }
                    }
                    "VersionId" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.version_id = Some(text);
                        }
                    }
                    "IsCurrentVersion" => {
                        if let Some(blob) = current_blob.as_mut() {
                            blob.is_current_version = Some(text.eq_ignore_ascii_case("true"));
                        }
                    }
                    "Blob" => {
                        if let Some(blob) = current_blob.take() {
                            out.items.push(blob);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Ok(out)
}

fn invalid_xml(msg: &str) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("Azure blob list XML is malformed: {msg}"),
    )
}

/// Result of parsing the `Filesystem - List Paths` JSON returned by ADLS Gen2.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ParsedPathList {
    pub paths: Vec<DfsPathEntry>,
    pub continuation: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DfsPathEntry {
    pub name: String,
    pub is_directory: bool,
    pub etag: Option<String>,
    pub size: Option<u64>,
    pub last_modified: Option<SystemTime>,
}

#[derive(Deserialize)]
struct RawPathList {
    paths: Vec<RawPath>,
}

#[derive(Deserialize)]
struct RawPath {
    name: String,
    #[serde(default)]
    #[serde(rename = "isDirectory")]
    is_directory: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default, rename = "contentLength")]
    content_length: Option<serde_json::Value>,
    #[serde(default, rename = "lastModified")]
    last_modified: Option<String>,
}

/// Parse `Filesystem - List Paths` JSON. The continuation token arrives via the
/// `x-ms-continuation` response header (not in the body) and is plumbed in separately.
pub(crate) fn parse_dfs_path_list_json(
    body: &str,
    continuation: Option<String>,
) -> Result<ParsedPathList> {
    let raw: RawPathList = serde_json::from_str(body).map_err(|e| {
        Error::new(
            ErrorCode::Internal,
            format!("Azure ADLS Gen2 path list JSON is malformed: {e}"),
        )
    })?;
    let paths = raw
        .paths
        .into_iter()
        .map(|p| DfsPathEntry {
            name: p.name,
            is_directory: p
                .is_directory
                .map(|s| s.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            etag: p.etag.map(|e| strip_quotes(&e)),
            size: p.content_length.and_then(|value| match value {
                serde_json::Value::Number(n) => n.as_u64(),
                serde_json::Value::String(s) => s.parse().ok(),
                _ => None,
            }),
            last_modified: p
                .last_modified
                .as_deref()
                .and_then(|s| httpdate::parse_http_date(s).ok()),
        })
        .collect();
    Ok(ParsedPathList {
        paths,
        continuation,
    })
}

/// Convert decoded `BlobListEntry`s into addressed `ObjectInfo`s.
pub(crate) fn list_xml_to_object_infos(
    parsed: &ParsedBlobList,
    address_root: &Url,
) -> Result<Vec<ObjectInfo>> {
    let mut items = Vec::new();
    let mut marker_addresses = std::collections::HashSet::new();
    for blob in &parsed.items {
        let blob_address = address::join_relative(address_root, &blob.name)?;
        let info = blob_to_object_info(blob, blob_address);
        if info.kind == ObjectKind::DirectoryMarker {
            marker_addresses.insert(info.address.as_str().to_string());
        }
        items.push(info);
    }
    for prefix in &parsed.prefixes {
        let address = address::join_relative(address_root, prefix)?;
        if marker_addresses.contains(address.as_str()) {
            continue;
        }
        // Azure flat-blob `BlobPrefix` is the wire's `CommonPrefix` analogue —
        // there's no backing object, so tag the entry as `DirectoryInferred`.
        items.push(ObjectInfo {
            address,
            kind: ObjectKind::DirectoryInferred,
            etag: None,
            version: None,
            size: None,
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: None,
            modified_by: None,
        });
    }
    Ok(items)
}

/// Convert a list of HNS path entries into addressed `ObjectInfo`s.
pub(crate) fn dfs_paths_to_object_infos(
    parsed: &ParsedPathList,
    address_root: &Url,
) -> Result<Vec<ObjectInfo>> {
    parsed
        .paths
        .iter()
        .map(|path| {
            let address = address::join_relative(address_root, &path.name)?;
            // HNS reports real directory inodes via the filesystem path API; mark
            // `ObjectKind::Directory` so the host dispatcher skips the marker-fold pass.
            Ok(ObjectInfo {
                address,
                kind: if path.is_directory {
                    ObjectKind::Directory
                } else {
                    ObjectKind::File
                },
                etag: path.etag.clone(),
                version: None,
                size: path.size,
                mtime: path.last_modified,
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: None,
                modified_by: None,
            })
        })
        .collect()
}

pub(crate) fn blob_to_object_info(blob: &BlobListEntry, address: Url) -> ObjectInfo {
    let mut checksums = ChecksumSet::new();
    if let Some(md5) = &blob.content_md5 {
        checksums.insert(ChecksumAlgorithm::md5(), md5.clone());
    }
    let mut system_metadata: SystemMetadata = HashMap::new();
    if let Some(content_type) = &blob.content_type {
        system_metadata.insert("content-type".into(), content_type.clone());
    }
    let is_marker = blob.name.ends_with('/') && blob.size.unwrap_or(0) == 0;
    ObjectInfo {
        address,
        kind: if is_marker {
            ObjectKind::DirectoryMarker
        } else {
            ObjectKind::File
        },
        etag: blob.etag.clone(),
        version: blob.version_id.clone(),
        size: (!is_marker).then_some(blob.size).flatten(),
        mtime: blob.last_modified,
        checksums,
        effective_permissions: None,
        system_metadata: if system_metadata.is_empty() {
            None
        } else {
            Some(system_metadata)
        },
        user_metadata: None,
        modified_by: None,
    }
}

/// Build a pinned-address `ObjectInfo` from a parsed list entry (when XML carries `include=versions`).
/// Returns `None` for entries lacking a `versionid` since they can't be addressed via a query-pin.
pub(crate) fn blob_to_version_item(
    blob: &BlobListEntry,
    address_root: &Url,
) -> Result<Option<ObjectInfo>> {
    let Some(version_id) = blob.version_id.clone() else {
        return Ok(None);
    };
    let blob_address = address::join_relative(address_root, &blob.name)?;
    let address = address::with_query_pair(&blob_address, "versionid", &version_id)?;
    Ok(Some(blob_to_object_info(blob, address)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_is_case_insensitive() {
        let headers = HeaderMap::from_pairs([("Content-Length", "42"), ("ETag", "\"abc\"")]);
        assert_eq!(headers.first("content-length"), Some("42"));
        assert_eq!(headers.first("etag"), Some("\"abc\""));
        assert_eq!(headers.first("missing"), None);
    }

    #[test]
    fn parse_object_info_packs_etag_size_and_user_metadata() {
        let headers = HeaderMap::from_pairs([
            ("ETag", "\"0x8DBABCD\""),
            ("Content-Length", "1024"),
            ("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT"),
            ("x-ms-version-id", "2024-01-01T00:00:00.0000000Z"),
            ("x-ms-meta-author", "Alice"),
            ("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
        ]);
        let address = address::parse("azure://acct/container/blob").unwrap();
        let info = parse_object_info(address, &headers, false).unwrap();
        assert_eq!(info.etag.as_deref(), Some("0x8DBABCD"));
        assert_eq!(info.size, Some(1024));
        assert_eq!(
            info.version.as_deref(),
            Some("2024-01-01T00:00:00.0000000Z")
        );
        assert!(info.mtime.is_some());
        let metadata = info.user_metadata.unwrap();
        assert_eq!(metadata.get("author").map(String::as_str), Some("Alice"));
        assert!(info.checksums.get(&ChecksumAlgorithm::md5()).is_some());
    }

    #[test]
    fn parse_blob_list_xml_handles_prefixes_and_blobs() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="container">
  <Prefix>logs/</Prefix>
  <Delimiter>/</Delimiter>
  <Blobs>
    <Blob>
      <Name>logs/2024-01-01.log</Name>
      <Properties>
        <Last-Modified>Mon, 01 Jan 2024 00:00:00 GMT</Last-Modified>
        <Etag>0x8DC0A</Etag>
        <Content-Length>500</Content-Length>
        <Content-Type>application/json</Content-Type>
        <Content-MD5>1B2M2Y8AsgTpgAmY7PhCfg==</Content-MD5>
      </Properties>
      <VersionId>2024-01-01T01:00:00.1234567Z</VersionId>
      <IsCurrentVersion>true</IsCurrentVersion>
    </Blob>
    <BlobPrefix>
      <Name>logs/sub/</Name>
    </BlobPrefix>
  </Blobs>
  <NextMarker>opaque-marker</NextMarker>
</EnumerationResults>"#;
        let parsed = parse_blob_list_xml(xml).unwrap();
        assert_eq!(parsed.items.len(), 1);
        let blob = &parsed.items[0];
        assert_eq!(blob.name, "logs/2024-01-01.log");
        assert_eq!(blob.size, Some(500));
        assert_eq!(blob.etag.as_deref(), Some("0x8DC0A"));
        assert_eq!(blob.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            blob.version_id.as_deref(),
            Some("2024-01-01T01:00:00.1234567Z")
        );
        assert_eq!(blob.is_current_version, Some(true));
        assert_eq!(parsed.prefixes, vec!["logs/sub/"]);
        assert_eq!(parsed.next_marker.as_deref(), Some("opaque-marker"));
    }

    #[test]
    fn parse_dfs_path_list_handles_directories_and_files() {
        let body = r#"{
  "paths": [
    { "name": "data/file1.bin", "contentLength": "12345", "etag": "0x8DC1A", "lastModified": "Tue, 02 Jan 2024 00:00:00 GMT" },
    { "name": "data/sub", "isDirectory": "true", "lastModified": "Tue, 02 Jan 2024 01:00:00 GMT" }
  ]
}"#;
        let parsed = parse_dfs_path_list_json(body, Some("next-page".into())).unwrap();
        assert_eq!(parsed.continuation.as_deref(), Some("next-page"));
        assert_eq!(parsed.paths.len(), 2);
        assert!(!parsed.paths[0].is_directory);
        assert_eq!(parsed.paths[0].size, Some(12345));
        assert!(parsed.paths[1].is_directory);
        assert!(parsed.paths[1].size.is_none());
    }

    #[test]
    fn version_listing_uses_versionid_query_address() {
        let blob = BlobListEntry {
            name: "blob.bin".into(),
            etag: Some("0x1".into()),
            size: Some(7),
            last_modified: None,
            content_md5: None,
            content_type: None,
            version_id: Some("v1".into()),
            is_current_version: Some(false),
        };
        let root = Url::parse("azure://acct/container/").unwrap();
        let item = blob_to_version_item(&blob, &root)
            .unwrap()
            .expect("expected version item");
        assert_eq!(
            item.address.as_str(),
            "azure://acct/container/blob.bin?versionid=v1"
        );
    }

    #[test]
    fn quoted_etag_round_trips_to_unquoted() {
        assert_eq!(strip_quotes("\"abc\""), "abc");
        assert_eq!(strip_quotes("abc"), "abc");
        assert_eq!(strip_quotes("\"\""), "");
    }

    #[test]
    fn parse_object_info_tags_hns_directory_kind_from_resource_type() {
        // ADLS Gen2 `getStatus` returns `x-ms-resource-type: directory`
        // on directory inodes. The dispatcher's marker-fold runs on
        // `list`, not `stat`, so the kind has to be authoritative here
        // or a direct `stat` call sees `File` for a real directory.
        let headers = HeaderMap::from_pairs([
            ("ETag", "\"0x8DC1B\""),
            ("Content-Length", "0"),
            ("x-ms-resource-type", "directory"),
        ]);
        let address = address::parse("azure://acct/container/dir").unwrap();
        let info = parse_object_info(address, &headers, true).unwrap();
        assert_eq!(info.kind, ObjectKind::Directory);
    }

    #[test]
    fn parse_object_info_files_remain_file_kind() {
        let headers = HeaderMap::from_pairs([
            ("ETag", "\"0x8DC1B\""),
            ("Content-Length", "42"),
            ("x-ms-resource-type", "file"),
        ]);
        let address = address::parse("azure://acct/container/x.txt").unwrap();
        let info = parse_object_info(address, &headers, true).unwrap();
        assert_eq!(info.kind, ObjectKind::File);
    }

    #[test]
    fn parse_object_info_without_resource_type_defaults_to_file() {
        // Flat Azure-Blob `Get Blob Properties` doesn't set
        // `x-ms-resource-type`; the kind defaults to `File` and the
        // `stat` call site stamps `DirectoryMarker` for a
        // trailing-slash address based on its own state.
        let headers = HeaderMap::from_pairs([("ETag", "\"0x8DC1B\""), ("Content-Length", "0")]);
        let address = address::parse("azure://acct/container/x.txt").unwrap();
        let info = parse_object_info(address, &headers, false).unwrap();
        assert_eq!(info.kind, ObjectKind::File);
    }
}
