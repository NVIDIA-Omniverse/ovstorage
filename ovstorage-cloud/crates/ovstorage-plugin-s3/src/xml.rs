// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal XML parsing for S3 list / multipart responses.
//! Event-driven `quick-xml`: malformed responses surface as clean errors, not serde-derive panics.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use ovstorage_plugin::{Error, ErrorCode, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListBucketResult {
    pub contents: Vec<ListObject>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListObject {
    pub key: String,
    pub size: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub storage_class: Option<String>,
}

pub fn parse_list_objects_v2(body: &str) -> Result<ListBucketResult> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut result = ListBucketResult::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut current_object = ListObject::default();
    let mut current_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = std::str::from_utf8(tag.name().as_ref())
                    .map_err(xml_err)?
                    .to_string();
                if name == "Contents" {
                    current_object = ListObject::default();
                }
                path.push(name);
                current_text.clear();
            }
            Ok(Event::End(_tag)) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str);
                let text = std::mem::take(&mut current_text);
                match (parent, name.as_str()) {
                    (Some("Contents"), "Key") => current_object.key = text,
                    (Some("Contents"), "Size") => {
                        current_object.size = text.parse::<u64>().ok();
                    }
                    (Some("Contents"), "ETag") => current_object.etag = Some(strip_quotes(&text)),
                    (Some("Contents"), "LastModified") => {
                        current_object.last_modified = Some(text);
                    }
                    (Some("Contents"), "StorageClass") => {
                        current_object.storage_class = Some(text);
                    }
                    (Some("ListBucketResult"), "Contents") => {
                        result.contents.push(std::mem::take(&mut current_object));
                    }
                    (Some("CommonPrefixes"), "Prefix") => {
                        result.common_prefixes.push(text);
                    }
                    (Some("ListBucketResult"), "IsTruncated") => {
                        result.is_truncated = text.eq_ignore_ascii_case("true");
                    }
                    (Some("ListBucketResult"), "NextContinuationToken") => {
                        result.next_continuation_token = Some(text);
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(text)) => {
                current_text.push_str(&text.unescape().map_err(xml_err)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(xml_err(err)),
            _ => {}
        }
        buf.clear();
    }
    Ok(result)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListVersionsResult {
    pub versions: Vec<VersionEntry>,
    pub delete_markers: Vec<VersionEntry>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_key_marker: Option<String>,
    pub next_version_id_marker: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionEntry {
    pub key: String,
    pub version_id: Option<String>,
    pub is_latest: bool,
    pub size: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub storage_class: Option<String>,
}

pub fn parse_list_versions(body: &str) -> Result<ListVersionsResult> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut result = ListVersionsResult::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut current_entry = VersionEntry::default();
    let mut current_kind: Option<&'static str> = None;
    let mut current_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = std::str::from_utf8(tag.name().as_ref())
                    .map_err(xml_err)?
                    .to_string();
                if name == "Version" {
                    current_entry = VersionEntry::default();
                    current_kind = Some("Version");
                } else if name == "DeleteMarker" {
                    current_entry = VersionEntry::default();
                    current_kind = Some("DeleteMarker");
                }
                path.push(name);
                current_text.clear();
            }
            Ok(Event::End(_tag)) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str);
                let text = std::mem::take(&mut current_text);
                match (parent, name.as_str()) {
                    (Some("Version") | Some("DeleteMarker"), "Key") => current_entry.key = text,
                    (Some("Version") | Some("DeleteMarker"), "VersionId") => {
                        current_entry.version_id = Some(text);
                    }
                    (Some("Version") | Some("DeleteMarker"), "IsLatest") => {
                        current_entry.is_latest = text.eq_ignore_ascii_case("true");
                    }
                    (Some("Version") | Some("DeleteMarker"), "LastModified") => {
                        current_entry.last_modified = Some(text);
                    }
                    (Some("Version"), "Size") => {
                        current_entry.size = text.parse::<u64>().ok();
                    }
                    (Some("Version"), "ETag") => current_entry.etag = Some(strip_quotes(&text)),
                    (Some("Version") | Some("DeleteMarker"), "StorageClass") => {
                        current_entry.storage_class = Some(text);
                    }
                    (Some("ListVersionsResult"), "Version") => {
                        result.versions.push(std::mem::take(&mut current_entry));
                        current_kind = None;
                    }
                    (Some("ListVersionsResult"), "DeleteMarker") => {
                        result
                            .delete_markers
                            .push(std::mem::take(&mut current_entry));
                        current_kind = None;
                    }
                    (Some("CommonPrefixes"), "Prefix") => {
                        result.common_prefixes.push(text);
                    }
                    (Some("ListVersionsResult"), "IsTruncated") => {
                        result.is_truncated = text.eq_ignore_ascii_case("true");
                    }
                    (Some("ListVersionsResult"), "NextKeyMarker") => {
                        result.next_key_marker = Some(text);
                    }
                    (Some("ListVersionsResult"), "NextVersionIdMarker") => {
                        result.next_version_id_marker = Some(text);
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(text)) => {
                current_text.push_str(&text.unescape().map_err(xml_err)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(xml_err(err)),
            _ => {}
        }
        buf.clear();
    }
    let _ = current_kind;
    Ok(result)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InitiateMultipartUploadResult {
    pub upload_id: String,
}

pub fn parse_initiate_multipart_upload(body: &str) -> Result<InitiateMultipartUploadResult> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut result = InitiateMultipartUploadResult::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut current_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = std::str::from_utf8(tag.name().as_ref())
                    .map_err(xml_err)?
                    .to_string();
                path.push(name);
                current_text.clear();
            }
            Ok(Event::End(_tag)) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str);
                if let (Some("InitiateMultipartUploadResult"), "UploadId") = (parent, name.as_str())
                {
                    result.upload_id = std::mem::take(&mut current_text);
                } else {
                    current_text.clear();
                }
            }
            Ok(Event::Text(text)) => {
                current_text.push_str(&text.unescape().map_err(xml_err)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(xml_err(err)),
            _ => {}
        }
        buf.clear();
    }

    if result.upload_id.is_empty() {
        return Err(Error::new(
            ErrorCode::Internal,
            "S3 InitiateMultipartUpload response did not contain an UploadId",
        ));
    }
    Ok(result)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompleteMultipartUploadResult {
    pub etag: Option<String>,
    pub key: Option<String>,
    pub version_id: Option<String>,
}

pub fn parse_complete_multipart_upload(body: &str) -> Result<CompleteMultipartUploadResult> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut result = CompleteMultipartUploadResult::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut current_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = std::str::from_utf8(tag.name().as_ref())
                    .map_err(xml_err)?
                    .to_string();
                path.push(name);
                current_text.clear();
            }
            Ok(Event::End(_tag)) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str);
                let text = std::mem::take(&mut current_text);
                match (parent, name.as_str()) {
                    (Some("CompleteMultipartUploadResult"), "ETag") => {
                        result.etag = Some(strip_quotes(&text));
                    }
                    (Some("CompleteMultipartUploadResult"), "Key") => {
                        result.key = Some(text);
                    }
                    (Some("CompleteMultipartUploadResult"), "VersionId") => {
                        result.version_id = Some(text);
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(text)) => {
                current_text.push_str(&text.unescape().map_err(xml_err)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(xml_err(err)),
            _ => {}
        }
        buf.clear();
    }
    Ok(result)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct S3ErrorBody {
    pub code: Option<String>,
    pub message: Option<String>,
}

/// Detect `<Error>` anywhere in the body. `CompleteMultipartUpload` can return HTTP 200 with an
/// `<Error>` envelope during long stitches; without this check, a failed commit looks like a success.
pub fn parse_s3_error(body: &str) -> Option<S3ErrorBody> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);
    let mut path: Vec<String> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut current_text = String::new();
    let mut result = S3ErrorBody::default();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = std::str::from_utf8(tag.name().as_ref()).ok()?.to_string();
                path.push(name);
                current_text.clear();
            }
            Ok(Event::End(_)) => {
                let name = path.pop().unwrap_or_default();
                let text = std::mem::take(&mut current_text);
                let in_error = path.iter().any(|p| p == "Error");
                if in_error {
                    match name.as_str() {
                        "Code" => result.code = Some(text),
                        "Message" => result.message = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::Text(text)) => {
                current_text.push_str(&text.unescape().ok()?);
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
    if result.code.is_some() {
        Some(result)
    } else {
        None
    }
}

/// Build a `CompleteMultipartUpload` body from ordered `(part_number, etag)` entries.
pub fn build_complete_multipart_upload_body(parts: &[(u32, String)]) -> String {
    let mut out = String::new();
    out.push_str("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        out.push_str("<Part><PartNumber>");
        out.push_str(&number.to_string());
        out.push_str("</PartNumber><ETag>");
        out.push_str(&etag_escape(etag));
        out.push_str("</ETag></Part>");
    }
    out.push_str("</CompleteMultipartUpload>");
    out
}

fn etag_escape(value: &str) -> String {
    let value = strip_quotes(value);
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn strip_quotes(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn xml_err<E: std::fmt::Display>(err: E) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("S3 XML response could not be parsed: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_objects_v2_parses_contents_and_common_prefixes() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>example-bucket</Name>
  <Prefix>photos/</Prefix>
  <Delimiter>/</Delimiter>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>photos/cat.jpg</Key>
    <LastModified>2024-01-02T03:04:05.000Z</LastModified>
    <ETag>"abc123"</ETag>
    <Size>1024</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>photos/dog.jpg</Key>
    <LastModified>2024-01-03T03:04:05.000Z</LastModified>
    <ETag>"def456"</ETag>
    <Size>2048</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes>
    <Prefix>photos/raw/</Prefix>
  </CommonPrefixes>
  <CommonPrefixes>
    <Prefix>photos/edited/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;
        let result = parse_list_objects_v2(body).unwrap();
        assert_eq!(result.contents.len(), 2);
        assert_eq!(result.contents[0].key, "photos/cat.jpg");
        assert_eq!(result.contents[0].etag.as_deref(), Some("abc123"));
        assert_eq!(result.contents[0].size, Some(1024));
        assert_eq!(result.contents[1].key, "photos/dog.jpg");
        assert_eq!(
            result.common_prefixes,
            vec!["photos/raw/", "photos/edited/"]
        );
        assert!(!result.is_truncated);
        assert!(result.next_continuation_token.is_none());
    }

    #[test]
    fn list_versions_parses_versions_and_delete_markers() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult>
  <Name>bkt</Name>
  <IsTruncated>true</IsTruncated>
  <NextKeyMarker>k</NextKeyMarker>
  <NextVersionIdMarker>v</NextVersionIdMarker>
  <Version>
    <Key>obj</Key>
    <VersionId>v1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2024-01-02T03:04:05.000Z</LastModified>
    <ETag>"v1etag"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>obj</Key>
    <VersionId>v0</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>"#;
        let result = parse_list_versions(body).unwrap();
        assert_eq!(result.versions.len(), 1);
        assert_eq!(result.versions[0].version_id.as_deref(), Some("v1"));
        assert_eq!(result.versions[0].size, Some(10));
        assert_eq!(result.delete_markers.len(), 1);
        assert!(result.is_truncated);
        assert_eq!(result.next_key_marker.as_deref(), Some("k"));
    }

    #[test]
    fn initiate_multipart_upload_extracts_upload_id() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
  <Bucket>bkt</Bucket>
  <Key>k</Key>
  <UploadId>UPLOAD-ABC</UploadId>
</InitiateMultipartUploadResult>"#;
        let result = parse_initiate_multipart_upload(body).unwrap();
        assert_eq!(result.upload_id, "UPLOAD-ABC");
    }

    #[test]
    fn complete_multipart_upload_extracts_etag() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
  <Location>https://bkt.s3.amazonaws.com/k</Location>
  <Bucket>bkt</Bucket>
  <Key>k</Key>
  <ETag>"final-etag-1"</ETag>
</CompleteMultipartUploadResult>"#;
        let result = parse_complete_multipart_upload(body).unwrap();
        assert_eq!(result.etag.as_deref(), Some("final-etag-1"));
        assert_eq!(result.key.as_deref(), Some("k"));
    }

    #[test]
    fn parse_s3_error_extracts_code_from_root_error_envelope() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InternalError</Code><Message>boom</Message><RequestId>r1</RequestId></Error>"#;
        let parsed = parse_s3_error(body).expect("error should parse");
        assert_eq!(parsed.code.as_deref(), Some("InternalError"));
        assert_eq!(parsed.message.as_deref(), Some("boom"));
    }

    #[test]
    fn parse_s3_error_returns_none_for_success_envelope() {
        let body =
            r#"<CompleteMultipartUploadResult><ETag>"e"</ETag></CompleteMultipartUploadResult>"#;
        assert!(parse_s3_error(body).is_none());
    }

    #[test]
    fn build_complete_multipart_upload_body_serialises_parts() {
        let body = build_complete_multipart_upload_body(&[
            (1, "etag-1".to_string()),
            (2, "\"etag-2\"".to_string()),
        ]);
        assert_eq!(
            body,
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>\"etag-2\"</ETag></Part></CompleteMultipartUpload>",
        );
    }
}
