// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Read;

use flate2::read::DeflateDecoder;
use ovstorage_plugin::{Error, ErrorCode, Result};
use serde_json::Value;

const MAGIC: &[u8; 4] = b"Obj\x01";
const SYNC_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ChangeFeedRecord {
    pub event_type: String,
    pub subject: String,
    pub event_time: String,
    pub etag: Option<String>,
    pub url: Option<String>,
    /// Blob content length from `data.contentLength`. Populated for
    /// create / properties-update / tier-change records; absent on
    /// deletes.
    pub content_length: Option<u64>,
    /// Blob version ID from `data.blobVersion` (or `data.versionId`).
    /// Populated only when versioning is enabled on the account.
    pub version_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AvroType {
    Null,
    Boolean,
    Int,
    Long,
    Float,
    Double,
    Bytes,
    String,
    Record(Vec<Field>),
    Union(Vec<AvroType>),
    Map(Box<AvroType>),
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Field {
    name: String,
    ty: AvroType,
}

pub(crate) fn decode_change_feed_records(bytes: &[u8]) -> Result<Vec<ChangeFeedRecord>> {
    let mut input = DecoderInput::new(bytes);
    input.expect_bytes(MAGIC, "Avro object container magic")?;
    let metadata = read_metadata_map(&mut input)?;
    let sync = input.read_fixed(SYNC_LEN, "Avro sync marker")?.to_vec();
    let schema_json = metadata.get("avro.schema").ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "Avro object container is missing avro.schema metadata",
        )
    })?;
    let codec = metadata
        .get("avro.codec")
        .map(String::as_str)
        .unwrap_or("null");
    let schema_value: Value = serde_json::from_str(schema_json).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("Avro schema metadata is not valid JSON: {err}"),
        )
    })?;
    let schema = parse_schema(&schema_value)?;
    let mut records = Vec::new();

    while !input.is_eof() {
        let count = input.read_long("Avro block count")?;
        if count < 0 {
            return Err(Error::new(
                ErrorCode::Internal,
                "Avro block count must not be negative",
            ));
        }
        let block_len = input.read_long("Avro block byte length")?;
        if block_len < 0 {
            return Err(Error::new(
                ErrorCode::Internal,
                "Avro block byte length must not be negative",
            ));
        }
        let compressed = input
            .read_fixed(block_len as usize, "Avro block payload")?
            .to_vec();
        let block = decode_block_payload(codec, &compressed)?;
        let got_sync = input.read_fixed(SYNC_LEN, "Avro block sync marker")?;
        if got_sync != sync.as_slice() {
            return Err(Error::new(
                ErrorCode::Internal,
                "Avro block sync marker did not match object header",
            ));
        }

        let mut block_input = DecoderInput::new(&block);
        for _ in 0..count {
            records.push(read_change_feed_record(&schema, &mut block_input)?);
        }
        if !block_input.is_eof() {
            return Err(Error::new(
                ErrorCode::Internal,
                "Avro block contained trailing bytes after declared records",
            ));
        }
    }

    Ok(records)
}

fn decode_block_payload(codec: &str, payload: &[u8]) -> Result<Vec<u8>> {
    match codec {
        "null" => Ok(payload.to_vec()),
        "deflate" => {
            let mut decoder = DeflateDecoder::new(payload);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("Avro deflate block could not be decompressed: {err}"),
                )
            })?;
            Ok(out)
        }
        other => Err(Error::new(
            ErrorCode::Internal,
            format!("Avro codec '{other}' is not supported"),
        )),
    }
}

fn read_metadata_map(input: &mut DecoderInput<'_>) -> Result<HashMap<String, String>> {
    let mut out = HashMap::new();
    loop {
        let mut count = input.read_long("Avro metadata map count")?;
        if count == 0 {
            return Ok(out);
        }
        if count < 0 {
            count = -count;
            let _ = input.read_long("Avro metadata map block size")?;
        }
        for _ in 0..count {
            let key = input.read_string("Avro metadata key")?;
            let value = input.read_bytes("Avro metadata value")?;
            let value = String::from_utf8(value).map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("Avro metadata value for '{key}' is not UTF-8: {err}"),
                )
            })?;
            out.insert(key, value);
        }
    }
}

fn parse_schema(value: &Value) -> Result<AvroType> {
    match value {
        Value::String(name) => Ok(parse_type_name(name)),
        Value::Array(branches) => {
            let mut parsed = Vec::with_capacity(branches.len());
            for branch in branches {
                parsed.push(parse_schema(branch)?);
            }
            Ok(AvroType::Union(parsed))
        }
        Value::Object(map) => {
            let ty = map
                .get("type")
                .ok_or_else(|| Error::new(ErrorCode::Internal, "Avro schema object lacks type"))?;
            if let Some(name) = ty.as_str() {
                match name {
                    "record" => {
                        let fields =
                            map.get("fields").and_then(Value::as_array).ok_or_else(|| {
                                Error::new(ErrorCode::Internal, "Avro record lacks fields")
                            })?;
                        let mut out = Vec::with_capacity(fields.len());
                        for field in fields {
                            let field_obj = field.as_object().ok_or_else(|| {
                                Error::new(ErrorCode::Internal, "Avro field is not an object")
                            })?;
                            let name = field_obj
                                .get("name")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    Error::new(ErrorCode::Internal, "Avro field lacks name")
                                })?
                                .to_string();
                            let ty = field_obj.get("type").ok_or_else(|| {
                                Error::new(ErrorCode::Internal, "Avro field lacks type")
                            })?;
                            out.push(Field {
                                name,
                                ty: parse_schema(ty)?,
                            });
                        }
                        Ok(AvroType::Record(out))
                    }
                    "map" => {
                        let values = map.get("values").ok_or_else(|| {
                            Error::new(ErrorCode::Internal, "Avro map lacks values")
                        })?;
                        Ok(AvroType::Map(Box::new(parse_schema(values)?)))
                    }
                    "array" | "enum" | "fixed" => Ok(AvroType::Unsupported(name.into())),
                    primitive => Ok(parse_type_name(primitive)),
                }
            } else if ty.is_array() {
                parse_schema(ty)
            } else {
                Err(Error::new(
                    ErrorCode::Internal,
                    "Avro schema type must be a string or union",
                ))
            }
        }
        _ => Err(Error::new(
            ErrorCode::Internal,
            "Avro schema node must be a string, object, or union",
        )),
    }
}

fn parse_type_name(name: &str) -> AvroType {
    match name {
        "null" => AvroType::Null,
        "boolean" => AvroType::Boolean,
        "int" => AvroType::Int,
        "long" => AvroType::Long,
        "float" => AvroType::Float,
        "double" => AvroType::Double,
        "bytes" => AvroType::Bytes,
        "string" => AvroType::String,
        other => AvroType::Unsupported(other.into()),
    }
}

fn read_change_feed_record(
    schema: &AvroType,
    input: &mut DecoderInput<'_>,
) -> Result<ChangeFeedRecord> {
    let mut record = ChangeFeedRecord::default();
    read_root_record(schema, input, &mut record)?;
    if record.event_type.is_empty() || record.subject.is_empty() {
        return Err(Error::new(
            ErrorCode::Internal,
            "Avro change-feed record lacked eventType or subject",
        ));
    }
    Ok(record)
}

fn read_root_record(
    schema: &AvroType,
    input: &mut DecoderInput<'_>,
    record: &mut ChangeFeedRecord,
) -> Result<()> {
    let AvroType::Record(fields) = schema else {
        return Err(Error::new(
            ErrorCode::Internal,
            "Avro change-feed schema root must be a record",
        ));
    };
    for field in fields {
        match field.name.as_str() {
            "eventType" => record.event_type = read_nullable_string(&field.ty, input)?,
            "subject" => record.subject = read_nullable_string(&field.ty, input)?,
            "eventTime" => record.event_time = read_nullable_string(&field.ty, input)?,
            "data" => read_data_record(&field.ty, input, record)?,
            _ => skip_supported(&field.ty, input)?,
        }
    }
    Ok(())
}

fn read_data_record(
    schema: &AvroType,
    input: &mut DecoderInput<'_>,
    record: &mut ChangeFeedRecord,
) -> Result<()> {
    match schema {
        AvroType::Union(branches) => {
            let index = input.read_long("Avro union branch")?;
            if index < 0 || index as usize >= branches.len() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "Avro union branch is invalid",
                ));
            }
            read_data_record(&branches[index as usize], input, record)
        }
        AvroType::Null => Ok(()),
        AvroType::Record(fields) => {
            for field in fields {
                match field.name.as_str() {
                    "url" => record.url = Some(read_nullable_string(&field.ty, input)?),
                    "eTag" | "etag" => record.etag = Some(read_nullable_string(&field.ty, input)?),
                    "contentLength" => {
                        record.content_length = read_nullable_long(&field.ty, input)?
                            .and_then(|v| u64::try_from(v).ok());
                    }
                    "blobVersion" | "versionId" => {
                        let value = read_nullable_string(&field.ty, input)?;
                        if !value.is_empty() {
                            record.version_id = Some(value);
                        }
                    }
                    "metadata" => record.metadata = read_nullable_string_map(&field.ty, input)?,
                    _ => skip_supported(&field.ty, input)?,
                }
            }
            Ok(())
        }
        _ => Err(Error::new(
            ErrorCode::Internal,
            "Avro change-feed data field must be a record or nullable record",
        )),
    }
}

fn read_nullable_string(schema: &AvroType, input: &mut DecoderInput<'_>) -> Result<String> {
    match schema {
        AvroType::String => input.read_string("Avro string"),
        AvroType::Union(branches) => {
            let index = input.read_long("Avro union branch")?;
            if index < 0 || index as usize >= branches.len() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "Avro union branch is invalid",
                ));
            }
            match &branches[index as usize] {
                AvroType::Null => Ok(String::new()),
                branch => read_nullable_string(branch, input),
            }
        }
        _ => Err(Error::new(
            ErrorCode::Internal,
            "Avro field was not a string or nullable string",
        )),
    }
}

fn read_nullable_long(schema: &AvroType, input: &mut DecoderInput<'_>) -> Result<Option<i64>> {
    match schema {
        AvroType::Long | AvroType::Int => input.read_long("Avro long").map(Some),
        AvroType::Union(branches) => {
            let index = input.read_long("Avro union branch")?;
            if index < 0 || index as usize >= branches.len() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "Avro union branch is invalid",
                ));
            }
            match &branches[index as usize] {
                AvroType::Null => Ok(None),
                branch => read_nullable_long(branch, input),
            }
        }
        _ => Err(Error::new(
            ErrorCode::Internal,
            "Avro field was not a long or nullable long",
        )),
    }
}

fn read_nullable_string_map(
    schema: &AvroType,
    input: &mut DecoderInput<'_>,
) -> Result<HashMap<String, String>> {
    match schema {
        AvroType::Map(value) if matches!(value.as_ref(), AvroType::String) => {
            input.read_string_map()
        }
        AvroType::Union(branches) => {
            let index = input.read_long("Avro union branch")?;
            if index < 0 || index as usize >= branches.len() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "Avro union branch is invalid",
                ));
            }
            match &branches[index as usize] {
                AvroType::Null => Ok(HashMap::new()),
                branch => read_nullable_string_map(branch, input),
            }
        }
        _ => Err(Error::new(
            ErrorCode::Internal,
            "Avro metadata field was not map<string,string>",
        )),
    }
}

fn skip_supported(schema: &AvroType, input: &mut DecoderInput<'_>) -> Result<()> {
    match schema {
        AvroType::Null => Ok(()),
        AvroType::Boolean => input.skip_fixed(1, "Avro boolean"),
        AvroType::Int | AvroType::Long => input.skip_long("Avro integer"),
        AvroType::Float => input.skip_fixed(4, "Avro float"),
        AvroType::Double => input.skip_fixed(8, "Avro double"),
        AvroType::Bytes | AvroType::String => {
            let len = input.read_long("Avro bytes length")?;
            if len < 0 {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "Avro bytes length must not be negative",
                ));
            }
            input.skip_fixed(len as usize, "Avro bytes")
        }
        AvroType::Union(branches) => {
            let index = input.read_long("Avro union branch")?;
            if index < 0 || index as usize >= branches.len() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "Avro union branch is invalid",
                ));
            }
            skip_supported(&branches[index as usize], input)
        }
        AvroType::Map(value) => loop {
            let mut count = input.read_long("Avro map count")?;
            if count == 0 {
                return Ok(());
            }
            if count < 0 {
                count = -count;
                let _ = input.read_long("Avro map block size")?;
            }
            for _ in 0..count {
                let _ = input.read_string("Avro map key")?;
                skip_supported(value, input)?;
            }
        },
        AvroType::Record(_) => Err(Error::new(
            ErrorCode::Internal,
            "Avro schema contains an unsupported unknown record field",
        )),
        AvroType::Unsupported(_) => Err(Error::new(
            ErrorCode::Internal,
            "Avro schema contains an unsupported complex unknown field",
        )),
    }
}

struct DecoderInput<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DecoderInput<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn expect_bytes(&mut self, expected: &[u8], label: &str) -> Result<()> {
        let got = self.read_fixed(expected.len(), label)?;
        if got == expected {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                format!("{label} did not match expected bytes"),
            ))
        }
    }

    fn read_fixed(&mut self, len: usize, label: &str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::new(ErrorCode::Internal, format!("{label} length overflowed")))?;
        let slice = self.bytes.get(self.pos..end).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                format!("Avro input ended while reading {label}"),
            )
        })?;
        self.pos = end;
        Ok(slice)
    }

    fn skip_fixed(&mut self, len: usize, label: &str) -> Result<()> {
        let _ = self.read_fixed(len, label)?;
        Ok(())
    }

    fn read_long(&mut self, label: &str) -> Result<i64> {
        let mut value: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = *self.read_fixed(1, label)?.first().unwrap();
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                let decoded = ((value >> 1) as i64) ^ (-((value & 1) as i64));
                return Ok(decoded);
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!("{label} varint was too long"),
                ));
            }
        }
    }

    fn skip_long(&mut self, label: &str) -> Result<()> {
        let _ = self.read_long(label)?;
        Ok(())
    }

    fn read_bytes(&mut self, label: &str) -> Result<Vec<u8>> {
        let len = self.read_long(label)?;
        if len < 0 {
            return Err(Error::new(
                ErrorCode::Internal,
                format!("{label} length must not be negative"),
            ));
        }
        Ok(self.read_fixed(len as usize, label)?.to_vec())
    }

    fn read_string(&mut self, label: &str) -> Result<String> {
        let bytes = self.read_bytes(label)?;
        String::from_utf8(bytes).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("{label} was not valid UTF-8: {err}"),
            )
        })
    }

    fn read_string_map(&mut self) -> Result<HashMap<String, String>> {
        let mut out = HashMap::new();
        loop {
            let mut count = self.read_long("Avro map count")?;
            if count == 0 {
                return Ok(out);
            }
            if count < 0 {
                count = -count;
                let _ = self.read_long("Avro map block size")?;
            }
            for _ in 0..count {
                let key = self.read_string("Avro map key")?;
                let value = self.read_string("Avro map value")?;
                out.insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::DeflateEncoder;
    use std::io::Write;

    const SYNC: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn decodes_null_codec_container() {
        let bytes = container("null", base_schema(None), record_bytes(None), false);
        let records = decode_change_feed_records(&bytes).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_type, "BlobCreated");
        assert_eq!(records[0].subject, subject());
        assert_eq!(
            records[0].metadata.get("tier").map(String::as_str),
            Some("hot")
        );
    }

    #[test]
    fn decodes_deflate_codec_container() {
        let bytes = container("deflate", base_schema(None), record_bytes(None), false);
        let records = decode_change_feed_records(&bytes).unwrap();
        assert_eq!(records[0].event_type, "BlobCreated");
    }

    #[test]
    fn unsupported_codec_surfaces_as_error() {
        let bytes = container("snappy", base_schema(None), record_bytes(None), false);
        let err = decode_change_feed_records(&bytes).unwrap_err();
        assert!(err.message().contains("snappy"));
    }

    #[test]
    fn decodes_content_length_and_blob_version_into_record() {
        // Schema with extra data fields the production decoder maps to
        // `content_length` / `version_id`.
        let schema = r#"{
            "type":"record",
            "name":"ChangeFeedEvent",
            "fields":[
                {"name":"eventType","type":"string"},
                {"name":"subject","type":"string"},
                {"name":"eventTime","type":"string"},
                {"name":"data","type":{
                    "type":"record",
                    "name":"Data",
                    "fields":[
                        {"name":"url","type":["null","string"]},
                        {"name":"eTag","type":["null","string"]},
                        {"name":"contentLength","type":["null","long"]},
                        {"name":"blobVersion","type":["null","string"]},
                        {"name":"metadata","type":["null",{"type":"map","values":"string"}]}
                    ]
                }}
            ]
        }"#;
        let mut record = Vec::new();
        put_string(&mut record, "BlobCreated");
        put_string(&mut record, &subject());
        put_string(&mut record, "2026-05-12T10:00:00Z");
        // data record (bare record, no union branch tag in this schema)
        // url: union branch 1 (string)
        put_long(&mut record, 1);
        put_string(
            &mut record,
            "https://acct.blob.core.windows.net/container/dir/blob.txt",
        );
        // eTag: union branch 1 (string)
        put_long(&mut record, 1);
        put_string(&mut record, "0x8DC");
        // contentLength: union branch 1 (long) 4096
        put_long(&mut record, 1);
        put_long(&mut record, 4096);
        // blobVersion: union branch 1 (string)
        put_long(&mut record, 1);
        put_string(&mut record, "2026-05-12T10:00:00.1234567Z");
        // metadata: union branch 0 (null)
        put_long(&mut record, 0);
        let bytes = container("null", schema.into(), record, false);

        let records = decode_change_feed_records(&bytes).unwrap();
        assert_eq!(records[0].content_length, Some(4096));
        assert_eq!(
            records[0].version_id.as_deref(),
            Some("2026-05-12T10:00:00.1234567Z")
        );
    }

    #[test]
    fn skips_supported_primitive_unknown_field() {
        let bytes = container(
            "null",
            base_schema(Some(r#"{"name":"future","type":"long"}"#)),
            {
                let mut bytes = record_prefix();
                put_long(&mut bytes, 42);
                record_suffix(&mut bytes);
                bytes
            },
            false,
        );
        let records = decode_change_feed_records(&bytes).unwrap();
        assert_eq!(records[0].event_type, "BlobCreated");
    }

    #[test]
    fn unknown_nested_record_field_surfaces_as_error() {
        let unknown = r#"{"name":"future","type":{"type":"record","name":"Future","fields":[{"name":"child","type":{"type":"record","name":"Child","fields":[{"name":"label","type":"string"}]}},{"name":"count","type":"long"}]}}"#;
        let bytes = container(
            "null",
            base_schema(Some(unknown)),
            {
                let mut bytes = record_prefix();
                put_string(&mut bytes, "nested");
                put_long(&mut bytes, 42);
                record_suffix(&mut bytes);
                bytes
            },
            false,
        );
        let err = decode_change_feed_records(&bytes).unwrap_err();
        assert!(err.message().contains("unknown record field"));
    }

    #[test]
    fn unsupported_complex_unknown_field_surfaces_as_error() {
        let unknown = r#"{"name":"future","type":{"type":"array","items":"string"}}"#;
        let bytes = container(
            "null",
            base_schema(Some(unknown)),
            {
                let mut bytes = record_prefix();
                put_long(&mut bytes, 0);
                record_suffix(&mut bytes);
                bytes
            },
            false,
        );
        let err = decode_change_feed_records(&bytes).unwrap_err();
        assert!(err.message().contains("unsupported complex unknown"));
    }

    #[test]
    fn truncated_container_surfaces_as_error() {
        let mut bytes = container("null", base_schema(None), record_bytes(None), false);
        bytes.truncate(bytes.len() - 3);
        let err = decode_change_feed_records(&bytes).unwrap_err();
        assert!(err.message().contains("sync marker"));
    }

    #[test]
    fn sync_mismatch_surfaces_as_error() {
        let bytes = container("null", base_schema(None), record_bytes(None), true);
        let err = decode_change_feed_records(&bytes).unwrap_err();
        assert!(err.message().contains("sync marker"));
    }

    fn base_schema(extra_field: Option<&str>) -> String {
        let extra = extra_field
            .map(|field| format!("{field},"))
            .unwrap_or_default();
        format!(
            r#"{{
                "type":"record",
                "name":"ChangeFeedEvent",
                "fields":[
                    {{"name":"eventType","type":"string"}},
                    {{"name":"subject","type":"string"}},
                    {{"name":"eventTime","type":"string"}},
                    {extra}
                    {{"name":"data","type":{{
                        "type":"record",
                        "name":"Data",
                        "fields":[
                            {{"name":"url","type":["null","string"]}},
                            {{"name":"eTag","type":["null","string"]}},
                            {{"name":"metadata","type":["null",{{"type":"map","values":"string"}}]}}
                        ]
                    }}}}
                ]
            }}"#
        )
    }

    fn record_bytes(extra: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = record_prefix();
        if let Some(extra) = extra {
            bytes.extend_from_slice(extra);
        }
        record_suffix(&mut bytes);
        bytes
    }

    fn record_prefix() -> Vec<u8> {
        let mut bytes = Vec::new();
        put_string(&mut bytes, "BlobCreated");
        put_string(&mut bytes, &subject());
        put_string(&mut bytes, "2026-05-12T10:00:00Z");
        bytes
    }

    fn record_suffix(bytes: &mut Vec<u8>) {
        put_long(bytes, 1);
        put_string(
            bytes,
            "https://acct.blob.core.windows.net/container/dir/blob.txt",
        );
        put_long(bytes, 1);
        put_string(bytes, "0x8DB");
        put_long(bytes, 1);
        put_long(bytes, 1);
        put_string(bytes, "tier");
        put_string(bytes, "hot");
        put_long(bytes, 0);
    }

    fn subject() -> String {
        "/blobServices/default/containers/container/blobs/dir/blob.txt".into()
    }

    fn container(codec: &str, schema: String, record: Vec<u8>, bad_sync: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_long(&mut out, 2);
        put_string(&mut out, "avro.schema");
        put_bytes(&mut out, schema.as_bytes());
        put_string(&mut out, "avro.codec");
        put_bytes(&mut out, codec.as_bytes());
        put_long(&mut out, 0);
        out.extend_from_slice(&SYNC);

        let payload = if codec == "deflate" {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&record).unwrap();
            encoder.finish().unwrap()
        } else {
            record
        };
        put_long(&mut out, 1);
        put_long(&mut out, payload.len() as i64);
        out.extend_from_slice(&payload);
        if bad_sync {
            out.extend_from_slice(b"fedcba9876543210");
        } else {
            out.extend_from_slice(&SYNC);
        }
        out
    }

    fn put_string(out: &mut Vec<u8>, value: &str) {
        put_bytes(out, value.as_bytes());
    }

    fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
        put_long(out, value.len() as i64);
        out.extend_from_slice(value);
    }

    fn put_long(out: &mut Vec<u8>, value: i64) {
        let mut encoded = ((value << 1) ^ (value >> 63)) as u64;
        loop {
            let mut byte = (encoded & 0x7f) as u8;
            encoded >>= 7;
            if encoded != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if encoded == 0 {
                break;
            }
        }
    }
}
