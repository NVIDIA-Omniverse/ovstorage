// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ovstorage::{
    ByteRange, Error, ErrorCode, ListOptions, ObjectInfo, ReadOptions, StatOptions, Storage,
};
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error_wrap::library_result_to_tool_result;
use crate::server::OvstorageServer;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilitiesParams {
    pub prefix: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CapabilitiesResult {
    pub supports_if_match_write: bool,
    pub supports_no_overwrite_write: bool,
    pub supports_overwrite: bool,
    pub supports_native_metadata_patch: bool,
    pub supports_metadata_rewrite_emulation: bool,
    pub writes_are_atomic: bool,
    pub supports_server_side_copy: bool,
    pub supports_server_side_rename: bool,
    pub supports_atomic_rename: bool,
    pub has_real_directories: bool,
    pub supports_list: bool,
    pub wants_list_backed_stat: bool,
    pub supports_recursive_list: bool,
    pub populates_subdirectory_metadata: bool,
    pub supports_version_listing: bool,
    pub populates_effective_permissions_on_stat: bool,
    pub supports_access_check: bool,
    pub supports_watch_directory: bool,
    pub watch_directory_resumable: bool,
    pub watch_directory_max_lag_ms: Option<u128>,
    pub redirect_size_threshold: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatParams {
    pub address: String,
    #[serde(default)]
    pub full_metadata: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct StatResult {
    pub address: String,
    /// Canonical snake-case [`ovstorage::ObjectKind`]: `file`,
    /// `directory`, `directory_marker`, or `directory_inferred`.
    /// Matches the REST `kind` field on `ObjectInfoResponse` exactly.
    pub kind: String,
    pub size: Option<u64>,
    pub mtime_unix_nanos: Option<i128>,
    pub etag: Option<String>,
    pub version: Option<String>,
    pub user_metadata: serde_json::Map<String, serde_json::Value>,
    pub system_metadata: serde_json::Map<String, serde_json::Value>,
    pub modified_by: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    pub prefix: String,
    #[serde(default)]
    pub recursive: bool,
    pub max_results: Option<u32>,
    pub page_token: Option<String>,
    #[serde(default)]
    pub full_metadata: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListEntry {
    pub kind: String,
    pub address: String,
    pub size: Option<u64>,
    pub mtime_unix_nanos: Option<i128>,
    pub etag: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListResult {
    pub items: Vec<ListEntry>,
    pub next_page_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadParams {
    pub address: String,
    pub max_bytes: u64,
    pub if_match: Option<String>,
    pub range_start: Option<u64>,
    pub range_end: Option<u64>,
}

/// JSON tagged-union for destination-existence preconditions on
/// `write` / `copy` / `move`. Mirrors the SPI enum
/// [`ovstorage::IfDestExists`] verbatim:
///
/// - `{"kind": "overwrite"}` — clobber unconditionally (default if omitted).
/// - `{"kind": "fail"}` — refuse to overwrite (`AlreadyExists` if present).
/// - `{"kind": "match_etag", "etag": "<s>"}` — overwrite only when the
///   destination's current etag matches `<s>` (`ObjectModified` otherwise).
#[derive(Clone, Debug, Default, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IfDestExistsInput {
    #[default]
    Overwrite,
    Fail,
    MatchEtag {
        etag: String,
    },
}

impl From<IfDestExistsInput> for ovstorage::IfDestExists {
    fn from(value: IfDestExistsInput) -> Self {
        match value {
            IfDestExistsInput::Overwrite => Self::Overwrite,
            IfDestExistsInput::Fail => Self::Fail,
            IfDestExistsInput::MatchEtag { etag } => Self::MatchEtag(etag),
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReadResult {
    pub data_base64: String,
    pub info: StatResult,
}

#[tool_router(router = read_tool_router, vis = "pub(crate)")]
impl OvstorageServer {
    #[tool(description = "Return capability bits for the backend serving `prefix`.")]
    pub async fn ovstorage_capabilities(
        &self,
        Parameters(params): Parameters<CapabilitiesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = (|| -> ovstorage::Result<CapabilitiesResult> {
            let prefix = ovstorage::address::parse(&params.prefix)?;
            let caps = self.library().capabilities_for(&prefix)?;
            Ok(CapabilitiesResult {
                supports_if_match_write: caps.supports_if_match_write,
                supports_no_overwrite_write: caps.supports_no_overwrite_write,
                supports_overwrite: true,
                supports_native_metadata_patch: caps.supports_native_metadata_patch,
                supports_metadata_rewrite_emulation: caps.supports_metadata_rewrite_emulation,
                writes_are_atomic: caps.writes_are_atomic,
                supports_server_side_copy: caps.supports_server_side_copy,
                supports_server_side_rename: caps.supports_server_side_rename,
                supports_atomic_rename: caps.supports_atomic_rename,
                has_real_directories: caps.has_real_directories,
                supports_list: caps.supports_list,
                wants_list_backed_stat: caps.wants_list_backed_stat,
                supports_recursive_list: caps.supports_recursive_list,
                populates_subdirectory_metadata: caps.populates_subdirectory_metadata,
                supports_version_listing: caps.supports_version_listing,
                populates_effective_permissions_on_stat: caps
                    .populates_effective_permissions_on_stat,
                supports_access_check: caps.supports_access_check,
                supports_watch_directory: caps.supports_watch_directory,
                watch_directory_resumable: caps.watch_directory_resumable,
                watch_directory_max_lag_ms: caps.watch_directory_max_lag.map(|d| d.as_millis()),
                redirect_size_threshold: caps.redirect_size_threshold,
            })
        })();
        library_result_to_tool_result("ovstorage_capabilities", outcome)
    }

    #[tool(description = "Return object metadata for `address`.")]
    pub async fn ovstorage_stat(
        &self,
        Parameters(params): Parameters<StatParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            let info = self
                .library()
                .stat(
                    addr,
                    StatOptions {
                        full_metadata: params.full_metadata,
                    },
                    None,
                )
                .await?;
            Ok(info_to_result(info))
        }
        .await;
        library_result_to_tool_result("ovstorage_stat", outcome)
    }

    #[tool(description = "List one page of entries under `prefix`.")]
    pub async fn ovstorage_list(
        &self,
        Parameters(params): Parameters<ListParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let prefix = ovstorage::address::parse(&params.prefix)?;
            let page = self
                .library()
                .list_page(
                    prefix,
                    ListOptions {
                        recursive: params.recursive,
                        max_results: params.max_results,
                        page_token: params.page_token,
                        full_metadata: params.full_metadata,
                    },
                    None,
                )
                .await?;
            Ok(ListResult {
                items: page.items.into_iter().map(info_to_list_entry).collect(),
                next_page_token: page.next_page_token,
            })
        }
        .await;
        library_result_to_tool_result("ovstorage_list", outcome)
    }

    #[tool(description = "Read bytes from `address`, capped by required `max_bytes`.")]
    pub async fn ovstorage_read(
        &self,
        Parameters(params): Parameters<ReadParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            let opts = ReadOptions {
                if_match: params.if_match,
                range: read_range(params.range_start, params.range_end)?,
                max_bytes: Some(params.max_bytes),
            };
            let (bytes, info) = self.library().read_bytes(addr, opts, None).await?;
            Ok(ReadResult {
                data_base64: B64.encode(bytes),
                info: info_to_result(info),
            })
        }
        .await;
        library_result_to_tool_result("ovstorage_read", outcome)
    }
}

pub fn info_to_result(info: ObjectInfo) -> StatResult {
    StatResult {
        address: info.address.to_string(),
        kind: info.kind.as_str().to_string(),
        size: info.size,
        mtime_unix_nanos: info.mtime.and_then(system_time_to_unix_nanos),
        etag: info.etag,
        version: info.version,
        user_metadata: map_to_json(info.user_metadata),
        system_metadata: map_to_json(info.system_metadata),
        modified_by: info.modified_by,
    }
}

fn info_to_list_entry(info: ObjectInfo) -> ListEntry {
    let info = info_to_result(info);
    ListEntry {
        kind: info.kind,
        address: info.address,
        size: info.size,
        mtime_unix_nanos: info.mtime_unix_nanos,
        etag: info.etag,
        version: info.version,
    }
}

fn read_range(start: Option<u64>, end: Option<u64>) -> ovstorage::Result<Option<ByteRange>> {
    match (start, end) {
        (None, None) => Ok(None),
        (Some(start), end_inclusive) => {
            if let Some(end) = end_inclusive
                && end < start
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "range_end must be greater than or equal to range_start",
                ));
            }
            Ok(Some(ByteRange {
                start,
                end_inclusive,
            }))
        }
        (None, Some(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "range_end requires range_start",
        )),
    }
}

fn map_to_json(
    map: Option<std::collections::HashMap<String, String>>,
) -> serde_json::Map<String, serde_json::Value> {
    map.unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect()
}

fn system_time_to_unix_nanos(value: std::time::SystemTime) -> Option<i128> {
    value
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
}
