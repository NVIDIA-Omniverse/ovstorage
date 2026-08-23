// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ovstorage::ext::LayerExt;
use ovstorage::{
    Body, CopyOptions, CreateDirectoryOptions, Error, ErrorCode, RenameOptions,
    UpdateMetadataOptions, WriteOptions,
};
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error_wrap::library_result_to_tool_result;
use crate::server::OvstorageServer;
use crate::tools::read::{IfDestExistsInput, StatResult, info_to_result};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteParams {
    pub address: String,
    pub data_base64: String,
    #[serde(default)]
    pub if_dest: IfDestExistsInput,
    pub user_metadata: Option<BTreeMap<String, String>>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct WriteResult {
    pub info: StatResult,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateMetadataParams {
    pub address: String,
    pub set: Option<BTreeMap<String, String>>,
    pub remove: Option<Vec<String>>,
    pub if_match: Option<String>,
    #[serde(default)]
    pub allow_rewrite_emulation: bool,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateDirectoryParams {
    pub address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CopyParams {
    pub src: String,
    pub dest: String,
    pub if_source: Option<String>,
    #[serde(default)]
    pub if_dest: IfDestExistsInput,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveParams {
    pub src: String,
    pub dest: String,
    pub if_source: Option<String>,
    #[serde(default)]
    pub if_dest: IfDestExistsInput,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MoveResult {
    pub ok: bool,
}

#[tool_router(router = write_tool_router, vis = "pub(crate)")]
impl OvstorageServer {
    #[tool(
        description = "Write base64-encoded bytes to `address`. Pass `if_dest` to control \
                       what happens when the destination already exists (default: overwrite)."
    )]
    pub async fn ovstorage_write(
        &self,
        Parameters(params): Parameters<WriteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            let data = B64.decode(params.data_base64.as_bytes()).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("data_base64 decode failed: {err}"),
                )
            })?;
            let result = self
                .stack()
                .write(
                    addr,
                    Body::Bytes(data),
                    WriteOptions {
                        if_dest: params.if_dest.into(),
                        size_hint: None,
                        user_metadata: params.user_metadata.map(|map| map.into_iter().collect()),
                        message: params.message,
                    },
                    None,
                )
                .await?;
            Ok(WriteResult {
                info: info_to_result(result.info),
            })
        }
        .await;
        library_result_to_tool_result("ovstorage_write", outcome)
    }

    #[tool(description = "Update user metadata on an object.")]
    pub async fn ovstorage_update_metadata(
        &self,
        Parameters(params): Parameters<UpdateMetadataParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            let info = self
                .stack()
                .update_metadata(
                    addr,
                    UpdateMetadataOptions {
                        if_match: params.if_match,
                        allow_rewrite_emulation: params.allow_rewrite_emulation,
                        user_metadata_set: params.set.unwrap_or_default().into_iter().collect(),
                        user_metadata_remove: params.remove.unwrap_or_default(),
                        message: params.message,
                    },
                    None,
                )
                .await?;
            Ok(info_to_result(info))
        }
        .await;
        library_result_to_tool_result("ovstorage_update_metadata", outcome)
    }

    #[tool(description = "Create a directory or directory marker at `address`.")]
    pub async fn ovstorage_create_directory(
        &self,
        Parameters(params): Parameters<CreateDirectoryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            let info = self
                .stack()
                .create_directory(addr, CreateDirectoryOptions::default(), None)
                .await?;
            Ok(info_to_result(info))
        }
        .await;
        library_result_to_tool_result("ovstorage_create_directory", outcome)
    }

    #[tool(description = "Copy the object at `src` to `dest`.")]
    pub async fn ovstorage_copy(
        &self,
        Parameters(params): Parameters<CopyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let src = ovstorage::address::parse(&params.src)?;
            let dest = ovstorage::address::parse(&params.dest)?;
            let result = self
                .stack()
                .copy(
                    src,
                    dest,
                    CopyOptions {
                        if_source: params.if_source,
                        if_dest: params.if_dest.into(),
                        message: params.message,
                    },
                    None,
                )
                .await?;
            Ok(WriteResult {
                info: info_to_result(result.info),
            })
        }
        .await;
        library_result_to_tool_result("ovstorage_copy", outcome)
    }

    #[tool(description = "Move (rename) the object at `src` to `dest`.")]
    pub async fn ovstorage_move(
        &self,
        Parameters(params): Parameters<MoveParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let src = ovstorage::address::parse(&params.src)?;
            let dest = ovstorage::address::parse(&params.dest)?;
            self.stack()
                .rename(
                    src,
                    dest,
                    RenameOptions {
                        if_source: params.if_source,
                        if_dest: params.if_dest.into(),
                        message: params.message,
                    },
                    None,
                )
                .await?;
            Ok(MoveResult { ok: true })
        }
        .await;
        library_result_to_tool_result("ovstorage_move", outcome)
    }
}
