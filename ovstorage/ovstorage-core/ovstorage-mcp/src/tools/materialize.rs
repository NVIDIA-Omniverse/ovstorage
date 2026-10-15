// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ovstorage::ext::LayerExt;
use ovstorage::{Error, ErrorCode, ReadOptions, address};
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error_wrap::library_result_to_tool_result;
use crate::lease_store::SessionId;
use crate::server::OvstorageServer;
use crate::tools::read::{StatResult, info_to_result};

const DEFAULT_TTL: Duration = Duration::from_secs(1800);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializeParams {
    pub address: String,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MaterializeResult {
    pub path: String,
    pub info: StatResult,
    pub expires_at_unix_seconds: i64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseParams {
    pub path: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ReleaseResult {
    pub released: bool,
    pub was_active: bool,
}

#[tool_router(router = materialize_tool_router, vis = "pub(crate)")]
impl OvstorageServer {
    #[tool(
        description = "Materialize `address` as a local file pinned in the cache. \
                       Returns path, info, and expires_at_unix_seconds. \
                       Call ovstorage_release when done. Default TTL is 1800 seconds."
    )]
    pub async fn ovstorage_materialize(
        &self,
        Parameters(params): Parameters<MaterializeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = address::parse(&params.address)?;
            let ttl = ttl_from_params(params.ttl_seconds)?;
            let delegate = self
                .stack()
                .materialize(addr, ReadOptions::default(), None)
                .await?;
            let path = delegate.path.clone();
            let info = info_to_result(delegate.info.clone());
            self.lease_store()
                .insert(SessionId::stdio(), path.clone(), delegate, ttl)
                .await;
            Ok(MaterializeResult {
                path: path.to_string_lossy().into_owned(),
                info,
                expires_at_unix_seconds: expires_at_unix_seconds(ttl)?,
            })
        }
        .await;
        library_result_to_tool_result("ovstorage_materialize", outcome)
    }

    #[tool(
        description = "Release a lease from an earlier materialize call. Idempotent: \
                       was_active is false when the lease is absent or expired."
    )]
    pub async fn ovstorage_release(
        &self,
        Parameters(params): Parameters<ReleaseParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let was_active = self
            .lease_store()
            .remove(SessionId::stdio(), PathBuf::from(params.path))
            .await;
        let outcome: ovstorage::Result<ReleaseResult> = Ok(ReleaseResult {
            released: true,
            was_active,
        });
        library_result_to_tool_result("ovstorage_release", outcome)
    }
}

fn ttl_from_params(ttl_seconds: Option<u64>) -> ovstorage::Result<Duration> {
    match ttl_seconds {
        None => Ok(DEFAULT_TTL),
        Some(0) => Err(Error::new(
            ErrorCode::InvalidArgument,
            "ttl_seconds must be a positive integer",
        )),
        Some(seconds) => Ok(Duration::from_secs(seconds)),
    }
}

fn expires_at_unix_seconds(ttl: Duration) -> ovstorage::Result<i64> {
    let expires_at = SystemTime::now().checked_add(ttl).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "ttl_seconds exceeds supported timestamp range",
        )
    })?;
    let duration = expires_at.duration_since(UNIX_EPOCH).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("system time before unix epoch: {err}"),
        )
    })?;
    i64::try_from(duration.as_secs()).map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "ttl_seconds exceeds supported timestamp range",
        )
    })
}
