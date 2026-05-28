// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage_envelope::Envelope;
use rmcp::ErrorData;
use rmcp::model::{CallToolResult, Content};
use serde::Serialize;

pub fn library_result_to_tool_result<T: Serialize>(
    operation: &'static str,
    outcome: ovstorage::Result<T>,
) -> Result<CallToolResult, ErrorData> {
    let env = match outcome {
        Ok(value) => Envelope::ok(operation, value),
        Err(err) => Envelope::err(operation, (&err).into()),
    };
    let is_error = !env.ok;
    let json = serde_json::to_string(&env)
        .map_err(|err| ErrorData::internal_error(format!("envelope serialize: {err}"), None))?;
    let result = if is_error {
        CallToolResult::error(vec![Content::text(json)])
    } else {
        CallToolResult::success(vec![Content::text(json)])
    };
    Ok(result)
}
