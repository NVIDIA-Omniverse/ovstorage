// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use crate::error_wrap::library_result_to_tool_result;
use crate::server::OvstorageServer;

#[tool_router(router = diagnostics_tool_router, vis = "pub(crate)")]
impl OvstorageServer {
    #[tool(description = "Aggregate library diagnostic state into an envelope-wrapped report.")]
    pub async fn ovstorage_doctor(&self) -> Result<CallToolResult, ErrorData> {
        let outcome = ovstorage_cli::commands::doctor::gather(self.library());
        library_result_to_tool_result("ovstorage_doctor", outcome)
    }
}
