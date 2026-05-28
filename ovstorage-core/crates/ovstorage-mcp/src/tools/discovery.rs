// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use rmcp::ErrorData;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::Serialize;

use crate::error_wrap::library_result_to_tool_result;
use crate::server::OvstorageServer;

#[derive(Debug, Serialize, JsonSchema)]
pub struct ConnectionsList {
    pub connections: Vec<ConnectionEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AddressRootsList {
    pub address_roots: Vec<AddressRootEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ConnectionEntry {
    pub id: String,
    pub backend_kind: String,
    pub display_name: String,
    pub addresses: Vec<String>,
    pub auth_state_kind: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AddressRootEntry {
    pub address: String,
    pub backend_kind: String,
    pub display_name: Option<String>,
    pub visibility: String,
}

#[tool_router(router = discovery_tool_router, vis = "pub(crate)")]
impl OvstorageServer {
    #[tool(description = "List configured connections.")]
    pub async fn ovstorage_connections_list(&self) -> Result<CallToolResult, ErrorData> {
        let outcome = ovstorage_cli::commands::doctor::gather_connections(self.library()).map(
            |connections| ConnectionsList {
                connections: connections
                    .into_iter()
                    .map(|c| ConnectionEntry {
                        id: c.id,
                        backend_kind: c.backend_kind,
                        display_name: c.display_name,
                        addresses: c.addresses,
                        auth_state_kind: c.auth_state_kind,
                    })
                    .collect(),
            },
        );
        library_result_to_tool_result("ovstorage_connections_list", outcome)
    }

    #[tool(description = "List configured address roots.")]
    pub async fn ovstorage_address_roots_list(&self) -> Result<CallToolResult, ErrorData> {
        let outcome = ovstorage_cli::commands::doctor::gather_address_roots(self.library()).map(
            |address_roots| AddressRootsList {
                address_roots: address_roots
                    .into_iter()
                    .map(|r| AddressRootEntry {
                        address: r.address,
                        backend_kind: r.backend_kind,
                        display_name: r.display_name,
                        visibility: r.visibility,
                    })
                    .collect(),
            },
        );
        library_result_to_tool_result("ovstorage_address_roots_list", outcome)
    }
}
