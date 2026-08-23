// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use ovstorage::Stack;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool_handler};

use crate::lease_store::LeaseStore;

#[derive(Clone)]
pub struct OvstorageServer {
    stack: Arc<Stack>,
    lease_store: LeaseStore,
    tool_router: ToolRouter<Self>,
}

impl OvstorageServer {
    pub fn new(stack: Arc<Stack>) -> Self {
        Self {
            stack,
            lease_store: LeaseStore::new(),
            tool_router: crate::tools::tool_router(),
        }
    }

    pub fn stack(&self) -> &Arc<Stack> {
        &self.stack
    }

    pub fn lease_store(&self) -> &LeaseStore {
        &self.lease_store
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OvstorageServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::default())
            .with_server_info(
                Implementation::new("ovstorage-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("ovstorage MCP")
                    .with_description("MCP stdio server exposing ovstorage tools."),
            )
            .with_instructions(
                "ovstorage MCP server. Tool responses are wrapped in the v=0.1 agent envelope.",
            )
    }
}
