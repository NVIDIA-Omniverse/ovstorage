// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use ovstorage::Library;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ProtocolVersion, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool_handler};

use crate::lease_store::LeaseStore;

#[derive(Clone)]
pub struct OvstorageServer {
    library: Arc<Library>,
    lease_store: LeaseStore,
    tool_router: ToolRouter<Self>,
}

impl OvstorageServer {
    pub fn new(library: Arc<Library>) -> Self {
        Self {
            library,
            lease_store: LeaseStore::new(),
            tool_router: crate::tools::tool_router(),
        }
    }

    pub fn library(&self) -> &Library {
        &self.library
    }

    pub fn lease_store(&self) -> &LeaseStore {
        &self.lease_store
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OvstorageServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "ovstorage-mcp".into(),
                title: Some("ovstorage MCP".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                description: Some("MCP stdio server exposing ovstorage tools.".into()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "ovstorage MCP server. Tool responses are wrapped in the v=0.1 agent envelope."
                    .into(),
            ),
        }
    }
}
