// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod delete;
pub mod diagnostics;
pub mod discovery;
pub mod materialize;
pub mod read;
pub mod write;

use rmcp::handler::server::router::tool::ToolRouter;

use crate::server::OvstorageServer;

pub fn tool_router() -> ToolRouter<OvstorageServer> {
    OvstorageServer::diagnostics_tool_router()
        + OvstorageServer::read_tool_router()
        + OvstorageServer::write_tool_router()
        + OvstorageServer::delete_tool_router()
        + OvstorageServer::discovery_tool_router()
        + OvstorageServer::materialize_tool_router()
}
