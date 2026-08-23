// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod bootstrap;
mod error_wrap;
mod lease_store;
mod server;
mod tools;

use anyhow::Context;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing_subscriber::EnvFilter;

use crate::server::OvstorageServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let stack = bootstrap::bootstrap_stack()
        .await
        .context("stack bootstrap")?;
    let service = OvstorageServer::new(stack)
        .serve(stdio())
        .await
        .context("serving MCP stdio")?;
    service.waiting().await.context("MCP server wait")?;
    Ok(())
}
