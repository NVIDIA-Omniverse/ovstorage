// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use ovstorage::ext::LayerExt;
use ovstorage::{DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, ListOptions, Stack, Url};
use rmcp::ErrorData;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error_wrap::library_result_to_tool_result;
use crate::server::OvstorageServer;

const DRY_RUN_ENTRY_CAP: usize = 100_000;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteParams {
    pub address: String,
    /// Etag precondition: refuse the delete unless the target matches
    /// the supplied opaque etag token. Mirrors `read.if_match` /
    /// `update_metadata.if_match`. Mismatch surfaces `PreconditionFailed`.
    pub if_match: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteResult {
    pub deleted: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteDirectoryParams {
    pub address: String,
    pub recursive: bool,
    pub dry_run: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteDirectoryDryRun {
    pub would_delete_paths: Vec<String>,
    pub would_delete_count: usize,
    pub dry_run: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DeleteDirectoryExecuted {
    pub deleted: bool,
    pub dry_run: bool,
}

struct DeletePlan {
    objects: Vec<Url>,
    directories: Vec<Url>,
}

#[tool_router(router = delete_tool_router, vis = "pub(crate)")]
impl OvstorageServer {
    #[tool(
        description = "Delete a single object at `address`. Pass `if_match` (etag) to refuse \
                       the delete unless the target matches the supplied opaque etag token."
    )]
    pub async fn ovstorage_delete(
        &self,
        Parameters(params): Parameters<DeleteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            self.stack()
                .delete(
                    addr,
                    DeleteOptions {
                        if_match: params.if_match,
                    },
                    None,
                )
                .await?;
            Ok(DeleteResult { deleted: true })
        }
        .await;
        library_result_to_tool_result("ovstorage_delete", outcome)
    }

    #[tool(description = "Delete a directory. `dry_run` is required; pass true before executing.")]
    pub async fn ovstorage_delete_directory(
        &self,
        Parameters(params): Parameters<DeleteDirectoryParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let outcome = async {
            let addr = ovstorage::address::parse(&params.address)?;
            if params.dry_run {
                let plan = collect_delete_plan(self.stack(), addr, params.recursive).await?;
                let would_delete_paths = plan.objects.iter().map(ToString::to_string).collect();
                return Ok(serde_json::to_value(DeleteDirectoryDryRun {
                    would_delete_count: plan.objects.len(),
                    would_delete_paths,
                    dry_run: true,
                })
                .expect("serializing dry-run result cannot fail"));
            }
            if params.recursive {
                let plan = collect_delete_plan(self.stack(), addr.clone(), true).await?;
                for object in plan.objects {
                    self.stack()
                        .delete(object, DeleteOptions::default(), None)
                        .await?;
                }
                let mut dirs = plan.directories;
                dirs.sort_by_key(|url| std::cmp::Reverse(url.as_str().len()));
                for dir in dirs {
                    self.stack()
                        .delete_directory(dir, DeleteDirectoryOptions, None)
                        .await?;
                }
            }
            self.stack()
                .delete_directory(addr, DeleteDirectoryOptions, None)
                .await?;
            Ok(serde_json::to_value(DeleteDirectoryExecuted {
                deleted: true,
                dry_run: false,
            })
            .expect("serializing delete result cannot fail"))
        }
        .await;
        library_result_to_tool_result("ovstorage_delete_directory", outcome)
    }
}

async fn collect_delete_plan(
    stack: &Stack,
    root: Url,
    recursive: bool,
) -> ovstorage::Result<DeletePlan> {
    if recursive {
        collect_recursive_delete_plan(stack, root).await
    } else {
        let mut objects = Vec::new();
        let mut directories = Vec::new();
        collect_one_directory(stack, root, false, &mut objects, &mut directories).await?;
        Ok(DeletePlan {
            objects,
            directories,
        })
    }
}

async fn collect_recursive_delete_plan(stack: &Stack, root: Url) -> ovstorage::Result<DeletePlan> {
    let mut objects = Vec::new();
    let mut directories = Vec::new();
    let mut pending = vec![root];
    while let Some(dir) = pending.pop() {
        let before = directories.len();
        collect_one_directory(stack, dir, true, &mut objects, &mut directories).await?;
        pending.extend(directories[before..].iter().cloned());
        if objects.len() + pending.len() + directories.len() > DRY_RUN_ENTRY_CAP {
            // `Internal` for the same reason the CLI's identical cap uses it:
            // a fixed local bound is reached on every attempt, so a retry
            // repeats the enumeration to reach it again.
            return Err(Error::new(
                ErrorCode::Internal,
                "delete_directory dry-run exceeded 100000 entries",
            ));
        }
    }
    Ok(DeletePlan {
        objects,
        directories,
    })
}

async fn collect_one_directory(
    stack: &Stack,
    dir: Url,
    include_subdirs: bool,
    objects: &mut Vec<Url>,
    directories: &mut Vec<Url>,
) -> ovstorage::Result<()> {
    let mut page_token = None;
    loop {
        let page = stack
            .list_page(
                dir.clone(),
                ListOptions {
                    recursive: false,
                    max_results: Some(1000),
                    page_token,
                    full_metadata: false,
                },
                None,
            )
            .await?;
        for item in page.items {
            if item.kind.is_file() {
                objects.push(item.address);
            } else if include_subdirs {
                directories.push(item.address);
            }
        }
        match page.next_page_token {
            Some(next) => page_token = Some(next),
            None => break,
        }
    }
    Ok(())
}
