// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use async_trait::async_trait;
use nucleus_client::generated::Connection as Omni1;
use nucleus_client::types::{
    Copy2Response, CreateAssetResult, CreateDirectoryResult, Delete2Response,
    GetACLResolvedResponses, GetCheckpointsResponse, List2Response, MoveResponse, PathAtBranch,
    PathAtVersion, PathPermission, PathType, PathsToCopy, PathsToRename, ReadAssetVersionResult,
    Stat2Result, StatusType, UpdateAssetResult,
};
use nucleus_transport::{Subscription, Transport};
use ovstorage_plugin::{
    ConnectionId, EffectivePermissions, Error, ErrorCode, ErrorContext, Result,
};

/// Dyn-compatible adapter over the typed nucleus omni1 client.
///
/// Streaming methods (`read_asset_version`, `list2`, `subscribe_list`)
/// are flattened into owned values or a `WatchHandle` to keep the trait object-safe.
#[async_trait]
#[allow(clippy::too_many_arguments)]
pub(crate) trait NucleusOps: Send + Sync {
    async fn stat2(&self, path: PathAtVersion) -> Result<Stat2Result>;

    async fn read_asset_version(
        &self,
        path: PathAtVersion,
        etag: Option<String>,
    ) -> Result<ReadAssetVersionResult>;

    async fn create_asset(
        &self,
        path: PathAtBranch,
        content: Option<Vec<u8>>,
        content_id: Option<u64>,
        overwrite: Option<bool>,
        message: Option<String>,
    ) -> Result<CreateAssetResult>;

    async fn update_asset(
        &self,
        path: PathAtBranch,
        etag: Option<String>,
        delta: Option<String>,
        content: Option<Vec<u8>>,
        content_id: Option<u64>,
        ts: Option<HashMap<String, u64>>,
        message: Option<String>,
    ) -> Result<UpdateAssetResult>;

    async fn delete2(&self, paths: Vec<PathAtVersion>) -> Result<Delete2Response>;

    async fn list2(
        &self,
        path: String,
        branches: Option<Vec<String>>,
        path_types: Option<Vec<PathType>>,
        show_hidden: Option<bool>,
    ) -> Result<Vec<List2Response>>;

    async fn get_checkpoints(&self, path: PathAtBranch) -> Result<GetCheckpointsResponse>;

    async fn copy2(&self, paths: Vec<PathsToCopy>) -> Result<Copy2Response>;

    async fn rename2(&self, paths: Vec<PathsToRename>) -> Result<MoveResponse>;

    async fn create_directory(&self, path: PathAtBranch) -> Result<CreateDirectoryResult>;

    async fn get_acl_resolved(&self, paths: Vec<PathAtVersion>) -> Result<GetACLResolvedResponses>;

    async fn open_subscribe_list(&self, path: PathAtBranch) -> Result<WatchHandle>;
}

/// Live `subscribe_list` subscription drained on a dedicated OS thread so it
/// can be polled from sync host code without re-entering tokio's runtime.
pub(crate) struct WatchHandle {
    pub subscription: Subscription,
}

/// Production adapter that drives a real nucleus transport.
pub(crate) struct RuntimeOps<T: Transport + 'static> {
    transport: T,
}

impl<T: Transport + 'static> RuntimeOps<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl<T: Transport + 'static> NucleusOps for RuntimeOps<T> {
    async fn stat2(&self, path: PathAtVersion) -> Result<Stat2Result> {
        <T as Omni1>::stat2(&self.transport, path)
            .await
            .map_err(into_internal_err)
    }

    async fn read_asset_version(
        &self,
        path: PathAtVersion,
        etag: Option<String>,
    ) -> Result<ReadAssetVersionResult> {
        let mut sub = <T as Omni1>::read_asset_version(&self.transport, path, etag)
            .await
            .map_err(into_internal_err)?;
        let (mut resp, blob): (ReadAssetVersionResult, _) =
            sub.recv().await.map_err(into_internal_err)?;
        if let Some(data) = blob {
            resp.content = Some(data);
        }
        Ok(resp)
    }

    async fn create_asset(
        &self,
        path: PathAtBranch,
        content: Option<Vec<u8>>,
        content_id: Option<u64>,
        overwrite: Option<bool>,
        message: Option<String>,
    ) -> Result<CreateAssetResult> {
        <T as Omni1>::create_asset(
            &self.transport,
            path,
            content,
            content_id,
            overwrite,
            message,
        )
        .await
        .map_err(into_internal_err)
    }

    async fn update_asset(
        &self,
        path: PathAtBranch,
        etag: Option<String>,
        delta: Option<String>,
        content: Option<Vec<u8>>,
        content_id: Option<u64>,
        ts: Option<HashMap<String, u64>>,
        message: Option<String>,
    ) -> Result<UpdateAssetResult> {
        <T as Omni1>::update_asset(
            &self.transport,
            path,
            etag,
            delta,
            content,
            content_id,
            ts,
            message,
        )
        .await
        .map_err(into_internal_err)
    }

    async fn delete2(&self, paths: Vec<PathAtVersion>) -> Result<Delete2Response> {
        <T as Omni1>::delete2(&self.transport, paths)
            .await
            .map_err(into_internal_err)
    }

    async fn list2(
        &self,
        path: String,
        branches: Option<Vec<String>>,
        path_types: Option<Vec<PathType>>,
        show_hidden: Option<bool>,
    ) -> Result<Vec<List2Response>> {
        let mut sub = <T as Omni1>::list2(&self.transport, path, branches, path_types, show_hidden)
            .await
            .map_err(into_internal_err)?;
        let mut all = Vec::new();
        loop {
            match sub.recv::<List2Response>().await {
                Ok((resp, _)) => match resp.status {
                    // `Done` is the only terminal-success status. `OK` and
                    // `PartiallyCompleted` mean "more entries coming, keep
                    // reading" — paginated responses for large directories
                    // arrive as multiple `PartiallyCompleted` frames before
                    // a final `Done`. Anything else is an error from the
                    // server; falling through would hang waiting for a
                    // frame the server is never going to send.
                    StatusType::Done => {
                        all.push(resp);
                        return Ok(all);
                    }
                    StatusType::OK | StatusType::PartiallyCompleted => {
                        all.push(resp);
                    }
                    other => {
                        return Err(Error::new(
                            ErrorCode::Internal,
                            format!("nucleus list2: server returned status {other:?}"),
                        ));
                    }
                },
                Err(err) => {
                    return Err(Error::new(
                        ErrorCode::Transient,
                        format!("nucleus list2: stream closed before terminal status: {err:#}"),
                    ));
                }
            }
        }
    }

    async fn get_checkpoints(&self, path: PathAtBranch) -> Result<GetCheckpointsResponse> {
        <T as Omni1>::get_checkpoints(&self.transport, path)
            .await
            .map_err(into_internal_err)
    }

    async fn copy2(&self, paths: Vec<PathsToCopy>) -> Result<Copy2Response> {
        <T as Omni1>::copy2(&self.transport, paths)
            .await
            .map_err(into_internal_err)
    }

    async fn rename2(&self, paths: Vec<PathsToRename>) -> Result<MoveResponse> {
        <T as Omni1>::rename2(&self.transport, paths)
            .await
            .map_err(into_internal_err)
    }

    async fn create_directory(&self, path: PathAtBranch) -> Result<CreateDirectoryResult> {
        <T as Omni1>::create_directory(&self.transport, path)
            .await
            .map_err(into_internal_err)
    }

    async fn get_acl_resolved(&self, paths: Vec<PathAtVersion>) -> Result<GetACLResolvedResponses> {
        <T as Omni1>::get_acl_resolved(&self.transport, paths)
            .await
            .map_err(into_internal_err)
    }

    async fn open_subscribe_list(&self, path: PathAtBranch) -> Result<WatchHandle> {
        let subscription = <T as Omni1>::subscribe_list(&self.transport, path)
            .await
            .map_err(into_internal_err)?;
        Ok(WatchHandle { subscription })
    }
}

#[allow(dead_code)]
fn into_internal_err(err: impl std::fmt::Display) -> Error {
    // `{err:#}` preserves the chained source on `anyhow::Error`; for
    // typed errors (e.g. `nucleus_transport::TransportError`) the
    // alternate format falls through to plain `Display`.
    Error::new(ErrorCode::Internal, format!("{err:#}"))
}

/// Map an omni1 status to a typed `Result`; the `op` label flows into the error message.
pub(crate) fn status_to_result(status: StatusType, op: &str) -> Result<()> {
    match status {
        StatusType::OK | StatusType::Done | StatusType::Latest | StatusType::Idle => Ok(()),
        StatusType::PartiallyCompleted => Err(Error::new(
            ErrorCode::Transient,
            format!("nucleus {op}: server returned partial completion"),
        )),
        StatusType::Denied => Err(Error::new(
            ErrorCode::PermissionDenied,
            format!("nucleus {op}: access denied"),
        )),
        StatusType::Unauthenticated => Err(Error::new(
            ErrorCode::AuthRequired,
            format!("nucleus {op}: not authenticated"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("status_unauthenticated".into()),
            expired_at: None,
        })),
        // `TokenExpired` is recoverable: `with_refresh` drives a single-flight refresh and re-issues once.
        StatusType::TokenExpired => Err(Error::new(
            ErrorCode::AuthExpired,
            format!("nucleus {op}: token expired"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("status_token_expired".into()),
            expired_at: None,
        })),
        StatusType::NotExist => Err(Error::new(
            ErrorCode::NotFound,
            format!("nucleus {op}: path does not exist"),
        )),
        StatusType::AlreadyExists => Err(Error::new(
            ErrorCode::AlreadyExists,
            format!("nucleus {op}: target already exists"),
        )),
        StatusType::ResourceBusy => Err(Error::new(
            ErrorCode::Locked,
            format!("nucleus {op}: resource busy"),
        )),
        StatusType::InvalidETag | StatusType::InvalidTransactionId => Err(Error::new(
            ErrorCode::PreconditionFailed,
            format!("nucleus {op}: precondition failed"),
        )),
        StatusType::FolderNotEmpty => Err(Error::new(
            ErrorCode::DirectoryNotEmpty,
            format!("nucleus {op}: folder not empty"),
        )),
        StatusType::ContentLengthMismatch | StatusType::ContentBufferOverflow => Err(Error::new(
            ErrorCode::ContentMismatch,
            format!("nucleus {op}: content length mismatch"),
        )),
        StatusType::NotImplemented => Err(Error::new(
            ErrorCode::Unsupported,
            format!("nucleus {op}: not implemented by the server"),
        )),
        StatusType::Timeout => Err(Error::new(
            ErrorCode::DeadlineExceeded,
            format!("nucleus {op}: timed out"),
        )),
        StatusType::SlowDown | StatusType::QuotaReached => Err(Error::new(
            ErrorCode::Transient,
            format!("nucleus {op}: server requested slowdown"),
        )),
        StatusType::ConnectionLost | StatusType::AccessLost => Err(Error::new(
            ErrorCode::Transient,
            format!("nucleus {op}: connection lost"),
        )),
        // INVALID_URI's IDL name suggests "malformed path", but the server
        // also returns it for stat/read/delete of paths that don't exist —
        // observed empirically against content.ov.nvidia.com. Map to NotFound
        // so callers can distinguish "missing" from genuine client-bug input.
        StatusType::InvalidPath => Err(Error::new(
            ErrorCode::NotFound,
            format!("nucleus {op}: path does not exist"),
        )),
        StatusType::InvalidCommand
        | StatusType::InvalidContentId
        | StatusType::InvalidParameters
        | StatusType::IncompatibleVersion => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("nucleus {op}: invalid request"),
        )),
        StatusType::NotAsset | StatusType::NotObject => Err(Error::new(
            ErrorCode::IncompatibleType,
            format!("nucleus {op}: path is not the requested type"),
        )),
        StatusType::AlreadyAuthenticated => Ok(()),
        other => Err(Error::new(
            ErrorCode::Internal,
            format!("nucleus {op}: unexpected status {other:?}"),
        )),
    }
}

/// Translate an omni1 ACL permission set into `EffectivePermissions`.
/// Nucleus has no separate metadata permission, so metadata changes ride on the `write` bit.
pub(crate) fn acl_to_effective_permissions(acl: &[PathPermission]) -> EffectivePermissions {
    let mut perms = EffectivePermissions::empty();
    for entry in acl {
        match entry {
            PathPermission::Read => perms |= EffectivePermissions::READ,
            PathPermission::Write => {
                perms |= EffectivePermissions::READ
                    | EffectivePermissions::WRITE
                    | EffectivePermissions::DELETE
                    | EffectivePermissions::UPDATE_METADATA;
            }
            PathPermission::Admin => perms |= EffectivePermissions::all(),
        }
    }
    perms
}
