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
use nucleus_transport::{Subscription, Transport, TransportError};
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
            .map_err(classify_transport_err)
    }

    async fn read_asset_version(
        &self,
        path: PathAtVersion,
        etag: Option<String>,
    ) -> Result<ReadAssetVersionResult> {
        let mut sub = <T as Omni1>::read_asset_version(&self.transport, path, etag)
            .await
            .map_err(classify_transport_err)?;
        let (mut resp, blob): (ReadAssetVersionResult, _) =
            sub.recv().await.map_err(classify_transport_err)?;
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
        .map_err(classify_mutation_transport_err)
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
        .map_err(classify_mutation_transport_err)
    }

    async fn delete2(&self, paths: Vec<PathAtVersion>) -> Result<Delete2Response> {
        <T as Omni1>::delete2(&self.transport, paths)
            .await
            .map_err(classify_mutation_transport_err)
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
            .map_err(classify_transport_err)?;
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
            .map_err(classify_transport_err)
    }

    async fn copy2(&self, paths: Vec<PathsToCopy>) -> Result<Copy2Response> {
        <T as Omni1>::copy2(&self.transport, paths)
            .await
            .map_err(classify_mutation_transport_err)
    }

    async fn rename2(&self, paths: Vec<PathsToRename>) -> Result<MoveResponse> {
        <T as Omni1>::rename2(&self.transport, paths)
            .await
            .map_err(classify_mutation_transport_err)
    }

    async fn create_directory(&self, path: PathAtBranch) -> Result<CreateDirectoryResult> {
        <T as Omni1>::create_directory(&self.transport, path)
            .await
            .map_err(classify_mutation_transport_err)
    }

    async fn get_acl_resolved(&self, paths: Vec<PathAtVersion>) -> Result<GetACLResolvedResponses> {
        <T as Omni1>::get_acl_resolved(&self.transport, paths)
            .await
            .map_err(classify_transport_err)
    }

    async fn open_subscribe_list(&self, path: PathAtBranch) -> Result<WatchHandle> {
        let subscription = <T as Omni1>::subscribe_list(&self.transport, path)
            .await
            .map_err(classify_transport_err)?;
        Ok(WatchHandle { subscription })
    }
}

/// Classify a nucleus SPI failure into a typed [`ErrorCode`] so the host's
/// retry logic fires on transient failures instead of collapsing every nucleus
/// error to opaque `Internal`.
///
/// Transport-level failures carry a downcastable
/// [`nucleus_transport::TransportError`] — whether they surface as an
/// `anyhow::Error` from the generated omni1 methods (which propagate it through
/// `?`, keeping the concrete type downcastable) or as a bare `TransportError`
/// from `Subscription::recv`. Those map to retry-classifiable codes:
/// - `Timeout` → `DeadlineExceeded` (the request outlived its deadline);
/// - `ConnectionFailed` (connect refused / socket never came up) →
///   `BrokerUnavailable`, so the host treats the endpoint as down-but-retryable;
/// - `ConnectionClosed` / `SubscriptionClosed` / `WebSocketError` (mid-flight
///   drops) → `Transient`.
///
/// Everything else stays `Internal`: a `SerializationError` is our own bug, and
/// an error with no transport shape is genuinely opaque. `{err:#}` preserves the
/// chained source for the message.
fn classify_transport_err(err: impl Into<anyhow::Error>) -> Error {
    let err = err.into();
    let code = match err.downcast_ref::<TransportError>() {
        Some(TransportError::Timeout) => ErrorCode::DeadlineExceeded,
        Some(TransportError::ConnectionFailed(_)) => ErrorCode::BrokerUnavailable,
        Some(TransportError::ConnectionClosed)
        | Some(TransportError::SubscriptionClosed)
        | Some(TransportError::WebSocketError(_)) => ErrorCode::Transient,
        Some(TransportError::SerializationError(_)) | None => ErrorCode::Internal,
    };
    Error::new(code, format!("{err:#}"))
}

/// Mutation-path twin of [`classify_transport_err`].
///
/// A non-idempotent mutation may not be blind-retried on a transport failure,
/// because NO `TransportError` variant distinguishes "the request never left
/// the client" from "the server executed it and the response was lost":
/// `ConnectionClosed` and `Timeout` are post-send by construction, and
/// `ConnectionFailed` is delivered to already-in-flight requests too, via
/// `notify_pending_error`. Classifying any of them as retryable lets
/// `RetryWrapper` replay a mutation nucleus already committed — a
/// `MatchEtag` write then fails with `PreconditionFailed`, a create-only write
/// with `AlreadyExists`, and a rename with `NotFound`, each reporting failure
/// for an operation that actually succeeded.
///
/// So every post-send-reachable variant becomes [`ErrorCode::CommitAmbiguous`]
/// — "may or may not have been applied", in the non-retryable `Internal`
/// bucket — which is exactly the outcome the caller faces. Reads keep the
/// retryable classification via [`classify_transport_err`]; only
/// `SerializationError` stays `Internal`, since it fails before anything is
/// sent.
fn classify_mutation_transport_err(err: impl Into<anyhow::Error>) -> Error {
    let err = err.into();
    let code = match err.downcast_ref::<TransportError>() {
        Some(TransportError::Timeout)
        | Some(TransportError::ConnectionFailed(_))
        | Some(TransportError::ConnectionClosed)
        | Some(TransportError::SubscriptionClosed)
        | Some(TransportError::WebSocketError(_)) => ErrorCode::CommitAmbiguous,
        Some(TransportError::SerializationError(_)) | None => ErrorCode::Internal,
    };
    Error::new(code, format!("{err:#}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_transport_error_surfaces_retryable() {
        // A timeout-shaped transport failure — the case the host's retry
        // classifier must recognize — arrives as an `anyhow::Error` from the
        // generated omni1 methods; downcast must still see `TransportError`.
        let err: anyhow::Error = TransportError::Timeout.into();
        let classified = classify_transport_err(err);
        assert_eq!(classified.code(), ErrorCode::DeadlineExceeded);
        assert!(
            classified.code().retryable(),
            "nucleus timeout must be retryable at the host"
        );
    }

    #[test]
    fn connect_refused_surfaces_retryable_broker_unavailable() {
        let err = TransportError::ConnectionFailed("connection refused".into());
        let classified = classify_transport_err(err);
        assert_eq!(classified.code(), ErrorCode::BrokerUnavailable);
        assert!(classified.code().retryable());
    }

    #[test]
    fn dropped_connection_surfaces_retryable_transient() {
        for err in [
            TransportError::ConnectionClosed,
            TransportError::SubscriptionClosed,
        ] {
            let classified = classify_transport_err(err);
            assert_eq!(classified.code(), ErrorCode::Transient);
            assert!(classified.code().retryable());
        }
    }

    #[test]
    fn serialization_error_stays_internal() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{bad").unwrap_err();
        let classified = classify_transport_err(TransportError::from(json_err));
        assert_eq!(classified.code(), ErrorCode::Internal);
        assert!(!classified.code().retryable());
    }

    #[test]
    fn opaque_non_transport_error_stays_internal() {
        let classified = classify_transport_err(anyhow::anyhow!("opaque nucleus failure"));
        assert_eq!(classified.code(), ErrorCode::Internal);
        assert!(!classified.code().retryable());
    }

    /// The mutation classifier is the whole point of the split: a
    /// non-idempotent nucleus op must never come back retryable, because no
    /// transport variant can tell "never sent" from "response lost". Every one
    /// of them collapses to the non-retryable `CommitAmbiguous`.
    #[test]
    fn mutation_transport_failures_are_never_retryable() {
        // `TransportError` is not `Clone`, so each case builds its own pair.
        let cases = || {
            [
                TransportError::Timeout,
                TransportError::ConnectionFailed("connection refused".into()),
                TransportError::ConnectionClosed,
                TransportError::SubscriptionClosed,
            ]
        };
        for (read_err, mutation_err) in cases().into_iter().zip(cases()) {
            let read_side = classify_transport_err(read_err);
            let classified = classify_mutation_transport_err(mutation_err);
            assert_eq!(
                classified.code(),
                ErrorCode::CommitAmbiguous,
                "a mutation must report an ambiguous commit, not {:?}",
                read_side.code(),
            );
            assert!(
                !classified.code().retryable(),
                "retrying this would replay a mutation the server may have committed",
            );
            // The read-shaped classification is deliberately unchanged.
            assert!(read_side.code().retryable());
        }
    }

    /// A serialization failure happens before anything is sent, so it stays
    /// `Internal` rather than claiming the commit is ambiguous.
    #[test]
    fn mutation_serialization_error_is_not_commit_ambiguous() {
        let json_err = serde_json::from_str::<serde_json::Value>("{{bad").unwrap_err();
        let classified = classify_mutation_transport_err(TransportError::from(json_err));
        assert_eq!(classified.code(), ErrorCode::Internal);
        assert!(!classified.code().retryable());
    }
}
