// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use ovstorage_plugin::{
    AccessDecision, AccessOps, AuthReason, BackendItemInfo, CancellationToken, ConnectionId,
    CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode,
    ListOptions, ListVersionsOptions, ObjectInfo, ReadOptions, ReadResult, RedirectResultBatch,
    RenameOptions, ResolvedTarget, StatOptions, UpdateMetadataOptions, WriteOptions,
    WriteRedirectBatch, WriteResult, WriteStep, shim,
};

/// Backend installed on routes whose connection is in `AwaitingAuth`. Every
/// SPI call returns `AuthRequired { connection_id, reason }`. The dispatcher's
/// `bring_up_or_fail` hook normally swaps this stub for a live backend before
/// any method is called; the impls below are defense-in-depth so a
/// missed dispatch path surfaces a meaningful error rather than the plugin
/// trait's default `Unsupported`.
pub(crate) struct AwaitingAuthStub {
    connection_id: ConnectionId,
    reason: AuthReason,
}

impl AwaitingAuthStub {
    pub(crate) fn new(connection_id: ConnectionId, reason: AuthReason) -> Arc<Self> {
        Arc::new(Self {
            connection_id,
            reason,
        })
    }

    fn auth_required<T>(&self) -> Result<T, Error> {
        Err(Error::new(
            ErrorCode::AuthRequired,
            format!(
                "connection '{}' is awaiting authentication ({:?})",
                self.connection_id.0, self.reason
            ),
        ))
    }
}

#[async_trait::async_trait]
impl shim::Backend for AwaitingAuthStub {
    async fn stat(
        &self,
        _target: ResolvedTarget,
        _opts: StatOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo, Error> {
        self.auth_required()
    }

    async fn read(
        &self,
        _target: ResolvedTarget,
        _opts: ReadOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<ReadResult, Error> {
        self.auth_required()
    }

    async fn write(
        &self,
        _target: ResolvedTarget,
        _bytes: Vec<u8>,
        _opts: WriteOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult, Error> {
        self.auth_required()
    }

    async fn write_stream(
        &self,
        _target: ResolvedTarget,
        _body: ovstorage_plugin::BodyStream,
        _opts: WriteOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteResult, Error> {
        self.auth_required()
    }

    async fn write_redirect(
        &self,
        _target: ResolvedTarget,
        _opts: WriteOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch, Error> {
        self.auth_required()
    }

    async fn continue_write(
        &self,
        _target: ResolvedTarget,
        _redirects: WriteRedirectBatch,
        _results: RedirectResultBatch,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep, Error> {
        self.auth_required()
    }

    async fn delete(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        self.auth_required()
    }

    async fn list(
        &self,
        _prefix: ResolvedTarget,
        _opts: ListOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>, Error> {
        self.auth_required()
    }

    async fn list_versions(
        &self,
        _target: ResolvedTarget,
        _opts: ListVersionsOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>, Error> {
        self.auth_required()
    }

    async fn get_latest_version(
        &self,
        _target: ResolvedTarget,
        _cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo, Error> {
        self.auth_required()
    }

    async fn create_directory(
        &self,
        _target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo, Error> {
        self.auth_required()
    }

    async fn delete_directory(
        &self,
        _target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        self.auth_required()
    }

    async fn copy(
        &self,
        _src: ResolvedTarget,
        _dest: ResolvedTarget,
        _opts: CopyOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<WriteStep, Error> {
        self.auth_required()
    }

    async fn rename(
        &self,
        _src: ResolvedTarget,
        _dest: ResolvedTarget,
        _opts: RenameOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<(), Error> {
        self.auth_required()
    }

    async fn update_metadata(
        &self,
        _target: ResolvedTarget,
        _opts: UpdateMetadataOptions,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo, Error> {
        self.auth_required()
    }

    async fn check_access(
        &self,
        _target: ResolvedTarget,
        _ops: AccessOps,
        _cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision, Error> {
        self.auth_required()
    }
}
