// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Transport trait the broker daemon implements and the broker plugin consumes; lives
//! here so the broker can implement it without rlib-linking the plugin crate.

use ovstorage_plugin::{
    AccessDecision, AccessOps, AddressRoot, Body, ChangeEvent, CopyOptions, CreateDirectoryOptions,
    DeleteDirectoryOptions, DeleteOptions, InteractiveAuthCapability, ListOptions, ListPage,
    ListVersionsOptions, ObjectInfo, ReadOptions, ReadResult, RedirectResultBatch, RenameOptions,
    Result, StatOptions, UpdateMetadataOptions, Url, WatchDirectoryOptions, WriteOptions,
    WriteRedirectBatch, WriteResult, WriteStep,
};

/// Iterator returned by `watch_directory`; each item is a parsed `ChangeEvent`.
pub type BrokerClientWatchDirectoryStream = Box<dyn Iterator<Item = Result<ChangeEvent>> + Send>;

/// Server-pushed stream returned by `watch_address_roots`: `Snapshot` on subscribe, then
/// `Added` / `Removed` deltas.
pub type AddressRootsChangeStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<AddressRootsChange>> + Send>>;

/// First emission per subscription is always `Snapshot`; subsequent emissions are deltas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressRootsChange {
    Snapshot(Vec<AddressRoot>),
    Added(Vec<AddressRoot>),
    /// Echoes the full `AddressRoot` (not just the address) so subscribers can log display
    /// names without a separate lookup.
    Removed(Vec<AddressRoot>),
}

/// Transport surface the broker daemon exposes for the broker plugin (production: gRPC
/// `Broker`; tests: per-fixture stubs). All `Storage`-mirroring methods are `async` so the
/// plugin's tonic calls `.await` directly — making them sync would re-enter the host runtime
/// via `block_on` and panic.
#[async_trait::async_trait]
pub trait BrokerClientTransport: Send + Sync {
    async fn list_address_roots(&self) -> Result<Vec<AddressRoot>>;
    /// Server-streaming follow-up to `list_address_roots`. Default impl returns `Unsupported`
    /// so partial transports keep compiling.
    async fn watch_address_roots(&self) -> Result<AddressRootsChangeStream> {
        Err(ovstorage_plugin::Error::new(
            ovstorage_plugin::ErrorCode::Unsupported,
            "broker transport does not implement watch_address_roots",
        ))
    }
    async fn stat(&self, address: Url, options: StatOptions) -> Result<ObjectInfo>;
    async fn read(&self, address: Url, options: ReadOptions) -> Result<ReadResult>;
    async fn write(&self, address: Url, body: Body, options: WriteOptions) -> Result<WriteStep>;
    /// Body-less redirect emission; gateway follows the batch before calling `continue_write`.
    /// `Unsupported` propagates from the upstream plugin and signals the dispatcher to fall
    /// back to `write` / `write_stream`.
    async fn write_redirect(
        &self,
        address: Url,
        options: WriteOptions,
    ) -> Result<WriteRedirectBatch>;
    /// Returns `Done` for single-stage finalize, or `Redirects` for multi-stage multipart
    /// flows (e.g. S3 part upload batch followed by `CompleteMultipartUpload`).
    async fn continue_write(
        &self,
        address: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
    ) -> Result<WriteStep>;
    async fn delete(&self, address: Url, options: DeleteOptions) -> Result<()>;
    async fn list(&self, prefix: Url, options: ListOptions) -> Result<ListPage>;
    async fn list_versions(
        &self,
        address: Url,
        options: ListVersionsOptions,
    ) -> Result<Vec<ObjectInfo>>;
    async fn get_latest_version(&self, address: Url) -> Result<ObjectInfo>;
    async fn watch_directory(
        &self,
        prefix: Url,
        opts: WatchDirectoryOptions,
    ) -> Result<BrokerClientWatchDirectoryStream>;
    async fn create_directory(
        &self,
        address: Url,
        options: CreateDirectoryOptions,
    ) -> Result<ObjectInfo>;
    async fn delete_directory(&self, address: Url, options: DeleteDirectoryOptions) -> Result<()>;
    async fn copy(
        &self,
        source: Url,
        destination: Url,
        options: CopyOptions,
    ) -> Result<WriteResult>;
    async fn rename(&self, source: Url, destination: Url, options: RenameOptions) -> Result<()>;
    async fn update_metadata(
        &self,
        address: Url,
        options: UpdateMetadataOptions,
    ) -> Result<ObjectInfo>;
    async fn check_access(&self, address: Url, operations: AccessOps) -> Result<AccessDecision>;

    /// Open the streaming `Auth` RPC for `address`, carrying the capability
    /// selected for this authentication request. The broker stack resolves the
    /// caller's principal, drives an allowed upstream OAuth flow, and persists
    /// the resulting credential before emitting success. The client pairs
    /// `Succeeded { connection_id }` with the in-flight `Connection` and
    /// surfaces the events through `Stack::authenticate_connection`. The
    /// default implementation returns `Unsupported`.
    async fn auth_stream(
        &self,
        _address: Url,
        _capability: InteractiveAuthCapability,
    ) -> Result<UpstreamAuthStream> {
        Err(ovstorage_plugin::Error::new(
            ovstorage_plugin::ErrorCode::Unsupported,
            "broker transport does not implement auth_stream",
        ))
    }

    /// Register a client-supplied upstream credential for `address`. The broker
    /// dispatches it through its authenticated stack, where the stamped
    /// principal selects the credential slot and the upstream-credential layer
    /// persists it.
    async fn register_credential(
        &self,
        _address: Url,
        _payload: RegisterCredentialPayload,
    ) -> Result<()> {
        Err(ovstorage_plugin::Error::new(
            ovstorage_plugin::ErrorCode::Unsupported,
            "broker transport does not implement register_credential",
        ))
    }
}

/// Server-streamed partial events while the broker drives upstream OAuth.
pub type UpstreamAuthStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<crate::AuthEventPartial>> + Send>>;

/// Wire shape for a client-supplied upstream OAuth credential.
#[derive(Clone, Debug)]
pub struct RegisterCredentialPayload {
    pub access_token: Vec<u8>,
    pub refresh_token: Option<Vec<u8>>,
    pub expires_at: Option<std::time::SystemTime>,
}
