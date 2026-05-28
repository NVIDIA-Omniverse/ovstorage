// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! tonic Channel + per-service stub builders for the Omniverse Storage Service plugin.
//!
//! The Omniverse Storage Service publishes multiple service kinds in `/api/v1/services`
//! (`storage` for FileObject / Capabilities / Metadata / Versioning,
//! `notification-consumer` for the event-stream watch). Each kind lives on a
//! different gRPC endpoint, so the transport caches one Channel per kind,
//! built lazily on first use. The auth interceptor is wrapped at
//! stub-construction time so every RPC carries the current bearer.
//!
//! Services discovery (`/api/v1/services`) is itself auth-gated on
//! Omniverse Storage Service deployments, so it can't run during `instantiate` on a
//! cold-start OIDC connect. The transport defers that fetch to the first
//! `channel_for_kind` call: the bearer must be installed (via
//! `update_credentials` after the OIDC flow) before the first RPC.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ovstorage_services_protos::nvidia::omniverse::notifications::consumer::v1beta::event_consumer_service_client::EventConsumerServiceClient;
use ovstorage_services_protos::nvidia::omniverse::storage::{
    capabilities::v1alpha::capabilities_service_client::CapabilitiesServiceClient,
    filefolder::v1alpha::file_folder_service_client::FileFolderServiceClient,
    fileobject::v1alpha::file_object_service_client::FileObjectServiceClient,
    metadata::v1alpha::metadata_service_client::MetadataServiceClient,
    versioning::v1alpha::versioning_service_client::VersioningServiceClient,
};
use ovstorage_plugin::{Error, ErrorCode, Result};
use tokio::sync::{Mutex, OnceCell};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::auth::{AuthorizationInterceptor, DiscoveryState};
use crate::discovery::{ServiceEndpoint, fetch_service_endpoints, find_grpc_endpoint_for_kind};

/// Omniverse Storage Service service-kind names from `/api/v1/services`. These are the
/// `type` values plugins route on; they're part of the wire contract.
pub const KIND_STORAGE: &str = "storage";
pub const KIND_NOTIFICATION_CONSUMER: &str = "notification-consumer";

#[derive(Clone)]
pub struct OmniverseStorageTransport {
    inner: Arc<TransportInner>,
}

struct TransportInner {
    discovery_url: String,
    auth_state: DiscoveryState,
    /// `/api/v1/services` response, fetched on first `channel_for_kind`
    /// call and reused for every subsequent kind lookup.
    endpoints: OnceCell<Vec<ServiceEndpoint>>,
    /// One `Channel` per service kind. `tokio::sync::Mutex` rather than
    /// `OnceCell<HashMap>` so a slow `endpoint.connect()` for one kind
    /// doesn't serialise unrelated kinds.
    channels: Mutex<HashMap<String, Channel>>,
}

pub type Stub<T> = T;

pub type FileObject =
    FileObjectServiceClient<InterceptedService<Channel, AuthorizationInterceptor>>;
pub type FileFolder =
    FileFolderServiceClient<InterceptedService<Channel, AuthorizationInterceptor>>;
pub type Capabilities =
    CapabilitiesServiceClient<InterceptedService<Channel, AuthorizationInterceptor>>;
pub type Metadata = MetadataServiceClient<InterceptedService<Channel, AuthorizationInterceptor>>;
pub type Versioning =
    VersioningServiceClient<InterceptedService<Channel, AuthorizationInterceptor>>;
pub type EventConsumer =
    EventConsumerServiceClient<InterceptedService<Channel, AuthorizationInterceptor>>;

impl OmniverseStorageTransport {
    pub fn new(discovery_url: String, auth_state: DiscoveryState) -> Self {
        tracing::info!(
            target: "ovstorage.omniverse_storage_service.transport",
            plugin = "omniverse-storage-service",
            discovery_url = %discovery_url,
            "omniverse-storage-service: transport initialized (channel deferred until first RPC)",
        );
        Self {
            inner: Arc::new(TransportInner {
                discovery_url,
                auth_state,
                endpoints: OnceCell::new(),
                channels: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Construct a transport from an already-connected `Channel` — used by
    /// tests that wire up an in-memory tonic server over a duplex stream.
    /// The channel is registered as the `storage`-kind endpoint; tests that
    /// exercise notification-consumer paths set up their own seam.
    pub fn with_channel(channel: Channel, auth_state: DiscoveryState) -> Self {
        let mut map = HashMap::new();
        map.insert(KIND_STORAGE.to_string(), channel);
        Self {
            inner: Arc::new(TransportInner {
                discovery_url: "duplex://test".into(),
                auth_state,
                endpoints: OnceCell::new(),
                channels: Mutex::new(map),
            }),
        }
    }

    pub fn auth_state(&self) -> &DiscoveryState {
        &self.inner.auth_state
    }

    /// Fetch `/api/v1/services` once and cache the response. Subsequent
    /// callers (one per service kind) reuse the same vector.
    async fn endpoints(&self) -> Result<&Vec<ServiceEndpoint>> {
        self.inner
            .endpoints
            .get_or_try_init(|| async {
                let http = reqwest::Client::new();
                fetch_service_endpoints(&http, &self.inner.discovery_url, &self.inner.auth_state)
                    .await
            })
            .await
    }

    /// Lazy gRPC channel for the named service kind (e.g. `"storage"`,
    /// `"notification-consumer"`). Each kind lands on its own backend so
    /// they don't share TCP/HTTP-2 with each other.
    async fn channel_for_kind(&self, kind: &str) -> Result<Channel> {
        // Fast path: already established.
        {
            let map = self.inner.channels.lock().await;
            if let Some(existing) = map.get(kind) {
                return Ok(existing.clone());
            }
        }
        let endpoints = self.endpoints().await?;
        let (grpc_uri, plaintext) = find_grpc_endpoint_for_kind(endpoints, kind)?;
        tracing::debug!(
            target: "ovstorage.omniverse_storage_service.transport",
            plugin = "omniverse-storage-service",
            kind,
            grpc_uri = %grpc_uri,
            "omniverse-storage-service: establishing gRPC channel",
        );
        let mut endpoint = Endpoint::from_shared(grpc_uri.clone()).map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("omniverse-storage-service: invalid gRPC endpoint '{grpc_uri}': {err}"),
            )
        })?;
        // Keepalive matches the C++ provider_omnistorage settings at
        // StorageProvider.cpp:1089-1091. Without these, idle proxies
        // (NLB / cloud LBs / corp middleboxes) silently drop the
        // bidi `watch_directory` stream — gRPC is layered on HTTP/2
        // PING frames that L4 LBs can't see, and the consumer-side
        // RPC docs explicitly call this out.
        endpoint = endpoint
            .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true);
        if !plaintext {
            endpoint = endpoint
                .tls_config(ClientTlsConfig::new().with_native_roots())
                .map_err(|err| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "omniverse-storage-service: TLS config for '{grpc_uri}' failed: {err}"
                        ),
                    )
                })?;
        }
        let channel = endpoint.connect().await.map_err(|err| {
            tracing::warn!(
                target: "ovstorage.omniverse_storage_service.transport",
                plugin = "omniverse-storage-service",
                kind,
                grpc_uri = %grpc_uri,
                "omniverse-storage-service: gRPC channel connect failed",
            );
            Error::new(
                ErrorCode::Transient,
                format!("omniverse-storage-service: failed to connect to gRPC endpoint '{grpc_uri}': {err}"),
            )
        })?;
        tracing::debug!(
            target: "ovstorage.omniverse_storage_service.transport",
            plugin = "omniverse-storage-service",
            kind,
            grpc_uri = %grpc_uri,
            "omniverse-storage-service: gRPC channel established",
        );
        // Race: another caller may have inserted concurrently. Prefer the
        // first-inserted channel so we don't leak a TCP connection.
        let mut map = self.inner.channels.lock().await;
        let installed = map.entry(kind.to_string()).or_insert(channel).clone();
        Ok(installed)
    }

    fn interceptor(&self) -> AuthorizationInterceptor {
        AuthorizationInterceptor::new(self.inner.auth_state.clone())
    }

    pub async fn capabilities_client(&self) -> Result<Capabilities> {
        let channel = self.channel_for_kind(KIND_STORAGE).await?;
        Ok(
            CapabilitiesServiceClient::with_interceptor(channel, self.interceptor())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
    }

    pub async fn fileobject_client(&self) -> Result<FileObject> {
        let channel = self.channel_for_kind(KIND_STORAGE).await?;
        Ok(
            FileObjectServiceClient::with_interceptor(channel, self.interceptor())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
    }

    pub async fn filefolder_client(&self) -> Result<FileFolder> {
        let channel = self.channel_for_kind(KIND_STORAGE).await?;
        Ok(
            FileFolderServiceClient::with_interceptor(channel, self.interceptor())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
    }

    pub async fn metadata_client(&self) -> Result<Metadata> {
        let channel = self.channel_for_kind(KIND_STORAGE).await?;
        Ok(
            MetadataServiceClient::with_interceptor(channel, self.interceptor())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
    }

    pub async fn versioning_client(&self) -> Result<Versioning> {
        let channel = self.channel_for_kind(KIND_STORAGE).await?;
        Ok(
            VersioningServiceClient::with_interceptor(channel, self.interceptor())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
    }

    pub async fn event_consumer_client(&self) -> Result<EventConsumer> {
        let channel = self.channel_for_kind(KIND_NOTIFICATION_CONSUMER).await?;
        Ok(
            EventConsumerServiceClient::with_interceptor(channel, self.interceptor())
                .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES),
        )
    }
}

/// Per-message gRPC size cap. tonic's default is 4 MiB which is exactly
/// what the Omniverse Storage Service's recommended chunk size is, so the proto envelope
/// overhead (~10 bytes per Chunk message) tips a 4 MiB body chunk over
/// the limit. Bumping to 16 MiB gives comfortable headroom for chunks
/// at the documented 4 MiB target without unbounded growth.
pub const MAX_GRPC_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// HTTP/2 PING interval. Matches `provider_omnistorage` at
/// `StorageProvider.cpp:1089-1091`.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Time to wait for a PING ack before declaring the connection dead.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
