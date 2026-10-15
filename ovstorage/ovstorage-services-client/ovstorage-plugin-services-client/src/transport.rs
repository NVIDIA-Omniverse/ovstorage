// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! tonic Channel + per-service stub builders for the Omniverse Storage Service plugin.
//!
//! The Omniverse Storage Service publishes multiple service kinds in `/api/v1/services`
//! (`storage` for FileObject / Capabilities / Metadata / Versioning,
//! `notification-consumer` for the event-stream watch). A kind may live on its
//! own gRPC endpoint — nothing requires the published values to differ — so the
//! transport caches one Channel per kind, built lazily on first use. The auth
//! interceptor is wrapped at stub-construction time so every RPC carries the
//! current bearer.
//!
//! A connection is located one of two ways, told apart by the scheme of its
//! configured URL (see [`crate::config::ServiceLocation`]):
//!
//! - **Discovery.** Services discovery (`/api/v1/services`) is itself auth-gated
//!   on Omniverse Storage Service deployments, so it cannot run while the
//!   connection scaffold is built — that step is deliberately network-free. The
//!   transport defers the fetch to the first `channel_for_kind` call, by which
//!   point the bearer has been installed by the connection's auth bring-up.
//! - **Direct gRPC endpoint.** The configured address *is* the `storage`
//!   endpoint, so no fetch happens at all and every other kind is refused by
//!   name. Such a deployment publishes no auth-config, so no grant of any kind
//!   runs here — the only bearer such a connection can hold is one the host
//!   supplies and replaces directly.

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
use crate::config::ServiceLocation;
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
    location: ServiceLocation,
    auth_state: DiscoveryState,
    /// `/api/v1/services` response, fetched on first `channel_for_kind`
    /// call and reused for every subsequent kind lookup. `Arc`-shared so a
    /// [`OmniverseStorageTransport::probe_with_state`] sibling reuses the same
    /// discovered endpoints (and, in tests, the injected channel below) while
    /// reading its bearer from a different `auth_state`.
    endpoints: Arc<OnceCell<Vec<ServiceEndpoint>>>,
    /// One `Channel` per service kind. `tokio::sync::Mutex` rather than
    /// `OnceCell<HashMap>` so a slow `endpoint.connect()` for one kind
    /// doesn't serialise unrelated kinds. `Arc`-shared with `probe_with_state`
    /// siblings (see `endpoints`).
    channels: Arc<Mutex<HashMap<String, Channel>>>,
}

/// Strip userinfo, query and fragment from a locator for a diagnostic.
///
/// Free function rather than a method because the transport's constructor logs
/// before `self` exists. [`OmniverseStorageTransport::redacted_locator`] is the
/// same rule for callers that have one.
fn redacted(raw: &str) -> String {
    match ovstorage_plugin::Url::parse(raw) {
        Ok(url) => ovstorage_plugin::RedactedUrl(&url).to_string(),
        Err(_) => "<unparseable>".to_string(),
    }
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
    pub fn new(location: ServiceLocation, auth_state: DiscoveryState) -> Self {
        tracing::info!(
            target: "ovstorage.omniverse_storage_service.transport",
            plugin = "omniverse-storage-service",
            // Redacted: a discovery URL may carry userinfo, and this line is
            // emitted for every connection at INFO.
            service_url = %redacted(location.locator()),
            direct_endpoint = location.discovery_url().is_none(),
            "omniverse-storage-service: transport initialized (channel deferred until first RPC)",
        );
        Self {
            inner: Arc::new(TransportInner {
                location,
                auth_state,
                endpoints: Arc::new(OnceCell::new()),
                channels: Arc::new(Mutex::new(HashMap::new())),
            }),
        }
    }

    /// Whether a caller may BLOCK waiting for a bearer to appear.
    ///
    /// True only for a discovery connection, where a grant or an interactive
    /// sign-in will eventually install one. A direct endpoint may hold a bearer
    /// — the host can supply one — but nothing here will ever produce one on its
    /// own, and such a connection is equally allowed to hold none, so a wait
    /// there is unbounded rather than slow. It also does not need one: bring-up
    /// installs a supplied bearer before any root discovery runs, and a bearer
    /// arriving later re-lists roots through `update_connection_credentials`.
    pub fn requires_bearer(&self) -> bool {
        self.inner.location.discovery_url().is_some()
    }

    /// This connection's durable locator, for a diagnostic — userinfo, query
    /// and fragment removed.
    ///
    /// **Never log the raw locator.** A DIRECT endpoint's address is safe by
    /// construction, because config validation refuses userinfo, a path, a
    /// query and a fragment on that arm. A DISCOVERY URL is not:
    /// `https://user:pw@host` is deliberately still accepted there, so that
    /// value can carry a password. Rather than make every call site establish
    /// which arm it is looking at — a rule the next caller has to remember —
    /// this is the only way to get the locator OUT OF A TRANSPORT, and it is
    /// redacted for both arms.
    ///
    /// It is not the only route to the string itself: `ServiceLocation::locator`
    /// is public, and the layer builds a connection's display name and
    /// `BackendId` from it, so a discovery URL's userinfo still reaches those.
    /// That is pre-existing and outside this seam; what is closed here is the
    /// logging one.
    ///
    /// A locator that does not parse as a URL is reported as a fixed
    /// placeholder rather than passed through: an unparseable value is exactly
    /// the one whose shape nothing has established.
    pub fn redacted_locator(&self) -> String {
        redacted(self.inner.location.locator())
    }

    /// Whether this connection's channel is cleartext AND leaves this machine.
    ///
    /// The condition a bearer token needs
    /// [`crate::config::ALLOW_PLAINTEXT_CREDENTIALS_KEY`] for.
    ///
    /// The only cleartext question a TRANSPORT answers. "Is the channel
    /// cleartext" has no caller that wants it on its own: every use is really
    /// asking whether a credential is being disclosed, and a loopback endpoint
    /// is cleartext while disclosing nothing.
    ///
    /// There is a second cleartext predicate in the crate and the two are not
    /// duplicates: `config::plaintext_is_safe` decides whether cleartext may be
    /// spoken to an ADDRESS at all, and answers yes across private and
    /// in-cluster space — which is exactly where an eavesdropper who is not this
    /// machine lives, and so exactly where a CREDENTIAL still needs the
    /// operator's opt-in. Two questions, deliberately answered differently; the
    /// hazard to watch is anyone "unifying" them.
    ///
    /// A discovery connection answers `false` — its channel scheme is not known
    /// until its endpoints are fetched, which is after the credential decision.
    /// That is a stated gap, recorded in the shipped documentation.
    pub fn is_plaintext_beyond_loopback(&self) -> bool {
        self.inner.location.is_plaintext_beyond_loopback()
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
                location: ServiceLocation::Discovery("duplex://test".into()),
                auth_state,
                endpoints: Arc::new(OnceCell::new()),
                channels: Arc::new(Mutex::new(map)),
            }),
        }
    }

    /// Build an ephemeral sibling transport that SHARES this transport's channel
    /// cache and discovered service endpoints, but reads its bearer from
    /// `auth_state` instead of the live token cell. The driver's `verify` uses
    /// this to run one read-only probe RPC with a CANDIDATE bearer — reusing the
    /// live gRPC channel (and, in tests, a `with_channel`-injected in-memory
    /// channel) without installing the candidate on the live cell or perturbing a
    /// concurrent live RPC. Any auth-gated services-discovery it triggers runs
    /// with `auth_state`'s bearer, so a probe never needs a token on the live
    /// cell to establish its channel.
    pub fn probe_with_state(&self, auth_state: DiscoveryState) -> Self {
        Self {
            inner: Arc::new(TransportInner {
                location: self.inner.location.clone(),
                auth_state,
                endpoints: self.inner.endpoints.clone(),
                channels: self.inner.channels.clone(),
            }),
        }
    }

    pub fn auth_state(&self) -> &DiscoveryState {
        &self.inner.auth_state
    }

    /// Fetch `/api/v1/services` once and cache the response. Subsequent
    /// callers (one per service kind) reuse the same vector.
    async fn endpoints(&self) -> Result<&Vec<ServiceEndpoint>> {
        let discovery_url = self.inner.location.discovery_url().ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                "omniverse-storage-service: this connection is configured with a direct gRPC \
                 endpoint, so there is no discovery service to resolve endpoints from",
            )
        })?;
        self.inner
            .endpoints
            .get_or_try_init(|| async {
                let http = reqwest::Client::new();
                fetch_service_endpoints(&http, discovery_url, &self.inner.auth_state).await
            })
            .await
    }

    /// Resolve `kind` to a `(uri, plaintext)` pair.
    ///
    /// A direct endpoint names exactly one service — `storage`. Every other
    /// kind is refused by name rather than dialed at the storage address on the
    /// chance that the same process also serves it: a wrong guess would surface
    /// as an opaque protocol error at the first RPC, where the refusal states
    /// what is missing and what would supply it.
    async fn resolve_kind(&self, kind: &str) -> Result<(String, bool)> {
        if let ServiceLocation::DirectGrpc { dial_uri, .. } = &self.inner.location {
            if kind == KIND_STORAGE {
                return Ok((dial_uri.clone(), dial_uri.starts_with("http://")));
            }
            return Err(Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "omniverse-storage-service: a direct gRPC endpoint names only the '{KIND_STORAGE}' \
                     service, so the '{kind}' service cannot be resolved; configure a discovery URL \
                     to use it"
                ),
            ));
        }
        let endpoints = self.endpoints().await?;
        find_grpc_endpoint_for_kind(endpoints, kind)
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
        let (grpc_uri, plaintext) = self.resolve_kind(kind).await?;
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
