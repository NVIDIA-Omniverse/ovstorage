// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
//! # Credential lock order
//!
//! Every lock a credential operation may hold, in the order they must be
//! acquired. A path may take a suffix or a prefix of this order, never a
//! permutation.
//!
//! 1. **Publication lock.** Held across a durable write and across an
//!    identity-changing install, so a keyring write and an install cannot
//!    interleave. It exists as a lock of its own — rather than reusing the
//!    identity fence — because an OS secret-store round trip (DBus, Keychain, the
//!    Windows credential manager) can take seconds, and the identity fence is
//!    on the read path. It is acquired FIRST for the same reason: a lock taken
//!    ahead of it is held for that entire round trip, and the credential cells
//!    are read by the transport interceptor on every RPC.
//! 2. **Credential state locks** (access token → refresh token → expiry →
//!    cached client credentials). Held by an install so the bundle it writes is
//!    never observed half-applied. They are synchronous locks, not async ones,
//!    precisely so an install can hold the publication lock — a
//!    `std::sync::MutexGuard` — while acquiring them.
//! 3. **Binding mutex / identity fence.** Held across the identity generation
//!    bump and the binding write, so the two are one step to any observer. Work
//!    under it must be bounded and non-blocking: no I/O, no further locks.
//!
//! **Every** install site takes the publication lock before any credential
//! guard — the `client_credentials` update included, not just the token
//! installs. These locks are synchronous and non-reentrant, so a single site
//! that took a credential guard first would close the graph into a cycle and
//! permanently deadlock the connection's credential path (and, with it, durable
//! persistence, which takes the publication lock on every write). The compiler
//! does not catch this: holding a `parking_lot` guard across a
//! `std::sync::Mutex::lock()` is legal Rust. Enumerate the sites by reading.
//!
//! None of these is held across an `.await`. The durable writes they guard are
//! synchronous host callbacks, which is what makes that possible.

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use ovstorage_broker_protocol::{
    self as protocol, BrokerClientTransport, BrokerClientWatchDirectoryStream, pb,
};
use ovstorage_plugin::*;
use ovstorage_plugin::{
    BackendChangeEvent, BackendChangeStream, BackendItemInfo, ReadResult, WriteStep,
};
use serde::Deserialize;

/// HTTP/2 PING interval on the broker TCP channel. 10 s matches
/// the server-side policy in `ovstorage-broker::grpc` and the
/// `provider_omnistorage` reference at
/// `client-library/source/library/provider_omnistorage/StorageProvider.cpp:1089-1091`.
const BROKER_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Time to wait for a PING ack before declaring the broker connection dead.
const BROKER_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

mod auth;
mod driver;
mod layer;
pub use auth::{
    AuthClientConfig, AuthConfig, AuthorizationInterceptor, DiscoveryState, OidcConfig,
    REFRESH_SKEW, capability_from_metadata, drive_client_credentials_grant,
    drive_interactive_login, drive_refresh_token_grant, drive_upstream_auth, fetch_auth_config,
    fetch_oidc_config,
};
pub use ovstorage_broker_protocol::X_OV_IAUTH;

/// Backend-kind string this plugin advertises (also the secret store backend kind).
const KIND: &str = "broker";
const KEYRING_BACKEND_KIND: &str = "broker";
const PLUGIN_NAME: &str = "broker";

pub struct BrokerClientBackend {
    discovery_url: String,
    /// Per-backend transport cache: TLS handshake / socket connect /
    /// discovery RTT happens once per instance, every SPI call reuses.
    transport: tokio::sync::OnceCell<Arc<dyn BrokerClientTransport>>,
    /// Per-connection OIDC discovery state: auth-config, IDP discovery,
    /// current tokens, generation counter. The interceptor reads it per
    /// RPC; refreshes write back.
    auth_state: DiscoveryState,
}

impl BrokerClientBackend {
    /// Build a per-connection backend sharing `auth_state` with its
    /// `BrokerDriver`: the transport interceptor and the
    /// driver's grants read/write the same [`DiscoveryState`] token cell. The
    /// transport is established lazily on the first SPI call.
    pub fn new(discovery_url: String, auth_state: DiscoveryState) -> Self {
        Self {
            discovery_url,
            transport: tokio::sync::OnceCell::new(),
            auth_state,
        }
    }

    pub fn discovery_url(&self) -> &str {
        &self.discovery_url
    }

    pub fn auth_state(&self) -> &DiscoveryState {
        &self.auth_state
    }

    /// Discover the broker's published address roots (the cheap read-only RPC
    /// the layer uses for routing bring-up and the driver's `verify`).
    pub async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
        self.transport().await?.list_address_roots().await
    }

    /// Test-only constructor that injects a pre-built transport. Used
    /// by `tests/precondition.rs` to drive the SPI surface against a
    /// recording transport without standing up a gRPC fake-server.
    /// Not part of the public API; `#[doc(hidden)]` keeps it out of
    /// rustdoc and the `_test_support` feature gate keeps it out of
    /// release builds entirely. The crate self-references with this
    /// feature enabled in `[dev-dependencies]`, so integration tests
    /// pick it up automatically.
    #[doc(hidden)]
    #[cfg(feature = "_test_support")]
    pub fn new_for_tests(
        discovery_url: impl Into<String>,
        transport: Arc<dyn BrokerClientTransport>,
    ) -> Self {
        let cell = tokio::sync::OnceCell::new();
        // OnceCell::set returns Err only if the cell is already full;
        // we just created it, so this is infallible.
        let _ = cell.set(transport);
        Self {
            discovery_url: discovery_url.into(),
            transport: cell,
            auth_state: DiscoveryState::new("test"),
        }
    }
}

/// Per-connection object operations used by `BrokerClientLayer`, with
/// `ConnectionSet`-driven recovery for replayable calls.
impl BrokerClientBackend {
    pub async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "broker.stat",
            op = "stat",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .stat(target.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        // Boundary sanity: reject inverted byte ranges before any wire
        // call. The broker daemon would reject this too (the
        // gateway-side range follower can't satisfy `end < start`), but
        // catching at the plugin boundary saves a round-trip and gives
        // a precise `InvalidArgument` rather than a downstream
        // `Internal` from whichever upstream backend the broker
        // dispatches to.
        if let Some(range) = opts.range.as_ref()
            && let Some(end) = range.end_inclusive
            && end < range.start
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "broker read: inverted byte range: start={} end_inclusive={end}",
                    range.start,
                ),
            ));
        }
        let span = tracing::debug_span!(
            "broker.read",
            op = "read",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .read(target.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::debug_span!(
            "broker.write",
            op = "write",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
        match self
            .transport()
            .await?
            .write(target.resolved_address, Body::Bytes(bytes), opts)
            .await?
        {
            WriteStep::Done(result) => Ok(result),
            WriteStep::Redirects(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "broker write: upstream emitted redirects; \
                 the broker-bypass redirect-forwarding path lives in write_redirect (not yet wired)",
            )),
        }
            })
        .await
    }

    pub async fn write_stream(
        &self,
        target: ResolvedTarget,
        stream: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::debug_span!(
            "broker.write",
            op = "write",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            match self
                .transport()
                .await?
                .write(target.resolved_address, Body::Stream(stream), opts)
                .await?
            {
                WriteStep::Done(result) => Ok(result),
                WriteStep::Redirects(_) => Err(Error::new(
                    ErrorCode::Unsupported,
                    "broker write_stream: upstream emitted redirects",
                )),
            }
        })
        .await
    }

    pub async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        // `size_hint = None` is forwarded faithfully (no boundary
        // refusal): the broker daemon's `Broker::write_redirect`
        // delegates to the backend-emitted write-redirect protocol
        // (`stack.write_redirect`), which accepts unknown size and lets
        // the backend presign the redirect targets. Refusing here would
        // deny a path the wire fully supports. This contrasts with the
        // nucleus plugin's `spi.rs::write_redirect` (LFT multipart needs
        // total length to compute part offsets) — the broker wire is not
        // multipart.
        let span = tracing::debug_span!(
            "broker.write",
            op = "write",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            // Body-less unary RPC; UNIMPLEMENTED upstream surfaces as
            // `Unsupported` so the gateway falls back to write / write_stream.
            self.transport()
                .await?
                .write_redirect(target.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = tracing::debug_span!(
            "broker.delete",
            op = "delete",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .delete(target.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ListPage> {
        let span = tracing::debug_span!(
            "broker.list",
            op = "list",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        let _guard = span.enter();
        // The broker daemon paginates on its own stack and returns a fully
        // server-paged `ListPage`; surface it verbatim (including
        // `next_page_token`) so the caller can reach pages 2+.
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .list(prefix.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "broker.list_versions",
            op = "list_versions",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .list_versions(target.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "broker.get_latest_version",
            op = "get_latest_version",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .get_latest_version(target.resolved_address)
                .await
        })
        .await
    }

    pub async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let span = tracing::debug_span!(
            "broker.watch_directory",
            op = "watch_directory",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            let stream = self
                .transport()
                .await?
                .watch_directory(prefix.resolved_address, opts)
                .await?;
            let translated: BackendChangeStream =
                Box::new(stream.map(|event| event.map(broker_watch_directory_event_to_backend)));
            Ok(translated)
        })
        .await
    }

    pub async fn create_directory(
        &self,
        target: ResolvedTarget,
        opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = tracing::debug_span!(
            "broker.create_directory",
            op = "create_directory",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            let info = self
                .transport()
                .await?
                .create_directory(target.resolved_address, opts)
                .await?;
            Ok(backend_item_info(info))
        })
        .await
    }

    pub async fn delete_directory(
        &self,
        target: ResolvedTarget,
        opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = tracing::debug_span!(
            "broker.delete_directory",
            op = "delete_directory",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .delete_directory(target.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = tracing::debug_span!(
            "broker.copy",
            op = "copy",
            object.address = %RedactedUrl(&src.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            let result = self
                .transport()
                .await?
                .copy(src.resolved_address, dest.resolved_address, opts)
                .await?;
            Ok(WriteStep::Done(result))
        })
        .await
    }

    pub async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = tracing::debug_span!(
            "broker.rename",
            op = "rename",
            object.address = %RedactedUrl(&src.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .rename(src.resolved_address, dest.resolved_address, opts)
                .await
        })
        .await
    }

    pub async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = tracing::debug_span!(
            "broker.update_metadata",
            op = "update_metadata",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            let info = self
                .transport()
                .await?
                .update_metadata(target.resolved_address, opts)
                .await?;
            Ok(backend_item_info(info))
        })
        .await
    }

    pub async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let span = tracing::debug_span!(
            "broker.check_access",
            op = "check_access",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            self.transport()
                .await?
                .check_access(target.resolved_address, ops)
                .await
        })
        .await
    }

    pub async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = tracing::debug_span!(
            "broker.write",
            op = "write",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _guard = span.enter();
        race_cancel(cancel.as_ref(), async move {
            ovstorage_plugin::validate_redirect_results(&redirects, &results)?;
            self.transport()
                .await?
                .continue_write(target.resolved_address, redirects, results)
                .await
        })
        .await
    }

    pub async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        race_cancel(cancel.as_ref(), async move {
            // Translate protocol `AddressRootsChange` -> SPI variant per frame.
            // The two enums match by shape; the SPI must not depend on the
            // broker protocol crate.
            use futures::StreamExt;
            let transport_stream = self.transport().await?.watch_address_roots().await?;
            let translated = transport_stream.map(|item| {
                item.map(|change| match change {
                    protocol::AddressRootsChange::Snapshot(roots) => {
                        AddressRootsChange::Snapshot(roots)
                    }
                    protocol::AddressRootsChange::Added(roots) => AddressRootsChange::Added(roots),
                    protocol::AddressRootsChange::Removed(roots) => {
                        AddressRootsChange::Removed(roots)
                    }
                })
            });
            let boxed: BackendAddressRootsStream = Box::pin(translated);
            Ok(boxed)
        })
        .await
    }
}

impl BrokerClientBackend {
    /// Resolve the broker transport, populating the per-backend cache on
    /// first call. The interceptor shares `auth_state`, so token rotation
    /// reaches the live channel without rebuild. Transient failures leave
    /// the cell empty (matches `OnceCell::get_or_try_init`).
    async fn transport(&self) -> Result<Arc<dyn BrokerClientTransport>> {
        self.transport
            .get_or_try_init(|| {
                transport_for_with_auth(&self.discovery_url, Some(self.auth_state.clone()))
            })
            .await
            .cloned()
    }
}

fn discovery_url(config: &std::collections::HashMap<String, ConfigValue>) -> Result<String> {
    let value = match config.get("address") {
        Some(ConfigValue::String(value)) => value,
        Some(_) => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "broker address must be a string",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "missing broker address",
            ));
        }
    };
    normalize_discovery_url(value)
}

/// Decoded `[connection.auth]` block. Mode/auth coherence is enforced
/// at parse time: `token_file` is direct-mode only, `client_secret_file`
/// is discovery-mode only.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
struct ConnectionAuthBlock {
    /// Bearer token sourced from a file (k8s SA token, vault-injected secret).
    /// Direct gRPC mode only.
    #[serde(default)]
    token_file: Option<String>,
    /// OAuth2 `client_credentials` grant secret. Discovery mode only.
    #[serde(default)]
    client_secret_file: Option<String>,
}

impl ConnectionAuthBlock {
    fn parse(config: &std::collections::HashMap<String, ConfigValue>) -> Result<Option<Self>> {
        let toml = match config.get("auth") {
            Some(ConfigValue::Toml(s)) => s,
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "broker [connection.auth] must be a table",
                ));
            }
            None => return Ok(None),
        };
        // The host wraps the table under its key when reserializing nested
        // config; unwrap before parsing.
        let outer: toml::Value = toml.parse().map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker [connection.auth] is not valid TOML: {err}"),
            )
        })?;
        let inner: toml::Value = outer
            .as_table()
            .and_then(|t: &toml::value::Table| t.get("auth"))
            .cloned()
            .unwrap_or(outer);
        let block: ConnectionAuthBlock = inner.try_into().map_err(|err: toml::de::Error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker [connection.auth] shape: {err}"),
            )
        })?;
        if block.token_file.is_some() && block.client_secret_file.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "broker [connection.auth]: set token_file OR client_secret_file, not both",
            ));
        }
        Ok(Some(block))
    }

    fn validate_against_address(&self, address: &str) -> Result<()> {
        let is_direct = address.starts_with("grpc")
            || address.starts_with("unix:")
            || address.starts_with("npipe:");
        let is_discovery = address.starts_with("http://") || address.starts_with("https://");
        if self.token_file.is_some() && !is_direct {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "broker [connection.auth] token_file requires a direct address \
                 (grpc[+tls/+tcp]://, unix:, npipe:); discovery mode (http(s)://) does \
                 not need it because the broker advertises auth-config",
            ));
        }
        if self.client_secret_file.is_some() && !is_discovery {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "broker [connection.auth] client_secret_file requires a discovery \
                 address (http(s)://); direct mode has no token endpoint to drive a \
                 client_credentials grant against",
            ));
        }
        Ok(())
    }
}

fn read_token_file(path: &std::path::Path) -> Result<String> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        Error::new(
            ErrorCode::CredentialUnavailable,
            format!("broker token_file '{}' read failed: {err}", path.display()),
        )
    })?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorCode::CredentialUnavailable,
            format!("broker token_file '{}' is empty", path.display()),
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_discovery_url(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "broker address must not be empty",
        ));
    }
    // Absolute path → unix socket.
    if trimmed.starts_with('/') {
        return Ok(format!("unix:{trimmed}"));
    }
    // pipe:NAME shorthand → npipe URL.
    if let Some(name) = trimmed.strip_prefix("pipe:") {
        let name = name.trim_start_matches('/').trim_matches('/');
        if name.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "broker address 'pipe:' must include a pipe name",
            ));
        }
        return Ok(format!("npipe:/{name}"));
    }
    // Windows native form `\\.\pipe\NAME`.
    if trimmed.starts_with(r"\\.\pipe\") || trimmed.starts_with(r"\\?\pipe\") {
        let name = trimmed.rsplit('\\').next().unwrap_or("");
        if name.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "broker address must include a pipe name",
            ));
        }
        return Ok(format!("npipe:/{name}"));
    }
    let trimmed = trimmed.trim_end_matches('/');
    if has_local_direct_endpoint_scheme(trimmed) {
        url::Url::parse(trimmed).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("broker address must be a URL: {error}"),
            )
        })?;
        return Ok(trimmed.to_string());
    }
    if trimmed.contains("://") && url::Url::parse(trimmed).is_ok() {
        return Ok(trimmed.to_string());
    }
    let scheme = if should_infer_http(trimmed) {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{trimmed}")
        .trim_end_matches('/')
        .to_string())
}

async fn transport_for_with_auth(
    discovery_url: &str,
    auth_state: Option<DiscoveryState>,
) -> Result<Arc<dyn BrokerClientTransport>> {
    let discovery_url = normalize_discovery_url(discovery_url)?;
    let endpoint = if let Some(endpoint) = parse_direct_endpoint(&discovery_url)? {
        endpoint
    } else {
        let endpoint = fetch_discovered_broker_endpoint(&discovery_url).await?;
        parse_broker_endpoint(&endpoint)?
    };
    let mut client = TonicBrokerClient::new(endpoint);
    if let Some(state) = auth_state {
        client = client.with_auth_state(state);
    }
    Ok(Arc::new(client))
}

/// gRPC client type cached inside `TonicBrokerClient`; wraps the tonic
/// `Channel` with `AuthorizationInterceptor`.
type CachedClient = pb::broker_service_client::BrokerServiceClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        AuthorizationInterceptor,
    >,
>;

#[derive(Clone)]
struct TonicBrokerClient {
    endpoint: BrokerEndpoint,
    /// Lazy-init cache of the connected gRPC client. `Channel::clone` is
    /// cheap (the connector is shared via `Arc`); the outer `Arc<OnceCell>`
    /// keeps `TonicBrokerClient: Clone` while ensuring all clones share
    /// one channel.
    client: Arc<tokio::sync::OnceCell<CachedClient>>,
    /// Always set (empty `DiscoveryState` for no-auth deployments) so the
    /// interceptor can read the current access token on every RPC.
    auth_state: DiscoveryState,
}

struct BrokerWatchDirectoryStream {
    receiver: mpsc::IntoIter<Result<ChangeEvent>>,
    cancel: CancellationToken,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Iterator for BrokerWatchDirectoryStream {
    type Item = Result<ChangeEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        self.receiver.next()
    }
}

impl Drop for BrokerWatchDirectoryStream {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl TonicBrokerClient {
    fn new(endpoint: BrokerEndpoint) -> Self {
        Self {
            endpoint,
            client: Arc::new(tokio::sync::OnceCell::new()),
            auth_state: DiscoveryState::new("default"),
        }
    }

    fn with_auth_state(mut self, state: DiscoveryState) -> Self {
        self.auth_state = state;
        self
    }

    /// Return the cached `BrokerServiceClient`, populating on first call.
    async fn connect(&self) -> Result<CachedClient> {
        self.client
            .get_or_try_init(|| self.establish())
            .await
            .cloned()
    }

    /// One-shot channel establishment.
    async fn establish(&self) -> Result<CachedClient> {
        let (uri, plaintext) = match &self.endpoint {
            BrokerEndpoint::Tcp {
                channel_uri,
                plaintext,
            } => (channel_uri.clone(), *plaintext),
            BrokerEndpoint::UnixSocket(path) => {
                tracing::debug!(
                    target: "ovstorage.broker.transport",
                    path = %path,
                    "broker: connecting via Unix socket"
                );
                let result = connect_unix_socket(path, self.auth_state.clone()).await;
                if result.is_ok() {
                    tracing::info!(
                        target: "ovstorage.broker.transport",
                        path = %path,
                        "broker: Unix socket transport established"
                    );
                }
                return result;
            }
            BrokerEndpoint::NamedPipe(name) => {
                tracing::debug!(
                    target: "ovstorage.broker.transport",
                    pipe = %name,
                    "broker: connecting via named pipe"
                );
                let result = connect_named_pipe(name, self.auth_state.clone()).await;
                if result.is_ok() {
                    tracing::info!(
                        target: "ovstorage.broker.transport",
                        pipe = %name,
                        "broker: named pipe transport established"
                    );
                }
                return result;
            }
        };
        tracing::debug!(
            target: "ovstorage.broker.transport",
            uri = %uri,
            plaintext,
            "broker: establishing gRPC TCP connection"
        );
        let mut endpoint =
            tonic::transport::Endpoint::from_shared(uri.clone()).map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid broker gRPC endpoint '{uri}': {error}"),
                )
            })?;
        // HTTP/2 keepalive on the TCP path. Without it, idle proxies
        // (NLB / cloud LBs / corp middleboxes) silently drop bidi auth and
        // server-streaming `watch_*` RPCs because L4 LBs can't see the
        // gRPC PING frames as activity. Symmetric with the server-side
        // policy in `ovstorage-broker/src/grpc.rs` and the omnistorage
        // plugin's transport. Unix-socket and named-pipe paths skip this
        // since they don't traverse a network.
        endpoint = endpoint
            .http2_keep_alive_interval(BROKER_KEEPALIVE_INTERVAL)
            .keep_alive_timeout(BROKER_KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true);
        if !plaintext {
            endpoint = endpoint
                .tls_config(tonic::transport::ClientTlsConfig::new().with_enabled_roots())
                .map_err(|error| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("invalid broker TLS endpoint '{uri}': {error}"),
                    )
                })?;
        }
        let channel = endpoint.connect().await.map_err(|error| {
            Error::new(
                ErrorCode::BrokerUnavailable,
                format!("failed to connect to broker gRPC endpoint '{uri}': {error}"),
            )
        })?;
        tracing::info!(
            target: "ovstorage.broker.transport",
            uri = %uri,
            "broker: gRPC TCP transport established"
        );
        Ok(
            pb::broker_service_client::BrokerServiceClient::with_interceptor(
                channel,
                AuthorizationInterceptor::new(self.auth_state.clone()),
            ),
        )
    }
}

#[cfg(unix)]
async fn connect_unix_socket(path: &str, auth_state: DiscoveryState) -> Result<CachedClient> {
    let path = path.to_string();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("invalid local Unix broker endpoint template: {error}"),
            )
        })?
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::BrokerUnavailable,
                format!("failed to connect to broker Unix socket: {error}"),
            )
        })?;
    Ok(
        pb::broker_service_client::BrokerServiceClient::with_interceptor(
            channel,
            AuthorizationInterceptor::new(auth_state),
        ),
    )
}

#[cfg(not(unix))]
async fn connect_unix_socket(path: &str, _auth_state: DiscoveryState) -> Result<CachedClient> {
    Err(Error::new(
        ErrorCode::Unsupported,
        format!("unix socket broker endpoint '{path}' is not available on this platform"),
    ))
}

#[cfg(windows)]
async fn connect_named_pipe(name: &str, auth_state: DiscoveryState) -> Result<CachedClient> {
    let pipe_path = named_pipe_path(name);
    let endpoint = tonic::transport::Endpoint::try_from("http://[::]:50051").map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid local named-pipe broker endpoint template: {error}"),
        )
    })?;
    let mut last_error = None;
    for _ in 0..20 {
        let pipe_path = pipe_path.clone();
        match endpoint
            .connect_with_connector(tower::service_fn(move |_| {
                let pipe_path = pipe_path.clone();
                async move {
                    tokio::net::windows::named_pipe::ClientOptions::new()
                        .open(pipe_path)
                        .map(hyper_util::rt::TokioIo::new)
                }
            }))
            .await
        {
            Ok(channel) => {
                return Ok(
                    pb::broker_service_client::BrokerServiceClient::with_interceptor(
                        channel,
                        AuthorizationInterceptor::new(auth_state),
                    ),
                );
            }
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
    Err(Error::new(
        ErrorCode::BrokerUnavailable,
        format!(
            "failed to connect to broker named pipe: {}",
            last_error
                .map(|error| format!("{error:?}"))
                .unwrap_or_else(|| "transport error".into())
        ),
    ))
}

#[cfg(not(windows))]
async fn connect_named_pipe(name: &str, _auth_state: DiscoveryState) -> Result<CachedClient> {
    Err(Error::new(
        ErrorCode::Unsupported,
        format!("named pipe broker endpoint '{name}' is not available on this platform"),
    ))
}

#[cfg(windows)]
fn named_pipe_path(name: &str) -> String {
    let trimmed = name.trim().trim_matches(['/', '\\']);
    if trimmed.starts_with("\\\\.\\pipe\\") {
        trimmed.to_string()
    } else {
        format!("\\\\.\\pipe\\{trimmed}")
    }
}

fn upstream_auth_request(
    address: &Url,
    capability: InteractiveAuthCapability,
) -> tonic::Request<pb::AuthRequest> {
    let mut request = tonic::Request::new(pb::AuthRequest {
        address: protocol::object_address_to_proto(address),
    });
    request.metadata_mut().insert(
        protocol::X_OV_IAUTH,
        protocol::capability_metadata_value(capability),
    );
    request
}

#[async_trait::async_trait]
impl BrokerClientTransport for TonicBrokerClient {
    async fn list_address_roots(&self) -> Result<Vec<AddressRoot>> {
        let mut client = self.connect().await?;
        let response = client
            .list_address_roots(pb::ListAddressRootsRequest {})
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        response
            .roots
            .into_iter()
            .map(protocol::address_root_from_proto)
            .collect()
    }

    async fn watch_address_roots(
        &self,
    ) -> Result<ovstorage_broker_protocol::AddressRootsChangeStream> {
        use futures::StreamExt;
        let mut client = self.connect().await?;
        let response = client
            .watch_address_roots(pb::WatchAddressRootsRequest {})
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        // tonic `Status` -> stream item `Err`; proto decode failures
        // (missing oneof variant) become `Unsupported`.
        let stream = response.map(|frame| match frame {
            Ok(change) => protocol::address_roots_change_from_proto(change),
            Err(status) => Err(protocol::status_to_error(status)),
        });
        Ok(Box::pin(stream))
    }

    async fn stat(&self, address: Url, options: StatOptions) -> Result<ObjectInfo> {
        let mut client = self.connect().await?;
        let response = client
            .stat(pb::StatRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::stat_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        protocol::object_info_from_proto(response.info)
    }

    async fn read(&self, address: Url, options: ReadOptions) -> Result<ReadResult> {
        let mut client = self.connect().await?;
        let mut stream = client
            .read(pb::ReadRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::read_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        let Some(response) = stream.message().await.map_err(protocol::status_to_error)? else {
            return Err(Error::new(
                ErrorCode::BrokerUnavailable,
                "broker read stream ended before returning a result",
            ));
        };
        // First frame must be `info` (alone, then body..., or then redirect)
        // or a standalone `redirect`. Anything else is a protocol violation.
        match response.result.ok_or_else(|| {
            Error::new(
                ErrorCode::BrokerUnavailable,
                "broker read response is empty",
            )
        })? {
            pb::read_response::Result::Info(info) => {
                // `info, redirect` is an allowed sequence: peek the second
                // frame; on `Redirect` (no body), surface `ReadResult::Redirect`
                // so the host follows the pre-signed origin URL. Otherwise
                // build the body stream prepending the first chunk pulled.
                let info = protocol::object_info_from_proto(Some(info))?;
                let second = stream.message().await.map_err(protocol::status_to_error)?;
                match second.and_then(|m| m.result) {
                    Some(pb::read_response::Result::Redirect(redirect)) => {
                        protocol::read_redirect_from_proto(redirect).map(ReadResult::Redirect)
                    }
                    Some(pb::read_response::Result::Body(chunk)) => {
                        let read_stream = grpc_read_stream_with_initial_body(stream, chunk);
                        Ok(ReadResult::Stream {
                            stream: read_stream,
                            info,
                        })
                    }
                    Some(pb::read_response::Result::Info(_)) => Err(Error::new(
                        ErrorCode::Internal,
                        "protocol violation: broker emitted info after info",
                    )),
                    None => Ok(ReadResult::Stream {
                        stream: empty_read_stream(),
                        info,
                    }),
                }
            }
            pb::read_response::Result::Redirect(redirect) => {
                protocol::read_redirect_from_proto(redirect).map(ReadResult::Redirect)
            }
            pb::read_response::Result::Body(_) => Err(Error::new(
                ErrorCode::Internal,
                "protocol violation: broker emitted body before info",
            )),
        }
    }

    async fn write(&self, address: Url, body: Body, options: WriteOptions) -> Result<WriteStep> {
        let chunk_iter = protocol::body_to_chunk_iter(body)?;
        let open_request = pb::WriteRequest {
            step: Some(pb::write_request::Step::Open(pb::WriteOpen {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::write_options_to_proto(&options)),
            })),
        };
        // A chunk-pull error must propagate as gRPC RST_STREAM(CANCEL),
        // not graceful EOF on the request half — a graceful EOF would
        // tell the broker to commit whatever bytes it has buffered.
        // The pump task holds the channel sender alive after capturing
        // an error (`pending()`), keeping the request half open until
        // the coordinator drops the response handle (triggering
        // RST_STREAM) so the server sees `Err(Cancelled)` instead of
        // `Ok(None)`.
        let captured_error: Arc<Mutex<Option<Error>>> = Arc::new(Mutex::new(None));
        let captured_for_pump = captured_error.clone();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let cancel_signal = Arc::new(Mutex::new(Some(cancel_tx)));
        let cancel_for_pump = cancel_signal.clone();
        let (request_tx, request_rx) = tokio::sync::mpsc::channel::<pb::WriteRequest>(4);
        request_tx
            .send(open_request)
            .await
            .map_err(|_| Error::new(ErrorCode::Internal, "broker write request channel closed"))?;
        tokio::spawn(async move {
            let mut chunks = chunk_iter;
            loop {
                let item = chunks.next();
                match item {
                    Some(Ok(bytes)) => {
                        if request_tx
                            .send(pb::WriteRequest {
                                step: Some(pb::write_request::Step::Chunk(bytes)),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    Some(Err(err)) => {
                        if let Ok(mut slot) = captured_for_pump.lock() {
                            *slot = Some(err);
                        }
                        if let Ok(mut slot) = cancel_for_pump.lock()
                            && let Some(tx) = slot.take()
                        {
                            let _ = tx.send(());
                        }
                        // Hold the sender so tonic does not see a graceful
                        // half-close before the coordinator can RST_STREAM.
                        std::future::pending::<()>().await;
                        drop(request_tx);
                        return;
                    }
                    None => return,
                }
            }
        });
        let request_stream = tokio_stream::wrappers::ReceiverStream::new(request_rx);
        let mut client = self.connect().await?;
        // Race the RPC future against cancel_rx: a bidirectional streaming
        // RPC's response future does not resolve until the server's handler
        // returns, so if the pump captures a chunk error mid-stream the
        // server is blocked waiting for the next chunk and the future hangs.
        // Dropping the future on cancel propagates RST_STREAM(CANCEL) via
        // tonic's underlying HTTP/2 stream, which the server sees as
        // `Err(status.code() == Cancelled)`.
        let mut cancel_rx = cancel_rx;
        let mut response_result = std::pin::pin!(client.write(request_stream));
        let response_result = tokio::select! {
            biased;
            _ = &mut cancel_rx => {
                if let Some(err) = captured_error.lock().ok().and_then(|mut g| g.take()) {
                    return Err(err);
                }
                return Err(Error::new(
                    ErrorCode::Cancelled,
                    "broker write cancelled by chunk-pull error",
                ));
            }
            res = &mut response_result => res,
        };
        if let Some(err) = captured_error.lock().ok().and_then(|mut g| g.take()) {
            return Err(err);
        }
        let mut responses = response_result
            .map_err(protocol::status_to_error)?
            .into_inner();
        let response = tokio::select! {
            biased;
            _ = &mut cancel_rx => {
                drop(responses);
                if let Some(err) = captured_error.lock().ok().and_then(|mut g| g.take()) {
                    return Err(err);
                }
                return Err(Error::new(
                    ErrorCode::Cancelled,
                    "broker write cancelled by chunk-pull error",
                ));
            }
            msg = responses.message() => msg.map_err(protocol::status_to_error)?,
        };
        let Some(response) = response else {
            if let Some(err) = captured_error.lock().ok().and_then(|mut g| g.take()) {
                return Err(err);
            }
            return Err(Error::new(
                ErrorCode::BrokerUnavailable,
                "broker write stream ended before returning a result",
            ));
        };
        match response.step.ok_or_else(|| {
            Error::new(
                ErrorCode::BrokerUnavailable,
                "broker write response is empty",
            )
        })? {
            pb::write_response::Step::Done(result) => {
                protocol::write_result_from_proto(Some(result)).map(WriteStep::Done)
            }
            pb::write_response::Step::Redirects(batch) => {
                protocol::write_redirect_batch_from_proto(Some(batch)).map(WriteStep::Redirects)
            }
            pb::write_response::Step::AcceptUpload(_) => Err(Error::new(
                ErrorCode::Unsupported,
                "broker requested client streaming upload without a final write result",
            )),
        }
    }

    async fn write_redirect(
        &self,
        address: Url,
        options: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        let mut client = self.connect().await?;
        let response = client
            .write_redirect(pb::WriteRedirectRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::write_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        protocol::write_redirect_batch_from_proto(response.redirects)
    }

    async fn continue_write(
        &self,
        address: Url,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
    ) -> Result<WriteStep> {
        validate_redirect_results(&redirects, &results)?;
        let mut client = self.connect().await?;
        let response = client
            .continue_write(pb::ContinueWriteRequest {
                address: protocol::object_address_to_proto(&address),
                redirects: Some(protocol::write_redirect_batch_to_proto(&redirects)),
                results: Some(protocol::redirect_result_batch_to_proto(&results)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        match response.step.ok_or_else(|| {
            Error::new(
                ErrorCode::BrokerUnavailable,
                "broker continue_write response is empty",
            )
        })? {
            pb::continue_write_response::Step::Redirects(batch) => {
                protocol::write_redirect_batch_from_proto(Some(batch)).map(WriteStep::Redirects)
            }
            pb::continue_write_response::Step::Done(result) => {
                protocol::write_result_from_proto(Some(result)).map(WriteStep::Done)
            }
        }
    }

    async fn delete(&self, address: Url, options: DeleteOptions) -> Result<()> {
        let mut client = self.connect().await?;
        client
            .delete(pb::DeleteRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::delete_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?;
        Ok(())
    }

    async fn list(&self, prefix: Url, options: ListOptions) -> Result<ListPage> {
        let mut client = self.connect().await?;
        let response = client
            .list(pb::ListRequest {
                prefix: protocol::object_address_to_proto(&prefix),
                options: Some(protocol::list_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        protocol::list_page_from_proto(response.page)
    }

    async fn list_versions(
        &self,
        address: Url,
        options: ListVersionsOptions,
    ) -> Result<Vec<ObjectInfo>> {
        let mut client = self.connect().await?;
        let response = client
            .list_versions(pb::ListVersionsRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::list_versions_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        response
            .items
            .into_iter()
            .map(|info| protocol::object_info_from_proto(Some(info)))
            .collect()
    }

    async fn get_latest_version(&self, address: Url) -> Result<ObjectInfo> {
        let mut client = self.connect().await?;
        let response = client
            .get_latest_version(pb::GetLatestVersionRequest {
                address: protocol::object_address_to_proto(&address),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        let version = response.version.ok_or_else(|| {
            ovstorage_plugin::Error::new(
                ovstorage_plugin::ErrorCode::Internal,
                "broker GetLatestVersion response missing version field",
            )
        })?;
        protocol::object_info_from_proto(Some(version))
    }

    async fn watch_directory(
        &self,
        prefix: Url,
        opts: WatchDirectoryOptions,
    ) -> Result<BrokerClientWatchDirectoryStream> {
        let endpoint = self.endpoint.clone();
        let auth_state = self.auth_state.clone();
        let (sender, receiver) = mpsc::channel();
        // Cancel is shared with the returned iterator's Drop guard: when
        // the host drops the iterator, the bridge thread leaves plugin
        // code before the host can unload this cdylib.
        let cancel = CancellationToken::new();
        let bridge_cancel = cancel.clone();
        // Watch is a sync-Iterator FFI surface; the host drains via
        // blocking `recv`. `tokio::spawn` onto the plugin's runtime would
        // deadlock a single-thread test runtime whose only worker is the
        // thread now blocked on `recv`. Use a dedicated `std::thread` +
        // per-bridge `Runtime` until the watch surface itself goes async.
        let join = std::thread::Builder::new()
            .name("ovs-bc-watch".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Runtime::new() else {
                    let _ = sender.send(Err(Error::new(
                        ErrorCode::BrokerUnavailable,
                        "failed to create broker watch_directory runtime",
                    )));
                    return;
                };
                runtime.block_on(async move {
                    let client = TonicBrokerClient::new(endpoint).with_auth_state(auth_state);
                    let event_sender = sender.clone();
                    let cancel_before_open = bridge_cancel.clone();
                    let result = tokio::select! {
                        biased;
                        _ = cancel_before_open.cancelled() => Ok(()),
                        result = async move {
                            let mut grpc = client.connect().await?;
                            let mut stream = grpc
                                .watch_directory(protocol::watch_directory_request_to_proto(
                                    &prefix, &opts,
                                ))
                                .await
                                .map_err(protocol::status_to_error)?
                                .into_inner();
                            loop {
                                tokio::select! {
                                    biased;
                                    _ = bridge_cancel.cancelled() => break,
                                    msg = stream.message() => {
                                        match msg.map_err(protocol::status_to_error)? {
                                            Some(response) => {
                                                let event = protocol::change_event_from_proto(response.event)?;
                                                if event_sender.send(Ok(event)).is_err() {
                                                    break;
                                                }
                                            }
                                            None => break,
                                        }
                                    }
                                }
                            }
                            Ok::<(), Error>(())
                        } => result,
                    };
                    if let Err(error) = result {
                        let _ = sender.send(Err(error));
                    }
                });
            })
            .expect("failed to spawn thread");
        Ok(Box::new(BrokerWatchDirectoryStream {
            receiver: receiver.into_iter(),
            cancel,
            join: Some(join),
        }))
    }

    async fn create_directory(
        &self,
        address: Url,
        options: CreateDirectoryOptions,
    ) -> Result<ObjectInfo> {
        let mut client = self.connect().await?;
        let response = client
            .create_directory(pb::CreateDirectoryRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::create_directory_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        protocol::object_info_from_proto(response.info)
    }

    async fn delete_directory(&self, address: Url, options: DeleteDirectoryOptions) -> Result<()> {
        let mut client = self.connect().await?;
        client
            .delete_directory(pb::DeleteDirectoryRequest {
                address: protocol::object_address_to_proto(&address),
                options: Some(protocol::delete_directory_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?;
        Ok(())
    }

    async fn copy(
        &self,
        source: Url,
        destination: Url,
        options: CopyOptions,
    ) -> Result<WriteResult> {
        let mut client = self.connect().await?;
        let response = client
            .copy(pb::CopyRequest {
                source: protocol::object_address_to_proto(&source),
                destination: protocol::object_address_to_proto(&destination),
                options: Some(protocol::copy_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        protocol::write_result_from_proto(response.result)
    }

    async fn rename(&self, source: Url, destination: Url, options: RenameOptions) -> Result<()> {
        let mut client = self.connect().await?;
        client
            .rename(pb::RenameRequest {
                source: protocol::object_address_to_proto(&source),
                destination: protocol::object_address_to_proto(&destination),
                options: Some(protocol::rename_options_to_proto(&options)),
            })
            .await
            .map_err(protocol::status_to_error)?;
        Ok(())
    }

    async fn update_metadata(
        &self,
        address: Url,
        options: UpdateMetadataOptions,
    ) -> Result<ObjectInfo> {
        let mut client = self.connect().await?;
        let response = client
            .update_metadata(pb::UpdateMetadataRequest {
                address: protocol::object_address_to_proto(&address),
                user_metadata_set: options.user_metadata_set,
                user_metadata_remove: options.user_metadata_remove,
                if_match: options.if_match.clone(),
                allow_rewrite_emulation: options.allow_rewrite_emulation,
                message: options.message,
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        protocol::object_info_from_proto(response.info)
    }

    async fn check_access(&self, address: Url, operations: AccessOps) -> Result<AccessDecision> {
        let mut client = self.connect().await?;
        let response = client
            .check_access(pb::CheckAccessRequest {
                address: protocol::object_address_to_proto(&address),
                operations: Some(protocol::access_ops_to_proto(&operations)),
            })
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        Ok(protocol::access_decision_from_proto(response.decision))
    }

    async fn auth_stream(
        &self,
        address: Url,
        capability: InteractiveAuthCapability,
    ) -> Result<ovstorage_broker_protocol::UpstreamAuthStream> {
        use futures::StreamExt;
        let mut client = self.connect().await?;
        let request = upstream_auth_request(&address, capability);
        let response = client
            .auth(request)
            .await
            .map_err(protocol::status_to_error)?
            .into_inner();
        let stream = response.map(|frame| match frame {
            Ok(envelope) => protocol::auth_event_from_proto_partial(envelope),
            Err(status) => Err(protocol::status_to_error(status)),
        });
        Ok(Box::pin(stream))
    }

    async fn register_credential(
        &self,
        address: Url,
        payload: ovstorage_broker_protocol::RegisterCredentialPayload,
    ) -> Result<()> {
        let mut client = self.connect().await?;
        let expires_at_unix_millis = payload
            .expires_at
            .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        client
            .register_credential(pb::RegisterCredentialRequest {
                address: protocol::object_address_to_proto(&address),
                access_token: payload.access_token,
                refresh_token: payload.refresh_token.unwrap_or_default(),
                expires_at_unix_millis,
            })
            .await
            .map_err(protocol::status_to_error)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum BrokerEndpoint {
    Tcp {
        channel_uri: String,
        plaintext: bool,
    },
    UnixSocket(String),
    NamedPipe(String),
}

#[derive(Debug, Deserialize)]
struct ServicesDocument {
    /// Operator-supplied deployment label; missing or empty is a parse-time
    /// `NotConfigured` failure.
    name: String,
    services: Vec<ServiceEntry>,
}

#[derive(Debug, Deserialize)]
struct ServiceEntry {
    /// Each entry carries exactly `type` and `endpoint` (no `name`).
    #[serde(rename = "type")]
    service_type: String,
    endpoint: String,
}

/// Map a non-2xx HTTP response from `/api/v1/services` to a typed `Error`.
///
/// | Status class             | Codes          | `ErrorCode`         |
/// |--------------------------|----------------|---------------------|
/// | Auth required            | 401            | `AuthRequired`      |
/// | Permission denied        | 403            | `PermissionDenied`  |
/// | Permanent schema/deploy  | 404, 410       | `NotConfigured`     |
/// | Transient transport      | 408, 429, 5xx  | `BrokerUnavailable` |
///
/// 401 vs 403 split is deliberate: 401 lets the host invalidate creds and
/// retry; 403 is final (the authenticated principal lacks permission).
fn classify_discovery_status(
    status: reqwest::StatusCode,
    services_url: &str,
    discovery_url: &str,
) -> Error {
    use reqwest::StatusCode;
    match status {
        StatusCode::UNAUTHORIZED => Error::new(
            ErrorCode::AuthRequired,
            format!(
                "broker discovery requires authentication; \
                 auth-config at {discovery_url}/api/v1/auth-config"
            ),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("discovery_unauthorized".into()),
            expired_at: None,
        }),
        StatusCode::FORBIDDEN => Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "broker discovery at '{services_url}' returned 403 Forbidden: \
                 the authenticated principal is not permitted to enumerate \
                 broker services"
            ),
        ),
        StatusCode::NOT_FOUND | StatusCode::GONE => Error::new(
            ErrorCode::NotConfigured,
            format!(
                "broker discovery URL '{services_url}' returned {status}: \
                 endpoint is not a conformant broker"
            ),
        ),
        _ => Error::new(
            ErrorCode::BrokerUnavailable,
            format!("broker discovery request to '{services_url}' failed with status {status}"),
        ),
    }
}

/// Parse a services document and return the `ovstorage-broker` endpoint URL.
/// Schema-class failures all surface as `NotConfigured`.
fn parse_services_document(body: &[u8], services_url: &str) -> Result<String> {
    let document: ServicesDocument = serde_json::from_slice(body).map_err(|error| {
        Error::new(
            ErrorCode::NotConfigured,
            format!("broker services document from '{services_url}' is invalid: {error}"),
        )
    })?;
    tracing::trace!(
        target: "ovstorage.broker.discovery",
        url = %services_url,
        services = ?document,
        "broker: /api/v1/services response body",
    );
    if document.name.trim().is_empty() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!("broker services document from '{services_url}' has empty `name` field"),
        ));
    }
    if document.services.is_empty() {
        return Err(Error::new(
            ErrorCode::NotConfigured,
            format!("broker services document from '{services_url}' has empty `services[]`"),
        ));
    }
    document
        .services
        .into_iter()
        .find(|service| service.service_type == "ovstorage-broker")
        .map(|service| service.endpoint)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::NotConfigured,
                format!(
                    "broker services document from '{services_url}' does not include \
                     an ovstorage-broker entry"
                ),
            )
        })
}

/// Discovery redirect rule: HTTPS-initial chains MUST stay on `https://`;
/// loopback HTTP chains MUST stay on loopback HTTP; cross-scheme downgrades
/// fail.
fn discovery_redirect_allowed(initial: &url::Url, next: &url::Url) -> bool {
    let initial_scheme = initial.scheme();
    let next_scheme = next.scheme();
    match (initial_scheme, next_scheme) {
        ("https", "https") => true,
        ("http", "http") => is_loopback_authority(initial) && is_loopback_authority(next),
        _ => false,
    }
}

/// Loopback host detection for the redirect guard: `localhost`, IPv4/IPv6
/// loopback literals, and `.local` mDNS hosts.
fn is_loopback_authority(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => {
            let host = name.to_ascii_lowercase();
            host == "localhost" || host.ends_with(".local")
        }
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

/// Build a `reqwest::Client` whose redirect policy enforces the discovery
/// scheme guard, capping the chain at 5 hops and rejecting cross-scheme
/// downgrades.
fn discovery_client(initial_url: &str) -> Result<reqwest::Client> {
    let initial = url::Url::parse(initial_url).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker discovery initial URL is not a URL: {error}"),
        )
    })?;
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("broker discovery exceeded redirect chain limit (5 hops)");
        }
        if discovery_redirect_allowed(&initial, attempt.url()) {
            attempt.follow()
        } else {
            let next = attempt.url().clone();
            attempt.error(format!(
                "broker discovery refused cross-scheme redirect from '{initial}' to '{next}'",
            ))
        }
    });
    reqwest::Client::builder()
        .redirect(policy)
        .build()
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to construct broker discovery HTTP client: {error}"),
            )
        })
}

async fn fetch_discovered_broker_endpoint(discovery_url: &str) -> Result<String> {
    let services_url = format!("{discovery_url}/api/v1/services");
    let response = discovery_client(&services_url)?
        .get(&services_url)
        .send()
        .await
        .map_err(|error| {
            Error::new(
                ErrorCode::BrokerUnavailable,
                format!("failed to fetch broker services from '{services_url}': {error}"),
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(classify_discovery_status(
            status,
            &services_url,
            discovery_url,
        ));
    }
    let body = response.bytes().await.map_err(|error| {
        Error::new(
            ErrorCode::BrokerUnavailable,
            format!("failed to read broker services body from '{services_url}': {error}"),
        )
    })?;
    parse_services_document(&body, &services_url)
}

fn parse_direct_endpoint(value: &str) -> Result<Option<BrokerEndpoint>> {
    let parsed = url::Url::parse(value).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker address must be a URL: {error}"),
        )
    })?;
    match parsed.scheme() {
        "grpc" | "grpc+tcp" | "grpc+tls" | "unix" | "npipe" => {
            parse_broker_endpoint(value).map(Some)
        }
        _ => Ok(None),
    }
}

fn parse_broker_endpoint(value: &str) -> Result<BrokerEndpoint> {
    let parsed = url::Url::parse(value).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("broker endpoint must be a URL: {error}"),
        )
    })?;
    match parsed.scheme() {
        "grpc+tcp" | "http" => tcp_endpoint(&parsed, false),
        "grpc+tls" | "https" => tcp_endpoint(&parsed, true),
        "grpc" => {
            let host = parsed.host_str().unwrap_or("");
            let tls = !ovstorage::is_local_cleartext_host(host);
            tcp_endpoint(&parsed, tls)
        }
        "unix" => {
            let path = parsed.path();
            if path.is_empty() || !path.starts_with('/') {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "unix broker endpoint must include an absolute socket path; use unix:/path or unix:///path",
                ));
            }
            Ok(BrokerEndpoint::UnixSocket(path.to_string()))
        }
        "npipe" => {
            let name = parsed.host_str().unwrap_or(parsed.path()).trim_matches('/');
            if name.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "npipe broker endpoint must include a pipe name",
                ));
            }
            Ok(BrokerEndpoint::NamedPipe(name.to_string()))
        }
        other => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("unsupported broker endpoint scheme '{other}'"),
        )),
    }
}

fn has_local_direct_endpoint_scheme(value: &str) -> bool {
    value
        .split_once(':')
        .map(|(scheme, rest)| {
            rest.starts_with('/')
                && (scheme.eq_ignore_ascii_case("unix") || scheme.eq_ignore_ascii_case("npipe"))
        })
        .unwrap_or(false)
}

fn tcp_endpoint(parsed: &url::Url, tls: bool) -> Result<BrokerEndpoint> {
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "broker endpoint has no host"))?;
    if !tls && !ovstorage::is_local_cleartext_host(host) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "plaintext broker endpoints are accepted only for loopback/local use; use grpc+tls/https for remote endpoints",
        ));
    }
    let port = parsed.port_or_known_default().ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidArgument,
            "broker endpoint must include a port",
        )
    })?;
    let scheme = if tls { "https" } else { "http" };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    Ok(BrokerEndpoint::Tcp {
        channel_uri: format!("{scheme}://{host}:{port}"),
        plaintext: !tls,
    })
}

fn should_infer_http(value: &str) -> bool {
    let host = value
        .split_once('/')
        .map(|(host, _)| host)
        .unwrap_or(value)
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(value)
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(value)
        .trim_matches(['[', ']']);
    ovstorage::is_local_cleartext_host(host)
}

/// Bridge the post-`info` body cursor into [`ovstorage::ReadStream`],
/// optionally prepending an `initial` chunk pulled while peeking for an
/// `info, redirect` sequence. Only `body(_)` frames are valid past this
/// point; stray `info`/`redirect`/`None` is a protocol violation.
fn grpc_read_stream_with_initial_body(
    grpc_stream: tonic::Streaming<pb::ReadResponse>,
    initial: Vec<u8>,
) -> ovstorage::ReadStream {
    let stream = async_stream::stream! {
        if !initial.is_empty() {
            yield Ok(bytes::Bytes::from(initial));
        }
        let mut grpc_stream = grpc_stream;
        loop {
            match grpc_stream.message().await {
                Ok(Some(message)) => match message.result {
                    Some(pb::read_response::Result::Body(chunk)) => {
                        yield Ok(bytes::Bytes::from(chunk));
                    }
                    Some(pb::read_response::Result::Info(_)) => {
                        yield Err(Error::new(
                            ErrorCode::Internal,
                            "protocol violation: broker emitted info after info",
                        ));
                        return;
                    }
                    Some(pb::read_response::Result::Redirect(_)) => {
                        yield Err(Error::new(
                            ErrorCode::Internal,
                            "protocol violation: broker emitted redirect after body",
                        ));
                        return;
                    }
                    None => return,
                },
                Ok(None) => return,
                Err(status) => {
                    yield Err(protocol::status_to_error(status));
                    return;
                }
            }
        }
    };
    Box::pin(stream)
}

/// Empty `ReadStream` for zero-byte `info`-only responses.
fn empty_read_stream() -> ovstorage::ReadStream {
    Box::pin(async_stream::stream! {
        if false {
            yield Ok(bytes::Bytes::new());
        }
    })
}

fn backend_item_info(info: ObjectInfo) -> BackendItemInfo {
    BackendItemInfo {
        kind: info.kind,
        etag: info.etag,
        version: info.version,
        size: info.size,
        mtime: info.mtime,
        checksums: info.checksums,
        effective_permissions: info.effective_permissions,
        system_metadata: info.system_metadata,
        user_metadata: info.user_metadata,
        modified_by: info.modified_by,
    }
}

fn broker_watch_directory_event_to_backend(event: ChangeEvent) -> BackendChangeEvent {
    match event {
        ChangeEvent::Object {
            address,
            kind,
            etag,
            // The broker wire carries version/size/mtime alongside the
            // etag (see `ObjectChange` in broker.proto); pass them
            // through verbatim. The upstream plugin's notification
            // surface decides which of these are populated.
            version,
            size,
            mtime,
            at,
            cursor,
        } => BackendChangeEvent::Object {
            address,
            kind,
            etag,
            version,
            size,
            mtime,
            at,
            cursor,
        },
        ChangeEvent::Lapsed { since, cursor } => BackendChangeEvent::Lapsed { since, cursor },
    }
}

ovstorage_plugin::ovstorage_layer_plugin!(backend, layer::BrokerClientLayerFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    #[test]
    fn broker_watch_directory_stream_drop_cancels_and_joins_bridge_thread() {
        let (sender, receiver) = mpsc::channel::<Result<ChangeEvent>>();
        drop(sender);
        let cancel = CancellationToken::new();
        let cancel_for_thread = cancel.clone();
        let joined = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let joined_for_thread = joined.clone();
        let join = std::thread::Builder::new()
            .name("ovs-bc-watch".into())
            .spawn(move || {
                while !cancel_for_thread.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                joined_for_thread.store(true, std::sync::atomic::Ordering::SeqCst);
            })
            .expect("failed to spawn thread");

        {
            let _stream = BrokerWatchDirectoryStream {
                receiver: receiver.into_iter(),
                cancel,
                join: Some(join),
            };
        }

        assert!(joined.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn descriptor_exposes_broker_kind() {
        let descriptor = crate::layer::broker_descriptor();
        assert_eq!(descriptor.kind, "broker");
        assert!(descriptor.supports_runtime_add);
        assert!(
            descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "address")
        );
        assert!(
            !descriptor
                .config_schema
                .iter()
                .any(|field| field.key == "prefix")
        );
    }

    #[test]
    fn upstream_auth_request_stamps_the_selected_capability() {
        let address = Url::parse("gs://bucket/private/object.usd").unwrap();
        for capability in [
            InteractiveAuthCapability::None,
            InteractiveAuthCapability::Headless,
        ] {
            let request = upstream_auth_request(&address, capability);
            assert_eq!(
                protocol::capability_from_metadata(request.metadata()),
                capability,
            );
            assert_eq!(request.get_ref().address, address.as_str());
        }
    }

    #[test]
    fn discovery_url_normalization_infers_local_http_and_remote_https() {
        assert_eq!(
            normalize_discovery_url("localhost:8787/").unwrap(),
            "http://localhost:8787"
        );
        assert_eq!(
            normalize_discovery_url("127.0.0.1:8787/").unwrap(),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            normalize_discovery_url("broker.local:8787/").unwrap(),
            "http://broker.local:8787"
        );
        assert_eq!(
            normalize_discovery_url("broker.example.com/").unwrap(),
            "https://broker.example.com"
        );
    }

    #[test]
    fn address_normalization_accepts_bare_paths_and_pipe_shorthand() {
        assert_eq!(
            normalize_discovery_url("/tmp/ovstorage.sock").unwrap(),
            "unix:/tmp/ovstorage.sock"
        );
        assert_eq!(
            normalize_discovery_url("pipe:ovstorage-test").unwrap(),
            "npipe:/ovstorage-test"
        );
    }

    #[test]
    fn address_normalization_rejects_empty_and_pipe_without_name() {
        assert!(normalize_discovery_url("").is_err());
        assert!(normalize_discovery_url("   ").is_err());
        assert!(normalize_discovery_url("pipe:").is_err());
    }

    #[test]
    fn connection_auth_block_rejects_both_fields() {
        let mut config = std::collections::HashMap::new();
        config.insert(
            "auth".into(),
            ConfigValue::Toml(
                "[auth]\ntoken_file = \"/tmp/t\"\nclient_secret_file = \"/tmp/s\"\n".into(),
            ),
        );
        let err = ConnectionAuthBlock::parse(&config).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn connection_auth_block_validates_against_address_scheme() {
        let token_only = ConnectionAuthBlock {
            token_file: Some("/tmp/t".into()),
            client_secret_file: None,
        };
        // token_file must be direct mode.
        assert!(
            token_only
                .validate_against_address("https://broker.example.com")
                .is_err()
        );
        assert!(
            token_only
                .validate_against_address("grpc+tls://broker:443")
                .is_ok()
        );
        assert!(
            token_only
                .validate_against_address("unix:/tmp/sock")
                .is_ok()
        );

        let secret_only = ConnectionAuthBlock {
            token_file: None,
            client_secret_file: Some("/tmp/s".into()),
        };
        // client_secret_file must be discovery mode.
        assert!(
            secret_only
                .validate_against_address("grpc+tls://broker:443")
                .is_err()
        );
        assert!(
            secret_only
                .validate_against_address("https://broker.example.com")
                .is_ok()
        );
    }

    #[test]
    fn connection_auth_block_parses_nested_or_flat_toml() {
        let mut config = std::collections::HashMap::new();
        config.insert(
            "auth".into(),
            ConfigValue::Toml("[auth]\ntoken_file = \"/var/run/secrets/sa-token\"\n".into()),
        );
        let block = ConnectionAuthBlock::parse(&config).unwrap().unwrap();
        assert_eq!(
            block.token_file.as_deref(),
            Some("/var/run/secrets/sa-token")
        );
        assert!(block.client_secret_file.is_none());
    }

    #[test]
    fn grpc_scheme_auto_selects_tls_by_host() {
        // grpc:// resolves to plaintext for local hosts, TLS for remote.
        let local = parse_broker_endpoint("grpc://127.0.0.1:8787").unwrap();
        assert!(matches!(
            local,
            BrokerEndpoint::Tcp {
                plaintext: true,
                ..
            }
        ));
        let remote = parse_broker_endpoint("grpc://broker.example.com:8443").unwrap();
        assert!(matches!(
            remote,
            BrokerEndpoint::Tcp {
                plaintext: false,
                ..
            }
        ));
    }

    #[test]
    fn discovery_url_normalization_preserves_local_direct_endpoint_schemes() {
        assert_eq!(
            normalize_discovery_url("unix:/tmp/ovstorage.sock").unwrap(),
            "unix:/tmp/ovstorage.sock"
        );
        assert_eq!(
            normalize_discovery_url("unix:///tmp/ovstorage.sock").unwrap(),
            "unix:///tmp/ovstorage.sock"
        );
        assert_eq!(
            normalize_discovery_url("npipe:/ovstorage-test").unwrap(),
            "npipe:/ovstorage-test"
        );
        assert_eq!(
            normalize_discovery_url("npipe:///ovstorage-test").unwrap(),
            "npipe:///ovstorage-test"
        );
    }

    #[test]
    fn broker_endpoint_parsing_accepts_grpc_aliases_and_rejects_remote_plaintext() {
        assert!(parse_broker_endpoint("grpc+tcp://127.0.0.1:4321").is_ok());
        assert!(parse_broker_endpoint("http://localhost:4321").is_ok());
        assert!(parse_broker_endpoint("grpc+tls://broker.example.com:443").is_ok());
        assert!(parse_broker_endpoint("https://broker.example.com:443").is_ok());
        assert!(parse_broker_endpoint("grpc+tcp://broker.example.com:4321").is_err());
    }

    #[test]
    fn broker_endpoint_parsing_accepts_single_and_triple_slash_local_schemes() {
        assert_eq!(
            parse_broker_endpoint("unix:/tmp/ovstorage.sock").unwrap(),
            BrokerEndpoint::UnixSocket("/tmp/ovstorage.sock".into())
        );
        assert_eq!(
            parse_broker_endpoint("unix:///tmp/ovstorage.sock").unwrap(),
            BrokerEndpoint::UnixSocket("/tmp/ovstorage.sock".into())
        );
        assert_eq!(
            parse_broker_endpoint("npipe:/ovstorage-test").unwrap(),
            BrokerEndpoint::NamedPipe("ovstorage-test".into())
        );
        assert_eq!(
            parse_broker_endpoint("npipe:///ovstorage-test").unwrap(),
            BrokerEndpoint::NamedPipe("ovstorage-test".into())
        );
    }

    #[test]
    fn direct_endpoint_detection_keeps_http_urls_as_discovery_bases() {
        assert!(
            parse_direct_endpoint("grpc+tcp://127.0.0.1:4321")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_direct_endpoint("grpc+tls://broker.example.com:443")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_direct_endpoint("http://localhost:4321")
                .unwrap()
                .is_none()
        );
        assert!(
            parse_direct_endpoint("https://broker.example.com:443")
                .unwrap()
                .is_none()
        );
        assert!(
            parse_direct_endpoint("unix:/tmp/ovstorage.sock")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_direct_endpoint("unix:///tmp/ovstorage.sock")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_direct_endpoint("npipe:/ovstorage-test")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_direct_endpoint("npipe:///ovstorage-test")
                .unwrap()
                .is_some()
        );
    }

    // Discovery status mapping:
    // 401 -> AuthRequired, 403 -> PermissionDenied,
    // 404/410 -> NotConfigured, 408/429/5xx -> BrokerUnavailable,
    // schema/parse -> NotConfigured.

    use reqwest::StatusCode;

    #[test]
    fn classify_401_surfaces_auth_required() {
        let err = classify_discovery_status(
            StatusCode::UNAUTHORIZED,
            "https://broker.example.com/api/v1/services",
            "https://broker.example.com",
        );
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        assert!(
            err.message().contains("auth-config"),
            "expected message to mention auth-config; got: {}",
            err.message()
        );
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("discovery_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn classify_403_surfaces_permission_denied() {
        let err = classify_discovery_status(
            StatusCode::FORBIDDEN,
            "https://broker.example.com/api/v1/services",
            "https://broker.example.com",
        );
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(
            err.message().contains("403"),
            "expected message to mention 403; got: {}",
            err.message()
        );
        assert!(
            err.context().is_none(),
            "403 must not carry Auth context; got: {:?}",
            err.context()
        );
    }

    #[test]
    fn classify_404_410_surfaces_not_configured() {
        for status in [StatusCode::NOT_FOUND, StatusCode::GONE] {
            let err = classify_discovery_status(
                status,
                "https://broker.example.com/api/v1/services",
                "https://broker.example.com",
            );
            assert_eq!(err.code(), ErrorCode::NotConfigured);
        }
    }

    #[test]
    fn classify_transient_statuses_surface_broker_unavailable() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            let err = classify_discovery_status(
                status,
                "https://broker.example.com/api/v1/services",
                "https://broker.example.com",
            );
            assert_eq!(
                err.code(),
                ErrorCode::BrokerUnavailable,
                "status {status} should map to BrokerUnavailable"
            );
        }
    }

    #[test]
    fn parse_services_document_accepts_well_formed() {
        let body = br#"{
            "name": "Acme Production",
            "services": [
                {"type": "ovstorage-broker", "endpoint": "grpc+tls://broker.example.com:443"},
                {"type": "ovstorage-rest", "endpoint": "https://rest.example.com/v1"}
            ]
        }"#;
        let endpoint =
            parse_services_document(body, "https://broker.example.com/api/v1/services").unwrap();
        assert_eq!(endpoint, "grpc+tls://broker.example.com:443");
    }

    #[test]
    fn parse_services_document_rejects_missing_name() {
        let body = br#"{
            "services": [{"type": "ovstorage-broker", "endpoint": "grpc+tls://b.example.com"}]
        }"#;
        let err = parse_services_document(body, "https://broker.example.com/api/v1/services")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn parse_services_document_rejects_empty_name() {
        let body = br#"{
            "name": "  ",
            "services": [{"type": "ovstorage-broker", "endpoint": "grpc+tls://b.example.com"}]
        }"#;
        let err = parse_services_document(body, "https://broker.example.com/api/v1/services")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("name"));
    }

    #[test]
    fn parse_services_document_rejects_empty_services_array() {
        let body = br#"{"name": "Acme Prod", "services": []}"#;
        let err = parse_services_document(body, "https://broker.example.com/api/v1/services")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("services"));
    }

    #[test]
    fn parse_services_document_rejects_missing_broker_entry() {
        let body = br#"{
            "name": "Acme Prod",
            "services": [{"type": "ovstorage-rest", "endpoint": "https://rest.example.com"}]
        }"#;
        let err = parse_services_document(body, "https://broker.example.com/api/v1/services")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
        assert!(err.message().contains("ovstorage-broker"));
    }

    #[test]
    fn parse_services_document_rejects_malformed_json() {
        let body = b"not json at all";
        let err = parse_services_document(body, "https://broker.example.com/api/v1/services")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    fn parse(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn redirect_https_to_https_is_allowed() {
        assert!(discovery_redirect_allowed(
            &parse("https://broker.example.com/api/v1/services"),
            &parse("https://canonical.example.com/api/v1/services"),
        ));
    }

    #[test]
    fn redirect_https_to_http_is_blocked() {
        assert!(!discovery_redirect_allowed(
            &parse("https://broker.example.com/api/v1/services"),
            &parse("http://broker.example.com/api/v1/services"),
        ));
        assert!(!discovery_redirect_allowed(
            &parse("https://broker.example.com"),
            &parse("http://localhost:8787"),
        ));
    }

    #[test]
    fn redirect_loopback_http_to_loopback_http_is_allowed() {
        assert!(discovery_redirect_allowed(
            &parse("http://localhost:8787/api/v1/services"),
            &parse("http://127.0.0.1:9090/api/v1/services"),
        ));
        assert!(discovery_redirect_allowed(
            &parse("http://localhost"),
            &parse("http://[::1]:8787"),
        ));
    }

    #[test]
    fn redirect_loopback_http_to_remote_http_is_blocked() {
        assert!(!discovery_redirect_allowed(
            &parse("http://localhost:8787"),
            &parse("http://broker.example.com:8787"),
        ));
    }

    #[test]
    fn redirect_remote_http_initial_blocks_everything() {
        // Non-loopback http:// initial must not silently follow anything.
        assert!(!discovery_redirect_allowed(
            &parse("http://broker.example.com"),
            &parse("http://other.example.com"),
        ));
        assert!(!discovery_redirect_allowed(
            &parse("http://broker.example.com"),
            &parse("https://other.example.com"),
        ));
    }

    #[test]
    fn redirect_loopback_recognises_localhost_loopback_literals_and_mdns() {
        assert!(is_loopback_authority(&parse("http://localhost")));
        assert!(is_loopback_authority(&parse("http://localhost:8787")));
        assert!(is_loopback_authority(&parse("http://127.0.0.1")));
        assert!(is_loopback_authority(&parse("http://[::1]")));
        assert!(is_loopback_authority(&parse("http://broker.local")));
        assert!(!is_loopback_authority(&parse("http://broker.example.com")));
        assert!(!is_loopback_authority(&parse("http://10.0.0.1")));
    }

    #[test]
    fn discovery_client_builds_with_https_initial() {
        assert!(discovery_client("https://broker.example.com/api/v1/services").is_ok());
        assert!(discovery_client("http://localhost:8787/api/v1/services").is_ok());
    }

    #[test]
    fn discovery_client_rejects_non_url_initial() {
        let err = discovery_client("not a url").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn tonic_broker_starts_with_empty_channel_cell() {
        let client = TonicBrokerClient::new(BrokerEndpoint::Tcp {
            channel_uri: "http://127.0.0.1:1".into(),
            plaintext: true,
        });
        assert!(
            client.client.get().is_none(),
            "channel cell must start empty"
        );
        // Clones share the same Arc<OnceCell>: one channel per logical
        // client, not per `.clone()`.
        let cloned = client.clone();
        assert!(Arc::ptr_eq(&client.client, &cloned.client));
    }

    #[tokio::test]
    async fn backend_transport_cell_starts_empty() {
        let backend = BrokerClientBackend {
            discovery_url: "https://broker.example.com".into(),
            transport: tokio::sync::OnceCell::new(),
            auth_state: DiscoveryState::new("default"),
        };
        assert!(
            backend.transport.get().is_none(),
            "backend transport cell must start empty"
        );
    }

    #[tokio::test]
    async fn backend_transport_cache_reuses_set_value() {
        let backend = BrokerClientBackend {
            discovery_url: "https://broker.example.com".into(),
            transport: tokio::sync::OnceCell::new(),
            auth_state: DiscoveryState::new("default"),
        };
        let initial: Arc<dyn BrokerClientTransport> =
            Arc::new(TonicBrokerClient::new(BrokerEndpoint::Tcp {
                channel_uri: "http://127.0.0.1:1".into(),
                plaintext: true,
            }));
        if backend.transport.set(initial.clone()).is_err() {
            panic!("cell unexpectedly populated");
        }

        for _ in 0..10 {
            let t = backend.transport().await.unwrap();
            assert!(Arc::ptr_eq(&t, &initial), "transport Arc should be cached");
            std::mem::drop(t.list_address_roots());
        }
    }

    /// T2 (3539858355): the broker keys its keyring entries by origin + OIDC
    /// client identity, so two connections to the same discovery URL under
    /// different clients get DISTINCT entries — B's persist can't clobber A's
    /// token, and A's warm-continue reads A's token, not B's. Pins the
    /// derivation the write (`update_credentials`) and read (`authenticate`)
    /// paths share.
    #[test]
    fn broker_keyring_key_is_scoped_by_client() {
        let url = "https://broker.example.com/discovery";
        let a = ovstorage_plugin::oauth_secret_store::conn_id_from_url_and_client(url, "client-a");
        let b = ovstorage_plugin::oauth_secret_store::conn_id_from_url_and_client(url, "client-b");
        assert_ne!(
            a.0, b.0,
            "same URL, different client must not share a stored secret",
        );
        // The write and read paths derive the same key for the same (url, client).
        assert_eq!(
            a.0,
            ovstorage_plugin::oauth_secret_store::conn_id_from_url_and_client(url, "client-a").0,
        );
    }
}
