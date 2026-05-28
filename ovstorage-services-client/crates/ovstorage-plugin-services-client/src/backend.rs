// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `Backend` impl: maps ovstorage SPI calls to Omniverse Storage Service gRPC RPCs.

use std::pin::Pin;

use bytes::Bytes;
use futures::{Stream, StreamExt};
use ovstorage_plugin::shim;
use ovstorage_plugin::{
    AccessDecision, AccessOps, AddressRoot, AddressRootsChange, AddressVisibility,
    BackendAddressRootsStream, BackendChangeEvent, BackendChangeStream, BackendItemInfo, Body,
    BodyStream, Capabilities, ChangeKind, ChecksumSet, ConnectionId, CopyOptions,
    CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, ErrorContext,
    HttpRequest, IfDestExists, ListOptions, ListVersionsOptions, ObjectInfo, ObjectKind,
    ReadOptions, ReadRedirect, ReadResult, RedirectBodySource, RedirectResultBatch, RedirectScope,
    RenameOptions, ResolvedTarget, ResponseParsing, Result, ResultCapture, RouteSource,
    StatOptions, SystemMetadata, UpdateMetadataOptions, UserMetadata, WatchDirectoryCursor,
    WatchDirectoryOptions, WriteOptions, WriteRedirect, WriteRedirectBatch, WriteResult, WriteStep,
    race_cancel, validate_redirect_results,
};
use ovstorage_services_protos::nvidia::omniverse::notifications::consumer::v1beta as notif;
use ovstorage_services_protos::nvidia::omniverse::storage::{
    filefolder::v1alpha as ff, fileobject::v1alpha as fo, metadata::v1alpha as md,
    versioning::v1alpha as ver,
};

use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::convert::{
    fields_from_metadata, map_status, object_info_from, require_etag_only_if_match, require_field,
    resource_identity_from,
};
use crate::multipart::{Continuation, ContinuationKind};
use crate::trace::RedactedUrl;
use crate::transport::OmniverseStorageTransport;

/// Default chunk size for streaming writes. Each chunk maps 1:1 to a gRPC
/// `WriteRequest`. Storage-core itself doesn't impose a hard cap, but the
/// 4 MiB default keeps tonic's per-message buffer modest.
const WRITE_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// User-metadata key the Omniverse Storage Service uses to publish a
/// per-object access-control list. Matches the C++ provider's
/// `kMetadataKeyAcl` at `StorageProvider.cpp:168`.
const ACL_METADATA_KEY: &str = "acl";

// SPI: opts.message stashed via the metadata service when the backend has
// no per-operation annotation slot.
const OV_MESSAGE_KEY: &str = "x-ov-message";

/// Well-known metadata keys the Omniverse Storage Service stamps on every object. Mirrors
/// `kMetadataKey*` constants at `provider_omnistorage/StorageProvider.cpp:168-173`
/// and the explicit list at `_getMetadata` (`StorageProvider.cpp:5919-5920`).
const STD_KEY_CREATED_BY: &str = "created_by";
const STD_KEY_MODIFIED_BY: &str = "modified_by";
const STD_KEY_CREATED_TIMESTAMP: &str = "created_timestamp";
const STD_KEY_MODIFIED_TIMESTAMP: &str = "modified_timestamp";

const STANDARD_METADATA_KEYS: &[&str] = &[
    STD_KEY_CREATED_BY,
    STD_KEY_MODIFIED_BY,
    STD_KEY_CREATED_TIMESTAMP,
    STD_KEY_MODIFIED_TIMESTAMP,
];

/// Output of a `full_metadata` fetch. The plugin merges these into
/// `ObjectInfo` / `BackendItemInfo` so the host's stat / list paths see
/// who-touched-what and when, paying the extra round-trip only when the
/// caller asked for it.
#[derive(Debug, Default)]
struct StandardMetadata {
    modified_by: Option<String>,
    system_metadata: SystemMetadata,
    user_metadata: UserMetadata,
}

fn config_kind() -> &'static str {
    crate::config::KIND
}

fn grant_all() -> AccessOps {
    AccessOps {
        read: true,
        write: true,
        delete: true,
        update_metadata: true,
    }
}

fn parse_standard_metadata(response: md::GetMetadataResponse) -> StandardMetadata {
    use ovstorage_services_protos::google::protobuf::value::Kind;
    let mut out = StandardMetadata::default();
    for (key, entry) in response.user_metadata {
        let value = match entry.value.as_ref().and_then(|v| v.kind.as_ref()) {
            Some(Kind::StringValue(s)) => Some(s.clone()),
            Some(Kind::NumberValue(n))
                if matches!(
                    key.as_str(),
                    STD_KEY_CREATED_TIMESTAMP | STD_KEY_MODIFIED_TIMESTAMP
                ) =>
            {
                Some(format_timestamp_seconds(*n))
            }
            Some(Kind::NumberValue(n)) => Some(n.to_string()),
            Some(Kind::BoolValue(b)) => Some(b.to_string()),
            _ => None,
        };
        let Some(value) = value else { continue };
        out.user_metadata.insert(key.clone(), value.clone());
        if key.as_str() == STD_KEY_MODIFIED_BY {
            out.modified_by = Some(value.clone());
        }
        // Stamp every recognized key into system_metadata too so callers
        // that want the raw values (or future keys we don't yet promote
        // to a typed field) still see them.
        if STANDARD_METADATA_KEYS.contains(&key.as_str()) {
            out.system_metadata.insert(key, value);
        }
    }
    out
}

/// Storage-core publishes timestamps as `NumberValue` (Unix seconds, possibly
/// fractional). The C++ client formats them via `system_clock::time_point`;
/// we hand back an ISO-8601 string so the SPI's `system_metadata` map (which
/// is `String → String`) carries something humans can reason about.
fn format_timestamp_seconds(seconds: f64) -> String {
    if seconds.is_finite() {
        let whole = seconds.trunc() as i64;
        let nanos = ((seconds.fract().abs() * 1_000_000_000.0).round()) as u32;
        if let Some(t) =
            std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(whole.max(0) as u64, nanos))
        {
            // RFC 3339-ish with seconds resolution. No external crate
            // dep; the host doesn't parse this — it's display-only.
            let secs_since_epoch = t
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return format!("{secs_since_epoch}");
        }
    }
    seconds.to_string()
}

fn merge_standard_metadata_into_object(info: &mut ObjectInfo, extra: StandardMetadata) {
    if extra.modified_by.is_some() {
        info.modified_by = extra.modified_by;
    }
    if !extra.system_metadata.is_empty() {
        match info.system_metadata.as_mut() {
            Some(existing) => existing.extend(extra.system_metadata),
            None => info.system_metadata = Some(extra.system_metadata),
        }
    }
    if !extra.user_metadata.is_empty() {
        match info.user_metadata.as_mut() {
            Some(existing) => existing.extend(extra.user_metadata),
            None => info.user_metadata = Some(extra.user_metadata),
        }
    }
}

/// Translate a `google.protobuf.Value` ACL list into a granted-op set.
/// Unknown permission tokens are ignored (logged at trace level by the
/// C++ provider too). Bad shapes (not a list, or a list of non-strings)
/// fall through to `AccessOps::default()` — granting nothing — which the
/// caller composes with the requested ops to produce a fail-closed
/// decision.
fn parse_acl_grants(value: &md::UserMetadataValue) -> AccessOps {
    use ovstorage_services_protos::google::protobuf::value::Kind;
    let mut grants = AccessOps::default();
    let list = match value.value.as_ref().and_then(|v| v.kind.as_ref()) {
        Some(Kind::ListValue(list)) => list,
        _ => return grants,
    };
    for item in &list.values {
        let permission = match item.kind.as_ref() {
            Some(Kind::StringValue(s)) => s.as_str(),
            _ => continue,
        };
        match permission {
            "read" => grants.read = true,
            "write" => {
                grants.write = true;
                grants.update_metadata = true;
            }
            "admin" => grants.delete = true,
            _ => {
                tracing::trace!(
                    target: "ovstorage.omniverse_storage_service.access",
                    permission,
                    "omniverse-storage-service: unknown ACL permission token",
                );
            }
        }
    }
    grants
}

pub struct OmniverseStorageBackend {
    discovery_url: String,
    capabilities: Capabilities,
    transport: OmniverseStorageTransport,
}

impl OmniverseStorageBackend {
    pub fn new(
        discovery_url: String,
        capabilities: Capabilities,
        transport: OmniverseStorageTransport,
    ) -> Self {
        Self {
            discovery_url,
            capabilities,
            transport,
        }
    }

    pub async fn capabilities_for_root(&self, address: &Url) -> Capabilities {
        let mut capabilities = self.capabilities.clone();
        self.apply_folder_mode_capabilities(address, &mut capabilities)
            .await;
        self.apply_optimistic_locking_capabilities(address, &mut capabilities)
            .await;
        capabilities
    }

    async fn apply_folder_mode_capabilities(&self, address: &Url, capabilities: &mut Capabilities) {
        let Ok(mut client) = self.transport.filefolder_client().await else {
            return;
        };
        let response = match client
            .get_folder_mode(ff::GetFolderModeRequest {
                folder: Some(ff::FolderAddress {
                    uri: address.to_string(),
                }),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::Unimplemented => return,
            Err(status) => {
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.backend",
                    plugin = "omniverse-storage-service",
                    address = %RedactedUrl(address),
                    error = %status,
                    "omniverse-storage-service: GetFolderMode failed; using default directory capabilities",
                );
                return;
            }
        };
        match ff::FolderMode::try_from(response.folder_mode).unwrap_or(ff::FolderMode::Unspecified)
        {
            ff::FolderMode::Native => {
                capabilities.has_real_directories = true;
                capabilities.supports_create_directory = true;
                capabilities.supports_delete_directory = true;
            }
            ff::FolderMode::Hybrid => {
                capabilities.has_real_directories = false;
                capabilities.supports_create_directory = true;
                capabilities.supports_delete_directory = true;
            }
            ff::FolderMode::NoEmpty => {
                capabilities.has_real_directories = false;
                capabilities.supports_create_directory = false;
                capabilities.supports_delete_directory = false;
            }
            ff::FolderMode::Unspecified => {}
        }
    }

    async fn apply_optimistic_locking_capabilities(
        &self,
        address: &Url,
        capabilities: &mut Capabilities,
    ) {
        let Ok(mut client) = self.transport.fileobject_client().await else {
            return;
        };
        let response = match client
            .get_optimistic_locking_support(fo::GetOptimisticLockingSupportRequest {
                resource_address: address.to_string(),
            })
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == tonic::Code::Unimplemented => return,
            Err(status) => {
                tracing::warn!(
                    target: "ovstorage.omniverse_storage_service.backend",
                    plugin = "omniverse-storage-service",
                    address = %RedactedUrl(address),
                    error = %status,
                    "omniverse-storage-service: GetOptimisticLockingSupport failed; using default precondition capabilities",
                );
                return;
            }
        };
        capabilities.supports_if_match_write = response.supports_write;
    }

    pub fn discovery_url(&self) -> &str {
        &self.discovery_url
    }

    pub fn transport(&self) -> &OmniverseStorageTransport {
        &self.transport
    }
}

#[async_trait::async_trait]
impl shim::Backend for OmniverseStorageBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.stat",
            op = "stat",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            let response = client
                .stat(fo::StatRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status)?;
            let info = require_field(response.into_inner().resource_info, "stat.resource_info")?;
            let mut object_info = object_info_from(target.resolved_address.clone(), &info);
            if opts.full_metadata
                && let Some(extra) = self.fetch_standard_metadata(&target).await?
            {
                merge_standard_metadata_into_object(&mut object_info, extra);
            }
            Ok(object_info)
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        require_etag_only_if_match(opts.if_match.as_deref())?;
        let span = tracing::debug_span!(
            "omniverse_storage_service.read",
            op = "read",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            let (object_info, body) = if let Some(expected) = opts.if_match.as_ref() {
                // ResourceIdentity.encoded_identity is the SPI etag
                // token. A caller-supplied if_match is therefore already the
                // server-side precondition identity; resolving the address
                // first would only add latency and can race the read.
                fetch_read_by_identity(&mut client, &target, expected).await?
            } else {
                fetch_read_from_address(&mut client, &target).await?
            };
            // Apply opts.range on the body. For Chunks we slice the
            // bytes the plugin is producing (servers only inline-stream
            // small objects). For Redirect we return the redirect
            // unchanged — the host injects the Range header in
            // `redirect.rs` so every plugin returning ReadResult::Redirect
            // benefits without re-implementing.
            match body {
                ReadBody::Empty => {
                    if let Some(range) = opts.range.as_ref() {
                        // start>0 against a zero-byte object is out of bounds.
                        if range.start > 0 {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "omniverse-storage-service: range start {} beyond object size 0",
                                    range.start,
                                ),
                            ));
                        }
                    }
                    let empty: Pin<
                        Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>,
                    > = Box::pin(futures::stream::empty());
                    Ok(ReadResult::Stream {
                        stream: empty,
                        info: object_info,
                    })
                }
                ReadBody::Chunks(mut stream) => {
                    if let Some(range) = opts.range.as_ref() {
                        // Buffer-then-slice. Bounded waste: the server only
                        // chooses inline streaming for small objects.
                        let mut buf: Vec<u8> = Vec::new();
                        while let Some(chunk) = stream.next().await {
                            buf.extend_from_slice(&chunk?);
                        }
                        // Validate range BEFORE slicing — otherwise an
                        // inverted (end < start) or out-of-bounds range
                        // would panic the slice and abort under the
                        // workspace's panic policy.
                        if let Some(end) = range.end_inclusive
                            && end < range.start
                        {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "omniverse-storage-service: range end_inclusive {} is less than start {}",
                                    end, range.start,
                                ),
                            ));
                        }
                        let start = range.start as usize;
                        if start > buf.len() {
                            return Err(Error::new(
                                ErrorCode::InvalidArgument,
                                format!(
                                    "omniverse-storage-service: range start {} beyond object size {}",
                                    range.start,
                                    buf.len(),
                                ),
                            ));
                        }
                        let end_exclusive = range
                            .end_inclusive
                            .map(|e| (e as usize).saturating_add(1).min(buf.len()))
                            .unwrap_or(buf.len());
                        debug_assert!(
                            end_exclusive >= start,
                            "end_exclusive >= start should be guaranteed by the inverted-range check above",
                        );
                        let slice = buf[start..end_exclusive].to_vec();
                        Ok(ReadResult::Bytes {
                            bytes: slice,
                            info: object_info,
                        })
                    } else {
                        Ok(ReadResult::Stream {
                            stream,
                            info: object_info,
                        })
                    }
                }
                ReadBody::Redirect(redirect) => {
                    Ok(ReadResult::Redirect(build_read_redirect(redirect)))
                }
            }
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let body = Body::Bytes(bytes);
            self.send_inline_write(target, body, opts).await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn write_stream(
        &self,
        target: ResolvedTarget,
        body: BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            self.send_inline_write(target, Body::Stream(body), opts)
                .await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            self.start_write_redirect(target, opts).await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.write",
            op = "write",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            self.finalize_write_redirect(target, redirects, results)
                .await
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        require_etag_only_if_match(opts.if_match.as_deref())?;
        let span = tracing::debug_span!(
            "omniverse_storage_service.delete",
            op = "delete",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            let previous_version = resource_identity_from(&opts.if_match);
            // delete is idempotent: a missing target is success (NotFound from server is mapped to Ok).
            match client
                .delete(fo::DeleteRequest {
                    resource_address: target.resolved_address.to_string(),
                    previous_version,
                })
                .await
            {
                Ok(_) => Ok(()),
                Err(status) => {
                    let err = map_status(status);
                    if err.code() == ErrorCode::NotFound {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            }
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.list",
            op = "list",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&prefix.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        // Capability `supports_recursive_list = false` (factory.rs).
        // The OvCS ListStat RPC only enumerates the immediate level,
        // so silently dropping `opts.recursive = true` would hand
        // callers a partial subtree as if it were the full result.
        // Refuse instead.
        if opts.recursive {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: recursive list is not supported by this backend \
                 (Capabilities.supports_recursive_list = false)",
            ));
        }
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.filefolder_client().await?;
            let mut stream = client
                .list_stat(ff::ListStatRequest {
                    folder: Some(ff::FolderAddress {
                        uri: prefix.resolved_address.to_string(),
                    }),
                })
                .await
                .map_err(map_status)?
                .into_inner();
            let mut items = Vec::new();
            let mut metadata_targets: Vec<(usize, String)> = Vec::new();
            while let Some(frame) = stream.message().await.map_err(map_status)? {
                for sub in frame.subfolder_addresses {
                    let address = parse_server_address(&sub.uri, "list subfolder address")?;
                    items.push(default_object_info(address, ObjectKind::Directory));
                }
                for entry in frame.entries {
                    let address =
                        parse_server_address(&entry.resource_address, "list resource address")?;
                    let info = entry
                        .resource_info
                        .as_ref()
                        .map(|info| object_info_from(address.clone(), info))
                        .unwrap_or_else(|| default_object_info(address.clone(), ObjectKind::File));
                    if opts.full_metadata {
                        metadata_targets.push((items.len(), entry.resource_address.clone()));
                    }
                    items.push(info);
                }
            }
            // Per-entry metadata fetch on `full_metadata`. Mirrors the C++
            // provider, which calls `_getMetadata` for each list entry
            // (`StorageProvider.cpp:_listStat` callback). N round-trips by
            // design — the host pays a clear cost when it asks for it, and
            // a cheap stat / list never pays.
            if opts.full_metadata {
                for (idx, address) in metadata_targets {
                    if let Some(extra) = self.fetch_standard_metadata_by_address(&address).await? {
                        merge_standard_metadata_into_object(&mut items[idx], extra);
                    }
                }
            }
            Ok(items)
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.list_versions",
            op = "list_versions",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        // EnumerateVersions has no max_results / page_token on the
        // wire, and the host does NOT paginate list_versions for the
        // plugin (unlike list). Silently dropping these knobs would
        // hand the caller every version from the start when they
        // asked for a bounded page. Refuse instead — the test plugin
        // does the same.
        if opts.max_results.is_some() || opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: list_versions does not support max_results / page_token \
                 (EnumerateVersions returns every version in one stream)",
            ));
        }
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.versioning_client().await?;
            let mut stream = client
                .enumerate_versions(ver::EnumerateVersionsRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(|status| {
                    if status.code() == tonic::Code::InvalidArgument {
                        Error::new(
                            ErrorCode::Unsupported,
                            "omniverse-storage-service: cannot list all versions from this address; \
                             the service rejected it as invalid for EnumerateVersions. \
                             Pass the unversioned resource address instead of a version resource address.",
                        )
                    } else {
                        map_status(status)
                    }
                })?
                .into_inner();
            let mut items = Vec::new();
            while let Some(frame) = stream.message().await.map_err(map_status)? {
                for v in frame.items {
                    items.push(object_info_from_version_proto(v)?);
                }
            }
            Ok(items)
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.get_latest_version",
            op = "get_latest_version",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.versioning_client().await?;
            let enumerate = client
                .enumerate_versions(ver::EnumerateVersionsRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status);
            let mut stream = match enumerate {
                Ok(response) => response.into_inner(),
                Err(err) if err.code() == ErrorCode::InvalidArgument => {
                    // Omniverse Storage Service resource addresses are opaque. A version address
                    // returned by EnumerateVersions is valid for Stat/Read,
                    // but the service rejects it as an input to
                    // EnumerateVersions. Preserve that exact address instead
                    // of trying to recognize a backend-specific URL shape.
                    let mut client = self.transport.fileobject_client().await?;
                    let response = client
                        .stat(fo::StatRequest {
                            resource_address: target.resolved_address.to_string(),
                        })
                        .await
                        .map_err(map_status)?;
                    let info =
                        require_field(response.into_inner().resource_info, "stat.resource_info")?;
                    return Ok(object_info_from(target.resolved_address.clone(), &info));
                }
                Err(err) => return Err(err),
            };
            let mut picker = LatestVersionPicker::new();
            while let Some(frame) = stream.message().await.map_err(map_status)? {
                if picker.observe_frame(frame)? {
                    break;
                }
            }
            picker.finish()
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.create_directory",
            op = "create_directory",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.filefolder_client().await?;
            client
                .create_folder(ff::CreateFolderRequest {
                    folder: Some(ff::FolderAddress {
                        uri: target.resolved_address.to_string(),
                    }),
                })
                .await
                .map_err(map_status)?;
            Ok(BackendItemInfo {
                kind: ObjectKind::Directory,
                ..Default::default()
            })
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.delete_directory",
            op = "delete_directory",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.filefolder_client().await?;
            // delete_directory is idempotent: a missing target is success.
            match client
                .delete_folder(ff::DeleteFolderRequest {
                    folder: Some(ff::FolderAddress {
                        uri: target.resolved_address.to_string(),
                    }),
                })
                .await
            {
                Ok(_) => Ok(()),
                Err(status) => {
                    let err = map_status(status);
                    if err.code() == ErrorCode::NotFound {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            }
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        require_etag_only_if_match(opts.if_source.as_deref())?;
        // The Storage API wire has no "fail if destination exists" primitive —
        // CopyRequest.previous_version is a compare-and-swap on the
        // destination's current identity, not an absence assertion.
        // Silently ignoring `IfDestExists::Fail` would clobber an
        // existing object; refuse loudly instead (matches the
        // `supports_no_overwrite_write = false` capability).
        if matches!(opts.if_dest, IfDestExists::Fail) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: copy with if_dest=Fail is not supported by this backend \
                 (Storage API wire has no fail-if-exists primitive; \
                 Capabilities.supports_no_overwrite_write = false)",
            ));
        }
        let span = tracing::debug_span!(
            "omniverse_storage_service.copy",
            op = "copy",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&src.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            // CopyRequest.source_resource_identity is required by the Storage API
            // wire. With an explicit source etag, use it directly as the
            // opaque ResourceIdentity/precondition token. Without one, Stat
            // the current source head to obtain the identity the RPC requires.
            let source_resource_identity = if let Some(etag) = opts.if_source.as_ref() {
                fo::ResourceIdentity {
                    encoded_identity: etag.clone(),
                }
            } else {
                let stat = client
                    .stat(fo::StatRequest {
                        resource_address: src.resolved_address.to_string(),
                    })
                    .await
                    .map_err(map_status)?;
                let stat_info =
                    require_field(stat.into_inner().resource_info, "stat.resource_info")?;
                require_field(
                    stat_info.resource_identity,
                    "stat.resource_info.resource_identity",
                )?
            };
            // Destination-side precondition: `MatchEtag` becomes a
            // compare-and-swap on `previous_version`. `Overwrite`
            // leaves the field unset. (`Fail` was rejected above.)
            let previous_version = match &opts.if_dest {
                IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
                IfDestExists::Overwrite | IfDestExists::Fail => None,
            };
            let response = client
                .copy(fo::CopyRequest {
                    source_resource_identity: Some(source_resource_identity),
                    destination_resource_address: dest.resolved_address.to_string(),
                    previous_version,
                })
                .await
                .map_err(|status| {
                    if opts.if_source.is_some() {
                        map_identity_precondition_status(status, &src.resolved_address, "copy")
                    } else {
                        map_status(status)
                    }
                })?;
            let resource_identity = response.into_inner().resource_identity;
            let etag = resource_identity
                .map(|id| id.encoded_identity)
                .filter(|s| !s.is_empty());
            let dest_address = dest.resolved_address.clone();
            self.stash_message(dest_address.as_str(), opts.message.as_deref())
                .await;
            Ok(WriteStep::Done(WriteResult {
                info: ObjectInfo {
                    address: dest_address,
                    kind: ObjectKind::File,
                    etag,
                    version: None,
                    size: None,
                    mtime: None,
                    checksums: ChecksumSet::default(),
                    effective_permissions: None,
                    system_metadata: None,
                    user_metadata: None,
                    modified_by: None,
                },
            }))
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        require_etag_only_if_match(opts.if_source.as_deref())?;
        // The Storage API wire has no "fail if destination exists" primitive
        // for Move: MoveRequest.destination_previous_version is a
        // compare-and-swap on an existing identity, not an absence
        // assertion. Silently ignoring `IfDestExists::Fail` would
        // clobber an existing object; refuse loudly.
        if matches!(opts.if_dest, IfDestExists::Fail) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: rename with if_dest=Fail is not supported by this backend \
                 (Storage API wire has no fail-if-exists primitive; \
                 Capabilities.supports_no_overwrite_write = false)",
            ));
        }
        let span = tracing::debug_span!(
            "omniverse_storage_service.rename",
            op = "rename",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&src.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.fileobject_client().await?;
            // The Storage API proto's MoveRequest carries separate
            // source/destination previous-version slots, so the new
            // split SPI maps cleanly: `if_source` -> source side,
            // `if_dest::MatchEtag` -> destination side.
            let source_previous_version = resource_identity_from(&opts.if_source);
            let destination_previous_version = match &opts.if_dest {
                IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
                IfDestExists::Overwrite | IfDestExists::Fail => None,
            };
            client
                .r#move(fo::MoveRequest {
                    source_resource_address: src.resolved_address.to_string(),
                    source_previous_version,
                    destination_resource_address: dest.resolved_address.to_string(),
                    destination_previous_version,
                })
                .await
                .map_err(map_status)?;
            self.stash_message(dest.resolved_address.as_str(), opts.message.as_deref())
                .await;
            Ok(())
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.update_metadata",
            op = "update_metadata",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&target.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            if opts.if_match.is_some() {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service update_metadata cannot honor object-level if_match: \
                     the metadata service uses per-key etags, not an object identity",
                ));
            }
            let mut client = self.transport.metadata_client().await?;
            for (key, value) in opts.user_metadata_set {
                client
                    .update_metadata(md::UpdateMetadataRequest {
                        uri: target.resolved_address.to_string(),
                        user_metadata_key: key,
                        user_metadata: Some(md_value_string(value)),
                        expected_etag: None,
                    })
                    .await
                    .map_err(map_status)?;
            }
            for key in opts.user_metadata_remove {
                client
                    .delete_metadata(md::DeleteMetadataRequest {
                        uri: target.resolved_address.to_string(),
                        user_metadata_key: key,
                        expected_etag: None,
                    })
                    .await
                    .map_err(map_status)?;
            }
            self.stash_message(target.resolved_address.as_str(), opts.message.as_deref())
                .await;
            let mut object_client = self.transport.fileobject_client().await?;
            let stat = object_client
                .stat(fo::StatRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status)?;
            let info = require_field(stat.into_inner().resource_info, "stat.resource_info")?;
            let mut object_info = object_info_from(target.resolved_address.clone(), &info);
            if let Some(extra) = self.fetch_standard_metadata(&target).await? {
                merge_standard_metadata_into_object(&mut object_info, extra);
            }
            Ok(backend_item_info_from_object(object_info))
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let span = tracing::debug_span!(
            "omniverse_storage_service.watch_directory",
            op = "watch_directory",
            plugin = "omniverse-storage-service",
            "object.address" = %RedactedUrl(&prefix.resolved_address),
            outcome = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = race_cancel(cancel.as_ref(), async move {
            let mut client = self.transport.event_consumer_client().await?;
            let prefix_address = prefix.resolved_address.to_string();
            let request_msg = notif::ConsumeNonDurableEventsRequest {
                filter_groups: build_watch_filter_groups(&prefix_address, opts.recursive),
                reconnect_token: opts
                    .since
                    .as_ref()
                    .and_then(|c| std::str::from_utf8(&c.0).ok())
                    .map(|s| s.to_string()),
                // Single-shot filter request: we never refilter mid-stream, so
                // there are no previous filter groups to invalidate.
                previous_filter_groups: Vec::new(),
            };
            // Bidi streaming: single-shot filter request, then read events.
            // Storage-core supports refilter mid-stream by sending more
            // ConsumeNonDurableEventsRequest frames; we don't refilter here.
            let request_stream = futures::stream::once(async move { request_msg });
            let response = client
                .consume_non_durable_events(request_stream)
                .await
                .map_err(map_status)?;
            let server_stream = response.into_inner();
            Ok(spawn_watch_bridge(prefix.resolved_address, server_stream))
        })
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "err" });
        result
    }

    async fn watch_address_roots(
        &self,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendAddressRootsStream> {
        race_cancel(cancel.as_ref(), async move {
            // Block until interactive sign-in installs a bearer; without it
            // services discovery (and hence ListTopLevelAddresses) 401s
            // against auth-required deployments.
            self.transport.auth_state().wait_for_token().await;
            // Storage-core today exposes ListTopLevelAddresses but no delta
            // feed. Emit a single Snapshot so the host's per-connection
            // watcher gets the current view, then end the stream. When the
            // upstream service publishes Added/Removed events, replace this
            // with a real bridge.
            let urls = self.list_top_level_addresses().await?;
            tracing::debug!(
                target: "ovstorage.omniverse_storage_service.backend",
                plugin = "omniverse-storage-service",
                discovery_url = %self.discovery_url,
                count = urls.len(),
                "omniverse-storage-service: list_top_level_addresses returned",
            );
            let backend_kind = config_kind();
            let connection_id =
                ConnectionId(format!("omniverse-storage-service:{}", self.discovery_url));
            let mut roots = Vec::with_capacity(urls.len());
            for address in urls {
                let capabilities = self.capabilities_for_root(&address).await;
                roots.push(AddressRoot {
                    address,
                    display_name: None,
                    backend_kind: backend_kind.to_string(),
                    connection_id: Some(connection_id.clone()),
                    capabilities,
                    source: RouteSource::ConnectionContributed {
                        connection_id: connection_id.clone(),
                    },
                    visibility: AddressVisibility::Visible,
                    user_metadata: UserMetadata::new(),
                });
            }
            let snapshot = Ok(AddressRootsChange::Snapshot(roots));
            let stream: BackendAddressRootsStream =
                Box::pin(futures::stream::once(async move { snapshot }));
            Ok(stream)
        })
        .await
    }

    async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        race_cancel(cancel.as_ref(), async move {
            let mut file_client = self.transport.fileobject_client().await?;
            file_client
                .stat(fo::StatRequest {
                    resource_address: target.resolved_address.to_string(),
                })
                .await
                .map_err(map_status)?;
            let granted = self.fetch_acl_grants(&target).await?;
            let denied_ops = AccessOps {
                read: ops.read && !granted.read,
                write: ops.write && !granted.write,
                delete: ops.delete && !granted.delete,
                update_metadata: ops.update_metadata && !granted.update_metadata,
            };
            let allowed = !denied_ops.read
                && !denied_ops.write
                && !denied_ops.delete
                && !denied_ops.update_metadata;
            Ok(AccessDecision {
                allowed,
                denied_ops,
                reason: if allowed {
                    None
                } else {
                    Some("omniverse-storage-service: object ACL does not grant the requested operations".into())
                },
            })
        })
        .await
    }
}

fn extract_chunk(frame: fo::ReadFromAddressResponse) -> Result<Bytes> {
    use fo::read_from_address_response::ReplyType;
    match frame.reply_type {
        Some(ReplyType::Chunk(chunk)) => Ok(chunk.chunk),
        Some(ReplyType::ResourceInfo(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent ResourceInfo mid-stream",
        )),
        Some(ReplyType::Redirect(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent Redirect after Chunk frames; \
             redirect path is mutually exclusive with chunk delivery",
        )),
        None => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: empty Read frame",
        )),
    }
}

fn extract_read_chunk(frame: fo::ReadResponse) -> Result<Bytes> {
    use fo::read_response::ReplyType;
    match frame.reply_type {
        Some(ReplyType::Chunk(chunk)) => Ok(chunk.chunk),
        Some(ReplyType::Metadata(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent Metadata mid-stream",
        )),
        Some(ReplyType::Redirect(_)) => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: server sent Redirect after Chunk frames; \
             redirect path is mutually exclusive with chunk delivery",
        )),
        None => Err(Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service: empty Read frame",
        )),
    }
}

/// Unified body-delivery shape returned by the read path.
enum ReadBody {
    Empty,
    Chunks(Pin<Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>>),
    Redirect(fo::Redirect),
}

/// Read a caller-supplied etag as a Storage API ResourceIdentity.
///
/// This is not address-level version selection. The SPI version selector is
/// the URL returned by version listing; `if_match` is the opaque etag token
/// from a prior operation on the same address. The Storage API names that token
/// `ResourceIdentity`, so a successful identity read is the server-side
/// precondition check. If the server has discarded or rejects the identity,
/// map that miss to `ObjectModified`.
async fn fetch_read_by_identity(
    client: &mut crate::transport::FileObject,
    target: &ResolvedTarget,
    etag: &str,
) -> Result<(ObjectInfo, ReadBody)> {
    let response = client
        .read(fo::ReadRequest {
            resource_identity: Some(fo::ResourceIdentity {
                encoded_identity: etag.to_string(),
            }),
            download_preference: None,
        })
        .await
        .map_err(|status| {
            map_identity_precondition_status(status, &target.resolved_address, "read")
        })?;
    let mut server_stream = response.into_inner();
    use fo::read_response::ReplyType;
    let first = server_stream
        .message()
        .await
        .map_err(|status| {
            map_identity_precondition_status(status, &target.resolved_address, "read")
        })?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: read stream closed before first reply",
            )
        })?;
    let object_info = match first.reply_type {
        Some(ReplyType::Metadata(metadata)) => {
            object_info_from_read_metadata(target.resolved_address.clone(), Some(&metadata), etag)
        }
        Some(ReplyType::Chunk(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Chunk before Metadata",
            ));
        }
        Some(ReplyType::Redirect(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Redirect before Metadata",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: Read reply_type missing on first frame",
            ));
        }
    };
    let second = server_stream.message().await.map_err(|status| {
        map_identity_precondition_status(status, &target.resolved_address, "read")
    })?;
    let body = match second.and_then(|frame| frame.reply_type) {
        Some(ReplyType::Chunk(chunk)) => {
            let first_chunk = futures::stream::once(async move { Ok(chunk.chunk) });
            let rest =
                server_stream.map(|frame| frame.map_err(map_status).and_then(extract_read_chunk));
            let stream: Pin<Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>> =
                Box::pin(first_chunk.chain(rest));
            ReadBody::Chunks(stream)
        }
        Some(ReplyType::Redirect(redirect)) => ReadBody::Redirect(redirect),
        Some(ReplyType::Metadata(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Metadata mid-stream",
            ));
        }
        None => ReadBody::Empty,
    };
    Ok((object_info, body))
}

fn object_info_from_read_metadata(
    address: Url,
    metadata: Option<&fo::Metadata>,
    etag: &str,
) -> ObjectInfo {
    let fields = fields_from_metadata(metadata, Some(etag.to_string()).filter(|s| !s.is_empty()));
    ObjectInfo {
        address,
        kind: ObjectKind::File,
        etag: fields.etag,
        version: None,
        size: fields.size,
        mtime: fields.mtime,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn default_object_info(address: Url, kind: ObjectKind) -> ObjectInfo {
    ObjectInfo {
        address,
        kind,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::default(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn backend_item_info_from_object(info: ObjectInfo) -> BackendItemInfo {
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

fn parse_server_address(raw: &str, label: &'static str) -> Result<Url> {
    Url::parse(raw).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: invalid {label} {raw:?}: {err}"),
        )
    })
}

fn map_identity_precondition_status(
    status: tonic::Status,
    address: &Url,
    op: &'static str,
) -> Error {
    match status.code() {
        tonic::Code::NotFound | tonic::Code::FailedPrecondition => Error::new(
            ErrorCode::ObjectModified,
            format!(
                "omniverse-storage-service {op}: supplied identity no longer names readable bytes for {}",
                RedactedUrl(address),
            ),
        )
        .with_context(ErrorContext::Identity { new_etag: None }),
        _ => map_status(status),
    }
}

fn object_info_from_version_proto(v: ver::VersionInfo) -> Result<ObjectInfo> {
    let address = version_resource_address(&v)?;
    Ok(v.resource_info
        .as_ref()
        .map(|info| object_info_from(address.clone(), info))
        .unwrap_or_else(|| default_object_info(address, ObjectKind::File)))
}

fn version_resource_address(v: &ver::VersionInfo) -> Result<Url> {
    let raw = v
        .resource_address
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: EnumerateVersions item has no resource_address",
            )
        })?;
    Url::parse(raw).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("omniverse-storage-service: invalid version resource_address {raw:?}: {err}"),
        )
    })
}

struct LatestVersionPicker {
    order: Option<ver::VersionsOrder>,
    selected: Option<SelectedVersion>,
}

struct SelectedVersion {
    item: ObjectInfo,
    sorting_key: Option<String>,
}

impl LatestVersionPicker {
    fn new() -> Self {
        Self {
            order: None,
            selected: None,
        }
    }

    fn observe_frame(&mut self, frame: ver::EnumerateVersionsResponse) -> Result<bool> {
        let order = ver::VersionsOrder::try_from(frame.versions_order)
            .unwrap_or(ver::VersionsOrder::Unspecified);
        if order == ver::VersionsOrder::Unspecified {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: EnumerateVersions returned VERSIONS_ORDER_UNSPECIFIED",
            ));
        }
        if let Some(previous) = self.order {
            if previous != order {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "omniverse-storage-service: EnumerateVersions changed versions_order mid-stream",
                ));
            }
        } else {
            self.order = Some(order);
        }

        match order {
            ver::VersionsOrder::NewestFirst => {
                if self.selected.is_none()
                    && let Some(item) = frame.items.into_iter().next()
                {
                    self.selected = Some(SelectedVersion {
                        item: object_info_from_version_proto(item)?,
                        sorting_key: None,
                    });
                    return Ok(true);
                }
            }
            ver::VersionsOrder::OldestFirst => {
                for item in frame.items {
                    self.selected = Some(SelectedVersion {
                        item: object_info_from_version_proto(item)?,
                        sorting_key: None,
                    });
                }
            }
            ver::VersionsOrder::ByKey => {
                for item in frame.items {
                    let sorting_key = item.sorting_key.clone().ok_or_else(|| {
                        Error::new(
                            ErrorCode::Unsupported,
                            "omniverse-storage-service: versions_order=BY_KEY item has no sorting_key",
                        )
                    })?;
                    // Per the vendored storage API proto,
                    // VERSIONS_ORDER_BY_KEY sorts ascending by sorting_key
                    // lexicographically, so the latest item is the greatest
                    // sorting_key under string comparison.
                    let replace = self
                        .selected
                        .as_ref()
                        .and_then(|selected| selected.sorting_key.as_ref())
                        .map(|current| sorting_key.as_str() > current.as_str())
                        .unwrap_or(true);
                    if replace {
                        self.selected = Some(SelectedVersion {
                            item: object_info_from_version_proto(item)?,
                            sorting_key: Some(sorting_key),
                        });
                    }
                }
            }
            ver::VersionsOrder::Unspecified => unreachable!("handled above"),
        }
        Ok(false)
    }

    fn finish(self) -> Result<ObjectInfo> {
        self.selected.map(|selected| selected.item).ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "omniverse-storage-service: EnumerateVersions returned no versions",
            )
        })
    }
}

/// Read the latest version at the address via `ReadFromAddress`.
async fn fetch_read_from_address(
    client: &mut crate::transport::FileObject,
    target: &ResolvedTarget,
) -> Result<(ObjectInfo, ReadBody)> {
    let response = client
        .read_from_address(fo::ReadFromAddressRequest {
            resource_address: target.resolved_address.to_string(),
            download_preference: None,
        })
        .await
        .map_err(map_status)?;
    let mut server_stream = response.into_inner();
    use fo::read_from_address_response::ReplyType;
    let first = server_stream
        .message()
        .await
        .map_err(map_status)?
        .ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: read stream closed before first reply",
            )
        })?;
    let object_info = match first.reply_type {
        Some(ReplyType::ResourceInfo(info)) => {
            object_info_from(target.resolved_address.clone(), &info)
        }
        Some(ReplyType::Chunk(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Chunk before ResourceInfo",
            ));
        }
        Some(ReplyType::Redirect(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent Redirect before ResourceInfo",
            ));
        }
        None => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: ReadFromAddress reply_type missing on first frame",
            ));
        }
    };
    let second = server_stream.message().await.map_err(map_status)?;
    let body = match second.and_then(|frame| frame.reply_type) {
        Some(ReplyType::Chunk(chunk)) => {
            let first_chunk = futures::stream::once(async move { Ok(chunk.chunk) });
            let rest = server_stream.map(|frame| frame.map_err(map_status).and_then(extract_chunk));
            let stream: Pin<Box<dyn Stream<Item = ovstorage_plugin::Result<Bytes>> + Send>> =
                Box::pin(first_chunk.chain(rest));
            ReadBody::Chunks(stream)
        }
        Some(ReplyType::Redirect(redirect)) => ReadBody::Redirect(redirect),
        Some(ReplyType::ResourceInfo(_)) => {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: server sent ResourceInfo mid-stream",
            ));
        }
        None => ReadBody::Empty,
    };
    Ok((object_info, body))
}

/// Build the SPI's `ReadRedirect` from the proto `Redirect` frame.
///
/// Storage-core's `Redirect.method` is deprecated; we default to GET
/// unless the server explicitly sets it. Headers round-trip verbatim so
/// the host's redirect follower replays signed-URL parameters
/// (`x-amz-*`, `Authorization`, etc.) the server stamped on.
fn build_read_redirect(redirect: fo::Redirect) -> ReadRedirect {
    #[allow(deprecated)]
    let method = if redirect.method.trim().is_empty() {
        "GET".to_string()
    } else {
        redirect.method.clone()
    };
    let headers: Vec<(String, String)> = redirect
        .additional_headers
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect();
    let url = redirect.redirect_target_url;
    // Server doesn't publish a redirect TTL today; one hour matches the
    // signed-URL window storage backends typically grant.
    let expires_at = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    // The non-redirect read path returns the Storage API wire's
    // `ResourceIdentity.encoded_identity` as the etag. The redirect path
    // lands on whichever underlying cloud the server federates to
    // (S3, Azure, GCS, …), whose HTTP-level `ETag` header has its own
    // shape — sending that value back through a future `if_match` would
    // be rejected at the Storage API wire. Clear `etag_header` so the redirect
    // path advertises "no usable etag" instead of returning an
    // incompatible token. (`Stat` remains the supported way to obtain
    // an `if_match` token before a redirect-fetched read.)
    let response_parsing = ResponseParsing {
        etag_header: None,
        ..ResponseParsing::default()
    };
    ReadRedirect {
        request: HttpRequest {
            method,
            url: url.clone(),
            headers,
        },
        response_parsing,
        expires_at,
        scope: RedirectScope {
            physical_url_prefix: url,
            operations: AccessOps {
                read: true,
                ..Default::default()
            },
            expires_at,
        },
        audit_id: String::new(),
        policy_epoch: 0,
    }
}

fn md_value_string(value: String) -> ovstorage_services_protos::google::protobuf::Value {
    use ovstorage_services_protos::google::protobuf::{Value, value::Kind};
    Value {
        kind: Some(Kind::StringValue(value)),
    }
}

impl OmniverseStorageBackend {
    async fn list_top_level_addresses(&self) -> Result<Vec<url::Url>> {
        use ovstorage_services_protos::nvidia::omniverse::storage::capabilities::v1alpha as cap;
        let mut client = self.transport.capabilities_client().await?;
        let response = client
            .list_top_level_addresses(cap::ListTopLevelAddressesRequest {})
            .await
            .map_err(map_status)?;
        let raw: Vec<String> = response
            .into_inner()
            .items
            .into_iter()
            .map(|entry| entry.top_level_address)
            .collect();
        let parsed: Vec<url::Url> = raw.iter().filter_map(|s| url::Url::parse(s).ok()).collect();
        if raw.len() != parsed.len() {
            tracing::warn!(
                target: "ovstorage.omniverse_storage_service.backend",
                plugin = "omniverse-storage-service",
                raw_count = raw.len(),
                parsed_count = parsed.len(),
                rejected = ?raw.iter().filter(|s| url::Url::parse(s).is_err()).collect::<Vec<_>>(),
                "omniverse-storage-service: ListTopLevelAddresses returned entries that failed URL parsing",
            );
        }
        Ok(parsed)
    }

    async fn send_inline_write(
        &self,
        target: ResolvedTarget,
        body: Body,
        opts: WriteOptions,
    ) -> Result<WriteResult> {
        // Map IfDestExists to Storage API WriteParameters.previous_version:
        // - Overwrite -> no precondition
        // - MatchEtag(s) -> compare-and-swap on the destination's
        //   current identity
        // - Fail -> the Storage API wire has no fail-if-exists primitive;
        //   refuse loudly (matches `supports_no_overwrite_write = false`).
        let previous_version = match &opts.if_dest {
            IfDestExists::Overwrite => None,
            IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
            IfDestExists::Fail => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service: write with if_dest=Fail is not supported by this backend \
                     (Storage API wire has no fail-if-exists primitive; \
                     Capabilities.supports_no_overwrite_write = false)",
                ));
            }
        };
        let mut client = self.transport.fileobject_client().await?;
        let (data_object_size, body_stream) = body_to_chunk_stream(body, opts.size_hint).await?;
        let params = fo::WriteRequest {
            write_request_type: Some(fo::write_request::WriteRequestType::Params(
                fo::WriteParameters {
                    destination_resource_address: target.resolved_address.to_string(),
                    previous_version,
                    data_object_size,
                    upload_preference: Some(fo::UploadPreference::Body as i32),
                },
            )),
        };
        let (request_stream, source_err) = build_write_request_stream(params, body_stream);
        // `.fuse()` keeps the receiver safe to re-poll after it has
        // resolved — without it, the second select! below would panic
        // with "called after complete" on the clean-EOS path.
        use futures::future::FutureExt;
        let mut source_err = source_err.fuse();

        // We can't truly cancel a tonic 0.14 client-streaming RPC
        // mid-flight — `Grpc::streaming` wraps the request stream as
        // `s.map(Ok)`, so source errors can't reach h2's error path,
        // and dropping the response future / response stream lets h2
        // send END_STREAM gracefully rather than RST_STREAM. A
        // truncated upload can therefore finalize on the server. The
        // OmniverseStorageService doesn't validate received bytes
        // against `WriteParameters.data_object_size` either, so we
        // can't rely on server-side rejection. Best we can do from
        // the client is surface the source error to the caller so it
        // never silently reports success on a partial upload.
        let response = tokio::select! {
            biased;
            Ok(err) = &mut source_err => return Err(err),
            resp = client.write(request_stream) => resp.map_err(map_status)?,
        };
        let mut server_stream = response.into_inner();
        let mut last_resource_info: Option<fo::ResourceInfo> = None;
        loop {
            tokio::select! {
                biased;
                Ok(err) = &mut source_err => return Err(err),
                msg = server_stream.message() => {
                    let Some(msg) = msg.map_err(map_status)? else { break };
                    use fo::write_response::WriteResponseType;
                    match msg.write_response_type {
                        Some(WriteResponseType::WriteChunksAccepted(_)) => continue,
                        Some(WriteResponseType::ResourceInfo(info)) => {
                            last_resource_info = Some(info);
                        }
                        Some(WriteResponseType::WriteRedirect(_))
                        | Some(WriteResponseType::MultipartUpload(_)) => {
                            return Err(Error::new(
                                ErrorCode::Unsupported,
                                "omniverse-storage-service: server demanded redirect mid-inline-write; \
                                 host should call write_redirect for this size class",
                            ));
                        }
                        None => {}
                    }
                }
            }
        }
        // Server-stream end and source-error can land in the same
        // poll cycle. Prefer the source error over the (potentially
        // truncated) server response.
        if let Some(Ok(err)) = source_err.now_or_never() {
            return Err(err);
        }
        let info = last_resource_info.ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: write stream closed without ResourceInfo",
            )
        })?;
        let address = target.resolved_address.clone();
        let address_str = address.as_str().to_string();
        self.stash_message(&address_str, opts.message.as_deref())
            .await;
        self.stash_user_metadata(&address_str, opts.user_metadata.as_ref())
            .await;
        Ok(WriteResult {
            info: object_info_from(address, &info),
        })
    }

    async fn start_write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        // Map IfDestExists to Storage API WriteParameters.previous_version
        // (see send_inline_write for the full rationale on each arm).
        let previous_version = match &opts.if_dest {
            IfDestExists::Overwrite => None,
            IfDestExists::MatchEtag(etag) => resource_identity_from(&Some(etag.clone())),
            IfDestExists::Fail => {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "omniverse-storage-service: write with if_dest=Fail is not supported by this backend \
                     (Storage API wire has no fail-if-exists primitive; \
                     Capabilities.supports_no_overwrite_write = false)",
                ));
            }
        };
        // Redirect uploads emit `RedirectBodySource::UserBytes { len }`,
        // which the host's redirect follower drains exactly. Without
        // an upfront size we can't supply a finite `len` — emitting
        // `u64::MAX` would make any normal finite body fail at EOF.
        // The host falls back to write/write_stream when redirect is
        // not viable.
        let size = opts.size_hint.ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: write_redirect requires size_hint; \
                 host should fall through to write/write_stream",
            )
        })?;
        let mut client = self.transport.fileobject_client().await?;
        let preferred = preferred_upload_method(&mut client, &target, size).await?;
        if matches!(
            preferred,
            fo::UploadPreference::Body | fo::UploadPreference::Unspecified
        ) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: server reports inline upload for this size; \
                 host should fall through to write/write_stream",
            ));
        }
        let params = fo::WriteRequest {
            write_request_type: Some(fo::write_request::WriteRequestType::Params(
                fo::WriteParameters {
                    destination_resource_address: target.resolved_address.to_string(),
                    previous_version,
                    data_object_size: size,
                    upload_preference: Some(preferred as i32),
                },
            )),
        };
        // No chunks — server must respond on the first frame with a redirect
        // or a multipart_upload control message.
        let empty: Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>> =
            futures::stream::empty().boxed();
        // No chunks → source can never error → the receiver here will
        // resolve with `RecvError` when the sender is dropped (stream
        // ends). We just discard it.
        let (request_stream, _source_err) = build_write_request_stream(params, empty);
        let response = client.write(request_stream).await.map_err(map_status)?;
        let mut server_stream = response.into_inner();
        let first = server_stream
            .message()
            .await
            .map_err(map_status)?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "omniverse-storage-service: write stream closed before first reply",
                )
            })?;
        use fo::write_response::WriteResponseType;
        match first.write_response_type {
            Some(WriteResponseType::WriteRedirect(props)) => Ok(single_redirect_batch(
                &target,
                size,
                opts.message.clone(),
                opts.user_metadata.clone(),
                props,
            )),
            Some(WriteResponseType::MultipartUpload(mp)) => {
                multipart_redirect_batch(
                    self,
                    &target,
                    size,
                    opts.message.clone(),
                    opts.user_metadata.clone(),
                    mp,
                )
                .await
            }
            Some(WriteResponseType::ResourceInfo(_))
            | Some(WriteResponseType::WriteChunksAccepted(_)) => Err(Error::new(
                ErrorCode::Unsupported,
                "omniverse-storage-service: server accepted inline write but write_redirect was requested",
            )),
            None => Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: write_response_type missing on first redirect frame",
            )),
        }
    }

    // Stash opts.message under user_metadata key `x-ov-message` after a
    // successful mutating write. Best-effort: a metadata-service Unimplemented
    // response is silently ignored (matches fetch_standard_metadata).
    async fn stash_message(&self, address: &str, message: Option<&str>) {
        let Some(value) = message.filter(|m| !m.is_empty()) else {
            return;
        };
        let Ok(mut client) = self.transport.metadata_client().await else {
            return;
        };
        let _ = client
            .update_metadata(md::UpdateMetadataRequest {
                uri: address.to_string(),
                user_metadata_key: OV_MESSAGE_KEY.to_string(),
                user_metadata: Some(md_value_string(value.to_string())),
                expected_etag: None,
            })
            .await;
    }

    async fn stash_user_metadata(
        &self,
        address: &str,
        user_metadata: Option<&ovstorage_plugin::UserMetadata>,
    ) {
        let Some(map) = user_metadata.filter(|m| !m.is_empty()) else {
            return;
        };
        let Ok(mut client) = self.transport.metadata_client().await else {
            return;
        };
        for (key, value) in map {
            let _ = client
                .update_metadata(md::UpdateMetadataRequest {
                    uri: address.to_string(),
                    user_metadata_key: key.clone(),
                    user_metadata: Some(md_value_string(value.clone())),
                    expected_etag: None,
                })
                .await;
        }
    }

    async fn fetch_standard_metadata(
        &self,
        target: &ResolvedTarget,
    ) -> Result<Option<StandardMetadata>> {
        self.fetch_standard_metadata_by_address(target.resolved_address.as_str())
            .await
    }

    async fn fetch_standard_metadata_by_address(
        &self,
        address: &str,
    ) -> Result<Option<StandardMetadata>> {
        let mut client = self.transport.metadata_client().await?;
        let response = match client
            .get_metadata(md::GetMetadataRequest {
                uri: address.to_string(),
                // Empty key list asks the service for all user metadata.
                // `parse_standard_metadata` also promotes the known
                // service-stamped keys into system_metadata/modified_by.
                user_metadata_keys: Vec::new(),
            })
            .await
        {
            Ok(resp) => resp,
            Err(status) if status.code() == tonic::Code::Unimplemented => {
                // Server has no metadata service: silent no-op so stat/list
                // don't fail just because the deployment skips notifications.
                return Ok(None);
            }
            Err(status) => return Err(map_status(status)),
        };
        Ok(Some(parse_standard_metadata(response.into_inner())))
    }

    /// Fetch the per-object `acl` user metadata key and translate it to the
    /// granted-op set. Mirrors the C++ provider_omnistorage parse at
    /// `StorageProvider.cpp:5966-6011`. Mapping:
    ///
    /// - `"read"`  → `AccessOps::read`
    /// - `"write"` → `AccessOps::write` + `AccessOps::update_metadata`
    ///   (writing object content implies writing user metadata)
    /// - `"admin"` → `AccessOps::delete` (the elevated permission the C++
    ///   client uses to gate destructive ops)
    ///
    /// Absent `acl` key or missing `metadata` user-metadata altogether →
    /// grant all ops. An `acl` value that is not a list grants nothing;
    /// unknown or non-string entries inside a list are ignored. The server
    /// is still the authoritative gate; `check_access` is a hint, and the
    /// actual RPC may return `PermissionDenied` even after an allowed
    /// decision.
    async fn fetch_acl_grants(&self, target: &ResolvedTarget) -> Result<AccessOps> {
        let mut client = self.transport.metadata_client().await?;
        let response = match client
            .get_metadata(md::GetMetadataRequest {
                uri: target.resolved_address.to_string(),
                user_metadata_keys: vec![ACL_METADATA_KEY.to_string()],
            })
            .await
        {
            Ok(resp) => resp,
            Err(status) if status.code() == tonic::Code::Unimplemented => {
                // Server has no metadata service; fall back to "grant all".
                return Ok(grant_all());
            }
            Err(status) => return Err(map_status(status)),
        };
        let map = response.into_inner().user_metadata;
        match map.get(ACL_METADATA_KEY) {
            Some(value) => Ok(parse_acl_grants(value)),
            None => Ok(grant_all()),
        }
    }

    async fn finalize_write_redirect(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
    ) -> Result<WriteStep> {
        validate_redirect_results(&redirects, &results)?;
        let continuation = Continuation::decode(&redirects.continuation)?;
        let pending_message = continuation.message.clone();
        let pending_user_metadata = continuation.user_metadata.clone();
        let mut client = self.transport.fileobject_client().await?;
        match continuation.kind {
            ContinuationKind::SingleRedirect {
                completion_header_names,
            } => {
                let result = results.results.into_iter().next().ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: single-redirect continuation expected one result",
                    )
                })?;
                if !(200..300).contains(&result.status_code) {
                    return Err(map_redirect_status(result.status_code, 0));
                }
                let additional_headers =
                    extract_completion_headers(&completion_header_names, &result.captured_headers);
                let response = client
                    .complete_redirect_upload(fo::CompleteRedirectUploadRequest {
                        destination_resource_address: continuation.destination_resource_address,
                        additional_headers,
                    })
                    .await
                    .map_err(map_status)?;
                let info = require_field(
                    response.into_inner().resource_info,
                    "complete_redirect_upload.resource_info",
                )?;
                let address_str = target.resolved_address.as_str().to_string();
                self.stash_message(&address_str, pending_message.as_deref())
                    .await;
                self.stash_user_metadata(&address_str, pending_user_metadata.as_ref())
                    .await;
                Ok(WriteStep::Done(WriteResult {
                    info: object_info_from(target.resolved_address, &info),
                }))
            }
            ContinuationKind::Multipart {
                upload_id,
                total_parts,
            } => {
                let aborter = MultipartAborter {
                    transport: self.transport.clone(),
                    destination: continuation.destination_resource_address.clone(),
                    upload_id: upload_id.clone(),
                    armed: true,
                };
                if results.results.len() as u32 != total_parts {
                    aborter.abort_now().await;
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "omniverse-storage-service: multipart continuation result count != redirect count",
                    ));
                }
                let mut parts = Vec::with_capacity(results.results.len());
                for (idx, result) in results.results.iter().enumerate() {
                    if !(200..300).contains(&result.status_code) {
                        aborter.abort_now().await;
                        return Err(map_redirect_status(result.status_code, idx));
                    }
                    parts.push(fo::CompletedUploadPart {
                        part_number: idx as u32,
                        headers: result
                            .captured_headers
                            .iter()
                            .map(|(name, value)| fo::Header {
                                name: name.clone(),
                                value: value.clone(),
                            })
                            .collect(),
                    });
                }
                let response = client
                    .complete_multipart_upload(fo::CompleteMultipartUploadRequest {
                        upload_id: upload_id.clone(),
                        destination_resource_address: continuation.destination_resource_address,
                        parts,
                    })
                    .await;
                let response = match response {
                    Ok(response) => response,
                    Err(status) => {
                        aborter.abort_now().await;
                        return Err(map_status(status));
                    }
                };
                aborter.disarm();
                let info = require_field(
                    response.into_inner().resource_info,
                    "complete_multipart_upload.resource_info",
                )?;
                let address_str = target.resolved_address.as_str().to_string();
                self.stash_message(&address_str, pending_message.as_deref())
                    .await;
                self.stash_user_metadata(&address_str, pending_user_metadata.as_ref())
                    .await;
                Ok(WriteStep::Done(WriteResult {
                    info: object_info_from(target.resolved_address, &info),
                }))
            }
        }
    }
}

// 4xx codes from the redirect upload are caller faults (auth, precondition,
// not-found); only 5xx / 408 / 429 are retryable. Mirrors
// `ovstorage-plugin-opendal::map_redirect_status`.
fn map_redirect_status(status: u16, index: usize) -> Error {
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("omniverse-storage-service redirect upload #{index} returned HTTP 401"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("omniverse_storage_service_redirect_unauthorized".into()),
            expired_at: None,
        });
    }
    let code = match status {
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        408 => ErrorCode::Transient,
        409 => ErrorCode::Conflict,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        429 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Internal,
    };
    Error::new(
        code,
        format!("omniverse-storage-service redirect upload #{index} returned HTTP {status}"),
    )
}

fn single_redirect_batch(
    target: &ResolvedTarget,
    size: u64,
    message: Option<String>,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
    props: fo::WriteRedirectProperties,
) -> WriteRedirectBatch {
    let mut continuation = Continuation::single_redirect(
        target.resolved_address.to_string(),
        props.completion_header_names.clone(),
    );
    continuation.message = message;
    continuation.user_metadata = user_metadata.filter(|m| !m.is_empty());
    let redirect = redirect_from_props(target, size, &props);
    WriteRedirectBatch {
        continuation: continuation.encode(),
        redirects: vec![redirect],
    }
}

async fn multipart_redirect_batch(
    backend: &OmniverseStorageBackend,
    target: &ResolvedTarget,
    size: u64,
    message: Option<String>,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
    mp: fo::CreateMultipartUploadResponse,
) -> Result<WriteRedirectBatch> {
    let upload_id = mp.upload_id.clone();
    let aborter = MultipartAborter {
        transport: backend.transport.clone(),
        destination: target.resolved_address.to_string(),
        upload_id: upload_id.clone(),
        armed: true,
    };
    let result = async {
        let first_part = require_field(mp.first_part_write_redirect, "multipart.first_part")?;
        let total_parts = compute_total_parts(
            size,
            mp.minimum_size_per_part,
            mp.maximum_size_per_part,
            mp.maximum_parts_number,
        )?;
        let mut redirects = Vec::with_capacity(total_parts as usize);
        redirects.push(part_redirect(target, size, &first_part, 0, total_parts));
        if total_parts > 1 {
            let mut client = backend.transport.fileobject_client().await?;
            let response = client
                .upload_part(fo::UploadPartRequest {
                    upload_id: upload_id.clone(),
                    destination_resource_address: target.resolved_address.to_string(),
                    part_number: 1,
                    part_count: Some(total_parts - 1),
                })
                .await
                .map_err(map_status)?;
            for (offset, props) in response
                .into_inner()
                .part_write_redirects
                .into_iter()
                .enumerate()
            {
                let part_index = (offset + 1) as u32;
                redirects.push(part_redirect(target, size, &props, part_index, total_parts));
            }
        }
        if redirects.len() as u32 != total_parts {
            return Err(Error::new(
                ErrorCode::Internal,
                "omniverse-storage-service: multipart UploadPart returned fewer redirects than requested",
            ));
        }
        let mut continuation =
            Continuation::multipart(target.resolved_address.to_string(), upload_id, total_parts);
        continuation.message = message;
        continuation.user_metadata = user_metadata.filter(|m| !m.is_empty());
        Ok(WriteRedirectBatch {
            continuation: continuation.encode(),
            redirects,
        })
    }
    .await;
    match result {
        Ok(batch) => {
            aborter.disarm();
            Ok(batch)
        }
        Err(err) => {
            aborter.abort_now().await;
            Err(err)
        }
    }
}

fn redirect_from_props(
    _target: &ResolvedTarget,
    size: u64,
    props: &fo::WriteRedirectProperties,
) -> WriteRedirect {
    let method =
        match fo::UploadMethod::try_from(props.method).unwrap_or(fo::UploadMethod::Unspecified) {
            fo::UploadMethod::Post => "POST",
            _ => "PUT",
        };
    WriteRedirect {
        request: HttpRequest {
            method: method.into(),
            url: props.redirect_target_url.clone(),
            headers: props
                .additional_headers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect(),
        },
        body_source: RedirectBodySource::UserBytes {
            offset: 0,
            len: size,
        },
        result_capture: ResultCapture {
            headers: props.completion_header_names.clone(),
            body_max_bytes: 0,
        },
        expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        scope: RedirectScope {
            physical_url_prefix: props.redirect_target_url.clone(),
            operations: AccessOps {
                write: true,
                ..Default::default()
            },
            expires_at: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
        },
        audit_id: String::new(),
        policy_epoch: 0,
    }
}

/// Target per-part size when the server's constraints leave us
/// freedom to choose. Sits between common SDK defaults (AWS CLI
/// 8 MiB, aws-sdk-go 5 MiB) and AWS's "100 MB+ for large objects"
/// recommendation — balances per-RPC overhead against retry
/// granularity and parallelism on multi-GiB uploads.
const TARGET_PART_SIZE: u64 = 32 * 1024 * 1024;

/// Pick `total_parts` for a multipart upload of `size` bytes given
/// the server's optional constraints. Each resulting part (computed
/// later by [`part_redirect`]) must satisfy:
///
/// - sum of parts = `size` (covers the upload),
/// - per-part size `>= min` and `<= max` (where set),
/// - `total_parts <= max_parts` (where set).
///
/// Strategy: aim for parts of [`TARGET_PART_SIZE`] (clamped into the
/// server's [min, max] window), then clamp the part count into
/// [`min_parts_for_max_size`, `max_parts_allowed`] so we never
/// violate the server's caps. This avoids two anti-patterns:
/// "1 huge part" (when max is huge — bad for parallelism / retry)
/// and "many tiny parts at min" (when min is tiny — too much RPC
/// overhead on big uploads). For tight ranges like
/// `min=5, max=6`, the clamps dominate and total falls out of the
/// hard constraints (the reviewer's 6/5/5 case).
///
/// Inconsistent server constraints (e.g. `min > max`, or
/// `max_size * max_parts < size`) surface as `Internal` — the
/// server-issued multipart contract was unsatisfiable.
///
/// All four constraint inputs honor the proto's `optional` semantics:
/// `None` or `Some(0)` means "unconstrained".
fn compute_total_parts(
    size: u64,
    min_size_per_part: Option<u64>,
    max_size_per_part: Option<u64>,
    max_parts_number: Option<u32>,
) -> Result<u32> {
    let min = min_size_per_part.filter(|v| *v > 0);
    let max = max_size_per_part.filter(|v| *v > 0);
    let max_parts = max_parts_number.filter(|v| *v > 0);

    // Hard lower bound: enough parts so no single part exceeds max.
    let min_parts_for_max_size = match max {
        Some(max) => size.div_ceil(max).max(1),
        None => 1,
    };
    // Hard upper bound: enough headroom so every part is >= min (floor).
    let max_parts_for_min_size = match min {
        Some(min) => size / min,
        None => u64::MAX,
    };
    let max_parts_for_count = max_parts.map(u64::from).unwrap_or(u64::MAX);
    let max_parts_allowed = max_parts_for_min_size.min(max_parts_for_count);

    if min_parts_for_max_size == 0 || min_parts_for_max_size > max_parts_allowed {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service: server's multipart constraints unsatisfiable for \
                 size={size} (min_size={min:?}, max_size={max:?}, max_parts={max_parts:?})",
            ),
        ));
    }

    // Pick a target per-part size inside the server's window, then
    // a target part count from it. The clamps below pull the count
    // back into the hard feasibility range when the target lands
    // outside (e.g. for tight `[min, max]` windows, the clamps
    // dominate and we converge on the same total a naive
    // smallest-count algorithm would have picked).
    let target_part_size = TARGET_PART_SIZE
        .max(min.unwrap_or(1))
        .min(max.unwrap_or(u64::MAX));
    let target_total = size.div_ceil(target_part_size).max(1);
    let total = target_total
        .max(min_parts_for_max_size)
        .min(max_parts_allowed);

    // The returned value fits in u32 iff `max_parts_for_count` is
    // u32-bounded (always — it's derived from a u32 proto field).
    // The only path that can produce an oversized value is when
    // `max_size` is set, `max_parts` is unset, and the upload is
    // huge (e.g. size=u64::MAX with max=1). Guard explicitly
    // rather than truncating silently on the `as u32`.
    if total > u32::MAX as u64 {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service: server's multipart constraints would require more \
                 than u32::MAX parts for size={size} max_size={max:?}; cannot represent on the wire",
            ),
        ));
    }
    Ok(total as u32)
}

fn part_redirect(
    target: &ResolvedTarget,
    size: u64,
    props: &fo::WriteRedirectProperties,
    part_index: u32,
    total_parts: u32,
) -> WriteRedirect {
    let total = total_parts as u64;
    let base = size / total;
    let remainder = size % total;
    // Balanced split: distribute the remainder as +1 across the
    // first `remainder` parts, so every part is `base` or
    // `base + 1`. The naive "ceil(size / total) for all but last,
    // last = whatever remains" approach leaves the last part
    // potentially below `minimum_size_per_part` even when
    // compute_total_parts picked a viable `total`. Example:
    // size=16, min=5, max=6 → total=3; ceil(16/3)=6 gives 6/6/4,
    // but the balanced split 6/5/5 keeps every part in [5,6].
    let idx = part_index as u64;
    let (offset, len) = if idx < remainder {
        ((base + 1) * idx, base + 1)
    } else {
        ((base + 1) * remainder + base * (idx - remainder), base)
    };
    let mut redirect = redirect_from_props(target, size, props);
    redirect.body_source = RedirectBodySource::UserBytes { offset, len };
    redirect
}

fn extract_completion_headers(names: &[String], captured: &[(String, String)]) -> Vec<fo::Header> {
    if names.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for name in names {
        let lc = name.to_ascii_lowercase();
        if let Some((_, value)) = captured
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lc) || k.eq_ignore_ascii_case(name))
        {
            out.push(fo::Header {
                name: name.clone(),
                value: value.clone(),
            });
        }
    }
    out
}

async fn preferred_upload_method(
    client: &mut crate::transport::FileObject,
    target: &ResolvedTarget,
    size: u64,
) -> Result<fo::UploadPreference> {
    let response = client
        .fetch_write_type_info(fo::FetchWriteTypeInfoRequest {
            destination_resource_address: target.resolved_address.to_string(),
        })
        .await
        .map_err(map_status)?;
    let intervals = response.into_inner().write_type_intervals;
    for iv in &intervals {
        if size >= iv.minimum_data_object_size && size < iv.maximum_data_object_size {
            return Ok(fo::UploadPreference::try_from(iv.preferred_upload_method)
                .unwrap_or(fo::UploadPreference::Unspecified));
        }
    }
    Ok(fo::UploadPreference::Redirect)
}

async fn body_to_chunk_stream(
    body: Body,
    size_hint: Option<u64>,
) -> Result<(
    u64,
    Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>>,
)> {
    match body {
        Body::Bytes(bytes) => {
            let size = bytes.len() as u64;
            let chunks = chunk_bytes_into_requests(bytes);
            Ok((size, futures::stream::iter(chunks).boxed()))
        }
        Body::LocalFile(path) => {
            // Probe size up front so the WriteParameters carries an
            // accurate `data_object_size` (the server uses it to pick
            // inline vs. multipart). Falls back to size_hint, then 0.
            let size = match tokio::fs::metadata(&path).await {
                Ok(meta) => meta.len(),
                Err(_) => size_hint.unwrap_or(0),
            };
            let file = tokio::fs::File::open(&path).await.map_err(|err| {
                Error::new(
                    ErrorCode::NotFound,
                    format!(
                        "omniverse-storage-service: open {} failed: {err}",
                        path.display()
                    ),
                )
            })?;
            let reader = tokio_util::io::ReaderStream::with_capacity(file, WRITE_CHUNK_SIZE);
            let request_stream = reader.map(|item| match item {
                Ok(chunk) => Ok(fo::WriteRequest {
                    write_request_type: Some(fo::write_request::WriteRequestType::Chunk(
                        fo::Chunk { chunk },
                    )),
                }),
                Err(err) => Err(Error::new(
                    ErrorCode::Transient,
                    format!("omniverse-storage-service: LocalFile read error: {err}"),
                )),
            });
            Ok((size, request_stream.boxed()))
        }
        Body::Stream(stream) => {
            let known_size = size_hint.unwrap_or(0);
            let stream = body_stream_to_request_stream(stream);
            Ok((known_size, stream))
        }
    }
}

fn chunk_bytes_into_requests(bytes: Vec<u8>) -> Vec<Result<fo::WriteRequest>> {
    if bytes.is_empty() {
        return vec![Ok(fo::WriteRequest {
            write_request_type: Some(fo::write_request::WriteRequestType::Chunk(fo::Chunk {
                chunk: Bytes::new(),
            })),
        })];
    }
    bytes
        .chunks(WRITE_CHUNK_SIZE)
        .map(|slice| {
            Ok(fo::WriteRequest {
                write_request_type: Some(fo::write_request::WriteRequestType::Chunk(fo::Chunk {
                    chunk: Bytes::copy_from_slice(slice),
                })),
            })
        })
        .collect()
}

/// Bridge a sync `BodyStream` into an async `Stream` of `WriteRequest`. The
/// iterator runs on a blocking-friendly task; chunks are forwarded one at a
/// time so peak in-flight memory stays bounded by the channel capacity.
fn body_stream_to_request_stream(
    body: BodyStream,
) -> Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<fo::WriteRequest>>(2);
    // BodyStream::next_chunk re-enters tokio via the host's FFI callback
    // (LoadedBackend::run_ffi). spawn_blocking workers inherit the calling
    // runtime context and would deadlock when the callback drives async I/O.
    // A vanilla OS thread severs that context.
    std::thread::Builder::new()
        .name("ovs-oms-body".into())
        .spawn(move || {
            let mut iter = body;
            while let Some(item) = iter.next_chunk() {
                let msg = match item {
                    Ok(bytes) => Ok(fo::WriteRequest {
                        write_request_type: Some(fo::write_request::WriteRequestType::Chunk(
                            fo::Chunk {
                                chunk: Bytes::from(bytes),
                            },
                        )),
                    }),
                    Err(err) => Err(err),
                };
                if tx.blocking_send(msg).is_err() {
                    break;
                }
            }
        })
        .expect("ovs-oms-body thread spawn");
    ReceiverStream::new(rx).boxed()
}

/// Build the bidirectional WriteRequest stream that gets handed to
/// `FileObjectService::write`. The chunk source can fail mid-stream
/// (a `LocalFile` read error, a `BodyStream::next_chunk` error).
/// gRPC client streams have no Err variant, so we forward the first
/// source error through a oneshot channel and end the stream. The
/// caller races that receiver against the server response so it
/// never silently reports success on a partial upload.
fn build_write_request_stream(
    params: fo::WriteRequest,
    chunk_stream: Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>>,
) -> (
    impl Stream<Item = fo::WriteRequest> + Send,
    tokio::sync::oneshot::Receiver<Error>,
) {
    let (err_tx, err_rx) = tokio::sync::oneshot::channel::<Error>();
    // Box-pin the combined stream so `StreamExt::next` (which requires
    // `Self: Unpin`) can be called inside the unfold closure — the
    // `Once<async block>` half isn't Unpin on its own.
    let combined: Pin<Box<dyn Stream<Item = Result<fo::WriteRequest>> + Send>> =
        futures::stream::once(async move { Ok::<fo::WriteRequest, Error>(params) })
            .chain(chunk_stream)
            .boxed();
    let stream = futures::stream::unfold(
        (combined, Some(err_tx)),
        |(mut inner, mut err_tx)| async move {
            match inner.next().await {
                None => None,
                Some(Ok(req)) => Some((req, (inner, err_tx))),
                Some(Err(err)) => {
                    if let Some(tx) = err_tx.take() {
                        let _ = tx.send(err);
                    }
                    None
                }
            }
        },
    );
    (stream, err_rx)
}

#[cfg(test)]
mod acl_tests {
    use super::*;
    use ovstorage_services_protos::google::protobuf::{ListValue, Value, value::Kind};

    fn list_value(strings: &[&str]) -> md::UserMetadataValue {
        let values: Vec<Value> = strings
            .iter()
            .map(|s| Value {
                kind: Some(Kind::StringValue((*s).into())),
            })
            .collect();
        md::UserMetadataValue {
            value: Some(Value {
                kind: Some(Kind::ListValue(ListValue { values })),
            }),
            etag: String::new(),
        }
    }

    #[test]
    fn read_only_grants_read() {
        let g = parse_acl_grants(&list_value(&["read"]));
        assert_eq!(
            g,
            AccessOps {
                read: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn write_grants_write_and_update_metadata() {
        let g = parse_acl_grants(&list_value(&["write"]));
        assert_eq!(
            g,
            AccessOps {
                write: true,
                update_metadata: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn admin_grants_delete() {
        let g = parse_acl_grants(&list_value(&["admin"]));
        assert_eq!(
            g,
            AccessOps {
                delete: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn full_acl_grants_everything() {
        let g = parse_acl_grants(&list_value(&["read", "write", "admin"]));
        assert_eq!(g, grant_all());
    }

    #[test]
    fn unknown_tokens_are_ignored() {
        let g = parse_acl_grants(&list_value(&["banana", "read", "moderator"]));
        assert_eq!(
            g,
            AccessOps {
                read: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn malformed_value_grants_nothing() {
        let bad = md::UserMetadataValue {
            value: Some(Value {
                kind: Some(Kind::StringValue("not-a-list".into())),
            }),
            etag: String::new(),
        };
        assert_eq!(parse_acl_grants(&bad), AccessOps::default());
    }
}

/// Storage-core publishes folder mutations under these event-type names.
/// Mirrors `provider_omnistorage` `StorageProvider.cpp:3175-3180`.
const WATCH_EVENT_TYPES: &[&str] = &[
    "omni.storage.created",
    "omni.storage.deleted",
    "omni.storage.dir_created",
    "omni.storage.dir_deleted",
];

fn build_watch_filter_groups(prefix: &str, recursive: bool) -> Vec<notif::FilterGroup> {
    let filter_type = if recursive {
        notif::resource_filter::FilterType::StartsWithGreedy
    } else {
        notif::resource_filter::FilterType::StartsWithLazy
    } as i32;
    WATCH_EVENT_TYPES
        .iter()
        .map(|event_type| notif::FilterGroup {
            event_type: (*event_type).to_string(),
            filters: vec![notif::ResourceFilter {
                filter_type,
                resource_id: prefix.to_string(),
            }],
        })
        .collect()
}

/// Bridge the async ConsumeNonDurableEvents stream into the SPI's sync
/// iterator-shaped `BackendChangeStream`. Mirrors the broker plugin's
/// `auth.rs::drive_upstream_auth` pattern: dedicated thread + per-bridge
/// tokio runtime + std::sync::mpsc, no buffering.
fn spawn_watch_bridge(
    prefix: Url,
    mut server_stream: tonic::Streaming<notif::ConsumeNonDurableEventsResponse>,
) -> BackendChangeStream {
    let (sender, receiver) = std::sync::mpsc::channel::<Result<BackendChangeEvent>>();
    std::thread::Builder::new()
        .name("ovs-oms-watch".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = sender.send(Err(Error::new(
                        ErrorCode::Internal,
                        format!("omniverse-storage-service: watch_directory runtime: {err}"),
                    )));
                    return;
                }
            };
            runtime.block_on(async move {
                loop {
                    let frame = match server_stream.message().await {
                        Ok(Some(frame)) => frame,
                        Ok(None) => return, // Stream closed cleanly.
                        Err(status) => {
                            let _ = sender.send(Err(map_status(status)));
                            return;
                        }
                    };
                    let cursor = WatchDirectoryCursor(frame.reconnect_token.into_bytes());
                    for event in frame.events {
                        match convert_notification_event(&prefix, event, &cursor) {
                            Ok(Some(change)) => {
                                if sender.send(Ok(change)).is_err() {
                                    return;
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                let _ = sender.send(Err(err));
                                return;
                            }
                        }
                    }
                }
            });
        })
        .expect("failed to spawn thread");
    Box::new(receiver.into_iter())
}

fn convert_notification_event(
    prefix: &Url,
    event: notif::Event,
    cursor: &WatchDirectoryCursor,
) -> Result<Option<BackendChangeEvent>> {
    let kind = match event.event_type.as_str() {
        "omni.storage.created" | "omni.storage.dir_created" => ChangeKind::Created,
        "omni.storage.deleted" | "omni.storage.dir_deleted" => ChangeKind::Deleted,
        _ => return Ok(None),
    };
    let resource_address = event_resource_address(&event).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            "omniverse-storage-service watch event missing resource_address",
        )
    })?;
    let address = Url::parse(&resource_address).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service watch event has invalid resource_address {resource_address:?}: {err}"
            ),
        )
    })?;
    ovstorage_plugin::address::strip_prefix(&address, prefix).ok_or_else(|| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "omniverse-storage-service watch event address {address} is outside watched prefix {prefix}"
            ),
        )
    })?;
    let at = event
        .occurred_at
        .as_ref()
        .and_then(crate::convert::timestamp_to_system_time)
        .unwrap_or_else(std::time::SystemTime::now);
    // the Notifications API `EventConsumerService` notification carries `event_type`,
    // `principal_identity`, `occurred_at`/`published_at`, and a generic
    // `message: google.protobuf.Struct` whose only consumed field today is
    // `resource_address`. The notification surface does not publish an
    // object etag, resource_identity, size, or object mtime alongside the
    // event, so those descriptive fields stay `None` until the Storage API wire
    // adds them.
    Ok(Some(BackendChangeEvent::Object {
        address,
        kind,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        at,
        cursor: cursor.clone(),
    }))
}

fn event_resource_address(event: &notif::Event) -> Option<String> {
    use ovstorage_services_protos::google::protobuf::value::Kind;
    let message = event.message.as_ref()?;
    let value = message.fields.get("resource_address")?;
    match value.kind.as_ref()? {
        Kind::StringValue(s) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;
    use ovstorage_services_protos::google::protobuf::{Struct, Value, value::Kind};

    fn make_event(event_type: &str, resource_address: &str) -> notif::Event {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "resource_address".to_string(),
            Value {
                kind: Some(Kind::StringValue(resource_address.into())),
            },
        );
        notif::Event {
            event_type: event_type.into(),
            principal_identity: String::new(),
            occurred_at: None,
            published_at: None,
            message: Some(Struct {
                fields: fields.into_iter().collect(),
            }),
        }
    }

    #[test]
    fn maps_created_event_and_strips_prefix() {
        let cursor = WatchDirectoryCursor(b"tok".to_vec());
        let evt = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.storage.created", "omni://server/folder/file.usd"),
            &cursor,
        )
        .unwrap()
        .expect("event present");
        match evt {
            BackendChangeEvent::Object {
                address,
                kind,
                cursor: c,
                ..
            } => {
                assert_eq!(address.as_str(), "omni://server/folder/file.usd");
                assert!(matches!(kind, ChangeKind::Created));
                assert_eq!(c.0, b"tok");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn maps_dir_deleted_event() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let evt = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.storage.dir_deleted", "omni://server/folder/sub"),
            &cursor,
        )
        .unwrap()
        .expect("event present");
        match evt {
            BackendChangeEvent::Object { kind, .. } => {
                assert!(matches!(kind, ChangeKind::Deleted));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ignores_unknown_event_type() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let evt = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.other.event", "omni://server/folder/x"),
            &cursor,
        )
        .unwrap();
        assert!(evt.is_none());
    }

    #[test]
    fn errors_on_event_without_resource_address() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let event = notif::Event {
            event_type: "omni.storage.created".into(),
            principal_identity: String::new(),
            occurred_at: None,
            published_at: None,
            message: None,
        };
        let err =
            convert_notification_event(&Url::parse("omni://server/").unwrap(), event, &cursor)
                .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn errors_on_event_outside_watched_prefix() {
        let cursor = WatchDirectoryCursor(Vec::new());
        let err = convert_notification_event(
            &Url::parse("omni://server/folder/").unwrap(),
            make_event("omni.storage.created", "omni://server/other/file.usd"),
            &cursor,
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }
}

/// RAII abort guard for in-flight multipart uploads.
struct MultipartAborter {
    transport: OmniverseStorageTransport,
    destination: String,
    upload_id: String,
    armed: bool,
}

impl MultipartAborter {
    fn disarm(mut self) {
        self.armed = false;
    }

    async fn abort_now(self) {
        let mut this = self;
        if !this.armed {
            return;
        }
        this.armed = false;
        if let Ok(mut client) = this.transport.fileobject_client().await {
            let _ = client
                .abort_multipart_upload(fo::AbortMultipartUploadRequest {
                    upload_id: std::mem::take(&mut this.upload_id),
                    destination_resource_address: std::mem::take(&mut this.destination),
                })
                .await;
        }
    }
}

impl Drop for MultipartAborter {
    fn drop(&mut self) {
        // Sync drop can't issue an async abort. The on-success path calls
        // `disarm()`; on-error paths above call `abort_now().await` before
        // dropping. If we hit Drop while still armed (panic, early return
        // we missed), log so the orphan upload is visible.
        if self.armed {
            tracing::warn!(
                target: "ovstorage.omniverse_storage_service.write_redirect",
                upload_id = %self.upload_id,
                "omniverse-storage-service: multipart aborter dropped while armed; \
                 server-side garbage collection should reclaim parts"
            );
        }
    }
}

#[cfg(test)]
mod multipart_sizing_tests {
    use super::*;

    /// Mirror `part_redirect`'s balanced split rule so the
    /// assertions match what the host would actually send on the
    /// wire. Distribute the remainder as +1 across the first parts
    /// — `[base+1, base+1, ..., base, base]`.
    fn part_sizes(size: u64, total_parts: u32) -> Vec<u64> {
        let total = total_parts as u64;
        let base = size / total;
        let remainder = size % total;
        (0..total_parts)
            .map(|i| {
                if (i as u64) < remainder {
                    base + 1
                } else {
                    base
                }
            })
            .collect()
    }

    /// Reviewer's concrete case: 11-byte upload with `min=5`, no
    /// other constraints. The old code picked total_parts = ceil(11/5)
    /// = 3, then `part_redirect` produced 4/4/3 — the last part
    /// violates `min`. The right answer is a single 11-byte part
    /// (or 6/5); pick the smallest viable count to minimize
    /// per-part overhead.
    #[test]
    fn min_only_size_11_min_5_picks_single_part() {
        let total = compute_total_parts(11, Some(5), None, None).expect("constraints satisfiable");
        assert_eq!(total, 1);
        let parts = part_sizes(11, total);
        assert_eq!(parts, vec![11]);
        assert!(
            parts.iter().all(|&p| p >= 5),
            "every part must be >= min=5; got {parts:?}",
        );
    }

    /// `max_parts_number` is the field the old code ignored. With
    /// no other constraints, it shouldn't force a split — a single
    /// part is fine.
    #[test]
    fn max_parts_only_picks_single_part_when_no_size_constraint() {
        let total = compute_total_parts(11, None, None, Some(4)).expect("constraints satisfiable");
        assert_eq!(total, 1);
    }

    /// `max_parts_number` actively constrains: 11 bytes, max=3,
    /// max_parts=2 → we'd want 4 parts to fit under max=3, but
    /// max_parts=2 says we can only have 2 parts. Constraints are
    /// jointly unsatisfiable (no way to have 2 parts of size <=3
    /// covering 11 bytes); fail loudly.
    #[test]
    fn unsatisfiable_constraints_error() {
        let err = compute_total_parts(11, None, Some(3), Some(2))
            .expect_err("max=3, max_parts=2 can't cover 11 bytes");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    /// `min=max` doesn't divide evenly: 11 bytes, min=max=5 →
    /// ceil(11/5)=3 parts of <=5, but floor(11/5)=2 parts of >=5;
    /// unsatisfiable.
    #[test]
    fn min_equal_max_non_multiple_errors() {
        let err = compute_total_parts(11, Some(5), Some(5), None)
            .expect_err("size=11, min=max=5 is unsatisfiable");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    /// All three constraints in harmony: 11 bytes, min=5, max=10,
    /// max_parts=2. Both bounds agree on 2 parts (6, 5).
    #[test]
    fn all_three_constraints_pick_two_parts() {
        let total =
            compute_total_parts(11, Some(5), Some(10), Some(2)).expect("constraints satisfiable");
        assert_eq!(total, 2);
        let parts = part_sizes(11, total);
        assert_eq!(parts, vec![6, 5]);
        assert!(parts.iter().all(|&p| (5..=10).contains(&p)));
    }

    /// Existing-shape regression: 2 MiB upload, min=1, max=1 MiB,
    /// max_parts=2 (the test mock's hardcoded values). Expect 2
    /// equal 1 MiB parts.
    #[test]
    fn existing_two_mib_two_parts_matches_prior_behavior() {
        let size = 2 * 1024 * 1024;
        let total = compute_total_parts(size, Some(1), Some(1024 * 1024), Some(2))
            .expect("constraints satisfiable");
        assert_eq!(total, 2);
        let parts = part_sizes(size, total);
        assert_eq!(parts, vec![1024 * 1024, 1024 * 1024]);
    }

    /// `Some(0)` is treated as "unconstrained" — matches the proto's
    /// optional-but-uint convention.
    #[test]
    fn zero_constraint_is_unconstrained() {
        let total =
            compute_total_parts(11, Some(0), Some(0), Some(0)).expect("zero means unconstrained");
        assert_eq!(total, 1);
    }

    /// No constraints at all → single-part upload.
    #[test]
    fn no_constraints_picks_single_part() {
        let total = compute_total_parts(11, None, None, None).expect("unconstrained");
        assert_eq!(total, 1);
    }

    /// Small object with max_size present: 100 bytes, min=10, max=40,
    /// max_parts=3. min_parts_by_size = ceil(100/40)=3, max_parts=3.
    /// total=3 → 100/3 = 33 with remainder 1, so parts of 34, 33, 33,
    /// all in [10,40].
    #[test]
    fn medium_object_three_parts_all_in_range() {
        let total =
            compute_total_parts(100, Some(10), Some(40), Some(3)).expect("constraints satisfiable");
        assert_eq!(total, 3);
        let parts = part_sizes(100, total);
        assert_eq!(parts, vec![34, 33, 33]);
        assert!(parts.iter().all(|&p| (10..=40).contains(&p)));
    }

    /// Reviewer's regression case: size=16, min=5, max=6 forces
    /// total=3, but ceil(16/3)=6 leaves the last part at 4 (below
    /// min). The balanced split 6/5/5 stays within [5,6].
    #[test]
    fn size_16_min_5_max_6_balanced_split_avoids_under_min_last_part() {
        let total =
            compute_total_parts(16, Some(5), Some(6), None).expect("constraints satisfiable");
        assert_eq!(total, 3);
        let parts = part_sizes(16, total);
        assert_eq!(
            parts,
            vec![6, 5, 5],
            "balanced split must keep every part in [min, max]; \
             ceil(size/total) would have produced 6/6/4 with the last below min=5",
        );
        assert_eq!(parts.iter().sum::<u64>(), 16);
        assert!(
            parts.iter().all(|&p| (5..=6).contains(&p)),
            "every part must satisfy 5 <= p <= 6; got {parts:?}",
        );
    }

    /// `compute_total_parts` must guard the `as u32` cast: a huge
    /// upload with a small max and no other constraints would
    /// otherwise truncate silently.
    #[test]
    fn parts_count_overflowing_u32_errors() {
        // 5 * 2^32 bytes with max=1 → 5 * 2^32 parts > u32::MAX.
        let huge = 5u64 << 32;
        let err = compute_total_parts(huge, None, Some(1), None)
            .expect_err("more than u32::MAX parts must be refused");
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    /// Realistic S3-shaped backend (min=5 MiB, max=5 GiB): a 10 GiB
    /// upload with the OLD smallest-count algorithm produced 2 parts
    /// of 5 GiB (terrible for retry granularity and parallelism).
    /// The target-based algorithm aims for ~32 MiB parts and picks
    /// 320, giving real parallelism without exceeding the max.
    #[test]
    fn s3_shaped_10gib_upload_uses_target_part_size() {
        let mib = 1024 * 1024u64;
        let gib = 1024 * mib;
        let total = compute_total_parts(10 * gib, Some(5 * mib), Some(5 * gib), None)
            .expect("constraints satisfiable");
        // 10 GiB / 32 MiB = 320.
        assert_eq!(total, 320);
        let parts = part_sizes(10 * gib, total);
        // Every part should be ~32 MiB (within [5 MiB, 5 GiB]).
        assert!(
            parts.iter().all(|&p| (5 * mib..=5 * gib).contains(&p)),
            "every part must be in [5 MiB, 5 GiB]; got len={} first={} last={}",
            parts.len(),
            parts[0],
            parts[parts.len() - 1],
        );
        assert_eq!(parts.iter().sum::<u64>(), 10 * gib);
    }

    /// max_parts cap dominates the target: a 500 GiB upload with
    /// S3-like (min=5 MiB, max=5 GiB) and max_parts=10000 (S3's
    /// real cap) — the target wants 16000 parts but we clamp to
    /// 10000 parts of ~50 MiB.
    #[test]
    fn s3_shaped_500gib_upload_clamps_to_max_parts() {
        let mib = 1024 * 1024u64;
        let gib = 1024 * mib;
        let total = compute_total_parts(500 * gib, Some(5 * mib), Some(5 * gib), Some(10_000))
            .expect("constraints satisfiable");
        assert_eq!(total, 10_000);
        let parts = part_sizes(500 * gib, total);
        // Every part ~50 MiB, all within [5 MiB, 5 GiB].
        assert!(parts.iter().all(|&p| (5 * mib..=5 * gib).contains(&p)));
        assert_eq!(parts.iter().sum::<u64>(), 500 * gib);
    }

    /// Tight `[min, max]` ranges should still respect the hard
    /// `min_parts_for_max_size` lower bound even when the target
    /// part size lands above max. Reviewer's case: target wants
    /// 1 part of 16 bytes (target=32 MiB > 16), but max=6 forces
    /// 3 parts.
    #[test]
    fn target_clamped_up_to_min_parts_when_max_is_tight() {
        let total = compute_total_parts(16, Some(5), Some(6), None).expect("satisfiable");
        // 32 MiB target / 16 byte upload would naively be 1, but
        // ceil(16/6) = 3 dominates.
        assert_eq!(total, 3);
    }
}
