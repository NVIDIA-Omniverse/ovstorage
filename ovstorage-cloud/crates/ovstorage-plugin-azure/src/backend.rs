// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `shim::Backend` implementation for Azure Blob Storage and ADLS Gen2.
//!
//! One backend instance is bound to a `(account, container, hns_flag)` triple
//! and a resolved `AzureAuth`. Every public trait method funnels through the
//! synchronous `AzureClient` for non-redirected requests, or returns a
//! `ReadResult::Redirect` / `WriteStep::Redirects` so the host follower runs
//! the byte-bearing hops directly against Azure.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::shim;
use ovstorage_plugin::{
    AccessDecision, AccessOps, CancellationToken, Capabilities, ChangeKindSet, ChecksumAlgorithm,
    ChecksumSet, ConnectionId, CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions,
    DeleteOptions, Error, ErrorCode, ErrorContext, HttpRequest, IfDestExists, ListOptions,
    ListVersionsOptions, MtimeFormat, ObjectInfo, ObjectKind, ReadOptions, ReadRedirect,
    RedirectBodySource, RedirectResultBatch, RedirectScope, RenameOptions, ResolvedTarget,
    ResponseParsing, Result, ResultCapture, StatOptions, UpdateMetadataOptions, VersionListOrder,
    WatchDirectoryOptions, WriteOptions, WriteRedirect, WriteRedirectBatch, WriteResult, address,
    race_cancel, reject_pinned_for_mutation, validate_redirect_results,
};

/// Pull the legacy `(if_match_etag, no_overwrite)` pair out of the new
/// `IfDestExists` discriminator. Azure's wire protocol uses two separate
/// HTTP headers (`If-Match` and `If-None-Match: *`) for these two cases,
/// so the multipart-continuation envelope and lower-level write helpers
/// thread them around as `(etag, no_overwrite)`.
#[inline]
fn split_if_dest(if_dest: &IfDestExists) -> (Option<String>, bool) {
    match if_dest {
        IfDestExists::Overwrite => (None, false),
        IfDestExists::Fail => (None, true),
        IfDestExists::MatchEtag(etag) => (Some(etag.clone()), false),
    }
}

enum FlatDirectoryProbe {
    Missing,
    Marker(Box<ObjectInfo>),
    Inferred,
}

const PINNED_VERSION_KEYS: &[&str] = &["versionid"];
pub use ovstorage_plugin::{BackendChangeStream, BackendItemInfo, ReadResult, WriteStep};

use tracing::{Instrument, debug_span};

use crate::auth::{AuthSource, AzureAuth};
use crate::client::{AzureClient, AzureRequest, map_status_to_error};
use crate::config::{AzureAddress, AzureConnectionConfig};
use crate::convert::require_etag_only_if_match;

/// Display wrapper that strips query params and fragment from a URL before logging.
/// Signed URLs (SAS tokens) embed credentials in query strings; this prevents accidental leakage.
struct RedactedUrl<'a>(&'a ovstorage_plugin::Url);

impl std::fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let u = self.0;
        write!(
            f,
            "{}://{}{}",
            u.scheme(),
            u.host_str().unwrap_or(""),
            u.path()
        )
    }
}

use crate::parse::{
    HNS_SYSTEM_METADATA_HEADERS, SYSTEM_METADATA_HEADERS, blob_to_object_info,
    blob_to_version_item, dfs_paths_to_object_infos, list_xml_to_object_infos, parse_blob_list_xml,
    parse_dfs_path_list_json, parse_object_info,
};
use crate::signing::{DEFAULT_SAS_VERSION, SasPermission, ServiceSasRequest, service_sas_query};

const SAS_LIFETIME_SECS: i64 = 5 * 60;

const AZURE_COPY_POLL_INTERVAL: Duration = Duration::from_millis(500);
const AZURE_COPY_POLL_DEADLINE: Duration = Duration::from_secs(60 * 30);

/// Single-`Put Blob` ceiling; above this, switch to staged `Put Block` + `Put Block List`.
/// Conservative vs the modern 5000 MiB cap to keep headroom for older API versions
/// pinned to the legacy 256 MiB / 100 MiB ceilings.
const AZURE_STAGED_THRESHOLD_BYTES: u64 = 256 * 1024 * 1024;

/// `write_stream` inline-vs-staged cutover. For known-size streams at or below this
/// threshold we drain a single buffer and submit one `Put Blob`. Above the cutover
/// (and for unknown sizes) we stage blocks at `AZURE_BLOCK_SIZE_BYTES` granularity
/// and finalize with `Put Block List`.
const AZURE_SINGLE_PUT_THRESHOLD_BYTES: u64 = 4 * 1024 * 1024;

/// Per-block size for staged commit. 4 MiB keeps redirect payloads small while staying within
/// Azure's 50000-block-per-blob limit for objects up to ~200 GiB (Azure max block is 4000 MiB).
const AZURE_BLOCK_SIZE_BYTES: u64 = 4 * 1024 * 1024;

/// Max staged-commit size: 50000 blocks × 4 MiB = 200 GiB. Above this returns Unsupported
/// instead of producing an XML commit Azure rejects with `BlockCountExceedsLimit`.
const AZURE_STAGED_MAX_BYTES: u64 = 50_000 * AZURE_BLOCK_SIZE_BYTES;

/// Azure Blob / ADLS Gen2 backend instance.
pub struct AzureBackend {
    pub(crate) config: Arc<AzureConnectionConfig>,
    pub(crate) client: AzureClient,
}

impl AzureBackend {
    pub(crate) fn new(config: AzureConnectionConfig, auth: AzureAuth) -> Result<Self> {
        Self::with_auth(config, auth)
    }

    /// Test-only constructor exposed via `__test_only_with_credentials`.
    #[doc(hidden)]
    pub fn with_auth(config: AzureConnectionConfig, auth: AzureAuth) -> Result<Self> {
        let client = AzureClient::new(config.account.clone(), auth)?;
        Ok(Self {
            config: Arc::new(config),
            client,
        })
    }

    pub(crate) fn capabilities(&self) -> Capabilities {
        azure_capabilities(
            self.config.hierarchical_namespace,
            self.config.change_feed_enabled,
        )
    }

    async fn flat_directory_probe(
        &self,
        prefix: &str,
        address: &ovstorage_plugin::Url,
    ) -> Result<FlatDirectoryProbe> {
        let base_url = format!("{}/{}", self.config.blob_url_base(), self.config.container);
        let canonical_path = format!("/{}", self.config.container);
        let query: Vec<(String, String)> = vec![
            ("restype".into(), "container".into()),
            ("comp".into(), "list".into()),
            ("prefix".into(), prefix.to_string()),
            ("delimiter".into(), "/".into()),
            ("maxresults".into(), "2".into()),
        ];
        let req = AzureRequest {
            method: reqwest::Method::GET,
            url: format!("{}?{}", base_url, encode_query(&query)),
            canonical_path: &canonical_path,
            canonical_query: query,
            extra_headers: vec![],
            content_type: None,
            content_md5: None,
            if_match: None,
            if_none_match: None,
            range: None,
            body: None,
        };
        let response = self.client.send(req).await?;
        if !response.ok() {
            return Err(map_status_to_error(&response, "stat prefix probe"));
        }
        let parsed = parse_blob_list_xml(response.body_str()?)?;
        if let Some(marker) = parsed.items.iter().find(|blob| blob.name == prefix) {
            let mut info = blob_to_object_info(marker, address.clone());
            info.kind = ObjectKind::DirectoryMarker;
            return Ok(FlatDirectoryProbe::Marker(Box::new(info)));
        }
        let mut descendant_seen = false;
        for blob in &parsed.items {
            if !blob.name.starts_with(prefix) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "Azure returned blob '{}' outside requested stat prefix '{}'",
                        blob.name, prefix
                    ),
                ));
            }
            descendant_seen = true;
        }
        for child in &parsed.prefixes {
            if child == prefix {
                continue;
            }
            if !child.starts_with(prefix) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "Azure returned blob prefix '{}' outside requested stat prefix '{}'",
                        child, prefix
                    ),
                ));
            }
            descendant_seen = true;
        }
        Ok(if descendant_seen {
            FlatDirectoryProbe::Inferred
        } else {
            FlatDirectoryProbe::Missing
        })
    }

    fn validate_target(&self, target: &ResolvedTarget) -> Result<()> {
        let parsed = AzureAddress::parse(&target.resolved_address)?;
        if parsed.account != self.config.account || parsed.container != self.config.container {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "azure address is outside the configured account/container",
            ));
        }
        Ok(())
    }

    fn require_blob_address(&self, target: &ResolvedTarget) -> Result<AzureAddress> {
        let parsed = AzureAddress::parse(&target.resolved_address)?;
        if parsed.account != self.config.account || parsed.container != self.config.container {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "azure address is outside the configured account/container",
            ));
        }
        if parsed.key.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "Azure operation requires a non-empty blob key",
            ));
        }
        Ok(parsed)
    }

    fn blob_url(&self, blob_key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.config.blob_url_base(),
            self.config.container,
            url_encode_path(blob_key),
        )
    }

    /// Build the URL handed to Azure as `x-ms-copy-source`. Under SharedKey we mint a 5-minute
    /// read-only Service SAS so the destination's principal authorizes the source read; under
    /// caller-supplied SAS we re-attach the token; OAuth/Anonymous use the bare URL.
    /// `version_id` pins the source via `?versionid=...`.
    fn copy_source_url(&self, blob_key: &str, version_id: Option<&str>) -> Result<String> {
        let mut url = self.blob_url(blob_key);
        if let Some(vid) = version_id {
            url.push_str(&format!("?versionid={}", urlencoding::encode(vid)));
        }
        match self.client.auth().source() {
            AuthSource::SharedKey { account_key_bytes } => {
                let expiry = format_sas_expiry(SAS_LIFETIME_SECS);
                let sas = service_sas_query(
                    account_key_bytes,
                    &ServiceSasRequest {
                        account: &self.config.account,
                        container: &self.config.container,
                        blob_path: blob_key,
                        permissions: &[SasPermission::Read],
                        start: None,
                        expiry: &expiry,
                        protocol: Some("https"),
                        version: DEFAULT_SAS_VERSION,
                    },
                )?;
                let sep = if url.contains('?') { '&' } else { '?' };
                Ok(format!("{url}{sep}{sas}"))
            }
            AuthSource::Sas { sas_token } => {
                let sep = if url.contains('?') { '&' } else { '?' };
                Ok(format!("{url}{sep}{sas_token}"))
            }
            AuthSource::Oauth2ClientSecret { .. }
            | AuthSource::Oauth2Federated { .. }
            | AuthSource::Anonymous => Ok(url),
        }
    }

    fn dfs_url(&self, path: &str) -> String {
        let trimmed = path.trim_start_matches('/');
        format!(
            "{}/{}/{}",
            self.config.dfs_url_base(),
            self.config.container,
            url_encode_path(trimmed),
        )
    }

    fn canonical_path_for_blob(&self, blob_key: &str) -> String {
        format!("/{}/{}", self.config.container, blob_key)
    }

    fn canonical_path_for_dfs(&self, path: &str) -> String {
        format!(
            "/{}/{}",
            self.config.container,
            path.trim_start_matches('/')
        )
    }

    fn user_metadata_headers(
        &self,
        user_metadata: Option<&ovstorage_plugin::UserMetadata>,
    ) -> Vec<(String, String)> {
        user_metadata
            .map(|map| {
                map.iter()
                    .map(|(k, v)| (format!("x-ms-meta-{k}"), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn url_encode_path(key: &str) -> String {
    // Encode each segment but preserve `/` so path structure survives.
    key.split('/')
        .map(|seg| urlencoding::encode(seg).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Capability vector for an Azure connection; HNS flips real-directory and server-side rename flags.
pub(crate) fn azure_capabilities(
    hierarchical_namespace: bool,
    change_feed_enabled: bool,
) -> Capabilities {
    let mut caps = Capabilities::empty();
    caps.supports_no_overwrite_write = true;
    caps.supports_if_match_write = true;
    caps.supports_native_metadata_patch = true;
    caps.supports_metadata_rewrite_emulation = false;
    caps.writes_are_atomic = true;
    caps.supports_write = true;
    caps.supports_write_stream = true;
    caps.supports_write_redirect = true;
    caps.supports_delete = true;
    caps.supports_server_side_copy = true;
    caps.supports_version_listing = true;
    caps.version_list_order = Some(VersionListOrder::Oldest);
    caps.has_real_directories = hierarchical_namespace;
    caps.supports_list = true;
    caps.wants_list_backed_stat = true;
    caps.supports_recursive_list = true;
    caps.supports_create_directory = true;
    caps.supports_delete_directory = true;
    caps.populates_subdirectory_metadata = hierarchical_namespace;
    caps.supports_server_side_rename = hierarchical_namespace;
    caps.supports_atomic_rename = hierarchical_namespace;
    let supports_watch_directory = change_feed_enabled && !hierarchical_namespace;
    caps.supports_watch_directory = supports_watch_directory;
    caps.watch_directory_kinds = if supports_watch_directory {
        ChangeKindSet {
            created: true,
            modified: false,
            deleted: true,
            metadata_changed: true,
        }
    } else {
        ChangeKindSet::empty()
    };
    caps.watch_directory_resumable = false;
    caps.watch_directory_max_lag = supports_watch_directory.then_some(Duration::from_secs(120));
    caps
}

#[async_trait::async_trait]
impl shim::Backend for AzureBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = debug_span!(
            "azure.stat",
            op = "stat",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        let _ = opts;
        race_cancel(
            cancel.as_ref(),
            async move {
                let parsed = self.require_blob_address(&target)?;
                let blob_key = parsed.key.clone();
                let version_id = parsed.version_id.clone();
                if self.config.hierarchical_namespace {
                    let mut canonical_query: Vec<(String, String)> =
                        vec![("action".into(), "getStatus".into())];
                    if let Some(vid) = version_id.as_ref() {
                        canonical_query.push(("versionid".into(), vid.clone()));
                    }
                    let url = format!(
                        "{}?{}",
                        self.dfs_url(&blob_key),
                        encode_query(&canonical_query)
                    );
                    let canonical_path = self.canonical_path_for_dfs(&blob_key);
                    let req = AzureRequest {
                        method: reqwest::Method::HEAD,
                        url,
                        canonical_path: &canonical_path,
                        canonical_query,
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    };
                    let response = self.client.send(req).await?;
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "stat"));
                    }
                    parse_object_info(target.resolved_address.clone(), &response.headers, true)
                } else {
                    let mut canonical_query: Vec<(String, String)> = Vec::new();
                    let url = if let Some(vid) = version_id.as_ref() {
                        canonical_query.push(("versionid".into(), vid.clone()));
                        format!(
                            "{}?versionid={}",
                            self.blob_url(&blob_key),
                            urlencoding::encode(vid)
                        )
                    } else {
                        self.blob_url(&blob_key)
                    };
                    let canonical_path = self.canonical_path_for_blob(&blob_key);
                    let req = AzureRequest {
                        method: reqwest::Method::HEAD,
                        url,
                        canonical_path: &canonical_path,
                        canonical_query,
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    };
                    let response = self.client.send(req).await?;
                    // Flat Azure-Blob is a prefix namespace: the
                    // dispatcher folds directory markers on `list`, but
                    // `stat` runs here. For a trailing-slash address,
                    // the HEAD probes the zero-byte marker directly.
                    // Hit → tag `DirectoryMarker`. If the marker is
                    // missing, a bounded prefix-list probe must prove
                    // a descendant exists before we surface
                    // `DirectoryInferred`.
                    let trailing_slash = blob_key.ends_with('/');
                    if response.status == 404 {
                        if trailing_slash && version_id.is_none() {
                            match self
                                .flat_directory_probe(&blob_key, &target.resolved_address)
                                .await?
                            {
                                FlatDirectoryProbe::Marker(info) => return Ok(*info),
                                FlatDirectoryProbe::Inferred => {
                                    return Ok(ObjectInfo {
                                        address: target.resolved_address.clone(),
                                        kind: ObjectKind::DirectoryInferred,
                                        etag: None,
                                        version: None,
                                        size: None,
                                        mtime: None,
                                        checksums: Default::default(),
                                        effective_permissions: None,
                                        system_metadata: None,
                                        user_metadata: None,
                                        modified_by: None,
                                    });
                                }
                                FlatDirectoryProbe::Missing => {}
                            }
                        }
                        return Err(map_status_to_error(&response, "stat"));
                    }
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "stat"));
                    }
                    let mut info = parse_object_info(
                        target.resolved_address.clone(),
                        &response.headers,
                        false,
                    )?;
                    if trailing_slash {
                        info.kind = ObjectKind::DirectoryMarker;
                    }
                    Ok(info)
                }
            }
            .instrument(span),
        )
        .await
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        require_etag_only_if_match(opts.if_match.as_ref())?;
        // Validate any byte range before we sign a URL we couldn't honor.
        let _range_header = opts.range.as_ref().map(read_range_header).transpose()?;
        let span = debug_span!(
            "azure.read",
            op = "read",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parsed = self.require_blob_address(&target)?;
                let blob_key = parsed.key.clone();
                let version_id = parsed.version_id.clone();
                let mut url = self.blob_url(&blob_key);
                if let Some(vid) = version_id.as_ref() {
                    url.push_str(&format!("?versionid={}", urlencoding::encode(vid)));
                }
                let mut headers: Vec<(String, String)> = Vec::new();
                headers.push(("x-ms-version".to_string(), DEFAULT_SAS_VERSION.to_string()));
                if let Some(range) = opts.range.as_ref() {
                    // Pre-validated at entry; this can't fail now, but
                    // we propagate the error rather than panic.
                    headers.push(("Range".into(), read_range_header(range)?));
                }
                if let Some(if_match) = opts.if_match.as_ref() {
                    // Azure requires RFC 7232 entity-tag quoting; the
                    // SPI documents `if_match` as the raw value the
                    // backend returned. `quote_etag` is a no-op if the
                    // caller already supplied the quoted form.
                    headers.push(("If-Match".into(), quote_etag(if_match)));
                }

                let signed_url = match self.client.auth().source() {
                    AuthSource::SharedKey { account_key_bytes } => {
                        let expiry = format_sas_expiry(SAS_LIFETIME_SECS);
                        let sas = service_sas_query(
                            account_key_bytes,
                            &ServiceSasRequest {
                                account: &self.config.account,
                                container: &self.config.container,
                                blob_path: &blob_key,
                                permissions: &[SasPermission::Read],
                                start: None,
                                expiry: &expiry,
                                protocol: Some("https"),
                                version: DEFAULT_SAS_VERSION,
                            },
                        )?;
                        let sep = if url.contains('?') { '&' } else { '?' };
                        format!("{url}{sep}{sas}")
                    }
                    AuthSource::Sas { sas_token } => {
                        let sep = if url.contains('?') { '&' } else { '?' };
                        format!("{url}{sep}{sas_token}")
                    }
                    AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
                        let bearer = self.client.auth().bearer_token(self.client.http()).await?;
                        headers.push(("Authorization".into(), format!("Bearer {bearer}")));
                        url.clone()
                    }
                    AuthSource::Anonymous => url.clone(),
                };

                // Azure emits `Content-MD5` (whole-blob, set if uploaded with one). MD5 is the only
                // verifier algorithm Azure surfaces on a GET response; the host verifier handles it inline.
                let mut checksum_headers = std::collections::HashMap::new();
                checksum_headers.insert(ChecksumAlgorithm::md5(), "Content-MD5".into());
                let mut response_parsing = ResponseParsing {
                    etag_header: Some("etag".into()),
                    version_header: Some("x-ms-version-id".into()),
                    size_header: Some("content-length".into()),
                    mtime_header: Some("last-modified".into()),
                    mtime_format: MtimeFormat::Rfc1123,
                    system_metadata_headers: SYSTEM_METADATA_HEADERS
                        .iter()
                        .map(|s| (*s).into())
                        .collect(),
                    content_checksum_header: Some("Content-MD5".into()),
                    content_checksum_algorithm: Some(ChecksumAlgorithm::md5()),
                    checksum_headers,
                };
                if self.config.hierarchical_namespace {
                    for header in HNS_SYSTEM_METADATA_HEADERS {
                        response_parsing
                            .system_metadata_headers
                            .push((*header).to_string());
                    }
                }

                let scope_prefix =
                    format!("{}/{}/", self.config.blob_url_base(), self.config.container);
                let now = SystemTime::now();
                let expires_at = now + Duration::from_secs(SAS_LIFETIME_SECS as u64);
                Ok(ReadResult::Redirect(ReadRedirect {
                    request: HttpRequest {
                        method: "GET".into(),
                        url: signed_url,
                        headers,
                    },
                    response_parsing,
                    expires_at,
                    scope: RedirectScope {
                        physical_url_prefix: scope_prefix,
                        operations: AccessOps {
                            read: true,
                            write: false,
                            delete: false,
                            update_metadata: false,
                        },
                        expires_at,
                    },
                    audit_id: format!("azure-read-{}", monotonic_id()),
                    policy_epoch: 0,
                }))
            }
            .instrument(span),
        )
        .await
    }

    /// Buffered inline write — used by callers writing zero-byte or
    /// sub-`redirect_size_threshold` bodies, where the SAS-redirect
    /// round-trip is pure overhead. Issues a single `Put Blob` directly
    /// from the plugin instead of emitting a `WriteRedirect`.
    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(&target.resolved_address, "azure write", PINNED_VERSION_KEYS)?;
        let span = debug_span!(
            "azure.write",
            op = "write",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = bytes.len() as u64,
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let blob_key = self.require_blob_address(&target)?.key.clone();
                let blob_url = self.blob_url(&blob_key);
                let canonical_path = self.canonical_path_for_blob(&blob_key);
                let mut user_metadata = opts.user_metadata.clone().unwrap_or_default();
                if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                    user_metadata.insert("x-ov-message".to_string(), message.to_string());
                }
                let mut extra_headers: Vec<(String, String)> =
                    vec![("x-ms-blob-type".into(), "BlockBlob".into())];
                extra_headers.extend(self.user_metadata_headers(Some(&user_metadata)));
                let (if_match, no_overwrite) = split_if_dest(&opts.if_dest);
                let if_none_match = if no_overwrite {
                    Some("*".to_string())
                } else {
                    None
                };
                let req = AzureRequest {
                    method: reqwest::Method::PUT,
                    url: blob_url,
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers,
                    content_type: Some("application/octet-stream".into()),
                    content_md5: None,
                    if_match,
                    if_none_match,
                    range: None,
                    body: Some(bytes),
                };
                let response = self.client.send(req).await?;
                if response.status == 412 {
                    return Err(Error::new(
                        ErrorCode::PreconditionFailed,
                        "Azure Put Blob precondition failed",
                    )
                    .with_context(ErrorContext::Identity {
                        new_etag: response
                            .headers
                            .first("etag")
                            .map(|s| s.trim_matches('"').to_string()),
                    }));
                }
                if !response.ok() {
                    return Err(map_status_to_error(&response, "write"));
                }
                let info = parse_object_info(
                    target.resolved_address.clone(),
                    &response.headers,
                    self.config.hierarchical_namespace,
                )?;
                Ok(WriteResult { info })
            }
            .instrument(span),
        )
        .await
    }

    /// Streaming write. Azure supports unknown-size uploads through the
    /// block-staging API (`Put Block` per chunk, then `Put Block List`
    /// to finalize). For known-size streams at or below
    /// `AZURE_SINGLE_PUT_THRESHOLD_BYTES` we drain the body once and
    /// submit a single `Put Blob` instead.
    ///
    /// Errors from the underlying `BodyStream` propagate as-is; we do
    /// not silently drop chunks via `filter_map(|i| i.ok())`.
    async fn write_stream(
        &self,
        target: ResolvedTarget,
        mut body: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "azure write_stream",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "azure.write_stream",
            op = "write",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = opts.size_hint,
        );
        let cancel_inner = cancel.clone();
        race_cancel(
            cancel.as_ref(),
            async move {
                let blob_key = self.require_blob_address(&target)?.key.clone();
                let blob_url = self.blob_url(&blob_key);
                let canonical_path = self.canonical_path_for_blob(&blob_key);

                let mut user_metadata = opts.user_metadata.clone().unwrap_or_default();
                if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                    user_metadata.insert("x-ov-message".to_string(), message.to_string());
                }
                let (if_match, no_overwrite) = split_if_dest(&opts.if_dest);
                let if_none_match = if no_overwrite { Some("*".to_string()) } else { None };

                // Inline path: known size that fits a single `Put Blob`.
                // We still drain the body fully before issuing the
                // request so a mid-stream error surfaces as an upload
                // failure (no partial blob is ever created).
                if let Some(total) = opts.size_hint
                    && total <= AZURE_SINGLE_PUT_THRESHOLD_BYTES
                {
                    let mut buf: Vec<u8> = Vec::with_capacity(total as usize);
                    for chunk in body.by_ref() {
                        let chunk = chunk?;
                        buf.extend_from_slice(&chunk);
                    }
                    let mut extra_headers: Vec<(String, String)> =
                        vec![("x-ms-blob-type".into(), "BlockBlob".into())];
                    extra_headers.extend(self.user_metadata_headers(Some(&user_metadata)));
                    let req = AzureRequest {
                        method: reqwest::Method::PUT,
                        url: blob_url,
                        canonical_path: &canonical_path,
                        canonical_query: vec![],
                        extra_headers,
                        content_type: Some("application/octet-stream".into()),
                        content_md5: None,
                        if_match,
                        if_none_match,
                        range: None,
                        body: Some(buf),
                    };
                    let response = self.client.send(req).await?;
                    if response.status == 412 {
                        return Err(Error::new(
                            ErrorCode::PreconditionFailed,
                            "Azure Put Blob precondition failed",
                        )
                        .with_context(ErrorContext::Identity {
                            new_etag: response
                                .headers
                                .first("etag")
                                .map(|s| s.trim_matches('"').to_string()),
                        }));
                    }
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "write_stream put_blob"));
                    }
                    let info = parse_object_info(
                        target.resolved_address.clone(),
                        &response.headers,
                        self.config.hierarchical_namespace,
                    )?;
                    return Ok(WriteResult { info });
                }

                // Staged path: stream into 4 MiB blocks, `Put Block`
                // each, finalize with `Put Block List`. Block IDs are
                // deterministic (sha256(blob_key)[..12] || seq) so a
                // retry of the same chunk overwrites cleanly.
                let block_size = AZURE_BLOCK_SIZE_BYTES as usize;
                let max_blocks = AZURE_STAGED_MAX_BYTES / AZURE_BLOCK_SIZE_BYTES;
                let mut buffer: Vec<u8> = Vec::with_capacity(block_size);
                let mut block_ids: Vec<String> = Vec::new();
                let mut seq: u32 = 0;

                for chunk in body.by_ref() {
                    let chunk = chunk?;
                    let mut cursor = 0;
                    while cursor < chunk.len() {
                        let take = (block_size - buffer.len()).min(chunk.len() - cursor);
                        buffer.extend_from_slice(&chunk[cursor..cursor + take]);
                        cursor += take;
                        if buffer.len() == block_size {
                            // Honor cancellation at block boundaries.
                            if let Some(token) = cancel_inner.as_ref()
                                && token.is_cancelled()
                            {
                                return Err(Error::new(
                                    ErrorCode::Cancelled,
                                    "cancelled by host",
                                ));
                            }
                            if (seq as u64) >= max_blocks {
                                return Err(Error::new(
                                    ErrorCode::Unsupported,
                                    format!(
                                        "Azure block-blob staged commit caps at 50000 × 4 MiB = {} bytes",
                                        AZURE_STAGED_MAX_BYTES
                                    ),
                                ));
                            }
                            let id = block_id(&blob_key, seq);
                            let id_url_safe = urlencoding::encode(&id);
                            let url = format!("{blob_url}?comp=block&blockid={id_url_safe}");
                            let req_query: Vec<(String, String)> = vec![
                                ("blockid".into(), id.clone()),
                                ("comp".into(), "block".into()),
                            ];
                            let bytes = std::mem::take(&mut buffer);
                            buffer = Vec::with_capacity(block_size);
                            let req = AzureRequest {
                                method: reqwest::Method::PUT,
                                url,
                                canonical_path: &canonical_path,
                                canonical_query: req_query,
                                extra_headers: vec![],
                                content_type: Some("application/octet-stream".into()),
                                content_md5: None,
                                if_match: None,
                                if_none_match: None,
                                range: None,
                                body: Some(bytes),
                            };
                            let response = self.client.send(req).await?;
                            if !response.ok() {
                                return Err(map_status_to_error(
                                    &response,
                                    "write_stream put_block",
                                ));
                            }
                            block_ids.push(id);
                            seq += 1;
                        }
                    }
                }
                // Final, possibly-short, block. Skip if there was no
                // data at all; we still issue Put Block List below.
                if !buffer.is_empty() {
                    if (seq as u64) >= max_blocks {
                        return Err(Error::new(
                            ErrorCode::Unsupported,
                            format!(
                                "Azure block-blob staged commit caps at 50000 × 4 MiB = {} bytes",
                                AZURE_STAGED_MAX_BYTES
                            ),
                        ));
                    }
                    let id = block_id(&blob_key, seq);
                    let id_url_safe = urlencoding::encode(&id);
                    let url = format!("{blob_url}?comp=block&blockid={id_url_safe}");
                    let req_query: Vec<(String, String)> = vec![
                        ("blockid".into(), id.clone()),
                        ("comp".into(), "block".into()),
                    ];
                    let bytes = std::mem::take(&mut buffer);
                    let req = AzureRequest {
                        method: reqwest::Method::PUT,
                        url,
                        canonical_path: &canonical_path,
                        canonical_query: req_query,
                        extra_headers: vec![],
                        content_type: Some("application/octet-stream".into()),
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: Some(bytes),
                    };
                    let response = self.client.send(req).await?;
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "write_stream put_block"));
                    }
                    block_ids.push(id);
                    seq += 1;
                }

                // Finalize. Empty block list is still valid (creates a
                // zero-byte blob) — Azure's Put Block List allows it.
                let xml = build_block_list_xml(&block_ids);
                let mut extra_headers: Vec<(String, String)> = Vec::new();
                extra_headers.extend(self.user_metadata_headers(Some(&user_metadata)));
                extra_headers.push((
                    "x-ms-blob-content-type".into(),
                    "application/octet-stream".into(),
                ));
                let req = AzureRequest {
                    method: reqwest::Method::PUT,
                    url: format!("{blob_url}?comp=blocklist"),
                    canonical_path: &canonical_path,
                    canonical_query: vec![("comp".into(), "blocklist".into())],
                    extra_headers,
                    content_type: Some("application/xml".into()),
                    content_md5: None,
                    if_match,
                    if_none_match,
                    range: None,
                    body: Some(xml.into_bytes()),
                };
                let response = self.client.send(req).await?;
                if response.status == 412 {
                    return Err(Error::new(
                        ErrorCode::PreconditionFailed,
                        "Azure Put Block List precondition failed",
                    )
                    .with_context(ErrorContext::Identity {
                        new_etag: response
                            .headers
                            .first("etag")
                            .map(|s| s.trim_matches('"').to_string()),
                    }));
                }
                if !response.ok() {
                    return Err(map_status_to_error(&response, "write_stream put_block_list"));
                }
                let _ = seq; // last-block count is observable via tracing
                let info = parse_object_info(
                    target.resolved_address.clone(),
                    &response.headers,
                    self.config.hierarchical_namespace,
                )?;
                Ok(WriteResult { info })
            }
            .instrument(span),
        )
        .await
    }

    async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        // A known size is required for write_redirect. Without it
        // we'd have to advertise `len = AZURE_BLOCK_BLOB_MAX_BYTES`
        // on the inline path, producing Content-Length mismatches at
        // the follower; on the staged path we couldn't enumerate the
        // block count up front at all. The host falls back to a buffered
        // upload through `write_stream` when this refusal surfaces.
        if opts.size_hint.is_none() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "azure write_redirect requires a known size_hint; streaming uploads route through write_stream",
            ));
        }
        reject_pinned_for_mutation(
            &target.resolved_address,
            "azure write_redirect",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "azure.write",
            op = "write",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = opts.size_hint,
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                // Two paths:
                //   - size_hint ≤ 256 MiB (or unknown): single SAS-signed `Put Blob` PUT redirect.
                //     Continuation has empty `block_ids`; `continue_write` extracts ETag from captured headers.
                //   - size_hint > 256 MiB: stage `Put Block` redirects per 4 MiB chunk, deterministic
                //     IDs via SHA-256(blob_key)[..12] + 4-byte BE seq. Continuation carries the block-id
                //     list; `continue_write` issues `Put Block List` to commit.
                let blob_key = self.require_blob_address(&target)?.key.clone();
                let blob_url = self.blob_url(&blob_key);
                let now = SystemTime::now();
                let expires_at = now + Duration::from_secs(SAS_LIFETIME_SECS as u64);
                let scope_prefix =
                    format!("{}/{}/", self.config.blob_url_base(), self.config.container);
                let scope = RedirectScope {
                    physical_url_prefix: scope_prefix,
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at,
                };
                let bearer_for_oauth = match self.client.auth().source() {
                    AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
                        Some(self.client.auth().bearer_token(self.client.http()).await?)
                    }
                    _ => None,
                };
                let staged = matches!(
                    opts.size_hint,
                    Some(n) if n > AZURE_STAGED_THRESHOLD_BYTES
                );
                let mut user_metadata = opts.user_metadata.clone().unwrap_or_default();
                if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                    user_metadata.insert("x-ov-message".to_string(), message.to_string());
                }
                if staged {
                    let total = opts.size_hint.expect("matched Some above");
                    if total > AZURE_STAGED_MAX_BYTES {
                        return Err(Error::new(
                            ErrorCode::Unsupported,
                            format!(
                                "Azure block-blob staged commit caps at 50000 × 4 MiB = {} bytes",
                                AZURE_STAGED_MAX_BYTES
                            ),
                        ));
                    }
                    let total_blocks = total.div_ceil(AZURE_BLOCK_SIZE_BYTES);
                    let mut redirects: Vec<WriteRedirect> =
                        Vec::with_capacity(total_blocks as usize);
                    let mut block_ids: Vec<String> = Vec::with_capacity(total_blocks as usize);
                    for seq in 0..total_blocks {
                        let offset = seq * AZURE_BLOCK_SIZE_BYTES;
                        let len = AZURE_BLOCK_SIZE_BYTES.min(total - offset);
                        let id = block_id(&blob_key, seq as u32);
                        block_ids.push(id.clone());
                        let id_url_safe = urlencoding::encode(&id);
                        let block_query = format!("comp=block&blockid={id_url_safe}");
                        let mut headers: Vec<(String, String)> =
                            vec![("x-ms-version".into(), DEFAULT_SAS_VERSION.into())];
                        let url = match self.client.auth().source() {
                            AuthSource::SharedKey { account_key_bytes } => {
                                let expiry = format_sas_expiry(SAS_LIFETIME_SECS);
                                let sas = service_sas_query(
                                    account_key_bytes,
                                    &ServiceSasRequest {
                                        account: &self.config.account,
                                        container: &self.config.container,
                                        blob_path: &blob_key,
                                        permissions: &[SasPermission::Write, SasPermission::Create],
                                        start: None,
                                        expiry: &expiry,
                                        protocol: Some("https"),
                                        version: DEFAULT_SAS_VERSION,
                                    },
                                )?;
                                format!("{blob_url}?{block_query}&{sas}")
                            }
                            AuthSource::Sas { sas_token } => {
                                format!("{blob_url}?{block_query}&{sas_token}")
                            }
                            AuthSource::Oauth2ClientSecret { .. }
                            | AuthSource::Oauth2Federated { .. } => {
                                headers.push((
                                    "Authorization".into(),
                                    format!(
                                        "Bearer {}",
                                        bearer_for_oauth
                                            .as_ref()
                                            .expect("oauth bearer cached above"),
                                    ),
                                ));
                                format!("{blob_url}?{block_query}")
                            }
                            AuthSource::Anonymous => {
                                return Err(Error::new(
                                    ErrorCode::AuthRequired,
                                    "Azure anonymous connections cannot write_redirect",
                                )
                                .with_context(ErrorContext::Auth {
                                    connection_id: ConnectionId(String::new()),
                                    reason: Some("anonymous_no_write".into()),
                                    expired_at: None,
                                }));
                            }
                        };
                        redirects.push(WriteRedirect {
                            request: HttpRequest {
                                method: "PUT".into(),
                                url,
                                headers,
                            },
                            body_source: RedirectBodySource::UserBytes { offset, len },
                            result_capture: ResultCapture {
                                headers: vec!["etag".into()],
                                body_max_bytes: 1024,
                            },
                            expires_at,
                            scope: scope.clone(),
                            audit_id: format!("azure-put-block-{seq}-{}", monotonic_id()),
                            policy_epoch: 0,
                        });
                    }
                    let (if_match_cont, no_overwrite_cont) = split_if_dest(&opts.if_dest);
                    let continuation = WriteContinuation {
                        blob_key,
                        block_ids,
                        user_metadata: if user_metadata.is_empty() {
                            None
                        } else {
                            Some(user_metadata)
                        },
                        if_match: if_match_cont,
                        no_overwrite: no_overwrite_cont,
                        content_type: "application/octet-stream".into(),
                    };
                    return Ok(WriteRedirectBatch {
                        continuation: continuation.encode(),
                        redirects,
                    });
                }
                let mut request_headers: Vec<(String, String)> = vec![
                    ("x-ms-version".into(), DEFAULT_SAS_VERSION.into()),
                    ("x-ms-blob-type".into(), "BlockBlob".into()),
                ];
                let inline_metadata = if user_metadata.is_empty() {
                    None
                } else {
                    Some(&user_metadata)
                };
                request_headers.extend(self.user_metadata_headers(inline_metadata));
                let (if_match_single, no_overwrite_single) = split_if_dest(&opts.if_dest);
                if no_overwrite_single {
                    request_headers.push(("If-None-Match".into(), "*".into()));
                }
                if let Some(if_match) = if_match_single.clone() {
                    // Azure conditional headers require RFC 7232
                    // entity-tag quoting; the SPI etag is the raw value
                    // the backend returned, so route through
                    // `quote_etag` for redirect-uploaded blobs too.
                    request_headers.push(("If-Match".into(), quote_etag(&if_match)));
                }
                let signed_url = match self.client.auth().source() {
                    AuthSource::SharedKey { account_key_bytes } => {
                        let expiry = format_sas_expiry(SAS_LIFETIME_SECS);
                        let sas = service_sas_query(
                            account_key_bytes,
                            &ServiceSasRequest {
                                account: &self.config.account,
                                container: &self.config.container,
                                blob_path: &blob_key,
                                permissions: &[SasPermission::Write, SasPermission::Create],
                                start: None,
                                expiry: &expiry,
                                protocol: Some("https"),
                                version: DEFAULT_SAS_VERSION,
                            },
                        )?;
                        format!("{blob_url}?{sas}")
                    }
                    AuthSource::Sas { sas_token } => format!("{blob_url}?{sas_token}"),
                    AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
                        request_headers.push((
                            "Authorization".into(),
                            format!(
                                "Bearer {}",
                                bearer_for_oauth
                                    .as_ref()
                                    .expect("oauth bearer cached above"),
                            ),
                        ));
                        blob_url.clone()
                    }
                    AuthSource::Anonymous => {
                        return Err(Error::new(
                            ErrorCode::AuthRequired,
                            "Azure anonymous connections cannot write_redirect",
                        )
                        .with_context(ErrorContext::Auth {
                            connection_id: ConnectionId(String::new()),
                            reason: Some("anonymous_no_write".into()),
                            expired_at: None,
                        }));
                    }
                };
                // `size_hint.is_none()` is refused at the top of
                // write_redirect, so the unwrap below is infallible.
                let advertised_len = opts.size_hint.expect("size_hint presence checked at entry");
                let redirect = WriteRedirect {
                    request: HttpRequest {
                        method: "PUT".into(),
                        url: signed_url,
                        headers: request_headers,
                    },
                    body_source: RedirectBodySource::UserBytes {
                        offset: 0,
                        len: advertised_len,
                    },
                    result_capture: ResultCapture {
                        headers: vec![
                            "etag".into(),
                            "last-modified".into(),
                            "x-ms-version-id".into(),
                        ],
                        body_max_bytes: 1024,
                    },
                    expires_at,
                    scope,
                    audit_id: format!("azure-put-blob-{}", monotonic_id()),
                    policy_epoch: 0,
                };
                let continuation = WriteContinuation {
                    blob_key,
                    block_ids: Vec::new(),
                    user_metadata: opts.user_metadata.clone(),
                    if_match: if_match_single,
                    no_overwrite: no_overwrite_single,
                    content_type: "application/octet-stream".into(),
                };
                Ok(WriteRedirectBatch {
                    continuation: continuation.encode(),
                    redirects: vec![redirect],
                })
            }
            .instrument(span),
        )
        .await
    }

    async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = debug_span!(
            "azure.continue_write",
            op = "write",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                validate_redirect_results(&redirects, &results)?;
                for (i, result) in results.results.iter().enumerate() {
                    if !(200..300).contains(&result.status_code) {
                        let synthetic = synthesize_redirect_response(result);
                        let op = format!("redirect upload #{i}");
                        return Err(map_status_to_error(&synthetic, &op));
                    }
                }
                let continuation = WriteContinuation::decode(&redirects.continuation)?;
                if continuation.block_ids.is_empty() {
                    // Single PutBlob: the redirect itself committed; build ObjectInfo from captured headers.
                    let captured = results.results.first().ok_or_else(|| {
                        Error::new(
                            ErrorCode::Internal,
                            "Azure single-PutBlob continuation expected one redirect result",
                        )
                    })?;
                    let headers = crate::parse::HeaderMap::from_pairs(
                        captured
                            .captured_headers
                            .iter()
                            .map(|(n, v)| (n.as_str(), v.as_str())),
                    );
                    let info = parse_object_info(
                        target.resolved_address.clone(),
                        &headers,
                        self.config.hierarchical_namespace,
                    )?;
                    return Ok(WriteStep::Done(WriteResult { info }));
                }
                let blob_url = self.blob_url(&continuation.blob_key);
                let canonical_path = self.canonical_path_for_blob(&continuation.blob_key);
                let xml = build_block_list_xml(&continuation.block_ids);
                let mut extra_headers: Vec<(String, String)> = Vec::new();
                extra_headers
                    .extend(self.user_metadata_headers(continuation.user_metadata.as_ref()));
                extra_headers.push((
                    "x-ms-blob-content-type".into(),
                    continuation.content_type.clone(),
                ));

                let if_none_match = if continuation.no_overwrite {
                    Some("*".to_string())
                } else {
                    None
                };
                let if_match = continuation.if_match.clone();

                let req = AzureRequest {
                    method: reqwest::Method::PUT,
                    url: format!("{blob_url}?comp=blocklist"),
                    canonical_path: &canonical_path,
                    canonical_query: vec![("comp".into(), "blocklist".into())],
                    extra_headers,
                    content_type: Some("application/xml".into()),
                    content_md5: None,
                    if_match,
                    if_none_match,
                    range: None,
                    body: Some(xml.into_bytes()),
                };
                let response = self.client.send(req).await?;
                if !response.ok() {
                    return Err(map_status_to_error(&response, "Put Block List"));
                }
                let info = parse_object_info(
                    target.resolved_address.clone(),
                    &response.headers,
                    self.config.hierarchical_namespace,
                )?;
                Ok(WriteStep::Done(WriteResult { info }))
            }
            .instrument(span),
        )
        .await
    }

    async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        require_etag_only_if_match(opts.if_match.as_ref())?;
        let span = debug_span!(
            "azure.delete",
            op = "delete",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parsed = self.require_blob_address(&target)?;
                let blob_key = parsed.key.clone();
                let version_id = parsed.version_id.clone();
                let mut canonical_query: Vec<(String, String)> = Vec::new();
                let url = if let Some(vid) = version_id.as_ref() {
                    canonical_query.push(("versionid".into(), vid.clone()));
                    format!(
                        "{}?versionid={}",
                        self.blob_url(&blob_key),
                        urlencoding::encode(vid)
                    )
                } else {
                    self.blob_url(&blob_key)
                };
                let canonical_path = self.canonical_path_for_blob(&blob_key);
                let if_match = opts.if_match;
                let req = AzureRequest {
                    method: reqwest::Method::DELETE,
                    url,
                    canonical_path: &canonical_path,
                    canonical_query,
                    extra_headers: vec![],
                    content_type: None,
                    content_md5: None,
                    if_match,
                    if_none_match: None,
                    range: None,
                    body: None,
                };
                let response = self.client.send(req).await?;
                // delete is idempotent: a missing target is success.
                if response.status == 404 {
                    return Ok(());
                }
                if !response.ok() {
                    return Err(map_status_to_error(&response, "delete"));
                }
                Ok(())
            }
            .instrument(span),
        )
        .await
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = debug_span!(
            "azure.list",
            op = "list",
            plugin = "azure",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                self.validate_target(&prefix)?;
                let parsed = AzureAddress::parse(&prefix.resolved_address)?;
                let prefix_str = parsed.key.to_string();
                if self.config.hierarchical_namespace {
                    list_hns(self, &prefix_str, &opts).await
                } else {
                    list_blob(self, &prefix_str, &opts, false).await
                }
            }
            .instrument(span),
        )
        .await
    }

    async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = debug_span!(
            "azure.list_versions",
            op = "list",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parsed = self.require_blob_address(&target)?;
                let blob_key = parsed.key.clone();
                let base_url = format!("{}/{}", self.config.blob_url_base(), self.config.container);
                let canonical_path = format!("/{}", self.config.container);
                let mut items: Vec<ObjectInfo> = Vec::new();
                let mut marker: Option<String> = opts.page_token.clone();
                let mut remaining: Option<u32> = opts.max_results;
                loop {
                    let mut query: Vec<(String, String)> = vec![
                        ("restype".into(), "container".into()),
                        ("comp".into(), "list".into()),
                        ("prefix".into(), blob_key.clone()),
                        ("include".into(), "versions".into()),
                    ];
                    if let Some(rem) = remaining {
                        query.push(("maxresults".into(), rem.to_string()));
                    }
                    if let Some(m) = &marker {
                        query.push(("marker".into(), m.clone()));
                    }
                    let url_with_query = format!("{}?{}", base_url, encode_query(&query));
                    let req = AzureRequest {
                        method: reqwest::Method::GET,
                        url: url_with_query,
                        canonical_path: &canonical_path,
                        canonical_query: query,
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    };
                    let response = self.client.send(req).await?;
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "list_versions"));
                    }
                    let parsed = parse_blob_list_xml(response.body_str()?)?;
                    let mut page: Vec<ObjectInfo> = Vec::new();
                    for blob in parsed.items.iter().filter(|b| b.name == blob_key) {
                        if let Some(item) = blob_to_version_item(blob, &self.config.address_root)? {
                            page.push(item);
                        }
                    }
                    if let Some(rem) = remaining.as_mut() {
                        if (page.len() as u32) >= *rem {
                            page.truncate(*rem as usize);
                            items.extend(page);
                            return Ok(items);
                        }
                        *rem -= page.len() as u32;
                    }
                    items.extend(page);
                    match parsed.next_marker {
                        Some(next) if !next.is_empty() => marker = Some(next),
                        _ => return Ok(items),
                    }
                }
            }
            .instrument(span),
        )
        .await
    }

    async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = debug_span!(
            "azure.get_latest_version",
            op = "stat",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parsed = self.require_blob_address(&target)?;
                let blob_key = parsed.key.clone();
                let pinned = parsed.version_id.clone();
                let mut canonical_query: Vec<(String, String)> = Vec::new();
                let url = if let Some(vid) = pinned.as_ref() {
                    canonical_query.push(("versionid".into(), vid.clone()));
                    format!(
                        "{}?versionid={}",
                        self.blob_url(&blob_key),
                        urlencoding::encode(vid)
                    )
                } else {
                    self.blob_url(&blob_key)
                };
                let canonical_path = self.canonical_path_for_blob(&blob_key);
                let req = AzureRequest {
                    method: reqwest::Method::HEAD,
                    url,
                    canonical_path: &canonical_path,
                    canonical_query,
                    extra_headers: vec![],
                    content_type: None,
                    content_md5: None,
                    if_match: None,
                    if_none_match: None,
                    range: None,
                    body: None,
                };
                let response = self.client.send(req).await?;
                if !response.ok() {
                    return Err(map_status_to_error(&response, "get_latest_version"));
                }
                let info = parse_object_info(
                    target.resolved_address.clone(),
                    &response.headers,
                    self.config.hierarchical_namespace,
                )?;
                let value = pinned
                    .or_else(|| info.version.clone())
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::Unsupported,
                            "Azure blob has no x-ms-version-id (container may not have versioning enabled)",
                        )
                    })?;
                let address = version_address(&target.resolved_address, &value)?;
                Ok(ObjectInfo { address, ..info })
            }
            .instrument(span),
        )
        .await
    }

    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let span = debug_span!(
            "azure.watch_directory",
            op = "watch_directory",
            plugin = "azure",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        let cancel_for_watch = cancel.clone();
        race_cancel(
            cancel.as_ref(),
            async move {
                self.validate_target(&prefix)?;
                crate::subscription::watch_directory(self, prefix, opts, cancel_for_watch).await
            }
            .instrument(span),
        )
        .await
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let span = debug_span!(
            "azure.create_directory",
            op = "write",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                self.validate_target(&target)?;
                let parsed = AzureAddress::parse(&target.resolved_address)?;
                let key = parsed.key.trim_end_matches('/').to_string();
                if key.is_empty() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "Azure create_directory requires a non-empty directory path",
                    ));
                }
                if self.config.hierarchical_namespace {
                    let url = format!("{}?resource=directory", self.dfs_url(&key));
                    let canonical_path = self.canonical_path_for_dfs(&key);
                    let req = AzureRequest {
                        method: reqwest::Method::PUT,
                        url,
                        canonical_path: &canonical_path,
                        canonical_query: vec![("resource".into(), "directory".into())],
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    };
                    let response = self.client.send(req).await?;
                    // create_directory is idempotent: ADLS Gen2 returns 409 if the directory already exists.
                    if response.status == 409 {
                        return Ok(BackendItemInfo {
                            kind: ObjectKind::Directory,
                            ..BackendItemInfo::default()
                        });
                    }
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "create_directory"));
                    }
                    return Ok(BackendItemInfo {
                        kind: ObjectKind::Directory,
                        etag: response
                            .headers
                            .first("etag")
                            .map(|s| s.trim_matches('"').to_string()),
                        version: None,
                        size: None,
                        mtime: response
                            .headers
                            .first("last-modified")
                            .and_then(|s| httpdate::parse_http_date(s).ok()),
                        ..Default::default()
                    });
                }
                let marker_key = format!("{key}/");
                let url = self.blob_url(&marker_key);
                let canonical_path = self.canonical_path_for_blob(&marker_key);
                let extra_headers = vec![("x-ms-blob-type".into(), "BlockBlob".into())];
                let req = AzureRequest {
                    method: reqwest::Method::PUT,
                    url,
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers,
                    content_type: Some("application/octet-stream".into()),
                    content_md5: None,
                    if_match: None,
                    if_none_match: None,
                    range: None,
                    body: Some(Vec::new()),
                };
                let response = self.client.send(req).await?;
                if !response.ok() {
                    return Err(map_status_to_error(&response, "create_directory marker"));
                }
                Ok(BackendItemInfo {
                    kind: ObjectKind::DirectoryMarker,
                    ..BackendItemInfo::default()
                })
            }
            .instrument(span),
        )
        .await
    }

    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = debug_span!(
            "azure.delete_directory",
            op = "delete",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                self.validate_target(&target)?;
                let parsed = AzureAddress::parse(&target.resolved_address)?;
                let key = parsed.key.trim_end_matches('/').to_string();
                if key.is_empty() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "Azure delete_directory requires a non-empty directory path",
                    ));
                }
                if self.config.hierarchical_namespace {
                    let canonical_path = self.canonical_path_for_dfs(&key);
                    let req = AzureRequest {
                        method: reqwest::Method::DELETE,
                        url: self.dfs_url(&key),
                        canonical_path: &canonical_path,
                        canonical_query: vec![],
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    };
                    let response = self.client.send(req).await?;
                    // delete_directory is idempotent: a missing target is success.
                    if response.status == 404 {
                        return Ok(());
                    }
                    if !response.ok() {
                        if response.status == 409 {
                            return Err(Error::new(
                                ErrorCode::DirectoryNotEmpty,
                                "Azure HNS directory is not empty",
                            ));
                        }
                        return Err(map_status_to_error(&response, "delete_directory"));
                    }
                    return Ok(());
                }
                let marker_key = format!("{key}/");
                let url = self.blob_url(&marker_key);
                let canonical_path = self.canonical_path_for_blob(&marker_key);
                let req = AzureRequest {
                    method: reqwest::Method::DELETE,
                    url,
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers: vec![],
                    content_type: None,
                    content_md5: None,
                    if_match: None,
                    if_none_match: None,
                    range: None,
                    body: None,
                };
                let response = self.client.send(req).await?;
                if !response.ok() && response.status != 404 {
                    return Err(map_status_to_error(&response, "delete_directory marker"));
                }
                Ok(())
            }
            .instrument(span),
        )
        .await
    }

    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let span = debug_span!(
            "azure.copy",
            op = "copy",
            plugin = "azure",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let src_parsed = self.require_blob_address(&src)?;
                let src_key = src_parsed.key.clone();
                let src_version_id = src_parsed.version_id.clone();
                let dest_parsed = self.require_blob_address(&dest)?;
                if dest_parsed.version_id.is_some() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "Azure copy destination cannot pin a versionid",
                    ));
                }
                let dest_key = dest_parsed.key.clone();
                let dest_url = self.blob_url(&dest_key);
                let canonical_path = self.canonical_path_for_blob(&dest_key);
                let copy_source = self.copy_source_url(&src_key, src_version_id.as_deref())?;
                let mut extra_headers: Vec<(String, String)> =
                    vec![("x-ms-copy-source".into(), copy_source)];
                // `CopyOptions::if_source` is the source-side
                // conditional (caller asserting "copy only if the
                // source still has this etag"). On Azure that's
                // `x-ms-source-if-match`, not the destination's
                // `If-Match`.
                if let Some(etag) = opts.if_source.as_deref() {
                    extra_headers.push(("x-ms-source-if-match".into(), quote_etag(etag)));
                }
                // `CopyOptions::if_dest` is the destination-side precondition.
                let (dest_if_match, dest_no_overwrite) = split_if_dest(&opts.if_dest);
                let dest_if_none_match = if dest_no_overwrite {
                    Some("*".to_string())
                } else {
                    None
                };
                let req = AzureRequest {
                    method: reqwest::Method::PUT,
                    url: dest_url,
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers,
                    content_type: None,
                    content_md5: None,
                    if_match: dest_if_match,
                    if_none_match: dest_if_none_match,
                    range: None,
                    body: None,
                };
                let mut response = self.client.send(req).await?;
                if !response.ok() {
                    return Err(map_status_to_error(&response, "copy"));
                }
                let mut status = response
                    .headers
                    .first("x-ms-copy-status")
                    .map(str::to_string)
                    .unwrap_or_else(|| "success".into());
                let started = std::time::Instant::now();
                let dest_blob_url = self.blob_url(&dest_key);
                let dest_canonical = self.canonical_path_for_blob(&dest_key);
                while status.eq_ignore_ascii_case("pending") {
                    if started.elapsed() > AZURE_COPY_POLL_DEADLINE {
                        return Err(Error::new(
                            ErrorCode::Transient,
                            "Azure copy still pending after deadline",
                        ));
                    }
                    tokio::time::sleep(AZURE_COPY_POLL_INTERVAL).await;
                    let head = AzureRequest {
                        method: reqwest::Method::HEAD,
                        url: dest_blob_url.clone(),
                        canonical_path: &dest_canonical,
                        canonical_query: vec![],
                        extra_headers: vec![],
                        content_type: None,
                        content_md5: None,
                        if_match: None,
                        if_none_match: None,
                        range: None,
                        body: None,
                    };
                    let probe = self.client.send(head).await?;
                    if !probe.ok() {
                        return Err(map_status_to_error(&probe, "copy poll"));
                    }
                    status = probe
                        .headers
                        .first("x-ms-copy-status")
                        .map(str::to_string)
                        .unwrap_or_else(|| "success".into());
                    response = probe;
                }
                if status.eq_ignore_ascii_case("failed") || status.eq_ignore_ascii_case("aborted") {
                    let detail = response
                        .headers
                        .first("x-ms-copy-status-description")
                        .unwrap_or("(no description)")
                        .to_string();
                    return Err(Error::new(
                        ErrorCode::Internal,
                        format!("Azure copy {status}: {detail}"),
                    ));
                }
                let info = parse_object_info(
                    dest.resolved_address.clone(),
                    &response.headers,
                    self.config.hierarchical_namespace,
                )?;
                Ok(WriteStep::Done(WriteResult { info }))
            }
            .instrument(span),
        )
        .await
    }

    async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        reject_pinned_for_mutation(
            &src.resolved_address,
            "azure rename(src)",
            PINNED_VERSION_KEYS,
        )?;
        reject_pinned_for_mutation(
            &dest.resolved_address,
            "azure rename(dst)",
            PINNED_VERSION_KEYS,
        )?;
        let span = debug_span!(
            "azure.rename",
            op = "rename",
            plugin = "azure",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                if self.config.hierarchical_namespace {
                    let src_key = self.require_blob_address(&src)?.key.clone();
                    let dest_key = self.require_blob_address(&dest)?.key.clone();
                    let url = self.dfs_url(&dest_key);
                    let canonical_path = self.canonical_path_for_dfs(&dest_key);
                    let mut extra_headers: Vec<(String, String)> = vec![(
                        "x-ms-rename-source".into(),
                        format!("/{}/{}", self.config.container, url_encode_path(&src_key)),
                    )];
                    // `RenameOptions::if_source` is a source-side
                    // conditional. On the DFS rename endpoint the
                    // source conditional is `x-ms-source-if-match`,
                    // matching the Copy-Blob shape used for the non-HNS
                    // copy+delete fallback below.
                    if let Some(etag) = opts.if_source.as_deref() {
                        extra_headers.push(("x-ms-source-if-match".into(), quote_etag(etag)));
                    }
                    // Destination-side precondition.
                    let (dest_if_match, dest_no_overwrite) = split_if_dest(&opts.if_dest);
                    let dest_if_none_match = if dest_no_overwrite {
                        Some("*".to_string())
                    } else {
                        None
                    };
                    let req = AzureRequest {
                        method: reqwest::Method::PUT,
                        url,
                        canonical_path: &canonical_path,
                        canonical_query: vec![],
                        extra_headers,
                        content_type: None,
                        content_md5: None,
                        if_match: dest_if_match,
                        if_none_match: dest_if_none_match,
                        range: None,
                        body: None,
                    };
                    let response = self.client.send(req).await?;
                    if !response.ok() {
                        return Err(map_status_to_error(&response, "rename"));
                    }
                    return Ok(());
                }
                let _ = self
                    .copy(
                        src.clone(),
                        dest,
                        CopyOptions {
                            if_source: opts.if_source.clone(),
                            if_dest: opts.if_dest.clone(),
                            message: opts.message.clone(),
                        },
                        None,
                    )
                    .await?;
                // Carry the caller's source precondition through to the
                // delete so a concurrent source mutation between the
                // copy and the delete cannot weaken the contract.
                self.delete(
                    src,
                    DeleteOptions {
                        if_match: opts.if_source.clone(),
                    },
                    None,
                )
                .await?;
                Ok(())
            }
            .instrument(span),
        )
        .await
    }

    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        require_etag_only_if_match(opts.if_match.as_ref())?;
        let span = debug_span!(
            "azure.update_metadata",
            op = "stat",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(cancel.as_ref(), async move {
            let parsed = self.require_blob_address(&target)?;
            if parsed.version_id.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "Azure update_metadata does not support pinned versionid (Azure Set Blob Metadata operates on the current version only)",
                ));
            }
            let blob_key = parsed.key.clone();
            // Azure `Set Blob Metadata` is replace, not patch: HEAD the blob, merge set/remove
            // onto existing x-ms-meta-* headers, then PUT the full resulting set.
            let head_url = self.blob_url(&blob_key);
            let head_path = self.canonical_path_for_blob(&blob_key);
            let head_req = AzureRequest {
                method: reqwest::Method::HEAD,
                url: head_url,
                canonical_path: &head_path,
                canonical_query: vec![],
                extra_headers: vec![],
                content_type: None,
                content_md5: None,
                if_match: None,
                if_none_match: None,
                range: None,
                body: None,
            };
            let head_response = self.client.send(head_req).await?;
            if !head_response.ok() {
                return Err(map_status_to_error(&head_response, "update_metadata head"));
            }
            let existing_etag = head_response
                .headers
                .first("etag")
                .map(|s| s.trim_matches('"').to_string());

            let mut metadata = ovstorage_plugin::UserMetadata::new();
            for (name, value) in head_response.headers.iter() {
                let lower = name.to_ascii_lowercase();
                if let Some(rest) = lower.strip_prefix("x-ms-meta-")
                    && !rest.is_empty()
                {
                    metadata.insert(rest.to_string(), value.to_string());
                }
            }
            for key in &opts.user_metadata_remove {
                metadata.remove(key);
            }
            for (k, v) in opts.user_metadata_set {
                metadata.insert(k, v);
            }
            if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                metadata.insert("x-ov-message".to_string(), message.to_string());
            }

            let if_match = opts.if_match.or(existing_etag);
            let url = format!("{}?comp=metadata", self.blob_url(&blob_key));
            let canonical_path = self.canonical_path_for_blob(&blob_key);
            let extra_headers = self.user_metadata_headers(Some(&metadata));
            let req = AzureRequest {
                method: reqwest::Method::PUT,
                url,
                canonical_path: &canonical_path,
                canonical_query: vec![("comp".into(), "metadata".into())],
                extra_headers,
                content_type: None,
                content_md5: None,
                if_match,
                if_none_match: None,
                range: None,
                body: None,
            };
            let response = self.client.send(req).await?;
            if !response.ok() {
                return Err(map_status_to_error(&response, "update_metadata"));
            }
            Ok(BackendItemInfo {
                kind: ObjectKind::File,
                etag: response
                    .headers
                    .first("etag")
                    .map(|s| s.trim_matches('"').to_string()),
                version: response
                    .headers
                    .first("x-ms-version-id")
                    .map(str::to_string),
                size: None,
                mtime: response
                    .headers
                    .first("last-modified")
                    .and_then(|s| httpdate::parse_http_date(s).ok()),
                checksums: ChecksumSet::new(),
                effective_permissions: None,
                system_metadata: None,
                user_metadata: Some(metadata),
                modified_by: None,
            })
        }.instrument(span))
        .await
    }

    async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let span = debug_span!(
            "azure.check_access",
            op = "stat",
            plugin = "azure",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let blob_key = self.require_blob_address(&target)?.key.clone();
                let url = self.blob_url(&blob_key);
                let canonical_path = self.canonical_path_for_blob(&blob_key);
                let req = AzureRequest {
                    method: reqwest::Method::HEAD,
                    url,
                    canonical_path: &canonical_path,
                    canonical_query: vec![],
                    extra_headers: vec![],
                    content_type: None,
                    content_md5: None,
                    if_match: None,
                    if_none_match: None,
                    range: None,
                    body: None,
                };
                let response = self.client.send(req).await?;
                let allowed = response.ok();
                let mut denied_ops = AccessOps::default();
                if !allowed {
                    denied_ops.read = ops.read;
                    denied_ops.write = ops.write;
                    denied_ops.delete = ops.delete;
                    denied_ops.update_metadata = ops.update_metadata;
                }
                let reason = if allowed {
                    None
                } else {
                    Some(format!("Azure HEAD returned HTTP {}", response.status))
                };
                Ok(AccessDecision {
                    allowed,
                    denied_ops,
                    reason,
                })
            }
            .instrument(span),
        )
        .await
    }
}

fn version_address(
    addr: &ovstorage_plugin::Url,
    version_id: &str,
) -> Result<ovstorage_plugin::Url> {
    let mut base = addr.clone();
    base.set_query(None);
    base.set_fragment(None);
    address::with_query_pair(&base, "versionid", version_id)
}

async fn list_blob(
    backend: &AzureBackend,
    prefix: &str,
    opts: &ListOptions,
    include_versions: bool,
) -> Result<Vec<ObjectInfo>> {
    let base_url = format!(
        "{}/{}",
        backend.config.blob_url_base(),
        backend.config.container
    );
    let canonical_path = format!("/{}", backend.config.container);
    let mut items: Vec<ObjectInfo> = Vec::new();
    let mut marker: Option<String> = opts.page_token.clone();
    let mut remaining: Option<u32> = opts.max_results;
    loop {
        let mut query: Vec<(String, String)> = vec![
            ("restype".into(), "container".into()),
            ("comp".into(), "list".into()),
            ("prefix".into(), prefix.to_string()),
        ];
        if !opts.recursive {
            query.push(("delimiter".into(), "/".into()));
        }
        if let Some(rem) = remaining {
            query.push(("maxresults".into(), rem.to_string()));
        }
        if let Some(m) = &marker {
            query.push(("marker".into(), m.clone()));
        }
        if include_versions {
            query.push(("include".into(), "versions".into()));
        }
        let url_with_query = format!("{}?{}", base_url, encode_query(&query));
        let req = AzureRequest {
            method: reqwest::Method::GET,
            url: url_with_query,
            canonical_path: &canonical_path,
            canonical_query: query,
            extra_headers: vec![],
            content_type: None,
            content_md5: None,
            if_match: None,
            if_none_match: None,
            range: None,
            body: None,
        };
        let response = backend.client.send(req).await?;
        if !response.ok() {
            return Err(map_status_to_error(&response, "list"));
        }
        let parsed = parse_blob_list_xml(response.body_str()?)?;
        let mut page = list_xml_to_object_infos(&parsed, &backend.config.address_root)?;
        if let Some(rem) = remaining.as_mut() {
            if (page.len() as u32) >= *rem {
                page.truncate(*rem as usize);
                items.extend(page);
                return Ok(items);
            }
            *rem -= page.len() as u32;
        }
        items.extend(page);
        match parsed.next_marker {
            Some(next) if !next.is_empty() => marker = Some(next),
            _ => return Ok(items),
        }
    }
}

async fn list_hns(
    backend: &AzureBackend,
    prefix: &str,
    opts: &ListOptions,
) -> Result<Vec<ObjectInfo>> {
    let base_url = format!(
        "{}/{}",
        backend.config.dfs_url_base(),
        backend.config.container
    );
    let canonical_path = format!("/{}", backend.config.container);
    let mut items: Vec<ObjectInfo> = Vec::new();
    let mut continuation: Option<String> = opts.page_token.clone();
    let mut remaining: Option<u32> = opts.max_results;
    loop {
        let mut query: Vec<(String, String)> = vec![
            ("resource".into(), "filesystem".into()),
            ("recursive".into(), opts.recursive.to_string()),
        ];
        if !prefix.is_empty() {
            query.push(("directory".into(), prefix.to_string()));
        }
        if let Some(rem) = remaining {
            query.push(("maxresults".into(), rem.to_string()));
        }
        if let Some(token) = &continuation {
            query.push(("continuation".into(), token.clone()));
        }
        let url = format!("{}?{}", base_url, encode_query(&query));
        let req = AzureRequest {
            method: reqwest::Method::GET,
            url,
            canonical_path: &canonical_path,
            canonical_query: query,
            extra_headers: vec![],
            content_type: None,
            content_md5: None,
            if_match: None,
            if_none_match: None,
            range: None,
            body: None,
        };
        let response = backend.client.send(req).await?;
        if !response.ok() {
            return Err(map_status_to_error(&response, "list (HNS)"));
        }
        let next_continuation = response
            .headers
            .first("x-ms-continuation")
            .map(str::to_string);
        let parsed = parse_dfs_path_list_json(response.body_str()?, next_continuation.clone())?;
        let mut page = dfs_paths_to_object_infos(&parsed, &backend.config.address_root)?;
        if let Some(rem) = remaining.as_mut() {
            if (page.len() as u32) >= *rem {
                page.truncate(*rem as usize);
                items.extend(page);
                return Ok(items);
            }
            *rem -= page.len() as u32;
        }
        items.extend(page);
        match next_continuation {
            Some(next) if !next.is_empty() => continuation = Some(next),
            _ => return Ok(items),
        }
    }
}

/// Deterministic block ID for a blob's `seq`-th block. Layout:
/// `sha256(blob_key)[..12] || seq.to_be_bytes()` → 16 bytes, std base64 → 24 chars.
/// Uniform length satisfies Azure's "same length per blob" requirement.
pub(crate) fn block_id(blob_key: &str, seq: u32) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(blob_key.as_bytes());
    let mut raw = [0u8; 16];
    raw[..12].copy_from_slice(&digest[..12]);
    raw[12..].copy_from_slice(&seq.to_be_bytes());
    base64::engine::general_purpose::STANDARD.encode(raw)
}

pub(crate) fn build_block_list_xml(block_ids_b64: &[String]) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>");
    for id in block_ids_b64 {
        out.push_str("<Latest>");
        out.push_str(id);
        out.push_str("</Latest>");
    }
    out.push_str("</BlockList>");
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WriteContinuation {
    pub blob_key: String,
    pub block_ids: Vec<String>,
    pub user_metadata: Option<ovstorage_plugin::UserMetadata>,
    pub if_match: Option<String>,
    pub no_overwrite: bool,
    pub content_type: String,
}

impl WriteContinuation {
    pub fn encode(&self) -> Vec<u8> {
        // JSON keeps the format human-debuggable; host treats it as opaque.
        serde_json::to_vec(&WriteContinuationWire {
            blob_key: &self.blob_key,
            block_ids: &self.block_ids,
            user_metadata: self.user_metadata.as_ref(),
            if_match: self.if_match.as_deref(),
            no_overwrite: self.no_overwrite,
            content_type: &self.content_type,
        })
        .expect("WriteContinuation serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: WriteContinuationOwned = serde_json::from_slice(bytes).map_err(|e| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("Azure write continuation is malformed: {e}"),
            )
        })?;
        Ok(Self {
            blob_key: wire.blob_key,
            block_ids: wire.block_ids,
            user_metadata: wire.user_metadata,
            if_match: wire.if_match,
            no_overwrite: wire.no_overwrite,
            content_type: wire.content_type,
        })
    }
}

#[derive(serde::Serialize)]
struct WriteContinuationWire<'a> {
    blob_key: &'a str,
    block_ids: &'a [String],
    user_metadata: Option<&'a ovstorage_plugin::UserMetadata>,
    if_match: Option<&'a str>,
    no_overwrite: bool,
    content_type: &'a str,
}

#[derive(serde::Deserialize)]
struct WriteContinuationOwned {
    blob_key: String,
    block_ids: Vec<String>,
    user_metadata: Option<ovstorage_plugin::UserMetadata>,
    if_match: Option<String>,
    no_overwrite: bool,
    content_type: String,
}

/// Wrap a raw ETag value in double-quotes if the caller passed it
/// unquoted. Azure's `If-Match` / `x-ms-source-if-match` headers expect
/// the RFC 7232 `entity-tag` shape (`"..."`), and the SPI documents
/// the `if_match` etag as the raw value the backend handed back.
pub(crate) fn quote_etag(etag: &str) -> String {
    if etag.starts_with('"') && etag.ends_with('"') {
        etag.to_string()
    } else {
        format!("\"{etag}\"")
    }
}

/// Build an Azure `Range: bytes=...` header value, validating that
/// `start <= end_inclusive`. Inverted ranges would slice a zero-length
/// window at the host follower and panic on `Bytes::slice` under
/// `panic = "abort"`; surface them as `InvalidArgument` here so the
/// caller can fix the request before any wire round-trip.
pub(crate) fn read_range_header(range: &ovstorage_plugin::ByteRange) -> Result<String> {
    match range.end_inclusive {
        Some(end) => {
            if end < range.start {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "azure read range is inverted: start={} > end_inclusive={}",
                        range.start, end,
                    ),
                ));
            }
            Ok(format!("bytes={}-{}", range.start, end))
        }
        None => Ok(format!("bytes={}-", range.start)),
    }
}

fn encode_query(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn synthesize_redirect_response(
    result: &ovstorage_plugin::RedirectResult,
) -> crate::client::AzureResponse {
    let mut headers = crate::parse::HeaderMap::new();
    for (name, value) in &result.captured_headers {
        headers.insert(name, value);
    }
    crate::client::AzureResponse {
        status: result.status_code,
        headers,
        body: result.captured_body.clone(),
    }
}

fn format_sas_expiry(seconds_from_now: i64) -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Iso8601;
    let target = OffsetDateTime::now_utc() + time::Duration::seconds(seconds_from_now);
    target
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn monotonic_id() -> u128 {
    // Opaque audit-trace ID; per-process uniqueness is enough.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    nanos ^ ((n as u128) << 64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    #[allow(unused_imports)]
    use ovstorage_plugin::shim::{Backend as _, Factory as _};
    use ovstorage_plugin::{SecretBundle, address};

    fn fixture_config() -> AzureConnectionConfig {
        AzureConnectionConfig {
            account: "acct".into(),
            container: "container".into(),
            endpoint_suffix: "core.windows.net".into(),
            hierarchical_namespace: false,
            change_feed_enabled: false,
            change_feed_segment_lag_seconds: 60,
            change_feed_poll_interval_seconds: 15,
            test_change_feed_endpoint: None,
            test_endpoint_override: None,
            address_root: address::parse("azure://acct/container/").unwrap(),
        }
    }

    #[test]
    fn capabilities_track_hns_flag() {
        let flat = azure_capabilities(false, false);
        let hns = azure_capabilities(true, true);
        assert!(!flat.has_real_directories);
        assert!(hns.has_real_directories);
        assert!(hns.supports_server_side_rename);
        assert!(!flat.supports_server_side_rename);
        assert!(flat.supports_list);
        assert!(flat.supports_native_metadata_patch);
        assert!(flat.supports_version_listing);
        assert_eq!(flat.version_list_order, Some(VersionListOrder::Oldest));
        assert!(!flat.supports_watch_directory);
        assert!(!hns.supports_watch_directory);

        let watched = azure_capabilities(false, true);
        assert!(watched.supports_watch_directory);
        assert!(watched.watch_directory_kinds.created);
        assert!(!watched.watch_directory_kinds.modified);
        assert!(watched.watch_directory_kinds.deleted);
        assert!(watched.watch_directory_kinds.metadata_changed);
        assert!(!watched.watch_directory_resumable);
        assert_eq!(
            watched.watch_directory_max_lag,
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn block_list_xml_round_trips_in_order() {
        let xml = build_block_list_xml(&["AAA=".into(), "BBB=".into()]);
        assert!(xml.contains("<Latest>AAA=</Latest><Latest>BBB=</Latest>"));
        assert!(xml.starts_with("<?xml"));
    }

    #[test]
    fn write_continuation_round_trips_through_json() {
        let mut metadata = ovstorage_plugin::UserMetadata::new();
        metadata.insert("author".into(), "alice".into());
        let cont = WriteContinuation {
            blob_key: "docs/manual.bin".into(),
            block_ids: vec!["AAA=".into(), "BBB=".into()],
            user_metadata: Some(metadata.clone()),
            if_match: Some("0xETAG".into()),
            no_overwrite: false,
            content_type: "application/octet-stream".into(),
        };
        let bytes = cont.encode();
        let decoded = WriteContinuation::decode(&bytes).unwrap();
        assert_eq!(decoded, cont);
    }

    #[tokio::test]
    async fn stage_block_sequence_emits_redirects_then_done() {
        let key = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(key.into_bytes())),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let backend = AzureBackend::new(fixture_config(), auth).unwrap();

        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/large.bin").unwrap(),
        };
        // 300 MiB > 256 MiB threshold ⇒ staged-block planning at 4 MiB chunks ⇒ 75 redirects.
        let total: u64 = 300 * 1024 * 1024;
        let opts = WriteOptions {
            size_hint: Some(total),
            ..WriteOptions::default()
        };
        let batch = ovstorage_plugin::shim::Backend::write_redirect(&backend, target, opts, None)
            .await
            .expect("write_redirect emits batch");
        assert_eq!(batch.redirects.len(), 75, "75 × 4 MiB = 300 MiB");
        // Azure requires all block IDs in a blob share length.
        let cont = WriteContinuation::decode(&batch.continuation).unwrap();
        assert_eq!(cont.block_ids.len(), 75);
        let lens: std::collections::HashSet<usize> =
            cont.block_ids.iter().map(|s| s.len()).collect();
        assert_eq!(lens.len(), 1, "all block IDs must share a single length");
        match batch.redirects[0].body_source {
            RedirectBodySource::UserBytes { offset, len } => {
                assert_eq!(offset, 0);
                assert_eq!(len, AZURE_BLOCK_SIZE_BYTES);
            }
            _ => panic!("first block redirect must use UserBytes"),
        }
        match batch.redirects[74].body_source {
            RedirectBodySource::UserBytes { offset, len } => {
                assert_eq!(offset, 74 * AZURE_BLOCK_SIZE_BYTES);
                assert_eq!(len, total - 74 * AZURE_BLOCK_SIZE_BYTES);
            }
            _ => panic!("last block redirect must use UserBytes"),
        }
        for redirect in &batch.redirects {
            assert!(
                redirect.request.url.contains("comp=block&blockid="),
                "url missing block params: {}",
                redirect.request.url
            );
        }
    }

    #[test]
    fn block_id_is_deterministic_and_uniform_length() {
        let a0 = block_id("docs/manual.bin", 0);
        let a0_again = block_id("docs/manual.bin", 0);
        let a1 = block_id("docs/manual.bin", 1);
        let b0 = block_id("other/blob.bin", 0);
        assert_eq!(a0, a0_again, "deterministic per (key, seq)");
        assert_ne!(a0, a1, "different seq produces different id");
        assert_ne!(a0, b0, "different blob key produces different id");
        assert_eq!(a0.len(), a1.len(), "all blocks share the same id length");
        assert_eq!(a0.len(), b0.len(), "across blobs ids share length");
        assert_eq!(a0.len(), 24);
    }

    #[tokio::test]
    async fn read_redirect_populates_content_md5_checksum_parsing() {
        let key = base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(key.into_bytes())),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let backend = AzureBackend::new(fixture_config(), auth).unwrap();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/small.bin").unwrap(),
        };
        let result =
            ovstorage_plugin::shim::Backend::read(&backend, target, ReadOptions::default(), None)
                .await
                .expect("read returns Redirect on the SharedKey path");
        let redirect = match result {
            ReadResult::Redirect(r) => r,
            other => panic!("expected ReadResult::Redirect, got {other:?}"),
        };
        let parsing = &redirect.response_parsing;
        assert_eq!(
            parsing.content_checksum_header.as_deref(),
            Some("Content-MD5"),
            "verifier must read Content-MD5"
        );
        assert_eq!(
            parsing
                .content_checksum_algorithm
                .as_ref()
                .map(|a| a.as_str()),
            Some("md5")
        );
        assert_eq!(
            parsing
                .checksum_headers
                .get(&ChecksumAlgorithm::md5())
                .map(String::as_str),
            Some("Content-MD5"),
            "Content-MD5 must also propagate into ObjectInfo.checksums via checksum_headers"
        );
    }

    #[tokio::test]
    async fn read_redirect_checksum_headers_only_lists_md5() {
        let key = base64::engine::general_purpose::STANDARD.encode([0x44u8; 32]);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(key.into_bytes())),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let backend = AzureBackend::new(fixture_config(), auth).unwrap();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin").unwrap(),
        };
        let result =
            ovstorage_plugin::shim::Backend::read(&backend, target, ReadOptions::default(), None)
                .await
                .unwrap();
        let redirect = match result {
            ReadResult::Redirect(r) => r,
            other => panic!("expected ReadResult::Redirect, got {other:?}"),
        };
        assert_eq!(redirect.response_parsing.checksum_headers.len(), 1);
    }

    #[tokio::test]
    async fn write_redirect_below_threshold_keeps_single_putblob() {
        let key = base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(key.into_bytes())),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let backend = AzureBackend::new(fixture_config(), auth).unwrap();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/small.bin").unwrap(),
        };
        let opts = WriteOptions {
            size_hint: Some(100 * 1024 * 1024),
            ..WriteOptions::default()
        };
        let batch = ovstorage_plugin::shim::Backend::write_redirect(&backend, target, opts, None)
            .await
            .unwrap();
        assert_eq!(batch.redirects.len(), 1);
        let cont = WriteContinuation::decode(&batch.continuation).unwrap();
        assert!(
            cont.block_ids.is_empty(),
            "single PutBlob has empty block list"
        );
    }

    #[test]
    fn list_xml_to_object_infos_uses_child_addresses() {
        let xml = r#"<?xml version="1.0"?>
<EnumerationResults><Blobs>
<Blob><Name>docs/file.bin</Name><Properties><Etag>0x1</Etag><Content-Length>12</Content-Length></Properties></Blob>
<BlobPrefix><Name>docs/sub/</Name></BlobPrefix>
</Blobs></EnumerationResults>"#;
        let parsed = parse_blob_list_xml(xml).unwrap();
        let address_root = address::parse("azure://acct/container/").unwrap();
        let items = list_xml_to_object_infos(&parsed, &address_root).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0].address.as_str(),
            "azure://acct/container/docs/file.bin"
        );
        assert_eq!(items[0].kind, ObjectKind::File);
        assert_eq!(
            items[1].address.as_str(),
            "azure://acct/container/docs/sub/"
        );
        assert_eq!(items[1].kind, ObjectKind::DirectoryInferred);
    }

    #[test]
    fn list_xml_to_object_infos_marker_wins_over_duplicate_prefix() {
        let xml = r#"<?xml version="1.0"?>
<EnumerationResults><Blobs>
<Blob><Name>docs/sub/</Name><Properties><Etag>0x2</Etag><Content-Length>0</Content-Length></Properties></Blob>
<BlobPrefix><Name>docs/sub/</Name></BlobPrefix>
</Blobs></EnumerationResults>"#;
        let parsed = parse_blob_list_xml(xml).unwrap();
        let address_root = address::parse("azure://acct/container/").unwrap();
        let items = list_xml_to_object_infos(&parsed, &address_root).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].address.as_str(),
            "azure://acct/container/docs/sub/"
        );
        assert_eq!(items[0].kind, ObjectKind::DirectoryMarker);
        assert_eq!(items[0].etag.as_deref(), Some("0x2"));
    }

    #[test]
    fn url_encoding_preserves_segments_but_escapes_unsafe_bytes() {
        assert_eq!(url_encode_path("a/b c/d"), "a/b%20c/d");
        assert_eq!(url_encode_path("a//b"), "a//b");
    }

    fn shared_key_backend() -> AzureBackend {
        let key = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(key.into_bytes())),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        AzureBackend::new(fixture_config(), auth).unwrap()
    }

    #[test]
    fn copy_source_url_under_shared_key_appends_read_only_service_sas() {
        let backend = shared_key_backend();
        let url = backend.copy_source_url("docs/file.bin", None).unwrap();
        assert!(
            url.starts_with("https://acct.blob.core.windows.net/container/docs/file.bin?"),
            "url was {url}"
        );
        assert!(url.contains("sr=b"), "should be blob-scoped SAS");
        assert!(url.contains("sp=r"), "should be read-only");
        assert!(url.contains("sv="), "must include signed-version");
        assert!(url.contains("se="), "must include expiry");
        assert!(url.contains("sig="), "must include signature");
    }

    #[test]
    fn copy_source_url_with_caller_sas_appends_token_verbatim() {
        let token = "sv=2024&sig=ZZZ";
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "sas_token".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(
                token.as_bytes().to_vec(),
            )),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let backend = AzureBackend::new(fixture_config(), auth).unwrap();
        let url = backend.copy_source_url("doc.bin", None).unwrap();
        assert_eq!(
            url,
            format!("https://acct.blob.core.windows.net/container/doc.bin?{token}")
        );
    }

    #[test]
    fn azure_address_decodes_percent_encoded_blob_key() {
        let addr = address::parse("azure://acct/container/a%20b%2Fc.txt").unwrap();
        let parsed = AzureAddress::parse(&addr).unwrap();
        assert_eq!(parsed.account, "acct");
        assert_eq!(parsed.container, "container");
        assert_eq!(parsed.key, "a b/c.txt");
        assert!(parsed.version_id.is_none());
    }

    #[test]
    fn azure_address_extracts_versionid_query_param() {
        let addr = address::parse(
            "azure://acct/container/blob.bin?versionid=2024-01-01T00%3A00%3A00.000Z",
        )
        .unwrap();
        let parsed = AzureAddress::parse(&addr).unwrap();
        assert_eq!(parsed.key, "blob.bin");
        assert_eq!(
            parsed.version_id.as_deref(),
            Some("2024-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn url_encode_path_does_not_double_encode_after_address_decode() {
        let key = "a b.txt";
        assert_eq!(url_encode_path(key), "a%20b.txt");
        let percent_key = "a%b.txt";
        assert_eq!(url_encode_path(percent_key), "a%25b.txt");
    }

    #[tokio::test]
    async fn require_blob_address_propagates_versionid() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin?versionid=v-123")
                .unwrap(),
        };
        let parsed = backend.require_blob_address(&target).unwrap();
        assert_eq!(parsed.version_id.as_deref(), Some("v-123"));
        assert_eq!(parsed.key, "blob.bin");
    }

    #[test]
    fn copy_source_url_with_versionid_under_shared_key_pins_source_version() {
        let backend = shared_key_backend();
        let url = backend
            .copy_source_url("docs/file.bin", Some("2024-01-01T00:00:00.000Z"))
            .unwrap();
        assert!(
            url.contains("versionid=2024-01-01T00%3A00%3A00.000Z"),
            "x-ms-copy-source must pin versionid (url-encoded), got {url}"
        );
        assert!(url.contains("sig="), "must still carry the SAS signature");
        let qstart = url.find('?').unwrap();
        assert!(
            url[..qstart].ends_with("docs/file.bin"),
            "versionid+sas must follow a single `?` separator"
        );
    }

    #[test]
    fn copy_source_url_with_versionid_under_caller_sas_pins_source_version() {
        let token = "sv=2024&sig=ZZZ";
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "sas_token".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(
                token.as_bytes().to_vec(),
            )),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        let backend = AzureBackend::new(fixture_config(), auth).unwrap();
        let url = backend.copy_source_url("doc.bin", Some("v-99")).unwrap();
        assert!(url.contains("versionid=v-99"));
        assert!(url.contains(token));
    }

    #[tokio::test]
    async fn read_redirect_url_carries_versionid_query_param() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin?versionid=v-7")
                .unwrap(),
        };
        let result =
            ovstorage_plugin::shim::Backend::read(&backend, target, ReadOptions::default(), None)
                .await
                .unwrap();
        let redirect = match result {
            ReadResult::Redirect(r) => r,
            other => panic!("expected ReadResult::Redirect, got {other:?}"),
        };
        assert!(
            redirect.request.url.contains("versionid=v-7"),
            "read URL must carry versionid, got {}",
            redirect.request.url
        );
    }

    #[test]
    fn hns_stat_canonical_query_carries_action_and_versionid() {
        let q: Vec<(String, String)> = vec![
            ("action".into(), "getStatus".into()),
            ("versionid".into(), "v-7".into()),
        ];
        let encoded = encode_query(&q);
        assert!(encoded.contains("action=getStatus"));
        assert!(encoded.contains("versionid=v-7"));
    }

    #[tokio::test]
    async fn update_metadata_with_versionid_is_invalid_argument() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin?versionid=v-7")
                .unwrap(),
        };
        let opts = UpdateMetadataOptions::default();
        let err = ovstorage_plugin::shim::Backend::update_metadata(&backend, target, opts, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn read_returns_canceled_when_token_already_cancelled() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin").unwrap(),
        };
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        let err = ovstorage_plugin::shim::Backend::read(
            &backend,
            target,
            ReadOptions::default(),
            Some(token),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn list_versions_returns_canceled_when_token_already_cancelled() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin").unwrap(),
        };
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        let err = ovstorage_plugin::shim::Backend::list_versions(
            &backend,
            target,
            ListVersionsOptions::default(),
            Some(token),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn stat_returns_canceled_when_token_already_cancelled() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin").unwrap(),
        };
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        let err = ovstorage_plugin::shim::Backend::stat(
            &backend,
            target,
            StatOptions::default(),
            Some(token),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn delete_returns_canceled_when_token_already_cancelled() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin").unwrap(),
        };
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        let err = ovstorage_plugin::shim::Backend::delete(
            &backend,
            target,
            DeleteOptions::default(),
            Some(token),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn list_returns_canceled_when_token_already_cancelled() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/").unwrap(),
        };
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        let err = ovstorage_plugin::shim::Backend::list(
            &backend,
            target,
            ListOptions::default(),
            Some(token),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn write_redirect_returns_canceled_when_token_already_cancelled() {
        let backend = shared_key_backend();
        let target = ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
            resolved_address: address::parse("azure://acct/container/blob.bin").unwrap(),
        };
        let token = ovstorage_plugin::CancellationToken::new();
        token.cancel();
        // Need a non-None size_hint here: write_redirect refuses
        // unknown sizes before checking the cancel token, and that
        // refusal would mask the cancellation we want to exercise.
        let opts = WriteOptions {
            size_hint: Some(1024),
            ..WriteOptions::default()
        };
        let err =
            ovstorage_plugin::shim::Backend::write_redirect(&backend, target, opts, Some(token))
                .await
                .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Cancelled);
    }

    #[test]
    fn synthesize_redirect_response_routes_412_to_precondition_failed() {
        let result = ovstorage_plugin::RedirectResult {
            status_code: 412,
            captured_headers: vec![("etag".into(), "\"abc\"".into())],
            captured_body: b"<Error>...</Error>".to_vec(),
        };
        let synthetic = synthesize_redirect_response(&result);
        assert_eq!(synthetic.status, 412);
        assert_eq!(synthetic.headers.first("etag"), Some("\"abc\""));
        let err = map_status_to_error(&synthetic, "redirect upload #0");
        assert_eq!(err.code(), ovstorage_plugin::ErrorCode::PreconditionFailed);
    }
}
