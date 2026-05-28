// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native S3 / S3-compatible `shim::Backend` implementation.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use tracing::{Instrument as _, debug, info, warn};

use ovstorage_plugin::ReadRedirect;
use ovstorage_plugin::shim;
use ovstorage_plugin::{
    AccessDecision, BackendItemInfo, CopyOptions, CreateDirectoryOptions, ReadOptions, ReadResult,
    RenameOptions, UpdateMetadataOptions,
};
use ovstorage_plugin::{
    AccessOps, CancellationToken, Capabilities, ChecksumAlgorithm, ChecksumSet,
    DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, ErrorContext, HttpRequest,
    IfDestExists, ListOptions, ListVersionsOptions, MtimeFormat, ObjectInfo, ObjectKind,
    RedirectBodySource, RedirectResultBatch, RedirectScope, ResolvedTarget, ResponseParsing,
    Result, ResultCapture, SecretBundle, StatOptions, SystemMetadata, Url, UserMetadata,
    VersionListOrder, WriteOptions, WriteRedirect, WriteRedirectBatch, WriteResult, address,
    race_cancel, reject_pinned_for_mutation,
};

const PINNED_VERSION_KEYS: &[&str] = &["versionId"];

/// Pull the legacy `(if_match_etag, no_overwrite)` pair out of the new
/// `IfDestExists` discriminator. S3's wire protocol uses two separate
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

use crate::config::{S3AddressParts, S3Config, resolve_endpoint};
use crate::convert::require_etag_only_if_match;
use crate::credentials::AwsCredentials;

/// Display wrapper that strips query params and fragment from a URL before logging.
/// Signed URLs embed credentials in query strings; this prevents accidental leakage.
struct RedactedUrl<'a>(&'a Url);

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
use crate::http::{HttpResponse, build_client, execute, map_error_status};
use crate::multipart::{
    DEFAULT_PART_SIZE_BYTES, MIN_PART_SIZE_BYTES, MULTIPART_REDIRECT_THRESHOLD_BYTES,
    MultipartContinuation, MultipartPart, compute_total_parts, ensure_streaming_part_limit,
    part_sizes,
};
use crate::sigv4::{
    CanonicalRequest, SigningContext, canonicalize_query, payload_hash, presign_query, sign_request,
};
use crate::xml::{
    build_complete_multipart_upload_body, parse_complete_multipart_upload,
    parse_initiate_multipart_upload, parse_list_objects_v2, parse_list_versions, parse_s3_error,
};

/// Default presigned-URL TTL; short because the host follower consumes immediately.
pub(crate) const DEFAULT_PRESIGN_TTL_SECS: u32 = 300;

/// Capabilities advertised for AWS-shaped buckets and well-known S3-compatible profiles.
pub fn s3_capabilities() -> Capabilities {
    s3_capabilities_for_config(None)
}

pub fn s3_capabilities_for_config(config: Option<&S3Config>) -> Capabilities {
    let mut capabilities = Capabilities::empty();
    capabilities.supports_no_overwrite_write = true;
    capabilities.supports_if_match_write = true;
    capabilities.supports_server_side_copy = true;
    capabilities.supports_server_side_rename = true;
    capabilities.writes_are_atomic = true;
    capabilities.supports_write = true;
    capabilities.supports_write_stream = true;
    capabilities.supports_write_redirect = true;
    capabilities.supports_delete = true;
    capabilities.supports_recursive_list = true;
    capabilities.supports_list = true;
    capabilities.wants_list_backed_stat = true;
    capabilities.has_real_directories = false;
    capabilities.supports_create_directory = true;
    capabilities.supports_delete_directory = true;
    capabilities.populates_subdirectory_metadata = false;
    capabilities.supports_version_listing = true;
    capabilities.version_list_order = Some(VersionListOrder::Newest);
    capabilities.supports_native_metadata_patch = false;
    capabilities.supports_metadata_rewrite_emulation = true;
    capabilities.supports_access_check = true;
    if config
        .and_then(|config| config.sqs_queue_url.as_ref())
        .is_some()
    {
        capabilities.supports_watch_directory = true;
        capabilities.watch_directory_resumable = false;
        capabilities.watch_directory_max_lag = Some(Duration::from_secs(60));
        capabilities.watch_directory_kinds = ovstorage_plugin::ChangeKindSet {
            created: true,
            modified: true,
            deleted: true,
            metadata_changed: true,
        };
    }
    // S3 always emits a write_redirect (single PUT or multipart >= 100 MiB); host shouldn't size-gate it.
    capabilities.redirect_size_threshold = None;
    capabilities
}

pub struct S3Backend {
    config: S3Config,
    credentials: Mutex<Option<AwsCredentials>>,
    is_anonymous: bool,
    client: reqwest::Client,
}

impl S3Backend {
    pub fn with_credentials(config: S3Config, credentials: AwsCredentials) -> Result<Self> {
        Ok(Self {
            credentials: Mutex::new(Some(credentials)),
            is_anonymous: false,
            client: build_client()?,
            config,
        })
    }

    /// No credentials, no signing — sends bare unsigned HTTP requests.
    /// The server decides whether the bucket / object is publicly accessible.
    pub fn anonymous(config: S3Config) -> Result<Self> {
        Ok(Self {
            credentials: Mutex::new(None),
            is_anonymous: true,
            client: build_client()?,
            config,
        })
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    pub(crate) fn is_anonymous(&self) -> bool {
        self.is_anonymous
    }

    pub fn store_credentials(&self, credentials: AwsCredentials) {
        *self.credentials.lock().expect("credential mutex poisoned") = Some(credentials);
    }

    /// Returns cached credentials or the empty-strings sentinel for anonymous
    /// backends. The sentinel is never passed to a signing function — callers
    /// must branch on `is_anonymous` before signing.
    pub(crate) fn resolve_credentials(
        &self,
        _bundle: Option<&SecretBundle>,
    ) -> Result<AwsCredentials> {
        if self.is_anonymous {
            return Ok(AwsCredentials::empty());
        }
        if let Some(creds) = self
            .credentials
            .lock()
            .expect("credential mutex poisoned")
            .as_ref()
        {
            debug!(plugin = "s3", cache.hit = true, "credential cache hit");
            return Ok(creds.clone());
        }
        Err(Error::new(
            ErrorCode::AuthRequired,
            "S3 backend has no credentials configured (and is not anonymous)",
        )
        .with_context(ErrorContext::Auth {
            connection_id: ovstorage_plugin::ConnectionId(String::new()),
            reason: Some("missing_credentials".into()),
            expired_at: None,
        }))
    }

    pub(crate) fn parse_target(&self, target: &ResolvedTarget) -> Result<S3AddressParts> {
        crate::config::parse_s3_address(&target.resolved_address, &self.config.bucket)
    }

    pub(crate) fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn parse_object_target(&self, target: &ResolvedTarget) -> Result<S3AddressParts> {
        let parts = self.parse_target(target)?;
        if parts.key.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "S3 object operation requires a non-empty object key",
            ));
        }
        Ok(parts)
    }

    fn signing_context<'a>(&'a self, amz_date: &'a str, date_stamp: &'a str) -> SigningContext<'a> {
        SigningContext {
            region: self.config.signing_region(),
            service: "s3",
            amz_date,
            date_stamp,
        }
    }
}

#[async_trait::async_trait]
impl shim::Backend for S3Backend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "s3.stat",
            op = "stat",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_object_target(&target)?;
            let credentials = self.resolve_credentials(None)?;
            let version_id = address_version_id(&target.resolved_address);
            // S3 is a flat namespace. The dispatcher's marker-folding
            // runs on `list`, not `stat`, so directory shape has to be
            // resolved here when the caller addresses a `key/`.
            //
            // For a trailing-slash address, the HEAD probes the
            // zero-byte marker object directly. If it exists, the
            // returned `ObjectInfo` is the marker — tag it as
            // `DirectoryMarker`. If the marker is missing, a bounded
            // prefix-list probe must prove a descendant exists before
            // we surface `DirectoryInferred`.
            let trailing_slash = parts.key.ends_with('/');
            let response = self
                .head_object(&credentials, &parts.key, version_id.as_deref())
                .await?;
            if response.status == 404 {
                if trailing_slash && version_id.is_none() {
                    let probe = self
                        .flat_directory_probe(&credentials, &parts.key, &target.resolved_address)
                        .await?;
                    match probe {
                        FlatDirectoryProbe::Marker(info) => return Ok(*info),
                        FlatDirectoryProbe::Inferred => {
                            return Ok(ObjectInfo {
                                address: target.resolved_address.clone(),
                                kind: ObjectKind::DirectoryInferred,
                                etag: None,
                                version: None,
                                size: None,
                                mtime: None,
                                checksums: ChecksumSet::default(),
                                effective_permissions: None,
                                system_metadata: None,
                                user_metadata: None,
                                modified_by: None,
                            });
                        }
                        FlatDirectoryProbe::Missing => {}
                    }
                }
                return Err(Error::new(
                    ErrorCode::NotFound,
                    format!("S3 object '{}' not found", parts.key),
                ));
            }
            if !is_success(response.status) {
                return Err(map_error_status(response.status, &response.body));
            }
            let mut info = object_info_from_head(&target.resolved_address, &response);
            if trailing_slash {
                info.kind = ObjectKind::DirectoryMarker;
            }
            Ok(info)
        })
        .instrument(span)
        .await
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        require_etag_only_if_match(opts.if_match.as_ref())?;
        let _span = tracing::debug_span!(
            "s3.read",
            op = "read",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        )
        .entered();
        let _ = &cancel; // signs a presigned redirect URL; no I/O here.
        let parts = self.parse_object_target(&target)?;
        let (now, amz_date, date_stamp) = current_amz_date();
        let endpoint = resolve_endpoint(&self.config, &parts.key)?;

        let mut existing_query: Vec<(String, String)> = Vec::new();
        if let Some(version_id) = address_version_id(&target.resolved_address) {
            existing_query.push(("versionId".to_string(), version_id));
        }
        if self.config.force_request_payer {
            existing_query.push(("x-amz-request-payer".to_string(), "requester".to_string()));
        }
        let mut request_headers: Vec<(String, String)> = Vec::new();
        if let Some(range_header) = read_range_header(&opts)? {
            request_headers.push(("range".to_string(), range_header));
        }
        if let Some(if_match) = opts.if_match.as_deref() {
            request_headers.push(("if-match".to_string(), quote_etag(if_match)));
        }
        let url = if self.is_anonymous {
            let canonical = canonicalize_query(&existing_query);
            if canonical.is_empty() {
                format!(
                    "{}://{}{}",
                    endpoint.scheme, endpoint.host, endpoint.canonical_uri,
                )
            } else {
                format!(
                    "{}://{}{}?{}",
                    endpoint.scheme, endpoint.host, endpoint.canonical_uri, canonical,
                )
            }
        } else {
            let credentials = self.resolve_credentials(None)?;
            let ctx = self.signing_context(&amz_date, &date_stamp);
            let presigned = presign_query(
                &credentials,
                &ctx,
                "GET",
                &endpoint.canonical_uri,
                &endpoint.host,
                &canonicalize_query(&existing_query),
                DEFAULT_PRESIGN_TTL_SECS,
                &request_headers,
            );
            format!(
                "{}://{}{}?{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri, presigned.query,
            )
        };
        let request = HttpRequest {
            method: "GET".to_string(),
            url,
            headers: request_headers,
        };
        let scope = RedirectScope {
            physical_url_prefix: format!("{}://{}/", endpoint.scheme, endpoint.host),
            operations: AccessOps {
                read: true,
                ..AccessOps::default()
            },
            expires_at: now + Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64),
        };
        Ok(ReadResult::Redirect(ReadRedirect {
            request,
            response_parsing: read_response_parsing(),
            expires_at: scope.expires_at,
            scope,
            audit_id: format!("s3-read-{}", parts.key),
            policy_epoch: 0,
        }))
    }

    /// Buffered inline write — used by callers writing zero-byte or
    /// sub-`redirect_size_threshold` bodies, where the redirect round-trip
    /// is pure overhead. Issues a single signed PutObject directly from
    /// the plugin instead of emitting a `WriteRedirect`.
    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(&target.resolved_address, "s3 write", PINNED_VERSION_KEYS)?;
        let span = tracing::debug_span!(
            "s3.write",
            op = "write",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = bytes.len() as u64,
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parts = self.parse_object_target(&target)?;
                let credentials = self.resolve_credentials(None)?;
                let opts = with_message_stashed(opts);
                let info = self
                    .put_object_inline(&credentials, &parts.key, &bytes, &opts)
                    .await?;
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
        reject_pinned_for_mutation(
            &target.resolved_address,
            "s3 write_redirect",
            PINNED_VERSION_KEYS,
        )?;
        // S3 write_redirect emits a presigned PUT (or a multipart batch) with
        // a fixed advertised `Content-Length`. Without a known upload size we
        // can't supply that length; the previous code substituted
        // `S3_PUTOBJECT_MAX_BYTES` (5 GiB), which produced Content-Length
        // mismatches at the follower or unbounded body sources for the
        // single-PutObject path. Refuse instead so the host falls back to
        // `write_stream`, which buffers parts incrementally.
        let size = opts.size_hint.ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "s3 write_redirect requires a known size_hint; \
                 streaming uploads route through write_stream",
            )
        })?;
        let span = tracing::debug_span!(
            "s3.write",
            op = "write",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = size,
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                // ≥ 100 MiB known size → multipart; otherwise single PutObject.
                let parts = self.parse_object_target(&target)?;
                let credentials = self.resolve_credentials(None)?;
                let (if_match_etag, no_overwrite) = split_if_dest(&opts.if_dest);
                if size >= MULTIPART_REDIRECT_THRESHOLD_BYTES {
                    let total_parts = compute_total_parts(size)?;
                    let upload_id = self
                        .create_multipart_upload(&credentials, &parts.key, &opts)
                        .await?;
                    let continuation = MultipartContinuation::new(
                        parts.key.clone(),
                        upload_id,
                        opts.user_metadata
                            .as_ref()
                            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                        if_match_etag.clone(),
                        no_overwrite,
                        total_parts,
                    );
                    let batch = self.build_part_batch(&credentials, &continuation, size)?;
                    return Ok(WriteRedirectBatch {
                        continuation: continuation.encode(),
                        redirects: batch,
                    });
                }
                // Empty upload_id marks single-PutObject: continue_write skips CompleteMultipartUpload.
                let continuation = MultipartContinuation::new(
                    parts.key.clone(),
                    String::new(),
                    opts.user_metadata
                        .as_ref()
                        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                    if_match_etag,
                    no_overwrite,
                    1,
                );
                let redirect =
                    self.build_single_put_redirect(&credentials, &parts.key, size, &opts)?;
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
    ) -> Result<ovstorage_plugin::WriteStep> {
        let span = tracing::debug_span!(
            "s3.continue_write",
            op = "write",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(cancel.as_ref(), async move {
        self.parse_object_target(&target)?;
        let mut continuation = MultipartContinuation::decode(&redirects.continuation)?;
        if redirects.redirects.len() != results.results.len() {
            if !continuation.upload_id.is_empty() {
                let _ = self.abort_multipart_upload(&continuation).await;
            }
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "S3 multipart continuation result count does not match the redirect batch",
            ));
        }
        // Empty upload_id: the single-PutObject redirect's response is itself the commit.
        if continuation.upload_id.is_empty() {
            if results.results.len() != 1 {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "S3 single-PutObject continuation expected exactly one result",
                ));
            }
            let result = &results.results[0];
            if !is_success(result.status_code) {
                return Err(map_error_status(result.status_code, &result.captured_body));
            }
            let etag = header_value(&result.captured_headers, "etag")
                .map(|value| value.trim_matches('"').to_string());
            let info = ObjectInfo {
                address: target.resolved_address,
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
            };
            return Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }));
        }
        let starting_index = continuation.parts.len();
        for (offset, (redirect, result)) in redirects
            .redirects
            .iter()
            .zip(results.results.iter())
            .enumerate()
        {
            let part_number = (starting_index + offset + 1) as u32;
            if !is_success(result.status_code) {
                let _ = self.abort_multipart_upload(&continuation).await;
                return Err(map_error_status(result.status_code, &result.captured_body));
            }
            let etag = match header_value(&result.captured_headers, "etag")
                .map(|value| value.trim_matches('"').to_string())
            {
                Some(etag) => etag,
                None => {
                    let _ = self.abort_multipart_upload(&continuation).await;
                    return Err(Error::new(
                        ErrorCode::Internal,
                        format!(
                            "S3 multipart part {part_number} response did not include an ETag header"
                        ),
                    ));
                }
            };
            let (offset_bytes, length_bytes) = match &redirect.body_source {
                RedirectBodySource::UserBytes { offset, len } => (*offset, *len),
                _ => (0u64, 0u64),
            };
            continuation.parts.push(MultipartPart {
                part_number,
                byte_offset: offset_bytes,
                byte_length: length_bytes,
                etag: Some(etag),
            });
        }
        if continuation.parts.len() < continuation.total_parts as usize {
            let _ = self.abort_multipart_upload(&continuation).await;
            return Err(Error::new(
                ErrorCode::Internal,
                "S3 multipart continuation expected more parts than the host returned",
            ));
        }
        let credentials = self.resolve_credentials(None)?;
        let info = match self
            .complete_multipart_upload(&credentials, &continuation)
            .await
        {
            Ok(info) => info,
            Err(err) => {
                let _ = self.abort_multipart_upload(&continuation).await;
                return Err(err);
            }
        };
        let _ = target;
        Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
      }.instrument(span))
      .await
    }

    /// Streaming write: buffers ~8 MiB chunks and uploads via direct `UploadPart` calls,
    /// bypassing the buffered redirect-follower without materialising the full object.
    async fn write_stream(
        &self,
        target: ResolvedTarget,
        body: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "s3 write_stream",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "s3.write_stream",
            op = "write",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
            // size_bytes omitted: streaming body — unknown at entry
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                match self.stream_write(target, body, opts).await? {
                    ovstorage_plugin::WriteStep::Done(result) => Ok(result),
                    ovstorage_plugin::WriteStep::Redirects(_) => Err(Error::new(
                        ErrorCode::Internal,
                        "S3 stream_write produced unexpected Redirects step",
                    )),
                }
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
        let span = tracing::debug_span!(
            "s3.delete",
            op = "delete",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parts = self.parse_object_target(&target)?;
                let credentials = self.resolve_credentials(None)?;
                let mut headers: Vec<(String, String)> = Vec::new();
                if let Some(if_match) = opts.if_match.clone() {
                    headers.push(("if-match".to_string(), quote_etag(&if_match)));
                }
                let query = match address_version_id(&target.resolved_address) {
                    Some(version) => canonicalize_query(&[("versionId".to_string(), version)]),
                    None => String::new(),
                };
                let response = self
                    .signed_request(&credentials, "DELETE", &parts.key, &query, &headers, &[])
                    .await?;
                // delete is idempotent: a missing target is success.
                if response.status == 404 {
                    return Ok(());
                }
                if !is_success(response.status) {
                    return Err(map_error_status(response.status, &response.body));
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
        let span = tracing::debug_span!(
            "s3.list",
            op = "list",
            plugin = "s3",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parts = self.parse_target(&prefix)?;
                let credentials = self.resolve_credentials(None)?;
                let prefix_key = if parts.key.is_empty() || parts.key.ends_with('/') {
                    parts.key.clone()
                } else {
                    format!("{}/", parts.key)
                };
                let mut params: Vec<(String, String)> =
                    vec![("list-type".to_string(), "2".to_string())];
                if !prefix_key.is_empty() {
                    params.push(("prefix".to_string(), prefix_key.clone()));
                }
                if !opts.recursive {
                    params.push(("delimiter".to_string(), "/".to_string()));
                }
                if let Some(max_results) = opts.max_results {
                    params.push(("max-keys".to_string(), max_results.to_string()));
                }
                if let Some(token) = opts.page_token.as_ref() {
                    params.push(("continuation-token".to_string(), token.clone()));
                }
                let query = canonicalize_query(&params);
                let response = self
                    .signed_request(&credentials, "GET", "", &query, &[], &[])
                    .await?;
                if !is_success(response.status) {
                    return Err(map_error_status(response.status, &response.body));
                }
                let body_text = String::from_utf8(response.body).map_err(|_| {
                    Error::new(
                        ErrorCode::Internal,
                        "S3 ListObjectsV2 response body was not UTF-8",
                    )
                })?;
                let parsed = parse_list_objects_v2(&body_text)?;
                let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
                let mut items: Vec<ObjectInfo> = Vec::new();
                let mut marker_addresses = std::collections::HashSet::new();
                for object in parsed.contents {
                    if object.key == prefix_key {
                        continue;
                    }
                    let address = address::join_relative(&bucket_root, &object.key)?;
                    let _ = address::strip_prefix(&address, &prefix.resolved_address).ok_or_else(
                        || {
                            Error::new(
                                ErrorCode::Internal,
                                format!(
                                    "S3 returned object key '{}' outside requested prefix '{}'",
                                    object.key,
                                    RedactedUrl(&prefix.resolved_address)
                                ),
                            )
                        },
                    )?;
                    let mtime = object
                        .last_modified
                        .as_deref()
                        .and_then(parse_iso8601_to_system_time);
                    let etag = object.etag.clone();
                    let size = object.size;
                    let mut system_metadata: SystemMetadata = SystemMetadata::new();
                    if let Some(class) = object.storage_class {
                        system_metadata.insert("x-amz-storage-class".into(), class);
                    }
                    let kind = if object.key.ends_with('/') && object.size.unwrap_or(0) == 0 {
                        ObjectKind::DirectoryMarker
                    } else {
                        ObjectKind::File
                    };
                    if kind == ObjectKind::DirectoryMarker {
                        marker_addresses.insert(address.as_str().to_string());
                    }
                    items.push(ObjectInfo {
                        address,
                        kind,
                        etag,
                        version: None,
                        size: (kind == ObjectKind::File).then_some(size).flatten(),
                        mtime,
                        checksums: ChecksumSet::default(),
                        effective_permissions: None,
                        system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
                        user_metadata: None,
                        modified_by: None,
                    });
                }
                for prefix_str in parsed.common_prefixes {
                    let address = address::join_relative(&bucket_root, &prefix_str)?;
                    // If S3 reports the same slash key as both a real zero-byte
                    // marker object and a CommonPrefix, keep the marker. The
                    // marker is the concrete directory representation and
                    // carries etag/mtime metadata the inferred prefix lacks.
                    if marker_addresses.contains(address.as_str()) {
                        continue;
                    }
                    let _ = address::strip_prefix(&address, &prefix.resolved_address).ok_or_else(
                        || {
                            Error::new(
                                ErrorCode::Internal,
                                format!(
                                    "S3 returned common prefix '{}' outside requested prefix '{}'",
                                    prefix_str,
                                    RedactedUrl(&prefix.resolved_address)
                                ),
                            )
                        },
                    )?;
                    // S3 has no explicit directory entity; tag CommonPrefixes as `DirectoryInferred`.
                    items.push(ObjectInfo {
                        address,
                        kind: ObjectKind::DirectoryInferred,
                        etag: None,
                        version: None,
                        size: None,
                        mtime: None,
                        checksums: ChecksumSet::default(),
                        effective_permissions: None,
                        system_metadata: None,
                        user_metadata: None,
                        modified_by: None,
                    });
                }
                Ok(items)
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
        let span = tracing::debug_span!(
            "s3.list_versions",
            op = "list",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parts = self.parse_target(&target)?;
                let credentials = self.resolve_credentials(None)?;
                let mut params: Vec<(String, String)> =
                    vec![("versions".to_string(), String::new())];
                if !parts.key.is_empty() {
                    params.push(("prefix".to_string(), parts.key.clone()));
                }
                if let Some(max_results) = opts.max_results {
                    params.push(("max-keys".to_string(), max_results.to_string()));
                }
                if let Some(token) = opts.page_token.as_ref() {
                    if let Some((key, version)) = token.split_once('|') {
                        if !key.is_empty() {
                            params.push(("key-marker".to_string(), key.to_string()));
                        }
                        if !version.is_empty() {
                            params.push(("version-id-marker".to_string(), version.to_string()));
                        }
                    } else {
                        params.push(("key-marker".to_string(), token.clone()));
                    }
                }
                let query = canonicalize_query(&params);
                let response = self
                    .signed_request(&credentials, "GET", "", &query, &[], &[])
                    .await?;
                if !is_success(response.status) {
                    return Err(map_error_status(response.status, &response.body));
                }
                let body_text = String::from_utf8(response.body).map_err(|_| {
                    Error::new(
                        ErrorCode::Internal,
                        "S3 ListObjectVersions response body was not UTF-8",
                    )
                })?;
                let parsed = parse_list_versions(&body_text)?;
                let mut base_address = target.resolved_address.clone();
                base_address.set_query(None);
                base_address.set_fragment(None);
                let mut items = Vec::new();
                for version in parsed.versions {
                    if version.key != parts.key {
                        continue;
                    }
                    // S3 ListObjectVersions emits "null" for entries from a
                    // non-versioned bucket; an entry without an id can't be
                    // addressed via a query-pin and is skipped.
                    let Some(version_id) = version.version_id.clone() else {
                        continue;
                    };
                    let mtime = version
                        .last_modified
                        .as_deref()
                        .and_then(parse_iso8601_to_system_time);
                    let address =
                        address::with_query_pair(&base_address, "versionId", &version_id)?;
                    items.push(ObjectInfo {
                        address,
                        kind: ObjectKind::File,
                        etag: version.etag,
                        version: Some(version_id),
                        size: version.size,
                        mtime,
                        checksums: ChecksumSet::default(),
                        effective_permissions: None,
                        system_metadata: None,
                        user_metadata: None,
                        modified_by: None,
                    });
                }
                Ok(items)
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
        let span = tracing::debug_span!(
            "s3.get_latest_version",
            op = "stat",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parts = self.parse_object_target(&target)?;
                let credentials = self.resolve_credentials(None)?;
                let pinned = address_version_id(&target.resolved_address);
                let response = self
                    .head_object(&credentials, &parts.key, pinned.as_deref())
                    .await?;
                if response.status == 404 {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        format!("S3 object '{}' not found", parts.key),
                    ));
                }
                if !is_success(response.status) {
                    return Err(map_error_status(response.status, &response.body));
                }
                let info = object_info_from_head(&target.resolved_address, &response);
                let value = pinned.or_else(|| info.version.clone()).ok_or_else(|| {
                    Error::new(
                        ErrorCode::Unsupported,
                        "S3 object is not versioned (no x-amz-version-id on HEAD)",
                    )
                })?;
                let mut base_address = target.resolved_address.clone();
                base_address.set_query(None);
                base_address.set_fragment(None);
                let address = address::with_query_pair(&base_address, "versionId", &value)?;
                Ok(ObjectInfo { address, ..info })
            }
            .instrument(span),
        )
        .await
    }

    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: ovstorage_plugin::WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::BackendChangeStream> {
        crate::subscription::watch_directory(self, prefix, opts, cancel).await
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_target(&target)?;
            let credentials = self.resolve_credentials(None)?;
            let key = directory_marker_key(&parts.key)?;
            let response = self
                .signed_request(&credentials, "PUT", &key, "", &[], &[])
                .await?;
            if !is_success(response.status) {
                return Err(map_error_status(response.status, &response.body));
            }
            Ok(BackendItemInfo {
                kind: ObjectKind::DirectoryMarker,
                etag: response
                    .header("etag")
                    .map(|value| value.trim_matches('"').to_string()),
                version: response.header("x-amz-version-id").map(str::to_string),
                size: Some(0),
                mtime: response.header("last-modified").and_then(parse_http_date),
                ..BackendItemInfo::default()
            })
        })
        .await
    }

    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_target(&target)?;
            let credentials = self.resolve_credentials(None)?;
            let key = directory_marker_key(&parts.key)?;
            let response = self
                .signed_request(&credentials, "DELETE", &key, "", &[], &[])
                .await?;
            // delete_directory is idempotent: a missing marker is success.
            if response.status == 404 {
                return Ok(());
            }
            if !is_success(response.status) {
                return Err(map_error_status(response.status, &response.body));
            }
            Ok(())
        })
        .await
    }

    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::WriteStep> {
        reject_pinned_for_mutation(&dest.resolved_address, "s3 copy(dst)", PINNED_VERSION_KEYS)?;
        let span = tracing::debug_span!(
            "s3.copy",
            op = "copy",
            plugin = "s3",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let src_parts = self.parse_object_target(&src)?;
                let dest_parts = self.parse_object_target(&dest)?;
                let credentials = self.resolve_credentials(None)?;
                let src_version = address_version_id(&src.resolved_address);
                let mut headers: Vec<(String, String)> = vec![(
                    "x-amz-copy-source".to_string(),
                    copy_source_header(&src_parts, src_version.as_deref()),
                )];
                if let Some(if_source) = opts.if_source.as_deref() {
                    headers.push((
                        "x-amz-copy-source-if-match".to_string(),
                        quote_etag(if_source),
                    ));
                }
                match &opts.if_dest {
                    IfDestExists::Overwrite => {}
                    IfDestExists::Fail => {
                        headers.push(("if-none-match".to_string(), "*".to_string()));
                    }
                    IfDestExists::MatchEtag(etag) => {
                        headers.push(("if-match".to_string(), quote_etag(etag)));
                    }
                }
                let response = self
                    .signed_request(&credentials, "PUT", &dest_parts.key, "", &headers, &[])
                    .await?;
                if !is_success(response.status) {
                    return Err(map_error_status(response.status, &response.body));
                }
                let info = object_info_from_head(&dest.resolved_address, &response);
                Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
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
        reject_pinned_for_mutation(&src.resolved_address, "s3 rename(src)", PINNED_VERSION_KEYS)?;
        reject_pinned_for_mutation(
            &dest.resolved_address,
            "s3 rename(dst)",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "s3.rename",
            op = "rename",
            plugin = "s3",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        async move {
            let copy_opts = CopyOptions {
                if_source: opts.if_source.clone(),
                if_dest: opts.if_dest.clone(),
                message: opts.message,
            };
            match self
                .copy(src.clone(), dest, copy_opts, cancel.clone())
                .await?
            {
                ovstorage_plugin::WriteStep::Done(_) => {
                    // Carry the caller's source precondition through to the
                    // delete so a concurrent source mutation between the copy
                    // and the delete cannot weaken the contract.
                    let delete_opts = DeleteOptions {
                        if_match: opts.if_source.clone(),
                    };
                    if let Err(err) = self.delete(src.clone(), delete_opts, cancel).await {
                        return Err(Error::new(
                            ErrorCode::Internal,
                            format!(
                                "S3 rename copied to destination but failed to delete source: {}",
                                err.message()
                            ),
                        ));
                    }
                    Ok(())
                }
                ovstorage_plugin::WriteStep::Redirects(_) => Err(Error::new(
                    ErrorCode::Internal,
                    "S3 server-side copy unexpectedly returned a redirect batch",
                )),
            }
        }
        .instrument(span)
        .await
    }

    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        require_etag_only_if_match(opts.if_match.as_ref())?;
        reject_pinned_for_mutation(
            &target.resolved_address,
            "s3 update_metadata",
            PINNED_VERSION_KEYS,
        )?;
        race_cancel(cancel.as_ref(), async move {
            if !opts.allow_rewrite_emulation {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    "S3 metadata patch requires UpdateMetadataOptions.allow_rewrite_emulation = true",
                ));
            }
            let parts = self.parse_object_target(&target)?;
            let credentials = self.resolve_credentials(None)?;
            let version_id = address_version_id(&target.resolved_address);
            let head = self
                .head_object(&credentials, &parts.key, version_id.as_deref())
                .await?;
            if !is_success(head.status) {
                return Err(map_error_status(head.status, &head.body));
            }
            let existing = collect_user_metadata(&head).unwrap_or_default();
            let mut desired = merge_metadata(
                &existing,
                &opts.user_metadata_set,
                &opts.user_metadata_remove,
            );
            if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                desired.retain(|(k, _)| k != "x-ov-message");
                desired.push(("x-ov-message".to_string(), message.to_string()));
            }
            let mut headers: Vec<(String, String)> = vec![
                (
                    "x-amz-copy-source".to_string(),
                    copy_source_header(&parts, version_id.as_deref()),
                ),
                (
                    "x-amz-metadata-directive".to_string(),
                    "REPLACE".to_string(),
                ),
            ];
            for (key, value) in &desired {
                headers.push((format!("x-amz-meta-{}", key.to_ascii_lowercase()), value.clone()));
            }
            if let Some(if_match) = opts.if_match.clone() {
                headers.push((
                    "x-amz-copy-source-if-match".to_string(),
                    quote_etag(&if_match),
                ));
            }
            let response =
                self.signed_request(&credentials, "PUT", &parts.key, "", &headers, &[]).await?;
            if !is_success(response.status) {
                return Err(map_error_status(response.status, &response.body));
            }
            Ok(BackendItemInfo {
                kind: ObjectKind::File,
                etag: response
                    .header("etag")
                    .map(|value| value.trim_matches('"').to_string()),
                version: response.header("x-amz-version-id").map(str::to_string),
                size: response
                    .header("content-length")
                    .and_then(|value| value.parse().ok()),
                mtime: response.header("last-modified").and_then(parse_http_date),
                ..BackendItemInfo::default()
            })
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
            let parts = self.parse_target(&target)?;
            let credentials = self.resolve_credentials(None)?;
            let response = if parts.key.is_empty() {
                self.signed_request(&credentials, "GET", "", "policyStatus=", &[], &[])
                    .await?
            } else {
                self.head_object(&credentials, &parts.key, None).await?
            };
            match response.status {
                200..=299 => Ok(AccessDecision {
                    allowed: true,
                    denied_ops: AccessOps::default(),
                    reason: None,
                }),
                401 | 403 => Ok(AccessDecision {
                    allowed: false,
                    denied_ops: ops,
                    reason: Some(format!("S3 returned HTTP {}", response.status)),
                }),
                404 => Err(Error::new(
                    ErrorCode::NotFound,
                    "S3 access target not found",
                )),
                other => Err(map_error_status(other, &response.body)),
            }
        })
        .await
    }
}

impl S3Backend {
    async fn head_object(
        &self,
        credentials: &AwsCredentials,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<HttpResponse> {
        let query = match version_id {
            Some(version) => canonicalize_query(&[("versionId".to_string(), version.to_string())]),
            None => String::new(),
        };
        self.signed_request(credentials, "HEAD", key, &query, &[], &[])
            .await
    }

    async fn flat_directory_probe(
        &self,
        credentials: &AwsCredentials,
        prefix_key: &str,
        address: &Url,
    ) -> Result<FlatDirectoryProbe> {
        let params: Vec<(String, String)> = vec![
            ("delimiter".to_string(), "/".to_string()),
            ("list-type".to_string(), "2".to_string()),
            ("max-keys".to_string(), "2".to_string()),
            ("prefix".to_string(), prefix_key.to_string()),
        ];
        let response = self
            .signed_request(
                credentials,
                "GET",
                "",
                &canonicalize_query(&params),
                &[],
                &[],
            )
            .await?;
        if !is_success(response.status) {
            return Err(map_error_status(response.status, &response.body));
        }
        let body_text = String::from_utf8(response.body).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "S3 ListObjectsV2 response body was not UTF-8",
            )
        })?;
        let parsed = parse_list_objects_v2(&body_text)?;
        if let Some(marker) = parsed
            .contents
            .iter()
            .find(|object| object.key == prefix_key)
        {
            let mut system_metadata: SystemMetadata = SystemMetadata::new();
            if let Some(class) = marker.storage_class.clone() {
                system_metadata.insert("x-amz-storage-class".into(), class);
            }
            return Ok(FlatDirectoryProbe::Marker(Box::new(ObjectInfo {
                address: address.clone(),
                kind: ObjectKind::DirectoryMarker,
                etag: marker.etag.clone(),
                version: None,
                size: marker.size,
                mtime: marker
                    .last_modified
                    .as_deref()
                    .and_then(parse_iso8601_to_system_time),
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
                user_metadata: None,
                modified_by: None,
            })));
        }
        let mut descendant_seen = false;
        for object in &parsed.contents {
            if !object.key.starts_with(prefix_key) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "S3 returned object key '{}' outside requested stat prefix '{}'",
                        object.key, prefix_key
                    ),
                ));
            }
            descendant_seen = true;
        }
        for prefix in &parsed.common_prefixes {
            if prefix == prefix_key {
                continue;
            }
            if !prefix.starts_with(prefix_key) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "S3 returned common prefix '{}' outside requested stat prefix '{}'",
                        prefix, prefix_key
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

    async fn put_object_inline(
        &self,
        credentials: &AwsCredentials,
        key: &str,
        body: &[u8],
        opts: &WriteOptions,
    ) -> Result<ObjectInfo> {
        let mut headers: Vec<(String, String)> = Vec::new();
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => {
                headers.push(("if-none-match".to_string(), "*".to_string()));
            }
            IfDestExists::MatchEtag(etag) => {
                headers.push(("if-match".to_string(), quote_etag(etag)));
            }
        }
        if let Some(metadata) = opts.user_metadata.as_ref() {
            for (k, v) in metadata {
                headers.push((format!("x-amz-meta-{}", k.to_ascii_lowercase()), v.clone()));
            }
        }
        let response = self
            .signed_request(credentials, "PUT", key, "", &headers, body)
            .await?;
        if response.status == 412 {
            return Err(Error::new(
                ErrorCode::PreconditionFailed,
                "S3 PutObject precondition failed",
            )
            .with_context(ErrorContext::Identity {
                new_etag: response
                    .header("etag")
                    .map(|value| value.trim_matches('"').to_string()),
            }));
        }
        if !is_success(response.status) {
            return Err(map_error_status(response.status, &response.body));
        }
        let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
        let resolved = address::join_relative(&bucket_root, key)?;
        Ok(ObjectInfo {
            address: resolved,
            kind: ObjectKind::File,
            etag: response
                .header("etag")
                .map(|value| value.trim_matches('"').to_string()),
            version: response.header("x-amz-version-id").map(str::to_string),
            size: Some(body.len() as u64),
            mtime: response.header("last-modified").and_then(parse_http_date),
            checksums: collect_checksums(&response),
            effective_permissions: None,
            system_metadata: collect_system_metadata(&response),
            user_metadata: opts.user_metadata.clone(),
            modified_by: None,
        })
    }

    async fn create_multipart_upload(
        &self,
        credentials: &AwsCredentials,
        key: &str,
        opts: &WriteOptions,
    ) -> Result<String> {
        let mut headers: Vec<(String, String)> = Vec::new();
        if let Some(metadata) = opts.user_metadata.as_ref() {
            for (k, v) in metadata {
                headers.push((format!("x-amz-meta-{}", k.to_ascii_lowercase()), v.clone()));
            }
        }
        let response = self
            .signed_request(credentials, "POST", key, "uploads=", &headers, &[])
            .await?;
        if !is_success(response.status) {
            return Err(map_error_status(response.status, &response.body));
        }
        let body_text = String::from_utf8(response.body).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "S3 InitiateMultipartUpload response body was not UTF-8",
            )
        })?;
        let upload_id = parse_initiate_multipart_upload(&body_text)?.upload_id;
        info!(plugin = "s3", op = "write", "s3 multipart upload initiated");
        Ok(upload_id)
    }

    fn build_single_put_redirect(
        &self,
        credentials: &AwsCredentials,
        key: &str,
        len: u64,
        opts: &WriteOptions,
    ) -> Result<WriteRedirect> {
        let endpoint = resolve_endpoint(&self.config, key)?;
        let (now, amz_date, date_stamp) = current_amz_date();
        // Conditional + x-amz-meta headers must be both signed into the URL and emitted on the request.
        let signed_headers = put_redirect_signed_headers(opts);
        let url = if self.is_anonymous {
            format!(
                "{}://{}{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri
            )
        } else {
            let ctx = self.signing_context(&amz_date, &date_stamp);
            let presigned = presign_query(
                credentials,
                &ctx,
                "PUT",
                &endpoint.canonical_uri,
                &endpoint.host,
                "",
                DEFAULT_PRESIGN_TTL_SECS,
                &signed_headers,
            );
            format!(
                "{}://{}{}?{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri, presigned.query
            )
        };
        let scope = RedirectScope {
            physical_url_prefix: format!("{}://{}/", endpoint.scheme, endpoint.host),
            operations: AccessOps {
                write: true,
                ..AccessOps::default()
            },
            expires_at: now + Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64),
        };
        Ok(WriteRedirect {
            request: HttpRequest {
                method: "PUT".into(),
                url,
                headers: signed_headers,
            },
            body_source: RedirectBodySource::UserBytes { offset: 0, len },
            result_capture: ResultCapture {
                headers: vec!["etag".into(), "x-amz-version-id".into()],
                body_max_bytes: 0,
            },
            expires_at: scope.expires_at,
            scope,
            audit_id: format!("s3-put-{}", key),
            policy_epoch: 0,
        })
    }

    fn build_part_batch(
        &self,
        credentials: &AwsCredentials,
        continuation: &MultipartContinuation,
        total_bytes: u64,
    ) -> Result<Vec<WriteRedirect>> {
        let endpoint = resolve_endpoint(&self.config, &continuation.key)?;
        let (now, amz_date, date_stamp) = current_amz_date();
        // Balanced base/remainder split; offsets are a prefix sum so the
        // final part lines up exactly with `total_bytes` even when the
        // total is not a multiple of the part count.
        let sizes = part_sizes(total_bytes, continuation.total_parts);
        let mut redirects = Vec::with_capacity(continuation.total_parts as usize);
        let mut offset: u64 = 0;
        for (part_index, &length) in sizes.iter().enumerate() {
            let part_number = (part_index as u32) + 1;
            let extra_query = canonicalize_query(&[
                ("partNumber".to_string(), part_number.to_string()),
                ("uploadId".to_string(), continuation.upload_id.clone()),
            ]);
            let url = if self.is_anonymous {
                format!(
                    "{}://{}{}?{}",
                    endpoint.scheme, endpoint.host, endpoint.canonical_uri, extra_query,
                )
            } else {
                let ctx = self.signing_context(&amz_date, &date_stamp);
                let presigned = presign_query(
                    credentials,
                    &ctx,
                    "PUT",
                    &endpoint.canonical_uri,
                    &endpoint.host,
                    &extra_query,
                    DEFAULT_PRESIGN_TTL_SECS,
                    &[],
                );
                format!(
                    "{}://{}{}?{}",
                    endpoint.scheme, endpoint.host, endpoint.canonical_uri, presigned.query,
                )
            };
            let scope = RedirectScope {
                physical_url_prefix: format!("{}://{}/", endpoint.scheme, endpoint.host),
                operations: AccessOps {
                    write: true,
                    ..AccessOps::default()
                },
                expires_at: now + Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64),
            };
            redirects.push(WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    url,
                    headers: Vec::new(),
                },
                body_source: RedirectBodySource::UserBytes {
                    offset,
                    len: length,
                },
                result_capture: ResultCapture {
                    headers: vec!["etag".into(), "x-amz-version-id".into()],
                    body_max_bytes: 0,
                },
                expires_at: scope.expires_at,
                scope,
                audit_id: format!(
                    "s3-multipart-{}-part-{}",
                    continuation.upload_id, part_number
                ),
                policy_epoch: 0,
            });
            offset += length;
        }
        Ok(redirects)
    }

    async fn complete_multipart_upload(
        &self,
        credentials: &AwsCredentials,
        continuation: &MultipartContinuation,
    ) -> Result<ObjectInfo> {
        let parts: Vec<(u32, String)> = continuation
            .parts
            .iter()
            .filter_map(|p| p.etag.as_ref().map(|etag| (p.part_number, etag.clone())))
            .collect();
        let body = build_complete_multipart_upload_body(&parts);
        info!(
            plugin = "s3",
            op = "write",
            "s3 multipart upload completing",
        );
        let mut headers: Vec<(String, String)> =
            vec![("content-type".to_string(), "application/xml".to_string())];
        if let Some(if_match) = continuation.if_match.as_ref() {
            headers.push(("if-match".to_string(), quote_etag(if_match)));
        }
        if continuation.no_overwrite {
            headers.push(("if-none-match".to_string(), "*".to_string()));
        }
        let query = canonicalize_query(&[("uploadId".to_string(), continuation.upload_id.clone())]);
        let response = self
            .signed_request(
                credentials,
                "POST",
                &continuation.key,
                &query,
                &headers,
                body.as_bytes(),
            )
            .await?;
        if !is_success(response.status) {
            return Err(map_error_status(response.status, &response.body));
        }
        let last_modified = response.header("last-modified").and_then(parse_http_date);
        let system_metadata = collect_system_metadata(&response);
        let body_text = String::from_utf8(response.body).map_err(|_| {
            Error::new(
                ErrorCode::Internal,
                "S3 CompleteMultipartUpload response body was not UTF-8",
            )
        })?;
        if let Some(s3_error) = parse_s3_error(&body_text) {
            return Err(map_complete_multipart_error(&s3_error));
        }
        let parsed = parse_complete_multipart_upload(&body_text)?;
        if parsed.etag.is_none() {
            return Err(Error::new(
                ErrorCode::Internal,
                "S3 CompleteMultipartUpload returned 2xx but the response did not include an ETag",
            ));
        }
        let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
        let resolved = address::join_relative(&bucket_root, &continuation.key)?;
        let total_size: u64 = continuation.parts.iter().map(|p| p.byte_length).sum();
        let user_metadata: Option<UserMetadata> =
            continuation.user_metadata.as_ref().map(|pairs| {
                let mut map: HashMap<String, String> = HashMap::new();
                for (k, v) in pairs {
                    map.insert(k.clone(), v.clone());
                }
                map
            });
        Ok(ObjectInfo {
            address: resolved,
            kind: ObjectKind::File,
            etag: parsed.etag,
            version: parsed.version_id,
            size: Some(total_size),
            mtime: last_modified,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata,
            user_metadata,
            modified_by: None,
        })
    }

    /// Streaming multipart write. Buffers ~8 MiB per part; degrades to PutObject if the whole
    /// stream fits the first buffer (S3 rejects non-final multipart parts < 5 MiB).
    async fn stream_write(
        &self,
        target: ResolvedTarget,
        mut stream: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
    ) -> Result<ovstorage_plugin::WriteStep> {
        let parts = self.parse_object_target(&target)?;
        let credentials = self.resolve_credentials(None)?;
        let part_capacity = DEFAULT_PART_SIZE_BYTES as usize;
        let mut first_part = Vec::with_capacity(part_capacity);
        while first_part.len() < part_capacity {
            match stream.next() {
                None => break,
                Some(Ok(chunk)) => first_part.extend_from_slice(&chunk),
                Some(Err(err)) => return Err(err),
            }
        }
        // Whole stream fit the first buffer; degrade to PutObject.
        if first_part.len() < part_capacity {
            let info = self
                .put_object_inline(&credentials, &parts.key, &first_part, &opts)
                .await?;
            return Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }));
        }
        let _ = target;
        let upload_id = self
            .create_multipart_upload(&credentials, &parts.key, &opts)
            .await?;
        let (if_match_etag, no_overwrite) = split_if_dest(&opts.if_dest);
        let mut continuation = MultipartContinuation::new(
            parts.key.clone(),
            upload_id,
            opts.user_metadata
                .as_ref()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
            if_match_etag,
            no_overwrite,
            0,
        );
        let mut total_bytes: u64 = 0;
        let mut next_part_number: u32 = 1;
        self.commit_streaming_part(
            &credentials,
            &mut continuation,
            &mut next_part_number,
            &mut total_bytes,
            &mut first_part,
        )
        .await?;
        let mut buffer = Vec::with_capacity(part_capacity);
        loop {
            match stream.next() {
                None => break,
                Some(Ok(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    if buffer.len() >= part_capacity {
                        self.commit_streaming_part(
                            &credentials,
                            &mut continuation,
                            &mut next_part_number,
                            &mut total_bytes,
                            &mut buffer,
                        )
                        .await?;
                    }
                }
                Some(Err(err)) => {
                    let _ = self.abort_multipart_upload(&continuation).await;
                    return Err(err);
                }
            }
            if let Err(err) = ensure_streaming_part_limit(next_part_number) {
                let _ = self.abort_multipart_upload(&continuation).await;
                return Err(err);
            }
        }
        // Final part may be any size > 0 (S3 exemption).
        self.commit_streaming_part(
            &credentials,
            &mut continuation,
            &mut next_part_number,
            &mut total_bytes,
            &mut buffer,
        )
        .await?;
        // S3 rejects CompleteMultipartUpload if any non-final part is < 5 MiB; loop only flushes at >= 8 MiB.
        debug_assert!(
            !continuation
                .parts
                .iter()
                .rev()
                .skip(1)
                .any(|p| p.byte_length < MIN_PART_SIZE_BYTES),
            "S3 streaming write produced a non-final part below the 5 MiB minimum",
        );
        continuation.total_parts = continuation.parts.len() as u32;
        let info = match self
            .complete_multipart_upload(&credentials, &continuation)
            .await
        {
            Ok(info) => info,
            Err(err) => {
                let _ = self.abort_multipart_upload(&continuation).await;
                return Err(err);
            }
        };
        Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
    }

    /// Upload `buffer` as the next part; aborts the upload on failure. No-op when empty.
    async fn commit_streaming_part(
        &self,
        credentials: &AwsCredentials,
        continuation: &mut MultipartContinuation,
        next_part_number: &mut u32,
        total_bytes: &mut u64,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let part_number = *next_part_number;
        debug!(
            plugin = "s3",
            op = "write",
            retry.attempt = 1,
            "s3 multipart part upload starting",
            // part number is logged as a flat field; not a standard namespace field
        );
        let upload_result = self
            .upload_part_streamed(credentials, continuation, part_number, buffer)
            .await;
        let etag = match upload_result {
            Ok(etag) => etag,
            Err(err) => {
                warn!(
                    plugin = "s3",
                    op = "write",
                    error.code = ?err.code(),
                    "s3 multipart part upload failed",
                );
                let _ = self.abort_multipart_upload(continuation).await;
                return Err(err);
            }
        };
        continuation.parts.push(MultipartPart {
            part_number,
            byte_offset: *total_bytes,
            byte_length: buffer.len() as u64,
            etag: Some(etag),
        });
        *total_bytes += buffer.len() as u64;
        *next_part_number += 1;
        buffer.clear();
        Ok(())
    }

    /// Direct signed S3 UploadPart; returns the ETag CompleteMultipartUpload requires.
    async fn upload_part_streamed(
        &self,
        credentials: &AwsCredentials,
        continuation: &MultipartContinuation,
        part_number: u32,
        body: &[u8],
    ) -> Result<String> {
        let query = canonicalize_query(&[
            ("partNumber".to_string(), part_number.to_string()),
            ("uploadId".to_string(), continuation.upload_id.clone()),
        ]);
        let response = self
            .signed_request(credentials, "PUT", &continuation.key, &query, &[], body)
            .await?;
        if !is_success(response.status) {
            return Err(map_error_status(response.status, &response.body));
        }
        response
            .header("etag")
            .map(|value| value.trim_matches('"').to_string())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    format!("S3 UploadPart {part_number} response did not include an ETag header"),
                )
            })
    }

    async fn abort_multipart_upload(&self, continuation: &MultipartContinuation) -> Result<()> {
        let credentials = self.resolve_credentials(None)?;
        let query = canonicalize_query(&[("uploadId".to_string(), continuation.upload_id.clone())]);
        let response = self
            .signed_request(&credentials, "DELETE", &continuation.key, &query, &[], &[])
            .await?;
        if is_success(response.status) || response.status == 404 {
            return Ok(());
        }
        Err(map_error_status(response.status, &response.body))
    }

    async fn signed_request(
        &self,
        credentials: &AwsCredentials,
        method: &str,
        key: &str,
        canonical_query: &str,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        let endpoint = resolve_endpoint(&self.config, key)?;
        let url = if canonical_query.is_empty() {
            format!(
                "{}://{}{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri
            )
        } else {
            format!(
                "{}://{}{}?{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri, canonical_query
            )
        };
        let body_to_send: &[u8] = if matches!(method, "GET" | "HEAD" | "DELETE") {
            &[]
        } else {
            body
        };

        let headers: Vec<(String, String)> = if self.is_anonymous {
            // Unsigned request: no Authorization, no x-amz-content-sha256, no
            // x-amz-date. The server replies based on the bucket's public ACL.
            let mut hs = Vec::with_capacity(extra_headers.len() + 2);
            hs.push(("host".to_string(), endpoint.host.clone()));
            hs.extend_from_slice(extra_headers);
            if self.config.force_request_payer {
                hs.push(("x-amz-request-payer".to_string(), "requester".to_string()));
            }
            hs
        } else {
            let (_, amz_date, date_stamp) = current_amz_date();
            let ctx = self.signing_context(&amz_date, &date_stamp);
            let payload = if body.is_empty() || matches!(method, "GET" | "HEAD" | "DELETE") {
                payload_hash(&[])
            } else {
                payload_hash(body)
            };
            let mut signed_extras: Vec<(String, String)> = extra_headers.to_vec();
            if self.config.force_request_payer {
                // Requester-pays buckets 403 every call without signed `x-amz-request-payer`.
                signed_extras.push(("x-amz-request-payer".to_string(), "requester".to_string()));
            }
            signed_extras.push(("x-amz-content-sha256".to_string(), payload.clone()));
            let canonical = CanonicalRequest {
                method,
                canonical_uri: endpoint.canonical_uri.clone(),
                canonical_query: canonical_query.to_string(),
                host: &endpoint.host,
                extra_signed_headers: signed_extras,
                payload_hash: payload,
            };
            let signed = sign_request(credentials, &ctx, &canonical);
            signed.headers
        };
        execute(&self.client, method, &url, &headers, body_to_send).await
    }
}

fn copy_source_header(parts: &S3AddressParts, version_id: Option<&str>) -> String {
    let mut out = format!(
        "/{}{}",
        parts.bucket,
        crate::sigv4::canonical_path(&parts.key)
    );
    if let Some(version) = version_id {
        out.push_str("?versionId=");
        for byte in version.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(byte as char);
            } else {
                out.push('%');
                out.push(hex_nibble(byte >> 4));
                out.push(hex_nibble(byte & 0x0f));
            }
        }
    }
    out
}

fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => unreachable!("nibble in range"),
    }
}

fn merge_metadata(
    existing: &UserMetadata,
    user_metadata_set: &HashMap<String, String>,
    user_metadata_remove: &[String],
) -> Vec<(String, String)> {
    let mut desired: HashMap<String, String> = HashMap::new();
    for (k, v) in existing {
        desired.insert(k.to_ascii_lowercase(), v.clone());
    }
    for k in user_metadata_remove {
        desired.remove(&k.to_ascii_lowercase());
    }
    for (k, v) in user_metadata_set {
        desired.insert(k.to_ascii_lowercase(), v.clone());
    }
    let mut out: Vec<(String, String)> = desired.into_iter().collect();
    out.sort();
    out
}

fn map_complete_multipart_error(err: &crate::xml::S3ErrorBody) -> Error {
    let code_str = err.code.as_deref().unwrap_or("");
    let message = err.message.as_deref().unwrap_or("(no message)");
    let trail = format!(
        "S3 CompleteMultipartUpload returned 2xx with embedded <Error code={code_str}>: {message}"
    );
    let kind = match code_str {
        "InternalError" | "ServiceUnavailable" | "SlowDown" | "RequestTimeout"
        | "OperationAborted" => ErrorCode::Transient,
        "PreconditionFailed" => ErrorCode::PreconditionFailed,
        "InvalidPart" | "InvalidPartOrder" | "EntityTooSmall" => ErrorCode::ObjectModified,
        _ => ErrorCode::Internal,
    };
    Error::new(kind, trail)
}

fn directory_marker_key(prefix_key: &str) -> Result<String> {
    if prefix_key.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "S3 directory marker requires a non-empty prefix key",
        ));
    }
    if prefix_key.ends_with('/') {
        Ok(prefix_key.to_string())
    } else {
        Ok(format!("{prefix_key}/"))
    }
}

/// Stash `opts.message` as the `x-ov-message` user-metadata entry (the
/// project-wide convention for backends without native commit annotations);
/// returns `opts` unchanged when the message is absent or empty.
fn with_message_stashed(mut opts: WriteOptions) -> WriteOptions {
    let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) else {
        return opts;
    };
    let mut metadata = opts.user_metadata.take().unwrap_or_default();
    metadata.insert("x-ov-message".into(), message.to_string());
    opts.user_metadata = Some(metadata);
    opts
}

/// Conditional + `x-amz-meta-*` headers signed into the presigned URL; follower must echo them verbatim.
fn put_redirect_signed_headers(opts: &WriteOptions) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    match &opts.if_dest {
        IfDestExists::Overwrite => {}
        IfDestExists::Fail => {
            headers.push(("if-none-match".to_string(), "*".to_string()));
        }
        IfDestExists::MatchEtag(etag) => {
            headers.push(("if-match".to_string(), quote_etag(etag)));
        }
    }
    if let Some(metadata) = opts.user_metadata.as_ref() {
        for (key, value) in metadata {
            headers.push((
                format!("x-amz-meta-{}", key.to_ascii_lowercase()),
                value.clone(),
            ));
        }
    }
    headers
}

/// Build the `Range:` header value for a `ReadOptions.range`. Returns
/// `Ok(None)` when no range is requested. Rejects inverted ranges
/// (`end_inclusive < start`) with `InvalidArgument` — the workspace
/// uses `panic = "abort"`, so an inverted slice on the host-side
/// follower would terminate the worker if we let one through.
fn read_range_header(opts: &ReadOptions) -> Result<Option<String>> {
    let Some(range) = opts.range.as_ref() else {
        return Ok(None);
    };
    if let Some(end) = range.end_inclusive
        && end < range.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "s3 read: inverted byte range start={} end_inclusive={}",
                range.start, end,
            ),
        ));
    }
    let end = range
        .end_inclusive
        .map(|end| end.to_string())
        .unwrap_or_default();
    Ok(Some(format!("bytes={}-{}", range.start, end)))
}

fn quote_etag(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        trimmed.to_string()
    } else {
        format!("\"{trimmed}\"")
    }
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

fn read_response_parsing() -> ResponseParsing {
    let mut checksum_headers = HashMap::new();
    checksum_headers.insert(ChecksumAlgorithm::sha256(), "x-amz-checksum-sha256".into());
    checksum_headers.insert(ChecksumAlgorithm::crc32c(), "x-amz-checksum-crc32c".into());
    checksum_headers.insert(
        ChecksumAlgorithm::new("crc64nvme").expect("crc64nvme is a valid token"),
        "x-amz-checksum-crc64nvme".into(),
    );
    checksum_headers.insert(ChecksumAlgorithm::md5(), "x-amz-checksum-md5".into());
    ResponseParsing {
        etag_header: Some("etag".into()),
        version_header: Some("x-amz-version-id".into()),
        size_header: Some("content-length".into()),
        mtime_header: Some("last-modified".into()),
        mtime_format: MtimeFormat::Rfc1123,
        system_metadata_headers: vec![
            "x-amz-storage-class".into(),
            "x-amz-server-side-encryption".into(),
            "x-amz-server-side-encryption-aws-kms-key-id".into(),
            "x-amz-replication-status".into(),
        ],
        // S3 only emits `x-amz-checksum-sha256` when the object was PUT with `x-amz-checksum-algorithm: SHA256`; absent header → pass-through.
        content_checksum_header: Some("x-amz-checksum-sha256".into()),
        content_checksum_algorithm: Some(ChecksumAlgorithm::sha256()),
        checksum_headers,
    }
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn object_info_from_head(addr: &Url, response: &HttpResponse) -> ObjectInfo {
    ObjectInfo {
        address: addr.clone(),
        kind: ObjectKind::File,
        etag: response
            .header("etag")
            .map(|value| value.trim_matches('"').to_string()),
        version: response.header("x-amz-version-id").map(str::to_string),
        size: response
            .header("content-length")
            .and_then(|value| value.parse().ok()),
        mtime: response.header("last-modified").and_then(parse_http_date),
        checksums: collect_checksums(response),
        effective_permissions: None,
        system_metadata: collect_system_metadata(response),
        user_metadata: collect_user_metadata(response),
        modified_by: None,
    }
}

fn collect_checksums(response: &HttpResponse) -> ChecksumSet {
    let mut out = ChecksumSet::default();
    for (name, value) in &response.headers {
        let lower = name.to_ascii_lowercase();
        let Some(suffix) = lower.strip_prefix("x-amz-checksum-") else {
            continue;
        };
        let Ok(algorithm) = ChecksumAlgorithm::new(suffix) else {
            continue;
        };
        out.insert(algorithm, value.as_bytes().to_vec());
    }
    out
}

fn collect_system_metadata(response: &HttpResponse) -> Option<SystemMetadata> {
    let mut metadata = SystemMetadata::new();
    for (name, value) in &response.headers {
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("x-amz-")
            && !lower.starts_with("x-amz-meta-")
            && !lower.starts_with("x-amz-checksum-")
        {
            metadata.insert(lower, value.clone());
        }
    }
    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

fn collect_user_metadata(response: &HttpResponse) -> Option<UserMetadata> {
    let mut metadata = UserMetadata::new();
    for (name, value) in &response.headers {
        let lower = name.to_ascii_lowercase();
        if let Some(stripped) = lower.strip_prefix("x-amz-meta-") {
            metadata.insert(stripped.to_string(), value.clone());
        }
    }
    if metadata.is_empty() {
        None
    } else {
        Some(metadata)
    }
}

pub(crate) fn current_amz_date() -> (SystemTime, String, String) {
    let now = SystemTime::now();
    let datetime = time::OffsetDateTime::from(now);
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    );
    let date_stamp = format!(
        "{:04}{:02}{:02}",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day()
    );
    (now, amz_date, date_stamp)
}

fn parse_http_date(value: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(value).ok()
}

fn parse_iso8601_to_system_time(value: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|datetime| datetime.into())
}

fn address_version_id(addr: &Url) -> Option<String> {
    let value = addr.as_str();
    let query_start = value.find('?')?;
    let query = &value[query_start + 1..];
    for piece in query.split('&') {
        if let Some(value) = piece.strip_prefix("versionId=") {
            return urlencoding::decode(value).ok().map(|cow| cow.into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use ovstorage_plugin::shim::{Backend as _, Factory as _};

    #[test]
    fn directory_marker_key_appends_slash() {
        assert_eq!(directory_marker_key("dir").unwrap(), "dir/");
        assert_eq!(directory_marker_key("dir/").unwrap(), "dir/");
        assert!(directory_marker_key("").is_err());
    }

    #[test]
    fn read_range_header_serialises_open_and_closed_ranges() {
        let opts = ReadOptions {
            range: Some(ovstorage_plugin::ByteRange {
                start: 5,
                end_inclusive: Some(10),
            }),
            ..ReadOptions::default()
        };
        assert_eq!(
            read_range_header(&opts).unwrap().as_deref(),
            Some("bytes=5-10"),
        );

        let open = ReadOptions {
            range: Some(ovstorage_plugin::ByteRange {
                start: 5,
                end_inclusive: None,
            }),
            ..ReadOptions::default()
        };
        assert_eq!(
            read_range_header(&open).unwrap().as_deref(),
            Some("bytes=5-"),
        );
    }

    #[test]
    fn read_range_header_rejects_inverted_range() {
        let opts = ReadOptions {
            range: Some(ovstorage_plugin::ByteRange {
                start: 100,
                end_inclusive: Some(50),
            }),
            ..ReadOptions::default()
        };
        let err = read_range_header(&opts).expect_err("inverted range must error");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn quote_etag_only_wraps_unquoted_values() {
        assert_eq!(quote_etag("abc"), "\"abc\"");
        assert_eq!(quote_etag("\"already\""), "\"already\"");
    }

    #[test]
    fn collect_checksums_normalises_known_algorithm_tokens() {
        let response = HttpResponse {
            status: 200,
            headers: vec![
                ("x-amz-checksum-sha256".to_string(), "deadbeef".to_string()),
                ("x-amz-checksum-crc32c".to_string(), "4242".to_string()),
                ("etag".to_string(), "\"e\"".to_string()),
            ],
            body: Vec::new(),
        };
        let set = collect_checksums(&response);
        let sha = set.get(&ChecksumAlgorithm::sha256()).unwrap();
        assert_eq!(sha, b"deadbeef");
        let crc = set.get(&ChecksumAlgorithm::crc32c()).unwrap();
        assert_eq!(crc, b"4242");
    }

    #[test]
    fn address_version_id_extracted_from_query_string() {
        let addr = address::parse("s3://bucket/key?versionId=abc%20123").unwrap();
        assert_eq!(address_version_id(&addr).as_deref(), Some("abc 123"));
    }

    #[test]
    fn put_redirect_signed_headers_emits_no_overwrite() {
        let opts = WriteOptions {
            if_dest: IfDestExists::Fail,
            ..WriteOptions::default()
        };
        let headers = put_redirect_signed_headers(&opts);
        assert_eq!(
            headers,
            vec![("if-none-match".to_string(), "*".to_string())]
        );
    }

    #[test]
    fn put_redirect_signed_headers_emits_quoted_if_match() {
        let opts = WriteOptions {
            if_dest: IfDestExists::MatchEtag("abc123".into()),
            ..WriteOptions::default()
        };
        let headers = put_redirect_signed_headers(&opts);
        assert_eq!(
            headers,
            vec![("if-match".to_string(), "\"abc123\"".to_string())]
        );
    }

    #[test]
    fn put_redirect_signed_headers_emits_amz_meta_lowercased() {
        let mut metadata: UserMetadata = std::collections::HashMap::new();
        metadata.insert("Foo".into(), "bar".into());
        let opts = WriteOptions {
            user_metadata: Some(metadata),
            ..WriteOptions::default()
        };
        let headers = put_redirect_signed_headers(&opts);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "x-amz-meta-foo");
        assert_eq!(headers[0].1, "bar");
    }

    #[test]
    fn force_request_payer_drives_signed_extras_addition() {
        // SigV4 sorts headers lowercase: `x-amz-request-payer` lands between `x-amz-date` and `x-amz-content-sha256`.
        let extras: Vec<(String, String)> = vec![
            ("x-amz-request-payer".into(), "requester".into()),
            ("x-amz-content-sha256".into(), payload_hash(&[])),
        ];
        let canonical = CanonicalRequest {
            method: "HEAD",
            canonical_uri: "/key".into(),
            canonical_query: String::new(),
            host: "bucket.s3.amazonaws.com",
            extra_signed_headers: extras,
            payload_hash: payload_hash(&[]),
        };
        let creds = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let now = current_amz_date();
        let ctx = SigningContext {
            amz_date: &now.1,
            date_stamp: &now.2,
            region: "us-east-1",
            service: "s3",
        };
        let signed = sign_request(&creds, &ctx, &canonical);
        assert!(
            signed
                .canonical_request
                .contains("x-amz-request-payer:requester"),
            "canonical request missing header line: {}",
            signed.canonical_request
        );
        assert!(
            signed.canonical_request.contains(";x-amz-request-payer\n"),
            "SignedHeaders row missing x-amz-request-payer: {}",
            signed.canonical_request
        );
    }

    #[test]
    fn put_redirect_signed_headers_combines_if_dest_and_metadata() {
        // IfDestExists is now a single tagged enum; MatchEtag and Fail are
        // mutually exclusive. Combine MatchEtag with user metadata here.
        let mut metadata: UserMetadata = std::collections::HashMap::new();
        metadata.insert("k".into(), "v".into());
        let opts = WriteOptions {
            if_dest: IfDestExists::MatchEtag("etag".into()),
            user_metadata: Some(metadata),
            ..WriteOptions::default()
        };
        let headers = put_redirect_signed_headers(&opts);
        assert_eq!(headers[0].0, "if-match");
        assert_eq!(headers[1].0, "x-amz-meta-k");
    }
}
