// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `NucleusBackend` and its `shim::Backend` SPI implementation, plus the
//! `NucleusContinuation` codec for the `write_redirect` / `continue_write` roundtrip.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nucleus_client::LftClient;
use nucleus_client::types::{PathAtBranch, PathAtVersion, PathsToCopy, PathsToRename};
use ovstorage_plugin::{
    AccessDecision, AccessOps, BodyStream, CancellationToken, Capabilities, ChangeKindSet,
    CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions,
    EffectivePermissions, Error, ErrorCode, IfDestExists, ListOptions, ListVersionsOptions,
    ObjectInfo, ObjectKind, ReadOptions, RenameOptions, ResolvedTarget, Result, StatOptions,
    UpdateMetadataOptions, Url, VersionListOrder, WatchDirectoryOptions, WriteOptions, WriteResult,
    shim,
};
use ovstorage_plugin::{
    BackendChangeStream, BackendItemInfo, HttpRequest, ReadRedirect, ReadResult,
    RedirectBodySource, RedirectResultBatch, RedirectScope, ResponseParsing, ResultCapture,
    WriteRedirect, WriteRedirectBatch, WriteStep, race_cancel, validate_redirect_results,
};

use tracing::Instrument;

use crate::address::{NucleusTarget, parse_nucleus_address, path_is_under_prefix};
use crate::convert::require_etag_only_if_match;
use crate::ops::{NucleusOps, acl_to_effective_permissions, status_to_result};
use crate::trace::RedactedUrl;

use super::convert::{
    create_asset_to_object_info, list_entry_to_item, path_at_version, poisoned_state,
    read_result_to_object_info, stat2_to_object_info, update_asset_to_object_info,
};
use super::factory::{NucleusShared, with_refresh};
use super::watch::WatchIter;

pub struct NucleusBackend {
    server: String,
    prefix: String,
    #[allow(dead_code)]
    root: Url,
    shared: Arc<NucleusShared>,
}

impl NucleusBackend {
    pub(crate) fn from_shared(shared: Arc<NucleusShared>) -> Self {
        Self {
            server: shared.config.server.clone(),
            prefix: shared.config.prefix.clone(),
            root: shared.config.root.clone(),
            shared,
        }
    }

    fn target(&self, target: &ResolvedTarget) -> Result<NucleusTarget> {
        let parsed = parse_nucleus_address(&target.resolved_address)?;
        if parsed.server != self.server {
            return Err(Error::new(
                ErrorCode::NoRoute,
                "Nucleus target server does not match backend server",
            ));
        }
        if !path_is_under_prefix(&parsed.path, &self.prefix) {
            return Err(Error::new(
                ErrorCode::NoRoute,
                "Nucleus target path is outside the configured prefix",
            ));
        }
        Ok(parsed)
    }

    fn ops(&self) -> Result<Arc<dyn NucleusOps>> {
        self.shared
            .ops
            .lock()
            .map_err(poisoned_state)?
            .clone()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::AuthRequired,
                    "Sign in to this Nucleus connection before issuing object operations",
                )
            })
    }

    /// Reject mutating ops on a `?checkpoint=N` address. Nucleus checkpoints
    /// are frozen historical versions; without this guard the omni1
    /// `PathAtBranch`-typed ops (create_asset, delete2, rename2) silently
    /// strip the version and operate on the head, which loses data.
    /// Read-side ops use `PathAtVersion` and need no guard. Cp source is also
    /// allowed — copying out of an old version is a legitimate use.
    fn reject_checkpoint(parsed: &NucleusTarget, op: &str) -> Result<()> {
        if parsed.checkpoint.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "Nucleus {op}: cannot mutate a frozen checkpoint version \
                     (drop the ?checkpoint=N suffix to operate on the current version)"
                ),
            ));
        }
        Ok(())
    }

    fn reject_user_metadata(opts: &WriteOptions, op: &str) -> Result<()> {
        if opts.user_metadata.as_ref().is_some_and(|m| !m.is_empty()) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "Nucleus {op}: backend has no caller-owned user-metadata facet; \
                     drop opts.user_metadata or target a backend that supports it"
                ),
            ));
        }
        Ok(())
    }

    /// `None` when `use_lft = false` or LFT is not yet wired up.
    fn lft(&self) -> Result<Option<Arc<LftClient>>> {
        if !self.shared.config.use_lft {
            return Ok(None);
        }
        Ok(self
            .shared
            .lft_client
            .lock()
            .map_err(poisoned_state)?
            .clone())
    }

    /// Buffered commit shared by `write` and the below-LFT-threshold `write_stream` path.
    /// Above-threshold streaming writes return `Unsupported` until LFT redirect plumbing
    /// carries `Body::Stream` through to a streaming `reqwest::Body`.
    async fn commit_buffered(
        &self,
        address: Url,
        parsed: NucleusTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
    ) -> Result<WriteResult> {
        let ops = self.ops()?;
        let path = PathAtBranch {
            path: parsed.path.clone(),
            branch: parsed.branch.clone(),
        };
        // Universal contract: backends advertising supports_version_listing produce a version on every write; map None to Some("") so omni1 always checkpoints.
        let message = Some(opts.message.clone().unwrap_or_default());
        let info = match &opts.if_dest {
            IfDestExists::MatchEtag(etag) => {
                let result = ops
                    .update_asset(
                        path,
                        Some(etag.clone()),
                        None,
                        Some(bytes),
                        None,
                        None,
                        message,
                    )
                    .await?;
                status_to_result(result.status, "update_asset")?;
                update_asset_to_object_info(address.clone(), result)
            }
            IfDestExists::Overwrite | IfDestExists::Fail => {
                let overwrite = matches!(opts.if_dest, IfDestExists::Overwrite);
                let result = ops
                    .create_asset(path, Some(bytes), None, Some(overwrite), message)
                    .await?;
                status_to_result(result.status, "create_asset")?;
                create_asset_to_object_info(address.clone(), result)
            }
        };
        Ok(WriteResult { info })
    }

    /// Finalize an LFT upload via `create_asset`/`update_asset(content_id=Some(N))`
    /// over the omni1 websocket after the host has driven the redirect.
    async fn finalize_with_content_id(
        &self,
        address: Url,
        parsed: NucleusTarget,
        content_id: u64,
        opts: &WriteOptions,
    ) -> Result<WriteResult> {
        let ops = self.ops()?;
        let path = PathAtBranch {
            path: parsed.path.clone(),
            branch: parsed.branch.clone(),
        };
        let message = Some(opts.message.clone().unwrap_or_default());
        let info = match &opts.if_dest {
            IfDestExists::MatchEtag(etag) => {
                let response = ops
                    .update_asset(
                        path,
                        Some(etag.clone()),
                        None,
                        None,
                        Some(content_id),
                        None,
                        message,
                    )
                    .await?;
                status_to_result(response.status, "update_asset")?;
                update_asset_to_object_info(address.clone(), response)
            }
            IfDestExists::Overwrite | IfDestExists::Fail => {
                let overwrite = matches!(opts.if_dest, IfDestExists::Overwrite);
                let response = ops
                    .create_asset(path, None, Some(content_id), Some(overwrite), message)
                    .await?;
                status_to_result(response.status, "create_asset")?;
                create_asset_to_object_info(address.clone(), response)
            }
        };
        Ok(WriteResult { info })
    }

    /// Build a multi-part `WriteRedirectBatch` to the LFT upload URL: one
    /// `WriteRedirect` per part, each carrying its own `Content-Start` so
    /// the server can derive `part_number = Content-Start / chunk + 1`.
    /// Files <= chunk size collapse to a single part.
    ///
    /// The server's per-PUT cap is 24 MiB (`CLIENT_MAX_SIZE` in the LFT
    /// server); we defensively clamp the part size to 20 MiB if a
    /// deployment ever advertises a larger `multipart_chunk_size`, which
    /// would otherwise 413 the upload.
    pub(crate) fn build_lft_redirect_batch(
        &self,
        parsed: &NucleusTarget,
        opts: &WriteOptions,
        lft: &LftClient,
        lft_info: &nucleus_client::LftUploadInfo,
        total_len: u64,
    ) -> Result<WriteRedirectBatch> {
        const PART_SIZE_CEILING: u64 = 20 * 1024 * 1024;
        let advertised = lft.chunk_size().max(1);
        let chunk = if advertised > PART_SIZE_CEILING {
            tracing::warn!(
                advertised,
                clamped_to = PART_SIZE_CEILING,
                "nucleus LFT: server-advertised multipart_chunk_size exceeds the 24 MiB \
                 per-PUT cap; clamping to stay under it"
            );
            PART_SIZE_CEILING
        } else {
            advertised
        };
        let part_count = if total_len == 0 {
            1
        } else {
            total_len.div_ceil(chunk)
        };
        let expires = SystemTime::now() + Duration::from_secs(300);
        let (if_match_etag, no_overwrite) = match &opts.if_dest {
            IfDestExists::MatchEtag(etag) => (Some(etag.clone()), false),
            IfDestExists::Fail => (None, true),
            IfDestExists::Overwrite => (None, false),
        };
        let cont = NucleusContinuation {
            path: parsed.path.clone(),
            branch: parsed.branch.clone(),
            content_id: lft_info.content_id,
            if_match_etag,
            no_overwrite,
            message: opts.message.clone(),
        };
        let continuation = encode_nucleus_continuation(&cont);
        let mut redirects = Vec::with_capacity(part_count as usize);
        for i in 0..part_count {
            let offset = i * chunk;
            let len = if total_len == 0 {
                0
            } else {
                chunk.min(total_len - offset)
            };
            let headers = lft.part_headers(
                &lft_info.content_id_str,
                lft_info.content_id,
                offset,
                &parsed.path,
            );
            redirects.push(WriteRedirect {
                request: HttpRequest {
                    method: "PUT".into(),
                    url: lft_info.upload_url.clone(),
                    headers,
                },
                body_source: RedirectBodySource::UserBytes { offset, len },
                result_capture: ResultCapture::default(),
                expires_at: expires,
                scope: RedirectScope {
                    physical_url_prefix: lft_info.upload_url.clone(),
                    operations: AccessOps {
                        write: true,
                        ..AccessOps::default()
                    },
                    expires_at: expires,
                },
                audit_id: format!("nucleus-lft-write:{}:{}", parsed.path, i),
                policy_epoch: 0,
            });
        }
        Ok(WriteRedirectBatch {
            continuation,
            redirects,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct NucleusContinuation {
    pub path: String,
    pub branch: Option<String>,
    pub content_id: u64,
    pub if_match_etag: Option<String>,
    pub no_overwrite: bool,
    /// Persisted across the redirect round-trip so finalize sees the same
    /// `WriteOptions::message` the original `write_redirect` was given.
    #[serde(default)]
    pub message: Option<String>,
}

pub(super) fn encode_nucleus_continuation(cont: &NucleusContinuation) -> Vec<u8> {
    serde_json::to_vec(cont).expect("NucleusContinuation serialization is infallible")
}

pub(super) fn decode_nucleus_continuation(raw: &[u8]) -> Result<NucleusContinuation> {
    serde_json::from_slice(raw).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("invalid Nucleus write continuation: {err}"),
        )
    })
}

#[async_trait::async_trait]
impl shim::Backend for NucleusBackend {
    async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let parsed = self.target(&target)?;
        let address = target.resolved_address.clone();
        let span = tracing::info_span!("nucleus.stat", op = "stat", plugin = "nucleus", "object.address" = %RedactedUrl(&address));
        // Nucleus stat2 only matches one path shape: files have no trailing
        // slash, folders require one. The host SPI doesn't tell us which it
        // is, so when the address is unannotated we probe both in parallel.
        let needs_dual_probe = !parsed.path.ends_with('/');
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let address = address.clone();
                async move {
                    let ops = self.ops()?;
                    if !needs_dual_probe {
                        let result = ops.stat2(path_at_version(&parsed)).await?;
                        status_to_result(result.status, "stat2")?;
                        return Ok(stat2_to_object_info(address, result));
                    }

                    let file_target = parsed.clone();
                    let mut folder_target = parsed.clone();
                    folder_target.path = format!("{}/", folder_target.path);

                    let file_fut = async {
                        let r = ops.stat2(path_at_version(&file_target)).await?;
                        status_to_result(r.status, "stat2")?;
                        Ok::<_, Error>(r)
                    };
                    let folder_fut = async {
                        let r = ops.stat2(path_at_version(&folder_target)).await?;
                        status_to_result(r.status, "stat2")?;
                        Ok::<_, Error>(r)
                    };
                    let (file_res, folder_res) = tokio::join!(file_fut, folder_fut);

                    match (file_res, folder_res) {
                        (Ok(file_result), _) => Ok(stat2_to_object_info(address, file_result)),
                        (Err(_), Ok(folder_result)) => {
                            let mut folder_address = address.clone();
                            let new_path = format!("{}/", folder_address.path());
                            folder_address.set_path(&new_path);
                            Ok(stat2_to_object_info(folder_address, folder_result))
                        }
                        (Err(file_err), Err(_)) => Err(file_err),
                    }
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        require_etag_only_if_match(opts.if_match.as_deref())?;
        // Reject inverted ranges with the more specific InvalidArgument
        // before the blanket Unsupported refusal below: the workspace
        // builds with `panic = "abort"`, so an inverted range from a
        // buggy caller is best surfaced as a typed error rather than
        // silently falling through into the catch-all message.
        if let Some(range) = opts.range.as_ref()
            && let Some(end) = range.end_inclusive
            && end < range.start
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "Nucleus read: inverted byte range: start={} end_inclusive={end}",
                    range.start,
                ),
            ));
        }
        if opts.range.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus read: ranged reads are not supported by omni1 read_asset_version",
            ));
        }
        let parsed = self.target(&target)?;
        let address = target.resolved_address.clone();
        let span = tracing::info_span!("nucleus.read", op = "read", plugin = "nucleus", "object.address" = %RedactedUrl(&address));
        let etag = opts.if_match;
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let address = address.clone();
                let etag = etag.clone();
                async move {
                    let ops = self.ops()?;
                    let result = ops
                        .read_asset_version(path_at_version(&parsed), etag.clone())
                        .await?;
                    // SPI: read with if_match returns ObjectModified on mismatch
                    // (PreconditionFailed is reserved for write/update_metadata).
                    match status_to_result(result.status, "read_asset_version") {
                        Ok(()) => {}
                        Err(err)
                            if etag.is_some() && err.code() == ErrorCode::PreconditionFailed =>
                        {
                            return Err(Error::new(
                                ErrorCode::ObjectModified,
                                err.message().to_string(),
                            ));
                        }
                        Err(err) => return Err(err),
                    }
                    // Nucleus signals an LFT download by setting uri_redirection;
                    // observed live, it ALSO returns `content: Some([])` (empty
                    // placeholder) alongside, so we cannot gate on `content.is_none()`.
                    // The redirect URL takes precedence whenever it's set.
                    if let Some(redirect_url) = result.uri_redirection.as_deref() {
                        tracing::debug!(redirect.kind = "lft_download", redirect.target = %redirect_url, "nucleus read: LFT redirect");
                        let lft = self.lft()?.ok_or_else(|| {
                            Error::new(
                                ErrorCode::Unsupported,
                                "Nucleus server returned an LFT download redirect but the \
                                 plugin has no LftClient (set use_lft=true and authenticate)",
                            )
                        })?;
                        let expires = SystemTime::now() + Duration::from_secs(300);
                        return Ok(ReadResult::Redirect(ReadRedirect {
                            request: HttpRequest {
                                method: "GET".into(),
                                url: redirect_url.to_string(),
                                headers: lft.auth_headers(),
                            },
                            response_parsing: ResponseParsing::default(),
                            expires_at: expires,
                            scope: RedirectScope {
                                physical_url_prefix: redirect_url.to_string(),
                                operations: AccessOps {
                                    read: true,
                                    ..AccessOps::default()
                                },
                                expires_at: expires,
                            },
                            audit_id: format!("nucleus-lft-read:{}", parsed.path),
                            policy_epoch: 0,
                        }));
                    }
                    let bytes = result.content.clone().unwrap_or_default();
                    let info = read_result_to_object_info(address, &result, &bytes);
                    Ok(ReadResult::Bytes { bytes, info })
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let parsed = self.target(&target)?;
        Self::reject_checkpoint(&parsed, "write")?;
        Self::reject_user_metadata(&opts, "write")?;
        let address = target.resolved_address.clone();
        let span = tracing::info_span!("nucleus.write", op = "write", plugin = "nucleus", "object.address" = %RedactedUrl(&address));
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let address = address.clone();
                let bytes = bytes.clone();
                let opts = opts.clone();
                async move { self.commit_buffered(address, parsed, bytes, opts).await }
            }),
        )
        .instrument(span)
        .await
    }

    async fn write_stream(
        &self,
        target: ResolvedTarget,
        stream: BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        let span = tracing::info_span!("nucleus.write", op = "write", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        let parsed = self.target(&target)?;
        Self::reject_checkpoint(&parsed, "write_stream")?;
        Self::reject_user_metadata(&opts, "write_stream")?;
        // Below LFT threshold: host has gated by `redirect_size_threshold`, so the body
        // fits in memory by contract; drain and use the buffered create_asset path.
        // At/above threshold: inline streaming PUT requires `Body::Stream` propagation
        // through the LFT client (deferred); draining to `Vec<u8>` would be a memory-DoS
        // half-measure forbidden by the public-gateway streaming policy. Use
        // `write_redirect` instead.
        let lft = self.lft()?;
        let above_threshold = match (lft.as_ref(), opts.size_hint) {
            (Some(lft), Some(n)) => lft.should_use_lft(n),
            (Some(_), None) => true,
            (None, _) => false,
        };
        if above_threshold && lft.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus write_stream: above-LFT-threshold streams require redirect (use write_redirect); inline streaming PUT pending Body::Stream propagation through the LFT client",
            ));
        }
        // Memory-bounded by the host's `redirect_size_threshold` gating.
        let mut bytes = Vec::new();
        for chunk in stream {
            if cancel.as_ref().is_some_and(|t| t.is_cancelled()) {
                return Err(Error::new(ErrorCode::Cancelled, "cancelled by host"));
            }
            bytes.extend_from_slice(&chunk?);
        }
        race_cancel(
            cancel.as_ref(),
            self.commit_buffered(target.resolved_address, parsed, bytes, opts),
        )
        .instrument(span)
        .await
    }

    async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        let span = tracing::info_span!("nucleus.write", op = "write", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        let parsed = self.target(&target)?;
        Self::reject_checkpoint(&parsed, "write_redirect")?;
        Self::reject_user_metadata(&opts, "write_redirect")?;
        let lft = self.lft()?.ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "Nucleus write_redirect: no LftClient (set use_lft=true and authenticate)",
            )
        })?;
        // Multipart needs a known total length to compute part offsets.
        // Body::Stream of unknown length is deferred work; the host preserves
        // Body::Bytes/Body::LocalFile across redirect rounds and populates
        // size_hint from those, so the practical CLI/SDK paths are covered.
        let total_len = opts.size_hint.ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "Nucleus LFT multipart write requires opts.size_hint; \
                 streams of unknown length are not yet supported",
            )
        })?;
        let path = parsed.path.clone();
        let lft_for_generate = Arc::clone(&lft);
        let lft_info = race_cancel(cancel.as_ref(), async move {
            lft_for_generate
                .generate_upload(&path)
                .await
                .map_err(|err| {
                    Error::new(
                        ErrorCode::Internal,
                        format!("Nucleus LFT generate_upload failed: {err:#}"),
                    )
                })
        })
        .instrument(span)
        .await?;
        self.build_lft_redirect_batch(&parsed, &opts, &lft, &lft_info, total_len)
    }

    async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        tracing::debug!(op = "write", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address), "nucleus continue_write");
        validate_redirect_results(&redirects, &results)?;
        for (i, part) in results.results.iter().enumerate() {
            if !(200..300).contains(&part.status_code) {
                let context = format!(
                    "Nucleus LFT upload part {} of {} returned HTTP {} (body: {} bytes)",
                    i + 1,
                    results.results.len(),
                    part.status_code,
                    part.captured_body.len()
                );
                return Err(map_lft_http_status(part.status_code, context));
            }
        }
        let cont = decode_nucleus_continuation(&redirects.continuation)?;
        let parsed = NucleusTarget {
            server: String::new(), // ignored by finalize
            path: cont.path,
            branch: cont.branch,
            checkpoint: None,
        };
        let if_dest = match (cont.if_match_etag, cont.no_overwrite) {
            (Some(etag), _) => IfDestExists::MatchEtag(etag),
            (None, true) => IfDestExists::Fail,
            (None, false) => IfDestExists::Overwrite,
        };
        let opts = WriteOptions {
            if_dest,
            size_hint: None,
            user_metadata: None,
            message: cont.message,
        };
        let address = target.resolved_address.clone();
        let content_id = cont.content_id;
        let result = race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let opts = opts.clone();
                let address = address.clone();
                async move {
                    self.finalize_with_content_id(address, parsed, content_id, &opts)
                        .await
                }
            }),
        )
        .await?;
        Ok(WriteStep::Done(result))
    }

    async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        // omni1 delete2 takes Vec<PathAtVersion>; PathAtVersion has no etag
        // field, so if-match is not expressible at the protocol level. The
        // host doesn't synthesize CAS (would race a concurrent writer
        // between our stat and the delete). See `project_nucleus_no_conditional_mutate`.
        require_etag_only_if_match(opts.if_match.as_deref())?;
        if opts.if_match.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus delete: if_match preconditions are not expressible in omni1 delete2",
            ));
        }
        let parsed = self.target(&target)?;
        Self::reject_checkpoint(&parsed, "delete")?;
        let span = tracing::info_span!("nucleus.delete", op = "delete", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                async move {
                    let ops = self.ops()?;
                    let response = ops.delete2(vec![path_at_version(&parsed)]).await?;
                    // delete is idempotent: a missing target is success.
                    match status_to_result(response.status, "delete2") {
                        Ok(()) => {}
                        Err(err) if err.code() == ErrorCode::NotFound => return Ok(()),
                        Err(err) => return Err(err),
                    }
                    if let Some(per_path) = response.responses.first() {
                        match status_to_result(*per_path, "delete2 entry") {
                            Ok(()) => {}
                            Err(err) if err.code() == ErrorCode::NotFound => return Ok(()),
                            Err(err) => return Err(err),
                        }
                    }
                    Ok(())
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        if opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus list: page_token is not supported (omni1 list2 has no cursor)",
            ));
        }
        if opts.recursive {
            // omni1 list2 returns one level per call; the SPI rule forbids
            // silently amplifying a single call into N internal calls.
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus list: recursive listing is not supported (omni1 list2 returns one level per call)",
            ));
        }
        let parsed = self.target(&prefix)?;
        let span = tracing::info_span!("nucleus.list", op = "list", plugin = "nucleus", "object.address" = %RedactedUrl(&prefix.resolved_address));
        let prefix_address = prefix.resolved_address.clone();
        let recursive = opts.recursive;
        let max_results = opts.max_results.map(|n| n as usize);
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let prefix_address = prefix_address.clone();
                async move {
                    let ops = self.ops()?;
                    let path = parsed.path.clone();
                    let branches = parsed.branch.clone().map(|b| vec![b]);
                    let responses = ops.list2(path, branches, None, None).await?;
                    let mut items = Vec::new();
                    // Per-frame status was already validated by `ops.list2`; re-checking
                    // here would reject `PartiallyCompleted` frames that the streaming
                    // loop deliberately accepts.
                    'outer: for response in responses {
                        for entry in response.entries.into_iter().flatten() {
                            let Some(item) = list_entry_to_item(
                                &prefix_address,
                                &parsed.path,
                                entry,
                                recursive,
                            )?
                            else {
                                continue;
                            };
                            items.push(item);
                            if let Some(cap) = max_results
                                && items.len() >= cap
                            {
                                break 'outer;
                            }
                        }
                    }
                    Ok(items)
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        // omni1 `get_checkpoints` returns the full checkpoint list in a
        // single response with no `max_results` / `page_token` parameters.
        // Silently dropping a caller-supplied page_token would loop them
        // indefinitely; silently truncating to max_results would lose
        // versions without telling the host. Refuse both rather than
        // ignore them; the SPI's capability-honesty rule (a backend that
        // can't honor a caller-supplied option must surface `Unsupported`
        // rather than silently ignore it) applies.
        if opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus list_versions: page_token is not supported (omni1 get_checkpoints has no cursor)",
            ));
        }
        if opts.max_results.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus list_versions: max_results is not supported (omni1 get_checkpoints returns the full list in one call)",
            ));
        }
        let parsed = self.target(&target)?;
        let span = tracing::info_span!("nucleus.list_versions", op = "list_versions", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        let base_address = target.resolved_address.clone();
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let base_address = base_address.clone();
                async move {
                    let ops = self.ops()?;
                    let path = PathAtBranch {
                        path: parsed.path.clone(),
                        branch: parsed.branch.clone(),
                    };
                    let response = ops.get_checkpoints(path).await?;
                    status_to_result(response.status, "get_checkpoints")?;
                    let mut items = Vec::with_capacity(response.checkpoints.len());
                    for checkpoint in response.checkpoints {
                        let Some(id) = checkpoint.checkpoint_id else {
                            continue;
                        };
                        let address = checkpoint_address(&base_address, &parsed, id);
                        let info = ObjectInfo {
                            address,
                            kind: ObjectKind::File,
                            etag: None,
                            version: Some(id.to_string()),
                            size: None,
                            mtime: None,
                            checksums: Default::default(),
                            effective_permissions: None,
                            system_metadata: None,
                            user_metadata: None,
                            modified_by: None,
                        };
                        items.push(info);
                    }
                    Ok(items)
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let parsed = self.target(&target)?;
        let address = target.resolved_address.clone();
        let span = tracing::info_span!(
            "nucleus.get_latest_version",
            op = "get_latest_version",
            plugin = "nucleus",
            "object.address" = %RedactedUrl(&address),
        );
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let address = address.clone();
                async move {
                    let ops = self.ops()?;
                    if let Some(checkpoint) = parsed.checkpoint {
                        let result = ops.stat2(path_at_version(&parsed)).await?;
                        status_to_result(result.status, "stat2")?;
                        let version_address = checkpoint_address(&address, &parsed, checkpoint);
                        let info = stat2_to_object_info(version_address, result);
                        return Ok(info);
                    }
                    let path = PathAtBranch {
                        path: parsed.path.clone(),
                        branch: parsed.branch.clone(),
                    };
                    let response = ops.get_checkpoints(path).await?;
                    status_to_result(response.status, "get_checkpoints")?;
                    // omni1 doesn't document checkpoint ordering; checkpoint_id is monotonic,
                    // so max() is the head regardless of how the server sorts the list.
                    let latest_id = response
                        .checkpoints
                        .into_iter()
                        .filter_map(|c| c.checkpoint_id)
                        .max()
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Unsupported,
                                "Nucleus path has no checkpoints; create one before requesting the latest version",
                            )
                        })?;
                    let mut at_checkpoint = parsed.clone();
                    at_checkpoint.checkpoint = Some(latest_id);
                    let result = ops.stat2(path_at_version(&at_checkpoint)).await?;
                    status_to_result(result.status, "stat2")?;
                    let version_address = checkpoint_address(&address, &parsed, latest_id);
                    let info = stat2_to_object_info(version_address, result);
                    Ok(info)
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        let parsed = self.target(&prefix)?;
        let span = tracing::info_span!("nucleus.watch_directory", op = "watch_directory", plugin = "nucleus", "object.address" = %RedactedUrl(&prefix.resolved_address));
        if opts.since.is_some() {
            return Ok(Box::new(WatchIter::lapsed_only()));
        }
        let watched_prefix = parsed.path.clone();
        let handle = race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                async move {
                    let ops = self.ops()?;
                    let path = PathAtBranch {
                        path: parsed.path.clone(),
                        branch: parsed.branch,
                    };
                    ops.open_subscribe_list(path).await
                }
            }),
        )
        .instrument(span)
        .await?;
        Ok(Box::new(WatchIter::new(
            handle,
            prefix.resolved_address,
            watched_prefix,
            opts.recursive,
            opts.include_metadata_changes,
        )))
    }

    async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        let parsed = self.target(&target)?;
        Self::reject_checkpoint(&parsed, "create_directory")?;
        let span = tracing::info_span!("nucleus.create_directory", op = "write", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                async move {
                    let ops = self.ops()?;
                    let path = PathAtBranch {
                        path: parsed.path.clone(),
                        branch: parsed.branch.clone(),
                    };
                    let response = ops.create_directory(path).await?;
                    status_to_result(response.status, "create_directory")?;
                    Ok(BackendItemInfo::default())
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let parsed = self.target(&target)?;
        Self::reject_checkpoint(&parsed, "delete_directory")?;
        let span = tracing::info_span!("nucleus.delete", op = "delete", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                async move {
                    let ops = self.ops()?;
                    let path = PathAtVersion {
                        path: parsed.path.clone(),
                        branch: parsed.branch,
                        checkpoint: parsed.checkpoint,
                    };
                    let response = ops.delete2(vec![path]).await?;
                    status_to_result(response.status, "delete2 directory")?;
                    if let Some(per_path) = response.responses.first() {
                        status_to_result(*per_path, "delete2 directory entry")?;
                    }
                    Ok(())
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        require_etag_only_if_match(opts.if_source.as_deref())?;
        // omni1 copy2 takes Vec<PathsToCopy>; PathsToCopy has no etag field
        // on the source and no destination conditional, so neither side's
        // precondition is expressible at the protocol level. See the
        // regular `delete` impl.
        if opts.if_source.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus copy: source-side if_match preconditions are not expressible in omni1 copy2",
            ));
        }
        if !matches!(opts.if_dest, IfDestExists::Overwrite) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus copy: destination-side if_dest preconditions are not expressible in omni1 copy2",
            ));
        }
        let span = tracing::info_span!("nucleus.copy", op = "copy", plugin = "nucleus", "object.address" = %RedactedUrl(&src.resolved_address));
        let src_parsed = self.target(&src)?;
        let dst_parsed = self.target(&dest)?;
        // Source MAY carry a checkpoint (copy out of an old version is valid);
        // destination must not (omni1 copy2's dst is PathAtBranch). Server
        // rejects with InvalidArgument anyway; checking here gives a cleaner
        // message and is symmetric with rename.
        Self::reject_checkpoint(&dst_parsed, "copy destination")?;
        let dest_address = dest.resolved_address.clone();
        let message = opts.message.clone().unwrap_or_default();
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let src_parsed = src_parsed.clone();
                let dst_parsed = dst_parsed.clone();
                let dest_address = dest_address.clone();
                let message = message.clone();
                async move {
                    let ops = self.ops()?;
                    let response = ops
                        .copy2(vec![PathsToCopy {
                            src: path_at_version(&src_parsed),
                            dst: PathAtBranch {
                                path: dst_parsed.path,
                                branch: dst_parsed.branch,
                            },
                            message: Some(message),
                        }])
                        .await?;
                    status_to_result(response.status, "copy2")?;
                    if let Some(per_path) = response.responses.first() {
                        status_to_result(*per_path, "copy2 entry")?;
                    }
                    let info = ObjectInfo {
                        address: dest_address,
                        kind: ObjectKind::File,
                        etag: None,
                        version: None,
                        size: None,
                        mtime: None,
                        checksums: Default::default(),
                        effective_permissions: None,
                        system_metadata: None,
                        user_metadata: None,
                        modified_by: None,
                    };
                    Ok(WriteStep::Done(WriteResult { info }))
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        require_etag_only_if_match(opts.if_source.as_deref())?;
        // omni1 rename2 takes Vec<PathsToRename>; PathsToRename has no etag
        // field on either side and no destination conditional. See the
        // regular `delete` impl.
        if opts.if_source.is_some() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus rename: source-side if_match preconditions are not expressible in omni1 rename2",
            ));
        }
        if !matches!(opts.if_dest, IfDestExists::Overwrite) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "Nucleus rename: destination-side if_dest preconditions are not expressible in omni1 rename2",
            ));
        }
        let span = tracing::info_span!("nucleus.rename", op = "rename", plugin = "nucleus", "object.address" = %RedactedUrl(&src.resolved_address));
        let src_parsed = self.target(&src)?;
        let dst_parsed = self.target(&dest)?;
        // Nucleus's rename2 takes PathAtBranch on both sides, so a checkpoint
        // suffix on either silently strips and corrupts the head; reject both.
        // (The dest case is also rejected server-side, but checking here gives
        // a clearer error message.)
        Self::reject_checkpoint(&src_parsed, "rename source")?;
        Self::reject_checkpoint(&dst_parsed, "rename destination")?;
        let message = opts.message.clone().unwrap_or_default();
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let src_parsed = src_parsed.clone();
                let dst_parsed = dst_parsed.clone();
                let message = message.clone();
                async move {
                    let ops = self.ops()?;
                    let response = ops
                        .rename2(vec![PathsToRename {
                            src: PathAtBranch {
                                path: src_parsed.path,
                                branch: src_parsed.branch,
                            },
                            dst: PathAtBranch {
                                path: dst_parsed.path,
                                branch: dst_parsed.branch,
                            },
                            message: Some(message),
                        }])
                        .await?;
                    status_to_result(response.status, "rename2")?;
                    if let Some(per_path) = response.responses.first() {
                        status_to_result(*per_path, "rename2 entry")?;
                    }
                    Ok(())
                }
            }),
        )
        .instrument(span)
        .await
    }

    async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        require_etag_only_if_match(opts.if_match.as_deref())?;
        let _ = &cancel; // no async work in this method body; nothing to interrupt.
        // omni1 has set_path_options for created_by/modified_by/timestamps but no free-form user_metadata patch.
        let _ = self.target(&target)?;
        Err(Error::new(
            ErrorCode::Unsupported,
            "Nucleus does not expose a user-metadata patch endpoint via omni1",
        ))
    }

    async fn check_access(
        &self,
        target: ResolvedTarget,
        ops_requested: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        let span = tracing::info_span!("nucleus.check_access", op = "stat", plugin = "nucleus", "object.address" = %RedactedUrl(&target.resolved_address));
        let parsed = self.target(&target)?;
        let principal = self
            .shared
            .session
            .lock()
            .map_err(poisoned_state)?
            .as_ref()
            .map(|s| s.principal.clone());
        race_cancel(
            cancel.as_ref(),
            with_refresh(&self.shared, || {
                let parsed = parsed.clone();
                let ops_requested = ops_requested.clone();
                let principal = principal.clone();
                async move {
                    let ops = self.ops()?;
                    let response = ops.get_acl_resolved(vec![path_at_version(&parsed)]).await?;
                    status_to_result(response.status, "get_acl_resolved")?;
                    let resolved = response.responses.into_iter().next().ok_or_else(|| {
                        Error::new(
                            ErrorCode::Internal,
                            "Nucleus get_acl_resolved returned no entries",
                        )
                    })?;
                    status_to_result(resolved.status, "get_acl_resolved entry")?;
                    let principal = match principal.as_ref().filter(|s| !s.is_empty()) {
                        Some(p) => p.clone(),
                        None => {
                            return Ok(AccessDecision {
                                allowed: false,
                                denied_ops: ops_requested.clone(),
                                reason: Some("nucleus principal unknown".into()),
                            });
                        }
                    };
                    let mut effective = EffectivePermissions::empty();
                    if let Some(acl) = resolved.acl
                        && let Some(value) = acl.get(&principal)
                    {
                        effective |= acl_to_effective_permissions(&value.acl);
                    }
                    let mut denied = AccessOps::default();
                    if ops_requested.read && !effective.contains(EffectivePermissions::READ) {
                        denied.read = true;
                    }
                    if ops_requested.write && !effective.contains(EffectivePermissions::WRITE) {
                        denied.write = true;
                    }
                    if ops_requested.delete && !effective.contains(EffectivePermissions::DELETE) {
                        denied.delete = true;
                    }
                    if ops_requested.update_metadata
                        && !effective.contains(EffectivePermissions::UPDATE_METADATA)
                    {
                        denied.update_metadata = true;
                    }
                    let allowed =
                        !denied.read && !denied.write && !denied.delete && !denied.update_metadata;
                    Ok(AccessDecision {
                        allowed,
                        denied_ops: denied,
                        reason: None,
                    })
                }
            }),
        )
        .instrument(span)
        .await
    }
}

fn checkpoint_address(base: &Url, target: &NucleusTarget, checkpoint: u64) -> Url {
    let mut address = base.clone();
    address.set_query(None);
    address.set_fragment(None);
    let selector = match target.branch.as_deref() {
        Some(branch) => format!("{branch}&{checkpoint}"),
        None => format!("&{checkpoint}"),
    };
    address.set_query(Some(&selector));
    address
}

// Decode an LFT HTTP status to the typed `ErrorCode`. Lumping all non-2xx
// into Transient triggers useless backoff on deterministic failures.
fn map_lft_http_status(status: u16, context: String) -> Error {
    let code = match status {
        401 => ErrorCode::AuthRequired,
        403 => ErrorCode::PermissionDenied,
        404 => ErrorCode::NotFound,
        409 => ErrorCode::Conflict,
        412 => ErrorCode::PreconditionFailed,
        429 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Internal,
    };
    Error::new(code, context)
}

pub(crate) fn native_capabilities() -> Capabilities {
    Capabilities {
        supports_if_match_write: true,
        supports_no_overwrite_write: true,
        // omni1 has no caller-owned user-metadata patch.
        supports_native_metadata_patch: false,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: true,
        supports_write: true,
        supports_write_stream: true,
        supports_write_redirect: true,
        supports_delete: true,
        supports_server_side_copy: true,
        supports_server_side_rename: true,
        supports_atomic_rename: false,
        has_real_directories: true,
        supports_list: true,
        wants_list_backed_stat: true,
        // omni1 list2 returns a single directory level; recursive walks are host-driven.
        supports_recursive_list: false,
        supports_create_directory: true,
        supports_delete_directory: true,
        populates_subdirectory_metadata: true,
        supports_version_listing: true,
        version_list_order: Some(VersionListOrder::Newest),
        populates_effective_permissions_on_stat: true,
        supports_access_check: true,
        supports_watch_directory: true,
        watch_directory_kinds: ChangeKindSet {
            created: true,
            modified: true,
            deleted: true,
            metadata_changed: true,
        },
        watch_directory_resumable: false,
        watch_directory_max_lag: None,
        // Patched with the server-advertised value once `LftClient` installs.
        redirect_size_threshold: Some(DEFAULT_LFT_THRESHOLD_BYTES),
    }
}

/// 16 MiB matches the omni1 buffered-PUT upper bound for typical deployments.
pub(crate) const DEFAULT_LFT_THRESHOLD_BYTES: u64 = 16 * 1024 * 1024;
