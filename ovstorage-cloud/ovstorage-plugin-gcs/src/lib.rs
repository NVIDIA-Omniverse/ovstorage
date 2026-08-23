// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::subscription::WatchCoalescer;
use ovstorage_plugin::*;
use ovstorage_plugin::{
    AccessDecision, AccessOps, BackendChangeStream, BackendItemInfo, CopyOptions,
    CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, IfDestExists, ListOptions,
    ListVersionsOptions, ObjectKind, ReadOptions, ReadResult, RenameOptions, ResolvedTarget,
    StatOptions, UpdateMetadataOptions, WatchDirectoryOptions, WriteRedirectBatch, WriteStep,
    race_cancel, reject_pinned_for_mutation,
};

const PINNED_VERSION_KEYS: &[&str] = &["generation"];
use serde::{Deserialize, Serialize};
use tracing::{Instrument, warn};

mod auth;
mod convert;
mod driver;
mod error_body;
mod layer;

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
mod parse;
mod promotion;
mod sign;
mod subscription;

use auth::{Authenticator, CredentialSource};
use convert::require_version_only_if_match;
use error_body::provider_detail;
use parse::{
    GcsList, GcsObject, ParsedObject, RewriteResponse, TestIamPermissionsResponse, parse_object,
};
use sign::{DEFAULT_EXPIRY_SECONDS, V4Request, sign_url};

const DEFAULT_ENDPOINT: &str = "https://storage.googleapis.com";
const HTTP_USER_AGENT: &str = concat!("ovstorage-plugin-gcs/", env!("CARGO_PKG_VERSION"));
const RESULT_CAPTURE_BODY_BYTES: u32 = 64 * 1024;
/// GCS object size cap (5 TiB). Sentinel length on resumable redirects
/// when body size is unknown; the host uses chunked encoding and the
/// real length is settled at end-of-stream.
const GCS_MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;

/// IAM probe endpoint; note `Iam` infix — `testPermissions` 404s.
const TEST_IAM_PERMISSIONS_PATH: &str = "iam/testIamPermissions";

/// User-metadata key under which `WriteOptions::message` is persisted on
/// backends without native commit-annotation support.
const OV_MESSAGE_KEY: &str = "x-ov-message";

/// The static backend descriptor; converted to the v2 `LayerKindDescriptor`
/// via `descriptor_to_layer_kind` at the factory/layer surface.
pub(crate) fn kind_descriptor() -> StorageBackendKindDescriptor {
    StorageBackendKindDescriptor {
            kind: "gcs".into(),
            display_name: "Google Cloud Storage".into(),
            description: Some(
                "Native Google Cloud Storage provider with JSON REST, V4 signed URLs, resumable uploads, and ADC credential discovery".into(),
            ),
            config_schema: vec![
                text_field(
                    "bucket",
                    "Bucket",
                    true,
                    Some("example-bucket"),
                    Some("GCS bucket served by this connection"),
                    false,
                ),
                text_field(
                    "project_id",
                    "Project ID",
                    false,
                    Some("example-project"),
                    Some("Optional Google Cloud project used by provider-native operations"),
                    true,
                ),
                text_field(
                    "service_account",
                    "Service account",
                    false,
                    Some("storage-reader@example-project.iam.gserviceaccount.com"),
                    Some("Optional named service account in the GCS credential chain"),
                    true,
                ),
                url_field(
                    "endpoint",
                    "Endpoint",
                    false,
                    Some("https://storage.googleapis.com"),
                    Some("Optional endpoint override for GCS-compatible deployments"),
                    true,
                ),
                watch_text_field(
                    "pubsub_subscription",
                    "Pub/Sub subscription",
                    Some("projects/example-project/subscriptions/object-changes"),
                    Some("Cloud Pub/Sub subscription that receives Cloud Storage object-change notifications"),
                ),
                watch_int_field(
                    "pubsub_pull_max",
                    "Pub/Sub pull max",
                    Some(100),
                    Some("Maximum Pub/Sub messages requested per pull for directory watches"),
                    Some("100"),
                ),
            ],
            credential_schema: vec![
                CredentialField {
                    key: "service_account_key".into(),
                    display_name: "Service account key".into(),
                    default: None,
                    help: Some(
                        "Optional service-account JSON for deployments that do not use ADC".into(),
                    ),
                    advanced: false,
                },
                CredentialField {
                    key: "file_path".into(),
                    display_name: "ADC file path".into(),
                    default: Some(
                        "~/.config/gcloud/application_default_credentials.json".into(),
                    ),
                    help: Some(
                        "Path to a gcloud ADC JSON file (service-account or authorized-user)".into(),
                    ),
                    advanced: false,
                },
            ],
            credential_methods: vec![
                CredentialMethod {
                    key: "service_account_key".into(),
                    display_name: "Service account key (JSON)".into(),
                    fields: vec!["service_account_key".into()],
                    help: Some("Paste a service-account JSON keyfile.".into()),
                    advanced: false,
                },
                CredentialMethod {
                    key: "gcloud_adc_file".into(),
                    display_name: "User credentials from gcloud ADC file".into(),
                    fields: vec!["file_path".into()],
                    help: Some(
                        "Reads the ADC JSON file written by `gcloud auth application-default login`.".into(),
                    ),
                    advanced: false,
                },
            ],
            icon: None,
            supports_runtime_add: true,
            supports_user_metadata: true,
        }
}

pub struct GcsBackend {
    config: GcsConnectionConfig,
    http: reqwest::Client,
    auth: Arc<Authenticator>,
    /// Per-connection watch coalescer: concurrent `watch_directory` calls
    /// (any prefix, any principal) merge onto ONE Pub/Sub pull consumer per
    /// connection, fanning events out prefix-filtered per subscriber.
    watch_coalescer: Arc<WatchCoalescer>,
}

/// `bearer_auth` variant that no-ops on an empty token so anonymous and
/// authenticated request paths share one builder chain.
trait MaybeBearerAuth {
    fn maybe_bearer_auth(self, token: String) -> Self;
}

impl MaybeBearerAuth for reqwest::RequestBuilder {
    fn maybe_bearer_auth(self, token: String) -> Self {
        if token.is_empty() {
            self
        } else {
            self.bearer_auth(token)
        }
    }
}

impl GcsBackend {
    /// The connection's credential. Its refusal epoch and IdP-refusal latch are
    /// what `GcsLayer`'s promotion witness reads.
    pub(crate) fn authenticator(&self) -> &Authenticator {
        &self.auth
    }

    /// Send one storage request and record what the answer says about this
    /// connection's credential.
    ///
    /// Every storage request in this crate goes through here, which is what
    /// makes the judgment complete — but nothing in the type system enforces
    /// that. A new call site that reaches for `self.http` directly would send an
    /// unjudged request, and the connection would simply never promote on it.
    /// The IdP exchange and the Pub/Sub calls do exactly that, deliberately.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let request = request.build().map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("GCS request could not be built: {err}"),
            )
        })?;
        // The request is built rather than sent through the builder so the
        // redirect watch can wrap the execution itself; `RequestBuilder::send`
        // is `client.execute(self.build()?)`, so nothing else changes.
        let (outcome, bearer_survived) =
            promotion::watching_redirects(self.http.execute(request)).await;
        let response = outcome.map_err(|err| {
            Error::new(
                ErrorCode::Transient,
                format!("GCS HTTP transport error: {err}"),
            )
        })?;
        note_promotion_evidence(&self.auth, bearer_survived, &response);
        Ok(response)
    }

    fn new(config: GcsConnectionConfig, http: reqwest::Client, auth: Arc<Authenticator>) -> Self {
        let watch_coalescer = WatchCoalescer::new();
        Self {
            config,
            http,
            auth,
            watch_coalescer,
        }
    }

    /// The per-connection watch coalescer that merges concurrent
    /// `watch_directory` calls onto one Pub/Sub pull consumer.
    pub(crate) fn watch_coalescer(&self) -> &Arc<WatchCoalescer> {
        &self.watch_coalescer
    }

    fn parse_target(&self, target: &ResolvedTarget, require_object: bool) -> Result<GcsObjectRef> {
        let parsed = parse_gcs_address(&target.resolved_address)?;
        if parsed.bucket != self.config.bucket {
            return Err(Error::new(
                ErrorCode::NoRoute,
                "GCS address bucket is not served by this connection",
            ));
        }
        if require_object && parsed.object.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "GCS object operation requires a non-empty object name",
            ));
        }
        Ok(parsed)
    }

    fn endpoint(&self) -> &str {
        self.config.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT)
    }

    fn object_url(&self, bucket: &str, object: &str) -> String {
        format!(
            "{}/storage/v1/b/{}/o/{}",
            self.endpoint(),
            urlencoding::encode(bucket),
            urlencoding::encode(object)
        )
    }

    fn list_url(&self, bucket: &str) -> String {
        format!(
            "{}/storage/v1/b/{}/o",
            self.endpoint(),
            urlencoding::encode(bucket)
        )
    }

    fn upload_url(&self, bucket: &str) -> String {
        format!(
            "{}/upload/storage/v1/b/{}/o",
            self.endpoint(),
            urlencoding::encode(bucket)
        )
    }

    fn rewrite_url(
        &self,
        src_bucket: &str,
        src_object: &str,
        dst_bucket: &str,
        dst_object: &str,
    ) -> String {
        format!(
            "{}/storage/v1/b/{}/o/{}/rewriteTo/b/{}/o/{}",
            self.endpoint(),
            urlencoding::encode(src_bucket),
            urlencoding::encode(src_object),
            urlencoding::encode(dst_bucket),
            urlencoding::encode(dst_object),
        )
    }

    async fn bearer_token(&self) -> Result<String> {
        self.auth.access_token().await
    }

    async fn fetch_object(&self, object: &GcsObjectRef) -> Result<GcsObject> {
        let token = self.bearer_token().await?;
        let mut request = self
            .http
            .get(self.object_url(&object.bucket, &object.object))
            .query(&[
                (
                    "fields",
                    "bucket,name,etag,generation,metageneration,size,updated,timeCreated,md5Hash,crc32c,storageClass,contentType,contentEncoding,temporaryHold,eventBasedHold,retentionExpirationTime,metadata",
                ),
            ])
            .maybe_bearer_auth(token);
        if let Some(generation) = object.generation_selector() {
            request = request.query(&[("generation", generation.as_str())]);
        }
        let response = self.send(request).await?;
        decode_object(response).await
    }

    /// One cheap read-only RPC for the connection driver's verify:
    /// `objects.list` with `maxResults=1` on the configured bucket. GCS
    /// splits the auth verdict natively by status (401 = bad/expired
    /// credentials via `ensure_success`; 403 = valid-but-unauthorized), so
    /// the driver classifies the MAPPED error — no raw-response plumbing.
    pub(crate) async fn verify_probe(&self) -> Result<()> {
        let token = self.bearer_token().await?;
        let request = self
            .http
            .get(self.list_url(&self.config.bucket))
            .query(&[("maxResults", "1"), ("fields", "items(name)")])
            .maybe_bearer_auth(token);
        let response = self.send(request).await?;
        let _: GcsList = decode_json(response).await?;
        Ok(())
    }

    async fn directory_has_descendants(&self, bucket: &str, prefix: &str) -> Result<bool> {
        let token = self.bearer_token().await?;
        let request = self
            .http
            .get(self.list_url(bucket))
            .query(&[
                ("prefix", prefix),
                ("maxResults", "1"),
                ("fields", "items(name)"),
            ])
            .maybe_bearer_auth(token);
        let response = self.send(request).await?;
        let listing: GcsList = decode_json(response).await?;
        Ok(!listing.items.is_empty())
    }
}

/// The GCS object/data operations used by the native Layer slots.
/// `crate::layer::GcsLayer` delegates its operation slots here.
impl GcsBackend {
    pub async fn stat(
        &self,
        target: ResolvedTarget,
        _opts: StatOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "gcs.stat",
            op = "stat",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let object = self.parse_target(&target, false)?;
                if object.object.is_empty() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "GCS stat at the bucket root is not supported",
                    ));
                }
                match self.fetch_object(&object).await {
                    Ok(found) => {
                        let parsed = parse_object(&found)?;
                        let mut info = materialize_info(&target.resolved_address, parsed);
                        if object.object.ends_with('/') {
                            info.kind = ObjectKind::DirectoryMarker;
                        }
                        return Ok(info);
                    }
                    Err(err) if err.code() == ErrorCode::NotFound => {}
                    Err(err) => return Err(err),
                }
                // Flat-backend fallback: slash-form marker, then a bounded
                // prefix probe for an inferred directory.
                if !object.object.ends_with('/') {
                    let marker_object = GcsObjectRef {
                        bucket: object.bucket.clone(),
                        object: directory_marker_name(&object.object),
                        selector: None,
                    };
                    match self.fetch_object(&marker_object).await {
                        Ok(found) => {
                            let parsed = parse_object(&found)?;
                            let mut info = materialize_info(&target.resolved_address, parsed);
                            info.kind = ObjectKind::DirectoryMarker;
                            return Ok(info);
                        }
                        Err(err) if err.code() == ErrorCode::NotFound => {}
                        Err(err) => return Err(err),
                    }
                }
                let probe_prefix = directory_marker_name(&object.object);
                if self
                    .directory_has_descendants(&object.bucket, &probe_prefix)
                    .await?
                {
                    return Ok(inferred_directory_info(&target.resolved_address));
                }
                Err(Error::new(ErrorCode::NotFound, "GCS object not found"))
            }
            .instrument(span),
        )
        .await
    }

    pub async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        let span = tracing::debug_span!(
            "gcs.read",
            op = "read",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                require_version_only_if_match(opts.if_match.as_deref())?;
                let object = self.parse_target(&target, true)?;
                let if_generation_match = opts.if_match.clone();
                let range_header = read_range_header(opts.range.as_ref())?;
                if self.auth.is_anonymous() {
                    let endpoint = self.config.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
                    let host = endpoint
                        .strip_prefix("https://")
                        .or_else(|| endpoint.strip_prefix("http://"))
                        .unwrap_or(endpoint)
                        .trim_end_matches('/')
                        .to_string();
                    let mut url = format!(
                        "{}/{}/{}",
                        endpoint.trim_end_matches('/'),
                        urlencoding::encode(&object.bucket),
                        urlencoding::encode(&object.object),
                    );
                    let mut query: Vec<(String, String)> = Vec::new();
                    if let Some(generation) = object.generation_selector() {
                        query.push(("generation".into(), generation));
                    }
                    // SPI `if_match` rides as `ifGenerationMatch` on the
                    // public download URL: GCS enforces it server-side
                    // and the redirect follower surfaces 412 as
                    // `ObjectModified`. Dropping it (the prior shape)
                    // would let a stale-read race silently return the
                    // newer object's bytes.
                    if let Some(generation) = if_generation_match.as_ref() {
                        query.push(("ifGenerationMatch".into(), generation.clone()));
                    }
                    if !query.is_empty() {
                        let encoded: Vec<String> = query
                            .iter()
                            .map(|(k, v)| {
                                format!("{}={}", urlencoding::encode(k), urlencoding::encode(v))
                            })
                            .collect();
                        url.push('?');
                        url.push_str(&encoded.join("&"));
                    }
                    let mut extras: Vec<(String, String)> = Vec::new();
                    if let Some(range) = range_header.clone() {
                        extras.push(("range".into(), range));
                    }
                    // Public-bucket download URL: unsigned, so it carries no
                    // credential at all.
                    return Ok(ReadResult::Redirect(read_redirect(
                        url,
                        host,
                        extras,
                        RedirectCredential::None,
                    )));
                }
                let source = self.auth.resolve_source()?;
                // GCS preconditions are generation-based; etag is separate
                // and has no `ifEtagMatch` endpoint, so `if_match.etag` is
                // silently ignored — strict gating requires generation.
                match source {
                    CredentialSource::Anonymous => unreachable!("checked above"),
                    CredentialSource::ServiceAccount(sa) => {
                        let mut query: Vec<(String, String)> = Vec::new();
                        if let Some(generation) = object.generation_selector() {
                            query.push(("generation".to_string(), generation));
                        }
                        if let Some(generation) = if_generation_match.as_ref() {
                            query.push(("ifGenerationMatch".to_string(), generation.clone()));
                        }
                        let signed = sign_url(
                            &sa,
                            V4Request {
                                method: "GET",
                                bucket: &object.bucket,
                                object: &object.object,
                                query: &query,
                                now: SystemTime::now(),
                                expires_in_seconds: DEFAULT_EXPIRY_SECONDS,
                                endpoint: self.config.endpoint.as_deref(),
                            },
                        )?;
                        let mut extras: Vec<(String, String)> = Vec::new();
                        if let Some(range) = range_header.clone() {
                            extras.push(("range".into(), range));
                        }
                        // V4 signature over this bucket, object, method and a
                        // `DEFAULT_EXPIRY_SECONDS` window.
                        Ok(ReadResult::Redirect(read_redirect(
                            signed.url,
                            signed.host_header,
                            extras,
                            RedirectCredential::Request,
                        )))
                    }
                    CredentialSource::User(_) => {
                        let info = parse_object(&self.fetch_object(&object).await?)?;
                        let info = materialize_info(&target.resolved_address, info);
                        // Whole-object reads stream; range reads buffer
                        // (bounded slice + identity-from-headers stays simple).
                        if range_header.is_none() {
                            let stream = self
                                .download_stream(&object, if_generation_match.as_deref())
                                .await
                                .map_err(|err| read_precondition_to_modified(err, &opts))?;
                            return Ok(ReadResult::Stream { stream, info });
                        }
                        let bytes = self
                            .download_bytes(
                                &object,
                                range_header.as_deref(),
                                if_generation_match.as_deref(),
                            )
                            .await
                            .map_err(|err| read_precondition_to_modified(err, &opts))?;
                        Ok(ReadResult::Bytes { bytes, info })
                    }
                }
            }
            .instrument(span),
        )
        .await
    }

    /// Buffered inline write — used by callers writing zero-byte or
    /// sub-`redirect_size_threshold` bodies, where the resumable
    /// session round-trip is pure overhead. Issues a single
    /// `uploadType=multipart` POST that bundles metadata + body.
    pub async fn write(
        &self,
        target: ResolvedTarget,
        bytes: Vec<u8>,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(&target.resolved_address, "gcs write", PINNED_VERSION_KEYS)?;
        let span = tracing::debug_span!(
            "gcs.write",
            op = "write",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = bytes.len() as u64,
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let object = self.parse_target(&target, true)?;
                self.put_object_inline(target, object, bytes, opts).await
            }
            .instrument(span),
        )
        .await
    }

    pub async fn write_redirect(
        &self,
        target: ResolvedTarget,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteRedirectBatch> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "gcs write_redirect",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "gcs.write",
            op = "write",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
            size_bytes = opts.size_hint,
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                // Single-redirect follower can't emit GCS Content-Range chunk
                // framing, so unknown-size streams route via `write_stream`.
                if opts.size_hint.is_none() {
                    return Err(Error::new(
                        ErrorCode::Unsupported,
                        "GCS write_redirect requires a known size_hint; \
                     streaming uploads route through write_stream",
                    ));
                }
                let object = self.parse_target(&target, true)?;
                self.initiate_resumable_redirect(target, object, opts).await
            }
            .instrument(span),
        )
        .await
    }

    pub async fn write_stream(
        &self,
        target: ResolvedTarget,
        body: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteResult> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "gcs write_stream",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "gcs.write_stream",
            op = "write",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
            // size_bytes omitted: streaming body — unknown at entry
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let object = self.parse_target(&target, true)?;
                match self
                    .stream_resumable_upload(target, object, body, opts)
                    .await?
                {
                    WriteStep::Done(result) => Ok(result),
                    WriteStep::Redirects(_) => Err(Error::new(
                        ErrorCode::Internal,
                        "GCS write_stream produced redirects instead of WriteResult",
                    )),
                }
            }
            .instrument(span),
        )
        .await
    }

    pub async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        let _ = &cancel; // no async work; nothing to interrupt.
        // Guarded like every other `continue_write`, even though this one
        // performs no outbound call: it still reports an address, and reporting
        // a pinned one it did not act on is its own defect. Leaving GCS as the
        // single unguarded adopter would also make the rule unstatable.
        reject_pinned_for_mutation(
            &target.resolved_address,
            "gcs continue_write",
            PINNED_VERSION_KEYS,
        )?;
        validate_redirect_results(&redirects, &results)?;
        if results.results.len() != 1 {
            return Err(Error::new(
                ErrorCode::Internal,
                "GCS resumable continue_write expects exactly one redirect result",
            ));
        }
        let continuation: ResumableContinuation = serde_json::from_slice(&redirects.continuation)
            .map_err(|err| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("GCS continue_write continuation is not the expected JSON: {err}"),
            )
        })?;
        // Defence in depth, not the control. GCS's capability-bearing identity
        // is `session_url`, issued by GCS in the resumable-initiate `Location`
        // header: it names the object by itself and cannot be recomputed from
        // the address, so unlike the other adopters this plugin has nothing to
        // derive. What is left is a comparison, and on the broker's
        // client-driven route both sides of it arrive from the same remote
        // caller — a caller presenting a genuine session for another object can
        // rewrite `target_address` to match. It is kept because it does catch a
        // real mismatch on the routes where a follower produced the batch, and
        // costs nothing.
        if continuation.target_address != target.resolved_address.as_str() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "GCS continue_write target address does not match the continuation",
            ));
        }
        let redirect_url = redirects
            .redirects
            .first()
            .map(|r| r.request.url.as_str())
            .unwrap_or("");
        // Exact equality on path/host: `starts_with` would let
        // `.../sessionXXX` match a sibling `.../sessionXXXextra`. Like the
        // check above this is an internal-consistency assertion: both sides
        // come out of the same batch, so on the client-driven route it
        // establishes only that the caller was self-consistent.
        if trim_session_query(redirect_url) != trim_session_query(&continuation.session_url) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "GCS continue_write redirect URL does not match the continuation session URL",
            ));
        }
        let result = &results.results[0];
        // 308 Resume Incomplete on the single-PUT path means the session
        // is unfinished; do not synthesize a success.
        if result.status_code == 308 {
            return Err(Error::new(
                ErrorCode::Internal,
                "GCS continue_write received 308 Resume Incomplete from a single-PUT redirect; \
                 the resumable session was not committed",
            ));
        }
        if !is_status_success(result.status_code) {
            return Err(map_status_to_error(
                result.status_code,
                &String::from_utf8_lossy(&result.captured_body),
            ));
        }
        let object: GcsObject = serde_json::from_slice(&result.captured_body).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "GCS resumable response was not Object JSON: {}",
                    crate::error_body::decode_failure(&err, result.captured_body.len())
                ),
            )
        })?;
        // Re-check the object the response names against the target. On a
        // follower route the captured body came from GCS and this is a genuine
        // post-commit detection; on the client-driven route the body is
        // caller-supplied, so a caller that forges it forges this check's input
        // too. Worth keeping for the honest case, worth nothing against the
        // dishonest one.
        let target_object = self.parse_target(&target, true)?;
        match object.name.as_deref() {
            Some(name) if name == target_object.object => {}
            Some(_) => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "GCS continue_write captured Object name does not match the target",
                ));
            }
            None => {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "GCS continue_write captured Object JSON is missing the 'name' field",
                ));
            }
        }
        let parsed = parse_object(&object)?;
        // Parsed out of the response body the caller captured and handed back,
        // so the reserved attribution key inside it is the caller's shape. It
        // is put right by the host's attribution overlay, which is the one
        // place every `continue_write` result passes through; what GCS
        // *persisted* was committed server-side when the resumable session was
        // opened and the caller never held it.
        let info = materialize_info(&target.resolved_address, parsed);
        Ok(WriteStep::Done(WriteResult { info }))
    }

    pub async fn delete(
        &self,
        target: ResolvedTarget,
        opts: DeleteOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        let span = tracing::debug_span!(
            "gcs.delete",
            op = "delete",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                require_version_only_if_match(opts.if_match.as_deref())?;
                let object = self.parse_target(&target, true)?;
                let token = self.bearer_token().await?;
                let mut request = self
                    .http
                    .delete(self.object_url(&object.bucket, &object.object))
                    .maybe_bearer_auth(token);
                if let Some(version) = opts.if_match.as_deref() {
                    request = request.query(&[("ifGenerationMatch", version)]);
                } else if let Some(generation) = object.generation_selector() {
                    request = request.query(&[("generation", generation.as_str())]);
                }
                let response = self.send(request).await?;
                // delete is idempotent: a missing target is success.
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(());
                }
                ensure_success(response).await?;
                Ok(())
            }
            .instrument(span),
        )
        .await
    }

    pub async fn list(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "gcs.list",
            op = "list",
            plugin = "gcs",
            object.address = %RedactedUrl(&prefix.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let target = self.parse_target(&prefix, false)?;
                let mut items: Vec<ObjectInfo> = Vec::new();
                let mut page_token = opts.page_token.clone();
                let mut remaining = opts.max_results;
                loop {
                    let mut query: Vec<(String, String)> = Vec::new();
                    if !target.object.is_empty() {
                        query.push((
                            "prefix".to_string(),
                            address::directory_key(&target.object),
                        ));
                    }
                    if !opts.recursive {
                        query.push(("delimiter".to_string(), "/".to_string()));
                    }
                    if let Some(token) = page_token.as_ref() {
                        query.push(("pageToken".to_string(), token.clone()));
                    }
                    if let Some(limit) = remaining {
                        query.push(("maxResults".to_string(), limit.to_string()));
                    }
                    let token = self.bearer_token().await?;
                    let request = self
                        .http
                        .get(self.list_url(&target.bucket))
                        .query(&query)
                        .maybe_bearer_auth(token);
                    let response = self.send(request).await?;
                    let listing: GcsList = decode_json(response).await?;
                    let listed_marker_name = if target.object.is_empty() {
                        String::new()
                    } else if target.object.ends_with('/') {
                        target.object.clone()
                    } else {
                        format!("{}/", target.object)
                    };
                    let mut emitted: u32 = 0;
                    let mut marker_addresses = std::collections::HashSet::new();
                    for object in &listing.items {
                        let Some(name) = object.name.as_deref() else {
                            continue;
                        };
                        if !listed_marker_name.is_empty() && name == listed_marker_name {
                            continue;
                        }
                        let is_marker =
                            name.ends_with('/') && object.size.as_deref().unwrap_or("0") == "0";
                        if is_marker {
                            let Ok(address) =
                                address::join_relative(&self.config.address_root, name)
                            else {
                                // The name cannot be spelled as a URI path, so
                                // any address built for it would resolve to a
                                // different object. Omit the entry and keep the
                                // page: invisible beats mis-addressed, and
                                // failing the page would hide every sibling
                                // too.
                                tracing::warn!(
                                    target: "ovstorage.gcs.backend",
                                    plugin = "gcs",
                                    key = %name,
                                    "gcs: object name is not addressable as a URI path; omitted from listing",
                                );
                                continue;
                            };
                            marker_addresses.insert(address.as_str().to_string());
                            items.push(ObjectInfo {
                                address,
                                kind: ObjectKind::DirectoryMarker,
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
                            emitted += 1;
                            continue;
                        }
                        let parsed = parse_object(object)?;
                        let Ok(address) = address::join_relative(&self.config.address_root, name)
                        else {
                            tracing::warn!(
                                target: "ovstorage.gcs.backend",
                                plugin = "gcs",
                                key = %name,
                                "gcs: object name is not addressable as a URI path; omitted from listing",
                            );
                            continue;
                        };
                        items.push(materialize_info(&address, parsed));
                        emitted += 1;
                    }
                    for prefix_value in &listing.prefixes {
                        let Ok(address) =
                            address::join_relative(&self.config.address_root, prefix_value)
                        else {
                            tracing::warn!(
                                target: "ovstorage.gcs.backend",
                                plugin = "gcs",
                                key = %prefix_value,
                                "gcs: common prefix is not addressable as a URI path; omitted from listing",
                            );
                            continue;
                        };
                        if marker_addresses.contains(address.as_str()) {
                            continue;
                        }
                        items.push(inferred_directory_info(&address));
                        emitted += 1;
                    }
                    if let Some(limit) = remaining {
                        remaining = Some(limit.saturating_sub(emitted));
                        if remaining == Some(0) {
                            break;
                        }
                    }
                    match listing.next_page_token {
                        Some(next) if !next.is_empty() => page_token = Some(next),
                        _ => break,
                    }
                }
                Ok(items)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn list_versions(
        &self,
        target: ResolvedTarget,
        opts: ListVersionsOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<Vec<ObjectInfo>> {
        let span = tracing::debug_span!(
            "gcs.list_versions",
            op = "list",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let object = self.parse_target(&target, true)?;
                let mut versions = Vec::new();
                let mut page_token = opts.page_token.clone();
                'pages: loop {
                    let mut query: Vec<(String, String)> = vec![
                        ("prefix".to_string(), object.object.clone()),
                        ("versions".to_string(), "true".to_string()),
                    ];
                    if let Some(token) = page_token.as_ref() {
                        query.push(("pageToken".to_string(), token.clone()));
                    }
                    if let Some(limit) = opts.max_results {
                        let already = versions.len() as u32;
                        let need = limit.saturating_sub(already);
                        if need == 0 {
                            break;
                        }
                        query.push(("maxResults".to_string(), need.to_string()));
                    }
                    let token = self.bearer_token().await?;
                    let request = self
                        .http
                        .get(self.list_url(&object.bucket))
                        .query(&query)
                        .maybe_bearer_auth(token);
                    let response = self.send(request).await?;
                    let listing: GcsList = decode_json(response).await?;
                    for entry in &listing.items {
                        let Some(name) = entry.name.as_deref() else {
                            continue;
                        };
                        if name != object.object {
                            continue;
                        }
                        let Some(generation) = entry.generation.clone() else {
                            continue;
                        };
                        let parsed = parse_object(entry)?;
                        let address = generation_address(&target.resolved_address, &generation)?;
                        versions.push(materialize_info(&address, parsed));
                        if let Some(limit) = opts.max_results
                            && versions.len() as u32 >= limit
                        {
                            break 'pages;
                        }
                    }
                    match listing.next_page_token {
                        Some(next) if !next.is_empty() => page_token = Some(next),
                        _ => break,
                    }
                }
                Ok(versions)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn get_latest_version(
        &self,
        target: ResolvedTarget,
        cancel: Option<CancellationToken>,
    ) -> Result<ObjectInfo> {
        let span = tracing::debug_span!(
            "gcs.get_latest_version",
            op = "stat",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let object = self.parse_target(&target, true)?;
                if object.object.is_empty() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "GCS get_latest_version at the bucket root is not supported",
                    ));
                }
                let pinned = object.generation_selector();
                let fetched = self.fetch_object(&object).await?;
                let parsed = parse_object(&fetched)?;
                let value = pinned.or_else(|| parsed.version.clone()).ok_or_else(|| {
                    Error::new(
                        ErrorCode::Unsupported,
                        "GCS object has no generation (bucket may not be versioned)",
                    )
                })?;
                let address = generation_address(&target.resolved_address, &value)?;
                Ok(materialize_info(&address, parsed))
            }
            .instrument(span),
        )
        .await
    }

    pub async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: WatchDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendChangeStream> {
        subscription::watch_directory(self, prefix, opts, cancel).await
    }

    pub async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "gcs create_directory",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "gcs.create_directory",
            op = "write",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let directory = self.parse_target(&target, false)?;
                let marker_name = directory_marker_name(&directory.object);
                let object_ref = GcsObjectRef {
                    bucket: directory.bucket.clone(),
                    object: marker_name,
                    selector: None,
                };
                let parsed = self.put_marker(&object_ref).await?;
                // The PUT just created the zero-byte marker object,
                // so tag the returned info as `DirectoryMarker` —
                // the dispatcher's marker-folding only runs on `list`
                // and a direct create_directory caller would otherwise
                // see `ObjectKind::File` for what's actually a marker.
                let mut info = backend_item_info(parsed);
                info.kind = ObjectKind::DirectoryMarker;
                Ok(info)
            }
            .instrument(span),
        )
        .await
    }

    pub async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "gcs delete_directory",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "gcs.delete_directory",
            op = "delete",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let directory = self.parse_target(&target, false)?;
                let marker_name = directory_marker_name(&directory.object);
                if self
                    .has_descendants(&directory.bucket, &marker_name)
                    .await?
                {
                    return Err(Error::new(
                        ErrorCode::DirectoryNotEmpty,
                        format!("GCS directory {} is not empty", marker_name),
                    ));
                }
                let token = self.bearer_token().await?;
                let response = self
                    .send(
                        self.http
                            .delete(self.object_url(&directory.bucket, &marker_name))
                            .maybe_bearer_auth(token),
                    )
                    .await?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(());
                }
                ensure_success(response).await?;
                Ok(())
            }
            .instrument(span),
        )
        .await
    }

    pub async fn copy(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: CopyOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<WriteStep> {
        reject_pinned_for_mutation(&dest.resolved_address, "gcs copy(dst)", PINNED_VERSION_KEYS)?;
        let span = tracing::debug_span!(
            "gcs.copy",
            op = "copy",
            plugin = "gcs",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                require_version_only_if_match(opts.if_source.as_deref())?;
                let src_ref = self.parse_target(&src, true)?;
                let dest_ref = self.parse_target(&dest, true)?;
                let parsed = self.rewrite_object(&src_ref, &dest_ref, &opts).await?;
                let info = materialize_info(&dest.resolved_address, parsed);
                Ok(WriteStep::Done(WriteResult { info }))
            }
            .instrument(span),
        )
        .await
    }

    pub async fn rename(
        &self,
        src: ResolvedTarget,
        dest: ResolvedTarget,
        opts: RenameOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        reject_pinned_for_mutation(
            &src.resolved_address,
            "gcs rename(src)",
            PINNED_VERSION_KEYS,
        )?;
        reject_pinned_for_mutation(
            &dest.resolved_address,
            "gcs rename(dst)",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "gcs.rename",
            op = "rename",
            plugin = "gcs",
            object.address = %RedactedUrl(&dest.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                require_version_only_if_match(opts.if_source.as_deref())?;
                let src_ref = self.parse_target(&src, true)?;
                let dest_ref = self.parse_target(&dest, true)?;
                // GCS has no native rename: copy-then-delete with rollback
                // on delete failure to avoid orphaning the destination.
                let copy_opts = CopyOptions {
                    if_source: opts.if_source.clone(),
                    if_dest: opts.if_dest.clone(),
                    message: opts.message.clone(),
                };
                let _ = self.rewrite_object(&src_ref, &dest_ref, &copy_opts).await?;
                let token = self.bearer_token().await?;
                let mut delete_request = self
                    .http
                    .delete(self.object_url(&src_ref.bucket, &src_ref.object))
                    .maybe_bearer_auth(token);
                if let Some(version) = opts.if_source.as_deref() {
                    delete_request = delete_request.query(&[("ifGenerationMatch", version)]);
                } else if let Some(generation) = src_ref.generation_selector() {
                    delete_request = delete_request.query(&[("generation", generation.as_str())]);
                }
                let response = self.send(delete_request).await?;
                if response.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(());
                }
                if let Err(delete_error) = ensure_success(response).await {
                    // Best-effort rollback so the caller does not see two
                    // surviving copies after the delete fails.
                    //
                    // Every step is folded into one `Result` rather than
                    // propagated with `?`: a rollback that fails on its token
                    // refresh or its transport leaves the destination standing
                    // just as surely as one that gets a non-2xx, and those are
                    // the likely companions of whatever broke the source
                    // delete. Letting either escape here would report the
                    // rollback's own error and hide the surviving copy — the
                    // exact misreport this arm exists to prevent.
                    let rollback_outcome: Result<()> = (async {
                        let token = self.bearer_token().await?;
                        let rollback_response = self
                            .send(
                                self.http
                                    .delete(self.object_url(&dest_ref.bucket, &dest_ref.object))
                                    .maybe_bearer_auth(token),
                            )
                            .await?;
                        ensure_success(rollback_response).await?;
                        Ok(())
                    })
                    .await;
                    if let Err(rollback) = rollback_outcome {
                        warn!(target: "ovstorage::gcs", "rename rollback failed: {rollback}");
                        // Rollback failed, so the destination survives
                        // alongside the source. Surfacing the delete error
                        // alone would hide that: it reads as "the rename did
                        // not happen" when a full copy is sitting at the
                        // destination.
                        return Err(Error::new(
                            ErrorCode::CommitAmbiguous,
                            format!(
                                "GCS rename copied to destination but failed to \
                                 delete source ({delete_error}), and could not \
                                 roll the destination back ({rollback})"
                            ),
                        )
                        .with_next_action(
                            "The object may exist at both addresses. Inspect \
                             both before deleting either one.",
                        ));
                    }
                    // Rollback succeeded: the destination is gone and the
                    // source is intact, so the original error describes the
                    // whole outcome.
                    return Err(delete_error);
                }
                Ok(())
            }
            .instrument(span),
        )
        .await
    }

    pub async fn update_metadata(
        &self,
        target: ResolvedTarget,
        opts: UpdateMetadataOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        reject_pinned_for_mutation(
            &target.resolved_address,
            "gcs update_metadata",
            PINNED_VERSION_KEYS,
        )?;
        let span = tracing::debug_span!(
            "gcs.update_metadata",
            op = "write",
            plugin = "gcs",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                require_version_only_if_match(opts.if_match.as_deref())?;
                let object = self.parse_target(&target, true)?;
                let mut metadata: serde_json::Map<String, serde_json::Value> =
                    serde_json::Map::new();
                for (key, value) in &opts.user_metadata_set {
                    metadata.insert(key.clone(), serde_json::Value::String(value.clone()));
                }
                for key in &opts.user_metadata_remove {
                    metadata.insert(key.clone(), serde_json::Value::Null);
                }
                if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                    metadata.insert(
                        OV_MESSAGE_KEY.into(),
                        serde_json::Value::String(message.to_string()),
                    );
                }
                let mut body = serde_json::Map::new();
                body.insert("metadata".into(), serde_json::Value::Object(metadata));
                let token = self.bearer_token().await?;
                let mut request = self
                    .http
                    .patch(self.object_url(&object.bucket, &object.object))
                    .maybe_bearer_auth(token)
                    .json(&body);
                if let Some(generation) = object.generation_selector() {
                    request = request.query(&[("generation", generation.as_str())]);
                }
                if let Some(version) = opts.if_match.as_deref() {
                    request = request.query(&[("ifGenerationMatch", version)]);
                }
                let response = self.send(request).await?;
                let object_resource: GcsObject = decode_json(response).await?;
                Ok(backend_item_info(parse_object(&object_resource)?))
            }
            .instrument(span),
        )
        .await
    }

    pub async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        race_cancel(cancel.as_ref(), async move {
            let object = self.parse_target(&target, false)?;
            let mut requested = Vec::new();
            if ops.read {
                requested.push("storage.objects.get");
            }
            if ops.write {
                requested.push("storage.objects.create");
            }
            if ops.delete {
                requested.push("storage.objects.delete");
            }
            if ops.update_metadata {
                requested.push("storage.objects.update");
            }
            if requested.is_empty() {
                return Ok(AccessDecision {
                    allowed: true,
                    denied_ops: AccessOps::default(),
                    reason: None,
                });
            }
            let url = format!(
                "{}/storage/v1/b/{}/{}",
                self.endpoint(),
                urlencoding::encode(&object.bucket),
                TEST_IAM_PERMISSIONS_PATH
            );
            let mut query: Vec<(&str, &str)> = Vec::new();
            for permission in &requested {
                query.push(("permissions", permission));
            }
            let token = self.bearer_token().await?;
            let request = self.http.get(url).query(&query).maybe_bearer_auth(token);
            let response = self.send(request).await?;
            let body: TestIamPermissionsResponse = decode_json(response).await?;
            let allowed: std::collections::HashSet<&str> =
                body.permissions.iter().map(|p| p.as_str()).collect();
            let mut denied = AccessOps::default();
            if ops.read && !allowed.contains("storage.objects.get") {
                denied.read = true;
            }
            if ops.write && !allowed.contains("storage.objects.create") {
                denied.write = true;
            }
            if ops.delete && !allowed.contains("storage.objects.delete") {
                denied.delete = true;
            }
            if ops.update_metadata && !allowed.contains("storage.objects.update") {
                denied.update_metadata = true;
            }
            let any_denied = denied.read || denied.write || denied.delete || denied.update_metadata;
            Ok(AccessDecision {
                allowed: !any_denied,
                denied_ops: denied,
                reason: None,
            })
        })
        .await
    }
}

impl GcsBackend {
    async fn download_bytes(
        &self,
        object: &GcsObjectRef,
        range_header: Option<&str>,
        if_generation_match: Option<&str>,
    ) -> Result<Vec<u8>> {
        let token = self.bearer_token().await?;
        let mut request = self
            .http
            .get(self.object_url(&object.bucket, &object.object))
            .query(&[("alt", "media")])
            .maybe_bearer_auth(token);
        if let Some(generation) = object.generation_selector() {
            request = request.query(&[("generation", generation.as_str())]);
        }
        if let Some(generation) = if_generation_match {
            request = request.query(&[("ifGenerationMatch", generation)]);
        }
        if let Some(range) = range_header {
            request = request.header(reqwest::header::RANGE, range);
        }
        let response = self.send(request).await?;
        let response = ensure_success(response).await?;
        response.bytes().await.map(|b| b.to_vec()).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("GCS download body read failed: {err}"),
            )
        })
    }

    /// Streaming counterpart to `download_bytes`: yields a stream of
    /// `bytes::Bytes` straight from reqwest's `bytes_stream()` — no
    /// `to_vec()` copy and no mpsc bridge.
    async fn download_stream(
        &self,
        object: &GcsObjectRef,
        if_generation_match: Option<&str>,
    ) -> Result<ovstorage_plugin::ReadStream> {
        use futures::StreamExt;
        let token = self.bearer_token().await?;
        let mut request = self
            .http
            .get(self.object_url(&object.bucket, &object.object))
            .query(&[("alt", "media")])
            .maybe_bearer_auth(token);
        if let Some(generation) = object.generation_selector() {
            request = request.query(&[("generation", generation.as_str())]);
        }
        if let Some(generation) = if_generation_match {
            request = request.query(&[("ifGenerationMatch", generation)]);
        }
        let response = self.send(request).await?;
        let response = ensure_success(response).await?;
        let stream = response.bytes_stream().map(|item| match item {
            Ok(bytes) => Ok(bytes),
            Err(err) => Err(Error::new(
                ErrorCode::Transient,
                format!("GCS streamed read: {err}"),
            )),
        });
        Ok(Box::pin(stream))
    }

    /// Single-shot multipart upload bundling JSON metadata + binary body.
    /// Used by the inline-write fast path for zero-byte and sub-threshold writes.
    async fn put_object_inline(
        &self,
        target: ResolvedTarget,
        object: GcsObjectRef,
        bytes: Vec<u8>,
        opts: WriteOptions,
    ) -> Result<WriteResult> {
        let token = self.bearer_token().await?;
        let mut metadata_payload = serde_json::Map::new();
        metadata_payload.insert(
            "name".into(),
            serde_json::Value::String(object.object.clone()),
        );
        let mut metadata_map = serde_json::Map::new();
        if let Some(user_metadata) = opts.user_metadata.as_ref() {
            for (key, value) in user_metadata {
                metadata_map.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }
        if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
            metadata_map.insert(
                OV_MESSAGE_KEY.into(),
                serde_json::Value::String(message.to_string()),
            );
        }
        if !metadata_map.is_empty() {
            metadata_payload.insert("metadata".into(), serde_json::Value::Object(metadata_map));
        }
        let mut query: Vec<(String, String)> = vec![
            ("uploadType".to_string(), "multipart".to_string()),
            ("name".to_string(), object.object.clone()),
        ];
        apply_write_preconditions(&mut query, &opts);

        // RFC 2046 multipart/related body: JSON metadata part, then binary body part.
        let boundary = format!("ovstorage_gcs_{}", short_random_hex());
        let metadata_json = serde_json::to_vec(&serde_json::Value::Object(metadata_payload))
            .map_err(|err| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to encode GCS multipart metadata: {err}"),
                )
            })?;
        let mut body: Vec<u8> = Vec::with_capacity(metadata_json.len() + bytes.len() + 256);
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        body.extend_from_slice(&metadata_json);
        body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let request = self
            .http
            .post(self.upload_url(&object.bucket))
            .query(&query)
            .maybe_bearer_auth(token)
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/related; boundary={boundary}"),
            )
            .body(body);
        let response = ensure_success(self.send(request).await?)
            .await
            .map_err(|err| precondition_to_already_exists(err, &opts.if_dest))?;
        let object_resource: GcsObject = decode_json(response).await?;
        let parsed = parse_object(&object_resource)?;
        let info = materialize_info(&target.resolved_address, parsed);
        Ok(WriteResult { info })
    }

    async fn initiate_resumable_redirect(
        &self,
        target: ResolvedTarget,
        object: GcsObjectRef,
        opts: WriteOptions,
    ) -> Result<WriteRedirectBatch> {
        let token = self.bearer_token().await?;
        let mut metadata_payload = serde_json::Map::new();
        metadata_payload.insert(
            "name".into(),
            serde_json::Value::String(object.object.clone()),
        );
        let mut metadata_map = serde_json::Map::new();
        if let Some(user_metadata) = opts.user_metadata.as_ref() {
            for (key, value) in user_metadata {
                metadata_map.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }
        if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
            metadata_map.insert(
                OV_MESSAGE_KEY.into(),
                serde_json::Value::String(message.to_string()),
            );
        }
        if !metadata_map.is_empty() {
            metadata_payload.insert("metadata".into(), serde_json::Value::Object(metadata_map));
        }
        let mut query: Vec<(String, String)> = vec![
            ("uploadType".to_string(), "resumable".to_string()),
            ("name".to_string(), object.object.clone()),
        ];
        apply_write_preconditions(&mut query, &opts);
        let mut request = self
            .http
            .post(self.upload_url(&object.bucket))
            .query(&query)
            .maybe_bearer_auth(token)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=UTF-8",
            )
            .json(&serde_json::Value::Object(metadata_payload));
        if let Some(size) = opts.size_hint {
            request = request.header("X-Upload-Content-Length", size.to_string());
        }
        let response = self.send(request).await?;
        let response = ensure_success(response)
            .await
            .map_err(|err| precondition_to_already_exists(err, &opts.if_dest))?;
        let session_url = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "GCS resumable upload response missing Location header",
                )
            })?;

        // Known size → host sets Content-Length, session commits at
        // end-of-body. Unknown → sentinel triggers chunked encoding and
        // GCS commits on end-of-stream.
        let advertised_len = opts.size_hint.unwrap_or(GCS_MAX_OBJECT_BYTES);
        let body_source = RedirectBodySource::UserBytes {
            offset: 0,
            len: advertised_len,
        };
        let request = HttpRequest {
            method: "PUT".to_string(),
            url: session_url.clone(),
            headers: vec![(
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            )],
        };
        let scope = RedirectScope {
            physical_url_prefix: trim_session_query(&session_url),
            operations: AccessOps {
                read: false,
                write: true,
                delete: false,
                update_metadata: false,
            },
            expires_at: SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 7),
            // The session URL GCS returned in `Location` authorizes uploads to
            // this one object through this one session, and nothing else the
            // connection can reach.
            credential: RedirectCredential::Request,
        };
        let result_capture = ResultCapture {
            headers: vec![
                "etag".into(),
                "x-goog-generation".into(),
                "x-goog-metageneration".into(),
                "x-goog-hash".into(),
            ],
            body_max_bytes: RESULT_CAPTURE_BODY_BYTES,
        };
        let redirect = WriteRedirect {
            request,
            body_source,
            result_capture,
            expires_at: scope.expires_at,
            scope,
            audit_id: format!("gcs-resumable-{}", short_random_hex()),
            policy_epoch: 0,
        };
        let continuation = ResumableContinuation {
            session_url,
            target_address: target.resolved_address.as_str().to_string(),
        };
        let continuation_bytes = serde_json::to_vec(&continuation).map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to encode GCS resumable continuation: {err}"),
            )
        })?;
        Ok(WriteRedirectBatch {
            continuation: continuation_bytes,
            redirects: vec![redirect],
        })
    }

    /// Streaming-resumable write for `Body::Stream`. Initiates a session
    /// without `X-Upload-Content-Length`, PUTs each non-final chunk
    /// 256-KiB-aligned with `Content-Range: bytes <s>-<e>/*`, and
    /// finalises with `Content-Range: bytes <s>-<e>/<total>`. Bypasses
    /// the host follower (which needs body length up front); memory is
    /// bounded by one chunk (~8 MiB).
    async fn stream_resumable_upload(
        &self,
        target: ResolvedTarget,
        object: GcsObjectRef,
        mut stream: ovstorage_plugin::BodyStream,
        opts: WriteOptions,
    ) -> Result<WriteStep> {
        const CHUNK_ALIGNMENT: usize = 256 * 1024;
        const STREAM_CHUNK_BYTES: usize = 32 * CHUNK_ALIGNMENT; // 8 MiB

        let token = self.bearer_token().await?;
        let mut metadata_payload = serde_json::Map::new();
        metadata_payload.insert(
            "name".into(),
            serde_json::Value::String(object.object.clone()),
        );
        let mut metadata_map = serde_json::Map::new();
        if let Some(user_metadata) = opts.user_metadata.as_ref() {
            for (key, value) in user_metadata {
                metadata_map.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }
        if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
            metadata_map.insert(
                OV_MESSAGE_KEY.into(),
                serde_json::Value::String(message.to_string()),
            );
        }
        if !metadata_map.is_empty() {
            metadata_payload.insert("metadata".into(), serde_json::Value::Object(metadata_map));
        }
        let mut query: Vec<(String, String)> = vec![
            ("uploadType".to_string(), "resumable".to_string()),
            ("name".to_string(), object.object.clone()),
        ];
        apply_write_preconditions(&mut query, &opts);
        let initiate = self
            .http
            .post(self.upload_url(&object.bucket))
            .query(&query)
            .maybe_bearer_auth(token)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/json; charset=UTF-8",
            )
            .json(&serde_json::Value::Object(metadata_payload));
        let response = ensure_success(self.send(initiate).await?)
            .await
            .map_err(|err| precondition_to_already_exists(err, &opts.if_dest))?;
        let session_url = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "GCS resumable upload response missing Location header",
                )
            })?;

        let mut buffer: Vec<u8> = Vec::with_capacity(STREAM_CHUNK_BYTES);
        let mut next_chunk: Option<Vec<u8>> = None;
        let mut bytes_uploaded: u64 = 0;

        let object_resource: GcsObject = loop {
            // Refill up to STREAM_CHUNK_BYTES; `next_chunk` carries
            // leftovers from the previous pull.
            while buffer.len() < STREAM_CHUNK_BYTES {
                let chunk = match next_chunk.take() {
                    Some(chunk) => chunk,
                    None => match stream.next() {
                        None => break,
                        Some(Ok(chunk)) => chunk,
                        Some(Err(err)) => return Err(err),
                    },
                };
                let want = STREAM_CHUNK_BYTES - buffer.len();
                if chunk.len() <= want {
                    buffer.extend_from_slice(&chunk);
                } else {
                    buffer.extend_from_slice(&chunk[..want]);
                    next_chunk = Some(chunk[want..].to_vec());
                }
            }
            let stream_drained = next_chunk.is_none() && buffer.len() < STREAM_CHUNK_BYTES;

            if stream_drained {
                // Final chunk: needs total length, any size allowed.
                let total = bytes_uploaded + buffer.len() as u64;
                let token = self.bearer_token().await?;
                let content_range = if buffer.is_empty() {
                    format!("bytes */{total}")
                } else {
                    format!(
                        "bytes {}-{}/{}",
                        bytes_uploaded,
                        bytes_uploaded + buffer.len() as u64 - 1,
                        total
                    )
                };
                let mut request = self
                    .http
                    .put(&session_url)
                    .maybe_bearer_auth(token)
                    .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                    .header("content-range", content_range);
                request = if buffer.is_empty() {
                    request.body(Vec::<u8>::new())
                } else {
                    request.body(std::mem::take(&mut buffer))
                };
                // The resumable session enforces the initiation-time
                // `ifGenerationMatch` at finalize, so the no-overwrite
                // refusal surfaces here.
                let response = ensure_success(self.send(request).await?)
                    .await
                    .map_err(|err| precondition_to_already_exists(err, &opts.if_dest))?;
                break decode_json::<GcsObject>(response).await?;
            }

            // GCS rejects the session if any non-final chunk is not a
            // 256-KiB multiple; STREAM_CHUNK_BYTES = 32 * CHUNK_ALIGNMENT.
            assert_eq!(
                buffer.len(),
                STREAM_CHUNK_BYTES,
                "GCS resumable intermediate chunk must be exactly STREAM_CHUNK_BYTES",
            );
            debug_assert!(
                buffer.len().is_multiple_of(CHUNK_ALIGNMENT),
                "GCS resumable intermediate chunk must be 256 KiB-aligned",
            );
            let payload_len = buffer.len();
            let payload = std::mem::take(&mut buffer);
            buffer.reserve(STREAM_CHUNK_BYTES);
            let token = self.bearer_token().await?;
            let content_range = format!(
                "bytes {}-{}/*",
                bytes_uploaded,
                bytes_uploaded + payload_len as u64 - 1
            );
            let request = self
                .http
                .put(&session_url)
                .maybe_bearer_auth(token)
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .header("content-range", content_range)
                .body(payload);
            let response = self.send(request).await?;
            // 308 Resume Incomplete = success for an intermediate chunk.
            if response.status().as_u16() != 308 {
                return Err(precondition_to_already_exists(
                    map_status_to_error(
                        response.status().as_u16(),
                        &response.text().await.unwrap_or_default(),
                    ),
                    &opts.if_dest,
                ));
            }
            bytes_uploaded += payload_len as u64;
        };

        let parsed = parse_object(&object_resource)?;
        let info = materialize_info(&target.resolved_address, parsed);
        Ok(WriteStep::Done(WriteResult { info }))
    }

    async fn put_marker(&self, object: &GcsObjectRef) -> Result<ParsedObject> {
        let token = self.bearer_token().await?;
        let query: Vec<(String, String)> = vec![
            ("uploadType".to_string(), "media".to_string()),
            ("name".to_string(), object.object.clone()),
        ];
        let request = self
            .http
            .post(self.upload_url(&object.bucket))
            .query(&query)
            .maybe_bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(Vec::<u8>::new());
        let response = self.send(request).await?;
        let object_resource: GcsObject = decode_json(response).await?;
        parse_object(&object_resource)
    }

    // True iff anything besides the marker itself exists under `prefix`.
    // Probe with maxResults=2 so a marker-only directory short-circuits.
    async fn has_descendants(&self, bucket: &str, prefix: &str) -> Result<bool> {
        let token = self.bearer_token().await?;
        let request = self
            .http
            .get(self.list_url(bucket))
            .query(&[("prefix", prefix), ("maxResults", "2")])
            .maybe_bearer_auth(token);
        let response = self.send(request).await?;
        let listing: GcsList = decode_json(response).await?;
        Ok(listing
            .items
            .iter()
            .any(|object| object.name.as_deref() != Some(prefix)))
    }

    async fn rewrite_object(
        &self,
        src: &GcsObjectRef,
        dst: &GcsObjectRef,
        opts: &CopyOptions,
    ) -> Result<ParsedObject> {
        let message_payload = opts
            .message
            .as_deref()
            .filter(|m| !m.is_empty())
            .map(|message| {
                let mut metadata_map = serde_json::Map::new();
                metadata_map.insert(
                    OV_MESSAGE_KEY.into(),
                    serde_json::Value::String(message.to_string()),
                );
                let mut body = serde_json::Map::new();
                body.insert("metadata".into(), serde_json::Value::Object(metadata_map));
                serde_json::Value::Object(body)
            });
        let mut rewrite_token: Option<String> = None;
        loop {
            let token = self.bearer_token().await?;
            let mut request = self
                .http
                .post(self.rewrite_url(&src.bucket, &src.object, &dst.bucket, &dst.object))
                .maybe_bearer_auth(token);
            // GCS rewrite accepts target metadata only on the first call;
            // resumed calls (with rewriteToken) must keep the empty body.
            request = match (rewrite_token.as_ref(), message_payload.as_ref()) {
                (None, Some(body)) => request
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/json; charset=UTF-8",
                    )
                    .json(body),
                _ => request.header(reqwest::header::CONTENT_LENGTH, "0"),
            };
            if let Some(precondition) = opts.if_source.as_deref() {
                request = request.query(&[("ifSourceGenerationMatch", precondition)]);
            }
            match &opts.if_dest {
                IfDestExists::Overwrite => {}
                IfDestExists::Fail => {
                    request = request.query(&[("ifGenerationMatch", "0")]);
                }
                IfDestExists::MatchEtag(generation) => {
                    request = request.query(&[("ifGenerationMatch", generation.as_str())]);
                }
            }
            if let Some(generation) = src.generation_selector() {
                request = request.query(&[("sourceGeneration", generation.as_str())]);
            }
            if let Some(token) = rewrite_token.as_ref() {
                request = request.query(&[("rewriteToken", token.as_str())]);
            }
            let response = self.send(request).await?;
            let body: RewriteResponse = decode_json(response).await.map_err(|err| {
                // Rewrite's `ifGenerationMatch=0` no-overwrite refusal is the
                // exists-refusal contract on the copy/rename path;
                // with a source precondition also on the wire the 412 cannot
                // be attributed, so it keeps `PreconditionFailed`.
                if opts.if_source.is_none() {
                    precondition_to_already_exists(err, &opts.if_dest)
                } else {
                    err
                }
            })?;
            if body.done {
                let resource = body.resource.ok_or_else(|| {
                    Error::new(
                        ErrorCode::Internal,
                        "GCS rewrite reported done with no resource",
                    )
                })?;
                return parse_object(&resource);
            }
            rewrite_token = body.rewrite_token;
            if rewrite_token.is_none() {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "GCS rewrite did not finish and returned no rewriteToken",
                ));
            }
        }
    }
}

/// Continuation for a resumable session. Note what is *not* here: a derivable
/// object identity. `session_url` is issued by GCS and names the object on its
/// own, so `continue_write` cannot recompute it from the request address the
/// way the other adopters recompute a key. `target_address` is a recorded copy
/// of the address at mint time; see `continue_write` for what comparing it does
/// and does not establish.
///
/// Load-bearing context for anyone who later changes the authorization gate:
/// the session is initiated with **this backend's own GCS credential**
/// (`initiate_resumable_redirect` → `self.bearer_token()`), not the caller's, so
/// GCS never re-checks the caller against the object. The only thing standing
/// between a caller and a session for some object is the host's `Operation::Write`
/// check on `write_redirect`'s request address. Holding a genuine `session_url`
/// for an object therefore means having been authorized for that object, and the
/// rewritten-continuation residual is not a privilege escalation *because of
/// that gate* — weaken it and the residual becomes one. This also assumes the
/// GCS-issued upload id is unguessable, which is a provider property and is not
/// established anywhere in this repository.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResumableContinuation {
    session_url: String,
    target_address: String,
}

fn directory_marker_name(prefix: &str) -> String {
    if prefix.is_empty() {
        return "/".to_string();
    }
    if prefix.ends_with('/') {
        prefix.to_string()
    } else {
        format!("{prefix}/")
    }
}

fn relative_key_for(prefix: &str, full_name: &str) -> String {
    if prefix.is_empty() {
        return full_name.to_string();
    }
    full_name
        .strip_prefix(prefix)
        .map(|s| s.to_string())
        .unwrap_or_else(|| full_name.to_string())
}

fn generation_address(addr: &Url, generation: &str) -> Result<Url> {
    let mut base = addr.clone();
    base.set_query(None);
    base.set_fragment(None);
    address::with_query_pair(&base, "generation", generation)
}

/// Open-ended range emits `bytes=start-` so GCS returns through
/// end-of-object. Rejects inverted ranges (`end_inclusive < start`)
/// with `InvalidArgument` so an inverted slice can't panic the
/// host-side follower — a clean typed error instead of a
/// `catch_unwind`-converted `Internal`.
fn read_range_header(range: Option<&ovstorage_plugin::ByteRange>) -> Result<Option<String>> {
    let Some(r) = range else {
        return Ok(None);
    };
    if let Some(end) = r.end_inclusive
        && end < r.start
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "gcs read: inverted byte range start={} end_inclusive={}",
                r.start, end,
            ),
        ));
    }
    let end = r.end_inclusive.map(|e| e.to_string()).unwrap_or_default();
    Ok(Some(format!("bytes={}-{}", r.start, end)))
}

fn trim_session_query(url: &str) -> String {
    url.split_once('?')
        .map(|(prefix, _)| prefix.to_string())
        .unwrap_or_else(|| url.to_string())
}

/// `credential` is decided by the caller's auth branch: the public-bucket URL
/// carries nothing, the service-account URL is V4-signed over this object and
/// this method.
fn read_redirect(
    url: String,
    host: String,
    extra_headers: Vec<(String, String)>,
    credential: RedirectCredential,
) -> ReadRedirect {
    // V4 only signs `host`; other headers (notably `Range`) pass through
    // unsigned. Generation/etag preconditions ride in the signed query.
    let mut headers = Vec::with_capacity(1 + extra_headers.len());
    headers.push(("host".into(), host));
    headers.extend(extra_headers);
    let request = HttpRequest {
        method: "GET".to_string(),
        url: url.clone(),
        headers,
    };
    // `x-goog-hash` is a multi-value composite (repeated headers or a
    // single comma-separated value, each tagged `crc32c=` / `md5=`).
    // The host's `StreamingVerifier` and result propagator special-case
    // it: verifier uses `content_checksum_algorithm` (crc32c — md5 is
    // weak, sha256 isn't produced by GCS), propagator lifts both values
    // into `ObjectInfo.checksums`.
    let mut checksum_headers = std::collections::HashMap::new();
    checksum_headers.insert(ChecksumAlgorithm::crc32c(), "x-goog-hash".into());
    checksum_headers.insert(ChecksumAlgorithm::md5(), "x-goog-hash".into());
    let response_parsing = ResponseParsing {
        // GCS interprets the SPI `if_match` etag as a numeric generation
        // (`ifGenerationMatch=<n>`), and `parse_object` in the
        // non-redirect path returns `etag = generation`. Pin the
        // redirect's etag to the same surface (`x-goog-generation`) so
        // a `stat -> read -> if_match=info.etag` round-trip stays
        // generation-shaped; HTTP `ETag` is a separate value that would
        // be rejected as a precondition token.
        etag_header: Some("x-goog-generation".into()),
        version_header: Some("x-goog-generation".into()),
        size_header: Some("content-length".into()),
        mtime_header: Some("last-modified".into()),
        mtime_format: MtimeFormat::Rfc1123,
        system_metadata_headers: vec![
            "etag".into(),
            "x-goog-metageneration".into(),
            "x-goog-storage-class".into(),
            "x-goog-stored-content-encoding".into(),
            "x-goog-hash".into(),
        ],
        content_checksum_header: Some("x-goog-hash".into()),
        content_checksum_algorithm: Some(ChecksumAlgorithm::crc32c()),
        checksum_headers,
    };
    let expires_at = SystemTime::now() + Duration::from_secs(DEFAULT_EXPIRY_SECONDS);
    let scope = RedirectScope {
        physical_url_prefix: trim_session_query(&url),
        operations: AccessOps {
            read: true,
            write: false,
            delete: false,
            update_metadata: false,
        },
        expires_at,
        credential,
    };
    ReadRedirect {
        request,
        response_parsing,
        expires_at,
        scope,
        audit_id: format!("gcs-signed-get-{}", short_random_hex()),
        policy_epoch: 0,
    }
}

fn apply_write_preconditions(query: &mut Vec<(String, String)>, opts: &WriteOptions) {
    match &opts.if_dest {
        IfDestExists::Overwrite => {}
        IfDestExists::Fail => {
            query.push(("ifGenerationMatch".to_string(), "0".to_string()));
        }
        IfDestExists::MatchEtag(generation) => {
            query.push(("ifGenerationMatch".to_string(), generation.clone()));
        }
    }
}

fn materialize_info(addr: &Url, parsed: ParsedObject) -> ObjectInfo {
    ObjectInfo {
        address: addr.clone(),
        // GCS is flat; per-object infos carry no directory shape.
        kind: ObjectKind::File,
        etag: parsed.etag,
        version: parsed.version,
        size: parsed.size,
        mtime: parsed.mtime,
        checksums: parsed.checksums,
        effective_permissions: None,
        system_metadata: if parsed.system_metadata.is_empty() {
            None
        } else {
            Some(parsed.system_metadata)
        },
        user_metadata: if parsed.user_metadata.is_empty() {
            None
        } else {
            Some(parsed.user_metadata)
        },
        modified_by: None,
    }
}

fn inferred_directory_info(addr: &Url) -> ObjectInfo {
    ObjectInfo {
        address: addr.clone(),
        kind: ObjectKind::DirectoryInferred,
        etag: None,
        version: None,
        size: None,
        mtime: None,
        checksums: ChecksumSet::new(),
        effective_permissions: None,
        system_metadata: None,
        user_metadata: None,
        modified_by: None,
    }
}

fn backend_item_info(parsed: ParsedObject) -> BackendItemInfo {
    BackendItemInfo {
        // Object entries only; subdirectory entries come from common-prefix paths.
        kind: ObjectKind::File,
        etag: parsed.etag,
        version: parsed.version,
        size: parsed.size,
        mtime: parsed.mtime,
        checksums: parsed.checksums,
        effective_permissions: None,
        system_metadata: if parsed.system_metadata.is_empty() {
            None
        } else {
            Some(parsed.system_metadata)
        },
        user_metadata: if parsed.user_metadata.is_empty() {
            None
        } else {
            Some(parsed.user_metadata)
        },
        modified_by: None,
    }
}

/// Record what `response` says about `auth`'s credential.
///
/// A refusal condemns the credential for everyone signing through it, so it
/// goes to the authenticator's connection-wide epoch; an acceptance vindicates
/// only the operation that earned it, so it goes to that operation's task-local
/// sink. Anonymous connections record neither — there is no credential to
/// prove, and an unsigned 200 must not report one.
///
/// Judged from the status and headers alone, before the body is read: the
/// service has already delivered its answer at this point, and a body that
/// fails mid-stream must not discard it. Losing a REFUSAL is the dangerous
/// half — a multi-request operation whose first request was accepted and whose
/// second was refused with a truncated body would look like an operation with
/// an acceptance and no refusal.
fn note_promotion_evidence(
    auth: &Authenticator,
    bearer_survived: bool,
    response: &reqwest::Response,
) {
    // An anonymous connection has no credential to prove or to condemn, so an
    // unsigned response is evidence about neither.
    if auth.is_anonymous() {
        return;
    }
    let status = response.status().as_u16();
    // Judge in NEITHER direction an answer the credential did not reach. A hop
    // that changed host or port took the `Authorization` header with it and
    // reqwest never restores it, so a chain that returns to the configured
    // endpoint still delivers a 200 fetched with no credential at all — and, the
    // other way round, a redirect target wanting its own auth answers 401 to a
    // request it was never given a bearer for. Counting that as a refusal would
    // condemn the connection on every request, which is worse than the promotion
    // it was protecting. A SAME-origin redirect keeps the bearer, so its verdict
    // is ours and is judged normally.
    if !bearer_survived {
        tracing::debug!(
            plugin = "gcs",
            status,
            "gcs: a redirect stripped this request's credential; recording no \
             evidence in either direction"
        );
        return;
    }
    if promotion::vetoes_promotion(status) {
        auth.note_refusal();
        return;
    }
    if promotion::proves_credentials(status, response.headers(), || {
        auth.claim_unstamped_warning()
    }) {
        promotion::credit_operation_acceptance();
    }
}

async fn decode_json<T: for<'de> serde::Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T> {
    let response = ensure_success(response).await?;
    let body = response.text().await.map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("GCS response body read failed: {err}"),
        )
    })?;
    serde_json::from_str(&body).map_err(|err| {
        // Only the error's classification and position are reported, never its
        // `Display`: on a type mismatch serde renders the offending value
        // verbatim (`invalid type: string "…"`), which would put a slice of the
        // provider response back into the message this module exists to keep it
        // out of.
        Error::new(
            ErrorCode::Internal,
            format!(
                "GCS response was not JSON: {}",
                crate::error_body::decode_failure(&err, body.len())
            ),
        )
    })
}

async fn decode_object(response: reqwest::Response) -> Result<GcsObject> {
    decode_json(response).await
}

async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response.text().await.unwrap_or_default();
    Err(map_status_to_error(status.as_u16(), &body))
}

fn is_status_success(status_code: u16) -> bool {
    (200..300).contains(&status_code)
}

fn map_status_to_error(status: u16, body: &str) -> Error {
    // The body never reaches the message; only the allowlisted provider code does.
    let detail = provider_detail(body);
    // 401 → AuthRequired (host invalidates creds + retries once);
    // 403 → PermissionDenied (final, principal lacks IAM permission).
    if status == 401 {
        return Error::new(
            ErrorCode::AuthRequired,
            format!("GCS request requires authentication (HTTP 401): {detail}"),
        )
        .with_context(ErrorContext::Auth {
            connection_id: ConnectionId(String::new()),
            reason: Some("gcs_unauthorized".into()),
            expired_at: None,
        });
    }
    let code = match status {
        403 => ErrorCode::PermissionDenied,
        404 | 410 => ErrorCode::NotFound,
        409 => ErrorCode::Conflict,
        412 => ErrorCode::PreconditionFailed,
        416 => ErrorCode::InvalidArgument,
        // match-arm order matters: 408/504 + 429/503 must precede the 500..=599 catchall.
        408 | 504 => ErrorCode::DeadlineExceeded,
        429 | 503 => ErrorCode::ResourceExhausted,
        500..=599 => ErrorCode::Transient,
        _ => ErrorCode::Transient,
    };
    Error::new(code, format!("GCS returned HTTP {status}: {detail}"))
}

// SPI: a mutation with `IfDestExists::Fail` refused because the
// destination exists surfaces `AlreadyExists` (the documented contract).
// GCS signals the refusal as HTTP 412 on the `ifGenerationMatch=0`
// query, so remap here; a genuine generation precondition (`MatchEtag`)
// keeps `PreconditionFailed`. Callers whose op also carries a source
// precondition (rewrite's `ifSourceGenerationMatch`) must guard the call
// themselves — a combined 412 cannot be attributed.
fn precondition_to_already_exists(err: Error, if_dest: &IfDestExists) -> Error {
    if matches!(if_dest, IfDestExists::Fail) && err.code() == ErrorCode::PreconditionFailed {
        return Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "GCS refused: destination already exists and IfDestExists::Fail was \
                 requested ({})",
                err.message()
            ),
        );
    }
    err
}

// SPI: read with if_match returns ObjectModified on a precondition mismatch
// (PreconditionFailed is reserved for write/update_metadata).
fn read_precondition_to_modified(err: Error, opts: &ReadOptions) -> Error {
    if opts.if_match.is_some() && err.code() == ErrorCode::PreconditionFailed {
        return Error::new(ErrorCode::ObjectModified, err.message().to_string());
    }
    err
}

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(HTTP_USER_AGENT)
        .timeout(Duration::from_secs(30))
        // Redirects are still followed exactly as before; the policy only
        // OBSERVES them, recording the hop that costs the request its bearer so
        // the promotion rule can decline to judge an answer the credential did
        // not earn. reqwest drops `Authorization` when host or port changes
        // (`redirect::remove_sensitive_headers`) and never restores it, so the
        // same test decides it here.
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if let Some(previous) = attempt.previous().last()
                && (previous.host_str() != attempt.url().host_str()
                    || previous.port_or_known_default() != attempt.url().port_or_known_default())
            {
                promotion::note_bearer_stripped();
            }
            // Matches `Policy::limited(10)`, the default this replaces, in both
            // respects: it follows ten hops and FAILS on the eleventh rather
            // than handing the caller an unfollowed `3xx` that would flow on
            // into body parsing.
            if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|err| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to build GCS HTTP client: {err}"),
            )
        })
}

fn short_random_hex() -> String {
    use sha2::{Digest, Sha256};
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(now.to_le_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

#[derive(Clone, Debug)]
pub struct GcsConnectionConfig {
    bucket: String,
    address_root: Url,
    endpoint: Option<String>,
    pubsub_endpoint: Option<String>,
    pubsub_subscription: Option<String>,
    pubsub_pull_max: u32,
}

impl GcsConnectionConfig {
    fn from_request(request: &ConnectionRequest) -> Result<Self> {
        let bucket = required_text(&request.config, "bucket")?;
        validate_bucket(&bucket)?;
        let _project_id = optional_text(&request.config, "project_id")?;
        let _service_account = optional_text(&request.config, "service_account")?;
        let endpoint = optional_url(&request.config, "endpoint")?
            .map(|address| address.as_str().trim_end_matches('/').to_string());
        let pubsub_endpoint =
            optional_loopback_url(&request.config, &request.credentials, "pubsub_endpoint")?
                .map(|address| address.trim_end_matches('/').to_string());
        let pubsub_subscription = optional_text(&request.config, "pubsub_subscription")?;
        if let Some(subscription) = pubsub_subscription.as_deref() {
            validate_pubsub_subscription(subscription)?;
        }
        let pubsub_pull_max =
            optional_int(&request.config, "pubsub_pull_max", 1, 1000)?.unwrap_or(100) as u32;
        validate_credentials(&request.credentials)?;
        let address_root = address::parse(&format!("gs://{bucket}/"))?;
        Ok(Self {
            bucket,
            address_root,
            endpoint,
            pubsub_endpoint,
            pubsub_subscription,
            pubsub_pull_max,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GcsObjectRef {
    bucket: String,
    object: String,
    selector: Option<String>,
}

impl GcsObjectRef {
    fn generation_selector(&self) -> Option<String> {
        let selector = self.selector.as_deref()?;
        let stripped = selector.strip_prefix('?').unwrap_or(selector);
        for pair in stripped.split('&') {
            if let Some(value) = pair.strip_prefix("generation=") {
                let end = value.find('#').unwrap_or(value.len());
                return Some(value[..end].to_string());
            }
        }
        None
    }
}

fn parse_gcs_address(addr: &Url) -> Result<GcsObjectRef> {
    if addr.scheme() != "gs" {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS backend requires gs:// addresses",
        ));
    }
    // The bucket is the parsed host, not a slice of the serialized authority.
    // Slicing takes userinfo and a port with it, and those are exactly the
    // components on which the backend must agree with the authorization
    // matcher: the matcher keys on `(scheme, host, port)` and ignores userinfo
    // entirely, so a backend deriving a bucket from a different set of
    // components either rejects addresses the matcher allows or serves two
    // scopes the matcher ranks apart.
    let bucket = addr.host_str().unwrap_or_default();
    if bucket.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS bucket is empty",
        ));
    }
    if addr.port().is_some() {
        // A port makes two addresses distinct scopes to the matcher while
        // naming one bucket here. Refuse rather than let the two disagree: a
        // GCS address has no port to carry.
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS address must not carry a port",
        ));
    }
    // The selector is the parsed query. `canonicalize` has already stripped any
    // fragment, so there is nothing left to cut the string at.
    let selector = addr.query();
    // The object name is the DECODED path. Slicing the serialized address gives
    // the wrong name: the canonical form still escapes space, controls and `%`,
    // so `gs://b/pub%20x` sliced raw asks GCS for an object named `pub%20x`.
    //
    // `key_utf8` rather than `key`: the name goes into the JSON API URL path,
    // which is a `&str`, so a name outside UTF-8 is refused rather than
    // collapsed onto a different object.
    let object = address::key_utf8(addr)?;
    validate_object_name(&object)?;
    Ok(GcsObjectRef {
        bucket: bucket.to_string(),
        object,
        selector: selector.map(str::to_string),
    })
}

fn validate_object_name(object: &str) -> Result<()> {
    if matches!(object, "." | "..") {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS object name must not be exactly '.' or '..'",
        ));
    }
    Ok(())
}

fn validate_bucket(bucket: &str) -> Result<()> {
    if bucket.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS bucket config must not be empty",
        ));
    }
    if bucket != bucket.trim()
        || bucket.contains(['/', '\\', '?', '#', '@'])
        || bucket.chars().any(|ch| ch.is_ascii_uppercase())
    {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "GCS bucket config must be a lowercase bucket name, not a URL or path",
        ));
    }
    Ok(())
}

fn validate_pubsub_subscription(subscription: &str) -> Result<()> {
    let parts: Vec<_> = subscription.split('/').collect();
    if parts.len() == 4
        && parts[0] == "projects"
        && !parts[1].is_empty()
        && parts[2] == "subscriptions"
        && !parts[3].is_empty()
    {
        return Ok(());
    }
    Err(Error::new(
        ErrorCode::InvalidArgument,
        "GCS pubsub_subscription must be projects/{project}/subscriptions/{subscription}",
    ))
}

fn validate_credentials(credentials: &SecretBundle) -> Result<()> {
    for (key, value) in &credentials.fields {
        match key.as_str() {
            "service_account_key" => {
                let bytes = match value {
                    SecretValue::Bytes(b) | SecretValue::File(b) => b.as_bytes(),
                    _ => {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            "GCS credential field 'service_account_key' must be secret bytes or a file",
                        ));
                    }
                };
                // Reject malformed creds at update time, not on first token call.
                auth::parse_credentials_json(bytes)?;
            }
            "file_path" => match value {
                SecretValue::Bytes(_) | SecretValue::File(_) => {}
                _ => {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "GCS credential field 'file_path' must be a text value",
                    ));
                }
            },
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("unsupported GCS credential field '{key}'"),
                ));
            }
        }
    }
    Ok(())
}

fn required_text(config: &HashMap<String, ConfigValue>, key: &str) -> Result<String> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(value.trim().to_string())
        }
        Some(ConfigValue::String(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must not be empty"),
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must be text"),
        )),
        None => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("missing required GCS connection config '{key}'"),
        )),
    }
}

fn optional_text(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(value.trim().to_string()))
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must be text"),
        )),
    }
}

fn optional_url(config: &HashMap<String, ConfigValue>, key: &str) -> Result<Option<Url>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            Ok(Some(address::parse(value.trim())?))
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must be a URL string"),
        )),
    }
}

fn optional_loopback_url(
    config: &HashMap<String, ConfigValue>,
    credentials: &SecretBundle,
    key: &str,
) -> Result<Option<String>> {
    match config.get(key) {
        Some(ConfigValue::String(value)) if !value.trim().is_empty() => {
            if !credentials.fields.is_empty() {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "GCS connection config '{key}' is only supported for anonymous loopback tests"
                    ),
                ));
            }
            let value = value.trim();
            let parsed = Url::parse(value).map_err(|err| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!("GCS connection config '{key}' must be an absolute URL: {err}"),
                )
            })?;
            if matches!(parsed.scheme(), "http" | "https") && url_host_is_loopback(&parsed) {
                Ok(Some(value.to_string()))
            } else {
                Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "GCS connection config '{key}' is only supported for loopback test endpoints"
                    ),
                ))
            }
        }
        Some(ConfigValue::String(_)) | None => Ok(None),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must be a URL string"),
        )),
    }
}

fn url_host_is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.parse::<std::net::IpAddr>()
        .map(|addr| addr.is_loopback())
        .unwrap_or(false)
}

fn optional_int(
    config: &HashMap<String, ConfigValue>,
    key: &str,
    min: i64,
    max: i64,
) -> Result<Option<i64>> {
    match config.get(key) {
        Some(ConfigValue::Int(value)) if *value >= min && *value <= max => Ok(Some(*value)),
        Some(ConfigValue::Int(_)) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must be between {min} and {max}"),
        )),
        Some(_) => Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("GCS connection config '{key}' must be an integer"),
        )),
        None => Ok(None),
    }
}

fn gcs_capabilities(config: &GcsConnectionConfig) -> Capabilities {
    let supports_watch_directory = config.pubsub_subscription.is_some();
    Capabilities {
        supports_if_match_write: true,
        supports_no_overwrite_write: true,
        supports_native_metadata_patch: true,
        supports_metadata_rewrite_emulation: false,
        writes_are_atomic: true,
        supports_copy: true,
        supports_rename: true,
        supports_write: true,
        supports_write_stream: true,
        supports_write_redirect: true,
        supports_delete: true,
        supports_server_side_copy: true,
        supports_server_side_rename: false,
        supports_atomic_rename: false,
        has_real_directories: false,
        supports_list: true,
        wants_list_backed_stat: true,
        supports_recursive_list: true,
        supports_create_directory: true,
        supports_delete_directory: true,
        populates_subdirectory_metadata: false,
        supports_version_listing: true,
        version_list_order: Some(VersionListOrder::Newest),
        populates_effective_permissions_on_stat: false,
        supports_access_check: true,
        supports_watch_directory,
        watch_directory_kinds: if supports_watch_directory {
            ChangeKindSet {
                created: true,
                modified: false,
                deleted: true,
                metadata_changed: true,
            }
        } else {
            ChangeKindSet::empty()
        },
        watch_directory_resumable: false,
        watch_directory_max_lag: supports_watch_directory.then_some(Duration::from_secs(30)),
        redirect_size_threshold: None,
    }
}

fn text_field(
    key: &str,
    display_name: &str,
    required: bool,
    example: Option<&str>,
    help: Option<&str>,
    advanced: bool,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Text,
        required,
        default: None,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("provider".into()),
        advanced,
    }
}

fn url_field(
    key: &str,
    display_name: &str,
    required: bool,
    example: Option<&str>,
    help: Option<&str>,
    advanced: bool,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Url,
        required,
        default: None,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("provider".into()),
        advanced,
    }
}

fn watch_text_field(
    key: &str,
    display_name: &str,
    example: Option<&str>,
    help: Option<&str>,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Text,
        required: false,
        default: None,
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("watch".into()),
        advanced: true,
    }
}

fn watch_int_field(
    key: &str,
    display_name: &str,
    default: Option<i64>,
    help: Option<&str>,
    example: Option<&str>,
) -> ConfigField {
    ConfigField {
        key: key.into(),
        display_name: display_name.into(),
        kind: ConfigFieldKind::Integer,
        required: false,
        default: default.map(ConfigValue::Int),
        help: help.map(str::to_string),
        example: example.map(str::to_string),
        group: Some("watch".into()),
        advanced: true,
    }
}

pub use crate::layer::GcsLayerFactory;

/// Test-only parser hook; not part of the published surface.
#[doc(hidden)]
pub fn __test_only_parse_config(
    config: &HashMap<String, ConfigValue>,
) -> Result<GcsConnectionConfig> {
    GcsConnectionConfig::from_request(&ConnectionRequest {
        backend_kind: "gcs".into(),
        config: config.clone(),
        credentials: SecretBundle::default(),
        persist: false,
        display_name: None,
    })
}

/// Test-only constructor hook; lets integration tests build a backend from a
/// parsed config and an explicit credentials bundle (typically
/// `SecretBundle::default()` for anonymous access against a fake server).
#[doc(hidden)]
pub fn __test_only_backend(
    config: GcsConnectionConfig,
    credentials: SecretBundle,
) -> Result<GcsBackend> {
    let http = build_http_client()?;
    let authenticator = Arc::new(Authenticator::new(&credentials, http.clone())?);
    Ok(GcsBackend::new(config, http, authenticator))
}

ovstorage_plugin::ovstorage_layer_plugin!(backend, GcsLayerFactory::default);

#[cfg(test)]
mod tests {
    use super::*;
    fn request(bucket: &str) -> ConnectionRequest {
        let mut config = HashMap::new();
        config.insert("bucket".into(), ConfigValue::String(bucket.into()));
        config.insert(
            "project_id".into(),
            ConfigValue::String("example-project".into()),
        );
        config.insert(
            "service_account".into(),
            ConfigValue::String("storage-reader@example-project.iam.gserviceaccount.com".into()),
        );
        config.insert(
            "endpoint".into(),
            ConfigValue::String("https://storage.googleapis.com".into()),
        );
        ConnectionRequest {
            backend_kind: "gcs".into(),
            config,
            credentials: SecretBundle::default(),
            persist: false,
            display_name: None,
        }
    }

    #[test]
    fn descriptor_reports_native_gcs_schema() {
        use ovstorage_plugin::BackendFactory as _;
        let descriptor = GcsLayerFactory::default().descriptor();
        assert_eq!(descriptor.kind, "gcs");
        assert_eq!(descriptor.display_name, "Google Cloud Storage");
        assert!(descriptor.accepts_connections);
        assert_eq!(
            descriptor
                .config_schema
                .iter()
                .map(|field| field.key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "bucket",
                "project_id",
                "service_account",
                "endpoint",
                "pubsub_subscription",
                "pubsub_pull_max",
            ]
        );
        assert_eq!(
            descriptor
                .credential_schema
                .iter()
                .map(|field| field.key.as_str())
                .collect::<Vec<_>>(),
            vec!["service_account_key", "file_path"]
        );
    }

    async fn layer_root_caps(req: &ConnectionRequest) -> ovstorage_plugin::Capabilities {
        use ovstorage_plugin::{BackendFactory as _, LayerConnectionRequest, Request, address};
        let layer = GcsLayerFactory::default()
            .create_backend("gcs", &ovstorage_plugin::LayerConfig::new(), None)
            .await
            .unwrap();
        layer
            .add_connection(
                Request::new(LayerConnectionRequest {
                    target: "gcs".into(),
                    connection: req.clone(),
                }),
                None,
            )
            .await
            .unwrap();
        layer
            .root_info_for(
                &address::parse(&format!("gs://{}/x", "asset-bucket")).unwrap(),
                &ovstorage_plugin::Extensions::new(),
                None,
            )
            .await
            .unwrap()
            .capabilities
    }

    #[tokio::test]
    async fn add_connection_reports_native_capabilities() {
        let caps = layer_root_caps(&request("asset-bucket")).await;
        assert!(caps.supports_native_metadata_patch);
        assert!(!caps.supports_watch_directory);
    }

    #[tokio::test]
    async fn add_connection_reports_watch_capabilities_when_pubsub_is_configured() {
        let mut req = request("asset-bucket");
        req.config.insert(
            "pubsub_subscription".into(),
            ConfigValue::String("projects/example/subscriptions/assets-watch".into()),
        );
        let caps = &layer_root_caps(&req).await;
        assert!(caps.supports_watch_directory);
        assert!(caps.watch_directory_kinds.created);
        assert!(!caps.watch_directory_kinds.modified);
        assert!(caps.watch_directory_kinds.deleted);
        assert!(caps.watch_directory_kinds.metadata_changed);
        assert!(!caps.watch_directory_resumable);
        assert_eq!(caps.watch_directory_max_lag, Some(Duration::from_secs(30)));
    }

    #[test]
    fn hidden_pubsub_endpoint_override_is_loopback_only() {
        let mut req = request("asset-bucket");
        req.config.insert(
            "pubsub_endpoint".into(),
            ConfigValue::String("https://pubsub.invalid.example".into()),
        );
        let err = GcsConnectionConfig::from_request(&req).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("loopback"));

        req.config.insert(
            "pubsub_endpoint".into(),
            ConfigValue::String("http://127.0.0.1:8085".into()),
        );
        let config = GcsConnectionConfig::from_request(&req).unwrap();
        assert_eq!(
            config.pubsub_endpoint.as_deref(),
            Some("http://127.0.0.1:8085")
        );

        req.credentials.fields.insert(
            "file_path".into(),
            SecretValue::Bytes(SecretBytes(b"adc.json".to_vec())),
        );
        let err = GcsConnectionConfig::from_request(&req).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert!(err.message().contains("anonymous"));
    }

    #[test]
    fn parser_extracts_object_path_and_selector() {
        // `address::parse` canonicalizes before this parser sees the input: dot
        // segments resolve, percent-escapes decode — so `%2F` arrives as a real
        // separator — and the fragment is gone, which is why the selector below
        // carries none. The selector is the parsed query, so it carries no
        // leading `?` either.
        let parsed = parse_gcs_address(
            &address::parse("gs://asset-bucket/a//../b.%2F?generation=7&x=y#frag").unwrap(),
        )
        .unwrap();
        assert_eq!(
            parsed,
            GcsObjectRef {
                bucket: "asset-bucket".into(),
                object: "a/b./".into(),
                selector: Some("generation=7&x=y".into()),
            }
        );
        assert_eq!(parsed.generation_selector().as_deref(), Some("7"));
    }

    #[test]
    fn directory_marker_appends_trailing_slash() {
        assert_eq!(directory_marker_name(""), "/");
        assert_eq!(directory_marker_name("foo"), "foo/");
        assert_eq!(directory_marker_name("foo/"), "foo/");
    }

    #[test]
    fn relative_key_strips_prefix() {
        assert_eq!(relative_key_for("dir/", "dir/file.txt"), "file.txt");
        assert_eq!(relative_key_for("", "file.txt"), "file.txt");
    }

    #[test]
    fn map_status_to_error_translates_common_gcs_codes() {
        assert_eq!(map_status_to_error(404, "").code(), ErrorCode::NotFound);
        assert_eq!(map_status_to_error(410, "").code(), ErrorCode::NotFound);
        assert_eq!(
            map_status_to_error(412, "").code(),
            ErrorCode::PreconditionFailed
        );
        assert_eq!(
            map_status_to_error(416, "").code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_status_to_error(408, "").code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            map_status_to_error(504, "").code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            map_status_to_error(429, "").code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            map_status_to_error(503, "").code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(map_status_to_error(500, "").code(), ErrorCode::Transient);
        assert_eq!(map_status_to_error(502, "").code(), ErrorCode::Transient);
        // Non-classified statuses surface as Transient (proxy/gateway weirdness),
        // never Internal — Internal is reserved for plugin-detected logic bugs.
        assert_eq!(map_status_to_error(418, "").code(), ErrorCode::Transient);
    }

    #[test]
    fn map_status_to_error_401_is_auth_required_with_context() {
        let err = map_status_to_error(401, "token expired or revoked");
        assert_eq!(err.code(), ErrorCode::AuthRequired);
        match err.context() {
            Some(ErrorContext::Auth {
                reason, expired_at, ..
            }) => {
                assert_eq!(reason.as_deref(), Some("gcs_unauthorized"));
                assert!(expired_at.is_none());
            }
            other => panic!("expected Auth context, got {other:?}"),
        }
    }

    #[test]
    fn map_status_to_error_403_is_permission_denied_no_context() {
        let err = map_status_to_error(403, "iam.objects.get denied");
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert!(err.context().is_none());
    }

    /// A malformed provider response reports its length, not its text.
    ///
    /// The body is valid JSON with a wrongly-typed field rather than syntactic
    /// garbage: a syntax error only ever renders a position, but a type error
    /// renders the offending value (`invalid type: string "…"`), so this is the
    /// shape that can actually carry response text into the message.
    ///
    /// The planted value deliberately looks like a signature rather than a
    /// bearer token: the core redactor scrubs `Bearer …` literals, so a
    /// `Bearer`-prefixed fixture would pass on the core's behaviour even if
    /// this module interpolated the whole serde error.
    #[tokio::test]
    async fn decode_json_reports_body_length_not_body_text() {
        let body = r#"{"temporaryHold":"7hK4wQ2mZ9pR1tY6uXbN5cJfA8sVdE3o"}"#;
        let response = reqwest::Response::from(
            http::Response::builder()
                .status(200)
                .body(body.to_string())
                .expect("build response"),
        );
        let err = decode_json::<GcsObject>(response)
            .await
            .expect_err("a wrongly-typed field is an error");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(err.message().contains(&format!("{} byte body", body.len())));
        assert!(
            !err.message().contains("7hK4wQ"),
            "response text reached the message: {}",
            err.message()
        );
        // The classification and position still make the failure diagnosable.
        assert!(err.message().contains("Data"), "{}", err.message());
    }

    #[test]
    fn apply_write_preconditions_emits_no_overwrite_first() {
        let mut query = Vec::new();
        let opts = WriteOptions {
            if_dest: IfDestExists::Fail,
            ..WriteOptions::default()
        };
        apply_write_preconditions(&mut query, &opts);
        assert_eq!(query, vec![("ifGenerationMatch".into(), "0".into())]);
    }

    #[test]
    fn apply_write_preconditions_threads_if_match_generation() {
        let mut query = Vec::new();
        let opts = WriteOptions {
            if_dest: IfDestExists::MatchEtag("42".into()),
            ..WriteOptions::default()
        };
        apply_write_preconditions(&mut query, &opts);
        assert_eq!(query, vec![("ifGenerationMatch".into(), "42".into())]);
    }

    #[test]
    fn read_range_header_serialises_open_and_closed_ranges() {
        let closed = read_range_header(Some(&ovstorage_plugin::ByteRange {
            start: 5,
            end_inclusive: Some(10),
        }))
        .unwrap();
        assert_eq!(closed.as_deref(), Some("bytes=5-10"));

        let open = read_range_header(Some(&ovstorage_plugin::ByteRange {
            start: 0,
            end_inclusive: None,
        }))
        .unwrap();
        assert_eq!(open.as_deref(), Some("bytes=0-"));

        assert_eq!(read_range_header(None).unwrap(), None);
    }

    #[test]
    fn read_range_header_rejects_inverted_range() {
        // An inverted range reaching a downstream slice would panic;
        // reject at construction so the caller gets InvalidArgument
        // rather than a catch_unwind-converted Internal.
        let inverted = read_range_header(Some(&ovstorage_plugin::ByteRange {
            start: 100,
            end_inclusive: Some(50),
        }))
        .expect_err("inverted range must error");
        assert_eq!(inverted.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn read_redirect_propagates_extra_headers() {
        let redirect = read_redirect(
            "https://storage.googleapis.com/b/o?X-Goog-Signature=zz".into(),
            "storage.googleapis.com".into(),
            vec![("range".into(), "bytes=0-1023".into())],
            RedirectCredential::None,
        );
        let headers = &redirect.request.headers;
        assert_eq!(headers[0].0, "host");
        assert_eq!(headers[1].0, "range");
        assert_eq!(headers[1].1, "bytes=0-1023");
    }

    #[test]
    fn read_redirect_populates_x_goog_hash_checksum_parsing() {
        let redirect = read_redirect(
            "https://storage.googleapis.com/b/o?X-Goog-Signature=zz".into(),
            "storage.googleapis.com".into(),
            Vec::new(),
            RedirectCredential::None,
        );
        let parsing = &redirect.response_parsing;
        assert_eq!(
            parsing.content_checksum_header.as_deref(),
            Some("x-goog-hash"),
            "content_checksum_header must be x-goog-hash so the verifier knows to multi-value-parse"
        );
        assert_eq!(
            parsing
                .content_checksum_algorithm
                .as_ref()
                .map(|a| a.as_str()),
            Some("crc32c"),
            "verifier algorithm must be crc32c — the strongest GCS reliably ships"
        );
        assert_eq!(
            parsing
                .checksum_headers
                .get(&ChecksumAlgorithm::crc32c())
                .map(String::as_str),
            Some("x-goog-hash")
        );
        assert_eq!(
            parsing
                .checksum_headers
                .get(&ChecksumAlgorithm::md5())
                .map(String::as_str),
            Some("x-goog-hash")
        );
    }

    #[test]
    fn read_redirect_pins_etag_header_to_x_goog_generation() {
        // GCS interprets the SPI `if_match` etag as a generation
        // (`ifGenerationMatch=<n>`), and the non-redirect path
        // (`parse_object`) sets `ObjectInfo.etag = generation`. The
        // redirect path must match so a `stat -> read -> if_match`
        // round-trip stays generation-shaped; HTTP `ETag` would be
        // rejected as a precondition token.
        let redirect = read_redirect(
            "https://storage.googleapis.com/b/o?X-Goog-Signature=zz".into(),
            "storage.googleapis.com".into(),
            Vec::new(),
            RedirectCredential::None,
        );
        assert_eq!(
            redirect.response_parsing.etag_header.as_deref(),
            Some("x-goog-generation"),
            "redirect must extract etag from x-goog-generation so it round-trips to ifGenerationMatch",
        );
        // The HTTP-level ETag is retained for diagnostics under
        // system_metadata, where the non-redirect path also keeps it.
        assert!(
            redirect
                .response_parsing
                .system_metadata_headers
                .iter()
                .any(|h| h == "etag"),
            "HTTP etag must still propagate to system_metadata for diagnostic parity with parse_object",
        );
    }

    /// Both algorithms route through the same physical header so the
    /// host's multi-value extractor disambiguates by tag prefix on the
    /// wire. Full propagation lives in the host's `redirect_info_*` tests.
    #[test]
    fn read_redirect_x_goog_hash_pins_both_algorithms_to_same_header() {
        let redirect = read_redirect(
            "https://storage.googleapis.com/b/o?X-Goog-Signature=zz".into(),
            "storage.googleapis.com".into(),
            Vec::new(),
            RedirectCredential::None,
        );
        let map = &redirect.response_parsing.checksum_headers;
        let crc_header = map.get(&ChecksumAlgorithm::crc32c()).expect("crc32c entry");
        let md5_header = map.get(&ChecksumAlgorithm::md5()).expect("md5 entry");
        assert_eq!(crc_header, "x-goog-hash");
        assert_eq!(md5_header, "x-goog-hash");
    }

    #[test]
    fn test_iam_permissions_path_is_correct_gcs_endpoint() {
        // Regression pin: GCS uses `testIamPermissions`, not `testPermissions`.
        // https://cloud.google.com/storage/docs/json_api/v1/buckets/testIamPermissions
        assert_eq!(TEST_IAM_PERMISSIONS_PATH, "iam/testIamPermissions");
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b/{}/{}",
            urlencoding::encode("my-bucket"),
            TEST_IAM_PERMISSIONS_PATH
        );
        assert_eq!(
            url,
            "https://storage.googleapis.com/storage/v1/b/my-bucket/iam/testIamPermissions"
        );
    }

    /// Marker prefix must end with `/`, else recursive delete on
    /// `gs://b/foo` matches `foobar` / `foo.txt` siblings.
    #[test]
    fn directory_marker_prefix_never_matches_siblings_at_boundary() {
        let marker = directory_marker_name("foo");
        assert_eq!(marker, "foo/");
        assert!(!"foobar".starts_with(&marker));
        assert!(!"foo.txt".starts_with(&marker));
        assert!("foo/bar".starts_with(&marker));
    }

    fn make_backend(bucket: &str) -> Arc<GcsBackend> {
        let req = request(bucket);
        let config = GcsConnectionConfig::from_request(&req).unwrap();
        let http = build_http_client().unwrap();
        let auth = Authenticator::new(&req.credentials, http.clone()).unwrap();
        Arc::new(GcsBackend::new(config, http, Arc::new(auth)))
    }

    fn make_target(addr: &str) -> ResolvedTarget {
        ResolvedTarget {
            backend_id: BackendId("gcs:test".into()),
            resolved_address: address::parse(addr).unwrap(),
        }
    }

    fn write_redirect_batch_with(
        continuation: &ResumableContinuation,
        url: &str,
    ) -> WriteRedirectBatch {
        let now = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        let request_obj = HttpRequest {
            method: "PUT".into(),
            url: url.into(),
            headers: Vec::new(),
        };
        let scope = RedirectScope {
            physical_url_prefix: trim_session_query(url),
            operations: AccessOps {
                read: false,
                write: true,
                delete: false,
                update_metadata: false,
            },
            expires_at: now,
            credential: RedirectCredential::None,
        };
        let redirect = WriteRedirect {
            request: request_obj,
            body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
            result_capture: ResultCapture {
                headers: Vec::new(),
                body_max_bytes: 1024,
            },
            expires_at: now,
            scope,
            audit_id: "test".into(),
            policy_epoch: 0,
        };
        WriteRedirectBatch {
            continuation: serde_json::to_vec(continuation).unwrap(),
            redirects: vec![redirect],
        }
    }

    #[tokio::test]
    async fn continue_write_rejects_a_continuation_recording_another_address() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/wrong-target".into(),
        };
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// Guarded like every other `continue_write` in the tree, even though this
    /// one performs no outbound call — it still reports an address.
    #[tokio::test]
    async fn continue_write_refuses_a_version_pinned_address() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let err = backend
            .continue_write(
                make_target("gs://asset-bucket/file.txt?generation=123"),
                batch,
                results,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// The substitution attack this PR closes elsewhere is closed here too, and
    /// this is the test that settles it rather than an argument.
    ///
    /// A caller holds a **genuine, internally consistent** continuation for
    /// `other.txt`: `target_address` is exactly what `write_redirect` mints
    /// (`target.resolved_address.as_str()`, `lib.rs:1623-1626`), `session_url`
    /// is the session GCS issued for that object, and the redirect batch echoes
    /// that same session. Nothing is edited. It is presented against the
    /// authorized request address `file.txt`.
    ///
    /// It is refused, because the recorded address is compared against
    /// `target.resolved_address` — the authorized address the request arrived
    /// with — and not against another field of the same blob. Substituting an
    /// untouched continuation therefore does not work on GCS.
    ///
    /// Verified by control: deleting that one comparison makes this test fail.
    /// The captured body is forged to name the *authorized* object precisely so
    /// the comparison is what does the refusing — with an honest body naming
    /// `other.txt`, the later response `name` re-check refuses it instead and
    /// the test passes whether or not the address comparison exists.
    ///
    /// What *does* get through is substitution **plus modification**: rewriting
    /// `target_address` to the authorized address, which
    /// `continue_write_cannot_detect_a_fully_rewritten_continuation` pins. The
    /// two tests together state the boundary exactly — this plugin stops the
    /// unforgeable-substitution case and not the forged one, because nothing in
    /// the SPI makes the blob tamper-evident.
    #[tokio::test]
    async fn continue_write_refuses_a_genuine_unmodified_continuation_for_another_object() {
        let backend = make_backend("asset-bucket");
        let minted_for = make_target("gs://asset-bucket/other.txt");
        // Exactly the expression `write_redirect` uses at mint time.
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=other"
                    .into(),
            target_address: minted_for.resolved_address.as_str().to_string(),
        };
        // Self-consistent: the batch echoes the session the continuation names.
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                // Forged to name the authorized object, which is what an
                // attacker would do — that is what isolates the address
                // comparison as the check doing the work. An honest body naming
                // `other.txt` would be caught later by the response re-check
                // instead, and the test would pass for the wrong reason.
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let err = backend
            .continue_write(
                make_target("gs://asset-bucket/file.txt"),
                batch,
                results,
                None,
            )
            .await
            .expect_err("an unmodified continuation for another object must be refused");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// Characterization, not a guarantee: the case this plugin cannot close.
    ///
    /// A caller holding a genuine resumable session for `other.txt` presents it
    /// against the authorized address `file.txt`, having rewritten the recorded
    /// `target_address` to match and supplied a captured body naming `file.txt`.
    /// Every check in `continue_write` then compares caller-supplied data
    /// against caller-supplied data and passes. The bytes are already at
    /// `other.txt` — the client's own PUT to the session URL was the commit —
    /// so what this returns is a report about the wrong object rather than a
    /// misdirected write.
    ///
    /// GCS's session URL names the object by itself and cannot be recomputed
    /// from the address, so the derivation the other adopters use is not
    /// available here. This test exists to keep that residual visible: if it
    /// ever starts failing, the plugin gained an anchor and this comment is out
    /// of date.
    #[tokio::test]
    async fn continue_write_cannot_detect_a_fully_rewritten_continuation() {
        let backend = make_backend("asset-bucket");
        // A real session for `other.txt`, with the recorded address rewritten
        // to the address the caller is authorized for.
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=other"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let step = backend
            .continue_write(target, batch, results, None)
            .await
            .expect("no check in this plugin can reach this case");
        match step {
            WriteStep::Done(result) => {
                assert_eq!(result.info.address.as_str(), "gs://asset-bucket/file.txt");
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn continue_write_rejects_session_url_mismatch() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let batch = write_redirect_batch_with(
            &continuation,
            "https://elsewhere.example/v1/upload?upload_id=abc",
        );
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn continue_write_rejects_malformed_continuation() {
        let backend = make_backend("asset-bucket");
        let now = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        let request_obj = HttpRequest {
            method: "PUT".into(),
            url: "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                .into(),
            headers: Vec::new(),
        };
        let scope = RedirectScope {
            physical_url_prefix:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o".into(),
            operations: AccessOps {
                read: false,
                write: true,
                delete: false,
                update_metadata: false,
            },
            expires_at: now,
            credential: RedirectCredential::None,
        };
        let batch = WriteRedirectBatch {
            continuation: b"not-json".to_vec(),
            redirects: vec![WriteRedirect {
                request: request_obj,
                body_source: RedirectBodySource::UserBytes { offset: 0, len: 0 },
                result_capture: ResultCapture {
                    headers: Vec::new(),
                    body_max_bytes: 1024,
                },
                expires_at: now,
                scope,
                audit_id: "test".into(),
                policy_epoch: 0,
            }],
        };
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn continue_write_rejects_object_name_mismatch() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"different.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn continue_write_rejects_session_url_sibling_prefix_match() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let sibling_url =
            "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/oXXX?upload_id=abc";
        let batch = write_redirect_batch_with(&continuation, sibling_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"name":"file.txt","generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn continue_write_rejects_partial_308_status() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 308,
                captured_headers: Vec::new(),
                captured_body: Vec::new(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[tokio::test]
    async fn continue_write_rejects_object_with_no_name_field() {
        let backend = make_backend("asset-bucket");
        let continuation = ResumableContinuation {
            session_url:
                "https://storage.googleapis.com/upload/storage/v1/b/asset-bucket/o?upload_id=abc"
                    .into(),
            target_address: "gs://asset-bucket/file.txt".into(),
        };
        let batch = write_redirect_batch_with(&continuation, &continuation.session_url);
        let results = RedirectResultBatch {
            results: vec![RedirectResult {
                status_code: 200,
                captured_headers: Vec::new(),
                captured_body: br#"{"generation":"1"}"#.to_vec(),
            }],
        };
        let target = make_target("gs://asset-bucket/file.txt");
        let err = backend
            .continue_write(target, batch, results, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[tokio::test]
    async fn write_redirect_unsupported_when_size_hint_is_unknown() {
        let backend = make_backend("asset-bucket");
        let target = make_target("gs://asset-bucket/file.txt");
        let opts = WriteOptions {
            size_hint: None,
            ..WriteOptions::default()
        };
        let err = backend
            .write_redirect(target, opts, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn validate_credentials_rejects_non_json_service_account_bytes() {
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "service_account_key".into(),
            SecretValue::Bytes(SecretBytes(b"definitely-not-json".to_vec())),
        );
        let err = validate_credentials(&bundle).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn validate_credentials_accepts_well_formed_authorized_user_json() {
        let mut bundle = SecretBundle::default();
        let json = serde_json::json!({
            "type": "authorized_user",
            "client_id": "abc",
            "client_secret": "shh",
            "refresh_token": "rt",
        })
        .to_string();
        bundle.fields.insert(
            "service_account_key".into(),
            SecretValue::Bytes(SecretBytes(json.into_bytes())),
        );
        validate_credentials(&bundle).unwrap();
    }

    /// The object name is the decoded path, matching `address::key`.
    ///
    /// A raw slice of the serialized address is the wrong name: the canonical
    /// form still escapes space, controls and `%`, so `gs://b/pub%20x` sliced
    /// raw asks GCS for an object literally named `pub%20x`.
    #[test]
    fn the_object_name_is_the_decoded_path() {
        for (address, expected) in [
            ("gs://example-bucket/pub%20x", "pub x"),
            ("gs://example-bucket/dir/a%25b", "dir/a%b"),
            ("gs://example-bucket/plain/key", "plain/key"),
            ("gs://example-bucket/", ""),
            ("gs://example-bucket/k?generation=7", "k"),
        ] {
            let parsed = parse_gcs_address(&address::parse(address).unwrap()).unwrap();
            assert_eq!(parsed.object, expected, "object of {address}");
        }
    }

    /// A name whose bytes are not valid UTF-8 is refused rather than collapsed.
    ///
    /// The name goes into a JSON API URL path built from a `&str`, so there is
    /// nowhere for those bytes to go. Converting them lossily would make the
    /// backend fetch one object for two distinct addresses.
    #[test]
    fn an_object_name_that_is_not_utf8_is_refused_rather_than_collapsed() {
        let error = parse_gcs_address(&address::parse("gs://example-bucket/x%FF").unwrap())
            .expect_err("a non-UTF-8 object name has no GCS wire spelling");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
    }
}

#[cfg(test)]
mod user_metadata_declaration_tests {
    use super::*;

    /// This kind's `supports_user_metadata` declaration is what a host reads to
    /// decide whether to compose its attribution layer over this backend's
    /// branch. Asserted here, in the crate that owns the answer, because a host
    /// crate cannot reach it: a plugin crate may not depend on a host-side
    /// crate, and two plugin rlibs in one test binary are a duplicate-symbol
    /// link error under `rust-lld`.
    ///
    /// Flipping it is a behaviour change for every host that loads this plugin —
    /// stores object `metadata` on upload and on resumable-session initiation.
    #[test]
    fn gcs_declares_its_user_metadata_support() {
        let descriptor = kind_descriptor();
        assert_eq!(descriptor.kind, "gcs");
        assert!(
            descriptor.supports_user_metadata,
            "gcs's user-metadata declaration changed; a host composes its \
             attribution layer from it"
        );
    }
}
