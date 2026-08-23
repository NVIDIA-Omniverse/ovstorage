// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native S3 / S3-compatible object/data operations (ABI-v2 Layer backend).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, MetadataDirective, RequestPayer};
use tracing::{Instrument as _, debug, info, warn};

use ovstorage_plugin::ReadRedirect;
use ovstorage_plugin::{
    AccessDecision, BackendItemInfo, CopyOptions, CreateDirectoryOptions, ReadOptions, ReadResult,
    RenameOptions, UpdateMetadataOptions,
};
use ovstorage_plugin::{
    AccessOps, CancellationToken, Capabilities, ChecksumAlgorithm, ChecksumSet,
    DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, ErrorContext, HttpRequest,
    IfDestExists, ListOptions, ListVersionsOptions, MtimeFormat, ObjectInfo, ObjectKind,
    RedirectBodySource, RedirectCredential, RedirectResultBatch, RedirectScope, ResolvedTarget,
    ResponseParsing, Result, ResultCapture, SecretBundle, StatOptions, SystemMetadata, Url,
    UserMetadata, VersionListOrder, WriteOptions, WriteRedirect, WriteRedirectBatch, WriteResult,
    address, race_cancel, reject_pinned_for_mutation,
};

const PINNED_VERSION_KEYS: &[&str] = &["versionId"];

/// How many entries one `list` may accumulate before it refuses to continue.
///
/// **Counted in entries rather than pages, because memory is the hazard and a
/// page is not a fixed amount of it.** `ListObjectsV2` returns up to 1000 keys
/// per response but may return one, so a page budget bounds round trips and
/// nothing else; an entry budget bounds the `Vec` that actually grows.
///
/// 100_000 entries is roughly 50 MB once each `ObjectInfo`'s address, etag and
/// per-item system-metadata map are counted at ~500 bytes. Round trips are
/// bounded by [`LIST_PAGE_BUDGET`] rather than by this: a store filling every
/// page reaches the entry budget in ~100 responses, one returning a key at a
/// time would take 100_001, and the response budget is what stops that. The
/// number is chosen against the failure it prevents rather than against a
/// workload: one `list` of a few hundred bytes must not be able to exhaust a
/// host shared with other tenants, and on the broker every caller is another
/// tenant.
///
/// It is deliberately far above anything a directory listing reaches. The
/// default `ListOptions` is non-recursive, so an ordinary browse is bounded by
/// one level's fan-out; what exceeds this is a `recursive: true` walk of a
/// large bucket, which is the request that has no bounded answer and should be
/// narrowed rather than served.
///
/// A walk that would continue past it is [`ErrorCode::Internal`] and
/// never a short listing — see [`refuse_partial_listing`] for why that code, and
/// for why truncating instead would reintroduce the defect the walk exists to
/// remove. A listing the store COMPLETES may finish over this budget rather than
/// be discarded, bounded by [`LIST_ITEM_CEILING`].
const LIST_ITEM_BUDGET: usize = 100_000;

/// How many responses one `list` may take before it refuses.
///
/// [`LIST_ITEM_BUDGET`] alone does not bound the walk, and the gap is not
/// theoretical: **a store that answers with EMPTY pages and a fresh
/// continuation token each time grows no entries at all**, so an entry budget
/// never trips while the loop spins and `seen_tokens` grows for ever. A page
/// budget is what closes that, and it also bounds round trips, which the entry
/// budget only bounds indirectly.
///
/// 1000 is ten times the ~100 pages a full entry budget needs at S3's 1000-key
/// page size, so a store returning genuinely sparse pages — many
/// `CommonPrefixes` rolled up under a delimiter — is not refused for being
/// sparse. What it refuses is a store that is not making progress.
const LIST_PAGE_BUDGET: usize = 1_000;

/// The most one call may hold and hand on, whatever the store does.
///
/// [`LIST_ITEM_BUDGET`] is checked on the edge that would fetch another page,
/// so a listing the store completes is allowed to finish over budget rather
/// than be discarded — but "over by one page" is only bounded for a store that
/// honours `MaxKeys`. One that ignores it can answer a single request with
/// millions of keys, and that response is buffered, parsed and folded whole
/// before anything is checked. This ceiling is where such a response is
/// refused instead of handed to `S3Layer::list`, which folds and paginates it
/// into two further allocations of the same set. A complete listing is no
/// safer to forward than a truncated one when the size is the hazard.
///
/// Exactly one conforming page of overshoot, so it can never fire for a store
/// that answers the page size it was asked for — counting, as S3 does, its
/// `CommonPrefixes` against the same `MaxKeys` as its `Contents`. A store that
/// applies the limit to `Contents` alone can still reach this, and is refused
/// with the same message, which is the honest outcome: the response was larger
/// than the one that was asked for.
const LIST_ITEM_CEILING: usize = LIST_ITEM_BUDGET + S3_MAX_KEYS_PER_PAGE as usize;

/// S3's own maximum keys per `ListObjectsV2` response, and the page size this
/// backend always asks for. Pinning it is what keeps one response a bounded
/// term in the memory the walk holds.
const S3_MAX_KEYS_PER_PAGE: u32 = 1_000;

/// Apply the connection's requester-pays flag to an S3 request builder.
/// Requester-pays is all-or-nothing per request, so centralising the flag
/// keeps a future data-plane op from silently omitting it — a missing
/// `x-amz-request-payer` against a requester-pays bucket is a `403` /
/// billing bug, not a visible one. Works across the heterogeneous fluent
/// builder types, which share no common `request_payer` trait.
macro_rules! apply_request_payer {
    ($builder:expr, $config:expr) => {
        if $config.force_request_payer {
            $builder.request_payer(RequestPayer::Requester)
        } else {
            $builder
        }
    };
}

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

use crate::client::{
    RefusalEpoch, SharedAwsCredentials, build_anonymous_s3_client, build_http_client,
    build_s3_client, build_sqs_client,
};
use crate::config::{
    S3AddressParts, S3Config, canonical_path, canonicalize_query, resolve_endpoint,
};
use crate::convert::require_etag_only_if_match;
use crate::credentials::AwsCredentials;
use crate::errors::{map_anonymous_refusal, map_error_status, map_sdk_error};

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
use crate::multipart::{
    DEFAULT_PART_SIZE_BYTES, MIN_PART_SIZE_BYTES, MULTIPART_REDIRECT_THRESHOLD_BYTES,
    MultipartContinuation, MultipartPart, compute_total_parts, ensure_streaming_part_limit,
    part_sizes,
};

/// Default presigned-URL TTL; short because the host follower consumes immediately.
pub(crate) const DEFAULT_PRESIGN_TTL_SECS: u32 = 300;

/// Presigning config for the standard redirect TTL.
fn presign_config() -> Result<PresigningConfig> {
    PresigningConfig::expires_in(Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64)).map_err(
        |err| {
            Error::new(
                ErrorCode::Internal,
                format!("s3: invalid presign TTL: {err}"),
            )
        },
    )
}

/// Capabilities advertised for AWS-shaped buckets and well-known S3-compatible profiles.
pub fn s3_capabilities() -> Capabilities {
    s3_capabilities_for_config(None)
}

pub fn s3_capabilities_for_config(config: Option<&S3Config>) -> Capabilities {
    let mut capabilities = Capabilities::empty();
    capabilities.supports_no_overwrite_write = true;
    capabilities.supports_if_match_write = true;
    capabilities.supports_server_side_copy = true;
    // S3 has no rename primitive: `Backend::rename` is CopyObject followed by
    // DeleteObject. That is availability without mechanism — the operation is
    // offered, but the bytes do not move in one server-side step and the
    // result is not atomic.
    capabilities.supports_server_side_rename = false;
    capabilities.supports_copy = true;
    capabilities.supports_rename = true;
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

/// Capabilities for an anonymous (no-credentials) backend.
///
/// **Anonymous does not mean read-only-one-object.** S3 authenticates a request
/// by its SigV4 signature; a request that carries none is evaluated as the
/// anonymous principal, and any action a bucket's policy grants to `*` is
/// servable that way. Listing a public bucket
/// (`GET /?list-type=2&prefix=…&delimiter=/`) and heading a public object are
/// ordinary unsigned requests, so this advertises the read side: `list`,
/// recursive list, version listing and `check_access`. `read` and `stat` need
/// no capability flag of their own.
///
/// **The rule for what goes in here is "whatever a credentialed connection
/// advertises, minus what an anonymous one genuinely cannot do."** Two
/// weaknesses in the read side are real and are NOT addressed by this shape —
/// `list_versions` reads one native page, and `check_access`
/// decides from one probe rather than per requested permission — but they are
/// properties of the operations, identical on a credentialed connection, and
/// narrowing them is a decision about the whole plugin. Withholding a bit here
/// on account of them would not make the plugin more truthful; it would only
/// make the two connection shapes disagree about the same operation.
///
/// The Layer contract does not force this either way, and it is worth being
/// exact about that. Its self-gate rule
/// (`docs/public/plugin-storage/CONFORMANCE.md`) constrains the PAIR: if a bit
/// is false, its slot must refuse locally without touching the wire. So
/// withholding `supports_access_check` AND self-gating `check_access` conforms
/// just as well — the azure sibling does exactly that for this very bit
/// (`azure_capabilities` never sets it, and `AzureBackend::check_access`
/// refuses locally when it is false). Note azure withholds it for EVERY
/// connection rather than for anonymous ones, so it is a precedent for the
/// shape and not for making the shape depend on the credential. What the rule
/// rules out is the half-measure: a false bit in front of a slot that still
/// runs. Advertising rather than self-gating is the policy above, not a
/// contract requirement.
///
/// `check_access` is in fact MORE accurate on an anonymous connection than on
/// a credentialed one: the mutating operations are reported denied, because
/// they are refused before the wire, and the bucket arm probes with a bounded
/// `ListObjectsV2` rather than a `GetBucketPolicyStatus` no anonymous caller
/// holds.
///
/// Withheld are the bits an anonymous connection cannot serve:
///
/// - every mutation (`write*`, `delete`, `copy`, `rename`, directory create /
///   delete, `update_metadata`) — refused by decision, see
///   [`S3Backend::signed_client`];
/// - `watch_directory`, which polls SQS: [`crate::subscription`] refuses it
///   for an anonymous connection, and the anonymous constructor builds no SQS
///   client for it to poll with.
///
/// Capabilities are hints, not guarantees. A bucket that grants anonymous
/// `s3:GetObject` but not `s3:ListBucket` is a real and common configuration,
/// and `supports_list` is still the right advertisement for it — the backend
/// can issue the request, and the store decides. What must be honest is the
/// runtime failure, which is [`crate::errors::map_anonymous_refusal`].
///
/// `wants_list_backed_stat` is raised too, so the two connection shapes agree
/// on every read-side bit. It is not an advertisement — the metadata cache
/// reads it as an instruction to FETCH a listing of the parent and answer
/// `stat` out of it (`ovstorage-plugin-cache/src/metadata_cache.rs`,
/// `stat_from_parent_list`) — and it is safe only because `S3Backend::list`
/// walks a prefix to its end: `find_in_page` treats an absent entry in a
/// listing with no next token as authoritative, so it depends on that listing
/// being complete.
///
/// The cost does not point one way, which is why it is not a per-shape
/// decision. On a bucket granting `s3:GetObject` but not `s3:ListBucket`, an
/// uncached `stat` spends a refused listing before falling back to the
/// `HeadObject` that answers. On a bucket that does grant listing — anonymous
/// browsing, the case this shape exists for — withholding would instead cost a
/// `HeadObject` per `stat` where the credentialed shape answers from a listing
/// it has already paid for. Whether the parent lists cheaply is a property of
/// the bucket rather than of holding a credential, so matching the credentialed
/// shape is the answer that needs no exception.
pub(crate) fn anonymous_capabilities() -> Capabilities {
    let mut capabilities = Capabilities::empty();
    capabilities.supports_list = true;
    capabilities.supports_recursive_list = true;
    capabilities.supports_version_listing = true;
    capabilities.version_list_order = Some(VersionListOrder::Newest);
    capabilities.wants_list_backed_stat = true;
    capabilities.supports_access_check = true;
    capabilities.has_real_directories = false;
    capabilities.populates_subdirectory_metadata = false;
    capabilities
}

pub struct S3Backend {
    config: S3Config,
    credentials: Arc<Mutex<Option<AwsCredentials>>>,
    is_anonymous: bool,
    /// The connection's AWS SDK S3 client: signing when the connection is
    /// credentialed, unsigned when it is anonymous. Reached through
    /// [`S3Backend::unsigned_capable_client`] by operations a public bucket can serve, and
    /// through [`S3Backend::signed_client`] by those it cannot.
    s3_client: aws_sdk_s3::Client,
    /// AWS SDK SQS client for `watch_directory`; `Some` only when the
    /// connection configured `sqs_queue_url` (and the backend is credentialed).
    sqs_client: Option<aws_sdk_sqs::Client>,
    /// Per-connection watch coalescer: concurrent `watch_directory` calls
    /// (any prefix, any principal) merge onto ONE SQS consumer per connection,
    /// fanning events out prefix-filtered per subscriber.
    watch_coalescer: Arc<ovstorage_plugin::subscription::WatchCoalescer>,
    /// Advanced when the store refuses this connection's credential. Read by
    /// `S3Layer`'s promotion witness, which requires it unchanged across an
    /// operation before promoting a parked connection on that operation's
    /// acceptance.
    refusals: RefusalEpoch,
}

impl S3Backend {
    pub fn with_credentials(config: S3Config, credentials: AwsCredentials) -> Result<Self> {
        Self::with_credentials_cell(config, Arc::new(Mutex::new(Some(credentials))))
    }

    /// Build a credentialed backend around an externally owned credential
    /// cell. The connection-lifecycle driver (`S3Driver::activate`) writes
    /// proven credentials into the same cell, so the live SDK clients pick
    /// them up without rebuilding the backend.
    pub fn with_credentials_cell(
        config: S3Config,
        credentials: Arc<Mutex<Option<AwsCredentials>>>,
    ) -> Result<Self> {
        // One rustls+ring HTTP client shared by the S3 and SQS service clients.
        let http = build_http_client();
        let provider = SharedAwsCredentials::new(credentials.clone());
        let refusals = RefusalEpoch::default();
        let s3_client = build_s3_client(&config, provider.clone(), http.clone(), refusals.clone())?;
        let sqs_client = match config.sqs_queue_url.as_deref() {
            Some(queue_url) => Some(build_sqs_client(&config, provider, http, queue_url)?),
            None => None,
        };
        let watch_coalescer = ovstorage_plugin::subscription::WatchCoalescer::new();
        Ok(Self {
            credentials,
            is_anonymous: false,
            s3_client,
            sqs_client,
            watch_coalescer,
            refusals,
            config,
        })
    }

    /// No credentials, no signing — anonymous public-bucket access.
    ///
    /// The connection still gets a full SDK client; it just signs nothing, so
    /// every request goes to the store as the anonymous principal. `read`
    /// bypasses it entirely and emits a plain unsigned redirect URL, because a
    /// redirect the host follows cannot be presigned without a credential.
    /// `write`-shaped operations are refused locally — see `signed_client`,
    /// deliberately not linked because it is private and this constructor is
    /// not — and `watch_directory` has no SQS client to poll with.
    ///
    /// Building the client makes this fallible where it was not. The conditions
    /// are the same ones `resolve_endpoint` already rejects on the first
    /// anonymous `read` — a malformed `endpoint`, or a compatibility profile
    /// that requires one and has none — so a config that reaches here and fails
    /// was never usable; it now fails at `add_connection`, which is where the
    /// credentialed constructor has always failed on it.
    pub fn anonymous(config: S3Config) -> Result<Self> {
        let watch_coalescer = ovstorage_plugin::subscription::WatchCoalescer::new();
        let s3_client = build_anonymous_s3_client(&config, build_http_client())?;
        Ok(Self {
            credentials: Arc::new(Mutex::new(None)),
            is_anonymous: true,
            s3_client,
            sqs_client: None,
            watch_coalescer,
            // Never advanced: the anonymous client carries no
            // `PromotionEvidence` interceptor, and nothing it sends is signed,
            // so there is no credential for the store to refuse.
            refusals: RefusalEpoch::default(),
            config,
        })
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    pub(crate) fn is_anonymous(&self) -> bool {
        self.is_anonymous
    }

    /// How many times the store has refused this connection's credential. A
    /// promotion witness snapshots this before its operation and requires it
    /// unchanged after — "did a refusal land while I ran?", whoever provoked it.
    pub(crate) fn refusal_epoch(&self) -> u64 {
        self.refusals.get()
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

    /// The AWS SDK SQS client for `watch_directory`. `None` unless the
    /// connection configured `sqs_queue_url` with credentials.
    pub(crate) fn sqs_client(&self) -> Option<&aws_sdk_sqs::Client> {
        self.sqs_client.as_ref()
    }

    /// The per-connection watch coalescer that merges concurrent
    /// `watch_directory` calls onto one SQS consumer.
    pub(crate) fn watch_coalescer(&self) -> &Arc<ovstorage_plugin::subscription::WatchCoalescer> {
        &self.watch_coalescer
    }

    /// The connection's SDK client, whatever its auth shape — signing when the
    /// connection is credentialed, unsigned when it is anonymous.
    ///
    /// The name states the precondition for reaching for it: call this **only
    /// where an unsigned request is a legitimate way to serve the operation**,
    /// which is `list`, the `stat` probes, `list_versions` and `check_access`.
    /// Anything else takes [`Self::signed_client`] and is refused on an
    /// anonymous connection.
    ///
    /// A refusal reaching a caller through this accessor comes from the store,
    /// not from here, and on an anonymous connection it is restated by
    /// [`crate::errors::map_anonymous_refusal`].
    pub(crate) fn unsigned_capable_client(&self) -> &aws_sdk_s3::Client {
        &self.s3_client
    }

    /// The SDK client for operations this plugin will only issue SIGNED.
    ///
    /// Refusing here is a decision, not a limit of the protocol. S3 would
    /// accept an unsigned `PutObject` or `DeleteObject` against a bucket whose
    /// policy grants the action to `*`; such a bucket is a misconfiguration to
    /// be repaired rather than a deployment shape to write into, and ovstorage
    /// does not mint unsigned mutations. `write_redirect` could not work
    /// anyway: it hands the host a SigV4 presign, which has no unsigned
    /// equivalent.
    ///
    /// Refusing locally also answers faster and more usefully than the round
    /// trip would — `Unsupported` names the connection's shape, where the
    /// store's `403` would name only the request.
    ///
    /// This accessor is not the whole enforcement — three slots call
    /// [`Self::reject_anonymous_mutation`] directly, for the reasons given
    /// there.
    pub(crate) fn signed_client(&self) -> Result<&aws_sdk_s3::Client> {
        self.reject_anonymous_mutation()?;
        Ok(&self.s3_client)
    }

    /// The anonymous-mutation policy itself, separate from fetching a client.
    ///
    /// Seven mutation slots get this incidentally, by reaching
    /// [`Self::signed_client`]. Three call it directly because they do work
    /// before they would reach a client: `write_stream` buffers a part of the
    /// caller's body, `update_metadata` issues a `HeadObject`, and
    /// `continue_write`'s single-`PutObject` arm commits from the caller's own
    /// result batch and touches no client at all — under the broker that batch
    /// arrives from a remote caller, which is what makes a fabricated one
    /// reachable.
    ///
    /// All ten call it AFTER their argument checks, so an anonymous `delete` of
    /// a malformed address answers `InvalidArgument` like every other slot. The
    /// Layer contract's self-gate rule is satisfied either way — it asks for a
    /// typed `Unsupported` "without performing any backend work or side
    /// effects", and parsing an address is neither. What it does require, and
    /// what this position delivers, is that nothing is decoded, buffered or
    /// sent first.
    pub(crate) fn reject_anonymous_mutation(&self) -> Result<()> {
        if self.is_anonymous {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "this S3 connection is anonymous; ovstorage issues no unsigned \
                 writes, deletes, copies, renames or metadata changes",
            )
            .with_next_action(
                "remove and re-add this connection with credentials to modify objects \
                 in this bucket",
            ));
        }
        Ok(())
    }

    /// Map a failure from a request issued through [`Self::unsigned_capable_client`], which on
    /// an anonymous connection went out unsigned.
    ///
    /// The anonymity is read here rather than passed in at each call site so a
    /// future unsigned-capable operation cannot forget it — a plain
    /// `map_sdk_error` would report the store's refusal of an unsigned request
    /// as a credential problem.
    fn map_store_error<E>(&self, context: &str, err: aws_sdk_s3::error::SdkError<E>) -> Error
    where
        E: std::fmt::Debug + aws_sdk_s3::error::ProvideErrorMetadata,
    {
        let mapped = map_sdk_error(context, err);
        if self.is_anonymous {
            map_anonymous_refusal(mapped)
        } else {
            mapped
        }
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

    /// Build the plain, unsigned `GET` request for an anonymous (public-bucket)
    /// read. No SigV4: the object URL carries only the `versionId` query pin,
    /// and the `x-amz-request-payer` / `If-Match` headers travel unsigned. The
    /// host injects the `Range:` header on the redirect request before
    /// following (plugin-dev contract), so this request never carries one.
    fn anonymous_read_request(
        &self,
        key: &str,
        version_id: Option<&str>,
        opts: &ReadOptions,
    ) -> Result<HttpRequest> {
        let endpoint = resolve_endpoint(&self.config, key)?;
        let mut existing_query: Vec<(String, String)> = Vec::new();
        if let Some(version) = version_id {
            existing_query.push(("versionId".to_string(), version.to_string()));
        }
        let canonical = canonicalize_query(&existing_query);
        let url = if canonical.is_empty() {
            format!(
                "{}://{}{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri,
            )
        } else {
            format!(
                "{}://{}{}?{}",
                endpoint.scheme, endpoint.host, endpoint.canonical_uri, canonical,
            )
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        // Requester-pays is honored only as a request header; S3 ignores it as
        // a query param, so a query placement would `403` against a
        // requester-pays bucket. The credentialed path emits it as a header via
        // the SDK's `.request_payer()`.
        if self.config.force_request_payer {
            headers.push(("x-amz-request-payer".to_string(), "requester".to_string()));
        }
        if let Some(if_match) = opts.if_match.as_deref() {
            headers.push(("if-match".to_string(), quote_etag(if_match)));
        }
        Ok(HttpRequest {
            method: "GET".to_string(),
            url,
            headers,
        })
    }
}

/// The S3 object/data operations used by the native Layer slots.
/// `crate::layer::S3Layer` delegates its operation slots here.
impl S3Backend {
    pub async fn stat(
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
            self.resolve_credentials(None)?;
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
            let Some(output) = self.head_object(&parts.key, version_id.as_deref()).await? else {
                if trailing_slash && version_id.is_none() {
                    let probe = self
                        .flat_directory_probe(&parts.key, &target.resolved_address)
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
            };
            let mut info = object_info_from_head_output(&target.resolved_address, &output);
            if trailing_slash {
                info.kind = ObjectKind::DirectoryMarker;
            }
            Ok(info)
        })
        .instrument(span)
        .await
    }

    pub async fn read(
        &self,
        target: ResolvedTarget,
        opts: ReadOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ReadResult> {
        require_etag_only_if_match(opts.if_match.as_ref())?;
        let span = tracing::debug_span!(
            "s3.read",
            op = "read",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_object_target(&target)?;
            let version_id = address_version_id(&target.resolved_address);
            // Validate the requested range eagerly, then discard it: the plugin
            // does not carry the `Range` header. For a `ReadResult::Redirect`
            // the host injects `Range:` on the request before following
            // (plugin-dev contract), so emitting it here would send a duplicate
            // (and a signed duplicate breaks the SigV4 header set → `403`).
            read_range_header(&opts)?;
            let now = SystemTime::now();
            let expires_at = now + Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64);

            let request = if self.is_anonymous {
                // Anonymous (public-bucket) read: a plain, unsigned object URL.
                self.anonymous_read_request(&parts.key, version_id.as_deref(), &opts)?
            } else {
                // Credentialed read: a SigV4 query-presigned GetObject. The SDK
                // folds If-Match / versionId / request-payer into the signed URL
                // and returns them as headers the follower re-sends verbatim.
                // `Range` is deliberately not signed: the host injects it, and
                // an unsigned `Range` on a presigned GET is honored by S3.
                self.resolve_credentials(None)?; // AuthRequired early if creds missing
                let mut get = self
                    .signed_client()?
                    .get_object()
                    .bucket(&self.config.bucket)
                    .key(&parts.key);
                if let Some(if_match) = opts.if_match.as_deref() {
                    get = get.if_match(quote_etag(if_match));
                }
                if let Some(version) = version_id.as_deref() {
                    get = get.version_id(version);
                }
                get = apply_request_payer!(get, self.config);
                let presigned = get
                    .presigned(presign_config()?)
                    .await
                    .map_err(|err| map_sdk_error("s3 read presign", err))?;
                HttpRequest {
                    method: presigned.method().to_string(),
                    url: presigned.uri().to_string(),
                    headers: presigned
                        .headers()
                        .map(|(name, value)| (name.to_string(), value.to_string()))
                        .collect(),
                }
            };

            let scope = RedirectScope {
                physical_url_prefix: redirect_prefix(&request.url)?,
                operations: AccessOps {
                    read: true,
                    ..AccessOps::default()
                },
                expires_at,
                // Same branch that built `request` above: the anonymous URL is
                // unsigned and carries nothing, the credentialed one is a SigV4
                // query presign over this key, this method and this TTL.
                credential: if self.is_anonymous {
                    RedirectCredential::None
                } else {
                    RedirectCredential::Request
                },
            };
            Ok(ReadResult::Redirect(ReadRedirect {
                request,
                response_parsing: read_response_parsing(),
                expires_at: scope.expires_at,
                scope,
                audit_id: format!("s3-read-{}", parts.key),
                policy_epoch: 0,
            }))
        })
        .instrument(span)
        .await
    }

    /// Buffered inline write — used by callers writing zero-byte or
    /// sub-`redirect_size_threshold` bodies, where the redirect round-trip
    /// is pure overhead. Issues a single signed PutObject directly from
    /// the plugin instead of emitting a `WriteRedirect`.
    pub async fn write(
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
                self.resolve_credentials(None)?;
                let opts = with_message_stashed(opts);
                let info = self.put_object_inline(&parts.key, &bytes, &opts).await?;
                Ok(WriteResult { info })
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
            "s3 write_redirect",
            PINNED_VERSION_KEYS,
        )?;
        // S3 write_redirect emits a presigned PUT (or a multipart batch) with
        // a fixed advertised `Content-Length`. Without a known upload size we
        // can't supply that length; substituting `S3_PUTOBJECT_MAX_BYTES`
        // (5 GiB) would produce Content-Length mismatches at the follower or
        // unbounded body sources for the single-PutObject path. Refuse instead
        // so the host falls back to `write_stream`, which buffers parts
        // incrementally.
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
                self.resolve_credentials(None)?;
                let (if_match_etag, no_overwrite) = split_if_dest(&opts.if_dest);
                if size >= MULTIPART_REDIRECT_THRESHOLD_BYTES {
                    let total_parts = compute_total_parts(size)?;
                    let upload_id = self.create_multipart_upload(&parts.key, &opts).await?;
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
                    let batch = self.build_part_batch(&continuation, size).await?;
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
                let redirect = self
                    .build_single_put_redirect(&parts.key, size, &opts)
                    .await?;
                Ok(WriteRedirectBatch {
                    continuation: continuation.encode(),
                    redirects: vec![redirect],
                })
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
    ) -> Result<ovstorage_plugin::WriteStep> {
        let span = tracing::debug_span!(
            "s3.continue_write",
            op = "write",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(cancel.as_ref(), async move {
        // A pinned-version address is refused here for the same reason `write`,
        // `write_stream` and `write_redirect` refuse it: `parse_object_target`
        // drops the selector, so the commit would land on the head while
        // authorization was decided on the frozen-version URL.
        // Deliberately ahead of the decode, so no multipart upload is aborted on
        // this path — the upload id is still inside the blob and unread. That is
        // the right trade: reaching the id means reading the caller's
        // continuation first, which is the thing this PR exists to stop, and a
        // caller that forged its own request can strand its own upload.
        reject_pinned_for_mutation(
            &target.resolved_address,
            "s3 continue_write",
            PINNED_VERSION_KEYS,
        )?;
        let authorized = self.parse_object_target(&target)?;
        // Before the continuation is decoded — see `reject_anonymous_mutation`.
        self.reject_anonymous_mutation()?;
        let mut continuation = MultipartContinuation::decode(&redirects.continuation)?;
        // Derive the object from the authorized address rather than reading it
        // out of the continuation: on the broker's client-driven route the whole
        // batch, blob included, arrives from the remote caller, while the address
        // is what authorization was decided on.
        //
        // The derived key is threaded to every commit and abort below as its own
        // argument rather than written back into the decoded continuation. That
        // is what makes the dependency a compile error instead of an ordering
        // convention: `MultipartContinuation::key` decodes to `""`, so a
        // back-patch would leave every later read correct only because one
        // assignment happened to run first, and an early return inserted above it
        // would abort against an empty key with nothing to catch it.
        let key = authorized.key;
        if redirects.redirects.len() != results.results.len() {
            if !continuation.upload_id.is_empty() {
                self.abort_multipart_upload_best_effort(&key, &continuation.upload_id)
                    .await;
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
                self.abort_multipart_upload_best_effort(&key, &continuation.upload_id)
                    .await;
                return Err(map_error_status(result.status_code, &result.captured_body));
            }
            let etag = match header_value(&result.captured_headers, "etag")
                .map(|value| value.trim_matches('"').to_string())
            {
                Some(etag) => etag,
                None => {
                    self.abort_multipart_upload_best_effort(&key, &continuation.upload_id)
                    .await;
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
            self.abort_multipart_upload_best_effort(&key, &continuation.upload_id)
                    .await;
            return Err(Error::new(
                ErrorCode::Internal,
                "S3 multipart continuation expected more parts than the host returned",
            ));
        }
        self.resolve_credentials(None)?;
        let info = match self.complete_multipart_upload(&key, &continuation).await {
            Ok(info) => info,
            Err(err) => {
                self.abort_multipart_upload_best_effort(&key, &continuation.upload_id)
                    .await;
                return Err(err);
            }
        };
        Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
      }.instrument(span))
      .await
    }

    /// Streaming write: buffers ~8 MiB chunks and uploads via direct `UploadPart` calls,
    /// bypassing the buffered redirect-follower without materialising the full object.
    pub async fn write_stream(
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
        // Before the buffering loop takes ~8 MiB of the caller's body. This is
        // the one slot whose address parse happens later, in `stream_write`, so
        // a malformed address here answers `Unsupported` where the other nine
        // say `InvalidArgument`; `anonymous_public_bucket.rs` pins the rule and
        // this exception. See `reject_anonymous_mutation`.
        self.reject_anonymous_mutation()?;
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

    pub async fn delete(
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
                self.resolve_credentials(None)?;
                let mut request = self
                    .signed_client()?
                    .delete_object()
                    .bucket(&self.config.bucket)
                    .key(&parts.key);
                if let Some(if_match) = opts.if_match.as_deref() {
                    request = request.if_match(quote_etag(if_match));
                }
                if let Some(version) = address_version_id(&target.resolved_address) {
                    request = request.version_id(version);
                }
                request = apply_request_payer!(request, self.config);
                match request.send().await {
                    Ok(_) => Ok(()),
                    // delete is idempotent: a missing target is success.
                    Err(err)
                        if err.raw_response().map(|resp| resp.status().as_u16()) == Some(404) =>
                    {
                        Ok(())
                    }
                    Err(err) => Err(map_sdk_error("s3 delete", err)),
                }
            }
            .instrument(span),
        )
        .await
    }

    /// List one prefix, walking S3's paging to the end of it.
    ///
    /// **The whole listing is materialized in memory before anything is
    /// returned**, and the caller should size that before asking. `Vec<ObjectInfo>`
    /// is the return type, so there is no streaming seam here to use instead;
    /// budget roughly half a kilobyte per entry once the address, etag and the
    /// per-item system-metadata map are counted, and one sequential round trip
    /// per up to 1000 entries — the service page size, which `CommonPrefixes`
    /// count toward as well. A recursive list of a bucket root is a request
    /// for every object in the bucket, at once — millions of keys is gigabytes
    /// and thousands of serial requests.
    ///
    /// Two things make that acceptable rather than merely tolerated. `S3Layer::list`
    /// asks for the full set by construction — it clears `max_results` and
    /// `page_token` and paginates host-side — so a short answer is read as a
    /// complete one, and the alternative to walking is not "less memory" but
    /// "wrong results". And the default `ListOptions` is non-recursive, so the
    /// `stat` path that reaches here through the metadata cache is bounded by
    /// one directory's fan-out rather than by the bucket.
    ///
    /// A direct `S3Backend` caller that wants a bound has one: pass
    /// `max_results`, which stops the walk after a single request. It buys a
    /// bound and nothing else — this function returns `Vec<ObjectInfo>` and no
    /// continuation token, so there is no way to ask for the next page. A
    /// caller that needs both a bound and the rest of the prefix has to drive
    /// `ListObjectsV2` itself. Nobody arriving through `S3Layer::list` takes
    /// that branch: it hard-sets `max_results` and `page_token` to `None`, and
    /// the host's own page token is a decimal index from `paginate_list_items`,
    /// a different token space.
    ///
    /// # Why the walk exists
    ///
    /// `ListObjectsV2` answers at most 1000 keys per request, so one response
    /// is a page and not the listing. `S3Layer::list` asks for the full set and
    /// paginates host-side, and the metadata cache's `find_in_page` treats an
    /// absent entry in a page with no next token as an authoritative
    /// `NotFound` — so a caller above this reads a short answer as a complete
    /// one, and an object past the first page reads as missing. Following
    /// `NextContinuationToken` to the end is what makes "complete" true.
    ///
    /// So an unbounded call never answers `Ok` with less than the whole prefix
    /// (a `max_results` call is the deliberate exception above).
    ///
    /// # What the budgets do and do not bound
    ///
    /// The budgets are checked after a response is folded in and on the edge
    /// that would fetch another, so one response is the term they cannot see
    /// and a walk the store has already completed is not refused for finishing
    /// over budget — up to `LIST_ITEM_CEILING`, which is the one bound that
    /// applies however complete the answer claims to be.
    /// Every request therefore asks for S3's own
    /// 1000-key maximum and `max_results` may only narrow it — without that,
    /// an `S3Layer` call (which clears `max_results`) sent no `MaxKeys` at all
    /// and left the size of each response entirely to the store.
    ///
    /// That narrows the term; it does not bound it. `MaxKeys` is a request
    /// parameter, and a store that ignores it is exactly the kind of store
    /// these budgets exist to defend against — a non-conforming peer can still
    /// answer with one arbitrarily large page, which is buffered, parsed and
    /// folded whole before any check runs. Peak memory is the entry budget plus
    /// one response, bounded for a conforming store and not for a hostile one.
    /// Bounding it there needs a streaming parse, which the SDK does not give
    /// us.
    /// A store that cannot be followed, and a listing over this backend's
    /// per-call budgets, both end in an error instead — `Transient` for the
    /// first, `Internal` for the second, because a budget is this backend's own
    /// fixed bound rather than anything the store did wrong — the entry budget
    /// bounds the memory the process would otherwise exhaust — and a fixed
    /// bound is reached identically on every attempt, so it must not be in a
    /// retryable bucket.
    /// Neither is linked here because both are private; see `LIST_ITEM_BUDGET`
    /// and `refuse_partial_listing` in this module.
    pub async fn list(
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
                self.resolve_credentials(None)?;
                // `directory_key` rather than the key verbatim: `x` and `x/`
                // name one node, and a verbatim listing prefix matches every
                // sibling whose name merely starts with this one's.
                let prefix_key = address::directory_key(&parts.key);
                let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
                let mut items: Vec<ObjectInfo> = Vec::new();
                let mut marker_addresses = std::collections::HashSet::new();
                let mut continuation = opts.page_token.clone();
                // Every token this walk has followed, seeded with the caller's
                // so a store that hands its own starting token straight back is
                // caught on the first response rather than the second.
                let mut seen_tokens: std::collections::HashSet<String> =
                    continuation.iter().cloned().collect();
                let mut pages: usize = 0;
                loop {
                    pages += 1;
                let mut request = self
                    .unsigned_capable_client()
                    .list_objects_v2()
                    .bucket(&self.config.bucket);
                if !prefix_key.is_empty() {
                    request = request.prefix(&prefix_key);
                }
                if !opts.recursive {
                    request = request.delimiter("/");
                }
                // Asked for on every request; see the doc comment for the term
                // it narrows and the one it cannot.
                let page_size = opts
                    .max_results
                    .map_or(S3_MAX_KEYS_PER_PAGE, |n| n.min(S3_MAX_KEYS_PER_PAGE));
                request = request.max_keys(page_size as i32);
                if let Some(token) = continuation.as_ref() {
                    request = request.continuation_token(token);
                }
                request = apply_request_payer!(request, self.config);
                let output = request
                    .send()
                    .await
                    .map_err(|err| self.map_store_error("s3 list", err))?;
                for object in output.contents() {
                    let Some(key) = object.key() else {
                        continue;
                    };
                    if key == prefix_key {
                        continue;
                    }
                    let Ok(address) = address::join_relative(&bucket_root, key) else {
                        // The key cannot be named by a URI path, so any address
                        // built for it would resolve to a different object.
                        // Omit the entry and keep the page: invisible beats
                        // mis-addressed, and failing the page would hide every
                        // sibling too.
                        tracing::warn!(
                            target: "ovstorage.s3.backend",
                            plugin = "s3",
                            key = %key,
                            "s3: object key is not addressable as a URI path; omitted from listing",
                        );
                        continue;
                    };
                    let _ = address::relative_suffix(&address, &prefix.resolved_address).ok_or_else(
                        || {
                            Error::new(
                                ErrorCode::Internal,
                                format!(
                                    "S3 returned object key '{}' outside requested prefix '{}'",
                                    key,
                                    RedactedUrl(&prefix.resolved_address)
                                ),
                            )
                        },
                    )?;
                    let mtime = object.last_modified().and_then(datetime_to_system_time);
                    let etag = object
                        .e_tag()
                        .map(|value| value.trim_matches('"').to_string());
                    let size = object.size().and_then(|n| u64::try_from(n).ok());
                    let mut system_metadata: SystemMetadata = SystemMetadata::new();
                    if let Some(class) = object.storage_class() {
                        system_metadata.insert("x-amz-storage-class".into(), class.as_str().into());
                    }
                    let kind = if key.ends_with('/') && size.unwrap_or(0) == 0 {
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
                for prefix_entry in output.common_prefixes() {
                    let Some(prefix_str) = prefix_entry.prefix() else {
                        continue;
                    };
                    let Ok(address) = address::join_relative(&bucket_root, prefix_str) else {
                        tracing::warn!(
                            target: "ovstorage.s3.backend",
                            plugin = "s3",
                            key = %prefix_str,
                            "s3: common prefix is not addressable as a URI path; omitted from listing",
                        );
                        continue;
                    };
                    // If S3 reports the same slash key as both a real zero-byte
                    // marker object and a CommonPrefix, keep the marker. The
                    // marker is the concrete directory representation and
                    // carries etag/mtime metadata the inferred prefix lacks.
                    if marker_addresses.contains(address.as_str()) {
                        continue;
                    }
                    let _ = address::relative_suffix(&address, &prefix.resolved_address).ok_or_else(
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
                // Checked on every path out of a folded page — before the
                // bounded-request break as well, since a store that ignores
                // `MaxKeys` overruns a bounded caller just as easily. Past the
                // ceiling the RESPONSE is the exhaustion, and neither
                // completeness nor a caller's bound makes it safe to hand on.
                // See `LIST_ITEM_CEILING`.
                if items.len() > LIST_ITEM_CEILING {
                    return Err(refuse_partial_listing(
                        ErrorCode::Internal,
                        &prefix.resolved_address,
                        &format!(
                            "one response carried the listing past this backend's \
                             {LIST_ITEM_CEILING}-entry ceiling; the store answered with \
                             far more than the {S3_MAX_KEYS_PER_PAGE} keys per response it \
                             was asked for"
                        ),
                    ));
                }
                // A bounded request keeps its single-page meaning and stops
                // here, token or no token: the caller asked for one page and a
                // short answer is what it asked for.
                if opts.max_results.is_some() {
                    break;
                }
                // The walk ends in exactly one of two ways: the store offers no
                // further token and did not claim truncation, which is a
                // complete listing — or it does something this loop cannot
                // safely continue from, which is an ERROR and not a short
                // listing. See `refuse_partial_listing` for why that distinction
                // is the whole point.
                match output.next_continuation_token() {
                    Some(token) if !token.is_empty() => {
                        // A token already issued means the store is not
                        // advancing. `seen_tokens` rather than "differs from the
                        // previous one" because a cycle can be longer than one
                        // step: A → B → A defeats a single-step comparison and
                        // loops for ever.
                        if !seen_tokens.insert(token.to_string()) {
                            return Err(refuse_partial_listing(
                                ErrorCode::Transient,
                                &prefix.resolved_address,
                                "the store reissued a continuation token it had already \
                                 handed back, so the listing cannot be advanced",
                            ));
                        }
                        // The budgets sit on the edge that would fetch ANOTHER
                        // page, so a listing the store has already declared
                        // complete is returned rather than discarded for being
                        // one page over. Peak memory is the same either way —
                        // this page is folded in before the check runs — and a
                        // walk that intends to continue is caught here, while
                        // one that cannot be continued at all is caught by the
                        // arms around this one. The precedence that produces:
                        // an oversize response outranks everything, since it is
                        // checked before the match; below it a store's own
                        // misbehaviour outranks the budgets, since the cycle
                        // guard runs first. Entries bound memory; responses bound a store
                        // answering empty pages for ever, which grows no
                        // entries and so never trips the first.
                        if items.len() > LIST_ITEM_BUDGET {
                            return Err(refuse_partial_listing(
                                ErrorCode::Internal,
                                &prefix.resolved_address,
                                &format!(
                                    "the listing exceeded this backend's \
                                     {LIST_ITEM_BUDGET}-entry budget for a single call and \
                                     the store has more to send; narrow the prefix — and if \
                                     this is one directory level with more than \
                                     {LIST_ITEM_CEILING} direct children, there is no narrower \
                                     request and the shape cannot be listed through the Layer"
                                ),
                            ));
                        }
                        if pages >= LIST_PAGE_BUDGET {
                            return Err(refuse_partial_listing(
                                ErrorCode::Internal,
                                &prefix.resolved_address,
                                &format!(
                                    "the listing exceeded this backend's \
                                     {LIST_PAGE_BUDGET}-response budget for a single call \
                                     without completing; the store may be paging without \
                                     making progress"
                                ),
                            ));
                        }
                        continuation = Some(token.to_string());
                    }
                    _ if output.is_truncated() == Some(true) => {
                        return Err(refuse_partial_listing(
                            ErrorCode::Transient,
                            &prefix.resolved_address,
                            "the store reported the listing as truncated but offered no \
                             continuation token to resume from",
                        ));
                    }
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
            "s3.list_versions",
            op = "list",
            plugin = "s3",
            object.address = %RedactedUrl(&target.resolved_address),
        );
        race_cancel(
            cancel.as_ref(),
            async move {
                let parts = self.parse_target(&target)?;
                self.resolve_credentials(None)?;
                let mut request = self
                    .unsigned_capable_client()
                    .list_object_versions()
                    .bucket(&self.config.bucket);
                if !parts.key.is_empty() {
                    request = request.prefix(&parts.key);
                }
                if let Some(max_results) = opts.max_results {
                    request = request.max_keys(i32::try_from(max_results).unwrap_or(i32::MAX));
                }
                if let Some(token) = opts.page_token.as_ref() {
                    if let Some((key, version)) = token.split_once('|') {
                        if !key.is_empty() {
                            request = request.key_marker(key);
                        }
                        if !version.is_empty() {
                            request = request.version_id_marker(version);
                        }
                    } else {
                        request = request.key_marker(token);
                    }
                }
                request = apply_request_payer!(request, self.config);
                let output = request
                    .send()
                    .await
                    .map_err(|err| self.map_store_error("s3 list_versions", err))?;
                let mut base_address = target.resolved_address.clone();
                base_address.set_query(None);
                base_address.set_fragment(None);
                let mut items = Vec::new();
                for version in output.versions() {
                    if version.key() != Some(parts.key.as_str()) {
                        continue;
                    }
                    // S3 ListObjectVersions emits "null" for entries from a
                    // non-versioned bucket; an entry without an id can't be
                    // addressed via a query-pin and is skipped.
                    let Some(version_id) = version.version_id() else {
                        continue;
                    };
                    let mtime = version.last_modified().and_then(datetime_to_system_time);
                    let address = address::with_query_pair(&base_address, "versionId", version_id)?;
                    items.push(ObjectInfo {
                        address,
                        kind: ObjectKind::File,
                        etag: version
                            .e_tag()
                            .map(|value| value.trim_matches('"').to_string()),
                        version: Some(version_id.to_string()),
                        size: version.size().and_then(|n| u64::try_from(n).ok()),
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

    pub async fn get_latest_version(
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
                self.resolve_credentials(None)?;
                let pinned = address_version_id(&target.resolved_address);
                let Some(output) = self.head_object(&parts.key, pinned.as_deref()).await? else {
                    return Err(Error::new(
                        ErrorCode::NotFound,
                        format!("S3 object '{}' not found", parts.key),
                    ));
                };
                let info = object_info_from_head_output(&target.resolved_address, &output);
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

    pub async fn watch_directory(
        &self,
        prefix: ResolvedTarget,
        opts: ovstorage_plugin::WatchDirectoryOptions,
        effective_cadence: Duration,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::BackendChangeStream> {
        crate::subscription::watch_directory(self, prefix, opts, effective_cadence, cancel).await
    }

    pub async fn create_directory(
        &self,
        target: ResolvedTarget,
        _opts: CreateDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<BackendItemInfo> {
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_target(&target)?;
            self.resolve_credentials(None)?;
            let key = directory_marker_key(&parts.key)?;
            let mut request = self
                .signed_client()?
                .put_object()
                .bucket(&self.config.bucket)
                .key(&key)
                .body(ByteStream::from(Vec::new()));
            request = apply_request_payer!(request, self.config);
            let output = request
                .send()
                .await
                .map_err(|err| map_sdk_error("s3 create_directory", err))?;
            Ok(BackendItemInfo {
                kind: ObjectKind::DirectoryMarker,
                etag: output
                    .e_tag()
                    .map(|value| value.trim_matches('"').to_string()),
                version: output.version_id().map(str::to_string),
                size: Some(0),
                mtime: None,
                ..BackendItemInfo::default()
            })
        })
        .await
    }

    pub async fn delete_directory(
        &self,
        target: ResolvedTarget,
        _opts: DeleteDirectoryOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<()> {
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_target(&target)?;
            self.resolve_credentials(None)?;
            let key = directory_marker_key(&parts.key)?;
            let mut request = self
                .signed_client()?
                .delete_object()
                .bucket(&self.config.bucket)
                .key(&key);
            request = apply_request_payer!(request, self.config);
            // delete_directory is idempotent: a missing marker is success.
            match request.send().await {
                Ok(_) => Ok(()),
                Err(err) if err.raw_response().map(|resp| resp.status().as_u16()) == Some(404) => {
                    Ok(())
                }
                Err(err) => Err(map_sdk_error("s3 delete_directory", err)),
            }
        })
        .await
    }

    pub async fn copy(
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
                self.resolve_credentials(None)?;
                let src_version = address_version_id(&src.resolved_address);
                let mut request = self
                    .signed_client()?
                    .copy_object()
                    .bucket(&self.config.bucket)
                    .key(&dest_parts.key)
                    .copy_source(copy_source_header(&src_parts, src_version.as_deref()));
                if let Some(if_source) = opts.if_source.as_deref() {
                    request = request.copy_source_if_match(quote_etag(if_source));
                }
                match &opts.if_dest {
                    IfDestExists::Overwrite => {}
                    IfDestExists::Fail => request = request.if_none_match("*"),
                    IfDestExists::MatchEtag(etag) => request = request.if_match(quote_etag(etag)),
                }
                request = apply_request_payer!(request, self.config);
                // S3 CopyObject can return HTTP 200 with an embedded <Error>
                // body; the SDK models that as a typed error, so a success here
                // is a real copy. The new ETag/version live in the typed result.
                // `copy_source_if_match` also surfaces 412, so the remap only
                // applies when the source precondition is absent.
                let output = request.send().await.map_err(|err| {
                    Self::no_overwrite_refusal_to_already_exists(
                        map_sdk_error("s3 copy", err),
                        matches!(opts.if_dest, IfDestExists::Fail) && opts.if_source.is_none(),
                        "CopyObject",
                    )
                })?;
                let result = output.copy_object_result();
                // CopyObject echoes SSE / KMS / expiration as response headers;
                // surface them so a caller trusting the returned ObjectInfo on an
                // SSE/KMS/expiring bucket doesn't see an empty map. Storage
                // class, replication status, and object-lock are not returned by
                // CopyObject, and it echoes neither user-metadata nor checksums
                // as headers, so those stay None.
                let mut system_metadata = SystemMetadata::new();
                if let Some(sse) = output.server_side_encryption() {
                    system_metadata
                        .insert("x-amz-server-side-encryption".into(), sse.as_str().into());
                }
                if let Some(key_id) = output.ssekms_key_id() {
                    system_metadata.insert(
                        "x-amz-server-side-encryption-aws-kms-key-id".into(),
                        key_id.into(),
                    );
                }
                if let Some(algorithm) = output.sse_customer_algorithm() {
                    system_metadata.insert(
                        "x-amz-server-side-encryption-customer-algorithm".into(),
                        algorithm.into(),
                    );
                }
                if let Some(enabled) = output.bucket_key_enabled() {
                    system_metadata.insert(
                        "x-amz-server-side-encryption-bucket-key-enabled".into(),
                        enabled.to_string(),
                    );
                }
                if let Some(expiration) = output.expiration() {
                    system_metadata.insert("x-amz-expiration".into(), expiration.into());
                }
                let info = ObjectInfo {
                    address: dest.resolved_address.clone(),
                    kind: ObjectKind::File,
                    etag: result
                        .and_then(|r| r.e_tag())
                        .map(|value| value.trim_matches('"').to_string()),
                    version: output.version_id().map(str::to_string),
                    size: None,
                    mtime: result
                        .and_then(|r| r.last_modified())
                        .and_then(datetime_to_system_time),
                    checksums: ChecksumSet::default(),
                    effective_permissions: None,
                    system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
                    user_metadata: None,
                    modified_by: None,
                };
                Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
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
                    match self.delete(src.clone(), delete_opts, cancel).await {
                        Ok(()) => {}
                        // The source is already gone — that is the state a
                        // rename produces, so the operation succeeded.
                        Err(err) if err.code() == ErrorCode::NotFound => {}
                        Err(err) => {
                            // The destination is committed, so this is a
                            // partial rename, not an internal fault: the object
                            // exists at both addresses and the caller has to
                            // reconcile. `Internal` reads as "the library
                            // broke" and says nothing about the state left
                            // behind.
                            return Err(Error::new(
                                ErrorCode::CommitAmbiguous,
                                format!(
                                    "S3 rename copied to destination but failed to delete source: {}",
                                    err.message()
                                ),
                            )
                            .with_next_action(
                                "The destination is committed. Whether the \
                                 source was deleted is unknown — a delete can \
                                 commit and still report failure if its \
                                 response is lost. Inspect both addresses \
                                 before deleting either one.",
                            ));
                        }
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

    pub async fn update_metadata(
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
            self.resolve_credentials(None)?;
            // Before the read half: this is the one mutation that begins with
            // a `HeadObject`, which an anonymous connection CAN serve, so the
            // caller would otherwise spend a round trip and be handed the
            // head's error. See `reject_anonymous_mutation`.
            self.reject_anonymous_mutation()?;
            let version_id = address_version_id(&target.resolved_address);
            let Some(head) = self.head_object(&parts.key, version_id.as_deref()).await? else {
                return Err(Error::new(
                    ErrorCode::NotFound,
                    format!("S3 object '{}' not found", parts.key),
                ));
            };
            let existing = user_metadata_from_map(head.metadata()).unwrap_or_default();
            let mut desired = merge_metadata(
                &existing,
                &opts.user_metadata_set,
                &opts.user_metadata_remove,
            );
            if let Some(message) = opts.message.as_deref().filter(|m| !m.is_empty()) {
                desired.retain(|(k, _)| k != "x-ov-message");
                desired.push(("x-ov-message".to_string(), message.to_string()));
            }
            // Apply the merged metadata via a self-copy with REPLACE directive.
            let mut metadata_map: HashMap<String, String> = HashMap::new();
            for (key, value) in &desired {
                metadata_map.insert(key.to_ascii_lowercase(), value.clone());
            }
            let mut request = self
                .signed_client()?
                .copy_object()
                .bucket(&self.config.bucket)
                .key(&parts.key)
                .copy_source(copy_source_header(&parts, version_id.as_deref()))
                .metadata_directive(MetadataDirective::Replace)
                .set_metadata(Some(metadata_map));
            if let Some(if_match) = opts.if_match.as_deref() {
                request = request.copy_source_if_match(quote_etag(if_match));
            }
            request = apply_request_payer!(request, self.config);
            let output = request
                .send()
                .await
                .map_err(|err| map_sdk_error("s3 update_metadata", err))?;
            let result = output.copy_object_result();
            Ok(BackendItemInfo {
                kind: ObjectKind::File,
                etag: result
                    .and_then(|r| r.e_tag())
                    .map(|value| value.trim_matches('"').to_string()),
                version: output.version_id().map(str::to_string),
                size: None,
                mtime: result.and_then(|r| r.last_modified()).and_then(datetime_to_system_time),
                ..BackendItemInfo::default()
            })
        })
        .await
    }

    /// Ask the store what the caller may do, by provoking the answer and
    /// classifying the HTTP status (success / 401-403 / 404 / other).
    ///
    /// An object target uses `HeadObject` on both connection shapes. **A bucket
    /// target is probed differently depending on the shape**, because the two
    /// are asking different questions. `GetBucketPolicyStatus` answers "what is
    /// my standing with this bucket's configuration", which is what a
    /// credentialed principal wants and a permission an account routinely
    /// holds. An anonymous caller essentially never holds it — not even on a
    /// bucket whose objects the whole world can read — so asking it reports
    /// `allowed: false` for the very deployment that connection shape exists to
    /// serve. A bounded `ListObjectsV2` asks something meaningful there instead:
    /// may the anonymous principal enumerate this bucket? `max_keys(1)` keeps
    /// it to one round trip and one key.
    ///
    /// That is not a strictly better probe, and the residual is worth naming:
    /// on a bucket granting `s3:GetObject` to `*` but not `s3:ListBucket`, it
    /// reports the ROOT as unreadable while every object under it reads. That
    /// is the same understatement `GetBucketPolicyStatus` makes, moved to a
    /// narrower half of the space — a public bucket that cannot be listed is
    /// less useful to a browser than one that can, but it is not an empty case.
    /// Answering "may I read the root" exactly would need a probe S3 does not
    /// offer.
    ///
    /// The decision comes from one probe rather than from each requested
    /// permission separately, on both shapes. An anonymous connection is the
    /// more accurate of the two, because its mutating operations are refused
    /// before the wire and reported denied without asking.
    ///
    /// The object arm resolves the address's own shape before classifying:
    /// a `?versionId=` address pins the HEAD to that version, and a `key/`
    /// address that has no marker object falls back to the same bounded prefix
    /// probe [`Self::stat`] uses. Without that, this operation would answer
    /// about a different resource than the one it was asked about — and would
    /// report a `DirectoryInferred` address returned by this backend's own
    /// `list` as absent.
    pub async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        race_cancel(cancel.as_ref(), async move {
            let parts = self.parse_target(&target)?;
            self.resolve_credentials(None)?;
            let client = self.unsigned_capable_client();
            // Provoke the answer and classify by the status — see the doc
            // comment for why the bucket arm differs by connection shape.
            let probe_status: Option<u16> = if parts.key.is_empty() {
                if self.is_anonymous {
                    let mut request = client
                        .list_objects_v2()
                        .bucket(&self.config.bucket)
                        .max_keys(1);
                    request = apply_request_payer!(request, self.config);
                    match request.send().await {
                        Ok(_) => Some(200),
                        Err(err) => err.raw_response().map(|resp| resp.status().as_u16()),
                    }
                } else {
                    match client
                        .get_bucket_policy_status()
                        .bucket(&self.config.bucket)
                        .send()
                        .await
                    {
                        Ok(_) => Some(200),
                        Err(err) => err.raw_response().map(|resp| resp.status().as_u16()),
                    }
                }
            } else {
                // The probe must ask about the resource the address names, not
                // about a similarly-spelled one: a `?versionId=` address asks
                // after that version, and a `key/` address is the shape this
                // backend's own `list` hands back as `DirectoryInferred`, which
                // usually has no marker object to HEAD. `stat` resolves both the
                // same way; answering the bare HEAD would report an address this
                // backend just returned as absent.
                let version_id = address_version_id(&target.resolved_address);
                let mut request = client
                    .head_object()
                    .bucket(&self.config.bucket)
                    .key(&parts.key);
                if let Some(version) = version_id.as_deref() {
                    request = request.version_id(version);
                }
                request = apply_request_payer!(request, self.config);
                let head_status = match request.send().await {
                    Ok(_) => Some(200),
                    Err(err) => err.raw_response().map(|resp| resp.status().as_u16()),
                };
                if head_status == Some(404) && parts.key.ends_with('/') && version_id.is_none() {
                    match self
                        .flat_directory_probe(&parts.key, &target.resolved_address)
                        .await
                    {
                        Ok(FlatDirectoryProbe::Marker(_) | FlatDirectoryProbe::Inferred) => {
                            Some(200)
                        }
                        Ok(FlatDirectoryProbe::Missing) => head_status,
                        // A refused probe answers the access question rather
                        // than the existence one, so it joins the refusal arm
                        // below and is reported the way every refusal here is:
                        // each requested op denied, which is this operation's
                        // documented single-probe limitation rather than a
                        // claim about writing specifically. The status follows
                        // the probe's error rather than being fixed at 403 —
                        // note the anonymous restatement collapses a store's
                        // 401 into `PermissionDenied` first, on purpose, so on
                        // that connection shape the reason reads 403 whatever
                        // the store sent.
                        Err(err) if err.code() == ErrorCode::AuthRequired => Some(401),
                        Err(err) if err.code() == ErrorCode::PermissionDenied => Some(403),
                        Err(err) => return Err(err),
                    }
                } else {
                    head_status
                }
            };
            match probe_status {
                Some(status) if (200..300).contains(&status) => {
                    // An accepted probe says the caller may read. It says
                    // nothing about writing, and on an anonymous connection the
                    // answer for writing is known without asking: every
                    // mutation is refused by `signed_client` before the wire.
                    // Reporting them as allowed because a HEAD succeeded would
                    // be a confident wrong answer to the only question this
                    // operation exists to answer.
                    let denied_ops = if self.is_anonymous {
                        AccessOps {
                            read: false,
                            write: ops.write,
                            delete: ops.delete,
                            update_metadata: ops.update_metadata,
                        }
                    } else {
                        AccessOps::default()
                    };
                    let denied_any =
                        denied_ops.write || denied_ops.delete || denied_ops.update_metadata;
                    Ok(AccessDecision {
                        allowed: !denied_any,
                        denied_ops,
                        reason: denied_any.then(|| {
                            "this S3 connection is anonymous; it issues no unsigned mutations"
                                .to_string()
                        }),
                    })
                }
                Some(status @ (401 | 403)) => Ok(AccessDecision {
                    allowed: false,
                    denied_ops: ops,
                    reason: Some(format!("S3 returned HTTP {status}")),
                }),
                Some(404) => Err(Error::new(
                    ErrorCode::NotFound,
                    "S3 access target not found",
                )),
                Some(other) => Err(map_error_status(other, b"")),
                None => Err(Error::new(
                    ErrorCode::Transient,
                    "S3 check_access failed without an HTTP response",
                )),
            }
        })
        .await
    }
}

impl S3Backend {
    /// `HeadObject` via the SDK. Returns `Ok(None)` on a 404 so callers can run
    /// their not-found fallbacks (e.g. the directory-marker probe). A `HEAD` is
    /// servable unsigned, so an anonymous connection issues it too, and the
    /// bucket policy decides.
    async fn head_object(
        &self,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<Option<HeadObjectOutput>> {
        let mut request = self
            .unsigned_capable_client()
            .head_object()
            .bucket(&self.config.bucket)
            .key(key);
        if let Some(version) = version_id {
            request = request.version_id(version);
        }
        request = apply_request_payer!(request, self.config);
        match request.send().await {
            Ok(output) => Ok(Some(output)),
            Err(err) if err.raw_response().map(|resp| resp.status().as_u16()) == Some(404) => {
                Ok(None)
            }
            Err(err) => Err(self.map_store_error("s3 head_object", err)),
        }
    }

    async fn flat_directory_probe(
        &self,
        prefix_key: &str,
        address: &Url,
    ) -> Result<FlatDirectoryProbe> {
        let mut request = self
            .unsigned_capable_client()
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .delimiter("/")
            .max_keys(2)
            .prefix(prefix_key);
        request = apply_request_payer!(request, self.config);
        let output = request
            .send()
            .await
            .map_err(|err| self.map_store_error("s3 list (directory probe)", err))?;
        if let Some(marker) = output
            .contents()
            .iter()
            .find(|object| object.key() == Some(prefix_key))
        {
            let mut system_metadata: SystemMetadata = SystemMetadata::new();
            if let Some(class) = marker.storage_class() {
                system_metadata.insert("x-amz-storage-class".into(), class.as_str().into());
            }
            return Ok(FlatDirectoryProbe::Marker(Box::new(ObjectInfo {
                address: address.clone(),
                kind: ObjectKind::DirectoryMarker,
                etag: marker
                    .e_tag()
                    .map(|value| value.trim_matches('"').to_string()),
                version: None,
                size: marker.size().and_then(|n| u64::try_from(n).ok()),
                mtime: marker.last_modified().and_then(datetime_to_system_time),
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
                user_metadata: None,
                modified_by: None,
            })));
        }
        let mut descendant_seen = false;
        for object in output.contents() {
            let Some(key) = object.key() else {
                continue;
            };
            if !key.starts_with(prefix_key) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "S3 returned object key '{key}' outside the requested directory prefix '{prefix_key}'"
                    ),
                ));
            }
            descendant_seen = true;
        }
        for prefix in output.common_prefixes() {
            let Some(prefix) = prefix.prefix() else {
                continue;
            };
            if prefix == prefix_key {
                continue;
            }
            if !prefix.starts_with(prefix_key) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "S3 returned common prefix '{prefix}' outside the requested directory prefix '{prefix_key}'"
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

    /// The documented `IfDestExists::Fail` exists-refusal for `op`.
    fn already_exists_refusal(op: &str) -> Error {
        Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "S3 {op} refused: destination already exists and IfDestExists::Fail was requested"
            ),
        )
    }

    /// Post-map the no-overwrite (`If-None-Match: *`) 412 refusal to the
    /// documented `AlreadyExists`. `unambiguous` is the caller's
    /// attribution guard: `IfDestExists::Fail` was requested AND no other
    /// precondition (source etag / `if_match`) could also have produced the
    /// 412 — a combined refusal cannot be attributed and keeps
    /// `PreconditionFailed`.
    fn no_overwrite_refusal_to_already_exists(mapped: Error, unambiguous: bool, op: &str) -> Error {
        if unambiguous && mapped.code() == ErrorCode::PreconditionFailed {
            return Self::already_exists_refusal(op);
        }
        mapped
    }

    async fn put_object_inline(
        &self,
        key: &str,
        body: &[u8],
        opts: &WriteOptions,
    ) -> Result<ObjectInfo> {
        let mut request = self
            .signed_client()?
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(ByteStream::from(body.to_vec()));
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => request = request.if_none_match("*"),
            IfDestExists::MatchEtag(etag) => request = request.if_match(quote_etag(etag)),
        }
        if let Some(metadata) = opts.user_metadata.as_ref() {
            for (k, v) in metadata {
                request = request.metadata(k.to_ascii_lowercase(), v.clone());
            }
        }
        request = apply_request_payer!(request, self.config);
        let output = match request.send().await {
            Ok(output) => output,
            Err(err) if err.raw_response().map(|resp| resp.status().as_u16()) == Some(412) => {
                // A 412 on the `If-None-Match: *` path is the no-overwrite
                // refusal: the destination exists (`IfDestExists::Fail`
                // contract → `AlreadyExists`). Only a genuine `If-Match` etag
                // precondition keeps `PreconditionFailed`.
                if matches!(opts.if_dest, IfDestExists::Fail) {
                    return Err(Self::already_exists_refusal("PutObject"));
                }
                // Carry the response ETag through so the caller can re-issue the
                // conditional write with the current precondition.
                let new_etag = err
                    .raw_response()
                    .and_then(|resp| resp.headers().get("etag"))
                    .map(|value| value.trim_matches('"').to_string());
                return Err(Error::new(
                    ErrorCode::PreconditionFailed,
                    "S3 PutObject precondition failed",
                )
                .with_context(ErrorContext::Identity { new_etag }));
            }
            Err(err) => return Err(map_sdk_error("s3 put_object", err)),
        };
        let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
        let resolved = address::join_relative(&bucket_root, key)?;
        Ok(ObjectInfo {
            address: resolved,
            kind: ObjectKind::File,
            etag: output
                .e_tag()
                .map(|value| value.trim_matches('"').to_string()),
            version: output.version_id().map(str::to_string),
            size: Some(body.len() as u64),
            // S3 PutObject responses carry no Last-Modified header.
            mtime: None,
            checksums: checksums_from_parts(
                output.checksum_sha256(),
                output.checksum_sha1(),
                output.checksum_crc32(),
                output.checksum_crc32_c(),
                output.checksum_crc64_nvme(),
            ),
            effective_permissions: None,
            system_metadata: None,
            user_metadata: opts.user_metadata.clone(),
            modified_by: None,
        })
    }

    async fn create_multipart_upload(&self, key: &str, opts: &WriteOptions) -> Result<String> {
        let mut request = self
            .signed_client()?
            .create_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key);
        if let Some(metadata) = opts.user_metadata.as_ref() {
            for (k, v) in metadata {
                request = request.metadata(k.to_ascii_lowercase(), v.clone());
            }
        }
        request = apply_request_payer!(request, self.config);
        let output = request
            .send()
            .await
            .map_err(|err| map_sdk_error("s3 create_multipart_upload", err))?;
        let upload_id = output
            .upload_id()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    "S3 CreateMultipartUpload returned no UploadId",
                )
            })?
            .to_string();
        info!(plugin = "s3", op = "write", "s3 multipart upload initiated");
        Ok(upload_id)
    }

    async fn build_single_put_redirect(
        &self,
        key: &str,
        len: u64,
        opts: &WriteOptions,
    ) -> Result<WriteRedirect> {
        // Conditional + x-amz-meta headers are signed into the presigned URL by
        // the SDK; they are also echoed in `request.headers` so the follower
        // re-sends them (without them the signature would not match).
        let mut request = self
            .signed_client()?
            .put_object()
            .bucket(&self.config.bucket)
            .key(key);
        match &opts.if_dest {
            IfDestExists::Overwrite => {}
            IfDestExists::Fail => request = request.if_none_match("*"),
            IfDestExists::MatchEtag(etag) => request = request.if_match(quote_etag(etag)),
        }
        if let Some(metadata) = opts.user_metadata.as_ref() {
            for (k, v) in metadata {
                request = request.metadata(k.to_ascii_lowercase(), v.clone());
            }
        }
        request = apply_request_payer!(request, self.config);
        let expires_at = SystemTime::now() + Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64);
        let presigned = request
            .presigned(presign_config()?)
            .await
            .map_err(|err| map_sdk_error("s3 write_redirect presign", err))?;
        let url = presigned.uri().to_string();
        let headers: Vec<(String, String)> = presigned
            .headers()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        let scope = RedirectScope {
            physical_url_prefix: redirect_prefix(&url)?,
            operations: AccessOps {
                write: true,
                ..AccessOps::default()
            },
            expires_at,
            // SigV4 query presign over one key, one method, one TTL.
            credential: RedirectCredential::Request,
        };
        Ok(WriteRedirect {
            request: HttpRequest {
                method: presigned.method().to_string(),
                url,
                headers,
            },
            body_source: RedirectBodySource::UserBytes { offset: 0, len },
            result_capture: ResultCapture {
                headers: vec!["etag".into(), "x-amz-version-id".into()],
                body_max_bytes: 0,
            },
            expires_at: scope.expires_at,
            scope,
            audit_id: format!("s3-put-{key}"),
            policy_epoch: 0,
        })
    }

    async fn build_part_batch(
        &self,
        continuation: &MultipartContinuation,
        total_bytes: u64,
    ) -> Result<Vec<WriteRedirect>> {
        // Balanced base/remainder split; offsets are a prefix sum so the
        // final part lines up exactly with `total_bytes` even when the
        // total is not a multiple of the part count.
        let sizes = part_sizes(total_bytes, continuation.total_parts);
        let expires_at = SystemTime::now() + Duration::from_secs(DEFAULT_PRESIGN_TTL_SECS as u64);
        let mut redirects = Vec::with_capacity(continuation.total_parts as usize);
        let mut offset: u64 = 0;
        for (part_index, &length) in sizes.iter().enumerate() {
            let part_number = (part_index as u32) + 1;
            let mut request = self
                .signed_client()?
                .upload_part()
                .bucket(&self.config.bucket)
                .key(&continuation.key)
                .upload_id(&continuation.upload_id)
                .part_number(part_number as i32);
            request = apply_request_payer!(request, self.config);
            let presigned = request
                .presigned(presign_config()?)
                .await
                .map_err(|err| map_sdk_error("s3 upload_part presign", err))?;
            let url = presigned.uri().to_string();
            let headers: Vec<(String, String)> = presigned
                .headers()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect();
            let scope = RedirectScope {
                physical_url_prefix: redirect_prefix(&url)?,
                operations: AccessOps {
                    write: true,
                    ..AccessOps::default()
                },
                expires_at,
                // SigV4 query presign over one UploadPart: this key, this
                // upload id, this part number.
                credential: RedirectCredential::Request,
            };
            redirects.push(WriteRedirect {
                request: HttpRequest {
                    method: presigned.method().to_string(),
                    url,
                    headers,
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
        key: &str,
        continuation: &MultipartContinuation,
    ) -> Result<ObjectInfo> {
        // A part missing its ETag would be silently dropped from the completion
        // list while `total_size` (below) still sums every part — a truncated
        // object with an over-reported size, and no error. Not reachable in
        // normal flow (commit_streaming_part / the redirect path always set
        // Some(etag)), but `MultipartContinuation::decode()` does not validate
        // per-part ETag presence, so a corrupted/crafted continuation token
        // round-tripped through the host could reach here. Returning an error is
        // enough to abort: both callers abort on any `Err` from this method, and
        // aborting here as well would issue a second `AbortMultipartUpload`
        // against an upload the first one just removed.
        let mut parts: Vec<CompletedPart> = Vec::with_capacity(continuation.parts.len());
        for part in &continuation.parts {
            let Some(etag) = part.etag.as_ref() else {
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!(
                        "S3 multipart part {} is missing its ETag; the upload will not be completed",
                        part.part_number
                    ),
                ));
            };
            parts.push(
                CompletedPart::builder()
                    .part_number(part.part_number as i32)
                    .e_tag(etag)
                    .build(),
            );
        }
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        info!(
            plugin = "s3",
            op = "write",
            "s3 multipart upload completing"
        );
        let mut request = self
            .signed_client()?
            .complete_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(&continuation.upload_id)
            .multipart_upload(completed);
        if let Some(if_match) = continuation.if_match.as_ref() {
            request = request.if_match(quote_etag(if_match));
        }
        if continuation.no_overwrite {
            request = request.if_none_match("*");
        }
        request = apply_request_payer!(request, self.config);
        // The SDK detects an HTTP-200 `<Error>` envelope and surfaces it as a
        // typed error; `map_sdk_error` classifies the modeled code.
        // `continuation.if_match` and `no_overwrite` are mutually exclusive,
        // so the no-overwrite complete's 412 is unambiguous.
        let output = request.send().await.map_err(|err| {
            Self::no_overwrite_refusal_to_already_exists(
                map_sdk_error("s3 complete_multipart_upload", err),
                continuation.no_overwrite,
                "CompleteMultipartUpload",
            )
        })?;
        let etag = output
            .e_tag()
            .map(|value| value.trim_matches('"').to_string());
        if etag.is_none() {
            return Err(Error::new(
                ErrorCode::Internal,
                "S3 CompleteMultipartUpload returned 2xx but the response did not include an ETag",
            ));
        }
        let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
        let resolved = address::join_relative(&bucket_root, key)?;
        let total_size: u64 = continuation.parts.iter().map(|p| p.byte_length).sum();
        // Rebuilt from the continuation the caller echoed back, so this map is
        // the caller's shape. The reserved attribution key inside it is put
        // right by the host's attribution overlay, which is the one place every
        // `continue_write` result passes through; what S3 *persisted* was bound
        // at `CreateMultipartUpload` and the caller never held it.
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
            etag,
            version: output.version_id().map(str::to_string),
            size: Some(total_size),
            mtime: None,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: None,
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
        self.resolve_credentials(None)?;
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
                .put_object_inline(&parts.key, &first_part, &opts)
                .await?;
            return Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }));
        }
        let _ = target;
        let upload_id = self.create_multipart_upload(&parts.key, &opts).await?;
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
                            &mut continuation,
                            &mut next_part_number,
                            &mut total_bytes,
                            &mut buffer,
                        )
                        .await?;
                    }
                }
                Some(Err(err)) => {
                    self.abort_multipart_upload_best_effort(
                        &continuation.key,
                        &continuation.upload_id,
                    )
                    .await;
                    return Err(err);
                }
            }
            if let Err(err) = ensure_streaming_part_limit(next_part_number) {
                self.abort_multipart_upload_best_effort(&continuation.key, &continuation.upload_id)
                    .await;
                return Err(err);
            }
        }
        // Final part may be any size > 0 (S3 exemption).
        self.commit_streaming_part(
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
            .complete_multipart_upload(&continuation.key, &continuation)
            .await
        {
            Ok(info) => info,
            Err(err) => {
                self.abort_multipart_upload_best_effort(&continuation.key, &continuation.upload_id)
                    .await;
                return Err(err);
            }
        };
        Ok(ovstorage_plugin::WriteStep::Done(WriteResult { info }))
    }

    /// Upload `buffer` as the next part; aborts the upload on failure. No-op when empty.
    async fn commit_streaming_part(
        &self,
        continuation: &mut MultipartContinuation,
        next_part_number: &mut u32,
        total_bytes: &mut u64,
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        let part_number = *next_part_number;
        let byte_length = buffer.len() as u64;
        debug!(
            plugin = "s3",
            op = "write",
            retry.attempt = 1,
            "s3 multipart part upload starting",
            // part number is logged as a flat field; not a standard namespace field
        );
        // Hand the part's allocation to the upload instead of copying it, and
        // leave a fresh same-capacity buffer behind for the next part — avoids
        // a per-part memcpy of the whole (~8 MiB) part.
        let cap = buffer.capacity();
        let part = std::mem::replace(buffer, Vec::with_capacity(cap));
        let upload_result = self
            .upload_part_streamed(continuation, part_number, part)
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
                self.abort_multipart_upload_best_effort(&continuation.key, &continuation.upload_id)
                    .await;
                return Err(err);
            }
        };
        continuation.parts.push(MultipartPart {
            part_number,
            byte_offset: *total_bytes,
            byte_length,
            etag: Some(etag),
        });
        *total_bytes += byte_length;
        *next_part_number += 1;
        Ok(())
    }

    /// Direct signed S3 UploadPart; returns the ETag CompleteMultipartUpload
    /// requires. Takes the part `body` by value so its allocation moves
    /// straight into the `ByteStream` without a copy.
    async fn upload_part_streamed(
        &self,
        continuation: &MultipartContinuation,
        part_number: u32,
        body: Vec<u8>,
    ) -> Result<String> {
        let mut request = self
            .signed_client()?
            .upload_part()
            .bucket(&self.config.bucket)
            .key(&continuation.key)
            .upload_id(&continuation.upload_id)
            .part_number(part_number as i32)
            .body(ByteStream::from(body));
        request = apply_request_payer!(request, self.config);
        let output = request
            .send()
            .await
            .map_err(|err| map_sdk_error("s3 upload_part", err))?;
        output
            .e_tag()
            .map(|value| value.trim_matches('"').to_string())
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::Internal,
                    format!("S3 UploadPart {part_number} response did not include an ETag header"),
                )
            })
    }

    async fn abort_multipart_upload(&self, key: &str, upload_id: &str) -> Result<AbortOutcome> {
        let mut request = self
            .signed_client()?
            .abort_multipart_upload()
            .bucket(&self.config.bucket)
            .key(key)
            .upload_id(upload_id);
        request = apply_request_payer!(request, self.config);
        match request.send().await {
            Ok(_) => Ok(AbortOutcome::Aborted),
            // Match the modeled code, not the raw 404. S3 answers 404 for a
            // missing bucket too, and an S3-compatible endpoint behind a proxy
            // answers it for an unrouted path; only `NoSuchUpload` says anything
            // about the upload id. Everything else stays an error.
            Err(err)
                if {
                    use aws_sdk_s3::error::ProvideErrorMetadata as _;
                    err.as_service_error()
                        .and_then(|svc| svc.code())
                        .is_some_and(|code| code == "NoSuchUpload")
                } =>
            {
                Ok(AbortOutcome::NotResolved)
            }
            Err(err) => Err(map_sdk_error("s3 abort_multipart_upload", err)),
        }
    }

    /// Abort from an error path, where the caller is already returning a more
    /// specific failure. The abort's own outcome stays unpropagated but is
    /// logged: an abort that fails without a trace leaves a multipart upload
    /// that is billed, invisible, and reclaimed only by a bucket lifecycle
    /// rule.
    ///
    /// `NoSuchUpload` gets its own line rather than being folded into success.
    /// It establishes exactly one thing — the id did not resolve under the key
    /// this call sent — which happens when the id belongs to a different object
    /// (the key comes from the authorized address, the id from the continuation)
    /// and equally when the upload was already aborted or completed. The line
    /// says that and stops; nothing available here distinguishes the two.
    ///
    /// The key rides the line rather than being left to the enclosing span.
    /// Every span in this file is a `debug_span!`, so under the default `INFO`
    /// filter it is `Span::none()` and records no fields — an operator would
    /// otherwise get this warning with no object on it at all. The value is safe
    /// to print: since `continue_write` derives it, it is the key of the
    /// authorized address, and `RedactedUrl` — the house form for addresses —
    /// preserves the path anyway.
    async fn abort_multipart_upload_best_effort(&self, key: &str, upload_id: &str) {
        match self.abort_multipart_upload(key, upload_id).await {
            Ok(AbortOutcome::Aborted) => {}
            Ok(AbortOutcome::NotResolved) => tracing::warn!(
                target: "ovstorage::s3",
                upload_id = %UploadIdPrefix(upload_id),
                object.key = %key,
                "S3 AbortMultipartUpload answered NoSuchUpload: the upload id did \
                 not resolve under the key this call sent. If the upload is still \
                 live it was not reached by this abort",
            ),
            Err(err) => tracing::warn!(
                target: "ovstorage::s3",
                error = %err,
                upload_id = %UploadIdPrefix(upload_id),
                "S3 AbortMultipartUpload failed; the multipart upload may be orphaned",
            ),
        }
    }
}

/// Bounds a caller-supplied upload id before it reaches a log field. On the
/// broker's client-driven route the id comes out of the echoed continuation and
/// `decode` validates only the tag, so an unbounded copy would let a caller
/// choose the contents and the size of a WARN record it can trigger without any
/// provider round trip. A prefix is enough to correlate with the provider's own
/// records.
struct UploadIdPrefix<'a>(&'a str);

impl std::fmt::Display for UploadIdPrefix<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const KEEP: usize = 24;
        match self.0.char_indices().nth(KEEP) {
            Some((cut, _)) => write!(f, "{}…", &self.0[..cut]),
            None => f.write_str(self.0),
        }
    }
}

/// What an `AbortMultipartUpload` answered. `NotResolved` is named for the
/// observation — S3 returned `NoSuchUpload`, so the id did not resolve under the
/// key sent — and not for any conclusion about why; see
/// [`S3Backend::abort_multipart_upload_best_effort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbortOutcome {
    Aborted,
    NotResolved,
}

/// Build the `x-amz-copy-source` value (`/{bucket}/{key}[?versionId=…]`). The
/// SDK sends this header verbatim (its docs require the caller to URL-encode
/// it), so the key path and the versionId are percent-encoded here via the
/// same `config` encoders the anonymous-read path uses — one encoding stack,
/// two callers.
fn copy_source_header(parts: &S3AddressParts, version_id: Option<&str>) -> String {
    let mut out = format!("/{}{}", parts.bucket, canonical_path(&parts.key));
    if let Some(version) = version_id {
        out.push_str("?versionId=");
        out.push_str(&crate::config::encode_query_token(version));
    }
    out
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
/// Derive the redirect-scope `physical_url_prefix` (`scheme://authority/`) from
/// a (presigned or plain) object URL. The host uses this to gate which URLs a
/// follower may fetch, so it must match the authority the SDK actually signed.
fn redirect_prefix(url: &str) -> Result<String> {
    let parsed = Url::parse(url).map_err(|err| {
        Error::new(
            ErrorCode::Internal,
            format!("s3 read: object URL is not valid: {err}"),
        )
    })?;
    let scheme = parsed.scheme();
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::new(ErrorCode::Internal, "s3 read: object URL has no host"))?;
    match parsed.port() {
        Some(port) => Ok(format!("{scheme}://{host}:{port}/")),
        None => Ok(format!("{scheme}://{host}/")),
    }
}

/// Build the `Range:` header value for a `ReadOptions.range`. Returns
/// `Ok(None)` when no range is requested. Rejects inverted ranges
/// (`end_inclusive < start`) with `InvalidArgument` so an inverted
/// slice can't panic the host-side follower — a clean typed error
/// instead of a `catch_unwind`-converted `Internal`.
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
        // Kept in lockstep with `system_metadata_from_head` (the HEAD/stat
        // path); both feed the same externally-visible `system_metadata` map.
        system_metadata_headers: vec![
            "x-amz-storage-class".into(),
            "x-amz-server-side-encryption".into(),
            "x-amz-server-side-encryption-aws-kms-key-id".into(),
            "x-amz-server-side-encryption-customer-algorithm".into(),
            "x-amz-server-side-encryption-bucket-key-enabled".into(),
            "x-amz-replication-status".into(),
            "x-amz-expiration".into(),
            "x-amz-restore".into(),
            "x-amz-archive-status".into(),
            "x-amz-website-redirect-location".into(),
            "x-amz-object-lock-mode".into(),
            "x-amz-object-lock-retain-until-date".into(),
            "x-amz-object-lock-legal-hold".into(),
            "x-amz-mp-parts-count".into(),
            "x-amz-missing-meta".into(),
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

/// Convert an SDK `DateTime` (S3 `Last-Modified`) to `SystemTime`.
fn datetime_to_system_time(dt: &aws_sdk_s3::primitives::DateTime) -> Option<SystemTime> {
    SystemTime::try_from(*dt).ok()
}

/// Build a `ChecksumSet` from the typed `x-amz-checksum-*` fields S3 returns
/// (only populated when the object was stored with a checksum algorithm).
fn checksums_from_parts(
    sha256: Option<&str>,
    sha1: Option<&str>,
    crc32: Option<&str>,
    crc32c: Option<&str>,
    crc64nvme: Option<&str>,
) -> ChecksumSet {
    let mut out = ChecksumSet::default();
    if let Some(value) = sha256 {
        out.insert(ChecksumAlgorithm::sha256(), value.as_bytes().to_vec());
    }
    if let Some(value) = sha1
        && let Ok(algorithm) = ChecksumAlgorithm::new("sha1")
    {
        out.insert(algorithm, value.as_bytes().to_vec());
    }
    if let Some(value) = crc32
        && let Ok(algorithm) = ChecksumAlgorithm::new("crc32")
    {
        out.insert(algorithm, value.as_bytes().to_vec());
    }
    if let Some(value) = crc32c {
        out.insert(ChecksumAlgorithm::crc32c(), value.as_bytes().to_vec());
    }
    if let Some(value) = crc64nvme
        && let Ok(algorithm) = ChecksumAlgorithm::new("crc64nvme")
    {
        out.insert(algorithm, value.as_bytes().to_vec());
    }
    out
}

/// System (`x-amz-*`) metadata projected from a typed `HeadObjectOutput`.
///
/// `main`'s header-based collector passed through every non-meta/non-checksum
/// `x-amz-*` header; the typed SDK output exposes no raw header map, so the
/// equivalent fields are read individually from its accessors. Keep this set in
/// lockstep with `read_response_parsing`'s `system_metadata_headers` (the
/// redirect-read path), since both feed the same externally-visible
/// `system_metadata` map.
fn system_metadata_from_head(out: &HeadObjectOutput) -> Option<SystemMetadata> {
    let mut metadata = SystemMetadata::new();
    if let Some(storage_class) = out.storage_class() {
        metadata.insert("x-amz-storage-class".into(), storage_class.as_str().into());
    }
    if let Some(sse) = out.server_side_encryption() {
        metadata.insert("x-amz-server-side-encryption".into(), sse.as_str().into());
    }
    if let Some(key_id) = out.ssekms_key_id() {
        metadata.insert(
            "x-amz-server-side-encryption-aws-kms-key-id".into(),
            key_id.into(),
        );
    }
    if let Some(algorithm) = out.sse_customer_algorithm() {
        metadata.insert(
            "x-amz-server-side-encryption-customer-algorithm".into(),
            algorithm.into(),
        );
    }
    if let Some(enabled) = out.bucket_key_enabled() {
        metadata.insert(
            "x-amz-server-side-encryption-bucket-key-enabled".into(),
            enabled.to_string(),
        );
    }
    if let Some(status) = out.replication_status() {
        metadata.insert("x-amz-replication-status".into(), status.as_str().into());
    }
    if let Some(expiration) = out.expiration() {
        metadata.insert("x-amz-expiration".into(), expiration.into());
    }
    if let Some(restore) = out.restore() {
        metadata.insert("x-amz-restore".into(), restore.into());
    }
    if let Some(archive) = out.archive_status() {
        metadata.insert("x-amz-archive-status".into(), archive.as_str().into());
    }
    if let Some(redirect) = out.website_redirect_location() {
        metadata.insert("x-amz-website-redirect-location".into(), redirect.into());
    }
    if let Some(mode) = out.object_lock_mode() {
        metadata.insert("x-amz-object-lock-mode".into(), mode.as_str().into());
    }
    if let Some(retain) = out.object_lock_retain_until_date().and_then(|dt| {
        dt.fmt(aws_sdk_s3::primitives::DateTimeFormat::DateTime)
            .ok()
    }) {
        metadata.insert("x-amz-object-lock-retain-until-date".into(), retain);
    }
    if let Some(hold) = out.object_lock_legal_hold_status() {
        metadata.insert("x-amz-object-lock-legal-hold".into(), hold.as_str().into());
    }
    if let Some(parts) = out.parts_count() {
        metadata.insert("x-amz-mp-parts-count".into(), parts.to_string());
    }
    if let Some(missing) = out.missing_meta() {
        metadata.insert("x-amz-missing-meta".into(), missing.to_string());
    }
    (!metadata.is_empty()).then_some(metadata)
}

/// User metadata (`x-amz-meta-*`) from the SDK's already-stripped, lowercased map.
fn user_metadata_from_map(meta: Option<&HashMap<String, String>>) -> Option<UserMetadata> {
    let meta = meta?;
    if meta.is_empty() {
        return None;
    }
    let mut metadata = UserMetadata::new();
    for (key, value) in meta {
        metadata.insert(key.to_ascii_lowercase(), value.clone());
    }
    Some(metadata)
}

/// Build an `ObjectInfo` (kind `File`) from a typed `HeadObjectOutput`.
fn object_info_from_head_output(addr: &Url, out: &HeadObjectOutput) -> ObjectInfo {
    ObjectInfo {
        address: addr.clone(),
        kind: ObjectKind::File,
        etag: out.e_tag().map(|value| value.trim_matches('"').to_string()),
        version: out.version_id().map(str::to_string),
        size: out.content_length().and_then(|n| u64::try_from(n).ok()),
        mtime: out.last_modified().and_then(datetime_to_system_time),
        checksums: checksums_from_parts(
            out.checksum_sha256(),
            out.checksum_sha1(),
            out.checksum_crc32(),
            out.checksum_crc32_c(),
            out.checksum_crc64_nvme(),
        ),
        effective_permissions: None,
        system_metadata: system_metadata_from_head(out),
        user_metadata: user_metadata_from_map(out.metadata()),
        modified_by: None,
    }
}

/// The error a listing walk ends with when it cannot prove it saw everything.
///
/// This is the whole reason the walk exists, stated as a rule: **a short
/// listing must never be returned as if it were complete.** `S3Backend::list`
/// answers a bare `Vec<ObjectInfo>` with no truncation signal in it, so a
/// caller cannot tell a partial answer from a whole one — and the metadata
/// cache does not try: `find_in_page` reads a page with no next token as
/// authoritative and turns an absent entry into `NotFound`. Returning `Ok`
/// with what was read would therefore convert a misbehaving store into a
/// confident "that object does not exist", which is exactly the defect the
/// pagination fix removed. An error is recoverable; a false `NotFound` is not.
///
/// The `code` is the caller's, because the two ways a walk ends early are not
/// the same kind of failure and a caller acts on them differently:
///
/// - `Transient` for a store that misbehaved — reissued a token, or claimed
///   truncation with nothing to resume from. The fault is in the answer, not in
///   this process, and a retry against a healthy replica or after a restart can
///   succeed.
/// - `Internal` for all three local bounds — the two budgets and the ceiling —
///   which are this backend's own hard limits on what one call may consume
///   rather than anything the store did wrong. `LIST_ITEM_BUDGET` bounds the
///   memory the process would otherwise exhaust; `LIST_PAGE_BUDGET` bounds the
///   round trips and the token set instead of the bytes, for a store whose
///   pages are empty and so grow no memory at all; `LIST_ITEM_CEILING` bounds
///   one oversize response.
///
/// **What decides it is the retry, and it took three rulings to settle.** The
/// obvious reading is `ResourceExhausted` — a resource this backend bounds was
/// exhausted, and gRPC's own definition of that code covers genuine
/// exhaustion rather than only a quota. But retryability here is exactly bucket
/// membership by construction (`ovstorage-core/ovstorage-layer/src/errors.rs`,
/// `ErrorBucket::retryable`), `ResourceExhausted` is in one of the two
/// retryable buckets, and the shipped broker stack composes `RetryWrapper`
/// above the router at five attempts. A budget is a **fixed local bound**: the
/// same request reaches it on every attempt, so each retry re-walks the whole
/// prefix — up to five full scans and five times the allocation — to fail
/// identically. There is no code that both says "a resource was exhausted" and
/// stays out of the retryable buckets, so the choice is between an accurate
/// name and a survivable cost, and the cost wins.
///
/// `Internal` is what the taxonomy already gives for "server-side, not the
/// caller's fault, not safe to blindly retry", and
/// `docs/public/plugin-storage/CONFORMANCE.md`'s error-code table now names a
/// plugin's own hard bound alongside a plugin bug, so this is the code the spec
/// asks for rather than a local reading of it. The same choice is made by the
/// two sibling caps in this workspace — the CLI's recursive enumeration and the
/// MCP dry run, both at 100,000 entries.
///
/// `InvalidArgument` is not the alternative: `S3Layer::list` hard-sets
/// `max_results: None`, so a caller's own `max_results` slices the answer
/// without bounding the walk. A caller has a remedy — narrow the prefix — but
/// no parameter. `Unsupported` is worse still: the host reads it as equivalent
/// to a false capability bit, and `supports_list` is true.
///
/// **The real fix is neither code.** Doing 100 requests and 50 MB of work and
/// then discarding all of it is the defect underneath this; `list` returning
/// what it has with a continuation token, or streaming, is what removes it.
/// Both change the Layer/backend pagination contract, so both are filed rather
/// than built here, and the cap is the stopgap that makes the failure bounded
/// instead of fatal.
fn refuse_partial_listing(code: ErrorCode, prefix: &Url, what_happened: &str) -> Error {
    Error::new(
        code,
        format!(
            "S3 list of '{}' could not be completed: {what_happened}; refusing \
             to return a partial listing that would read as complete",
            RedactedUrl(prefix)
        ),
    )
}

fn address_version_id(addr: &Url) -> Option<String> {
    // Read the parsed query rather than slicing the serialization at the first
    // `?`. The slice found one inside a *fragment* too, so
    // `s3://b/obj#?versionId=secret` selected version `secret` while the URL's
    // query was `None` — a selector the caller never wrote, taken from a
    // component that is never sent to a server.
    //
    // Canonicalization strips the fragment before an address reaches this
    // plugin, so the host already closes it. A plugin that misparses its own
    // selector should not depend on a layer above it for that, and GCS already
    // reads the query directly.
    for piece in addr.query()?.split('&') {
        if let Some(value) = piece.strip_prefix("versionId=") {
            return urlencoding::decode(value).ok().map(|cow| cow.into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anonymous advertisement, both halves, enumerated against the
    /// credentialed set so a bit added there cannot silently appear or fail to
    /// appear here.
    ///
    /// Both directions are needed: asserting only the raised bits would pass
    /// on `s3_capabilities()` itself, and asserting only the withheld ones
    /// would pass on `Capabilities::empty()`.
    #[test]
    fn anonymous_advertises_the_read_side_and_no_mutation() {
        let caps = anonymous_capabilities();

        // The anonymous set IS the credentialed set with the mutation bits
        // cleared. `s3_capabilities()` is the no-config build, so the watch
        // bits are already false on both sides and nothing clears them here.
        // Asserted as one struct comparison
        // rather than field by field, so a capability added to
        // `s3_capabilities_for_config` later is compared here whether or not
        // anyone remembers this test exists — which is what the previous
        // hand-listed version claimed and did not deliver.
        let mut expected = s3_capabilities();
        expected.supports_no_overwrite_write = false;
        expected.supports_if_match_write = false;
        expected.supports_server_side_copy = false;
        expected.supports_copy = false;
        expected.supports_rename = false;
        expected.writes_are_atomic = false;
        expected.supports_write = false;
        expected.supports_write_stream = false;
        expected.supports_write_redirect = false;
        expected.supports_delete = false;
        expected.supports_create_directory = false;
        expected.supports_delete_directory = false;
        expected.supports_native_metadata_patch = false;
        expected.supports_metadata_rewrite_emulation = false;
        expected.redirect_size_threshold = None;

        assert_eq!(
            caps, expected,
            "an anonymous connection advertises the credentialed set minus the \
             mutation bits; a field that differs beyond those is either a new \
             capability nobody classified, or a drift between the two builders"
        );

        // The three that matter most, named as well, so a failure of the whole
        // -struct comparison says which property was lost rather than printing
        // two structs and leaving the reader to diff them.
        assert!(caps.supports_list, "listing a public bucket is the point");
        assert!(!caps.supports_write, "no unsigned mutations");
        assert!(
            !caps.supports_watch_directory,
            "no SQS client is built for an anonymous connection"
        );
    }

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
    fn checksums_from_parts_maps_known_algorithms() {
        let set = checksums_from_parts(Some("deadbeef"), Some("abc123"), None, Some("4242"), None);
        let sha = set.get(&ChecksumAlgorithm::sha256()).unwrap();
        assert_eq!(sha, b"deadbeef");
        let sha1 = set.get(&ChecksumAlgorithm::new("sha1").unwrap()).unwrap();
        assert_eq!(sha1, b"abc123");
        let crc = set.get(&ChecksumAlgorithm::crc32c()).unwrap();
        assert_eq!(crc, b"4242");
    }

    #[test]
    fn address_version_id_extracted_from_query_string() {
        let addr = address::parse("s3://bucket/key?versionId=abc%20123").unwrap();
        assert_eq!(address_version_id(&addr).as_deref(), Some("abc 123"));
    }

    /// A `?` inside a fragment is not a query, and must not select a version.
    ///
    /// The address is built with `Url::parse` rather than `address::parse`
    /// because canonicalization strips the fragment — going through the host
    /// entry point would test the host's guard instead of the plugin's, and
    /// this assertion exists precisely so the plugin does not depend on it.
    #[test]
    fn address_version_id_ignores_a_selector_hidden_in_a_fragment() {
        let addr = Url::parse("s3://bucket/obj#?versionId=secret").unwrap();
        assert_eq!(addr.query(), None, "the fixture must carry no real query");
        assert_eq!(address_version_id(&addr), None);
    }

    fn anonymous_backend(force_request_payer: bool) -> S3Backend {
        let config = S3Config {
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            endpoint: None,
            profile_name: None,
            compatibility: crate::config::CompatibilityProfile::Aws,
            force_path_style: false,
            force_request_payer,
            sqs_queue_url: None,
            sqs_max_messages: 10,
            sqs_wait_seconds: 20,
            sqs_visibility_timeout: 30,
            address_root: address::parse("s3://bucket/").expect("valid address root"),
        };
        S3Backend::anonymous(config).expect("anonymous backend")
    }

    /// The host injects `Range:` on the redirect request before following
    /// (plugin-dev contract); the plugin must not carry it, or the follower
    /// would send a duplicate `Range` header.
    #[test]
    fn anonymous_read_request_omits_range_header() {
        let backend = anonymous_backend(false);
        let opts = ReadOptions {
            range: Some(ovstorage_plugin::ByteRange {
                start: 0,
                end_inclusive: Some(99),
            }),
            ..ReadOptions::default()
        };
        let request = backend
            .anonymous_read_request("dir/key.txt", None, &opts)
            .expect("anonymous read request");
        assert!(
            !request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("range")),
            "anonymous read must not carry a Range header; got {:?}",
            request.headers
        );
        assert!(
            !request.url.to_ascii_lowercase().contains("range"),
            "Range must not leak into the URL either: {}",
            request.url
        );
    }

    /// `x-amz-request-payer` is honored by S3 only as a request header; as a
    /// query param it is ignored (a requester-pays bucket would `403`).
    #[test]
    fn anonymous_read_request_sends_requester_pays_as_header() {
        let backend = anonymous_backend(true);
        let request = backend
            .anonymous_read_request("key", None, &ReadOptions::default())
            .expect("anonymous read request");
        assert!(
            request.headers.iter().any(|(name, value)| name
                .eq_ignore_ascii_case("x-amz-request-payer")
                && value == "requester"),
            "requester-pays must be sent as a header; got {:?}",
            request.headers
        );
        assert!(
            !request.url.contains("x-amz-request-payer"),
            "requester-pays must not be placed in the query string: {}",
            request.url
        );
    }
}
