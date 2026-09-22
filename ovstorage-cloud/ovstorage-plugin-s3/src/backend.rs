// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native S3 / S3-compatible object/data operations (ABI-v2 Layer backend).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_sdk_s3::operation::head_object::HeadObjectOutput;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, MetadataDirective, RequestPayer};
use futures::{Stream, StreamExt as _};
use tracing::{Instrument as _, debug, info, warn};

use ovstorage_plugin::ReadRedirect;
use ovstorage_plugin::{
    AccessDecision, BackendItemInfo, CopyOptions, CreateDirectoryOptions, ReadOptions, ReadResult,
    RenameOptions, UpdateMetadataOptions,
};
use ovstorage_plugin::{
    AccessOps, CancellationToken, Capabilities, ChecksumAlgorithm, ChecksumSet,
    DeleteDirectoryOptions, DeleteOptions, Error, ErrorCode, ErrorContext, EtagStrength,
    HttpRequest, IfDestExists, ListOptions, ListVersionsOptions, MESSAGE_METADATA_KEY, MtimeFormat,
    ObjectInfo, ObjectKind, RedirectBodySource, RedirectCredential, RedirectResultBatch,
    RedirectScope, ResolvedTarget, ResponseParsing, Result, ResultCapture, SecretBundle,
    StatOptions, SystemMetadata, Url, UserMetadata, VersionListOrder, WriteOptions, WriteRedirect,
    WriteRedirectBatch, WriteResult, address, normalize_optional_wire_etag, normalize_wire_etag,
    race_cancel, reject_pinned_for_mutation,
};

const PINNED_VERSION_KEYS: &[&str] = &["versionId"];

/// An S3 error document fits well under 1 KiB. Successful PUT and UploadPart
/// responses have empty bodies, so capture is failure-only in practice.
/// Leak-safety is owned by `map_error_status` in `errors.rs`, which reduces the
/// body to a sanitized `<Code>` token before building any message.
const REDIRECT_ERROR_BODY_CAPTURE_BYTES: u32 = 1024;

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

/// Continuation tokens retained by the unbudgeted streaming walk.
///
/// The buffered path retains every token because its page budget bounds that
/// set. A consumer-driven stream has no page budget, so it remembers only a
/// small recent window and separately rejects an immediate no-progress token.
const LIST_STREAM_TOKEN_WINDOW: usize = 32;

struct S3ListPage {
    items: Vec<ObjectInfo>,
    next_continuation_token: Option<String>,
    is_truncated: bool,
}

type S3ListPageStream = std::pin::Pin<Box<dyn Stream<Item = Result<S3ListPage>> + Send + 'static>>;

/// Namespace of the page token the versioned walk mints.
///
/// `ListObjectsV2` continuation tokens are base64 and cannot contain `:`, so
/// the prefix alone tells the two walks' tokens apart; a token replayed under
/// the other flag is refused instead of being sent to an API whose markers
/// mean something else.
const VERSIONED_LIST_TOKEN_PREFIX: &str = "versions:";

/// What one page walk owns for its lifetime, whichever listing API drives it.
///
/// Built once by [`S3Backend::list_pages`] after the shared preamble so the
/// two walks cannot drift on how they name the bucket root or read the prefix.
struct ListWalk {
    /// The prefix as sent to S3: the requested key as a directory key, empty
    /// for the bucket root.
    prefix_key: String,
    bucket_root: Url,
    requested_prefix: Url,
    config: S3Config,
    client: aws_sdk_s3::Client,
    anonymous: Option<AnonymousShape>,
    region_mismatch: Arc<Mutex<Option<RegionMismatch>>>,
}

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

impl ListWalk {
    /// Whether a `CommonPrefixes` entry of a `ListObjectVersions` response
    /// names a subtree that `ListObjectsV2` would also report.
    ///
    /// S3 folds every version and delete marker under the delimiter into a
    /// common prefix, so a subtree whose objects are all deleted, or that
    /// holds only non-current versions, arrives looking exactly like a live
    /// one. One `ListObjectsV2` request for a single key under the prefix
    /// settles it; it carries no delimiter so a key nested at any depth
    /// counts. `KeyCount` is read first because a conforming store spells it;
    /// `Contents` covers a store that leaves it out.
    async fn prefix_has_current_object(&self, prefix_key: &str) -> Result<bool> {
        let mut request = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .prefix(prefix_key)
            .max_keys(1);
        request = apply_request_payer!(request, self.config);
        let output = request.send().await.map_err(|err| {
            map_unsigned_store_error(
                "s3 list (prefix probe)",
                err,
                self.anonymous.as_ref(),
                &self.region_mismatch,
            )
        })?;
        Ok(output.key_count().is_some_and(|count| count > 0) || !output.contents().is_empty())
    }
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
use crate::errors::{
    AnonymousShape, RegionMismatch, bucket_region_from_error, is_valid_region_token,
    map_anonymous_refusal, map_error_status, map_sdk_error, map_sdk_error_for,
    region_mismatch_from_error,
};

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
    /// `None` on a credentialed connection. Otherwise the request leaves
    /// unsigned, and the shape says which of the two ways it came to: an
    /// anonymous connection or the scheme fallback. Read by
    /// [`crate::errors::map_anonymous_refusal`] to name the remedy an
    /// operator can follow.
    anonymous: Option<AnonymousShape>,
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
    /// The store's latest word, on a data-path `301`, that this backend is
    /// built for a region that does not serve its bucket. Written by
    /// [`Self::map_store_error`]; read through [`Self::region_mismatch`] by
    /// the anonymous `s3://` fallback, which learned the region itself and
    /// relearns it from this. A connection backend records it too and nobody
    /// reads it: its region is the operator's setting, and the `301` mapping
    /// already tells the operator what to set.
    region_mismatch: Arc<Mutex<Option<RegionMismatch>>>,
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
            anonymous: None,
            s3_client,
            sqs_client,
            watch_coalescer,
            refusals,
            region_mismatch: Arc::new(Mutex::new(None)),
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
        Self::unsigned(config, AnonymousShape::Connection)
    }

    /// The anonymous `s3://` fallback's backend for one bucket no connection
    /// serves: [`Self::anonymous`] in every respect but the remedy its
    /// refusals name. There is no connection to remove and re-add, so a store
    /// refusal sends the operator to add one for the bucket root.
    ///
    /// # Errors
    ///
    /// As [`Self::anonymous`].
    pub(crate) fn fallback(config: S3Config) -> Result<Self> {
        let root = config.address_root.clone();
        Self::unsigned(config, AnonymousShape::Fallback { root })
    }

    fn unsigned(config: S3Config, shape: AnonymousShape) -> Result<Self> {
        let watch_coalescer = ovstorage_plugin::subscription::WatchCoalescer::new();
        let s3_client = build_anonymous_s3_client(&config, build_http_client())?;
        Ok(Self {
            credentials: Arc::new(Mutex::new(None)),
            anonymous: Some(shape),
            s3_client,
            sqs_client: None,
            watch_coalescer,
            // Never advanced: the anonymous client carries no
            // `PromotionEvidence` interceptor, and nothing it sends is signed,
            // so there is no credential for the store to refuse.
            refusals: RefusalEpoch::default(),
            region_mismatch: Arc::new(Mutex::new(None)),
            config,
        })
    }

    pub fn config(&self) -> &S3Config {
        &self.config
    }

    pub(crate) fn is_anonymous(&self) -> bool {
        self.anonymous.is_some()
    }

    /// How many times the store has refused this connection's credential. A
    /// promotion witness snapshots this before its operation and requires it
    /// unchanged after — "did a refusal land while I ran?", whoever provoked it.
    pub(crate) fn refusal_epoch(&self) -> u64 {
        self.refusals.get()
    }

    /// The store's verdict, if a data-path `301` has delivered one, that this
    /// backend's bucket lives in a region other than the one it is built for.
    /// It is a fact about the backend and stays set: the region a client was
    /// built for does not change.
    pub(crate) fn region_mismatch(&self) -> Option<RegionMismatch> {
        self.region_mismatch
            .lock()
            .expect("region mismatch mutex poisoned")
            .clone()
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
        if self.is_anonymous() {
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
        if self.is_anonymous() {
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
    /// as a credential problem. `list` streams past the `&self` borrow and
    /// calls [`map_unsigned_store_error`] with clones of the same two fields.
    fn map_store_error<E>(&self, context: &str, err: aws_sdk_s3::error::SdkError<E>) -> Error
    where
        E: std::fmt::Debug + aws_sdk_s3::error::ProvideErrorMetadata,
    {
        map_unsigned_store_error(context, err, self.anonymous.as_ref(), &self.region_mismatch)
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

/// The mapping behind [`S3Backend::map_store_error`], as a free function so the
/// `list` page stream — which outlives the `&self` borrow and captures clones
/// of the backend's fields — applies exactly the same one.
///
/// Three things happen here, in order. A `301` is recorded in
/// `region_mismatch` before the error is consumed, because the verdict is
/// only readable off the raw response. The SDK error is then classified with
/// the region remedy worded for `shape`. Last, on an anonymous backend, a
/// `401`/`403` is restated as a refusal of an unsigned request.
fn map_unsigned_store_error<E>(
    context: &str,
    err: aws_sdk_s3::error::SdkError<E>,
    shape: Option<&AnonymousShape>,
    region_mismatch: &Mutex<Option<RegionMismatch>>,
) -> Error
where
    E: std::fmt::Debug + aws_sdk_s3::error::ProvideErrorMetadata,
{
    if let Some(verdict) = region_mismatch_from_error(&err) {
        *region_mismatch
            .lock()
            .expect("region mismatch mutex poisoned") = Some(verdict);
    }
    let mapped = map_sdk_error_for(context, err, shape);
    match shape {
        Some(shape) => map_anonymous_refusal(mapped, shape),
        None => mapped,
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
                                etag_strength: Default::default(),
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
                                versioned_address: None,
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
            let mut info = object_info_from_head_output(&target.resolved_address, &output)?;
            if trailing_slash {
                // A directory kind is never pinned, whatever version id the
                // marker object carries.
                info.kind = ObjectKind::DirectoryMarker;
                info.versioned_address = None;
            } else if let Some(pin) = s3_version_pin(version_id.as_deref()) {
                // The caller's selector is what the HEAD answered for, so it
                // is the pin reported, with the precedence `get_latest_version`
                // gives it.
                info.versioned_address = Some(s3_version_address(&target.resolved_address, pin)?);
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

            let request = if self.is_anonymous() {
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
                credential: if self.is_anonymous() {
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
        // The annotation rides in the metadata that is signed into the
        // presigned PUT or set on `CreateMultipartUpload`, as on a buffered
        // write.
        let opts = with_message_stashed(opts);
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
        // out of the continuation. The broker's client-driven RPC authenticates
        // the blob and its address binding, but the Layer SPI supplies no such
        // integrity: a direct SPI caller or an unsealed host can rewrite the
        // blob, and follower routes carry no SPI-level guarantee. The address is
        // what authorization was decided on for every route.
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
            let (etag, etag_strength) = normalize_optional_wire_etag(header_value(
                &result.captured_headers,
                "etag",
            ));
            let info = ObjectInfo {
                etag_strength,
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
                versioned_address: None,
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
                .map(|value| normalize_wire_etag(value).0)
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
        // The annotation rides in the multipart upload's metadata, as on a
        // buffered write.
        let opts = with_message_stashed(opts);
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

    /// Build the shared lazy page walk over one prefix.
    ///
    /// `ListOptions::versioned_address` selects the API: `ListObjectsV2` by
    /// default, `ListObjectVersions` when set, because only the latter carries
    /// the version id that pins each file. Both walks share one page
    /// conversion, so their items differ only in `versioned_address`, and both
    /// hand `list` and `list_stream` the same `S3ListPage` shape.
    ///
    /// Each poll past a yielded page issues at most one further request. Page
    /// conversion preserves S3's response order: keys first, followed by
    /// `CommonPrefixes`. Marker/common-prefix dedup retains only the current
    /// and immediately previous page's marker addresses, which covers the only
    /// boundary on which adjacent S3 key ranges can split the pair while
    /// keeping streaming state bounded. Buffered `list` separately retains
    /// whole-walk marker addresses, preserving its behavior even if a
    /// nonconforming store separates a marker from its matching common prefix
    /// by more than one page.
    ///
    /// The versioned walk costs more per item. S3 counts every version and
    /// delete marker under the prefix against `MaxKeys`, so a response carries
    /// fewer current items than the page size asked for, possibly none, and a
    /// heavily versioned prefix takes more responses to complete. Each common
    /// prefix a delimited page emits costs one further `ListObjectsV2` probe;
    /// `list_pages_versioned` says why. It also needs `s3:ListBucketVersions`,
    /// a separate grant from the `s3:ListBucket` its probes use; a store that
    /// refuses it fails the listing, because a `ListObjectsV2` fallback could
    /// not answer what was asked.
    async fn list_pages(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<S3ListPageStream> {
        // Make a token cancelled before open observable before any request is
        // constructed. Per-request races below carry the same open-time token
        // through the lifetime of the returned stream.
        race_cancel(cancel.as_ref(), async { Ok(()) }).await?;
        let parts = self.parse_target(&prefix)?;
        self.resolve_credentials(None)?;
        // A token names the walk that minted it, and neither walk can resume
        // from the other's: a V2 continuation token is opaque to
        // `ListObjectVersions`, and a key/version marker pair is not a
        // continuation token.
        if let Some(token) = opts.page_token.as_deref() {
            let minted_versioned = token.starts_with(VERSIONED_LIST_TOKEN_PREFIX);
            if minted_versioned != opts.versioned_address {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "S3 list page token was minted with versioned_address={minted_versioned} \
                         and replayed with versioned_address={}; a listing continues under the \
                         options it started with",
                        opts.versioned_address
                    ),
                ));
            }
        }

        let walk = ListWalk {
            // `directory_key` rather than the key verbatim: `x` and `x/`
            // name one node, and a verbatim listing prefix matches every sibling
            // whose name merely starts with this one's.
            prefix_key: address::directory_key(&parts.key),
            bucket_root: address::parse(&format!("s3://{}/", self.config.bucket))?,
            requested_prefix: prefix.resolved_address,
            config: self.config.clone(),
            client: self.unsigned_capable_client().clone(),
            anonymous: self.anonymous.clone(),
            region_mismatch: Arc::clone(&self.region_mismatch),
        };
        Ok(if opts.versioned_address {
            Self::list_pages_versioned(walk, opts, cancel)
        } else {
            Self::list_pages_current(walk, opts, cancel)
        })
    }

    /// The `ListObjectsV2` walk: the default, and all an unpinned listing needs.
    fn list_pages_current(
        walk: ListWalk,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> S3ListPageStream {
        Box::pin(async_stream::try_stream! {
            let ListWalk {
                prefix_key,
                bucket_root,
                requested_prefix,
                config,
                client,
                anonymous,
                region_mismatch,
            } = walk;
            let ctx = ListPageContext {
                bucket_root: &bucket_root,
                requested_prefix: &requested_prefix,
                prefix_key: &prefix_key,
            };
            let mut continuation = opts.page_token.clone();
            let mut previous_page_marker_addresses = HashSet::<String>::new();
            loop {
                let mut request = client.list_objects_v2().bucket(&config.bucket);
                if !prefix_key.is_empty() {
                    request = request.prefix(&prefix_key);
                }
                if !opts.recursive {
                    request = request.delimiter("/");
                }
                // Asked for on every request; see `list`'s doc comment for the
                // term it narrows and the one it cannot.
                let page_size = opts
                    .max_results
                    .map_or(S3_MAX_KEYS_PER_PAGE, |n| n.min(S3_MAX_KEYS_PER_PAGE));
                request = request.max_keys(page_size as i32);
                if let Some(token) = continuation.as_ref() {
                    request = request.continuation_token(token);
                }
                request = apply_request_payer!(request, config);
                let output = race_cancel(cancel.as_ref(), async {
                    request.send().await.map_err(|err| {
                        map_unsigned_store_error(
                            "s3 list",
                            err,
                            anonymous.as_ref(),
                            &region_mismatch,
                        )
                    })
                }).await?;

                let (page_items, marker_addresses) = convert_list_page(
                    &ctx,
                    output.contents().iter().map(ListedKey::from),
                    output.common_prefixes(),
                    &previous_page_marker_addresses,
                )?;

                let next_continuation_token = output
                    .next_continuation_token()
                    .filter(|token| !token.is_empty())
                    .map(str::to_string);
                let is_truncated = output.is_truncated() == Some(true);
                drop(output);
                previous_page_marker_addresses = marker_addresses;
                yield S3ListPage {
                    items: page_items,
                    next_continuation_token: next_continuation_token.clone(),
                    is_truncated,
                };

                if opts.max_results.is_some() {
                    break;
                }
                match next_continuation_token {
                    Some(token) => continuation = Some(token),
                    None => break,
                }
            }
        })
    }

    /// The `ListObjectVersions` walk behind `ListOptions::versioned_address`.
    ///
    /// Only the entry S3 marks `IsLatest` is what `ListObjectsV2` would have
    /// listed, so those are the only `Version` entries converted. A key whose
    /// newest entry is a delete marker has no such version and drops out here
    /// exactly as V2 omits it; the response's `DeleteMarker` list is never
    /// consulted.
    ///
    /// `CommonPrefixes` convert as in the V2 walk but carry no `IsLatest`: S3
    /// folds every version and delete marker under the delimiter into them,
    /// so a subtree whose objects are all deleted, or that holds only
    /// non-current versions, arrives as a prefix V2 would not report. Each
    /// inferred directory the page would emit is therefore verified with one
    /// `ListObjectsV2` request for a single key under it and dropped when
    /// nothing current answers, so the flagged and unflagged listings agree
    /// on which directories exist. A marker-backed directory is a real object
    /// that passed the `IsLatest` filter and is not probed. The probes run one
    /// at a time, so a page that emits N inferred directories costs 1 + N
    /// requests; a recursive walk has no common prefixes and pays nothing.
    /// They also need `s3:ListBucket` alongside `s3:ListBucketVersions`.
    ///
    /// The page token is the response's `NextKeyMarker`/`NextVersionIdMarker`
    /// pair under [`VERSIONED_LIST_TOKEN_PREFIX`], so the cycle guards in
    /// `list` and `flatten_list_pages` see one string per page as they do for
    /// V2.
    fn list_pages_versioned(
        walk: ListWalk,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> S3ListPageStream {
        Box::pin(async_stream::try_stream! {
            let ctx = ListPageContext {
                bucket_root: &walk.bucket_root,
                requested_prefix: &walk.requested_prefix,
                prefix_key: &walk.prefix_key,
            };
            let mut continuation = opts.page_token.clone();
            let mut previous_page_marker_addresses = HashSet::<String>::new();
            loop {
                let mut request = walk.client.list_object_versions().bucket(&walk.config.bucket);
                if !walk.prefix_key.is_empty() {
                    request = request.prefix(&walk.prefix_key);
                }
                if !opts.recursive {
                    request = request.delimiter("/");
                }
                // The same page size the V2 walk asks for, but S3 counts every
                // version and delete marker against it, so a page may carry
                // far fewer current items than this.
                let page_size = opts
                    .max_results
                    .map_or(S3_MAX_KEYS_PER_PAGE, |n| n.min(S3_MAX_KEYS_PER_PAGE));
                request = request.max_keys(page_size as i32);
                if let Some(token) = continuation.as_deref() {
                    let (key_marker, version_id_marker) = decode_versions_token(token)?;
                    request = request.key_marker(key_marker);
                    if let Some(version_id_marker) = version_id_marker {
                        request = request.version_id_marker(version_id_marker);
                    }
                }
                request = apply_request_payer!(request, walk.config);
                let output = race_cancel(cancel.as_ref(), async {
                    request.send().await.map_err(|err| {
                        map_unsigned_store_error(
                            "s3 list (versions)",
                            err,
                            walk.anonymous.as_ref(),
                            &walk.region_mismatch,
                        )
                    })
                }).await?;

                let latest = output
                    .versions()
                    .iter()
                    .filter(|version| version.is_latest() == Some(true))
                    .map(ListedKey::from);
                let (converted, marker_addresses) = convert_list_page(
                    &ctx,
                    latest,
                    output.common_prefixes(),
                    &previous_page_marker_addresses,
                )?;

                // Every inferred directory here came from `CommonPrefixes`, the
                // one part of the response the `IsLatest` filter cannot vet.
                // Dropping one leaves `marker_addresses` alone, since only
                // marker objects populate it, so a dropped prefix cannot
                // resurface on the next page. The address round-trips to the
                // key the way every other operation on a listed item does.
                let mut page_items = Vec::with_capacity(converted.len());
                for item in converted {
                    if item.kind == ObjectKind::DirectoryInferred {
                        let prefix_key = address::key_utf8(&item.address)?;
                        let has_current = race_cancel(
                            cancel.as_ref(),
                            walk.prefix_has_current_object(&prefix_key),
                        )
                        .await?;
                        if !has_current {
                            continue;
                        }
                    }
                    page_items.push(item);
                }

                let is_truncated = output.is_truncated() == Some(true);
                let next_continuation_token = output
                    .next_key_marker()
                    .filter(|key_marker| is_truncated && !key_marker.is_empty())
                    .map(|key_marker| {
                        encode_versions_token(key_marker, output.next_version_id_marker())
                    });
                drop(output);
                previous_page_marker_addresses = marker_addresses;
                yield S3ListPage {
                    items: page_items,
                    next_continuation_token: next_continuation_token.clone(),
                    is_truncated,
                };

                if opts.max_results.is_some() {
                    break;
                }
                match next_continuation_token {
                    Some(token) => continuation = Some(token),
                    None => break,
                }
            }
        })
    }

    /// Materialize one prefix by draining the shared S3 page walk.
    ///
    /// The buffered Layer contract treats a tokenless return as complete, so
    /// this method walks to the end unless `max_results` deliberately requests
    /// one native page. It retains the full continuation-token set and applies
    /// the fixed cumulative item/page budgets. `list_stream` is the bounded-
    /// residency surface for callers that do not need buffered pagination.
    ///
    /// Under `versioned_address` the native page comes from
    /// `ListObjectVersions`, whose `MaxKeys` counts every version and delete
    /// marker: `max_results` bounds the response, not the items returned, so
    /// one page may carry fewer current items than requested, and the response
    /// budget is reached with fewer items on a heavily versioned prefix. Each
    /// inferred directory a delimited page emits also costs one `ListObjectsV2`
    /// probe, so such a page takes 1 + N requests for N common prefixes; the
    /// response budget counts pages, not probes.
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
        let cancel_for_race = cancel.clone();
        race_cancel(
            cancel_for_race.as_ref(),
            async move {
                let mut page_stream = self
                    .list_pages(prefix.clone(), opts.clone(), cancel.clone())
                    .await?;
                let mut items = Vec::new();
                // Every token this walk has followed, seeded with the caller's so
                // a store that hands its own starting token straight back is caught
                // on the first response rather than the second.
                let mut seen_tokens: HashSet<String> = opts.page_token.iter().cloned().collect();
                // Buffered listing already has a fixed cumulative item budget,
                // so retain every concrete marker address seen by the walk. The
                // shared page generator intentionally keeps only a two-page
                // window for bounded streaming; this set preserves the buffered
                // walk's wider marker/common-prefix dedup contract.
                let mut marker_addresses = HashSet::<String>::new();
                let mut pages: usize = 0;

                while let Some(page) = page_stream.next().await {
                    let page = page?;
                    pages += 1;
                    marker_addresses.extend(
                        page.items
                            .iter()
                            .filter(|item| item.kind == ObjectKind::DirectoryMarker)
                            .map(|item| item.address.as_str().to_string()),
                    );
                    items.extend(page.items.into_iter().filter(|item| {
                        item.kind != ObjectKind::DirectoryInferred
                            || !marker_addresses.contains(item.address.as_str())
                    }));

                    // Checked on every path out of a folded page — before the
                    // bounded-request break as well, since a store that ignores
                    // `MaxKeys` overruns a bounded caller just as easily.
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
                    // here, token or no token.
                    if opts.max_results.is_some() {
                        break;
                    }

                    match page.next_continuation_token {
                        Some(token) => {
                            // The buffered path deliberately retains the full token
                            // set; LIST_PAGE_BUDGET bounds it.
                            if !seen_tokens.insert(token.clone()) {
                                return Err(refuse_partial_listing(
                                    ErrorCode::Transient,
                                    &prefix.resolved_address,
                                    "the store reissued a continuation token it had already \
                                 handed back, so the listing cannot be advanced",
                                ));
                            }
                            // These checks remain on the edge that would fetch
                            // ANOTHER page. Their text and precedence are the
                            // buffered-list contract.
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
                        }
                        None if page.is_truncated => {
                            return Err(refuse_partial_listing(
                                ErrorCode::Transient,
                                &prefix.resolved_address,
                                "the store reported the listing as truncated but offered no \
                             continuation token to resume from",
                            ));
                        }
                        None => break,
                    }
                }
                Ok(items)
            }
            .instrument(span),
        )
        .await
    }

    /// Stream an S3 listing in the backend's native emission order.
    ///
    /// Recursive requests omit the delimiter, so S3 yields only byte-ordered
    /// `Contents`, satisfying the incremental flat-fold precondition.
    /// Non-recursive requests preserve each page's `Contents`-then-
    /// `CommonPrefixes` order and are therefore not globally byte-sorted.
    /// The next response is fetched only after the consumer polls past every
    /// entry in the current response.
    pub async fn list_stream(
        &self,
        prefix: ResolvedTarget,
        opts: ListOptions,
        cancel: Option<CancellationToken>,
    ) -> Result<ovstorage_plugin::ListStream> {
        if opts.max_results.is_some() || opts.page_token.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "list_stream does not accept max_results or page_token",
            ));
        }
        let requested_prefix = prefix.resolved_address.clone();
        let stream_cancel = cancel.clone();
        let pages = self.list_pages(prefix, opts, cancel).await?;
        Ok(flatten_list_pages(pages, requested_prefix, stream_cancel))
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
                    let address = s3_version_address(&target.resolved_address, version_id)?;
                    // The item's address already names this one version, unless
                    // the id is the mutable `null` version, which pins nothing.
                    let versioned_address =
                        s3_version_pin(Some(version_id)).map(|_| address.clone());
                    let (etag, etag_strength) = normalize_optional_wire_etag(version.e_tag());
                    items.push(ObjectInfo {
                        etag_strength,
                        address,
                        kind: ObjectKind::File,
                        etag,
                        version: Some(version_id.to_string()),
                        size: version.size().and_then(|n| u64::try_from(n).ok()),
                        mtime,
                        checksums: ChecksumSet::default(),
                        effective_permissions: None,
                        system_metadata: None,
                        user_metadata: None,
                        modified_by: None,
                        versioned_address,
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
                let info = object_info_from_head_output(&target.resolved_address, &output)?;
                let value = pinned.or_else(|| info.version.clone()).ok_or_else(|| {
                    Error::new(
                        ErrorCode::Unsupported,
                        "S3 object is not versioned (no x-amz-version-id on HEAD)",
                    )
                })?;
                let address = s3_version_address(&target.resolved_address, &value)?;
                Ok(ObjectInfo {
                    // The address returned already names this one version,
                    // unless it is the mutable `null` version, which pins nothing.
                    versioned_address: s3_version_pin(Some(&value)).map(|_| address.clone()),
                    address,
                    ..info
                })
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
            let (etag, etag_strength) = normalize_optional_wire_etag(output.e_tag());
            Ok(BackendItemInfo {
                etag_strength,
                kind: ObjectKind::DirectoryMarker,
                etag,
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
                let (etag, etag_strength) = normalize_optional_wire_etag(
                    result.and_then(|copy_result| copy_result.e_tag()),
                );
                let info = ObjectInfo {
                    etag_strength,
                    address: dest.resolved_address.clone(),
                    kind: ObjectKind::File,
                    etag,
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
                    versioned_address: None,
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
            let desired = update_metadata_entries(
                &existing,
                &opts.user_metadata_set,
                &opts.user_metadata_remove,
                opts.message.as_deref(),
            );
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
            let (etag, etag_strength) = normalize_optional_wire_etag(
                result.and_then(|copy_result| copy_result.e_tag()),
            );
            Ok(BackendItemInfo {
                etag_strength,
                kind: ObjectKind::File,
                etag,
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
                if self.is_anonymous() {
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
                    let denied_ops = if self.is_anonymous() {
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
    /// One unsigned `HeadBucket`, asking where this backend's bucket lives.
    ///
    /// The anonymous `s3://` fallback sends this from a probe backend built
    /// for its default region: S3 answers a request that reached the wrong
    /// region with `301` (or `400` under SigV4), and stamps
    /// `x-amz-bucket-region` on that refusal and on most others, so the
    /// bucket's region is read off whatever came back. A header that names a
    /// region is believed on any status. What an answer without one means
    /// depends on whether the store judged the bucket at all:
    ///
    /// - a `404` is an error — the bucket does not exist, and there is
    ///   nothing to learn;
    /// - any other `2xx` or `4xx`, including a `403` for a bucket that
    ///   grants the anonymous principal no `HeadBucket`, is a verdict about
    ///   the bucket and is `Ok(None)`: the caller takes the bucket to live in
    ///   the region the probe reached, and the data-path request that follows
    ///   reports the bucket's real answer;
    /// - a `3xx` naming no region is an error as [`map_sdk_error`] classifies
    ///   it. A redirect says the bucket is served from somewhere else, which
    ///   is the opposite of "the region the probe reached", so it must not be
    ///   read as the default; AWS always names the region on its `301`, and a
    ///   compatible store that does not has told the caller only that it does
    ///   not know;
    /// - a `429` or `5xx` is an error as [`map_sdk_error`] classifies it, the
    ///   same as a transport failure. The store shed the request without
    ///   judging the bucket, so the answer says nothing about where the
    ///   bucket lives, and reading it as "the default region" would pin a
    ///   bucket elsewhere to the wrong region for as long as the caller
    ///   remembers the verdict.
    ///
    /// A value is admitted only through [`is_valid_region_token`], because it
    /// becomes part of a hostname.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::NotFound`] — S3 answered `404`: no such bucket.
    /// - [`ErrorCode::Cancelled`] — `cancel` fired.
    /// - A `3xx` naming no region, a `429` or `5xx`, and transport failures,
    ///   as [`map_sdk_error`] classifies them.
    pub(crate) async fn head_bucket_region(
        &self,
        cancel: Option<&CancellationToken>,
    ) -> Result<Option<String>> {
        race_cancel(cancel, async {
            let request = self
                .unsigned_capable_client()
                .head_bucket()
                .bucket(&self.config.bucket);
            match request.send().await {
                Ok(output) => Ok(output
                    .bucket_region()
                    .filter(|region| is_valid_region_token(region))
                    .map(str::to_string)),
                Err(err) => {
                    let status = err.raw_response().map(|resp| resp.status().as_u16());
                    if status == Some(404) {
                        return Err(Error::new(
                            ErrorCode::NotFound,
                            format!("S3 bucket '{}' does not exist", self.config.bucket),
                        ));
                    }
                    if let Some(region) = bucket_region_from_error(&err) {
                        return Ok(Some(region));
                    }
                    match status {
                        // The store judged the bucket and named no region.
                        // A `404` never reaches here.
                        Some(200..=299 | 400..=428 | 430..=499) => Ok(None),
                        // A redirect naming no region, a shed request, or no
                        // answer at all: nothing here says where the bucket
                        // lives.
                        _ => Err(map_sdk_error_for(
                            "s3 head_bucket",
                            err,
                            self.anonymous.as_ref(),
                        )),
                    }
                }
            }
        })
        .await
    }

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
            let (etag, etag_strength) = normalize_optional_wire_etag(marker.e_tag());
            return Ok(FlatDirectoryProbe::Marker(Box::new(ObjectInfo {
                etag_strength,
                address: address.clone(),
                kind: ObjectKind::DirectoryMarker,
                etag,
                version: None,
                size: marker.size().and_then(|n| u64::try_from(n).ok()),
                mtime: marker.last_modified().and_then(datetime_to_system_time),
                checksums: ChecksumSet::default(),
                effective_permissions: None,
                system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
                user_metadata: None,
                modified_by: None,
                versioned_address: None,
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
                    .map(|value| normalize_wire_etag(value).0);
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
        let (etag, etag_strength) = normalize_optional_wire_etag(output.e_tag());
        Ok(ObjectInfo {
            etag_strength,
            address: resolved,
            kind: ObjectKind::File,
            etag,
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
            versioned_address: None,
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
                body_max_bytes: REDIRECT_ERROR_BODY_CAPTURE_BYTES,
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
                    body_max_bytes: REDIRECT_ERROR_BODY_CAPTURE_BYTES,
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
        let (etag, etag_strength) = normalize_optional_wire_etag(output.e_tag());
        if etag.is_none() {
            return Err(Error::new(
                ErrorCode::Internal,
                "S3 CompleteMultipartUpload returned 2xx but the response did not include an ETag",
            ));
        }
        let bucket_root = address::parse(&format!("s3://{}/", self.config.bucket))?;
        let resolved = address::join_relative(&bucket_root, key)?;
        let total_size: u64 = continuation.parts.iter().map(|p| p.byte_length).sum();
        // Rebuilt from the returned continuation. The broker seal prevents an
        // edit on its client-driven route, but the Layer also supports unsealed
        // callers, and no seal binds this value to the principal finalizing the
        // write. The reserved attribution key is put right by the host's
        // attribution overlay, which is the one place every `continue_write`
        // result passes through; what S3 *persisted* was bound at
        // `CreateMultipartUpload` and the caller never held it.
        let user_metadata: Option<UserMetadata> =
            continuation.user_metadata.as_ref().map(|pairs| {
                let mut map: HashMap<String, String> = HashMap::new();
                for (k, v) in pairs {
                    map.insert(k.clone(), v.clone());
                }
                map
            });
        Ok(ObjectInfo {
            etag_strength,
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
            versioned_address: None,
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
            .map(|value| normalize_wire_etag(value).0)
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

/// Bounds an upload id before it reaches a log field. The broker's client-driven
/// RPC authenticates the continuation, but the Layer SPI does not: a direct SPI
/// caller or an unsealed host can choose the id because `decode` validates only
/// the plugin tag. An unbounded copy would then let that caller choose the
/// contents and size of a WARN record it can trigger without any provider round
/// trip. A prefix is enough to correlate with the provider's own records.
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

/// The metadata set the self-copy replaces the object's with: `existing` with
/// `remove` and `set` applied by [`merge_metadata`], then `message` under
/// [`MESSAGE_METADATA_KEY`] unless `set` spells that key under any ASCII case.
/// A `set` entry under the key stands; otherwise the message replaces whatever
/// the object holds under it, a removal of the key in the same call included.
fn update_metadata_entries(
    existing: &UserMetadata,
    set: &HashMap<String, String>,
    remove: &[String],
    message: Option<&str>,
) -> Vec<(String, String)> {
    let mut desired = merge_metadata(existing, set, remove);
    if !carries_message_key(set.keys())
        && let Some(message) = message.filter(|m| !m.is_empty() && is_header_value(m))
    {
        desired.retain(|(k, _)| k != MESSAGE_METADATA_KEY);
        desired.push((MESSAGE_METADATA_KEY.to_string(), message.to_string()));
    }
    desired
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

/// Whether `value` can travel as an HTTP header value: visible ASCII, space,
/// tab, or bytes above 0x7F. Metadata rides in `x-amz-meta-*` headers here, so a
/// message outside that set cannot be stored as is, and the annotation is
/// droppable by contract: the stash declines it rather than turning the call
/// into a request-construction failure.
fn is_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (0x20..0x7F).contains(&byte) || byte >= 0x80)
}

/// Stash `opts.message` as the [`MESSAGE_METADATA_KEY`] user-metadata entry (the
/// project-wide convention for backends without native commit annotations) when
/// the caller's map leaves that key unset. The caller's own entry stands: user
/// metadata is persisted, the per-operation annotation is droppable. Returns
/// `opts` unchanged when the message is absent, empty, or not a header value
/// per [`is_header_value`].
fn with_message_stashed(mut opts: WriteOptions) -> WriteOptions {
    let Some(message) = opts
        .message
        .as_deref()
        .filter(|m| !m.is_empty() && is_header_value(m))
    else {
        return opts;
    };
    let mut metadata = opts.user_metadata.take().unwrap_or_default();
    if !carries_message_key(metadata.keys()) {
        metadata.insert(MESSAGE_METADATA_KEY.into(), message.to_string());
    }
    opts.user_metadata = Some(metadata);
    opts
}

/// Whether a caller-supplied metadata map spells [`MESSAGE_METADATA_KEY`] under
/// any ASCII case. S3 lower-cases metadata names on the wire, so every spelling
/// lands on the same stored entry.
fn carries_message_key<'a>(keys: impl IntoIterator<Item = &'a String>) -> bool {
    keys.into_iter()
        .any(|key| key.eq_ignore_ascii_case(MESSAGE_METADATA_KEY))
}

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
        etag_strength: EtagStrength::Unspecified,
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

/// The `ObjectInfo` (kind `File`) a typed `HeadObjectOutput` describes.
///
/// The pin comes free with the response: `x-amz-version-id` is on every HEAD
/// of a versioned bucket, so it is reported whether or not the caller asked
/// to pay for it.
fn object_info_from_head_output(addr: &Url, out: &HeadObjectOutput) -> Result<ObjectInfo> {
    let (etag, etag_strength) = normalize_optional_wire_etag(out.e_tag());
    let versioned_address = s3_version_pin(out.version_id())
        .map(|version_id| s3_version_address(addr, version_id))
        .transpose()?;
    Ok(ObjectInfo {
        etag_strength,
        address: addr.clone(),
        kind: ObjectKind::File,
        etag,
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
        versioned_address,
    })
}

/// The error a listing walk ends with when it cannot prove it saw everything.
///
/// Flatten converted S3 pages without reading ahead of the current page.
///
/// Unlike buffered `list`, this walk has no item or page budget: the consumer
/// controls progress and cancellation bounds an abandoned or runaway walk.
/// The continuation guard is correspondingly fixed-size. It catches immediate
/// no-progress and cycles within the recent window without growing with the
/// number of pages consumed.
fn flatten_list_pages(
    mut pages: S3ListPageStream,
    requested_prefix: Url,
    cancel: Option<CancellationToken>,
) -> ovstorage_plugin::ListStream {
    Box::pin(async_stream::stream! {
        let mut continuation = None;
        let mut recent_tokens = VecDeque::<String>::new();

        'walk: while let Some(page) = pages.next().await {
            let page = match page {
                Ok(page) => page,
                Err(error) => {
                    yield Err(error);
                    break;
                }
            };
            let S3ListPage {
                items,
                next_continuation_token,
                is_truncated,
            } = page;

            for item in items {
                if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
                    yield Err(Error::new(ErrorCode::Cancelled, "list_stream cancelled"));
                    break 'walk;
                }
                yield Ok(item);
            }
            if cancel.as_ref().is_some_and(CancellationToken::is_cancelled) {
                yield Err(Error::new(ErrorCode::Cancelled, "list_stream cancelled"));
                break;
            }

            match next_continuation_token {
                Some(token) => {
                    let no_progress = continuation.as_deref() == Some(token.as_str());
                    let recent_cycle = recent_tokens.iter().any(|seen| seen == &token);
                    if no_progress || recent_cycle {
                        yield Err(refuse_partial_listing(
                            ErrorCode::Transient,
                            &requested_prefix,
                            "the store reissued a continuation token it had already \
                             handed back, so the listing cannot be advanced",
                        ));
                        break;
                    }
                    if recent_tokens.len() == LIST_STREAM_TOKEN_WINDOW {
                        recent_tokens.pop_front();
                    }
                    recent_tokens.push_back(token.clone());
                    continuation = Some(token);
                }
                None if is_truncated => {
                    yield Err(refuse_partial_listing(
                        ErrorCode::Transient,
                        &requested_prefix,
                        "the store reported the listing as truncated but offered no \
                         continuation token to resume from",
                    ));
                    break;
                }
                None => break,
            }
        }
    })
}

/// Build the common refusal for a page walk that cannot safely continue.
///
/// A short buffered listing cannot be returned as complete: callers treat a
/// tokenless result as authoritative and may infer `NotFound` from absence.
/// Store pagination faults are `Transient`; fixed local buffered-list budgets
/// are `Internal` so retry policy does not repeat the same bounded walk. The
/// streaming surface uses this helper only for store faults and the per-
/// response ceiling, never for cumulative item or page budgets.
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

/// The address that names exactly one version of `addr`'s object.
///
/// Any selector or fragment already on `addr` is replaced rather than
/// stacked, so the pin has one spelling whichever address it was derived
/// from.
fn s3_version_address(addr: &Url, version_id: &str) -> Result<Url> {
    let mut base = addr.clone();
    base.set_query(None);
    base.set_fragment(None);
    address::with_query_pair(&base, "versionId", version_id)
}

/// A version id that names an immutable version, or `None`.
///
/// S3 reports the literal `null` for the mutable null version of an
/// unversioned or suspended bucket, on HEAD and in `ListObjectVersions`
/// alike. `?versionId=null` selects whatever bytes the key holds at read
/// time, so it pins nothing and is not reported as a pin.
fn s3_version_pin(version_id: Option<&str>) -> Option<&str> {
    version_id.filter(|version_id| *version_id != "null")
}

/// Mint the versioned walk's page token from a response's marker pair.
///
/// Both halves are percent-encoded so a key or version id containing `|`
/// survives the split in [`decode_versions_token`].
fn encode_versions_token(key_marker: &str, version_id_marker: Option<&str>) -> String {
    format!(
        "{VERSIONED_LIST_TOKEN_PREFIX}{}|{}",
        urlencoding::encode(key_marker),
        version_id_marker
            .map(urlencoding::encode)
            .unwrap_or_default()
    )
}

/// Read a token minted by [`encode_versions_token`] back into its
/// `(key_marker, version_id_marker)` pair.
fn decode_versions_token(token: &str) -> Result<(String, Option<String>)> {
    let malformed = || {
        Error::new(
            ErrorCode::InvalidArgument,
            "S3 list page token is not a versioned-listing token",
        )
    };
    let body = token
        .strip_prefix(VERSIONED_LIST_TOKEN_PREFIX)
        .ok_or_else(malformed)?;
    let (key_marker, version_id_marker) = body.split_once('|').unwrap_or((body, ""));
    let decode = |part: &str| {
        urlencoding::decode(part)
            .map(|decoded| decoded.into_owned())
            .map_err(|_| malformed())
    };
    let key_marker = decode(key_marker)?;
    let version_id_marker = (!version_id_marker.is_empty())
        .then(|| decode(version_id_marker))
        .transpose()?;
    Ok((key_marker, version_id_marker))
}

/// One listed key, whichever listing API reported it.
///
/// `ListObjectsV2` reports `Object` entries and `ListObjectVersions` reports
/// `ObjectVersion` entries; both carry the fields a listing item needs, and
/// only the latter carries a version id.
struct ListedKey<'a> {
    key: Option<&'a str>,
    e_tag: Option<&'a str>,
    size: Option<i64>,
    last_modified: Option<&'a aws_sdk_s3::primitives::DateTime>,
    storage_class: Option<&'a str>,
    version_id: Option<&'a str>,
}

impl<'a> From<&'a aws_sdk_s3::types::Object> for ListedKey<'a> {
    fn from(object: &'a aws_sdk_s3::types::Object) -> Self {
        Self {
            key: object.key(),
            e_tag: object.e_tag(),
            size: object.size(),
            last_modified: object.last_modified(),
            storage_class: object.storage_class().map(|class| class.as_str()),
            version_id: None,
        }
    }
}

impl<'a> From<&'a aws_sdk_s3::types::ObjectVersion> for ListedKey<'a> {
    fn from(version: &'a aws_sdk_s3::types::ObjectVersion) -> Self {
        Self {
            key: version.key(),
            e_tag: version.e_tag(),
            size: version.size(),
            last_modified: version.last_modified(),
            storage_class: version.storage_class().map(|class| class.as_str()),
            version_id: version.version_id(),
        }
    }
}

/// What page conversion needs to know about the listing it serves.
struct ListPageContext<'a> {
    bucket_root: &'a Url,
    requested_prefix: &'a Url,
    /// The prefix as sent to S3; its own marker object is not an entry of the
    /// listing it names.
    prefix_key: &'a str,
}

/// Turn one listing response into `ObjectInfo` items, whichever API produced it.
///
/// Emission order is S3's: keys first, then `CommonPrefixes`. The requested
/// prefix's own marker is skipped; a key that cannot be spelled as a URI path
/// is omitted with a warning; a key or prefix outside the requested prefix is
/// refused as `Internal`, because the response does not describe the listing
/// asked for. A `CommonPrefixes` entry that a concrete marker in this or the
/// previous page already names is dropped so a directory appears once.
/// Returns the items and this page's marker addresses for the caller to carry
/// to the next page.
fn convert_list_page<'a>(
    ctx: &ListPageContext<'_>,
    keys: impl Iterator<Item = ListedKey<'a>>,
    prefixes: &[aws_sdk_s3::types::CommonPrefix],
    previous_page_marker_addresses: &HashSet<String>,
) -> Result<(Vec<ObjectInfo>, HashSet<String>)> {
    let mut page_items = Vec::new();
    let mut marker_addresses = HashSet::new();
    for listed in keys {
        let Some(key) = listed.key else {
            continue;
        };
        if key == ctx.prefix_key {
            continue;
        }
        let Ok(address) = address::join_relative(ctx.bucket_root, key) else {
            // The key cannot be named by a URI path, so any address
            // built for it would resolve to a different object.
            tracing::warn!(
                target: "ovstorage.s3.backend",
                plugin = "s3",
                key = %key,
                "s3: object key is not addressable as a URI path; omitted from listing",
            );
            continue;
        };
        let _ = address::relative_suffix(&address, ctx.requested_prefix).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "S3 returned object key '{}' outside requested prefix '{}'",
                    key,
                    RedactedUrl(ctx.requested_prefix)
                ),
            )
        })?;
        let mtime = listed.last_modified.and_then(datetime_to_system_time);
        let (etag, etag_strength) = normalize_optional_wire_etag(listed.e_tag);
        let size = listed.size.and_then(|n| u64::try_from(n).ok());
        let mut system_metadata: SystemMetadata = SystemMetadata::new();
        if let Some(class) = listed.storage_class {
            system_metadata.insert("x-amz-storage-class".into(), class.into());
        }
        let kind = if key.ends_with('/') && size.unwrap_or(0) == 0 {
            ObjectKind::DirectoryMarker
        } else {
            ObjectKind::File
        };
        if kind == ObjectKind::DirectoryMarker {
            marker_addresses.insert(address.as_str().to_string());
        }
        // A directory kind is never pinned, whatever version id the wire
        // attached to the marker object.
        let versioned_address = if kind == ObjectKind::File {
            s3_version_pin(listed.version_id)
                .map(|version_id| s3_version_address(&address, version_id))
                .transpose()?
        } else {
            None
        };
        page_items.push(ObjectInfo {
            etag_strength,
            address,
            kind,
            etag,
            // Reported as the store spelled it, `null` included, like HEAD.
            version: listed.version_id.map(str::to_string),
            size: (kind == ObjectKind::File).then_some(size).flatten(),
            mtime,
            checksums: ChecksumSet::default(),
            effective_permissions: None,
            system_metadata: (!system_metadata.is_empty()).then_some(system_metadata),
            user_metadata: None,
            modified_by: None,
            versioned_address,
        });
    }
    for prefix_entry in prefixes {
        let Some(prefix_str) = prefix_entry.prefix() else {
            continue;
        };
        let Ok(address) = address::join_relative(ctx.bucket_root, prefix_str) else {
            tracing::warn!(
                target: "ovstorage.s3.backend",
                plugin = "s3",
                key = %prefix_str,
                "s3: common prefix is not addressable as a URI path; omitted from listing",
            );
            continue;
        };
        // Prefer a concrete marker reported in this page or across
        // the immediately adjacent page boundary.
        if marker_addresses.contains(address.as_str())
            || previous_page_marker_addresses.contains(address.as_str())
        {
            continue;
        }
        let _ = address::relative_suffix(&address, ctx.requested_prefix).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "S3 returned common prefix '{}' outside requested prefix '{}'",
                    prefix_str,
                    RedactedUrl(ctx.requested_prefix)
                ),
            )
        })?;
        // S3 has no explicit directory entity; tag CommonPrefixes as `DirectoryInferred`.
        page_items.push(ObjectInfo {
            etag_strength: EtagStrength::Unspecified,
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
            versioned_address: None,
        });
    }

    // The response-sized bound both walks share; the buffered `list` applies
    // its cumulative ceiling separately. A conforming response cannot reach
    // it because every request asks for at most 1000.
    if page_items.len() > LIST_ITEM_CEILING {
        return Err(refuse_partial_listing(
            ErrorCode::Internal,
            ctx.requested_prefix,
            &format!(
                "one response carried the listing past this backend's \
                 {LIST_ITEM_CEILING}-entry ceiling; the store answered with \
                 far more than the {S3_MAX_KEYS_PER_PAGE} keys per response it \
                 was asked for"
            ),
        ));
    }
    Ok((page_items, marker_addresses))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    struct ListFixture {
        endpoint: String,
        requests: Arc<AtomicUsize>,
    }

    fn list_body(contents: &[&str], prefixes: &[&str], next: Option<&str>) -> String {
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>bucket</Name><Prefix>assets/</Prefix>",
        );
        // `KeyCount` as S3 spells it: the keys and common prefixes of this
        // response.
        body.push_str(&format!(
            "<KeyCount>{}</KeyCount>",
            contents.len() + prefixes.len()
        ));
        body.push_str(if next.is_some() {
            "<IsTruncated>true</IsTruncated>"
        } else {
            "<IsTruncated>false</IsTruncated>"
        });
        if let Some(token) = next {
            body.push_str(&format!(
                "<NextContinuationToken>{token}</NextContinuationToken>"
            ));
        }
        for key in contents {
            let size = if key.ends_with('/') { 0 } else { 1 };
            body.push_str(&format!(
                "<Contents><Key>{key}</Key>\
                 <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
                 <ETag>&quot;etag&quot;</ETag><Size>{size}</Size></Contents>"
            ));
        }
        for prefix in prefixes {
            body.push_str(&format!(
                "<CommonPrefixes><Prefix>{prefix}</Prefix></CommonPrefixes>"
            ));
        }
        body.push_str("</ListBucketResult>");
        body
    }

    /// A `ListObjectVersions` answer. `versions` are `(key, version_id,
    /// is_latest)`, `delete_markers` are `(key, is_latest)`, and `next` is the
    /// `(NextKeyMarker, NextVersionIdMarker)` pair of a truncated page.
    fn list_versions_body(
        versions: &[(&str, &str, bool)],
        delete_markers: &[(&str, bool)],
        prefixes: &[&str],
        next: Option<(&str, &str)>,
    ) -> String {
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>bucket</Name><Prefix>assets/</Prefix>",
        );
        body.push_str(if next.is_some() {
            "<IsTruncated>true</IsTruncated>"
        } else {
            "<IsTruncated>false</IsTruncated>"
        });
        if let Some((key_marker, version_id_marker)) = next {
            body.push_str(&format!(
                "<NextKeyMarker>{key_marker}</NextKeyMarker>\
                 <NextVersionIdMarker>{version_id_marker}</NextVersionIdMarker>"
            ));
        }
        for (key, version_id, is_latest) in versions {
            let size = if key.ends_with('/') { 0 } else { 1 };
            body.push_str(&format!(
                "<Version><Key>{key}</Key><VersionId>{version_id}</VersionId>\
                 <IsLatest>{is_latest}</IsLatest>\
                 <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
                 <ETag>&quot;etag&quot;</ETag><Size>{size}</Size>\
                 <StorageClass>STANDARD</StorageClass></Version>"
            ));
        }
        for (key, is_latest) in delete_markers {
            body.push_str(&format!(
                "<DeleteMarker><Key>{key}</Key><VersionId>marker</VersionId>\
                 <IsLatest>{is_latest}</IsLatest>\
                 <LastModified>2026-01-02T03:04:05.000Z</LastModified></DeleteMarker>"
            ));
        }
        for prefix in prefixes {
            body.push_str(&format!(
                "<CommonPrefixes><Prefix>{prefix}</Prefix></CommonPrefixes>"
            ));
        }
        body.push_str("</ListVersionsResult>");
        body
    }

    /// `spawn_list_fixture` that also keeps every request it answered, for
    /// assertions on the wire shape.
    fn recording_fixture(
        answer: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> (ListFixture, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_for_fixture = Arc::clone(&seen);
        let fixture = spawn_list_fixture(move |request| {
            seen_for_fixture.lock().unwrap().push(request.to_string());
            answer(request)
        });
        (fixture, seen)
    }

    /// The request line of every request a recording fixture answered.
    fn request_lines(seen: &Mutex<Vec<String>>) -> Vec<String> {
        seen.lock()
            .unwrap()
            .iter()
            .map(|request| request.lines().next().unwrap_or_default().to_string())
            .collect()
    }

    /// The query of one request line as `(name, value)` pairs, so a test can
    /// ask for `max-keys=1` without also matching `max-keys=1000`.
    fn query_pairs(request_line: &str) -> Vec<(String, String)> {
        request_line
            .split(' ')
            .nth(1)
            .and_then(|target| target.split_once('?'))
            .map(|(_, query)| {
                query
                    .split('&')
                    .map(|pair| {
                        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                        (name.to_string(), value.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Asserts one request line is the prefix probe for `encoded_prefix`: a
    /// `ListObjectsV2` request for a single key with no delimiter.
    fn assert_prefix_probe(line: &str, encoded_prefix: &str) {
        let pairs = query_pairs(line);
        let has = |name: &str, value: &str| pairs.iter().any(|(n, v)| n == name && v == value);
        assert!(has("list-type", "2"), "{line}");
        assert!(has("max-keys", "1"), "{line}");
        assert!(has("prefix", encoded_prefix), "{line}");
        assert!(
            !pairs.iter().any(|(name, _)| name == "delimiter"),
            "a probe counts keys at any depth: {line}"
        );
    }

    fn spawn_list_fixture(answer: impl Fn(&str) -> String + Send + Sync + 'static) -> ListFixture {
        spawn_status_fixture(move |request| (200, answer(request)))
    }

    /// `spawn_list_fixture` whose answer also picks the HTTP status, for a
    /// request the store refuses.
    fn spawn_status_fixture(
        answer: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
    ) -> ListFixture {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind list fixture");
        let endpoint = format!("http://{}", listener.local_addr().expect("fixture address"));
        let requests = Arc::new(AtomicUsize::new(0));
        let requests_for_thread = requests.clone();
        let answer = Arc::new(answer);
        thread::Builder::new()
            .name("ovs-s3-list-stream-test".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("set fixture timeout");
                    let mut raw = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    while let Ok(read) = stream.read(&mut chunk) {
                        if read == 0 {
                            break;
                        }
                        raw.extend_from_slice(&chunk[..read]);
                        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let raw = String::from_utf8_lossy(&raw);
                    requests_for_thread.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = answer(&raw);
                    let reason = match status {
                        200 => "OK",
                        500 => "Internal Server Error",
                        _ => "Error",
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\n\
                         x-amz-request-id: TESTREQ\r\nContent-Type: application/xml\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            })
            .expect("spawn list fixture");
        ListFixture { endpoint, requests }
    }

    fn list_test_backend(endpoint: &str) -> S3Backend {
        S3Backend::anonymous(S3Config {
            bucket: "bucket".into(),
            region: "us-east-1".into(),
            endpoint: Some(endpoint.into()),
            profile_name: None,
            compatibility: crate::config::CompatibilityProfile::Custom,
            force_path_style: true,
            force_request_payer: false,
            sqs_queue_url: None,
            sqs_max_messages: 10,
            sqs_wait_seconds: 20,
            sqs_visibility_timeout: 30,
            address_root: address::parse("s3://bucket/").expect("test root"),
        })
        .expect("anonymous test backend")
    }

    fn list_test_target() -> ResolvedTarget {
        ResolvedTarget {
            backend_id: ovstorage_plugin::BackendId("s3-test".into()),
            resolved_address: address::parse("s3://bucket/assets/").expect("test prefix"),
        }
    }

    async fn stream_addresses(mut stream: ovstorage_plugin::ListStream) -> Result<Vec<String>> {
        let mut addresses = Vec::new();
        while let Some(item) = stream.next().await {
            addresses.push(item?.address.to_string());
        }
        Ok(addresses)
    }

    #[tokio::test]
    async fn buffered_and_streaming_lists_share_multi_page_order_in_both_modes() {
        let fixture = spawn_list_fixture(|request| {
            let second = request.contains("continuation-token=NEXT");
            let delimited = request.contains("delimiter=%2F");
            match (delimited, second) {
                (true, false) => {
                    list_body(&["assets/team/file.txt"], &["assets/docs/"], Some("NEXT"))
                }
                (true, true) => list_body(&["assets/z.usd"], &["assets/x/"], None),
                (false, false) => list_body(&["assets/a.usd"], &[], Some("NEXT")),
                (false, true) => list_body(&["assets/b.usd"], &[], None),
            }
        });
        let backend = list_test_backend(&fixture.endpoint);

        for recursive in [false, true] {
            let options = ListOptions {
                recursive,
                ..ListOptions::default()
            };
            let buffered = backend
                .list(list_test_target(), options.clone(), None)
                .await
                .expect("buffered list");
            let buffered: Vec<String> = buffered
                .into_iter()
                .map(|item| item.address.to_string())
                .collect();
            let streamed = stream_addresses(
                backend
                    .list_stream(list_test_target(), options, None)
                    .await
                    .expect("open list stream"),
            )
            .await
            .expect("consume list stream");
            assert_eq!(streamed, buffered, "recursive={recursive}");
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 8);
    }

    #[tokio::test]
    async fn buffered_list_retains_whole_walk_marker_dedup() {
        // A conforming S3 walk places a marker and its matching common prefix
        // together or across an adjacent page boundary. Keep the buffered
        // backend's historical behavior even when a nonconforming store puts
        // an intervening page between them; the bounded stream deliberately
        // retains only the current and previous page's markers.
        let fixture = spawn_list_fixture(|request| {
            if request.contains("continuation-token=FIRST") {
                list_body(&["assets/unrelated.usd"], &[], Some("SECOND"))
            } else if request.contains("continuation-token=SECOND") {
                list_body(&[], &["assets/team/"], None)
            } else {
                list_body(&["assets/team/"], &[], Some("FIRST"))
            }
        });
        let backend = list_test_backend(&fixture.endpoint);

        let items = backend
            .list(list_test_target(), ListOptions::default(), None)
            .await
            .expect("buffered list");

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].address.as_str(), "s3://bucket/assets/team/");
        assert_eq!(items[0].kind, ObjectKind::DirectoryMarker);
        assert_eq!(
            items[1].address.as_str(),
            "s3://bucket/assets/unrelated.usd"
        );
        assert_eq!(items[1].kind, ObjectKind::File);
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn streaming_list_cycle_guard_fails_transient_mid_stream() {
        let fixture = spawn_list_fixture(|request| {
            if request.contains("continuation-token=A") {
                list_body(&["assets/two.usd"], &[], Some("B"))
            } else if request.contains("continuation-token=B") {
                list_body(&["assets/three.usd"], &[], Some("A"))
            } else {
                list_body(&["assets/one.usd"], &[], Some("A"))
            }
        });
        let backend = list_test_backend(&fixture.endpoint);
        let mut stream = backend
            .list_stream(list_test_target(), ListOptions::default(), None)
            .await
            .expect("open list stream");

        for expected in ["one.usd", "two.usd", "three.usd"] {
            let item = stream
                .next()
                .await
                .expect("stream item")
                .expect("entry before cycle");
            assert!(item.address.path().ends_with(expected));
        }
        let error = stream
            .next()
            .await
            .expect("cycle error")
            .expect_err("cycle must fail");
        assert_eq!(error.code(), ErrorCode::Transient);
        assert!(error.message().contains("reissued a continuation token"));
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn streaming_list_cancellation_between_pages_prevents_next_request() {
        let fixture = spawn_list_fixture(|request| {
            if request.contains("continuation-token=NEXT") {
                list_body(&["assets/two.usd"], &[], None)
            } else {
                list_body(&["assets/one.usd"], &[], Some("NEXT"))
            }
        });
        let backend = list_test_backend(&fixture.endpoint);
        let cancel = CancellationToken::new();
        let mut stream = backend
            .list_stream(
                list_test_target(),
                ListOptions::default(),
                Some(cancel.clone()),
            )
            .await
            .expect("open list stream");

        let first = stream
            .next()
            .await
            .expect("first item")
            .expect("first page succeeds");
        assert!(first.address.path().ends_with("one.usd"));
        cancel.cancel();
        let error = stream
            .next()
            .await
            .expect("cancellation item")
            .expect_err("cancelled stream must stop");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert_eq!(
            fixture.requests.load(Ordering::SeqCst),
            1,
            "cancellation between pages must prevent the second request"
        );
    }

    #[tokio::test]
    async fn streaming_list_cancellation_while_draining_final_page_is_terminal() {
        let fixture =
            spawn_list_fixture(|_| list_body(&["assets/one.usd", "assets/two.usd"], &[], None));
        let backend = list_test_backend(&fixture.endpoint);
        let cancel = CancellationToken::new();
        let mut stream = backend
            .list_stream(
                list_test_target(),
                ListOptions::default(),
                Some(cancel.clone()),
            )
            .await
            .expect("open list stream");

        let first = stream
            .next()
            .await
            .expect("first item")
            .expect("first item succeeds");
        assert!(first.address.path().ends_with("one.usd"));
        cancel.cancel();
        let error = stream
            .next()
            .await
            .expect("terminal cancellation")
            .expect_err("cancelled stream must not drain the fetched page");
        assert_eq!(error.code(), ErrorCode::Cancelled);
        assert!(stream.next().await.is_none());
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    }

    fn pin_summary(items: &[ObjectInfo]) -> Vec<(&str, ObjectKind, Option<&str>)> {
        items
            .iter()
            .map(|item| {
                (
                    item.address.as_str(),
                    item.kind,
                    item.versioned_address.as_ref().map(Url::as_str),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn versioned_list_keeps_only_latest_versions_and_pins_them() {
        let (fixture, seen) = recording_fixture(|request| {
            // The probe finds a current object under `assets/docs/`, so the
            // prefix stays.
            if request.contains("list-type=2") {
                return list_body(&["assets/docs/guide.usd"], &[], None);
            }
            list_versions_body(
                &[
                    ("assets/a.usd", "v2", true),
                    ("assets/a.usd", "v1", false),
                    ("assets/b.usd", "v1", false),
                    ("assets/team/", "m1", true),
                ],
                &[("assets/b.usd", true)],
                &["assets/docs/"],
                None,
            )
        });
        let backend = list_test_backend(&fixture.endpoint);
        let options = ListOptions {
            versioned_address: true,
            ..ListOptions::default()
        };

        let buffered = backend
            .list(list_test_target(), options.clone(), None)
            .await
            .expect("versioned list");
        assert_eq!(
            pin_summary(&buffered),
            vec![
                (
                    "s3://bucket/assets/a.usd",
                    ObjectKind::File,
                    Some("s3://bucket/assets/a.usd?versionId=v2"),
                ),
                (
                    "s3://bucket/assets/team/",
                    ObjectKind::DirectoryMarker,
                    None
                ),
                (
                    "s3://bucket/assets/docs/",
                    ObjectKind::DirectoryInferred,
                    None
                ),
            ],
            "only the IsLatest version of a key is listed, and a key whose latest \
             entry is a delete marker is absent"
        );
        assert_eq!(
            buffered[0].version.as_deref(),
            Some("v2"),
            "the flagged list carries the version id the wire supplied"
        );

        let mut stream = backend
            .list_stream(list_test_target(), options, None)
            .await
            .expect("open list stream");
        let mut streamed = Vec::new();
        while let Some(item) = stream.next().await {
            streamed.push(item.expect("streamed item"));
        }
        assert_eq!(pin_summary(&streamed), pin_summary(&buffered));

        let lines = request_lines(&seen);
        let (versions, probes): (Vec<_>, Vec<_>) =
            lines.iter().partition(|line| line.contains("?versions"));
        assert_eq!(
            versions.len(),
            2,
            "one versions page per listing, buffered and streamed"
        );
        for line in &versions {
            assert!(line.contains("delimiter=%2F"), "{line}");
            assert!(line.contains("prefix=assets%2F"), "{line}");
        }
        assert_eq!(
            probes.len(),
            2,
            "the common prefix is probed once per listing; the marker-backed \
             `assets/team/` is a current object and is not"
        );
        for line in &probes {
            assert_prefix_probe(line, "assets%2Fdocs%2F");
        }
    }

    #[tokio::test]
    async fn versioned_list_drops_common_prefixes_without_a_current_object() {
        // S3 folds delete markers and non-current versions into a common
        // prefix as readily as live objects, so the response alone cannot tell
        // the two prefixes apart; the probe can: nothing current answers under
        // `assets/docs/`, one key does under `assets/team2/`.
        let (fixture, seen) = recording_fixture(|request| {
            if !request.contains("list-type=2") {
                return list_versions_body(
                    &[("assets/a.usd", "v1", true)],
                    &[],
                    &["assets/docs/", "assets/team2/"],
                    None,
                );
            }
            if request.contains("prefix=assets%2Fdocs%2F") {
                list_body(&[], &[], None)
            } else {
                list_body(&["assets/team2/readme.usd"], &[], None)
            }
        });
        let backend = list_test_backend(&fixture.endpoint);
        let options = ListOptions {
            versioned_address: true,
            ..ListOptions::default()
        };

        let buffered = backend
            .list(list_test_target(), options.clone(), None)
            .await
            .expect("versioned list");
        assert_eq!(
            pin_summary(&buffered),
            vec![
                (
                    "s3://bucket/assets/a.usd",
                    ObjectKind::File,
                    Some("s3://bucket/assets/a.usd?versionId=v1"),
                ),
                (
                    "s3://bucket/assets/team2/",
                    ObjectKind::DirectoryInferred,
                    None
                ),
            ],
            "a common prefix with nothing current under it is not a directory \
             the unflagged listing reports, so it is not one here either"
        );

        let lines = request_lines(&seen);
        assert_eq!(
            lines.len(),
            3,
            "one versions page, then one probe per prefix in page order"
        );
        assert!(lines[0].contains("?versions"), "{}", lines[0]);
        assert_prefix_probe(&lines[1], "assets%2Fdocs%2F");
        assert_prefix_probe(&lines[2], "assets%2Fteam2%2F");

        let mut stream = backend
            .list_stream(list_test_target(), options, None)
            .await
            .expect("open list stream");
        let mut streamed = Vec::new();
        while let Some(item) = stream.next().await {
            streamed.push(item.expect("streamed item"));
        }
        assert_eq!(pin_summary(&streamed), pin_summary(&buffered));
        assert_eq!(
            request_lines(&seen).len(),
            6,
            "the streamed walk probes the same prefixes over again"
        );
    }

    /// A refusal as S3 spells it, for a probe the store fails.
    const INTERNAL_ERROR_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <Error><Code>InternalError</Code>\
        <Message>We encountered an internal error. Please try again.</Message>\
        <RequestId>TESTREQ</RequestId></Error>";

    #[tokio::test]
    async fn versioned_list_fails_the_page_when_a_prefix_probe_fails() {
        let fixture = spawn_status_fixture(|request| {
            if request.contains("list-type=2") {
                (500, INTERNAL_ERROR_BODY.to_string())
            } else {
                (
                    200,
                    list_versions_body(
                        &[("assets/a.usd", "v1", true)],
                        &[],
                        &["assets/docs/"],
                        None,
                    ),
                )
            }
        });
        let backend = list_test_backend(&fixture.endpoint);
        let options = ListOptions {
            versioned_address: true,
            ..ListOptions::default()
        };

        let error = backend
            .list(list_test_target(), options.clone(), None)
            .await
            .expect_err("a prefix the walk cannot verify fails the page");
        assert_eq!(error.code(), ErrorCode::Transient);
        let message = error.message();
        assert!(message.contains("s3 list (prefix probe)"), "{message}");
        assert!(message.contains("InternalError"), "{message}");
        assert_eq!(
            fixture.requests.load(Ordering::SeqCst),
            2,
            "the versions page and the probe that failed; nothing is retried"
        );

        let mut stream = backend
            .list_stream(list_test_target(), options, None)
            .await
            .expect("open list stream");
        let streamed = stream
            .next()
            .await
            .expect("the failure is the stream's only item")
            .expect_err("no item of the page is delivered ahead of the failure");
        assert_eq!(streamed.code(), ErrorCode::Transient);
        assert!(stream.next().await.is_none());
    }

    /// A `ListObjectsV2` answer from a store that omits `KeyCount`.
    const UNCOUNTED_LIST_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
        <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
        <Name>bucket</Name><Prefix>assets/uncounted/</Prefix>\
        <IsTruncated>false</IsTruncated>\
        <Contents><Key>assets/uncounted/x.usd</Key>\
        <LastModified>2026-01-02T03:04:05.000Z</LastModified>\
        <ETag>&quot;etag&quot;</ETag><Size>1</Size></Contents>\
        </ListBucketResult>";

    #[tokio::test]
    async fn prefix_probe_reads_key_count_then_contents() {
        let (fixture, seen) = recording_fixture(|request| {
            if request.contains("prefix=assets%2Fempty%2F") {
                list_body(&[], &[], None)
            } else if request.contains("prefix=assets%2Funcounted%2F") {
                UNCOUNTED_LIST_BODY.to_string()
            } else {
                list_body(&["assets/full/x.usd"], &[], None)
            }
        });
        let backend = list_test_backend(&fixture.endpoint);
        let walk = ListWalk {
            prefix_key: "assets/".into(),
            bucket_root: address::parse("s3://bucket/").expect("bucket root"),
            requested_prefix: address::parse("s3://bucket/assets/").expect("prefix"),
            config: backend.config.clone(),
            client: backend.unsigned_capable_client().clone(),
            anonymous: backend.anonymous.clone(),
            region_mismatch: Arc::clone(&backend.region_mismatch),
        };

        assert!(
            !walk
                .prefix_has_current_object("assets/empty/")
                .await
                .expect("probe"),
            "KeyCount 0 and no Contents"
        );
        assert!(
            walk.prefix_has_current_object("assets/full/")
                .await
                .expect("probe"),
            "KeyCount 1"
        );
        assert!(
            walk.prefix_has_current_object("assets/uncounted/")
                .await
                .expect("probe"),
            "Contents stands in for a KeyCount the store omits"
        );

        let lines = request_lines(&seen);
        assert_eq!(lines.len(), 3);
        assert_prefix_probe(&lines[0], "assets%2Fempty%2F");
        assert_prefix_probe(&lines[1], "assets%2Ffull%2F");
        assert_prefix_probe(&lines[2], "assets%2Funcounted%2F");
    }

    #[tokio::test]
    async fn versioned_list_follows_key_and_version_markers() {
        let (fixture, seen) = recording_fixture(|request| {
            if request.contains("key-marker=") {
                list_versions_body(&[("assets/b.usd", "v7", true)], &[], &[], None)
            } else {
                list_versions_body(
                    &[("assets/a.usd", "v2", true)],
                    &[],
                    &[],
                    Some(("assets/a.usd", "v2")),
                )
            }
        });
        let backend = list_test_backend(&fixture.endpoint);

        let items = backend
            .list(
                list_test_target(),
                ListOptions {
                    recursive: true,
                    versioned_address: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .expect("versioned list");
        assert_eq!(
            pin_summary(&items),
            vec![
                (
                    "s3://bucket/assets/a.usd",
                    ObjectKind::File,
                    Some("s3://bucket/assets/a.usd?versionId=v2"),
                ),
                (
                    "s3://bucket/assets/b.usd",
                    ObjectKind::File,
                    Some("s3://bucket/assets/b.usd?versionId=v7"),
                ),
            ]
        );

        let lines = request_lines(&seen);
        assert_eq!(lines.len(), 2);
        assert!(!lines[0].contains("key-marker="), "{}", lines[0]);
        assert!(
            lines[1].contains("key-marker=assets%2Fa.usd"),
            "{}",
            lines[1]
        );
        assert!(lines[1].contains("version-id-marker=v2"), "{}", lines[1]);
        for line in &lines {
            assert!(
                !line.contains("delimiter="),
                "a recursive walk sends no delimiter: {line}"
            );
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn list_page_token_minted_under_the_other_flag_is_refused() {
        let fixture = spawn_list_fixture(|_| list_body(&[], &[], None));
        let backend = list_test_backend(&fixture.endpoint);

        let replayed_as_current = backend
            .list(
                list_test_target(),
                ListOptions {
                    page_token: Some(encode_versions_token("assets/a.usd", Some("v2"))),
                    versioned_address: false,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .expect_err("a versions token cannot continue a V2 walk");
        assert_eq!(replayed_as_current.code(), ErrorCode::InvalidArgument);
        let message = replayed_as_current.message();
        assert!(message.contains("versioned_address=true"), "{message}");
        assert!(message.contains("versioned_address=false"), "{message}");

        let replayed_as_versioned = backend
            .list(
                list_test_target(),
                ListOptions {
                    page_token: Some("OPAQUE".into()),
                    versioned_address: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .expect_err("a V2 token cannot continue a versions walk");
        assert_eq!(replayed_as_versioned.code(), ErrorCode::InvalidArgument);
        let message = replayed_as_versioned.message();
        assert!(message.contains("versioned_address=false"), "{message}");
        assert!(message.contains("versioned_address=true"), "{message}");

        assert_eq!(
            fixture.requests.load(Ordering::SeqCst),
            0,
            "the refusal happens before any request is sent"
        );
    }

    #[tokio::test]
    async fn null_listed_version_id_is_not_a_pin() {
        let fixture = spawn_list_fixture(|_| {
            list_versions_body(&[("assets/a.usd", "null", true)], &[], &[], None)
        });
        let backend = list_test_backend(&fixture.endpoint);

        let items = backend
            .list(
                list_test_target(),
                ListOptions {
                    versioned_address: true,
                    ..ListOptions::default()
                },
                None,
            )
            .await
            .expect("versioned list");
        assert_eq!(
            pin_summary(&items),
            vec![("s3://bucket/assets/a.usd", ObjectKind::File, None)]
        );
        assert_eq!(
            items[0].version.as_deref(),
            Some("null"),
            "the opaque version id is still reported as the store spelled it"
        );

        let versions = backend
            .list_versions(
                ResolvedTarget {
                    backend_id: ovstorage_plugin::BackendId("s3-test".into()),
                    resolved_address: address::parse("s3://bucket/assets/a.usd").expect("key"),
                },
                ListVersionsOptions::default(),
                None,
            )
            .await
            .expect("list_versions");
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].address.as_str(),
            "s3://bucket/assets/a.usd?versionId=null"
        );
        assert_eq!(
            versions[0].versioned_address, None,
            "the null version's address selects mutable content, so it is not a pin"
        );
    }

    #[tokio::test]
    async fn unflagged_list_reports_no_versioned_address() {
        let (fixture, seen) = recording_fixture(|_| {
            list_body(&["assets/team/", "assets/a.usd"], &["assets/docs/"], None)
        });
        let backend = list_test_backend(&fixture.endpoint);

        let items = backend
            .list(list_test_target(), ListOptions::default(), None)
            .await
            .expect("list");
        assert_eq!(
            pin_summary(&items),
            vec![
                (
                    "s3://bucket/assets/team/",
                    ObjectKind::DirectoryMarker,
                    None
                ),
                ("s3://bucket/assets/a.usd", ObjectKind::File, None),
                (
                    "s3://bucket/assets/docs/",
                    ObjectKind::DirectoryInferred,
                    None
                ),
            ]
        );

        let lines = request_lines(&seen);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("list-type=2"), "{}", lines[0]);
        assert!(!lines[0].contains("versions"), "{}", lines[0]);
    }

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
    fn head_object_etag_declares_normalized_wire_strength() {
        let address = address::parse("s3://bucket/object").unwrap();
        let strong = HeadObjectOutput::builder().e_tag("\"strong\"").build();
        let info = object_info_from_head_output(&address, &strong).expect("head info");
        assert_eq!(info.etag.as_deref(), Some("strong"));
        assert_eq!(info.etag_strength, EtagStrength::Strong);

        let weak = HeadObjectOutput::builder().e_tag("W/\"weak\"").build();
        let info = object_info_from_head_output(&address, &weak).expect("head info");
        assert_eq!(info.etag.as_deref(), Some("weak"));
        assert_eq!(info.etag_strength, EtagStrength::Weak);

        let absent = HeadObjectOutput::builder().build();
        let info = object_info_from_head_output(&address, &absent).expect("head info");
        assert_eq!(info.etag, None);
        assert_eq!(info.etag_strength, EtagStrength::Unspecified);
    }

    #[test]
    fn head_object_version_id_pins_the_address() {
        let address = address::parse("s3://bucket/object").unwrap();
        let pinned = HeadObjectOutput::builder().version_id("abc").build();
        let info = object_info_from_head_output(&address, &pinned).expect("head info");
        assert_eq!(info.version.as_deref(), Some("abc"));
        assert_eq!(
            info.versioned_address.as_ref().map(Url::as_str),
            Some("s3://bucket/object?versionId=abc")
        );

        // A selector already on the address is replaced, not stacked.
        let selected = address::parse("s3://bucket/object?versionId=old").unwrap();
        let info = object_info_from_head_output(&selected, &pinned).expect("head info");
        assert_eq!(
            info.versioned_address.as_ref().map(Url::as_str),
            Some("s3://bucket/object?versionId=abc")
        );

        let absent = HeadObjectOutput::builder().build();
        let info = object_info_from_head_output(&address, &absent).expect("head info");
        assert_eq!(info.version, None);
        assert_eq!(info.versioned_address, None);
    }

    #[test]
    fn null_head_version_id_is_not_a_pin() {
        assert_eq!(s3_version_pin(Some("null")), None);
        assert_eq!(s3_version_pin(Some("abc")), Some("abc"));
        assert_eq!(s3_version_pin(None), None);

        let address = address::parse("s3://bucket/object").unwrap();
        let null_version = HeadObjectOutput::builder().version_id("null").build();
        let info = object_info_from_head_output(&address, &null_version).expect("head info");
        assert_eq!(
            info.version.as_deref(),
            Some("null"),
            "the opaque version id is still reported as the store spelled it"
        );
        assert_eq!(info.versioned_address, None);
    }

    #[test]
    fn versions_token_round_trips_keys_with_pipes() {
        let token = encode_versions_token("a|b", Some("x|y"));
        assert!(token.starts_with(VERSIONED_LIST_TOKEN_PREFIX));
        assert_eq!(
            decode_versions_token(&token).expect("decode"),
            ("a|b".to_string(), Some("x|y".to_string()))
        );

        let token = encode_versions_token("plain/key", None);
        assert_eq!(
            decode_versions_token(&token).expect("decode"),
            ("plain/key".to_string(), None)
        );

        let error =
            decode_versions_token("OPAQUE").expect_err("a V2 token is not a versions token");
        assert_eq!(error.code(), ErrorCode::InvalidArgument);
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
        anonymous_backend_in("us-east-1", force_request_payer)
    }

    fn anonymous_backend_in(region: &str, force_request_payer: bool) -> S3Backend {
        let config = S3Config {
            bucket: "bucket".into(),
            region: region.into(),
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

    /// A public-bucket read in the China partition has to reach
    /// `amazonaws.com.cn`. The alias rules accept the `.com.cn` spelling a
    /// user pastes and rewrite it to `s3://bucket/`; if this path then rebuilt
    /// the host on the standard suffix, that valid URL would be redirected to
    /// a hostname that does not exist.
    #[test]
    fn anonymous_read_request_uses_the_china_partition_host() {
        let request = anonymous_backend_in("cn-north-1", false)
            .anonymous_read_request("dir/key.txt", None, &ReadOptions::default())
            .expect("anonymous read request");
        assert_eq!(
            request.url,
            "https://bucket.s3.cn-north-1.amazonaws.com.cn/dir/key.txt"
        );
    }

    /// And every other partition keeps the standard suffix — GovCloud
    /// included, which is `us-gov-*` on `amazonaws.com`.
    #[test]
    fn anonymous_read_request_keeps_the_standard_suffix_elsewhere() {
        for region in ["us-west-2", "us-gov-west-1"] {
            let request = anonymous_backend_in(region, false)
                .anonymous_read_request("key", None, &ReadOptions::default())
                .expect("anonymous read request");
            assert_eq!(
                request.url,
                format!("https://bucket.s3.{region}.amazonaws.com/key")
            );
        }
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

    /// A message that cannot travel as a header value is dropped, not
    /// stashed, so the write proceeds without it instead of failing request
    /// construction; a header-legal non-ASCII message is kept.
    #[test]
    fn with_message_stashed_drops_a_message_that_cannot_travel_as_a_header() {
        let mut user_metadata = UserMetadata::new();
        user_metadata.insert("owner".into(), "alice".into());
        let opts = with_message_stashed(WriteOptions {
            user_metadata: Some(user_metadata.clone()),
            message: Some("line one\r\nx-amz-meta-injected: yes".into()),
            ..WriteOptions::default()
        });
        assert_eq!(opts.user_metadata, Some(user_metadata.clone()));

        let opts = with_message_stashed(WriteOptions {
            user_metadata: Some(user_metadata),
            message: Some("café ☕".into()),
            ..WriteOptions::default()
        });
        assert_eq!(
            opts.user_metadata
                .as_ref()
                .and_then(|m| m.get(MESSAGE_METADATA_KEY))
                .map(String::as_str),
            Some("café ☕")
        );
    }

    /// On a patch the same rule keeps the object's earlier annotation in
    /// place: a message that cannot travel as a header neither replaces it
    /// nor fails the call.
    #[test]
    fn update_metadata_entries_keep_the_earlier_annotation_over_an_unstorable_message() {
        let entries = update_metadata_entries(
            &stored_annotation("old"),
            &HashMap::new(),
            &[],
            Some("line one\r\nline two"),
        );
        let annotations: Vec<&str> = entries
            .iter()
            .filter(|(k, _)| k == MESSAGE_METADATA_KEY)
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(annotations, vec!["old"], "{entries:?}");
    }

    #[test]
    fn with_message_stashed_fills_an_unset_message_key() {
        let mut user_metadata = UserMetadata::new();
        user_metadata.insert("owner".into(), "alice".into());
        let opts = with_message_stashed(WriteOptions {
            user_metadata: Some(user_metadata),
            message: Some("commit note".into()),
            ..WriteOptions::default()
        });
        let metadata = opts.user_metadata.expect("metadata is populated");
        assert_eq!(metadata.get("owner").map(String::as_str), Some("alice"));
        assert_eq!(
            metadata.get(MESSAGE_METADATA_KEY).map(String::as_str),
            Some("commit note")
        );
    }

    #[test]
    fn with_message_stashed_keeps_the_callers_entry_under_the_key() {
        let mut user_metadata = UserMetadata::new();
        user_metadata.insert(MESSAGE_METADATA_KEY.into(), "caller".into());
        let opts = with_message_stashed(WriteOptions {
            user_metadata: Some(user_metadata),
            message: Some("real".into()),
            ..WriteOptions::default()
        });
        let metadata = opts.user_metadata.expect("caller metadata is kept");
        assert_eq!(metadata.len(), 1, "{metadata:?}");
        assert_eq!(
            metadata.get(MESSAGE_METADATA_KEY).map(String::as_str),
            Some("caller")
        );
    }

    /// S3 lower-cases metadata names on the wire, so an upper-cased caller
    /// spelling of the key is the same stored entry and must win too.
    #[test]
    fn with_message_stashed_keeps_a_differently_cased_caller_entry() {
        let caller_key = MESSAGE_METADATA_KEY.to_ascii_uppercase();
        let mut user_metadata = UserMetadata::new();
        user_metadata.insert(caller_key.clone(), "caller".into());
        let opts = with_message_stashed(WriteOptions {
            user_metadata: Some(user_metadata),
            message: Some("real".into()),
            ..WriteOptions::default()
        });
        let metadata = opts.user_metadata.expect("caller metadata is kept");
        assert_eq!(
            metadata.len(),
            1,
            "no second spelling of the key is added: {metadata:?}"
        );
        assert_eq!(
            metadata.get(&caller_key).map(String::as_str),
            Some("caller")
        );
    }

    #[test]
    fn with_message_stashed_leaves_the_map_untouched_without_a_message() {
        for message in [None, Some(String::new())] {
            let mut user_metadata = UserMetadata::new();
            user_metadata.insert("owner".into(), "alice".into());
            let opts = with_message_stashed(WriteOptions {
                user_metadata: Some(user_metadata.clone()),
                message: message.clone(),
                ..WriteOptions::default()
            });
            assert_eq!(
                opts.user_metadata.as_ref(),
                Some(&user_metadata),
                "message {message:?}"
            );

            let opts = with_message_stashed(WriteOptions {
                message: message.clone(),
                ..WriteOptions::default()
            });
            assert_eq!(opts.user_metadata, None, "message {message:?}");
        }
    }

    /// An object's stored metadata as `update_metadata` reads it back, with an
    /// earlier annotation under the key.
    fn stored_annotation(value: &str) -> UserMetadata {
        let mut existing = UserMetadata::new();
        existing.insert("owner".into(), "alice".into());
        existing.insert(MESSAGE_METADATA_KEY.into(), value.into());
        existing
    }

    fn entry<'a>(entries: &'a [(String, String)], key: &str) -> Option<&'a str> {
        entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// A `user_metadata_set` entry under the key stands over the message under
    /// every ASCII case: S3 lower-cases metadata names, so the caller's
    /// spelling folds onto the one stored entry.
    #[test]
    fn update_metadata_entries_keep_the_callers_set_entry_over_the_message() {
        for caller_key in [
            MESSAGE_METADATA_KEY.to_string(),
            MESSAGE_METADATA_KEY.to_ascii_uppercase(),
        ] {
            let mut set = HashMap::new();
            set.insert(caller_key.clone(), "caller".to_string());
            let entries =
                update_metadata_entries(&stored_annotation("old"), &set, &[], Some("real"));
            assert_eq!(entries.len(), 2, "{caller_key}: {entries:?}");
            assert_eq!(entry(&entries, "owner"), Some("alice"), "{caller_key}");
            assert_eq!(
                entry(&entries, MESSAGE_METADATA_KEY),
                Some("caller"),
                "{caller_key}"
            );
        }
    }

    #[test]
    fn update_metadata_entries_replace_an_earlier_annotation_with_the_message() {
        let entries = update_metadata_entries(
            &stored_annotation("old"),
            &HashMap::new(),
            &[],
            Some("real"),
        );
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entry(&entries, "owner"), Some("alice"));
        assert_eq!(entry(&entries, MESSAGE_METADATA_KEY), Some("real"));
    }

    /// Removing the key in the same call does not keep the message off the
    /// object: the removal clears the earlier annotation, the message lands.
    #[test]
    fn update_metadata_entries_land_the_message_when_the_same_call_removes_the_key() {
        let entries = update_metadata_entries(
            &stored_annotation("old"),
            &HashMap::new(),
            &[MESSAGE_METADATA_KEY.to_string()],
            Some("real"),
        );
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(entry(&entries, MESSAGE_METADATA_KEY), Some("real"));
    }

    /// A key named in both `set` and `remove` of one patch is set: `remove`
    /// applies first, so the `set` entry stands.
    #[test]
    fn update_metadata_entries_set_a_key_the_same_call_also_removes() {
        let mut set = HashMap::new();
        set.insert("owner".to_string(), "bob".to_string());
        let entries = update_metadata_entries(
            &stored_annotation("old"),
            &set,
            &["owner".to_string()],
            None,
        );
        assert_eq!(entry(&entries, "owner"), Some("bob"), "{entries:?}");
        assert_eq!(entries.len(), 2, "{entries:?}");
    }

    #[test]
    fn update_metadata_entries_drop_a_removed_annotation_without_a_message() {
        for message in [None, Some("")] {
            let entries = update_metadata_entries(
                &stored_annotation("old"),
                &HashMap::new(),
                &[MESSAGE_METADATA_KEY.to_string()],
                message,
            );
            assert_eq!(
                entries,
                vec![("owner".to_string(), "alice".to_string())],
                "message {message:?}"
            );
        }
    }
}
