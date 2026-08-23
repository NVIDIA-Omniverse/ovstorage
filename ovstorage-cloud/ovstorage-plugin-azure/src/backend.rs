// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Azure Blob Storage / ADLS Gen2 object and data operations (ABI-v2 Layer backend).
//!
//! One backend instance is bound to a `(account, container, hns_flag)` triple
//! and a resolved `AzureAuth`. Every public trait method funnels through the
//! synchronous `AzureClient` for non-redirected requests, or returns a
//! `ReadResult::Redirect` / `WriteStep::Redirects` so the host follower runs
//! the byte-bearing hops directly against Azure.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ovstorage_plugin::{
    AccessDecision, AccessOps, CancellationToken, Capabilities, ChangeKindSet, ChecksumAlgorithm,
    ChecksumSet, CopyOptions, CreateDirectoryOptions, DeleteDirectoryOptions, DeleteOptions, Error,
    ErrorCode, ErrorContext, HttpRequest, IfDestExists, ListOptions, ListVersionsOptions,
    MtimeFormat, ObjectInfo, ObjectKind, ReadOptions, ReadRedirect, RedirectBodySource,
    RedirectCredential, RedirectResultBatch, RedirectScope, RenameOptions, ResolvedTarget,
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

/// What a redirect minted under this connection's authentication mode
/// authorizes. Every redirect this plugin emits carries the credential the
/// matching arm of the URL-signing match installs, so the scope is a property
/// of the mode and of nothing else.
///
/// - `SharedKey` mints a fresh service SAS naming one blob, one permission set
///   and a five-minute expiry, so it authorizes the redirected request alone.
/// - `Sas` appends a token the operator supplied verbatim. It may be scoped to
///   one blob or to the whole account, and the plugin can neither read that out
///   of it nor narrow it, so it must be assumed connection-wide.
/// - The Entra modes send the connection's own bearer, which authorizes every
///   blob the principal can reach for as long as the token lives.
/// - `Anonymous` signs nothing; the redirect carries no credential. Writes
///   refuse this mode before a redirect is minted.
fn redirect_credential(source: &AuthSource) -> RedirectCredential {
    match source {
        AuthSource::SharedKey { .. } => RedirectCredential::Request,
        AuthSource::Sas { .. } => RedirectCredential::Connection,
        AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
            RedirectCredential::Connection
        }
        AuthSource::Anonymous => RedirectCredential::None,
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
#[cfg(test)]
use crate::client::{OperationEvidence, with_operation_evidence};
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

/// Deadline for the advisory HNS kind preflight, which is far shorter than the
/// 60s data-path timeout its client would otherwise lend it.
///
/// Every way of not hearing an answer — a transport error, a 404, a SAS scoped
/// too narrowly — already yields `false` and leaves the read to proceed, so
/// expiry is one more of those and the caller's behaviour is unchanged by it.
/// What it buys is the blackholed `dfs` host: Azure publishes private endpoints
/// per sub-resource, and an account published on `blob` alone has no
/// `privatelink.dfs` zone, so the public `dfs` address resolves and a VNet with
/// no egress — or a firewall that drops rather than rejects — swallows the
/// connection instead of refusing it. `read` on that topology mints its
/// redirect without reaching the service at all, and must not be held for a
/// minute asking a host that will never answer.
///
/// **What the budget covers is the whole of `send_advisory`, not just the HEAD.**
/// On an Entra connection that includes acquiring the bearer, so a cold token
/// cache and a throttled IdP can spend the budget before the `dfs` host is
/// addressed, and the read signs its redirect without a kind verdict. Both ways
/// of excluding the grant cost more than that, and they cost it differently:
///
/// - Warming the token before the clock starts leaves that wait unbounded on
///   `read`'s critical path rather than inside the probe. `read` awaits the
///   same grant either way to sign its redirect, and a failed fetch is not
///   cached, so an IdP that answers nothing is waited on twice over instead of
///   once.
/// - Applying the deadline to the `getStatus` request alone leaves the grant on
///   the client-wide 60s timeout, which is the wait this exists to cap.
///
/// Five seconds is generous headroom for a warm-token cross-region `getStatus`
/// HEAD, which is the answer worth waiting for.
///
/// **The residual, stated rather than solved.** Giving up is not the same as
/// hearing nothing: a `401` whose headers land between this deadline and the
/// client's own is a refusal this probe gives up on rather than witnesses, so
/// it does not advance the refusal epoch. That is the third entry in the list
/// [`AzureClient::send_advisory`] keeps of refusals this probe cannot be relied
/// on to witness, and it is the same trade as the other two — the probe is one
/// witness among a connection's traffic, and a service that refuses a
/// credential refuses the operations too.
const AZURE_HNS_KIND_PROBE_DEADLINE: Duration = Duration::from_secs(5);

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
    ///
    /// This is the shared post-auth construction point — `new` and the
    /// `__test_only_*` hook both land here — which is why the cleartext
    /// endpoint WARNING lives here rather than in config parsing: every
    /// constructor is covered, and the resolved [`AuthSource`] is in hand so
    /// the message describes what will actually reach the wire rather than
    /// which credential fields happen to be present. It is advisory; nothing
    /// here refuses an endpoint.
    #[doc(hidden)]
    pub fn with_auth(config: AzureConnectionConfig, auth: AzureAuth) -> Result<Self> {
        crate::cleartext::warn_on_cleartext_endpoint(&config, auth.source());
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
            matches!(self.client.auth().source(), AuthSource::Anonymous),
        )
    }

    /// One cheap read-only RPC for the connection driver's verify: List Blobs
    /// `maxresults=1` on the configured container. Returns the raw response —
    /// success or HTTP error alike — so the driver can judge the verdict
    /// leniently from the status + `x-ms-error-code`; a transport/IdP failure
    /// surfaces as `Err` for the driver to classify.
    pub(crate) async fn verify_probe(&self) -> Result<crate::client::AzureResponse> {
        let base_url = format!("{}/{}", self.config.blob_url_base(), self.config.container);
        let canonical_path = self.canonical_path_for_blob_container();
        let query: Vec<(String, String)> = vec![
            ("restype".into(), "container".into()),
            ("comp".into(), "list".into()),
            ("maxresults".into(), "1".into()),
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
        self.client.send(req).await
    }

    async fn flat_directory_probe(
        &self,
        prefix: &str,
        address: &ovstorage_plugin::Url,
    ) -> Result<FlatDirectoryProbe> {
        let base_url = format!("{}/{}", self.config.blob_url_base(), self.config.container);
        let canonical_path = self.canonical_path_for_blob_container();
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
                        protocol: Some(self.config.sas_protocol()),
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

    /// Shared Key canonical path for a blob-tier object request.
    ///
    /// Azure canonicalizes as `/{account}` plus the request URI path, with
    /// URI-derived parts "encoded exactly as it is in the URI" — so this must
    /// reproduce the path component of [`Self::blob_url`] byte for byte, and
    /// the key goes through the same [`url_encode_path`] that URL uses.
    ///
    /// Signing the RAW key while sending the encoded one is a mixed
    /// convention that costs an unexplained 403 on any key needing escaping
    /// (a space, a `+`, a non-ASCII segment). The endpoint's path prefix is
    /// encoded for the same reason, so both halves agree: a path-style
    /// emulator (`http://127.0.0.1:10000/devstoreaccount1`) signs
    /// `/devstoreaccount1/container/key`, while host-style addressing keeps
    /// the empty prefix and the familiar `/container/key`.
    fn canonical_path_for_blob(&self, blob_key: &str) -> String {
        format!(
            "{}/{}/{}",
            self.config.blob_canonical_prefix(),
            self.config.container,
            url_encode_path(blob_key),
        )
    }

    /// [`Self::canonical_path_for_blob`]'s DFS-tier twin, prefixed from the
    /// DFS endpoint because the two tiers can be addressed differently, and
    /// encoded to match [`Self::dfs_url`] for the same reason.
    fn canonical_path_for_dfs(&self, path: &str) -> String {
        format!(
            "{}/{}/{}",
            self.config.dfs_canonical_prefix(),
            self.config.container,
            url_encode_path(path.trim_start_matches('/')),
        )
    }

    /// Shared Key canonical path for a blob-tier container request (List
    /// Blobs and friends): the same prefix rule, stopping at the container.
    fn canonical_path_for_blob_container(&self) -> String {
        format!(
            "{}/{}",
            self.config.blob_canonical_prefix(),
            self.config.container
        )
    }

    /// [`Self::canonical_path_for_blob_container`]'s DFS-tier twin, used by
    /// the filesystem-scoped ADLS Gen2 list.
    fn canonical_path_for_dfs_container(&self) -> String {
        format!(
            "{}/{}",
            self.config.dfs_canonical_prefix(),
            self.config.container
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
/// The destination no-overwrite refusal is `AlreadyExists` (the documented
/// `IfDestExists::Fail` contract): a 409 `BlobAlreadyExists` already maps
/// there generically; a 412 on the `If-None-Match: *` header is remapped
/// here — only when the caller requested the no-overwrite condition AND no
/// source precondition is in play (a combined 412 cannot be attributed and
/// keeps `PreconditionFailed`).
fn no_overwrite_412_to_already_exists(
    mapped: Error,
    dest_no_overwrite: bool,
    if_source_absent: bool,
    op: &str,
) -> Error {
    if dest_no_overwrite && if_source_absent && mapped.code() == ErrorCode::PreconditionFailed {
        return Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "Azure {op} refused: destination already exists and IfDestExists::Fail was \
                 requested"
            ),
        );
    }
    mapped
}

/// The refusal an anonymous connection gives for a delegated write: both
/// `write_redirect` arms, and `continue_write`, which is gated by the same
/// withheld bit and so must refuse rather than run behind it.
///
/// `Unsupported`, not `AuthRequired`: `azure_capabilities` withholds
/// `supports_write_redirect` for this connection shape, and the self-gate rule
/// asks a false bit's slot for a typed `Unsupported`. `AuthRequired` would also
/// be read as "your credential was rejected" by machinery that then looks for a
/// credential to refresh, and an anonymous connection has none — the same
/// reasoning as the s3 sibling's `signed_client`.
fn anonymous_write_redirect_unsupported() -> Error {
    Error::new(
        ErrorCode::Unsupported,
        "this Azure connection is anonymous; a write redirect needs a SAS to \
         delegate with, and there is no credential to mint one from",
    )
    .with_next_action(
        "remove and re-add this connection with credentials to write through a redirect",
    )
}

/// `anonymous` withholds `supports_write_redirect`, and nothing else.
///
/// An anonymous connection refuses `write_redirect` locally — there is no SAS
/// to delegate with — so the bit is false and the slot answers a typed
/// `Unsupported` without touching the wire, which is what the Layer contract's
/// self-gate rule asks of a false bit
/// (`docs/public/plugin-storage/CONFORMANCE.md`).
///
/// The rule runs ONE way, and it is worth stating precisely because the
/// converse is tempting and false: a slot that refuses locally is not thereby
/// required to withhold its bit. `write_redirect` on a CREDENTIALED connection
/// refuses locally too when `size_hint` is absent, and rightly keeps the bit —
/// that refusal is about the request, not about the connection. What the rule
/// forbids is only the half-measure: a false bit in front of a slot that still
/// runs.
///
/// Every other bit stays as it is for both auth shapes, deliberately. Azure
/// signs nothing when anonymous and lets the service decide, so `write`,
/// `delete`, `copy` and the rest are genuinely attempted — what comes back is
/// the container's public-access level talking, not the plugin's. What the
/// plugin refuses itself is the delegated-write pair: `write_redirect`, which
/// has no SAS to mint, and `continue_write`, which this bit gates implicitly.
pub(crate) fn azure_capabilities(
    hierarchical_namespace: bool,
    change_feed_enabled: bool,
    anonymous: bool,
) -> Capabilities {
    let mut caps = Capabilities::empty();
    caps.supports_no_overwrite_write = true;
    caps.supports_if_match_write = true;
    caps.supports_native_metadata_patch = true;
    caps.supports_metadata_rewrite_emulation = false;
    caps.writes_are_atomic = true;
    caps.supports_write = true;
    caps.supports_write_stream = true;
    caps.supports_write_redirect = !anonymous;
    caps.supports_delete = true;
    caps.supports_server_side_copy = true;
    caps.supports_copy = true;
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
    // Availability: the non-HNS path renames via copy+delete, so `rename`
    // is offered on both namespace shapes; only the mechanism differs.
    caps.supports_rename = true;
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

/// A built, unsigned ADLS Gen2 `getStatus` HEAD. Holds the three pieces that
/// must agree for the Shared Key signature to be valid, so the URL and the
/// canonical path cannot be constructed apart from each other.
struct HnsStatusProbe {
    url: String,
    canonical_path: String,
    canonical_query: Vec<(String, String)>,
}

impl HnsStatusProbe {
    fn request(&self) -> AzureRequest<'_> {
        AzureRequest {
            method: reqwest::Method::HEAD,
            url: self.url.clone(),
            canonical_path: &self.canonical_path,
            canonical_query: self.canonical_query.clone(),
            extra_headers: vec![],
            content_type: None,
            content_md5: None,
            if_match: None,
            if_none_match: None,
            range: None,
            body: None,
        }
    }
}

/// The Azure object/data operations used by the native Layer slots.
/// `crate::layer::AzureLayer` delegates its operation slots here.
impl AzureBackend {
    /// Whether the IdP has refused a grant for this connection's credential
    /// and has not since issued one. See `AzureAuth::credential_refused`.
    pub(crate) fn credential_refused(&self) -> bool {
        self.client.credential_refused()
    }

    /// The connection's refusal epoch. See `AzureClient::refusal_epoch`.
    pub(crate) fn refusal_epoch(&self) -> u64 {
        self.client.refusal_epoch()
    }

    pub async fn stat(
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
                    let probe = self.hns_get_status_probe(&blob_key, version_id.as_deref());
                    let response = self.client.send(probe.request()).await?;
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

    /// The ADLS Gen2 `getStatus` HEAD, built once for the two callers that need
    /// it: `stat`'s HNS branch and `read`'s directory preflight.
    ///
    /// Shared because both are SIGNED, and a signature is only valid if the URL
    /// and the canonical path agree exactly. Two hand-rolled copies of that
    /// assembly drift the moment either side changes — and `canonical_path_for_dfs`
    /// has open work against it. The preflight fails open, so a copy left
    /// behind would produce a request the service refuses and a directory read
    /// that silently goes back to signing a redirect.
    fn hns_get_status_probe(&self, blob_key: &str, version_id: Option<&str>) -> HnsStatusProbe {
        let blob_key = dfs_path_key(blob_key);
        let mut canonical_query: Vec<(String, String)> =
            vec![("action".into(), "getStatus".into())];
        if let Some(vid) = version_id {
            canonical_query.push(("versionid".into(), vid.to_string()));
        }
        HnsStatusProbe {
            url: format!(
                "{}?{}",
                self.dfs_url(blob_key),
                encode_query(&canonical_query)
            ),
            canonical_path: self.canonical_path_for_dfs(blob_key),
            canonical_query,
        }
    }

    /// Whether the ADLS Gen2 (HNS) namespace AFFIRMATIVELY reports `blob_key`
    /// as a directory inode, read from the `x-ms-resource-type` header that
    /// `parse_object_info` trusts for the same verdict on `stat`.
    ///
    /// Only an affirmative `directory` answers `true`. A refused, failed or
    /// unanswered probe — a 404, a SAS scoped narrower than the DFS path, a
    /// transport blip, a host that swallows the connection — is NO verdict, and
    /// the caller proceeds exactly as it would have without the probe. That
    /// keeps the probe from converting a readable object into a failed read:
    /// the refusal it exists to produce is the only outcome it can cause.
    ///
    /// It is that indifference to failure which lets the probe carry a deadline
    /// of its own, [`AZURE_HNS_KIND_PROBE_DEADLINE`], instead of the client's
    /// 60s data-path timeout: expiry yields the same `false` as every other way
    /// of not hearing an answer, so it changes what this read does only by
    /// deciding sooner. It is not free to the promotion machinery, and that
    /// constant records what it costs there.
    ///
    /// That neutrality has to reach the promotion machinery too, which is why
    /// this goes through `send_advisory`. The probe signs against the `dfs`
    /// host while the read hands back a `blob` URL, and Azure provisions
    /// private endpoints per sub-resource — so an account reachable on `blob`
    /// alone answers the public `dfs` host with `403 AuthorizationFailure`.
    /// Counting that as a refusal would advance the connection-wide refusal
    /// epoch on every HNS read and veto the concurrent operations the `blob`
    /// endpoint is happily serving, which is the condition this plugin's
    /// promotion exists to end. An affirmative answer still counts: a service
    /// that answered a signed request authenticated it.
    async fn hns_reports_directory(&self, blob_key: &str, version_id: Option<&str>) -> bool {
        let probe = self.hns_get_status_probe(blob_key, version_id);
        let answered = tokio::time::timeout(
            AZURE_HNS_KIND_PROBE_DEADLINE,
            self.client.send_advisory(probe.request()),
        )
        .await;
        match answered {
            Ok(Ok(response)) if response.ok() => response
                .headers
                .first("x-ms-resource-type")
                .is_some_and(|kind| kind.eq_ignore_ascii_case("directory")),
            Ok(Ok(response)) => {
                tracing::debug!(
                    plugin = "azure",
                    status = response.status,
                    "azure read: directory preflight returned no kind verdict"
                );
                false
            }
            Ok(Err(error)) => {
                tracing::debug!(
                    plugin = "azure",
                    error.code = ?error.code(),
                    "azure read: directory preflight failed; proceeding without a kind verdict"
                );
                false
            }
            Err(_elapsed) => {
                tracing::debug!(
                    plugin = "azure",
                    deadline_secs = AZURE_HNS_KIND_PROBE_DEADLINE.as_secs(),
                    "azure read: directory preflight timed out; proceeding without a kind verdict"
                );
                false
            }
        }
    }

    pub async fn read(
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
                // `Layer::read` owes a directory address `InvalidArgument`
                // wherever `has_real_directories` is advertised, which for
                // azure is exactly `hierarchical_namespace`. The rest of this
                // slot mints a signed URL without touching the service, so the
                // kind verdict has to be asked for: one HNS `getStatus` HEAD,
                // the same call `stat` makes, under a deadline of its own so a
                // `dfs` host that never answers costs seconds rather than the
                // data path's minute. Flat namespaces advertise no real
                // directories and pay nothing.
                if self.config.hierarchical_namespace
                    && self
                        .hns_reports_directory(&blob_key, version_id.as_deref())
                        .await
                {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "read target is a directory; use list()",
                    ));
                }
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

                // Read from the same `AuthSource` the match below signs with, so
                // the declared scope and the installed credential cannot drift.
                let credential = redirect_credential(self.client.auth().source());
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
                                protocol: Some(self.config.sas_protocol()),
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
                        let bearer = self.client.bearer_token().await?;
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
                        credential,
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
    pub async fn write(
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
    pub async fn write_stream(
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

    pub async fn write_redirect(
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
                //     Continuation carries an empty block list; `continue_write` extracts ETag from captured headers.
                //   - size_hint > 256 MiB: stage `Put Block` redirects per 4 MiB chunk, deterministic
                //     IDs via SHA-256(blob_key)[..12] + 4-byte BE seq. `continue_write` reads only the
                //     block *count* back — it regenerates the ids from the key it derives from the
                //     authorized address — and issues `Put Block List` to commit.
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
                    // Both write shapes below — the staged `Put Block` batch and
                    // the single `Put Blob` — sign from this `AuthSource`, so
                    // one scope describes both.
                    credential: redirect_credential(self.client.auth().source()),
                };
                let bearer_for_oauth = match self.client.auth().source() {
                    AuthSource::Oauth2ClientSecret { .. } | AuthSource::Oauth2Federated { .. } => {
                        Some(self.client.bearer_token().await?)
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
                                        protocol: Some(self.config.sas_protocol()),
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
                                return Err(anonymous_write_redirect_unsupported());
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
                                protocol: Some(self.config.sas_protocol()),
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
                        return Err(anonymous_write_redirect_unsupported());
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

    pub async fn continue_write(
        &self,
        target: ResolvedTarget,
        redirects: WriteRedirectBatch,
        results: RedirectResultBatch,
        attested_modified_by: Option<&str>,
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
                // A pinned-version address is refused here for the same reason
                // `write`, `write_stream` and `write_redirect` refuse it: the
                // selector is dropped when the blob key is derived, so the
                // commit would land on the current blob while authorization was
                // decided on the frozen-version URL.
                reject_pinned_for_mutation(
                    &target.resolved_address,
                    "azure continue_write",
                    PINNED_VERSION_KEYS,
                )?;
                // An anonymous connection withholds `supports_write_redirect`,
                // and `continue_write` is gated by that same bit rather than by
                // one of its own — it only runs after a redirect. A withheld
                // bit in front of a slot that still runs is the half-measure
                // the self-gate rule forbids, so the slot refuses here.
                //
                // Before the continuation is decoded, and before the results
                // are trusted: the single-blob arm below commits from
                // `results.results.first()`'s captured headers and reaches no
                // client at all, so without this an anonymous connection could
                // report a successful write having issued nothing. On the
                // broker's client-driven route that batch arrives from the
                // remote caller, which is what makes a fabricated one
                // reachable.
                if matches!(self.client.auth().source(), AuthSource::Anonymous) {
                    return Err(anonymous_write_redirect_unsupported());
                }
                validate_redirect_results(&redirects, &results)?;
                for (i, result) in results.results.iter().enumerate() {
                    if !(200..300).contains(&result.status_code) {
                        let synthetic = synthesize_redirect_response(result);
                        let op = format!("redirect upload #{i}");
                        return Err(map_status_to_error(&synthetic, &op));
                    }
                }
                let mut continuation = WriteContinuation::decode(&redirects.continuation)?;
                // Derive the blob from the authorized request address rather
                // than reading it out of the continuation: on the broker's
                // client-driven route the whole batch is echoed back by the
                // remote caller, while the address is what authorization was
                // decided on. Deriving here also applies the account/container
                // containment check to both branches below.
                let blob_key = self.require_blob_address(&target)?.key;
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
                    // Built from the headers the caller captured and handed
                    // back, so the reserved attribution key inside is the
                    // caller's shape; the host's attribution overlay puts it
                    // right on the way out. Nothing here can fix what the
                    // inline PUT actually stored — that request was the
                    // caller's and the commit is already done.
                    let info = parse_object_info(
                        target.resolved_address.clone(),
                        &headers,
                        self.config.hierarchical_namespace,
                    )?;
                    return Ok(WriteStep::Done(WriteResult { info }));
                }
                // One `blob_key` local feeds both the URL and the canonical path
                // because the latter is what the SharedKey signature is computed
                // over; deriving them from different values breaks signing.
                let blob_url = self.blob_url(&blob_key);
                let canonical_path = self.canonical_path_for_blob(&blob_key);
                if continuation.block_ids.len() != redirects.redirects.len() {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "Azure staged continuation block count does not match the redirect batch",
                    ));
                }
                // The staged ids are `block_id(blob_key, seq)` over a contiguous
                // `0..n`, so they are regenerated from the derived key. Only the
                // count comes from the continuation.
                let block_ids: Vec<String> = (0..continuation.block_ids.len() as u32)
                    .map(|seq| block_id(&blob_key, seq))
                    .collect();
                let xml = build_block_list_xml(&block_ids);
                let mut extra_headers: Vec<(String, String)> = Vec::new();
                // `Put Block List` is where a staged blob's metadata is set — a
                // block blob does not exist until then, so there is nothing to
                // bind it to while the blocks are staged, the way a presigned
                // single PUT binds its `x-ms-meta-*` into a signed URL. The
                // metadata therefore rides in the continuation and comes back
                // through the caller. Where a host attribution layer asserted a
                // writer identity for this request, it replaces the reserved
                // namespace in the copy that travelled.
                ovstorage_plugin::reassert_attribution(
                    attested_modified_by,
                    &mut continuation.user_metadata,
                );
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

    pub async fn delete(
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

    pub async fn list(
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
                // The blob branch takes a BYTE prefix, so it needs the
                // directory form: the host does not rewrite a directory-verb
                // address, and a prefix taken verbatim matches every sibling
                // whose name starts with this directory's.
                //
                // The HNS branch takes ADLS Gen2's `directory=` filter, which is
                // hierarchical rather than a byte prefix — `directory=docs`
                // never returned `docsx` — so it does not need the directory
                // form. It does need ONE spelling: see [`dfs_path_key`].
                let prefix_str = if self.config.hierarchical_namespace {
                    dfs_path_key(&parsed.key).to_string()
                } else {
                    address::directory_key(&parsed.key)
                };
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

    pub async fn list_versions(
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
                let canonical_path = self.canonical_path_for_blob_container();
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

    pub async fn get_latest_version(
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

    pub async fn watch_directory(
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

    pub async fn create_directory(
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

    pub async fn delete_directory(
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

    pub async fn copy(
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
                    return Err(no_overwrite_412_to_already_exists(
                        map_status_to_error(&response, "copy"),
                        dest_no_overwrite,
                        opts.if_source.is_none(),
                        "copy",
                    ));
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
                    return Err(Error::new(
                        ErrorCode::Internal,
                        format!(
                            "Azure copy {status}: {}",
                            copy_failure_detail(&response.headers)
                        ),
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

    pub async fn rename(
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
                        return Err(no_overwrite_412_to_already_exists(
                            map_status_to_error(&response, "rename"),
                            dest_no_overwrite,
                            opts.if_source.is_none(),
                            "rename",
                        ));
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
                match self
                    .delete(
                        src,
                        DeleteOptions {
                            if_match: opts.if_source.clone(),
                        },
                        None,
                    )
                    .await
                {
                    Ok(()) => Ok(()),
                    // The source is already gone — the state a rename
                    // produces, so the operation succeeded.
                    Err(err) if err.code() == ErrorCode::NotFound => Ok(()),
                    // The copy above committed the destination, so the object
                    // now exists at both addresses. Propagating the delete
                    // error unchanged reads as "the rename did not happen".
                    Err(err) => Err(Error::new(
                        ErrorCode::CommitAmbiguous,
                        format!(
                            "azure rename copied to destination but failed to \
                             delete source: {}",
                            err.message()
                        ),
                    )
                    .with_next_action(
                        "The destination is committed. Whether the source was \
                         deleted is unknown — a delete can commit and still \
                         report failure if its response is lost. Inspect both \
                         addresses before deleting either one.",
                    )),
                }
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

    pub async fn check_access(
        &self,
        target: ResolvedTarget,
        ops: AccessOps,
        cancel: Option<CancellationToken>,
    ) -> Result<AccessDecision> {
        // Capability self-gate: azure does not advertise
        // `supports_access_check` — the signed HEAD probe below can only
        // witness readability, not the per-op decision the slot promises —
        // so refuse locally with a typed `Unsupported` before touching the
        // wire. The probe body stays for the day the bit is advertised.
        if !self.capabilities().supports_access_check {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "azure does not support check_access (supports_access_check is not advertised); \
                 probe readability with stat instead",
            ));
        }
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

/// Describe a failed server-side copy without quoting the provider's text.
///
/// `x-ms-copy-status-description` is free-form, not a code field — it renders as
/// `403 AuthenticationFailed "Server failed to authenticate…"`, carrying the same
/// signing material the body redaction exists to keep out. Unlike an OAuth body,
/// which has a documented `error` field to isolate, this header has no grammar to
/// isolate a code from, so it is reported by length alone.
///
/// That would leave an operator with nothing to correlate, so the
/// server-generated `x-ms-request-id` is carried instead — the same handle every
/// other Azure error path attaches, and the one Azure support asks for.
fn copy_failure_detail(headers: &crate::parse::HeaderMap) -> String {
    let detail = match headers.first("x-ms-copy-status-description") {
        Some(description) => format!(
            "no provider error code; {} byte description suppressed",
            description.len()
        ),
        None => "no copy status description".to_string(),
    };
    match crate::error_body::request_id(headers) {
        Some(id) => format!("{detail}; request_id={id}"),
        None => detail,
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
    let canonical_path = backend.canonical_path_for_blob_container();
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

/// The DFS spelling of a path key: no trailing separator.
///
/// **The one place the ADLS Gen2 wire spelling of a path is decided**, because
/// it has to be the same for both spellings of one node. The DFS namespace
/// addresses a directory without a trailing slash — `create_directory` and
/// `delete_directory` both trim before building their paths — while an
/// `azure://` address preserves whichever spelling the caller used and the host
/// canonicalizes directories WITH the slash. So a key reaching this backend may
/// carry the slash or not, and nothing upstream will have removed it.
///
/// Leaving the caller's spelling on the wire is wrong in two different ways
/// depending on the verb, which is why they share this:
///
/// - `getStatus` on `/assets/dir/` asks about a path this backend never
///   creates. The read preflight fails open and goes on to sign a redirect for
///   a directory; `stat` does not fail open at all and turns the 404 into
///   `NotFound` for a directory that exists.
/// - `list` with `directory=docs/` is a different filter value from
///   `directory=docs`. That one is not a sibling leak — the `directory=` filter
///   is hierarchical rather than a byte prefix, so `directory=docs` never
///   returned `docsx` — it is an identity split: the metadata cache keys a
///   listing on the node, so `list docs` and `list docs/` share one row on the
///   stated ground that they return the same page. Two wire values for one
///   cache row means a page fetched under one spelling is served for the other.
///
/// An all-slash key would trim to empty and address the filesystem root rather
/// than the path the caller named, so it is left alone.
fn dfs_path_key(key: &str) -> &str {
    let trimmed = key.trim_end_matches('/');
    if trimmed.is_empty() { key } else { trimmed }
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
    let canonical_path = backend.canonical_path_for_dfs_container();
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
    /// The blob this continuation was minted for. Written to the encoded form
    /// but never read back from it — `decode` drops the caller's value and
    /// `continue_write` derives the key from the authorized request address —
    /// so it survives only to keep a continuation decodable by a peer replica
    /// running an earlier build while an upload is in flight.
    pub blob_key: String,
    /// The staged block ids. Only their *count* is read back: each id is
    /// `block_id(blob_key, seq)` over a contiguous `0..n`, so `continue_write`
    /// regenerates the list from the derived key. An empty list marks the
    /// single `Put Blob` redirect, whose own response is the commit.
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
            // The caller's copy of the blob key is dropped on the floor rather
            // than parsed: `continue_write` derives it from the authorized
            // address, and a field that is never populated cannot be read by
            // mistake later.
            blob_key: String::new(),
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

/// Decode-side mirror. `blob_key` is absent by design: serde ignores the
/// unknown field, so a caller cannot get one through and `decode` has nothing
/// to put in the struct's slot.
#[derive(serde::Deserialize)]
struct WriteContinuationOwned {
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
/// window at the host follower and panic on `Bytes::slice`; surface
/// them as `InvalidArgument` here so the caller can fix the request
/// before any wire round-trip.
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
    use ovstorage_plugin::{SecretBundle, address};

    use crate::config::AzureEndpoint;

    /// The mode-to-credential mapping, which is the security-load-bearing part
    /// of this plugin's redirect declarations and had no direct test.
    ///
    /// Host tests use a synthetic backend and the other Azure redirect tests
    /// assert unrelated fields, so changing `Sas` or either Entra arm to
    /// `Request` would hand a connection-wide credential to clients under the
    /// default policy with every other test still green. The mapping is
    /// exhaustive over `AuthSource`, so a new mode has to choose a value there —
    /// and the match at the end of this test, which also has no wildcard, makes
    /// a new variant fail to compile here until someone extends the table.
    ///
    /// Read the values as claims about the credential, not about Azure: a
    /// Shared Key connection lets the plugin mint a fresh Service SAS scoped to
    /// one blob, an operator-supplied `sas_token` is appended verbatim and can
    /// neither be read nor narrowed, and the Entra modes send the connection's
    /// own bearer, which reaches every blob the principal can.
    #[test]
    fn every_auth_mode_declares_the_credential_its_redirects_actually_carry() {
        use std::path::PathBuf;

        let cases = [
            (
                AuthSource::SharedKey {
                    account_key_bytes: vec![0u8; 32],
                },
                RedirectCredential::Request,
                "a freshly minted Service SAS is scoped to the one blob",
            ),
            (
                AuthSource::Sas {
                    sas_token: "sv=2022-11-02&sig=redacted".into(),
                },
                RedirectCredential::Connection,
                "an operator-supplied SAS cannot be read or narrowed by the plugin",
            ),
            (
                AuthSource::Oauth2ClientSecret {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    client_secret: "s".into(),
                },
                RedirectCredential::Connection,
                "the Entra bearer is account-scoped and outlives the request",
            ),
            (
                AuthSource::Oauth2Federated {
                    tenant_id: "t".into(),
                    client_id: "c".into(),
                    token_file: PathBuf::from("/nonexistent"),
                },
                RedirectCredential::Connection,
                "the federated Entra bearer is the same disclosure",
            ),
            (
                AuthSource::Anonymous,
                RedirectCredential::None,
                "an anonymous URL is unsigned and carries nothing",
            ),
        ];

        for (source, expected, why) in &cases {
            assert_eq!(
                redirect_credential(source),
                *expected,
                "{why} — so this mode must declare {expected:?}"
            );
        }

        // Every variant is named with no wildcard, so adding an `AuthSource`
        // stops this test compiling until it is classified here too. Without
        // this, `cases` is a plain slice and a new mode would simply go
        // untested — the assertions above would all still pass.
        for (source, _, _) in &cases {
            match source {
                AuthSource::SharedKey { .. }
                | AuthSource::Sas { .. }
                | AuthSource::Oauth2ClientSecret { .. }
                | AuthSource::Oauth2Federated { .. }
                | AuthSource::Anonymous => {}
            }
        }
        assert_eq!(
            cases.len(),
            5,
            "every AuthSource variant needs a row here; the match above is what \
             forces a new one to be noticed"
        );

        // Anti-vacuity: the table must actually distinguish modes. If every arm
        // returned the same value the assertions above would all hold while
        // saying nothing about the mapping.
        let declared: std::collections::BTreeSet<_> = cases
            .iter()
            .map(|(source, _, _)| format!("{:?}", redirect_credential(source)))
            .collect();
        assert_eq!(
            declared.len(),
            3,
            "the mapping must separate request-scoped, connection-wide and \
             credential-free modes; got {declared:?}"
        );
    }

    /// A failed copy must not quote `x-ms-copy-status-description` — it carries
    /// the same signing material as an error body — but it must still leave the
    /// operator a correlation handle.
    #[test]
    fn a_failed_copy_suppresses_the_description_but_keeps_the_request_id() {
        let headers = crate::parse::HeaderMap::from_pairs([
            (
                "x-ms-copy-status-description",
                "403 AuthenticationFailed \"Server failed to authenticate the request. sig=7hK4wQ2m\"",
            ),
            ("x-ms-request-id", "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"),
        ]);
        let detail = copy_failure_detail(&headers);
        assert!(detail.contains("byte description suppressed"), "{detail}");
        assert!(
            detail.contains("request_id=1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"),
            "the correlation handle is what replaces the description: {detail}"
        );
        for leaked in ["AuthenticationFailed", "sig=7hK4wQ2m", "Server failed"] {
            assert!(!detail.contains(leaked), "{leaked} survived: {detail}");
        }
    }

    /// A malformed `x-ms-request-id` is dropped rather than reported, so an
    /// intermediary cannot use it to smuggle material past the suppression.
    #[test]
    fn a_copy_failure_drops_a_non_guid_request_id() {
        let headers = crate::parse::HeaderMap::from_pairs([
            ("x-ms-copy-status-description", "403 Forbidden"),
            ("x-ms-request-id", "not-a-guid sig=7hK4wQ2m"),
        ]);
        let detail = copy_failure_detail(&headers);
        assert!(!detail.contains("request_id"), "{detail}");
        assert!(!detail.contains("7hK4wQ2m"), "{detail}");
    }

    /// Azurite-shaped path-style addressing: one host serving both tiers,
    /// plain HTTP, with the account name carried in the URL path instead of
    /// the hostname.
    fn emulator_config() -> AzureConnectionConfig {
        let endpoint =
            AzureEndpoint::parse("http://127.0.0.1:10000/devstoreaccount1", "blob_endpoint")
                .expect("fixture endpoint parses");
        AzureConnectionConfig {
            blob_endpoint: Some(endpoint.clone()),
            dfs_endpoint: Some(endpoint),
            ..fixture_config()
        }
    }

    fn fixture_config() -> AzureConnectionConfig {
        AzureConnectionConfig {
            account: "acct".into(),
            container: "container".into(),
            endpoint_suffix: "core.windows.net".into(),
            blob_endpoint: None,
            dfs_endpoint: None,
            hierarchical_namespace: false,
            change_feed_enabled: false,
            change_feed_segment_lag_seconds: 60,
            change_feed_poll_interval_seconds: 15,
            test_change_feed_endpoint: None,
            test_endpoint_override: None,
            address_root: address::parse("azure://acct/container/").unwrap(),
        }
    }

    /// Serve one canned response per accepted connection, in order, and close
    /// the connection once the queue is empty. Returns the `http://host:port`
    /// the caller points a config or an Entra host at.
    async fn spawn_scripted_listener(responses: Vec<String>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut queue: std::collections::VecDeque<String> = responses.into();
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                let _ = socket.read(&mut buf).await;
                if let Some(response) = queue.pop_front() {
                    let _ = socket.write_all(response.as_bytes()).await;
                }
                let _ = socket.shutdown().await;
            }
        });
        endpoint
    }

    /// A scripted listener that also records each request line, so a test can
    /// assert what actually went on the wire rather than only what came back.
    async fn spawn_recording_listener(
        responses: Vec<String>,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let recorded = seen.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut queue: std::collections::VecDeque<String> = responses.into();
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                let read = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..read]).into_owned();
                if let Some(line) = request.lines().next() {
                    recorded.lock().unwrap().push(line.to_string());
                }
                if let Some(response) = queue.pop_front() {
                    let _ = socket.write_all(response.as_bytes()).await;
                }
                let _ = socket.shutdown().await;
            }
        });
        (endpoint, seen)
    }

    /// One node, one `directory=` filter value.
    ///
    /// The blob branch needs the directory form because its prefix is a byte
    /// prefix. The HNS branch does not — `directory=` is hierarchical, so
    /// `directory=docs` never returned `docsx` — but it still may not put the
    /// caller's spelling on the wire, because the metadata cache keys a listing
    /// on the NODE: `list docs` and `list docs/` share one row on the stated
    /// ground that they return the same page. Two wire values under one cache
    /// row means a page fetched for one spelling is served for the other.
    #[tokio::test]
    async fn hns_list_sends_one_directory_filter_for_both_spellings() {
        let empty_page = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
             content-length: 14\r\n\r\n{\"paths\":[]}\r\n"
            .to_string();
        let (endpoint, seen) = spawn_recording_listener(vec![empty_page.clone(), empty_page]).await;

        let backend = AzureBackend::with_auth(
            AzureConnectionConfig {
                hierarchical_namespace: true,
                test_endpoint_override: Some(
                    AzureEndpoint::parse(&endpoint, "__test_endpoint")
                        .expect("recording listener endpoint parses"),
                ),
                ..fixture_config()
            },
            shared_key_auth(),
        )
        .expect("backend builds");

        for spelling in [
            "azure://acct/container/docs",
            "azure://acct/container/docs/",
        ] {
            let _ = backend
                .list(
                    ResolvedTarget {
                        backend_id: ovstorage_plugin::BackendId("azure:test".into()),
                        resolved_address: address::parse(spelling).unwrap(),
                    },
                    ListOptions::default(),
                    None,
                )
                .await;
        }

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen.len(),
            2,
            "both spellings must reach the wire: {seen:?}"
        );
        assert_eq!(
            seen[0], seen[1],
            "one node must produce one request; the cache merges these two spellings into a \
             single row, so differing wire values serve one page for the other"
        );
        assert!(
            seen[0].contains("directory=docs ") || seen[0].contains("directory=docs&"),
            "the DFS spelling carries no trailing separator: {}",
            seen[0]
        );
    }

    fn shared_key_auth() -> AzureAuth {
        use base64::Engine as _;
        use ovstorage_plugin::{SecretBytes, SecretValue};

        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            SecretValue::Bytes(SecretBytes(
                base64::engine::general_purpose::STANDARD
                    .encode(b"0123456789abcdef")
                    .into_bytes(),
            )),
        );
        AzureAuth::resolve(&bundle).expect("shared key auth resolves")
    }

    fn oauth_auth(entra_host: &str) -> AzureAuth {
        use ovstorage_plugin::{SecretBytes, SecretValue};

        let mut bundle = SecretBundle::default();
        for (key, value) in [
            ("tenant_id", "tenant-uuid"),
            ("client_id", "client-uuid"),
            ("client_secret", "secret-value"),
        ] {
            bundle.fields.insert(
                key.into(),
                SecretValue::Bytes(SecretBytes(value.as_bytes().to_vec())),
            );
        }
        let mut auth = AzureAuth::resolve(&bundle).expect("oauth auth resolves");
        auth.set_entra_host_for_test(entra_host.to_string());
        auth
    }

    /// The case the promotion veto exists for, on the OAuth arm: one request in
    /// the operation is ACCEPTED, and the credential is then refused by the
    /// IdP before the operation finishes.
    ///
    /// An HNS `read` is the only slot that has both halves. It sends the
    /// `getStatus` kind preflight through the client — which the service
    /// answers, crediting this operation an acceptance — and then acquires a second
    /// bearer to sign the redirect it hands back. That second acquisition is a
    /// cache miss whenever the token is inside `REFRESH_LEEWAY` of expiry, so
    /// a secret rotated mid-operation surfaces there and nowhere else. The
    /// `expires_in: 0` below is what puts the token in that window: `AzureAuth`
    /// serves the cache only while `expires_at > now + REFRESH_LEEWAY`
    /// (`auth.rs`, 60s), so the redirect's acquisition goes to the wire and
    /// meets the refusal. Raise it above 60 and the acquisition is served from
    /// cache, the read succeeds, and this test fails on its first assertion —
    /// it cannot pass without exercising the second fetch.
    /// Both
    /// halves must record, because promotion is evidence-based rather than
    /// outcome-based: `AcceptanceWitness` reads them on a failed operation too,
    /// and an acceptance with no refusal would promote a connection whose
    /// credential had just died.
    #[tokio::test]
    async fn an_idp_refusal_after_an_accepted_request_records_both() {
        let token_body = r#"{"access_token":"t","token_type":"Bearer","expires_in":0}"#;
        let refusal_body = r#"{"error":"invalid_client"}"#;
        let entra_host = spawn_scripted_listener(vec![
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{token_body}",
                token_body.len()
            ),
            format!(
                "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{refusal_body}",
                refusal_body.len()
            ),
        ])
        .await;
        // The preflight's verdict is `file`, so the read proceeds to mint the
        // redirect — which is what asks for the second token.
        let storage_endpoint = spawn_scripted_listener(vec![format!(
            "HTTP/1.1 200 OK\r\nx-ms-resource-type: file\r\n\
             x-ms-request-id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed\r\n\
             content-length: 0\r\n\r\n"
        )])
        .await;

        let config = AzureConnectionConfig {
            hierarchical_namespace: true,
            test_endpoint_override: Some(
                AzureEndpoint::parse(&storage_endpoint, "__test_endpoint")
                    .expect("scripted listener endpoint parses"),
            ),
            ..fixture_config()
        };
        let backend =
            AzureBackend::with_auth(config, oauth_auth(&entra_host)).expect("backend builds");

        let evidence = Arc::new(OperationEvidence::default());
        let epoch_before = backend.refusal_epoch();
        let outcome = with_operation_evidence(evidence.clone(), async {
            backend
                .read(
                    ResolvedTarget {
                        backend_id: ovstorage_plugin::BackendId("azure:test".into()),
                        resolved_address: address::parse("azure://acct/container/obj.txt").unwrap(),
                    },
                    ReadOptions::default(),
                    None,
                )
                .await
        })
        .await;

        assert!(outcome.is_err(), "the second grant was refused");
        assert!(
            evidence.saw_acceptance(),
            "the preflight was answered by the service"
        );
        assert_eq!(
            backend.refusal_epoch(),
            epoch_before + 1,
            "the IdP refusal must move the connection's refusal epoch, which is \
             what vetoes the promotion the preflight would otherwise earn"
        );
    }

    /// An AMBIGUOUS refusal on the kind preflight must not veto anybody's
    /// promotion — and an unambiguous one still must.
    ///
    /// The probe signs against the `dfs` host while the read hands back a
    /// `blob` URL, and Azure provisions private endpoints per sub-resource, so
    /// an account reachable on `blob` alone answers the public `dfs` host with
    /// `403 AuthorizationFailure`. That is a statement about which endpoints
    /// are published; counting it advances the connection-wide refusal epoch on
    /// every HNS read and vetoes the concurrent blob-tier work — `write`,
    /// `copy`, `delete` — that the `blob` endpoint is serving, so a read-heavy
    /// connection could never promote. (`stat` and `list` on a hierarchical
    /// namespace reach `dfs` themselves, through ordinary `send`, because they
    /// depend on the answer; on a blob-only topology those still veto, which is
    /// the deployment's endpoint contract rather than something this can fix.)
    ///
    /// `AuthenticationFailed` is the opposite case and the line is drawn
    /// between them deliberately: it means the service verified the signature
    /// and rejected it, which is host-independent. Dropping it would lose the
    /// guarantee the epoch exists for — a credential that dies between a
    /// neighbour's acceptance and its promotion, witnessed by nobody but this
    /// probe.
    ///
    /// `read_on_hns_redirects_when_the_preflight_is_refused` covers a third
    /// shape, `AuthorizationPermissionMismatch` — the one 403 code exempt from
    /// the veto outright — so it exercises neither side of this line.
    #[tokio::test]
    async fn a_refused_kind_preflight_vetoes_only_on_an_unambiguous_refusal() {
        // (error code, or None for one a proxy stripped; must the epoch move?)
        for (code, vetoes) in [
            (Some("AuthorizationFailure"), false),
            // The shape the unpublished-endpoint argument actually rests on.
            (None, false),
            (Some("AuthenticationFailed"), true),
        ] {
            let code_header = match code {
                Some(code) => format!("x-ms-error-code: {code}\r\n"),
                None => String::new(),
            };
            let code = code.unwrap_or("<stripped>");
            let storage_endpoint = spawn_scripted_listener(vec![format!(
                "HTTP/1.1 403 Forbidden\r\n{code_header}\
                 x-ms-request-id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed\r\n\
                 content-length: 0\r\n\r\n"
            )])
            .await;
            let config = AzureConnectionConfig {
                hierarchical_namespace: true,
                test_endpoint_override: Some(
                    AzureEndpoint::parse(&storage_endpoint, "__test_endpoint")
                        .expect("scripted listener endpoint parses"),
                ),
                ..fixture_config()
            };
            let backend = AzureBackend::with_auth(config, shared_key_auth()).expect("backend");
            let epoch_before = backend.refusal_epoch();

            let evidence = Arc::new(OperationEvidence::default());
            let outcome = with_operation_evidence(evidence.clone(), async {
                backend
                    .read(
                        ResolvedTarget {
                            backend_id: ovstorage_plugin::BackendId("azure:test".into()),
                            resolved_address: address::parse("azure://acct/container/obj.txt")
                                .unwrap(),
                        },
                        ReadOptions::default(),
                        None,
                    )
                    .await
            })
            .await;

            // Either way the probe is no verdict on the READ: it still signs.
            assert!(
                matches!(outcome, Ok(ReadResult::Redirect(_))),
                "{code}: a refused preflight must not fail a readable object"
            );
            let expected = epoch_before + u64::from(vetoes);
            assert_eq!(
                backend.refusal_epoch(),
                expected,
                "{code}: epoch should {} have moved",
                if vetoes { "" } else { "NOT" }
            );
            assert!(
                !evidence.saw_acceptance(),
                "{code}: a refusal is not an acceptance"
            );
        }
    }

    /// An IdP refusal reached through the preflight still vetoes, because a
    /// refused grant precedes any storage response and says nothing about which
    /// host was asked. The advisory path narrows which STORAGE refusals count;
    /// it does not touch the token path.
    #[tokio::test]
    async fn an_idp_refusal_on_the_preflight_still_vetoes() {
        let refusal = r#"{"error":"invalid_client"}"#;
        let entra_host = spawn_scripted_listener(vec![format!(
            "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
             content-length: {}\r\n\r\n{refusal}",
            refusal.len()
        )])
        .await;
        // The storage endpoint is never reached: the grant fails first.
        let storage_endpoint = spawn_scripted_listener(vec![]).await;
        let config = AzureConnectionConfig {
            hierarchical_namespace: true,
            test_endpoint_override: Some(
                AzureEndpoint::parse(&storage_endpoint, "__test_endpoint")
                    .expect("scripted listener endpoint parses"),
            ),
            ..fixture_config()
        };
        let backend =
            AzureBackend::with_auth(config, oauth_auth(&entra_host)).expect("backend builds");
        let epoch_before = backend.refusal_epoch();

        let evidence = Arc::new(OperationEvidence::default());
        let _ = with_operation_evidence(evidence.clone(), async {
            backend
                .read(
                    ResolvedTarget {
                        backend_id: ovstorage_plugin::BackendId("azure:test".into()),
                        resolved_address: address::parse("azure://acct/container/obj.txt").unwrap(),
                    },
                    ReadOptions::default(),
                    None,
                )
                .await
        })
        .await;

        assert_eq!(
            backend.refusal_epoch(),
            epoch_before + 1,
            "a refused grant on the advisory path is still a credential verdict"
        );
    }

    /// The refusal no operation's window contains: the background refresh loop meets
    /// it at no operation's time, and it leaves the cached bearer in place, so
    /// the data path goes on being ACCEPTED with the credential already dead.
    /// A connection promoted there latches `Authenticated` and breaks
    /// unrecoverably when the bearer expires.
    #[tokio::test]
    async fn a_background_grant_refusal_latches_and_survives_an_acceptance() {
        let token_body = r#"{"access_token":"t","token_type":"Bearer","expires_in":3600}"#;
        let refusal_body = r#"{"error":"invalid_client"}"#;
        let entra_host = spawn_scripted_listener(vec![
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{token_body}",
                token_body.len()
            ),
            format!(
                "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{refusal_body}",
                refusal_body.len()
            ),
            // The operator repairs the credential; the loop's next retry
            // succeeds and must release the latch.
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{token_body}",
                token_body.len()
            ),
        ])
        .await;
        let storage_endpoint = spawn_scripted_listener(vec![format!(
            "HTTP/1.1 200 OK\r\nx-ms-resource-type: file\r\n\
             x-ms-request-id: 1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed\r\n\
             content-length: 0\r\n\r\n"
        )])
        .await;

        let config = AzureConnectionConfig {
            hierarchical_namespace: true,
            test_endpoint_override: Some(
                AzureEndpoint::parse(&storage_endpoint, "__test_endpoint")
                    .expect("scripted listener endpoint parses"),
            ),
            ..fixture_config()
        };
        let backend =
            AzureBackend::with_auth(config, oauth_auth(&entra_host)).expect("backend builds");

        // The grant that seeds the cache succeeds, so nothing is latched, and
        // the operation's own evidence would otherwise prove acceptance.
        let evidence = Arc::new(OperationEvidence::default());
        let _ = with_operation_evidence(evidence.clone(), async {
            backend
                .read(
                    ResolvedTarget {
                        backend_id: ovstorage_plugin::BackendId("azure:test".into()),
                        resolved_address: address::parse("azure://acct/container/obj.txt").unwrap(),
                    },
                    ReadOptions::default(),
                    None,
                )
                .await
        })
        .await;
        assert!(
            !backend.credential_refused(),
            "a granted token must not latch a refusal"
        );
        assert!(
            evidence.saw_acceptance(),
            "the operation's own request was accepted; only the latch may veto it"
        );

        // The proactive refresh then meets a refused grant. It talks to
        // the IdP rather than to storage, so it advances no refusal epoch
        // however it overlaps an operation in time, and it leaves the cached
        // bearer usable. Only the latch records it.
        //
        // Driven by calling `refresh_now` rather than by waiting on the
        // background loop: the loop's whole body is this call, and its cadence
        // is 90% of a token's TTL.
        let refreshed = backend.client.auth().refresh_now().await;
        assert!(refreshed.is_err(), "the refresh grant was refused");
        assert!(
            evidence.saw_acceptance(),
            "a background refusal belongs to no operation, so it cannot show up \
             in one's acceptance sink — which is exactly why the latch is needed"
        );
        assert!(
            backend.credential_refused(),
            "a background refusal must latch, or the veto never sees it"
        );

        // The latch is a statement about the IdP's current verdict, not a
        // headstone: a later grant supersedes it, and the connection becomes
        // promotable again on its next accepted operation.
        backend
            .client
            .auth()
            .refresh_now()
            .await
            .expect("the repaired credential is granted");
        assert!(
            !backend.credential_refused(),
            "a later successful grant must release the latch"
        );
    }

    /// The latch is for refused grants, not for outages.
    ///
    /// A 5xx or a 429 is nobody answering about the credential, so it neither
    /// latches nor parks. A 400 is the IdP refusing the grant, and it latches
    /// whatever OAuth code rides along with it — including
    /// `temporarily_unavailable`, because no code discriminates permanence and
    /// the safe direction is to withhold. A connection withheld in error
    /// un-parks on its next accepted operation; one promoted in error never
    /// recovers.
    #[tokio::test]
    async fn an_idp_outage_is_not_a_refusal_but_a_refused_grant_latches() {
        let brownout = r#"{"error":"temporarily_unavailable"}"#;
        let entra_host = spawn_scripted_listener(vec![
            "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n".to_string(),
            "HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\n\r\n".to_string(),
            format!(
                "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\n\r\n{brownout}",
                brownout.len()
            ),
        ])
        .await;
        let auth = oauth_auth(&entra_host);

        for outage in ["503", "429"] {
            auth.refresh_now().await.expect_err("the IdP was unwell");
            assert!(
                !auth.credential_refused(),
                "{outage} is nobody answering about the credential"
            );
        }

        auth.refresh_now().await.expect_err("the grant was refused");
        assert!(
            auth.credential_refused(),
            "a refused grant withholds a promotion whatever code it carried"
        );
    }

    /// An anonymous connection withholds exactly one bit, and it is the one
    /// whose slot it refuses locally. Everything else is attempted unsigned and
    /// answered by the service, so withholding more would advertise an
    /// inability azure does not have.
    #[test]
    fn anonymous_withholds_only_the_bit_whose_slot_it_refuses() {
        let credentialed = azure_capabilities(false, true, false);
        let anonymous = azure_capabilities(false, true, true);

        assert!(credentialed.supports_write_redirect);
        assert!(
            !anonymous.supports_write_redirect,
            "write_redirect is refused locally (no SAS to delegate), so the bit \
             must not be advertised"
        );

        // Every other bit agrees. A field added to `Capabilities` that this
        // function sets will be compared here without anyone remembering to.
        let mut expected = credentialed;
        expected.supports_write_redirect = false;
        assert_eq!(
            anonymous, expected,
            "anonymity must change nothing but supports_write_redirect"
        );
    }

    #[test]
    fn capabilities_track_hns_flag() {
        let flat = azure_capabilities(false, false, false);
        let hns = azure_capabilities(true, true, false);
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

        let watched = azure_capabilities(false, true, false);
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
        // The blob key still rides the encoded blob so a peer replica on an
        // earlier build can decode it, ...
        // A mirror of the shape an older build parses, not a substring match.
        // Every field the pre-derivation decoder required.
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct LegacyWriteContinuation {
            blob_key: String,
            block_ids: Vec<String>,
            user_metadata: Option<ovstorage_plugin::UserMetadata>,
            if_match: Option<String>,
            no_overwrite: bool,
            content_type: String,
        }
        let legacy: LegacyWriteContinuation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(legacy.blob_key, "docs/manual.bin");
        assert_eq!(legacy.block_ids.len(), 2);
        assert_eq!(legacy.content_type, "application/octet-stream");
        let decoded = WriteContinuation::decode(&bytes).unwrap();
        // ... but it is never read back, so the round trip is equal in every
        // field except that one.
        assert_eq!(decoded.blob_key, "");
        assert_eq!(
            decoded,
            WriteContinuation {
                blob_key: String::new(),
                ..cont
            }
        );
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
        let batch = AzureBackend::write_redirect(&backend, target, opts, None)
            .await
            .expect("write_redirect emits batch");
        assert_eq!(batch.redirects.len(), 75, "75 × 4 MiB = 300 MiB");
        // The continuation carries only the count; `continue_write` regenerates
        // the ids from the blob key it derives from the authorized address.
        let cont = WriteContinuation::decode(&batch.continuation).unwrap();
        assert_eq!(cont.block_ids.len(), 75);
        // Azure's "same length per blob" requirement is a property of `block_id`
        // itself and is pinned by `block_id_is_deterministic_and_uniform_length`;
        // asserting it again over base64 of a fixed 16 bytes cannot fail.
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
        let result = AzureBackend::read(&backend, target, ReadOptions::default(), None)
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
        let result = AzureBackend::read(&backend, target, ReadOptions::default(), None)
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
        let batch = AzureBackend::write_redirect(&backend, target, opts, None)
            .await
            .unwrap();
        assert_eq!(batch.redirects.len(), 1);
        let cont = WriteContinuation::decode(&batch.continuation).unwrap();
        assert!(
            cont.block_ids.is_empty(),
            "single PutBlob has an empty block list"
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
        shared_key_backend_with(fixture_config())
    }

    fn shared_key_backend_with(config: AzureConnectionConfig) -> AzureBackend {
        let key = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let mut bundle = SecretBundle::default();
        bundle.fields.insert(
            "account_key".into(),
            ovstorage_plugin::SecretValue::Bytes(ovstorage_plugin::SecretBytes(key.into_bytes())),
        );
        let auth = AzureAuth::resolve(&bundle).unwrap();
        AzureBackend::new(config, auth).unwrap()
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
        let result = AzureBackend::read(&backend, target, ReadOptions::default(), None)
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
        let err = AzureBackend::update_metadata(&backend, target, opts, None)
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
        let err = AzureBackend::read(&backend, target, ReadOptions::default(), Some(token))
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
        let err = AzureBackend::list_versions(
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
        let err = AzureBackend::stat(&backend, target, StatOptions::default(), Some(token))
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
        let err = AzureBackend::delete(&backend, target, DeleteOptions::default(), Some(token))
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
        let err = AzureBackend::list(&backend, target, ListOptions::default(), Some(token))
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
        let err = AzureBackend::write_redirect(&backend, target, opts, Some(token))
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

    #[test]
    fn path_style_endpoint_prefixes_request_urls_and_canonical_paths() {
        let backend = shared_key_backend_with(emulator_config());
        assert_eq!(
            backend.blob_url("a/b c.txt"),
            "http://127.0.0.1:10000/devstoreaccount1/container/a/b%20c.txt"
        );
        assert_eq!(
            backend.dfs_url("/a/b c.txt"),
            "http://127.0.0.1:10000/devstoreaccount1/container/a/b%20c.txt"
        );
        // Shared Key canonicalizes as `/{account}` + the request URI path,
        // so the endpoint's path prefix has to appear here too — and the key
        // has to appear in the SAME encoded form the URL above carries.
        assert_eq!(
            backend.canonical_path_for_blob("a/b c.txt"),
            "/devstoreaccount1/container/a/b%20c.txt"
        );
        assert_eq!(
            backend.canonical_path_for_dfs("/a/b c.txt"),
            "/devstoreaccount1/container/a/b%20c.txt"
        );
        assert_eq!(
            backend.canonical_path_for_blob_container(),
            "/devstoreaccount1/container"
        );
        assert_eq!(
            backend.canonical_path_for_dfs_container(),
            "/devstoreaccount1/container"
        );
        assert_eq!(backend.config.sas_protocol(), "https,http");
    }

    /// The rule itself, as an invariant rather than a table of expected
    /// strings: Azure signs URI-derived parts of the canonicalized resource
    /// "encoded exactly as it is in the URI", so the canonical path must be
    /// the path component of the request URL, byte for byte.
    ///
    /// Stated this way it holds for keys and prefixes together and cannot be
    /// satisfied by a case that happens to be encoding-invariant, which is
    /// how signing the raw key survived beside an encoding `blob_url`.
    #[test]
    fn a_canonical_path_is_the_request_urls_path_byte_for_byte() {
        for backend in [
            shared_key_backend(),
            shared_key_backend_with(emulator_config()),
        ] {
            for key in [
                "plain.txt",
                "dir/file.txt",
                // Every shape that makes the two conventions differ.
                "a b.txt",
                "dir/a b/c+d.txt",
                "unicode/fıle-Ω.txt",
                "punct/100%.txt",
                "q/a?b#c.txt",
            ] {
                let blob =
                    ovstorage_plugin::Url::parse(&backend.blob_url(key)).expect("blob url parses");
                assert_eq!(
                    blob.path(),
                    backend.canonical_path_for_blob(key),
                    "blob canonical path must equal the URL path for key {key:?}"
                );
                let dfs = ovstorage_plugin::Url::parse(&backend.dfs_url(&format!("/{key}")))
                    .expect("dfs url parses");
                assert_eq!(
                    dfs.path(),
                    backend.canonical_path_for_dfs(&format!("/{key}")),
                    "dfs canonical path must equal the URL path for key {key:?}"
                );
            }
            // The container-level requests too.
            let container = ovstorage_plugin::Url::parse(&format!(
                "{}/{}",
                backend.config.blob_url_base(),
                backend.config.container
            ))
            .expect("container url parses");
            assert_eq!(
                container.path(),
                backend.canonical_path_for_blob_container()
            );
        }
    }

    #[test]
    fn natural_host_endpoint_keeps_unprefixed_urls_and_canonical_paths() {
        let backend = shared_key_backend();
        assert_eq!(
            backend.blob_url("a/b.txt"),
            "https://acct.blob.core.windows.net/container/a/b.txt"
        );
        assert_eq!(
            backend.dfs_url("/a/b.txt"),
            "https://acct.dfs.core.windows.net/container/a/b.txt"
        );
        assert_eq!(
            backend.canonical_path_for_blob("a/b.txt"),
            "/container/a/b.txt"
        );
        assert_eq!(
            backend.canonical_path_for_dfs("/a/b.txt"),
            "/container/a/b.txt"
        );
        assert_eq!(backend.canonical_path_for_blob_container(), "/container");
        assert_eq!(backend.canonical_path_for_dfs_container(), "/container");
        assert_eq!(backend.config.sas_protocol(), "https");
    }

    /// The loopback `__test_endpoint` hook carries no path, so the canonical
    /// paths it signs must stay byte-identical to the natural-host form —
    /// `tests/precondition.rs` and the conformance scenarios depend on it.
    #[test]
    fn bare_test_endpoint_override_leaves_canonical_paths_unprefixed() {
        let backend = shared_key_backend_with(AzureConnectionConfig {
            test_endpoint_override: Some(
                AzureEndpoint::parse("http://127.0.0.1:9999", "__test_endpoint")
                    .expect("fixture endpoint parses"),
            ),
            ..fixture_config()
        });
        assert_eq!(
            backend.blob_url("a/b.txt"),
            "http://127.0.0.1:9999/container/a/b.txt"
        );
        assert_eq!(
            backend.canonical_path_for_blob("a/b.txt"),
            "/container/a/b.txt"
        );
        assert_eq!(backend.canonical_path_for_blob_container(), "/container");
    }

    #[test]
    fn service_sas_protocol_follows_the_effective_endpoint_scheme() {
        let emulator = shared_key_backend_with(emulator_config())
            .copy_source_url("docs/file.bin", None)
            .unwrap();
        assert!(
            emulator
                .starts_with("http://127.0.0.1:10000/devstoreaccount1/container/docs/file.bin?"),
            "url was {emulator}"
        );
        assert!(
            emulator.contains("spr=https%2Chttp"),
            "an HTTP endpoint must widen spr, got {emulator}"
        );

        let public = shared_key_backend()
            .copy_source_url("docs/file.bin", None)
            .unwrap();
        assert!(
            public.contains("spr=https&"),
            "an HTTPS endpoint stays pinned to https, got {public}"
        );
    }

    /// `copy_source_url` is only one of four SAS-minting sites. A builder
    /// left pinned to `spr=https` would be unusable against an HTTP emulator
    /// while the assertion above still passed, so every site that hands a
    /// signed URL to the caller is checked: the read redirect, the
    /// single-shot write redirect, and the staged write redirect.
    #[tokio::test]
    async fn every_redirect_builder_follows_the_effective_endpoint_scheme() {
        fn target(key: &str) -> ResolvedTarget {
            ResolvedTarget {
                backend_id: ovstorage_plugin::BackendId("azure:test".into()),
                resolved_address: address::parse(&format!("azure://acct/container/{key}")).unwrap(),
            }
        }
        for (label, backend, expected) in [
            (
                "emulator",
                shared_key_backend_with(emulator_config()),
                "spr=https%2Chttp",
            ),
            ("public", shared_key_backend(), "spr=https&"),
        ] {
            let read = backend
                .read(target("docs/file.bin"), ReadOptions::default(), None)
                .await
                .expect("read mints a redirect under Shared Key");
            let ReadResult::Redirect(redirect) = read else {
                panic!("{label}: expected a redirect read result");
            };
            assert!(
                redirect.request.url.contains(expected),
                "{label}: read redirect must carry {expected}, got {}",
                redirect.request.url
            );

            // Single-shot: a size hint under the staging threshold takes the
            // inline branch. (`write_redirect` requires a known size either
            // way; streaming routes through `write_stream`.)
            let single = backend
                .write_redirect(
                    target("docs/file.bin"),
                    WriteOptions {
                        size_hint: Some(1024),
                        ..WriteOptions::default()
                    },
                    None,
                )
                .await
                .expect("single-shot write redirect");
            assert!(
                !single.redirects.is_empty(),
                "{label}: single-shot must emit a redirect"
            );
            for redirect in &single.redirects {
                assert!(
                    redirect.request.url.contains(expected),
                    "{label}: single-shot redirect must carry {expected}, got {}",
                    redirect.request.url
                );
            }

            // Staged: a size hint past the threshold takes the block-list
            // branch, which mints a SAS per block plus the commit.
            let staged = backend
                .write_redirect(
                    target("docs/file.bin"),
                    WriteOptions {
                        size_hint: Some(AZURE_STAGED_THRESHOLD_BYTES + 1),
                        ..WriteOptions::default()
                    },
                    None,
                )
                .await
                .expect("staged write redirect");
            assert!(
                staged.redirects.len() > 1,
                "{label}: a staged write must emit per-block redirects, got {}",
                staged.redirects.len()
            );
            for redirect in &staged.redirects {
                assert!(
                    redirect.request.url.contains(expected),
                    "{label}: staged redirect must carry {expected}, got {}",
                    redirect.request.url
                );
            }
        }
    }
}
