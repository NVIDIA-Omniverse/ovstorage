// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use url::Url;

pub type Result<T> = std::result::Result<T, Error>;

/// Substitute `${NAME}` references in `raw` with values from the process
/// environment. Strict POSIX identifier grammar (`[A-Za-z_][A-Za-z0-9_]*`);
/// anything that isn't a clean `${IDENT}` passes through literally.
/// Returns `NotConfigured` if a referenced env var is unset.
pub fn resolve_env_refs(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut cursor = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$'
            && bytes[i + 1] == b'{'
            && let Some((name, end)) = scan_env_ref(bytes, i + 2)
        {
            out.push_str(&raw[cursor..i]);
            let value = std::env::var(name).map_err(|_| {
                Error::new(
                    ErrorCode::NotConfigured,
                    format!("env var '{name}' is not set"),
                )
            })?;
            out.push_str(&value);
            cursor = end;
            i = end;
            continue;
        }
        i += 1;
    }
    out.push_str(&raw[cursor..]);
    Ok(out)
}

fn scan_env_ref(bytes: &[u8], start: usize) -> Option<(&str, usize)> {
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while let Some(&b) = bytes.get(end)
        && (b.is_ascii_alphanumeric() || b == b'_')
    {
        end += 1;
    }
    if bytes.get(end)? != &b'}' {
        return None;
    }
    Some((std::str::from_utf8(&bytes[start..end]).ok()?, end + 1))
}

/// Async chunk-stream of an object's bytes — the streaming variant of
/// `ReadResult`. Peak memory is bounded by chunk size × channel
/// capacity, never by object size.
pub type ReadStream = std::pin::Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes>> + Send>>;
pub type ChangeStream = Box<dyn Iterator<Item = Result<ChangeEvent>> + Send>;
pub type ConnectionChangeStream = Box<dyn Iterator<Item = Result<ConnectionChange>> + Send>;
pub type AddressRootSnapshotStream = Box<dyn Iterator<Item = Result<Vec<AddressRoot>>> + Send>;
pub type AuthEventStream = Box<dyn Iterator<Item = Result<AuthEvent>> + Send>;
pub type SystemMetadata = HashMap<String, String>;
pub type UserMetadata = HashMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChecksumAlgorithm(String);

impl ChecksumAlgorithm {
    pub fn new(algorithm: impl AsRef<str>) -> Result<Self> {
        let raw = algorithm.as_ref().trim();
        if raw.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "checksum algorithm must not be empty",
            ));
        }
        let lower = raw.to_ascii_lowercase();
        let normalized = match lower.as_str() {
            "sha-256" | "sha_256" | "sha256" => "sha256".to_string(),
            "crc32-c" | "crc32_c" | "crc32c" => "crc32c".to_string(),
            "crc64-nvme" | "crc64_nvme" | "crc64nvme" => "crc64nvme".to_string(),
            "md-5" | "md_5" | "md5" => "md5".to_string(),
            _ => lower,
        };
        if !normalized.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        }) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "checksum algorithm must be an ASCII token",
            ));
        }
        Ok(Self(normalized))
    }

    pub fn sha256() -> Self {
        Self("sha256".into())
    }

    pub fn crc32c() -> Self {
        Self("crc32c".into())
    }

    pub fn md5() -> Self {
        Self("md5".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChecksumSet {
    entries: Vec<(ChecksumAlgorithm, Vec<u8>)>,
}

impl ChecksumSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, algorithm: &ChecksumAlgorithm) -> Option<&[u8]> {
        self.entries
            .iter()
            .find_map(|(a, v)| (a == algorithm).then_some(v.as_slice()))
    }

    pub fn insert(&mut self, algorithm: ChecksumAlgorithm, bytes: Vec<u8>) {
        if let Some(entry) = self.entries.iter_mut().find(|(a, _)| a == &algorithm) {
            entry.1 = bytes;
        } else {
            self.entries.push((algorithm, bytes));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ChecksumAlgorithm, &[u8])> {
        self.entries.iter().map(|(a, v)| (a, v.as_slice()))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EffectivePermissions(u32);

impl EffectivePermissions {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const DELETE: Self = Self(1 << 2);
    pub const UPDATE_METADATA: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn all() -> Self {
        Self(Self::READ.0 | Self::WRITE.0 | Self::DELETE.0 | Self::UPDATE_METADATA.0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::all().0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for EffectivePermissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for EffectivePermissions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for EffectivePermissions {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for EffectivePermissions {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BackendId(pub String);

/// File / directory discriminator for `ObjectInfo`.
///
/// All three directory variants surface real distinctions:
/// - `Directory` vs `DirectoryInferred`: persistence. A `DirectoryInferred`
///   exists only as a common key prefix among descendants; deleting the last
///   child makes the directory vanish from listings.
/// - `Directory` vs `DirectoryMarker`: post-delete state. Deleting a
///   `Directory` removes the directory inode; deleting a `DirectoryMarker`
///   removes the zero-byte marker but the prefix may remain visible as
///   `DirectoryInferred` if children exist.
/// - `DirectoryMarker` vs `DirectoryInferred`: existence of a backing
///   storage object (relevant for cost / sync / lifecycle reasoning).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ObjectKind {
    #[default]
    File = 0,
    /// Native directory inode (POSIX file plugins, Nucleus, Azure ADLS Gen2 HNS).
    Directory = 1,
    /// Zero-byte marker object on a flat-namespace backend (e.g. S3/GCS
    /// `dir/`-keyed objects).
    DirectoryMarker = 2,
    /// Directory inferred from descendant common prefixes by the
    /// dispatcher's marker-folding pass. No backing storage object.
    DirectoryInferred = 3,
}

impl ObjectKind {
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File)
    }

    pub fn is_directory(&self) -> bool {
        !self.is_file()
    }

    /// Canonical snake-case wire string. Every agent-facing surface
    /// (REST, MCP, future bindings) renders [`ObjectKind`] through
    /// this helper so one enum stringifies to exactly one shape on
    /// the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::DirectoryMarker => "directory_marker",
            Self::DirectoryInferred => "directory_inferred",
        }
    }
}

/// Destination-side precondition for `write` / `copy` / `rename`.
///
/// `Overwrite` clobbers an existing object unconditionally and is the
/// `Default`. `Fail` refuses to overwrite — operation errors with
/// `ErrorCode::AlreadyExists` if the destination is present. `MatchEtag`
/// permits the overwrite only when the destination's current etag matches
/// the supplied token; mismatches surface `ErrorCode::ObjectModified`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum IfDestExists {
    #[default]
    Overwrite,
    Fail,
    MatchEtag(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectInfo {
    pub address: Url,
    pub kind: ObjectKind,
    /// Opaque token that changes when the object's content changes. The
    /// only field used for precondition checks (see `if_match` on
    /// `ReadOptions` / `DeleteOptions` / `UpdateMetadataOptions` /
    /// `CopyOptions::if_source` / `RenameOptions::if_source`, and
    /// `IfDestExists::MatchEtag`). Plugins may encode whatever they
    /// need into this string (e.g., the file plugin synthesizes
    /// `"size:N,mtime:T"`).
    pub etag: Option<String>,
    /// Backend-specific version identifier when the backend supports
    /// versioning (e.g., S3 versionId, GCS generation). Descriptive
    /// only — not used as a precondition.
    pub version: Option<String>,
    /// Object size in bytes. `None` for directories of any kind.
    pub size: Option<u64>,
    /// Last-modified time. `None` for `ObjectKind::DirectoryInferred`
    /// (no backing object to carry an mtime); populated for files and
    /// for `Directory` / `DirectoryMarker` entries that carry one.
    pub mtime: Option<SystemTime>,
    pub checksums: ChecksumSet,
    pub effective_permissions: Option<EffectivePermissions>,
    pub system_metadata: Option<SystemMetadata>,
    pub user_metadata: Option<UserMetadata>,
    /// Identity of the last writer.
    ///
    /// **Population is opt-in via [`StatOptions::full_metadata`] /
    /// [`ListOptions::full_metadata`]** — populating this field can
    /// cost extra round-trips on some backends (S3 needs a separate
    /// `GetObjectAcl`, POSIX needs `getpwuid_r`, Windows needs
    /// `GetSecurityInfo` + `LookupAccountSidW`). Default-stat callers
    /// who only want etag/size pay nothing.
    ///
    /// **Source by mode:**
    /// - *Direct-library mode*: whatever the plugin natively reports
    ///   (POSIX uid resolved to username, plugin-nucleus user, etc.).
    ///   `None` for plugins without a native source (S3, Azure, GCS).
    /// - *Brokered mode*: the broker's attribution layer overrides
    ///   from a reserved key in `user_metadata` it stamps on every
    ///   write — so this reflects the principal the broker
    ///   authenticated, not the underlying backend identity. See
    ///   `ovstorage_authz::AttributionLayer`.
    ///
    /// **Caveats:** POSIX `st_uid` and Windows DACL owner are *owner*,
    /// not strictly *modifier* — neither kernel records who performed
    /// the last `write()`. On most single-user systems they coincide.
    pub modified_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub backend_id: BackendId,
    pub resolved_address: Url,
}

/// Source of bytes the host hands the plugin for `write`. `Stream`
/// MUST be consumed chunk-by-chunk — draining it into a buffer
/// re-introduces a memory-DoS risk on the public REST gateway.
/// Plugins without chunked-upload support should return
/// `ErrorCode::Unsupported` for the `Stream` variant rather than
/// collecting it.
#[derive(Debug)]
pub enum Body {
    Bytes(Vec<u8>),
    LocalFile(PathBuf),
    Stream(BodyStream),
}

/// Chunk-by-chunk stream of bytes for `Body::Stream`. Plugins
/// consume it with [`BodyStream::next_chunk`].
pub struct BodyStream {
    inner: Box<dyn Iterator<Item = Result<Vec<u8>>> + Send>,
}

impl BodyStream {
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<I>(iter: I) -> Self
    where
        I: Iterator<Item = Result<Vec<u8>>> + Send + 'static,
    {
        Self {
            inner: Box::new(iter),
        }
    }

    pub fn next_chunk(&mut self) -> Option<Result<Vec<u8>>> {
        self.inner.next()
    }
}

impl std::fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BodyStream{{..}}")
    }
}

impl Iterator for BodyStream {
    type Item = Result<Vec<u8>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteResult {
    pub info: ObjectInfo,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct StatOptions {
    pub full_metadata: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReadOptions {
    /// Etag the caller expects the object to have. When `Some`, a
    /// mismatch surfaces `ErrorCode::ObjectModified`.
    pub if_match: Option<String>,
    pub range: Option<ByteRange>,
    /// Optional facade-side cap on buffered read size.
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WriteOptions {
    /// Destination-side precondition. See [`IfDestExists`].
    pub if_dest: IfDestExists,
    pub size_hint: Option<u64>,
    pub user_metadata: Option<UserMetadata>,
    /// Optional human-readable annotation attached to this operation.
    /// Backends that version objects (e.g. Nucleus checkpoints) treat
    /// this as the version commit message; backends without per-operation
    /// annotation drop it silently.
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DeleteOptions {
    /// Etag the caller expects the target object to have. When `Some`,
    /// a mismatch surfaces `ErrorCode::ObjectModified`.
    pub if_match: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ListOptions {
    pub recursive: bool,
    pub max_results: Option<u32>,
    pub page_token: Option<String>,
    pub full_metadata: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ListVersionsOptions {
    pub max_results: Option<u32>,
    pub page_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CreateDirectoryOptions {}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DeleteDirectoryOptions;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CopyOptions {
    /// Source-side etag precondition: when `Some`, the operation
    /// requires the source object's current etag to match. Mismatches
    /// surface `ErrorCode::ObjectModified`.
    pub if_source: Option<String>,
    /// Destination-side precondition. See [`IfDestExists`].
    pub if_dest: IfDestExists,
    /// Per-operation annotation; see [`WriteOptions::message`].
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RenameOptions {
    /// Source-side etag precondition: when `Some`, the operation
    /// requires the source object's current etag to match. Mismatches
    /// surface `ErrorCode::ObjectModified`.
    pub if_source: Option<String>,
    /// Destination-side precondition. See [`IfDestExists`].
    pub if_dest: IfDestExists,
    /// Per-operation annotation; see [`WriteOptions::message`].
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UpdateMetadataOptions {
    /// Etag the caller expects the target object to have. When `Some`,
    /// a mismatch surfaces `ErrorCode::ObjectModified`.
    pub if_match: Option<String>,
    pub allow_rewrite_emulation: bool,
    pub user_metadata_set: HashMap<String, String>,
    pub user_metadata_remove: Vec<String>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end_inclusive: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AccessOps {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub update_metadata: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessDecision {
    pub allowed: bool,
    pub denied_ops: AccessOps,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectScope {
    pub physical_url_prefix: String,
    pub operations: AccessOps,
    pub expires_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRedirect {
    pub request: HttpRequest,
    pub response_parsing: ResponseParsing,
    pub expires_at: SystemTime,
    pub scope: RedirectScope,
    pub audit_id: String,
    pub policy_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRedirect {
    pub request: HttpRequest,
    pub body_source: RedirectBodySource,
    pub result_capture: ResultCapture,
    pub expires_at: SystemTime,
    pub scope: RedirectScope,
    pub audit_id: String,
    pub policy_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseParsing {
    pub etag_header: Option<String>,
    pub version_header: Option<String>,
    pub size_header: Option<String>,
    pub mtime_header: Option<String>,
    pub mtime_format: MtimeFormat,
    pub system_metadata_headers: Vec<String>,
    /// Header carrying the wire-integrity checksum to verify against
    /// the streamed body. The host surfaces
    /// `ErrorCode::ContentChecksumMismatch` at end-of-stream on
    /// mismatch. Missing header or unsupported algorithm degrade to
    /// pass-through (never reject a read for a verifier capability
    /// gap).
    pub content_checksum_header: Option<String>,
    /// Algorithm for `content_checksum_header`. Only `sha256` is
    /// verified host-side in 0.1; other tokens degrade to pass-through.
    pub content_checksum_algorithm: Option<ChecksumAlgorithm>,
    /// Additional algorithm→header bindings folded into
    /// `ObjectInfo.checksums` without verification — propagation only.
    pub checksum_headers: HashMap<ChecksumAlgorithm, String>,
}

impl Default for ResponseParsing {
    fn default() -> Self {
        Self {
            etag_header: Some("etag".into()),
            version_header: None,
            size_header: Some("content-length".into()),
            mtime_header: Some("last-modified".into()),
            mtime_format: MtimeFormat::Rfc1123,
            system_metadata_headers: Vec::new(),
            content_checksum_header: None,
            content_checksum_algorithm: None,
            checksum_headers: HashMap::new(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum MtimeFormat {
    #[default]
    Rfc1123,
    Iso8601,
    UnixSeconds,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultCapture {
    pub headers: Vec<String>,
    pub body_max_bytes: u32,
}

impl Default for ResultCapture {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            body_max_bytes: 4096,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RedirectBodySource {
    Empty,
    UserBytes { offset: u64, len: u64 },
    Inline(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteRedirectBatch {
    pub continuation: Vec<u8>,
    pub redirects: Vec<WriteRedirect>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectResult {
    pub status_code: u16,
    pub captured_headers: Vec<(String, String)>,
    pub captured_body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectResultBatch {
    pub results: Vec<RedirectResult>,
}

pub fn validate_redirect_results(
    batch: &WriteRedirectBatch,
    results: &RedirectResultBatch,
) -> Result<()> {
    if batch.redirects.len() != results.results.len() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "redirect result batch cardinality does not match the preceding redirect batch",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListPage {
    pub items: Vec<ObjectInfo>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionPage {
    pub items: Vec<ObjectInfo>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeEvent {
    Object {
        address: Url,
        kind: ChangeKind,
        /// Etag of the object after the change. The opaque
        /// precondition token; round-trips through `if_match` /
        /// `if_source` / `IfDestExists::MatchEtag`.
        etag: Option<String>,
        /// Backend-specific version identifier (e.g. S3 versionId,
        /// GCS generation, Azure blob version-id) when the backend
        /// surfaces it on the notification. `None` on deletes and
        /// on backends that don't version.
        version: Option<String>,
        /// Object size in bytes after the change, when the backend
        /// surfaces it on the notification.
        size: Option<u64>,
        /// Last-modified time of the object after the change, when
        /// the backend surfaces it on the notification.
        mtime: Option<SystemTime>,
        at: SystemTime,
        cursor: WatchDirectoryCursor,
    },
    Lapsed {
        since: Option<SystemTime>,
        cursor: WatchDirectoryCursor,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
    MetadataChanged,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WatchDirectoryCursor(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchDirectoryOptions {
    pub recursive: bool,
    pub include_metadata_changes: bool,
    pub since: Option<WatchDirectoryCursor>,
    pub poll_interval: Duration,
}

impl Default for WatchDirectoryOptions {
    fn default() -> Self {
        Self {
            recursive: false,
            include_metadata_changes: true,
            since: None,
            poll_interval: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AliasId(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressRoot {
    pub address: Url,
    pub display_name: Option<String>,
    pub backend_kind: String,
    pub connection_id: Option<ConnectionId>,
    pub capabilities: Capabilities,
    pub source: RouteSource,
    pub visibility: AddressVisibility,
    pub user_metadata: UserMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSource {
    Static {
        layer: ConfigLayer,
    },
    ConnectionContributed {
        connection_id: ConnectionId,
    },
    BrokerDelivered {
        broker_principal: String,
        connection_id: ConnectionId,
    },
    Alias {
        to: Url,
        alias_source: AliasSource,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasSource {
    Static { layer: ConfigLayer },
    Runtime { persisted: bool },
    BrokerDelivered { broker_principal: String },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum AddressVisibility {
    #[default]
    Visible,
    Hidden,
    Suppressed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConfigLayer {
    Programmatic,
    Env,
    Project,
    User,
    Machine,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageBackendKindDescriptor {
    pub kind: String,
    pub display_name: String,
    pub description: Option<String>,
    pub config_schema: Vec<ConfigField>,
    pub credential_schema: Vec<CredentialField>,
    /// Named credential entry-points (e.g. "default_chain", "static_key", "sso").
    /// Each method references a subset of `credential_schema` by key. Empty
    /// means the host walks every credential field individually.
    pub credential_methods: Vec<CredentialMethod>,
    pub icon: Option<Vec<u8>>,
    pub supports_runtime_add: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigField {
    pub key: String,
    pub display_name: String,
    pub kind: ConfigFieldKind,
    pub required: bool,
    pub default: Option<ConfigValue>,
    pub help: Option<String>,
    pub example: Option<String>,
    pub group: Option<String>,
    /// Hidden from interactive flows that only surface common fields. The
    /// field still parses out of TOML and is honored at runtime.
    pub advanced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialMethod {
    pub key: String,
    pub display_name: String,
    /// Keys referencing entries in the descriptor's `credential_schema`.
    /// Empty = no fields to gather (e.g. SSO that drives `authenticate_connection`).
    pub fields: Vec<String>,
    pub help: Option<String>,
    /// Hidden from method pickers that only surface common methods.
    pub advanced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigFieldKind {
    Url,
    Text,
    Integer,
    Bool,
    Enum { source: EnumSource },
    Path,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnumSource {
    Static(Vec<String>),
    Discovered,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialField {
    pub key: String,
    pub display_name: String,
    /// Default value applied across every `CredentialMethod` that
    /// references this field. Literal text, or a `${NAME}` reference
    /// that `resolve_env_refs` substitutes from the process environment
    /// at TOML-load time.
    pub default: Option<String>,
    pub help: Option<String>,
    pub advanced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigValue {
    String(String),
    Int(i64),
    Bool(bool),
    /// Reserialized TOML payload — a nested table or array of tables
    /// captured opaquely by the host. Named `Toml` (not `Table`)
    /// because the payload covers both tables and arrays of tables.
    Toml(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub backend_kind: String,
    /// Flat key/value config. Top-level TOML scalars carry their typed
    /// variant; nested tables and arrays arrive as `ConfigValue::Toml`.
    pub config: HashMap<String, ConfigValue>,
    pub credentials: SecretBundle,
    pub persist: bool,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SecretBundle {
    pub fields: HashMap<String, SecretValue>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(pub Vec<u8>);

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl SecretBytes {
    /// Consume the wrapper and return the inner bytes. Caller owns the
    /// buffer and is responsible for clearing it; the Drop zeroize is
    /// bypassed on this path. For non-owning use, pass `&SecretBytes`.
    pub fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    /// Borrow the inner bytes without consuming the wrapper.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretValue {
    Bytes(SecretBytes),
    OAuthToken {
        token: SecretBytes,
        refresh: Option<SecretBytes>,
        expires_at: Option<SystemTime>,
    },
    File(SecretBytes),
    MtlsCertPair {
        cert_pem: SecretBytes,
        key_pem: SecretBytes,
    },
    SystemIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub id: ConnectionId,
    pub backend_kind: String,
    pub display_name: String,
    pub source: ConnectionSource,
    pub capabilities: Capabilities,
    pub current_addresses: Vec<Url>,
    pub auth_state: ConnectionAuthState,
    pub last_probed: Option<SystemTime>,
    pub user_metadata: UserMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionSource {
    Static { layer: ConfigLayer },
    Runtime { persisted: bool },
    BrokerDelivered { broker_principal: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionChange {
    Added(Connection),
    Removed { id: ConnectionId },
    Updated(Connection),
    Snapshot(Vec<Connection>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasRequest {
    pub from: Url,
    pub to: Url,
    pub visibility: AddressVisibility,
    pub persist: bool,
    pub display_name: Option<String>,
    pub user_metadata: UserMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alias {
    pub id: AliasId,
    pub from: Url,
    pub to: Url,
    pub visibility: AddressVisibility,
    pub source: AliasSource,
    pub state: AliasState,
    pub display_name: Option<String>,
    pub user_metadata: UserMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasState {
    Live,
    Dangling,
    ChainTooLong { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressVisibilityOverride {
    pub address: Url,
    pub visibility: AddressVisibility,
    pub persisted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionAuthState {
    Authenticated {
        last_authenticated_at: SystemTime,
        expires_at: Option<SystemTime>,
    },
    AwaitingAuth {
        reason: AuthReason,
        last_attempt: Option<AuthAttempt>,
    },
    AuthFailed {
        error: Error,
        attempts: u32,
    },
    Anonymous,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthReason {
    NeverAuthenticated,
    RefreshTokenExpired,
    RefreshTokenRevoked,
    CredentialsRotated,
    ManuallyRequested,
    /// Cached routes are installed but the live silent bring-up failed for
    /// a non-auth reason (network, broker down). The dispatcher retries the
    /// silent path on each new request; `reauth` force-retries.
    BackendUnreachable,
    Unknown {
        details: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthAttempt {
    pub at: SystemTime,
    pub error: Option<Error>,
}

/// Host-declared limit on what kind of interactive authentication the
/// plugin may attempt. Threaded through `Factory::authenticate` and
/// across the broker as the `x-ov-iauth` gRPC metadata header.
/// Default `Browser`: desktop / local-terminal callers can both
/// launch a browser and bind a 127.0.0.1 redirect listener.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum InteractiveAuthCapability {
    /// No interactive auth at all (CI, sandboxed services, render
    /// workers). Blocks the interactive entry point only:
    /// `Factory::authenticate` returns `Err(AuthRequired)` without
    /// emitting any `AuthEvent`s, and the broker short-circuits its
    /// IDP-driven flows.
    ///
    /// Does NOT block non-interactive credential resolution —
    /// credential-cache hits, the host's provider chain, and
    /// proactive cache pushes via `Library::set_credential` continue
    /// to work. The external-token-injection pattern pairs `None`
    /// with a callback-style credential provider that delegates to a
    /// control-plane portal so the credential is fulfilled
    /// out-of-band.
    None,
    /// Host can show URLs / codes for cross-device action but cannot
    /// bind a 127.0.0.1 redirect listener. OAuth plugins use the
    /// device-authorisation flow (RFC 8628).
    Headless,
    /// Host can launch a browser AND bind a redirect listener.
    /// Plugins prefer PKCE.
    #[default]
    Browser,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthEvent {
    OpenBrowser {
        url: String,
        expires_at: SystemTime,
    },
    DeviceCode {
        user_code: String,
        verification_url: String,
        expires_at: SystemTime,
        interval: Duration,
    },
    Progress {
        message: String,
    },
    Succeeded {
        connection: Box<Connection>,
        /// Credentials produced by the auth flow (e.g. OAuth bearer +
        /// refresh). `None` means the flow installs tokens itself or
        /// uses static creds; `Some` triggers the host to call
        /// `update_credentials` on the connection's factory.
        credentials: Option<SecretBundle>,
    },
    Failed {
        error: Error,
    },
    Cancelled,
}

pub struct LocalDelegate {
    pub path: PathBuf,
    pub info: ObjectInfo,
    /// Opaque RAII guard pinning the file against cache eviction for
    /// as long as ANY clone of the delegate is held. `Arc` (not
    /// `Box`) so `Clone` preserves the lease. Host-only state;
    /// plugins set this to `None`. Type-erased to keep the SPI free
    /// of an `ovstorage-cache` dependency.
    pub guard: Option<std::sync::Arc<dyn Send + Sync>>,
}

impl Clone for LocalDelegate {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            info: self.info.clone(),
            guard: self.guard.clone(),
        }
    }
}

impl std::fmt::Debug for LocalDelegate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalDelegate")
            .field("path", &self.path)
            .field("info", &self.info)
            .field("guard", &self.guard.as_ref().map(|_| "<opaque>"))
            .finish()
    }
}

impl PartialEq for LocalDelegate {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path && self.info == other.info
    }
}

impl Eq for LocalDelegate {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub supports_if_match_write: bool,
    pub supports_no_overwrite_write: bool,
    pub supports_native_metadata_patch: bool,
    pub supports_metadata_rewrite_emulation: bool,
    pub writes_are_atomic: bool,
    pub supports_server_side_copy: bool,
    pub supports_server_side_rename: bool,
    pub supports_atomic_rename: bool,
    pub has_real_directories: bool,
    /// Gates buffered single-shot
    /// [`shim::Backend::write`](crate::shim::Backend::write). Plugins
    /// that only implement streaming or redirect writes leave this
    /// `false`.
    pub supports_write: bool,
    /// Gates [`shim::Backend::write_stream`](crate::shim::Backend::write_stream).
    pub supports_write_stream: bool,
    /// Gates [`shim::Backend::write_redirect`](crate::shim::Backend::write_redirect)
    /// (and by implication `continue_write`, which only runs after a redirect).
    pub supports_write_redirect: bool,
    /// Gates [`shim::Backend::delete`](crate::shim::Backend::delete).
    pub supports_delete: bool,
    pub supports_list: bool,
    pub wants_list_backed_stat: bool,
    pub supports_recursive_list: bool,
    pub populates_subdirectory_metadata: bool,
    /// Gates [`shim::Backend::create_directory`](crate::shim::Backend::create_directory).
    pub supports_create_directory: bool,
    /// Gates [`shim::Backend::delete_directory`](crate::shim::Backend::delete_directory).
    pub supports_delete_directory: bool,
    pub supports_version_listing: bool,
    pub version_list_order: Option<VersionListOrder>,
    pub populates_effective_permissions_on_stat: bool,
    pub supports_access_check: bool,
    pub supports_watch_directory: bool,
    pub watch_directory_kinds: ChangeKindSet,
    pub watch_directory_resumable: bool,
    pub watch_directory_max_lag: Option<Duration>,
    /// Smallest size at which `write_redirect` is worth calling. When
    /// the write's `size_hint` is `Some(n)` and `n < threshold`, the
    /// host skips `write_redirect` and dispatches directly to
    /// `write` / `write_stream`. `None` means "always try
    /// write_redirect first".
    pub redirect_size_threshold: Option<u64>,
}

impl Capabilities {
    pub fn empty() -> Self {
        Self {
            supports_if_match_write: false,
            supports_no_overwrite_write: false,
            supports_native_metadata_patch: false,
            supports_metadata_rewrite_emulation: false,
            writes_are_atomic: false,
            supports_server_side_copy: false,
            supports_server_side_rename: false,
            supports_atomic_rename: false,
            has_real_directories: false,
            supports_write: false,
            supports_write_stream: false,
            supports_write_redirect: false,
            supports_delete: false,
            supports_list: false,
            wants_list_backed_stat: false,
            supports_recursive_list: false,
            populates_subdirectory_metadata: false,
            supports_create_directory: false,
            supports_delete_directory: false,
            supports_version_listing: false,
            version_list_order: None,
            populates_effective_permissions_on_stat: false,
            supports_access_check: false,
            supports_watch_directory: false,
            watch_directory_kinds: ChangeKindSet::empty(),
            watch_directory_resumable: false,
            watch_directory_max_lag: None,
            redirect_size_threshold: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionListOrder {
    Newest,
    Oldest,
    Unordered,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ChangeKindSet {
    pub created: bool,
    pub modified: bool,
    pub deleted: bool,
    pub metadata_changed: bool,
}

impl ChangeKindSet {
    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    code: ErrorCode,
    message: String,
    context: Option<Box<ErrorContext>>,
    next_action: Option<String>,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let raw = message.into();
        let message = match crate::redact::redact_message(&raw) {
            std::borrow::Cow::Borrowed(_) => raw,
            std::borrow::Cow::Owned(scrubbed) => scrubbed,
        };
        Self {
            code,
            message,
            context: None,
            next_action: None,
        }
    }

    /// Attach a typed [`ErrorContext`] to an existing error.
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(Box::new(context));
        self
    }

    /// Attach a human/agent-readable recovery hint.
    pub fn with_next_action(mut self, next_action: impl Into<String>) -> Self {
        let raw = next_action.into();
        let scrubbed = match crate::redact::redact_message(&raw) {
            std::borrow::Cow::Borrowed(_) => raw,
            std::borrow::Cow::Owned(s) => s,
        };
        self.next_action = Some(scrubbed);
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return the structured payload, if any.
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_deref()
    }

    pub fn next_action(&self) -> Option<&str> {
        self.next_action.as_deref()
    }
}

/// Typed payload attached to an [`Error`] for variants with stable
/// structured fields. Codes without a canonical payload leave
/// `context` as `None`; future unknown variants are treated as `None`
/// for forward-compatibility.
///
/// - `ObjectModified` → [`ErrorContext::Identity`].
/// - `AuthRequired` / `AuthCancelled` / `AuthExpired` →
///   [`ErrorContext::Auth`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorContext {
    /// Companion to `ErrorCode::ObjectModified`. `new_etag` is the
    /// etag the backend reported, distinct from the caller's
    /// `if_match`.
    Identity { new_etag: Option<String> },
    /// Companion to `ErrorCode::AuthRequired` / `AuthCancelled` /
    /// `AuthExpired`. `expired_at` is set only on `AuthExpired`.
    Auth {
        connection_id: ConnectionId,
        reason: Option<String>,
        expired_at: Option<SystemTime>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    PreconditionFailed,
    Conflict,
    DirectoryNotEmpty,
    Unsupported,
    InvalidArgument,
    IncompatibleType,
    Locked,
    Cancelled,
    DeadlineExceeded,
    Transient,
    ResourceExhausted,
    IntegrityFailure,
    Internal,
    BrokerUnavailable,
    BrokerRequired,
    RedirectExpired,
    PolicyEpochStale,
    AuthorizationLeaseExpired,
    CacheCorrupt,
    StagingExpired,
    CommitAmbiguous,
    CacheLockContention,
    StateRootUnavailable,
    NetworkFilesystemRefused,
    ObjectModified,
    NoRoute,
    RouteConflict,
    NotConfigured,
    AliasChainTooLong,
    CredentialExpired,
    CredentialUnavailable,
    AuthRequired,
    AuthCancelled,
    AuthExpired,
    ContentMismatch,
    ContentChecksumMismatch,
    /// Host refused to load the plugin for policy reasons (e.g. a
    /// `test_only` cdylib in a production host). Distinct from
    /// `InvalidArgument` so operators can tell a policy refusal apart
    /// from a malformed binary.
    PluginRejected,
}

impl ErrorCode {
    /// Stable string name of the variant for agent-facing JSON errors.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotFound => "NotFound",
            ErrorCode::AlreadyExists => "AlreadyExists",
            ErrorCode::PermissionDenied => "PermissionDenied",
            ErrorCode::PreconditionFailed => "PreconditionFailed",
            ErrorCode::Conflict => "Conflict",
            ErrorCode::DirectoryNotEmpty => "DirectoryNotEmpty",
            ErrorCode::Unsupported => "Unsupported",
            ErrorCode::InvalidArgument => "InvalidArgument",
            ErrorCode::IncompatibleType => "IncompatibleType",
            ErrorCode::Locked => "Locked",
            ErrorCode::Cancelled => "Cancelled",
            ErrorCode::DeadlineExceeded => "DeadlineExceeded",
            ErrorCode::Transient => "Transient",
            ErrorCode::ResourceExhausted => "ResourceExhausted",
            ErrorCode::IntegrityFailure => "IntegrityFailure",
            ErrorCode::Internal => "Internal",
            ErrorCode::BrokerUnavailable => "BrokerUnavailable",
            ErrorCode::BrokerRequired => "BrokerRequired",
            ErrorCode::RedirectExpired => "RedirectExpired",
            ErrorCode::PolicyEpochStale => "PolicyEpochStale",
            ErrorCode::AuthorizationLeaseExpired => "AuthorizationLeaseExpired",
            ErrorCode::CacheCorrupt => "CacheCorrupt",
            ErrorCode::StagingExpired => "StagingExpired",
            ErrorCode::CommitAmbiguous => "CommitAmbiguous",
            ErrorCode::CacheLockContention => "CacheLockContention",
            ErrorCode::StateRootUnavailable => "StateRootUnavailable",
            ErrorCode::NetworkFilesystemRefused => "NetworkFilesystemRefused",
            ErrorCode::ObjectModified => "ObjectModified",
            ErrorCode::NoRoute => "NoRoute",
            ErrorCode::RouteConflict => "RouteConflict",
            ErrorCode::NotConfigured => "NotConfigured",
            ErrorCode::AliasChainTooLong => "AliasChainTooLong",
            ErrorCode::CredentialExpired => "CredentialExpired",
            ErrorCode::CredentialUnavailable => "CredentialUnavailable",
            ErrorCode::AuthRequired => "AuthRequired",
            ErrorCode::AuthCancelled => "AuthCancelled",
            ErrorCode::AuthExpired => "AuthExpired",
            ErrorCode::ContentMismatch => "ContentMismatch",
            ErrorCode::ContentChecksumMismatch => "ContentChecksumMismatch",
            ErrorCode::PluginRejected => "PluginRejected",
        }
    }

    /// Whether a blind retry of the same operation might succeed.
    ///
    /// Retryable: Transient, BrokerUnavailable, ResourceExhausted,
    /// DeadlineExceeded, CacheLockContention, AuthorizationLeaseExpired.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            ErrorCode::Transient
                | ErrorCode::BrokerUnavailable
                | ErrorCode::ResourceExhausted
                | ErrorCode::DeadlineExceeded
                | ErrorCode::CacheLockContention
                | ErrorCode::AuthorizationLeaseExpired
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_env_refs_passes_literal_text() {
        assert_eq!(resolve_env_refs("AKIAEXAMPLE").unwrap(), "AKIAEXAMPLE");
        assert_eq!(resolve_env_refs("").unwrap(), "");
        assert_eq!(resolve_env_refs("just text").unwrap(), "just text");
    }

    #[test]
    fn resolve_env_refs_substitutes_env_var() {
        let name = "OVSTORAGE_TPL_TEST_BASIC";
        // SAFETY: single-threaded test using a unique var name.
        unsafe { std::env::set_var(name, "secret-value") };
        assert_eq!(
            resolve_env_refs(&format!("${{{name}}}")).unwrap(),
            "secret-value",
        );
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn resolve_env_refs_composes_around_env_var() {
        let name = "OVSTORAGE_TPL_TEST_COMPOSE";
        unsafe { std::env::set_var(name, "MIDDLE") };
        assert_eq!(
            resolve_env_refs(&format!("prefix-${{{name}}}-suffix")).unwrap(),
            "prefix-MIDDLE-suffix",
        );
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn resolve_env_refs_missing_env_is_not_configured() {
        let err = resolve_env_refs("${OVSTORAGE_TPL_TEST_DEFINITELY_UNSET_xyz}").unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotConfigured);
    }

    #[test]
    fn resolve_env_refs_only_matches_strict_posix_identifier() {
        for raw in [
            "${var:-default}",
            "${1var}",
            "${env:NAME}",
            "$VAR",
            "pass$word",
            "${unterminated",
        ] {
            assert_eq!(resolve_env_refs(raw).unwrap(), raw);
        }
    }

    #[test]
    fn checksum_algorithm_normalizes_common_names() {
        assert_eq!(
            ChecksumAlgorithm::new("SHA-256").unwrap().as_str(),
            "sha256"
        );
        assert_eq!(
            ChecksumAlgorithm::new("crc32_c").unwrap().as_str(),
            "crc32c"
        );
        assert_eq!(
            ChecksumAlgorithm::new("CRC64-NVME").unwrap().as_str(),
            "crc64nvme"
        );
        assert_eq!(
            ChecksumAlgorithm::new("x-provider-hash").unwrap().as_str(),
            "x-provider-hash"
        );
    }

    #[test]
    fn checksum_algorithm_rejects_invalid_tokens() {
        assert_eq!(
            ChecksumAlgorithm::new("").unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            ChecksumAlgorithm::new("sha 256").unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn error_new_redacts_signed_url_in_message() {
        let err = Error::new(
            ErrorCode::Transient,
            "broker fetch failed from \
             https://bucket.s3.amazonaws.com/key?X-Amz-Signature=secret&versionId=7",
        );
        let msg = err.message();
        assert!(msg.contains("X-Amz-Signature=REDACTED"), "{msg}");
        assert!(msg.contains("versionId=7"), "{msg}");
        assert!(!msg.contains("secret"), "{msg}");
    }

    #[test]
    fn error_new_redacts_bearer_in_message() {
        let err = Error::new(
            ErrorCode::PermissionDenied,
            "request rejected: Bearer eyJhbGciOiJIUzI1NiJ9.bogus.token",
        );
        let msg = err.message();
        assert!(msg.contains("Bearer REDACTED"), "{msg}");
        assert!(!msg.contains("eyJhbGciOiJIUzI1NiJ9"), "{msg}");
    }

    #[test]
    fn error_new_passes_through_plain_messages_unchanged() {
        let err = Error::new(ErrorCode::NotFound, "object does not exist");
        assert_eq!(err.message(), "object does not exist");
    }

    #[test]
    fn error_display_shows_redacted_message() {
        let err = Error::new(
            ErrorCode::Transient,
            "fetch failed from https://example.com/x?X-Amz-Signature=abc",
        );
        let display = format!("{err}");
        assert!(display.contains("Transient:"), "{display}");
        assert!(display.contains("X-Amz-Signature=REDACTED"), "{display}");
        assert!(!display.contains("X-Amz-Signature=abc"), "{display}");
    }

    #[test]
    fn error_with_next_action_sets_field() {
        let err = Error::new(ErrorCode::NotFound, "object missing")
            .with_next_action("call library.stat first to confirm address");
        assert_eq!(
            err.next_action(),
            Some("call library.stat first to confirm address")
        );
    }

    #[test]
    fn error_without_next_action_returns_none() {
        let err = Error::new(ErrorCode::NotFound, "object missing");
        assert!(err.next_action().is_none());
    }

    #[test]
    fn error_next_action_is_redacted() {
        let err = Error::new(ErrorCode::Transient, "transient").with_next_action(
            "retry using \
             https://example.com/p?X-Amz-Signature=secret",
        );
        let na = err.next_action().expect("next_action present");
        assert!(na.contains("X-Amz-Signature=REDACTED"), "{na}");
        assert!(!na.contains("secret"), "{na}");
    }

    #[test]
    fn error_code_retryable_classification() {
        use ErrorCode::*;
        assert!(Transient.retryable());
        assert!(BrokerUnavailable.retryable());
        assert!(ResourceExhausted.retryable());
        assert!(DeadlineExceeded.retryable());
        assert!(CacheLockContention.retryable());
        assert!(AuthorizationLeaseExpired.retryable());

        assert!(!NotFound.retryable());
        assert!(!PermissionDenied.retryable());
        assert!(!InvalidArgument.retryable());
        assert!(!Cancelled.retryable());
        assert!(!ObjectModified.retryable());
        assert!(!CredentialUnavailable.retryable());
        assert!(!AuthRequired.retryable());
    }

    #[test]
    fn error_code_as_str_returns_variant_name() {
        use ErrorCode::*;
        assert_eq!(NotFound.as_str(), "NotFound");
        assert_eq!(PermissionDenied.as_str(), "PermissionDenied");
        assert_eq!(CredentialUnavailable.as_str(), "CredentialUnavailable");
        assert_eq!(BrokerUnavailable.as_str(), "BrokerUnavailable");
    }
}
