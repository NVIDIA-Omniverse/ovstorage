// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use url::Url;

use crate::{Error, ErrorCode};

pub type Result<T> = std::result::Result<T, Error>;

/// Substitute `${NAME}` references in `raw` with values from the process
/// environment. Strict POSIX identifier grammar (`[A-Za-z_][A-Za-z0-9_]*`);
/// anything that isn't a clean `${IDENT}` passes through literally.
/// Returns `NotConfigured` if a referenced env var is unset.
///
/// # Errors
///
/// - [`ErrorCode::NotConfigured`] — a referenced environment variable is not
///   set.
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

/// True when `raw` contains at least one reference [`resolve_env_refs`] would
/// substitute — a well-formed `${IDENT}` under the same strict grammar.
///
/// Callers that treat a value as a reference (and so hand it on unexamined)
/// must decide with this rather than by searching for `${`: a `$` and a brace
/// are not a reference, and a value that merely contains them is literal text
/// that `resolve_env_refs` passes through untouched. Sharing `scan_env_ref`
/// with the resolver is the point — a second, looser spelling of "looks like a
/// reference" is how a secret earns reference treatment it does not deserve.
pub fn contains_env_ref(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' && scan_env_ref(bytes, i + 2).is_some() {
            return true;
        }
        i += 1;
    }
    false
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

pub type SystemMetadata = HashMap<String, String>;
pub type UserMetadata = HashMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChecksumAlgorithm(String);

impl ChecksumAlgorithm {
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidArgument`] — the algorithm name is empty or
    ///   contains non-ASCII bytes other than hyphen, underscore, or period.
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
    // The `cbindgen:ignore` annotations hide these associated constants
    // from ovstorage-plugin's cbindgen pass: cbindgen matches them (by
    // type name) against the named-field ffi shadow struct, cannot map
    // the tuple-struct constructor onto its fields, and emits zero-valued
    // empty `{ }` initializers. The C header re-emits them by hand via
    // `after_includes` in ovstorage-plugin/cbindgen.toml — keep the bit
    // values there in lock-step with these definitions.
    /// cbindgen:ignore
    pub const READ: Self = Self(1 << 0);
    /// cbindgen:ignore
    pub const WRITE: Self = Self(1 << 1);
    /// cbindgen:ignore
    pub const DELETE: Self = Self(1 << 2);
    /// cbindgen:ignore
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
    /// Whether a write's `WriteOptions::user_metadata` can survive this
    /// backend kind — the plugin's own answer to a question no host can
    /// answer on its behalf.
    ///
    /// This is a property of the *kind*, declared at discovery time, and it is
    /// deliberately coarse. Hosts read it to decide graph shape before any root
    /// is resolved, so it cannot depend on a root — which means **a kind whose
    /// roots disagree has to pick one answer for all of them**, and which
    /// answer is the plugin author's decision rather than a reading of the
    /// write path:
    ///
    /// - `true` permits a host to stamp every branch of the kind. What a root
    ///   that cannot store the key does with that stamp is the plugin's own
    ///   behaviour: conformance asks it to refuse the write rather than drop
    ///   the key silently, and `omniverse-storage-service` declares `true`
    ///   while deviating for the reserved keys, logging and discarding where
    ///   every key that failed is one of the host's own.
    /// - `false` withholds the host's stamp from every branch of the kind. It
    ///   does not say the kind rejects `user_metadata`: `opendal` declares
    ///   `false` while keeping a caller's own keys on the drivers that
    ///   advertise them, because accepting the stamp would fail writes outright
    ///   on a driver without metadata support and cost the presigned write path
    ///   to every connection whose driver presigns at all.
    ///
    /// Both answers are taken in tree, and the reason for each is recorded on
    /// the declaration it belongs to. A host that composed an attribution
    /// wrapper over a branch declaring `false` would plant a reserved key on a
    /// kind that asked not to carry one — on `nucleus`, which rejects a
    /// non-empty `user_metadata` with `Unsupported`, that fails the write.
    pub supports_user_metadata: bool,
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

/// A change to a producer's connection set.
///
/// ## Ordering
///
/// This is a **requirement on producers**, not a property a consumer may assume
/// of an arbitrary stream.
///
/// A producer emitting for connections it owns MUST, per connection, emit in an
/// order consistent with its own committed state: `Added` before any `Updated`,
/// and `Removed` last. The way to hold that is to emit inside the same critical
/// section that commits the membership change — see [`crate::ordered`], which
/// makes an unguarded emission fail to compile. Emitting after the guard drops
/// lets a concurrent committer interleave, and a consumer keyed by connection
/// then retains an entry that the producer's state no longer has.
///
/// Across producers there is **no** order, and none can be manufactured: a
/// stream that merges two independent producers (an alias's own rules and its
/// inner layer's connections) has no shared guard to serialize against. Consume
/// a merged stream as a keyed upsert/delete, never as a sequence.
///
/// A forwarder — an FFI bridge, an authz pass-through, a language binding —
/// relays its inner producer's order and introduces none of its own. It owns no
/// state, so it has no commit to be ordered against.
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
    /// silent path on each new request; `reauth` force-retries on a backend
    /// that has an interactive flow. A backend that has none answers
    /// [`Layer::authenticate_connection`](crate::Layer::authenticate_connection)
    /// with [`ErrorCode::Unsupported`], so `reauth` is not a route back for it
    /// at all — the flow it would drive does not exist.
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
    /// workers). Blocks the interactive entry point only: a backend whose
    /// flow needs a browser or a device code typically returns
    /// `Err(AuthRequired)` without emitting any `AuthEvent`s, and the
    /// broker short-circuits its IDP-driven flows. A backend whose
    /// credential shape needs no user present may still run — nucleus
    /// drives its API-token and username/password handshakes under this
    /// capability.
    ///
    /// A backend with no interactive flow answers `Err(Unsupported)`
    /// under this capability exactly as it does under the others — it
    /// has nothing to block — so a caller distinguishing "no flow
    /// offered" from "a flow this host cannot drive" must read the code,
    /// not the capability it passed in.
    ///
    /// Does NOT block non-interactive credential resolution —
    /// credential-cache hits, the host's provider chain, and proactive
    /// credential updates continue to work. The external-token-injection
    /// pattern pairs `None`
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub supports_if_match_write: bool,
    pub supports_no_overwrite_write: bool,
    pub supports_native_metadata_patch: bool,
    pub supports_metadata_rewrite_emulation: bool,
    pub writes_are_atomic: bool,
    /// Availability: a `copy` naming this root can be attempted. Says
    /// nothing about mechanism or cost — an emulating layer above the
    /// backend sets this even when the backend copies nothing itself.
    /// Callers asking "will `copy` work?" want this bit;
    /// [`Capabilities::supports_server_side_copy`] answers the different
    /// question of whether the bytes stay on the server.
    ///
    /// `copy` names two roots, and this bit answers only for the root it
    /// is attached to. A read-only root can be a valid *source* while
    /// being useless as a *destination*: check the destination root's
    /// [`Capabilities::supports_write`] /
    /// [`Capabilities::supports_write_stream`] before offering it as one.
    pub supports_copy: bool,
    /// Availability: a `rename` naming this root can be attempted. See
    /// [`Capabilities::supports_copy`] for the availability/mechanism
    /// split.
    pub supports_rename: bool,
    /// Mechanism: the backend performs `copy` without routing the object
    /// through the host — no egress, and native metadata and checksums
    /// are preserved. Never set by an emulating layer.
    pub supports_server_side_copy: bool,
    /// Mechanism: the backend performs `rename` without routing the
    /// object through the host. Never set by an emulating layer.
    pub supports_server_side_rename: bool,
    /// Guarantee about the **native** path: the backend's own `rename` is
    /// atomic — the destination appears and the source disappears
    /// indivisibly.
    ///
    /// It does not promise that every `rename` a caller issues will be
    /// atomic. Whether a request runs natively or is emulated above the
    /// backend is a property of the request, not of the root: a backend
    /// can rename most objects server-side and decline the one carrying a
    /// precondition it cannot express, and an emulated rename is a copy
    /// followed by a delete, which is never atomic. That is why this bit
    /// is not lowered when an emulating layer is composed — doing so
    /// would deny a guarantee that holds for nearly every request. A
    /// caller that must know watches for the emulation event the
    /// `copy_rename_fallback` layer emits.
    pub supports_atomic_rename: bool,
    pub has_real_directories: bool,
    /// Gates buffered single-shot `write`. Layers that only implement
    /// streaming or redirect writes leave this `false`.
    pub supports_write: bool,
    /// Gates `write_stream`.
    pub supports_write_stream: bool,
    /// Gates `write_redirect` (and by implication `continue_write`, which only
    /// runs after a redirect).
    pub supports_write_redirect: bool,
    /// Gates `delete`.
    pub supports_delete: bool,
    pub supports_list: bool,
    pub wants_list_backed_stat: bool,
    pub supports_recursive_list: bool,
    pub populates_subdirectory_metadata: bool,
    /// Gates `create_directory`.
    pub supports_create_directory: bool,
    /// Gates `delete_directory`.
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
            supports_copy: false,
            supports_rename: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `RedirectScope` literal in the workspace names `credential`.
    ///
    /// This is the claim the design actually rests on — a backend that fails to
    /// declare what its redirect's credential authorizes must fail to compile —
    /// and it is checked here at the **mint sites**, which is where the claim
    /// lives, rather than by reading this type's own declaration.
    ///
    /// The earlier version of this test scraped the text around `RedirectScope`
    /// for a `Default` impl and a `#[non_exhaustive]` attribute. That was the
    /// wrong target twice over. It depended on incidental formatting, so when an
    /// assumption stopped holding it passed rather than failed — three
    /// self-referencing bugs were found in it. And the presence of a `Default`
    /// impl is only a *proxy*: what actually breaks the guarantee is a mint site
    /// that omits the field, which is what this looks for directly. A
    /// functional-update literal — `RedirectScope { .., ..base }` — is the way
    /// that happens, and it is caught the same way every other omission is, by
    /// the absence of the field rather than by the presence of the `..`.
    ///
    /// **What this does not do.** It is a text scan, not the compiler, so it
    /// cannot prove the property the way a compile-fail fixture would; the
    /// honest description is that it catches the shape a lapse takes, at every
    /// site, and fails loudly if it stops finding those sites. `trybuild` is the
    /// tool that would prove it and is not a dependency of this workspace.
    #[test]
    fn every_redirect_scope_literal_declares_a_credential() {
        // Two levels up from this crate is the workspace root.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root resolves");

        fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                // `target` holds build output including vendored sources. Every
                // hidden directory is skipped too, which matters more than it
                // looks: this repo keeps git worktrees under
                // `<root>/.claude/worktrees/<branch>/`, so a walk that descends
                // into them scans a dozen other branches — including ones
                // predating this field — and reports hundreds of offenders that
                // have nothing to do with the tree under test. It would be green
                // in CI, which checks out clean, and red for every human. A test
                // that reddens for reasons unrelated to your change is a test
                // that gets deleted.
                if name == "target" || name.to_string_lossy().starts_with('.') {
                    continue;
                }
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }

        let mut files = Vec::new();
        rust_files(&root, &mut files);

        let type_name = concat!("Redirect", "Scope");
        let mut sites = 0usize;
        let mut offenders = Vec::new();
        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for (index, line) in text.lines().enumerate() {
                // A literal of THIS type: not the declaration, and not the
                // generated protobuf twin `pb::RedirectScope`, which is a
                // different type with its own wire defaults and whose tests
                // legitimately build it with `..Default::default()`.
                let trimmed = line.trim_start();
                // Comment lines are never scanned. Prose about this rule names
                // the pattern the rule looks for, so a scan that reads comments
                // matches its own explanation. That happened four times while
                // this test and its predecessor were written — including in the
                // comment that used to sit here explaining the next clause — so
                // the exclusion is unconditional rather than case-by-case.
                if trimmed.starts_with("//") || trimmed.starts_with("*") {
                    continue;
                }
                // Tolerant of `RedirectScope{` as well as `RedirectScope {`:
                // rustfmt writes the spaced form, but `#[rustfmt::skip]` and
                // macro-expanded code need not, and an omitting literal in the
                // unspaced spelling is exactly what must not slip through.
                let opens_a_literal = line.split(type_name).skip(1).any(|rest| {
                    rest.trim_start().starts_with('{') && rest.len() - rest.trim_start().len() < 2
                });
                if !opens_a_literal
                    || trimmed.starts_with("pub struct")
                    || trimmed.starts_with("struct ")
                    // A trait impl's empty body is shaped like a literal.
                    || trimmed.starts_with("impl")
                    || trimmed.starts_with("unsafe impl")
                    // The generated protobuf twin and the `#[repr(C)]` FFI twin
                    // are different types with their own defaults and their own
                    // tests; only the layer type is under this rule.
                    || line.contains(concat!("pb::", "RedirectScope"))
                    || line.contains(concat!("ffi::", "RedirectScope"))
                {
                    continue;
                }
                sites += 1;
                // The literal's body: from here to the line whose indentation
                // returns to the opening line's, which closes it. Twenty lines
                // is far more than any in-tree literal needs.
                let indent = line.len() - line.trim_start().len();
                let body: String = text
                    .lines()
                    .skip(index)
                    .take(20)
                    .take_while(|l| {
                        l.trim().is_empty()
                            || (l.len() - l.trim_start().len()) > indent
                            || l.contains(type_name)
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let where_ = format!(
                    "{}:{}",
                    file.strip_prefix(&root).unwrap_or(file).display(),
                    index + 1
                );
                // Searched over the whole body rather than line by line, and
                // both spellings count: `credential: value` and the field
                // shorthand `credential,`. A line-anchored check reports a
                // correct one-line literal as an offender, because its only body
                // line begins with the binding rather than the field — and
                // rustfmt collapses a literal onto one line as soon as it fits.
                // The capital in `RedirectCredential::` means the type name
                // cannot satisfy either match.
                let declares = body.contains("credential:") || body.contains("credential,");
                if !declares {
                    offenders.push(where_);
                }
            }
        }

        // Non-vacuity: a scan that located nothing must fail rather than pass.
        // The floor is well under the count at the time of writing, so ordinary
        // churn does not trip it while a broken walk or a renamed type does.
        assert!(
            sites >= 30,
            "found only {sites} `RedirectScope` literals in {} files — the scan is \
             not finding the mint sites, so it proves nothing",
            files.len()
        );
        assert!(
            offenders.is_empty(),
            "these `RedirectScope` literals do not declare a credential, so the \
             redirect they mint classifies as whatever the unset value says:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// Every header an in-tree backend attaches to a redirect it declares
    /// request-scoped must be inert, or the host demotes that declaration and
    /// withholds a redirect that was perfectly safe to hand over.
    ///
    /// The inert allowlist fails toward availability by design: a name nobody
    /// listed costs a proxied transfer rather than a disclosure. That is the
    /// right polarity, and it is also the reason an omission is invisible —
    /// nothing breaks loudly, an operator simply loses the redirect path for
    /// some writes. So the cost is enumerated here rather than trusted.
    ///
    /// This caught a real one: S3 and Azure both attach `x-amz-meta-*` /
    /// `x-ms-meta-*` when a write carries user metadata, and matching those by
    /// exact name is impossible because the suffix is the caller's own key. A
    /// metadata-bearing write to either backend was being demoted to
    /// connection-scoped and withheld under the default policy — on S3, and on
    /// the one Azure mode whose redirects are genuinely object-scoped.
    ///
    /// Each entry cites where the backend attaches it. The list is
    /// hand-maintained against the code, so it is a floor and not a proof: a
    /// backend adding a header without adding it here still gets through. It
    /// is the cheapest thing that turns a silent availability loss into a red
    /// test.
    #[test]
    fn every_header_an_in_tree_backend_puts_on_a_delegable_redirect_is_inert() {
        // (header, which backend attaches it, on what)
        let attached: &[(&str, &str)] = &[
            // S3 presigned GET/PUT: the SDK echoes what it signed, and the
            // follower must re-send it verbatim or the signature fails.
            ("host", "s3 presign, every redirect"),
            ("content-length", "s3 presigned PUT"),
            ("if-match", "s3 presign, IfDestExists::MatchEtag"),
            ("if-none-match", "s3 presign, IfDestExists::Fail"),
            ("x-amz-meta-author", "s3 presigned PUT with user_metadata"),
            ("X-Amz-Meta-Author", "the same header, as the SDK cases it"),
            ("x-amz-request-payer", "s3, requester-pays buckets"),
            ("x-amz-checksum-sha256", "s3, checksum-bearing writes"),
            // The checksum family is matched by prefix, because its suffix is an
            // algorithm name the SDK adds to over time. `crc64nvme` is the live
            // example: this tree already maps it for response parsing while it
            // was absent from the exact-name list, which is the same silent
            // demotion the metadata prefixes were added for.
            (
                "x-amz-checksum-crc64nvme",
                "s3, already mapped for response parsing",
            ),
            ("x-amz-sdk-checksum-algorithm", "s3, the algorithm selector"),
            // Azure Shared Key: the mode whose redirects are object-scoped, so
            // the mode that must stay delegable.
            ("x-ms-version", "azure, every redirect"),
            ("x-ms-blob-type", "azure block-blob writes"),
            ("x-ms-blob-content-type", "azure, content-typed writes"),
            (
                "x-ms-meta-author",
                "azure write redirect with user_metadata",
            ),
            ("Range", "azure read redirect with a range"),
            ("If-Match", "azure read redirect with a precondition"),
            // GCS resumable upload session.
            ("content-type", "gcs resumable session redirect"),
            // `x-goog-content-length-range` is on the inert allowlist but not
            // in this list: no in-tree backend puts it on a redirect. GCS sends
            // the size as `X-Upload-Content-Length` on the session-*creation*
            // request, which the client never sees. Every entry here is cited
            // against a real attach site, so an uncited one does not belong.
        ];

        for (header, attached_by) in attached {
            assert!(
                header_is_inert(header),
                "`{header}` ({attached_by}) is not inert, so a redirect carrying it is \
                 demoted to connection-scoped and withheld under the default policy — \
                 an availability regression for a backend that declared honestly"
            );
        }

        // The polarity check. If everything were inert the assertions above
        // would pass while proving nothing, so name headers that must NOT be:
        // the ambient credentials the old gate matched, and the two Nucleus
        // spellings it missed, which are the reason this list is an allowlist.
        for header in [
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Authorization-Token",
            "Connection-Signature",
            "x-amz-security-token",
        ] {
            assert!(
                !header_is_inert(header),
                "`{header}` is treated as inert, so a redirect carrying it would be \
                 handed over on the strength of its declaration alone"
            );
        }
    }

    /// The zero discriminant is fail-safe, not neutral.
    ///
    /// It is what a peer that omits the protobuf field decodes to, and what a
    /// backend copying a header set it did not mint honestly declares. A host
    /// that read "did not say" as "nothing to worry about" would disclose
    /// exactly the credentials nobody was able to classify.
    #[test]
    fn an_unspecified_credential_is_not_delegable() {
        assert!(!redirect_is_delegable(RedirectCredential::Unspecified, &[]));
        assert!(!redirect_is_delegable(RedirectCredential::Connection, &[]));
        assert!(redirect_is_delegable(RedirectCredential::None, &[]));
        assert!(redirect_is_delegable(RedirectCredential::Request, &[]));
    }

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

    /// `contains_env_ref` must agree with `resolve_env_refs` about what a
    /// reference is, so no caller can decide "this is a reference" about a
    /// value the resolver treats as literal text. The equality is structural —
    /// both walk the same loop over the same `scan_env_ref` — and the table
    /// below pins both directions against regression rather than establishing
    /// the property by enumeration.
    #[test]
    fn contains_env_ref_agrees_with_the_resolver() {
        let name = "OVSTORAGE_TPL_TEST_AGREES";
        unsafe { std::env::set_var(name, "V") };

        let references = [
            format!("${{{name}}}"),
            format!("prefix-${{{name}}}-suffix"),
            format!("${{{name}}}/${{{name}}}"),
        ];
        for raw in &references {
            assert!(contains_env_ref(raw), "{raw:?} is a reference");
            assert_ne!(
                resolve_env_refs(raw).unwrap(),
                *raw,
                "{raw:?} must actually resolve"
            );
        }

        let literals = [
            "${var:-default}",
            "${1var}",
            "${env:NAME}",
            "$VAR",
            "pass$word",
            "${unterminated",
            "secret${unterminated",
            "p${assw0rd",
            "${}",
            "${",
            "",
        ];
        for raw in literals {
            assert!(!contains_env_ref(raw), "{raw:?} is literal text");
            assert_eq!(
                resolve_env_refs(raw).unwrap(),
                raw,
                "{raw:?} must pass through the resolver unchanged"
            );
        }

        unsafe { std::env::remove_var(name) };
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
}

pub type ConnectionChangeStream = Box<dyn Iterator<Item = Result<ConnectionChange>> + Send>;
pub type AddressRootSnapshotStream = Box<dyn Iterator<Item = Result<Vec<AddressRoot>>> + Send>;
pub type AuthEventStream = Box<dyn Iterator<Item = Result<AuthEvent>> + Send>;
pub type RootInfoUpdateStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<RootInfoChange>> + Send>>;
pub type ConnectionUpdateStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<ConnectionChange>> + Send>>;

pub type BackendAddressRootsStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<AddressRootsChange>> + Send>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressRootsChange {
    Snapshot(Vec<AddressRoot>),
    Added(Vec<AddressRoot>),
    Removed(Vec<AddressRoot>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerConnectionRequest {
    pub target: String,
    pub connection: ConnectionRequest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionKey {
    pub target: String,
    pub id: ConnectionId,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct AttributePatch {
    pub display_name: Option<String>,
    pub access_mode: Option<String>,
    pub visible: Option<bool>,
    pub user_metadata: HashMap<String, Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticateRequest {
    pub key: ConnectionKey,
    pub capability: InteractiveAuthCapability,
    pub auto_open_browser: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateConnectionAttributesRequest {
    pub key: ConnectionKey,
    pub patch: AttributePatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateConnectionCredentialsRequest {
    pub key: ConnectionKey,
    pub credentials: SecretBundle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootInfo {
    pub root: Url,
    pub display_name: Option<String>,
    pub layer_kind: String,
    pub connection_id: Option<ConnectionId>,
    /// The instance name of the Layer that owns connections for this root — the
    /// [`ConnectionKey::target`] a connection op (`add`/`remove`/`authenticate`/
    /// `update_credentials`) must address to reach `connection_id`. Distinct
    /// from `layer_kind` (the descriptor kind): connection ops route by the
    /// graph-unique instance name, so a backend Layer named differently from
    /// its kind (`s3_prod` of kind `s3`) is still reachable. Reported alongside
    /// `connection_id` so a caller resolves both from ONE `root_info_for`
    /// (no second lookup that a live route change could race), and — unlike the
    /// host-side `Layer::owning_target_for` — it crosses the plugin ABI, so a
    /// loaded composite plugin (a foreign router/wrapper `.so`) reports its
    /// internal owning backend, not its outer root name. `None` for a route
    /// with no owning connection (a static route).
    pub owning_target: Option<String>,
    pub capabilities: Capabilities,
    pub range_read_strategy: RangeReadStrategy,
    pub source: RouteSource,
    pub visible: bool,
    pub visibility: AddressVisibility,
    pub alias_state: Option<AliasState>,
    pub icon: Option<Vec<u8>>,
    pub user_metadata: UserMetadata,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum RangeReadStrategy {
    Native,
    CachedReadThrough,
    MaterializeOnly,
    #[default]
    Unsupported,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum CacheLocality {
    CachedComplete,
    CachedPartial,
    #[default]
    NotCached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootInfoSnapshot {
    pub roots: Vec<RootInfo>,
    pub updates: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootInfoChange {
    Snapshot(Vec<RootInfo>),
    Added(Vec<RootInfo>),
    Removed(Vec<RootInfo>),
    Updated(Vec<RootInfo>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionSnapshot {
    pub connections: Vec<Connection>,
    pub updates: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LayerType {
    Backend,
    Wrapper,
    Router,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerKindDescriptor {
    pub kind: String,
    pub layer_type: LayerType,
    pub display_name: String,
    pub description: Option<String>,
    pub config_schema: Vec<ConfigField>,
    pub credential_schema: Vec<CredentialField>,
    pub credential_methods: Vec<CredentialMethod>,
    pub icon: Option<Vec<u8>>,
    pub accepts_connections: bool,
    /// Whether this kind may be composed as a listener authentication Layer.
    /// Hosts fail closed when the selected kind does not advertise this.
    pub auth_capable: bool,
    /// The backend kind's `supports_user_metadata` declaration, carried on the
    /// layer descriptor because that is the only shape a loaded factory hands a
    /// host. Meaningless for a wrapper or router, which own no storage; those
    /// declare `false`, as they do for `accepts_connections`.
    pub supports_user_metadata: bool,
}

/// Async chunk-stream of an object's bytes — the streaming variant of
/// `ReadResult`. Peak memory is bounded by chunk size × channel
/// capacity, never by object size.
pub type ReadStream = std::pin::Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes>> + Send>>;
pub type ChangeStream = Box<dyn Iterator<Item = Result<ChangeEvent>> + Send>;

/// What the plugin or Layer's `read` returned.
pub enum ReadResult {
    Bytes {
        bytes: Vec<u8>,
        info: ObjectInfo,
    },
    Stream {
        stream: ReadStream,
        info: ObjectInfo,
    },
    LocalDelegate(LocalDelegate),
    Redirect(ReadRedirect),
}

impl std::fmt::Debug for ReadResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadResult::Bytes { bytes, info } => f
                .debug_struct("Bytes")
                .field("bytes_len", &bytes.len())
                .field("info", info)
                .finish(),
            ReadResult::Stream { info, .. } => {
                f.debug_struct("Stream").field("info", info).finish()
            }
            ReadResult::LocalDelegate(delegate) => {
                f.debug_tuple("LocalDelegate").field(delegate).finish()
            }
            ReadResult::Redirect(redirect) => f.debug_tuple("Redirect").field(redirect).finish(),
        }
    }
}

/// One step of a write that a backend may complete over several round trips.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum WriteStep {
    /// The write is complete and the object is visible at the backend under
    /// the reported validator.
    Done(WriteResult),
    /// More redirected transfers are required before the write completes.
    ///
    /// **No part of the object may be observable at the backend at this
    /// point.** A backend that transfers in pieces must stage them somewhere a
    /// reader cannot reach — an S3 multipart upload id, an Azure uncommitted
    /// block list — and make the object visible only in the transition to
    /// [`Done`](Self::Done). Abandoning a write here must leave the address
    /// exactly as it was.
    ///
    /// Callers rely on this to keep derived state coherent: a mid-flight step
    /// means the address still holds what it held before, so anything a host
    /// computed from it remains valid. The in-tree byte cache is additionally
    /// robust to a violation — it invalidates before `continue_write` runs —
    /// but that is defence in depth, and says nothing about other hosts.
    Redirects(WriteRedirectBatch),
}

pub type BackendChangeStream = Box<dyn Iterator<Item = Result<BackendChangeEvent>> + Send>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendChangeEvent {
    Object {
        address: Url,
        kind: ChangeKind,
        etag: Option<String>,
        version: Option<String>,
        size: Option<u64>,
        mtime: Option<std::time::SystemTime>,
        at: std::time::SystemTime,
        cursor: WatchDirectoryCursor,
    },
    Lapsed {
        since: Option<std::time::SystemTime>,
        cursor: WatchDirectoryCursor,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BackendItemInfo {
    pub kind: ObjectKind,
    pub etag: Option<String>,
    pub version: Option<String>,
    pub size: Option<u64>,
    pub mtime: Option<std::time::SystemTime>,
    pub checksums: ChecksumSet,
    pub effective_permissions: Option<EffectivePermissions>,
    pub system_metadata: Option<SystemMetadata>,
    pub user_metadata: Option<UserMetadata>,
    pub modified_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatRequest {
    pub address: Url,
    pub options: StatOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub address: Url,
    pub options: ReadOptions,
}

#[derive(Debug)]
pub struct WriteRequest {
    pub address: Url,
    pub body: Body,
    pub options: WriteOptions,
}

#[derive(Debug)]
pub struct ContinueWriteRequest {
    pub address: Url,
    pub redirects: WriteRedirectBatch,
    pub results: RedirectResultBatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteRequest {
    pub address: Url,
    pub options: DeleteOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyRequest {
    pub source: Url,
    pub destination: Url,
    pub options: CopyOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenameRequest {
    pub source: Url,
    pub destination: Url,
    pub options: RenameOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateMetadataRequest {
    pub address: Url,
    pub options: UpdateMetadataOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckAccessRequest {
    pub address: Url,
    pub operations: AccessOps,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListRequest {
    pub prefix: Url,
    pub options: ListOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListVersionsRequest {
    pub address: Url,
    pub options: ListVersionsOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchDirectoryRequest {
    pub prefix: Url,
    pub options: WatchDirectoryOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateDirectoryRequest {
    pub address: Url,
    pub options: CreateDirectoryOptions,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteDirectoryRequest {
    pub address: Url,
    pub options: DeleteDirectoryOptions,
}

/// Destination-side precondition for `write` / `copy` / `rename`.
///
/// `Overwrite` clobbers an existing object unconditionally and is the
/// `Default`. `Fail` refuses to overwrite — operation errors with
/// `ErrorCode::AlreadyExists` if the destination is present. `MatchEtag`
/// permits the overwrite only when the destination's current etag matches
/// the supplied token; mismatches surface `ErrorCode::PreconditionFailed`,
/// the destination having been checked before anything is committed.
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

impl From<(Url, BackendItemInfo)> for ObjectInfo {
    /// An [`ObjectInfo`] is a [`BackendItemInfo`] plus its address. The
    /// Layer directory/metadata ops return the address-less
    /// `BackendItemInfo`, so re-attach the request `address` the caller
    /// supplied. This is the single conversion the host-side introspection
    /// readers delegate to, so a new `ObjectInfo` field is forced to be
    /// handled in exactly one place.
    fn from((address, info): (Url, BackendItemInfo)) -> Self {
        ObjectInfo {
            address,
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
}

impl From<ObjectInfo> for BackendItemInfo {
    fn from(info: ObjectInfo) -> Self {
        Self {
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
    /// Optional host-side cap on buffered read size.
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
    /// a mismatch surfaces `ErrorCode::PreconditionFailed` — the delete
    /// is refused before anything is removed, so no work happened.
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
    /// requires the source object's current etag to match. A mismatch
    /// detected before any work surfaces `ErrorCode::PreconditionFailed`;
    /// a source that changes *during* an already-started transfer surfaces
    /// `ErrorCode::ObjectModified`.
    pub if_source: Option<String>,
    /// Destination-side precondition. See [`IfDestExists`].
    pub if_dest: IfDestExists,
    /// Per-operation annotation; see [`WriteOptions::message`].
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RenameOptions {
    /// Source-side etag precondition: when `Some`, the operation
    /// requires the source object's current etag to match. A mismatch
    /// detected before any work surfaces `ErrorCode::PreconditionFailed`;
    /// a source that changes *during* an already-started transfer surfaces
    /// `ErrorCode::ObjectModified`.
    pub if_source: Option<String>,
    /// Destination-side precondition. See [`IfDestExists`].
    pub if_dest: IfDestExists,
    /// Per-operation annotation; see [`WriteOptions::message`].
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct UpdateMetadataOptions {
    /// Etag the caller expects the target object to have. When `Some`,
    /// a mismatch surfaces `ErrorCode::PreconditionFailed` — the patch is
    /// refused before anything is written, so no work happened.
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

/// What a redirect's credential authorizes, declared by the backend that
/// minted it.
///
/// A host that surfaces a redirect to a caller outside its own process hands
/// over whatever authorizes the redirected request. Only the minting backend
/// knows how much that authorizes: a shared-access signature scoped to one blob
/// for five minutes and an account-wide one an operator pasted into config are
/// byte-identical in shape, so no amount of header or query inspection recovers
/// the difference. This field is where the backend states it.
///
/// [`RedirectScope`] is built by struct literal at every mint site and has
/// neither a [`Default`] nor `#[non_exhaustive]`, so a backend that fails to
/// declare fails to compile. That is deliberate: a policy an operator opts into
/// must not have gaps its own author could not see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectCredential {
    /// The minting backend does not know. It copies a credential it did not
    /// construct — the services client and OpenDAL forward an opaque header set
    /// their upstream returned — so it cannot state the scope without guessing.
    /// A host treats this exactly as [`RedirectCredential::Connection`].
    Unspecified,
    /// The redirect carries no credential. Its target is fetchable by anyone
    /// holding the URL, and delegating it discloses nothing.
    None,
    /// The credential authorizes this request and expires with the redirect: it
    /// names the object and the method, and outlives neither. A presigned URL
    /// is the usual shape.
    Request,
    /// The credential authorizes the connection at large — objects this
    /// redirect does not name, and time beyond its expiry. A storage-account
    /// bearer token or a connection's own authentication headers are this.
    Connection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectScope {
    pub physical_url_prefix: String,
    pub operations: AccessOps,
    pub expires_at: SystemTime,
    /// What the credential on this redirect authorizes, for a host deciding
    /// whether it may cross a process boundary. See [`RedirectCredential`].
    pub credential: RedirectCredential,
}

impl RedirectCredential {
    /// Whether a host may hand a redirect carrying this credential to a caller
    /// outside its own process, when the operator permits disclosure of nothing
    /// broader than the redirected request.
    ///
    /// [`RedirectCredential::Unspecified`] is refused for the same reason
    /// [`RedirectCredential::Connection`] is: an undeclared scope is not a
    /// narrow one.
    pub fn is_request_scoped(self) -> bool {
        matches!(self, Self::None | Self::Request)
    }
}

/// Headers a redirect legitimately needs in order to address, condition or
/// describe the transfer. Everything else is presumed to carry a credential.
///
/// The polarity is deliberate and is the whole point of the list. Enumerating
/// *credentials* cannot be done: the set is open, every backend spells its own
/// differently, and a name nobody anticipated fails in the disclosing
/// direction. Enumerating the inert headers closes over a set that is small and
/// knowable, and an unrecognised name fails in the availability direction
/// instead — the host moves the bytes itself rather than handing over something
/// it could not classify.
///
/// A wrong entry here costs a redirect that could have been delegated, not a
/// disclosure — but that cost is real, so
/// `every_header_an_in_tree_backend_puts_on_a_delegable_redirect_is_inert`
/// enumerates what the in-tree backends actually attach and fails when one of
/// them is not covered. An omission there does not disclose anything; it takes
/// an operator's redirect path away for a header nobody thought to list.
///
/// User metadata is matched by prefix rather than by name, because its
/// suffix is the caller's own key. It is caller-supplied data echoed back on
/// the request that carries it, so it authorizes nothing, and every cloud
/// backend attaches it to a redirect whenever the write carries metadata.
fn header_is_inert(name: &str) -> bool {
    /// Namespaces matched by prefix because their suffix is not ours to
    /// enumerate: the three clouds' user metadata (`x-amz-meta-<key>` and
    /// friends), whose suffix is the caller's own key, and S3's checksum
    /// family, whose suffix is an algorithm name that grows with the SDK.
    ///
    /// Both are content, not authority. Metadata is caller-supplied data echoed
    /// back on the request carrying it; a checksum is a digest of the body. A
    /// holder of either learns nothing and can reach nothing.
    const INERT_PREFIXES: &[&str] = &[
        "x-amz-checksum-",
        "x-amz-meta-",
        "x-goog-meta-",
        "x-ms-meta-",
    ];
    const INERT: &[&str] = &[
        "accept",
        "accept-encoding",
        "cache-control",
        "content-disposition",
        "content-encoding",
        "content-language",
        "content-length",
        "content-md5",
        "content-range",
        "content-type",
        "expect",
        "host",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
        "range",
        "user-agent",
        "x-amz-request-payer",
        "x-amz-sdk-checksum-algorithm",
        "x-goog-content-length-range",
        "x-ms-blob-content-type",
        "x-ms-blob-type",
        "x-ms-version",
    ];
    let lowered = name.to_ascii_lowercase();
    INERT_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
        || INERT.iter().any(|inert| lowered == *inert)
}

/// The credential a redirect actually carries: the minting backend's
/// declaration, demoted when the redirect's own headers contradict it.
///
/// The declaration is the primary answer because it is the only one that can be
/// correct. A signature scoped to one object and one an operator minted for a
/// whole account are the same shape on the wire, so no inspection recovers the
/// difference — only the backend that built the credential knows what it
/// authorizes.
///
/// Inspection is kept as a one-way check: it can lower a declaration to
/// [`RedirectCredential::Connection`], never raise one. A backend that declares
/// a request-scoped credential and then attaches a header this host cannot
/// account for is treated as connection-scoped, so a declaration mistake costs
/// a proxied transfer rather than a disclosure.
pub fn effective_redirect_credential(
    declared: RedirectCredential,
    headers: &[(String, String)],
) -> RedirectCredential {
    if declared.is_request_scoped() && headers.iter().any(|(name, _)| !header_is_inert(name)) {
        return RedirectCredential::Connection;
    }
    declared
}

/// Whether a redirect may be handed to a caller outside this host's process
/// when the operator permits disclosing nothing broader than the redirected
/// request.
///
/// This is the single predicate for both directions. The read and write
/// wrappers in the redirect follower are thin shims over it, precisely so the
/// two paths cannot drift apart, and the hosts call it directly at their
/// out-edges. That they agree is asserted against both host guards in the
/// broker's `the_read_and_write_guards_agree_on_every_declaration`.
pub fn redirect_is_delegable(declared: RedirectCredential, headers: &[(String, String)]) -> bool {
    effective_redirect_credential(declared, headers).is_request_scoped()
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

/// One redirect's outcome as reported by the party that performed it.
///
/// These fields are input to the plugin, not an observation the plugin made.
/// Who produced them depends on the route rather than on the deployment: a
/// redirect follower inside a host stack on one route — the library deployment,
/// and equally the broker's own `write`/`write_stream` path and the REST
/// gateway, which compose the same follower — or a remote client driving the
/// redirect protocol itself over the broker's `continue_write` RPC.
///
/// What is checked before they reach a plugin is less than it looks, and on any
/// follower route it is nothing at all.
///
/// Batch cardinality is **the plugin's own obligation**: call
/// [`validate_redirect_results`] at the top of `continue_write`. No follower
/// route does it for you — the follower hands the batch straight through. The
/// broker's `continue_write` RPC does check it before dispatch, but there the
/// same caller supplied both sides of the comparison, so even then it
/// establishes only that caller's self-consistency.
///
/// That RPC additionally refuses any status outside `200..300`. It is the only
/// place that happens; on a follower route a non-2xx arrives here, including a
/// retryable one whenever the redirect took the no-retry path — either because
/// the method is not idempotent, or because the write body was streamed and so
/// could not be replayed. Nothing validates the header set or the body.
///
/// The same is true of the `continuation` blob echoed back alongside these
/// results. The plugin minted it, but what returns is what the caller sent,
/// with no signature binding it to the operation it was issued for.
///
/// **The request address is the only authenticated part of the call.**
/// Authorization is decided on it, so the object the operation acts on must be
/// *derived from* it rather than taken from the continuation — recomputed from
/// the address, with the blob's copy never read. Comparing the blob's copy
/// against the address is weaker and, on the route where a remote caller
/// supplies the batch, establishes nothing: it presents an address it is
/// authorized for beside a continuation whose recorded copy it rewrote to
/// match. Selecting the target from unauthenticated input is the caller
/// choosing its own authorization.
///
/// Some values cannot come from the address — a server-issued upload id or
/// resumable-session handle, and the preconditions the original write requested.
/// The continuation is their only carrier, so re-deriving them is not an option.
/// The two handle shapes differ. An upload id travels with a key, so pinning
/// the key to the address makes the request commit to the authorized object by
/// construction and the id rides along. A resumable-session handle names the
/// object by itself, and any check confined to the continuation — a recorded
/// address, or the session URL against the redirect batch — compares
/// caller-supplied data with caller-supplied data, so it is worth only what the
/// blob's integrity is worth, and nothing here provides that. Resolve such a
/// session from the address or from backend-held state, or make the blob
/// tamper-evident first. Re-validating the object named in the finalize
/// response is a backstop where the response carries one, but it is detection
/// after the commit, not prevention. Treat the rest as caller-chosen: nothing
/// makes the blob tamper-evident, so a precondition arriving this way must not
/// carry a guarantee another principal depends on.
///
/// Beyond that, these fields must never be evidence for anything the plugin
/// persists, shares, or grants: whether a connection is authenticated, whether
/// a credential is still valid, quota consumption, principal identity, or
/// recorded metrics. Treating a reported status as proof that a request took
/// place lets any caller with write access move operator-configured state
/// without performing one.
///
/// They may shape the result of this call — the [`ObjectInfo`] returned, the
/// ETags assembled for a completion already bound to the authorized address.
/// Even there, a host may cache what is returned, so a lie can outlive the call.
///
/// The test when adding a use: *would this still be true if the caller were
/// lying?* If a wrong answer selects a resource, or reaches anyone but that
/// caller, take the fact from the address or from the plugin's own transport.
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

/// # Errors
///
/// - [`ErrorCode::InvalidArgument`] — the redirect result batch cardinality
///   does not match the preceding redirect batch.
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
