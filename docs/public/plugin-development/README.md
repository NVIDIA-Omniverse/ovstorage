# Plugin development — shared foundation

> "I'm writing an ovstorage plugin and want to know how the ABI works
> and how to test my plugin."

This directory is the entry point for plugin authors. The active
overlay is `plugin-storage`. This README is the canonical reference for
the foreign interface every plugin crosses, the SPI shape every plugin
implements, the type vocabulary every plugin speaks in, the conformance
harness every plugin is tested against, the build-and-load loop every
plugin runs through, and the ABI-stability rules every plugin commits
to at 1.0.

**Where to read first.** The single most useful starting point for a
new storage-backend author is
[`../plugin-storage/CONFORMANCE.md`](../plugin-storage/CONFORMANCE.md) —
the cross-cutting behavioral contract for every Storage SPI method
(what each method must do on success, the edge cases the type signature
doesn't capture, and the capability-driven branch points). Read it,
then come back here for the C-ABI / type-vocabulary / build-and-load
machinery.

## Foreign interface — the C ABI

The C ABI is the canonical foreign interface every plugin crosses.
Even a Rust-authored plugin loaded by a Rust-authored host crosses it,
because the Rust ABI is unstable and a `cdylib` is the only shape that
survives independent compilation. The generated `ovstorage.h` /
`ovstorage.hpp`, the `OvStorage_*` type prefix convention, the
always-async callback shape, the `OvStorage_Bytes` / `OvStorage_Error`
ownership rules, and the `catch_unwind` + `panic = "abort"`
panic-discipline contract live in [library-cpp](../library-cpp/README.md).
(`catch_unwind` is the Rust standard-library guard that converts a
panic into a typed `Result`; `panic = "abort"` is the
`Cargo.toml`-pinned profile flag that aborts the process on panic
rather than unwinding the stack — together they keep a panicking
plugin from corrupting the host's runtime state.)

The C ABI is the ABI stability layer, not a hand-authoring target.
Authors write plugins in Rust (or C++ / Python wrappers as those
mature). Hand-written-C plugin authoring is out of scope; the C
surface is designed for stability and correctness, not C-only
ergonomics.

## SPI shape — vtables, manifest, init

Plugin loading is a two-symbol handshake: the host `dlopen`s the
cdylib, looks up `ovstorage_plugin_manifest_v1` (a static carrying
`struct_size: usize`, the ABI-version constants, NUL-terminated
name/version pointers, and the `test_only` flag), validates the
manifest, then calls `ovstorage_plugin_init_v1(host_callbacks)` and
stores the returned factory vtable pointer (carried in
`BackendPluginInitResultV1.factory_vtable`). There is no separate
`ovstorage_plugin_vtable_v1` symbol — the vtable is a static inside
the plugin's own `.so` whose pointer the init function returns. The
vtable is a populated table of `extern "C" fn` slots — `drop` plus
the factory + backend method tables — with 16 zero-initialized
reserved trailing slots so a newer host running against an older
plugin sees `None` for an unimplemented call rather than reading
past the plugin's vtable.

The full SPI shape — Rust traits (`shim::Backend`, `shim::Factory`),
the `Capabilities` bitset, `ReadResult` / `WriteStep`, the manifest
struct, the C-ABI handshake symbols, and how options structs are
versioned across the boundary — is reproduced in full below.

## Surface boundary — host APIs vs plugin SPI

The plugin SPI is not the public `Library` / `Storage` API. It pins
the contract between a host process and a loaded backend plugin.

- **Application-facing APIs** live in [library-rust](../library-rust/README.md),
  [library-cpp](../library-cpp/README.md), and the broker / REST
  protocol surface. They expose address-routed helpers such as
  `capabilities_for`, `read_bytes`, `read_stream`, `materialize`, and
  `check_access`, plus local management surfaces for connections,
  aliases, visibility, and authentication. The Rust type vocabulary
  they speak in is documented under § Type vocabulary below.
- **Host responsibilities** live in the library or broker: route
  resolution, alias expansion, cache lookup and herd collapse, cache
  commit / eviction, redirect execution, retry and backoff policy,
  secret persistence, broker authorization, observability, and
  conversion between plugin-facing values and public API shapes.
- **`Backend` SPI methods** are what plugins implement. The Rust trait
  is `#[async_trait]` and every I/O method takes
  `cancel: Option<CancellationToken>`. It covers the object
  operations (`stat`, `read`, `write`, `write_stream`, `write_redirect`,
  `continue_write`, `delete`, `list`, `list_versions`,
  `get_latest_version`, `watch_directory`, `watch_address_roots`,
  `copy`, `rename`, `create_directory`, `delete_directory`,
  `update_metadata`, `check_access`). Capabilities flow per-route via
  the `BackendInstance.capabilities` field (and `AddressRoot.capabilities`
  deltas), not through a `Backend` trait method. The SPI is
  deliberately not the same list as the public `Storage` trait: some
  public methods collapse several SPI calls, and some SPI calls
  exist only so the host can manage routing or lifecycle.

The host canonicalizes directory-facing public calls before they
reach the SPI. `Backend::create_directory`, `Backend::delete_directory`,
and `Backend::list` receive directory targets in canonical slash
form. Public `stat` is input-guided, but the host may answer an
unversioned exact-object `stat` from a cached or freshly fetched
one-level parent `Backend::list` entry when the route supports
one-level list and sets `wants_list_backed_stat`. If that
list-backed path is unavailable or does not contain the object,
`stat("foo")` dispatches `Backend::stat` for exact `foo`, and only
if that returns `NotFound` does the host issue `Backend::stat` for
`foo/`; `stat("foo/")` arrives only as `Backend::stat` for `foo/`.
Permission/auth errors from the attempted spelling are final.
Plugins should not implement a second trailing-slash policy of
their own.

**`Factory` SPI methods** (`Factory::descriptor`, `probe`,
`instantiate`, `update_credentials`, and `authenticate`) are
management/configuration entry points. They are not object I/O, and
conformance must not count them as part of the object-operation
surface.

This split is load-bearing for the "same plugin binary in library
and broker" rule: the plugin exposes one SPI; each host decides how
that SPI maps onto its public surface.

## Type vocabulary

The Rust type vocabulary every host and every plugin uses lives in
`ovstorage_plugin`: `ObjectAddress`, `ObjectInfo`, `ObjectKind`,
`IfDestExists`, `ResolvedTarget`, the options structs, the error
taxonomy, the connection / alias / auth types, `LocalDelegate`, and
`SecretBytes`. The dispatcher re-exports these so application code
does not need to depend on the plugin crate directly; this section
is the source of truth for their shape.

### Core types

Caller-facing addresses are `url::Url` — there is no separate
`ObjectAddress` newtype. The `ovstorage_plugin::address` module
exposes free helpers (`parse`, `key`, `is_directory`, `to_directory`,
`parent_and_name`, `replace_prefix`, `is_prefix_of`,
`join_relative`) that operate directly on `Url`. Version pins are part
of the address itself; the dispatcher does not expose a separate
version-selection value. URL canonicalization is whatever
`url::Url::parse` produces; the per-address invariants below still
apply.

```text
pub struct ObjectInfo {
    pub address:               Url,
    pub kind:                  ObjectKind,
    pub etag:                  Option<String>,
    pub version:               Option<String>,
    pub size:                  Option<u64>,                // None for directories
    pub mtime:                 Option<SystemTime>,         // None for DirectoryInferred
    pub checksums:             ChecksumSet,
    pub effective_permissions: Option<EffectivePermissions>,
    pub system_metadata:       Option<SystemMetadata>,
    pub user_metadata:         Option<UserMetadata>,
    pub modified_by:           Option<String>,
}

pub enum ObjectKind {
    File,
    Directory,           // backend with native directory inodes (POSIX, ADLS Gen2 HNS, Nucleus)
    DirectoryMarker,     // zero-byte marker object on a flat key namespace
    DirectoryInferred,   // directory inferred by the dispatcher from common prefixes; no backing object
}

impl ObjectKind {
    pub fn is_file(&self) -> bool { matches!(self, Self::File) }
    pub fn is_directory(&self) -> bool { !self.is_file() }
}

pub enum IfDestExists {
    Overwrite,           // default; replace any existing destination
    Fail,                // refuse if the destination exists (Conflict / AlreadyExists)
    MatchEtag(String),   // refuse unless the destination's current etag matches
}

pub struct ResolvedTarget {
    pub backend_id:       BackendId,
    pub resolved_address: Url,
}

pub struct ChecksumSet { /* zero or more (ChecksumAlgorithm, bytes) entries */ }

pub struct ChecksumAlgorithm(String); // normalized ASCII token, e.g. "sha256", "crc32c", "md5"

// Hand-rolled u32 newtype — kept off the `bitflags` crate so the C ABI
// shadow type and the Rust type stay in lock-step. `READ | WRITE |
// DELETE | UPDATE_METADATA` constants plus `BitOr` / `BitAnd` operator
// impls.
pub struct EffectivePermissions(u32);

impl EffectivePermissions {
    pub const READ: Self            = Self(1 << 0);
    pub const WRITE: Self           = Self(1 << 1);
    pub const DELETE: Self          = Self(1 << 2);
    pub const UPDATE_METADATA: Self = Self(1 << 3);
}

pub type SystemMetadata = HashMap<String, String>;     // backend-owned, opaque vendor pass-through
pub type UserMetadata   = HashMap<String, String>;     // caller-owned, set on write, edited via update_metadata

// `Body` is not `Clone`/`PartialEq`/`Eq` because `Stream`'s iterator is
// stateful. Plugins that haven't implemented chunked uploads return
// `ErrorCode::Unsupported` for `Stream` rather than draining it.
pub enum Body {
    Bytes(Vec<u8>),
    LocalFile(PathBuf),
    Stream(BodyStream),
}

pub struct BodyStream { /* boxed Iterator<Item = Result<Vec<u8>>> + Send */ }

pub struct WriteResult {
    pub info: ObjectInfo,
}

pub type Result<T> = std::result::Result<T, Error>;
pub type ReadStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<bytes::Bytes>> + Send>>;

pub struct BackendId(pub String);
pub struct ByteRange { pub start: u64, pub end_inclusive: Option<u64> }
pub struct AccessOps { pub read: bool, pub write: bool, pub delete: bool, pub update_metadata: bool }
pub struct AccessDecision { pub allowed: bool, pub denied_ops: AccessOps, pub reason: Option<String> }
```

`SystemMetadata` and `UserMetadata` are separate types so ownership
is enforced at the type level — backends own `SystemMetadata`,
callers own `UserMetadata`.

Ownership and invariants:

- Caller-facing `Url`s are always the URL the application passed, or
  a caller-facing URL projected by the dispatcher from a backend
  result address. Plugins never return rewritten physical URLs to
  application code.
- `ResolvedTarget` is internal to routing, plugin dispatch, tracing,
  and errors. It is the full URL handed to the plugin after any
  `rewrite_to` prefix swap, paired with the selected `BackendId`.
- `ObjectInfo.etag` / `version` / `size` / `mtime` contain only
  facts the backend returned or the plugin could verify from the
  backend response. The library never invents an ETag, version,
  size, or mtime to make preconditions easier.
- `ObjectInfo.address` is canonical for the object being described.
  Public callers see it in the same address namespace they used;
  plugins return it in the resolved backend namespace they were
  handed. For `list`, `watch_directory`, `list_versions`, and
  `get_latest_version`, the dispatcher projects each returned address
  from the requested resolved prefix back into the caller-facing
  prefix. A backend result outside the requested scope is an
  `Internal` backend contract violation, not a child the dispatcher
  should silently hide or rewrite. `ObjectInfo.etag` (together with
  `version` / `size` / `mtime`) is the latest response metadata known
  for that address.
  `ObjectInfo.system_metadata` is backend-owned and read-only;
  `ObjectInfo.user_metadata` is caller-owned and mutable only
  through `write` and `update_metadata`.
- `ObjectInfo.kind` discriminates files from directories. The three
  directory variants encode persistence and post-delete behavior:
  `Directory` is a native directory inode (persists independently of
  contained objects; `delete_directory` removes it cleanly when
  empty); `DirectoryMarker` is a zero-byte marker object on a flat
  backend (after `delete_directory` removes the marker, the
  directory falls to `DirectoryInferred` if children remain, or
  vanishes entirely if not); `DirectoryInferred` exists only because
  at least one child key shares the prefix (no backing storage
  object; vanishes once the last child is deleted). Callers asking
  "is this a directory?" use `kind.is_directory()`.
- The `address` module exposes parser-level helpers used by
  dispatchers and bindings: `is_directory`, `to_directory`, and
  `parent_and_name`. `parent_and_name` intentionally returns `None`
  for directory-form URLs and any URL with a fragment. The dispatcher
  does not try to identify which query key is a provider's version
  pin; the whole query-bearing address is non-cacheable for
  list-backed stat.

### Options structs

Etag-sensitive read / delete / metadata operations use a single
`if_match: Option<String>` precondition — an opaque etag string the
plugin compares against the current backend etag. Writes and
copy / rename use the richer `IfDestExists` enum on the destination
side. Copy and rename additionally accept `if_source: Option<String>`
to constrain the source. Listing, routing introspection, connection
management, alias management, and auth streams do not take etag
preconditions because they are not conditional object mutations.
The full vocabulary:

```text
pub struct StatOptions {
    pub full_metadata: bool,
}

pub struct ReadOptions {
    pub if_match: Option<String>,         // etag
    pub range:    Option<ByteRange>,
}

pub struct WriteOptions {
    pub if_dest:         IfDestExists,                 // Overwrite (default) / Fail / MatchEtag(etag)
    pub size_hint:       Option<u64>,
    pub user_metadata:   Option<UserMetadata>,
    pub message:         Option<String>,               // human-readable per-operation annotation
    /* other fields... */
}

pub struct DeleteOptions          { pub if_match: Option<String> }
pub struct UpdateMetadataOptions  {
    pub if_match:                  Option<String>,
    pub allow_rewrite_emulation:   bool,
    pub user_metadata_set:         HashMap<String, String>,
    pub user_metadata_remove:      Vec<String>,
    pub message:                   Option<String>,
}
pub struct CopyOptions   {
    pub if_source: Option<String>,        // etag constraining the source
    pub if_dest:   IfDestExists,          // destination-side precondition
    pub message:   Option<String>,
}
pub struct RenameOptions {
    pub if_source: Option<String>,
    pub if_dest:   IfDestExists,
    pub message:   Option<String>,
}

pub struct ListOptions {
    pub recursive:     bool,                            // false: one level; true: full subtree
    pub max_results:   Option<u32>,
    pub page_token:    Option<String>,
    pub full_metadata: bool,
}

pub struct ListVersionsOptions {
    pub max_results: Option<u32>,
    pub page_token:  Option<String>,
}

pub struct CreateDirectoryOptions {}

pub struct DeleteDirectoryOptions;                      // unit struct; the SPI's directory-delete
                                                       //   removes only the directory representation.

pub struct WatchDirectoryOptions {
    pub recursive:                bool,                 // default false
    pub include_metadata_changes: bool,                 // default true
    pub since:                    Option<WatchDirectoryCursor>,
    pub poll_interval:            Duration,             // default 1s
}
```

#### Enforcement contract

The host passes `opts` to the plugin verbatim and does **not**
post-filter. Plugins MUST enforce these fields directly:

| Field | Op | Plugin contract |
|---|---|---|
| `if_match` | read / delete / update_metadata | If `Some(etag)`, only operate on bytes that match the caller's opaque etag token for that same address. The etag is opaque to the SPI — its internal structure is the plugin's choice. The `file` plugin synthesizes `"size:N,mtime:Tms"`; cloud plugins use the backend-supplied ETag or equivalent validator; the Omniverse Storage Service uses `ResourceIdentity.encoded_identity`. Version IDs/generations stay in `ObjectInfo.version` and version-pinned addresses, not in precondition fields. For reads, prefer a server-side precondition (HTTP `If-Match`, an etag-keyed/identity-keyed read RPC); when the wire doesn't carry one, fetch metadata and compare client-side. |
| `if_source` | copy / rename | If `Some(etag)`, only copy or rename source bytes matching the caller's opaque etag token for that same source address. Maps to backend source-side conditional headers or identity slots (S3 `x-amz-copy-source-if-match`, Azure `x-ms-source-if-match`, GCS `ifSourceGenerationMatch`, Storage API `source_resource_identity`). |
| `if_dest` | write / copy / rename | `IfDestExists::Overwrite` replaces any existing destination. `IfDestExists::Fail` refuses when the destination exists; plugins that advertise `Capabilities.supports_no_overwrite_write = true` MUST honor this with `Conflict` / `AlreadyExists`, others MUST return `Unsupported`. `IfDestExists::MatchEtag(etag)` refuses unless the destination's current etag matches; plugins that advertise `Capabilities.supports_if_match_write = true` MUST honor this, others MUST return `Unsupported`. The host does not pre-check. |
| `range` (read) | read | Plugin MUST apply the range. For `ReadResult::Stream` and `ReadResult::Bytes`, slice the bytes the plugin is producing. For `ReadResult::Redirect`, the host injects `Range:` headers on the redirect request before following — plugins return the redirect unchanged. For `ReadResult::LocalDelegate`, the host handles the slice. |
| `max_bytes` (read) | read | Host-side cap on buffered read size. Plugins MAY ignore it; the host applies it to the returned stream/bytes. |
| `size_hint` (write) | write | Hint for routing decisions (e.g., inline vs. multipart). Not a contract; backends may treat it as advisory. |
| `user_metadata` (write / update_metadata) | mutating | Plugin SHOULD persist if its backend supports user metadata; SHOULD silently drop otherwise. |
| `message` (write / copy / rename / update_metadata) | mutating | Plugin SHOULD attach as a per-operation annotation if the backend supports one (e.g., a version commit message); drop silently otherwise. |

Silently ignoring any of the MUST fields is a bug — a caller's
`if_match` precondition that the plugin ignores will let stale reads
succeed and lose the optimistic-locking guarantee. If the wire
protocol can't carry a precondition, the plugin must emulate it
(read then compare, or refuse with `Unsupported`) rather than drop
the field on the floor.

For the common "I just did `stat`, now read with the same etag"
case, the caller sets `if_match: info.etag.clone()` directly on the
relevant options struct. There is no `if_matches(&info)` constructor
helper; every options field is constructed by struct-literal
expressions. For writes that should refuse to overwrite, the caller
sets `if_dest: IfDestExists::Fail`; to constrain a write against an
existing etag, `if_dest: IfDestExists::MatchEtag(etag)`.

Directory-facing operations accept either spelling for a directory
address. `create_directory("foo")` is equivalent to
`create_directory("foo/")`; the same rule applies to
`delete_directory` and `list`. The canonical directory form
appends the slash before any query or fragment
(`foo?x=1` becomes `foo/?x=1`), and returned directory `ObjectInfo`
/ list child addresses use the canonical slash form.

`stat` uses the caller's spelling to choose probe order because it
can describe either an object or a directory. `stat("foo")` first
stats the exact object address `foo`; only if that returns
`NotFound` does the library try the canonical directory form
`foo/`. `stat("foo/")` stats only the directory form and never
falls back to exact object `foo`. If object `foo` and
directory/prefix `foo/` coexist, `stat("foo")` returns the object
and `stat("foo/")` returns the directory. Permission/auth errors
from either probe are final.

`create_directory` is idempotent: it makes the requested directory
exist according to the backend's directory model and returns
success when the target directory representation already exists.

`Backend::delete_directory` removes only the backend's directory
representation: a real directory must be empty, and a
flat-object-store marker removal leaves children untouched. The SPI
does not expose a recursive subtree-delete.

### Version-pinned addresses

Version selection lives in the `Url`, not in a separate side value
type. A backend that supports historical reads uses its native address
syntax (`?versionId=...`, `?generation=...`, Nucleus checkpoint query
forms, and so on) as the durable pin. `list_versions` and
`get_latest_version` return `ObjectInfo` values whose
`ObjectInfo.address` is already pinned to the version being described.
The dispatcher only projects the route prefix between backend and
caller namespaces; it does not synthesize or interpret a sidecar
field.

### `ChangeKind` and `WatchDirectoryCursor`

```text
pub enum ChangeKind { Created, Modified, Deleted, MetadataChanged }

pub struct WatchDirectoryCursor(pub Vec<u8>);
```

`ChangeKind` is shared between the plugin SPI's `BackendChangeEvent`
and the public `ChangeEvent`.

### Connection-management types

```text
pub struct ConnectionId(pub String);

pub struct StorageBackendKindDescriptor {
    pub kind:                 String,
    pub display_name:         String,
    pub description:          Option<String>,
    pub config_schema:        Vec<ConfigField>,
    pub credential_schema:    Vec<CredentialField>,
    pub capabilities:         Capabilities,
    pub icon:                 Option<Vec<u8>>,
    pub supports_runtime_add: bool,
}

pub struct ConfigField {
    pub key:          String,
    pub display_name: String,
    pub kind:         ConfigFieldKind,
    pub required:     bool,
    pub default:      Option<ConfigValue>,
    pub help:         Option<String>,
    pub example:      Option<String>,
    pub group:        Option<String>,
}

pub enum ConfigFieldKind { Url, Text, Integer, Bool, Enum { source: EnumSource }, Path }
pub enum EnumSource     { Static(Vec<String>), Discovered }

pub struct CredentialField {
    pub key:          String,
    pub display_name: String,
    pub kind:         CredentialFieldKind,
    pub required:     bool,
    pub help:         Option<String>,
}

pub enum CredentialFieldKind {
    Secret,
    OAuthFlow { provider: String },
    FileUpload,
    MtlsCertPair,
    SystemIdentity,
}

pub enum ConfigValue {
    String(String),
    Int(i64),
    Bool(bool),
    /// Reserialized TOML payload — a nested table or array of tables
    /// captured opaquely by the host. The plugin parses with
    /// `toml::from_str` on receipt.
    Toml(String),
}

pub struct ConnectionRequest {
    pub backend_kind:  String,
    pub config:        HashMap<String, ConfigValue>,
    pub credentials:   SecretBundle,
    pub persist:       bool,
    pub display_name:  Option<String>,
}

pub struct SecretBundle { pub fields: HashMap<String, SecretValue> }

pub enum SecretValue {
    Bytes(SecretBytes),
    OAuthToken { token: SecretBytes, refresh: Option<SecretBytes>, expires_at: Option<SystemTime> },
    File(SecretBytes),
    MtlsCertPair { cert_pem: SecretBytes, key_pem: SecretBytes },
    SystemIdentity,
}

pub struct Connection {
    pub id:                ConnectionId,
    pub backend_kind:      String,
    pub display_name:      String,
    pub source:            ConnectionSource,
    pub capabilities:      Capabilities,
    pub current_addresses: Vec<Url>,
    pub auth_state:        ConnectionAuthState,
    pub last_probed:       Option<SystemTime>,
    pub user_metadata:     UserMetadata,
}

pub enum ConnectionSource {
    Static { layer: ConfigLayer },
    Runtime { persisted: bool },
    BrokerDelivered { broker_principal: String },
}

pub enum ConnectionChange {
    Added(Connection),
    Removed { id: ConnectionId },
    Updated(Connection),
    Snapshot(Vec<Connection>),
}
```

### Alias types

```text
pub struct AliasId(pub String);

pub struct AliasRequest {
    pub from:          Url,
    pub to:            Url,
    pub visibility:    AddressVisibility,
    pub persist:       bool,
    pub display_name:  Option<String>,
    pub user_metadata: UserMetadata,
}

pub struct Alias {
    pub id:            AliasId,
    pub from:          Url,
    pub to:            Url,
    pub visibility:    AddressVisibility,
    pub source:        AliasSource,
    pub state:         AliasState,
    pub display_name:  Option<String>,
    pub user_metadata: UserMetadata,
}

pub enum AliasState {
    Live,                                       // `to` resolves to a non-alias row
    Dangling,                                   // `to` does not resolve currently
    ChainTooLong { reason: String },            // `to` resolves to another alias
}

pub struct AddressVisibilityOverride {
    pub address:    Url,
    pub visibility: AddressVisibility,
    pub persisted:  bool,
}
```

### Connection authentication types

```text
pub enum ConnectionAuthState {
    Authenticated { last_authenticated_at: SystemTime, expires_at: Option<SystemTime> },
    AwaitingAuth  { reason: AuthReason, last_attempt: Option<AuthAttempt> },
    AuthFailed    { error: Error, attempts: u32 },
    Anonymous,
}

pub enum AuthReason {
    NeverAuthenticated,
    RefreshTokenExpired,
    RefreshTokenRevoked,
    CredentialsRotated,
    ManuallyRequested,
    BackendUnreachable,
    Unknown { details: String },
}

pub struct AuthAttempt {
    pub at:    SystemTime,
    pub error: Option<Error>,
}

pub enum AuthEvent {
    OpenBrowser  { url: String, expires_at: SystemTime },
    DeviceCode   { user_code: String, verification_url: String, expires_at: SystemTime, interval: Duration },
    Progress     { message: String },
    Succeeded    { connection: Box<Connection> },
    Failed       { error: Error },
    Cancelled,
}

/// Host-declared limit on what kind of interactive auth the plugin
/// may attempt. Set once at `Library::builder()` time; threaded into
/// `Factory::authenticate` so the plugin picks the right OAuth subflow
/// (or fails fast). Default `Browser`.
pub enum InteractiveAuthCapability {
    /// CI / render workers / sandboxed services. Plugins emit
    /// `Err(AuthRequired)` immediately; **no `AuthEvent` ever lands
    /// on the wire**.
    None,
    /// SSH session / container shell. Host can show URLs and codes
    /// for the user to act on a different device but cannot bind a
    /// 127.0.0.1 redirect listener. OAuth-IDP plugins use device
    /// flow (RFC 8628). PKCE is forbidden in this mode.
    Headless,
    /// Desktop GUI / local terminal. Host can both launch a browser
    /// and bind a redirect listener. PKCE is preferred.
    Browser,
}
```

`Factory::authenticate` takes the capability between `connection` and `cancel`:

```text
async fn authenticate(
    &self,
    connection: Connection,
    capability: InteractiveAuthCapability,
    cancel: Option<CancellationToken>,
) -> Result<AuthEventStream, Error>;
```

Plugin behavior matrix:

| Capability | OAuth-IDP plugins | Long-flow plugins | Anonymous / non-interactive |
|---|---|---|---|
| `None`     | `Err(AuthRequired)` immediately, no events | `Err(AuthRequired)` immediately | unchanged |
| `Headless` | Device flow (RFC 8628) | URL+nonce-poll (works since the user can open the URL on any device) | unchanged |
| `Browser`  | PKCE (or device fallback if the IDP advertises only device) | URL+nonce-poll | unchanged |

The capability flows transparently across the broker via the
`x-ov-iauth: <browser|headless|none>` gRPC metadata header
(HPACK-indexed by Tonic's interceptor; ~1-2 bytes per call after the
first).

### `LocalDelegate`

```text
pub struct LocalDelegate {
    pub path: PathBuf,
    pub info: ObjectInfo,
}
```

`materialize` returns a path to an existing file on local disk —
either a cache entry the library already materialized, or, for the
`file` plugin, the source file itself. The caller opens the file
directly: `File::open(&local.path)`, `mmap` for random access, hand
the path to a child process. No bytes flow through the `Library`
API.

Cache leasing (the RAII handle that pins the file in place against
GC eviction) and time-bounded delegate expiry are not modelled on
the plugin-facing struct. The struct carries only the path and
`ObjectInfo`; the cache layer keeps lease bookkeeping out of band.
Plugins that hand back a path to a file with finite lifetime encode
that out of band; there is no typed lease/`expires_at` extension.

### `SecretBytes`

```text
pub struct SecretBytes(/* heap-allocated, zeroized on drop */);
```

A newtype around a heap-allocated buffer that:

- Zeros its memory on drop (`zeroize` + `Drop`).
- Implements `Debug` as the literal string
  `SecretBytes(<redacted>)`. There is no `Display` impl — values do
  not silently format into log lines.
- Derives `Clone` so credentials can be threaded through plugin
  callbacks; `into_inner` consumes the wrapper without zeroizing
  (the caller takes responsibility), and `as_bytes` borrows under
  the existing Drop guard.
- Serializes only over the broker's authenticated gRPC channel,
  never to disk in plaintext, never to logs. mTLS is deferred.
- Crosses the C ABI as `ffi::SecretBytes`;
  `shim::descriptor::secret_bytes_from_ffi` rewraps the underlying
  FFI allocation in place rather than copying first, so the
  original page is zeroized by `SecretBytes::Drop` before the
  allocator reclaims it.

The runtime properties on `SecretBytes` (zeroize-on-drop, redacted
`Debug`, no `Display` impl, no `serde::Serialize` impl) carry the
redaction guarantee through the type system: a hypothetical
audit-record `serde::Serialize` would fail to compile if it tried
to take a `SecretBytes` field, and the redacted `Debug` keeps trace
lines clean.

## Error model

The shared error taxonomy lives in [GLOSSARY.md](../GLOSSARY.md#error-model).
The categories: generic, retryability rules, brokered, cache/state,
preconditions, routing, credential, authentication, and content.
Plugins translate backend failures into the shared `ErrorCode` enum
and return promptly; retry, backoff, circuit breaking, cache
fallback, and user-visible policy are host responsibilities unless a
backend protocol has an indivisible internal retry required for a
single operation to complete safely.

## Connection lifecycle errors

Connection-management methods (`Factory::probe`, `instantiate`,
`update_credentials`, `authenticate`) report errors as the same flat
`ErrorCode` shape used elsewhere; there is no separate
`ConnectionError` type. The mapping from lifecycle stage to typical
`ErrorCode` value:

| Lifecycle stage                           | Typical `ErrorCode` |
|-------------------------------------------|---------------------|
| Config schema mismatch / missing field    | `InvalidArgument`   |
| Config conflict / route already exists    | `RouteConflict` / `AlreadyExists` |
| IdP rejects supplied credentials          | `PermissionDenied`  |
| No credentials reached the plugin         | `CredentialUnavailable` |
| Plugin requires interactive auth          | `AuthRequired`      |
| Refresh token revoked / cancelled         | `AuthCancelled`     |
| Refresh token expired                     | `AuthExpired`       |
| Backend unreachable / 5xx / network blip  | `Transient`         |
| Plugin must be re-instantiated            | `IncompatibleType`  |
| Plugin's internal setup fails             | `Internal`          |

This list is informative, not exhaustive — every plugin is free to
return any `ErrorCode` value that preserves recovery semantics. The
host's lifecycle layer (auth refresh, re-instantiate-on-`IncompatibleType`,
retry on `Transient`) reads the code and reacts; the message field
carries human context.

## URL canonicalization

The library canonicalizes URLs at parse time, but only on the parts
of the URL that name *where* the request goes — scheme, host, port,
and query encoding. **Object key segments are preserved byte-for-byte.**
Object stores commonly accept keys with literal `..`, `.`,
double-slashes, trailing dots, control characters, and
unicode-normalization-sensitive sequences, and the library doesn't
rewrite any of them.

Transformations the library *does* apply: lowercase the scheme,
lowercase the host where the scheme treats host as case-insensitive,
strip default ports, encode query parameters canonically without
reordering them, apply IDN punycode normalization to the host.

Mutating ops whose backend wire format cannot carry a version pin
must reject any caller-supplied version-pinned address with
`InvalidArgument` rather than silently dropping the pin and writing to
head. The shared helper
`ovstorage_plugin::url_helpers::reject_pinned_for_mutation` takes
the resolved URL and a list of version-pin keys (`versionId`,
`generation`, `versionid`, `version`, `checkpoint`, …) and returns
the typed error so each plugin's mutating-op surface stays
consistent.

## `ReadResult`: the read shapes

Every plugin's `read` SPI call returns one of four shapes. The
library's typed helpers (`read_bytes`, `read_stream`, `materialize`)
consume the enum and present the appropriate result to the caller;
applications never branch on the variant directly.

```text
pub enum ReadResult {
    Bytes { bytes: Vec<u8>, info: ObjectInfo },
    Stream { stream: ReadStream, info: ObjectInfo },
    LocalDelegate(LocalDelegate),
    Redirect(ReadRedirect),
}
```

- **`LocalDelegate`** — bytes are already on local disk under a
  leased path. Returned from cache hits and from the `file` plugin.
  The library hands it back unchanged; `read_stream` opens the file
  and emits 64 KiB chunks.
- **`Bytes`** — the plugin returns an in-memory byte buffer plus
  `ObjectInfo`. Used for small responses (under the per-plugin
  small-response threshold) and for ranged reads where the caller
  already bounded the slice. `read_stream` wraps it as a single
  iterator chunk.
- **`Stream { stream, info }`** — async chunk-stream for whole-object
  reads above the small-response threshold. Returned by every cloud
  plugin's whole-object path. Peak host memory is bounded by the
  stream's chunk size, never by object size — this is the substrate
  that prevents the "redirect a 10 GiB read and OOM the host"
  pattern.
- **`Redirect`** — the plugin returns a short-lived HTTP request
  envelope plus response-parsing hints. The host follows the request
  through the shared redirect follower.

The conformance harness asserts that streaming reads from a
multi-GiB fixture peak at chunk-size memory rather than object-size
memory; plugins that rebuild buffers internally fail this assertion
even if they advertise streaming.

## Plugin SPI

The checked-in Rust SPI lives under `ovstorage_plugin::shim` and
exposes two layers for first-party backends:

1. `shim::Factory`: one object per backend kind. It exposes
   descriptors, probes connection requests, instantiates backend
   instances, accepts credential updates, and drives authentication
   events.
2. `shim::Backend`: one object per configured backend instance /
   route. It owns backend clients, per-instance config, and the SPI
   methods the host dispatches after routing.

Both traits are `#[async_trait]` and every I/O method takes
`cancel: Option<CancellationToken>` so the host can interrupt
long-running work. The dynamic C ABI populates a heterogeneous
vtable: synchronous slots (`drop` on the backend, `drop` and
`descriptor` on the factory) return through out-pointers, while
every async I/O slot is callback-shaped — the host calls the vtable
method, the thunk converts inputs synchronously, spawns the work on
the plugin's tokio runtime, and fires `on_complete` exactly once
when the spawned future settles. Capabilities are not a vtable slot;
they ride on the `BackendInstance` value that `Factory::instantiate`
returns and on each `AddressRoot.capabilities` from
`watch_address_roots`. Rust plugin authors use the function-like
macro `ovstorage_plugin!(MyFactory::default)` (an expression that
resolves to `fn() -> impl Factory`) to emit the manifest/init
symbols; the macro is not an attribute.

```text
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn stat(&self, target: ResolvedTarget, opts: StatOptions, cancel: Option<CancellationToken>) -> Result<ObjectInfo>;
    async fn read(&self, target: ResolvedTarget, opts: ReadOptions, cancel: Option<CancellationToken>) -> Result<ReadResult>;

    // The single doc-level "write" splits across three SPI methods. The host gates by
    // `Capabilities::redirect_size_threshold` and dispatches to the matching one;
    // defaults return `Unsupported` so plugins opt in to the shapes they implement.
    async fn write(&self, target: ResolvedTarget, bytes: Vec<u8>, opts: WriteOptions, cancel: Option<CancellationToken>) -> Result<WriteResult>;
    async fn write_stream(&self, target: ResolvedTarget, body: BodyStream, opts: WriteOptions, cancel: Option<CancellationToken>) -> Result<WriteResult>;
    async fn write_redirect(&self, target: ResolvedTarget, opts: WriteOptions, cancel: Option<CancellationToken>) -> Result<WriteRedirectBatch>;
    async fn continue_write(&self, target: ResolvedTarget, redirects: WriteRedirectBatch, results: RedirectResultBatch, cancel: Option<CancellationToken>) -> Result<WriteStep>;

    async fn delete(&self, target: ResolvedTarget, opts: DeleteOptions, cancel: Option<CancellationToken>) -> Result<()>;
    async fn list(&self, prefix: ResolvedTarget, opts: ListOptions, cancel: Option<CancellationToken>) -> Result<Vec<ObjectInfo>>;
    async fn list_versions(&self, target: ResolvedTarget, opts: ListVersionsOptions, cancel: Option<CancellationToken>) -> Result<Vec<ObjectInfo>>;
    /// Resolve the input to a single version-pinned address: returns the
    /// requested version's `ObjectInfo` if `target` already carries a
    /// version pin, otherwise the current head's pinned `ObjectInfo`.
    /// Capability-gated on `supports_version_listing`; default returns
    /// `Unsupported`.
    async fn get_latest_version(&self, target: ResolvedTarget, cancel: Option<CancellationToken>) -> Result<ObjectInfo>;
    async fn watch_directory(&self, prefix: ResolvedTarget, opts: WatchDirectoryOptions, cancel: Option<CancellationToken>) -> Result<BackendChangeStream>;
    /// Server-streamed address-root deltas for backends whose
    /// `Capabilities::address_roots_are_dynamic = true`.
    async fn watch_address_roots(&self, cancel: Option<CancellationToken>) -> Result<BackendAddressRootsStream>;
    async fn create_directory(&self, target: ResolvedTarget, opts: CreateDirectoryOptions, cancel: Option<CancellationToken>) -> Result<BackendItemInfo>;
    async fn delete_directory(&self, target: ResolvedTarget, opts: DeleteDirectoryOptions, cancel: Option<CancellationToken>) -> Result<()>;
    async fn copy(&self, src: ResolvedTarget, dest: ResolvedTarget, opts: CopyOptions, cancel: Option<CancellationToken>) -> Result<WriteStep>;
    async fn rename(&self, src: ResolvedTarget, dest: ResolvedTarget, opts: RenameOptions, cancel: Option<CancellationToken>) -> Result<()>;
    async fn update_metadata(&self, target: ResolvedTarget, opts: UpdateMetadataOptions, cancel: Option<CancellationToken>) -> Result<BackendItemInfo>;
    async fn check_access(&self, target: ResolvedTarget, ops: AccessOps, cancel: Option<CancellationToken>) -> Result<AccessDecision>;
}
```

`Factory` mirrors the same async + cancel shape: `descriptor()` is
sync, while `probe`, `instantiate`, `update_credentials`, and
`authenticate` are async with `cancel: Option<CancellationToken>`.
`instantiate` returns a
`BackendInstance { backend_id, backend: Arc<dyn Backend>, address_roots: Vec<Url>, capabilities, display_name, auth_state }`.

### `list` shape contract

Two shapes, picked by `ListOptions.recursive`:

- **`recursive: false`** — one-level listing. Plugins emit
  one `ObjectInfo` for every object directly under the prefix and one
  `ObjectInfo` for every immediate child container (native directory,
  marker, or inferred prefix); the plugin populates `kind` per
  `ObjectKind`
  (`Directory` / `DirectoryMarker` / `DirectoryInferred`).
- **`recursive: true`** — full subtree listing. Plugins emit every
  descendant object plus any directory facts the backend natively
  returns or stores: real directories as `Directory`, zero-byte flat
  markers as `DirectoryMarker`, and backend-reported prefixes as
  `DirectoryInferred`. Flat backends may also emit inferred ancestor
  directories implied by descendant objects. The host normalizes public
  recursive list results the same way after address projection, so
  `foo/bar/baz.txt` implies visible `foo/` and `foo/bar/`
  `DirectoryInferred` entries when no concrete directory fact exists.
  When the same address appears as both a concrete directory fact
  (`Directory` or `DirectoryMarker`) and an inferred prefix, emit only
  the concrete fact; it carries metadata the inferred prefix lacks.

Plugins that cannot honor a recursive list natively (anonymous HTTP,
single-resource backends) advertise
`Capabilities::supports_recursive_list = false` AND MUST return
`Unsupported` when called with `ListOptions { recursive: true, .. }`.
The host forwards `recursive = true` to the plugin verbatim today —
silently dropping it would hand callers a one-level enumeration in
place of the full subtree they asked for.

### `WriteStep` and redirect shape

```text
pub enum WriteStep {
    Done(WriteResult),
    Redirects(WriteRedirectBatch),
}
```

`ReadResult::Redirect` and per-batch write redirects share the
fields below. The host (library or broker) is a generic HTTP
follower over them: it executes `request`, slices the body per
`body_source`, parses response headers per `response_parsing`, and
(for writes) extracts only the headers listed in
`result_capture.headers` and at most `body_max_bytes` of the
response body. **Plugins are the only component that has to know
S3, GCS, Azure, etc. exist.**

```text
pub struct HttpRequest {
    pub method:  String,
    pub url:     String,
    pub headers: Vec<(String, String)>,
}

pub struct ResponseParsing {
    pub etag_header:               Option<String>,      // default "etag"
    pub version_header:            Option<String>,      // e.g. "x-amz-version-id", "x-ms-version-id", "x-goog-generation"
    pub size_header:               Option<String>,      // default "content-length"
    pub mtime_header:              Option<String>,      // default "last-modified"
    pub mtime_format:              MtimeFormat,         // RFC 1123 (default), ISO-8601, Unix-seconds
    pub system_metadata_headers:   Vec<String>,
    pub content_checksum_header:   Option<String>,
    pub content_checksum_algorithm: Option<ChecksumAlgorithm>,
    pub checksum_headers:          HashMap<ChecksumAlgorithm, String>,
}

pub struct RedirectScope {
    pub physical_url_prefix: String,
    pub operations:          AccessOps,
    pub expires_at:          SystemTime,
}

pub struct ReadRedirect {
    pub request:          HttpRequest,
    pub response_parsing: ResponseParsing,
    pub expires_at:       SystemTime,
    pub scope:            RedirectScope,
    pub audit_id:         String,
    pub policy_epoch:     u64,
}

pub struct WriteRedirect {
    pub request:        HttpRequest,
    pub body_source:    RedirectBodySource,
    pub result_capture: ResultCapture,
    pub expires_at:     SystemTime,
    pub scope:          RedirectScope,
    pub audit_id:       String,
    pub policy_epoch:   u64,
}

pub enum RedirectBodySource {
    Empty,                                 // no request body
    UserBytes { offset: u64, len: u64 },   // bytes from the application's write stream, sliced
    Inline(Vec<u8>),                       // bytes the plugin supplied (e.g. a multipart Complete XML body)
}

pub struct ResultCapture {
    pub headers:        Vec<String>,       // headers to forward back
    pub body_max_bytes: u32,               // default 4096
}

pub struct RedirectResult {
    pub status_code:      u16,
    pub captured_headers: Vec<(String, String)>,
    pub captured_body:    Vec<u8>,         // bounded by ResultCapture.body_max_bytes
}

pub struct WriteRedirectBatch {
    pub continuation: Vec<u8>,             // opaque, plugin-owned continuation echoed back to continue_write
    pub redirects:    Vec<WriteRedirect>,
}

pub struct RedirectResultBatch {
    pub results: Vec<RedirectResult>,
}
```

A simple S3 PUT collapses into two SPI calls: `write` returns
`Redirects { state, [put_request] }`, the host runs the request,
calls `continue_write(state, [response])`, and the plugin returns
`Done(result)`. An S3 multipart upload of N parts collapses into
four: `write` returns `Redirects { state, [initiate] }`;
`continue_write` returns `Redirects { state', [upload_part_1, ..., upload_part_N] }`
after parsing the `UploadId`; `continue_write` again returns
`Redirects { state'', [complete] }` after collecting part ETags;
`continue_write` finally returns `Done(result)`. Plugins that can't
redirect (`file`, an SCM plugin) handle their write internally and
return `Done(result)` directly from `write`; they never implement
`continue_write` meaningfully.

Reads stay one SPI call. `read` returns `ReadResult` directly; the
host inspects the variant and acts. There is no `continue_read`.

`list_versions` makes no order guarantee. Plugins return
version-pinned `ObjectInfo` values in whatever order their backend's
native list API produces. `supports_version_listing` gates the
operation; `version_list_order` advertises what the backend natively
does (`Newest`, `Oldest`, or `Unordered`).

**`watch_directory` SPI.** Plugins translate native feeds into a single shape:

```text
pub enum BackendChangeEvent {
    Object {
        address:      Url,
        kind:         ChangeKind,
        etag:         Option<String>,
        at:           SystemTime,
        cursor:       WatchDirectoryCursor,
    },
    Lapsed { since: Option<SystemTime>, cursor: WatchDirectoryCursor },
}
```

Backends without a native feed leave `supports_watch_directory = false`;
the SPI does not include a polling mode (callers can drive `list`
themselves on whatever cadence they choose). Plugins are responsible
for translating native gap conditions into `Lapsed`: a plugin that
can't distinguish "everything fine" from "we dropped events" is
required to emit `Lapsed` defensively on every reconnect.

### Address projection

For SPI calls that return object addresses, plugins return
`ObjectInfo.address` values in the resolved backend namespace they
were handed. The library, which is the only component that knows
about routes and aliases, projects those addresses back into the
caller's namespace before returning them publicly. Projection is a
prefix replacement, not display-label generation: callers derive
labels from parent and child addresses with `parent_and_name` or
equivalent URL parsing.

- **`list`** — each returned `ObjectInfo.address` must be inside the
  requested resolved prefix. The library replaces that prefix with
  the caller's request prefix and leaves the rest of the address
  intact.
- **List-backed `stat`** — when a route sets `wants_list_backed_stat`
  and the host uses `Backend::list` to satisfy an object `stat`, it
  reuses only returned `ObjectInfo` values whose `kind.is_file()`.
- **`list_versions`** — each returned `ObjectInfo.address` is the full
  version-pinned backend address for that version. The library
  projects only the route prefix; the version pin remains part of the
  address.
- **`watch_directory`** — each `BackendChangeEvent::Object` carries a
  full backend address in the watched resolved prefix and is projected
  the same way as `list`.

If a plugin returns an address outside the requested resolved prefix
for any projected result, the host treats it as `Internal`: the
backend violated the SPI contract.

`address_roots` and `watch_address_roots` are **not** differential.
They return absolute addresses, not route-prefix-relative fragments.

## C-ABI surface

From the library's perspective there is one plugin transport: a
dynamically loaded shared library (`.so` / `.dylib` / `.dll`) opened
through `libloading`. Every plugin binary exports two C-ABI symbols:

- `ovstorage_plugin_manifest_v1` — a `static PluginManifestV1`
  describing the plugin (`struct_size: usize`, `abi_version: u32`,
  NUL-terminated `name` and `version` pointers, `test_only: bool`).
  There is no `plugin_kind` field on the manifest; storage vs. authz
  is disambiguated by cdylib filename prefix and by which symbols
  the loader resolves.
- `ovstorage_plugin_init_v1` — the binary init function. It receives
  a `*const HostCallbacks` and returns
  `BackendPluginInitResultV1 { struct_size, abi_version, min_supported_abi_version, max_supported_abi_version, plugin_state, factory_vtable }`.
  The `factory_vtable` field points at the populated factory-level
  vtable inside the plugin's binary; the host borrows the pointer
  for the cdylib's lifetime.

The factory-level vtable shape is `BackendFactoryVTableV1`: `drop`,
`descriptor`, `probe`, `instantiate`, `update_credentials`,
`authenticate`. `instantiate` hands back a `BackendInstance`
carrying the route's `Capabilities` as a value field; the
`backend.vtable` points at `BackendVTableV1` (one slot per `Backend`
trait method).

**Async callback `status` convention.** Every async vtable method's
`on_complete` callback receives `(status: i32, result, error, user_data)`.
`status == FFI_STATUS_OK` (`0`) is reserved exclusively for success;
every error path returns `FFI_STATUS_ERR` (`-1`). The real
`ErrorCode` lives on the heap-allocated `*mut Error` pointer the
callback receives, never in the integer status word. Outcome
dispatch is pointer-presence based: `error == NULL` is success;
`error != NULL` is failure.

**`*_free` ownership.** The C ABI exposes two distinct allocation
patterns and each `ovstorage_plugin_*_free` export honours exactly
one of them — calling the wrong one is undefined behaviour:

1. **Callback-delivered (heap)** — the plugin's thunk
   `Box::into_raw(Box::new(...))`'s the value and the host receives
   a `*mut T` that *owns* a `Layout::new::<T>` allocation. The
   matching `_free` reclaims it via `Box::from_raw`.
2. **Caller-owned (in-place clear)** — the value lives in storage
   the caller already owns. The matching `_free` does
   `std::ptr::drop_in_place(value)` so nested allocations are
   released without trying to free the outer slot.

Plugin and manifest live in the same binary by construction; there
is no separate file to drift, lose, or forge.

## Ownership and lifetime invariants

- Manifest memory is static and immutable for the lifetime of the
  loaded binary. The host never frees it.
- Plugin, factory, backend, stream, future, `LocalDelegate`, and
  error handles are opaque. Whoever creates an owned handle also
  exports the destructor for that handle.
- No borrowed pointer, slice, string, header map, options struct,
  or callback reference may be retained after the vtable call
  returns unless the ABI field is explicitly an owned handle.
- `Backend` methods take `&self` semantically and may be called
  concurrently by the host. Plugins must protect non-thread-safe
  SDK clients, refresh-token state, multipart upload maps, and
  native handles internally.
- `Capabilities` are immutable for the lifetime of a `Backend`
  instance.
- `WriteRedirectBatch.continuation` is an opaque, plugin-owned
  continuation blob. The host echoes it byte-for-byte to
  `continue_write`, may persist it only for the lifetime of the
  in-flight operation, and must not inspect or log it.
- A `LocalDelegate` path is meaningful only on the host that
  received it from the plugin or cache. The plugin must not delete
  or mutate the delegated file while the lease is alive.
- Plugin unload is reverse-topology: all in-flight calls and
  returned streams/delegates must be dropped before backend
  destruction; all backends before factories; all factories before
  plugin-state destruction; plugin-state destruction before the
  shared library is closed.

## Capability vocabulary

`Capabilities` is application-facing, returned by
`Library::capabilities_for(prefix)`. It describes what the *caller*
can do against the route covering `prefix`: in Direct mode it
reflects the plugin's own behavior; in Brokered mode the broker may
strip operations its policy forbids. Capabilities are per route —
each `BackendInstance` returned from `Factory::instantiate` carries
one `capabilities` value, and dynamic-roots plugins push deltas
through `watch_address_roots` (`AddressRoot.capabilities`). The host
stores the value on the `Route` and gates dispatch on it.

The bits, stable across the project:

**Concurrency**
- `supports_if_match_write` (writes honor `IfDestExists::MatchEtag(etag)` — real CAS, not best-effort)
- `supports_no_overwrite_write` (writes honor `IfDestExists::Fail`)

**Metadata**
- `supports_native_metadata_patch` (backend can patch `UserMetadata` without rewriting bytes — GCS, Azure, local FS, Perforce)
- `supports_metadata_rewrite_emulation` (backend can emulate metadata patch by full object rewrite — S3, where modifying `x-amz-meta-*` requires `CopyObject`-onto-self)

**Write**
- `writes_are_atomic` (an overwrite is all-or-nothing from the reader's perspective; partial writes are never visible)
- `supports_server_side_copy` (the backend can execute `Backend::copy` without the host streaming bytes through itself)

**Naming**
- `supports_server_side_rename` (the backend can execute `Backend::rename` as a backend operation)
- `supports_atomic_rename` (cross-prefix `rename` is atomic and crash-safe)
- `has_real_directories` (the backend has actual directory inodes that exist independently of contained objects)

**Listing**
- `supports_list` (the backend can serve `ListOptions { recursive: false, .. }`)
- `wants_list_backed_stat` (the host may use one-level `list` as an object-`stat` accelerator on this route)
- `supports_recursive_list` (the backend can serve `ListOptions { recursive: true, .. }`)
- `populates_subdirectory_metadata` (whether directory-kind `ObjectInfo` metadata fields ever carry useful data on this route)

**Address roots**
- `address_roots_are_dynamic` (the plugin's `address_roots` answer can change between calls and the plugin implements `watch_address_roots` meaningfully)

**Versions**
- `supports_version_listing` (the backend can serve `list_versions`)
- `version_list_order: Option<VersionListOrder>` (advertises native order: `Some(Newest)`, `Some(Oldest)`, or `Some(Unordered)`)

**Permissions**
- `populates_effective_permissions_on_stat` (whether `ObjectInfo.effective_permissions` is ever `Some` on this route)
- `supports_access_check` (whether `check_access` answers)

**Watches**
- `supports_watch_directory` (the plugin implements `watch_directory` non-trivially)
- `watch_directory_kinds: ChangeKindSet` (which `ChangeKind` variants the backend's feed can distinguish)
- `watch_directory_resumable` (whether the plugin honors `WatchDirectoryOptions.since`)
- `watch_directory_max_lag: Option<Duration>` (advisory upper bound on event lag the plugin expects under normal conditions)

**Redirect dispatch**
- `redirect_size_threshold: Option<u64>` — smallest size at which `write_redirect` is worth calling. `None` means "always try `write_redirect` first" (the host's optimistic default; honors plugin-side `Unsupported` degrade).

**Kind-level (on `StorageBackendKindDescriptor`, *not* on a per-connection `Capabilities` value)**
- `supports_runtime_add: bool` — the plugin's factory can be invoked from `add_connection` at runtime. Most plugins set `true`. Plugins that hook native libraries with global, non-thread-safe initialization state set `false` and can only be created from static config at process start.

The conformance suite skips a test only if the relevant capability
is absent; every skip cites the capability.

## Object information from the backend

**The dividing line: ovstorage understands a value, or it doesn't.**
Values ovstorage parses, validates, or compares against semantics
live in typed fields on `ObjectInfo`. Values ovstorage merely
shuttles between backend and application live in `SystemMetadata`,
an opaque `String → String` map whose keys are plugin-chosen and
whose semantics are entirely the backend's.

**Typed fields on `ObjectInfo`** (in addition to `address`, `kind`,
`etag`, `version`, `size`, `mtime`):

- **`checksums: ChecksumSet`** — backend-supplied content hashes.
  The plugin populates one entry per algorithm the backend actually
  returned; an algorithm that's absent means "the backend didn't
  tell us."
- **`effective_permissions: Option<EffectivePermissions>`** — what the
  calling principal is allowed to do against this specific object,
  when the backend can answer for free. **`None` and
  `Some(EffectivePermissions::empty())` mean different things:**
  `None` means the backend didn't tell us; `Some(empty)` means the
  backend told us this principal cannot perform any of these
  operations.

**Opaque values in `SystemMetadata`.** Everything backend-owned that
ovstorage does not understand. Keys are plugin-chosen; ovstorage
neither parses nor normalizes them.

## Conformance harness

The conformance harness is the in-tree controllable plugin the
workspace's conformance suite drives ABI shapes through. It is not
a production backend and not a third-party plugin TCK. It exists so
host conformance suites can exercise ABI shapes that real services
cannot produce reliably on demand: streamed reads that fail
mid-flight, redirects with exact header whitelists, multipart writes
whose final `continue_write` returns `Done`, change streams that
emit `Lapsed` and resume, auth flows that cancel.

The conformance plugin's manifest carries `test_only = true`.
Production hosts (broker binary, library outside `cargo test`) treat
`test_only = true` plugins as opt-in: `Library::load_plugin` returns
`ErrorCode::PluginRejected` against a default-posture host, and
`Library::load_plugins_from_dir` skips the cdylib at debug-log level
so the bundled conformance fixture in `<archive>/plugins/` doesn't
crash startup. See "What's not supported" below.

### Registry entry shape

Every conformance scenario has one registry entry, and the registry
is the only place where scenario behavior is declared. Each entry
carries:

- `name`: the stable string used in URLs, reports, and test filters.
- `spi_methods`: the `Backend`, `Factory`, or host-only boundary
  methods the scenario is expected to exercise.
- `required_profile` and `required_capabilities`: the capability
  profile and exact capability bits required before the test is
  meaningful.
- `required_config`: keys such as `scratch_dir`, `redirect_base_url`,
  `required_host`, or `clock = real`.
- `allowed_hosts`: `library`, `broker`, or both. Host-specific
  scenarios must say why the difference exists.
- `expected_calls`: recorder assertions, including negative
  assertions such as "must not call `update_metadata`".
- `failure_contract`: the typed error expected on the primary
  failure path, when the scenario is negative.
- `report_tags`: short tags (`redirect`, `lifetime`, `capability-skip`,
  `broker-parity`, `ffi`) so nightly reports can be grouped without
  parsing names.

Scenario names are append-only once published. If a behavior
changes incompatibly, add a new scenario name and leave the old one
as a compatibility test until the ABI revision that removes it.

## Streaming seams

Every boundary a `Body::Stream` crosses needs a regression test that
asserts the stream is forwarded chunk-by-chunk — never drained to a
buffer in the middle. Buffering at any seam is a memory-DoS vector
on the public REST gateway. **Rule:** if you add a seam, add a
`streaming_invariant` test for it.

### What the test asserts

The shared helper drives a `Body::Stream` of N≥3 chunks totaling ≥
64 MiB at 4 MiB chunk size, with a seam-specific `Recorder`
observing what crosses the boundary. The test asserts:

1. **Max in-flight bytes ≤ chunk_size × small_const.** Buffering
   would push this above 64 MiB.
2. **Chunk count preserved end-to-end.** N out → N observed.
3. **Chunks observed in order, not all-at-once.** The recorder
   timestamps each chunk; the spread must exceed a small floor.

### Inventory

Each row's "Test" column is the home of the seam-specific test that
uses the helper. Rows marked `(new)` indicate a seam where the test
has not yet been added.

| Seam                            | Test                                                                 |
|---------------------------------|----------------------------------------------------------------------|
| host ↔ FFI plugin               | extend the existing host-plugin behaviors test                       |
| host ↔ nucleus gRPC client      | nucleus transport tests (extend `connlib_test.rs`, `sows_test.rs`)   |
| broker server ↔ plugin          | broker streaming-invariant write test (new)                          |
| REST ↔ host                     | REST streaming-invariant objects test (new)                          |
| s3 plugin ↔ S3 transport        | s3 plugin streaming-invariant test (new)                             |
| gcs plugin ↔ GCS transport      | gcs plugin streaming-invariant test (new)                            |
| azure plugin ↔ Azure transport  | azure plugin streaming-invariant test (new)                          |
| opendal plugin ↔ opendal        | opendal plugin streaming-invariant test (new)                        |
| http plugin ↔ HTTP transport    | http plugin streaming-invariant test (new)                           |
| file plugin ↔ filesystem        | file plugin streaming-invariant test (new)                           |
| broker-client ↔ broker          | broker-client streaming-invariant test (new)                         |

### Deferred-streaming seams

Plugins that return `Unsupported` for `Body::Stream` writes pin the
gap with a test asserting the `Unsupported` return — pre-empting an
accidental disk-spool half-measure that would silently buffer to
disk and look like the bug returned.

### Recorder shapes per seam

- **gRPC seams** (nucleus, broker, broker-client): tonic `Service`
  layer interceptor that records the size + timestamp of each
  out-bound `Bytes` frame.
- **HTTP seams** (REST, http plugin): a hyper `Service` that wraps
  the inner with a stream-tap.
- **FFI seam** (host ↔ plugin): a mock plugin whose
  `body_stream_next_thunk` impl records call counts and chunk sizes.
- **Filesystem seam** (file plugin): poll the temp directory size at
  intervals during the stream and assert it stays well below the
  total payload size.
- **opendal**: the opendal in-memory backend exposes a stream sink
  that already records chunk arrival.

## Build and load

A plugin is a `cdylib` (`.so` / `.dylib` / `.dll`) loaded via
`dlopen`. The loader contract:

1. Open the shared object.
2. Resolve `ovstorage_plugin_manifest_v1`. Validate `struct_size`,
   the ABI-version band (the host expects
   `min_supported_abi_version <= OVSTORAGE_PLUGIN_ABI_VERSION <= max_supported_abi_version`;
   width-1 bands set both equal to the constant),
   and (when `LibraryBuilder::allow_test_plugins(false)` — the
   default) refuse `test_only = true`.
3. Resolve `ovstorage_plugin_init_v1`. Call it with the host
   callbacks pointer; the plugin returns a `BackendPluginInitResultV1`
   carrying its `factory_vtable` pointer.
4. The host stores the vtable and dispatches every subsequent SPI
   call through it.

Hosts load plugins explicitly. Passing `None` to
`Library::load_plugins_from_dir` resolves the configured
`OVSTORAGE_PLUGIN_DIR` environment variable, falling back to
`<exe_dir>/plugins/` — that's the recommended deployment shape, and
what `ovstorage::default_plugin_dir()` returns. `Library::load_plugin`
and `Library::load_plugins_from_dir(Some(dir))` are also public and
available in production builds; they're appropriate for embedded hosts
that already control which cdylibs are on disk via package management or
container image. The `test_only = true` policy still applies: direct
`load_plugin` surfaces `ErrorCode::PluginRejected` against a default-
posture host, and `load_plugins_from_dir` skips the cdylib at debug-
log level. Opting in requires `LibraryBuilder::allow_test_plugins
(true)`, which is gated by callers.

A minimum viable Rust plugin is two files. The `Cargo.toml`:

```toml
[package]
name    = "my-storage-plugin"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
ovstorage-plugin = "0.1"
async-trait      = "0.1"
tokio-util       = { version = "0.7", default-features = false }
```

And `src/lib.rs`:

```rust
use async_trait::async_trait;
use ovstorage_plugin::shim::{BackendInstance, Factory};
use ovstorage_plugin::types::StorageBackendKindDescriptor;
use ovstorage_plugin::{address, Capabilities, ConnectionRequest, Error,
    ErrorCode, Result, Url};
use ovstorage_plugin::ovstorage_plugin;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct MyFactory;

#[async_trait]
impl Factory for MyFactory {
    fn descriptor(&self) -> StorageBackendKindDescriptor {
        StorageBackendKindDescriptor {
            kind: "my-backend".into(),
            display_name: "My Backend".into(),
            description: None,
            config_schema: vec![],
            credential_schema: vec![],
            capabilities: Capabilities::empty(),
            icon: None,
            supports_runtime_add: false,
        }
    }

    async fn instantiate(
        &self,
        _request: &ConnectionRequest,
        _cancel: Option<CancellationToken>,
    ) -> Result<BackendInstance> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "my-backend factory is a stub",
        ))
    }
}

ovstorage_plugin!(MyFactory::default);
```

`cargo build --release` produces `target/release/libmy_storage_plugin.so`
(or `.dylib` / `.dll`); copy it under the plugin dir and the loader
picks it up.

## Plugin macros

Rust plugin authors get the manifest and init exports from a single
function-like proc macro:

```text
ovstorage_plugin!(MyFactory::default);
ovstorage_plugin!(MyFactory::default, test_only);
```

Argument shape: a constructor expression `fn() -> F` where
`F: Factory`. The macro invokes the constructor once at load time,
boxes the result into a `Box<dyn Factory>`, leaks it, and stores
the leaked pointer in `BackendPluginInitResultV1::plugin_state`.
The host releases the factory via `FACTORY_VTABLE.drop` before
unloading the plugin.

The optional trailing `, test_only` flag flips the manifest's
`test_only` bit. Production hosts configured with
`allow_test_plugins = false` refuse to load such plugins.
`Library::load_plugin` (direct, by-path) returns
`ErrorCode::PluginRejected`; `Library::load_plugins_from_dir` (bulk
discovery used by the broker and REST gateway) silently skips the
plugin at debug-log level and continues the scan, so a release
archive that ships a test plugin alongside production plugins still
starts cleanly against a default-posture host. Any other token after
the comma is a compile error so misspelled flags don't slip through
silently.

The plugin's name and version come from `CARGO_PKG_NAME` /
`CARGO_PKG_VERSION` at the macro-expansion site (the plugin's own
`Cargo.toml`); the macro reads these via `std::env::var` during
expansion.

### Generated symbols

The expansion declares two exports:

- `ovstorage_plugin_manifest_v1`: `PluginManifestV1` static carrying
  `struct_size`, the compile-time `OVSTORAGE_PLUGIN_ABI_VERSION`
  constant, NUL-terminated `name` / `version` pointers, and the
  `test_only` flag.
- `ovstorage_plugin_init_v1`:
  `unsafe extern "C" fn(*const HostCallbacks) -> BackendPluginInitResultV1`.
  The thunk calls `ovstorage_plugin::shim::register_host(host)`
  first so per-method dispatch can recover the host callbacks via
  `shim::host()`, then invokes the factory constructor and returns
  a `BackendPluginInitResultV1` whose `factory_vtable` points to
  the static `ovstorage_plugin::thunks::FACTORY_VTABLE`.

Both exports use `#[unsafe(no_mangle)]` (Rust 2024 spelling) to
keep the symbol names exactly what the host loader expects.

### Banded ABI handshake

The generated `BackendPluginInitResultV1` carries `struct_size: usize`,
`abi_version: u32`, `min_supported_abi_version: u32`,
`max_supported_abi_version: u32`, `plugin_state: *mut c_void`, and
`factory_vtable: *const BackendFactoryVTableV1`. The macro sets
`abi_version == min_supported_abi_version == max_supported_abi_version == OVSTORAGE_PLUGIN_ABI_VERSION`
because every 0.x plugin is compiled against exactly one ABI version.

Authz plugins hand-write their own manifest + init exports against
the authz SPI, reusing the shared FFI primitives re-exported from
`ovstorage_plugin::ffi`.

### Panic safety

The generated `ovstorage_plugin_init_v1` rides on the workspace's
`panic = "abort"` profile pinned for both `dev` and `release`. A
panic in the plugin author's factory constructor aborts the process
before any frame unwinds, so the macro deliberately does not wrap
the init body in `catch_unwind`. The `catch_unwind` walls in
`ovstorage_plugin::thunks` around per-method async dispatch are
defense in depth for downstream consumers that override the profile
to `panic = "unwind"`.

## ABI roadmap

Pre-1.0, every plugin's banded handshake reports a width-1 band
(`min == max == OVSTORAGE_PLUGIN_ABI_VERSION`). The host validates
equality on load. At 1.0 the band widens: a host built against ABI
version `N` will accept a plugin reporting `min <= N <= max`, and the
release-notes / `OVSTORAGE_PLUGIN_ABI_VERSION` constant in
`ovstorage-plugin` is the source of truth for what value to compile
against. Until then, plugin authors learn the value by depending on
`ovstorage-plugin`'s exported `OVSTORAGE_PLUGIN_ABI_VERSION` constant
(the macro fills it in automatically); a host running a different
ABI fails the load with `IncompatibleType`.

## ABI-stability rules

The plugin C ABI freezes at 1.0; once shipped, breakage is a 2.0.
Three layered defenses authors must understand:

- **`struct_size` handshake on every options struct.** Every public
  V1 options struct (read, write, list, stat, etc.) carries
  `size_t struct_size` as its first field. The callee validates
  `struct_size >= sizeof(known_minimum)` before reading any tail
  field; an undersized struct returns `InvalidArgument` rather than
  reading uninitialized memory. Newer callers passing a larger size
  remain compatible because the callee ignores fields past its
  known maximum.
- **Reserved padding on options structs and vtables.** Every public
  options struct ends with `_reserved: ReservedOptionsPadding` (8
  zero-initialized `void*` slots). Backend and factory vtables end
  with 16 zero-initialized reserved-fn slots. Additive growth
  consumes the next free slot in tree order; existing fields never
  reorder.
- **Banded ABI handshake.** The `BackendPluginInitResultV1` carries
  `min_supported_abi_version` and `max_supported_abi_version`.
  While pre-1.0, both equal `OVSTORAGE_PLUGIN_ABI_VERSION` — a single
  point, not a band.

## What's not supported

- **`test_only = true` plugins are host-gated, not package-gated.**
  `LibraryBuilder::allow_test_plugins(true)` is the opt-in; a
  default-posture host (broker / library binary that hasn't called
  it) treats a `test_only` cdylib as unloadable. `load_plugin` (direct,
  by-path) surfaces `ErrorCode::PluginRejected`;
  `load_plugins_from_dir` skips the cdylib silently at debug-log
  level. The release archive ships the conformance plugin under
  `<archive>/plugins/` so downstream host authors can opt in to it for
  testing; default-posture deployments scan the same directory
  without disruption.
- **No plugin sandboxing.** Plugins run in-process with the host's
  privileges. There is no seccomp filter, no namespace isolation,
  no capability dropping. Operators who need plugin isolation must
  run the plugin behind a separate process.
- **No plugin hot-reload.** Loaded plugins live for the host
  process's lifetime. Replacing a `.so` requires restarting the
  host.
