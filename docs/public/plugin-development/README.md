# Plugin development — shared foundation

> "I'm writing an ovstorage plugin and want to know how the ABI works
> and how to test my plugin."

This directory is the entry point for plugin authors. The active
overlay is `plugin-storage`. This README is the canonical reference for
the foreign interface every plugin crosses, the Layer contract every plugin
implements, the type vocabulary every plugin speaks in, the conformance
harness every plugin is tested against, the build-and-load loop every
plugin runs through, and the ABI-stability rules every plugin commits
to at 1.0.

**Where to read first.** The single most useful starting point for a
new storage-backend author is
[`../plugin-storage/CONFORMANCE.md`](../plugin-storage/CONFORMANCE.md) —
the cross-cutting behavioral contract for every storage Layer method
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
ownership rules, and the `catch_unwind` panic-discipline contract
live in [library-cpp](../library-cpp/README.md).
(`catch_unwind` is the Rust standard-library guard wrapping every FFI
entry point; it converts a panic into a typed `Result`
(`Status::Internal`) before it can unwind across the C ABI. The
workspace keeps the default `panic = "unwind"` so those walls can
catch — together they keep a panicking plugin from corrupting the
host's runtime state.)

The C ABI is the ABI stability layer, not a hand-authoring target.
Authors write plugins in Rust (or C++ / Python wrappers as those
mature). Hand-written-C plugin authoring is out of scope; the C
surface is designed for stability and correctness, not C-only
ergonomics.

For C ABI implementors, the typed `AUTH_CREDENTIAL` decoder is plugin support
code, not a host callback or a process-global host export. A C auth wrapper
compiles `auth_credential.c`, `plugin_values.c`, `plat.c`, and `utf8.c` from the
shipped source distribution into its own cdylib, so
`ovstorage_plugin_auth_credential_decode` and `_free` bind within the plugin.
Rust plugins receive the same helper implementation by linking the
`ovstorage-plugin` crate. ABI-v15 exact matching keeps the helper's wire and
value layouts aligned with the loading host.

## Layer shape — vtables, manifest, init

Plugin loading is a two-symbol handshake. The host opens the cdylib,
validates the `ovstorage_plugin_manifest_v1` static, then calls
`ovstorage_plugin_init_v1(host_callbacks)`. The `_v1` in those symbol
names is frozen and does not track the Layer ABI version; the manifest
carries that version. Init
returns `PluginInitResultV1`, which owns plugin-scoped state, a
`PluginVTableV1`, and the descriptors for every Layer kind in the
binary. Stack construction calls the matching `create_backend`,
`create_wrapper`, or `create_router` slot and receives a `LayerHandle`.
Every handle uses the uniform `LayerVTableV1` operational surface.

The full Layer shape — Rust `Layer` and factory traits, request envelopes,
the `Capabilities` bitset, `ReadResult` / `WriteStep`, the manifest,
and C-ABI ownership rules — is reproduced below.

## Surface boundary — host APIs vs plugin Layer

The plugin Layer ABI is not the public `Stack` convenience API. It pins the
contract between a host process and a loaded Layer plugin.

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
- **`Layer` methods** are what plugins implement. The Rust trait is
  `#[async_trait]`; object and connection operations receive a typed
  `Request<T>` plus `cancel: Option<CancellationToken>`. Synchronous
  introspection covers `root_info_for`, `list_kinds`,
  `list_address_roots`, and `list_connections`. Capabilities flow in
  `RootInfo`, not through a separate backend-instance object.

**A directory-facing Layer method receives the address the caller wrote,
and must derive its own directory key.** `Layer::create_directory`,
`Layer::delete_directory`, `Layer::list` and `Layer::watch_directory` do
*not* get a trailing slash added for them. `docs` and `docs/` name one
node and every host-side comparison knows that, but on a flat namespace
they may be two distinct objects — so choosing a spelling for you would
be choosing which object a `delete_directory` destroys. Use
`address::directory_key` on the decoded key; a backend that lists on the
key verbatim returns the contents of `docsx` for a listing of `docs`,
which is a disclosure and cannot be undone. Public `stat` is input-guided, but the host may answer an
unversioned exact-object `stat` from a cached or freshly fetched
one-level parent `Layer::list` entry when the route supports
one-level list and sets `wants_list_backed_stat`. If that
list-backed path is unavailable or does not contain the object,
`stat("foo")` dispatches `Layer::stat` for exact `foo`, and only
if that returns `NotFound` does the host issue `Layer::stat` for
`foo/`; `stat("foo/")` arrives only as `Layer::stat` for `foo/`.
Permission/auth errors from the attempted spelling are final.
Plugins should not implement a second trailing-slash policy of
their own.

**Factory traits** construct the three composition shapes.
`BackendFactory::create_backend` has no child,
`WrapperFactory::create_wrapper` receives one owned inner handle, and
`RouterFactory::create_router` receives owned children. Connection
lifecycle is part of `Layer`, so wrappers can participate uniformly.

This split is load-bearing for the "same plugin binary in library
and broker" rule: the plugin exposes one Layer contract; each host decides how
that contract maps onto its public surface.

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
    Fail,                // refuse if the destination exists (AlreadyExists)
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

pub struct DeleteDirectoryOptions;                      // unit struct; the Layer's directory-delete
                                                       //   removes only the directory representation.

pub struct WatchDirectoryOptions {
    pub recursive:                bool,                 // default false
    pub include_metadata_changes: bool,                 // default true
    pub since:                    Option<WatchDirectoryCursor>,
    pub poll_interval:            Duration,             // default 1s
}
```

#### Enforcement contract

Plugins MUST enforce the options they receive. Most options pass through
verbatim. Watch options are the exception when a competing-consumer backend
self-coalesces via the SDK `WatchCoalescer`: it opens one recursive,
metadata-inclusive physical watch and post-filters that superset for each
logical subscriber. Therefore a recursive watch MUST include every event
that the same backend would emit for the corresponding non-recursive watch, and
a metadata-inclusive watch MUST include every event that it would emit with
metadata changes excluded. A backend must not replace direct-child events with
different directory-rollup events when recursion is enabled.

| Field | Op | Plugin contract |
|---|---|---|
| `if_match` | read / delete / update_metadata | If `Some(etag)`, only operate on bytes that match the caller's opaque etag token for that same address. The etag is opaque to the Layer — its internal structure is the plugin's choice. The `file` plugin synthesizes `"size:N,mtime:Tms"`; cloud plugins use the backend-supplied ETag or equivalent validator; the Omniverse Storage Service uses `ResourceIdentity.encoded_identity`. Version IDs/generations stay in `ObjectInfo.version` and version-pinned addresses, not in precondition fields. For reads, prefer a server-side precondition (HTTP `If-Match`, an etag-keyed/identity-keyed read RPC); when the wire doesn't carry one, fetch metadata and compare client-side. |
| `if_source` | copy / rename | If `Some(etag)`, only copy or rename source bytes matching the caller's opaque etag token for that same source address. Maps to backend source-side conditional headers or identity slots (S3 `x-amz-copy-source-if-match`, Azure `x-ms-source-if-match`, GCS `ifSourceGenerationMatch`, Storage API `source_resource_identity`). |
| `if_dest` | write / copy / rename | `IfDestExists::Overwrite` replaces any existing destination. `IfDestExists::Fail` refuses when the destination exists; plugins that advertise `Capabilities.supports_no_overwrite_write = true` MUST honor this with `AlreadyExists`, others MUST return `Unsupported`. `IfDestExists::MatchEtag(etag)` refuses unless the destination's current etag matches; plugins that advertise `Capabilities.supports_if_match_write = true` MUST honor this, others MUST return `Unsupported`. The host does not pre-check. |
| `range` (read) | read | Plugin MUST apply the range. For `ReadResult::Stream` and `ReadResult::Bytes`, slice the bytes the plugin is producing. For `ReadResult::Redirect`, the host injects `Range:` headers on the redirect request before following — plugins return the redirect unchanged. For `ReadResult::LocalDelegate`, the host handles the slice. |
| `max_bytes` (read) | read | Host-side cap on buffered read size. Plugins MAY ignore it; the host applies it to the returned stream/bytes. |
| `size_hint` (write) | write | Hint for routing decisions (e.g., inline vs. multipart). Not a contract; backends may treat it as advisory. |
| `user_metadata` (write / update_metadata) | mutating | Plugin MUST persist if its backend supports user metadata, and MUST reject a non-empty map with `Unsupported` when its backend cannot store one — never report success having dropped it, or a caller's `--metadata foo=bar` disappears without notice. Where support is a per-connection property (the OpenDAL adapter's driver capability), decide per call rather than per plugin. If your backend records metadata out of band, after the object commits, that is a second durability stage and CONFORMANCE's *Publish-before-durable* → *Multi-stage durability* governs it: surface a failure of that stage even though the bytes have landed, so the caller knows to re-issue the patch. The built-in `file` backend surfaces such a failure from its user-metadata sidecar; the Omniverse storage service client discards them, and its page records that deviation. See CONFORMANCE, `write, write_stream, write_redirect, continue_write` → *Edge cases*, and *Publish-before-durable*. |
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

`Layer::delete_directory` removes only the backend's directory
representation: a real directory must be empty, and a
flat-object-store marker removal leaves children untouched. The Layer
contract does not expose a recursive subtree-delete.

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

`ChangeKind` is shared between the Layer's `BackendChangeEvent`
and the public `ChangeEvent`.

### Connection-management types

```text
pub struct ConnectionId(pub String);

pub struct StorageBackendKindDescriptor {
    pub kind:                   String,
    pub display_name:           String,
    pub description:            Option<String>,
    pub config_schema:          Vec<ConfigField>,
    pub credential_schema:      Vec<CredentialField>,
    pub capabilities:           Capabilities,
    pub icon:                   Option<Vec<u8>>,
    pub supports_runtime_add:   bool,
    pub supports_user_metadata: bool,
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
/// may attempt. Set by the host; threaded into
/// `Layer::authenticate_connection` so the plugin picks the right OAuth subflow
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

`Layer::authenticate_connection` carries the capability in its request:

```text
async fn authenticate_connection(
    &self,
    request: Request<AuthenticateRequest>,
    cancel: Option<CancellationToken>,
) -> Result<AuthEventStream>;
```

Plugin behavior matrix:

| Capability | OAuth-IDP plugins | Long-flow plugins | Anonymous / non-interactive |
|---|---|---|---|
| `None`     | `Err(AuthRequired)` immediately, no events | `Err(AuthRequired)` immediately | `Err(Unsupported)` immediately |
| `Headless` | Device flow (RFC 8628) | URL+nonce-poll (works since the user can open the URL on any device) | `Err(Unsupported)` immediately |
| `Browser`  | PKCE (or device fallback if the IDP advertises only device) | URL+nonce-poll | `Err(Unsupported)` immediately |

The last column is capability-independent because the capability describes what
the *host* can drive, and these backends have nothing to drive under any of
them: their credentials arrive with the connection. `Unsupported` is the code
`Layer::authenticate_connection` documents for it, and because the error is
raised before any event stream exists, the connection's state is untouched — a
connection parked by a refused credential stays parked rather than being
reported `Authenticated` on no grant and no probe. In-tree, `azure`, `gcs`,
`s3` and `opendal` answer it from their connection-auth drivers, as does the
broker client for its direct-endpoint addresses — anything that is not
`http(s)://`, so `grpc://`, `grpc+tcp://`, `grpc+tls://`, `unix:/…` and
`npipe:/…` —
which have no OAuth surface and take whatever credential bring-up resolved. A
layer with no connection-auth driver at all — `file`, `http` — answers it from
the `Layer` leaf default, which is the same code.

Answer this column **before** any capability check. Whether a backend has an
interactive flow is a property of the backend, not of what the host can drive,
and the two codes mean different things to a caller: `Unsupported` says no flow
was ever offered, so nothing ran and the registration stands, while
`AuthRequired` is an ordinary failure of a flow that does exist. What a host
does with that is its own policy — `ovstorage connect` keeps the connection and
reports its state, while `ovstorage reauth`, whose whole purpose was to run a
flow, reports the refusal.

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
the path to a child process. No bytes flow through the `Stack`
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
  never to disk in plaintext, never to logs. The channel's own transport
  authentication is the broker listener's `authn_mode`; this bullet makes
  no additional mTLS guarantee.
- Crosses the C ABI as `ffi::SecretBytes`. The two live on different
  heaps — an ABI buffer on the shared process heap (see
  [Allocator contract](#allocator-contract)), a `Vec` on the Rust
  global allocator — so a secret is copied across rather than adopted
  in place, in both directions. Each copy erases its own source:
  `ffi::SecretBytes` zeroizes on drop, and
  `marshal::descriptor::secret_bytes_to_ffi` zeroizes the `Vec` it
  consumed. Do not "optimize" either direction back into an in-place
  adoption (`Vec::from_raw_parts` over an ABI buffer, or leaking a
  `Vec` into one): that hands one allocator's block to the other and
  is the corruption the allocator contract exists to prevent.

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

**Policy retry** has one owner because backoff composes badly. Two layers each
retrying on independently-tuned schedules multiply their attempt counts rather
than adding them, and neither can report the true total — so the bound a caller
was promised and the numbers an operator reads both stop being true. Keeping it
in one place is what makes a total bound expressible at all, and it is why
policy retry is a composed Layer rather than something each plugin implements.

Two other kinds of re-attempt are not that, and are not forbidden by it. A
protocol may require an indivisible internal retry for one operation to complete
safely, as above. And the plugin SDK's `ConnectionSet::with_recovery` runs a
bounded **credential recovery**. That one is the plugin's to drive, not the
host's: you wrap a call in `connection_set.with_recovery(&id, || ...)`, and if
it fails with a driver-classified recoverable credential error the connection is
refreshed and the call replayed exactly once before the error surfaces — so a
`stat` or `read` can be attempted twice without any policy Layer being involved.
The replay is not guaranteed by routing alone: it happens only if the recovery
step decides to retry, and a driver whose credentials are static keeps `refresh`
at its `Unsupported` default, so that attempt normally surfaces the error
instead. Write the closure so that a second call is *safe*, not so that a second
call is certain.

It covers only what you route through it, and the criterion for routing
something through it is **replayability**, because the closure may run a second
time. The first-party Layers that own a `ConnectionSet` therefore keep `write`,
`write_stream` and `write_redirect` out of it: the body is consumed by the first
attempt, or the mutation spans rounds this call does not own. `continue_write`
is the judgement call — it carries no body of its own, so a Layer whose
finalization is keyed by a server-side identifier can route it through recovery,
and one does. A credential error from an op you left outside surfaces with no
refresh and no replay. Neither re-attempt is a tunable backoff schedule, which
is the thing that must not be duplicated.

## Connection lifecycle errors

Connection-management methods (`add_connection`, `remove_connection`,
`update_connection_credentials`, `authenticate_connection`) report errors as the same flat
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

**An address names a node, and the address a plugin receives has already
been normalized.** Canonicalization runs at parse time and again at the
`Stack` boundary, so every layer and every plugin sees one spelling of a
given object.

### What canonicalization does to the path

The path is percent-decoded to bytes, dot segments are resolved, runs of
`/` are collapsed to one, the fragment is dropped, and the result is
re-encoded so that no byte can be decoded a second time. A `%2F`
therefore *becomes* a separator, which is what lets a dot segment hiding
behind one resolve.

**The trailing slash is never touched, in either direction.** `x` and
`x/` name the same node, and every site that compares two addresses
knows that; but on a flat store they may be two distinct objects, so the
spelling a caller wrote survives to the backend.

Elsewhere in the URL: the scheme is lowercased, the host is lowercased
and IDN-punycoded, default ports are stripped, and an empty-authority
path gains its `/`.

### Keys that are not expressible as a URI path

A backend key containing a dot segment, a doubled separator, or a
literal `/` inside a segment cannot be named by an address: any address
built for it re-derives to a *different* key. Such an object is
**unaddressable**, and the host's emitter drops it from a listing with a
`warn!` rather than handing out an address that names something else.
Invisible is the deliberate choice — the alternative is a `delete` of
the address `list` just returned destroying the wrong object.

**Key segments are canonicalized rather than preserved byte-for-byte**
— escapes are decoded, normalized and re-encoded once. So
`s3://b/pub%20x` names the key `pub x`, and a key that literally
contains the three characters `%20` is named by escaping the escape:
`s3://b/pub%2520x`.

### The plugin emitter obligation

**A plugin that turns a backend key into an address must escape the key,
and must drop any key whose emitted address does not re-derive to it.**
The host cannot check this for you: the original key never crosses the
ABI, so there is nothing to compare against. `address::join_relative`
(and `join_relative_bytes`, for a key that is not valid UTF-8) does both
halves — it escapes `%` and refuses a key that is not addressable — so
call it rather than building the address by hand, and skip the entry
with a `warn!` when it refuses.

The conformance suite asserts this obligation. See `### Address
projection` and `## Conformance harness` below.

**The host refuses an address whose own spelling the URL parser
rewrites.** A returned address is the plugin's claim about which object
it named, so the host validates it instead of normalizing it — rewriting
a claim is retargeting. Two things can rewrite one, and both are
refused: the URL parser resolves `.` and `..` segments (including the
`%2e` spellings), removes ASCII TAB, LF and CR from anywhere in the
string, trims a leading or trailing space, and folds `\` to `/` on
`http`, `https`, `ws`, `wss`, `ftp` and `file`; and ovstorage's own path
canonicalization decodes escapes and collapses separator runs. So
`s3://bucket/public/../private/secret` is refused, because it names
`private/secret` while reading as a key under `public/`.

Nothing built with `join_relative` or serialized from a `Url` can hit
this: a `Url`'s serialization has its dot segments already resolved,
carries no raw TAB, LF or CR and no untrimmed edge, and carries no `\`
in the region where a special scheme would fold one. (A `\` in a query
or a fragment is untouched by the parser and is accepted, because it is
what the `Url` itself serializes to.) Only an address assembled by
string formatting can be refused, and such an address was about to name
a different object than the key it came from.

### Object keys are bytes

`address::key` returns the decoded path as bytes, because a key is an
arbitrary byte sequence and the `file:` backend resolves one byte for
byte. A backend whose wire API cannot carry those bytes calls
`address::key_utf8`, which **rejects** such a key with `InvalidArgument`
rather than converting it lossily — a lossy conversion would make the
backend fetch one object for two distinct addresses, which authorization
treats as two.

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

Every plugin's `read` Layer call returns one of four shapes. The
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

## Plugin Layer contract

The checked-in Rust Layer trait is `ovstorage_plugin::Layer`. One operational
trait covers backends, wrappers, and routers. A wrapper returns its inner
handle from `inner_layer`; default method bodies then delegate, so it
implements only the operations it intercepts. Backend and router leaves
keep the default `Unsupported` behavior for unimplemented operations.

`Layer` is `#[async_trait]`. Every asynchronous operation receives a
typed `Request<T>` (or, for the introspection queries, an `&Extensions`
fact bag) plus `cancel: Option<CancellationToken>`. Introspection splits
by cost: the three **runtime-state** queries — `root_info_for`,
`list_address_roots`, and `list_connections` — are async and cancellable,
because a connection-owning backend resolves them against live connection
state and a router fans them out across its children. The one **structural**
introspection query, `list_kinds`, is synchronous: the reachable kind
set is fixed manifest/topology metadata.

The structural methods — `name`, `descriptor`, `inner_layer`,
`owned_targets`, and `list_kinds` — are synchronous and bound by a
**no-I/O contract**: they return bounded, in-memory data and must not
perform I/O, block, spawn or enter an async runtime, or (in bindings)
touch the Python GIL. They are safe to call from any thread with no
ambient executor. The C projection is one uniform `LayerVTableV1`:
synchronous methods write caller-owned out values; asynchronous methods
invoke `on_complete` exactly once. Plugins export the surface with
`ovstorage_layer_plugin!` (see § Plugin macros).

```text
#[async_trait::async_trait]
pub trait Layer: Send + Sync {
    // Structural (synchronous, no-I/O): bounded in-memory metadata only.
    fn name(&self) -> &str;
    fn descriptor(&self) -> LayerKindDescriptor;
    fn inner_layer(&self) -> Option<&LayerHandle> { None }
    fn owned_targets(&self) -> Vec<String> { ... }
    fn list_kinds(&self, cx: &Extensions) -> Result<Vec<LayerKindDescriptor>>;

    // Runtime-state introspection (async, cancellable).
    async fn root_info_for(&self, url: &Url, cx: &Extensions, cancel: Option<CancellationToken>)
        -> Result<RootInfo>;
    async fn list_address_roots(&self, cx: &Extensions, cancel: Option<CancellationToken>)
        -> Result<(RootInfoSnapshot, Option<RootInfoUpdateStream>)>;
    async fn list_connections(&self, cx: &Extensions, cancel: Option<CancellationToken>)
        -> Result<(ConnectionSnapshot, Option<ConnectionUpdateStream>)>;

    async fn stat(&self, request: Request<StatRequest>, cancel: Option<CancellationToken>) -> Result<ObjectInfo>;
    async fn read(&self, request: Request<ReadRequest>, cancel: Option<CancellationToken>) -> Result<ReadResult>;
    async fn write(&self, request: Request<WriteRequest>, cancel: Option<CancellationToken>) -> Result<WriteResult>;
    async fn list(&self, request: Request<ListRequest>, cancel: Option<CancellationToken>) -> Result<Vec<ObjectInfo>>;
    // The remaining object and connection operations use the same envelope.
}
```

Plugin load and inspect are synchronous, local loader operations: opening a
cdylib, validating its manifest, and running its init entry point read only
in-process state and perform no backend network discovery. Discovering a
backend's live roots or connections happens later, through the async
`list_address_roots` / `list_connections` queries against a built Stack.

The complete trait in `ovstorage-layer/src/traits.rs` is authoritative.
Factories implement `descriptor()` plus exactly one creation method and
return `LayerHandle` (`Arc<dyn Layer>` in Rust). A `LayerKindDescriptor`
declares its `layer_type` and whether the kind accepts connections.

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
The host forwards `recursive = true` to the plugin verbatim rather than
filtering it out — silently dropping it would hand callers a one-level
enumeration in place of the full subtree they asked for. Implementing
recursive list, or refusing it, is therefore the plugin's obligation and
not something the host will paper over.

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

A simple S3 PUT collapses into two Layer calls: `write` returns
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

**While a write is in a redirect step, no part of the object may be
observable at the backend.** Stage the transfer somewhere a reader cannot
reach — the multipart upload id above, an uncommitted block list — and let
the object become visible only in the transition to `Done`. A caller that
abandons the write mid-flight must leave the address exactly as it was.
Hosts depend on this to keep their own derived state coherent: a mid-flight
step means the address still holds what it held before, so anything a host
computed from it remains valid. A plugin that published partial content there
would silently invalidate those derivations. (The in-tree byte cache is
additionally robust to a plugin that breaks this — it invalidates before
`continue_write` runs — but that is defence in depth, not permission.)

This is achievable only where `continue_write` performs the commit. A
single-redirect fast path — one presigned `PUT` that the caller's own request
commits — has already written the object by the time `continue_write` is
called, so there the verb reports rather than commits, and abandoning after the
`PUT` does change the address.

**Which shape you have is a property of the individual write, not of the
backend.** Several in-tree backends implement both and choose per call — by
`size_hint` against a threshold, or on whatever the remote service answers — so
"does this backend stage?" is the wrong question to ask of your own plugin. The
one to ask is: *for this write, is the commit an outbound call my
`continue_write` makes, or was it the caller's own request?* If your
`continue_write` finalizes — an S3 `CompleteMultipartUpload`, an Azure
`Put Block List`, a Nucleus `create_asset` — you have the guarantee and must
keep it. If the caller's presigned `PUT` was the commit and `continue_write`
only reports
or reads back, you do not have it on that path, whatever the backend does on
others. Keep the staged shape wherever you have a choice, and where you do not,
say so in the plugin's own documentation rather than leaving a reader to assume
the guarantee holds.

**Everything `continue_write` receives except the address is reported by the
caller, not observed by you** — the results, the redirect batch echoed with
them, and the continuation blob inside it. That caller is a redirect follower
inside a host stack on one route, and a remote client on the other; the broker
has both, because its own `write` path follows redirects in process. Check the
cardinality yourself, because no follower route checks it, and expect any status
to arrive: only the broker's `continue_write` RPC refuses one outside 200..300,
and its cardinality check compares two counts the same caller supplied. Nothing
else is validated, and no signature binds the continuation to the operation you
issued it for.

The address is the only authenticated part of the call, because authorization is
decided on it. **Derive the object you act on from the address** rather than
taking it from the continuation. Where the provider's handle makes that
impossible, keep whatever comparison you have but say in the code that it is
defence in depth rather than presenting it as the control — on the broker's
client-driven route both sides of a comparison come from the same caller.
Acting on whatever object the blob names lets the caller pick its own
authorization. Values the address cannot supply — a
server-issued session handle, the preconditions of the original write — have to
travel in the blob, so treat those as caller-chosen rather than as facts.
Beyond that, none of these values may be evidence about connection auth state,
credential validity, quota, principal identity, or metrics. The full rule is
*Everything `continue_write` receives except the address is caller-supplied
input* in [CONFORMANCE.md](../plugin-storage/CONFORMANCE.md).

Reads stay one Layer call. `read` returns `ReadResult` directly; the
host inspects the variant and acts. There is no `continue_read`.

`list_versions` makes no order guarantee. Plugins return
version-pinned `ObjectInfo` values in whatever order their backend's
native list API produces. `supports_version_listing` gates the
operation; `version_list_order` advertises what the backend natively
does (`Newest`, `Oldest`, or `Unordered`).

**`watch_directory` Layer method.** Plugins translate native feeds into a single shape:

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
the Layer contract does not include a polling mode (callers can drive `list`
themselves on whatever cadence they choose). Plugins are responsible
for translating native gap conditions into `Lapsed`: a plugin that
can't distinguish "everything fine" from "we dropped events" is
required to emit `Lapsed` defensively on every reconnect.

Every successful concurrent call is an independent logical subscription: from
the point it returns, it receives every event eligible under its own options.
A competing-consumer backend — where each notification is delivered to exactly
one reader, so two watches sharing the connection's queue would cannibalize
each other's events — MUST self-coalesce via the SDK `WatchCoalescer` and pass
the `watch-concurrent-cross-prefix-no-split` conformance scenario. The
coalescer collapses live subscriptions sharing one connection onto a single
recursive, metadata-inclusive physical watch and filters each subscriber. It is
principal-blind: subscriptions key only on the connection/prefix, never on the
principal, and it enforces no per-principal watcher limit (a per-principal limit,
if any, belongs at a central chokepoint, not in each backend's coalescer). A
call with a `since` cursor requests replay: a resumable backend may
serve it from a dedicated seek reader with real replay, while a non-resumable
competing-consumer backend coalesces onto the live stream and prepends a single
initial `Lapsed`. Either way a `since` subscription never attaches behind an
existing live consumer that could truncate its replay.

Cache `watch_invalidation` opens one identity-free logical subscription per
advertised root because cache invalidation is address-wide, independent of any
caller watch — and, where a root's own watch is refused with
`PermissionDenied`, a bounded number of narrower subscriptions on directories
the cache holds entries for instead. On a competing-consumer backend that
subscription shares the connection's queue with caller watches and may
coalesce onto a single physical
upstream, so the backend's self-coalescing is what lets both still receive every
event; a backend that does not self-coalesce must leave cache watch invalidation
disabled and rely on TTL invalidation.

### Address projection

For Layer calls that return object addresses, plugins return
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
  and the host uses `Layer::list` to satisfy an object `stat`, it
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
backend violated the Layer contract.

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
  `PluginInitResultV1 { struct_size, abi_version, plugin_state,
  plugin_vtable, kinds, kind_count }`. The descriptors are borrowed
  for the plugin lifetime. `PluginVTableV1` owns the three creation
  slots; each successful call returns a `LayerHandle` whose
  `LayerVTableV1` contains identity, introspection, object-operation,
  and connection-lifecycle slots.

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
- Plugin, Layer, stream, future, `LocalDelegate`, and
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
  in-flight operation, and must not inspect or log it. That is the
  host's obligation, not a property a plugin may assume held: the
  blob returns over the same unchecked path as the redirect results,
  so derive the object you act on from the request address instead of
  decoding it out of the blob, and treat what the address cannot
  supply as caller-chosen. See *Everything
  `continue_write` receives except the address is caller-supplied
  input* in [CONFORMANCE.md](../plugin-storage/CONFORMANCE.md).
- Redirect `HttpRequest.method` is drawn from a fixed allowlist,
  matched exactly and in uppercase: a `ReadRedirect` may use `GET`
  or `HEAD`; a `WriteRedirect` may use `PUT`, `POST`, or `PATCH`.
  Any other method — including a lowercase spelling of a permitted
  one — is rejected with `PermissionDenied` before any network I/O.
  A plugin that needs a non-write verb against the origin (a
  `DELETE` to abort a multipart upload, say) performs it through
  its own client rather than as a redirect.
- A `Content-Length` header you put on a **write** redirect must be
  `1*DIGIT` per RFC 9110. Surrounding whitespace is trimmed, but a sign
  character — `+123` as much as `-123` — is refused with
  `InvalidArgument` before any network I/O, as is an empty value and a
  second `Content-Length` header. The **read** path replays your
  headers unchecked, so a malformed value there reaches the origin
  instead of being refused — that is a gap in the check, not a licence.
  Format it as bare digits on both. Same rule, stated in full, in
  [CONFORMANCE.md](../plugin-storage/CONFORMANCE.md).
- Every redirect must **declare what its credential authorizes**, on
  `RedirectScope.credential`. The four values are `None` (no
  credential; the URL alone fetches the target), `Request`
  (authorizes this one request and expires with the redirect),
  `Connection` (authorizes the connection at large — other objects,
  and time beyond this redirect's expiry), and `Unspecified` (the
  plugin forwards a credential it did not construct and cannot
  classify).

  Declare it, do not compute it: the host cannot. An account-wide
  signature and one scoped to a single blob are the same shape on the
  wire, so no header or URL inspection recovers the difference, and
  only the code that built the credential knows what it covers.
  Derive the value from the branch that constructs the credential — the
  auth mode, the signing call — rather than from the redirect's shape,
  so the two cannot drift apart.

  `Unspecified` is fail-safe, not neutral: a host treats it exactly as
  `Connection`. Declare it honestly when you are copying a header set
  from upstream; guessing `Request` to keep the redirect path is the
  failure this field exists to prevent.

  **Choose `Unspecified` over `Connection` when you do not know rather
  than when you know it is broad**, even though hosts treat the two the
  same today. The two say different things — `Connection` is a claim
  about the credential, `Unspecified` is a statement that you are
  forwarding something you did not construct and cannot introspect — and
  only the second stays true on its own if the upstream narrows what it
  returns. The in-tree OpenDAL and Omniverse Storage Service plugins are
  both `Unspecified` for exactly that reason; Nucleus LFT is
  `Connection`, because it knows its redirect carries the connection's
  own auth headers.

  What the host does with the declaration is the **operator's**
  choice, not the plugin's — the deciding question is whether the
  clients are trusted, which no plugin can know. Under the default
  policy a host withholds redirects declared `Connection` or
  `Unspecified` and moves the bytes itself; an operator may opt in to
  handing them over.

  A host may **lower** a declaration but never raise one: a redirect
  declared `Request` that also carries a header the host cannot
  account for as addressing or conditioning the request is treated as
  `Connection`. So attaching an unusual header to a request-scoped
  redirect costs a proxied transfer, not a disclosure. Prefer scoping
  the credential into the presigned URL where the backend allows it.
- A `LocalDelegate` path is meaningful only on the host that
  received it from the plugin or cache. The plugin must not delete
  or mutate the delegated file while the lease is alive.
- Plugin unload is reverse-topology: all in-flight calls and
  returned streams/delegates must be dropped before backend
  destruction; all backends before factories; all factories before
  plugin-state destruction; plugin-state destruction before the
  shared library is closed.

## Capability vocabulary

`Capabilities` is application-facing through `RootInfo`. It describes
what the caller can do against a root: in Direct mode it reflects the
plugin behavior; in Brokered mode the broker may strip operations its
policy forbids. Dynamic-root plugins publish updated `RootInfo` values
through the `list_address_roots` update stream. The host gates dispatch
on the effective root capabilities.

### Bits are hints, and the two answers are not symmetric

A capability bit is a **hint that lets a caller skip a round-trip it
knows cannot succeed**. It is not an enforcement mechanism and not a
promise:

- **`false` is actionable.** The operation is known to be unavailable
  on this route, so a caller may skip it and a UI may grey it out.
- **`true` is not a guarantee.** It means only "not known to be
  impossible." The operation can still fail — including with
  `Unsupported` — for reasons the bit cannot express: the deployment
  behind a protocol has not implemented the RPC, a policy layer
  intercepts the slot, or the specific arguments fall outside what the
  backend supports.

Two obligations follow.

**Plugin authors: self-gate.** A backend layer that does not support an
operation returns `Unsupported` (or the appropriate typed error) with
**no side effects** when a caller ignores the hint and calls the slot
anyway. The host does not pre-gate on your behalf. Where a capability
varies by deployment rather than by protocol, negotiate it per root in
`capabilities_for_root` rather than hard-coding the protocol's answer —
the services-client plugin does this for folder mode and optimistic
locking.

**Callers: handle `Unsupported` from advertised operations.** Treat a
`true` bit as "worth attempting," never as "will succeed." Masking a
bit is likewise not enforcement: a wrapper that strips a bit from
`root_info_for` changes the hint only, so a policy-enforcing Layer must
also intercept and reject the operation slots it forbids.

### Availability, mechanism, and guarantee are three different claims

For `copy` and `rename` the bits answer three separate questions, and
conflating them is what makes a stack behave inconsistently:

- **Availability** — `supports_copy`, `supports_rename`: the operation
  can be attempted on this root. This is what a caller asking "will
  `copy` work?" wants. A layer that emulates the operation sets it even
  though the backend beneath performs nothing.
- **Mechanism** — `supports_server_side_copy`,
  `supports_server_side_rename`: the backend moves the bytes itself, so
  there is no egress through the host and native metadata and checksums
  survive. Only a backend that really does this sets it; an emulating
  layer never raises it.
- **Guarantee** — `supports_atomic_rename`: the backend's own rename is
  indivisible. It describes the *native* path, not every request: an
  emulated rename is a copy followed by a delete and is never atomic.

An emulating layer clears the mechanism and guarantee bits when emulation is
**certain** — a root reporting no `rename` of its own is never asked, so every
rename against it is copy-then-delete and `supports_atomic_rename = true`
would be a promise the stack cannot keep for any call. It leaves them alone
when emulation is merely *possible*, because that is decided per request.

Availability is a property of the root. Mechanism and guarantee describe
what the backend does when it handles the request itself — and whether it
does is decided per request, not per root, because a backend can perform
most renames server-side and decline the one carrying a precondition it
cannot express. So an emulating layer raises availability and leaves the
other two alone: lowering them would deny a capability that holds for
nearly every request. The degradation is reported per request instead —
`copy_rename_fallback` emits a `tracing` event whenever it emulates.

A backend whose `rename` is its own copy-then-delete therefore reports
`supports_rename = true`, `supports_server_side_rename = false`,
`supports_atomic_rename = false` — all three answers differ, and each is
true.

The bits, stable across the project:

**Concurrency**
- `supports_if_match_write` (writes honor `IfDestExists::MatchEtag(etag)` — real CAS, not best-effort)
- `supports_no_overwrite_write` (writes honor `IfDestExists::Fail`)

**Metadata**
- `supports_native_metadata_patch` (backend can patch `UserMetadata` without rewriting bytes — GCS, Azure, local FS, Perforce)
- `supports_metadata_rewrite_emulation` (backend can emulate metadata patch by full object rewrite — S3, where modifying `x-amz-meta-*` requires `CopyObject`-onto-self)

**Write**
- `writes_are_atomic` (an overwrite is all-or-nothing from the reader's perspective; partial writes are never visible)
- `supports_copy` (availability: `Layer::copy` can be attempted on this root, natively or by emulation above it)
- `supports_server_side_copy` (the backend can execute `Layer::copy` without the host streaming bytes through itself)

**Naming**
- `supports_rename` (availability: `Layer::rename` can be attempted on this root, natively or by emulation above it)
- `supports_server_side_rename` (the backend can execute `Layer::rename` as a backend operation)
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
Production hosts treat `test_only = true` plugins as opt-in: direct
loading returns `ErrorCode::PluginRejected` against a default-posture
host, and directory discovery skips the cdylib at debug-log level
so the bundled conformance fixture in `<archive>/plugins/` doesn't
crash startup. See "What's not supported" below.

### Registry entry shape

Every conformance scenario has one registry entry, and the registry
is the only place where scenario behavior is declared. Each entry
carries:

- `name`: the stable string used in URLs, reports, and test filters.
- `vtable_slots`: the `OvStorage_LayerVTable` slots the scenario is
  expected to exercise.
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
uses the helper. Rows marked `(missing)` indicate a seam that has no
seam-specific test yet; the marker is about test coverage, not about the
seam itself.

| Seam                           | Test                                                               |
|--------------------------------|--------------------------------------------------------------------|
| host ↔ FFI plugin              | extend the existing host-plugin behaviors test                     |
| host ↔ nucleus gRPC client     | nucleus transport tests (extend `connlib_test.rs`, `sows_test.rs`) |
| broker server ↔ plugin         | broker streaming-invariant write test (missing)                    |
| REST ↔ host                    | REST streaming-invariant objects test (missing)                    |
| s3 plugin ↔ S3 transport       | s3 plugin streaming-invariant test (missing)                       |
| gcs plugin ↔ GCS transport     | gcs plugin streaming-invariant test (missing)                      |
| azure plugin ↔ Azure transport | azure plugin streaming-invariant test (missing)                    |
| opendal plugin ↔ opendal       | opendal plugin streaming-invariant test (missing)                  |
| http plugin ↔ HTTP transport   | http plugin streaming-invariant test (missing)                     |
| file plugin ↔ filesystem       | file plugin streaming-invariant test (missing)                     |
| broker-client ↔ broker         | broker-client streaming-invariant test (missing)                   |

### Deferred-streaming seams

Plugins that return `Unsupported` for `Body::Stream` writes pin the
gap with a test asserting the `Unsupported` return — pre-empting an
accidental disk-spool half-measure that would silently buffer to disk
and present as unbounded memory-and-disk growth under a name that says
"streaming". An honest `Unsupported` is the required answer; a spool is
not a lesser version of streaming.

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
   require the exact Layer ABI version, and refuse `test_only = true`
   unless the host configuration enables test plugins.
3. Resolve `ovstorage_plugin_init_v1`. Call it with the host
   callbacks pointer; the plugin returns `PluginInitResultV1` with its
   kind descriptors and plugin-scoped creation vtable.
4. Stack construction creates each configured Layer and dispatches
   through the resulting `LayerVTableV1`.

The loader accepts only an exact match on the Layer ABI version the host was
built with — 14 in ovstorage 0.2.1. A direct load of an
incompatible manifest or init result returns `ErrorCode::IncompatibleType`;
directory discovery skips that artifact and continues loading compatible
neighbors. `ErrorCode::PluginRejected` is reserved for host policy, including
an opted-out `test_only` plugin.

Hosts discover plugins while constructing their plugin registry.
`OVSTORAGE_PLUGIN_DIR` overrides the default `<exe_dir>/plugins/`
directory. Embedded hosts may call `load_plugin` or
`load_plugins_from_dir` against paths controlled by their package or
container image. Direct loading rejects an opted-out `test_only`
plugin; directory discovery skips it at debug level. A directory scan
fails if two plugin libraries advertise the same Layer kind, including
when an upgrade leaves old and new copies of one plugin together. Keep
exactly one installed library for each kind. (A copy built against a
different ABI version does not collide, because it is skipped at the ABI
gate before its kinds are read.)

A minimum viable Rust plugin is two files. The `Cargo.toml` — note that
`version` is your *plugin's* version and has nothing to do with the
`ovstorage-plugin` pin two lines below it:

```toml
[package]
name    = "my-storage-plugin"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
ovstorage-plugin = "0.2"
async-trait      = "0.1"
```

And `src/lib.rs` (the in-tree
`ovstorage-core/examples/plugin-rust/` crate is this template, kept
compiling in CI):

```rust
use async_trait::async_trait;
use ovstorage_plugin::{
    BackendFactory, CancellationToken, Error, ErrorCode, LayerConfig,
    LayerHandle, LayerKindDescriptor, LayerType, Result,
    ovstorage_layer_plugin,
};

#[derive(Default)]
pub struct MyFactory;

#[async_trait]
impl BackendFactory for MyFactory {
    fn descriptor(&self) -> LayerKindDescriptor {
        LayerKindDescriptor {
            kind: "my-backend".into(),
            layer_type: LayerType::Backend,
            display_name: "My Backend".into(),
            description: None,
            config_schema: vec![],
            credential_schema: vec![],
            credential_methods: vec![],
            icon: None,
            accepts_connections: false,
            // Whether a write's `user_metadata` survives this backend.
            // This stub creates no backend and stores nothing, so it
            // declares `false`. Declare `true` only if every write slot
            // keeps the map: a host that attributes composes its
            // attribution layer over a declaring kind's branch and, under
            // the default `user_metadata` strategy, stamps a reserved key
            // into the writes that reach it.
            supports_user_metadata: false,
        }
    }

    async fn create_backend(
        &self,
        _name: &str,
        _config: &LayerConfig,
        _cancel: Option<CancellationToken>,
    ) -> Result<LayerHandle> {
        Err(Error::new(
            ErrorCode::Unsupported,
            "my-backend factory is a stub",
        ))
    }
}

ovstorage_layer_plugin!(backend, MyFactory::default);
```

A real plugin returns an `Arc`'d `Layer` implementation from
`create_backend` (see `ovstorage-core/ovstorage-plugin-test-layer` for
a minimal working in-memory backend).

`cargo build --release` produces `target/release/libmy_storage_plugin.so`
(or `.dylib` / `.dll`); copy it under the plugin dir and the loader
picks it up.

## Plugin macros

Rust plugin authors get the manifest and init exports from a single
function-like proc macro:

```text
ovstorage_layer_plugin!(backend, MyFactory::default);
ovstorage_layer_plugin!(backend, MyFactory::default, test_only);
ovstorage_layer_plugin!((
    (backend, MyBackendFactory::default),
    (wrapper, MyWrapperFactory::default),
    (router, MyRouterFactory::default),
));
```

Argument shape: a layer-type tag (`backend` / `wrapper` / `router`)
followed by a constructor expression `fn() -> F` where `F` implements
the matching factory trait (`BackendFactory` / `WrapperFactory` /
`RouterFactory`). The bundled form takes one or more
`(tag, constructor)` pairs and exports all of their kinds from the same
cdylib. The macro invokes each constructor once at load time, wraps each
factory in an `Arc`, and installs the factory vector as the plugin's
`LayerPlugin` state behind the ABI-v2 vtable thunks. The host rejects a
plugin that advertises one kind more than once, two discovered plugins
that advertise the same kind, or a plugin that collides with the built-in
`file` kind.

The optional trailing `, test_only` flag flips the manifest's
`test_only` bit for the whole plugin, including every factory in a
bundle. Production hosts configured with
`allow_test_plugins = false` refuse to load such plugins.
Direct loading returns `ErrorCode::PluginRejected`; directory
discovery used by the broker and REST gateway silently skips the
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

The expansion declares the two stable plugin exports:

- `ovstorage_plugin_manifest_v1`: `PluginManifestV1` static carrying
  `struct_size`, the compile-time `OVSTORAGE_PLUGIN_ABI_V2_VERSION`
  constant (at or above `OVSTORAGE_PLUGIN_ABI_V2_FLOOR`, then validated
  by exact match), NUL-terminated `name` / `version` pointers, and the
  `test_only` flag.
- `ovstorage_plugin_init_v1`:
  `unsafe extern "C" fn(*const HostCallbacks) -> PluginInitResultV1`.
  The thunk registers the host callbacks, installs the tracing log
  layer, invokes the factory constructor, and returns a
  `PluginInitResultV1` carrying the plugin's per-kind factory vtable
  state (`thunks_v2::LayerPlugin`).

Both exports use `#[unsafe(no_mangle)]` (Rust 2024 spelling) to
keep the symbol names exactly what the host loader expects.

### ABI version handshake

The generated `PluginInitResultV1` repeats the manifest's
`OVSTORAGE_PLUGIN_ABI_V2_VERSION`. The host requires an exact match;
plugins do not advertise a compatibility band, and a plugin cannot
declare support for more than one ABI version.

The Layer ABI version is a constant — 14 as of ovstorage 0.2.1, the
version that adds the `LayerKindDescriptor.auth_capable` listener-auth
discriminator (the typed `AUTH_CREDENTIAL` decode helpers are additive SDK
surface, not an ABI change) — and the per-version history in the generated
`ovstorage_plugin.h` header doc block is authoritative. Read the constant
rather than a number quoted in prose, including this page's. **The two
surfaces spell it differently**, which is worth knowing before you go looking:
Rust has `OVSTORAGE_PLUGIN_ABI_V2_VERSION`, while the generated header emits
`#define OVSTORAGE_PLUGIN_ABI_VERSION`, with no `V2`. The floor is
`OVSTORAGE_PLUGIN_ABI_V2_FLOOR` in Rust and
`OvStoragePlugin_OVSTORAGE_PLUGIN_ABI_V2_FLOOR` in the header, and is 5 in
ovstorage 0.2.1. The header's prose keeps the Rust spellings, so grepping it
turns up both — the `#define` lines are the ones a compiler sees.

Note that the ABI version number, the `v2` in these constant names, and the
ovstorage package version are three separate things. `v2` names the ABI
*family*; 14 is the version within it; 0.2.1 is the release. A plugin author
reasoning about compatibility cares only about the version number.

**When a change needs a version bump.** The default is that it does. One narrow
case is exempt, and it is exempt only when *all* of its conditions hold. Check
them in **both directions**, because a version that does not bump lets an old
binary pair with a new one either way round:

- the growth consumes slots already reserved in a struct's tail, the struct's
  size is unchanged, and every existing field keeps its offset;
- the new field's alignment is satisfied by the bytes it takes over;
- **old producer, new consumer:** the all-zero bytes an older binary leaves
  there decode as a valid, *correct* value — not merely a parseable one;
- **new producer, old consumer:** the bytes mean nothing to the older binary, so
  the new field must impose no obligation it cannot know about. A field it must
  free, unmap, close, or otherwise act on is not exempt, because the older
  binary will do none of those things.

That last condition is the one this repository has already spent. `RootInfo`
gained `owning_target` against three of its eight reserved pointers, and it
satisfies the layout conditions and the zero-decode condition: an older plugin
zeroes those bytes and a zeroed `Optional` reads as absent, which is the truth.
It does **not** satisfy the fourth. `owning_target` is an owning `Optional<Str>`,
so a plugin built against the current header can return `Some` to a host built
against the ABI version before the field existed, and that host — seeing only
reserved pointers — never runs the release path. The pairing stays
memory-safe, which is what the in-tree comment claims, but it leaks the string
on every call. Treat `RootInfo` as an accepted exception rather than the
pattern to copy. This pairing is reachable only *within* the v2 ABI family.

Consuming reserved bytes is therefore not by itself a licence to skip the bump.
A field with no valid zero representation, one whose zero means something false
rather than "absent", one needing stricter alignment than the slot provides, or
one that changes who owns or drops a value, all break an older binary while
looking like a tail append. Under exact-version matching those are semantic
conditions you must check, not consequences the layout gives you — and the
ownership case is listed among the shapes that bump, three paragraphs down, for
exactly this reason.

Everything else bumps. The shapes below are drawn from the ABI versions this
project has spent. It is a record rather than
a taxonomy — do not read the list as exhaustive, and do not read it as a
porting checklist either.

- **An insertion that moves an existing field.** Two bools —
  `supports_copy` and `supports_rename` — were added to the middle of
  `Capabilities` rather than its tail, shifting every field below them and
  every struct embedding it by value, so a cdylib built against the older
  header misreads the whole block.
- **A trailing field in a struct with no reserved tail.** `ReadOptions` gained
  `max_bytes` at the end and bumped anyway, because there was no reserved
  budget to spend. "At the tail" is not the exemption; "into reserved slots"
  is.
- **A field whose type changes.** Re-typing the `Extensions` entries swapped one
  two-word representation for another, moving nothing — the bytes simply mean
  something else. (The ABI version that carried this also carried a layout
  change, so read the bullet for the shape rather than as a clean example.)
- **A function-pointer signature change.** Adding a request-context parameter to
  the introspection slots changed no struct at all. It is invisible to the
  `struct_size` handshake, which is exactly why it needs the version.
- **A change to who owns a value.** Moving every ABI buffer onto the shared OS
  heap left most layouts untouched; the bump is what forces the rebuild that
  carries the allocator choice, which a cdylib bakes in at compile time. (The
  ABI version that carried this also carried a real layout change, so it is not
  a pure example — the ownership half is the part worth learning from.)

So the question is not "did the bytes move" but "could a binary built against
the header one ABI version earlier still be right about this value". Some of
that is checked
mechanically — the one reserved-tail append carries a `const` assertion pinning
the sizes it spent and its offset relative to the field before it — but the
assertion is narrower than it looks: it catches a reordering around the appended
field, not growth somewhere above it, which moves both offsets together and
leaves every clause true. Treat the version decision as yours to make, not as
something the compiler will make for you.

### Allocator contract

Values that cross the ABI live on the **process-wide operating-system
heap** — `malloc`/`free` on POSIX, the process heap on Win32 — not on
whatever allocator the producing binary happens to install. That covers
the outer heap envelope of a result and every `Str`, `Bytes`, and `List`
buffer nested inside it, in both directions.

This matters because `#[global_allocator]` is a per-artifact choice: a
plugin cdylib and its host each pick their own. A plugin is free to
install jemalloc, mimalloc, or any other allocator — that choice governs
the plugin's own internal allocations and nothing else. A value handed
across the ABI must not come from it, because the receiving binary
releases that value through its own allocator.

Rust plugins get this for free: `ovstorage-plugin`'s marshalling layer
routes every ABI buffer through `std::alloc::System`, which
`#[global_allocator]` cannot redirect. Plugins written directly against
the C header use `malloc`/`free` (or, on Win32, `HeapAlloc`/`HeapFree`
against `GetProcessHeap()`) for the same buffers, and must not substitute
a private arena or a statically linked CRT's heap.

Routing a release through an exported `ovstorage_plugin_*_free` symbol is
**not** a substitute. Those exports ship in the `ovstorage-plugin` rlib,
which links into the host and into every plugin cdylib, so each binary
carries its own copy and a call from Rust binds to the caller's — the
caller's heap, which is the thing being worked around.

### Panic safety

The `catch_unwind` walls in the ABI-v2 thunk runtime around
per-method async dispatch are the panic-safety contract: they convert
a plugin panic to `ErrorCode::Internal` before it can unwind across
the C ABI. The workspace keeps the default `panic = "unwind"` for both
`dev` and `release` so those walls can catch. The generated
`ovstorage_plugin_init_v1` deliberately does not wrap its body in
`catch_unwind` — a panic in the plugin author's factory constructor
escapes the `extern "C"` init fn and is force-aborted by rustc (≥1.81,
guaranteed on edition 2024) rather than unwinding the C frame, which
is the desired hard-fail.

## ABI roadmap

The Layer ABI uses exact version matching. Plugin authors depend on
`ovstorage-plugin`; the macro writes its
`OVSTORAGE_PLUGIN_ABI_V2_VERSION` into both manifest and init result.
A host running a different ABI rejects the cdylib with
`IncompatibleType`. Compatibility for a future
frozen ABI requires an explicit new versioning decision rather than an
inferred version band.

## ABI-stability rules

The plugin C ABI freezes at **ABI 1.0** — a milestone of the ABI's own
versioning, not the ovstorage 1.0 release — and once that ships, a break is an
**ABI 2.0**. Neither number tracks the package version, which is 0.2.1 today.
Until that freeze, the ABI version simply increments.
Three layered defenses authors must understand:

- **`struct_size` handshake on every options struct.** Every
  `OvStoragePlugin_*Options` struct (read, write, list, stat, etc.)
  carries `size_t struct_size` as its first field. The callee validates
  `struct_size >= sizeof(known_minimum)` before reading any tail
  field; an undersized struct returns `InvalidArgument` rather than
  reading uninitialized memory. Newer callers passing a larger size
  remain compatible because the callee ignores fields past its
  known maximum. This handshake operates *within* one ABI version and
  does not soften the exact-version gate described under [ABI version
  handshake](#abi-version-handshake): a plugin declaring a different ABI
  version is refused before any options struct is read, so `struct_size`
  never gets the chance to bridge a plugin built against a different ABI
  version to this host.
- **Reserved padding on request structs and vtables.** Every plugin
  request struct ends with reserved pointer slots. The Layer and plugin
  vtables end with zero-initialized reserved-fn slots. Additive growth
  consumes the next free slot in tree order; existing fields never
  reorder. This is a *narrower* set than the rule above: the
  `*Options` structs have no reserved slots (the two directory ones
  are the only exception), so a new option is added by appending the
  field and bumping `struct_size` — the prefix check is the whole
  guarantee there.
- **Exact ABI handshake.** `PluginManifestV1` and
  `PluginInitResultV1` carry `OVSTORAGE_PLUGIN_ABI_V2_VERSION`; the
  host requires exact equality before reading the v2 init result.

The first two rules are specific to `ovstorage_plugin.h`, which crosses a
real `dlopen` boundary. The application C API in `ovstorage.h` uses
neither: it ships as source compiled together with its implementation, so
its public structs carry no `struct_size` and no reserved padding.

## What's not supported

- **`test_only = true` plugins are host-gated, not package-gated.**
  The host's `allow_test_plugins` setting is the opt-in; a
  default-posture host treats a `test_only` cdylib as unloadable.
  Direct loading surfaces `ErrorCode::PluginRejected`; directory
  discovery skips the cdylib silently at debug-log
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
