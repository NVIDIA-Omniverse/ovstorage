# library-rust persona

> *I'm writing a Rust app that needs to read and write objects across local
> files, S3 / GCS / Azure / Nucleus / public HTTP, with one address-routed
> API and minimal coupling to any specific backend.*

This persona lands you at `ovstorage::Library` running in **Direct mode** —
your process links plugins in-process, no daemon required. You link the
crate into your binary, hand it a `LibraryBuilder`, register one or more
backend plugins, and issue every read / write / list / watch through the
address-routed `Storage` trait. The dispatcher matches caller-facing
`ObjectAddress` values (`url::Url`) against the routing table and forwards
each call to the right backend. Application code never branches on backend
kind, never composes URLs out of pieces, and never sees plaintext credentials
after `add_connection`. The alternative — Brokered mode — runs an
`ovstorage-broker` daemon and is described in §"What's not supported".

## Where to find each piece

- **API entry and method semantics.** `ovstorage::Library` and the
  `Storage` trait are documented below under [Storage trait](#storage-trait),
  [Listing and paging types](#listing-and-paging-types),
  [Change-notification types](#change-notification-types),
  [Address-root introspection types](#address-root-introspection-types),
  and [Routing-table types](#routing-table-types). The trait lists every
  method (`stat`, `read_bytes`, `read_stream`, `materialize`, `write`,
  `delete`, `list`, `list_versions`, `copy`, `rename`, directory ops,
  watch APIs, plus connection / alias / visibility management) and is
  the source of truth for dispatcher guarantees.
- **Type vocabulary.**
  [plugin-development README § Type vocabulary](../plugin-development/README.md#type-vocabulary)
  is the canonical home for `ObjectAddress` / `Url`, `ObjectInfo`,
  `ObjectKind`, `IfDestExists`, the options structs, the `ErrorCode`
  taxonomy, the `Capabilities` bitset, `LocalDelegate`, and
  `SecretBytes`. `ovstorage`
  re-exports these so `use ovstorage::ObjectAddress;` keeps working.
- **Backend-specific behavior.** The active direct backends each have
  their own reference describing URL shape, config keys, capability
  matrix, and credential story:
  [file](../plugin-storage/plugin-file.md),
  [http](../plugin-storage/plugin-http.md).
- **Glossary.** Project terms (Address root, Backend, Connection, Direct
  mode, ResolvedTarget, SecretBytes, …) are defined once in
  [`docs/public/GLOSSARY.md`](../GLOSSARY.md).

## Loading plugins

Plugins are first-party cdylibs (`libovstorage_plugin_*.{so,dylib,dll}`).
The library does not link them statically.

> **Already ran `make dist` from the repo root?** Skip the per-plugin build below — `<repo-root>/dist/plugins/` already has every first-party plugin built. Just `export OVSTORAGE_PLUGIN_DIR="$(git rev-parse --show-toplevel)/dist/plugins"` (or the absolute path) and continue at the *Tell `LibraryBuilder` which ones to load* paragraph.

**Build at least one plugin first.** Add `ovstorage` to your
`Cargo.toml`, then build the plugin you want — for example, the file
backend:

```sh
cargo build -p ovstorage-plugin-file --release
```

The cdylib lands in `target/release/libovstorage_plugin_file.so` (or
`.dylib`/`.dll` per platform). The `LibraryBuilder` finds plugins via
`OVSTORAGE_PLUGIN_DIR` (an explicit env var) or, if that's unset,
`<your-binary's-exe-dir>/plugins/`. Either copy the `.so` into one of
those locations, or set `OVSTORAGE_PLUGIN_DIR=$PWD/target/release` and
the dispatcher will pick it up.

Open the library first, then load trusted plugin cdylibs with either
`load_plugin(path)` or `load_plugins_from_dir(dir)`. Both are `unsafe` —
`dlopen` runs platform loader hooks; load only trusted plugins. The
helper `ovstorage::default_plugin_dir()` resolves to
`$OVSTORAGE_PLUGIN_DIR` if set, else `<exe-dir>/plugins/`. Python and
C/C++ callers use the same helper when `load_plugins_from_dir(None)` is
called, so a single `OVSTORAGE_PLUGIN_DIR` can populate plugins
consistently across every binding. `Library::open(None)` and
`LibraryBuilder::open()` initialize the process-global
[**auth substrate**](../GLOSSARY.md) automatically; callers that need a
custom auth state directory can call
`ovstorage::init_auth_substrate(Some(path))` before the first open.

After registration, instantiate backends with
`Storage::add_connection(ConnectionRequest, cancel)`. The request names a
`backend_kind` (`"file"`, `"s3"`, …), a `HashMap<String, ConfigValue>`,
and an optional `SecretBundle`. The returned `Connection` exposes the
address roots the backend serves; those become the prefixes you pass to
every object operation.

### Picking up connections saved by the CLI

If you've already used `ovstorage connect` and `ovstorage write-config`
to set up a backend interactively, your app can pick those connections
up automatically:

```rust
let library = Library::open(None)?;
unsafe { library.load_plugins_from_dir(None)?; }   // None = OVSTORAGE_PLUGIN_DIR / <exe-dir>/plugins
library.load_config(None).await?;                  // None = ./ovstorage.toml then XDG path
```

`load_config(None)` searches `./ovstorage.toml` then
`$XDG_CONFIG_HOME/ovstorage/ovstorage.toml` (matching the CLI) and
registers every `[[connections]]` entry on the live library. Credential
refs (env / keyring) resolve against the same `SecretStore` you opened
with, so a CLI `write-config --secrets keyring` flow Just Works. No
file? `load_config` returns `Ok(Vec::new())`. Pass `Some(&path)` for a
non-default location. Per-route overrides and `[state]` are
builder-time concerns — wire those via `LibraryBuilder::with_cache`
and `LibraryBuilder::add_route` before `open` if your TOML carries
them.

## Why management lives on the `Storage` trait

`add_connection`, `add_alias`, `set_address_visibility`, and
`authenticate_connection` share the trait with `read_bytes` because they
affect routing and operation success in-process. A UI, CLI, or
long-running app needs one coherent handle that can register a connection,
watch its address roots, authenticate it, add an alias, and read from the
resulting address — without racing a separate local state channel.

Brokered mode does **not** project these management calls through
`broker-client`. Object operations route by `ObjectAddress`, but
`add_connection` does not name an address the library could route to a
broker. The `broker-client` plugin sits behind the `StorageBackend` SPI,
which deliberately omits management APIs. Operators run a broker, edit
its TOML, and reload; client-side `Storage` management is local to the
library process.

## Stable read / modify / write

`stat` (and reads, writes, lists, directory ops) returns `ObjectInfo`
carrying the backend-observed `etag` (plus descriptive `version` /
`size` / `mtime`). To make a later call conditional on the same
bytes, pass the etag back as `ReadOptions::if_match` /
`DeleteOptions::if_match` / `UpdateMetadataOptions::if_match`, or
inside `WriteOptions::if_dest = IfDestExists::MatchEtag(etag)` /
`CopyOptions::if_source` / `RenameOptions::if_source`. The address
names *which* object; the etag asserts *which version of its bytes*.
Backends with native versioning expose version selection through
version-pinned addresses. Preconditions are etag-only: pass
`ObjectInfo.etag` back through the relevant `if_match` /
`if_source` / `if_dest` field to validate the object you observed.
Backends without etag-bound writes advertise that through the
`Capabilities::supports_if_match_write` bit and reject etag-bound
writes with a typed error rather than silently last-writer-wins.

## Address building

The library never composes URLs by string concat or `format!` — caller
code shouldn't either. Use the helpers in `ovstorage::address`
(re-exported from `ovstorage_plugin::address`):
`address::parse(s)` validates and normalizes a caller-facing string;
`address::join_relative(prefix, key)` joins a child key onto an
address-root prefix without re-encoding existing percent-escapes.
Roll-your-own concatenation breaks on roots whose paths don't end in `/`,
on keys with reserved characters, and on multi-byte UTF-8.

## Secrets

`SecretBytes` is redacted in `Debug`, zeroizes on drop, refuses
serialization. Every `CredentialField` in a `StorageBackendKindDescriptor`
is flagged `secret = true`; the public API never returns plaintext after
`add_connection`. A descriptor-driven UI that respects `secret = true`
can render the schema, accept user-supplied bytes as `SecretBytes`, and
only ever read back redacted values.

## Direct-mode trust boundary

Routes are local naming concerns. The library trusts the process it runs
in: anything that can call `add_connection` or edit the config files
feeding it can register a backend. Operator control over who can mutate
the routing table is the defense; library-side hardening against a
principal who already has process access is not. For cross-process
authorization, run a broker — it enforces authz on incoming caller-facing
addresses and only dispatches addresses in its own table.

## End-to-end example: file backend round-trip

The pattern below is exactly what
`ovstorage-core/crates/ovstorage-plugin-file/tests/loaded.rs` exercises
against the dlopen'd file plugin. Minimum `Cargo.toml`:

```toml
[dependencies]
ovstorage = "0.1"
ovstorage-plugin = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
tempfile = "3"
anyhow = "1"
```

Build the file plugin once with `cargo build -p ovstorage-plugin-file
--release` (or the HTTP plugin with
`cargo build -p ovstorage-plugin-http --release`; "first-party" here means a
cdylib in this repo, never statically linked).

```rust,ignore
use std::collections::HashMap;

use ovstorage::Library;
use ovstorage::Storage as _;
use ovstorage::address;
use ovstorage_plugin::{
    Body, ConfigValue, ConnectionRequest, DeleteOptions,
    ListOptions, ReadOptions, SecretBundle, StatOptions, WriteOptions,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let library = Library::open(None)?;
    // SAFETY: only load plugin paths you trust; `dlopen` runs loader hooks.
    unsafe { library.load_plugins_from_dir(None)?; }

    let root = tempfile::tempdir()?;
    let mut config = HashMap::new();
    config.insert(
        "root".into(),
        ConfigValue::String(root.path().to_string_lossy().into_owned()),
    );
    let connection = library
        .add_connection(
            ConnectionRequest {
                backend_kind: "file".into(),
                config,
                credentials: SecretBundle::default(),
                persist: false,
                display_name: Some("scratch".into()),
            },
            None,
        )
        .await?;
    // `current_addresses: Vec<Url>` carries every address root the
    // connection serves. The file plugin publishes exactly one root —
    // the configured `root` directory — so `[0]` is the only element.
    // Backends that publish multiple roots (S3 multi-bucket, broker-
    // delivered fan-out) hand back a list; iterate or pick by display
    // hint depending on what the connection advertises.
    let prefix = connection.current_addresses[0].clone();
    let object = address::join_relative(&prefix, "hello.txt")?;

    library
        .write(object.clone(), Body::Bytes(b"hello".to_vec()),
               WriteOptions::default(), None)
        .await?;
    let (bytes, _info) =
        library.read_bytes(object.clone(), ReadOptions::default(), None).await?;
    assert_eq!(bytes, b"hello");
    let _listing =
        library.list(prefix.clone(), ListOptions::default(), None).await?;
    library.delete(object.clone(), DeleteOptions::default(), None).await?;
    let _ = library.stat(object, StatOptions::default(), None).await; // NotFound
    Ok(())
}
```

## Streaming write limits

`Body::Stream` propagates chunk-by-chunk through every seam (dispatcher,
redirect follower, plugin SPI) — never drained to a `Vec<u8>`. The
single restriction: streaming writes are limited to one redirect round.
A second redirect round on a consumed stream surfaces `Unsupported`,
because the body bytes are gone after the first round. In practice
this means streaming uploads to S3 multipart (which can need a fresh
redirect for each part-completion phase) currently return `Unsupported`
on the second round; one-shot S3 PUTs, GCS resumable uploads, Azure
block blobs, and the file plugin all complete in one round and stream
fine.

## What's not supported

Direct mode runs in your process. A few capabilities require a broker:

- **Group cancellation.** Direct mode cancels per-call via the `cancel:
  Option<&CancellationToken>` parameter. There is no "cancel everything
  for principal X" library API.
- **Cross-process authorization.** Allow / deny / audit policy runs in
  the broker against an `AuthzPlugin`. Direct-mode `Library` trusts the
  process.
- **Per-principal limits and quotas.** Rate limits, quotas, and
  per-principal credentials live broker-side.
- **`add_connection` against `broker-client`.** Brokered backends are
  configured operator-side in the broker's TOML and published to clients
  as address roots through the `address_roots` stream. Clients consume
  them; they do not register them.

Those capabilities require a broker deployment, which is outside the
scope of the current in-repo surface. The application surface
(`Library`, `Storage`, addresses, options, errors) is designed so the
same caller code works against both modes.

## Storage trait

`Storage` is the abstract operation surface every binding ultimately
calls into. The `Library` handle implements it; test doubles implement
the same shape so generic application code works against either.

The current surface includes the object-addressed core
(`capabilities_for`, `stat`, the three read entry points plus
`read_raw` for binding-side gateways, `write`, `write_redirect` +
`continue_write` for body-less / multi-stage redirect flows, `delete`,
`list`, `list_versions`, `get_latest_version`, `copy`, `rename`,
`create_directory`, `delete_directory`, `update_metadata`, and
`check_access`) plus the direct-mode control APIs: `watch_directory`,
`list_address_roots`, backend-kind descriptors, connection
add/remove/list/watch, alias add/remove/list/watch, exact-row
visibility overrides, and `authenticate_connection`.

The trait signature below names methods, address types, options, and
return types. The actual trait carries `#[async_trait]`; every
byte-moving method is `async` and takes a final
`cancel: Option<CancellationToken>` parameter that propagates through
`StorageBackend` SPI calls. State-reader methods (`list_*`, `watch_*`
setup, `capabilities_for`) stay synchronous because they only touch
in-memory state. The names below match the actual trait one-to-one —
the `async` and `cancel` modifiers are elided for readability. *(Note:
Rust signatures use `url::Url` for the address parameter type; this
section uses `ObjectAddress` as the conceptual name. The crate
re-exports `ovstorage_plugin::address` so `use ovstorage::ObjectAddress`
keeps working.)*

```text
pub trait Storage {
    fn capabilities_for(&self, prefix: &ObjectAddress) -> Result<Capabilities>;
    fn list_address_roots(&self) -> Result<Vec<AddressRoot>>;
    fn list_backend_kinds(&self) -> Result<Vec<StorageBackendKindDescriptor>>;
    fn add_connection(&self, request: ConnectionRequest) -> Result<Connection>;
    fn remove_connection(&self, id: &ConnectionId) -> Result<()>;
    fn update_connection_credentials(&self, id: &ConnectionId, credentials: SecretBundle) -> Result<Connection>;
    fn list_connections(&self) -> Result<Vec<Connection>>;
    fn watch_connections(&self) -> Result<ConnectionChangeStream>;
    fn add_alias(&self, request: AliasRequest) -> Result<Alias>;
    fn remove_alias(&self, id: &AliasId) -> Result<()>;
    fn list_aliases(&self) -> Result<Vec<Alias>>;
    fn watch_address_roots(&self) -> Result<AddressRootSnapshotStream>;
    fn set_address_visibility(&self, address: ObjectAddress, visibility: AddressVisibility, persist: bool) -> Result<AddressVisibilityOverride>;
    fn list_address_visibility_overrides(&self) -> Result<Vec<AddressVisibilityOverride>>;
    fn authenticate_connection(&self, id: &ConnectionId) -> Result<AuthEventStream>;
    fn stat(&self, addr: ObjectAddress, opts: StatOptions) -> Result<ObjectInfo>;
    fn read_bytes(&self, addr: ObjectAddress, opts: ReadOptions) -> Result<(Vec<u8>, ObjectInfo)>;
    fn read_stream(&self, addr: ObjectAddress, opts: ReadOptions) -> Result<(ReadStream, ObjectInfo)>;
    fn materialize(&self, addr: ObjectAddress, opts: ReadOptions) -> Result<LocalDelegate>;
    fn read_raw(&self, addr: ObjectAddress, opts: ReadOptions) -> Result<ReadResult>;
    fn write(&self, dest: ObjectAddress, body: Body, opts: WriteOptions) -> Result<WriteResult>;
    fn write_redirect(&self, dest: ObjectAddress, opts: WriteOptions) -> Result<WriteRedirectBatch>;
    fn continue_write(&self, dest: ObjectAddress, redirects: WriteRedirectBatch, results: RedirectResultBatch) -> Result<WriteStep>;
    fn delete(&self, addr: ObjectAddress, opts: DeleteOptions) -> Result<()>;
    fn list(&self, prefix: ObjectAddress, opts: ListOptions) -> Result<Vec<ObjectInfo>>;
    fn list_versions(&self, addr: ObjectAddress, opts: ListVersionsOptions) -> Result<Vec<ObjectInfo>>;
    fn get_latest_version(&self, addr: ObjectAddress) -> Result<ObjectInfo>;
    fn watch_directory(&self, prefix: ObjectAddress, opts: WatchDirectoryOptions) -> Result<ChangeStream>;
    fn create_directory(&self, addr: ObjectAddress, opts: CreateDirectoryOptions) -> Result<ObjectInfo>;
    fn delete_directory(&self, addr: ObjectAddress, opts: DeleteDirectoryOptions) -> Result<()>;
    fn copy(&self, src: ObjectAddress, dest: ObjectAddress, opts: CopyOptions) -> Result<WriteResult>;
    fn rename(&self, src: ObjectAddress, dest: ObjectAddress, opts: RenameOptions) -> Result<()>;
    fn update_metadata(&self, addr: ObjectAddress, opts: UpdateMetadataOptions) -> Result<ObjectInfo>;
    fn check_access(&self, addr: ObjectAddress, ops: AccessOps) -> Result<AccessDecision>;
}
```

`read_raw` returns the raw `ReadResult` from the backend without
following redirects or materializing local-delegate files; the REST
gateway uses it to surface `ReadResult::Redirect` as `307` and stream
`ReadResult::LocalDelegate` directly to the caller. `write_redirect`
is a body-less entry that resolves the route and asks the plugin for
redirect requests directly — used by the broker's gRPC `WriteRedirect`
handler. `continue_write` feeds executed redirect results back to the
plugin and returns either the final `WriteResult` (`WriteStep::Done`)
or another `WriteStep::Redirects` for multi-stage multipart uploads.

The trait carries only the signatures and the contracts they imply;
the type definitions are in
[plugin-development README § Type vocabulary](../plugin-development/README.md#type-vocabulary).

The trait is async (`#[async_trait]`); pure state-reader methods
(`list_*`, `watch_*` setup, `capabilities_for`) stay synchronous
because they only touch in-memory state. `list` and `list_versions`
return finite vectors, and `Library::list_page` returns a
`ListPage { items, next_page_token }` struct for boundary APIs that
need paging. `read_stream` returns an async
`futures::Stream<Item = Result<bytes::Bytes>>`; `watch_directory`,
connection watches, alias watches, and auth events are synchronous
boxed iterators (`Box<dyn Iterator<Item = Result<…>> + Send>`)
returned by an async setup call — those are notification-rate watch
channels, not data paths, and the iterator shape is fine for them.

For API framing, treat `Storage` as one trait with four groups. The
first two groups together are the object-addressed core; the split
below keeps byte-moving I/O distinct from adjacent control:

- **Object I/O:** `stat`, `read_bytes`, `read_stream`, `materialize`,
  `write`, `delete`, `list`, `list_versions`, `copy`, `rename`,
  `create_directory`, `delete_directory`, `update_metadata`.
- **Object-adjacent control:** `check_access`, `capabilities_for`;
  `watch_directory` joins this group when change notifications land.
- **Routing and connection management:** `list_address_roots`,
  connection add / remove / list / watch / credential update, alias
  add / remove / list / watch, visibility overrides.
- **Authentication streams:** `authenticate_connection` and
  `watch_auth_events`.

The first group is the data-plane surface application authors usually
learn first. The other groups are still public API; bindings and the
CLI expose them rather than inventing crate-specific management APIs.

## Listing, versions, and paging types

```text
pub enum ObjectKind { File, Directory, DirectoryMarker, DirectoryInferred }

pub struct ListPage {
    pub items:           Vec<ObjectInfo>,
    pub next_page_token: Option<String>,
}

pub struct VersionPage {
    pub items:           Vec<ObjectInfo>,
    pub next_page_token: Option<String>,
}
```

`list` returns `ObjectInfo` values directly. `ObjectInfo.kind`
distinguishes files from directories, so a non-recursive list can
return object entries and immediate child directory entries in the
same vector; recursive lists return the subtree and include directory
facts (`Directory`, `DirectoryMarker`, or `DirectoryInferred`). On
flat backends, descendant objects imply missing inferred ancestor
directories. Display names are derived from the listed prefix and each
returned `ObjectInfo.address`; they are not a separate API field.

`list_versions` is public API because versioned-object workflows need
caller-facing, version-pinned addresses. The dispatcher calls the
plugin's `list_versions`, projects each returned `ObjectInfo.address`
into the caller-facing namespace, and leaves the backend-native
version pin in the address. `get_latest_version` returns the same
shape for one address: if the input is unpinned, the returned
`ObjectInfo.address` pins the current head; if the input is already
pinned, it describes that exact version. Ordering is whatever the
backend naturally produces;
`Capabilities.supports_version_listing` gates the operation, and
`Capabilities.version_list_order` tells callers whether the native
order is `Newest`, `Oldest`, or `Unordered` when listing is supported.

Rust callers consume finite `Vec<ObjectInfo>` values from the trait.
Boundary APIs that need page envelopes use
`ListPage` / `VersionPage`; the page token is opaque and is owned by
the library/adapter, not by application code.

## Change-notification types

```text
pub enum ChangeEvent {
    Object {
        address:  ObjectAddress,
        kind:     ChangeKind,
        etag:     Option<String>,
        at:       SystemTime,
        cursor:   WatchDirectoryCursor,
    },
    Lapsed {
        since:  Option<SystemTime>,
        cursor: WatchDirectoryCursor,
    },
}
```

`watch_directory` streams are at-least-once with explicit gap
signaling. Events are best-effort. Ordering within a single object's
URL is preserved when the native feed preserves it. Total ordering
across a prefix is **not** guaranteed. Whenever the plugin knows it
has dropped events, it emits an explicit
`ChangeEvent::Lapsed { since }` and the caller is responsible for
re-listing if correctness matters. `ChangeKind` and
`WatchDirectoryCursor` are defined in
[plugin-development README § Type vocabulary](../plugin-development/README.md#type-vocabulary).

## Address-root introspection types

```text
pub struct AddressRoot {
    pub address:        ObjectAddress,
    pub display_name:   Option<String>,
    pub backend_kind:   String,
    pub connection_id:  Option<ConnectionId>,
    pub capabilities:   Capabilities,
    pub source:         RouteSource,
    pub visibility:     AddressVisibility,
    pub user_metadata:  UserMetadata,
}

pub enum RouteSource {
    Static { layer: ConfigLayer },
    ConnectionContributed { connection_id: ConnectionId },
    BrokerDelivered { broker_principal: String, connection_id: ConnectionId },
    Alias { to: ObjectAddress, alias_source: AliasSource },
}

pub enum AliasSource {
    Static { layer: ConfigLayer },
    Runtime { added_by: Option<PrincipalView>, persisted: bool },
    BrokerDelivered { broker_principal: String },
}

pub enum AddressVisibility {
    Visible,
    Hidden,
    Suppressed,
}

pub enum ConfigLayer { Programmatic, Env, Project, User, Machine }
```

## Routing-table types

The routing table is the merge of three sources, all producing rows
keyed by **absolute `ObjectAddress`** — there is no library-side URL
composition (plugins own all URL knowledge; see
[plugin-development README § Surface boundary](../plugin-development/README.md#surface-boundary)):

1. **Static rows** — programmatic config, env, project, user, machine
   config. `RouteSource = Static { layer }`.
2. **Connection-contributed rows** — every address returned by an
   active connection's `StorageBackend::address_roots` becomes a row.
   `RouteSource = ConnectionContributed { connection_id }` for direct
   connections, `BrokerDelivered { broker_principal, connection_id }`
   for addresses flowing in through a `broker-client` connection.
3. **Alias rows** — every alias produces a row whose `from` is the
   row's address and whose `to` is an `ObjectAddress` somewhere else
   in the table. `RouteSource = Alias { to, alias_source }`.

```text
pub struct RouteRow {
    pub address:          ObjectAddress,
    pub backend_instance: Option<BackendId>,    // None for alias rows
    pub capabilities:     Capabilities,
    pub source:           RouteSource,
    pub visibility:       AddressVisibility,
    pub display_name:     Option<String>,
    pub user_metadata:    UserMetadata,
}
```

Resolution is **prefix-only and longest-prefix wins**. Equal-prefix
conflicts are resolved by source priority. Configuration sources, in
order of precedence (highest first): programmatic > env > project >
user > machine > broker-delivered.

The `Storage` trait above is the abstract operation surface; generic
code can be written once and run against either a real `Library` or a
test double that implements the same trait.
