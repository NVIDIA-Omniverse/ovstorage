# Configuration Contract

The resolver supports both standalone OpenUSD usage and embedded application
usage. Configuration is explicit so that multiple
stages, jobs, or tests can run without accidentally sharing unsafe global
state.

## Runtime Properties

- Local USD files work without ovstorage.
- Remote USD identifiers require ovstorage and fail clearly when ovstorage is
  missing or misconfigured.
- The product API must not require a process-global raw library handle.
- Host applications can configure resolver behavior before opening remote USD.
- Diagnostics can be run before the first remote OpenUSD operation.
- Materialized-file lifetime is owned by the storage bridge; the resolver
  keeps only the bridge-supplied lease and drops it when the caller is done.

## Configuration Inputs

Hosts configure the resolver by building a `ResolverOptions` value (declared in
`include/ovstorage_usd_resolver/configuration.hpp`) and passing it to
`createResolverRuntime()`. Its fields are:

- `remoteUriSchemes` — the URI schemes this runtime treats as remote (must be a
  subset of what the build advertises via `OVS_USD_RESOLVER_URI_SCHEMES`;
  narrowing is enforced by identifier creation, resolution, metadata, open,
  and write paths; widening is rejected at validation time). Disabled schemes
  fail closed before the runtime calls its storage bridge.
- `isolationKey` — a per-stage/per-job label hosts may use for their own
  bookkeeping. Not a security boundary and not used to partition any
  resolver-owned state.
- `storageBridgeFactory` — host-provided factory invoked once when the runtime
  builds its storage bridge. The default (`unavailableStorageBridgeFactory`)
  returns a bridge that reports every operation as unavailable, so a missing or
  mis-wired factory produces a resolver-owned diagnostic instead of a crash or
  hidden fallback.
- `traceSink` — optional callback invoked at selected resolver/runtime
  operation boundaries and raw-input points. Before invocation, identifiers
  lose URI userinfo and sensitive query, fragment, and SDF-argument values;
  URI-shaped tokens in status/detail messages receive the same treatment.
  The emitted event families are `create_identifier.*`, `resolve.*`,
  `resolve_for_new_asset.*`,
  `open_asset.*` (including a `open_asset.raw_input` for the pre-normalization
  identifier handed by OpenUSD), `stat.*`, and `write.*`, plus
  `modification_timestamp.raw_input` and `asset_info.raw_input` on the
  metadata paths. Compatibility probing additionally emits
  `resolve_existence_cache.{hit,miss,wait,coalesced,invalidate}`. Hosts own
  sink synchronization; the resolver may invoke it from multiple threads.
- `resolveVerifiesExistence` - when true, `_Resolve()` stats a claimed remote
  object through the bound runtime before returning it. `Success`
  returns the normalized path, authoritative `NotFound` returns empty, and all
  other failures preserve the path so later IO can report the real auth,
  routing, or backend error. One exception: an identifier whose path names a
  UDIM tile set (`<UDIM>`, `<UVTILE0>` or `<UVTILE1>`, each delimiter raw or
  percent-encoded) is a set of objects, not one, so it resolves to itself
  without a stat, whether or not any tile exists; the consumer that expands
  the tiles checks them. A nonempty `Resolve()` therefore does not prove that a
  tile set has tiles. Concrete tiles, and tags outside the path (SDF format
  arguments, a package's inner path, the URI's query or fragment), keep the
  check. See D-0010. The generic default is false. Legacy-replacement
  hosts enable it when their clients use a nonempty `Resolve()` result as an
  existence signal.
- `resolveExistencePositiveTtl` and `resolveExistenceNegativeTtl` - retention
  periods for successful and authoritative missing results. Defaults are five
  seconds and one second. Zero disables retention for that result class;
  negative durations fail option validation.
- `resolveExistenceCacheMaxEntries` - hard per-runtime metadata-entry bound,
  default 4096. Least-recently-used entries are evicted at the bound. It must
  be nonzero when existence verification is enabled.

Provider selection, credentials, endpoint configuration, and read-policy knobs
(range-read strategy, chunk sizes, retries) live on the ovstorage side — either
in the host-built `LayerHandle` handed to `OvStorageBridgeOptions::layerHandle`,
or in the stack configuration file pointed at by
`OvStorageBridgeOptions::configPath`. The resolver has no view into them and no
duplicate resolver-side knobs.

The declarative construction path creates an ovstorage `Registry`, asks
`StackConfig` to parse and build the graph, and does not inspect provider kinds
or URI schemes. Ovstorage seeds that registry with only the built-in `file`
provider. If the TOML names plugin-provided kinds, the host sets
`OvStorageBridgeOptions::pluginDirectory` to an explicitly trusted directory
of native provider libraries: `libovstorage_plugin_*.so` on Linux,
`ovstorage_plugin_*.dll` on Windows, or `libovstorage_plugin_*.dylib` on macOS. The bridge registers every matching
plugin and keeps it alive until after the built `LayerHandle` is destroyed.
Standalone CLI commands map `OVSTORAGE_PLUGIN_DIR` to this field. Hosts that
need an exact plugin allowlist build their own registry and `LayerHandle`, then
use the host-handle path.

`configPath` and `loadDefaultConfig` are mutually exclusive. The latter uses
ovstorage's documented search order (`./ovstorage.toml`, then the XDG user
config path); the CLI selects it when `--stack-config` is omitted.

### Hugging Face read-only example

The shipping scheme list includes `hf`, but registration is not provider
configuration. The host still supplies an ovstorage connection for each Hub
repository it wants to expose. This minimal StackConfig mounts one immutable
dataset revision through ovstorage's Hugging Face plugin:

```toml
[ovstorage]
root = "huggingface"

[ovstorage.layers.huggingface]

[[ovstorage.connections]]
backend_kind = "huggingface"
config = { repo_id = "namespace/repository", repo_type = "dataset", revision = "<commit-sha>" }
```

With the trusted ovstorage plugin directory configured, OpenUSD consumers use
logical addresses such as
`hf://datasets/namespace/repository/path/to/root.usd`. The resolver neither
turns these addresses into HTTP URLs nor implements Hugging Face behavior;
ovstorage owns Hub authentication, routing, and CDN redirects. The shipped
provider is read-only. MDL, texture, and other non-USD consumers in a host need
their own `hf://` integration because this resolver handles USD layers and
packages only.

There is no resolver-owned materialization cache: no cache root, no cache
budget, no LRU. Every `materialize` call returns a `MaterializedAsset` lease
over an on-disk file the concrete storage bridge placed (and, for the shipped
ovstorage bridge, the ovstorage runtime GCs). Hosts that want a global
materialization-size budget configure it on the ovstorage layer.

The optional Resolve-existence cache is separate metadata-only state. It is
owned by one `ResolverRuntime`, coalesces concurrent first probes for the same
provider key, and stores only success and authoritative `NotFound`. A
successful resolver write invalidates the affected key, including suppression
of an older probe that was still in flight. External changes become visible
after the configured TTL. Package inner paths and SDF format arguments share
the outer provider-object key.

`createResolverRuntime()` is the core runtime hook. It validates
`ResolverOptions`, constructs the configured bridge, and returns an explicit
runtime handle. Multiple runtime handles can coexist in one process.

OpenUSD callers bind explicit runtime handles through `ArResolverContext` with
`makeOpenUsdResolverContext()`. The resolver's `_OpenAsset` path requires that
bound context for remote reads and fails closed when no resolver context is
bound. The bound runtime also determines the active scheme subset, so different
contexts in one process can enable different portions of the compiled list and
can disagree about the existence of the same URI without cache leakage.

## Standalone Usage

Source consumers follow the [build guide](building.md) for the supported
host SDK layout and ovstorage 0.3.x. No resolver wheels are published for this
release. An [optional locally built Python package](python-wheels.md) provides
explicit registration and runtime binding for the pinned SDK. For a source build:

1. point `PXR_PLUGINPATH_NAME` at the build tree's `plugInfo.json`;
2. run `doctor` to validate CLI setup and ovstorage bridge
   availability;
3. open a remote USD through OpenUSD;
4. run `materialize` or `trace` for debugging.

No renderer or OV application is required for this path.

## Embedded Usage

Embedded applications configure the resolver before the first OpenUSD resolver
selection. In particular, they do not select or replace
the resolver after OpenUSD has already initialized `ArGetResolver()`.

For remote asset reads, embedded applications:

1. build a `ResolverOptions` value;
2. enable `resolveVerifiesExistence` when replacing a legacy resolver contract
   that treats nonempty `Resolve()` as proof of existence;
3. call `createResolverRuntime()`;
4. create an OpenUSD resolver context with `makeOpenUsdResolverContext()`;
5. pass that context to `UsdStage::Open(path, context)` when opening a stage;
6. bind that context with OpenUSD's thread-local `ArResolverContextBinder` on
   each thread that performs lower-level direct resolver or asset operations.

Passing the context into `UsdStage::Open` is the preferred stage-composition
contract. It keeps the ovstorage runtime available for sublayers, references,
payloads, and package-internal assets that OpenUSD resolves after the root
layer starts loading.

`setDefaultResolverRuntime` registers a process-wide runtime choice used when
creating a default context; it does not bind that context across threads.
`ScopedDefaultContext` wraps the same thread-local binder, so create one around
OpenUSD work on every worker thread or pass the context explicitly.

Ownership is divided as follows:

- the host owns the ovstorage context or configuration;
- the host provides the bridge factory before remote USD use;
- the resolver owns OpenUSD identifier and asset behavior;
- ovstorage owns provider-specific IO and owns the on-disk materialized bytes
  (the resolver holds a bridge-supplied `LocalLeaseHandle`, not a byte cache);
- the host owns application-specific non-USD asset IO.

## Bridge Contract

The resolver calls ovstorage through the narrow, fake-testable
`StorageBridge` interface. It exposes:

- whole-object and range reads;
- stat and object metadata;
- bridge-owned local materialization leases;
- whole-object writes with explicit destination preconditions;
- aggregate and per-address capability checks;
- per-address owning-target lookup for adapter diagnostics; and
- normalized storage status and error codes.

The bridge contains no:

- provider SDK calls;
- hidden omniclient calls;
- private endpoint assumptions;
- process-global raw handles as the product configuration API.

## Materialization directory permissions

The concrete bridge creates lease files atomically in the system temporary
directory and removes them when the lease ends. POSIX files have mode 0600.
Windows files inherit the temporary directory's DACL; CRT read/write flags do
not create an owner-only ACL. Windows hosts must select a per-user temporary
directory with access limited to the application identity and trusted
administrators before starting the process. A shared writable/readable TEMP
directory does not provide confidentiality for materialized assets.
