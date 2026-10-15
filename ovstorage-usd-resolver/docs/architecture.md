# Architecture Reference

## Runtime Flow

```text
USD application
  |
  | opens root layer
  v
OpenUSD
  |
  | local file path
  v
OpenUSD local filesystem resolver
  |
  v
local disk
```

```text
USD application
  |
  | opens remote root layer or remote dependency
  v
OpenUSD
  |
  | http://, https://, s3://, hf://, package path with remote outer asset
  v
ovstorage USD resolver
  |
  | read/stat/range/materialize
  v
ovstorage
  |
  | provider-specific implementation
  v
configured ovstorage provider
```

The resolver composes USD layers and resolves USD asset paths. It can also be
used standalone with ovstorage to validate or materialize USD assets without
rendering them.

## Local vs Remote Behavior

Local files continue through OpenUSD's normal filesystem path. Ovstorage is
not required for ordinary local USD workflows.

Remote identifiers claimed by this resolver use ovstorage. If ovstorage is
missing, unavailable, or cannot access a backend, the resolver returns a
categorized failure rather than falling back to another storage path.

## Resolver Registration Posture

The resolver registers as a URI resolver for the build-advertised URI schemes
(`OVS_USD_RESOLVER_URI_SCHEMES`; shipping default `s3;http;https;hf`). OpenUSD's
default filesystem resolver continues to own local paths — the ovstorage
resolver never claims them.

Registration mode is set through the resolver plugin's `plugInfo.json`
metadata: the `uriSchemes` array lists the same normalized scheme set the
compiled claim gate consumes, and OpenUSD reads it at plugin discovery to
build its URI dispatch table. Runtime `ResolverOptions::remoteUriSchemes` may
narrow that list per-runtime but cannot widen it (validation rejects a scheme
not in the build-advertised set, because OpenUSD's `Ar` dispatch table is
locked at plugin discovery and would never route a runtime-only scheme).
Identifier creation, resolution, metadata, open, and write paths all enforce
the subset from the bound context before calling the storage bridge.
Direct runtime calls apply the same gate to remote identifiers claimed by this
build; non-claimed identifiers such as `file:` remain available to bridge-level
diagnostics without making this OpenUSD resolver their owner.

This shape keeps local USD workflows on the OpenUSD default path with no
resolver-side risk, and confines ovstorage's blast radius to the identifiers
this resolver actively claims.

## ovstorage Boundary

The resolver calls ovstorage through the narrow `StorageBridge` contract. It
exposes only the operations used by the resolver:

- whole-object and range reads;
- stat and object metadata;
- bridge-owned local materialization leases;
- whole-object writes with explicit destination preconditions;
- aggregate and per-address capability checks;
- per-address owning-target lookup for adapter diagnostics; and
- normalized storage status and error codes.

The resolver does not call provider SDKs directly.

The host-provided ovstorage `LayerHandle` is the sole operational router.
`stat`, read, materialize, and write calls reach it without a resolver-side
route preflight. Per-address capability and ownership decisions use
`LayerHandle::root_info_for()`, which shares ovstorage's aliasing,
canonicalization, and live route table. `list_address_roots()` is retained only
for aggregate advisory capabilities; discovery failure does not make otherwise
routable data operations fail.

## Write Boundary

`ArResolver` writes are whole-provider-object operations. The write target is
normalized once before capability lookup or local staging; SDF format
arguments are removed because they select file-format behavior rather than a
different stored object. A package-inner identifier is rejected before
materialization or PUT. Callers replace an outer USDZ only by naming the outer
package directly; editing individual package members is outside the resolver's
write contract.

`ArResolver::WriteMode` controls local staging and the close-time storage
condition. `Replace` starts from an empty file and uploads with overwrite
semantics. `Update` seeds from the existing object and preserves every byte
outside ranges written by the client. A missing `Update` target starts from an
empty seed and closes with a create-only precondition, so a concurrent creator
produces `Conflict` instead of being overwritten. The resolver never infers a
new logical EOF from the highest offset written; clients request `Replace` for
whole-object replacement.

Writable assets stage in a uniquely created private directory. The
suffix-bearing target file is created exclusively before OpenUSD opens it, so
format dispatch retains `.usd`, `.usda`, `.usdc`, or another validated suffix
without a check-then-open pathname race. Cleanup removes the owned directory,
including any sibling left by a failed `TfSafeOutputFile` rename, before a
failed local close can reach the provider PUT.

For an existing `Update` target, the selected route's If-Match capability
controls the close precondition. A capable route requires a nonempty ETag from
the seed materialization; missing or empty validators abort the open. Routes
without If-Match support use overwrite even if materialization returns an ETag.
A rejected conditional close is never retried as overwrite. Other materialization
failures abort the open rather than turning into a create.

The bridge contract is represented in
`include/ovstorage_usd_resolver/storage_bridge.hpp`. It deliberately models
capabilities and normalized resolver-facing errors before choosing whether the
concrete ovstorage binding is linked directly, loaded dynamically, or provided
by an embedding host.

Layering (two files, two responsibilities):

- `storage_bridge.hpp/.cpp` — the resolver-facing **contract**. Declares the
  abstract `StorageBridge` interface, the value types the resolver hands
  callers (`StorageStatus`, `Capabilities`, request/response records), and
  the always-available `UnavailableStorageBridge` used when no concrete
  backend is configured.
- `ovstorage_stack_bridge.hpp/.cpp` — one **concrete implementation** of that
  contract, backed by an ovstorage `LayerHandle`. Provides
  `OvStorageBridgeOptions`, the `createOvStorageBridge` /
  `ovStorageBridgeFactory` entry points, and the internal
  `OvStorageStackBridge` class the factory returns. Additional implementations
  (host-provided stacks, in-memory bridges for tests) can be added alongside
  it without touching the contract.

The resolver core links against the contract; the concrete implementation is
optional at build time. no-SDK builds link `storage_bridge` only and report
`UnavailableStorageBridge` through the runtime.

Configuration uses a host-provided bridge factory plus explicit resolver
scope. This lets standalone tools and embedded hosts
create resolver-owned bridge instances without relying on a
process-global raw ovstorage handle.

## Configuration

The configuration model supports standalone OpenUSD usage, embedded
application initialization, and optional diagnostic tracing, and does not
require any private endpoint to be baked into docs or tests.

`ResolverOptions` carries the resolver-facing pieces of that model: a storage
bridge factory, an optional trace sink, an isolation key hosts may use as a
per-stage/per-job label, the per-runtime remote scheme list, and an opt-in
legacy-compatible Resolve-existence policy. The
configuration API does not use a process-global raw ovstorage handle — hosts
build their own bridge (or point at a stack-config file) and hand it to the
resolver through the factory.

See [configuration.md](configuration.md) for the field-by-field contract and
the host/bridge/resolver ownership split.

### Diagnostic boundary

Storage operations use exact identifiers and return provider status messages
unchanged to their direct caller. Before a trace event crosses into a
host-provided `ResolverTraceSink`, the runtime removes URI userinfo and hides
query values, fragment values, and SDF format arguments from identifiers. It
also redacts URI-shaped tokens in both trace status messages and event detail.
This keeps a host from accidentally persisting credentials merely by enabling
tracing. The CLI applies the same policy before storing doctor records and
before formatting other passive command output and errors. Exact `resolve`
output remains functional data rather than a passive diagnostic.

## Package and USDZ Boundary

USDZ support separates a remote outer package from its package-relative inner
paths. The resolver materializes the outer provider object to a leased local
file when OpenUSD asks it to open that object; OpenUSD's package resolver then
seeks and reads the package contents.

Implemented behavior:

- remote outer package path is resolved through ovstorage;
- inner path is preserved;
- a relative dependency authored inside a package remains package-relative,
  while an absolute URI with another advertised scheme leaves the package and
  resolves through that scheme on the same runtime;
- SDF format arguments are preserved;
- materialized package files are scoped and cleaned up;
- errors distinguish missing outer package from missing inner package.

OpenUSD's built-in package resolver owns the contents of the materialized
package. The ovstorage resolver resolves, preflights, reads, or materializes
the remote outer package while preserving the full package identifier for
OpenUSD package machinery.

## Cache Boundary

The resolver holds no materialized-byte cache. Every `ResolverRuntime::materialize`
call goes straight through the storage bridge; the bridge returns a
`MaterializedAsset` whose opaque `LocalLeaseHandle` keeps the local
file alive until the asset drops. The ovstorage runtime (or, for the
HTTP fallback, the bridge-owned `TempFileLease`) owns the on-disk
bytes and picks its own GC cadence.

When `ResolverOptions::resolveVerifiesExistence` is enabled, the runtime does
hold a bounded metadata-only cache for `_Resolve()` stat results. It is scoped
to one runtime/context, caches only success and authoritative `NotFound`, uses
separate positive and negative TTLs, and coalesces concurrent same-key probes.
Package inner paths and SDF format arguments key the remote outer object. A
successful resolver write invalidates that key and prevents an older in-flight
probe from repopulating it. Authentication, routing, transient, and backend
failures are never cached as absence.

The concrete bridge requires ovstorage's `Error::code_name()` API. Only an
object-operation error with coarse `NotFound` and fine-grained `NotFound`
is authoritative absence. `NotConfigured` and no-route failures map to
`Unsupported`; missing or unrecognized identity maps to `BackendError`.
Setup failures (configuration loading, stack construction, plugin loading)
never describe missing USD objects, even if ovstorage reports `NotFound`.
Classification does not inspect human-readable error messages.

Direct runtime callers can request ranges through `StorageBridge::read` with
an offset and length. OpenUSD asset opening uses bridge materialization because
`ArAsset` needs a stable backing object; the bridge falls back to a whole-object
read when a provider does not supply native local materialization.

`include/ovstorage_usd_resolver/materialization_cache.hpp` exposes only the
`MaterializedAsset` lease type despite its filename; the resolver has no
materialized-byte cache API.

Two concrete lease shapes ship with the resolver:

- The concrete ovstorage bridge routes to
  `LayerHandle::read_local_file` and, on success, hands back a lease
  wrapping the ovstorage runtime's own `::ovstorage::LocalDelegate`.
  The bridge reads `LocalDelegate::info()` before moving the delegate into
  that lease, so the local bytes and returned metadata describe one
  materialization operation; it never follows a successful materialization
  with a separate `stat`.
  Dropping the delegate asks the ovstorage runtime to GC the local
  file per its own policy — resolver-side eviction, budget, and LRU
  are gone with the cache. This is the path the `file` layer takes.
- Backends whose Layer surface does not implement `read_local_file`
  (including the shipped HTTP plugin) fall back to a bridge-owned
  `TempFileLease`: the bridge reads bytes and writes them to a temp
  path whose lease unlinks the file on drop. The resolver's public
  header still sees only the type-erased `LocalLeaseHandle`; no
  ovstorage type leaks.

`MaterializedAsset` is move-only; ordinary destruction runs the
lease's deleter and releases the file. There is no `release()` verb
— `::ovstorage::LocalDelegate` has no detach API, so a resolver-side
`release()` returning only a path would either be unsafe or would
require an ovstorage-side extension. Callers that need the file
beyond the lease's lifetime `std::filesystem::copy_file` before the
`MaterializedAsset` drops. The CLI's `materialize --out` command is
the one in-tree consumer that needs this and does exactly that.

Concurrent `materialize` calls are independent by construction: the runtime
holds no per-identifier mutex or byte cache, calls the bridge for each request,
and receives a separate lease for each result.

## Search-Path Boundary

Search-path semantics ship as follows: remote roots are explicit only. A bare
asset path never becomes a remote lookup on the ovstorage side — OpenUSD's
default resolver keeps ownership of bare-root asset paths and applies its own
search-path behavior. Relative dependencies of an explicit remote layer
(sublayers, references, payloads, package-internal assets) anchor to the
remote layer's URL and route through this resolver.

The rule the resolver enforces: an ovstorage-owned identifier must arrive
either as an absolute URI in one of the build-advertised schemes, or as a
relative reference resolved against a remote base. Bare asset paths with no
remote anchor stay with OpenUSD's default resolver.

## No-omniclient Boundary

For this repo, "no hidden omniclient dependency" means:

- the resolver does not link against omniclient;
- the resolver does not load omniclient to resolve or materialize USD assets;
- required tests do not need Nucleus or omniclient services.

It does not claim that every possible downstream consumer has removed all
legacy byte-IO paths.

## Legacy Resolver Coexistence

The coexistence posture is: one resolver owns each URI scheme in a
process. The resolver claims the build-advertised URI schemes
(`OVS_USD_RESOLVER_URI_SCHEMES`; shipping default `s3;http;https;hf`).
A host may add schemes when it supplies matching ovstorage routes and ensures
that no other resolver registers the same schemes. For example, with the
legacy Omni USD resolver installed, the default configuration leaves `omni`
and `omniverse` with that resolver. The ovstorage resolver can instead own
those schemes when configured accordingly; this is not a transport restriction.
Without another registered owner, an unadvertised scheme is not made usable
by installing this resolver. Duplicate ownership has no supported precedence
contract, including for `http` and `https`.

Registering a Nucleus-backed route does not provide service-specific workflow
APIs such as live edit, subscriptions, checkpoint history/restoration or
checkpoint-message controls. Those belong to provider/application integration;
ordinary object resolution and writes still follow the route's capabilities.

## Related Repositories

- `ovstorage`: storage library and provider behavior.
