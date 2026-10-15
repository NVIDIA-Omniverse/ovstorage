# Develop Resolver

Start with:

1. [`docs/architecture.md`](../docs/architecture.md)
2. [`docs/api-stability.md`](../docs/api-stability.md)
3. [`docs/configuration.md`](../docs/configuration.md)
4. [`docs/test-strategy.md`](../docs/test-strategy.md)
5. [`docs/decisions/README.md`](../docs/decisions/README.md)

Implementation rules:

- keep the OpenUSD resolver integration in C++;
- keep the ovstorage calls behind a narrow bridge;
- treat the supplied `LayerHandle` as the routing authority: data operations go
  directly to it, per-address decisions use `root_info_for()`, and discovery
  snapshots are not raw-prefix-matched;
- extend `include/ovstorage_usd_resolver/storage_bridge.hpp` before adding
  resolver code that needs more storage behavior;
- treat materialization as bridge-owned: the resolver receives a
  `MaterializedAsset` (an opaque `LocalLeaseHandle` plus `localPath`) from
  the bridge and keeps the lease alive for as long as it needs the local
  bytes — see `StorageBridge::materialize` in
  `include/ovstorage_usd_resolver/storage_bridge.hpp`;
- extract metadata from `LocalDelegate::info()` before moving the delegate
  into its lease; do not issue a second stat after materialization;
- do not add resolver-side materialized-byte caches, byte budgets, or a
  `release()`-style path-detach on top of the lease; there is no
  resolver-owned materialization cache, and `MaterializedAsset` is
  intentionally move-only with no detach verb. The one distinct metadata
  cache is the bounded per-runtime Resolve-existence cache controlled by
  `ResolverOptions`; keep it separate from byte ownership (see
  `docs/architecture.md` "Cache Boundary" for both invariants);
- callers that need a file past the lease's lifetime must
  `std::filesystem::copy_file` before the `MaterializedAsset` drops;
- keep shared runtime options in
  `include/ovstorage_usd_resolver/configuration.hpp`;
- use the configured `StorageBridgeFactory` for storage access instead of
  process-global raw handles;
- treat the resolver's isolation key as a host-facing label only. It is not a
  cache-partition key; Resolve-existence state is already scoped by runtime;
- do not call provider SDKs directly;
- classify concrete ovstorage failures by status and stable `Error::code_name()`,
  never by message text. Only object-operation `NotFound` with that exact
  identity is cacheable absence; setup failures are never object absence;
- do not link or load omniclient;
- preserve SDF format arguments and package identifiers;
- keep writable staging inside an exclusively created private directory;
  suffix preservation must not reintroduce name-then-open temp paths, and every
  failure path must remove the complete owned directory before returning;
- keep `resources/plugInfo.json.in` aligned with resolver registration
  decisions;
- keep local-file fallback explicit in tests;
- redact credential-bearing identifiers and URI-shaped provider messages
  before they enter trace sinks, diagnostic records, logs, or passive CLI
  output; storage operations still receive exact identifiers and `resolve`
  remains an explicitly documented functional-output exception;
- treat every header under `include/ovstorage_usd_resolver/` as public preview
  API; describe consumer-visible changes in `CHANGELOG.md` and update the API
  stability policy when its inventory or compatibility posture changes;
- add or update tests with every behavior change.

Before changing a release-blocking contract, check
[`docs/decisions/README.md`](../docs/decisions/README.md) and update its public
summary with the implementation.

Current local build:

```bash
cmake -S . -B build -DOVS_USD_RESOLVER_BUILD_TESTS=ON
cmake --build build
```
