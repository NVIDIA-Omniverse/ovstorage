# Integrate ovstage

Start with the generic OpenUSD integration contract in
[`integrate-openusd.md`](integrate-openusd.md), then apply these host-specific
requirements:

- register the resolver plugin before the first `ArGetResolver()` call;
- choose any preferred primary resolver (`ArSetPreferredResolver`) before
  verifying dispatch or binding a context, because both construct OpenUSD's
  resolver and a preference set afterwards is silently ignored;
- treat a failed dispatch check as fatal at startup: when the primary resolver
  can also open a scheme, a late registration loads remote scenes through it
  with no error;
- construct the ovstorage-backed resolver runtime before creating the ovstage
  instance. A host that owns the process's ovstorage stack hands it over with
  `host.hpp` (`createRuntimeForStack`, `createRuntimeForSharedStack`) and uses
  `openusd_host.hpp` for registration, the dispatch check and the context.
  `host.hpp` is a C++17 header, but building its `ovstorage::usd_resolver_host`
  library from source needs the concrete bridge's C++20 compiler floor (GCC
  13+, Clang 17+ or MSVC 19.40+); a GCC 11 builder needs the bridge's C++17
  port first;
- set `ResolverOptions::resolveVerifiesExistence` to `true` because this host
  treats a nonempty `Resolve()` result as an existence signal;
- carry the captured `ArResolverContext` onto worker threads and bind it around
  OpenUSD work;
- expose resolver, ovstorage, and provider failures through application
  diagnostics; and
- leave renderer-side MDL and texture IO with the host's separately configured
  asset system.

The embedding host owns resolver registration and its exact USD ABI. Do not
assume an OVStage binary bundles this resolver or exposes the storage adapter
from an integration prototype. A Python binding around a host call does not
implicitly bind host-created worker threads. Verify the actual consumer SDK
and adapter, including worker context propagation, in an installed OVStage test.
The resolver has no OmniClient or Carbonite dependency; that is not a promise
of Nucleus support in the default scheme profile.

`CONFIG` and `BORROWED_STACK` describe the ovstage integration adapter modes,
not resolver API options or a guarantee about every published OVStage build. A `CONFIG` integration supplies an ovstorage StackConfig path and
trusted plugin directory. A `BORROWED_STACK` integration supplies a host-built
`LayerHandle`. Both modes construct the same resolver `StorageBridge` and use
the same OpenUSD context contract.
