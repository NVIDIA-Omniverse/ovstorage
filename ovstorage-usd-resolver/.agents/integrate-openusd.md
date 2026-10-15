# Integrate OpenUSD

Start with:

1. [`examples/embed_resolver/`](../examples/embed_resolver/)
2. [`docs/architecture.md`](../docs/architecture.md)
3. [`docs/configuration.md`](../docs/configuration.md)
4. [`docs/compatibility-matrix.md`](../docs/compatibility-matrix.md)

Integration reminders:

- acquire the exact 0.1 Linux x86_64 SDK with
  `python3 tools/dependencies/acquire_openusd_sdk.py --output
  .deps/openusd/25.11.kit.4-gl.21081`; other OpenUSD 25.11 distributions are
  not release-tested or assumed binary-compatible;
- install the platform OpenGL development package before linking the plugin
  (`libgl1-mesa-dev` on Debian or Ubuntu Linux);
- build the optional plugin target with
  `-DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON` and
  `-DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081`;
- build and run the source-consumer proof with
  `-DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON`; its subprocess smoke requires an
  ovstorage SDK layout that includes provider plugins;
- create a `ResolverRuntime` from `ResolverOptions`, wrap it with
  `makeOpenUsdResolverContext()`, and either pass that context explicitly or
  bind it with `ArResolverContextBinder` before opening remote USD;
- a host that builds the process's one ovstorage stack adopts it with
  `include/ovstorage_usd_resolver/host.hpp` instead of composing a second one,
  and registers through `openusd_host.hpp`: register with the dispatch check
  deferred before any OpenUSD use, choose any preferred primary resolver, then
  call `verifyResolverDispatch()` and treat a failure as fatal. Keep the copy
  that built the stack, and its provider plugins, loaded until the runtime is
  released. That happens only when the last stage, binder or context copy that
  holds it is gone, not when the host drops its own handle. Every copy of
  ovstorage's C runtime in the process, the host's included, keeps its
  `ovstorage_*` symbols out of the global scope. In a host that is itself a
  shared library, `-Wl,--exclude-libs,ALL` does that for an archived copy such
  as this package's; a copy compiled from ovstorage's C sources into the
  library needs hidden visibility or a version script (see `host.hpp` for the
  rule and how to check a prebuilt library). An exported handle is accepted
  only from trusted in-process code.
  The header is C++17, but building `ovstorage::usd_resolver_host` from source
  needs the concrete bridge's C++20 compiler floor (GCC 13+, Clang 17+ or MSVC
  19.40+); a GCC 11 builder needs the bridge's C++17 port first;
- distinguish process registration from thread-local binding:
  `setDefaultResolverRuntime` selects the process default, while
  `ArResolverContextBinder` and `ScopedDefaultContext` must wrap OpenUSD work
  on each worker thread;
- configure its concrete bridge with either a host-built `LayerHandle` or an
  ovstorage StackConfig path. For the latter, supply a trusted generic plugin
  directory when the graph uses kinds other than built-in `file`;
- set `ResolverOptions::remoteUriSchemes` to the schemes that context may use;
  it can narrow but not widen the build-time list, and disabled schemes do not
  reach the storage bridge;
- enable `ResolverOptions::resolveVerifiesExistence` for legacy-replacement
  hosts whose clients treat a nonempty `Resolve()` as an
  existence signal; keep the generic default off for hosts that want the
  scheme-only low-latency path;
- prove local USD still works without ovstorage;
- prove remote USD uses ovstorage;
- keep public S3-backed HTTPS proof distinct from native `s3://` proof;
- keep S3 endpoint, compatibility-profile, and credential configuration in
  the ovstorage graph. Resolver 0.1 is release-qualified against AWS S3;
  non-AWS S3-compatible profiles are inherited ovstorage capabilities unless
  separately qualified by this repository;
- keep native `hf://` identifiers intact and let ovstorage's Hugging Face
  provider follow its own redirects; configure renderer-side MDL and texture
  consumers separately because they are outside this resolver;
- verify package/USDZ behavior with a materialized remote outer package,
  including absolute dependencies that select another advertised scheme;
- treat `UsdStage::Open` returning non-null as necessary but insufficient:
  assert expected prims/layers, zero composition errors, and zero failed
  resolver trace events for composed-scene acceptance;
- report failures with resolver, OpenUSD, ovstorage, and backend boundaries
  clearly separated.

For optional locally built Python packages and their consumer validation, follow
[the local Python package guide](../docs/python-wheels.md). Do not substitute `usd-core` for
the selected Kit nopy ABI or claim that the wheel supplies USD Python bindings.
