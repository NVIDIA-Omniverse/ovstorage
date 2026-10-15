# Changelog

All notable changes to `ovstorage-usd-resolver` are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once a
first tagged release ships.

## [Unreleased]

## [0.1.0] - 2026-10-15

Expanded platform preview candidate. This date identifies the candidate's
release-notes snapshot, not a completed public release. No resolver wheels are
published to PyPI or elsewhere for this release. The
entries below record tooling added during preparation, not published artifacts;
prior candidate tags remain unchanged. Final promotion requires
released ovstorage 0.3.0 and release approvals.

### Security

- `resolve` parser errors redact credential-bearing URI arguments and use the
  JSON error envelope when requested. Successful output retains exact identifiers.

### Added

- Add a host-owned stack API for hosts that build the process's one ovstorage
  stack. `host.hpp` adopts a stack built by the same copy of ovstorage's C
  runtime (`createRuntimeForStack`) or exported by another copy
  (`createRuntimeForSharedStack`), without reading configuration or building a
  second stack. The header is C++17; its library,
  `ovstorage::usd_resolver_host`, contains the concrete bridge and builds only
  at that bridge's C++20 compiler floor (GCC 13+, Clang 17+ or MSVC 19.40+).
  Header-only `openusd_host.hpp` registers the plugin with late-registration
  (`Unavailable`) and duplicate-scheme (`Conflict`) diagnostics, and rejects a
  directory that is not the registered plugin's (`InvalidArgument`). It
  verifies dispatch, rechecking scheme ownership and that the plugin library
  loads, and makes the runtime's `ArResolverContext`. The native package
  exports `ovstorage::usd_resolver_host`, built position-independent so a host
  that is itself a shared library can link it. On Linux such a host must keep
  `ovstorage_*` symbols out of its exports itself: `-Wl,--exclude-libs,ALL`
  covers the bundled C runtime, which is linked from a static archive, and a
  copy compiled into the host from ovstorage's C sources needs hidden
  visibility or a version script.
  `createRuntimeForSharedStack` takes ownership of the exported handle unless
  it returns `InvalidArgument`, which means the handle was not touched.

- Add an opt-in relocatable native CMake package with embedding targets,
  headers, plugin metadata, CLI, notices, exact host-USD checks, and native
  installed-consumer qualification. Conan publication remains separate.

- Archive the verified native package per platform as a deterministic
  `tar.gz` or `zip` named by resolver version, exact host USD package version
  and platform, with sha256 sidecars and a combined `SHA256SUMS`, uploaded as
  `wheel-build` workflow artifacts.

- Scan wheel metadata and native string literals for forbidden publication
  references, and remap compiled source/SDK paths to relative diagnostics.

- Tooling for auditing local manylinux_2_35 wheels with explicit external Kit
  SDK metadata. The earlier PyPI publication plan is superseded; no resolver
  wheels are published for this release. Native archive/Conan delivery is a
  separate decision.

- Internal candidate wheel tooling and installed-consumer tests against public
  ovstorage v0.3.0. Private test artifacts are not public release deliverables.
- Optional locally built, flavour-named Python packages with explicit StackConfig construction,
  optional constructor-level exact-SDK verification,
  thread-scoped bindings, eager setup errors, and a relocatable diagnostic CLI.
- Installed-consumer tests using the host Kit USD runtime and exact matching
  ovstorage providers; local wheel validation does not imply publication.

- Native socket and subprocess fixture checks in the no-SDK suite.

- SHA-256-pinned acquisition of the selected Kit OpenUSD SDK on Linux aarch64
  and Windows x86_64, with native extraction/provenance CI.

- No-SDK Release/CTest CI for Linux aarch64, Windows x86_64, and macOS arm64,
  each with default and az-only URI schemes. This covers the core and CLI;
  SDK-backed plugin and wheel qualification remain separate checks.

- A public API stability policy that inventories every exported header and
  distinguishes preview C++/trace surfaces from the stable `0.1.x` CLI JSON
  contract.
- A source-release process with continuous public-tree validation, manually
  cut release-candidate tags, a disposable filtered-source preview branch,
  and explicit promotion of one verified candidate to the final tag.
- A pinned public acquisition helper and exported-source CI proof for the exact
  NVIDIA Kit OpenUSD `25.11.kit.4-gl.21081` SDK used by the 0.1 source build.
- An explicit ovstorage 0.3.x release dependency, with the exact tag recorded
  for final verification; pre-release candidates record their tested source
  revision while the dependency release is pending.
- OpenUSD builds discover the required system OpenGL linker interface, with the
  corresponding development-package prerequisite documented for consumers.
- A root `VERSION` file as the release-version source of truth for CMake and
  release automation.
- OSS standard files: `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  `CHANGELOG.md`.
- Opt-in legacy-compatible `Resolve()` existence verification with a bounded,
  per-runtime positive/`NotFound` cache, concurrent probe coalescing, TTLs, and
  successful-write invalidation. The generic default remains off; Kit/ovstage
  replacement profiles enable it explicitly.
- Default `hf://` registration with the read-only ovstorage Hugging Face provider, with
  offline StackConfig routing coverage and an opt-in live OpenUSD composition
  smoke pinned to a public NVIDIA Hugging Face dataset revision.
- Deterministic remote USDZ coverage for an absolute layer reference that
  leaves the package and resolves through a second advertised scheme.
- A runnable source-consumer example that builds an ovstorage stack, hands its
  `LayerHandle` to the resolver, binds an OpenUSD context, and opens a remote
  stage, plus a deterministic subprocess smoke for the complete path.

### Changed

- Document source consumption for this release: no resolver wheels are
  published to PyPI or elsewhere. This supersedes the PyPI wheel publication
  plan noted under Added; local build and bootstrap tooling remain available.
- Clarify host SDK build restrictions, component working directories and
  scheme registration versus ovstorage provider capabilities. Public agent
  guides no longer direct consumers to excluded maintainer release scripts.

- Build the exported `ovstorage::usd_resolver_ovstorage_bridge` target
  position-independent in every configuration, not only with the Python
  bootstrap, so a direct bridge consumer can link it into a shared library.
  On Linux that library must keep the bundled C runtime's `ovstorage_*`
  symbols out of its exports, with `-Wl,--exclude-libs,ALL` or a version
  script.

- Public release guidance now distinguishes automated source/OpenUSD checks
  from manual exact-candidate provider evidence, configure-time compiler floors
  from the Ubuntu 22.04/GCC 13 qualified baseline, and process runtime
  registration from thread-local OpenUSD context binding. Custom-scheme
  guidance now names both build advertisement and runtime routing.
- Native-S3 compatibility claims now distinguish resolver read/composition
  evidence against AWS S3 from non-AWS endpoint profiles inherited from
  ovstorage.
  MinIO, Cloudflare R2, Backblaze B2, and custom S3-compatible deployments are
  not resolver-qualified platforms in 0.1.
- Documentation reorganized.

- Public headers and CLI help use product terminology; docstrings describe
  what the API does rather than which delivery cycle produced it.
- Documentation repo-name references normalized to the public name
  `ovstorage-usd-resolver`.
- Bridge construction is ovstorage's responsibility. The resolver
  accepts either a pre-built `LayerHandle` on
  `OvStorageBridgeOptions::layerHandle` or a stack-configuration file
  path on `OvStorageBridgeOptions::configPath`; the standalone CLI
  takes the config-file path via `--stack-config <ovstorage.toml>`.
  The prior resolver-side topology block (per-backend flags and
  registry) was removed.
- `MaterializationCache` removed; every materialize call routes
  through the storage bridge and returns an opaque
  `LocalLeaseHandle` lease over the local file. The resolver holds
  no on-disk cache: no `maxCacheBytes`, no LRU, no `release()` verb.

### Fixed

- With `resolveVerifiesExistence`, a UDIM tile-set identifier (`<UDIM>`,
  `<UVTILE0>`, `<UVTILE1>`; each delimiter raw or percent-encoded, escape hex
  digits in either case) resolves to itself without an existence probe,
  instead of empty: no object is ever called `...<UDIM>.png`, so the probe
  always reported `NotFound` and the texture set was dropped. Only a tag in the
  path of the object that would be probed counts; SDF format arguments, a
  package's inner path and the URI's authority, query and fragment do not, and
  concrete tiles keep the check. A pattern resolves whether or not any tile
  exists (D-0010). (#268)

- Choose existing-object Update preconditions from the selected route's If-Match
  capability. Unsupported routes use overwrite even when they return an ETag;
  capable routes reject missing or empty coherent validators before staging edits.

- Preserve an explicitly bound runtime when OpenUSD captures a stage context,
  so sublayers and later reloads retain the same storage configuration.

- Use Winsock and direct native subprocesses for SDK-backed HTTP/CLI fixtures;
  derive provider filenames and file URLs for each host platform.

- Import Windows Kit USD runtime DLLs and import libraries from their native
  SDK locations, and add those directories to the SDK-backed test environment.

- Require C++17 explicitly for the plugin metadata test, including compilers
  whose default language mode predates C++17.
- Create bridge materialization files exclusively on Windows and POSIX,
  preserving binary bytes and format suffixes until lease destruction.
- Discover provider libraries using the native platform filename convention
  and pass configuration/plugin paths to ovstorage as UTF-8.

- Export core runtime symbols on Windows so the separate CLI and test
  executables can link against the shared library.

- CLI parser errors honor `--json` before or after invalid arguments.

- Concrete ovstorage errors retain stable object-absence identity. Missing
  configuration, unknown identity, and stack/plugin setup failures cannot
  become negative-cached missing USD objects. The bridge requires the
  `Error::code_name()` C++ API and preserves actionable error categories.
- Remote OpenUSD writes now use an exclusively created target inside a private
  staging directory, preserving file-format suffixes without a temporary-path
  race and removing any OpenUSD sibling file after close failures.
- Trace callbacks and passive CLI diagnostics now remove URI userinfo and hide
  query, fragment, and SDF-format-argument values before storing or formatting
  identifiers and URI-shaped provider messages. Exact `resolve` output remains
  an explicitly documented functional exception.
- Provider-backed CLI commands now reject local or unadvertised identifiers
  with `scheme_not_owned` before checking optional ovstorage bridge
  availability, and structural no-SDK tests pin the versioned JSON error and
  exit-code contract across default and non-default scheme builds.
- Routed native-S3 test stacks now load and retain ovstorage's core router
  plugin alongside the HTTP and S3 plugins. Live S3 smokes also attach the
  selected AWS credential bundle instead of silently constructing an
  anonymous connection.
- Remote writes now strip SDF format arguments before capability checks,
  Update materialization, PUT, tracing, and existence-cache invalidation.
  Package-inner identifiers are rejected instead of creating a literal
  bracket-bearing storage key or overwriting the outer package.
- Successful `trace --json` output now uses the same stable top-level
  `checks`, `operations`, and `errors` envelope as every other command.

### Release Scope

- Default URI-resolver registration for `http`, `https`, native `s3://`, and
  `hf://`, with write behavior determined by the configured provider;
  local paths continue through OpenUSD's default filesystem resolver.
- Concrete ovstorage bridge (file / HTTP / native S3 / read-only Hugging Face
  backends), with native-S3 read/composition qualification against AWS S3,
  routed alongside the fake bridge used for deterministic unit
  tests.
- Lease-based materialization: the ovstorage runtime owns the
  local-disk bytes; the resolver holds only a lease.
- Diagnostic CLI (`doctor`, `resolve`, `materialize`, `trace`,
  `put`, `benchmark`) with schema-versioned JSON output and a
  categorized error taxonomy for agents.
- Live AWS S3 stage composition smoke gated on
  `OVS_USD_RESOLVER_LIVE_S3_STAGE_URL`; non-AWS S3-compatible endpoint
  profiles remain inherited, unqualified ovstorage capabilities in 0.1.
- Live Hugging Face stage composition smoke gated on
  `OVS_USD_RESOLVER_RUN_LIVE_HF`, with repository and revision fixed in the
  test fixture.
- Pinned Kit OpenUSD `25.11.kit.4-gl.21081` acquisition and native SDK fixture
  CI on Linux x86_64, Linux aarch64, and Windows x86_64.
- Resolver source consumption; no resolver wheels are published to PyPI or
  elsewhere for this release. Optional local installations require their own
  consumer validation. Native archive/Conan delivery remains a separate
  decision; no stable C++ or cross-USD binary ABI promise.
- macOS arm64 is a source portability target, without a qualified binary SDK.

<!--
Compare-URL references are intentionally omitted until publish-time.
Once the public repo is live, add:

  [Unreleased]: https://github.com/NVIDIA-Omniverse/ovstorage-usd-resolver/compare/v0.1.0...HEAD
  [0.1.0]: https://github.com/NVIDIA-Omniverse/ovstorage-usd-resolver/releases/tag/v0.1.0
-->
