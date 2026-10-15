# ovstorage USD Resolver

`ovstorage-usd-resolver` is an OpenUSD `ArResolver` plugin that lets USD
consumers compose, materialize, and write remote USD content through
NVIDIA's ovstorage library while preserving normal local-file USD
behavior.

Status: preview. Resolver 0.1 is provided as source; no resolver wheels are
published to PyPI or another destination for this release. Build it against
ovstorage 0.3.x and the consuming host's compatible USD SDK using the
[source build guide](docs/building.md). Current plugin integration requires
NVIDIA Kit OpenUSD 25.11 monolithic; other USD versions and split-library
layouts require build-system work, not just a different SDK path.
Public C++ headers remain preview and may change during the pre-1.0 line; the
versioned CLI JSON contract is stable within `0.1.x`. See
[`docs/api-stability.md`](docs/api-stability.md) for the precise commitments.

## Consumer story

The intended consumer of this resolver is an OpenUSD-hosting
application (`ovstage`, `usdview`-family tools, custom pipeline hosts).
The flow the resolver is designed for:

1. **Application configures ovstorage.** The host loads or authors an
   ovstorage stack configuration (`ovstorage.toml`) that describes
   which providers to enable, for example HTTP origins, S3 buckets, or
   Hugging Face repositories, together with their endpoints and credentials.
   This provider graph is an ovstorage choice, not a resolver backend list.
2. **Application builds or loads the stack.** Either the host builds an
   `ovstorage::LayerHandle` programmatically, or it points the resolver
   at the stack-config file so ovstorage owns composition end-to-end. A
   config that uses plugin-provided layer kinds also needs a trusted
   provider-plugin directory; `file` is built into ovstorage.
3. **Application hands the resolver a bridge.** For programmatic use,
   the host populates `OvStorageBridgeOptions::layerHandle`; for the
   config-file path, it populates `OvStorageBridgeOptions::configPath`
   and, when needed, `pluginDirectory`.
   The standalone CLI takes the config-file path via `--stack-config
   <ovstorage.toml>`.
4. **Application opens a USD stage.** A remote identifier routes through this
   resolver when its scheme is advertised by the build and owned by the
   configured ovstorage stack. The 0.1 default advertises `s3`, `http`,
   `https`, and `hf`; custom builds can advertise other provider-backed
   schemes without changing resolver source. Local paths continue through
   OpenUSD's default filesystem resolver — the resolver stays out of the way
   for them.

Once configured, host applications call OpenUSD normally. The resolver
is a library integration point, not a service.

The runnable [`examples/embed_resolver/`](examples/embed_resolver/) program
shows this complete source-consumer path, including provider loading, stack
construction, `LayerHandle` ownership, resolver discovery, context binding,
and `UsdStage::Open`.

## What it does

- **Registers configured URI schemes without implementing their transports.**
  The resolver delegates provider behavior to ovstorage. Its advertised
  scheme list is set at build time via the `OVS_USD_RESOLVER_URI_SCHEMES`
  CMake variable (semicolon-separated). The default `s3;http;https;hf` is the
  provider profile selected for the 0.1 source release (`s3` via
  `ovstorage-plugin-s3`; `http`/`https` via `ovstorage-plugin-http`; `hf`
  via the read-only `ovstorage-plugin-huggingface`), not an architectural
  allowlist.
  Additional ovstorage backends — for example an `az://` plugin — are
  picked up by extending the list before configuring the build. Local
  paths stay with OpenUSD's default filesystem resolver. Each
  `ResolverRuntime` may narrow the compiled list with
  `ResolverOptions::remoteUriSchemes`; resolve, metadata, open, and write calls
  for a disabled scheme fail before reaching its storage bridge.
- **Composes remote USD stages** through ovstorage: stat, read, range
  reads, materialization to a bridge-owned on-disk lease, USDZ
  outer-package handling, and SDF format-args round-trip on package
  paths.
- **Supports legacy-compatible missing-asset resolution when requested.**
  `ResolverOptions::resolveVerifiesExistence` makes `Resolve()` return empty
  for an authoritative remote `NotFound`, backed by a bounded per-runtime
  positive/negative metadata cache. It is off by default for standalone
  low-latency use; Kit/ovstage-style legacy replacement profiles should enable
  it. Authentication, routing, and transient failures remain nonempty so a
  later open can report the actionable error. A UDIM tile-set pattern
  (`albedo.<UDIM>.png`) names a set of tiles, not one object, so it resolves
  without a probe and the consumer that expands it checks the tiles.
- **Writes whole objects back to remote storage.** `UsdStage::Save` and
  `ArResolver::OpenAssetForWrite` PUT through the ovstorage bridge for
  write-capable routes (native `s3://` in the default provider set; HTTP is
  read-only in the shipped ovstorage provider). The CLI `put` command
  exposes the same path with `--overwrite` (LWW default) and
  `--if-none-match` (strict create-only). OpenUSD `Update` writes preserve
  bytes outside the ranges a client writes and create a missing destination;
  existing-object updates use If-Match only when the selected route supports
  it, with the nonempty ETag from the materialization that supplied their seed
  bytes. A capable route fails closed if that validator is missing or empty;
  routes without If-Match support use overwrite even if they return an ETag. At the OpenUSD producer boundary, saving
  an existing USDC `SdfLayer` uses `Update`, while `UsdStage::Export` uses
  `Replace` and discards the previous object as a whole.
  SDF format arguments are removed before routing the write because they do not
  name a separate provider object. Package-inner identifiers are read-only;
  replace an outer USDZ only by naming that outer object directly.
- **Preserves provider-native version identifiers.** Query strings such as an
  S3 `?versionId=...` pin pass through normal stat, read, and open paths. On a
  version-enabled S3 bucket, a normal write creates a backend-managed object
  version. Version enumeration, restoration, and lifecycle management remain
  ovstorage or provider concerns rather than `ArResolver` APIs.
- **Qualifies a concrete 0.1 provider profile.** Resolver 0.1 release evidence
  covers HTTP(S), native S3, and read-only Hugging Face Hub routes, and
  qualifies native-S3 read/composition against AWS S3. The pinned ovstorage S3
  provider also exposes configuration profiles for MinIO, Cloudflare R2,
  Backblaze B2, and custom S3-compatible endpoints; those are inherited
  provider capabilities, not platforms release-tested by this resolver.
  Endpoint, compatibility-profile, and credential configuration remains
  entirely on the ovstorage side. See the
  [compatibility matrix](docs/compatibility-matrix.md#native-s3-evidence-boundary).
- **Diagnostic CLI** (`ovstorage-usd-resolver`) with six commands —
  `doctor`, `resolve`, `materialize`, `trace`, `put`, `benchmark` —
  plus stable schema-versioned JSON output and a categorized error
  taxonomy for agents. Passive diagnostics redact credential-bearing URI
  fields by default; `resolve` intentionally returns its exact functional
  result. See [Sensitive identifier output](docs/cli-reference.md#sensitive-identifier-output).

## What it doesn't do

- Provider access for renderer-side, non-USD dependencies such as MDL and
  textures. A host that renders a remote stage must configure those consumers
  separately; this resolver owns USD layer and package IO only.
- In-place writes to members inside a USDZ package.
- A qualified macOS OpenUSD plugin. macOS coverage is limited to source
  portability of the core and CLI; see the compatibility matrix.
- A cross-distribution USD binary ABI promise. Compile against the host SDK;
  the resolver does not supply OpenUSD or its Python bindings.

## Product boundary

- The resolver is a library integration point, not a service.
- OpenUSD owns USD composition; ovstorage owns provider-specific storage
  behavior; applications own how they configure and consume stages.
- The resolver delegates transports and backend capabilities to ovstorage.
  A URI reaches it when its scheme is advertised by the build and enabled in
  the runtime; the configured ovstorage stack supplies the route. See
  [scheme registration](docs/building.md#scheme-registration).
- Default HTTP and Hugging Face providers are read-only. A route is writable
  when its selected provider advertises the required capability. Provider
  limitations are not intrinsic restrictions on URI schemes. HTTPS writes need
  a write-capable ovstorage layer for the target service. `hf://` identifiers
  remain intact; provider redirects do not rewrite them into HTTP identifiers.

## Layout

| Path | Purpose |
| --- | --- |
| [`docs/`](docs/) | Architecture, compatibility, and verification guides |
| [`examples/`](examples/) | Runnable source-consumer integration examples |
| [`.agents/`](.agents/) | Task-routing notes for engineers and agents |
| [`include/`](include/) | Public headers |
| [`resources/`](resources/) | OpenUSD plugin metadata template |
| [`src/`](src/) | Resolver implementation |
| [`tests/`](tests/) | Unit, integration, and OpenUSD smoke tests |
| [`tools/`](tools/) | Diagnostic CLI and dependency-acquisition source |
| [`AGENTS.md`](AGENTS.md) | Root agent entrypoint |
| [`LICENSE`](LICENSE) | Apache 2.0 license text and NVIDIA copyright preface |
| [`NOTICE`](NOTICE) | NVIDIA notice |
| [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) | Third-party attribution |

## Building

Three build configurations, in order of dependencies:

**Core + CLI** (no ovstorage, no OpenUSD):

Run component commands from the directory containing this README
(`ovstorage-usd-resolver/` in the combined checkout). Start with the
[source build guide](docs/building.md) for SDK and provider setup.

```bash
cmake -S . -B build -DOVS_USD_RESOLVER_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Runs the identifier, configuration, storage-bridge, runtime, and
materialized-asset unit tests plus the no-SDK CLI regressions.
Local file USD continues to work through OpenUSD's default resolver
without needing this build path.

**With ovstorage 0.3.x** (adds the concrete storage bridge):

CMake accepts GCC 13+, Clang 17+, or MSVC 19.40+ for the ovstorage C++20
wrapper. These are configure-time floors, not three qualified release
platforms. The 0.1 full-stack build and test baseline is GCC 13 on Ubuntu 22.04
Linux x86_64. Maintainer CI has separate Linux aarch64 and Windows jobs for
core/CLI and Kit-plugin fixtures. Those fixtures do not qualify the concrete
ovstorage providers; matched provider-backed composition remains a separate
evidence gate. Compiler acceptance alone is not release qualification.

No-SDK core and CLI CI also exercises Linux aarch64, Windows x86_64, and
macOS arm64, each with default and az-only URI schemes. macOS is a source
portability target rather than a supported prebuilt release platform. These
checks do not qualify the SDK-backed plugin, providers, or wheels; see the
[compatibility matrix](docs/compatibility-matrix.md).

```bash
CXX=g++-13 CC=gcc-13 cmake -S . -B build-ovstorage \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage
cmake --build build-ovstorage
ctest --test-dir build-ovstorage --output-on-failure
```

Enables the concrete bridge (file / HTTP / S3 / Hugging Face backends), CLI
`materialize` and `doctor --uri` probes, and the loopback HTTP
integration smoke. When the ovstorage dist includes the Hugging Face and core
plugins, an offline smoke also proves that a pinned `hf://` StackConfig builds
and routes without performing network IO.

**With ovstorage + OpenUSD plugin** (full resolver + full CLI):

The NVIDIA Kit OpenUSD SDK requires the platform OpenGL development linker
interface. On Debian or Ubuntu Linux, install `libgl1-mesa-dev`; use the
equivalent development package on another Linux x86_64 environment you are
evaluating.

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081

CXX=g++-13 CC=gcc-13 cmake -S . -B build-openusd-ovstorage \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081 \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON
cmake --build build-openusd-ovstorage
ctest --test-dir build-openusd-ovstorage --output-on-failure
```

Builds the compiled `ArResolver` plugin, exercises the full OpenUSD
integration smokes (strict multi-root HTTP composition across sublayer,
reference, and payload arcs; remote USDZ with package-internal and cross-scheme
dependencies; plugin registration), and links the CLI against OpenUSD so
`trace` drives a full `UsdStage::Open`. The deterministic composition smoke
rejects partial stages by checking exact prims, used layers, successful asset
opens, composition errors, and failed resolver traces.
When examples are enabled and ovstorage provider plugins are present, CTest
also runs the public embed example as a subprocess against a loopback HTTP
stage and requires evidence that the resolver opened assets through ovstorage.
An opt-in live Hugging Face smoke opens a pinned public NVIDIA USD fixture
through the native `hf://` route; see
[`docs/local-verification.md`](docs/local-verification.md).

See [`docs/local-verification.md`](docs/local-verification.md) for the exact
SDK package contract, source-build variants, and troubleshooting.

## CLI quick reference

```bash
# Required when ovstorage.toml names plugin-provided kinds such as HTTP or S3.
export OVSTORAGE_PLUGIN_DIR=/path/to/ovstorage/plugins

./build/ovstorage-usd-resolver doctor --json

./build/ovstorage-usd-resolver resolve \
  ./textures/a.png \
  --base https://example.com/scene/root.usd \
  --json

./build-ovstorage/ovstorage-usd-resolver materialize \
  https://example.com/scene/root.usda \
  --stack-config /path/to/ovstorage.toml \
  --out /tmp/root.usda --json

./build-openusd-ovstorage/ovstorage-usd-resolver trace \
  s3://my-bucket/scene/root.usd \
  --stack-config /path/to/ovstorage.toml --json

./build-ovstorage/ovstorage-usd-resolver put \
  ./scene.usda s3://my-bucket/scene/scene.usda \
  --stack-config /path/to/ovstorage.toml --overwrite --json
```

Bridge construction has two paths. Library callers hand the resolver a
pre-built ovstorage `LayerHandle` via
`OvStorageBridgeOptions::layerHandle`. Standalone CLI users and hosts
that prefer ovstorage to own composition point the bridge at a stack
configuration file via `OvStorageBridgeOptions::configPath`
(`--stack-config <ovstorage.toml>` on the CLI). The bridge loads generic
`libovstorage_plugin_*.so` providers from its explicitly trusted
`pluginDirectory`; the CLI maps `OVSTORAGE_PLUGIN_DIR` to that option.
If `--stack-config` is omitted, the CLI uses ovstorage's default-path search
(`./ovstorage.toml`, then the XDG user config path). Hosts that require an
exact plugin allowlist should build the registry and `LayerHandle` themselves
and use the first path. Both paths land on the same `LayerHandle`; aggregate
capabilities are derived from the built layer's address-root discovery
snapshot. Data operations and per-address capability
queries use the live ovstorage router, including its URL canonicalization and
dynamic routes; the resolver does not raw-prefix-match that snapshot.

`doctor --json` output includes a stable schema and a categorized
error taxonomy (`resolver` / `configuration` / `plugin` / `route` /
`backend`) so agents can route failures without parsing message text.

## Start Here

| Goal | Entry |
| --- | --- |
| Build from source | [`docs/building.md`](docs/building.md) |
| Understand the architecture | [`docs/architecture.md`](docs/architecture.md) |
| Check API and ABI commitments | [`docs/api-stability.md`](docs/api-stability.md) |
| Embed the resolver in an OpenUSD host | [`examples/embed_resolver/`](examples/embed_resolver/) |
| Review release-blocking decisions | [`docs/decisions/README.md`](docs/decisions/README.md) |
| Read the CLI reference | [`docs/cli-reference.md`](docs/cli-reference.md) |
| Reproduce SDK-backed verification | [`docs/local-verification.md`](docs/local-verification.md) |
| Work as an agent | [`AGENTS.md`](AGENTS.md) |
| Compatibility matrix | [`docs/compatibility-matrix.md`](docs/compatibility-matrix.md) |

## External Contributions

This project is currently not accepting contributions.

## License

NVIDIA-authored source code and documentation in this repository is
licensed under the Apache License, Version 2.0, unless otherwise noted.
See [`LICENSE`](LICENSE).

Third-party attribution is recorded in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Native embedders can use the preview [CMake install package](docs/native-package.md).
