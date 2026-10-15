# ovstorage USD Resolver Agent Entry

This is the resolver component of `NVIDIA-Omniverse/ovstorage`.
Component commands run from the directory containing this file
(`ovstorage-usd-resolver/` in the combined checkout).

This component is the ovstorage-backed OpenUSD resolver. The product boundary
is intentionally narrow:

- local USD files keep using normal OpenUSD local behavior;
- remote USD identifiers are resolved and materialized through ovstorage;
- renderer-side or non-USD asset IO belongs outside this resolver;
- omniclient is not a dependency, and provider-specific Nucleus behavior can
  enter only through an explicitly configured ovstorage provider.

Status: preview release. Resolver 0.1 is consumed from source and publishes
no wheels for this release. It requires ovstorage 0.3.x,
and qualifies the NVIDIA Kit OpenUSD 25.11 monolithic ABI. The compatibility
matrix pins one SDK package for reproducible evidence; other OpenUSD builds are
not release-qualified by 0.1.

Implemented surface:

- URI resolver plugin with build-advertised schemes (default
  `s3;http;https;hf`) and context-local narrowing;
- scheme-agnostic concrete ovstorage bridge using host-provided `LayerHandle`
  or StackConfig plus a caller-trusted provider directory;
- bridge-owned materialization leases and whole-object writes to routes that
  advertise write support;
- byte-preserving OpenUSD Update with coherent ETag matching, create-on-missing,
  normalized provider targets, and package-member write rejection;
- opt-in bounded, runtime-owned Resolve-existence verification for
  legacy-replacement hosts; and
- diagnostic CLI commands `doctor`, `resolve`, `materialize`, `trace`, `put`,
  and `benchmark`.

Local files work without ovstorage. Deterministic composition coverage includes
cross-scheme remote USDZ dependencies. Version 0.1 qualifies native S3
read/composition against AWS S3 and gates native `hf://` on its pinned live
smoke. Other S3-compatible endpoint profiles are ovstorage capabilities, not
resolver-qualified platforms. The default schemes are the 0.1 provider profile,
not a resolver backend allowlist. A URI scheme must be advertised by the build,
enabled in the runtime and routed by the configured ovstorage stack. Transport
and write capabilities belong to the selected provider. See the
[source build guide](docs/building.md) for current USD restrictions and
[compatibility matrix](docs/compatibility-matrix.md) for platform coverage.

## Route by Task

| You want to... | Load |
| --- | --- |
| Build the resolver from source | [`docs/building.md`](docs/building.md) |
| Reason about resolver architecture | [`docs/architecture.md`](docs/architecture.md) |
| Review public API stability | [`docs/api-stability.md`](docs/api-stability.md) |
| Cross-check legacy resolver behavior | [`docs/legacy-behavior-ledger.md`](docs/legacy-behavior-ledger.md) |
| Work on resolver code | [`.agents/develop-resolver.md`](.agents/develop-resolver.md) |
| Plan or run tests | [`.agents/test-resolver.md`](.agents/test-resolver.md) |
| Reproduce real SDK-backed verification | [`.agents/verify-empirically.md`](.agents/verify-empirically.md) |
| Use the CLI | [`.agents/use-cli.md`](.agents/use-cli.md) |
| Embed the resolver in OpenUSD clients | [`.agents/integrate-openusd.md`](.agents/integrate-openusd.md) |
| Integrate the resolver into ovstage | [`.agents/integrate-ovstage.md`](.agents/integrate-ovstage.md) |
| Install or consume the native SDK | [`docs/native-package.md`](docs/native-package.md) |
| Build or validate the optional Python package | [`docs/python-wheels.md`](docs/python-wheels.md) |
| Verify a source build or local install | [`.agents/release.md`](.agents/release.md) |
| Triage failures | [`.agents/triage.md`](.agents/triage.md) |
| Review release-blocking decisions | [`docs/decisions/README.md`](docs/decisions/README.md) |

## Required Context

Before implementation work, read:

1. [`docs/architecture.md`](docs/architecture.md)
2. [`docs/api-stability.md`](docs/api-stability.md)
3. [`docs/test-strategy.md`](docs/test-strategy.md)

If your task touches release behavior, also read:

1. [`docs/compatibility-matrix.md`](docs/compatibility-matrix.md)
2. [`docs/local-verification.md`](docs/local-verification.md)

## Current Verification

```bash
cmake -S . -B build -DOVS_USD_RESOLVER_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Optional real ovstorage bridge check (ovstorage SDK required, compiler
floor GCC 13+ / Clang 17+ / MSVC 19.40+):

Those are configure-time acceptance floors. Resolver 0.1 full-stack release
evidence uses GCC 13 on Ubuntu 22.04 Linux x86_64.

```bash
CXX=g++-13 CC=gcc-13 cmake -S . -B build-ovstorage \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage/main-checkout
cmake --build build-ovstorage
ctest --test-dir build-ovstorage --output-on-failure
```

This exercises the concrete ovstorage bridge and StackConfig path against the
built-in `file` backend end-to-end. If the detected SDK layout also contains a
provider-plugin directory and the build advertises `http`, it runs the HTTP CLI
doctor routed/unrouted smoke.
See
[`docs/local-verification.md`](docs/local-verification.md) for the recognized
SDK layouts.

Optional combined OpenUSD plus ovstorage check (file + HTTP + S3 + Hugging
Face backends):

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081

CXX=g++-13 CC=gcc-13 cmake -S . -B build-openusd-ovstorage \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081 \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage/main-checkout
cmake --build build-openusd-ovstorage
ctest --test-dir build-openusd-ovstorage --output-on-failure
```

`openusd_ovstorage_bridge_http` runs a deterministic two-root loopback HTTP
stage with sublayer, reference, payload, exact scene-signature checks, and a
missing-route negative control through the ovstorage bridge. The opt-in
`live_http_stage` smoke runs when `OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL`
is set. `live_hf_stage` uses a repository and immutable revision recorded in
the test fixture and runs when `OVS_USD_RESOLVER_RUN_LIVE_HF=1` is set.
With examples enabled, `embed_example` also launches the public
[`examples/embed_resolver/`](examples/embed_resolver/) consumer binary against
a loopback stage and rejects a successful open that did not pass through the
ovstorage-backed resolver.

## House Rules

- Keep this repo focused on the USD resolver.
- Do not copy implementation code from earlier NVIDIA USD resolver
  codebases; write against this repo's own contract.
- Do not add private endpoints, credentials, Slack excerpts, machine-local
  paths, or non-public operational details to committed docs or tests.
- Keep native `s3://` support distinct from public S3-backed HTTPS support.
- Keep AWS S3 release evidence distinct from MinIO, Cloudflare R2, Backblaze
  B2, and custom endpoint profiles inherited from ovstorage. Do not promote a
  provider configuration to resolver-qualified support without corresponding
  end-to-end evidence.
- Keep native `hf://` identifiers intact. Hugging Face redirect handling is an
  ovstorage provider concern, and renderer-side MDL/texture IO is outside this
  resolver.
- Describe `s3;http;https;hf` as the default provider profile, not the complete
  set of backends the scheme-agnostic bridge can use.
- Describe additional schemes through registration, runtime enablement and
  ovstorage routing. Do not turn default provider choices into intrinsic
  resolver transport limitations or claim untested integrations are qualified.
- Treat OpenUSD flavor compatibility as a binary compatibility requirement,
  not a generic source-level assumption.
- Update agent docs when adding build, test, CLI, or release commands.
