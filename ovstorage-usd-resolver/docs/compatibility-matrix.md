# Compatibility Matrix

The resolver core is portable where practical, but each compiled OpenUSD plugin
is tied to the SDK used to build it. No resolver wheels are published for this
release. See the [source build guide](building.md) for the current SDK layout
restrictions. The
[API stability policy](api-stability.md) defines which source and diagnostic
contracts are preview or stable within the `0.1.x` line.

## 0.1 Target Matrix

| Area | 0.1 target | Status | Release note |
| --- | --- | --- | --- |
| OpenUSD flavor | NVIDIA Kit OpenUSD nopy monolithic `0.25.11.kit.4-gl.21081`, with the platform packages listed below | supported | The repository helper acquires the public package by pinned SHA-256. `PXR_VERSION 2511` alone does not identify this package or imply ABI compatibility with another 25.11 build. |
| OpenUSD ABI | Build against the consuming host's exact compatible SDK | source-supported within the Kit 25.11 monolithic layout | Other USD versions or split-library layouts need CMake changes. Matching `PXR_VERSION` alone is insufficient. |
| ovstorage | ovstorage 0.3.0 | required for final release | Candidates record the exact tested revision; a development revision is provisional until qualification against the released tag. Older `Library`-facade and pre-StackConfig layouts are rejected at CMake configure time. See "ovstorage version and API floor" below. |
| Concrete bridge compiler check | GCC 13+, Clang 17+, or MSVC 19.40+ for the ovstorage C++20 coroutine wrapper | accepted configure floors | Core resolver stays C++17. `ovs_check_ovstorage_compiler_floor` fails configuration under `OVS_OVSTORAGE_REQUIRED=ON` below these floors. Historical source evidence uses GCC 13. For maintainer context only, the internal `wheel-build` workflow uses Clang 18 with GCC 11 headers on Ubuntu 22.04 for both Linux architectures and MSVC on Windows; it is not public evidence (see the [platform evidence boundary](#platform-evidence-boundary)). SDK-backed support claims require native full-stack evidence; local package tests remain separate from publication. |
| Resolver registration | URI resolver for the build-advertised remote schemes (`OVS_USD_RESOLVER_URI_SCHEMES`; shipping default `s3;http;https;hf`) | supported; native `s3://` read/composition qualified against AWS S3; `hf://` gated on its pinned live smoke | Deterministic smokes prove plugin discovery, generic URI registration, resolver construction, file and loopback-HTTP IO, native-S3 route construction, offline Hugging Face routing, and strict multi-root composition. Live AWS S3 and pinned Hugging Face composition smokes provide the provider-backed release gates. |
| Existing-asset `Resolve()` semantics | Scheme-only by default; opt-in legacy-compatible provider existence verification | supported | `ResolverOptions::resolveVerifiesExistence` is off for the generic low-latency API and enabled by hosts that require `Resolve()` to prove existence. Per-runtime bounded positive/`NotFound` caching, TTL expiry, coalescing, write invalidation, package/SDF outer-key handling, and unknown-error preservation are deterministic-test covered. `_ResolveForNewAsset()` never probes, and neither does a UDIM tile-set pattern, which resolves whether or not any tile exists (D-0010). |
| Packaging | Source build and optional local installation | no published resolver wheels | ovstorage packages remain separately available. Local wheel/native installation tooling does not imply a resolver publication channel. |
| Ubuntu 22.04 Linux x86_64 | Required | supported and release-tested | First-release full-stack source-build evidence uses GCC 13 on this baseline. Other Linux x86_64 environments may work but are not independently qualified for 0.1. |
| Linux aarch64 | Pinned Kit SDK target | core/CLI and Kit-plugin fixture CI | Matched concrete-provider composition remains a separate qualification gate. Maintainer `sdk-plugin` fixture checks do not provide it; see the evidence boundary below. No published resolver wheel. |
| Windows x86_64 | Pinned Kit SDK target | core/CLI and Kit-plugin fixture CI | Matched concrete-provider composition remains a separate qualification gate. Maintainer `sdk-plugin` fixture checks do not provide it; see the evidence boundary below. No published resolver wheel. |
| macOS arm64 | Source portability target | no-SDK core and CLI CI | Not a supported prebuilt release platform. No matched Kit OpenUSD package or full-stack qualification is established. |

### Platform evidence boundary

The maintainer `sdk-plugin` workflow runs Kit-plugin fixtures, while
`wheel-build` separately exercises the concrete bridge, released providers and
local installed consumers. These workflows and their run artifacts are not
included in the public source checkout. Their existence is not proof that a
particular revision or host passed them. Public consumers can reproduce the
[source build and provider-backed checks](building.md#build-and-test); retain
the actual SDK, provider and test evidence for the combination being used.
Live-provider qualification remains separate from deterministic fixtures.

The Update/If-Match decision matrix is tested through real OpenUSD with a
controlled storage bridge. Live S3 and Hugging Face read/composition evidence
does not qualify native-provider conditional writes; no such qualification is
claimed for 0.1. Failed writes retain their status in `write.end` trace events.

### Pinned SDK acquisition targets

The helper pins the same NVIDIA Kit nopy monolithic version,
`0.25.11.kit.4-gl.21081`, for these packages:

| Target | Package platform | Archive SHA-256 |
| --- | --- | --- |
| Linux x86_64 | `manylinux_2_35_x86_64` | `e89a24d8c7f9c315115204c40dbe0925e9689c8e3f330df12d44a05f6ee7745d` |
| Linux aarch64 | `manylinux_2_35_aarch64` | `b808bca4f7202dd0dc38ead625c170d8da4ed3f0addb3f65f84c1e9ce0d36f58` |
| Windows x86_64 | `windows-x86_64` | `4413994b5324eb3f830f8735a909aac2441ac1c4f8f84d87d5fb8f5e010d3bdb` |

Package names are `usd.nopy.<platform>.ov-full-monolithic.release`.
The acquisition workflow verifies extraction, required layout, and provenance
on each native host. Acquisition is not a plugin build or runtime proof.
The helper defaults to the native host. `--target` can acquire another
platform's package for inspection, but does not select a cross compiler.
There is no pinned macOS package; an unsupported native host fails explicitly.

## ovstorage version and API floor

Resolver 0.1 requires ovstorage 0.3.x. It uses the
`StackConfig::from_toml_*` / `StackConfig::build` loader path on
the C ABI, plus the earlier C ABI additions the resolver depends on
for correct write, route-discovery, and range-read behavior:

- `if_match_etag` on `OvStorage_WriteOptions` — required for Update-mode
  conditional writes (closes the lost-update window inside our writable
  asset path).
- Six write/delete availability flags on `OvStorage_Capabilities`
  (`supports_write`, `supports_write_stream`, `supports_write_redirect`,
  `supports_delete`, `supports_create_directory`,
  `supports_delete_directory`) — required for `canWriteRoute` and
  `capabilities()` to be derived from what the backend advertises
  rather than from resolver-side configuration flags.
- `RootInfo.owning_target` — required to construct valid `authenticate`
  / `update_credentials` / `remove` calls against composite plugins
  whose internal backend differs from the outer root name.
- `RootInfo.range_read_strategy` — informs the range-read fallback path.
- Public `ReadOptions` overload on `read_bytes`, `read_stream`, and
  `read_local_file` — removes the resolver-side workaround that
  previously reached into `::ovstorage::detail::` machinery to submit
  range-aware reads.
- `LocalDelegate::info()` in the C++ wrapper — exposes the metadata already
  paired with the materialized local file on the C ABI, avoiding a racy
  follow-up stat.
- `Error::code_name() const` in the C++ wrapper retains the C API's stable
  error identity, so missing configuration is not negative-cached as object
  absence. Coarse `NotFound` without an explicit object identity fails closed.
- The `huggingface` provider plugin and its `hf://{models|datasets|spaces}/...`
  address contract — required for the default Hub route and its read-only
  release smoke.

The public 0.1 release requires ovstorage `v0.3.0`, released at commit
`8a8689c0f497ae9755052cce9ceb4cbb13378234`. Build the C API from that tag and use
its released providers (plugin ABI 19). Development source and provider bundles
may have different ABIs; earlier development evidence does not qualify the
public release. Source candidates must be tested against the released
dependency before final promotion. CMake does not
infer a semantic version from arbitrary source checkouts; it enforces the
bridge's required C++ API surface at configure time. The detected facade must
expose `LayerHandle::root_info_for()`, `Error::code_name() const`,
`LocalDelegate::info() const &`, and the
`StackConfig` loader/build API. With `OVS_OVSTORAGE_REQUIRED=ON`, a missing
surface is a fatal error naming what is unavailable; otherwise the concrete
bridge is disabled with a warning.

## Compatibility Proofs

The 0.1 verification baseline is source-tree based. Release-candidate
preparation exports the exact public tree, acquires the pinned OpenUSD SDK, and
builds and tests the plugin from that exported source. A maintainer records the
combined product proof separately from the exact candidate SHA: build against
the pinned OpenUSD SDK and selected ovstorage source or dist tree, then run
`ctest`. See
[local-verification.md](local-verification.md) for the SDK-backed
proof commands and expected outputs.

## OpenUSD Build Proof

Acquire the exact 0.1 SDK and build the plugin from source:

Install the platform OpenGL development linker interface first. On Debian or
Ubuntu Linux this is provided by `libgl1-mesa-dev`; use the equivalent package
on another Linux x86_64 environment you are evaluating.

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081
cmake -S . -B build-openusd \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081
cmake --build build-openusd
ctest --test-dir build-openusd --output-on-failure
```

The smoke proves:

- the C++ plugin compiles and links against `PXR_VERSION 2511`;
- OpenUSD can discover the resolver through `plugInfo.json`;
- the build-advertised URI schemes (`OVS_USD_RESOLVER_URI_SCHEMES`; shipping
  default `s3;http;https;hf`) are registered — extending or narrowing the
  advertised set is a configure-time knob, not a source edit;
- a remote USDZ package under one advertised scheme can compose an absolute
  layer reference under a second advertised scheme through the same runtime;
- a resolver instance can be constructed through OpenUSD's type registry;
- the resolver resolves normalized remote identifiers in claimed schemes and
  does not claim local paths.

## SDK-Backed Bridge Proof

The repository also has opt-in concrete bridge checks when both a Kit OpenUSD
SDK and a usable ovstorage SDK layout are available. See
[local-verification.md](local-verification.md) for the expected SDK shape and
commands.

This path proves:

- the concrete bridge accepts a host-provided
  `OvStorageBridgeOptions::layerHandle` and derives its capabilities
  from the built layer's address roots;
- the `configPath` bridge-construction path builds through ovstorage's
  `StackConfig::from_toml_*` / `StackConfig::build` API;
- built-in `file` backend `stat`/`read`/`materialize` succeeds through
  ovstorage;
- the `http` layer, loaded generically from an explicitly trusted plugin
  directory and pinned by the bridge, `stat`/`read`s a loopback HTTP server
  fixture;
- combined file + HTTP routing serves both backends under one bridge;
- CLI `materialize` copies one loopback HTTP asset to `--out` through
  StackConfig and verifies the resulting bytes;
- repeated bridge creation and destruction on the calling thread is safe;
- OpenUSD `_OpenAsset` composed HTTP stage loading through the ovstorage
  bridge.

Native `s3://` support ships: the ovstorage stack configuration
describes the `s3` layer (bucket, region, endpoint, compatibility
profile, requester-pays) and supplies credentials through the connection's
secret bundle; the bridge adopts
the built `LayerHandle` — either handed in programmatically or loaded
from a stack config file via `--stack-config <ovstorage.toml>`. `s3`
is listed in the plugin `uriSchemes`. Live-S3 stage composition is
gated by `OVS_USD_RESOLVER_LIVE_S3_STAGE_URL` (with optional
`_REGION`, `_ENDPOINT`, `_PROFILE`, `_COMPAT`, `_REQUESTER_PAYS` env
vars). It requires complete composition and can route mixed HTTPS dependencies
through the semicolon-separated `OVS_USD_RESOLVER_LIVE_S3_HTTP_ROOTS` list.

### Native S3 evidence boundary

The resolver stays agnostic to S3 vendors: bucket, region, endpoint,
compatibility profile, requester-pays behavior, and credentials are ovstorage
connection concerns. Version 0.1 makes narrower claims than the pinned
ovstorage provider can configure:

| Target | Resolver 0.1 status | Evidence boundary |
| --- | --- | --- |
| AWS S3 read and composition | release-qualified | The public Robot fixture opens through native `s3://`, composes its real HTTPS dependencies, and checks 264 prims, 7 used layers, 6 successful resolver opens, zero failed trace events, and zero composition errors. |
| Native-S3 write plumbing | preview behavior with targeted evidence | A credentialed loopback MinIO PUT/reopen check exercises capability discovery, secret attachment, export, and reopen. It is not an AWS-hosted write test or broad MinIO qualification. |
| MinIO, Cloudflare R2, Backblaze B2, and custom S3-compatible deployments | inherited ovstorage configuration capability; not resolver-release-tested | The S3 provider exposes these compatibility profiles and the live-smoke harness accepts their settings, but version 0.1 records no full resolver qualification for these platforms. |

Selecting a non-AWS profile does not add endpoint-specific code to the
resolver, and it does not make generic `https://` routes writable. The shipped
ovstorage HTTP provider remains read-only; S3 writes use a native `s3://`
route whose configured ovstorage backend advertises write capability.

The default ovstorage Hugging Face provider is read-only. The default scheme
list advertises `hf`, while
ovstorage's Hugging Face provider owns repository connections, optional
authentication, revision selection, and Hub/CDN redirect handling. The
deterministic `huggingface_stack_config` smoke builds a connection through the
generic StackConfig/plugin-directory path and verifies native route ownership
without network IO. The opt-in `live_hf_stage` smoke opens
`nvidia/Spark-AnomalyGen-USD` at revision
`0bbac7b7322afcfa0d58c837c17fddaee84d9b76`, requires known composed USD
layers and a minimum scene signature, and rejects resolver-visible HTTP
rewrites. It runs only when `OVS_USD_RESOLVER_RUN_LIVE_HF=1`.

That proof covers USD composition, not rendering. MDL files and textures in a
Hub repository are consumed by renderer/application subsystems outside this
resolver and need their own storage integration.

Bound-context retention through plain `UsdStage::Open` and `Reload` is tested
on the pinned Kit SDK above. URI-resolver default-context dispatch must be
requalified for every additional USD flavour; a shared version number alone
does not establish that behavior.

Windows materialization relies on a private per-user temporary-directory DACL;
see [configuration](configuration.md#materialization-directory-permissions).
Exclusive creation and lease cleanup do not imply owner-only Windows ACLs.
