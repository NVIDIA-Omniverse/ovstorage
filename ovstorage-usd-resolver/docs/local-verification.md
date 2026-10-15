# Local Empirical Verification

This document records the reproducible setup for proving the resolver against
real NVIDIA Kit OpenUSD and ovstorage artifacts. It is intentionally separate
from normal SDK-independent development so the ordinary contributor path stays
small.

Use this when a review needs evidence beyond code inspection:

- the OpenUSD plugin compiles and registers against the target Kit USD flavor;
- the concrete ovstorage bridge compiles and links against the ovstorage C ABI;
- real ovstorage providers can read and materialize assets;
- OpenUSD composition can fetch remote layers through the resolver and
  ovstorage.

Do not commit access tokens or local absolute paths. Use repository-local
placeholders in docs and PR bodies.

## Required Inputs

| Input | Expected shape | Notes |
| --- | --- | --- |
| NVIDIA Kit OpenUSD SDK | directory containing `bin/`, `cmake/`, `include/`, `lib/`, `plugin/`, `pxrConfig.cmake`, and related resources | Exact 0.1 target is the Linux x86_64 nopy monolithic package `0.25.11.kit.4-gl.21081`. |
| ovstorage SDK/dist | ovstorage 0.3.x main-source or release-archive layout described below | Required only for concrete bridge and provider-backed CLI checks. |
| Compiler | C++17 for core resolver; C++20-capable compiler for the concrete bridge path | CMake accepts GCC 13+, Clang 17+, or MSVC 19.40+ for the concrete bridge. The historical source baseline uses GCC 13 on Ubuntu 22.04 Linux x86_64. Wheel CI uses Clang 18 with GCC 11 headers on Ubuntu 22.04 for both Linux architectures and MSVC on Windows; accepted compiler floors are not qualification of every compiler version. |
| OpenGL development files | a discoverable `OpenGL::GL` CMake target | Required by the NVIDIA Kit OpenUSD SDK when linking the plugin. On Debian or Ubuntu Linux, install `libgl1-mesa-dev`; use the equivalent package elsewhere. |

## Kit OpenUSD SDK

Version 0.1 validates against this exact public package:

| Field | Value |
| --- | --- |
| Package | `usd.nopy.manylinux_2_35_x86_64.ov-full-monolithic.release` |
| Version | `0.25.11.kit.4-gl.21081` |
| Platform ABI | `manylinux_2_35_x86_64` |
| SHA-256 | `e89a24d8c7f9c315115204c40dbe0925e9689c8e3f330df12d44a05f6ee7745d` |

Acquire and prepare it from NVIDIA's anonymously readable package endpoint:

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081
```

The helper downloads the pinned archive, verifies its SHA-256 before
extraction, restores Linux shared-library links represented as Windows reparse
records in the archive, validates the expected SDK shape, and writes an
acquisition marker. The acquisition step requires Python 3.10+ and CMake, but
no NVIDIA credentials or package-manager configuration. Building the plugin
also requires the platform OpenGL development files listed above. Re-running
the command validates and reuses the existing destination. It never replaces
an unrecognized directory.

For independent audit, the helper's `PACKAGE_URL`, package coordinates, and
digest are constants in
[`tools/dependencies/acquire_openusd_sdk.py`](../tools/dependencies/acquire_openusd_sdk.py).

`OVS_USD_SDK_ROOT` must point at the resulting SDK root:

```text
.deps/openusd/25.11.kit.4-gl.21081/
```

Expected layout:

```text
<openusd-sdk>/
  bin/
  cmake/
  include/
  lib/
  libraries/
  plugin/
  pxrConfig.cmake
  resources/
  scripts/
```

The package identity matters. `PXR_VERSION` reports only `2511`; it does not
identify NVIDIA's package revision or establish C++ ABI compatibility with
another OpenUSD 25.11 build. CMake requires the Kit 25.11 monolithic library
name and `usd_m` target. Other versions and split-library SDKs require build
integration changes. Other SDKs satisfying these layout checks still need
host-specific validation; they are not automatically qualified. See the
[source build guide](building.md). No resolver wheels are published for this
release; the optional local Python package is restricted to the pinned SDK.

## ovstorage SDK Layout

`OVS_OVSTORAGE_SDK_ROOT` must point at ovstorage 0.3.x with the required C++
facade. Two usable shapes are recognized, plus an unsupported legacy shape that
is detected to produce an actionable error:

**Main source checkout** (recommended for development):

```text
<ovstorage-sdk>/
  ovstorage-c-source/
    include/ovstorage.hpp
    include/ovstorage.h
    src/*.c
  plugins/libovstorage_plugin_*.so    # if a dist build is present
```

Point `OVS_OVSTORAGE_SDK_ROOT` at the storage component root (the directory
containing `ovstorage-c-source/`), not the combined repository root.

**ovstorage 0.3.x release archive**:

```text
<ovstorage-sdk>/
  c-source/
    include/ovstorage.hpp
    src/*.c
  lib/libovstorage_capi.so
  plugins/libovstorage_plugin_*.so
```

**Legacy `Library`-facade layout** (unsupported):

```text
<ovstorage-sdk>/
  include/ovstorage.hpp          # exposes class Library — rejected at configure time
  lib/libovstorage_capi.so
  plugins/libovstorage_plugin_*.so
```

CMake configure prints a clear error if the detected header exposes the
older `Library` facade instead of the current ovstorage classes.
`OVS_OVSTORAGE_REQUIRED=ON` also fatal-errors when no SDK is detected at
all, which CI should set to prevent silent skips.

The concrete ovstorage bridge target additionally requires a compiler that
supports the ovstorage C++20 coroutine wrapper: **GCC 13+, Clang 17+, or
MSVC 19.40+**. CMake probes for this and disables the target (or hard-fails
under `OVS_OVSTORAGE_REQUIRED`) if the compiler is below the floor. These are
configure-time acceptance floors. The historical source proof uses GCC 13 on
Ubuntu 22.04 Linux x86_64. Optional internal wheel validation uses
Clang 18/GCC 11 headers on both Linux architectures and MSVC on Windows to test
the complete stack and installed consumers. Those maintainer runs are not
included in this public checkout. Retain evidence when making a local package
compatibility claim; wheel qualification/publication is not a prerequisite for
this source release. Provider-backed source qualification remains a separate
gate; see [the build guide](building.md#build-and-test) for CTest discovery.

The detected C++ facade must also expose `Error::code_name() const`,
`LayerHandle::root_info_for()`,
`LocalDelegate::info() const &`, and the `StackConfig` loader/build API. These
are required for authoritative routing, coherent materialization metadata, and
the public `--stack-config` construction path. CMake reports a missing surface
at configure time instead of allowing the bridge compile to fail later.

If the ovstorage 0.3.x release provides C sources and provider plugins but
not a prebuilt `libovstorage_capi.so`, build the C API library from the
release's `c-source/` directory and assemble the release-archive layout above.

Minimal CMake project for that local SDK assembly:

```cmake
cmake_minimum_required(VERSION 3.16)
project(ovstorage_capi_shim LANGUAGES C)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
find_package(Threads REQUIRED)
if(NOT WIN32)
    add_compile_definitions(_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700 _FILE_OFFSET_BITS=64)
endif()

set(SRC_DIR "<path-to-ovstorage-dist>/c-source")
file(GLOB CAPI_SRC "${SRC_DIR}/src/*.c")
add_library(ovstorage_capi SHARED ${CAPI_SRC})
target_include_directories(ovstorage_capi PUBLIC "${SRC_DIR}/include")
target_link_libraries(ovstorage_capi PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(ovstorage_capi PRIVATE -Wall -Wextra -Wno-unused-parameter)
set_target_properties(ovstorage_capi PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
```

Then copy:

- `c-source/include/` to `<ovstorage-sdk>/include/`;
- the built `libovstorage_capi.so` to `<ovstorage-sdk>/lib/`;
- provider `.so` files to `<ovstorage-sdk>/plugins/`.

## Required Local Checks

Core and CLI checks, no ovstorage or OpenUSD SDK required:

```bash
cmake -S . -B build -DOVS_USD_RESOLVER_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Concrete ovstorage bridge checks:

```bash
cmake -S . -B build-ovstorage \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage-sdk
cmake --build build-ovstorage
ctest --test-dir build-ovstorage --output-on-failure
```

Combined OpenUSD plus ovstorage checks:

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081

cmake -S . -B build-openusd-ovstorage \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081 \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage-sdk
cmake --build build-openusd-ovstorage
ctest --test-dir build-openusd-ovstorage --output-on-failure
```

## Fresh-agent one-command usable-bridge check

Before running the full combined suite, fresh agents should run one CLI
command that answers "do I have a usable ovstorage bridge?":

```bash
export OVSTORAGE_PLUGIN_DIR=/path/to/ovstorage/plugins
./build-ovstorage/ovstorage-usd-resolver doctor \
  --stack-config /path/to/ovstorage.toml \
  --json
```

Read the JSON output top-to-bottom:

- `ovstorage_bridge_build = ok` — the binary was built with the
  ovstorage bridge.
- `ovstorage_stack_config = ok` — the bridge actually initializes
  from the supplied stack configuration. If this is `error`, the
  `errors[].category` tells you which layer to look at:
  `configuration` (stack-config file missing, malformed, or references
  a plugin that isn't on disk), `plugin` (`.so` load or ABI mismatch),
  `route` (no factory for a scheme declared in the stack), or
  `backend` (a backend named in the stack refused a probe).

`OVSTORAGE_PLUGIN_DIR` is unnecessary for a file-only config. Set it to an
explicitly trusted directory when the TOML names plugin-provided kinds; the
bridge loads matching `libovstorage_plugin_*.so` files and pins them for the
built layer's lifetime.

Text output uses `error[<category>/<code>]: <message>`. If the category
alone is unfamiliar, see the "Error categories" section in
[`.agents/use-cli.md`](../.agents/use-cli.md).

The combined suite covers:

- plugin discovery and resolver construction through real OpenUSD;
- the public `examples/embed_resolver` consumer binary in a separate process,
  including StackConfig-to-`LayerHandle` construction, context binding, stage
  opening, and a nonzero ovstorage resolver-open signal;
- local filesystem resolver coexistence;
- USDZ/package behavior through real OpenUSD;
- concrete ovstorage `file://` provider stat/read/materialize through the
  bridge;
- concrete ovstorage `http://` layer loaded generically from the configured
  trusted plugin directory and pinned by the bridge;
- concrete ovstorage Hugging Face graph built from a pinned public repository
  configuration, with native `hf://` route ownership and read-only capability
  proven without network IO;
- concrete routed native-S3 graph construction with the core router, HTTP, and
  S3 plugins retained for the layer lifetime; route ownership is checked
  without provider IO (`host_s3_routed_stack`);
- CLI `materialize`, `trace`, and `doctor` against a loopback HTTP backend via
  `--stack-config`;
- strict OpenUSD composed HTTP stage loading across two address roots,
  including sublayer, reference, and payload arcs plus a missing-route
  negative control (`openusd_ovstorage_bridge_http`).

The optional live stage smoke `live_http_stage` is skipped unless the
environment variable below is set:

```bash
OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL=https://example.com/path/root.usd \
ctest --test-dir build-openusd-ovstorage -R live_http_stage --output-on-failure
```

Success requires zero failed resolver traces, zero composition errors, and
minimum prim/layer/successful-open counts. Override those floors with
`OVS_USD_RESOLVER_LIVE_HTTP_MIN_PRIMS`,
`OVS_USD_RESOLVER_LIVE_HTTP_MIN_USED_LAYERS`, and
`OVS_USD_RESOLVER_LIVE_HTTP_MIN_SUCCESSFUL_OPENS`; require stable prim paths
with semicolon-separated `OVS_USD_RESOLVER_LIVE_HTTP_REQUIRED_PRIMS`. Add any
dependency address roots not covered by the root layer's directory with
semicolon-separated `OVS_USD_RESOLVER_LIVE_HTTP_ROOTS`.

The optional `live_s3_stage` smoke is skipped unless
`OVS_USD_RESOLVER_LIVE_S3_STAGE_URL` is set. Additional environment variables
let one binary run the AWS S3 release qualification or investigate a MinIO,
R2, B2, or custom endpoint configured by ovstorage:

```bash
OVS_USD_RESOLVER_LIVE_S3_STAGE_URL=s3://my-bucket/scene/root.usd \
OVS_USD_RESOLVER_LIVE_S3_STAGE_REGION=us-east-1 \
ctest --test-dir build-openusd-ovstorage -R live_s3_stage --output-on-failure
```

Set only the optional values needed by the selected ovstorage profile. For
example, a MinIO endpoint can use:

```bash
export OVS_USD_RESOLVER_LIVE_S3_STAGE_ENDPOINT=https://minio.example.com
export OVS_USD_RESOLVER_LIVE_S3_STAGE_COMPAT=minio
```

Credentials, requester-pays behavior, and allowed HTTPS dependency roots are
independent optional inputs:

```bash
export OVS_USD_RESOLVER_LIVE_S3_STAGE_PROFILE=my-aws-profile
export OVS_USD_RESOLVER_LIVE_S3_STAGE_REQUESTER_PAYS=true
export OVS_USD_RESOLVER_LIVE_S3_HTTP_ROOTS=https://dependency.example.com/
```

Valid compatibility values are `aws`, `minio`, `r2`, `b2`, and `custom`.

For version 0.1, only the AWS S3 read/composition run below is release
qualification. A non-AWS run is optional provider-compatibility evidence and
does not broaden the resolver claim unless its environment, scope, and result
are recorded separately. The resolver does not interpret the endpoint,
profile, or credential settings; the test host passes them into ovstorage's S3
connection.

Public buckets need no credentials. For private buckets, provide
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (plus `AWS_SESSION_TOKEN` when
needed), or select a shared credentials file with
`AWS_SHARED_CREDENTIALS_FILE` and a profile with either
`OVS_USD_RESOLVER_LIVE_S3_STAGE_PROFILE` or `AWS_PROFILE`. These values are
attached to the ovstorage connection as secrets; ordinary S3 layer config does
not itself authenticate a connection.

The S3 smoke applies the same complete-composition checks. Its optional
overrides are `OVS_USD_RESOLVER_LIVE_S3_MIN_PRIMS`,
`OVS_USD_RESOLVER_LIVE_S3_MIN_USED_LAYERS`,
`OVS_USD_RESOLVER_LIVE_S3_MIN_SUCCESSFUL_OPENS`, and the semicolon-separated
`OVS_USD_RESOLVER_LIVE_S3_REQUIRED_PRIMS` list.

The release-candidate native-S3 read can be repeated against the public Robot
fixture. For anonymous qualification, run in an environment without
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`,
`AWS_SHARED_CREDENTIALS_FILE`, or a smoke-specific credential profile. Otherwise
the test deliberately uses the configured credential path, which may fail even
when anonymous public access succeeds. Both AWS URL spellings are intentional: the root object's S3 redirect
and its composed HTTPS dependencies use different regional host forms.

```bash
OVS_USD_RESOLVER_LIVE_S3_STAGE_URL=s3://omniverse-content-production/Samples/Robot-OVRTX/robot-ovrtx.usda \
OVS_USD_RESOLVER_LIVE_S3_STAGE_REGION=us-west-2 \
OVS_USD_RESOLVER_LIVE_S3_HTTP_ROOTS='https://omniverse-content-production.s3-us-west-2.amazonaws.com/;https://omniverse-content-production.s3.us-west-2.amazonaws.com/' \
ctest --test-dir build-openusd-ovstorage \
  -R '^ovstorage_usd_resolver.live_s3_stage$' --output-on-failure
```

The optional live write smoke requires credentials and a disposable object URL
for which the caller has PUT permission. It exports a small USDA stage,
reopens it through the resolver, and checks the authored prim. The test
overwrites the selected object and does not delete it.

```bash
AWS_ACCESS_KEY_ID=<access-key-id> \
AWS_SECRET_ACCESS_KEY=<secret-access-key> \
OVS_USD_RESOLVER_LIVE_WRITE_STAGE_URL=s3://my-writable-bucket/smoke/live-write.usda \
OVS_USD_RESOLVER_LIVE_WRITE_STAGE_REGION=us-east-1 \
ctest --test-dir build-openusd-ovstorage \
  -R '^ovstorage_usd_resolver.live_write_stage$' --output-on-failure
```

`OVS_USD_RESOLVER_LIVE_WRITE_STAGE_ENDPOINT`, `_PROFILE`, `_COMPAT`, and
`_REQUESTER_PAYS` provide the same ovstorage-owned controls for S3-compatible
stores. A successful run validates the selected native-S3 write path; it does
not by itself qualify that provider for all resolver use cases. In particular,
the 0.1 engineering evidence includes a credentialed loopback MinIO
PUT/reopen, not a broad MinIO claim or an AWS-hosted write claim. An unset live
URL produces CTest status `Skipped` (return code 77); it is not passing live
evidence. These controls do not apply to generic HTTPS writes, which remain
unsupported by the shipped ovstorage HTTP provider.

The optional `live_hf_stage` smoke uses a fixed public NVIDIA sample and an
immutable repository revision, so its evidence is reproducible without
accepting a caller-selected URL:

```bash
OVS_USD_RESOLVER_RUN_LIVE_HF=1 \
ctest --test-dir build-openusd-ovstorage -R live_hf_stage --output-on-failure
```

Fixture: Hugging Face dataset `nvidia/Spark-AnomalyGen-USD`, revision
`0bbac7b7322afcfa0d58c837c17fddaee84d9b76`, root layer `pcb.usd`. Success
requires at least 1,000 prims, stable PCB and mask prim landmarks, three used
layers, three successful resolver opens, the two known ECAD mask layers, zero
failed resolver traces, and zero composition errors. It also verifies that
every resolver-attributed open and non-anonymous used layer remains under the
native `hf://datasets/nvidia/Spark-AnomalyGen-USD/` root. The sample is fetched
for the test and is not redistributed with this source tree. The dataset is
published under the NVIDIA Sample Data License; review its terms at the
[pinned fixture](https://huggingface.co/datasets/nvidia/Spark-AnomalyGen-USD/tree/0bbac7b7322afcfa0d58c837c17fddaee84d9b76).

This is a USD composition check. The dataset also contains MDL and texture
assets; loading those for rendering belongs to the host's non-USD asset IO and
is not evidence this resolver is expected to provide.

Do not add private endpoints or credentials to the repository.

## Troubleshooting

If the concrete bridge fails to compile with coroutine-related diagnostics from
`ovstorage.hpp`, check the compiler first. Some GCC 11 environments have hit
coroutine-wrapper diagnostics in the ovstorage headers during empirical
review. GCC 13 on Ubuntu 22.04 is the historical source baseline. For optional local wheel
validation, reproduce the Clang 18/GCC 11 header configuration in
[the local wheel guide](python-wheels.md); a newer compiler or standard library
can raise the required runtime floor even if the source compiles.

If OpenUSD cannot discover the plugin:

- confirm `OVS_USD_SDK_ROOT` points at the SDK root, not only `lib/`;
- confirm `resources/plugInfo.json` exists in the build tree;
- rerun the `openusd_plugin_registration` CTest with
  `--output-on-failure`.

If ovstorage providers cannot be loaded:

- confirm `OVS_OVSTORAGE_SDK_ROOT/plugins` contains provider `.so` files;
- confirm `LD_LIBRARY_PATH` includes `<ovstorage-sdk>/lib` when invoking
  binaries manually;
- run the `stack_config_bridge` and `cli_stack_config_doctor` CTests before
  debugging OpenUSD composition.

For hand-run Windows SDK consumers (including the embedding example), add the
selected SDK's `lib`, `bin`, and `plugin/usd` directories and the resolver build
directory to `PATH` before launching. CTest applies these paths only to its
registered tests; it does not configure an interactive shell.
