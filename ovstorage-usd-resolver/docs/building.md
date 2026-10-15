# Build the resolver for your USD host

No resolver wheels are published to PyPI or elsewhere for this release. Build
the resolver from source for the application that owns OpenUSD. The ovstorage
library publishes its own packages; installing `ovstorage` alone does not
install this resolver.

Run the commands here from the **resolver component root**, the directory
containing its `CMakeLists.txt` and README. In a combined checkout, first run
`cd ovstorage-usd-resolver`. The sibling `../ovstorage` is the storage component
root; it contains `ovstorage-c-source/`.

## Select the host SDK

Current CMake integration requires NVIDIA Kit **25.11 nopy monolithic**:
`PXR_VERSION` must be `2511`, the SDK must export `usd_m`, and its library name
must match `ov_25.11usd_ms`. The pinned baseline is
`0.25.11.kit.4-gl.21081`; [the compatibility matrix](compatibility-matrix.md)
lists its Linux x86_64, Linux aarch64 and Windows x86_64 packages and hashes.

Other USD versions and stock split-library SDKs need build-system changes.
Changing `OVS_USD_SDK_ROOT` alone does not enable them. Even another SDK that
satisfies these layout checks needs validation against the actual host.
Matching the USD version number alone does not establish ABI compatibility:
use matching headers, library bytes, architecture, build configuration,
compiler ABI and C++ runtime. Do not load a second incompatible USD runtime.

The acquisition helper downloads the pinned package for the native host:

```sh
python3 tools/dependencies/acquire_openusd_sdk.py --output .deps/openusd/25.11.kit.4-gl.21081
```

There is no pinned macOS SDK. macOS core/CLI portability tests do not establish
support for a macOS OpenUSD plugin. See [local verification](local-verification.md)
for acquisition details, SDK layout and diagnostic checks.

## Build and test

Install CMake 3.22+, Python 3.10+ and a compiler accepted by the ovstorage bridge:
GCC 13+, Clang 17+ or MSVC 19.40+. Compiler acceptance is not a guarantee that
its runtime matches the host. Linux also needs the SDK's OpenGL/X11 link
dependencies; on Ubuntu these include `libgl1-mesa-dev`, `libsm-dev`,
`libice-dev`, `libx11-dev` and `libxext-dev`.

Use the bundled ovstorage 0.3.0 sources or a matching standalone source/release
layout. The resolver compiles the C API; provider plugins remain external and
must match its plugin ABI. Obtain providers from the corresponding storage
build or published ovstorage package, not an arbitrary newer version. The
Python library exposes its provider directory as `ovstorage.bundled_plugins_dir()`.
CMake registers provider-backed CTests only when it finds a provider directory
at configure time. It uses `<OVS_OVSTORAGE_SDK_ROOT>/plugins` when that
directory exists and falls back to `<OVS_OVSTORAGE_SDK_ROOT>/dist/plugins` only
when it does not. Pointing a runtime at the Python package's provider directory
alone does not register those tests. Stage the matching providers into
`plugins/` first, then configure (or reconfigure) CMake. Do not rely on the
`dist/plugins` fallback for a source-built storage distribution: it also holds
test-only conformance plugins.

Use one of the following, run from the resolver component root. For a
source-built storage distribution, build it with its own prerequisites, then
copy only its runtime providers into a fresh `plugins/`:

```sh
make -C ../ovstorage dist
python3 tools/dependencies/stage_ovstorage_providers.py --ovstorage-root ../ovstorage
```

For the bundled storage 0.3.0 source, the prebuilt-provider alternative copies
the published package's providers instead, in a Python environment:

```sh
python3 -m pip install 'ovstorage==0.3.0'
python3 -c "import ovstorage, shutil; shutil.copytree(ovstorage.bundled_plugins_dir(), '../ovstorage/plugins')"
```

The `make` route assumes a POSIX shell with GNU Make; an MSVC developer shell
does not provide `make`. On Windows, use the prebuilt-provider route, or build
the storage distribution with the storage component's own instructions and then
run the same staging helper. Run the Python commands with `python` where
`python3` is unavailable.

Both methods stop with an error if `plugins/` already exists, so they cannot
silently mix provider versions. To restage or switch between them, delete
`../ovstorage/plugins` first, stage again, and reconfigure CMake. For a
standalone checkout, replace `../ovstorage` with the matching storage component
root. See [SDK layouts](local-verification.md#ovstorage-sdk-layout) for fixture
discovery and [configuration](configuration.md) for trusted runtime providers.

From the resolver component root in the combined checkout, on Linux:

```sh
CC=gcc-13 CXX=g++-13 cmake -S . -B build-host -DCMAKE_BUILD_TYPE=Release \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_TESTS=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_SDK_ROOT="$PWD/.deps/openusd/25.11.kit.4-gl.21081" \
  -DOVS_OVSTORAGE_SDK_ROOT="$PWD/../ovstorage"
cmake --build build-host --parallel
ctest --test-dir build-host --output-on-failure
```

In a standalone checkout, replace the storage path with the matching storage
component root. On Windows, use a developer shell for the matching MSVC
toolchain, a single-configuration generator such as Ninja, and absolute SDK
paths with the same CMake options; omit the Unix compiler assignments.

Tests depend on available SDKs/providers, and the core suite alone does not
prove provider-backed composition. List the registered tests with
`ctest --test-dir build-host -N`. With providers staged and the default schemes,
the list includes `ovstorage_usd_resolver.embed_example`,
`ovstorage_usd_resolver.cli_stack_config_doctor` and
`ovstorage_usd_resolver.host_api_openusd`; if they are missing, CMake did not
find a provider directory. In the test output, `live_*` tests without their
opt-in configuration report as skipped, not passed. Use the
[local verification guide](local-verification.md) to exercise loopback HTTP
composition and the embedding example with matching providers. Live-provider
tests are separate opt-in checks with their own configuration and evidence.

## Scheme registration

The resolver delegates storage operations to the configured ovstorage stack.
To handle a URI scheme, advertise it to OpenUSD at build time and configure a
corresponding ovstorage route. For example, a deployment with an `az` route
can configure `-DOVS_USD_RESOLVER_URI_SCHEMES="s3;http;https;hf;az"`.
This changes registration, not the installed providers or stack configuration.
Runtime `remoteUriSchemes` may narrow the compiled list but cannot widen it.

Available operations depend on the selected route's capabilities. There is no
special prohibition on `omni` or `omniverse`; they require the same registration
and provider setup as other remote schemes. This is not a claim that any
particular provider/host combination has been qualified. Keep a single resolver
owner per scheme: duplicate OpenUSD registrations have no supported precedence
contract. Local files continue through OpenUSD's default filesystem resolver.

## Install and integrate

For a relocatable local CMake installation, enable
`OVS_USD_RESOLVER_INSTALL_NATIVE=ON` in a separate build and follow
[native installation](native-package.md). This does not publish a package.
The [optional local Python package](python-wheels.md) provides a ctypes
bootstrap and has stricter pinned-SDK receipt requirements.

Register the built plugin metadata before the host's first OpenUSD resolver
use. For standalone processes, set `PXR_PLUGINPATH_NAME` to the built plugin's
`plugInfo.json` as shown in [Standalone Usage](configuration.md#standalone-usage). Supply the matching USD runtime loader paths, construct a storage-backed
resolver runtime, and bind its context on threads performing USD work. Keep
the runtime and provider lifetimes valid for the stages using them. Follow
[the embedding example](../examples/embed_resolver/) and
[OpenUSD integration guide](../.agents/integrate-openusd.md); verify remote
composition in the actual host before claiming integration.
