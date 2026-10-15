# Build ovstorage and the USD resolver

Run the commands below from the public repository root. See the
[documentation index](README.md) for installation, configuration, and API guides.

## Prerequisites

Both build paths below compile the resolver and bundled storage C source.
Run them from the repository root on Linux with the prerequisites in the
[storage guide](../ovstorage/README.md) and
[resolver build guide](../ovstorage-usd-resolver/docs/local-verification.md). The concrete
bridge requires GCC 13+, Clang 17+, or MSVC 19.40+. Use a compiler and C++
standard library compatible with the selected USD SDK.

Both paths need CMake 3.20+, Python 3.10+, the native compiler and build tools,
OpenSSL development files, pkg-config, and the SDK link dependencies.
On Ubuntu, install:

```sh
sudo apt-get update
sudo apt-get install --yes g++-13 cmake make libssl-dev pkg-config python3-venv \
  libgl1-mesa-dev libsm-dev libice-dev libx11-dev libxext-dev
```

## Build the bundled sources

After the [shared prerequisites](#prerequisites), install the storage Rust
toolchain described in the [storage guide](../ovstorage/README.md) and the
Protocol Buffers compiler (`sudo apt-get install --yes protobuf-compiler` on
Ubuntu). Then build the storage providers and resolver:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r ovstorage/tools/requirements-dev.txt
make -C ovstorage dist
python3 ovstorage-usd-resolver/tools/dependencies/stage_ovstorage_providers.py --ovstorage-root ovstorage
OPENUSD_SDK="$PWD/ovstorage-usd-resolver/.deps/openusd/25.11.kit.4-gl.21081"
python3 ovstorage-usd-resolver/tools/dependencies/acquire_openusd_sdk.py --output "$OPENUSD_SDK"
CC=gcc-13 CXX=g++-13 cmake -S ovstorage-usd-resolver -B build/resolver -DCMAKE_BUILD_TYPE=Release \
  -DOVS_USD_RESOLVER_BUILD_TESTS=ON \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT="$PWD/ovstorage" \
  -DOVS_USD_SDK_ROOT="$OPENUSD_SDK"
cmake --build build/resolver --parallel
ctest --test-dir build/resolver --output-on-failure
```

`make dist` builds the storage workspace and stages native providers under
`ovstorage/dist/plugins`, including a test-only conformance plugin. The staging
helper copies the regular runtime providers listed by storage's wheel policy
into `ovstorage/plugins`. The resolver compiles the bundled C implementation
and discovers that directory. Use `ovstorage/plugins` for runtime configuration.
The helper requires a fresh destination to prevent mixing provider builds.
The SDK acquisition helper downloads and verifies one pinned NVIDIA Kit USD
package, set by `PACKAGE_VERSION` in
`ovstorage-usd-resolver/tools/dependencies/acquire_openusd_sdk.py` and printed
as `Package:` when it finishes. `PACKAGE_VERSION` (`0.25.11.kit.4-gl.21081`) is
the package identity; the `OPENUSD_SDK` directory is only a label that, like
the resolver docs, drops the leading `0.`. Change it with the pin. The resolver
component's `.gitignore` already ignores `ovstorage-usd-resolver/.deps/`.
Current CMake requires the `ov_25.11usd_ms` library, `PXR_VERSION=2511` and
`usd_m` target. Passing an arbitrary SDK path does not provide support for
another USD version or split-library layout; those need build-system changes
and host ABI validation. The commands do not build a resolver wheel, and no
resolver wheels are published for this release.

## Using prebuilt storage providers

A supported alternative is to compile the resolver against the bundled C
source and supply compatible prebuilt storage providers. Select the exact
storage package version validated for this snapshot; do not assume the latest
wheel is compatible. Its plugin ABI must match the bundled source, and the
integration tests must pass with those provider binaries. The Python package
exposes its provider directory through `ovstorage.bundled_plugins_dir()`.

Install the [shared prerequisites](#prerequisites), including all packages in
the Ubuntu block. Create and activate a Python virtual environment, then install
`ovstorage` at the version recorded in `SOURCE_PROVENANCE.json`. This path does not require
the Rust toolchain, `protobuf-compiler`, or `ovstorage/tools/requirements-dev.txt`.
Skip `make -C ovstorage dist`
and the source-built staging helper: copy the entire directory returned by
`ovstorage.bundled_plugins_dir()` into a fresh `ovstorage/plugins` directory,
then continue with SDK acquisition, CMake configuration, build, and tests above.
Stage providers before configuring CMake: it discovers tests from
`OVS_OVSTORAGE_SDK_ROOT/plugins` or `OVS_OVSTORAGE_SDK_ROOT/dist/plugins`.
Selecting a pip provider directory only at runtime does not enable those tests.
