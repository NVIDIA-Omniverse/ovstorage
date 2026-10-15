Up: [ovstorage-expert](../../SKILL.md)

# Build the resolver

Prerequisites: the [combined build prerequisites](../../../../docs/building.md#prerequisites) are the one maintained list of compilers, CMake, Python and Ubuntu packages; the full build from this checkout below also needs the storage Rust toolchain and `protobuf-compiler` listed there. Windows needs CMake 3.22+. Full procedure and troubleshooting: [local-verification.md](../../../../ovstorage-usd-resolver/docs/local-verification.md).

## Three build levels

Pick the smallest that answers the question; each adds to the previous one.

| Level | Adds | Configure flags |
| --- | --- | --- |
| Core and CLI | Identifier logic, CLI, unit tests; no ovstorage, no USD | `-DOVS_USD_RESOLVER_BUILD_TESTS=ON` |
| ovstorage bridge | Real storage I/O through the CLI | `-DOVS_OVSTORAGE_REQUIRED=ON -DOVS_OVSTORAGE_SDK_ROOT=…` |
| OpenUSD plugin | The `ArResolver` plugin, OpenUSD smokes, and the embedding example | `-DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON -DOVS_USD_SDK_ROOT=…` |

## Full build from this checkout (Linux)

```sh
make -C ovstorage dist                     # storage providers in ovstorage/dist/plugins
python3 ovstorage-usd-resolver/tools/dependencies/stage_ovstorage_providers.py --ovstorage-root ovstorage
cd ovstorage-usd-resolver
OPENUSD_SDK="$PWD/.deps/openusd/25.11.kit.4-gl.21081"
python3 tools/dependencies/acquire_openusd_sdk.py --output "$OPENUSD_SDK"
CC=gcc-13 CXX=g++-13 cmake -S . -B build-openusd-ovstorage -DCMAKE_BUILD_TYPE=Release \
  -DOVS_USD_RESOLVER_BUILD_TESTS=ON \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_SDK_ROOT="$OPENUSD_SDK" \
  -DOVS_OVSTORAGE_SDK_ROOT="$PWD/../ovstorage"
cmake --build build-openusd-ovstorage
ctest --test-dir build-openusd-ovstorage --output-on-failure
```

- Provider-backed CTests are registered only when CMake finds providers under
  the storage SDK's `plugins` or `dist/plugins` at configure time. The staging
  helper above selects runtime plugins into a fresh `ovstorage/plugins`,
  excluding test-only conformance plugins. Pip-installed providers require
  equivalent staging before configuring; runtime plugin configuration alone
  does not enable those tests.
- `OVS_OVSTORAGE_REQUIRED=ON` turns a missing or too-old ovstorage into a configure error instead of a silent build without the bridge. `cmake/DetectOvstorageSdk.cmake` accepts a source tree (`ovstorage-c-source/`) or a release archive (`c-source/`) and checks the compiler and API floor.
- The package identity is `PACKAGE_VERSION` in `tools/dependencies/acquire_openusd_sdk.py` (`0.25.11.kit.4-gl.21081`), which the helper prints as `Package:`. `OPENUSD_SDK` is only a directory label; like the resolver docs, it drops the leading `0.`. Change it with the pin. The [combined build guide](../../../../docs/building.md) is the canonical recipe from the repository root.
- The SDK helper downloads by pinned SHA-256 and writes `.ovs-openusd-sdk.json`; `cmake/NvidiaKitUsd.cmake` rejects any SDK without the Kit 25.11 monolithic layout. To use another SDK, see [openusd-version.md](openusd-version.md).
- Other build options — install surfaces, wheel, Python bootstrap, `plugInfo.json` paths, and the advertised scheme list — are declared at the top of [CMakeLists.txt](../../../../ovstorage-usd-resolver/CMakeLists.txt); scheme selection is in [configure.md](configure.md).

## Platform notes

- Ubuntu 22.04 x86_64 is the source-build baseline; Linux aarch64 and Windows x86_64 have Kit-plugin fixture CI. Matched provider-backed composition remains a separate qualification gate ([compatibility matrix](../../../../ovstorage-usd-resolver/docs/compatibility-matrix.md)).
- Windows: tests prepend the SDK `lib`, `bin`, and `plugin/usd` directories to `PATH`; a host must do the same.
- macOS: there is no pinned SDK package and the helper fails explicitly. Only the core and CLI level builds there.

Next: [validate.md](validate.md).
