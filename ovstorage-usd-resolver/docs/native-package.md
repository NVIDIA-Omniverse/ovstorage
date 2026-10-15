# Native CMake package

The preview native install surface targets Linux x86_64/aarch64 and Windows
x86_64. It installs the core, OpenUSD plugin, static ovstorage bridge and C API,
public headers, plugin metadata, diagnostic CLI, CMake exports, and notices.
The USD SDK and ovstorage provider libraries remain external. Python bootstrap
and wheels use a separate build and install component.

The prefix's `licenses/` directory contains `LICENSE`, `NOTICE`,
`THIRD_PARTY_NOTICES.md`, and `tomlc17-LICENSE` for the parser included in the
static C API. Installed ovstorage headers retain their upstream notices.

Run from the resolver component root with the prerequisites in the
[source build guide](building.md). Use a single-configuration Release generator
and a supported compiler:

```sh
cmake -S . -B build-native -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_TESTS=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_RESOLVER_INSTALL_NATIVE=ON \
  -DOVS_USD_SDK_ROOT=/path/to/exact/kit-sdk \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage-v0.3.0-source
cmake --build build-native
cmake --install build-native --prefix /path/to/resolver-sdk --component native
```

The ovstorage C API must be built from sources. A prebuilt C API library is
rejected to avoid an untracked runtime dependency. Native and wheel install
options must not be enabled in the same build directory. The default build
continues to provide the original build-tree CLI and tests; installation uses
a separate CLI with relative plugin discovery.

A downstream project uses the installed prefix and its exact host SDK:

```cmake
find_package(OvStorageUsdResolver 0.1.0 EXACT REQUIRED CONFIG)
target_link_libraries(my_host PRIVATE
    ovstorage::usd_resolver_ovstorage_bridge
    ovstorage::usd_resolver_openusd)
```

Pass `-DCMAKE_PREFIX_PATH=/path/to/resolver-sdk` and
`-DOVS_USD_SDK_ROOT=/path/to/exact/kit-sdk` at consumer configuration.
`OvStorageUsdResolver_PLUGIN_DIR` identifies the installed `plugin/` directory.
Register it before first OpenUSD use, retain the ovstorage runtime, and propagate
contexts to host workers as described in the embedding guide. The exported
core target is `ovstorage::usd_resolver_core`; the bridge transitively supplies
its bundled static C API and ovstorage headers. A host that builds its own
ovstorage stack links `ovstorage::usd_resolver_host` and hands that stack to
the resolver through `ovstorage_usd_resolver/host.hpp` instead of configuring
the bridge. It also links `ovstorage::usd_resolver_openusd` when it includes
`ovstorage_usd_resolver/openusd_host.hpp`. That header calls nothing in the
plugin library but needs OpenUSD and the resolver core, which the target
supplies through its interface; linking it also makes the plugin library a
load-time dependency, the same file `plugin/plugInfo.json` names. Including
`host.hpp` needs only C++17, but the library behind it is the concrete bridge's
code: building it from source needs the bridge's C++20 compiler floor (GCC 13+,
Clang 17+ or MSVC 19.40+), and linking the prebuilt archive needs the matching
compiler and runtime described below. The host target links the package's copy
of the static C API, with global `ovstorage_*` symbols, into the host. On
Linux, a copy of ovstorage's C runtime that exports those symbols into the
process's global scope can capture another copy's calls to the same names. So
no two copies may share a binary, and no copy, the host's included, may export
them from a shared library the executable links or opens with `RTLD_GLOBAL`,
or from an executable linked with `--export-dynamic`. In a host that is itself
a shared library, `-Wl,--exclude-libs,ALL` keeps the package's archived copy
local, as the reference consumer below does; a copy compiled from ovstorage's
C sources into the library itself needs hidden visibility or a version script.
Check a prebuilt library with `nm -D --defined-only`. Provider plugins and
Python extension modules export `ovstorage_plugin_*` helpers, but ovstorage
and Python open them with `RTLD_LOCAL`, outside the global scope. A Windows DLL
exports only functions marked for export, and ovstorage's headers mark none.
`createRuntimeForSharedStack` calls through the exported handle's function
table, so accept an exported handle only from trusted code already running in
the process, never from external or serialized input.

The package compares the host's monolithic USD library SHA-256 with the one
used at build time and rejects a conflicting pre-existing `usd_m` target.
This is an exact-host check, not a general C++ ABI guarantee: compiler, runtime,
architecture, configuration and the full USD SDK must still match. The package
version check accepts only the exact resolver version. macOS native packages
and arbitrary OpenUSD distributions are not qualified.

The prefix can be moved after installation. On Linux, libraries use relative
rpaths and the CLI is in `bin/`. On Windows, the CLI is in `lib/` beside its
resolver DLLs. The host must expose the exact SDK's `lib`, `bin`, and
`plugin/usd` runtime directories to its loader. Providers are explicitly loaded
from a trusted external directory; they are not part of this install tree.

Native CI installs and relocates the prefix, copies a standalone embedding
consumer outside the source tree, builds it using only `find_package`, and
checks HTTP composition, installed CLI discovery, package payloads, wrong-SDK
rejection and conflicting-host-target rejection. A second consumer is a C++17
shared library that links `ovstorage::usd_resolver_host`. It registers and
verifies the plugin, builds a stack through ovstorage's C API, and adopts it.
On Linux it links with `--exclude-libs,ALL`, and the check fails if it exports
any `ovstorage_*` symbol.

To reproduce the installed-consumer checks locally on Linux after the build
and install above, run from the resolver component root. Use the same compiler
and exact SDK, and a matching provider directory containing the HTTP provider:

```sh
resolver_sdk=/path/to/resolver-sdk
usd_sdk=/path/to/exact/kit-sdk
providers=/path/to/ovstorage-v0.3.0-source/plugins
consumer_work=$(mktemp -d)
cp tests/installed/CMakeLists.txt tests/installed/host_consumer*.cpp "$consumer_work/"
cp examples/embed_resolver/embed_resolver.cpp "$consumer_work/"
cmake -S "$consumer_work" -B "$consumer_work/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$resolver_sdk" -DOVS_USD_SDK_ROOT="$usd_sdk"
cmake --build "$consumer_work/build"
export LD_LIBRARY_PATH="$resolver_sdk/lib:$usd_sdk/lib:$usd_sdk/bin:$usd_sdk/plugin/usd${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
build-native/ovstorage_usd_resolver_embed_example_smoke \
  "$consumer_work/build/installed-consumer" "$resolver_sdk/plugin" "$providers"
"$consumer_work/build/installed-host-consumer" "$resolver_sdk/plugin" "$consumer_work"
```

On Windows x86_64, run the equivalent from PowerShell in a developer shell for
the same MSVC toolchain. The SDK and resolver runtime directories go on `PATH`,
and the providers are the matching Windows DLLs:

```powershell
$resolver_sdk = "C:\path\to\resolver-sdk"
$usd_sdk = "C:\path\to\exact\kit-sdk"
$providers = "C:\path\to\ovstorage-v0.3.0-source\plugins"
$consumer_work = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid())
New-Item -ItemType Directory $consumer_work | Out-Null
Copy-Item tests\installed\CMakeLists.txt, tests\installed\host_consumer*.cpp, `
  examples\embed_resolver\embed_resolver.cpp -Destination $consumer_work
cmake -S $consumer_work -B "$consumer_work\build" -G Ninja -DCMAKE_BUILD_TYPE=Release `
  "-DCMAKE_PREFIX_PATH=$resolver_sdk" "-DOVS_USD_SDK_ROOT=$usd_sdk"
cmake --build "$consumer_work\build"
$env:PATH = "$resolver_sdk\lib;$usd_sdk\lib;$usd_sdk\bin;$usd_sdk\plugin\usd;$env:PATH"
.\build-native\ovstorage_usd_resolver_embed_example_smoke.exe `
  "$consumer_work\build\installed-consumer.exe" "$resolver_sdk\plugin" $providers
& "$consumer_work\build\installed-host-consumer.exe" "$resolver_sdk\plugin" $consumer_work
```

The first executable checks HTTP composition through the installed package;
the second checks host-owned stack adoption. To check relocation, move the
installed prefix to a fresh location first and set `resolver_sdk` to that path.
These public-source commands do not perform the internal CI payload scan or
wrong-SDK negative controls described above.

Those checks validate local installation; producing a native archive or Conan
package for distribution requires a separate release decision. No resolver
wheels are published for this release. Maintainer release automation is not
part of the public source checkout.
