# Optional local Python package

No resolver wheels are published to PyPI or elsewhere for this release. Start
with [building from source](building.md). This page describes local wheel
builds and the Python bootstrap for the pinned SDK; it is not an installation
recipe for a published resolver package. ovstorage publishes its own packages.

The distribution is `ovstorage-usd-resolver-kit-25-11`; its Python import remains
`ovstorage_usd_resolver`. The name selects the Kit 25.11 flavour family; the
receipt and runtime check select the exact nopy monolithic SDK below. Different
flavour distributions must not be installed together into one environment.

The local wheel build targets the NVIDIA Kit **nopy, ov-full-monolithic,
0.25.11.kit.4-gl.21081** ABI on Linux x86_64, Linux aarch64, and Windows x86_64.
Matching `PXR_VERSION=2511` alone is insufficient. The host supplies this exact
OpenUSD runtime and its system dependencies. The wheel does not bundle another
USD runtime, install `usd-core`, or provide `pxr` Python bindings. Its Python API
configures storage and binds it around a compatible host's OpenUSD work.
macOS remains a source portability target with no qualified wheel SDK.

The package contains the resolver core, USD plugin, a ctypes bootstrap, plugin
metadata, and diagnostic CLI. It statically links the ovstorage C API. Provider
libraries come from the `ovstorage>=0.3.0,<0.4.0` dependency; callers explicitly
select its trusted provider directory. Their licenses remain with that package.
The wheel preserves the copied C API TOML parser's MIT license separately.

The bootstrap uses no Python C API, so the audited CI wheel tags are
`py3-none-manylinux_2_35_x86_64`, `py3-none-manylinux_2_35_aarch64`, and
`py3-none-win_amd64`. Linux wheel CI builds use Clang 18 with Ubuntu 22.04's
GCC 11 C++ headers, retain the system libstdc++ ABI, and audit the result against
the glibc 2.35 policy. Building with a newer GCC standard library can introduce
newer symbol requirements and is not sufficient evidence for that wheel tag.
Windows builds use the MSVC runtime and the selected Kit DLLs. The manylinux
tag describes the resolver libraries, not the external USD runtime: a host
SDK with newer system-library requirements still needs those requirements
satisfied. Pip cannot check that external dependency.

The Linux audit excludes only the exact host USD SONAME. It must not copy USD,
SDK support libraries, or provider libraries into the wheel. The host SDK
remains a prerequisite: `Requires-External` records its exact flavour/version,
and `build-info.json` records its package and library fingerprints. Pip does
not install or enforce `Requires-External`; the host must supply that SDK and
its runtime dependencies before loading the plugin. This is a host plugin,
not a standalone USD installation. Installed-consumer tests exercise this contract on each configured CI target.
That evidence does not make a wheel a published release artifact.

## Python configuration

Register before the host's first OpenUSD resolver use. Import alone does not
load USD or change resolver state. The SDK root can be supplied on the first
registration call; otherwise the host must already provide its loader setup.
An explicitly supplied SDK library must match the wheel receipt's SHA-256.
`Runtime(..., usd_sdk_root=...)` performs the same verification and registration
before constructing storage, so a separate registration call is optional.
Repeating the same SDK root is supported. A different root, or adding a root
following unverified host-based initialization, requires restarting the process.
Omitting the root explicitly leaves ABI selection with the embedding host.
The host must not have loaded an incompatible USD implementation beforehand.
On Linux, configure the host SDK's `lib` and `plugin/usd` loader search paths
before starting Python. On Windows, explicit SDK registration adds its native
DLL directories for this process.

```python
import ovstorage
import ovstorage_usd_resolver as resolver

resolver.register_plugin(usd_sdk_root="/path/to/matching/kit-sdk")
with resolver.Runtime(
    "ovstorage.toml",
    plugin_directory=ovstorage.bundled_plugins_dir(),
    verify_existence=False,
) as runtime:
    with runtime.bind():
        # Invoke the embedding host's OpenUSD API on this thread.
        # A stage captures this context for its dependency loads and reloads.
        pass
```

Configuration is an explicit ovstorage StackConfig file. Invalid configuration
fails during `Runtime` construction. Omitting `plugin_directory` permits only
built-in providers, such as file IO. The API does not silently search for plugin
code or choose a process-wide default runtime.

Each worker thread must enter its own binding. Nested scopes unwind in reverse
order on the entering OS thread. Do not suspend an asynchronous task while a
scope is active: another task on the same thread could observe its context.
`close()` releases the Python owner's reference; existing scopes and captured
stage contexts retain the runtime. A closed owner cannot create new bindings.
The native C++ embedding APIs remain available and independent.

`cli_path()` returns the installed executable. The CLI finds its plugin metadata
relative to itself. Subprocesses need the host SDK loader environment too;
process-local DLL handles from Python are not inherited by a new process.

## Build and validation

Acquire the pinned SDK with `tools/dependencies/acquire_openusd_sdk.py` and use
an ovstorage 0.3 source SDK (the wheel requires the C API sources, not an external
prebuilt C API library):

```bash
python -m pip wheel . --no-deps -w dist/wheels \
  -Ccmake.define.OVS_USD_SDK_ROOT=/path/to/acquired/kit-sdk \
  -Ccmake.define.OVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage-source
```

Use GCC 13+, Clang 17+, or MSVC 19.40+ for the bridge and CMake 3.22+.
Wheel builds require the SDK helper's provenance receipt and include it in
`build-info.json` with the linked USD library's SHA-256 and exact ovstorage source commit.
For a source archive without Git metadata, supply the recorded 40-digit commit
with `-Ccmake.define.OVS_OVSTORAGE_SOURCE_REVISION=<commit>` and the resolver's
40-digit commit with `-Ccmake.define.OVS_USD_RESOLVER_SOURCE_REVISION=<commit>`. Relative plugin paths
and loader paths keep build-machine resolver directories out of the install.

The installed-consumer test uses a separate C++ host linked only to USD, since
the selected nopy SDK has no Python bindings. Python configures and binds the
installed resolver; that host composes a remote root and sublayer through it.
The test also checks concurrent threads, invalid configuration, binding order,
lifetime after closing the Python owner, and installed CLI discovery.

Local tests may install with `--no-deps` and use providers built from the
recorded ovstorage revision. Such a test does not exercise normal pip
dependency resolution. Internal full-stack CI also tests against the released
ovstorage 0.3.0 package and its providers. Neither path publishes resolver wheels.

## Host-owned OVStage integration

The embedding application owns resolver installation, ABI selection and early
registration. Initialize/register before OVStage or another USD user can freeze
resolver discovery; construct storage before creating a stage. Use
`verify_existence=True` for hosts that treat a nonempty Resolve result as proof
of existence. Each worker thread needs its own binding or an explicitly passed
captured context. A Python scope around an asynchronous host call alone does
not propagate the context to host-created workers.

The host must align resolver scheme registration with its ovstorage routes.
This resolver does not initialize OmniClient or load Carbonite. Host ownership
of the resolver does not imply that a particular OVStage release uses this exact
Kit SDK; check the actual host package ABI and run an installed OVStage consumer
test before claiming integration. Our USD-only test host proves the bootstrap
contract, not the full OVStage adapter or its worker-thread behavior.

## Local artifact checks

Use the locally built wheel only with its recorded SDK and compatible provider
binaries. Raw Linux development wheel tags do not establish a manylinux runtime
floor; do not rename wheels to imply that guarantee. Existing CI audits native
library dependencies, license inventory, paths and printable binary strings.
These tests remain useful without making package publication a release gate.

A successful local Python consumer is not evidence of Conan packaging or a
complete OVStage integration. Validate the actual host's plugin discovery,
context propagation and remote composition separately.
