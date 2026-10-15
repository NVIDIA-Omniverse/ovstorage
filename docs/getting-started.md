# Getting started

This page covers the two ways to start: installing the standalone storage package, and building the USD resolver from this repository's sources.

## Install the storage package

```sh
python -m pip install "ovstorage==<storage version>"
```

Replace `<storage version>` with the storage version recorded in
[VERSION.md](../VERSION.md), which lists it and the resolver's version
separately; the [root README](../README.md) shows the rendered command. Do not
substitute the newest wheel when reproducing the bundled source/provider
combination.

Continue with the guide for your language: [Python](../ovstorage/docs/public/library-python/README.md), [Rust](../ovstorage/docs/public/library-rust/README.md), or [C++](../ovstorage/docs/public/library-cpp/README.md). Backend selection and connection settings are described in [configuration](../ovstorage/docs/public/configuration.md).

## Build the USD resolver

No resolver wheels are published to PyPI or elsewhere for this release. Build
from source for the consuming host. A USD version number alone does not identify
a compatible binary SDK; match the host headers, libraries and runtime. The
supported 0.1 plugin baseline is the NVIDIA Kit OpenUSD 25.11 monolithic ABI.

Follow the [combined build guide](building.md). It is the one maintained list
of toolchain, Linux link-dependency and OpenUSD SDK requirements, and covers
source-built or prebuilt storage providers, SDK acquisition, and CMake/CTest.
Those commands run from the **combined repository root**. Component guides
that use `cmake -S .` or `make` expect the corresponding component root.

The [local verification guide](../ovstorage-usd-resolver/docs/local-verification.md)
describes SDK layouts, provider-backed tests and optional live checks. To embed the resolver in your own host, start with the [architecture reference](../ovstorage-usd-resolver/docs/architecture.md) and the [configuration contract](../ovstorage-usd-resolver/docs/configuration.md).

## Using prebuilt storage providers

You can compile the resolver against the bundled C source and supply compatible prebuilt storage providers. Select the exact storage package version validated for this snapshot rather than the latest wheel; the provider plugin ABI must match the bundled source.

The Python storage package exposes `ovstorage.bundled_plugins_dir()` for its
provider directory. Select the exact version matching the bundled sources;
this does not install the resolver. For provider-backed CTests, stage that
matching package's plugins under `ovstorage/plugins` (fresh destination), then
reconfigure CMake. CMake searches `plugins` and `dist/plugins` beneath
`OVS_OVSTORAGE_SDK_ROOT`; runtime configuration alone does not register tests.
See the resolver [SDK layout guide](../ovstorage-usd-resolver/docs/local-verification.md#ovstorage-sdk-layout).

## Component boundaries

- `ovstorage/ovstorage-services/` contains vendored Storage, Notifications and
  Permissions API contracts, generated/reference material and conformance
  examples. Production service implementations, Helm charts and deployment
  assets are not included. Imported draft or external deployment guidance is
  not a runnable library setup path.
- `ovstorage/ovstorage-services-client/` implements a client plugin for those
  APIs; its name and generated bindings are legitimate component paths.
- `ovstorage/ovstorage-remote/` implements the separate broker/REST surfaces.
  Existing public guidance does not recommend these for new deployments;
  normal library and resolver use embeds storage in-process.

Use the [storage skill inventory](../ovstorage/AGENTS.md#invocable-skills) for linked library
workflows. The copied API directory is reference material, not another set of
runtime skills to register indiscriminately. Its files retain upstream terms
and follow the vendor-sync process.
