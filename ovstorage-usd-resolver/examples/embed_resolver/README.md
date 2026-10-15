# Embed the resolver

This example is the native source-embedding consumer path for 0.1. It shows the host-owned
integration boundary:

1. load provider plugins from a trusted directory into an ovstorage registry;
2. build an ovstorage stack from `ovstorage.toml` and receive its
   `LayerHandle`;
3. move that handle into `OvStorageBridgeOptions::layerHandle`;
4. create a resolver runtime and bind it to the OpenUSD context; and
5. call `UsdStage::Open` normally.

The program is provider-agnostic. The included [`ovstorage.toml`](ovstorage.toml)
selects an identity route for NVIDIA's public S3-backed HTTPS sample origin, so
it is runnable without credentials. Changing providers within a scheme already
advertised by the resolver build requires only a matching TOML route. A new URI
scheme, such as `az`, must also be advertised when configuring the build, for
example with `-DOVS_USD_RESOLVER_URI_SCHEMES="s3;http;https;hf;az"`. The stage
URI's scheme must therefore be present in both the build-advertised resolver
list and the runtime ovstorage graph. No C++ source change is required, but a
different build-time scheme list requires rebuilding the resolver.

Provider-agnostic wiring does not imply that every provider has the same
release evidence: resolver 0.1 qualifies native-S3 read/composition against
AWS S3, as recorded in the
[compatibility matrix](../../docs/compatibility-matrix.md).

## Build

Use the release-target OpenUSD SDK and ovstorage 0.3.x as specified in the
[compatibility matrix](../../docs/compatibility-matrix.md). Each resolver
candidate records the exact ovstorage 0.3.x tag used for verification. The
ovstorage SDK path must contain its C source or C API library; its provider
plugins may be supplied from a separate directory at run time.

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081

CXX=g++-13 CC=gcc-13 cmake -S . -B build-embed \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_USD_RESOLVER_BUILD_EXAMPLES=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081
cmake --build build-embed --target ovstorage_usd_resolver_embed
```

## Run

Open the public stage covered by the sample configuration:

```bash
export LD_LIBRARY_PATH="$(pwd)/.deps/openusd/25.11.kit.4-gl.21081/lib:$(pwd)/.deps/openusd/25.11.kit.4-gl.21081/plugin/usd${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

./build-embed/examples/embed_resolver/ovstorage-usd-resolver-embed \
  https://omniverse-content-production.s3.us-west-2.amazonaws.com/Samples/Astronaut/Astronaut.usd \
  examples/embed_resolver/ovstorage.toml \
  /path/to/ovstorage/plugins \
  build-embed/resources
```

The output is deliberately machine-readable enough for a smoke check:

```text
root_identifier=https://omniverse-content-production.s3.us-west-2.amazonaws.com/Samples/Astronaut/Astronaut.usd
prim_count=...
used_layer_count=...
ovstorage_asset_opens=...
```

`ovstorage_asset_opens` must be nonzero. This guards against a stage opening
through some other resolver path while the example appears to succeed.

Loading a shared library executes code. Point the provider-plugin argument only
at a directory whose contents the host trusts. Applications requiring an exact
allowlist can replace the directory scan with explicit `Plugin::load` calls;
the `LayerHandle` handoff remains unchanged.
