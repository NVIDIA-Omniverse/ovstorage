Up: [ovstorage-expert](../../SKILL.md)

# Embed or install the resolver

All paths below require the host's OpenUSD to be the **exact** SDK the resolver was built for. A matching `PXR_VERSION` alone is not enough ([openusd-version.md](openusd-version.md)).

## C++ host from source

Follow [examples/embed_resolver](../../../../ovstorage-usd-resolver/examples/embed_resolver/README.md), the runnable reference:

1. Load provider plugins from a trusted directory into an ovstorage registry, build the Stack from `ovstorage.toml`, and take its `LayerHandle`.
2. Move it into `OvStorageBridgeOptions::layerHandle`, or pass `configPath` and `pluginDirectory` and let the bridge build the Stack.
3. Build `ResolverOptions`, call `createResolverRuntime()`, then `makeOpenUsdResolverContext()`.
4. Pass that context to `UsdStage::Open(path, context)`. Bind it with `ArResolverContextBinder` (or `ScopedDefaultContext`) on every thread that resolves or opens assets directly.

Configure the runtime before OpenUSD first calls `ArGetResolver()`; it cannot be swapped afterward. Rules and ownership: the "Embedded Usage" section of [configuration.md](../../../../ovstorage-usd-resolver/docs/configuration.md).

## Native CMake package

Install with `-DOVS_USD_RESOLVER_INSTALL_NATIVE=ON`, then in the consumer:

```cmake
find_package(OvStorageUsdResolver 0.1.0 EXACT REQUIRED CONFIG)
target_link_libraries(app PRIVATE ovstorage::usd_resolver_openusd)
```

Other exported targets: `ovstorage::usd_resolver_core` and `ovstorage::usd_resolver_ovstorage_bridge`. At configure time the package checks the consumer's USD library hash against the one it was built with and refuses a mismatch. Details: [native-package.md](../../../../ovstorage-usd-resolver/docs/native-package.md).

## Optional locally built Python package

No resolver wheels are published for this release. Build the optional package
locally using the linked guide; its SDK receipt requirements are stricter than
the plugin source build. Installing `ovstorage` alone does not provide it.

The distribution name encodes the USD flavour (`ovstorage-usd-resolver-kit-25-11`); it imports as `ovstorage_usd_resolver` and depends on `ovstorage>=0.3.0,<0.4.0` for providers. It bundles no `pxr` bindings: the host supplies the matching Kit SDK.

```python
import ovstorage, ovstorage_usd_resolver as resolver

resolver.register_plugin(usd_sdk_root="/path/to/matching/kit-sdk")
with resolver.Runtime("ovstorage.toml",
                      plugin_directory=ovstorage.bundled_plugins_dir()) as runtime:
    with runtime.bind():          # per OS thread; don't suspend async tasks inside
        ...                       # OpenUSD work
```

`usd_sdk_root` verifies the SDK against the wheel's receipt; a different SDK needs a new process. Reference: [python-wheels.md](../../../../ovstorage-usd-resolver/docs/python-wheels.md).

Verify any of these with [validate.md](validate.md).
