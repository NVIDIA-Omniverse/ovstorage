# ovstorage-plugin-macros

> The canonical author reference is
> [`plugin-development` § Plugin macros](../../docs/public/plugin-development/README.md#plugin-macros).

## Purpose

This proc-macro crate provides `ovstorage_layer_plugin!`, which exports an
ABI-v2 Layer plugin from a Rust `cdylib`:

```rust,ignore
ovstorage_layer_plugin!(backend, MyBackendFactory::default);
ovstorage_layer_plugin!(wrapper, MyWrapperFactory::default);
ovstorage_layer_plugin!(router, MyRouterFactory::default);
ovstorage_layer_plugin!(backend, TestFactory::default, test_only);
ovstorage_layer_plugin!((
    (backend, MyBackendFactory::default),
    (wrapper, MyWrapperFactory::default),
    (router, MyRouterFactory::default),
));
```

The first argument selects the factory trait and composition shape. The second
is a constructor expression yielding the matching `BackendFactory`,
`WrapperFactory`, or `RouterFactory`. The optional `test_only` flag marks the
manifest for host-side gating.

The bundled form exports several kinds from one `cdylib`. Each entry is a
`(tag, constructor)` pair and the optional `test_only` flag applies to the
whole plugin. The host rejects a bundle that advertises the same kind more
than once.

The macro emits `ovstorage_plugin_manifest_v1` and
`ovstorage_plugin_init_v1`. Those are stable symbol names; the manifest's
`abi_version` identifies the Layer ABI. Init installs a `LayerPlugin` containing
the factory and returns the ABI-v2 `PluginInitResultV1`.

## Contributor notes

The expansion uses `format!` plus `TokenStream::from_str` to avoid
`proc-macro2`, `syn`, and `quote` dependencies. Argument parsing walks
`proc_macro::TokenTree`, splitting only top-level commas while respecting angle
brackets. A non-empty third segment must be exactly `test_only`; other flags
produce `compile_error!`.

Package name and version come from `CARGO_PKG_NAME` and `CARGO_PKG_VERSION` at
the invocation site. The expansion registers host callbacks, installs the log
Layer, constructs each factory once, and passes the factory vector to ABI-v2
thunk installation.

## Cross-links

- [ovstorage-plugin](../ovstorage-plugin/README.md) — Layer and C-ABI contract.
- [ovstorage-plugin-test](../ovstorage-plugin-test/README.md) — conformance
  fixture exported with the `test_only` flag.
- [plugin-rust](../examples/plugin-rust/) — minimal compiling backend example.
