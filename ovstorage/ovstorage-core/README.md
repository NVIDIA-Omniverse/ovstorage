# ovstorage-core

The core workspace: the `ovstorage` library and its first-party direct-mode
plugins, language bindings, and CLI. This workspace ships everything a Rust
/ C / C++ / Python application needs to run `ovstorage` in Direct mode
without an external daemon.

See the [repo-root README](../README.md) for the cross-workspace layout
and dependency graph.

## Crates

- [`ovstorage`](ovstorage/README.md) — the public library; Stack construction, `LayerExt` operations, routing, wrappers, authentication, and the built-in native `file://` backend (in `ovstorage/src/file/`).
- [`ovstorage-plugin`](ovstorage-plugin/README.md) — plugin SPI: types, capabilities, manifest, C ABI handshake.
- [`ovstorage-plugin-macros`](ovstorage-plugin-macros/README.md) — `ovstorage_layer_plugin!` proc-macro that exports ABI-v2 Layer plugins.
- [`ovstorage-cache`](ovstorage-cache/README.md) — embedded on-disk state and content-addressed byte cache, not a daemon.
- [`ovstorage-python`](ovstorage-python/README.md) — PyO3 + `abi3-py310` Python wheel.
- [`ovstorage-cli`](ovstorage-cli/README.md) — `ovstorage` command-line binary.
- [`ovstorage-plugin-http`](ovstorage-plugin-http/README.md) — public HTTP(S) read-mostly backend (ABI-v2 Layer cdylib). The `file://` backend is no longer a plugin crate — it is built into `ovstorage` (see above).
- [`ovstorage-plugin-test`](ovstorage-plugin-test/README.md) — controllable test plugin + the workspace's conformance harness, including the [streaming-seams](ovstorage-plugin-test/README.md#streaming-seams) gold reference.

## Examples

- [`examples/plugin-rust/`](examples/plugin-rust/) — minimal Rust storage plugin (the `plugin-storage` persona's working example).
- [`examples/python/`](examples/python/) — dependency-free Python examples
  for calling `ovstorage` through the Python binding.

## Verification

`make verify` from the repo root is the source of truth. Per-crate
`cargo doc -p <crate> --no-deps` is clean for every crate here.
