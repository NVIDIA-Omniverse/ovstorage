# ovstorage-core

The core workspace: the `ovstorage` library and its first-party direct-mode
plugins, language bindings, and CLI. This workspace ships everything a Rust
/ C / C++ / Python application needs to run `ovstorage` in Direct mode
without an external daemon.

See the [repo-root README](../README.md) for the cross-workspace layout
and dependency graph.

## Crates

- [`ovstorage`](crates/ovstorage/README.md) — the public library; `Storage` trait, `Library`, dispatcher, routing, retries, OAuth surface.
- [`ovstorage-plugin`](crates/ovstorage-plugin/README.md) — plugin SPI: types, capabilities, manifest, C ABI handshake.
- [`ovstorage-plugin-macros`](crates/ovstorage-plugin-macros/README.md) — `ovstorage_plugin!` proc-macro that emits the C ABI for storage plugins.
- [`ovstorage-cache`](crates/ovstorage-cache/README.md) — on-disk state and content-addressed byte cache. Library, not a daemon.
- [`ovstorage-capi`](crates/ovstorage-capi/README.md) — C ABI cdylib + the C++20 header-only wrapper `ovstorage.hpp`.
- [`ovstorage-python`](crates/ovstorage-python/README.md) — PyO3 + `abi3-py310` Python wheel.
- [`ovstorage-cli`](crates/ovstorage-cli/README.md) — `ovstorage` command-line binary.
- [`ovstorage-plugin-file`](crates/ovstorage-plugin-file/README.md) — `file://` backend.
- [`ovstorage-plugin-http`](crates/ovstorage-plugin-http/README.md) — public HTTP(S) read-mostly backend.
- [`ovstorage-plugin-test`](crates/ovstorage-plugin-test/README.md) — controllable test plugin + the workspace's conformance harness, including the [streaming-seams](crates/ovstorage-plugin-test/README.md#streaming-seams) gold reference.

## Examples

- [`examples/plugin-rust/`](examples/plugin-rust/) — minimal Rust storage plugin (the `plugin-storage` persona's working example).
- `examples/cpp-async/` — CMake project showing `ovstorage::task<T>` coroutines + `sync_wait` over the C ABI.
- [`examples/python/`](examples/python/) — dependency-free Python examples
  for calling `ovstorage` through the Python binding.

## Verification

`make verify` from the repo root is the source of truth. Per-crate
`cargo doc -p <crate> --no-deps` is clean for every crate here.
