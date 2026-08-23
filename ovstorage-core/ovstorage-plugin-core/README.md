# ovstorage-plugin-core

This Rust implementation crate provides the public, host-independent
composition Layers:

- `router`
- `alias`
- `copy_rename_fallback`
- `retry`

The sibling `ovstorage-plugin-core-abi` package exports these factories as the
shipped `libovstorage_plugin_core` ABI-v2 cdylib. Keeping the fixed-name entry
points in that cdylib-only shell lets Rust hosts link this implementation
without exporting plugin symbols from their own binaries.
