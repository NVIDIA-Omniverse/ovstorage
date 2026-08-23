# ovstorage-plugin-cache

This Rust implementation crate provides the `metadata_cache` and `byte_cache`
wrapper Layers. The sibling `ovstorage-plugin-cache-abi` package exports them
as the shipped `libovstorage_plugin_cache` ABI-v2 cdylib.

`metadata_cache` caches `stat` and `list` results. `byte_cache` stores validated
object content in a local content-addressed cache. Both wrappers preserve the
request extension envelope and invalidate entries when mutations or watch
events pass through them.
