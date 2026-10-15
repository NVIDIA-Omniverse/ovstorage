# Test plugin (`ovstorage-plugin-test`)

`ovstorage-plugin-test` is a *test* plugin (`test_only = true`),
not a template for vendor backends. See
[`../plugin-development/README.md` § Conformance harness](../plugin-development/README.md#conformance-harness)
for what the host exercises against you and the registry entry
shape that pins each scenario.

## Bundled with the release archive

The cdylib ships alongside the production plugins in
`<archive>/plugins/`. It is built from the sibling
`ovstorage-plugin-test-abi` crate (artifact
`libovstorage_plugin_test_abi.so` / `.dylib` /
`ovstorage_plugin_test_abi.dll`; manifest
`name = "ovstorage-plugin-test-abi"`), which wraps the rlib-only
`ovstorage-plugin-test` harness crate — the ABI export was split out
so the harness can be linked into other plugins' test binaries
without entry-point symbol collisions. The manifest carries
`test_only = true` and the loader gates it behind
the host's `allow_test_plugins` setting (default `false`).

Two host code paths interact differently with that gate:

- Directory discovery — the broker and
  REST gateway use this at startup). When `allow_test_plugins` is
  off, the test plugin is **skipped** at debug-log level and the
  scan continues. A default-posture host that points at the release
  archive's `plugins/` directory ignores the test plugin and starts
  cleanly.
- Direct, by-path loading — when
  `allow_test_plugins` is off, the call returns
  `ErrorCode::PluginRejected`. A caller that explicitly asks for the
  test plugin gets a clear refusal rather than silent inaction.

Consumers who want to drive their host through the conformance edge
cases enable `allow_test_plugins` in the host configuration and point
plugin discovery at a directory containing the test cdylib.
