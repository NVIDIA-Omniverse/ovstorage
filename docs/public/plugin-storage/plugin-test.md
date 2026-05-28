# Test plugin (`ovstorage-plugin-test`)

`ovstorage-plugin-test` is a *test* plugin (`test_only = true`),
not a template for vendor backends. See
[`../plugin-development/README.md` § Conformance harness](../plugin-development/README.md#conformance-harness)
for what the host exercises against you and the registry entry
shape that pins each scenario.

## Bundled with the release archive

The cdylib ships alongside the production plugins in
`<archive>/plugins/`. The manifest carries `test_only = true` and the
loader gates it behind `Builder::allow_test_plugins(true)` (default
`false`).

Two host code paths interact differently with that gate:

- `Library::load_plugins_from_dir` — bulk discovery (the broker and
  REST gateway use this at startup). When `allow_test_plugins` is
  off, the test plugin is **skipped** at debug-log level and the
  scan continues. A default-posture host that points at the release
  archive's `plugins/` directory ignores the test plugin and starts
  cleanly.
- `Library::load_plugin` — direct, by-path load. When
  `allow_test_plugins` is off, the call returns
  `ErrorCode::PluginRejected`. A caller that explicitly asks for the
  test plugin gets a clear refusal rather than silent inaction.

Consumers who want to drive their host through the conformance edge
cases build the host with `allow_test_plugins(true)` and either call
`load_plugin` directly with the cdylib path, or set the bulk-load
plugin directory to one containing the test plugin.
