# ovstorage-authz-toml

> Canonical user-facing reference (the TOML policy schema, the
> matching rules, examples) lives in
> [`docs/public/plugin-authz/README.md`](../../../docs/public/plugin-authz/README.md).

First-party authz plugin for `ovstorage-broker` and
`ovstorage-rest`. Implements the `AuthzPlugin` SPI from
[`ovstorage-authz`](../ovstorage-authz/README.md) using deterministic
TOML policy that runs in local conformance without external
services. The only authz plugin shipped in-tree today.

Hosts select this plugin by manifest `name = "ovstorage-authz-toml"`
under their `[authz]` config block; unknown plugin names fail
startup with `NotConfigured`.

## Internal architecture

- **`src/lib.rs`** — `TomlAuthzPlugin`, the `AuthzPlugin` impl,
  rule matching (`glob_match`, segment-aligned prefix matching,
  longest-prefix precedence + same-prefix later-rule precedence).
- **`src/ffi_export.rs`** — the cdylib export thunks
  (`configure_thunk`, `authorize_thunk`,
  `filter_list_batch_thunk`, `drop_plugin`); per-instance
  multi-threaded `tokio::runtime::Runtime`; in-flight counter
  (mutex + condvar) with a 5-second drain timeout on
  `drop_plugin`.
- **`build.rs`** — builds the cdylib for the `_test_support`
  feature path.
- **`tests/`** — end-to-end conformance harness (FFI vtable
  validation, concurrent `authorize`, drain semantics, schema
  validation).

## Test layout

- `src/lib.rs::tests` — empty policy denies, allow / deny
  matching, wildcard principal, wildcard operation,
  longest-prefix precedence, same-prefix later-rule precedence,
  invalid effect / operation / prefix validation, `glob_match`
  edge cases, `decision_ttl_max_seconds` round-trip,
  `address = None` matches only `prefix = "*"` rules.
- `tests/` — cdylib `configure` rejects negative / wrong-typed
  knobs with `InvalidArgument`; `decision_ttl_max_seconds`
  round-trips through `configure` -> `authorize` to the FFI
  decision; 32 concurrent `authorize` calls on the per-instance
  tokio runtime; clean drop after in-flight calls (drain on
  `LoadedAuthzPlugin::drop`).

## ABI lifecycle

The init result advertises `OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION`
(defined in `ovstorage-authz`), distinct from the storage SPI's
`OVSTORAGE_PLUGIN_ABI_VERSION`. The host validates the init result
against the same authz constant via
`validate_authz_init_result_header`, so authz and storage ABIs
evolve independently.

Each FFI vtable thunk dispatches via
`tokio::runtime::Runtime::spawn` on the plugin's per-instance
runtime. `PluginState` carries an internal in-flight counter;
each thunk increments before spawning, the guard decrements and
notifies on drop. `drop_plugin` waits on the condvar up to a
5-second drain timeout before freeing state — callbacks never
observe a torn-down runtime.

Cancellation differs per thunk:

- `configure_thunk` receives a real `*const CancelTokenFFI`
  pointer when the host built one; `cancel_is_signalled` is
  consulted before scheduling work.
- `authorize_thunk` and `filter_list_batch_thunk` each receive
  `std::ptr::null()` for the cancel slot today (the Rust
  `AuthzPlugin` trait methods take no `CancellationToken`); each
  thunk defensively calls `cancel_is_signalled` but the null
  pointer means it always returns false. Closing the gap is a
  three-workspace trait change documented in
  [`docs/public/plugin-authz/README.md` § Cancellation contract](../../../docs/public/plugin-authz/README.md#cancellation-contract).
