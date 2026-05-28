# ovstorage-authz

> Canonical user-facing reference lives in
> [`docs/public/plugin-authz/README.md`](../../../docs/public/plugin-authz/README.md).

SPI crate for authorization across the ovstorage workspace. Defines
the `AuthzPlugin` trait, the request / decision / operation types,
the cdylib loader (`LoadedAuthzPlugin`), and the stable C ABI
(`AuthzPluginVTableV1`, `AuthzPluginInitResultV1`,
`OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION` distinct from the storage
SPI's version).

Consumed by both authorization-aware hosts:
[`ovstorage-broker`](../ovstorage-broker/README.md) and
[`ovstorage-rest`](../ovstorage-rest/README.md). The in-tree
first-party plugin built against this SPI is
[`ovstorage-authz-toml`](../ovstorage-authz-toml/README.md).

## Internal architecture

- **`src/lib.rs`** — module wiring, public re-exports
  (`AuthzPlugin` trait, `Principal`, `RequestContext`,
  `AuthzRequest`, `AuthzEffect`, `AuthzDecision`, `Operation`,
  `operation_name`, `operation_from_name`,
  `AUTHZ_PLUGIN_KIND_TOML`).
- **`src/policy.rs`** — `PolicyEpochState` state machine:
  `current_epoch`, `advance`, `check`, `invalidate`. In-memory and
  persisted-via-`state_root` variants. Freshness modes
  `PolicyFreshness::Strict` and `GraceWindow`; grace-window
  honors only `request_epoch + 1 == current_epoch`.
- **`src/attribution.rs`** — `AttributionLayer`,
  `AttributionStrategy` (`UserMetadata`, `Passthrough`,
  `ExternalDb`), `ATTRIBUTION_KEY_MODIFIED_BY`,
  `RESERVED_METADATA_PREFIX`.
- **`src/loaded.rs`** — host-side cdylib loader
  (`LoadedAuthzPlugin`). Validates the plugin's `abi_version`
  against `OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION` via
  `validate_authz_init_result_header`.
- **`src/ffi.rs`** — C ABI types (`AuthzPluginVTableV1`,
  `AuthzPluginInitResultV1`, `AuthzPluginManifestV1`,
  `AuthzDecisionV1`) and `validate_authz_init_result_header`.
- **`src/shim.rs`** — host-side shim that bridges between the
  trait object and the FFI vtable.
- **`src/thunks.rs`** — the macro-generated thunk shapes
  `ovstorage_authz_plugin!` emits. Marshal `AuthzRequest` and
  `&[Url]` from FFI; spawn on the plugin's per-instance tokio
  runtime; capture the response and fire `on_complete`.

## Test layout

- `src/lib.rs::tests` — operation round-trip
  (`operation_names_round_trip`),
  `filter_list_batch_default_uses_request_operation` (pinning the
  Fix A behavior: default impl passes `request.operation`
  through, doesn't hardcode `Operation::Read`).
- `src/policy.rs::tests` — grace-window edge cases:
  `grace_window_honors_immediate_previous_epoch`,
  `grace_window_rejects_two_epochs_old`,
  `grace_window_rejects_invalidated_previous_epoch`,
  `strict_rejects_any_stale_epoch`,
  `current_epoch_accepted_in_both_modes`.

## Cancellation contract

The vtable signatures for `authorize` and `filter_list_batch` each
carry a `cancel: *const CancelTokenFFI` slot, but the Rust
`AuthzPlugin` trait methods take no `CancellationToken`. The
loader passes `std::ptr::null()` for those two slots today. The
`configure` thunk does propagate cancellation when the host hands
it one.

Plugin authors SHOULD bound their own work with an internal
deadline; the host does not propagate cancellation across the
cdylib FFI today. See
[`docs/public/plugin-authz/README.md` § Cancellation contract](../../../docs/public/plugin-authz/README.md#cancellation-contract)
for the operator-facing guidance.

## FFI input ownership contract

Every `*const T` input parameter on a vtable method transfers
ownership from host to plugin at call time. The plugin MUST
consume each input synchronously before returning into
plugin-owned storage. Result and error pointers passed to
`on_complete` transfer ownership in the opposite direction.
Convention matches the storage SPI.
