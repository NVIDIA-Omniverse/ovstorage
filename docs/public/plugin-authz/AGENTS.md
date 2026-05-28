# plugin-authz — agent routing

Terse map for agents authoring an authz plugin for `ovstorage-broker`
or `ovstorage-rest`. For prose, see [README.md](README.md).

## Where to start

- **AuthzPlugin trait + types**: [README.md § AuthzPlugin trait](README.md#authzplugin-trait).
- **The 21 operations**: [README.md § The 21 operations](README.md#the-21-operations).
- **Reference plugin**:
  `ovstorage-remote/crates/ovstorage-authz-toml/src/` for sources;
  [README.md § Worked example: ovstorage-authz-toml](README.md#worked-example-ovstorage-authz-toml)
  for the schema.
- **Macro**: `ovstorage_authz_plugin!(MyAuthz::default)` at module
  scope. Emits `ovstorage_authz_plugin_manifest_v1` and
  `ovstorage_authz_plugin_init_v1` cdylib symbols.

## Trait shape

```text
async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision>;
async fn filter_list_batch(&self, request: &AuthzRequest, addresses: &[Url])
    -> Result<Vec<AuthzDecision>>;
fn plugin_name(&self) -> &str;
```

- `AuthzRequest`: `{ principal, operation, address: Option<Url>,
  policy_epoch, audit_id }`.
- `AuthzDecision`: `{ effect: Allow|Deny, reason, explanation,
  decision_ttl }`.
- `Principal.id` is the stable host-supplied identifier — write rules
  against `id`, not `source`.
- `address` is the **caller-facing** URL (never a resolved physical
  target).

## Cancellation contract

The vtable signatures for `authorize` and `filter_list_batch` carry
a `cancel: *const CancelTokenFFI` slot, but the Rust trait methods
take no `CancellationToken`. The loader passes `std::ptr::null()`
today.

**Plugins SHOULD bound their own work with an internal deadline;
the host does not propagate cancellation across the cdylib FFI
today.** Wrap any blocking call in `tokio::time::timeout` with a
deadline shorter than the host's RPC timeout. Return
`Err(Error::new(Transient, ...))` on timeout — host retry kicks in.

## FFI input ownership

Every `*const T` input on a vtable method transfers ownership
host -> plugin at call time. Consume synchronously (`ptr::read` in
Rust) before returning. The macro emits correct thunks.

## Operations

21 stable names:

- Object I/O: `stat`, `read`, `write`, `delete`, `list`,
  `list_versions`, `watch_directory`, `create_directory`,
  `delete_directory`, `update_metadata`, `check_access`,
  `list_address_roots`.
- Introspection: `list_backend_kinds`.
- Connection mgmt: `add_connection`, `remove_connection`,
  `update_connection_credentials`, `list_connections`.
- Alias mgmt: `add_alias`, `remove_alias`, `list_aliases`.
- Visibility mgmt: `set_address_visibility`.

**`copy` and `rename` are not standalone ops.** Hosts decompose:
`copy` -> `read(src)` + `write(dst)`; `rename` -> `read(src)` +
`delete(src)` + `write(dst)`. `add_alias` keeps its own op + host
issues `read(to)`.

Use `operation_name(op)` / `operation_from_name(s)` for stable
string round-tripping.

## Policy epoch

- Host stamps `request.policy_epoch` on every call.
- Read it, optionally use it in your cache key or `decision_ttl`
  computation.
- Don't run the state machine yourself; that's host-owned.
- Freshness modes (`strict`, `grace_window`) live on the host; under
  `grace_window`, only `request_epoch + 1 == current_epoch` is
  honored, and only when the epoch isn't explicitly invalidated.

## ABI

- `OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION` (distinct from storage SPI's
  `OVSTORAGE_PLUGIN_ABI_VERSION`).
- Filename prefix is the kind disambiguator: `libovstorage_authz_*`.
- Manifest `name` must match the host's `[authz] plugin`
  configuration; mismatch fails startup with `NotConfigured`.
- `test_only: bool` on the manifest — production hosts refuse to
  load `test_only` plugins.

## Audit-safe explanation

`AuthzDecision.explanation` is **stable, audit-safe** — typically a
rule id. MUST NOT contain bearer tokens, signed URLs, credential
bytes, or unredacted physical URLs. It rides through tracing spans
and the gRPC error-details message on deny.

## Conformance checklist

1. Empty policy denies.
2. Allow / deny matching.
3. Wildcard principal + wildcard operation.
4. Longest-prefix precedence.
5. Same-prefix later-rule precedence.
6. `decision_ttl` round-trip into both effects.
7. `address = None` matches only `prefix = "*"` rules.
8. 32 concurrent `authorize` calls.
9. Clean `drop_plugin` with in-flight calls (5 s drain).
10. Internal deadlines bound plugin work.

Mirror `ovstorage-authz-toml`'s `tests/`.

## What lives elsewhere

- Storage SPI authoring is in [plugin-storage AGENTS](../plugin-storage/AGENTS.md)
  (different SPI, separate ABI version).
- Shared C ABI substrate is in
  [plugin-development AGENTS](../plugin-development/AGENTS.md).
- How operators configure your plugin and consume its decisions:
  [broker-operator README § Authz plugin selection](../broker-operator/README.md#authz-plugin-selection).
- REST gateway authz behavior (same SPI, same rules):
  [library-web README](../library-web/README.md).
