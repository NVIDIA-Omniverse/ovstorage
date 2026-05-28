---
name: ovstorage-contributor-author-authz-plugin
description: Use when adding or reviewing an authz plugin for ovstorage-broker or ovstorage-rest - covers the AuthzPlugin trait, the 21 operations, the policy-epoch model, and the cdylib cancellation contract.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, plugin, authz]
tools: [Read, Bash]
compatibility: Requires an ovstorage checkout, Rust toolchain, and authz plugin ABI docs. No external credentials are required.
---

# Author an Authz Plugin

## Goal

Implement a cdylib authz plugin that advertises a stable name,
authorizes the 21 operations correctly, bounds its own work with
internal deadlines (the host does not propagate cancellation across
the cdylib FFI today), and returns audit-safe `explanation` handles.

## Recipe

1. Read
   [`docs/public/plugin-authz/README.md`](../../docs/public/plugin-authz/README.md)
   for the SPI shape, the stable list of 21 operation names, the
   `copy` / `rename` decomposition rule, the policy-epoch model,
   and the audit-safe diagnostics.
2. Start from the in-tree reference plugin:
   `ovstorage-remote/crates/ovstorage-authz-toml/` is the only
   first-party authz plugin and exercises every line of the SPI.
3. Implement the trait:
   ```rust
   #[async_trait::async_trait]
   impl AuthzPlugin for MyAuthz {
       fn plugin_name(&self) -> &str { "my-authz" }

       async fn authorize(&self, request: &AuthzRequest)
           -> Result<AuthzDecision> { ... }

       // Default `filter_list_batch` calls `authorize` per
       // address with `request.operation` (the Fix A behavior).
       // Override for batch-aware policy backends.
   }
   ```
4. Wire the macro at module scope:
   ```rust
   ovstorage_authz_plugin!(MyAuthz::default);
   ```
   Emits `ovstorage_authz_plugin_manifest_v1` +
   `ovstorage_authz_plugin_init_v1` cdylib symbols. Pulls `name` /
   `version` from `CARGO_PKG_NAME` / `CARGO_PKG_VERSION`. The
   plugin's manifest `name` MUST match the host's
   `[authz] plugin` config; mismatch fails startup with
   `NotConfigured`.
5. Validate the manifest filename. Authz cdylibs use
   `libovstorage_authz_*` prefix and the
   `ovstorage_authz_plugin_*` symbol prefix; this is the kind
   disambiguator between storage and authz cdylibs.
6. **Bound your work with internal deadlines.** The vtable's
   `cancel: *const CancelTokenFFI` slot is `std::ptr::null()`
   today for `authorize` and `filter_list_batch` (the Rust trait
   methods take no `CancellationToken`). A wedged plugin pins
   the host's outer RPC timeout rather than honoring host
   cancellation. Wrap any blocking call in
   `tokio::time::timeout` with a deadline shorter than the
   host's RPC timeout; return `Err(Error::new(Transient, ...))`
   on timeout so the host's `with_route_retry` kicks in. This
   follows the documented "plugins SHOULD bound their own work
   with an internal deadline; the host does not propagate
   cancellation across the cdylib FFI today" contract.
7. Match against `Principal.id`, not `Principal.source`. `id` is
   the stable host-supplied identifier; `source` is a diagnostic
   value indicating which listener authn mode minted the
   principal.
8. Don't try to authorize `copy` or `rename` directly. They
   decompose at the host into primitive `Read` / `Write` /
   `Delete` checks before reaching the plugin. `add_alias` keeps
   its own op but the host also issues a `Read` check on the
   alias's `to` target.
9. Set `AuthzDecision.explanation` to an audit-safe handle
   (typically a rule id). It rides through tracing spans and the
   gRPC error-details message on deny. **Never** include bearer
   tokens, signed URLs, credential bytes, or unredacted physical
   URLs in `explanation` or `reason`.
10. Decide `decision_ttl` policy. Returning `None` forces per-call
    evaluation. Returning `Some(d)` lets the host cache the
    decision; the host clamps `d` against route + host policy
    limits.
11. Run `cargo xtask validate-skills` (for the skill itself) and
    `make verify` (for the crate). Add conformance tests
    mirroring `ovstorage-authz-toml/tests/`:
    - empty policy denies;
    - allow / deny matching, wildcard principal, wildcard
      operation;
    - longest-prefix precedence + same-prefix later-rule
      precedence;
    - `address = None` matches only `prefix = "*"` rules;
    - 32 concurrent `authorize` calls don't corrupt state;
    - clean drop with in-flight calls (5-second drain).

## Review checks

- Manifest `name` and `version` come from Cargo package metadata.
- ABI version advertises `OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION`
  (distinct from the storage SPI's
  `OVSTORAGE_PLUGIN_ABI_VERSION`).
- Calls bound their own work with internal deadlines (see
  cancellation contract above).
- `explanation` and `reason` are redaction-clean.
- The plugin denies by default; missing rules don't accidentally
  allow.
- The plugin distinguishes `Err(...)` (host fails closed) from
  `Ok(Deny(...))` (host returns `PermissionDenied` with the
  plugin's reason). Use `Err` for genuine plugin failures, not
  for routine deny decisions.
- `filter_list_batch` either uses the default (passes
  `request.operation` per address) or overrides correctly without
  silently changing the operation.

## What's not in scope

- Sandboxing. Authz plugins run in-process at full host trust.
- Multi-plugin authz. The broker supports exactly one authz
  plugin; chained evaluation across multiple engines is a v2
  concern.
- C / C++ authz plugins. The macro is the authoring target and
  is Rust by convention.

## References

- [`docs/public/plugin-authz/README.md`](../../docs/public/plugin-authz/README.md)
  — full SPI surface, type vocabulary, conformance checklist.
- `ovstorage-remote/crates/ovstorage-authz-toml/` — reference
  plugin sources.
- [`docs/public/plugin-development/README.md`](../../docs/public/plugin-development/README.md)
  — shared C ABI substrate (manifest, loader, ABI versioning).
- [`ovstorage-contributor-author-storage-plugin`](../ovstorage-contributor-author-storage-plugin/SKILL.md)
  — the storage-SPI counterpart (different ABI, separate
  version).
- [`ovstorage-contributor-run-broker-locally`](../ovstorage-contributor-run-broker-locally/SKILL.md)
  — running the broker locally with your plugin loaded.
