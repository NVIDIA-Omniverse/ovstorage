# ovstorage-plugin-nucleus

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-nucleus.md`](../../docs/public/plugin-storage/plugin-nucleus.md).

Cdylib ABI-v2 backend-`Layer` plugin for NVIDIA Omniverse Nucleus
(`omniverse://server[:port]/path`). Loads through the C ABI declared
by `ovstorage-plugin`; sits on top of the five `nucleus-*` support
crates in this workspace plus the `omni1` IDL compiled by
`nucleus-codegen`.

## Internal architecture

- **`src/lib.rs`** — module wiring, `ovstorage_layer_plugin!` macro
  invocation, public re-exports.
- **`src/config.rs`** — descriptor config / credential schemas
  (`nucleus_config_schema()`).
- **`src/address.rs`** — `omniverse://` URL parsing and
  `PathAtVersion` selector handling for the `?<branch>&<checkpoint>`
  query form.
- **`src/auth.rs`** — credential-shape classification and
  auth-method orchestration over `nucleus-auth`.
- **`src/handshake.rs`** — SOWS discovery, the four auth flows
  (`establish_api_token` / `establish_username_password` /
  `establish_interactive_auth` / `try_warm_continue`), and
  ConnLib `authorize_token`.
- **`src/layer.rs` / `src/driver.rs`** — the ABI-v2 surface
  (RFC-0066): `NucleusLayerFactory` + `NucleusLayer` own
  routing and delegate connection lifecycle to a generic
  `ConnectionSet<NucleusDriver>`; the driver maps the session
  handshake onto obtain / verify / on_authenticated / refresh /
  interactive.
- **`src/backend/`** — the object/data operations: `spi.rs`
  carries `NucleusBackend`'s inherent op methods that map each
  call onto `NucleusOps` and apply the enforcement helpers;
  `session.rs` holds `NucleusShared` (the live per-connection
  session cell, refresh-lock, cred-epoch) and the handshake
  install/refresh machinery.
- **`src/convert.rs`** — SPI option translation, including the
  `require_etag_only_if_match` helper that refuses any
  unenforceable `if_match` precondition.
- **`src/ops.rs`** — `NucleusOps` trait (async façade over the
  omni1 surface) and `RuntimeOps<T: Transport>` production adapter.
- **`src/trace.rs`** — tracing field setup.
- **`src/test_support.rs`** — `MockTransport` fixtures for unit
  and SPI tests.

## Operational notes

- **Where a reverse proxy fronts Nucleus, the access token reaches its access
  logs by design.** Some deployments put a reverse proxy in front of Nucleus
  that rejects requests carrying no valid token, added to protect deployments
  reachable from the public web against DDoS. Such a proxy has to rule on the
  HTTP request that opens the websocket, before any frame exists, so the
  ConnLib connect URL carries the access token as a query parameter where the
  edge can read it. A proxy configured to log request URLs therefore records
  that token. This follows from putting the credential where the edge can see
  it; it is not something the plugin can suppress from its side, and the
  recorded token stops being useful when it expires. The transport redacts the
  parameter from the events it emits itself, so ovstorage's own logs do not
  carry it at their usual levels. The websocket library still renders the whole
  HTTP upgrade request, request target included, through the `log` crate at
  TRACE inside the plugin. The plugin's logging bridge suppresses those TRACE
  records at the plugin boundary for every host, so the rendered request is not
  handed to a host log callback. In ovstorage's own logging setup, the noisy
  crate filter honors an operator directive that explicitly names a silenced
  crate root, such as `OVSTORAGE_LOG=tungstenite=trace`, while its crate-level
  warning directives still override catch-alls such as `OVSTORAGE_LOG=trace`.
  Operators should scope retention and access on the proxy's access logs — and
  on any packet capture of the connection — to match how they treat short-lived
  credentials.

## Test layout

- `src/*::tests` — unit tests per module (config parsing, URL
  parsing, ACL mapping, status translation, etc.).
- `tests/precondition.rs` — integration tests pinning the
  hardening refusals: compound `if_match`, inverted range,
  `write_redirect` size_hint requirement, `recursive list` refusal,
  `delete` / `copy` / `rename` `if_match` refusal, `list`
  page-token refusal.
- `tests/<other>.rs` — see file listing.
