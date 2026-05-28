# ovstorage-plugin-nucleus

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-nucleus.md`](../../../docs/public/plugin-storage/plugin-nucleus.md).

Cdylib `Backend` plugin for NVIDIA Omniverse Nucleus
(`omniverse://server[:port]/path`). Loads through the C ABI declared
by `ovstorage-plugin`; sits on top of the five `nucleus-*` support
crates in this workspace plus the `omni1` IDL compiled by
`nucleus-codegen`.

## Internal architecture

- **`src/lib.rs`** — module wiring, `ovstorage_plugin!` macro
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
- **`src/backend/`** — SPI dispatcher: `factory.rs` carries
  `NucleusBackendFactory`, `spi.rs` carries the `Backend` trait
  impl that maps each SPI call onto `NucleusOps` and applies the
  enforcement helpers; `mod.rs` holds `NucleusShared` (per-root
  state, refresh-lock, cred-epoch).
- **`src/convert.rs`** — SPI option translation, including the
  `require_etag_only_if_match` helper that refuses any
  unenforceable `if_match` precondition.
- **`src/ops.rs`** — `NucleusOps` trait (async façade over the
  omni1 surface) and `RuntimeOps<T: Transport>` production adapter.
- **`src/trace.rs`** — tracing field setup.
- **`src/test_support.rs`** — `MockTransport` fixtures for unit
  and SPI tests.

## Test layout

- `src/*::tests` — unit tests per module (config parsing, URL
  parsing, ACL mapping, status translation, etc.).
- `tests/precondition.rs` — integration tests pinning the
  hardening refusals: compound `if_match`, inverted range,
  `write_redirect` size_hint requirement, `recursive list` refusal,
  `delete` / `copy` / `rename` `if_match` refusal, `list`
  page-token refusal.
- `tests/<other>.rs` — see file listing.
