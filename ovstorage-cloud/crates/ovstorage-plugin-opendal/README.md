# ovstorage-plugin-opendal

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-opendal.md`](../../../docs/public/plugin-storage/plugin-opendal.md).

Cdylib `Backend` plugin fronting Apache OpenDAL for long-tail
storage services (`fs`, `s3`, `webdav`). Loads through the C ABI
declared by `ovstorage-plugin`; sits behind the same `Factory` /
`Backend` SPI as the other first-party storage plugins.
Workspace-pinned to OpenDAL `0.50` with the `services-fs`,
`services-http`, `services-s3`, and `services-webdav` features.

## Internal architecture

- **`src/lib.rs`** holds the factory + backend + adapter logic. The
  plugin maps each SPI call to OpenDAL's `Operator` API. Whole-object
  reads return `ReadResult::Stream` from
  `Operator::reader(...).into_bytes_stream(..)`; range reads stay
  buffered.
- Per-driver allow-list lives in `DRIVER_SPECS`. The descriptor's
  `service` enum is sourced from those specs (so the variants stay
  in lock-step with the workspace-compiled OpenDAL features), and
  `instantiate` rejects services outside the allow-list with
  `Unsupported`.
- Capability bits are derived from the chosen OpenDAL service's
  per-driver allow-list at instantiate time, not from OpenDAL's
  runtime `Capability` struct directly.

## Test layout

- `src/*::tests` — unit tests covering:
  - Descriptor shape and the per-driver capability allow-list
    (`descriptor_service_enum_omits_disabled_services` is the test
    that pins the workspace-feature-vs-descriptor invariant).
  - A full `fs` round-trip (write, stat, range read, async streamed
    read, recursive + one-level list, delete, copy, rename).
  - Percent-encoded key round-tripping, recursive listings omitting
    `Subdirectory` entries.
  - Cancellation surfacing as `ErrorCode::Cancelled`.
  - `WriteOptions.user_metadata` plumbing through the buffered write
    path.
  - The `write_redirect` capability gate (`fs` returns `Unsupported`,
    not `InvalidArgument`) and the `write_redirect`
    `IfDestExists::Fail` rejection.
  - The `config_json` parser handling multibyte UTF-8 plus `\uXXXX`
    escapes.
- Streaming writes, presigned writes, and the non-`fs` drivers are
  not exercised by an in-process test; per-driver conformance against
  a test-container suite is aspirational.
