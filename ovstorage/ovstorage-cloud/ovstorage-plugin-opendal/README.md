# ovstorage-plugin-opendal

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-opendal.md`](../../docs/public/plugin-storage/plugin-opendal.md).

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
  buffered. Listings expose OpenDAL's pull-based `Lister` directly;
  `list_stream` retains one provider page and folds directory facts
  incrementally without collecting the prefix.
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
  - A signed loopback S3-compatible fixture covering paginated recursive
    `list_stream`, delimiter-free wire requests, cancellation before the next
    page, and fail-loud handling of provider-order regressions.
  - Cancellation surfacing as `ErrorCode::Cancelled`.
  - `WriteOptions.user_metadata` handling on both body-typed write
    paths: a driver that cannot store it refuses a non-empty caller
    map rather than dropping it, while a bare `WriteOptions.message`
    is still accepted and discarded. The capable arm is covered both as
    a decision test and against a real `s3` connection, which is
    constructible in-process because operator construction runs no
    reachability probe.
  - The `write_redirect` capability gate (`fs` returns `Unsupported`,
    not `InvalidArgument`) and the `write_redirect`
    `IfDestExists::Fail` rejection.
  - The `config_json` parser handling multibyte UTF-8 plus `\uXXXX`
    escapes.
- No test contacts a live remote service. The `fs` profile uses a `TempDir`,
  while credentialed S3-compatible and WebDAV wire behavior uses scripted
  loopback servers. Presigned writes are not exercised end to end.
  Per-driver conformance against a test-container suite is aspirational.
