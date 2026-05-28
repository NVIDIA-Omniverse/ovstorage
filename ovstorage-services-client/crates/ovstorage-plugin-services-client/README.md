# ovstorage-plugin-services-client

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-services-client.md`](../../../docs/public/plugin-storage/plugin-services-client.md).

Cdylib `Backend` plugin that speaks gRPC + OIDC to the Omniverse Storage
Service. Loads through the C ABI declared by
`ovstorage-plugin`; behaves as a sibling to `ovstorage-plugin-file` and
`ovstorage-plugin-http`. The canonical wire contracts live in
[`ovstorage-services/apis/`](../../../ovstorage-services/apis/) and are
treated as vendored source of truth — do not edit in place.

## Internal architecture

- **Transport**: `OmniverseStorageTransport` owns the
  `tonic::transport::Channel`, the bearer-token interceptor, and the
  discovery state. The channel is shared across all per-service
  client stubs (`FileObjectServiceClient`,
  `FileFolderServiceClient`, …).
- **Factory**: `OmniverseStorageFactory` is the SPI entry point —
  emits the descriptor, drives instantiate / authenticate /
  update_credentials, and retains a slot table keyed by
  `ConnectionId` so refreshes find their target backend.
- **Backend**: `OmniverseStorageBackend` is the per-connection
  object-I/O dispatcher. SPI methods (stat / read / write / list / …)
  translate to one or more gRPC RPCs per the mapping table in the
  public doc.
- **Multipart**: the multipart upload state machine encodes part
  metadata into the redirect's continuation token. The encoding is
  unit-tested in `src/multipart.rs::tests`.
- **Watch translation**: server events
  (`omni.storage.{,dir_}{created,deleted}`) translate to
  `WatchEvent::{Created,Modified,Deleted}` / `MetadataChanged`. The
  filter and translation rules are unit-tested in
  `src/backend.rs::tests`.

## Test layout

- `src/*::tests` — unit tests for config parsing, the auth
  interceptor, ACL parsing, error mapping (gRPC status → typed
  `ErrorCode`), multipart continuation encoding, and watch-event
  translation.
- `tests/end_to_end.rs` — integration tests over an in-process
  duplex `tonic` channel: stat round-trip; read (streamed chunks,
  redirect dispatch, empty body); `write_redirect` (single-part and
  multipart abort); `check_access` over each ACL path.
- `tests/streaming_invariant.rs` — drives the bidi `Write` seam at
  16 × 4 MiB and asserts the host-side streaming invariants
  (`ovstorage_plugin_test::streaming::assert_streaming_invariants`).
  Mirrors the conformance check applied to every first-party plugin.
