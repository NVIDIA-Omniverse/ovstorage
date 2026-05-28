# ovstorage-broker-protocol

> Wire-contract crate for the library <-> broker gRPC protocol. The
> object-IO wire shape (RPCs, redirect envelopes, streaming framing,
> error mapping) appears in the public docs as part of the
> [broker storage plugin reference](../../../docs/public/plugin-storage/plugin-broker.md)
> and the [broker-operator persona](../../../docs/public/broker-operator/README.md).

This crate ships the `.proto` IDL plus the `tonic-build`-generated
Rust stubs. Both sides of the brokered topology
([`ovstorage-broker`](../ovstorage-broker/README.md) and
[`ovstorage-plugin-broker`](../ovstorage-plugin-broker/README.md))
link this crate, and nothing else in the workspace does.

**Do not modify the generated code.** The `OUT_DIR` Rust output is
regenerated from `proto/` on every build via `build.rs`; any manual
edit to a generated `*.pb.rs` will be overwritten.

## Module map

- `proto/ovstorage/v2/broker.proto` — the v2 wire contract. The
  20 RPCs (`ListAddressRoots`, `WatchAddressRoots`, `Stat`,
  `Read`, `Write`, `WriteRedirect`, `ContinueWrite`, `Delete`,
  `List`, `ListVersions`, `GetLatestVersion`, `WatchDirectory`,
  `CreateDirectory`, `DeleteDirectory`, `Copy`, `Rename`,
  `UpdateMetadata`, `CheckAccess`, `Auth`, `RegisterCredential`).
- `proto/grpc/health/v1/health.proto` — vendored upstream
  `grpc.health.v1` service.
- `build.rs` — `tonic-build` invocation with vendored `protoc`
  binary; pinned `compile_well_known_types(false)` so an upstream
  default flip can't silently pull in `prost-types`.
- `src/lib.rs` — re-exports of generated `ovstorage.v2` and
  `grpc.health.v1` stubs; conversion helpers between proto
  messages and core domain types
  (`address_root_from_proto`,
  `address_roots_change_from_proto`, `object_address_to_proto`,
  `object_info_from_proto`, `stat_options_to_proto`,
  `read_options_to_proto`, `error_to_status`,
  `error_to_status_with_context`, `status_to_error`, etc.).
  `PROTOCOL_V2` constant.
  `BrokerClientTransport` async trait (the high-level
  method-level surface the broker-client plugin and the broker
  daemon both implement against, sitting on top of the generated
  tonic stubs); `BrokerClientWatchDirectoryStream` iterator alias.

## Test layout

- `src/lib.rs::tests` — round-trip / round-table conversion tests
  (`object_identity_round_trips_empty_as_none`,
  `checksum_algorithms_round_trip_as_strings`,
  `error_status_preserves_core_code_class`,
  `error_status_preserves_core_code_details`,
  `read_redirect_round_trips_non_default_response_parsing`,
  `write_redirect_round_trips_non_default_result_capture`,
  `error_context_identity_round_trips`,
  `error_context_auth_round_trips`,
  `error_code_to_status_code_table`,
  `unknown_address_visibility_falls_closed_to_suppressed`,
  `unknown_change_kind_is_invalid_argument`,
  `body_bytes_chunks_at_local_file_chunk_size`,
  `body_bytes_empty_yields_no_chunks`,
  `body_bytes_at_chunk_boundary_yields_one_chunk`).

## Schema evolution discipline

Additive-only within a major version: new fields take new tag
numbers, never reuse retired ones; new `oneof` arms append; new
RPCs are additions. Field renumbering or removal is a 2.0-class
change. Deleted fields are marked `reserved <tag>;` and never
reissued.

A wire-shape golden CI gate (checked-in serialized fixture) and a
`buf breaking` CI gate are tracked work items, not in CI today.
Until they ship, renumbering an existing field is a code-review
concern, not a CI gate.

For the major-version bump procedure: copy `ovstorage/vN/*.proto`
to `ovstorage/v(N+1)/*.proto`, register the new service in the
broker, run both side-by-side for one release before retiring the
prior major.

### Version history

- **v2.0 — 2026-05-20**: clean-slate tag rebase under the if-match
  redesign. The `IfDestExists` precondition replaces the old
  `if_match` + `no_overwrite` shape on `WriteOptions` /
  `CopyOptions` / `RenameOptions`, and `ObjectIdentity` collapses
  to a flat `etag` on `ObjectInfo`. Tag numbers reset to start at
  1 on every reshaped message; `mtime_unix_millis` standardises
  on `int64` across the wire so pre-epoch values (file plugin
  clock skew) survive a round trip. `ObjectInfo.version` becomes
  `optional` to match the SPI's `Option<String>` semantics.

## Conformance test gaps

Forward-compat tests (`proto_unknown_field_round_trip`,
`proto_unknown_oneof_arm`, `proto_renumbered_field_caught`),
mid-stream / out-of-order wire framing tests, and the
WatchDirectory fan-out / Lapsed conformance live with the broker
daemon, not this crate.
