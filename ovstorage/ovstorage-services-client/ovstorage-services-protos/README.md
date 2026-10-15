# ovstorage-services-protos

Tonic-generated bindings for the Omniverse Storage Service
contracts. The crate has no user-facing API: it exists so the plugin
crate
([`ovstorage-plugin-services-client`](../ovstorage-plugin-services-client/README.md))
can `use ovstorage_services_protos::nvidia::omniverse::storage::…`.

## Where the protos come from

`build.rs` compiles from **two** in-repo canonical roots:

- `ovstorage-services/apis/storage-api/proto/` — v1alpha protos for
  capabilities, fileobject, filefolder, metadata, versioning.
- `ovstorage-services/apis/notifications-api/consumer/protos/` —
  v1beta consumer proto (`event_consumer.proto`) for
  `watch_directory`.

The `ovstorage-services/` subtree is **vendored source of truth**.
Do not edit in place; refreshes must come from the upstream service/API source
of truth and should be reviewed as a separate vendor-sync change.

v1beta storage protos exist canonically alongside v1alpha but are not
compiled today — the plugin targets v1alpha. Add the v1beta service
entries to `build.rs` when the plugin gains v1beta support.

## Why two `tonic::include_proto!` subtrees

Each service compiles into its own `OUT_DIR` subdirectory so prost
emits separate `google.protobuf` stanzas per service. Without that
split, `Timestamp` / `Value` collide across services. The
`src/lib.rs` `mod google { mod protobuf { include_proto!(...) ; ... } }`
shape is one-protobuf-stanza-per-service by design.
