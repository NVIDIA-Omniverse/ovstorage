# ovstorage-services-client

Omniverse Storage Service support for `ovstorage`: a cdylib
backend plugin that speaks gRPC + OIDC, plus the tonic-generated proto
crate it compiles against.

> Canonical user-facing reference lives in
> [`docs/public/plugin-storage/plugin-services-client.md`](../docs/public/plugin-storage/plugin-services-client.md).

## Crates

- [`ovstorage-plugin-services-client`](ovstorage-plugin-services-client/README.md)
  — the plugin (cdylib).
- [`ovstorage-services-protos`](ovstorage-services-protos/README.md)
  — tonic-generated stubs compiled from the canonical contracts at
  `ovstorage-services/apis/`.

## Build outputs

`cargo build --release` inside this workspace produces
`libovstorage_plugin_services_client.{so,dylib,dll}`. Drop the file
into the host's plugin directory (`OVSTORAGE_PLUGIN_DIR` or
`<exe>/plugins/`) or register programmatically — see the user
reference in `docs/public/plugin-storage/` for the current
`ovstorage::host::build_stack(...)` flow.
