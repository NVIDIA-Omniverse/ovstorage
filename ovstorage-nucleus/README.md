# ovstorage-nucleus

Omniverse Nucleus support for `ovstorage`: the storage plugin plus the
WebSocket transports (SOWS for short-lived discovery / auth, ConnLib
for the long-lived `Connection` socket), codegen, auth, discovery,
and client crates the plugin sits on top of. The plugin loads as a
cdylib through the C ABI declared by
[`ovstorage-plugin`](../ovstorage-core/crates/ovstorage-plugin/README.md);
the support crates exist because Nucleus's protocols are unique
enough that the plugin needs first-class Rust bindings, not a generic
SDK.

See the [repo-root README](../README.md) for the cross-workspace layout
and dependency graph.

## Crates

- [`ovstorage-plugin-nucleus`](crates/ovstorage-plugin-nucleus/README.md) — the plugin itself. Implements `Backend` (the `shim::Backend` SPI; conceptually `StorageBackend`) over Nucleus's `omniverse://` URLs.
- [`nucleus-client`](crates/nucleus-client/README.md) — generated `omni1` client over the `nucleus-transport::Transport` trait, plus the `LftClient` for the LFT (Large File Transfer) side channel. Transport-level retry, version-handshake gating, and `ServerFeatures` consumption are not wired in this crate today; the per-crate README describes the gap.
- [`nucleus-transport`](crates/nucleus-transport/README.md) — WebSocket transport implementations: SOWS framing for short-lived discovery / auth sockets, ConnLib framing for the long-lived storage `Connection` socket. TLS-or-cleartext via `tokio-tungstenite`.
- [`nucleus-discovery`](crates/nucleus-discovery/README.md) — service discovery over the Nucleus discovery protocol; `find_interface`, IP-literal handling, per-interface URL minting.
- [`nucleus-auth`](crates/nucleus-auth/README.md) — auth handshake + interactive login surface. Generated trait shapes for credentials / login / refresh.
- [`nucleus-codegen`](crates/nucleus-codegen/README.md) — IDL parser + Rust trait/struct emission used to generate the client crates.
