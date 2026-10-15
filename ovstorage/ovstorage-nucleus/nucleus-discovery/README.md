# nucleus-discovery (`nucleus-discovery`)

## Purpose

Wraps the Nucleus `omni/discovery` service surface for plugin-side consumers. Houses the codegen output for `Discovery.idl.ts` plus a small set of hand-authored helpers that the storage plugin uses during handshake to (a) build the discovery URL from a Nucleus host string, (b) describe its own supported transports, and (c) decode `TransportSettings` payloads into concrete `ws://…` / `wss://…` URLs.

The crate sits between [nucleus-codegen](../nucleus-codegen/README.md) (build-time IDL→Rust generator) and [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) (the host-facing storage plugin). The plugin's handshake calls this crate's `discovery_url(...)` first, opens a SOWS connection there, dispatches `DiscoverySearch::find` (generated trait) to learn where the auth and main `omni1` interfaces live, and then uses `url_from_transport(...)` to build the URLs for follow-up connections.

## Public surface

- `pub mod types` — re-exports the codegen-generated types from `Discovery.idl.ts`: `DiscoverInterfaceQuery`, `ServiceInterface`, `SupportedTransport`, `TransportSettings`, `SearchResult`.
- `pub mod generated` — the codegen `include!` output, defining the `DiscoveryRegistration` and `DiscoverySearch` traits over `Transport`. The plugin only consumes `DiscoverySearch::find`; `DiscoveryRegistration` is generated for completeness.
- `pub type DiscoveryClient = nucleus_transport::SowsTransport;` — the conventional transport choice for the discovery endpoint (always SOWS).
- `pub fn discovery_url(host: &str) -> String` — builds `{ws,wss}://{host}/omni/discovery` with the SSL-incompatibility heuristic described below.
- `pub fn supported_transports<T: Transport>() -> Vec<SupportedTransport>` — describes the calling crate's own transport implementations to pass into `make_query`. Reads `T::descriptors()` and converts each into the discovery wire shape.
- `pub fn make_query(origin, name, capabilities, deployment, supported_transport) -> DiscoverInterfaceQuery` — builds a `DiscoverInterfaceQuery` for `DiscoverySearch::find`. The `deployment` argument, when `Some`, is folded into the query's `meta` map under the key `"deployment"`. An empty `supported_transport` slice serializes as `None` (the optional IDL field is omitted) rather than `Some([])`, which matters if the discovery server distinguishes "no preference" from "client supports zero transports".
- `pub fn url_from_transport(transport: &TransportSettings) -> Option<String>` — decodes a `TransportSettings` returned from `DiscoverySearch::find` into a concrete URL.
- `pub use nucleus_transport::{self, Transport};`

## URL convention

Discovery URLs always have the path `/omni/discovery`. The host string is first parsed structurally (`parse_authority`) to extract host and optional port, distinguishing DNS names, IPv4 literals, bare IPv6 literals (e.g. `::1`), and bracketed IPv6 literals (e.g. `[::1]`, `[::1]:3333`). The output URL emits IPv6 hosts in bracketed form regardless of input form.

Cleartext `ws://` is selected only for hosts that are clearly local-network:

- `host == "localhost"` (with or without `:port`).
- `host` ending in `.local`.
- IPv4 literal that is loopback, RFC1918 private, link-local (169.254/16), unspecified (0.0.0.0), or broadcast.
- IPv6 literal that is loopback (`::1`), unspecified (`::`), unique-local (`fc00::/7`), or unicast link-local (`fe80::/10`).

All other hosts — including public IPv4 (e.g. `203.0.113.10`) and public IPv6 (e.g. `2001:db8::1`) — get `wss://`. This rules out cleartext for public-IP discovery URLs.

If `parse_authority` rejects the input (empty host, host with `@`/`/`/control chars, malformed brackets, port outside `1..=65535`, garbage), the call falls through to `wss://{host}/omni/discovery` using the raw input — secure-by-default, and the downstream connection will fail loudly when the URL is parsed by the WebSocket client.

## TransportSettings → URL decoding

`url_from_transport` reads the `params` JSON object for `host` (string, required), `port` (u64, required), and `path` (string, optional, defaults to `""`). It validates each field structurally:

- **host**: must be a syntactically valid DNS name, IPv4 literal, or IPv6 literal (bare or bracketed). Hosts containing `@`, `/`, `?`, `#`, `\`, whitespace, or control characters are rejected — this blocks userinfo-style injection (`expected.example@attacker.example`), path-grafting (`example.com/evil`), and CRLF smuggling. Bare IPv6 input is normalized to bracketed form on output (`::1` → `[::1]`).
- **port**: must be in `1..=65535`. Port `0` and ports >= 65536 are rejected.
- **path**: must be empty or start with `/`. Control characters (including CR/LF) are rejected to prevent header smuggling on the resulting WebSocket handshake.

`meta["ssl"]` is interpreted as `"true"` → `wss://`, anything else (including missing, `"false"`, or arbitrary garbage like `"yes"`) → `ws://`. This matches the existing wire convention; the `ssl` field is treated as a literal `"true"` test rather than a generic boolean parser.

Any validation failure causes `url_from_transport` to return `None` and emit a `warn`-level trace with the rejected payload, so operators can diagnose malformed discovery responses without crashing the caller.

Note that the `meta["ssl"]` flag here is independent of the local-cleartext rule in `discovery_url`: the discovery URL uses the rule because the Nucleus discovery server itself doesn't expose its TLS choice on the wire, whereas a `TransportSettings` returned from discovery encodes the answer explicitly.

## Generated-trait usage

`DiscoverySearch::find(query)` is the only generated method the plugin consumes. The plugin's `handshake::discover_auth_endpoints` and `handshake::find_interface` build a `DiscoverInterfaceQuery` from `make_query`, dispatch `find` over the SOWS discovery transport, and decode each returned `TransportSettings` via `url_from_transport`. `DiscoveryRegistration` is generated but not used; it is available for a Nucleus deployment that needs to publish its own service registration.

## Build-time codegen

`build.rs` invokes `nucleus_codegen::generate_from_file("../Discovery.idl.ts")` and writes the Rust output to `OUT_DIR/generated.rs`, which `pub mod generated` includes verbatim. See [nucleus-codegen](../nucleus-codegen/README.md) for the IDL subset accepted.

## Cross-links

- [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) — the storage plugin's `handshake::discover_auth_endpoints` / `handshake::find_interface` helpers consume this crate's `discovery_url`, `make_query`, and `url_from_transport`.
- [nucleus-transport](../nucleus-transport/README.md) — defines the `Transport` trait the generated `DiscoverySearch` impl dispatches over.
- [nucleus-codegen](../nucleus-codegen/README.md) — generates `mod generated`.

## Implementation gaps

- `DiscoveryRegistration` is generated but not consumed in the workspace. That is by design — the workspace is a client, not a registrant.
- The local-cleartext rule is hard-coded; operators who need a different policy must build the discovery URL themselves rather than calling `discovery_url`. That is the explicit shape of the helper.
- `transport.name` is not cross-checked against the caller's supported-transport list inside `url_from_transport`. The plugin handshake performs that check at the call site after dispatching `DiscoverySearch::find`; this crate is the URL-construction layer and stays narrow.
