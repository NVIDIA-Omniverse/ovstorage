# nucleus-transport (`nucleus-transport`)

## Purpose

The raw wire-protocol layer for talking to Nucleus over WebSockets. Defines the `Transport` trait that every higher-level Nucleus crate (auth, client, discovery) generics over, plus two concrete implementations — `SowsTransport` for the binary "Sub-Object Wire Stream" framing and `ConnLibTransport` for the JSON-with-optional-binary-tail framing. Nothing in this crate retries, pools, times out, or reconnects: it owns one WebSocket and multiplexes per-request subscriptions over it.

The crate sits below all the other `nucleus-*` crates. Generated traits like `Connection`, `Tokens`, `DiscoverySearch` dispatch their methods through `Transport::send`, then read frames via `Subscription::recv`. The host-side storage plugin's retry, redirect-following, and lifecycle policies live one layer up; see [ovstorage](../../../ovstorage-core/crates/ovstorage/README.md) for the `Library`-level transient-error retry contract.

## Public surface

- `pub mod connlib`, `pub mod error`, `pub mod sows`, `pub mod transport` (top-level modules; everything users need is re-exported below).
- `pub use connlib::ConnLibTransport;`
- `pub use error::TransportError;`
- `pub use sows::SowsTransport;`
- `pub use transport::{RawResponse, Subscription, Transport, TransportDescriptor};`

### `Transport` trait

```text
pub trait Transport: Send + Sync {
    fn descriptors() -> Vec<TransportDescriptor>
        where Self: Sized;                    // default: empty
    fn send(&self, interface: &str, method: &str,
            params: serde_json::Value,
            binary: Option<Vec<u8>>)
        -> impl Future<Output = Result<Subscription>> + Send;
}
```

`descriptors()` reports what discovery-layer settings the transport advertises. `SowsTransport` returns 4 descriptors (the `ssl × supports_path` matrix). `ConnLibTransport` returns 1 (`name = "connlib"`, no metadata).

`send` opens a new logical subscription on the underlying WebSocket. Both transports multiplex by request id; the returned `Subscription` is the per-id channel. There is no per-call timeout in `send` — the only timeout API is on the receiving end (`Subscription::recv_timeout`).

### `Subscription` lifecycle

`Subscription` is `Stream<Item = Result<RawResponse>>` plus convenience methods:

- `recv_raw() -> Result<RawResponse>` — wait for one frame.
- `recv::<T>() -> Result<(T, Option<Vec<u8>>)>` — wait for one frame and deserialize the JSON body into `T`. The optional binary tail (BS-marshalled blob) is returned as the second tuple element.
- `recv_timeout::<T>(duration) -> Result<(T, Option<Vec<u8>>)>` — same, with a `tokio::time::timeout` wrapper that returns `TransportError::Timeout` on expiry.
- `stop()` — sets the `finished` `AtomicBool`, closes the receiver, and sends a stop frame upstream. Idempotent — repeated calls are safe because `finished` short-circuits the upstream send.
- `Drop` — if the `finished` bit is still false, the drop emits a stop frame on the upstream channel via `try_send`. The stop channel is sized at 1024 entries; a `try_send` failure is logged at `warn` so that a flood of in-flight cancellations larger than the buffer is observable rather than silent. The wire-level stop is still best-effort by design.

### `RawResponse`

```text
pub struct RawResponse { pub json: Vec<u8>, pub blob: Option<Vec<u8>> }
```

Both transports surface the JSON-and-optional-blob shape; the blob carries the BS-marshalled binary tail when the wire frame produced one.

### `TransportError`

```text
pub enum TransportError {
    ConnectionFailed(String),
    ConnectionClosed,
    WebSocketError(tungstenite::Error),
    SerializationError(serde_json::Error),
    Timeout,
}
```

`tokio::time::timeout` failures map to `Timeout`. `tungstenite` and `serde_json` errors map through `#[from]` impls.

## SOWS framing

`SowsTransport::connect(url) -> Result<Self>` opens a WebSocket and starts a background task that demuxes incoming frames by request id.

Outbound frame format is binary:

```text
REQUEST_SEND=1 (1 byte) | id u32 LE (4) | "interface.method" (UTF-8 bytes) |
0x00 (1) | params_len u32 LE (4) | params_bytes (UTF-8 JSON) |
[optional binary tail]
```

Inbound frame types:

- `RESPONSE_ERROR = 0` — error envelope, surfaced as `Err(...)` on the receiver.
- `RESPONSE_SEND = 1` — data envelope, demuxed into the per-id `Subscription`. Truncated headers or truncated result bodies are converted to a terminal `ConnectionFailed("malformed RESPONSE_SEND: ...")` for the matching pending request rather than being silently skipped.
- `RESPONSE_DONE = 5` — terminal frame; closes the `Subscription`.
- Codes `2` / `3` / `4` — surfaced as terminal `ConnectionFailed("unhandled SOWS response type N")` against the matching pending id rather than dropped silently. They remain reserved on the wire and no Nucleus deployment in the workspace's reference set emits them.

`next_id()` is a u32 monotonic counter that skips 0 and asserts on `u32::MAX - 1` exhaustion. The plugin should never hit that bound during a single connection; if it does, the right fix is a connection bounce rather than wraparound.

`SowsTransport::descriptors()` advertises 4 entries — every combination of `ssl ∈ {true, false}` and `supports_path ∈ {true, false}` — all with `serializer = "json"`, `marshaller = "bs"`.

## ConnLib framing

`ConnLibTransport::connect(url) -> Result<Self>` opens a WebSocket and runs the same demux pattern.

Outbound frame format is JSON-with-optional-binary-tail:

```text
{"command":"<interface>.<method>","id":<u64>, ...params}
```

… optionally followed by a `\0` separator and a binary blob in the same WebSocket message. Per-id u64 monotonic counter; `fin: true` or `stopped: true` flags terminate a subscription.

`ConnLibTransport::descriptors()` advertises 1 entry: `name = "connlib"`, no metadata. Discovery looks the transport up by exactly that name.

## Multiplexing model

Each transport owns one WebSocket and three background tasks: a `read_loop` (demux of inbound frames into per-id `Subscription` channels), a `send_loop` (drains the outbound message queue into the WebSocket sink), and a `stop_loop` (consumes `Subscription` cancellations and emits the wire stop frames). The three tasks share a `tokio_util::sync::CancellationToken` and are tracked as `JoinHandle`s on the transport struct; if any half observes a wire-side failure or a peer close, it cancels the token and aborts the others. Dropping the `Transport` cancels the token and aborts each handle so spawned tasks are not leaked across reconnects.

Failure propagation is symmetric. The `read_loop` calls a `notify_pending_error` helper that drains the pending map and delivers a terminal error to every active subscription on connection close, peer error, or token cancellation. The `send_loop` runs the same drain when the outbound sink fails, with a `"send half failed: ..."` `ConnectionFailed` so logs distinguish the two failure sides — pending requests cannot strand if the write half goes down before the read half observes the close.

Frame ordering per-id is preserved end-to-end because the demux task is the only writer into each per-id channel. Per-`Subscription` channel capacity is 16. The demux task uses `try_send` rather than awaiting the bounded channel: if a slow consumer keeps a subscription alive without polling and that channel fills, the demux removes the pending entry and delivers a terminal `ConnectionFailed("subscription overflow")` to the slow subscriber instead of stalling the entire multiplexed connection on its behalf.

## What does NOT live here

There is **no** crate-level retry, no connection pool, and no per-call timeout. The only timeout API is `Subscription::recv_timeout` on individual `recv` calls. `Transport` has no retry hook. This matches the project's pinned policy: retry of transient errors lives at `ovstorage::Library`, not at the transport layer. See [ovstorage](../../../ovstorage-core/crates/ovstorage/README.md) "Retry policy" for the canonical retry surface.

`SowsTransport::connect` and `ConnLibTransport::connect` each open a single WebSocket; there is no auto-reconnect. The host-side caller (plugin-nucleus) explicitly owns reconnection and any associated backoff.

## Cross-links

- [nucleus-codegen](../nucleus-codegen/README.md) — emits the trait dispatch that calls `Transport::send`.
- [nucleus-auth](../nucleus-auth/README.md) / [nucleus-client](../nucleus-client/README.md) / [nucleus-discovery](../nucleus-discovery/README.md) — the three crates whose generated traits use this layer.
- [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) — host-side consumer; owns the connect / reconnect / retry policy.
- [ovstorage](../../../ovstorage-core/crates/ovstorage/README.md) — `Library`-level transient-error retry, the project's canonical retry surface.

## Logging and credentials

The auth flow that runs over these transports is concrete: the `Tokens.auth_with_api_token` and `Credentials.auth` methods carry literal API tokens and username/password payloads as `params`, and the corresponding response envelopes carry `access_token` / `refresh_token` strings. To prevent `trace`-level capture from persisting credentials into logs, the request and response logging sites in both `SowsTransport` and `ConnLibTransport` emit only structured metadata: `conn_id`, `id`, `interface`, `method`, `params_len`, `json_len`, `blob_len`, `fin`, `stopped`, `code`. JSON bodies are never formatted into `trace` events. If a developer needs payload-level capture for local debugging, decoding from a packet capture (or instrumenting a single test transport) is the supported path.

## Implementation gaps

- The SOWS `last` flag carried by `RESPONSE_SEND` is parsed-and-discarded. Termination is recognised only on `RESPONSE_DONE`. Whether the SOWS wire contract allows `last = 1` to terminate without a following `RESPONSE_DONE` is an open spec question; the in-tree handshake code consistently waits for additional frames after `last`-bearing payloads, which suggests the current behaviour matches reality.
- The per-`Subscription` channel capacity is hard-coded at 16; backpressure tuning is not exposed. The demux sheds slow subscribers with a terminal overflow error rather than stalling the connection, so this is a tuning question rather than a correctness one.
- Drop-triggered connection stop is best-effort under bursty load: the bounded stop channel logs when it cannot enqueue the stop request, but it can still lose that signal. A full fix would move the stop path to an unbounded or otherwise guaranteed channel shape across the generated clients.
- No connection pool. Every plugin connection opens its own WebSocket. Nucleus deployments tolerate many concurrent connections per principal and the per-connection state is small.
