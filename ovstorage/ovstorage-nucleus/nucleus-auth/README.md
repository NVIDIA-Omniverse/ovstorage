# nucleus-auth (`nucleus-auth`)

## Purpose

Wraps the Nucleus *OmniAuth* surface — the auth-service traits Nucleus speaks over SOWS — for plugin-side consumers. Houses the codegen output for the `OmniAuth.idl.ts` IDL plus a small hand-authored helper module for the URL+nonce interactive auth flow that Nucleus uses in place of OAuth.

The crate sits between [nucleus-codegen](../nucleus-codegen/README.md) (build-time IDL→Rust generator) and [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) (the host-facing storage plugin that consumes these traits). The plugin's authentication state machine drives this crate's `flow::start_interactive` helper to obtain the browser URL and the still-open `Tokens.subscribe` subscription that the plugin polls for the user's terminal `Auth` envelope.

## Public surface

- `pub mod types` — re-exports the codegen-generated types from `OmniAuth.idl.ts`: `Auth`, `AuthStatus`, `CredentialSettings`, `ProfileSettings`, `SSOSettings`, etc.
- `pub mod generated` — the codegen `include!` output, defining the `Credentials`, `Profiles`, `SSO`, `Tokens`, `UserStore`, `DeviceFlow` traits over `Transport`. Each trait has one impl per `Transport` implementor (so `SowsTransport` implements all of them).
- `pub mod flow` — hand-authored helpers for the URL+nonce interactive flow:
  - `pub struct InteractiveHandshakeStart { auth_url, nonce, expires_at, subscription }` — the result of the URL+nonce leg; the `subscription` field is the still-open `Tokens.subscribe` SOWS subscription that the caller polls for the terminal `Auth` envelope.
  - `pub const DEFAULT_EXPIRES_IN: Duration = Duration::from_secs(300)` — assumed nonce TTL. SOWS does not advertise a TTL on the wire, so this constant captures the Nucleus reference client's observed value.
  - `pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5)` — informational; the polling cadence is enforced by the caller, not this helper.
  - `pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(30)` — per-await upper bound applied to each pre-browser leg (`get_settings`, `subscribe`, first-frame `recv`) when `start_interactive` is used. Override with `start_interactive_with_timeout`.
  - `pub async fn start_interactive<C: Transport, T: Transport>(credentials: &C, tokens: &T, return_to: &str) -> Result<InteractiveHandshakeStart>` — calls `Credentials::get_settings()` to learn the configured `login_url`, then `Tokens::subscribe()`, then waits for the first frame (must be `AuthStatus::Subscribed` carrying a non-empty `nonce`), and builds `login_url?nonce=...&return_to=...`. Each pre-browser await is bounded by `DEFAULT_START_TIMEOUT`.
  - `pub async fn start_interactive_with_timeout<C: Transport, T: Transport>(credentials: &C, tokens: &T, return_to: &str, timeout: Option<Duration>) -> Result<InteractiveHandshakeStart>` — same as `start_interactive` but with a configurable per-await timeout. Pass `None` to disable bounds.
- `pub type AuthClient = nucleus_transport::SowsTransport;` — the conventional transport choice for the auth endpoint (OmniAuth is served over SOWS, never ConnLib).
- `pub use flow::{start_interactive, start_interactive_with_timeout, InteractiveHandshakeStart, DEFAULT_EXPIRES_IN, DEFAULT_POLL_INTERVAL, DEFAULT_START_TIMEOUT};`
- `pub use nucleus_transport::{self, Transport};`

## URL+nonce flow vs OAuth

Nucleus does **not** speak OAuth. The auth flow is:

1. Client calls `Credentials.get_settings()` over SOWS → `CredentialSettings { login_url, ... }`.
2. Client calls `Tokens.subscribe()` over the same SOWS endpoint. The first server frame is `Auth { status: Subscribed, nonce: Some(_) }`.
3. Client opens `{login_url}?nonce={nonce}&return_to={return_to}` in a browser.
4. User signs in. The Nucleus auth-service publishes the resulting `Auth { access_token, refresh_token, ... }` on the *same* SOWS subscription as a subsequent frame.
5. Client's polling loop awaits `subscription.recv::<Auth>()` until it returns a terminal envelope (or transitions through more `Pending` frames).

`start_interactive` runs steps 1–3. The caller drives step 5 with whatever cancel/timeout policy fits. The plugin-nucleus production state machine lives in `ovstorage-plugin-nucleus::handshake::establish_interactive_auth`.

## Generated traits not wired by the plugin

`Profiles`, `SSO`, `DeviceFlow`, and `UserStore` are generated and available to direct consumers of this crate (a binary built against `nucleus-auth` can use them). ovstorage-plugin-nucleus does *not* call any of them. This crate's surface is complete; the plugin-side wiring is the gap.

## URL encoding

`flow::build_auth_url` parses `login_url` with the `url` crate, rejects schemes other than `http`/`https` (a malicious or misconfigured Nucleus server cannot hand the user's browser a `javascript:`, `file:`, or `data:` URL), and appends `nonce` and `return_to` via `query_pairs_mut()`. Existing query strings and fragments are preserved.

## Build-time codegen

`build.rs` invokes `nucleus_codegen::generate_from_file("../OmniAuth.idl.ts")` and writes the Rust output to `OUT_DIR/generated.rs`, which `pub mod generated` includes verbatim. Drift between the IDL and this crate's `types` module surfaces at build time. See [nucleus-codegen](../nucleus-codegen/README.md) for the IDL subset accepted and the deprecated-method filter.

## Cross-links

- [plugin-nucleus](../ovstorage-plugin-nucleus/README.md) — the storage plugin that consumes this crate's surface; its Authentication section's `?nonce=...&return_to=...` URL shape is authoritatively defined in `flow.rs`.
- [nucleus-transport](../nucleus-transport/README.md) — defines the `Transport` trait the generated traits dispatch over.
- [nucleus-codegen](../nucleus-codegen/README.md) — generates `mod generated`.

## Implementation gaps

- The `Profiles` / `SSO` / `DeviceFlow` / `UserStore` traits are generated but not consumed by ovstorage-plugin-nucleus. Surfacing them through the plugin's `AuthEvent` envelope is open work.
