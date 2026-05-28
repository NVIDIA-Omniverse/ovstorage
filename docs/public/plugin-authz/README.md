# plugin-authz persona

> *I'm writing an authorization plugin for an authorization-aware
> ovstorage host (broker or REST gateway). I implement the
> `AuthzPlugin` trait, wire it through the `ovstorage_authz_plugin!`
> macro, ship a cdylib, and the host loads me at runtime and asks me
> whether each call is allowed.*

You're writing a new authz engine. The in-tree authz reference is
`ovstorage-authz-toml` (a deterministic TOML policy engine usable in
local conformance without external services). The shared substrate
— C ABI, cdylib loader, manifest validation, conformance harness —
lives in `ovstorage-authz` and is consumed by both authorization-aware
hosts:

- `ovstorage-broker` (gRPC daemon) — authorizes every RPC before
  backend dispatch, runs per-item list filtering, runs per-event
  watch filtering, enforces a state-root-persisted `policy_epoch`.
- `ovstorage-rest` (REST gateway) — same rules, in-memory
  `policy_epoch`.

## AuthzPlugin trait

```rust
#[async_trait::async_trait]
pub trait AuthzPlugin: Send + Sync {
    fn plugin_name(&self) -> &str;

    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision>;

    async fn filter_list_batch(
        &self,
        request: &AuthzRequest,
        addresses: &[Url],
    ) -> Result<Vec<AuthzDecision>> {
        // Default: authorize per-address with `request.operation`.
    }
}
```

Both methods are async — real plugins may consult a remote policy
server. `filter_list_batch` exists because `list` results need
per-item filtering and a batch entry point lets you collapse N policy
lookups into one (or amortize a single round-trip to a remote PDP).
The default impl forwards `request.operation` per address; override
it for batch-aware policy backends.

Hosts hold an `Arc<dyn AuthzPlugin>` and call the trait directly.
There is no per-call cancellation parameter on the trait today (see
*Cancellation contract* below).

## Request and decision types

```rust
pub struct Principal {
    pub id: String,
    pub display_name: Option<String>,
    pub attributes: HashMap<String, String>,
    pub valid_until: Option<SystemTime>,
    pub source: String,
}

pub struct AuthzRequest {
    pub principal: Principal,
    pub operation: Operation,
    pub address: Option<Url>,
    pub policy_epoch: u64,
    pub audit_id: Option<String>,
}

pub struct AuthzDecision {
    pub effect: AuthzEffect,           // Allow | Deny
    pub reason: Option<String>,
    pub explanation: Option<String>,
    pub decision_ttl: Option<Duration>,
}
```

`Principal.id` is the stable, host-supplied identifier you write your
rules against (`alice@example.com`, `team-platform`,
`urn:service:render-worker-42`, …). `source` is a broker-core
diagnostic value (`jwt_verify`, `trusted_unsigned_jwt`,
`trusted_forwarded_headers`, `peer_cred`, `dev_current_user`) — write
your rules against `id`, not `source`.

`address` is the **incoming caller-facing** `Url`, never a resolved
physical target. Policy is written over the human-readable address
operators and audit reviewers understand; aliases act as
compatibility gates, not policy-bypass holes.

`policy_epoch` is the host's current epoch counter; stamp it on
`decision_ttl` if you cache decisions. The host stamps every request
with the current epoch and clamps any plugin-provided `decision_ttl`
against route + host policy limits. A plugin returning no TTL forces
per-call evaluation.

`audit_id` is a fresh-minted handle the host attaches to traces,
redirect envelopes, and error details. Round-trip it through your
explanation if useful for offline forensics; don't rely on it being
present (it's `None` when the host caller doesn't provide one and the
authz plugin runs before the host mints a fallback).

`AuthzDecision.explanation` is a **stable, audit-safe handle** —
typically a rule id like `"team-read"`. It rides through tracing
spans and the gRPC error-details message. It MUST NOT contain bearer
tokens, signed URLs, credential bytes, or unredacted physical URLs.

## The 21 operations

The stable operation names hosts ask you to authorize:

**Object I/O (12)**: `stat`, `read`, `write`, `delete`, `list`,
`list_versions`, `watch_directory`, `create_directory`,
`delete_directory`, `update_metadata`, `check_access`,
`list_address_roots`.

**Routing introspection (1)**: `list_backend_kinds`.

**Connection management (4)**: `add_connection`, `remove_connection`,
`update_connection_credentials`, `list_connections`.

**Alias management (3)**: `add_alias`, `remove_alias`, `list_aliases`.

**Visibility management (1)**: `set_address_visibility`.

That's 21. `copy` and `rename` are **intentionally absent**:
directional ops decompose into primitive checks at the host before
they reach your plugin. `copy` becomes `read` on the source plus
`write` on the destination; `rename` becomes `read` + `delete` on the
source plus `write` on the destination. This lets a policy that
grants `read` on `/src/` and `write` on `/dst/` permit a copy without
authoring a separate `copy` rule.

`add_alias` is asymmetric: it keeps its own op (the `from` side is
structurally different — registering a route, not writing data), and
the host **also** issues a `read` check on the alias's `to` target so
that creating an alias to data the caller couldn't access themselves
doesn't let *other* callers reach it through the alias.

Direct-mode `Library` calls (in-process, principal = local process)
bypass authz for connection / alias / visibility management; the
broker / REST hosts route those same methods through your plugin when
they cross the host boundary.

Use `operation_name(op)` and `operation_from_name(s)` for stable
string round-tripping across the C ABI.

## Policy epoch model

The `policy_epoch` is a monotonically-increasing `u64` stamped on
every `AuthzRequest`. Hosts own a `PolicyEpochState` with three
operations:

- `current_epoch()` — read the active epoch.
- `advance()` — bump the epoch (broker reload) and persist if
  `state_root` is configured.
- `check(request_epoch)` — validate the inbound epoch.

Freshness modes:

- **`strict`** (default) — reauthorize every cache hit against the
  current epoch.
- **`grace_window`** — allow previously authorized cache hits inside
  the configured window, then require reauthorization. The current
  policy honors only the **immediate previous epoch** (`request_epoch
  + 1 == current_epoch`); older epochs reject. Explicitly invalidated
  epochs also reject.

Hosts may invalidate specific older epochs to evict in-flight stale
work; subsequent requests carrying invalidated epochs fail with
`PolicyEpochStale`.

Your plugin doesn't run the epoch state machine; it reads the
stamped `request.policy_epoch` and may use it as part of a cache key
or as evidence of policy freshness when computing `decision_ttl`.

## Manifest, descriptor, and lifecycle

A cdylib authz plugin's surface:

- **Manifest** — cdylib-level metadata exported as the
  `ovstorage_authz_plugin_manifest_v1` symbol. Carries
  `struct_size: usize`, `abi_version: u32`,
  `name` and `version` (NUL-terminated, from `CARGO_PKG_NAME` /
  `CARGO_PKG_VERSION`), and `test_only: bool` (production hosts
  refuse to load `test_only` plugins).
- **ABI version** — `OVSTORAGE_AUTHZ_PLUGIN_ABI_VERSION`, distinct
  from the storage SPI's `OVSTORAGE_PLUGIN_ABI_VERSION`. Authz and
  storage ABIs evolve independently. The loader's
  `validate_authz_init_result_header` compares the plugin's
  `abi_version` against the authz constant.
- **Init function** — exports `ovstorage_authz_plugin_init_v1` which
  hands the host a `BackendFactoryVTableV1`-shaped vtable for
  `configure` / `authorize` / `filter_list_batch`.

Hosts select the plugin by manifest `name` (e.g.
`ovstorage-authz-toml`); unknown plugin names fail startup with
`NotConfigured`. The kind disambiguator between storage and authz
cdylibs is **filename prefix** (`libovstorage_plugin_*` for storage;
`libovstorage_authz_*` for authz) plus the symbol prefix the loader
resolves; there is no `plugin_kind` field on the manifest.

A skeleton Rust authz plugin is two files. The `Cargo.toml`:

```toml
[package]
name    = "my-authz-plugin"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
ovstorage-authz  = "0.1"
ovstorage-plugin = "0.1"
async-trait      = "0.1"
tokio-util       = { version = "0.7", default-features = false }
```

And `src/lib.rs` implementing `AuthzPlugin` and invoking the macro at
module scope. The macro emits the two cdylib symbols
(`ovstorage_authz_plugin_manifest_v1` and
`ovstorage_authz_plugin_init_v1`) and pulls `name` / `version` from
`CARGO_PKG_*`.

```rust
#[derive(Default)]
struct ExampleAuthz;

#[async_trait::async_trait]
impl AuthzPlugin for ExampleAuthz {
    fn plugin_name(&self) -> &str { "example-authz" }

    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision> {
        // Toy: allow `read` for anonymous, deny everything else.
        match request.operation {
            Operation::Read | Operation::Stat | Operation::List => {
                Ok(AuthzDecision::allow_with_explanation("rule:public-read"))
            }
            _ => Ok(AuthzDecision::deny("default-deny")),
        }
    }
}

ovstorage_authz_plugin!(ExampleAuthz::default);
```

Hosts call `configure` once at startup with the operator's opaque
TOML subtable (the trailing keys under `[authz]` minus the `plugin`
field), then call `authorize` and `filter_list_batch` per request
for the process lifetime. A clean `drop_plugin` shutdown drains
in-flight calls up to a 5-second timeout before freeing the boxed
state.

## Cancellation contract

The vtable signatures for `authorize` and `filter_list_batch` each
carry a `cancel: *const CancelTokenFFI` slot, but the Rust
`AuthzPlugin` trait methods take no `CancellationToken` parameter, so
the loader passes `std::ptr::null()` for those two slots today. The
`configure` thunk does propagate cancellation when the host hands it
one.

**Plugin authors SHOULD bound their own work with an internal
deadline. The host does not propagate cancellation across the cdylib
FFI today.** A remote-policy plugin that hangs on a slow upstream
pins the host's outer RPC timeout (whatever the caller configured)
rather than the host's own cancel signal. That is acceptable for
synchronous in-tree plugins (the first-party `ovstorage-authz-toml`
is synchronous and never blocks on I/O) but is a known
shutdown-latency and resource-exhaustion risk if a plugin contacts a
remote policy server. The risk is bounded by the project's "all
plugins first-party" memory: there are no third-party authz plugins
shipping today, so the consumer-side mitigation is operator-level
(don't deploy a hanging plugin).

Closing the gap requires a trait change — adding
`cancel: Option<CancellationToken>` (or equivalent) to `authorize` /
`filter_list_batch`. That change crosses three workspaces (core,
remote, broker) and needs to land as one atomic patch — tracked
internally as an in-flight design effort.

Until then, the rule: if your plugin's `authorize` calls anything
that can block (network I/O, file I/O, IPC, lock acquisition,
DNS, …), wrap it in `tokio::time::timeout` with a deadline shorter
than the host's RPC timeout, and return `Err(Error::new(Transient,
"…"))` on timeout. The host's `with_route_retry` will retry
`Transient` errors per its retry config.

## FFI input ownership contract

Every `*const T` input parameter on a vtable method (`configure`,
`authorize`, `filter_list_batch`) transfers ownership from host to
plugin at call time. The plugin MUST consume each input
synchronously before returning (typically via `ptr::read` in Rust or
`memcpy` / deep-copy in C) into plugin-owned storage, because the
host considers the inputs gone the instant the vtable function
returns and will not free them. Holding an input pointer across an
async boundary is undefined behavior. Result and error pointers
passed to `on_complete` transfer ownership in the opposite direction
(plugin to host).

This convention matches the storage SPI's per-vtable-call contract.
The `ovstorage_authz_plugin!` macro emits thunks that handle
marshaling correctly; hand-authoring the vtable in C is out of scope
— authz plugins are Rust by convention, and the macro is the
authoring target.

## Worked example: ovstorage-authz-toml

The in-tree reference plugin. Its TOML shape:

```toml
[authz]
plugin = "ovstorage-authz-toml"
decision_ttl_max_seconds = 30          # optional; clamped by the host

[[authz.policy]]
id        = "team-read"
effect    = "allow"
principal = "team-*"                   # glob against Principal.id
operations = ["read", "stat", "list"]
prefix    = "s3://corp-prod/team/"     # segment-aligned

[[authz.policy]]
id        = "deny-secrets"
effect    = "deny"
principal = "*"
operations = ["read"]
prefix    = "s3://corp-prod/team/secrets/"
```

Matching rules:

- The plugin denies by default.
- A rule matches when `principal` glob-matches `Principal.id`,
  `operations` contains the requested operation (or `"*"`), and
  `prefix` is `"*"` or a segment-aligned prefix of
  `request.address`. Segment alignment means `s3://bucket/foo` does
  not match `s3://bucket/foobar`; only `/`, `?`, and `#` count as
  segment boundaries. Use a trailing `/` (`s3://bucket/foo/`) for
  every-descendant matching.
- When multiple rules match, **longest matching prefix wins**;
  ties go to the later rule.
- The winning rule's `id` rides as `AuthzDecision.explanation` for
  audit.

`prefix = "*"` matches every operation, including ones without an
address (`list_address_roots`, `list_backend_kinds`,
`list_connections`, …); a concrete prefix only matches requests that
carry an address.

Sources are in
`ovstorage-remote/crates/ovstorage-authz-toml/src/`. The
`README.md` there is the dev-only pointer; the public reference for
the TOML policy schema lives in this file.

## Audit-safe diagnostics

The fields hosts emit today (per
[broker-operator README § Observability](../broker-operator/README.md#observability)):

- `principal.id` on object-IO spans.
- `policy_epoch` on object-IO spans and `pb::ErrorDetail`.
- `object.address` (redacted) on object-IO spans.
- `audit_id` on redirects and `pb::ErrorDetail`.
- `outcome` (`allow|deny|error`) on the `authz_decisions_total`
  counter.

Your plugin's `reason` and `explanation` are folded into the
`PermissionDenied` error message that flows through the gRPC
error-details message on a deny. Neither is emitted as a separate
structured field today; closing that gap is a tracked work item.

The host fails closed: if your plugin returns an `Err(...)`, the RPC
returns a typed error and the backend is not called. A `Deny`
decision returns `PermissionDenied`.

## Conformance checklist

A new authz plugin should cover at minimum:

1. **Empty policy denies.** No rules = no allows.
2. **Allow / deny matching.** Both effects work.
3. **Wildcards.** `principal = "*"` and `operations = ["*"]` match.
4. **Longest-prefix precedence.** Rules with longer prefixes win.
5. **Same-prefix later-rule precedence.** Tie-break by order.
6. **Decision TTL round-trip.** If your plugin returns
   `decision_ttl: Some(...)`, the host respects it (clamped).
7. **`address = None`.** Requests without an address (e.g.
   `list_address_roots`) match only `prefix = "*"` rules.
8. **Concurrent `authorize` calls.** 32 in parallel must not
   corrupt state.
9. **Clean drop with in-flight calls.** `drop_plugin` waits up to
   5 seconds for outstanding work.
10. **Internal deadlines.** Calls bound their own work; a wedged
    upstream doesn't pin the host's RPC timeout indefinitely.

`ovstorage-authz-toml` exercises all of these in its
`tests/`. Mirror the structure.

## What's not in scope

- **`AuthenticateConnection` and auth-event streams.** These are
  local `Library` APIs in Direct mode and never go through the
  authz plugin. The broker's per-user upstream OAuth is its own
  surface (`Auth` / `RegisterCredential` RPCs); your authz plugin
  is consulted on the upstream RPC the user-code runs after
  authenticating, not on the authentication flow itself.
- **`InteractiveAuthCapability` carrying.** The
  `x-ov-iauth: browser|headless|none` gRPC metadata header is a
  broker listener-authn signal, not part of `RequestContext` or
  `AuthzRequest`. The broker threads it alongside the context only
  on the paths that need it.
- **Multi-plugin authz.** The broker supports exactly one authz
  plugin. Chained evaluation across multiple authz engines is a
  v2 concern.
- **Dynamic sandboxing.** Authz plugins run in-process at full host
  trust. The cdylib loader does not run them in a separate process
  or under a syscall filter; manifests are descriptive metadata,
  not a runtime gate.

## Related

- [plugin-development README](../plugin-development/README.md) — the
  shared C ABI substrate.
- [plugin-storage README](../plugin-storage/README.md) — storage
  plugin author surface (different SPI, separate ABI version).
- [broker-operator README](../broker-operator/README.md) — how
  operators configure your plugin and consume its decisions.
- [library-web README](../library-web/README.md) — REST gateway
  authz behavior (same SPI, same rules).
