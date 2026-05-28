# broker-operator persona

> *I run `ovstorage-broker` — the gRPC daemon that holds long-lived
> cloud credentials, enforces per-call authorization, and dispatches
> through the embedded `ovstorage::Library` to backend plugins. I write
> its TOML, manage its policy plugin, configure its listeners,
> consume its tracing fields, and debug what it does at runtime.*

This persona lands you at the `ovstorage-broker` binary in
`ovstorage-remote/crates/ovstorage-broker/`. The daemon embeds the
`ovstorage` Rust crate so the dispatcher, routing table, plugin
loader, and `ovstorage-cache` substrate are all the same code clients
run in Direct mode; what's broker-specific is the gRPC accept loop,
the authz-then-forward dispatch wrapper, broker-side caching, and
broker-side ownership of credentials and state.

The broker is **single-tenant by design**: one broker, one credential
boundary. Separate trust scopes are separate broker deployments —
prod versus dev, two cloud accounts, mutually untrusted teams all run
separate brokers.

## Deployment

The broker ships as a single binary:

```sh
ovstorage-broker --config /etc/ovstorage/broker.toml
```

`--config PATH` is recommended. With no `--config`, the binary falls
back to `./ovstorage.toml` in the current working directory; if
neither resolves, it hard-fails before binding any socket.

Optional flags:

- `--listen HOST:PORT` — override the listener bind value for quick
  local runs. Per-listener TLS / authn modes still come from the
  config file.

`make dist` from the repo root assembles the daemon, the REST
gateway, the CLI, and every cdylib plugin into `dist/bin/` and
`dist/plugins/`. systemd, Docker, Kubernetes, and Helm packaging are
**not** provided; operators run the binary with their existing
process-management tooling and ship `OVSTORAGE_PLUGIN_DIR` /
`OVSTORAGE_AUTHZ_PLUGIN_DIR` into the unit so the loader picks up
the right cdylibs.

A minimal systemd unit (illustrative, not provided in-tree):

```ini
[Unit]
Description=ovstorage broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ovstorage-broker --config /etc/ovstorage/broker.toml
Environment=OVSTORAGE_PLUGIN_DIR=/usr/local/lib/ovstorage/plugins
User=ovstorage
Group=ovstorage
StateDirectory=ovstorage
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Configure SIGHUP to reload, SIGTERM to drain — both are wired through
the broker's `LifecycleController`.

## Configuration shape

```toml
# /etc/ovstorage/broker.toml

# ---- Listener ----
[listener]
bind = "0.0.0.0:8787"
trusted_proxy = false                   # set true only when behind a trusted proxy
# trusted_peers = ["10.0.0.0/8"]        # required when trusted_proxy = true on TCP

[listener.tls]
cert_path = "/etc/ovstorage/broker.crt"
key_path  = "/etc/ovstorage/broker.key"

[listener.authn]
mode      = "jwt_verify"                # see "Listener authn modes" below
issuer    = "https://login.example.com"
audience  = "ovstorage"
jwks_url  = "https://login.example.com/.well-known/jwks.json"

# ---- Discovery (optional) ----
[discovery]
bind = "0.0.0.0:443"                    # serves /api/v1/services + /api/v1/auth-config
name = "Acme Production"

[[discovery.services]]
type     = "ovstorage-broker"
endpoint = "grpc+tls://broker.example.com:8787"

[[discovery.services]]
type     = "ovstorage-rest"
endpoint = "https://rest.example.com/v1"

[discovery.auth_config]
openid_configuration = "https://login.example.com/.well-known/openid-configuration"

[discovery.auth_config.clients.default]
client_id = "ovstorage-cli"
scope     = "openid email ovstorage:read ovstorage:write"

# ---- Authz plugin ----
[authz]
plugin = "ovstorage-authz-toml"

[[authz.policy]]
id        = "team-read"
effect    = "allow"
principal = "team-*"
operations = ["read", "stat", "list"]
prefix    = "s3://corp-prod/team/"

# ---- Observability ----
[observability]
prometheus_bind = "127.0.0.1:9090"      # opt-in /metrics endpoint
# otlp_endpoint = "..."                 # reserved; surfaces Unsupported today

# ---- State and cache ----
[state]
state_root = "/var/lib/ovstorage/broker/state"
cache_root = "/var/lib/ovstorage/broker/cache"

# ---- Per-route policy ----
[[routes]]
prefix = "s3://prod-assets/"

[routes.cache]
max_object_bytes = 1048576              # broker-side byte cache threshold

[routes.redirect]
ttl_seconds = 300                       # default; min 30, max 3600

# ---- Backend connections (flatten of `LibraryConfig`) ----
[[connections]]
backend_kind = "s3"
display_name = "prod-assets"
config       = { bucket = "prod-assets", region = "us-east-1" }
credentials  = { fields = { aws_access_key_id = "...", aws_secret_access_key = "..." } }
```

The broker reuses the same flat `LibraryConfig` shape the CLI and REST
gateway use, so a single `ovstorage.toml` feeds broker + CLI + REST.
`[[connections]]` registers backends at startup through the in-process
`Library`.

`make verify` from the repo root validates this config shape against
`cargo run -p xtask -- list-routes` (which loads the same TOML, resolves
credentials, and exits non-zero on bad routes / unresolvable secret
refs without binding any sockets). Use it before deploying a config
change.

## Listener authn modes

Transport is auto-detected from the `bind` value: absolute path
(`/tmp/sock`) -> Unix domain socket; `pipe:NAME` -> Windows named pipe;
`host:port` -> TCP. TCP listeners can run with TLS by setting
`[listener.tls]`. Plaintext TCP is valid for loopback / local
deterministic use; a non-loopback plaintext TCP bind is accepted only
when `trusted_proxy = true` and `trusted_peers = [...]` constrains
which proxy peers can reach the listener.

When `[listener.authn]` is omitted, the mode is auto-selected:
`peer_cred` for UDS / npipe, `jwt_verify` for TCP.

| Mode | Use when | What it requires |
|---|---|---|
| `dev_current_user` | Local development only. Identity is the current OS user. | Nothing. Avoid in production. |
| `jwt_verify` | Public TCP + TLS bearer mode — the production default. | `issuer`, `audience`, `jwks_url`. The JWKS doc is fetched through a listener-owned `reqwest::Client` (5 s connect / 10 s read), cached for a 5-minute TTL; on unknown `kid` the cache is force-refreshed once before returning `Unauthenticated`. |
| `trusted_unsigned_jwt` | Bearer JWT claims without signature validation. | `trusted_proxy = true` listener; CIDR allow-list of trusted peers. |
| `trusted_forwarded_headers` | Reverse-proxy terminates auth and forwards identity in headers. | `identity_header` (default `X-Forwarded-User`), optional `claim_headers` map; `trusted_proxy = true`; CIDR allow-list. |
| `peer_cred` | UDS / named-pipe peer-credential identity. | UDS or named-pipe `bind`. Invalid on TCP listeners. |
| `mtls` | **Reserved.** Config parses, startup fails with `Unsupported`. | Full certificate-chain validation, CA-bundle reload, SAN principal mapping not implemented today; ships in 0.5. |

All implemented modes produce an `ovstorage_authz::Principal { id,
display_name, attributes, valid_until, source }`. `source` is a
broker-core diagnostic value such as `jwt_verify`,
`trusted_unsigned_jwt`, `trusted_forwarded_headers`, or `peer_cred`.

`trusted_proxy = true` is rejected at startup for UDS / npipe
transports because they carry no peer IP for `trusted_peers` to
constrain. For TCP listeners the configured CIDRs are enforced at
request time: every gRPC call captures the peer address and the
listener rejects with `Unauthenticated` before the configured authn
header is read whenever the peer IP doesn't match an allowed CIDR.
Both IPv4 and IPv6 CIDRs are supported.

Unusual third-party authn schemes should terminate in a trusted proxy
that validates the site-specific scheme, then forwards normalized
identity to a trusted broker listener through headers or an unsigned
JWT.

## TLS

For TCP listeners, set `[listener.tls]` to a cert / key pair the
broker reads at startup. The broker speaks rustls + system trust roots;
operators with stricter trust postures deploy custom CAs into the
system trust store.

Certificate hot-reload is not implemented today — a cert rotation
requires SIGHUP (which re-reads the config and rebuilds the listener)
or a process restart.

For UDS / npipe listeners, TLS is not used; trust is OS-level (file
permissions for UDS, ACLs for named pipes).

## Authz plugin selection

The broker loads exactly one authz plugin per process. The `[authz]
plugin` field names the manifest of the cdylib to load from
`OVSTORAGE_AUTHZ_PLUGIN_DIR`. Authz plugins use a separate ABI from
storage plugins (they export `ovstorage_authz_plugin_manifest_v1` +
`ovstorage_authz_plugin_init_v1`, where storage plugins export
`ovstorage_plugin_manifest_v1` + `ovstorage_plugin_init_v1`); the
loader's filename filter selects authz cdylibs, and the manifest's
`name` field must equal `[authz].plugin`.

The first-party `ovstorage-authz-toml` plugin is what ships in-tree.
Third-party plugins build against the `ovstorage-authz` SPI per
[plugin-authz README](../plugin-authz/README.md). Hosts select the
plugin by manifest name; unknown plugin names fail startup with
`NotConfigured`.

With no `[authz]` section, the broker has no authz plugin — every RPC
is allowed. **This is dev-mode behavior.** Production deployments
must configure `[authz]` explicitly.

## Per-route policy

Each `[[routes]]` block keys policy by the *incoming caller-facing*
URL prefix:

```toml
[[routes]]
prefix = "s3://corp-prod/team/"

[routes.cache]
max_object_bytes = 1048576              # cache threshold; 0 disables

[routes.redirect]
ttl_seconds          = 300              # clamp: min 30, max 3600
read_endpoint        = "https://..."    # optional override; deterministic local conformance
write_endpoint       = "https://..."    # optional override
```

The broker uses `cache.max_object_bytes` to gate the broker-side byte
cache (default `0` — off). Raising the threshold is an explicit
decision: small same-datacenter fleets gain round-trip savings (one
warm broker connection instead of N cold cloud connections) plus
caching for objects under the threshold.

`redirect.ttl_seconds` controls the per-route redirect lifetime.
Default `300` (5 minutes), maximum `3600` (1 hour), minimum `30`.
Values outside the range produce `InvalidConfig` at config load. Short
TTLs are the project's primary lever against redirect exfiltration —
once a presigned URL leaves the broker, the broker can no longer
revoke it; only TTL expiry bounds the exposure window.

## Policy management

The broker advances `policy_epoch` on every successful SIGHUP reload.
On Unix the daemon installs a SIGHUP signal handler that re-reads + re-
validates the config, builds a fresh `Broker`, advances `policy_epoch`,
and atomically swaps the live broker pointer. The reload captures the
old broker's current epoch first, then advances the new broker's
counter strictly past it before swapping. New RPCs see the swapped
broker immediately; in-flight RPCs continue against the snapshot
`Arc<Broker>` they captured at dispatch (so the old broker is dropped
only after its last in-flight RPC completes). A failed reload logs
and leaves the old broker live.

The `state_root` directory persists the `policy_epoch` counter across
restarts so a stale request stamped with a pre-restart epoch can be
detected and rejected. **In-memory mode** (the default test/dev
configuration without `state_root`) starts every process at epoch `0`.

Specific older epochs can be invalidated through host-internal
maintenance; subsequent requests carrying invalidated epochs fail the
freshness gate with `PolicyEpochStale`.

Freshness modes:

- `strict` (default) — reauthorize every cache hit against the
  current epoch.
- `grace_window` — allow previously authorized cache hits inside the
  configured window, then require reauthorization.

Pre-deploy config validation: run
`cargo run -p xtask -- list-routes --config <broker-config>` against
the broker TOML to load the same shared `LibraryConfig` flattened in
the broker TOML, resolve credentials, and exit non-zero on bad routes
or unresolvable secret refs without binding any sockets. (`ovstorage-cli
--config <broker-config> list-routes` is the same surface from the
CLI binary.)

## Windows behavior

Windows has no SIGHUP. The broker on Windows installs CTRL_C /
CTRL_BREAK handlers that trigger drain-first shutdown (see below),
but it does not install a SIGHUP-equivalent reload path. Config
changes on Windows require a process restart.

## Observability

### Metrics

Prometheus `/metrics` is opt-in via `[observability] prometheus_bind =
"HOST:PORT"`; when set, the broker spawns an axum listener and serves
`text/plain; version=0.0.4` exposition.

Eleven metric families register at startup:

- `broker_rpc_seconds` (histogram, label `op`) — RPC latency. Dormant
  (no observation sites in the current broker).
- `broker_cache_metadata_hits_total` — metadata-cache hits.
- `broker_cache_object_hits_total` — object-byte-cache hits.
- `broker_cache_object_fills_total` — object-byte-cache fills.
- `broker_cache_evictions_total` — dormant.
- `broker_authz_decisions_total` (label `outcome` in
  `allow|deny|error`).
- `broker_watch_fanout` (gauge) — dormant.
- `broker_policy_epoch_advances_total` — increments on every successful
  reload.
- `broker_redirect_emissions_total` (label `kind` in `read|write`) —
  increments at every fixture-driven and plugin-driven redirect.
- `broker_lifecycle_events_total` (label `event` in
  `reload_ok|reload_failed|drain_start|drain_complete`).
- `broker_uptime_seconds`.

OTLP push is reserved (`otlp_endpoint` field surfaces `Unsupported` if
set). Operators wanting OTLP can layer `opentelemetry_otlp` onto the
existing `init_tracing_from_env` subscriber path.

### Health

Standard `grpc.health.v1` on the same gRPC endpoint as the rest of the
broker API. `Health/Check` reports `Serving` whenever
`library.list_backend_kinds()` succeeds. Readiness is not flipped
during drain (the gRPC server stops accepting new connections via
`serve_with_incoming_shutdown` but `Health/Check` keeps the last
reported state until the server thread exits) or failed reload (the
controller logs and keeps the old broker live).

### Tracing

In-broker calls flow through the same OpenTelemetry subscriber the
library uses. Broker spans add the following audit-safe attributes on
top of the library's set so traces carry the same fields an audit
sink would consume:

- `principal.id` — every object-IO span (`broker.stat`, `broker.read`,
  `broker.write`, `broker.list`, `broker.list_versions`,
  `broker.list_address_roots`).
- `policy_epoch` — every object-IO span and every `pb::ErrorDetail`.
- `object.address` — redacted via `RedactedUrl` (scheme + host + port
  + path only, no query / fragment / userinfo) — on every object-IO
  span that has an address.
- `audit_id` — on `ReadRedirect` and `WriteRedirect` envelopes and on
  every `pb::ErrorDetail`. Freshly minted when `RequestContext.audit_id`
  is `None`.
- `cache.hit` and `redirect.kind` where applicable.
- `outcome` (`allow|deny|error`) on the `broker_authz_decisions_total`
  counter.

`route.id` and `backend.id` are **not** stamped on per-RPC tracing
spans today: the broker does not stamp routes and does not expose the
dispatch's resolved backend without leaking. Closing the gap is a
tracked work item.

### Audit log shape

Durable audit sinks are **not** provided. The diagnostic fields land
in tracing spans, `pb::ErrorDetail` envelopes, and redirect envelopes
only. Operators that need an audit log point a log aggregator at the
broker's tracing output and filter on `audit_id` + `policy_epoch` +
`principal.id`.

Any sink that consumes these fields must redact physical URLs before
logging query strings or signed headers. The pipeline must never log
raw bearer tokens, credential bytes, or usable signed URLs.

## Debug runbook

### "The broker won't start"

1. Run
   `cargo run -p xtask -- list-routes --config /etc/ovstorage/broker.toml`
   to validate the config without binding sockets. Bad routes,
   unresolvable secret refs, and invalid listener authn config all
   fail here before the broker accepts traffic.
2. Check the journal: the broker fails closed on bad listener authn
   config, invalid authz plugin policy, missing backend plugin, bad
   route binding, unavailable state root, unavailable cache root, or
   listener bind failure. The error is typed and names the
   offending field.
3. Confirm the cdylibs are where the loader expects them:
   `OVSTORAGE_PLUGIN_DIR` for storage plugins,
   `OVSTORAGE_AUTHZ_PLUGIN_DIR` for the authz plugin. Verify the
   manifest `name` matches `[authz].plugin`.

### "The broker accepts the call but every request fails authz"

1. Look at the tracing output for `broker_authz_decisions_total
   {outcome="deny"}`. The deny path threads the plugin's `reason` and
   `explanation` into the gRPC `PermissionDenied` message; a
   well-written authz plugin returns a stable rule id as
   `explanation`.
2. Check `policy_epoch` — a recent reload may have invalidated older
   epochs. Requests stamped with `PolicyEpochStale` need to refresh
   their connection.
3. Confirm the principal's `id` matches a rule in the TOML. Look at
   the `principal.id` field on the failing span.

### "The broker is up but no routes are visible"

1. Run `cargo run -p xtask -- list-routes --config <broker-config>`
   from the broker host to load the same TOML the broker loads. If
   the routes are missing here, the config is missing them.
2. Check `[[connections]]` blocks — backends register at startup, and
   a missing or misnamed plugin manifest fails startup.
3. Confirm the embedded `Library` sees the published address roots:
   the broker's `ListAddressRoots` RPC mirrors what `Library` would
   return in-process.

### "Streaming writes are slow / corrupted / aborted"

1. The broker server distinguishes graceful EOF (`Ok(None)` from the
   inbound stream) from RST_STREAM(CANCEL) (`Err(status)` with
   `status.code() == Cancelled`). Look for `broker.write` spans
   ending in `Status::cancelled` — that's the client-side abort path.
2. Inline upload size is bounded by `WRITE_BODY_BYTE_CAP` (64 MiB)
   after authz. Larger writes must use the redirect branch (S3
   multipart, GCS resumable, etc.); the plugin must mint redirects
   via `WriteStep::Redirects`.
3. Check `broker_redirect_emissions_total{kind="write"}` — a missing
   redirect emission means the plugin can't mint redirects for that
   route, and the broker is falling back to inline upload.

### "Lifecycle: reload didn't pick up my change"

1. `broker_lifecycle_events_total{event="reload_failed"}` increments
   when a SIGHUP reload fails validation. Check the journal for the
   typed validation error.
2. A successful reload increments `policy_epoch_advances_total`.
3. Windows hosts: no SIGHUP. Use a process restart.

### "Drain: shutdown hangs"

The broker drains on SIGTERM / SIGINT (Unix) and CTRL_C / CTRL_BREAK
(Windows) up to the configurable `drain_timeout` (default
`DEFAULT_DRAIN_TIMEOUT`). `serve_with_incoming_shutdown` stops
accepting new connections and runs in-flight RPCs to completion
within the timeout. If a worker RPC is wedged in the plugin (most
commonly, a hung remote authz plugin or a wedged upstream backend),
the drain deadline expires and the process exits with in-flight RPCs
truncated. Tune `drain_timeout` to the longest legitimate request
your workload tolerates.

## Implementation gaps

- **mTLS.** `authn.mode = "mtls"` parses as a reserved config shape
  but startup validation returns `Unsupported`. Client-certificate
  validation, CA-bundle reload, certificate / SAN principal mapping,
  and the matching conformance for bad chain, wrong SAN, revoked /
  expired certificate, and rotation are not implemented. Full
  support ships in 0.5.
- **Per-principal connection / RPC / watch limits.** The broker
  enforces only a global per-watch-key fan-out cap (256) and
  per-watcher queue depth (256); per-principal quotas mapped to
  `ResourceExhausted` are not implemented.
- **Durable audit sinks.** No `AuditRecord` / `AuditEvent` type,
  durable sink, or operator-facing `explain-decision` tool is
  provided. Diagnostic fields land in tracing spans, error details,
  and redirect envelopes only.
- **OTLP push.** Field reserved; surfaces `Unsupported` if set.
- **Certificate hot-reload.** Cert rotation requires SIGHUP or
  process restart.
- **Crash-injection conformance.** Tests that crash the broker
  mid-redirect-issuance or mid-write are not implemented;
  partial-publish hardening rides on the `ovstorage-cache`
  substrate's atomic put.
- **Operator packaging assets.** systemd, Docker, Kubernetes, and Helm
  assets are not provided.

## Related

- [plugin-storage README](../plugin-storage/README.md) — backend
  plugin author concerns.
- [plugin-storage plugin-broker page](../plugin-storage/plugin-broker.md)
  — the `broker-client` cdylib that calls this daemon from
  library-side processes.
- [plugin-authz README](../plugin-authz/README.md) — authz plugin
  author concerns. The `AuthzPlugin` SPI, the 21 operations, the
  policy-epoch model.
- [library-web README](../library-web/README.md) — the REST gateway
  in front of the broker.
