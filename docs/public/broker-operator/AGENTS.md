# broker-operator — agent routing

Terse map for agents operating an `ovstorage-broker` deployment. For
prose, see [README.md](README.md).

## Where to start

- **Config shape**: [README.md § Configuration shape](README.md#configuration-shape).
- **Rule prefixes**: [README.md § Rule prefixes](README.md#rule-prefixes).
- **Authn front-end**: [README.md § Authn front-end](README.md#authn-front-end).
- **Auth layer**: [README.md § Auth layer](README.md#auth-layer).
- **Policy management**: [README.md § Policy management](README.md#policy-management).
- **Observability**: [README.md § Observability](README.md#observability).
- **Debug runbook**: [README.md § Debug runbook](README.md#debug-runbook).

## House rules

- The broker is single-tenant by design. One broker, one credential
  boundary. Separate trust scopes are separate brokers.
- Auth is **fail-closed**: every listener must declare an `auth` block.
  A missing `auth` refuses to start; `auth = "anonymous"` is the
  explicit unauthenticated allow-all opt-in.
- For `builtin-auth`, authn is transport-branched: peer credentials for
  UDS / npipe and an explicit `authn_mode` for authenticated TCP. Signed
  JWT is the default when the OIDC triplet is present; trusted proxy modes
  require `trusted_proxy = true` plus an enforced `trusted_peers` CIDR
  list; mTLS requires `[listener.tls].client_ca_path`. Plugin auth kinds
  own their credential decoding and configuration schema.
- The broker never mints redirects. The configured backend plugins hold
  the credentials in the broker process and do the presigning; the
  broker forwards what comes back through the Stack, and the redirect's
  lifetime and revocation are the backend's.
- Whether a forwarded redirect may reach the client is the operator's
  `redirect_credential_disclosure` (`refuse` by default, `allow` to opt
  in), governing the read and the write path together. The test is what
  the minting backend declares its credential authorizes, not which
  header carries it. Enforced in the `redirect_follower` layer, where a
  refusal can still fetch the bytes, and again at the broker's out-edge,
  where an operator graph cannot compose it away.

## Lifecycle

- **Start**: `ovstorage-broker --config /etc/ovstorage/broker.toml`.
  Falls back to `./ovstorage.toml`; hard-fails with no config.
- **Reload (Unix)**: SIGHUP atomic reload. `LifecycleController`
  re-reads and re-validates config, builds a fresh `Broker` (which
  reconstructs the auth layer from the fresh `auth` config), atomically
  swaps. Failed reload logs and leaves the old broker live.
- **Reload (Windows)**: no SIGHUP equivalent. Process restart.
- **Drain**: SIGTERM / SIGINT (Unix) and CTRL_C / CTRL_BREAK (Windows)
  trigger `LifecycleController::signal_drain`. New connections refused;
  in-flight RPCs run to completion up to `drain_timeout`
  (`DEFAULT_DRAIN_TIMEOUT`).
- **Crash recovery**: delegated to `ovstorage-cache`. On restart the
  broker reopens its state DB, cleans abandoned cache leases /
  staging rows, and never publishes a partially written
  broker-cache entry. Issued redirects remain cloud-valid until TTL.

## Auth layer

- Authn + authz are one auth wrapper composed over the shared inner Stack
  and configured per listener under `[listener.auth]`. Accepted choices are
  the explicit `auth = "anonymous"` allow-all form, `kind =
  "builtin-auth"`, or a loaded wrapper kind whose descriptor declares
  `auth_capable = true`. A missing or unknown kind, a backend or router,
  or an ordinary wrapper fails startup. Plugin auth uses the ordinary
  storage Layer ABI; there is no separate authorization-plugin ABI.
- For `builtin-auth`, `[listener.auth.config]` carries the `policy` rule
  set, TCP `authn_mode` settings, optional `jwt_*` settings, and
  `peer_dev_current_user`. The rule set is the `ovstorage-authz-toml`
  shape (`[[policy]]` rules). These built-in authn settings do not
  configure a plugin kind.
- A plugin auth factory receives `[listener.auth.config]` verbatim and
  owns its schema, credential decoding, and authorization behavior. On a
  trusted-proxy TCP listener the broker validates `trusted_peers` before
  capturing only the plugin config's `forwarded_identity_header` and
  `forwarded_claim_headers`; duplicate values and input order are preserved.
- `copy` and `rename` decompose at the layer into primitive
  `Read`/`Write`/`Delete` checks.
- `list` and `watch_directory` post-filter entries / events by
  per-item visibility; filtered drops are silent.
- The auth layer gates data verbs, the two per-principal introspection slots
  (`list_address_roots`, `list_connections`), and the two slots that establish
  connection credentials (`authenticate_connection`,
  `update_connection_credentials`). Remaining management slots are
  config-time and ungated. On allow it stamps `ext::PRINCIPAL_ID` DOWN; on deny
  it returns `PermissionDenied`.

## Policy revocation

- No policy-epoch counter, no freshness mode, no epoch persistence. The
  built-in auth layer evaluates the fresh policy on every request, so a
  revoked principal is denied on its next request. `PolicyEpochStale`
  exists only as a wire error code.
- SIGHUP rebuilds the broker (and its auth layer) from fresh config;
  the new policy is live on the next request.
- Plugin auth kinds have no built-in typed policy hot-reload operation.
  SIGHUP reconstructs the plugin wrapper from its verbatim config as part
  of the fresh broker; Windows requires a process restart.
- A live `watch_directory` stream keeps delivering change
  notifications for its already-authorized prefix until disconnect
  (each event re-checked for `Read`); non-stream ops reflect
  revocation immediately.

## Caching

- Caching is layers in the `[ovstorage]` graph, not per-route config:
  `[ovstorage.layers.byte_cache]` with `cache_root`, `state_root` and
  `max_object_bytes` (default `0` — off), and
  `[ovstorage.layers.metadata_cache]` with `max_entries` and
  `ttl_seconds`. Under-threshold objects: broker
  fetches + caches + streams. Over-threshold objects: broker forwards a
  `Redirect` when `redirect_credential_disclosure` permits it, otherwise
  streams the bytes itself.
- Metadata cache (stat / list / list_versions) is layer TTL plus
  broker-driven invalidation on writes, and `watch_invalidation = true`
  for watch-driven invalidation. Backend change-notification
  dispatchers (S3-SQS / GCS-Pub/Sub / Azure-EventGrid) are wired but
  return `Unsupported` — declared sources fall through to TTL-only
  mode.

## Streaming

- Inline upload size is bounded by `WRITE_BODY_BYTE_CAP` (64 MiB)
  after authz. Larger writes use the redirect branch.
- Watch_directory fan-out: no per-principal watcher cap (future work at
  a central chokepoint, not the per-backend coalescer) and no global
  per-watch-key cap. Per-watcher queue depth is 256; overflow injects
  one `Lapsed` and resumes.
- gRPC `Write` distinguishes graceful EOF (commit) from
  RST_STREAM(CANCEL) (abort with `Status::cancelled`).

## Observability

- Metrics: opt-in `[observability] prometheus_bind`. 10 families
  register; some are dormant (RPC-latency histogram,
  cache-eviction counter, watch-fanout gauge). Auth decisions are
  `ovstorage_auth_decisions_total` (`outcome = allow|deny|error`).
- Health: standard `grpc.health.v1`. Readiness not flipped during
  drain.
- Tracing: `principal.id`, redacted `object.address`, `audit_id`,
  `cache.hit`, `redirect.kind` on object-IO spans. `route.id` /
  `backend.id` not stamped (tracked work item).
- Audit: no durable sink; tracing output is the audit surface.

## What lives elsewhere

- `broker-client` plugin (library-side counterpart) is in
  [plugin-storage plugin-broker.md](../plugin-storage/plugin-broker.md).
- REST gateway is in [library-web README](../library-web/README.md).
- Storage backend plugin author surface is in
  [plugin-storage README](../plugin-storage/README.md).
