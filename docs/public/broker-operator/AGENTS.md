# broker-operator — agent routing

Terse map for agents operating an `ovstorage-broker` deployment. For
prose, see [README.md](README.md).

## Where to start

- **Config shape**: [README.md § Configuration shape](README.md#configuration-shape).
- **Listener authn modes**: [README.md § Listener authn modes](README.md#listener-authn-modes).
- **Policy management**: [README.md § Policy management](README.md#policy-management).
- **Observability**: [README.md § Observability](README.md#observability).
- **Debug runbook**: [README.md § Debug runbook](README.md#debug-runbook).

## House rules

- The broker is single-tenant by design. One broker, one credential
  boundary. Separate trust scopes are separate brokers.
- Production must configure `[authz]` explicitly. No `[authz]` =
  allow-all dev mode.
- `[listener]` `mode` defaults: `peer_cred` for UDS / npipe,
  `jwt_verify` for TCP. Public TCP needs `[listener.tls]` +
  `jwt_verify` with valid `issuer`, `audience`, `jwks_url`.
- `[routes.redirect] ttl_seconds` is clamped at config load: min 30,
  max 3600, default 300. Short TTLs are the primary
  redirect-exfiltration mitigation.

## Lifecycle

- **Start**: `ovstorage-broker --config /etc/ovstorage/broker.toml`.
  Falls back to `./ovstorage.toml`; hard-fails with no config.
- **Reload (Unix)**: SIGHUP atomic reload. `LifecycleController`
  re-reads and re-validates config, builds a fresh `Broker`, advances
  `policy_epoch`, atomically swaps. Failed reload logs and leaves the
  old broker live.
- **Reload (Windows)**: no SIGHUP equivalent. Process restart.
- **Drain**: SIGTERM / SIGINT (Unix) and CTRL_C / CTRL_BREAK (Windows)
  trigger `LifecycleController::signal_drain`. New connections refused;
  in-flight RPCs run to completion up to `drain_timeout`
  (`DEFAULT_DRAIN_TIMEOUT`).
- **Crash recovery**: delegated to `ovstorage-cache`. On restart the
  broker reopens its state DB, cleans abandoned cache leases /
  staging rows, and never publishes a partially written
  broker-cache entry. Issued redirects remain cloud-valid until TTL.

## Authz

- Single authz plugin per process via `[authz] plugin =
  "<manifest-name>"`. Cdylib loaded from
  `OVSTORAGE_AUTHZ_PLUGIN_DIR`. The first-party plugin is
  `ovstorage-authz-toml`.
- Authz uses a separate ABI from storage; the loader's filename
  filter selects authz cdylibs.
- `copy` and `rename` decompose at the broker into primitive
  `Read`/`Write`/`Delete` checks. `add_alias` checks
  `AddAlias(from) + Read(to)`.
- `list` and `watch_directory` run per-item / per-event filtering
  via `AuthzPlugin::filter_list_batch`. Filtered drops are silent
  (no `Lapsed` synthesis for authz drops).
- Connection / alias / visibility management calls go through authz
  when they cross the broker (the same op names appear in the
  stable list); direct-mode `Library` calls bypass authz because
  the principal is the local process.
- See [plugin-authz README](../plugin-authz/README.md) for the
  SPI.

## Policy epoch

- `policy_epoch` is a monotonically-increasing `u64` stamped on every
  `AuthzRequest`.
- `advance()` bumps the epoch and persists it under `state_root`.
- `check(request_epoch)` rejects stale epochs except under
  `grace_window`, which honors `request_epoch + 1 == current_epoch`
  unless explicitly invalidated.
- In-memory mode (no `state_root`) starts at epoch `0` on every
  process start.

## Caching

- `[routes.cache] max_object_bytes` gates the broker-side byte cache.
  Default `0` (off). Under-threshold objects: broker fetches +
  caches + streams. Over-threshold objects: broker forwards a
  `Redirect`; bytes flow cloud <-> caller direct.
- Metadata cache (stat / list / list_versions) is per-route TTL plus
  broker-driven invalidation on writes. Backend change-notification
  dispatchers (S3-SQS / GCS-Pub/Sub / Azure-EventGrid) are wired but
  return `Unsupported` — declared sources fall through to TTL-only
  mode.

## Streaming

- Inline upload size is bounded by `WRITE_BODY_BYTE_CAP` (64 MiB)
  after authz. Larger writes use the redirect branch.
- Watch_directory fan-out: hard-coded cap of 256 downstream
  watchers per upstream key
  (`DEFAULT_WATCH_DIRECTORY_FANOUT_LIMIT`). Per-watcher queue depth
  256 (`DEFAULT_WATCH_DIRECTORY_QUEUE_DEPTH`); overflow injects one
  `Lapsed` and resumes.
- gRPC `Write` distinguishes graceful EOF (commit) from
  RST_STREAM(CANCEL) (abort with `Status::cancelled`).

## Observability

- Metrics: opt-in `[observability] prometheus_bind`. 11 families
  register; some are dormant (RPC-latency histogram,
  cache-eviction counter, watch-fanout gauge).
- Health: standard `grpc.health.v1`. Readiness not flipped during
  drain.
- Tracing: `principal.id`, `policy_epoch`, redacted `object.address`,
  `audit_id`, `cache.hit`, `redirect.kind` on object-IO spans.
  `route.id` / `backend.id` not stamped (tracked work item).
- Audit: no durable sink; tracing output is the audit surface.

## What lives elsewhere

- `broker-client` plugin (library-side counterpart) is in
  [plugin-storage plugin-broker.md](../plugin-storage/plugin-broker.md).
- REST gateway is in [library-web README](../library-web/README.md).
- Authz plugin author surface is in
  [plugin-authz README](../plugin-authz/README.md).
- Storage backend plugin author surface is in
  [plugin-storage README](../plugin-storage/README.md).
