---
name: ovstorage-operator-deploy-broker
description: Use when deploying the ovstorage-broker daemon to production - covers TOML config, listener authn modes, TLS, policy plug-in, and state directory layout.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, broker, deployment]
tools: [Read, Write, Bash]
compatibility: Requires operator access to deployment hosts or manifests, TLS material, authn configuration, and approved secret-management paths.
---

# Deploy the ovstorage Broker

## Goal

Stand up a single-tenant `ovstorage-broker` daemon with the right
listener authn mode, valid TLS (for public TCP), a configured authz
plugin, and persistent `state_root` for policy-epoch survival across
restarts.

## Recipe

1. Read [`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md)
   for the full operator surface (config shape, listener authn modes,
   TLS, policy management, observability).
2. Build the binary + plugins:
   ```sh
   make dist
   # dist/bin/ovstorage-broker plus dist/plugins/lib*.so
   ```
3. Pick a listener authn mode. Defaults: `peer_cred` for UDS / npipe,
   `jwt_verify` for TCP. Production public TCP requires
   `[listener.tls]` and `jwt_verify` with valid `issuer`, `audience`,
   `jwks_url`. `mtls` is reserved in 0.4 and fails startup with
   `Unsupported`.
4. Choose an authz plugin. `[authz] plugin = "ovstorage-authz-toml"`
   is the in-tree default. With no `[authz]` section, the broker
   runs allow-all (dev mode) — never deploy this publicly.
5. Provision a persistent `state_root` (and `cache_root` if
   `[routes.cache] max_object_bytes > 0` is set on any route).
   Without `state_root`, the policy-epoch counter starts at `0` on
   every process restart.
6. Validate the config without binding sockets:
   ```sh
   cargo run -p xtask -- list-routes --config /etc/ovstorage/broker.toml
   ```
   Bad routes, unresolvable secret refs, and invalid listener authn
   config all fail here.
7. Start the daemon:
   ```sh
   ovstorage-broker --config /etc/ovstorage/broker.toml
   ```
   Plug `OVSTORAGE_PLUGIN_DIR` and `OVSTORAGE_AUTHZ_PLUGIN_DIR` into
   the systemd unit (or your process supervisor) so the loaders find
   the cdylibs.
8. Configure SIGHUP for reload (Unix; Windows has no SIGHUP — config
   changes need a process restart) and SIGTERM / SIGINT for
   drain-first shutdown.

## Checks before going live

- `[listener.authn] mode = "jwt_verify"` on a public TCP bind with
  `[listener.tls]` populated.
- `[authz]` section present and pointing at a valid plugin manifest.
- `state_root` is on durable, broker-owned storage.
- `[routes.redirect] ttl_seconds` is set per route (default 300; max
  3600; min 30; clamped at config load).
- `OVSTORAGE_PLUGIN_DIR` / `OVSTORAGE_AUTHZ_PLUGIN_DIR` resolve to
  directories the broker user can read.
- The broker user has no shell / no login privileges.

## What's not in scope

systemd / Docker / Kubernetes / Helm packaging assets are NOT
provided in-tree. Certificate hot-reload is NOT implemented (rotate
via SIGHUP or process restart). mTLS is reserved.

This skill is only for the lightweight `ovstorage-broker` daemon. It does not
deploy or operate the Kubernetes-based `ovstorage-services` stack; for that
service stack, use the `ovstorage-services` routing in a source checkout.

## References

- [`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md)
  — full deployment surface, configuration shape, listener authn modes,
  observability, debug runbook.
- [`docs/public/plugin-authz/README.md`](../../docs/public/plugin-authz/README.md)
  — authz plugin author surface; the `[authz]` block your broker
  loads.
- [`ovstorage-operator-configure-broker-policy`](../ovstorage-operator-configure-broker-policy/SKILL.md)
  — `[authz]` policy authoring + epoch management.
- [`ovstorage-operator-monitor-broker`](../ovstorage-operator-monitor-broker/SKILL.md) —
  Prometheus metrics + tracing field reference.
- [`ovstorage-operator-debug-broker`](../ovstorage-operator-debug-broker/SKILL.md) —
  runtime triage.
