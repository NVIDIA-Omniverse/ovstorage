---
name: ovstorage-operator-configure-broker-policy
description: Use when authoring or rotating the broker's authz policy - covers the [authz] TOML block, plugin selection, policy-epoch advance/invalidate, and grace-window freshness mode.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, broker, authz]
tools: [Read, Write]
compatibility: Requires access to broker configuration files and the operator's approved policy source. Secrets and deployment details are user-supplied.
---

# Configure Broker Authz Policy

## Goal

Write a correct `[authz]` policy block for `ovstorage-broker`,
manage `policy_epoch` advances on policy rotation, and pick
freshness modes (`strict` vs `grace_window`) that match the
deployment's tolerance for cached decisions.

## Recipe

1. Read
   [`docs/public/plugin-authz/README.md`](../../docs/public/plugin-authz/README.md)
   for the SPI shape, the stable list of 21 operation names, the
   `copy` / `rename` decomposition rule, and the policy-epoch model.
2. Pick an authz plugin. `ovstorage-authz-toml` ships in-tree;
   third-party plugins build against the SPI per the same doc.
3. Author the `[authz]` block:
   ```toml
   [authz]
   plugin = "ovstorage-authz-toml"
   decision_ttl_max_seconds = 30      # optional; clamped by the host

   [[authz.policy]]
   id        = "team-read"
   effect    = "allow"
   principal = "team-*"               # glob against Principal.id
   operations = ["read", "stat", "list"]
   prefix    = "s3://corp-prod/team/"  # segment-aligned, caller-facing
   ```
   Rules: longest-prefix wins; ties go to the later rule. Denies by
   default. Prefix is the *incoming caller-facing* URL, never a
   resolved physical target.
4. Decompose `copy` and `rename`: those are NOT standalone authz
   ops. Grant `read` on source + `write` on destination instead.
   `add_alias` keeps its own op AND requires `read` on the alias
   `to` target.
5. Pick freshness:
   - `strict` (default) — reauthorize every cache hit against the
     current `policy_epoch`. Most secure; slowest for policy
     churn.
   - `grace_window` — honor `request_epoch + 1 == current_epoch`
     for cache hits (unless explicitly invalidated). Trades some
     freshness for lower load on the authz plugin during reload
     windows.
6. Validate before deploying:
   ```sh
   cargo run -p xtask -- list-routes --config /etc/ovstorage/broker.toml
   ```
7. On Unix, advance the policy with SIGHUP. The
   `LifecycleController` re-reads and re-validates the config,
   builds a fresh `Broker`, advances `policy_epoch`, and
   atomically swaps. New RPCs see the swapped broker immediately;
   in-flight RPCs continue against their captured snapshot.
8. On Windows, restart the process — no SIGHUP equivalent.

## Policy rotation runbook

- **Add a new allow rule for a new team.** Edit TOML; SIGHUP. New
  rule applies on the next RPC.
- **Revoke access immediately.** Add a `deny` rule, SIGHUP. Pair
  with `grace_window: false` if you cannot tolerate the previous
  epoch's cached decisions.
- **Wholesale policy rewrite.** Edit TOML; SIGHUP. The fresh
  `policy_epoch` advances past the old; stale requests stamped with
  the old epoch fail with `PolicyEpochStale` (which the SDK turns
  into a refresh-and-retry).
- **Invalidate one specific older epoch** without a full advance:
  use the broker's internal `PolicyEpochState::invalidate` path
  (currently only exposed to in-process maintenance; no operator
  CLI today).

## Common mistakes

- Writing rules against the *resolved* physical target instead of
  the caller-facing alias. The broker authorizes the
  caller-facing address; aliases are compatibility gates, not
  policy-bypass holes.
- Forgetting that `prefix = "*"` matches calls without an
  address (`list_address_roots`, `list_backend_kinds`, etc.); a
  concrete prefix only matches requests carrying an address.
- Granting `copy` or `rename` directly — those decompose into
  primitives at the broker before they reach the plugin. Grant the
  primitives.
- Forgetting the alias-write `read(to)` check. Creating an alias
  to data the caller can't read themselves would let others reach
  it through the alias.
- Skipping `state_root` in production. In-memory mode resets the
  epoch counter to `0` on every restart.

## References

- [`docs/public/plugin-authz/README.md`](../../docs/public/plugin-authz/README.md)
  — SPI, operation names, policy-epoch model, audit-safe
  explanations.
- [`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md)
  — `[authz]` block placement, lifecycle interactions.
- `ovstorage-remote/crates/ovstorage-authz-toml/` — the TOML policy
  engine sources for reference.
- [`ovstorage-operator-deploy-broker`](../ovstorage-operator-deploy-broker/SKILL.md) —
  initial deployment.
- [`ovstorage-operator-debug-broker`](../ovstorage-operator-debug-broker/SKILL.md) —
  triaging denied requests at runtime.
