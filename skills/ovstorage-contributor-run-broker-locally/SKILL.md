---
name: ovstorage-contributor-run-broker-locally
description: Use when starting an ovstorage-broker locally for development or integration testing - covers a minimal TOML, the cdylib plugin path, and how to hit the listener with broker-client or curl.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, broker, development]
tools: [Read, Bash]
compatibility: Requires an ovstorage checkout, built plugins, local networking, and optional local test credentials supplied by the user.
---

# Run the Broker Locally

## Goal

Stand up a local `ovstorage-broker` against a minimal TOML config
for development / integration testing. UDS-bound, `peer_cred`
auth, in-tree `ovstorage-authz-toml` policy, file-backed routes.

## Recipe

1. Build the binaries + plugins:
   ```sh
   make dist
   # dist/bin/ovstorage-broker plus dist/plugins/lib*.so
   ```
2. Author a minimal config at `$XDG_RUNTIME_DIR/broker.toml`:
   ```toml
   [listener]
   bind = "/tmp/ovstorage-broker.sock"
   # No [listener.authn] — UDS auto-defaults to peer_cred.

   [authz]
   plugin = "ovstorage-authz-toml"

   [[authz.policy]]
   id        = "allow-me"
   effect    = "allow"
   principal = "*"
   operations = ["*"]
   prefix    = "*"

   [[connections]]
   backend_kind = "file"
   display_name = "scratch"
   config       = { root = "/tmp/ovstorage-broker-scratch" }
   ```
   `mkdir -p /tmp/ovstorage-broker-scratch` first.
3. Start the daemon:
   ```sh
   OVSTORAGE_PLUGIN_DIR=$(pwd)/dist/plugins \
   OVSTORAGE_AUTHZ_PLUGIN_DIR=$(pwd)/dist/plugins \
   ./dist/bin/ovstorage-broker --config "$XDG_RUNTIME_DIR/broker.toml"
   ```
   The broker binds the UDS, auto-defaults to `peer_cred`, loads
   the in-tree authz plugin, and registers the file backend.
4. Hit it from `ovstorage` CLI (or any `broker-client`-loaded
   library):
   ```sh
   ./dist/bin/ovstorage connect \
       --kind broker \
       --display-name local-broker \
       --address "unix:/tmp/ovstorage-broker-scratch.sock"
   ./dist/bin/ovstorage list "file:///" \
       --through local-broker
   ```
5. For HTTP discovery testing, add a `[discovery]` block and a
   TCP listener:
   ```toml
   [listener]
   bind = "127.0.0.1:8787"
   trusted_proxy = false

   # peer_cred is invalid on TCP; explicit dev mode:
   [listener.authn]
   mode = "dev_current_user"

   [discovery]
   bind = "127.0.0.1:8088"
   name = "Local Dev"

   [[discovery.services]]
   type     = "ovstorage-broker"
   endpoint = "grpc+tcp://127.0.0.1:8787"
   ```
   Then `curl http://127.0.0.1:8088/api/v1/services` should
   surface the broker entry.
6. On Unix, send SIGHUP to advance `policy_epoch` and reload
   config after edits:
   ```sh
   kill -HUP $(pgrep ovstorage-broker)
   ```
7. To drain on shutdown, send SIGTERM. The
   `LifecycleController` refuses new connections and runs
   in-flight RPCs to completion within `drain_timeout`.

## Common mistakes during local dev

- Pointing `OVSTORAGE_PLUGIN_DIR` at `target/debug/` instead of
  `dist/plugins/`. `make dist` runs the cdylib build with the
  right rustc flags and stages every shipped plugin in one
  place.
- Forgetting that `peer_cred` is invalid on TCP. The broker
  refuses to start with `peer_cred` + TCP `bind`.
- Trying to set `trusted_proxy = true` on a UDS listener. UDS /
  npipe carry no peer IP for `trusted_peers` to constrain;
  startup fails.
- Setting `[listener.tls]` on UDS. Not used; TLS is TCP-only.
- Skipping `[authz]` and surfacing the broker on a non-loopback
  bind. That's allow-all mode; never expose publicly.

## Test the broker-client round-trip

`ovstorage-remote/crates/ovstorage-plugin-broker/tests/precondition.rs`
exercises the broker-client SPI surface against a recording
transport. For a true end-to-end `cargo test`-style run that
launches a live broker process and talks to it through
`broker-client`, look at
`ovstorage-remote/crates/ovstorage-broker/tests/`.

## References

- [`docs/public/broker-operator/README.md`](../../docs/public/broker-operator/README.md)
  — the operator surface; reuse the listener-authn-mode and
  policy sections.
- [`docs/public/plugin-storage/plugin-broker.md`](../../docs/public/plugin-storage/plugin-broker.md)
  — the broker-client SPI surface.
- [`docs/public/library-web/README.md`](../../docs/public/library-web/README.md)
  — running the REST gateway in front of your local broker.
- [`ovstorage-contributor-author-authz-plugin`](../ovstorage-contributor-author-authz-plugin/SKILL.md)
  — authoring a custom authz plugin to load instead of
  `ovstorage-authz-toml`.
- [`ovstorage-contributor-verify-before-merge`](../ovstorage-contributor-verify-before-merge/SKILL.md)
  — `make verify` + `make test` before opening a PR.
