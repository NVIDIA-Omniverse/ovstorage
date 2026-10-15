# ovstorage-authz

Slim shared host types for ovstorage's remote surfaces.

This crate exports `Principal` plus the attribution overlay used by the broker
and REST gateway. Authorization itself is implemented as the built-in storage
Layer in [`ovstorage-authz-layer`](../ovstorage-authz-layer/src/lib.rs), backed
by the pure TOML policy engine in
[`ovstorage-authz-policy`](../ovstorage-authz-policy/src/lib.rs).

There is no authorization-specific plugin ABI or loader in this crate.

## Contents

- `src/lib.rs`: `Principal`, the public attribution re-exports, and where the
  attribution Layer belongs in a host's graph — `UserMetadataKinds`,
  `attributed_router_layers` and `ensure_branch_attribution`, which place one
  instance per router branch, on the branches whose backend kind declares it can
  carry a `user_metadata` key.
- `src/attribution.rs`: `AttributionLayer`, `AttributionWrapper`, strategies,
  and reserved metadata keys.

See the public [authorization policy guide](../../docs/public/authz-policy/README.md)
for the supported configuration and runtime contract.
