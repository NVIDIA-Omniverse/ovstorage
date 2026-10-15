# Authorization policy agent routing

Use this surface for the built-in authorization Layer and its TOML policy.

- Operator configuration: [broker operator guide](../broker-operator/README.md#auth-layer)
- Policy contract: [README.md](README.md)
- Layer implementation: `ovstorage-remote/ovstorage-authz-layer/`
- Pure policy engine: `ovstorage-remote/ovstorage-authz-policy/`
- Shared principal and credential context: `ovstorage-remote/ovstorage-authz-context/`

The host does not load standalone authorization cdylibs, and there is no
dedicated authz ABI. Do not add an authorization-specific ABI or loader path.
A third-party listener-auth kind is an ordinary storage Layer wrapper whose
descriptor declares `auth_capable = true`; unknown, non-wrapper, and
non-auth-capable kinds fail startup. The wrapper owns its config schema and
policy lifecycle. The built-in typed policy reload applies only to
`builtin-auth`; broker SIGHUP reconstructs a plugin auth wrapper from its
verbatim config as part of the fresh broker.
