# Running Services

Use this guide when an existing ovstorage-compatible service deployment is
already available and you need to connect clients or verify behavior.

This repo does not include service source code or a runnable production stack.
It includes API snapshots, conformance guidance, and operational guidance.

## Client Connection

The active client/runtime service path is the `ovstorage-services-client`
plugin, configured from the main ovstorage library, CLI, broker, or REST
gateway. Service deployments should advertise supported API versions and
capabilities; clients should use those signals before attempting backend-
specific operations.

## Operator Checklist

- Confirm the deployment advertises the API versions it supports.
- Confirm discovery returns top-level addresses and capability routes.
- Confirm required auth headers or token providers are configured outside repo
  logs and examples.
- Use the active client/runtime CLI or API for smoke checks.
- Use the API conformance suite for implementation-level compatibility.

## Related Material

- API support template: [`../templates/api-support.yaml`](../templates/api-support.yaml)
- Conformance guide: [`conformance.md`](conformance.md)
- Debug skill: [`../skills/service-debug.md`](../skills/service-debug.md)
