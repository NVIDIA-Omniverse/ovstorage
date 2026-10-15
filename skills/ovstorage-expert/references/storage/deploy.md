Up: [ovstorage-expert](../../SKILL.md)

# Operate an existing broker or REST deployment

Normal library and resolver use embeds ovstorage in-process and deploys no
service. The existing public broker/REST guidance does not recommend these
surfaces for new deployments. The following routes support existing deployments:


| Daemon | Existing role | Guide |
| --- | --- | --- |
| `ovstorage-broker` (gRPC) | Several clients need credential isolation, policy enforcement, or shared metadata; clients reach it through the broker-client backend | [broker-operator](../../../../ovstorage/docs/public/broker-operator/README.md) |
| `ovstorage-rest` (HTTP) | Browser, Node, or non-Rust callers need object I/O over REST | [library-web](../../../../ovstorage/docs/public/library-web/README.md) |

Both ship as single binaries in `ovstorage/dist/`; run them under your process manager. The repository provides no container images or Helm charts for them. Each loads an `[ovstorage]` Stack with the same schema as every other host ([configure.md](configure.md)), plus its own listener, auth, and observability sections.

## Operator skills

For an existing broker installation, use the relevant operator guide:

1. [Deploy the broker](../../../../ovstorage/skills/ovstorage-operator-deploy-broker/SKILL.md) — listener, TLS, auth kind.
2. [Configure broker policy](../../../../ovstorage/skills/ovstorage-operator-configure-broker-policy/SKILL.md) — `[[policy]]` rules ([authz-policy](../../../../ovstorage/docs/public/authz-policy/README.md)).
3. [Monitor the broker](../../../../ovstorage/skills/ovstorage-operator-monitor-broker/SKILL.md) — Prometheus, tracing, audit.
4. [Debug the broker](../../../../ovstorage/skills/ovstorage-operator-debug-broker/SKILL.md) — startup failures, denies, listener mismatches.

For local development, [run the broker locally](../../../../ovstorage/skills/ovstorage-contributor-run-broker-locally/SKILL.md).

## Not covered here

- The vendored service subtree contains API contracts and reference material. Production service implementations, Helm charts and deployment
  assets are not included. Imported draft deployment guidance does not make
  those services part of this repository; preserve vendor files and licenses.
- Neither daemon is a content cache. For cluster-scale read caching see [related experts](../related-experts.md).
