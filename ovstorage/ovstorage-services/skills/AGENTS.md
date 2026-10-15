# ovstorage-services Skills Router

Use one service/API route per task. This subtree is secondary; for ordinary
application storage, return to the root [`../../AGENTS.md`](../../AGENTS.md)
and choose the library/plugin route that matches the task.

| Persona | Goal | Start |
|---|---|---|
| API reader | Look up Storage API RPCs, versions, and wire contracts | [`api-reference.md`](api-reference.md) |
| API contributor | Change API specs, conformance tests, or API examples | [`api-contribute/AGENTS.md`](api-contribute/AGENTS.md) |
| Service implementer | Build a service that conforms to the APIs | [`service-developer.md`](service-developer.md) |
| Python reference implementer | Use the Python reference backend interface | [`service-quick-start.md`](service-quick-start.md) |
| Production implementer | Implement a service in Go, Java, Rust, or another stack | [`service-implementation.md`](service-implementation.md) |
| Conformance owner | Run or debug API conformance tests | [`conformance-testing.md`](conformance-testing.md) |
| Operator | Deploy, observe, upgrade, or roll back services | [`operator.md`](operator.md) |
| Deployment skill user | Use the imported Omniverse Storage APIs deploy skill bundle | [`deploy/README.md`](deploy/README.md) |
| Debugger | Triage a running service deployment | [`service-debug.md`](service-debug.md) |
| Auth/secret owner | Plan service credentials, cloud identity, or token handling | [`auth-secrets.md`](auth-secrets.md) |
| Release owner | Check API support, service compatibility, images, and charts | [`release.md`](release.md) |

Service source code, Helm charts, operators, and environment-specific runtime
tests live outside this repo. This repo provides the API contracts,
conformance/example material, and guidance needed to build and run them.
