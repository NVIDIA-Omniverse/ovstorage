# Skill: ovstorage-services/service-developer

Use this skill when creating or modifying a service implementation that conforms
to one of the APIs under [`../apis/`](../apis/).

Service source code does not live in this repo. This repo provides the API
contracts, conformance tests, examples, and compatibility guidance that service
implementations must follow.

## Route by Need

| Need | Use |
|---|---|
| Read Storage API methods, versions, and REST/gRPC locations | [`api-reference.md`](api-reference.md) |
| Build from the Python reference implementation | [`service-quick-start.md`](service-quick-start.md) |
| Implement directly in Go, Java, Rust, or another production stack | [`service-implementation.md`](service-implementation.md) |
| Check the backend interface used by the reference service | [`backend-interface.md`](backend-interface.md) |
| Run conformance tests | [`conformance-testing.md`](conformance-testing.md) |
| Update API specs or conformance tests | [`api-contribute/AGENTS.md`](api-contribute/AGENTS.md) |

## Service Implementation Rules

- Implement against the API specs under [`../apis/`](../apis/).
- Keep gRPC, REST, conformance tests, and examples aligned for the API you
  touch.
- Declare supported API versions using
  [`../templates/api-support.yaml`](../templates/api-support.yaml).
- Treat unsupported operations as explicit unsupported responses, not silent
  success.
- Keep service implementation source, charts, and deployment-specific runtime
  tests in their owning repos.
