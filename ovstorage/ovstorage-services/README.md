# ovstorage-services

`ovstorage-services` is the retained managed-service and API support area for
ovstorage.

Services remain active because ovstorage needs a place for service/API
contracts, conformance guidance, deployment notes, and operator skills. The
client/runtime implementation lives in the main workspaces (`ovstorage-core`,
`ovstorage-services-client`, `ovstorage-cloud`, `ovstorage-nucleus`, and
`ovstorage-remote`).

Use this subtree when the task is about a deployed service or a service/API
contract. Use the root library/plugin routes for ordinary application storage,
direct cloud plugins, the broker, REST gateway, language bindings, or MCP.

## Agent Entry

Agents working on service deployment, service implementation, API specs,
conformance, or day-2 operations should start at [`AGENTS.md`](AGENTS.md).

## Layout

| Path | Purpose |
|---|---|
| `apis/` | Storage, Notifications, and Permissions API release snapshots |
| `docs/` | Service/API support, conformance, deployment, and runtime guidance |
| `skills/` | Service, API, and operator persona skills |
| `templates/` | Support templates copied by service/API contributors |

Service source repositories, Helm charts, and production deployment assets are
not included in this repo. This subtree carries the retained API and operator
material that should survive the client implementation replacement.

## Start Here

| Goal | Entry |
|---|---|
| Understand the included API snapshots | [`apis/README.md`](apis/README.md) |
| Check service/API support declarations | [`docs/api-support.md`](docs/api-support.md) |
| Run or inspect conformance material | [`docs/conformance.md`](docs/conformance.md) |
| Understand deployment boundaries | [`docs/deployment.md`](docs/deployment.md) |
| Route service/API agent work | [`skills/AGENTS.md`](skills/AGENTS.md) |

The generated HTML docs under each API snapshot are included so public readers
and agents can inspect the rendered API reference without rebuilding docs.

## Relationship to the Client Runtime

The client/runtime workspaces provide direct plugins, broker, REST gateway, and
language bindings. This subtree remains the service/API support boundary:
Storage API contracts, service conformance material, deployment guidance, and
service-oriented agent skills.

## License Boundary

This subtree is not licensed by the root Apache-2.0 grant. It carries
separately licensed service/API material, including files marked
`LicenseRef-NvidiaProprietary` and NVIDIA Software License Agreement /
Omniverse product terms. Keep the in-subtree license files with the API
snapshots and check the root [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md)
for the summary.
