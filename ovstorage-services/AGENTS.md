# ovstorage-services Agent Entry

This subtree is active during the ovstorage implementation transition. Load it
when the task is about deployed services, API snapshots, conformance,
deployment, service implementation, or runtime operations.

## Route by Task

| You want to... | Load |
|---|---|
| See the service skill routes | [`skills/AGENTS.md`](skills/AGENTS.md) |
| Understand the service/API support layout | [`README.md`](README.md) |
| Work on service implementation guidance | [`skills/service-developer.md`](skills/service-developer.md) |
| Deploy or operate the stack | [`skills/operator.md`](skills/operator.md) |
| Plan auth, secrets, or cloud identity for services | [`skills/auth-secrets.md`](skills/auth-secrets.md) |
| Debug a running service | [`skills/service-debug.md`](skills/service-debug.md) |
| Prepare service releases | [`skills/release.md`](skills/release.md) |
| Work on mirrored API snapshots | [`skills/api-contribute/AGENTS.md`](skills/api-contribute/AGENTS.md) |

If the task concerns the client library, plugins, broker, REST gateway, or
language bindings, return to [`../AGENTS.md`](../AGENTS.md) and choose the
root route for that surface.

## Fresh-Agent Checks

Before publication, verify this subtree answers the service/API questions
without private context:

1. Which API snapshots are included, and where are proto/OpenAPI/generated docs?
2. How does a service implementation declare supported API versions?
3. How does a service or agent run conformance material?
4. What deployment guidance is included here, and what remains outside this repo?
5. Which license/product terms govern the API snapshots and service skills?

If the answer depends on an internal deployment repository, say so plainly and
route to the public service/API contract or template that remains in this repo.
