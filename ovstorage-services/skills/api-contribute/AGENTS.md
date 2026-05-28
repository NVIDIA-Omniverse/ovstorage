# API Contribute Skills - Agent Router

You want to **extend the ovstorage API specs** — add an RPC, introduce a new API surface, bump a version, or publish a release. These skills cover the workflow for changing the spec itself, not implementing against it.

> **Status:** these skills are concrete for the Storage API snapshot mirrored
> under [`../../apis/storage-api/`](../../apis/storage-api/). Notifications and
> Permissions snapshots are present under `../../apis/`; contribution workflows
> for their conformance suites and examples are less complete.

## Route by task

| I want to… | Load |
|---|---|
| Understand the system design, service boundaries, and versioning model | [`architecture.md`](architecture.md) |
| Add a new RPC end-to-end (proto → bindings → REST → conformance test) | [`add-endpoint.md`](add-endpoint.md) |
| Publish a new calendar-versioned release (`YY.MM`) of this repo | [`release.md`](release.md) |
| Promote an API from `v1alpha` to `v1beta` or `v1` | [`release.md`](release.md) (§Maturity promotion) |
| Add a new API snapshot to the repo | [`add-endpoint.md`](add-endpoint.md) (§New API surface) + [`architecture.md`](architecture.md) |

## Core conventions

- API versions are `v1alpha` / `v1beta` / `v1`. Multiple versions coexist.
- Spec changes ship with matching conformance tests in the same commit — no exceptions.
- Breaking changes require a new version path; backwards-compatible changes update the existing one.
- Every RPC has both gRPC and REST forms. They must stay in sync.

## Source of truth

When changing the Storage API spec:
- Proto files live at [`../../apis/storage-api/proto/`](../../apis/storage-api/proto/)
- OpenAPI files live at [`../../apis/storage-api/openapi/`](../../apis/storage-api/openapi/)
- Conformance tests live at [`../../apis/storage-api/conformance_tests/`](../../apis/storage-api/conformance_tests/) — **co-located with the spec, not a separate tree**

All three must change together.

Treat the vendored spec subtree as read-only unless the task explicitly asks for
a contract snapshot update.

## Not here

| You want… | Go to |
|---|---|
| To build a backend against an existing spec | [`../service-developer.md`](../service-developer.md) |
| The vendored Storage API agent guide | [`../../apis/storage-api/AGENTS.md`](../../apis/storage-api/AGENTS.md) |
| The vendored Storage API prompt templates | [`../../apis/storage-api/PROMPTS.md`](../../apis/storage-api/PROMPTS.md) |
