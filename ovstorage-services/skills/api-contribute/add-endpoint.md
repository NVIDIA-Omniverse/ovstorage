---
name: ovstorage-services/api-contribute/add-endpoint
description: End-to-end workflow for adding a new RPC to an ovstorage API — proto → bindings → REST → conformance test
type: skill
---

# Skill: ovstorage-services/api-contribute/add-endpoint

> **Staging status:** Structured workflow outline. Concrete file diffs will be filled in from the first real endpoint addition.

The canonical workflow for adding a new RPC, a new message type, or a whole new API surface. Ship with matching conformance tests — or don't ship.

## 1. Decide scope

| What you're adding | Steps needed |
|---|---|
| New field on an existing message | Proto + OpenAPI + conformance (compatibility test) |
| New RPC on existing service | Proto + OpenAPI + service skeleton + conformance |
| New service on existing API | Proto + OpenAPI + version directory check + conformance |
| New API surface entirely | All the above **+** new `ovstorage-services/apis/<api-name>/` directory, API README, conformance entry point, examples when available, and `api-support.yaml` guidance update |

## 2. Version choice

- Adding a **new endpoint** at an existing maturity stage is allowed only if the stage permits non-breaking additions (yes for `v1beta` / `v1`, always for `v1alpha`).
- Changing the **shape** of an existing endpoint → requires bumping to a new version path.
- Removing an endpoint → requires deprecation cycle; see [`architecture.md`](architecture.md) §6.

## 3. Proto change

For the local Storage API contract, protos live under:

```
ovstorage-services/apis/storage-api/proto/nvidia/omniverse/storage/<version>/<service>.proto
```

Contract path: [`../../apis/storage-api/proto/nvidia/omniverse/storage/`](../../apis/storage-api/proto/nvidia/omniverse/storage/) (read-only unless the task explicitly asks for a contract snapshot update).

- Add RPC definition
- Add request/response messages
- Update `CapabilitiesService.ListServices` output if adding a service or version
- Compile locally: `buf build` / `protoc --dry_run`

## 4. OpenAPI change

For storage-api:

```
ovstorage-services/apis/storage-api/openapi/<surface>/<version>/<surface>-api.yaml
```

e.g. `openapi/fileobject/v1beta/fileobject-api.yaml`. Mirror path: [`../../apis/storage-api/openapi/`](../../apis/storage-api/openapi/).

- Add path + method
- Define request / response schemas (JSON equivalents of proto messages)
- Ensure naming convention matches (`listStat` RPC → `/list-stat/{addr}` path — verify the canonical mapping rule)

REST and gRPC must stay in sync. They are kept manually — the REST spec is **not** generated from proto.

## 5. Reference implementation change

If the new RPC is in `v1beta` or `v1`, the Python reference backend must implement it. The reference lives at [`../../apis/storage-api/filesystem_example/`](../../apis/storage-api/filesystem_example/):

- Add method to `filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py`
- Update the reference `filesystem_example` backend implementations
- Update the gRPC + REST service layers in the same tree

See [`../../apis/storage-api/AGENTS.md`](../../apis/storage-api/AGENTS.md) §Path A for the mechanics.

## 6. Conformance test change (required)

Conformance tests are **co-located with the spec**, not in a separate `tests/` root. Add a `.feature` file under:

```
ovstorage-services/apis/storage-api/conformance_tests/src/conformance_tests/features/<surface>/<version>/<operation>.feature
```

Scenarios must cover:
- Happy path
- Missing resource / unauthorized / malformed request
- `UNIMPLEMENTED` response path (if the operation is optional)
- Both gRPC and REST (parametrize via `Examples:` or the existing test-step indirection)

Also add or update the matching step definitions under `conformance_tests/src/conformance_tests/steps/<surface>/` and the top-level `test_<operation>.py` runner.

See the existing features for patterns: [`../../apis/storage-api/conformance_tests/src/conformance_tests/features/`](../../apis/storage-api/conformance_tests/src/conformance_tests/features/).

## 7. Documentation change

*TBD:*

- Update [`../api-reference.md`](../api-reference.md) — add row in the RPC table
- Update the version matrix in [`../api-reference.md`](../api-reference.md) §1 if promotion is involved
- Update [`../backend-interface.md`](../backend-interface.md) if the Python reference interface gained methods
- Update the relevant API README under [`../../apis/`](../../apis/)

## 8. Single commit

All of the above lands in **one commit** (or one PR, squashed). Spec and tests never ship in separate commits.

Commit message convention:

```
feat(<api>/<version>): add <rpc-name>

- proto: new RPC + messages
- openapi: new path + schemas
- ref-impl: backend method
- conformance: happy-path + error-path + partial-impl
```

## 9. Pre-merge checklist

- [ ] Proto compiles clean across gRPC code generators (Go, Java, Rust test builds pass)
- [ ] OpenAPI validates (lint clean)
- [ ] Reference backend passes added conformance tests locally
- [ ] `api-reference.md` updated
- [ ] CHANGELOG entry added for the upcoming `YY.MM` release

## See also

- [`architecture.md`](architecture.md) — when to bump versions vs. add in place
- [`release.md`](release.md) — cutting the release after the change lands
- [`../conformance-testing.md`](../conformance-testing.md) — running the added tests
- [`../../apis/storage-api/AGENTS.md`](../../apis/storage-api/AGENTS.md) — vendored implementation guide
- [`../../apis/storage-api/PROMPTS.md`](../../apis/storage-api/PROMPTS.md) — reusable prompt templates for RPC additions
