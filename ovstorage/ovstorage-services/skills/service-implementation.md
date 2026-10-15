---
name: ovstorage-services/service-implementation
description: Implement a production ovstorage service in Go, Java, or Rust directly from proto and OpenAPI specs
type: skill
---

# Skill: ovstorage-services/service-implementation

> **Staging status:** Structured outline. Per-language code generation commands and service skeletons will be filled in by the next authoring pass.

Path B: skip the Python plugin model and implement the gRPC + REST service directly in a compiled language. Used when you need throughput beyond what Python can deliver, or when your team's stack is Go/Java/Rust-native.

## When to use this skill

Load this skill if:
- Your service will carry high concurrent load (100+ RPS per replica)
- You cannot accept the Python interpreter overhead
- Your team's standard stack is Go, Java, Rust, or another compiled language
- You want full control over the service layer, not just the backend logic

For a 15-minute Python on-ramp, load [`service-quick-start.md`](service-quick-start.md). For the complete Python interface reference, load [`backend-interface.md`](backend-interface.md).

---

## 1. Source specs

- gRPC: [`../apis/storage-api/proto/`](../apis/storage-api/proto/)
- REST: [`../apis/storage-api/openapi/`](../apis/storage-api/openapi/)

Both are authoritative. They are hand-authored and kept in lockstep — the REST spec is **not** generated from proto.

Upstream also ships per-language starter guidance at [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) §Path B (Go / Java / Rust `protoc` invocations, REST-only implementation checklist). Read that alongside this skill.

---

## 2. Code generation

*TBD — exact `protoc` / `buf` / `openapi-generator` invocations for:*

- **Go**: `protoc --go_out=. --go-grpc_out=. proto/**/*.proto` + `oapi-codegen -package storage openapi/storage.yaml`
- **Java**: Gradle `protobuf-gradle-plugin` + `openapi-generator-maven-plugin`
- **Rust**: `tonic-build` in `build.rs` + `utoipa`/`openapi-generator` for REST

Output expectations per language — TBD.

---

## 3. Service checklist

Every production service must implement:

### Storage API — 18 RPCs

- [ ] `CapabilitiesService.ListServices`
- [ ] `CapabilitiesService.ListTopLevelAddresses`
- [ ] `FileObjectService.Enumerate`
- [ ] `FileObjectService.Stat`
- [ ] `FileObjectService.Read`
- [ ] `FileObjectService.ReadFromAddress`
- [ ] `FileObjectService.FetchWriteTypeInfo`
- [ ] `FileObjectService.Write`
- [ ] `FileObjectService.CompleteRedirectUpload`
- [ ] `FileObjectService.UploadPart`
- [ ] `FileObjectService.CompleteMultipartUpload`
- [ ] `FileObjectService.AbortMultipartUpload`
- [ ] `FileObjectService.Delete`
- [ ] `FileFolderService.List`
- [ ] `FileFolderService.ListStat`
- [ ] `FileFolderService.DeleteFolder`
- [ ] `VersioningService.EnumerateVersions`
- [ ] REST equivalent for all of the above

*TBD — similar checklists for notification-api, permission-api, etc.*

---

## 4. REST ↔ gRPC mapping

Every RPC has both forms. They share semantics but differ in:

| Aspect | gRPC | REST |
|---|---|---|
| Streaming | Server-streaming RPCs (`Read`, `Enumerate`) | Chunked transfer + continuation tokens |
| Metadata | gRPC trailers or first streaming frame | Response headers |
| Error encoding | Status code enum | HTTP status + problem+json body |
| Auth | `authorization` metadata entry | `Authorization` bearer header |

*TBD — per-RPC table with exact method ↔ path mapping sourced from OpenAPI spec.*

---

## 5. Error codes — canonical mapping

| gRPC status | HTTP | Meaning |
|---|---|---|
| `UNAUTHENTICATED` | 401 | Missing / invalid token |
| `PERMISSION_DENIED` | 403 | Valid token, insufficient scope |
| `NOT_FOUND` | 404 | Resource does not exist |
| `FAILED_PRECONDITION` | 412 | Optimistic-lock mismatch, or preconditions unmet |
| `INVALID_ARGUMENT` | 400 | Malformed request |
| `RESOURCE_EXHAUSTED` | 429 | Rate limit |
| `INTERNAL` | 500 | Server-side error |
| `UNIMPLEMENTED` | 501 | Conformant "not supported" — **must be used** for partial impl |

Conformance tests verify these mappings explicitly.

---

## 6. Streaming semantics

*TBD — per-operation notes:*

- `Read` / `ReadFromAddress`: server emits metadata frame first, then data chunks. Client must buffer metadata before data.
- `Enumerate` / `List` / `ListStat`: paginated streams with continuation tokens in response trailers.
- `Write`: client streams data chunks; server responds with `WriteResponse` that indicates body-accepted, redirect-URL, or multipart handle.

---

## 7. Backend abstraction inside your service

Even in a production implementation, decouple the API layer from the storage driver:

```
  [gRPC server] ─┐
                 ├── [API-layer: validation, error mapping, auth] ── [StorageDriver interface] ── [S3 / Azure Blob / FS driver]
  [REST server] ─┘
```

This mirrors the Python reference layering and keeps conformance tests backend-agnostic.

---

## 8. Validation

Pass the **spec conformance** suite — Python `pytest-bdd` under [`../apis/storage-api/conformance_tests/`](../apis/storage-api/conformance_tests/). Point its `TEST_STORAGE_API_*` env vars at your running implementation and invoke the release wrapper at [`../apis/storage-api/run_tests.sh`](../apis/storage-api/run_tests.sh). There is no unified `ovstorage-conformance` binary today.

See [`conformance-testing.md`](conformance-testing.md) for the real invocation
and [`../docs/conformance.md`](../docs/conformance.md) for service conformance
guidance. Deployment-specific E2E and smoke/resiliency suites live with the
owning service/deployment repos.

---

## See also

- [`backend-interface.md`](backend-interface.md) — Python interface, useful as a semantics reference even for non-Python builds
- [`conformance-testing.md`](conformance-testing.md) — real validation workflow
- [`api-reference.md`](api-reference.md) — complete RPC + REST spec lookup
- [`../apis/storage-api/proto/`](../apis/storage-api/proto/) — authoritative gRPC
- [`../apis/storage-api/openapi/`](../apis/storage-api/openapi/) — authoritative REST
- [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) §Path B — `protoc` starters for Go / Java / Rust
