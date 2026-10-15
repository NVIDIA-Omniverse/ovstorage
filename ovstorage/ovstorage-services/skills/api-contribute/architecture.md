---
name: ovstorage-services/api-contribute/architecture
description: ovstorage system design — service boundaries, address/identity model, versioning lifecycle, v1alpha vs v1beta policy
type: skill
---

# Skill: ovstorage-services/api-contribute/architecture

> **Staging status:** Structured outline. Diagrams and detailed subsystem walkthroughs will be filled in by the next authoring pass.

Systems-level view of ovstorage service APIs. Load this skill before making
cross-cutting spec changes, adding a new API snapshot, restructuring versioning,
or redefining address/identity semantics.

## 1. Product architecture (three layers)

```
CLIENT APPS            ADAPTERS + CORE SERVICES       INFRASTRUCTURE
─────────────           ───────────────────────       ────────────────
Kit SDK        ─────▶   storage-service        ──▶   S3 / Azure Blob
Python client  ─────▶   discovery-service      ──▶   DNS / TLS / SQS
Agents         ─────▶   permission-service     ──▶   Postgres (Cedar)
Navigator UI   ─────▶   notification-services  ──▶   RabbitMQ / SQS
                        metadata-services
```

Left: client tools speak gRPC + REST where applicable. Center: modular services
implement published API surfaces. Right: storage and infrastructure owned by the
deployment.

Implementers write **adapters** (custom storage drivers) or **replacement services** (full API implementations in Go/Java/Rust). Both validate the same way: conformance suite.

## 2. Address / identity model

*TBD — canonical definition:*

- **Address** = mutable URI, `scheme://authority/path`. Scheme identifies the backend family.
- **Identity** = immutable, opaque, base64url-encoded. Encoding is backend-specific; clients treat as opaque.
- Round-trip: `identity = create_identity_from_address(addr); addr2 = address_from_identity(identity); assert addr == addr2` must hold.

## 3. Versioning model

### Maturity stages (per API)

| Stage | Breaking changes | Typical lifetime |
|---|---|---|
| `v1alpha` | Expected | One to two releases |
| `v1beta` | Discouraged | Several releases |
| `v1` | Forbidden (backwards-compatible only) | Long-lived |

### Promotion policy

*TBD:*
- Minimum soak time at each stage
- Conformance coverage required for promotion
- Deprecation notice required before removing a `v1alpha`
- How multiple versions coexist in a running service

### Calendar versions (repo-level)

This repo tags `YY.MM` releases bundling a coherent set of API spec versions. Services declare exactly which versions they support via `api-support.yaml`.

## 4. Service boundaries

*TBD — which operations belong in which service. Particularly:*

- Metadata service vs. Storage `stat` — overlap is intentional but the semantics differ
- Permission service vs. backend-native ACLs — Cedar is additive
- Notifications vs. storage mutation events — delivery semantics and coupling.

## 5. Conformance as contract

Specs + conformance tests are the contract. A spec change without a matching conformance-test change is **not** an accepted change. See [`add-endpoint.md`](add-endpoint.md) for the required workflow.

## 6. Deprecations

*TBD — deprecation lifecycle:*

- Marked `deprecated: true` in the OpenAPI / proto comment
- Documented in CHANGELOG for the release introducing the deprecation
- Retained for at least one `YY.MM` release
- Removed only with a version bump

## See also

- [`add-endpoint.md`](add-endpoint.md) — workflow for adding an RPC or a new API surface
- [`release.md`](release.md) — cutting a release + promoting maturity stages
- [`../../apis/storage-api/AGENTS.md`](../../apis/storage-api/AGENTS.md) — vendored implementation guide (covers the address/identity model with worked examples)
- [`../../apis/storage-api/CHANGELOG.md`](../../apis/storage-api/CHANGELOG.md) — vendored contract version history
- [`../../apis/README.md`](../../apis/README.md) — current local API map
