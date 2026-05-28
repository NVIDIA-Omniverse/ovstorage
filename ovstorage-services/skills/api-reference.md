---
name: ovstorage-services/api-reference
description: RPC, message, and REST endpoint reference for the mirrored ovstorage service APIs
type: skill
---

# Skill: ovstorage-services/api-reference

The single lookup page. Not a tutorial — just the spec, table-first. Load when
you need a specific RPC name, message field, error code, or REST path.

## Layout

1. [Version matrix](#1-version-matrix-v1alpha-vs-v1beta-vs-v1)
2. [Storage API](#2-storage-api) — 4 services, 18 RPCs
3. [Notifications and Permissions APIs](#3-notifications-and-permissions-apis)
4. [Error code catalog](#4-error-code-catalog)

---

## 1. Version matrix (v1alpha vs v1beta vs v1)

**Philosophy:** `v1alpha` = breaking changes expected. `v1beta` = stabilizing, breaking changes discouraged. `v1` = backwards-compatible only. Multiple versions coexist.

### Storage API

| Feature | `v1alpha` | `v1beta` | `v1` |
|---|---|---|---|
| FileObjectService core (read/write/stat/delete) | ✅ | ✅ | — |
| Enumerate / streaming list | ✅ | ✅ | — |
| FileFolderService.List / ListStat | ✅ | ✅ | — |
| FileFolderService.DeleteFolder | ✅ | ✅ | — |
| FileFolderService.CreateFolder (explicit) | ✅ | ❌ | — |
| VersioningService.EnumerateVersions | ✅ | ✅ | — |
| MetadataService (ETag key/value) | ✅ | ❌ | — |
| CapabilitiesService.ListRoutes | ✅ | ❌ | — |
| Copy / Move RPCs | ✅ | ❌ | — |
| Versioned address syntax (`addr;version`) | ✅ | ❌ | — |
| Multipart upload (server-driven) | ✅ | ✅ | — |

**Decision guide:** target `v1beta` unless you explicitly need metadata, copy/move, or versioned addresses — those require `v1alpha`.

### Other APIs

| API | Local versions |
|---|---|
| Notifications Aggregation / Publisher | `v1beta` |
| Notifications Consumer | `v1beta` |
| Permissions | `v1beta` |

---

## 2. Storage API

**Proto location:** [`../apis/storage-api/proto/nvidia/omniverse/storage/`](../apis/storage-api/proto/nvidia/omniverse/storage/)
**OpenAPI location:** [`../apis/storage-api/openapi/`](../apis/storage-api/openapi/)
**Conformance tests:** [`../apis/storage-api/conformance_tests/`](../apis/storage-api/conformance_tests/) (pytest-bdd, bundled with the spec)

### 2.1 CapabilitiesService

Package: `nvidia.omniverse.storage.capabilities.v1beta`

| RPC | Request | Response | REST | Purpose |
|---|---|---|---|---|
| `ListServices` | `ListServicesRequest` | `ListServicesResponse` | `GET /v1beta/capabilities/services` | Return supported services + versions |
| `ListTopLevelAddresses` | `ListTopLevelAddressesRequest` | `ListTopLevelAddressesResponse` | `GET /v1beta/capabilities/top-level-addresses` | Return root address prefixes this instance serves |

### 2.2 FileObjectService

Package: `nvidia.omniverse.storage.fileobject.v1beta`

| RPC | Streaming? | REST | Purpose |
|---|---|---|---|
| `Enumerate` | server-stream | `GET /v1beta/fileobject/enumerate` | Recursive paginated list with metadata |
| `Stat` | unary | `GET /v1beta/fileobject/stat` | Metadata + identity for an address |
| `Read` | server-stream | `GET /v1beta/fileobject/by-identity/{id}` | Read by identity; metadata frame then data chunks |
| `ReadFromAddress` | server-stream | `GET /v1beta/fileobject/by-address/{addr}` | Read by address (resolves to latest) |
| `FetchWriteTypeInfo` | unary | `POST /v1beta/fileobject/write-type-info` | Query preferred upload method for a size |
| `Write` | bidi-stream | `POST /v1beta/fileobject/write` | Upload — body / redirect / multipart response |
| `CompleteRedirectUpload` | unary | `POST /v1beta/fileobject/complete-redirect` | Finalize after direct-to-storage PUT |
| `UploadPart` | unary | `POST /v1beta/fileobject/upload-part` | Presigned URL for one multipart part |
| `CompleteMultipartUpload` | unary | `POST /v1beta/fileobject/complete-multipart` | Assemble + finalize multipart |
| `AbortMultipartUpload` | unary | `POST /v1beta/fileobject/abort-multipart` | Cancel in-progress multipart |
| `Delete` | unary | `DELETE /v1beta/fileobject/by-address/{addr}` | Remove latest version |

### 2.3 FileFolderService

Package: `nvidia.omniverse.storage.filefolder.v1beta`

| RPC | Streaming? | REST | Purpose |
|---|---|---|---|
| `List` | server-stream | `GET /v1beta/filefolder/list/{addr}` | Children (addresses only) |
| `ListStat` | server-stream | `GET /v1beta/filefolder/list-stat/{addr}` | Children with `ResourceInfo` (zero-copy stat) |
| `DeleteFolder` | unary | `DELETE /v1beta/filefolder/{addr}` | Remove an empty folder |

### 2.4 VersioningService

Package: `nvidia.omniverse.storage.versioning.v1beta`

| RPC | Streaming? | REST | Purpose |
|---|---|---|---|
| `EnumerateVersions` | server-stream | `GET /v1beta/versioning/enumerate/{addr}` | All historical versions with sorting_key |

### 2.5 Key message types

*TBD — field-level tables for: `ResourceIdentity`, `ResourceInfo`, `WriteParameters`, `WriteRedirectProperties`, `CreateMultipartUploadResponse`, `DownloadPreference`, `UploadPreference`, `VersionsOrder`, `FolderMode`, `OptimisticLockingSupport`, `ListEntry`.*

---

## 3. Notifications and Permissions APIs

These API snapshots are siblings of Storage API under
[`../apis/`](../apis/). They are mirrored release bundles and do not currently
share Storage API's conformance-test packaging in this repo.

| API | Proto | OpenAPI | Key service |
|---|---|---|---|
| Notifications Aggregation / Publisher | [`../apis/notifications-api/aggregation/protos/nvidia/omniverse/notifications/publisher/v1beta/event_publisher.proto`](../apis/notifications-api/aggregation/protos/nvidia/omniverse/notifications/publisher/v1beta/event_publisher.proto) | [`../apis/notifications-api/aggregation/openapi/v1beta/openapi.yaml`](../apis/notifications-api/aggregation/openapi/v1beta/openapi.yaml) | `EventPublishingService` |
| Notifications Consumer | [`../apis/notifications-api/consumer/protos/nvidia/omniverse/notifications/consumer/v1beta/event_consumer.proto`](../apis/notifications-api/consumer/protos/nvidia/omniverse/notifications/consumer/v1beta/event_consumer.proto) | [`../apis/notifications-api/consumer/openapi/v1beta/openapi.yaml`](../apis/notifications-api/consumer/openapi/v1beta/openapi.yaml) | `EventConsumerService` |
| Permissions | [`../apis/permissions-api/protos/nvidia/omniverse/permission/v1beta/permission_service.proto`](../apis/permissions-api/protos/nvidia/omniverse/permission/v1beta/permission_service.proto) | [`../apis/permissions-api/openapi/permissions/v1beta/openapi.json`](../apis/permissions-api/openapi/permissions/v1beta/openapi.json) | `PermissionService` |

### 3.1 Notifications Aggregation / Publisher

Package: `nvidia.omniverse.notifications.publisher.v1beta`

| RPC | REST | Purpose |
|---|---|---|
| `PublishEvent` | `POST /api/v1beta/events` | Publish a single event |
| `BatchPublishEvents` | `POST /api/v1beta/events/batch` | Publish multiple events |
| Health | `GET /api/v1beta/health` | Service health check |

### 3.2 Notifications Consumer

Package: `nvidia.omniverse.notifications.consumer.v1beta`

| RPC | REST | Purpose |
|---|---|---|
| `ConsumeDurableEvents` | `GET /api/v1beta/events/stream-durable` | Consume events through a durable queue |
| `ConsumeNonDurableEvents` | `GET /api/v1beta/events/stream` | Consume transient event streams |
| `CreateDurableQueue` | `POST /api/v1beta/queues/durable` | Create a durable queue |
| `DeleteDurableQueue` | `DELETE /api/v1beta/queues/durable/{queue}` | Delete a durable queue |
| `UpdateDurableQueue` | `PUT /api/v1beta/queues/durable/{queue}` | Update durable queue configuration |
| Metrics | `GET /api/v1beta/metrics/channel-pool` | Channel-pool metrics |
| Health | `GET /api/v1beta/health` | Service health check |

The Metadata API's `v1alpha` is the only one with proto available today; it
ships inside the vendored Storage API contract under
`ovstorage-services/apis/storage-api/proto/nvidia/omniverse/storage/metadata/v1alpha/`.

### 3.3 Permissions

Package: `nvidia.omniverse.permission.v1beta`

| RPC | REST | Purpose |
|---|---|---|
| `CheckPermission` | `POST /v1beta/authorization/` | Check one principal/action/resource authorization decision |
| `CheckPermissionBatch` | `POST /v1beta/authorization/batch/` | Check multiple authorization decisions |
| Health | `GET /health` | Service health check |

See [`../apis/README.md`](../apis/README.md) for the current local API map.

---

## 4. Error code catalog

| Condition | gRPC | HTTP | Notes |
|---|---|---|---|
| Missing / invalid token | `UNAUTHENTICATED` | 401 | Re-auth or refresh |
| Valid token, insufficient scope | `PERMISSION_DENIED` | 403 | Principal denied by permission service |
| Resource not found | `NOT_FOUND` | 404 | |
| Malformed request | `INVALID_ARGUMENT` | 400 | Include actionable field-level detail |
| Optimistic-lock mismatch | `FAILED_PRECONDITION` | 412 | `previous_version` stale |
| Rate limit | `RESOURCE_EXHAUSTED` | 429 | Honor `Retry-After` |
| Unsupported operation | `UNIMPLEMENTED` | 501 | **Conformant response for partial impl** |
| Server error | `INTERNAL` | 500 | Log + trace id |

Conformance tests verify these mappings on both transports.

---

## See also

- [`backend-interface.md`](backend-interface.md) — Python interface that maps to these RPCs
- [`service-implementation.md`](service-implementation.md) — production service skeleton per language
- [`conformance-testing.md`](conformance-testing.md) — validation
- [`../apis/storage-api/proto/`](../apis/storage-api/proto/) — authoritative gRPC specs
- [`../apis/storage-api/openapi/`](../apis/storage-api/openapi/) — authoritative REST specs
