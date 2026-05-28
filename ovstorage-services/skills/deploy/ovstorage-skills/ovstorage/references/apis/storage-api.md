# Storage API Reference

> **Deployment info** (Helm charts, values files, adapter setup) is in `references/deployment/`.
> This file covers the **API specification** -- concepts, services, and usage patterns for
> developers interacting with or implementing a Storage Service adapter.

---

## Overview

The Storage API is a gRPC and REST/OpenAPI specification for the data access layer within the
Omniverse platform. A Storage Service adapter implements this API on top of any backend storage
system (S3, Azure Blob, a local filesystem, a custom database, etc.).

**Two interface styles (both exposed by any conforming adapter):**
- **gRPC** -- Protocol Buffer-based, high-performance, strongly-typed. Preferred for production microservices.
- **REST/OpenAPI** -- HTTP/JSON-based. More accessible for web clients and debugging.

**API prefix and port by adapter type:**

| Adapter | REST prefix | gRPC port | REST port |
|---------|-------------|-----------|-----------|
| Python filesystem example | `/v1beta/` | 50051 | 8011 |
| NVIDIA pre-built adapter (S3/Azure) | `/v1alpha/` | 8011 | 8012 |

> The NVIDIA pre-built adapter exposes both `/v1beta/` and `/v1alpha/` REST prefixes.
> The `/v1alpha/` prefix includes additional extension endpoints (Copy, Move, etc.).

---

## Core Concepts

### Resource Address

A **Resource Address** is a string that acts as a mutable locator for objects within a storage
system -- analogous to a file path or URL.

**Key characteristics:**
- Storage-specific format. The format depends on the adapter:
  - **NVIDIA pre-built adapter (S3)**: `https://bucket.s3.region.amazonaws.com/path/to/file.ext`
    (uses the bucket's virtual-hosted S3 URL -- confirm via `GET /v1alpha/capabilities/routes`)
  - **NVIDIA pre-built adapter (Azure)**: `https://account.blob.core.windows.net/container/path/to/file.ext`
  - Local filesystem (Python example): `file-storage://fileservice/path/to/file.txt`
  - Custom DB: `my_database://17A56A6F8734E`
  - Versioned (S3): `https://bucket.s3.region.amazonaws.com/path/to/file.ext?etag=a64be1231acd`
  > **Important:** The NVIDIA adapter does NOT use `s3://` or `azureblob://` URI schemes.
  > Use the HTTPS URL format matching the patterns returned by `GET /v1alpha/capabilities/routes`.
- Content at a given address **can change** over time (same address may return different data).
- For file-system-like storage, follows RFC 3986 URI syntax.
- A storage service must be able to identify its own Resource Addresses (required for multi-service routing).

**Used in these API functions:**

| Function | Role |
|----------|------|
| `Enumerate` | List contents of a storage location |
| `Stat` | Return info about the object at the address |
| `ReadFromAddress` | Read binary data at the address (current content) |
| `Write` | Specify where data should be written |
| `Delete` | Remove data at the address (including prior versions) |
| `Copy` | Specify the destination of a copy (v1alpha only) |

---

### Resource Identity

A **Resource Identity** is an opaque string that identifies **a specific, immutable instance of a
data object** (a particular version). Unlike a Resource Address, which points to a location, a
Resource Identity points to exact content.

**Key characteristics:**
- Opaque and storage-service specific -- treat as an opaque string, do not parse.
- **Immutable content**: always retrieves the same content when passed to `Read` (if still available).
- Durable: survives service redeployments. Lifetime tied to the data, not the service.
- Shareable between users (subject to permissions).
- Not a unique key: different identities may rarely resolve to the same object.
- Suitable as a cache key; not reliable for equality comparison.

**Used in these API functions:**

| Function | Role |
|----------|------|
| `Stat` | Returns the Resource Identity of the current object at a given address |
| `EnumerateVersions` | Returns list of Resource Identities for all versions at an address |
| `Write` | Returns the Resource Identity of the data just written |
| `Read` | Used to retrieve a specific, immutable data object instance |
| `Copy` (as source) | Ensures a specific version is copied (v1alpha only) |

---

### Summary

| Concept | Points to | Content | Used for |
|---------|-----------|---------|----------|
| **Resource Address** | A storage location | Mutable (can change over time) | Enumerate, Stat, Write, Delete, Copy destination |
| **Resource Identity** | A specific data object instance | Immutable (always same content) | Read, EnumerateVersions, Copy source |

---

## v1beta gRPC Services

All v1beta services are exposed by any conforming adapter. Proto package prefix: `nvidia.omniverse.storage.*.v1beta`.

### CapabilitiesService

Reflects which services are implemented by this server.

| RPC | Request | Response | Streaming | Description |
|-----|---------|----------|-----------|-------------|
| `ListServices` | `ListServicesRequest` | `ListServicesResponse` | Unary | Returns the list of service APIs implemented by this server |
| `ListTopLevelAddresses` | `ListTopLevelAddressesRequest` | `ListTopLevelAddressesResponse` | Unary | Returns top-level resource addresses suited for browsing this storage service |

### FileObjectService

Core data-object operations: read, write, stat, delete, enumerate. Supports direct streaming and redirect-based upload/download flows.

| RPC | Request | Response | Streaming | Description |
|-----|---------|----------|-----------|-------------|
| `Stat` | `StatRequest` | `StatResponse` | Unary | Check existence and get ResourceIdentity + Metadata for a resource address |
| `Read` | `ReadRequest` | `ReadResponse` | Server-streaming | Read binary data by ResourceIdentity (immutable); returns metadata then chunks or redirect |
| `ReadFromAddress` | `ReadFromAddressRequest` | `ReadFromAddressResponse` | Server-streaming | Read binary data at a resource address (current version); returns ResourceInfo then chunks or redirect |
| `Write` | `WriteRequest` | `WriteResponse` | Bidirectional-streaming | Write data to a resource address; client sends params then chunks; server may accept chunks, redirect, or initiate multipart |
| `Enumerate` | `EnumerateRequest` | `EnumerateResponse` | Server-streaming | List child objects at a resource address with metadata |
| `Delete` | `DeleteRequest` | `DeleteResponse` | Unary | Delete the object (and all versions) at a resource address; supports optimistic locking via `previous_version` |
| `FetchWriteTypeInfo` | `FetchWriteTypeInfoRequest` | `FetchWriteTypeInfoResponse` | Unary | Query recommended upload method (body/redirect/multipart) for a given destination address and size range |
| `CompleteRedirectUpload` | `CompleteRedirectUploadRequest` | `CompleteRedirectUploadResponse` | Unary | After a redirect-based upload, retrieve the ResourceInfo for the uploaded object |
| `UploadPart` | `UploadPartRequest` | `UploadPartResponse` | Unary | Get presigned URL(s) for uploading one or more parts of a multipart upload |
| `CompleteMultipartUpload` | `CompleteMultipartUploadRequest` | `CompleteMultipartUploadResponse` | Unary | Assemble previously uploaded parts into the final object; returns ResourceInfo |
| `AbortMultipartUpload` | `AbortMultipartUploadRequest` | `AbortMultipartUploadResponse` | Unary | Cancel an in-progress multipart upload and free storage for uploaded parts |

### FileFolderService

Folder-level operations: listing contents and deleting empty folders.

| RPC | Request | Response | Streaming | Description |
|-----|---------|----------|-----------|-------------|
| `List` | `ListRequest` | `ListResponse` | Server-streaming | List subfolder addresses and sub-resource addresses at a folder address |
| `ListStat` | `ListStatRequest` | `ListStatResponse` | Server-streaming | Like `List` but includes resource identities and metadata for each file entry |
| `DeleteFolder` | `DeleteFolderRequest` | `DeleteFolderResponse` | Unary | Delete a folder; must fail if the folder is not empty |

### VersioningService

Version enumeration for data objects.

| RPC | Request | Response | Streaming | Description |
|-----|---------|----------|-----------|-------------|
| `EnumerateVersions` | `EnumerateVersionsRequest` | `EnumerateVersionsResponse` | Server-streaming | List all versions of a data object at a resource address; returns VersionInfo items with ordering |

---

## REST Endpoints

All paths below are relative to the API version prefix (e.g., `/v1beta/`). Path parameters shown as `{param}` must be URL-encoded.

### Capabilities

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/capabilities/services` | List service APIs implemented by this server |
| `GET` | `/capabilities/top-level-addresses` | List top-level resource addresses for browsing |

### FileObject

| Method | Path | Description |
|--------|------|-------------|
| `HEAD` | `/fileobject/by-address/{resource_address}` | Stat -- get metadata and resource identity (returned in response headers) |
| `GET` | `/fileobject/by-address/{resource_address}` | ReadFromAddress -- download data at address (200 body or 300 redirect) |
| `PUT` | `/fileobject/by-address/{resource_address}` | Write -- upload data to address (201 success or 300 redirect/multipart) |
| `DELETE` | `/fileobject/by-address/{resource_address}` | Delete object and all versions at address |
| `POST` | `/fileobject/by-address/{resource_address}/redirect/complete` | CompleteRedirectUpload -- get ResourceInfo after redirect upload |
| `GET` | `/fileobject/by-identity/{resource_identity}` | Read -- download immutable data by identity (200 body or 300 redirect) |
| `GET` | `/fileobject/data-objects/{resource_address}` | Enumerate -- list child objects at address (paginated) |
| `GET` | `/fileobject/upload-options/by-address/{resource_address}` | FetchWriteTypeInfo -- get recommended upload method for size ranges |
| `POST` | `/fileobject/by-address/{resource_address}/multipart/prepare` | UploadPart -- get presigned URL(s) for multipart upload parts |
| `POST` | `/fileobject/by-address/{resource_address}/multipart/complete` | CompleteMultipartUpload -- assemble parts into final object |
| `POST` | `/fileobject/by-address/{resource_address}/multipart/abort` | AbortMultipartUpload -- cancel multipart upload |

### FileFolder

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/filefolder/list/{folder_address}` | List -- subfolder addresses and sub-resource addresses (paginated) |
| `DELETE` | `/filefolder/list/{folder_address}` | DeleteFolder -- delete folder (must be empty) |
| `GET` | `/filefolder/liststat/{folder_address}` | ListStat -- list with resource identities and metadata (paginated) |

### Versioning

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/versioning/{resource_address}/versions` | EnumerateVersions -- list all versions at address (paginated) |

---

## Key Message Types

Important protobuf messages from the `fileobject.v1beta` and related packages:

| Message | Package | Description |
|---------|---------|-------------|
| `Metadata` | `fileobject.v1beta` | Object metadata: `data_object_size` (uint64), optional `last_modified_timestamp` (UTC) |
| `ResourceInfo` | `fileobject.v1beta` | Combines `ResourceIdentity` + `Metadata` for a data object |
| `ResourceIdentity` | `fileobject.v1beta` | Opaque string (`encoded_identity`) identifying a specific immutable object version |
| `Chunk` | `fileobject.v1beta` | Binary data segment (`bytes chunk`) used in streaming read/write |
| `Redirect` | `fileobject.v1beta` | Instructs client to fetch/upload via `redirect_target_url` with optional `additional_headers` |
| `AddressInfo` | `fileobject.v1beta` | Child-object entry from Enumerate: `resource_address` + `Metadata` |
| `WriteParameters` | `fileobject.v1beta` | First message in Write stream: `destination_resource_address`, optional `previous_version`, `data_object_size`, optional `upload_preference` |
| `WriteRedirectProperties` | `fileobject.v1beta` | Presigned URL details for redirect upload: URL, method, headers, `completion_header_names` |
| `CreateMultipartUploadResponse` | `fileobject.v1beta` | Multipart session info: `upload_id`, `first_part_write_redirect`, optional size/count constraints |
| `FolderAddress` | `filefolder.v1beta` | Folder URI (`string uri`), follows RFC 3986 |
| `ListItem` | `filefolder.v1beta` | Entry from ListStat: `resource_address` + optional `ResourceInfo` |
| `VersionInfo` | `versioning.v1beta` | Version entry: `ResourceInfo` + optional `sorting_key` |
| `VersionsOrder` | `versioning.v1beta` | Enum: `NEWEST_FIRST`, `OLDEST_FIRST`, `BY_KEY` |
| `ServiceEntry` | `capabilities.v1beta` | Service descriptor: `service_name` + `service_versions` list |
| `TopLevelAddressEntry` | `capabilities.v1beta` | Root namespace address (`top_level_address`) |

---

## v1alpha Preview (NVIDIA Adapter Extensions)

The following services are **only available on the NVIDIA pre-built adapter** and are exposed under the `v1alpha` API prefix. They are not part of the stable specification and custom adapters are not required to implement them.

| Service | RPC / Endpoint | Description |
|---------|----------------|-------------|
| `FileObjectService` | `Copy` | Copy a data object from one address to another |
| `FileObjectService` | `Move` | Move (rename) a data object |
| `FileFolderService` | `CreateFolder` | Create an empty folder at an address |
| `FileFolderService` | `GetFolderMode` | Query whether a folder address exists and its mode |
| `CapabilitiesService` | `ListRoutes` | List route patterns for multi-service deployments |
| `MetadataService` | (multiple RPCs) | Store/retrieve arbitrary metadata on addresses or identities |

---

## Client and Service Implementation Examples

### REST: Stat a file

```bash
# Python example adapter (port 8011)
curl -I "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt"
# Response headers include:
#   x-nvidia-omniverse-storage-metadata: {"data_object_size": 1234}
#   x-nvidia-omniverse-storage-resource-identity: <encoded_identity>
```

### REST: Read from address

```bash
curl "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt"
# Returns 200 with binary body, or 300 with redirect JSON
```

### REST: Write a file

```bash
curl -X PUT \
  "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Fnew-file.txt?data_object_size=11" \
  -H "Content-Type: application/octet-stream" \
  -d "hello world"
# Returns 201 with ResourceInfo JSON, or 300 with redirect/multipart info
```

### gRPC: Stat (Python)

```python
import grpc
from nvidia.omniverse.storage.fileobject.v1beta import fileobject_service_pb2 as svc
from nvidia.omniverse.storage.fileobject.v1beta import fileobject_service_pb2_grpc as stub

channel = grpc.insecure_channel("localhost:50051")
client = stub.FileObjectServiceStub(channel)
response = client.Stat(svc.StatRequest(resource_address="file-storage://fileservice/test.txt"))
print(response.resource_info.resource_identity.encoded_identity)
print(response.resource_info.metadata.data_object_size)
```

For full adapter implementation guidance, including how to build a custom storage adapter, see `references/development/custom-storage-adapter.md`.

---

## Conformance Testing

Any adapter implementation can be validated against the specification using the conformance test
suite included in the `storage-api` NGC resource (`nvidia/omniverse/storage-api`):

```bash
ngc registry resource download-version "nvidia/omniverse/storage-api:{version}"
cd storage-api-{version}/conformance_tests
python -m pytest --storage-service-url=http://localhost:8011
```

The suite uses Gherkin BDD format and covers both normal operation and edge cases / error conditions. For more details on running and interpreting conformance tests, see `references/development/custom-storage-adapter.md`.

---

## Health Check

Both gRPC and REST health endpoints are available on any conforming adapter:
- REST: `GET /health`
- gRPC: Standard gRPC health checking protocol

---

## Changelog

**v1.0.0-beta.2**
- Added Python filesystem reference implementation
- Added conformance test suite
- Added v1alpha preview channel:
  - `FileObjectService`: Copy, Move
  - `FileFolderService`: CreateFolder, GetFolderMode
  - `CapabilitiesService`: ListRoutes
  - `VersioningService`: versioned resource addresses (in addition to identities)
  - New `MetadataService`: arbitrary metadata on addresses/identities

**v1.0.0-beta.1**
- Initial closed availability release
