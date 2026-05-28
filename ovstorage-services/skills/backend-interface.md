---
name: ovstorage-services/backend-interface
description: Complete reference for StorageBackendInterface — all ~40 methods, data classes, folder modes, exceptions
type: skill
---

# Skill: ovstorage-services/backend-interface

> **Staging status:** Structured reference outline. Exact method signatures and per-method semantics will be filled in from `storage_backend_interface.py` and the existing `AGENTS.md` Path A content.

Complete reference for the Python `StorageBackendInterface`. ~40 methods across
8 categories. Load this skill when you need to implement a service-side Storage
API backend method and want authoritative semantics.

The authoritative interface source is the vendored reference implementation at
[`../apis/storage-api/filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py`](../apis/storage-api/filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py).
Treat this skill as service-side API guidance, not as client-library plugin
guidance.

For a 15-minute on-ramp, load [`service-quick-start.md`](service-quick-start.md). This skill is reference material — not a tutorial.

---

## 1. Method categories

| Category | Methods | Required for conformance |
|---|---|---|
| Configuration | 1 (`base_uri`) | Yes |
| Address handling | 6 | Yes |
| File existence / type | 3 | Yes (for most tests) |
| File operations | 10 | Yes (write/read subset) |
| Folder operations | 5 | Yes for folder tests |
| Versioning | 1 (`enumerate_versions`) | Only for versioning-suite |
| Metadata (v1alpha) | 3 | Only if implementing MetadataService |
| Upload support | 6 | Only if implementing redirect / multipart |

*TBD — per-method table with: signature, return type, raises, notes. Authoritative source is the vendored reference implementation at [`../apis/storage-api/filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py`](../apis/storage-api/filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py). For a hand-written walkthrough, see [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) §Path A.*

---

## 2. Key data classes

```python
Metadata(data_object_size: int, last_modified_timestamp: datetime)
VersionInfo(resource_identity: str, metadata: Metadata, sorting_key: Optional[str], resource_address: Optional[str])
ListEntry(resource_address: str, metadata: Optional[Metadata], resource_identity: Optional[str])
OptimisticLockingSupport(write: bool, delete: bool, copy: bool, move: bool)
```

*TBD — fully documented, with which methods return / consume each.*

---

## 3. Folder mode enum

Backends declare how they handle folders:

| Mode | Behavior | Typical backend |
|---|---|---|
| `NATIVE` | Real filesystem directories. Empty folders persist. | Local FS |
| `NO_EMPTY` | S3-style. Folders are implicit in key prefixes, disappear when empty. | S3, Azure Blob |
| `HYBRID` | Placeholder files simulate explicit empty folders. | S3 with sentinel objects |

The conformance tests check `folder_mode` first and skip folder scenarios that don't apply.

---

## 4. Exceptions

| Exception | Raised when | Maps to |
|---|---|---|
| `EtagMismatchError(key, expected_etag, actual_etag)` | Metadata update fails optimistic check | HTTP 412 / gRPC FAILED_PRECONDITION |
| `MetadataKeyNotFoundError(key)` | Get/delete on missing metadata key | HTTP 404 / gRPC NOT_FOUND |

*TBD — expand to include the full list of exceptions the interface defines and their gRPC/REST mappings.*

---

## 5. Implementing optimistic concurrency

*TBD — detailed section covering:*

- How `previous_version` flows from RPC to backend
- Per-backend semantics (S3 conditional PUT with `If-Match`, Azure Blob `If-Match` etag)
- What to return on mismatch
- Declaration via `get_optimistic_locking_support()`
- How to partially support OCC (e.g., writes but not deletes)

---

## 6. Implementing redirect uploads

*TBD — flow:*

- `supports_redirect_upload() -> True`
- `construct_redirect_url(resource_address, host, port)` returns a pre-signed URL
- The reference service layer calls this during `FetchWriteTypeInfo` when size is in the redirect range
- The client PUTs to the URL, then calls `CompleteRedirectUpload` — backend verifies and records

---

## 7. Implementing multipart uploads

*TBD — correct method names (do NOT trust older PROMPTS.md examples):*

- `supports_multipart_upload() -> True`
- `encode_upload_id(...)` / `decode_upload_id(...)` — opaque session token encoding
- `construct_redirect_url(...)` for each part URL (same function, with part-number context)
- The reference service orchestrates `CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload` / `AbortMultipartUpload`

**Known issue:** older `PROMPTS.md` referenced method names `create_upload_session` / `get_upload_part_path`. Those are **not** the actual interface. Use `encode_upload_id` / `decode_upload_id`.

---

## 8. Metadata service (v1alpha)

*TBD — 3 methods: `get_metadata`, `update_metadata`, `delete_metadata`. ETag-based OCC. Returns `Dict[key, {value, etag}]`.*

---

## 9. Testing your implementation

Run the full suite: `./run_tests.sh`. See [`conformance-testing.md`](conformance-testing.md) for invocation, incremental order, and failure interpretation.

---

## See also

- [`service-quick-start.md`](service-quick-start.md) — minimum 10 methods to pass first test
- [`conformance-testing.md`](conformance-testing.md) — run + interpret the full suite
- [`api-reference.md`](api-reference.md) — how interface methods map to RPCs
- [`../apis/storage-api/filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py`](../apis/storage-api/filesystem_example/src/local_filesystem_service/backends/storage_backend_interface.py) — source of truth
- [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) — vendored agent guide covering same material with worked examples
- [`../apis/storage-api/PROMPTS.md`](../apis/storage-api/PROMPTS.md) — ready-to-paste prompts for implementing individual methods
