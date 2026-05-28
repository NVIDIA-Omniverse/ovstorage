---
name: ovstorage-services/service-quick-start
description: Build a Python storage backend plugin in 15 minutes - template, register, run first conformance tests
type: skill
---

# Skill: ovstorage-services/service-quick-start

> **Staging status:** Structured outline. Inline code samples and the minimum-10-methods walkthrough will be filled in by the next authoring pass. Skeletons below describe intent.

Path A (Python plugin): subclass `StorageBackendInterface`, study the
reference gRPC/REST service layers, pass your first conformance test in ~15
minutes.

## When to use this skill

Use this skill if you want the **fastest on-ramp** to a working ovstorage backend. It is narrower and more opinionated than [`backend-interface.md`](backend-interface.md) — it covers the 10 methods you must implement to see a first test pass, and defers the rest.

If you need a non-Python production service, load [`service-implementation.md`](service-implementation.md). If you need the complete method reference, load [`backend-interface.md`](backend-interface.md).

---

## 1. Prerequisites

- Python 3.10+
- Access to the reference Python implementation at [`../apis/storage-api/filesystem_example/`](../apis/storage-api/filesystem_example/) - this is the canonical reference; subclass its `StorageBackendInterface`
- Upstream agent guidance: [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) §Path A covers the same ground with an annotated example, load it if this skill is not enough
- `uv` or `pip` for dependency install

---

## 2. Start From The Licensed Reference Boundary

Use the reference implementation to understand the service boundary and
conformance expectations. Do not copy files out of the vendored reference into
another project unless the applicable license/product terms for that subtree
allow your use case. For internal ovstorage development, keep derived service
experiments in an approved service/deployment repo and preserve the in-subtree
license files.

---

## 3. Implement the minimum 10 methods

To pass the `capabilities` and `stat` conformance suites (the first two in the incremental test order), implement:

1. `base_uri` (property)
2. `is_address_valid(resource_address)`
3. `create_identity_from_resource_address(resource_address)`
4. `address_from_identity(resource_identity)`
5. `exists(resource_address)`
6. `is_file(resource_address)`
7. `is_dir(resource_address)`
8. `stat(resource_address)` → `VersionInfo`
9. `stat_identity(resource_identity)` → `VersionInfo`
10. `get_optimistic_locking_support()` → `OptimisticLockingSupport(write=False, delete=False, copy=False, move=False)` (return the all-False variant to start)

*TBD — concrete code block for each, based on a simple in-memory / tmpfs-backed example.*

---

## 4. Register your backend

*TBD — exact config change and CLI invocation to register. Expected: edit a backends registry entry, point it at your class path.*

---

## 5. Run the first test slice

```sh
# from ovstorage-services/apis/storage-api
./run_tests.sh -k "capabilities or stat"
```

Expected: `PASSED` for capabilities scenarios and at least stat-on-existing-file. If you see `PASSED`, your plumbing is working.

---

## 6. Expand incrementally

Add methods in this order to light up more tests:

1. `write_version` + `read_from_address` + `read_from_identity` → write/read scenarios pass
2. `list` + `list_stat` + `enumerate` → folder scenarios pass
3. `remove_by_address` + `remove_empty_folder` → delete scenarios pass
4. `enumerate_versions` → versioning scenarios pass
5. Multipart / redirect support → only if your backend exposes presigned URLs

Full walkthrough lives in [`backend-interface.md`](backend-interface.md) §Method categories.

---

## 7. Common first-run gotchas

- **Port conflict.** The reference service starts on `:8011` (gRPC) + `:8012` (REST). Check nothing else is bound.
- **Identity round-trip.** `create_identity_from_resource_address(addr)` then `address_from_identity(id)` must return the original address. Failures here break almost every subsequent test.
- **Timestamps.** `last_modified_timestamp` must be a `datetime` with tzinfo. Naive datetimes fail serialization silently.

*TBD — expand to ~5–8 common gotchas based on conformance-test-review findings.*

---

## See also

- [`backend-interface.md`](backend-interface.md) — complete method reference once you outgrow this skill
- [`conformance-testing.md`](conformance-testing.md) — running and interpreting the full conformance suite
- [`api-reference.md`](api-reference.md) — spec-level detail on RPCs and messages
- [`../apis/storage-api/filesystem_example/`](../apis/storage-api/filesystem_example/) — reference backend and conformance semantics source; copy only when the subtree license permits it
- [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) — vendored step-by-step guide (Path A)
