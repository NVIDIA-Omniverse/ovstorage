---
name: ovstorage-services/conformance-testing
description: Run the storage-api spec conformance suite against your backend; interpret results; debug common failures
type: skill
---

# Skill: ovstorage-services/conformance-testing

Verify that your service implements the Storage API correctly. The suite is a Python `pytest-bdd` package that runs 24 Gherkin feature files against a live endpoint and tells you whether the behavior matches the contract.

> **This skill supersedes earlier drafts that referenced an `ovstorage-conformance` CLI.** There is no such CLI. The direct entrypoint is `run-conformance-tests` from the conformance package; the release bundle also provides a root [`../apis/storage-api/run_tests.sh`](../apis/storage-api/run_tests.sh) wrapper that can start the reference filesystem service and then run the suite.

## When to use this skill

Load this skill if you need to:
- Run the conformance suite against your service for the first time
- Debug a specific failure
- Set up CI gating on the exit code
- Understand what "passing" means (hint: correctly returning `UNIMPLEMENTED` for operations you don't support **is** passing)

## 1. Install

From the mirrored Storage API release snapshot:

```sh
cd ovstorage-services/apis/storage-api
python -m venv .venv
source .venv/bin/activate
pip install -e filesystem_example
pip install -e conformance_tests
```

Python 3.10, 3.11, or 3.12.

## 2. Point it at your service

Environment variables (defaults match the reference `local-filesystem-service`):

| Variable | Default | Purpose |
|---|---|---|
| `TEST_STORAGE_API_REST_ENDPOINT` | `http://localhost:8011` | REST base URL (root, not a versioned path) |
| `TEST_STORAGE_API_GRPC_ENDPOINT` | `localhost:50051` | gRPC `host:port` |
| `TEST_STORAGE_API_RESOURCE_BASE` | `file-storage://fileservice` | Resource-address prefix your service accepts |
| `STORAGEAPI_TEST_HTTP_TIMEOUT` | `60` | Seconds |
| `TEST_INVALID_RESOURCE_ADDRESS` | `c:d:e:\0` | Known-invalid address used in negative tests |
| `TEST_INVALID_RESOURCE_IDENTITY` | `c:d:e:\0` | Known-invalid identity used in negative tests |

Optional OpenAPI schema-comparison tests:

| Variable | Purpose |
|---|---|
| `OASDIFF_EXECUTABLE` | Path to the `oasdiff` binary |
| `TEST_EXACT_OPENAPI_MATCH` | Set `true` to enable strict-match tests |

## 3. Invoke

Direct pytest form:

```sh
run-conformance-tests
```

With keyword filtering (forwarded to pytest):

```sh
run-conformance-tests -k "stat" -vv
```

Wrapper script from the Storage API release bundle:

```sh
cd ovstorage-services/apis/storage-api
./run_tests.sh
./run_tests.sh -k "stat" --verbose
./run_tests.sh --test-only
```

The wrapper runs with 8-way parallelism (`-n 8`) via `pytest-xdist` by default,
starts the bundled `local-filesystem-service` unless `--test-only` is provided,
and forwards `-k`, `-m`, and verbosity options to pytest.

## 4. Test-data generator plugins

The runner needs a plugin that creates pre-existing objects for tests to read, delete, etc. Two plugins ship:

| Plugin (pass as `PYTEST_PLUGINS`) | Uses | Coverage implications |
|---|---|---|
| `conformance_tests.example_fixtures.storageapi_testdata_generator` (default) | The Storage API itself to create fixtures | "Symmetry" bias: if write is buggy and read is buggy in the same way, tests still pass. Permission tests limited. |
| `conformance_tests.example_fixtures.boto3_testdata_generator` | `boto3` against an S3-compatible backend | Direct-to-S3 fixture creation → catches symmetry bugs + enables permission tests. AWS env vars required. |

For maximum confidence, run both — default for quick iteration, boto3 plugin for
full coverage. You can also subclass `AbstractTestDataGenerator` to write your
own for a non-S3 backend.

## 5. What "passing" means

Each scenario produces a pytest outcome. The spec-conformance contract is:

| Outcome | Meaning | Conformance implication |
|---|---|---|
| `PASSED` | Service returned correct response per spec | Conformant |
| `SKIPPED` (via `@optional` or `UNIMPLEMENTED`) | Operation not supported; server returned `UNIMPLEMENTED` exactly as spec defines | Conformant — partial support is allowed |
| `FAILED` | Wrong status, malformed response, silently dropped request, or ignored call | Non-conformant |

Exit code is the standard pytest code: `0` = green, nonzero = one or more FAILs or collection errors.

Partial implementations are conformant only if unimplemented operations explicitly return `UNIMPLEMENTED` (gRPC) / the REST equivalent. Silently accepting and dropping a request is a FAIL.

## 6. What's covered (24 feature files)

```
features/
├── capabilities/{v1alpha,v1beta}/listtopleveladdresses.feature
├── filefolder/
│   ├── v1alpha/{create_folder,delete_folder,list}.feature
│   └── v1beta/{delete_folder,list}.feature
├── fileobject/
│   ├── v1alpha/{copy,delete,enumerate,fetch_write_type_info,move,read,stat,write}.feature
│   └── v1beta/{delete,enumerate,fetch_write_type_info,read,stat,write}.feature
├── metadata/v1alpha/metadata.feature
└── versioning/{v1alpha,v1beta}/enumerate_versions.feature
```

`v1alpha` is the superset (includes deprecated / optional RPCs like `move` and `copy`). `v1beta` is the stable contract. Most production services only need to pass `v1beta`.

## 7. Incremental order (first-time developers)

Get these green in order — each unblocks the next. Use `-k` to slice:

```sh
run-conformance-tests -k capabilities
run-conformance-tests -k stat
run-conformance-tests -k write
run-conformance-tests -k read
run-conformance-tests -k enumerate
run-conformance-tests -k delete
run-conformance-tests -k "folder or list"
run-conformance-tests -k versioning
run-conformance-tests -k fetch_write_type_info
```

## 8. Failure catalog (common FAIL modes)

*TBD — populate after the first real run. Patterns seen elsewhere:*

### 8.1 Identity round-trip failures

Symptom: `stat(identity=id)` returns a different address than the one that produced `id`.
Cause: Your identity encoding is not reversible, or you URL-encode inside the encoded identity.

### 8.2 Streaming metadata ordering

Symptom: client decodes data chunks before metadata on gRPC `Read`.
Cause: `Read` sends data first, metadata second.
Fix: Metadata frame must be the first streamed message.

### 8.3 URL-encoding ambiguity (REST)

Symptom: reads succeed, writes fail on addresses containing `/` or `%`.
Cause: Double-encoding or non-encoding of path components.
Fix: Treat the address as a single opaque path segment and encode once.

### 8.4 Optimistic lock off-by-one

Symptom: write succeeds when `previous_version` is stale.
Cause: Version check compares wrong field, or tolerates near-matches.
Fix: Exact byte comparison on identity.

### 8.5 Empty folder semantics mismatch

Symptom: `list` on empty folder returns `NOT_FOUND` instead of empty result.
Cause: Backend declared `NATIVE` folder mode but doesn't persist empty folders.
Fix: Declare `NO_EMPTY` or `HYBRID` accurately in `Capabilities`.

## 9. CI integration

Standard pytest exit code. Integrate with any CI. The boto3 generator is preferred for CI because it catches symmetry bugs.

```yaml
- name: Spec conformance
  run: |
    cd ovstorage-services/apis/storage-api
    source .venv/bin/activate
    TEST_STORAGE_API_REST_ENDPOINT=${{ env.SERVICE_REST }} \
    TEST_STORAGE_API_GRPC_ENDPOINT=${{ env.SERVICE_GRPC }} \
    PYTEST_PLUGINS=conformance_tests.example_fixtures.boto3_testdata_generator \
    ./run_tests.sh --test-only
```

NVIDIA does not publish a mandated CI pipeline; integrators wire the suite into their own.

## 10. Other suites in the ovstorage product family

This skill is about **spec conformance**: "does my backend match the API
contract?" Deployment smoke tests and environment-specific runtime suites live
with the owning service/deployment repos, not in this repo.

See [`../docs/conformance.md`](../docs/conformance.md) for the current service
conformance guidance.

## See also

- [`../apis/storage-api/conformance_tests/README.md`](../apis/storage-api/conformance_tests/README.md) — conformance README (authoritative on install/config)
- [`backend-interface.md`](backend-interface.md) — method reference while fixing failures
- [`service-quick-start.md`](service-quick-start.md) — minimum methods to get your first PASS
- [`api-reference.md`](api-reference.md) — spec detail for interpreting test expectations
- [`../apis/storage-api/AGENTS.md`](../apis/storage-api/AGENTS.md) §Testing Your Implementation — vendored debugging loop
