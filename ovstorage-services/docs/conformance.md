# API Conformance

API conformance answers whether a service implementation follows the API
contract. It is separate from library unit tests and separate from deployment
smoke tests.

Each API snapshot should keep its conformance suite under its own API folder:

```text
ovstorage-services/apis/<api-name>/conformance_tests/
```

The Storage API conformance suite currently lives at
[`../apis/storage-api/conformance_tests/`](../apis/storage-api/conformance_tests/).

## Storage API Quick Path

```sh
cd ovstorage-services/apis/storage-api
python -m venv .venv
source .venv/bin/activate
pip install -e filesystem_example
pip install -e conformance_tests
./run_tests.sh
```

Set the suite's `TEST_STORAGE_API_*` environment variables to point at the
service under test. Use `./run_tests.sh --test-only` when the service is already
running. See the Storage API conformance README for the authoritative variables
and invocation details.

## Related Material

- Conformance skill: [`../skills/conformance-testing.md`](../skills/conformance-testing.md)
- Storage API conformance README: [`../apis/storage-api/conformance_tests/README.md`](../apis/storage-api/conformance_tests/README.md)
