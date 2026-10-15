# Verify Empirically

Use this entrypoint when a review asks for real execution evidence instead of
code inspection only.

Start with:

1. [`docs/local-verification.md`](../docs/local-verification.md)
2. [`docs/compatibility-matrix.md`](../docs/compatibility-matrix.md)
3. [`docs/test-strategy.md`](../docs/test-strategy.md)

Required principles:

- keep private artifact URLs, credentials, and local-only absolute paths out of
  committed files;
- distinguish default no-SDK checks from SDK-backed bridge checks;
- record whether a check used real OpenUSD, real ovstorage, loopback HTTP, or
  optional live public content;
- do not treat native `s3://` as release-tested for 0.1 unless the
  env-var-gated `live_s3_stage` smoke has passed against AWS S3;
- report MinIO, Cloudflare R2, Backblaze B2, and custom-endpoint runs as
  separate ovstorage-provider compatibility evidence, not as implied coverage
  of every S3-compatible deployment;
- record `live_write_stage` separately from public read evidence: it must use a
  credentialed writable route, complete a provider PUT, and reopen the stage;
- report env-gated CTest status `Skipped` as not run, never as passing live
  evidence;
- do not treat native `hf://` as release-tested unless `live_hf_stage` has
  passed against the pinned public repository revision; keep the logical
  resolver identifiers as `hf://` in the evidence;
- do not use empirical bridge checks to resolve the multi-init contract
  by observation alone; that behavior belongs in a targeted test.

Minimum review evidence:

```bash
cmake -S . -B build -DOVS_USD_RESOLVER_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

When the SDKs are available:

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081

cmake -S . -B build-openusd-ovstorage \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081 \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage-0.3-sdk
cmake --build build-openusd-ovstorage
ctest --test-dir build-openusd-ovstorage --output-on-failure
```

Before investigating a suspected setup problem, run the one-command
usable-bridge check from
[`docs/local-verification.md`](../docs/local-verification.md):

```bash
export OVSTORAGE_PLUGIN_DIR=/path/to/ovstorage/plugins
./build-openusd-ovstorage/ovstorage-usd-resolver doctor \
  --stack-config /path/to/ovstorage.toml \
  --json
```

Read the `ovstorage_stack_config` check to see whether the Stack
actually initializes. Any failure in `errors[]` carries a `category`
field (`resolver` / `configuration` / `plugin` / `route` / `backend`)
that tells you which layer to inspect without needing to parse the
message text.

The environment variable is unnecessary for a file-only graph. For remote
provider kinds it must name an explicitly trusted directory containing the
ovstorage plugin libraries used by the TOML.

If the concrete bridge fails with coroutine diagnostics from `ovstorage.hpp`,
use the documented toolchain for the artifact being qualified: GCC 13 on
Ubuntu 22.04 for the historical source baseline, or the optional local wheel
configuration documented in `docs/python-wheels.md` (Clang 18/GCC 11 header
configuration on Linux and MSVC on Windows). Use the
public ovstorage v0.3.0 C API and its matching released providers. For the
public S3 read fixture, explicitly choose anonymous or credentialed execution
as described in the local verification guide.
