# Test Resolver

Start with:

1. [`docs/test-strategy.md`](../docs/test-strategy.md)
2. [`docs/local-verification.md`](../docs/local-verification.md)
3. [`docs/cli-reference.md`](../docs/cli-reference.md)

Required tests should not need GPUs, private endpoints, deployed services, or
cloud credentials.

Priority coverage:

- identifier parsing and normalization;
- OpenUSD `plugInfo.json` metadata guardrails;
- storage bridge capabilities, error mapping, stat, read, range-read, and
  materialization behavior;
- bridge-provided `MaterializedAsset` / `LocalLeaseHandle` behavior: local
  path safety, lease lifetime governs on-disk lifetime, dropping the
  `MaterializedAsset` releases the bridge-owned file, move-only semantics
  hold, and there is no `release()` path-detach verb — see
  `tests/unit/materialized_asset_tests.cpp` for the shape;
- resolver-side no-cache assertions: `ResolverRuntime::materialize` calls
  go through the bridge every time (no resolver-owned byte cache short-circuits
  a repeat open of the same identifier). Separately test the opt-in,
  metadata-only Resolve-existence cache for status classification, TTLs,
  bounded eviction, concurrent coalescing, per-runtime isolation, provider
  outer keys, and successful-write invalidation;
- resolver option defaults, validation, context-local scheme gates across
  resolve/open/stat/write (including no bridge call when disabled), bridge
  factory behavior, isolation-key label plumbing (host-facing label, never a
  cache partition selector), and trace sink behavior;
- remote relative joins;
- SDF format arguments;
- package and USDZ identifiers, including an absolute dependency that leaves a
  package through a second advertised scheme;
- MDL module names and remote MDL file paths;
- local file fallback without ovstorage;
- resolver registration and coexistence with the default filesystem resolver
  and legacy Omni USD resolver scheme ownership;
- fake ovstorage bridge reads, stats, errors, and ABI mismatch;
- direct-LayerHandle versus concrete-bridge canonical routing parity and
  authoritative per-address capability lookup;
- producer-level USDC `SdfLayer::Save` Update behavior and
  `UsdStage::Export` Replace behavior, including untouched-byte preservation
  and conditional-write conflict handling;
- writable staging ownership: private-directory permissions, exclusive target
  creation, suffix preservation, abandonment cleanup, and removal of OpenUSD
  sibling files after a real rename failure;
- optional real ovstorage `file://` bridge smoke with `OVS_OVSTORAGE_SDK_ROOT`;
- optional combined OpenUSD plus real ovstorage smoke when both SDKs are
  available (strict two-root loopback HTTP composition with exact scene
  signature and a missing-route negative control);
- deterministic Hugging Face StackConfig construction and native `hf://`
  route ownership with no network call when the ovstorage plugin artifacts are
  available;
- deterministic native-S3-plus-HTTPS host graph construction, including the
  core router, HTTP, and S3 plugin closure retained beyond registry teardown;
- strict stage acceptance for every deterministic stage smoke: exact prim,
  used-layer, and successful-open sets plus zero failed traces and zero
  composition errors; live variants use configurable minimum signatures;
- two-runtime live composition with an explicit stage context for each runtime,
  in addition to binder-scoped trace isolation;
- CLI `doctor` setup JSON in all builds, plus loopback HTTP URI probe success
  through the real ovstorage bridge when the ovstorage SDK is available;
- CLI `materialize` success through the real ovstorage HTTP backend when
  the ovstorage SDK is available, plus a clear unavailable diagnostic
  otherwise;
- diagnostic CLI JSON and exact exit/code/category tuples, including the
  no-SDK default-scheme and non-default-scheme matrix legs plus the SDK-on
  claimed-but-unrouted doctor probe and successful trace envelope;
- credential redaction at the trace-callback boundary and in passive CLI text
  and JSON, using fake userinfo, generic and signed-URL-shaped query values,
  fragments, percent escapes, packages, SDF arguments, and provider messages.

Optional live smokes must be clearly marked as optional and manually triggered.

No-SDK CI runs both default and az-only schemes on Linux x86_64/aarch64,
Windows x86_64 and macOS arm64. On Windows, run the commands below from an
MSVC developer environment and add `-G Ninja -DCMAKE_BUILD_TYPE=Release` to
configuration. No-SDK success does not qualify the SDK-backed plugin or wheels.

Current local test command:

```bash
cmake -S . -B build -DOVS_USD_RESOLVER_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Optional real ovstorage bridge command (ovstorage 0.3.x required, compiler
floor GCC 13+ / Clang 17+ / MSVC 19.40+):

Those are configure-time acceptance floors. The 0.1 qualified full-stack
baseline is GCC 13 on Ubuntu 22.04 Linux x86_64.

```bash
CXX=g++-13 CC=gcc-13 cmake -S . -B build-ovstorage \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage/main-checkout
cmake --build build-ovstorage
ctest --test-dir build-ovstorage --output-on-failure
```

Optional combined OpenUSD plus ovstorage command:

```bash
python3 tools/dependencies/acquire_openusd_sdk.py \
  --output .deps/openusd/25.11.kit.4-gl.21081

CXX=g++-13 CC=gcc-13 cmake -S . -B build-openusd-ovstorage \
  -DOVS_USD_RESOLVER_BUILD_OPENUSD_PLUGIN=ON \
  -DOVS_OVSTORAGE_REQUIRED=ON \
  -DOVS_USD_SDK_ROOT=.deps/openusd/25.11.kit.4-gl.21081 \
  -DOVS_OVSTORAGE_SDK_ROOT=/path/to/ovstorage/main-checkout
cmake --build build-openusd-ovstorage
ctest --test-dir build-openusd-ovstorage --output-on-failure
```

Optional live/public HTTP stage command:

```bash
OVS_USD_RESOLVER_LIVE_HTTP_STAGE_URL=https://bucket.s3.region.amazonaws.com/path/root.usd \
ctest --test-dir build-openusd-ovstorage -R live_http_stage --output-on-failure
```

Leave the variable unset for normal deterministic checks; the test is skipped
by CTest when no live URL is configured.

Live scene smokes require complete composition: no composition errors, no
failed resolver traces, and configurable minimum prim/layer/open counts. Use
semicolon-separated `..._REQUIRED_PRIMS` for stable scene landmarks. HTTP can
add route spellings with `OVS_USD_RESOLVER_LIVE_HTTP_ROOTS`; native S3 can add
mixed HTTPS dependency roots with `OVS_USD_RESOLVER_LIVE_S3_HTTP_ROOTS`.
Credentialed S3 checks must attach credentials to the connection request;
setting a profile as ordinary layer config is not authentication. Treat CTest
status `Skipped` for an unset live URL as unavailable evidence, not a pass.
The 0.1 release qualification uses AWS S3. A run against MinIO, Cloudflare R2,
Backblaze B2, or a custom endpoint is optional provider-compatibility evidence
and does not broaden the release claim unless its scope and results are
recorded explicitly.

Optional pinned Hugging Face stage command:

```bash
OVS_USD_RESOLVER_RUN_LIVE_HF=1 \
ctest --test-dir build-openusd-ovstorage -R live_hf_stage --output-on-failure
```

The repository, immutable revision, expected composed layers, and minimum
scene signature are fixed in `tests/openusd/support/huggingface_fixture.hpp`.
Do not replace this with an `hf://` to HTTP rewrite or make the test depend on
renderer-side MDL/texture loading.

Windows SDK-backed tests require CMake 3.22+ to prepend the Kit DLL directories
to the child-process search path. Use Ninja with a Release MSVC environment.
SDK acquisition tests (no network):

```bash
python3 -m unittest discover -s tools/dependencies/tests -v
```

`sdk-acquisition.yml` also extracts and verifies the pinned package on Linux
x86_64, Linux aarch64 and Windows x86_64. This does not qualify a plugin build.

Optional local Python package validation builds `ovstorage_usd_resolver_python_test_host` with
`OVS_USD_RESOLVER_BUILD_PYTHON_BOOTSTRAP=ON`. Install the wheel in a fresh Python
environment, then run `tests/python/test_installed.py` with `--probe`, `--usd-sdk`
and `--provider-dir`. The test host links only USD. Document when `--no-deps`
and provisional source-built providers were used instead of released ovstorage.
