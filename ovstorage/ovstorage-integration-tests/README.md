<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# ovstorage-integration-tests

Application-level integration suite for the **shipped routed `Stack` API** —
exercised exactly as an application developer uses it.

There is one scenario contract. The harness constructs the object an app
constructs: one `Stack` with an explicit
`alias → redirect_follower → retry → router` chain, with one backend Layer per
available plugin kind under the router, then operates **by address**
(`file:///…`, `azure://…`, `s3://…`, `gs://…`, `hf://…`). The router picks the
backend Layer by URL prefix; redirect-following happens inside the chain.

Backend Layers are **`dlopen`'d at runtime** from the staged ABI-v2 plugin
directory, so the per-plugin `#[unsafe(no_mangle)]` FFI exports never collide
and one test binary drives every backend through the same plugin boundary an
application uses. The crate depends on host-side crates only — `ovstorage`,
plus `ovstorage-authz` for the attribution overlay — and never on a plugin
crate. A repository test run therefore has two load-bearing parts:
stage this checkout's plugin cdylibs, then point the harness at exactly that
staging directory and require the wrapper chain plus the backends intended for
that run.

## The composition is load-bearing, not boilerplate

`redirect_follower` is not optional. The azure and s3 backends answer *every*
`read` with `ReadResult::Redirect` (a SAS / presigned URL); only the follower
resolves it, so a chain without it cannot read a single cloud object. The
follower is also what gives cloud targets `materialize`, via its
staged-temp-file fallback — which is why `read_stream_and_materialize` passes
with no byte cache composed.

## Running

No test is `#[ignore]`d and nothing is `cfg`-gated. Every case is entered by
`cargo test`; the ones that cannot run skip *visibly* on stderr. The canonical
repository entry point is the Make target, because it establishes the staged
plugin and hermetic-guard contract around that Cargo invocation:

```sh
# Hermetic, credential-free. A normal local run requires only `file`.
make test-integration

# Live cloud. The target rejects an empty or file-only require list before it
# attempts credential setup.
OVSTORAGE_REQUIRE_LIVE_BACKENDS=azure,s3 make test-integration-live
```

To reproduce the full hermetic CI matrix locally, start the pinned fixtures and
require their emulator origins explicitly:

```sh
python tools/ovtasks/fake_gcs.py start
python tools/ovtasks/azurite.py start
OVSTORAGE_AZURITE_ENDPOINT=http://127.0.0.1:10000 \
OVSTORAGE_FAKE_GCS_ENDPOINT=http://127.0.0.1:4443 \
make INTEGRATION_HERMETIC_REQUIRE=file,azure,gcs test-integration

# Run the same matrix through the Python binding.
OVSTORAGE_AZURITE_ENDPOINT=http://127.0.0.1:10000 \
OVSTORAGE_FAKE_GCS_ENDPOINT=http://127.0.0.1:4443 \
make INTEGRATION_HERMETIC_REQUIRE=file,azure,gcs test-integration-python
```

The endpoint variables accept HTTP(S) loopback IPs only. They select published
emulator identities and never reuse ambient live-cloud credentials. Live
requests are resolved separately, so `OVSTORAGE_FORBID_LIVE_BACKENDS` still
rejects a real fixture and credential before any connection is attempted.
The pinned fake-GCS server covers JSON request composition, pagination,
redirects, ordinary reads/writes, copy/rename, range reads, streaming, and
user metadata carried on a write, read back by a full-metadata stat, or set by
a metadata patch. It
does not faithfully reproduce bucket IAM, conditional-write preconditions,
directory-marker stat behavior, or metadata-key removal; those four scenarios
remain explicit emulator skips and continue to run against live GCS.

Both targets build and stage the ABI-v2 backend plugins and C++ driver, set the
per-plugin overrides to this checkout's artifacts, require the staged plugin
set, and pass `--nocapture` so connect and skip lines remain visible. A bare
`cargo test -p ovstorage-integration-tests` does none of that setup: it uses
whatever is already present in the compiled-in or ambient plugin directory,
does not require a complete staged set, and does not apply the hermetic guard.
It is useful for focused harness debugging after setup, but it is not the
repository integration-test gate.

### The Python leg

The same scenario contract runs a second time through the Python bindings —
the same 23 scenarios over the same backends, so a regression that only breaks
the binding surface is caught rather than assumed absent. `make
test-integration-python` builds this checkout's extension with `maturin
develop` into `target/python-test-venv-<version>` and runs pytest against
`tests/python/`:

```sh
make test-integration-python
```

`tests/python.rs` is a libtest shim so a plain `cargo test` reports the Python
leg's status too. It only *runs* pytest when this checkout's `ovstorage` wheel
and pytest are importable; otherwise it skips visibly with the command to run.
A globally installed `ovstorage` wheel is deliberately ignored, so stale
binding coverage is never reported as this checkout's.

### The C++ leg

A third run of the same contract, through the shipped C++20 wrapper
(`ovstorage-c-source/include/ovstorage.hpp`), as a **Rust → C++ live handoff**:
`tests/cpp.rs` composes the same `app()` Stack the Rust leg drives, exports its
root with `ovstorage::export_handle`, and hands the handle to a `dlopen`'d
driver (`tests/cpp/cloud_driver.cpp`) that imports it with
`ovstorage_import_handle` and drives the scenario against the C++ RAII types.

The handoff is not an implementation detail — it is the only way this leg can
reach a cloud backend at all. The shipped pure-C runtime is file-backend-only
by design (no HTTP, no TLS, **no redirect follower**), while Azure and S3 answer
every read with a redirect. Importing the real Rust Stack, which has the
follower, is both what makes cloud reads work and what real C++ hosts do.

`make build-test-plugins` builds the driver from
`tests/cpp/CMakeLists.txt` — the full pure-C source set plus the C++ TU in one
standalone `.so`, never linked against `ovstorage-plugin`'s rlib (both export
`ovstorage_plugin_*`). It needs cmake ≥3.16 and a C++20 toolchain (GCC 13+,
Clang 17+); without either, staging says so loudly and every C++ case skips
visibly. `OVSTORAGE_REQUIRE_CPP20=1` or `OVSTORAGE_REQUIRE_TEST_PLUGINS=1`
turns that into a hard failure for a runner known to clear the floor.

Five scenarios have no C++ equivalent and are skipped with a stated reason
rather than quietly dropped:

| Scenario | Why the C++ leg skips it |
|---|---|
| `range_read` | the case is not yet rebuilt against `ovstorage.hpp`'s ranged `read_bytes(address, options)` overload, which `read_only_range_read` drives (issue #614) |
| `key_encoding` | the scenario asserts *address composition*; there is no C/C++ equivalent of `address::join_relative` |
| `write_stream` | the case is not yet rebuilt against the streaming-write entry point (issue #614) |
| `get_latest_version` | the case is not yet rebuilt against `ovstorage.hpp`'s `get_latest_version`, which `read_only_version_pinning` drives (issue #614) |
| `message_annotation` | the C ABI carries no per-operation message: `OvStorage_WriteOptions` has no message field and `OvStorage_UpdateMetadataOptions` has only set/remove, so the leg cannot ask a backend to stash the annotation |

`conditional_write`, `update_metadata` and `attribution_round_trip` run in
reduced form: `conditional_write` drives only its create-only half (the
etag-CAS half is not yet rebuilt against `WriteOptions::if_match_etag` — issue
#614); `OvStorage_UpdateMetadataOptions` has no `allow_rewrite_emulation` (so a
backend that can only emulate the patch — S3 — skips both metadata scenarios);
and the C ABI carries no request extensions, so `attribution_round_trip`
cannot present a principal to an attribution layer and instead pins the
portable half — the reserved key `ovstorage_modified_by` stored and read back
under its exact spelling.

The three `read_only_*` scenarios are implemented in full in the driver —
ranged reads through `ovstorage::ReadOptions`, versions through
`list_versions` / `get_latest_version` — with the same in-driver capability
gates as the other legs.

The suite is a plain workspace member, so `make test` runs its Rust and C++
legs as part of `cargo test --workspace`. That Make target first stages and
requires this checkout's plugin artifacts and pins the hermetic guards; it is
not equivalent to a bare `cargo test --workspace`. The Python libtest shim may
skip when the checkout's wheel and pytest are unavailable, so
`make test-integration-python` remains the Python integration gate.
`make test-integration-live` is the target that talks to real backends.
`make build-test-plugins` is the staging step; this crate's `build.rs` does
**not** shell out to cargo — it only records `target/test-plugins/` as the
compile-time default plugin directory.

## The guards that keep a green run honest

A runtime-skip model has several ways to lie, and each has a gate that
turns it into a hard failure during app construction (not an end-of-suite test,
whose execution order libtest does not guarantee):

| Variable | Meaning | Use |
|---|---|---|
| `OVSTORAGE_REQUIRE_HERMETIC_BACKENDS` | fail if a listed local/emulator target did **not** connect | hermetic CI — requires `file`, Azurite, and fake GCS rather than accepting skips |
| `OVSTORAGE_REQUIRE_LIVE_BACKENDS` | fail if a listed live target did **not** connect | live CI — stops vanished credentials from going vacuously green |
| `OVSTORAGE_FORBID_LIVE_BACKENDS` | fail if a listed live request resolves | hermetic runs — rejects real fixture credentials before any connection attempt |

Both take a comma-separated list of `backend` or `backend:access`:

```sh
# live job
OVSTORAGE_REQUIRE_LIVE_BACKENDS=azure,s3,azure:hns,s3:versioned \
  make test-integration-live

# full hermetic matrix after starting the two emulators
OVSTORAGE_REQUIRE_HERMETIC_BACKENDS=file,azure,gcs \
OVSTORAGE_FORBID_LIVE_BACKENDS=azure,s3,gcs \
OVSTORAGE_AZURITE_ENDPOINT=http://127.0.0.1:10000 \
OVSTORAGE_FAKE_GCS_ENDPOINT=http://127.0.0.1:4443 \
  cargo test -p ovstorage-integration-tests
```

`backend` alone means that backend's `default` target. `require` additionally
fails on any *recorded connect failure* for the named backend, so a target that
was configured but rejected the credentials is a failure rather than a skip.

`make test`, `make test-ci`, `make test-integration` and
`make test-integration-python` set the hermetic guards themselves. They require
`file` by default; set `INTEGRATION_HERMETIC_REQUIRE=file,azure,gcs` after
starting the emulators to reproduce CI. The live targets take their requirement
list from the caller and clear the hermetic guards.

`huggingface` is live-only: it has no emulator origin (its hermetic coverage
lives in the plugin's own loopback suites), so never name it in
`OVSTORAGE_REQUIRE_HERMETIC_BACKENDS` / `INTEGRATION_HERMETIC_REQUIRE` — the
requirement maps every non-`file` hermetic backend to an emulator origin and
fails as "not connected".

Both live Make targets require the list to contain at least one `azure`, `s3`,
`gcs`, or `huggingface` selector, optionally with `:default`, `:versioned`, or
`:hns`. They perform that intent check before sourcing a credential helper, so
a missing, empty, or file-only value cannot launch an unnecessary Vault login.
A huggingface-only run is anonymous and needs no credentials at all — when
every required selector is anonymous, the Make prelude skips the credential
mapper on its own, so the other clouds' fixtures are never exported into the
run. The harness remains responsible for validating every selector and for
proving each required target connected.

## Other knobs

- `OVSTORAGE_PLUGIN_DIR` — directory to `dlopen` plugins from. Overrides the
  compile-time default (`<workspace>/target/test-plugins`, written by
  `build.rs`). Honored by the host's `default_plugin_dir()` too.
- `OVSTORAGE_INTEGRATION_PLUGIN_DIR_OVERRIDE` — build-time equivalent, baked
  into the binary. For a tree that stages somewhere else.
- `OVSTORAGE_REQUIRE_TEST_PLUGINS=1` — the repository gate meaning "a
  staged plugin set is mandatory", so a run whose staging step never happened
  fails instead of quietly degrading to file-only coverage. `make test` and
  `make test-integration` set it through their shared staged-test environment.
- `OVSTORAGE_LIVE_FAST=1` — shrink the streaming-write payload from 8 MiB to
  1 MiB for fast iteration.
- `RUST_LOG` — `tracing` filter for plugin/host events (default `warn`).
  Requires `-- --nocapture`.
- `OVSTORAGE_AUTH_DIR` — where `init_auth_substrate` keeps its state; defaults
  to a per-pid temp directory.

## Credentials (env contract)

Config and credentials are resolved from the environment into a
`ConnectionRequest`; **no plugin reads the environment itself**, so this table
is the only translation layer. A backend whose identifying config or required
credentials are absent is simply not requested, and its scenarios skip.

**Live fixture identity is environment-only.** No real account, container,
bucket, or region is compiled into the crate. The only built-in identities are
the public development values for the loopback emulators. A missing live
fixture variable is exactly as inert as a missing live credential: both skip
visibly.

| Backend | Config | Credentials | Versioned target |
|---|---|---|---|
| Azure | `OVSTORAGE_AZURE_ACCOUNT` + `OVSTORAGE_AZURE_CONTAINER` | `OVSTORAGE_AZURE_ACCOUNT_KEY` or `OMNI_STORAGE_SERVICE_AZURE_STORAGE_KEY_VERSIONED`; otherwise `OVSTORAGE_AZURE_{TENANT_ID,CLIENT_ID,CLIENT_SECRET}` or `OMNI_STORAGE_SERVICE_AZURE_{TENANT_ID,CLIENT_ID,CLIENT_SECRET}` | `OVSTORAGE_AZURE_VERSIONED_{ACCOUNT,CONTAINER}`; either half falls back to the default target's, but at least one must be set |
| Azure HNS | `OVSTORAGE_AZURE_HNS_ACCOUNT`; `OVSTORAGE_AZURE_HNS_CONTAINER` falls back to `OVSTORAGE_AZURE_CONTAINER` | `OVSTORAGE_AZURE_HNS_ACCOUNT_KEY`, **or** the Azure service principal above when it has RBAC on the HNS account | — |
| S3 | `OVSTORAGE_S3_BUCKET` + `OVSTORAGE_S3_REGION` / `AWS_REGION` / `AWS_DEFAULT_REGION` | `OVSTORAGE_S3_{ACCESS_KEY_ID,SECRET_ACCESS_KEY}` or `AWS_{ACCESS_KEY_ID,SECRET_ACCESS_KEY}` or `OMNI_STORAGE_SERVICE_AWS_{ACCESS_KEY_ID,SECRET_ACCESS_KEY}` (+ optional `…_SESSION_TOKEN` / `AWS_SESSION_TOKEN`) | `OVSTORAGE_S3_VERSIONED_BUCKET` (same credentials and region) |
| GCS | `OVSTORAGE_GCS_BUCKET` | `OVSTORAGE_GCS_SERVICE_ACCOUNT_KEY`, else `OVSTORAGE_GCS_CREDENTIALS_FILE` / `GOOGLE_APPLICATION_CREDENTIALS` | `OVSTORAGE_GCS_VERSIONED_BUCKET` |
| Hugging Face | `OVSTORAGE_HUGGINGFACE_REPO_ID` (+ optional `OVSTORAGE_HUGGINGFACE_REPO_TYPE`, `OVSTORAGE_HUGGINGFACE_REVISION`) | optional: `OVSTORAGE_HUGGINGFACE_TOKEN`, else `HF_TOKEN`, else anonymous | — (versions are the repo's commits, not a second fixture) |

Hugging Face is the one row where the fixture variable alone makes the target
live: the backend is anonymous-capable, so `OVSTORAGE_HUGGINGFACE_REPO_ID` —
no credential required — resolves a live request. Three consequences worth
knowing:

- **Anonymous connect is unprobed.** An anonymous connection verifies without a
  wire call, so a mistyped repo id still "connects" (auth state `Anonymous`)
  and surfaces later, as `NotFound` from the required read scenarios — a
  scenario failure, not a `✗ CONNECT-FAILED` line. The required scenarios are
  the probe.
- **A stale ambient `HF_TOKEN` flips the run from anonymous to failed.** A
  token, once resolved, is verified against the Hub; a rejected one is a
  connect failure, with no silent fall-back to anonymous. Unset it (or set
  `OVSTORAGE_HUGGINGFACE_TOKEN`) rather than expecting the harness to shrug it
  off.
- **A persistently exported `OVSTORAGE_HUGGINGFACE_REPO_ID` fails hermetic
  runs.** `make test` / `make test-integration` forbid the live huggingface
  target, and the fixture variable is exactly what resolves it. That failure is
  the guard working; unset the variable for hermetic work.

The emulator contract is intentionally separate: set
`OVSTORAGE_AZURITE_ENDPOINT` or `OVSTORAGE_FAKE_GCS_ENDPOINT` to a loopback IP
endpoint, and the harness supplies only that emulator's public identity. These
variables never substitute for, inherit, or suppress the live rows above.

The versioned column is never inferred from the primary target: object
versioning is a per-bucket / per-account setting, so an unnamed versioned
fixture means `list_versions` and `get_latest_version` skip rather than run
against a store that keeps no history and fail.

Private staging checkouts may provide all of the above — fixture names included
— through a credential mapper that is deliberately excluded from the public
source tree. Set `LIVE_ENV_SCRIPT=<path>` when invoking a live Make target to
source a trusted mapper in the test shell. If the complete environment is
already exported, set `OVSTORAGE_LIVE_AUTO_ENV=0` instead. Public-source
checkouts receive no fixture identity or credentials by default.

Native GCS does **not** use the `OMNI_STORAGE_SERVICE_GCP_KEY_*` HMAC entries —
those are S3-compatible XML credentials, not GCS JSON API credentials. GCS
needs an ADC JSON credential (`service_account`, `authorized_user`,
`external_account`, or `impersonated_service_account`), inline via
`OVSTORAGE_GCS_SERVICE_ACCOUNT_KEY` or as a file:

```sh
gcloud auth application-default login   # writes the ADC file
# optional: exercise the same identity CI uses (the fixture project's CI
# service account; its concrete name lives in .github/workflows/cloud-live.yml,
# which the public source tree excludes)
gcloud auth application-default login \
  --impersonate-service-account=<the fixture project's CI service account>
```

Do not put a local ADC JSON in a CI secret; those are short-lived user-login
credentials. The hosted `cloud-live` job authenticates GCS without any stored
secret: workload identity federation. Its GitHub OIDC token (subject
`repo:<this org>@<org id>/<this repository>@<repo id>:environment:cloud-live`)
is trusted by a workload identity pool in the fixture project, whose provider
lets the job impersonate the fixture project's CI service account (object
read/write on both fixture buckets, nothing else). The repository sets
`use_immutable_subject`, so those numeric IDs are part of the subject: a
name-only `owner/name` form matches nothing, and a credential registered in
that shape fails the exchange outright rather than degrading. The workflow
stages a standard `external_account` ADC file pointing at the job's OIDC
endpoint and passes it as `OVSTORAGE_GCS_CREDENTIALS_FILE`; the plugin
re-fetches the subject token per exchange, so every step in the job stays
fresh. The concrete resource names all live in
`.github/workflows/cloud-live.yml`, excluded from the public tree. One
coverage caveat: keyless credentials cannot V4-sign, so the signed
read-redirect path is only exercised by a real `service_account` key.

## Targets: `(backend, access)`

A `Target` is one connection plus its advertised address root. `access`
distinguishes the per-backend-meaningful flavors:

- `default` — the primary bucket/container.
- `versioned` — a versioning-enabled bucket/container, for `list_versions` and
  `get_latest_version`.
- `hns` — Azure ADLS Gen2 hierarchical namespace, the only cloud target with
  real directories. No S3/GCS analog.

Two `(backend, access)` requests that resolve to the *same* routed address root
share one connection: an alias `Target` is recorded rather than a second
`add_connection`, because the HNS flag is hidden config and must not create a
duplicate route. HNS is preferred over `default` for a shared root so the
richer real-directory-capable connection wins.

## Scenarios

23 scenarios × 5 backends = 115 generated cases (`app_suite!` in
`src/lib.rs`, expanded by `tests/live.rs`). Each one gates on the target's real
advertised `Capabilities`, so a backend that does not claim a capability skips
rather than failing.

The contract splits into two families. The **write family**
(`CORE_OBJECT_SCENARIOS` plus the per-row extras) mints its own fixtures and
runs on every row with `write_family: true`. The **read family** — the three
`read_only_*` scenarios — runs only where a target lists but cannot write
(`supports_list && !supports_write`): it discovers an object from the fixture
itself and asserts self-consistency only (stat size == list size == read
length; range == slice of the full read; a version-pinned re-read returns the
serving bytes) — never names, counts, or hashes of a third-party fixture, so
the fixture repo can evolve without breaking the suite. Write-capable targets
skip the read family with "write-capable target; the write family covers it";
write-family scenarios skip on a read-only target as "missing capability
supports_write". A read-only baseline row (`write_family: false`) names its
whole required floor explicitly — the read family plus
`error_path_not_found`, the one core scenario a backend that cannot write
still owes.

| Scenario | What it pins |
|---|---|
| `write_stat_read` | the load-bearing round trip; the redirect-followed cloud read |
| `delete` | delete then `NotFound` |
| `list_prefix_delimiter` | non-recursive list folds `sub/` into a directory entry |
| `list_recursive_and_pagination` | recursion + **real backend pagination** (`list_page` passes `max_results`/`page_token` straight through) |
| `copy`, `rename` | server-side or fallback transfer, bytes preserved |
| `update_metadata` | native patch or rewrite emulation; set *and* remove |
| `attribution_round_trip` | write, stream and patch through an attributing host: the principal lands under the literal reserved key `ovstorage_modified_by`, is harvested into `modified_by`, the reserved namespace is hidden from callers, and the hyphenated spelling is ordinary metadata |
| `message_annotation` | a caller `message` lands in user metadata under the literal portable key `x_ov_message`, outside the reserved namespace so an attributing host leaves it visible, beside the caller's own keys, on a write and on a patch, on every write-family backend that stores user metadata; a copy carrying a message keeps the source's own keys and content type everywhere and records the annotation where the backend writes it (GCS) |
| `check_access` | the configured principal is allowed to read its own root |
| `error_path_not_found` | `stat`/`read` of a missing key |
| `range_read` | exact sub-range bytes |
| `read_stream_and_materialize` | streaming read + local delegate (follower fallback on cloud) |
| `key_encoding` | keys containing `space % ? #` round-trip |
| `conditional_write` | create-only and etag CAS, including the stale-etag reject |
| `write_stream` | multipart/block-staged upload past the threshold, byte-integrity checked |
| `directory_ops` | real directories (file native, Azure HNS) |
| `directory_marker_ops` | flat-store directory markers (S3/GCS/flat Azure) |
| `list_versions` | ≥2 distinct, individually readable version pins |
| `get_latest_version` | a concrete, version-pinned address |
| `read_only_list_stat_read` | discovery on a read-only fixture, stat + read at the listed snapshot: list size == stat size == read length |
| `read_only_range_read` | strict-interior ranged read at the listed snapshot == slice of the full read (and strictly shorter than it) |
| `read_only_version_pinning` | serving-version pin re-reads the same bytes; a pin no repository resolves is `NotFound`; `get_latest_version` pins exactly the version it reports |

Cross-backend error-model notes the assertions encode:

- Create-only on an existing key: `AlreadyExists` (file) vs
  `PreconditionFailed` (cloud `If-None-Match: *` → 412).
- A failed caller etag precondition: `ObjectModified` (cloud) vs
  `PreconditionFailed` (file).
- GCS maps `MatchEtag` onto a numeric `ifGenerationMatch`, so the stale-etag
  case reuses a *real* prior etag rather than a synthetic string.

## Cleanup

Every scenario tracks the addresses it creates in a RAII guard, so a scenario
that panics mid-run still deletes what it wrote:

- `TempKeys` — objects.
- `TempDirs` — directories (`delete_directory`).
- `VersionedTempKeys` — version pins. It deliberately never deletes the
  *unpinned* base key: on S3 that writes a delete marker instead of removing
  history.

Each guard's `Drop` runs its deletes on a fresh thread driving the shared
runtime (`block_on` inside a runtime context panics).

The `file` backend's scratch root lives under
`$TMPDIR/ovstorage-integration-tests/run-<pid>-<nanos>/` and is owned by a
`FileRoot` guard that removes it on drop. Because the process-wide `AppState`
lives in a `static` — which Rust never drops — the guard *also* sweeps roots
older than an hour when it creates a new one; that sweep, not the destructor, is
what actually bounds `$TMPDIR`, and it works for a run killed mid-test too.

## Layout

```
src/lib.rs        harness: Stack composition, plugin loading, env → connection
                  resolution, the require/forbid guards, RAII cleanup,
                  the app_suite! macro
src/scenarios.rs  the shared scenario contract (capability-gated)
tests/live.rs     Rust runner — expands app_suite! into the 115-case matrix
tests/python.rs   libtest shim for the Python leg; runs pytest when this
                  checkout's wheel + pytest are importable, else skips visibly
tests/python/     Python runner: conftest.py mirrors the harness (composition,
                  env → connection resolution, the same require/forbid guards,
                  the same RAII cleanup) and test_cloud_app.py implements the
                  same 23 scenarios, parametrized over the same backends
tests/cpp.rs      C++ runner — the same 115-case matrix; composes the SAME
                  app() Stack, exports its root, and drives the C++ driver
                  once per case, then sweeps the case's key prefix
tests/cpp/        C++ driver: cloud_driver.cpp implements the scenarios over
                  ovstorage.hpp against an imported handle, and CMakeLists.txt
                  builds it with the pure-C source set into one standalone .so
build.rs          records target/test-plugins/ as the default plugin dir
```

The three legs are kept in step by name: `tests/python/test_cloud_app.py`
defines `test_<scenario>`, and `tests/cpp.rs`'s `cpp_suite!` names
`<scenario>`, for exactly the scenario list in `tests/live.rs`. The C++ leg
refuses a name it has no case for at both ends — `case_for` in `tests/cpp.rs`
panics, and the driver returns a failure rather than a skip — so a scenario
added to the contract and listed there cannot silently go unrun.
