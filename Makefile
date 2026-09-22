# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Repo-wide make targets. The pure-cargo gates call `cargo` (and the cargo
# subcommand tools) directly against the single flat workspace. Everything
# outside cargo — C-header regeneration, third-party notices, source/skill/doc
# lints, packaging, wheels, release archives, and version management — is
# driven by the per-command Python scripts in `tools/ovtasks/`. CI invokes
# `make verify`.

# The python.org Windows installer ships `python.exe` only -- `python3` is a
# Unix convention and resolves to nothing there, so every ovtasks target dies
# with "The system cannot find the file specified" before running. `?=` still
# lets either default be overridden (`make PYTHON=py ...`).
ifeq ($(OS),Windows_NT)
PYTHON ?= python
else
PYTHON ?= python3
endif
OV := $(PYTHON) tools/ovtasks

.PHONY: verify help validate-skills lint-public-docs lint-source-headers lint-abi-mint-chokepoint lint-layer-ownership lint-bridge-gil \
        lint-comment-hygiene lint-auth-test-root lint-auth-root-delegation lint-no-keyring-dependency \
           \
        regenerate-headers verify-headers-clean \
        c-source-examples regenerate-third-party-notices verify-third-party-notices-clean \
        fmt fmt-check fmt-toml fmt-toml-check cargo-deny cargo-machete \
        clippy doc test test-ci python-test-env test-python \
        test-integration test-integration-live \
        test-integration-python test-integration-python-live \
        test-hub-live \
        bench perf-live perf-smoke \
        build-test-plugins install-tools build dist dist-wheel release-archive

help:
	@echo "Available targets:"
	@echo "  verify                 — non-test gate: skills + public-doc lint + source notices + ABI mint chokepoint + Layer ownership + headers + Rust/TOML format checks + cargo-deny + cargo-machete + clippy + doc"
	@echo "  validate-skills        — validate publication frontmatter on repo-root agent skills"
	@echo "  lint-public-docs       — fail if any markdown link in docs/public/ escapes the public surface"
	@echo "  lint-source-headers    — fail if active source files lack SPDX/copyright notices"
	@echo "  lint-abi-mint-chokepoint — fail if an async plugin slot completes outside the ABI mint chokepoint"
	@echo "  lint-layer-ownership  — fail if the Layer ownership registry drifts from Rust"
	@echo "  lint-bridge-gil          — fail if the Python bridge attaches to the interpreter outside its gate"
	@echo "  lint-comment-hygiene   — fail if a code comment cites a GitHub issue number"
	@echo "  lint-auth-test-root    — fail if a test recipe stops pinning OVSTORAGE_AUTH_DIR away from \$$HOME"
	@echo "  lint-auth-root-delegation — fail if a host resolves the auth directory outside the shared resolver"
	@echo "  lint-no-keyring-dependency — fail if the keyring crate returns to the dependency graph"
	@echo "  regenerate-headers     — rewrite checked-in C headers from Rust (cbindgen CLI)"
	@echo "  verify-headers-clean   — fail if regenerated headers differ"
	@echo "  c-source-examples      — verify, build, and run the standalone pure-C C/C++ examples"
	@echo "  regenerate-third-party-notices       — rewrite the Cargo dependency table in THIRD_PARTY_NOTICES.md"
	@echo "  verify-third-party-notices-clean     — fail if the Cargo dependency table is stale"
	@echo "  fmt                    — cargo fmt: format Rust code in place across the workspace"
	@echo "  fmt-check              — cargo fmt --check: fail if Rust code is unformatted"
	@echo "  fmt-toml               — taplo fmt: format every TOML file in place"
	@echo "  fmt-toml-check         — taplo fmt --check: fail if any TOML is unformatted"
	@echo "  cargo-deny             — cargo deny check (license/advisories/bans/sources)"
	@echo "  cargo-machete          — cargo machete: fail on unused dependencies"
	@echo "  clippy                 — cargo clippy --workspace, -D warnings"
	@echo "  doc                    — cargo doc --workspace --document-private-items, -D on all three rustdoc link lints"
	@echo "  test                   — cargo test --workspace (pre-builds test plugins to skip nested-cargo)"
	@echo "  test-ci                — cargo test --workspace for hosted CI"
	@echo "  python-test-env        — create target/python-test-venv and install the extension into it (shared by every Python gate)"
	@echo "  test-python            — build/install the Python extension and run its pytest + stubtest gate"
	@echo "  test-integration       — app-level integration suite, hermetic: file backend required, cloud backends forbidden"
	@echo "  test-integration-live  — app-level integration suite against live cloud backends (sources LIVE_ENV_SCRIPT)"
	@echo "  test-integration-python  — Python leg of the app-level integration suite, hermetic"
	@echo "  test-integration-python-live — Python leg against live cloud backends (sources LIVE_ENV_SCRIPT)"
	@echo "  test-hub-live          — hub_cache live tier against a real hub: reuses one on 14093 or launches one (OVSTORAGE_HUB_LIVE_EXE or a sibling omni-hub checkout)"
	@echo "  bench                  — criterion micro-benchmarks, whole workspace"
	@echo "  perf-live              — live read-perf harness against cloud backends (sources LIVE_ENV_SCRIPT)"
	@echo "  perf-smoke             — read-perf harness, hermetic smoke run (file backend; plus emulators when configured)"
	@echo "  build-test-plugins     — stage cdylib plugins under target/test-plugins/ for the OVSTORAGE_*_OVERRIDE env vars"
	@echo "  install-tools          — cargo install taplo-cli, cargo-deny, cargo-machete, maturin, cbindgen; pip install tooling deps"
	@echo "  build                  — cargo build --workspace"
	@echo "  dist                   — build all + assemble dist/ at the repo root"
	@echo "  dist-wheel             — dist + build Python wheel into dist/wheels/ via maturin"
	@echo "  release-archive        — full dist + tar.gz/zip at dist/ovstorage-vX.Y.Z-<platform>; PLATFORM=<name> overrides auto-detect"

# --- Composite gate ---------------------------------------------------------
verify: validate-skills lint-public-docs lint-source-headers lint-abi-mint-chokepoint lint-layer-ownership lint-bridge-gil \
        lint-comment-hygiene lint-auth-test-root lint-auth-root-delegation lint-no-keyring-dependency \
           \
        verify-third-party-notices-clean \
        verify-headers-clean fmt-check fmt-toml-check cargo-deny cargo-machete clippy doc

# --- Non-cargo tasks (Python tooling) ---------------------------------------
validate-skills:
	$(OV)/validate_skills.py

lint-public-docs:
	$(OV)/lint_public_docs.py

lint-source-headers:
	$(OV)/lint_source_headers.py

lint-abi-mint-chokepoint:
	$(OV)/lint_abi_mint_chokepoint.py

lint-layer-ownership:
	$(OV)/lint_layer_ownership.py

lint-bridge-gil:
	$(OV)/lint_bridge_gil.py

lint-comment-hygiene:
	$(OV)/lint_comment_hygiene.py

lint-auth-test-root:
	$(OV)/lint_auth_test_root.py

lint-auth-root-delegation:
	$(OV)/lint_auth_root_delegation.py

lint-no-keyring-dependency:
	$(OV)/lint_no_keyring_dependency.py

regenerate-headers:
	$(OV)/regenerate_headers.py

verify-headers-clean:
	$(OV)/verify_headers_clean.py

c-source-examples:
	$(OV)/c_source_examples.py

regenerate-third-party-notices:
	$(OV)/regenerate_third_party_notices.py

verify-third-party-notices-clean:
	$(OV)/verify_third_party_notices_clean.py

build-test-plugins:
	$(OV)/build_test_plugins.py

dist:
	$(OV)/dist.py

dist-wheel:
	$(OV)/dist.py --release --wheel

# --- Pure-cargo gates (driven directly against the single workspace) --------
fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

fmt-toml:
	taplo fmt

fmt-toml-check:
	taplo fmt --check

cargo-deny:
	# No explicit --config: <cwd>/deny.toml is the default in every cargo-deny
	# version, and the flag's position moved from `check` to the root command
	# in 0.20.0 — passing it breaks one side or the other.
	cargo deny --all-features check

cargo-machete:
	cargo-machete $(CURDIR)

clippy:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# `--document-private-items` is what makes the link lints reach private items.
# Without it rustdoc never renders a private item and never resolves its
# intra-doc links, so a broken link on one passes the gate and rots.
#
# `private_intra_doc_links` is denied alongside the other two because the
# published docs are built WITHOUT the flag: a public item whose docs link to a
# private one renders a dead link there. Such a reference is written as plain
# code formatting instead.
doc:
	RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links \
	  -D rustdoc::private_intra_doc_links \
	  -D rustdoc::redundant_explicit_links" DOCS_RS=1 \
	  cargo doc --workspace --no-deps --all-features --locked \
	    --document-private-items

build:
	cargo build --workspace

# Pre-build the test plugins once so the test build.rs files short-circuit
# their nested-cargo paths. Tests then dlopen the staged .so files via the
# OVSTORAGE_*_OVERRIDE env vars. With the flattened workspace this is a single
# `cargo build -p ...` against the one target/ dir.
TEST_PLUGIN_DIR := $(CURDIR)/target/test-plugins
# `build-test-plugins` pre-builds the cdylibs (including the ABI-v2 mini layer)
# into the profile dir, so OVSTORAGE_REQUIRE_TEST_PLUGINS turns a missing plugin
# into a hard error: the dlopen-backed mixed-layer and Stack plugin tests fail
# loud in CI instead of skipping vacuously.
#
# The `NO_PROXY` rule keeps the suite independent of the developer's or
# runner's ambient proxy environment: HTTP clients honor `HTTP_PROXY` /
# `HTTPS_PROXY` process-wide, so on a host that exports them the many tests
# expecting requests to reach a loopback mock server instead reach the
# corporate proxy and fail their hit assertions.
#
# All three parts are load-bearing. hyper-util's matcher — shared by reqwest
# and by the AWS Smithy connector — parses each `NO_PROXY` entry as an IP
# address, a CIDR network, or (failing both) a domain rule, and then consults
# only the matching list for a given host. `*` is the bypass-everything
# *domain* rule and never applies to an IP-literal host, so `NO_PROXY=*` alone
# leaves `http://127.0.0.1:<port>` mock endpoints proxied; the two default
# routes cover the IP side.
#
# The proxy characterization tests deliberately clear every proxy variable —
# `NO_PROXY` included — before spawning their child, so they still exercise the
# real routing.
NO_PROXY_ALL := *,0.0.0.0/0,::/0

# The auth substrate's default root is a real per-user directory, so a harness
# that resolves the default reaches the credentials the developer signed in
# with. Pinning it here covers what a per-harness `tempdir()` cannot: the CLI
# and MCP integration tests spawn a binary that initialises auth at startup,
# and a child process inherits this but cannot inherit an in-process
# `set_var`. Harnesses that pass an explicit directory still win over it; this
# is the floor, not the isolation.
TEST_AUTH_ROOT := $(CURDIR)/target/test-auth-root

TEST_ENV := \
  NO_PROXY='$(NO_PROXY_ALL)' \
  no_proxy='$(NO_PROXY_ALL)' \
  OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) \
  OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_example_rust.so \
  OVSTORAGE_HTTP_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_http.so \
  OVSTORAGE_S3_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_s3.so \
  OVSTORAGE_AZURE_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_azure.so \
  OVSTORAGE_GCS_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_gcs.so \
  OVSTORAGE_HUGGINGFACE_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_huggingface.so \
  OVSTORAGE_OPENDAL_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_opendal.so \
  OVSTORAGE_NUCLEUS_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_nucleus.so \
  OVSTORAGE_REQUIRE_TEST_PLUGINS=1

# `cargo test --workspace` includes `ovstorage-integration-tests`, whose
# cases connect to whatever backends the *ambient shell* has credentials for. On
# a developer machine that has sourced the live env, a plain `make test` would
# silently do live cloud I/O against shared fixture buckets — slow, chargeable,
# and mutating storage nobody asked it to touch. So the workspace gate pins the
# same hermetic guard pair `test-integration` uses (defined below with the rest
# of the integration knobs): `file` must connect, azure/s3/gcs/huggingface
# must not, and an ambient credential (or, for the anonymous-capable
# huggingface backend, its fixture variable alone) is a hard failure rather
# than an invisible mode switch.
# `test-integration-live` deliberately does NOT take this — it reads
# OVSTORAGE_REQUIRE_LIVE_BACKENDS from the caller instead.
test: build-test-plugins
	$(INTEGRATION_GUARD_ENV) $(TEST_ENV) cargo test --workspace

# Single workspace, single target/ dir — the former per-workspace `cargo clean`
# loop (a disk-pressure workaround for five duplicated dep graphs) is gone.
test-ci: build-test-plugins
	$(INTEGRATION_GUARD_ENV) $(TEST_ENV) cargo test --workspace

# The venv path carries the interpreter's full `major.minor.micro`. Creation is
# guarded by `test -x $(PYTHON_TEST_VENV)/bin/python`, so an untagged path is
# reused by whatever interpreter happens to have built it first: `make
# test-python PYTHON=python3.12` after a 3.10 run would report a green 3.12
# result from a 3.10 interpreter. Tagging means a different interpreter builds
# its own venv instead of inheriting one.
#
# The patch level is part of that identity rather than decoration: a minor-only
# tag would let a venv built by 3.13.7 answer a 3.13.8 request, so the suite
# would run on an interpreter nobody chose. That matters more here than in most
# projects, because 3.13.7 and 3.13.8 differ in how CPython handles a forbidden
# interpreter attach -- abort on the older, blocked thread on the newer -- so
# "which patch release ran" is a real variable for this crate rather than noise.
#
# `PYTHON_TEST_EXPECT` is the second half of the control, for callers that know
# which interpreter they asked for -- a CI matrix leg passes its own version and
# the recipe fails if the venv disagrees. The tag alone cannot catch a venv
# whose directory name and contents have drifted apart.
#
# The tag is deferred (`=`, not `:=`) so no `make` invocation launches a Python
# subprocess unless a recipe needs the path, and memoized on first use so the
# recipe's dozen references resolve one interpreter once rather than re-probing
# a `PYTHON` that could change underneath them.
#
# A caller that names the variable at all meant to assert something, so an empty
# value is a mistake rather than a way to opt out. `PYTHON_TEST_EXPECT=$(PY_VER)`
# with `PY_VER` unset expands to empty, and treating that as "no expectation
# given" would skip the check and report green -- the same outcome as a guard
# that never worked, reached from the caller CI actually is. `origin` separates
# "not passed" from "passed as empty"; only the first skips.
#
# The snapshot is what makes that guarantee hold rather than merely look right.
# A command-line variable is recursive, so `$(PYTHON_TEST_EXPECT)` is a fresh
# expansion at every mention: the check below can inspect one result while the
# recipe uses another, and a value carrying `$(eval ...)` differs between the
# two on purpose. `:=` expands it exactly once, here, so the value that is
# validated is the identical string the recipe exports and Python compares.
#
# `override` because a command-line assignment outranks a makefile one, and
# every name the recipe reads has to derive from `PYTHON_TEST_EXPECT` rather
# than be settable beside it. Without it `make test-python PYTHON_TEST_EXPECT=
# 3.13 PYTHON_TEST_EXPECT_SNAPSHOT=3.10` checks 3.10 while the invocation names
# 3.13 -- an internal name is not private just because callers have no reason to
# know it.
override PYTHON_TEST_EXPECT_SNAPSHOT := $(PYTHON_TEST_EXPECT)
ifneq ($(origin PYTHON_TEST_EXPECT),undefined)
ifeq ($(strip $(PYTHON_TEST_EXPECT_SNAPSHOT)),)
$(error PYTHON_TEST_EXPECT was given but is empty; pass a version like 3.13, or leave it unset entirely)
endif
endif
PYTHON_TEST_TAG = $(eval PYTHON_TEST_TAG := $(shell $(PYTHON) -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])'))$(PYTHON_TEST_TAG)
PYTHON_TEST_VENV = $(CURDIR)/target/python-test-venv-$(PYTHON_TEST_TAG)
PYTHON_TEST_PIP = $(PYTHON_TEST_VENV)/bin/python -m pip
PYTHON_TEST_MATURIN = $(PYTHON_TEST_VENV)/bin/maturin
PYTHON_TEST_PYTEST = $(PYTHON_TEST_VENV)/bin/python -m pytest
PYTHON_CRATE_DIR := $(CURDIR)/ovstorage-core/ovstorage-python

# Shared prerequisite of every Python gate (`test-python` and both integration
# legs): one venv holding one `maturin develop --features test-probes` build of
# the extension. Factored out because three targets need it and each of them is
# reachable on its own from a clean tree — CI runs `test-python` and
# `test-integration-python` in different jobs, and `test-integration-python-live`
# in a third — so the setup cannot live in any one of them. Running two of them
# in the same invocation still builds the extension once: make honors a phony
# prerequisite at most once per run.
#
# `maturin develop` installs the pyproject `[dependency-groups]` dev group via
# `pip install --group`, which needs pip >= 25.1; CI runner images can ship an
# older pip, so upgrade the venv's pip before building.
#
# `override` is what keeps the two names from drifting apart. The empty-value
# guard above protects `PYTHON_TEST_EXPECT`, but the recipe consults
# `OVSTORAGE_EXPECT_PYTHON`, and a command-line assignment outranks a plain
# target-specific one -- so `make test-python PYTHON_TEST_EXPECT=3.13
# OVSTORAGE_EXPECT_PYTHON=` empties the variable the check actually reads while
# the guarded one still says 3.13, and the gate goes green having asserted
# nothing. With `override` the recipe always sees the snapshot, which is the
# only value any guard has inspected.
test-python: export override OVSTORAGE_EXPECT_PYTHON := $(PYTHON_TEST_EXPECT_SNAPSHOT)
python-test-env: build-test-plugins
	@test -n "$(PYTHON_TEST_TAG)" || { \
	  echo "make test-python: PYTHON=$(PYTHON) is not runnable, so the venv path has no interpreter tag"; \
	  exit 1; \
	}
	@# Which interpreter ran is the first thing anyone reading a failed CI leg
	@# needs, and it is otherwise nowhere in the log.
	@echo "test-python: interpreter $(PYTHON) is $(PYTHON_TEST_TAG), venv $(PYTHON_TEST_VENV)"
	@# The assertion is opt-in, so the log has to distinguish "asserted 3.13 and
	@# matched" from "asserted nothing" -- otherwise a leg that stopped naming a
	@# version reads exactly like one that passed. A caller can stop naming it by
	@# misspelling the knob, since `make` accepts any unknown variable assignment
	@# without complaint, or by losing the argument from the workflow step.
	@#
	@# Read from the environment for the same reason the comparison below is:
	@# substituting the value into this line would let it forge log lines, and
	@# would make the banner a second reading of the expectation rather than the
	@# one the check uses. `:-` supplies the unset text in the shell, so the
	@# printed string and the compared string are the same variable.
	@echo "test-python: expectation $${OVSTORAGE_EXPECT_PYTHON:-<none supplied; interpreter not asserted>}"
	test -x $(PYTHON_TEST_VENV)/bin/python || $(PYTHON) -m venv $(PYTHON_TEST_VENV)
	@# Compares as many version fields as the caller supplied, so a matrix
	@# The expectation is asserted by `tests/conftest.py`, at collection time,
	@# rather than by a check on this line. The recipe can only interrogate
	@# whichever interpreter it names, and every variable naming one --
	@# `PYTHON`, `PYTHON_TEST_VENV`, `PYTHON_TEST_PYTEST` -- is settable from the
	@# command line, so a recipe-level check and the suite it vouches for can be
	@# made two different processes. Asserted from inside the run, the process
	@# doing the checking is the process being checked, and no build variable can
	@# separate them. The line above reports the expectation; `conftest.py`
	@# enforces it.
	$(PYTHON_TEST_PIP) install --upgrade pip
	$(PYTHON_TEST_PIP) install -r $(PYTHON_CRATE_DIR)/requirements-dev.txt maturin
	cd $(PYTHON_CRATE_DIR) && VIRTUAL_ENV=$(PYTHON_TEST_VENV) $(PYTHON_TEST_MATURIN) develop --features test-probes

# Exercise the installed extension, including async tests and mypy.stubtest.
# conftest.py honors OVSTORAGE_REQUIRE_TEST_PLUGINS by checking the test cdylib
# before collection, so missing plugin coverage fails directly rather than
# skipping or otherwise turning vacuously green.
test-python: python-test-env
	cd $(PYTHON_CRATE_DIR) && NO_PROXY='$(NO_PROXY_ALL)' no_proxy='$(NO_PROXY_ALL)' OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) OVSTORAGE_REQUIRE_TEST_PLUGINS=1 $(PYTHON_TEST_PYTEST) tests

# --- App-level integration suite --------------------------------------------
# `ovstorage-integration-tests` drives the shipped Stack/Layer API the way an
# application does: build the default stack, dlopen the staged plugin cdylibs,
# register one connection per backend, and operate by address. One scenario
# contract, run from Rust (`--test live`) and from Python (tests/python).
#
# Backend selection is environment-driven, so both directions of "wrong
# environment" have to be errors rather than a quietly smaller run:
#
# - OVSTORAGE_REQUIRE_HERMETIC_BACKENDS — a listed local/emulator backend that
#   is not configured fails the run instead of skipping. The default local run
#   requires only file; CI overrides the list after starting its emulators.
# - OVSTORAGE_REQUIRE_LIVE_BACKENDS — the corresponding guard for live cloud
#   fixtures. It is intentionally independent of the hermetic guard.
# - OVSTORAGE_FORBID_LIVE_BACKENDS — a listed live cloud fixture that IS
#   configured fails the run. Emulator targets of the same backend kind remain
#   allowed. This keeps `test-integration` hermetic on a developer machine that
#   already exports cloud credentials in its shell.
INTEGRATION_PACKAGE := ovstorage-integration-tests
INTEGRATION_PYTHON_TESTS := $(CURDIR)/ovstorage-integration-tests/tests/python

# Guard env for the hermetic legs — `test` and `test-ci` above included, since
# `cargo test --workspace` sweeps this package in. The live legs have their own
# targets (`test-integration-live`, `test-integration-python-live`) and do not
# reference this variable at all. Use those targets to reach live backends;
# command-line overrides remain available for harness development.
INTEGRATION_HERMETIC_REQUIRE ?= file
INTEGRATION_GUARD_ENV := \
  OVSTORAGE_REQUIRE_LIVE_BACKENDS= \
  OVSTORAGE_REQUIRE_HERMETIC_BACKENDS=$(INTEGRATION_HERMETIC_REQUIRE) \
  OVSTORAGE_FORBID_LIVE_BACKENDS=azure,s3,gcs,huggingface

# `--nocapture`: the suite prints one line per scenario/backend, including the
# visible skip lines. Capturing them makes a run that exercised nothing look
# identical to a run that exercised everything.
#
# `--test cpp` alongside `--test live`: the C++ leg runs the same matrix as
# `live` through the C++20 wrapper over a Rust->C++ handoff, and naming only
# `live` here would leave it running nowhere but a bare `cargo test`. It skips
# visibly, per case, when `build-test-plugins` could not build its driver.
#
# The C++ leg is Unix-only BY DESIGN, not by accident: `tests/cpp.rs` locates
# its driver as `libovsx_cloud_cpp_driver.{so,dylib}` and dlopens it directly,
# with no `.dll` name, no import-library link step, and no PATH/DLL-directory
# staging for the transitive dependencies a Windows load would need. So on
# Windows every C++ case fails the `OVSTORAGE_REQUIRE_TEST_PLUGINS=1` assertion
# instead of running. The Rust and Python legs are portable; only this one is
# gated, which is why the integration jobs in CI are Linux-only. Adding Windows
# is a driver-packaging effort (DLL naming plus dependent-DLL staging), not a
# runner change.
INTEGRATION_TEST_TARGETS := --test live --test cpp

test-integration: build-test-plugins
	$(INTEGRATION_GUARD_ENV) $(TEST_ENV) \
	  cargo test -p $(INTEGRATION_PACKAGE) $(INTEGRATION_TEST_TARGETS) -- --nocapture

# Live counterpart: same suite, no FORBID guard, and OVSTORAGE_REQUIRE_LIVE_BACKENDS
# comes from the caller's environment (CI sets it from a secret; locally you
# pick which backends must be present). The credential script is `source`d into
# one bash invocation because make gives each recipe line its own shell, and
# `/bin/sh` cannot source it.
#
# Set OVSTORAGE_LIVE_AUTO_ENV=0 when the credentials are already exported in
# your shell (or supplied by CI) and the script should not run at all. When
# every required selector is anonymous (huggingface only), the prelude skips
# the mapper on its own: sourcing it would export the other clouds' fixtures
# and credentials and take them live in a run nobody asked to touch them. To
# combine an anonymous selector with credentialed ones, just name both — any
# azure/s3/gcs selector brings the mapper back; to force-source it for an
# hf-only run, source it in your shell first.
#
# Private staging checkouts carry this credential mapper, while the public
# source tree excludes it. A missing script is therefore normal for a public
# consumer: the prelude prints a notice and uses the caller's exported
# credentials. Set this hook explicitly to select another trusted mapper.
LIVE_ENV_SCRIPT ?= $(CURDIR)/tools/vault/local_env.sh

# The credential prelude both live targets share. It is a variable rather than
# a target because `source` only affects the shell that runs it: the sourcing
# and the test command have to be one `bash -c`, and make gives each recipe
# line its own shell (`/bin/sh`, which has no `source`). `$$` survives make
# expansion as a single `$` for that shell. Backslash-newlines collapse to
# spaces inside a variable assignment, so this expands to one shell line.
LIVE_ENV_PRELUDE = set -euo pipefail; \
  live_cloud_selector=; \
  live_credentialed_selector=; \
  IFS=',' read -ra live_required_selectors <<< "$${OVSTORAGE_REQUIRE_LIVE_BACKENDS:-}"; \
  for selector in "$${live_required_selectors[@]+"$${live_required_selectors[@]}"}"; do \
    if [[ "$$selector" =~ ^[[:space:]]*(azure|s3|gcs|huggingface)(:(default|versioned|hns))?[[:space:]]*$$ ]]; then \
      live_cloud_selector="$$selector"; \
    fi; \
    if [[ "$$selector" =~ ^[[:space:]]*(azure|s3|gcs)(:(default|versioned|hns))?[[:space:]]*$$ ]]; then \
      live_credentialed_selector="$$selector"; \
    fi; \
  done; \
  if [ -z "$$live_cloud_selector" ]; then \
    echo "OVSTORAGE_REQUIRE_LIVE_BACKENDS must name at least one live cloud target (azure, s3, gcs, or huggingface, optionally followed by :default, :versioned, or :hns)" >&2; \
    exit 2; \
  fi; \
  if [ "$${OVSTORAGE_LIVE_AUTO_ENV:-1}" = "0" ]; then \
    echo "OVSTORAGE_LIVE_AUTO_ENV=0: using the credentials already in the environment"; \
  elif [ -z "$$live_credentialed_selector" ]; then \
    echo "OVSTORAGE_REQUIRE_LIVE_BACKENDS names only anonymous targets; skipping the credential mapper"; \
  elif [ -r "$(LIVE_ENV_SCRIPT)" ]; then \
    source "$(LIVE_ENV_SCRIPT)"; \
  else \
    echo "no credential script at $(LIVE_ENV_SCRIPT); using the credentials already in the environment"; \
  fi

test-integration-live: build-test-plugins
	bash -c '$(LIVE_ENV_PRELUDE); \
	  OVSTORAGE_REQUIRE_HERMETIC_BACKENDS= OVSTORAGE_FORBID_LIVE_BACKENDS= \
	    $(TEST_ENV) cargo test -p $(INTEGRATION_PACKAGE) $(INTEGRATION_TEST_TARGETS) -- --nocapture'

# The hub_cache live tier is connect-only, so this launches (or reuses) a
# real hub for it — the one behavior a fixture cannot vouch for is the real
# daemon's wire.
test-hub-live:
	$(OV)/hub_live.py test

# Python leg, hermetic: the same guard pair as `test-integration`, applied to
# the same scenario contract through the binding. OVSTORAGE_PLUGIN_DIR points
# pytest at the same staged cdylibs the Rust leg dlopens.
test-integration-python: python-test-env
	$(INTEGRATION_GUARD_ENV) OVSTORAGE_PLUGIN_DIR=$(TEST_PLUGIN_DIR) \
	  $(PYTHON_TEST_PYTEST) $(INTEGRATION_PYTHON_TESTS)

# Live counterpart of the Python leg, standing in the same relation to
# `test-integration-python` that `test-integration-live` does to
# `test-integration`: no FORBID guard, OVSTORAGE_REQUIRE_LIVE_BACKENDS supplied
# by the caller (CI sets it on the job; locally you pick), and the same
# LIVE_ENV_SCRIPT sourcing. Without this target the Python scenarios only ever
# ran against `file`, so every Python-side cloud path — the whole reason the
# scenario contract is cross-binding — went unexercised.
#
# OVSTORAGE_REQUIRE_TEST_PLUGINS=1 matters more here than in the hermetic leg:
# the cloud backends are reached through the staged plugin cdylibs, so a
# staging regression would otherwise leave every cloud target unconfigured, and
# unconfigured targets are exactly what REQUIRE turns into a failure. Setting
# it makes the diagnosis "the plugins are missing" rather than "azure did not
# connect".
test-integration-python-live: python-test-env
	bash -c '$(LIVE_ENV_PRELUDE); \
	  OVSTORAGE_REQUIRE_HERMETIC_BACKENDS= OVSTORAGE_FORBID_LIVE_BACKENDS= \
	    OVSTORAGE_PLUGIN_DIR=$(TEST_PLUGIN_DIR) OVSTORAGE_REQUIRE_TEST_PLUGINS=1 \
	    $(PYTHON_TEST_PYTEST) $(INTEGRATION_PYTHON_TESTS)'

# --- Performance ------------------------------------------------------------
# Criterion micro-benchmarks (hermetic, in-process; no plugin staging — the
# bench registers its backend factory directly). Keep this a lone cargo
# invocation: `ovstorage`'s build script runs a nested cargo build, so a
# second concurrent cargo command in this workspace can contend with it.
bench:
	cargo bench --workspace

# Live read-perf harness: the perf counterpart of `test-integration-live`,
# sharing its credential prelude and guard semantics (REQUIRE comes from the
# caller, FORBID cleared). Dev profile on purpose: the staged plugin cdylibs
# it dlopens are dev-profile, and keeping both sides of the ABI on one profile
# makes runs comparable with each other, which is all trend tracking needs.
# OVSTORAGE_PERF_OUTPUT (optional) names the JSON report path.
perf-live: build-test-plugins
	bash -c '$(LIVE_ENV_PRELUDE); \
	  OVSTORAGE_REQUIRE_HERMETIC_BACKENDS= OVSTORAGE_FORBID_LIVE_BACKENDS= \
	    $(TEST_ENV) cargo run -p ovstorage-perf --bin ovstorage-perf-live -- --profile nightly'

# Hermetic smoke of the same binary: live backends forbidden by the same
# guard pair `test-integration` pins, so it can run on any machine (and in
# credential-free CI) to prove the harness has not rotted. It measures every
# hermetic backend the environment configures: file only by default, file
# plus the Azurite/fake-GCS emulators where CI (or a developer) exports their
# endpoints.
perf-smoke: build-test-plugins
	$(INTEGRATION_GUARD_ENV) $(TEST_ENV) \
	  cargo run -p ovstorage-perf --bin ovstorage-perf-live -- --profile smoke

install-tools:
	cargo install taplo-cli --features lsp
	cargo install cargo-deny
	cargo install cargo-machete
	cargo install maturin
	cargo install cbindgen
	$(PYTHON) -m pip install -r tools/requirements-dev.txt

PLATFORM ?= auto
release-archive:
	$(OV)/release_archive.py --platform $(PLATFORM)
