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

.PHONY: verify help validate-skills lint-public-docs lint-source-headers lint-abi-mint-chokepoint lint-bridge-gil \
        lint-comment-hygiene lint-auth-test-root lint-auth-root-delegation lint-no-keyring-dependency \
           \
        regenerate-headers verify-headers-clean \
        c-source-examples regenerate-third-party-notices verify-third-party-notices-clean \
        fmt fmt-check fmt-toml fmt-toml-check cargo-deny cargo-machete \
        clippy doc test test-ci test-python build-test-plugins install-tools build dist dist-wheel release-archive

help:
	@echo "Available targets:"
	@echo "  verify                 — non-test gate: skills + public-doc lint + source notices + ABI mint chokepoint + headers + Rust/TOML format checks + cargo-deny + cargo-machete + clippy + doc"
	@echo "  validate-skills        — validate publication frontmatter on repo-root agent skills"
	@echo "  lint-public-docs       — fail if any markdown link in docs/public/ escapes the public surface"
	@echo "  lint-source-headers    — fail if active source files lack SPDX/copyright notices"
	@echo "  lint-abi-mint-chokepoint — fail if an async plugin slot completes outside the ABI mint chokepoint"
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
	@echo "  test-python            — build/install the Python extension and run its pytest + stubtest gate"
	@echo "  build-test-plugins     — stage cdylib plugins under target/test-plugins/ for the OVSTORAGE_*_OVERRIDE env vars"
	@echo "  install-tools          — cargo install taplo-cli, cargo-deny, cargo-machete, maturin, cbindgen; pip install tooling deps"
	@echo "  build                  — cargo build --workspace"
	@echo "  dist                   — build all + assemble dist/ at the repo root"
	@echo "  dist-wheel             — dist + build Python wheel into dist/wheels/ via maturin"
	@echo "  release-archive        — full dist + tar.gz/zip at dist/ovstorage-vX.Y.Z-<platform>; PLATFORM=<name> overrides auto-detect"

# --- Composite gate ---------------------------------------------------------
verify: validate-skills lint-public-docs lint-source-headers lint-abi-mint-chokepoint lint-bridge-gil \
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
  OVSTORAGE_OPENDAL_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_opendal.so \
  OVSTORAGE_NUCLEUS_PLUGIN_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_nucleus.so \
  OVSTORAGE_REQUIRE_TEST_PLUGINS=1

test: build-test-plugins
	$(TEST_ENV) cargo test --workspace

# Single workspace, single target/ dir — the former per-workspace `cargo clean`
# loop (a disk-pressure workaround for five duplicated dep graphs) is gone.
test-ci: build-test-plugins
	$(TEST_ENV) cargo test --workspace

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

# Exercise the installed extension, including async tests and mypy.stubtest.
# conftest.py honors OVSTORAGE_REQUIRE_TEST_PLUGINS by checking the test cdylib
# before collection, so missing plugin coverage fails directly rather than
# skipping or otherwise turning vacuously green.
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
test-python: build-test-plugins
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
	cd $(PYTHON_CRATE_DIR) && NO_PROXY='$(NO_PROXY_ALL)' no_proxy='$(NO_PROXY_ALL)' OVSTORAGE_AUTH_DIR=$(TEST_AUTH_ROOT) OVSTORAGE_REQUIRE_TEST_PLUGINS=1 $(PYTHON_TEST_PYTEST) tests

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
