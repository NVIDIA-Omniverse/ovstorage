# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Repo-wide make targets. Thin wrappers over `cargo xtask` so humans
# don't have to remember the subcommand list. CI invokes `make verify`.

.PHONY: verify help validate-skills lint-public-docs lint-source-headers regenerate-headers verify-headers-clean \
        regenerate-third-party-notices verify-third-party-notices-clean \
        fmt fmt-check fmt-toml fmt-toml-check cargo-deny cargo-machete \
        clippy doc test test-ci build-test-plugins install-tools build dist dist-wheel release-archive

help:
	@echo "Available targets:"
	@echo "  verify                 — non-test gate: skills + public-doc lint + source notices + headers + Rust/TOML format checks + cargo-deny + cargo-machete + clippy + doc"
	@echo "  validate-skills        — validate publication frontmatter on repo-root agent skills"
	@echo "  lint-public-docs       — fail if any markdown link in docs/public/ escapes the public surface"
	@echo "  lint-source-headers    — fail if active source files lack SPDX/copyright notices"
	@echo "  regenerate-headers     — rewrite checked-in C headers from Rust"
	@echo "  verify-headers-clean   — fail if regenerated headers differ"
	@echo "  regenerate-third-party-notices       — rewrite the Cargo dependency table in THIRD_PARTY_NOTICES.md"
	@echo "  verify-third-party-notices-clean     — fail if the Cargo dependency table is stale"
	@echo "  fmt                    — cargo fmt: format Rust code in place across the active workspaces"
	@echo "  fmt-check              — cargo fmt --check: fail if Rust code is unformatted"
	@echo "  fmt-toml               — taplo fmt: format every TOML file in place"
	@echo "  fmt-toml-check         — taplo fmt --check: fail if any TOML is unformatted"
	@echo "  cargo-deny             — cargo deny check (license/advisories/bans/sources)"
	@echo "  cargo-machete          — cargo machete: fail on unused dependencies"
	@echo "  clippy                 — cargo clippy per workspace, -D warnings"
	@echo "  doc                    — cargo doc per workspace, -D rustdoc::broken_intra_doc_links"
	@echo "  test                   — cargo test across the active workspaces (pre-builds test plugins to skip nested-cargo)"
	@echo "  test-ci                — cargo test across active workspaces with per-workspace cleanup for hosted CI disk limits"
	@echo "  build-test-plugins     — stage cdylib plugins under target/test-plugins/ for the OVSTORAGE_*_OVERRIDE env vars"
	@echo "  install-tools          — cargo install taplo-cli, cargo-deny, cargo-machete"
	@echo "  build                  — cargo build --workspace across the active workspaces"
	@echo "  dist                   — build all + assemble dist/ at the repo root"
	@echo "  dist-wheel             — dist + build Python wheel into dist/wheels/ via maturin"
	@echo "  release-archive        — full dist + tar.gz/zip at dist/ovstorage-vX.Y.Z-<platform>; PLATFORM=<name> overrides auto-detect"

verify:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- verify

validate-skills:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- validate-skills

lint-public-docs:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- lint-public-docs

lint-source-headers:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- lint-source-headers

regenerate-headers:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- regenerate-headers

verify-headers-clean:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- verify-headers-clean

regenerate-third-party-notices:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- regenerate-third-party-notices

verify-third-party-notices-clean:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- verify-third-party-notices-clean

fmt:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- fmt

fmt-check:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- fmt-check

fmt-toml:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- fmt-toml

fmt-toml-check:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- fmt-toml-check

cargo-deny:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- cargo-deny

cargo-machete:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- cargo-machete

clippy:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- clippy

doc:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- doc

# Pre-build the test plugins once so the test build.rs files short-circuit
# their nested-cargo paths. Tests then dlopen the staged .so files via the
# OVSTORAGE_*_OVERRIDE env vars.
TEST_PLUGIN_DIR := $(CURDIR)/target/test-plugins
TEST_ENV := \
  OVSTORAGE_EXAMPLE_PLUGIN_RUST_SO_OVERRIDE=$(TEST_PLUGIN_DIR)/libovstorage_plugin_example_rust.so

build-test-plugins:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- build-test-plugins

test: build-test-plugins
	cd ovstorage-core            && $(TEST_ENV) cargo test --workspace
	cd ovstorage-services-client && $(TEST_ENV) cargo test --workspace
	cd ovstorage-cloud           && $(TEST_ENV) cargo test --workspace
	cd ovstorage-nucleus         && $(TEST_ENV) cargo test --workspace
	cd ovstorage-remote          && $(TEST_ENV) cargo test --workspace

test-ci: build-test-plugins
	cd ovstorage-core            && $(TEST_ENV) cargo test --workspace && cargo clean
	cd ovstorage-services-client && $(TEST_ENV) cargo test --workspace && cargo clean
	cd ovstorage-cloud           && $(TEST_ENV) cargo test --workspace && cargo clean
	cd ovstorage-nucleus         && $(TEST_ENV) cargo test --workspace && cargo clean
	cd ovstorage-remote          && $(TEST_ENV) cargo test --workspace && cargo clean

install-tools:
	cargo install taplo-cli --features lsp
	cargo install cargo-deny
	cargo install cargo-machete
	cargo install maturin

build:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- build

dist:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- dist

dist-wheel:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- dist --release --wheel

# Defaults PLATFORM to a coarse `uname`-based label so a local invocation
# produces a sensibly-named archive. CI overrides with the canonical name.
PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')-$(shell uname -m)
release-archive:
	cargo run -p xtask --quiet --manifest-path Cargo.toml -- release-archive --platform $(PLATFORM)
