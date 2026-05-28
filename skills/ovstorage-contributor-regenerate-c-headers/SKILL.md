---
name: ovstorage-contributor-regenerate-c-headers
description: Use when Rust changes affect ovstorage C or C++ headers and checked-in generated headers must be refreshed.
license: CC-BY-4.0
version: "0.1.0"
author: NVIDIA Omniverse
tags: [ovstorage, c-abi, headers]
tools: [Read, Bash]
compatibility: Requires an ovstorage checkout and the Rust toolchain used by make regenerate-headers.
---

# Regenerate C Headers

## Goal

Keep checked-in C/C++ ABI headers synchronized with Rust source changes.

## Recipe

1. Make the ABI-affecting Rust change under `ovstorage-core`.
2. Run `make regenerate-headers`.
3. Inspect the diff under
   [`ovstorage-capi/include`](../../ovstorage-core/crates/ovstorage-capi/include/).
4. Run `make verify-headers-clean`.
5. Commit the Rust source and regenerated headers together.

## References

- [`ovstorage-capi`](../../ovstorage-core/crates/ovstorage-capi/README.md) for
  C ABI stability rules.
