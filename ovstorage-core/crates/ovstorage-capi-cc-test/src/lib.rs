// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build-time smoke test crate. The real work happens in `build.rs`,
//! which compiles `tests/include_smoke.c` and `tests/include_smoke.cpp`
//! against the checked-in public headers from:
//!
//! - `ovstorage-capi/include/ovstorage.h`
//! - `ovstorage-plugin/include/ovstorage_plugin.h`
//!
//! Authz headers join this smoke test when the remote/broker workspace lands.
//!
//! If any header fails to parse as valid C or C++, this crate's build
//! fails — surfacing the kind of cbindgen template-leakage / forward-
//! decl breakage that is otherwise invisible to the Rust-only test
//! suite.
