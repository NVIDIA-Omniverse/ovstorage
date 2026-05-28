// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// C++ smoke test. Compiles `ovstorage.h` (the cbindgen-generated C ABI
// header) under C++ rules to catch C/C++ impedance issues — type-name
// collisions, missing `extern "C"` guards, reserved-keyword clashes.
//
// What this test does NOT cover:
//
//   - The hand-authored C++ wrapper `ovstorage.hpp`. The wrapper has
//     pre-existing template-instantiation bugs that are out of scope
//     for the gate (per todo.md:23, "the gate prevents regression
//     after the fix"). Once the wrapper is fixed, swap this include
//     for `ovstorage.hpp` to satisfy todo.md:19's full intent.
//
//   - `ovstorage_plugin.h`. Compiling it as C++ would require fixing
//     the `enum X { ... } / typedef uint8_t X;` collisions cbindgen
//     emits for `#[repr(uN)]` enums. Same out-of-scope bucket as the
//     wrapper. The C smoke (include_smoke.c) covers that header in C.

#include "ovstorage.h"

#include <cstddef>

namespace {

constexpr std::size_t sz_handle_ptr = sizeof(::OvStorage_Library *);
constexpr std::size_t sz_status = sizeof(::OvStorage_Status);

}  // namespace

extern "C" int ovstorage_capi_cc_smoke_cpp_anchor(void);
extern "C" int ovstorage_capi_cc_smoke_cpp_anchor(void) {
    return static_cast<int>(sz_handle_ptr + sz_status);
}
