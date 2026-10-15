// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Header-conformance gate: this translation unit includes exactly one
// shipped header and nothing else.  A header that stops compiling as
// standalone C++17 (missing cbindgen cpp_compat enum guards or
// extern "C" linkage guards) fails this crate's build instead of the
// first downstream consumer's.  tests/roundtrip.rs calls the probe so
// the object is pulled into the link on every target.

#include "ovstorage_plugin.h"

extern "C" int ovstorage_c_source_header_plugin_cpp17();

extern "C" int ovstorage_c_source_header_plugin_cpp17()
{
    /* The volatile read defeats constant folding, so the comparison is
     * real and -Waddress stays quiet. */
    void (*volatile reclaim)(OvStoragePlugin_Error *) =
        &ovstorage_plugin_error_free;

    return reclaim != nullptr && sizeof(OvStoragePlugin_LayerVTableV1) != 0
        ? 0
        : 1;
}
