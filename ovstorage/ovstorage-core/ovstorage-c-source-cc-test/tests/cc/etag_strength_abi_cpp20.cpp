// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Etag-strength coverage through the shipped C++20 wrapper and pure-C host.
// A current Rust plugin's ObjectInfo must reach C++ with its strength intact.

#include "ovstorage.hpp"

#if defined(_WIN32)
#include "windows_posix_compat.h"
#else
#include <dlfcn.h>
#endif

#include <cstdio>
#include <utility>

namespace {

using ExportParkedFn = int (*)(OvStoragePlugin_LayerHandle*);

bool current_object_info_reaches_cpp(const char* fixture_path)
{
    // RTLD_LOCAL keeps the Rust fixture's bundled plugin-SDK symbols from
    // interposing the statically linked pure-C runtime.
    void* fixture = dlopen(fixture_path, RTLD_NOW | RTLD_LOCAL);
    if (fixture == nullptr) {
        std::fprintf(stderr, "dlopen(%s): %s\n", fixture_path, dlerror());
        return false;
    }
    auto export_parked = reinterpret_cast<ExportParkedFn>(
        dlsym(fixture, "ovstorage_test_export_parked_stack"));
    if (export_parked == nullptr) {
        std::fputs("dlsym of ovstorage_test_export_parked_stack failed\n", stderr);
        return false;
    }

    OvStoragePlugin_LayerHandle raw{};
    if (export_parked(&raw) != 0) {
        std::fputs("ovstorage_test_export_parked_stack failed\n", stderr);
        return false;
    }
    auto imported = ovstorage::LayerHandle::import_handle(raw);
    if (!imported) {
        std::fprintf(stderr,
            "current ABI handle import failed: status %d: %s\n",
            static_cast<int>(imported.error().code()),
            imported.error().message().c_str());
        return false;
    }
    ovstorage::LayerHandle layer = std::move(imported).value();
    auto stated = ovstorage::sync_wait(layer.stat("park://data/a.bin"));
    if (!stated) {
        std::fprintf(stderr,
            "current ABI stat failed: status %d: %s\n",
            static_cast<int>(stated.error().code()),
            stated.error().message().c_str());
        return false;
    }
    if (stated.value().etag().empty() ||
        stated.value().etag_strength() != OVSTORAGE_ETAG_STRENGTH_STRONG) {
        std::fputs(
            "current Rust ObjectInfo did not preserve its Strong etag declaration\n",
            stderr);
        return false;
    }

    // The imported handle and process-global runtime retain fixture code, so
    // keep the image mapped for process lifetime, matching the parked drivers.
    return true;
}

} // namespace

extern "C" int ovstorage_c_source_etag_strength_abi_cpp20(
    const char* fixture_path);

extern "C" int ovstorage_c_source_etag_strength_abi_cpp20(
    const char* fixture_path)
{
    if (fixture_path == nullptr) {
        std::fputs("fixture path is null\n", stderr);
        return 1;
    }
    return current_object_info_reaches_cpp(fixture_path) ? 0 : 1;
}
