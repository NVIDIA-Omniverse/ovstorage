// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Versioned-address coverage through the shipped C++20 wrapper and pure-C
// host. The Rust fixture pins its one object only when the request's
// `versioned_address` flag reaches it, so each verb is driven twice: the
// options form must collect the pin (a request path that drops the flag fails
// there) and the flag-less form must collect none (a path that invents the
// flag fails there). Both `stat` and `list` are exercised, so the list options
// overload has behavioural coverage and not only a signature check.

#include "ovstorage.hpp"

#if defined(_WIN32)
#include "windows_posix_compat.h"
#else
#include <dlfcn.h>
#endif

#include <cstdio>
#include <string>
#include <utility>

namespace {

using ExportParkedFn = int (*)(OvStoragePlugin_LayerHandle*);

constexpr const char* kParkedPrefix = "park://data/";
constexpr const char* kParkedObject = "park://data/a.bin";
constexpr const char* kParkedPin = "park://data/a.bin?version=1";

template <class T>
bool succeeded(const char* leg, const ovstorage::Result<T>& result)
{
    if (result) {
        return true;
    }
    std::fprintf(stderr,
        "current ABI %s failed: status %d: %s\n",
        leg,
        static_cast<int>(result.error().code()),
        result.error().message().c_str());
    return false;
}

// One check for every leg, so the four cannot drift apart in what they demand
// of the pin. `expected == nullptr` means no pin may arrive at all.
template <class View>
bool pin_matches(const char* leg, const View& view, const char* expected)
{
    const bool has = view.has_versioned_address();
    const auto pin = view.versioned_address();
    if (has != pin.has_value()) {
        std::fprintf(stderr,
            "%s: has_versioned_address() and versioned_address() disagree\n",
            leg);
        return false;
    }
    if (expected == nullptr) {
        if (has) {
            std::fprintf(stderr,
                "%s: a versioned address arrived without the flag: %s\n",
                leg,
                pin->c_str());
            return false;
        }
        return true;
    }
    if (!has) {
        std::fprintf(stderr,
            "%s: the versioned address asked for did not arrive\n",
            leg);
        return false;
    }
    if (*pin != expected) {
        std::fprintf(stderr,
            "%s: the wrong versioned address arrived: %s\n",
            leg,
            pin->c_str());
        return false;
    }
    return true;
}

bool one_parked_item(const char* leg, const ovstorage::List& list)
{
    if (list.size() != 1) {
        std::fprintf(stderr,
            "%s: expected the one parked object, got %zu item(s)\n",
            leg,
            list.size());
        return false;
    }
    if (list.address(0) != kParkedObject) {
        std::fprintf(stderr,
            "%s: listed %s instead of %s\n",
            leg,
            list.address(0).c_str(),
            kParkedObject);
        return false;
    }
    return true;
}

bool flag_and_pin_cross_cpp(const char* fixture_path)
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

    // The options form asks for the pin, so it must arrive.
    OvStorage_StatOptions stat_asked{};
    stat_asked.versioned_address = true;
    auto stated_asked = ovstorage::sync_wait(layer.stat(kParkedObject, stat_asked));
    if (!succeeded("stat (options form)", stated_asked) ||
        !pin_matches("stat (options form)", stated_asked.value(), kParkedPin)) {
        return false;
    }

    // The bool form carries no flag, so no pin may arrive.
    auto stated_plain = ovstorage::sync_wait(layer.stat(kParkedObject));
    if (!succeeded("stat (bool form)", stated_plain) ||
        !pin_matches("stat (bool form)", stated_plain.value(), nullptr)) {
        return false;
    }

    // The list options form asks for the pin on every item.
    OvStorage_ListOptions list_asked{};
    list_asked.versioned_address = true;
    auto listed_asked = ovstorage::sync_wait(layer.list(kParkedPrefix, list_asked));
    if (!succeeded("list (options form)", listed_asked) ||
        !one_parked_item("list (options form)", listed_asked.value()) ||
        !pin_matches("list (options form)", listed_asked.value().info(0), kParkedPin)) {
        return false;
    }

    // The positional form carries no flag, so no item may be pinned.
    auto listed_plain = ovstorage::sync_wait(layer.list(kParkedPrefix));
    if (!succeeded("list (positional form)", listed_plain) ||
        !one_parked_item("list (positional form)", listed_plain.value()) ||
        !pin_matches("list (positional form)", listed_plain.value().info(0), nullptr)) {
        return false;
    }

    // The imported handle and process-global runtime retain fixture code, so
    // keep the image mapped for process lifetime, matching the parked drivers.
    return true;
}

} // namespace

extern "C" int ovstorage_c_source_versioned_address_abi_cpp20(
    const char* fixture_path);

extern "C" int ovstorage_c_source_versioned_address_abi_cpp20(
    const char* fixture_path)
{
    if (fixture_path == nullptr) {
        std::fputs("fixture path is null\n", stderr);
        return 1;
    }
    return flag_and_pin_cross_cpp(fixture_path) ? 0 : 1;
}
