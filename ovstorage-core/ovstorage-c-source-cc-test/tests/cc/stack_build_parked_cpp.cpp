// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Runtime coverage: the shipped C++20 wrapper's coroutine machinery
// (`task<T>` / `detail::awaiter_base` / `sync_wait`) drives a genuinely
// PARKED C-ABI operation across a foreign plugin boundary without blocking,
// lets unrelated work progress while it is parked, completes with
// `Cancelled` when its cancel token fires, and leaves the driven root
// reusable and destructible.
//
// This is the shipped configuration end to end: the wrapper's own awaiters
// over the pure-C runtime this crate compiles and links, against a Rust
// plugin loaded through the C ABI's handoff verbs. It is the C++ twin of
// `stack_build_parked_c.c`, which pins the same contract at the C level, and
// it links the C ABI directly exactly as that sibling does.
//
// WHY ROOT DISCOVERY, NOT `Stack::build()`:
// -----------------------------------------
// The parking fixture (`ovstorage-plugin-test-abi`) exposes its `ParkBackend`
// ONLY through the dlsym'able `ovstorage_test_export_parked_stack` symbol; it
// is deliberately NOT registered on the plugin's factory set. The public
// Stack-builder surface composes layers only by factory `kind` resolved
// through a `Registry`; no public verb mounts a pre-built or imported handle
// into a Stack. So a genuinely parked `ovstorage_stack_build_async` against
// this fixture is not reachable through the real public API.
//
// The strongest GENUINE parked async operation the fixture supports through
// the public surface is its root-discovery slot: import the parked root and
// drive `LayerHandle::list_address_roots`, whose v8 slot parks until released
// or cancelled. That IS root discovery — the build-time work targeted here —
// reached through the discovery entry point. The real
// `ovstorage_stack_build_async` non-blocking / cancel / reuse contract (over
// the built-in file backend, which does not park) is pinned by the sibling
// `stack_async_c.c`, and a genuinely parked build by
// `stack_build_abandon_repro.c`.
//
// Determinism: every wait is a latch or condition variable. The fixture
// signals arrival the instant its slot parks, so cancel and release always
// land on a genuinely in-flight parked op — no sleeps, no timing assumptions.

#include "ovstorage.hpp"

#if defined(_WIN32)
#include "windows_posix_compat.h"
#else
#include <dlfcn.h>
#endif

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

namespace {

using ExportParkedFn = int (*)(OvStoragePlugin_LayerHandle*);
using ParkVoidFn = void (*)();

ExportParkedFn g_export_parked = nullptr;
ParkVoidFn g_park_wait_arrived = nullptr;
ParkVoidFn g_release_park_gate = nullptr;

// Import a fresh parked root from the fixture (each export resets the gate).
// The handoff runs through the wrapper's own `import_handle`, so the returned
// root is an ordinary `LayerHandle` with an ordinary destructor.
ovstorage::Result<ovstorage::LayerHandle> import_parked_root()
{
    OvStoragePlugin_LayerHandle raw{};
    if (g_export_parked(&raw) != 0) {
        return ovstorage::Result<ovstorage::LayerHandle>::failure(ovstorage::Error(
            OvStorage_Status_Internal, "ovstorage_test_export_parked_stack failed"));
    }
    return ovstorage::LayerHandle::import_handle(raw);
}

// Scenario A — cancel a parked root discovery.
//   * The discovery task is driven by `sync_wait` on a worker thread and
//     parks; the fixture's arrival latch rendezvouses with the park point.
//   * With the op genuinely parked the worker has NOT returned (the parked
//     async op neither completes early nor blocks the rest of the process),
//     and a sibling `stat` on THIS thread completes (unrelated work
//     progresses while the discovery is parked).
//   * Firing the cancel token completes the discovery with `Cancelled`.
//   * The imported root is then destroyed cleanly.
bool run_cancel_while_parked()
{
    auto imported = import_parked_root();
    if (!imported) {
        std::fprintf(stderr, "import of the parked root failed: %s\n",
            imported.error().message().c_str());
        return false;
    }
    ovstorage::LayerHandle handle = std::move(imported).value();

    ovstorage::CancelToken cancel;
    std::atomic<bool> worker_returned{false};
    OvStorage_Status observed = OvStorage_Status_Ok;
    std::size_t root_count = 0;

    std::thread worker([&] {
        auto result = ovstorage::sync_wait(handle.list_address_roots(&cancel));
        if (result) {
            root_count = result.value().size();
        } else {
            observed = result.error().code();
        }
        worker_returned.store(true, std::memory_order_release);
    });

    g_park_wait_arrived();  // deterministic rendezvous: the slot has parked

    bool ok = true;
    if (worker_returned.load(std::memory_order_acquire)) {
        std::fputs("parked discovery completed before cancel\n", stderr);
        ok = false;
    }

    // Unrelated work progresses on this thread while the discovery is parked.
    auto info = ovstorage::sync_wait(handle.stat("park://data/a.bin"));
    if (!info) {
        std::fprintf(stderr, "sibling stat failed while parked: %s\n",
            info.error().message().c_str());
        ok = false;
    } else if (info.value().address() != "park://data/a.bin") {
        std::fputs("sibling stat returned the wrong object\n", stderr);
        ok = false;
    }

    cancel.cancel();
    worker.join();

    if (observed != OvStorage_Status_Cancelled) {
        std::fprintf(stderr,
            "cancelled discovery observed status %d, want Cancelled (%d)\n",
            static_cast<int>(observed),
            static_cast<int>(OvStorage_Status_Cancelled));
        ok = false;
    }
    if (root_count != 0) {
        std::fputs("a cancelled discovery must not deliver a list\n", stderr);
        ok = false;
    }

    // `handle` is destroyed here: destructible after a cancelled parked op.
    return ok;
}

// Scenario B — release a parked discovery. Proves the slot is reusable: a
// freshly imported root drives it to a NORMAL completion once released.
bool run_release_while_parked()
{
    auto imported = import_parked_root();
    if (!imported) {
        std::fprintf(stderr, "import of the parked root failed: %s\n",
            imported.error().message().c_str());
        return false;
    }
    ovstorage::LayerHandle handle = std::move(imported).value();

    std::atomic<bool> worker_returned{false};
    bool succeeded = false;
    std::size_t root_count = 0;

    std::thread worker([&] {
        auto result = ovstorage::sync_wait(handle.list_address_roots());
        if (result) {
            succeeded = true;
            root_count = result.value().size();
        }
        worker_returned.store(true, std::memory_order_release);
    });

    g_park_wait_arrived();

    bool ok = true;
    if (worker_returned.load(std::memory_order_acquire)) {
        std::fputs("parked discovery completed before release\n", stderr);
        ok = false;
    }

    g_release_park_gate();
    worker.join();

    if (!succeeded) {
        std::fputs("released discovery did not complete normally\n", stderr);
        ok = false;
    }
    if (root_count != 1) {
        std::fprintf(stderr, "released discovery returned %zu roots, want 1\n",
            root_count);
        ok = false;
    }

    return ok;
}

}  // namespace

// Entry point: `fixture_path` is the workspace `ovstorage-plugin-test-abi`
// cdylib, located and skip-gated by roundtrip.rs. Returns 0 on success.
extern "C" int ovstorage_c_source_stack_build_parked_cpp(const char* fixture_path);

extern "C" int ovstorage_c_source_stack_build_parked_cpp(const char* fixture_path)
{
    if (fixture_path == nullptr) {
        std::fputs("fixture path is null\n", stderr);
        return 1;
    }
    // RTLD_LOCAL so the fixture's own bundled plugin-SDK symbols never
    // interpose the statically-linked pure-C runtime.
    void* fixture = dlopen(fixture_path, RTLD_NOW | RTLD_LOCAL);
    if (fixture == nullptr) {
        std::fprintf(stderr, "dlopen(%s): %s\n", fixture_path, dlerror());
        return 1;
    }
    g_export_parked = reinterpret_cast<ExportParkedFn>(
        dlsym(fixture, "ovstorage_test_export_parked_stack"));
    g_park_wait_arrived = reinterpret_cast<ParkVoidFn>(
        dlsym(fixture, "ovstorage_test_park_wait_arrived"));
    g_release_park_gate = reinterpret_cast<ParkVoidFn>(
        dlsym(fixture, "ovstorage_test_release_park_gate"));
    if (g_export_parked == nullptr || g_park_wait_arrived == nullptr ||
        g_release_park_gate == nullptr) {
        std::fputs("dlsym of a fixture export failed\n", stderr);
        return 1;
    }

    // The fixture (and the imported roots it produces) may be referenced by
    // the process-global runtime, so it is never dlclose'd — it stays mapped
    // for process lifetime, matching the sibling drivers.
    constexpr int kIterations = 25;
    for (int i = 0; i < kIterations; ++i) {
        if (!run_cancel_while_parked()) {
            std::fprintf(stderr, "cancel-while-parked failed on iteration %d\n", i);
            return 1;
        }
        if (!run_release_while_parked()) {
            std::fprintf(stderr, "release-while-parked failed on iteration %d\n", i);
            return 1;
        }
    }

    return 0;
}
