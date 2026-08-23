// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Runtime regression coverage: `ovstorage::sync_wait` must not let the
// completing thread touch its mutex/condition_variable after the waiting
// thread has returned and destroyed them.
//
// THE WINDOW
// ----------
// `sync_wait` keeps the slot, mutex and condition_variable as locals and
// hands pointers to them to a `fire_and_forget` runner that completes on
// whichever thread the C callback fired on. If the runner publishes the
// result and then touches the condition_variable or the mutex outside the
// waiter's ownership, the waiter can observe the predicate, return, and run
// `~condition_variable` / `~mutex` on those locals while the runner is still
// inside them.
//
// No spurious wakeup is needed to reach it. `cv.wait(lk, pred)` evaluates the
// predicate BEFORE blocking, so if the runner publishes while the waiter is
// still between "start sync_wait" and "call wait", the waiter never blocks at
// all: it takes the lock, sees the result, returns, and tears the locals down
// immediately — while the runner is still on its way to `notify_all`.
//
// HOW THIS DRIVES IT
// ------------------
// Each iteration completes from a foreign thread that has ALREADY been
// released before `sync_wait` is entered, so the publish lands in that
// narrow pre-wait region as often as the scheduler allows. Background
// threads add scheduling pressure so the completing thread is more likely to
// be descheduled between publishing and finishing with the primitives, which
// is the interleaving that faults.
//
// WHAT CATCHES IT
// ---------------
// AddressSanitizer's use-after-scope instrumentation. `sync_wait`'s locals
// are poisoned the moment it returns, so any later access from the
// completing thread is reported as stack-use-after-scope rather than
// silently corrupting whatever reuses that stack. The Rust runner launches
// this under a timeout and fails on a non-zero exit, so a fault, a hang, or
// an ASan report all surface.

#include "ovstorage.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_stop{false};
std::atomic<int> g_outstanding{0};

// Stand-in for a per-method awaiter. It reuses the real `awaiter_base`
// plumbing — the typed body handle, the heap awaiter state, the leaked
// user_data ref, `commit_suspend` and `deliver` — and completes from a
// detached thread, exactly as a C-ABI callback on a runtime worker does.
struct racing_awaiter : ovstorage::detail::awaiter_base<int> {
    bool await_suspend(body_handle h)
    {
        s->continuation = h;
        void* user_data = release_user_data();
        g_outstanding.fetch_add(1, std::memory_order_relaxed);
        std::thread([user_data] {
            auto state = reclaim_state(user_data);
            state->outcome = ovstorage::Result<int>::success(7);
            deliver(state);
            g_outstanding.fetch_sub(1, std::memory_order_release);
        }).detach();
        return commit_suspend(h);
    }
};

ovstorage::task<int> completes_from_a_foreign_thread()
{
    racing_awaiter a{};
    co_return co_await a;
}

}  // namespace

int main()
{
    // Scheduling pressure widens the interval in which a completing thread
    // can be descheduled between publishing its result and finishing with
    // the caller's synchronization primitives.
    std::vector<std::thread> noise;
    const unsigned noise_threads =
        std::max(2u, std::thread::hardware_concurrency());
    for (unsigned i = 0; i < noise_threads; ++i) {
        noise.emplace_back([] {
            while (!g_stop.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
        });
    }

    constexpr int kIterations = 20000;
    for (int i = 0; i < kIterations; ++i) {
        auto result = ovstorage::sync_wait(completes_from_a_foreign_thread());
        if (!result || result.value() != 7) {
            std::fprintf(stderr, "sync_wait returned the wrong outcome at %d\n", i);
            g_stop.store(true, std::memory_order_relaxed);
            for (auto& t : noise) t.join();
            return 1;
        }
    }

    g_stop.store(true, std::memory_order_relaxed);
    for (auto& t : noise) {
        t.join();
    }
    // Let every completing thread finish before the process exits, so a
    // LeakSanitizer report is about the wrapper and not about this driver.
    while (g_outstanding.load(std::memory_order_acquire) != 0) {
        std::this_thread::yield();
    }

    std::puts("cpp20_sync_wait_destroy_race: ok");
    return 0;
}
