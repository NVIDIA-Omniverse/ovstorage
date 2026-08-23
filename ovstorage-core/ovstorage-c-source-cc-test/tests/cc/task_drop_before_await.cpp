// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Runtime regression coverage: the eager-start `ovstorage::task<T>`
// drop-before-await abandon path must NOT self-destroy the coroutine frame
// from inside `final_awaiter::await_suspend`.
//
// This program exercises the SAME machinery the C ABI drives — `task<T>`, its
// promise/`final_awaiter` abandon state machine, and `detail::awaiter_base`'s
// `commit_suspend`/`deliver` — but with a custom awaiter whose "callback" fires
// from a std::thread instead of a real tokio worker, so it needs no live
// runtime and links against the header alone.
//
// To make the test a DETERMINISTIC exerciser of the abandon path (rather than
// leaving which branch runs to a timing race), each iteration uses a
// per-iteration handshake: the consumer creates the eager task, drops it
// WITHOUT awaiting, and only THEN releases the worker to fire its callback. So
// `~task` always runs while the body is suspended at the in-flight callback,
// writing promise state 3; the worker then runs the abandoned body to
// `final_suspend`, which takes the state==3 path every time. `g_abandon_taken`
// counts those iterations and `main` asserts it equals the iteration count.
//
// `final_awaiter::await_suspend` must not call `h.destroy()` on its own frame
// mid symmetric-transfer — freeing a coroutine from inside its own suspension
// machinery is UB. Whether it FAULTS is codegen-dependent: on toolchains where
// AddressSanitizer's instrumented frame teardown pokes the freed frame after
// the transfer point, the worker's `resume()` never returns (a hang); on
// GCC 14 / clang 22 here nothing touches the frame post-destroy, so such a
// build appears benign. This driver therefore does NOT claim to reproduce the
// hang on every toolchain; it guards the abandon path along every dimension
// ASan can see:
//   * Leak — with the handshake forcing the abandon path every iteration, the
//     orphaned frame MUST be reclaimed by `detail::deliver` after `resume()`
//     unwinds. If the fix ever stops reclaiming (parks without freeing),
//     LeakSanitizer reports the orphaned coroutine frames at exit. This is the
//     load-bearing assertion: it proves the reclaim ran for every abandon.
//   * Use-after-free / double-free — ASan flags them if the reclaim path
//     mishandles frame ownership.
//   * Hang — the worker for each iteration decrements an outstanding counter
//     only after `on_complete` returns, and the iteration waits for zero, so a
//     worker wedged inside `resume()` (the reporter's symptom, on toolchains
//     that exhibit it) hangs the process and the launching Rust test times out.

#include "ovstorage.hpp"

#include <atomic>
#include <condition_variable>
#include <coroutine>
#include <cstdio>
#include <mutex>
#include <thread>

#if defined(_WIN32) && defined(_MSC_VER)
#include <crtdbg.h>
#endif

namespace {

// Per-iteration handshake: the worker blocks until the consumer signals it has
// dropped the task, so the abandon (state==3) path is taken deterministically.
struct Handshake {
    std::mutex m;
    std::condition_variable cv;
    bool dropped = false;

    void wait_for_drop()
    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [this] { return dropped; });
    }
    void signal_dropped()
    {
        {
            std::lock_guard<std::mutex> lk(m);
            dropped = true;
        }
        cv.notify_one();
    }
};

// Iterations whose worker observed the drop and drove the state==3 abandon
// path (incremented right before `deliver`, once the drop is guaranteed).
std::atomic<long> g_abandon_taken{0};
// Workers still running (a wedged worker never decrements → the drain hangs).
std::atomic<int> g_outstanding{0};

// A stand-in for a per-method awaiter (`detail::info_awaiter`, ...). It reuses
// the real `awaiter_base` plumbing — the typed `body_handle`, heap awaiter
// state, the leaked user_data ref, `commit_suspend`, `deliver` — and simulates
// the C ABI's cross-thread `on_complete` with a detached std::thread gated on
// the handshake.
struct test_awaiter : ovstorage::detail::awaiter_base<int> {
    Handshake* handshake;
    explicit test_awaiter(Handshake* hs) : handshake(hs) {}

    // Takes the TYPED body handle (see awaiter_base::body_handle): a mismatched
    // awaiter/task pairing would not compile here.
    bool await_suspend(body_handle h)
    {
        s->continuation = h;
        void* user_data = release_user_data();
        Handshake* hs = handshake;
        g_outstanding.fetch_add(1, std::memory_order_relaxed);
        std::thread([user_data, hs] {
            hs->wait_for_drop();
            on_complete(user_data);
            g_outstanding.fetch_sub(1, std::memory_order_relaxed);
        }).detach();
        return commit_suspend(h);
    }

    // Mirrors a real on_complete thunk: reclaim the leaked state, populate the
    // outcome, and drive the resume/abandon state machine. The consumer has
    // dropped by now (handshake), so this iteration takes the state==3 path.
    static void on_complete(void* user_data)
    {
        auto state = reclaim_state(user_data);
        state->outcome = ovstorage::Result<int>::success(42);
        g_abandon_taken.fetch_add(1, std::memory_order_relaxed);
        deliver(state);
    }
};

ovstorage::task<int> make_task(Handshake* handshake)
{
    co_return co_await test_awaiter{handshake};
}

}  // namespace

int main()
{
#if defined(_WIN32) && defined(_MSC_VER)
    // MSVC AddressSanitizer has no leak detector. The CRT debug heap is what
    // catches an unreclaimed coroutine frame — the load-bearing assertion
    // this driver exists to make on Windows.
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
#endif
    // Enough iterations to shake out any ordering-dependent hazard under ASan.
    constexpr int kIterations = 4000;
    for (int i = 0; i < kIterations; ++i) {
        Handshake handshake;
        // Eager-start the task; it suspends at the awaiter with a worker parked
        // on the handshake. Drop it WITHOUT awaiting, then release the worker:
        // `~task` marks the promise abandoned before `on_complete` fires, so the
        // worker's final_awaiter takes the state==3 path.
        { ovstorage::task<int> abandoned = make_task(&handshake); }
        handshake.signal_dropped();
        // Join this iteration's worker before `handshake` leaves scope (the
        // worker holds a pointer to it). A worker wedged in resume() never
        // decrements, so this spin — and the process — hangs, which the
        // launching Rust test surfaces as a timeout failure.
        while (g_outstanding.load(std::memory_order_relaxed) != 0) {
            std::this_thread::yield();
        }
    }

    if (g_abandon_taken.load(std::memory_order_relaxed) != kIterations) {
        std::fprintf(
            stderr,
            "abandon path taken %ld/%d times — the handshake did not force the "
            "state==3 path\n",
            g_abandon_taken.load(std::memory_order_relaxed), kIterations);
        return 1;
    }

    std::puts("cpp20_task_drop_before_await_no_uaf: ok");
#if defined(_WIN32) && defined(_MSC_VER)
    if (_CrtDumpMemoryLeaks() != 0) {
        std::fputs("CRT debug heap reported leaks\n", stderr);
        return 1;
    }
#endif
    return 0;
}
