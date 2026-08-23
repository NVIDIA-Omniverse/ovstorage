// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Toolchain probe: does THIS compiler emit coroutine frames that can be
// resumed from another thread without racing the frame's own bookkeeping?
//
// This file includes NO ovstorage header on purpose. It is a verdict about the
// compiler, not about the wrapper, and it must stay readable as such: if it
// reports a race, no amount of reading `ovstorage.hpp` will explain it.
//
// WHAT IT PINS
// ------------
// GCC 15 adds a 16-bit `_Coro_frame_refcount` to every coroutine frame and
// manipulates it NON-ATOMICALLY from both halves of the coroutine:
//
//     ramp:   refcount = 1;  actor(frame);  refcount -= 1;  if (0) delete frame
//     actor:  (initial entry)  refcount += 1;
//             (final suspend)  refcount -= 1;  if (0) delete frame
//
// A coroutine that publishes its handle from inside `await_suspend` — the only
// conforming place for a callback-driven awaiter to hand its continuation to
// whatever will complete it — lets the resuming thread run the actor's
// decrement while the ramp thread is still executing its own. Two threads, one
// plain 16-bit read-modify-write, no synchronization between them. TSAN reports
// a 2-byte data race inside the coroutine at the `co_await`, attributed to the
// frame's heap block.
//
// The consequence is not merely formal: a lost decrement means both sides read
// the same value and write the same result, the refcount never reaches zero,
// and the frame is leaked.
//
// OBSERVED FRAME LAYOUT
// ---------------------
// The field TSAN names is easy to misread as `_Coro_resume_index`, which sits
// two bytes before it and is what a reader reaching for "the 2-byte field near
// the top of a coroutine frame" will guess. Recorded here so a future reader
// need not re-derive it from DWARF (`readelf --debug-dump=info`, look for the
// `..._ZN...Ev.Frame` struct GCC synthesizes per coroutine). Observed for
// `publishes_during_the_ramp` below, g++ 15.2.0, x86_64, `-O1 -g`:
//
//    0  _Coro_resume_fn                    (8)
//    8  _Coro_destroy_fn                   (8)
//   16  _Coro_promise                      (2)
//   18  _Coro_resume_index                 (2)   <- NOT this one
//   20  _Coro_frame_refcount               (2)   <- the racing field
//   22  _Coro_frame_needs_free             (1)
//   23  _Coro_initial_await_resume_called  (1)
//   24  ...awaiter/temporary slots...            frame size 32
//
// So the address TSAN reports is the frame's heap block + 20. Confirm with
// arithmetic on the report ("Read of size 2 at ADDR" minus "Location is heap
// block ... at BASE") rather than by trusting the field name in any prose,
// including this comment: the offsets move with the coroutine's body.
//
// WHAT THE TWO LOOPS PROVE
// ------------------------
// Both loops hand a suspended handle to the SAME worker thread through the SAME
// release-store / acquire-load pair, so both have a proper happens-before edge
// on the handle itself and neither can be blamed on "resuming across threads is
// racy". The loops differ in exactly one way: WHERE the handle is published.
//
//   * Loop B, the control, runs first. Its awaiter is a plain
//     `std::suspend_always`; the ramp returns the handle to `main`, which
//     publishes only after the ramp — including its refcount decrement — has
//     finished. Clean on every toolchain.
//   * Loop A is the racy shape. Its awaiter release-stores the handle from
//     inside `await_suspend`, so the worker can be resuming, running to final
//     suspend and decrementing the refcount while the ramp is still returning.
//
// Running the control first means an affected toolchain fails with the
// difference already on screen: the control's "ok" line, then the report from
// loop A. That ordering is deliberate — under `halt_on_error=1` an affected
// toolchain exits within the first handful of loop-A iterations, so a control
// placed second would never run at all.

#include <atomic>
#include <coroutine>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {

// The suspended handle in flight between the publishing thread and the worker.
// The worker CONSUMES it with an exchange rather than clearing it afterwards,
// so a worker looping back cannot re-read a handle it already resumed.
std::atomic<void*> g_slot{nullptr};
std::atomic<unsigned long> g_resumed{0};
std::atomic<unsigned long> g_completed{0};
std::atomic<bool> g_stop{false};

// Detached-completion coroutine: no handle handed back to the caller, frame
// self-destroyed at final suspend by whichever thread resumed it. This is the
// shape every callback-driven awaiter ends up with.
struct fire_and_forget {
    struct promise_type {
        fire_and_forget get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::abort(); }
    };
};

// Loop A's awaiter: publishes from inside `await_suspend`, exactly as an
// awaiter must when the thing that completes it needs the continuation before
// the suspending thread regains control.
struct publishes_from_await_suspend {
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> h) const noexcept
    {
        g_slot.store(h.address(), std::memory_order_release);
    }
    void await_resume() const noexcept {}
};

fire_and_forget publishes_during_the_ramp()
{
    co_await publishes_from_await_suspend{};
    g_resumed.fetch_add(1, std::memory_order_relaxed);
}

// Loop B's coroutine hands its handle back so `main` can publish it after the
// ramp has fully returned. Suspending on `std::suspend_always` keeps the body
// parked until then.
struct deferred {
    struct promise_type {
        deferred get_return_object() noexcept
        {
            return deferred{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::abort(); }
    };

    std::coroutine_handle<> handle;
};

deferred parks_until_the_ramp_returns()
{
    co_await std::suspend_always{};
    g_resumed.fetch_add(1, std::memory_order_relaxed);
}

// Resume whatever appears in the slot. The acquire on the exchange pairs with
// the release store on the publishing side, so the handle itself — and
// everything the publisher wrote before it — is properly synchronized. Any race
// TSAN reports is therefore about state the compiler touches OUTSIDE this edge.
void worker()
{
    unsigned long done = 0;
    while (true) {
        void* address = g_slot.exchange(nullptr, std::memory_order_acquire);
        if (address == nullptr) {
            if (g_stop.load(std::memory_order_acquire)) {
                return;
            }
            std::this_thread::yield();
            continue;
        }
        std::coroutine_handle<>::from_address(address).resume();
        ++done;
        // Publish the completion count last, so the driver's wait below is an
        // acquire on everything this iteration did.
        g_completed.store(done, std::memory_order_release);
    }
}

// Block until the worker has finished `count` resumptions.
void await_completions(unsigned long count)
{
    while (g_completed.load(std::memory_order_acquire) < count) {
        std::this_thread::yield();
    }
}

// The interleaving needs the worker to reach final suspend before the ramp
// finishes its own decrement, so a single iteration is not enough. The count is
// a margin/cost trade: the expensive error is a false "race-free" verdict, and
// this binary is also RUN at build time, so a race-free toolchain pays the full
// two loops on every build. Measured here (g++ 15.2.0, x86_64):
//
//   * affected toolchain, `halt_on_error=1` — halts in the first handful of
//     loop-A iterations, ~0.05s total. 5/5 at this count, and also 3/3 at 4000,
//     so the window is hit almost immediately rather than rarely.
//   * running both loops to completion under TSAN — ~3.4s. ~20ms without TSAN.
//
// Raising the count past this buys little: an affected toolchain trips on its
// first concurrent iteration, and the case no count can rescue is a host that
// never runs the worker concurrently at all.
constexpr unsigned long kIterations = 8000;

// EXIT CODE CONTRACT
// ------------------
// `build.rs` runs this binary to derive a toolchain verdict, so the exit code
// has to separate "the toolchain is racy" from "this probe did not work". With
// `TSAN_OPTIONS=...:exitcode=1`:
//
//   0  both loops completed with no report  -> race-free
//   1  TSAN halted on a report              -> SEE BELOW; only sometimes racy
//   2  the probe's own self-check failed    -> unknown; the verdict means nothing
//
// Anything else (a signal, a crash) is also "unknown" to the caller. Keep the
// self-check off 1 so a broken probe can never be read as a toolchain verdict.
constexpr int kSelfCheckFailed = 2;

// OUTPUT CONTRACT — why exit 1 alone is not the verdict
// -----------------------------------------------------
// `exitcode=1` is what TSAN exits with for ANY report or runtime failure: a
// race in libstdc++, a race the control loop provoked, a startup failure like
// "unexpected memory mapping". Reading a bare 1 as "this compiler races its
// coroutine frames" would let any of those disable ThreadSanitizer for the
// sync_wait regression and print a confident, wrong diagnosis about the
// compiler — the same species of mistake this probe exists to correct.
//
// So a caller must confirm the report is THIS one, from the output:
//
//   * stdout contains kControlOkMarker below — the control loop ran to
//     completion, so whatever TSAN halted on came after it and is not the
//     control's.
//   * stderr names a "data race" of size 2 in `publishes_during_the_ramp`,
//     which is the racy loop's coroutine and the width of the frame refcount.
//
// `build.rs` and `tests/roundtrip.rs` match these as string literals. There is
// deliberately no `kRacyFunctionMarker` constant here to pair with the one
// below: nothing in this file could reference it, so it would be dead — which
// Clang rejects under the `-Wall -Werror` this probe is built with, and which
// would not catch a rename of the coroutine either. The Rust side enforces
// both markers against this source instead; see
// `cpp20_coroutine_frame_probe_markers_match_the_driver` in
// `tests/roundtrip.rs`, which fails if a rename here leaves the matchers
// looking for a string this file no longer contains.
constexpr const char* kControlOkMarker =
    "coroutine_frame_refcount_race: control (publish after the ramp) ok";

}  // namespace

int main()
{
    std::thread w(worker);

    // Control first: publication strictly after the ramp returns.
    for (unsigned long i = 0; i < kIterations; ++i) {
        deferred d = parks_until_the_ramp_returns();
        g_slot.store(d.handle.address(), std::memory_order_release);
        await_completions(i + 1);
    }
    std::puts(kControlOkMarker);
    std::fflush(stdout);

    // The racy shape: publication from inside `await_suspend`.
    for (unsigned long i = 0; i < kIterations; ++i) {
        publishes_during_the_ramp();
        await_completions(kIterations + i + 1);
    }

    g_stop.store(true, std::memory_order_release);
    w.join();

    const unsigned long resumed = g_resumed.load(std::memory_order_relaxed);
    if (resumed != 2 * kIterations) {
        std::fprintf(stderr,
                     "coroutine_frame_refcount_race: %lu of %lu bodies resumed\n",
                     resumed,
                     2 * kIterations);
        return kSelfCheckFailed;
    }

    std::puts("coroutine_frame_refcount_race: ok");
    return 0;
}
