// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Runtime regression: dropping an eager `ovstorage::task<T>`
// after its callback worker reaches final_suspend must not destroy the
// coroutine frame until the worker's body.resume() call has fully unwound.

#include <atomic>

namespace task_race_test {
void final_suspend_hook(int previous_state, std::atomic<int>& promise_state) noexcept;
void before_resume_context_release_hook() noexcept;
}

// Park the worker immediately after route_final_suspend publishes state=2.
// This makes the worker-parks-first ordering deterministic and leaves the
// worker executing against the promise while the consumer drops the task.
#define OVSTORAGE_DETAIL_TASK_FINAL_SUSPEND_TEST_HOOK(previous_state, promise_state) \
    ::task_race_test::final_suspend_hook(previous_state, promise_state)
#define OVSTORAGE_DETAIL_BEFORE_RESUME_CONTEXT_RELEASE_TEST_HOOK() \
    ::task_race_test::before_resume_context_release_hook()
#include "ovstorage.hpp"
#undef OVSTORAGE_DETAIL_BEFORE_RESUME_CONTEXT_RELEASE_TEST_HOOK
#undef OVSTORAGE_DETAIL_TASK_FINAL_SUSPEND_TEST_HOOK

#include <condition_variable>
#include <coroutine>
#include <cstdio>
#include <mutex>
#include <thread>

#if defined(_WIN32) && defined(_MSC_VER)
#include <crtdbg.h>
#endif

namespace task_race_test {

struct Handshake {
    std::mutex mutex;
    std::condition_variable cv;
    bool start_worker = false;
    bool worker_parked = false;
    bool task_dropped = false;
    bool worker_done = false;
    bool promise_survived_drop = false;
    bool park_final_suspend = true;
    bool park_context_release = false;
    bool context_release_parked = false;
    bool release_context = false;

    void wait_for_start()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return start_worker; });
    }

    void signal_start()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            start_worker = true;
        }
        cv.notify_all();
    }

    void wait_for_worker_park()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return worker_parked; });
    }

    void park_at_final_suspend(std::atomic<int>& promise_state)
    {
        std::unique_lock<std::mutex> lock(mutex);
        worker_parked = true;
        cv.notify_all();
        cv.wait(lock, [this] { return task_dropped; });

        // The destructor marks the task abandoned and defers frame
        // destruction to deliver(), so the promise is still live here. A
        // destructor that freed the frame itself would make this a
        // use-after-free (caught by ASan), or leave state=2 without ASan.
        promise_survived_drop =
            promise_state.load(std::memory_order_acquire) == 3;
    }

    void signal_drop()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            task_dropped = true;
        }
        cv.notify_all();
    }

    void signal_worker_done()
    {
        std::lock_guard<std::mutex> lock(mutex);
        worker_done = true;
        cv.notify_all();
    }

    void wait_for_worker_done()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return worker_done; });
    }

    void park_before_context_release()
    {
        if (!park_context_release) return;
        std::unique_lock<std::mutex> lock(mutex);
        context_release_parked = true;
        cv.notify_all();
        cv.wait(lock, [this] { return release_context; });
    }

    void wait_for_context_release_park()
    {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return context_release_parked; });
    }

    void signal_context_release()
    {
        {
            std::lock_guard<std::mutex> lock(mutex);
            release_context = true;
        }
        cv.notify_all();
    }
};

thread_local Handshake* current_handshake = nullptr;

void final_suspend_hook(
    int previous_state,
    std::atomic<int>& promise_state) noexcept
{
    if (previous_state == 0 && current_handshake != nullptr &&
        current_handshake->park_final_suspend) {
        current_handshake->park_at_final_suspend(promise_state);
    }
}

void before_resume_context_release_hook() noexcept
{
    if (current_handshake != nullptr) {
        current_handshake->park_before_context_release();
    }
}

template <class Out>
struct test_awaiter : ovstorage::detail::awaiter_base<Out> {
    Handshake* handshake;
    explicit test_awaiter(Handshake* value) : handshake(value) {}

    bool await_suspend(typename test_awaiter::body_handle body)
    {
        this->s->continuation = body;
        void* user_data = this->release_user_data();
        Handshake* worker_handshake = handshake;
        std::thread([user_data, worker_handshake] {
            worker_handshake->wait_for_start();
            current_handshake = worker_handshake;
            on_complete(user_data);
            current_handshake = nullptr;
            worker_handshake->signal_worker_done();
        }).detach();
        return this->commit_suspend(body);
    }

    static void on_complete(void* user_data)
    {
        auto state = test_awaiter::reclaim_state(user_data);
        if constexpr (std::is_void_v<Out>) {
            state->outcome = ovstorage::Result<void>::success();
        } else {
            state->outcome = ovstorage::Result<Out>::success(42);
        }
        test_awaiter::deliver(state);
    }
};

ovstorage::task<int> make_int_task(Handshake* handshake)
{
    co_return co_await test_awaiter<int>{handshake};
}

ovstorage::task<void> make_void_task(Handshake* handshake)
{
    co_return co_await test_awaiter<void>{handshake};
}

ovstorage::task<int> make_nested_int_task(Handshake* handshake)
{
    co_return co_await make_int_task(handshake);
}

ovstorage::task<void> make_nested_void_task(Handshake* handshake)
{
    co_return co_await make_void_task(handshake);
}

ovstorage::task<int> make_sequential_int_task(
    Handshake* first,
    Handshake* second)
{
    auto first_result = co_await make_int_task(first);
    if (!first_result) co_return first_result;
    co_return co_await make_int_task(second);
}

struct manual_awaiter {
    std::coroutine_handle<> continuation;

    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) noexcept
    {
        continuation = handle;
    }
    void await_resume() const noexcept {}
    void resume() const { continuation.resume(); }
};

ovstorage::task<int> suspend_on_manual_awaiter(
    Handshake* handshake,
    manual_awaiter* manual)
{
    auto result = co_await make_int_task(handshake);
    co_await *manual;
    co_return result;
}

ovstorage::task<int> wrap_task(ovstorage::task<int> inner)
{
    co_return co_await inner;
}

template <class Factory>
bool run_worker_first_drop(Factory&& factory)
{
    Handshake handshake;
    {
        auto task = factory(&handshake);
        handshake.signal_start();
        handshake.wait_for_worker_park();
    }
    handshake.signal_drop();
    handshake.wait_for_worker_done();
    return handshake.promise_survived_drop;
}

bool run_sequential_worker_handoff()
{
    Handshake first;
    Handshake second;
    first.park_final_suspend = false;
    second.park_final_suspend = false;
    first.park_context_release = true;

    auto task = make_sequential_int_task(&first, &second);
    first.signal_start();
    first.wait_for_context_release_park();
    second.signal_start();
    second.wait_for_worker_done();
    first.signal_context_release();
    first.wait_for_worker_done();

    auto result = ovstorage::sync_wait(std::move(task));
    return result && result.value() == 42;
}

bool run_manual_resume_after_context_release()
{
    Handshake handshake;
    handshake.park_final_suspend = false;
    manual_awaiter manual;

    auto inner = suspend_on_manual_awaiter(&handshake, &manual);
    auto inner_handle = inner.handle();
    auto outer = wrap_task(std::move(inner));
    handshake.signal_start();
    handshake.wait_for_worker_done();

    if (inner_handle.promise().active_resume_context != nullptr) return false;
    manual.resume();
    auto result = ovstorage::sync_wait(std::move(outer));
    return result && result.value() == 42;
}

}  // namespace task_race_test

int main()
{
#if defined(_WIN32) && defined(_MSC_VER)
    // MSVC AddressSanitizer has no leak detector. The CRT debug heap is what
    // catches an unreclaimed coroutine frame — the load-bearing assertion
    // this driver exists to make on Windows.
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF);
#endif
    constexpr int kIterations = 100;
    for (int i = 0; i < kIterations; ++i) {
        if (!task_race_test::run_worker_first_drop(task_race_test::make_int_task)) {
            std::fputs("task<int> promise did not survive worker-first drop\n", stderr);
            return 1;
        }
        if (!task_race_test::run_worker_first_drop(task_race_test::make_void_task)) {
            std::fputs("task<void> promise did not survive worker-first drop\n", stderr);
            return 1;
        }
        if (!task_race_test::run_worker_first_drop(
                task_race_test::make_nested_int_task)) {
            std::fputs(
                "nested task<int> promise did not survive worker-first drop\n",
                stderr);
            return 1;
        }
        if (!task_race_test::run_worker_first_drop(
                task_race_test::make_nested_void_task)) {
            std::fputs(
                "nested task<void> promise did not survive worker-first drop\n",
                stderr);
            return 1;
        }
        if (!task_race_test::run_sequential_worker_handoff()) {
            std::fputs("sequential task awaits corrupted resume ownership\n", stderr);
            return 1;
        }
        if (!task_race_test::run_manual_resume_after_context_release()) {
            std::fputs("manual resume observed a dangling resume context\n", stderr);
            return 1;
        }
    }

    std::puts("cpp20_task_drop_after_worker_park_no_uaf: ok");
#if defined(_WIN32) && defined(_MSC_VER)
    if (_CrtDumpMemoryLeaks() != 0) {
        std::fputs("CRT debug heap reported leaks\n", stderr);
        return 1;
    }
#endif
    return 0;
}
