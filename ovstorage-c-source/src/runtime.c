/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Process-global worker runtime for the pure-C ovstorage implementation.
 */

#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct ovc_runtime_task ovc_runtime_task;
typedef struct ovc_runtime_pool ovc_runtime_pool;

#if defined(OVC_RUNTIME_TEST_MAIN) || \
    defined(OVC_RUNTIME_TEST_QUIESCENCE)
#define OVC_RUNTIME_TRACK_QUIESCENCE 1
#endif

struct ovc_runtime_task {
    ovc_runtime_task_fn function;
    void *argument;
    ovc_runtime_task *next;
};

struct ovc_runtime_pool {
    ovc_mutex mutex;
    ovc_cond work_available;
#if defined(OVC_RUNTIME_TRACK_QUIESCENCE)
    ovc_cond idle;
    size_t outstanding_tasks;
#endif
    ovc_runtime_task *head;
    ovc_runtime_task *tail;
    uint32_t worker_count;

    /* Used only to roll back an unpublished, partially-created pool. */
    int stop_startup;
};

/*
 * The initialization mutex defines which concurrent ensure call wins.  The
 * pool pointer is published only after every worker exists and is detached.
 * It is never cleared or freed, so readers may keep a copied pointer after
 * releasing this mutex.
 */
static ovc_mutex g_ovc_runtime_init_mutex = OVC_MUTEX_INITIALIZER;
static ovc_runtime_pool *g_ovc_runtime_pool;

static void ovc_runtime_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

static int ovc_runtime_thread_detach(ovc_thread *thread)
{
    if (thread == NULL || !thread->joinable) {
        return EINVAL;
    }

#if defined(_WIN32)
    if (!CloseHandle(thread->handle)) {
        return (int)GetLastError();
    }
    thread->handle = NULL;
    thread->joinable = 0;
    return 0;
#else
    {
        int result;

        result = pthread_detach(thread->handle);
        if (result == 0) {
            thread->joinable = 0;
        }
        return result;
    }
#endif
}

static int ovc_runtime_parse_thread_count(const char *value,
                                          uint32_t *thread_count)
{
    uint32_t parsed;
    const unsigned char *cursor;

    if (value == NULL || value[0] == '\0' || thread_count == NULL) {
        return 0;
    }

    parsed = 0;
    cursor = (const unsigned char *)value;
    do {
        uint32_t digit;

        if (*cursor < (unsigned char)'0' ||
            *cursor > (unsigned char)'9') {
            return 0;
        }
        digit = (uint32_t)(*cursor - (unsigned char)'0');
        if (parsed > (UINT32_MAX - digit) / UINT32_C(10)) {
            return 0;
        }
        parsed = parsed * UINT32_C(10) + digit;
        ++cursor;
    } while (*cursor != '\0');

    if (parsed == 0) {
        return 0;
    }
    *thread_count = parsed;
    return 1;
}

uint32_t ovc_runtime_resolve_threads(uint32_t requested,
                                     const char *env_value_string,
                                     uint32_t hw_parallelism)
{
    uint32_t environment_threads;

    if (requested != 0) {
        return requested;
    }
    if (ovc_runtime_parse_thread_count(env_value_string,
                                       &environment_threads)) {
        return environment_threads;
    }
    if (hw_parallelism < UINT32_C(2)) {
        return UINT32_C(2);
    }
    if (hw_parallelism > UINT32_C(32)) {
        return UINT32_C(32);
    }
    return hw_parallelism;
}

static void ovc_runtime_worker(void *argument)
{
    ovc_runtime_pool *pool;

    pool = (ovc_runtime_pool *)argument;
    for (;;) {
        ovc_runtime_task *task;

        ovc_runtime_sync_success(ovc_mutex_lock(&pool->mutex));
        while (pool->head == NULL && !pool->stop_startup) {
            ovc_runtime_sync_success(
                ovc_cond_wait(&pool->work_available, &pool->mutex));
        }
        if (pool->head == NULL && pool->stop_startup) {
            ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));
            return;
        }

        task = pool->head;
        pool->head = task->next;
        if (pool->head == NULL) {
            pool->tail = NULL;
        }
        ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));

        task->function(task->argument);
        free(task);
#if defined(OVC_RUNTIME_TRACK_QUIESCENCE)
        ovc_runtime_sync_success(ovc_mutex_lock(&pool->mutex));
        if (pool->outstanding_tasks == 0) {
            ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));
            abort();
        }
        --pool->outstanding_tasks;
        if (pool->outstanding_tasks == 0) {
            ovc_runtime_sync_success(ovc_cond_broadcast(&pool->idle));
        }
        ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));
#endif
    }
}

static void ovc_runtime_pool_destroy_unpublished(ovc_runtime_pool *pool)
{
#if defined(OVC_RUNTIME_TRACK_QUIESCENCE)
    ovc_runtime_sync_success(ovc_cond_destroy(&pool->idle));
#endif
    ovc_runtime_sync_success(ovc_cond_destroy(&pool->work_available));
    ovc_runtime_sync_success(ovc_mutex_destroy(&pool->mutex));
    free(pool);
}

static int ovc_runtime_pool_create(uint32_t worker_count,
                                   ovc_runtime_pool **out_pool)
{
    ovc_runtime_pool *pool;
    ovc_thread *workers;
    size_t worker_bytes;
    size_t worker_slots;
    uint32_t created;
    int result;

    if (worker_count == 0 || out_pool == NULL) {
        return EINVAL;
    }
    *out_pool = NULL;

    pool = (ovc_runtime_pool *)calloc(1, sizeof(*pool));
    if (pool == NULL) {
        return ENOMEM;
    }
    pool->worker_count = worker_count;

    result = ovc_mutex_init(&pool->mutex);
    if (result != 0) {
        free(pool);
        return result;
    }
    result = ovc_cond_init(&pool->work_available);
    if (result != 0) {
        ovc_runtime_sync_success(ovc_mutex_destroy(&pool->mutex));
        free(pool);
        return result;
    }
#if defined(OVC_RUNTIME_TRACK_QUIESCENCE)
    result = ovc_cond_init(&pool->idle);
    if (result != 0) {
        ovc_runtime_sync_success(
            ovc_cond_destroy(&pool->work_available));
        ovc_runtime_sync_success(ovc_mutex_destroy(&pool->mutex));
        free(pool);
        return result;
    }
#endif

    worker_slots = (size_t)worker_count;
    worker_bytes = worker_slots * sizeof(*workers);
    if ((uint32_t)worker_slots != worker_count ||
        worker_bytes / sizeof(*workers) != worker_slots) {
        ovc_runtime_pool_destroy_unpublished(pool);
        return ENOMEM;
    }
    workers = (ovc_thread *)calloc(worker_slots, sizeof(*workers));
    if (workers == NULL) {
        ovc_runtime_pool_destroy_unpublished(pool);
        return ENOMEM;
    }

    created = 0;
    while (created < worker_count) {
        result = ovc_thread_create(&workers[created],
                                   ovc_runtime_worker,
                                   pool);
        if (result != 0) {
            uint32_t index;

            ovc_runtime_sync_success(ovc_mutex_lock(&pool->mutex));
            pool->stop_startup = 1;
            ovc_runtime_sync_success(
                ovc_cond_broadcast(&pool->work_available));
            ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));

            for (index = 0; index < created; ++index) {
                ovc_runtime_sync_success(ovc_thread_join(&workers[index]));
            }
            free(workers);
            ovc_runtime_pool_destroy_unpublished(pool);
            return result;
        }
        ++created;
    }

    /*
     * Once detached, the workers and pool deliberately live until process
     * termination.  POSIX process exit and Win32 ExitProcess do not wait for
     * these workers; queued work is not implicitly drained at exit.  Blocking
     * callers that need a result must use a completion latch before returning.
    */
    for (created = 0; created < worker_count; ++created) {
        /*
         * A successfully-created thread is necessarily joinable here.  Once
         * an earlier worker is detached, a later detach failure cannot be
         * rolled back safely, so treat that impossible handle-state failure
         * like the mutex/condition invariant failures in this module.
         */
        ovc_runtime_sync_success(
            ovc_runtime_thread_detach(&workers[created]));
    }
    free(workers);

    *out_pool = pool;
    return 0;
}

int ovc_runtime_ensure(uint32_t requested)
{
    ovc_runtime_pool *pool;
    uint32_t worker_count;
    unsigned int hardware_parallelism;
    int result;

    ovc_runtime_sync_success(ovc_mutex_lock(&g_ovc_runtime_init_mutex));
    pool = g_ovc_runtime_pool;
    if (pool != NULL) {
        if (requested != 0 && requested != pool->worker_count) {
            (void)fprintf(
                stderr,
                "ovstorage: ovstorage_stack_build ignored "
                "runtime_threads=%lu; the process-global pure-C runtime was "
                "already built with %lu worker thread(s) and is shared by "
                "every Stack, so the new value has no effect.\n",
                (unsigned long)requested,
                (unsigned long)pool->worker_count);
        }
        ovc_runtime_sync_success(
            ovc_mutex_unlock(&g_ovc_runtime_init_mutex));
        return 0;
    }

    if (requested != 0) {
        worker_count =
            ovc_runtime_resolve_threads(requested, NULL, UINT32_C(0));
    } else {
        hardware_parallelism = ovc_cpu_count();
        {
            char *configured;

            errno = 0;
            configured = ovc_env_dup("OVSTORAGE_C_RUNTIME_THREADS");
            if (configured == NULL && errno != 0) {
                ovc_runtime_sync_success(
                    ovc_mutex_unlock(&g_ovc_runtime_init_mutex));
                return ENOMEM;
            }
            worker_count = ovc_runtime_resolve_threads(
                requested,
                configured,
                (uint32_t)(hardware_parallelism > 32U
                               ? 32U
                               : hardware_parallelism));
            free(configured);
        }
    }
    result = ovc_runtime_pool_create(worker_count, &pool);
    if (result == 0) {
        g_ovc_runtime_pool = pool;
    }
    ovc_runtime_sync_success(ovc_mutex_unlock(&g_ovc_runtime_init_mutex));
    return result;
}

uint32_t ovc_runtime_worker_count(void)
{
    uint32_t worker_count;

    ovc_runtime_sync_success(ovc_mutex_lock(&g_ovc_runtime_init_mutex));
    worker_count = g_ovc_runtime_pool == NULL
                       ? 0
                       : g_ovc_runtime_pool->worker_count;
    ovc_runtime_sync_success(ovc_mutex_unlock(&g_ovc_runtime_init_mutex));
    return worker_count;
}

int ovc_runtime_submit(ovc_runtime_task_fn function, void *argument)
{
    ovc_runtime_pool *pool;
    ovc_runtime_task *task;

    if (function == NULL) {
        return EINVAL;
    }

    ovc_runtime_sync_success(ovc_mutex_lock(&g_ovc_runtime_init_mutex));
    pool = g_ovc_runtime_pool;
    ovc_runtime_sync_success(ovc_mutex_unlock(&g_ovc_runtime_init_mutex));
    if (pool == NULL) {
        return EINVAL;
    }

    task = (ovc_runtime_task *)malloc(sizeof(*task));
    if (task == NULL) {
        return ENOMEM;
    }
    task->function = function;
    task->argument = argument;
    task->next = NULL;

    ovc_runtime_sync_success(ovc_mutex_lock(&pool->mutex));
#if defined(OVC_RUNTIME_TRACK_QUIESCENCE)
    if (pool->outstanding_tasks == SIZE_MAX) {
        ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));
        free(task);
        return EOVERFLOW;
    }
    ++pool->outstanding_tasks;
#endif
    if (pool->tail == NULL) {
        pool->head = task;
    } else {
        pool->tail->next = task;
    }
    pool->tail = task;
    ovc_runtime_sync_success(ovc_cond_signal(&pool->work_available));
    ovc_runtime_sync_success(ovc_mutex_unlock(&pool->mutex));
    return 0;
}

#if defined(OVC_RUNTIME_TRACK_QUIESCENCE)
int ovc_runtime_wait_for_idle(uint64_t timeout_ns)
{
    ovc_runtime_pool *pool;
    uint64_t deadline;
    uint64_t now;
    int result;
    int unlock_result;

    ovc_runtime_sync_success(ovc_mutex_lock(&g_ovc_runtime_init_mutex));
    pool = g_ovc_runtime_pool;
    ovc_runtime_sync_success(
        ovc_mutex_unlock(&g_ovc_runtime_init_mutex));
    if (pool == NULL) {
        return EINVAL;
    }

    errno = 0;
    now = ovc_monotonic_ns();
    if (now == 0 && errno != 0) {
        return errno;
    }
    deadline = timeout_ns > UINT64_MAX - now
                   ? UINT64_MAX
                   : now + timeout_ns;

    result = ovc_mutex_lock(&pool->mutex);
    if (result != 0) {
        return result;
    }
    while (pool->outstanding_tasks != 0) {
        uint64_t remaining;

        errno = 0;
        now = ovc_monotonic_ns();
        if (now == 0 && errno != 0) {
            result = errno;
            break;
        }
        if (now >= deadline) {
            result = ETIMEDOUT;
            break;
        }
        remaining = deadline - now;
        result =
            ovc_cond_timedwait_ns(&pool->idle, &pool->mutex, remaining);
        if (result == ETIMEDOUT) {
            if (pool->outstanding_tasks == 0) {
                result = 0;
            }
            break;
        }
        if (result != 0) {
            break;
        }
    }
    unlock_result = ovc_mutex_unlock(&pool->mutex);
    return result != 0 ? result : unlock_result;
}
#endif

int ovc_completion_latch_init(ovc_completion_latch *latch)
{
    int result;

    if (latch == NULL) {
        return EINVAL;
    }
    latch->completed = 0;
    result = ovc_mutex_init(&latch->mutex);
    if (result != 0) {
        return result;
    }
    result = ovc_cond_init(&latch->condition);
    if (result != 0) {
        ovc_runtime_sync_success(ovc_mutex_destroy(&latch->mutex));
        return result;
    }
    return 0;
}

int ovc_completion_latch_complete(ovc_completion_latch *latch)
{
    int result;
    int unlock_result;

    if (latch == NULL) {
        return EINVAL;
    }
    result = ovc_mutex_lock(&latch->mutex);
    if (result != 0) {
        return result;
    }
    latch->completed = 1;
    result = ovc_cond_broadcast(&latch->condition);
    unlock_result = ovc_mutex_unlock(&latch->mutex);
    return result != 0 ? result : unlock_result;
}

int ovc_completion_latch_wait(ovc_completion_latch *latch)
{
    int result;
    int unlock_result;

    if (latch == NULL) {
        return EINVAL;
    }
    result = ovc_mutex_lock(&latch->mutex);
    if (result != 0) {
        return result;
    }
    while (!latch->completed) {
        result = ovc_cond_wait(&latch->condition, &latch->mutex);
        if (result != 0) {
            break;
        }
    }
    unlock_result = ovc_mutex_unlock(&latch->mutex);
    return result != 0 ? result : unlock_result;
}

int ovc_completion_latch_destroy(ovc_completion_latch *latch)
{
    int result;
    int mutex_result;

    if (latch == NULL) {
        return EINVAL;
    }
    result = ovc_cond_destroy(&latch->condition);
    mutex_result = ovc_mutex_destroy(&latch->mutex);
    return result != 0 ? result : mutex_result;
}

#if defined(OVC_RUNTIME_TEST_MAIN)

#include <assert.h>

#if defined(NDEBUG)
#error "OVC_RUNTIME_TEST_MAIN requires assertions to be enabled"
#endif

typedef struct ovc_runtime_test_batch {
    ovc_mutex mutex;
    ovc_completion_latch completed;
    uint32_t finished;
    uint32_t target;
} ovc_runtime_test_batch;

typedef struct ovc_runtime_test_ensure_call {
    uint32_t requested;
    int result;
} ovc_runtime_test_ensure_call;

typedef struct ovc_runtime_test_parked_task {
    ovc_completion_latch started;
    ovc_completion_latch release;
} ovc_runtime_test_parked_task;

static void ovc_runtime_test_ensure(void *argument)
{
    ovc_runtime_test_ensure_call *call;

    call = (ovc_runtime_test_ensure_call *)argument;
    call->result = ovc_runtime_ensure(call->requested);
}

static void ovc_runtime_test_task(void *argument)
{
    ovc_runtime_test_batch *batch;
    int is_last;

    batch = (ovc_runtime_test_batch *)argument;
    ovc_runtime_sync_success(ovc_mutex_lock(&batch->mutex));
    ++batch->finished;
    is_last = batch->finished == batch->target;
    ovc_runtime_sync_success(ovc_mutex_unlock(&batch->mutex));
    if (is_last) {
        ovc_runtime_sync_success(
            ovc_completion_latch_complete(&batch->completed));
    }
}

static void ovc_runtime_test_park(void *argument)
{
    ovc_runtime_test_parked_task *task;

    task = (ovc_runtime_test_parked_task *)argument;
    ovc_runtime_sync_success(
        ovc_completion_latch_complete(&task->started));
    ovc_runtime_sync_success(
        ovc_completion_latch_wait(&task->release));
}

static void ovc_runtime_test_resolver(void)
{
    assert(ovc_runtime_resolve_threads(7, "11", 64) == 7);
    assert(ovc_runtime_resolve_threads(UINT32_MAX, NULL, 1) == UINT32_MAX);

    assert(ovc_runtime_resolve_threads(0, "11", 64) == 11);
    assert(ovc_runtime_resolve_threads(0, "0007", 64) == 7);
    assert(ovc_runtime_resolve_threads(0, "4294967295", 64) == UINT32_MAX);

    assert(ovc_runtime_resolve_threads(0, NULL, 9) == 9);
    assert(ovc_runtime_resolve_threads(0, "", 9) == 9);
    assert(ovc_runtime_resolve_threads(0, "0", 9) == 9);
    assert(ovc_runtime_resolve_threads(0, "-1", 9) == 9);
    assert(ovc_runtime_resolve_threads(0, "+1", 9) == 9);
    assert(ovc_runtime_resolve_threads(0, " 1", 9) == 9);
    assert(ovc_runtime_resolve_threads(0, "1x", 9) == 9);
    assert(ovc_runtime_resolve_threads(0, "4294967296", 9) == 9);

    assert(ovc_runtime_resolve_threads(0, NULL, 0) == 2);
    assert(ovc_runtime_resolve_threads(0, NULL, 1) == 2);
    assert(ovc_runtime_resolve_threads(0, NULL, 2) == 2);
    assert(ovc_runtime_resolve_threads(0, NULL, 17) == 17);
    assert(ovc_runtime_resolve_threads(0, NULL, 32) == 32);
    assert(ovc_runtime_resolve_threads(0, NULL, 33) == 32);
}

static void ovc_runtime_test_submit_batch(uint32_t task_count)
{
    ovc_runtime_test_batch batch;
    uint32_t index;

    ovc_runtime_sync_success(ovc_mutex_init(&batch.mutex));
    ovc_runtime_sync_success(
        ovc_completion_latch_init(&batch.completed));
    batch.finished = 0;
    batch.target = task_count;

    for (index = 0; index < task_count; ++index) {
        ovc_runtime_sync_success(
            ovc_runtime_submit(ovc_runtime_test_task, &batch));
    }
    ovc_runtime_sync_success(
        ovc_completion_latch_wait(&batch.completed));
    assert(batch.finished == task_count);
    assert(ovc_runtime_wait_for_idle(UINT64_C(5000000000)) == 0);

    ovc_runtime_sync_success(
        ovc_completion_latch_destroy(&batch.completed));
    ovc_runtime_sync_success(ovc_mutex_destroy(&batch.mutex));
}

static void ovc_runtime_test_quiescence(void)
{
    ovc_runtime_test_parked_task task;

    ovc_runtime_sync_success(
        ovc_completion_latch_init(&task.started));
    ovc_runtime_sync_success(
        ovc_completion_latch_init(&task.release));
    ovc_runtime_sync_success(
        ovc_runtime_submit(ovc_runtime_test_park, &task));
    ovc_runtime_sync_success(
        ovc_completion_latch_wait(&task.started));

    assert(ovc_runtime_wait_for_idle(UINT64_C(10000000)) == ETIMEDOUT);

    ovc_runtime_sync_success(
        ovc_completion_latch_complete(&task.release));
    assert(ovc_runtime_wait_for_idle(UINT64_C(5000000000)) == 0);
    ovc_runtime_sync_success(
        ovc_completion_latch_destroy(&task.release));
    ovc_runtime_sync_success(
        ovc_completion_latch_destroy(&task.started));
}

int main(void)
{
    ovc_completion_latch already_completed;
    ovc_runtime_test_ensure_call ensure_calls[4];
    ovc_thread ensure_threads[4];
    size_t index;

    ovc_runtime_test_resolver();
    assert(ovc_runtime_worker_count() == 0);
    assert(ovc_runtime_submit(ovc_runtime_test_task, NULL) != 0);
    assert(ovc_runtime_submit(NULL, NULL) == EINVAL);

    ovc_runtime_sync_success(
        ovc_completion_latch_init(&already_completed));
    ovc_runtime_sync_success(
        ovc_completion_latch_complete(&already_completed));
    ovc_runtime_sync_success(
        ovc_completion_latch_wait(&already_completed));
    ovc_runtime_sync_success(
        ovc_completion_latch_destroy(&already_completed));

    for (index = 0; index < sizeof(ensure_threads) / sizeof(ensure_threads[0]);
         ++index) {
        ensure_calls[index].requested = 2;
        ensure_calls[index].result = -1;
        ovc_runtime_sync_success(
            ovc_thread_create(&ensure_threads[index],
                              ovc_runtime_test_ensure,
                              &ensure_calls[index]));
    }
    for (index = 0; index < sizeof(ensure_threads) / sizeof(ensure_threads[0]);
         ++index) {
        ovc_runtime_sync_success(ovc_thread_join(&ensure_threads[index]));
        assert(ensure_calls[index].result == 0);
    }
    assert(ovc_runtime_worker_count() == 2);
    ovc_runtime_test_quiescence();
    ovc_runtime_test_submit_batch(128);

    ovc_runtime_sync_success(ovc_runtime_ensure(0));
    ovc_runtime_sync_success(ovc_runtime_ensure(3));
    assert(ovc_runtime_worker_count() == 2);
    ovc_runtime_test_submit_batch(128);

    /* Exercise normal process exit while the permanent workers are idle. */
    return 0;
}

#endif /* OVC_RUNTIME_TEST_MAIN */
