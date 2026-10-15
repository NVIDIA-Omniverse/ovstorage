/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host and plugin-ABI cancellation tokens for the pure-C implementation.
 */

#include "internal.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

typedef struct ovc_cancel_callback_entry ovc_cancel_callback_entry;

struct ovc_cancel_callback_entry {
    uint64_t id;
    void (*callback)(void *user_data);
    void *user_data;
    int in_flight;
    ovc_cancel_callback_entry *next;
};

/* Completes the opaque type declared by the frozen plugin header. */
struct OvStoragePlugin_AtomicCancelState {
    ovc_ref_count references;
    volatile long canceled;
    ovc_mutex callbacks_mutex;
    ovc_cond callbacks_changed;
    uint64_t next_callback_id;
    ovc_cancel_callback_entry *callbacks;
};

struct OvStorage_CancelToken {
    OvStoragePlugin_AtomicCancelState *state;
};

#if !defined(_WIN32) && !defined(__GNUC__) && !defined(__clang__)
static ovc_mutex g_ovc_cancel_atomic_lock = OVC_MUTEX_INITIALIZER;
#endif

static void ovc_cancel_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

static void ovc_cancel_lock(OvStoragePlugin_AtomicCancelState *state)
{
    ovc_cancel_sync_success(ovc_mutex_lock(&state->callbacks_mutex));
}

static void ovc_cancel_unlock(OvStoragePlugin_AtomicCancelState *state)
{
    ovc_cancel_sync_success(ovc_mutex_unlock(&state->callbacks_mutex));
}

static long ovc_cancel_atomic_load(const volatile long *value)
{
#if defined(_WIN32)
    return InterlockedCompareExchange((volatile long *)value, 0L, 0L);
#elif defined(__GNUC__) || defined(__clang__)
    return __sync_val_compare_and_swap((volatile long *)value, 0L, 0L);
#else
    long result;

    ovc_cancel_sync_success(ovc_mutex_lock(&g_ovc_cancel_atomic_lock));
    result = *value;
    ovc_cancel_sync_success(ovc_mutex_unlock(&g_ovc_cancel_atomic_lock));
    return result;
#endif
}

static int ovc_cancel_atomic_mark(volatile long *value)
{
#if defined(_WIN32)
    return InterlockedCompareExchange(value, 1L, 0L) == 0L;
#elif defined(__GNUC__) || defined(__clang__)
    return __sync_bool_compare_and_swap(value, 0L, 1L);
#else
    int marked;

    ovc_cancel_sync_success(ovc_mutex_lock(&g_ovc_cancel_atomic_lock));
    marked = *value == 0L;
    if (marked) {
        *value = 1L;
    }
    ovc_cancel_sync_success(ovc_mutex_unlock(&g_ovc_cancel_atomic_lock));
    return marked;
#endif
}

static OvStoragePlugin_AtomicCancelState *ovc_cancel_state_create(void)
{
    OvStoragePlugin_AtomicCancelState *state;
    int result;

    state = (OvStoragePlugin_AtomicCancelState *)malloc(sizeof(*state));
    if (state == NULL) {
        return NULL;
    }

    state->references.value = 1L;
    state->canceled = 0L;
    state->next_callback_id = UINT64_C(1);
    state->callbacks = NULL;

    result = ovc_mutex_init(&state->callbacks_mutex);
    if (result != 0) {
        free(state);
        errno = result;
        return NULL;
    }
    result = ovc_cond_init(&state->callbacks_changed);
    if (result != 0) {
        (void)ovc_mutex_destroy(&state->callbacks_mutex);
        free(state);
        errno = result;
        return NULL;
    }
    return state;
}

static void ovc_cancel_state_destroy(OvStoragePlugin_AtomicCancelState *state)
{
    ovc_cancel_callback_entry *entry;

    entry = state->callbacks;
    while (entry != NULL) {
        ovc_cancel_callback_entry *next;

        next = entry->next;
        free(entry);
        entry = next;
    }
    ovc_cancel_sync_success(ovc_cond_destroy(&state->callbacks_changed));
    ovc_cancel_sync_success(ovc_mutex_destroy(&state->callbacks_mutex));
    free(state);
}

static const OvStoragePlugin_AtomicCancelState *ovc_cancel_state_retain(
    const OvStoragePlugin_AtomicCancelState *state)
{
    OvStoragePlugin_AtomicCancelState *mutable_state;

    if (state == NULL) {
        return NULL;
    }
    mutable_state = (OvStoragePlugin_AtomicCancelState *)state;

#if defined(_WIN32)
    {
        long current;

        current = InterlockedCompareExchange(
            &mutable_state->references.value, 0L, 0L);
        for (;;) {
            long observed;

            if (current <= 0L || current == LONG_MAX) {
                return NULL;
            }
            observed = InterlockedCompareExchange(
                &mutable_state->references.value, current + 1L, current);
            if (observed == current) {
                return state;
            }
            current = observed;
        }
    }
#elif defined(__GNUC__) || defined(__clang__)
    {
        long current;

        current = __sync_val_compare_and_swap(
            &mutable_state->references.value, 0L, 0L);
        for (;;) {
            if (current <= 0L || current == LONG_MAX) {
                return NULL;
            }
            if (__sync_bool_compare_and_swap(&mutable_state->references.value,
                                             current,
                                             current + 1L)) {
                return state;
            }
            current = __sync_val_compare_and_swap(
                &mutable_state->references.value, 0L, 0L);
        }
    }
#else
    {
        int retained;

        ovc_cancel_sync_success(ovc_mutex_lock(&g_ovc_cancel_atomic_lock));
        retained = mutable_state->references.value > 0L &&
                   mutable_state->references.value < LONG_MAX;
        if (retained) {
            ++mutable_state->references.value;
        }
        ovc_cancel_sync_success(ovc_mutex_unlock(&g_ovc_cancel_atomic_lock));
        return retained ? state : NULL;
    }
#endif
}

static void ovc_cancel_state_release(
    const OvStoragePlugin_AtomicCancelState *state)
{
    OvStoragePlugin_AtomicCancelState *mutable_state;
    int last;

    if (state == NULL) {
        return;
    }
    mutable_state = (OvStoragePlugin_AtomicCancelState *)state;

#if defined(_WIN32)
    last = InterlockedDecrement(&mutable_state->references.value) == 0L;
#elif defined(__GNUC__) || defined(__clang__)
    last = __sync_sub_and_fetch(&mutable_state->references.value, 1L) == 0L;
#else
    ovc_cancel_sync_success(ovc_mutex_lock(&g_ovc_cancel_atomic_lock));
    --mutable_state->references.value;
    last = mutable_state->references.value == 0L;
    ovc_cancel_sync_success(ovc_mutex_unlock(&g_ovc_cancel_atomic_lock));
#endif

    if (last) {
        ovc_cancel_state_destroy(mutable_state);
    }
}

static bool ovc_cancel_ffi_is_canceled(
    const OvStoragePlugin_AtomicCancelState *state)
{
    return state != NULL && ovc_cancel_atomic_load(&state->canceled) != 0L;
}

static uint64_t ovc_cancel_ffi_register_callback(
    const OvStoragePlugin_AtomicCancelState *state,
    void (*callback)(void *user_data),
    void *user_data)
{
    OvStoragePlugin_AtomicCancelState *mutable_state;
    ovc_cancel_callback_entry *entry;
    uint64_t id;

    if (state == NULL || callback == NULL) {
        return 0;
    }
    mutable_state = (OvStoragePlugin_AtomicCancelState *)state;

    if (ovc_cancel_ffi_is_canceled(state)) {
        callback(user_data);
        return 0;
    }

    entry = (ovc_cancel_callback_entry *)malloc(sizeof(*entry));
    if (entry == NULL) {
        /* The ABI has no registration-error channel. */
        abort();
    }
    entry->callback = callback;
    entry->user_data = user_data;
    entry->in_flight = 0;

    ovc_cancel_lock(mutable_state);
    if (ovc_cancel_ffi_is_canceled(state)) {
        ovc_cancel_unlock(mutable_state);
        free(entry);
        callback(user_data);
        return 0;
    }

    id = mutable_state->next_callback_id;
    ++mutable_state->next_callback_id;
    if (mutable_state->next_callback_id == 0) {
        mutable_state->next_callback_id = UINT64_C(1);
    }
    entry->id = id;
    entry->next = mutable_state->callbacks;
    mutable_state->callbacks = entry;
    ovc_cancel_unlock(mutable_state);
    return id;
}

static void ovc_cancel_ffi_unregister_callback(
    const OvStoragePlugin_AtomicCancelState *state,
    uint64_t subscription_id)
{
    OvStoragePlugin_AtomicCancelState *mutable_state;

    if (state == NULL || subscription_id == 0) {
        return;
    }
    mutable_state = (OvStoragePlugin_AtomicCancelState *)state;

    ovc_cancel_lock(mutable_state);
    for (;;) {
        ovc_cancel_callback_entry **link;
        ovc_cancel_callback_entry *entry;

        link = &mutable_state->callbacks;
        while (*link != NULL && (*link)->id != subscription_id) {
            link = &(*link)->next;
        }
        entry = *link;
        if (entry == NULL) {
            ovc_cancel_unlock(mutable_state);
            return;
        }
        if (entry->in_flight) {
            ovc_cancel_sync_success(ovc_cond_wait(
                &mutable_state->callbacks_changed,
                &mutable_state->callbacks_mutex));
            continue;
        }

        *link = entry->next;
        ovc_cancel_unlock(mutable_state);
        free(entry);
        return;
    }
}

static const OvStoragePlugin_AtomicCancelState *ovc_cancel_ffi_clone(
    const OvStoragePlugin_AtomicCancelState *state)
{
    return ovc_cancel_state_retain(state);
}

static void ovc_cancel_ffi_drop(
    const OvStoragePlugin_AtomicCancelState *state)
{
    ovc_cancel_state_release(state);
}

static void ovc_cancel_state_cancel(OvStoragePlugin_AtomicCancelState *state)
{
    ovc_cancel_callback_entry *entry;

    if (state == NULL || !ovc_cancel_atomic_mark(&state->canceled)) {
        return;
    }

    /*
     * Mark the complete registry snapshot before releasing the lock.  That
     * keeps every selected node and its user_data alive until its callback
     * returns; unregister waits on callbacks_changed when it finds the mark.
     * As in the frozen Rust ABI, callbacks must not re-enter this registry.
     */
    ovc_cancel_lock(state);
    for (entry = state->callbacks; entry != NULL; entry = entry->next) {
        entry->in_flight = 1;
    }
    entry = state->callbacks;
    ovc_cancel_unlock(state);

    while (entry != NULL) {
        ovc_cancel_callback_entry *next;
        void (*callback)(void *user_data);
        void *user_data;

        next = entry->next;
        callback = entry->callback;
        user_data = entry->user_data;
        callback(user_data);

        ovc_cancel_lock(state);
        entry->in_flight = 0;
        ovc_cancel_sync_success(
            ovc_cond_broadcast(&state->callbacks_changed));
        ovc_cancel_unlock(state);
        entry = next;
    }
}

OvStorage_CancelToken *ovstorage_cancel_token_create(void)
{
    OvStorage_CancelToken *token;
    OvStoragePlugin_AtomicCancelState *state;

    state = ovc_cancel_state_create();
    if (state == NULL) {
        return NULL;
    }
    token = (OvStorage_CancelToken *)malloc(sizeof(*token));
    if (token == NULL) {
        ovc_cancel_state_release(state);
        return NULL;
    }
    token->state = state;
    return token;
}

void ovstorage_cancel_token_destroy(OvStorage_CancelToken *token)
{
    if (token == NULL) {
        return;
    }
    ovc_cancel_state_release(token->state);
    free(token);
}

void ovstorage_cancel_token_cancel(const OvStorage_CancelToken *token)
{
    if (token != NULL) {
        ovc_cancel_state_cancel(token->state);
    }
}

bool ovstorage_cancel_token_is_canceled(const OvStorage_CancelToken *token)
{
    return token != NULL && ovc_cancel_ffi_is_canceled(token->state);
}

OvStoragePlugin_CancelTokenFFI
ovc_cancel_token_mint(const OvStorage_CancelToken *token)
{
    OvStoragePlugin_CancelTokenFFI result;
    const OvStoragePlugin_AtomicCancelState *state;

    if (token == NULL) {
        state = ovc_cancel_state_create();
    } else {
        state = ovc_cancel_state_retain(token->state);
    }
    if (state == NULL) {
        /* The by-value ABI has no way to return a minting failure. */
        abort();
    }

    result.state = state;
    result.is_canceled = ovc_cancel_ffi_is_canceled;
    result.register_callback = ovc_cancel_ffi_register_callback;
    result.unregister_callback = ovc_cancel_ffi_unregister_callback;
    result.clone = ovc_cancel_ffi_clone;
    result.drop = ovc_cancel_ffi_drop;
    return result;
}
