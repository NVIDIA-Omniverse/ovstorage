/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dedicated-thread adapters for plugin blocking-pull streams.
 */

#include "internal.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

/* Keep the C99 source promise while pinning the copied ABI at compile time. */
#define OVC_STREAM_JOIN_INNER(left, right) left##right
#define OVC_STREAM_JOIN(left, right) OVC_STREAM_JOIN_INNER(left, right)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define OVC_STREAM_STATIC_ASSERT(condition, message) \
    _Static_assert(condition, message)
#else
#define OVC_STREAM_STATIC_ASSERT(condition, message)                       \
    typedef char OVC_STREAM_JOIN(ovc_stream_static_assert_at_line_,        \
                                 __LINE__)[(condition) ? 1 : -1]
#endif

OVC_STREAM_STATIC_ASSERT(OvStoragePlugin_StreamStep_Yielded == 0,
                         "StreamStep::Yielded changed");
OVC_STREAM_STATIC_ASSERT(OvStoragePlugin_StreamStep_Ended == 1,
                         "StreamStep::Ended changed");
OVC_STREAM_STATIC_ASSERT(OvStoragePlugin_StreamStep_Failed == 2,
                         "StreamStep::Failed changed");

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define OVC_STREAM_TYPE_MATCH(expression, type) \
    _Generic((expression), type: 1, default: 0)
OVC_STREAM_STATIC_ASSERT(
    OVC_STREAM_TYPE_MATCH(
        ((OvStoragePlugin_AuthEventStream *)0)->next_fn,
        OvStoragePlugin_StreamStep (*)(void *,
                                       OvStoragePlugin_AuthEvent *,
                                       OvStoragePlugin_Error *)),
    "AuthEventStream next_fn signature changed");
OVC_STREAM_STATIC_ASSERT(
    OVC_STREAM_TYPE_MATCH(
        ((OvStoragePlugin_BodyStream *)0)->next_fn,
        OvStoragePlugin_StreamStep (*)(void *,
                                       OvStoragePlugin_Bytes *,
                                       OvStoragePlugin_Error *)),
    "BodyStream next_fn signature changed");
OVC_STREAM_STATIC_ASSERT(
    OVC_STREAM_TYPE_MATCH(
        ((OvStoragePlugin_BackendChangeStream *)0)->next_fn,
        OvStoragePlugin_StreamStep (*)(void *,
                                       OvStoragePlugin_BackendChangeEvent *,
                                       OvStoragePlugin_Error *)),
    "BackendChangeStream next_fn signature changed");
#elif defined(__GNUC__) || defined(__clang__)
OVC_STREAM_STATIC_ASSERT(
    __builtin_types_compatible_p(
        __typeof__(((OvStoragePlugin_AuthEventStream *)0)->next_fn),
        OvStoragePlugin_StreamStep (*)(void *,
                                       OvStoragePlugin_AuthEvent *,
                                       OvStoragePlugin_Error *)),
    "AuthEventStream next_fn signature changed");
OVC_STREAM_STATIC_ASSERT(
    __builtin_types_compatible_p(
        __typeof__(((OvStoragePlugin_BodyStream *)0)->next_fn),
        OvStoragePlugin_StreamStep (*)(void *,
                                       OvStoragePlugin_Bytes *,
                                       OvStoragePlugin_Error *)),
    "BodyStream next_fn signature changed");
OVC_STREAM_STATIC_ASSERT(
    __builtin_types_compatible_p(
        __typeof__(((OvStoragePlugin_BackendChangeStream *)0)->next_fn),
        OvStoragePlugin_StreamStep (*)(void *,
                                       OvStoragePlugin_BackendChangeEvent *,
                                       OvStoragePlugin_Error *)),
    "BackendChangeStream next_fn signature changed");
#endif

OVC_STREAM_STATIC_ASSERT(
    offsetof(OvStoragePlugin_AuthEventStream, state) == 0,
    "AuthEventStream state must remain first");
OVC_STREAM_STATIC_ASSERT(
    offsetof(OvStoragePlugin_AuthEventStream, next_fn) <
        offsetof(OvStoragePlugin_AuthEventStream, drop_fn),
    "AuthEventStream next_fn/drop_fn order changed");
OVC_STREAM_STATIC_ASSERT(
    offsetof(OvStoragePlugin_AuthEventStream, drop_fn) +
            sizeof(((OvStoragePlugin_AuthEventStream *)0)->drop_fn) ==
        sizeof(OvStoragePlugin_AuthEventStream),
    "AuthEventStream gained an unpinned tail");

OVC_STREAM_STATIC_ASSERT(
    offsetof(OvStoragePlugin_BodyStream, state) == 0,
    "BodyStream state must remain first");
OVC_STREAM_STATIC_ASSERT(
    offsetof(OvStoragePlugin_BodyStream, next_fn) <
        offsetof(OvStoragePlugin_BodyStream, drop_fn),
    "BodyStream next_fn/drop_fn order changed");
OVC_STREAM_STATIC_ASSERT(
    offsetof(OvStoragePlugin_BodyStream, drop_fn) +
            sizeof(((OvStoragePlugin_BodyStream *)0)->drop_fn) ==
        sizeof(OvStoragePlugin_BodyStream),
    "BodyStream gained an unpinned tail");

typedef enum ovc_stream_kind {
    OVC_STREAM_KIND_AUTH = 0,
    OVC_STREAM_KIND_BYTES = 1,
    OVC_STREAM_KIND_BACKEND_CHANGE = 2
} ovc_stream_kind;

struct ovc_stream_cancel_scope {
    OvStorage_CancelToken *producer;
    OvStoragePlugin_CancelTokenFFI parent;
    uint64_t parent_subscription;
    int has_parent;
};

struct ovc_stream_pump {
    ovc_thread thread;
    ovc_mutex mutex;
    ovc_cond start_changed;
    int start_released;
    int close_requested;
    ovc_stream_kind kind;
    union {
        OvStoragePlugin_AuthEventStream *auth;
        OvStoragePlugin_BodyStream *bytes;
        OvStoragePlugin_BackendChangeStream *backend_change;
    } stream;
    void *stream_owner;
    ovc_stream_reclaim_fn reclaim_stream;
    ovc_stream_cancel_scope *cancel_scope;
    union {
        ovc_auth_stream_item_fn auth;
        ovc_byte_stream_item_fn bytes;
        ovc_backend_change_stream_item_fn backend_change;
    } on_item;
    ovc_stream_terminal_fn on_terminal;
    void *user_data;
};

static void ovc_stream_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

/* C99/MSVC also gets a required compatible assignment at each launch. */
static void ovc_stream_pin_next_shapes(void)
{
    OvStoragePlugin_AuthEventNextFn auth_actual;
    OvStoragePlugin_BodyStreamNextFn bytes_actual;
    OvStoragePlugin_BackendChangeNextFn backend_change_actual;
    OvStoragePlugin_StreamStep (*auth_exact)(
        void *, OvStoragePlugin_AuthEvent *, OvStoragePlugin_Error *);
    OvStoragePlugin_StreamStep (*bytes_exact)(
        void *, OvStoragePlugin_Bytes *, OvStoragePlugin_Error *);
    OvStoragePlugin_StreamStep (*backend_change_exact)(
        void *, OvStoragePlugin_BackendChangeEvent *, OvStoragePlugin_Error *);

    auth_actual = NULL;
    bytes_actual = NULL;
    backend_change_actual = NULL;
    auth_exact = auth_actual;
    bytes_exact = bytes_actual;
    backend_change_exact = backend_change_actual;
    (void)auth_exact;
    (void)bytes_exact;
    (void)backend_change_exact;
}

static void ovc_stream_forward_cancel(void *user_data)
{
    ovc_stream_cancel_scope *scope;

    scope = (ovc_stream_cancel_scope *)user_data;
    if (scope != NULL) {
        ovstorage_cancel_token_cancel(scope->producer);
    }
}

ovc_stream_cancel_scope *
ovc_stream_cancel_scope_create(const OvStorage_CancelToken *parent)
{
    ovc_stream_cancel_scope *scope;

    scope = (ovc_stream_cancel_scope *)calloc(1, sizeof(*scope));
    if (scope == NULL) {
        return NULL;
    }

    scope->producer = ovstorage_cancel_token_create();
    if (scope->producer == NULL) {
        free(scope);
        return NULL;
    }

    if (parent != NULL) {
        scope->parent = ovc_cancel_token_mint(parent);
        scope->has_parent = 1;
        scope->parent_subscription = scope->parent.register_callback(
            scope->parent.state, ovc_stream_forward_cancel, scope);
    }
    return scope;
}

OvStoragePlugin_CancelTokenFFI
ovc_stream_cancel_scope_mint_producer(
    const ovc_stream_cancel_scope *scope)
{
    if (scope == NULL || scope->producer == NULL) {
        abort();
    }
    return ovc_cancel_token_mint(scope->producer);
}

void ovc_stream_cancel_scope_cancel(ovc_stream_cancel_scope *scope)
{
    if (scope != NULL) {
        ovstorage_cancel_token_cancel(scope->producer);
    }
}

bool ovc_stream_cancel_scope_is_canceled(
    const ovc_stream_cancel_scope *scope)
{
    return scope != NULL &&
           ovstorage_cancel_token_is_canceled(scope->producer);
}

void ovc_stream_cancel_scope_destroy(ovc_stream_cancel_scope *scope)
{
    if (scope == NULL) {
        return;
    }

    ovc_stream_cancel_scope_cancel(scope);
    if (scope->has_parent) {
        if (scope->parent_subscription != 0) {
            scope->parent.unregister_callback(
                scope->parent.state, scope->parent_subscription);
        }
        scope->parent.drop(scope->parent.state);
    }
    ovstorage_cancel_token_destroy(scope->producer);
    free(scope);
}

static int ovc_stream_pump_is_canceled(ovc_stream_pump *pump)
{
    int close_requested;

    ovc_stream_sync_success(ovc_mutex_lock(&pump->mutex));
    close_requested = pump->close_requested;
    ovc_stream_sync_success(ovc_mutex_unlock(&pump->mutex));
    return close_requested ||
           ovc_stream_cancel_scope_is_canceled(pump->cancel_scope);
}

static void ovc_auth_stream_run(ovc_stream_pump *pump)
{
    OvStoragePlugin_Error error;
    OvStoragePlugin_Error *terminal_error;
    ovc_stream_terminal_reason terminal_reason;

    terminal_error = NULL;
    terminal_reason = OVC_STREAM_TERMINAL_ENDED;
    for (;;) {
        OvStoragePlugin_AuthEvent event;
        OvStoragePlugin_StreamStep step;
        int canceled;

        if (ovc_stream_pump_is_canceled(pump)) {
            terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
            break;
        }

        step = pump->stream.auth->next_fn(pump->stream.auth->state,
                                          &event,
                                          &error);
        canceled = ovc_stream_pump_is_canceled(pump);

        if (step == OvStoragePlugin_StreamStep_Yielded) {
            pump->on_item.auth(&event, !canceled, pump->user_data);
            if (canceled) {
                terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
                break;
            }
            continue;
        }

        if (step == OvStoragePlugin_StreamStep_Failed) {
            terminal_error = &error;
        }
        if (canceled) {
            terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
            break;
        }

        if (step == OvStoragePlugin_StreamStep_Ended) {
            terminal_reason = OVC_STREAM_TERMINAL_ENDED;
        } else if (step == OvStoragePlugin_StreamStep_Failed) {
            terminal_reason = OVC_STREAM_TERMINAL_FAILED;
        } else {
            terminal_error = NULL;
            terminal_reason = OVC_STREAM_TERMINAL_PROTOCOL_ERROR;
        }
        break;
    }

    /* The producer destructor drives drop_fn after the final next_fn return. */
    pump->reclaim_stream(pump->stream_owner);
    pump->on_terminal(terminal_reason, terminal_error, pump->user_data);
}

static void ovc_byte_stream_run(ovc_stream_pump *pump)
{
    OvStoragePlugin_Error error;
    OvStoragePlugin_Error *terminal_error;
    ovc_stream_terminal_reason terminal_reason;

    terminal_error = NULL;
    terminal_reason = OVC_STREAM_TERMINAL_ENDED;
    for (;;) {
        OvStoragePlugin_Bytes chunk;
        OvStoragePlugin_StreamStep step;
        int canceled;

        if (ovc_stream_pump_is_canceled(pump)) {
            terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
            break;
        }

        step = pump->stream.bytes->next_fn(pump->stream.bytes->state,
                                           &chunk,
                                           &error);
        canceled = ovc_stream_pump_is_canceled(pump);

        if (step == OvStoragePlugin_StreamStep_Yielded) {
            pump->on_item.bytes(&chunk, !canceled, pump->user_data);
            if (canceled) {
                terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
                break;
            }
            continue;
        }

        if (step == OvStoragePlugin_StreamStep_Failed) {
            terminal_error = &error;
        }
        if (canceled) {
            terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
            break;
        }

        if (step == OvStoragePlugin_StreamStep_Ended) {
            terminal_reason = OVC_STREAM_TERMINAL_ENDED;
        } else if (step == OvStoragePlugin_StreamStep_Failed) {
            terminal_reason = OVC_STREAM_TERMINAL_FAILED;
        } else {
            terminal_error = NULL;
            terminal_reason = OVC_STREAM_TERMINAL_PROTOCOL_ERROR;
        }
        break;
    }

    /* The producer destructor drives drop_fn after the final next_fn return. */
    pump->reclaim_stream(pump->stream_owner);
    pump->on_terminal(terminal_reason, terminal_error, pump->user_data);
}

static void ovc_backend_change_stream_run(ovc_stream_pump *pump)
{
    OvStoragePlugin_Error error;
    OvStoragePlugin_Error *terminal_error;
    ovc_stream_terminal_reason terminal_reason;

    terminal_error = NULL;
    terminal_reason = OVC_STREAM_TERMINAL_ENDED;
    for (;;) {
        OvStoragePlugin_BackendChangeEvent event;
        OvStoragePlugin_StreamStep step;
        int canceled;

        if (ovc_stream_pump_is_canceled(pump)) {
            terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
            break;
        }
        step = pump->stream.backend_change->next_fn(
            pump->stream.backend_change->state, &event, &error);
        canceled = ovc_stream_pump_is_canceled(pump);
        if (step == OvStoragePlugin_StreamStep_Yielded) {
            pump->on_item.backend_change(
                &event, !canceled, pump->user_data);
            if (canceled) {
                terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
                break;
            }
            continue;
        }
        if (step == OvStoragePlugin_StreamStep_Failed) {
            terminal_error = &error;
        }
        if (canceled) {
            terminal_reason = OVC_STREAM_TERMINAL_CANCELED;
            break;
        }
        if (step == OvStoragePlugin_StreamStep_Ended) {
            terminal_reason = OVC_STREAM_TERMINAL_ENDED;
        } else if (step == OvStoragePlugin_StreamStep_Failed) {
            terminal_reason = OVC_STREAM_TERMINAL_FAILED;
        } else {
            terminal_error = NULL;
            terminal_reason = OVC_STREAM_TERMINAL_PROTOCOL_ERROR;
        }
        break;
    }
    pump->reclaim_stream(pump->stream_owner);
    pump->on_terminal(terminal_reason, terminal_error, pump->user_data);
}

static void ovc_stream_pump_thread(void *argument)
{
    ovc_stream_pump *pump;

    pump = (ovc_stream_pump *)argument;
    ovc_stream_sync_success(ovc_mutex_lock(&pump->mutex));
    while (!pump->start_released) {
        ovc_stream_sync_success(
            ovc_cond_wait(&pump->start_changed, &pump->mutex));
    }
    ovc_stream_sync_success(ovc_mutex_unlock(&pump->mutex));

    if (pump->kind == OVC_STREAM_KIND_AUTH) {
        ovc_auth_stream_run(pump);
    } else if (pump->kind == OVC_STREAM_KIND_BYTES) {
        ovc_byte_stream_run(pump);
    } else {
        ovc_backend_change_stream_run(pump);
    }
}

static ovc_stream_pump *ovc_stream_pump_allocate(
    ovc_stream_kind kind,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_stream_terminal_fn on_terminal,
    void *user_data,
    int *out_error)
{
    ovc_stream_pump *pump;
    int result;

    pump = (ovc_stream_pump *)calloc(1, sizeof(*pump));
    if (pump == NULL) {
        *out_error = ENOMEM;
        return NULL;
    }

    result = ovc_mutex_init(&pump->mutex);
    if (result != 0) {
        free(pump);
        *out_error = result;
        return NULL;
    }
    result = ovc_cond_init(&pump->start_changed);
    if (result != 0) {
        ovc_stream_sync_success(ovc_mutex_destroy(&pump->mutex));
        free(pump);
        *out_error = result;
        return NULL;
    }

    pump->kind = kind;
    pump->stream_owner = stream_owner;
    pump->reclaim_stream = reclaim_stream;
    pump->cancel_scope = cancel_scope;
    pump->on_terminal = on_terminal;
    pump->user_data = user_data;
    *out_error = 0;
    return pump;
}

static int ovc_stream_pump_launch(ovc_stream_pump *pump,
                                  ovc_stream_pump **out_pump)
{
    int result;

    result = ovc_thread_create(&pump->thread,
                               ovc_stream_pump_thread,
                               pump);
    if (result != 0) {
        ovc_stream_sync_success(ovc_cond_destroy(&pump->start_changed));
        ovc_stream_sync_success(ovc_mutex_destroy(&pump->mutex));
        free(pump);
        return result;
    }

    *out_pump = pump;
    return 0;
}

int ovc_auth_stream_pump_start(
    ovc_stream_pump **out_pump,
    OvStoragePlugin_AuthEventStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_auth_stream_item_fn on_event,
    ovc_stream_terminal_fn on_terminal,
    void *user_data)
{
    ovc_stream_pump *pump;
    int result;

    ovc_stream_pin_next_shapes();
    if (out_pump == NULL) {
        return EINVAL;
    }
    *out_pump = NULL;
    if (stream == NULL || stream_owner == NULL || stream->next_fn == NULL ||
        stream->drop_fn == NULL || reclaim_stream == NULL ||
        cancel_scope == NULL || on_event == NULL || on_terminal == NULL) {
        return EINVAL;
    }

    pump = ovc_stream_pump_allocate(OVC_STREAM_KIND_AUTH,
                                    stream_owner,
                                    reclaim_stream,
                                    cancel_scope,
                                    on_terminal,
                                    user_data,
                                    &result);
    if (pump == NULL) {
        return result;
    }
    pump->stream.auth = stream;
    pump->on_item.auth = on_event;
    return ovc_stream_pump_launch(pump, out_pump);
}

int ovc_byte_stream_pump_start(
    ovc_stream_pump **out_pump,
    OvStoragePlugin_BodyStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_byte_stream_item_fn on_chunk,
    ovc_stream_terminal_fn on_terminal,
    void *user_data)
{
    ovc_stream_pump *pump;
    int result;

    ovc_stream_pin_next_shapes();
    if (out_pump == NULL) {
        return EINVAL;
    }
    *out_pump = NULL;
    if (stream == NULL || stream_owner == NULL || stream->next_fn == NULL ||
        stream->drop_fn == NULL || reclaim_stream == NULL ||
        cancel_scope == NULL || on_chunk == NULL || on_terminal == NULL) {
        return EINVAL;
    }

    pump = ovc_stream_pump_allocate(OVC_STREAM_KIND_BYTES,
                                    stream_owner,
                                    reclaim_stream,
                                    cancel_scope,
                                    on_terminal,
                                    user_data,
                                    &result);
    if (pump == NULL) {
        return result;
    }
    pump->stream.bytes = stream;
    pump->on_item.bytes = on_chunk;
    return ovc_stream_pump_launch(pump, out_pump);
}

int ovc_backend_change_stream_pump_start(
    ovc_stream_pump **out_pump,
    OvStoragePlugin_BackendChangeStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream,
    ovc_stream_cancel_scope *cancel_scope,
    ovc_backend_change_stream_item_fn on_event,
    ovc_stream_terminal_fn on_terminal,
    void *user_data)
{
    ovc_stream_pump *pump;
    int result;

    ovc_stream_pin_next_shapes();
    if (out_pump == NULL) {
        return EINVAL;
    }
    *out_pump = NULL;
    if (stream == NULL || stream_owner == NULL || stream->next_fn == NULL ||
        stream->drop_fn == NULL || reclaim_stream == NULL ||
        cancel_scope == NULL || on_event == NULL || on_terminal == NULL) {
        return EINVAL;
    }
    pump = ovc_stream_pump_allocate(OVC_STREAM_KIND_BACKEND_CHANGE,
                                    stream_owner,
                                    reclaim_stream,
                                    cancel_scope,
                                    on_terminal,
                                    user_data,
                                    &result);
    if (pump == NULL) {
        return result;
    }
    pump->stream.backend_change = stream;
    pump->on_item.backend_change = on_event;
    return ovc_stream_pump_launch(pump, out_pump);
}

void ovc_stream_pump_arm(ovc_stream_pump *pump)
{
    if (pump == NULL) {
        return;
    }

    ovc_stream_sync_success(ovc_mutex_lock(&pump->mutex));
    pump->start_released = 1;
    ovc_stream_sync_success(ovc_cond_broadcast(&pump->start_changed));
    ovc_stream_sync_success(ovc_mutex_unlock(&pump->mutex));
}

void ovc_stream_pump_cancel(ovc_stream_pump *pump)
{
    if (pump == NULL) {
        return;
    }

    ovc_stream_sync_success(ovc_mutex_lock(&pump->mutex));
    pump->close_requested = 1;
    pump->start_released = 1;
    ovc_stream_sync_success(ovc_cond_broadcast(&pump->start_changed));
    ovc_stream_sync_success(ovc_mutex_unlock(&pump->mutex));
    ovc_stream_cancel_scope_cancel(pump->cancel_scope);
}

static int ovc_stream_pump_is_current_thread(const ovc_stream_pump *pump)
{
#if defined(_WIN32)
    DWORD pump_thread_id;

    pump_thread_id = GetThreadId(pump->thread.handle);
    if (pump_thread_id == 0) {
        abort();
    }
    return pump_thread_id == GetCurrentThreadId();
#else
    return pthread_equal(pump->thread.handle, pthread_self()) != 0;
#endif
}

void ovc_stream_pump_destroy(ovc_stream_pump *pump)
{
    if (pump == NULL) {
        return;
    }
    if (ovc_stream_pump_is_current_thread(pump)) {
        /* See the non-reentrant destruction contract in internal.h. */
        abort();
    }

    ovc_stream_pump_cancel(pump);
    ovc_stream_sync_success(ovc_thread_join(&pump->thread));
    ovc_stream_cancel_scope_destroy(pump->cancel_scope);
    ovc_stream_sync_success(ovc_cond_destroy(&pump->start_changed));
    ovc_stream_sync_success(ovc_mutex_destroy(&pump->mutex));
    free(pump);
}

static int ovc_updates_discard(void *stream,
                               void *stream_owner,
                               ovc_stream_reclaim_fn reclaim_stream,
                               int has_drop_fn)
{
    if (stream == NULL) {
        return 0;
    }
    if (stream_owner == NULL || !has_drop_fn || reclaim_stream == NULL) {
        return EINVAL;
    }

    /* Snapshot-only means there can be no concurrent next_fn here. */
    reclaim_stream(stream_owner);
    return 0;
}

int ovc_root_updates_discard(
    OvStoragePlugin_RootInfoChangeStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream)
{
    return ovc_updates_discard(stream,
                               stream_owner,
                               reclaim_stream,
                               stream != NULL && stream->drop_fn != NULL);
}

int ovc_connection_updates_discard(
    OvStoragePlugin_ConnectionChangeStream *stream,
    void *stream_owner,
    ovc_stream_reclaim_fn reclaim_stream)
{
    return ovc_updates_discard(stream,
                               stream_owner,
                               reclaim_stream,
                               stream != NULL && stream->drop_fn != NULL);
}

#if defined(OVC_STREAMS_TEST_MAIN)

#include <assert.h>
#include <string.h>

#if defined(NDEBUG)
#error "OVC_STREAMS_TEST_MAIN requires assertions to be enabled"
#endif

typedef struct ovc_stream_test_blocking_state {
    ovc_mutex mutex;
    ovc_cond changed;
    int entered;
    int wake;
    int sequence;
    int next_return_sequence;
    int drop_sequence;
    int drop_count;
    OvStoragePlugin_CancelTokenFFI producer_cancel;
    uint64_t producer_subscription;
} ovc_stream_test_blocking_state;

typedef struct ovc_stream_test_terminal_state {
    ovc_completion_latch completed;
    ovc_stream_terminal_reason reason;
    int terminal_count;
    int delivered_count;
    int discarded_count;
    int error_count;
} ovc_stream_test_terminal_state;

static void ovc_stream_test_wake(void *user_data)
{
    ovc_stream_test_blocking_state *state;

    state = (ovc_stream_test_blocking_state *)user_data;
    ovc_stream_sync_success(ovc_mutex_lock(&state->mutex));
    state->wake = 1;
    ovc_stream_sync_success(ovc_cond_broadcast(&state->changed));
    ovc_stream_sync_success(ovc_mutex_unlock(&state->mutex));
}

static OvStoragePlugin_StreamStep ovc_stream_test_blocking_next(
    void *opaque,
    OvStoragePlugin_Bytes *out_chunk,
    OvStoragePlugin_Error *out_error)
{
    ovc_stream_test_blocking_state *state;

    (void)out_error;
    state = (ovc_stream_test_blocking_state *)opaque;
    ovc_stream_sync_success(ovc_mutex_lock(&state->mutex));
    state->entered = 1;
    ovc_stream_sync_success(ovc_cond_broadcast(&state->changed));
    while (!state->wake) {
        ovc_stream_sync_success(
            ovc_cond_wait(&state->changed, &state->mutex));
    }
    ovc_stream_sync_success(ovc_mutex_unlock(&state->mutex));

    out_chunk->ptr = (uint8_t *)malloc(1);
    assert(out_chunk->ptr != NULL);
    out_chunk->ptr[0] = 0x5a;
    out_chunk->len = 1;
    ovc_stream_sync_success(ovc_mutex_lock(&state->mutex));
    state->next_return_sequence = ++state->sequence;
    ovc_stream_sync_success(ovc_mutex_unlock(&state->mutex));
    return OvStoragePlugin_StreamStep_Yielded;
}

static void ovc_stream_test_blocking_drop(void *opaque)
{
    ovc_stream_test_blocking_state *state;

    state = (ovc_stream_test_blocking_state *)opaque;
    state->producer_cancel.unregister_callback(
        state->producer_cancel.state, state->producer_subscription);
    state->producer_cancel.drop(state->producer_cancel.state);

    ovc_stream_sync_success(ovc_mutex_lock(&state->mutex));
    assert(state->next_return_sequence != 0);
    state->drop_sequence = ++state->sequence;
    ++state->drop_count;
    ovc_stream_sync_success(ovc_mutex_unlock(&state->mutex));
}

static void ovc_stream_test_body_reclaim(void *owner)
{
    OvStoragePlugin_BodyStream *stream;

    stream = (OvStoragePlugin_BodyStream *)owner;
    stream->drop_fn(stream->state);
    free(stream);
}

static void ovc_stream_test_chunk(OvStoragePlugin_Bytes *chunk,
                                  bool deliver,
                                  void *user_data)
{
    ovc_stream_test_terminal_state *terminal;

    terminal = (ovc_stream_test_terminal_state *)user_data;
    assert(chunk->ptr != NULL);
    assert(chunk->len == 1);
    free(chunk->ptr);
    chunk->ptr = NULL;
    chunk->len = 0;
    if (deliver) {
        ++terminal->delivered_count;
    } else {
        ++terminal->discarded_count;
    }
}

static void ovc_stream_test_terminal(
    ovc_stream_terminal_reason reason,
    OvStoragePlugin_Error *error,
    void *user_data)
{
    ovc_stream_test_terminal_state *terminal;

    terminal = (ovc_stream_test_terminal_state *)user_data;
    if (error != NULL) {
        assert(error->message_ptr != NULL);
        assert(error->context == NULL);
        free(error->message_ptr);
        error->message_ptr = NULL;
        error->message_len = 0;
        ++terminal->error_count;
    }
    terminal->reason = reason;
    ++terminal->terminal_count;
    ovc_stream_sync_success(
        ovc_completion_latch_complete(&terminal->completed));
}

static void ovc_stream_test_blocking_state_init(
    ovc_stream_test_blocking_state *state,
    ovc_stream_cancel_scope *scope)
{
    OvStoragePlugin_CancelTokenFFI producer;

    memset(state, 0, sizeof(*state));
    ovc_stream_sync_success(ovc_mutex_init(&state->mutex));
    ovc_stream_sync_success(ovc_cond_init(&state->changed));

    producer = ovc_stream_cancel_scope_mint_producer(scope);
    state->producer_cancel = producer;
    state->producer_cancel.state = producer.clone(producer.state);
    state->producer_subscription = producer.register_callback(
        state->producer_cancel.state, ovc_stream_test_wake, state);
    producer.drop(producer.state);
}

static void ovc_stream_test_blocking_state_destroy(
    ovc_stream_test_blocking_state *state)
{
    ovc_stream_sync_success(ovc_cond_destroy(&state->changed));
    ovc_stream_sync_success(ovc_mutex_destroy(&state->mutex));
}

static void ovc_stream_test_wait_entered(
    ovc_stream_test_blocking_state *state)
{
    ovc_stream_sync_success(ovc_mutex_lock(&state->mutex));
    while (!state->entered) {
        ovc_stream_sync_success(
            ovc_cond_wait(&state->changed, &state->mutex));
    }
    ovc_stream_sync_success(ovc_mutex_unlock(&state->mutex));
}

static ovc_stream_pump *ovc_stream_test_start_blocked(
    ovc_stream_test_blocking_state *state,
    ovc_stream_test_terminal_state *terminal,
    const OvStorage_CancelToken *parent)
{
    ovc_stream_cancel_scope *scope;
    OvStoragePlugin_BodyStream *stream;
    ovc_stream_pump *pump;

    scope = ovc_stream_cancel_scope_create(parent);
    assert(scope != NULL);
    ovc_stream_test_blocking_state_init(state, scope);

    stream = (OvStoragePlugin_BodyStream *)malloc(sizeof(*stream));
    assert(stream != NULL);
    stream->state = state;
    stream->next_fn = ovc_stream_test_blocking_next;
    stream->drop_fn = ovc_stream_test_blocking_drop;

    ovc_stream_sync_success(
        ovc_byte_stream_pump_start(&pump,
                                   stream,
                                   stream,
                                   ovc_stream_test_body_reclaim,
                                   scope,
                                   ovc_stream_test_chunk,
                                   ovc_stream_test_terminal,
                                   terminal));
    ovc_stream_pump_arm(pump);
    ovc_stream_test_wait_entered(state);
    return pump;
}

typedef struct ovc_stream_test_runtime_task_state {
    ovc_mutex mutex;
    ovc_completion_latch completed;
    int count;
} ovc_stream_test_runtime_task_state;

static void ovc_stream_test_runtime_task(void *argument)
{
    ovc_stream_test_runtime_task_state *state;
    int complete;

    state = (ovc_stream_test_runtime_task_state *)argument;
    ovc_stream_sync_success(ovc_mutex_lock(&state->mutex));
    ++state->count;
    complete = state->count == 2;
    ovc_stream_sync_success(ovc_mutex_unlock(&state->mutex));
    if (complete) {
        ovc_stream_sync_success(
            ovc_completion_latch_complete(&state->completed));
    }
}

static void ovc_stream_test_blocked_cancel_and_runtime(void)
{
    ovc_stream_test_blocking_state states[2];
    ovc_stream_test_terminal_state terminals[2];
    ovc_stream_pump *pumps[2];
    ovc_stream_test_runtime_task_state runtime_tasks;
    OvStorage_CancelToken *parent;
    size_t index;

    ovc_stream_sync_success(ovc_runtime_ensure(2));
    parent = ovstorage_cancel_token_create();
    assert(parent != NULL);
    memset(terminals, 0, sizeof(terminals));
    for (index = 0; index < 2; ++index) {
        ovc_stream_sync_success(
            ovc_completion_latch_init(&terminals[index].completed));
        pumps[index] = ovc_stream_test_start_blocked(
            &states[index], &terminals[index], index == 0 ? parent : NULL);
    }

    memset(&runtime_tasks, 0, sizeof(runtime_tasks));
    ovc_stream_sync_success(ovc_mutex_init(&runtime_tasks.mutex));
    ovc_stream_sync_success(
        ovc_completion_latch_init(&runtime_tasks.completed));
    ovc_stream_sync_success(
        ovc_runtime_submit(ovc_stream_test_runtime_task, &runtime_tasks));
    ovc_stream_sync_success(
        ovc_runtime_submit(ovc_stream_test_runtime_task, &runtime_tasks));
    ovc_stream_sync_success(
        ovc_completion_latch_wait(&runtime_tasks.completed));
    assert(runtime_tasks.count == 2);

    /* Exercise both caller-token cancellation and handle-close cancellation. */
    ovstorage_cancel_token_cancel(parent);
    ovc_stream_sync_success(
        ovc_completion_latch_wait(&terminals[0].completed));
    ovc_stream_pump_destroy(pumps[0]);
    ovstorage_cancel_token_destroy(parent);
    ovc_stream_pump_destroy(pumps[1]);

    for (index = 0; index < 2; ++index) {
        assert(states[index].drop_count == 1);
        assert(states[index].next_return_sequence <
               states[index].drop_sequence);
        assert(terminals[index].terminal_count == 1);
        assert(terminals[index].reason == OVC_STREAM_TERMINAL_CANCELED);
        assert(terminals[index].delivered_count == 0);
        assert(terminals[index].discarded_count == 1);
        ovc_stream_sync_success(
            ovc_completion_latch_destroy(&terminals[index].completed));
        ovc_stream_test_blocking_state_destroy(&states[index]);
    }

    ovc_stream_sync_success(
        ovc_completion_latch_destroy(&runtime_tasks.completed));
    ovc_stream_sync_success(ovc_mutex_destroy(&runtime_tasks.mutex));
}

typedef struct ovc_stream_test_body_state {
    int fail;
    int next_count;
    int drop_count;
} ovc_stream_test_body_state;

static OvStoragePlugin_StreamStep ovc_stream_test_body_next(
    void *opaque,
    OvStoragePlugin_Bytes *out_chunk,
    OvStoragePlugin_Error *out_error)
{
    ovc_stream_test_body_state *state;

    state = (ovc_stream_test_body_state *)opaque;
    if (state->next_count != 0) {
        ++state->next_count;
        return OvStoragePlugin_StreamStep_Ended;
    }
    ++state->next_count;

    if (state->fail) {
        memset(out_error, 0, sizeof(*out_error));
        out_error->code = OvStoragePlugin_ErrorCode_Internal;
        out_error->message_ptr = (char *)malloc(6);
        assert(out_error->message_ptr != NULL);
        memcpy(out_error->message_ptr, "failed", 6);
        out_error->message_len = 6;
        return OvStoragePlugin_StreamStep_Failed;
    }

    out_chunk->ptr = (uint8_t *)malloc(1);
    assert(out_chunk->ptr != NULL);
    out_chunk->ptr[0] = 0xa5;
    out_chunk->len = 1;
    return OvStoragePlugin_StreamStep_Yielded;
}

static void ovc_stream_test_body_drop(void *opaque)
{
    ovc_stream_test_body_state *state;

    state = (ovc_stream_test_body_state *)opaque;
    ++state->drop_count;
}

static void ovc_stream_test_body_delivery_and_failure(void)
{
    int fail;

    for (fail = 0; fail <= 1; ++fail) {
        ovc_stream_test_body_state state;
        ovc_stream_test_terminal_state terminal;
        ovc_stream_cancel_scope *scope;
        OvStoragePlugin_BodyStream *stream;
        ovc_stream_pump *pump;

        memset(&state, 0, sizeof(state));
        memset(&terminal, 0, sizeof(terminal));
        state.fail = fail;
        ovc_stream_sync_success(
            ovc_completion_latch_init(&terminal.completed));
        scope = ovc_stream_cancel_scope_create(NULL);
        assert(scope != NULL);
        stream = (OvStoragePlugin_BodyStream *)malloc(sizeof(*stream));
        assert(stream != NULL);
        stream->state = &state;
        stream->next_fn = ovc_stream_test_body_next;
        stream->drop_fn = ovc_stream_test_body_drop;

        ovc_stream_sync_success(
            ovc_byte_stream_pump_start(&pump,
                                       stream,
                                       stream,
                                       ovc_stream_test_body_reclaim,
                                       scope,
                                       ovc_stream_test_chunk,
                                       ovc_stream_test_terminal,
                                       &terminal));
        ovc_stream_pump_arm(pump);
        ovc_stream_sync_success(
            ovc_completion_latch_wait(&terminal.completed));
        ovc_stream_pump_destroy(pump);

        assert(state.drop_count == 1);
        assert(terminal.terminal_count == 1);
        if (fail) {
            assert(state.next_count == 1);
            assert(terminal.reason == OVC_STREAM_TERMINAL_FAILED);
            assert(terminal.delivered_count == 0);
            assert(terminal.error_count == 1);
        } else {
            assert(state.next_count == 2);
            assert(terminal.reason == OVC_STREAM_TERMINAL_ENDED);
            assert(terminal.delivered_count == 1);
            assert(terminal.error_count == 0);
        }
        ovc_stream_sync_success(
            ovc_completion_latch_destroy(&terminal.completed));
    }
}

typedef struct ovc_stream_test_auth_state {
    int next_count;
    int drop_count;
} ovc_stream_test_auth_state;

static OvStoragePlugin_StreamStep ovc_stream_test_auth_next(
    void *opaque,
    OvStoragePlugin_AuthEvent *out_event,
    OvStoragePlugin_Error *out_error)
{
    ovc_stream_test_auth_state *state;

    (void)out_error;
    state = (ovc_stream_test_auth_state *)opaque;
    if (state->next_count == 2) {
        return OvStoragePlugin_StreamStep_Ended;
    }
    memset(out_event, 0, sizeof(*out_event));
    out_event->tag = OvStoragePlugin_AuthEventTag_Progress;
    out_event->progress.message.ptr = (char *)malloc(4);
    assert(out_event->progress.message.ptr != NULL);
    memcpy(out_event->progress.message.ptr, "work", 4);
    out_event->progress.message.len = 4;
    ++state->next_count;
    return OvStoragePlugin_StreamStep_Yielded;
}

static void ovc_stream_test_auth_drop(void *opaque)
{
    ovc_stream_test_auth_state *state;

    state = (ovc_stream_test_auth_state *)opaque;
    ++state->drop_count;
}

static void ovc_stream_test_auth_reclaim(void *owner)
{
    OvStoragePlugin_AuthEventStream *stream;

    stream = (OvStoragePlugin_AuthEventStream *)owner;
    stream->drop_fn(stream->state);
    free(stream);
}

static void ovc_stream_test_event(OvStoragePlugin_AuthEvent *event,
                                  bool deliver,
                                  void *user_data)
{
    ovc_stream_test_terminal_state *terminal;

    assert(event->tag == OvStoragePlugin_AuthEventTag_Progress);
    assert(event->progress.message.ptr != NULL);
    assert(event->progress.message.len == 4);
    free(event->progress.message.ptr);
    event->progress.message.ptr = NULL;
    event->progress.message.len = 0;
    terminal = (ovc_stream_test_terminal_state *)user_data;
    if (deliver) {
        ++terminal->delivered_count;
    } else {
        ++terminal->discarded_count;
    }
}

static void ovc_stream_test_auth_multi_fire(void)
{
    ovc_stream_test_auth_state state;
    ovc_stream_test_terminal_state terminal;
    ovc_stream_cancel_scope *scope;
    OvStoragePlugin_AuthEventStream *stream;
    ovc_stream_pump *pump;

    memset(&state, 0, sizeof(state));
    memset(&terminal, 0, sizeof(terminal));
    ovc_stream_sync_success(
        ovc_completion_latch_init(&terminal.completed));
    scope = ovc_stream_cancel_scope_create(NULL);
    assert(scope != NULL);
    stream = (OvStoragePlugin_AuthEventStream *)malloc(sizeof(*stream));
    assert(stream != NULL);
    stream->state = &state;
    stream->next_fn = ovc_stream_test_auth_next;
    stream->drop_fn = ovc_stream_test_auth_drop;

    ovc_stream_sync_success(
        ovc_auth_stream_pump_start(&pump,
                                   stream,
                                   stream,
                                   ovc_stream_test_auth_reclaim,
                                   scope,
                                   ovc_stream_test_event,
                                   ovc_stream_test_terminal,
                                   &terminal));
    assert(state.next_count == 0);
    assert(terminal.terminal_count == 0);
    ovc_stream_pump_arm(pump);
    ovc_stream_sync_success(
        ovc_completion_latch_wait(&terminal.completed));
    ovc_stream_pump_destroy(pump);

    assert(state.next_count == 2);
    assert(state.drop_count == 1);
    assert(terminal.delivered_count == 2);
    assert(terminal.discarded_count == 0);
    assert(terminal.terminal_count == 1);
    assert(terminal.reason == OVC_STREAM_TERMINAL_ENDED);
    ovc_stream_sync_success(
        ovc_completion_latch_destroy(&terminal.completed));
}

typedef struct ovc_stream_test_discard_state {
    int next_count;
    int drop_count;
} ovc_stream_test_discard_state;

static OvStoragePlugin_StreamStep ovc_stream_test_root_next(
    void *opaque,
    OvStoragePlugin_RootInfoChange *out_item,
    OvStoragePlugin_Error *out_error)
{
    ovc_stream_test_discard_state *state;

    (void)out_item;
    (void)out_error;
    state = (ovc_stream_test_discard_state *)opaque;
    ++state->next_count;
    return OvStoragePlugin_StreamStep_Ended;
}

static void ovc_stream_test_discard_drop(void *opaque)
{
    ovc_stream_test_discard_state *state;

    state = (ovc_stream_test_discard_state *)opaque;
    ++state->drop_count;
}

static void ovc_stream_test_root_reclaim(void *owner)
{
    OvStoragePlugin_RootInfoChangeStream *stream;

    stream = (OvStoragePlugin_RootInfoChangeStream *)owner;
    stream->drop_fn(stream->state);
    free(stream);
}

static OvStoragePlugin_StreamStep ovc_stream_test_connection_next(
    void *opaque,
    OvStoragePlugin_ConnectionChange *out_item,
    OvStoragePlugin_Error *out_error)
{
    ovc_stream_test_discard_state *state;

    (void)out_item;
    (void)out_error;
    state = (ovc_stream_test_discard_state *)opaque;
    ++state->next_count;
    return OvStoragePlugin_StreamStep_Ended;
}

static void ovc_stream_test_connection_reclaim(void *owner)
{
    OvStoragePlugin_ConnectionChangeStream *stream;

    stream = (OvStoragePlugin_ConnectionChangeStream *)owner;
    stream->drop_fn(stream->state);
    free(stream);
}

static void ovc_stream_test_snapshot_discard(void)
{
    ovc_stream_test_discard_state state;
    OvStoragePlugin_RootInfoChangeStream *root_stream;
    OvStoragePlugin_ConnectionChangeStream *connection_stream;

    memset(&state, 0, sizeof(state));
    root_stream =
        (OvStoragePlugin_RootInfoChangeStream *)malloc(sizeof(*root_stream));
    assert(root_stream != NULL);
    root_stream->state = &state;
    root_stream->next_fn = ovc_stream_test_root_next;
    root_stream->drop_fn = ovc_stream_test_discard_drop;

    ovc_stream_sync_success(
        ovc_root_updates_discard(root_stream,
                                 root_stream,
                                 ovc_stream_test_root_reclaim));
    assert(state.next_count == 0);
    assert(state.drop_count == 1);

    connection_stream = (OvStoragePlugin_ConnectionChangeStream *)malloc(
        sizeof(*connection_stream));
    assert(connection_stream != NULL);
    connection_stream->state = &state;
    connection_stream->next_fn = ovc_stream_test_connection_next;
    connection_stream->drop_fn = ovc_stream_test_discard_drop;

    ovc_stream_sync_success(
        ovc_connection_updates_discard(
            connection_stream,
            connection_stream,
            ovc_stream_test_connection_reclaim));
    assert(state.next_count == 0);
    assert(state.drop_count == 2);
}

int main(void)
{
    ovc_stream_test_blocked_cancel_and_runtime();
    ovc_stream_test_body_delivery_and_failure();
    ovc_stream_test_auth_multi_fire();
    ovc_stream_test_snapshot_discard();
    return 0;
}

#endif /* OVC_STREAMS_TEST_MAIN */

#if defined(OVC_STREAM_TYPE_MATCH)
#undef OVC_STREAM_TYPE_MATCH
#endif
#undef OVC_STREAM_STATIC_ASSERT
#undef OVC_STREAM_JOIN
#undef OVC_STREAM_JOIN_INNER
