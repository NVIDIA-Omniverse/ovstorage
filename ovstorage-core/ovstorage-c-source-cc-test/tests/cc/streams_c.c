/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(OVC_INSPECT_FIXTURE)

#include "ovstorage_plugin.h"

#include <string.h>

#if defined(_WIN32)
#define OVC_TEST_EXPORT __declspec(dllexport)
#else
#define OVC_TEST_EXPORT __attribute__((visibility("default")))
#endif

static char g_inspect_kind[] = "cc-test-inspect";
static char g_inspect_display_name[] = "C source inspect fixture";
static int g_inspect_plugin_state;

static void inspect_fixture_drop(void *plugin_state)
{
    (void)plugin_state;
}

static OvStoragePlugin_FfiStatus inspect_fixture_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    (void)plugin_state;
    (void)request;
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (error != NULL) {
        *error = NULL;
    }
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static const OvStoragePlugin_PluginVTableV1 g_inspect_plugin_vtable = {
    .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = inspect_fixture_drop,
    .create_backend = inspect_fixture_create_backend,
};

static const OvStoragePlugin_LayerKindDescriptor g_inspect_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Backend,
    .accepts_connections = true,
    .kind = {g_inspect_kind, sizeof(g_inspect_kind) - 1},
    .display_name = {g_inspect_display_name,
                     sizeof(g_inspect_display_name) - 1},
    .auth_capable = false,
};

OVC_TEST_EXPORT const OvStoragePlugin_PluginManifestV1
    ovstorage_plugin_manifest_v1 = {
        .struct_size = sizeof(OvStoragePlugin_PluginManifestV1),
        .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
        .name = "ovstorage-c-source-cc-test-inspect",
        .version = "0.0.0",
        .test_only = true,
};

OVC_TEST_EXPORT OvStoragePlugin_PluginInitResultV1
ovstorage_plugin_init_v1(const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    (void)host;
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.abi_version =
        OVSTORAGE_PLUGIN_ABI_VERSION;
    result.plugin_state = &g_inspect_plugin_state;
    result.plugin_vtable = &g_inspect_plugin_vtable;
    result.kinds = &g_inspect_descriptor;
    result.kind_count = 1;
    return result;
}

#else /* OVC_INSPECT_FIXTURE */

/* internal.h must precede every libc header in this translation unit. */
#include "../../../../ovstorage-c-source/src/internal.h"
#include "../../../../ovstorage-c-source/src/temp_dir.h"

#include "file_url.h"
#include "ovstorage_defaults.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include "windows_posix_compat.h"
#define unlink(path) ovc_test_remove_file(path)
#define rmdir(path) ovc_test_remove_dir(path)
#define close(descriptor) _close(descriptor)
#define dup(descriptor) _dup(descriptor)
#define dup2(source, destination) _dup2((source), (destination))
#define fileno(stream) _fileno(stream)
#define STDERR_FILENO 2
#else
#include <unistd.h>
#endif

#if defined(NDEBUG)
#error "the C source contract tests require assertions"
#endif

/* dispatch.c owns this deliberately-private constructor. The cc-test uses it
 * to put a controlled vtable behind the exact public LayerHandle dispatch. */
OvStorage_LayerHandle *ovc_dispatch_layer_handle_create(
    OvStoragePlugin_LayerHandle root,
    ovc_layer_factory *const *factories,
    size_t factory_count);

/* dispatch.c's deliberately-private introspection twin: the number of stream
 * pumps currently registered on a handle. The reap pin below uses it to
 * assert completed auth pumps detach at their terminal, not at destroy. */
size_t ovc_dispatch_registered_pump_count(OvStorage_LayerHandle *handle);

#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
/* Implemented by leak_contracts_main.c in the instrumented contract binary. */
void ovc_test_abi_alloc_arm(size_t byte_count, const char *site);
int ovc_test_abi_alloc_expect_fired(const char *site);
#endif

static void test_sleep_ns(ovc_mutex *mutex,
                          ovc_cond *cond,
                          uint64_t wait_ns);
static OvStoragePlugin_Str test_owned_str(const char *value);

typedef struct TestIoResult {
    ovc_completion_latch completed;
    OvStorage_Status status;
    OvStorage_Info *info;
    OvStorage_Bytes bytes;
    int callback_count;
    int had_error;
    char error_message[128];
} TestIoResult;

static void test_io_result_init(TestIoResult *result)
{
    memset(result, 0, sizeof(*result));
    assert(ovc_completion_latch_init(&result->completed) == 0);
}

static void test_info_complete(OvStorage_Status status,
                               OvStorage_Info *info,
                               const OvStorage_Error *error,
                               void *user_data)
{
    TestIoResult *result;
    const char *message;
    size_t message_len;

    result = (TestIoResult *)user_data;
    result->status = status;
    result->info = info;
    result->had_error = error != NULL;
    message = error == NULL ? NULL : ovstorage_error_message(error);
    if (message != NULL) {
        message_len = strlen(message);
        assert(message_len < sizeof(result->error_message));
        memcpy(result->error_message, message, message_len + 1);
    }
    ++result->callback_count;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_read_complete(OvStorage_Status status,
                               OvStorage_Bytes bytes,
                               OvStorage_Info *info,
                               const OvStorage_Error *error,
                               void *user_data)
{
    TestIoResult *result;

    result = (TestIoResult *)user_data;
    result->status = status;
    result->bytes = bytes;
    result->info = info;
    result->had_error = error != NULL;
    ++result->callback_count;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_io_result_wait(TestIoResult *result)
{
    assert(ovc_completion_latch_wait(&result->completed) == 0);
}

static void test_io_result_destroy(TestIoResult *result)
{
    ovstorage_info_destroy(result->info);
    ovstorage_bytes_destroy(&result->bytes);
    assert(ovc_completion_latch_destroy(&result->completed) == 0);
}

typedef struct BlockingPullState {
    ovc_mutex mutex;
    ovc_cond changed;
    int block;
    int fail_on_wake;
    int yield_nul_progress;
    int entered;
    int wake;
    int sequence;
    int next_return_sequence;
    int drop_sequence;
    int next_count;
    int drop_count;
    OvStoragePlugin_CancelTokenFFI cancel;
    uint64_t cancel_subscription;
} BlockingPullState;

static void blocking_pull_wake(void *user_data)
{
    BlockingPullState *state;

    state = (BlockingPullState *)user_data;
    assert(ovc_mutex_lock(&state->mutex) == 0);
    state->wake = 1;
    assert(ovc_cond_broadcast(&state->changed) == 0);
    assert(ovc_mutex_unlock(&state->mutex) == 0);
}

static BlockingPullState *blocking_pull_create(
    const OvStoragePlugin_CancelTokenFFI *cancel,
    int block)
{
    BlockingPullState *state;

    assert(cancel != NULL);
    assert(cancel->state != NULL);
    assert(cancel->clone != NULL);
    assert(cancel->register_callback != NULL);
    state = (BlockingPullState *)calloc(1, sizeof(*state));
    assert(state != NULL);
    assert(ovc_mutex_init(&state->mutex) == 0);
    assert(ovc_cond_init(&state->changed) == 0);
    state->block = block;
    state->cancel = *cancel;
    state->cancel.state = cancel->clone(cancel->state);
    assert(state->cancel.state != NULL);
    state->cancel_subscription = state->cancel.register_callback(
        state->cancel.state, blocking_pull_wake, state);
    assert(state->cancel_subscription != 0);
    return state;
}

static OvStoragePlugin_StreamStep blocking_pull_next(
    BlockingPullState *state)
{
    assert(ovc_mutex_lock(&state->mutex) == 0);
    state->entered = 1;
    assert(ovc_cond_broadcast(&state->changed) == 0);
    while (state->block && !state->wake) {
        assert(ovc_cond_wait(&state->changed, &state->mutex) == 0);
    }
    ++state->next_count;
    state->next_return_sequence = ++state->sequence;
    assert(ovc_mutex_unlock(&state->mutex) == 0);
    return OvStoragePlugin_StreamStep_Ended;
}

static void blocking_pull_drop(void *opaque)
{
    BlockingPullState *state;

    state = (BlockingPullState *)opaque;
    state->cancel.unregister_callback(state->cancel.state,
                                      state->cancel_subscription);
    state->cancel.drop(state->cancel.state);
    assert(ovc_mutex_lock(&state->mutex) == 0);
    state->drop_sequence = ++state->sequence;
    ++state->drop_count;
    assert(ovc_cond_broadcast(&state->changed) == 0);
    assert(ovc_mutex_unlock(&state->mutex) == 0);
}

static void blocking_pull_wait_entered(BlockingPullState *state)
{
    assert(ovc_mutex_lock(&state->mutex) == 0);
    while (!state->entered) {
        assert(ovc_cond_wait(&state->changed, &state->mutex) == 0);
    }
    assert(ovc_mutex_unlock(&state->mutex) == 0);
}

static void blocking_pull_assert_dropped_once(BlockingPullState *state)
{
    assert(ovc_mutex_lock(&state->mutex) == 0);
    assert(state->next_count == 1);
    assert(state->drop_count == 1);
    assert(state->next_return_sequence != 0);
    assert(state->next_return_sequence < state->drop_sequence);
    assert(ovc_mutex_unlock(&state->mutex) == 0);
}

static void blocking_pull_destroy(BlockingPullState *state)
{
    assert(ovc_cond_destroy(&state->changed) == 0);
    assert(ovc_mutex_destroy(&state->mutex) == 0);
    free(state);
}

typedef struct StubLayer {
    OvStoragePlugin_LayerVTableV1 vtable;
    ovc_mutex mutex;
    int block_auth;
    int fail_auth;
    int yield_nul_progress;
    int watch_mode;
    int redirect_overflow;
    uint64_t watch_poll_interval_ms;
    size_t watch_since_len;
    int watch_since_present;
    int drop_count;
    BlockingPullState *last_pull;
    ovc_mutex barrier_mutex;
    ovc_cond barrier_changed;
    int barrier_arrivals;
    int barrier_timed_out;
} StubLayer;

typedef struct StubWatchState {
    int mode;
    int index;
    BlockingPullState *pull;
} StubWatchState;

static OvStoragePlugin_StreamStep stub_auth_next(
    void *opaque,
    OvStoragePlugin_AuthEvent *out_event,
    OvStoragePlugin_Error *out_error)
{
    static const char failure_message[] = "stub auth transient failure";
    BlockingPullState *state;
    OvStoragePlugin_StreamStep step;

    (void)out_event;
    state = (BlockingPullState *)opaque;
    /* yield_nul_progress and fail_on_wake are written once before the
     * stream is handed to the pump, so the unlocked reads here are ordered
     * by the stream handoff. */
    if (state->yield_nul_progress) {
        /* Interior NUL included: the dispatcher must convert this lossily
         * ("step\0one" -> "step\\0one") instead of failing the flow. */
        static const char nul_message[] = "step\0one";
        char *copy;

        state->yield_nul_progress = 0;
        copy = (char *)ovc_abi_alloc(sizeof(nul_message) - 1);
        assert(copy != NULL);
        memcpy(copy, nul_message, sizeof(nul_message) - 1);
        memset(out_event, 0, sizeof(*out_event));
        out_event->tag = OvStoragePlugin_AuthEventTag_Progress;
        out_event->progress.message.ptr = copy;
        out_event->progress.message.len = sizeof(nul_message) - 1;
        return OvStoragePlugin_StreamStep_Yielded;
    }
    step = blocking_pull_next(state);
    if (state->fail_on_wake) {
        static const char hint[] = "Retry once the upstream settles.";
        char *copy;
        char *hint_copy;

        /* Minted with the ABI allocator: the dispatcher releases plugin
         * error messages with ovc_abi_free. */
        copy = (char *)ovc_abi_alloc(sizeof(failure_message));
        assert(copy != NULL);
        memcpy(copy, failure_message, sizeof(failure_message));
        memset(out_error, 0, sizeof(*out_error));
        out_error->code = OvStoragePlugin_ErrorCode_Transient;
        out_error->message_ptr = copy;
        out_error->message_len = sizeof(failure_message) - 1;
        /* A recovery hint, owned by the error exactly like the message. A
         * reclamation path that releases the message but not this one is a
         * leak the sanitizer leg reports; the hint is what a real plugin
         * attaches via with_next_action. */
        hint_copy = (char *)ovc_abi_alloc(sizeof(hint) - 1);
        assert(hint_copy != NULL);
        memcpy(hint_copy, hint, sizeof(hint) - 1);
        out_error->next_action.present = true;
        out_error->next_action.value.ptr = hint_copy;
        out_error->next_action.value.len = sizeof(hint) - 1;
        return OvStoragePlugin_StreamStep_Failed;
    }
    return step;
}

static OvStoragePlugin_StreamStep stub_watch_next(
    void *opaque,
    OvStoragePlugin_BackendChangeEvent *out_event,
    OvStoragePlugin_Error *out_error)
{
    (void)out_event;
    (void)out_error;
    return blocking_pull_next((BlockingPullState *)opaque);
}

static OvStoragePlugin_Str stub_watch_str(const char *value)
{
    OvStoragePlugin_Str result;

    result.len = strlen(value);
    result.ptr = (char *)ovc_abi_copy_bytes(value, result.len);
    assert(result.ptr != NULL);
    return result;
}

static OvStoragePlugin_Bytes stub_watch_bytes(const char *value)
{
    OvStoragePlugin_Bytes result;

    result.len = strlen(value);
    result.ptr = (uint8_t *)ovc_abi_copy_bytes(value, result.len);
    assert(result.ptr != NULL);
    return result;
}

static int stub_watch_prefix_equals(
    const OvStoragePlugin_WatchDirectoryRequest *request,
    const char *expected)
{
    size_t expected_len;

    expected_len = strlen(expected);
    return request->prefix.len == expected_len &&
           memcmp(request->prefix.ptr, expected, expected_len) == 0;
}

static OvStoragePlugin_StreamStep stub_watch_event_next(
    void *opaque,
    OvStoragePlugin_BackendChangeEvent *out_event,
    OvStoragePlugin_Error *out_error)
{
    StubWatchState *state;

    state = (StubWatchState *)opaque;
    memset(out_event, 0, sizeof(*out_event));
    memset(out_error, 0, sizeof(*out_error));
    if (state->mode == 2 && state->index == 0) {
        out_event->tag = OvStoragePlugin_BackendChangeEventTag_Object;
        out_event->object.address =
            stub_watch_str("test://watched/malformed");
        out_event->object.kind = OvStoragePlugin_ChangeKind_Modified;
        out_event->object.at_unix_ms = INT64_C(1700000000000);
        out_event->object.cursor.bytes.ptr = NULL;
        out_event->object.cursor.bytes.len = 1;
        ++state->index;
        return OvStoragePlugin_StreamStep_Yielded;
    }
    if (state->mode != 1 && state->mode != 3 && state->mode != 4) {
        return OvStoragePlugin_StreamStep_Ended;
    }
    if (state->index == 0) {
        out_event->tag = OvStoragePlugin_BackendChangeEventTag_Object;
        out_event->object.address =
            stub_watch_str("test://watched/object");
        out_event->object.kind = OvStoragePlugin_ChangeKind_Modified;
        out_event->object.etag.present = true;
        out_event->object.etag.value = stub_watch_str("etag-1");
        out_event->object.version.present = true;
        out_event->object.version.value = stub_watch_str("version-1");
        out_event->object.size.present = true;
        out_event->object.size.value = 42;
        out_event->object.mtime_unix_ms.present = true;
        out_event->object.mtime_unix_ms.value =
            state->mode == 3 ? -1 : INT64_C(1700000000123);
        out_event->object.at_unix_ms = INT64_C(1700000000000);
        out_event->object.cursor.bytes =
            stub_watch_bytes("object-cursor");
        ++state->index;
        return OvStoragePlugin_StreamStep_Yielded;
    }
    if (state->mode == 4 && state->index == 1) {
        return blocking_pull_next(state->pull);
    }
    if (state->index == 1) {
        out_event->tag = OvStoragePlugin_BackendChangeEventTag_Lapsed;
        out_event->lapsed.since_unix_ms.present = true;
        out_event->lapsed.since_unix_ms.value =
            state->mode == 3 ? -1 : INT64_C(1700000001000);
        out_event->lapsed.cursor.bytes =
            stub_watch_bytes("lapsed-cursor");
        ++state->index;
        return OvStoragePlugin_StreamStep_Yielded;
    }
    return OvStoragePlugin_StreamStep_Ended;
}

static void stub_watch_event_drop(void *opaque)
{
    StubWatchState *state;

    state = (StubWatchState *)opaque;
    if (state->pull != NULL) {
        blocking_pull_drop(state->pull);
        blocking_pull_destroy(state->pull);
    }
    free(state);
}

static void stub_layer_drop(void *opaque)
{
    StubLayer *layer;

    layer = (StubLayer *)opaque;
    assert(ovc_mutex_lock(&layer->mutex) == 0);
    ++layer->drop_count;
    assert(ovc_mutex_unlock(&layer->mutex) == 0);
}

static void stub_take_auth_request(
    const OvStoragePlugin_AuthenticateRequest *request)
{
    if (request == NULL) {
        return;
    }
    /* The dispatcher mints moved-in request payloads with ovc_abi_alloc, so
     * the stub that takes them must release them with the matching
     * ovc_abi_free rather than the CRT allocator. */
    ovc_abi_free(request->key.target.ptr);
    ovc_abi_free(request->key.id.ptr);
}

static void stub_authenticate(
    void *opaque,
    const OvStoragePlugin_AuthenticateRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    StubLayer *layer;
    BlockingPullState *pull;
    OvStoragePlugin_AuthEventStream *stream;

    layer = (StubLayer *)opaque;
    pull = blocking_pull_create(cancel, layer->block_auth);
    pull->fail_on_wake = layer->fail_auth;
    pull->yield_nul_progress = layer->yield_nul_progress;
    /* ABI mint: the dispatcher reclaims this outer block with ovc_abi_free
     * in ovc_dispatch_auth_stream_reclaim. */
    stream = (OvStoragePlugin_AuthEventStream *)ovc_abi_alloc(sizeof(*stream));
    assert(stream != NULL);
    memset(stream, 0, sizeof(*stream));
    stream->state = pull;
    stream->next_fn = stub_auth_next;
    stream->drop_fn = blocking_pull_drop;
    assert(ovc_mutex_lock(&layer->mutex) == 0);
    assert(layer->last_pull == NULL);
    layer->last_pull = pull;
    assert(ovc_mutex_unlock(&layer->mutex) == 0);
    stub_take_auth_request(request);
    on_complete(OvStoragePlugin_FFI_STATUS_OK, stream, NULL, user_data);
}

static void stub_watch_directory(
    void *opaque,
    const OvStoragePlugin_WatchDirectoryRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    StubLayer *layer;
    BlockingPullState *pull;
    StubWatchState *events;
    OvStoragePlugin_BackendChangeStream *stream;
    OvStoragePlugin_WatchDirectoryRequest moved;

    layer = (StubLayer *)opaque;
    if (stub_watch_prefix_equals(request, "test://watched-default/")) {
        assert(!request->options.recursive);
        assert(request->options.include_metadata_changes);
        assert(!request->options.since.present);
        assert(request->options.poll_interval_ms == 1000);
    }
    layer->watch_poll_interval_ms = request->options.poll_interval_ms;
    layer->watch_since_present = request->options.since.present;
    layer->watch_since_len = request->options.since.present
                                 ? request->options.since.value.bytes.len
                                 : 0;
    /* ABI mint for uniformity with the auth stream; the watch test's own
     * pump reclaims it with the matching ovc_abi_free. */
    stream = (OvStoragePlugin_BackendChangeStream *)ovc_abi_alloc(
        sizeof(*stream));
    assert(stream != NULL);
    memset(stream, 0, sizeof(*stream));
    if (layer->watch_mode == 0) {
        pull = blocking_pull_create(cancel, 1);
        stream->state = pull;
        stream->next_fn = stub_watch_next;
        stream->drop_fn = blocking_pull_drop;
        assert(ovc_mutex_lock(&layer->mutex) == 0);
        assert(layer->last_pull == NULL);
        layer->last_pull = pull;
        assert(ovc_mutex_unlock(&layer->mutex) == 0);
    } else {
        events = (StubWatchState *)calloc(1, sizeof(*events));
        assert(events != NULL);
        events->mode =
            stub_watch_prefix_equals(request, "test://throwing-watch/")
                ? 4
                : layer->watch_mode;
        if (events->mode == 4) {
            events->pull = blocking_pull_create(cancel, 1);
        }
        stream->state = events;
        stream->next_fn = stub_watch_event_next;
        stream->drop_fn = stub_watch_event_drop;
    }
    moved = *request;
    ovstorage_plugin_str_free(&moved.prefix);
    if (moved.options.since.present) {
        ovstorage_plugin_bytes_free(
            &moved.options.since.value.bytes);
    }
    on_complete(OvStoragePlugin_FFI_STATUS_OK, stream, NULL, user_data);
}

static void stub_io_barrier(StubLayer *layer)
{
    uint64_t deadline;
    uint64_t now;
    int result;

    deadline = ovc_monotonic_ns() + UINT64_C(5000000000);
    assert(ovc_mutex_lock(&layer->barrier_mutex) == 0);
    ++layer->barrier_arrivals;
    assert(ovc_cond_broadcast(&layer->barrier_changed) == 0);
    while (layer->barrier_arrivals != 2 && !layer->barrier_timed_out) {
        now = ovc_monotonic_ns();
        if (now >= deadline) {
            layer->barrier_timed_out = 1;
            assert(ovc_cond_broadcast(&layer->barrier_changed) == 0);
            break;
        }
        result = ovc_cond_timedwait_ns(&layer->barrier_changed,
                                       &layer->barrier_mutex,
                                       deadline - now);
        if (result == ETIMEDOUT) {
            layer->barrier_timed_out = 1;
            assert(ovc_cond_broadcast(&layer->barrier_changed) == 0);
        } else {
            assert(result == 0);
        }
    }
    assert(ovc_mutex_unlock(&layer->barrier_mutex) == 0);
}

static void stub_fill_info(OvStoragePlugin_ObjectInfo *info,
                           OvStoragePlugin_Str address,
                           uint64_t size)
{
    memset(info, 0, sizeof(*info));
    info->address = address;
    info->kind = OvStoragePlugin_ObjectKindV1_File;
    info->size.present = true;
    info->size.value = size;
}

static int stub_str_eq(OvStoragePlugin_Str value, const char *expected)
{
    size_t length;

    length = strlen(expected);
    return value.ptr != NULL && value.len == length &&
           memcmp(value.ptr, expected, length) == 0;
}

static OvStoragePlugin_Connection *stub_connection(
    const char *id,
    const char *display_name)
{
    OvStoragePlugin_Connection *connection;

    connection = (OvStoragePlugin_Connection *)ovc_abi_alloc(
        sizeof(*connection));
    assert(connection != NULL);
    memset(connection, 0, sizeof(*connection));
    connection->id.id = test_owned_str(id);
    connection->backend_kind = test_owned_str("stub-kind");
    connection->display_name = test_owned_str(display_name);
    connection->source.tag =
        OvStoragePlugin_ConnectionSourceTag_Runtime;
    connection->source.runtime.persisted = true;
    connection->auth_state.tag =
        OvStoragePlugin_ConnectionAuthStateTag_Authenticated;
    return connection;
}

static void stub_get_latest_version(
    void *opaque,
    const OvStoragePlugin_ReadRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ObjectInfo *info;

    (void)opaque;
    (void)cancel;
    assert(request->struct_size == sizeof(*request));
    assert(stub_str_eq(request->address, "test://latest-version"));
    assert(request->options.struct_size == sizeof(request->options));
    assert(request->options.range.present);
    assert(request->options.range.value.start == 2);
    assert(request->options.range.value.end_inclusive.present);
    assert(request->options.range.value.end_inclusive.value == 4);
    info = (OvStoragePlugin_ObjectInfo *)ovc_abi_alloc(sizeof(*info));
    assert(info != NULL);
    stub_fill_info(info, request->address, UINT64_C(777));
    on_complete(OvStoragePlugin_FFI_STATUS_OK, info, NULL, user_data);
}

static void stub_probe(
    void *opaque,
    const OvStoragePlugin_LayerConnectionRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    static const uint8_t expected_secret[] = {1, 2, 3, 4};
    OvStoragePlugin_LayerConnectionRequest moved;
    OvStoragePlugin_Connection *connection;

    (void)opaque;
    (void)cancel;
    moved = *request;
    assert(moved.struct_size == sizeof(moved));
    assert(stub_str_eq(moved.target, "test://probe-target"));
    assert(stub_str_eq(moved.connection.backend_kind, "stub-kind"));
    assert(moved.connection.persist);
    assert(moved.connection.display_name.present);
    assert(stub_str_eq(moved.connection.display_name.value,
                       "Probe Display"));
    assert(moved.connection.config.len == 1);
    assert(stub_str_eq(moved.connection.config.ptr[0].key,
                       "endpoint"));
    assert(moved.connection.config.ptr[0].value.tag ==
           OvStoragePlugin_ConfigValueTag_String);
    assert(stub_str_eq(
        moved.connection.config.ptr[0].value.string_value,
        "test://config-value"));
    assert(moved.connection.credentials.entries.len == 1);
    assert(stub_str_eq(
        moved.connection.credentials.entries.ptr[0].field,
        "token"));
    assert(moved.connection.credentials.entries.ptr[0].value.tag ==
           OvStoragePlugin_SecretValueTag_Bytes);
    assert(moved.connection.credentials.entries.ptr[0].value.bytes.bytes.len ==
           sizeof(expected_secret));
    assert(memcmp(
               moved.connection.credentials.entries.ptr[0]
                   .value.bytes.bytes.ptr,
               expected_secret,
               sizeof(expected_secret)) == 0);
    ovstorage_plugin_str_free(&moved.target);
    ovstorage_plugin_connection_request_free(&moved.connection);
    connection = stub_connection("probe-sentinel", "Probe Result");
    on_complete(OvStoragePlugin_FFI_STATUS_OK,
                connection,
                NULL,
                user_data);
}

static void stub_update_connection_attributes(
    void *opaque,
    const OvStoragePlugin_UpdateConnectionAttributesRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_UpdateConnectionAttributesRequest moved;
    OvStoragePlugin_Connection *connection;
    size_t index;

    (void)opaque;
    (void)cancel;
    moved = *request;
    assert(moved.struct_size == sizeof(moved));
    assert(stub_str_eq(moved.key.target, "test://attributes-target"));
    assert(stub_str_eq(moved.key.id, "connection-394"));
    assert(moved.patch.display_name.present);
    assert(stub_str_eq(moved.patch.display_name.value,
                       "Updated Display"));
    assert(moved.patch.access_mode.present);
    assert(stub_str_eq(moved.patch.access_mode.value, "read-write"));
    assert(moved.patch.visible.present);
    assert(!moved.patch.visible.value);
    assert(moved.patch.set_user_metadata.len == 1);
    assert(stub_str_eq(moved.patch.set_user_metadata.ptr[0].key,
                       "owner"));
    assert(stub_str_eq(moved.patch.set_user_metadata.ptr[0].value,
                       "integration-test"));
    assert(moved.patch.remove_user_metadata.len == 1);
    assert(stub_str_eq(moved.patch.remove_user_metadata.ptr[0],
                       "obsolete"));

    ovstorage_plugin_str_free(&moved.key.target);
    ovstorage_plugin_str_free(&moved.key.id);
    ovstorage_plugin_str_free(&moved.patch.display_name.value);
    ovstorage_plugin_str_free(&moved.patch.access_mode.value);
    for (index = 0; index < moved.patch.set_user_metadata.len; ++index) {
        ovstorage_plugin_str_free(
            &moved.patch.set_user_metadata.ptr[index].key);
        ovstorage_plugin_str_free(
            &moved.patch.set_user_metadata.ptr[index].value);
    }
    ovc_abi_free(moved.patch.set_user_metadata.ptr);
    for (index = 0; index < moved.patch.remove_user_metadata.len; ++index) {
        ovstorage_plugin_str_free(
            &moved.patch.remove_user_metadata.ptr[index]);
    }
    ovc_abi_free(moved.patch.remove_user_metadata.ptr);
    connection =
        stub_connection("attributes-sentinel", "Attributes Result");
    on_complete(OvStoragePlugin_FFI_STATUS_OK,
                connection,
                NULL,
                user_data);
}

static void stub_stat(void *opaque,
                      const OvStoragePlugin_StatRequest *request,
                      const OvStoragePlugin_CancelTokenFFI *cancel,
                      OvStoragePlugin_OnComplete on_complete,
                      void *user_data)
{
    StubLayer *layer;
    OvStoragePlugin_ObjectInfo *info;

    (void)cancel;
    layer = (StubLayer *)opaque;
    stub_io_barrier(layer);
    /* ABI mint: the dispatcher reclaims the ObjectInfo with ovc_abi_free. */
    info = (OvStoragePlugin_ObjectInfo *)ovc_abi_alloc(sizeof(*info));
    assert(info != NULL);
    memset(info, 0, sizeof(*info));
    stub_fill_info(info, request->address, UINT64_C(22));
    on_complete(OvStoragePlugin_FFI_STATUS_OK, info, NULL, user_data);
}

static void stub_read(void *opaque,
                      const OvStoragePlugin_ReadRequest *request,
                      const OvStoragePlugin_CancelTokenFFI *cancel,
                      OvStoragePlugin_OnComplete on_complete,
                      void *user_data)
{
    static const uint8_t payload[] = "two runtime workers live";
    StubLayer *layer;
    OvStoragePlugin_ReadResult *result;

    (void)cancel;
    layer = (StubLayer *)opaque;
    stub_io_barrier(layer);
    /* Both allocations are minted with the ABI allocator: the dispatcher
     * reclaims plugin read results (bytes and outer) with ovc_abi_free. */
    result = (OvStoragePlugin_ReadResult *)ovc_abi_alloc(sizeof(*result));
    assert(result != NULL);
    memset(result, 0, sizeof(*result));
    result->tag = OvStoragePlugin_ReadResultTag_Bytes;
    result->bytes.bytes.ptr = (uint8_t *)ovc_abi_alloc(sizeof(payload) - 1);
    assert(result->bytes.bytes.ptr != NULL);
    memcpy(result->bytes.bytes.ptr, payload, sizeof(payload) - 1);
    result->bytes.bytes.len = sizeof(payload) - 1;
    stub_fill_info(&result->bytes.info,
                   request->address,
                   sizeof(payload) - 1);
    on_complete(OvStoragePlugin_FFI_STATUS_OK, result, NULL, user_data);
}

static void stub_write_stream(
    void *opaque,
    const OvStoragePlugin_WriteRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_WriteRequest moved;
    OvStoragePlugin_WriteResult *result;
    OvStoragePlugin_Error *failed;
    OvStoragePlugin_Bytes chunk;
    OvStoragePlugin_Error error;
    OvStoragePlugin_StreamStep step;
    uint8_t received[14];
    uint64_t total;

    (void)opaque;
    (void)cancel;
    moved = *request;
    assert(moved.body.tag == OvStoragePlugin_BodyTag_Stream);
    total = 0;
    for (;;) {
        memset(&chunk, 0, sizeof(chunk));
        memset(&error, 0, sizeof(error));
        step = moved.body.stream.next_fn(moved.body.stream.state,
                                         &chunk,
                                         &error);
        if (step == OvStoragePlugin_StreamStep_Ended) {
            break;
        }
        if (step == OvStoragePlugin_StreamStep_Failed) {
            failed = (OvStoragePlugin_Error *)ovc_abi_alloc(
                sizeof(*failed));
            assert(failed != NULL);
            *failed = error;
            moved.body.stream.drop_fn(moved.body.stream.state);
            memset(&moved.body.stream, 0, sizeof(moved.body.stream));
            ovstorage_plugin_str_free(&moved.address);
            on_complete(OvStoragePlugin_FFI_STATUS_ERR,
                        NULL,
                        failed,
                        user_data);
            return;
        }
        assert(step == OvStoragePlugin_StreamStep_Yielded);
        assert(total <= sizeof(received));
        assert(chunk.len <= sizeof(received) - total);
        memcpy(received + total, chunk.ptr, chunk.len);
        total += chunk.len;
        ovstorage_plugin_bytes_free(&chunk);
    }
    assert(total == sizeof(received));
    assert(memcmp(received, "streamed write", sizeof(received)) == 0);
    moved.body.stream.drop_fn(moved.body.stream.state);
    memset(&moved.body.stream, 0, sizeof(moved.body.stream));
    result = (OvStoragePlugin_WriteResult *)ovc_abi_alloc(sizeof(*result));
    assert(result != NULL);
    memset(result, 0, sizeof(*result));
    stub_fill_info(&result->info, moved.address, total);
    memset(&moved.address, 0, sizeof(moved.address));
    on_complete(OvStoragePlugin_FFI_STATUS_OK, result, NULL, user_data);
}

static void stub_redirect_clear(OvStoragePlugin_WriteRedirect *redirect)
{
    size_t index;

    ovstorage_plugin_str_free(&redirect->request.method);
    ovstorage_plugin_str_free(&redirect->request.url);
    for (index = 0; index < redirect->request.headers.len; ++index) {
        ovstorage_plugin_str_free(
            &redirect->request.headers.ptr[index].key);
        ovstorage_plugin_str_free(
            &redirect->request.headers.ptr[index].value);
    }
    ovc_abi_free(redirect->request.headers.ptr);
    if (redirect->body_source.tag ==
        OvStoragePlugin_RedirectBodySourceTag_Inline) {
        ovstorage_plugin_bytes_free(&redirect->body_source.inline_);
    }
    for (index = 0; index < redirect->result_capture.headers.len;
         ++index) {
        ovstorage_plugin_str_free(
            &redirect->result_capture.headers.ptr[index]);
    }
    ovc_abi_free(redirect->result_capture.headers.ptr);
    ovstorage_plugin_str_free(&redirect->scope.physical_url_prefix);
    ovstorage_plugin_str_free(&redirect->audit_id);
}

static void stub_redirect_batch_clear(
    OvStoragePlugin_WriteRedirectBatch *batch)
{
    size_t index;

    ovstorage_plugin_bytes_free(&batch->continuation);
    for (index = 0; index < batch->redirects.len; ++index) {
        stub_redirect_clear(&batch->redirects.ptr[index]);
    }
    ovc_abi_free(batch->redirects.ptr);
    memset(batch, 0, sizeof(*batch));
}

static void stub_redirect_results_clear(
    OvStoragePlugin_RedirectResultBatch *batch)
{
    size_t index;
    size_t header_index;

    for (index = 0; index < batch->results.len; ++index) {
        for (header_index = 0;
             header_index <
             batch->results.ptr[index].captured_headers.len;
             ++header_index) {
            ovstorage_plugin_str_free(
                &batch->results.ptr[index]
                     .captured_headers.ptr[header_index]
                     .key);
            ovstorage_plugin_str_free(
                &batch->results.ptr[index]
                     .captured_headers.ptr[header_index]
                     .value);
        }
        ovc_abi_free(
            batch->results.ptr[index].captured_headers.ptr);
        ovstorage_plugin_bytes_free(
            &batch->results.ptr[index].captured_body);
    }
    ovc_abi_free(batch->results.ptr);
    memset(batch, 0, sizeof(*batch));
}

static OvStoragePlugin_WriteRedirectBatch *
stub_redirect_batch(const uint8_t *continuation,
                    size_t continuation_len,
                    int overflow_user_range)
{
    OvStoragePlugin_WriteRedirectBatch *batch;
    OvStoragePlugin_WriteRedirect *redirect;

    batch = (OvStoragePlugin_WriteRedirectBatch *)ovc_abi_alloc(
        sizeof(*batch));
    assert(batch != NULL);
    memset(batch, 0, sizeof(*batch));
    batch->continuation.ptr =
        (uint8_t *)ovc_abi_alloc(continuation_len);
    assert(batch->continuation.ptr != NULL);
    memcpy(batch->continuation.ptr,
           continuation,
           continuation_len);
    batch->continuation.len = continuation_len;
    batch->redirects.ptr =
        (OvStoragePlugin_WriteRedirect *)ovc_abi_alloc(
            sizeof(*batch->redirects.ptr));
    assert(batch->redirects.ptr != NULL);
    batch->redirects.len = 1;
    redirect = &batch->redirects.ptr[0];
    memset(redirect, 0, sizeof(*redirect));
    redirect->request.method = test_owned_str("PUT");
    redirect->request.url =
        test_owned_str("https://upload.example/object");
    redirect->request.headers.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
            sizeof(*redirect->request.headers.ptr));
    assert(redirect->request.headers.ptr != NULL);
    redirect->request.headers.len = 1;
    redirect->request.headers.ptr[0].key =
        test_owned_str("content-type");
    redirect->request.headers.ptr[0].value =
        test_owned_str("application/octet-stream");
    redirect->body_source.tag =
        OvStoragePlugin_RedirectBodySourceTag_UserBytes;
    redirect->body_source.user_bytes.offset =
        overflow_user_range ? UINT64_MAX : 0;
    redirect->body_source.user_bytes.len = 5;
    redirect->result_capture.headers.ptr =
        (OvStoragePlugin_Str *)ovc_abi_alloc(
            sizeof(*redirect->result_capture.headers.ptr));
    assert(redirect->result_capture.headers.ptr != NULL);
    redirect->result_capture.headers.len = 1;
    redirect->result_capture.headers.ptr[0] =
        test_owned_str("etag");
    redirect->result_capture.body_max_bytes = 64;
    redirect->expires_at_unix_ms = INT64_C(1700000000000);
    redirect->scope.physical_url_prefix =
        test_owned_str("https://upload.example/");
    redirect->scope.operations.write = true;
    redirect->scope.expires_at_unix_ms =
        INT64_C(1700000001000);
    redirect->scope.credential =
        OvStoragePlugin_RedirectCredential_Connection;
    redirect->audit_id = test_owned_str("audit-394");
    redirect->policy_epoch = 9;
    return batch;
}

static void stub_write_redirect(
    void *opaque,
    const OvStoragePlugin_WriteRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    static const uint8_t continuation[] = {1, 3, 5, 7};
    StubLayer *layer;
    OvStoragePlugin_WriteRequest moved;
    OvStoragePlugin_WriteRedirectBatch *batch;

    layer = (StubLayer *)opaque;
    (void)cancel;
    moved = *request;
    assert(moved.body.tag == OvStoragePlugin_BodyTag_Bytes);
    assert(moved.body.bytes.len == 0);
    assert(moved.options.size_hint.present);
    assert(moved.options.size_hint.value == UINT64_C(5));
    batch = stub_redirect_batch(
        continuation,
        sizeof(continuation),
        layer->redirect_overflow);
    ovstorage_plugin_str_free(&moved.address);
    ovstorage_plugin_bytes_free(&moved.body.bytes);
    on_complete(OvStoragePlugin_FFI_STATUS_OK,
                batch,
                NULL,
                user_data);
}

static void stub_continue_write(
    void *opaque,
    const OvStoragePlugin_ContinueWriteRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    static const char expected_body[] = "saved";
    static const uint8_t next_continuation[] = {2, 4, 6, 8};
    OvStoragePlugin_WriteRedirectBatch *next_batch;
    OvStoragePlugin_ContinueWriteRequest moved;
    OvStoragePlugin_WriteStep *step;
    int first_step;

    (void)opaque;
    (void)cancel;
    moved = *request;
    assert(moved.redirects.continuation.len == 4);
    first_step = moved.redirects.continuation.ptr[0] == 1;
    if (first_step) {
        assert(memcmp(moved.redirects.continuation.ptr,
                      "\x01\x03\x05\x07",
                      4) == 0);
    } else {
        assert(memcmp(moved.redirects.continuation.ptr,
                      next_continuation,
                      sizeof(next_continuation)) == 0);
    }
    assert(moved.redirects.redirects.len == 1);
    assert(moved.redirects.redirects.ptr[0].request.method.len == 3);
    assert(memcmp(moved.redirects.redirects.ptr[0].request.method.ptr,
                  "PUT",
                  3) == 0);
    assert(moved.redirects.redirects.ptr[0].body_source.tag ==
           OvStoragePlugin_RedirectBodySourceTag_UserBytes);
    assert(moved.redirects.redirects.ptr[0]
               .body_source.user_bytes.len == 5);
    assert(moved.redirects.redirects.ptr[0].scope.credential ==
           OvStoragePlugin_RedirectCredential_Connection);
    assert(moved.results.results.len == 1);
    assert(moved.results.results.ptr[0].status_code == 201);
    assert(moved.results.results.ptr[0].captured_headers.len == 1);
    assert(
        moved.results.results.ptr[0].captured_headers.ptr[0].key.len ==
        4);
    assert(memcmp(
               moved.results.results.ptr[0]
                   .captured_headers.ptr[0]
                   .key.ptr,
               "etag",
               4) == 0);
    assert(
        moved.results.results.ptr[0].captured_headers.ptr[0].value.len ==
        5);
    assert(memcmp(
               moved.results.results.ptr[0]
                   .captured_headers.ptr[0]
                   .value.ptr,
               "\"abc\"",
               5) == 0);
    assert(moved.results.results.ptr[0].captured_body.len ==
           sizeof(expected_body) - 1);
    assert(memcmp(moved.results.results.ptr[0].captured_body.ptr,
                  expected_body,
                  sizeof(expected_body) - 1) == 0);
    step = (OvStoragePlugin_WriteStep *)ovc_abi_alloc(sizeof(*step));
    assert(step != NULL);
    memset(step, 0, sizeof(*step));
    if (first_step) {
        step->tag = OvStoragePlugin_WriteStepTag_Redirects;
        next_batch = stub_redirect_batch(
            next_continuation, sizeof(next_continuation), 0);
        step->redirects = *next_batch;
        ovc_abi_free(next_batch);
        ovstorage_plugin_str_free(&moved.address);
    } else {
        step->tag = OvStoragePlugin_WriteStepTag_Done;
        stub_fill_info(&step->done.info, moved.address, UINT64_C(5));
        memset(&moved.address, 0, sizeof(moved.address));
    }
    stub_redirect_batch_clear(&moved.redirects);
    stub_redirect_results_clear(&moved.results);
    on_complete(OvStoragePlugin_FFI_STATUS_OK, step, NULL, user_data);
}

static void stub_layer_init(StubLayer *layer, int block_auth)
{
    memset(layer, 0, sizeof(*layer));
    assert(ovc_mutex_init(&layer->mutex) == 0);
    assert(ovc_mutex_init(&layer->barrier_mutex) == 0);
    assert(ovc_cond_init(&layer->barrier_changed) == 0);
    layer->block_auth = block_auth;
    layer->vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    layer->vtable.drop = stub_layer_drop;
    layer->vtable.stat = stub_stat;
    layer->vtable.read = stub_read;
    layer->vtable.get_latest_version = stub_get_latest_version;
    layer->vtable.write_stream = stub_write_stream;
    layer->vtable.write_redirect = stub_write_redirect;
    layer->vtable.continue_write = stub_continue_write;
    layer->vtable.watch_directory = stub_watch_directory;
    layer->vtable.probe = stub_probe;
    layer->vtable.update_connection_attributes =
        stub_update_connection_attributes;
    layer->vtable.authenticate_connection = stub_authenticate;
}

static void stub_layer_destroy(StubLayer *layer)
{
    assert(ovc_cond_destroy(&layer->barrier_changed) == 0);
    assert(ovc_mutex_destroy(&layer->barrier_mutex) == 0);
    assert(ovc_mutex_destroy(&layer->mutex) == 0);
}

static OvStoragePlugin_LayerHandle stub_layer_root(StubLayer *layer)
{
    OvStoragePlugin_LayerHandle root;

    root.state = layer;
    root.vtable = &layer->vtable;
    return root;
}

static OvStorage_LayerHandle *stub_layer_public_handle(StubLayer *layer)
{
    return ovc_dispatch_layer_handle_create(stub_layer_root(layer), NULL, 0);
}

/*
 * Controlled root for the C++ wrapper round trip. It uses the same exact
 * request assertions and sentinel results as the C entry-point tests.
 */
OvStoragePlugin_LayerHandle ovstorage_c_source_new_ops_stub_root(void);

/* What the last watch_directory request carried, so the C++ driver can
 * assert on the request the stub actually received rather than on the
 * options it believes it sent. */
int ovstorage_c_source_new_ops_watch_since_present(void);
size_t ovstorage_c_source_new_ops_watch_since_len(void);

static StubLayer *g_ovc_new_ops_layer;

OvStoragePlugin_LayerHandle ovstorage_c_source_new_ops_stub_root(void)
{
    static StubLayer layer;
    static int initialized;

    if (!initialized) {
        stub_layer_init(&layer, 0);
        layer.watch_mode = 1;
        g_ovc_new_ops_layer = &layer;
        initialized = 1;
    }
    return stub_layer_root(&layer);
}

int ovstorage_c_source_new_ops_watch_since_present(void)
{
    return g_ovc_new_ops_layer == NULL
               ? 0
               : g_ovc_new_ops_layer->watch_since_present;
}

size_t ovstorage_c_source_new_ops_watch_since_len(void)
{
    return g_ovc_new_ops_layer == NULL
               ? 0
               : g_ovc_new_ops_layer->watch_since_len;
}

static void test_copy_error_message(char *out,
                                    size_t capacity,
                                    const OvStorage_Error *error)
{
    const char *message;
    size_t length;

    assert(out != NULL);
    assert(capacity != 0);
    out[0] = '\0';
    message = error == NULL ? NULL : ovstorage_error_message(error);
    if (message == NULL) {
        return;
    }
    length = strlen(message);
    if (length >= capacity) {
        length = capacity - 1u;
    }
    memcpy(out, message, length);
    out[length] = '\0';
}

typedef struct TestAuthResult {
    ovc_completion_latch completed;
    int callback_count;
    int event_count;
    int terminal_count;
    int terminal_had_error;
    OvStorage_Status terminal_error_code;
    int bad_shape;
    int progress_message_set;
    char progress_message[64];
    char terminal_message[256];
} TestAuthResult;

static void test_auth_result_init(TestAuthResult *result)
{
    memset(result, 0, sizeof(*result));
    assert(ovc_completion_latch_init(&result->completed) == 0);
}

static void test_auth_complete(OvStorage_AuthEvent *event,
                               const OvStorage_Error *error,
                               bool done,
                               void *user_data)
{
    TestAuthResult *result;

    result = (TestAuthResult *)user_data;
    ++result->callback_count;
    if (!done) {
        if (event == NULL || error != NULL) {
            result->bad_shape = 1;
        }
        ++result->event_count;
        if (event != NULL && !result->progress_message_set &&
            event->kind == OvStorage_AuthEventKind_Progress) {
            const char *message;

            message = event->as.progress.message;
            if (message != NULL) {
                (void)snprintf(result->progress_message,
                               sizeof(result->progress_message),
                               "%s",
                               message);
                result->progress_message_set = 1;
            }
        }
        ovstorage_auth_event_destroy(event);
        return;
    }
    if (event != NULL) {
        result->bad_shape = 1;
        ovstorage_auth_event_destroy(event);
    }
    ++result->terminal_count;
    result->terminal_had_error = error != NULL;
    result->terminal_error_code =
        error == NULL ? OvStorage_Status_Ok : error->code;
    test_copy_error_message(result->terminal_message,
                            sizeof(result->terminal_message),
                            error);
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_auth_result_wait(TestAuthResult *result)
{
    assert(ovc_completion_latch_wait(&result->completed) == 0);
}

static void test_auth_result_destroy(TestAuthResult *result)
{
    assert(ovc_completion_latch_destroy(&result->completed) == 0);
}

typedef struct TestWatchResult {
    ovc_completion_latch completed;
    int event_count;
    int terminal_count;
    int validate_events;
    OvStorage_Status terminal_status;
} TestWatchResult;

static void test_watch_result_callback(
    const OvStorage_BackendChangeEvent *event,
    const OvStorage_Error *error,
    bool done,
    void *user_data)
{
    TestWatchResult *result;

    result = (TestWatchResult *)user_data;
    if (!done) {
        assert(event != NULL);
        assert(error == NULL);
        if (result->validate_events != 0 && result->event_count == 0) {
            assert(event->kind ==
                   OvStorage_BackendChangeEventKind_Object);
            assert(event->change_kind == OvStorage_ChangeKind_Modified);
            assert(strcmp(event->address,
                          "test://watched/object") == 0);
            assert(strcmp(event->etag, "etag-1") == 0);
            assert(strcmp(event->version, "version-1") == 0);
            assert(event->has_size);
            assert(event->size == 42);
            if (result->validate_events == 3) {
                assert(!event->has_mtime_unix_nanos);
            } else {
                assert(event->has_mtime_unix_nanos);
                assert(event->mtime_unix_nanos ==
                       UINT64_C(1700000000123000000));
            }
            assert(event->at_unix_nanos ==
                   UINT64_C(1700000000000000000));
            assert(!event->has_since_unix_nanos);
            assert(event->cursor_len == strlen("object-cursor"));
            assert(memcmp(event->cursor,
                          "object-cursor",
                          event->cursor_len) == 0);
        } else if (result->validate_events != 0 &&
                   result->event_count == 1) {
            assert(event->kind ==
                   OvStorage_BackendChangeEventKind_Lapsed);
            assert(event->address == NULL);
            if (result->validate_events == 3) {
                assert(!event->has_since_unix_nanos);
            } else {
                assert(event->has_since_unix_nanos);
                assert(event->since_unix_nanos ==
                       UINT64_C(1700000001000000000));
            }
            assert(event->cursor_len == strlen("lapsed-cursor"));
            assert(memcmp(event->cursor,
                          "lapsed-cursor",
                          event->cursor_len) == 0);
        } else {
            assert(!result->validate_events);
        }
        ++result->event_count;
        return;
    }
    assert(event == NULL);
    ++result->terminal_count;
    result->terminal_status =
        error == NULL ? OvStorage_Status_Ok : error->code;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static OvStoragePlugin_Str test_owned_str(const char *value)
{
    OvStoragePlugin_Str result;

    result.len = strlen(value);
    /* Adopted by the file backend, which frees request payloads with
     * ovc_abi_free — mint with the matching ABI allocator. */
    result.ptr = (char *)ovc_abi_alloc(result.len == 0 ? 1 : result.len);
    assert(result.ptr != NULL);
    if (result.len == 0) {
        result.ptr[0] = '\0';
    } else {
        memcpy(result.ptr, value, result.len);
    }
    return result;
}

static void test_watch_cancel_once(void)
{
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *token;
    TestWatchResult result;
    BlockingPullState *pull;
    ovc_mutex sleep_mutex;
    ovc_cond sleep_cond;
    uint64_t deadline;

    stub_layer_init(&layer, 1);
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    token = ovstorage_cancel_token_create();
    assert(token != NULL);
    memset(&result, 0, sizeof(result));
    assert(ovc_completion_latch_init(&result.completed) == 0);
    ovstorage_watch_directory(handle,
                              "test://blocked/",
                              NULL,
                              token,
                              test_watch_result_callback,
                              &result);
    assert(ovc_mutex_init(&sleep_mutex) == 0);
    assert(ovc_cond_init(&sleep_cond) == 0);
    deadline = ovc_monotonic_ns() + UINT64_C(5000000000);
    pull = NULL;
    while (pull == NULL && ovc_monotonic_ns() < deadline) {
        assert(ovc_mutex_lock(&layer.mutex) == 0);
        pull = layer.last_pull;
        assert(ovc_mutex_unlock(&layer.mutex) == 0);
        if (pull == NULL) {
            test_sleep_ns(&sleep_mutex,
                          &sleep_cond,
                          UINT64_C(1000000));
        }
    }
    assert(ovc_cond_destroy(&sleep_cond) == 0);
    assert(ovc_mutex_destroy(&sleep_mutex) == 0);
    assert(pull != NULL);
    blocking_pull_wait_entered(pull);
    ovstorage_cancel_token_cancel(token);
    assert(ovc_completion_latch_wait(&result.completed) == 0);
    assert(result.event_count == 0);
    assert(result.terminal_count == 1);
    assert(result.terminal_status == OvStorage_Status_Cancelled);
    blocking_pull_assert_dropped_once(pull);

    ovstorage_layer_handle_destroy(handle);
    assert(layer.drop_count == 1);
    ovstorage_cancel_token_destroy(token);
    assert(ovc_completion_latch_destroy(&result.completed) == 0);
    blocking_pull_destroy(pull);
    stub_layer_destroy(&layer);
}

static void test_watch_events_once(
    int watch_mode,
    int expected_events,
    OvStorage_Status expected_terminal)
{
    static const uint8_t since[] = "starting-cursor";
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_WatchDirectoryOptions options;
    TestWatchResult result;

    stub_layer_init(&layer, 1);
    layer.watch_mode = watch_mode;
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    memset(&options, 0, sizeof(options));
    options.recursive = true;
    options.include_metadata_changes = true;
    options.since = since;
    if (watch_mode == 3) {
        options.poll_interval_ms = 0;
        options.since_len = 0;
    } else {
        options.poll_interval_ms = 25;
        options.since_len = sizeof(since) - 1;
    }
    memset(&result, 0, sizeof(result));
    result.validate_events =
        watch_mode == 1 || watch_mode == 3 ? watch_mode : 0;
    assert(ovc_completion_latch_init(&result.completed) == 0);
    ovstorage_watch_directory(handle,
                              "test://watched/",
                              &options,
                              NULL,
                              test_watch_result_callback,
                              &result);
    assert(ovc_completion_latch_wait(&result.completed) == 0);
    assert(result.event_count == expected_events);
    assert(result.terminal_count == 1);
    assert(result.terminal_status == expected_terminal);
    if (watch_mode == 3) {
        assert(layer.watch_poll_interval_ms == 1000);
        assert(!layer.watch_since_present);
        assert(layer.watch_since_len == 0);
    } else {
        assert(layer.watch_poll_interval_ms == 25);
        assert(layer.watch_since_present);
        assert(layer.watch_since_len == sizeof(since) - 1);
    }

    ovstorage_layer_handle_destroy(handle);
    assert(layer.drop_count == 1);
    assert(ovc_completion_latch_destroy(&result.completed) == 0);
    stub_layer_destroy(&layer);
}

static void test_auth_cancel_once(void)
{
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *token;
    TestAuthResult result;
    BlockingPullState *pull;

    stub_layer_init(&layer, 1);
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    token = ovstorage_cancel_token_create();
    assert(token != NULL);
    test_auth_result_init(&result);
    ovstorage_authenticate_connection(handle,
                                      "stub",
                                      "blocked",
                                      OvStorage_InteractiveAuthCapability_None,
                                      false,
                                      token,
                                      test_auth_complete,
                                      &result);
    pull = layer.last_pull;
    assert(pull != NULL);
    blocking_pull_wait_entered(pull);
    ovstorage_cancel_token_cancel(token);
    test_auth_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.event_count == 0);
    assert(result.terminal_count == 1);
    assert(result.terminal_had_error);
    assert(result.terminal_error_code == OvStorage_Status_Cancelled);
    assert(!result.bad_shape);
    ovstorage_layer_handle_destroy(handle);
    assert(result.callback_count == 1);
    assert(result.event_count == 0);
    assert(result.terminal_count == 1);
    assert(result.terminal_had_error);
    assert(result.terminal_error_code == OvStorage_Status_Cancelled);
    assert(!result.bad_shape);
    blocking_pull_assert_dropped_once(pull);
    assert(layer.drop_count == 1);
    ovstorage_cancel_token_destroy(token);
    test_auth_result_destroy(&result);
    blocking_pull_destroy(pull);
    stub_layer_destroy(&layer);
}

/* Pins the terminal contract for a cancel racing a Failed step: the pump
 * reports CANCELED with the producer's error attached, and the dispatch
 * adapter must release that plugin error and report Cancelled to the host
 * (internal.h stream-pump contract: cancellation is polled before the
 * failed item is examined, which is what decides the race). */
static void test_auth_cancel_failed_step_once(void)
{
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *token;
    TestAuthResult result;
    BlockingPullState *pull;

    stub_layer_init(&layer, 1);
    layer.fail_auth = 1;
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    token = ovstorage_cancel_token_create();
    assert(token != NULL);
    test_auth_result_init(&result);
    ovstorage_authenticate_connection(handle,
                                      "stub",
                                      "blocked",
                                      OvStorage_InteractiveAuthCapability_None,
                                      false,
                                      token,
                                      test_auth_complete,
                                      &result);
    pull = layer.last_pull;
    assert(pull != NULL);
    blocking_pull_wait_entered(pull);
    ovstorage_cancel_token_cancel(token);
    test_auth_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.event_count == 0);
    assert(result.terminal_count == 1);
    assert(result.terminal_had_error);
    assert(result.terminal_error_code == OvStorage_Status_Cancelled);
    assert(!result.bad_shape);
    ovstorage_layer_handle_destroy(handle);
    assert(result.callback_count == 1);
    assert(result.terminal_count == 1);
    assert(result.terminal_error_code == OvStorage_Status_Cancelled);
    blocking_pull_assert_dropped_once(pull);
    assert(layer.drop_count == 1);
    ovstorage_cancel_token_destroy(token);
    test_auth_result_destroy(&result);
    blocking_pull_destroy(pull);
    stub_layer_destroy(&layer);
}

static OvStorage_LayerHandle *test_build_file_stack(const char *root_address,
                                                    uint32_t runtime_threads)
{
    OvStorage_Registry *registry;
    OvStorage_Stack *stack;
    OvStorage_ConnectionRequest *request;
    OvStorage_ConfigValue *root;
    OvStorage_StackBuildOptions options;
    OvStorage_LayerHandle *handle;
    OvStorage_Error error;

    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    request = ovstorage_connection_request_create("file");
    root = ovstorage_config_value_create_string(root_address);
    memset(&options, 0, sizeof(options));
    options.runtime_threads = runtime_threads;
    memset(&error, 0, sizeof(error));
    handle = NULL;
    assert(registry != NULL);
    assert(stack != NULL);
    assert(request != NULL);
    assert(root != NULL);
    assert(ovstorage_stack_add_layer(
               stack, registry, "files", "file", &error) ==
           OvStorage_Status_Ok);
    ovstorage_registry_destroy(registry);
    assert(ovstorage_stack_set_root(stack, "files", &error) ==
           OvStorage_Status_Ok);
    assert(ovstorage_connection_request_add_config(request, "root", root));
    assert(ovstorage_stack_add_connection(
               stack, "files", &request, &error) == OvStorage_Status_Ok);
    assert(request == NULL);
    assert(ovstorage_stack_build(stack, &options, &handle, &error) ==
           OvStorage_Status_Ok);
    assert(handle != NULL);
    ovstorage_error_clear(&error);
    return handle;
}

static void test_file_stack_stat_read(OvStorage_LayerHandle *handle,
                                      const char *address,
                                      const uint8_t *payload,
                                      size_t payload_len)
{
    OvStorage_StatOptions stat_options;
    OvStorage_ReadOptions read_options;
    TestIoResult stat_result;
    TestIoResult read_result;

    memset(&stat_options, 0, sizeof(stat_options));
    memset(&read_options, 0, sizeof(read_options));
    test_io_result_init(&stat_result);
    test_io_result_init(&read_result);
    ovstorage_stat(handle,
                   address,
                   &stat_options,
                   NULL,
                   test_info_complete,
                   &stat_result);
    ovstorage_read_bytes(handle,
                         address,
                         &read_options,
                         NULL,
                         test_read_complete,
                         &read_result);
    test_io_result_wait(&stat_result);
    test_io_result_wait(&read_result);
    assert(stat_result.status == OvStorage_Status_Ok);
    assert(!stat_result.had_error);
    assert(stat_result.callback_count == 1);
    assert(stat_result.info != NULL);
    assert(stat_result.info->has_size);
    assert(stat_result.info->size == payload_len);
    assert(read_result.status == OvStorage_Status_Ok);
    assert(!read_result.had_error);
    assert(read_result.callback_count == 1);
    assert(read_result.info != NULL);
    assert(read_result.bytes.len == payload_len);
    assert(payload_len == 0 ||
           memcmp(read_result.bytes.data, payload, payload_len) == 0);
    test_io_result_destroy(&stat_result);
    test_io_result_destroy(&read_result);
}

/* An unnamed read/write temporary file for capturing redirected stderr.
 *
 * `tmpfile()` would be the obvious call, but glibc's implementation ignores
 * $TMPDIR and always opens under /tmp, which is not writable everywhere this
 * suite runs.  `mkstemp` honours the resolved temporary root; the immediate
 * `unlink` restores the property the capture leg depends on -- the file is
 * gone once the stream is closed, so it cannot litter the temporary root. */
static FILE *test_open_anonymous_temp_file(void)
{
#if defined(_WIN32)
    /* `tmpfile_s` has the same defect as glibc's `tmpfile()` in stronger
     * form: MSVC documents that it creates the file in the ROOT of the
     * current drive, which is routinely unwritable for a non-elevated
     * process and ignores the temporary root every other case here honours.
     * Compose under `ovc_temp_root_dup()` and open delete-on-close, which
     * is the Win32 spelling of the POSIX branch's `mkstemp` + `unlink`. */
    char path[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    FILE *stream;
    int written;
    int descriptor;

    root = ovc_temp_root_dup();
    if (root == NULL) {
        return NULL;
    }
    written = snprintf(path,
                       sizeof(path),
                       "%s\\ovstorage-capture-%lu-%u",
                       root,
                       (unsigned long)GetCurrentProcessId(),
                       (unsigned)GetTickCount());
    free(root);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    if (_sopen_s(&descriptor,
                 path,
                 _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY | _O_TEMPORARY,
                 _SH_DENYNO,
                 _S_IREAD | _S_IWRITE)
        != 0) {
        return NULL;
    }
    stream = _fdopen(descriptor, "w+b");
    if (stream == NULL) {
        _close(descriptor);
    }
    return stream;
#else
    char path[OVC_TEMP_DIR_PATH_MAX];
    char *root;
    FILE *stream;
    int written;
    int descriptor;

    root = ovc_temp_root_dup();
    if (root == NULL) {
        return NULL;
    }
    written = snprintf(path,
                       sizeof(path),
                       "%s/ovstorage-c-source-capture-XXXXXX",
                       root);
    free(root);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return NULL;
    }
    descriptor = mkstemp(path);
    if (descriptor < 0) {
        return NULL;
    }
    if (unlink(path) != 0) {
        (void)close(descriptor);
        return NULL;
    }
    stream = fdopen(descriptor, "w+b");
    if (stream == NULL) {
        (void)close(descriptor);
        return NULL;
    }
    return stream;
#endif
}

/* `directory` is a native path and is encoded; `suffix` is appended as-is,
 * so callers pass literal URL path text.  Returns the snprintf length, or
 * -1 when the composed URL path does not fit. */
static int test_file_url(char *out,
                         size_t out_size,
                         const char *directory,
                         const char *suffix)
{
    /* Worst case, every byte of the URL path escapes to three, plus the
     * leading separator Win32 drive paths take. */
    char encoded_directory[3 * (OVC_TEMP_DIR_PATH_MAX + 2) + 8];

    if (test_file_url_path(directory,
                           encoded_directory,
                           sizeof(encoded_directory)) != 0) {
        return -1;
    }
    return snprintf(out, out_size, "file://%s%s", encoded_directory, suffix);
}

int ovstorage_c_source_runtime_contracts(void)
{
    static const uint8_t payload[] = "second Stack remains operational";
    char directory_a[OVC_TEMP_DIR_PATH_MAX];
    char directory_b[OVC_TEMP_DIR_PATH_MAX];
    char root_a[1024];
    char root_b[1024];
    char address_b[1024];
    char path_b[1024];
    char warning[2048];
    OvStorage_LayerHandle *stack_a;
    OvStorage_LayerHandle *stack_b;
    FILE *capture;
    FILE *object;
    int saved_stderr;
    int written;
    size_t warning_len;

    assert(ovc_temp_dir_create("ovstorage-c-source-runtime-a",
                               directory_a,
                               sizeof(directory_a)) == 0);
    assert(ovc_temp_dir_create("ovstorage-c-source-runtime-b",
                               directory_b,
                               sizeof(directory_b)) == 0);
    written = test_file_url(root_a, sizeof(root_a), directory_a, "/");
    assert(written > 0 && (size_t)written < sizeof(root_a));
    written = test_file_url(root_b, sizeof(root_b), directory_b, "/");
    assert(written > 0 && (size_t)written < sizeof(root_b));
    written = test_file_url(
        address_b, sizeof(address_b), directory_b, "/alive.bin");
    assert(written > 0 && (size_t)written < sizeof(address_b));
    written = snprintf(path_b,
                       sizeof(path_b),
                       "%s/alive.bin",
                       directory_b);
    assert(written > 0 && (size_t)written < sizeof(path_b));

    stack_a = test_build_file_stack(root_a, 2);
    assert(ovc_runtime_worker_count() == 2);

    capture = test_open_anonymous_temp_file();
    assert(capture != NULL);
    assert(fflush(stderr) == 0);
    saved_stderr = dup(STDERR_FILENO);
    assert(saved_stderr >= 0);
    assert(dup2(fileno(capture), STDERR_FILENO) >= 0);
    stack_b = test_build_file_stack(root_b, 4);
    assert(fflush(stderr) == 0);
    assert(dup2(saved_stderr, STDERR_FILENO) >= 0);
    assert(close(saved_stderr) == 0);
    assert(fseek(capture, 0, SEEK_SET) == 0);
    warning_len = fread(warning, 1, sizeof(warning) - 1, capture);
    assert(!ferror(capture));
    warning[warning_len] = '\0';
    assert(fclose(capture) == 0);
    assert(strstr(warning, "ignored runtime_threads=4") != NULL);
    assert(strstr(warning, "already built with 2 worker thread(s)") != NULL);
    assert(ovc_runtime_worker_count() == 2);

    ovstorage_layer_handle_destroy(stack_a);
    assert(ovc_runtime_worker_count() == 2);
#if defined(_WIN32)
    object = NULL;
    assert(fopen_s(&object, path_b, "wb") == 0);
#else
    object = fopen(path_b, "wb");
#endif
    assert(object != NULL);
    assert(fwrite(payload, 1, sizeof(payload) - 1, object) ==
           sizeof(payload) - 1);
    assert(fclose(object) == 0);
    test_file_stack_stat_read(stack_b,
                              address_b,
                              payload,
                              sizeof(payload) - 1);
    ovstorage_layer_handle_destroy(stack_b);
    assert(ovc_runtime_worker_count() == 2);

    assert(unlink(path_b) == 0);
    assert(rmdir(directory_a) == 0);
    assert(rmdir(directory_b) == 0);
    return EXIT_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/*
 * Ownership reporting for `ovstorage_add_connection` and
 * `ovstorage_update_connection_credentials`.
 *
 * Both take a handle the caller owns, and both have failures on either side
 * of the transfer: an argument the prologue rejects before it touches the
 * handle, and an error the Layer raises after the handle has moved into it.
 * Those two arrive at the caller as the SAME failed status, so status cannot
 * be the oracle for cleanup — re-adopting a handle the callee took double
 * frees it, abandoning one it declined leaks a credential.
 *
 * The slot is the oracle instead: the callee NULLs it exactly when it takes
 * the handle. This contract drives both failures with ONE builder and ONE
 * bundle, and cleans up with the same unconditional `_destroy` call after
 * each — the code a caller following the header actually writes.
 *
 * Read the assertions together with what they cost when they are wrong,
 * because the sanitized leg of this suite catches the same two mutations
 * without them. Clearing the slot on the declined path strands a request
 * nobody frees, which LeakSanitizer reports; leaving it filled on the taken
 * path makes the `_destroy` below a second free, which AddressSanitizer
 * reports. The assertions localize the failure, they do not create it.
 */

typedef struct TestConnResult {
    ovc_completion_latch completed;
    int callback_count;
    OvStorage_Status status;
    OvStorage_Connection *connection;
    char message[256];
} TestConnResult;

static void test_conn_result_init(TestConnResult *result)
{
    memset(result, 0, sizeof(*result));
    assert(ovc_completion_latch_init(&result->completed) == 0);
}

static void test_conn_complete(OvStorage_Status status,
                               OvStorage_Connection *connection,
                               const OvStorage_Error *error,
                               void *user_data)
{
    TestConnResult *result;

    result = (TestConnResult *)user_data;
    result->status = status;
    result->connection = connection;
    /* The message is only valid for the duration of this callback, so it is
     * copied rather than pointed at. */
    test_copy_error_message(result->message, sizeof(result->message), error);
    ++result->callback_count;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_conn_result_wait(TestConnResult *result)
{
    assert(ovc_completion_latch_wait(&result->completed) == 0);
}

static void test_conn_result_destroy(TestConnResult *result)
{
    ovstorage_connection_destroy(result->connection);
    assert(ovc_completion_latch_destroy(&result->completed) == 0);
}

typedef struct TestStatusResult {
    ovc_completion_latch completed;
    int callback_count;
    OvStorage_Status status;
    char message[256];
} TestStatusResult;

static void test_status_result_init(TestStatusResult *result)
{
    memset(result, 0, sizeof(*result));
    assert(ovc_completion_latch_init(&result->completed) == 0);
}

static void test_status_complete(OvStorage_Status status,
                                 const OvStorage_Error *error,
                                 void *user_data)
{
    TestStatusResult *result;

    result = (TestStatusResult *)user_data;
    result->status = status;
    test_copy_error_message(result->message, sizeof(result->message), error);
    ++result->callback_count;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_status_result_wait(TestStatusResult *result)
{
    assert(ovc_completion_latch_wait(&result->completed) == 0);
}

static void test_status_result_destroy(TestStatusResult *result)
{
    assert(ovc_completion_latch_destroy(&result->completed) == 0);
}

static void test_public_connection_operations(
    OvStorage_LayerHandle *handle)
{
    static const uint8_t secret_bytes[] = {1, 2, 3, 4};
    OvStorage_ConnectionRequest *request;
    OvStorage_ConfigValue *config;
    OvStorage_SecretValue *secret;
    OvStorage_UpdateMetadataOptions *metadata;
    OvStorage_AttributePatch patch;
    OvStorage_Error error;
    TestConnResult result;

    request = ovstorage_connection_request_create("stub-kind");
    assert(request != NULL);
    ovstorage_connection_request_set_display_name(request,
                                                  "Probe Display");
    ovstorage_connection_request_set_persist(request, true);
    config = ovstorage_config_value_create_string(
        "test://config-value");
    assert(config != NULL);
    assert(ovstorage_connection_request_add_config(
        request, "endpoint", config));
    secret = ovstorage_secret_value_create_bytes(
        secret_bytes, sizeof(secret_bytes));
    assert(secret != NULL);
    assert(ovstorage_connection_request_add_credential(
        request, "token", secret));
    test_conn_result_init(&result);
    ovstorage_probe(handle,
                    "test://probe-target",
                    request,
                    NULL,
                    test_conn_complete,
                    &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_Ok);
    assert(result.connection != NULL);
    assert(strcmp(result.connection->id, "probe-sentinel") == 0);
    assert(strcmp(result.connection->display_name, "Probe Result") == 0);
    test_conn_result_destroy(&result);

    /* Probe borrows the builder; a successful mutation afterwards proves it
     * remains live rather than merely checking the local pointer value. */
    config = ovstorage_config_value_create_string("still-live");
    assert(config != NULL);
    assert(ovstorage_connection_request_add_config(
        request, "after-probe", config));
    ovstorage_connection_request_destroy(request);

    metadata = ovstorage_update_metadata_options_create();
    assert(metadata != NULL);
    memset(&error, 0, sizeof(error));
    assert(ovstorage_update_metadata_options_set(
               metadata,
               "owner",
               "integration-test",
               &error) == OvStorage_Status_Ok);
    assert(ovstorage_update_metadata_options_remove(
               metadata,
               "obsolete",
               &error) == OvStorage_Status_Ok);
    ovstorage_error_clear(&error);
    memset(&patch, 0, sizeof(patch));
    patch.has_display_name = true;
    patch.display_name = "Updated Display";
    patch.has_access_mode = true;
    patch.access_mode = "read-write";
    patch.has_visible = true;
    patch.visible = false;
    patch.user_metadata = metadata;
    test_conn_result_init(&result);
    ovstorage_update_connection_attributes(
        handle,
        "test://attributes-target",
        "connection-394",
        &patch,
        NULL,
        test_conn_complete,
        &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_Ok);
    assert(result.connection != NULL);
    assert(strcmp(result.connection->id, "attributes-sentinel") == 0);
    assert(strcmp(result.connection->display_name, "Attributes Result") == 0);
    test_conn_result_destroy(&result);
    ovstorage_update_metadata_options_destroy(metadata);
}

/* A request whose contents span many small allocations. One large block can
 * escape LeakSanitizer behind a stale pointer in a register or on the stack;
 * a few dozen small ones cannot, so a stranded request is unmistakable on
 * the sanitized leg. */
static OvStorage_ConnectionRequest *test_ownership_request(void)
{
    static const uint8_t token[] = {0x73, 0x33, 0x63, 0x72, 0x33, 0x74};
    OvStorage_ConnectionRequest *request;
    OvStorage_ConfigValue *value;
    OvStorage_SecretValue *secret;
    char key[24];
    unsigned index;

    request = ovstorage_connection_request_create("file");
    assert(request != NULL);
    for (index = 0; index < 16; ++index) {
        assert(snprintf(key, sizeof(key), "config-%u", index) > 0);
        value = ovstorage_config_value_create_string("file:///tmp/ownership");
        assert(value != NULL);
        assert(ovstorage_connection_request_add_config(request, key, value));
        assert(snprintf(key, sizeof(key), "secret-%u", index) > 0);
        secret = ovstorage_secret_value_create_bytes(token, sizeof(token));
        assert(secret != NULL);
        assert(
            ovstorage_connection_request_add_credential(request, key, secret));
    }
    return request;
}

static OvStorage_SecretBundle *test_ownership_bundle(void)
{
    static const uint8_t token[] = {0x73, 0x33, 0x63, 0x72, 0x33, 0x74};
    OvStorage_SecretBundle *bundle;
    OvStorage_SecretValue *secret;
    char key[24];
    unsigned index;

    bundle = ovstorage_secret_bundle_create();
    assert(bundle != NULL);
    for (index = 0; index < 16; ++index) {
        assert(snprintf(key, sizeof(key), "secret-%u", index) > 0);
        secret = ovstorage_secret_value_create_bytes(token, sizeof(token));
        assert(secret != NULL);
        assert(ovstorage_secret_bundle_add(bundle, key, secret));
    }
    return bundle;
}

static void test_connection_ownership_once(OvStorage_LayerHandle *handle)
{
    OvStorage_ConnectionRequest *request;
    OvStorage_ConfigValue *prefix;
    OvStorage_SecretBundle *bundle;
    OvStorage_AttributePatch patch;
    TestConnResult result;

    request = test_ownership_request();

    /* A probe borrows the builder. The file Layer does not implement this
     * slot, but the public dispatch must still reach it and leave the request
     * available to the caller after the asynchronous error completion. */
    test_conn_result_init(&result);
    ovstorage_probe(handle,
                    "files",
                    request,
                    NULL,
                    test_conn_complete,
                    &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_Unsupported);
    assert(request != NULL);
    test_conn_result_destroy(&result);

    memset(&patch, 0, sizeof(patch));
    patch.has_display_name = true;
    patch.display_name = "Renamed";
    patch.has_visible = true;
    patch.visible = false;
    test_conn_result_init(&result);
    ovstorage_update_connection_attributes(handle,
                                           "files",
                                           "missing",
                                           &patch,
                                           NULL,
                                           test_conn_complete,
                                           &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_Unsupported);
    test_conn_result_destroy(&result);

    /* Declined. A null `target` is rejected by the prologue, which never
     * hands the request to the Layer, so the slot still holds it. */
    test_conn_result_init(&result);
    ovstorage_add_connection(handle,
                             NULL,
                             &request,
                             NULL,
                             test_conn_complete,
                             &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_InvalidArgument);
    assert(request != NULL);
    test_conn_result_destroy(&result);

    /* Still the caller's, so it is still usable: the same builder is
     * amended and goes into the corrected call below. */
    prefix = ovstorage_config_value_create_string("sub/");
    assert(prefix != NULL);
    assert(ovstorage_connection_request_add_config(request, "prefix", prefix));

    /* Taken. The file Layer rejects the `prefix` config it does not
     * implement, which is a failure raised AFTER the request moved into
     * the Layer — and it reports the SAME InvalidArgument the prologue
     * reported above, so status cannot separate the two. The slot is
     * cleared, so the identical cleanup line below is a no-op. */
    test_conn_result_init(&result);
    ovstorage_add_connection(handle,
                             "files",
                             &request,
                             NULL,
                             test_conn_complete,
                             &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_InvalidArgument);
    assert(request == NULL);
    test_conn_result_destroy(&result);

    ovstorage_connection_request_destroy(request);
    request = NULL;

    /* The same two-sided contract for the credential bundle, where an
     * abandoned handle is secret material left unwiped on the heap. */
    bundle = test_ownership_bundle();

    test_conn_result_init(&result);
    ovstorage_update_connection_credentials(handle,
                                            NULL,
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status == OvStorage_Status_InvalidArgument);
    assert(bundle != NULL);
    test_conn_result_destroy(&result);

    test_conn_result_init(&result);
    ovstorage_update_connection_credentials(handle,
                                            "files",
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &result);
    test_conn_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.status != OvStorage_Status_Ok);
    assert(bundle == NULL);
    test_conn_result_destroy(&result);

    ovstorage_secret_bundle_destroy(bundle);
    bundle = NULL;
}

/* The prologue names which argument it rejected.
 *
 * Status cannot separate these cases -- every one of them is
 * InvalidArgument, which is what the ownership contract above turns on. The
 * message is therefore the only thing that tells a caller whether they passed
 * a bad target or handed over a request they had already spent, and those have
 * different fixes. A caller who double-`std::move`s one `ConnectionRequest`
 * presents a null handle on the second call; with one shared message that is
 * indistinguishable from a typo in the target.
 *
 * The assertions are pairwise-distinct rather than exact-match so that
 * rewording a message does not break the test, while collapsing any two of
 * them back into one shared string does. */
static void test_connection_diagnostics_once(OvStorage_LayerHandle *handle)
{
    OvStorage_ConnectionRequest *request;
    OvStorage_ConnectionRequest *consumed_alias;
    OvStorage_SecretBundle *bundle;
    OvStorage_Stack *scratch;
    OvStorage_Error scratch_error;
    TestConnResult bad_target;
    TestConnResult null_handle;
    TestConnResult null_request;
    TestConnResult consumed;
    TestConnResult null_bundle;
    TestConnResult bad_id;
    TestConnResult bad_cred_target;
    TestConnResult null_cred_handle;
    TestConnResult consumed_bundle;

    /* A malformed target, with a perfectly good request. Declined before the
     * Layer sees it, so the slot still holds the request. */
    request = test_ownership_request();
    test_conn_result_init(&bad_target);
    ovstorage_add_connection(handle,
                             NULL,
                             &request,
                             NULL,
                             test_conn_complete,
                             &bad_target);
    test_conn_result_wait(&bad_target);
    assert(bad_target.status == OvStorage_Status_InvalidArgument);
    assert(request != NULL);
    ovstorage_connection_request_destroy(request);
    request = NULL;

    /* A good target, and a request slot holding nothing. This is what a
     * moved-from `ConnectionRequest` presents as: the wrapper's `release()`
     * yields a null pointer, so the prologue is the only place that can say
     * which argument was at fault. */
    test_conn_result_init(&null_request);
    ovstorage_add_connection(handle,
                             "files",
                             &request,
                             NULL,
                             test_conn_complete,
                             &null_request);
    test_conn_result_wait(&null_request);
    assert(null_request.status == OvStorage_Status_InvalidArgument);

    /* A null handle, with everything else well formed. */
    test_conn_result_init(&null_handle);
    ovstorage_add_connection(NULL,
                             "files",
                             &request,
                             NULL,
                             test_conn_complete,
                             &null_handle);
    test_conn_result_wait(&null_handle);
    assert(null_handle.status == OvStorage_Status_InvalidArgument);

    /* An already-consumed request, presented through an alias that is still
     * live.
     *
     * Reaching this branch safely takes care. A request consumed by
     * `ovstorage_add_connection` or by a built Stack is destroyed by that
     * call, so an alias to it dangles and reading `consumed` would itself be
     * a use-after-free. `ovstorage_stack_add_connection` is the one consumer
     * that marks the request and keeps it alive -- until the Stack is built
     * or destroyed -- so a scratch Stack that is never built gives a live,
     * consumed object to present. */
    scratch = ovstorage_stack_create();
    assert(scratch != NULL);
    memset(&scratch_error, 0, sizeof(scratch_error));
    {
        OvStorage_Registry *scratch_registry = ovstorage_registry_create();

        assert(scratch_registry != NULL);
        assert(ovstorage_stack_add_layer(
                   scratch, scratch_registry, "files", "file",
                   &scratch_error) == OvStorage_Status_Ok);
        ovstorage_registry_destroy(scratch_registry);
    }
    consumed_alias = test_ownership_request();
    request = consumed_alias;
    assert(ovstorage_stack_add_connection(
               scratch, "files", &request, &scratch_error) ==
           OvStorage_Status_Ok);
    assert(request == NULL);
    ovstorage_error_clear(&scratch_error);

    request = consumed_alias;
    test_conn_result_init(&consumed);
    ovstorage_add_connection(handle,
                             "files",
                             &request,
                             NULL,
                             test_conn_complete,
                             &consumed);
    test_conn_result_wait(&consumed);
    assert(consumed.status == OvStorage_Status_InvalidArgument);
    /* Declined, so the slot still holds the alias -- and the scratch Stack,
     * not this test, owns the request. */
    assert(request == consumed_alias);
    ovstorage_stack_destroy(scratch);

    /* The same set for the credential bundle, which reports ownership through
     * its slot in the same way. Every argument rejection is driven, so a
     * partial collapse cannot hide behind an untested message. */
    bundle = NULL;
    test_conn_result_init(&null_bundle);
    ovstorage_update_connection_credentials(handle,
                                            "files",
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &null_bundle);
    test_conn_result_wait(&null_bundle);
    assert(null_bundle.status == OvStorage_Status_InvalidArgument);

    bundle = test_ownership_bundle();
    test_conn_result_init(&bad_id);
    ovstorage_update_connection_credentials(handle,
                                            "files",
                                            NULL,
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &bad_id);
    test_conn_result_wait(&bad_id);
    assert(bad_id.status == OvStorage_Status_InvalidArgument);
    assert(bundle != NULL);

    test_conn_result_init(&bad_cred_target);
    ovstorage_update_connection_credentials(handle,
                                            NULL,
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &bad_cred_target);
    test_conn_result_wait(&bad_cred_target);
    assert(bad_cred_target.status == OvStorage_Status_InvalidArgument);
    assert(bundle != NULL);

    test_conn_result_init(&null_cred_handle);
    ovstorage_update_connection_credentials(NULL,
                                            "files",
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &null_cred_handle);
    test_conn_result_wait(&null_cred_handle);
    assert(null_cred_handle.status == OvStorage_Status_InvalidArgument);
    assert(bundle != NULL);

    assert(ovc_secret_bundle_mark_consumed(bundle));
    test_conn_result_init(&consumed_bundle);
    ovstorage_update_connection_credentials(handle,
                                            "files",
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &consumed_bundle);
    test_conn_result_wait(&consumed_bundle);
    assert(consumed_bundle.status == OvStorage_Status_InvalidArgument);
    assert(bundle != NULL);
    ovstorage_secret_bundle_destroy(bundle);

    /* Every rejection names its own argument.
     *
     * Three properties, and each catches something the others do not.
     *
     * Pairwise distinctness catches a collapse -- two cases answering with
     * one shared string, which is the defect this whole change exists to
     * remove. Every pair within each function is compared, so a collapse
     * cannot hide behind an untested message.
     *
     * Non-emptiness catches a message that was never set. Without it two
     * absent messages compare equal and the distinctness assertion reports
     * the collapse, which is a confusing way to learn the message is
     * missing.
     *
     * The fallback check catches the case neither of the others can. When a
     * message is NULL the dispatcher substitutes a generic
     * "ovstorage operation failed", which is non-empty AND still distinct
     * from its neighbours -- so a single lost message would satisfy both
     * properties above while destroying the diagnostic. */
    {
        const TestConnResult *const results[] = {
            &bad_target, &null_handle, &null_request, &consumed,
            &null_bundle, &bad_id, &bad_cred_target, &null_cred_handle,
            &consumed_bundle};
        /* What each message must SAY, not merely that it differs from its
         * neighbours. Distinctness alone is preserved under a permutation:
         * swapping two messages keeps all nine unique while diagnosing a bad
         * target as a moved-from request, which is the exact confusion this
         * change removes. These substrings pin the case-to-message mapping
         * while leaving the rest of each message free to be reworded. */
        static const char *const expected[] = {
            "target is null",
            "handle is null",
            "connection request is null",
            "already consumed",
            "credential bundle is null",
            "connection id is null",
            "target is null",
            "handle is null",
            "already consumed"};
        size_t i;
        size_t j;

        for (i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
            /* Exactly one completion per rejection, on every path. */
            assert(results[i]->callback_count == 1);
            assert(results[i]->message[0] != '\0');
            assert(strcmp(results[i]->message, "ovstorage operation failed") !=
                   0);
            assert(strstr(results[i]->message, expected[i]) != NULL);
        }
        /* Within `add_connection`, indices 0..3; within
         * `update_connection_credentials`, indices 4..8. Cross-function pairs
         * are deliberately not compared -- the two functions prefix their
         * messages differently, and requiring distinctness across them would
         * pin naming rather than behaviour. */
        for (i = 0; i < 4; ++i) {
            for (j = i + 1; j < 4; ++j) {
                assert(strcmp(results[i]->message, results[j]->message) != 0);
            }
        }
        for (i = 4; i < 9; ++i) {
            for (j = i + 1; j < 9; ++j) {
                assert(strcmp(results[i]->message, results[j]->message) != 0);
            }
        }
    }

    test_conn_result_destroy(&bad_target);
    test_conn_result_destroy(&null_handle);
    test_conn_result_destroy(&null_request);
    test_conn_result_destroy(&consumed);
    test_conn_result_destroy(&null_bundle);
    test_conn_result_destroy(&bad_id);
    test_conn_result_destroy(&bad_cred_target);
    test_conn_result_destroy(&null_cred_handle);
    test_conn_result_destroy(&consumed_bundle);
}

static void test_remove_and_authenticate_diagnostics_once(
    OvStorage_LayerHandle *handle)
{
    TestStatusResult remove_null_handle;
    TestStatusResult remove_bad_target;
    TestStatusResult remove_bad_id;
    TestAuthResult auth_null_handle;
    TestAuthResult auth_bad_target;
    TestAuthResult auth_bad_id;
    TestAuthResult auth_bad_capability;
    TestAuthResult auth_negative_capability;

    test_status_result_init(&remove_null_handle);
    ovstorage_remove_connection(NULL,
                                "files",
                                "missing",
                                NULL,
                                test_status_complete,
                                &remove_null_handle);
    test_status_result_wait(&remove_null_handle);

    test_status_result_init(&remove_bad_target);
    ovstorage_remove_connection(handle,
                                NULL,
                                "missing",
                                NULL,
                                test_status_complete,
                                &remove_bad_target);
    test_status_result_wait(&remove_bad_target);

    test_status_result_init(&remove_bad_id);
    ovstorage_remove_connection(handle,
                                "files",
                                NULL,
                                NULL,
                                test_status_complete,
                                &remove_bad_id);
    test_status_result_wait(&remove_bad_id);

    test_auth_result_init(&auth_null_handle);
    ovstorage_authenticate_connection(
        NULL,
        "files",
        "missing",
        OvStorage_InteractiveAuthCapability_None,
        false,
        NULL,
        test_auth_complete,
        &auth_null_handle);
    test_auth_result_wait(&auth_null_handle);

    test_auth_result_init(&auth_bad_target);
    ovstorage_authenticate_connection(
        handle,
        NULL,
        "missing",
        OvStorage_InteractiveAuthCapability_None,
        false,
        NULL,
        test_auth_complete,
        &auth_bad_target);
    test_auth_result_wait(&auth_bad_target);

    test_auth_result_init(&auth_bad_id);
    ovstorage_authenticate_connection(
        handle,
        "files",
        NULL,
        OvStorage_InteractiveAuthCapability_None,
        false,
        NULL,
        test_auth_complete,
        &auth_bad_id);
    test_auth_result_wait(&auth_bad_id);

    test_auth_result_init(&auth_bad_capability);
    ovstorage_authenticate_connection(
        handle,
        "files",
        "missing",
        (OvStorage_InteractiveAuthCapability)(
            OvStorage_InteractiveAuthCapability_Browser + 1),
        false,
        NULL,
        test_auth_complete,
        &auth_bad_capability);
    test_auth_result_wait(&auth_bad_capability);

    test_auth_result_init(&auth_negative_capability);
    ovstorage_authenticate_connection(
        handle,
        "files",
        "missing",
        (OvStorage_InteractiveAuthCapability)-1,
        false,
        NULL,
        test_auth_complete,
        &auth_negative_capability);
    test_auth_result_wait(&auth_negative_capability);

    {
        const TestStatusResult *const results[] = {
            &remove_null_handle, &remove_bad_target, &remove_bad_id};
        static const char *const expected[] = {
            "handle is null", "target is null", "connection id is null"};
        size_t i;
        size_t j;

        for (i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
            assert(results[i]->callback_count == 1);
            assert(results[i]->status == OvStorage_Status_InvalidArgument);
            assert(results[i]->message[0] != '\0');
            assert(strcmp(results[i]->message, "ovstorage operation failed") !=
                   0);
            assert(strstr(results[i]->message, expected[i]) != NULL);
        }
        for (i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
            for (j = i + 1; j < sizeof(results) / sizeof(results[0]); ++j) {
                assert(strcmp(results[i]->message, results[j]->message) != 0);
            }
        }
    }

    {
        const TestAuthResult *const results[] = {
            &auth_null_handle,
            &auth_bad_target,
            &auth_bad_id,
            &auth_bad_capability,
            &auth_negative_capability};
        static const char *const expected[] = {
            "handle is null",
            "target is null",
            "connection id is null",
            "capability is not recognized",
            "capability is not recognized"};
        size_t i;
        size_t j;

        for (i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
            assert(results[i]->callback_count == 1);
            assert(results[i]->terminal_count == 1);
            assert(results[i]->terminal_had_error);
            assert(results[i]->terminal_error_code ==
                   OvStorage_Status_InvalidArgument);
            assert(!results[i]->bad_shape);
            assert(results[i]->terminal_message[0] != '\0');
            assert(strcmp(results[i]->terminal_message,
                          "ovstorage operation failed") != 0);
            assert(strstr(results[i]->terminal_message, expected[i]) != NULL);
        }
        for (i = 0; i < 4; ++i) {
            for (j = i + 1; j < 4; ++j) {
                assert(strcmp(results[i]->terminal_message,
                              results[j]->terminal_message) != 0);
            }
        }
        assert(strcmp(auth_bad_capability.terminal_message,
                      auth_negative_capability.terminal_message) == 0);
    }

    test_status_result_destroy(&remove_null_handle);
    test_status_result_destroy(&remove_bad_target);
    test_status_result_destroy(&remove_bad_id);
    test_auth_result_destroy(&auth_null_handle);
    test_auth_result_destroy(&auth_bad_target);
    test_auth_result_destroy(&auth_bad_id);
    test_auth_result_destroy(&auth_bad_capability);
    test_auth_result_destroy(&auth_negative_capability);
}

#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
static void test_connection_allocation_failures_once(
    OvStorage_LayerHandle *handle)
{
    enum {
        ADD_SECRET_BYTES = 4093,
        UPDATE_SECRET_BYTES = 4091,
        REMOVE_ID_BYTES = 4087,
        AUTH_ID_BYTES = 4079
    };
    uint8_t add_secret_bytes[ADD_SECRET_BYTES];
    uint8_t update_secret_bytes[UPDATE_SECRET_BYTES];
    char remove_id[REMOVE_ID_BYTES + 1];
    char auth_id[AUTH_ID_BYTES + 1];
    OvStorage_ConnectionRequest *request;
    OvStorage_ConnectionRequest *original_request;
    OvStorage_SecretBundle *bundle;
    OvStorage_SecretBundle *original_bundle;
    OvStorage_SecretValue *secret;
    TestConnResult add_result;
    TestConnResult update_result;
    TestStatusResult remove_result;
    TestAuthResult auth_result;

    memset(add_secret_bytes, 0x5a, sizeof(add_secret_bytes));
    request = ovstorage_connection_request_create("file");
    assert(request != NULL);
    secret =
        ovstorage_secret_value_create_bytes(add_secret_bytes,
                                            sizeof(add_secret_bytes));
    assert(secret != NULL);
    assert(ovstorage_connection_request_add_credential(
        request, "allocation-trap", secret));
    original_request = request;

    test_conn_result_init(&add_result);
    ovc_test_abi_alloc_arm(sizeof(add_secret_bytes),
                           "add_connection secret copy");
    ovstorage_add_connection(handle,
                             "files",
                             &request,
                             NULL,
                             test_conn_complete,
                             &add_result);
    assert(ovc_test_abi_alloc_expect_fired(
        "add_connection secret copy"));
    test_conn_result_wait(&add_result);
    assert(add_result.callback_count == 1);
    assert(add_result.status == OvStorage_Status_Internal);
    assert(strstr(add_result.message, "out of memory") != NULL);
    assert(request == original_request);
    test_conn_result_destroy(&add_result);
    ovstorage_connection_request_destroy(request);

    memset(update_secret_bytes, 0x6b, sizeof(update_secret_bytes));
    bundle = ovstorage_secret_bundle_create();
    assert(bundle != NULL);
    secret =
        ovstorage_secret_value_create_bytes(update_secret_bytes,
                                            sizeof(update_secret_bytes));
    assert(secret != NULL);
    assert(ovstorage_secret_bundle_add(bundle, "allocation-trap", secret));
    original_bundle = bundle;

    test_conn_result_init(&update_result);
    ovc_test_abi_alloc_arm(sizeof(update_secret_bytes),
                           "update credentials secret copy");
    ovstorage_update_connection_credentials(handle,
                                            "files",
                                            "missing",
                                            &bundle,
                                            NULL,
                                            test_conn_complete,
                                            &update_result);
    assert(ovc_test_abi_alloc_expect_fired(
        "update credentials secret copy"));
    test_conn_result_wait(&update_result);
    assert(update_result.callback_count == 1);
    assert(update_result.status == OvStorage_Status_Internal);
    assert(strstr(update_result.message, "out of memory") != NULL);
    assert(bundle == original_bundle);
    test_conn_result_destroy(&update_result);
    ovstorage_secret_bundle_destroy(bundle);

    memset(remove_id, 'r', REMOVE_ID_BYTES);
    remove_id[REMOVE_ID_BYTES] = '\0';
    test_status_result_init(&remove_result);
    ovc_test_abi_alloc_arm(REMOVE_ID_BYTES,
                           "remove_connection id copy");
    ovstorage_remove_connection(handle,
                                "files",
                                remove_id,
                                NULL,
                                test_status_complete,
                                &remove_result);
    assert(ovc_test_abi_alloc_expect_fired(
        "remove_connection id copy"));
    test_status_result_wait(&remove_result);
    assert(remove_result.callback_count == 1);
    assert(remove_result.status == OvStorage_Status_Internal);
    assert(strstr(remove_result.message, "out of memory") != NULL);
    test_status_result_destroy(&remove_result);

    memset(auth_id, 'a', AUTH_ID_BYTES);
    auth_id[AUTH_ID_BYTES] = '\0';
    test_auth_result_init(&auth_result);
    ovc_test_abi_alloc_arm(AUTH_ID_BYTES,
                           "authenticate_connection id copy");
    ovstorage_authenticate_connection(
        handle,
        "files",
        auth_id,
        OvStorage_InteractiveAuthCapability_None,
        false,
        NULL,
        test_auth_complete,
        &auth_result);
    assert(ovc_test_abi_alloc_expect_fired(
        "authenticate_connection id copy"));
    test_auth_result_wait(&auth_result);
    assert(auth_result.callback_count == 1);
    assert(auth_result.terminal_count == 1);
    assert(auth_result.terminal_had_error);
    assert(auth_result.terminal_error_code == OvStorage_Status_Internal);
    assert(!auth_result.bad_shape);
    assert(strstr(auth_result.terminal_message, "out of memory") != NULL);
    test_auth_result_destroy(&auth_result);
}
#endif

int ovstorage_c_source_connection_ownership_contract(void)
{
    char directory[OVC_TEMP_DIR_PATH_MAX];
    char root_url[1024];
    OvStorage_LayerHandle *handle;
    size_t iteration;
    int written;

    assert(ovc_temp_dir_create("ovstorage-c-source-conn-ownership",
                               directory,
                               sizeof(directory)) == 0);
    written = test_file_url(root_url, sizeof(root_url), directory, "/");
    assert(written > 0 && (size_t)written < sizeof(root_url));
    handle = test_build_file_stack(root_url, 2);

    for (iteration = 0; iteration < 10; ++iteration) {
        test_connection_ownership_once(handle);
        test_connection_diagnostics_once(handle);
        test_remove_and_authenticate_diagnostics_once(handle);
    }
#if defined(OVC_ABI_ALLOC_FAILURE_TEST)
    test_connection_allocation_failures_once(handle);
#endif

    ovstorage_layer_handle_destroy(handle);
    assert(rmdir(directory) == 0);
    return EXIT_SUCCESS;
}

static void test_unsupported_new_operations_release_requests(void);

int ovstorage_c_source_default_vtables_reserved_null(void)
{
    size_t index;
    size_t count;

    /* The frozen forward-compat protocol requires unimplemented reserved
     * slots to stay NULL so a newer host sees "not implemented" (the Rust
     * reference keeps [None; 16] in both default tables). */
    count = sizeof(OVSTORAGE_UNSUPPORTED_VTABLE._reserved) /
            sizeof(OVSTORAGE_UNSUPPORTED_VTABLE._reserved[0]);
    for (index = 0; index < count; ++index) {
        assert(OVSTORAGE_UNSUPPORTED_VTABLE._reserved[index] == NULL);
        assert(OVSTORAGE_PASSTHROUGH_VTABLE._reserved[index] == NULL);
    }
    test_unsupported_new_operations_release_requests();
    return EXIT_SUCCESS;
}

int ovstorage_c_source_stream_cancel_contracts(void)
{
    size_t iteration;

    for (iteration = 0; iteration < 100; ++iteration) {
        test_watch_cancel_once();
        test_auth_cancel_once();
    }
    test_watch_events_once(1, 2, OvStorage_Status_Ok);
    test_watch_events_once(2, 0, OvStorage_Status_Internal);
    test_watch_events_once(3, 2, OvStorage_Status_Ok);
    return EXIT_SUCCESS;
}

int ovstorage_c_source_auth_cancel_failed_step(void)
{
    size_t iteration;

    for (iteration = 0; iteration < 100; ++iteration) {
        test_auth_cancel_failed_step_once();
    }
    return EXIT_SUCCESS;
}

/* Pins the dispatcher's lossy auth-event conversion: an interior NUL in a
 * Progress message must be escaped ("step\0one" -> "step\\0one"), the event
 * delivered, and the flow still end in a clean success terminal. Escaping
 * rather than dropping is what distinguishes event strings from the
 * connection strings beside them. */
static void test_auth_nul_progress_once(void)
{
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    TestAuthResult result;
    BlockingPullState *pull;

    stub_layer_init(&layer, 0);
    layer.yield_nul_progress = 1;
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    test_auth_result_init(&result);
    ovstorage_authenticate_connection(handle,
                                      "stub",
                                      "nul-progress",
                                      OvStorage_InteractiveAuthCapability_None,
                                      false,
                                      NULL,
                                      test_auth_complete,
                                      &result);
    pull = layer.last_pull;
    assert(pull != NULL);
    test_auth_result_wait(&result);
    assert(result.callback_count == 2);
    assert(result.event_count == 1);
    assert(result.terminal_count == 1);
    assert(!result.terminal_had_error);
    assert(result.terminal_error_code == OvStorage_Status_Ok);
    assert(result.progress_message_set);
    assert(strcmp(result.progress_message, "step\\0one") == 0);
    assert(!result.bad_shape);
    ovstorage_layer_handle_destroy(handle);
    blocking_pull_assert_dropped_once(pull);
    assert(layer.drop_count == 1);
    test_auth_result_destroy(&result);
    blocking_pull_destroy(pull);
    stub_layer_destroy(&layer);
}

int ovstorage_c_source_auth_nul_progress(void)
{
    size_t iteration;

    for (iteration = 0; iteration < 10; ++iteration) {
        test_auth_nul_progress_once();
    }
    return EXIT_SUCCESS;
}

/* Sleep for roughly wait_ns without a signaler: the timed wait can only
 * return ETIMEDOUT, giving the reap poll below a portable pause. */
static void test_sleep_ns(ovc_mutex *mutex, ovc_cond *cond, uint64_t wait_ns)
{
    assert(ovc_mutex_lock(mutex) == 0);
    (void)ovc_cond_timedwait_ns(cond, mutex, wait_ns);
    assert(ovc_mutex_unlock(mutex) == 0);
}

/* Pins that a completed auth pump is reaped from its owning handle at
 * the stream terminal.  Ten flows (successful and cancelled, alternating)
 * run against one live handle without destroying it; if reaping regressed
 * to destroy-time, all ten pumps would still be registered below and the
 * zero assertion would fail. */
int ovstorage_c_source_pump_reap_contract(void)
{
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *token;
    TestAuthResult result;
    BlockingPullState *pull;
    ovc_mutex sleep_mutex;
    ovc_cond sleep_cond;
    uint64_t deadline;
    size_t iteration;
    size_t pump_count;
    int blocked;

    stub_layer_init(&layer, 1);
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);

    for (iteration = 0; iteration < 10; ++iteration) {
        /* Even iterations block and are cancelled; odd iterations end
         * immediately with the empty-success terminal. */
        blocked = (iteration % 2) == 0;
        layer.block_auth = blocked;
        token = NULL;
        if (blocked) {
            token = ovstorage_cancel_token_create();
            assert(token != NULL);
        }
        test_auth_result_init(&result);
        ovstorage_authenticate_connection(
            handle,
            "stub",
            "reap",
            OvStorage_InteractiveAuthCapability_None,
            false,
            token,
            test_auth_complete,
            &result);
        pull = layer.last_pull;
        assert(pull != NULL);
        if (blocked) {
            blocking_pull_wait_entered(pull);
            /* The pump is provably registered while its pull is blocked,
             * so the zero assertion after the loop observes real reaping
             * rather than a counter that never counts. */
            assert(ovc_dispatch_registered_pump_count(handle) >= 1);
            ovstorage_cancel_token_cancel(token);
        }
        test_auth_result_wait(&result);
        assert(result.callback_count == 1);
        assert(result.event_count == 0);
        assert(result.terminal_count == 1);
        assert(result.terminal_had_error == blocked);
        assert(result.terminal_error_code ==
               (blocked ? OvStorage_Status_Cancelled : OvStorage_Status_Ok));
        assert(!result.bad_shape);
        blocking_pull_assert_dropped_once(pull);
        /* Reset the slot so the next flow can record its stream against
         * the same still-live handle. */
        assert(ovc_mutex_lock(&layer.mutex) == 0);
        layer.last_pull = NULL;
        assert(ovc_mutex_unlock(&layer.mutex) == 0);
        ovstorage_cancel_token_destroy(token);
        test_auth_result_destroy(&result);
        blocking_pull_destroy(pull);
    }

    /* The terminal latch fires before the pump detaches itself, so poll
     * the registration count down with a bounded wait. */
    assert(ovc_mutex_init(&sleep_mutex) == 0);
    assert(ovc_cond_init(&sleep_cond) == 0);
    deadline = ovc_monotonic_ns() + UINT64_C(5000000000);
    for (;;) {
        pump_count = ovc_dispatch_registered_pump_count(handle);
        if (pump_count == 0 || ovc_monotonic_ns() >= deadline) {
            break;
        }
        test_sleep_ns(&sleep_mutex, &sleep_cond, UINT64_C(1000000));
    }
    assert(ovc_cond_destroy(&sleep_cond) == 0);
    assert(ovc_mutex_destroy(&sleep_mutex) == 0);
    assert(pump_count == 0);

    ovstorage_layer_handle_destroy(handle);
    assert(layer.drop_count == 1);
    stub_layer_destroy(&layer);
    return EXIT_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Direct-vtable pin for the REAL file backend's etag write precondition.
 *
 * The public WriteOptions carries only no_overwrite, so an if_dest
 * MatchEtag write can only be expressed at the plugin ABI.  This case
 * resolves the builtin file factory from a seeded Registry, creates the
 * backend Layer, adds a root connection, and drives the write slot with a
 * genuinely stale etag captured from an earlier write. */

typedef struct TestPluginCompletion {
    ovc_completion_latch completed;
    int32_t status;
    void *result;
    OvStoragePlugin_Error *error;
    int callback_count;
} TestPluginCompletion;

static void test_plugin_complete(int32_t status,
                                 void *result,
                                 OvStoragePlugin_Error *error,
                                 void *user_data)
{
    TestPluginCompletion *completion;

    completion = (TestPluginCompletion *)user_data;
    completion->status = status;
    completion->result = result;
    completion->error = error;
    ++completion->callback_count;
    assert(ovc_completion_latch_complete(&completion->completed) == 0);
}

static void test_plugin_completion_start(TestPluginCompletion *completion)
{
    memset(completion, 0, sizeof(*completion));
    assert(ovc_completion_latch_init(&completion->completed) == 0);
}

static void test_plugin_completion_finish(TestPluginCompletion *completion)
{
    assert(ovc_completion_latch_destroy(&completion->completed) == 0);
}

/* The Layer consumes owned request payloads in its synchronous prologue,
 * so every Str/Bytes handed over below is a fresh heap allocation. */
static void test_file_backend_add_root(OvStoragePlugin_LayerHandle *backend,
                                       const char *target,
                                       const char *root_url)
{
    OvStoragePlugin_LayerConnectionRequest request;
    OvStoragePlugin_ConnectionConfigEntry *config;
    OvStoragePlugin_CancelTokenFFI cancel;
    TestPluginCompletion completion;

    /* Adopted by the Layer, which frees the entry array with ovc_abi_free —
     * mint with the matching ABI allocator. */
    config = (OvStoragePlugin_ConnectionConfigEntry *)ovc_abi_alloc(
        sizeof(*config));
    assert(config != NULL);
    memset(config, 0, sizeof(*config));
    config->key = test_owned_str("root");
    config->value.tag = OvStoragePlugin_ConfigValueTag_String;
    config->value.string_value = test_owned_str(root_url);
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.target = test_owned_str(target);
    request.connection.backend_kind = test_owned_str("file");
    request.connection.config.ptr = config;
    request.connection.config.len = 1;
    test_plugin_completion_start(&completion);
    cancel = ovc_cancel_token_mint(NULL);
    backend->vtable->add_connection(backend->state,
                                    &request,
                                    &cancel,
                                    test_plugin_complete,
                                    &completion);
    cancel.drop(cancel.state);
    assert(ovc_completion_latch_wait(&completion.completed) == 0);
    assert(completion.callback_count == 1);
    assert(completion.status == OvStoragePlugin_FFI_STATUS_OK);
    assert(completion.error == NULL);
    assert(completion.result != NULL);
    /* connection_free drops the nested allocations in place; the outer
     * heap block handed to OnComplete is released through the ABI
     * allocator, matching the dispatch adapter's reclamation. */
    ovstorage_plugin_connection_free(
        (OvStoragePlugin_Connection *)completion.result);
    ovc_abi_free(completion.result);
    test_plugin_completion_finish(&completion);
}

/* Drive one buffered write.  match_etag == NULL writes unconditionally
 * (if_dest Overwrite); otherwise if_dest is MatchEtag with that etag.
 * The caller inspects and releases completion.result/completion.error and
 * then calls test_plugin_completion_finish. */
static void test_file_backend_write(OvStoragePlugin_LayerHandle *backend,
                                    const char *address,
                                    const uint8_t *payload,
                                    size_t payload_len,
                                    const char *match_etag,
                                    TestPluginCompletion *completion)
{
    OvStoragePlugin_WriteRequest request;
    OvStoragePlugin_CancelTokenFFI cancel;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = test_owned_str(address);
    request.body.tag = OvStoragePlugin_BodyTag_Bytes;
    /* The backend steals the body and frees it with ovc_abi_free at task
     * destroy — mint with the matching ABI allocator. */
    request.body.bytes.ptr =
        (uint8_t *)ovc_abi_alloc(payload_len == 0 ? 1 : payload_len);
    assert(request.body.bytes.ptr != NULL);
    if (payload_len != 0) {
        memcpy(request.body.bytes.ptr, payload, payload_len);
    }
    request.body.bytes.len = payload_len;
    request.options.struct_size = sizeof(request.options);
    if (match_etag == NULL) {
        request.options.if_dest.tag =
            OvStoragePlugin_IfDestExistsTag_Overwrite;
    } else {
        request.options.if_dest.tag =
            OvStoragePlugin_IfDestExistsTag_MatchEtag;
        request.options.if_dest.match_etag.etag = test_owned_str(match_etag);
    }
    test_plugin_completion_start(completion);
    cancel = ovc_cancel_token_mint(NULL);
    backend->vtable->write(backend->state,
                           &request,
                           &cancel,
                           test_plugin_complete,
                           completion);
    cancel.drop(cancel.state);
    assert(ovc_completion_latch_wait(&completion->completed) == 0);
    assert(completion->callback_count == 1);
}

int ovstorage_c_source_file_backend_etag_precondition(void)
{
    static const uint8_t first_payload[] = "etag precondition first";
    static const uint8_t second_payload[] = "etag precondition second write";
    char directory_storage[OVC_TEMP_DIR_PATH_MAX];
    char meta_directory[1024];
    char root_url[1024];
    char object_url[1024];
    char object_path[1024];
    char *directory;
    char *stale_etag;
    OvStorage_Registry *registry;
    const ovc_layer_factory *factory;
    OvStoragePlugin_CreateBackendRequest create;
    OvStoragePlugin_LayerHandle backend;
    OvStoragePlugin_Error *factory_error;
    OvStoragePlugin_WriteResult *write_result;
    TestPluginCompletion completion;
    int written;

    /* The file backend runs its tasks on the process-global runtime that
     * ovstorage_c_source_runtime_contracts pinned to two workers. */
    assert(ovc_runtime_worker_count() == 2);
    assert(ovc_temp_dir_create("ovstorage-c-source-etag",
                               directory_storage,
                               sizeof(directory_storage)) == 0);
    directory = directory_storage;
    written = test_file_url(root_url, sizeof(root_url), directory, "/");
    assert(written > 0 && (size_t)written < sizeof(root_url));
    written = test_file_url(
        object_url, sizeof(object_url), directory, "/etag.bin");
    assert(written > 0 && (size_t)written < sizeof(object_url));
    written = snprintf(object_path,
                       sizeof(object_path),
                       "%s/etag.bin",
                       directory);
    assert(written > 0 && (size_t)written < sizeof(object_path));
    written = snprintf(meta_directory,
                       sizeof(meta_directory),
                       "%s/.ovstorage-meta",
                       directory);
    assert(written > 0 && (size_t)written < sizeof(meta_directory));

    /* A fresh Registry is seeded with the builtin file factory; this is
     * exactly how stack.c resolves "file" during ovstorage_stack_build. */
    registry = ovstorage_registry_create();
    assert(registry != NULL);
    factory = ovc_registry_find_factory(registry, "file");
    assert(factory != NULL);
    assert(factory->plugin_vtable != NULL);
    assert(factory->plugin_vtable->create_backend != NULL);

    memset(&create, 0, sizeof(create));
    create.struct_size = sizeof(create);
    create.kind = test_owned_str("file");
    create.instance_id = test_owned_str("files");
    memset(&backend, 0, sizeof(backend));
    factory_error = NULL;
    assert(factory->plugin_vtable->create_backend(factory->plugin_state,
                                                  &create,
                                                  &backend,
                                                  &factory_error) ==
           OvStoragePlugin_FFI_STATUS_OK);
    assert(factory_error == NULL);
    assert(backend.state != NULL);
    assert(backend.vtable != NULL);

    test_file_backend_add_root(&backend, "files", root_url);

    /* First write pins the object's real etag. */
    test_file_backend_write(&backend,
                            object_url,
                            first_payload,
                            sizeof(first_payload) - 1,
                            NULL,
                            &completion);
    assert(completion.status == OvStoragePlugin_FFI_STATUS_OK);
    assert(completion.error == NULL);
    write_result = (OvStoragePlugin_WriteResult *)completion.result;
    assert(write_result != NULL);
    assert(write_result->info.etag.present);
    assert(write_result->info.etag.value.ptr != NULL);
    stale_etag = (char *)malloc(write_result->info.etag.value.len + 1);
    assert(stale_etag != NULL);
    memcpy(stale_etag,
           write_result->info.etag.value.ptr,
           write_result->info.etag.value.len);
    stale_etag[write_result->info.etag.value.len] = '\0';
    ovstorage_plugin_write_result_free(write_result);
    test_plugin_completion_finish(&completion);

    /* The second write changes the object's size, so the first etag is
     * stale regardless of filesystem mtime granularity. */
    test_file_backend_write(&backend,
                            object_url,
                            second_payload,
                            sizeof(second_payload) - 1,
                            NULL,
                            &completion);
    assert(completion.status == OvStoragePlugin_FFI_STATUS_OK);
    assert(completion.error == NULL);
    assert(completion.result != NULL);
    ovstorage_plugin_write_result_free(
        (OvStoragePlugin_WriteResult *)completion.result);
    test_plugin_completion_finish(&completion);

    /* The stale-etag conditional write must fail with PreconditionFailed:
     * a destination precondition is checked before any bytes commit, so
     * nothing happened.  ObjectModified is reserved for a change detected
     * mid-operation, after bytes have already flowed. */
    test_file_backend_write(&backend,
                            object_url,
                            first_payload,
                            sizeof(first_payload) - 1,
                            stale_etag,
                            &completion);
    assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
    assert(completion.result == NULL);
    assert(completion.error != NULL);
    assert(completion.error->code ==
           OvStoragePlugin_ErrorCode_PreconditionFailed);
    ovstorage_plugin_error_free(completion.error);
    test_plugin_completion_finish(&completion);

    free(stale_etag);
    backend.vtable->drop(backend.state);
    ovstorage_registry_destroy(registry);
    assert(unlink(object_path) == 0);
    (void)rmdir(meta_directory);
    assert(rmdir(directory) == 0);
    return EXIT_SUCCESS;
}

typedef struct TestWriteSource {
    size_t index;
    int fail;
    int drop_count;
} TestWriteSource;

static OvStorage_WriteStreamStep test_write_source_next(
    void *opaque,
    OvStorage_Bytes *out_chunk,
    OvStorage_Status *out_status,
    const char **out_error_message)
{
    static const uint8_t first[] = "streamed ";
    static const uint8_t second[] = "write";
    TestWriteSource *source;

    source = (TestWriteSource *)opaque;
    memset(out_chunk, 0, sizeof(*out_chunk));
    if (source->fail != 0) {
        *out_status = source->fail == 1
                          ? OvStorage_Status_ObjectModified
                          : OvStorage_Status_NoRoute;
        *out_error_message =
            source->fail == 1 ? "stream source changed" : NULL;
        source->fail = 0;
        return OvStorage_WriteStreamStep_Error;
    }
    if (source->index == 0) {
        out_chunk->data = first;
        out_chunk->len = sizeof(first) - 1;
    } else if (source->index == 1) {
        out_chunk->data = second;
        out_chunk->len = sizeof(second) - 1;
    } else {
        return OvStorage_WriteStreamStep_End;
    }
    ++source->index;
    return OvStorage_WriteStreamStep_Chunk;
}

static void test_write_source_drop(void *opaque)
{
    TestWriteSource *source;

    source = (TestWriteSource *)opaque;
    ++source->drop_count;
}

static void test_public_write_stream(OvStorage_LayerHandle *handle)
{
    TestWriteSource source;
    OvStorage_WriteStream stream;
    OvStorage_WriteOptions options;
    TestIoResult result;

    memset(&source, 0, sizeof(source));
    memset(&stream, 0, sizeof(stream));
    memset(&options, 0, sizeof(options));
    stream.state = &source;
    stream.next = test_write_source_next;
    stream.drop = test_write_source_drop;
    options.has_size_hint = true;
    options.size_hint = 14;
    test_io_result_init(&result);
    ovstorage_write_stream(handle,
                           "test://streamed-write",
                           &stream,
                           &options,
                           NULL,
                           test_info_complete,
                           &result);
    assert(stream.next == NULL);
    assert(stream.drop == NULL);
    test_io_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(result.info->has_size);
    assert(result.info->size == 14);
    assert(source.index == 2);
    assert(source.drop_count == 1);
    test_io_result_destroy(&result);
}

static void test_public_get_latest_version(
    OvStorage_LayerHandle *handle)
{
    OvStorage_ReadOptions options;
    TestIoResult result;

    memset(&options, 0, sizeof(options));
    options.has_range = true;
    options.range_start = 2;
    options.has_range_end = true;
    options.range_end_inclusive = 4;
    test_io_result_init(&result);
    ovstorage_get_latest_version(handle,
                                 "test://latest-version",
                                 &options,
                                 NULL,
                                 test_info_complete,
                                 &result);
    test_io_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(result.info->has_size);
    assert(result.info->size == 777);
    test_io_result_destroy(&result);
}

static void test_public_write_stream_error(
    OvStorage_LayerHandle *handle,
    int fail_mode,
    OvStorage_Status expected_status,
    const char *expected_message)
{
    TestWriteSource source;
    OvStorage_WriteStream stream;
    TestIoResult result;

    memset(&source, 0, sizeof(source));
    source.fail = fail_mode;
    memset(&stream, 0, sizeof(stream));
    stream.state = &source;
    stream.next = test_write_source_next;
    stream.drop = test_write_source_drop;
    test_io_result_init(&result);
    ovstorage_write_stream(handle,
                           "test://streamed-write-error",
                           &stream,
                           NULL,
                           NULL,
                           test_info_complete,
                           &result);
    assert(stream.next == NULL);
    assert(stream.drop == NULL);
    test_io_result_wait(&result);
    assert(result.status == expected_status);
    assert(result.had_error);
    assert(strcmp(result.error_message, expected_message) == 0);
    assert(result.callback_count == 1);
    assert(result.info == NULL);
    assert(source.index == 0);
    assert(source.drop_count == 1);
    test_io_result_destroy(&result);
}

static OvStoragePlugin_Bytes test_owned_bytes(
    const uint8_t *data,
    size_t len)
{
    OvStoragePlugin_Bytes result;

    memset(&result, 0, sizeof(result));
    result.ptr = (uint8_t *)ovc_abi_alloc(len == 0 ? 1 : len);
    assert(result.ptr != NULL);
    if (len != 0) {
        memcpy(result.ptr, data, len);
    }
    result.len = len;
    return result;
}

static void unsupported_complete(
    OvStoragePlugin_FfiStatus status,
    void *result,
    OvStoragePlugin_Error *error,
    void *user_data)
{
    int *callbacks;

    callbacks = (int *)user_data;
    assert(status == OvStoragePlugin_FFI_STATUS_ERR);
    assert(result == NULL);
    assert(error != NULL);
    assert(error->code == OvStoragePlugin_ErrorCode_Unsupported);
    ++*callbacks;
    ovstorage_plugin_error_free(error);
}

static void unsupported_write_request_once(int redirect)
{
    static const uint8_t body[] = "owned body";
    OvStoragePlugin_WriteRequest request;
    TestWriteSource source;
    int callbacks = 0;

    memset(&request, 0, sizeof(request));
    memset(&source, 0, sizeof(source));
    request.struct_size = sizeof(request);
    request.address = test_owned_str("test://unsupported-write");
    if (redirect) {
        request.body.tag = OvStoragePlugin_BodyTag_Bytes;
        request.body.bytes = test_owned_bytes(body, sizeof(body) - 1);
    } else {
        request.body.tag = OvStoragePlugin_BodyTag_Stream;
        request.body.stream.state = &source;
        request.body.stream.next_fn = NULL;
        request.body.stream.drop_fn = test_write_source_drop;
    }
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag =
        OvStoragePlugin_IfDestExistsTag_MatchEtag;
    request.options.if_dest.match_etag.etag =
        test_owned_str("etag-1");
    request.options.user_metadata.present = true;
    request.options.user_metadata.value.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
            sizeof(*request.options.user_metadata.value.ptr));
    assert(request.options.user_metadata.value.ptr != NULL);
    request.options.user_metadata.value.len = 1;
    request.options.user_metadata.value.ptr[0].key =
        test_owned_str("owner");
    request.options.user_metadata.value.ptr[0].value =
        test_owned_str("test");
    request.options.message.present = true;
    request.options.message.value = test_owned_str("message");
    if (redirect) {
        OVSTORAGE_UNSUPPORTED_VTABLE.write_redirect(
            NULL, &request, NULL, unsupported_complete, &callbacks);
    } else {
        OVSTORAGE_UNSUPPORTED_VTABLE.write_stream(
            NULL, &request, NULL, unsupported_complete, &callbacks);
    }
    assert(callbacks == 1);
    assert(source.drop_count == (redirect ? 0 : 1));
}

static void unsupported_continue_write_once(void)
{
    static const uint8_t continuation[] = {1, 3, 5, 7};
    static const uint8_t body[] = "captured";
    OvStoragePlugin_ContinueWriteRequest request;
    OvStoragePlugin_WriteRedirectBatch *redirects;
    int callbacks = 0;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = test_owned_str("test://unsupported-continue");
    redirects = stub_redirect_batch(
        continuation, sizeof(continuation), 0);
    request.redirects = *redirects;
    ovc_abi_free(redirects);
    request.redirects.redirects.ptr[0].body_source.tag =
        OvStoragePlugin_RedirectBodySourceTag_Inline;
    request.redirects.redirects.ptr[0].body_source.inline_ =
        test_owned_bytes(body, sizeof(body) - 1);
    request.results.results.ptr =
        (OvStoragePlugin_RedirectResult *)ovc_abi_alloc(
            sizeof(*request.results.results.ptr));
    assert(request.results.results.ptr != NULL);
    request.results.results.len = 1;
    memset(request.results.results.ptr,
           0,
           sizeof(*request.results.results.ptr));
    request.results.results.ptr[0].status_code = 201;
    request.results.results.ptr[0].captured_headers.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
            sizeof(*request.results.results.ptr[0]
                        .captured_headers.ptr));
    assert(request.results.results.ptr[0].captured_headers.ptr != NULL);
    request.results.results.ptr[0].captured_headers.len = 1;
    request.results.results.ptr[0].captured_headers.ptr[0].key =
        test_owned_str("etag");
    request.results.results.ptr[0].captured_headers.ptr[0].value =
        test_owned_str("\"abc\"");
    request.results.results.ptr[0].captured_body =
        test_owned_bytes(body, sizeof(body) - 1);
    OVSTORAGE_UNSUPPORTED_VTABLE.continue_write(
        NULL, &request, NULL, unsupported_complete, &callbacks);
    assert(callbacks == 1);
}

static void unsupported_latest_version_once(void)
{
    OvStoragePlugin_ReadRequest request;
    int callbacks = 0;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = test_owned_str("test://unsupported-latest");
    request.options.struct_size = sizeof(request.options);
    request.options.if_match.present = true;
    request.options.if_match.value = test_owned_str("etag-2");
    OVSTORAGE_UNSUPPORTED_VTABLE.get_latest_version(
        NULL, &request, NULL, unsupported_complete, &callbacks);
    assert(callbacks == 1);
}

static void unsupported_watch_directory_once(void)
{
    static const uint8_t cursor[] = "cursor";
    OvStoragePlugin_WatchDirectoryRequest request;
    int callbacks = 0;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.prefix = test_owned_str("test://unsupported-watch/");
    request.options.struct_size = sizeof(request.options);
    request.options.since.present = true;
    request.options.since.value.bytes =
        test_owned_bytes(cursor, sizeof(cursor) - 1);
    OVSTORAGE_UNSUPPORTED_VTABLE.watch_directory(
        NULL, &request, NULL, unsupported_complete, &callbacks);
    assert(callbacks == 1);
}

static void unsupported_probe_once(void)
{
    OvStoragePlugin_LayerConnectionRequest request;
    int callbacks = 0;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.target = test_owned_str("test://unsupported-probe");
    request.connection.backend_kind = test_owned_str("stub-kind");
    request.connection.display_name.present = true;
    request.connection.display_name.value =
        test_owned_str("Unsupported Probe");
    OVSTORAGE_UNSUPPORTED_VTABLE.probe(
        NULL, &request, NULL, unsupported_complete, &callbacks);
    assert(callbacks == 1);
}

static void unsupported_update_attributes_once(void)
{
    OvStoragePlugin_UpdateConnectionAttributesRequest request;
    int callbacks = 0;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.key.target = test_owned_str("test://unsupported-attrs");
    request.key.id = test_owned_str("connection");
    request.patch.display_name.present = true;
    request.patch.display_name.value = test_owned_str("Display");
    request.patch.access_mode.present = true;
    request.patch.access_mode.value = test_owned_str("read-write");
    request.patch.set_user_metadata.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
            sizeof(*request.patch.set_user_metadata.ptr));
    assert(request.patch.set_user_metadata.ptr != NULL);
    request.patch.set_user_metadata.len = 1;
    request.patch.set_user_metadata.ptr[0].key =
        test_owned_str("owner");
    request.patch.set_user_metadata.ptr[0].value =
        test_owned_str("test");
    request.patch.remove_user_metadata.ptr =
        (OvStoragePlugin_Str *)ovc_abi_alloc(
            sizeof(*request.patch.remove_user_metadata.ptr));
    assert(request.patch.remove_user_metadata.ptr != NULL);
    request.patch.remove_user_metadata.len = 1;
    request.patch.remove_user_metadata.ptr[0] =
        test_owned_str("obsolete");
    OVSTORAGE_UNSUPPORTED_VTABLE.update_connection_attributes(
        NULL, &request, NULL, unsupported_complete, &callbacks);
    assert(callbacks == 1);
}

static void test_unsupported_new_operations_release_requests(void)
{
    static void (*const cases[])(void) = {
        unsupported_continue_write_once,
        unsupported_latest_version_once,
        unsupported_watch_directory_once,
        unsupported_probe_once,
        unsupported_update_attributes_once,
    };
    size_t index;

    unsupported_write_request_once(0);
    unsupported_write_request_once(1);
    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cases[index]();
    }
}

typedef struct TestRedirectResult {
    ovc_completion_latch completed;
    OvStorage_Status status;
    OvStorage_WriteRedirectBatch *redirects;
    OvStorage_Info *info;
    int callback_count;
    int had_error;
} TestRedirectResult;

static void test_redirect_result_init(TestRedirectResult *result)
{
    memset(result, 0, sizeof(*result));
    assert(ovc_completion_latch_init(&result->completed) == 0);
}

static void test_write_redirect_complete(
    OvStorage_Status status,
    OvStorage_WriteRedirectBatch *redirects,
    const OvStorage_Error *error,
    void *user_data)
{
    TestRedirectResult *result;

    result = (TestRedirectResult *)user_data;
    result->status = status;
    result->redirects = redirects;
    result->had_error = error != NULL;
    ++result->callback_count;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_continue_write_complete(
    OvStorage_Status status,
    OvStorage_Info *info,
    OvStorage_WriteRedirectBatch *redirects,
    const OvStorage_Error *error,
    void *user_data)
{
    TestRedirectResult *result;

    result = (TestRedirectResult *)user_data;
    result->status = status;
    result->info = info;
    result->redirects = redirects;
    result->had_error = error != NULL;
    ++result->callback_count;
    assert(ovc_completion_latch_complete(&result->completed) == 0);
}

static void test_redirect_result_destroy(TestRedirectResult *result)
{
    ovstorage_info_destroy(result->info);
    ovstorage_write_redirect_batch_destroy(result->redirects);
    assert(ovc_completion_latch_destroy(&result->completed) == 0);
}

static void test_public_redirect_write(StubLayer *layer,
                                       OvStorage_LayerHandle *handle)
{
    static const uint8_t expected_continuation[] = {1, 3, 5, 7};
    static const uint8_t next_continuation[] = {2, 4, 6, 8};
    static const uint8_t response_body[] = "saved";
    uint8_t oversized_body[65];
    OvStorage_WriteOptions options;
    TestRedirectResult invalid;
    TestRedirectResult initial;
    TestRedirectResult continued;
    TestRedirectResult finished;
    OvStorage_Header response_header;
    OvStorage_RedirectResult response;
    OvStorage_RedirectResultBatch responses;
    const OvStorage_WriteRedirect *redirect;

    memset(&options, 0, sizeof(options));
    options.has_size_hint = true;
    options.size_hint = 5;

    layer->redirect_overflow = 1;
    test_redirect_result_init(&invalid);
    ovstorage_write_redirect(handle,
                             "test://redirect-overflow",
                             &options,
                             NULL,
                             test_write_redirect_complete,
                             &invalid);
    assert(ovc_completion_latch_wait(&invalid.completed) == 0);
    assert(invalid.status == OvStorage_Status_Internal);
    assert(invalid.had_error);
    assert(invalid.callback_count == 1);
    assert(invalid.redirects == NULL);
    test_redirect_result_destroy(&invalid);
    layer->redirect_overflow = 0;

    test_redirect_result_init(&initial);
    ovstorage_write_redirect(handle,
                             "test://redirect-write",
                             &options,
                             NULL,
                             test_write_redirect_complete,
                             &initial);
    assert(ovc_completion_latch_wait(&initial.completed) == 0);
    assert(initial.status == OvStorage_Status_Ok);
    assert(!initial.had_error);
    assert(initial.callback_count == 1);
    assert(initial.redirects != NULL);
    assert(initial.redirects->continuation_len ==
           sizeof(expected_continuation));
    assert(memcmp(initial.redirects->continuation,
                  expected_continuation,
                  sizeof(expected_continuation)) == 0);
    assert(initial.redirects->redirects_len == 1);
    redirect = &initial.redirects->redirects[0];
    assert(strcmp(redirect->method, "PUT") == 0);
    assert(strcmp(redirect->url,
                  "https://upload.example/object") == 0);
    assert(redirect->headers_len == 1);
    assert(strcmp(redirect->headers[0].name, "content-type") == 0);
    assert(strcmp(redirect->headers[0].value,
                  "application/octet-stream") == 0);
    assert(redirect->body_source_kind ==
           OvStorage_RedirectBodySourceKind_UserBytes);
    assert(redirect->body_offset == 0);
    assert(redirect->body_len == 5);
    assert(redirect->capture_headers_len == 1);
    assert(strcmp(redirect->capture_headers[0], "etag") == 0);
    assert(redirect->capture_body_max_bytes == 64);
    assert(redirect->expires_at_unix_nanos ==
           UINT64_C(1700000000000000000));
    assert(strcmp(redirect->scope_physical_url_prefix,
                  "https://upload.example/") == 0);
    assert(redirect->scope_operations.write);
    assert(redirect->scope_expires_at_unix_nanos ==
           UINT64_C(1700000001000000000));
    assert(redirect->scope_credential ==
           OvStorage_RedirectCredential_Connection);
    assert(strcmp(redirect->audit_id, "audit-394") == 0);
    assert(redirect->policy_epoch == 9);

    response_header.name = "etag";
    response_header.value = "\"abc\"";
    memset(&response, 0, sizeof(response));
    response.status_code = 201;
    response.captured_headers = &response_header;
    response.captured_headers_len = 1;
    responses.results = &response;
    responses.results_len = 1;

    memset(oversized_body, 0x5a, sizeof(oversized_body));
    response.captured_body = oversized_body;
    response.captured_body_len = sizeof(oversized_body);
    test_redirect_result_init(&invalid);
    ovstorage_continue_write(handle,
                             "test://redirect-write",
                             initial.redirects,
                             &responses,
                             NULL,
                             test_continue_write_complete,
                             &invalid);
    assert(ovc_completion_latch_wait(&invalid.completed) == 0);
    assert(invalid.status == OvStorage_Status_InvalidArgument);
    assert(invalid.had_error);
    assert(invalid.callback_count == 1);
    assert(invalid.info == NULL);
    assert(invalid.redirects == NULL);
    test_redirect_result_destroy(&invalid);

    response.captured_body = response_body;
    response.captured_body_len = sizeof(response_body) - 1;
    test_redirect_result_init(&continued);
    ovstorage_continue_write(handle,
                             "test://redirect-write",
                             initial.redirects,
                             &responses,
                             NULL,
                             test_continue_write_complete,
                             &continued);
    ovstorage_write_redirect_batch_destroy(initial.redirects);
    initial.redirects = NULL;
    assert(ovc_completion_latch_wait(&continued.completed) == 0);
    assert(continued.status == OvStorage_Status_Ok);
    assert(!continued.had_error);
    assert(continued.callback_count == 1);
    assert(continued.info == NULL);
    assert(continued.redirects != NULL);
    assert(continued.redirects->continuation_len ==
           sizeof(next_continuation));
    assert(memcmp(continued.redirects->continuation,
                  next_continuation,
                  sizeof(next_continuation)) == 0);
    assert(continued.redirects->redirects_len == 1);

    test_redirect_result_init(&finished);
    ovstorage_continue_write(handle,
                             "test://redirect-write",
                             continued.redirects,
                             &responses,
                             NULL,
                             test_continue_write_complete,
                             &finished);
    ovstorage_write_redirect_batch_destroy(continued.redirects);
    continued.redirects = NULL;
    assert(ovc_completion_latch_wait(&finished.completed) == 0);
    assert(finished.status == OvStorage_Status_Ok);
    assert(!finished.had_error);
    assert(finished.callback_count == 1);
    assert(finished.info != NULL);
    assert(finished.redirects == NULL);
    assert(finished.info->has_size);
    assert(finished.info->size == 5);
    test_redirect_result_destroy(&finished);
    test_redirect_result_destroy(&continued);
    test_redirect_result_destroy(&initial);
}

int ovstorage_c_source_stream_concurrency(void)
{
    static const uint8_t expected[] = "two runtime workers live";
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_CancelToken *cancel;
    OvStorage_StatOptions stat_options;
    OvStorage_ReadOptions read_options;
    TestAuthResult auth;
    TestIoResult stat_result;
    TestIoResult read_result;
    BlockingPullState *pull;

    assert(ovc_runtime_worker_count() == 2);
    stub_layer_init(&layer, 1);
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    test_public_get_latest_version(handle);
    test_public_connection_operations(handle);
    test_public_write_stream(handle);
    test_public_write_stream_error(handle,
                                   1,
                                   OvStorage_Status_ObjectModified,
                                   "stream source changed");
    test_public_write_stream_error(handle,
                                   2,
                                   OvStorage_Status_NoRoute,
                                   "write stream producer failed");
    test_public_redirect_write(&layer, handle);
    cancel = ovstorage_cancel_token_create();
    assert(cancel != NULL);
    test_auth_result_init(&auth);
    ovstorage_authenticate_connection(handle,
                                      "stub",
                                      "concurrent",
                                      OvStorage_InteractiveAuthCapability_None,
                                      false,
                                      cancel,
                                      test_auth_complete,
                                      &auth);
    pull = layer.last_pull;
    assert(pull != NULL);
    blocking_pull_wait_entered(pull);

    memset(&stat_options, 0, sizeof(stat_options));
    memset(&read_options, 0, sizeof(read_options));
    test_io_result_init(&stat_result);
    test_io_result_init(&read_result);
    ovstorage_stat(handle,
                   "test://concurrent/object",
                   &stat_options,
                   NULL,
                   test_info_complete,
                   &stat_result);
    ovstorage_read_bytes(handle,
                         "test://concurrent/object",
                         &read_options,
                         NULL,
                         test_read_complete,
                         &read_result);
    test_io_result_wait(&stat_result);
    test_io_result_wait(&read_result);
    assert(layer.barrier_arrivals == 2);
    assert(!layer.barrier_timed_out);
    assert(stat_result.status == OvStorage_Status_Ok);
    assert(!stat_result.had_error);
    assert(stat_result.callback_count == 1);
    assert(stat_result.info != NULL);
    assert(read_result.status == OvStorage_Status_Ok);
    assert(!read_result.had_error);
    assert(read_result.callback_count == 1);
    assert(read_result.info != NULL);
    assert(read_result.bytes.len == sizeof(expected) - 1);
    assert(memcmp(read_result.bytes.data,
                  expected,
                  sizeof(expected) - 1) == 0);

    ovstorage_cancel_token_cancel(cancel);
    test_auth_result_wait(&auth);
    assert(auth.callback_count == 1);
    assert(auth.terminal_count == 1);
    assert(auth.terminal_had_error);
    assert(auth.terminal_error_code == OvStorage_Status_Cancelled);
    ovstorage_layer_handle_destroy(handle);
    assert(auth.callback_count == 1);
    assert(auth.event_count == 0);
    assert(auth.terminal_count == 1);
    assert(auth.terminal_had_error);
    assert(auth.terminal_error_code == OvStorage_Status_Cancelled);
    assert(!auth.bad_shape);
    blocking_pull_assert_dropped_once(pull);
    assert(layer.drop_count == 1);
    assert(ovc_runtime_worker_count() == 2);

    test_io_result_destroy(&stat_result);
    test_io_result_destroy(&read_result);
    test_auth_result_destroy(&auth);
    ovstorage_cancel_token_destroy(cancel);
    blocking_pull_destroy(pull);
    stub_layer_destroy(&layer);
    return EXIT_SUCCESS;
}

int ovstorage_c_source_auth_terminal_contract(void)
{
    StubLayer layer;
    OvStorage_LayerHandle *handle;
    TestAuthResult result;
    BlockingPullState *pull;

    stub_layer_init(&layer, 0);
    handle = stub_layer_public_handle(&layer);
    assert(handle != NULL);
    test_auth_result_init(&result);
    ovstorage_authenticate_connection(handle,
                                      "stub",
                                      "terminal",
                                      OvStorage_InteractiveAuthCapability_None,
                                      false,
                                      NULL,
                                      test_auth_complete,
                                      &result);
    pull = layer.last_pull;
    assert(pull != NULL);
    test_auth_result_wait(&result);
    assert(result.callback_count == 1);
    assert(result.event_count == 0);
    assert(result.terminal_count == 1);
    assert(!result.terminal_had_error);
    assert(result.terminal_error_code == OvStorage_Status_Ok);
    assert(!result.bad_shape);
    ovstorage_layer_handle_destroy(handle);
    assert(result.callback_count == 1);
    assert(result.event_count == 0);
    assert(result.terminal_count == 1);
    assert(!result.terminal_had_error);
    assert(result.terminal_error_code == OvStorage_Status_Ok);
    assert(!result.bad_shape);
    blocking_pull_assert_dropped_once(pull);
    assert(layer.drop_count == 1);
    test_auth_result_destroy(&result);
    blocking_pull_destroy(pull);
    stub_layer_destroy(&layer);
    return EXIT_SUCCESS;
}

int ovstorage_c_source_inspect_contract(const char *fixture_path)
{
    static const char expected_kind[] = "cc-test-inspect";
    static const char expected_display_name[] = "C source inspect fixture";
    OvStorage_KindDescriptorList *descriptors;
    OvStorage_Error error;
    const char *value;
    size_t length;

    memset(&error, 0, sizeof(error));
    descriptors = NULL;
    assert(ovstorage_inspect_plugin(fixture_path,
                                    true,
                                    &descriptors,
                                    &error) == OvStorage_Status_Ok);
    assert(descriptors != NULL);
    assert(ovstorage_kind_descriptor_list_len(descriptors) == 1);
    assert(ovstorage_kind_descriptor_list_item_layer_type(descriptors, 0) ==
           (int32_t)OvStoragePlugin_LayerType_Backend);
    value = ovstorage_kind_descriptor_list_item_kind(descriptors, 0, &length);
    assert(value != NULL);
    assert(length == sizeof(expected_kind) - 1);
    assert(memcmp(value, expected_kind, length) == 0);
    value = ovstorage_kind_descriptor_list_item_display_name(descriptors,
                                                             0,
                                                             &length);
    assert(value != NULL);
    assert(length == sizeof(expected_display_name) - 1);
    assert(memcmp(value, expected_display_name, length) == 0);

    /* Contract note: this test intentionally inspects exactly once and makes
     * no unload assertion. Every successful call copies the descriptors but
     * pins another mapping until process exit. The distribution README's
     * "Header inventory" points to the frozen include/ovstorage.h contract;
     * its ovstorage_inspect_plugin warning is normative for that lifetime. */
    ovstorage_kind_descriptor_list_destroy(descriptors);
    ovstorage_error_clear(&error);
    return EXIT_SUCCESS;
}

#endif /* OVC_INSPECT_FIXTURE */
