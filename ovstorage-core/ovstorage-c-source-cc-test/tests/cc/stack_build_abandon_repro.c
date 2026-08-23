/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Abandoning a pure-C Stack build blocked in a Layer that ignores its
 * cancellation token.
 *
 * The Layer registered here parks inside a build slot and never reads the
 * token clone the build hands it, so the build thread's only way out is the
 * build-scoped token itself.  Both abandonable slots are covered by a
 * composition each — `add_connection` on a single backend, and
 * `list_address_roots` on a router whose second child parks while the first
 * answers inline — and each runs three gate-driven legs:
 *
 *   (a) cancel while parked — `on_complete` must fire `Cancelled` promptly,
 *       after which the builder is destroyed.  The Layer is then released and
 *       delivers its completion into a build that is long gone: it must find
 *       its own state alive (the magic check below), hand over a payload
 *       nobody reads, and leave nothing behind.
 *   (b) release while parked — the same composition builds to `Ok`, so the
 *       abandonable wait still carries a normal completion.
 *   (c) the Layer cancels the build itself and then completes successfully
 *       from its own thread, racing its outcome against the wakeup.
 *
 * Leg (c) can land on either branch, so each branch also gets a deterministic
 * leg, plus one for each remaining shape the slot has to account for:
 *
 *   (d) a Layer that cancels and completes SYNCHRONOUSLY, before the build
 *       thread ever waits, forcing the completion-first post-wait re-check.
 *   (e) a Layer that fires its completion twice inside the vtable call, while
 *       the build thread's reference is certainly still alive.
 *   (f) a parking wrapper over an inner backend from a SEPARATE loaded plugin
 *       (`abandon_inner_fixture.c`), with that plugin's registry destroyed
 *       before the abandoned call completes — so only the quarantine can keep
 *       the inner plugin alive for its own Layer's eventual drop.
 *   (g) a parked Layer that completes with a plugin ERROR rather than a
 *       result, abandoned in leg (a) and released here, so both the slot's
 *       reclaimer and the build's failure path see one.
 *
 * Two invariants are asserted continuously rather than per leg: no Layer is
 * ever released inside its own completion callback, and by the end every
 * Layer minted has been released.
 *
 * This is a standalone executable so the harness can bound it with a timeout:
 * a build that cannot abandon its wait hangs here rather than returning a
 * wrong answer, and it is built with AddressSanitizer where the toolchain
 * supports it because the completion state is reference-counted across two
 * threads that release it in either order.
 *
 * Takes the companion plugin's path as its only argument.
 */

/* internal.h must precede every libc header in this translation unit. */
#include "../../../../ovstorage-c-source/src/internal.h"

#include "ovstorage.h"
#include "ovstorage_defaults.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PARK_ITERATIONS 25
#define PARK_LAYER_MAGIC 0x7061726b7374617eULL

static char g_park_kind[] = "cc-test-park";
static char g_park_display_name[] = "C source parking backend";
static char g_park_router_kind[] = "cc-test-park-router";
static char g_park_router_display_name[] = "C source parking router";
static char g_park_wrapper_kind[] = "cc-test-park-wrapper";
static char g_park_wrapper_display_name[] = "C source parking wrapper";
/* Kind advertised by the companion cdylib in abandon_inner_fixture.c. */
static const char g_inner_kind[] = "cc-test-abandon-inner";
static int g_park_plugin_state;
static OvStoragePlugin_LayerVTableV1 g_park_layer_vtable;
static OvStoragePlugin_LayerVTableV1 g_park_router_vtable;
static OvStoragePlugin_LayerVTableV1 g_park_wrapper_vtable;

static void park_fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

static void park_check(int result, const char *message)
{
    if (result != 0) {
        park_fail(message);
    }
}

/* --- counting gates ------------------------------------------------------ */

/*
 * A monotonically counted rendezvous: waiters block until the count reaches
 * the generation they name, so a gate signalled by an earlier iteration can
 * never satisfy a later one.
 */
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    unsigned long count;
} Gate;

static void gate_init(Gate *gate)
{
    park_check(pthread_mutex_init(&gate->mutex, NULL), "gate mutex init");
    park_check(pthread_cond_init(&gate->changed, NULL), "gate cond init");
    gate->count = 0;
}

static void gate_destroy(Gate *gate)
{
    (void)pthread_cond_destroy(&gate->changed);
    (void)pthread_mutex_destroy(&gate->mutex);
}

static void gate_signal(Gate *gate)
{
    park_check(pthread_mutex_lock(&gate->mutex), "gate lock");
    ++gate->count;
    park_check(pthread_cond_broadcast(&gate->changed), "gate broadcast");
    park_check(pthread_mutex_unlock(&gate->mutex), "gate unlock");
}

/* The generation a caller signalling next would produce. */
static unsigned long gate_next_generation(Gate *gate)
{
    unsigned long next;

    park_check(pthread_mutex_lock(&gate->mutex), "gate lock");
    next = gate->count + 1;
    park_check(pthread_mutex_unlock(&gate->mutex), "gate unlock");
    return next;
}

static void gate_wait(Gate *gate, unsigned long generation)
{
    park_check(pthread_mutex_lock(&gate->mutex), "gate lock");
    while (gate->count < generation) {
        park_check(pthread_cond_wait(&gate->changed, &gate->mutex),
                   "gate wait");
    }
    park_check(pthread_mutex_unlock(&gate->mutex), "gate unlock");
}

/* The parked slot has entered the Layer, the caller has let it go, and the
 * Layer has returned from its completion. */
static Gate g_arrived;
static Gate g_released;
static Gate g_completed;

/* Every Layer this fixture mints and every one the host releases. An
 * abandoned Layer is released after its completion arrives, off the
 * completing thread, so the run ends by waiting for these two to agree —
 * which is both the drain and the leak assertion. */
static Gate g_created;
static Gate g_dropped;

/* --- parking backend ----------------------------------------------------- */

/*
 * One backend serves both abandonable build slots. The instance name picks
 * which one parks, so a router can hold a child that answers root discovery
 * immediately next to one that never does.
 */
#define PARK_INSTANCE_CONNECTION "connection"
#define PARK_INSTANCE_ROOTS "roots"
#define PARK_INSTANCE_PROMPT "prompt"
#define PARK_INSTANCE_ERROR "error"
#define PARK_INSTANCE_TWICE "twice"
#define PARK_INSTANCE_SELFCANCEL "selfcancel"

typedef enum {
    /* Parks until released, then completes with a Connection. */
    PARK_SLOT_CONNECTION,
    /* Parks until released, then completes with a root snapshot. */
    PARK_SLOT_ROOTS,
    /* Answers root discovery inline; never parks. */
    PARK_SLOT_NONE,
    /* Parks until released, then completes with a plugin error. */
    PARK_SLOT_ERROR,
    /* Fires the completion twice inside the vtable call. */
    PARK_SLOT_TWICE,
    /* Cancels the build and completes successfully, both inside the vtable
     * call, so the outcome is recorded before the build thread ever waits. */
    PARK_SLOT_SELFCANCEL
} ParkSlot;

typedef struct {
    unsigned long long magic;
    ParkSlot slot;
} ParkLayerState;

/*
 * When set, a parked Layer cancels this token immediately before it delivers
 * a SUCCESSFUL completion, racing its own outcome against the build's wakeup.
 * Either order must report Cancelled and reclaim the delivered payload.
 */
static OvStorage_CancelToken *g_self_cancel;

/*
 * The thread currently inside a Layer's `on_complete`, if any.
 *
 * A quarantined Layer's release lands on whichever thread drops the slot's
 * last reference, and for an abandoned call that is normally the plugin's own
 * completing thread.  Tearing the Layer down there would re-enter the plugin
 * inside a live call frame, so the host hands that work to a runtime worker;
 * a drop observed on the completing thread means it did not.
 */
static pthread_mutex_t g_completing_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_completing_thread;
static int g_completing_active;

static void completing_thread_enter(void)
{
    park_check(pthread_mutex_lock(&g_completing_mutex), "completing lock");
    g_completing_thread = pthread_self();
    g_completing_active = 1;
    park_check(pthread_mutex_unlock(&g_completing_mutex), "completing unlock");
}

static void completing_thread_leave(void)
{
    park_check(pthread_mutex_lock(&g_completing_mutex), "completing lock");
    g_completing_active = 0;
    park_check(pthread_mutex_unlock(&g_completing_mutex), "completing unlock");
}

static void completing_thread_assert_not_current(void)
{
    int reentrant;

    park_check(pthread_mutex_lock(&g_completing_mutex), "completing lock");
    reentrant = g_completing_active &&
                pthread_equal(g_completing_thread, pthread_self());
    park_check(pthread_mutex_unlock(&g_completing_mutex), "completing unlock");
    if (reentrant) {
        park_fail("a Layer was released inside its own completion callback");
    }
}

typedef struct {
    ParkLayerState *state;
    /* Set for the add_connection slot only; root discovery moves no payload
     * the host has to hand back. */
    OvStoragePlugin_LayerConnectionRequest request;
    int has_request;
    OvStoragePlugin_OnComplete on_complete;
    void *user_data;
    unsigned long generation;
} ParkCall;

/* The moved request carries no config, credentials, or display name: this
 * composition records none, so only the four owned buffers exist. */
static void park_connection_request_clear(
    OvStoragePlugin_LayerConnectionRequest *request)
{
    ovc_abi_free(request->target.ptr);
    ovc_abi_free(request->connection.backend_kind.ptr);
    ovc_abi_free(request->connection.config.ptr);
    ovc_abi_free(request->connection.credentials.entries.ptr);
    memset(request, 0, sizeof(*request));
}

/* An empty root snapshot with no update stream: enough for the router's root
 * validation to accept the child. */
static OvStoragePlugin_ListAddressRootsResult *park_roots_result(void)
{
    OvStoragePlugin_ListAddressRootsResult *envelope;

    envelope = (OvStoragePlugin_ListAddressRootsResult *)ovc_abi_alloc(
        sizeof(*envelope));
    if (envelope == NULL) {
        park_fail("out of memory minting the root snapshot");
        return NULL;
    }
    memset(envelope, 0, sizeof(*envelope));
    return envelope;
}

/* A plugin-minted Connection, the add_connection slot's success payload. */
static OvStoragePlugin_Connection *park_connection_result(void)
{
    OvStoragePlugin_Connection *connection;

    connection = (OvStoragePlugin_Connection *)ovc_abi_alloc(
        sizeof(*connection));
    if (connection == NULL) {
        park_fail("out of memory minting the parked connection");
        return NULL;
    }
    memset(connection, 0, sizeof(*connection));
    return connection;
}

/* A plugin-minted error, the failure payload the host's reclaimers must
 * release when nobody reads the outcome. */
static OvStoragePlugin_Error *park_error_result(void)
{
    static const char message[] = "parked layer refused the connection";
    OvStoragePlugin_Error *error;

    error = (OvStoragePlugin_Error *)ovc_abi_alloc(sizeof(*error));
    if (error == NULL) {
        park_fail("out of memory minting the parked error");
        return NULL;
    }
    memset(error, 0, sizeof(*error));
    error->code = OvStoragePlugin_ErrorCode_Internal;
    error->message_len = sizeof(message) - 1;
    error->message_ptr = (char *)ovc_abi_alloc(error->message_len);
    if (error->message_ptr == NULL) {
        park_fail("out of memory minting the parked error message");
        return NULL;
    }
    memcpy(error->message_ptr, message, error->message_len);
    return error;
}

static void *park_call_main(void *argument)
{
    ParkCall *call;
    void *result;
    OvStoragePlugin_Error *error;

    call = (ParkCall *)argument;
    gate_signal(&g_arrived);
    gate_wait(&g_released, call->generation);

    if (call->has_request) {
        park_connection_request_clear(&call->request);
    }
    /*
     * The completion is the point of the exercise: reading the Layer's own
     * state here catches a host that unwound this Layer while its call was
     * still outstanding. Nothing touches it after `on_complete`, which is the
     * terminal — the host owns the Layer again the moment it fires.
     */
    if (call->state->magic != PARK_LAYER_MAGIC) {
        park_fail("the parked Layer's state was released under its own call");
    }
    result = NULL;
    error = NULL;
    if (call->state->slot == PARK_SLOT_ERROR) {
        error = park_error_result();
    } else if (call->has_request) {
        result = park_connection_result();
    } else {
        result = park_roots_result();
    }
    if (g_self_cancel != NULL) {
        ovstorage_cancel_token_cancel(g_self_cancel);
    }
    completing_thread_enter();
    call->on_complete(0,
                      result,
                      error,
                      call->user_data);
    completing_thread_leave();
    free(call);
    gate_signal(&g_completed);
    return NULL;
}

static void park_spawn(ParkLayerState *state,
                       const OvStoragePlugin_LayerConnectionRequest *request,
                       OvStoragePlugin_OnComplete on_complete,
                       void *user_data)
{
    ParkCall *call;
    pthread_t worker;
    pthread_attr_t attributes;

    call = (ParkCall *)malloc(sizeof(*call));
    if (call == NULL) {
        park_fail("out of memory recording the parked call");
        return;
    }
    call->state = state;
    call->has_request = request != NULL;
    if (request != NULL) {
        call->request = *request;
    } else {
        memset(&call->request, 0, sizeof(call->request));
    }
    call->on_complete = on_complete;
    call->user_data = user_data;
    call->generation = gate_next_generation(&g_released);

    park_check(pthread_attr_init(&attributes), "thread attr init");
    park_check(pthread_attr_setdetachstate(&attributes,
                                           PTHREAD_CREATE_DETACHED),
               "thread attr detach");
    park_check(pthread_create(&worker, &attributes, park_call_main, call),
               "park thread create");
    (void)pthread_attr_destroy(&attributes);
}

/*
 * `cancel` is deliberately never consulted by either slot: this Layer models
 * the interactive credential acquisition the build cannot interrupt from the
 * inside.
 */
static void park_add_connection(void *state,
                                const OvStoragePlugin_LayerConnectionRequest *request,
                                const OvStoragePlugin_CancelTokenFFI *cancel,
                                OvStoragePlugin_OnComplete on_complete,
                                void *user_data)
{
    ParkLayerState *layer;
    OvStoragePlugin_LayerConnectionRequest moved;

    (void)cancel;
    layer = (ParkLayerState *)state;
    switch (layer->slot) {
    case PARK_SLOT_CONNECTION:
    case PARK_SLOT_ERROR:
        park_spawn(layer, request, on_complete, user_data);
        return;
    case PARK_SLOT_TWICE:
        /*
         * Two fires inside the vtable call, so the build thread's reference is
         * certainly still alive for the second: the host must keep the first
         * outcome and reclaim the repeat fire's payload rather than record or
         * release twice.  A repeat fire after the last reference is gone is
         * undefined and deliberately not modelled.
         */
        moved = *request;
        park_connection_request_clear(&moved);
        on_complete(0,
                    park_connection_result(),
                    NULL,
                    user_data);
        on_complete(0,
                    park_connection_result(),
                    NULL,
                    user_data);
        return;
    case PARK_SLOT_SELFCANCEL:
        /*
         * Cancel, then succeed, both before the build thread reaches its wait.
         * The outcome is therefore already recorded when the wait runs, which
         * forces the completion-first branch: the build accepts nothing and
         * reclaims the Connection through the post-wait re-check.
         */
        moved = *request;
        park_connection_request_clear(&moved);
        ovstorage_cancel_token_cancel(g_self_cancel);
        on_complete(0,
                    park_connection_result(),
                    NULL,
                    user_data);
        return;
    default:
        park_fail("add_connection reached a Layer that does not implement it");
    }
}

static void park_list_address_roots(void *state,
                                    const OvStoragePlugin_ListAddressRootsRequest *request,
                                    const OvStoragePlugin_CancelTokenFFI *cancel,
                                    OvStoragePlugin_OnComplete on_complete,
                                    void *user_data)
{
    ParkLayerState *layer;

    (void)request;
    (void)cancel;
    layer = (ParkLayerState *)state;
    if (layer->slot == PARK_SLOT_ROOTS) {
        park_spawn(layer, NULL, on_complete, user_data);
        return;
    }
    /* The sibling answers inline, so the router walks past it to the child
     * that parks. */
    on_complete(0,
                park_roots_result(),
                NULL,
                user_data);
}

static void park_layer_drop(void *state)
{
    ParkLayerState *layer;

    completing_thread_assert_not_current();
    layer = (ParkLayerState *)state;
    layer->magic = 0;
    free(layer);
    gate_signal(&g_dropped);
}

/* --- parking wrapper ----------------------------------------------------- */

/*
 * A composite whose inner half is built by a DIFFERENT plugin. Quarantining
 * this wrapper quarantines that foreign Layer with it, so the host has to keep
 * the inner plugin's factory retained too, not just this one's.
 */
typedef struct {
    /* First member, so the parking machinery drives a wrapper unchanged. */
    ParkLayerState base;
    OvStoragePlugin_LayerHandle inner;
} ParkWrapperState;

static void park_wrapper_drop(void *state)
{
    ParkWrapperState *wrapper;

    completing_thread_assert_not_current();
    wrapper = (ParkWrapperState *)state;
    /* Dropping the inner Layer calls into the plugin that built it. */
    if (wrapper->inner.vtable != NULL && wrapper->inner.vtable->drop != NULL) {
        wrapper->inner.vtable->drop(wrapper->inner.state);
    }
    wrapper->base.magic = 0;
    free(wrapper);
    gate_signal(&g_dropped);
}

static void park_wrapper_add_connection(
    void *state,
    const OvStoragePlugin_LayerConnectionRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ParkWrapperState *wrapper;

    (void)cancel;
    wrapper = (ParkWrapperState *)state;
    park_spawn(&wrapper->base, request, on_complete, user_data);
}

static OvStoragePlugin_FfiStatus park_create_wrapper(
    void *plugin_state,
    const OvStoragePlugin_CreateWrapperRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    ParkWrapperState *wrapper;

    (void)plugin_state;
    *error = NULL;
    wrapper = (ParkWrapperState *)malloc(sizeof(*wrapper));
    if (wrapper == NULL) {
        park_fail("out of memory creating the parking wrapper");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    wrapper->base.magic = PARK_LAYER_MAGIC;
    wrapper->base.slot = PARK_SLOT_CONNECTION;
    /* The factory owns the inner handle from here on. */
    wrapper->inner = request->inner;
    ovc_abi_free(request->kind.ptr);
    ovc_abi_free(request->instance_id.ptr);
    ovc_abi_free(request->config.ptr);
    out->state = wrapper;
    out->vtable = &g_park_wrapper_vtable;
    gate_signal(&g_created);
    return OvStoragePlugin_FFI_STATUS_OK;
}

/* --- parking router ------------------------------------------------------ */

/* The router owns the child handles the factory hands it. */
typedef struct {
    OvStoragePlugin_LayerHandle *children;
    size_t child_count;
} ParkRouterState;

static void park_router_drop(void *state)
{
    ParkRouterState *router;
    size_t index;

    router = (ParkRouterState *)state;
    for (index = 0; index < router->child_count; ++index) {
        OvStoragePlugin_LayerHandle *child;

        child = &router->children[index];
        if (child->vtable != NULL && child->vtable->drop != NULL) {
            child->vtable->drop(child->state);
        }
    }
    free(router->children);
    free(router);
    gate_signal(&g_dropped);
}

static OvStoragePlugin_FfiStatus park_create_router(
    void *plugin_state,
    const OvStoragePlugin_CreateRouterRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    ParkRouterState *router;
    size_t index;

    (void)plugin_state;
    *error = NULL;
    router = (ParkRouterState *)malloc(sizeof(*router));
    if (router == NULL) {
        park_fail("out of memory creating the parking router");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    router->child_count = request->child_count;
    router->children = (OvStoragePlugin_LayerHandle *)malloc(
        (router->child_count == 0 ? 1 : router->child_count) *
        sizeof(*router->children));
    if (router->children == NULL) {
        park_fail("out of memory adopting the router children");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    /* The factory owns every child handle from here on. */
    for (index = 0; index < router->child_count; ++index) {
        router->children[index] = request->children[index].handle;
    }
    ovc_abi_free(request->kind.ptr);
    ovc_abi_free(request->instance_id.ptr);
    ovc_abi_free(request->config.ptr);
    out->state = router;
    out->vtable = &g_park_router_vtable;
    gate_signal(&g_created);
    return OvStoragePlugin_FFI_STATUS_OK;
}

static void park_create_backend_request_clear(
    OvStoragePlugin_CreateBackendRequest *request)
{
    ovc_abi_free(request->kind.ptr);
    ovc_abi_free(request->instance_id.ptr);
    ovc_abi_free(request->config.ptr);
    memset(request, 0, sizeof(*request));
}

static OvStoragePlugin_FfiStatus park_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **error)
{
    OvStoragePlugin_CreateBackendRequest moved;
    ParkLayerState *state;
    ParkSlot slot;

    static const struct {
        const char *instance;
        ParkSlot slot;
    } behaviours[] = {
        {PARK_INSTANCE_CONNECTION, PARK_SLOT_CONNECTION},
        {PARK_INSTANCE_ROOTS, PARK_SLOT_ROOTS},
        {PARK_INSTANCE_PROMPT, PARK_SLOT_NONE},
        {PARK_INSTANCE_ERROR, PARK_SLOT_ERROR},
        {PARK_INSTANCE_TWICE, PARK_SLOT_TWICE},
        {PARK_INSTANCE_SELFCANCEL, PARK_SLOT_SELFCANCEL},
    };
    size_t index;

    (void)plugin_state;
    *error = NULL;
    /* The instance name selects the behaviour; take it before the moved
     * request's buffers are released. */
    slot = PARK_SLOT_NONE;
    for (index = 0; index < sizeof(behaviours) / sizeof(behaviours[0]);
         ++index) {
        size_t length;

        length = strlen(behaviours[index].instance);
        if (request->instance_id.len == length &&
            memcmp(request->instance_id.ptr, behaviours[index].instance,
                   length) == 0) {
            slot = behaviours[index].slot;
            break;
        }
    }
    moved = *request;
    park_create_backend_request_clear(&moved);
    state = (ParkLayerState *)malloc(sizeof(*state));
    if (state == NULL) {
        memset(out, 0, sizeof(*out));
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    state->magic = PARK_LAYER_MAGIC;
    state->slot = slot;
    out->state = state;
    out->vtable = &g_park_layer_vtable;
    gate_signal(&g_created);
    return OvStoragePlugin_FFI_STATUS_OK;
}

static void park_plugin_drop(void *plugin_state)
{
    (void)plugin_state;
}

static const OvStoragePlugin_PluginVTableV1 g_park_plugin_vtable = {
    .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = park_plugin_drop,
    .create_backend = park_create_backend,
    .create_wrapper = park_create_wrapper,
    .create_router = park_create_router,
};

static const OvStoragePlugin_LayerKindDescriptor g_park_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Backend,
    .accepts_connections = true,
    .kind = {g_park_kind, sizeof(g_park_kind) - 1},
    .display_name = {g_park_display_name, sizeof(g_park_display_name) - 1},
    .auth_capable = false,
};

static const OvStoragePlugin_LayerKindDescriptor g_park_wrapper_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Wrapper,
    .accepts_connections = true,
    .kind = {g_park_wrapper_kind, sizeof(g_park_wrapper_kind) - 1},
    .display_name = {g_park_wrapper_display_name,
                     sizeof(g_park_wrapper_display_name) - 1},
    .auth_capable = false,
};

static const OvStoragePlugin_LayerKindDescriptor g_park_router_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Router,
    .accepts_connections = false,
    .kind = {g_park_router_kind, sizeof(g_park_router_kind) - 1},
    .display_name = {g_park_router_display_name,
                     sizeof(g_park_router_display_name) - 1},
    .auth_capable = false,
};

/* --- build completion ---------------------------------------------------- */

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int done;
    int fire_count;
    OvStorage_Status status;
    OvStorage_LayerHandle *handle;
    /* Static, process-lifetime per the code-name contract. */
    const char *code_name;
} BuildCompletion;

static void build_completion_init(BuildCompletion *completion)
{
    memset(completion, 0, sizeof(*completion));
    park_check(pthread_mutex_init(&completion->mutex, NULL),
               "completion mutex init");
    park_check(pthread_cond_init(&completion->changed, NULL),
               "completion cond init");
    completion->status = OvStorage_Status_Internal;
}

static void build_completion_destroy(BuildCompletion *completion)
{
    (void)pthread_cond_destroy(&completion->changed);
    (void)pthread_mutex_destroy(&completion->mutex);
}

static void on_build(OvStorage_Status status,
                     OvStorage_LayerHandle *handle,
                     const OvStorage_Error *error,
                     void *user_data)
{
    BuildCompletion *completion = (BuildCompletion *)user_data;

    park_check(pthread_mutex_lock(&completion->mutex), "completion lock");
    ++completion->fire_count;
    completion->status = status;
    completion->handle = handle;
    completion->code_name = ovstorage_error_code_name(error);
    completion->done = 1;
    park_check(pthread_cond_broadcast(&completion->changed),
               "completion broadcast");
    park_check(pthread_mutex_unlock(&completion->mutex), "completion unlock");
}

static void build_completion_wait(BuildCompletion *completion)
{
    park_check(pthread_mutex_lock(&completion->mutex), "completion lock");
    while (!completion->done) {
        park_check(pthread_cond_wait(&completion->changed,
                                     &completion->mutex),
                   "completion wait");
    }
    park_check(pthread_mutex_unlock(&completion->mutex), "completion unlock");
}

static int build_completion_is_done(BuildCompletion *completion)
{
    int done;

    park_check(pthread_mutex_lock(&completion->mutex), "completion lock");
    done = completion->done;
    park_check(pthread_mutex_unlock(&completion->mutex), "completion unlock");
    return done;
}

/* --- composition --------------------------------------------------------- */

/* Record the connection whose `add_connection` the named layer implements,
 * then root the Stack there. */
static void park_finish_connection_stack(OvStorage_Stack *stack,
                                         const char *instance,
                                         const char *kind)
{
    OvStorage_ConnectionRequest *request;
    OvStorage_Error error = {0};

    request = ovstorage_connection_request_create(kind);
    if (request == NULL) {
        park_fail("failed to create the parking connection request");
    }
    if (ovstorage_stack_add_connection(stack, instance, &request, &error) !=
        OvStorage_Status_Ok) {
        park_fail("failed to record the parking connection");
    }
    if (ovstorage_stack_set_root(stack, instance, &error) !=
        OvStorage_Status_Ok) {
        park_fail("failed to set the stack root");
    }
}

/* A one-layer Stack rooted at a parking backend, with the single recorded
 * connection whose add_connection the named instance implements. */
static OvStorage_Stack *park_backend_stack_create(
    const OvStorage_Registry *registry,
    const char *instance)
{
    OvStorage_Stack *stack;
    OvStorage_Error error = {0};

    stack = ovstorage_stack_create();
    if (stack == NULL) {
        park_fail("failed to create a Stack builder");
        return NULL;
    }
    if (ovstorage_stack_add_layer(stack, registry, instance, g_park_kind,
                                  &error) != OvStorage_Status_Ok) {
        park_fail("failed to declare the parking layer");
    }
    park_finish_connection_stack(stack, instance, g_park_kind);
    return stack;
}

static OvStorage_Stack *park_connection_stack_create(
    const OvStorage_Registry *registry)
{
    return park_backend_stack_create(registry, PARK_INSTANCE_CONNECTION);
}

static OvStorage_Stack *park_error_stack_create(
    const OvStorage_Registry *registry)
{
    return park_backend_stack_create(registry, PARK_INSTANCE_ERROR);
}

static OvStorage_Stack *park_twice_stack_create(
    const OvStorage_Registry *registry)
{
    return park_backend_stack_create(registry, PARK_INSTANCE_TWICE);
}

static OvStorage_Stack *park_selfcancel_stack_create(
    const OvStorage_Registry *registry)
{
    return park_backend_stack_create(registry, PARK_INSTANCE_SELFCANCEL);
}

/*
 * A parking wrapper over an inner backend from the SEPARATE companion plugin.
 *
 * The wrapper adopts that foreign Layer before its own `add_connection` parks,
 * so abandoning this build quarantines a subtree spanning two plugins. Nothing
 * but the quarantine keeps the inner plugin's registration alive once the
 * Stack and registry are gone, and its Layer reads that plugin's state when it
 * is finally dropped.
 */
static OvStorage_Stack *park_foreign_inner_stack_create(
    const OvStorage_Registry *registry)
{
    OvStorage_Stack *stack;
    OvStorage_Error error = {0};

    stack = ovstorage_stack_create();
    if (stack == NULL) {
        park_fail("failed to create a Stack builder");
        return NULL;
    }
    if (ovstorage_stack_add_layer(stack, registry, "inner", g_inner_kind,
                                  &error) != OvStorage_Status_Ok) {
        park_fail("failed to declare the foreign inner layer");
    }
    if (ovstorage_stack_add_layer(stack, registry, PARK_INSTANCE_CONNECTION,
                                  g_park_wrapper_kind, &error) !=
        OvStorage_Status_Ok) {
        park_fail("failed to declare the parking wrapper");
    }
    if (ovstorage_stack_set_inner(stack, PARK_INSTANCE_CONNECTION, "inner",
                                  &error) != OvStorage_Status_Ok) {
        park_fail("failed to record the wrapper's inner layer");
    }
    park_finish_connection_stack(stack, PARK_INSTANCE_CONNECTION,
                                 g_park_wrapper_kind);
    return stack;
}

/*
 * A router over two connection-less children: the first answers root
 * discovery inline, the second parks in it. Root validation therefore reaches
 * a parked `list_address_roots` with a live sibling child handle already
 * copied into the router's pending child array.
 */
static OvStorage_Stack *park_router_stack_create(
    const OvStorage_Registry *registry)
{
    static const char *const children[] = {PARK_INSTANCE_PROMPT,
                                           PARK_INSTANCE_ROOTS};
    const size_t child_count = sizeof(children) / sizeof(children[0]);
    OvStorage_Stack *stack;
    OvStorage_Error error = {0};
    size_t index;

    stack = ovstorage_stack_create();
    if (stack == NULL) {
        park_fail("failed to create a Stack builder");
        return NULL;
    }
    for (index = 0; index < child_count; ++index) {
        if (ovstorage_stack_add_layer(stack, registry, children[index],
                                      g_park_kind, &error) !=
            OvStorage_Status_Ok) {
            park_fail("failed to declare a router child");
        }
    }
    if (ovstorage_stack_add_layer(stack, registry, "router",
                                  g_park_router_kind, &error) !=
        OvStorage_Status_Ok) {
        park_fail("failed to declare the parking router");
    }
    if (ovstorage_stack_set_children(stack, "router", children, child_count,
                                     &error) != OvStorage_Status_Ok) {
        park_fail("failed to record the router children");
    }
    if (ovstorage_stack_set_root(stack, "router", &error) !=
        OvStorage_Status_Ok) {
        park_fail("failed to set the stack root");
    }
    return stack;
}

typedef OvStorage_Stack *(*StackFactory)(const OvStorage_Registry *);

/* Leg (a): cancel a build parked in a Layer that ignores its token. */
static void run_abandon_while_parked(const OvStorage_Registry *registry,
                                     StackFactory compose,
                                     unsigned long generation)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Stack *stack;
    OvStorage_CancelToken *cancel;

    build_completion_init(&completion);
    stack = compose(registry);
    cancel = ovstorage_cancel_token_create();
    if (cancel == NULL) {
        park_fail("failed to create the cancel token");
    }

    ovstorage_stack_build_async(stack, &options, cancel, on_build,
                               &completion);
    gate_wait(&g_arrived, generation);
    if (build_completion_is_done(&completion)) {
        park_fail("the parked build completed before it was cancelled");
    }

    ovstorage_cancel_token_cancel(cancel);
    /* Without an abandonable wait this never returns. */
    build_completion_wait(&completion);

    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Cancelled ||
        completion.handle != NULL) {
        fprintf(stderr,
                "a cancelled parked build fired %d time(s) with status %d "
                "instead of exactly one Cancelled fire\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }
    if (completion.code_name == NULL ||
        strcmp(completion.code_name, "Cancelled") != 0) {
        fprintf(stderr,
                "the cancelled parked build's code name was %s instead of "
                "Cancelled\n",
                completion.code_name == NULL ? "(null)"
                                             : completion.code_name);
        exit(EXIT_FAILURE);
    }

    /* The contract allows the builder to go once on_complete has fired, so
     * release the Layer only afterwards: its completion lands in a build
     * whose builder, build thread, and cancel token are all gone. */
    ovstorage_stack_destroy(stack);
    ovstorage_cancel_token_destroy(cancel);
    gate_signal(&g_released);
    gate_wait(&g_completed, generation);
    build_completion_destroy(&completion);
}

/* Leg (b): release the same parked build and let it commit. */
static void run_release_while_parked(const OvStorage_Registry *registry,
                                     StackFactory compose,
                                     unsigned long generation)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Stack *stack;

    build_completion_init(&completion);
    stack = compose(registry);

    ovstorage_stack_build_async(stack, &options, NULL, on_build, &completion);
    gate_wait(&g_arrived, generation);
    if (build_completion_is_done(&completion)) {
        park_fail("the parked build completed before it was released");
    }
    gate_signal(&g_released);
    build_completion_wait(&completion);
    gate_wait(&g_completed, generation);

    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Ok ||
        completion.handle == NULL) {
        fprintf(stderr,
                "a released parked build fired %d time(s) with status %d "
                "instead of exactly one Ok fire\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }
    /* Success consumed the builder; only the handle needs releasing. */
    ovstorage_layer_handle_destroy(completion.handle);
    build_completion_destroy(&completion);
}

/*
 * Leg (d): a Layer that cancels the build and completes SUCCESSFULLY, both
 * inside the vtable call, so the outcome is recorded before the build thread
 * ever waits.
 *
 * That forces the completion-first branch deterministically: the wait finds
 * the outcome and returns it, and the post-wait re-check is what turns the
 * build into `Cancelled` and reclaims the Connection nobody accepted. The
 * abandon-first branch is the one legs (a)/(c) take, so the two are covered
 * separately rather than left to the scheduler.
 */
static void run_completion_before_wait(const OvStorage_Registry *registry,
                                       StackFactory compose)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Stack *stack;
    OvStorage_CancelToken *cancel;

    build_completion_init(&completion);
    stack = compose(registry);
    cancel = ovstorage_cancel_token_create();
    if (cancel == NULL) {
        park_fail("failed to create the cancel token");
    }
    g_self_cancel = cancel;

    ovstorage_stack_build_async(stack, &options, cancel, on_build,
                               &completion);
    build_completion_wait(&completion);
    g_self_cancel = NULL;

    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Cancelled ||
        completion.handle != NULL) {
        fprintf(stderr,
                "a build cancelled by its own layer fired %d time(s) with "
                "status %d instead of exactly one Cancelled fire\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }
    ovstorage_stack_destroy(stack);
    ovstorage_cancel_token_destroy(cancel);
    build_completion_destroy(&completion);
}

/*
 * Leg (g): release a parked Layer that completes with a plugin ERROR.
 *
 * The build must surface it as a failure, which is the path that consumes the
 * delivered error; its abandoned twin (leg (a) over the same composition)
 * leaves the same error for the slot's reclaimer instead.
 */
static void run_release_with_error(const OvStorage_Registry *registry,
                                   unsigned long generation)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Stack *stack;

    build_completion_init(&completion);
    stack = park_error_stack_create(registry);

    ovstorage_stack_build_async(stack, &options, NULL, on_build, &completion);
    gate_wait(&g_arrived, generation);
    gate_signal(&g_released);
    build_completion_wait(&completion);
    gate_wait(&g_completed, generation);

    if (completion.fire_count != 1 ||
        completion.status == OvStorage_Status_Ok ||
        completion.handle != NULL) {
        fprintf(stderr,
                "a build whose layer reported an error fired %d time(s) with "
                "status %d instead of exactly one failure\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }
    ovstorage_stack_destroy(stack);
    build_completion_destroy(&completion);
}

/*
 * Leg (e): a Layer that fires its completion twice inside the vtable call.
 *
 * The build thread's reference is still alive for the repeat, so the host must
 * keep the first outcome, reclaim the second payload, and release exactly
 * once — the build still commits normally.
 */
static void run_duplicate_completion(const OvStorage_Registry *registry,
                                     StackFactory compose)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Stack *stack;

    build_completion_init(&completion);
    stack = compose(registry);

    ovstorage_stack_build_async(stack, &options, NULL, on_build, &completion);
    build_completion_wait(&completion);

    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Ok ||
        completion.handle == NULL) {
        fprintf(stderr,
                "a build whose layer completed twice fired %d time(s) with "
                "status %d instead of exactly one Ok fire\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }
    ovstorage_layer_handle_destroy(completion.handle);
    build_completion_destroy(&completion);
}

/*
 * Leg (c): the parked Layer cancels the build itself and then completes
 * SUCCESSFULLY from its own thread, so the recorded outcome and the wakeup
 * race each other. The final status is `Cancelled` on either branch; the value
 * here is the interleaving, not the branch — legs (a) and (d) pin each branch
 * deterministically.
 */
static void run_completion_races_cancel(const OvStorage_Registry *registry,
                                        StackFactory compose,
                                        unsigned long generation)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Stack *stack;
    OvStorage_CancelToken *cancel;

    build_completion_init(&completion);
    stack = compose(registry);
    cancel = ovstorage_cancel_token_create();
    if (cancel == NULL) {
        park_fail("failed to create the cancel token");
    }
    g_self_cancel = cancel;

    ovstorage_stack_build_async(stack, &options, cancel, on_build,
                               &completion);
    gate_wait(&g_arrived, generation);
    gate_signal(&g_released);
    build_completion_wait(&completion);
    gate_wait(&g_completed, generation);
    g_self_cancel = NULL;

    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Cancelled ||
        completion.handle != NULL) {
        fprintf(stderr,
                "a self-cancelled build fired %d time(s) with status %d "
                "instead of exactly one Cancelled fire\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }
    ovstorage_stack_destroy(stack);
    ovstorage_cancel_token_destroy(cancel);
    build_completion_destroy(&completion);
}

/* Register the kinds this driver implements itself into `registry`. */
static void park_register_builtin_kinds(OvStorage_Registry *registry)
{
    static const OvStoragePlugin_LayerKindDescriptor *const descriptors[] = {
        &g_park_descriptor, &g_park_wrapper_descriptor,
        &g_park_router_descriptor};
    OvStorage_Error error = {0};
    size_t index;

    for (index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]);
         ++index) {
        if (ovc_registry_register_builtin_kind(registry,
                                               descriptors[index],
                                               &g_park_plugin_state,
                                               &g_park_plugin_vtable,
                                               &error) !=
            OvStorage_Status_Ok) {
            park_fail("failed to register a parking kind");
        }
    }
    ovstorage_error_clear(&error);
}

/*
 * Leg (f): abandon a build whose quarantined subtree spans two plugins.
 *
 * This leg owns its registry so every host-side reference to the companion
 * plugin can be dropped while its Layer is still inside the quarantine. If the
 * quarantine retained only the outstanding Layer's own factory, the inner
 * plugin's registration would go with the registry, `plugin_vtable->drop`
 * would free its state, and the inner Layer's own drop would read it back
 * after the abandoned call finally completed.
 */
static void run_foreign_inner_abandon(const char *fixture_path,
                                      unsigned long generation)
{
    OvStorage_StackBuildOptions options = {0};
    BuildCompletion completion;
    OvStorage_Registry *registry;
    OvStorage_Plugin *plugin;
    OvStorage_Stack *stack;
    OvStorage_CancelToken *cancel;
    OvStorage_Error error = {0};

    build_completion_init(&completion);

    registry = ovstorage_registry_create();
    if (registry == NULL) {
        park_fail("failed to create the registry");
    }
    park_register_builtin_kinds(registry);
    if (ovstorage_load_plugin(fixture_path, true, &plugin, &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr,
                "failed to load the companion plugin at %s: %s\n",
                fixture_path,
                error.message == NULL ? "(null)" : error.message);
        exit(EXIT_FAILURE);
    }
    if (ovstorage_registry_add_plugin(registry, plugin, &error) !=
        OvStorage_Status_Ok) {
        park_fail("failed to register the companion plugin");
    }
    /* The registry cloned the factories it needs. */
    ovstorage_plugin_destroy(plugin);

    stack = park_foreign_inner_stack_create(registry);
    cancel = ovstorage_cancel_token_create();
    if (cancel == NULL) {
        park_fail("failed to create the cancel token");
    }
    ovstorage_stack_build_async(stack, &options, cancel, on_build,
                               &completion);
    gate_wait(&g_arrived, generation);
    if (build_completion_is_done(&completion)) {
        park_fail("the parked build completed before it was cancelled");
    }
    ovstorage_cancel_token_cancel(cancel);
    build_completion_wait(&completion);

    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Cancelled ||
        completion.handle != NULL) {
        fprintf(stderr,
                "a cancelled cross-plugin build fired %d time(s) with status "
                "%d instead of exactly one Cancelled fire\n",
                completion.fire_count,
                (int)completion.status);
        exit(EXIT_FAILURE);
    }

    /* Every host-side reference to the companion plugin goes here, before its
     * Layer is released: from now on only the quarantine holds it. */
    ovstorage_stack_destroy(stack);
    ovstorage_registry_destroy(registry);
    ovstorage_cancel_token_destroy(cancel);

    gate_signal(&g_released);
    gate_wait(&g_completed, generation);
    build_completion_destroy(&completion);
    ovstorage_error_clear(&error);
}

int main(int argc, char **argv)
{
    static const StackFactory parked[] = {park_connection_stack_create,
                                          park_router_stack_create};
    const char *fixture_path;
    OvStorage_Registry *registry;
    unsigned long generation;
    size_t at;
    int iteration;

    if (argc < 2) {
        park_fail("usage: stack_build_abandon_repro <companion-plugin-path>");
        return EXIT_FAILURE;
    }
    fixture_path = argv[1];

    g_park_layer_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    g_park_layer_vtable.drop = park_layer_drop;
    g_park_layer_vtable.add_connection = park_add_connection;
    g_park_layer_vtable.list_address_roots = park_list_address_roots;
    g_park_wrapper_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    g_park_wrapper_vtable.drop = park_wrapper_drop;
    g_park_wrapper_vtable.add_connection = park_wrapper_add_connection;
    g_park_router_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    g_park_router_vtable.drop = park_router_drop;

    gate_init(&g_arrived);
    gate_init(&g_released);
    gate_init(&g_completed);
    gate_init(&g_created);
    gate_init(&g_dropped);

    registry = ovstorage_registry_create();
    if (registry == NULL) {
        park_fail("failed to create the registry");
    }
    park_register_builtin_kinds(registry);

    /* Every abandonable slot and every outcome shape, repeated: the reference
     * counts are only interesting under repetition. */
    generation = 0;
    for (iteration = 0; iteration < PARK_ITERATIONS; ++iteration) {
        for (at = 0; at < sizeof(parked) / sizeof(parked[0]); ++at) {
            run_abandon_while_parked(registry, parked[at], ++generation);
            run_release_while_parked(registry, parked[at], ++generation);
            run_completion_races_cancel(registry, parked[at], ++generation);
        }
        /* A pending ERROR outcome, abandoned then released, so both the
         * slot's reclaimer and the build's failure path see one. */
        run_abandon_while_parked(registry, park_error_stack_create,
                                 ++generation);
        run_release_with_error(registry, ++generation);
        run_completion_before_wait(registry, park_selfcancel_stack_create);
        run_duplicate_completion(registry, park_twice_stack_create);
        run_foreign_inner_abandon(fixture_path, ++generation);
    }

    /* Every abandoned Layer must eventually be released; a fix that lost one
     * would hang here rather than pass. */
    gate_wait(&g_dropped, gate_next_generation(&g_created) - 1);

    ovstorage_registry_destroy(registry);
    gate_destroy(&g_dropped);
    gate_destroy(&g_created);
    gate_destroy(&g_completed);
    gate_destroy(&g_released);
    gate_destroy(&g_arrived);
    return EXIT_SUCCESS;
}
