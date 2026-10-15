/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * A Layer whose only implemented slot emits one DeviceCode auth event and
 * then parks until released, so a test can observe an interactive auth event
 * WHILE the flow is still running.
 *
 * That ordering is the whole point of incremental delivery and it cannot be
 * observed through a composed Stack: the built-in `file` backend answers
 * Unsupported with zero events, and no auth-emitting Layer is reachable as a
 * factory `kind`. It IS reachable through the handoff verbs — this file mints
 * an ordinary plugin-ABI `LayerHandle`, which `ovstorage_import_handle` turns
 * into a public `OvStorage_LayerHandle*` the same way it does for a cdylib's.
 *
 * Written in C, next to the other stub Layers, because minting the event
 * needs the ABI allocator from `internal.h` (the dispatcher reclaims the
 * stream block and every string it carries with `ovc_abi_free`). The C++
 * consumer imports the root and drives it through the shipped wrapper.
 *
 * Single-use per export: one flow at a time, reset by re-exporting.
 *
 * Every wait here is BOUNDED. The regressions this fixture exists to catch
 * are "the worker never got here" and "the observer never fired", and an
 * unbounded wait turns either into a wedged test binary that fails only when
 * the CI job times out, with nothing said about why. A bounded wait that
 * reports its own timeout is the difference between a diagnosis and a hang.
 */

/* Generous enough that a loaded CI runner never trips it, short enough that a
 * genuine wedge is reported rather than waited out. */
#define OVC_AUTH_STUB_TIMEOUT_NS UINT64_C(30000000000) /* 30s */

#include "ovstorage_plugin.h"

#include "../../../../ovstorage-c-source/src/internal.h"

#include "ovstorage_defaults.h"

#include <assert.h>
#include <string.h>

#define OVC_AUTH_STUB_USER_CODE "WDJB-MJHT"
#define OVC_AUTH_STUB_URL "https://example.invalid/device"

typedef struct {
    ovc_mutex mutex;
    ovc_cond changed;
    int emitted;  /* the DeviceCode event has been yielded */
    int released; /* the test has allowed the flow to terminate */
} AuthStubGate;

static AuthStubGate g_gate;
static OvStoragePlugin_LayerVTableV1 g_vtable;
static int g_initialized;

static void gate_reset(void)
{
    assert(ovc_mutex_lock(&g_gate.mutex) == 0);
    g_gate.emitted = 0;
    g_gate.released = 0;
    assert(ovc_mutex_unlock(&g_gate.mutex) == 0);
}

static void gate_signal_emitted(void)
{
    assert(ovc_mutex_lock(&g_gate.mutex) == 0);
    g_gate.emitted = 1;
    assert(ovc_cond_broadcast(&g_gate.changed) == 0);
    assert(ovc_mutex_unlock(&g_gate.mutex) == 0);
}

/* Park the emitting slot until the test releases it. Bounded: a test that
 * fails an assertion before releasing must not strand a runtime thread here
 * for the life of the process. */
static void gate_wait_released(void)
{
    int status = 0;

    assert(ovc_mutex_lock(&g_gate.mutex) == 0);
    while (!g_gate.released && status == 0) {
        status = ovc_cond_timedwait_ns(&g_gate.changed,
                                       &g_gate.mutex,
                                       OVC_AUTH_STUB_TIMEOUT_NS);
    }
    assert(ovc_mutex_unlock(&g_gate.mutex) == 0);
}

/* Copy a NUL-terminated literal into an ABI-allocated Str the dispatcher
 * reclaims. The trailing NUL is deliberately not copied: Str is a
 * pointer/length pair. */
static void abi_str(OvStoragePlugin_Str *out, const char *text)
{
    size_t length = strlen(text);
    char *copy = (char *)ovc_abi_alloc(length);

    assert(copy != NULL);
    memcpy(copy, text, length);
    out->ptr = copy;
    out->len = length;
}

static OvStoragePlugin_StreamStep auth_stub_next(
    void *opaque,
    OvStoragePlugin_AuthEvent *out_event,
    OvStoragePlugin_Error *out_error)
{
    int *yielded = (int *)opaque;

    (void)out_error;
    if (*yielded) {
        /* Park until the test releases us, so the observer's sighting of the
         * event above is provably mid-flight rather than after the fact. */
        gate_wait_released();
        return OvStoragePlugin_StreamStep_Ended;
    }
    *yielded = 1;
    memset(out_event, 0, sizeof(*out_event));
    out_event->tag = OvStoragePlugin_AuthEventTag_DeviceCode;
    abi_str(&out_event->device_code.user_code, OVC_AUTH_STUB_USER_CODE);
    abi_str(&out_event->device_code.verification_url, OVC_AUTH_STUB_URL);
    out_event->device_code.expires_at_unix_ms = 1000;
    out_event->device_code.interval_ms = 5;
    gate_signal_emitted();
    return OvStoragePlugin_StreamStep_Yielded;
}

static void auth_stub_drop_stream(void *opaque)
{
    ovc_abi_free(opaque);
}

static void auth_stub_authenticate(
    void *opaque,
    const OvStoragePlugin_AuthenticateRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_AuthEventStream *stream;
    int *yielded;

    (void)opaque;
    (void)cancel;
    if (request != NULL) {
        /* The dispatcher mints these with `ovc_abi_alloc`, so they must go
         * back through `ovc_abi_free`. CRT `free()` happens to work on
         * POSIX, where both are malloc/free, and is an invalid free on
         * Win32, where the ABI heap is the process heap. */
        ovc_abi_free(request->key.target.ptr);
        ovc_abi_free(request->key.id.ptr);
    }
    yielded = (int *)ovc_abi_alloc(sizeof(*yielded));
    assert(yielded != NULL);
    *yielded = 0;
    /* ABI mint: the dispatcher reclaims this outer block with ovc_abi_free
     * in ovc_dispatch_auth_stream_reclaim. */
    stream = (OvStoragePlugin_AuthEventStream *)ovc_abi_alloc(sizeof(*stream));
    assert(stream != NULL);
    memset(stream, 0, sizeof(*stream));
    stream->state = yielded;
    stream->next_fn = auth_stub_next;
    stream->drop_fn = auth_stub_drop_stream;
    on_complete(OvStoragePlugin_FFI_STATUS_OK, stream, NULL, user_data);
}

static void auth_stub_drop_layer(void *opaque)
{
    (void)opaque;
}

/* Mint a root whose authenticate_connection slot emits one DeviceCode event
 * and then parks. Resets the gate, so each export starts a fresh flow. */
OvStoragePlugin_LayerHandle ovstorage_c_source_auth_stub_root(void);

OvStoragePlugin_LayerHandle ovstorage_c_source_auth_stub_root(void)
{
    OvStoragePlugin_LayerHandle root;

    if (!g_initialized) {
        assert(ovc_mutex_init(&g_gate.mutex) == 0);
        assert(ovc_cond_init(&g_gate.changed) == 0);
        g_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
        g_vtable.drop = auth_stub_drop_layer;
        g_vtable.authenticate_connection = auth_stub_authenticate;
        g_initialized = 1;
    }
    gate_reset();
    root.state = &g_vtable; /* stateless: any non-NULL owned pointer */
    root.vtable = &g_vtable;
    return root;
}

/* Block until the stub has yielded its DeviceCode event. Returns 1 when it
 * did and 0 on timeout — a timeout means the flow never reached the slot,
 * which the caller reports rather than waiting out. */
int ovstorage_c_source_auth_stub_wait_emitted(void);

int ovstorage_c_source_auth_stub_wait_emitted(void)
{
    int status = 0;
    int emitted;

    assert(ovc_mutex_lock(&g_gate.mutex) == 0);
    while (!g_gate.emitted && status == 0) {
        status = ovc_cond_timedwait_ns(&g_gate.changed,
                                       &g_gate.mutex,
                                       OVC_AUTH_STUB_TIMEOUT_NS);
    }
    emitted = g_gate.emitted;
    assert(ovc_mutex_unlock(&g_gate.mutex) == 0);
    return emitted;
}

/* Let the parked flow terminate. */
void ovstorage_c_source_auth_stub_release(void);

void ovstorage_c_source_auth_stub_release(void)
{
    assert(ovc_mutex_lock(&g_gate.mutex) == 0);
    g_gate.released = 1;
    assert(ovc_cond_broadcast(&g_gate.changed) == 0);
    assert(ovc_mutex_unlock(&g_gate.mutex) == 0);
}

/* The user code and URL the stub emits, for the consumer's assertions. */
const char *ovstorage_c_source_auth_stub_user_code(void);

const char *ovstorage_c_source_auth_stub_user_code(void)
{
    return OVC_AUTH_STUB_USER_CODE;
}

const char *ovstorage_c_source_auth_stub_verification_url(void);

const char *ovstorage_c_source_auth_stub_verification_url(void)
{
    return OVC_AUTH_STUB_URL;
}
