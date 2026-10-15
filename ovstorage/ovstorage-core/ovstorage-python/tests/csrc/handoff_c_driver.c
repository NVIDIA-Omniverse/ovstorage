/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Genuine C driver for the cross-language live handoff.
 *
 * This translation unit is compiled by the C compiler into a *standalone*
 * `.so` (see `tools/ovtasks/_test_plugins.py`) that links nothing from the
 * ovstorage runtime — it only `#include`s `ovstorage_plugin.h` for the ABI-v2
 * types. `pytest` `ctypes`-loads it `RTLD_LOCAL` and hands it an
 * `OvStoragePlugin_LayerHandle` that a *Python* producer exported, so the
 * matrix's Python->C leg genuinely runs C-compiled code in a separate image
 * consuming a Python-produced handle through raw vtable calls.
 *
 * The single entry point `ovsx_drive_exported_handle` drives a representative
 * span of the handoff crossing surface against baked-in addresses (the
 * producer under test seeds `handoff://data/...`): `stat`, buffered `read`, a
 * streamed `read` drained one chunk then early-dropped, `write`, `list`, the
 * async `list_connections` introspection slot, a full `CancelTokenFFI`
 * round trip (a live token threaded through every op, plus the pre-canceled
 * synchronous-callback path), and finally the vtable `drop` slot. Observations
 * are stashed in file statics that the auxiliary getters below expose so the
 * pytest can assert the bytes genuinely crossed rather than merely that the
 * call returned 0.
 *
 * Memory: results handed to `on_complete` are owned by this receiver, but a
 * header-only consumer has no access to the `ovstorage_plugin_*_free` fns, so
 * buffered payloads are intentionally leaked — the pytest process is
 * short-lived and this leg is not run under a sanitizer (the ASan/LSan leg is
 * the C<->C contract). Streams are the exception: their `drop_fn` releases a
 * live producer-side bridge task and is always invoked.
 */

#include <ovstorage_plugin.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Observations + last-error reporting                                 */
/* ------------------------------------------------------------------ */

static char ovsx_error_buf[256];
static int ovsx_stage_value;
static unsigned long long ovsx_stat_size_value;
static unsigned long ovsx_read_len_value;
static unsigned char ovsx_read_head_buf[128];
static unsigned long ovsx_read_head_len;
static unsigned long ovsx_stream_chunk_len_value;
static int ovsx_was_stream_value;
static unsigned long long ovsx_write_size_value;
static unsigned long ovsx_list_count_value;
static unsigned long ovsx_conn_count_value;

static void ovsx_fail(int stage, const char *msg)
{
    ovsx_stage_value = stage;
    snprintf(ovsx_error_buf, sizeof(ovsx_error_buf), "stage %d: %s", stage, msg);
}

/* Copy a producer-owned Error's message into the reporting buffer. */
static void ovsx_fail_from_error(int stage, const OvStoragePlugin_Error *error)
{
    if (error != NULL && error->message_ptr != NULL && error->message_len > 0) {
        size_t len = error->message_len;
        if (len >= sizeof(ovsx_error_buf) - 32) {
            len = sizeof(ovsx_error_buf) - 32;
        }
        ovsx_stage_value = stage;
        snprintf(ovsx_error_buf, sizeof(ovsx_error_buf), "stage %d: code %d: %.*s", stage,
                 (int)error->code, (int)len, error->message_ptr);
    } else {
        ovsx_fail(stage, "operation returned an error");
    }
}

/* ------------------------------------------------------------------ */
/* Host-supplied cancellation token (the consumer owns this ABI)       */
/* ------------------------------------------------------------------ */

/*
 * The host mints the `CancelTokenFFI` and the producer consumes it:
 * `cancel_token_from_ffi` (ovstorage-plugin) `clone`s the state, then
 * `register_callback`s a waker (which fires synchronously and returns 0 when
 * the token is already canceled), and on task exit `unregister_callback`s and
 * `drop`s its clone. So a correct host token is a refcounted, thread-safe
 * atomic flag with a small callback list — implemented here in pure C.
 */

struct ovsx_cb_node {
    uint64_t id;
    void (*cb)(void *);
    void *user_data;
    struct ovsx_cb_node *next;
};

struct ovsx_cancel_state {
    _Atomic int refcount;
    _Atomic int canceled;
    pthread_mutex_t mu;
    uint64_t next_id;
    struct ovsx_cb_node *callbacks;
};

/* cbindgen emits the shared state as an opaque incomplete type; the vtable fn
 * pointers take it by `const` pointer, so round-trip through the opaque type. */
typedef const OvStoragePlugin_AtomicCancelState *ovsx_opaque;

static struct ovsx_cancel_state *ovsx_state_of(ovsx_opaque opaque)
{
    return (struct ovsx_cancel_state *)(void *)(uintptr_t)opaque;
}

static ovsx_opaque ovsx_opaque_of(struct ovsx_cancel_state *state)
{
    return (ovsx_opaque)(void *)state;
}

static bool ovsx_is_canceled(ovsx_opaque opaque)
{
    return atomic_load(&ovsx_state_of(opaque)->canceled) != 0;
}

static uint64_t ovsx_register_callback(ovsx_opaque opaque, void (*cb)(void *), void *user_data)
{
    struct ovsx_cancel_state *state = ovsx_state_of(opaque);
    /* Already canceled: fire synchronously and report "no subscription" (0). */
    if (atomic_load(&state->canceled) != 0) {
        cb(user_data);
        return 0;
    }
    struct ovsx_cb_node *node = (struct ovsx_cb_node *)malloc(sizeof(*node));
    if (node == NULL) {
        return 0;
    }
    pthread_mutex_lock(&state->mu);
    /* Re-check under the lock so a cancel racing the registration still fires. */
    if (atomic_load(&state->canceled) != 0) {
        pthread_mutex_unlock(&state->mu);
        free(node);
        cb(user_data);
        return 0;
    }
    uint64_t id = ++state->next_id;
    node->id = id;
    node->cb = cb;
    node->user_data = user_data;
    node->next = state->callbacks;
    state->callbacks = node;
    pthread_mutex_unlock(&state->mu);
    return id;
}

static void ovsx_unregister_callback(ovsx_opaque opaque, uint64_t sub_id)
{
    struct ovsx_cancel_state *state = ovsx_state_of(opaque);
    if (sub_id == 0) {
        return;
    }
    pthread_mutex_lock(&state->mu);
    struct ovsx_cb_node **link = &state->callbacks;
    while (*link != NULL) {
        if ((*link)->id == sub_id) {
            struct ovsx_cb_node *dead = *link;
            *link = dead->next;
            free(dead);
            break;
        }
        link = &(*link)->next;
    }
    pthread_mutex_unlock(&state->mu);
}

static ovsx_opaque ovsx_clone(ovsx_opaque opaque)
{
    struct ovsx_cancel_state *state = ovsx_state_of(opaque);
    atomic_fetch_add(&state->refcount, 1);
    return opaque;
}

static void ovsx_drop(ovsx_opaque opaque)
{
    struct ovsx_cancel_state *state = ovsx_state_of(opaque);
    if (atomic_fetch_sub(&state->refcount, 1) == 1) {
        /* Last reference: reclaim any still-registered callback nodes. */
        struct ovsx_cb_node *node = state->callbacks;
        while (node != NULL) {
            struct ovsx_cb_node *next = node->next;
            free(node);
            node = next;
        }
        pthread_mutex_destroy(&state->mu);
        free(state);
    }
}

static OvStoragePlugin_CancelTokenFFI ovsx_token_new(struct ovsx_cancel_state **out_state)
{
    struct ovsx_cancel_state *state = (struct ovsx_cancel_state *)malloc(sizeof(*state));
    atomic_init(&state->refcount, 1);
    atomic_init(&state->canceled, 0);
    pthread_mutex_init(&state->mu, NULL);
    state->next_id = 0;
    state->callbacks = NULL;
    *out_state = state;

    OvStoragePlugin_CancelTokenFFI token;
    token.state = ovsx_opaque_of(state);
    token.is_canceled = ovsx_is_canceled;
    token.register_callback = ovsx_register_callback;
    token.unregister_callback = ovsx_unregister_callback;
    token.clone = ovsx_clone;
    token.drop = ovsx_drop;
    return token;
}

/* Set canceled and fire every registered callback (drains the list). */
static void ovsx_token_cancel(struct ovsx_cancel_state *state)
{
    pthread_mutex_lock(&state->mu);
    atomic_store(&state->canceled, 1);
    struct ovsx_cb_node *node = state->callbacks;
    state->callbacks = NULL;
    pthread_mutex_unlock(&state->mu);
    while (node != NULL) {
        struct ovsx_cb_node *next = node->next;
        node->cb(node->user_data);
        free(node);
        node = next;
    }
}

/* ------------------------------------------------------------------ */
/* Async completion latch for OnComplete                               */
/* ------------------------------------------------------------------ */

struct ovsx_completion {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool done;
    int32_t status;
    void *result;
    OvStoragePlugin_Error *error;
};

static void ovsx_completion_init(struct ovsx_completion *c)
{
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    c->done = false;
    c->status = 0;
    c->result = NULL;
    c->error = NULL;
}

static void ovsx_completion_destroy(struct ovsx_completion *c)
{
    pthread_cond_destroy(&c->cv);
    pthread_mutex_destroy(&c->mu);
}

/* `OvStoragePlugin_OnComplete`: fires exactly once, from a producer runtime
 * thread, after the vtable slot returns. */
static void ovsx_on_complete(int32_t status, void *result, OvStoragePlugin_Error *error,
                             void *user_data)
{
    struct ovsx_completion *c = (struct ovsx_completion *)user_data;
    pthread_mutex_lock(&c->mu);
    c->status = status;
    c->result = result;
    c->error = error;
    c->done = true;
    pthread_cond_signal(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void ovsx_completion_wait(struct ovsx_completion *c)
{
    pthread_mutex_lock(&c->mu);
    while (!c->done) {
        pthread_cond_wait(&c->cv, &c->mu);
    }
    pthread_mutex_unlock(&c->mu);
}

/* ------------------------------------------------------------------ */
/* Request builders                                                    */
/* ------------------------------------------------------------------ */

/*
 * Build an owned request `Str`. Request payloads flow host->plugin and are
 * *consumed* by the plugin: after decoding the request the plugin drops each
 * `Str`/`Bytes`, which frees `ptr` via the shared ABI allocator (`Vec<u8>` ==
 * malloc/free on POSIX, `cap == len`, or a 1-byte sentinel for the empty
 * string). So the host must hand over a fresh `malloc`ed buffer of exactly
 * `len` bytes (never a static or stack buffer) and must NOT free it itself.
 */
static OvStoragePlugin_Str ovsx_str(const char *s)
{
    size_t len = strlen(s);
    size_t cap = len == 0 ? 1 : len;
    char *buf = (char *)malloc(cap);
    if (len > 0) {
        memcpy(buf, s, len);
    }
    OvStoragePlugin_Str out;
    out.ptr = buf;
    out.len = len;
    return out;
}

/* Owned request `Bytes`, same allocator/ownership contract as `ovsx_str`. */
static OvStoragePlugin_Bytes ovsx_bytes(const unsigned char *data, size_t len)
{
    size_t cap = len == 0 ? 1 : len;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (len > 0) {
        memcpy(buf, data, len);
    }
    OvStoragePlugin_Bytes out;
    out.ptr = buf;
    out.len = len;
    return out;
}

/* Baked-in addresses: the producer under test (a Python leaf on an OwnedLoop,
 * or the all-Rust HandoffBackend for standalone validation) seeds these. */
#define OVSX_OBJECT "handoff://data/a.bin"
#define OVSX_STREAM "handoff://data/a.bin/stream"
#define OVSX_PREFIX "handoff://data/"
#define OVSX_WRITE "handoff://data/written"

static const unsigned char OVSX_WRITE_PAYLOAD[] = "written-by-the-c-driver";

/* ------------------------------------------------------------------ */
/* Driver                                                              */
/* ------------------------------------------------------------------ */

/*
 * Drive a representative span of the crossing surface, then drop the handle.
 * Returns 0 on success or a negative stage number on the first failure (see
 * `ovsx_last_stage` / `ovsx_last_error`). Never returns without invoking the
 * vtable `drop` slot so the producer-side reference is always released.
 */
int ovsx_drive_exported_handle(const OvStoragePlugin_LayerHandle *handle)
{
    ovsx_stage_value = 0;
    ovsx_error_buf[0] = '\0';

    if (handle == NULL || handle->state == NULL || handle->vtable == NULL) {
        ovsx_fail(1, "null handle, state, or vtable");
        return -1;
    }
    const OvStoragePlugin_LayerVTableV1 *vt = handle->vtable;
    void *state = handle->state;
    int rc = 0;

    /* A live token threaded through the object ops (normal clone/register/
     * unregister/drop flow). */
    struct ovsx_cancel_state *live_state = NULL;
    OvStoragePlugin_CancelTokenFFI live = ovsx_token_new(&live_state);

    /* --- stage 2: stat --- */
    {
        OvStoragePlugin_StatRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;
        req.address = ovsx_str(OVSX_OBJECT);
        req.options.struct_size = sizeof(req.options);
        req.options.full_metadata = false;

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->stat(state, &req, &live, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        if (c.status != 0 || c.result == NULL) {
            ovsx_fail_from_error(2, c.error);
            ovsx_completion_destroy(&c);
            rc = -2;
            goto done;
        }
        OvStoragePlugin_ObjectInfo *info = (OvStoragePlugin_ObjectInfo *)c.result;
        ovsx_stat_size_value = info->size.present ? info->size.value : 0;
        ovsx_completion_destroy(&c);
    }

    /* --- stage 3: buffered read --- */
    {
        OvStoragePlugin_ReadRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;
        req.address = ovsx_str(OVSX_OBJECT);
        req.options.struct_size = sizeof(req.options);

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->read(state, &req, &live, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        if (c.status != 0 || c.result == NULL) {
            ovsx_fail_from_error(3, c.error);
            ovsx_completion_destroy(&c);
            rc = -3;
            goto done;
        }
        OvStoragePlugin_ReadResult *read = (OvStoragePlugin_ReadResult *)c.result;
        if (read->tag != OvStoragePlugin_ReadResultTag_Bytes) {
            ovsx_fail(3, "buffered read did not return Bytes");
            ovsx_completion_destroy(&c);
            rc = -3;
            goto done;
        }
        OvStoragePlugin_Bytes b = read->bytes.bytes;
        ovsx_read_len_value = (unsigned long)b.len;
        ovsx_read_head_len = b.len < sizeof(ovsx_read_head_buf) ? b.len : sizeof(ovsx_read_head_buf);
        if (b.ptr != NULL && ovsx_read_head_len > 0) {
            memcpy(ovsx_read_head_buf, b.ptr, ovsx_read_head_len);
        }
        ovsx_completion_destroy(&c);
    }

    /* --- stage 4: streamed read, pull one chunk, then early-drop --- */
    {
        OvStoragePlugin_ReadRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;
        req.address = ovsx_str(OVSX_STREAM);
        req.options.struct_size = sizeof(req.options);

        /* A dedicated token so cancelling it can't disturb the ops above. */
        struct ovsx_cancel_state *stream_state = NULL;
        OvStoragePlugin_CancelTokenFFI stream_tok = ovsx_token_new(&stream_state);

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->read(state, &req, &stream_tok, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        if (c.status != 0 || c.result == NULL) {
            ovsx_fail_from_error(4, c.error);
            ovsx_completion_destroy(&c);
            stream_tok.drop(stream_tok.state);
            rc = -4;
            goto done;
        }
        OvStoragePlugin_ReadResult *read = (OvStoragePlugin_ReadResult *)c.result;
        if (read->tag != OvStoragePlugin_ReadResultTag_Stream) {
            ovsx_fail(4, "streamed read did not return Stream");
            ovsx_completion_destroy(&c);
            stream_tok.drop(stream_tok.state);
            rc = -4;
            goto done;
        }
        ovsx_was_stream_value = 1;
        OvStoragePlugin_BodyStream body = read->stream.stream;
        OvStoragePlugin_Bytes chunk;
        OvStoragePlugin_Error chunk_err;
        memset(&chunk, 0, sizeof(chunk));
        memset(&chunk_err, 0, sizeof(chunk_err));
        OvStoragePlugin_StreamStep step = body.next_fn(body.state, &chunk, &chunk_err);
        if (step == OvStoragePlugin_StreamStep_Yielded) {
            ovsx_stream_chunk_len_value = (unsigned long)chunk.len;
        } else if (step == OvStoragePlugin_StreamStep_Failed) {
            ovsx_fail_from_error(4, &chunk_err);
            body.drop_fn(body.state);
            ovsx_completion_destroy(&c);
            stream_tok.drop(stream_tok.state);
            rc = -4;
            goto done;
        }
        /* Cancel mid-stream and early-drop without draining: the drop_fn must
         * release the producer-side bridge task cleanly. */
        ovsx_token_cancel(stream_state);
        body.drop_fn(body.state);
        ovsx_completion_destroy(&c);
        stream_tok.drop(stream_tok.state);
    }

    /* --- stage 5: write --- */
    {
        OvStoragePlugin_WriteRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;
        req.address = ovsx_str(OVSX_WRITE);
        req.body.tag = OvStoragePlugin_BodyTag_Bytes;
        req.body.bytes = ovsx_bytes(OVSX_WRITE_PAYLOAD, sizeof(OVSX_WRITE_PAYLOAD) - 1);
        req.options.struct_size = sizeof(req.options);
        req.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->write(state, &req, &live, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        if (c.status != 0 || c.result == NULL) {
            ovsx_fail_from_error(5, c.error);
            ovsx_completion_destroy(&c);
            rc = -5;
            goto done;
        }
        OvStoragePlugin_WriteResult *wr = (OvStoragePlugin_WriteResult *)c.result;
        ovsx_write_size_value = wr->info.size.present ? wr->info.size.value : 0;
        ovsx_completion_destroy(&c);
    }

    /* --- stage 6: list --- */
    {
        OvStoragePlugin_ListRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;
        req.prefix = ovsx_str(OVSX_PREFIX);
        req.options.struct_size = sizeof(req.options);
        req.options.recursive = true;

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->list(state, &req, &live, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        if (c.status != 0 || c.result == NULL) {
            ovsx_fail_from_error(6, c.error);
            ovsx_completion_destroy(&c);
            rc = -6;
            goto done;
        }
        OvStoragePlugin_ListPage *page = (OvStoragePlugin_ListPage *)c.result;
        ovsx_list_count_value = (unsigned long)page->items.len;
        ovsx_completion_destroy(&c);
    }

    /* --- stage 7: list_connections (async runtime-state introspection slot) --- */
    {
        OvStoragePlugin_ListConnectionsRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->list_connections(state, &req, &live, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        if (c.status != 0 || c.result == NULL) {
            ovsx_fail_from_error(7, c.error);
            ovsx_completion_destroy(&c);
            rc = -7;
            goto done;
        }
        OvStoragePlugin_ListConnectionsResult *lc =
            (OvStoragePlugin_ListConnectionsResult *)c.result;
        ovsx_conn_count_value = (unsigned long)lc->snapshot.connections.len;
        if (lc->updates != NULL) {
            /* An update stream came back; we snapshot only, so release it. */
            /* The stream is a heap ConnectionChangeStream; its drop_fn frees
             * the plugin-owned iterator state. We cannot free the heap boxes
             * (the stream box and the result envelope) header-only, so leak
             * them (benign, one-shot). */
            lc->updates->drop_fn(lc->updates->state);
        }
        ovsx_completion_destroy(&c);
    }

    /* --- stage 8: pre-canceled token exercises the synchronous callback path
     * (register fires immediately, returns sub_id 0). The op may complete or
     * report Cancelled; both prove the token ABI crossed without a crash. --- */
    {
        struct ovsx_cancel_state *pc_state = NULL;
        OvStoragePlugin_CancelTokenFFI pc = ovsx_token_new(&pc_state);
        ovsx_token_cancel(pc_state);

        OvStoragePlugin_StatRequest req;
        memset(&req, 0, sizeof(req));
        req.struct_size = sizeof(req);
        req.extensions = NULL;
        req.address = ovsx_str(OVSX_OBJECT);
        req.options.struct_size = sizeof(req.options);

        struct ovsx_completion c;
        ovsx_completion_init(&c);
        vt->stat(state, &req, &pc, ovsx_on_complete, &c);
        ovsx_completion_wait(&c);
        ovsx_completion_destroy(&c);
        pc.drop(pc.state);
    }

done:
    live.drop(live.state);
    /* Always release the producer-side reference. */
    vt->drop(handle->state);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Auxiliary getters (read by the pytest via ctypes)                   */
/* ------------------------------------------------------------------ */

const char *ovsx_last_error(void)
{
    return ovsx_error_buf;
}

int ovsx_last_stage(void)
{
    return ovsx_stage_value;
}

unsigned long long ovsx_stat_size(void)
{
    return ovsx_stat_size_value;
}

unsigned long ovsx_read_len(void)
{
    return ovsx_read_len_value;
}

/* Copy up to `cap` observed read bytes into `out`; returns the count copied. */
unsigned long ovsx_read_head(char *out, unsigned long cap)
{
    unsigned long n = ovsx_read_head_len < cap ? ovsx_read_head_len : cap;
    if (out != NULL && n > 0) {
        memcpy(out, ovsx_read_head_buf, n);
    }
    return n;
}

int ovsx_was_stream(void)
{
    return ovsx_was_stream_value;
}

unsigned long ovsx_stream_chunk_len(void)
{
    return ovsx_stream_chunk_len_value;
}

unsigned long long ovsx_write_size(void)
{
    return ovsx_write_size_value;
}

unsigned long ovsx_list_count(void)
{
    return ovsx_list_count_value;
}

unsigned long ovsx_conn_count(void)
{
    return ovsx_conn_count_value;
}
