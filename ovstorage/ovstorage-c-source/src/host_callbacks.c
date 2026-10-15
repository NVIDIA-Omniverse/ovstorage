/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Process-global plugin host callbacks and the durable pure-C auth substrate.
 */

#include "internal.h"

#include "temp_dir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

typedef struct ovc_host_refresh_entry ovc_host_refresh_entry;

#if defined(_MSC_VER)
#define OVC_HOST_THREAD_LOCAL __declspec(thread)
#define OVC_HOST_HAS_THREAD_LOCAL 1
#elif defined(__GNUC__) || defined(__clang__)
#define OVC_HOST_THREAD_LOCAL __thread
#define OVC_HOST_HAS_THREAD_LOCAL 1
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define OVC_HOST_THREAD_LOCAL _Thread_local
#define OVC_HOST_HAS_THREAD_LOCAL 1
#else
#define OVC_HOST_HAS_THREAD_LOCAL 0
#endif

#define OVC_HOST_CALLBACKS_V1_SIZE                                      \
    (offsetof(OvStoragePlugin_HostCallbacks, log) +                     \
     sizeof(((OvStoragePlugin_HostCallbacks *)0)->log))

typedef struct ovc_host_slice {
    const char *ptr;
    size_t len;
} ovc_host_slice;

typedef struct ovc_host_key_view {
    ovc_host_slice backend_kind;
    ovc_host_slice connection_id;
    ovc_host_slice field;
} ovc_host_key_view;

struct ovc_host_refresh_entry {
    char *backend_kind;
    size_t backend_kind_len;
    char *connection_id;
    size_t connection_id_len;
    ovc_cond changed;
    int in_progress;
    int has_success;
    uint64_t last_success_ns;
    ovc_host_refresh_entry *next;
};

/* The address of this object is the callback-table identity token. */
static unsigned char g_ovc_host_state;

static ovc_mutex g_ovc_host_lifecycle_mutex = OVC_MUTEX_INITIALIZER;
static ovc_cond g_ovc_host_lifecycle_changed = OVC_COND_INITIALIZER;
static size_t g_ovc_host_active_callbacks;
static int g_ovc_host_closing;
static int g_ovc_host_cleaned;

#if OVC_HOST_HAS_THREAD_LOCAL
static OVC_HOST_THREAD_LOCAL size_t g_ovc_host_callback_depth;
#endif

static ovc_mutex g_ovc_host_secret_mutex = OVC_MUTEX_INITIALIZER;
static ovc_cred_store *g_ovc_host_cred_store;

static ovc_mutex g_ovc_host_refresh_mutex = OVC_MUTEX_INITIALIZER;
static ovc_host_refresh_entry *g_ovc_host_refreshes;
static int g_ovc_host_refresh_closing;

static ovc_mutex g_ovc_host_init_mutex = OVC_MUTEX_INITIALIZER;
static char *g_ovc_host_auth_dir;
static char *g_ovc_host_credential_namespace;
static int g_ovc_host_cleanup_registered;

static ovc_mutex g_ovc_host_log_mutex = OVC_MUTEX_INITIALIZER;
static OvStorage_PluginLogLevel g_ovc_host_log_level =
    OvStorage_PluginLogLevel_Warn;
static OvStorage_PluginLogSink g_ovc_host_log_sink;
static void *g_ovc_host_log_sink_state;
static int g_ovc_host_log_sampled;

#if defined(OVC_HOST_CALLBACKS_TEST_MAIN) && defined(NDEBUG)
#error "OVC_HOST_CALLBACKS_TEST_MAIN requires assertions to be enabled"
#endif

static OvStoragePlugin_Error *ovc_host_secret_get(
    void *host_state,
    const OvStoragePlugin_SecretKey *key,
    OvStoragePlugin_Optional_SecretBytes *out_value);
static OvStoragePlugin_Error *ovc_host_secret_put(
    void *host_state,
    const OvStoragePlugin_SecretKey *key,
    const OvStoragePlugin_SecretBytes *value);
static OvStoragePlugin_Error *ovc_host_secret_delete(
    void *host_state,
    const OvStoragePlugin_SecretKey *key);
static OvStoragePlugin_Error *ovc_host_auth_refresh_lock(
    void *host_state,
    const OvStoragePlugin_Str *backend_kind,
    const OvStoragePlugin_ConnectionId *connection_id,
    uint64_t freshness_window_ms,
    void *refresh_state,
    OvStoragePlugin_HostRefreshFn refresh_fn);
static void ovc_host_log(void *host_state,
                         uint8_t level,
                         const OvStoragePlugin_Str *target,
                         const OvStoragePlugin_Str *message);
static void ovc_host_process_cleanup(void);

static const OvStoragePlugin_HostCallbacks g_ovc_host_callbacks = {
    .struct_size = OVC_HOST_CALLBACKS_V1_SIZE,
    .host_state = &g_ovc_host_state,
    .secret_get = ovc_host_secret_get,
    .secret_put = ovc_host_secret_put,
    .secret_delete = ovc_host_secret_delete,
    .auth_refresh_lock_with_refresh = ovc_host_auth_refresh_lock,
    .host_kind = UINT32_C(0), /* OvStoragePlugin_HostKindV1_Library */
    .log = ovc_host_log,
};

static void ovc_host_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

static void *ovc_host_allocate(size_t byte_count)
{
    return malloc(byte_count == 0 ? 1 : byte_count);
}

/*
 * Values adopted by the Rust plugin codec use the shared ABI allocator pair
 * (ovc_abi_alloc/ovc_abi_free in plat.c — malloc/free on POSIX and the
 * process heap on Win32).  Internal map/path allocations remain ordinary C
 * allocations.
 */

static void *ovc_host_copy_bytes(const void *bytes, size_t byte_count)
{
    unsigned char *copy;

    copy = (unsigned char *)ovc_host_allocate(byte_count);
    if (copy == NULL) {
        return NULL;
    }
    if (byte_count != 0) {
        memcpy(copy, bytes, byte_count);
    } else {
        copy[0] = 0;
    }
    return copy;
}

static char *ovc_host_duplicate_c_string(const char *value)
{
    size_t length;
    char *copy;

    length = strlen(value);
    if (length == SIZE_MAX) {
        errno = ENOMEM;
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, length + 1);
    return copy;
}

static OvStoragePlugin_Error *ovc_host_plugin_error(
    OvStoragePlugin_ErrorCode code,
    const char *message)
{
    OvStoragePlugin_Error *error;
    size_t message_len;

    message_len = strlen(message);
    error = (OvStoragePlugin_Error *)ovc_abi_alloc(sizeof(*error));
    if (error == NULL) {
        abort();
    }
    error->message_ptr =
        (char *)ovc_abi_copy_bytes(message, message_len);
    if (error->message_ptr == NULL) {
        ovc_abi_free(error);
        abort();
    }
    error->code = code;
    error->message_len = message_len;
    error->context = NULL;
    error->next_action.present = false;
    return error;
}

static OvStorage_Status ovc_host_public_result(OvStorage_Error *out_error,
                                                OvStorage_Status status,
                                                const char *message)
{
    if (out_error != NULL) {
        free(out_error->message);
        out_error->code = status;
        out_error->message = NULL;
        out_error->code_name = ovc_status_code_name(status);
        if (status != OvStorage_Status_Ok && message != NULL) {
            out_error->message = ovc_host_duplicate_c_string(message);
        }
    }
    return status;
}

static int ovc_host_utf8_valid(const char *value, size_t length)
{
    return ovc_utf8_is_valid(value, length);
}

static int ovc_host_slice_valid(const OvStoragePlugin_Str *value,
                                int require_nonempty,
                                ovc_host_slice *out_slice)
{
    if (value == NULL || value->ptr == NULL ||
        (require_nonempty && value->len == 0) ||
        !ovc_host_utf8_valid(value->ptr, value->len)) {
        return 0;
    }
    out_slice->ptr = value->ptr;
    out_slice->len = value->len;
    return 1;
}

static int ovc_host_key_view_from_ffi(
    const OvStoragePlugin_SecretKey *key,
    ovc_host_key_view *out_key)
{
    return key != NULL &&
           ovc_host_slice_valid(&key->backend_kind, 0,
                                &out_key->backend_kind) &&
           ovc_host_slice_valid(&key->connection_id.id, 1,
                                &out_key->connection_id) &&
           ovc_host_slice_valid(&key->field, 0, &out_key->field);
}

static int ovc_host_refresh_key_from_ffi(
    const OvStoragePlugin_Str *backend_kind,
    const OvStoragePlugin_ConnectionId *connection_id,
    ovc_host_slice *out_backend_kind,
    ovc_host_slice *out_connection_id)
{
    return connection_id != NULL &&
           ovc_host_slice_valid(backend_kind, 0, out_backend_kind) &&
           ovc_host_slice_valid(&connection_id->id, 1, out_connection_id);
}

static int ovc_host_slice_equal(const char *stored,
                                size_t stored_len,
                                ovc_host_slice value)
{
    return stored_len == value.len &&
           (stored_len == 0 || memcmp(stored, value.ptr, stored_len) == 0);
}

static int ovc_host_operation_enter(void)
{
    int entered;

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_lifecycle_mutex));
    entered = !g_ovc_host_closing &&
              g_ovc_host_active_callbacks != SIZE_MAX;
#if OVC_HOST_HAS_THREAD_LOCAL
    entered = entered && g_ovc_host_callback_depth != SIZE_MAX;
#endif
    if (entered) {
        ++g_ovc_host_active_callbacks;
#if OVC_HOST_HAS_THREAD_LOCAL
        ++g_ovc_host_callback_depth;
#endif
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_lifecycle_mutex));
    return entered;
}

static int ovc_host_callback_enter(void *host_state)
{
    return host_state == &g_ovc_host_state && ovc_host_operation_enter();
}

static void ovc_host_operation_leave(void)
{
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_lifecycle_mutex));
    if (g_ovc_host_active_callbacks == 0) {
        abort();
    }
#if OVC_HOST_HAS_THREAD_LOCAL
    if (g_ovc_host_callback_depth == 0) {
        abort();
    }
    --g_ovc_host_callback_depth;
#endif
    --g_ovc_host_active_callbacks;
    if (g_ovc_host_closing) {
        ovc_host_sync_success(
            ovc_cond_broadcast(&g_ovc_host_lifecycle_changed));
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_lifecycle_mutex));
}

static void ovc_host_callback_leave(void)
{
    ovc_host_operation_leave();
}

static OvStoragePlugin_Error *ovc_host_cred_error(
    const char *op,
    const ovc_cred_error *store_error)
{
    OvStoragePlugin_ErrorCode code;
    char message[sizeof(store_error->message) + 32];

    switch (store_error->status) {
    case OVC_CRED_UNAVAILABLE:
    case OVC_CRED_CORRUPT:
    case OVC_CRED_NEWER_FORMAT:
        code = OvStoragePlugin_ErrorCode_StateRootUnavailable;
        break;
    case OVC_CRED_LOCKED:
        code = OvStoragePlugin_ErrorCode_Transient;
        break;
    case OVC_CRED_INVALID:
        code = OvStoragePlugin_ErrorCode_InvalidArgument;
        break;
    case OVC_CRED_NOMEM:
        code = OvStoragePlugin_ErrorCode_ResourceExhausted;
        break;
    case OVC_CRED_OK:
    default:
        code = OvStoragePlugin_ErrorCode_Internal;
        break;
    }
    (void)snprintf(message,
                   sizeof(message),
                   "%s: %s",
                   op,
                   store_error->message);
    return ovc_host_plugin_error(code, message);
}

/* Called with g_ovc_host_secret_mutex held. */
static int ovc_host_cred_store_ensure_open(ovc_cred_error *store_error)
{
    char *auth_dir;
    char *credential_namespace;
    ovc_cred_store *store;
    int initialized;
    int opened;

    if (g_ovc_host_cred_store != NULL) {
        return 1;
    }

    auth_dir = NULL;
    credential_namespace = NULL;
    initialized = 0;
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_init_mutex));
    if (g_ovc_host_auth_dir != NULL &&
        g_ovc_host_credential_namespace != NULL) {
        initialized = 1;
        auth_dir = ovc_host_duplicate_c_string(g_ovc_host_auth_dir);
        if (auth_dir != NULL) {
            credential_namespace = ovc_host_duplicate_c_string(
                g_ovc_host_credential_namespace);
        }
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_init_mutex));

    if (!initialized) {
        store_error->status = OVC_CRED_INVALID;
        (void)snprintf(store_error->message,
                       sizeof(store_error->message),
                       "credential store substrate is not initialized");
        return 0;
    }
    if (auth_dir == NULL || credential_namespace == NULL) {
        free(credential_namespace);
        free(auth_dir);
        store_error->status = OVC_CRED_NOMEM;
        (void)snprintf(store_error->message,
                       sizeof(store_error->message),
                       "out of memory copying credential store settings");
        return 0;
    }

    store = NULL;
    opened = ovc_cred_store_open(auth_dir,
                                 credential_namespace,
                                 &store,
                                 store_error);
    free(credential_namespace);
    free(auth_dir);
    if (!opened) {
        return 0;
    }
    g_ovc_host_cred_store = store;
    return 1;
}

static void ovc_host_cred_record_from_view(
    const ovc_host_key_view *view,
    ovc_cred_record *record)
{
    memset(record, 0, sizeof(*record));
    record->backend_kind = (uint8_t *)(void *)view->backend_kind.ptr;
    record->backend_kind_len = view->backend_kind.len;
    record->connection_id = (uint8_t *)(void *)view->connection_id.ptr;
    record->connection_id_len = view->connection_id.len;
    record->field = (uint8_t *)(void *)view->field.ptr;
    record->field_len = view->field.len;
}

static OvStoragePlugin_Error *ovc_host_secret_get(
    void *host_state,
    const OvStoragePlugin_SecretKey *key,
    OvStoragePlugin_Optional_SecretBytes *out_value)
{
    ovc_host_key_view view;
    ovc_cred_record record;
    ovc_cred_error store_error;
    uint8_t *copy;
    size_t copy_len;
    int found;
    int succeeded;
    OvStoragePlugin_Error *error;

    if (!ovc_host_callback_enter(host_state)) {
        return ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_Internal,
            "host callback invoked with invalid or closing host state");
    }

    error = NULL;
    if (out_value == NULL) {
        error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "secret_get: out_value pointer is null");
        goto done;
    }
    memset(out_value, 0, sizeof(*out_value));
    if (!ovc_host_key_view_from_ffi(key, &view)) {
        error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "secret_get: key is null, malformed, or not UTF-8");
        goto done;
    }

    copy = NULL;
    copy_len = 0;
    found = 0;
    ovc_host_cred_record_from_view(&view, &record);
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_secret_mutex));
    succeeded = ovc_host_cred_store_ensure_open(&store_error) &&
                ovc_cred_store_get(g_ovc_host_cred_store,
                                   &record,
                                   &copy,
                                   &copy_len,
                                   &found,
                                   &store_error);
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_secret_mutex));

    if (!succeeded) {
        error = ovc_host_cred_error("secret_get", &store_error);
        goto done;
    }
    if (found) {
        out_value->present = true;
        out_value->value.bytes.ptr = copy;
        out_value->value.bytes.len = copy_len;
    }

done:
    ovc_host_callback_leave();
    return error;
}

static OvStoragePlugin_Error *ovc_host_secret_put(
    void *host_state,
    const OvStoragePlugin_SecretKey *key,
    const OvStoragePlugin_SecretBytes *value)
{
    ovc_host_key_view view;
    ovc_cred_record record;
    ovc_cred_error store_error;
    int succeeded;
    OvStoragePlugin_Error *error;

    if (!ovc_host_callback_enter(host_state)) {
        return ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_Internal,
            "host callback invoked with invalid or closing host state");
    }

    error = NULL;
    if (!ovc_host_key_view_from_ffi(key, &view)) {
        error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "secret_put: key is null, malformed, or not UTF-8");
        goto done;
    }
    if (value == NULL || value->bytes.ptr == NULL) {
        error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "secret_put: value pointer is null or malformed");
        goto done;
    }

    ovc_host_cred_record_from_view(&view, &record);
    record.value = value->bytes.ptr;
    record.value_len = value->bytes.len;
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_secret_mutex));
    succeeded = ovc_host_cred_store_ensure_open(&store_error) &&
                ovc_cred_store_put(g_ovc_host_cred_store,
                                   &record,
                                   &store_error);
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_secret_mutex));
    if (!succeeded) {
        error = ovc_host_cred_error("secret_put", &store_error);
    }

done:
    ovc_host_callback_leave();
    return error;
}

static OvStoragePlugin_Error *ovc_host_secret_delete(
    void *host_state,
    const OvStoragePlugin_SecretKey *key)
{
    ovc_host_key_view view;
    ovc_cred_record record;
    ovc_cred_error store_error;
    int succeeded;
    OvStoragePlugin_Error *error;

    if (!ovc_host_callback_enter(host_state)) {
        return ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_Internal,
            "host callback invoked with invalid or closing host state");
    }

    error = NULL;
    if (!ovc_host_key_view_from_ffi(key, &view)) {
        error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "secret_delete: key is null, malformed, or not UTF-8");
        goto done;
    }

    ovc_host_cred_record_from_view(&view, &record);
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_secret_mutex));
    succeeded = ovc_host_cred_store_ensure_open(&store_error) &&
                ovc_cred_store_delete(g_ovc_host_cred_store,
                                      &record,
                                      &store_error);
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_secret_mutex));
    if (!succeeded) {
        error = ovc_host_cred_error("secret_delete", &store_error);
    }

done:
    ovc_host_callback_leave();
    return error;
}

static ovc_host_refresh_entry *ovc_host_refresh_find(
    ovc_host_slice backend_kind,
    ovc_host_slice connection_id)
{
    ovc_host_refresh_entry *entry;

    for (entry = g_ovc_host_refreshes; entry != NULL; entry = entry->next) {
        if (ovc_host_slice_equal(entry->backend_kind,
                                 entry->backend_kind_len,
                                 backend_kind) &&
            ovc_host_slice_equal(entry->connection_id,
                                 entry->connection_id_len,
                                 connection_id)) {
            return entry;
        }
    }
    return NULL;
}

static void ovc_host_refresh_entry_destroy(ovc_host_refresh_entry *entry)
{
    if (entry == NULL) {
        return;
    }
    ovc_host_sync_success(ovc_cond_destroy(&entry->changed));
    free(entry->connection_id);
    free(entry->backend_kind);
    free(entry);
}

static ovc_host_refresh_entry *ovc_host_refresh_entry_create(
    ovc_host_slice backend_kind,
    ovc_host_slice connection_id)
{
    ovc_host_refresh_entry *entry;
    int result;

    entry = (ovc_host_refresh_entry *)calloc(1, sizeof(*entry));
    if (entry == NULL) {
        return NULL;
    }
    entry->backend_kind = (char *)ovc_host_copy_bytes(backend_kind.ptr,
                                                       backend_kind.len);
    entry->connection_id = (char *)ovc_host_copy_bytes(connection_id.ptr,
                                                        connection_id.len);
    if (entry->backend_kind == NULL || entry->connection_id == NULL) {
        free(entry->connection_id);
        free(entry->backend_kind);
        free(entry);
        return NULL;
    }
    entry->backend_kind_len = backend_kind.len;
    entry->connection_id_len = connection_id.len;
    result = ovc_cond_init(&entry->changed);
    if (result != 0) {
        free(entry->connection_id);
        free(entry->backend_kind);
        free(entry);
        errno = result;
        return NULL;
    }
    return entry;
}

static uint64_t ovc_host_freshness_ns(uint64_t freshness_window_ms)
{
    if (freshness_window_ms >
        UINT64_MAX / UINT64_C(1000000)) {
        return UINT64_MAX;
    }
    return freshness_window_ms * UINT64_C(1000000);
}

static int ovc_host_monotonic_now(uint64_t *out_now)
{
    uint64_t now;

    errno = 0;
    now = ovc_monotonic_ns();
    if (now == 0 && errno != 0) {
        return 0;
    }
    *out_now = now;
    return 1;
}

static int ovc_host_refresh_is_fresh(const ovc_host_refresh_entry *entry,
                                     uint64_t freshness_window_ns)
{
    uint64_t now;

    if (freshness_window_ns == 0 || !entry->has_success ||
        !ovc_host_monotonic_now(&now)) {
        return 0;
    }
    if (now < entry->last_success_ns) {
        return 1;
    }
    return now - entry->last_success_ns < freshness_window_ns;
}

static OvStoragePlugin_Error *ovc_host_auth_refresh_lock(
    void *host_state,
    const OvStoragePlugin_Str *backend_kind,
    const OvStoragePlugin_ConnectionId *connection_id,
    uint64_t freshness_window_ms,
    void *refresh_state,
    OvStoragePlugin_HostRefreshFn refresh_fn)
{
    ovc_host_slice backend_kind_view;
    ovc_host_slice connection_id_view;
    ovc_host_refresh_entry *candidate;
    ovc_host_refresh_entry *entry;
    OvStoragePlugin_Error *refresh_error;
    uint64_t freshness_window_ns;
    uint64_t refreshed_at;
    int have_refreshed_at;
    int wait_result;

    if (!ovc_host_callback_enter(host_state)) {
        return ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_Internal,
            "host callback invoked with invalid or closing host state");
    }
    if (!ovc_host_refresh_key_from_ffi(backend_kind,
                                       connection_id,
                                       &backend_kind_view,
                                       &connection_id_view) ||
        refresh_fn == NULL) {
        refresh_error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "auth refresh lock: key or refresh callback is malformed");
        ovc_host_callback_leave();
        return refresh_error;
    }

    freshness_window_ns = ovc_host_freshness_ns(freshness_window_ms);
    candidate = NULL;
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_refresh_mutex));
    if (g_ovc_host_refresh_closing) {
        refresh_error = ovc_host_plugin_error(
            OvStoragePlugin_ErrorCode_Internal,
            "auth refresh lock: auth substrate is shutting down");
        ovc_host_sync_success(
            ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
        ovc_host_callback_leave();
        return refresh_error;
    }
    entry = ovc_host_refresh_find(backend_kind_view, connection_id_view);
    if (entry == NULL) {
        ovc_host_sync_success(
            ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
        candidate = ovc_host_refresh_entry_create(backend_kind_view,
                                                  connection_id_view);
        if (candidate == NULL) {
            refresh_error = ovc_host_plugin_error(
                OvStoragePlugin_ErrorCode_ResourceExhausted,
                "auth refresh lock: failed to allocate lock state");
            ovc_host_callback_leave();
            return refresh_error;
        }
        ovc_host_sync_success(
            ovc_mutex_lock(&g_ovc_host_refresh_mutex));
        if (g_ovc_host_refresh_closing) {
            refresh_error = ovc_host_plugin_error(
                OvStoragePlugin_ErrorCode_Internal,
                "auth refresh lock: auth substrate is shutting down");
            ovc_host_sync_success(
                ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
            ovc_host_refresh_entry_destroy(candidate);
            ovc_host_callback_leave();
            return refresh_error;
        }
        entry = ovc_host_refresh_find(backend_kind_view,
                                      connection_id_view);
        if (entry == NULL) {
            entry = candidate;
            candidate = NULL;
            entry->next = g_ovc_host_refreshes;
            g_ovc_host_refreshes = entry;
        }
    }
    ovc_host_refresh_entry_destroy(candidate);

    for (;;) {
        if (g_ovc_host_refresh_closing) {
            refresh_error = ovc_host_plugin_error(
                OvStoragePlugin_ErrorCode_Internal,
                "auth refresh lock: auth substrate is shutting down");
            ovc_host_sync_success(
                ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
            ovc_host_callback_leave();
            return refresh_error;
        }
        if (entry->in_progress) {
            wait_result =
                ovc_cond_wait(&entry->changed, &g_ovc_host_refresh_mutex);
            if (wait_result != 0) {
                refresh_error = ovc_host_plugin_error(
                    OvStoragePlugin_ErrorCode_Internal,
                    "auth refresh lock: condition wait failed");
                ovc_host_sync_success(
                    ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
                ovc_host_callback_leave();
                return refresh_error;
            }
            continue;
        }
        if (ovc_host_refresh_is_fresh(entry, freshness_window_ns)) {
            ovc_host_sync_success(
                ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
            ovc_host_callback_leave();
            return NULL;
        }
        entry->in_progress = 1;
        break;
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_refresh_mutex));

    refresh_error = refresh_fn(refresh_state);
    refreshed_at = 0;
    have_refreshed_at = 0;
    if (refresh_error == NULL) {
        have_refreshed_at = ovc_host_monotonic_now(&refreshed_at);
    }

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_refresh_mutex));
    entry->in_progress = 0;
    if (refresh_error == NULL) {
        if (have_refreshed_at) {
            entry->last_success_ns = refreshed_at;
            entry->has_success = 1;
        } else {
            entry->has_success = 0;
        }
    }
    ovc_host_sync_success(ovc_cond_broadcast(&entry->changed));
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_refresh_mutex));

    ovc_host_callback_leave();
    return refresh_error;
}

static const char *ovc_host_log_level(uint8_t level)
{
    switch (level) {
    case 0:
        return "TRACE";
    case 1:
        return "DEBUG";
    case 3:
        return "WARN";
    case 4:
        return "ERROR";
    case 2:
    default:
        return "INFO";
    }
}

static OvStorage_PluginLogLevel ovc_host_log_normalize_level(uint8_t level)
{
    if (level <= (uint8_t)OvStorage_PluginLogLevel_Error) {
        return (OvStorage_PluginLogLevel)level;
    }
    /* A future producer level remains visible at the ordinary Info threshold. */
    return OvStorage_PluginLogLevel_Info;
}

static int ovc_host_log_ascii_equal(const char *value,
                                    size_t value_len,
                                    const char *expected)
{
    size_t index;

    if (value_len != strlen(expected)) {
        return 0;
    }
    for (index = 0; index < value_len; ++index) {
        unsigned char character;
        unsigned char expected_character;

        character = (unsigned char)value[index];
        expected_character = (unsigned char)expected[index];
        if (character >= 'A' && character <= 'Z') {
            character = (unsigned char)(character - 'A' + 'a');
        }
        if (character != expected_character) {
            return 0;
        }
    }
    return 1;
}

static int ovc_host_log_parse_level(const char *value,
                                    size_t value_len,
                                    OvStorage_PluginLogLevel *out_level)
{
    if (ovc_host_log_ascii_equal(value, value_len, "off") ||
        ovc_host_log_ascii_equal(value, value_len, "0")) {
        *out_level = (OvStorage_PluginLogLevel)5;
    } else if (ovc_host_log_ascii_equal(value, value_len, "trace") ||
               ovc_host_log_ascii_equal(value, value_len, "5")) {
        *out_level = OvStorage_PluginLogLevel_Trace;
    } else if (ovc_host_log_ascii_equal(value, value_len, "debug") ||
               ovc_host_log_ascii_equal(value, value_len, "4")) {
        *out_level = OvStorage_PluginLogLevel_Debug;
    } else if (ovc_host_log_ascii_equal(value, value_len, "info") ||
               ovc_host_log_ascii_equal(value, value_len, "3")) {
        *out_level = OvStorage_PluginLogLevel_Info;
    } else if (ovc_host_log_ascii_equal(value, value_len, "warn") ||
               ovc_host_log_ascii_equal(value, value_len, "2")) {
        *out_level = OvStorage_PluginLogLevel_Warn;
    } else if (ovc_host_log_ascii_equal(value, value_len, "error") ||
               ovc_host_log_ascii_equal(value, value_len, "1")) {
        *out_level = OvStorage_PluginLogLevel_Error;
    } else {
        return 0;
    }
    return 1;
}

static int ovc_host_log_target_valid(const char *value, size_t value_len)
{
    size_t index;

    if (value_len == 0) {
        return 0;
    }
    for (index = 0; index < value_len; ++index) {
        unsigned char character = (unsigned char)value[index];

        if (!(character >= 'a' && character <= 'z') &&
            !(character >= 'A' && character <= 'Z') &&
            !(character >= '0' && character <= '9') &&
            character != '_' && character != '-' && character != ':') {
            return 0;
        }
    }
    return 1;
}

static int ovc_host_log_env_level(const char *value,
                                  OvStorage_PluginLogLevel *out_level)
{
    const char *directive;
    OvStorage_PluginLogLevel result;
    int found;

    if (value == NULL) {
        return 0;
    }
    result = OvStorage_PluginLogLevel_Warn;
    found = 0;
    directive = value;
    for (;;) {
        const char *delimiter = directive;
        const char *end;
        const char *equals = NULL;
        OvStorage_PluginLogLevel level;

        while (*delimiter != '\0' && *delimiter != ',') {
            if (*delimiter == '=') {
                equals = delimiter;
            }
            ++delimiter;
        }
        end = delimiter;
        while (directive != end && (*directive == ' ' || *directive == '\t')) {
            ++directive;
        }
        while (end != directive && (end[-1] == ' ' || end[-1] == '\t')) {
            --end;
        }
        if (equals != NULL && (equals < directive || equals >= end)) {
            equals = NULL;
        }
        if (directive == end) {
            if (*delimiter == '\0') {
                break;
            }
            directive = delimiter + 1;
            continue;
        }
        if (equals == NULL) {
            if (!ovc_host_log_parse_level(directive, (size_t)(end - directive), &level)) {
                if (!ovc_host_log_target_valid(directive, (size_t)(end - directive))) {
                    return 0;
                }
                level = OvStorage_PluginLogLevel_Trace;
            }
        } else if (!ovc_host_log_target_valid(directive, (size_t)(equals - directive)) ||
                   !ovc_host_log_parse_level(equals + 1, (size_t)(end - equals - 1), &level)) {
            return 0;
        }
        if (!found || level < result) {
            result = level;
        }
        found = 1;

        if (*delimiter == '\0') {
            break;
        }
        directive = delimiter + 1;
    }
    if (found) {
        *out_level = result;
    }
    return found;
}

static OvStorage_PluginLogLevel ovc_host_log_fallback_level(void)
{
    char *value;
    OvStorage_PluginLogLevel level;

    value = ovc_env_dup("OVSTORAGE_LOG");
    if (ovc_host_log_env_level(value, &level)) {
        free(value);
        return level;
    }
    free(value);
    value = ovc_env_dup("RUST_LOG");
    if (ovc_host_log_env_level(value, &level)) {
        free(value);
        return level;
    }
    free(value);
    return OvStorage_PluginLogLevel_Warn;
}

static void ovc_host_log_slice(const OvStoragePlugin_Str *value,
                               const char *fallback)
{
    if (value == NULL || value->ptr == NULL) {
        (void)fputs(fallback, stderr);
    } else if (value->len != 0) {
        (void)fwrite(value->ptr, 1, value->len, stderr);
    }
}

static void ovc_host_log(void *host_state,
                         uint8_t level,
                         const OvStoragePlugin_Str *target,
                         const OvStoragePlugin_Str *message)
{
    OvStorage_PluginLogLevel normalized_level;

    if (!ovc_host_callback_enter(host_state)) {
        return;
    }
    normalized_level = ovc_host_log_normalize_level(level);
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_log_mutex));
    if (!g_ovc_host_log_sampled) {
        g_ovc_host_log_level = ovc_host_log_fallback_level();
        g_ovc_host_log_sampled = 1;
    }
    if (normalized_level < g_ovc_host_log_level) {
        ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_log_mutex));
        ovc_host_callback_leave();
        return;
    }
    if (g_ovc_host_log_sink != NULL) {
        g_ovc_host_log_sink(g_ovc_host_log_sink_state,
                            normalized_level,
                            target == NULL || target->ptr == NULL ? "plugin" : target->ptr,
                            target == NULL || target->ptr == NULL ? sizeof("plugin") - 1 : target->len,
                            message == NULL || message->ptr == NULL ? "<unreadable message>" : message->ptr,
                            message == NULL || message->ptr == NULL ? sizeof("<unreadable message>") - 1 : message->len);
        ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_log_mutex));
        ovc_host_callback_leave();
        return;
    }
    (void)fprintf(stderr, "ovstorage plugin [%s] ",
                  ovc_host_log_level(level));
    ovc_host_log_slice(target, "plugin");
    (void)fputs(": ", stderr);
    ovc_host_log_slice(message, "<unreadable message>");
    (void)fputc('\n', stderr);
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_log_mutex));
    ovc_host_callback_leave();
}

OvStorage_Status ovstorage_set_plugin_log_options(
    const OvStorage_PluginLogOptions *options,
    OvStorage_Error *out_error)
{
    if (options != NULL &&
        (options->level < OvStorage_PluginLogLevel_Trace ||
         options->level > OvStorage_PluginLogLevel_Error)) {
        return ovc_host_public_result(out_error,
                                      OvStorage_Status_InvalidArgument,
                                      "plugin log options have an invalid level");
    }
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_log_mutex));
    if (options == NULL) {
        g_ovc_host_log_sink = NULL;
        g_ovc_host_log_sink_state = NULL;
        g_ovc_host_log_level = ovc_host_log_fallback_level();
        g_ovc_host_log_sampled = 1;
    } else {
        g_ovc_host_log_level = options->level;
        g_ovc_host_log_sink = options->sink;
        g_ovc_host_log_sink_state = options->sink_state;
        g_ovc_host_log_sampled = 1;
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_log_mutex));
    return ovc_host_public_result(out_error, OvStorage_Status_Ok, NULL);
}

/* `name`'s value, but only when it is set, non-empty, absolute and UTF-8.
 *
 * The XDG base-directory spec requires an absolute path and says a relative
 * value must be ignored; it treats an empty value as unset. Honouring either
 * would put the auth directory somewhere that moves with the working
 * directory. LOCALAPPDATA gets the same treatment. */
static char *ovc_host_env_absolute_dup(const char *name)
{
    char *value;

    errno = 0;
    value = ovc_env_dup(name);
    if (value == NULL) {
        return NULL;
    }
    if (value[0] == '\0' || !ovc_path_is_absolute(value) ||
        !ovc_host_utf8_valid(value, strlen(value))) {
        free(value);
        return NULL;
    }
    return value;
}

/* The per-user data directory, or NULL when the environment names no home.
 *
 * Resolves the same variables in the same order as the Rust hosts'
 * `ovstorage::auth::default_state_root`, so a C embedder and a CLI running as
 * one OS user address one auth directory. The C credential store lives in
 * `c-credentials/` beside the Rust host's `auth.sqlite`; the directory is
 * shared, but their credential bytes and formats are not interoperable. */
static char *ovc_host_platform_data_dir(void)
{
#if defined(_WIN32)
    return ovc_host_env_absolute_dup("LOCALAPPDATA");
#elif defined(__APPLE__)
    char *home;
    char *library;
    char *result;

    home = ovc_host_env_absolute_dup("HOME");
    if (home == NULL) {
        return NULL;
    }
    library = ovc_path_join(home, "Library");
    free(home);
    if (library == NULL) {
        return NULL;
    }
    result = ovc_path_join(library, "Application Support");
    free(library);
    return result;
#else
    char *data;
    char *home;
    char *local;
    char *result;

    data = ovc_host_env_absolute_dup("XDG_DATA_HOME");
    if (data != NULL) {
        return data;
    }
    home = ovc_host_env_absolute_dup("HOME");
    if (home == NULL) {
        return NULL;
    }
    local = ovc_path_join(home, ".local");
    free(home);
    if (local == NULL) {
        return NULL;
    }
    result = ovc_path_join(local, "share");
    free(local);
    return result;
#endif
}

/* `<platform data dir>/ovstorage/auth`, or NULL when there is no data dir. */
static char *ovc_host_platform_auth_dir(void)
{
    char *base;
    char *scoped;
    char *result;

    base = ovc_host_platform_data_dir();
    if (base == NULL) {
        return NULL;
    }
    scoped = ovc_path_join(base, "ovstorage");
    free(base);
    if (scoped == NULL) {
        return NULL;
    }
    result = ovc_path_join(scoped, "auth");
    free(scoped);
    return result;
}

static OvStorage_Status ovc_host_default_auth_dir(char **out_path,
                                                   const char **out_message)
{
    char *configured;
    char *temp_root;
    char *scoped;
    char child[64];
    int child_length;

    errno = 0;
    configured = ovc_env_dup("OVSTORAGE_AUTH_DIR");
    if (configured == NULL && errno != 0) {
        *out_message = "failed to read OVSTORAGE_AUTH_DIR";
        return OvStorage_Status_Internal;
    }
    if (configured != NULL) {
        size_t length;

        length = strlen(configured);
        if (length == 0) {
            free(configured);
            *out_message = "OVSTORAGE_AUTH_DIR must not be empty";
            return OvStorage_Status_InvalidArgument;
        }
        if (!ovc_host_utf8_valid(configured, length)) {
            free(configured);
            *out_message = "OVSTORAGE_AUTH_DIR must be valid UTF-8";
            return OvStorage_Status_InvalidArgument;
        }
        /* Same rule as XDG_DATA_HOME and LOCALAPPDATA above: a relative value
         * would be re-resolved against the working directory on every open,
         * so a secret stored before a chdir would vanish after it and two
         * processes given the same value from different directories would
         * take different lock files. The shared predicate is the one that
         * knows Win32: `C:dir` (drive-relative) and `\dir` (root-relative)
         * both move with the working directory and are refused. */
        if (!ovc_path_is_absolute(configured)) {
            free(configured);
            *out_message = "OVSTORAGE_AUTH_DIR must be an absolute path";
            return OvStorage_Status_InvalidArgument;
        }
        *out_path = ovc_host_duplicate_c_string(configured);
        free(configured);
        if (*out_path == NULL) {
            *out_message = "failed to copy OVSTORAGE_AUTH_DIR";
            return OvStorage_Status_Internal;
        }
        return OvStorage_Status_Ok;
    }

    /* The durable per-user path, shared with every other host. Only when the
     * environment names no home at all does this fall back to a directory
     * under the shared temporary directory, scoped to the user id so two
     * accounts on one host do not collide -- and NOT to the process id, which
     * would evaporate on restart and, being recycled, would let a later
     * process adopt a dead one's state. The result is
     * `<temp>/ovstorage-<uid>/auth` on POSIX and `<temp>/ovstorage/auth` on
     * Windows: the same path the Rust resolver's `temp_fallback().join("auth")`
     * produces, so a C embedder and a CLI started without a home still
     * address one directory. */
    *out_path = ovc_host_platform_auth_dir();
    if (*out_path != NULL) {
        return OvStorage_Status_Ok;
    }

    temp_root = ovc_temp_root_dup();
#if defined(_WIN32)
    /* The Windows temporary directory is already per-user, so the plain name
     * is user-scoped there without a suffix. */
    child_length = snprintf(child, sizeof(child), "ovstorage");
#else
    /* GetTempPathW already yields UTF-8; only the POSIX $TMPDIR arm carries a
     * byte string the process never validated. */
    if (temp_root != NULL && !ovc_host_utf8_valid(temp_root,
                                                  strlen(temp_root))) {
        free(temp_root);
        *out_message = "the process temporary directory must be valid UTF-8";
        return OvStorage_Status_Internal;
    }
    child_length = snprintf(child,
                            sizeof(child),
                            "ovstorage-%lu",
                            (unsigned long)getuid());
#endif
    if (temp_root == NULL || child_length < 0 ||
        (size_t)child_length >= sizeof(child)) {
        free(temp_root);
        *out_message = "failed to resolve the process temporary directory";
        return OvStorage_Status_Internal;
    }
    scoped = ovc_path_join(temp_root, child);
    free(temp_root);
    if (scoped == NULL) {
        *out_message = "failed to resolve the process auth directory";
        return OvStorage_Status_Internal;
    }
    /* The `auth` leaf is what puts the C store beside the Rust hosts'
     * `auth.sqlite` in this arm too; without it the store lands one level
     * above where every Rust host looks. */
    *out_path = ovc_path_join(scoped, "auth");
    free(scoped);
    if (*out_path == NULL) {
        *out_message = "failed to resolve the process auth directory";
        return OvStorage_Status_Internal;
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_host_resolve_auth_dir(
    const char *explicit_auth_dir,
    char **out_path,
    const char **out_message)
{
    size_t length;

    *out_path = NULL;
    if (explicit_auth_dir == NULL) {
        return ovc_host_default_auth_dir(out_path, out_message);
    }
    length = strlen(explicit_auth_dir);
    if (length == 0) {
        *out_message = "auth_dir must not be empty";
        return OvStorage_Status_InvalidArgument;
    }
    if (!ovc_host_utf8_valid(explicit_auth_dir, length)) {
        *out_message = "auth_dir must be valid UTF-8";
        return OvStorage_Status_InvalidArgument;
    }
    /* The store keeps this string and re-opens paths under it for the life
     * of the process, so it must not move with the working directory. On
     * Win32 the shared predicate refuses drive-relative and root-relative
     * forms as well, which a bare `path[1] == ':'` check would admit. */
    if (!ovc_path_is_absolute(explicit_auth_dir)) {
        *out_message = "auth_dir must be an absolute path";
        return OvStorage_Status_InvalidArgument;
    }
    *out_path = ovc_host_duplicate_c_string(explicit_auth_dir);
    if (*out_path == NULL) {
        *out_message = "failed to copy auth_dir";
        return OvStorage_Status_Internal;
    }
    return OvStorage_Status_Ok;
}

static OvStorage_Status ovc_host_install_substrate(
    char *resolved_dir,
    char *resolved_namespace,
    int require_same,
    const char **out_message)
{
    OvStorage_Status status;

    status = OvStorage_Status_Ok;
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_init_mutex));
    if (g_ovc_host_auth_dir != NULL) {
        if (require_same &&
            (strcmp(g_ovc_host_auth_dir, resolved_dir) != 0 ||
             strcmp(g_ovc_host_credential_namespace,
                    resolved_namespace) != 0)) {
            status = OvStorage_Status_Unsupported;
            *out_message =
                "the process-global auth substrate is already pinned to a "
                "different auth_dir or credential_namespace";
        }
    } else {
        if (!g_ovc_host_cleanup_registered) {
            if (atexit(ovc_host_process_cleanup) != 0) {
                status = OvStorage_Status_Internal;
                *out_message = "failed to register auth substrate cleanup";
            } else {
                g_ovc_host_cleanup_registered = 1;
            }
        }
        if (status == OvStorage_Status_Ok) {
            g_ovc_host_auth_dir = resolved_dir;
            resolved_dir = NULL;
            g_ovc_host_credential_namespace = resolved_namespace;
            resolved_namespace = NULL;
        }
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_init_mutex));
    free(resolved_dir);
    free(resolved_namespace);
    return status;
}

OvStorage_Status ovstorage_init_auth_substrate(
    const OvStorage_InitAuthSubstrateOptions *options,
    OvStorage_Error *out_error)
{
    const char *explicit_auth_dir;
    const char *explicit_namespace;
    const char *message;
    char *resolved_dir;
    char *resolved_namespace;
    OvStorage_Status status;

    explicit_auth_dir = NULL;
    explicit_namespace = NULL;
    message = NULL;
    resolved_dir = NULL;
    resolved_namespace = NULL;
    status = OvStorage_Status_Ok;
    if (!ovc_host_operation_enter()) {
        return ovc_host_public_result(
            out_error,
            OvStorage_Status_Internal,
            "the process-global auth substrate is shutting down");
    }
    if (options != NULL) {
        /*
         * Pinning is one-shot and process-global.  An options struct that
         * names neither setting carries no request, so reject it rather than
         * pin the defaults on the caller's behalf and make their later
         * explicit call fail with Unsupported. Callers that want both
         * defaults pass options == NULL.
         */
        if (options->auth_dir == NULL &&
            options->credential_namespace == NULL) {
            status = OvStorage_Status_InvalidArgument;
            message =
                "init_auth_substrate options.auth_dir and "
                "options.credential_namespace must not both be NULL; "
                "pass options = NULL for the default auth_dir and "
                "credential_namespace";
            goto done;
        }
        explicit_auth_dir = options->auth_dir;
        explicit_namespace = options->credential_namespace;
    }

    if (explicit_namespace != NULL &&
        !ovc_cred_namespace_valid(explicit_namespace)) {
        status = OvStorage_Status_InvalidArgument;
        message =
            "credential_namespace must be 1-64 bytes of "
            "[A-Za-z0-9._-] and start with an ASCII alphanumeric character";
        goto done;
    }
    resolved_namespace = ovc_host_duplicate_c_string(
        explicit_namespace != NULL ? explicit_namespace : "default");
    if (resolved_namespace == NULL) {
        status = OvStorage_Status_Internal;
        message = "failed to copy credential_namespace";
        goto done;
    }

    status = ovc_host_resolve_auth_dir(explicit_auth_dir,
                                       &resolved_dir,
                                       &message);
    if (status == OvStorage_Status_Ok) {
        status = ovc_host_install_substrate(resolved_dir,
                                            resolved_namespace,
                                            1,
                                            &message);
        resolved_dir = NULL;
        resolved_namespace = NULL;
    }

done:
    free(resolved_dir);
    free(resolved_namespace);
    ovc_host_operation_leave();
    return ovc_host_public_result(out_error, status, message);
}

OvStorage_Status ovc_auth_substrate_auto_init(OvStorage_Error *out_error)
{
    const char *message;
    char *resolved_dir;
    char *resolved_namespace;
    OvStorage_Status status;
    int initialized;

    message = NULL;
    resolved_dir = NULL;
    resolved_namespace = NULL;
    status = OvStorage_Status_Ok;
    if (!ovc_host_operation_enter()) {
        return ovc_host_public_result(
            out_error,
            OvStorage_Status_Internal,
            "the process-global auth substrate is shutting down");
    }
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_init_mutex));
    initialized = g_ovc_host_auth_dir != NULL;
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_init_mutex));
    if (initialized) {
        goto done;
    }

    resolved_namespace = ovc_host_duplicate_c_string("default");
    if (resolved_namespace == NULL) {
        status = OvStorage_Status_Internal;
        message = "failed to copy credential_namespace";
        goto done;
    }
    status = ovc_host_resolve_auth_dir(NULL, &resolved_dir, &message);
    if (status == OvStorage_Status_Ok) {
        /* Another explicit initializer wins without becoming a conflict. */
        status = ovc_host_install_substrate(resolved_dir,
                                            resolved_namespace,
                                            0,
                                            &message);
        resolved_dir = NULL;
        resolved_namespace = NULL;
    }

done:
    free(resolved_dir);
    free(resolved_namespace);
    ovc_host_operation_leave();
    return ovc_host_public_result(out_error, status, message);
}

const OvStoragePlugin_HostCallbacks *ovc_host_callbacks_get(void)
{
    if (ovc_auth_substrate_auto_init(NULL) != OvStorage_Status_Ok) {
        return NULL;
    }
    return &g_ovc_host_callbacks;
}

static void ovc_host_process_cleanup(void)
{
    ovc_host_refresh_entry *entry;
    ovc_host_refresh_entry *refreshes;
    size_t callbacks_on_this_thread;

    callbacks_on_this_thread = 0;
#if OVC_HOST_HAS_THREAD_LOCAL
    callbacks_on_this_thread = g_ovc_host_callback_depth;
#endif

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_lifecycle_mutex));
    if (g_ovc_host_cleaned) {
        ovc_host_sync_success(
            ovc_mutex_unlock(&g_ovc_host_lifecycle_mutex));
        return;
    }
    g_ovc_host_closing = 1;
    if (g_ovc_host_active_callbacks < callbacks_on_this_thread) {
        abort();
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_lifecycle_mutex));

    /* Wake refresh waiters before draining active callbacks. */
    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_refresh_mutex));
    g_ovc_host_refresh_closing = 1;
    for (entry = g_ovc_host_refreshes; entry != NULL; entry = entry->next) {
        ovc_host_sync_success(ovc_cond_broadcast(&entry->changed));
    }
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_refresh_mutex));

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_lifecycle_mutex));
    /*
     * exit() does not return to a callback that invoked it.  Waiting for that
     * same stack would deadlock the atexit handler, so drain only callbacks on
     * other threads before clearing process state.
     */
    while (g_ovc_host_active_callbacks > callbacks_on_this_thread) {
        ovc_host_sync_success(
            ovc_cond_wait(&g_ovc_host_lifecycle_changed,
                          &g_ovc_host_lifecycle_mutex));
    }
    g_ovc_host_cleaned = 1;
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_lifecycle_mutex));

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_secret_mutex));
    ovc_cred_store_close(g_ovc_host_cred_store);
    g_ovc_host_cred_store = NULL;
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_secret_mutex));

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_refresh_mutex));
    refreshes = g_ovc_host_refreshes;
    g_ovc_host_refreshes = NULL;
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_refresh_mutex));
    while (refreshes != NULL) {
        ovc_host_refresh_entry *next;

        next = refreshes->next;
        refreshes->next = NULL;
        ovc_host_refresh_entry_destroy(refreshes);
        refreshes = next;
    }

    ovc_host_sync_success(ovc_mutex_lock(&g_ovc_host_init_mutex));
    free(g_ovc_host_auth_dir);
    g_ovc_host_auth_dir = NULL;
    free(g_ovc_host_credential_namespace);
    g_ovc_host_credential_namespace = NULL;
    ovc_host_sync_success(ovc_mutex_unlock(&g_ovc_host_init_mutex));
}

#if defined(OVC_HOST_CALLBACKS_TEST_MAIN)

#include <assert.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#define OVC_HOST_TEST_THREAD_COUNT 12
#define OVC_HOST_TEST_MAX_EXPECTED_RELEASES 4

typedef struct ovc_host_test_refresh_state {
    ovc_mutex mutex;
    ovc_cond changed;
    size_t ready;
    size_t calling;
    size_t invocations;
    int start;
    int release;
    const OvStoragePlugin_HostCallbacks *callbacks;
    OvStoragePlugin_Str backend_kind;
    OvStoragePlugin_ConnectionId connection_id;
} ovc_host_test_refresh_state;

typedef struct ovc_host_test_refresh_call {
    ovc_host_test_refresh_state *state;
    OvStoragePlugin_Error *error;
} ovc_host_test_refresh_call;

typedef struct ovc_host_test_error_refresh_state {
    OvStoragePlugin_Error *expected;
    size_t invocations;
} ovc_host_test_error_refresh_state;

static size_t g_ovc_host_test_zeroed_releases;
static size_t g_ovc_host_test_expected_release_lengths[
    OVC_HOST_TEST_MAX_EXPECTED_RELEASES];
static size_t g_ovc_host_test_expected_release_count;
static size_t g_ovc_host_test_expected_release_index;
static char g_ovc_host_test_auth_dir[512];

static void ovc_host_test_set_env(const char *name, const char *value)
{
#if defined(_WIN32)
    wchar_t *wide_name;
    wchar_t *wide_value;

    wide_name = ovc_utf8_to_wide(name);
    assert(wide_name != NULL);
    wide_value = value == NULL ? NULL : ovc_utf8_to_wide(value);
    assert(value == NULL || wide_value != NULL);
    if (SetEnvironmentVariableW(wide_name, wide_value) == 0) {
        assert(value == NULL && GetLastError() == ERROR_ENVVAR_NOT_FOUND);
    }
    free(wide_value);
    free(wide_name);
#else
    if (value == NULL) {
        assert(unsetenv(name) == 0);
    } else {
        assert(setenv(name, value, 1) == 0);
    }
#endif
}

static OvStoragePlugin_Str ovc_host_test_str(const char *value)
{
    OvStoragePlugin_Str result;

    memcpy(&result.ptr, &value, sizeof(result.ptr));
    result.len = strlen(value);
    return result;
}

static void ovc_host_test_plugin_error_destroy(
    OvStoragePlugin_Error *error)
{
    if (error == NULL) {
        return;
    }
    assert(error->message_ptr != NULL);
    assert(error->context == NULL);
    ovc_pval_error_clear(error);
    ovc_abi_free(error);
}

static void ovc_host_test_cred_error_mapping(void)
{
    static const struct {
        ovc_cred_status status;
        OvStoragePlugin_ErrorCode code;
    } cases[] = {
        {OVC_CRED_UNAVAILABLE,
         OvStoragePlugin_ErrorCode_StateRootUnavailable},
        {OVC_CRED_CORRUPT,
         OvStoragePlugin_ErrorCode_StateRootUnavailable},
        {OVC_CRED_NEWER_FORMAT,
         OvStoragePlugin_ErrorCode_StateRootUnavailable},
        {OVC_CRED_LOCKED, OvStoragePlugin_ErrorCode_Transient},
        {OVC_CRED_INVALID, OvStoragePlugin_ErrorCode_InvalidArgument},
        {OVC_CRED_NOMEM, OvStoragePlugin_ErrorCode_ResourceExhausted},
    };
    static const char expected[] = "secret_put: test path: test reason";
    ovc_cred_error store_error;
    OvStoragePlugin_Error *error;
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        store_error.status = cases[index].status;
        (void)snprintf(store_error.message,
                       sizeof(store_error.message),
                       "test path: test reason");
        error = ovc_host_cred_error("secret_put", &store_error);
        assert(error != NULL);
        assert(error->code == cases[index].code);
        assert(error->message_len == strlen(expected));
        assert(memcmp(error->message_ptr,
                      expected,
                      strlen(expected)) == 0);
        ovc_host_test_plugin_error_destroy(error);
    }
}

static void ovc_host_test_secret_destroy(
    OvStoragePlugin_SecretBytes *secret)
{
    size_t allocation_len;

    assert(secret->bytes.ptr != NULL);
    allocation_len = secret->bytes.len == 0 ? 1 : secret->bytes.len;
    ovc_secure_zero(secret->bytes.ptr, allocation_len);
    ovc_abi_free(secret->bytes.ptr);
    secret->bytes.ptr = NULL;
    secret->bytes.len = 0;
}

static void ovc_host_test_observe_secret_release(const uint8_t *value,
                                                 size_t length)
{
    size_t index;

    assert(value != NULL);
    assert(length != 0);
    assert(g_ovc_host_test_expected_release_index <
           g_ovc_host_test_expected_release_count);
    assert(length ==
           g_ovc_host_test_expected_release_lengths
               [g_ovc_host_test_expected_release_index]);
    for (index = 0; index < length; ++index) {
        assert(value[index] == 0);
    }
    ++g_ovc_host_test_expected_release_index;
    ++g_ovc_host_test_zeroed_releases;
}

static size_t ovc_host_test_expect_releases(const size_t *lengths,
                                            size_t count)
{
    assert(g_ovc_host_test_expected_release_index ==
           g_ovc_host_test_expected_release_count);
    assert(count <= OVC_HOST_TEST_MAX_EXPECTED_RELEASES);
    if (count != 0) {
        memcpy(g_ovc_host_test_expected_release_lengths,
               lengths,
               count * sizeof(lengths[0]));
    }
    g_ovc_host_test_expected_release_count = count;
    g_ovc_host_test_expected_release_index = 0;
    return g_ovc_host_test_zeroed_releases;
}

static void ovc_host_test_assert_expected_releases(size_t before)
{
    assert(g_ovc_host_test_expected_release_index ==
           g_ovc_host_test_expected_release_count);
    assert(g_ovc_host_test_zeroed_releases ==
           before + g_ovc_host_test_expected_release_count);
    g_ovc_host_test_expected_release_count = 0;
    g_ovc_host_test_expected_release_index = 0;
}

static int ovc_host_test_path_exists(const char *path)
{
#if defined(_WIN32)
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
#else
    return access(path, F_OK) == 0;
#endif
}

static int ovc_host_test_auth_dir_exists(void)
{
    return ovc_host_test_path_exists(g_ovc_host_test_auth_dir);
}

static void ovc_host_test_assert_store_exists(void)
{
    char *credential_dir;
    char *stem;
    char *record_path;
    char record_name[OVC_CRED_NAMESPACE_MAX * 2 + sizeof(".creds")];

    credential_dir = ovc_path_join(g_ovc_host_test_auth_dir,
                                   "c-credentials");
    assert(credential_dir != NULL);
    stem = ovc_cred_namespace_file_stem("host-callbacks-suite");
    assert(stem != NULL);
    (void)snprintf(record_name, sizeof(record_name), "%s.creds", stem);
    record_path = ovc_path_join(credential_dir, record_name);
    assert(record_path != NULL);
    assert(ovc_host_test_auth_dir_exists());
    assert(ovc_host_test_path_exists(credential_dir));
    assert(ovc_host_test_path_exists(record_path));
#if !defined(_WIN32)
    {
        struct stat info;

        assert(stat(g_ovc_host_test_auth_dir, &info) == 0);
        assert(S_ISDIR(info.st_mode));
        assert((info.st_mode & 0777) == 0700);
        assert(stat(credential_dir, &info) == 0);
        assert(S_ISDIR(info.st_mode));
        assert((info.st_mode & 0777) == 0700);
        assert(stat(record_path, &info) == 0);
        assert(S_ISREG(info.st_mode));
        assert((info.st_mode & 0777) == 0600);
    }
#endif
    free(record_path);
    free(stem);
    free(credential_dir);
}

static void ovc_host_test_remove_store(void)
{
    char *credential_dir;
    char *stem;
    char *record_path;
    char *lock_path;
    char record_name[OVC_CRED_NAMESPACE_MAX * 2 + sizeof(".creds")];
    char lock_name[OVC_CRED_NAMESPACE_MAX * 2 + sizeof(".lock")];

    credential_dir = ovc_path_join(g_ovc_host_test_auth_dir,
                                   "c-credentials");
    assert(credential_dir != NULL);
    stem = ovc_cred_namespace_file_stem("host-callbacks-suite");
    assert(stem != NULL);
    (void)snprintf(record_name, sizeof(record_name), "%s.creds", stem);
    (void)snprintf(lock_name, sizeof(lock_name), "%s.lock", stem);
    record_path = ovc_path_join(credential_dir, record_name);
    lock_path = ovc_path_join(credential_dir, lock_name);
    assert(record_path != NULL);
    assert(lock_path != NULL);
    assert(remove(record_path) == 0);
    assert(remove(lock_path) == 0);
#if defined(_WIN32)
    assert(RemoveDirectoryA(credential_dir));
    assert(RemoveDirectoryA(g_ovc_host_test_auth_dir));
#else
    assert(rmdir(credential_dir) == 0);
    assert(rmdir(g_ovc_host_test_auth_dir) == 0);
#endif
    free(lock_path);
    free(record_path);
    free(stem);
    free(credential_dir);
}

static const OvStoragePlugin_HostCallbacks *ovc_host_test_init(void)
{
    OvStorage_InitAuthSubstrateOptions options;
    OvStorage_Error error;
    const OvStoragePlugin_HostCallbacks *callbacks;
    char oversized_namespace[OVC_CRED_NAMESPACE_MAX + 2];
    char leaf[128];
    char *saved_auth_dir;
    char *temp_root;
    char *joined;
    int path_length;

    memset(&options, 0, sizeof(options));
    memset(&error, 0, sizeof(error));

    /* An empty default override fails before the process-global substrate is
     * pinned. Restoring the environment and pinning a valid explicit path
     * below proves the failed auto-init does not poison the process. */
    errno = 0;
    saved_auth_dir = ovc_env_dup("OVSTORAGE_AUTH_DIR");
    assert(saved_auth_dir != NULL || errno == 0);
    ovc_host_test_set_env("OVSTORAGE_AUTH_DIR", "");
    assert(ovc_auth_substrate_auto_init(&error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "must not be empty") != NULL);
    /* A relative override is refused for the same reason the platform
     * variables ignore a relative value: it would move with the working
     * directory, and two processes would take different lock files. */
    ovc_host_test_set_env("OVSTORAGE_AUTH_DIR", "relative-auth-dir");
    assert(ovc_auth_substrate_auto_init(&error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "absolute") != NULL);
#if defined(_WIN32)
    /* Drive-relative (`C:dir`) and root-relative (`\dir`) paths also move
     * with the working directory; only a drive qualifier followed by a
     * separator, or a UNC path, counts as absolute. */
    ovc_host_test_set_env("OVSTORAGE_AUTH_DIR", "C:ovstorage\\auth");
    assert(ovc_auth_substrate_auto_init(&error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "absolute") != NULL);
    ovc_host_test_set_env("OVSTORAGE_AUTH_DIR", "\\ovstorage\\auth");
    assert(ovc_auth_substrate_auto_init(&error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "absolute") != NULL);
#endif
    ovc_host_test_set_env("OVSTORAGE_AUTH_DIR", saved_auth_dir);
    free(saved_auth_dir);

    /*
     * A zero-initialized options struct names neither setting. Pinning is
     * one-shot and process-global, so it is rejected instead of quietly
     * pinning the defaults: the explicit call further down must still be able
     * to succeed.
     */
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);

    options.auth_dir = "";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "must not be empty") != NULL);
    options.auth_dir = NULL;

    options.credential_namespace = "../x";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    options.credential_namespace = "";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    options.credential_namespace = ".hidden";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    memset(oversized_namespace, 'a', sizeof(oversized_namespace) - 1);
    oversized_namespace[sizeof(oversized_namespace) - 1] = '\0';
    options.credential_namespace = oversized_namespace;
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);

    /* A relative auth_dir is refused (below), so the suite's own directory
     * is an absolute, process-scoped leaf under the temporary root. */
    path_length = snprintf(leaf,
                           sizeof(leaf),
                           "ovstorage-host-callbacks-test-auth-%lu-%p",
#if defined(_WIN32)
                           (unsigned long)GetCurrentProcessId(),
#else
                           (unsigned long)getpid(),
#endif
                           (void *)&g_ovc_host_test_auth_dir);
    assert(path_length > 0);
    assert((size_t)path_length < sizeof(leaf));
    temp_root = ovc_temp_root_dup();
    assert(temp_root != NULL);
    joined = ovc_path_join(temp_root, leaf);
    assert(joined != NULL);
    path_length = snprintf(g_ovc_host_test_auth_dir,
                           sizeof(g_ovc_host_test_auth_dir),
                           "%s",
                           joined);
    assert(path_length > 0);
    assert((size_t)path_length < sizeof(g_ovc_host_test_auth_dir));
    free(joined);
    free(temp_root);
    assert(!ovc_host_test_auth_dir_exists());

    /* The same leaf given relative is refused before anything is pinned:
     * a relative directory would move with the working directory. The
     * namespace is valid here so the directory is the only thing at fault. */
    options.credential_namespace = "host-callbacks-suite";
    options.auth_dir = leaf;
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "absolute") != NULL);
#if defined(_WIN32)
    /* `C:ovstorage\auth` is drive C's current directory plus a relative
     * tail, and `\ovstorage\auth` is root-relative to the current drive:
     * both are exactly what the absolute-path rule exists to refuse. */
    options.auth_dir = "C:ovstorage\\auth";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "absolute") != NULL);
    options.auth_dir = "\\ovstorage\\auth";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_InvalidArgument);
    assert(error.code == OvStorage_Status_InvalidArgument);
    assert(error.message != NULL);
    assert(strstr(error.message, "absolute") != NULL);
#endif

    options.auth_dir = g_ovc_host_test_auth_dir;
    options.credential_namespace = "host-callbacks-suite";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_Ok);
    assert(!ovc_host_test_auth_dir_exists());
    assert(error.code == OvStorage_Status_Ok);
    assert(error.message == NULL);

    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_Ok);
    options.credential_namespace = "other";
    assert(ovstorage_init_auth_substrate(&options, &error) ==
           OvStorage_Status_Unsupported);
    assert(error.code == OvStorage_Status_Unsupported);
    assert(error.message != NULL);

    /* Load-time auto-init preserves the earlier explicit directory and namespace. */
    assert(ovc_auth_substrate_auto_init(&error) == OvStorage_Status_Ok);
    assert(error.message == NULL);

    callbacks = ovc_host_callbacks_get();
    assert(callbacks != NULL);
    assert(callbacks->struct_size == sizeof(*callbacks));
    assert(callbacks->host_state != NULL);
    assert(callbacks->secret_get != NULL);
    assert(callbacks->secret_put != NULL);
    assert(callbacks->secret_delete != NULL);
    assert(callbacks->auth_refresh_lock_with_refresh != NULL);
    assert(callbacks->host_kind == UINT32_C(0));
    assert(callbacks->log != NULL);

    free(error.message);
    return callbacks;
}

static void ovc_host_test_secret_round_trip(
    const OvStoragePlugin_HostCallbacks *callbacks)
{
    static const uint8_t first_expected[] = {0xde, 0xad, 0xbe, 0xef};
    static uint8_t second[] = {0x73, 0x65, 0x63, 0x72, 0x65, 0x74};
    uint8_t first[sizeof(first_expected)];
    uint8_t empty_sentinel;
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_SecretBytes value;
    OvStoragePlugin_Optional_SecretBytes output;
    OvStoragePlugin_Error *error;
    size_t expected_releases[2];
    size_t releases;

    key.backend_kind = ovc_host_test_str("s3");
    key.connection_id.id = ovc_host_test_str("connection-1");
    key.field = ovc_host_test_str("refresh-token");
    memcpy(first, first_expected, sizeof(first));

    memset(&output, 0xa5, sizeof(output));
    releases = ovc_host_test_expect_releases(NULL, 0);
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    assert(error == NULL);
    assert(!output.present);
    ovc_host_test_assert_expected_releases(releases);

    value.bytes.ptr = (uint8_t *)first;
    value.bytes.len = sizeof(first);
    expected_releases[0] = sizeof(first);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    error = callbacks->secret_put(callbacks->host_state, &key, &value);
    assert(error == NULL);
    ovc_host_test_assert_expected_releases(releases);
    ovc_host_test_assert_store_exists();
    memset(first, 0, sizeof(first));

    expected_releases[0] = sizeof(first_expected);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    assert(error == NULL);
    ovc_host_test_assert_expected_releases(releases);
    assert(output.present);
    assert(output.value.bytes.len == sizeof(first_expected));
    assert(memcmp(output.value.bytes.ptr,
                  first_expected,
                  sizeof(first_expected)) == 0);
    ovc_host_test_secret_destroy(&output.value);

    expected_releases[0] = sizeof(first_expected);
    expected_releases[1] = sizeof(second);
    releases = ovc_host_test_expect_releases(expected_releases, 2);
    value.bytes.ptr = second;
    value.bytes.len = sizeof(second);
    error = callbacks->secret_put(callbacks->host_state, &key, &value);
    assert(error == NULL);
    ovc_host_test_assert_expected_releases(releases);

    expected_releases[0] = sizeof(second);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    assert(error == NULL);
    ovc_host_test_assert_expected_releases(releases);
    assert(output.present);
    assert(output.value.bytes.len == sizeof(second));
    assert(memcmp(output.value.bytes.ptr, second, sizeof(second)) == 0);
    ovc_host_test_secret_destroy(&output.value);

    expected_releases[0] = sizeof(second);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    error = callbacks->secret_delete(callbacks->host_state, &key);
    assert(error == NULL);
    ovc_host_test_assert_expected_releases(releases);
    releases = ovc_host_test_expect_releases(NULL, 0);
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    assert(error == NULL);
    assert(!output.present);
    ovc_host_test_assert_expected_releases(releases);
    releases = ovc_host_test_expect_releases(NULL, 0);
    assert(callbacks->secret_delete(callbacks->host_state, &key) == NULL);
    ovc_host_test_assert_expected_releases(releases);

    /* Empty secrets still use the ABI's non-null one-byte sentinel. */
    empty_sentinel = 0;
    value.bytes.ptr = &empty_sentinel;
    value.bytes.len = 0;
    expected_releases[0] = 1;
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    assert(callbacks->secret_put(callbacks->host_state, &key, &value) ==
           NULL);
    ovc_host_test_assert_expected_releases(releases);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    assert(callbacks->secret_get(callbacks->host_state, &key, &output) ==
           NULL);
    ovc_host_test_assert_expected_releases(releases);
    assert(output.present);
    assert(output.value.bytes.ptr != NULL);
    assert(output.value.bytes.len == 0);
    ovc_host_test_secret_destroy(&output.value);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    assert(callbacks->secret_delete(callbacks->host_state, &key) == NULL);
    ovc_host_test_assert_expected_releases(releases);

    key.connection_id.id = ovc_host_test_str("");
    releases = ovc_host_test_expect_releases(NULL, 0);
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    assert(error != NULL);
    assert(error->code == OvStoragePlugin_ErrorCode_InvalidArgument);
    ovc_host_test_plugin_error_destroy(error);
    ovc_host_test_assert_expected_releases(releases);
}

static OvStoragePlugin_Error *ovc_host_test_refresh(void *opaque)
{
    ovc_host_test_refresh_state *state;

    state = (ovc_host_test_refresh_state *)opaque;
    ovc_host_sync_success(ovc_mutex_lock(&state->mutex));
    ++state->invocations;
    ovc_host_sync_success(ovc_cond_broadcast(&state->changed));
    while (!state->release) {
        ovc_host_sync_success(
            ovc_cond_wait(&state->changed, &state->mutex));
    }
    ovc_host_sync_success(ovc_mutex_unlock(&state->mutex));
    return NULL;
}

static void ovc_host_test_refresh_caller(void *opaque)
{
    ovc_host_test_refresh_call *call;
    ovc_host_test_refresh_state *state;

    call = (ovc_host_test_refresh_call *)opaque;
    state = call->state;
    ovc_host_sync_success(ovc_mutex_lock(&state->mutex));
    ++state->ready;
    ovc_host_sync_success(ovc_cond_broadcast(&state->changed));
    while (!state->start) {
        ovc_host_sync_success(
            ovc_cond_wait(&state->changed, &state->mutex));
    }
    ++state->calling;
    ovc_host_sync_success(ovc_cond_broadcast(&state->changed));
    ovc_host_sync_success(ovc_mutex_unlock(&state->mutex));

    call->error = state->callbacks->auth_refresh_lock_with_refresh(
        state->callbacks->host_state,
        &state->backend_kind,
        &state->connection_id,
        UINT64_MAX,
        state,
        ovc_host_test_refresh);
}

static OvStoragePlugin_Error *ovc_host_test_error_refresh(void *opaque)
{
    ovc_host_test_error_refresh_state *state;

    state = (ovc_host_test_error_refresh_state *)opaque;
    ++state->invocations;
    return state->expected;
}

static OvStoragePlugin_Error *ovc_host_test_count_refresh(void *opaque)
{
    size_t *count;

    count = (size_t *)opaque;
    ++*count;
    return NULL;
}

static void ovc_host_test_refresh_coalescing(
    const OvStoragePlugin_HostCallbacks *callbacks)
{
    ovc_host_test_refresh_state state;
    ovc_host_test_refresh_call calls[OVC_HOST_TEST_THREAD_COUNT];
    ovc_thread threads[OVC_HOST_TEST_THREAD_COUNT];
    ovc_host_test_error_refresh_state failed;
    OvStoragePlugin_ConnectionId failed_connection;
    OvStoragePlugin_Str other_backend_kind;
    OvStoragePlugin_Error *error;
    size_t other_backend_refresh;
    size_t success_after_failure;
    size_t index;

    memset(&state, 0, sizeof(state));
    memset(calls, 0, sizeof(calls));
    ovc_host_sync_success(ovc_mutex_init(&state.mutex));
    ovc_host_sync_success(ovc_cond_init(&state.changed));
    state.callbacks = callbacks;
    state.backend_kind = ovc_host_test_str("nucleus");
    state.connection_id.id = ovc_host_test_str("connection-refresh");

    for (index = 0; index < OVC_HOST_TEST_THREAD_COUNT; ++index) {
        calls[index].state = &state;
        ovc_host_sync_success(
            ovc_thread_create(&threads[index],
                              ovc_host_test_refresh_caller,
                              &calls[index]));
    }

    ovc_host_sync_success(ovc_mutex_lock(&state.mutex));
    while (state.ready != OVC_HOST_TEST_THREAD_COUNT) {
        ovc_host_sync_success(
            ovc_cond_wait(&state.changed, &state.mutex));
    }
    state.start = 1;
    ovc_host_sync_success(ovc_cond_broadcast(&state.changed));
    while (state.calling != OVC_HOST_TEST_THREAD_COUNT ||
           state.invocations == 0) {
        ovc_host_sync_success(
            ovc_cond_wait(&state.changed, &state.mutex));
    }
    assert(state.invocations == 1);

    /* Backend kind is part of the refresh key, not just connection id. */
    other_backend_kind = ovc_host_test_str("s3");
    other_backend_refresh = 0;
    error = callbacks->auth_refresh_lock_with_refresh(
        callbacks->host_state,
        &other_backend_kind,
        &state.connection_id,
        UINT64_MAX,
        &other_backend_refresh,
        ovc_host_test_count_refresh);
    assert(error == NULL);
    assert(other_backend_refresh == 1);
    state.release = 1;
    ovc_host_sync_success(ovc_cond_broadcast(&state.changed));
    ovc_host_sync_success(ovc_mutex_unlock(&state.mutex));

    for (index = 0; index < OVC_HOST_TEST_THREAD_COUNT; ++index) {
        ovc_host_sync_success(ovc_thread_join(&threads[index]));
        assert(calls[index].error == NULL);
    }
    assert(state.invocations == 1);

    /* A later caller inside the same window also skips. */
    error = callbacks->auth_refresh_lock_with_refresh(
        callbacks->host_state,
        &state.backend_kind,
        &state.connection_id,
        UINT64_MAX,
        &state,
        ovc_host_test_refresh);
    assert(error == NULL);
    assert(state.invocations == 1);

    /* A zero window is always stale. */
    error = callbacks->auth_refresh_lock_with_refresh(
        callbacks->host_state,
        &state.backend_kind,
        &state.connection_id,
        0,
        &state,
        ovc_host_test_refresh);
    assert(error == NULL);
    assert(state.invocations == 2);

    /* A plugin error is returned unchanged and does not mark freshness. */
    memset(&failed, 0, sizeof(failed));
    failed.expected = ovc_host_plugin_error(
        OvStoragePlugin_ErrorCode_Transient, "refresh failed");
    failed_connection.id = ovc_host_test_str("connection-refresh-failed");
    error = callbacks->auth_refresh_lock_with_refresh(
        callbacks->host_state,
        &state.backend_kind,
        &failed_connection,
        UINT64_MAX,
        &failed,
        ovc_host_test_error_refresh);
    assert(error == failed.expected);
    assert(failed.invocations == 1);
    ovc_host_test_plugin_error_destroy(error);

    success_after_failure = 0;
    error = callbacks->auth_refresh_lock_with_refresh(
        callbacks->host_state,
        &state.backend_kind,
        &failed_connection,
        UINT64_MAX,
        &success_after_failure,
        ovc_host_test_count_refresh);
    assert(error == NULL);
    assert(success_after_failure == 1);

    ovc_host_sync_success(ovc_cond_destroy(&state.changed));
    ovc_host_sync_success(ovc_mutex_destroy(&state.mutex));
}

static void ovc_host_test_teardown_zeroes(
    const OvStoragePlugin_HostCallbacks *callbacks)
{
    static uint8_t secret[] = {1, 2, 3, 4, 5};
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_SecretBytes value;
    OvStoragePlugin_Optional_SecretBytes output;
    OvStoragePlugin_Error *error;
    OvStorage_Error public_error;
    size_t expected_releases[1];
    size_t releases;

    key.backend_kind = ovc_host_test_str("s3");
    key.connection_id.id = ovc_host_test_str("connection-at-exit");
    key.field = ovc_host_test_str("secret");
    value.bytes.ptr = secret;
    value.bytes.len = sizeof(secret);
    expected_releases[0] = sizeof(secret);
    releases = ovc_host_test_expect_releases(expected_releases, 1);
    assert(callbacks->secret_put(callbacks->host_state, &key, &value) ==
           NULL);
    ovc_host_test_assert_expected_releases(releases);
    ovc_host_test_assert_store_exists();

    releases = ovc_host_test_expect_releases(NULL, 0);
    ovc_host_process_cleanup();
    ovc_host_test_assert_expected_releases(releases);
    ovc_host_test_assert_store_exists();

    memset(&public_error, 0, sizeof(public_error));
    assert(ovc_auth_substrate_auto_init(&public_error) ==
           OvStorage_Status_Internal);
    assert(public_error.code == OvStorage_Status_Internal);
    assert(public_error.message != NULL);
    free(public_error.message);
    assert(ovc_host_callbacks_get() == NULL);

    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    assert(error != NULL);
    assert(error->code == OvStoragePlugin_ErrorCode_Internal);
    ovc_host_test_plugin_error_destroy(error);
}

/* The no-home fallback lands where the Rust hosts' resolver lands:
 * `<temp>/ovstorage-<uid>/auth` on POSIX and `<temp>/ovstorage/auth` on
 * Windows. `temp_fallback().join("auth")` in `auth/state_root.rs` is the other
 * half of this contract; a C embedder and a CLI started without a home must
 * still address one directory. Runs before anything pins the substrate, and
 * restores every variable it clears. */
static void ovc_host_test_default_auth_dir_fallback(void)
{
    static const char *const names[] = {
        "OVSTORAGE_AUTH_DIR",
        "HOME",
        "XDG_DATA_HOME",
        "LOCALAPPDATA",
    };
    char *saved[sizeof(names) / sizeof(names[0])];
    char *temp_root;
    char *scoped;
    char *expected;
    char *resolved;
    const char *message;
    char child[64];
    size_t index;

    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        errno = 0;
        saved[index] = ovc_env_dup(names[index]);
        assert(saved[index] != NULL || errno == 0);
        ovc_host_test_set_env(names[index], NULL);
    }

    temp_root = ovc_temp_root_dup();
    assert(temp_root != NULL);
#if defined(_WIN32)
    assert(snprintf(child, sizeof(child), "ovstorage") > 0);
#else
    assert(snprintf(child,
                    sizeof(child),
                    "ovstorage-%lu",
                    (unsigned long)getuid()) > 0);
#endif
    scoped = ovc_path_join(temp_root, child);
    assert(scoped != NULL);
    expected = ovc_path_join(scoped, "auth");
    assert(expected != NULL);

    resolved = NULL;
    message = NULL;
    assert(ovc_host_default_auth_dir(&resolved, &message) ==
           OvStorage_Status_Ok);
    assert(resolved != NULL);
    assert(strcmp(resolved, expected) == 0);

    free(resolved);
    free(expected);
    free(scoped);
    free(temp_root);
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        ovc_host_test_set_env(names[index], saved[index]);
        free(saved[index]);
    }
}

int main(void)
{
    const OvStoragePlugin_HostCallbacks *callbacks;

    ovc_host_test_default_auth_dir_fallback();
    ovc_host_test_cred_error_mapping();
    ovc_cred_test_set_release_observer(
        ovc_host_test_observe_secret_release);
    callbacks = ovc_host_test_init();
    ovc_host_test_secret_round_trip(callbacks);
    ovc_host_test_refresh_coalescing(callbacks);
    ovc_host_test_teardown_zeroes(callbacks);
    ovc_cred_test_set_release_observer(NULL);
    ovc_host_test_remove_store();
    assert(!ovc_host_test_auth_dir_exists());
    return 0;
}

#endif /* OVC_HOST_CALLBACKS_TEST_MAIN */
