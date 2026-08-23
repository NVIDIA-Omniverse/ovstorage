/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Public Layer-handle dispatch and Stack lifetime management.
 */

#include "internal.h"

#include "ovstorage_defaults.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ovc_dispatch_pump_link ovc_dispatch_pump_link;
typedef struct ovc_dispatch_operation ovc_dispatch_operation;
typedef struct ovc_dispatch_io_task ovc_dispatch_io_task;

static void ovc_dispatch_secret_bundle_clear(
    OvStoragePlugin_SecretBundle *bundle);
static void ovc_dispatch_update_metadata_request_clear(
    OvStoragePlugin_UpdateMetadataRequest *request);
static void ovc_dispatch_update_attributes_request_clear(
    OvStoragePlugin_UpdateConnectionAttributesRequest *request);
/* The v8 list introspection completions decode their result envelopes with
 * these snapshot/updates helpers, all defined below their point of use. */
static void ovc_dispatch_root_snapshot_clear(
    OvStoragePlugin_RootInfoSnapshot *snapshot);
static bool ovc_dispatch_root_updates_discard(
    OvStoragePlugin_RootInfoChangeStream *updates);
static OvStorage_RootInfoList *ovc_dispatch_root_list_from_plugin(
    const OvStoragePlugin_RootInfoSnapshot *snapshot);
static void ovc_dispatch_connection_snapshot_clear(
    OvStoragePlugin_ConnectionSnapshot *snapshot);
static void ovc_dispatch_connection_updates_clear(
    OvStoragePlugin_ConnectionChangeStream *updates);
static OvStorage_ConnectionList *ovc_dispatch_connection_list_from_plugin(
    const OvStoragePlugin_ConnectionSnapshot *snapshot);

struct ovc_dispatch_pump_link {
    ovc_stream_pump *pump;
    ovc_dispatch_pump_link *next;
};

struct OvStorage_LayerHandle {
    OvStoragePlugin_LayerHandle root;
    ovc_layer_factory **factories;
    size_t factory_count;
    ovc_mutex mutex;
    ovc_cond drained;
    size_t in_flight;
    bool closing;
    ovc_dispatch_pump_link *pumps;
};

typedef enum ovc_dispatch_operation_kind {
    OVC_DISPATCH_INFO_OBJECT = 0,
    OVC_DISPATCH_INFO_WRITE = 1,
    OVC_DISPATCH_INFO_WRITE_STEP = 2,
    OVC_DISPATCH_INFO_BACKEND_ITEM = 3,
    OVC_DISPATCH_READ_BYTES = 4,
    OVC_DISPATCH_READ_STREAM = 5,
    OVC_DISPATCH_LOCAL_DELEGATE = 6,
    OVC_DISPATCH_STATUS = 7,
    OVC_DISPATCH_LIST = 8,
    OVC_DISPATCH_VERSION_LIST = 9,
    OVC_DISPATCH_ACCESS = 10,
    OVC_DISPATCH_CONNECTION = 11,
    OVC_DISPATCH_AUTH_STREAM = 12,
    OVC_DISPATCH_ROOT_LIST = 13,
    OVC_DISPATCH_CONNECTION_LIST = 14,
    OVC_DISPATCH_WATCH_STREAM = 15,
    OVC_DISPATCH_WRITE_REDIRECT_BATCH = 16,
    OVC_DISPATCH_WRITE_STEP = 17
} ovc_dispatch_operation_kind;

typedef union ovc_dispatch_callback {
    OvStorage_InfoCallback info;
    OvStorage_ReadBytesCallback read_bytes;
    OvStorage_ReadStreamCallback read_stream;
    OvStorage_ReadLocalFileCallback local_delegate;
    OvStorage_StatusCallback status;
    OvStorage_ListCallback list;
    OvStorage_ListVersionsCallback version_list;
    OvStorage_CheckAccessCallback access;
    OvStorage_ConnectionCallback connection;
    OvStorage_AuthEventCallback auth;
    OvStorage_RootInfoListCallback root_list;
    OvStorage_ConnectionListCallback connection_list;
    OvStorage_WatchDirectoryCallback watch;
    OvStorage_WriteRedirectCallback write_redirect;
    OvStorage_WriteStepCallback write_step;
} ovc_dispatch_callback;

struct ovc_dispatch_operation {
    OvStorage_LayerHandle *handle;
    ovc_dispatch_operation_kind kind;
    ovc_dispatch_callback callback;
    void *user_data;
    char *address;
    ovc_stream_cancel_scope *stream_scope;
    ovc_stream_pump *pump;
    uint8_t *collected_bytes;
    size_t collected_len;
    size_t collected_capacity;
    OvStorage_Info *collected_info;
    bool stream_conversion_failed;
};

typedef enum ovc_dispatch_io_task_kind {
    OVC_DISPATCH_IO_TASK_ERROR = 0,
    OVC_DISPATCH_IO_TASK_STAT = 1,
    OVC_DISPATCH_IO_TASK_READ = 2,
    OVC_DISPATCH_IO_TASK_MATERIALIZE = 3,
    OVC_DISPATCH_IO_TASK_WRITE = 4,
    OVC_DISPATCH_IO_TASK_LIST = 5,
    OVC_DISPATCH_IO_TASK_LIST_VERSIONS = 6,
    OVC_DISPATCH_IO_TASK_LIST_ADDRESS_ROOTS = 7,
    OVC_DISPATCH_IO_TASK_DELETE = 8,
    OVC_DISPATCH_IO_TASK_COPY = 9,
    OVC_DISPATCH_IO_TASK_RENAME = 10,
    OVC_DISPATCH_IO_TASK_CREATE_DIRECTORY = 11,
    OVC_DISPATCH_IO_TASK_DELETE_DIRECTORY = 12,
    OVC_DISPATCH_IO_TASK_UPDATE_METADATA = 13,
    OVC_DISPATCH_IO_TASK_CHECK_ACCESS = 14,
    OVC_DISPATCH_IO_TASK_LIST_CONNECTIONS = 15,
    OVC_DISPATCH_IO_TASK_GET_LATEST_VERSION = 16,
    OVC_DISPATCH_IO_TASK_PROBE = 17,
    OVC_DISPATCH_IO_TASK_UPDATE_CONNECTION_ATTRIBUTES = 18,
    OVC_DISPATCH_IO_TASK_WRITE_STREAM = 19,
    OVC_DISPATCH_IO_TASK_WATCH_DIRECTORY = 20,
    OVC_DISPATCH_IO_TASK_WRITE_REDIRECT = 21,
    OVC_DISPATCH_IO_TASK_CONTINUE_WRITE = 22
} ovc_dispatch_io_task_kind;

typedef union ovc_dispatch_io_request {
    OvStoragePlugin_StatRequest stat;
    OvStoragePlugin_ReadRequest read;
    OvStoragePlugin_WriteRequest write;
    OvStoragePlugin_ListRequest list;
    OvStoragePlugin_ListVersionsRequest list_versions;
    OvStoragePlugin_DeleteRequest delete_;
    OvStoragePlugin_CopyRequest copy;
    OvStoragePlugin_RenameRequest rename;
    OvStoragePlugin_CreateDirectoryRequest create_directory;
    OvStoragePlugin_DeleteDirectoryRequest delete_directory;
    OvStoragePlugin_UpdateMetadataRequest update_metadata;
    OvStoragePlugin_CheckAccessRequest check_access;
    OvStoragePlugin_ListAddressRootsRequest list_address_roots;
    OvStoragePlugin_ListConnectionsRequest list_connections;
    OvStoragePlugin_LayerConnectionRequest layer_connection;
    OvStoragePlugin_UpdateConnectionAttributesRequest update_attributes;
    OvStoragePlugin_WatchDirectoryRequest watch_directory;
    OvStoragePlugin_ContinueWriteRequest continue_write;
} ovc_dispatch_io_request;

struct ovc_dispatch_io_task {
    OvStorage_LayerHandle *handle;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task_kind kind;
    ovc_dispatch_io_request request;
    OvStoragePlugin_CancelTokenFFI cancel;
    bool has_cancel;
    OvStorage_Status error_status;
    const char *error_message;
};

typedef struct ovc_dispatch_write_stream {
    OvStorage_WriteStream source;
} ovc_dispatch_write_stream;

/* ------------------------------------------------------------------------- */
/* Small ownership and validation helpers. */

static void ovc_dispatch_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

static char *ovc_dispatch_cstring_copy(const char *value)
{
    char *copy;
    size_t length;

    if (value == NULL) {
        return NULL;
    }
    length = strlen(value);
    if (length == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, value, length + 1);
    }
    return copy;
}

static bool ovc_dispatch_utf8_valid(const char *value)
{
    if (value == NULL) {
        return false;
    }
    return ovc_utf8_is_valid(value, strlen(value));
}

static char *ovc_dispatch_slice_copy(const char *bytes, size_t length)
{
    char *copy;

    if ((bytes == NULL && length != 0) ||
        (bytes != NULL && memchr(bytes, '\0', length) != NULL) ||
        length == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }
    if (length != 0) {
        memcpy(copy, bytes, length);
    }
    copy[length] = '\0';
    return copy;
}

/*
 * Lossy variant: each interior NUL becomes the two-character escape "\0"
 * instead of failing the conversion, so this fails only when memory is
 * exhausted.  The result is a
 * public app-API string and stays on the plain C allocator.
 */
static char *ovc_dispatch_slice_copy_lossy(const char *bytes, size_t length)
{
    char *copy;
    size_t nul_count;
    size_t index;
    size_t out_index;

    if (bytes == NULL && length != 0) {
        return NULL;
    }
    nul_count = 0;
    for (index = 0; index < length; ++index) {
        if (bytes[index] == '\0') {
            ++nul_count;
        }
    }
    if (length >= SIZE_MAX - 1 || nul_count > SIZE_MAX - 1 - length) {
        return NULL;
    }
    copy = (char *)malloc(length + nul_count + 1);
    if (copy == NULL) {
        return NULL;
    }
    out_index = 0;
    for (index = 0; index < length; ++index) {
        if (bytes[index] == '\0') {
            copy[out_index++] = '\\';
            copy[out_index++] = '0';
        } else {
            copy[out_index++] = bytes[index];
        }
    }
    copy[out_index] = '\0';
    return copy;
}

/*
 * Filtering variant mirroring the connection-local cstring_lossy that
 * ffi/connection.rs shadows the crate-wide escaping helper with: interior
 * NUL bytes are dropped from the copy (not escaped), so this fails only
 * when memory is exhausted.  The result is a public app-API string and
 * stays on the plain C allocator.
 */
static char *ovc_dispatch_slice_copy_filtered(const char *bytes, size_t length)
{
    char *copy;
    size_t index;
    size_t out_index;

    if (bytes == NULL && length != 0) {
        return NULL;
    }
    if (length == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }
    out_index = 0;
    for (index = 0; index < length; ++index) {
        if (bytes[index] != '\0') {
            copy[out_index++] = bytes[index];
        }
    }
    copy[out_index] = '\0';
    return copy;
}

/*
 * Ownership split for allocations in this file: every buffer that crosses
 * the plugin ABI — nested request payloads the Layer adopts during the
 * vtable prologue, and every plugin-produced result/error/stream payload the
 * host releases — uses the ovc_abi_alloc/ovc_abi_free pair (Rust's System
 * allocator convention: malloc/free on POSIX, the process heap on Win32).
 * Buffers that stay host-internal or are handed to the public app API
 * (OvStorage_* values reclaimed by values.c) remain on plain malloc/free.
 */
static bool ovc_dispatch_abi_str_copy(OvStoragePlugin_Str *out,
                                      const char *bytes,
                                      size_t length)
{
    memset(out, 0, sizeof(*out));
    if (bytes == NULL && length != 0) {
        return false;
    }
    out->ptr = (char *)ovc_abi_copy_bytes(bytes, length);
    if (out->ptr == NULL) {
        return false;
    }
    out->len = length;
    return true;
}

static bool ovc_dispatch_abi_cstring_copy(OvStoragePlugin_Str *out,
                                          const char *value)
{
    return value != NULL &&
           ovc_dispatch_abi_str_copy(out, value, strlen(value));
}

static bool ovc_dispatch_abi_bytes_copy(OvStoragePlugin_Bytes *out,
                                        const uint8_t *bytes,
                                        size_t length)
{
    memset(out, 0, sizeof(*out));
    if (bytes == NULL && length != 0) {
        return false;
    }
    out->ptr = (uint8_t *)ovc_abi_copy_bytes(bytes, length);
    if (out->ptr == NULL) {
        return false;
    }
    out->len = length;
    return true;
}

static void ovc_dispatch_abi_str_clear(OvStoragePlugin_Str *value)
{
    if (value == NULL) {
        return;
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_dispatch_abi_bytes_clear(OvStoragePlugin_Bytes *value,
                                         bool secure)
{
    if (value == NULL) {
        return;
    }
    if (secure && value->ptr != NULL) {
        ovc_secure_zero(value->ptr, value->len);
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_dispatch_abi_key_values_clear(
    OvStoragePlugin_KeyValueList *values)
{
    size_t index;

    if (values == NULL) {
        return;
    }
    if (values->ptr != NULL) {
        for (index = 0; index < values->len; ++index) {
            ovc_dispatch_abi_str_clear(&values->ptr[index].key);
            ovc_dispatch_abi_str_clear(&values->ptr[index].value);
        }
    }
    ovc_abi_free(values->ptr);
    values->ptr = NULL;
    values->len = 0;
}

static void ovc_dispatch_plugin_error_clear(OvStoragePlugin_Error *error,
                                            bool free_outer)
{
    if (error == NULL) {
        return;
    }
    /* Field teardown is ovc_pval_error_clear's, so this surface cannot fall
     * behind a field added to the struct. The memset that follows clears the
     * scalars it leaves alone; the pointer fields it already nulled. */
    ovc_pval_error_clear(error);
    memset(error, 0, sizeof(*error));
    if (free_outer) {
        ovc_abi_free(error);
    }
}

static OvStorage_Error ovc_dispatch_public_error(
    OvStorage_Status status,
    const char *message)
{
    OvStorage_Error error;

    error.code = status;
    error.message = ovc_dispatch_cstring_copy(
        message == NULL ? "ovstorage operation failed" : message);
    error.code_name = ovc_status_code_name(status);
    return error;
}

static OvStorage_Error ovc_dispatch_error_from_plugin(
    OvStoragePlugin_Error *plugin_error,
    bool free_outer)
{
    OvStorage_Error error;

    if (plugin_error == NULL) {
        return ovc_dispatch_public_error(OvStorage_Status_Internal,
                                         "plugin returned an invalid result");
    }
    error.code = ovc_status_from_plugin_code(plugin_error->code);
    error.message = plugin_error->message_ptr == NULL
                        ? NULL
                        : ovc_dispatch_slice_copy(
                              plugin_error->message_ptr,
                              plugin_error->message_len);
    if (error.message == NULL) {
        error.message = ovc_dispatch_cstring_copy("plugin operation failed");
    }
    error.code_name = ovc_plugin_error_code_name(plugin_error->code);
    ovc_dispatch_plugin_error_clear(plugin_error, free_outer);
    return error;
}

static void ovc_dispatch_error_done(OvStorage_Error *error)
{
    ovstorage_error_clear(error);
}

/* ------------------------------------------------------------------------- */
/* Handle ownership and in-flight draining. */

static bool ovc_dispatch_operation_enter(OvStorage_LayerHandle *handle)
{
    bool entered;

    if (handle == NULL) {
        return false;
    }
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    entered = !handle->closing && handle->in_flight != SIZE_MAX;
    if (entered) {
        ++handle->in_flight;
    }
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
    return entered;
}

/*
 * A queued invocation and its eventual completion have independent
 * lifetimes.  In particular, a Layer may invoke on_complete synchronously
 * and then continue using its state before returning from the vtable call.
 * Keep a second in-flight reference for that synchronous prologue so Stack
 * destruction cannot drop the Layer between the callback and slot return.
 */
static bool ovc_dispatch_invocation_retain(OvStorage_LayerHandle *handle)
{
    bool retained;

    if (handle == NULL) {
        return false;
    }
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    retained = handle->in_flight != SIZE_MAX;
    if (retained) {
        ++handle->in_flight;
    }
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
    return retained;
}

static void ovc_dispatch_operation_leave(OvStorage_LayerHandle *handle)
{
    if (handle == NULL) {
        return;
    }
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    if (handle->in_flight == 0) {
        ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
        abort();
    }
    --handle->in_flight;
    if (handle->closing && handle->in_flight == 0) {
        ovc_dispatch_sync_success(ovc_cond_broadcast(&handle->drained));
    }
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
}

static bool ovc_dispatch_register_pump(OvStorage_LayerHandle *handle,
                                       ovc_stream_pump *pump)
{
    ovc_dispatch_pump_link *link;

    link = (ovc_dispatch_pump_link *)malloc(sizeof(*link));
    if (link == NULL) {
        return false;
    }
    link->pump = pump;
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    if (handle->closing) {
        ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
        free(link);
        return false;
    }
    link->next = handle->pumps;
    handle->pumps = link;
    /* Publish and release the start barrier as one handle-locked action.
     * Destroy cannot detach/free the pump between registration and arm. */
    ovc_stream_pump_arm(pump);
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
    return true;
}

static ovc_dispatch_pump_link *ovc_dispatch_detach_pump(
    OvStorage_LayerHandle *handle,
    ovc_stream_pump *pump)
{
    ovc_dispatch_pump_link **cursor;
    ovc_dispatch_pump_link *found;

    found = NULL;
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    cursor = &handle->pumps;
    while (*cursor != NULL) {
        if ((*cursor)->pump == pump) {
            found = *cursor;
            *cursor = found->next;
            found->next = NULL;
            break;
        }
        cursor = &(*cursor)->next;
    }
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
    return found;
}

static void ovc_dispatch_restore_pump(OvStorage_LayerHandle *handle,
                                      ovc_dispatch_pump_link *link)
{
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    link->next = handle->pumps;
    handle->pumps = link;
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
}

static void ovc_dispatch_pump_reap_task(void *argument)
{
    ovc_stream_pump_destroy((ovc_stream_pump *)argument);
}

static void ovc_dispatch_reap_completed_pump(
    ovc_dispatch_operation *operation)
{
    ovc_dispatch_pump_link *link;
    ovc_stream_pump *pump;

    pump = operation->pump;
    operation->pump = NULL;
    if (pump == NULL) {
        return;
    }
    link = ovc_dispatch_detach_pump(operation->handle, pump);
    if (link == NULL) {
        /* Registration failed; the completing caller owns pump destruction. */
        return;
    }
    if (ovc_runtime_submit(ovc_dispatch_pump_reap_task, pump) == 0) {
        free(link);
        return;
    }
    /* Preserve teardown ownership if the process-global queue is exhausted. */
    ovc_dispatch_restore_pump(operation->handle, link);
}

/* Deliberately-private introspection twin of ovc_dispatch_layer_handle_create:
 * the cc-test declares it directly to pin that completed streams are reaped
 * from the handle before destroy rather than accumulating until teardown. */
size_t ovc_dispatch_registered_pump_count(OvStorage_LayerHandle *handle)
{
    size_t count;
    const ovc_dispatch_pump_link *link;

    count = 0;
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    for (link = handle->pumps; link != NULL; link = link->next) {
        ++count;
    }
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));
    return count;
}

/* ------------------------------------------------------------------------- */
/*
 * Refcounted root forwarding proxy (cross-language live handoff, RFC-0066).
 *
 * ovc_dispatch_layer_handle_create wraps every root in one of these
 * unconditionally, because handle->root is deliberately read without the
 * handle mutex once dispatch begins (ovc_dispatch_io_task_run copies it on
 * a pool worker; the connection slots call through it directly): re-seating
 * a live handle's root at export time would race those unlocked reads.
 * Wrapping at creation keeps "root is written exactly once" true while
 * still letting ovstorage_export_handle mint additional owned handles over
 * the same inner Layer — each proxy owns one refbox reference, and the
 * inner root is dropped when the last proxy drops, wherever that happens.
 *
 * The proxy state follows the ovstorage_defaults.h wrapper contract: the
 * inner handle stays the FIRST member so every OVSTORAGE_PASSTHROUGH_VTABLE
 * slot forwards unchanged, and only `drop` is replaced because the proxy
 * has storage of its own to reclaim.  The vtable copy lives in the refbox,
 * which outlives every proxy minted over it.
 */

typedef struct ovc_dispatch_root_refbox {
    OvStoragePlugin_LayerVTableV1 vtable;
    OvStoragePlugin_LayerHandle inner;
    ovc_ref_count references;
} ovc_dispatch_root_refbox;

typedef struct ovc_dispatch_root_proxy {
    /* Must stay first: the passthrough slots locate the child here. */
    OvStoragePlugin_LayerHandle inner;
    ovc_dispatch_root_refbox *refbox;
} ovc_dispatch_root_proxy;

#if !defined(_WIN32) && !defined(__GNUC__) && !defined(__clang__)
static ovc_mutex g_ovc_dispatch_proxy_reference_lock = OVC_MUTEX_INITIALIZER;
#endif

static bool ovc_dispatch_proxy_reference_retain(volatile long *references)
{
#if defined(_WIN32)
    long current;

    current = InterlockedCompareExchange(references, 0, 0);
    for (;;) {
        long observed;

        if (current <= 0 || current == LONG_MAX) {
            return false;
        }
        observed = InterlockedCompareExchange(references,
                                              current + 1,
                                              current);
        if (observed == current) {
            return true;
        }
        current = observed;
    }
#elif defined(__GNUC__) || defined(__clang__)
    long current;

    current = __sync_val_compare_and_swap(references, 0L, 0L);
    for (;;) {
        if (current <= 0 || current == LONG_MAX) {
            return false;
        }
        if (__sync_bool_compare_and_swap(references,
                                         current,
                                         current + 1)) {
            return true;
        }
        current = __sync_val_compare_and_swap(references, 0L, 0L);
    }
#else
    bool retained;

    (void)ovc_mutex_lock(&g_ovc_dispatch_proxy_reference_lock);
    retained = *references > 0 && *references < LONG_MAX;
    if (retained) {
        ++*references;
    }
    (void)ovc_mutex_unlock(&g_ovc_dispatch_proxy_reference_lock);
    return retained;
#endif
}

static bool ovc_dispatch_proxy_reference_release(volatile long *references)
{
#if defined(_WIN32)
    return InterlockedDecrement(references) == 0;
#elif defined(__GNUC__) || defined(__clang__)
    return __sync_sub_and_fetch(references, 1L) == 0;
#else
    bool last;

    (void)ovc_mutex_lock(&g_ovc_dispatch_proxy_reference_lock);
    --*references;
    last = *references == 0;
    (void)ovc_mutex_unlock(&g_ovc_dispatch_proxy_reference_lock);
    return last;
#endif
}

static void ovc_dispatch_root_proxy_drop(void *state)
{
    ovc_dispatch_root_proxy *proxy;
    ovc_dispatch_root_refbox *refbox;

    proxy = (ovc_dispatch_root_proxy *)state;
    if (proxy == NULL) {
        return;
    }
    refbox = proxy->refbox;
    free(proxy);
    if (!ovc_dispatch_proxy_reference_release(&refbox->references.value)) {
        return;
    }
    refbox->inner.vtable->drop(refbox->inner.state);
    free(refbox);
}

/* Mint one proxy handle over `refbox` without touching its reference
 * count: the caller transfers exactly one owned reference into `out`. */
static bool ovc_dispatch_root_proxy_mint(ovc_dispatch_root_refbox *refbox,
                                         OvStoragePlugin_LayerHandle *out)
{
    ovc_dispatch_root_proxy *proxy;

    proxy = (ovc_dispatch_root_proxy *)calloc(1, sizeof(*proxy));
    if (proxy == NULL) {
        return false;
    }
    proxy->inner = refbox->inner;
    proxy->refbox = refbox;
    out->state = proxy;
    out->vtable = &refbox->vtable;
    return true;
}

/* Adopt the validated raw root into a fresh refbox and mint its first
 * proxy.  On failure nothing has been adopted: the root stays with the
 * caller, preserving ovc_dispatch_layer_handle_create's failure contract. */
static bool ovc_dispatch_root_proxy_create(OvStoragePlugin_LayerHandle root,
                                           OvStoragePlugin_LayerHandle *out)
{
    ovc_dispatch_root_refbox *refbox;

    refbox = (ovc_dispatch_root_refbox *)calloc(1, sizeof(*refbox));
    if (refbox == NULL) {
        return false;
    }
    refbox->vtable = OVSTORAGE_PASSTHROUGH_VTABLE;
    refbox->vtable.drop = ovc_dispatch_root_proxy_drop;
    refbox->inner = root;
    refbox->references.value = 1L;
    if (!ovc_dispatch_root_proxy_mint(refbox, out)) {
        free(refbox);
        return false;
    }
    return true;
}

/* Every slot the dispatcher (or the passthrough proxy on its behalf) calls
 * unconditionally.  Shared by handle creation and ovstorage_import_handle,
 * which needs the same answer to pick the right typed error. */
static bool ovc_dispatch_root_slots_supported(
    const OvStoragePlugin_LayerVTableV1 *vtable)
{
    return vtable->drop != NULL && vtable->stat != NULL &&
           vtable->read != NULL && vtable->materialize != NULL &&
           vtable->write != NULL && vtable->delete_ != NULL &&
           vtable->list != NULL && vtable->list_versions != NULL &&
           vtable->copy != NULL && vtable->rename != NULL &&
           vtable->update_metadata != NULL &&
           vtable->check_access != NULL &&
           vtable->create_directory != NULL &&
           vtable->delete_directory != NULL &&
           vtable->add_connection != NULL &&
           vtable->list_connections != NULL &&
           vtable->remove_connection != NULL &&
           vtable->update_connection_credentials != NULL &&
           vtable->authenticate_connection != NULL &&
           vtable->list_address_roots != NULL &&
           vtable->write_stream != NULL &&
           vtable->write_redirect != NULL &&
           vtable->continue_write != NULL &&
           vtable->get_latest_version != NULL &&
           vtable->watch_directory != NULL &&
           vtable->probe != NULL &&
           vtable->update_connection_attributes != NULL;
}

OvStorage_LayerHandle *ovc_dispatch_layer_handle_create(
    OvStoragePlugin_LayerHandle root,
    ovc_layer_factory *const *factories,
    size_t factory_count)
{
    OvStorage_LayerHandle *handle;
    size_t index;

    if (root.vtable == NULL ||
        root.vtable->struct_size < sizeof(*root.vtable) ||
        root.vtable->abi_version !=
            OVSTORAGE_PLUGIN_ABI_VERSION ||
        !ovc_dispatch_root_slots_supported(root.vtable) ||
        (factory_count != 0 && factories == NULL) ||
        factory_count > SIZE_MAX / sizeof(*handle->factories)) {
        return NULL;
    }
    handle = (OvStorage_LayerHandle *)calloc(1, sizeof(*handle));
    if (handle == NULL) {
        return NULL;
    }
    if (ovc_mutex_init(&handle->mutex) != 0) {
        free(handle);
        return NULL;
    }
    if (ovc_cond_init(&handle->drained) != 0) {
        ovc_dispatch_sync_success(ovc_mutex_destroy(&handle->mutex));
        free(handle);
        return NULL;
    }
    if (factory_count != 0) {
        handle->factories = (ovc_layer_factory **)calloc(
            factory_count, sizeof(*handle->factories));
        if (handle->factories == NULL) {
            ovc_dispatch_sync_success(ovc_cond_destroy(&handle->drained));
            ovc_dispatch_sync_success(ovc_mutex_destroy(&handle->mutex));
            free(handle);
            return NULL;
        }
    }
    for (index = 0; index < factory_count; ++index) {
        handle->factories[index] = ovc_layer_factory_retain(factories[index]);
        if (handle->factories[index] == NULL) {
            size_t release_index;

            for (release_index = 0; release_index < index; ++release_index) {
                ovc_layer_factory_release(handle->factories[release_index]);
            }
            free(handle->factories);
            ovc_dispatch_sync_success(ovc_cond_destroy(&handle->drained));
            ovc_dispatch_sync_success(ovc_mutex_destroy(&handle->mutex));
            free(handle);
            return NULL;
        }
    }
    /* Wrap unconditionally (never re-seat a live handle's root): pool
     * workers read handle->root without the mutex, so this write must be
     * the only one the handle ever sees. */
    if (!ovc_dispatch_root_proxy_create(root, &handle->root)) {
        for (index = 0; index < factory_count; ++index) {
            ovc_layer_factory_release(handle->factories[index]);
        }
        free(handle->factories);
        ovc_dispatch_sync_success(ovc_cond_destroy(&handle->drained));
        ovc_dispatch_sync_success(ovc_mutex_destroy(&handle->mutex));
        free(handle);
        return NULL;
    }
    handle->factory_count = factory_count;
    return handle;
}

void ovstorage_layer_handle_destroy(OvStorage_LayerHandle *handle)
{
    ovc_dispatch_pump_link *pumps;
    ovc_dispatch_pump_link *link;
    size_t index;

    if (handle == NULL) {
        return;
    }
    ovc_dispatch_sync_success(ovc_mutex_lock(&handle->mutex));
    handle->closing = true;
    for (link = handle->pumps; link != NULL; link = link->next) {
        ovc_stream_pump_cancel(link->pump);
    }
    while (handle->in_flight != 0) {
        ovc_dispatch_sync_success(
            ovc_cond_wait(&handle->drained, &handle->mutex));
    }
    pumps = handle->pumps;
    handle->pumps = NULL;
    ovc_dispatch_sync_success(ovc_mutex_unlock(&handle->mutex));

    while (pumps != NULL) {
        ovc_dispatch_pump_link *next;

        next = pumps->next;
        ovc_stream_pump_destroy(pumps->pump);
        free(pumps);
        pumps = next;
    }
    if (handle->root.vtable != NULL && handle->root.vtable->drop != NULL) {
        handle->root.vtable->drop(handle->root.state);
    }
    memset(&handle->root, 0, sizeof(handle->root));
    for (index = 0; index < handle->factory_count; ++index) {
        ovc_layer_factory_release(handle->factories[index]);
    }
    free(handle->factories);
    ovc_dispatch_sync_success(ovc_cond_destroy(&handle->drained));
    ovc_dispatch_sync_success(ovc_mutex_destroy(&handle->mutex));
    free(handle);
}

/* ------------------------------------------------------------------------- */
/* Plugin result reclamation and public value conversion. */

static void ovc_dispatch_checksum_list_clear(
    OvStoragePlugin_List_ChecksumEntry *checksums)
{
    size_t index;

    if (checksums == NULL) {
        return;
    }
    if (checksums->ptr != NULL) {
        for (index = 0; index < checksums->len; ++index) {
            ovc_dispatch_abi_str_clear(
                &checksums->ptr[index].algorithm.token);
            ovc_dispatch_abi_bytes_clear(&checksums->ptr[index].bytes, false);
        }
    }
    ovc_abi_free(checksums->ptr);
    checksums->ptr = NULL;
    checksums->len = 0;
}

static void ovc_dispatch_object_info_clear(OvStoragePlugin_ObjectInfo *info,
                                           bool free_outer)
{
    if (info == NULL) {
        return;
    }
    ovc_dispatch_abi_str_clear(&info->address);
    if (info->etag.present) {
        ovc_dispatch_abi_str_clear(&info->etag.value);
    }
    if (info->version.present) {
        ovc_dispatch_abi_str_clear(&info->version.value);
    }
    ovc_dispatch_checksum_list_clear(&info->checksums);
    if (info->system_metadata.present) {
        ovc_dispatch_abi_key_values_clear(&info->system_metadata.value);
    }
    if (info->user_metadata.present) {
        ovc_dispatch_abi_key_values_clear(&info->user_metadata.value);
    }
    if (info->modified_by.present) {
        ovc_dispatch_abi_str_clear(&info->modified_by.value);
    }
    memset(info, 0, sizeof(*info));
    if (free_outer) {
        ovc_abi_free(info);
    }
}

static void ovc_dispatch_backend_item_clear(
    OvStoragePlugin_BackendItemInfo *info,
    bool free_outer)
{
    if (info == NULL) {
        return;
    }
    if (info->etag.present) {
        ovc_dispatch_abi_str_clear(&info->etag.value);
    }
    if (info->version.present) {
        ovc_dispatch_abi_str_clear(&info->version.value);
    }
    ovc_dispatch_checksum_list_clear(&info->checksums);
    if (info->system_metadata.present) {
        ovc_dispatch_abi_key_values_clear(&info->system_metadata.value);
    }
    if (info->user_metadata.present) {
        ovc_dispatch_abi_key_values_clear(&info->user_metadata.value);
    }
    if (info->modified_by.present) {
        ovc_dispatch_abi_str_clear(&info->modified_by.value);
    }
    memset(info, 0, sizeof(*info));
    if (free_outer) {
        ovc_abi_free(info);
    }
}

static void ovc_dispatch_http_request_clear(
    OvStoragePlugin_HttpRequest *request)
{
    ovc_dispatch_abi_str_clear(&request->method);
    ovc_dispatch_abi_str_clear(&request->url);
    ovc_dispatch_abi_key_values_clear(&request->headers);
}

static void ovc_dispatch_list_str_clear(OvStoragePlugin_List_Str *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    if (list->ptr != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_dispatch_abi_str_clear(&list->ptr[index]);
        }
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

static void ovc_dispatch_read_redirect_clear(
    OvStoragePlugin_ReadRedirect *redirect)
{
    size_t index;
    OvStoragePlugin_ResponseParsing *parsing;

    if (redirect == NULL) {
        return;
    }
    ovc_dispatch_http_request_clear(&redirect->request);
    parsing = &redirect->response_parsing;
    if (parsing->etag_header.present) {
        ovc_dispatch_abi_str_clear(&parsing->etag_header.value);
    }
    if (parsing->version_header.present) {
        ovc_dispatch_abi_str_clear(&parsing->version_header.value);
    }
    if (parsing->size_header.present) {
        ovc_dispatch_abi_str_clear(&parsing->size_header.value);
    }
    if (parsing->mtime_header.present) {
        ovc_dispatch_abi_str_clear(&parsing->mtime_header.value);
    }
    ovc_dispatch_list_str_clear(&parsing->system_metadata_headers);
    if (parsing->content_checksum_header.present) {
        ovc_dispatch_abi_str_clear(
            &parsing->content_checksum_header.value);
    }
    if (parsing->content_checksum_algorithm.present) {
        ovc_dispatch_abi_str_clear(
            &parsing->content_checksum_algorithm.value.token);
    }
    if (parsing->checksum_headers.ptr != NULL) {
        for (index = 0; index < parsing->checksum_headers.len; ++index) {
            ovc_dispatch_abi_str_clear(
                &parsing->checksum_headers.ptr[index].algorithm.token);
            ovc_dispatch_abi_str_clear(
                &parsing->checksum_headers.ptr[index].header);
        }
    }
    ovc_abi_free(parsing->checksum_headers.ptr);
    ovc_dispatch_abi_str_clear(&redirect->scope.physical_url_prefix);
    ovc_dispatch_abi_str_clear(&redirect->audit_id);
    memset(redirect, 0, sizeof(*redirect));
}

static void ovc_dispatch_read_result_clear(OvStoragePlugin_ReadResult *result,
                                           bool free_outer)
{
    if (result == NULL) {
        return;
    }
    switch (result->tag) {
    case OvStoragePlugin_ReadResultTag_Bytes:
        ovc_dispatch_abi_bytes_clear(&result->bytes.bytes, false);
        ovc_dispatch_object_info_clear(&result->bytes.info, false);
        break;
    case OvStoragePlugin_ReadResultTag_LocalDelegate:
        ovc_dispatch_abi_str_clear(&result->local_delegate.path);
        ovc_dispatch_object_info_clear(&result->local_delegate.info, false);
        /* Release the delegate's optional eviction lease; mirrors
         * the Stream case's drop_fn discharge below. */
        if (result->local_delegate.lease.drop_fn != NULL) {
            result->local_delegate.lease.drop_fn(
                result->local_delegate.lease.state);
        }
        break;
    case OvStoragePlugin_ReadResultTag_Redirect:
        ovc_dispatch_read_redirect_clear(&result->redirect);
        break;
    case OvStoragePlugin_ReadResultTag_Stream:
        if (result->stream.stream.drop_fn != NULL) {
            result->stream.stream.drop_fn(result->stream.stream.state);
        }
        memset(&result->stream.stream, 0, sizeof(result->stream.stream));
        ovc_dispatch_object_info_clear(&result->stream.info, false);
        break;
    default:
        break;
    }
    memset(result, 0, sizeof(*result));
    if (free_outer) {
        ovc_abi_free(result);
    }
}

static void ovc_dispatch_write_result_clear(
    OvStoragePlugin_WriteResult *result)
{
    if (result == NULL) {
        return;
    }
    ovc_dispatch_object_info_clear(&result->info, false);
    ovc_abi_free(result);
}

static void ovc_dispatch_write_redirect_clear(
    OvStoragePlugin_WriteRedirect *redirect)
{
    if (redirect == NULL) {
        return;
    }
    ovc_dispatch_http_request_clear(&redirect->request);
    if (redirect->body_source.tag ==
        OvStoragePlugin_RedirectBodySourceTag_Inline) {
        ovc_dispatch_abi_bytes_clear(&redirect->body_source.inline_, false);
    }
    ovc_dispatch_list_str_clear(&redirect->result_capture.headers);
    ovc_dispatch_abi_str_clear(&redirect->scope.physical_url_prefix);
    ovc_dispatch_abi_str_clear(&redirect->audit_id);
    memset(redirect, 0, sizeof(*redirect));
}

static void ovc_dispatch_write_redirect_batch_clear(
    OvStoragePlugin_WriteRedirectBatch *batch)
{
    size_t index;

    if (batch == NULL) {
        return;
    }
    ovc_dispatch_abi_bytes_clear(&batch->continuation, false);
    if (batch->redirects.ptr != NULL) {
        for (index = 0; index < batch->redirects.len; ++index) {
            ovc_dispatch_write_redirect_clear(&batch->redirects.ptr[index]);
        }
    }
    ovc_abi_free(batch->redirects.ptr);
    memset(batch, 0, sizeof(*batch));
}

static void ovc_dispatch_write_step_clear(OvStoragePlugin_WriteStep *step)
{
    if (step == NULL) {
        return;
    }
    if (step->tag == OvStoragePlugin_WriteStepTag_Done) {
        ovc_dispatch_object_info_clear(&step->done.info, false);
    } else if (step->tag == OvStoragePlugin_WriteStepTag_Redirects) {
        ovc_dispatch_write_redirect_batch_clear(&step->redirects);
    }
    ovc_abi_free(step);
}

static void ovc_dispatch_redirect_result_batch_clear(
    OvStoragePlugin_RedirectResultBatch *batch)
{
    size_t index;

    if (batch == NULL) {
        return;
    }
    if (batch->results.ptr != NULL) {
        for (index = 0; index < batch->results.len; ++index) {
            ovc_dispatch_abi_key_values_clear(
                &batch->results.ptr[index].captured_headers);
            ovc_dispatch_abi_bytes_clear(
                &batch->results.ptr[index].captured_body, false);
        }
    }
    ovc_abi_free(batch->results.ptr);
    memset(batch, 0, sizeof(*batch));
}

static void ovc_dispatch_public_redirect_clear(
    OvStorage_WriteRedirect *redirect)
{
    size_t index;

    if (redirect == NULL) {
        return;
    }
    free((char *)redirect->method);
    free((char *)redirect->url);
    if (redirect->headers != NULL) {
        for (index = 0; index < redirect->headers_len; ++index) {
            free((char *)redirect->headers[index].name);
            free((char *)redirect->headers[index].value);
        }
    }
    free((OvStorage_Header *)redirect->headers);
    free((uint8_t *)redirect->inline_body);
    if (redirect->capture_headers != NULL) {
        for (index = 0; index < redirect->capture_headers_len; ++index) {
            free((char *)redirect->capture_headers[index]);
        }
    }
    free((char **)redirect->capture_headers);
    free((char *)redirect->scope_physical_url_prefix);
    free((char *)redirect->audit_id);
    memset(redirect, 0, sizeof(*redirect));
}

void ovstorage_write_redirect_batch_destroy(OvStorage_WriteRedirectBatch *batch)
{
    size_t index;

    if (batch == NULL) {
        return;
    }
    free((uint8_t *)batch->continuation);
    if (batch->redirects != NULL) {
        for (index = 0; index < batch->redirects_len; ++index) {
            ovc_dispatch_public_redirect_clear(&batch->redirects[index]);
        }
    }
    free(batch->redirects);
    memset(batch, 0, sizeof(*batch));
    free(batch);
}

static bool ovc_dispatch_public_raw_bytes_copy(const uint8_t **out,
                                               const uint8_t *source,
                                               size_t length)
{
    uint8_t *copy;

    *out = NULL;
    if (source == NULL && length != 0) {
        return false;
    }
    if (length == 0) {
        return true;
    }
    copy = (uint8_t *)malloc(length);
    if (copy == NULL) {
        return false;
    }
    memcpy(copy, source, length);
    *out = copy;
    return true;
}

static bool ovc_dispatch_public_redirect_from_plugin(
    OvStorage_WriteRedirect *out,
    const OvStoragePlugin_WriteRedirect *source)
{
    OvStorage_Header *headers;
    char **capture_headers;
    size_t index;

    memset(out, 0, sizeof(*out));
    if (source->body_source.tag >
            OvStoragePlugin_RedirectBodySourceTag_Inline ||
        (int)source->scope.credential < 0 ||
        source->scope.credential >
            OvStoragePlugin_RedirectCredential_Connection ||
        (source->request.headers.ptr == NULL &&
         source->request.headers.len != 0) ||
        (source->result_capture.headers.ptr == NULL &&
         source->result_capture.headers.len != 0) ||
        source->expires_at_unix_ms < 0 ||
        source->scope.expires_at_unix_ms < 0 ||
        (source->body_source.tag ==
             OvStoragePlugin_RedirectBodySourceTag_UserBytes &&
         source->body_source.user_bytes.offset >
             UINT64_MAX - source->body_source.user_bytes.len) ||
        (uint64_t)source->expires_at_unix_ms >
            UINT64_MAX / UINT64_C(1000000) ||
        (uint64_t)source->scope.expires_at_unix_ms >
            UINT64_MAX / UINT64_C(1000000)) {
        return false;
    }
    out->method = ovc_dispatch_slice_copy(source->request.method.ptr,
                                          source->request.method.len);
    out->url = ovc_dispatch_slice_copy(source->request.url.ptr,
                                       source->request.url.len);
    out->scope_physical_url_prefix = ovc_dispatch_slice_copy(
        source->scope.physical_url_prefix.ptr,
        source->scope.physical_url_prefix.len);
    out->audit_id = ovc_dispatch_slice_copy(source->audit_id.ptr,
                                            source->audit_id.len);
    if (out->method == NULL || out->url == NULL ||
        out->scope_physical_url_prefix == NULL ||
        out->audit_id == NULL) {
        ovc_dispatch_public_redirect_clear(out);
        return false;
    }

    if (source->request.headers.len >
        SIZE_MAX / sizeof(*headers)) {
        ovc_dispatch_public_redirect_clear(out);
        return false;
    }
    headers = source->request.headers.len == 0
                  ? NULL
                  : (OvStorage_Header *)calloc(
                        source->request.headers.len, sizeof(*headers));
    if (source->request.headers.len != 0 && headers == NULL) {
        ovc_dispatch_public_redirect_clear(out);
        return false;
    }
    out->headers = headers;
    out->headers_len = source->request.headers.len;
    for (index = 0; index < out->headers_len; ++index) {
        headers[index].name = ovc_dispatch_slice_copy(
            source->request.headers.ptr[index].key.ptr,
            source->request.headers.ptr[index].key.len);
        headers[index].value = ovc_dispatch_slice_copy(
            source->request.headers.ptr[index].value.ptr,
            source->request.headers.ptr[index].value.len);
        if (headers[index].name == NULL || headers[index].value == NULL) {
            ovc_dispatch_public_redirect_clear(out);
            return false;
        }
    }

    out->body_source_kind =
        (OvStorage_RedirectBodySourceKind)source->body_source.tag;
    if (source->body_source.tag ==
        OvStoragePlugin_RedirectBodySourceTag_UserBytes) {
        out->body_offset = source->body_source.user_bytes.offset;
        out->body_len = source->body_source.user_bytes.len;
    } else if (source->body_source.tag ==
               OvStoragePlugin_RedirectBodySourceTag_Inline) {
        if (!ovc_dispatch_public_raw_bytes_copy(
                &out->inline_body,
                source->body_source.inline_.ptr,
                source->body_source.inline_.len)) {
            ovc_dispatch_public_redirect_clear(out);
            return false;
        }
        out->inline_body_len = source->body_source.inline_.len;
    }

    if (source->result_capture.headers.len >
        SIZE_MAX / sizeof(*capture_headers)) {
        ovc_dispatch_public_redirect_clear(out);
        return false;
    }
    capture_headers =
        source->result_capture.headers.len == 0
            ? NULL
            : (char **)calloc(source->result_capture.headers.len,
                              sizeof(*capture_headers));
    if (source->result_capture.headers.len != 0 &&
        capture_headers == NULL) {
        ovc_dispatch_public_redirect_clear(out);
        return false;
    }
    out->capture_headers = (const char *const *)capture_headers;
    out->capture_headers_len = source->result_capture.headers.len;
    for (index = 0; index < out->capture_headers_len; ++index) {
        capture_headers[index] = ovc_dispatch_slice_copy(
            source->result_capture.headers.ptr[index].ptr,
            source->result_capture.headers.ptr[index].len);
        if (capture_headers[index] == NULL) {
            ovc_dispatch_public_redirect_clear(out);
            return false;
        }
    }
    out->capture_body_max_bytes =
        source->result_capture.body_max_bytes;
    /* An expiry that is negative or overflows nanoseconds is reported as
     * the epoch — already expired. The header requires a caller to check
     * freshness before using a redirect, so the fail-safe answer for a
     * timestamp we cannot represent is the one that fails that check,
     * not a wrapped value that reads as far in the future. */
    out->expires_at_unix_nanos = 0;
    if (source->expires_at_unix_ms >= 0 &&
        (uint64_t)source->expires_at_unix_ms <=
            UINT64_MAX / UINT64_C(1000000)) {
        out->expires_at_unix_nanos =
            (uint64_t)source->expires_at_unix_ms * UINT64_C(1000000);
    }
    out->scope_operations.read = source->scope.operations.read;
    out->scope_operations.write = source->scope.operations.write;
    out->scope_operations.delete_ = source->scope.operations.delete_;
    out->scope_operations.update_metadata =
        source->scope.operations.update_metadata;
    out->scope_expires_at_unix_nanos = 0;
    if (source->scope.expires_at_unix_ms >= 0 &&
        (uint64_t)source->scope.expires_at_unix_ms <=
            UINT64_MAX / UINT64_C(1000000)) {
        out->scope_expires_at_unix_nanos =
            (uint64_t)source->scope.expires_at_unix_ms * UINT64_C(1000000);
    }
    out->scope_credential =
        (OvStorage_RedirectCredential)source->scope.credential;
    out->policy_epoch = source->policy_epoch;
    return true;
}

static OvStorage_WriteRedirectBatch *
ovc_dispatch_public_redirect_batch_from_plugin(
    const OvStoragePlugin_WriteRedirectBatch *source)
{
    OvStorage_WriteRedirectBatch *out;
    size_t index;

    if (source == NULL ||
        (source->redirects.ptr == NULL && source->redirects.len != 0) ||
        source->redirects.len > SIZE_MAX / sizeof(*out->redirects)) {
        return NULL;
    }
    out = (OvStorage_WriteRedirectBatch *)calloc(1, sizeof(*out));
    if (out == NULL) {
        return NULL;
    }
    if (!ovc_dispatch_public_raw_bytes_copy(
            &out->continuation,
            source->continuation.ptr,
            source->continuation.len)) {
        ovstorage_write_redirect_batch_destroy(out);
        return NULL;
    }
    out->continuation_len = source->continuation.len;
    if (source->redirects.len != 0) {
        out->redirects = (OvStorage_WriteRedirect *)calloc(
            source->redirects.len, sizeof(*out->redirects));
        if (out->redirects == NULL) {
            ovstorage_write_redirect_batch_destroy(out);
            return NULL;
        }
    }
    out->redirects_len = source->redirects.len;
    for (index = 0; index < out->redirects_len; ++index) {
        if (!ovc_dispatch_public_redirect_from_plugin(
                &out->redirects[index], &source->redirects.ptr[index])) {
            ovstorage_write_redirect_batch_destroy(out);
            return NULL;
        }
    }
    return out;
}

static bool ovc_dispatch_redirect_to_plugin(
    OvStoragePlugin_WriteRedirect *out,
    const OvStorage_WriteRedirect *source)
{
    size_t capacity;
    size_t index;

    memset(out, 0, sizeof(*out));
    if (source == NULL ||
        source->body_source_kind > OvStorage_RedirectBodySourceKind_Inline ||
        (int)source->scope_credential < 0 ||
        source->scope_credential >
            OvStorage_RedirectCredential_Connection ||
        source->method == NULL || source->url == NULL ||
        source->scope_physical_url_prefix == NULL ||
        source->audit_id == NULL ||
        (source->headers == NULL && source->headers_len != 0) ||
        (source->capture_headers == NULL &&
         source->capture_headers_len != 0) ||
        (source->inline_body == NULL && source->inline_body_len != 0) ||
        !ovc_dispatch_utf8_valid(source->method) ||
        !ovc_dispatch_utf8_valid(source->url) ||
        !ovc_dispatch_utf8_valid(source->scope_physical_url_prefix) ||
        !ovc_dispatch_utf8_valid(source->audit_id)) {
        return false;
    }
    if (!ovc_dispatch_abi_cstring_copy(&out->request.method,
                                       source->method) ||
        !ovc_dispatch_abi_cstring_copy(&out->request.url,
                                       source->url) ||
        !ovc_dispatch_abi_cstring_copy(
            &out->scope.physical_url_prefix,
            source->scope_physical_url_prefix) ||
        !ovc_dispatch_abi_cstring_copy(&out->audit_id,
                                       source->audit_id)) {
        ovc_dispatch_write_redirect_clear(out);
        return false;
    }

    capacity = source->headers_len == 0 ? 1 : source->headers_len;
    if (capacity > SIZE_MAX / sizeof(*out->request.headers.ptr)) {
        ovc_dispatch_write_redirect_clear(out);
        return false;
    }
    out->request.headers.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
            capacity * sizeof(*out->request.headers.ptr));
    if (out->request.headers.ptr == NULL) {
        ovc_dispatch_write_redirect_clear(out);
        return false;
    }
    memset(out->request.headers.ptr,
           0,
           capacity * sizeof(*out->request.headers.ptr));
    for (index = 0; index < source->headers_len; ++index) {
        if (source->headers[index].name == NULL ||
            source->headers[index].value == NULL ||
            !ovc_dispatch_utf8_valid(source->headers[index].name) ||
            !ovc_dispatch_utf8_valid(source->headers[index].value) ||
            !ovc_dispatch_abi_cstring_copy(
                &out->request.headers.ptr[index].key,
                source->headers[index].name) ||
            !ovc_dispatch_abi_cstring_copy(
                &out->request.headers.ptr[index].value,
                source->headers[index].value)) {
            out->request.headers.len = index + 1;
            ovc_dispatch_write_redirect_clear(out);
            return false;
        }
        out->request.headers.len = index + 1;
    }

    out->body_source.tag =
        (OvStoragePlugin_RedirectBodySourceTag)source->body_source_kind;
    if (source->body_source_kind ==
        OvStorage_RedirectBodySourceKind_UserBytes) {
        out->body_source.user_bytes.offset = source->body_offset;
        out->body_source.user_bytes.len = source->body_len;
    } else if (source->body_source_kind ==
               OvStorage_RedirectBodySourceKind_Inline) {
        if (!ovc_dispatch_abi_bytes_copy(&out->body_source.inline_,
                                         source->inline_body,
                                         source->inline_body_len)) {
            ovc_dispatch_write_redirect_clear(out);
            return false;
        }
    }

    capacity = source->capture_headers_len == 0
                   ? 1
                   : source->capture_headers_len;
    if (capacity >
        SIZE_MAX / sizeof(*out->result_capture.headers.ptr)) {
        ovc_dispatch_write_redirect_clear(out);
        return false;
    }
    out->result_capture.headers.ptr =
        (OvStoragePlugin_Str *)ovc_abi_alloc(
            capacity * sizeof(*out->result_capture.headers.ptr));
    if (out->result_capture.headers.ptr == NULL) {
        ovc_dispatch_write_redirect_clear(out);
        return false;
    }
    memset(out->result_capture.headers.ptr,
           0,
           capacity * sizeof(*out->result_capture.headers.ptr));
    for (index = 0; index < source->capture_headers_len; ++index) {
        if (source->capture_headers[index] == NULL ||
            !ovc_dispatch_utf8_valid(source->capture_headers[index]) ||
            !ovc_dispatch_abi_cstring_copy(
                &out->result_capture.headers.ptr[index],
                source->capture_headers[index])) {
            out->result_capture.headers.len = index + 1;
            ovc_dispatch_write_redirect_clear(out);
            return false;
        }
        out->result_capture.headers.len = index + 1;
    }
    out->result_capture.body_max_bytes =
        source->capture_body_max_bytes;
    out->expires_at_unix_ms =
        (int64_t)(source->expires_at_unix_nanos /
                  UINT64_C(1000000));
    out->scope.operations.read = source->scope_operations.read;
    out->scope.operations.write = source->scope_operations.write;
    out->scope.operations.delete_ = source->scope_operations.delete_;
    out->scope.operations.update_metadata =
        source->scope_operations.update_metadata;
    out->scope.expires_at_unix_ms =
        (int64_t)(source->scope_expires_at_unix_nanos /
                  UINT64_C(1000000));
    out->scope.credential =
        (OvStoragePlugin_RedirectCredential)source->scope_credential;
    out->policy_epoch = source->policy_epoch;
    return true;
}

static bool ovc_dispatch_redirect_batch_to_plugin(
    OvStoragePlugin_WriteRedirectBatch *out,
    const OvStorage_WriteRedirectBatch *source)
{
    size_t capacity;
    size_t index;

    memset(out, 0, sizeof(*out));
    if (source == NULL ||
        (source->continuation == NULL && source->continuation_len != 0) ||
        (source->redirects == NULL && source->redirects_len != 0)) {
        return false;
    }
    if (!ovc_dispatch_abi_bytes_copy(&out->continuation,
                                     source->continuation,
                                     source->continuation_len)) {
        return false;
    }
    capacity = source->redirects_len == 0 ? 1 : source->redirects_len;
    if (capacity > SIZE_MAX / sizeof(*out->redirects.ptr)) {
        ovc_dispatch_write_redirect_batch_clear(out);
        return false;
    }
    out->redirects.ptr = (OvStoragePlugin_WriteRedirect *)ovc_abi_alloc(
        capacity * sizeof(*out->redirects.ptr));
    if (out->redirects.ptr == NULL) {
        ovc_dispatch_write_redirect_batch_clear(out);
        return false;
    }
    memset(out->redirects.ptr,
           0,
           capacity * sizeof(*out->redirects.ptr));
    for (index = 0; index < source->redirects_len; ++index) {
        if (!ovc_dispatch_redirect_to_plugin(
                &out->redirects.ptr[index], &source->redirects[index])) {
            out->redirects.len = index + 1;
            ovc_dispatch_write_redirect_batch_clear(out);
            return false;
        }
        out->redirects.len = index + 1;
    }
    return true;
}

static bool ovc_dispatch_redirect_results_to_plugin(
    OvStoragePlugin_RedirectResultBatch *out,
    const OvStorage_RedirectResultBatch *source,
    const OvStorage_WriteRedirectBatch *redirects)
{
    OvStoragePlugin_RedirectResult *result;
    size_t capacity;
    size_t header_capacity;
    size_t index;
    size_t header_index;

    memset(out, 0, sizeof(*out));
    if (source == NULL || redirects == NULL ||
        source->results_len != redirects->redirects_len ||
        (source->results == NULL && source->results_len != 0)) {
        return false;
    }
    capacity = source->results_len == 0 ? 1 : source->results_len;
    if (capacity > SIZE_MAX / sizeof(*out->results.ptr)) {
        return false;
    }
    out->results.ptr = (OvStoragePlugin_RedirectResult *)ovc_abi_alloc(
        capacity * sizeof(*out->results.ptr));
    if (out->results.ptr == NULL) {
        return false;
    }
    memset(out->results.ptr,
           0,
           capacity * sizeof(*out->results.ptr));
    for (index = 0; index < source->results_len; ++index) {
        const OvStorage_RedirectResult *public_result;

        public_result = &source->results[index];
        result = &out->results.ptr[index];
        out->results.len = index + 1;
        if ((public_result->captured_headers == NULL &&
             public_result->captured_headers_len != 0) ||
            (public_result->captured_body == NULL &&
             public_result->captured_body_len != 0) ||
            public_result->captured_body_len >
                redirects->redirects[index].capture_body_max_bytes) {
            ovc_dispatch_redirect_result_batch_clear(out);
            return false;
        }
        result->status_code = public_result->status_code;
        header_capacity = public_result->captured_headers_len == 0
                              ? 1
                              : public_result->captured_headers_len;
        if (header_capacity >
            SIZE_MAX / sizeof(*result->captured_headers.ptr)) {
            ovc_dispatch_redirect_result_batch_clear(out);
            return false;
        }
        result->captured_headers.ptr =
            (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
                header_capacity *
                sizeof(*result->captured_headers.ptr));
        if (result->captured_headers.ptr == NULL) {
            ovc_dispatch_redirect_result_batch_clear(out);
            return false;
        }
        memset(result->captured_headers.ptr,
               0,
               header_capacity *
                   sizeof(*result->captured_headers.ptr));
        for (header_index = 0;
             header_index < public_result->captured_headers_len;
             ++header_index) {
            const OvStorage_Header *header;

            header = &public_result->captured_headers[header_index];
            if (header->name == NULL || header->value == NULL ||
                !ovc_dispatch_utf8_valid(header->name) ||
                !ovc_dispatch_utf8_valid(header->value) ||
                !ovc_dispatch_abi_cstring_copy(
                    &result->captured_headers.ptr[header_index].key,
                    header->name) ||
                !ovc_dispatch_abi_cstring_copy(
                    &result->captured_headers.ptr[header_index].value,
                    header->value)) {
                result->captured_headers.len = header_index + 1;
                ovc_dispatch_redirect_result_batch_clear(out);
                return false;
            }
            result->captured_headers.len = header_index + 1;
        }
        if (!ovc_dispatch_abi_bytes_copy(
                &result->captured_body,
                public_result->captured_body,
                public_result->captured_body_len)) {
            ovc_dispatch_redirect_result_batch_clear(out);
            return false;
        }
    }
    return true;
}

/*
 * When filter_nuls is set, keys and values DROP interior NULs instead of
 * failing (the connection converter needs this); the strict Info/RootInfo
 * callers keep rejecting them. Note this differs from the escaping the
 * auth-event strings use — see ovc_dispatch_slice_copy_lossy.
 */
static bool ovc_dispatch_metadata_copy(ovc_metadata_entry **out_entries,
                                       size_t *out_len,
                                       const OvStoragePlugin_KeyValueList *source,
                                       bool filter_nuls)
{
    char *(*copy_fn)(const char *, size_t);
    ovc_metadata_entry *entries;
    size_t index;

    copy_fn =
        filter_nuls ? ovc_dispatch_slice_copy_filtered : ovc_dispatch_slice_copy;
    *out_entries = NULL;
    *out_len = 0;
    if (source == NULL || source->len == 0) {
        return true;
    }
    if (source->ptr == NULL) {
        return false;
    }
    if (source->ptr == NULL ||
        source->len > SIZE_MAX / sizeof(*entries)) {
        return false;
    }
    entries = (ovc_metadata_entry *)calloc(source->len, sizeof(*entries));
    if (entries == NULL) {
        return false;
    }
    for (index = 0; index < source->len; ++index) {
        if (source->ptr[index].key.ptr == NULL ||
            source->ptr[index].value.ptr == NULL) {
            size_t clear_index;

            for (clear_index = 0; clear_index < index; ++clear_index) {
                free((void *)entries[clear_index].key);
                free((void *)entries[clear_index].value);
            }
            free(entries);
            return false;
        }
        entries[index].key = copy_fn(
            source->ptr[index].key.ptr, source->ptr[index].key.len);
        entries[index].value = copy_fn(
            source->ptr[index].value.ptr, source->ptr[index].value.len);
        if (entries[index].key == NULL || entries[index].value == NULL) {
            size_t clear_index;

            for (clear_index = 0; clear_index <= index; ++clear_index) {
                free((void *)entries[clear_index].key);
                free((void *)entries[clear_index].value);
            }
            free(entries);
            return false;
        }
    }
    *out_entries = entries;
    *out_len = source->len;
    return true;
}

/* Permission bit positions in `OvStoragePlugin_EffectivePermissions`. The
 * plugin ABI documents them as `READ = 1<<0 .. UPDATE_METADATA = 1<<3` and
 * tells consumers to ignore unknown bits, so this decodes the four it knows
 * into the header's own `OvStorage_AccessOps` rather than republishing a
 * bitset the C surface does not otherwise use. */
#define OVC_DISPATCH_PERMISSION_READ (UINT32_C(1) << 0)
#define OVC_DISPATCH_PERMISSION_WRITE (UINT32_C(1) << 1)
#define OVC_DISPATCH_PERMISSION_DELETE (UINT32_C(1) << 2)
#define OVC_DISPATCH_PERMISSION_UPDATE_METADATA (UINT32_C(1) << 3)

static OvStorage_AccessOps ovc_dispatch_access_ops_from_bits(uint32_t bits)
{
    OvStorage_AccessOps ops;

    memset(&ops, 0, sizeof(ops));
    ops.read = (bits & OVC_DISPATCH_PERMISSION_READ) != 0;
    ops.write = (bits & OVC_DISPATCH_PERMISSION_WRITE) != 0;
    ops.delete_ = (bits & OVC_DISPATCH_PERMISSION_DELETE) != 0;
    ops.update_metadata =
        (bits & OVC_DISPATCH_PERMISSION_UPDATE_METADATA) != 0;
    return ops;
}

static bool ovc_dispatch_checksums_copy(
    OvStorage_ChecksumEntry **out_entries,
    size_t *out_len,
    const OvStoragePlugin_List_ChecksumEntry *source)
{
    OvStorage_ChecksumEntry *entries;
    uint8_t *bytes;
    size_t index;

    *out_entries = NULL;
    *out_len = 0;
    if (source == NULL || source->len == 0) {
        return true;
    }
    if (source->ptr == NULL || source->len > SIZE_MAX / sizeof(*entries)) {
        return false;
    }
    entries = (OvStorage_ChecksumEntry *)calloc(source->len, sizeof(*entries));
    if (entries == NULL) {
        return false;
    }
    for (index = 0; index < source->len; ++index) {
        if (source->ptr[index].algorithm.token.ptr == NULL) {
            ovc_checksums_destroy(entries, index);
            return false;
        }
        entries[index].algorithm = ovc_dispatch_slice_copy(
            source->ptr[index].algorithm.token.ptr,
            source->ptr[index].algorithm.token.len);
        if (entries[index].algorithm == NULL) {
            ovc_checksums_destroy(entries, index + 1);
            return false;
        }
        entries[index].bytes_len = source->ptr[index].bytes.len;
        if (source->ptr[index].bytes.len != 0) {
            if (source->ptr[index].bytes.ptr == NULL) {
                ovc_checksums_destroy(entries, index + 1);
                return false;
            }
            bytes = (uint8_t *)malloc(source->ptr[index].bytes.len);
            if (bytes == NULL) {
                ovc_checksums_destroy(entries, index + 1);
                return false;
            }
            memcpy(bytes,
                   source->ptr[index].bytes.ptr,
                   source->ptr[index].bytes.len);
            entries[index].bytes = bytes;
        }
    }
    *out_entries = entries;
    *out_len = source->len;
    return true;
}

static OvStorage_Info *ovc_dispatch_info_from_object(
    const OvStoragePlugin_ObjectInfo *source)
{
    OvStorage_Info *info;
    ovc_metadata_entry *metadata;
    OvStorage_ChecksumEntry *checksums;

    if (source == NULL || source->address.ptr == NULL || source->kind >
                              OvStoragePlugin_ObjectKindV1_DirectoryInferred) {
        return NULL;
    }
    info = (OvStorage_Info *)calloc(1, sizeof(*info));
    if (info == NULL) {
        return NULL;
    }
    info->address = ovc_dispatch_slice_copy(source->address.ptr,
                                            source->address.len);
    info->kind = (OvStorage_ObjectKind)source->kind;
    if (info->address == NULL) {
        ovstorage_info_destroy(info);
        return NULL;
    }
    if (source->size.present) {
        info->has_size = true;
        info->size = source->size.value;
    }
    if (source->mtime_unix_ms.present &&
        source->mtime_unix_ms.value >= 0 &&
        (uint64_t)source->mtime_unix_ms.value <=
            UINT64_MAX / UINT64_C(1000000)) {
        info->has_mtime_unix_nanos = true;
        info->mtime_unix_nanos =
            (uint64_t)source->mtime_unix_ms.value * UINT64_C(1000000);
    }
    if (source->etag.present) {
        info->etag = ovc_dispatch_slice_copy(source->etag.value.ptr,
                                             source->etag.value.len);
        if (info->etag == NULL) {
            ovstorage_info_destroy(info);
            return NULL;
        }
    }
    if (source->version.present) {
        info->version = ovc_dispatch_slice_copy(source->version.value.ptr,
                                                source->version.value.len);
        if (info->version == NULL) {
            ovstorage_info_destroy(info);
            return NULL;
        }
    }
    if (source->user_metadata.present) {
        metadata = NULL;
        if (!ovc_dispatch_metadata_copy(&metadata,
                                        &info->user_metadata_len,
                                        &source->user_metadata.value,
                                        false)) {
            ovstorage_info_destroy(info);
            return NULL;
        }
        info->user_metadata = metadata;
    }
    if (source->system_metadata.present) {
        metadata = NULL;
        if (!ovc_dispatch_metadata_copy(&metadata,
                                        &info->system_metadata_len,
                                        &source->system_metadata.value,
                                        false)) {
            ovstorage_info_destroy(info);
            return NULL;
        }
        info->system_metadata = metadata;
    }
    if (source->modified_by.present) {
        info->modified_by = ovc_dispatch_slice_copy(
            source->modified_by.value.ptr, source->modified_by.value.len);
        if (info->modified_by == NULL) {
            ovstorage_info_destroy(info);
            return NULL;
        }
    }
    if (source->effective_permissions.present) {
        info->has_effective_permissions = true;
        info->effective_permissions = ovc_dispatch_access_ops_from_bits(
            source->effective_permissions.value.bits);
    }
    checksums = NULL;
    if (!ovc_dispatch_checksums_copy(
            &checksums, &info->checksums_len, &source->checksums)) {
        ovstorage_info_destroy(info);
        return NULL;
    }
    info->checksums = checksums;
    return info;
}

static OvStorage_Info *ovc_dispatch_info_from_backend_item(
    const OvStoragePlugin_BackendItemInfo *source,
    const char *address)
{
    OvStoragePlugin_ObjectInfo object;

    if (source == NULL || address == NULL) {
        return NULL;
    }
    memset(&object, 0, sizeof(object));
    object.address.ptr = (char *)address;
    object.address.len = strlen(address);
    object.kind = source->kind;
    object.etag = source->etag;
    object.version = source->version;
    object.size = source->size;
    object.mtime_unix_ms = source->mtime_unix_ms;
    object.user_metadata = source->user_metadata;
    object.system_metadata = source->system_metadata;
    return ovc_dispatch_info_from_object(&object);
}

static bool ovc_dispatch_public_bytes_copy(OvStorage_Bytes *out,
                                           const uint8_t *data,
                                           size_t length)
{
    uint8_t *allocation;

    memset(out, 0, sizeof(*out));
    if (data == NULL && length != 0) {
        return false;
    }
    allocation = (uint8_t *)malloc(length == 0 ? 1 : length);
    if (allocation == NULL) {
        return false;
    }
    if (length == 0) {
        allocation[0] = 0;
    } else {
        memcpy(allocation, data, length);
    }
    out->data = allocation;
    out->len = length;
    out->free_ctx = allocation;
    return true;
}

static void ovc_dispatch_capabilities_copy(
    OvStorage_Capabilities *out,
    const OvStoragePlugin_Capabilities *source)
{
    memset(out, 0, sizeof(*out));
    out->supports_if_match_write = source->supports_if_match_write;
    out->supports_no_overwrite_write =
        source->supports_no_overwrite_write;
    out->supports_native_metadata_patch =
        source->supports_native_metadata_patch;
    out->supports_metadata_rewrite_emulation =
        source->supports_metadata_rewrite_emulation;
    out->writes_are_atomic = source->writes_are_atomic;
    out->supports_copy = source->supports_copy;
    out->supports_rename = source->supports_rename;
    out->supports_server_side_copy = source->supports_server_side_copy;
    out->supports_server_side_rename = source->supports_server_side_rename;
    out->supports_atomic_rename = source->supports_atomic_rename;
    out->has_real_directories = source->has_real_directories;
    out->supports_write = source->supports_write;
    out->supports_write_stream = source->supports_write_stream;
    out->supports_write_redirect = source->supports_write_redirect;
    out->supports_delete = source->supports_delete;
    out->supports_list = source->supports_list;
    out->wants_list_backed_stat = source->wants_list_backed_stat;
    out->supports_recursive_list = source->supports_recursive_list;
    out->populates_subdirectory_metadata =
        source->populates_subdirectory_metadata;
    out->supports_create_directory = source->supports_create_directory;
    out->supports_delete_directory = source->supports_delete_directory;
    out->supports_version_listing = source->supports_version_listing;
    out->has_version_list_order = source->version_list_order.present;
    if (source->version_list_order.present) {
        out->version_list_order =
            (OvStorage_VersionListOrder)source->version_list_order.value;
    }
    out->populates_effective_permissions_on_stat =
        source->populates_effective_permissions_on_stat;
    out->supports_access_check = source->supports_access_check;
    out->supports_watch_directory = source->supports_watch_directory;
    out->watch_directory_kinds.created =
        source->watch_directory_kinds.created;
    out->watch_directory_kinds.modified =
        source->watch_directory_kinds.modified;
    out->watch_directory_kinds.deleted =
        source->watch_directory_kinds.deleted;
    out->watch_directory_kinds.metadata_changed =
        source->watch_directory_kinds.metadata_changed;
    out->watch_directory_resumable = source->watch_directory_resumable;
    out->has_watch_directory_max_lag =
        source->watch_directory_max_lag_ms.present;
    if (source->watch_directory_max_lag_ms.present &&
        source->watch_directory_max_lag_ms.value <=
            UINT64_MAX / UINT64_C(1000000)) {
        out->watch_directory_max_lag_nanos =
            source->watch_directory_max_lag_ms.value * UINT64_C(1000000);
    }
    out->has_redirect_size_threshold =
        source->redirect_size_threshold.present;
    if (source->redirect_size_threshold.present) {
        out->redirect_size_threshold = source->redirect_size_threshold.value;
    }
}

static void ovc_dispatch_connection_clear(
    OvStoragePlugin_Connection *connection,
    bool free_outer)
{
    size_t index;

    if (connection == NULL) {
        return;
    }
    ovc_dispatch_abi_str_clear(&connection->id.id);
    ovc_dispatch_abi_str_clear(&connection->backend_kind);
    ovc_dispatch_abi_str_clear(&connection->display_name);
    if (connection->source.tag ==
        OvStoragePlugin_ConnectionSourceTag_BrokerDelivered) {
        ovc_dispatch_abi_str_clear(
            &connection->source.broker_delivered.broker_principal);
    }
    if (connection->current_addresses.ptr != NULL) {
        for (index = 0; index < connection->current_addresses.len; ++index) {
            ovc_dispatch_abi_str_clear(
                &connection->current_addresses.ptr[index]);
        }
    }
    ovc_abi_free(connection->current_addresses.ptr);
    if (connection->auth_state.tag ==
        OvStoragePlugin_ConnectionAuthStateTag_AwaitingAuth) {
        if (connection->auth_state.awaiting_auth.reason.tag ==
            OvStoragePlugin_AuthReasonTag_Unknown) {
            ovc_dispatch_abi_str_clear(
                &connection->auth_state.awaiting_auth.reason.unknown_details);
        }
        if (connection->auth_state.awaiting_auth.last_attempt.present &&
            connection->auth_state.awaiting_auth.last_attempt.value.error
                .present) {
            ovc_dispatch_abi_str_clear(
                &connection->auth_state.awaiting_auth.last_attempt.value.error
                     .value.message);
        }
    } else if (connection->auth_state.tag ==
               OvStoragePlugin_ConnectionAuthStateTag_AuthFailed) {
        ovc_dispatch_abi_str_clear(
            &connection->auth_state.auth_failed.error_message);
    }
    ovc_dispatch_abi_key_values_clear(&connection->user_metadata);
    memset(connection, 0, sizeof(*connection));
    if (free_outer) {
        ovc_abi_free(connection);
    }
}

/*
 * Every string field — id, backend_kind, display_name, addresses,
 * user_metadata keys/values, broker principal, auth-failure message —
 * FILTERS interior NULs out (auth-EVENT strings are
 * different — they escape NULs per ffi/mod.rs's cstring_lossy).  The
 * conversion never fails on string content, only on OOM or a malformed
 * ABI slice.
 */
static OvStorage_Connection *ovc_dispatch_connection_from_plugin(
    const OvStoragePlugin_Connection *source)
{
    OvStorage_Connection *connection;
    char **addresses;
    ovc_metadata_entry *metadata;
    size_t index;

    if (source == NULL || source->id.id.ptr == NULL ||
        source->backend_kind.ptr == NULL || source->display_name.ptr == NULL) {
        return NULL;
    }
    connection = (OvStorage_Connection *)calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return NULL;
    }
    connection->id = ovc_dispatch_slice_copy_filtered(source->id.id.ptr,
                                                      source->id.id.len);
    connection->backend_kind = ovc_dispatch_slice_copy_filtered(
        source->backend_kind.ptr, source->backend_kind.len);
    connection->display_name = ovc_dispatch_slice_copy_filtered(
        source->display_name.ptr, source->display_name.len);
    if (connection->id == NULL || connection->backend_kind == NULL ||
        connection->display_name == NULL) {
        ovstorage_connection_destroy(connection);
        return NULL;
    }
    ovc_dispatch_capabilities_copy(&connection->capabilities,
                                   &source->capabilities);
    if (source->current_addresses.len != 0) {
        if (source->current_addresses.ptr == NULL ||
            source->current_addresses.len >
                SIZE_MAX / sizeof(*connection->addresses)) {
            ovstorage_connection_destroy(connection);
            return NULL;
        }
        addresses = (char **)calloc(source->current_addresses.len,
                                    sizeof(*addresses));
        if (addresses == NULL) {
            ovstorage_connection_destroy(connection);
            return NULL;
        }
        connection->addresses = (const char *const *)addresses;
        connection->addresses_len = source->current_addresses.len;
        for (index = 0; index < connection->addresses_len; ++index) {
            addresses[index] = ovc_dispatch_slice_copy_filtered(
                source->current_addresses.ptr[index].ptr,
                source->current_addresses.ptr[index].len);
            if (addresses[index] == NULL) {
                ovstorage_connection_destroy(connection);
                return NULL;
            }
        }
    }
    metadata = NULL;
    if (!ovc_dispatch_metadata_copy(&metadata,
                                    &connection->user_metadata_len,
                                    &source->user_metadata,
                                    /* filter_nuls */ true)) {
        ovstorage_connection_destroy(connection);
        return NULL;
    }
    connection->user_metadata = metadata;
    connection->source_kind =
        (OvStorage_ConnectionSourceKind)source->source.tag;
    if (source->source.tag == OvStoragePlugin_ConnectionSourceTag_Static) {
        connection->source_static_layer =
            (OvStorage_ConfigLayer)source->source.static_.layer;
    } else if (source->source.tag ==
               OvStoragePlugin_ConnectionSourceTag_Runtime) {
        connection->source_runtime_persisted = source->source.runtime.persisted;
    } else if (source->source.tag ==
               OvStoragePlugin_ConnectionSourceTag_BrokerDelivered) {
        connection->source_broker_principal = ovc_dispatch_slice_copy_filtered(
            source->source.broker_delivered.broker_principal.ptr,
            source->source.broker_delivered.broker_principal.len);
        if (connection->source_broker_principal == NULL) {
            ovstorage_connection_destroy(connection);
            return NULL;
        }
    }
    connection->auth_state_kind =
        (OvStorage_ConnectionAuthStateKind)source->auth_state.tag;
    if (source->auth_state.tag ==
        OvStoragePlugin_ConnectionAuthStateTag_AuthFailed) {
        connection->auth_failed_attempts =
            source->auth_state.auth_failed.attempts;
        connection->auth_failed_code = ovc_status_from_plugin_code(
            source->auth_state.auth_failed.error_code);
        connection->auth_failed_code_name = ovc_plugin_error_code_name(
            source->auth_state.auth_failed.error_code);
        connection->auth_failed_message = ovc_dispatch_slice_copy_filtered(
            source->auth_state.auth_failed.error_message.ptr,
            source->auth_state.auth_failed.error_message.len);
        if (connection->auth_failed_message == NULL) {
            ovstorage_connection_destroy(connection);
            return NULL;
        }
    } else if (source->auth_state.tag ==
               OvStoragePlugin_ConnectionAuthStateTag_Authenticated) {
        if (source->auth_state.authenticated
                    .last_authenticated_at_unix_ms >= 0 &&
            (uint64_t)source->auth_state.authenticated
                    .last_authenticated_at_unix_ms <=
                UINT64_MAX / UINT64_C(1000000)) {
            connection->has_authenticated_at = true;
            connection->authenticated_at_unix_nanos =
                (uint64_t)source->auth_state.authenticated
                    .last_authenticated_at_unix_ms *
                UINT64_C(1000000);
        }
        if (source->auth_state.authenticated.expires_at_unix_ms.present &&
            source->auth_state.authenticated.expires_at_unix_ms.value >= 0 &&
            (uint64_t)source->auth_state.authenticated.expires_at_unix_ms
                    .value <= UINT64_MAX / UINT64_C(1000000)) {
            connection->has_authenticated_expires_at = true;
            connection->authenticated_expires_at_unix_nanos =
                (uint64_t)source->auth_state.authenticated
                    .expires_at_unix_ms.value *
                UINT64_C(1000000);
        }
    } else if (source->auth_state.tag ==
               OvStoragePlugin_ConnectionAuthStateTag_AwaitingAuth) {
        connection->awaiting_auth_reason =
            (OvStorage_AuthReason)source->auth_state.awaiting_auth.reason.tag;
        if (source->auth_state.awaiting_auth.reason.tag ==
                OvStoragePlugin_AuthReasonTag_Unknown &&
            source->auth_state.awaiting_auth.reason.unknown_details.ptr !=
                NULL) {
            connection->awaiting_auth_unknown_details =
                ovc_dispatch_slice_copy_filtered(
                    source->auth_state.awaiting_auth.reason.unknown_details
                        .ptr,
                    source->auth_state.awaiting_auth.reason.unknown_details
                        .len);
            if (connection->awaiting_auth_unknown_details == NULL) {
                ovstorage_connection_destroy(connection);
                return NULL;
            }
        }
    }
    if (source->last_probed_unix_ms.present &&
        source->last_probed_unix_ms.value >= 0 &&
        (uint64_t)source->last_probed_unix_ms.value <=
            UINT64_MAX / UINT64_C(1000000)) {
        connection->has_last_probed = true;
        connection->last_probed_unix_nanos =
            (uint64_t)source->last_probed_unix_ms.value *
            UINT64_C(1000000);
    }
    return connection;
}

static void ovc_dispatch_root_info_clear(OvStoragePlugin_RootInfo *root,
                                         bool free_outer)
{
    size_t struct_size;
    size_t clear_size;

    if (root == NULL) {
        return;
    }
    struct_size = root->struct_size;
#define OVC_DISPATCH_ROOT_HAS(field)                                    \
    (struct_size >= offsetof(OvStoragePlugin_RootInfo, field) +         \
                        sizeof(root->field))
    if (OVC_DISPATCH_ROOT_HAS(root)) {
        ovc_dispatch_abi_str_clear(&root->root);
    }
    if (OVC_DISPATCH_ROOT_HAS(display_name) && root->display_name.present) {
        ovc_dispatch_abi_str_clear(&root->display_name.value);
    }
    if (OVC_DISPATCH_ROOT_HAS(layer_kind)) {
        ovc_dispatch_abi_str_clear(&root->layer_kind);
    }
    if (OVC_DISPATCH_ROOT_HAS(connection_id) && root->connection_id.present) {
        ovc_dispatch_abi_str_clear(&root->connection_id.value.id);
    }
    if (OVC_DISPATCH_ROOT_HAS(source)) {
        if (root->source.connection_id.present) {
            ovc_dispatch_abi_str_clear(
                &root->source.connection_id.value.id);
        }
        if (root->source.broker_principal.present) {
            ovc_dispatch_abi_str_clear(
                &root->source.broker_principal.value);
        }
        if (root->source.alias_to.present) {
            ovc_dispatch_abi_str_clear(&root->source.alias_to.value);
        }
        if (root->source.alias_source.present &&
            root->source.alias_source.value.broker_principal.present) {
            ovc_dispatch_abi_str_clear(
                &root->source.alias_source.value.broker_principal.value);
        }
    }
    if (OVC_DISPATCH_ROOT_HAS(alias_state) && root->alias_state.present &&
        root->alias_state.value.reason.present) {
        ovc_dispatch_abi_str_clear(&root->alias_state.value.reason.value);
    }
    if (OVC_DISPATCH_ROOT_HAS(icon) && root->icon.present) {
        ovc_dispatch_abi_bytes_clear(&root->icon.value, false);
    }
    if (OVC_DISPATCH_ROOT_HAS(user_metadata)) {
        ovc_dispatch_abi_key_values_clear(&root->user_metadata);
    }
    if (OVC_DISPATCH_ROOT_HAS(owning_target) && root->owning_target.present) {
        ovc_dispatch_abi_str_clear(&root->owning_target.value);
    }
    clear_size = struct_size < sizeof(*root) ? struct_size : sizeof(*root);
    if (clear_size < sizeof(root->struct_size)) {
        clear_size = sizeof(root->struct_size);
    }
    memset(root, 0, clear_size);
#undef OVC_DISPATCH_ROOT_HAS
    if (free_outer) {
        ovc_abi_free(root);
    }
}

static OvStorage_RootInfo *ovc_dispatch_root_info_from_plugin(
    const OvStoragePlugin_RootInfo *source)
{
    OvStorage_RootInfo *root;
    ovc_metadata_entry *metadata;
    uint8_t *icon;

    if (source == NULL || source->struct_size < sizeof(*source) ||
        source->root.ptr == NULL || source->layer_kind.ptr == NULL) {
        return NULL;
    }
    root = (OvStorage_RootInfo *)calloc(1, sizeof(*root));
    if (root == NULL) {
        return NULL;
    }
    root->root = ovc_dispatch_slice_copy(source->root.ptr, source->root.len);
    root->layer_kind = ovc_dispatch_slice_copy(source->layer_kind.ptr,
                                               source->layer_kind.len);
    if (root->root == NULL || root->layer_kind == NULL) {
        ovstorage_root_info_destroy(root);
        return NULL;
    }
    if (source->display_name.present) {
        root->display_name = ovc_dispatch_slice_copy(
            source->display_name.value.ptr,
            source->display_name.value.len);
        if (root->display_name == NULL) {
            ovstorage_root_info_destroy(root);
            return NULL;
        }
    }
    if (source->connection_id.present) {
        root->has_connection_id = true;
        root->connection_id = ovc_dispatch_slice_copy(
            source->connection_id.value.id.ptr,
            source->connection_id.value.id.len);
        if (root->connection_id == NULL) {
            ovstorage_root_info_destroy(root);
            return NULL;
        }
    }
    root->visible = source->visible;
    root->visibility = (OvStorage_AddressVisibility)source->visibility;
    root->range_read_strategy =
        (OvStorage_RangeReadStrategy)source->range_read_strategy;
    ovc_dispatch_capabilities_copy(&root->capabilities,
                                   &source->capabilities);
    if (source->owning_target.present) {
        root->owning_target = ovc_dispatch_slice_copy(
            source->owning_target.value.ptr,
            source->owning_target.value.len);
        if (root->owning_target == NULL) {
            ovstorage_root_info_destroy(root);
            return NULL;
        }
    }
    root->source_kind = (OvStorage_RouteSourceKind)source->source.tag;
    root->source_static_layer = (OvStorage_ConfigLayer)source->source.layer;
    if (source->source.connection_id.present) {
        root->source_connection_id = ovc_dispatch_slice_copy(
            source->source.connection_id.value.id.ptr,
            source->source.connection_id.value.id.len);
    }
    if (source->source.broker_principal.present) {
        root->source_broker_principal = ovc_dispatch_slice_copy(
            source->source.broker_principal.value.ptr,
            source->source.broker_principal.value.len);
    }
    if (source->source.alias_to.present) {
        root->source_alias_to = ovc_dispatch_slice_copy(
            source->source.alias_to.value.ptr,
            source->source.alias_to.value.len);
    }
    if ((source->source.connection_id.present &&
         root->source_connection_id == NULL) ||
        (source->source.broker_principal.present &&
         root->source_broker_principal == NULL) ||
        (source->source.alias_to.present && root->source_alias_to == NULL)) {
        ovstorage_root_info_destroy(root);
        return NULL;
    }
    if (source->source.alias_source.present) {
        root->source_alias_source_kind = (OvStorage_AliasSourceKind)
            source->source.alias_source.value.tag;
        root->source_alias_source_static_layer = (OvStorage_ConfigLayer)
            source->source.alias_source.value.layer;
        root->source_alias_source_runtime_persisted =
            source->source.alias_source.value.persisted;
        if (source->source.alias_source.value.broker_principal.present) {
            root->source_alias_source_broker_principal =
                ovc_dispatch_slice_copy(
                    source->source.alias_source.value.broker_principal.value.ptr,
                    source->source.alias_source.value.broker_principal.value.len);
            if (root->source_alias_source_broker_principal == NULL) {
                ovstorage_root_info_destroy(root);
                return NULL;
            }
        }
    }
    if (source->alias_state.present) {
        root->has_alias_state = true;
        root->alias_state_kind =
            (OvStorage_AliasStateKind)source->alias_state.value.tag;
        if (source->alias_state.value.reason.present) {
            root->alias_state_chain_too_long_reason =
                ovc_dispatch_slice_copy(
                    source->alias_state.value.reason.value.ptr,
                    source->alias_state.value.reason.value.len);
            if (root->alias_state_chain_too_long_reason == NULL) {
                ovstorage_root_info_destroy(root);
                return NULL;
            }
        }
    }
    metadata = NULL;
    if (!ovc_dispatch_metadata_copy(&metadata,
                                    &root->user_metadata_len,
                                    &source->user_metadata,
                                    false)) {
        ovstorage_root_info_destroy(root);
        return NULL;
    }
    root->user_metadata = metadata;
    if (source->icon.present) {
        icon = (uint8_t *)malloc(source->icon.value.len == 0
                                     ? 1
                                     : source->icon.value.len);
        root->icon = icon;
        if (icon == NULL ||
            (source->icon.value.ptr == NULL && source->icon.value.len != 0)) {
            ovstorage_root_info_destroy(root);
            return NULL;
        }
        if (source->icon.value.len != 0) {
            memcpy(icon, source->icon.value.ptr, source->icon.value.len);
        }
        root->has_icon = true;
        root->icon_len = source->icon.value.len;
    }
    return root;
}

static void ovc_dispatch_auth_event_clear(OvStoragePlugin_AuthEvent *event)
{
    if (event == NULL) {
        return;
    }
    switch (event->tag) {
    case OvStoragePlugin_AuthEventTag_OpenBrowser:
        ovc_dispatch_abi_str_clear(&event->open_browser.url);
        break;
    case OvStoragePlugin_AuthEventTag_DeviceCode:
        ovc_dispatch_abi_str_clear(&event->device_code.user_code);
        ovc_dispatch_abi_str_clear(&event->device_code.verification_url);
        break;
    case OvStoragePlugin_AuthEventTag_Progress:
        ovc_dispatch_abi_str_clear(&event->progress.message);
        break;
    case OvStoragePlugin_AuthEventTag_Succeeded:
        ovc_dispatch_connection_clear(&event->succeeded.connection, false);
        if (event->succeeded.credentials.present) {
            ovc_dispatch_secret_bundle_clear(
                &event->succeeded.credentials.value);
        }
        break;
    case OvStoragePlugin_AuthEventTag_Failed:
        ovc_dispatch_abi_str_clear(&event->failed.error_message);
        break;
    case OvStoragePlugin_AuthEventTag_Cancelled:
    default:
        break;
    }
    memset(event, 0, sizeof(*event));
}

static OvStorage_AuthEvent *ovc_dispatch_auth_event_from_plugin(
    const OvStoragePlugin_AuthEvent *source)
{
    OvStorage_AuthEvent *event;

    if (source == NULL) {
        return NULL;
    }
    event = (OvStorage_AuthEvent *)calloc(1, sizeof(*event));
    if (event == NULL) {
        return NULL;
    }
    event->kind = (OvStorage_AuthEventKind)source->tag;
    /* Event strings convert lossily — interior NULs are ESCAPED rather
     * than dropped — so conversion fails only on OOM. */
    switch (source->tag) {
    case OvStoragePlugin_AuthEventTag_OpenBrowser:
        event->as.open_browser.url = ovc_dispatch_slice_copy_lossy(
            source->open_browser.url.ptr, source->open_browser.url.len);
        if (source->open_browser.expires_at_unix_ms >= 0 &&
            (uint64_t)source->open_browser.expires_at_unix_ms <=
                UINT64_MAX / UINT64_C(1000000)) {
            event->as.open_browser.expires_at_unix_nanos =
                (uint64_t)source->open_browser.expires_at_unix_ms *
                UINT64_C(1000000);
        }
        if (event->as.open_browser.url == NULL) {
            ovstorage_auth_event_destroy(event);
            return NULL;
        }
        break;
    case OvStoragePlugin_AuthEventTag_DeviceCode:
        event->as.device_code.user_code = ovc_dispatch_slice_copy_lossy(
            source->device_code.user_code.ptr,
            source->device_code.user_code.len);
        event->as.device_code.verification_url =
            ovc_dispatch_slice_copy_lossy(
            source->device_code.verification_url.ptr,
            source->device_code.verification_url.len);
        if (source->device_code.expires_at_unix_ms >= 0 &&
            (uint64_t)source->device_code.expires_at_unix_ms <=
                UINT64_MAX / UINT64_C(1000000)) {
            event->as.device_code.expires_at_unix_nanos =
                (uint64_t)source->device_code.expires_at_unix_ms *
                UINT64_C(1000000);
        }
        if (source->device_code.interval_ms <=
            UINT64_MAX / UINT64_C(1000000)) {
            event->as.device_code.interval_nanos =
                source->device_code.interval_ms * UINT64_C(1000000);
        }
        if (event->as.device_code.user_code == NULL ||
            event->as.device_code.verification_url == NULL) {
            ovstorage_auth_event_destroy(event);
            return NULL;
        }
        break;
    case OvStoragePlugin_AuthEventTag_Progress:
        event->as.progress.message = ovc_dispatch_slice_copy_lossy(
            source->progress.message.ptr, source->progress.message.len);
        if (event->as.progress.message == NULL) {
            ovstorage_auth_event_destroy(event);
            return NULL;
        }
        break;
    case OvStoragePlugin_AuthEventTag_Succeeded:
        /* The nested connection FILTERS interior NULs out of its string
         * fields (see ovc_dispatch_connection_from_plugin) — unlike the
         * event's own strings above, which escape them — so a Succeeded
         * event fails only on OOM or malformed ABI data. */
        event->as.succeeded.connection = ovc_dispatch_connection_from_plugin(
            &source->succeeded.connection);
        if (event->as.succeeded.connection == NULL) {
            ovstorage_auth_event_destroy(event);
            return NULL;
        }
        break;
    case OvStoragePlugin_AuthEventTag_Failed:
        event->as.failed.code =
            ovc_status_from_plugin_code(source->failed.error_code);
        event->as.failed.code_name =
            ovc_plugin_error_code_name(source->failed.error_code);
        event->as.failed.message = ovc_dispatch_slice_copy_lossy(
            source->failed.error_message.ptr,
            source->failed.error_message.len);
        if (event->as.failed.message == NULL) {
            ovstorage_auth_event_destroy(event);
            return NULL;
        }
        break;
    case OvStoragePlugin_AuthEventTag_Cancelled:
        break;
    default:
        ovstorage_auth_event_destroy(event);
        return NULL;
    }
    return event;
}

/* ------------------------------------------------------------------------- */
/* Public-request to plugin-ABI marshalling. */

static void ovc_dispatch_config_value_clear(
    OvStoragePlugin_ConfigValue *value)
{
    if (value == NULL) {
        return;
    }
    if (value->tag == OvStoragePlugin_ConfigValueTag_String) {
        ovc_dispatch_abi_str_clear(&value->string_value);
    } else if (value->tag == OvStoragePlugin_ConfigValueTag_Toml) {
        ovc_dispatch_abi_str_clear(&value->toml_value);
    }
    memset(value, 0, sizeof(*value));
}

static bool ovc_dispatch_config_value_copy(
    OvStoragePlugin_ConfigValue *out,
    const OvStorage_ConfigValue *source)
{
    memset(out, 0, sizeof(*out));
    if (source == NULL) {
        return false;
    }
    switch (source->kind) {
    case OvStorage_ConfigValueKind_String:
        out->tag = OvStoragePlugin_ConfigValueTag_String;
        return ovc_dispatch_abi_cstring_copy(&out->string_value,
                                             source->payload.string);
    case OvStorage_ConfigValueKind_Int:
        out->tag = OvStoragePlugin_ConfigValueTag_Int;
        out->int_value = source->payload.integer;
        return true;
    case OvStorage_ConfigValueKind_Bool:
        out->tag = OvStoragePlugin_ConfigValueTag_Bool;
        out->bool_value = source->payload.boolean;
        return true;
    case OvStorage_ConfigValueKind_Toml:
        out->tag = OvStoragePlugin_ConfigValueTag_Toml;
        return ovc_dispatch_abi_cstring_copy(&out->toml_value,
                                             source->payload.string);
    default:
        return false;
    }
}

static void ovc_dispatch_config_list_clear(
    OvStoragePlugin_List_ConnectionConfigEntry *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    if (list->ptr != NULL) {
        for (index = 0; index < list->len; ++index) {
            ovc_dispatch_abi_str_clear(&list->ptr[index].key);
            ovc_dispatch_config_value_clear(&list->ptr[index].value);
        }
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

static bool ovc_dispatch_config_list_copy(
    OvStoragePlugin_List_ConnectionConfigEntry *out,
    const OvStorage_ConnectionRequest *source)
{
    size_t allocation_count;
    size_t index;

    memset(out, 0, sizeof(*out));
    allocation_count = source->config_len == 0 ? 1 : source->config_len;
    if (allocation_count > SIZE_MAX / sizeof(*out->ptr)) {
        return false;
    }
    out->ptr = (OvStoragePlugin_ConnectionConfigEntry *)ovc_abi_alloc(
        allocation_count * sizeof(*out->ptr));
    if (out->ptr == NULL) {
        return false;
    }
    memset(out->ptr, 0, allocation_count * sizeof(*out->ptr));
    for (index = 0; index < source->config_len; ++index) {
        out->len = index + 1;
        if (!ovc_dispatch_abi_cstring_copy(&out->ptr[index].key,
                                           source->config[index].key) ||
            !ovc_dispatch_config_value_copy(&out->ptr[index].value,
                                            source->config[index].value)) {
            ovc_dispatch_config_list_clear(out);
            return false;
        }
    }
    return true;
}

static void ovc_dispatch_secret_value_clear(
    OvStoragePlugin_SecretValue *value)
{
    if (value == NULL) {
        return;
    }
    switch (value->tag) {
    case OvStoragePlugin_SecretValueTag_Bytes:
        ovc_dispatch_abi_bytes_clear(&value->bytes.bytes, true);
        break;
    case OvStoragePlugin_SecretValueTag_OAuthToken:
        ovc_dispatch_abi_bytes_clear(&value->oauth_token.token.bytes, true);
        if (value->oauth_token.refresh.present) {
            ovc_dispatch_abi_bytes_clear(
                &value->oauth_token.refresh.value.bytes, true);
        }
        break;
    case OvStoragePlugin_SecretValueTag_File:
        ovc_dispatch_abi_bytes_clear(&value->file.bytes, true);
        break;
    case OvStoragePlugin_SecretValueTag_MtlsCertPair:
        ovc_dispatch_abi_bytes_clear(
            &value->mtls_cert_pair.cert_pem.bytes, true);
        ovc_dispatch_abi_bytes_clear(
            &value->mtls_cert_pair.key_pem.bytes, true);
        break;
    case OvStoragePlugin_SecretValueTag_SystemIdentity:
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

static bool ovc_dispatch_secret_value_copy(
    OvStoragePlugin_SecretValue *out,
    const OvStorage_SecretValue *source)
{
    uint64_t expires_ms;

    memset(out, 0, sizeof(*out));
    if (source == NULL) {
        return false;
    }
    switch (source->kind) {
    case OVC_SECRET_VALUE_BYTES:
        out->tag = OvStoragePlugin_SecretValueTag_Bytes;
        return ovc_dispatch_abi_bytes_copy(&out->bytes.bytes,
                                           source->payload.bytes.data,
                                           source->payload.bytes.len);
    case OVC_SECRET_VALUE_FILE:
        out->tag = OvStoragePlugin_SecretValueTag_File;
        return ovc_dispatch_abi_bytes_copy(&out->file.bytes,
                                           source->payload.bytes.data,
                                           source->payload.bytes.len);
    case OVC_SECRET_VALUE_OAUTH_TOKEN:
        out->tag = OvStoragePlugin_SecretValueTag_OAuthToken;
        if (!ovc_dispatch_abi_bytes_copy(
                &out->oauth_token.token.bytes,
                source->payload.oauth_token.token.data,
                source->payload.oauth_token.token.len)) {
            return false;
        }
        if (source->payload.oauth_token.has_refresh) {
            out->oauth_token.refresh.present = true;
            if (!ovc_dispatch_abi_bytes_copy(
                    &out->oauth_token.refresh.value.bytes,
                    source->payload.oauth_token.refresh.data,
                    source->payload.oauth_token.refresh.len)) {
                ovc_dispatch_secret_value_clear(out);
                return false;
            }
        }
        if (source->payload.oauth_token.has_expires_at) {
            expires_ms = source->payload.oauth_token.expires_at_unix_nanos /
                         UINT64_C(1000000);
            if (expires_ms > (uint64_t)INT64_MAX) {
                ovc_dispatch_secret_value_clear(out);
                return false;
            }
            out->oauth_token.expires_at_unix_ms.present = true;
            out->oauth_token.expires_at_unix_ms.value = (int64_t)expires_ms;
        }
        return true;
    case OVC_SECRET_VALUE_MTLS_CERT_PAIR:
        out->tag = OvStoragePlugin_SecretValueTag_MtlsCertPair;
        if (!ovc_dispatch_abi_bytes_copy(
                &out->mtls_cert_pair.cert_pem.bytes,
                source->payload.mtls_cert_pair.cert_pem.data,
                source->payload.mtls_cert_pair.cert_pem.len) ||
            !ovc_dispatch_abi_bytes_copy(
                &out->mtls_cert_pair.key_pem.bytes,
                source->payload.mtls_cert_pair.key_pem.data,
                source->payload.mtls_cert_pair.key_pem.len)) {
            ovc_dispatch_secret_value_clear(out);
            return false;
        }
        return true;
    case OVC_SECRET_VALUE_SYSTEM_IDENTITY:
        out->tag = OvStoragePlugin_SecretValueTag_SystemIdentity;
        return true;
    default:
        return false;
    }
}

static void ovc_dispatch_secret_bundle_clear(
    OvStoragePlugin_SecretBundle *bundle)
{
    size_t index;

    if (bundle == NULL) {
        return;
    }
    if (bundle->entries.ptr != NULL) {
        for (index = 0; index < bundle->entries.len; ++index) {
            ovc_dispatch_abi_str_clear(&bundle->entries.ptr[index].field);
            ovc_dispatch_secret_value_clear(
                &bundle->entries.ptr[index].value);
        }
    }
    ovc_abi_free(bundle->entries.ptr);
    memset(bundle, 0, sizeof(*bundle));
}

static bool ovc_dispatch_secret_bundle_copy(
    OvStoragePlugin_SecretBundle *out,
    const OvStorage_SecretBundle *source)
{
    size_t allocation_count;
    size_t index;

    memset(out, 0, sizeof(*out));
    allocation_count = source->len == 0 ? 1 : source->len;
    if (allocation_count > SIZE_MAX / sizeof(*out->entries.ptr)) {
        return false;
    }
    out->entries.ptr = (OvStoragePlugin_SecretBundleEntry *)ovc_abi_alloc(
        allocation_count * sizeof(*out->entries.ptr));
    if (out->entries.ptr == NULL) {
        return false;
    }
    memset(out->entries.ptr, 0, allocation_count * sizeof(*out->entries.ptr));
    for (index = 0; index < source->len; ++index) {
        out->entries.len = index + 1;
        if (!ovc_dispatch_abi_cstring_copy(
                &out->entries.ptr[index].field,
                source->entries[index].key) ||
            !ovc_dispatch_secret_value_copy(
                &out->entries.ptr[index].value,
                source->entries[index].value)) {
            ovc_dispatch_secret_bundle_clear(out);
            return false;
        }
    }
    return true;
}

static void ovc_dispatch_connection_request_clear(
    OvStoragePlugin_ConnectionRequest *request)
{
    if (request == NULL) {
        return;
    }
    ovc_dispatch_abi_str_clear(&request->backend_kind);
    ovc_dispatch_config_list_clear(&request->config);
    ovc_dispatch_secret_bundle_clear(&request->credentials);
    if (request->display_name.present) {
        ovc_dispatch_abi_str_clear(&request->display_name.value);
    }
    memset(request, 0, sizeof(*request));
}

static bool ovc_dispatch_connection_request_copy(
    OvStoragePlugin_ConnectionRequest *out,
    const OvStorage_ConnectionRequest *source)
{
    memset(out, 0, sizeof(*out));
    if (source == NULL || source->backend_kind == NULL ||
        !ovc_dispatch_abi_cstring_copy(&out->backend_kind,
                                       source->backend_kind) ||
        !ovc_dispatch_config_list_copy(&out->config, source) ||
        !ovc_dispatch_secret_bundle_copy(&out->credentials,
                                         &source->credentials)) {
        ovc_dispatch_connection_request_clear(out);
        return false;
    }
    out->persist = source->persist;
    if (source->display_name != NULL) {
        out->display_name.present = true;
        if (!ovc_dispatch_abi_cstring_copy(&out->display_name.value,
                                           source->display_name)) {
            ovc_dispatch_connection_request_clear(out);
            return false;
        }
    }
    return true;
}

static bool ovc_dispatch_read_options(
    OvStoragePlugin_ReadOptions *out,
    const OvStorage_ReadOptions *options)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    if (options == NULL) {
        return true;
    }
    if (options->has_range) {
        out->range.present = true;
        out->range.value.start = options->range_start;
        out->range.value.end_inclusive.present = options->has_range_end;
        out->range.value.end_inclusive.value = options->range_end_inclusive;
        if (options->has_range_end &&
            options->range_end_inclusive < options->range_start) {
            return false;
        }
    }
    return true;
}

static bool ovc_dispatch_stat_options(
    OvStoragePlugin_StatOptions *out,
    const OvStorage_StatOptions *options)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    if (options == NULL) {
        return true;
    }
    out->full_metadata = options->full_metadata;
    return true;
}

/* Marshal caller write options into the plugin request.
 *
 * `*out_reason` is written only on failure, and names the option that is
 * wrong rather than leaving the caller with the entry point's catch-all
 * "arguments are invalid" — an if-match etag is usually computed from a
 * prior stat, so a caller who gets it wrong needs to be told which of the
 * two preconditions the host refused. */
static bool ovc_dispatch_write_options(
    OvStoragePlugin_WriteOptions *out,
    const OvStorage_WriteOptions *options,
    const char **out_reason)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;
    if (options == NULL) {
        return true;
    }
    if (options->no_overwrite && options->if_match_etag != NULL) {
        *out_reason =
            "write options set both no_overwrite and if_match_etag; a "
            "destination precondition is one or the other";
        return false;
    }
    if (options->no_overwrite) {
        out->if_dest.tag = OvStoragePlugin_IfDestExistsTag_Fail;
    } else if (options->if_match_etag != NULL) {
        if (options->if_match_etag[0] == '\0') {
            *out_reason =
                "write options carry an empty if_match_etag; pass NULL for "
                "no precondition";
            return false;
        }
        if (!ovc_dispatch_utf8_valid(options->if_match_etag)) {
            *out_reason = "write options carry a non-UTF-8 if_match_etag";
            return false;
        }
        if (!ovc_dispatch_abi_cstring_copy(&out->if_dest.match_etag.etag,
                                           options->if_match_etag)) {
            *out_reason = "could not allocate the if_match_etag precondition";
            return false;
        }
        out->if_dest.tag = OvStoragePlugin_IfDestExistsTag_MatchEtag;
    }
    out->size_hint.present = options->has_size_hint;
    out->size_hint.value = options->size_hint;
    return true;
}

/* Release what `ovc_dispatch_write_options` allocated, for the paths that
 * abandon the request before it becomes a task (a task's own teardown
 * covers it). Safe on a zeroed struct: the zero tag is `Overwrite`. */
static void ovc_dispatch_write_options_clear(
    OvStoragePlugin_WriteOptions *options)
{
    if (options->if_dest.tag == OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        ovc_dispatch_abi_str_clear(&options->if_dest.match_etag.etag);
        options->if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;
    }
}

static bool ovc_dispatch_list_options(
    OvStoragePlugin_ListOptions *out,
    const OvStorage_ListOptions *options)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    if (options == NULL) {
        return true;
    }
    out->recursive = options->recursive;
    out->max_results.present = options->has_max_results;
    out->max_results.value = options->max_results;
    out->full_metadata = options->full_metadata;
    if (options->page_token != NULL) {
        out->page_token.present = true;
        if (!ovc_dispatch_utf8_valid(options->page_token) ||
            !ovc_dispatch_abi_cstring_copy(&out->page_token.value,
                                           options->page_token)) {
            return false;
        }
    }
    return true;
}

static void ovc_dispatch_list_options_clear(
    OvStoragePlugin_ListOptions *options)
{
    if (options->page_token.present) {
        ovc_dispatch_abi_str_clear(&options->page_token.value);
    }
    memset(options, 0, sizeof(*options));
}

static bool ovc_dispatch_list_versions_options(
    OvStoragePlugin_ListVersionsOptions *out,
    const OvStorage_ListVersionsOptions *options)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    if (options == NULL) {
        return true;
    }
    out->max_results.present = options->has_max_results;
    out->max_results.value = options->max_results;
    if (options->page_token != NULL) {
        out->page_token.present = true;
        if (!ovc_dispatch_utf8_valid(options->page_token) ||
            !ovc_dispatch_abi_cstring_copy(&out->page_token.value,
                                           options->page_token)) {
            return false;
        }
    }
    return true;
}

static void ovc_dispatch_list_versions_options_clear(
    OvStoragePlugin_ListVersionsOptions *options)
{
    if (options->page_token.present) {
        ovc_dispatch_abi_str_clear(&options->page_token.value);
    }
    memset(options, 0, sizeof(*options));
}

/* ------------------------------------------------------------------------- */
/* Async completion conversion. */

static void ovc_dispatch_list_page_clear(OvStoragePlugin_ListPage *page)
{
    size_t index;

    if (page == NULL) {
        return;
    }
    if (page->items.ptr != NULL) {
        for (index = 0; index < page->items.len; ++index) {
            ovc_dispatch_object_info_clear(&page->items.ptr[index], false);
        }
    }
    ovc_abi_free(page->items.ptr);
    if (page->next_page_token.present) {
        ovc_dispatch_abi_str_clear(&page->next_page_token.value);
    }
    ovc_abi_free(page);
}

static void ovc_dispatch_version_page_clear(
    OvStoragePlugin_VersionPage *page)
{
    size_t index;

    if (page == NULL) {
        return;
    }
    if (page->items.ptr != NULL) {
        for (index = 0; index < page->items.len; ++index) {
            ovc_dispatch_object_info_clear(&page->items.ptr[index], false);
        }
    }
    ovc_abi_free(page->items.ptr);
    if (page->next_page_token.present) {
        ovc_dispatch_abi_str_clear(&page->next_page_token.value);
    }
    ovc_abi_free(page);
}

static OvStorage_List *ovc_dispatch_list_from_plugin(
    const OvStoragePlugin_ListPage *source)
{
    OvStorage_List *list;
    OvStorage_Info *converted;
    OvStorage_Info *items = NULL;
    size_t index;

    if (source == NULL ||
        (source->items.len != 0 && source->items.ptr == NULL) ||
        source->items.len > SIZE_MAX / sizeof(*list->items)) {
        return NULL;
    }
    list = (OvStorage_List *)calloc(1, sizeof(*list));
    if (list == NULL) {
        return NULL;
    }
    if (source->items.len != 0) {
        items = (OvStorage_Info *)calloc(source->items.len, sizeof(*items));
        if (items == NULL) {
            ovstorage_list_destroy(list);
            return NULL;
        }
        list->items = items;
    }
    list->len = source->items.len;
    for (index = 0; index < list->len; ++index) {
        converted =
            ovc_dispatch_info_from_object(&source->items.ptr[index]);
        if (converted == NULL) {
            ovstorage_list_destroy(list);
            return NULL;
        }
        items[index] = *converted;
        free(converted);
    }
    if (source->next_page_token.present) {
        list->next_page_token = ovc_dispatch_slice_copy(
            source->next_page_token.value.ptr,
            source->next_page_token.value.len);
        if (list->next_page_token == NULL) {
            ovstorage_list_destroy(list);
            return NULL;
        }
    }
    return list;
}

static OvStorage_VersionList *ovc_dispatch_version_list_from_plugin(
    const OvStoragePlugin_VersionPage *source)
{
    OvStorage_VersionList *list;
    OvStorage_Info *converted;
    OvStorage_Info *items = NULL;
    size_t index;

    if (source == NULL ||
        (source->items.len != 0 && source->items.ptr == NULL) ||
        source->items.len > SIZE_MAX / sizeof(*list->items)) {
        return NULL;
    }
    list = (OvStorage_VersionList *)calloc(1, sizeof(*list));
    if (list == NULL) {
        return NULL;
    }
    if (source->items.len != 0) {
        items = (OvStorage_Info *)calloc(source->items.len, sizeof(*items));
        if (items == NULL) {
            ovstorage_version_list_destroy(list);
            return NULL;
        }
        list->items = items;
    }
    list->len = source->items.len;
    for (index = 0; index < list->len; ++index) {
        converted =
            ovc_dispatch_info_from_object(&source->items.ptr[index]);
        if (converted == NULL) {
            ovstorage_version_list_destroy(list);
            return NULL;
        }
        items[index] = *converted;
        free(converted);
    }
    if (source->next_page_token.present) {
        list->next_page_token = ovc_dispatch_slice_copy(
            source->next_page_token.value.ptr,
            source->next_page_token.value.len);
        if (list->next_page_token == NULL) {
            ovstorage_version_list_destroy(list);
            return NULL;
        }
    }
    return list;
}

static void ovc_dispatch_access_clear(
    OvStoragePlugin_AccessDecision *decision)
{
    if (decision == NULL) {
        return;
    }
    if (decision->reason.present) {
        ovc_dispatch_abi_str_clear(&decision->reason.value);
    }
    ovc_abi_free(decision);
}

static bool ovc_dispatch_access_from_plugin(
    OvStorage_AccessDecision *out,
    const OvStoragePlugin_AccessDecision *source)
{
    memset(out, 0, sizeof(*out));
    if (source == NULL) {
        return false;
    }
    out->allowed = source->allowed;
    out->denied_ops.read = source->denied_ops.read;
    out->denied_ops.write = source->denied_ops.write;
    out->denied_ops.delete_ = source->denied_ops.delete_;
    out->denied_ops.update_metadata = source->denied_ops.update_metadata;
    if (source->reason.present) {
        out->reason = ovc_dispatch_slice_copy(source->reason.value.ptr,
                                              source->reason.value.len);
        if (out->reason == NULL) {
            return false;
        }
    }
    return true;
}

/* Release a delegate's optional eviction lease: a non-NULL
 * drop_fn is driven exactly once with the opaque state, releasing the
 * producer-side pin.  NULL-safe on both fields; zeroed after the call so
 * a re-tagged delegate (see local_delegate_to_stream) cannot double-drop. */
static void ovc_dispatch_lease_drop(OvStoragePlugin_LeaseHandle *lease)
{
    if (lease != NULL && lease->drop_fn != NULL) {
        lease->drop_fn(lease->state);
        lease->state = NULL;
        lease->drop_fn = NULL;
    }
}

static void ovc_dispatch_local_delegate_clear(
    OvStoragePlugin_LocalDelegate *delegate)
{
    if (delegate == NULL) {
        return;
    }
    ovc_dispatch_abi_str_clear(&delegate->path);
    ovc_dispatch_object_info_clear(&delegate->info, false);
    ovc_dispatch_lease_drop(&delegate->lease);
    ovc_abi_free(delegate);
}

static OvStorage_LocalDelegate *ovc_dispatch_local_delegate_from_plugin(
    const OvStoragePlugin_LocalDelegate *source)
{
    OvStorage_LocalDelegate *delegate;

    if (source == NULL) {
        return NULL;
    }
    delegate = (OvStorage_LocalDelegate *)calloc(1, sizeof(*delegate));
    if (delegate == NULL) {
        return NULL;
    }
    delegate->path = ovc_dispatch_slice_copy(source->path.ptr,
                                             source->path.len);
    delegate->info = ovc_dispatch_info_from_object(&source->info);
    if (delegate->path == NULL || delegate->info == NULL) {
        ovstorage_local_delegate_destroy(delegate);
        return NULL;
    }
    return delegate;
}

static void ovc_dispatch_fire_callback_error(
    ovc_dispatch_operation_kind kind,
    ovc_dispatch_callback callback,
    void *user_data,
    OvStorage_Error *error)
{
    OvStorage_Bytes empty_bytes;
    OvStorage_AccessDecision empty_decision;

    memset(&empty_bytes, 0, sizeof(empty_bytes));
    memset(&empty_decision, 0, sizeof(empty_decision));
    switch (kind) {
    case OVC_DISPATCH_INFO_OBJECT:
    case OVC_DISPATCH_INFO_WRITE:
    case OVC_DISPATCH_INFO_WRITE_STEP:
    case OVC_DISPATCH_INFO_BACKEND_ITEM:
        callback.info(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_READ_BYTES:
        callback.read_bytes(error->code,
                            empty_bytes,
                            NULL,
                            error,
                            user_data);
        break;
    case OVC_DISPATCH_READ_STREAM:
        callback.read_stream(empty_bytes, error, true, user_data);
        break;
    case OVC_DISPATCH_LOCAL_DELEGATE:
        callback.local_delegate(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_STATUS:
        callback.status(error->code, error, user_data);
        break;
    case OVC_DISPATCH_LIST:
        callback.list(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_VERSION_LIST:
        callback.version_list(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_ACCESS:
        callback.access(error->code, empty_decision, error, user_data);
        break;
    case OVC_DISPATCH_CONNECTION:
        callback.connection(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_AUTH_STREAM:
        callback.auth(NULL, error, true, user_data);
        break;
    case OVC_DISPATCH_ROOT_LIST:
        callback.root_list(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_CONNECTION_LIST:
        callback.connection_list(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_WATCH_STREAM:
        callback.watch(NULL, error, true, user_data);
        break;
    case OVC_DISPATCH_WRITE_REDIRECT_BATCH:
        callback.write_redirect(error->code, NULL, error, user_data);
        break;
    case OVC_DISPATCH_WRITE_STEP:
        callback.write_step(error->code, NULL, NULL, error, user_data);
        break;
    default:
        break;
    }
}

static void ovc_dispatch_fire_inline_error(
    ovc_dispatch_operation_kind kind,
    ovc_dispatch_callback callback,
    void *user_data,
    OvStorage_Status status,
    const char *message)
{
    OvStorage_Error error;

    error = ovc_dispatch_public_error(status, message);
    ovc_dispatch_fire_callback_error(kind, callback, user_data, &error);
    ovc_dispatch_error_done(&error);
}

static ovc_dispatch_operation *ovc_dispatch_operation_create(
    OvStorage_LayerHandle *handle,
    ovc_dispatch_operation_kind kind,
    ovc_dispatch_callback callback,
    void *user_data,
    const char *address)
{
    ovc_dispatch_operation *operation;

    if (!ovc_dispatch_operation_enter(handle)) {
        return NULL;
    }
    operation = (ovc_dispatch_operation *)calloc(1, sizeof(*operation));
    if (operation == NULL) {
        ovc_dispatch_operation_leave(handle);
        return NULL;
    }
    operation->handle = handle;
    operation->kind = kind;
    operation->callback = callback;
    operation->user_data = user_data;
    if (address != NULL) {
        operation->address = ovc_dispatch_cstring_copy(address);
        if (operation->address == NULL) {
            ovc_dispatch_operation_leave(handle);
            free(operation);
            return NULL;
        }
    }
    return operation;
}

static void ovc_dispatch_operation_free(ovc_dispatch_operation *operation)
{
    if (operation == NULL) {
        return;
    }
    ovc_stream_cancel_scope_destroy(operation->stream_scope);
    free(operation->collected_bytes);
    ovstorage_info_destroy(operation->collected_info);
    free(operation->address);
    free(operation);
}

static void ovc_dispatch_operation_fail(
    ovc_dispatch_operation *operation,
    OvStoragePlugin_Error *plugin_error,
    bool free_plugin_error,
    const char *fallback)
{
    OvStorage_Error error;
    OvStorage_LayerHandle *handle;

    handle = operation->handle;
    if (plugin_error != NULL) {
        error = ovc_dispatch_error_from_plugin(plugin_error,
                                               free_plugin_error);
    } else {
        error = ovc_dispatch_public_error(OvStorage_Status_Internal,
                                         fallback);
    }
    ovc_dispatch_fire_callback_error(operation->kind,
                                     operation->callback,
                                     operation->user_data,
                                     &error);
    ovc_dispatch_error_done(&error);
    ovc_dispatch_operation_leave(handle);
    ovc_dispatch_operation_free(operation);
}

static void ovc_dispatch_operation_fail_status(
    ovc_dispatch_operation *operation,
    OvStorage_Status status,
    const char *message)
{
    OvStorage_Error error;
    OvStorage_LayerHandle *handle;

    handle = operation->handle;
    error = ovc_dispatch_public_error(status, message);
    ovc_dispatch_fire_callback_error(operation->kind,
                                     operation->callback,
                                     operation->user_data,
                                     &error);
    ovc_dispatch_error_done(&error);
    ovc_dispatch_operation_leave(handle);
    ovc_dispatch_operation_free(operation);
}

typedef struct ovc_dispatch_local_file_stream {
    FILE *file;
} ovc_dispatch_local_file_stream;

static OvStoragePlugin_ErrorCode ovc_dispatch_native_error_code(
    int native_error)
{
    switch (native_error) {
#ifdef ENOENT
    case ENOENT:
        return OvStoragePlugin_ErrorCode_NotFound;
#endif
#ifdef EACCES
    case EACCES:
        return OvStoragePlugin_ErrorCode_PermissionDenied;
#endif
#if defined(EPERM) && (!defined(EACCES) || EPERM != EACCES)
    case EPERM:
        return OvStoragePlugin_ErrorCode_PermissionDenied;
#endif
    default:
        return OvStoragePlugin_ErrorCode_Transient;
    }
}

/*
 * These errors take the plugin-ABI Error shape and are reclaimed by
 * ovc_dispatch_plugin_error_clear, so they are minted on the ABI allocator
 * even though the host produces them.
 */
static void ovc_dispatch_plugin_error_init(
    OvStoragePlugin_Error *error,
    OvStoragePlugin_ErrorCode code,
    const char *message)
{
    size_t length;

    memset(error, 0, sizeof(*error));
    error->code = code;
    if (message == NULL) {
        message = "local delegate I/O failed";
    }
    length = strlen(message);
    error->message_ptr = (char *)ovc_abi_copy_bytes(message, length);
    if (error->message_ptr == NULL) {
        error->code = OvStoragePlugin_ErrorCode_Internal;
        return;
    }
    error->message_len = length;
}

static OvStoragePlugin_Error *ovc_dispatch_plugin_error_create(
    OvStoragePlugin_ErrorCode code,
    const char *message)
{
    OvStoragePlugin_Error *error;

    error = (OvStoragePlugin_Error *)ovc_abi_alloc(sizeof(*error));
    if (error != NULL) {
        ovc_dispatch_plugin_error_init(error, code, message);
    }
    return error;
}

static OvStoragePlugin_ErrorCode ovc_dispatch_plugin_code_from_status(
    OvStorage_Status status)
{
    switch (status) {
    case OvStorage_Status_NotFound:
        return OvStoragePlugin_ErrorCode_NotFound;
    case OvStorage_Status_AlreadyExists:
        return OvStoragePlugin_ErrorCode_AlreadyExists;
    case OvStorage_Status_PermissionDenied:
        return OvStoragePlugin_ErrorCode_PermissionDenied;
    case OvStorage_Status_PreconditionFailed:
        return OvStoragePlugin_ErrorCode_PreconditionFailed;
    case OvStorage_Status_Conflict:
        return OvStoragePlugin_ErrorCode_Conflict;
    case OvStorage_Status_DirectoryNotEmpty:
        return OvStoragePlugin_ErrorCode_DirectoryNotEmpty;
    case OvStorage_Status_Unsupported:
        return OvStoragePlugin_ErrorCode_Unsupported;
    case OvStorage_Status_InvalidArgument:
        return OvStoragePlugin_ErrorCode_InvalidArgument;
    case OvStorage_Status_IncompatibleType:
        return OvStoragePlugin_ErrorCode_IncompatibleType;
    case OvStorage_Status_Cancelled:
        return OvStoragePlugin_ErrorCode_Cancelled;
    case OvStorage_Status_Transient:
        return OvStoragePlugin_ErrorCode_Transient;
    case OvStorage_Status_ResourceExhausted:
        return OvStoragePlugin_ErrorCode_ResourceExhausted;
    /* Without this arm a write-stream producer reporting a half-completed
     * operation falls to the default and is re-coded Internal, losing the one
     * distinction the code exists to make. */
    case OvStorage_Status_PartialCompletion:
        return OvStoragePlugin_ErrorCode_PartialCompletion;
    case OvStorage_Status_ObjectModified:
        return OvStoragePlugin_ErrorCode_ObjectModified;
    case OvStorage_Status_NoRoute:
        return OvStoragePlugin_ErrorCode_NoRoute;
    case OvStorage_Status_Ok:
    case OvStorage_Status_Internal:
    default:
        return OvStoragePlugin_ErrorCode_Internal;
    }
}

static OvStoragePlugin_StreamStep ovc_dispatch_write_stream_next(
    void *opaque,
    OvStoragePlugin_Bytes *out_chunk,
    OvStoragePlugin_Error *out_error)
{
    ovc_dispatch_write_stream *stream;
    OvStorage_Bytes chunk;
    OvStorage_Status status;
    const char *message;
    OvStorage_WriteStreamStep step;

    stream = (ovc_dispatch_write_stream *)opaque;
    memset(out_chunk, 0, sizeof(*out_chunk));
    memset(out_error, 0, sizeof(*out_error));
    memset(&chunk, 0, sizeof(chunk));
    status = OvStorage_Status_Internal;
    message = NULL;
    step = stream->source.next(stream->source.state,
                               &chunk,
                               &status,
                               &message);
    if (step == OvStorage_WriteStreamStep_Chunk) {
        if (chunk.data == NULL && chunk.len != 0) {
            ovstorage_bytes_destroy(&chunk);
            ovc_dispatch_plugin_error_init(
                out_error,
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "write stream returned an invalid chunk");
            return OvStoragePlugin_StreamStep_Failed;
        }
        if (!ovc_dispatch_abi_bytes_copy(out_chunk,
                                         chunk.data,
                                         chunk.len)) {
            ovstorage_bytes_destroy(&chunk);
            ovc_dispatch_plugin_error_init(
                out_error,
                OvStoragePlugin_ErrorCode_ResourceExhausted,
                "could not copy a write stream chunk");
            return OvStoragePlugin_StreamStep_Failed;
        }
        ovstorage_bytes_destroy(&chunk);
        return OvStoragePlugin_StreamStep_Yielded;
    }
    ovstorage_bytes_destroy(&chunk);
    if (step == OvStorage_WriteStreamStep_End) {
        return OvStoragePlugin_StreamStep_Ended;
    }
    ovc_dispatch_plugin_error_init(
        out_error,
        ovc_dispatch_plugin_code_from_status(status),
        message == NULL ? "write stream producer failed" : message);
    return OvStoragePlugin_StreamStep_Failed;
}

static void ovc_dispatch_write_stream_drop(void *opaque)
{
    ovc_dispatch_write_stream *stream;

    stream = (ovc_dispatch_write_stream *)opaque;
    if (stream == NULL) {
        return;
    }
    stream->source.drop(stream->source.state);
    free(stream);
}

static FILE *ovc_dispatch_open_local_delegate(const char *path)
{
#if defined(_WIN32)
    int wide_count;
    WCHAR *wide;
    FILE *file;

    if (path == NULL) {
        errno = EINVAL;
        return NULL;
    }
    wide_count = MultiByteToWideChar(CP_UTF8,
                                     MB_ERR_INVALID_CHARS,
                                     path,
                                     -1,
                                     NULL,
                                     0);
    if (wide_count <= 0 ||
        (size_t)wide_count > SIZE_MAX / sizeof(*wide)) {
        errno = EINVAL;
        return NULL;
    }
    wide = (WCHAR *)malloc((size_t)wide_count * sizeof(*wide));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8,
                            MB_ERR_INVALID_CHARS,
                            path,
                            -1,
                            wide,
                            wide_count) <= 0) {
        free(wide);
        errno = EINVAL;
        return NULL;
    }
    file = NULL;
    if (_wfopen_s(&file, wide, L"rb") != 0) {
        file = NULL;
    }
    free(wide);
    return file;
#else
    return fopen(path, "rb");
#endif
}

static OvStoragePlugin_StreamStep ovc_dispatch_local_file_next(
    void *opaque,
    OvStoragePlugin_Bytes *out_chunk,
    OvStoragePlugin_Error *out_error)
{
    enum { OVC_DISPATCH_LOCAL_FILE_CHUNK_SIZE = 64 * 1024 };
    ovc_dispatch_local_file_stream *stream;
    uint8_t *bytes;
    size_t count;
    int native_error;

    stream = (ovc_dispatch_local_file_stream *)opaque;
    /* Chunks are reclaimed by the pump's ABI bytes clear. */
    bytes = (uint8_t *)ovc_abi_alloc(OVC_DISPATCH_LOCAL_FILE_CHUNK_SIZE);
    if (bytes == NULL) {
        ovc_dispatch_plugin_error_init(
            out_error,
            OvStoragePlugin_ErrorCode_ResourceExhausted,
            "could not allocate a local delegate read chunk");
        return OvStoragePlugin_StreamStep_Failed;
    }
    errno = 0;
    count = fread(bytes,
                  1,
                  OVC_DISPATCH_LOCAL_FILE_CHUNK_SIZE,
                  stream->file);
    if (count != 0) {
        out_chunk->ptr = bytes;
        out_chunk->len = count;
        return OvStoragePlugin_StreamStep_Yielded;
    }
    ovc_abi_free(bytes);
    if (feof(stream->file)) {
        return OvStoragePlugin_StreamStep_Ended;
    }
    native_error = errno == 0 ? EIO : errno;
    ovc_dispatch_plugin_error_init(
        out_error,
        ovc_dispatch_native_error_code(native_error),
        "could not read a local delegate file");
    return OvStoragePlugin_StreamStep_Failed;
}

static void ovc_dispatch_local_file_drop(void *opaque)
{
    ovc_dispatch_local_file_stream *stream;

    stream = (ovc_dispatch_local_file_stream *)opaque;
    if (stream != NULL) {
        if (stream->file != NULL) {
            (void)fclose(stream->file);
        }
        free(stream);
    }
}

static bool ovc_dispatch_local_delegate_to_stream(
    OvStoragePlugin_ReadResult *result,
    OvStoragePlugin_Error **out_error)
{
    ovc_dispatch_local_file_stream *state;
    char *path;
    FILE *file;
    int native_error;

    *out_error = NULL;
    if (result == NULL ||
        result->tag != OvStoragePlugin_ReadResultTag_LocalDelegate) {
        return false;
    }
    path = ovc_dispatch_slice_copy(result->local_delegate.path.ptr,
                                   result->local_delegate.path.len);
    if (path == NULL) {
        *out_error = ovc_dispatch_plugin_error_create(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "local delegate path is not valid UTF-8 path data");
        return false;
    }
    errno = 0;
    file = ovc_dispatch_open_local_delegate(path);
    native_error = errno;
    free(path);
    if (file == NULL) {
        *out_error = ovc_dispatch_plugin_error_create(
            ovc_dispatch_native_error_code(native_error),
            "could not open a local delegate file");
        return false;
    }
    state = (ovc_dispatch_local_file_stream *)calloc(1, sizeof(*state));
    if (state == NULL) {
        (void)fclose(file);
        *out_error = ovc_dispatch_plugin_error_create(
            OvStoragePlugin_ErrorCode_ResourceExhausted,
            "could not allocate local delegate stream state");
        return false;
    }
    state->file = file;

    result->stream.info = result->local_delegate.info;
    memset(&result->local_delegate.info,
           0,
           sizeof(result->local_delegate.info));
    ovc_dispatch_abi_str_clear(&result->local_delegate.path);
    /* The file is now held open; release the delegate's optional lease
     * before the result is re-tagged as a Stream, which orphans
     * the local_delegate field. */
    ovc_dispatch_lease_drop(&result->local_delegate.lease);
    result->stream.stream.state = state;
    result->stream.stream.next_fn = ovc_dispatch_local_file_next;
    result->stream.stream.drop_fn = ovc_dispatch_local_file_drop;
    result->tag = OvStoragePlugin_ReadResultTag_Stream;
    return true;
}

static void ovc_dispatch_result_discard(ovc_dispatch_operation_kind kind,
                                        void *result)
{
    if (result == NULL) {
        return;
    }
    switch (kind) {
    case OVC_DISPATCH_INFO_OBJECT:
        ovc_dispatch_object_info_clear((OvStoragePlugin_ObjectInfo *)result,
                                       true);
        break;
    case OVC_DISPATCH_INFO_WRITE:
        ovc_dispatch_write_result_clear(
            (OvStoragePlugin_WriteResult *)result);
        break;
    case OVC_DISPATCH_INFO_WRITE_STEP:
        ovc_dispatch_write_step_clear((OvStoragePlugin_WriteStep *)result);
        break;
    case OVC_DISPATCH_INFO_BACKEND_ITEM:
        ovc_dispatch_backend_item_clear(
            (OvStoragePlugin_BackendItemInfo *)result, true);
        break;
    case OVC_DISPATCH_READ_BYTES:
    case OVC_DISPATCH_READ_STREAM:
        ovc_dispatch_read_result_clear(
            (OvStoragePlugin_ReadResult *)result, true);
        break;
    case OVC_DISPATCH_LOCAL_DELEGATE:
        ovc_dispatch_local_delegate_clear(
            (OvStoragePlugin_LocalDelegate *)result);
        break;
    case OVC_DISPATCH_LIST:
        ovc_dispatch_list_page_clear((OvStoragePlugin_ListPage *)result);
        break;
    case OVC_DISPATCH_VERSION_LIST:
        ovc_dispatch_version_page_clear(
            (OvStoragePlugin_VersionPage *)result);
        break;
    case OVC_DISPATCH_ACCESS:
        ovc_dispatch_access_clear(
            (OvStoragePlugin_AccessDecision *)result);
        break;
    case OVC_DISPATCH_CONNECTION:
        ovc_dispatch_connection_clear(
            (OvStoragePlugin_Connection *)result, true);
        break;
    case OVC_DISPATCH_AUTH_STREAM: {
        OvStoragePlugin_AuthEventStream *stream;

        stream = (OvStoragePlugin_AuthEventStream *)result;
        if (stream->drop_fn != NULL) {
            stream->drop_fn(stream->state);
        }
        ovc_abi_free(stream);
        break;
    }
    case OVC_DISPATCH_WATCH_STREAM: {
        OvStoragePlugin_BackendChangeStream *stream;

        stream = (OvStoragePlugin_BackendChangeStream *)result;
        if (stream->drop_fn != NULL) {
            stream->drop_fn(stream->state);
        }
        ovc_abi_free(stream);
        break;
    }
    case OVC_DISPATCH_WRITE_REDIRECT_BATCH: {
        OvStoragePlugin_WriteRedirectBatch *batch;

        batch = (OvStoragePlugin_WriteRedirectBatch *)result;
        ovc_dispatch_write_redirect_batch_clear(batch);
        ovc_abi_free(batch);
        break;
    }
    case OVC_DISPATCH_WRITE_STEP:
        ovc_dispatch_write_step_clear((OvStoragePlugin_WriteStep *)result);
        break;
    case OVC_DISPATCH_ROOT_LIST: {
        OvStoragePlugin_ListAddressRootsResult *envelope;

        envelope = (OvStoragePlugin_ListAddressRootsResult *)result;
        (void)ovc_dispatch_root_updates_discard(envelope->updates);
        ovc_dispatch_root_snapshot_clear(&envelope->snapshot);
        ovc_abi_free(envelope);
        break;
    }
    case OVC_DISPATCH_CONNECTION_LIST: {
        OvStoragePlugin_ListConnectionsResult *envelope;

        envelope = (OvStoragePlugin_ListConnectionsResult *)result;
        ovc_dispatch_connection_updates_clear(envelope->updates);
        ovc_dispatch_connection_snapshot_clear(&envelope->snapshot);
        ovc_abi_free(envelope);
        break;
    }
    case OVC_DISPATCH_STATUS:
    default:
        ovc_abi_free(result);
        break;
    }
}

static void ovc_dispatch_read_result_reclaim(void *owner)
{
    ovc_dispatch_read_result_clear((OvStoragePlugin_ReadResult *)owner,
                                   true);
}

static void ovc_dispatch_auth_stream_reclaim(void *owner)
{
    OvStoragePlugin_AuthEventStream *stream;

    stream = (OvStoragePlugin_AuthEventStream *)owner;
    if (stream != NULL) {
        if (stream->drop_fn != NULL) {
            stream->drop_fn(stream->state);
        }
        ovc_abi_free(stream);
    }
}

static void ovc_dispatch_byte_collect_item(
    OvStoragePlugin_Bytes *chunk,
    bool deliver,
    void *user_data)
{
    ovc_dispatch_operation *operation;

    operation = (ovc_dispatch_operation *)user_data;
    if (deliver && !operation->stream_conversion_failed) {
        if ((chunk->ptr == NULL && chunk->len != 0) ||
            chunk->len > SIZE_MAX - operation->collected_len) {
            /* The terminal is already bound to report this failure;
             * stop collecting and cancel the pump's scope so the
             * producer winds down instead of draining the rest of the
             * stream. */
            operation->stream_conversion_failed = true;
            ovc_stream_pump_cancel(operation->pump);
        } else if (operation->collected_len + chunk->len >
                   operation->collected_capacity) {
            size_t needed;
            size_t next_capacity;
            uint8_t *next;

            needed = operation->collected_len + chunk->len;
            next_capacity = operation->collected_capacity == 0
                                ? 4096
                                : operation->collected_capacity;
            while (next_capacity < needed) {
                if (next_capacity > SIZE_MAX / 2) {
                    next_capacity = needed;
                    break;
                }
                next_capacity *= 2;
            }
            next = (uint8_t *)realloc(operation->collected_bytes,
                                      next_capacity);
            if (next == NULL) {
                operation->stream_conversion_failed = true;
                ovc_stream_pump_cancel(operation->pump);
            } else {
                operation->collected_bytes = next;
                operation->collected_capacity = next_capacity;
            }
        }
        if (!operation->stream_conversion_failed && chunk->len != 0) {
            memcpy(operation->collected_bytes + operation->collected_len,
                   chunk->ptr,
                   chunk->len);
            operation->collected_len += chunk->len;
        }
    }
    ovc_dispatch_abi_bytes_clear(chunk, false);
}

static void ovc_dispatch_byte_pump_item(OvStoragePlugin_Bytes *chunk,
                                        bool deliver,
                                        void *user_data)
{
    ovc_dispatch_operation *operation;
    OvStorage_Bytes public_chunk;

    operation = (ovc_dispatch_operation *)user_data;
    memset(&public_chunk, 0, sizeof(public_chunk));
    if (deliver && !operation->stream_conversion_failed) {
        if (ovc_dispatch_public_bytes_copy(&public_chunk,
                                           chunk->ptr,
                                           chunk->len)) {
            operation->callback.read_stream(public_chunk,
                                            NULL,
                                            false,
                                            operation->user_data);
        } else {
            /* Delivering later chunks would hand the caller a byte
             * sequence with a hole; stop deliveries and cancel the pump's
             * scope so the producer winds down instead of draining. */
            operation->stream_conversion_failed = true;
            ovc_stream_pump_cancel(operation->pump);
        }
    }
    ovc_dispatch_abi_bytes_clear(chunk, false);
}

static void ovc_dispatch_stream_terminal(
    ovc_stream_terminal_reason reason,
    OvStoragePlugin_Error *plugin_error,
    void *user_data)
{
    ovc_dispatch_operation *operation;
    OvStorage_Error error;
    OvStorage_Bytes empty;
    bool buffered;
    bool success;

    operation = (ovc_dispatch_operation *)user_data;
    memset(&empty, 0, sizeof(empty));
    buffered = operation->kind == OVC_DISPATCH_READ_BYTES;
    success = reason == OVC_STREAM_TERMINAL_ENDED &&
              !operation->stream_conversion_failed;
    if (success && buffered && operation->collected_info == NULL) {
        operation->stream_conversion_failed = true;
        success = false;
    }
    if (success && buffered && operation->collected_bytes == NULL) {
        operation->collected_bytes = (uint8_t *)malloc(1);
        if (operation->collected_bytes == NULL) {
            operation->stream_conversion_failed = true;
            success = false;
        } else {
            operation->collected_bytes[0] = 0;
        }
    }
    if (!success) {
        if (operation->stream_conversion_failed) {
            /* A conversion failure cancels the pump itself to stop the
             * producer; report that first failure, not the wind-down
             * cancellation or a later producer error. */
            ovc_dispatch_plugin_error_clear(plugin_error, false);
            error = ovc_dispatch_public_error(
                OvStorage_Status_Internal,
                "could not convert a streamed byte chunk");
        } else if (reason == OVC_STREAM_TERMINAL_CANCELED) {
            ovc_dispatch_plugin_error_clear(plugin_error, false);
            error = ovc_dispatch_public_error(OvStorage_Status_Cancelled,
                                              "stream was cancelled");
        } else if (plugin_error != NULL) {
            error = ovc_dispatch_error_from_plugin(plugin_error, false);
        } else {
            error = ovc_dispatch_public_error(
                OvStorage_Status_Internal,
                "stream ended with an invalid protocol result");
        }
    } else {
        memset(&error, 0, sizeof(error));
    }
    if (success) {
        if (buffered) {
            OvStorage_Bytes bytes;
            OvStorage_Info *info;

            bytes.data = operation->collected_bytes;
            bytes.len = operation->collected_len;
            bytes.free_ctx = operation->collected_bytes;
            operation->collected_bytes = NULL;
            operation->collected_len = 0;
            operation->collected_capacity = 0;
            info = operation->collected_info;
            operation->collected_info = NULL;
            operation->callback.read_bytes(OvStorage_Status_Ok,
                                           bytes,
                                           info,
                                           NULL,
                                           operation->user_data);
        } else {
            operation->callback.read_stream(empty,
                                            NULL,
                                            true,
                                            operation->user_data);
        }
    } else {
        if (buffered) {
            operation->callback.read_bytes(error.code,
                                           empty,
                                           NULL,
                                           &error,
                                           operation->user_data);
        } else {
            operation->callback.read_stream(empty,
                                            &error,
                                            true,
                                            operation->user_data);
        }
        ovc_dispatch_error_done(&error);
    }
    ovc_dispatch_reap_completed_pump(operation);
    ovc_dispatch_operation_leave(operation->handle);
    ovc_dispatch_operation_free(operation);
}

static void ovc_dispatch_auth_pump_item(OvStoragePlugin_AuthEvent *event,
                                        bool deliver,
                                        void *user_data)
{
    ovc_dispatch_operation *operation;
    OvStorage_AuthEvent *public_event;

    operation = (ovc_dispatch_operation *)user_data;
    public_event = NULL;
    /* After a conversion failure (OOM), deliver no further events so the
     * event sequence agrees with the terminal-error fire. */
    if (deliver && !operation->stream_conversion_failed) {
        public_event = ovc_dispatch_auth_event_from_plugin(event);
        if (public_event != NULL) {
            operation->callback.auth(public_event,
                                     NULL,
                                     false,
                                     operation->user_data);
        } else {
            /* Delivering later events would hand the caller an event
             * sequence with a hole; stop deliveries and cancel the pump's
             * scope so the producer winds down instead of running the
             * interactive flow to completion with every event discarded. */
            operation->stream_conversion_failed = true;
            ovc_stream_pump_cancel(operation->pump);
        }
    }
    ovc_dispatch_auth_event_clear(event);
}

static void ovc_dispatch_auth_terminal(
    ovc_stream_terminal_reason reason,
    OvStoragePlugin_Error *plugin_error,
    void *user_data)
{
    ovc_dispatch_operation *operation;
    OvStorage_Error error;
    bool success;

    operation = (ovc_dispatch_operation *)user_data;
    success = reason == OVC_STREAM_TERMINAL_ENDED &&
              !operation->stream_conversion_failed;
    if (!success) {
        if (operation->stream_conversion_failed) {
            /* A conversion failure cancels the pump itself to stop the
             * producer; report that first failure, not the wind-down
             * cancellation or a later producer error. */
            ovc_dispatch_plugin_error_clear(plugin_error, false);
            error = ovc_dispatch_public_error(
                OvStorage_Status_Internal,
                "could not convert an authentication event");
        } else if (reason == OVC_STREAM_TERMINAL_CANCELED) {
            ovc_dispatch_plugin_error_clear(plugin_error, false);
            error = ovc_dispatch_public_error(OvStorage_Status_Cancelled,
                                              "authentication was cancelled");
        } else if (plugin_error != NULL) {
            error = ovc_dispatch_error_from_plugin(plugin_error, false);
        } else {
            error = ovc_dispatch_public_error(
                OvStorage_Status_Internal,
                "authentication stream returned an invalid protocol result");
        }
    } else {
        memset(&error, 0, sizeof(error));
    }
    operation->callback.auth(NULL,
                             success ? NULL : &error,
                             true,
                             operation->user_data);
    if (!success) {
        ovc_dispatch_error_done(&error);
    }
    ovc_dispatch_reap_completed_pump(operation);
    ovc_dispatch_operation_leave(operation->handle);
    ovc_dispatch_operation_free(operation);
}

static bool ovc_dispatch_millis_to_nanos(int64_t millis,
                                         uint64_t *out_nanos)
{
    if (millis < 0 ||
        (uint64_t)millis > UINT64_MAX / UINT64_C(1000000)) {
        return false;
    }
    *out_nanos = (uint64_t)millis * UINT64_C(1000000);
    return true;
}

static void ovc_dispatch_public_change_clear(
    OvStorage_BackendChangeEvent *event)
{
    if (event == NULL) {
        return;
    }
    free((char *)event->address);
    free((char *)event->etag);
    free((char *)event->version);
    memset(event, 0, sizeof(*event));
}

static bool ovc_dispatch_change_from_plugin(
    OvStorage_BackendChangeEvent *out,
    const OvStoragePlugin_BackendChangeEvent *source)
{
    memset(out, 0, sizeof(*out));
    if (source->tag == OvStoragePlugin_BackendChangeEventTag_Object) {
        const OvStoragePlugin_BackendChangeEventObject *object;

        object = &source->object;
        if (object->kind > OvStoragePlugin_ChangeKind_MetadataChanged ||
            !ovc_dispatch_millis_to_nanos(object->at_unix_ms,
                                          &out->at_unix_nanos)) {
            return false;
        }
        out->kind = OvStorage_BackendChangeEventKind_Object;
        out->change_kind = (OvStorage_ChangeKind)object->kind;
        out->address = ovc_dispatch_slice_copy(object->address.ptr,
                                               object->address.len);
        if (out->address == NULL) {
            return false;
        }
        if (object->etag.present) {
            out->etag = ovc_dispatch_slice_copy(object->etag.value.ptr,
                                                object->etag.value.len);
            if (out->etag == NULL) {
                ovc_dispatch_public_change_clear(out);
                return false;
            }
        }
        if (object->version.present) {
            out->version = ovc_dispatch_slice_copy(
                object->version.value.ptr, object->version.value.len);
            if (out->version == NULL) {
                ovc_dispatch_public_change_clear(out);
                return false;
            }
        }
        out->has_size = object->size.present;
        if (out->has_size) {
            out->size = object->size.value;
        }
        if (object->mtime_unix_ms.present) {
            out->has_mtime_unix_nanos = ovc_dispatch_millis_to_nanos(
                object->mtime_unix_ms.value,
                &out->mtime_unix_nanos);
        }
        out->cursor = object->cursor.bytes.ptr;
        out->cursor_len = object->cursor.bytes.len;
        if (out->cursor == NULL && out->cursor_len != 0) {
            ovc_dispatch_public_change_clear(out);
            return false;
        }
        return true;
    }
    if (source->tag == OvStoragePlugin_BackendChangeEventTag_Lapsed) {
        out->kind = OvStorage_BackendChangeEventKind_Lapsed;
        if (source->lapsed.since_unix_ms.present) {
            out->has_since_unix_nanos = ovc_dispatch_millis_to_nanos(
                source->lapsed.since_unix_ms.value,
                &out->since_unix_nanos);
        }
        out->cursor = source->lapsed.cursor.bytes.ptr;
        out->cursor_len = source->lapsed.cursor.bytes.len;
        return out->cursor != NULL || out->cursor_len == 0;
    }
    return false;
}

static void ovc_dispatch_watch_stream_reclaim(void *owner)
{
    ovstorage_plugin_backend_change_stream_free(
        (OvStoragePlugin_BackendChangeStream *)owner);
}

static void ovc_dispatch_watch_pump_item(
    OvStoragePlugin_BackendChangeEvent *event,
    bool deliver,
    void *user_data)
{
    ovc_dispatch_operation *operation;
    OvStorage_BackendChangeEvent public_event;

    operation = (ovc_dispatch_operation *)user_data;
    memset(&public_event, 0, sizeof(public_event));
    if (deliver && !operation->stream_conversion_failed) {
        if (ovc_dispatch_change_from_plugin(&public_event, event)) {
            operation->callback.watch(&public_event,
                                      NULL,
                                      false,
                                      operation->user_data);
            ovc_dispatch_public_change_clear(&public_event);
        } else {
            operation->stream_conversion_failed = true;
            ovc_stream_pump_cancel(operation->pump);
        }
    }
    ovstorage_plugin_backend_change_event_free(event);
}

static void ovc_dispatch_watch_terminal(
    ovc_stream_terminal_reason reason,
    OvStoragePlugin_Error *plugin_error,
    void *user_data)
{
    ovc_dispatch_operation *operation;
    OvStorage_Error error;
    bool success;

    operation = (ovc_dispatch_operation *)user_data;
    success = reason == OVC_STREAM_TERMINAL_ENDED &&
              !operation->stream_conversion_failed;
    if (!success) {
        if (operation->stream_conversion_failed) {
            ovc_dispatch_plugin_error_clear(plugin_error, false);
            error = ovc_dispatch_public_error(
                OvStorage_Status_Internal,
                "could not convert a directory change event");
        } else if (reason == OVC_STREAM_TERMINAL_CANCELED) {
            ovc_dispatch_plugin_error_clear(plugin_error, false);
            error = ovc_dispatch_public_error(
                OvStorage_Status_Cancelled,
                "directory watch was cancelled");
        } else if (plugin_error != NULL) {
            error = ovc_dispatch_error_from_plugin(plugin_error, false);
        } else {
            error = ovc_dispatch_public_error(
                OvStorage_Status_Internal,
                "directory watch returned an invalid protocol result");
        }
    } else {
        memset(&error, 0, sizeof(error));
    }
    operation->callback.watch(NULL,
                              success ? NULL : &error,
                              true,
                              operation->user_data);
    if (!success) {
        ovc_dispatch_error_done(&error);
    }
    ovc_dispatch_reap_completed_pump(operation);
    ovc_dispatch_operation_leave(operation->handle);
    ovc_dispatch_operation_free(operation);
}

static void ovc_dispatch_complete(int32_t status,
                                  void *result,
                                  OvStoragePlugin_Error *plugin_error,
                                  void *user_data)
{
    ovc_dispatch_operation *operation;
    operation = (ovc_dispatch_operation *)user_data;
    /* The frozen ABI defines pointer presence as the outcome discriminator. */
    (void)status;
    if (plugin_error != NULL) {
        ovc_dispatch_result_discard(operation->kind, result);
        ovc_dispatch_operation_fail(operation,
                                    plugin_error,
                                    true,
                                    "plugin operation failed without an error");
        return;
    }
    if (operation->kind != OVC_DISPATCH_STATUS && result == NULL) {
        ovc_dispatch_operation_fail(
            operation,
            NULL,
            false,
            "plugin completed without an error or required result");
        return;
    }

    switch (operation->kind) {
    case OVC_DISPATCH_INFO_OBJECT: {
        OvStorage_Info *info;

        info = ovc_dispatch_info_from_object(
            (OvStoragePlugin_ObjectInfo *)result);
        ovc_dispatch_object_info_clear(
            (OvStoragePlugin_ObjectInfo *)result, true);
        if (info == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert object metadata");
            return;
        }
        operation->callback.info(OvStorage_Status_Ok,
                                 info,
                                 NULL,
                                 operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_INFO_WRITE: {
        OvStoragePlugin_WriteResult *write_result;
        OvStorage_Info *info;

        write_result = (OvStoragePlugin_WriteResult *)result;
        info = write_result == NULL
                   ? NULL
                   : ovc_dispatch_info_from_object(&write_result->info);
        ovc_dispatch_write_result_clear(write_result);
        if (info == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert write metadata");
            return;
        }
        operation->callback.info(OvStorage_Status_Ok,
                                 info,
                                 NULL,
                                 operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_INFO_WRITE_STEP: {
        OvStoragePlugin_WriteStep *step;
        OvStorage_Info *info;
        bool redirects;

        step = (OvStoragePlugin_WriteStep *)result;
        redirects = step != NULL &&
                    step->tag == OvStoragePlugin_WriteStepTag_Redirects;
        info = step != NULL && step->tag == OvStoragePlugin_WriteStepTag_Done
                   ? ovc_dispatch_info_from_object(&step->done.info)
                   : NULL;
        ovc_dispatch_write_step_clear(step);
        if (info == NULL) {
            if (redirects) {
                ovc_dispatch_operation_fail_status(
                    operation,
                    OvStorage_Status_Unsupported,
                    "copy returned redirects but this Stack has no redirect follower");
            } else {
                ovc_dispatch_operation_fail(
                    operation,
                    NULL,
                    false,
                    "could not convert copy metadata");
            }
            return;
        }
        operation->callback.info(OvStorage_Status_Ok,
                                 info,
                                 NULL,
                                 operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_WRITE_REDIRECT_BATCH: {
        OvStoragePlugin_WriteRedirectBatch *plugin_batch;
        OvStorage_WriteRedirectBatch *batch;

        plugin_batch = (OvStoragePlugin_WriteRedirectBatch *)result;
        batch = ovc_dispatch_public_redirect_batch_from_plugin(
            plugin_batch);
        ovc_dispatch_write_redirect_batch_clear(plugin_batch);
        ovc_abi_free(plugin_batch);
        if (batch == NULL) {
            ovc_dispatch_operation_fail(
                operation,
                NULL,
                false,
                "could not convert write redirects");
            return;
        }
        operation->callback.write_redirect(OvStorage_Status_Ok,
                                           batch,
                                           NULL,
                                           operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_WRITE_STEP: {
        OvStoragePlugin_WriteStep *step;
        OvStorage_Info *info;
        OvStorage_WriteRedirectBatch *batch;

        step = (OvStoragePlugin_WriteStep *)result;
        info = NULL;
        batch = NULL;
        if (step != NULL &&
            step->tag == OvStoragePlugin_WriteStepTag_Done) {
            info = ovc_dispatch_info_from_object(&step->done.info);
        } else if (step != NULL &&
                   step->tag ==
                       OvStoragePlugin_WriteStepTag_Redirects) {
            batch = ovc_dispatch_public_redirect_batch_from_plugin(
                &step->redirects);
        }
        ovc_dispatch_write_step_clear(step);
        if (info == NULL && batch == NULL) {
            ovc_dispatch_operation_fail(
                operation,
                NULL,
                false,
                "could not convert continued write result");
            return;
        }
        operation->callback.write_step(OvStorage_Status_Ok,
                                       info,
                                       batch,
                                       NULL,
                                       operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_INFO_BACKEND_ITEM: {
        OvStoragePlugin_BackendItemInfo *item;
        OvStorage_Info *info;

        item = (OvStoragePlugin_BackendItemInfo *)result;
        info = ovc_dispatch_info_from_backend_item(item, operation->address);
        ovc_dispatch_backend_item_clear(item, true);
        if (info == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert object metadata");
            return;
        }
        operation->callback.info(OvStorage_Status_Ok,
                                 info,
                                 NULL,
                                 operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_READ_BYTES: {
        OvStoragePlugin_ReadResult *read_result;
        OvStoragePlugin_Error *local_error;

        read_result = (OvStoragePlugin_ReadResult *)result;
        local_error = NULL;
        if (read_result != NULL &&
            read_result->tag ==
                OvStoragePlugin_ReadResultTag_LocalDelegate &&
            !ovc_dispatch_local_delegate_to_stream(read_result,
                                                   &local_error)) {
            ovc_dispatch_read_result_clear(read_result, true);
            ovc_dispatch_operation_fail(
                operation,
                local_error,
                true,
                "could not open a local delegate returned by read");
            return;
        }
        if (read_result != NULL &&
            read_result->tag == OvStoragePlugin_ReadResultTag_Redirect) {
            ovc_dispatch_read_result_clear(read_result, true);
            ovc_dispatch_operation_fail_status(
                operation,
                OvStorage_Status_Unsupported,
                "read returned a redirect but this Stack has no redirect follower");
            return;
        }
        if (ovc_stream_cancel_scope_is_canceled(
                operation->stream_scope)) {
            ovc_dispatch_read_result_clear(read_result, true);
            ovc_dispatch_operation_fail_status(
                operation,
                OvStorage_Status_Cancelled,
                "read was cancelled");
            return;
        }
        if (read_result != NULL &&
            read_result->tag == OvStoragePlugin_ReadResultTag_Bytes) {
            OvStorage_Bytes bytes;
            OvStorage_Info *info;
            bool converted;

            memset(&bytes, 0, sizeof(bytes));
            converted = ovc_dispatch_public_bytes_copy(
                &bytes,
                read_result->bytes.bytes.ptr,
                read_result->bytes.bytes.len);
            info = ovc_dispatch_info_from_object(&read_result->bytes.info);
            ovc_dispatch_read_result_clear(read_result, true);
            if (!converted || info == NULL) {
                ovstorage_bytes_destroy(&bytes);
                ovstorage_info_destroy(info);
                ovc_dispatch_operation_fail(
                    operation,
                    NULL,
                    false,
                    "could not convert buffered read bytes");
                return;
            }
            operation->callback.read_bytes(OvStorage_Status_Ok,
                                           bytes,
                                           info,
                                           NULL,
                                           operation->user_data);
            ovc_dispatch_operation_leave(operation->handle);
            break;
        }
        if (read_result != NULL &&
            read_result->tag == OvStoragePlugin_ReadResultTag_Stream) {
            ovc_stream_pump *pump;

            operation->collected_info = ovc_dispatch_info_from_object(
                &read_result->stream.info);
            pump = NULL;
            if (operation->collected_info != NULL &&
                ovc_byte_stream_pump_start(
                    &pump,
                    &read_result->stream.stream,
                    read_result,
                    ovc_dispatch_read_result_reclaim,
                    operation->stream_scope,
                    ovc_dispatch_byte_collect_item,
                    ovc_dispatch_stream_terminal,
                    operation) == 0) {
                operation->stream_scope = NULL;
                operation->pump = pump;
                if (!ovc_dispatch_register_pump(operation->handle, pump)) {
                    ovc_stream_pump_destroy(pump);
                    return;
                }
                return;
            }
        }
        ovc_dispatch_read_result_clear(read_result, true);
        ovc_dispatch_operation_fail(
            operation,
            NULL,
            false,
            "read result is not available as buffered bytes");
        return;
    }
    case OVC_DISPATCH_READ_STREAM: {
        OvStoragePlugin_ReadResult *read_result;
        OvStoragePlugin_Error *local_error;

        read_result = (OvStoragePlugin_ReadResult *)result;
        local_error = NULL;
        if (read_result != NULL &&
            read_result->tag ==
                OvStoragePlugin_ReadResultTag_LocalDelegate &&
            !ovc_dispatch_local_delegate_to_stream(read_result,
                                                   &local_error)) {
            ovc_dispatch_read_result_clear(read_result, true);
            ovc_dispatch_operation_fail(
                operation,
                local_error,
                true,
                "could not open a local delegate returned by read");
            return;
        }
        if (read_result != NULL &&
            read_result->tag == OvStoragePlugin_ReadResultTag_Redirect) {
            ovc_dispatch_read_result_clear(read_result, true);
            ovc_dispatch_operation_fail_status(
                operation,
                OvStorage_Status_Unsupported,
                "read returned a redirect but this Stack has no redirect follower");
            return;
        }
        if (read_result != NULL &&
            read_result->tag == OvStoragePlugin_ReadResultTag_Bytes) {
            OvStorage_Bytes bytes;
            OvStorage_Bytes empty;

            memset(&bytes, 0, sizeof(bytes));
            memset(&empty, 0, sizeof(empty));
            if (ovc_stream_cancel_scope_is_canceled(
                    operation->stream_scope)) {
                ovc_dispatch_read_result_clear(read_result, true);
                ovc_dispatch_operation_fail_status(
                    operation,
                    OvStorage_Status_Cancelled,
                    "read stream was cancelled");
                return;
            }
            if (!ovc_dispatch_public_bytes_copy(
                    &bytes,
                    read_result->bytes.bytes.ptr,
                    read_result->bytes.bytes.len)) {
                ovc_dispatch_read_result_clear(read_result, true);
                ovc_dispatch_operation_fail(operation,
                                            NULL,
                                            false,
                                            "could not convert read bytes");
                return;
            }
            ovc_dispatch_read_result_clear(read_result, true);
            ovc_stream_cancel_scope_destroy(operation->stream_scope);
            operation->stream_scope = NULL;
            operation->callback.read_stream(bytes,
                                            NULL,
                                            false,
                                            operation->user_data);
            operation->callback.read_stream(empty,
                                            NULL,
                                            true,
                                            operation->user_data);
            ovc_dispatch_operation_leave(operation->handle);
            break;
        }
        if (read_result != NULL &&
            read_result->tag == OvStoragePlugin_ReadResultTag_Stream) {
            ovc_stream_pump *pump;

            pump = NULL;
            if (ovc_byte_stream_pump_start(
                    &pump,
                    &read_result->stream.stream,
                    read_result,
                    ovc_dispatch_read_result_reclaim,
                    operation->stream_scope,
                    ovc_dispatch_byte_pump_item,
                    ovc_dispatch_stream_terminal,
                    operation) == 0) {
                operation->stream_scope = NULL;
                operation->pump = pump;
                if (!ovc_dispatch_register_pump(operation->handle, pump)) {
                    ovc_stream_pump_destroy(pump);
                    return;
                }
                return;
            }
        }
        ovc_dispatch_read_result_clear(read_result, true);
        ovc_dispatch_operation_fail(
            operation,
            NULL,
            false,
            "read result is not available as a byte stream");
        return;
    }
    case OVC_DISPATCH_LOCAL_DELEGATE: {
        OvStoragePlugin_LocalDelegate *plugin_delegate;
        OvStorage_LocalDelegate *delegate;

        plugin_delegate = (OvStoragePlugin_LocalDelegate *)result;
        delegate = ovc_dispatch_local_delegate_from_plugin(plugin_delegate);
        ovc_dispatch_local_delegate_clear(plugin_delegate);
        if (delegate == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert local delegate");
            return;
        }
        operation->callback.local_delegate(OvStorage_Status_Ok,
                                           delegate,
                                           NULL,
                                           operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_STATUS:
        if (result != NULL) {
            ovc_abi_free(result);
        }
        operation->callback.status(OvStorage_Status_Ok,
                                   NULL,
                                   operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    case OVC_DISPATCH_LIST: {
        OvStoragePlugin_ListPage *page;
        OvStorage_List *list;

        page = (OvStoragePlugin_ListPage *)result;
        list = ovc_dispatch_list_from_plugin(page);
        ovc_dispatch_list_page_clear(page);
        if (list == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert list result");
            return;
        }
        operation->callback.list(OvStorage_Status_Ok,
                                 list,
                                 NULL,
                                 operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_VERSION_LIST: {
        OvStoragePlugin_VersionPage *page;
        OvStorage_VersionList *list;

        page = (OvStoragePlugin_VersionPage *)result;
        list = ovc_dispatch_version_list_from_plugin(page);
        ovc_dispatch_version_page_clear(page);
        if (list == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert version list");
            return;
        }
        operation->callback.version_list(OvStorage_Status_Ok,
                                         list,
                                         NULL,
                                         operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_ACCESS: {
        OvStoragePlugin_AccessDecision *plugin_decision;
        OvStorage_AccessDecision decision;

        plugin_decision = (OvStoragePlugin_AccessDecision *)result;
        if (!ovc_dispatch_access_from_plugin(&decision, plugin_decision)) {
            ovc_dispatch_access_clear(plugin_decision);
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert access decision");
            return;
        }
        ovc_dispatch_access_clear(plugin_decision);
        operation->callback.access(OvStorage_Status_Ok,
                                   decision,
                                   NULL,
                                   operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_CONNECTION: {
        OvStoragePlugin_Connection *plugin_connection;
        OvStorage_Connection *connection;

        plugin_connection = (OvStoragePlugin_Connection *)result;
        connection = ovc_dispatch_connection_from_plugin(plugin_connection);
        ovc_dispatch_connection_clear(plugin_connection, true);
        if (connection == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert connection");
            return;
        }
        operation->callback.connection(OvStorage_Status_Ok,
                                       connection,
                                       NULL,
                                       operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_AUTH_STREAM: {
        OvStoragePlugin_AuthEventStream *stream;
        ovc_stream_pump *pump;

        stream = (OvStoragePlugin_AuthEventStream *)result;
        pump = NULL;
        if (stream != NULL && stream->next_fn != NULL &&
            stream->drop_fn != NULL &&
            ovc_auth_stream_pump_start(
                &pump,
                stream,
                stream,
                ovc_dispatch_auth_stream_reclaim,
                operation->stream_scope,
                ovc_dispatch_auth_pump_item,
                ovc_dispatch_auth_terminal,
                operation) == 0) {
            operation->stream_scope = NULL;
            operation->pump = pump;
            if (!ovc_dispatch_register_pump(operation->handle, pump)) {
                ovc_stream_pump_destroy(pump);
                return;
            }
            return;
        }
        ovc_dispatch_auth_stream_reclaim(stream);
        ovc_dispatch_operation_fail(operation,
                                    NULL,
                                    false,
                                    "could not start authentication stream");
        return;
    }
    case OVC_DISPATCH_WATCH_STREAM: {
        OvStoragePlugin_BackendChangeStream *stream;
        ovc_stream_pump *pump;

        stream = (OvStoragePlugin_BackendChangeStream *)result;
        pump = NULL;
        if (stream != NULL && stream->next_fn != NULL &&
            stream->drop_fn != NULL &&
            ovc_backend_change_stream_pump_start(
                &pump,
                stream,
                stream,
                ovc_dispatch_watch_stream_reclaim,
                operation->stream_scope,
                ovc_dispatch_watch_pump_item,
                ovc_dispatch_watch_terminal,
                operation) == 0) {
            operation->stream_scope = NULL;
            operation->pump = pump;
            if (!ovc_dispatch_register_pump(operation->handle, pump)) {
                ovc_stream_pump_destroy(pump);
                return;
            }
            return;
        }
        ovc_dispatch_watch_stream_reclaim(stream);
        ovc_dispatch_operation_fail(operation,
                                    NULL,
                                    false,
                                    "could not start directory watch stream");
        return;
    }
    case OVC_DISPATCH_ROOT_LIST: {
        OvStoragePlugin_ListAddressRootsResult *envelope;
        OvStorage_RootInfoList *list;
        bool update_shape_valid;
        bool update_discarded;

        envelope = (OvStoragePlugin_ListAddressRootsResult *)result;
        /* The snapshot's `updates` flag must agree with the presence of the
         * change-stream pointer; drive the (always-NULL here) stream's
         * destructor before converting the snapshot. */
        update_shape_valid =
            envelope->snapshot.updates == (envelope->updates != NULL);
        update_discarded =
            ovc_dispatch_root_updates_discard(envelope->updates);
        list = update_shape_valid && update_discarded
                   ? ovc_dispatch_root_list_from_plugin(&envelope->snapshot)
                   : NULL;
        ovc_dispatch_root_snapshot_clear(&envelope->snapshot);
        ovc_abi_free(envelope);
        if (list == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert address roots");
            return;
        }
        operation->callback.root_list(OvStorage_Status_Ok,
                                      list,
                                      NULL,
                                      operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    case OVC_DISPATCH_CONNECTION_LIST: {
        OvStoragePlugin_ListConnectionsResult *envelope;
        OvStorage_ConnectionList *list;
        bool update_shape_valid;

        envelope = (OvStoragePlugin_ListConnectionsResult *)result;
        update_shape_valid =
            envelope->snapshot.updates == (envelope->updates != NULL);
        list = update_shape_valid
                   ? ovc_dispatch_connection_list_from_plugin(
                         &envelope->snapshot)
                   : NULL;
        ovc_dispatch_connection_snapshot_clear(&envelope->snapshot);
        ovc_dispatch_connection_updates_clear(envelope->updates);
        ovc_abi_free(envelope);
        if (list == NULL) {
            ovc_dispatch_operation_fail(operation,
                                        NULL,
                                        false,
                                        "could not convert connection list");
            return;
        }
        operation->callback.connection_list(OvStorage_Status_Ok,
                                            list,
                                            NULL,
                                            operation->user_data);
        ovc_dispatch_operation_leave(operation->handle);
        break;
    }
    default:
        ovc_dispatch_result_discard(operation->kind, result);
        ovc_dispatch_operation_fail(operation,
                                    NULL,
                                    false,
                                    "unknown dispatch operation");
        return;
    }
    ovc_dispatch_operation_free(operation);
}

static void ovc_dispatch_cancel_drop(OvStoragePlugin_CancelTokenFFI *cancel)
{
    if (cancel != NULL && cancel->state != NULL && cancel->drop != NULL) {
        cancel->drop(cancel->state);
    }
    if (cancel != NULL) {
        memset(cancel, 0, sizeof(*cancel));
    }
}

static void ovc_dispatch_transfer_options_clear(
    OvStoragePlugin_Optional_Str *if_source,
    OvStoragePlugin_IfDestExistsV1 *if_dest,
    OvStoragePlugin_Optional_Str *message)
{
    if (if_source->present) {
        ovc_dispatch_abi_str_clear(&if_source->value);
    }
    if (if_dest->tag == OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        ovc_dispatch_abi_str_clear(&if_dest->match_etag.etag);
    }
    if (message->present) {
        ovc_dispatch_abi_str_clear(&message->value);
    }
}

static void ovc_dispatch_io_request_clear(ovc_dispatch_io_task *task)
{
    OvStoragePlugin_ReadRequest *read;
    OvStoragePlugin_WriteRequest *write;

    if (task == NULL) {
        return;
    }
    switch (task->kind) {
    case OVC_DISPATCH_IO_TASK_STAT:
        ovc_dispatch_abi_str_clear(&task->request.stat.address);
        break;
    case OVC_DISPATCH_IO_TASK_READ:
    case OVC_DISPATCH_IO_TASK_MATERIALIZE:
    case OVC_DISPATCH_IO_TASK_GET_LATEST_VERSION:
        read = &task->request.read;
        ovc_dispatch_abi_str_clear(&read->address);
        if (read->options.if_match.present) {
            ovc_dispatch_abi_str_clear(&read->options.if_match.value);
        }
        break;
    case OVC_DISPATCH_IO_TASK_PROBE:
        ovc_dispatch_abi_str_clear(
            &task->request.layer_connection.target);
        ovc_dispatch_connection_request_clear(
            &task->request.layer_connection.connection);
        break;
    case OVC_DISPATCH_IO_TASK_UPDATE_CONNECTION_ATTRIBUTES:
        ovc_dispatch_update_attributes_request_clear(
            &task->request.update_attributes);
        break;
    case OVC_DISPATCH_IO_TASK_WATCH_DIRECTORY:
        ovc_dispatch_abi_str_clear(
            &task->request.watch_directory.prefix);
        if (task->request.watch_directory.options.since.present) {
            ovc_dispatch_abi_bytes_clear(
                &task->request.watch_directory.options.since.value.bytes,
                false);
        }
        break;
    case OVC_DISPATCH_IO_TASK_WRITE:
    case OVC_DISPATCH_IO_TASK_WRITE_STREAM:
    case OVC_DISPATCH_IO_TASK_WRITE_REDIRECT:
        write = &task->request.write;
        ovc_dispatch_abi_str_clear(&write->address);
        switch (write->body.tag) {
        case OvStoragePlugin_BodyTag_Bytes:
            ovc_dispatch_abi_bytes_clear(&write->body.bytes, false);
            break;
        case OvStoragePlugin_BodyTag_LocalFile:
            ovc_dispatch_abi_str_clear(&write->body.local_file);
            break;
        case OvStoragePlugin_BodyTag_Stream:
            if (write->body.stream.drop_fn != NULL) {
                write->body.stream.drop_fn(write->body.stream.state);
            }
            break;
        default:
            break;
        }
        if (write->options.if_dest.tag ==
            OvStoragePlugin_IfDestExistsTag_MatchEtag) {
            ovc_dispatch_abi_str_clear(
                &write->options.if_dest.match_etag.etag);
        }
        if (write->options.user_metadata.present) {
            ovc_dispatch_abi_key_values_clear(
                &write->options.user_metadata.value);
        }
        if (write->options.message.present) {
            ovc_dispatch_abi_str_clear(&write->options.message.value);
        }
        break;
    case OVC_DISPATCH_IO_TASK_CONTINUE_WRITE:
        ovc_dispatch_abi_str_clear(
            &task->request.continue_write.address);
        ovc_dispatch_write_redirect_batch_clear(
            &task->request.continue_write.redirects);
        ovc_dispatch_redirect_result_batch_clear(
            &task->request.continue_write.results);
        break;
    case OVC_DISPATCH_IO_TASK_LIST:
        ovc_dispatch_abi_str_clear(&task->request.list.prefix);
        ovc_dispatch_list_options_clear(&task->request.list.options);
        break;
    case OVC_DISPATCH_IO_TASK_LIST_VERSIONS:
        ovc_dispatch_abi_str_clear(
            &task->request.list_versions.address);
        ovc_dispatch_list_versions_options_clear(
            &task->request.list_versions.options);
        break;
    case OVC_DISPATCH_IO_TASK_DELETE:
        ovc_dispatch_abi_str_clear(&task->request.delete_.address);
        if (task->request.delete_.options.if_match.present) {
            ovc_dispatch_abi_str_clear(
                &task->request.delete_.options.if_match.value);
        }
        break;
    case OVC_DISPATCH_IO_TASK_COPY:
        ovc_dispatch_abi_str_clear(&task->request.copy.source);
        ovc_dispatch_abi_str_clear(&task->request.copy.destination);
        ovc_dispatch_transfer_options_clear(
            &task->request.copy.options.if_source,
            &task->request.copy.options.if_dest,
            &task->request.copy.options.message);
        break;
    case OVC_DISPATCH_IO_TASK_RENAME:
        ovc_dispatch_abi_str_clear(&task->request.rename.source);
        ovc_dispatch_abi_str_clear(&task->request.rename.destination);
        ovc_dispatch_transfer_options_clear(
            &task->request.rename.options.if_source,
            &task->request.rename.options.if_dest,
            &task->request.rename.options.message);
        break;
    case OVC_DISPATCH_IO_TASK_CREATE_DIRECTORY:
        ovc_dispatch_abi_str_clear(
            &task->request.create_directory.address);
        break;
    case OVC_DISPATCH_IO_TASK_DELETE_DIRECTORY:
        ovc_dispatch_abi_str_clear(
            &task->request.delete_directory.address);
        break;
    case OVC_DISPATCH_IO_TASK_UPDATE_METADATA:
        ovc_dispatch_update_metadata_request_clear(
            &task->request.update_metadata);
        break;
    case OVC_DISPATCH_IO_TASK_CHECK_ACCESS:
        ovc_dispatch_abi_str_clear(&task->request.check_access.address);
        break;
    case OVC_DISPATCH_IO_TASK_ERROR:
    case OVC_DISPATCH_IO_TASK_LIST_ADDRESS_ROOTS:
    case OVC_DISPATCH_IO_TASK_LIST_CONNECTIONS:
    default:
        /* The two list requests carry only struct_size + a borrowed
         * extensions pointer, so there is nothing owned to release. */
        break;
    }
    memset(&task->request, 0, sizeof(task->request));
}

static ovc_dispatch_io_task *ovc_dispatch_io_task_create(
    ovc_dispatch_operation *operation,
    ovc_dispatch_io_task_kind kind)
{
    ovc_dispatch_io_task *task;

    task = (ovc_dispatch_io_task *)calloc(1, sizeof(*task));
    if (task == NULL) {
        return NULL;
    }
    if (!ovc_dispatch_invocation_retain(operation->handle)) {
        free(task);
        return NULL;
    }
    task->handle = operation->handle;
    task->operation = operation;
    task->kind = kind;
    return task;
}

static bool ovc_dispatch_io_task_is_canceled(
    const ovc_dispatch_io_task *task)
{
    return task->has_cancel && task->cancel.state != NULL &&
           task->cancel.is_canceled != NULL &&
           task->cancel.is_canceled(task->cancel.state);
}

static void ovc_dispatch_io_task_abort(ovc_dispatch_io_task *task,
                                       OvStorage_Status status,
                                       const char *message)
{
    ovc_dispatch_operation *operation;
    OvStorage_LayerHandle *handle;

    operation = task->operation;
    handle = task->handle;
    ovc_dispatch_io_request_clear(task);
    if (task->has_cancel) {
        ovc_dispatch_cancel_drop(&task->cancel);
    }
    free(task);
    /* Release the vtable-call lifetime before firing the public callback. */
    ovc_dispatch_operation_leave(handle);
    ovc_dispatch_operation_fail_status(operation, status, message);
}

static void ovc_dispatch_io_task_run(void *argument)
{
    ovc_dispatch_io_task *task;
    OvStoragePlugin_LayerHandle root;
    OvStorage_LayerHandle *handle;

    task = (ovc_dispatch_io_task *)argument;
    if (task->kind == OVC_DISPATCH_IO_TASK_ERROR) {
        ovc_dispatch_io_task_abort(task,
                                   task->error_status,
                                   task->error_message);
        return;
    }
    if (ovc_dispatch_io_task_is_canceled(task)) {
        ovc_dispatch_io_task_abort(task,
                                   OvStorage_Status_Cancelled,
                                   "operation was cancelled before dispatch");
        return;
    }

    root = task->handle->root;
    switch (task->kind) {
    case OVC_DISPATCH_IO_TASK_STAT:
        root.vtable->stat(root.state,
                          &task->request.stat,
                          &task->cancel,
                          ovc_dispatch_complete,
                          task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_READ:
        root.vtable->read(root.state,
                          &task->request.read,
                          &task->cancel,
                          ovc_dispatch_complete,
                          task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_MATERIALIZE:
        root.vtable->materialize(root.state,
                                 &task->request.read,
                                 &task->cancel,
                                 ovc_dispatch_complete,
                                 task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_GET_LATEST_VERSION:
        root.vtable->get_latest_version(root.state,
                                        &task->request.read,
                                        &task->cancel,
                                        ovc_dispatch_complete,
                                        task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_WRITE:
        root.vtable->write(root.state,
                           &task->request.write,
                           &task->cancel,
                           ovc_dispatch_complete,
                           task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_WRITE_STREAM:
        root.vtable->write_stream(root.state,
                                  &task->request.write,
                                  &task->cancel,
                                  ovc_dispatch_complete,
                                  task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_WRITE_REDIRECT:
        root.vtable->write_redirect(root.state,
                                    &task->request.write,
                                    &task->cancel,
                                    ovc_dispatch_complete,
                                    task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_CONTINUE_WRITE:
        root.vtable->continue_write(
            root.state,
            &task->request.continue_write,
            &task->cancel,
            ovc_dispatch_complete,
            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_LIST:
        root.vtable->list(root.state,
                          &task->request.list,
                          &task->cancel,
                          ovc_dispatch_complete,
                          task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_LIST_VERSIONS:
        root.vtable->list_versions(root.state,
                                   &task->request.list_versions,
                                   &task->cancel,
                                   ovc_dispatch_complete,
                                   task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_DELETE:
        root.vtable->delete_(root.state,
                             &task->request.delete_,
                             &task->cancel,
                             ovc_dispatch_complete,
                             task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_COPY:
        root.vtable->copy(root.state,
                          &task->request.copy,
                          &task->cancel,
                          ovc_dispatch_complete,
                          task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_RENAME:
        root.vtable->rename(root.state,
                            &task->request.rename,
                            &task->cancel,
                            ovc_dispatch_complete,
                            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_CREATE_DIRECTORY:
        root.vtable->create_directory(
            root.state,
            &task->request.create_directory,
            &task->cancel,
            ovc_dispatch_complete,
            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_DELETE_DIRECTORY:
        root.vtable->delete_directory(
            root.state,
            &task->request.delete_directory,
            &task->cancel,
            ovc_dispatch_complete,
            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_UPDATE_METADATA:
        root.vtable->update_metadata(
            root.state,
            &task->request.update_metadata,
            &task->cancel,
            ovc_dispatch_complete,
            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_CHECK_ACCESS:
        root.vtable->check_access(root.state,
                                  &task->request.check_access,
                                  &task->cancel,
                                  ovc_dispatch_complete,
                                  task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_LIST_ADDRESS_ROOTS:
        root.vtable->list_address_roots(root.state,
                                        &task->request.list_address_roots,
                                        &task->cancel,
                                        ovc_dispatch_complete,
                                        task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_LIST_CONNECTIONS:
        root.vtable->list_connections(root.state,
                                      &task->request.list_connections,
                                      &task->cancel,
                                      ovc_dispatch_complete,
                                      task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_PROBE:
        root.vtable->probe(root.state,
                           &task->request.layer_connection,
                           &task->cancel,
                           ovc_dispatch_complete,
                           task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_UPDATE_CONNECTION_ATTRIBUTES:
        root.vtable->update_connection_attributes(
            root.state,
            &task->request.update_attributes,
            &task->cancel,
            ovc_dispatch_complete,
            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_WATCH_DIRECTORY:
        root.vtable->watch_directory(
            root.state,
            &task->request.watch_directory,
            &task->cancel,
            ovc_dispatch_complete,
            task->operation);
        break;
    case OVC_DISPATCH_IO_TASK_ERROR:
    default:
        abort();
    }

    /* The v2 handshake moves nested request allocations into the Layer. */
    memset(&task->request, 0, sizeof(task->request));
    ovc_dispatch_cancel_drop(&task->cancel);
    task->has_cancel = false;
    handle = task->handle;
    free(task);
    ovc_dispatch_operation_leave(handle);
}

static void ovc_dispatch_io_task_submit(ovc_dispatch_io_task *task)
{
    if (ovc_runtime_submit(ovc_dispatch_io_task_run, task) != 0) {
        ovc_dispatch_io_task_abort(task,
                                   OvStorage_Status_Internal,
                                   "operation could not be queued");
    }
}

static bool ovc_dispatch_address_valid(const char *address)
{
    return address != NULL && ovc_dispatch_utf8_valid(address);
}

/* ------------------------------------------------------------------------- */
/* Object operations. */

void ovstorage_stat(const OvStorage_LayerHandle *handle,
                    const char *address,
                    const OvStorage_StatOptions *options,
                    const OvStorage_CancelToken *cancel,
                    OvStorage_InfoCallback on_complete,
                    void *user_data)
{
    OvStoragePlugin_StatRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_OBJECT,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "stat needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = ovc_dispatch_address_valid(address) &&
            ovc_dispatch_stat_options(&request.options, options);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_OBJECT,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_OBJECT,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_STAT);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a stat dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "stat arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.stat = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

static void ovc_dispatch_read_start(const OvStorage_LayerHandle *handle,
                                    const char *address,
                                    const OvStorage_ReadOptions *options,
                                    const OvStorage_CancelToken *cancel,
                                    ovc_dispatch_operation_kind kind,
                                    ovc_dispatch_callback callback,
                                    void *user_data)
{
    OvStoragePlugin_ReadRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    ovc_dispatch_io_task_kind task_kind;
    bool valid;

    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(kind,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "read needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = ovc_dispatch_address_valid(address) &&
            ovc_dispatch_read_options(&request.options, options);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        kind,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(kind,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task_kind = kind == OVC_DISPATCH_LOCAL_DELEGATE
                    ? OVC_DISPATCH_IO_TASK_MATERIALIZE
                    : OVC_DISPATCH_IO_TASK_READ;
    task = ovc_dispatch_io_task_create(operation, task_kind);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a read dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "read arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    if (kind == OVC_DISPATCH_READ_BYTES ||
        kind == OVC_DISPATCH_READ_STREAM) {
        operation->stream_scope = ovc_stream_cancel_scope_create(cancel);
        if (operation->stream_scope == NULL) {
            ovc_dispatch_abi_str_clear(&request.address);
            task->kind = OVC_DISPATCH_IO_TASK_ERROR;
            task->error_status = OvStorage_Status_Internal;
            task->error_message =
                "could not create stream cancellation state";
            ovc_dispatch_io_task_submit(task);
            return;
        }
        ffi_cancel = ovc_stream_cancel_scope_mint_producer(
            operation->stream_scope);
    } else {
        ffi_cancel = ovc_cancel_token_mint(cancel);
    }
    task->request.read = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_read_bytes(const OvStorage_LayerHandle *handle,
                          const char *address,
                          const OvStorage_ReadOptions *options,
                          const OvStorage_CancelToken *cancel,
                          OvStorage_ReadBytesCallback on_complete,
                          void *user_data)
{
    ovc_dispatch_callback callback;

    if (on_complete == NULL) {
        return;
    }
    callback.read_bytes = on_complete;
    ovc_dispatch_read_start(handle,
                            address,
                            options,
                            cancel,
                            OVC_DISPATCH_READ_BYTES,
                            callback,
                            user_data);
}

void ovstorage_read_stream(const OvStorage_LayerHandle *handle,
                           const char *address,
                           const OvStorage_ReadOptions *options,
                           const OvStorage_CancelToken *cancel,
                           OvStorage_ReadStreamCallback on_complete,
                           void *user_data)
{
    ovc_dispatch_callback callback;

    if (on_complete == NULL) {
        return;
    }
    callback.read_stream = on_complete;
    ovc_dispatch_read_start(handle,
                            address,
                            options,
                            cancel,
                            OVC_DISPATCH_READ_STREAM,
                            callback,
                            user_data);
}

void ovstorage_read_local_file(const OvStorage_LayerHandle *handle,
                               const char *address,
                               const OvStorage_ReadOptions *options,
                               const OvStorage_CancelToken *cancel,
                               OvStorage_ReadLocalFileCallback on_complete,
                               void *user_data)
{
    ovc_dispatch_callback callback;

    if (on_complete == NULL) {
        return;
    }
    callback.local_delegate = on_complete;
    ovc_dispatch_read_start(handle,
                            address,
                            options,
                            cancel,
                            OVC_DISPATCH_LOCAL_DELEGATE,
                            callback,
                            user_data);
}

void ovstorage_write(const OvStorage_LayerHandle *handle,
                     const char *address,
                     const uint8_t *data,
                     size_t len,
                     const OvStorage_WriteOptions *options,
                     const OvStorage_CancelToken *cancel,
                     OvStorage_InfoCallback on_complete,
                     void *user_data)
{
    OvStoragePlugin_WriteRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    const char *reason;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_WRITE,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "write needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.body.tag = OvStoragePlugin_BodyTag_Bytes;
    reason = "write arguments are invalid";
    valid = ovc_dispatch_address_valid(address) &&
            !(data == NULL && len != 0) &&
            ovc_dispatch_write_options(&request.options, options, &reason);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address) &&
                ovc_dispatch_abi_bytes_copy(&request.body.bytes, data, len);
    }
    request.options.size_hint.present = true;
    request.options.size_hint.value = (uint64_t)len;
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_WRITE,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_abi_bytes_clear(&request.body.bytes, false);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_WRITE,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_WRITE);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_abi_bytes_clear(&request.body.bytes, false);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a write dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_abi_bytes_clear(&request.body.bytes, false);
        ovc_dispatch_write_options_clear(&request.options);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = reason;
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.write = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_write_stream(const OvStorage_LayerHandle *handle,
                            const char *address,
                            OvStorage_WriteStream *stream_slot,
                            const OvStorage_WriteOptions *options,
                            const OvStorage_CancelToken *cancel,
                            OvStorage_InfoCallback on_complete,
                            void *user_data)
{
    OvStoragePlugin_WriteRequest request;
    ovc_dispatch_write_stream *stream;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    const char *reason;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    reason = "write_stream arguments are invalid";
    valid = handle != NULL &&
            ovc_dispatch_address_valid(address) &&
            stream_slot != NULL &&
            stream_slot->next != NULL &&
            stream_slot->drop != NULL &&
            ovc_dispatch_write_options(&request.options, options, &reason);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_WRITE,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       reason);
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_WRITE,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_WRITE,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_WRITE_STREAM);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a write_stream dispatch task");
        return;
    }
    stream = (ovc_dispatch_write_stream *)calloc(1, sizeof(*stream));
    if (stream == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_io_task_abort(
            task,
            OvStorage_Status_Internal,
            "could not allocate a write_stream adapter");
        return;
    }

    stream->source = *stream_slot;
    memset(stream_slot, 0, sizeof(*stream_slot));
    request.body.tag = OvStoragePlugin_BodyTag_Stream;
    request.body.stream.state = stream;
    request.body.stream.next_fn = ovc_dispatch_write_stream_next;
    request.body.stream.drop_fn = ovc_dispatch_write_stream_drop;
    task->request.write = request;
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_write_redirect(const OvStorage_LayerHandle *handle,
                              const char *address,
                              const OvStorage_WriteOptions *options,
                              const OvStorage_CancelToken *cancel,
                              OvStorage_WriteRedirectCallback on_complete,
                              void *user_data)
{
    OvStoragePlugin_WriteRequest request;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    const char *reason;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.write_redirect = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_WRITE_REDIRECT_BATCH,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "write_redirect needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.body.tag = OvStoragePlugin_BodyTag_Bytes;
    reason = "write_redirect arguments are invalid";
    valid = ovc_dispatch_address_valid(address) &&
            ovc_dispatch_write_options(&request.options, options, &reason);
    if (valid) {
        valid =
            ovc_dispatch_abi_cstring_copy(&request.address, address) &&
            ovc_dispatch_abi_bytes_copy(&request.body.bytes, NULL, 0);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_WRITE_REDIRECT_BATCH,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_abi_bytes_clear(&request.body.bytes, false);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_WRITE_REDIRECT_BATCH,
            callback,
            user_data,
            OvStorage_Status_Internal,
            "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_WRITE_REDIRECT);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_abi_bytes_clear(&request.body.bytes, false);
        ovc_dispatch_write_options_clear(&request.options);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a write_redirect dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_abi_bytes_clear(&request.body.bytes, false);
        ovc_dispatch_write_options_clear(&request.options);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = reason;
        ovc_dispatch_io_task_submit(task);
        return;
    }
    task->request.write = request;
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_continue_write(const OvStorage_LayerHandle *handle,
                              const char *address,
                              const OvStorage_WriteRedirectBatch *redirects,
                              const OvStorage_RedirectResultBatch *results,
                              const OvStorage_CancelToken *cancel,
                              OvStorage_WriteStepCallback on_complete,
                              void *user_data)
{
    OvStoragePlugin_ContinueWriteRequest request;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.write_step = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_WRITE_STEP,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "continue_write needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = ovc_dispatch_address_valid(address) &&
            redirects != NULL &&
            results != NULL;
    if (valid) {
        valid =
            ovc_dispatch_abi_cstring_copy(&request.address, address) &&
            ovc_dispatch_redirect_batch_to_plugin(
                &request.redirects, redirects) &&
            ovc_dispatch_redirect_results_to_plugin(
                &request.results, results, redirects);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_WRITE_STEP,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_redirect_batch_clear(&request.redirects);
        ovc_dispatch_redirect_result_batch_clear(&request.results);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_WRITE_STEP,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_CONTINUE_WRITE);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_redirect_batch_clear(&request.redirects);
        ovc_dispatch_redirect_result_batch_clear(&request.results);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a continue_write dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_write_redirect_batch_clear(&request.redirects);
        ovc_dispatch_redirect_result_batch_clear(&request.results);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "continue_write arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    task->request.continue_write = request;
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_delete(const OvStorage_LayerHandle *handle,
                      const char *address,
                      const OvStorage_CancelToken *cancel,
                      OvStorage_StatusCallback on_complete,
                      void *user_data)
{
    OvStoragePlugin_DeleteRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.status = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "delete needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.options.struct_size = sizeof(request.options);
    valid = ovc_dispatch_address_valid(address);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_STATUS,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_DELETE);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a delete dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "delete arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.delete_ = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_list(const OvStorage_LayerHandle *handle,
                    const char *prefix,
                    const OvStorage_ListOptions *options,
                    const OvStorage_CancelToken *cancel,
                    OvStorage_ListCallback on_complete,
                    void *user_data)
{
    OvStoragePlugin_ListRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.list = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "list needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = ovc_dispatch_address_valid(prefix) &&
            ovc_dispatch_list_options(&request.options, options);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.prefix, prefix);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_LIST,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        ovc_dispatch_list_options_clear(&request.options);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_LIST);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        ovc_dispatch_list_options_clear(&request.options);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a list dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        ovc_dispatch_list_options_clear(&request.options);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "list arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.list = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_list_versions(const OvStorage_LayerHandle *handle,
                             const char *address,
                             const OvStorage_ListVersionsOptions *options,
                             const OvStorage_CancelToken *cancel,
                             OvStorage_ListVersionsCallback on_complete,
                             void *user_data)
{
    OvStoragePlugin_ListVersionsRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.version_list = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_VERSION_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "list_versions needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = ovc_dispatch_address_valid(address) &&
            ovc_dispatch_list_versions_options(&request.options, options);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_VERSION_LIST,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_list_versions_options_clear(&request.options);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_VERSION_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_LIST_VERSIONS);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_list_versions_options_clear(&request.options);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a list_versions dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_list_versions_options_clear(&request.options);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "list_versions arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.list_versions = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_get_latest_version(
    const OvStorage_LayerHandle *handle,
    const char *address,
    const OvStorage_ReadOptions *options,
    const OvStorage_CancelToken *cancel,
    OvStorage_InfoCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_ReadRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_OBJECT,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "get_latest_version needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = ovc_dispatch_address_valid(address) &&
            ovc_dispatch_read_options(&request.options, options);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_OBJECT,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_OBJECT,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_GET_LATEST_VERSION);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a get_latest_version dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "get_latest_version arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.read = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_watch_directory(
    const OvStorage_LayerHandle *handle,
    const char *prefix,
    const OvStorage_WatchDirectoryOptions *options,
    const OvStorage_CancelToken *cancel,
    OvStorage_WatchDirectoryCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_WatchDirectoryRequest request;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.watch = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_WATCH_STREAM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "watch_directory needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.options.struct_size = sizeof(request.options);
    request.options.include_metadata_changes = true;
    request.options.poll_interval_ms = 1000;
    valid = ovc_dispatch_address_valid(prefix);
    if (options != NULL) {
        request.options.recursive = options->recursive;
        request.options.include_metadata_changes =
            options->include_metadata_changes;
        if (options->poll_interval_ms != 0) {
            request.options.poll_interval_ms =
                options->poll_interval_ms;
        }
        /* Presence is the caller's flag or a non-empty cursor, never the
         * length alone: a backend may mint a zero-length cursor, and
         * keying on length would silently turn resuming from one into
         * replaying the whole change history. */
        if (options->has_since || options->since_len != 0) {
            request.options.since.present = true;
            valid = valid &&
                    (options->since != NULL || options->since_len == 0) &&
                    ovc_dispatch_abi_bytes_copy(
                        &request.options.since.value.bytes,
                        options->since,
                        options->since_len);
        }
    }
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.prefix, prefix);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_WATCH_STREAM,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        if (request.options.since.present) {
            ovc_dispatch_abi_bytes_clear(
                &request.options.since.value.bytes, false);
        }
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_WATCH_STREAM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_WATCH_DIRECTORY);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        if (request.options.since.present) {
            ovc_dispatch_abi_bytes_clear(
                &request.options.since.value.bytes, false);
        }
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a watch_directory dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        if (request.options.since.present) {
            ovc_dispatch_abi_bytes_clear(
                &request.options.since.value.bytes, false);
        }
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "watch_directory arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    operation->stream_scope = ovc_stream_cancel_scope_create(cancel);
    if (operation->stream_scope == NULL) {
        ovc_dispatch_abi_str_clear(&request.prefix);
        if (request.options.since.present) {
            ovc_dispatch_abi_bytes_clear(
                &request.options.since.value.bytes, false);
        }
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_Internal;
        task->error_message =
            "could not create directory watch cancellation state";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    task->request.watch_directory = request;
    task->cancel = ovc_stream_cancel_scope_mint_producer(
        operation->stream_scope);
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_copy(const OvStorage_LayerHandle *handle,
                    const char *src,
                    const char *dest,
                    const OvStorage_CancelToken *cancel,
                    OvStorage_InfoCallback on_complete,
                    void *user_data)
{
    OvStoragePlugin_CopyRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_WRITE_STEP,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "copy needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;
    valid = ovc_dispatch_address_valid(src) &&
            ovc_dispatch_address_valid(dest);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.source, src) &&
                ovc_dispatch_abi_cstring_copy(&request.destination, dest);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_WRITE_STEP,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.source);
        ovc_dispatch_abi_str_clear(&request.destination);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_WRITE_STEP,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_COPY);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.source);
        ovc_dispatch_abi_str_clear(&request.destination);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a copy dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.source);
        ovc_dispatch_abi_str_clear(&request.destination);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "copy arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.copy = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_rename(const OvStorage_LayerHandle *handle,
                      const char *src,
                      const char *dest,
                      const OvStorage_CancelToken *cancel,
                      OvStorage_StatusCallback on_complete,
                      void *user_data)
{
    OvStoragePlugin_RenameRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.status = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "rename needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;
    valid = ovc_dispatch_address_valid(src) &&
            ovc_dispatch_address_valid(dest);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.source, src) &&
                ovc_dispatch_abi_cstring_copy(&request.destination, dest);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_STATUS,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.source);
        ovc_dispatch_abi_str_clear(&request.destination);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_RENAME);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.source);
        ovc_dispatch_abi_str_clear(&request.destination);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a rename dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.source);
        ovc_dispatch_abi_str_clear(&request.destination);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "rename arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.rename = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_create_directory(
    const OvStorage_LayerHandle *handle,
    const char *address,
    const OvStorage_CancelToken *cancel,
    OvStorage_InfoCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_CreateDirectoryRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_BACKEND_ITEM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "create_directory needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.options.struct_size = sizeof(request.options);
    valid = ovc_dispatch_address_valid(address);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_BACKEND_ITEM,
        callback,
        user_data,
        valid ? address : NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_BACKEND_ITEM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_CREATE_DIRECTORY);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a create_directory dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "create_directory arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.create_directory = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_delete_directory(
    const OvStorage_LayerHandle *handle,
    const char *address,
    const OvStorage_CancelToken *cancel,
    OvStorage_StatusCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_DeleteDirectoryRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.status = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "delete_directory needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.options.struct_size = sizeof(request.options);
    valid = ovc_dispatch_address_valid(address);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_STATUS,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_DELETE_DIRECTORY);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a delete_directory dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "delete_directory arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.delete_directory = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

static void ovc_dispatch_update_metadata_request_clear(
    OvStoragePlugin_UpdateMetadataRequest *request)
{
    ovc_dispatch_abi_str_clear(&request->address);
    ovc_dispatch_abi_key_values_clear(&request->options.user_metadata_set);
    ovc_dispatch_list_str_clear(&request->options.user_metadata_remove);
    memset(request, 0, sizeof(*request));
}

static bool ovc_dispatch_metadata_patch_copy(
    OvStoragePlugin_KeyValueList *set_entries,
    OvStoragePlugin_List_Str *remove_keys,
    const OvStorage_UpdateMetadataOptions *options)
{
    size_t index;
    size_t set_len;
    size_t remove_len;
    size_t set_capacity;
    size_t remove_capacity;

    set_len = options == NULL ? 0 : options->set_len;
    remove_len = options == NULL ? 0 : options->remove_len;
    set_capacity = set_len == 0 ? 1 : set_len;
    remove_capacity = remove_len == 0 ? 1 : remove_len;
    if (set_capacity > SIZE_MAX / sizeof(*set_entries->ptr) ||
        remove_capacity > SIZE_MAX / sizeof(*remove_keys->ptr)) {
        return false;
    }
    set_entries->ptr = (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
        set_capacity * sizeof(*set_entries->ptr));
    remove_keys->ptr = (OvStoragePlugin_Str *)ovc_abi_alloc(
        remove_capacity * sizeof(*remove_keys->ptr));
    if (set_entries->ptr == NULL || remove_keys->ptr == NULL) {
        ovc_dispatch_abi_key_values_clear(set_entries);
        ovc_dispatch_list_str_clear(remove_keys);
        return false;
    }
    memset(set_entries->ptr,
           0,
           set_capacity * sizeof(*set_entries->ptr));
    memset(remove_keys->ptr,
           0,
           remove_capacity * sizeof(*remove_keys->ptr));
    for (index = 0; index < set_len; ++index) {
        set_entries->len = index + 1;
        if (!ovc_dispatch_abi_cstring_copy(
                &set_entries->ptr[index].key,
                options->set_entries[index].key) ||
            !ovc_dispatch_abi_cstring_copy(
                &set_entries->ptr[index].value,
                options->set_entries[index].value)) {
            ovc_dispatch_abi_key_values_clear(set_entries);
            ovc_dispatch_list_str_clear(remove_keys);
            return false;
        }
    }
    for (index = 0; index < remove_len; ++index) {
        remove_keys->len = index + 1;
        if (!ovc_dispatch_abi_cstring_copy(&remove_keys->ptr[index],
                                           options->remove_keys[index])) {
            ovc_dispatch_abi_key_values_clear(set_entries);
            ovc_dispatch_list_str_clear(remove_keys);
            return false;
        }
    }
    return true;
}

static bool ovc_dispatch_update_metadata_request_init(
    OvStoragePlugin_UpdateMetadataRequest *request,
    const char *address,
    const OvStorage_UpdateMetadataOptions *options)
{
    memset(request, 0, sizeof(*request));
    request->struct_size = sizeof(*request);
    request->options.struct_size = sizeof(request->options);
    if (options == NULL || !ovc_dispatch_abi_cstring_copy(&request->address,
                                                          address)) {
        return false;
    }
    if (!ovc_dispatch_metadata_patch_copy(
            &request->options.user_metadata_set,
            &request->options.user_metadata_remove,
            options)) {
        ovc_dispatch_update_metadata_request_clear(request);
        return false;
    }
    return true;
}

void ovstorage_update_metadata(
    const OvStorage_LayerHandle *handle,
    const char *address,
    const OvStorage_UpdateMetadataOptions *options,
    const OvStorage_CancelToken *cancel,
    OvStorage_InfoCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_UpdateMetadataRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.info = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_BACKEND_ITEM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "update_metadata needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    valid = ovc_dispatch_address_valid(address) &&
            ovc_dispatch_update_metadata_request_init(&request,
                                                      address,
                                                      options);
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_INFO_BACKEND_ITEM,
        callback,
        user_data,
        valid ? address : NULL);
    if (operation == NULL) {
        ovc_dispatch_update_metadata_request_clear(&request);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_INFO_BACKEND_ITEM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_UPDATE_METADATA);
    if (task == NULL) {
        ovc_dispatch_update_metadata_request_clear(&request);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate an update_metadata dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_update_metadata_request_clear(&request);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "update_metadata arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.update_metadata = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_check_access(const OvStorage_LayerHandle *handle,
                            const char *address,
                            OvStorage_AccessOps ops,
                            const OvStorage_CancelToken *cancel,
                            OvStorage_CheckAccessCallback on_complete,
                            void *user_data)
{
    OvStoragePlugin_CheckAccessRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.access = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_ACCESS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "check_access needs a live Stack");
        return;
    }
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.operations.read = ops.read;
    request.operations.write = ops.write;
    request.operations.delete_ = ops.delete_;
    request.operations.update_metadata = ops.update_metadata;
    valid = ovc_dispatch_address_valid(address);
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.address, address);
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_ACCESS,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_ACCESS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_CHECK_ACCESS);
    if (task == NULL) {
        ovc_dispatch_abi_str_clear(&request.address);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a check_access dispatch task");
        return;
    }
    if (!valid) {
        ovc_dispatch_abi_str_clear(&request.address);
        task->kind = OVC_DISPATCH_IO_TASK_ERROR;
        task->error_status = OvStorage_Status_InvalidArgument;
        task->error_message = "check_access arguments are invalid";
        ovc_dispatch_io_task_submit(task);
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    task->request.check_access = request;
    task->cancel = ffi_cancel;
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

/* ------------------------------------------------------------------------- */
/* Connection management and synchronous snapshots. */

static void ovc_dispatch_layer_connection_request_clear(
    OvStoragePlugin_LayerConnectionRequest *request)
{
    ovc_dispatch_abi_str_clear(&request->target);
    ovc_dispatch_connection_request_clear(&request->connection);
    memset(request, 0, sizeof(*request));
}

/* Reject a connection-result operation before it is submitted.
 *
 * The prologue below checks each argument separately rather than as one
 * disjunction so that this message can distinguish a null handle from a
 * malformed target from a request the caller has already handed to an earlier
 * call. Those are different mistakes with different fixes, and the C++ wrapper
 * surfaces this string verbatim, so it is the only diagnostic a caller in
 * either language gets. */
static void ovc_dispatch_reject_connection(ovc_dispatch_callback callback,
                                           void *user_data,
                                           OvStorage_Status status,
                                           const char *message)
{
    ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION,
                                   callback,
                                   user_data,
                                   status,
                                   message);
}

void ovstorage_probe(const OvStorage_LayerHandle *handle,
                     const char *target,
                     const OvStorage_ConnectionRequest *request_value,
                     const OvStorage_CancelToken *cancel,
                     OvStorage_ConnectionCallback on_complete,
                     void *user_data)
{
    OvStoragePlugin_LayerConnectionRequest request;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;

    if (on_complete == NULL) {
        return;
    }
    callback.connection = on_complete;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    if (handle == NULL) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "probe: handle is null");
        return;
    }
    if (!ovc_dispatch_address_valid(target)) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "probe: target is null or not a valid address");
        return;
    }
    if (request_value == NULL || request_value->consumed) {
        ovc_dispatch_reject_connection(
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            request_value == NULL
                ? "probe: connection request is null"
                : "probe: connection request was already consumed");
        return;
    }
    if (!ovc_dispatch_abi_cstring_copy(&request.target, target) ||
        !ovc_dispatch_connection_request_copy(&request.connection,
                                              request_value)) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "probe: out of memory copying its arguments");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_CONNECTION,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(operation,
                                       OVC_DISPATCH_IO_TASK_PROBE);
    if (task == NULL) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a probe dispatch task");
        return;
    }
    task->request.layer_connection = request;
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_add_connection(const OvStorage_LayerHandle *handle,
                              const char *target,
                              OvStorage_ConnectionRequest **request_slot,
                              const OvStorage_CancelToken *cancel,
                              OvStorage_ConnectionCallback on_complete,
                              void *user_data)
{
    OvStoragePlugin_LayerConnectionRequest request;
    OvStorage_ConnectionRequest *request_value;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;

    if (on_complete == NULL) {
        return;
    }
    callback.connection = on_complete;
    /* A caller who passes no slot at all is folded into the null-request case
     * below, which is what keeps the `*request_slot = NULL` commit further
     * down safe to write unconditionally: the only way past that check is a
     * non-NULL `request_slot`. Reordering the checks so the commit becomes
     * reachable with a NULL slot would dereference NULL. */
    request_value = (request_slot == NULL) ? NULL : *request_slot;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    if (handle == NULL) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "add_connection: handle is null");
        return;
    }
    if (!ovc_dispatch_address_valid(target)) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "add_connection: target is null or not "
                                       "a valid address");
        return;
    }
    if (request_value == NULL) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "add_connection: connection request is "
                                       "null");
        return;
    }
    if (request_value->consumed) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "add_connection: connection request was "
                                       "already consumed by an earlier call");
        return;
    }
    if (!ovc_dispatch_abi_cstring_copy(&request.target, target) ||
        !ovc_dispatch_connection_request_copy(&request.connection,
                                              request_value)) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "add_connection: out of memory copying "
                                       "its arguments");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_CONNECTION,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    if (!ovc_connection_request_mark_consumed(request_value)) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovc_dispatch_operation_fail(operation,
                                    NULL,
                                    false,
                                    "connection request was already consumed");
        return;
    }
    /*
     * This is the ownership commit point.  Clearing the caller's slot is the
     * signal that the transfer happened: every exit above leaves the slot
     * holding the request, and every exit below disposes of it here.  The
     * caller's cleanup is an unconditional destroy of whatever the slot
     * still holds, which is a no-op once it is NULL.
     */
    *request_slot = NULL;
    /* Hold a second in-flight reference across the vtable call: the Layer
     * may complete synchronously and keep using its state before the slot
     * returns (see ovc_dispatch_invocation_retain). */
    if (!ovc_dispatch_invocation_retain((OvStorage_LayerHandle *)handle)) {
        ovc_dispatch_layer_connection_request_clear(&request);
        ovstorage_connection_request_destroy(request_value);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not retain the Stack for add_connection");
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    handle->root.vtable->add_connection(handle->root.state,
                                         &request,
                                         &ffi_cancel,
                                         ovc_dispatch_complete,
                                         operation);
    ovc_dispatch_cancel_drop(&ffi_cancel);
    memset(&request, 0, sizeof(request));
    ovc_dispatch_operation_leave((OvStorage_LayerHandle *)handle);
    ovstorage_connection_request_destroy(request_value);
}

static void ovc_dispatch_connection_snapshot_clear(
    OvStoragePlugin_ConnectionSnapshot *snapshot)
{
    size_t index;

    if (snapshot == NULL) {
        return;
    }
    if (snapshot->connections.ptr != NULL) {
        for (index = 0; index < snapshot->connections.len; ++index) {
            ovc_dispatch_connection_clear(
                &snapshot->connections.ptr[index], false);
        }
    }
    ovc_abi_free(snapshot->connections.ptr);
    memset(snapshot, 0, sizeof(*snapshot));
}

static OvStorage_ConnectionList *ovc_dispatch_connection_list_from_plugin(
    const OvStoragePlugin_ConnectionSnapshot *snapshot)
{
    OvStorage_ConnectionList *list;
    OvStorage_Connection *converted;
    OvStorage_Connection *items = NULL;
    size_t index;

    if (snapshot == NULL ||
        (snapshot->connections.len != 0 &&
         snapshot->connections.ptr == NULL) ||
        snapshot->connections.len > SIZE_MAX / sizeof(*list->items)) {
        return NULL;
    }
    list = (OvStorage_ConnectionList *)calloc(1, sizeof(*list));
    if (list == NULL) {
        return NULL;
    }
    if (snapshot->connections.len != 0) {
        items = (OvStorage_Connection *)calloc(snapshot->connections.len,
                                               sizeof(*items));
        if (items == NULL) {
            ovstorage_connection_list_destroy(list);
            return NULL;
        }
        list->items = items;
    }
    list->len = snapshot->connections.len;
    for (index = 0; index < list->len; ++index) {
        converted = ovc_dispatch_connection_from_plugin(
            &snapshot->connections.ptr[index]);
        if (converted == NULL) {
            ovstorage_connection_list_destroy(list);
            return NULL;
        }
        items[index] = *converted;
        free(converted);
    }
    return list;
}

static void ovc_dispatch_connection_updates_clear(
    OvStoragePlugin_ConnectionChangeStream *updates)
{
    if (updates == NULL) {
        return;
    }
    if (updates->drop_fn != NULL) {
        updates->drop_fn(updates->state);
    }
    ovc_abi_free(updates);
}

void ovstorage_list_connections(
    const OvStorage_LayerHandle *handle,
    const OvStorage_CancelToken *cancel,
    OvStorage_ConnectionListCallback on_complete,
    void *user_data)
{
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;

    if (on_complete == NULL) {
        return;
    }
    callback.connection_list = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "list_connections needs a live Stack");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_CONNECTION_LIST,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_LIST_CONNECTIONS);
    if (task == NULL) {
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a list_connections dispatch task");
        return;
    }
    task->request.list_connections.struct_size =
        sizeof(task->request.list_connections);
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_remove_connection(const OvStorage_LayerHandle *handle,
                                 const char *target,
                                 const char *connection_id,
                                 const OvStorage_CancelToken *cancel,
                                 OvStorage_StatusCallback on_complete,
                                 void *user_data)
{
    OvStoragePlugin_RemoveConnectionRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;

    if (on_complete == NULL) {
        return;
    }
    callback.status = on_complete;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "remove_connection: handle is null");
        return;
    }
    if (!ovc_dispatch_address_valid(target)) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_STATUS,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "remove_connection: target is null or not a valid address");
        return;
    }
    if (!ovc_dispatch_address_valid(connection_id)) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_STATUS,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "remove_connection: connection id is null or not valid UTF-8");
        return;
    }
    if (!ovc_dispatch_abi_cstring_copy(&request.key.target, target) ||
        !ovc_dispatch_abi_cstring_copy(&request.key.id, connection_id)) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_STATUS,
            callback,
            user_data,
            OvStorage_Status_Internal,
            "remove_connection: out of memory copying its arguments");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_STATUS,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_STATUS,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    /* Hold a second in-flight reference across the vtable call; a
     * synchronous completion must not let a concurrent destroy drop the
     * Layer before the slot returns. */
    if (!ovc_dispatch_invocation_retain((OvStorage_LayerHandle *)handle)) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not retain the Stack for remove_connection");
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    handle->root.vtable->remove_connection(handle->root.state,
                                           &request,
                                           &ffi_cancel,
                                           ovc_dispatch_complete,
                                           operation);
    ovc_dispatch_cancel_drop(&ffi_cancel);
    memset(&request, 0, sizeof(request));
    ovc_dispatch_operation_leave((OvStorage_LayerHandle *)handle);
}

static void ovc_dispatch_update_credentials_request_clear(
    OvStoragePlugin_UpdateConnectionCredentialsRequest *request)
{
    ovc_dispatch_abi_str_clear(&request->key.target);
    ovc_dispatch_abi_str_clear(&request->key.id);
    ovc_dispatch_secret_bundle_clear(&request->credentials);
    memset(request, 0, sizeof(*request));
}

static void ovc_dispatch_update_attributes_request_clear(
    OvStoragePlugin_UpdateConnectionAttributesRequest *request)
{
    if (request == NULL) {
        return;
    }
    ovc_dispatch_abi_str_clear(&request->key.target);
    ovc_dispatch_abi_str_clear(&request->key.id);
    if (request->patch.display_name.present) {
        ovc_dispatch_abi_str_clear(&request->patch.display_name.value);
    }
    if (request->patch.access_mode.present) {
        ovc_dispatch_abi_str_clear(&request->patch.access_mode.value);
    }
    ovc_dispatch_abi_key_values_clear(&request->patch.set_user_metadata);
    ovc_dispatch_list_str_clear(&request->patch.remove_user_metadata);
    memset(request, 0, sizeof(*request));
}

void ovstorage_update_connection_credentials(
    const OvStorage_LayerHandle *handle,
    const char *target,
    const char *connection_id,
    OvStorage_SecretBundle **credentials_slot,
    const OvStorage_CancelToken *cancel,
    OvStorage_ConnectionCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_UpdateConnectionCredentialsRequest request;
    OvStorage_SecretBundle *credentials;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;

    if (on_complete == NULL) {
        return;
    }
    callback.connection = on_complete;
    /* As in `ovstorage_add_connection`: no slot is folded into the null-bundle
     * case, which is what makes the `*credentials_slot = NULL` commit below
     * safe to write unconditionally. */
    credentials = (credentials_slot == NULL) ? NULL : *credentials_slot;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    if (handle == NULL) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "update_connection_credentials: handle "
                                       "is null");
        return;
    }
    if (!ovc_dispatch_address_valid(target)) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "update_connection_credentials: target "
                                       "is null or not a valid address");
        return;
    }
    if (!ovc_dispatch_address_valid(connection_id)) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "update_connection_credentials: "
                                       "connection id is null or empty");
        return;
    }
    if (credentials == NULL) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "update_connection_credentials: "
                                       "credential bundle is null");
        return;
    }
    if (credentials->consumed) {
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "update_connection_credentials: "
                                       "credential bundle was already consumed "
                                       "by an earlier call");
        return;
    }
    if (!ovc_dispatch_abi_cstring_copy(&request.key.target, target) ||
        !ovc_dispatch_abi_cstring_copy(&request.key.id, connection_id) ||
        !ovc_dispatch_secret_bundle_copy(&request.credentials, credentials)) {
        ovc_dispatch_update_credentials_request_clear(&request);
        ovc_dispatch_reject_connection(callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "update_connection_credentials: out of "
                                       "memory copying its arguments");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_CONNECTION,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_update_credentials_request_clear(&request);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    if (!ovc_secret_bundle_mark_consumed(credentials)) {
        ovc_dispatch_update_credentials_request_clear(&request);
        ovc_dispatch_operation_fail(operation,
                                    NULL,
                                    false,
                                    "credential bundle was already consumed");
        return;
    }
    /*
     * This is the ownership commit point.  Clearing the caller's slot is the
     * signal that the transfer happened: every exit above leaves the slot
     * holding the bundle, and every exit below disposes of it here.  The
     * caller's cleanup is an unconditional destroy of whatever the slot
     * still holds, which is a no-op once it is NULL.
     */
    *credentials_slot = NULL;
    /* Hold a second in-flight reference across the vtable call (see
     * ovc_dispatch_invocation_retain). */
    if (!ovc_dispatch_invocation_retain((OvStorage_LayerHandle *)handle)) {
        ovc_dispatch_update_credentials_request_clear(&request);
        ovstorage_secret_bundle_destroy(credentials);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not retain the Stack for update_connection_credentials");
        return;
    }
    ffi_cancel = ovc_cancel_token_mint(cancel);
    handle->root.vtable->update_connection_credentials(
        handle->root.state,
        &request,
        &ffi_cancel,
        ovc_dispatch_complete,
        operation);
    ovc_dispatch_cancel_drop(&ffi_cancel);
    memset(&request, 0, sizeof(request));
    ovc_dispatch_operation_leave((OvStorage_LayerHandle *)handle);
    ovstorage_secret_bundle_destroy(credentials);
}

void ovstorage_update_connection_attributes(
    const OvStorage_LayerHandle *handle,
    const char *target,
    const char *connection_id,
    const OvStorage_AttributePatch *patch,
    const OvStorage_CancelToken *cancel,
    OvStorage_ConnectionCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_UpdateConnectionAttributesRequest request;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;
    bool valid;

    if (on_complete == NULL) {
        return;
    }
    callback.connection = on_complete;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    valid = handle != NULL &&
            ovc_dispatch_address_valid(target) &&
            ovc_dispatch_address_valid(connection_id) &&
            (patch == NULL ||
             ((!patch->has_display_name ||
               ovc_dispatch_utf8_valid(patch->display_name)) &&
              (!patch->has_access_mode ||
               ovc_dispatch_utf8_valid(patch->access_mode))));
    if (valid) {
        valid = ovc_dispatch_abi_cstring_copy(&request.key.target, target) &&
                ovc_dispatch_abi_cstring_copy(&request.key.id,
                                              connection_id);
    }
    if (valid && patch != NULL && patch->has_display_name) {
        request.patch.display_name.present = true;
        valid = ovc_dispatch_abi_cstring_copy(
            &request.patch.display_name.value, patch->display_name);
    }
    if (valid && patch != NULL && patch->has_access_mode) {
        request.patch.access_mode.present = true;
        valid = ovc_dispatch_abi_cstring_copy(
            &request.patch.access_mode.value, patch->access_mode);
    }
    if (patch != NULL && patch->has_visible) {
        request.patch.visible.present = true;
        request.patch.visible.value = patch->visible;
    }
    if (valid) {
        valid = ovc_dispatch_metadata_patch_copy(
            &request.patch.set_user_metadata,
            &request.patch.remove_user_metadata,
            patch == NULL ? NULL : patch->user_metadata);
    }
    if (!valid) {
        ovc_dispatch_update_attributes_request_clear(&request);
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_CONNECTION,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "update_connection_attributes arguments are invalid");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_CONNECTION,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_update_attributes_request_clear(&request);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_CONNECTION,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_UPDATE_CONNECTION_ATTRIBUTES);
    if (task == NULL) {
        ovc_dispatch_update_attributes_request_clear(&request);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate an update_connection_attributes dispatch task");
        return;
    }
    task->request.update_attributes = request;
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    memset(&request, 0, sizeof(request));
    ovc_dispatch_io_task_submit(task);
}

void ovstorage_authenticate_connection(
    const OvStorage_LayerHandle *handle,
    const char *target,
    const char *connection_id,
    OvStorage_InteractiveAuthCapability capability,
    bool auto_open_browser,
    const OvStorage_CancelToken *cancel,
    OvStorage_AuthEventCallback on_complete,
    void *user_data)
{
    OvStoragePlugin_AuthenticateRequest request;
    OvStoragePlugin_CancelTokenFFI ffi_cancel;
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;

    if (on_complete == NULL) {
        return;
    }
    callback.auth = on_complete;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_AUTH_STREAM,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "authenticate_connection: handle is null");
        return;
    }
    if (!ovc_dispatch_address_valid(target)) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_AUTH_STREAM,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "authenticate_connection: target is null or not a valid address");
        return;
    }
    if (!ovc_dispatch_address_valid(connection_id)) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_AUTH_STREAM,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "authenticate_connection: connection id is null or not valid "
            "UTF-8");
        return;
    }
    if ((unsigned int)capability >
        (unsigned int)OvStorage_InteractiveAuthCapability_Browser) {
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_AUTH_STREAM,
            callback,
            user_data,
            OvStorage_Status_InvalidArgument,
            "authenticate_connection: capability is not recognized");
        return;
    }
    if (!ovc_dispatch_abi_cstring_copy(&request.key.target, target) ||
        !ovc_dispatch_abi_cstring_copy(&request.key.id, connection_id)) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_fire_inline_error(
            OVC_DISPATCH_AUTH_STREAM,
            callback,
            user_data,
            OvStorage_Status_Internal,
            "authenticate_connection: out of memory copying its arguments");
        return;
    }
    request.capability = (OvStoragePlugin_InteractiveAuthCapabilityV1)capability;
    request.auto_open_browser = auto_open_browser;
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_AUTH_STREAM,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_AUTH_STREAM,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    operation->stream_scope = ovc_stream_cancel_scope_create(cancel);
    if (operation->stream_scope == NULL) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_operation_fail(operation,
                                    NULL,
                                    false,
                                    "could not create authentication cancellation state");
        return;
    }
    /* Hold a second in-flight reference across the vtable call (see
     * ovc_dispatch_invocation_retain). */
    if (!ovc_dispatch_invocation_retain((OvStorage_LayerHandle *)handle)) {
        ovc_dispatch_abi_str_clear(&request.key.target);
        ovc_dispatch_abi_str_clear(&request.key.id);
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not retain the Stack for authenticate_connection");
        return;
    }
    ffi_cancel = ovc_stream_cancel_scope_mint_producer(
        operation->stream_scope);
    handle->root.vtable->authenticate_connection(handle->root.state,
                                                  &request,
                                                  &ffi_cancel,
                                                  ovc_dispatch_complete,
                                                  operation);
    ovc_dispatch_cancel_drop(&ffi_cancel);
    memset(&request, 0, sizeof(request));
    ovc_dispatch_operation_leave((OvStorage_LayerHandle *)handle);
}

static void ovc_dispatch_root_snapshot_clear(
    OvStoragePlugin_RootInfoSnapshot *snapshot)
{
    size_t index;

    if (snapshot == NULL) {
        return;
    }
    if (snapshot->roots.ptr != NULL) {
        for (index = 0; index < snapshot->roots.len; ++index) {
            ovc_dispatch_root_info_clear(&snapshot->roots.ptr[index], false);
        }
    }
    ovc_abi_free(snapshot->roots.ptr);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void ovc_dispatch_root_updates_reclaim(void *owner)
{
    OvStoragePlugin_RootInfoChangeStream *updates;

    updates = (OvStoragePlugin_RootInfoChangeStream *)owner;
    if (updates == NULL) {
        return;
    }
    if (updates->drop_fn != NULL) {
        updates->drop_fn(updates->state);
    }
    ovc_abi_free(updates);
}

static bool ovc_dispatch_root_updates_discard(
    OvStoragePlugin_RootInfoChangeStream *updates)
{
    if (updates == NULL) {
        return true;
    }
    if (ovc_root_updates_discard(updates,
                                 updates,
                                 ovc_dispatch_root_updates_reclaim) == 0) {
        return true;
    }
    /* A malformed stream has no safe state destructor. */
    ovc_abi_free(updates);
    return false;
}

static OvStorage_RootInfoList *ovc_dispatch_root_list_from_plugin(
    const OvStoragePlugin_RootInfoSnapshot *snapshot)
{
    OvStorage_RootInfoList *list;
    OvStorage_RootInfo *converted;
    OvStorage_RootInfo *items = NULL;
    size_t index;

    if (snapshot == NULL ||
        (snapshot->roots.len != 0 && snapshot->roots.ptr == NULL) ||
        snapshot->roots.len > SIZE_MAX / sizeof(*list->items)) {
        return NULL;
    }
    list = (OvStorage_RootInfoList *)calloc(1, sizeof(*list));
    if (list == NULL) {
        return NULL;
    }
    if (snapshot->roots.len != 0) {
        items = (OvStorage_RootInfo *)calloc(snapshot->roots.len,
                                             sizeof(*items));
        if (items == NULL) {
            ovstorage_root_info_list_destroy(list);
            return NULL;
        }
        list->items = items;
    }
    list->len = snapshot->roots.len;
    for (index = 0; index < list->len; ++index) {
        converted = ovc_dispatch_root_info_from_plugin(
            &snapshot->roots.ptr[index]);
        if (converted == NULL) {
            ovstorage_root_info_list_destroy(list);
            return NULL;
        }
        items[index] = *converted;
        free(converted);
    }
    return list;
}

void ovstorage_list_address_roots(
    const OvStorage_LayerHandle *handle,
    const OvStorage_CancelToken *cancel,
    OvStorage_RootInfoListCallback on_complete,
    void *user_data)
{
    ovc_dispatch_callback callback;
    ovc_dispatch_operation *operation;
    ovc_dispatch_io_task *task;

    if (on_complete == NULL) {
        return;
    }
    callback.root_list = on_complete;
    if (handle == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_ROOT_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_InvalidArgument,
                                       "list_address_roots needs a live Stack");
        return;
    }
    operation = ovc_dispatch_operation_create(
        (OvStorage_LayerHandle *)handle,
        OVC_DISPATCH_ROOT_LIST,
        callback,
        user_data,
        NULL);
    if (operation == NULL) {
        ovc_dispatch_fire_inline_error(OVC_DISPATCH_ROOT_LIST,
                                       callback,
                                       user_data,
                                       OvStorage_Status_Internal,
                                       "Stack is closing or out of memory");
        return;
    }
    task = ovc_dispatch_io_task_create(
        operation, OVC_DISPATCH_IO_TASK_LIST_ADDRESS_ROOTS);
    if (task == NULL) {
        ovc_dispatch_operation_fail_status(
            operation,
            OvStorage_Status_Internal,
            "could not allocate a list_address_roots dispatch task");
        return;
    }
    task->request.list_address_roots.struct_size =
        sizeof(task->request.list_address_roots);
    task->cancel = ovc_cancel_token_mint(cancel);
    task->has_cancel = true;
    ovc_dispatch_io_task_submit(task);
}

/* ------------------------------------------------------------------------- */
/* Cross-language live handoff (RFC-0066): export/import the root Layer. */

static OvStorage_Status ovc_dispatch_handoff_error(OvStorage_Error *out_error,
                                                   OvStorage_Status status,
                                                   const char *message)
{
    if (out_error == NULL) {
        return status;
    }
    ovstorage_error_clear(out_error);
    out_error->code = status;
    out_error->message = ovc_dispatch_cstring_copy(message);
    out_error->code_name = ovc_status_code_name(status);
    return status;
}

OvStorage_Status ovstorage_export_handle(const OvStorage_LayerHandle *handle,
                                         OvStoragePlugin_LayerHandle *out_handle,
                                         OvStorage_Error *out_error)
{
    OvStorage_LayerHandle *mutable_handle;
    ovc_dispatch_root_refbox *refbox;
    OvStorage_Status status;

    if (handle == NULL || out_handle == NULL) {
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "export_handle needs a live Stack handle and an out_handle");
    }
    memset(out_handle, 0, sizeof(*out_handle));
    /* Hold an in-flight reference so a destroy racing this export drains
     * behind it instead of dropping the root mid-mint. */
    mutable_handle = (OvStorage_LayerHandle *)handle;
    if (!ovc_dispatch_operation_enter(mutable_handle)) {
        return ovc_dispatch_handoff_error(out_error,
                                          OvStorage_Status_Internal,
                                          "Stack is closing");
    }
    /* Every built root is a forwarding proxy (wrapped at handle creation),
     * so exporting only bumps the shared refbox and mints one more owned
     * proxy handle over the same inner Layer. */
    refbox = ((ovc_dispatch_root_proxy *)handle->root.state)->refbox;
    if (!ovc_dispatch_proxy_reference_retain(&refbox->references.value)) {
        status = ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_Internal,
            "exported-handle reference count overflow");
    } else if (!ovc_dispatch_root_proxy_mint(refbox, out_handle)) {
        /* The handle's own reference keeps the count above zero here. */
        (void)ovc_dispatch_proxy_reference_release(&refbox->references.value);
        status = ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_Internal,
            "out of memory exporting the Stack root");
    } else {
        ovstorage_error_clear(out_error);
        status = OvStorage_Status_Ok;
    }
    ovc_dispatch_operation_leave(mutable_handle);
    return status;
}

OvStorage_Status ovstorage_import_handle(OvStoragePlugin_LayerHandle handle,
                                         OvStorage_LayerHandle **out_handle,
                                         OvStorage_Error *out_error)
{
    OvStorage_LayerHandle *created;

    if (out_handle == NULL) {
        /* The handle has not been touched: the caller retains it. */
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "import_handle needs an out_handle");
    }
    *out_handle = NULL;
    /* Failure disposal below follows the ownership-transfer handshake
     * contract: a handle that fails before its vtable header is trusted
     * is returned undisposed; once {struct_size, abi_version} check out,
     * the drop slot immediately after them is trustworthy and the handle
     * is consumed. */
    if (handle.state == NULL || handle.vtable == NULL) {
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_InvalidArgument,
            "import_handle needs a non-null {state, vtable} pair");
    }
    if (handle.vtable->struct_size < sizeof(*handle.vtable)) {
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_IncompatibleType,
            "foreign Layer vtable is smaller than the ABI-v2 table");
    }
    if (handle.vtable->abi_version !=
        OVSTORAGE_PLUGIN_ABI_VERSION) {
        if (handle.vtable->drop != NULL) {
            handle.vtable->drop(handle.state);
        }
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_IncompatibleType,
            "foreign Layer handle has an unsupported abi_version");
    }
    if (!ovc_dispatch_root_slots_supported(handle.vtable)) {
        if (handle.vtable->drop != NULL) {
            handle.vtable->drop(handle.state);
        }
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_IncompatibleType,
            "foreign Layer handle does not implement the required "
            "ABI-v2 slots");
    }
    /* An imported root dispatches on the same process-global runtime a
     * built Stack uses; initialize it if no build has run here yet. */
    if (ovc_runtime_ensure(0) != 0) {
        handle.vtable->drop(handle.state);
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_Internal,
            "could not initialize the process-global runtime");
    }
    created = ovc_dispatch_layer_handle_create(handle, NULL, 0);
    if (created == NULL) {
        /* Validation passed above, so this is an allocation failure; the
         * handshake held and the handle is consumed. */
        handle.vtable->drop(handle.state);
        return ovc_dispatch_handoff_error(
            out_error,
            OvStorage_Status_Internal,
            "out of memory importing the Layer handle");
    }
    *out_handle = created;
    ovstorage_error_clear(out_error);
    return OvStorage_Status_Ok;
}

#if defined(OVC_DISPATCH_TEST_MAIN)

#include <assert.h>
#include "ovstorage_defaults.h"
#include "temp_dir.h"

#if defined(NDEBUG)
#error "OVC_DISPATCH_TEST_MAIN requires assertions to be enabled"
#endif

#if defined(_WIN32)
#include <direct.h>
#include <io.h>

typedef DWORD ovc_dispatch_test_thread_id;

static ovc_dispatch_test_thread_id ovc_dispatch_test_thread_self(void)
{
    return GetCurrentThreadId();
}

static int ovc_dispatch_test_thread_equal(ovc_dispatch_test_thread_id left,
                                          ovc_dispatch_test_thread_id right)
{
    return left == right ? 1 : 0;
}

#define unlink _unlink
#define rmdir _rmdir
#else
#include <unistd.h>

typedef pthread_t ovc_dispatch_test_thread_id;

static ovc_dispatch_test_thread_id ovc_dispatch_test_thread_self(void)
{
    return pthread_self();
}

static int ovc_dispatch_test_thread_equal(ovc_dispatch_test_thread_id left,
                                          ovc_dispatch_test_thread_id right)
{
    return pthread_equal(left, right);
}
#endif

typedef struct ovc_dispatch_test_result {
    ovc_completion_latch completed;
    OvStorage_Status status;
    OvStorage_Info *info;
    OvStorage_Bytes bytes;
    OvStorage_AccessDecision access;
    bool had_error;
    OvStorage_Status error_code;
    size_t callback_count;
    ovc_dispatch_test_thread_id callback_thread;
} ovc_dispatch_test_result;

typedef struct ovc_dispatch_test_blocking_callback {
    ovc_mutex mutex;
    ovc_cond changed;
    bool entered;
    bool release;
    bool exited;
    OvStorage_Status status;
    OvStorage_Info *info;
    bool had_error;
} ovc_dispatch_test_blocking_callback;

typedef struct ovc_dispatch_test_destroy {
    OvStorage_LayerHandle *handle;
    ovc_mutex mutex;
    ovc_cond changed;
    bool started;
    bool returned;
} ovc_dispatch_test_destroy;

typedef struct ovc_dispatch_test_fake_layer {
    ovc_mutex mutex;
    ovc_cond changed;
    const char *local_path;
    size_t local_size;
    size_t read_calls;
    size_t read_returns;
    size_t streams_created;
    size_t stream_next_calls;
    size_t stream_drop_calls;
    size_t root_calls;
    size_t root_update_next_calls;
    size_t root_update_drop_calls;
    size_t layer_drop_calls;
    size_t cancel_ffi_completions;
    bool cancel_slot_ready;
    bool cancel_thread_created;
    ovc_thread cancel_thread;
    ovc_dispatch_test_thread_id read_slot_thread;
    ovc_dispatch_test_thread_id root_slot_thread;
} ovc_dispatch_test_fake_layer;

typedef struct ovc_dispatch_test_fake_stream {
    ovc_dispatch_test_fake_layer *layer;
    size_t next_index;
} ovc_dispatch_test_fake_stream;

typedef struct ovc_dispatch_test_cancel_context {
    ovc_mutex mutex;
    ovc_cond changed;
    bool awakened;
    OvStoragePlugin_CancelTokenFFI cancel;
    OvStoragePlugin_OnComplete on_complete;
    void *user_data;
    ovc_dispatch_test_fake_layer *layer;
} ovc_dispatch_test_cancel_context;

typedef struct ovc_dispatch_test_stream_result {
    ovc_completion_latch completed;
    OvStorage_CancelToken *cancel_after_first;
    uint8_t bytes[32];
    size_t bytes_len;
    size_t callback_count;
    size_t chunk_count;
    size_t terminal_count;
    bool terminal_error;
    OvStorage_Status terminal_error_code;
    bool terminal_seen;
} ovc_dispatch_test_stream_result;

typedef struct ovc_dispatch_test_root_result {
    ovc_completion_latch completed;
    ovc_dispatch_test_fake_layer *layer;
    OvStorage_Status status;
    OvStorage_RootInfoList *list;
    bool had_error;
    size_t callback_count;
    size_t update_drops_at_callback;
    ovc_dispatch_test_thread_id callback_thread;
} ovc_dispatch_test_root_result;

typedef struct ovc_dispatch_test_local_result {
    ovc_completion_latch completed;
    OvStorage_Status status;
    OvStorage_LocalDelegate *delegate;
    bool had_error;
    size_t callback_count;
} ovc_dispatch_test_local_result;

typedef struct ovc_dispatch_test_list_result {
    ovc_completion_latch completed;
    OvStorage_Status status;
    OvStorage_List *list;
    OvStorage_VersionList *versions;
    bool had_error;
    size_t callback_count;
} ovc_dispatch_test_list_result;

static OvStoragePlugin_LayerVTableV1 g_ovc_dispatch_test_fake_vtable;

static void ovc_dispatch_test_fake_lock(
    ovc_dispatch_test_fake_layer *layer)
{
    assert(ovc_mutex_lock(&layer->mutex) == 0);
}

static void ovc_dispatch_test_fake_unlock(
    ovc_dispatch_test_fake_layer *layer)
{
    assert(ovc_mutex_unlock(&layer->mutex) == 0);
}

static void ovc_dispatch_test_fake_info(
    OvStoragePlugin_ObjectInfo *info,
    OvStoragePlugin_Str address,
    uint64_t size)
{
    memset(info, 0, sizeof(*info));
    info->address = address;
    info->kind = OvStoragePlugin_ObjectKindV1_File;
    info->size.present = true;
    info->size.value = size;
}

static OvStoragePlugin_StreamStep ovc_dispatch_test_fake_stream_next(
    void *opaque,
    OvStoragePlugin_Bytes *out_chunk,
    OvStoragePlugin_Error *out_error)
{
    static const uint8_t first[] = {'a', 'b'};
    static const uint8_t second[] = {'c', 'd', 'e'};
    ovc_dispatch_test_fake_stream *stream;
    const uint8_t *source;
    size_t length;

    (void)out_error;
    stream = (ovc_dispatch_test_fake_stream *)opaque;
    ovc_dispatch_test_fake_lock(stream->layer);
    ++stream->layer->stream_next_calls;
    ovc_dispatch_test_fake_unlock(stream->layer);
    if (stream->next_index == 0) {
        source = first;
        length = sizeof(first);
    } else if (stream->next_index == 1) {
        source = second;
        length = sizeof(second);
    } else {
        return OvStoragePlugin_StreamStep_Ended;
    }
    ++stream->next_index;
    /* The fake Layer plays the plugin role: mint on the ABI allocator. */
    out_chunk->ptr = (uint8_t *)ovc_abi_alloc(length);
    assert(out_chunk->ptr != NULL);
    memcpy(out_chunk->ptr, source, length);
    out_chunk->len = length;
    return OvStoragePlugin_StreamStep_Yielded;
}

static void ovc_dispatch_test_fake_stream_drop(void *opaque)
{
    ovc_dispatch_test_fake_stream *stream;

    stream = (ovc_dispatch_test_fake_stream *)opaque;
    ovc_dispatch_test_fake_lock(stream->layer);
    ++stream->layer->stream_drop_calls;
    ovc_dispatch_test_fake_unlock(stream->layer);
    free(stream);
}

static void ovc_dispatch_test_cancel_wake(void *opaque)
{
    ovc_dispatch_test_cancel_context *context;

    context = (ovc_dispatch_test_cancel_context *)opaque;
    assert(ovc_mutex_lock(&context->mutex) == 0);
    context->awakened = true;
    assert(ovc_cond_broadcast(&context->changed) == 0);
    assert(ovc_mutex_unlock(&context->mutex) == 0);
}

static void ovc_dispatch_test_cancel_thread(void *opaque)
{
    ovc_dispatch_test_cancel_context *context;
    OvStoragePlugin_Error *error;
    uint64_t subscription;

    context = (ovc_dispatch_test_cancel_context *)opaque;
    subscription = context->cancel.register_callback(
        context->cancel.state,
        ovc_dispatch_test_cancel_wake,
        context);
    ovc_dispatch_test_fake_lock(context->layer);
    context->layer->cancel_slot_ready = true;
    assert(ovc_cond_broadcast(&context->layer->changed) == 0);
    ovc_dispatch_test_fake_unlock(context->layer);
    assert(ovc_mutex_lock(&context->mutex) == 0);
    while (!context->cancel.is_canceled(context->cancel.state)) {
        assert(ovc_cond_wait(&context->changed, &context->mutex) == 0);
    }
    assert(ovc_mutex_unlock(&context->mutex) == 0);
    if (subscription != 0) {
        context->cancel.unregister_callback(context->cancel.state,
                                            subscription);
    }
    error = ovc_dispatch_plugin_error_create(
        OvStoragePlugin_ErrorCode_Cancelled,
        "fake Layer observed cancellation");
    assert(error != NULL);
    context->on_complete(OvStoragePlugin_FFI_STATUS_ERR,
                         NULL,
                         error,
                         context->user_data);
    context->cancel.drop(context->cancel.state);
    ovc_dispatch_test_fake_lock(context->layer);
    ++context->layer->cancel_ffi_completions;
    ovc_dispatch_test_fake_unlock(context->layer);
    assert(ovc_cond_destroy(&context->changed) == 0);
    assert(ovc_mutex_destroy(&context->mutex) == 0);
    free(context);
}

static void ovc_dispatch_test_fake_layer_drop(void *opaque)
{
    ovc_dispatch_test_fake_layer *layer;

    layer = (ovc_dispatch_test_fake_layer *)opaque;
    if (layer->cancel_thread_created) {
        assert(ovc_thread_join(&layer->cancel_thread) == 0);
        layer->cancel_thread_created = false;
    }
    ovc_dispatch_test_fake_lock(layer);
    ++layer->layer_drop_calls;
    ovc_dispatch_test_fake_unlock(layer);
}

static void ovc_dispatch_test_fake_read(
    void *opaque,
    const OvStoragePlugin_ReadRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_dispatch_test_fake_layer *layer;
    OvStoragePlugin_ReadRequest moved;
    OvStoragePlugin_ReadResult *result;
    char *address;
    bool completes_async;

    layer = (ovc_dispatch_test_fake_layer *)opaque;
    assert(request != NULL);
    assert(request->struct_size >= sizeof(*request));
    moved = *request;
    address = ovc_dispatch_slice_copy(moved.address.ptr,
                                      moved.address.len);
    assert(address != NULL);
    ovc_dispatch_test_fake_lock(layer);
    ++layer->read_calls;
    layer->read_slot_thread = ovc_dispatch_test_thread_self();
    ovc_dispatch_test_fake_unlock(layer);

    result = (OvStoragePlugin_ReadResult *)ovc_abi_alloc(sizeof(*result));
    assert(result != NULL);
    memset(result, 0, sizeof(*result));
    completes_async = false;
    if (strcmp(address, "test://cancel-ffi") == 0) {
        ovc_dispatch_test_cancel_context *context;

        assert(cancel != NULL);
        assert(cancel->state != NULL);
        assert(cancel->is_canceled != NULL);
        assert(cancel->register_callback != NULL);
        assert(cancel->unregister_callback != NULL);
        assert(cancel->clone != NULL);
        assert(cancel->drop != NULL);
        assert(!cancel->is_canceled(cancel->state));
        context = (ovc_dispatch_test_cancel_context *)calloc(
            1, sizeof(*context));
        assert(context != NULL);
        assert(ovc_mutex_init(&context->mutex) == 0);
        assert(ovc_cond_init(&context->changed) == 0);
        context->cancel = *cancel;
        context->cancel.state = cancel->clone(cancel->state);
        assert(context->cancel.state != NULL);
        context->on_complete = on_complete;
        context->user_data = user_data;
        context->layer = layer;
        ovc_abi_free(result);
        result = NULL;
        assert(ovc_thread_create(&layer->cancel_thread,
                                 ovc_dispatch_test_cancel_thread,
                                 context) == 0);
        ovc_dispatch_test_fake_lock(layer);
        assert(!layer->cancel_thread_created);
        layer->cancel_thread_created = true;
        ovc_dispatch_test_fake_unlock(layer);
        completes_async = true;
    } else if (strcmp(address, "test://stream") == 0) {
        ovc_dispatch_test_fake_stream *stream;

        stream = (ovc_dispatch_test_fake_stream *)calloc(1,
                                                         sizeof(*stream));
        assert(stream != NULL);
        stream->layer = layer;
        result->tag = OvStoragePlugin_ReadResultTag_Stream;
        result->stream.stream.state = stream;
        result->stream.stream.next_fn =
            ovc_dispatch_test_fake_stream_next;
        result->stream.stream.drop_fn =
            ovc_dispatch_test_fake_stream_drop;
        ovc_dispatch_test_fake_info(&result->stream.info,
                                    moved.address,
                                    UINT64_C(5));
        memset(&moved.address, 0, sizeof(moved.address));
        ovc_dispatch_test_fake_lock(layer);
        ++layer->streams_created;
        ovc_dispatch_test_fake_unlock(layer);
    } else if (strcmp(address, "test://local") == 0) {
        result->tag = OvStoragePlugin_ReadResultTag_LocalDelegate;
        assert(ovc_dispatch_abi_cstring_copy(
            &result->local_delegate.path, layer->local_path));
        ovc_dispatch_test_fake_info(&result->local_delegate.info,
                                    moved.address,
                                    (uint64_t)layer->local_size);
        memset(&moved.address, 0, sizeof(moved.address));
    } else {
        assert(strcmp(address, "test://redirect") == 0);
        result->tag = OvStoragePlugin_ReadResultTag_Redirect;
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.request.method, "GET"));
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.request.url,
            "https://example.invalid/object"));
        result->redirect.request.headers.ptr =
            (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
                sizeof(*result->redirect.request.headers.ptr));
        result->redirect.response_parsing.system_metadata_headers.ptr =
            (OvStoragePlugin_Str *)ovc_abi_alloc(
                sizeof(*result->redirect.response_parsing
                            .system_metadata_headers.ptr));
        result->redirect.response_parsing.checksum_headers.ptr =
            (OvStoragePlugin_ChecksumHeaderBinding *)ovc_abi_alloc(
                sizeof(*result->redirect.response_parsing
                            .checksum_headers.ptr));
        assert(result->redirect.request.headers.ptr != NULL);
        assert(result->redirect.response_parsing
                   .system_metadata_headers.ptr != NULL);
        assert(result->redirect.response_parsing.checksum_headers.ptr !=
               NULL);
        memset(result->redirect.request.headers.ptr,
               0,
               sizeof(*result->redirect.request.headers.ptr));
        memset(result->redirect.response_parsing
                   .system_metadata_headers.ptr,
               0,
               sizeof(*result->redirect.response_parsing
                           .system_metadata_headers.ptr));
        memset(result->redirect.response_parsing.checksum_headers.ptr,
               0,
               sizeof(*result->redirect.response_parsing
                           .checksum_headers.ptr));
        result->redirect.request.headers.len = 1;
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.request.headers.ptr[0].key, "accept"));
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.request.headers.ptr[0].value,
            "application/octet-stream"));
        result->redirect.response_parsing.system_metadata_headers.len = 1;
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.response_parsing
                 .system_metadata_headers.ptr[0],
            "x-test-metadata"));
        result->redirect.response_parsing.checksum_headers.len = 1;
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.response_parsing
                 .checksum_headers.ptr[0].algorithm.token,
            "sha256"));
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.response_parsing
                 .checksum_headers.ptr[0].header,
            "x-test-checksum"));
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.scope.physical_url_prefix,
            "https://example.invalid/"));
        assert(ovc_dispatch_abi_cstring_copy(
            &result->redirect.audit_id, "test-audit"));
    }
    free(address);
    ovc_dispatch_abi_str_clear(&moved.address);
    if (moved.options.if_match.present) {
        ovc_dispatch_abi_str_clear(&moved.options.if_match.value);
    }
    if (!completes_async) {
        on_complete(OvStoragePlugin_FFI_STATUS_OK,
                    result,
                    NULL,
                    user_data);
    }
    ovc_dispatch_test_fake_lock(layer);
    ++layer->read_returns;
    ovc_dispatch_test_fake_unlock(layer);
}

static OvStoragePlugin_StreamStep ovc_dispatch_test_root_update_next(
    void *opaque,
    OvStoragePlugin_RootInfoChange *out_item,
    OvStoragePlugin_Error *out_error)
{
    ovc_dispatch_test_fake_layer *layer;

    (void)out_item;
    (void)out_error;
    layer = (ovc_dispatch_test_fake_layer *)opaque;
    ovc_dispatch_test_fake_lock(layer);
    ++layer->root_update_next_calls;
    ovc_dispatch_test_fake_unlock(layer);
    return OvStoragePlugin_StreamStep_Ended;
}

static void ovc_dispatch_test_root_update_drop(void *opaque)
{
    ovc_dispatch_test_fake_layer *layer;

    layer = (ovc_dispatch_test_fake_layer *)opaque;
    ovc_dispatch_test_fake_lock(layer);
    ++layer->root_update_drop_calls;
    ovc_dispatch_test_fake_unlock(layer);
}

static void ovc_dispatch_test_fake_roots(
    void *opaque,
    const OvStoragePlugin_ListAddressRootsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_dispatch_test_fake_layer *layer;
    OvStoragePlugin_ListAddressRootsResult *envelope;
    OvStoragePlugin_RootInfoChangeStream *updates;

    (void)request;
    (void)cancel;
    layer = (ovc_dispatch_test_fake_layer *)opaque;
    ovc_dispatch_test_fake_lock(layer);
    ++layer->root_calls;
    layer->root_slot_thread = ovc_dispatch_test_thread_self();
    ovc_dispatch_test_fake_unlock(layer);
    envelope = (OvStoragePlugin_ListAddressRootsResult *)ovc_abi_alloc(
        sizeof(*envelope));
    assert(envelope != NULL);
    memset(envelope, 0, sizeof(*envelope));
    envelope->snapshot.roots.ptr = (OvStoragePlugin_RootInfo *)ovc_abi_alloc(
        sizeof(*envelope->snapshot.roots.ptr));
    assert(envelope->snapshot.roots.ptr != NULL);
    memset(envelope->snapshot.roots.ptr,
           0,
           sizeof(*envelope->snapshot.roots.ptr));
    envelope->snapshot.roots.len = 0;
    envelope->snapshot.updates = true;
    updates = (OvStoragePlugin_RootInfoChangeStream *)ovc_abi_alloc(
        sizeof(*updates));
    assert(updates != NULL);
    memset(updates, 0, sizeof(*updates));
    updates->state = layer;
    updates->next_fn = ovc_dispatch_test_root_update_next;
    updates->drop_fn = ovc_dispatch_test_root_update_drop;
    envelope->updates = updates;
    on_complete(OvStoragePlugin_FFI_STATUS_OK,
                envelope,
                NULL,
                user_data);
}

static OvStorage_LayerHandle *ovc_dispatch_test_fake_handle_create(
    ovc_dispatch_test_fake_layer *layer,
    const char *local_path,
    size_t local_size)
{
    OvStoragePlugin_LayerHandle root;

    memset(layer, 0, sizeof(*layer));
    assert(ovc_mutex_init(&layer->mutex) == 0);
    assert(ovc_cond_init(&layer->changed) == 0);
    layer->local_path = local_path;
    layer->local_size = local_size;
    g_ovc_dispatch_test_fake_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    g_ovc_dispatch_test_fake_vtable.drop =
        ovc_dispatch_test_fake_layer_drop;
    g_ovc_dispatch_test_fake_vtable.read = ovc_dispatch_test_fake_read;
    g_ovc_dispatch_test_fake_vtable.list_address_roots =
        ovc_dispatch_test_fake_roots;
    root.state = layer;
    root.vtable = &g_ovc_dispatch_test_fake_vtable;
    return ovc_dispatch_layer_handle_create(root, NULL, 0);
}

static void ovc_dispatch_test_sync(int result)
{
    assert(result == 0);
}

static void ovc_dispatch_test_result_init(ovc_dispatch_test_result *result)
{
    memset(result, 0, sizeof(*result));
    ovc_dispatch_test_sync(ovc_completion_latch_init(&result->completed));
}

static void ovc_dispatch_test_result_wait(ovc_dispatch_test_result *result)
{
    ovc_dispatch_test_sync(ovc_completion_latch_wait(&result->completed));
}

static void ovc_dispatch_test_result_destroy(ovc_dispatch_test_result *result)
{
    ovstorage_info_destroy(result->info);
    ovstorage_bytes_destroy(&result->bytes);
    ovstorage_access_decision_clear(&result->access);
    ovc_dispatch_test_sync(ovc_completion_latch_destroy(&result->completed));
}

static void ovc_dispatch_test_info_complete(
    OvStorage_Status status,
    OvStorage_Info *info,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_result *result;

    result = (ovc_dispatch_test_result *)user_data;
    result->status = status;
    result->info = info;
    result->had_error = error != NULL;
    result->error_code = error == NULL ? OvStorage_Status_Ok : error->code;
    result->callback_thread = ovc_dispatch_test_thread_self();
    ++result->callback_count;
    ovc_dispatch_test_sync(ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_read_complete(
    OvStorage_Status status,
    OvStorage_Bytes bytes,
    OvStorage_Info *info,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_result *result;

    result = (ovc_dispatch_test_result *)user_data;
    result->status = status;
    result->bytes = bytes;
    result->info = info;
    result->had_error = error != NULL;
    result->error_code = error == NULL ? OvStorage_Status_Ok : error->code;
    result->callback_thread = ovc_dispatch_test_thread_self();
    ++result->callback_count;
    ovc_dispatch_test_sync(ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_status_complete(
    OvStorage_Status status,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_result *result;

    result = (ovc_dispatch_test_result *)user_data;
    result->status = status;
    result->had_error = error != NULL;
    result->error_code = error == NULL ? OvStorage_Status_Ok : error->code;
    result->callback_thread = ovc_dispatch_test_thread_self();
    ++result->callback_count;
    ovc_dispatch_test_sync(ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_access_complete(
    OvStorage_Status status,
    OvStorage_AccessDecision decision,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_result *result;

    result = (ovc_dispatch_test_result *)user_data;
    result->status = status;
    result->access = decision;
    result->had_error = error != NULL;
    result->error_code = error == NULL ? OvStorage_Status_Ok : error->code;
    result->callback_thread = ovc_dispatch_test_thread_self();
    ++result->callback_count;
    ovc_dispatch_test_sync(ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_stream_result_init(
    ovc_dispatch_test_stream_result *result,
    OvStorage_CancelToken *cancel_after_first)
{
    memset(result, 0, sizeof(*result));
    result->cancel_after_first = cancel_after_first;
    ovc_dispatch_test_sync(ovc_completion_latch_init(&result->completed));
}

static void ovc_dispatch_test_stream_complete(
    OvStorage_Bytes chunk,
    const OvStorage_Error *error,
    bool done,
    void *user_data)
{
    ovc_dispatch_test_stream_result *result;

    result = (ovc_dispatch_test_stream_result *)user_data;
    assert(!result->terminal_seen);
    ++result->callback_count;
    if (!done) {
        assert(error == NULL);
        assert(chunk.len <= sizeof(result->bytes) - result->bytes_len);
        if (chunk.len != 0) {
            memcpy(result->bytes + result->bytes_len,
                   chunk.data,
                   chunk.len);
        }
        result->bytes_len += chunk.len;
        ++result->chunk_count;
        ovstorage_bytes_destroy(&chunk);
        if (result->cancel_after_first != NULL &&
            result->chunk_count == 1) {
            ovstorage_cancel_token_cancel(result->cancel_after_first);
        }
        return;
    }
    assert(chunk.data == NULL);
    assert(chunk.len == 0);
    assert(chunk.free_ctx == NULL);
    result->terminal_seen = true;
    result->terminal_error = error != NULL;
    result->terminal_error_code =
        error == NULL ? OvStorage_Status_Ok : error->code;
    ++result->terminal_count;
    ovc_dispatch_test_sync(
        ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_stream_result_wait_destroy(
    ovc_dispatch_test_stream_result *result)
{
    ovc_dispatch_test_sync(ovc_completion_latch_wait(&result->completed));
    ovc_dispatch_test_sync(ovc_completion_latch_destroy(&result->completed));
}

static void ovc_dispatch_test_root_complete(
    OvStorage_Status status,
    OvStorage_RootInfoList *list,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_root_result *result;

    result = (ovc_dispatch_test_root_result *)user_data;
    result->status = status;
    result->list = list;
    result->had_error = error != NULL;
    result->callback_thread = ovc_dispatch_test_thread_self();
    ++result->callback_count;
    ovc_dispatch_test_fake_lock(result->layer);
    result->update_drops_at_callback =
        result->layer->root_update_drop_calls;
    ovc_dispatch_test_fake_unlock(result->layer);
    ovc_dispatch_test_sync(
        ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_local_complete(
    OvStorage_Status status,
    OvStorage_LocalDelegate *delegate,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_local_result *result;

    result = (ovc_dispatch_test_local_result *)user_data;
    result->status = status;
    result->delegate = delegate;
    result->had_error = error != NULL;
    ++result->callback_count;
    ovc_dispatch_test_sync(
        ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_list_complete(
    OvStorage_Status status,
    OvStorage_List *list,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_list_result *result;

    result = (ovc_dispatch_test_list_result *)user_data;
    result->status = status;
    result->list = list;
    result->had_error = error != NULL;
    ++result->callback_count;
    ovc_dispatch_test_sync(
        ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_versions_complete(
    OvStorage_Status status,
    OvStorage_VersionList *versions,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_list_result *result;

    result = (ovc_dispatch_test_list_result *)user_data;
    result->status = status;
    result->versions = versions;
    result->had_error = error != NULL;
    ++result->callback_count;
    ovc_dispatch_test_sync(
        ovc_completion_latch_complete(&result->completed));
}

static void ovc_dispatch_test_blocking_callback_init(
    ovc_dispatch_test_blocking_callback *callback)
{
    memset(callback, 0, sizeof(*callback));
    ovc_dispatch_test_sync(ovc_mutex_init(&callback->mutex));
    ovc_dispatch_test_sync(ovc_cond_init(&callback->changed));
}

static void ovc_dispatch_test_blocking_info_complete(
    OvStorage_Status status,
    OvStorage_Info *info,
    const OvStorage_Error *error,
    void *user_data)
{
    ovc_dispatch_test_blocking_callback *callback;

    callback = (ovc_dispatch_test_blocking_callback *)user_data;
    ovc_dispatch_test_sync(ovc_mutex_lock(&callback->mutex));
    callback->status = status;
    callback->info = info;
    callback->had_error = error != NULL;
    callback->entered = true;
    ovc_dispatch_test_sync(ovc_cond_broadcast(&callback->changed));
    while (!callback->release) {
        ovc_dispatch_test_sync(
            ovc_cond_wait(&callback->changed, &callback->mutex));
    }
    callback->exited = true;
    ovc_dispatch_test_sync(ovc_cond_broadcast(&callback->changed));
    ovc_dispatch_test_sync(ovc_mutex_unlock(&callback->mutex));
}

static void ovc_dispatch_test_blocking_callback_wait(
    ovc_dispatch_test_blocking_callback *callback)
{
    ovc_dispatch_test_sync(ovc_mutex_lock(&callback->mutex));
    while (!callback->entered) {
        ovc_dispatch_test_sync(
            ovc_cond_wait(&callback->changed, &callback->mutex));
    }
    ovc_dispatch_test_sync(ovc_mutex_unlock(&callback->mutex));
}

static void ovc_dispatch_test_blocking_callback_release(
    ovc_dispatch_test_blocking_callback *callback)
{
    ovc_dispatch_test_sync(ovc_mutex_lock(&callback->mutex));
    callback->release = true;
    ovc_dispatch_test_sync(ovc_cond_broadcast(&callback->changed));
    ovc_dispatch_test_sync(ovc_mutex_unlock(&callback->mutex));
}

static void ovc_dispatch_test_blocking_callback_destroy(
    ovc_dispatch_test_blocking_callback *callback)
{
    assert(callback->entered);
    assert(callback->exited);
    assert(callback->status == OvStorage_Status_Ok);
    assert(!callback->had_error);
    assert(callback->info != NULL);
    ovstorage_info_destroy(callback->info);
    ovc_dispatch_test_sync(ovc_cond_destroy(&callback->changed));
    ovc_dispatch_test_sync(ovc_mutex_destroy(&callback->mutex));
}

static void ovc_dispatch_test_destroy_thread(void *argument)
{
    ovc_dispatch_test_destroy *destroy;

    destroy = (ovc_dispatch_test_destroy *)argument;
    ovc_dispatch_test_sync(ovc_mutex_lock(&destroy->mutex));
    destroy->started = true;
    ovc_dispatch_test_sync(ovc_cond_broadcast(&destroy->changed));
    ovc_dispatch_test_sync(ovc_mutex_unlock(&destroy->mutex));

    ovstorage_layer_handle_destroy(destroy->handle);

    ovc_dispatch_test_sync(ovc_mutex_lock(&destroy->mutex));
    destroy->returned = true;
    ovc_dispatch_test_sync(ovc_cond_broadcast(&destroy->changed));
    ovc_dispatch_test_sync(ovc_mutex_unlock(&destroy->mutex));
}

static OvStorage_LayerHandle *ovc_dispatch_test_build_file_stack(
    const char *root_url,
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
    root = ovstorage_config_value_create_string(root_url);
    memset(&options, 0, sizeof(options));
    options.runtime_threads = runtime_threads;
    handle = NULL;
    memset(&error, 0, sizeof(error));

    assert(registry != NULL);
    assert(stack != NULL);
    assert(request != NULL);
    assert(root != NULL);
    assert(ovstorage_stack_add_layer(
               stack, registry, "files", "file", &error) ==
           OvStorage_Status_Ok);
    /* The Stack's declaration pins the factory independently. */
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

static void ovc_dispatch_test_round_trip(OvStorage_LayerHandle *handle,
                                         const char *root_address,
                                         const char *address,
                                         const char *native_path,
                                         const uint8_t *payload,
                                         size_t payload_len)
{
    OvStorage_WriteOptions write_options;
    OvStorage_StatOptions stat_options;
    OvStorage_ReadOptions read_options;
    OvStorage_ListOptions list_options;
    OvStorage_ListVersionsOptions versions_options;
    ovc_dispatch_test_result result;
    ovc_dispatch_test_local_result local;
    ovc_dispatch_test_list_result listed;
    char *canonical_path;

    memset(&write_options, 0, sizeof(write_options));
    ovc_dispatch_test_result_init(&result);
    ovstorage_write(handle,
                    address,
                    payload,
                    payload_len,
                    &write_options,
                    NULL,
                    ovc_dispatch_test_info_complete,
                    &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.info != NULL);
    assert(result.callback_count == 1);
    assert(result.info->has_size);
    assert(result.info->size == payload_len);
    ovc_dispatch_test_result_destroy(&result);

    memset(&stat_options, 0, sizeof(stat_options));
    ovc_dispatch_test_result_init(&result);
    ovstorage_stat(handle,
                   address,
                   &stat_options,
                   NULL,
                   ovc_dispatch_test_info_complete,
                   &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.info != NULL);
    assert(result.callback_count == 1);
    assert(result.info->has_size);
    assert(result.info->size == payload_len);
    ovc_dispatch_test_result_destroy(&result);

    memset(&read_options, 0, sizeof(read_options));
    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         address,
                         &read_options,
                         NULL,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.info != NULL);
    assert(result.callback_count == 1);
    assert(result.bytes.len == payload_len);
    assert(payload_len == 0 ||
           memcmp(result.bytes.data, payload, payload_len) == 0);
    ovc_dispatch_test_result_destroy(&result);

    memset(&local, 0, sizeof(local));
    ovc_dispatch_test_sync(ovc_completion_latch_init(&local.completed));
    ovstorage_read_local_file(handle,
                              address,
                              &read_options,
                              NULL,
                              ovc_dispatch_test_local_complete,
                              &local);
    ovc_dispatch_test_sync(ovc_completion_latch_wait(&local.completed));
    assert(local.status == OvStorage_Status_Ok);
    assert(!local.had_error);
    assert(local.callback_count == 1);
    assert(local.delegate != NULL);
#if defined(_WIN32)
    /* `_fullpath` makes the path absolute but does NOT expand 8.3 short
     * components, so it is not the Windows analogue of realpath(3).
     * The backend canonicalizes through
     * `GetFinalPathNameByHandleW` (file_backend.c), which returns the long
     * form — so on a host whose %TEMP% carries a short name, as GitHub's
     * runners do (`C:\Users\RUNNER~1\...`), the two disagree and this
     * assertion fails on a correct implementation. Expand to the long form
     * so both sides name the same path. */
    {
        /* WIDE throughout. The ANSI spellings (`_fullpath`,
         * `GetLongPathNameA`) transcode through the active code page, so a
         * temp root outside it -- a non-ASCII account name is enough --
         * fails or comes back mangled, and the assertion below then fires
         * on a correct implementation. The backend canonicalizes wide for
         * the same reason. */
        wchar_t *wide_native = ovc_utf8_to_wide(native_path);
        wchar_t *wide_absolute = NULL;
        wchar_t *wide_long = NULL;
        DWORD long_length;

        canonical_path = NULL;
        if (wide_native != NULL) {
            wide_absolute = _wfullpath(NULL, wide_native, 0);
            free(wide_native);
        }
        if (wide_absolute != NULL) {
            long_length = GetLongPathNameW(wide_absolute, NULL, 0);
            if (long_length != 0) {
                wide_long = (wchar_t *)malloc((size_t)long_length
                                              * sizeof(*wide_long));
                if (wide_long != NULL
                    && GetLongPathNameW(wide_absolute, wide_long, long_length)
                           == 0) {
                    free(wide_long);
                    wide_long = NULL;
                }
            }
            free(wide_absolute);
        }
        if (wide_long != NULL) {
            canonical_path = ovc_wide_to_utf8(wide_long);
            free(wide_long);
        }
    }
#else
    canonical_path = realpath(native_path, NULL);
#endif
    assert(canonical_path != NULL);
    assert(strcmp(ovstorage_local_delegate_path(local.delegate),
                  canonical_path) == 0);
    free(canonical_path);
    assert(ovstorage_local_delegate_info(local.delegate) != NULL);
    assert(strcmp(ovstorage_local_delegate_info(local.delegate)->address,
                  address) == 0);
    assert(ovstorage_local_delegate_info(local.delegate)->size == payload_len);
    ovstorage_local_delegate_destroy(local.delegate);
    ovc_dispatch_test_sync(
        ovc_completion_latch_destroy(&local.completed));

    memset(&list_options, 0, sizeof(list_options));
    memset(&listed, 0, sizeof(listed));
    ovc_dispatch_test_sync(ovc_completion_latch_init(&listed.completed));
    ovstorage_list(handle,
                   root_address,
                   &list_options,
                   NULL,
                   ovc_dispatch_test_list_complete,
                   &listed);
    ovc_dispatch_test_sync(ovc_completion_latch_wait(&listed.completed));
    assert(listed.status == OvStorage_Status_Ok);
    assert(!listed.had_error);
    assert(listed.callback_count == 1);
    assert(listed.list != NULL);
    assert(listed.list->len == 1);
    ovstorage_list_destroy(listed.list);
    ovc_dispatch_test_sync(
        ovc_completion_latch_destroy(&listed.completed));

    memset(&versions_options, 0, sizeof(versions_options));
    memset(&listed, 0, sizeof(listed));
    ovc_dispatch_test_sync(ovc_completion_latch_init(&listed.completed));
    ovstorage_list_versions(handle,
                            address,
                            &versions_options,
                            NULL,
                            ovc_dispatch_test_versions_complete,
                            &listed);
    ovc_dispatch_test_sync(ovc_completion_latch_wait(&listed.completed));
    assert(listed.status == OvStorage_Status_Ok);
    assert(!listed.had_error);
    assert(listed.callback_count == 1);
    assert(listed.versions != NULL);
    assert(listed.versions->len == 1);
    ovstorage_version_list_destroy(listed.versions);
    ovc_dispatch_test_sync(
        ovc_completion_latch_destroy(&listed.completed));
}

static bool ovc_dispatch_test_has_user_metadata(
    const OvStorage_Info *info,
    const char *key,
    const char *value)
{
    size_t index;

    for (index = 0; index < info->user_metadata_len; ++index) {
        const char *item_key;
        const char *item_value;

        item_key = info->user_metadata[index].key;
        item_value = info->user_metadata[index].value;
        if (item_key != NULL && item_value != NULL &&
            strcmp(item_key, key) == 0 && strcmp(item_value, value) == 0) {
            return true;
        }
    }
    return false;
}

static void ovc_dispatch_test_namespace_ops(
    OvStorage_LayerHandle *handle,
    const char *root_address,
    const char *source_address,
    const uint8_t *payload,
    size_t payload_len)
{
    char copied_address[1024];
    char renamed_address[1024];
    char directory_address[1024];
    OvStorage_ReadOptions read_options;
    OvStorage_StatOptions stat_options;
    OvStorage_UpdateMetadataOptions *metadata_options;
    OvStorage_AccessOps access_ops;
    OvStorage_Error builder_error;
    ovc_dispatch_test_result result;
    int written;

    written = snprintf(copied_address,
                       sizeof(copied_address),
                       "%scopied.bin",
                       root_address);
    assert(written > 0 && (size_t)written < sizeof(copied_address));
    written = snprintf(renamed_address,
                       sizeof(renamed_address),
                       "%srenamed.bin",
                       root_address);
    assert(written > 0 && (size_t)written < sizeof(renamed_address));
    written = snprintf(directory_address,
                       sizeof(directory_address),
                       "%snested/",
                       root_address);
    assert(written > 0 && (size_t)written < sizeof(directory_address));

    ovc_dispatch_test_result_init(&result);
    ovstorage_copy(handle,
                   source_address,
                   copied_address,
                   NULL,
                   ovc_dispatch_test_info_complete,
                   &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(strcmp(result.info->address, copied_address) == 0);
    ovc_dispatch_test_result_destroy(&result);

    memset(&read_options, 0, sizeof(read_options));
    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         copied_address,
                         &read_options,
                         NULL,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.bytes.len == payload_len);
    assert(payload_len == 0 ||
           memcmp(result.bytes.data, payload, payload_len) == 0);
    ovc_dispatch_test_result_destroy(&result);

    memset(&builder_error, 0, sizeof(builder_error));
    metadata_options = ovstorage_update_metadata_options_create();
    assert(metadata_options != NULL);
    assert(ovstorage_update_metadata_options_set(metadata_options,
                                                 "color",
                                                 "blue",
                                                 &builder_error) ==
           OvStorage_Status_Ok);
    assert(ovstorage_update_metadata_options_set(metadata_options,
                                                 "obsolete",
                                                 "old",
                                                 &builder_error) ==
           OvStorage_Status_Ok);
    ovc_dispatch_test_result_init(&result);
    ovstorage_update_metadata(handle,
                              copied_address,
                              metadata_options,
                              NULL,
                              ovc_dispatch_test_info_complete,
                              &result);
    /* The public const options are borrowed and were cloned before return. */
    ovstorage_update_metadata_options_destroy(metadata_options);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(ovc_dispatch_test_has_user_metadata(result.info,
                                               "color",
                                               "blue"));
    assert(ovc_dispatch_test_has_user_metadata(result.info,
                                               "obsolete",
                                               "old"));
    ovc_dispatch_test_result_destroy(&result);

    metadata_options = ovstorage_update_metadata_options_create();
    assert(metadata_options != NULL);
    assert(ovstorage_update_metadata_options_remove(metadata_options,
                                                    "obsolete",
                                                    &builder_error) ==
           OvStorage_Status_Ok);
    ovc_dispatch_test_result_init(&result);
    ovstorage_update_metadata(handle,
                              copied_address,
                              metadata_options,
                              NULL,
                              ovc_dispatch_test_info_complete,
                              &result);
    ovstorage_update_metadata_options_destroy(metadata_options);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(ovc_dispatch_test_has_user_metadata(result.info,
                                               "color",
                                               "blue"));
    assert(!ovc_dispatch_test_has_user_metadata(result.info,
                                                "obsolete",
                                                "old"));
    ovc_dispatch_test_result_destroy(&result);
    ovstorage_error_clear(&builder_error);

    memset(&access_ops, 0, sizeof(access_ops));
    access_ops.update_metadata = true;
    ovc_dispatch_test_result_init(&result);
    ovstorage_check_access(handle,
                           root_address,
                           access_ops,
                           NULL,
                           ovc_dispatch_test_access_complete,
                           &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(!result.access.allowed);
    assert(result.access.denied_ops.update_metadata);
    assert(result.access.reason != NULL);
    ovstorage_access_decision_clear(&result.access);
    assert(result.access.reason == NULL);
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_result_init(&result);
    ovstorage_rename(handle,
                     copied_address,
                     renamed_address,
                     NULL,
                     ovc_dispatch_test_status_complete,
                     &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    ovc_dispatch_test_result_destroy(&result);

    memset(&stat_options, 0, sizeof(stat_options));
    stat_options.full_metadata = true;
    ovc_dispatch_test_result_init(&result);
    ovstorage_stat(handle,
                   renamed_address,
                   &stat_options,
                   NULL,
                   ovc_dispatch_test_info_complete,
                   &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.info != NULL);
    assert(ovc_dispatch_test_has_user_metadata(result.info,
                                               "color",
                                               "blue"));
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_result_init(&result);
    ovstorage_create_directory(handle,
                               directory_address,
                               NULL,
                               ovc_dispatch_test_info_complete,
                               &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(result.info->kind == OvStorage_ObjectKind_Directory);
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_result_init(&result);
    ovstorage_delete_directory(handle,
                               directory_address,
                               NULL,
                               ovc_dispatch_test_status_complete,
                               &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_result_init(&result);
    ovstorage_delete(handle,
                     renamed_address,
                     NULL,
                     ovc_dispatch_test_status_complete,
                     &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_result_init(&result);
    ovstorage_stat(handle,
                   renamed_address,
                   &stat_options,
                   NULL,
                   ovc_dispatch_test_info_complete,
                   &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_NotFound);
    assert(result.had_error);
    assert(result.error_code == OvStorage_Status_NotFound);
    assert(result.callback_count == 1);
    assert(result.info == NULL);
    ovc_dispatch_test_result_destroy(&result);
}

static void ovc_dispatch_test_fake_io(const char *local_path,
                                      const uint8_t *local_bytes,
                                      size_t local_len)
{
    static const uint8_t streamed[] = {'a', 'b', 'c', 'd', 'e'};
    ovc_dispatch_test_fake_layer layer;
    OvStorage_LayerHandle *handle;
    OvStorage_ReadOptions options;
    ovc_dispatch_test_result result;
    ovc_dispatch_test_stream_result stream_result;
    ovc_dispatch_test_root_result roots;
    OvStorage_CancelToken *cancel;
    ovc_dispatch_test_thread_id caller_thread;
    size_t next_before;
    size_t drops_before;

    caller_thread = ovc_dispatch_test_thread_self();
    handle = ovc_dispatch_test_fake_handle_create(&layer,
                                                  local_path,
                                                  local_len);
    assert(handle != NULL);
    memset(&options, 0, sizeof(options));

    ovc_dispatch_test_fake_lock(&layer);
    next_before = layer.stream_next_calls;
    drops_before = layer.stream_drop_calls;
    ovc_dispatch_test_fake_unlock(&layer);
    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         "test://stream",
                         &options,
                         NULL,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.info != NULL);
    assert(result.bytes.len == sizeof(streamed));
    assert(memcmp(result.bytes.data, streamed, sizeof(streamed)) == 0);
    assert(ovc_dispatch_test_thread_equal(result.callback_thread, caller_thread) == 0);
    ovc_dispatch_test_fake_lock(&layer);
    assert(layer.stream_next_calls - next_before == 3);
    assert(layer.stream_drop_calls - drops_before == 1);
    ovc_dispatch_test_fake_unlock(&layer);
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_fake_lock(&layer);
    next_before = layer.stream_next_calls;
    drops_before = layer.stream_drop_calls;
    ovc_dispatch_test_fake_unlock(&layer);
    ovc_dispatch_test_stream_result_init(&stream_result, NULL);
    ovstorage_read_stream(handle,
                          "test://stream",
                          &options,
                          NULL,
                          ovc_dispatch_test_stream_complete,
                          &stream_result);
    ovc_dispatch_test_stream_result_wait_destroy(&stream_result);
    assert(stream_result.callback_count == 3);
    assert(stream_result.chunk_count == 2);
    assert(stream_result.terminal_count == 1);
    assert(!stream_result.terminal_error);
    assert(stream_result.bytes_len == sizeof(streamed));
    assert(memcmp(stream_result.bytes, streamed, sizeof(streamed)) == 0);
    ovc_dispatch_test_fake_lock(&layer);
    assert(layer.stream_next_calls - next_before == 3);
    assert(layer.stream_drop_calls - drops_before == 1);
    ovc_dispatch_test_fake_unlock(&layer);

    cancel = ovstorage_cancel_token_create();
    assert(cancel != NULL);
    ovc_dispatch_test_fake_lock(&layer);
    next_before = layer.stream_next_calls;
    drops_before = layer.stream_drop_calls;
    ovc_dispatch_test_fake_unlock(&layer);
    ovc_dispatch_test_stream_result_init(&stream_result, cancel);
    ovstorage_read_stream(handle,
                          "test://stream",
                          &options,
                          cancel,
                          ovc_dispatch_test_stream_complete,
                          &stream_result);
    ovc_dispatch_test_stream_result_wait_destroy(&stream_result);
    assert(stream_result.callback_count == 2);
    assert(stream_result.chunk_count == 1);
    assert(stream_result.terminal_count == 1);
    assert(stream_result.terminal_error);
    assert(stream_result.terminal_error_code == OvStorage_Status_Cancelled);
    assert(stream_result.bytes_len == 2);
    assert(memcmp(stream_result.bytes, "ab", 2) == 0);
    ovc_dispatch_test_fake_lock(&layer);
    assert(layer.stream_next_calls - next_before == 1);
    assert(layer.stream_drop_calls - drops_before == 1);
    ovc_dispatch_test_fake_unlock(&layer);
    ovstorage_cancel_token_destroy(cancel);

    cancel = ovstorage_cancel_token_create();
    assert(cancel != NULL);
    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         "test://cancel-ffi",
                         &options,
                         cancel,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_fake_lock(&layer);
    while (!layer.cancel_slot_ready) {
        assert(ovc_cond_wait(&layer.changed, &layer.mutex) == 0);
    }
    ovc_dispatch_test_fake_unlock(&layer);
    ovstorage_cancel_token_cancel(cancel);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Cancelled);
    assert(result.had_error);
    assert(result.error_code == OvStorage_Status_Cancelled);
    assert(result.callback_count == 1);
    assert(result.info == NULL);
    ovc_dispatch_test_result_destroy(&result);
    ovstorage_cancel_token_destroy(cancel);

    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         "test://local",
                         &options,
                         NULL,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Ok);
    assert(!result.had_error);
    assert(result.callback_count == 1);
    assert(result.bytes.len == local_len);
    assert(local_len == 0 ||
           memcmp(result.bytes.data, local_bytes, local_len) == 0);
    ovc_dispatch_test_result_destroy(&result);

    ovc_dispatch_test_stream_result_init(&stream_result, NULL);
    ovstorage_read_stream(handle,
                          "test://local",
                          &options,
                          NULL,
                          ovc_dispatch_test_stream_complete,
                          &stream_result);
    ovc_dispatch_test_stream_result_wait_destroy(&stream_result);
    assert(stream_result.chunk_count >= 1);
    assert(stream_result.terminal_count == 1);
    assert(!stream_result.terminal_error);
    assert(stream_result.bytes_len == local_len);
    assert(local_len == 0 ||
           memcmp(stream_result.bytes, local_bytes, local_len) == 0);

    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         "test://redirect",
                         &options,
                         NULL,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Unsupported);
    assert(result.had_error);
    assert(result.error_code == OvStorage_Status_Unsupported);
    assert(result.callback_count == 1);
    assert(result.info == NULL);
    assert(result.bytes.data == NULL);
    assert(result.bytes.len == 0);
    ovc_dispatch_test_result_destroy(&result);

    cancel = ovstorage_cancel_token_create();
    assert(cancel != NULL);
    ovstorage_cancel_token_cancel(cancel);
    ovc_dispatch_test_result_init(&result);
    ovstorage_read_bytes(handle,
                         "test://stream",
                         &options,
                         cancel,
                         ovc_dispatch_test_read_complete,
                         &result);
    ovc_dispatch_test_result_wait(&result);
    assert(result.status == OvStorage_Status_Cancelled);
    assert(result.had_error);
    assert(result.error_code == OvStorage_Status_Cancelled);
    assert(result.callback_count == 1);
    assert(result.info == NULL);
    ovc_dispatch_test_result_destroy(&result);
    ovstorage_cancel_token_destroy(cancel);

    memset(&roots, 0, sizeof(roots));
    roots.layer = &layer;
    ovc_dispatch_test_sync(ovc_completion_latch_init(&roots.completed));
    ovstorage_list_address_roots(handle,
                                 NULL,
                                 ovc_dispatch_test_root_complete,
                                 &roots);
    ovc_dispatch_test_sync(ovc_completion_latch_wait(&roots.completed));
    assert(roots.status == OvStorage_Status_Ok);
    assert(!roots.had_error);
    assert(roots.callback_count == 1);
    assert(roots.list != NULL);
    assert(roots.list->len == 0);
    assert(roots.update_drops_at_callback == 1);
    assert(ovc_dispatch_test_thread_equal(roots.callback_thread, caller_thread) == 0);
    ovc_dispatch_test_fake_lock(&layer);
    assert(layer.root_calls == 1);
    assert(layer.root_update_next_calls == 0);
    assert(layer.root_update_drop_calls == 1);
    assert(ovc_dispatch_test_thread_equal(roots.callback_thread,
                         layer.root_slot_thread) != 0);
    ovc_dispatch_test_fake_unlock(&layer);
    ovstorage_root_info_list_destroy(roots.list);
    ovc_dispatch_test_sync(
        ovc_completion_latch_destroy(&roots.completed));

    ovstorage_layer_handle_destroy(handle);
    ovc_dispatch_test_fake_lock(&layer);
    assert(layer.read_calls == 7);
    assert(layer.read_returns == layer.read_calls);
    assert(layer.streams_created == 3);
    assert(layer.stream_drop_calls == layer.streams_created);
    assert(layer.layer_drop_calls == 1);
    assert(layer.cancel_ffi_completions == 1);
    ovc_dispatch_test_fake_unlock(&layer);
    ovc_dispatch_test_sync(ovc_cond_destroy(&layer.changed));
    ovc_dispatch_test_sync(ovc_mutex_destroy(&layer.mutex));
}

static void ovc_dispatch_test_destroy_drains_callback(
    OvStorage_LayerHandle *handle,
    const char *address)
{
    static const uint8_t payload[] = "drain me";
    OvStorage_WriteOptions options;
    ovc_dispatch_test_blocking_callback callback;
    ovc_dispatch_test_destroy destroy;
    ovc_thread thread;
    bool closing;

    memset(&options, 0, sizeof(options));
    ovc_dispatch_test_blocking_callback_init(&callback);
    ovstorage_write(handle,
                    address,
                    payload,
                    sizeof(payload) - 1,
                    &options,
                    NULL,
                    ovc_dispatch_test_blocking_info_complete,
                    &callback);
    ovc_dispatch_test_blocking_callback_wait(&callback);

    memset(&destroy, 0, sizeof(destroy));
    destroy.handle = handle;
    ovc_dispatch_test_sync(ovc_mutex_init(&destroy.mutex));
    ovc_dispatch_test_sync(ovc_cond_init(&destroy.changed));
    ovc_dispatch_test_sync(
        ovc_thread_create(&thread, ovc_dispatch_test_destroy_thread, &destroy));
    ovc_dispatch_test_sync(ovc_mutex_lock(&destroy.mutex));
    while (!destroy.started) {
        ovc_dispatch_test_sync(
            ovc_cond_wait(&destroy.changed, &destroy.mutex));
    }
    ovc_dispatch_test_sync(ovc_mutex_unlock(&destroy.mutex));

    do {
        ovc_dispatch_test_sync(ovc_mutex_lock(&handle->mutex));
        closing = handle->closing;
        ovc_dispatch_test_sync(ovc_mutex_unlock(&handle->mutex));
    } while (!closing);
    ovc_dispatch_test_sync(ovc_mutex_lock(&destroy.mutex));
    assert(!destroy.returned);
    ovc_dispatch_test_sync(ovc_mutex_unlock(&destroy.mutex));

    ovc_dispatch_test_blocking_callback_release(&callback);
    ovc_dispatch_test_sync(ovc_thread_join(&thread));
    ovc_dispatch_test_sync(ovc_mutex_lock(&destroy.mutex));
    assert(destroy.returned);
    ovc_dispatch_test_sync(ovc_mutex_unlock(&destroy.mutex));
    ovc_dispatch_test_blocking_callback_destroy(&callback);
    ovc_dispatch_test_sync(ovc_cond_destroy(&destroy.changed));
    ovc_dispatch_test_sync(ovc_mutex_destroy(&destroy.mutex));
}

/* Render a native temp-directory path as a `file://` root address ending in
 * `/`.
 *
 * NOT the same conversion as tests/cc/file_url.h, despite the shape.  That
 * helper also percent-encodes every byte per RFC 3986; this one does not,
 * because the paths it sees come from `ovc_temp_dir_create` under a root
 * this suite controls.  Do not read the two as interchangeable.  The
 * duplication is deliberate: this is shipped source and must not include a
 * test header.
 *
 * On Win32 a drive path needs the third slash after `file://` and `\` is a
 * path separator that becomes `/`.  A UNC root is refused outright rather
 * than converted -- see the check below.  On POSIX the path is already
 * rooted at `/` and a `\` in it is an ordinary filename byte, so nothing
 * is rewritten.
 *
 * Returns what snprintf(3) returns for the whole address. */
static int ovc_dispatch_test_root_url(char *out,
                                      size_t out_size,
                                      const char *directory)
{
#if defined(_WIN32)
    int written;
    size_t index;

    /* A UNC root has no `file://` spelling this backend accepts: the parser
     * reads the leading `//` as an authority and refuses a non-empty one,
     * and the Win32 native-path normalizer takes drive-letter roots only.
     * Refuse it here rather than emit an address that fails downstream --
     * the same decision the cc-test helper and the shipped examples make. */
    if (directory[0] == '\\' && directory[1] == '\\') {
        (void)fprintf(stderr,
                      "the temporary root is a UNC path (%s); this suite "
                      "needs a local-drive TMP/TEMP\n",
                      directory);
        return -1;
    }
    written = snprintf(out, out_size, "file:///%s/", directory);
    if (written < 0 || (size_t)written >= out_size) {
        return written;
    }
    /* Only the path component was just written, so every `\` in `out` came
     * from `directory`. */
    for (index = 0; out[index] != '\0'; ++index) {
        if (out[index] == '\\') {
            out[index] = '/';
        }
    }
    return written;
#else
    return snprintf(out, out_size, "file://%s/", directory);
#endif
}

int main(void)
{
    static const uint8_t payload[] = "the second stack is still alive";
    char directory_a[OVC_TEMP_DIR_PATH_MAX];
    char directory_b[OVC_TEMP_DIR_PATH_MAX];
    char root_a[1024];
    char root_b[1024];
    char object_a[1024];
    char object_b[1024];
    char native_object_b[1024];
    OvStorage_LayerHandle *stack_a;
    OvStorage_LayerHandle *stack_b;
    int written;

    assert(ovc_dispatch_plugin_code_from_status(
               OvStorage_Status_ObjectModified) ==
           OvStoragePlugin_ErrorCode_ObjectModified);
    assert(ovc_dispatch_plugin_code_from_status(
               OvStorage_Status_NoRoute) ==
           OvStoragePlugin_ErrorCode_NoRoute);
    assert(ovc_temp_dir_create("ovstorage-dispatch-a",
                               directory_a,
                               sizeof(directory_a)) == 0);
    assert(ovc_temp_dir_create("ovstorage-dispatch-b",
                               directory_b,
                               sizeof(directory_b)) == 0);
    written = ovc_dispatch_test_root_url(root_a, sizeof(root_a), directory_a);
    assert(written > 0 && (size_t)written < sizeof(root_a));
    written = ovc_dispatch_test_root_url(root_b, sizeof(root_b), directory_b);
    assert(written > 0 && (size_t)written < sizeof(root_b));
    written = snprintf(object_a, sizeof(object_a), "%sdrain.bin", root_a);
    assert(written > 0 && (size_t)written < sizeof(object_a));
    written = snprintf(object_b, sizeof(object_b), "%sround-trip.bin", root_b);
    assert(written > 0 && (size_t)written < sizeof(object_b));

    stack_a = ovc_dispatch_test_build_file_stack(root_a, 3);
    stack_b = ovc_dispatch_test_build_file_stack(root_b, 3);
    assert(ovc_runtime_worker_count() == 3);
    ovc_dispatch_test_destroy_drains_callback(stack_a, object_a);
    assert(ovc_runtime_worker_count() == 3);
    written = snprintf(native_object_b,
                       sizeof(native_object_b),
                       "%s%cround-trip.bin",
                       directory_b,
                       OVC_PATH_SEPARATOR);
    assert(written > 0 && (size_t)written < sizeof(native_object_b));
    ovc_dispatch_test_round_trip(stack_b,
                                 root_b,
                                 object_b,
                                 native_object_b,
                                 payload,
                                 sizeof(payload) - 1);
    ovc_dispatch_test_fake_io(native_object_b,
                              payload,
                              sizeof(payload) - 1);
    ovc_dispatch_test_namespace_ops(stack_b,
                                    root_b,
                                    object_b,
                                    payload,
                                    sizeof(payload) - 1);
    assert(ovc_runtime_worker_count() == 3);
    ovstorage_layer_handle_destroy(stack_b);
    assert(ovc_runtime_worker_count() == 3);

    written = snprintf(object_a,
                       sizeof(object_a),
                       "%s%cdrain.bin",
                       directory_a,
                       OVC_PATH_SEPARATOR);
    assert(written > 0 && (size_t)written < sizeof(object_a));
    written = snprintf(object_b,
                       sizeof(object_b),
                       "%s%cround-trip.bin",
                       directory_b,
                       OVC_PATH_SEPARATOR);
    assert(written > 0 && (size_t)written < sizeof(object_b));
    assert(unlink(object_a) == 0);
    assert(unlink(object_b) == 0);
    assert(rmdir(directory_a) == 0);
    assert(rmdir(directory_b) == 0);
    return 0;
}

#endif /* OVC_DISPATCH_TEST_MAIN */
