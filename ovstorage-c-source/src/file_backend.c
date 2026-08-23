/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Built-in pure-C file Layer.
 */

#include "internal.h"

#include "ovstorage_defaults.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#include <process.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define OVC_FILE_KIND "file"
#define OVC_FILE_DISPLAY_NAME "Local files"
#define OVC_FILE_DESCRIPTION "Read and write local file:// URLs"
#define OVC_FILE_DEFAULT_CONNECTION_NAME "File"
#define OVC_FILE_TEMP_ATTEMPTS 16U
#define OVC_FILE_IO_CHUNK_SIZE (1024U * 1024U)
#define OVC_FILE_MIN_WATCH_POLL_MS UINT64_C(10)
#define OVC_FILE_WATCH_WAIT_CHUNK_NS UINT64_C(86400000000000)
#define OVC_FILE_METADATA_DIRECTORY ".ovstorage-meta"
#define OVC_FILE_METADATA_SUFFIX ".meta"

#if defined(_WIN32)
static const char *ovc_file_strerror(int error)
{
    static __declspec(thread) char message[256];

    if (strerror_s(message, sizeof(message), error) != 0) {
        (void)snprintf(message, sizeof(message), "system error %d", error);
    }
    return message;
}
#else
#define ovc_file_strerror(error) strerror(error)
#endif

/* OvStoragePlugin_EffectivePermissions bit values (frozen ABI contract). */
#define OVC_FILE_PERMISSION_READ (UINT32_C(1) << 0)
#define OVC_FILE_PERMISSION_WRITE (UINT32_C(1) << 1)
#define OVC_FILE_PERMISSION_DELETE (UINT32_C(1) << 2)
#define OVC_FILE_PERMISSION_UPDATE_METADATA (UINT32_C(1) << 3)
#define OVC_FILE_PERMISSION_ALL                                               \
    (OVC_FILE_PERMISSION_READ | OVC_FILE_PERMISSION_WRITE |                   \
     OVC_FILE_PERMISSION_DELETE | OVC_FILE_PERMISSION_UPDATE_METADATA)

typedef struct ovc_file_connection {
    char *id;
    char *root_url;
    char *root_path;
    char *canonical_root;
    char *display_name;
    bool persisted;
    int64_t last_probed_unix_ms;
} ovc_file_connection;

typedef struct ovc_file_layer {
    ovc_ref_count references;
    OvStoragePlugin_LayerVTableV1 vtable;
    ovc_mutex mutex;
    char *name;
    ovc_file_connection *connections;
    size_t connection_count;
    size_t connection_capacity;
} ovc_file_layer;

typedef struct ovc_file_stat {
    uint64_t size;
    int64_t mtime_unix_ms;
    int64_t mtime_unix_nanos;
    bool is_directory;
    bool is_regular;
    /* Mirrors Rust std's Permissions::readonly(): no write permission bit at
     * all on POSIX, FILE_ATTRIBUTE_READONLY on Win32.  check_access and
     * effective_permissions derive their reference-model answers from this. */
    bool readonly;
} ovc_file_stat;

typedef enum ovc_file_task_kind {
    OVC_FILE_TASK_STAT = 0,
    OVC_FILE_TASK_READ = 1,
    OVC_FILE_TASK_WRITE = 2,
    OVC_FILE_TASK_LIST = 3,
    OVC_FILE_TASK_ADD_CONNECTION = 4,
    OVC_FILE_TASK_REMOVE_CONNECTION = 5,
    OVC_FILE_TASK_UPDATE_CREDENTIALS = 6,
    OVC_FILE_TASK_DELETE = 7,
    OVC_FILE_TASK_COPY = 8,
    OVC_FILE_TASK_RENAME = 9,
    OVC_FILE_TASK_UPDATE_METADATA = 10,
    OVC_FILE_TASK_CHECK_ACCESS = 11,
    OVC_FILE_TASK_MATERIALIZE = 12,
    OVC_FILE_TASK_LIST_VERSIONS = 13,
    OVC_FILE_TASK_GET_LATEST_VERSION = 14,
    OVC_FILE_TASK_CREATE_DIRECTORY = 15,
    OVC_FILE_TASK_DELETE_DIRECTORY = 16,
    OVC_FILE_TASK_ROOT_INFO_FOR = 17,
    OVC_FILE_TASK_LIST_ADDRESS_ROOTS = 18,
    OVC_FILE_TASK_LIST_CONNECTIONS = 19
} ovc_file_task_kind;

typedef struct ovc_file_task {
    ovc_file_task_kind kind;
    ovc_file_layer *layer;
    OvStoragePlugin_OnComplete on_complete;
    void *user_data;
    OvStoragePlugin_CancelTokenFFI cancel;
    bool has_cancel;
    char *address;
    union {
        struct {
            bool full_metadata;
        } stat;
        struct {
            char *if_match;
            bool has_range;
            uint64_t range_start;
            bool has_range_end;
            uint64_t range_end;
        } read;
        struct {
            uint8_t *bytes;
            size_t len;
            OvStoragePlugin_IfDestExistsTag if_dest;
            char *match_etag;
            OvStoragePlugin_KeyValueList user_metadata;
        } write;
        struct {
            bool recursive;
            bool full_metadata;
            bool has_max_results;
            uint32_t max_results;
            char *page_token;
        } list;
        struct {
            char *if_match;
        } delete_;
        struct {
            char *source;
            char *destination;
            char *if_source;
            OvStoragePlugin_IfDestExistsTag if_dest;
            char *match_etag;
            char *message;
        } transfer;
        struct {
            char *if_match;
            OvStoragePlugin_KeyValueList set;
            OvStoragePlugin_List_Str remove;
            char *message;
        } update_metadata;
        struct {
            OvStoragePlugin_AccessOps operations;
        } check_access;
        struct {
            bool has_max_results;
            uint32_t max_results;
            char *page_token;
        } list_versions;
        struct {
            char *target;
            char *backend_kind;
            char *root;
            char *display_name;
            bool persisted;
        } add_connection;
        struct {
            char *target;
            char *id;
        } connection_key;
    } payload;
} ovc_file_task;

typedef struct ovc_file_item_vector {
    OvStoragePlugin_ObjectInfo *items;
    size_t len;
    size_t capacity;
} ovc_file_item_vector;

typedef struct ovc_file_watch_entry {
    char *address;
    ovc_file_stat info;
    bool has_metadata_mtime;
    int64_t metadata_mtime_unix_nanos;
} ovc_file_watch_entry;

typedef struct ovc_file_watch_snapshot {
    ovc_file_watch_entry *items;
    size_t len;
    size_t capacity;
} ovc_file_watch_snapshot;

typedef struct ovc_file_watch_change {
    char *address;
    OvStoragePlugin_ChangeKind kind;
    bool has_current;
    ovc_file_stat current;
} ovc_file_watch_change;

typedef struct ovc_file_watch_changes {
    ovc_file_watch_change *items;
    size_t len;
    size_t capacity;
    size_t next;
} ovc_file_watch_changes;

typedef struct ovc_file_watcher {
    ovc_file_layer *layer;
    char *path;
    char *address;
    bool recursive;
    bool include_metadata_changes;
    uint64_t poll_interval_ms;
    bool emit_lapsed;
    ovc_file_watch_snapshot snapshot;
    ovc_file_watch_changes pending;
    ovc_mutex mutex;
    ovc_cond changed;
    bool canceled;
    bool exhausted;
    OvStoragePlugin_CancelTokenFFI cancel;
    bool has_cancel;
    uint64_t cancel_subscription;
#if defined(OVC_FILE_BACKEND_TEST_MAIN)
    ovc_completion_latch *test_wait_entered;
#endif
} ovc_file_watcher;

/* ------------------------------------------------------------------------- */
/* Allocation and ABI-value ownership helpers.
 *
 * Two allocator families coexist here, split by ownership role:
 *
 *   - Values that cross the plugin ABI use ovc_abi_alloc/ovc_abi_free.
 *     Everything this Layer RETURNS to the dispatcher (errors, results and
 *     the strings/lists nested in them, stream shells and stream items) is
 *     minted with the ABI allocator because the dispatcher reclaims it with
 *     ovc_abi_free.  Every request payload this Layer ADOPTS from a moved
 *     request (addresses, bodies, metadata pairs, config strings) was minted
 *     by the dispatcher with ovc_abi_alloc and is released here with
 *     ovc_abi_free — that is what the OvStoragePlugin_* clear helpers below
 *     do.
 *
 *   - Host-internal allocations (native paths, task structs, watcher
 *     bookkeeping, temp names) never cross the ABI and stay on plain
 *     malloc/free via ovc_file_allocate/ovc_file_callocate.
 *
 * ovc_file_abi_allocate/ovc_file_abi_callocate keep the same abort-on-OOM
 * policy as their host-internal twins; they cover small fixed-size mints
 * (including the error struct itself, which has no failure channel: a NULL
 * error means success).  Large fallible buffers call ovc_abi_alloc directly
 * and surface ResourceExhausted. */

static void *ovc_file_allocate(size_t byte_count)
{
    void *allocation;

    allocation = malloc(byte_count == 0 ? 1 : byte_count);
    if (allocation == NULL) {
        abort();
    }
    return allocation;
}

static void *ovc_file_callocate(size_t count, size_t item_size)
{
    void *allocation;

    if (count != 0 && item_size > SIZE_MAX / count) {
        abort();
    }
    allocation = calloc(count == 0 ? 1 : count, item_size);
    if (allocation == NULL) {
        abort();
    }
    return allocation;
}

static void *ovc_file_abi_allocate(size_t byte_count)
{
    void *allocation;

    allocation = ovc_abi_alloc(byte_count);
    if (allocation == NULL) {
        abort();
    }
    return allocation;
}

static void *ovc_file_abi_callocate(size_t count, size_t item_size)
{
    void *allocation;
    size_t total;

    if (count != 0 && item_size > SIZE_MAX / count) {
        abort();
    }
    total = count * item_size;
    allocation = ovc_file_abi_allocate(total);
    memset(allocation, 0, total == 0 ? 1 : total);
    return allocation;
}

static char *ovc_file_string_duplicate(const char *value)
{
    size_t length;
    char *copy;

    if (value == NULL) {
        return NULL;
    }
    length = strlen(value);
    if (length == SIZE_MAX) {
        abort();
    }
    copy = (char *)ovc_file_allocate(length + 1);
    memcpy(copy, value, length + 1);
    return copy;
}

static bool ovc_file_slice_is_c_string(const OvStoragePlugin_Str *value)
{
    if (value == NULL || value->ptr == NULL) {
        return false;
    }
    return memchr(value->ptr, '\0', value->len) == NULL;
}

static char *ovc_file_string_from_slice(const OvStoragePlugin_Str *value)
{
    char *copy;

    if (!ovc_file_slice_is_c_string(value) || value->len == SIZE_MAX) {
        return NULL;
    }
    copy = (char *)ovc_file_allocate(value->len + 1);
    if (value->len != 0) {
        memcpy(copy, value->ptr, value->len);
    }
    copy[value->len] = '\0';
    return copy;
}

static OvStoragePlugin_Str ovc_file_owned_string(const char *value)
{
    OvStoragePlugin_Str out;

    out.len = value == NULL ? 0 : strlen(value);
    out.ptr = (char *)ovc_file_abi_allocate(out.len == 0 ? 1 : out.len);
    if (out.len != 0) {
        memcpy(out.ptr, value, out.len);
    } else {
        out.ptr[0] = '\0';
    }
    return out;
}

static OvStoragePlugin_Str ovc_file_owned_slice(const char *value,
                                                size_t length)
{
    OvStoragePlugin_Str out;

    out.ptr = (char *)ovc_file_abi_allocate(length == 0 ? 1 : length);
    out.len = length;
    if (length != 0) {
        memcpy(out.ptr, value, length);
    } else {
        out.ptr[0] = '\0';
    }
    return out;
}

/* Checked twin of ovc_file_owned_slice for request-proportional copies:
 * host-supplied input must surface ResourceExhausted instead of aborting
 * the process when memory runs out. */
static bool ovc_file_try_owned_slice(const char *value,
                                     size_t length,
                                     OvStoragePlugin_Str *out)
{
    out->ptr = (char *)ovc_abi_alloc(length == 0 ? 1 : length);
    out->len = 0;
    if (out->ptr == NULL) {
        return false;
    }
    out->len = length;
    if (length != 0) {
        memcpy(out->ptr, value, length);
    } else {
        out->ptr[0] = '\0';
    }
    return true;
}

static void ovc_file_str_clear(OvStoragePlugin_Str *value)
{
    if (value == NULL) {
        return;
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static void ovc_file_bytes_clear(OvStoragePlugin_Bytes *value,
                                 bool secure)
{
    if (value == NULL) {
        return;
    }
    if (secure && value->ptr != NULL && value->len != 0) {
        ovc_secure_zero(value->ptr, value->len);
    }
    ovc_abi_free(value->ptr);
    value->ptr = NULL;
    value->len = 0;
}

static OvStoragePlugin_Error *ovc_file_error(
    OvStoragePlugin_ErrorCode code,
    const char *format,
    ...)
{
    char buffer[1024];
    int formatted;
    size_t length;
    va_list arguments;
    OvStoragePlugin_Error *error;

    va_start(arguments, format);
    formatted = vsnprintf(buffer, sizeof(buffer), format, arguments);
    va_end(arguments);
    if (formatted < 0) {
        buffer[0] = '\0';
    }
    buffer[sizeof(buffer) - 1] = '\0';
    length = strlen(buffer);

    error = (OvStoragePlugin_Error *)ovc_file_abi_callocate(1,
                                                            sizeof(*error));
    error->code = code;
    error->message_ptr =
        (char *)ovc_file_abi_allocate(length == 0 ? 1 : length);
    if (length != 0) {
        memcpy(error->message_ptr, buffer, length);
    } else {
        error->message_ptr[0] = '\0';
    }
    error->message_len = length;
    error->context = NULL;
    return error;
}

static void ovc_file_complete_error(
    OvStoragePlugin_OnComplete on_complete,
    void *user_data,
    OvStoragePlugin_Error *error)
{
    on_complete(OvStoragePlugin_FFI_STATUS_ERR,
                NULL,
                error,
                user_data);
}

static void ovc_file_complete_code(
    OvStoragePlugin_OnComplete on_complete,
    void *user_data,
    OvStoragePlugin_ErrorCode code,
    const char *message)
{
    ovc_file_complete_error(on_complete,
                            user_data,
                            ovc_file_error(code, "%s", message));
}

static OvStoragePlugin_ErrorCode ovc_file_errno_code(int native_error)
{
    switch (native_error) {
    case ENOENT:
    case ENOTDIR:
        return OvStoragePlugin_ErrorCode_NotFound;
    case EEXIST:
        return OvStoragePlugin_ErrorCode_AlreadyExists;
#ifdef EISDIR
    /* The Rust backend maps IsADirectory to NotFound (the Nucleus
     * InvalidPath precedent); keep the pure-C table identical. */
    case EISDIR:
        return OvStoragePlugin_ErrorCode_NotFound;
#endif
    case EACCES:
    case EPERM:
#ifdef EROFS
    case EROFS:
#endif
        return OvStoragePlugin_ErrorCode_PermissionDenied;
#ifdef ENOTEMPTY
    case ENOTEMPTY:
        return OvStoragePlugin_ErrorCode_DirectoryNotEmpty;
#endif
#ifdef ENOSPC
    case ENOSPC:
#endif
#ifdef EDQUOT
    case EDQUOT:
#endif
        return OvStoragePlugin_ErrorCode_ResourceExhausted;
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:
#endif
#ifdef ELOOP
    case ELOOP:
#endif
    case EINVAL:
        return OvStoragePlugin_ErrorCode_InvalidArgument;
#ifdef ECANCELED
    case ECANCELED:
        return OvStoragePlugin_ErrorCode_Cancelled;
#endif
    default:
        return OvStoragePlugin_ErrorCode_Transient;
    }
}

static OvStoragePlugin_Error *ovc_file_native_error(
    int native_error,
    const char *operation,
    const char *path)
{
    return ovc_file_error(ovc_file_errno_code(native_error),
                          "%s `%s`: %s",
                          operation,
                          path == NULL ? "" : path,
                          ovc_file_strerror(native_error));
}

/* Release an error this file minted but decided not to surface. Field
 * teardown is ovc_pval_error_clear's, so this surface stays correct for
 * fields the built-in backend does not populate today. */
static void ovc_file_error_destroy(OvStoragePlugin_Error *error)
{
    if (error == NULL) {
        return;
    }
    ovc_pval_error_clear(error);
    ovc_abi_free(error);
}

static void ovc_file_key_value_list_clear(
    OvStoragePlugin_KeyValueList *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->len; ++index) {
        ovc_file_str_clear(&list->ptr[index].key);
        ovc_file_str_clear(&list->ptr[index].value);
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

static void ovc_file_string_list_clear(OvStoragePlugin_List_Str *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->len; ++index) {
        ovc_file_str_clear(&list->ptr[index]);
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}

/* Request-proportional clone: the source sizes are host-controlled, so
 * allocation failure sets *out_of_memory (for a ResourceExhausted fail)
 * instead of aborting; a malformed source returns false without it. */
static bool ovc_file_key_value_list_clone(
    const OvStoragePlugin_KeyValueList *source,
    OvStoragePlugin_KeyValueList *out,
    bool *out_of_memory)
{
    size_t index;
    size_t count;

    memset(out, 0, sizeof(*out));
    if (source == NULL || (source->len != 0 && source->ptr == NULL)) {
        return false;
    }
    count = source->len == 0 ? 1 : source->len;
    if (count > SIZE_MAX / sizeof(*out->ptr)) {
        *out_of_memory = true;
        return false;
    }
    out->ptr = (OvStoragePlugin_KeyValuePair *)ovc_abi_alloc(
        count * sizeof(*out->ptr));
    if (out->ptr == NULL) {
        *out_of_memory = true;
        return false;
    }
    memset(out->ptr, 0, count * sizeof(*out->ptr));
    for (index = 0; index < source->len; ++index) {
        if (source->ptr[index].key.ptr == NULL ||
            source->ptr[index].value.ptr == NULL) {
            ovc_file_key_value_list_clear(out);
            return false;
        }
        if (!ovc_file_try_owned_slice(source->ptr[index].key.ptr,
                                      source->ptr[index].key.len,
                                      &out->ptr[index].key)) {
            ovc_file_key_value_list_clear(out);
            *out_of_memory = true;
            return false;
        }
        if (!ovc_file_try_owned_slice(source->ptr[index].value.ptr,
                                      source->ptr[index].value.len,
                                      &out->ptr[index].value)) {
            ovc_abi_free(out->ptr[index].key.ptr);
            out->ptr[index].key.ptr = NULL;
            ovc_file_key_value_list_clear(out);
            *out_of_memory = true;
            return false;
        }
        ++out->len;
    }
    return true;
}

/* Same host-controlled-size contract as ovc_file_key_value_list_clone. */
static bool ovc_file_string_list_clone(
    const OvStoragePlugin_List_Str *source,
    OvStoragePlugin_List_Str *out,
    bool *out_of_memory)
{
    size_t index;
    size_t count;

    memset(out, 0, sizeof(*out));
    if (source == NULL || (source->len != 0 && source->ptr == NULL)) {
        return false;
    }
    count = source->len == 0 ? 1 : source->len;
    if (count > SIZE_MAX / sizeof(*out->ptr)) {
        *out_of_memory = true;
        return false;
    }
    out->ptr = (OvStoragePlugin_Str *)ovc_abi_alloc(
        count * sizeof(*out->ptr));
    if (out->ptr == NULL) {
        *out_of_memory = true;
        return false;
    }
    memset(out->ptr, 0, count * sizeof(*out->ptr));
    for (index = 0; index < source->len; ++index) {
        if (source->ptr[index].ptr == NULL) {
            ovc_file_string_list_clear(out);
            return false;
        }
        if (!ovc_file_try_owned_slice(source->ptr[index].ptr,
                                      source->ptr[index].len,
                                      &out->ptr[index])) {
            ovc_file_string_list_clear(out);
            *out_of_memory = true;
            return false;
        }
        ++out->len;
    }
    return true;
}

static void ovc_file_config_value_clear(OvStoragePlugin_ConfigValue *value)
{
    if (value == NULL) {
        return;
    }
    if (value->tag == OvStoragePlugin_ConfigValueTag_String) {
        ovc_file_str_clear(&value->string_value);
    } else if (value->tag == OvStoragePlugin_ConfigValueTag_Toml) {
        ovc_file_str_clear(&value->toml_value);
    }
}

static void ovc_file_config_list_clear(
    OvStoragePlugin_List_ConnectionConfigEntry *list)
{
    size_t index;

    if (list == NULL) {
        return;
    }
    for (index = 0; index < list->len; ++index) {
        ovc_file_str_clear(&list->ptr[index].key);
        ovc_file_config_value_clear(&list->ptr[index].value);
    }
    ovc_abi_free(list->ptr);
    list->ptr = NULL;
    list->len = 0;
}




static void ovc_file_create_request_clear(
    OvStoragePlugin_CreateBackendRequest *request)
{
    if (request == NULL) {
        return;
    }
    ovc_file_str_clear(&request->kind);
    ovc_file_str_clear(&request->instance_id);
    ovc_file_config_list_clear(&request->config);
}


static void ovc_file_connection_key_clear(
    OvStoragePlugin_ConnectionKey *key)
{
    if (key == NULL) {
        return;
    }
    ovc_file_str_clear(&key->target);
    ovc_file_str_clear(&key->id);
}


static void ovc_file_object_info_clear(OvStoragePlugin_ObjectInfo *info)
{
    size_t index;

    if (info == NULL) {
        return;
    }
    ovc_file_str_clear(&info->address);
    if (info->etag.present) {
        ovc_file_str_clear(&info->etag.value);
    }
    if (info->version.present) {
        ovc_file_str_clear(&info->version.value);
    }
    for (index = 0; index < info->checksums.len; ++index) {
        ovc_file_str_clear(&info->checksums.ptr[index].algorithm.token);
        ovc_file_bytes_clear(&info->checksums.ptr[index].bytes, false);
    }
    ovc_abi_free(info->checksums.ptr);
    if (info->system_metadata.present) {
        ovc_file_key_value_list_clear(&info->system_metadata.value);
    }
    if (info->user_metadata.present) {
        ovc_file_key_value_list_clear(&info->user_metadata.value);
    }
    if (info->modified_by.present) {
        ovc_file_str_clear(&info->modified_by.value);
    }
    memset(info, 0, sizeof(*info));
}

#if defined(OVC_FILE_BACKEND_TEST_MAIN)
static void ovc_file_connection_ffi_clear(
    OvStoragePlugin_Connection *connection)
{
    size_t index;

    if (connection == NULL) {
        return;
    }
    ovc_file_str_clear(&connection->id.id);
    ovc_file_str_clear(&connection->backend_kind);
    ovc_file_str_clear(&connection->display_name);
    if (connection->source.tag ==
        OvStoragePlugin_ConnectionSourceTag_BrokerDelivered) {
        ovc_file_str_clear(
            &connection->source.broker_delivered.broker_principal);
    }
    for (index = 0; index < connection->current_addresses.len; ++index) {
        ovc_file_str_clear(&connection->current_addresses.ptr[index]);
    }
    ovc_abi_free(connection->current_addresses.ptr);
    if (connection->auth_state.tag ==
        OvStoragePlugin_ConnectionAuthStateTag_AwaitingAuth) {
        if (connection->auth_state.awaiting_auth.reason.tag ==
            OvStoragePlugin_AuthReasonTag_Unknown) {
            ovc_file_str_clear(
                &connection->auth_state.awaiting_auth.reason.unknown_details);
        }
    } else if (connection->auth_state.tag ==
               OvStoragePlugin_ConnectionAuthStateTag_AuthFailed) {
        ovc_file_str_clear(
            &connection->auth_state.auth_failed.error_message);
    }
    ovc_file_key_value_list_clear(&connection->user_metadata);
    memset(connection, 0, sizeof(*connection));
}
#endif

/* ------------------------------------------------------------------------- */
/* Descriptor, capabilities, connection, and root-info encoders. */

static OvStoragePlugin_Capabilities ovc_file_capabilities(void)
{
    OvStoragePlugin_Capabilities capabilities;

    memset(&capabilities, 0, sizeof(capabilities));
    capabilities.supports_if_match_write = true;
    capabilities.supports_no_overwrite_write = true;
    capabilities.supports_native_metadata_patch = true;
    capabilities.writes_are_atomic = true;
    capabilities.supports_copy = true;
    capabilities.supports_rename = true;
    capabilities.supports_server_side_copy = true;
    capabilities.supports_server_side_rename = true;
    /* rename(2) is atomic on one filesystem.  EXDEV deliberately falls back
     * to copy+delete below, so the Layer cannot promise atomicity globally. */
    capabilities.supports_atomic_rename = false;
    capabilities.has_real_directories = true;
    capabilities.supports_write = true;
    capabilities.supports_delete = true;
    capabilities.supports_list = true;
    capabilities.supports_recursive_list = true;
    capabilities.populates_subdirectory_metadata = true;
    capabilities.supports_create_directory = true;
    capabilities.supports_delete_directory = true;
    capabilities.supports_version_listing = true;
    capabilities.version_list_order.present = true;
    capabilities.version_list_order.value =
        OvStoragePlugin_VersionListOrder_Newest;
    capabilities.populates_effective_permissions_on_stat = true;
    capabilities.supports_access_check = true;
    capabilities.supports_watch_directory = true;
    capabilities.watch_directory_kinds.created = true;
    capabilities.watch_directory_kinds.modified = true;
    capabilities.watch_directory_kinds.deleted = true;
    capabilities.watch_directory_kinds.metadata_changed = true;
    return capabilities;
}

static void ovc_file_descriptor_fill(
    OvStoragePlugin_LayerKindDescriptor *out)
{
    OvStoragePlugin_ConfigField *root;

    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->layer_type = OvStoragePlugin_LayerType_Backend;
    out->accepts_connections = true;
    out->auth_capable = false;
    /* A write's user_metadata is kept in this backend's sidecar and returned
       by stat, so a host may compose an attribution layer over this branch. */
    out->supports_user_metadata = true;
    out->kind = ovc_file_owned_string(OVC_FILE_KIND);
    out->display_name = ovc_file_owned_string(OVC_FILE_DISPLAY_NAME);
    out->description.present = true;
    out->description.value = ovc_file_owned_string(OVC_FILE_DESCRIPTION);

    out->config_schema.ptr = (OvStoragePlugin_ConfigField *)
        ovc_file_abi_callocate(1, sizeof(*out->config_schema.ptr));
    out->config_schema.len = 1;
    root = &out->config_schema.ptr[0];
    root->key = ovc_file_owned_string("root");
    root->display_name = ovc_file_owned_string("Root");
    root->kind.tag = OvStoragePlugin_ConfigFieldKindTag_Url;
    root->required = true;
    root->help.present = true;
    root->help.value = ovc_file_owned_string(
        "file:// root or absolute filesystem path exposed by this connection");
    root->example.present = true;
    root->example.value = ovc_file_owned_string("file:///tmp/ovstorage/");

    out->credential_schema.ptr = (OvStoragePlugin_CredentialField *)
        ovc_file_abi_allocate(sizeof(*out->credential_schema.ptr));
    out->credential_schema.len = 0;
    out->credential_methods.ptr = (OvStoragePlugin_CredentialMethod *)
        ovc_file_abi_allocate(sizeof(*out->credential_methods.ptr));
    out->credential_methods.len = 0;
}

#if defined(OVC_FILE_BACKEND_TEST_MAIN)
static void ovc_file_descriptor_clear(
    OvStoragePlugin_LayerKindDescriptor *descriptor)
{
    size_t index;

    if (descriptor == NULL) {
        return;
    }
    ovc_file_str_clear(&descriptor->kind);
    ovc_file_str_clear(&descriptor->display_name);
    if (descriptor->description.present) {
        ovc_file_str_clear(&descriptor->description.value);
    }
    for (index = 0; index < descriptor->config_schema.len; ++index) {
        OvStoragePlugin_ConfigField *field;

        field = &descriptor->config_schema.ptr[index];
        ovc_file_str_clear(&field->key);
        ovc_file_str_clear(&field->display_name);
        if (field->kind.tag == OvStoragePlugin_ConfigFieldKindTag_Enum) {
            size_t choice;

            for (choice = 0;
                 choice < field->kind.enum_source.static_choices.len;
                 ++choice) {
                ovc_file_str_clear(
                    &field->kind.enum_source.static_choices.ptr[choice]);
            }
            ovc_abi_free(field->kind.enum_source.static_choices.ptr);
        }
        if (field->default_.present) {
            ovc_file_config_value_clear(&field->default_.value);
        }
        if (field->help.present) {
            ovc_file_str_clear(&field->help.value);
        }
        if (field->example.present) {
            ovc_file_str_clear(&field->example.value);
        }
        if (field->group.present) {
            ovc_file_str_clear(&field->group.value);
        }
    }
    ovc_abi_free(descriptor->config_schema.ptr);
    for (index = 0; index < descriptor->credential_schema.len; ++index) {
        OvStoragePlugin_CredentialField *field;

        field = &descriptor->credential_schema.ptr[index];
        ovc_file_str_clear(&field->key);
        ovc_file_str_clear(&field->display_name);
        if (field->default_.present) {
            ovc_file_str_clear(&field->default_.value);
        }
        if (field->help.present) {
            ovc_file_str_clear(&field->help.value);
        }
    }
    ovc_abi_free(descriptor->credential_schema.ptr);
    for (index = 0; index < descriptor->credential_methods.len; ++index) {
        OvStoragePlugin_CredentialMethod *method;
        size_t field_index;

        method = &descriptor->credential_methods.ptr[index];
        ovc_file_str_clear(&method->key);
        ovc_file_str_clear(&method->display_name);
        for (field_index = 0; field_index < method->fields.len;
             ++field_index) {
            ovc_file_str_clear(&method->fields.ptr[field_index]);
        }
        ovc_abi_free(method->fields.ptr);
        if (method->help.present) {
            ovc_file_str_clear(&method->help.value);
        }
    }
    ovc_abi_free(descriptor->credential_methods.ptr);
    if (descriptor->icon.present) {
        ovc_file_bytes_clear(&descriptor->icon.value, false);
    }
    memset(descriptor, 0, sizeof(*descriptor));
}
#endif

static void ovc_file_connection_destroy(ovc_file_connection *connection)
{
    if (connection == NULL) {
        return;
    }
    free(connection->id);
    free(connection->root_url);
    free(connection->root_path);
    free(connection->canonical_root);
    free(connection->display_name);
    memset(connection, 0, sizeof(*connection));
}

static bool ovc_file_connection_clone_native(
    const ovc_file_connection *source,
    ovc_file_connection *out)
{
    memset(out, 0, sizeof(*out));
    out->id = ovc_file_string_duplicate(source->id);
    out->root_url = ovc_file_string_duplicate(source->root_url);
    out->root_path = ovc_file_string_duplicate(source->root_path);
    out->canonical_root = ovc_file_string_duplicate(source->canonical_root);
    out->display_name = ovc_file_string_duplicate(source->display_name);
    out->persisted = source->persisted;
    out->last_probed_unix_ms = source->last_probed_unix_ms;
    return true;
}

static void ovc_file_connection_to_ffi(
    const ovc_file_connection *source,
    OvStoragePlugin_Connection *out)
{
    memset(out, 0, sizeof(*out));
    out->id.id = ovc_file_owned_string(source->id);
    out->backend_kind = ovc_file_owned_string(OVC_FILE_KIND);
    out->display_name = ovc_file_owned_string(source->display_name);
    out->source.tag = OvStoragePlugin_ConnectionSourceTag_Runtime;
    out->source.runtime.persisted = source->persisted;
    out->capabilities = ovc_file_capabilities();
    out->current_addresses.ptr = (OvStoragePlugin_Str *)
        ovc_file_abi_callocate(1, sizeof(*out->current_addresses.ptr));
    out->current_addresses.len = 1;
    out->current_addresses.ptr[0] = ovc_file_owned_string(source->root_url);
    out->auth_state.tag = OvStoragePlugin_ConnectionAuthStateTag_Anonymous;
    out->last_probed_unix_ms.present = true;
    out->last_probed_unix_ms.value = source->last_probed_unix_ms;
    out->user_metadata.ptr = (OvStoragePlugin_KeyValuePair *)
        ovc_file_abi_allocate(sizeof(*out->user_metadata.ptr));
    out->user_metadata.len = 0;
}

static void ovc_file_root_info_fill(
    const ovc_file_connection *connection,
    const char *owning_name,
    OvStoragePlugin_RootInfo *out)
{
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->root = ovc_file_owned_string(connection->root_url);
    out->layer_kind = ovc_file_owned_string(OVC_FILE_KIND);
    out->connection_id.present = true;
    out->connection_id.value.id = ovc_file_owned_string(connection->id);
    /* A connection-owned root reports the layer INSTANCE name connection ops
     * route by (`self.name()` in the Rust backend; the same `layer->name`
     * `ovc_file_layer_owned_targets` reports) — NOT the descriptor kind. */
    out->owning_target.present = true;
    out->owning_target.value = ovc_file_owned_string(owning_name);
    out->capabilities = ovc_file_capabilities();
    out->range_read_strategy = OvStoragePlugin_RangeReadStrategy_Native;
    out->source.tag = OvStoragePlugin_RouteSourceTag_ConnectionContributed;
    out->source.connection_id.present = true;
    out->source.connection_id.value.id =
        ovc_file_owned_string(connection->id);
    out->visible = true;
    out->visibility = OvStoragePlugin_AddressVisibility_Visible;
    out->user_metadata.ptr = (OvStoragePlugin_KeyValuePair *)
        ovc_file_abi_allocate(sizeof(*out->user_metadata.ptr));
    out->user_metadata.len = 0;
}

#if defined(OVC_FILE_BACKEND_TEST_MAIN)
static void ovc_file_root_info_clear(OvStoragePlugin_RootInfo *root)
{
    if (root == NULL) {
        return;
    }
    ovc_file_str_clear(&root->root);
    if (root->display_name.present) {
        ovc_file_str_clear(&root->display_name.value);
    }
    ovc_file_str_clear(&root->layer_kind);
    if (root->connection_id.present) {
        ovc_file_str_clear(&root->connection_id.value.id);
    }
    if (root->source.connection_id.present) {
        ovc_file_str_clear(&root->source.connection_id.value.id);
    }
    if (root->source.broker_principal.present) {
        ovc_file_str_clear(&root->source.broker_principal.value);
    }
    if (root->source.alias_to.present) {
        ovc_file_str_clear(&root->source.alias_to.value);
    }
    if (root->source.alias_source.present &&
        root->source.alias_source.value.broker_principal.present) {
        ovc_file_str_clear(
            &root->source.alias_source.value.broker_principal.value);
    }
    if (root->alias_state.present &&
        root->alias_state.value.reason.present) {
        ovc_file_str_clear(&root->alias_state.value.reason.value);
    }
    if (root->icon.present) {
        ovc_file_bytes_clear(&root->icon.value, false);
    }
    ovc_file_key_value_list_clear(&root->user_metadata);
    if (root->owning_target.present) {
        ovc_file_str_clear(&root->owning_target.value);
    }
    memset(root, 0, sizeof(*root));
}
#endif

/* ------------------------------------------------------------------------- */
/* Native file operations.  Positioned data I/O uses the shared shims. */

#if defined(_WIN32)

static wchar_t *ovc_file_utf8_to_wide(const char *value)
{
    int count;
    wchar_t *wide;

    if (value == NULL) {
        errno = EINVAL;
        return NULL;
    }
    count = MultiByteToWideChar(CP_UTF8,
                                MB_ERR_INVALID_CHARS,
                                value,
                                -1,
                                NULL,
                                0);
    if (count <= 0) {
        ovc_win32_set_errno(GetLastError());
        return NULL;
    }
    if ((size_t)count > SIZE_MAX / sizeof(*wide)) {
        errno = ENOMEM;
        return NULL;
    }
    wide = (wchar_t *)malloc((size_t)count * sizeof(*wide));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8,
                            MB_ERR_INVALID_CHARS,
                            value,
                            -1,
                            wide,
                            count) <= 0) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return NULL;
    }
    return wide;
}

static int64_t ovc_file_win32_filetime_nanos(FILETIME value)
{
    ULARGE_INTEGER ticks;
    const uint64_t unix_epoch_ticks = UINT64_C(116444736000000000);
    uint64_t unix_ticks;

    ticks.LowPart = value.dwLowDateTime;
    ticks.HighPart = value.dwHighDateTime;
    if (ticks.QuadPart < unix_epoch_ticks) {
        return 0;
    }
    unix_ticks = ticks.QuadPart - unix_epoch_ticks;
    if (unix_ticks > (uint64_t)INT64_MAX / UINT64_C(100)) {
        return INT64_MAX;
    }
    return (int64_t)(unix_ticks * UINT64_C(100));
}

static void ovc_file_win32_info_to_stat(
    DWORD attributes,
    DWORD size_high,
    DWORD size_low,
    FILETIME mtime,
    ovc_file_stat *out)
{
    ULARGE_INTEGER size;

    memset(out, 0, sizeof(*out));
    size.HighPart = size_high;
    size.LowPart = size_low;
    out->size = size.QuadPart;
    out->is_directory =
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    out->is_regular = !out->is_directory &&
                      (attributes & FILE_ATTRIBUTE_DEVICE) == 0;
    out->readonly = (attributes & FILE_ATTRIBUTE_READONLY) != 0;
    out->mtime_unix_nanos = ovc_file_win32_filetime_nanos(mtime);
    out->mtime_unix_ms = out->mtime_unix_nanos / INT64_C(1000000);
}

static int ovc_file_native_stat_path(const char *path, ovc_file_stat *out)
{
    wchar_t *wide;
    WIN32_FILE_ATTRIBUTE_DATA data;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    if (!GetFileAttributesExW(wide, GetFileExInfoStandard, &data)) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    free(wide);
    ovc_file_win32_info_to_stat(data.dwFileAttributes,
                                data.nFileSizeHigh,
                                data.nFileSizeLow,
                                data.ftLastWriteTime,
                                out);
    return 0;
}

static int ovc_file_native_path_is_link(const char *path, bool *out_is_link)
{
    wchar_t *wide;
    DWORD attributes;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    attributes = GetFileAttributesW(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD native_error;

        native_error = GetLastError();
        free(wide);
        ovc_win32_set_errno(native_error);
        return -1;
    }
    free(wide);
    *out_is_link = (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    return 0;
}

static int ovc_file_native_fstat(ovc_file file, ovc_file_stat *out)
{
    BY_HANDLE_FILE_INFORMATION data;

    if (!GetFileInformationByHandle(file, &data)) {
        ovc_win32_set_errno(GetLastError());
        return -1;
    }
    ovc_file_win32_info_to_stat(data.dwFileAttributes,
                                data.nFileSizeHigh,
                                data.nFileSizeLow,
                                data.ftLastWriteTime,
                                out);
    return 0;
}

static ovc_file ovc_file_native_open_read(const char *path)
{
    wchar_t *wide;
    HANDLE handle;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return OVC_INVALID_FILE;
    }
    handle = CreateFileW(wide,
                         GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE |
                             FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return OVC_INVALID_FILE;
    }
    free(wide);
    return handle;
}

static ovc_file ovc_file_native_create_new(const char *path)
{
    wchar_t *wide;
    HANDLE handle;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return OVC_INVALID_FILE;
    }
    handle = CreateFileW(wide,
                         GENERIC_WRITE | GENERIC_READ,
                         FILE_SHARE_READ,
                         NULL,
                         CREATE_NEW,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return OVC_INVALID_FILE;
    }
    free(wide);
    return handle;
}

static int ovc_file_native_close(ovc_file file)
{
    if (CloseHandle(file)) {
        return 0;
    }
    ovc_win32_set_errno(GetLastError());
    return -1;
}

static int ovc_file_native_sync(ovc_file file)
{
    if (FlushFileBuffers(file)) {
        return 0;
    }
    ovc_win32_set_errno(GetLastError());
    return -1;
}

static int ovc_file_native_unlink(const char *path)
{
    wchar_t *wide;
    BOOL removed;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    removed = DeleteFileW(wide);
    if (!removed) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    free(wide);
    return 0;
}

static int ovc_file_native_rename_replace(const char *source,
                                          const char *destination)
{
    wchar_t *source_wide;
    wchar_t *destination_wide;
    BOOL moved;

    source_wide = ovc_file_utf8_to_wide(source);
    destination_wide = ovc_file_utf8_to_wide(destination);
    if (source_wide == NULL || destination_wide == NULL) {
        free(source_wide);
        free(destination_wide);
        return -1;
    }
    moved = MoveFileExW(source_wide,
                        destination_wide,
                        MOVEFILE_REPLACE_EXISTING |
                            MOVEFILE_WRITE_THROUGH);
    if (!moved) {
        DWORD error;

        error = GetLastError();
        free(source_wide);
        free(destination_wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    free(source_wide);
    free(destination_wide);
    return 0;
}

static int ovc_file_native_mkdir(const char *path)
{
    wchar_t *wide;
    BOOL created;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    created = CreateDirectoryW(wide, NULL);
    if (!created) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    free(wide);
    return 0;
}

static int ovc_file_native_rmdir(const char *path)
{
    wchar_t *wide;
    BOOL removed;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    removed = RemoveDirectoryW(wide);
    if (!removed) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    free(wide);
    return 0;
}

static int ovc_file_native_copy_permissions(const char *source,
                                            const char *destination)
{
    wchar_t *source_wide;
    wchar_t *destination_wide;
    DWORD attributes;
    DWORD preserved;

    source_wide = ovc_file_utf8_to_wide(source);
    destination_wide = ovc_file_utf8_to_wide(destination);
    if (source_wide == NULL || destination_wide == NULL) {
        free(source_wide);
        free(destination_wide);
        return -1;
    }
    attributes = GetFileAttributesW(source_wide);
    free(source_wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD native_error;

        native_error = GetLastError();
        free(destination_wide);
        ovc_win32_set_errno(native_error);
        return -1;
    }
    preserved = attributes &
                (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                 FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
                 FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    if (preserved == 0) {
        preserved = FILE_ATTRIBUTE_NORMAL;
    }
    if (!SetFileAttributesW(destination_wide, preserved)) {
        DWORD native_error;

        native_error = GetLastError();
        free(destination_wide);
        ovc_win32_set_errno(native_error);
        return -1;
    }
    free(destination_wide);
    return 0;
}

static int ovc_file_native_preserve_destination_permissions(
    const char *destination,
    const char *temporary)
{
    wchar_t *destination_wide;
    wchar_t *temporary_wide;
    DWORD attributes;
    DWORD preserved;

    destination_wide = ovc_file_utf8_to_wide(destination);
    temporary_wide = ovc_file_utf8_to_wide(temporary);
    if (destination_wide == NULL || temporary_wide == NULL) {
        free(destination_wide);
        free(temporary_wide);
        return -1;
    }
    attributes = GetFileAttributesW(destination_wide);
    free(destination_wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD native_error;

        native_error = GetLastError();
        free(temporary_wide);
        if (native_error == ERROR_FILE_NOT_FOUND ||
            native_error == ERROR_PATH_NOT_FOUND) {
            return 0;
        }
        ovc_win32_set_errno(native_error);
        return -1;
    }
    preserved = attributes &
                (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                 FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE |
                 FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    if (preserved == 0) {
        preserved = FILE_ATTRIBUTE_NORMAL;
    }
    if (!SetFileAttributesW(temporary_wide, preserved)) {
        DWORD native_error;

        native_error = GetLastError();
        free(temporary_wide);
        ovc_win32_set_errno(native_error);
        return -1;
    }
    free(temporary_wide);
    return 0;
}

static char *ovc_file_native_realpath(const char *path)
{
    wchar_t *wide;
    wchar_t *resolved;
    const wchar_t *without_device_prefix;
    HANDLE handle;
    DWORD needed;
    int utf8_count;
    char *utf8;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return NULL;
    }
    handle = CreateFileW(wide,
                         FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE |
                             FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS,
                         NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        ovc_win32_set_errno(GetLastError());
        return NULL;
    }
    needed = GetFinalPathNameByHandleW(handle,
                                       NULL,
                                       0,
                                       FILE_NAME_NORMALIZED |
                                           VOLUME_NAME_DOS);
    if (needed == 0) {
        DWORD error;

        error = GetLastError();
        CloseHandle(handle);
        ovc_win32_set_errno(error);
        return NULL;
    }
    if ((size_t)needed + 1 > SIZE_MAX / sizeof(*resolved)) {
        CloseHandle(handle);
        errno = ENOMEM;
        return NULL;
    }
    resolved = (wchar_t *)malloc(((size_t)needed + 1) * sizeof(*resolved));
    if (resolved == NULL) {
        CloseHandle(handle);
        return NULL;
    }
    if (GetFinalPathNameByHandleW(handle,
                                  resolved,
                                  needed + 1,
                                  FILE_NAME_NORMALIZED |
                                      VOLUME_NAME_DOS) == 0) {
        DWORD error;

        error = GetLastError();
        CloseHandle(handle);
        free(resolved);
        ovc_win32_set_errno(error);
        return NULL;
    }
    CloseHandle(handle);
    without_device_prefix = resolved;
    if (wcsncmp(resolved, L"\\\\?\\", 4) == 0) {
        without_device_prefix += 4;
    }
    utf8_count = WideCharToMultiByte(CP_UTF8,
                                     WC_ERR_INVALID_CHARS,
                                     without_device_prefix,
                                     -1,
                                     NULL,
                                     0,
                                     NULL,
                                     NULL);
    if (utf8_count <= 0) {
        DWORD error;

        error = GetLastError();
        free(resolved);
        ovc_win32_set_errno(error);
        return NULL;
    }
    utf8 = (char *)malloc((size_t)utf8_count);
    if (utf8 == NULL) {
        free(resolved);
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            without_device_prefix,
                            -1,
                            utf8,
                            utf8_count,
                            NULL,
                            NULL) <= 0) {
        DWORD error;

        error = GetLastError();
        free(resolved);
        free(utf8);
        ovc_win32_set_errno(error);
        return NULL;
    }
    free(resolved);
    return utf8;
}

static unsigned long ovc_file_process_id(void)
{
    return (unsigned long)_getpid();
}

#else

static int ovc_file_stat_from_posix(const struct stat *native,
                                    ovc_file_stat *out)
{
    int64_t seconds;
    long nanoseconds;

    if (native->st_size < 0) {
        errno = EIO;
        return -1;
    }
#if defined(__APPLE__)
    seconds = (int64_t)native->st_mtimespec.tv_sec;
    nanoseconds = native->st_mtimespec.tv_nsec;
#else
    seconds = (int64_t)native->st_mtim.tv_sec;
    nanoseconds = native->st_mtim.tv_nsec;
#endif
    if (nanoseconds < 0 || nanoseconds >= 1000000000L ||
        seconds > (INT64_MAX - nanoseconds) / INT64_C(1000000000) ||
        seconds < (INT64_MIN + nanoseconds) / INT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->size = (uint64_t)native->st_size;
    out->mtime_unix_nanos =
        seconds * INT64_C(1000000000) + (int64_t)nanoseconds;
    out->mtime_unix_ms = out->mtime_unix_nanos / INT64_C(1000000);
    out->is_directory = S_ISDIR(native->st_mode) != 0;
    out->is_regular = S_ISREG(native->st_mode) != 0;
    out->readonly =
        (native->st_mode & (mode_t)(S_IWUSR | S_IWGRP | S_IWOTH)) == 0;
    return 0;
}

static int ovc_file_native_stat_path(const char *path, ovc_file_stat *out)
{
    struct stat native;

    if (fstatat(AT_FDCWD, path, &native, 0) != 0) {
        return -1;
    }
    return ovc_file_stat_from_posix(&native, out);
}

static int ovc_file_native_path_is_link(const char *path, bool *out_is_link)
{
    struct stat native;

    if (fstatat(AT_FDCWD, path, &native, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }
    *out_is_link = S_ISLNK(native.st_mode) != 0;
    return 0;
}

/*
 * Classify `path` without following a final symlink: reports existence,
 * whether it is a symlink, and whether it is a real directory.  A missing
 * path (ENOENT/ENOTDIR) is reported as out_exists = false, not an error.
 * The sidecar sweep uses this so it can never descend through a link.
 */
static int ovc_file_native_lstat_kind(const char *path,
                                      bool *out_exists,
                                      bool *out_is_link,
                                      bool *out_is_dir)
{
    struct stat native;

    *out_exists = false;
    *out_is_link = false;
    *out_is_dir = false;
    if (fstatat(AT_FDCWD, path, &native, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        return -1;
    }
    *out_exists = true;
    *out_is_link = S_ISLNK(native.st_mode) != 0;
    *out_is_dir = S_ISDIR(native.st_mode) != 0;
    return 0;
}

static int ovc_file_native_fstat(ovc_file file, ovc_file_stat *out)
{
    struct stat native;

    if (fstat(file, &native) != 0) {
        return -1;
    }
    return ovc_file_stat_from_posix(&native, out);
}

static ovc_file ovc_file_native_open_read(const char *path)
{
    int flags;

    flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif
    return open(path, flags);
}

static ovc_file ovc_file_native_create_new(const char *path)
{
    int flags;

    flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    return open(path, flags, (mode_t)0666);
}

static int ovc_file_native_close(ovc_file file)
{
    /* POSIX leaves the descriptor state unspecified after close(2) returns
     * EINTR; retrying can close an unrelated descriptor that reused the
     * number. */
    return close(file);
}

static int ovc_file_native_sync(ovc_file file)
{
    int result;

    do {
        result = fsync(file);
    } while (result != 0 && errno == EINTR);
    return result;
}

static int ovc_file_native_unlink(const char *path)
{
    return unlinkat(AT_FDCWD, path, 0);
}

static int ovc_file_native_rename_replace(const char *source,
                                          const char *destination)
{
    return renameat(AT_FDCWD, source, AT_FDCWD, destination);
}

static int ovc_file_native_mkdir(const char *path)
{
    return mkdirat(AT_FDCWD, path, (mode_t)0777);
}

static int ovc_file_native_rmdir(const char *path)
{
    return unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

static int ovc_file_native_copy_permissions(const char *source,
                                            const char *destination)
{
    struct stat source_info;

    if (fstatat(AT_FDCWD, source, &source_info, 0) != 0) {
        return -1;
    }
    return fchmodat(AT_FDCWD,
                    destination,
                    source_info.st_mode & (mode_t)07777,
                    0);
}

static int ovc_file_native_preserve_destination_permissions(
    const char *destination,
    const char *temporary)
{
    struct stat destination_info;

    if (fstatat(AT_FDCWD, destination, &destination_info, 0) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        return -1;
    }
    return fchmodat(AT_FDCWD,
                    temporary,
                    destination_info.st_mode & (mode_t)07777,
                    0);
}

static char *ovc_file_native_realpath(const char *path)
{
    return realpath(path, NULL);
}

static unsigned long ovc_file_process_id(void)
{
    return (unsigned long)getpid();
}

#endif

static int ovc_file_native_sync_parent(const char *path)
{
#if defined(_WIN32)
    (void)path;
    /* MoveFileExW(MOVEFILE_WRITE_THROUGH) provides the Win32 commit barrier. */
    return 0;
#else
    char *parent;
    char *separator;
    int descriptor;
    int result;

    parent = ovc_file_string_duplicate(path);
    separator = strrchr(parent, '/');
    if (separator == NULL) {
        free(parent);
        errno = EINVAL;
        return -1;
    }
    if (separator == parent) {
        separator[1] = '\0';
    } else {
        *separator = '\0';
    }
    descriptor = open(parent, O_RDONLY
#ifdef O_CLOEXEC
                                      | O_CLOEXEC
#endif
#ifdef O_DIRECTORY
                                      | O_DIRECTORY
#endif
    );
    free(parent);
    if (descriptor < 0) {
        return -1;
    }
    result = ovc_file_native_sync(descriptor);
    {
        int saved_error;

        saved_error = errno;
        (void)ovc_file_native_close(descriptor);
        errno = saved_error;
    }
    return result;
#endif
}

/* ------------------------------------------------------------------------- */
/* file: URL parsing, native normalization, and configured-root containment. */

static int ovc_file_ascii_equal_nocase(const char *left,
                                       const char *right,
                                       size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        unsigned char a;
        unsigned char b;

        a = (unsigned char)left[index];
        b = (unsigned char)right[index];
        if (a >= 'A' && a <= 'Z') {
            a = (unsigned char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (unsigned char)(b - 'A' + 'a');
        }
        if (a != b) {
            return 0;
        }
    }
    return 1;
}

static int ovc_file_hex_value(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static char *ovc_file_normalize_native_path(const char *input)
{
    size_t length;
    size_t read_at;
    size_t write_at;
    size_t prefix_length;
    char *out;

    if (input == NULL || !ovc_path_is_absolute(input)) {
        errno = EINVAL;
        return NULL;
    }
    length = strlen(input);
    out = (char *)malloc(length + 2);
    if (out == NULL) {
        return NULL;
    }
    read_at = 0;
    write_at = 0;
    prefix_length = 0;

#if defined(_WIN32)
    if (length >= 3 && input[1] == ':' &&
        ovc_path_is_separator(input[2])) {
        out[write_at++] = input[0];
        out[write_at++] = ':';
        out[write_at++] = OVC_PATH_SEPARATOR;
        read_at = 3;
        prefix_length = write_at;
    } else {
        free(out);
        errno = EINVAL;
        return NULL;
    }
#else
    out[write_at++] = '/';
    read_at = 1;
    prefix_length = write_at;
#endif

    while (read_at < length) {
        size_t segment_start;
        size_t segment_length;

        while (read_at < length && ovc_path_is_separator(input[read_at])) {
            ++read_at;
        }
        segment_start = read_at;
        while (read_at < length && !ovc_path_is_separator(input[read_at])) {
            ++read_at;
        }
        segment_length = read_at - segment_start;
        if (segment_length == 0) {
            continue;
        }
        if (segment_length == 1 && input[segment_start] == '.') {
            continue;
        }
        if (segment_length == 2 && input[segment_start] == '.' &&
            input[segment_start + 1] == '.') {
            free(out);
            errno = EINVAL;
            return NULL;
        }
        if (write_at > prefix_length &&
            !ovc_path_is_separator(out[write_at - 1])) {
            out[write_at++] = OVC_PATH_SEPARATOR;
        }
        memcpy(out + write_at, input + segment_start, segment_length);
        write_at += segment_length;
    }
    if (write_at > prefix_length &&
        ovc_path_is_separator(out[write_at - 1])) {
        --write_at;
    }
    out[write_at] = '\0';
    return out;
}

static char *ovc_file_url_to_path(const char *url,
                                  OvStoragePlugin_Error **out_error)
{
    size_t length;
    size_t path_at;
    size_t index;
    char *decoded;
    size_t decoded_length;
    char *normalized;

    *out_error = NULL;
    if (url == NULL) {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                    "file URL is null");
        return NULL;
    }
    length = strlen(url);
    if (length < 6 || !ovc_file_ascii_equal_nocase(url, "file:", 5)) {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                    "address is not a file: URL");
        return NULL;
    }
    path_at = 5;
    if (length - path_at >= 2 && url[path_at] == '/' &&
        url[path_at + 1] == '/') {
        size_t authority_at;
        size_t authority_length;

        authority_at = path_at + 2;
        path_at = authority_at;
        while (path_at < length && url[path_at] != '/') {
            ++path_at;
        }
        authority_length = path_at - authority_at;
        if (authority_length != 0 &&
            !(authority_length == 9 &&
              ovc_file_ascii_equal_nocase(url + authority_at,
                                          "localhost",
                                          9))) {
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "file:// URL authority must be empty or localhost");
            return NULL;
        }
    }
    if (path_at >= length || url[path_at] != '/') {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                    "file URL path must be absolute");
        return NULL;
    }
    decoded = (char *)ovc_file_allocate(length - path_at + 1);
    decoded_length = 0;
    for (index = path_at; index < length; ++index) {
        unsigned char byte;

        if (url[index] == '?' || url[index] == '#') {
            free(decoded);
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "file URLs with query strings or fragments are unsupported");
            return NULL;
        }
        if (url[index] == '%') {
            int high;
            int low;

            if (length - index < 3 ||
                (high = ovc_file_hex_value(url[index + 1])) < 0 ||
                (low = ovc_file_hex_value(url[index + 2])) < 0) {
                free(decoded);
                *out_error = ovc_file_error(
                    OvStoragePlugin_ErrorCode_InvalidArgument,
                    "file URL contains an invalid percent escape");
                return NULL;
            }
            byte = (unsigned char)((high << 4) | low);
            index += 2;
        } else {
            byte = (unsigned char)url[index];
        }
        if (byte == 0) {
            free(decoded);
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "file URL contains an encoded NUL byte");
            return NULL;
        }
#if defined(_WIN32)
        if (byte == '/') {
            byte = '\\';
        }
#endif
        decoded[decoded_length++] = (char)byte;
    }
    decoded[decoded_length] = '\0';
#if defined(_WIN32)
    if (decoded_length >= 3 && decoded[0] == '\\' && decoded[2] == ':') {
        memmove(decoded, decoded + 1, decoded_length);
    }
#endif
    normalized = ovc_file_normalize_native_path(decoded);
    if (normalized == NULL) {
        int saved_error;

        saved_error = errno;
        free(decoded);
        *out_error = ovc_file_native_error(saved_error,
                                           "normalize file URL",
                                           url);
        return NULL;
    }
    free(decoded);
    return normalized;
}

static bool ovc_file_url_safe_byte(unsigned char byte)
{
    return (byte >= 'a' && byte <= 'z') ||
           (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' ||
           byte == '.' || byte == '~' || byte == '/' || byte == ':';
}

static char *ovc_file_path_to_url(const char *path, bool directory)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t length;
    size_t index;
    size_t encoded_length;
    size_t cursor;
    char *url;

    length = strlen(path);
    encoded_length = 7;
#if defined(_WIN32)
    encoded_length += 1;
#endif
    for (index = 0; index < length; ++index) {
        unsigned char byte;

        byte = (unsigned char)path[index];
#if defined(_WIN32)
        if (byte == '\\') {
            byte = '/';
        }
#endif
        encoded_length += ovc_file_url_safe_byte(byte) ? 1 : 3;
    }
    if (directory && (length == 0 ||
                      !ovc_path_is_separator(path[length - 1]))) {
        ++encoded_length;
    }
    if (encoded_length == SIZE_MAX) {
        abort();
    }
    url = (char *)ovc_file_allocate(encoded_length + 1);
    memcpy(url, "file://", 7);
    cursor = 7;
#if defined(_WIN32)
    url[cursor++] = '/';
#endif
    for (index = 0; index < length; ++index) {
        unsigned char byte;

        byte = (unsigned char)path[index];
#if defined(_WIN32)
        if (byte == '\\') {
            byte = '/';
        }
#endif
        if (ovc_file_url_safe_byte(byte)) {
            url[cursor++] = (char)byte;
        } else {
            url[cursor++] = '%';
            url[cursor++] = hex[byte >> 4];
            url[cursor++] = hex[byte & 0x0f];
        }
    }
    if (directory && (cursor == 0 || url[cursor - 1] != '/')) {
        url[cursor++] = '/';
    }
    url[cursor] = '\0';
    return url;
}

static char *ovc_file_root_url_from_config(
    const char *raw,
    char **out_path,
    OvStoragePlugin_Error **out_error)
{
    char *path;
    char *url;

    *out_path = NULL;
    *out_error = NULL;
    if (raw == NULL || raw[0] == '\0') {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                    "file connection needs a non-empty root");
        return NULL;
    }
    if (strlen(raw) >= 5 && ovc_file_ascii_equal_nocase(raw, "file:", 5)) {
        path = ovc_file_url_to_path(raw, out_error);
        if (path == NULL) {
            return NULL;
        }
        url = ovc_file_path_to_url(path, true);
    } else {
        path = ovc_file_normalize_native_path(raw);
        if (path == NULL) {
            int saved_error;

            saved_error = errno;
            *out_error = ovc_file_native_error(saved_error,
                                               "normalize file root",
                                               raw);
            return NULL;
        }
        url = ovc_file_path_to_url(path, true);
    }
    *out_path = path;
    return url;
}

/* The trailing separator is not part of the root's identity.  A caller
 * addressing the connection root itself writes it without one, so comparing
 * against the spelled root refused the very node the connection publishes --
 * the routing failure this address model exists to remove.  Compare the root
 * without its trailing separator, then require a component boundary so a
 * sibling whose name merely starts with the root's is still outside it. */
static size_t ovc_file_root_node_length(const char *root)
{
    size_t root_length;

    root_length = strlen(root);
    if (root_length != 0 && ovc_path_is_separator(root[root_length - 1])) {
        root_length -= 1;
    }
    return root_length;
}

static bool ovc_file_path_has_prefix(const char *path, const char *root)
{
    size_t root_length;

    root_length = ovc_file_root_node_length(root);
#if defined(_WIN32)
    if (_strnicmp(path, root, root_length) != 0) {
        return false;
    }
#else
    if (strncmp(path, root, root_length) != 0) {
        return false;
    }
#endif
    /* The filesystem root contains everything; there is no boundary byte. */
    if (root_length == 0) {
        return true;
    }
    return path[root_length] == '\0' ||
           ovc_path_is_separator(path[root_length]);
}

static bool ovc_file_canonical_path_has_prefix(const char *path,
                                               const char *root)
{
    size_t root_length;

    /* Keep this comparison exact even on Win32.  Per-directory
     * case-sensitive namespaces can contain distinct Root/root siblings;
     * accepting a case-folded canonical prefix would widen the root jail.
     * On a conventional case-insensitive volume this may conservatively deny
     * an alternate-cased spelling, while never granting an out-of-root path. */
    root_length = ovc_file_root_node_length(root);
    if (strncmp(path, root, root_length) != 0) {
        return false;
    }
    if (root_length == 0) {
        return true;
    }
    return path[root_length] == '\0' ||
           ovc_path_is_separator(path[root_length]);
}

static bool ovc_file_all_decimal(const char *value,
                                 size_t begin,
                                 size_t end)
{
    size_t index;

    if (begin == end) {
        return false;
    }
    for (index = begin; index < end; ++index) {
        if (value[index] < '0' || value[index] > '9') {
            return false;
        }
    }
    return true;
}

static bool ovc_file_is_atomic_temp_name_n(const char *name, size_t length)
{
    size_t end;
    unsigned int numeric_segments;

    if (length < 10 || name[0] != '.' ||
#if defined(_WIN32)
        !ovc_file_ascii_equal_nocase(name + length - 4, ".tmp", 4)) {
#else
        memcmp(name + length - 4, ".tmp", 4) != 0) {
#endif
        return false;
    }
    end = length - 4;
    for (numeric_segments = 0; numeric_segments < 3;
         ++numeric_segments) {
        size_t begin;

        begin = end;
        while (begin > 0 && name[begin - 1] != '.') {
            --begin;
        }
        if (begin == 0 ||
            !ovc_file_all_decimal(name, begin, end)) {
            return false;
        }
        end = begin - 1;
    }
    return end > 1;
}

static bool ovc_file_path_is_internal(const char *path)
{
    size_t length;
    size_t at;

    length = strlen(path);
    at = 0;
    while (at < length) {
        size_t begin;
        size_t component_length;

        while (at < length && ovc_path_is_separator(path[at])) {
            ++at;
        }
        begin = at;
        while (at < length && !ovc_path_is_separator(path[at])) {
            ++at;
        }
        component_length = at - begin;
        if ((component_length == sizeof(".ovstorage-meta") - 1 &&
#if defined(_WIN32)
             ovc_file_ascii_equal_nocase(path + begin,
                                         ".ovstorage-meta",
                                         component_length)) ||
#else
             memcmp(path + begin,
                    ".ovstorage-meta",
                    component_length) == 0) ||
#endif
            ovc_file_is_atomic_temp_name_n(path + begin,
                                           component_length)) {
            return true;
        }
#if defined(_WIN32)
        {
            size_t character;

            for (character = 0; character < component_length; ++character) {
                if (path[begin + character] == ':' &&
                    !(begin == 0 && character == 1)) {
                    return true;
                }
            }
        }
#endif
    }
    return false;
}

static char *ovc_file_parent_path(const char *path)
{
    char *copy;
    size_t length;

    copy = ovc_file_string_duplicate(path);
    length = strlen(copy);
    while (length > 0 && !ovc_path_is_separator(copy[length - 1])) {
        --length;
    }
    while (length > 1 && ovc_path_is_separator(copy[length - 1])) {
        --length;
    }
#if defined(_WIN32)
    if (length == 2 && copy[1] == ':') {
        copy[length++] = OVC_PATH_SEPARATOR;
    }
#endif
    copy[length] = '\0';
    return copy;
}

static int ovc_file_validate_canonical_scope(
    const char *path,
    const char *canonical_root,
    OvStoragePlugin_Error **out_error)
{
    char *candidate;
    char *canonical;

    candidate = ovc_file_string_duplicate(path);
    canonical = NULL;
    for (;;) {
        canonical = ovc_file_native_realpath(candidate);
        if (canonical != NULL) {
            break;
        }
        if (errno != ENOENT && errno != ENOTDIR) {
            int saved_error;

            saved_error = errno;
            free(candidate);
            *out_error = ovc_file_native_error(saved_error,
                                               "resolve file path",
                                               path);
            return -1;
        }
        {
            char *parent;

            parent = ovc_file_parent_path(candidate);
            if (strcmp(parent, candidate) == 0 || parent[0] == '\0') {
                free(parent);
                free(candidate);
                *out_error = ovc_file_error(
                    OvStoragePlugin_ErrorCode_PermissionDenied,
                    "file address has no existing in-root ancestor");
                return -1;
            }
            free(candidate);
            candidate = parent;
        }
    }
    free(candidate);
    if (!ovc_file_canonical_path_has_prefix(canonical,
                                            canonical_root)) {
        free(canonical);
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_PermissionDenied,
            "file address resolves outside the configured root");
        return -1;
    }
    free(canonical);
    return 0;
}

static char *ovc_file_resolve_path(
    ovc_file_layer *layer,
    const char *address,
    ovc_file_connection *out_connection,
    OvStoragePlugin_Error **out_error)
{
    char *path;
    size_t index;
    size_t best;
    size_t best_length;
    char *canonical_root;

    path = ovc_file_url_to_path(address, out_error);
    if (path == NULL) {
        return NULL;
    }
    if (ovc_file_path_is_internal(path)) {
        free(path);
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_PermissionDenied,
            "file URL addresses backend-internal storage");
        return NULL;
    }
    best = SIZE_MAX;
    best_length = 0;
    canonical_root = NULL;
    (void)ovc_mutex_lock(&layer->mutex);
    for (index = 0; index < layer->connection_count; ++index) {
        size_t root_length;

        root_length = strlen(layer->connections[index].root_path);
        if (root_length > best_length &&
            ovc_file_path_has_prefix(path,
                                     layer->connections[index].root_path)) {
            best = index;
            best_length = root_length;
        }
    }
    if (best != SIZE_MAX) {
        canonical_root = ovc_file_string_duplicate(
            layer->connections[best].canonical_root);
        if (out_connection != NULL) {
            (void)ovc_file_connection_clone_native(
                &layer->connections[best], out_connection);
        }
    }
    (void)ovc_mutex_unlock(&layer->mutex);
    if (best == SIZE_MAX) {
        free(path);
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_NoRoute,
                                    "no configured file root matches address");
        return NULL;
    }
    if (ovc_file_validate_canonical_scope(path,
                                          canonical_root,
                                          out_error) != 0) {
        free(canonical_root);
        free(path);
        if (out_connection != NULL) {
            ovc_file_connection_destroy(out_connection);
        }
        return NULL;
    }
    free(canonical_root);
    return path;
}

static char *ovc_file_resolve_path_and_root_flag(
    ovc_file_layer *layer,
    const char *address,
    bool *out_is_connection_root,
    OvStoragePlugin_Error **out_error)
{
    ovc_file_connection connection;
    char *path;

    memset(&connection, 0, sizeof(connection));
    path = ovc_file_resolve_path(layer,
                                 address,
                                 &connection,
                                 out_error);
    if (path == NULL) {
        return NULL;
    }
#if defined(_WIN32)
    *out_is_connection_root =
        _stricmp(path, connection.root_path) == 0;
#else
    *out_is_connection_root = strcmp(path, connection.root_path) == 0;
#endif
    ovc_file_connection_destroy(&connection);
    return path;
}

static int ovc_file_make_parent_directories(
    const char *path,
    OvStoragePlugin_Error **out_error)
{
    char *parent;
    size_t length;
    size_t index;

    parent = ovc_file_parent_path(path);
    length = strlen(parent);
#if defined(_WIN32)
    index = length >= 3 && parent[1] == ':' ? 3 : 0;
#else
    index = 1;
#endif
    for (; index <= length; ++index) {
        char saved;
        ovc_file_stat info;

#if defined(_WIN32)
        memset(&info, 0, sizeof(info));
#endif
        if (index != length && !ovc_path_is_separator(parent[index])) {
            continue;
        }
        saved = parent[index];
        parent[index] = '\0';
        if (parent[0] != '\0' && ovc_file_native_mkdir(parent) != 0 &&
            errno != EEXIST) {
            int native_error;

            native_error = errno;
            parent[index] = saved;
            free(parent);
            *out_error = ovc_file_native_error(native_error,
                                               "create directory",
                                               path);
            return -1;
        }
        if (parent[0] != '\0' &&
            ovc_file_native_stat_path(parent, &info) != 0) {
            int native_error;

            native_error = errno;
            parent[index] = saved;
            free(parent);
            *out_error = ovc_file_native_error(native_error,
                                               "stat directory",
                                               path);
            return -1;
        }
        if (parent[0] != '\0' && !info.is_directory) {
            parent[index] = saved;
            free(parent);
            *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Conflict,
                                        "write parent is not a directory");
            return -1;
        }
        parent[index] = saved;
    }
    free(parent);
    return 0;
}

static int ovc_file_make_directories(const char *path,
                                     OvStoragePlugin_Error **out_error)
{
    size_t length;
    size_t index;
    char *copy;

    copy = ovc_file_string_duplicate(path);
    length = strlen(copy);
#if defined(_WIN32)
    index = length >= 3 && copy[1] == ':' ? 3 : 0;
#else
    index = 1;
#endif
    for (; index <= length; ++index) {
        char saved;
        ovc_file_stat info;

#if defined(_WIN32)
        memset(&info, 0, sizeof(info));
#endif
        if (index != length && !ovc_path_is_separator(copy[index])) {
            continue;
        }
        saved = copy[index];
        copy[index] = '\0';
        if (copy[0] != '\0' && ovc_file_native_mkdir(copy) != 0 &&
            errno != EEXIST) {
            int native_error;

            native_error = errno;
            copy[index] = saved;
            free(copy);
            *out_error = ovc_file_native_error(native_error,
                                               "create directory",
                                               path);
            return -1;
        }
        if (copy[0] != '\0' &&
            ovc_file_native_stat_path(copy, &info) != 0) {
            int native_error;

            native_error = errno;
            copy[index] = saved;
            free(copy);
            *out_error = ovc_file_native_error(native_error,
                                               "stat directory",
                                               path);
            return -1;
        }
        if (copy[0] != '\0' && !info.is_directory) {
            copy[index] = saved;
            free(copy);
            *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Conflict,
                                        "directory path contains a file");
            return -1;
        }
        copy[index] = saved;
    }
    free(copy);
    return 0;
}

/* User metadata has no portable filesystem primitive.  This mirrors the
 * Rust reference's Unix sidecar layout (metadata.rs metadata_path) exactly:
 *
 *   <parent>/.ovstorage-meta/<lowercase-hex(object-name)>.meta
 *
 * so a tree written by either implementation serves its metadata under the
 * other.  Like the reference, hex-doubling accepts that a NAME_MAX-sized
 * object name yields an over-long sidecar name: writing NON-empty metadata
 * to such a name fails loudly with ENAMETOOLONG rather than silently
 * diverging on disk, but the probe and cleanup paths (guard, existence stat,
 * empty-metadata unlink) treat ENAMETOOLONG — and the Win32
 * ERROR_FILENAME_EXCED_RANGE, which ovc_win32_set_errno maps to it —
 * exactly like ENOENT.  An over-long sidecar name cannot exist, so probing
 * it means "no metadata"; otherwise write/delete/copy/rename of a long-named
 * object would commit the object mutation and then false-fail on the sidecar
 * probe, where the reference's metadata_exists succeeds.
 * The Rust reference stores Windows metadata in an NTFS alternate data
 * stream instead; this backend keeps the same sidecar-directory layout on
 * every platform — that divergence is documented in README.md.  Each payload
 * line is hex(key)=hex(value); hex keeps the payload unambiguous for every
 * byte representable by the frozen Str ABI, including newlines and '='.  The
 * directory is rejected by URL resolution and hidden by list(), so callers
 * cannot forge another object's metadata through the storage API.  Metadata
 * on a configured root is rejected separately so this sibling layout never
 * writes outside the configured jail. */

static char *ovc_file_metadata_path(const char *path,
                                    OvStoragePlugin_Error **out_error)
{
    static const char hex[] = "0123456789abcdef";
    const char *basename;
    const char *cursor;
    char *parent;
    char *directory;
    char *encoded;
    char *result;
    size_t basename_length;
    size_t index;

    cursor = path + strlen(path);
    while (cursor > path && !ovc_path_is_separator(cursor[-1])) {
        --cursor;
    }
    basename = cursor;
    basename_length = strlen(basename);
    if (basename_length == 0) {
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "user metadata needs a named filesystem entry");
        return NULL;
    }
    if (basename_length >
        (SIZE_MAX - sizeof(OVC_FILE_METADATA_SUFFIX)) / 2) {
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "object name is too long for a metadata sidecar");
        return NULL;
    }
    encoded = (char *)ovc_file_allocate(
        basename_length * 2 + sizeof(OVC_FILE_METADATA_SUFFIX));
    for (index = 0; index < basename_length; ++index) {
        unsigned char byte;

        byte = (unsigned char)basename[index];
        encoded[index * 2] = hex[byte >> 4];
        encoded[index * 2 + 1] = hex[byte & 0x0f];
    }
    memcpy(encoded + basename_length * 2,
           OVC_FILE_METADATA_SUFFIX,
           sizeof(OVC_FILE_METADATA_SUFFIX));
    parent = ovc_file_parent_path(path);
    directory = ovc_path_join(parent, OVC_FILE_METADATA_DIRECTORY);
    free(parent);
    if (directory == NULL) {
        free(encoded);
        *out_error = ovc_file_native_error(errno,
                                           "build metadata directory",
                                           path);
        return NULL;
    }
    result = ovc_path_join(directory, encoded);
    free(directory);
    free(encoded);
    if (result == NULL) {
        *out_error = ovc_file_native_error(errno,
                                           "build metadata sidecar path",
                                           path);
    }
    return result;
}

static OvStoragePlugin_Error *ovc_file_metadata_path_guard(
    const char *sidecar)
{
    char *directory;
    bool is_link;
    ovc_file_stat directory_info;

    directory = ovc_file_parent_path(sidecar);
    if (ovc_file_native_path_is_link(directory, &is_link) != 0) {
        int native_error;

        native_error = errno;
        free(directory);
        /* ENAMETOOLONG: an over-long sidecar path cannot exist, so the probe
         * answer is "absent" — see the layout comment above. */
        if (native_error == ENOENT || native_error == ENOTDIR ||
            native_error == ENAMETOOLONG) {
            return NULL;
        }
        return ovc_file_native_error(native_error,
                                     "inspect metadata directory",
                                     sidecar);
    }
    if (is_link) {
        free(directory);
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_PermissionDenied,
            "file metadata directory must not be a symlink or reparse point");
    }
    if (ovc_file_native_stat_path(directory, &directory_info) != 0) {
        int native_error;

        native_error = errno;
        free(directory);
        return ovc_file_native_error(native_error,
                                     "stat metadata directory",
                                     sidecar);
    }
    free(directory);
    if (!directory_info.is_directory) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_CacheCorrupt,
                              "file metadata directory is not a directory");
    }
    if (ovc_file_native_path_is_link(sidecar, &is_link) != 0) {
        int native_error;

        native_error = errno;
        /* A hex-doubled basename past NAME_MAX yields ENAMETOOLONG here even
         * when `.ovstorage-meta` exists; such a sidecar cannot exist, so the
         * guard must answer "absent" instead of hard-failing an object
         * mutation that already committed. */
        if (native_error == ENOENT || native_error == ENOTDIR ||
            native_error == ENAMETOOLONG) {
            return NULL;
        }
        return ovc_file_native_error(native_error,
                                     "inspect metadata sidecar",
                                     sidecar);
    }
    if (is_link) {
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_CacheCorrupt,
            "file metadata sidecar must not be a symlink or reparse point");
    }
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_read_path_bytes(
    const char *path,
    uint8_t **out_bytes,
    size_t *out_length)
{
    ovc_file file;
    ovc_file_stat info;
    uint8_t *bytes;
    size_t length;
    size_t offset;

    file = ovc_file_native_open_read(path);
    if (file == OVC_INVALID_FILE) {
        return ovc_file_native_error(errno, "open metadata sidecar", path);
    }
    if (ovc_file_native_fstat(file, &info) != 0) {
        int native_error;

        native_error = errno;
        (void)ovc_file_native_close(file);
        return ovc_file_native_error(native_error,
                                     "stat metadata sidecar",
                                     path);
    }
    if (!info.is_regular || info.size > SIZE_MAX) {
        (void)ovc_file_native_close(file);
        return ovc_file_error(OvStoragePlugin_ErrorCode_CacheCorrupt,
                              "file metadata sidecar is not a regular file");
    }
    length = (size_t)info.size;
    bytes = (uint8_t *)ovc_file_allocate(length == 0 ? 1 : length);
    offset = 0;
    while (offset < length) {
        ovc_ssize_t count;

        count = ovc_pread(file,
                          bytes + offset,
                          length - offset,
                          (uint64_t)offset);
        if (count < 0) {
            int native_error;

            native_error = errno;
            free(bytes);
            (void)ovc_file_native_close(file);
            return ovc_file_native_error(native_error,
                                         "read metadata sidecar",
                                         path);
        }
        if (count == 0) {
            free(bytes);
            (void)ovc_file_native_close(file);
            return ovc_file_error(OvStoragePlugin_ErrorCode_CacheCorrupt,
                                  "file metadata sidecar was truncated");
        }
        offset += (size_t)count;
    }
    if (ovc_file_native_close(file) != 0) {
        int native_error;

        native_error = errno;
        free(bytes);
        return ovc_file_native_error(native_error,
                                     "close metadata sidecar",
                                     path);
    }
    if (length == 0) {
        bytes[0] = 0;
    }
    *out_bytes = bytes;
    *out_length = length;
    return NULL;
}

static int ovc_file_decode_hex(const uint8_t *encoded,
                               size_t length,
                               OvStoragePlugin_Str *out)
{
    size_t index;

    if ((length & 1U) != 0) {
        return -1;
    }
    out->ptr = (char *)ovc_file_abi_allocate(length == 0 ? 1 : length / 2);
    out->len = length / 2;
    for (index = 0; index < length; index += 2) {
        int high;
        int low;

        high = ovc_file_hex_value((char)encoded[index]);
        low = ovc_file_hex_value((char)encoded[index + 1]);
        if (high < 0 || low < 0) {
            ovc_file_str_clear(out);
            return -1;
        }
        out->ptr[index / 2] = (char)((high << 4) | low);
    }
    if (out->len == 0) {
        out->ptr[0] = '\0';
    }
    return 0;
}

static bool ovc_file_utf8_valid(const OvStoragePlugin_Str *value)
{
    return ovc_utf8_is_valid(value->ptr, value->len);
}

static OvStoragePlugin_Error *ovc_file_user_metadata_read(
    const char *path,
    OvStoragePlugin_KeyValueList *out)
{
    char *sidecar;
    uint8_t *bytes;
    size_t length;
    size_t line_count;
    size_t cursor;
    ovc_file_stat sidecar_info;
    OvStoragePlugin_Error *error;

    memset(out, 0, sizeof(*out));
    error = NULL;
    sidecar = ovc_file_metadata_path(path, &error);
    if (sidecar == NULL) {
        return error;
    }
    error = ovc_file_metadata_path_guard(sidecar);
    if (error != NULL) {
        free(sidecar);
        return error;
    }
    /* ENAMETOOLONG: the over-long sidecar cannot exist => no metadata, the
     * same answer the reference's metadata_exists gives. */
    if (ovc_file_native_stat_path(sidecar, &sidecar_info) != 0 &&
        (errno == ENOENT || errno == ENOTDIR || errno == ENAMETOOLONG)) {
        free(sidecar);
        out->ptr = (OvStoragePlugin_KeyValuePair *)
            ovc_file_abi_allocate(sizeof(*out->ptr));
        out->len = 0;
        return NULL;
    }
    bytes = NULL;
    length = 0;
    error = ovc_file_read_path_bytes(sidecar, &bytes, &length);
    free(sidecar);
    if (error != NULL) {
        return error;
    }
    line_count = 0;
    for (cursor = 0; cursor < length; ++cursor) {
        if (bytes[cursor] == '\n') {
            ++line_count;
        }
    }
    if (length != 0 && bytes[length - 1] != '\n') {
        ++line_count;
    }
    out->ptr = (OvStoragePlugin_KeyValuePair *)ovc_file_abi_callocate(
        line_count == 0 ? 1 : line_count,
        sizeof(*out->ptr));
    out->len = 0;
    cursor = 0;
    while (cursor < length) {
        size_t line_start;
        size_t line_end;
        size_t separator;
        OvStoragePlugin_KeyValuePair pair;

        line_start = cursor;
        while (cursor < length && bytes[cursor] != '\n') {
            ++cursor;
        }
        line_end = cursor;
        if (cursor < length) {
            ++cursor;
        }
        if (line_end == line_start) {
            ovc_file_key_value_list_clear(out);
            free(bytes);
            return ovc_file_error(OvStoragePlugin_ErrorCode_CacheCorrupt,
                                  "file metadata sidecar has an empty line");
        }
        separator = line_start;
        while (separator < line_end && bytes[separator] != '=') {
            ++separator;
        }
        memset(&pair, 0, sizeof(pair));
        if (separator == line_end ||
            ovc_file_decode_hex(bytes + line_start,
                                separator - line_start,
                                &pair.key) != 0 ||
            ovc_file_decode_hex(bytes + separator + 1,
                                line_end - separator - 1,
                                &pair.value) != 0 ||
            !ovc_file_utf8_valid(&pair.key) ||
            !ovc_file_utf8_valid(&pair.value)) {
            ovc_file_str_clear(&pair.key);
            ovc_file_str_clear(&pair.value);
            ovc_file_key_value_list_clear(out);
            free(bytes);
            return ovc_file_error(
                OvStoragePlugin_ErrorCode_CacheCorrupt,
                "file metadata sidecar has invalid hex or UTF-8");
        }
        out->ptr[out->len++] = pair;
    }
    free(bytes);
    return NULL;
}

static bool ovc_file_str_bytes_equal(const OvStoragePlugin_Str *left,
                                     const OvStoragePlugin_Str *right)
{
    return left->len == right->len &&
           (left->len == 0 || memcmp(left->ptr, right->ptr, left->len) == 0);
}

static void ovc_file_user_metadata_remove(
    OvStoragePlugin_KeyValueList *metadata,
    const OvStoragePlugin_Str *key)
{
    size_t index;

    for (index = 0; index < metadata->len; ++index) {
        if (!ovc_file_str_bytes_equal(&metadata->ptr[index].key, key)) {
            continue;
        }
        ovc_file_str_clear(&metadata->ptr[index].key);
        ovc_file_str_clear(&metadata->ptr[index].value);
        if (index + 1 < metadata->len) {
            memmove(&metadata->ptr[index],
                    &metadata->ptr[index + 1],
                    (metadata->len - index - 1) * sizeof(*metadata->ptr));
        }
        --metadata->len;
        return;
    }
}

static void ovc_file_user_metadata_set(
    OvStoragePlugin_KeyValueList *metadata,
    const OvStoragePlugin_Str *key,
    const OvStoragePlugin_Str *value)
{
    size_t index;
    OvStoragePlugin_KeyValuePair *next;

    for (index = 0; index < metadata->len; ++index) {
        if (ovc_file_str_bytes_equal(&metadata->ptr[index].key, key)) {
            ovc_file_str_clear(&metadata->ptr[index].value);
            metadata->ptr[index].value =
                ovc_file_owned_slice(value->ptr, value->len);
            return;
        }
    }
    /* Metadata lists cross the ABI, so they live on the ABI allocator,
     * which has no realloc: grow by copy.  These lists are small. */
    if (metadata->len >= SIZE_MAX / sizeof(*metadata->ptr) - 1) {
        abort();
    }
    next = (OvStoragePlugin_KeyValuePair *)ovc_file_abi_allocate(
        (metadata->len + 1) * sizeof(*metadata->ptr));
    if (metadata->len != 0) {
        memcpy(next, metadata->ptr, metadata->len * sizeof(*metadata->ptr));
    }
    ovc_abi_free(metadata->ptr);
    metadata->ptr = next;
    metadata->ptr[metadata->len].key =
        ovc_file_owned_slice(key->ptr, key->len);
    metadata->ptr[metadata->len].value =
        ovc_file_owned_slice(value->ptr, value->len);
    ++metadata->len;
}

/* ------------------------------------------------------------------------- */
/* Object metadata and atomic byte I/O. */

static char *ovc_file_etag(const ovc_file_stat *info)
{
    char buffer[128];
    int length;
    char *etag;

    length = snprintf(buffer,
                      sizeof(buffer),
                      "size:%llu,mtime:%lld",
                      (unsigned long long)info->size,
                      (long long)info->mtime_unix_nanos);
    if (length < 0 || (size_t)length >= sizeof(buffer)) {
        abort();
    }
    etag = (char *)ovc_file_allocate((size_t)length + 1);
    memcpy(etag, buffer, (size_t)length + 1);
    return etag;
}

/* Approximate effective permissions from the entry's read-only bit, exactly
 * as the Rust reference does (mod.rs effective_permissions_from_metadata): a
 * read-only entry advertises READ, everything else the full set. */
static uint32_t ovc_file_effective_permissions(const ovc_file_stat *native)
{
    return native->readonly ? OVC_FILE_PERMISSION_READ
                            : OVC_FILE_PERMISSION_ALL;
}

static OvStoragePlugin_Error *ovc_file_object_info_fill(
    OvStoragePlugin_ObjectInfo *out,
    const char *address,
    const char *path,
    bool full_metadata,
    const ovc_file_stat *native)
{
    char *etag;
    OvStoragePlugin_Error *error;

    memset(out, 0, sizeof(*out));
    out->address = ovc_file_owned_string(address);
    out->kind = native->is_directory
                    ? OvStoragePlugin_ObjectKindV1_Directory
                    : OvStoragePlugin_ObjectKindV1_File;
    etag = ovc_file_etag(native);
    out->etag.present = true;
    out->etag.value = ovc_file_owned_string(etag);
    free(etag);
    if (!native->is_directory) {
        out->size.present = true;
        out->size.value = native->size;
    }
    out->mtime_unix_ms.present = true;
    out->mtime_unix_ms.value = native->mtime_unix_ms;
    out->checksums.ptr = (OvStoragePlugin_ChecksumEntry *)
        ovc_file_abi_allocate(sizeof(*out->checksums.ptr));
    out->checksums.len = 0;
    out->effective_permissions.present = true;
    out->effective_permissions.value.bits =
        ovc_file_effective_permissions(native);
    if (full_metadata) {
        out->user_metadata.present = true;
        error = ovc_file_user_metadata_read(path,
                                            &out->user_metadata.value);
        if (error != NULL) {
            ovc_file_object_info_clear(out);
            return error;
        }
    }
    return NULL;
}

static void ovc_file_backend_item_info_take(
    OvStoragePlugin_BackendItemInfo *out,
    OvStoragePlugin_ObjectInfo *source)
{
    memset(out, 0, sizeof(*out));
    out->kind = source->kind;
    out->etag = source->etag;
    out->version = source->version;
    out->size = source->size;
    out->mtime_unix_ms = source->mtime_unix_ms;
    out->checksums = source->checksums;
    out->effective_permissions = source->effective_permissions;
    out->system_metadata = source->system_metadata;
    out->user_metadata = source->user_metadata;
    out->modified_by = source->modified_by;
    ovc_file_str_clear(&source->address);
    memset(source, 0, sizeof(*source));
}

static bool ovc_file_stat_identity_equal(const ovc_file_stat *left,
                                         const ovc_file_stat *right)
{
    return left->size == right->size &&
           left->mtime_unix_nanos == right->mtime_unix_nanos &&
           left->is_directory == right->is_directory &&
           left->is_regular == right->is_regular;
}

static bool ovc_file_cancelled(const ovc_file_task *task)
{
    return task != NULL && task->has_cancel && task->cancel.state != NULL &&
           task->cancel.is_canceled != NULL &&
           task->cancel.is_canceled(task->cancel.state);
}

static char *ovc_file_temp_sibling(const char *path, unsigned int attempt)
{
    char *parent;
    char name[160];
    uint64_t stamp;
    int length;
    char *result;

    parent = ovc_file_parent_path(path);
    stamp = ovc_monotonic_ns();
    /* A valid destination may consume the filesystem's entire NAME_MAX.  Keep
     * the staging basename fixed-size instead of appending to the destination
     * basename; timestamp + pid + retry index still make it process-unique. */
    length = snprintf(name,
                      sizeof(name),
                      ".ovstorage-stage.%llu.%lu.%u.tmp",
                      (unsigned long long)stamp,
                      ovc_file_process_id(),
                      attempt);
    if (length < 0 || (size_t)length >= sizeof(name)) {
        free(parent);
        errno = ENAMETOOLONG;
        return NULL;
    }
    result = ovc_path_join(parent, name);
    free(parent);
    return result;
}

static char *ovc_file_create_temp(
    const char *path,
    ovc_file *out_file,
    OvStoragePlugin_Error **out_error)
{
    unsigned int attempt;
    int last_error;

    last_error = EEXIST;
    for (attempt = 0; attempt < OVC_FILE_TEMP_ATTEMPTS; ++attempt) {
        char *candidate;
        ovc_file file;

        candidate = ovc_file_temp_sibling(path, attempt);
        if (candidate == NULL) {
            last_error = errno;
            break;
        }
        file = ovc_file_native_create_new(candidate);
        if (file != OVC_INVALID_FILE) {
            *out_file = file;
            return candidate;
        }
        last_error = errno;
        free(candidate);
        if (last_error != EEXIST) {
            break;
        }
    }
    *out_error = ovc_file_native_error(last_error,
                                       "create atomic-write temp file",
                                       path);
    return NULL;
}

static char *ovc_file_create_metadata_temp(
    const char *sidecar,
    ovc_file *out_file,
    OvStoragePlugin_Error **out_error)
{
    unsigned int attempt;
    int last_error;
    char *parent;

    parent = ovc_file_parent_path(sidecar);
    last_error = EEXIST;
    for (attempt = 0; attempt < OVC_FILE_TEMP_ATTEMPTS; ++attempt) {
        char name[160];
        char *candidate;
        int length;
        ovc_file file;

        /* Do not embed the object basename here: a valid NAME_MAX-sized
         * object must still leave room for metadata's atomic staging name. */
        length = snprintf(name,
                          sizeof(name),
                          ".metadata.%llu.%lu.%u.tmp",
                          (unsigned long long)ovc_monotonic_ns(),
                          ovc_file_process_id(),
                          attempt);
        if (length < 0 || (size_t)length >= sizeof(name)) {
            last_error = ENAMETOOLONG;
            break;
        }
        candidate = ovc_path_join(parent, name);
        if (candidate == NULL) {
            last_error = errno;
            break;
        }
        file = ovc_file_native_create_new(candidate);
        if (file != OVC_INVALID_FILE) {
            free(parent);
            *out_file = file;
            return candidate;
        }
        last_error = errno;
        free(candidate);
        if (last_error != EEXIST) {
            break;
        }
    }
    free(parent);
    *out_error = ovc_file_native_error(last_error,
                                       "create metadata temp file",
                                       sidecar);
    return NULL;
}

static int ovc_file_write_all(
    ovc_file file,
    const uint8_t *bytes,
    size_t length,
    const ovc_file_task *task,
    OvStoragePlugin_Error **out_error)
{
    size_t written;

    written = 0;
    while (written < length) {
        ovc_ssize_t result;
        size_t chunk_length;

        if (ovc_file_cancelled(task)) {
            *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                        "file write was cancelled");
            return -1;
        }
        chunk_length = length - written;
        if (chunk_length > OVC_FILE_IO_CHUNK_SIZE) {
            chunk_length = OVC_FILE_IO_CHUNK_SIZE;
        }
        result = ovc_pwrite(file,
                            bytes + written,
                            chunk_length,
                            (uint64_t)written);
        if (result < 0) {
            int native_error;

            native_error = errno;
            *out_error = ovc_file_native_error(native_error,
                                               "write temp file",
                                               "");
            return -1;
        }
        if (result == 0) {
            *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Transient,
                                        "file write made no progress");
            return -1;
        }
        written += (size_t)result;
    }
    return 0;
}

static OvStoragePlugin_Error *ovc_file_user_metadata_write(
    const char *path,
    const OvStoragePlugin_KeyValueList *metadata,
    const ovc_file_task *task)
{
    static const char hex[] = "0123456789abcdef";
    char *sidecar;
    char *temporary;
    char *metadata_directory;
    uint8_t *encoded;
    size_t encoded_length;
    size_t cursor;
    size_t index;
    ovc_file file;
    OvStoragePlugin_Error *error;
    bool published;

    error = NULL;
    sidecar = ovc_file_metadata_path(path, &error);
    if (sidecar == NULL) {
        return error;
    }
    error = ovc_file_metadata_path_guard(sidecar);
    if (error != NULL) {
        free(sidecar);
        return error;
    }
    if (metadata->len == 0) {
        /* ENAMETOOLONG: nothing with that over-long name can exist, so the
         * cleanup already holds — do not fail a committed object mutation. */
        if (ovc_file_native_unlink(sidecar) != 0 &&
            errno != ENOENT && errno != ENOTDIR &&
            errno != ENAMETOOLONG) {
            int native_error;

            native_error = errno;
            error = ovc_file_native_error(native_error,
                                          "remove metadata sidecar",
                                          sidecar);
            free(sidecar);
            return error;
        }
        metadata_directory = ovc_file_parent_path(sidecar);
        (void)ovc_file_native_rmdir(metadata_directory);
        free(metadata_directory);
        free(sidecar);
        return NULL;
    }
    encoded_length = 0;
    for (index = 0; index < metadata->len; ++index) {
        size_t pair_bytes;

        if (metadata->ptr[index].key.ptr == NULL ||
            metadata->ptr[index].value.ptr == NULL ||
            metadata->ptr[index].key.len >
                SIZE_MAX - metadata->ptr[index].value.len ||
            metadata->ptr[index].key.len +
                    metadata->ptr[index].value.len >
                (SIZE_MAX - 2) / 2) {
            free(sidecar);
            return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                  "user metadata contains an invalid entry");
        }
        pair_bytes = (metadata->ptr[index].key.len +
                      metadata->ptr[index].value.len) * 2;
        if (pair_bytes > SIZE_MAX - 2 - encoded_length) {
            free(sidecar);
            return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                                  "user metadata is too large");
        }
        encoded_length += pair_bytes + 2;
    }
    encoded = (uint8_t *)ovc_file_allocate(encoded_length);
    cursor = 0;
    for (index = 0; index < metadata->len; ++index) {
        size_t byte_index;

        for (byte_index = 0;
             byte_index < metadata->ptr[index].key.len;
             ++byte_index) {
            unsigned char byte;

            byte = (unsigned char)metadata->ptr[index].key.ptr[byte_index];
            encoded[cursor++] = (uint8_t)hex[byte >> 4];
            encoded[cursor++] = (uint8_t)hex[byte & 0x0f];
        }
        encoded[cursor++] = '=';
        for (byte_index = 0;
             byte_index < metadata->ptr[index].value.len;
             ++byte_index) {
            unsigned char byte;

            byte = (unsigned char)metadata->ptr[index].value.ptr[byte_index];
            encoded[cursor++] = (uint8_t)hex[byte >> 4];
            encoded[cursor++] = (uint8_t)hex[byte & 0x0f];
        }
        encoded[cursor++] = '\n';
    }
    if (ovc_file_make_parent_directories(sidecar, &error) != 0) {
        free(encoded);
        free(sidecar);
        return error;
    }
    error = ovc_file_metadata_path_guard(sidecar);
    if (error != NULL) {
        free(encoded);
        free(sidecar);
        return error;
    }
    temporary = ovc_file_create_metadata_temp(sidecar, &file, &error);
    if (temporary == NULL) {
        free(encoded);
        free(sidecar);
        return error;
    }
    published = false;
    if (ovc_file_write_all(file,
                           encoded,
                           encoded_length,
                           task,
                           &error) != 0 ||
        ovc_file_native_sync(file) != 0) {
        if (error == NULL) {
            error = ovc_file_native_error(errno,
                                          "sync metadata sidecar",
                                          temporary);
        }
    } else if (ovc_file_native_close(file) != 0) {
        file = OVC_INVALID_FILE;
        error = ovc_file_native_error(errno,
                                      "close metadata sidecar",
                                      temporary);
    } else {
        file = OVC_INVALID_FILE;
        if (ovc_file_native_rename_replace(temporary, sidecar) != 0) {
            error = ovc_file_native_error(errno,
                                          "publish metadata sidecar",
                                          sidecar);
        } else {
            published = true;
            if (ovc_file_native_sync_parent(sidecar) != 0) {
                error = ovc_file_error(
                    OvStoragePlugin_ErrorCode_CommitAmbiguous,
                    "metadata sidecar was published but its directory sync failed for `%s`: %s",
                    sidecar,
                    ovc_file_strerror(errno));
            }
        }
    }
    if (file != OVC_INVALID_FILE) {
        (void)ovc_file_native_close(file);
    }
    if (!published) {
        (void)ovc_file_native_unlink(temporary);
    }
    free(encoded);
    free(temporary);
    free(sidecar);
    return error;
}

static OvStoragePlugin_Error *ovc_file_user_metadata_copy(
    const char *source,
    const char *destination,
    const char *message,
    const ovc_file_task *task)
{
    static char message_key_bytes[] = "x-ov-message";
    OvStoragePlugin_KeyValueList metadata;
    OvStoragePlugin_Str message_key;
    OvStoragePlugin_Str message_value;
    OvStoragePlugin_Error *error;

    memset(&metadata, 0, sizeof(metadata));
    error = ovc_file_user_metadata_read(source, &metadata);
    if (error != NULL) {
        return error;
    }
    if (message != NULL && message[0] != '\0') {
        message_key.ptr = message_key_bytes;
        message_key.len = sizeof(message_key_bytes) - 1;
        message_value.ptr = (char *)message;
        message_value.len = strlen(message);
        ovc_file_user_metadata_set(&metadata,
                                   &message_key,
                                   &message_value);
    }
    error = ovc_file_user_metadata_write(destination, &metadata, task);
    ovc_file_key_value_list_clear(&metadata);
    return error;
}

static OvStoragePlugin_Error *ovc_file_user_metadata_remove_path(
    const char *path,
    const ovc_file_task *task)
{
    OvStoragePlugin_KeyValueList empty;

    /* Local-only list, but KeyValueList payloads uniformly live on the ABI
     * allocator in this file so the shared clear helpers stay correct. */
    empty.ptr = (OvStoragePlugin_KeyValuePair *)
        ovc_file_abi_allocate(sizeof(*empty.ptr));
    empty.len = 0;
    {
        OvStoragePlugin_Error *error;

        error = ovc_file_user_metadata_write(path, &empty, task);
        ovc_abi_free(empty.ptr);
        return error;
    }
}

static int ovc_file_check_destination_precondition(
    const char *path,
    OvStoragePlugin_IfDestExistsTag if_dest,
    const char *expected_etag,
    OvStoragePlugin_Error **out_error)
{
    ovc_file_stat info;

    if (if_dest == OvStoragePlugin_IfDestExistsTag_Overwrite) {
        return 0;
    }
    if (ovc_file_native_stat_path(path, &info) != 0) {
        int native_error;

        native_error = errno;
        if (native_error == ENOENT || native_error == ENOTDIR) {
            if (if_dest == OvStoragePlugin_IfDestExistsTag_Fail) {
                return 0;
            }
            *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_NotFound,
                                        "conditional-write destination does not exist");
            return -1;
        }
        *out_error = ovc_file_native_error(native_error,
                                           "stat write destination",
                                           path);
        return -1;
    }
    if (if_dest == OvStoragePlugin_IfDestExistsTag_Fail) {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_AlreadyExists,
                                    "write destination already exists");
        return -1;
    }
    if (if_dest == OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        char *actual;
        bool matches;

        actual = ovc_file_etag(&info);
        matches = expected_etag != NULL &&
                  strcmp(actual, expected_etag) == 0;
        free(actual);
        if (!matches) {
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_PreconditionFailed,
                "write destination etag does not match");
            return -1;
        }
        return 0;
    }
    *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                "write has an unknown if_dest tag");
    return -1;
}

static OvStoragePlugin_Error *ovc_file_stat_result(
    ovc_file_layer *layer,
    const char *address,
    bool full_metadata,
    OvStoragePlugin_ObjectInfo **out)
{
    char *path;
    ovc_file_stat native;
    OvStoragePlugin_Error *error;
    OvStoragePlugin_ObjectInfo *result;
    bool is_connection_root;

    error = NULL;
    path = ovc_file_resolve_path_and_root_flag(layer,
                                               address,
                                               &is_connection_root,
                                               &error);
    if (path == NULL) {
        return error;
    }
    if (ovc_file_native_stat_path(path, &native) != 0) {
        int native_error;

        native_error = errno;
        error = ovc_file_native_error(native_error, "stat file", path);
        free(path);
        return error;
    }
    result = (OvStoragePlugin_ObjectInfo *)
        ovc_file_abi_callocate(1, sizeof(*result));
    error = ovc_file_object_info_fill(result,
                                      address,
                                      path,
                                      full_metadata && !is_connection_root,
                                      &native);
    if (error != NULL) {
        ovc_abi_free(result);
        free(path);
        return error;
    }
    free(path);
    *out = result;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_read_result(
    ovc_file_task *task,
    OvStoragePlugin_ReadResult **out)
{
    char *path;
    ovc_file_stat before;
    ovc_file_stat after;
    ovc_file file;
    uint64_t start;
    uint64_t end;
    uint64_t read_length_u64;
    size_t read_length;
    size_t read_at;
    uint8_t *bytes;
    OvStoragePlugin_ReadResult *result;
    OvStoragePlugin_Error *error;

    error = NULL;
    path = ovc_file_resolve_path(task->layer,
                                 task->address,
                                 NULL,
                                 &error);
    if (path == NULL) {
        return error;
    }
    if (ovc_file_native_stat_path(path, &before) != 0) {
        int native_error;

        native_error = errno;
        error = ovc_file_native_error(native_error, "stat file for read", path);
        free(path);
        return error;
    }
    if (before.is_directory) {
        /* A directory is a type mismatch, not a missing object: answer the
         * same InvalidArgument + guidance the Rust reference gives
         * (mod.rs reject_directory_target), ahead of the if_match and range
         * branches so every arm agrees. */
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "read target is a directory; use list()");
    }
    if (!before.is_regular) {
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_Unsupported,
                              "cannot read a filesystem special file");
    }
    if (!task->payload.read.has_range) {
        char *canonical;

        /* A whole-object read returns a LocalDelegate (canonical path +
         * object info) instead of materializing the bytes, matching the
         * Rust reference (mod.rs read): the broker's raw-read path streams the
         * returned delegate itself.
         * The buffered Bytes path below serves only ranged reads.  The
         * delegate is built exactly as ovc_file_materialize_result builds
         * one, including the special-file guard above. */
        if (task->payload.read.if_match != NULL) {
            char *actual;
            bool matches;

            actual = ovc_file_etag(&before);
            matches = strcmp(actual, task->payload.read.if_match) == 0;
            free(actual);
            if (!matches) {
                free(path);
                return ovc_file_error(
                    OvStoragePlugin_ErrorCode_ObjectModified,
                    "read etag does not match");
            }
        }
        canonical = ovc_file_native_realpath(path);
        if (canonical == NULL) {
            error = ovc_file_native_error(errno,
                                          "resolve file for read",
                                          path);
            free(path);
            return error;
        }
        result = (OvStoragePlugin_ReadResult *)
            ovc_file_abi_callocate(1, sizeof(*result));
        result->tag = OvStoragePlugin_ReadResultTag_LocalDelegate;
        result->local_delegate.path = ovc_file_owned_string(canonical);
        free(canonical);
        error = ovc_file_object_info_fill(&result->local_delegate.info,
                                          task->address,
                                          path,
                                          true,
                                          &before);
        if (error != NULL) {
            ovc_file_str_clear(&result->local_delegate.path);
            ovc_abi_free(result);
            free(path);
            return error;
        }
        free(path);
        *out = result;
        return NULL;
    }
    file = ovc_file_native_open_read(path);
    if (file == OVC_INVALID_FILE) {
        int native_error;

        native_error = errno;
        error = ovc_file_native_error(native_error, "open file for read", path);
        free(path);
        return error;
    }
    if (ovc_file_native_fstat(file, &before) != 0) {
        int native_error;

        native_error = errno;
        (void)ovc_file_native_close(file);
        error = ovc_file_native_error(native_error, "fstat file for read", path);
        free(path);
        return error;
    }
    if (!before.is_regular) {
        (void)ovc_file_native_close(file);
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_Unsupported,
                              "cannot read a filesystem special file");
    }
    if (task->payload.read.if_match != NULL) {
        char *actual;
        bool matches;

        actual = ovc_file_etag(&before);
        matches = strcmp(actual, task->payload.read.if_match) == 0;
        free(actual);
        if (!matches) {
            (void)ovc_file_native_close(file);
            free(path);
            return ovc_file_error(OvStoragePlugin_ErrorCode_ObjectModified,
                                  "read etag does not match");
        }
    }
    start = 0;
    end = before.size == 0 ? 0 : before.size - 1;
    if (task->payload.read.has_range) {
        start = task->payload.read.range_start;
        if (task->payload.read.has_range_end &&
            task->payload.read.range_end < start) {
            (void)ovc_file_native_close(file);
            free(path);
            return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                  "byte range end precedes start");
        }
        if (before.size == 0 || start >= before.size) {
            (void)ovc_file_native_close(file);
            free(path);
            return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                  "byte range is outside the object");
        }
        if (task->payload.read.has_range_end &&
            task->payload.read.range_end < end) {
            end = task->payload.read.range_end;
        }
    }
    read_length_u64 = before.size == 0 ? 0 : end - start + 1;
    if (read_length_u64 > SIZE_MAX) {
        (void)ovc_file_native_close(file);
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "file is too large to return as bytes");
    }
    read_length = (size_t)read_length_u64;
    /* This buffer is returned across the ABI, so it must come from the ABI
     * allocator; the mint stays fallible because a large range is the
     * likeliest allocation to fail. */
    bytes = (uint8_t *)ovc_abi_alloc(read_length == 0 ? 1 : read_length);
    if (bytes == NULL) {
        (void)ovc_file_native_close(file);
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "not enough memory to return file bytes");
    }
    if (read_length == 0) {
        bytes[0] = 0;
    }
    read_at = 0;
    while (read_at < read_length) {
        ovc_ssize_t count;
        size_t chunk_length;

        if (ovc_file_cancelled(task)) {
            ovc_abi_free(bytes);
            (void)ovc_file_native_close(file);
            free(path);
            return ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                  "file read was cancelled");
        }
        chunk_length = read_length - read_at;
        if (chunk_length > OVC_FILE_IO_CHUNK_SIZE) {
            chunk_length = OVC_FILE_IO_CHUNK_SIZE;
        }
        count = ovc_pread(file,
                          bytes + read_at,
                          chunk_length,
                          start + (uint64_t)read_at);
        if (count < 0) {
            int native_error;

            native_error = errno;
            ovc_abi_free(bytes);
            (void)ovc_file_native_close(file);
            error = ovc_file_native_error(native_error, "read file", path);
            free(path);
            return error;
        }
        if (count == 0) {
            ovc_abi_free(bytes);
            (void)ovc_file_native_close(file);
            free(path);
            return ovc_file_error(OvStoragePlugin_ErrorCode_ObjectModified,
                                  "file became shorter during read");
        }
        read_at += (size_t)count;
    }
    if (ovc_file_native_fstat(file, &after) != 0) {
        int native_error;

        native_error = errno;
        ovc_abi_free(bytes);
        (void)ovc_file_native_close(file);
        error = ovc_file_native_error(native_error,
                                      "fstat file after read",
                                      path);
        free(path);
        return error;
    }
    (void)ovc_file_native_close(file);
    if (!ovc_file_stat_identity_equal(&before, &after)) {
        ovc_abi_free(bytes);
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_ObjectModified,
                              "file changed during read");
    }
    result = (OvStoragePlugin_ReadResult *)
        ovc_file_abi_callocate(1, sizeof(*result));
    result->tag = OvStoragePlugin_ReadResultTag_Bytes;
    result->bytes.bytes.ptr = bytes;
    result->bytes.bytes.len = read_length;
    error = ovc_file_object_info_fill(&result->bytes.info,
                                      task->address,
                                      path,
                                      true,
                                      &before);
    if (error != NULL) {
        ovc_file_bytes_clear(&result->bytes.bytes, false);
        ovc_abi_free(result);
        free(path);
        return error;
    }
    free(path);
    *out = result;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_write_result(
    ovc_file_task *task,
    OvStoragePlugin_WriteResult **out)
{
    char *path;
    char *temporary;
    ovc_file file;
    ovc_file_stat native;
    OvStoragePlugin_WriteResult *result;
    OvStoragePlugin_Error *error;
    bool renamed;

    error = NULL;
    path = ovc_file_resolve_path(task->layer,
                                 task->address,
                                 NULL,
                                 &error);
    if (path == NULL) {
        return error;
    }
    if (ovc_file_make_parent_directories(path, &error) != 0) {
        free(path);
        return error;
    }
    temporary = ovc_file_create_temp(path, &file, &error);
    if (temporary == NULL) {
        free(path);
        return error;
    }
    renamed = false;
    if (ovc_file_write_all(file,
                           task->payload.write.bytes,
                           task->payload.write.len,
                           task,
                           &error) != 0 ||
        ovc_file_native_sync(file) != 0) {
        if (error == NULL) {
            int native_error;

            native_error = errno;
            error = ovc_file_native_error(native_error,
                                          "sync temp file",
                                          temporary);
        }
        (void)ovc_file_native_close(file);
        (void)ovc_file_native_unlink(temporary);
        free(temporary);
        free(path);
        return error;
    }
    if (ovc_file_native_fstat(file, &native) != 0) {
        int native_error;

        native_error = errno;
        (void)ovc_file_native_close(file);
        (void)ovc_file_native_unlink(temporary);
        error = ovc_file_native_error(native_error,
                                      "fstat staged file",
                                      temporary);
        free(temporary);
        free(path);
        return error;
    }
    if (ovc_file_native_close(file) != 0) {
        int native_error;

        native_error = errno;
        (void)ovc_file_native_unlink(temporary);
        error = ovc_file_native_error(native_error,
                                      "close temp file",
                                      temporary);
        free(temporary);
        free(path);
        return error;
    }
    if (ovc_file_cancelled(task)) {
        (void)ovc_file_native_unlink(temporary);
        free(temporary);
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                              "file write was cancelled");
    }
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_check_destination_precondition(
            path,
            task->payload.write.if_dest,
            task->payload.write.match_etag,
            &error) == 0) {
        if (ovc_file_native_preserve_destination_permissions(path,
                                                             temporary) != 0) {
            int native_error;

            native_error = errno;
            error = ovc_file_native_error(
                native_error,
                "preserve destination permissions",
                path);
        } else if (ovc_file_native_rename_replace(temporary, path) == 0) {
            renamed = true;
            if (ovc_file_native_sync_parent(path) != 0) {
                int native_error;

                native_error = errno;
                error = ovc_file_error(
                    OvStoragePlugin_ErrorCode_CommitAmbiguous,
                    "file was published but its directory sync failed for `%s`: %s",
                    path,
                    ovc_file_strerror(native_error));
            } else {
                error = ovc_file_user_metadata_write(
                    path,
                    &task->payload.write.user_metadata,
                    NULL);
                if (error != NULL) {
                    /* The bytes are published; only the sidecar stage failed.
                     * Re-code as PartialCompletion so a caller can tell this
                     * from a write that did not happen, and so no retry Layer
                     * replays the write and changes the etag -- the
                     * multi-stage durability rule in
                     * docs/public/plugin-storage/CONFORMANCE.md, which names
                     * this backend as its example.  The Rust file backend
                     * reports the same code from the same stage.
                     *
                     * Code only, no ErrorContext: this backend attaches none
                     * to any error it mints (see ovc_file_error), including
                     * the CommitAmbiguous above. */
                    error->code =
                        OvStoragePlugin_ErrorCode_PartialCompletion;
                }
                /* Re-stat the published destination (as the staged copy
                 * does for out_info): the temp fstat above predates
                 * preserve-destination-permissions, so it would report an
                 * overwritten read-only file as writable.  The reference's
                 * write_atomic likewise ends with a stat of the destination
                 * path. */
                if (error == NULL &&
                    ovc_file_native_stat_path(path, &native) != 0) {
                    error = ovc_file_native_error(errno,
                                                  "stat published file",
                                                  path);
                }
            }
        } else {
            int native_error;

            native_error = errno;
            error = ovc_file_native_error(native_error,
                                          "publish file",
                                          path);
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    if (!renamed) {
        (void)ovc_file_native_unlink(temporary);
        free(temporary);
        free(path);
        return error;
    }
    free(temporary);
    if (error != NULL) {
        free(path);
        return error;
    }
    result = (OvStoragePlugin_WriteResult *)
        ovc_file_abi_callocate(1, sizeof(*result));
    error = ovc_file_object_info_fill(&result->info,
                                      task->address,
                                      path,
                                      true,
                                      &native);
    if (error != NULL) {
        ovc_abi_free(result);
        free(path);
        return error;
    }
    free(path);
    *out = result;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Namespace mutations and local-delegate/version helpers. */

static int ovc_file_parse_page_token(const char *token,
                                     size_t *out,
                                     OvStoragePlugin_Error **out_error);

static int ovc_file_check_source_precondition(
    const ovc_file_stat *info,
    const char *expected_etag,
    OvStoragePlugin_ErrorCode mismatch_code,
    OvStoragePlugin_Error **out_error)
{
    char *actual;
    bool matches;

    if (expected_etag == NULL) {
        return 0;
    }
    actual = ovc_file_etag(info);
    matches = strcmp(actual, expected_etag) == 0;
    free(actual);
    if (!matches) {
        *out_error = ovc_file_error(
            mismatch_code,
            "etag precondition does not match");
        return -1;
    }
    return 0;
}

/* Stage a byte-for-byte copy of `source` next to `destination` and publish
 * it with an atomic rename.  The bulk chunk loop runs UNLOCKED so a large
 * copy cannot stall every other operation on the layer; only the short
 * precondition-recheck -> publish-rename -> sidecar window takes
 * task->layer->mutex — the same shape as ovc_file_write_result.  The Rust
 * reference instead holds per-path source+destination locks across the whole
 * byte copy (mod.rs copy); this file has no per-path locks, so `if_source`
 * validity is preserved differently: the etag precondition is evaluated
 * against the staging pass's own before-fstat, the staged bytes are verified
 * unchanged after reading, and the publish window re-stats the source and
 * requires the same identity (ovc_file_stat_identity_equal) plus a locked
 * destination precondition re-verify before the rename becomes visible.
 *
 * `move_source` serves the cross-device rename fallback: the source is
 * unlinked inside the SAME critical section as the identity re-check and the
 * publish rename.  Retiring it in a separate lock acquisition would leave a
 * gap in which a concurrent write could publish new source content that the
 * unlink then silently destroys. */
static int ovc_file_copy_regular_staged(
    ovc_file_task *task,
    const char *source,
    const char *destination,
    const char *expected_source_etag,
    OvStoragePlugin_IfDestExistsTag if_dest,
    const char *expected_destination_etag,
    const char *message,
    bool move_source,
    ovc_file_stat *out_info,
    OvStoragePlugin_Error **out_error)
{
    ovc_file source_file;
    ovc_file destination_file;
    ovc_file_stat before;
    ovc_file_stat after;
    uint8_t *buffer;
    char *temporary;
    uint64_t offset;
    bool published;
    OvStoragePlugin_Error *error;

    source_file = OVC_INVALID_FILE;
    destination_file = OVC_INVALID_FILE;
    buffer = NULL;
    temporary = NULL;
    published = false;
    error = NULL;
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "file copy was cancelled");
        goto done;
    }
    /* Unlocked fast-fail so a doomed request does not stage a large copy;
     * the authoritative check re-runs under the mutex at publish. */
    if (ovc_file_check_destination_precondition(
            destination,
            if_dest,
            expected_destination_etag,
            &error) != 0) {
        goto done;
    }
    source_file = ovc_file_native_open_read(source);
    if (source_file == OVC_INVALID_FILE) {
        error = ovc_file_native_error(errno,
                                      "open copy source",
                                      source);
        goto done;
    }
    if (ovc_file_native_fstat(source_file, &before) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat copy source",
                                      source);
        goto done;
    }
    if (!before.is_regular) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Unsupported,
                               "copy source is not a regular file");
        goto done;
    }
    if (ovc_file_check_source_precondition(&before,
                                           expected_source_etag,
                                           OvStoragePlugin_ErrorCode_PreconditionFailed,
                                           &error) != 0) {
        goto done;
    }
    if (ovc_file_make_parent_directories(destination, &error) != 0) {
        goto done;
    }
    temporary = ovc_file_create_temp(destination,
                                     &destination_file,
                                     &error);
    if (temporary == NULL) {
        goto done;
    }
    buffer = (uint8_t *)ovc_file_allocate(OVC_FILE_IO_CHUNK_SIZE);
    offset = 0;
    while (offset < before.size) {
        size_t wanted;
        ovc_ssize_t received;
        size_t written;

        if (ovc_file_cancelled(task)) {
            error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                   "file copy was cancelled");
            goto done;
        }
        wanted = before.size - offset > OVC_FILE_IO_CHUNK_SIZE
                     ? OVC_FILE_IO_CHUNK_SIZE
                     : (size_t)(before.size - offset);
        received = ovc_pread(source_file, buffer, wanted, offset);
        if (received < 0) {
            error = ovc_file_native_error(errno,
                                          "read copy source",
                                          source);
            goto done;
        }
        if (received == 0) {
            error = ovc_file_error(OvStoragePlugin_ErrorCode_ObjectModified,
                                   "copy source became shorter while reading");
            goto done;
        }
        written = 0;
        while (written < (size_t)received) {
            ovc_ssize_t count;

            count = ovc_pwrite(destination_file,
                               buffer + written,
                               (size_t)received - written,
                               offset + (uint64_t)written);
            if (count < 0) {
                error = ovc_file_native_error(errno,
                                              "write staged copy",
                                              temporary);
                goto done;
            }
            if (count == 0) {
                error = ovc_file_error(OvStoragePlugin_ErrorCode_Transient,
                                       "staged copy made no write progress");
                goto done;
            }
            written += (size_t)count;
        }
        offset += (uint64_t)received;
    }
    if (ovc_file_native_fstat(source_file, &after) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat copy source after read",
                                      source);
        goto done;
    }
    if (!ovc_file_stat_identity_equal(&before, &after)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_ObjectModified,
                               "copy source changed while reading");
        goto done;
    }
#if defined(_WIN32)
    /* SetFileAttributesW may need a second path handle and the staging handle
     * intentionally does not share writes.  Flush/close first; the subsequent
     * MoveFileExW(MOVEFILE_WRITE_THROUGH) commits the copied attributes. */
    if (ovc_file_native_sync(destination_file) != 0) {
        error = ovc_file_native_error(errno,
                                      "sync staged copy",
                                      temporary);
        goto done;
    }
    if (ovc_file_native_close(destination_file) != 0) {
        destination_file = OVC_INVALID_FILE;
        error = ovc_file_native_error(errno,
                                      "close staged copy",
                                      temporary);
        goto done;
    }
    destination_file = OVC_INVALID_FILE;
    if (ovc_file_native_copy_permissions(source, temporary) != 0) {
        error = ovc_file_native_error(errno,
                                      "copy source permissions",
                                      source);
        goto done;
    }
#else
    if (ovc_file_native_copy_permissions(source, temporary) != 0) {
        error = ovc_file_native_error(errno,
                                      "copy source permissions",
                                      source);
        goto done;
    }
    if (ovc_file_native_sync(destination_file) != 0) {
        error = ovc_file_native_error(errno,
                                      "sync staged copy",
                                      temporary);
        goto done;
    }
    if (ovc_file_native_close(destination_file) != 0) {
        destination_file = OVC_INVALID_FILE;
        error = ovc_file_native_error(errno,
                                      "close staged copy",
                                      temporary);
        goto done;
    }
    destination_file = OVC_INVALID_FILE;
#endif
    if (ovc_file_native_close(source_file) != 0) {
        source_file = OVC_INVALID_FILE;
        error = ovc_file_native_error(errno,
                                      "close copy source",
                                      source);
        goto done;
    }
    source_file = OVC_INVALID_FILE;

    /* Publish window: only these re-checks, the rename, and the sidecar
     * mirror hold the layer mutex. */
    (void)ovc_mutex_lock(&task->layer->mutex);
    {
        ovc_file_stat current;

        if (ovc_file_cancelled(task)) {
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_Cancelled,
                "file copy was cancelled before publish");
        } else if (ovc_file_native_stat_path(source, &current) != 0) {
            error = ovc_file_native_error(errno,
                                          "re-stat copy source at publish",
                                          source);
        } else if (!ovc_file_stat_identity_equal(&before, &current)) {
            /* The staged bytes (and the sidecar about to be mirrored) no
             * longer describe the live source; publishing them would also
             * bypass a satisfied-at-staging if_source precondition. */
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_ObjectModified,
                "copy source changed before publish");
        } else if (ovc_file_check_destination_precondition(
                       destination,
                       if_dest,
                       expected_destination_etag,
                       &error) == 0) {
            if (ovc_file_native_rename_replace(temporary,
                                               destination) != 0) {
                error = ovc_file_native_error(errno,
                                              "publish copied file",
                                              destination);
            } else {
                published = true;
                if (ovc_file_native_sync_parent(destination) != 0) {
                    error = ovc_file_error(
                        OvStoragePlugin_ErrorCode_CommitAmbiguous,
                        "copied file was published but its directory sync failed for `%s`: %s",
                        destination,
                        ovc_file_strerror(errno));
                } else {
                    error = ovc_file_user_metadata_copy(source,
                                                        destination,
                                                        message,
                                                        NULL);
                    if (error == NULL &&
                        ovc_file_native_stat_path(destination,
                                                  out_info) != 0) {
                        error = ovc_file_native_error(errno,
                                                      "stat copied file",
                                                      destination);
                    }
                    if (error == NULL && move_source) {
                        /* Still inside the publish critical section: the
                         * identity re-check above proved the source is the
                         * staged content, and the held mutex keeps every
                         * other publish window out until the unlink lands.
                         * Failures here leave both names visible, so they
                         * report CommitAmbiguous — the file's convention for
                         * a transfer that committed but did not finish. */
                        if (ovc_file_native_unlink(source) != 0) {
                            error = ovc_file_error(
                                OvStoragePlugin_ErrorCode_CommitAmbiguous,
                                "cross-device rename copied `%s` to `%s` but could not delete the source: %s",
                                source,
                                destination,
                                ovc_file_strerror(errno));
                        } else if (ovc_file_native_sync_parent(source) != 0) {
                            error = ovc_file_error(
                                OvStoragePlugin_ErrorCode_CommitAmbiguous,
                                "cross-device rename deleted the source but its directory sync failed: %s",
                                ovc_file_strerror(errno));
                        } else {
                            error = ovc_file_user_metadata_remove_path(
                                source,
                                NULL);
                        }
                    }
                }
            }
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);

done:
    if (source_file != OVC_INVALID_FILE) {
        (void)ovc_file_native_close(source_file);
    }
    if (destination_file != OVC_INVALID_FILE) {
        (void)ovc_file_native_close(destination_file);
    }
    if (temporary != NULL && !published) {
        (void)ovc_file_native_unlink(temporary);
    }
    free(buffer);
    free(temporary);
    *out_error = error;
    return error == NULL ? 0 : -1;
}

static OvStoragePlugin_Error *ovc_file_delete_result(ovc_file_task *task)
{
    char *path;
    ovc_file_stat info;
    OvStoragePlugin_Error *error;
    bool removed;

    error = NULL;
    removed = false;
    path = ovc_file_resolve_path(task->layer,
                                 task->address,
                                 NULL,
                                 &error);
    if (path == NULL) {
        return error;
    }
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "file delete was cancelled");
    } else if (ovc_file_native_stat_path(path, &info) != 0) {
        int native_error;

        native_error = errno;
        if (native_error != ENOENT && native_error != ENOTDIR) {
            error = ovc_file_native_error(native_error,
                                          "stat file for delete",
                                          path);
        } else if (ovc_file_native_unlink(path) == 0) {
            /* stat(2) follows links.  A dangling symlink therefore looks
             * missing even though its directory entry still must be unlinked
             * for delete's Ok => name absent postcondition. */
            removed = true;
        } else if (errno != ENOENT && errno != ENOTDIR) {
            error = ovc_file_native_error(errno, "delete file", path);
        }
    } else if (ovc_file_check_source_precondition(
                   &info,
                   task->payload.delete_.if_match,
                   OvStoragePlugin_ErrorCode_PreconditionFailed,
                   &error) == 0) {
        if (ovc_file_native_unlink(path) == 0) {
            removed = true;
        } else {
            int native_error;

            native_error = errno;
            if (native_error != ENOENT && native_error != ENOTDIR) {
                error = ovc_file_native_error(native_error,
                                              "delete file",
                                              path);
            }
        }
    }
    if (error == NULL && removed &&
        ovc_file_native_sync_parent(path) != 0) {
        error = ovc_file_error(
            OvStoragePlugin_ErrorCode_CommitAmbiguous,
            "file was deleted but its directory sync failed for `%s`: %s",
            path,
            ovc_file_strerror(errno));
    }
    if (error == NULL) {
        /* Also cleans an orphaned sidecar for an already-missing object. */
        error = ovc_file_user_metadata_remove_path(path, NULL);
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    free(path);
    return error;
}

static OvStoragePlugin_Error *ovc_file_copy_result(
    ovc_file_task *task,
    OvStoragePlugin_WriteStep **out)
{
    char *source;
    char *destination;
    ovc_file_stat info;
    OvStoragePlugin_WriteStep *result;
    OvStoragePlugin_Error *error;

    error = NULL;
    source = ovc_file_resolve_path(task->layer,
                                   task->payload.transfer.source,
                                   NULL,
                                   &error);
    if (source == NULL) {
        return error;
    }
    destination = ovc_file_resolve_path(task->layer,
                                        task->payload.transfer.destination,
                                        NULL,
                                        &error);
    if (destination == NULL) {
        free(source);
        return error;
    }
    result = NULL;
    /* The bulk byte copy stages unlocked; ovc_file_copy_regular_staged takes
     * the layer mutex only for its short publish window. */
    if (ovc_file_copy_regular_staged(task,
                                     source,
                                     destination,
                                     task->payload.transfer.if_source,
                                     task->payload.transfer.if_dest,
                                     task->payload.transfer.match_etag,
                                     task->payload.transfer.message,
                                     false,
                                     &info,
                                     &error) == 0) {
        result = (OvStoragePlugin_WriteStep *)
            ovc_file_abi_callocate(1, sizeof(*result));
        result->tag = OvStoragePlugin_WriteStepTag_Done;
        error = ovc_file_object_info_fill(
            &result->done.info,
            task->payload.transfer.destination,
            destination,
            true,
            &info);
        if (error != NULL) {
            ovc_abi_free(result);
            result = NULL;
        }
    }
    free(source);
    free(destination);
    if (error == NULL) {
        *out = result;
    }
    return error;
}

static OvStoragePlugin_Error *ovc_file_rename_result(ovc_file_task *task)
{
    char *source;
    char *destination;
    ovc_file_stat source_info;
    OvStoragePlugin_Error *error;
    bool moved;
    bool cross_device;
    bool source_is_connection_root;
    bool destination_is_connection_root;

    error = NULL;
    source = ovc_file_resolve_path_and_root_flag(
        task->layer,
        task->payload.transfer.source,
        &source_is_connection_root,
        &error);
    if (source == NULL) {
        return error;
    }
    destination = ovc_file_resolve_path_and_root_flag(
        task->layer,
        task->payload.transfer.destination,
        &destination_is_connection_root,
        &error);
    if (destination == NULL) {
        free(source);
        return error;
    }
    if (source_is_connection_root || destination_is_connection_root) {
        free(source);
        free(destination);
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_PermissionDenied,
            "cannot rename a configured file root");
    }
    moved = false;
    cross_device = false;
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "file rename was cancelled");
    } else if (ovc_file_native_stat_path(source, &source_info) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat rename source",
                                      source);
    } else if (ovc_file_check_source_precondition(
                   &source_info,
                   task->payload.transfer.if_source,
                   OvStoragePlugin_ErrorCode_PreconditionFailed,
                   &error) != 0 ||
               ovc_file_check_destination_precondition(
                   destination,
                   task->payload.transfer.if_dest,
                   task->payload.transfer.match_etag,
                   &error) != 0 ||
               ovc_file_make_parent_directories(destination, &error) != 0) {
        /* `error` is populated by the failed helper. */
    } else if (strcmp(source, destination) == 0) {
        error = ovc_file_user_metadata_copy(
            source,
            destination,
            task->payload.transfer.message,
            task);
        moved = error == NULL;
    } else if (ovc_file_native_rename_replace(source, destination) == 0) {
        moved = true;
        if (ovc_file_native_sync_parent(destination) != 0 ||
            ovc_file_native_sync_parent(source) != 0) {
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_CommitAmbiguous,
                "renamed file was published but a directory sync failed: %s",
                ovc_file_strerror(errno));
        } else {
            error = ovc_file_user_metadata_copy(
                source,
                destination,
                task->payload.transfer.message,
                NULL);
            if (error == NULL) {
                error = ovc_file_user_metadata_remove_path(source, NULL);
            }
        }
    } else if (errno == EXDEV) {
        bool source_is_link;

        /* rename(2) cannot cross mount points.  The documented fallback is a
         * durable temp-sibling copy followed by source unlink.  It is
         * intentionally non-atomic: if the unlink fails, both names remain and
         * CommitAmbiguous tells the caller to reconcile. */
        if (ovc_file_native_path_is_link(source, &source_is_link) != 0) {
            error = ovc_file_native_error(errno,
                                          "inspect cross-device rename source",
                                          source);
        } else if (source_is_link) {
            /* A byte copy would silently turn the link into a regular file.
             * Preserve rename semantics by refusing this uncommon shape. */
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_Unsupported,
                "cross-device symlink rename is unsupported");
        } else if (source_info.is_directory) {
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_Unsupported,
                "cross-device directory rename is unsupported");
        } else {
            /* The bulk byte copy must not run under the layer mutex; fall
             * through to the staged copy below after unlocking. */
            cross_device = true;
        }
    } else {
        error = ovc_file_native_error(errno,
                                      "rename file",
                                      destination);
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    if (error == NULL && cross_device) {
        ovc_file_stat copied_info;

        /* Stage the fallback copy unlocked; the helper re-verifies the
         * source identity and the destination precondition under the mutex
         * at publish, so the checks made before rename(2) failed with EXDEV
         * cannot go stale unnoticed while the bytes are copied.  move_source
         * makes the helper retire the source inside that same critical
         * section: a write acknowledged after staging can never slip between
         * the publish and a separately-locked unlink and be destroyed. */
        if (ovc_file_copy_regular_staged(
                task,
                source,
                destination,
                task->payload.transfer.if_source,
                task->payload.transfer.if_dest,
                task->payload.transfer.match_etag,
                task->payload.transfer.message,
                true,
                &copied_info,
                &error) == 0) {
            moved = true;
        }
    }
    free(source);
    free(destination);
    (void)moved;
    return error;
}

static OvStoragePlugin_Error *ovc_file_update_metadata_result(
    ovc_file_task *task,
    OvStoragePlugin_BackendItemInfo **out)
{
    static char message_key_bytes[] = "x-ov-message";
    char *path;
    ovc_file_stat info;
    OvStoragePlugin_KeyValueList metadata;
    OvStoragePlugin_ObjectInfo object_info;
    OvStoragePlugin_BackendItemInfo *result;
    OvStoragePlugin_Error *error;
    size_t index;
    bool is_connection_root;

    error = NULL;
    path = ovc_file_resolve_path_and_root_flag(task->layer,
                                               task->address,
                                               &is_connection_root,
                                               &error);
    if (path == NULL) {
        return error;
    }
    if (is_connection_root) {
        free(path);
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_Unsupported,
            "user metadata on a configured file root is unsupported");
    }
    memset(&metadata, 0, sizeof(metadata));
    memset(&object_info, 0, sizeof(object_info));
    result = NULL;
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "metadata update was cancelled");
    } else if (ovc_file_native_stat_path(path, &info) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat metadata target",
                                      path);
    } else if (ovc_file_check_source_precondition(
                   &info,
                   task->payload.update_metadata.if_match,
                   OvStoragePlugin_ErrorCode_PreconditionFailed,
                   &error) == 0) {
        error = ovc_file_user_metadata_read(path, &metadata);
        if (error == NULL) {
            for (index = 0;
                 index < task->payload.update_metadata.remove.len;
                 ++index) {
                ovc_file_user_metadata_remove(
                    &metadata,
                    &task->payload.update_metadata.remove.ptr[index]);
            }
            for (index = 0;
                 index < task->payload.update_metadata.set.len;
                 ++index) {
                ovc_file_user_metadata_set(
                    &metadata,
                    &task->payload.update_metadata.set.ptr[index].key,
                    &task->payload.update_metadata.set.ptr[index].value);
            }
            if (task->payload.update_metadata.message != NULL &&
                task->payload.update_metadata.message[0] != '\0') {
                OvStoragePlugin_Str key;
                OvStoragePlugin_Str value;

                key.ptr = message_key_bytes;
                key.len = sizeof(message_key_bytes) - 1;
                value.ptr = task->payload.update_metadata.message;
                value.len = strlen(task->payload.update_metadata.message);
                ovc_file_user_metadata_set(&metadata, &key, &value);
            }
            error = ovc_file_user_metadata_write(path, &metadata, task);
        }
        if (error == NULL && ovc_file_native_stat_path(path, &info) != 0) {
            error = ovc_file_native_error(errno,
                                          "stat metadata target after update",
                                          path);
        }
        if (error == NULL) {
            error = ovc_file_object_info_fill(&object_info,
                                              task->address,
                                              path,
                                              true,
                                              &info);
        }
        if (error == NULL) {
            result = (OvStoragePlugin_BackendItemInfo *)
                ovc_file_abi_callocate(1, sizeof(*result));
            ovc_file_backend_item_info_take(result, &object_info);
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    ovc_file_key_value_list_clear(&metadata);
    ovc_file_object_info_clear(&object_info);
    free(path);
    if (error == NULL) {
        *out = result;
    }
    return error;
}

static OvStoragePlugin_Error *ovc_file_materialize_result(
    ovc_file_task *task,
    OvStoragePlugin_LocalDelegate **out)
{
    char *path;
    char *canonical;
    ovc_file_stat info;
    OvStoragePlugin_LocalDelegate *result;
    OvStoragePlugin_Error *error;

    error = NULL;
    if (task->payload.read.has_range) {
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "materialize does not accept a byte range");
    }
    path = ovc_file_resolve_path(task->layer,
                                 task->address,
                                 NULL,
                                 &error);
    if (path == NULL) {
        return error;
    }
    canonical = NULL;
    result = NULL;
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "file materialize was cancelled");
    } else if (ovc_file_native_stat_path(path, &info) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat materialize target",
                                      path);
    } else if (info.is_directory) {
        /* Ahead of the special-file branch: a directory is a type mismatch
         * the caller can fix, so it gets InvalidArgument + guidance like the
         * Rust reference (mod.rs reject_directory_target), while FIFOs,
         * sockets and devices stay Unsupported below. */
        error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                               "materialize target is a directory; use list()");
    } else if (!info.is_regular) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Unsupported,
                               "only regular files can be materialized");
    } else if (ovc_file_check_source_precondition(
                   &info,
                   task->payload.read.if_match,
                   OvStoragePlugin_ErrorCode_ObjectModified,
                   &error) == 0) {
        canonical = ovc_file_native_realpath(path);
        if (canonical == NULL) {
            error = ovc_file_native_error(errno,
                                          "resolve materialized file",
                                          path);
        } else {
            result = (OvStoragePlugin_LocalDelegate *)
                ovc_file_abi_callocate(1, sizeof(*result));
            result->path = ovc_file_owned_string(canonical);
            error = ovc_file_object_info_fill(&result->info,
                                              task->address,
                                              path,
                                              true,
                                              &info);
            if (error != NULL) {
                ovc_file_str_clear(&result->path);
                ovc_abi_free(result);
                result = NULL;
            }
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    free(canonical);
    free(path);
    if (error == NULL) {
        *out = result;
    }
    return error;
}

static OvStoragePlugin_Error *ovc_file_get_latest_version_result(
    ovc_file_task *task,
    OvStoragePlugin_ObjectInfo **out)
{
    OvStoragePlugin_ObjectInfo *result;
    OvStoragePlugin_Error *error;

    result = NULL;
    error = ovc_file_stat_result(task->layer,
                                 task->address,
                                 true,
                                 &result);
    if (error != NULL) {
        return error;
    }
    if (task->payload.read.if_match != NULL &&
        (!result->etag.present ||
         result->etag.value.len != strlen(task->payload.read.if_match) ||
         memcmp(result->etag.value.ptr,
                task->payload.read.if_match,
                result->etag.value.len) != 0)) {
        ovc_file_object_info_clear(result);
        ovc_abi_free(result);
        return ovc_file_error(OvStoragePlugin_ErrorCode_ObjectModified,
                              "latest-version etag does not match");
    }
    /* A local filesystem has no historical pin syntax.  Its single-version
     * model exposes the live ObjectInfo as the only/latest version, leaving
     * `version` absent and the address unchanged. */
    *out = result;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_list_versions_result(
    ovc_file_task *task,
    OvStoragePlugin_VersionPage **out)
{
    size_t start;
    OvStoragePlugin_ObjectInfo *current;
    OvStoragePlugin_VersionPage *page;
    OvStoragePlugin_Error *error;

    error = NULL;
    if (task->payload.list_versions.has_max_results &&
        task->payload.list_versions.max_results == 0) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "max_results must be greater than zero");
    }
    if (ovc_file_parse_page_token(task->payload.list_versions.page_token,
                                  &start,
                                  &error) != 0) {
        return error;
    }
    if (start > 1) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "version page token is past the only version");
    }
    page = (OvStoragePlugin_VersionPage *)
        ovc_file_abi_callocate(1, sizeof(*page));
    page->items.ptr = (OvStoragePlugin_ObjectInfo *)
        ovc_file_abi_callocate(1, sizeof(*page->items.ptr));
    page->items.len = 0;
    if (start == 0) {
        current = NULL;
        error = ovc_file_stat_result(task->layer,
                                     task->address,
                                     true,
                                     &current);
        if (error != NULL) {
            ovc_abi_free(page->items.ptr);
            ovc_abi_free(page);
            return error;
        }
        page->items.ptr[0] = *current;
        page->items.len = 1;
        ovc_abi_free(current);
    }
    /* See get_latest_version: the live state is the sole entry, so no
     * continuation token or synthetic query-string pin is invented. */
    *out = page;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_create_directory_result(
    ovc_file_task *task,
    OvStoragePlugin_BackendItemInfo **out)
{
    char *path;
    ovc_file_stat info;
    OvStoragePlugin_ObjectInfo object_info;
    OvStoragePlugin_BackendItemInfo *result;
    OvStoragePlugin_Error *error;
    bool is_connection_root;

    error = NULL;
    path = ovc_file_resolve_path_and_root_flag(task->layer,
                                               task->address,
                                               &is_connection_root,
                                               &error);
    if (path == NULL) {
        return error;
    }
    memset(&object_info, 0, sizeof(object_info));
    result = NULL;
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "create_directory was cancelled");
    } else if (ovc_file_make_directories(path, &error) == 0 &&
               ovc_file_native_stat_path(path, &info) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat created directory",
                                      path);
    } else if (error == NULL) {
        error = ovc_file_object_info_fill(&object_info,
                                          task->address,
                                          path,
                                          !is_connection_root,
                                          &info);
        if (error == NULL) {
            result = (OvStoragePlugin_BackendItemInfo *)
                ovc_file_abi_callocate(1, sizeof(*result));
            ovc_file_backend_item_info_take(result, &object_info);
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    ovc_file_object_info_clear(&object_info);
    free(path);
    if (error == NULL) {
        *out = result;
    }
    return error;
}

static bool ovc_file_is_cleared_by_directory_removal(const char *name);
#if defined(_WIN32)
static char *ovc_file_wide_name_to_utf8(const wchar_t *wide);
#endif

/* delete_directory support, mirroring the reference (mod.rs
 * delete_directory + metadata.rs remove_directory_metadata_dir): first
 * verify the directory holds no user-visible entries, then remove the
 * .ovstorage-meta sidecar dir with remove_dir_all semantics so an orphaned
 * sidecar (object removed out-of-band) or a crashed metadata staging temp
 * *inside that sidecar dir* does not leave a visually-empty directory
 * undeletable through the API.  That covers the sidecar namespace only; an
 * orphaned object staging temp is a sibling of the object, not a child of
 * the sidecar dir, and the paragraph below says what happens to it.
 * Entries inside .ovstorage-meta are backend-owned by construction — the
 * namespace is unaddressable through URL resolution — so they are unlinked
 * without inspection.
 *
 * The scan ignores exactly one name, .ovstorage-meta, which the cleanup
 * below clears; every other entry blocks the rmdir, so for the entries the
 * API can create the scan reaches the verdict the rmdir would.  An
 * atomic-write staging temp is the
 * case that makes this matter: it is hidden from list and watch because it
 * is not yet an object, but the kernel counts it, so a directory holding an
 * in-flight write is reported here as the DirectoryNotEmpty it is instead of
 * scanning as empty, losing its sidecar dir, and only then failing the
 * rmdir.  An entry created after the scan still fails the rmdir with
 * ENOTEMPTY, which the errno table maps to the same DirectoryNotEmpty.
 *
 * A staging temp whose writer died holds its directory the same way, and
 * no API call clears it: enumeration hides it and URL resolution refuses
 * to address it, so the refusal stands until something outside the API
 * removes the file.  The rmdir refuses over it either way, and the errno
 * table gives that refusal the same DirectoryNotEmpty either way; what the
 * scan decides here is whether the sidecar dir is destroyed first. */

#if defined(_WIN32)

static OvStoragePlugin_Error *ovc_file_directory_reject_visible_entries(
    const char *path)
{
    char *pattern;
    wchar_t *pattern_wide;
    WIN32_FIND_DATAW entry;
    HANDLE find;
    OvStoragePlugin_Error *error;

    pattern = ovc_path_join(path, "*");
    if (pattern == NULL) {
        return ovc_file_native_error(errno, "build delete scan pattern", path);
    }
    pattern_wide = ovc_file_utf8_to_wide(pattern);
    free(pattern);
    if (pattern_wide == NULL) {
        return ovc_file_native_error(errno, "encode delete scan pattern", path);
    }
    find = FindFirstFileW(pattern_wide, &entry);
    free(pattern_wide);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD native_error;

        native_error = GetLastError();
        if (native_error == ERROR_FILE_NOT_FOUND) {
            return NULL;
        }
        ovc_win32_set_errno(native_error);
        return ovc_file_native_error(errno, "scan directory for delete", path);
    }
    error = NULL;
    do {
        char *name;

        name = ovc_file_wide_name_to_utf8(entry.cFileName);
        if (name == NULL) {
            error = ovc_file_native_error(errno,
                                          "decode directory entry",
                                          path);
            break;
        }
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0 &&
            !ovc_file_is_cleared_by_directory_removal(name)) {
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                "directory is not empty");
            free(name);
            break;
        }
        free(name);
    } while (FindNextFileW(find, &entry));
    if (error == NULL && GetLastError() != ERROR_NO_MORE_FILES) {
        ovc_win32_set_errno(GetLastError());
        error = ovc_file_native_error(errno,
                                      "iterate directory for delete",
                                      path);
    }
    FindClose(find);
    return error;
}

/* True when the attributes describe a reparse point (junction or symlink):
 * such an entry is a link and must be removed as the link itself, never
 * traversed -- FindFirstFileW / opendir would otherwise enumerate the
 * target and the sweep would delete data outside the sidecar namespace. */
#if !defined(IsReparseTagNameSurrogate)
#define IsReparseTagNameSurrogate(tag) (((tag) & 0x20000000) != 0)
#endif

/*
 * True only for a reparse point whose tag is a NAME SURROGATE (symlink,
 * mount point / junction): those redirect the namespace, so they are the
 * links std::fs::remove_dir_all removes without traversing.  Non-surrogate
 * directory reparse points -- OneDrive Files-On-Demand cloud placeholders,
 * ProjFS, WCI -- are real directories whose children live under them, and
 * the reference recurses into them; classifying them as links would call
 * RemoveDirectoryW on a non-empty directory (ERROR_DIR_NOT_EMPTY) and make
 * it permanently undeletable.  `reparse_tag` is WIN32_FIND_DATAW.dwReserved0
 * for a found entry (valid only when FILE_ATTRIBUTE_REPARSE_POINT is set).
 */
static bool ovc_file_win32_attributes_are_link(DWORD attributes,
                                               DWORD reparse_tag)
{
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 &&
           IsReparseTagNameSurrogate(reparse_tag);
}

static OvStoragePlugin_Error *ovc_file_metadata_directory_remove_all(
    const char *metadata_directory)
{
    char *pattern;
    wchar_t *root_wide;
    wchar_t *pattern_wide;
    WIN32_FIND_DATAW root_entry;
    WIN32_FIND_DATAW entry;
    HANDLE root_find;
    HANDLE find;
    OvStoragePlugin_Error *error;
    DWORD root_attributes;
    DWORD root_reparse_tag;

    /*
     * Classify the root without following it.  Rust's remove_dir_all removes
     * a name-surrogate reparse point (symlink / junction) as the link itself
     * rather than traversing it.  FindFirstFileW on the root PATH (not the
     * "\\*" pattern) fills dwReserved0 with the reparse tag, which
     * GetFileAttributesW cannot report -- needed to tell a symlink/junction
     * apart from a non-surrogate directory reparse point (a cloud
     * placeholder / ProjFS directory) that must be recursed into.
     */
    root_wide = ovc_file_utf8_to_wide(metadata_directory);
    if (root_wide == NULL) {
        return ovc_file_native_error(errno,
                                     "encode internal metadata directory",
                                     metadata_directory);
    }
    root_find = FindFirstFileW(root_wide, &root_entry);
    free(root_wide);
    if (root_find == INVALID_HANDLE_VALUE) {
        DWORD native_error;

        native_error = GetLastError();
        if (native_error == ERROR_FILE_NOT_FOUND ||
            native_error == ERROR_PATH_NOT_FOUND) {
            return NULL;
        }
        ovc_win32_set_errno(native_error);
        return ovc_file_native_error(errno,
                                     "inspect internal metadata directory",
                                     metadata_directory);
    }
    root_attributes = root_entry.dwFileAttributes;
    root_reparse_tag = root_entry.dwReserved0;
    FindClose(root_find);
    if (ovc_file_win32_attributes_are_link(root_attributes,
                                           root_reparse_tag) ||
        (root_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        /* A name-surrogate link or a non-directory: remove the entry itself.
         * RemoveDirectoryW removes a directory reparse point without
         * following it; DeleteFileW removes a file or file symlink. */
        int removed;

        removed = (root_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                      ? ovc_file_native_rmdir(metadata_directory)
                      : ovc_file_native_unlink(metadata_directory);
        if (removed != 0 && errno != ENOENT && errno != ENOTDIR) {
            return ovc_file_native_error(errno,
                                         "remove internal metadata entry",
                                         metadata_directory);
        }
        return NULL;
    }

    pattern = ovc_path_join(metadata_directory, "*");
    if (pattern == NULL) {
        return ovc_file_native_error(errno,
                                     "build metadata scan pattern",
                                     metadata_directory);
    }
    pattern_wide = ovc_file_utf8_to_wide(pattern);
    free(pattern);
    if (pattern_wide == NULL) {
        return ovc_file_native_error(errno,
                                     "encode metadata scan pattern",
                                     metadata_directory);
    }
    find = FindFirstFileW(pattern_wide, &entry);
    free(pattern_wide);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD native_error;

        native_error = GetLastError();
        if (native_error == ERROR_FILE_NOT_FOUND ||
            native_error == ERROR_PATH_NOT_FOUND) {
            return NULL;
        }
        ovc_win32_set_errno(native_error);
        return ovc_file_native_error(errno,
                                     "open internal metadata directory",
                                     metadata_directory);
    }
    error = NULL;
    do {
        char *name;
        char *child;

        name = ovc_file_wide_name_to_utf8(entry.cFileName);
        if (name == NULL) {
            error = ovc_file_native_error(errno,
                                          "decode internal metadata entry",
                                          metadata_directory);
            break;
        }
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            free(name);
            continue;
        }
        child = ovc_path_join(metadata_directory, name);
        free(name);
        if (child == NULL) {
            error = ovc_file_native_error(errno,
                                          "join internal metadata entry",
                                          metadata_directory);
            break;
        }
        if (ovc_file_win32_attributes_are_link(entry.dwFileAttributes,
                                               entry.dwReserved0)) {
            /* A name-surrogate reparse point (symlink or junction): remove
             * the link, never recurse into it.  RemoveDirectoryW unlinks a
             * directory reparse point; DeleteFileW a file symlink. */
            int removed;

            removed = (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                          ? ovc_file_native_rmdir(child)
                          : ovc_file_native_unlink(child);
            if (removed != 0 && errno != ENOENT && errno != ENOTDIR) {
                error = ovc_file_native_error(errno,
                                              "remove internal metadata entry",
                                              child);
                free(child);
                break;
            }
        } else if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            /* A real subdirectory (out-of-band creation or a foreign tool's
             * leftovers) would fail DeleteFileW forever and make the parent
             * undeletable.  Mirror the reference's remove_dir_all and
             * recurse; depth is bounded by the backend-internal sidecar
             * namespace, not by caller input. */
            error = ovc_file_metadata_directory_remove_all(child);
            if (error != NULL) {
                free(child);
                break;
            }
        } else if (ovc_file_native_unlink(child) != 0 && errno != ENOENT) {
            error = ovc_file_native_error(errno,
                                          "remove internal metadata entry",
                                          child);
            free(child);
            break;
        }
        free(child);
    } while (FindNextFileW(find, &entry));
    if (error == NULL && GetLastError() != ERROR_NO_MORE_FILES) {
        ovc_win32_set_errno(GetLastError());
        error = ovc_file_native_error(errno,
                                      "iterate internal metadata directory",
                                      metadata_directory);
    }
    FindClose(find);
    if (error == NULL && ovc_file_native_rmdir(metadata_directory) != 0 &&
        errno != ENOENT && errno != ENOTDIR) {
        error = ovc_file_native_error(errno,
                                      "remove internal metadata directory",
                                      metadata_directory);
    }
    return error;
}

#else

static OvStoragePlugin_Error *ovc_file_directory_reject_visible_entries(
    const char *path)
{
    DIR *directory;
    struct dirent *entry;
    OvStoragePlugin_Error *error;

    directory = opendir(path);
    if (directory == NULL) {
        return ovc_file_native_error(errno,
                                     "scan directory for delete",
                                     path);
    }
    error = NULL;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            ovc_file_is_cleared_by_directory_removal(entry->d_name)) {
            errno = 0;
            continue;
        }
        error = ovc_file_error(OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                               "directory is not empty");
        break;
    }
    if (error == NULL && errno != 0) {
        error = ovc_file_native_error(errno,
                                      "iterate directory for delete",
                                      path);
    }
    (void)closedir(directory);
    return error;
}

static OvStoragePlugin_Error *ovc_file_metadata_directory_remove_all(
    const char *metadata_directory)
{
    DIR *directory;
    struct dirent *entry;
    OvStoragePlugin_Error *error;
    bool exists;
    bool is_link;
    bool is_dir;

    /*
     * Classify the root without following a final symlink.  Rust's
     * remove_dir_all removes a symlink as the link itself rather than
     * traversing it, so a symlinked `.ovstorage-meta` (planted by a foreign
     * tool or an attacker) must be unlinked, never opened, or the recursion
     * below would enumerate and delete the link target's tree and report
     * success.  A missing path is nothing to do.  (POSIX has no non-symlink
     * reparse points; the Win32 variant additionally distinguishes
     * name-surrogate reparse points from real cloud/ProjFS directories.)
     */
    if (ovc_file_native_lstat_kind(metadata_directory,
                                   &exists,
                                   &is_link,
                                   &is_dir) != 0) {
        return ovc_file_native_error(errno,
                                     "inspect internal metadata directory",
                                     metadata_directory);
    }
    if (!exists) {
        return NULL;
    }
    if (is_link || !is_dir) {
        /* A link or a non-directory: unlink the entry itself. */
        if (ovc_file_native_unlink(metadata_directory) != 0 &&
            errno != ENOENT) {
            return ovc_file_native_error(errno,
                                         "remove internal metadata entry",
                                         metadata_directory);
        }
        return NULL;
    }

    directory = opendir(metadata_directory);
    if (directory == NULL) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return NULL;
        }
        return ovc_file_native_error(errno,
                                     "open internal metadata directory",
                                     metadata_directory);
    }
    error = NULL;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *child;
        bool child_exists;
        bool child_is_link;
        bool child_is_dir;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            errno = 0;
            continue;
        }
        child = ovc_path_join(metadata_directory, entry->d_name);
        if (child == NULL) {
            error = ovc_file_native_error(errno,
                                          "join internal metadata entry",
                                          metadata_directory);
            break;
        }
        if (ovc_file_native_lstat_kind(child,
                                       &child_exists,
                                       &child_is_link,
                                       &child_is_dir) != 0) {
            error = ovc_file_native_error(errno,
                                          "inspect internal metadata entry",
                                          child);
            free(child);
            break;
        }
        if (child_exists && child_is_dir && !child_is_link) {
            /* A real subdirectory (out-of-band creation or a foreign tool's
             * leftovers) would make the parent undeletable forever; mirror
             * the reference's remove_dir_all and recurse.  Depth is bounded
             * by the backend-internal sidecar namespace.  A symlink or
             * junction is NOT a directory here: it falls through to the
             * unlink below, which removes the link, never its target. */
            error = ovc_file_metadata_directory_remove_all(child);
            if (error != NULL) {
                free(child);
                break;
            }
        } else if (ovc_file_native_unlink(child) != 0 && errno != ENOENT) {
            error = ovc_file_native_error(errno,
                                          "remove internal metadata entry",
                                          child);
            free(child);
            break;
        }
        free(child);
        errno = 0;
    }
    if (error == NULL && errno != 0) {
        error = ovc_file_native_error(errno,
                                      "iterate internal metadata directory",
                                      metadata_directory);
    }
    (void)closedir(directory);
    if (error == NULL && ovc_file_native_rmdir(metadata_directory) != 0 &&
        errno != ENOENT && errno != ENOTDIR) {
        error = ovc_file_native_error(errno,
                                      "remove internal metadata directory",
                                      metadata_directory);
    }
    return error;
}

#endif

static OvStoragePlugin_Error *ovc_file_delete_directory_result(
    ovc_file_task *task)
{
    char *path;
    char *metadata_directory;
    OvStoragePlugin_Error *error;
    bool is_connection_root;

    error = NULL;
    path = ovc_file_resolve_path_and_root_flag(task->layer,
                                               task->address,
                                               &is_connection_root,
                                               &error);
    if (path == NULL) {
        return error;
    }
    if (is_connection_root) {
        free(path);
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_PermissionDenied,
            "cannot delete a configured file root");
    }
    metadata_directory = ovc_path_join(path, OVC_FILE_METADATA_DIRECTORY);
    if (metadata_directory == NULL) {
        error = ovc_file_native_error(errno,
                                      "build directory metadata path",
                                      path);
        free(path);
        return error;
    }
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "delete_directory was cancelled");
    } else {
        /* Reference order: refuse a directory that still holds user-visible
         * entries BEFORE touching the sidecar dir, so a failed delete can
         * never destroy live objects' metadata as a side effect. */
        error = ovc_file_directory_reject_visible_entries(path);
        if (error == NULL) {
            error = ovc_file_metadata_directory_remove_all(
                metadata_directory);
        }
        if (error == NULL && ovc_file_native_rmdir(path) != 0) {
            error = ovc_file_native_error(errno,
                                          "delete directory",
                                          path);
        }
        if (error == NULL && ovc_file_native_sync_parent(path) != 0) {
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_CommitAmbiguous,
                "directory was deleted but its parent sync failed for `%s`: %s",
                path,
                ovc_file_strerror(errno));
        }
        if (error == NULL) {
            error = ovc_file_user_metadata_remove_path(path, NULL);
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    free(metadata_directory);
    free(path);
    return error;
}

static OvStoragePlugin_Error *ovc_file_check_access_result(
    ovc_file_task *task,
    OvStoragePlugin_AccessDecision **out)
{
    char *path;
    char *parent;
    ovc_file_stat info;
    ovc_file_stat parent_info;
    OvStoragePlugin_AccessDecision *result;
    OvStoragePlugin_Error *error;
    bool parent_readonly;
    bool is_connection_root;

    error = NULL;
    path = ovc_file_resolve_path_and_root_flag(task->layer,
                                               task->address,
                                               &is_connection_root,
                                               &error);
    if (path == NULL) {
        return error;
    }
    if (ovc_file_native_stat_path(path, &info) != 0) {
        error = ovc_file_native_error(errno,
                                      "stat access-check target",
                                      path);
        free(path);
        return error;
    }
    /* Reference decision model (mod.rs check_access): the TARGET's read-only
     * bit denies write and update_metadata; delete is denied when the target
     * OR its parent is read-only (delete unlinks the dentry from the parent,
     * so a read-only parent denies it even for a writable file).  A missing
     * parent (filesystem root) counts as writable, and read on an existing,
     * stat-able entry is never denied. */
    parent_readonly = false;
    if (task->payload.check_access.operations.delete_) {
        parent = ovc_file_parent_path(path);
        if (parent[0] != '\0' && strcmp(parent, path) != 0) {
            if (ovc_file_native_stat_path(parent, &parent_info) != 0) {
                error = ovc_file_native_error(errno,
                                              "stat access-check parent",
                                              parent);
                free(parent);
                free(path);
                return error;
            }
            parent_readonly = parent_info.readonly;
        }
        free(parent);
    }
    free(path);
    result = (OvStoragePlugin_AccessDecision *)
        ovc_file_abi_callocate(1, sizeof(*result));
    if (task->payload.check_access.operations.write && info.readonly) {
        result->denied_ops.write = true;
    }
    if (task->payload.check_access.operations.delete_ &&
        (info.readonly || parent_readonly)) {
        result->denied_ops.delete_ = true;
    }
    if (task->payload.check_access.operations.update_metadata &&
        (info.readonly || is_connection_root)) {
        /* is_connection_root: this backend rejects user metadata on a
         * configured root (see ovc_file_update_metadata_result), so the
         * decision reports what update_metadata would actually do. */
        result->denied_ops.update_metadata = true;
    }
    result->allowed = !result->denied_ops.read &&
                      !result->denied_ops.write &&
                      !result->denied_ops.delete_ &&
                      !result->denied_ops.update_metadata;
    if (!result->allowed) {
        result->reason.present = true;
        result->reason.value = ovc_file_owned_string(
            "filesystem metadata denies at least one requested operation");
    }
    *out = result;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Directory enumeration and decimal-offset pagination. */

/* True for the entry name a directory removal clears itself, so the
 * delete-emptiness scan may ignore it: .ovstorage-meta, which
 * ovc_file_metadata_directory_remove_all clears immediately before the
 * rmdir.  This matches the name; that cleanup classifies what the name
 * holds and clears a link or a non-directory outright, which is what the
 * Rust host does for the same occupant.
 *
 * Deliberately narrower than ovc_file_is_internal_entry.  An atomic-write
 * staging temp is internal — enumeration hides it because it is not yet an
 * object — but it is a real directory entry that the kernel counts, so the
 * rmdir refuses while one is present.  A delete scan that skipped it would
 * call the directory empty, destroy the sidecar dir, and only then fail the
 * removal.  For the entries the API can create, this predicate keeps the
 * backend's notion of "empty" identical to the kernel's.  The scan, the
 * cleanup's classification and its removal are separate calls, so an entry
 * that appears or changes kind between them is decided by the kernel at the
 * rmdir. */
static bool ovc_file_is_cleared_by_directory_removal(const char *name)
{
#if defined(_WIN32)
    return strlen(name) == sizeof(".ovstorage-meta") - 1 &&
           ovc_file_ascii_equal_nocase(name,
                                       ".ovstorage-meta",
                                       sizeof(".ovstorage-meta") - 1);
#else
    return strcmp(name, ".ovstorage-meta") == 0;
#endif
}

/* True for an entry enumeration must hide: the sidecar dir and an
 * atomic-write staging temp, neither of which is a caller-visible object. */
static bool ovc_file_is_internal_entry(const char *name)
{
    if (ovc_file_is_cleared_by_directory_removal(name)) {
        return true;
    }
    return ovc_file_is_atomic_temp_name_n(name, strlen(name));
}

static char *ovc_file_encode_url_segment(const char *name)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t length;
    size_t encoded_length;
    size_t index;
    size_t cursor;
    char *encoded;

    length = strlen(name);
    encoded_length = 0;
    for (index = 0; index < length; ++index) {
        unsigned char byte;

        byte = (unsigned char)name[index];
        encoded_length += ((byte >= 'a' && byte <= 'z') ||
                           (byte >= 'A' && byte <= 'Z') ||
                           (byte >= '0' && byte <= '9') || byte == '-' ||
                           byte == '_' || byte == '.' || byte == '~')
                              ? 1
                              : 3;
    }
    encoded = (char *)ovc_file_allocate(encoded_length + 1);
    cursor = 0;
    for (index = 0; index < length; ++index) {
        unsigned char byte;

        byte = (unsigned char)name[index];
        if ((byte >= 'a' && byte <= 'z') ||
            (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' ||
            byte == '.' || byte == '~') {
            encoded[cursor++] = (char)byte;
        } else {
            encoded[cursor++] = '%';
            encoded[cursor++] = hex[byte >> 4];
            encoded[cursor++] = hex[byte & 0x0f];
        }
    }
    encoded[cursor] = '\0';
    return encoded;
}

static char *ovc_file_join_address(const char *base,
                                   const char *name,
                                   bool directory)
{
    char *encoded;
    size_t base_length;
    size_t encoded_length;
    size_t length;
    size_t cursor;
    char *address;

    encoded = ovc_file_encode_url_segment(name);
    base_length = strlen(base);
    encoded_length = strlen(encoded);
    length = base_length + (base_length != 0 && base[base_length - 1] == '/'
                                ? 0
                                : 1) +
             encoded_length + (directory ? 1 : 0);
    address = (char *)ovc_file_allocate(length + 1);
    memcpy(address, base, base_length);
    cursor = base_length;
    if (cursor == 0 || address[cursor - 1] != '/') {
        address[cursor++] = '/';
    }
    memcpy(address + cursor, encoded, encoded_length);
    cursor += encoded_length;
    if (directory) {
        address[cursor++] = '/';
    }
    address[cursor] = '\0';
    free(encoded);
    return address;
}

/* The staging vector itself is host-internal (plain realloc/free): only the
 * ObjectInfo *contents* are ABI-owned, and they are moved into the
 * ABI-minted page array before the page crosses the ABI. */
static int ovc_file_item_vector_push(ovc_file_item_vector *vector,
                                     OvStoragePlugin_ObjectInfo *item)
{
    if (vector->len == vector->capacity) {
        size_t next_capacity;
        OvStoragePlugin_ObjectInfo *next;

        next_capacity = vector->capacity == 0 ? 16 : vector->capacity * 2;
        if (next_capacity < vector->capacity ||
            next_capacity > SIZE_MAX / sizeof(*next)) {
            return -1;
        }
        next = (OvStoragePlugin_ObjectInfo *)realloc(
            vector->items, next_capacity * sizeof(*next));
        if (next == NULL) {
            return -1;
        }
        vector->items = next;
        vector->capacity = next_capacity;
    }
    vector->items[vector->len++] = *item;
    memset(item, 0, sizeof(*item));
    return 0;
}

static void ovc_file_item_vector_clear(ovc_file_item_vector *vector)
{
    size_t index;

    for (index = 0; index < vector->len; ++index) {
        ovc_file_object_info_clear(&vector->items[index]);
    }
    free(vector->items);
    memset(vector, 0, sizeof(*vector));
}

#if defined(_WIN32)

static char *ovc_file_wide_name_to_utf8(const wchar_t *wide)
{
    int length;
    char *utf8;

    length = WideCharToMultiByte(CP_UTF8,
                                 WC_ERR_INVALID_CHARS,
                                 wide,
                                 -1,
                                 NULL,
                                 0,
                                 NULL,
                                 NULL);
    if (length <= 0) {
        ovc_win32_set_errno(GetLastError());
        return NULL;
    }
    utf8 = (char *)malloc((size_t)length);
    if (utf8 == NULL) {
        return NULL;
    }
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            wide,
                            -1,
                            utf8,
                            length,
                            NULL,
                            NULL) <= 0) {
        DWORD error;

        error = GetLastError();
        free(utf8);
        ovc_win32_set_errno(error);
        return NULL;
    }
    return utf8;
}

static OvStoragePlugin_Error *ovc_file_collect_list(
    ovc_file_task *task,
    const char *path,
    const char *address,
    ovc_file_item_vector *items)
{
    char *pattern;
    wchar_t *pattern_wide;
    WIN32_FIND_DATAW entry;
    HANDLE find;
    OvStoragePlugin_Error *error;

    pattern = ovc_path_join(path, "*");
    if (pattern == NULL) {
        return ovc_file_native_error(errno, "build list pattern", path);
    }
    pattern_wide = ovc_file_utf8_to_wide(pattern);
    free(pattern);
    if (pattern_wide == NULL) {
        return ovc_file_native_error(errno, "encode list pattern", path);
    }
    find = FindFirstFileW(pattern_wide, &entry);
    free(pattern_wide);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD native_error;

        native_error = GetLastError();
        if (native_error == ERROR_FILE_NOT_FOUND) {
            return NULL;
        }
        ovc_win32_set_errno(native_error);
        return ovc_file_native_error(errno, "list directory", path);
    }
    error = NULL;
    do {
        char *name;
        char *child_path;
        char *child_address;
        ovc_file_stat native;
        OvStoragePlugin_ObjectInfo item;

        if (ovc_file_cancelled(task)) {
            error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                   "file list was cancelled");
            break;
        }
        name = ovc_file_wide_name_to_utf8(entry.cFileName);
        if (name == NULL) {
            error = ovc_file_native_error(errno, "decode directory entry", path);
            break;
        }
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
            ovc_file_is_internal_entry(name)) {
            free(name);
            continue;
        }
        child_path = ovc_path_join(path, name);
        child_address = NULL;
        if (child_path == NULL ||
            ovc_file_native_stat_path(child_path, &native) != 0) {
            int native_error;

            native_error = errno;
            error = ovc_file_native_error(native_error,
                                          "stat directory entry",
                                          child_path == NULL ? path : child_path);
            free(child_path);
            free(name);
            break;
        }
        child_address = ovc_file_join_address(address,
                                              name,
                                              native.is_directory);
        {
            OvStoragePlugin_Error *scope_error;
            char *checked_path;

            scope_error = NULL;
            checked_path = ovc_file_resolve_path(task->layer,
                                                 child_address,
                                                 NULL,
                                                 &scope_error);
            if (checked_path == NULL) {
                /* An entry whose re-resolve fails — typically an in-root
                 * symlink whose target lies outside the configured root —
                 * is SKIPPED rather than failing the whole listing.  The
                 * Rust reference lists such directories fine (it never
                 * containment-checks children); the containment error is
                 * reserved for operations that dereference an address. */
                ovc_file_error_destroy(scope_error);
                free(child_address);
                free(child_path);
                free(name);
                continue;
            }
            free(checked_path);
        }
        memset(&item, 0, sizeof(item));
        error = ovc_file_object_info_fill(&item,
                                          child_address,
                                          child_path,
                                          task->payload.list.full_metadata,
                                          &native);
        if (error != NULL) {
            free(child_address);
            free(child_path);
            free(name);
            break;
        }
        if (ovc_file_item_vector_push(items, &item) != 0) {
            ovc_file_object_info_clear(&item);
            error = ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                                   "file list is too large");
            free(child_address);
            free(child_path);
            free(name);
            break;
        }
        if (task->payload.list.recursive && native.is_directory &&
            (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
            error = ovc_file_collect_list(task,
                                          child_path,
                                          child_address,
                                          items);
        }
        free(child_address);
        free(child_path);
        free(name);
        if (error != NULL) {
            break;
        }
    } while (FindNextFileW(find, &entry));
    if (error == NULL && GetLastError() != ERROR_NO_MORE_FILES) {
        ovc_win32_set_errno(GetLastError());
        error = ovc_file_native_error(errno, "iterate directory", path);
    }
    FindClose(find);
    return error;
}

#else

static OvStoragePlugin_Error *ovc_file_collect_list(
    ovc_file_task *task,
    const char *path,
    const char *address,
    ovc_file_item_vector *items)
{
    DIR *directory;
    struct dirent *entry;
    OvStoragePlugin_Error *error;

    directory = opendir(path);
    if (directory == NULL) {
        return ovc_file_native_error(errno, "list directory", path);
    }
    error = NULL;
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        char *child_path;
        char *child_address;
        struct stat link_info;
        ovc_file_stat native;
        OvStoragePlugin_ObjectInfo item;

        if (ovc_file_cancelled(task)) {
            error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                   "file list was cancelled");
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0 ||
            ovc_file_is_internal_entry(entry->d_name)) {
            errno = 0;
            continue;
        }
        child_path = ovc_path_join(path, entry->d_name);
        if (child_path == NULL) {
            error = ovc_file_native_error(errno, "join directory entry", path);
            break;
        }
        if (fstatat(AT_FDCWD,
                    child_path,
                    &link_info,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            ovc_file_native_stat_path(child_path, &native) != 0) {
            int native_error;

            native_error = errno;
            error = ovc_file_native_error(native_error,
                                          "stat directory entry",
                                          child_path);
            free(child_path);
            break;
        }
        child_address = ovc_file_join_address(address,
                                              entry->d_name,
                                              native.is_directory);
        {
            OvStoragePlugin_Error *scope_error;
            char *checked_path;

            scope_error = NULL;
            checked_path = ovc_file_resolve_path(task->layer,
                                                 child_address,
                                                 NULL,
                                                 &scope_error);
            if (checked_path == NULL) {
                /* An entry whose re-resolve fails — typically an in-root
                 * symlink whose target lies outside the configured root —
                 * is SKIPPED rather than failing the whole listing.  The
                 * Rust reference lists such directories fine (it never
                 * containment-checks children); the containment error is
                 * reserved for operations that dereference an address. */
                ovc_file_error_destroy(scope_error);
                free(child_address);
                free(child_path);
                errno = 0;
                continue;
            }
            free(checked_path);
        }
        memset(&item, 0, sizeof(item));
        error = ovc_file_object_info_fill(&item,
                                          child_address,
                                          child_path,
                                          task->payload.list.full_metadata,
                                          &native);
        if (error != NULL) {
            free(child_address);
            free(child_path);
            break;
        }
        if (ovc_file_item_vector_push(items, &item) != 0) {
            ovc_file_object_info_clear(&item);
            free(child_address);
            free(child_path);
            error = ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                                   "file list is too large");
            break;
        }
        if (task->payload.list.recursive && native.is_directory &&
            !S_ISLNK(link_info.st_mode)) {
            error = ovc_file_collect_list(task,
                                          child_path,
                                          child_address,
                                          items);
        }
        free(child_address);
        free(child_path);
        if (error != NULL) {
            break;
        }
        errno = 0;
    }
    if (error == NULL && errno != 0) {
        error = ovc_file_native_error(errno, "iterate directory", path);
    }
    (void)closedir(directory);
    return error;
}

#endif

static int ovc_file_compare_items(const void *left, const void *right)
{
    const OvStoragePlugin_ObjectInfo *left_info;
    const OvStoragePlugin_ObjectInfo *right_info;
    size_t common;
    int comparison;

    left_info = (const OvStoragePlugin_ObjectInfo *)left;
    right_info = (const OvStoragePlugin_ObjectInfo *)right;
    common = left_info->address.len < right_info->address.len
                 ? left_info->address.len
                 : right_info->address.len;
    comparison = memcmp(left_info->address.ptr,
                        right_info->address.ptr,
                        common);
    if (comparison != 0) {
        return comparison;
    }
    if (left_info->address.len < right_info->address.len) {
        return -1;
    }
    return left_info->address.len > right_info->address.len ? 1 : 0;
}

static int ovc_file_parse_page_token(const char *token,
                                     size_t *out,
                                     OvStoragePlugin_Error **out_error)
{
    size_t value;
    size_t index;

    if (token == NULL) {
        *out = 0;
        return 0;
    }
    if (token[0] == '\0') {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                    "list page token is not valid");
        return -1;
    }
    value = 0;
    for (index = 0; token[index] != '\0'; ++index) {
        unsigned int digit;

        if (token[index] < '0' || token[index] > '9') {
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "list page token is not valid");
            return -1;
        }
        digit = (unsigned int)(token[index] - '0');
        if (value > (SIZE_MAX - digit) / 10) {
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_InvalidArgument,
                "list page token is not valid");
            return -1;
        }
        value = value * 10 + digit;
    }
    *out = value;
    return 0;
}

static OvStoragePlugin_Error *ovc_file_list_result(
    ovc_file_task *task,
    OvStoragePlugin_ListPage **out)
{
    char *path;
    ovc_file_stat root_info;
    ovc_file_item_vector vector;
    OvStoragePlugin_Error *error;
    size_t start;
    size_t page_length;
    size_t end;
    size_t index;
    OvStoragePlugin_ListPage *page;

    memset(&vector, 0, sizeof(vector));
    error = NULL;
    if (task->payload.list.has_max_results &&
        task->payload.list.max_results == 0) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "max_results must be greater than zero");
    }
    if (ovc_file_parse_page_token(task->payload.list.page_token,
                                  &start,
                                  &error) != 0) {
        return error;
    }
    path = ovc_file_resolve_path(task->layer,
                                 task->address,
                                 NULL,
                                 &error);
    if (path == NULL) {
        return error;
    }
    if (ovc_file_native_stat_path(path, &root_info) != 0) {
        int native_error;

        native_error = errno;
        error = ovc_file_native_error(native_error,
                                      "stat list prefix",
                                      path);
        free(path);
        return error;
    }
    if (!root_info.is_directory) {
        free(path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "list prefix is not a directory");
    }
    error = ovc_file_collect_list(task,
                                  path,
                                  task->address,
                                  &vector);
    free(path);
    if (error != NULL) {
        ovc_file_item_vector_clear(&vector);
        return error;
    }
    if (ovc_file_cancelled(task)) {
        ovc_file_item_vector_clear(&vector);
        return ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                              "file list was cancelled");
    }
    if (vector.len > 1) {
        qsort(vector.items,
              vector.len,
              sizeof(*vector.items),
              ovc_file_compare_items);
    }
    if (ovc_file_cancelled(task)) {
        ovc_file_item_vector_clear(&vector);
        return ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                              "file list was cancelled");
    }
    if (start > vector.len) {
        ovc_file_item_vector_clear(&vector);
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "list page token is past the end of the listing");
    }
    page_length = task->payload.list.has_max_results
                      ? (size_t)task->payload.list.max_results
                      : vector.len - start;
    end = page_length > vector.len - start
              ? vector.len
              : start + page_length;
    page = (OvStoragePlugin_ListPage *)
        ovc_file_abi_callocate(1, sizeof(*page));
    page->items.len = end - start;
    page->items.ptr = (OvStoragePlugin_ObjectInfo *)ovc_file_abi_callocate(
        page->items.len == 0 ? 1 : page->items.len,
        sizeof(*page->items.ptr));
    for (index = start; index < end; ++index) {
        page->items.ptr[index - start] = vector.items[index];
        memset(&vector.items[index], 0, sizeof(vector.items[index]));
    }
    if (end < vector.len) {
        char token[64];
        int token_length;

        token_length = snprintf(token, sizeof(token), "%llu",
                                (unsigned long long)end);
        if (token_length < 0 || (size_t)token_length >= sizeof(token)) {
            abort();
        }
        page->next_page_token.present = true;
        page->next_page_token.value = ovc_file_owned_string(token);
    }
    ovc_file_item_vector_clear(&vector);
    *out = page;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Layer state lifetime and connection-table operations. */

#if !defined(_WIN32) && !defined(__GNUC__) && !defined(__clang__)
static ovc_mutex g_ovc_file_reference_mutex = OVC_MUTEX_INITIALIZER;
#endif
static ovc_mutex g_ovc_file_connection_id_mutex = OVC_MUTEX_INITIALIZER;
static uint64_t g_ovc_file_connection_id;

static uint64_t ovc_file_next_connection_id(void)
{
    uint64_t id;

    (void)ovc_mutex_lock(&g_ovc_file_connection_id_mutex);
    id = g_ovc_file_connection_id++;
    (void)ovc_mutex_unlock(&g_ovc_file_connection_id_mutex);
    return id;
}

static bool ovc_file_reference_retain(volatile long *references)
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

    (void)ovc_mutex_lock(&g_ovc_file_reference_mutex);
    retained = *references > 0 && *references < LONG_MAX;
    if (retained) {
        ++*references;
    }
    (void)ovc_mutex_unlock(&g_ovc_file_reference_mutex);
    return retained;
#endif
}

static bool ovc_file_reference_release(volatile long *references)
{
#if defined(_WIN32)
    return InterlockedDecrement(references) == 0;
#elif defined(__GNUC__) || defined(__clang__)
    return __sync_sub_and_fetch(references, 1L) == 0;
#else
    bool last;

    (void)ovc_mutex_lock(&g_ovc_file_reference_mutex);
    --*references;
    last = *references == 0;
    (void)ovc_mutex_unlock(&g_ovc_file_reference_mutex);
    return last;
#endif
}

static ovc_file_layer *ovc_file_layer_retain(ovc_file_layer *layer)
{
    if (layer == NULL ||
        !ovc_file_reference_retain(&layer->references.value)) {
        return NULL;
    }
    return layer;
}

#if defined(OVC_FILE_BACKEND_TEST_MAIN)
/* A Layer can retire on a runtime worker -- the task that outlives a
 * completion callback drops the last reference there -- so the test-only
 * destruction counter and any test read of a live reference count go
 * through the same primitives the reference count itself uses. */
static long ovc_file_test_counter_load(volatile long *counter)
{
#if defined(_WIN32)
    return InterlockedCompareExchange(counter, 0, 0);
#elif defined(__GNUC__) || defined(__clang__)
    return __sync_val_compare_and_swap(counter, 0L, 0L);
#else
    long current;

    (void)ovc_mutex_lock(&g_ovc_file_reference_mutex);
    current = *counter;
    (void)ovc_mutex_unlock(&g_ovc_file_reference_mutex);
    return current;
#endif
}

static void ovc_file_test_counter_bump(volatile long *counter)
{
#if defined(_WIN32)
    (void)InterlockedIncrement(counter);
#elif defined(__GNUC__) || defined(__clang__)
    (void)__sync_add_and_fetch(counter, 1L);
#else
    (void)ovc_mutex_lock(&g_ovc_file_reference_mutex);
    ++*counter;
    (void)ovc_mutex_unlock(&g_ovc_file_reference_mutex);
#endif
}

static volatile long g_ovc_file_layer_test_destroy_count;
#endif

static void ovc_file_layer_release(ovc_file_layer *layer)
{
    size_t index;

    if (layer == NULL ||
        !ovc_file_reference_release(&layer->references.value)) {
        return;
    }
#if defined(OVC_FILE_BACKEND_TEST_MAIN)
    ovc_file_test_counter_bump(&g_ovc_file_layer_test_destroy_count);
#endif
    for (index = 0; index < layer->connection_count; ++index) {
        ovc_file_connection_destroy(&layer->connections[index]);
    }
    free(layer->connections);
    free(layer->name);
    (void)ovc_mutex_destroy(&layer->mutex);
    free(layer);
}

static int64_t ovc_file_now_unix_ms(void)
{
    time_t now;

    now = time(NULL);
    if (now < 0) {
        return 0;
    }
    if ((uint64_t)now > (uint64_t)INT64_MAX / UINT64_C(1000)) {
        return INT64_MAX;
    }
    return (int64_t)now * INT64_C(1000);
}

/* ------------------------------------------------------------------------- */
/* Blocking-pull polling watcher. */

static void ovc_file_watch_sync_success(int result)
{
    if (result != 0) {
        abort();
    }
}

static void ovc_file_watch_snapshot_clear(
    ovc_file_watch_snapshot *snapshot)
{
    size_t index;

    if (snapshot == NULL) {
        return;
    }
    for (index = 0; index < snapshot->len; ++index) {
        free(snapshot->items[index].address);
    }
    free(snapshot->items);
    memset(snapshot, 0, sizeof(*snapshot));
}

static void ovc_file_watch_changes_clear(ovc_file_watch_changes *changes)
{
    size_t index;

    if (changes == NULL) {
        return;
    }
    for (index = 0; index < changes->len; ++index) {
        free(changes->items[index].address);
    }
    free(changes->items);
    memset(changes, 0, sizeof(*changes));
}

static bool ovc_file_watcher_is_canceled(ovc_file_watcher *watcher)
{
    bool canceled;

    ovc_file_watch_sync_success(ovc_mutex_lock(&watcher->mutex));
    canceled = watcher->canceled;
    ovc_file_watch_sync_success(ovc_mutex_unlock(&watcher->mutex));
    return canceled;
}

static OvStoragePlugin_Error *ovc_file_watch_snapshot_reserve(
    ovc_file_watch_snapshot *snapshot)
{
    size_t capacity;
    ovc_file_watch_entry *items;

    if (snapshot->len < snapshot->capacity) {
        return NULL;
    }
    capacity = snapshot->capacity == 0 ? 16 : snapshot->capacity * 2;
    if (capacity < snapshot->capacity ||
        capacity > SIZE_MAX / sizeof(*items)) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "file watch snapshot is too large");
    }
    items = (ovc_file_watch_entry *)realloc(
        snapshot->items, capacity * sizeof(*items));
    if (items == NULL) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "could not grow file watch snapshot");
    }
    snapshot->items = items;
    snapshot->capacity = capacity;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_watch_snapshot_push(
    ovc_file_watch_snapshot *snapshot,
    const char *address,
    const char *path,
    const ovc_file_stat *info)
{
    OvStoragePlugin_Error *error;
    char *sidecar;
    ovc_file_stat sidecar_info;
    ovc_file_watch_entry *entry;

    error = ovc_file_watch_snapshot_reserve(snapshot);
    if (error != NULL) {
        return error;
    }
    sidecar = ovc_file_metadata_path(path, &error);
    if (sidecar == NULL) {
        return error;
    }
    entry = &snapshot->items[snapshot->len];
    memset(entry, 0, sizeof(*entry));
    entry->address = ovc_file_string_duplicate(address);
    entry->info = *info;
    if (ovc_file_native_stat_path(sidecar, &sidecar_info) == 0) {
        entry->has_metadata_mtime = true;
        entry->metadata_mtime_unix_nanos =
            sidecar_info.mtime_unix_nanos;
    }
    free(sidecar);
    ++snapshot->len;
    return NULL;
}

#if defined(_WIN32)

static OvStoragePlugin_Error *ovc_file_watch_scan_directory(
    ovc_file_watcher *watcher,
    const char *path,
    const char *address,
    ovc_file_watch_snapshot *snapshot)
{
    char *pattern;
    wchar_t *pattern_wide;
    WIN32_FIND_DATAW native_entry;
    HANDLE find;
    OvStoragePlugin_Error *error;
    bool more;

    pattern = ovc_path_join(path, "*");
    if (pattern == NULL) {
        return ovc_file_native_error(errno,
                                     "build watch pattern",
                                     path);
    }
    pattern_wide = ovc_file_utf8_to_wide(pattern);
    free(pattern);
    if (pattern_wide == NULL) {
        return ovc_file_native_error(errno,
                                     "encode watch pattern",
                                     path);
    }
    find = FindFirstFileW(pattern_wide, &native_entry);
    free(pattern_wide);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD native_error;

        native_error = GetLastError();
        if (native_error == ERROR_FILE_NOT_FOUND) {
            return NULL;
        }
        ovc_win32_set_errno(native_error);
        return ovc_file_native_error(errno,
                                     "scan watched directory",
                                     path);
    }

    error = NULL;
    more = true;
    while (more) {
        char *name;
        char *child_path;
        char *child_address;
        char *checked_path;
        ovc_file_stat info;
        OvStoragePlugin_Error *scope_error;

        if (ovc_file_watcher_is_canceled(watcher)) {
            error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                   "file watch was cancelled");
            break;
        }
        name = ovc_file_wide_name_to_utf8(native_entry.cFileName);
        if (name == NULL) {
            error = ovc_file_native_error(errno,
                                          "decode watched entry",
                                          path);
            break;
        }
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
            ovc_file_is_internal_entry(name)) {
            free(name);
        } else {
            child_path = ovc_path_join(path, name);
            child_address = NULL;
            if (child_path == NULL ||
                ovc_file_native_stat_path(child_path, &info) != 0) {
                int native_error;

                native_error = errno;
                if (child_path != NULL &&
                    (native_error == ENOENT || native_error == ENOTDIR)) {
                    free(child_path);
                    free(name);
                    goto next_watch_entry;
                }
                error = ovc_file_native_error(
                    native_error,
                    "stat watched entry",
                    child_path == NULL ? path : child_path);
                free(child_path);
                free(name);
                break;
            }
            child_address = ovc_file_join_address(address,
                                                  name,
                                                  info.is_directory);
            scope_error = NULL;
            checked_path = ovc_file_resolve_path(watcher->layer,
                                                 child_address,
                                                 NULL,
                                                 &scope_error);
            if (checked_path == NULL) {
                error = scope_error;
            } else if (info.is_directory) {
                if (watcher->recursive &&
                    (native_entry.dwFileAttributes &
                     FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                    error = ovc_file_watch_scan_directory(watcher,
                                                          child_path,
                                                          child_address,
                                                          snapshot);
                    if (error != NULL &&
                        error->code == OvStoragePlugin_ErrorCode_NotFound) {
                        ovc_file_error_destroy(error);
                        error = NULL;
                    }
                }
            } else {
                error = ovc_file_watch_snapshot_push(snapshot,
                                                     child_address,
                                                     child_path,
                                                     &info);
            }
            free(checked_path);
            free(child_address);
            free(child_path);
            free(name);
            if (error != NULL) {
                break;
            }
        }

next_watch_entry:
        more = FindNextFileW(find, &native_entry) != 0;
        if (!more && GetLastError() != ERROR_NO_MORE_FILES) {
            ovc_win32_set_errno(GetLastError());
            error = ovc_file_native_error(errno,
                                          "iterate watched directory",
                                          path);
        }
    }
    FindClose(find);
    return error;
}

#else

static OvStoragePlugin_Error *ovc_file_watch_scan_directory(
    ovc_file_watcher *watcher,
    const char *path,
    const char *address,
    ovc_file_watch_snapshot *snapshot)
{
    DIR *directory;
    OvStoragePlugin_Error *error;

    directory = opendir(path);
    if (directory == NULL) {
        return ovc_file_native_error(errno,
                                     "scan watched directory",
                                     path);
    }
    error = NULL;
    for (;;) {
        struct dirent *native_entry;
        char *child_path;
        char *child_address;
        char *checked_path;
        struct stat link_info;
        ovc_file_stat info;
        OvStoragePlugin_Error *scope_error;

        if (ovc_file_watcher_is_canceled(watcher)) {
            error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                   "file watch was cancelled");
            break;
        }
        errno = 0;
        native_entry = readdir(directory);
        if (native_entry == NULL) {
            if (errno != 0) {
                error = ovc_file_native_error(errno,
                                              "iterate watched directory",
                                              path);
            }
            break;
        }
        if (strcmp(native_entry->d_name, ".") == 0 ||
            strcmp(native_entry->d_name, "..") == 0 ||
            ovc_file_is_internal_entry(native_entry->d_name)) {
            continue;
        }
        child_path = ovc_path_join(path, native_entry->d_name);
        if (child_path == NULL) {
            error = ovc_file_native_error(errno,
                                          "join watched entry",
                                          path);
            break;
        }
        if (fstatat(AT_FDCWD,
                    child_path,
                    &link_info,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            ovc_file_native_stat_path(child_path, &info) != 0) {
            int native_error;

            native_error = errno;
            if (native_error == ENOENT || native_error == ENOTDIR) {
                free(child_path);
                continue;
            }
            error = ovc_file_native_error(native_error,
                                          "stat watched entry",
                                          child_path);
            free(child_path);
            break;
        }
        child_address = ovc_file_join_address(address,
                                              native_entry->d_name,
                                              info.is_directory);
        scope_error = NULL;
        checked_path = ovc_file_resolve_path(watcher->layer,
                                             child_address,
                                             NULL,
                                             &scope_error);
        if (checked_path == NULL) {
            error = scope_error;
        } else if (info.is_directory) {
            if (watcher->recursive && !S_ISLNK(link_info.st_mode)) {
                error = ovc_file_watch_scan_directory(watcher,
                                                      child_path,
                                                      child_address,
                                                      snapshot);
                if (error != NULL &&
                    error->code == OvStoragePlugin_ErrorCode_NotFound) {
                    ovc_file_error_destroy(error);
                    error = NULL;
                }
            }
        } else {
            error = ovc_file_watch_snapshot_push(snapshot,
                                                 child_address,
                                                 child_path,
                                                 &info);
        }
        free(checked_path);
        free(child_address);
        free(child_path);
        if (error != NULL) {
            break;
        }
    }
    (void)closedir(directory);
    return error;
}

#endif

static int ovc_file_watch_compare_entries(const void *left,
                                          const void *right)
{
    const ovc_file_watch_entry *left_entry;
    const ovc_file_watch_entry *right_entry;

    left_entry = (const ovc_file_watch_entry *)left;
    right_entry = (const ovc_file_watch_entry *)right;
    return strcmp(left_entry->address, right_entry->address);
}

static OvStoragePlugin_Error *ovc_file_watch_snapshot_scan(
    ovc_file_watcher *watcher,
    ovc_file_watch_snapshot *snapshot)
{
    OvStoragePlugin_Error *error;

    memset(snapshot, 0, sizeof(*snapshot));
    error = ovc_file_watch_scan_directory(watcher,
                                          watcher->path,
                                          watcher->address,
                                          snapshot);
    if (error != NULL) {
        ovc_file_watch_snapshot_clear(snapshot);
        return error;
    }
    if (snapshot->len > 1) {
        qsort(snapshot->items,
              snapshot->len,
              sizeof(*snapshot->items),
              ovc_file_watch_compare_entries);
    }
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_watch_changes_push(
    ovc_file_watch_changes *changes,
    const char *address,
    OvStoragePlugin_ChangeKind kind,
    const ovc_file_stat *current)
{
    size_t capacity;
    ovc_file_watch_change *items;
    ovc_file_watch_change *change;

    if (changes->len == changes->capacity) {
        capacity = changes->capacity == 0 ? 8 : changes->capacity * 2;
        if (capacity < changes->capacity ||
            capacity > SIZE_MAX / sizeof(*items)) {
            return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                                  "file watch diff is too large");
        }
        items = (ovc_file_watch_change *)realloc(
            changes->items, capacity * sizeof(*items));
        if (items == NULL) {
            return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                                  "could not grow file watch diff");
        }
        changes->items = items;
        changes->capacity = capacity;
    }
    change = &changes->items[changes->len++];
    memset(change, 0, sizeof(*change));
    change->address = ovc_file_string_duplicate(address);
    change->kind = kind;
    if (current != NULL) {
        change->has_current = true;
        change->current = *current;
    }
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_watch_diff(
    const ovc_file_watch_snapshot *previous,
    const ovc_file_watch_snapshot *current,
    bool include_metadata_changes,
    ovc_file_watch_changes *changes)
{
    size_t old_index;
    size_t new_index;
    OvStoragePlugin_Error *error;

    memset(changes, 0, sizeof(*changes));
    old_index = 0;
    new_index = 0;
    error = NULL;
    while (old_index < previous->len || new_index < current->len) {
        const ovc_file_watch_entry *old_entry;
        const ovc_file_watch_entry *new_entry;
        int comparison;

        old_entry = old_index < previous->len
                        ? &previous->items[old_index]
                        : NULL;
        new_entry = new_index < current->len
                        ? &current->items[new_index]
                        : NULL;
        if (old_entry == NULL) {
            comparison = 1;
        } else if (new_entry == NULL) {
            comparison = -1;
        } else {
            comparison = strcmp(old_entry->address, new_entry->address);
        }

        if (comparison < 0) {
            error = ovc_file_watch_changes_push(
                changes,
                old_entry->address,
                OvStoragePlugin_ChangeKind_Deleted,
                NULL);
            ++old_index;
        } else if (comparison > 0) {
            error = ovc_file_watch_changes_push(
                changes,
                new_entry->address,
                OvStoragePlugin_ChangeKind_Created,
                &new_entry->info);
            ++new_index;
        } else {
            if (old_entry->info.size != new_entry->info.size ||
                old_entry->info.mtime_unix_nanos !=
                    new_entry->info.mtime_unix_nanos) {
                error = ovc_file_watch_changes_push(
                    changes,
                    new_entry->address,
                    OvStoragePlugin_ChangeKind_Modified,
                    &new_entry->info);
            } else if (include_metadata_changes &&
                       (old_entry->has_metadata_mtime !=
                            new_entry->has_metadata_mtime ||
                        (old_entry->has_metadata_mtime &&
                         old_entry->metadata_mtime_unix_nanos !=
                             new_entry->metadata_mtime_unix_nanos))) {
                error = ovc_file_watch_changes_push(
                    changes,
                    new_entry->address,
                    OvStoragePlugin_ChangeKind_MetadataChanged,
                    &new_entry->info);
            }
            ++old_index;
            ++new_index;
        }
        if (error != NULL) {
            ovc_file_watch_changes_clear(changes);
            return error;
        }
    }
    return NULL;
}

static OvStoragePlugin_WatchDirectoryCursor ovc_file_watch_fresh_cursor(void)
{
    char buffer[96];
    uint64_t monotonic;
    int length;
    OvStoragePlugin_WatchDirectoryCursor cursor;

    monotonic = ovc_monotonic_ns();
    length = snprintf(buffer,
                      sizeof(buffer),
                      "%lld:%llu",
                      (long long)ovc_file_now_unix_ms(),
                      (unsigned long long)monotonic);
    if (length < 0 || (size_t)length >= sizeof(buffer)) {
        abort();
    }
    cursor.bytes.ptr =
        (uint8_t *)ovc_file_abi_allocate((size_t)length);
    cursor.bytes.len = (size_t)length;
    memcpy(cursor.bytes.ptr, buffer, (size_t)length);
    return cursor;
}

static void ovc_file_watch_fill_lapsed(
    OvStoragePlugin_BackendChangeEvent *out_item)
{
    memset(out_item, 0, sizeof(*out_item));
    out_item->tag = OvStoragePlugin_BackendChangeEventTag_Lapsed;
    out_item->lapsed.cursor = ovc_file_watch_fresh_cursor();
}

static void ovc_file_watch_fill_change(
    const ovc_file_watch_change *change,
    OvStoragePlugin_BackendChangeEvent *out_item)
{
    char *etag;

    memset(out_item, 0, sizeof(*out_item));
    out_item->tag = OvStoragePlugin_BackendChangeEventTag_Object;
    out_item->object.address = ovc_file_owned_string(change->address);
    out_item->object.kind = change->kind;
    if (change->has_current) {
        /* ovc_file_etag mints a host-internal string; the change event
         * crosses the ABI, so copy the etag onto the ABI allocator. */
        etag = ovc_file_etag(&change->current);
        out_item->object.etag.present = true;
        out_item->object.etag.value = ovc_file_owned_string(etag);
        free(etag);
        out_item->object.size.present = true;
        out_item->object.size.value = change->current.size;
        out_item->object.mtime_unix_ms.present = true;
        out_item->object.mtime_unix_ms.value =
            change->current.mtime_unix_ms;
    }
    out_item->object.at_unix_ms = ovc_file_now_unix_ms();
    out_item->object.cursor = ovc_file_watch_fresh_cursor();
}

static int ovc_file_watch_timed_wait_locked(ovc_file_watcher *watcher)
{
    uint64_t interval_ns;
    uint64_t started;
    uint64_t deadline;

    interval_ns = watcher->poll_interval_ms >
                          UINT64_MAX / UINT64_C(1000000)
                      ? UINT64_MAX
                      : watcher->poll_interval_ms * UINT64_C(1000000);
    errno = 0;
    started = ovc_monotonic_ns();
    if (started == 0) {
        return errno == 0 ? EIO : errno;
    }
    deadline = interval_ns > UINT64_MAX - started
                   ? UINT64_MAX
                   : started + interval_ns;

    while (!watcher->canceled) {
        uint64_t now;
        uint64_t wait_ns;
        int result;

        errno = 0;
        now = ovc_monotonic_ns();
        if (now == 0) {
            return errno == 0 ? EIO : errno;
        }
        if (now >= deadline) {
            return 0;
        }
        wait_ns = deadline - now;
        if (wait_ns > OVC_FILE_WATCH_WAIT_CHUNK_NS) {
            wait_ns = OVC_FILE_WATCH_WAIT_CHUNK_NS;
        }
#if defined(OVC_FILE_BACKEND_TEST_MAIN)
        if (watcher->test_wait_entered != NULL) {
            ovc_completion_latch *entered;

            entered = watcher->test_wait_entered;
            watcher->test_wait_entered = NULL;
            if (ovc_completion_latch_complete(entered) != 0) {
                abort();
            }
        }
#endif
        /* ovc_cond_timedwait_ns measures the wait against a monotonic
         * clock where the platform provides one, so a wall-clock step
         * cannot stall change delivery.  The chunk cap only matters on the
         * rare POSIX platform whose condvars cannot use CLOCK_MONOTONIC:
         * there each chunk re-derives its absolute deadline from the
         * wall clock, bounding a backward-step overstay to one chunk. */
        result = ovc_cond_timedwait_ns(&watcher->changed,
                                       &watcher->mutex,
                                       wait_ns);
        if (result != 0 && result != ETIMEDOUT) {
            return result;
        }
    }
    return 0;
}

static void ovc_file_watch_cancel_callback(void *user_data)
{
    ovc_file_watcher *watcher;

    watcher = (ovc_file_watcher *)user_data;
    ovc_file_watch_sync_success(ovc_mutex_lock(&watcher->mutex));
    watcher->canceled = true;
    ovc_file_watch_sync_success(ovc_cond_broadcast(&watcher->changed));
    ovc_file_watch_sync_success(ovc_mutex_unlock(&watcher->mutex));
}

static void ovc_file_watcher_destroy(ovc_file_watcher *watcher)
{
    if (watcher == NULL) {
        return;
    }
    if (watcher->has_cancel && watcher->cancel_subscription != 0) {
        watcher->cancel.unregister_callback(
            watcher->cancel.state, watcher->cancel_subscription);
    }
    if (watcher->has_cancel) {
        watcher->cancel.drop(watcher->cancel.state);
    }
    ovc_file_watch_snapshot_clear(&watcher->snapshot);
    ovc_file_watch_changes_clear(&watcher->pending);
    ovc_file_layer_release(watcher->layer);
    free(watcher->path);
    free(watcher->address);
    ovc_file_watch_sync_success(ovc_cond_destroy(&watcher->changed));
    ovc_file_watch_sync_success(ovc_mutex_destroy(&watcher->mutex));
    free(watcher);
}

#if defined(OVC_FILE_BACKEND_TEST_MAIN)
static unsigned int g_ovc_file_watch_test_drop_count;
#endif

static void ovc_file_watch_drop(void *state)
{
#if defined(OVC_FILE_BACKEND_TEST_MAIN)
    ++g_ovc_file_watch_test_drop_count;
#endif
    ovc_file_watcher_destroy((ovc_file_watcher *)state);
}

static OvStoragePlugin_StreamStep ovc_file_watch_fail(
    ovc_file_watcher *watcher,
    OvStoragePlugin_Error *error,
    OvStoragePlugin_Error *out_error)
{
    ovc_file_watch_sync_success(ovc_mutex_lock(&watcher->mutex));
    watcher->exhausted = true;
    ovc_file_watch_sync_success(ovc_mutex_unlock(&watcher->mutex));
    if (out_error != NULL) {
        /* The payload moves into the caller's storage; only the heap shell
         * this file minted with the ABI allocator is released. */
        *out_error = *error;
        ovc_abi_free(error);
    } else {
        ovc_file_error_destroy(error);
    }
    return OvStoragePlugin_StreamStep_Failed;
}

static OvStoragePlugin_StreamStep ovc_file_watch_next(
    void *state,
    OvStoragePlugin_BackendChangeEvent *out_item,
    OvStoragePlugin_Error *out_error)
{
    ovc_file_watcher *watcher;

    watcher = (ovc_file_watcher *)state;
    for (;;) {
        int wait_error;
        bool emit_lapsed;
        const ovc_file_watch_change *change;
        ovc_file_watch_snapshot next_snapshot;
        ovc_file_watch_changes next_changes;
        OvStoragePlugin_Error *error;

        ovc_file_watch_sync_success(ovc_mutex_lock(&watcher->mutex));
        if (watcher->exhausted || watcher->canceled) {
            watcher->exhausted = true;
            ovc_file_watch_sync_success(
                ovc_mutex_unlock(&watcher->mutex));
            return OvStoragePlugin_StreamStep_Ended;
        }
        emit_lapsed = watcher->emit_lapsed;
        if (emit_lapsed) {
            watcher->emit_lapsed = false;
            ovc_file_watch_sync_success(
                ovc_mutex_unlock(&watcher->mutex));
            if (out_item == NULL) {
                return ovc_file_watch_fail(
                    watcher,
                    ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                   "file watch next needs item storage"),
                    out_error);
            }
            ovc_file_watch_fill_lapsed(out_item);
            return OvStoragePlugin_StreamStep_Yielded;
        }
        change = watcher->pending.next < watcher->pending.len
                     ? &watcher->pending.items[watcher->pending.next]
                     : NULL;
        if (change != NULL) {
            ++watcher->pending.next;
            ovc_file_watch_sync_success(
                ovc_mutex_unlock(&watcher->mutex));
            if (out_item == NULL) {
                return ovc_file_watch_fail(
                    watcher,
                    ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                   "file watch next needs item storage"),
                    out_error);
            }
            ovc_file_watch_fill_change(change, out_item);
            return OvStoragePlugin_StreamStep_Yielded;
        }

        wait_error = ovc_file_watch_timed_wait_locked(watcher);
        if (watcher->canceled) {
            watcher->exhausted = true;
            ovc_file_watch_sync_success(
                ovc_mutex_unlock(&watcher->mutex));
            return OvStoragePlugin_StreamStep_Ended;
        }
        ovc_file_watch_sync_success(ovc_mutex_unlock(&watcher->mutex));
        if (wait_error != 0) {
            return ovc_file_watch_fail(
                watcher,
                ovc_file_native_error(wait_error,
                                      "wait for file watch poll",
                                      watcher->path),
                out_error);
        }

        memset(&next_snapshot, 0, sizeof(next_snapshot));
        memset(&next_changes, 0, sizeof(next_changes));
        error = ovc_file_watch_snapshot_scan(watcher, &next_snapshot);
        if (error == NULL) {
            error = ovc_file_watch_diff(&watcher->snapshot,
                                        &next_snapshot,
                                        watcher->include_metadata_changes,
                                        &next_changes);
        }

        ovc_file_watch_sync_success(ovc_mutex_lock(&watcher->mutex));
        if (watcher->canceled) {
            watcher->exhausted = true;
            ovc_file_watch_sync_success(
                ovc_mutex_unlock(&watcher->mutex));
            ovc_file_watch_snapshot_clear(&next_snapshot);
            ovc_file_watch_changes_clear(&next_changes);
            ovc_file_error_destroy(error);
            return OvStoragePlugin_StreamStep_Ended;
        }
        if (error != NULL) {
            ovc_file_watch_sync_success(
                ovc_mutex_unlock(&watcher->mutex));
            ovc_file_watch_snapshot_clear(&next_snapshot);
            ovc_file_watch_changes_clear(&next_changes);
            return ovc_file_watch_fail(watcher, error, out_error);
        }
        ovc_file_watch_snapshot_clear(&watcher->snapshot);
        watcher->snapshot = next_snapshot;
        ovc_file_watch_changes_clear(&watcher->pending);
        watcher->pending = next_changes;
        ovc_file_watch_sync_success(ovc_mutex_unlock(&watcher->mutex));
    }
}

static ovc_file_watcher *ovc_file_watcher_create(
    ovc_file_layer *layer,
    const char *address,
    const OvStoragePlugin_WatchDirectoryOptions *options,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_Error **out_error)
{
    ovc_file_watcher *watcher;
    ovc_file_stat root_info;
    int result;

    *out_error = NULL;
    watcher = (ovc_file_watcher *)calloc(1, sizeof(*watcher));
    if (watcher == NULL) {
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_ResourceExhausted,
            "could not allocate file watcher");
        return NULL;
    }
    result = ovc_mutex_init(&watcher->mutex);
    if (result != 0) {
        free(watcher);
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Internal,
                                    "could not initialize file watcher mutex");
        return NULL;
    }
    result = ovc_cond_init(&watcher->changed);
    if (result != 0) {
        (void)ovc_mutex_destroy(&watcher->mutex);
        free(watcher);
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_Internal,
            "could not initialize file watcher condition");
        return NULL;
    }
    watcher->layer = ovc_file_layer_retain(layer);
    watcher->address = ovc_file_string_duplicate(address);
    watcher->recursive = options->recursive;
    watcher->include_metadata_changes =
        options->include_metadata_changes;
    watcher->poll_interval_ms =
        options->poll_interval_ms < OVC_FILE_MIN_WATCH_POLL_MS
            ? OVC_FILE_MIN_WATCH_POLL_MS
            : options->poll_interval_ms;
    watcher->emit_lapsed = options->since.present;
    if (watcher->layer == NULL) {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Internal,
                                    "could not retain file Layer for watch");
        ovc_file_watcher_destroy(watcher);
        return NULL;
    }

    if (cancel != NULL && cancel->state != NULL) {
        if (cancel->is_canceled == NULL ||
            cancel->register_callback == NULL ||
            cancel->unregister_callback == NULL || cancel->clone == NULL ||
            cancel->drop == NULL) {
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_Internal,
                "file watch received an incomplete cancel token");
            ovc_file_watcher_destroy(watcher);
            return NULL;
        }
        watcher->cancel = *cancel;
        watcher->cancel.state = cancel->clone(cancel->state);
        if (watcher->cancel.state == NULL) {
            *out_error = ovc_file_error(
                OvStoragePlugin_ErrorCode_Internal,
                "could not retain file watch cancel token");
            ovc_file_watcher_destroy(watcher);
            return NULL;
        }
        watcher->has_cancel = true;
        watcher->cancel_subscription =
            watcher->cancel.register_callback(
                watcher->cancel.state,
                ovc_file_watch_cancel_callback,
                watcher);
    }

    watcher->path = ovc_file_resolve_path(watcher->layer,
                                          watcher->address,
                                          NULL,
                                          out_error);
    if (watcher->path == NULL) {
        ovc_file_watcher_destroy(watcher);
        return NULL;
    }
    if (ovc_file_native_stat_path(watcher->path, &root_info) != 0) {
        int native_error;

        native_error = errno;
        *out_error = ovc_file_native_error(native_error,
                                            "stat watched directory",
                                            watcher->path);
        ovc_file_watcher_destroy(watcher);
        return NULL;
    }
    if (!root_info.is_directory) {
        *out_error = ovc_file_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "file watch prefix is not a directory");
        ovc_file_watcher_destroy(watcher);
        return NULL;
    }
    if (ovc_file_watcher_is_canceled(watcher)) {
        *out_error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                                    "file watch was cancelled");
        ovc_file_watcher_destroy(watcher);
        return NULL;
    }
    *out_error = ovc_file_watch_snapshot_scan(watcher,
                                               &watcher->snapshot);
    if (*out_error != NULL) {
        ovc_file_watcher_destroy(watcher);
        return NULL;
    }
    return watcher;
}

static int ovc_file_layer_reserve_connections(ovc_file_layer *layer)
{
    size_t capacity;
    ovc_file_connection *connections;

    if (layer->connection_count < layer->connection_capacity) {
        return 0;
    }
    capacity = layer->connection_capacity == 0
                   ? 4
                   : layer->connection_capacity * 2;
    if (capacity < layer->connection_capacity ||
        capacity > SIZE_MAX / sizeof(*connections)) {
        return -1;
    }
    connections = (ovc_file_connection *)realloc(
        layer->connections, capacity * sizeof(*connections));
    if (connections == NULL) {
        return -1;
    }
    memset(connections + layer->connection_capacity,
           0,
           (capacity - layer->connection_capacity) * sizeof(*connections));
    layer->connections = connections;
    layer->connection_capacity = capacity;
    return 0;
}

static OvStoragePlugin_Error *ovc_file_add_connection_result(
    ovc_file_task *task,
    OvStoragePlugin_Connection **out)
{
    char *root_url;
    char *root_path;
    char *canonical_root;
    ovc_file_stat root_info;
    ovc_file_connection connection;
    OvStoragePlugin_Connection *result;
    OvStoragePlugin_Error *error;
    char identifier[128];
    int identifier_length;

    if (strcmp(task->payload.add_connection.target,
               task->layer->name) != 0) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_NotFound,
                              "target file layer was not found");
    }
    if (strcmp(task->payload.add_connection.backend_kind,
               OVC_FILE_KIND) != 0) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "connection backend_kind must be file");
    }
    if (task->payload.add_connection.root == NULL) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "file connection needs root config");
    }
    error = NULL;
    root_url = ovc_file_root_url_from_config(
        task->payload.add_connection.root, &root_path, &error);
    if (root_url == NULL) {
        return error;
    }
    if (ovc_file_native_stat_path(root_path, &root_info) != 0) {
        int native_error;

        native_error = errno;
        error = ovc_file_native_error(native_error,
                                      "stat configured file root",
                                      root_path);
        free(root_url);
        free(root_path);
        return error;
    }
    if (!root_info.is_directory) {
        free(root_url);
        free(root_path);
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "configured file root is not a directory");
    }
    canonical_root = ovc_file_native_realpath(root_path);
    if (canonical_root == NULL) {
        int native_error;

        native_error = errno;
        error = ovc_file_native_error(native_error,
                                      "resolve configured file root",
                                      root_path);
        free(root_url);
        free(root_path);
        return error;
    }

    memset(&connection, 0, sizeof(connection));
    connection.root_url = root_url;
    connection.root_path = root_path;
    connection.canonical_root = canonical_root;
    connection.display_name = ovc_file_string_duplicate(
        task->payload.add_connection.display_name == NULL
            ? OVC_FILE_DEFAULT_CONNECTION_NAME
            : task->payload.add_connection.display_name);
    connection.persisted = task->payload.add_connection.persisted;
    connection.last_probed_unix_ms = ovc_file_now_unix_ms();

    (void)ovc_mutex_lock(&task->layer->mutex);
    identifier_length = snprintf(identifier,
                                 sizeof(identifier),
                                 "file-%lu-%llu",
                                 ovc_file_process_id(),
                                 (unsigned long long)
                                     ovc_file_next_connection_id());
    if (identifier_length < 0 ||
        (size_t)identifier_length >= sizeof(identifier) ||
        ovc_file_layer_reserve_connections(task->layer) != 0) {
        (void)ovc_mutex_unlock(&task->layer->mutex);
        ovc_file_connection_destroy(&connection);
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "could not record file connection");
    }
    connection.id = ovc_file_string_duplicate(identifier);
    task->layer->connections[task->layer->connection_count++] = connection;
    result = (OvStoragePlugin_Connection *)
        ovc_file_abi_callocate(1, sizeof(*result));
    ovc_file_connection_to_ffi(
        &task->layer->connections[task->layer->connection_count - 1],
        result);
    (void)ovc_mutex_unlock(&task->layer->mutex);
    *out = result;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_remove_connection_result(
    ovc_file_task *task)
{
    size_t index;
    ovc_file_connection removed;
    bool found;

    if (strcmp(task->payload.connection_key.target,
               task->layer->name) != 0) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_NotFound,
                              "target file layer was not found");
    }
    memset(&removed, 0, sizeof(removed));
    found = false;
    (void)ovc_mutex_lock(&task->layer->mutex);
    for (index = 0; index < task->layer->connection_count; ++index) {
        if (strcmp(task->layer->connections[index].id,
                   task->payload.connection_key.id) == 0) {
            removed = task->layer->connections[index];
            if (index + 1 < task->layer->connection_count) {
                memmove(&task->layer->connections[index],
                        &task->layer->connections[index + 1],
                        (task->layer->connection_count - index - 1) *
                            sizeof(*task->layer->connections));
            }
            --task->layer->connection_count;
            memset(&task->layer->connections[task->layer->connection_count],
                   0,
                   sizeof(*task->layer->connections));
            found = true;
            break;
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    if (!found) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_NotFound,
                              "file connection was not found");
    }
    ovc_file_connection_destroy(&removed);
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_update_credentials_result(
    ovc_file_task *task,
    OvStoragePlugin_Connection **out)
{
    size_t index;
    OvStoragePlugin_Connection *result;

    if (strcmp(task->payload.connection_key.target,
               task->layer->name) != 0) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_NotFound,
                              "target file layer was not found");
    }
    result = NULL;
    (void)ovc_mutex_lock(&task->layer->mutex);
    for (index = 0; index < task->layer->connection_count; ++index) {
        if (strcmp(task->layer->connections[index].id,
                   task->payload.connection_key.id) == 0) {
            /* File connections are anonymous. Credentials are securely
             * discarded in the synchronous prologue and the record is
             * returned unchanged. */
            result = (OvStoragePlugin_Connection *)
                ovc_file_abi_callocate(1, sizeof(*result));
            ovc_file_connection_to_ffi(&task->layer->connections[index],
                                       result);
            break;
        }
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
    if (result == NULL) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_NotFound,
                              "file connection was not found");
    }
    *out = result;
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Runtime tasks. */

/* Introspection result builders.  Each runs on an io-task worker (never the
 * caller thread) and mints an ABI-owned success payload the receiver reclaims:
 * root_info_for yields a heap RootInfo; the two list slots yield the paired
 * snapshot+updates result envelope with a NULL update channel (this backend
 * publishes no change stream). */
static OvStoragePlugin_Error *ovc_file_root_info_for_result(
    ovc_file_task *task,
    OvStoragePlugin_RootInfo **out)
{
    ovc_file_connection connection;
    char *path;
    OvStoragePlugin_Error *error;
    OvStoragePlugin_RootInfo *info;

    if (task->address == NULL) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                              "root_info_for URL is invalid");
    }
    memset(&connection, 0, sizeof(connection));
    error = NULL;
    path = ovc_file_resolve_path(task->layer,
                                 task->address,
                                 &connection,
                                 &error);
    free(path);
    if (error != NULL) {
        return error;
    }
    info = (OvStoragePlugin_RootInfo *)ovc_file_abi_allocate(sizeof(*info));
    ovc_file_root_info_fill(&connection, task->layer->name, info);
    ovc_file_connection_destroy(&connection);
    *out = info;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_list_address_roots_result(
    ovc_file_task *task,
    OvStoragePlugin_ListAddressRootsResult **out)
{
    ovc_file_layer *layer;
    OvStoragePlugin_ListAddressRootsResult *envelope;
    size_t index;

    layer = task->layer;
    envelope = (OvStoragePlugin_ListAddressRootsResult *)
        ovc_file_abi_allocate(sizeof(*envelope));
    memset(envelope, 0, sizeof(*envelope));
    envelope->updates = NULL;
    (void)ovc_mutex_lock(&layer->mutex);
    envelope->snapshot.roots.len = layer->connection_count;
    envelope->snapshot.roots.ptr =
        (OvStoragePlugin_RootInfo *)ovc_file_abi_callocate(
            layer->connection_count == 0 ? 1 : layer->connection_count,
            sizeof(*envelope->snapshot.roots.ptr));
    for (index = 0; index < layer->connection_count; ++index) {
        ovc_file_root_info_fill(&layer->connections[index],
                                layer->name,
                                &envelope->snapshot.roots.ptr[index]);
    }
    (void)ovc_mutex_unlock(&layer->mutex);
    envelope->snapshot.updates = false;
    *out = envelope;
    return NULL;
}

static OvStoragePlugin_Error *ovc_file_list_connections_result(
    ovc_file_task *task,
    OvStoragePlugin_ListConnectionsResult **out)
{
    ovc_file_layer *layer;
    OvStoragePlugin_ListConnectionsResult *envelope;
    size_t index;

    layer = task->layer;
    envelope = (OvStoragePlugin_ListConnectionsResult *)
        ovc_file_abi_allocate(sizeof(*envelope));
    memset(envelope, 0, sizeof(*envelope));
    envelope->updates = NULL;
    (void)ovc_mutex_lock(&layer->mutex);
    envelope->snapshot.connections.len = layer->connection_count;
    envelope->snapshot.connections.ptr = (OvStoragePlugin_Connection *)
        ovc_file_abi_callocate(layer->connection_count == 0
                                   ? 1
                                   : layer->connection_count,
                               sizeof(*envelope->snapshot.connections.ptr));
    for (index = 0; index < layer->connection_count; ++index) {
        ovc_file_connection_to_ffi(&layer->connections[index],
                                   &envelope->snapshot.connections.ptr[index]);
    }
    (void)ovc_mutex_unlock(&layer->mutex);
    envelope->snapshot.updates = false;
    *out = envelope;
    return NULL;
}

static void ovc_file_task_destroy(ovc_file_task *task)
{
    if (task == NULL) {
        return;
    }
    if (task->has_cancel && task->cancel.state != NULL &&
        task->cancel.drop != NULL) {
        task->cancel.drop(task->cancel.state);
    }
    free(task->address);
    switch (task->kind) {
    case OVC_FILE_TASK_READ:
    case OVC_FILE_TASK_MATERIALIZE:
    case OVC_FILE_TASK_GET_LATEST_VERSION:
        free(task->payload.read.if_match);
        break;
    case OVC_FILE_TASK_WRITE:
        /* The body buffer is STOLEN from the moved request in
         * ovc_file_layer_write; the dispatcher minted it with
         * ovc_abi_alloc, so it is released with ovc_abi_free. */
        ovc_abi_free(task->payload.write.bytes);
        free(task->payload.write.match_etag);
        ovc_file_key_value_list_clear(
            &task->payload.write.user_metadata);
        break;
    case OVC_FILE_TASK_LIST:
        free(task->payload.list.page_token);
        break;
    case OVC_FILE_TASK_DELETE:
        free(task->payload.delete_.if_match);
        break;
    case OVC_FILE_TASK_COPY:
    case OVC_FILE_TASK_RENAME:
        free(task->payload.transfer.source);
        free(task->payload.transfer.destination);
        free(task->payload.transfer.if_source);
        free(task->payload.transfer.match_etag);
        free(task->payload.transfer.message);
        break;
    case OVC_FILE_TASK_UPDATE_METADATA:
        free(task->payload.update_metadata.if_match);
        ovc_file_key_value_list_clear(
            &task->payload.update_metadata.set);
        ovc_file_string_list_clear(
            &task->payload.update_metadata.remove);
        free(task->payload.update_metadata.message);
        break;
    case OVC_FILE_TASK_LIST_VERSIONS:
        free(task->payload.list_versions.page_token);
        break;
    case OVC_FILE_TASK_ADD_CONNECTION:
        free(task->payload.add_connection.target);
        free(task->payload.add_connection.backend_kind);
        free(task->payload.add_connection.root);
        free(task->payload.add_connection.display_name);
        break;
    case OVC_FILE_TASK_REMOVE_CONNECTION:
    case OVC_FILE_TASK_UPDATE_CREDENTIALS:
        free(task->payload.connection_key.target);
        free(task->payload.connection_key.id);
        break;
    case OVC_FILE_TASK_STAT:
    case OVC_FILE_TASK_CHECK_ACCESS:
    case OVC_FILE_TASK_CREATE_DIRECTORY:
    case OVC_FILE_TASK_DELETE_DIRECTORY:
    default:
        break;
    }
    ovc_file_layer_release(task->layer);
    free(task);
}

static ovc_file_task *ovc_file_task_create(
    ovc_file_task_kind kind,
    ovc_file_layer *layer,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_file_task *task;

    task = (ovc_file_task *)ovc_file_callocate(1, sizeof(*task));
    task->kind = kind;
    task->layer = ovc_file_layer_retain(layer);
    task->on_complete = on_complete;
    task->user_data = user_data;
    if (task->layer == NULL) {
        free(task);
        return NULL;
    }
    if (cancel != NULL && cancel->state != NULL) {
        task->cancel = *cancel;
        if (cancel->clone == NULL) {
            ovc_file_task_destroy(task);
            return NULL;
        }
        task->cancel.state = cancel->clone(cancel->state);
        if (task->cancel.state == NULL) {
            ovc_file_task_destroy(task);
            return NULL;
        }
        task->has_cancel = true;
    }
    return task;
}

static void ovc_file_task_run(void *argument)
{
    ovc_file_task *task;
    OvStoragePlugin_Error *error;
    void *result;

    task = (ovc_file_task *)argument;
    error = NULL;
    result = NULL;
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "file operation was cancelled");
    } else {
        switch (task->kind) {
        case OVC_FILE_TASK_STAT: {
            OvStoragePlugin_ObjectInfo *typed_result;

            typed_result = NULL;
            error = ovc_file_stat_result(task->layer,
                                         task->address,
                                         task->payload.stat.full_metadata,
                                         &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_READ: {
            OvStoragePlugin_ReadResult *typed_result;

            typed_result = NULL;
            error = ovc_file_read_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_WRITE: {
            OvStoragePlugin_WriteResult *typed_result;

            typed_result = NULL;
            error = ovc_file_write_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_LIST: {
            OvStoragePlugin_ListPage *typed_result;

            typed_result = NULL;
            error = ovc_file_list_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_DELETE:
            error = ovc_file_delete_result(task);
            break;
        case OVC_FILE_TASK_COPY: {
            OvStoragePlugin_WriteStep *typed_result;

            typed_result = NULL;
            error = ovc_file_copy_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_RENAME:
            error = ovc_file_rename_result(task);
            break;
        case OVC_FILE_TASK_UPDATE_METADATA: {
            OvStoragePlugin_BackendItemInfo *typed_result;

            typed_result = NULL;
            error = ovc_file_update_metadata_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_CHECK_ACCESS: {
            OvStoragePlugin_AccessDecision *typed_result;

            typed_result = NULL;
            error = ovc_file_check_access_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_MATERIALIZE: {
            OvStoragePlugin_LocalDelegate *typed_result;

            typed_result = NULL;
            error = ovc_file_materialize_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_LIST_VERSIONS: {
            OvStoragePlugin_VersionPage *typed_result;

            typed_result = NULL;
            error = ovc_file_list_versions_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_GET_LATEST_VERSION: {
            OvStoragePlugin_ObjectInfo *typed_result;

            typed_result = NULL;
            error = ovc_file_get_latest_version_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_CREATE_DIRECTORY: {
            OvStoragePlugin_BackendItemInfo *typed_result;

            typed_result = NULL;
            error = ovc_file_create_directory_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_DELETE_DIRECTORY:
            error = ovc_file_delete_directory_result(task);
            break;
        case OVC_FILE_TASK_ADD_CONNECTION: {
            OvStoragePlugin_Connection *typed_result;

            typed_result = NULL;
            error = ovc_file_add_connection_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_REMOVE_CONNECTION:
            error = ovc_file_remove_connection_result(task);
            break;
        case OVC_FILE_TASK_UPDATE_CREDENTIALS: {
            OvStoragePlugin_Connection *typed_result;

            typed_result = NULL;
            error = ovc_file_update_credentials_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_ROOT_INFO_FOR: {
            OvStoragePlugin_RootInfo *typed_result;

            typed_result = NULL;
            error = ovc_file_root_info_for_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_LIST_ADDRESS_ROOTS: {
            OvStoragePlugin_ListAddressRootsResult *typed_result;

            typed_result = NULL;
            error = ovc_file_list_address_roots_result(task, &typed_result);
            result = typed_result;
            break;
        }
        case OVC_FILE_TASK_LIST_CONNECTIONS: {
            OvStoragePlugin_ListConnectionsResult *typed_result;

            typed_result = NULL;
            error = ovc_file_list_connections_result(task, &typed_result);
            result = typed_result;
            break;
        }
        default:
            error = ovc_file_error(OvStoragePlugin_ErrorCode_Internal,
                                   "unknown file runtime task");
            break;
        }
    }
    if (error == NULL) {
        task->on_complete(OvStoragePlugin_FFI_STATUS_OK,
                          result,
                          NULL,
                          task->user_data);
    } else {
        task->on_complete(OvStoragePlugin_FFI_STATUS_ERR,
                          NULL,
                          error,
                          task->user_data);
    }
    ovc_file_task_destroy(task);
}

static void ovc_file_submit_task(ovc_file_task *task)
{
    if (task == NULL) {
        return;
    }
    if (ovc_runtime_submit(ovc_file_task_run, task) != 0) {
        OvStoragePlugin_OnComplete on_complete;
        void *user_data;

        on_complete = task->on_complete;
        user_data = task->user_data;
        ovc_file_task_destroy(task);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "file operation could not be queued");
    }
}

static bool ovc_file_slice_equals(const OvStoragePlugin_Str *slice,
                                  const char *value)
{
    size_t length;

    length = strlen(value);
    return slice != NULL && slice->ptr != NULL && slice->len == length &&
           memcmp(slice->ptr, value, length) == 0;
}

static char *ovc_file_find_string_config(
    const OvStoragePlugin_List_ConnectionConfigEntry *config,
    const char *key,
    bool *wrong_type)
{
    size_t index;
    char *result;

    result = NULL;
    *wrong_type = false;
    for (index = 0; index < config->len; ++index) {
        if (!ovc_file_slice_equals(&config->ptr[index].key, key)) {
            continue;
        }
        free(result);
        result = NULL;
        if (config->ptr[index].value.tag !=
            OvStoragePlugin_ConfigValueTag_String) {
            *wrong_type = true;
        } else {
            result = ovc_file_string_from_slice(
                &config->ptr[index].value.string_value);
            if (result == NULL) {
                *wrong_type = true;
            }
        }
    }
    return result;
}

/* ------------------------------------------------------------------------- */
/* Layer identity and the synchronous list_kinds introspection slot. */

static void ovc_file_layer_drop(void *state)
{
    ovc_file_layer_release((ovc_file_layer *)state);
}

static void ovc_file_layer_name(void *state, OvStoragePlugin_Str *out)
{
    ovc_file_layer *layer;

    layer = (ovc_file_layer *)state;
    *out = ovc_file_owned_string(layer->name);
}

static void ovc_file_layer_descriptor(
    void *state,
    OvStoragePlugin_LayerKindDescriptor *out)
{
    (void)state;
    ovc_file_descriptor_fill(out);
}

static void ovc_file_layer_owned_targets(
    void *state,
    OvStoragePlugin_List_Str *out)
{
    ovc_file_layer *layer;

    layer = (ovc_file_layer *)state;
    out->ptr = (OvStoragePlugin_Str *)
        ovc_file_abi_callocate(1, sizeof(*out->ptr));
    out->len = 1;
    out->ptr[0] = ovc_file_owned_string(layer->name);
}

static OvStoragePlugin_Error *ovc_file_layer_list_kinds(
    void *state,
    const OvStoragePlugin_Extensions *extensions,
    OvStoragePlugin_List_LayerKindDescriptor *out)
{
    (void)state;
    (void)extensions;
    out->ptr = (OvStoragePlugin_LayerKindDescriptor *)
        ovc_file_abi_callocate(1, sizeof(*out->ptr));
    out->len = 1;
    ovc_file_descriptor_fill(&out->ptr[0]);
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Async Layer-slot prologues.  The ABI transfers nested request ownership. */
















static void ovc_file_task_fail(ovc_file_task *task,
                               OvStoragePlugin_ErrorCode code,
                               const char *message)
{
    OvStoragePlugin_OnComplete on_complete;
    void *user_data;

    on_complete = task->on_complete;
    user_data = task->user_data;
    ovc_file_task_destroy(task);
    ovc_file_complete_code(on_complete, user_data, code, message);
}

/* The three runtime-state introspection slots are async and cancellable like
 * the data ops: each validates the request prefix, then queues an io-task so
 * the plugin body never runs on the caller thread.  list_kinds stays
 * synchronous (fixed manifest metadata, no I/O). */
static void ovc_file_layer_root_info_for(
    void *state,
    const OvStoragePlugin_RootInfoForRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_RootInfoForRequest moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_root_info_for_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "root_info_for request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_ROOT_INFO_FOR,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovc_file_str_clear(&moved.url);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->address = ovc_file_string_from_slice(&moved.url);
    ovc_file_str_clear(&moved.url);
    if (task->address == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "root_info_for URL is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_list_address_roots(
    void *state,
    const OvStoragePlugin_ListAddressRootsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix reaches,
         * which is what makes it safe on the very struct this branch is
         * rejecting. */
        ovstorage_plugin_list_address_roots_request_release(request);
        ovc_file_complete_code(
            on_complete,
            user_data,
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "list_address_roots request struct_size is too small");
        return;
    }
    task = ovc_file_task_create(OVC_FILE_TASK_LIST_ADDRESS_ROOTS,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_list_connections(
    void *state,
    const OvStoragePlugin_ListConnectionsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix reaches,
         * which is what makes it safe on the very struct this branch is
         * rejecting. */
        ovstorage_plugin_list_connections_request_release(request);
        ovc_file_complete_code(
            on_complete,
            user_data,
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "list_connections request struct_size is too small");
        return;
    }
    task = ovc_file_task_create(OVC_FILE_TASK_LIST_CONNECTIONS,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_stat(
    void *state,
    const OvStoragePlugin_StatRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_StatRequest moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_stat_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "stat request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_STAT,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovc_file_str_clear(&moved.address);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->address = ovc_file_string_from_slice(&moved.address);
    task->payload.stat.full_metadata = moved.options.full_metadata;
    ovc_file_str_clear(&moved.address);
    if (task->address == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "stat address is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_read(
    void *state,
    const OvStoragePlugin_ReadRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ReadRequest moved;
    ovc_file_task *task;
    bool invalid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_read_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "read request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_READ,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_read_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    invalid = false;
    task->address = ovc_file_string_from_slice(&moved.address);
    if (task->address == NULL) {
        invalid = true;
    }
    if (moved.options.if_match.present) {
        task->payload.read.if_match =
            ovc_file_string_from_slice(&moved.options.if_match.value);
        if (task->payload.read.if_match == NULL) {
            invalid = true;
        }
    }
    if (moved.options.range.present) {
        task->payload.read.has_range = true;
        task->payload.read.range_start = moved.options.range.value.start;
        task->payload.read.has_range_end =
            moved.options.range.value.end_inclusive.present;
        if (task->payload.read.has_range_end) {
            task->payload.read.range_end =
                moved.options.range.value.end_inclusive.value;
        }
    }
    ovstorage_plugin_read_request_release(&moved);
    if (invalid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "read request contains an invalid string");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_write(
    void *state,
    const OvStoragePlugin_WriteRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_WriteRequest moved;
    ovc_file_task *task;
    bool invalid;
    bool exhausted;
    bool unsupported_body;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_write_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "write request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_WRITE,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_write_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    invalid = false;
    exhausted = false;
    unsupported_body = moved.body.tag != OvStoragePlugin_BodyTag_Bytes;
    task->address = ovc_file_string_from_slice(&moved.address);
    if (task->address == NULL) {
        invalid = true;
    }
    if (!unsupported_body) {
        if (moved.body.bytes.ptr == NULL) {
            invalid = true;
        } else {
            /* The ABI transfers nested request ownership to the callee, so
             * STEAL the body buffer instead of deep-copying it: copying
             * would transiently double peak memory for the largest buffer
             * this backend ever handles.  ovc_file_task_destroy releases it
             * with ovc_abi_free, matching the dispatcher's mint. */
            task->payload.write.len = moved.body.bytes.len;
            task->payload.write.bytes = moved.body.bytes.ptr;
            moved.body.bytes.ptr = NULL;
            moved.body.bytes.len = 0;
        }
    }
    task->payload.write.if_dest = moved.options.if_dest.tag;
    if (moved.options.if_dest.tag ==
        OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        task->payload.write.match_etag = ovc_file_string_from_slice(
            &moved.options.if_dest.match_etag.etag);
        if (task->payload.write.match_etag == NULL) {
            invalid = true;
        }
    }
    if (moved.options.user_metadata.present) {
        if (!ovc_file_key_value_list_clone(
                &moved.options.user_metadata.value,
                &task->payload.write.user_metadata,
                &exhausted)) {
            invalid = true;
        }
    } else {
        task->payload.write.user_metadata.ptr =
            (OvStoragePlugin_KeyValuePair *)ovc_file_abi_allocate(
                sizeof(*task->payload.write.user_metadata.ptr));
        task->payload.write.user_metadata.len = 0;
    }
    /* File has no version annotation slot; message is intentionally ignored. */
    ovstorage_plugin_write_request_release(&moved);
    if (unsupported_body) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_Unsupported,
                           "buffered file write requires a Bytes body");
        return;
    }
    if (exhausted) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_ResourceExhausted,
                           "not enough memory to copy the write metadata");
        return;
    }
    if (invalid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "write request contains an invalid value");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_list(
    void *state,
    const OvStoragePlugin_ListRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ListRequest moved;
    ovc_file_task *task;
    bool invalid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_list_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "list request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_LIST,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_list_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    invalid = false;
    task->address = ovc_file_string_from_slice(&moved.prefix);
    if (task->address == NULL) {
        invalid = true;
    }
    task->payload.list.recursive = moved.options.recursive;
    task->payload.list.full_metadata = moved.options.full_metadata;
    task->payload.list.has_max_results = moved.options.max_results.present;
    if (task->payload.list.has_max_results) {
        task->payload.list.max_results = moved.options.max_results.value;
    }
    if (moved.options.page_token.present) {
        task->payload.list.page_token = ovc_file_string_from_slice(
            &moved.options.page_token.value);
        if (task->payload.list.page_token == NULL) {
            invalid = true;
        }
    }
    ovstorage_plugin_list_request_release(&moved);
    if (invalid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "list request contains an invalid string");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_delete(
    void *state,
    const OvStoragePlugin_DeleteRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_DeleteRequest moved;
    ovc_file_task *task;
    bool invalid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_delete_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "delete request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_DELETE,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_delete_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    invalid = false;
    task->address = ovc_file_string_from_slice(&moved.address);
    if (task->address == NULL) {
        invalid = true;
    }
    if (moved.options.if_match.present) {
        task->payload.delete_.if_match =
            ovc_file_string_from_slice(&moved.options.if_match.value);
        if (task->payload.delete_.if_match == NULL) {
            invalid = true;
        }
    }
    ovstorage_plugin_delete_request_release(&moved);
    if (invalid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "delete request contains an invalid string");
        return;
    }
    ovc_file_submit_task(task);
}

static bool ovc_file_transfer_task_fill(
    ovc_file_task *task,
    const OvStoragePlugin_Str *source,
    const OvStoragePlugin_Str *destination,
    const OvStoragePlugin_Optional_Str *if_source,
    const OvStoragePlugin_IfDestExistsV1 *if_dest,
    const OvStoragePlugin_Optional_Str *message)
{
    bool valid;

    valid = true;
    task->payload.transfer.source = ovc_file_string_from_slice(source);
    task->payload.transfer.destination =
        ovc_file_string_from_slice(destination);
    if (task->payload.transfer.source == NULL ||
        task->payload.transfer.destination == NULL) {
        valid = false;
    }
    if (if_source->present) {
        task->payload.transfer.if_source =
            ovc_file_string_from_slice(&if_source->value);
        if (task->payload.transfer.if_source == NULL) {
            valid = false;
        }
    }
    task->payload.transfer.if_dest = if_dest->tag;
    if (if_dest->tag == OvStoragePlugin_IfDestExistsTag_MatchEtag) {
        task->payload.transfer.match_etag =
            ovc_file_string_from_slice(&if_dest->match_etag.etag);
        if (task->payload.transfer.match_etag == NULL) {
            valid = false;
        }
    } else if (if_dest->tag != OvStoragePlugin_IfDestExistsTag_Overwrite &&
               if_dest->tag != OvStoragePlugin_IfDestExistsTag_Fail) {
        valid = false;
    }
    if (message->present) {
        task->payload.transfer.message =
            ovc_file_string_from_slice(&message->value);
        if (task->payload.transfer.message == NULL) {
            valid = false;
        }
    }
    return valid;
}

static void ovc_file_layer_copy(
    void *state,
    const OvStoragePlugin_CopyRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_CopyRequest moved;
    ovc_file_task *task;
    bool valid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_copy_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "copy request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_COPY,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_copy_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    valid = ovc_file_transfer_task_fill(task,
                                        &moved.source,
                                        &moved.destination,
                                        &moved.options.if_source,
                                        &moved.options.if_dest,
                                        &moved.options.message);
    ovstorage_plugin_copy_request_release(&moved);
    if (!valid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "copy request contains an invalid value");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_rename(
    void *state,
    const OvStoragePlugin_RenameRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_RenameRequest moved;
    ovc_file_task *task;
    bool valid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_rename_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "rename request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_RENAME,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_rename_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    valid = ovc_file_transfer_task_fill(task,
                                        &moved.source,
                                        &moved.destination,
                                        &moved.options.if_source,
                                        &moved.options.if_dest,
                                        &moved.options.message);
    ovstorage_plugin_rename_request_release(&moved);
    if (!valid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "rename request contains an invalid value");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_update_metadata(
    void *state,
    const OvStoragePlugin_UpdateMetadataRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_UpdateMetadataRequest moved;
    ovc_file_task *task;
    bool valid;
    bool exhausted;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_update_metadata_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "update_metadata request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_UPDATE_METADATA,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_update_metadata_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    valid = true;
    exhausted = false;
    task->address = ovc_file_string_from_slice(&moved.address);
    if (task->address == NULL) {
        valid = false;
    }
    if (moved.options.if_match.present) {
        task->payload.update_metadata.if_match =
            ovc_file_string_from_slice(&moved.options.if_match.value);
        if (task->payload.update_metadata.if_match == NULL) {
            valid = false;
        }
    }
    if (!ovc_file_key_value_list_clone(
            &moved.options.user_metadata_set,
            &task->payload.update_metadata.set,
            &exhausted) ||
        !ovc_file_string_list_clone(
            &moved.options.user_metadata_remove,
            &task->payload.update_metadata.remove,
            &exhausted)) {
        valid = false;
    }
    if (moved.options.message.present) {
        task->payload.update_metadata.message =
            ovc_file_string_from_slice(&moved.options.message.value);
        if (task->payload.update_metadata.message == NULL) {
            valid = false;
        }
    }
    ovstorage_plugin_update_metadata_request_release(&moved);
    if (exhausted) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_ResourceExhausted,
                           "not enough memory to copy the metadata patch");
        return;
    }
    if (!valid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "update_metadata request contains an invalid value");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_check_access(
    void *state,
    const OvStoragePlugin_CheckAccessRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_CheckAccessRequest moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_check_access_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "check_access request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_CHECK_ACCESS,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_check_access_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->address = ovc_file_string_from_slice(&moved.address);
    task->payload.check_access.operations = moved.operations;
    ovstorage_plugin_check_access_request_release(&moved);
    if (task->address == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "check_access address is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_read_like(
    void *state,
    const OvStoragePlugin_ReadRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data,
    ovc_file_task_kind kind,
    const char *label)
{
    OvStoragePlugin_ReadRequest moved;
    ovc_file_task *task;
    bool valid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix reaches,
         * which is what makes it safe on the very struct this branch is
         * rejecting. */
        ovstorage_plugin_read_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               label);
        return;
    }
    moved = *request;
    task = ovc_file_task_create(kind,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_read_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    valid = true;
    task->address = ovc_file_string_from_slice(&moved.address);
    if (task->address == NULL) {
        valid = false;
    }
    if (moved.options.if_match.present) {
        task->payload.read.if_match =
            ovc_file_string_from_slice(&moved.options.if_match.value);
        if (task->payload.read.if_match == NULL) {
            valid = false;
        }
    }
    if (moved.options.range.present) {
        task->payload.read.has_range = true;
        task->payload.read.range_start = moved.options.range.value.start;
        task->payload.read.has_range_end =
            moved.options.range.value.end_inclusive.present;
        if (task->payload.read.has_range_end) {
            task->payload.read.range_end =
                moved.options.range.value.end_inclusive.value;
        }
    }
    ovstorage_plugin_read_request_release(&moved);
    if (!valid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "read-shaped request contains an invalid string");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_materialize(
    void *state,
    const OvStoragePlugin_ReadRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_file_layer_read_like(state,
                             request,
                             cancel,
                             on_complete,
                             user_data,
                             OVC_FILE_TASK_MATERIALIZE,
                             "materialize request struct_size is too small");
}

static void ovc_file_layer_get_latest_version(
    void *state,
    const OvStoragePlugin_ReadRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    ovc_file_layer_read_like(
        state,
        request,
        cancel,
        on_complete,
        user_data,
        OVC_FILE_TASK_GET_LATEST_VERSION,
        "get_latest_version request struct_size is too small");
}

static void ovc_file_layer_list_versions(
    void *state,
    const OvStoragePlugin_ListVersionsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ListVersionsRequest moved;
    ovc_file_task *task;
    bool valid;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_list_versions_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "list_versions request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_LIST_VERSIONS,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_list_versions_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    valid = true;
    task->address = ovc_file_string_from_slice(&moved.address);
    if (task->address == NULL) {
        valid = false;
    }
    task->payload.list_versions.has_max_results =
        moved.options.max_results.present;
    if (task->payload.list_versions.has_max_results) {
        task->payload.list_versions.max_results =
            moved.options.max_results.value;
    }
    if (moved.options.page_token.present) {
        task->payload.list_versions.page_token =
            ovc_file_string_from_slice(&moved.options.page_token.value);
        if (task->payload.list_versions.page_token == NULL) {
            valid = false;
        }
    }
    ovstorage_plugin_list_versions_request_release(&moved);
    if (!valid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "list_versions request contains an invalid string");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_watch_directory(
    void *state,
    const OvStoragePlugin_WatchDirectoryRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_WatchDirectoryRequest moved;
    OvStoragePlugin_WatchDirectoryOptions options;
    char *address;
    ovc_file_watcher *watcher;
    OvStoragePlugin_BackendChangeStream *stream;
    OvStoragePlugin_Error *error;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix reaches,
         * which is what makes it safe on the very struct this branch is
         * rejecting. */
        ovstorage_plugin_watch_directory_request_release(request);
        ovc_file_complete_code(
            on_complete,
            user_data,
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "watch_directory request struct_size is too small");
        return;
    }
    moved = *request;
    options = moved.options;
    address = ovc_file_string_from_slice(&moved.prefix);
    if (moved.options.since.present &&
        moved.options.since.value.bytes.ptr == NULL) {
        free(address);
        address = NULL;
    }
    ovstorage_plugin_watch_directory_request_release(&moved);
    if (address == NULL) {
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "watch_directory prefix or cursor is invalid");
        return;
    }

    error = NULL;
    watcher = ovc_file_watcher_create((ovc_file_layer *)state,
                                      address,
                                      &options,
                                      cancel,
                                      &error);
    free(address);
    if (watcher == NULL) {
        ovc_file_complete_error(on_complete, user_data, error);
        return;
    }
    /* The stream shell is returned across the ABI, so the host reclaims it
     * with ovc_abi_free; the mint is fallible and its failure is handled
     * below. */
    stream = (OvStoragePlugin_BackendChangeStream *)ovc_abi_alloc(
        sizeof(*stream));
    if (stream == NULL) {
        ovc_file_watcher_destroy(watcher);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_ResourceExhausted,
                               "could not allocate file watch stream");
        return;
    }
    memset(stream, 0, sizeof(*stream));
    stream->state = watcher;
    stream->next_fn = ovc_file_watch_next;
    stream->drop_fn = ovc_file_watch_drop;
    on_complete(OvStoragePlugin_FFI_STATUS_OK,
                stream,
                NULL,
                user_data);
}

static void ovc_file_layer_create_directory(
    void *state,
    const OvStoragePlugin_CreateDirectoryRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_CreateDirectoryRequest moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options) ||
        request->options._reserved != 0) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix reaches,
         * which is what makes it safe on the very struct this branch is
         * rejecting. */
        ovstorage_plugin_create_directory_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "create_directory request is invalid");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_CREATE_DIRECTORY,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_create_directory_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->address = ovc_file_string_from_slice(&moved.address);
    ovstorage_plugin_create_directory_request_release(&moved);
    if (task->address == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "create_directory address is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_delete_directory(
    void *state,
    const OvStoragePlugin_DeleteDirectoryRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_DeleteDirectoryRequest moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request) ||
        request->options.struct_size < sizeof(request->options) ||
        request->options._reserved != 0) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix reaches,
         * which is what makes it safe on the very struct this branch is
         * rejecting. */
        ovstorage_plugin_delete_directory_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "delete_directory request is invalid");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_DELETE_DIRECTORY,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_delete_directory_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->address = ovc_file_string_from_slice(&moved.address);
    ovstorage_plugin_delete_directory_request_release(&moved);
    if (task->address == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "delete_directory address is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_add_connection(
    void *state,
    const OvStoragePlugin_LayerConnectionRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_LayerConnectionRequest moved;
    ovc_file_task *task;
    bool invalid;
    bool wrong_type;
    char *prefix;
    bool prefix_wrong_type;
    bool unsupported_prefix;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_layer_connection_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "add_connection request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_ADD_CONNECTION,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_layer_connection_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    invalid = false;
    task->payload.add_connection.target =
        ovc_file_string_from_slice(&moved.target);
    task->payload.add_connection.backend_kind =
        ovc_file_string_from_slice(&moved.connection.backend_kind);
    task->payload.add_connection.root = ovc_file_find_string_config(
        &moved.connection.config, "root", &wrong_type);
    if (wrong_type) {
        invalid = true;
    }
    /* The Rust backend narrows the route and containment scope with the
     * `prefix` config. This backend does not implement that narrowing yet;
     * ignoring the key would silently widen access to the whole root, so a
     * request that carries it must fail loudly instead. */
    prefix = ovc_file_find_string_config(
        &moved.connection.config, "prefix", &prefix_wrong_type);
    unsupported_prefix = prefix != NULL || prefix_wrong_type;
    free(prefix);
    if (moved.connection.display_name.present) {
        task->payload.add_connection.display_name =
            ovc_file_string_from_slice(&moved.connection.display_name.value);
        if (task->payload.add_connection.display_name == NULL) {
            invalid = true;
        }
    }
    task->payload.add_connection.persisted = moved.connection.persist;
    if (task->payload.add_connection.target == NULL ||
        task->payload.add_connection.backend_kind == NULL) {
        invalid = true;
    }
    ovstorage_plugin_layer_connection_request_release(&moved);
    if (unsupported_prefix) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "the file connection `prefix` config is not "
                           "supported by the pure-C backend");
        return;
    }
    if (invalid) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "file connection config is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_remove_connection(
    void *state,
    const OvStoragePlugin_RemoveConnectionRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_ConnectionKey moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_remove_connection_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "remove_connection request struct_size is too small");
        return;
    }
    /* Adopt the key; `extensions` stays borrowed by the caller (the file
     * backend has no extension-sensitive behavior, so it never reads it). */
    moved = request->key;
    task = ovc_file_task_create(OVC_FILE_TASK_REMOVE_CONNECTION,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovc_file_connection_key_clear(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->payload.connection_key.target =
        ovc_file_string_from_slice(&moved.target);
    task->payload.connection_key.id =
        ovc_file_string_from_slice(&moved.id);
    ovc_file_connection_key_clear(&moved);
    if (task->payload.connection_key.target == NULL ||
        task->payload.connection_key.id == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "remove_connection key is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

static void ovc_file_layer_update_credentials(
    void *state,
    const OvStoragePlugin_UpdateConnectionCredentialsRequest *request,
    const OvStoragePlugin_CancelTokenFFI *cancel,
    OvStoragePlugin_OnComplete on_complete,
    void *user_data)
{
    OvStoragePlugin_UpdateConnectionCredentialsRequest moved;
    ovc_file_task *task;

    if (request == NULL || request->struct_size < sizeof(*request)) {
        /* The slot already owns this request, so declining it still owes a
         * release. The release reads only what the caller's prefix
         * reaches, which is what makes it safe on the very struct this
         * branch is rejecting. */
        ovstorage_plugin_update_connection_credentials_request_release(request);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_InvalidArgument,
                               "update_credentials request struct_size is too small");
        return;
    }
    moved = *request;
    task = ovc_file_task_create(OVC_FILE_TASK_UPDATE_CREDENTIALS,
                                (ovc_file_layer *)state,
                                cancel,
                                on_complete,
                                user_data);
    if (task == NULL) {
        ovstorage_plugin_update_connection_credentials_request_release(&moved);
        ovc_file_complete_code(on_complete,
                               user_data,
                               OvStoragePlugin_ErrorCode_Internal,
                               "could not retain file Layer");
        return;
    }
    task->payload.connection_key.target =
        ovc_file_string_from_slice(&moved.key.target);
    task->payload.connection_key.id =
        ovc_file_string_from_slice(&moved.key.id);
    ovstorage_plugin_update_connection_credentials_request_release(&moved);
    if (task->payload.connection_key.target == NULL ||
        task->payload.connection_key.id == NULL) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_InvalidArgument,
                           "update_credentials key is invalid");
        return;
    }
    ovc_file_submit_task(task);
}

/* ------------------------------------------------------------------------- */
/* Built-in factory and Registry seeding. */

static OvStoragePlugin_FfiStatus ovc_file_create_backend(
    void *plugin_state,
    const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out,
    OvStoragePlugin_Error **err)
{
    OvStoragePlugin_CreateBackendRequest moved;
    char *kind;
    char *instance_id;
    ovc_file_layer *layer;

    (void)plugin_state;
    if (err != NULL) {
        *err = NULL;
    }
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (request == NULL || request->struct_size < sizeof(*request) ||
        out == NULL || err == NULL) {
        if (err != NULL) {
            *err = ovc_file_error(OvStoragePlugin_ErrorCode_InvalidArgument,
                                  "file create_backend request is invalid");
        }
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    moved = *request;
    kind = ovc_file_string_from_slice(&moved.kind);
    instance_id = ovc_file_string_from_slice(&moved.instance_id);
    if (kind == NULL || instance_id == NULL || instance_id[0] == '\0' ||
        strcmp(kind, OVC_FILE_KIND) != 0 || moved.config.len != 0) {
        free(kind);
        free(instance_id);
        ovc_file_create_request_clear(&moved);
        *err = ovc_file_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "file create_backend needs kind=file, a name, and no Layer config");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }
    free(kind);
    ovc_file_create_request_clear(&moved);

    layer = (ovc_file_layer *)ovc_file_callocate(1, sizeof(*layer));
    layer->references.value = 1L;
    layer->name = instance_id;
    if (ovc_mutex_init(&layer->mutex) != 0) {
        free(layer->name);
        free(layer);
        *err = ovc_file_error(OvStoragePlugin_ErrorCode_Internal,
                              "could not initialize file Layer mutex");
        return OvStoragePlugin_FFI_STATUS_ERR;
    }

    /* The copied default is the source of every unimplemented slot. */
    layer->vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    layer->vtable.drop = ovc_file_layer_drop;
    layer->vtable.name = ovc_file_layer_name;
    layer->vtable.descriptor = ovc_file_layer_descriptor;
    layer->vtable.owned_targets = ovc_file_layer_owned_targets;
    layer->vtable.root_info_for = ovc_file_layer_root_info_for;
    layer->vtable.list_kinds = ovc_file_layer_list_kinds;
    layer->vtable.list_address_roots = ovc_file_layer_list_address_roots;
    layer->vtable.stat = ovc_file_layer_stat;
    layer->vtable.read = ovc_file_layer_read;
    layer->vtable.write = ovc_file_layer_write;
    layer->vtable.delete_ = ovc_file_layer_delete;
    layer->vtable.copy = ovc_file_layer_copy;
    layer->vtable.rename = ovc_file_layer_rename;
    layer->vtable.update_metadata = ovc_file_layer_update_metadata;
    layer->vtable.check_access = ovc_file_layer_check_access;
    layer->vtable.materialize = ovc_file_layer_materialize;
    layer->vtable.list = ovc_file_layer_list;
    layer->vtable.list_versions = ovc_file_layer_list_versions;
    layer->vtable.get_latest_version =
        ovc_file_layer_get_latest_version;
    layer->vtable.watch_directory = ovc_file_layer_watch_directory;
    layer->vtable.create_directory = ovc_file_layer_create_directory;
    layer->vtable.delete_directory = ovc_file_layer_delete_directory;
    layer->vtable.add_connection = ovc_file_layer_add_connection;
    layer->vtable.remove_connection = ovc_file_layer_remove_connection;
    layer->vtable.list_connections = ovc_file_layer_list_connections;
    layer->vtable.update_connection_credentials =
        ovc_file_layer_update_credentials;

    out->state = layer;
    out->vtable = &layer->vtable;
    return OvStoragePlugin_FFI_STATUS_OK;
}

static void ovc_file_builtin_plugin_drop(void *plugin_state)
{
    (void)plugin_state;
}

static char g_ovc_file_kind[] = OVC_FILE_KIND;
static char g_ovc_file_display_name[] = OVC_FILE_DISPLAY_NAME;
static char g_ovc_file_description[] = OVC_FILE_DESCRIPTION;
static char g_ovc_file_root_key[] = "root";
static char g_ovc_file_root_display_name[] = "Root";
static char g_ovc_file_root_help[] =
    "file:// root or absolute filesystem path exposed by this connection";
static char g_ovc_file_root_example[] = "file:///tmp/ovstorage/";
static OvStoragePlugin_CredentialField g_ovc_file_empty_credential_schema;
static OvStoragePlugin_CredentialMethod g_ovc_file_empty_credential_methods;

static OvStoragePlugin_ConfigField g_ovc_file_root_config_field = {
    .key = {g_ovc_file_root_key, sizeof(g_ovc_file_root_key) - 1},
    .display_name = {g_ovc_file_root_display_name,
                     sizeof(g_ovc_file_root_display_name) - 1},
    .kind = {.tag = OvStoragePlugin_ConfigFieldKindTag_Url},
    .required = true,
    .help = {true,
             {g_ovc_file_root_help, sizeof(g_ovc_file_root_help) - 1}},
    .example = {
        true,
        {g_ovc_file_root_example, sizeof(g_ovc_file_root_example) - 1}},
};

static const OvStoragePlugin_LayerKindDescriptor
    g_ovc_file_builtin_descriptor = {
        .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
        .layer_type = OvStoragePlugin_LayerType_Backend,
        .accepts_connections = true,
        .supports_user_metadata = true,
        .kind = {g_ovc_file_kind, sizeof(g_ovc_file_kind) - 1},
        .display_name = {g_ovc_file_display_name,
                         sizeof(g_ovc_file_display_name) - 1},
        .description = {
            true,
            {g_ovc_file_description, sizeof(g_ovc_file_description) - 1}},
        .config_schema = {&g_ovc_file_root_config_field, 1},
        .credential_schema = {&g_ovc_file_empty_credential_schema, 0},
        .credential_methods = {&g_ovc_file_empty_credential_methods, 0},
        .auth_capable = false,
};

static const OvStoragePlugin_PluginVTableV1 g_ovc_file_builtin_vtable = {
    .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = ovc_file_builtin_plugin_drop,
    .create_backend = ovc_file_create_backend,
    .create_wrapper = NULL,
    .create_router = NULL,
};

OvStorage_Status ovstorage_c_register_builtin_kinds(
    OvStorage_Registry *registry,
    OvStorage_Error *out_error)
{
    return ovc_registry_register_builtin_kind(
        registry,
        &g_ovc_file_builtin_descriptor,
        NULL,
        &g_ovc_file_builtin_vtable,
        out_error);
}

#if defined(OVC_FILE_BACKEND_TEST_MAIN)

#include <assert.h>

#include "temp_dir.h"

#if defined(NDEBUG)
#error "OVC_FILE_BACKEND_TEST_MAIN requires assertions to be enabled"
#endif

typedef struct ovc_file_test_completion {
    ovc_completion_latch latch;
    int32_t status;
    void *result;
    OvStoragePlugin_Error *error;
} ovc_file_test_completion;

/* The production definition lives in registry.c.  The focused backend test
 * links no registry implementation, but file_backend.c's public seeding hook
 * still needs a definition at link time. */
OvStorage_Status ovc_registry_register_builtin_kind(
    OvStorage_Registry *registry,
    const OvStoragePlugin_LayerKindDescriptor *descriptor,
    void *plugin_state,
    const OvStoragePlugin_PluginVTableV1 *plugin_vtable,
    OvStorage_Error *out_error)
{
    (void)registry;
    (void)descriptor;
    (void)plugin_state;
    (void)plugin_vtable;
    (void)out_error;
    return OvStorage_Status_Ok;
}

static void ovc_file_test_complete(int32_t status,
                                   void *result,
                                   OvStoragePlugin_Error *error,
                                   void *user_data)
{
    ovc_file_test_completion *completion;

    completion = (ovc_file_test_completion *)user_data;
    completion->status = status;
    completion->result = result;
    completion->error = error;
    assert(ovc_completion_latch_complete(&completion->latch) == 0);
}

static void ovc_file_test_completion_init(
    ovc_file_test_completion *completion)
{
    memset(completion, 0, sizeof(*completion));
    assert(ovc_completion_latch_init(&completion->latch) == 0);
}

static void ovc_file_test_completion_wait(
    ovc_file_test_completion *completion)
{
    assert(ovc_completion_latch_wait(&completion->latch) == 0);
    assert(ovc_completion_latch_destroy(&completion->latch) == 0);
}

/* Wait for an async op and require it succeeded.
 *
 * `what` names the operation, and a failure prints it alongside the status and
 * the producer's message before asserting. The assertion itself sits in this
 * shared helper, so its file and line identify the helper rather than any of
 * the callers -- without the label, a failure on a remote runner says only
 * that one of them failed, and discards the error that says why. */
static void ovc_file_test_expect_success(
    const char *what,
    ovc_file_test_completion *completion)
{
    ovc_file_test_completion_wait(completion);
    if (completion->status != OvStoragePlugin_FFI_STATUS_OK ||
        completion->error != NULL) {
        const char *message = "(none)";

        if (completion->error != NULL && completion->error->message_ptr != NULL) {
            message = (const char *)completion->error->message_ptr;
        }
        (void)fprintf(stderr,
                      "%s failed: status=%d message=%s\n",
                      what,
                      (int)completion->status,
                      message);
        (void)fflush(stderr);
    }
    assert(completion->status == OvStoragePlugin_FFI_STATUS_OK);
    assert(completion->error == NULL);
}

static OvStoragePlugin_CreateBackendRequest
ovc_file_test_create_backend_request(void)
{
    OvStoragePlugin_CreateBackendRequest request;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.kind = ovc_file_owned_string(OVC_FILE_KIND);
    request.instance_id = ovc_file_owned_string("files");
    request.config.ptr = (OvStoragePlugin_ConnectionConfigEntry *)
        ovc_file_abi_allocate(sizeof(*request.config.ptr));
    request.config.len = 0;
    return request;
}

static OvStoragePlugin_LayerConnectionRequest
ovc_file_test_add_request(const char *root_url)
{
    OvStoragePlugin_LayerConnectionRequest request;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.target = ovc_file_owned_string("files");
    request.connection.backend_kind = ovc_file_owned_string(OVC_FILE_KIND);
    request.connection.config.ptr = (OvStoragePlugin_ConnectionConfigEntry *)
        ovc_file_abi_callocate(1, sizeof(*request.connection.config.ptr));
    request.connection.config.len = 1;
    request.connection.config.ptr[0].key = ovc_file_owned_string("root");
    request.connection.config.ptr[0].value.tag =
        OvStoragePlugin_ConfigValueTag_String;
    request.connection.config.ptr[0].value.string_value =
        ovc_file_owned_string(root_url);
    request.connection.credentials.entries.ptr =
        (OvStoragePlugin_SecretBundleEntry *)ovc_file_abi_allocate(
            sizeof(*request.connection.credentials.entries.ptr));
    request.connection.credentials.entries.len = 0;
    request.connection.persist = false;
    return request;
}

static void ovc_file_test_write(OvStoragePlugin_LayerHandle *handle,
                                const char *address,
                                const uint8_t *bytes,
                                size_t length)
{
    OvStoragePlugin_WriteRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_WriteResult *result;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.body.tag = OvStoragePlugin_BodyTag_Bytes;
    /* The plugin steals this buffer and frees it with ovc_abi_free. */
    request.body.bytes.ptr = (uint8_t *)
        ovc_file_abi_allocate(length == 0 ? 1 : length);
    request.body.bytes.len = length;
    if (length != 0) {
        memcpy(request.body.bytes.ptr, bytes, length);
    } else {
        request.body.bytes.ptr[0] = 0;
    }
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;
    ovc_file_test_completion_init(&completion);
    handle->vtable->write(handle->state,
                          &request,
                          NULL,
                          ovc_file_test_complete,
                          &completion);
    ovc_file_test_expect_success("write", &completion);
    result = (OvStoragePlugin_WriteResult *)completion.result;
    assert(result != NULL);
    assert(result->info.size.present);
    assert(result->info.size.value == length);
    ovc_file_object_info_clear(&result->info);
    ovc_abi_free(result);
}

static void ovc_file_test_stat(OvStoragePlugin_LayerHandle *handle,
                               const char *address,
                               size_t expected_size)
{
    OvStoragePlugin_StatRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ObjectInfo *result;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->stat(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("stat", &completion);
    result = (OvStoragePlugin_ObjectInfo *)completion.result;
    assert(result != NULL);
    assert(result->kind == OvStoragePlugin_ObjectKindV1_File);
    assert(result->size.present);
    assert(result->size.value == expected_size);
    assert(result->mtime_unix_ms.present);
    ovc_file_object_info_clear(result);
    ovc_abi_free(result);
}

static void ovc_file_test_read(OvStoragePlugin_LayerHandle *handle,
                               const char *address,
                               const uint8_t *expected,
                               size_t expected_length)
{
    OvStoragePlugin_ReadRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ReadResult *result;

    /* A whole-object read returns a LocalDelegate; the delegate's canonical
     * path must serve the bytes. */
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->read(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("read", &completion);
    result = (OvStoragePlugin_ReadResult *)completion.result;
    assert(result != NULL);
    assert(result->tag == OvStoragePlugin_ReadResultTag_LocalDelegate);
    assert(result->local_delegate.info.size.present);
    assert(result->local_delegate.info.size.value == expected_length);
    {
        char *path;
        ovc_file file;
        uint8_t *bytes;
        ovc_ssize_t count;

        path = ovc_file_string_from_slice(&result->local_delegate.path);
        assert(path != NULL);
        file = ovc_file_native_open_read(path);
        assert(file != OVC_INVALID_FILE);
        bytes = (uint8_t *)ovc_file_allocate(
            expected_length == 0 ? 1 : expected_length);
        count = ovc_pread(file, bytes, expected_length, 0);
        assert(count == (ovc_ssize_t)expected_length);
        assert(memcmp(bytes, expected, expected_length) == 0);
        assert(ovc_file_native_close(file) == 0);
        free(bytes);
        free(path);
    }
    ovc_file_str_clear(&result->local_delegate.path);
    ovc_file_object_info_clear(&result->local_delegate.info);
    ovc_abi_free(result);

    /* A ranged read (here: the full window) is the only path that buffers
     * bytes, and it returns them as Bytes. */
    if (expected_length != 0) {
        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.address = ovc_file_owned_string(address);
        request.options.struct_size = sizeof(request.options);
        request.options.range.present = true;
        request.options.range.value.start = 0;
        request.options.range.value.end_inclusive.present = true;
        request.options.range.value.end_inclusive.value =
            expected_length - 1;
        ovc_file_test_completion_init(&completion);
        handle->vtable->read(handle->state,
                             &request,
                             NULL,
                             ovc_file_test_complete,
                             &completion);
        ovc_file_test_expect_success("read", &completion);
        result = (OvStoragePlugin_ReadResult *)completion.result;
        assert(result != NULL);
        assert(result->tag == OvStoragePlugin_ReadResultTag_Bytes);
        assert(result->bytes.bytes.len == expected_length);
        assert(memcmp(result->bytes.bytes.ptr,
                      expected,
                      expected_length) == 0);
        ovc_file_bytes_clear(&result->bytes.bytes, false);
        ovc_file_object_info_clear(&result->bytes.info);
        ovc_abi_free(result);
    }
}

static void ovc_file_test_list(OvStoragePlugin_LayerHandle *handle,
                               const char *root_url)
{
    OvStoragePlugin_ListRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ListPage *page;
    char *next_token;
    size_t index;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.prefix = ovc_file_owned_string(root_url);
    request.options.struct_size = sizeof(request.options);
    request.options.max_results.present = true;
    request.options.max_results.value = 1;
    ovc_file_test_completion_init(&completion);
    handle->vtable->list(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("list", &completion);
    page = (OvStoragePlugin_ListPage *)completion.result;
    assert(page != NULL);
    assert(page->items.len == 1);
    assert(page->next_page_token.present);
    next_token = ovc_file_string_from_slice(&page->next_page_token.value);
    assert(next_token != NULL);
    for (index = 0; index < page->items.len; ++index) {
        ovc_file_object_info_clear(&page->items.ptr[index]);
    }
    ovc_abi_free(page->items.ptr);
    ovc_file_str_clear(&page->next_page_token.value);
    ovc_abi_free(page);

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.prefix = ovc_file_owned_string(root_url);
    request.options.struct_size = sizeof(request.options);
    request.options.max_results.present = true;
    request.options.max_results.value = 1;
    request.options.page_token.present = true;
    request.options.page_token.value = ovc_file_owned_string(next_token);
    free(next_token);
    ovc_file_test_completion_init(&completion);
    handle->vtable->list(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("list", &completion);
    page = (OvStoragePlugin_ListPage *)completion.result;
    assert(page != NULL);
    assert(page->items.len == 1);
    assert(!page->next_page_token.present);
    for (index = 0; index < page->items.len; ++index) {
        ovc_file_object_info_clear(&page->items.ptr[index]);
    }
    ovc_abi_free(page->items.ptr);
    ovc_abi_free(page);
}

static void ovc_file_test_empty_list(OvStoragePlugin_LayerHandle *handle,
                                     const char *root_url)
{
    OvStoragePlugin_ListRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ListPage *page;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.prefix = ovc_file_owned_string(root_url);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->list(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("empty_list", &completion);
    page = (OvStoragePlugin_ListPage *)completion.result;
    assert(page != NULL);
    assert(page->items.ptr != NULL);
    assert(page->items.len == 0);
    assert(!page->next_page_token.present);
    ovc_abi_free(page->items.ptr);
    ovc_abi_free(page);
}

static void ovc_file_test_introspection(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    OvStoragePlugin_Str name;
    OvStoragePlugin_LayerKindDescriptor descriptor;
    OvStoragePlugin_List_Str owned;
    OvStoragePlugin_List_LayerKindDescriptor kinds;
    OvStoragePlugin_Error *error;
    size_t index;

    memset(&name, 0, sizeof(name));
    handle->vtable->name(handle->state, &name);
    assert(name.len == 5);
    assert(memcmp(name.ptr, "files", 5) == 0);
    ovc_file_str_clear(&name);

    memset(&descriptor, 0, sizeof(descriptor));
    handle->vtable->descriptor(handle->state, &descriptor);
    assert(descriptor.layer_type == OvStoragePlugin_LayerType_Backend);
    assert(descriptor.accepts_connections);
    assert(descriptor.config_schema.len == 1);
    ovc_file_descriptor_clear(&descriptor);

    memset(&owned, 0, sizeof(owned));
    handle->vtable->owned_targets(handle->state, &owned);
    assert(owned.len == 1);
    assert(owned.ptr[0].len == 5);
    ovc_file_str_clear(&owned.ptr[0]);
    ovc_abi_free(owned.ptr);

    memset(&kinds, 0, sizeof(kinds));
    error = handle->vtable->list_kinds(handle->state, NULL, &kinds);
    assert(error == NULL);
    assert(kinds.len == 1);
    ovc_file_descriptor_clear(&kinds.ptr[0]);
    ovc_abi_free(kinds.ptr);

    {
        OvStoragePlugin_ListAddressRootsRequest request;
        ovc_file_test_completion completion;
        OvStoragePlugin_ListAddressRootsResult *result;

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        ovc_file_test_completion_init(&completion);
        handle->vtable->list_address_roots(handle->state,
                                           &request,
                                           NULL,
                                           ovc_file_test_complete,
                                           &completion);
        ovc_file_test_expect_success("introspection", &completion);
        result =
            (OvStoragePlugin_ListAddressRootsResult *)completion.result;
        assert(result != NULL);
        assert(result->updates == NULL);
        assert(!result->snapshot.updates);
        assert(result->snapshot.roots.len == 1);
        assert(result->snapshot.roots.ptr[0].root.len == strlen(root_url));
        for (index = 0; index < result->snapshot.roots.len; ++index) {
            ovc_file_root_info_clear(&result->snapshot.roots.ptr[index]);
        }
        ovc_abi_free(result->snapshot.roots.ptr);
        ovc_abi_free(result);
    }

    {
        OvStoragePlugin_RootInfoForRequest request;
        ovc_file_test_completion completion;
        OvStoragePlugin_RootInfo *result;

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.url = ovc_file_owned_string(root_url);
        ovc_file_test_completion_init(&completion);
        handle->vtable->root_info_for(handle->state,
                                      &request,
                                      NULL,
                                      ovc_file_test_complete,
                                      &completion);
        ovc_file_test_expect_success("introspection", &completion);
        result = (OvStoragePlugin_RootInfo *)completion.result;
        assert(result != NULL);
        assert(result->connection_id.present);
        /* A connection-owned root reports its owning target = the layer
         * INSTANCE name ("files", deliberately different from the "file"
         * kind), NOT the descriptor kind; the clear below frees that owning
         * `Optional<Str>` (exercised leak-clean under the sanitizer gate). */
        assert(result->owning_target.present);
        assert(result->owning_target.value.len == 5);
        assert(memcmp(result->owning_target.value.ptr, "files", 5) == 0);
        assert(result->source.tag ==
               OvStoragePlugin_RouteSourceTag_ConnectionContributed);
        ovc_file_root_info_clear(result);
        ovc_abi_free(result);
    }
}

static char *ovc_file_test_connection_id(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    OvStoragePlugin_LayerConnectionRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_Connection *connection;
    char *id;

    request = ovc_file_test_add_request(root_url);
    ovc_file_test_completion_init(&completion);
    handle->vtable->add_connection(handle->state,
                                   &request,
                                   NULL,
                                   ovc_file_test_complete,
                                   &completion);
    ovc_file_test_expect_success("connection_id", &completion);
    connection = (OvStoragePlugin_Connection *)completion.result;
    assert(connection != NULL);
    assert(connection->current_addresses.len == 1);
    assert(connection->auth_state.tag ==
           OvStoragePlugin_ConnectionAuthStateTag_Anonymous);
    id = ovc_file_string_from_slice(&connection->id.id);
    assert(id != NULL);
    ovc_file_connection_ffi_clear(connection);
    ovc_abi_free(connection);
    return id;
}

static void ovc_file_test_connections(OvStoragePlugin_LayerHandle *handle,
                                      const char *connection_id)
{
    OvStoragePlugin_UpdateConnectionCredentialsRequest update;
    OvStoragePlugin_RemoveConnectionRequest remove;
    ovc_file_test_completion completion;
    OvStoragePlugin_Connection *connection;
    size_t index;

    {
        OvStoragePlugin_ListConnectionsRequest request;
        OvStoragePlugin_ListConnectionsResult *result;

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        ovc_file_test_completion_init(&completion);
        handle->vtable->list_connections(handle->state,
                                         &request,
                                         NULL,
                                         ovc_file_test_complete,
                                         &completion);
        ovc_file_test_expect_success("connections", &completion);
        result = (OvStoragePlugin_ListConnectionsResult *)completion.result;
        assert(result != NULL);
        assert(result->updates == NULL);
        assert(result->snapshot.connections.len == 1);
        for (index = 0; index < result->snapshot.connections.len; ++index) {
            ovc_file_connection_ffi_clear(
                &result->snapshot.connections.ptr[index]);
        }
        ovc_abi_free(result->snapshot.connections.ptr);
        ovc_abi_free(result);
    }

    memset(&update, 0, sizeof(update));
    update.struct_size = sizeof(update);
    update.key.target = ovc_file_owned_string("files");
    update.key.id = ovc_file_owned_string(connection_id);
    update.credentials.entries.ptr = (OvStoragePlugin_SecretBundleEntry *)
        ovc_file_abi_allocate(sizeof(*update.credentials.entries.ptr));
    update.credentials.entries.len = 0;
    ovc_file_test_completion_init(&completion);
    handle->vtable->update_connection_credentials(
        handle->state,
        &update,
        NULL,
        ovc_file_test_complete,
        &completion);
    ovc_file_test_expect_success("connections", &completion);
    connection = (OvStoragePlugin_Connection *)completion.result;
    assert(connection != NULL);
    assert(connection->id.id.len == strlen(connection_id));
    ovc_file_connection_ffi_clear(connection);
    ovc_abi_free(connection);

    memset(&remove, 0, sizeof(remove));
    remove.struct_size = sizeof(remove);
    remove.key.target = ovc_file_owned_string("files");
    remove.key.id = ovc_file_owned_string(connection_id);
    ovc_file_test_completion_init(&completion);
    handle->vtable->remove_connection(handle->state,
                                      &remove,
                                      NULL,
                                      ovc_file_test_complete,
                                      &completion);
    ovc_file_test_expect_success("connections", &completion);
    assert(completion.result == NULL);
}

static void ovc_file_backend_item_info_clear(
    OvStoragePlugin_BackendItemInfo *info)
{
    OvStoragePlugin_ObjectInfo object;

    memset(&object, 0, sizeof(object));
    object.kind = info->kind;
    object.etag = info->etag;
    object.version = info->version;
    object.size = info->size;
    object.mtime_unix_ms = info->mtime_unix_ms;
    object.checksums = info->checksums;
    object.effective_permissions = info->effective_permissions;
    object.system_metadata = info->system_metadata;
    object.user_metadata = info->user_metadata;
    object.modified_by = info->modified_by;
    ovc_file_object_info_clear(&object);
    memset(info, 0, sizeof(*info));
}

static void ovc_file_test_update_metadata(
    OvStoragePlugin_LayerHandle *handle,
    const char *address)
{
    OvStoragePlugin_UpdateMetadataRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_BackendItemInfo *result;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    request.options.user_metadata_set.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_file_abi_callocate(
            1, sizeof(*request.options.user_metadata_set.ptr));
    request.options.user_metadata_set.len = 1;
    request.options.user_metadata_set.ptr[0].key =
        ovc_file_owned_string("purpose");
    request.options.user_metadata_set.ptr[0].value =
        ovc_file_owned_string("roundtrip");
    request.options.user_metadata_remove.ptr =
        (OvStoragePlugin_Str *)ovc_file_abi_allocate(
            sizeof(*request.options.user_metadata_remove.ptr));
    request.options.user_metadata_remove.len = 0;
    ovc_file_test_completion_init(&completion);
    handle->vtable->update_metadata(handle->state,
                                    &request,
                                    NULL,
                                    ovc_file_test_complete,
                                    &completion);
    ovc_file_test_expect_success("update_metadata", &completion);
    result = (OvStoragePlugin_BackendItemInfo *)completion.result;
    assert(result != NULL);
    assert(result->user_metadata.present);
    assert(result->user_metadata.value.len == 1);
    assert(result->user_metadata.value.ptr[0].key.len == 7);
    assert(memcmp(result->user_metadata.value.ptr[0].key.ptr,
                  "purpose",
                  7) == 0);
    assert(result->user_metadata.value.ptr[0].value.len == 9);
    assert(memcmp(result->user_metadata.value.ptr[0].value.ptr,
                  "roundtrip",
                  9) == 0);
    ovc_file_backend_item_info_clear(result);
    ovc_abi_free(result);
}

/* The on-disk sidecar layout is a cross-implementation contract: the Rust
 * reference must find the metadata this backend writes and vice versa, so
 * assert the exact reference spelling
 * `<parent>/.ovstorage-meta/<lowercase-hex(name)>.meta` (metadata.rs). */
static void ovc_file_test_metadata_sidecar_layout(
    const char *parent_directory,
    const char *object_name)
{
    static const char hex[] = "0123456789abcdef";
    char *encoded;
    char *metadata_directory;
    char *sidecar;
    size_t length;
    size_t index;
    ovc_file_stat info;

    length = strlen(object_name);
    encoded = (char *)ovc_file_allocate(
        length * 2 + sizeof(OVC_FILE_METADATA_SUFFIX));
    for (index = 0; index < length; ++index) {
        unsigned char byte;

        byte = (unsigned char)object_name[index];
        encoded[index * 2] = hex[byte >> 4];
        encoded[index * 2 + 1] = hex[byte & 0x0f];
    }
    memcpy(encoded + length * 2,
           OVC_FILE_METADATA_SUFFIX,
           sizeof(OVC_FILE_METADATA_SUFFIX));
    metadata_directory = ovc_path_join(parent_directory,
                                       OVC_FILE_METADATA_DIRECTORY);
    assert(metadata_directory != NULL);
    sidecar = ovc_path_join(metadata_directory, encoded);
    assert(sidecar != NULL);
    assert(ovc_file_native_stat_path(sidecar, &info) == 0);
    assert(info.is_regular);
    free(sidecar);
    free(metadata_directory);
    free(encoded);
}

static void ovc_file_test_copy(OvStoragePlugin_LayerHandle *handle,
                               const char *source,
                               const char *destination,
                               size_t expected_size)
{
    OvStoragePlugin_CopyRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_WriteStep *result;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.source = ovc_file_owned_string(source);
    request.destination = ovc_file_owned_string(destination);
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag =
        OvStoragePlugin_IfDestExistsTag_Overwrite;
    ovc_file_test_completion_init(&completion);
    handle->vtable->copy(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("copy", &completion);
    result = (OvStoragePlugin_WriteStep *)completion.result;
    assert(result != NULL);
    assert(result->tag == OvStoragePlugin_WriteStepTag_Done);
    assert(result->done.info.size.present);
    assert(result->done.info.size.value == expected_size);
    assert(result->done.info.user_metadata.present);
    assert(result->done.info.user_metadata.value.len == 1);
    ovc_file_object_info_clear(&result->done.info);
    ovc_abi_free(result);
}

static void ovc_file_test_rename(OvStoragePlugin_LayerHandle *handle,
                                 const char *source,
                                 const char *destination)
{
    OvStoragePlugin_RenameRequest request;
    ovc_file_test_completion completion;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.source = ovc_file_owned_string(source);
    request.destination = ovc_file_owned_string(destination);
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag =
        OvStoragePlugin_IfDestExistsTag_Overwrite;
    ovc_file_test_completion_init(&completion);
    handle->vtable->rename(handle->state,
                           &request,
                           NULL,
                           ovc_file_test_complete,
                           &completion);
    ovc_file_test_expect_success("rename", &completion);
    assert(completion.result == NULL);
}

static void ovc_file_test_delete(OvStoragePlugin_LayerHandle *handle,
                                 const char *address)
{
    OvStoragePlugin_DeleteRequest request;
    ovc_file_test_completion completion;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->delete_(handle->state,
                            &request,
                            NULL,
                            ovc_file_test_complete,
                            &completion);
    ovc_file_test_expect_success("delete", &completion);
    assert(completion.result == NULL);
}

typedef struct ovc_file_test_watch_next {
    OvStoragePlugin_BackendChangeStream *stream;
    ovc_completion_latch entered;
    OvStoragePlugin_StreamStep step;
    OvStoragePlugin_BackendChangeEvent event;
    OvStoragePlugin_Error error;
} ovc_file_test_watch_next;

static void ovc_file_test_watch_event_clear(
    OvStoragePlugin_BackendChangeEvent *event)
{
    if (event->tag == OvStoragePlugin_BackendChangeEventTag_Object) {
        ovc_file_str_clear(&event->object.address);
        if (event->object.etag.present) {
            ovc_file_str_clear(&event->object.etag.value);
        }
        if (event->object.version.present) {
            ovc_file_str_clear(&event->object.version.value);
        }
        ovc_file_bytes_clear(&event->object.cursor.bytes, false);
    } else if (event->tag ==
               OvStoragePlugin_BackendChangeEventTag_Lapsed) {
        ovc_file_bytes_clear(&event->lapsed.cursor.bytes, false);
    }
    memset(event, 0, sizeof(*event));
}

static void ovc_file_test_watch_next_run(void *argument)
{
    ovc_file_test_watch_next *call;

    call = (ovc_file_test_watch_next *)argument;
    call->step = call->stream->next_fn(call->stream->state,
                                       &call->event,
                                       &call->error);
}

static void ovc_file_test_watch_next_start(
    ovc_file_test_watch_next *call,
    OvStoragePlugin_BackendChangeStream *stream,
    ovc_thread *thread)
{
    memset(call, 0, sizeof(*call));
    call->stream = stream;
    assert(ovc_completion_latch_init(&call->entered) == 0);
    assert(((ovc_file_watcher *)stream->state)->test_wait_entered == NULL);
    ((ovc_file_watcher *)stream->state)->test_wait_entered =
        &call->entered;
    assert(ovc_thread_create(thread,
                             ovc_file_test_watch_next_run,
                             call) == 0);
    assert(ovc_completion_latch_wait(&call->entered) == 0);
    assert(ovc_completion_latch_destroy(&call->entered) == 0);
}

static OvStoragePlugin_BackendChangeStream *ovc_file_test_watch_open(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url,
    uint64_t poll_interval_ms,
    const OvStoragePlugin_CancelTokenFFI *cancel)
{
    OvStoragePlugin_WatchDirectoryRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_BackendChangeStream *stream;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.prefix = ovc_file_owned_string(root_url);
    request.options.struct_size = sizeof(request.options);
    request.options.poll_interval_ms = poll_interval_ms;
    ovc_file_test_completion_init(&completion);
    handle->vtable->watch_directory(handle->state,
                                    &request,
                                    cancel,
                                    ovc_file_test_complete,
                                    &completion);
    ovc_file_test_expect_success("watch_open", &completion);
    stream = (OvStoragePlugin_BackendChangeStream *)completion.result;
    assert(stream != NULL);
    assert(stream->state != NULL);
    assert(stream->next_fn == ovc_file_watch_next);
    assert(stream->drop_fn == ovc_file_watch_drop);
    return stream;
}

static void ovc_file_test_watch_drop_once(
    OvStoragePlugin_BackendChangeStream *stream)
{
    unsigned int before;

    before = g_ovc_file_watch_test_drop_count;
    stream->drop_fn(stream->state);
    assert(g_ovc_file_watch_test_drop_count == before + 1);
    ovc_abi_free(stream);
}

static void ovc_file_test_watch_created(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    static const uint8_t payload[] = "watched";
    static const uint8_t updated_payload[] = "watched and modified";
    OvStoragePlugin_BackendChangeStream *stream;
    ovc_file_test_watch_next call;
    ovc_thread thread;
    char *address;

    stream = ovc_file_test_watch_open(handle, root_url, 0, NULL);
    assert(((ovc_file_watcher *)stream->state)->poll_interval_ms ==
           OVC_FILE_MIN_WATCH_POLL_MS);
    ovc_file_test_watch_next_start(&call, stream, &thread);
    address = ovc_file_join_address(root_url, "watch-created.txt", false);
    ovc_file_test_write(handle, address, payload, sizeof(payload) - 1);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Created);
    assert(call.event.object.address.len == strlen(address));
    assert(memcmp(call.event.object.address.ptr,
                  address,
                  strlen(address)) == 0);
    assert(call.event.object.etag.present);
    assert(call.event.object.size.present);
    assert(call.event.object.size.value == sizeof(payload) - 1);
    assert(call.event.object.mtime_unix_ms.present);
    ovc_file_test_watch_event_clear(&call.event);

    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovc_file_test_write(handle,
                        address,
                        updated_payload,
                        sizeof(updated_payload) - 1);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Modified);
    assert(call.event.object.size.present);
    assert(call.event.object.size.value == sizeof(updated_payload) - 1);
    ovc_file_test_watch_event_clear(&call.event);

    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovc_file_test_delete(handle, address);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Deleted);
    assert(!call.event.object.etag.present);
    assert(!call.event.object.size.present);
    assert(!call.event.object.mtime_unix_ms.present);
    ovc_file_test_watch_event_clear(&call.event);

    ovc_file_test_watch_drop_once(stream);
    free(address);
}

static void ovc_file_test_watch_cancel(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    OvStorage_CancelToken *token;
    OvStoragePlugin_CancelTokenFFI cancel;
    OvStoragePlugin_BackendChangeStream *stream;
    ovc_file_test_watch_next call;
    ovc_thread thread;
    uint64_t started;
    uint64_t elapsed;
    OvStoragePlugin_BackendChangeEvent event;
    OvStoragePlugin_Error error;

    token = ovstorage_cancel_token_create();
    assert(token != NULL);
    cancel = ovc_cancel_token_mint(token);
    stream = ovc_file_test_watch_open(handle,
                                      root_url,
                                      UINT64_C(30000),
                                      &cancel);
    cancel.drop(cancel.state);

    ovc_file_test_watch_next_start(&call, stream, &thread);
    started = ovc_monotonic_ns();
    assert(started != 0);
    ovstorage_cancel_token_cancel(token);
    assert(ovc_thread_join(&thread) == 0);
    elapsed = ovc_monotonic_ns() - started;
    assert(call.step == OvStoragePlugin_StreamStep_Ended);
    assert(elapsed < UINT64_C(2000000000));

    memset(&event, 0, sizeof(event));
    memset(&error, 0, sizeof(error));
    assert(stream->next_fn(stream->state, &event, &error) ==
           OvStoragePlugin_StreamStep_Ended);
    ovc_file_test_watch_drop_once(stream);
    ovstorage_cancel_token_destroy(token);
}

/* An async op's task holds its own counted reference on the layer and
 * releases it only *after* its completion callback returns, so a completion
 * that woke this thread does not prove the worker is done with the layer.
 * A test that wants the next handle it takes to be the layer's sole other
 * owner waits here first: the reference count falling back to the Layer
 * handle's single reference is the observable proof.  A timeout means the
 * worker never retired, which is a failure, not a reason to continue. */
static void ovc_file_test_await_sole_layer_reference(
    OvStoragePlugin_LayerHandle *handle)
{
    ovc_file_layer *layer;
    ovc_mutex mutex;
    ovc_cond condition;
    uint64_t started;
    uint64_t deadline;

    layer = (ovc_file_layer *)handle->state;
    started = ovc_monotonic_ns();
    assert(started != 0);
    deadline = started + UINT64_C(30000000000);
    assert(ovc_mutex_init(&mutex) == 0);
    assert(ovc_cond_init(&condition) == 0);
    assert(ovc_mutex_lock(&mutex) == 0);
    while (ovc_file_test_counter_load(&layer->references.value) != 1L) {
        assert(ovc_monotonic_ns() < deadline);
        (void)ovc_cond_timedwait_ns(&condition, &mutex, UINT64_C(200000));
    }
    assert(ovc_mutex_unlock(&mutex) == 0);
    assert(ovc_cond_destroy(&condition) == 0);
    assert(ovc_mutex_destroy(&mutex) == 0);
}

/* The change stream a completed watch hands back is a derived handle: the
 * host owns it and may drop its Layer reference while still draining the
 * stream.  The watcher's own counted reference on the layer is what keeps
 * that legal, so this drives the whole sequence against a Layer handle of
 * its own -- open, drop the Layer, drain, drop the stream -- and pins both
 * that the layer survives the Layer drop and that the stream drop is what
 * finally retires it. */
static void ovc_file_test_watch_outlives_layer(const char *root_url)
{
    OvStoragePlugin_CreateBackendRequest create;
    OvStoragePlugin_LayerHandle handle;
    OvStoragePlugin_Error *factory_error;
    OvStoragePlugin_FfiStatus factory_status;
    OvStorage_CancelToken *token;
    OvStoragePlugin_CancelTokenFFI cancel;
    OvStoragePlugin_BackendChangeStream *stream;
    ovc_file_test_watch_next call;
    ovc_thread thread;
    long destroyed_before;
    unsigned int dropped_before;
    char *connection_id;

    create = ovc_file_test_create_backend_request();
    memset(&handle, 0, sizeof(handle));
    factory_error = NULL;
    factory_status = ovc_file_create_backend(NULL,
                                             &create,
                                             &handle,
                                             &factory_error);
    assert(factory_status == OvStoragePlugin_FFI_STATUS_OK);
    assert(factory_error == NULL);
    connection_id = ovc_file_test_connection_id(&handle, root_url);
    /* Seeding the connection ran an async task that took its own reference;
     * the assertions below only mean what they say once the layer is back
     * to the Layer handle alone. */
    ovc_file_test_await_sole_layer_reference(&handle);

    token = ovstorage_cancel_token_create();
    assert(token != NULL);
    cancel = ovc_cancel_token_mint(token);
    stream = ovc_file_test_watch_open(&handle,
                                      root_url,
                                      UINT64_C(30000),
                                      &cancel);
    cancel.drop(cancel.state);

    /* The host relinquishes its Layer reference with the stream still
     * live.  The watcher's reference must hold the layer up. */
    destroyed_before =
        ovc_file_test_counter_load(&g_ovc_file_layer_test_destroy_count);
    dropped_before = g_ovc_file_watch_test_drop_count;
    handle.vtable->drop(handle.state);
    assert(ovc_file_test_counter_load(
               &g_ovc_file_layer_test_destroy_count) == destroyed_before);

    /* The stream still drives after the Layer handle is gone. */
    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovstorage_cancel_token_cancel(token);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Ended);

    ovc_file_test_watch_drop_once(stream);
    assert(g_ovc_file_watch_test_drop_count == dropped_before + 1);
    assert(ovc_file_test_counter_load(&g_ovc_file_layer_test_destroy_count) ==
           destroyed_before + 1);
    ovstorage_cancel_token_destroy(token);
    free(connection_id);
}

static void ovc_file_test_create_directory(
    OvStoragePlugin_LayerHandle *handle,
    const char *address)
{
    OvStoragePlugin_CreateDirectoryRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_BackendItemInfo *result;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->create_directory(handle->state,
                                     &request,
                                     NULL,
                                     ovc_file_test_complete,
                                     &completion);
    ovc_file_test_expect_success("create_directory", &completion);
    result = (OvStoragePlugin_BackendItemInfo *)completion.result;
    assert(result != NULL);
    assert(result->kind == OvStoragePlugin_ObjectKindV1_Directory);
    ovc_file_backend_item_info_clear(result);
    ovc_abi_free(result);
}

static void ovc_file_test_delete_directory(
    OvStoragePlugin_LayerHandle *handle,
    const char *address)
{
    OvStoragePlugin_DeleteDirectoryRequest request;
    ovc_file_test_completion completion;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->delete_directory(handle->state,
                                     &request,
                                     NULL,
                                     ovc_file_test_complete,
                                     &completion);
    ovc_file_test_expect_success("delete_directory", &completion);
    assert(completion.result == NULL);
}

/* Drive delete_directory and require it was refused with `expected`.  The
 * code is asserted, not merely the failure: a removal refused because the
 * directory holds something must not reach the caller as a retryable
 * condition, which would have it spin for the lifetime of whatever holds
 * the directory. */
static void ovc_file_test_delete_directory_refused(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    OvStoragePlugin_ErrorCode expected)
{
    OvStoragePlugin_DeleteDirectoryRequest request;
    ovc_file_test_completion completion;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->delete_directory(handle->state,
                                     &request,
                                     NULL,
                                     ovc_file_test_complete,
                                     &completion);
    ovc_file_test_completion_wait(&completion);
    if (completion.status != OvStoragePlugin_FFI_STATUS_ERR ||
        completion.error == NULL || completion.error->code != expected) {
        (void)fprintf(stderr,
                      "delete_directory of %s: status=%d code=%d "
                      "(expected refusal with code=%d)\n",
                      address,
                      (int)completion.status,
                      completion.error == NULL
                          ? -1
                          : (int)completion.error->code,
                      (int)expected);
        (void)fflush(stderr);
    }
    assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
    assert(completion.error != NULL);
    assert(completion.error->code == expected);
    assert(completion.result == NULL);
    ovc_file_error_destroy(completion.error);
}

static void ovc_file_test_materialize(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    const uint8_t *expected,
    size_t expected_length)
{
    OvStoragePlugin_ReadRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_LocalDelegate *result;
    char *path;
    ovc_file file;
    uint8_t *bytes;
    ovc_ssize_t count;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->materialize(handle->state,
                                &request,
                                NULL,
                                ovc_file_test_complete,
                                &completion);
    ovc_file_test_expect_success("materialize", &completion);
    result = (OvStoragePlugin_LocalDelegate *)completion.result;
    assert(result != NULL);
    path = ovc_file_string_from_slice(&result->path);
    assert(path != NULL);
    file = ovc_file_native_open_read(path);
    assert(file != OVC_INVALID_FILE);
    bytes = (uint8_t *)ovc_file_allocate(expected_length);
    count = ovc_pread(file, bytes, expected_length, 0);
    assert(count == (ovc_ssize_t)expected_length);
    assert(memcmp(bytes, expected, expected_length) == 0);
    assert(ovc_file_native_close(file) == 0);
    free(bytes);
    free(path);
    ovc_file_str_clear(&result->path);
    ovc_file_object_info_clear(&result->info);
    ovc_abi_free(result);
}

static void ovc_file_test_versions(OvStoragePlugin_LayerHandle *handle,
                                   const char *address)
{
    OvStoragePlugin_ListVersionsRequest list_request;
    OvStoragePlugin_ReadRequest latest_request;
    ovc_file_test_completion completion;
    OvStoragePlugin_VersionPage *page;
    OvStoragePlugin_ObjectInfo *latest;

    memset(&list_request, 0, sizeof(list_request));
    list_request.struct_size = sizeof(list_request);
    list_request.address = ovc_file_owned_string(address);
    list_request.options.struct_size = sizeof(list_request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->list_versions(handle->state,
                                  &list_request,
                                  NULL,
                                  ovc_file_test_complete,
                                  &completion);
    ovc_file_test_expect_success("versions", &completion);
    page = (OvStoragePlugin_VersionPage *)completion.result;
    assert(page != NULL);
    assert(page->items.len == 1);
    assert(!page->items.ptr[0].version.present);
    ovc_file_object_info_clear(&page->items.ptr[0]);
    ovc_abi_free(page->items.ptr);
    ovc_abi_free(page);

    memset(&latest_request, 0, sizeof(latest_request));
    latest_request.struct_size = sizeof(latest_request);
    latest_request.address = ovc_file_owned_string(address);
    latest_request.options.struct_size = sizeof(latest_request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->get_latest_version(handle->state,
                                       &latest_request,
                                       NULL,
                                       ovc_file_test_complete,
                                       &completion);
    ovc_file_test_expect_success("versions", &completion);
    latest = (OvStoragePlugin_ObjectInfo *)completion.result;
    assert(latest != NULL);
    assert(!latest->version.present);
    ovc_file_object_info_clear(latest);
    ovc_abi_free(latest);
}

static OvStoragePlugin_AccessDecision *ovc_file_test_check_access_call(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    OvStoragePlugin_AccessOps operations)
{
    OvStoragePlugin_CheckAccessRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_AccessDecision *decision;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.operations = operations;
    ovc_file_test_completion_init(&completion);
    handle->vtable->check_access(handle->state,
                                 &request,
                                 NULL,
                                 ovc_file_test_complete,
                                 &completion);
    ovc_file_test_expect_success("check_access_call", &completion);
    decision = (OvStoragePlugin_AccessDecision *)completion.result;
    assert(decision != NULL);
    return decision;
}

static void ovc_file_test_check_access(
    OvStoragePlugin_LayerHandle *handle,
    const char *address)
{
    OvStoragePlugin_AccessOps operations;
    OvStoragePlugin_AccessDecision *decision;

    memset(&operations, 0, sizeof(operations));
    operations.read = true;
    decision = ovc_file_test_check_access_call(handle, address, operations);
    assert(decision->allowed);
    assert(!decision->denied_ops.read);
    if (decision->reason.present) {
        ovc_file_str_clear(&decision->reason.value);
    }
    ovc_abi_free(decision);
}

static void ovc_file_test_stat_permissions(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    uint32_t expected_bits)
{
    OvStoragePlugin_StatRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ObjectInfo *result;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->stat(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("stat_permissions", &completion);
    result = (OvStoragePlugin_ObjectInfo *)completion.result;
    assert(result != NULL);
    assert(result->effective_permissions.present);
    assert(result->effective_permissions.value.bits == expected_bits);
    ovc_file_object_info_clear(result);
    ovc_abi_free(result);
}

#if !defined(_WIN32)
/* Reference access model (mod.rs check_access): the TARGET's readonly bit
 * denies write and update_metadata, delete is denied when target OR parent
 * is readonly, and effective_permissions reports READ for a readonly entry
 * and the full set otherwise. */
static void ovc_file_test_readonly_access(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    const char *path)
{
    OvStoragePlugin_AccessOps operations;
    OvStoragePlugin_AccessDecision *decision;

    memset(&operations, 0, sizeof(operations));
    operations.read = true;
    operations.write = true;
    operations.delete_ = true;
    operations.update_metadata = true;

    assert(chmod(path, (mode_t)0444) == 0);
    decision = ovc_file_test_check_access_call(handle, address, operations);
    assert(!decision->allowed);
    assert(!decision->denied_ops.read);
    assert(decision->denied_ops.write);
    assert(decision->denied_ops.delete_);
    assert(decision->denied_ops.update_metadata);
    assert(decision->reason.present);
    ovc_file_str_clear(&decision->reason.value);
    ovc_abi_free(decision);
    ovc_file_test_stat_permissions(handle,
                                   address,
                                   OVC_FILE_PERMISSION_READ);

    {
        OvStoragePlugin_WriteRequest request;
        ovc_file_test_completion completion;
        OvStoragePlugin_WriteResult *result;
        struct stat preserved;

        /* Overwriting a read-only destination preserves its mode, so the
         * write result must advertise the preserved READ-only permissions
         * (the backend re-stats the published destination, as the reference
         * does), not the staging temp's writable mode. */
        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.address = ovc_file_owned_string(address);
        request.body.tag = OvStoragePlugin_BodyTag_Bytes;
        request.body.bytes.ptr = (uint8_t *)ovc_file_abi_allocate(1);
        request.body.bytes.ptr[0] = 'r';
        request.body.bytes.len = 1;
        request.options.struct_size = sizeof(request.options);
        request.options.if_dest.tag =
            OvStoragePlugin_IfDestExistsTag_Overwrite;
        ovc_file_test_completion_init(&completion);
        handle->vtable->write(handle->state,
                              &request,
                              NULL,
                              ovc_file_test_complete,
                              &completion);
        ovc_file_test_expect_success("readonly_access", &completion);
        result = (OvStoragePlugin_WriteResult *)completion.result;
        assert(result != NULL);
        assert(result->info.effective_permissions.present);
        assert(result->info.effective_permissions.value.bits ==
               OVC_FILE_PERMISSION_READ);
        ovc_file_object_info_clear(&result->info);
        ovc_abi_free(result);
        assert(fstatat(AT_FDCWD, path, &preserved, 0) == 0);
        assert((preserved.st_mode & (mode_t)0777) == (mode_t)0444);
    }

    assert(chmod(path, (mode_t)0644) == 0);
    decision = ovc_file_test_check_access_call(handle, address, operations);
    assert(decision->allowed);
    assert(!decision->denied_ops.write);
    assert(!decision->denied_ops.delete_);
    assert(!decision->denied_ops.update_metadata);
    assert(!decision->reason.present);
    ovc_abi_free(decision);
    ovc_file_test_stat_permissions(handle,
                                   address,
                                   OVC_FILE_PERMISSION_ALL);
}
#endif

static void ovc_file_test_namespace_slots(
    OvStoragePlugin_LayerHandle *handle)
{
    assert(handle->vtable->delete_ != OVSTORAGE_UNSUPPORTED_VTABLE.delete_);
    assert(handle->vtable->copy != OVSTORAGE_UNSUPPORTED_VTABLE.copy);
    assert(handle->vtable->rename != OVSTORAGE_UNSUPPORTED_VTABLE.rename);
    assert(handle->vtable->materialize !=
           OVSTORAGE_UNSUPPORTED_VTABLE.materialize);
    assert(handle->vtable->watch_directory !=
           OVSTORAGE_UNSUPPORTED_VTABLE.watch_directory);
    assert(handle->vtable->write_stream ==
           OVSTORAGE_UNSUPPORTED_VTABLE.write_stream);
}

int main(void)
{
    OvStoragePlugin_CreateBackendRequest create;
    OvStoragePlugin_LayerHandle handle;
    OvStoragePlugin_Error *factory_error;
    OvStoragePlugin_FfiStatus factory_status;
#if defined(_WIN32)
    wchar_t directory_wide[MAX_PATH];
#else
    char directory_storage[OVC_TEMP_DIR_PATH_MAX];
#endif
    char *directory;
    char *root_url;
    char *first_address;
    char *second_address;
    char *copied_address;
    char *renamed_address;
    char *parent_directory_address;
    char *child_directory_address;
    char *first_path;
    char *connection_id;
    OvStoragePlugin_Error *path_error;
    static const uint8_t first_payload[] = "pure C file backend";
    static const uint8_t second_payload[] = "pagination";

    assert(ovc_file_is_internal_entry(".object.123.45.6.tmp"));
    assert(ovc_file_is_internal_entry(
        ".ovstorage-stage.123.45.6.tmp"));
    assert(!ovc_file_is_internal_entry(".ordinary.a.b.c.tmp"));

    /* The delete scan's skip set is the sidecar dir alone.  A staging temp
     * is internal to enumeration but counted by the kernel, so treating it
     * as absent would make the scan disagree with the rmdir. */
    assert(ovc_file_is_cleared_by_directory_removal(".ovstorage-meta"));
    assert(!ovc_file_is_cleared_by_directory_removal(
        ".ovstorage-stage.123.45.6.tmp"));
    assert(!ovc_file_is_cleared_by_directory_removal(".object.123.45.6.tmp"));

    /* A root spelled with its trailing separator covers the node it names.
     * Comparing against the spelled root refused the very path the connection
     * publishes, which is the routing failure in the C host, and it made the
     * two hosts disagree about which addresses route.  A sibling whose name
     * merely starts with the root's is still outside it. */
    assert(ovc_file_path_has_prefix("/data/root", "/data/root/"));
    assert(ovc_file_path_has_prefix("/data/root/", "/data/root/"));
    assert(ovc_file_path_has_prefix("/data/root/a.txt", "/data/root/"));
    assert(ovc_file_path_has_prefix("/data/root", "/data/root"));
    assert(ovc_file_path_has_prefix("/data/root/a.txt", "/data/root"));
    assert(!ovc_file_path_has_prefix("/data/rootx", "/data/root/"));
    assert(!ovc_file_path_has_prefix("/data/rootx", "/data/root"));
    assert(!ovc_file_path_has_prefix("/data/roo", "/data/root/"));
    assert(ovc_file_path_has_prefix("/anything", "/"));
    assert(ovc_file_canonical_path_has_prefix("/data/root", "/data/root/"));
    assert(ovc_file_canonical_path_has_prefix("/data/root/a", "/data/root/"));
    assert(!ovc_file_canonical_path_has_prefix("/data/rootx", "/data/root/"));
    assert(ovc_file_canonical_path_has_prefix("/anything", "/"));
    assert(ovc_runtime_ensure(2) == 0);
#if defined(_WIN32)
    {
        wchar_t temp_root[MAX_PATH];
        DWORD temp_length;

        temp_length = GetTempPathW(
            (DWORD)(sizeof(temp_root) / sizeof(temp_root[0])), temp_root);
        assert(temp_length != 0 &&
               temp_length < sizeof(temp_root) / sizeof(temp_root[0]));
        assert(GetTempFileNameW(temp_root,
                                L"ovc",
                                0,
                                directory_wide) != 0);
        assert(DeleteFileW(directory_wide));
        assert(CreateDirectoryW(directory_wide, NULL));
        directory = ovc_file_wide_name_to_utf8(directory_wide);
        assert(directory != NULL);
    }
#else
    assert(ovc_temp_dir_create("ovstorage-c-file",
                               directory_storage,
                               sizeof(directory_storage)) == 0);
    directory = directory_storage;
#endif
    root_url = ovc_file_path_to_url(directory, true);
    create = ovc_file_test_create_backend_request();
    memset(&handle, 0, sizeof(handle));
    factory_error = NULL;
    factory_status = ovc_file_create_backend(NULL,
                                             &create,
                                             &handle,
                                             &factory_error);
    assert(factory_status == OvStoragePlugin_FFI_STATUS_OK);
    assert(factory_error == NULL);
    assert(handle.state != NULL);
    assert(handle.vtable != NULL);

    connection_id = ovc_file_test_connection_id(&handle, root_url);
    ovc_file_test_introspection(&handle, root_url);
    ovc_file_test_empty_list(&handle, root_url);
    /* This one runs first among the watch tests: it owns the Layer handle
     * it watches, so it observes a missing watcher-side layer reference as
     * a failed assertion rather than as the use-after-free the shared
     * handle below would suffer from the same defect. */
    ovc_file_test_watch_outlives_layer(root_url);
    ovc_file_test_watch_created(&handle, root_url);
    ovc_file_test_watch_cancel(&handle, root_url);
    assert(g_ovc_file_watch_test_drop_count == 3);
    first_address = ovc_file_join_address(root_url,
                                          "roundtrip.txt",
                                          false);
    second_address = ovc_file_join_address(root_url,
                                           "second.txt",
                                           false);
    path_error = NULL;
    first_path = ovc_file_url_to_path(first_address, &path_error);
    assert(path_error == NULL);
    ovc_file_test_write(&handle,
                        first_address,
                        first_payload,
                        sizeof(first_payload) - 1);
#if !defined(_WIN32)
    {
        struct stat permissions;

        assert(chmod(first_path, (mode_t)0600) == 0);
        ovc_file_test_write(&handle,
                            first_address,
                            first_payload,
                            sizeof(first_payload) - 1);
        assert(fstatat(AT_FDCWD, first_path, &permissions, 0) == 0);
        assert((permissions.st_mode & (mode_t)0777) == (mode_t)0600);
    }
#endif
    ovc_file_test_write(&handle,
                        second_address,
                        second_payload,
                        sizeof(second_payload) - 1);
    ovc_file_test_stat(&handle,
                       first_address,
                       sizeof(first_payload) - 1);
    ovc_file_test_read(&handle,
                       first_address,
                       first_payload,
                       sizeof(first_payload) - 1);
    ovc_file_test_list(&handle, root_url);
    ovc_file_test_namespace_slots(&handle);

    ovc_file_test_update_metadata(&handle, first_address);
    ovc_file_test_metadata_sidecar_layout(directory, "roundtrip.txt");

    {
        char long_name[131];
        char *long_address;

        /* hex(name).meta doubles the basename, so a >=126-byte object name
         * yields a sidecar name past NAME_MAX.  The root already holds
         * `.ovstorage-meta` (roundtrip.txt has metadata just above), so the
         * sidecar probes see ENAMETOOLONG instead of ENOENT; write, stat,
         * and delete of a long-named object with no metadata must still
         * succeed, matching the reference's metadata_exists treating the
         * impossible sidecar as absent. */
        memset(long_name, 'n', sizeof(long_name) - 1);
        long_name[sizeof(long_name) - 1] = '\0';
        long_address = ovc_file_join_address(root_url, long_name, false);
        ovc_file_test_write(&handle,
                            long_address,
                            first_payload,
                            sizeof(first_payload) - 1);
        ovc_file_test_stat(&handle,
                           long_address,
                           sizeof(first_payload) - 1);
        {
            OvStoragePlugin_UpdateMetadataRequest request;
            ovc_file_test_completion completion;

            /* The documented NAME_MAX caveat still holds: only the
             * cannot-exist probes and cleanups are benign — writing
             * NON-empty metadata to the over-long sidecar name must fail
             * loudly rather than silently diverge on disk. */
            memset(&request, 0, sizeof(request));
            request.struct_size = sizeof(request);
            request.address = ovc_file_owned_string(long_address);
            request.options.struct_size = sizeof(request.options);
            request.options.user_metadata_set.ptr =
                (OvStoragePlugin_KeyValuePair *)ovc_file_abi_callocate(
                    1, sizeof(*request.options.user_metadata_set.ptr));
            request.options.user_metadata_set.len = 1;
            request.options.user_metadata_set.ptr[0].key =
                ovc_file_owned_string("purpose");
            request.options.user_metadata_set.ptr[0].value =
                ovc_file_owned_string("too-long");
            request.options.user_metadata_remove.ptr =
                (OvStoragePlugin_Str *)ovc_file_abi_allocate(
                    sizeof(*request.options.user_metadata_remove.ptr));
            request.options.user_metadata_remove.len = 0;
            ovc_file_test_completion_init(&completion);
            handle.vtable->update_metadata(handle.state,
                                           &request,
                                           NULL,
                                           ovc_file_test_complete,
                                           &completion);
            ovc_file_test_completion_wait(&completion);
            assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
            assert(completion.error != NULL);
            ovc_file_error_destroy(completion.error);
        }
        ovc_file_test_delete(&handle, long_address);
        free(long_address);
    }

    copied_address = ovc_file_join_address(root_url,
                                           "copied.txt",
                                           false);
    renamed_address = ovc_file_join_address(root_url,
                                            "renamed.txt",
                                            false);
    ovc_file_test_copy(&handle,
                       first_address,
                       copied_address,
                       sizeof(first_payload) - 1);
    ovc_file_test_read(&handle,
                       copied_address,
                       first_payload,
                       sizeof(first_payload) - 1);
    ovc_file_test_rename(&handle, copied_address, renamed_address);
    ovc_file_test_read(&handle,
                       renamed_address,
                       first_payload,
                       sizeof(first_payload) - 1);
    ovc_file_test_materialize(&handle,
                              renamed_address,
                              first_payload,
                              sizeof(first_payload) - 1);
    ovc_file_test_versions(&handle, renamed_address);
    ovc_file_test_check_access(&handle, renamed_address);
#if !defined(_WIN32)
    {
        char *renamed_path;

        path_error = NULL;
        renamed_path = ovc_file_url_to_path(renamed_address, &path_error);
        assert(path_error == NULL);
        ovc_file_test_readonly_access(&handle,
                                      renamed_address,
                                      renamed_path);
        free(renamed_path);
    }
#endif

    parent_directory_address = ovc_file_join_address(root_url,
                                                      "parent",
                                                      true);
    child_directory_address = ovc_file_join_address(
        parent_directory_address, "child", true);
    ovc_file_test_create_directory(&handle, child_directory_address);
    ovc_file_test_delete_directory(&handle, child_directory_address);
    ovc_file_test_delete_directory(&handle, parent_directory_address);

    {
        char *orphan_directory_address;
        char *orphan_directory_path;
        char *orphan_metadata_directory;
        char *orphan_sidecar;
        char *nested_directory;
        char *nested_file;
        ovc_file orphan_file;
        ovc_file nested_handle;

        /* An orphaned sidecar (object removed out-of-band) must not make a
         * visually-empty directory undeletable: delete_directory clears the
         * backend-owned .ovstorage-meta contents like the reference's
         * remove_dir_all. */
        orphan_directory_address = ovc_file_join_address(root_url,
                                                         "orphan",
                                                         true);
        ovc_file_test_create_directory(&handle, orphan_directory_address);
        path_error = NULL;
        orphan_directory_path = ovc_file_url_to_path(
            orphan_directory_address, &path_error);
        assert(path_error == NULL);
        orphan_metadata_directory = ovc_path_join(
            orphan_directory_path, OVC_FILE_METADATA_DIRECTORY);
        assert(orphan_metadata_directory != NULL);
        assert(ovc_file_native_mkdir(orphan_metadata_directory) == 0);
        /* hex("orphan.txt") + ".meta": a sidecar whose object is gone. */
        orphan_sidecar = ovc_path_join(orphan_metadata_directory,
                                       "6f727068616e2e747874.meta");
        assert(orphan_sidecar != NULL);
        orphan_file = ovc_file_native_create_new(orphan_sidecar);
        assert(orphan_file != OVC_INVALID_FILE);
        assert(ovc_file_native_close(orphan_file) == 0);
        /* A foreign SUBDIRECTORY (with a file inside) planted in
         * .ovstorage-meta fails unlink(2) forever; the sweep must recurse
         * like remove_dir_all instead of leaving the visually-empty
         * directory permanently undeletable. */
        nested_directory = ovc_path_join(orphan_metadata_directory,
                                         "nested");
        assert(nested_directory != NULL);
        assert(ovc_file_native_mkdir(nested_directory) == 0);
        nested_file = ovc_path_join(nested_directory, "leftover.meta");
        assert(nested_file != NULL);
        nested_handle = ovc_file_native_create_new(nested_file);
        assert(nested_handle != OVC_INVALID_FILE);
        assert(ovc_file_native_close(nested_handle) == 0);
        ovc_file_test_delete_directory(&handle, orphan_directory_address);
        free(nested_file);
        free(nested_directory);
        free(orphan_sidecar);
        free(orphan_metadata_directory);
        free(orphan_directory_path);
        free(orphan_directory_address);
    }

    {
        char *staging_directory_address;
        char *staging_directory_path;
        char *staging_metadata_directory;
        char *staging_child;
        char *staging_temp;
        ovc_file staging_handle;
        ovc_file_stat staging_info;

        /* A directory holding an atomic-write staging temp is not empty:
         * the kernel counts that entry, so the rmdir cannot succeed.  The
         * refusal must be reported as DirectoryNotEmpty, and must be
         * reached before the sidecar dir is touched, since no removal
         * happens.
         *
         * The temp is planted directly rather than driven from a parked
         * concurrent write: what this case pins is the scan predicate's
         * verdict on a name production generates, and ovc_file_temp_sibling
         * is the generator itself, so the name on disk is the real one. */
        staging_directory_address = ovc_file_join_address(root_url,
                                                          "staging",
                                                          true);
        ovc_file_test_create_directory(&handle, staging_directory_address);
        path_error = NULL;
        staging_directory_path = ovc_file_url_to_path(
            staging_directory_address, &path_error);
        assert(path_error == NULL);
        staging_metadata_directory = ovc_path_join(
            staging_directory_path, OVC_FILE_METADATA_DIRECTORY);
        assert(staging_metadata_directory != NULL);
        assert(ovc_file_native_mkdir(staging_metadata_directory) == 0);
        staging_child = ovc_path_join(staging_directory_path, "child.bin");
        assert(staging_child != NULL);
        staging_temp = ovc_file_temp_sibling(staging_child, 0);
        assert(staging_temp != NULL);
        staging_handle = ovc_file_native_create_new(staging_temp);
        assert(staging_handle != OVC_INVALID_FILE);
        assert(ovc_file_native_close(staging_handle) == 0);

        ovc_file_test_delete_directory_refused(
            &handle,
            staging_directory_address,
            OvStoragePlugin_ErrorCode_DirectoryNotEmpty);

        /* The refused removal must leave the sidecar dir standing: a scan
         * that mistook the temp for absent would have swept it already. */
        assert(ovc_file_native_stat_path(staging_metadata_directory,
                                         &staging_info) == 0);
        assert(staging_info.is_directory);

        /* Once the write commits its temp away, the directory deletes. */
        assert(ovc_file_native_unlink(staging_temp) == 0);
        ovc_file_test_delete_directory(&handle, staging_directory_address);
        free(staging_temp);
        free(staging_child);
        free(staging_metadata_directory);
        free(staging_directory_path);
        free(staging_directory_address);
    }

#if !defined(_WIN32)
    {
        char *linked_directory_address;
        char *linked_directory_path;
        char *linked_metadata_directory;
        char *outside_directory;
        char *outside_canary;
        ovc_file canary_handle;
        struct stat canary_info;

        /* A symlinked `.ovstorage-meta` ROOT must be removed as the link
         * itself, never opened: Rust's remove_dir_all never follows a link.
         * A sweep that opendir'd the symlinked root would recursively
         * DELETE the link target's tree and report success.  Plant an
         * outside directory holding a canary, point a symlinked sidecar root
         * at it, and assert delete_directory succeeds while the canary and
         * its directory survive untouched. */
        linked_directory_address = ovc_file_join_address(root_url,
                                                         "linked-meta",
                                                         true);
        ovc_file_test_create_directory(&handle, linked_directory_address);
        path_error = NULL;
        linked_directory_path = ovc_file_url_to_path(linked_directory_address,
                                                     &path_error);
        assert(path_error == NULL);
        linked_metadata_directory = ovc_path_join(
            linked_directory_path, OVC_FILE_METADATA_DIRECTORY);
        assert(linked_metadata_directory != NULL);
        outside_directory = ovc_path_join(directory, "sweep-outside");
        assert(outside_directory != NULL);
        assert(ovc_file_native_mkdir(outside_directory) == 0);
        outside_canary = ovc_path_join(outside_directory, "canary.txt");
        assert(outside_canary != NULL);
        canary_handle = ovc_file_native_create_new(outside_canary);
        assert(canary_handle != OVC_INVALID_FILE);
        assert(ovc_file_native_close(canary_handle) == 0);
        assert(symlink(outside_directory, linked_metadata_directory) == 0);

        ovc_file_test_delete_directory(&handle, linked_directory_address);

        /* The link target and its canary must be untouched, and the
         * symlinked sidecar root itself removed. */
        assert(stat(outside_canary, &canary_info) == 0);
        assert(lstat(linked_metadata_directory, &canary_info) != 0);
        assert(errno == ENOENT);
        assert(unlink(outside_canary) == 0);
        assert(rmdir(outside_directory) == 0);
        free(outside_canary);
        free(outside_directory);
        free(linked_metadata_directory);
        free(linked_directory_path);
        free(linked_directory_address);
    }
#endif

#if !defined(_WIN32)
    {
        char *dangling_address;
        char *dangling_path;
        struct stat link_info;

        dangling_address = ovc_file_join_address(root_url,
                                                  "dangling-link",
                                                  false);
        path_error = NULL;
        dangling_path = ovc_file_url_to_path(dangling_address, &path_error);
        assert(path_error == NULL);
        assert(symlink("missing-target", dangling_path) == 0);
        ovc_file_test_delete(&handle, dangling_address);
        errno = 0;
        assert(lstat(dangling_path, &link_info) != 0);
        assert(errno == ENOENT);
        free(dangling_path);
        free(dangling_address);
    }
#endif

    {
        char *move_source_address;
        char *move_destination_address;
        char *move_source_path;
        char *move_destination_path;
        ovc_file_task move_task;
        ovc_file_stat moved_info;
        ovc_file_stat move_probe;
        OvStoragePlugin_Error *move_error;

        /* The EXDEV rename fallback drives ovc_file_copy_regular_staged with
         * move_source set so the source is retired inside the same publish
         * critical section as the identity re-check.  EXDEV itself needs two
         * filesystems, so exercise the helper directly: the destination must
         * carry the bytes and the source must be gone on success. */
        move_source_address = ovc_file_join_address(root_url,
                                                    "move-source.txt",
                                                    false);
        move_destination_address = ovc_file_join_address(
            root_url, "move-destination.txt", false);
        ovc_file_test_write(&handle,
                            move_source_address,
                            first_payload,
                            sizeof(first_payload) - 1);
        path_error = NULL;
        move_source_path = ovc_file_url_to_path(move_source_address,
                                                &path_error);
        assert(path_error == NULL);
        move_destination_path = ovc_file_url_to_path(
            move_destination_address, &path_error);
        assert(path_error == NULL);
        memset(&move_task, 0, sizeof(move_task));
        move_task.kind = OVC_FILE_TASK_RENAME;
        move_task.layer = (ovc_file_layer *)handle.state;
        move_error = NULL;
        assert(ovc_file_copy_regular_staged(
                   &move_task,
                   move_source_path,
                   move_destination_path,
                   NULL,
                   OvStoragePlugin_IfDestExistsTag_Overwrite,
                   NULL,
                   NULL,
                   true,
                   &moved_info,
                   &move_error) == 0);
        assert(move_error == NULL);
        assert(moved_info.size == sizeof(first_payload) - 1);
        errno = 0;
        assert(ovc_file_native_stat_path(move_source_path,
                                         &move_probe) != 0);
        assert(errno == ENOENT);
        assert(ovc_file_native_stat_path(move_destination_path,
                                         &move_probe) == 0);
        assert(move_probe.size == sizeof(first_payload) - 1);
        ovc_file_test_delete(&handle, move_destination_address);
        free(move_destination_path);
        free(move_source_path);
        free(move_destination_address);
        free(move_source_address);
    }

    ovc_file_test_delete(&handle, renamed_address);
    ovc_file_test_delete(&handle, renamed_address);
    ovc_file_test_delete(&handle, first_address);
    ovc_file_test_delete(&handle, second_address);

#if !defined(_WIN32)
    {
        char *out_link_address;
        char *out_link_path;

        /* An in-root symlink resolving outside the configured root is
         * SKIPPED by list rather than failing the enumeration. */
        out_link_address = ovc_file_join_address(root_url,
                                                 "out-link",
                                                 false);
        path_error = NULL;
        out_link_path = ovc_file_url_to_path(out_link_address, &path_error);
        assert(path_error == NULL);
        assert(symlink("/", out_link_path) == 0);
        ovc_file_test_empty_list(&handle, root_url);
        assert(unlink(out_link_path) == 0);
        free(out_link_path);
        free(out_link_address);
    }
#endif

    ovc_file_test_connections(&handle, connection_id);
    {
        OvStoragePlugin_ListAddressRootsRequest request;
        ovc_file_test_completion completion;
        OvStoragePlugin_ListAddressRootsResult *result;

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        ovc_file_test_completion_init(&completion);
        handle.vtable->list_address_roots(handle.state,
                                          &request,
                                          NULL,
                                          ovc_file_test_complete,
                                          &completion);
        ovc_file_test_expect_success("namespace_slots", &completion);
        result =
            (OvStoragePlugin_ListAddressRootsResult *)completion.result;
        assert(result != NULL);
        assert(result->snapshot.roots.len == 0);
        ovc_abi_free(result->snapshot.roots.ptr);
        ovc_abi_free(result);
    }
    handle.vtable->drop(handle.state);

#if defined(_WIN32)
    assert(RemoveDirectoryW(directory_wide));
#else
    assert(rmdir(directory) == 0);
#endif
    free(connection_id);
    free(first_path);
    free(child_directory_address);
    free(parent_directory_address);
    free(renamed_address);
    free(copied_address);
    free(first_address);
    free(second_address);
    free(root_url);
#if defined(_WIN32)
    free(directory);
#endif
    return 0;
}

#endif /* OVC_FILE_BACKEND_TEST_MAIN */
