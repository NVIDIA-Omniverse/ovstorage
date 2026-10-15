/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Built-in pure-C file Layer.
 */

#if defined(__APPLE__)
/* flock is a BSD interface that _POSIX_C_SOURCE alone hides on Darwin. */
#define _DARWIN_C_SOURCE 1
#endif

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
#if defined(OVC_FILE_BACKEND_TEST_MAIN) &&                              \
    !defined(SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#else
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define OVC_FILE_KIND "file"
#define OVC_FILE_DISPLAY_NAME "Local files"
#define OVC_FILE_DESCRIPTION "Read and write local file:// URLs"
#define OVC_FILE_DEFAULT_CONNECTION_NAME "File"
#define OVC_FILE_TEMP_ATTEMPTS 16U
/* Access modes for ovc_file_native_open_probe, tried in this order. */
#define OVC_FILE_PROBE_READ_WRITE 0
#define OVC_FILE_PROBE_READ 1
#define OVC_FILE_PROBE_WRITE 2
#define OVC_FILE_IO_CHUNK_SIZE (1024U * 1024U)
#define OVC_FILE_MIN_WATCH_POLL_MS UINT64_C(10)
#define OVC_FILE_WATCH_WAIT_CHUNK_NS UINT64_C(86400000000000)

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
            /* The request carried a non-empty user_metadata map, which this
             * backend refuses once the address has resolved. */
            bool refuse_user_metadata;
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

/* Checked slice copy for request-proportional copies: host-supplied input
 * must surface ResourceExhausted instead of aborting the process when
 * memory runs out. */
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

/* Whether a failed stat's errno means "there is nothing (examinable) here"
 * rather than a real failure -- shared by the directory-listing skip-vs-fail
 * decision and the dangling-symlink no-follow fallback below. A directory
 * listing entry answering one of these should be skipped rather than
 * failing the whole listing: the entry itself is gone (ENOENT, a dangling
 * target or a delete-race with the directory read), was never examinable as
 * a path (ENOTDIR, a race with the parent being replaced), or cycles back on
 * itself (ELOOP). A followed stat answering one of these is the case the
 * no-follow fallback exists for: the link is there but its target is not.
 * Every other errno -- EACCES, EIO, ... -- denotes a real failure the
 * caller needs to see, not an absent target, so it is never skipped or
 * masked by a successful fallback. */
static bool ovc_file_stat_error_means_absent(int native_error)
{
    switch (native_error) {
    case ENOENT:
    case ENOTDIR:
#ifdef ELOOP
    case ELOOP:
#endif
        return true;
    default:
        return false;
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
    if (info->versioned_address.present) {
        ovc_file_str_clear(&info->versioned_address.value);
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
    if (connection->owning_target.present) {
        ovc_file_str_clear(&connection->owning_target.value);
    }
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
    /* This backend stores no user metadata: a write carrying a non-empty map
     * is refused with Unsupported and update_metadata is Unsupported, so no
     * native patch exists to advertise. */
    capabilities.supports_native_metadata_patch = false;
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
    /* No user metadata is stored, so nothing can change out from under a
     * watcher except the object bytes themselves. */
    capabilities.watch_directory_kinds.metadata_changed = false;
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
    /* This backend stores no user metadata: a write carrying a non-empty
       map is refused and stat reports an empty map, so a host composes no
       attribution layer over this branch. */
    out->supports_user_metadata = false;
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
    const char *owning_name,
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
    /* The layer INSTANCE name a connection op routes by — the same name
     * `ovc_file_layer_owned_targets` reports and the root encoder above
     * stamps — so a caller holding this row can build the `ConnectionKey`
     * that reaches it without deriving the owner from an address. */
    out->owning_target.present = true;
    out->owning_target.value = ovc_file_owned_string(owning_name);
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

/* `out_win32_error` is set to the raw `GetLastError()` value on failure and
 * left untouched on success; callers that only need the translated `errno`
 * (i.e. everyone but the dangling-link fallback below) pass NULL. */
static int ovc_file_native_stat_path_ex(const char *path,
                                        ovc_file_stat *out,
                                        DWORD *out_win32_error)
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
        if (out_win32_error != NULL) {
            *out_win32_error = error;
        }
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

static int ovc_file_native_stat_path(const char *path, ovc_file_stat *out)
{
    return ovc_file_native_stat_path_ex(path, out, NULL);
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

/* Windows counterpart of the POSIX `ovc_file_native_stat_path_or_link`
 * below: fall back to the reparse point's own attributes, read with an
 * exact no-follow open (`FILE_FLAG_OPEN_REPARSE_POINT`), when the normal
 * path lookup above fails for a reason that means the target is missing,
 * so a dangling link is reported rather than answered as absent.
 *
 * `CreateFileW` performs an exact lookup and never treats `*` or `?` in
 * `path` as wildcards, unlike `FindFirstFileW`; the caller-derived path
 * must never be handed to a directory-enumeration API, since a wildcard
 * match could silently report a different, unrelated filesystem entry.
 *
 * The fallback runs for `ovc_file_stat_error_means_absent` first failures,
 * and also for a raw `ERROR_INVALID_NAME` from the initial lookup: `*` or
 * `?` in `path` makes `GetFileAttributesExW` reject it outright (it never
 * treats those as wildcards), and the errno translation for that Win32 code
 * is shared with the unrelated over-long-name case (see
 * `ovc_win32_set_errno`), so it is checked here as the untranslated Win32
 * code rather than by widening the shared errno classifier. A path whose
 * first lookup failed for any other reason (an access error, a filesystem
 * error, ...) must keep reporting that failure, not a successful stat of
 * the link itself -- masking `PermissionDenied` or `Transient` as a clean
 * answer would be worse than the dangling-link gap this fallback exists to
 * close.
 *
 * `CreateFileW` rejects the same syntactically invalid names that
 * `GetFileAttributesExW` does, so an `ERROR_INVALID_NAME` first failure
 * always fails the fallback open too; that failure is reported as
 * `ENOENT` (the name is not just missing an exact-match target, it cannot
 * exist at all), rather than surfacing the unrelated errno the shared
 * translation happens to produce for `ERROR_INVALID_NAME`. */
static int ovc_file_native_stat_path_or_link(const char *path,
                                             ovc_file_stat *out)
{
    wchar_t *wide;
    HANDLE handle;
    BY_HANDLE_FILE_INFORMATION info;
    int first_errno;
    DWORD first_win32_error;
    bool invalid_name;

    first_win32_error = 0;
    if (ovc_file_native_stat_path_ex(path, out, &first_win32_error) == 0) {
        return 0;
    }
    first_errno = errno;
    invalid_name = (first_win32_error == ERROR_INVALID_NAME);
    if (!invalid_name && !ovc_file_stat_error_means_absent(first_errno)) {
        errno = first_errno;
        return -1;
    }
    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        errno = first_errno;
        return -1;
    }
    handle = CreateFileW(wide,
                         FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE |
                             FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT |
                             FILE_FLAG_BACKUP_SEMANTICS,
                         NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = invalid_name ? ENOENT : first_errno;
        return -1;
    }
    if (!GetFileInformationByHandle(handle, &info)) {
        CloseHandle(handle);
        errno = invalid_name ? ENOENT : first_errno;
        return -1;
    }
    CloseHandle(handle);
    ovc_file_win32_info_to_stat(info.dwFileAttributes,
                                info.nFileSizeHigh,
                                info.nFileSizeLow,
                                info.ftLastWriteTime,
                                out);
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
    /* FILE_SHARE_DELETE lets MoveFileExW publish the staging file while
     * the writer's handle, and the lock it carries, is still open. */
    handle = CreateFileW(wide,
                         GENERIC_WRITE | GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE |
                             FILE_SHARE_DELETE,
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

/* Exclusive staging lock without waiting: 0 when this handle holds it, -1
 * with errno EWOULDBLOCK when another handle does, -1 with the mapped errno
 * otherwise.  Win32 locks are mandatory, so the lock covers one byte far
 * past any possible end of file (0xFFFFFFFFFFFFFFFE), a range no read or
 * write of the object's bytes can overlap: a reader that finds the published
 * object before the writer's handle closes reads it normally.  The Rust host
 * locks the same byte.  Contention on an overlapped handle is reported as
 * ERROR_IO_PENDING; both spellings are intercepted before ovc_win32_set_errno,
 * which would read them as EACCES.  LOCKFILE_FAIL_IMMEDIATELY never queues a
 * request, so a stack OVERLAPPED needs no event or GetOverlappedResult. */
static int ovc_file_native_lock_exclusive_nonblocking(ovc_file file)
{
    OVERLAPPED overlapped;
    DWORD error;

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = 0xFFFFFFFEu;
    overlapped.OffsetHigh = 0xFFFFFFFFu;
    if (LockFileEx(file,
                   LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                   0,
                   1,
                   0,
                   &overlapped)) {
        return 0;
    }
    error = GetLastError();
    if (error == ERROR_LOCK_VIOLATION || error == ERROR_IO_PENDING) {
        errno = EWOULDBLOCK;
        return -1;
    }
    ovc_win32_set_errno(error);
    return -1;
}

/* Open a staging-temp probe handle without following a reparse point.  A
 * link or a directory wearing the name is refused with ELOOP rather than
 * opened, so the probe never locks or removes through it.  `access` is
 * accepted for symmetry with the POSIX arm; GENERIC_READ suffices for
 * LockFileEx and opens a read-only-attribute file. */
static ovc_file ovc_file_native_open_probe(const char *path, int access)
{
    wchar_t *wide;
    HANDLE handle;
    BY_HANDLE_FILE_INFORMATION info;

    (void)access;
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
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                             FILE_FLAG_BACKUP_SEMANTICS,
                         NULL);
    free(wide);
    if (handle == INVALID_HANDLE_VALUE) {
        ovc_win32_set_errno(GetLastError());
        return OVC_INVALID_FILE;
    }
    if (!GetFileInformationByHandle(handle, &info)) {
        DWORD error;

        error = GetLastError();
        CloseHandle(handle);
        ovc_win32_set_errno(error);
        return OVC_INVALID_FILE;
    }
    if ((info.dwFileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        CloseHandle(handle);
#ifdef ELOOP
        errno = ELOOP;
#else
        errno = EINVAL;
#endif
        return OVC_INVALID_FILE;
    }
    return handle;
}

/* Classify a staging-temp candidate without following a reparse point:
 * whether it exists and whether it is a plain file.  A missing path reports
 * out_exists = false, not an error. */
static int ovc_file_native_probe_kind(const char *path,
                                      bool *out_exists,
                                      bool *out_is_regular)
{
    wchar_t *wide;
    DWORD attributes;

    *out_exists = false;
    *out_is_regular = false;
    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    attributes = GetFileAttributesW(wide);
    free(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD error;

        error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return 0;
        }
        ovc_win32_set_errno(error);
        return -1;
    }
    *out_exists = true;
    *out_is_regular =
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
                       FILE_ATTRIBUTE_DEVICE)) == 0;
    return 0;
}

/* A copy staged from a read-only source carries FILE_ATTRIBUTE_READONLY,
 * which DeleteFileW refuses; clear it by path, as the unlink is. */
static int ovc_file_native_clear_readonly(const char *path)
{
    wchar_t *wide;
    DWORD attributes;

    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    attributes = GetFileAttributesW(wide);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    if ((attributes & FILE_ATTRIBUTE_READONLY) != 0 &&
        !SetFileAttributesW(wide, attributes & ~(DWORD)FILE_ATTRIBUTE_READONLY)) {
        DWORD error;

        error = GetLastError();
        free(wide);
        ovc_win32_set_errno(error);
        return -1;
    }
    free(wide);
    return 0;
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

/* `ovc_file_native_stat_path` follows a symlink, which is right for every
 * caller that needs the real object a path resolves to (read, write, copy,
 * list, ...) -- but wrong for the one that reports what is *at* an address:
 * a dangling link (a real, present object whose target does not exist) has
 * no "real object" for the follow to land on, and reporting that as
 * NotFound makes the link itself invisible. 2.x's own `native::stat` fell
 * back to `lstat` for exactly this case, reporting the link. The top-level
 * `stat` operation opts into this (see the `report_dangling_link` parameter
 * on `ovc_file_stat_result`, its sole caller), and so does
 * `ovc_file_check_destination_precondition`: a dangling link occupies its
 * directory entry as far as `no_overwrite`/`if_match_etag` are concerned,
 * so treating it as absent would let a Fail precondition clobber it and let
 * a MatchEtag precondition compare against a target that was never there.
 * Every other stat-shaped call in this file (read/copy-source/rename-source/
 * list/watch/get_latest_version/list_versions/...) keeps the plain
 * follow-only behavior above, since a dangling link is exactly as absent
 * for those as a link that was never there -- and, for the version-shaped
 * calls, pinning a caller's etag to the link's own size/mtime would
 * describe a version a follow-only read can never reproduce.
 *
 * The fallback only ever runs for `ovc_file_stat_error_means_absent` first
 * failures, for the same reason as the Windows counterpart above: an
 * accessible symlink whose target lookup failed for an unrelated reason
 * (EACCES on a target-path component, EIO, ...) must keep reporting that
 * failure, not the link's own successful metadata. */
static int ovc_file_native_stat_path_or_link(const char *path,
                                             ovc_file_stat *out)
{
    struct stat native;
    int first_errno;

    if (ovc_file_native_stat_path(path, out) == 0) {
        return 0;
    }
    first_errno = errno;
    if (!ovc_file_stat_error_means_absent(first_errno)) {
        errno = first_errno;
        return -1;
    }
    if (fstatat(AT_FDCWD, path, &native, AT_SYMLINK_NOFOLLOW) != 0) {
        errno = first_errno;
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
 * delete_directory uses this to refuse a link at the addressed path without
 * following it.
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

/* Exclusive advisory lock without waiting: 0 when this descriptor holds it,
 * -1 with errno EWOULDBLOCK when another does.  flock, not fcntl: a flock is
 * owned by the open file description, so a probe from another thread of this
 * process is excluded like one from another process, and closing the probe
 * releases only the probe's own lock. */
static int ovc_file_native_lock_exclusive_nonblocking(ovc_file file)
{
    int result;

    do {
        result = flock(file, LOCK_EX | LOCK_NB);
    } while (result != 0 && errno == EINTR);
    return result;
}

/* Open a staging-temp probe descriptor without following a final link
 * (ELOOP for a symlink) and without blocking (a fifo with no writer would
 * otherwise hold the open).  `access` is one of the OVC_FILE_PROBE_* modes:
 * read-write is asked first because an NFS flock emulation refuses an
 * exclusive lock on a descriptor not open for writing, and a copied mode
 * that denies one side falls back to the other; flock works on any. */
static ovc_file ovc_file_native_open_probe(const char *path, int access)
{
    int flags;

    flags = O_NOFOLLOW;
    switch (access) {
    case OVC_FILE_PROBE_READ:
        flags |= O_RDONLY;
        break;
    case OVC_FILE_PROBE_WRITE:
        flags |= O_WRONLY;
        break;
    default:
        flags |= O_RDWR;
        break;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif
    return open(path, flags);
}

/* Classify a staging-temp candidate without following a final link: whether
 * it exists and whether it is a regular file.  A missing path reports
 * out_exists = false, not an error. */
static int ovc_file_native_probe_kind(const char *path,
                                      bool *out_exists,
                                      bool *out_is_regular)
{
    struct stat native;

    *out_exists = false;
    *out_is_regular = false;
    if (fstatat(AT_FDCWD, path, &native, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        return -1;
    }
    *out_exists = true;
    *out_is_regular = S_ISREG(native.st_mode) != 0;
    return 0;
}

/* unlink needs only directory permissions here; nothing to clear. */
static int ovc_file_native_clear_readonly(const char *path)
{
    (void)path;
    return 0;
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

/* The staging-name shape: a leading '.', a ".tmp" suffix, exactly three
 * trailing all-decimal dot-groups, and a non-empty segment before them.
 * exact_suffix selects a case-sensitive suffix compare. */
static bool ovc_file_staging_temp_name_matches(const char *name,
                                               size_t length,
                                               bool exact_suffix)
{
    size_t end;
    unsigned int numeric_segments;

    if (length < 10 || name[0] != '.') {
        return false;
    }
    if (exact_suffix) {
        if (memcmp(name + length - 4, ".tmp", 4) != 0) {
            return false;
        }
    } else if (!ovc_file_ascii_equal_nocase(name + length - 4, ".tmp", 4)) {
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

/* Enumeration and address matcher: hides and refuses to address.  Win32
 * folds the suffix case because its filesystems do; hiding a name the
 * generator never wrote costs nothing. */
static bool ovc_file_is_atomic_temp_name_n(const char *name, size_t length)
{
#if defined(_WIN32)
    return ovc_file_staging_temp_name_matches(name, length, false);
#else
    return ovc_file_staging_temp_name_matches(name, length, true);
#endif
}

/* The one shape a directory removal may unlink: exact-case ".tmp" on every
 * platform, since neither host's generator writes anything else.  This is the
 * rule the Rust host's removal applies, so the two hosts agree on every name
 * over one on-disk format, and a name either host serves as an object
 * survives the other's removal. */
static bool ovc_file_is_clearable_staging_temp_name(const char *name)
{
    size_t length;

    length = strlen(name);
    /* Both generators write a UTF-8 object name as the leading segment, and
     * the Rust host's matchers see a non-UTF-8 name as no temp at all and
     * serve it as an object; the suffix and digit groups are ASCII, so
     * validating the whole name validates exactly the leading segment. */
    return ovc_file_staging_temp_name_matches(name, length, true) &&
           ovc_utf8_is_valid(name, length);
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
        if (ovc_file_is_atomic_temp_name_n(path + begin,
                                           component_length)) {
            return true;
        }
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

/* Walks `path` up toward `canonical_root`, resolving each candidate with
 * `ovc_file_native_realpath` until one exists, then checks the resolved
 * ancestor stays within the configured root.  `ENAMETOOLONG` joins
 * `ENOENT`/`ENOTDIR` as a "keep walking up" signal: on Windows,
 * `ovc_file_native_realpath`'s `CreateFileW` call rejects a candidate
 * containing `*` or `?` with `ERROR_INVALID_NAME`, which `ovc_win32_set_errno`
 * maps to `ENAMETOOLONG` (shared with the over-long-name case); a
 * syntactically invalid candidate cannot exist at any point in the tree, so
 * it is absent in the same sense `ENOENT` is, and the walk must continue
 * toward an existing in-root ancestor rather than failing the whole address
 * resolution outright. */
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
        if (errno != ENOENT && errno != ENOTDIR
#ifdef ENAMETOOLONG
            && errno != ENAMETOOLONG
#endif
            ) {
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
    bool full_metadata,
    const ovc_file_stat *native)
{
    char *etag;

    memset(out, 0, sizeof(*out));
    out->address = ovc_file_owned_string(address);
    out->kind = native->is_directory
                    ? OvStoragePlugin_ObjectKindV1_Directory
                    : OvStoragePlugin_ObjectKindV1_File;
    etag = ovc_file_etag(native);
    out->etag.present = true;
    out->etag.value = ovc_file_owned_string(etag);
    out->etag_strength = OvStoragePlugin_EtagStrengthV1_Weak;
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
        /* This backend stores no user metadata, so the map is present and
         * empty: nothing on disk is consulted. */
        out->user_metadata.present = true;
        out->user_metadata.value.ptr = (OvStoragePlugin_KeyValuePair *)
            ovc_file_abi_allocate(sizeof(*out->user_metadata.value.ptr));
        out->user_metadata.value.len = 0;
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
    out->etag_strength = source->etag_strength;
    out->version = source->version;
    out->size = source->size;
    out->mtime_unix_ms = source->mtime_unix_ms;
    out->checksums = source->checksums;
    out->effective_permissions = source->effective_permissions;
    out->system_metadata = source->system_metadata;
    out->user_metadata = source->user_metadata;
    out->modified_by = source->modified_by;
    out->versioned_address = source->versioned_address;
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

/* True when the lock attempt failed because another handle holds the lock. */
static bool ovc_file_lock_is_held(int error)
{
    return error == EWOULDBLOCK || error == EAGAIN;
}

/* True when the errno says the lock cannot answer on this filesystem rather
 * than that this attempt failed: no advisory locks at all, as some FUSE and
 * network mounts report, or EBADF from an NFS flock emulation that wants a
 * descriptor open for writing.  The writer's descriptor is always open for
 * writing, so for it this means staging unlocked; for a probe it means the
 * entry cannot be classified and the removal refuses. */
static bool ovc_file_lock_unsupported(int error)
{
    if (error == ENOLCK || error == EBADF) {
        return true;
    }
#ifdef EOPNOTSUPP
    if (error == EOPNOTSUPP) {
        return true;
    }
#endif
#ifdef ENOTSUP
    if (error == ENOTSUP) {
        return true;
    }
#endif
#ifdef ENOSYS
    if (error == ENOSYS) {
        return true;
    }
#endif
    return false;
}

/* Create the staging temp and take the exclusive advisory lock that marks the
 * write live to a delete_directory probing the name.  A removal that took the
 * lock first is clearing the name as an orphan, so a held lock, or a name
 * already gone once the lock is held, means this attempt lost the name and the
 * loop takes a fresh one.  A filesystem without advisory locks stages
 * unlocked; the removal side refuses what it cannot classify. */
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
        ovc_file_stat present;

        candidate = ovc_file_temp_sibling(path, attempt);
        if (candidate == NULL) {
            last_error = errno;
            break;
        }
        file = ovc_file_native_create_new(candidate);
        if (file == OVC_INVALID_FILE) {
            last_error = errno;
            free(candidate);
            if (last_error != EEXIST) {
                break;
            }
            continue;
        }
        if (ovc_file_native_lock_exclusive_nonblocking(file) != 0) {
            last_error = errno;
            if (ovc_file_lock_is_held(last_error)) {
                (void)ovc_file_native_close(file);
                free(candidate);
                last_error = EEXIST;
                continue;
            }
            if (!ovc_file_lock_unsupported(last_error)) {
                (void)ovc_file_native_close(file);
                (void)ovc_file_native_unlink(candidate);
                free(candidate);
                break;
            }
        } else if (ovc_file_native_stat_path(candidate, &present) != 0) {
            last_error = errno;
            (void)ovc_file_native_close(file);
            free(candidate);
            if (last_error == ENOENT) {
                last_error = EEXIST;
                continue;
            }
            break;
        }
        *out_file = file;
        return candidate;
    }
    *out_error = ovc_file_native_error(last_error,
                                       "create atomic-write temp file",
                                       path);
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
    /* A dangling symlink at the destination is a real, present directory
     * entry: `no_overwrite` must refuse to replace it, and `if_match_etag`
     * must compare against its own link metadata, not the target it fails
     * to resolve to. `ovc_file_native_stat_path_or_link` reports that entry
     * instead of answering NotFound for it, unlike the plain follow-only
     * stat every other caller in this file uses. */
    if (ovc_file_native_stat_path_or_link(path, &info) != 0) {
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

/* `report_dangling_link` selects between the two stat-shaped operations
 * that share this function: the top-level `stat` operation passes true,
 * wanting the "answer for the dangling link itself" behavior of
 * `ovc_file_native_stat_path_or_link`; `get_latest_version` and
 * `list_versions` pass false, keeping the plain follow-only behavior, since
 * a dangling link's own metadata is not a version of an object and would
 * pin a caller's etag to a size/mtime that a later follow-only read can
 * never match. */
static OvStoragePlugin_Error *ovc_file_stat_result(
    ovc_file_layer *layer,
    const char *address,
    bool full_metadata,
    bool report_dangling_link,
    OvStoragePlugin_ObjectInfo **out)
{
    char *path;
    ovc_file_stat native;
    OvStoragePlugin_Error *error;
    OvStoragePlugin_ObjectInfo *result;
    bool is_connection_root;
    int stat_result;

    error = NULL;
    path = ovc_file_resolve_path_and_root_flag(layer,
                                               address,
                                               &is_connection_root,
                                               &error);
    if (path == NULL) {
        return error;
    }
    stat_result = report_dangling_link
        ? ovc_file_native_stat_path_or_link(path, &native)
        : ovc_file_native_stat_path(path, &native);
    if (stat_result != 0) {
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
                                      full_metadata,
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
    /* The refusal follows address resolution and precedes every filesystem
     * step: no parent directory is created and no temp sibling is staged. */
    if (task->payload.write.refuse_user_metadata) {
        free(path);
        return ovc_file_error(
            OvStoragePlugin_ErrorCode_Unsupported,
            "file write: backend stores no user metadata; drop user_metadata "
            "or target a backend that supports it");
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
    /* The handle stays open, and so keeps its staging lock, until the rename
     * publishes the bytes; a delete_directory probing the temp meanwhile reads
     * that lock as a live write.  The fsync above already settled durability,
     * so the eventual close result carries nothing and is discarded. */
    if (ovc_file_cancelled(task)) {
        (void)ovc_file_native_unlink(temporary);
        (void)ovc_file_native_close(file);
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
            /* The handle, and the lock it carries, close once the rename has
             * published; the lock's range never overlaps content, so a reader
             * that already found the object is unaffected. */
            (void)ovc_file_native_close(file);
            file = OVC_INVALID_FILE;
            if (ovc_file_native_sync_parent(path) != 0) {
                int native_error;

                native_error = errno;
                error = ovc_file_error(
                    OvStoragePlugin_ErrorCode_CommitAmbiguous,
                    "file was published but its directory sync failed for `%s`: %s",
                    path,
                    ovc_file_strerror(native_error));
            } else if (ovc_file_native_stat_path(path, &native) != 0) {
                /* Re-stat the published destination (as the staged copy
                 * does for out_info): the temp fstat above predates
                 * preserve-destination-permissions, so it would report an
                 * overwritten read-only file as writable.  The reference's
                 * write_atomic likewise ends with a stat of the destination
                 * path. */
                error = ovc_file_native_error(errno,
                                              "stat published file",
                                              path);
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
        (void)ovc_file_native_close(file);
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
 * precondition-recheck -> publish-rename window takes
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
    /* Permissions are copied by path while the staging handle stays open: the
     * handle keeps its staging lock until the rename publishes the bytes, and
     * Win32 attribute writes are exempt from share-mode checks. */
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
    if (ovc_file_native_close(source_file) != 0) {
        source_file = OVC_INVALID_FILE;
        error = ovc_file_native_error(errno,
                                      "close copy source",
                                      source);
        goto done;
    }
    source_file = OVC_INVALID_FILE;

    /* Publish window: only these re-checks and the rename hold the layer
     * mutex. */
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
            /* The staged bytes do not describe the live source any more;
             * publishing them would also bypass a satisfied-at-staging
             * if_source precondition. */
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
                /* The handle, and the lock it carries, close once the rename
                 * has published; the lock's range never overlaps content, so
                 * a reader that already found the object is unaffected. */
                (void)ovc_file_native_close(destination_file);
                destination_file = OVC_INVALID_FILE;
                if (ovc_file_native_sync_parent(destination) != 0) {
                    error = ovc_file_error(
                        OvStoragePlugin_ErrorCode_CommitAmbiguous,
                        "copied file was published but its directory sync failed for `%s`: %s",
                        destination,
                        ovc_file_strerror(errno));
                } else {
                    if (ovc_file_native_stat_path(destination,
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
                                     false,
                                     &info,
                                     &error) == 0) {
        result = (OvStoragePlugin_WriteStep *)
            ovc_file_abi_callocate(1, sizeof(*result));
        result->tag = OvStoragePlugin_WriteStepTag_Done;
        error = ovc_file_object_info_fill(
            &result->done.info,
            task->payload.transfer.destination,
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
        /* A rename onto itself has nothing to move: the preconditions above
         * are satisfied and the object is already at its destination. */
        moved = true;
    } else if (ovc_file_native_rename_replace(source, destination) == 0) {
        moved = true;
        if (ovc_file_native_sync_parent(destination) != 0 ||
            ovc_file_native_sync_parent(source) != 0) {
            error = ovc_file_error(
                OvStoragePlugin_ErrorCode_CommitAmbiguous,
                "renamed file was published but a directory sync failed: %s",
                ovc_file_strerror(errno));
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
    char *path;
    OvStoragePlugin_Error *error;

    /* The address is still resolved first so a malformed or out-of-root URL
     * reports its own error rather than a blanket Unsupported, matching the
     * Rust host's update_metadata.  A resolvable address then has nothing to
     * patch: this backend stores no user metadata, whether or not the target
     * exists.  A host that needs attribution composes it in a layer over a
     * backend that stores the map. */
    (void)out;
    error = NULL;
    path = ovc_file_resolve_path(task->layer, task->address, NULL, &error);
    if (path == NULL) {
        return error;
    }
    free(path);
    return ovc_file_error(
        OvStoragePlugin_ErrorCode_Unsupported,
        "file update_metadata: backend stores no user metadata; target a "
        "backend that supports it");
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
                                 false,
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
                                     false,
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
                                          true,
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

#if defined(_WIN32)
static char *ovc_file_wide_name_to_utf8(const wchar_t *wide);
#endif

/* delete_directory support: verify the directory holds no entries, then
 * rmdir it.  This backend owns nothing inside a directory -- `.ovstorage-meta`
 * and every other name are ordinary content -- so the scan has no skip set:
 * every entry blocks the removal, and the scan reaches the verdict the rmdir
 * would while reporting it as DirectoryNotEmpty on every platform.
 *
 * A link at the addressed path is refused before the scan, so the scan never
 * runs through a link and rmdir's ENOTDIR never reaches the errno table as
 * NotFound.
 *
 * An atomic-write staging temp is the case that makes the scan matter: it is
 * hidden from list and watch because it is not yet an object, but the kernel
 * counts it, so a directory holding an in-flight write is reported here as
 * the DirectoryNotEmpty it is.  An entry created after the scan still fails
 * the rmdir with ENOTEMPTY, which the errno table maps to the same
 * DirectoryNotEmpty.
 *
 * A staging temp is decided by the lock its writer holds, not by its name.
 * The writer takes an exclusive advisory lock on the temp at creation and
 * releases it after the rename that publishes it, so a temp whose lock the
 * removal can take was left by a writer that died without unwinding, whatever
 * pid now wears the number in its name, and the removal clears it.  A temp
 * whose lock is held is a write in flight and refuses the removal as
 * DirectoryNotEmpty naming that write.  Every temp is probed before any is
 * removed, so a refusal destroys nothing.  Enumeration still hides the temp
 * and URL resolution still refuses
 * to address it; the removal is the one API call that clears it.  Only a
 * name the backend's own generator can emit is set aside
 * (ovc_file_is_clearable_staging_temp_name); any other entry, hidden or not,
 * keeps the honest DirectoryNotEmpty. */

/* Owned basenames collected by the delete scan; plain realloc/free. */
typedef struct ovc_file_name_list {
    char **names;
    size_t len;
    size_t capacity;
} ovc_file_name_list;

static int ovc_file_name_list_push(ovc_file_name_list *list, const char *name)
{
    size_t length;
    char *copy;

    if (list->len == list->capacity) {
        size_t next_capacity;
        char **next;

        next_capacity = list->capacity == 0 ? 4 : list->capacity * 2;
        if (next_capacity < list->capacity ||
            next_capacity > SIZE_MAX / sizeof(*next)) {
            errno = ENOMEM;
            return -1;
        }
        next = (char **)realloc(list->names, next_capacity * sizeof(*next));
        if (next == NULL) {
            errno = ENOMEM;
            return -1;
        }
        list->names = next;
        list->capacity = next_capacity;
    }
    length = strlen(name);
    copy = (char *)ovc_file_allocate(length + 1);
    memcpy(copy, name, length + 1);
    list->names[list->len++] = copy;
    return 0;
}

static void ovc_file_name_list_free(ovc_file_name_list *list)
{
    size_t index;

    for (index = 0; index < list->len; ++index) {
        free(list->names[index]);
    }
    free(list->names);
    list->names = NULL;
    list->len = 0;
    list->capacity = 0;
}

typedef enum ovc_file_staging_probe {
    /* The name is gone: its writer published or unlinked it since the scan. */
    OVC_FILE_STAGING_GONE = 0,
    /* Another handle holds the lock: a write in flight. */
    OVC_FILE_STAGING_LIVE = 1,
    /* This handle holds the lock; the writer is gone. */
    OVC_FILE_STAGING_ORPHAN = 2,
    /* Not a regular file, not openable, or no advisory locks: not shown to
     * be an orphan, so not unlinked. */
    OVC_FILE_STAGING_UNCLASSIFIABLE = 3
} ovc_file_staging_probe;

static OvStoragePlugin_Error *ovc_file_in_flight_write_refusal(void)
{
    return ovc_file_error(OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                          "directory holds an in-flight write");
}

static OvStoragePlugin_Error *ovc_file_unclassifiable_refusal(const char *what)
{
    return ovc_file_error(OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                          "directory holds %s",
                          what);
}

/* A temp the scan saw is gone: its writer published it as the child object
 * or unlinked it.  Either way the directory is not the one the scan judged,
 * and proceeding would rmdir over a child just published. */
static OvStoragePlugin_Error *ovc_file_directory_changed_refusal(void)
{
    return ovc_file_error(OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                          "directory changed while it was being removed");
}

#define OVC_FILE_NOT_A_REGULAR_FILE \
    "an entry wearing a staging temp name that is not a regular file"

/* Descriptor exhaustion is deterministic for the caller, so it is reported as
 * ResourceExhausted rather than the retryable code the errno table gives an
 * unknown errno. */
static OvStoragePlugin_Error *ovc_file_staging_probe_error(int native_error,
                                                           const char *action,
                                                           const char *path)
{
#ifdef EMFILE
    if (native_error == EMFILE) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "too many open files while probing staging temps");
    }
#endif
#ifdef ENFILE
    if (native_error == ENFILE) {
        return ovc_file_error(OvStoragePlugin_ErrorCode_ResourceExhausted,
                              "too many open files while probing staging temps");
    }
#endif
    return ovc_file_native_error(native_error, action, path);
}

/* Open, inspect and lock one staging temp, holding a single descriptor.  On
 * ORPHAN the locked handle is returned in *out_handle for the caller to
 * unlink under and close; every other verdict closes it here.  The open
 * never follows a link, so a symlink wearing the name is refused rather than
 * probed through, and never blocks, so a fifo cannot hold it. */
static ovc_file_staging_probe ovc_file_probe_staging_temp(
    const char *full,
    ovc_file *out_handle,
    const char **out_what,
    OvStoragePlugin_Error **out_error)
{
    ovc_file handle;
    ovc_file_stat info;
    int native_error;
    bool exists;
    bool is_regular;

    *out_handle = OVC_INVALID_FILE;
    *out_what = NULL;
    *out_error = NULL;
    /* Classify before opening, so a socket, a fifo or a link wearing the
     * name is refused on its kind and never reaches an open whose errno
     * would read as retryable. */
    if (ovc_file_native_probe_kind(full, &exists, &is_regular) != 0) {
        *out_error = ovc_file_staging_probe_error(errno,
                                                  "classify staging temp",
                                                  full);
        return OVC_FILE_STAGING_UNCLASSIFIABLE;
    }
    if (!exists) {
        return OVC_FILE_STAGING_GONE;
    }
    if (!is_regular) {
        *out_what = OVC_FILE_NOT_A_REGULAR_FILE;
        return OVC_FILE_STAGING_UNCLASSIFIABLE;
    }
    handle = ovc_file_native_open_probe(full, OVC_FILE_PROBE_READ_WRITE);
    if (handle == OVC_INVALID_FILE &&
        (errno == EACCES || errno == EPERM)) {
        /* A copy staged from a read-only or a write-only source carries
         * that mode; whichever side is allowed still carries the lock. */
        handle = ovc_file_native_open_probe(full, OVC_FILE_PROBE_READ);
    }
    if (handle == OVC_INVALID_FILE &&
        (errno == EACCES || errno == EPERM)) {
        handle = ovc_file_native_open_probe(full, OVC_FILE_PROBE_WRITE);
    }
    if (handle == OVC_INVALID_FILE) {
        native_error = errno;
        if (native_error == ENOENT) {
            return OVC_FILE_STAGING_GONE;
        }
        if (native_error == EACCES || native_error == EPERM) {
            *out_what = "an entry wearing a staging temp name that cannot be opened";
            return OVC_FILE_STAGING_UNCLASSIFIABLE;
        }
        /* An entry swapped since the classification: a link refuses the
         * no-follow open with ELOOP, a directory the read-write open with
         * EISDIR, a socket or a reader-less fifo with ENXIO.  None is the
         * backend's temp. */
#ifdef ELOOP
        if (native_error == ELOOP) {
            *out_what = OVC_FILE_NOT_A_REGULAR_FILE;
            return OVC_FILE_STAGING_UNCLASSIFIABLE;
        }
#endif
#ifdef EISDIR
        if (native_error == EISDIR) {
            *out_what = OVC_FILE_NOT_A_REGULAR_FILE;
            return OVC_FILE_STAGING_UNCLASSIFIABLE;
        }
#endif
#ifdef ENXIO
        if (native_error == ENXIO) {
            *out_what = OVC_FILE_NOT_A_REGULAR_FILE;
            return OVC_FILE_STAGING_UNCLASSIFIABLE;
        }
#endif
        *out_error = ovc_file_staging_probe_error(native_error,
                                                  "probe staging temp",
                                                  full);
        return OVC_FILE_STAGING_UNCLASSIFIABLE;
    }
    /* A staging temp is a regular file; a directory or a special file wearing
     * the name is not the backend's and is not unlinked. */
    if (ovc_file_native_fstat(handle, &info) != 0) {
        native_error = errno;
        (void)ovc_file_native_close(handle);
        *out_error = ovc_file_staging_probe_error(native_error,
                                                  "inspect staging temp",
                                                  full);
        return OVC_FILE_STAGING_UNCLASSIFIABLE;
    }
    if (!info.is_regular) {
        (void)ovc_file_native_close(handle);
        *out_what = OVC_FILE_NOT_A_REGULAR_FILE;
        return OVC_FILE_STAGING_UNCLASSIFIABLE;
    }
    if (ovc_file_native_lock_exclusive_nonblocking(handle) != 0) {
        native_error = errno;
        (void)ovc_file_native_close(handle);
        if (ovc_file_lock_is_held(native_error)) {
            return OVC_FILE_STAGING_LIVE;
        }
        if (ovc_file_lock_unsupported(native_error)) {
            *out_what = "a staging temp this filesystem cannot classify as orphaned";
            return OVC_FILE_STAGING_UNCLASSIFIABLE;
        }
        *out_error = ovc_file_staging_probe_error(native_error,
                                                  "lock staging temp",
                                                  full);
        return OVC_FILE_STAGING_UNCLASSIFIABLE;
    }
    *out_handle = handle;
    return OVC_FILE_STAGING_ORPHAN;
}

/* Turn a non-ORPHAN probe verdict into the caller's error. */
static OvStoragePlugin_Error *ovc_file_staging_probe_refusal(
    ovc_file_staging_probe verdict,
    const char *what,
    OvStoragePlugin_Error *error)
{
    switch (verdict) {
    case OVC_FILE_STAGING_GONE:
        return ovc_file_directory_changed_refusal();
    case OVC_FILE_STAGING_LIVE:
        return ovc_file_in_flight_write_refusal();
    case OVC_FILE_STAGING_UNCLASSIFIABLE:
        return error != NULL ? error : ovc_file_unclassifiable_refusal(what);
    default:
        return NULL;
    }
}

/* Clear the atomic-write staging temps the delete scan set aside, once each
 * is shown to belong to no live writer (see the block comment above).
 *
 * Two passes, one descriptor at a time, so the number of temps a removal can
 * clear is not bounded by the descriptor limit.  The first pass probes every
 * temp's lock and releases it; a write in flight, or an entry the probe
 * cannot classify, refuses the removal before anything is touched.  The
 * second pass takes each lock again and unlinks under it.  A name is never
 * created twice, so a temp free in the first pass has no writer to become
 * live in the second; a lock found busy there is another removal's probe and
 * is refused the same way.
 *
 * A temp the scan saw but the probe no longer finds is refused too: the way
 * a temp vanishes is its writer's rename publishing it as a child object.
 * The directory is not the one the scan judged, so the scan's verdict does
 * not carry.
 *
 * Removal is by path, never through the probe handle: a writer that renames
 * its temp into place between the probe's open and its lock leaves the probe
 * holding the published inode, and the by-path unlink then finds no such
 * name, where a handle-based delete would destroy the object just published.
 *
 * An entry the probe cannot show to be an orphan — of the wrong kind, not
 * openable, or on a filesystem without advisory locks — refuses the removal
 * as the DirectoryNotEmpty the kernel would report at the rmdir, rather than
 * risk a write in flight or surface a raw errno as retryable. */
static OvStoragePlugin_Error *ovc_file_directory_clear_orphaned_staging_temps(
    const char *path,
    const ovc_file_name_list *temps)
{
    size_t index;
    unsigned int pass;

    for (pass = 0; pass < 2; ++pass) {
        for (index = 0; index < temps->len; ++index) {
            char *full;
            ovc_file handle;
            const char *what;
            OvStoragePlugin_Error *error;
            ovc_file_staging_probe verdict;

            full = ovc_path_join(path, temps->names[index]);
            if (full == NULL) {
                return ovc_file_native_error(errno,
                                             "build staging temp path",
                                             path);
            }
            verdict = ovc_file_probe_staging_temp(full, &handle, &what, &error);
            if (verdict != OVC_FILE_STAGING_ORPHAN) {
                error = ovc_file_staging_probe_refusal(verdict, what, error);
                free(full);
                if (error != NULL) {
                    return error;
                }
                continue;
            }
            error = NULL;
            if (pass == 1) {
                if (ovc_file_native_clear_readonly(full) != 0) {
                    error = errno == ENOENT
                                ? ovc_file_directory_changed_refusal()
                                : ovc_file_staging_probe_error(
                                      errno, "clear staging temp attributes", full);
                } else if (ovc_file_native_unlink(full) != 0) {
                    error = errno == ENOENT
                                ? ovc_file_directory_changed_refusal()
                                : ovc_file_staging_probe_error(
                                      errno, "remove orphaned staging temp", full);
                }
            }
            /* Win32 completes the unlink at close, ahead of the rmdir. */
            (void)ovc_file_native_close(handle);
            free(full);
            if (error != NULL) {
                return error;
            }
        }
    }
    return NULL;
}

#if defined(_WIN32)

static OvStoragePlugin_Error *ovc_file_directory_reject_visible_entries(
    const char *path)
{
    char *pattern;
    wchar_t *pattern_wide;
    WIN32_FIND_DATAW entry;
    HANDLE find;
    OvStoragePlugin_Error *error;
    ovc_file_name_list temps;

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
    memset(&temps, 0, sizeof(temps));
    do {
        char *name;

        name = ovc_file_wide_name_to_utf8(entry.cFileName);
        if (name == NULL) {
            error = ovc_file_native_error(errno,
                                          "decode directory entry",
                                          path);
            break;
        }
        if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            if (ovc_file_is_clearable_staging_temp_name(name)) {
                if (ovc_file_name_list_push(&temps, name) != 0) {
                    error = ovc_file_native_error(errno,
                                                  "collect staging temps",
                                                  path);
                    free(name);
                    break;
                }
            } else {
                error = ovc_file_error(
                    OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                    "directory is not empty");
                free(name);
                break;
            }
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
    if (error == NULL) {
        error = ovc_file_directory_clear_orphaned_staging_temps(path, &temps);
    }
    ovc_file_name_list_free(&temps);
    return error;
}

/* True when the attributes describe a reparse point (junction or symlink):
 * such an entry is a link, and delete_directory refuses it rather than
 * enumerating through it -- FindFirstFileW would otherwise report the
 * target's contents as the link's own. */
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

static int ovc_file_delete_target_is_link(const char *path,
                                          bool *out_is_link)
{
    wchar_t *wide;
    HANDLE handle;
    FILE_ATTRIBUTE_TAG_INFO tag_info;

    *out_is_link = false;
    wide = ovc_file_utf8_to_wide(path);
    if (wide == NULL) {
        return -1;
    }
    handle = CreateFileW(wide,
                         FILE_READ_ATTRIBUTES,
                         FILE_SHARE_READ | FILE_SHARE_WRITE |
                             FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         FILE_FLAG_OPEN_REPARSE_POINT |
                             FILE_FLAG_BACKUP_SEMANTICS,
                         NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD native_error;

        native_error = GetLastError();
        free(wide);
        ovc_win32_set_errno(native_error);
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        return -1;
    }
    free(wide);
    if (!GetFileInformationByHandleEx(handle,
                                      FileAttributeTagInfo,
                                      &tag_info,
                                      sizeof(tag_info))) {
        DWORD native_error;

        native_error = GetLastError();
        (void)CloseHandle(handle);
        ovc_win32_set_errno(native_error);
        if (errno == ENOENT || errno == ENOTDIR) {
            return 0;
        }
        return -1;
    }
    (void)CloseHandle(handle);
    *out_is_link = ovc_file_win32_attributes_are_link(
        tag_info.FileAttributes, tag_info.ReparseTag);
    return 0;
}

#else

static OvStoragePlugin_Error *ovc_file_directory_reject_visible_entries(
    const char *path)
{
    DIR *directory;
    struct dirent *entry;
    OvStoragePlugin_Error *error;
    ovc_file_name_list temps;

    directory = opendir(path);
    if (directory == NULL) {
        return ovc_file_native_error(errno,
                                     "scan directory for delete",
                                     path);
    }
    error = NULL;
    memset(&temps, 0, sizeof(temps));
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            errno = 0;
            continue;
        }
        if (ovc_file_is_clearable_staging_temp_name(entry->d_name)) {
            if (ovc_file_name_list_push(&temps, entry->d_name) != 0) {
                error = ovc_file_native_error(errno,
                                              "collect staging temps",
                                              path);
                break;
            }
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
    if (error == NULL) {
        error = ovc_file_directory_clear_orphaned_staging_temps(path, &temps);
    }
    ovc_file_name_list_free(&temps);
    return error;
}

static int ovc_file_delete_target_is_link(const char *path,
                                          bool *out_is_link)
{
    bool exists;
    bool is_dir;

    if (ovc_file_native_lstat_kind(path,
                                   &exists,
                                   out_is_link,
                                   &is_dir) != 0) {
        return -1;
    }
    if (!exists) {
        *out_is_link = false;
    }
    return 0;
}

#endif

static OvStoragePlugin_Error *ovc_file_delete_directory_result(
    ovc_file_task *task)
{
    char *path;
    OvStoragePlugin_Error *error;
    bool is_connection_root;
    bool target_is_link;

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
    (void)ovc_mutex_lock(&task->layer->mutex);
    if (ovc_file_cancelled(task)) {
        error = ovc_file_error(OvStoragePlugin_ErrorCode_Cancelled,
                               "delete_directory was cancelled");
    } else if (ovc_file_delete_target_is_link(path, &target_is_link) != 0) {
        error = ovc_file_native_error(errno,
                                      "inspect delete_directory target",
                                      path);
    } else if (target_is_link) {
        error = ovc_file_error(
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "delete_directory target is a symlink; the entry is "
            "operator-configured on disk and delete_directory will not "
            "remove or follow it");
    } else {
        /* Refuse a directory that still holds entries before the rmdir so
         * the refusal carries DirectoryNotEmpty on every platform. */
        error = ovc_file_directory_reject_visible_entries(path);
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
    }
    (void)ovc_mutex_unlock(&task->layer->mutex);
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
        info.readonly) {
        /* The decision reports the filesystem's permission verdict only;
         * update_metadata itself is Unsupported on this backend (see
         * ovc_file_update_metadata_result), which is a capability answer
         * rather than an access one. */
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

/* True for an entry enumeration must hide: an atomic-write staging temp,
 * which is not yet a caller-visible object.  The delete-emptiness scan does
 * not consult this predicate: a staging temp is a real directory entry the
 * kernel counts, so the rmdir refuses while one is present.  The scan sets
 * aside only a name ovc_file_is_clearable_staging_temp_name accepts, for
 * ovc_file_directory_clear_orphaned_staging_temps to decide by the lock its
 * writer would hold: an orphan is unlinked under that lock and a write in
 * flight refuses the removal.  Every other entry is reported, so the
 * backend's notion of "empty" stays identical to the kernel's.  Every other
 * name, `.ovstorage-meta` included, is ordinary content: listed,
 * addressable, and counted by the scan. */
static bool ovc_file_is_internal_entry(const char *name)
{
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
        if (child_path == NULL) {
            error = ovc_file_native_error(errno,
                                          "stat directory entry",
                                          path);
            free(name);
            break;
        }
        if (ovc_file_native_stat_path(child_path, &native) != 0) {
            int native_error;

            native_error = errno;
            if (!ovc_file_stat_error_means_absent(native_error)) {
                error = ovc_file_native_error(native_error,
                                              "stat directory entry",
                                              child_path);
                free(child_path);
                free(name);
                break;
            }
            /* SKIPPED rather than failing the whole listing, matching the
             * POSIX branch: a dangling reparse point or an entry another
             * process deleted between `FindFirstFileW`/`FindNextFileW` and
             * this stat both land here, and one unexaminable entry should
             * not cost the caller every entry beside it. */
            free(child_path);
            free(name);
            continue;
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
            if (!ovc_file_stat_error_means_absent(native_error)) {
                error = ovc_file_native_error(native_error,
                                              "stat directory entry",
                                              child_path);
                free(child_path);
                break;
            }
            /* SKIPPED rather than failing the whole listing, matching the
             * re-resolve/containment failure just below: one unexaminable
             * entry should not cost the caller every entry beside it. */
            free(child_path);
            errno = 0;
            continue;
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
    const ovc_file_stat *info)
{
    OvStoragePlugin_Error *error;
    ovc_file_watch_entry *entry;

    error = ovc_file_watch_snapshot_reserve(snapshot);
    if (error != NULL) {
        return error;
    }
    entry = &snapshot->items[snapshot->len];
    memset(entry, 0, sizeof(*entry));
    entry->address = ovc_file_string_duplicate(address);
    entry->info = *info;
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
                error = ovc_file_watch_snapshot_push(snapshot,
                                                     child_address,
                                                     &info);
                if (error == NULL && watcher->recursive &&
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
            error = ovc_file_watch_snapshot_push(snapshot,
                                                 child_address,
                                                 &info);
            if (error == NULL && watcher->recursive &&
                !S_ISLNK(link_info.st_mode)) {
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
            /* A directory's inode metadata changes when its children change,
             * but watch_directory reports object changes, not directory
             * roll-ups. Keep directories in the snapshot so their own
             * creation and deletion are observable, while suppressing
             * metadata-only changes for an entry that remains a directory. */
            if (!old_entry->info.is_directory &&
                (old_entry->info.size != new_entry->info.size ||
                 old_entry->info.mtime_unix_nanos !=
                     new_entry->info.mtime_unix_nanos)) {
                error = ovc_file_watch_changes_push(
                    changes,
                    new_entry->address,
                    OvStoragePlugin_ChangeKind_Modified,
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
        if (!change->current.is_directory) {
            out_item->object.size.present = true;
            out_item->object.size.value = change->current.size;
        }
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
    /* options->include_metadata_changes is accepted and has no effect: this
     * backend stores no user metadata, so no MetadataChanged event exists. */
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
        task->layer->name,
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
                                       task->layer->name, result);
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
        ovc_file_connection_to_ffi(&layer->connections[index], layer->name,
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
                                         true,
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
    unsupported_body = moved.body.tag != OvStoragePlugin_BodyTag_Bytes;
    /* This backend stores no user metadata.  A present-but-empty map asks
     * for nothing and is accepted; a non-empty map is refused by the task
     * once the address has resolved, so an address error wins over the
     * refusal exactly as it does on the Rust host, and nothing touches disk
     * either way. */
    task->payload.write.refuse_user_metadata =
        moved.options.user_metadata.present &&
        moved.options.user_metadata.value.len > 0;
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
    /* File has no version annotation slot; message is intentionally ignored. */
    ovstorage_plugin_write_request_release(&moved);
    if (unsupported_body) {
        ovc_file_task_fail(task,
                           OvStoragePlugin_ErrorCode_Unsupported,
                           "buffered file write requires a Bytes body");
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
        /* Mirrors ovc_file_descriptor_fill: no user metadata is stored. */
        .supports_user_metadata = false,
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

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/un.h>
#endif

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
        assert(!page->items.ptr[index].versioned_address.present);
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
        assert(!page->items.ptr[index].versioned_address.present);
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
    /* A connection reports the layer INSTANCE name a connection op routes by
     * ("files", deliberately different from the "file" kind) -- the same value
     * this layer's roots report and `owned_targets` publishes. The clear below
     * frees that owning `Optional<Str>` (leak-clean under the sanitizer gate). */
    assert(connection->owning_target.present);
    assert(connection->owning_target.value.len == 5);
    assert(memcmp(connection->owning_target.value.ptr, "files", 5) == 0);
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
            /* Every listed row carries it, not only the one `add_connection`
             * handed back -- a caller that meets a connection through the
             * listing is the one that had to discover its owner by probing. */
            assert(result->snapshot.connections.ptr[index].owning_target
                       .present);
            assert(memcmp(result->snapshot.connections.ptr[index]
                              .owning_target.value.ptr,
                          "files",
                          5) == 0);
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
    assert(connection->owning_target.present);
    assert(memcmp(connection->owning_target.value.ptr, "files", 5) == 0);
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
    object.versioned_address = info->versioned_address;
    ovc_file_object_info_clear(&object);
    memset(info, 0, sizeof(*info));
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
    assert(result->done.info.user_metadata.value.len == 0);
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

static void ovc_file_test_watch_directory_child(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    static const uint8_t payload[] = "watched child";
    OvStoragePlugin_BackendChangeStream *stream;
    ovc_file_test_watch_next call;
    ovc_thread thread;
    char *created_address;
    char *deleted_address;
    char *old_address;
    char *new_address;
    char *child_address;
    char *descendant_address;
    char *signal_address;
    bool saw_deleted;
    bool saw_created;

    created_address = ovc_file_join_address(root_url,
                                            "watch-directory-created",
                                            true);
    signal_address = ovc_file_join_address(root_url,
                                           "watch-directory-signal.txt",
                                           false);
    stream = ovc_file_test_watch_open(handle, root_url, 0, NULL);
    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovc_file_test_create_directory(handle, created_address);
    ovc_file_test_write(handle, signal_address, payload, sizeof(payload) - 1);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Created);
    assert(call.event.object.address.len == strlen(created_address));
    assert(memcmp(call.event.object.address.ptr,
                  created_address,
                  strlen(created_address)) == 0);
    assert(!call.event.object.size.present);
    ovc_file_test_watch_event_clear(&call.event);
    ovc_file_test_watch_drop_once(stream);
    ovc_file_test_delete_directory(handle, created_address);
    ovc_file_test_delete(handle, signal_address);

    deleted_address = ovc_file_join_address(root_url,
                                            "watch-directory-deleted",
                                            true);
    ovc_file_test_create_directory(handle, deleted_address);
    stream = ovc_file_test_watch_open(handle, root_url, 0, NULL);
    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovc_file_test_delete_directory(handle, deleted_address);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Deleted);
    assert(call.event.object.address.len == strlen(deleted_address));
    assert(memcmp(call.event.object.address.ptr,
                  deleted_address,
                  strlen(deleted_address)) == 0);
    assert(!call.event.object.etag.present);
    assert(!call.event.object.size.present);
    assert(!call.event.object.mtime_unix_ms.present);
    ovc_file_test_watch_event_clear(&call.event);
    ovc_file_test_watch_drop_once(stream);

    old_address = ovc_file_join_address(root_url,
                                        "watch-directory-old",
                                        true);
    new_address = ovc_file_join_address(root_url,
                                        "watch-directory-new",
                                        true);
    ovc_file_test_create_directory(handle, old_address);
    stream = ovc_file_test_watch_open(handle, root_url, 0, NULL);
    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovc_file_test_rename(handle, old_address, new_address);
    assert(ovc_thread_join(&thread) == 0);
    saw_deleted = false;
    saw_created = false;
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    if (call.event.object.kind == OvStoragePlugin_ChangeKind_Deleted) {
        assert(call.event.object.address.len == strlen(old_address));
        assert(memcmp(call.event.object.address.ptr,
                      old_address,
                      strlen(old_address)) == 0);
        saw_deleted = true;
    } else {
        assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Created);
        assert(call.event.object.address.len == strlen(new_address));
        assert(memcmp(call.event.object.address.ptr,
                      new_address,
                      strlen(new_address)) == 0);
        saw_created = true;
    }
    ovc_file_test_watch_event_clear(&call.event);
    memset(&call.event, 0, sizeof(call.event));
    memset(&call.error, 0, sizeof(call.error));
    assert(stream->next_fn(stream->state, &call.event, &call.error) ==
           OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    if (call.event.object.kind == OvStoragePlugin_ChangeKind_Deleted) {
        assert(!saw_deleted);
        assert(call.event.object.address.len == strlen(old_address));
        assert(memcmp(call.event.object.address.ptr,
                      old_address,
                      strlen(old_address)) == 0);
        saw_deleted = true;
    } else {
        assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Created);
        assert(!saw_created);
        assert(call.event.object.address.len == strlen(new_address));
        assert(memcmp(call.event.object.address.ptr,
                      new_address,
                      strlen(new_address)) == 0);
        saw_created = true;
    }
    assert(saw_deleted);
    assert(saw_created);
    ovc_file_test_watch_event_clear(&call.event);
    ovc_file_test_watch_drop_once(stream);
    ovc_file_test_delete_directory(handle, new_address);

    child_address = ovc_file_join_address(root_url,
                                          "watch-directory-child",
                                          true);
    descendant_address = ovc_file_join_address(child_address,
                                               "descendant.txt",
                                               false);
    /* The child is in the opening snapshot. Its descendant write changes
     * the directory mtime, but the sorted signal event must arrive first:
     * a directory Modified roll-up would otherwise precede it. */
    ovc_file_test_create_directory(handle, child_address);
    stream = ovc_file_test_watch_open(handle, root_url, 0, NULL);
    ovc_file_test_watch_next_start(&call, stream, &thread);
    ovc_file_test_write(handle,
                        descendant_address,
                        payload,
                        sizeof(payload) - 1);
    ovc_file_test_write(handle, signal_address, payload, sizeof(payload) - 1);
    assert(ovc_thread_join(&thread) == 0);
    assert(call.step == OvStoragePlugin_StreamStep_Yielded);
    assert(call.event.tag == OvStoragePlugin_BackendChangeEventTag_Object);
    assert(call.event.object.kind == OvStoragePlugin_ChangeKind_Created);
    assert(call.event.object.address.len == strlen(signal_address));
    assert(memcmp(call.event.object.address.ptr,
                  signal_address,
                  strlen(signal_address)) == 0);
    assert(call.event.object.address.len != strlen(descendant_address));
    ovc_file_test_watch_event_clear(&call.event);
    ovc_file_test_watch_drop_once(stream);
    ovc_file_test_delete(handle, descendant_address);
    ovc_file_test_delete_directory(handle, child_address);
    ovc_file_test_delete(handle, signal_address);

    free(created_address);
    free(deleted_address);
    free(old_address);
    free(new_address);
    free(child_address);
    free(descendant_address);
    free(signal_address);
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

/* Final path component, past the last separator of either flavour. */
static const char *ovc_file_test_basename(const char *path)
{
    const char *slash;
    const char *backslash;
    const char *last;

    slash = strrchr(path, '/');
    backslash = strrchr(path, '\\');
    last = slash;
    if (backslash != NULL && (last == NULL || backslash > last)) {
        last = backslash;
    }
    return last == NULL ? path : last + 1;
}

/* Like ovc_file_test_delete_directory_refused, and the refusal's message
 * must also contain `needle`, so a refusal reached for the wrong reason
 * cannot pass on its code alone. */
static void ovc_file_test_delete_directory_refused_naming(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    OvStoragePlugin_ErrorCode expected,
    const char *needle)
{
    OvStoragePlugin_DeleteDirectoryRequest request;
    ovc_file_test_completion completion;
    char *message;

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
    assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
    assert(completion.error != NULL);
    assert(completion.error->code == expected);
    message = (char *)ovc_file_allocate(completion.error->message_len + 1);
    memcpy(message, completion.error->message_ptr,
           completion.error->message_len);
    message[completion.error->message_len] = '\0';
    if (strstr(message, needle) == NULL) {
        (void)fprintf(stderr,
                      "delete_directory of %s refused with `%s`, "
                      "expected a message naming `%s`\n",
                      address, message, needle);
        (void)fflush(stderr);
    }
    assert(strstr(message, needle) != NULL);
    free(message);
    ovc_file_error_destroy(completion.error);
}

/* Drive a write whose options carry `pairs` user-metadata entries (the map
 * is present even when `pairs` is zero) and, when `message` is non-NULL, a
 * version message.  `expected` is the refusal code, or one of these
 * sentinels: the write must succeed, or it must fail with any code except
 * Unsupported (an address whose own resolution error wins over the
 * user-metadata refusal). */
#define OVC_FILE_TEST_EXPECT_SUCCESS (-1)
#define OVC_FILE_TEST_ANY_ERROR_BUT_UNSUPPORTED (-2)

static void ovc_file_test_write_with_options(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    size_t pairs,
    const char *message,
    int expected)
{
    static const uint8_t payload[] = "metadata option probe";
    OvStoragePlugin_WriteRequest request;
    ovc_file_test_completion completion;
    size_t index;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.body.tag = OvStoragePlugin_BodyTag_Bytes;
    request.body.bytes.ptr = (uint8_t *)
        ovc_file_abi_allocate(sizeof(payload) - 1);
    request.body.bytes.len = sizeof(payload) - 1;
    memcpy(request.body.bytes.ptr, payload, sizeof(payload) - 1);
    request.options.struct_size = sizeof(request.options);
    request.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_Overwrite;
    request.options.user_metadata.present = true;
    request.options.user_metadata.value.ptr =
        (OvStoragePlugin_KeyValuePair *)ovc_file_abi_callocate(
            pairs == 0 ? 1 : pairs,
            sizeof(*request.options.user_metadata.value.ptr));
    request.options.user_metadata.value.len = pairs;
    for (index = 0; index < pairs; ++index) {
        request.options.user_metadata.value.ptr[index].key =
            ovc_file_owned_string("purpose");
        request.options.user_metadata.value.ptr[index].value =
            ovc_file_owned_string("refused");
    }
    if (message != NULL) {
        request.options.message.present = true;
        request.options.message.value = ovc_file_owned_string(message);
    }
    ovc_file_test_completion_init(&completion);
    handle->vtable->write(handle->state,
                          &request,
                          NULL,
                          ovc_file_test_complete,
                          &completion);
    if (expected == OVC_FILE_TEST_EXPECT_SUCCESS) {
        OvStoragePlugin_WriteResult *result;

        ovc_file_test_expect_success("write with options", &completion);
        result = (OvStoragePlugin_WriteResult *)completion.result;
        assert(result != NULL);
        assert(result->info.size.present);
        assert(result->info.size.value == sizeof(payload) - 1);
        assert(result->info.user_metadata.present);
        assert(result->info.user_metadata.value.len == 0);
        ovc_file_object_info_clear(&result->info);
        ovc_abi_free(result);
        return;
    }
    ovc_file_test_completion_wait(&completion);
    if (completion.status != OvStoragePlugin_FFI_STATUS_ERR ||
        completion.error == NULL ||
        (expected == OVC_FILE_TEST_ANY_ERROR_BUT_UNSUPPORTED
             ? completion.error->code == OvStoragePlugin_ErrorCode_Unsupported
             : (int)completion.error->code != expected)) {
        (void)fprintf(stderr,
                      "write of %s: status=%d code=%d (expected code=%d)\n",
                      address,
                      (int)completion.status,
                      completion.error == NULL
                          ? -1
                          : (int)completion.error->code,
                      expected);
        (void)fflush(stderr);
    }
    assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
    assert(completion.error != NULL);
    if (expected == OVC_FILE_TEST_ANY_ERROR_BUT_UNSUPPORTED) {
        assert(completion.error->code != OvStoragePlugin_ErrorCode_Unsupported);
    } else {
        assert((int)completion.error->code == expected);
    }
    assert(completion.result == NULL);
    ovc_file_error_destroy(completion.error);
}

/* The backend declares, in both descriptor spellings and in its
 * capabilities, that it stores no user metadata. */
static void ovc_file_test_no_user_metadata_declared(void)
{
    OvStoragePlugin_LayerKindDescriptor descriptor;
    OvStoragePlugin_Capabilities capabilities;

    ovc_file_descriptor_fill(&descriptor);
    assert(!descriptor.supports_user_metadata);
    ovc_file_descriptor_clear(&descriptor);
    assert(!g_ovc_file_builtin_descriptor.supports_user_metadata);

    capabilities = ovc_file_capabilities();
    assert(!capabilities.supports_native_metadata_patch);
    assert(!capabilities.watch_directory_kinds.metadata_changed);
    assert(capabilities.watch_directory_kinds.modified);
}

/* A write carrying a non-empty user-metadata map is refused with
 * Unsupported before the backend touches the filesystem: no object, no temp
 * sibling, no parent directory.  The refusal follows address resolution, so
 * an address outside the connection root reports its own error first, as
 * the Rust host does. */
static void ovc_file_test_write_user_metadata_refused(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url,
    const char *outside_address)
{
    char *directory_address;
    char *directory_path;
    char *address;
    char *path;
    OvStoragePlugin_Error *path_error;
    ovc_file_stat info;

    directory_address = ovc_file_join_address(root_url, "refused-meta", true);
    address = ovc_file_join_address(directory_address, "refused.txt", false);
    path_error = NULL;
    directory_path = ovc_file_url_to_path(directory_address, &path_error);
    assert(path_error == NULL);
    path = ovc_file_url_to_path(address, &path_error);
    assert(path_error == NULL);
    errno = 0;
    assert(ovc_file_native_stat_path(directory_path, &info) != 0);
    assert(errno == ENOENT);

    ovc_file_test_write_with_options(
        handle,
        address,
        1,
        NULL,
        (int)OvStoragePlugin_ErrorCode_Unsupported);

    errno = 0;
    assert(ovc_file_native_stat_path(path, &info) != 0);
    assert(errno == ENOENT);
    errno = 0;
    assert(ovc_file_native_stat_path(directory_path, &info) != 0);
    assert(errno == ENOENT);

    ovc_file_test_write_with_options(
        handle,
        outside_address,
        1,
        NULL,
        OVC_FILE_TEST_ANY_ERROR_BUT_UNSUPPORTED);
    free(path);
    free(directory_path);
    free(address);
    free(directory_address);
}

/* A present-but-empty map asks for nothing and is accepted; stat then
 * reports the same empty map. */
static void ovc_file_test_write_empty_user_metadata(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    char *address;
    OvStoragePlugin_StatRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ObjectInfo *result;

    address = ovc_file_join_address(root_url, "empty-meta.txt", false);
    ovc_file_test_write_with_options(
        handle, address, 0, NULL, OVC_FILE_TEST_EXPECT_SUCCESS);

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.address = ovc_file_owned_string(address);
    request.options.struct_size = sizeof(request.options);
    request.options.full_metadata = true;
    ovc_file_test_completion_init(&completion);
    handle->vtable->stat(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("stat empty-metadata object", &completion);
    result = (OvStoragePlugin_ObjectInfo *)completion.result;
    assert(result != NULL);
    assert(result->user_metadata.present);
    assert(result->user_metadata.value.len == 0);
    ovc_file_object_info_clear(result);
    ovc_abi_free(result);

    ovc_file_test_delete(handle, address);
    free(address);
}

/* A write carrying only a version message succeeds: the message is dropped
 * because the backend has no annotation slot for it. */
static void ovc_file_test_write_message_only(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    char *address;

    address = ovc_file_join_address(root_url, "message-only.txt", false);
    ovc_file_test_write_with_options(handle,
                                     address,
                                     0,
                                     "annotation the backend drops",
                                     OVC_FILE_TEST_EXPECT_SUCCESS);
    ovc_file_test_delete(handle, address);
    free(address);
}

/* update_metadata answers Unsupported for any address this backend serves,
 * whether or not the object exists; an address outside the connection root
 * reports its own resolution error first, as the Rust host does. */
static void ovc_file_test_update_metadata_unsupported_at(
    OvStoragePlugin_LayerHandle *handle,
    const char *address,
    bool expect_unsupported)
{
    OvStoragePlugin_UpdateMetadataRequest request;
    ovc_file_test_completion completion;

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
        ovc_file_owned_string("unsupported");
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
    ovc_file_test_completion_wait(&completion);
    assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
    assert(completion.error != NULL);
    if (expect_unsupported) {
        assert(completion.error->code == OvStoragePlugin_ErrorCode_Unsupported);
    } else {
        assert(completion.error->code != OvStoragePlugin_ErrorCode_Unsupported);
    }
    assert(completion.result == NULL);
    ovc_file_error_destroy(completion.error);
}

static void ovc_file_test_update_metadata_unsupported(
    OvStoragePlugin_LayerHandle *handle,
    const char *present_address,
    const char *root_url,
    const char *outside_address)
{
    char *missing_address;

    missing_address = ovc_file_join_address(root_url, "ghost.bin", false);
    ovc_file_test_update_metadata_unsupported_at(handle, present_address, true);
    ovc_file_test_update_metadata_unsupported_at(handle, missing_address, true);
    ovc_file_test_update_metadata_unsupported_at(handle, outside_address, false);
    free(missing_address);
}

/* A `.ovstorage-meta` directory found on disk is ordinary content: list
 * reports it like any other child, and delete_directory of its parent is
 * DirectoryNotEmpty until it is removed. */
static void ovc_file_test_metadata_directory_is_ordinary(
    OvStoragePlugin_LayerHandle *handle,
    const char *root_url)
{
    char *directory_address;
    char *directory_path;
    char *metadata_directory;
    OvStoragePlugin_Error *path_error;
    OvStoragePlugin_ListRequest request;
    ovc_file_test_completion completion;
    OvStoragePlugin_ListPage *page;
    const OvStoragePlugin_Str *listed;
    static const char suffix[] = ".ovstorage-meta/";

    directory_address = ovc_file_join_address(root_url, "meta-holder", true);
    ovc_file_test_create_directory(handle, directory_address);
    path_error = NULL;
    directory_path = ovc_file_url_to_path(directory_address, &path_error);
    assert(path_error == NULL);
    metadata_directory = ovc_path_join(directory_path, ".ovstorage-meta");
    assert(metadata_directory != NULL);
    assert(ovc_file_native_mkdir(metadata_directory) == 0);

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.prefix = ovc_file_owned_string(directory_address);
    request.options.struct_size = sizeof(request.options);
    ovc_file_test_completion_init(&completion);
    handle->vtable->list(handle->state,
                         &request,
                         NULL,
                         ovc_file_test_complete,
                         &completion);
    ovc_file_test_expect_success("list metadata-holder", &completion);
    page = (OvStoragePlugin_ListPage *)completion.result;
    assert(page != NULL);
    assert(page->items.len == 1);
    assert(page->items.ptr[0].kind == OvStoragePlugin_ObjectKindV1_Directory);
    listed = &page->items.ptr[0].address;
    assert(listed->len >= sizeof(suffix) - 1);
    assert(memcmp(listed->ptr + listed->len - (sizeof(suffix) - 1),
                  suffix,
                  sizeof(suffix) - 1) == 0);
    ovc_file_object_info_clear(&page->items.ptr[0]);
    ovc_abi_free(page->items.ptr);
    if (page->next_page_token.present) {
        ovc_file_str_clear(&page->next_page_token.value);
    }
    ovc_abi_free(page);

    ovc_file_test_delete_directory_refused(
        handle,
        directory_address,
        OvStoragePlugin_ErrorCode_DirectoryNotEmpty);

    assert(ovc_file_native_rmdir(metadata_directory) == 0);
    ovc_file_test_delete_directory(handle, directory_address);
    free(metadata_directory);
    free(directory_path);
    free(directory_address);
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
    assert(!page->items.ptr[0].versioned_address.present);
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
    assert(!latest->versioned_address.present);
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
    /* The file backend versions nothing, so no answer carries a pin. */
    assert(!result->versioned_address.present);
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
        assert(!result->info.versioned_address.present);
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

static FILE *ovc_file_test_fopen(const char *path, const char *mode)
{
#if defined(_WIN32)
    FILE *file = NULL;

    if (fopen_s(&file, path, mode) != 0) {
        return NULL;
    }
    return file;
#else
    return fopen(path, mode);
#endif
}

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

    /* `.ovstorage-meta` is ordinary content on this backend: enumeration
     * lists it and URL resolution addresses it like any other name. */
    assert(!ovc_file_is_internal_entry(".ovstorage-meta"));
    assert(!ovc_file_path_is_internal("/root/.ovstorage-meta/x.meta"));

    /* The predicate that may unlink agrees with the Rust host's removal on
     * every row: no leading segment and an uppercase suffix are objects on
     * one host or the other and survive both removals; every clearable name
     * is also hidden. */
    assert(!ovc_file_is_clearable_staging_temp_name(".2024.01.15.tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name(".1.2.3.tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name("..1.2.3.tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name(".report.1.2.3.TMP"));
    assert(!ovc_file_is_clearable_staging_temp_name(".report.1.2.3.Tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name(
        ".ovstorage-stage.1.2.3.TMP"));
    assert(ovc_file_is_clearable_staging_temp_name(".report.1.2.3.tmp"));
    assert(ovc_file_is_clearable_staging_temp_name(
        ".ovstorage-stage.1.2.3.tmp"));
    assert(ovc_file_is_clearable_staging_temp_name(".a.b.1.2.3.tmp"));
    assert(ovc_file_is_clearable_staging_temp_name(".1.2.3.4.tmp"));
    assert(ovc_file_is_clearable_staging_temp_name(
        ".12345.123456789.4242.7.tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name(".report.1.2.tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name(".report..2.3.tmp"));
    assert(!ovc_file_is_clearable_staging_temp_name(".report.1.2.3.txt"));
    assert(!ovc_file_is_clearable_staging_temp_name("report.1.2.3.tmp"));
    /* A non-UTF-8 leading segment is no temp to the Rust host, which serves
     * it as an object; the removal must not call it clearable. */
    assert(!ovc_file_is_clearable_staging_temp_name(".\xFF.1.2.3.tmp"));
    assert(ovc_file_is_clearable_staging_temp_name(".r\xC3\xA9port.1.2.3.tmp"));
    assert(ovc_file_is_internal_entry(".report.1.2.3.tmp"));
    assert(ovc_file_is_internal_entry(".ovstorage-stage.1.2.3.tmp"));

    /* A lock that cannot answer is never a raw error: an NFS flock emulation
     * refusing a read-only descriptor with EBADF reads as unclassifiable,
     * and contention reads as held. */
    assert(ovc_file_lock_unsupported(ENOLCK));
    assert(ovc_file_lock_unsupported(EBADF));
    assert(!ovc_file_lock_unsupported(EACCES));
    assert(ovc_file_lock_is_held(EWOULDBLOCK));
    assert(!ovc_file_lock_is_held(EBADF));

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
    ovc_file_test_watch_directory_child(&handle, root_url);
    ovc_file_test_watch_cancel(&handle, root_url);
    assert(g_ovc_file_watch_test_drop_count == 7);
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

    ovc_file_test_no_user_metadata_declared();
    ovc_file_test_write_empty_user_metadata(&handle, root_url);
    ovc_file_test_write_message_only(&handle, root_url);
    {
        char *outside_directory;
        char *outside_address;

        outside_directory = ovc_path_join(directory, "..");
        assert(outside_directory != NULL);
        outside_address = ovc_file_path_to_url(outside_directory, true);
        assert(outside_address != NULL);
        ovc_file_test_write_user_metadata_refused(&handle,
                                                  root_url,
                                                  outside_address);
        ovc_file_test_update_metadata_unsupported(&handle,
                                                  first_address,
                                                  root_url,
                                                  outside_address);
        free(outside_address);
        free(outside_directory);
    }
    ovc_file_test_metadata_directory_is_ordinary(&handle, root_url);

    {
        char long_name[131];
        char *long_address;

        /* A 130-byte basename sits well inside NAME_MAX but past half of
         * it: write, stat, and delete of a long-named object must succeed
         * with only the object's own name and its fixed-size staging temp
         * touching the directory. */
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
        char *orphan_leftover;
        ovc_file orphan_file;
        ovc_file_stat orphan_info;

        /* A `.ovstorage-meta` tree left on disk by another tool is ordinary
         * content: delete_directory neither sweeps it nor looks inside it,
         * so the enclosing directory is DirectoryNotEmpty until the tree is
         * removed out of band. */
        orphan_directory_address = ovc_file_join_address(root_url,
                                                         "orphan",
                                                         true);
        ovc_file_test_create_directory(&handle, orphan_directory_address);
        path_error = NULL;
        orphan_directory_path = ovc_file_url_to_path(
            orphan_directory_address, &path_error);
        assert(path_error == NULL);
        orphan_metadata_directory = ovc_path_join(orphan_directory_path,
                                                  ".ovstorage-meta");
        assert(orphan_metadata_directory != NULL);
        assert(ovc_file_native_mkdir(orphan_metadata_directory) == 0);
        orphan_leftover = ovc_path_join(orphan_metadata_directory,
                                       "6f727068616e2e747874.meta");
        assert(orphan_leftover != NULL);
        orphan_file = ovc_file_native_create_new(orphan_leftover);
        assert(orphan_file != OVC_INVALID_FILE);
        assert(ovc_file_native_close(orphan_file) == 0);

        ovc_file_test_delete_directory_refused(
            &handle,
            orphan_directory_address,
            OvStoragePlugin_ErrorCode_DirectoryNotEmpty);

        /* The refusal leaves the tree exactly as planted. */
        assert(ovc_file_native_stat_path(orphan_leftover, &orphan_info) == 0);
        assert(orphan_info.is_regular);

        assert(ovc_file_native_unlink(orphan_leftover) == 0);
        assert(ovc_file_native_rmdir(orphan_metadata_directory) == 0);
        ovc_file_test_delete_directory(&handle, orphan_directory_address);
        free(orphan_leftover);
        free(orphan_metadata_directory);
        free(orphan_directory_path);
        free(orphan_directory_address);
    }

    {
        char *staging_directory_address;
        char *staging_directory_path;
        char *staging_child;
        char *staging_temp;
        ovc_file staging_handle;
        ovc_file_stat staging_info;

        /* A directory holding an atomic-write staging temp is decided by
         * the lock the temp's writer holds.  Held: the write is in flight,
         * the kernel counts the entry, and the refusal must be reported as
         * DirectoryNotEmpty with the temp left in place.  Free: the writer
         * died without unwinding, and the removal clears the temp and
         * deletes the directory.
         *
         * The temp is planted directly rather than driven from a parked
         * concurrent write: what these cases pin is the verdict on a name
         * production generates, and ovc_file_temp_sibling is the generator
         * itself, so the name on disk is the real one; the lock the test
         * holds is the one ovc_file_create_temp takes. */
        staging_directory_address = ovc_file_join_address(root_url,
                                                          "staging",
                                                          true);
        ovc_file_test_create_directory(&handle, staging_directory_address);
        path_error = NULL;
        staging_directory_path = ovc_file_url_to_path(
            staging_directory_address, &path_error);
        assert(path_error == NULL);
        staging_child = ovc_path_join(staging_directory_path, "child.bin");
        assert(staging_child != NULL);
        staging_temp = ovc_file_temp_sibling(staging_child, 0);
        assert(staging_temp != NULL);
        staging_handle = ovc_file_native_create_new(staging_temp);
        assert(staging_handle != OVC_INVALID_FILE);
        assert(ovc_file_native_lock_exclusive_nonblocking(staging_handle) ==
               0);

        ovc_file_test_delete_directory_refused(
            &handle,
            staging_directory_address,
            OvStoragePlugin_ErrorCode_DirectoryNotEmpty);

        /* The refused removal must leave the live temp in place: a removal
         * that read the temp as an orphan would have cleared it already. */
        assert(ovc_file_native_stat_path(staging_temp, &staging_info) == 0);
        assert(staging_info.is_regular);

        /* Closing the handle releases the lock, which is what a writer's
         * death does; the temp is an orphan and the directory deletes,
         * taking the temp with it. */
        assert(ovc_file_native_close(staging_handle) == 0);
        ovc_file_test_delete_directory(&handle, staging_directory_address);
        assert(ovc_file_native_stat_path(staging_temp, &staging_info) != 0);
        assert(ovc_file_native_stat_path(staging_directory_path,
                                         &staging_info) != 0);

        /* The same orphan planted without ever taking the lock: the temp is
         * the removal's only occupant, and the directory still deletes. */
        ovc_file_test_create_directory(&handle, staging_directory_address);
        staging_handle = ovc_file_native_create_new(staging_temp);
        assert(staging_handle != OVC_INVALID_FILE);
        assert(ovc_file_native_close(staging_handle) == 0);
        ovc_file_test_delete_directory(&handle, staging_directory_address);
        assert(ovc_file_native_stat_path(staging_temp, &staging_info) != 0);

        /* A directory wearing the exact staging shape is not the backend's
         * temp: refused as DirectoryNotEmpty, not surfaced as the raw errno
         * its unlink would produce, and left standing. */
        ovc_file_test_create_directory(&handle, staging_directory_address);
        assert(ovc_file_native_mkdir(staging_temp) == 0);
        ovc_file_test_delete_directory_refused(
            &handle,
            staging_directory_address,
            OvStoragePlugin_ErrorCode_DirectoryNotEmpty);
        assert(ovc_file_native_stat_path(staging_temp, &staging_info) == 0);
        assert(staging_info.is_directory);
        assert(ovc_file_native_rmdir(staging_temp) == 0);

        /* A name the Rust host hides but this host serves as an object: it
         * has no leading segment, so the removal must not call it a staging
         * temp, and the honest DirectoryNotEmpty stands. */
        {
            char *object_name;
            ovc_file object_handle;

            object_name = ovc_path_join(staging_directory_path,
                                        ".2024.01.15.tmp");
            assert(object_name != NULL);
            object_handle = ovc_file_native_create_new(object_name);
            assert(object_handle != OVC_INVALID_FILE);
            assert(ovc_file_native_close(object_handle) == 0);
            ovc_file_test_delete_directory_refused(
                &handle,
                staging_directory_address,
                OvStoragePlugin_ErrorCode_DirectoryNotEmpty);
            assert(ovc_file_native_stat_path(object_name, &staging_info) == 0);
            assert(ovc_file_native_unlink(object_name) == 0);
            free(object_name);
        }

        /* The writer side: ovc_file_create_temp hands back a handle that
         * holds the staging lock, so a probe on a second handle reads it as
         * held and delete_directory refuses naming the in-flight write; the
         * handle closing is the writer going away, and the removal clears
         * the temp.  Pins that a future edit restoring a pre-rename close
         * would be caught by the C suite, not only the Rust one. */
        {
            char *live_temp;
            ovc_file writer_handle;
            ovc_file probe_handle;
            OvStoragePlugin_Error *create_error;

            create_error = NULL;
            live_temp = ovc_file_create_temp(staging_child,
                                             &writer_handle,
                                             &create_error);
            assert(live_temp != NULL);
            assert(create_error == NULL);
            assert(ovc_file_is_clearable_staging_temp_name(
                ovc_file_test_basename(live_temp)));
            probe_handle = ovc_file_native_open_probe(live_temp,
                                                      OVC_FILE_PROBE_READ);
            assert(probe_handle != OVC_INVALID_FILE);
            assert(ovc_file_native_lock_exclusive_nonblocking(probe_handle) ==
                   -1);
            assert(ovc_file_lock_is_held(errno));
            assert(ovc_file_native_close(probe_handle) == 0);

            ovc_file_test_delete_directory_refused_naming(
                &handle,
                staging_directory_address,
                OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                "in-flight write");
            assert(ovc_file_native_stat_path(live_temp, &staging_info) == 0);

            assert(ovc_file_native_close(writer_handle) == 0);
            ovc_file_test_delete_directory(&handle, staging_directory_address);
            assert(ovc_file_native_stat_path(live_temp, &staging_info) != 0);
            free(live_temp);
            ovc_file_test_create_directory(&handle, staging_directory_address);
        }

        /* Helper level: every temp is probed before any is removed, so an
         * unlocked orphan listed before a live temp survives the refusal in
         * either order, where an eager loop would have unlinked it on the
         * way to the live one. */
        {
            char *orphan_child;
            char *orphan_temp;
            char *live_child;
            char *live_temp;
            ovc_file orphan_handle;
            ovc_file live_handle;
            ovc_file_name_list temps;
            OvStoragePlugin_Error *sweep_error;
            unsigned int order;

            orphan_child = ovc_path_join(staging_directory_path, "orphan.bin");
            live_child = ovc_path_join(staging_directory_path, "live.bin");
            assert(orphan_child != NULL && live_child != NULL);
            orphan_temp = ovc_file_temp_sibling(orphan_child, 1);
            live_temp = ovc_file_temp_sibling(live_child, 2);
            assert(orphan_temp != NULL && live_temp != NULL);
            orphan_handle = ovc_file_native_create_new(orphan_temp);
            assert(orphan_handle != OVC_INVALID_FILE);
            assert(ovc_file_native_close(orphan_handle) == 0);
            live_handle = ovc_file_native_create_new(live_temp);
            assert(live_handle != OVC_INVALID_FILE);
            assert(ovc_file_native_lock_exclusive_nonblocking(live_handle) == 0);

            for (order = 0; order < 2; ++order) {
                const char *first;
                const char *second;

                first = order == 0 ? orphan_temp : live_temp;
                second = order == 0 ? live_temp : orphan_temp;
                memset(&temps, 0, sizeof(temps));
                assert(ovc_file_name_list_push(
                           &temps, ovc_file_test_basename(first)) == 0);
                assert(ovc_file_name_list_push(
                           &temps, ovc_file_test_basename(second)) == 0);
                sweep_error = ovc_file_directory_clear_orphaned_staging_temps(
                    staging_directory_path, &temps);
                assert(sweep_error != NULL);
                assert(sweep_error->code ==
                       OvStoragePlugin_ErrorCode_DirectoryNotEmpty);
                ovc_file_error_destroy(sweep_error);
                ovc_file_name_list_free(&temps);
                assert(ovc_file_native_stat_path(orphan_temp, &staging_info) == 0);
                assert(ovc_file_native_stat_path(live_temp, &staging_info) == 0);
            }

            /* A temp the scan saw but the probe no longer finds refuses the
             * sweep as a changed directory, clearing nothing. */
            memset(&temps, 0, sizeof(temps));
            assert(ovc_file_name_list_push(
                       &temps, ovc_file_test_basename(orphan_temp)) == 0);
            assert(ovc_file_name_list_push(&temps,
                                           ".vanished.1.2.3.tmp") == 0);
            sweep_error = ovc_file_directory_clear_orphaned_staging_temps(
                staging_directory_path, &temps);
            assert(sweep_error != NULL);
            assert(sweep_error->code ==
                   OvStoragePlugin_ErrorCode_DirectoryNotEmpty);
            ovc_file_error_destroy(sweep_error);
            ovc_file_name_list_free(&temps);
            assert(ovc_file_native_stat_path(orphan_temp, &staging_info) == 0);

            assert(ovc_file_native_close(live_handle) == 0);
            memset(&temps, 0, sizeof(temps));
            assert(ovc_file_name_list_push(
                       &temps, ovc_file_test_basename(orphan_temp)) == 0);
            assert(ovc_file_name_list_push(
                       &temps, ovc_file_test_basename(live_temp)) == 0);
            sweep_error = ovc_file_directory_clear_orphaned_staging_temps(
                staging_directory_path, &temps);
            assert(sweep_error == NULL);
            ovc_file_name_list_free(&temps);
            assert(ovc_file_native_stat_path(orphan_temp, &staging_info) != 0);
            assert(ovc_file_native_stat_path(live_temp, &staging_info) != 0);
            free(live_temp);
            free(orphan_temp);
            free(live_child);
            free(orphan_child);
        }

#if !defined(_WIN32)
        /* A symlink or a fifo wearing the staging name is classified without
         * being followed or read: the link's target survives, the fifo never
         * holds the probe, and both refuse the removal. */
        {
            char *link_target;
            ovc_file target_handle;

            link_target = ovc_path_join(directory, "link-target.bin");
            assert(link_target != NULL);
            target_handle = ovc_file_native_create_new(link_target);
            assert(target_handle != OVC_INVALID_FILE);
            assert(ovc_file_native_close(target_handle) == 0);
            assert(symlink(link_target, staging_temp) == 0);
            ovc_file_test_delete_directory_refused_naming(
                &handle,
                staging_directory_address,
                OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                "not a regular file");
            assert(ovc_file_native_stat_path(link_target, &staging_info) == 0);
            assert(ovc_file_native_unlink(staging_temp) == 0);
            assert(ovc_file_native_unlink(link_target) == 0);
            free(link_target);

            assert(mkfifo(staging_temp, 0600) == 0);
            ovc_file_test_delete_directory_refused_naming(
                &handle,
                staging_directory_address,
                OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                "not a regular file");
            assert(ovc_file_native_unlink(staging_temp) == 0);

            /* A fifo whose mode denies read, and a socket: neither can be
             * opened as a file, and both must still read as not a regular
             * file rather than as the retryable errno the open gives. */
            assert(mkfifo(staging_temp, 0200) == 0);
            ovc_file_test_delete_directory_refused_naming(
                &handle,
                staging_directory_address,
                OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                "not a regular file");
            assert(ovc_file_native_unlink(staging_temp) == 0);
            {
                char *socket_path;
                struct sockaddr_un address;
                int socket_fd;

                socket_path = ovc_path_join(staging_directory_path,
                                            ".s.1.2.3.tmp");
                assert(socket_path != NULL);
                assert(ovc_file_is_clearable_staging_temp_name(".s.1.2.3.tmp"));
                socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
                assert(socket_fd >= 0);
                memset(&address, 0, sizeof(address));
                address.sun_family = AF_UNIX;
                if (strlen(socket_path) < sizeof(address.sun_path)) {
                    memcpy(address.sun_path, socket_path, strlen(socket_path));
                    assert(bind(socket_fd, (struct sockaddr *)&address,
                                sizeof(address)) == 0);
                    ovc_file_test_delete_directory_refused_naming(
                        &handle,
                        staging_directory_address,
                        OvStoragePlugin_ErrorCode_DirectoryNotEmpty,
                        "not a regular file");
                    assert(ovc_file_native_unlink(socket_path) == 0);
                }
                assert(close(socket_fd) == 0);
                free(socket_path);
            }

            /* A regular file whose leading segment is not UTF-8 is an object
             * on the Rust host; this removal must leave it standing. */
            {
                char *foreign_name;
                ovc_file foreign_handle;

                foreign_name = ovc_path_join(staging_directory_path,
                                             ".\xFF.1.2.3.tmp");
                assert(foreign_name != NULL);
                foreign_handle = ovc_file_native_create_new(foreign_name);
                assert(foreign_handle != OVC_INVALID_FILE);
                assert(ovc_file_native_close(foreign_handle) == 0);
                ovc_file_test_delete_directory_refused(
                    &handle,
                    staging_directory_address,
                    OvStoragePlugin_ErrorCode_DirectoryNotEmpty);
                assert(ovc_file_native_stat_path(foreign_name, &staging_info) == 0);
                assert(ovc_file_native_unlink(foreign_name) == 0);
                free(foreign_name);
            }
        }

        /* A copy staged from a write-only source carries that mode; the
         * probe falls back to a write-only open and the orphan still clears.
         * Root reads anything, so the case is checked for its premise. */
        {
            ovc_file mode_handle;

            mode_handle = ovc_file_native_create_new(staging_temp);
            assert(mode_handle != OVC_INVALID_FILE);
            assert(ovc_file_native_close(mode_handle) == 0);
            assert(chmod(staging_temp, 0200) == 0);
            mode_handle = ovc_file_native_open_read(staging_temp);
            if (mode_handle == OVC_INVALID_FILE) {
                ovc_file_test_delete_directory(&handle,
                                               staging_directory_address);
                assert(ovc_file_native_stat_path(staging_temp,
                                                 &staging_info) != 0);
                ovc_file_test_create_directory(&handle,
                                               staging_directory_address);
            } else {
                assert(ovc_file_native_close(mode_handle) == 0);
                assert(ovc_file_native_unlink(staging_temp) == 0);
            }
        }
#endif

        /* The sweep holds one descriptor at a time, so many orphans clear
         * in one removal; under a reduced descriptor limit this is the case
         * that discriminates. */
        {
            unsigned int index;

            for (index = 0; index < 600; ++index) {
                char child_name[64];
                char *many_child;
                char *many_temp;
                ovc_file many_handle;

                (void)snprintf(child_name, sizeof(child_name),
                               "child-%u.bin", index);
                many_child = ovc_path_join(staging_directory_path, child_name);
                assert(many_child != NULL);
                many_temp = ovc_file_temp_sibling(many_child, index);
                assert(many_temp != NULL);
                many_handle = ovc_file_native_create_new(many_temp);
                assert(many_handle != OVC_INVALID_FILE);
                assert(ovc_file_native_close(many_handle) == 0);
                free(many_temp);
                free(many_child);
            }
        }
        ovc_file_test_delete_directory(&handle, staging_directory_address);
        assert(ovc_file_native_stat_path(staging_directory_path,
                                         &staging_info) != 0);
        free(staging_temp);
        free(staging_child);
        free(staging_directory_path);
        free(staging_directory_address);
    }

#if defined(_WIN32)
    {
        char *real_target_address;
        char *real_target_path;
        char *real_target_sentinel;
        char *vlink_address;
        char *vlink_path;
        wchar_t *real_target_wide;
        wchar_t *vlink_wide;
        DWORD link_attributes;
        ovc_file_stat target_info;

        /* Exercise the Win32 no-follow classifier, not just its tag helper:
         * delete_directory must open the directory symlink itself, identify
         * its name-surrogate tag, and refuse it without scanning or removing
         * anything in the target.  The Windows CI runner is elevated; the
         * unprivileged flag also supports non-elevated development machines
         * with Developer Mode enabled. */
        real_target_address = ovc_file_join_address(root_url,
                                                    "vlink-target",
                                                    true);
        ovc_file_test_create_directory(&handle, real_target_address);
        path_error = NULL;
        real_target_path = ovc_file_url_to_path(real_target_address,
                                                &path_error);
        assert(path_error == NULL);
        real_target_sentinel = ovc_path_join(real_target_path, "sentinel");
        assert(real_target_sentinel != NULL);
        assert(ovc_file_native_mkdir(real_target_sentinel) == 0);

        vlink_address = ovc_file_join_address(root_url, "vlink", true);
        path_error = NULL;
        vlink_path = ovc_file_url_to_path(vlink_address, &path_error);
        assert(path_error == NULL);
        real_target_wide = ovc_file_utf8_to_wide(real_target_path);
        vlink_wide = ovc_file_utf8_to_wide(vlink_path);
        assert(real_target_wide != NULL);
        assert(vlink_wide != NULL);
        assert(CreateSymbolicLinkW(
            vlink_wide,
            real_target_wide,
            SYMBOLIC_LINK_FLAG_DIRECTORY |
                SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE));

        ovc_file_test_delete_directory_refused(
            &handle,
            vlink_address,
            OvStoragePlugin_ErrorCode_InvalidArgument);

        link_attributes = GetFileAttributesW(vlink_wide);
        assert(link_attributes != INVALID_FILE_ATTRIBUTES);
        assert((link_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        assert((link_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
        assert(ovc_file_native_stat_path(real_target_path, &target_info) == 0);
        assert(target_info.is_directory);
        assert(ovc_file_native_stat_path(real_target_sentinel,
                                         &target_info) == 0);
        assert(target_info.is_directory);

        assert(RemoveDirectoryW(vlink_wide));
        assert(ovc_file_native_rmdir(real_target_sentinel) == 0);
        ovc_file_test_delete_directory(&handle, real_target_address);
        free(vlink_wide);
        free(real_target_wide);
        free(vlink_path);
        free(vlink_address);
        free(real_target_sentinel);
        free(real_target_path);
        free(real_target_address);
    }
#endif

#if !defined(_WIN32)
    {
        char *real_target_address;
        char *real_target_path;
        char *real_target_sentinel;
        char *vlink_address;
        char *vlink_path;
        struct stat link_info;
        struct stat target_info;

        /* A link at the addressed path is operator-managed state, so
         * delete_directory must refuse it before scanning through its
         * target; the sentinel inside the target proves nothing was
         * touched. */
        real_target_address = ovc_file_join_address(root_url,
                                                    "vlink-target",
                                                    true);
        ovc_file_test_create_directory(&handle, real_target_address);
        path_error = NULL;
        real_target_path = ovc_file_url_to_path(real_target_address,
                                                &path_error);
        assert(path_error == NULL);
        real_target_sentinel = ovc_path_join(real_target_path, "sentinel");
        assert(real_target_sentinel != NULL);
        assert(ovc_file_native_mkdir(real_target_sentinel) == 0);

        vlink_address = ovc_file_join_address(root_url, "vlink", true);
        path_error = NULL;
        vlink_path = ovc_file_url_to_path(vlink_address, &path_error);
        assert(path_error == NULL);
        assert(symlink(real_target_path, vlink_path) == 0);

        ovc_file_test_delete_directory_refused(
            &handle,
            vlink_address,
            OvStoragePlugin_ErrorCode_InvalidArgument);

        assert(lstat(vlink_path, &link_info) == 0);
        assert(S_ISLNK(link_info.st_mode));
        assert(stat(real_target_path, &target_info) == 0);
        assert(S_ISDIR(target_info.st_mode));
        assert(stat(real_target_sentinel, &target_info) == 0);
        assert(S_ISDIR(target_info.st_mode));

        assert(unlink(vlink_path) == 0);
        assert(rmdir(real_target_sentinel) == 0);
        ovc_file_test_delete_directory(&handle, real_target_address);
        free(vlink_path);
        free(vlink_address);
        free(real_target_sentinel);
        free(real_target_path);
        free(real_target_address);
    }

    {
        char *linked_directory_address;
        char *linked_directory_path;
        char *linked_metadata_directory;
        char *outside_directory;
        char *outside_canary;
        ovc_file canary_handle;
        struct stat canary_info;

        /* A symlink named `.ovstorage-meta` is ordinary content like any
         * other entry: delete_directory reports DirectoryNotEmpty and never
         * opens the link.  Plant an outside directory holding a canary,
         * point the link at it, and assert the refusal leaves the link, the
         * canary, and its directory untouched. */
        linked_directory_address = ovc_file_join_address(root_url,
                                                         "linked-meta",
                                                         true);
        ovc_file_test_create_directory(&handle, linked_directory_address);
        path_error = NULL;
        linked_directory_path = ovc_file_url_to_path(linked_directory_address,
                                                     &path_error);
        assert(path_error == NULL);
        linked_metadata_directory = ovc_path_join(linked_directory_path,
                                                  ".ovstorage-meta");
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

        ovc_file_test_delete_directory_refused(
            &handle,
            linked_directory_address,
            OvStoragePlugin_ErrorCode_DirectoryNotEmpty);

        /* The link, its target, and the canary are all untouched. */
        assert(stat(outside_canary, &canary_info) == 0);
        assert(lstat(linked_metadata_directory, &canary_info) == 0);
        assert(S_ISLNK(canary_info.st_mode));

        assert(unlink(linked_metadata_directory) == 0);
        ovc_file_test_delete_directory(&handle, linked_directory_address);
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

    /* Ask #2: `stat` on a dangling symlink must report the link itself
     * (2.x's `native::stat` fell back to `lstat` for exactly this), not
     * `NotFound` -- the link is a real, present object even though its
     * target is not. */
    {
        char *dangling_address;
        char *dangling_path;
        OvStoragePlugin_StatRequest request;
        ovc_file_test_completion completion;
        OvStoragePlugin_ObjectInfo *result;

        dangling_address = ovc_file_join_address(root_url,
                                                  "dangling-stat-link",
                                                  false);
        path_error = NULL;
        dangling_path = ovc_file_url_to_path(dangling_address, &path_error);
        assert(path_error == NULL);
        assert(symlink("missing-stat-target", dangling_path) == 0);

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.address = ovc_file_owned_string(dangling_address);
        request.options.struct_size = sizeof(request.options);
        ovc_file_test_completion_init(&completion);
        handle.vtable->stat(handle.state,
                            &request,
                            NULL,
                            ovc_file_test_complete,
                            &completion);
        ovc_file_test_expect_success("stat dangling link", &completion);
        result = (OvStoragePlugin_ObjectInfo *)completion.result;
        assert(result != NULL);
        /* `OvStoragePlugin_ObjectKindV1` has no dedicated symlink kind, so
         * the fallback's answer is classified `File` like any other
         * non-directory -- the meaningful check is that this is the
         * *link's own* lstat, not a failed follow onto the (absent)
         * target: its reported size is the length of the stored target
         * path string ("missing-stat-target", 20 bytes), which no real
         * target file at this address could coincidentally produce, since
         * none exists. */
        assert(result->size.present);
        assert(result->size.value == strlen("missing-stat-target"));
        ovc_file_object_info_clear(result);
        ovc_abi_free(result);

        assert(unlink(dangling_path) == 0);
        free(dangling_path);
        free(dangling_address);
    }

    /* Ask #3: a dangling symlink at a copy/rename destination occupies its
     * directory entry -- `no_overwrite` (`IfDestExistsTag_Fail`) must refuse
     * to replace it (AlreadyExists), not treat the follow-only ENOENT as
     * "nothing here" and let the rename/copy clobber the link, and
     * `if_match_etag` must report a mismatch (PreconditionFailed) rather
     * than NotFound. */
    {
        char *source_address;
        char *source_path;
        char *dangling_address;
        char *dangling_path;
        OvStoragePlugin_CopyRequest request;
        ovc_file_test_completion completion;
        char link_target[64];
        ssize_t link_length;

        source_address =
            ovc_file_join_address(root_url, "dangling-precondition-source.txt", false);
        path_error = NULL;
        source_path = ovc_file_url_to_path(source_address, &path_error);
        assert(path_error == NULL);
        {
            FILE *f = fopen(source_path, "wb");
            assert(f != NULL);
            assert(fwrite("payload", 1, 7, f) == 7);
            assert(fclose(f) == 0);
        }

        dangling_address =
            ovc_file_join_address(root_url, "dangling-precondition-dest", false);
        path_error = NULL;
        dangling_path = ovc_file_url_to_path(dangling_address, &path_error);
        assert(path_error == NULL);
        assert(symlink("missing-precondition-target", dangling_path) == 0);

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.source = ovc_file_owned_string(source_address);
        request.destination = ovc_file_owned_string(dangling_address);
        request.options.struct_size = sizeof(request.options);
        request.options.if_dest.tag = OvStoragePlugin_IfDestExistsTag_Fail;
        ovc_file_test_completion_init(&completion);
        handle.vtable->copy(handle.state,
                            &request,
                            NULL,
                            ovc_file_test_complete,
                            &completion);
        ovc_file_test_completion_wait(&completion);
        if (completion.status != OvStoragePlugin_FFI_STATUS_ERR ||
            completion.error == NULL ||
            completion.error->code != OvStoragePlugin_ErrorCode_AlreadyExists) {
            (void)fprintf(stderr,
                          "no_overwrite copy onto a dangling destination "
                          "link: status=%d code=%d (expected refusal with "
                          "AlreadyExists)\n",
                          (int)completion.status,
                          completion.error == NULL
                              ? -1
                              : (int)completion.error->code);
            (void)fflush(stderr);
        }
        assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
        assert(completion.error != NULL);
        assert(completion.error->code == OvStoragePlugin_ErrorCode_AlreadyExists);
        assert(completion.result == NULL);
        ovc_file_error_destroy(completion.error);

        /* The link itself, not a real file, must still occupy the
         * destination, and it must still point at its original target. */
        errno = 0;
        link_length = readlink(dangling_path, link_target, sizeof(link_target) - 1);
        assert(link_length > 0);
        link_target[link_length] = '\0';
        assert(strcmp(link_target, "missing-precondition-target") == 0);

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.source = ovc_file_owned_string(source_address);
        request.destination = ovc_file_owned_string(dangling_address);
        request.options.struct_size = sizeof(request.options);
        request.options.if_dest.tag =
            OvStoragePlugin_IfDestExistsTag_MatchEtag;
        request.options.if_dest.match_etag.etag =
            ovc_file_owned_string("stale-etag");
        ovc_file_test_completion_init(&completion);
        handle.vtable->copy(handle.state,
                            &request,
                            NULL,
                            ovc_file_test_complete,
                            &completion);
        ovc_file_test_completion_wait(&completion);
        if (completion.status != OvStoragePlugin_FFI_STATUS_ERR ||
            completion.error == NULL ||
            completion.error->code !=
                OvStoragePlugin_ErrorCode_PreconditionFailed) {
            (void)fprintf(stderr,
                          "if_match_etag copy onto a dangling destination "
                          "link: status=%d code=%d (expected refusal with "
                          "PreconditionFailed)\n",
                          (int)completion.status,
                          completion.error == NULL
                              ? -1
                              : (int)completion.error->code);
            (void)fflush(stderr);
        }
        assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
        assert(completion.error != NULL);
        assert(completion.error->code ==
               OvStoragePlugin_ErrorCode_PreconditionFailed);
        assert(completion.result == NULL);
        ovc_file_error_destroy(completion.error);

        errno = 0;
        link_length = readlink(dangling_path, link_target, sizeof(link_target) - 1);
        assert(link_length > 0);
        link_target[link_length] = '\0';
        assert(strcmp(link_target, "missing-precondition-target") == 0);

        assert(unlink(dangling_path) == 0);
        assert(unlink(source_path) == 0);
        free(dangling_path);
        free(dangling_address);
        free(source_path);
        free(source_address);
    }

    /* Ask #1: a listing must not fail entirely because one entry (here, a
     * dangling symlink) cannot be stat'd -- it should be skipped, and every
     * other entry still reported. */
    {
        char *ok_address;
        char *ok_path;
        char *broken_address;
        char *broken_path;
        OvStoragePlugin_ListRequest request;
        ovc_file_test_completion completion;
        OvStoragePlugin_ListPage *page;
        bool saw_ok_entry;
        size_t index;

        ok_address = ovc_file_join_address(root_url, "listing-ok.txt", false);
        path_error = NULL;
        ok_path = ovc_file_url_to_path(ok_address, &path_error);
        assert(path_error == NULL);
        {
            FILE *f = fopen(ok_path, "wb");
            assert(f != NULL);
            assert(fclose(f) == 0);
        }

        broken_address =
            ovc_file_join_address(root_url, "listing-broken-link", false);
        path_error = NULL;
        broken_path = ovc_file_url_to_path(broken_address, &path_error);
        assert(path_error == NULL);
        assert(symlink("missing-listing-target", broken_path) == 0);

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.prefix = ovc_file_owned_string(root_url);
        request.options.struct_size = sizeof(request.options);
        ovc_file_test_completion_init(&completion);
        handle.vtable->list(handle.state,
                            &request,
                            NULL,
                            ovc_file_test_complete,
                            &completion);
        ovc_file_test_expect_success("list with a dangling entry", &completion);
        page = (OvStoragePlugin_ListPage *)completion.result;
        assert(page != NULL);
        saw_ok_entry = false;
        for (index = 0; index < page->items.len; ++index) {
            char *item_address =
                ovc_file_string_from_slice(&page->items.ptr[index].address);
            assert(item_address != NULL);
            assert(strcmp(item_address, broken_address) != 0);
            if (strcmp(item_address, ok_address) == 0) {
                saw_ok_entry = true;
            }
            free(item_address);
            ovc_file_object_info_clear(&page->items.ptr[index]);
        }
        assert(saw_ok_entry);
        ovc_abi_free(page->items.ptr);
        if (page->next_page_token.present) {
            ovc_file_str_clear(&page->next_page_token.value);
        }
        ovc_abi_free(page);

        assert(unlink(broken_path) == 0);
        assert(unlink(ok_path) == 0);
        free(broken_path);
        free(broken_address);
        free(ok_path);
        free(ok_address);
    }
#endif

#if defined(_WIN32)
    {
        /* The dangling-link fallback (`ovc_file_native_stat_path_or_link`)
         * must perform an exact, no-follow lookup of the requested path and
         * never hand it to a directory-enumeration API: `*` and `?` are
         * wildcards to `FindFirstFileW`, so a literal address containing
         * one could otherwise match and disclose an unrelated sibling
         * file's metadata.  Neither `*` nor `?` can appear in a real
         * Windows filename, so the exact-match first lookup always fails
         * for this address and the fallback always runs; the only question
         * is whether it answers with the wildcard's absence (correct) or
         * with a sibling file's stat (the leak this test guards against). */
        char *victim_address;
        char *victim_path;
        char *probe_address;
        FILE *victim_file;
        OvStoragePlugin_StatRequest request;
        ovc_file_test_completion completion;

        victim_address =
            ovc_file_join_address(root_url, "secret.txt", false);
        path_error = NULL;
        victim_path = ovc_file_url_to_path(victim_address, &path_error);
        assert(path_error == NULL);
        victim_file = ovc_file_test_fopen(victim_path, "wb");
        assert(victim_file != NULL);
        assert(fwrite("s3cr3t-payload", 1, 14, victim_file) == 14);
        assert(fclose(victim_file) == 0);

        probe_address = ovc_file_join_address(root_url, "secret*", false);

        memset(&request, 0, sizeof(request));
        request.struct_size = sizeof(request);
        request.address = ovc_file_owned_string(probe_address);
        request.options.struct_size = sizeof(request.options);
        ovc_file_test_completion_init(&completion);
        handle.vtable->stat(handle.state,
                            &request,
                            NULL,
                            ovc_file_test_complete,
                            &completion);
        ovc_file_test_completion_wait(&completion);
        if (completion.status != OvStoragePlugin_FFI_STATUS_ERR ||
            completion.error == NULL ||
            completion.error->code != OvStoragePlugin_ErrorCode_NotFound) {
            (void)fprintf(stderr,
                          "stat of a literal wildcard address must report "
                          "NotFound, not disclose a sibling file's "
                          "metadata: status=%d code=%d\n",
                          (int)completion.status,
                          completion.error == NULL
                              ? -1
                              : (int)completion.error->code);
            (void)fflush(stderr);
        }
        assert(completion.status == OvStoragePlugin_FFI_STATUS_ERR);
        assert(completion.error != NULL);
        assert(completion.error->code == OvStoragePlugin_ErrorCode_NotFound);
        assert(completion.result == NULL);
        ovc_file_error_destroy(completion.error);

        assert(ovc_file_native_unlink(victim_path) == 0);
        free(victim_path);
        free(victim_address);
        free(probe_address);
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
