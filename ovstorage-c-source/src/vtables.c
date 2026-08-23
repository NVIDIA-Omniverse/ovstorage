/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Default Layer vtables for pure-C plugins.
 */

#include "internal.h"

#include "ovstorage_defaults.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Keep the C99 source promise while still pinning the copied ABI at compile time. */
#define OVC_JOIN_INNER(left, right) left##right
#define OVC_JOIN(left, right) OVC_JOIN_INNER(left, right)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define OVC_STATIC_ASSERT(condition, message) _Static_assert(condition, message)
#else
#define OVC_STATIC_ASSERT(condition, message)                                \
    typedef char OVC_JOIN(ovc_static_assert_at_line_, __LINE__)[(condition) \
                                                                    ? 1    \
                                                                    : -1]
#endif

typedef OvStoragePlugin_LayerVTableV1 ovc_layer_vtable;

OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, struct_size) == 0,
                  "Layer vtable struct_size must be first");
OVC_STATIC_ASSERT(sizeof(((ovc_layer_vtable *)0)->struct_size) ==
                      sizeof(size_t),
                  "Layer vtable struct_size type changed");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, abi_version) == sizeof(size_t),
                  "Layer vtable abi_version moved");
OVC_STATIC_ASSERT(sizeof(((ovc_layer_vtable *)0)->abi_version) ==
                      sizeof(uint32_t),
                  "Layer vtable abi_version type changed");
OVC_STATIC_ASSERT(OVSTORAGE_PLUGIN_ABI_VERSION == 15,
                  "Layer ABI version changed");

/* First operational slot, the update_connection_attributes slot, and the last operational slot. */
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, name) ==
                      offsetof(ovc_layer_vtable, drop) +
                          sizeof(((ovc_layer_vtable *)0)->drop),
                  "Layer vtable first slot moved");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, update_connection_attributes) ==
                      offsetof(ovc_layer_vtable, name) +
                          29 * sizeof(((ovc_layer_vtable *)0)->name),
                  "Layer vtable update_connection_attributes slot moved");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, authenticate_connection) ==
                      offsetof(ovc_layer_vtable,
                               update_connection_attributes) +
                          sizeof(((ovc_layer_vtable *)0)
                                     ->update_connection_attributes),
                  "Layer vtable last operational slot moved");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, _reserved) ==
                      offsetof(ovc_layer_vtable, authenticate_connection) +
                          sizeof(((ovc_layer_vtable *)0)
                                     ->authenticate_connection),
                  "Layer vtable reserved section moved");
OVC_STATIC_ASSERT(sizeof(((ovc_layer_vtable *)0)->_reserved) /
                          sizeof(((ovc_layer_vtable *)0)->_reserved[0]) ==
                      16,
                  "Layer vtable reserved slot count changed");
OVC_STATIC_ASSERT(sizeof(ovc_layer_vtable) ==
                      offsetof(ovc_layer_vtable, _reserved) +
                          sizeof(((ovc_layer_vtable *)0)->_reserved),
                  "Layer vtable gained an unpinned tail");

/* Pin the copied header's concrete layouts on the supported pointer widths. */
#if UINTPTR_MAX == UINT64_MAX
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, drop) == 16,
                  "64-bit Layer vtable prefix changed");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, name) == 24,
                  "64-bit Layer vtable first slot changed");
OVC_STATIC_ASSERT(
    offsetof(ovc_layer_vtable, update_connection_attributes) == 256,
    "64-bit Layer vtable update_connection_attributes slot changed");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, authenticate_connection) == 264,
                  "64-bit Layer vtable last slot changed");
OVC_STATIC_ASSERT(sizeof(ovc_layer_vtable) == 400,
                  "64-bit Layer vtable size changed");
#elif UINTPTR_MAX == UINT32_MAX
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, drop) == 8,
                  "32-bit Layer vtable prefix changed");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, name) == 12,
                  "32-bit Layer vtable first slot changed");
OVC_STATIC_ASSERT(
    offsetof(ovc_layer_vtable, update_connection_attributes) == 128,
    "32-bit Layer vtable update_connection_attributes slot changed");
OVC_STATIC_ASSERT(offsetof(ovc_layer_vtable, authenticate_connection) == 132,
                  "32-bit Layer vtable last slot changed");
OVC_STATIC_ASSERT(sizeof(ovc_layer_vtable) == 200,
                  "32-bit Layer vtable size changed");
#endif

OVC_STATIC_ASSERT(
    sizeof(((OvStoragePlugin_UpdateConnectionAttributesRequest *)0)->patch) ==
        sizeof(OvStoragePlugin_AttributePatch),
    "update_connection_attributes must carry AttributePatch");

/*
 * Every value minted here is adopted by the host and released through the
 * plugin-ABI allocator, so it must come from ovc_abi_alloc (which returns a
 * one-byte block for a zero size).  Allocation failure keeps abort() because
 * no caller has a representable degraded result: name/descriptor/
 * owned_targets return void, the synchronous list_kinds slot treats a NULL
 * Error as success, and OnComplete requires a non-NULL heap Error exactly on
 * failure.
 */
static void *ovc_allocate(size_t byte_count)
{
    void *allocation;

    allocation = ovc_abi_alloc(byte_count);
    if (allocation == NULL) {
        abort();
    }
    return allocation;
}

static OvStoragePlugin_Str ovc_empty_string(void)
{
    OvStoragePlugin_Str value;

    value.ptr = (char *)ovc_allocate(1);
    value.ptr[0] = '\0';
    value.len = 0;
    return value;
}

static OvStoragePlugin_Error *ovc_unsupported_error(void)
{
    static const char message[] = "operation is unsupported by this layer";
    OvStoragePlugin_Error *error;

    error = (OvStoragePlugin_Error *)ovc_allocate(sizeof(*error));
    error->message_len = sizeof(message) - 1;
    error->message_ptr = (char *)ovc_allocate(error->message_len);
    memcpy(error->message_ptr, message, error->message_len);
    error->code = OvStoragePlugin_ErrorCode_Unsupported;
    error->context = NULL;
    error->next_action.present = false;
    return error;
}

static void ovc_complete_unsupported(OvStoragePlugin_OnComplete on_complete,
                                     void *user_data)
{
    on_complete(OvStoragePlugin_FFI_STATUS_ERR,
                NULL,
                ovc_unsupported_error(),
                user_data);
}

/*
 * The default wrapper state is an OvStoragePlugin_LayerHandle. A wrapper with
 * additional state places that handle first, so the unchanged default thunks
 * can still find the child. Such a wrapper replaces drop when it has storage
 * of its own to reclaim.
 */
static OvStoragePlugin_LayerHandle *ovc_inner_handle(void *state)
{
    return (OvStoragePlugin_LayerHandle *)state;
}

/* ------------------------------------------------------------------------- */
/* Unsupported identity and synchronous-introspection slots. */

static void ovc_unsupported_drop(void *state)
{
    (void)state;
}

static void ovc_unsupported_name(void *state, OvStoragePlugin_Str *out)
{
    (void)state;
    *out = ovc_empty_string();
}

static void ovc_unsupported_descriptor(
    void *state,
    OvStoragePlugin_LayerKindDescriptor *out)
{
    (void)state;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    out->layer_type = OvStoragePlugin_LayerType_Backend;
    out->kind = ovc_empty_string();
    out->display_name = ovc_empty_string();
    out->config_schema.ptr =
        (OvStoragePlugin_ConfigField *)ovc_allocate(sizeof(*out->config_schema.ptr));
    out->credential_schema.ptr = (OvStoragePlugin_CredentialField *)ovc_allocate(
        sizeof(*out->credential_schema.ptr));
    out->credential_methods.ptr = (OvStoragePlugin_CredentialMethod *)ovc_allocate(
        sizeof(*out->credential_methods.ptr));
}

static void ovc_unsupported_owned_targets(void *state,
                                          OvStoragePlugin_List_Str *out)
{
    (void)state;
    out->ptr = (OvStoragePlugin_Str *)ovc_allocate(sizeof(*out->ptr));
    out->len = 0;
}

static OvStoragePlugin_Error *ovc_unsupported_list_kinds(
    void *state,
    const OvStoragePlugin_Extensions *extensions,
    OvStoragePlugin_List_LayerKindDescriptor *out)
{
    (void)state;
    (void)extensions;
    (void)out;
    return ovc_unsupported_error();
}

/* A declining slot still OWNS its request, so it releases before completing.
 *
 * This inventory generates both the declining thunks and their vtable
 * initializers. Its count is pinned against the complete operational span, so
 * adding a slot requires adding its request type and release function here.
 *
 * Release runs BEFORE `ovc_complete_unsupported`. Releasing a `Body` whose tag
 * is `Stream` calls the host's `drop_fn`, and a completion callback that has
 * already run may have torn down the state that stream refers to. Three of the
 * slots below take a `WriteRequest`. */
#define OVC_UNSUPPORTED_ASYNC_SLOTS(X)                                      \
    X(root_info_for,                                                        \
      OvStoragePlugin_RootInfoForRequest,                                   \
      ovstorage_plugin_root_info_for_request_release)                       \
    X(list_address_roots,                                                   \
      OvStoragePlugin_ListAddressRootsRequest,                              \
      ovstorage_plugin_list_address_roots_request_release)                  \
    X(list_connections,                                                     \
      OvStoragePlugin_ListConnectionsRequest,                               \
      ovstorage_plugin_list_connections_request_release)                    \
    X(stat,                                                                 \
      OvStoragePlugin_StatRequest,                                          \
      ovstorage_plugin_stat_request_release)                                \
    X(read,                                                                 \
      OvStoragePlugin_ReadRequest,                                          \
      ovstorage_plugin_read_request_release)                                \
    X(write,                                                                \
      OvStoragePlugin_WriteRequest,                                         \
      ovstorage_plugin_write_request_release)                               \
    X(write_stream,                                                         \
      OvStoragePlugin_WriteRequest,                                         \
      ovstorage_plugin_write_request_release)                               \
    X(write_redirect,                                                       \
      OvStoragePlugin_WriteRequest,                                         \
      ovstorage_plugin_write_request_release)                               \
    X(continue_write,                                                       \
      OvStoragePlugin_ContinueWriteRequest,                                 \
      ovstorage_plugin_continue_write_request_release)                      \
    X(delete_,                                                              \
      OvStoragePlugin_DeleteRequest,                                        \
      ovstorage_plugin_delete_request_release)                              \
    X(copy,                                                                 \
      OvStoragePlugin_CopyRequest,                                          \
      ovstorage_plugin_copy_request_release)                                \
    X(rename,                                                               \
      OvStoragePlugin_RenameRequest,                                        \
      ovstorage_plugin_rename_request_release)                              \
    X(update_metadata,                                                      \
      OvStoragePlugin_UpdateMetadataRequest,                                \
      ovstorage_plugin_update_metadata_request_release)                     \
    X(check_access,                                                         \
      OvStoragePlugin_CheckAccessRequest,                                   \
      ovstorage_plugin_check_access_request_release)                        \
    X(materialize,                                                          \
      OvStoragePlugin_ReadRequest,                                          \
      ovstorage_plugin_read_request_release)                                \
    X(list,                                                                 \
      OvStoragePlugin_ListRequest,                                          \
      ovstorage_plugin_list_request_release)                                \
    X(list_versions,                                                        \
      OvStoragePlugin_ListVersionsRequest,                                  \
      ovstorage_plugin_list_versions_request_release)                       \
    X(get_latest_version,                                                   \
      OvStoragePlugin_ReadRequest,                                          \
      ovstorage_plugin_read_request_release)                                \
    X(watch_directory,                                                      \
      OvStoragePlugin_WatchDirectoryRequest,                                \
      ovstorage_plugin_watch_directory_request_release)                     \
    X(create_directory,                                                     \
      OvStoragePlugin_CreateDirectoryRequest,                               \
      ovstorage_plugin_create_directory_request_release)                    \
    X(delete_directory,                                                     \
      OvStoragePlugin_DeleteDirectoryRequest,                               \
      ovstorage_plugin_delete_directory_request_release)                    \
    X(probe,                                                                \
      OvStoragePlugin_LayerConnectionRequest,                               \
      ovstorage_plugin_layer_connection_request_release)                    \
    X(add_connection,                                                       \
      OvStoragePlugin_LayerConnectionRequest,                               \
      ovstorage_plugin_layer_connection_request_release)                    \
    X(remove_connection,                                                    \
      OvStoragePlugin_RemoveConnectionRequest,                              \
      ovstorage_plugin_remove_connection_request_release)                   \
    X(update_connection_credentials,                                        \
      OvStoragePlugin_UpdateConnectionCredentialsRequest,                   \
      ovstorage_plugin_update_connection_credentials_request_release)       \
    X(update_connection_attributes,                                         \
      OvStoragePlugin_UpdateConnectionAttributesRequest,                    \
      ovstorage_plugin_update_connection_attributes_request_release)        \
    X(authenticate_connection,                                              \
      OvStoragePlugin_AuthenticateRequest,                                  \
      ovstorage_plugin_authenticate_request_release)

#define OVC_COUNT_UNSUPPORTED_ASYNC(slot_name, request_type, release_fn) +1
enum {
    OVC_UNSUPPORTED_ASYNC_SLOT_COUNT =
        0 OVC_UNSUPPORTED_ASYNC_SLOTS(OVC_COUNT_UNSUPPORTED_ASYNC)
};
#undef OVC_COUNT_UNSUPPORTED_ASYNC

OVC_STATIC_ASSERT(
    OVC_UNSUPPORTED_ASYNC_SLOT_COUNT + 4 ==
        (offsetof(ovc_layer_vtable, _reserved) -
         offsetof(ovc_layer_vtable, name)) /
            sizeof(((ovc_layer_vtable *)0)->name),
    "unsupported async inventory must cover every operational vtable slot");

#define OVC_DEFINE_UNSUPPORTED_ASYNC(slot_name, request_type, release_fn)     \
    static void OVC_JOIN(ovc_unsupported_, slot_name)(                       \
        void *state,                                                         \
        const request_type *request,                                         \
        const OvStoragePlugin_CancelTokenFFI *cancel,                        \
        OvStoragePlugin_OnComplete on_complete,                              \
        void *user_data)                                                     \
    {                                                                        \
        (void)state;                                                         \
        (void)cancel;                                                        \
        release_fn(request);                                                 \
        ovc_complete_unsupported(on_complete, user_data);                    \
    }

OVC_UNSUPPORTED_ASYNC_SLOTS(OVC_DEFINE_UNSUPPORTED_ASYNC)
#undef OVC_DEFINE_UNSUPPORTED_ASYNC

/* ------------------------------------------------------------------------- */
/* Passthrough slots. */

static void ovc_passthrough_drop(void *state)
{
    OvStoragePlugin_LayerHandle *inner;

    inner = ovc_inner_handle(state);
    if (inner == NULL) {
        return;
    }
    if (inner->state != NULL && inner->vtable != NULL) {
        inner->vtable->drop(inner->state);
        inner->state = NULL;
        inner->vtable = NULL;
    }
    free(inner);
}

static void ovc_passthrough_name(void *state, OvStoragePlugin_Str *out)
{
    OvStoragePlugin_LayerHandle *inner = ovc_inner_handle(state);

    inner->vtable->name(inner->state, out);
}

static void ovc_passthrough_descriptor(
    void *state,
    OvStoragePlugin_LayerKindDescriptor *out)
{
    OvStoragePlugin_LayerHandle *inner = ovc_inner_handle(state);

    inner->vtable->descriptor(inner->state, out);
}

static void ovc_passthrough_owned_targets(void *state,
                                          OvStoragePlugin_List_Str *out)
{
    OvStoragePlugin_LayerHandle *inner = ovc_inner_handle(state);

    inner->vtable->owned_targets(inner->state, out);
}

static OvStoragePlugin_Error *ovc_passthrough_list_kinds(
    void *state,
    const OvStoragePlugin_Extensions *extensions,
    OvStoragePlugin_List_LayerKindDescriptor *out)
{
    OvStoragePlugin_LayerHandle *inner = ovc_inner_handle(state);

    return inner->vtable->list_kinds(inner->state, extensions, out);
}

#define OVC_DEFINE_PASSTHROUGH_ASYNC(function_name, slot_name, request_type)  \
    static void function_name(                                               \
        void *state,                                                         \
        const request_type *request,                                         \
        const OvStoragePlugin_CancelTokenFFI *cancel,                        \
        OvStoragePlugin_OnComplete on_complete,                              \
        void *user_data)                                                     \
    {                                                                        \
        OvStoragePlugin_LayerHandle *inner = ovc_inner_handle(state);        \
                                                                             \
        inner->vtable->slot_name(                                            \
            inner->state, request, cancel, on_complete, user_data);          \
    }

OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_root_info_for,
                             root_info_for,
                             OvStoragePlugin_RootInfoForRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_list_address_roots,
                             list_address_roots,
                             OvStoragePlugin_ListAddressRootsRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_list_connections,
                             list_connections,
                             OvStoragePlugin_ListConnectionsRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_stat,
                             stat,
                             OvStoragePlugin_StatRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_read,
                             read,
                             OvStoragePlugin_ReadRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_write,
                             write,
                             OvStoragePlugin_WriteRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_write_stream,
                             write_stream,
                             OvStoragePlugin_WriteRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_write_redirect,
                             write_redirect,
                             OvStoragePlugin_WriteRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_continue_write,
                             continue_write,
                             OvStoragePlugin_ContinueWriteRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_delete,
                             delete_,
                             OvStoragePlugin_DeleteRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_copy,
                             copy,
                             OvStoragePlugin_CopyRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_rename,
                             rename,
                             OvStoragePlugin_RenameRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_update_metadata,
                             update_metadata,
                             OvStoragePlugin_UpdateMetadataRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_check_access,
                             check_access,
                             OvStoragePlugin_CheckAccessRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_materialize,
                             materialize,
                             OvStoragePlugin_ReadRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_list,
                             list,
                             OvStoragePlugin_ListRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_list_versions,
                             list_versions,
                             OvStoragePlugin_ListVersionsRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_get_latest_version,
                             get_latest_version,
                             OvStoragePlugin_ReadRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_watch_directory,
                             watch_directory,
                             OvStoragePlugin_WatchDirectoryRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_create_directory,
                             create_directory,
                             OvStoragePlugin_CreateDirectoryRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_delete_directory,
                             delete_directory,
                             OvStoragePlugin_DeleteDirectoryRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_probe,
                             probe,
                             OvStoragePlugin_LayerConnectionRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_add_connection,
                             add_connection,
                             OvStoragePlugin_LayerConnectionRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_remove_connection,
                             remove_connection,
                             OvStoragePlugin_RemoveConnectionRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(
    ovc_passthrough_update_connection_credentials,
    update_connection_credentials,
    OvStoragePlugin_UpdateConnectionCredentialsRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(
    ovc_passthrough_update_connection_attributes,
    update_connection_attributes,
    OvStoragePlugin_UpdateConnectionAttributesRequest)
OVC_DEFINE_PASSTHROUGH_ASYNC(ovc_passthrough_authenticate_connection,
                             authenticate_connection,
                             OvStoragePlugin_AuthenticateRequest)

/* ------------------------------------------------------------------------- */
/*
 * Public default tables. Keep initializers in frozen header order.
 *
 * `_reserved` deliberately stays all-NULL in both tables: the frozen
 * forward-compat protocol reads a NULL slot as "not implemented" (matching
 * the Rust reference's `[None; 16]`), so a newer host that assigns a real
 * meaning to a reserved slot falls back instead of calling a stale stub.
 */

const OvStoragePlugin_LayerVTableV1 OVSTORAGE_UNSUPPORTED_VTABLE = {
    .struct_size = sizeof(OvStoragePlugin_LayerVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = ovc_unsupported_drop,
    .name = ovc_unsupported_name,
    .descriptor = ovc_unsupported_descriptor,
    .owned_targets = ovc_unsupported_owned_targets,
    .list_kinds = ovc_unsupported_list_kinds,
#define OVC_INIT_UNSUPPORTED_ASYNC(slot_name, request_type, release_fn)       \
    .slot_name = OVC_JOIN(ovc_unsupported_, slot_name),
    OVC_UNSUPPORTED_ASYNC_SLOTS(OVC_INIT_UNSUPPORTED_ASYNC)
#undef OVC_INIT_UNSUPPORTED_ASYNC
    /* _reserved is zero-initialized: NULL means "not implemented". */
};
#undef OVC_UNSUPPORTED_ASYNC_SLOTS

const OvStoragePlugin_LayerVTableV1 OVSTORAGE_PASSTHROUGH_VTABLE = {
    .struct_size = sizeof(OvStoragePlugin_LayerVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = ovc_passthrough_drop,
    .name = ovc_passthrough_name,
    .descriptor = ovc_passthrough_descriptor,
    .owned_targets = ovc_passthrough_owned_targets,
    .root_info_for = ovc_passthrough_root_info_for,
    .list_kinds = ovc_passthrough_list_kinds,
    .list_address_roots = ovc_passthrough_list_address_roots,
    .stat = ovc_passthrough_stat,
    .read = ovc_passthrough_read,
    .write = ovc_passthrough_write,
    .write_stream = ovc_passthrough_write_stream,
    .write_redirect = ovc_passthrough_write_redirect,
    .continue_write = ovc_passthrough_continue_write,
    .delete_ = ovc_passthrough_delete,
    .copy = ovc_passthrough_copy,
    .rename = ovc_passthrough_rename,
    .update_metadata = ovc_passthrough_update_metadata,
    .check_access = ovc_passthrough_check_access,
    .materialize = ovc_passthrough_materialize,
    .list = ovc_passthrough_list,
    .list_versions = ovc_passthrough_list_versions,
    .get_latest_version = ovc_passthrough_get_latest_version,
    .watch_directory = ovc_passthrough_watch_directory,
    .create_directory = ovc_passthrough_create_directory,
    .delete_directory = ovc_passthrough_delete_directory,
    .probe = ovc_passthrough_probe,
    .add_connection = ovc_passthrough_add_connection,
    .remove_connection = ovc_passthrough_remove_connection,
    .list_connections = ovc_passthrough_list_connections,
    .update_connection_credentials =
        ovc_passthrough_update_connection_credentials,
    .update_connection_attributes =
        ovc_passthrough_update_connection_attributes,
    .authenticate_connection = ovc_passthrough_authenticate_connection,
    /* _reserved is zero-initialized: NULL means "not implemented". */
};

#undef OVC_DEFINE_PASSTHROUGH_ASYNC
#undef OVC_DEFINE_UNSUPPORTED_ASYNC
#undef OVC_STATIC_ASSERT
#undef OVC_JOIN
#undef OVC_JOIN_INNER
