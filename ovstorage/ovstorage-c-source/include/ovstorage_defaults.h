/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Default Layer vtables for C plugin authors.
 */

#ifndef OVSTORAGE_DEFAULTS_H
#define OVSTORAGE_DEFAULTS_H

#include "ovstorage_plugin.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A complete wrapper vtable whose operational slots delegate to the wrapped
 * Layer. Copy this table, then replace the slots the wrapper decorates.
 * `_reserved` slots are NULL, meaning "not implemented"; leave them NULL.
 * Each default slot passes the caller's `on_complete` and `user_data`
 * straight to the inner Layer, so the completion fires for the original
 * receiver unchanged.
 *
 * State-layout contract (mandatory): every slot left at its default locates
 * the wrapped Layer by casting `state` to `OvStoragePlugin_LayerHandle *`,
 * so `state` MUST point at a `malloc`-allocated block whose FIRST member is
 * the inner `OvStoragePlugin_LayerHandle`. The default `drop` slot drops the
 * inner handle and then calls `free()` on that block. Consequences:
 *
 * - A pure passthrough allocates a single `OvStoragePlugin_LayerHandle` with
 *   `malloc`, copies the factory request's `inner` into it, and may keep the
 *   default `drop`.
 * - A wrapper with storage of its own must keep the inner handle as the
 *   first member of its state struct AND replace `drop` (drop the inner
 *   handle, release the extra storage, then `free` the block) — the default
 *   `drop` would `free()` the whole block while leaking anything else in it.
 * - Any other layout makes the unreplaced slots reinterpret the leading
 *   bytes of `state` as a `LayerHandle` and call through garbage pointers.
 *
 * Minimal wrapper factory decorating only `stat`:
 *
 *     struct my_state {
 *         OvStoragePlugin_LayerHandle inner; // MUST stay the first member
 *         struct my_config cfg;              // wrapper-owned extras
 *     };
 *
 *     static OvStoragePlugin_LayerVTableV1 my_vtable;
 *
 *     static void init_my_vtable(void)
 *     {
 *         my_vtable = OVSTORAGE_PASSTHROUGH_VTABLE;
 *         my_vtable.stat = my_stat; // decorated slot
 *         my_vtable.drop = my_drop; // extra storage: must replace drop
 *     }
 *
 *     static OvStoragePlugin_FfiStatus my_create_wrapper(
 *         void *plugin_state,
 *         const OvStoragePlugin_CreateWrapperRequest *request,
 *         OvStoragePlugin_LayerHandle *out,
 *         OvStoragePlugin_Error **err)
 *     {
 *         struct my_state *state = malloc(sizeof(*state));
 *         if (state == NULL) {
 *             // report *err and drop request->inner: the factory owns it
 *             return OvStoragePlugin_FFI_STATUS_ERR;
 *         }
 *         state->inner = request->inner; // wrapper takes ownership
 *         state->cfg = my_config_from(request);
 *         out->state = state;
 *         out->vtable = &my_vtable;
 *         return OvStoragePlugin_FFI_STATUS_OK;
 *     }
 */
extern const OvStoragePlugin_LayerVTableV1 OVSTORAGE_PASSTHROUGH_VTABLE;

/**
 * A complete backend vtable whose operational slots report Unsupported.
 *
 * Backend implementations should start from a copy of this table and patch
 * in every slot they support. For example:
 *
 *     static OvStoragePlugin_LayerVTableV1 my_vtable;
 *
 *     static void init_my_vtable(void)
 *     {
 *         my_vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
 *         my_vtable.stat = my_stat;
 *         my_vtable.read = my_read;
 *     }
 */
extern const OvStoragePlugin_LayerVTableV1 OVSTORAGE_UNSUPPORTED_VTABLE;

/**
 * Release a request an operation slot declined.
 *
 * A slot OWNS the request it is handed. Whether it does the work or answers
 * "unsupported", the request's heap does not go back to the caller: the host
 * has already relinquished it by the time the slot runs. A slot that returns
 * without doing either the work or one of these calls leaks every buffer the
 * request names.
 *
 * That obligation lands on anyone who patches a slot into a copy of
 * `OVSTORAGE_UNSUPPORTED_VTABLE`, because a partial backend declines
 * constantly -- a bad address, an option it does not implement, a cancelled
 * call. Each of those is a leak without a release.
 *
 * So the rule is per-RETURN, not per-slot: **every path out of a slot that
 * does not hand the request onward must release it first**, including the
 * early ones. A slot that releases on the path its author was thinking about
 * and returns without releasing on an argument check, an allocation failure,
 * or a cancellation still leaks on each of those.
 *
 *     static void my_stat(void *state,
 *                         const OvStoragePlugin_StatRequest *request,
 *                         const OvStoragePlugin_CancelTokenFFI *cancel,
 *                         OvStoragePlugin_OnComplete on_complete,
 *                         void *user_data)
 *     {
 *         if (!i_can_serve(request)) {
 *             ovstorage_plugin_stat_request_release(request);
 *             my_complete_unsupported(on_complete, user_data);
 *             return;
 *         }
 *         ...
 *     }
 *
 * A completion helper for that decline uses the four-argument callback
 * shape:
 *
 *     static void my_complete_unsupported(
 *         OvStoragePlugin_OnComplete on_complete,
 *         void *user_data)
 *     {
 *         on_complete(OvStoragePlugin_FFI_STATUS_ERR,
 *                     NULL,
 *                     my_unsupported_error(),
 *                     user_data);
 *     }
 *
 * Release BEFORE firing the completion. Releasing a `Body` whose tag is
 * `Stream` runs the host's `drop_fn`, and a completion callback that has
 * already returned may have torn down the state that stream refers to.
 *
 * Each call takes `const` because that is what a slot receives, and the
 * pointee really is never modified: the caller's storage may legitimately be
 * read-only, so a release copies the struct and frees through the copy. Every
 * owned thing in a request is reached by pointer, so the copy names the same
 * buffers. Only those buffers are freed -- never the request struct itself,
 * which belongs to the host.
 *
 * A consequence worth knowing if you write your own: because the release
 * clears a copy, your struct still holds the freed pointers afterwards.
 * Releasing the same request twice is a double free.
 *
 * `extensions` is deliberately untouched. It is borrowed rather than
 * transferred, and freeing it double-frees on the host side.
 *
 * A NULL request is ignored. For a non-NULL request, `struct_size` describes a
 * versioned prefix: every owned field fully inside that prefix is released,
 * and fields beyond it are untouched. Nested options are released only where
 * both the request and options prefixes reach the owned field.
 *
 * These are no-ops for request types that own nothing
 * (`ListAddressRootsRequest`, `ListConnectionsRequest`), which are declared so
 * a slot author does not have to know which is which.
 */
void ovstorage_plugin_stat_request_release(
    const OvStoragePlugin_StatRequest *request);

void ovstorage_plugin_read_request_release(
    const OvStoragePlugin_ReadRequest *request);

void ovstorage_plugin_write_request_release(
    const OvStoragePlugin_WriteRequest *request);

void ovstorage_plugin_list_request_release(
    const OvStoragePlugin_ListRequest *request);

void ovstorage_plugin_delete_request_release(
    const OvStoragePlugin_DeleteRequest *request);

void ovstorage_plugin_copy_request_release(
    const OvStoragePlugin_CopyRequest *request);

void ovstorage_plugin_rename_request_release(
    const OvStoragePlugin_RenameRequest *request);

void ovstorage_plugin_update_metadata_request_release(
    const OvStoragePlugin_UpdateMetadataRequest *request);

void ovstorage_plugin_check_access_request_release(
    const OvStoragePlugin_CheckAccessRequest *request);

void ovstorage_plugin_list_versions_request_release(
    const OvStoragePlugin_ListVersionsRequest *request);

void ovstorage_plugin_watch_directory_request_release(
    const OvStoragePlugin_WatchDirectoryRequest *request);

void ovstorage_plugin_create_directory_request_release(
    const OvStoragePlugin_CreateDirectoryRequest *request);

void ovstorage_plugin_delete_directory_request_release(
    const OvStoragePlugin_DeleteDirectoryRequest *request);

void ovstorage_plugin_root_info_for_request_release(
    const OvStoragePlugin_RootInfoForRequest *request);

void ovstorage_plugin_continue_write_request_release(
    const OvStoragePlugin_ContinueWriteRequest *request);

void ovstorage_plugin_layer_connection_request_release(
    const OvStoragePlugin_LayerConnectionRequest *request);

void ovstorage_plugin_remove_connection_request_release(
    const OvStoragePlugin_RemoveConnectionRequest *request);

void ovstorage_plugin_update_connection_credentials_request_release(
    const OvStoragePlugin_UpdateConnectionCredentialsRequest *request);

void ovstorage_plugin_update_connection_attributes_request_release(
    const OvStoragePlugin_UpdateConnectionAttributesRequest *request);

void ovstorage_plugin_authenticate_request_release(
    const OvStoragePlugin_AuthenticateRequest *request);

void ovstorage_plugin_list_address_roots_request_release(
    const OvStoragePlugin_ListAddressRootsRequest *request);

void ovstorage_plugin_list_connections_request_release(
    const OvStoragePlugin_ListConnectionsRequest *request);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OVSTORAGE_DEFAULTS_H */
