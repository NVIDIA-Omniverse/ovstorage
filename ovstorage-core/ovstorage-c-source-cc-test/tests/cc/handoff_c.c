/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * C -> C cross-language live-handoff contract.
 *
 * Pins the pure-C ovstorage_export_handle / ovstorage_import_handle pair:
 * the ABI handshake's typed failures and their disposal contract (a
 * handle is consumed exactly when its vtable header is trustworthy), and a
 * real export -> import -> drive -> destroy round trip over the built-in
 * file backend, including an import that outlives the exporting handle
 * (the refcounted root proxy keeps the inner Layer alive).  The leak
 * harness (leak_contracts_main.c) reruns this entry under ASan+LSan, so a
 * disposal regression surfaces as a leak instead of passing silently.
 */

/* <dirent.h> and <unistd.h> need POSIX.1-2008; the sanitizer leak harness
 * compiles this TU with a plain `cc -std=c99` and no feature-test defines
 * (build.rs passes them, hence the ifndef guards). */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "ovstorage.h"
#include "ovstorage_defaults.h"

#include "../../../../ovstorage-c-source/src/temp_dir.h"

#include "file_url.h"
#include "sidecar_cleanup.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include "windows_posix_compat.h"
#define unlink(path) ovc_test_remove_file(path)
#define rmdir(path) ovc_test_remove_dir(path)
#define strerror(error) ovc_test_strerror(error)
#else
#include <dirent.h>
#include <pthread.h>
#include <unistd.h>
#endif

typedef struct HandoffCompletion {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int done;
    int had_error;
    OvStorage_Status status;
    OvStorage_Info *info;
    OvStorage_Bytes bytes;
} HandoffCompletion;

static int handoff_completion_init(HandoffCompletion *completion)
{
    int result;

    memset(completion, 0, sizeof(*completion));
    result = pthread_mutex_init(&completion->mutex, NULL);
    if (result != 0) {
        fprintf(stderr, "pthread_mutex_init failed: %s\n", strerror(result));
        return 0;
    }
    result = pthread_cond_init(&completion->changed, NULL);
    if (result != 0) {
        fprintf(stderr, "pthread_cond_init failed: %s\n", strerror(result));
        (void)pthread_mutex_destroy(&completion->mutex);
        return 0;
    }
    return 1;
}

static void handoff_completion_prepare(HandoffCompletion *completion)
{
    (void)pthread_mutex_lock(&completion->mutex);
    ovstorage_info_destroy(completion->info);
    completion->info = NULL;
    ovstorage_bytes_destroy(&completion->bytes);
    completion->done = 0;
    completion->had_error = 0;
    completion->status = OvStorage_Status_Internal;
    (void)pthread_mutex_unlock(&completion->mutex);
}

static void handoff_completion_signal(HandoffCompletion *completion)
{
    completion->done = 1;
    (void)pthread_cond_signal(&completion->changed);
    (void)pthread_mutex_unlock(&completion->mutex);
}

static void handoff_completion_wait(HandoffCompletion *completion)
{
    (void)pthread_mutex_lock(&completion->mutex);
    while (!completion->done) {
        (void)pthread_cond_wait(&completion->changed, &completion->mutex);
    }
    (void)pthread_mutex_unlock(&completion->mutex);
}

static void handoff_completion_destroy(HandoffCompletion *completion)
{
    ovstorage_info_destroy(completion->info);
    completion->info = NULL;
    ovstorage_bytes_destroy(&completion->bytes);
    (void)pthread_cond_destroy(&completion->changed);
    (void)pthread_mutex_destroy(&completion->mutex);
}

static void handoff_on_info(OvStorage_Status status,
                            OvStorage_Info *info,
                            const OvStorage_Error *error,
                            void *user_data)
{
    HandoffCompletion *completion = (HandoffCompletion *)user_data;

    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->info = info;
    completion->had_error = error != NULL;
    handoff_completion_signal(completion);
}

static void handoff_on_read(OvStorage_Status status,
                            OvStorage_Bytes bytes,
                            OvStorage_Info *info,
                            const OvStorage_Error *error,
                            void *user_data)
{
    HandoffCompletion *completion = (HandoffCompletion *)user_data;

    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->bytes = bytes;
    completion->info = info;
    completion->had_error = error != NULL;
    handoff_completion_signal(completion);
}

static void handoff_on_status(OvStorage_Status status,
                              const OvStorage_Error *error,
                              void *user_data)
{
    HandoffCompletion *completion = (HandoffCompletion *)user_data;

    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->had_error = error != NULL;
    handoff_completion_signal(completion);
}

static int handoff_completion_succeeded(const char *operation,
                                        const HandoffCompletion *completion)
{
    if (completion->status == OvStorage_Status_Ok && !completion->had_error) {
        return 1;
    }
    fprintf(stderr,
            "%s failed with status %d\n",
            operation,
            (int)completion->status);
    return 0;
}

static int handoff_write(OvStorage_LayerHandle *layer,
                         HandoffCompletion *completion,
                         const char *address,
                         const uint8_t *payload,
                         size_t payload_len,
                         const char *label)
{
    OvStorage_WriteOptions options = {0};

    handoff_completion_prepare(completion);
    ovstorage_write(layer,
                    address,
                    payload,
                    payload_len,
                    &options,
                    NULL,
                    handoff_on_info,
                    completion);
    handoff_completion_wait(completion);
    return handoff_completion_succeeded(label, completion);
}

static int handoff_read_equals(OvStorage_LayerHandle *layer,
                               HandoffCompletion *completion,
                               const char *address,
                               const uint8_t *payload,
                               size_t payload_len,
                               const char *label)
{
    OvStorage_ReadOptions options = {0};

    handoff_completion_prepare(completion);
    ovstorage_read_bytes(layer,
                         address,
                         &options,
                         NULL,
                         handoff_on_read,
                         completion);
    handoff_completion_wait(completion);
    if (!handoff_completion_succeeded(label, completion)) {
        return 0;
    }
    if (completion->bytes.len != payload_len ||
        completion->bytes.data == NULL ||
        memcmp(completion->bytes.data, payload, payload_len) != 0) {
        fprintf(stderr, "%s returned unexpected data\n", label);
        return 0;
    }
    return 1;
}

static int handoff_delete(OvStorage_LayerHandle *layer,
                          HandoffCompletion *completion,
                          const char *address,
                          const char *label)
{
    handoff_completion_prepare(completion);
    ovstorage_delete(layer, address, NULL, handoff_on_status, completion);
    handoff_completion_wait(completion);
    return handoff_completion_succeeded(label, completion);
}

/* ------------------------------------------------------------------------- */
/* Handshake negatives: a stub Layer whose drop slot only counts calls. */

static void handoff_stub_drop(void *state)
{
    ++*(size_t *)state;
}

static int handoff_status_is(const char *label,
                             OvStorage_Status status,
                             OvStorage_Status expected)
{
    if (status == expected) {
        return 1;
    }
    fprintf(stderr,
            "%s returned status %d instead of %d\n",
            label,
            (int)status,
            (int)expected);
    return 0;
}

static int handoff_handshake_negatives(void)
{
    OvStoragePlugin_LayerVTableV1 vtable;
    OvStoragePlugin_LayerHandle handle;
    OvStorage_LayerHandle *imported = NULL;
    OvStorage_Error error = {0};
    size_t drop_calls = 0;
    int exit_code = 0;

    /* A zeroed pair and a NULL vtable are rejected before the header can
     * be trusted; nothing is disposed and drop must not run. */
    memset(&handle, 0, sizeof(handle));
    if (!handoff_status_is(
            "import of a zeroed handle",
            ovstorage_import_handle(handle, &imported, &error),
            OvStorage_Status_InvalidArgument)) {
        goto cleanup;
    }
    handle.state = &drop_calls;
    handle.vtable = NULL;
    if (!handoff_status_is(
            "import with a NULL vtable",
            ovstorage_import_handle(handle, &imported, &error),
            OvStorage_Status_InvalidArgument)) {
        goto cleanup;
    }

    memset(&vtable, 0, sizeof(vtable));
    vtable.struct_size = sizeof(vtable);
    vtable.abi_version = OVSTORAGE_PLUGIN_ABI_VERSION;
    vtable.drop = handoff_stub_drop;
    handle.state = &drop_calls;
    handle.vtable = &vtable;

    /* A NULL out_handle fails before the handle is touched. */
    if (!handoff_status_is(
            "import with a NULL out_handle",
            ovstorage_import_handle(handle, NULL, &error),
            OvStorage_Status_InvalidArgument)) {
        goto cleanup;
    }
    if (drop_calls != 0) {
        fprintf(stderr, "a NULL out_handle must not dispose the handle\n");
        goto cleanup;
    }

    /* An undersized header has no trustworthy drop slot: the handle is
     * returned undisposed. */
    vtable.struct_size = sizeof(vtable) - 1;
    if (!handoff_status_is(
            "import of an undersized vtable",
            ovstorage_import_handle(handle, &imported, &error),
            OvStorage_Status_IncompatibleType)) {
        goto cleanup;
    }
    if (drop_calls != 0) {
        fprintf(stderr, "an undersized header must not dispose the handle\n");
        goto cleanup;
    }
    vtable.struct_size = sizeof(vtable);

    /* Once {struct_size, abi_version} check out, the drop slot right after
     * them is trustworthy: a version mismatch consumes the handle. */
    vtable.abi_version =
        OVSTORAGE_PLUGIN_ABI_VERSION + 1;
    if (!handoff_status_is(
            "import of an unsupported abi_version",
            ovstorage_import_handle(handle, &imported, &error),
            OvStorage_Status_IncompatibleType)) {
        goto cleanup;
    }
    if (drop_calls != 1) {
        fprintf(stderr,
                "an abi_version mismatch must dispose the handle exactly "
                "once (drop ran %zu times)\n",
                drop_calls);
        goto cleanup;
    }

    /* A valid handshake with missing required op slots is also consumed. */
    drop_calls = 0;
    vtable.abi_version = OVSTORAGE_PLUGIN_ABI_VERSION;
    if (!handoff_status_is(
            "import without the required Layer slots",
            ovstorage_import_handle(handle, &imported, &error),
            OvStorage_Status_IncompatibleType)) {
        goto cleanup;
    }
    if (drop_calls != 1) {
        fprintf(stderr,
                "a slot-incomplete handle must be disposed exactly once "
                "(drop ran %zu times)\n",
                drop_calls);
        goto cleanup;
    }

    /* The public dispatcher calls every current operation slot
     * unconditionally. A table that is otherwise complete but omits one of
     * the newly exposed slots must be rejected at import, before a worker can
     * dereference it. */
    drop_calls = 0;
    vtable = OVSTORAGE_UNSUPPORTED_VTABLE;
    vtable.drop = handoff_stub_drop;
    vtable.write_stream = NULL;
    handle.state = &drop_calls;
    handle.vtable = &vtable;
    if (!handoff_status_is(
            "import without the write_stream Layer slot",
            ovstorage_import_handle(handle, &imported, &error),
            OvStorage_Status_IncompatibleType)) {
        goto cleanup;
    }
    if (drop_calls != 1) {
        fprintf(stderr,
                "a write_stream-incomplete handle must be disposed exactly "
                "once (drop ran %zu times)\n",
                drop_calls);
        goto cleanup;
    }

    /* Export rejects NULL arguments without touching anything. */
    if (!handoff_status_is(
            "export from a NULL Stack handle",
            ovstorage_export_handle(NULL, &handle, &error),
            OvStorage_Status_InvalidArgument)) {
        goto cleanup;
    }
    if (imported != NULL) {
        fprintf(stderr, "a failed import must not produce a handle\n");
        goto cleanup;
    }

    exit_code = 1;

cleanup:
    ovstorage_error_clear(&error);
    return exit_code;
}

/* ------------------------------------------------------------------------- */
/* The real round trip over the built-in file backend. */

int ovstorage_c_source_handoff_contract(void)
{
    static const uint8_t payload[] = "ovstorage pure-C handoff round trip";
    static const uint8_t second_payload[] = "written through the import";
    char directory_storage[OVC_TEMP_DIR_PATH_MAX];
    char root_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char object_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char second_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    /* Worst case, every byte of the URL path escapes to three, plus the
     * leading separator Win32 drive paths take. */
    char encoded_directory[3 * (OVC_TEMP_DIR_PATH_MAX + 2) + 8];
    char native_object[512];
    char native_second[512];
    OvStorage_Registry *registry = NULL;
    OvStorage_Stack *stack = NULL;
    OvStorage_ConnectionRequest *request = NULL;
    OvStorage_ConfigValue *root_value = NULL;
    OvStorage_LayerHandle *layer = NULL;
    OvStorage_LayerHandle *imported = NULL;
    OvStorage_LayerHandle *survivor = NULL;
    OvStoragePlugin_LayerHandle exported;
    OvStoragePlugin_LayerHandle second_export;
    OvStorage_Error error = {0};
    OvStorage_StackBuildOptions build_options = {0};
    HandoffCompletion completion;
    char *directory = NULL;
    int completion_initialized = 0;
    int paths_initialized = 0;
    int exit_code = EXIT_FAILURE;
    int written;

    memset(&exported, 0, sizeof(exported));
    memset(&second_export, 0, sizeof(second_export));

    if (!handoff_handshake_negatives()) {
        goto cleanup;
    }

    if (ovc_temp_dir_create("ovstorage-c-source-handoff",
                            directory_storage,
                            sizeof(directory_storage)) != 0) {
        fprintf(stderr,
                "creating a temporary directory failed: %s\n",
                strerror(errno));
        goto cleanup;
    }
    directory = directory_storage;
    if (test_file_url_path(directory,
                           encoded_directory,
                           sizeof(encoded_directory)) != 0) {
        fprintf(stderr, "temporary URL directory is too long\n");
        goto cleanup;
    }
    written = snprintf(root_address,
                       sizeof(root_address),
                       "file://%s/",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(root_address)) {
        fprintf(stderr, "temporary root address is too long\n");
        goto cleanup;
    }
    written = snprintf(object_address,
                       sizeof(object_address),
                       "file://%s/handoff.bin",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(object_address)) {
        fprintf(stderr, "temporary object address is too long\n");
        goto cleanup;
    }
    written = snprintf(second_address,
                       sizeof(second_address),
                       "file://%s/handoff-imported.bin",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(second_address)) {
        fprintf(stderr, "temporary second address is too long\n");
        goto cleanup;
    }
    written = snprintf(native_object,
                       sizeof(native_object),
                       "%s/handoff.bin",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(native_object)) {
        fprintf(stderr, "temporary object path is too long\n");
        goto cleanup;
    }
    written = snprintf(native_second,
                       sizeof(native_second),
                       "%s/handoff-imported.bin",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(native_second)) {
        fprintf(stderr, "temporary second path is too long\n");
        goto cleanup;
    }
    paths_initialized = 1;

    if (!handoff_completion_init(&completion)) {
        goto cleanup;
    }
    completion_initialized = 1;

    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    if (registry == NULL || stack == NULL) {
        fprintf(stderr, "failed to create the registry or Stack builder\n");
        goto cleanup;
    }
    if (ovstorage_stack_add_layer(stack, registry, "files", "file", &error) !=
            OvStorage_Status_Ok ||
        ovstorage_stack_set_root(stack, "files", &error) !=
            OvStorage_Status_Ok) {
        fprintf(stderr, "failed to declare the file stack\n");
        goto cleanup;
    }
    request = ovstorage_connection_request_create("file");
    root_value = ovstorage_config_value_create_string(root_address);
    if (request == NULL || root_value == NULL ||
        !ovstorage_connection_request_add_config(request,
                                                 "root",
                                                 root_value)) {
        fprintf(stderr, "failed to create the file connection config\n");
        goto cleanup;
    }
    root_value = NULL;
    if (ovstorage_stack_add_connection(stack, "files", &request, &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "failed to record the file connection\n");
        goto cleanup;
    }
    request = NULL;
    if (ovstorage_stack_build(stack, &build_options, &layer, &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "stack_build failed\n");
        goto cleanup;
    }
    stack = NULL;

    if (!handoff_write(layer,
                       &completion,
                       object_address,
                       payload,
                       sizeof(payload) - 1,
                       "write through the exporting handle")) {
        goto cleanup;
    }

    /* Export -> import -> drive: the imported handle sees the exporting
     * handle's writes (one shared root Layer), and its own writes are
     * visible back through the exporter. */
    if (!handoff_status_is(
            "export_handle",
            ovstorage_export_handle(layer, &exported, &error),
            OvStorage_Status_Ok)) {
        goto cleanup;
    }
    if (exported.state == NULL || exported.vtable == NULL) {
        fprintf(stderr, "export_handle minted a null pair\n");
        goto cleanup;
    }
    if (!handoff_status_is(
            "import_handle",
            ovstorage_import_handle(exported, &imported, &error),
            OvStorage_Status_Ok)) {
        goto cleanup;
    }
    memset(&exported, 0, sizeof(exported)); /* consumed by the import */
    if (imported == NULL) {
        fprintf(stderr, "import_handle produced no handle\n");
        goto cleanup;
    }
    if (!handoff_read_equals(imported,
                             &completion,
                             object_address,
                             payload,
                             sizeof(payload) - 1,
                             "read through the imported handle")) {
        goto cleanup;
    }
    if (!handoff_write(imported,
                       &completion,
                       second_address,
                       second_payload,
                       sizeof(second_payload) - 1,
                       "write through the imported handle")) {
        goto cleanup;
    }
    if (!handoff_read_equals(layer,
                             &completion,
                             second_address,
                             second_payload,
                             sizeof(second_payload) - 1,
                             "read of the import's write via the exporter")) {
        goto cleanup;
    }

    /* Handles are move-only: a second consumer needs a second export.  The
     * import must keep the inner Layer alive after the exporting handle is
     * destroyed (the root proxy's refbox holds the last reference). */
    if (!handoff_status_is(
            "second export_handle",
            ovstorage_export_handle(layer, &second_export, &error),
            OvStorage_Status_Ok)) {
        goto cleanup;
    }
    ovstorage_layer_handle_destroy(layer);
    layer = NULL;
    if (!handoff_status_is(
            "import after the exporter was destroyed",
            ovstorage_import_handle(second_export, &survivor, &error),
            OvStorage_Status_Ok)) {
        goto cleanup;
    }
    memset(&second_export, 0, sizeof(second_export));
    if (!handoff_read_equals(survivor,
                             &completion,
                             object_address,
                             payload,
                             sizeof(payload) - 1,
                             "read after the exporting handle was destroyed")) {
        goto cleanup;
    }

    /* Delete through one import, observe through the other. */
    if (!handoff_delete(survivor,
                        &completion,
                        second_address,
                        "delete through the surviving import")) {
        goto cleanup;
    }
    if (!handoff_delete(imported,
                        &completion,
                        object_address,
                        "delete through the first import")) {
        goto cleanup;
    }

    exit_code = EXIT_SUCCESS;

cleanup:
    /* A never-imported export is disposed through its own drop slot. */
    if (exported.state != NULL && exported.vtable != NULL &&
        exported.vtable->drop != NULL) {
        exported.vtable->drop(exported.state);
    }
    if (second_export.state != NULL && second_export.vtable != NULL &&
        second_export.vtable->drop != NULL) {
        second_export.vtable->drop(second_export.state);
    }
    ovstorage_layer_handle_destroy(imported);
    ovstorage_layer_handle_destroy(survivor);
    ovstorage_layer_handle_destroy(layer);
    ovstorage_stack_destroy(stack);
    ovstorage_connection_request_destroy(request);
    ovstorage_config_value_destroy(root_value);
    ovstorage_registry_destroy(registry);
    ovstorage_error_clear(&error);
    if (completion_initialized) {
        handoff_completion_destroy(&completion);
    }
    if (paths_initialized && unlink(native_object) != 0 && errno != ENOENT) {
        fprintf(stderr, "unlink failed: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    if (paths_initialized && unlink(native_second) != 0 && errno != ENOENT) {
        fprintf(stderr, "unlink failed: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    if (directory != NULL) {
        ovc_test_remove_metadata_sidecars(directory);
    }
    if (directory != NULL && rmdir(directory) != 0) {
        fprintf(stderr, "rmdir failed: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    return exit_code;
}
