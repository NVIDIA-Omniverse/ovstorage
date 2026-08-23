/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * ovstorage_stack_build_async contract over the built-in file backend.
 *
 * Pins the async build's ownership rules against the pure-C
 * implementation: (a) a successful build consumes the builder and
 * delivers an owned root handle through the callback, (b) a prologue
 * rejection (root unset) fires the callback inline on the caller thread
 * and leaves the builder untouched and reusable, and (c) a pre-cancelled
 * token completes with Cancelled — code name included — and leaves the
 * builder intact, with the caller free to destroy its token wrapper as
 * soon as the call returns.  Every wait is a condition-variable latch;
 * there are no sleeps.
 */

#include "ovstorage.h"

#include "../../../../ovstorage-c-source/src/temp_dir.h"

#include "file_url.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include "windows_posix_compat.h"
#define rmdir(path) ovc_test_remove_dir(path)
#define strerror(error) ovc_test_strerror(error)
#else
#include <pthread.h>
#include <unistd.h>
#endif

typedef struct BuildCompletion {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int done;
    int fire_count;
    OvStorage_Status status;
    OvStorage_LayerHandle *handle;
    int had_error;
    /* Static process-lifetime string per the code-name contract. */
    const char *error_code_name;
    char error_message[512];
} BuildCompletion;

static int build_completion_init(BuildCompletion *completion)
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

static void build_completion_prepare(BuildCompletion *completion)
{
    (void)pthread_mutex_lock(&completion->mutex);
    completion->done = 0;
    completion->fire_count = 0;
    completion->status = OvStorage_Status_Internal;
    completion->handle = NULL;
    completion->had_error = 0;
    completion->error_code_name = NULL;
    completion->error_message[0] = '\0';
    (void)pthread_mutex_unlock(&completion->mutex);
}

static void build_completion_wait(BuildCompletion *completion)
{
    (void)pthread_mutex_lock(&completion->mutex);
    while (!completion->done) {
        (void)pthread_cond_wait(&completion->changed, &completion->mutex);
    }
    (void)pthread_mutex_unlock(&completion->mutex);
}

/* Whether the callback already fired, without blocking: pins the inline
 * (before-return) delivery of prologue rejections. */
static int build_completion_is_done(BuildCompletion *completion)
{
    int done;

    (void)pthread_mutex_lock(&completion->mutex);
    done = completion->done;
    (void)pthread_mutex_unlock(&completion->mutex);
    return done;
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

    (void)pthread_mutex_lock(&completion->mutex);
    ++completion->fire_count;
    completion->status = status;
    completion->handle = handle;
    completion->had_error = error != NULL;
    /* The error is borrowed for this fire only: copy the message and take
     * the (static, process-lifetime) code name before returning. */
    completion->error_code_name = ovstorage_error_code_name(error);
    if (error != NULL && error->message != NULL) {
        (void)snprintf(completion->error_message,
                       sizeof(completion->error_message),
                       "%s",
                       error->message);
    } else {
        completion->error_message[0] = '\0';
    }
    completion->done = 1;
    (void)pthread_cond_signal(&completion->changed);
    (void)pthread_mutex_unlock(&completion->mutex);
}

/* Declare the seeded built-in file layer plus its root connection into a
 * fresh builder.  The root is deliberately NOT set here: scenario (b)
 * builds without it, the others set it themselves. */
static OvStorage_Stack *build_rootless_file_stack(
    const OvStorage_Registry *registry,
    const char *root_address)
{
    OvStorage_Stack *stack;
    OvStorage_ConnectionRequest *request;
    OvStorage_ConfigValue *root_value;
    OvStorage_Error error = {0};

    stack = ovstorage_stack_create();
    if (stack == NULL) {
        fprintf(stderr, "failed to create a Stack builder\n");
        return NULL;
    }
    if (ovstorage_stack_add_layer(stack, registry, "files", "file", &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "failed to declare the file layer\n");
        ovstorage_error_clear(&error);
        ovstorage_stack_destroy(stack);
        return NULL;
    }
    request = ovstorage_connection_request_create("file");
    root_value = ovstorage_config_value_create_string(root_address);
    if (request == NULL || root_value == NULL ||
        !ovstorage_connection_request_add_config(request,
                                                 "root",
                                                 root_value)) {
        fprintf(stderr, "failed to create the file connection config\n");
        ovstorage_config_value_destroy(root_value);
        ovstorage_connection_request_destroy(request);
        ovstorage_stack_destroy(stack);
        return NULL;
    }
    if (ovstorage_stack_add_connection(stack, "files", &request, &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "failed to record the file connection\n");
        ovstorage_error_clear(&error);
        ovstorage_connection_request_destroy(request);
        ovstorage_stack_destroy(stack);
        return NULL;
    }
    return stack;
}

static int build_completion_succeeded(const char *label,
                                      const BuildCompletion *completion)
{
    if (completion->fire_count == 1 &&
        completion->status == OvStorage_Status_Ok &&
        !completion->had_error && completion->handle != NULL) {
        return 1;
    }
    fprintf(stderr,
            "%s fired %d time(s) with status %d%s%s\n",
            label,
            completion->fire_count,
            (int)completion->status,
            completion->error_message[0] == '\0' ? "" : ": ",
            completion->error_message);
    return 0;
}

int ovstorage_c_source_stack_build_async_contract(void)
{
    char directory_storage[OVC_TEMP_DIR_PATH_MAX];
    /* Worst case, every byte of the URL path escapes to three, plus the
     * leading separator Win32 drive paths take. */
    char encoded_directory[3 * (OVC_TEMP_DIR_PATH_MAX + 2) + 8];
    char root_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    OvStorage_Registry *registry = NULL;
    OvStorage_Stack *stack = NULL;
    OvStorage_CancelToken *cancel = NULL;
    OvStorage_Error error = {0};
    OvStorage_StackBuildOptions build_options = {0};
    BuildCompletion completion;
    char *directory = NULL;
    int completion_initialized = 0;
    int exit_code = EXIT_FAILURE;
    int written;

    if (ovc_temp_dir_create("ovstorage-c-source-stack-async",
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
    if (!build_completion_init(&completion)) {
        goto cleanup;
    }
    completion_initialized = 1;
    registry = ovstorage_registry_create();
    if (registry == NULL) {
        fprintf(stderr, "failed to create the registry\n");
        goto cleanup;
    }

    /* (a) A successful async build delivers an owned root handle through
     * the callback and consumes the builder. */
    stack = build_rootless_file_stack(registry, root_address);
    if (stack == NULL) {
        goto cleanup;
    }
    if (ovstorage_stack_set_root(stack, "files", &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "failed to set the stack root\n");
        goto cleanup;
    }
    build_completion_prepare(&completion);
    ovstorage_stack_build_async(stack,
                                &build_options,
                                NULL,
                                on_build,
                                &completion);
    build_completion_wait(&completion);
    if (!build_completion_succeeded("async build", &completion)) {
        goto cleanup;
    }
    /* Success consumed the builder; only the handle needs releasing. */
    stack = NULL;
    ovstorage_layer_handle_destroy(completion.handle);

    /* (b) A prologue rejection (root unset) fires inline on the caller
     * thread with the builder untouched: fix the root and the same
     * builder must build successfully. */
    stack = build_rootless_file_stack(registry, root_address);
    if (stack == NULL) {
        goto cleanup;
    }
    build_completion_prepare(&completion);
    ovstorage_stack_build_async(stack,
                                &build_options,
                                NULL,
                                on_build,
                                &completion);
    if (!build_completion_is_done(&completion)) {
        fprintf(stderr,
                "a prologue rejection must fire the callback inline, "
                "before ovstorage_stack_build_async returns\n");
        goto cleanup;
    }
    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_InvalidArgument ||
        completion.handle != NULL || !completion.had_error ||
        strstr(completion.error_message, "root not set") == NULL) {
        fprintf(stderr,
                "build with the root unset fired %d time(s) with status %d "
                "instead of an inline InvalidArgument rejection: %s\n",
                completion.fire_count,
                (int)completion.status,
                completion.error_message);
        goto cleanup;
    }
    if (ovstorage_stack_set_root(stack, "files", &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "failed to set the root after the rejection\n");
        goto cleanup;
    }
    build_completion_prepare(&completion);
    ovstorage_stack_build_async(stack,
                                &build_options,
                                NULL,
                                on_build,
                                &completion);
    build_completion_wait(&completion);
    if (!build_completion_succeeded("rebuild after the prologue rejection",
                                    &completion)) {
        goto cleanup;
    }
    stack = NULL;
    ovstorage_layer_handle_destroy(completion.handle);

    /* (c) A pre-cancelled token completes with Cancelled and leaves the
     * builder intact.  Destroying the token wrapper right after the call
     * returns pins the mint-retains-state contract: the token only has to
     * outlive the ovstorage_stack_build_async call itself. */
    stack = build_rootless_file_stack(registry, root_address);
    if (stack == NULL) {
        goto cleanup;
    }
    if (ovstorage_stack_set_root(stack, "files", &error) !=
        OvStorage_Status_Ok) {
        fprintf(stderr, "failed to set the stack root\n");
        goto cleanup;
    }
    cancel = ovstorage_cancel_token_create();
    if (cancel == NULL) {
        fprintf(stderr, "failed to create the cancel token\n");
        goto cleanup;
    }
    ovstorage_cancel_token_cancel(cancel);
    build_completion_prepare(&completion);
    ovstorage_stack_build_async(stack,
                                &build_options,
                                cancel,
                                on_build,
                                &completion);
    ovstorage_cancel_token_destroy(cancel);
    cancel = NULL;
    build_completion_wait(&completion);
    if (completion.fire_count != 1 ||
        completion.status != OvStorage_Status_Cancelled ||
        completion.handle != NULL || !completion.had_error) {
        fprintf(stderr,
                "a pre-cancelled build fired %d time(s) with status %d "
                "instead of exactly one Cancelled fire: %s\n",
                completion.fire_count,
                (int)completion.status,
                completion.error_message);
        goto cleanup;
    }
    if (completion.error_code_name == NULL ||
        strcmp(completion.error_code_name, "Cancelled") != 0) {
        fprintf(stderr,
                "the cancelled build's code name was %s instead of "
                "Cancelled\n",
                completion.error_code_name == NULL
                    ? "(null)"
                    : completion.error_code_name);
        goto cleanup;
    }
    build_completion_prepare(&completion);
    ovstorage_stack_build_async(stack,
                                &build_options,
                                NULL,
                                on_build,
                                &completion);
    build_completion_wait(&completion);
    if (!build_completion_succeeded("rebuild after the cancelled build",
                                    &completion)) {
        goto cleanup;
    }
    stack = NULL;
    ovstorage_layer_handle_destroy(completion.handle);

    exit_code = EXIT_SUCCESS;

cleanup:
    ovstorage_cancel_token_destroy(cancel);
    ovstorage_stack_destroy(stack);
    ovstorage_registry_destroy(registry);
    ovstorage_error_clear(&error);
    if (completion_initialized) {
        build_completion_destroy(&completion);
    }
    /* The builds record connections but write no objects, so the
     * directory must still be empty. */
    if (directory != NULL && rmdir(directory) != 0) {
        fprintf(stderr, "rmdir failed: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    return exit_code;
}
