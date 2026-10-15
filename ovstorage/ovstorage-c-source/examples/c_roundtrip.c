/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ovstorage.h"

/* Shared $TMPDIR resolution, from the source set this example builds. */
#include "../src/temp_dir.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
typedef SRWLOCK ExampleMutex;
typedef CONDITION_VARIABLE ExampleCondition;

static int example_mutex_init(ExampleMutex *mutex)
{
    InitializeSRWLock(mutex);
    return 0;
}

static int example_mutex_lock(ExampleMutex *mutex)
{
    AcquireSRWLockExclusive(mutex);
    return 0;
}

static int example_mutex_unlock(ExampleMutex *mutex)
{
    ReleaseSRWLockExclusive(mutex);
    return 0;
}

static int example_mutex_destroy(ExampleMutex *mutex)
{
    (void)mutex;
    return 0;
}

static int example_condition_init(ExampleCondition *condition)
{
    InitializeConditionVariable(condition);
    return 0;
}

static int example_condition_wait(ExampleCondition *condition,
                                  ExampleMutex *mutex)
{
    return SleepConditionVariableSRW(condition, mutex, INFINITE, 0) ? 0 : EIO;
}

static int example_condition_signal(ExampleCondition *condition)
{
    WakeConditionVariable(condition);
    return 0;
}

static int example_condition_destroy(ExampleCondition *condition)
{
    (void)condition;
    return 0;
}

static wchar_t *example_wide_path(const char *path)
{
    int count;
    wchar_t *wide;

    count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (count <= 0) {
        errno = EINVAL;
        return NULL;
    }
    wide = (wchar_t *)malloc((size_t)count * sizeof(*wide));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, count) <= 0) {
        free(wide);
        errno = EINVAL;
        return NULL;
    }
    return wide;
}

static int example_remove_file(const char *path)
{
    wchar_t *wide;
    DWORD error;

    wide = example_wide_path(path);
    if (wide == NULL) {
        return -1;
    }
    if (DeleteFileW(wide) != 0) {
        free(wide);
        return 0;
    }
    error = GetLastError();
    free(wide);
    errno = error == ERROR_FILE_NOT_FOUND ? ENOENT : EIO;
    return -1;
}

static int example_remove_directory(const char *path)
{
    wchar_t *wide;

    wide = example_wide_path(path);
    if (wide == NULL) {
        return -1;
    }
    if (RemoveDirectoryW(wide) != 0) {
        free(wide);
        return 0;
    }
    free(wide);
    errno = EIO;
    return -1;
}

static const char *example_error_message(int error)
{
    static __declspec(thread) char message[256];

    if (strerror_s(message, sizeof(message), error) != 0) {
        (void)snprintf(message, sizeof(message), "system error %d", error);
    }
    return message;
}
#else
typedef pthread_mutex_t ExampleMutex;
typedef pthread_cond_t ExampleCondition;

#define example_mutex_init(mutex) pthread_mutex_init((mutex), NULL)
#define example_mutex_lock(mutex) pthread_mutex_lock(mutex)
#define example_mutex_unlock(mutex) pthread_mutex_unlock(mutex)
#define example_mutex_destroy(mutex) pthread_mutex_destroy(mutex)
#define example_condition_init(condition) pthread_cond_init((condition), NULL)
#define example_condition_wait(condition, mutex) \
    pthread_cond_wait((condition), (mutex))
#define example_condition_signal(condition) pthread_cond_signal(condition)
#define example_condition_destroy(condition) pthread_cond_destroy(condition)
#define example_remove_file(path) unlink(path)
#define example_remove_directory(path) rmdir(path)
#define example_error_message(error) strerror(error)
#endif

/* Percent-encode a path for use as the path component of a `file://` URL.
 *
 * `ovc_temp_dir_create` hands back a NATIVE path, and the caller owns the
 * encoding (see src/temp_dir.h).  It matters: the default Windows temp root
 * is under `C:\Users\<username>\...`, and usernames routinely contain
 * spaces, while a POSIX $TMPDIR may hold `#`, `?` or `%` -- each of which
 * changes how the address parses, or is rejected outright.
 *
 * The rule is RFC 3986: pass the unreserved set through, escape every other
 * byte.  `/` is kept because it is already the URL separator by the time
 * this runs, and `:` because a Windows drive letter needs it.  Escaping a
 * byte that did not strictly need it is harmless -- the receiver decodes.
 *
 * NOT handled, because this example never produces them: a host/authority
 * component (a UNC share name is encoded as part of the path), and any
 * charset conversion.  Bytes are escaped individually, so a UTF-8 path
 * encodes correctly and any other encoding survives round-trip unchanged.
 *
 * Returns 0 on success, -1 if `out_size` is too small. */
static int example_percent_encode_path(const char *path,
                                       char *out,
                                       size_t out_size)
{
    static const char hex_digits[] = "0123456789ABCDEF";
    size_t written = 0;
    size_t index;

    for (index = 0; path[index] != '\0'; ++index) {
        unsigned char byte = (unsigned char)path[index];
        int literal = (byte >= 'A' && byte <= 'Z') ||
                      (byte >= 'a' && byte <= 'z') ||
                      (byte >= '0' && byte <= '9') || byte == '-' ||
                      byte == '.' || byte == '_' || byte == '~' ||
                      byte == '/' || byte == ':';

        if (literal) {
            if (written + 1 >= out_size) {
                return -1;
            }
            out[written++] = (char)byte;
        } else {
            if (written + 3 >= out_size) {
                return -1;
            }
            out[written++] = '%';
            out[written++] = hex_digits[byte >> 4];
            out[written++] = hex_digits[byte & 0x0FU];
        }
    }
    out[written] = '\0';
    return 0;
}

typedef struct Completion {
    ExampleMutex mutex;
    ExampleCondition changed;
    int done;
    int had_error;
    OvStorage_Status status;
    OvStorage_Info *info;
    OvStorage_Bytes bytes;
    OvStorage_List *list;
    char error_message[512];
} Completion;

static void completion_clear_outputs(Completion *completion)
{
    ovstorage_info_destroy(completion->info);
    completion->info = NULL;
    ovstorage_bytes_destroy(&completion->bytes);
    ovstorage_list_destroy(completion->list);
    completion->list = NULL;
}

static int completion_init(Completion *completion)
{
    int result;

    memset(completion, 0, sizeof(*completion));
    result = example_mutex_init(&completion->mutex);
    if (result != 0) {
        fprintf(stderr, "mutex initialization failed: %s\n",
                example_error_message(result));
        return 0;
    }
    result = example_condition_init(&completion->changed);
    if (result != 0) {
        fprintf(stderr, "condition initialization failed: %s\n",
                example_error_message(result));
        (void)example_mutex_destroy(&completion->mutex);
        return 0;
    }
    return 1;
}

static void completion_prepare(Completion *completion)
{
    (void)example_mutex_lock(&completion->mutex);
    completion_clear_outputs(completion);
    completion->done = 0;
    completion->had_error = 0;
    completion->status = OvStorage_Status_Internal;
    completion->error_message[0] = '\0';
    (void)example_mutex_unlock(&completion->mutex);
}

static void completion_copy_error(Completion *completion,
                                  const OvStorage_Error *error)
{
    completion->had_error = error != NULL;
    if (error != NULL && error->message != NULL) {
        (void)snprintf(completion->error_message,
                       sizeof(completion->error_message),
                       "%s",
                       error->message);
    } else {
        completion->error_message[0] = '\0';
    }
}

static void completion_signal(Completion *completion)
{
    completion->done = 1;
    (void)example_condition_signal(&completion->changed);
    (void)example_mutex_unlock(&completion->mutex);
}

static void on_info(OvStorage_Status status,
                    OvStorage_Info *info,
                    const OvStorage_Error *error,
                    void *user_data)
{
    Completion *completion = (Completion *)user_data;

    (void)example_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->info = info;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

static void on_read(OvStorage_Status status,
                    OvStorage_Bytes bytes,
                    OvStorage_Info *info,
                    const OvStorage_Error *error,
                    void *user_data)
{
    Completion *completion = (Completion *)user_data;

    (void)example_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->bytes = bytes;
    completion->info = info;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

static void on_list(OvStorage_Status status,
                    OvStorage_List *list,
                    const OvStorage_Error *error,
                    void *user_data)
{
    Completion *completion = (Completion *)user_data;

    (void)example_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->list = list;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

static void completion_wait(Completion *completion)
{
    (void)example_mutex_lock(&completion->mutex);
    while (!completion->done) {
        (void)example_condition_wait(&completion->changed, &completion->mutex);
    }
    (void)example_mutex_unlock(&completion->mutex);
}

static int completion_succeeded(const char *operation,
                                const Completion *completion)
{
    if (completion->status == OvStorage_Status_Ok &&
        !completion->had_error) {
        return 1;
    }

    fprintf(stderr,
            "%s failed with status %d%s%s\n",
            operation,
            (int)completion->status,
            completion->error_message[0] == '\0' ? "" : ": ",
            completion->error_message);
    return 0;
}

static void completion_destroy(Completion *completion)
{
    completion_clear_outputs(completion);
    (void)example_condition_destroy(&completion->changed);
    (void)example_mutex_destroy(&completion->mutex);
}

static int status_succeeded(const char *operation,
                            OvStorage_Status status,
                            const OvStorage_Error *error)
{
    if (status == OvStorage_Status_Ok) {
        return 1;
    }

    fprintf(stderr,
            "%s failed with status %d%s%s\n",
            operation,
            (int)status,
            error == NULL || error->message == NULL ? "" : ": ",
            error == NULL || error->message == NULL ? "" : error->message);
    return 0;
}

int main(void)
{
    static const uint8_t payload[] = "ovstorage pure-C round trip";
    char directory_storage[OVC_TEMP_DIR_PATH_MAX];
    char url_directory[OVC_TEMP_DIR_PATH_MAX + 1];
    /* Worst case, every byte of the path escapes to three. */
    char encoded_directory[3 * OVC_TEMP_DIR_PATH_MAX + 4];
    char root_address[3 * OVC_TEMP_DIR_PATH_MAX + 64];
    char object_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char native_object[512];
    OvStorage_Registry *registry = NULL;
    OvStorage_Stack *stack = NULL;
    OvStorage_ConnectionRequest *request = NULL;
    OvStorage_ConfigValue *root_value = NULL;
    OvStorage_LayerHandle *layer = NULL;
    OvStorage_Error error = {0};
    OvStorage_StackBuildOptions build_options = {0};
    OvStorage_WriteOptions write_options = {0};
    OvStorage_StatOptions stat_options = {0};
    OvStorage_ReadOptions read_options = {0};
    OvStorage_ListOptions list_options = {0};
    Completion completion;
    const char *listed_address;
    char *directory = NULL;
    int completion_initialized = 0;
    int paths_initialized = 0;
    int exit_code = EXIT_FAILURE;
    int written;
    size_t path_index;

    if (ovc_temp_dir_create("ovstorage-c-roundtrip",
                            directory_storage,
                            sizeof(directory_storage)) != 0) {
        fprintf(stderr,
                "creating a temporary directory failed: %s\n",
                example_error_message(errno));
        goto cleanup;
    }
    directory = directory_storage;

    /* Native path -> URL path.  A Windows UNC root already opens with the
     * two separators that follow `file://`; a drive path needs the third.
     * A POSIX path is already rooted at `/`, and a `\` in it is an ordinary
     * filename byte that must survive untouched. */
#if defined(_WIN32)
    /* A UNC root cannot be addressed: `file:` + `//server/share/...` reads
     * the leading `//` as an authority, which the parser refuses, and the
     * Win32 native-path normalizer accepts drive-letter roots only. Say so
     * here rather than emitting an address that fails later with a message
     * naming nothing. `GetTempPathW` yields a UNC path when TMP/TEMP points
     * at a share. */
    if (directory[0] == '\\' && directory[1] == '\\') {
        (void)fprintf(stderr,
                      "the temporary root is a UNC path (%s); this example "
                      "needs a local-drive TMP/TEMP\n",
                      directory);
        goto cleanup;
    }
    written = snprintf(url_directory, sizeof(url_directory), "/%s", directory);
#else
    written = snprintf(url_directory, sizeof(url_directory), "%s", directory);
#endif
    if (written < 0 || (size_t)written >= sizeof(url_directory)) {
        fprintf(stderr, "temporary root address is too long\n");
        goto cleanup;
    }
#if defined(_WIN32)
    for (path_index = 0; url_directory[path_index] != '\0'; ++path_index) {
        if (url_directory[path_index] == '\\') {
            url_directory[path_index] = '/';
        }
    }
#else
    (void)path_index;
#endif
    if (example_percent_encode_path(url_directory,
                                    encoded_directory,
                                    sizeof(encoded_directory)) != 0) {
        fprintf(stderr, "temporary root address is too long\n");
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
                       "%sc-roundtrip.bin",
                       root_address);
    if (written < 0 || (size_t)written >= sizeof(object_address)) {
        fprintf(stderr, "temporary object address is too long\n");
        goto cleanup;
    }
    written = snprintf(native_object,
                       sizeof(native_object),
                       "%s/c-roundtrip.bin",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(native_object)) {
        fprintf(stderr, "temporary object path is too long\n");
        goto cleanup;
    }
    paths_initialized = 1;

    if (!completion_init(&completion)) {
        goto cleanup;
    }
    completion_initialized = 1;

    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    if (registry == NULL || stack == NULL) {
        fprintf(stderr, "failed to create the registry or Stack builder\n");
        goto cleanup;
    }

    if (!status_succeeded(
            "stack_add_layer",
            ovstorage_stack_add_layer(
                stack, registry, "files", "file", &error),
            &error)) {
        goto cleanup;
    }
    if (!status_succeeded(
            "stack_set_root",
            ovstorage_stack_set_root(stack, "files", &error),
            &error)) {
        goto cleanup;
    }

    request = ovstorage_connection_request_create("file");
    root_value = ovstorage_config_value_create_string(root_address);
    if (request == NULL || root_value == NULL) {
        fprintf(stderr, "failed to create the file connection config\n");
        goto cleanup;
    }
    if (!ovstorage_connection_request_add_config(request, "root", root_value)) {
        fprintf(stderr, "failed to add the file connection root config\n");
        goto cleanup;
    }
    root_value = NULL;

    if (!status_succeeded(
            "stack_add_connection",
            ovstorage_stack_add_connection(stack, "files", &request, &error),
            &error)) {
        goto cleanup;
    }
    /* The call NULLs the slot exactly when it takes the builder, so this is
     * correct whether or not it did. */
    ovstorage_connection_request_destroy(request);

    if (!status_succeeded(
            "stack_build",
            ovstorage_stack_build(stack, &build_options, &layer, &error),
            &error)) {
        goto cleanup;
    }
    stack = NULL;
    if (layer == NULL) {
        fprintf(stderr, "stack_build returned no root Layer handle\n");
        goto cleanup;
    }

    completion_prepare(&completion);
    ovstorage_write(layer,
                    object_address,
                    payload,
                    sizeof(payload) - 1,
                    &write_options,
                    NULL,
                    on_info,
                    &completion);
    completion_wait(&completion);
    if (!completion_succeeded("write", &completion)) {
        goto cleanup;
    }
    if (completion.info == NULL ||
        !completion.info->has_size ||
        completion.info->size != sizeof(payload) - 1) {
        fprintf(stderr, "write returned unexpected object metadata\n");
        goto cleanup;
    }

    completion_prepare(&completion);
    ovstorage_stat(layer,
                   object_address,
                   &stat_options,
                   NULL,
                   on_info,
                   &completion);
    completion_wait(&completion);
    if (!completion_succeeded("stat", &completion)) {
        goto cleanup;
    }
    if (completion.info == NULL ||
        !completion.info->has_size ||
        completion.info->size != sizeof(payload) - 1) {
        fprintf(stderr, "stat returned unexpected object metadata\n");
        goto cleanup;
    }

    completion_prepare(&completion);
    ovstorage_read_bytes(layer,
                         object_address,
                         &read_options,
                         NULL,
                         on_read,
                         &completion);
    completion_wait(&completion);
    if (!completion_succeeded("read_bytes", &completion)) {
        goto cleanup;
    }
    if (completion.info == NULL ||
        completion.bytes.len != sizeof(payload) - 1 ||
        completion.bytes.data == NULL ||
        memcmp(completion.bytes.data, payload, sizeof(payload) - 1) != 0) {
        fprintf(stderr, "read_bytes returned unexpected data\n");
        goto cleanup;
    }

    list_options.recursive = true;
    completion_prepare(&completion);
    ovstorage_list(layer,
                   root_address,
                   &list_options,
                   NULL,
                   on_list,
                   &completion);
    completion_wait(&completion);
    listed_address = completion.list == NULL ||
            completion.list->len == 0
        ? NULL
        : completion.list->items[0].address;
    if (!completion_succeeded("list", &completion)) {
        goto cleanup;
    }
    if (completion.list == NULL ||
        completion.list->len != 1 ||
        listed_address == NULL ||
        strcmp(listed_address, object_address) != 0) {
        fprintf(stderr, "list did not return the round-trip object\n");
        goto cleanup;
    }

    printf("C round trip succeeded: %s\n", object_address);
    exit_code = EXIT_SUCCESS;

cleanup:
    ovstorage_layer_handle_destroy(layer);
    ovstorage_stack_destroy(stack);
    ovstorage_connection_request_destroy(request);
    ovstorage_config_value_destroy(root_value);
    ovstorage_registry_destroy(registry);
    ovstorage_error_clear(&error);
    if (completion_initialized) {
        completion_destroy(&completion);
    }
    if (paths_initialized &&
        example_remove_file(native_object) != 0 &&
        errno != ENOENT) {
        fprintf(stderr, "file removal failed: %s\n",
                example_error_message(errno));
        exit_code = EXIT_FAILURE;
    }
    if (directory != NULL && example_remove_directory(directory) != 0) {
        fprintf(stderr, "directory removal failed: %s\n",
                example_error_message(errno));
        exit_code = EXIT_FAILURE;
    }
    return exit_code;
}
