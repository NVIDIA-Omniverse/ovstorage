/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ovstorage.h"
#include "ovstorage_plugin.h"

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

typedef struct Completion {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
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

static void completion_prepare(Completion *completion)
{
    (void)pthread_mutex_lock(&completion->mutex);
    completion_clear_outputs(completion);
    completion->done = 0;
    completion->had_error = 0;
    completion->status = OvStorage_Status_Internal;
    completion->error_message[0] = '\0';
    (void)pthread_mutex_unlock(&completion->mutex);
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
    (void)pthread_cond_signal(&completion->changed);
    (void)pthread_mutex_unlock(&completion->mutex);
}

static void on_info(OvStorage_Status status,
                    OvStorage_Info *info,
                    const OvStorage_Error *error,
                    void *user_data)
{
    Completion *completion = (Completion *)user_data;

    (void)pthread_mutex_lock(&completion->mutex);
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

    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->bytes = bytes;
    completion->info = info;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

/* `ovstorage_read_local_file` is the host entry point onto the backend's
 * materialize slot.  The delegate is destroyed here rather than parked on
 * the Completion: these assertions only read `status`, and on the refusal
 * paths the delegate is NULL anyway. */
static void on_local_file(OvStorage_Status status,
                          OvStorage_LocalDelegate *delegate,
                          const OvStorage_Error *error,
                          void *user_data)
{
    Completion *completion = (Completion *)user_data;

    ovstorage_local_delegate_destroy(delegate);
    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

static void on_list(OvStorage_Status status,
                    OvStorage_List *list,
                    const OvStorage_Error *error,
                    void *user_data)
{
    Completion *completion = (Completion *)user_data;

    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->list = list;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

static void on_status(OvStorage_Status status,
                      const OvStorage_Error *error,
                      void *user_data)
{
    Completion *completion = (Completion *)user_data;

    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

static void on_connection(OvStorage_Status status,
                          OvStorage_Connection *connection,
                          const OvStorage_Error *error,
                          void *user_data)
{
    Completion *completion = (Completion *)user_data;

    ovstorage_connection_destroy(connection);
    (void)pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion_copy_error(completion, error);
    completion_signal(completion);
}

/* Accumulates ovstorage_read_stream fires: every chunk is appended and the
 * exactly-once done=true terminal releases the waiter.  Fires arriving after
 * the terminal are counted so the frozen single-terminal contract is pinned. */
typedef struct StreamCompletion {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    uint8_t *data;
    size_t len;
    int done_count;
    int fires_after_done;
    int had_error;
    int append_failed;
} StreamCompletion;

static int stream_completion_init(StreamCompletion *stream)
{
    int result;

    memset(stream, 0, sizeof(*stream));
    result = pthread_mutex_init(&stream->mutex, NULL);
    if (result != 0) {
        fprintf(stderr, "pthread_mutex_init failed: %s\n", strerror(result));
        return 0;
    }
    result = pthread_cond_init(&stream->changed, NULL);
    if (result != 0) {
        fprintf(stderr, "pthread_cond_init failed: %s\n", strerror(result));
        (void)pthread_mutex_destroy(&stream->mutex);
        return 0;
    }
    return 1;
}

static void on_stream(OvStorage_Bytes chunk,
                      const OvStorage_Error *error,
                      bool done,
                      void *user_data)
{
    StreamCompletion *stream = (StreamCompletion *)user_data;

    (void)pthread_mutex_lock(&stream->mutex);
    if (stream->done_count > 0) {
        ++stream->fires_after_done;
    }
    if (error != NULL) {
        stream->had_error = 1;
    }
    if (chunk.data != NULL && chunk.len > 0) {
        uint8_t *grown =
            (uint8_t *)realloc(stream->data, stream->len + chunk.len);

        if (grown == NULL) {
            stream->append_failed = 1;
        } else {
            memcpy(grown + stream->len, chunk.data, chunk.len);
            stream->data = grown;
            stream->len += chunk.len;
        }
    }
    if (done) {
        ++stream->done_count;
        (void)pthread_cond_signal(&stream->changed);
    }
    (void)pthread_mutex_unlock(&stream->mutex);
    ovstorage_bytes_destroy(&chunk);
}

static void stream_completion_wait(StreamCompletion *stream)
{
    (void)pthread_mutex_lock(&stream->mutex);
    while (stream->done_count == 0) {
        (void)pthread_cond_wait(&stream->changed, &stream->mutex);
    }
    (void)pthread_mutex_unlock(&stream->mutex);
}

static void stream_completion_destroy(StreamCompletion *stream)
{
    free(stream->data);
    stream->data = NULL;
    (void)pthread_cond_destroy(&stream->changed);
    (void)pthread_mutex_destroy(&stream->mutex);
}

static void completion_wait(Completion *completion)
{
    (void)pthread_mutex_lock(&completion->mutex);
    while (!completion->done) {
        (void)pthread_cond_wait(&completion->changed, &completion->mutex);
    }
    (void)pthread_mutex_unlock(&completion->mutex);
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
    (void)pthread_cond_destroy(&completion->changed);
    (void)pthread_mutex_destroy(&completion->mutex);
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

/* Stat `address` and require exactly `expected` (used for both Ok and the
 * NotFound pins after delete/rename and under a regular-file parent). */
static int stat_status_is(OvStorage_LayerHandle *layer,
                          Completion *completion,
                          const char *address,
                          OvStorage_Status expected,
                          const char *label)
{
    OvStorage_StatOptions options = {0};

    completion_prepare(completion);
    ovstorage_stat(layer, address, &options, NULL, on_info, completion);
    completion_wait(completion);
    if (completion->status != expected) {
        fprintf(stderr,
                "%s returned status %d instead of %d\n",
                label,
                (int)completion->status,
                (int)expected);
        return 0;
    }
    return 1;
}

static int read_equals(OvStorage_LayerHandle *layer,
                       Completion *completion,
                       const char *address,
                       const uint8_t *payload,
                       size_t payload_len,
                       const char *label)
{
    OvStorage_ReadOptions options = {0};

    completion_prepare(completion);
    ovstorage_read_bytes(layer, address, &options, NULL, on_read, completion);
    completion_wait(completion);
    if (!completion_succeeded(label, completion)) {
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

static int auth_bytes_equal(const OvStoragePlugin_Bytes *actual,
                            const uint8_t *expected,
                            size_t expected_len)
{
    return actual->len == expected_len && actual->ptr != NULL &&
           (expected_len == 0 ||
            memcmp(actual->ptr, expected, expected_len) == 0);
}

static int auth_str_equal(const OvStoragePlugin_Str *actual,
                          const char *expected,
                          size_t expected_len)
{
    return actual->len == expected_len && actual->ptr != NULL &&
           (expected_len == 0 ||
            memcmp(actual->ptr, expected, expected_len) == 0);
}

static OvStoragePlugin_AuthCredential *auth_decode_success(
    const char *label,
    const uint8_t *bytes,
    size_t len)
{
    OvStoragePlugin_AuthCredential *credential =
        (OvStoragePlugin_AuthCredential *)(uintptr_t)1u;
    OvStoragePlugin_Error *error = (OvStoragePlugin_Error *)(uintptr_t)2u;
    OvStoragePlugin_FfiStatus status;

    status = ovstorage_plugin_auth_credential_decode(
        bytes, len, &credential, &error);
    if (status != OvStoragePlugin_FFI_STATUS_OK || credential == NULL ||
        credential == (OvStoragePlugin_AuthCredential *)(uintptr_t)1u ||
        error != NULL) {
        fprintf(stderr, "%s did not decode successfully\n", label);
        if (credential !=
            (OvStoragePlugin_AuthCredential *)(uintptr_t)1u) {
            ovstorage_plugin_auth_credential_free(credential);
        }
        if (error != (OvStoragePlugin_Error *)(uintptr_t)2u) {
            ovstorage_plugin_error_free(error);
        }
        return NULL;
    }
    if (credential->struct_size != sizeof(*credential)) {
        fprintf(stderr, "%s returned the wrong struct_size\n", label);
        ovstorage_plugin_auth_credential_free(credential);
        return NULL;
    }
    return credential;
}

static int auth_decode_failure(const char *label,
                               const uint8_t *bytes,
                               size_t len,
                               OvStoragePlugin_ErrorCode expected_code,
                               const char *expected_message)
{
    OvStoragePlugin_AuthCredential *credential =
        (OvStoragePlugin_AuthCredential *)(uintptr_t)1u;
    OvStoragePlugin_Error *error = (OvStoragePlugin_Error *)(uintptr_t)2u;
    OvStoragePlugin_FfiStatus status;
    size_t expected_len = strlen(expected_message);
    int matches;

    status = ovstorage_plugin_auth_credential_decode(
        bytes, len, &credential, &error);
    matches = status == OvStoragePlugin_FFI_STATUS_ERR &&
              credential == NULL && error != NULL &&
              error != (OvStoragePlugin_Error *)(uintptr_t)2u &&
              error->code == expected_code &&
              error->message_len == expected_len &&
              error->message_ptr != NULL &&
              memcmp(error->message_ptr, expected_message, expected_len) == 0;
    if (!matches) {
        fprintf(stderr, "%s returned the wrong decode error\n", label);
    }
    if (credential != (OvStoragePlugin_AuthCredential *)(uintptr_t)1u) {
        ovstorage_plugin_auth_credential_free(credential);
    }
    if (error != (OvStoragePlugin_Error *)(uintptr_t)2u) {
        ovstorage_plugin_error_free(error);
    }
    return matches;
}

int ovstorage_c_source_auth_credential_contract(void)
{
    static const uint8_t tcp[] = {
        2,
        2, 0, 0, 0, 'A', 'B',
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP,
        3, 0, 0, 0, 'h', ':', '1',
        2, 0, 0, 0, 0xde, 0xad,
        0, 0, 0, 0,
    };
    static const uint8_t uds[] = {
        2,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS,
        7, 0, 0, 0,
        8, 0, 0, 0,
        0xfe, 0xff, 0xff, 0xff,
        0, 0, 0, 0,
    };
    static const uint8_t named_pipe[] = {
        2,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_NAMED_PIPE,
        3, 0, 0, 0, 'S', '-', '1',
        5, 0, 0, 0,
        0, 0, 0, 0,
    };
    static const uint8_t legacy[] = {
        1,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS,
        7, 0, 0, 0,
        8, 0, 0, 0,
        9, 0, 0, 0,
    };
    static const uint8_t forwarded[] = {
        2,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP,
        3, 0, 0, 0, 'h', ':', '1',
        0, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 0, 0, 'x', '-', 'u',
        5, 0, 0, 0, 'a', 'l', 'i', 'c', 'e',
        3, 0, 0, 0, 'x', '-', 't',
        3, 0, 0, 0, 'a', 'r', 't',
    };
    static const uint8_t unsupported[] = {
        99, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    static const uint8_t truncated[] = {
        2,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 0, 0,
        0, 0,
    };
    static const uint8_t bad_tag[] = {1, 0, 0, 0, 0, 7};
    static const uint8_t bad_utf8[] = {
        1, 0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_TCP,
        1, 0, 0, 0, 0xff,
    };
    static const uint8_t trailing[] = {
        1,
        0, 0, 0, 0,
        OVSTORAGE_AUTH_CREDENTIAL_TRANSPORT_UDS,
        1, 0, 0, 0,
        2, 0, 0, 0,
        3, 0, 0, 0,
        0xde,
    };
    static const uint8_t bearer[] = {'A', 'B'};
    static const uint8_t cert[] = {0xde, 0xad};
    OvStoragePlugin_AuthCredential *credential;

    credential = auth_decode_success("golden Tcp credential",
                                     tcp,
                                     sizeof(tcp));
    if (credential == NULL || !credential->bearer.present ||
        !auth_bytes_equal(&credential->bearer.value,
                          bearer,
                          sizeof(bearer)) ||
        credential->transport.tag !=
            OvStoragePlugin_AuthCredentialTransportTag_Tcp ||
        !auth_str_equal(&credential->transport.tcp.peer_addr, "h:1", 3) ||
        !credential->transport.tcp.tls_client_cert.present ||
        !auth_bytes_equal(&credential->transport.tcp.tls_client_cert.value,
                          cert,
                          sizeof(cert)) ||
        credential->forwarded_headers.len != 0 ||
        credential->forwarded_headers.ptr == NULL) {
        fprintf(stderr, "golden Tcp credential fields differ\n");
        ovstorage_plugin_auth_credential_free(credential);
        return 1;
    }
    ovstorage_plugin_auth_credential_free(credential);

    credential = auth_decode_success("golden Uds credential",
                                     uds,
                                     sizeof(uds));
    if (credential == NULL || credential->bearer.present ||
        credential->transport.tag !=
            OvStoragePlugin_AuthCredentialTransportTag_Uds ||
        credential->transport.uds.uid != 7 ||
        credential->transport.uds.gid != 8 ||
        credential->transport.uds.pid != -2 ||
        credential->forwarded_headers.len != 0 ||
        credential->forwarded_headers.ptr == NULL) {
        fprintf(stderr, "golden Uds credential fields differ\n");
        ovstorage_plugin_auth_credential_free(credential);
        return 2;
    }
    ovstorage_plugin_auth_credential_free(credential);

    credential = auth_decode_success("golden NamedPipe credential",
                                     named_pipe,
                                     sizeof(named_pipe));
    if (credential == NULL || credential->bearer.present ||
        credential->transport.tag !=
            OvStoragePlugin_AuthCredentialTransportTag_NamedPipe ||
        !auth_str_equal(&credential->transport.named_pipe.sid, "S-1", 3) ||
        credential->transport.named_pipe.pid != 5 ||
        credential->forwarded_headers.len != 0 ||
        credential->forwarded_headers.ptr == NULL) {
        fprintf(stderr, "golden NamedPipe credential fields differ\n");
        ovstorage_plugin_auth_credential_free(credential);
        return 3;
    }
    ovstorage_plugin_auth_credential_free(credential);

    credential = auth_decode_success("legacy v1 credential",
                                     legacy,
                                     sizeof(legacy));
    if (credential == NULL || credential->transport.tag !=
                                  OvStoragePlugin_AuthCredentialTransportTag_Uds ||
        credential->transport.uds.uid != 7 ||
        credential->transport.uds.gid != 8 ||
        credential->transport.uds.pid != 9 ||
        credential->forwarded_headers.len != 0 ||
        credential->forwarded_headers.ptr == NULL) {
        fprintf(stderr, "legacy v1 credential fields differ\n");
        ovstorage_plugin_auth_credential_free(credential);
        return 4;
    }
    ovstorage_plugin_auth_credential_free(credential);

    credential = auth_decode_success("forwarded-header credential",
                                     forwarded,
                                     sizeof(forwarded));
    if (credential == NULL || credential->forwarded_headers.len != 2 ||
        !auth_str_equal(&credential->forwarded_headers.ptr[0].name,
                        "x-u",
                        3) ||
        !auth_str_equal(&credential->forwarded_headers.ptr[0].value,
                        "alice",
                        5) ||
        !auth_str_equal(&credential->forwarded_headers.ptr[1].name,
                        "x-t",
                        3) ||
        !auth_str_equal(&credential->forwarded_headers.ptr[1].value,
                        "art",
                        3)) {
        fprintf(stderr, "forwarded-header credential fields differ\n");
        ovstorage_plugin_auth_credential_free(credential);
        return 5;
    }
    ovstorage_plugin_auth_credential_free(credential);

    if (!auth_decode_failure(
            "unsupported version",
            unsupported,
            sizeof(unsupported),
            OvStoragePlugin_ErrorCode_IncompatibleType,
            "AuthCredential decode failed: unsupported wire version") ||
        !auth_decode_failure(
            "truncated credential",
            truncated,
            sizeof(truncated),
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "AuthCredential decode failed: truncated buffer") ||
        !auth_decode_failure(
            "bad transport tag",
            bad_tag,
            sizeof(bad_tag),
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "AuthCredential decode failed: bad transport tag") ||
        !auth_decode_failure(
            "bad UTF-8",
            bad_utf8,
            sizeof(bad_utf8),
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "AuthCredential decode failed: invalid utf-8 in string field") ||
        !auth_decode_failure(
            "trailing data",
            trailing,
            sizeof(trailing),
            OvStoragePlugin_ErrorCode_InvalidArgument,
            "AuthCredential decode failed: trailing data after credential")) {
        return 6;
    }

    ovstorage_plugin_auth_credential_free(NULL);
    return 0;
}

int ovstorage_c_source_roundtrip_c(void)
{
    static const uint8_t payload[] = "ovstorage pure-C cc-test round trip";
    char directory_storage[OVC_TEMP_DIR_PATH_MAX];
    char root_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char object_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char child_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char renamed_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    char copied_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];
    /* Worst case, every byte of the URL path escapes to three, plus the
     * leading separator Win32 drive paths take. */
    char encoded_directory[3 * (OVC_TEMP_DIR_PATH_MAX + 2) + 8];
    char native_object[512];
    char native_renamed[512];
    char native_copied[512];
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
    StreamCompletion stream;
    const char *listed_address;
    char *directory = NULL;
    int completion_initialized = 0;
    int stream_initialized = 0;
    int paths_initialized = 0;
    int exit_code = EXIT_FAILURE;
    int written;

    if (ovc_temp_dir_create("ovstorage-c-source-cc-test-c",
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
                       "file://%s/c-roundtrip.bin",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(object_address)) {
        fprintf(stderr, "temporary object address is too long\n");
        goto cleanup;
    }
    written = snprintf(child_address,
                       sizeof(child_address),
                       "file://%s/c-roundtrip.bin/child",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(child_address)) {
        fprintf(stderr, "temporary child address is too long\n");
        goto cleanup;
    }
    written = snprintf(renamed_address,
                       sizeof(renamed_address),
                       "file://%s/c-renamed.bin",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(renamed_address)) {
        fprintf(stderr, "temporary renamed address is too long\n");
        goto cleanup;
    }
    written = snprintf(copied_address,
                       sizeof(copied_address),
                       "file://%s/c-copied.bin",
                       encoded_directory);
    if (written < 0 || (size_t)written >= sizeof(copied_address)) {
        fprintf(stderr, "temporary copied address is too long\n");
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
    written = snprintf(native_renamed,
                       sizeof(native_renamed),
                       "%s/c-renamed.bin",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(native_renamed)) {
        fprintf(stderr, "temporary renamed path is too long\n");
        goto cleanup;
    }
    written = snprintf(native_copied,
                       sizeof(native_copied),
                       "%s/c-copied.bin",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(native_copied)) {
        fprintf(stderr, "temporary copied path is too long\n");
        goto cleanup;
    }
    paths_initialized = 1;

    if (!completion_init(&completion)) {
        goto cleanup;
    }
    completion_initialized = 1;
    if (!stream_completion_init(&stream)) {
        goto cleanup;
    }
    stream_initialized = 1;

    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    if (registry == NULL || stack == NULL) {
        fprintf(stderr, "failed to create the registry or Stack builder\n");
        goto cleanup;
    }

    /* No plugin is loaded or registered: success proves that a fresh
     * registry resolves the seeded built-in file factory. */
    if (!status_succeeded(
            "seeded file resolution with zero plugins loaded",
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
    request = NULL;

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

    /* Create-only onto the existing object must report AlreadyExists, the
     * same precondition code the Rust file backend returns. */
    write_options.no_overwrite = true;
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
    write_options.no_overwrite = false;
    if (completion.status != OvStorage_Status_AlreadyExists) {
        fprintf(stderr,
                "create-only write onto an existing object returned status "
                "%d instead of AlreadyExists\n",
                (int)completion.status);
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
    ovstorage_get_latest_version(layer,
                                 object_address,
                                 &read_options,
                                 NULL,
                                 on_info,
                                 &completion);
    completion_wait(&completion);
    if (!completion_succeeded("get_latest_version", &completion)) {
        goto cleanup;
    }
    if (completion.info == NULL ||
        !completion.info->has_size ||
        completion.info->size != sizeof(payload) - 1) {
        fprintf(stderr,
                "get_latest_version returned unexpected object metadata\n");
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

    /* Stream-read the round-trip object: chunk bytes must accumulate to the
     * exact payload and the done=true terminal must fire exactly once. */
    ovstorage_read_stream(layer,
                          object_address,
                          &read_options,
                          NULL,
                          on_stream,
                          &stream);
    stream_completion_wait(&stream);
    if (stream.had_error || stream.append_failed) {
        fprintf(stderr, "read_stream reported an error\n");
        goto cleanup;
    }
    if (stream.done_count != 1 || stream.fires_after_done != 0) {
        fprintf(stderr,
                "read_stream fired done %d time(s) with %d fire(s) after "
                "done instead of exactly one terminal\n",
                stream.done_count,
                stream.fires_after_done);
        goto cleanup;
    }
    if (stream.len != sizeof(payload) - 1 || stream.data == NULL ||
        memcmp(stream.data, payload, sizeof(payload) - 1) != 0) {
        fprintf(stderr, "read_stream returned unexpected data\n");
        goto cleanup;
    }

    /* A child path under a regular file maps to NotFound: this pins the
     * ENOTDIR arm of the Rust backend's errno -> NotFound table. */
    if (!stat_status_is(layer,
                        &completion,
                        child_address,
                        OvStorage_Status_NotFound,
                        "stat of a child under a regular file")) {
        goto cleanup;
    }
    completion_prepare(&completion);
    ovstorage_read_bytes(layer,
                         child_address,
                         &read_options,
                         NULL,
                         on_read,
                         &completion);
    completion_wait(&completion);
    if (completion.status != OvStorage_Status_NotFound) {
        fprintf(stderr,
                "read of a child under a regular file returned status %d "
                "instead of NotFound\n",
                (int)completion.status);
        goto cleanup;
    }

#if !defined(_WIN32)
    /* Pin the EISDIR arm separately: a write onto an EXISTING DIRECTORY
     * address publishes via rename(2), which fails with EISDIR when the
     * destination is a directory, and the errno table maps that to
     * NotFound.  A byte read of the same directory never reaches the errno
     * table — the backend's is_directory guard answers first, with the
     * InvalidArgument type mismatch the Rust reference gives — so the two
     * codes are asserted side by side here. */
    {
        char directory_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];

        written = snprintf(directory_address,
                           sizeof(directory_address),
                           "%seisdir-target/",
                           root_address);
        if (written < 0 || (size_t)written >= sizeof(directory_address)) {
            fprintf(stderr, "directory address is too long\n");
            goto cleanup;
        }
        completion_prepare(&completion);
        ovstorage_create_directory(layer,
                                   directory_address,
                                   NULL,
                                   on_info,
                                   &completion);
        completion_wait(&completion);
        if (!completion_succeeded("create_directory", &completion)) {
            goto cleanup;
        }
        completion_prepare(&completion);
        ovstorage_write(layer,
                        directory_address,
                        payload,
                        sizeof(payload) - 1,
                        &write_options,
                        NULL,
                        on_info,
                        &completion);
        completion_wait(&completion);
        if (completion.status != OvStorage_Status_NotFound) {
            fprintf(stderr,
                    "write onto an existing directory returned status %d "
                    "instead of NotFound (EISDIR arm)\n",
                    (int)completion.status);
            goto cleanup;
        }
        completion_prepare(&completion);
        ovstorage_read_bytes(layer,
                             directory_address,
                             &read_options,
                             NULL,
                             on_read,
                             &completion);
        completion_wait(&completion);
        if (completion.status != OvStorage_Status_InvalidArgument) {
            fprintf(stderr,
                    "read of an existing directory returned status %d "
                    "instead of InvalidArgument\n",
                    (int)completion.status);
            goto cleanup;
        }
        /* materialize is the read's twin: it hands back a local delegate the
         * caller opens itself, so a directory must be the same type mismatch
         * and not the `!is_regular` Unsupported arm below it. */
        completion_prepare(&completion);
        ovstorage_read_local_file(layer,
                                  directory_address,
                                  &read_options,
                                  NULL,
                                  on_local_file,
                                  &completion);
        completion_wait(&completion);
        if (completion.status != OvStorage_Status_InvalidArgument) {
            fprintf(stderr,
                    "materialize of an existing directory returned status %d "
                    "instead of InvalidArgument\n",
                    (int)completion.status);
            goto cleanup;
        }
        {
            completion_prepare(&completion);
            ovstorage_delete_directory(layer,
                                       directory_address,
                                       NULL,
                                       on_status,
                                       &completion);
            completion_wait(&completion);
            if (!completion_succeeded("delete_directory", &completion)) {
                goto cleanup;
            }
        }
    }
#else
    /* The Win32 counterpart of the EISDIR arm above.  Both platforms refuse
     * to publish a write onto an existing directory, but they report the
     * refusal differently, so the expected status differs:
     * MoveFileExW(MOVEFILE_REPLACE_EXISTING) is documented not to replace a
     * directory, and it reports that refusal as ERROR_ACCESS_DENIED for
     * empty and non-empty destinations alike, which
     * ovc_win32_set_errno maps to EACCES and the errno table maps to
     * PermissionDenied.  ERROR_ACCESS_DENIED carries no "is a directory"
     * distinction on Win32, so PermissionDenied is the honest end of the
     * chain rather than an approximation of the POSIX NotFound. */
    {
        char directory_address[3 * OVC_TEMP_DIR_PATH_MAX + 128];

        written = snprintf(directory_address,
                           sizeof(directory_address),
                           "%seisdir-target/",
                           root_address);
        if (written < 0 || (size_t)written >= sizeof(directory_address)) {
            fprintf(stderr, "directory address is too long\n");
            goto cleanup;
        }
        completion_prepare(&completion);
        ovstorage_create_directory(layer,
                                   directory_address,
                                   NULL,
                                   on_info,
                                   &completion);
        completion_wait(&completion);
        if (!completion_succeeded("create_directory", &completion)) {
            goto cleanup;
        }
        completion_prepare(&completion);
        ovstorage_write(layer,
                        directory_address,
                        payload,
                        sizeof(payload) - 1,
                        &write_options,
                        NULL,
                        on_info,
                        &completion);
        completion_wait(&completion);
        if (completion.status != OvStorage_Status_PermissionDenied) {
            fprintf(stderr,
                    "write onto an existing directory returned status %d "
                    "instead of PermissionDenied (Win32 publish-refusal "
                    "arm)\n",
                    (int)completion.status);
            goto cleanup;
        }
        {
            completion_prepare(&completion);
            ovstorage_delete_directory(layer,
                                       directory_address,
                                       NULL,
                                       on_status,
                                       &completion);
            completion_wait(&completion);
            if (!completion_succeeded("delete_directory", &completion)) {
                goto cleanup;
            }
        }
    }
#endif

    /* The `prefix` connection config is not implemented by the pure-C
     * backend; ignoring it would silently widen the connection's scope to
     * the whole root, so it must be rejected loudly instead. */
    request = ovstorage_connection_request_create("file");
    root_value = ovstorage_config_value_create_string(root_address);
    if (request == NULL || root_value == NULL) {
        fprintf(stderr, "failed to create the prefixed connection config\n");
        goto cleanup;
    }
    if (!ovstorage_connection_request_add_config(request, "root", root_value)) {
        fprintf(stderr, "failed to add the prefixed connection root\n");
        goto cleanup;
    }
    root_value = ovstorage_config_value_create_string("sub/");
    if (root_value == NULL) {
        fprintf(stderr, "failed to create the prefix config value\n");
        goto cleanup;
    }
    if (!ovstorage_connection_request_add_config(request,
                                                 "prefix",
                                                 root_value)) {
        fprintf(stderr, "failed to add the prefix config\n");
        goto cleanup;
    }
    root_value = NULL;
    completion_prepare(&completion);
    ovstorage_add_connection(layer,
                             "files",
                             &request,
                             NULL,
                             on_connection,
                             &completion);
    /* The layer took the request and reports the rejection through the
     * callback, so the slot is already cleared and the `cleanup` label's
     * unconditional destroy has nothing left to free. */
    completion_wait(&completion);
    if (completion.status != OvStorage_Status_InvalidArgument) {
        fprintf(stderr,
                "add_connection with a `prefix` config returned status %d "
                "instead of InvalidArgument\n",
                (int)completion.status);
        goto cleanup;
    }
    if (strstr(completion.error_message, "prefix") == NULL) {
        fprintf(stderr,
                "the `prefix` rejection did not name the prefix config: %s\n",
                completion.error_message);
        goto cleanup;
    }

    /* Rename: content moves and the source disappears. */
    completion_prepare(&completion);
    ovstorage_rename(layer,
                     object_address,
                     renamed_address,
                     NULL,
                     on_status,
                     &completion);
    completion_wait(&completion);
    if (!completion_succeeded("rename", &completion)) {
        goto cleanup;
    }
    if (!stat_status_is(layer,
                        &completion,
                        object_address,
                        OvStorage_Status_NotFound,
                        "stat of the rename source")) {
        goto cleanup;
    }
    if (!read_equals(layer,
                     &completion,
                     renamed_address,
                     payload,
                     sizeof(payload) - 1,
                     "read of the rename destination")) {
        goto cleanup;
    }

    /* Copy: content duplicates and the source remains. */
    completion_prepare(&completion);
    ovstorage_copy(layer,
                   renamed_address,
                   copied_address,
                   NULL,
                   on_info,
                   &completion);
    completion_wait(&completion);
    if (!completion_succeeded("copy", &completion)) {
        goto cleanup;
    }
    if (!read_equals(layer,
                     &completion,
                     copied_address,
                     payload,
                     sizeof(payload) - 1,
                     "read of the copy destination")) {
        goto cleanup;
    }
    if (!stat_status_is(layer,
                        &completion,
                        renamed_address,
                        OvStorage_Status_Ok,
                        "stat of the copy source")) {
        goto cleanup;
    }

    /* Delete both objects and pin stat-after-delete -> NotFound. */
    completion_prepare(&completion);
    ovstorage_delete(layer, renamed_address, NULL, on_status, &completion);
    completion_wait(&completion);
    if (!completion_succeeded("delete", &completion)) {
        goto cleanup;
    }
    if (!stat_status_is(layer,
                        &completion,
                        renamed_address,
                        OvStorage_Status_NotFound,
                        "stat after delete")) {
        goto cleanup;
    }
    completion_prepare(&completion);
    ovstorage_delete(layer, copied_address, NULL, on_status, &completion);
    completion_wait(&completion);
    if (!completion_succeeded("delete of the copy", &completion)) {
        goto cleanup;
    }
    if (!stat_status_is(layer,
                        &completion,
                        copied_address,
                        OvStorage_Status_NotFound,
                        "stat after deleting the copy")) {
        goto cleanup;
    }

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
    if (stream_initialized) {
        stream_completion_destroy(&stream);
    }
    if (paths_initialized && unlink(native_object) != 0 && errno != ENOENT) {
        fprintf(stderr, "unlink failed: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    if (paths_initialized && unlink(native_renamed) != 0 && errno != ENOENT) {
        fprintf(stderr, "unlink failed: %s\n", strerror(errno));
        exit_code = EXIT_FAILURE;
    }
    if (paths_initialized && unlink(native_copied) != 0 && errno != ENOENT) {
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
