/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. */
/* SPDX-License-Identifier: Apache-2.0 */

/* Cross-process contract driver for the standalone C credential store. */

#include "ovstorage.h"
#include "ovstorage_plugin.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#endif

/* These implementation symbols are intentionally not part of the public
 * headers.  This driver links the complete standalone source set, and repeats
 * the narrow prototypes in the same way as secret_wipe_c.c. */
const OvStoragePlugin_HostCallbacks *ovc_host_callbacks_get(void);
void ovc_pval_secret_bytes_wipe(OvStoragePlugin_SecretBytes *value);
char *ovc_path_join(const char *left, const char *right);
char *ovc_cred_namespace_file_stem(const char *ns);

static OvStoragePlugin_Str driver_str(const char *value)
{
    OvStoragePlugin_Str result;

    result.ptr = (char *)(void *)value;
    result.len = strlen(value);
    return result;
}

static OvStoragePlugin_SecretKey driver_key(const char *connection_id)
{
    OvStoragePlugin_SecretKey key;

    key.backend_kind = driver_str("s3");
    key.connection_id.id = driver_str(connection_id);
    key.field = driver_str("refresh-token");
    return key;
}

/* SecretBytes has caller-owned outer storage, unlike the boxed Error. */
static void ovstorage_plugin_secret_bytes_free(
    OvStoragePlugin_SecretBytes *value)
{
    if (value == NULL) {
        return;
    }
    ovc_pval_secret_bytes_wipe(value);
    ovstorage_plugin_bytes_free(&value->bytes);
}

static void driver_print_plugin_error(const OvStoragePlugin_Error *error)
{
    static const char fallback[] = "credential callback failed\n";

    if (error == NULL || error->message_ptr == NULL) {
        (void)fwrite(fallback, 1, sizeof(fallback) - 1u, stderr);
        return;
    }
    (void)fwrite(error->message_ptr, 1, error->message_len, stderr);
    (void)fputc('\n', stderr);
}

static int driver_put(const OvStoragePlugin_HostCallbacks *callbacks,
                      const char *connection_id,
                      const char *text)
{
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_SecretBytes value;
    OvStoragePlugin_Error *error;

    key = driver_key(connection_id);
    value.bytes.ptr = (uint8_t *)(void *)text;
    value.bytes.len = strlen(text);
    error = callbacks->secret_put(callbacks->host_state, &key, &value);
    if (error != NULL) {
        driver_print_plugin_error(error);
        ovstorage_plugin_error_free(error);
        return 1;
    }
    return 0;
}

static int driver_get(const OvStoragePlugin_HostCallbacks *callbacks,
                      const char *connection_id,
                      const char *expected)
{
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_Optional_SecretBytes output;
    OvStoragePlugin_Error *error;
    size_t expected_len;
    int matches;

    key = driver_key(connection_id);
    memset(&output, 0, sizeof(output));
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    if (error != NULL) {
        driver_print_plugin_error(error);
        ovstorage_plugin_error_free(error);
        return 1;
    }
    expected_len = strlen(expected);
    matches = output.present && output.value.bytes.len == expected_len &&
              memcmp(output.value.bytes.ptr, expected, expected_len) == 0;
    if (output.present) {
        ovstorage_plugin_secret_bytes_free(&output.value);
    }
    if (!matches) {
        (void)fputs("credential get did not match the expectation\n", stderr);
        return 1;
    }
    return 0;
}

static int driver_absent(const OvStoragePlugin_HostCallbacks *callbacks,
                         const char *connection_id)
{
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_Optional_SecretBytes output;
    OvStoragePlugin_Error *error;

    key = driver_key(connection_id);
    memset(&output, 0, sizeof(output));
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    if (error != NULL) {
        driver_print_plugin_error(error);
        ovstorage_plugin_error_free(error);
        return 1;
    }
    if (output.present) {
        ovstorage_plugin_secret_bytes_free(&output.value);
        (void)fputs("credential unexpectedly present\n", stderr);
        return 1;
    }
    return 0;
}

static int driver_delete(const OvStoragePlugin_HostCallbacks *callbacks,
                         const char *connection_id)
{
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_Error *error;

    key = driver_key(connection_id);
    error = callbacks->secret_delete(callbacks->host_state, &key);
    if (error != NULL) {
        driver_print_plugin_error(error);
        ovstorage_plugin_error_free(error);
        return 1;
    }
    return 0;
}

static int driver_expect_unavailable(
    const OvStoragePlugin_HostCallbacks *callbacks,
    const char *connection_id)
{
    OvStoragePlugin_SecretKey key;
    OvStoragePlugin_Optional_SecretBytes output;
    OvStoragePlugin_Error *error;

    key = driver_key(connection_id);
    memset(&output, 0, sizeof(output));
    error = callbacks->secret_get(callbacks->host_state, &key, &output);
    if (error != NULL) {
        int expected;

        expected =
            error->code == OvStoragePlugin_ErrorCode_StateRootUnavailable;
        driver_print_plugin_error(error);
        ovstorage_plugin_error_free(error);
        return expected ? 2 : 1;
    }
    if (output.present) {
        ovstorage_plugin_secret_bytes_free(&output.value);
    }
    (void)fputs("credential store corruption was not refused\n", stderr);
    return 1;
}

static int driver_parse_count(const char *text, unsigned long *out)
{
    char *end;
    unsigned long value;

    errno = 0;
    end = NULL;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > 100000ul) {
        return 0;
    }
    *out = value;
    return 1;
}

static int driver_contend(const OvStoragePlugin_HostCallbacks *callbacks,
                          const char *worker_text,
                          const char *iteration_text)
{
    char key[64];
    char value[96];
    unsigned long worker;
    unsigned long iterations;
    unsigned long iteration;
    int count;

    if (!driver_parse_count(worker_text, &worker) ||
        !driver_parse_count(iteration_text, &iterations) || iterations == 0) {
        (void)fputs("invalid contention arguments\n", stderr);
        return 1;
    }
    count = snprintf(key, sizeof(key), "worker-%lu", worker);
    if (count < 0 || (size_t)count >= sizeof(key)) {
        (void)fputs("contention key formatting failed\n", stderr);
        return 1;
    }
    for (iteration = 0; iteration < iterations; ++iteration) {
        count = snprintf(value,
                         sizeof(value),
                         "%lu:%lu",
                         worker,
                         iteration);
        if (count < 0 || (size_t)count >= sizeof(value)) {
            (void)fputs("contention value formatting failed\n", stderr);
            return 1;
        }
        if (driver_put(callbacks, key, value) != 0 ||
            driver_get(callbacks, key, value) != 0) {
            return 1;
        }
        if (iteration % 3ul == 0 &&
            (driver_delete(callbacks, key) != 0 ||
             driver_absent(callbacks, key) != 0)) {
            return 1;
        }
    }
    return 0;
}

#if !defined(_WIN32)
static int driver_hold_lock(const char *auth_dir,
                            const char *credential_namespace,
                            const char *seconds_text)
{
    char *credential_dir;
    char *lock_name;
    char *path;
    struct flock request;
    struct timespec duration;
    size_t stem_len;
    unsigned long seconds;
    int file;
    char *stem;

    if (!driver_parse_count(seconds_text, &seconds) || seconds == 0) {
        (void)fputs("invalid lock hold duration\n", stderr);
        return 1;
    }
    stem = ovc_cred_namespace_file_stem(credential_namespace);
    if (stem == NULL) {
        (void)fputs("failed to encode credential namespace\n", stderr);
        return 1;
    }
    stem_len = strlen(stem);
    if (stem_len > (size_t)-1 - sizeof(".lock")) {
        free(stem);
        (void)fputs("credential namespace encoding is too long\n", stderr);
        return 1;
    }
    lock_name = (char *)malloc(stem_len + sizeof(".lock"));
    if (lock_name == NULL) {
        free(stem);
        (void)fputs("failed to allocate credential lock path\n", stderr);
        return 1;
    }
    memcpy(lock_name, stem, stem_len);
    memcpy(lock_name + stem_len, ".lock", sizeof(".lock"));
    free(stem);
    credential_dir = ovc_path_join(auth_dir, "c-credentials");
    path = credential_dir != NULL ? ovc_path_join(credential_dir, lock_name)
                                  : NULL;
    free(credential_dir);
    free(lock_name);
    if (path == NULL) {
        (void)fputs("failed to allocate credential lock path\n", stderr);
        return 1;
    }
    file = open(path, O_RDWR | O_CLOEXEC);
    free(path);
    if (file < 0) {
        (void)fprintf(stderr, "failed to open credential lock: %s\n", strerror(errno));
        return 1;
    }
    memset(&request, 0, sizeof(request));
    request.l_type = F_WRLCK;
    request.l_whence = SEEK_SET;
    request.l_start = 0;
    request.l_len = 0;
    if (fcntl(file, F_SETLK, &request) != 0) {
        (void)fprintf(stderr, "failed to hold credential lock: %s\n", strerror(errno));
        (void)close(file);
        return 1;
    }
    (void)fputs("locked\n", stdout);
    (void)fflush(stdout);
    duration.tv_sec = (time_t)seconds;
    duration.tv_nsec = 0;
    while (nanosleep(&duration, &duration) != 0 && errno == EINTR) {
    }
    (void)close(file);
    return 0;
}
#endif

static int driver_usage(void)
{
    (void)fputs("invalid credential process driver invocation\n", stderr);
    return 1;
}

int main(int argc, char **argv)
{
    OvStorage_InitAuthSubstrateOptions options;
    OvStorage_Error init_error;
    const OvStoragePlugin_HostCallbacks *callbacks;
    OvStorage_Status status;
    const char *phase;

    if (argc < 4) {
        return driver_usage();
    }
    phase = argv[3];
#if !defined(_WIN32)
    if (strcmp(phase, "hold-lock") == 0) {
        return argc == 5 ? driver_hold_lock(argv[1], argv[2], argv[4])
                         : driver_usage();
    }
#endif

    memset(&init_error, 0, sizeof(init_error));
    options.auth_dir = argv[1];
    options.credential_namespace = argv[2];
    status = ovstorage_init_auth_substrate(&options, &init_error);
    if (status != OvStorage_Status_Ok) {
        const char *message;

        message = ovstorage_error_message(&init_error);
        (void)fprintf(stderr,
                      "%s\n",
                      message != NULL ? message : "auth substrate init failed");
        ovstorage_error_clear(&init_error);
        return 1;
    }
    callbacks = ovc_host_callbacks_get();
    if (callbacks == NULL) {
        (void)fputs("host callback table is unavailable\n", stderr);
        return 1;
    }

    if (strcmp(phase, "put") == 0) {
        return argc == 6 ? driver_put(callbacks, argv[4], argv[5])
                         : driver_usage();
    }
    if (strcmp(phase, "get") == 0) {
        return argc == 6 ? driver_get(callbacks, argv[4], argv[5])
                         : driver_usage();
    }
    if (strcmp(phase, "absent") == 0) {
        return argc == 5 ? driver_absent(callbacks, argv[4])
                         : driver_usage();
    }
    if (strcmp(phase, "delete") == 0) {
        return argc == 5 ? driver_delete(callbacks, argv[4])
                         : driver_usage();
    }
    if (strcmp(phase, "contend") == 0) {
        return argc == 6 ? driver_contend(callbacks, argv[4], argv[5])
                         : driver_usage();
    }
    if (strcmp(phase, "get-expect-unavailable") == 0) {
        return argc == 5 ? driver_expect_unavailable(callbacks, argv[4])
                         : driver_usage();
    }
    return driver_usage();
}
