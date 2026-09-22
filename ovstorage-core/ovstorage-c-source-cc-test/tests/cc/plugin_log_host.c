/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ovstorage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <io.h>
#include "windows_posix_compat.h"
#define close(descriptor) _close(descriptor)
#define dup(descriptor) _dup(descriptor)
#define dup2(source, destination) _dup2((source), (destination))
#define fileno(stream) _fileno(stream)
#else
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#endif

#include "anonymous_temp_file.h"

typedef void (*EmitFn)(uint8_t level);

typedef struct {
    size_t counts[5];
    size_t unknown;
    size_t in_flight;
    size_t max_in_flight;
    pthread_mutex_t mutex;
} Capture;

typedef struct {
    char *ovstorage_log;
    char *rust_log;
    int had_ovstorage_log;
    int had_rust_log;
} LogEnvironment;

typedef struct {
    FILE *file;
    int saved_stderr;
} StderrCapture;

static char *duplicate_env(const char *name, int *out_present)
{
    const char *value = getenv(name);
    char *copy;

    *out_present = value != NULL;
    if (value == NULL) {
        return NULL;
    }
    copy = malloc(strlen(value) + 1);
    if (copy != NULL) {
        memcpy(copy, value, strlen(value) + 1);
    }
    return copy;
}

static int set_log_env(const char *name, const char *value)
{
#if defined(_WIN32)
    return _putenv_s(name, value == NULL ? "" : value);
#else
    return value == NULL ? unsetenv(name) : setenv(name, value, 1);
#endif
}

static void restore_log_environment(LogEnvironment *environment)
{
    (void)set_log_env("OVSTORAGE_LOG", environment->had_ovstorage_log ? environment->ovstorage_log : NULL);
    (void)set_log_env("RUST_LOG", environment->had_rust_log ? environment->rust_log : NULL);
    free(environment->ovstorage_log);
    free(environment->rust_log);
}

static int stderr_capture_begin(StderrCapture *capture)
{
    fflush(stderr);
    capture->file = ovc_test_open_anonymous_temp_file();
    capture->saved_stderr = -1;
    if (capture->file == NULL) {
        return 0;
    }
    capture->saved_stderr = dup(fileno(stderr));
    if (capture->saved_stderr < 0 || dup2(fileno(capture->file), fileno(stderr)) < 0) {
        if (capture->saved_stderr >= 0) close(capture->saved_stderr);
        fclose(capture->file);
        return 0;
    }
    return 1;
}

static int stderr_capture_end(StderrCapture *capture, char *buffer, size_t buffer_size)
{
    size_t count;
    int failed;

    fflush(stderr);
    if (dup2(capture->saved_stderr, fileno(stderr)) < 0) {
        close(capture->saved_stderr);
        fclose(capture->file);
        capture->saved_stderr = -1;
        capture->file = NULL;
        return 0;
    }
    close(capture->saved_stderr);
    capture->saved_stderr = -1;
    rewind(capture->file);
    count = fread(buffer, 1, buffer_size - 1, capture->file);
    buffer[count] = '\0';
    failed = ferror(capture->file);
    fclose(capture->file);
    capture->file = NULL;
    return !failed;
}

static void stderr_capture_restore(StderrCapture *capture)
{
    if (capture->saved_stderr >= 0) {
        fflush(stderr);
        (void)dup2(capture->saved_stderr, fileno(stderr));
        close(capture->saved_stderr);
        capture->saved_stderr = -1;
    }
    if (capture->file != NULL) {
        fclose(capture->file);
        capture->file = NULL;
    }
}

static void capture_pause(void)
{
#if defined(_WIN32)
    Sleep(10);
#else
    struct timespec delay = {0, 10 * 1000 * 1000};
    (void)nanosleep(&delay, NULL);
#endif
}

static void capture(void *opaque, OvStorage_PluginLogLevel level,
                    const char *target, size_t target_len,
                    const char *message, size_t message_len)
{
    Capture *state = opaque;
    int recognized;

    recognized = target_len == sizeof("fixture.plugin") - 1 &&
        memcmp(target, "fixture.plugin", target_len) == 0 &&
        message != NULL && message_len != 0 &&
        level <= OvStorage_PluginLogLevel_Error;
    (void)pthread_mutex_lock(&state->mutex);
    ++state->in_flight;
    if (state->in_flight > state->max_in_flight) {
        state->max_in_flight = state->in_flight;
    }
    if (!recognized) {
        ++state->unknown;
    } else {
        ++state->counts[level];
    }
    (void)pthread_mutex_unlock(&state->mutex);
    capture_pause();
    (void)pthread_mutex_lock(&state->mutex);
    --state->in_flight;
    (void)pthread_mutex_unlock(&state->mutex);
}

typedef struct {
    EmitFn emit;
    pthread_mutex_t *start_mutex;
    pthread_cond_t *start_cond;
    int *start;
} EmitCall;

static void *emit_warn(void *opaque)
{
    EmitCall *call = opaque;

    (void)pthread_mutex_lock(call->start_mutex);
    while (!*call->start) {
        (void)pthread_cond_wait(call->start_cond, call->start_mutex);
    }
    (void)pthread_mutex_unlock(call->start_mutex);
    call->emit(3);
    return NULL;
}

int ovstorage_c_source_plugin_log_contract(const char *fixture_path)
{
    OvStorage_PluginLogOptions options;
    OvStorage_PluginLogOptions invalid_options;
    OvStorage_Plugin *plugin;
    OvStorage_Error error;
    Capture capture_state;
    void *image;
    void *symbol;
    EmitFn emit;
    LogEnvironment environment;
    int result;
    StderrCapture stderr_capture;
    char stderr_output[2048];
    int capture_mutex_initialized;

    memset(&options, 0, sizeof(options));
    memset(&capture_state, 0, sizeof(capture_state));
    memset(&error, 0, sizeof(error));
    memset(&environment, 0, sizeof(environment));
    memset(&stderr_capture, 0, sizeof(stderr_capture));
    stderr_capture.saved_stderr = -1;
    capture_mutex_initialized = 0;
    environment.ovstorage_log = duplicate_env("OVSTORAGE_LOG", &environment.had_ovstorage_log);
    environment.rust_log = duplicate_env("RUST_LOG", &environment.had_rust_log);
    if ((environment.had_ovstorage_log && environment.ovstorage_log == NULL) ||
        (environment.had_rust_log && environment.rust_log == NULL) ||
        set_log_env("OVSTORAGE_LOG", "debug") != 0 || set_log_env("RUST_LOG", NULL) != 0) {
        restore_log_environment(&environment);
        return EXIT_FAILURE;
    }
    result = EXIT_FAILURE;
    plugin = NULL;
    image = NULL;
    if (pthread_mutex_init(&capture_state.mutex, NULL) != 0) goto cleanup;
    capture_mutex_initialized = 1;
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    if (ovstorage_load_plugin(fixture_path, true, &plugin, &error) != OvStorage_Status_Ok || plugin == NULL) {
        (void)stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output));
        fprintf(stderr, "could not load plugin log fixture: %s\n",
                error.message == NULL ? "unknown error" : error.message);
        goto cleanup;
    }
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "debug-sensitive-record") == NULL ||
        strstr(stderr_output, "trace-sensitive-record") != NULL) {
        fprintf(stderr, "the first plugin log did not sample OVSTORAGE_LOG=debug\n");
        goto cleanup;
    }
    ovstorage_plugin_destroy(plugin);
    plugin = NULL;
    if (set_log_env("OVSTORAGE_LOG", NULL) != 0 || set_log_env("RUST_LOG", NULL) != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    if (ovstorage_load_plugin(fixture_path, true, &plugin, &error) != OvStorage_Status_Ok || plugin == NULL) {
        (void)stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output));
        fprintf(stderr, "could not reload plugin log fixture: %s\n",
                error.message == NULL ? "unknown error" : error.message);
        goto cleanup;
    }
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "warn-record") == NULL || strstr(stderr_output, "error-record") == NULL ||
        strstr(stderr_output, "trace-sensitive-record") != NULL || strstr(stderr_output, "debug-sensitive-record") != NULL ||
        strstr(stderr_output, "info-record") != NULL) {
        fprintf(stderr, "default environment route did not keep only WARN and ERROR\n");
        goto cleanup;
    }
    image = dlopen(fixture_path, RTLD_NOW | RTLD_LOCAL);
    symbol = image == NULL ? NULL : dlsym(image, "ovstorage_test_plugin_log_emit");
    emit = NULL;
    memcpy(&emit, &symbol, sizeof(emit));
    if (emit == NULL) goto cleanup;

    if (set_log_env("OVSTORAGE_LOG", "error") != 0 || set_log_env("RUST_LOG", "trace") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(3);
    emit(4);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "concurrent-record") == NULL ||
        strstr(stderr_output, "[WARN]") != NULL ||
        strstr(stderr_output, "[TRACE]") != NULL) {
        fprintf(stderr, "OVSTORAGE_LOG did not take precedence over RUST_LOG\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", NULL) != 0 || set_log_env("RUST_LOG", "fixture_plugin=DeBuG") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(1);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[DEBUG]") == NULL || strstr(stderr_output, "[TRACE]") != NULL) {
        fprintf(stderr, "RUST_LOG target directive did not set the expected threshold\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", "fixture_plugin") != 0 ||
        set_log_env("RUST_LOG", "info") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(1);
    emit(2);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[TRACE]") == NULL || strstr(stderr_output, "[DEBUG]") == NULL ||
        strstr(stderr_output, "[INFO]") == NULL) {
        fprintf(stderr, "bare OVSTORAGE_LOG target did not enable Trace\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", "fixture/plugin") != 0 ||
        set_log_env("RUST_LOG", "info") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(1);
    emit(2);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[INFO]") == NULL || strstr(stderr_output, "[DEBUG]") != NULL) {
        fprintf(stderr, "malformed OVSTORAGE_LOG did not fall through to RUST_LOG\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", "error,fixture/plugin") != 0 ||
        set_log_env("RUST_LOG", "debug") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(1);
    emit(2);
    emit(3);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[DEBUG]") == NULL || strstr(stderr_output, "[INFO]") == NULL ||
        strstr(stderr_output, "[WARN]") == NULL || strstr(stderr_output, "[TRACE]") != NULL) {
        fprintf(stderr, "mixed OVSTORAGE_LOG did not invalidate the whole variable\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", "off") != 0 ||
        set_log_env("RUST_LOG", "trace") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(4);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "ovstorage plugin") != NULL) {
        fprintf(stderr, "OVSTORAGE_LOG=off did not suppress plugin records\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", "4") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(1);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[DEBUG]") == NULL || strstr(stderr_output, "[TRACE]") != NULL) {
        fprintf(stderr, "numeric Rust log level did not select Debug\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", "error") != 0 ||
        set_log_env("RUST_LOG", "trace") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (set_log_env("OVSTORAGE_LOG", "trace") != 0) goto cleanup;
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(4);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[ERROR]") == NULL || strstr(stderr_output, "[TRACE]") != NULL) {
        fprintf(stderr, "fallback options reread the environment during a plugin callback\n");
        goto cleanup;
    }
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[TRACE]") == NULL) {
        fprintf(stderr, "reset plugin log options did not refresh the fallback threshold\n");
        goto cleanup;
    }

    if (set_log_env("OVSTORAGE_LOG", ",,fixture_plugin=debug,,") != 0 ||
        set_log_env("RUST_LOG", "error") != 0) goto cleanup;
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(1);
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "[DEBUG]") == NULL || strstr(stderr_output, "[TRACE]") != NULL) {
        fprintf(stderr, "empty Rust log directives did not preserve the Debug threshold\n");
        goto cleanup;
    }

    options.level = OvStorage_PluginLogLevel_Trace;
    options.sink = capture;
    options.sink_state = &capture_state;
    if (ovstorage_set_plugin_log_options(&options, &error) != OvStorage_Status_Ok) {
        fprintf(stderr, "could not configure plugin log sink: %s\n", error.message);
        goto cleanup;
    }
    invalid_options = options;
    invalid_options.level = (OvStorage_PluginLogLevel)99;
    if (ovstorage_set_plugin_log_options(&invalid_options, &error) !=
        OvStorage_Status_InvalidArgument) {
        fprintf(stderr, "an invalid explicit level was accepted\n");
        goto cleanup;
    }
    ovstorage_error_clear(&error);
    if (!stderr_capture_begin(&stderr_capture)) goto cleanup;
    emit(0);
    emit(99);
    if (capture_state.counts[0] != 1 || capture_state.counts[2] != 1) {
        fprintf(stderr, "explicit Trace opt-in did not route verbose or future levels\n");
        goto cleanup;
    }
    {
        pthread_t threads[8];
        pthread_mutex_t start_mutex;
        pthread_cond_t start_cond;
        int start;
        EmitCall call;
        size_t created;
        size_t index;
        int thread_failure;

        if (pthread_mutex_init(&start_mutex, NULL) != 0) goto cleanup;
        if (pthread_cond_init(&start_cond, NULL) != 0) {
            (void)pthread_mutex_destroy(&start_mutex);
            goto cleanup;
        }
        start = 0;
        call.emit = emit;
        call.start_mutex = &start_mutex;
        call.start_cond = &start_cond;
        call.start = &start;
        created = 0;
        thread_failure = 0;
        for (index = 0; index < 8; ++index) {
            if (pthread_create(&threads[index], NULL, emit_warn, &call) != 0) {
                thread_failure = 1;
                break;
            }
            ++created;
        }
        (void)pthread_mutex_lock(&start_mutex);
        start = 1;
        for (index = 0; index < created; ++index) {
            (void)pthread_cond_signal(&start_cond);
        }
        (void)pthread_mutex_unlock(&start_mutex);
        for (index = 0; index < created; ++index) {
            if (pthread_join(threads[index], NULL) != 0) thread_failure = 1;
        }
        (void)pthread_cond_destroy(&start_cond);
        (void)pthread_mutex_destroy(&start_mutex);
        if (thread_failure || created != 8 || capture_state.counts[3] != 8 ||
            capture_state.max_in_flight != 1) {
            fprintf(stderr, "concurrent plugin callbacks were not serialized\n");
            goto cleanup;
        }
    }
    if (!stderr_capture_end(&stderr_capture, stderr_output, sizeof(stderr_output)) ||
        strstr(stderr_output, "ovstorage plugin") != NULL) {
        fprintf(stderr, "a configured sink also wrote plugin records to stderr\n");
        goto cleanup;
    }
    result = EXIT_SUCCESS;

cleanup:
    stderr_capture_restore(&stderr_capture);
    if (plugin != NULL) ovstorage_plugin_destroy(plugin);
    if (image != NULL) dlclose(image);
    (void)ovstorage_set_plugin_log_options(NULL, NULL);
    ovstorage_error_clear(&error);
    if (capture_mutex_initialized) {
        (void)pthread_mutex_destroy(&capture_state.mutex);
    }
    restore_log_environment(&environment);
    return result;
}
