/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Pure-C producer for the cross-language live-handoff
 * fixture `.so`.
 *
 * `tools/ovtasks/_test_plugins.py` compiles this translation unit together
 * with the FULL pure-C source distribution (every `.c` file under
 * `ovstorage-c-source/src`) directly with the C compiler
 * (`cc -fPIC -shared`, no cargo, no nested cargo build of
 * `ovstorage-c-source-cc-test`) into
 * `target/test-plugins/libovsx_c_source_handoff_fixture.so` -- genuinely
 * pure-C-compiled code in its own linked image. Two legs `dlopen` it
 * `RTLD_LOCAL`:
 *
 *  - **C -> Rust** (`ovstorage-core/ovstorage/tests/handoff_c_source.rs`,
 *    hosted there rather than in `ovstorage-c-source-cc-test`: that crate
 *    links the pure-C archive, and linking it *and* `ovstorage-plugin`'s
 *    rlib into one binary would collide -- both export `ovstorage_plugin_*`
 *    symbols).
 *  - **C -> Python** (`ovstorage-core/ovstorage-python/tests/`, smoke leg):
 *    `ctypes` loads this `.so` and hands the exported int to
 *    `LayerBase.import_handle`.
 *
 * `create_exported_stack` builds a temp-dir file-backend Stack via the
 * public `ovstorage.h` application API -- the same construction
 * `handoff_c.c` (the C->C contract) uses for its own round trip --
 * seeds one object, and exports the root through `ovstorage_export_handle`.
 * Importing it live-validates the cross-allocator error-free contract
 * payload bytes crossing the bridge were allocated by the pure-C
 * runtime's `malloc`-backed allocator and must be freed by whichever side's
 * codec claims them, with no leaks or double-frees in either direction; a
 * write back through the imported handle exercises the same contract the
 * other way (consumer-allocated request bytes freed by the pure-C plugin
 * decode path).
 *
 * The temp directory is deliberately left on disk: unlike `handoff_c.c`,
 * which drives every op itself and cleans up in the same process, this
 * fixture only *seeds* the object -- the consumer (a second process, for
 * the pytest leg) drives the ops afterward, so cleanup here would race it.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include "ovstorage.h"

#include "../../../../ovstorage-c-source/src/temp_dir.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const unsigned char OVSX_FIXTURE_PAYLOAD[] =
    "ovstorage pure-C source distribution handoff fixture payload";

static char ovsx_fixture_error_buf[256];
static char ovsx_fixture_prefix_buf[560];
static char ovsx_fixture_object_buf[600];

struct ovsx_fixture_completion {
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int done;
    OvStorage_Status status;
    OvStorage_Info *info;
};

static void ovsx_fixture_completion_init(struct ovsx_fixture_completion *completion)
{
    memset(completion, 0, sizeof(*completion));
    pthread_mutex_init(&completion->mutex, NULL);
    pthread_cond_init(&completion->changed, NULL);
}

static void ovsx_fixture_completion_destroy(struct ovsx_fixture_completion *completion)
{
    ovstorage_info_destroy(completion->info);
    pthread_cond_destroy(&completion->changed);
    pthread_mutex_destroy(&completion->mutex);
}

static void ovsx_fixture_on_info(OvStorage_Status status,
                                 OvStorage_Info *info,
                                 const OvStorage_Error *error,
                                 void *user_data)
{
    struct ovsx_fixture_completion *completion = (struct ovsx_fixture_completion *)user_data;

    (void)error;
    pthread_mutex_lock(&completion->mutex);
    completion->status = status;
    completion->info = info;
    completion->done = 1;
    pthread_cond_signal(&completion->changed);
    pthread_mutex_unlock(&completion->mutex);
}

static void ovsx_fixture_completion_wait(struct ovsx_fixture_completion *completion)
{
    pthread_mutex_lock(&completion->mutex);
    while (!completion->done) {
        pthread_cond_wait(&completion->changed, &completion->mutex);
    }
    pthread_mutex_unlock(&completion->mutex);
}

static void ovsx_fixture_fail(const char *message)
{
    snprintf(ovsx_fixture_error_buf, sizeof(ovsx_fixture_error_buf), "%s", message);
}

/*
 * Build a temp-dir file-backend Stack, seed one object at
 * `ovsx_fixture_object_address()` with `ovsx_fixture_payload()`, and export
 * its root into `*out_handle`. Returns 0 on success, or a negative value
 * with the reason available via `ovsx_fixture_last_error()`.
 */
int create_exported_stack(OvStoragePlugin_LayerHandle *out_handle)
{
    char directory[OVC_TEMP_DIR_PATH_MAX];
    OvStorage_Registry *registry = NULL;
    OvStorage_Stack *stack = NULL;
    OvStorage_ConnectionRequest *request = NULL;
    OvStorage_ConfigValue *root_value = NULL;
    OvStorage_LayerHandle *layer = NULL;
    OvStorage_Error error = {0};
    OvStorage_WriteOptions write_options = {0};
    OvStorage_StackBuildOptions build_options = {0};
    struct ovsx_fixture_completion completion;
    int written;
    int exit_code = -1;

    ovsx_fixture_error_buf[0] = '\0';
    if (out_handle == NULL) {
        ovsx_fixture_fail("create_exported_stack needs a non-NULL out_handle");
        return -1;
    }
    memset(out_handle, 0, sizeof(*out_handle));

    if (ovc_temp_dir_create("ovstorage-c-source-fixture",
                            directory,
                            sizeof(directory)) != 0) {
        ovsx_fixture_fail("creating a temporary directory failed");
        return -1;
    }
    written = snprintf(ovsx_fixture_prefix_buf,
                       sizeof(ovsx_fixture_prefix_buf),
                       "file://%s/",
                       directory);
    if (written < 0 || (size_t)written >= sizeof(ovsx_fixture_prefix_buf)) {
        ovsx_fixture_fail("fixture prefix is too long");
        return -1;
    }
    written = snprintf(ovsx_fixture_object_buf,
                       sizeof(ovsx_fixture_object_buf),
                       "%sa.bin",
                       ovsx_fixture_prefix_buf);
    if (written < 0 || (size_t)written >= sizeof(ovsx_fixture_object_buf)) {
        ovsx_fixture_fail("fixture object address is too long");
        return -1;
    }

    ovsx_fixture_completion_init(&completion);

    registry = ovstorage_registry_create();
    stack = ovstorage_stack_create();
    if (registry == NULL || stack == NULL) {
        ovsx_fixture_fail("failed to create the registry or Stack builder");
        goto cleanup;
    }
    if (ovstorage_stack_add_layer(stack, registry, "files", "file", &error) !=
            OvStorage_Status_Ok ||
        ovstorage_stack_set_root(stack, "files", &error) != OvStorage_Status_Ok) {
        ovsx_fixture_fail("failed to declare the file stack");
        goto cleanup;
    }
    request = ovstorage_connection_request_create("file");
    root_value = ovstorage_config_value_create_string(ovsx_fixture_prefix_buf);
    if (request == NULL || root_value == NULL ||
        !ovstorage_connection_request_add_config(request, "root", root_value)) {
        ovsx_fixture_fail("failed to create the file connection config");
        goto cleanup;
    }
    root_value = NULL;
    if (ovstorage_stack_add_connection(stack, "files", &request, &error) !=
        OvStorage_Status_Ok) {
        ovsx_fixture_fail("failed to record the file connection");
        goto cleanup;
    }
    request = NULL;
    if (ovstorage_stack_build(stack, &build_options, &layer, &error) !=
        OvStorage_Status_Ok) {
        ovsx_fixture_fail("stack_build failed");
        goto cleanup;
    }
    stack = NULL; /* consumed by a successful build */

    ovstorage_write(layer,
                    ovsx_fixture_object_buf,
                    OVSX_FIXTURE_PAYLOAD,
                    sizeof(OVSX_FIXTURE_PAYLOAD) - 1,
                    &write_options,
                    NULL,
                    ovsx_fixture_on_info,
                    &completion);
    ovsx_fixture_completion_wait(&completion);
    if (completion.status != OvStorage_Status_Ok) {
        ovsx_fixture_fail("seeding the fixture object failed");
        goto cleanup;
    }

    if (ovstorage_export_handle(layer, out_handle, &error) != OvStorage_Status_Ok) {
        ovsx_fixture_fail(error.message != NULL ? error.message : "export_handle failed");
        goto cleanup;
    }
    exit_code = 0;

cleanup:
    ovsx_fixture_completion_destroy(&completion);
    ovstorage_layer_handle_destroy(layer);
    ovstorage_stack_destroy(stack);
    ovstorage_connection_request_destroy(request);
    ovstorage_config_value_destroy(root_value);
    ovstorage_registry_destroy(registry);
    ovstorage_error_clear(&error);
    return exit_code;
}

const char *ovsx_fixture_last_error(void)
{
    return ovsx_fixture_error_buf;
}

/* "file://<tmpdir>/" -- the root every seeded/written address lives under. */
const char *ovsx_fixture_prefix(void)
{
    return ovsx_fixture_prefix_buf;
}

/* "file://<tmpdir>/a.bin" -- the seeded object's address. */
const char *ovsx_fixture_object_address(void)
{
    return ovsx_fixture_object_buf;
}

const unsigned char *ovsx_fixture_payload(void)
{
    return OVSX_FIXTURE_PAYLOAD;
}

unsigned long ovsx_fixture_payload_len(void)
{
    return (unsigned long)(sizeof(OVSX_FIXTURE_PAYLOAD) - 1);
}
