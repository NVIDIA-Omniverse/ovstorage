/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/* Loads the C auth fixture without publishing host-global decoder symbols. */

#include "ovstorage_plugin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include "windows_posix_compat.h"
#else
#include <dlfcn.h>
#endif

typedef int (*AuthDecoderProbeFn)(void);
typedef OvStoragePlugin_PluginInitResultV1 (*PluginInitFn)(
    const OvStoragePlugin_HostCallbacks *host);

int ovstorage_c_source_auth_decoder_plugin_contract(
    const char *fixture_path)
{
    void *fixture;
    void *symbol;
    const OvStoragePlugin_PluginManifestV1 *manifest;
    OvStoragePlugin_PluginInitResultV1 initialized;
    PluginInitFn init;
    AuthDecoderProbeFn probe;
    int result;

    if (fixture_path == NULL) {
        fprintf(stderr, "C auth decoder fixture path is null\n");
        return EXIT_FAILURE;
    }
    fixture = dlopen(fixture_path, RTLD_NOW | RTLD_LOCAL);
    if (fixture == NULL) {
        fprintf(stderr, "dlopen(%s): %s\n", fixture_path, dlerror());
        return EXIT_FAILURE;
    }
    manifest = (const OvStoragePlugin_PluginManifestV1 *)dlsym(
        fixture, "ovstorage_plugin_manifest_v1");
    symbol = dlsym(fixture, "ovstorage_plugin_init_v1");
    init = NULL;
    memcpy(&init, &symbol, sizeof(init));
    if (manifest == NULL || init == NULL ||
        manifest->abi_version != OVSTORAGE_PLUGIN_ABI_VERSION) {
        fprintf(stderr, "C auth decoder fixture has an invalid plugin handshake\n");
        return EXIT_FAILURE;
    }
    initialized = init(NULL);
    if (initialized.abi_version != OVSTORAGE_PLUGIN_ABI_VERSION ||
        initialized.plugin_vtable == NULL || initialized.kind_count != 1u ||
        initialized.kinds == NULL ||
        initialized.kinds[0].layer_type !=
            OvStoragePlugin_LayerType_Wrapper ||
        !initialized.kinds[0].auth_capable) {
        fprintf(stderr, "C auth decoder fixture is not an auth-capable plugin\n");
        return EXIT_FAILURE;
    }

    symbol = dlsym(fixture, "ovstorage_test_c_auth_decoder_probe");
    if (symbol == NULL) {
        fprintf(stderr, "C auth decoder fixture probe is not exported\n");
        return EXIT_FAILURE;
    }
    probe = NULL;
    memcpy(&probe, &symbol, sizeof(probe));
    result = probe();
    initialized.plugin_vtable->drop(initialized.plugin_state);
    return result;
}
