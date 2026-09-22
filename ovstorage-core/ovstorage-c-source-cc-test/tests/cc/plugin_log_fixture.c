/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ovstorage_plugin.h"

#include <string.h>

#if defined(_WIN32)
#define OVC_TEST_EXPORT __declspec(dllexport)
#else
#define OVC_TEST_EXPORT __attribute__((visibility("default")))
#endif

static const OvStoragePlugin_HostCallbacks *g_host;
static int g_plugin_state;
static char g_kind[] = "cc-plugin-log-fixture";
static char g_name[] = "C plugin log fixture";

static void emit(uint8_t level, const char *message)
{
    OvStoragePlugin_Str target = {"fixture.plugin", sizeof("fixture.plugin") - 1};
    OvStoragePlugin_Str text = {(char *)message, strlen(message)};
    g_host->log(g_host->host_state, level, &target, &text);
}

static void drop(void *state) { (void)state; }

static OvStoragePlugin_FfiStatus create_backend(
    void *state, const OvStoragePlugin_CreateBackendRequest *request,
    OvStoragePlugin_LayerHandle *out, OvStoragePlugin_Error **error)
{
    (void)state;
    (void)request;
    memset(out, 0, sizeof(*out));
    *error = NULL;
    return OvStoragePlugin_FFI_STATUS_ERR;
}

static const OvStoragePlugin_PluginVTableV1 g_vtable = {
    .struct_size = sizeof(OvStoragePlugin_PluginVTableV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .drop = drop,
    .create_backend = create_backend,
};

static const OvStoragePlugin_LayerKindDescriptor g_descriptor = {
    .struct_size = sizeof(OvStoragePlugin_LayerKindDescriptor),
    .layer_type = OvStoragePlugin_LayerType_Backend,
    .kind = {g_kind, sizeof("cc-plugin-log-fixture") - 1},
    .display_name = {g_name, sizeof("C plugin log fixture") - 1},
};

OVC_TEST_EXPORT const OvStoragePlugin_PluginManifestV1 ovstorage_plugin_manifest_v1 = {
    .struct_size = sizeof(OvStoragePlugin_PluginManifestV1),
    .abi_version = OVSTORAGE_PLUGIN_ABI_VERSION,
    .name = "ovstorage-c-plugin-log-fixture",
    .version = "0.0.0",
    .test_only = true,
};

OVC_TEST_EXPORT OvStoragePlugin_PluginInitResultV1
ovstorage_plugin_init_v1(const OvStoragePlugin_HostCallbacks *host)
{
    OvStoragePlugin_PluginInitResultV1 result;

    g_host = host;
    emit(0, "trace-sensitive-record");
    emit(1, "debug-sensitive-record");
    emit(2, "info-record");
    emit(3, "warn-record");
    emit(4, "error-record");
    memset(&result, 0, sizeof(result));
    result.struct_size = sizeof(result);
    result.abi_version = OVSTORAGE_PLUGIN_ABI_VERSION;
    result.plugin_state = &g_plugin_state;
    result.plugin_vtable = &g_vtable;
    result.kinds = &g_descriptor;
    result.kind_count = 1;
    return result;
}

OVC_TEST_EXPORT void ovstorage_test_plugin_log_emit(uint8_t level)
{
    emit(level, "concurrent-record");
}
